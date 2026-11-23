package kubetest

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/kube"
)

// Federation is a loopback fake of Google's two identity endpoints (ADR 0024
// M3a, spec v2 §2.6): STS's mTLS token exchange and IAM Credentials'
// generateAccessToken. Both serve one leaf for 127.0.0.1, issued by one P-256
// CA (Roots), and make no outbound connection.
//
// The STS fake is an http.Server of its own on a listener that does each TLS
// handshake itself. It speaks TLS 1.2 to 1.3 (1.2 alone under
// WithSTSMaxTLS12) and HTTP/1.1 only, asks for any client certificate
// (RequireAnyClientCert, or RequestClientCert under
// WithClientCertificateOptional) and verifies none at the TLS layer: the
// trust store depends on the audience, which only the form names. A
// connection whose handshake fails is half-closed for writing and read to EOF
// or for 1 s before it is closed, so a TLS alert reaches the client before
// any reset.
//
// Its handler answers POST /v1/token, in this order, each failure a 400 with
// {"error":…,"error_description":…}:
//  1. the body is application/x-www-form-urlencoded and has exactly the six
//     keys of kube.ExchangeForm, each once (invalid_request);
//  2. grant_type, requested_token_type and subject_token_type are exact
//     (invalid_request), and scope is a space-separated set of known scopes
//     containing cloud-platform (invalid_scope);
//  3. audience names a provider AddProvider added (invalid_target);
//  4. the connection presented a certificate (invalid_request);
//  5. subject_token is a JSON array of at least one standard-base64 DER,
//     whose first item byte-equals the handshake's leaf (invalid_grant);
//  6. the leaf verifies for client authentication against the provider's one
//     anchor, with the handshake's and the subject token's other
//     certificates as intermediates (invalid_grant);
//  7. the provider's condition holds (unauthorized_client): D3's
//     assertion.issuer.dn.cn == '<role ID>' && assertion.subject.dn.cn == '<role ID>',
//     read as the verified chain's second element's CN and the leaf's CN;
//  8. the answer is 200 with a federated token for the provider's role ID.
//
// The IAM Credentials fake answers
// POST /v1/projects/-/serviceAccounts/{email}:generateAccessToken, with
// Google's JSON error shape on failure: 401 UNAUTHENTICATED unless the bearer
// is a token the STS fake issued; 400 INVALID_ARGUMENT unless the body's keys
// are exactly scope and lifetime, compared case-sensitively (read by exact
// keys, never into a struct, as the rest of kubetest reads), with lifetime
// "3600s" and scope exactly kube.TokenScopes(); 403 PERMISSION_DENIED unless
// Bind bound the token's role ID to the email; else 200 with an access token
// that expires in an hour. It speaks HTTP/2 or HTTP/1.1, and asks for a
// client certificate (RequestClientCert), so a client that holds one would
// send it and the record shows none came.
//
// Every request a handler sees is recorded (Requests), and every handshake
// that reaches the server's VerifyConnection (Handshakes), whether a request
// follows or not. No token value and no Authorization header's value is ever
// recorded.
type Federation struct {
	cfg   federationConfig
	roots *x509.CertPool

	stsAddr string
	stsLn   *handshakeListener
	stsSrv  *http.Server
	stsDone chan struct{}

	iamAddr string
	iamSrv  *http.Server
	iamDone chan struct{}

	closeOnce sync.Once

	mu         sync.Mutex
	providers  map[string]federationProvider // by audience
	bindings   map[string][]string           // role ID → service account emails
	federated  map[string]string             // federated token → role ID
	issued     int
	requests   []FederationRequest
	handshakes []FederationHandshake
}

// FederationOption configures a Federation at NewFederation.
type FederationOption func(*federationConfig)

type federationConfig struct {
	certificateOptional   bool
	clientCAs             *x509.CertPool
	stsMaxTLS12           bool
	exchangeAnswer        *federationAnswer
	impersonationAnswer   *federationAnswer
	exchangeRedirect      string
	impersonationRedirect string
	expiresIn             int
}

type federationAnswer struct {
	code int
	body []byte
}

// federationProvider is one provider: its trust store, one anchor, and the
// role ID its condition pins.
type federationProvider struct {
	anchors *x509.CertPool
	roleID  string
}

// The fakes' fixed values.
const (
	// federationHandshakeTimeout bounds each STS handshake.
	federationHandshakeTimeout = 10 * time.Second
	// failedHandshakeDrain is how long a failed handshake's connection is
	// read, after its write side is closed, before it is closed.
	failedHandshakeDrain = time.Second
	// maxFederationRequest caps what one request may send.
	maxFederationRequest = 1 << 20
	// defaultExpiresIn is the STS fake's expires_in, as Google's STS states it.
	defaultExpiresIn = 3599
	// serviceAccountTokenLifetime is the IAM fake's tokens' lifetime.
	serviceAccountTokenLifetime = time.Hour
)

// WithClientCertificateOptional makes the STS fake ask for a client
// certificate without requiring one (tls.RequestClientCert), so a request
// with none reaches the handler, which refuses it (step 4).
func WithClientCertificateOptional() FederationOption {
	return func(c *federationConfig) { c.certificateOptional = true }
}

// WithClientCAs makes the STS fake send pool's subjects as its acceptable
// CAs. The TLS layer still verifies nothing.
func WithClientCAs(pool *x509.CertPool) FederationOption {
	return func(c *federationConfig) { c.clientCAs = pool }
}

// WithSTSMaxTLS12 makes the STS fake speak TLS 1.2 at most.
func WithSTSMaxTLS12() FederationOption {
	return func(c *federationConfig) { c.stsMaxTLS12 = true }
}

// WithExchangeAnswer replaces the STS fake's answer to every request that
// reached its handler: code (0 is 200) with body, as JSON when it begins with
// { or [. The request is still recorded.
func WithExchangeAnswer(code int, body string) FederationOption {
	return func(c *federationConfig) { c.exchangeAnswer = &federationAnswer{code: code, body: []byte(body)} }
}

// WithImpersonationAnswer does the same for the IAM Credentials fake.
func WithImpersonationAnswer(code int, body string) FederationOption {
	return func(c *federationConfig) { c.impersonationAnswer = &federationAnswer{code: code, body: []byte(body)} }
}

// WithExchangeRedirect answers every request for /v1/token with 307 and
// Location: location (absolute, or a path on the same host).
func WithExchangeRedirect(location string) FederationOption {
	return func(c *federationConfig) { c.exchangeRedirect = location }
}

// WithImpersonationRedirect answers every request for a generateAccessToken
// path with 307 and Location: location. A request for any other path,
// location's own included, is answered as usual: 404.
func WithImpersonationRedirect(location string) FederationOption {
	return func(c *federationConfig) { c.impersonationRedirect = location }
}

// WithExpiresIn sets the STS fake's expires_in (default 3599).
func WithExpiresIn(seconds int) FederationOption {
	return func(c *federationConfig) { c.expiresIn = seconds }
}

// FederationRequest is one request a fake's handler saw.
type FederationRequest struct {
	Server       string // "sts" or "iam"
	Method, Path string
	ContentType  string
	UserAgent    string
	// Headers are the request's header names, canonical and sorted, without
	// the three net/http adds itself (Accept-Encoding, Connection,
	// Content-Length). Authorization is listed by name; its value is never
	// recorded.
	Headers          []string
	PeerCertificates [][]byte   // what this request's connection presented; nil for none
	Form             url.Values // STS: the parsed form (public material only)
	Body             []byte     // IAM: the JSON body (no secret)
	As               string     // the role ID whose federated token authorised it; "" none, "?" unknown
}

// FederationHandshake is one completed or attempted handshake, recorded by
// the server's tls.Config.VerifyConnection, independently of any request.
type FederationHandshake struct {
	Server           string   // "sts" or "iam"
	PeerCertificates [][]byte // empty when the client presented none
	Version          uint16
}

// NewFederation starts both fakes on 127.0.0.1:0 and registers t.Cleanup to
// stop them.
func NewFederation(t testing.TB, opts ...FederationOption) *Federation {
	t.Helper()
	f, err := startFederation(opts...)
	if err != nil {
		t.Fatalf("kubetest: %v", err)
	}
	t.Cleanup(f.Close)
	return f
}

func startFederation(opts ...FederationOption) (*Federation, error) {
	cfg := federationConfig{expiresIn: defaultExpiresIn}
	for _, opt := range opts {
		opt(&cfg)
	}
	caPEM, leaf, err := newCertificates(net.IPv4(127, 0, 0, 1))
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("read the fakes' CA back")
	}
	f := &Federation{
		cfg:       cfg,
		roots:     roots,
		stsDone:   make(chan struct{}),
		iamDone:   make(chan struct{}),
		providers: map[string]federationProvider{},
		bindings:  map[string][]string{},
		federated: map[string]string{},
	}

	stsTLS := &tls.Config{
		Certificates:     []tls.Certificate{leaf},
		MinVersion:       tls.VersionTLS12,
		NextProtos:       []string{"http/1.1"},
		ClientAuth:       tls.RequireAnyClientCert,
		ClientCAs:        cfg.clientCAs,
		VerifyConnection: f.recordHandshake("sts"),
	}
	if cfg.certificateOptional {
		stsTLS.ClientAuth = tls.RequestClientCert
	}
	if cfg.stsMaxTLS12 {
		stsTLS.MaxVersion = tls.VersionTLS12
	}
	stsRaw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for the STS fake: %w", err)
	}
	iamRaw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = stsRaw.Close()
		return nil, fmt.Errorf("listen for the IAM Credentials fake: %w", err)
	}
	f.stsAddr = stsRaw.Addr().String()
	f.iamAddr = iamRaw.Addr().String()

	f.stsLn = newHandshakeListener(stsRaw, stsTLS)
	f.stsSrv = &http.Server{
		Handler:           http.HandlerFunc(f.serveSTS),
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	go func() {
		defer close(f.stsDone)
		_ = f.stsSrv.Serve(f.stsLn)
	}()

	f.iamSrv = &http.Server{
		Handler: http.HandlerFunc(f.serveIAM),
		TLSConfig: &tls.Config{
			Certificates:     []tls.Certificate{leaf},
			MinVersion:       tls.VersionTLS12,
			ClientAuth:       tls.RequestClientCert,
			VerifyConnection: f.recordHandshake("iam"),
		},
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	go func() {
		defer close(f.iamDone)
		_ = f.iamSrv.ServeTLS(iamRaw, "", "")
	}()
	return f, nil
}

// STSAddr is the STS fake's "127.0.0.1:<port>".
func (f *Federation) STSAddr() string { return f.stsAddr }

// IAMAddr is the IAM Credentials fake's "127.0.0.1:<port>".
func (f *Federation) IAMAddr() string { return f.iamAddr }

// Roots is a pool holding the one CA that issued both fakes' leaf.
func (f *Federation) Roots() *x509.CertPool { return f.roots.Clone() }

// AddProvider adds a provider: its audience is kube.Audience(projectNumber,
// pool, provider); its trust store anchorDER alone; its condition D3's,
// pinning roleID. It panics on an audience kube.Audience refuses or an
// anchor that does not parse, as AddKey does on its own bad input.
func (f *Federation) AddProvider(projectNumber, pool, provider string, anchorDER []byte, roleID string) {
	aud, err := kube.Audience(projectNumber, pool, provider)
	if err != nil {
		panic("kubetest: AddProvider: the audience's parts are not Google's shape")
	}
	anchor, err := x509.ParseCertificate(anchorDER)
	if err != nil {
		panic("kubetest: AddProvider: the anchor is not a certificate")
	}
	anchors := x509.NewCertPool()
	anchors.AddCert(anchor)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.providers[aud] = federationProvider{anchors: anchors, roleID: roleID}
}

// Bind grants roleID's principal the right to impersonate serviceAccount.
func (f *Federation) Bind(roleID, serviceAccount string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !slices.Contains(f.bindings[roleID], serviceAccount) {
		f.bindings[roleID] = append(f.bindings[roleID], serviceAccount)
	}
}

// Requests is every request both handlers saw, in order. Each is the
// caller's own copy.
func (f *Federation) Requests() []FederationRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]FederationRequest, len(f.requests))
	for i, r := range f.requests {
		r.Headers = slices.Clone(r.Headers)
		r.PeerCertificates = cloneDERs(r.PeerCertificates)
		if r.Form != nil {
			form := url.Values{}
			for k, v := range r.Form {
				form[k] = slices.Clone(v)
			}
			r.Form = form
		}
		r.Body = bytes.Clone(r.Body)
		out[i] = r
	}
	return out
}

// Handshakes is every handshake both servers' VerifyConnection saw, in order.
func (f *Federation) Handshakes() []FederationHandshake {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]FederationHandshake, len(f.handshakes))
	for i, h := range f.handshakes {
		h.PeerCertificates = cloneDERs(h.PeerCertificates)
		out[i] = h
	}
	return out
}

// Close stops both fakes and waits for them. It may be called more than once.
func (f *Federation) Close() {
	f.closeOnce.Do(func() {
		_ = f.stsSrv.Close()
		_ = f.stsLn.Close()
		<-f.stsDone
		f.stsLn.wait()
		_ = f.iamSrv.Close()
		<-f.iamDone
	})
}

func cloneDERs(ders [][]byte) [][]byte {
	if ders == nil {
		return nil
	}
	out := make([][]byte, len(ders))
	for i, d := range ders {
		out[i] = bytes.Clone(d)
	}
	return out
}

// recordHandshake is a server's VerifyConnection: it records the handshake
// and accepts it.
func (f *Federation) recordHandshake(server string) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		h := FederationHandshake{Server: server, Version: cs.Version}
		for _, c := range cs.PeerCertificates {
			h.PeerCertificates = append(h.PeerCertificates, bytes.Clone(c.Raw))
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.handshakes = append(f.handshakes, h)
		return nil
	}
}

// newRequest is r as recorded, before its body, form and As are set.
func newFederationRequest(server string, r *http.Request) FederationRequest {
	req := FederationRequest{
		Server:      server,
		Method:      r.Method,
		Path:        r.URL.Path,
		ContentType: r.Header.Get("Content-Type"),
		UserAgent:   r.UserAgent(),
	}
	for name := range r.Header {
		switch name {
		case "Accept-Encoding", "Connection", "Content-Length":
			continue
		}
		req.Headers = append(req.Headers, name)
	}
	slices.Sort(req.Headers)
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		for _, c := range r.TLS.PeerCertificates {
			req.PeerCertificates = append(req.PeerCertificates, bytes.Clone(c.Raw))
		}
	}
	return req
}

func (f *Federation) record(r FederationRequest) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r)
}

// newFederationToken is "kubetest-<kind>-<n>-" and 16 random hex characters.
// The caller holds f.mu.
func (f *Federation) newFederationToken(kind string) string {
	f.issued++
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("kubetest: draw a token: %v", err))
	}
	return fmt.Sprintf("kubetest-%s-%d-%s", kind, f.issued, hex.EncodeToString(b[:]))
}

// stsAnswer is the STS fake's 200, in the order Google writes it.
type stsAnswer struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
}

// exchangeFormKeys are kube.ExchangeForm's six keys.
var exchangeFormKeys = []string{"audience", "grant_type", "requested_token_type", "subject_token_type", "subject_token", "scope"}

// serveSTS is the STS fake's handler.
func (f *Federation) serveSTS(w http.ResponseWriter, r *http.Request) {
	req := newFederationRequest("sts", r)
	body, readErr := io.ReadAll(io.LimitReader(r.Body, maxFederationRequest+1))
	form, formErr := url.ParseQuery(string(body))
	if readErr == nil && formErr == nil && len(body) <= maxFederationRequest {
		req.Form = form
	}
	f.record(req)

	if a := f.cfg.exchangeAnswer; a != nil {
		writeAnswer(w, a.code, a.body)
		return
	}
	if r.URL.Path == kube.STSTokenPath && f.cfg.exchangeRedirect != "" {
		w.Header().Set("Location", f.cfg.exchangeRedirect)
		w.WriteHeader(http.StatusTemporaryRedirect)
		return
	}
	refuse := func(code, why string) {
		writeJSON(w, http.StatusBadRequest, oauthError{Error: code, Description: why})
	}
	switch {
	case r.URL.Path != kube.STSTokenPath:
		writeJSON(w, http.StatusNotFound, oauthError{Error: "invalid_request", Description: "the STS fake answers /v1/token only"})
		return
	case r.Method != http.MethodPost:
		writeJSON(w, http.StatusMethodNotAllowed, oauthError{Error: "invalid_request", Description: "the token exchange takes POST only"})
		return
	case readErr != nil || len(body) > maxFederationRequest:
		refuse("invalid_request", "the body could not be read")
		return
	}

	// 1. The form.
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || formErr != nil || len(form) != len(exchangeFormKeys) {
		refuse("invalid_request", "the body is not the exchange's six-key form")
		return
	}
	for _, k := range exchangeFormKeys {
		if len(form[k]) != 1 {
			refuse("invalid_request", "the form does not carry "+k+" exactly once")
			return
		}
	}
	// 2. The fixed values and the scopes.
	if form.Get("grant_type") != kube.GrantTypeTokenExchange || form.Get("requested_token_type") != kube.TokenTypeAccessToken ||
		form.Get("subject_token_type") != kube.TokenTypeMTLS {
		refuse("invalid_request", "a token type or the grant type is not the mTLS exchange's")
		return
	}
	if !knownScopes(form.Get("scope")) {
		refuse("invalid_scope", "the scope is not a set of known scopes containing cloud-platform")
		return
	}
	// 3. The provider.
	f.mu.Lock()
	p, ok := f.providers[form.Get("audience")]
	f.mu.Unlock()
	if !ok {
		refuse("invalid_target", "the audience names no provider")
		return
	}
	// 4. The handshake's certificate.
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		refuse("invalid_request", "the connection presented no client certificate")
		return
	}
	peers := r.TLS.PeerCertificates
	// 5. The subject token, its leaf the handshake's.
	subject, ok := subjectChain(form.Get("subject_token"))
	if !ok || !bytes.Equal(subject[0].Raw, peers[0].Raw) {
		refuse("invalid_grant", "the subject token is not a chain led by the handshake's leaf")
		return
	}
	// 6. The trust store.
	intermediates := x509.NewCertPool()
	for _, c := range peers[1:] {
		intermediates.AddCert(c)
	}
	for _, c := range subject[1:] {
		intermediates.AddCert(c)
	}
	chains, err := subject[0].Verify(x509.VerifyOptions{
		Roots:         p.anchors,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime:   time.Now(),
	})
	if err != nil || len(chains) == 0 {
		refuse("invalid_grant", "the leaf does not verify against the provider's trust store")
		return
	}
	// 7. The condition.
	chain := chains[0]
	issuerCN := chain[0].Issuer.CommonName
	if len(chain) > 1 {
		issuerCN = chain[1].Subject.CommonName
	}
	if issuerCN != p.roleID || chain[0].Subject.CommonName != p.roleID {
		writeJSON(w, http.StatusBadRequest, oauthError{Error: "unauthorized_client", Description: "the provider's condition does not hold"})
		return
	}
	// 8. The token.
	f.mu.Lock()
	token := f.newFederationToken("federated")
	f.federated[token] = p.roleID
	f.mu.Unlock()
	writeJSON(w, http.StatusOK, stsAnswer{
		AccessToken:     token,
		IssuedTokenType: kube.TokenTypeAccessToken,
		TokenType:       "Bearer",
		ExpiresIn:       f.cfg.expiresIn,
	})
}

// knownScopes is a space-separated set of kube's two scopes that holds
// cloud-platform.
func knownScopes(scope string) bool {
	hasCloudPlatform := false
	for _, s := range strings.Split(scope, " ") {
		switch s {
		case kube.ScopeCloudPlatform:
			hasCloudPlatform = true
		case kube.ScopeUserinfoEmail:
		default:
			return false
		}
	}
	return hasCloudPlatform
}

// subjectChain reads a subject token: a JSON array of at least one
// standard-base64 DER certificate.
func subjectChain(token string) ([]*x509.Certificate, bool) {
	var items []string
	if err := json.Unmarshal([]byte(token), &items); err != nil || len(items) == 0 {
		return nil, false
	}
	chain := make([]*x509.Certificate, 0, len(items))
	for _, it := range items {
		der, err := base64.StdEncoding.DecodeString(it)
		if err != nil {
			return nil, false
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, false
		}
		chain = append(chain, c)
	}
	return chain, true
}

// iamAnswer is the IAM Credentials fake's 200.
type iamAnswer struct {
	AccessToken string `json:"accessToken"`
	ExpireTime  string `json:"expireTime"`
}

// serveIAM is the IAM Credentials fake's handler.
func (f *Federation) serveIAM(w http.ResponseWriter, r *http.Request) {
	req := newFederationRequest("iam", r)
	body, readErr := io.ReadAll(io.LimitReader(r.Body, maxFederationRequest+1))
	if readErr == nil && len(body) <= maxFederationRequest {
		req.Body = body
	}
	bearer, hasBearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	f.mu.Lock()
	roleID, known := f.federated[bearer]
	f.mu.Unlock()
	switch {
	case r.Header.Get("Authorization") == "":
	case hasBearer && known:
		req.As = roleID
	default:
		req.As = "?"
		known = false
	}
	f.record(req)

	if a := f.cfg.impersonationAnswer; a != nil {
		writeAnswer(w, a.code, a.body)
		return
	}
	email, isGAT := generateAccessTokenEmail(r.URL.Path)
	if isGAT && f.cfg.impersonationRedirect != "" {
		w.Header().Set("Location", f.cfg.impersonationRedirect)
		w.WriteHeader(http.StatusTemporaryRedirect)
		return
	}
	fail := func(code int, status, message string) {
		writeJSON(w, code, googleError{Error: googleErrorBody{Code: code, Message: message, Status: status}})
	}
	switch {
	case !isGAT:
		fail(http.StatusNotFound, "NOT_FOUND", "the IAM Credentials fake answers generateAccessToken only")
	case r.Method != http.MethodPost:
		fail(http.StatusMethodNotAllowed, "INVALID_ARGUMENT", "generateAccessToken takes POST only")
	case !known:
		fail(http.StatusUnauthorized, "UNAUTHENTICATED", "the bearer is not a federated token the STS fake issued")
	case readErr != nil || !impersonationBodyOK(body):
		fail(http.StatusBadRequest, "INVALID_ARGUMENT", "the body is not exactly scope and lifetime, with kube's scopes and 3600s")
	case !f.bound(roleID, email):
		fail(http.StatusForbidden, "PERMISSION_DENIED", "the principal may not impersonate this service account")
	default:
		f.mu.Lock()
		token := f.newFederationToken("sa")
		f.mu.Unlock()
		writeJSON(w, http.StatusOK, iamAnswer{
			AccessToken: token,
			ExpireTime:  time.Now().UTC().Add(serviceAccountTokenLifetime).Format(time.RFC3339Nano),
		})
	}
}

func (f *Federation) bound(roleID, email string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Contains(f.bindings[roleID], email)
}

// generateAccessTokenEmail is the email a generateAccessToken path names.
func generateAccessTokenEmail(path string) (string, bool) {
	rest, ok := strings.CutPrefix(path, "/v1/projects/-/serviceAccounts/")
	if !ok {
		return "", false
	}
	email, ok := strings.CutSuffix(rest, ":generateAccessToken")
	if !ok || email == "" || strings.Contains(email, "/") {
		return "", false
	}
	return email, true
}

// impersonationBodyOK reads a generateAccessToken body by its exact keys:
// scope and lifetime, and nothing else, with lifetime "3600s" and scope
// exactly kube.TokenScopes(). encoding/json would match a struct's keys
// case-insensitively, so a {"Scope":…} body would pass one.
func impersonationBodyOK(body []byte) bool {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil || len(m) != 2 {
		return false
	}
	rawScope, ok1 := m["scope"]
	rawLifetime, ok2 := m["lifetime"]
	if !ok1 || !ok2 {
		return false
	}
	var lifetime string
	if err := json.Unmarshal(rawLifetime, &lifetime); err != nil || lifetime != "3600s" {
		return false
	}
	var scopes []string
	if err := json.Unmarshal(rawScope, &scopes); err != nil {
		return false
	}
	return slices.Equal(scopes, kube.TokenScopes())
}

// handshakeListener hands http.Server only connections whose TLS handshake
// it completed itself, each within federationHandshakeTimeout. A connection
// whose handshake fails has its write side closed and is read to EOF or for
// failedHandshakeDrain before it is closed: closing it at once with the
// client's request unread would send a reset, which can reach the client
// before the TLS alert it should read.
type handshakeListener struct {
	raw   net.Listener
	cfg   *tls.Config
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
	wg    sync.WaitGroup

	mu      sync.Mutex
	pending map[net.Conn]struct{}
}

func newHandshakeListener(raw net.Listener, cfg *tls.Config) *handshakeListener {
	l := &handshakeListener{
		raw:     raw,
		cfg:     cfg,
		conns:   make(chan net.Conn),
		done:    make(chan struct{}),
		pending: map[net.Conn]struct{}{},
	}
	l.wg.Add(1)
	go l.acceptLoop()
	return l
}

func (l *handshakeListener) acceptLoop() {
	defer l.wg.Done()
	for {
		c, err := l.raw.Accept()
		if err != nil {
			return
		}
		if !l.track(c) {
			_ = c.Close()
			return
		}
		l.wg.Add(1)
		go l.handshake(c)
	}
}

// track holds c as pending, so Close can end its handshake; false once the
// listener is closed.
func (l *handshakeListener) track(c net.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	select {
	case <-l.done:
		return false
	default:
	}
	l.pending[c] = struct{}{}
	return true
}

func (l *handshakeListener) untrack(c net.Conn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.pending, c)
}

func (l *handshakeListener) handshake(raw net.Conn) {
	defer l.wg.Done()
	defer l.untrack(raw)
	_ = raw.SetDeadline(time.Now().Add(federationHandshakeTimeout))
	tc := tls.Server(raw, l.cfg)
	if err := tc.Handshake(); err != nil {
		if tcp, ok := raw.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		_ = raw.SetReadDeadline(time.Now().Add(failedHandshakeDrain))
		_, _ = io.Copy(io.Discard, raw)
		_ = raw.Close()
		return
	}
	_ = raw.SetDeadline(time.Time{})
	select {
	case l.conns <- tc:
	case <-l.done:
		_ = tc.Close()
	}
}

func (l *handshakeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *handshakeListener) Close() error {
	l.once.Do(func() {
		l.mu.Lock()
		close(l.done)
		for c := range l.pending {
			_ = c.Close()
		}
		l.mu.Unlock()
		_ = l.raw.Close()
	})
	return nil
}

func (l *handshakeListener) Addr() net.Addr { return l.raw.Addr() }

// wait waits for the accept loop and every handshake to end.
func (l *handshakeListener) wait() { l.wg.Wait() }
