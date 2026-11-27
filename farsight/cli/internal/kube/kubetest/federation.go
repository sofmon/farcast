package kubetest

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
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

// Federation is a loopback fake of Google's three identity hosts (ADR 0024
// M3a, spec v2 §2.6; M3b.3): STS's mTLS token exchange, IAM Credentials'
// generateAccessToken, and IAM's API, where the reader reads the instance's
// workload identity providers. All three serve one leaf for 127.0.0.1,
// issued by one P-256 CA (Roots), and make no outbound connection.
//
// Its providers are kept as Google keeps them (AddProvider): a name, the
// trust store's anchor as PEM, D3's attribute mapping
// {"google.subject":"assertion.issuer.dn.cn"} and condition
// assertion.issuer.dn.cn == '<role ID>' && assertion.subject.dn.cn == '<role ID>',
// a state (ACTIVE, or DELETED after RemoveProvider, with an expireTime) and
// a disabled flag (DisableProvider).
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
//  3. audience names a provider AddProvider added, ACTIVE and not disabled
//     (invalid_target; what Google answers for a deleted or a disabled
//     provider is [unverified]);
//  4. the connection presented a certificate (invalid_request);
//  5. subject_token is a JSON array of at least one standard-base64 DER,
//     whose first item byte-equals the handshake's leaf (invalid_grant);
//  6. the leaf verifies for client authentication against the provider's
//     trust store, its stored anchors, with the handshake's and the subject
//     token's other certificates as intermediates (invalid_grant);
//  7. the provider's stored condition holds (unauthorized_client). Only D3's
//     exact form is evaluated, with the role ID parsed out of it, and read as
//     the verified chain's second element's CN and the leaf's CN; any other
//     condition holds for nothing;
//  8. the answer is 200 with a federated token for the principal the
//     provider's mapping names: D3's google.subject, the issuer's CN, which
//     is the role ID.
//
// The IAM Credentials fake answers
// POST /v1/projects/-/serviceAccounts/{email}:generateAccessToken, with
// Google's JSON error shape on failure: 401 UNAUTHENTICATED unless the bearer
// is a token the STS fake issued and RevokeFederatedTokens has not revoked
// since; 400 INVALID_ARGUMENT unless the body's keys are exactly scope and
// lifetime, compared case-sensitively (read by exact keys, never into a
// struct, as the rest of kubetest reads), with lifetime "3600s" and scope
// exactly one of kube's closed list (N9), in its order:
// kube.ScopesCluster's (cloud-platform, userinfo.email), ScopesStorage's
// (devstorage.full_control) or ScopesRegistry's (cloud-platform); 403
// PERMISSION_DENIED unless Bind bound the token's role ID to the email (and
// Unbind has not unbound it); else 200 with an access token that expires in
// an hour (WithServiceAccountTokenLifetime sets another lifetime). Each token
// it issues is kept in a registry, by value, with its role ID, email, scopes
// and expiry (ServiceAccountTokens lists them without the value): the IAM API
// fake, and a Server given WithFederation, take these tokens until they
// expire, and no other. It speaks HTTP/2 or HTTP/1.1, and asks for a
// client certificate (RequestClientCert), so a client that holds one would
// send it and the record shows none came.
//
// The IAM API fake is served as the IAM Credentials fake is, and answers GET
// for one provider and for a pool's list (iamapi.go has its rules), only to
// a live service-account token from the registry whose scopes hold
// cloud-platform and whose account GrantPoolViewer granted.
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

	iamAPIAddr string
	iamAPISrv  *http.Server
	iamAPIDone chan struct{}

	closeOnce sync.Once

	mu              sync.Mutex
	providers       map[string]federationProvider  // by audience
	bindings        map[string][]string            // role ID → service account emails
	federated       map[string]string              // federated token → role ID
	serviceAccounts map[string]ServiceAccountToken // service-account token → what it was issued for
	poolViewers     map[string]bool                // service account emails GrantPoolViewer granted
	issued          int
	requests        []FederationRequest
	handshakes      []FederationHandshake
}

// ServiceAccountToken is what the IAM Credentials fake issued one
// service-account token for. It never holds the token's value.
type ServiceAccountToken struct {
	RoleID  string    // the role ID whose federated token impersonated
	Email   string    // the service account impersonated
	Scopes  []string  // the body's scopes, one of kube's closed list, in order
	Expires time.Time // when the token expires: its lifetime after it was issued (an hour, or WithServiceAccountTokenLifetime's)
}

// FederationOption configures a Federation at NewFederation or
// StartFederation.
type FederationOption func(*federationConfig)

type federationConfig struct {
	certificateOptional   bool
	clientCAs             *x509.CertPool
	stsMaxTLS12           bool
	exchangeAnswer        *federationAnswer
	impersonationAnswer   *federationAnswer
	iamAPIAnswer          *federationAnswer
	exchangeRedirect      string
	impersonationRedirect string
	expiresIn             int
	serviceAccountLife    time.Duration
}

type federationAnswer struct {
	code int
	body []byte
}

// federationProvider is one provider, as Google keeps it: its name's parts,
// its trust store (the anchors' PEM as given, and the pool parsed from it),
// its attribute mapping and condition, its state and disabled flag, and when
// a DELETED one is purged.
type federationProvider struct {
	project, pool, id string
	anchorsPEM        []string
	anchors           *x509.CertPool
	mapping           map[string]string
	condition         string
	state             string
	disabled          bool
	expireTime        time.Time
}

// name is the provider's resource name, with its project's number.
func (p federationProvider) name() string {
	return "projects/" + p.project + "/locations/global/workloadIdentityPools/" + p.pool + "/providers/" + p.id
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
	// serviceAccountTokenLifetime is the IAM fake's tokens' lifetime, unless
	// WithServiceAccountTokenLifetime sets another.
	serviceAccountTokenLifetime = time.Hour

	// The provider states, as Google names them [PROV].
	providerActive  = "ACTIVE"
	providerDeleted = "DELETED"
	// deletedProviderKept is how long a DELETED provider is kept before it is
	// purged, its expireTime [PROV; inf]. The fake purges nothing.
	deletedProviderKept = 30 * 24 * time.Hour

	// D3's attribute mapping, and its condition's fixed parts around the
	// role ID: assertion.issuer.dn.cn == '<id>' && assertion.subject.dn.cn == '<id>'.
	mappingSubject      = "google.subject"
	mappingIssuerCN     = "assertion.issuer.dn.cn"
	conditionIssuerPart = "assertion.issuer.dn.cn == '"
	conditionMiddle     = "' && assertion.subject.dn.cn == '"
	conditionEnd        = "'"
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

// WithIAMAPIAnswer does the same for the IAM API fake: every request, a
// provider's get and a list's every page alike, is answered code with body,
// before its bearer is looked at.
func WithIAMAPIAnswer(code int, body string) FederationOption {
	return func(c *federationConfig) { c.iamAPIAnswer = &federationAnswer{code: code, body: []byte(body)} }
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

// WithServiceAccountTokenLifetime sets how long each service-account token
// the IAM Credentials fake issues lives (default an hour): its expireTime,
// and the moment from which the IAM API fake and a Server given
// WithFederation stop taking it. Zero or less issues a token that has already
// expired, for a test of that rule.
func WithServiceAccountTokenLifetime(d time.Duration) FederationOption {
	return func(c *federationConfig) { c.serviceAccountLife = d }
}

// FederationRequest is one request a fake's handler saw.
type FederationRequest struct {
	Server       string // "sts", "iam" (IAM Credentials) or "iamapi" (IAM's API)
	Method, Path string
	RawQuery     string // the query as sent, without its "?"
	ContentType  string
	UserAgent    string
	// Headers are the request's header names, canonical and sorted, without
	// the three net/http adds itself (Accept-Encoding, Connection,
	// Content-Length). Authorization is listed by name; its value is never
	// recorded.
	Headers          []string
	PeerCertificates [][]byte   // what this request's connection presented; nil for none
	Form             url.Values // STS: the parsed form (public material only)
	Body             []byte     // IAM Credentials: the JSON body (no secret)
	// As is who the bearer authorised the request as: at IAM Credentials the
	// role ID whose federated token it carried, at IAM's API the service
	// account whose token it carried; "" with no Authorization header, "?"
	// for one that carries no live token of the kind the server takes.
	As string
}

// FederationHandshake is one completed or attempted handshake, recorded by
// the server's tls.Config.VerifyConnection, independently of any request.
type FederationHandshake struct {
	Server           string   // "sts", "iam" or "iamapi"
	PeerCertificates [][]byte // empty when the client presented none
	Version          uint16
}

// NewFederation starts the three fakes on 127.0.0.1:0 and registers
// t.Cleanup to stop them.
func NewFederation(t testing.TB, opts ...FederationOption) *Federation {
	t.Helper()
	f, err := StartFederation(opts...)
	if err != nil {
		t.Fatalf("kubetest: %v", err)
	}
	t.Cleanup(f.Close)
	return f
}

// StartFederation is NewFederation for the rehearsal: no testing.TB, and the
// caller closes it.
func StartFederation(opts ...FederationOption) (*Federation, error) {
	cfg := federationConfig{expiresIn: defaultExpiresIn, serviceAccountLife: serviceAccountTokenLifetime}
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
		cfg:             cfg,
		roots:           roots,
		stsDone:         make(chan struct{}),
		iamDone:         make(chan struct{}),
		iamAPIDone:      make(chan struct{}),
		providers:       map[string]federationProvider{},
		bindings:        map[string][]string{},
		federated:       map[string]string{},
		serviceAccounts: map[string]ServiceAccountToken{},
		poolViewers:     map[string]bool{},
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
	var raws []net.Listener
	for _, what := range []string{"the STS fake", "the IAM Credentials fake", "the IAM API fake"} {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			for _, r := range raws {
				_ = r.Close()
			}
			return nil, fmt.Errorf("listen for %s: %w", what, err)
		}
		raws = append(raws, l)
	}
	stsRaw, iamRaw, iamAPIRaw := raws[0], raws[1], raws[2]
	f.stsAddr = stsRaw.Addr().String()
	f.iamAddr = iamRaw.Addr().String()
	f.iamAPIAddr = iamAPIRaw.Addr().String()

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

	f.iamSrv = f.bearerServer(leaf, "iam", f.serveIAM)
	go func() {
		defer close(f.iamDone)
		_ = f.iamSrv.ServeTLS(iamRaw, "", "")
	}()
	f.iamAPISrv = f.bearerServer(leaf, "iamapi", f.serveIAMAPI)
	go func() {
		defer close(f.iamAPIDone)
		_ = f.iamAPISrv.ServeTLS(iamAPIRaw, "", "")
	}()
	return f, nil
}

// bearerServer is IAM Credentials' or IAM's API's server: the leaf, TLS 1.2
// or later, HTTP/2 or HTTP/1.1, and a client certificate asked for
// (RequestClientCert) but never needed, so the record shows whether a client
// sent one.
func (f *Federation) bearerServer(leaf tls.Certificate, server string, h http.HandlerFunc) *http.Server {
	return &http.Server{
		Handler: h,
		TLSConfig: &tls.Config{
			Certificates:     []tls.Certificate{leaf},
			MinVersion:       tls.VersionTLS12,
			ClientAuth:       tls.RequestClientCert,
			VerifyConnection: f.recordHandshake(server),
		},
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
}

// STSAddr is the STS fake's "127.0.0.1:<port>".
func (f *Federation) STSAddr() string { return f.stsAddr }

// IAMAddr is the IAM Credentials fake's "127.0.0.1:<port>".
func (f *Federation) IAMAddr() string { return f.iamAddr }

// IAMAPIAddr is the IAM API fake's "127.0.0.1:<port>".
func (f *Federation) IAMAPIAddr() string { return f.iamAPIAddr }

// Roots is a pool holding the one CA that issued the three fakes' leaf.
func (f *Federation) Roots() *x509.CertPool { return f.roots.Clone() }

// AddProvider adds a provider, ACTIVE and enabled, in place of any it
// replaces: its audience is kube.Audience(projectNumber, pool, provider); its
// trust store anchorDER alone, kept as PEM; its mapping and condition D3's,
// pinning roleID, which is a role ID's 32 lowercase hex. It panics on an
// audience kube.Audience refuses, an anchor that does not parse or a role ID
// out of that shape, as AddKey does on its own bad input.
func (f *Federation) AddProvider(projectNumber, pool, provider string, anchorDER []byte, roleID string) {
	aud, err := kube.Audience(projectNumber, pool, provider)
	if err != nil {
		panic("kubetest: AddProvider: the audience's parts are not Google's shape")
	}
	anchor, err := x509.ParseCertificate(anchorDER)
	if err != nil {
		panic("kubetest: AddProvider: the anchor is not a certificate")
	}
	if !isRoleID(roleID) {
		panic("kubetest: AddProvider: the role ID is not 32 lowercase hex")
	}
	anchors := x509.NewCertPool()
	anchors.AddCert(anchor)
	p := federationProvider{
		project:    projectNumber,
		pool:       pool,
		id:         provider,
		anchorsPEM: []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: anchor.Raw}))},
		anchors:    anchors,
		mapping:    map[string]string{mappingSubject: mappingIssuerCN},
		condition:  conditionIssuerPart + roleID + conditionMiddle + roleID + conditionEnd,
		state:      providerActive,
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.providers[aud] = p
}

// RemoveProvider deletes a provider as Google does: it is kept, DELETED, with
// an expireTime 30 days on [PROV; inf]. A get still answers it, with its
// state; a list shows it only under showDeleted=true; STS refuses it. It
// panics on a provider AddProvider never added.
func (f *Federation) RemoveProvider(projectNumber, pool, provider string) {
	f.editProvider("RemoveProvider", projectNumber, pool, provider, func(p *federationProvider) {
		p.state = providerDeleted
		p.expireTime = time.Now().UTC().Add(deletedProviderKept)
	})
}

// DisableProvider disables a provider: STS refuses it, and a get or a list
// shows "disabled": true. It panics on a provider AddProvider never added.
func (f *Federation) DisableProvider(projectNumber, pool, provider string) {
	f.editProvider("DisableProvider", projectNumber, pool, provider, func(p *federationProvider) { p.disabled = true })
}

func (f *Federation) editProvider(what, projectNumber, pool, provider string, edit func(*federationProvider)) {
	aud, err := kube.Audience(projectNumber, pool, provider)
	if err != nil {
		panic("kubetest: " + what + ": the provider's parts are not Google's shape")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.providers[aud]
	if !ok {
		panic("kubetest: " + what + ": no such provider")
	}
	edit(&p)
	f.providers[aud] = p
}

// Bind grants roleID's principal the right to impersonate serviceAccount.
func (f *Federation) Bind(roleID, serviceAccount string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !slices.Contains(f.bindings[roleID], serviceAccount) {
		f.bindings[roleID] = append(f.bindings[roleID], serviceAccount)
	}
}

// Unbind takes back what Bind granted: from then on generateAccessToken for
// serviceAccount with roleID's federated token answers 403. Tokens already
// issued keep working until they expire, as Google's do.
func (f *Federation) Unbind(roleID, serviceAccount string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	kept := slices.DeleteFunc(slices.Clone(f.bindings[roleID]), func(sa string) bool { return sa == serviceAccount })
	if len(kept) == 0 {
		delete(f.bindings, roleID)
		return
	}
	f.bindings[roleID] = kept
}

// GrantPoolViewer grants serviceAccount roles/iam.workloadIdentityPoolViewer
// on the project, as M3a's setup does: only such an account's token may read
// the IAM API fake's providers. It panics on an empty email.
func (f *Federation) GrantPoolViewer(serviceAccount string) {
	if serviceAccount == "" {
		panic("kubetest: GrantPoolViewer needs a service account's email")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.poolViewers[serviceAccount] = true
}

// RevokeFederatedTokens makes every federated token the STS fake has issued
// so far unknown, so IAM Credentials answers 401 to each from then on, as it
// would to an expired one. A fresh exchange gets a token that works. Service
// account tokens already issued are kept.
func (f *Federation) RevokeFederatedTokens() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.federated = map[string]string{}
}

// Requests is every request the three handlers saw, in order. Each is the
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

// Handshakes is every handshake the three servers' VerifyConnection saw, in
// order.
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

// Close stops the three fakes and waits for them. It may be called more than
// once.
func (f *Federation) Close() {
	f.closeOnce.Do(func() {
		_ = f.stsSrv.Close()
		_ = f.stsLn.Close()
		<-f.stsDone
		f.stsLn.wait()
		_ = f.iamSrv.Close()
		<-f.iamDone
		_ = f.iamAPISrv.Close()
		<-f.iamAPIDone
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

// newFederationRequest is r as recorded, before its body, form and As are
// set.
func newFederationRequest(server string, r *http.Request) FederationRequest {
	req := FederationRequest{
		Server:      server,
		Method:      r.Method,
		Path:        r.URL.Path,
		RawQuery:    r.URL.RawQuery,
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
	// 3. The provider, ACTIVE and enabled.
	f.mu.Lock()
	p, ok := f.providers[form.Get("audience")]
	f.mu.Unlock()
	switch {
	case !ok:
		refuse("invalid_target", "the audience names no provider")
		return
	case p.state != providerActive || p.disabled:
		refuse("invalid_target", "the audience's provider is deleted or disabled")
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
	roleID, ok := conditionRoleID(p.condition)
	if !ok || issuerCN != roleID || chain[0].Subject.CommonName != roleID {
		writeJSON(w, http.StatusBadRequest, oauthError{Error: "unauthorized_client", Description: "the provider's condition does not hold"})
		return
	}
	// 8. The token, for the principal D3's mapping names: the issuer's CN.
	f.mu.Lock()
	token := f.newFederationToken("federated")
	f.federated[token] = issuerCN
	f.mu.Unlock()
	writeJSON(w, http.StatusOK, stsAnswer{
		AccessToken:     token,
		IssuedTokenType: kube.TokenTypeAccessToken,
		TokenType:       "Bearer",
		ExpiresIn:       f.cfg.expiresIn,
	})
}

// conditionRoleID reads D3's condition, exactly
// assertion.issuer.dn.cn == '<id>' && assertion.subject.dn.cn == '<id>' with
// one role ID in both places, and returns the ID; false for any other text.
func conditionRoleID(condition string) (string, bool) {
	rest, ok := strings.CutPrefix(condition, conditionIssuerPart)
	if !ok {
		return "", false
	}
	first, rest, ok := strings.Cut(rest, conditionMiddle)
	if !ok {
		return "", false
	}
	second, ok := strings.CutSuffix(rest, conditionEnd)
	if !ok || first != second || !isRoleID(first) {
		return "", false
	}
	return first, true
}

// isRoleID is ^[0-9a-f]{32}$, a role ID's hex (D2).
func isRoleID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := range len(s) {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
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
	scopes := impersonationScopes(body)
	switch {
	case !isGAT:
		fail(http.StatusNotFound, "NOT_FOUND", "the IAM Credentials fake answers generateAccessToken only")
	case r.Method != http.MethodPost:
		fail(http.StatusMethodNotAllowed, "INVALID_ARGUMENT", "generateAccessToken takes POST only")
	case !known:
		fail(http.StatusUnauthorized, "UNAUTHENTICATED", "the bearer is not a federated token the STS fake issued")
	case readErr != nil || scopes == nil:
		fail(http.StatusBadRequest, "INVALID_ARGUMENT", "the body is not exactly scope and lifetime, with one of kube's closed scope lists and 3600s")
	case !f.bound(roleID, email):
		fail(http.StatusForbidden, "PERMISSION_DENIED", "the principal may not impersonate this service account")
	default:
		expires := time.Now().UTC().Add(f.cfg.serviceAccountLife)
		f.mu.Lock()
		token := f.newFederationToken("sa")
		f.serviceAccounts[token] = ServiceAccountToken{RoleID: roleID, Email: email, Scopes: scopes, Expires: expires}
		f.mu.Unlock()
		writeJSON(w, http.StatusOK, iamAnswer{
			AccessToken: token,
			ExpireTime:  expires.Format(time.RFC3339Nano),
		})
	}
}

// ServiceAccountTokens is what each service-account token the IAM Credentials
// fake issued was issued for, in no fixed order, without the tokens'
// values. Each is the caller's own copy.
func (f *Federation) ServiceAccountTokens() []ServiceAccountToken {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]ServiceAccountToken, 0, len(f.serviceAccounts))
	for _, sa := range f.serviceAccounts {
		sa.Scopes = slices.Clone(sa.Scopes)
		out = append(out, sa)
	}
	return out
}

// liveServiceAccount is what token was issued for, while it is a
// service-account token the IAM Credentials fake issued and has not expired.
func (f *Federation) liveServiceAccount(token string) (ServiceAccountToken, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	sa, ok := f.serviceAccounts[token]
	if !ok || !time.Now().Before(sa.Expires) {
		return ServiceAccountToken{}, false
	}
	sa.Scopes = slices.Clone(sa.Scopes)
	return sa, true
}

// clusterServiceAccount is the service account a cluster request's token
// authenticates as (WithFederation): a live service-account token minted
// with exactly kube.ScopesCluster's scopes, and no other [inf: the fake's
// rule; what GKE answers a storage- or registry-scoped token is
// [unverified]].
func (f *Federation) clusterServiceAccount(token string) (string, bool) {
	sa, ok := f.liveServiceAccount(token)
	if !ok || !slices.Equal(sa.Scopes, kube.ScopesCluster.List()) {
		return "", false
	}
	return sa.Email, true
}

func (f *Federation) bound(roleID, email string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Contains(f.bindings[roleID], email)
}

// poolViewer reports whether GrantPoolViewer granted email.
func (f *Federation) poolViewer(email string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.poolViewers[email]
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

// impersonationScopes reads a generateAccessToken body by its exact keys:
// scope and lifetime, and nothing else, with lifetime "3600s" and scope
// exactly one of kube's closed list, in its order: ScopesCluster's,
// ScopesStorage's or ScopesRegistry's. It returns the scopes, or nil for a
// body it refuses. encoding/json would match a struct's keys
// case-insensitively, so a {"Scope":…} body would pass one.
func impersonationScopes(body []byte) []string {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil || len(m) != 2 {
		return nil
	}
	rawScope, ok1 := m["scope"]
	rawLifetime, ok2 := m["lifetime"]
	if !ok1 || !ok2 {
		return nil
	}
	var lifetime string
	if err := json.Unmarshal(rawLifetime, &lifetime); err != nil || lifetime != "3600s" {
		return nil
	}
	var scopes []string
	if err := json.Unmarshal(rawScope, &scopes); err != nil {
		return nil
	}
	for _, s := range []kube.Scopes{kube.ScopesCluster, kube.ScopesStorage, kube.ScopesRegistry} {
		if slices.Equal(scopes, s.List()) {
			return scopes
		}
	}
	return nil
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
