package kube

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"cloud.google.com/go/auth"
)

// This file is the identity path's wire code (ADR 0024 decision 8, design
// D5 and D6): the mTLS token exchange at STS and generateAccessToken at IAM
// Credentials. Nothing calls it until M3b, so the linker drops it, and it
// holds no init-time state: no init function, no package-level variable
// whose value is a call (a conversion included), and no regexp. Every shape
// check is a byte loop. TestFederatedHasNoInitTimeState holds that.

// The identity path's fixed values (ADR 0024 decision 8, design D5 and D6).
// Every URL is built from these constants, never read from a file, a flag or
// the environment. The audience and the paths are built only by the functions
// below.
const (
	// STSMTLSHost is STS's mTLS token endpoint's host, and STSTokenPath its
	// path [X509, fetched 2026-11-22: https://sts.mtls.googleapis.com/v1/token].
	STSMTLSHost  = "sts.mtls.googleapis.com"
	STSTokenPath = "/v1/token"

	// IAMCredentialsHost is IAM Credentials' service endpoint [IAMC-SVC; GAT;
	// X509's generateAccessToken example uses it with the STS token as bearer].
	IAMCredentialsHost = "iamcredentials.googleapis.com"

	// The token exchange's fixed values [STS; X509; vendored
	// cloud.google.com/go/auth/credentials/internal/stsexchange/sts_exchange.go:35-37].
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	TokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeMTLS          = "urn:ietf:params:oauth:token-type:mtls" // [X509, STS]; not a vendored constant

	// ImpersonationLifetime is generateAccessToken's lifetime, sent "3600s"
	// [GAT: default 1 h, the maximum without an org policy] (D5).
	ImpersonationLifetime = time.Hour

	maxFederationAnswer    = 64 << 10         // read +1 and refused, never truncated
	maxFederatedToken      = 12288            // STS's documented access_token bound [STS]
	maxServiceAccountToken = 8192             // [inf]: generateAccessToken's tokens are far smaller
	federationTimeout      = 30 * time.Second // per call, as tokenTimeout

	// exchangeMinTLS is the exchange transport's floor (spec v2 §7 Q4). In
	// TLS 1.2 the client's Certificate message, the leaf with its role ID,
	// crosses the network in clear; in TLS 1.3 it is encrypted. The
	// impersonation transport, which carries no certificate, keeps D6's TLS
	// 1.2 floor.
	exchangeMinTLS = tls.VersionTLS13
)

// The identity path's other fixed values.
const (
	// mediaForm is the exchange's body type, the one Google's own Go library
	// posts (vendored sts_exchange.go:66-85).
	mediaForm = "application/x-www-form-urlencoded"

	// scopePrefix is what every scope an exchange may ask for starts with.
	scopePrefix = "https://www.googleapis.com/auth/"

	// The audience's fixed parts [X509, STS].
	audiencePrefix   = "//iam.googleapis.com/projects/"
	audiencePools    = "/locations/global/workloadIdentityPools/"
	audienceProvider = "/providers/"

	// The generateAccessToken path's fixed parts [GAT: the - wildcard is
	// required].
	generateAccessTokenPrefix = "/v1/projects/-/serviceAccounts/"
	generateAccessTokenSuffix = ":generateAccessToken"

	// maxFederationHeader caps an answer's headers on both transports.
	maxFederationHeader = 64 << 10

	// The words an answer that is not a token's gives in place of a field.
	answerOversize  = "the answer is larger than 64 KiB"
	answerNotObject = "the answer is not a JSON object"
	// alertUnshaped stands for a TLS alert whose words are not in the alert
	// shape, so they are not carried.
	alertUnshaped = "a TLS alert"

	// The fixed texts every formatting of the identity path's types gives.
	clientIdentityText  = "client identity (not printed)"
	exchangeRequestText = "exchange request (not printed)"
	exchangeAnswerText  = "exchange answer (not printed)"
)

// Audience is a provider's audience [X509, STS]:
//
//	//iam.googleapis.com/projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>
//
// projectNumber is ^[0-9]{1,20}$. pool and provider are ^[a-z0-9-]{4,32}$,
// not starting "gcp-" [MGMT]. The error names the part, never the value. It
// takes no project ID: M3a's I5 builds its own audience string.
func Audience(projectNumber, pool, provider string) (string, error) {
	switch {
	case !isProjectNumber(projectNumber):
		return "", refuse(ErrCredentialInvalid, msgFederationRequest, "audience (project number)")
	case !isPoolOrProviderID(pool):
		return "", refuse(ErrCredentialInvalid, msgFederationRequest, "audience (pool)")
	case !isPoolOrProviderID(provider):
		return "", refuse(ErrCredentialInvalid, msgFederationRequest, "audience (provider)")
	}
	return audiencePrefix + projectNumber + audiencePools + pool + audienceProvider + provider, nil
}

// checkAudience is Exchange's own guard on its audience before anything is
// sent: the documented shape, with the project segment either a number or a
// project ID (^[a-z][a-z0-9-]{4,28}[a-z0-9]$). It guards against a malformed
// or injected audience; it builds nothing. The ID form is admitted for M3a's
// I5, which asks whether STS takes it; M3b narrows the guard to the number
// form once I5 is recorded.
func checkAudience(aud string) bool {
	rest, ok := strings.CutPrefix(aud, audiencePrefix)
	if !ok {
		return false
	}
	project, rest, ok := strings.Cut(rest, "/")
	if !ok || (!isProjectNumber(project) && !isProjectID(project)) {
		return false
	}
	rest, ok = strings.CutPrefix("/"+rest, audiencePools)
	if !ok {
		return false
	}
	pool, provider, ok := strings.Cut(rest, audienceProvider)
	return ok && isPoolOrProviderID(pool) && isPoolOrProviderID(provider)
}

// SubjectToken is the mTLS subject_token: a compact JSON array of the chain's
// DER certificates, each base64.StdEncoding (padded), the leaf first [X509;
// vendored x509_provider.go:72-76, :150-198]. Each DER must parse as a
// certificate; an empty chain is refused.
func SubjectToken(chain [][]byte) (string, error) {
	if len(chain) == 0 {
		return "", refuse(ErrCredentialInvalid, msgFederationRequest, "subject token")
	}
	var b strings.Builder
	b.WriteByte('[')
	for i, der := range chain {
		if _, err := x509.ParseCertificate(der); err != nil {
			return "", refuse(ErrCredentialInvalid, msgFederationRequest, "subject token")
		}
		if i > 0 {
			b.WriteByte(',')
		}
		// The standard alphabet is A-Z, a-z, 0-9, + and / with = padding, none
		// of which JSON escapes, so quoting is the whole encoding.
		b.WriteByte('"')
		b.WriteString(base64.StdEncoding.EncodeToString(der))
		b.WriteByte('"')
	}
	b.WriteByte(']')
	return b.String(), nil
}

// ExchangeForm is the form-encoded body Exchange posts: exactly audience,
// grant_type, requested_token_type, subject_token_type, subject_token and
// scope (space-joined), with no options, no client_id and no client_secret.
// It is application/x-www-form-urlencoded, the shape Google's own Go library
// sends (vendored sts_exchange.go:66-85, externalaccount.go:302) [read]. The
// X509 page's curl sends JSON; which shapes STS takes is [unverified].
func ExchangeForm(audience, subjectTokenType, subjectToken string, scopes []string) string {
	return url.Values{
		"audience":             {audience},
		"grant_type":           {GrantTypeTokenExchange},
		"requested_token_type": {TokenTypeAccessToken},
		"subject_token_type":   {subjectTokenType},
		"subject_token":        {subjectToken},
		"scope":                {strings.Join(scopes, " ")},
	}.Encode()
}

// ImpersonationBody is generateAccessToken's body, byte for byte:
//
//	{"scope":["https://www.googleapis.com/auth/cloud-platform","https://www.googleapis.com/auth/userinfo.email"],"lifetime":"3600s"}
//
// The fields are in the GAT reference's order (delegates, scope, lifetime,
// with no delegates) [GAT, fetched 2026-11-22], and the scopes in
// TokenScopes()'s order (D5). The vendored struct marshals lifetime first
// (impersonate.go:41-45), so it is not the source. The order matters to
// neither server; the test pins this one.
func ImpersonationBody() []byte {
	var b bytes.Buffer
	b.WriteString(`{"scope":[`)
	for i, s := range TokenScopes() {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Quote(s)) // a fixed URL: Go's quoting is JSON's here
	}
	b.WriteString(`],"lifetime":"`)
	b.WriteString(impersonationLifetimeText())
	b.WriteString(`"}`)
	return b.Bytes()
}

// impersonationLifetimeText is ImpersonationLifetime as generateAccessToken
// takes it: whole seconds with an s, "3600s".
func impersonationLifetimeText() string {
	return strconv.FormatInt(int64(ImpersonationLifetime/time.Second), 10) + "s"
}

// GenerateAccessTokenPath is "/v1/projects/-/serviceAccounts/" + email +
// ":generateAccessToken" [GAT: the - wildcard is required]. email must match
// ^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$
// (checked by hand, not by regexp). The error never contains the email.
func GenerateAccessTokenPath(serviceAccount string) (string, error) {
	if !isServiceAccountEmail(serviceAccount) {
		return "", refuse(ErrCredentialInvalid, msgFederationRequest, "service account")
	}
	return generateAccessTokenPrefix + serviceAccount + generateAccessTokenSuffix, nil
}

// The identity path's three value types hold their contents two pointers
// deep, as devicekey.RoleID and devicekey.Identity do, so none of them ever
// formats what it holds. fmt calls Format, String or GoString only on a
// value it can reach as an interface, which a value inside a caller's
// unexported field is not; it then walks the raw fields, and under a verb a
// pointer does not take (%s, %q) its badVerb prints the pointer again at
// depth 0 (go1.27.4 src/fmt/print.go:384-387), where a pointer to a struct is
// dereferenced (:905-910). A pointer to a pointer is printed as an address at
// every depth. So a ClientIdentity's chain (whose leaf CN is a role ID), an
// ExchangeRequest's audience (a project number, a pool and a provider ID) and
// an ExchangeAnswer's federated token print as their fixed text, as an
// address, or as {} under encoding/json, wherever a caller holds them.

// ClientIdentity is what a handshake presents: the chain sent, leaf first,
// and the leaf's key. The zero ClientIdentity presents no certificate. It
// formats as "client identity (not printed)".
type ClientIdentity struct{ p **clientIdentity }

type clientIdentity struct {
	chain  [][]byte
	signer crypto.Signer
}

// NewClientIdentity is a ClientIdentity presenting chain, leaf first, with
// signer, the leaf's key. It copies chain; Exchange checks both before
// anything is sent.
func NewClientIdentity(chain [][]byte, signer crypto.Signer) ClientIdentity {
	v := &clientIdentity{chain: cloneChain(chain), signer: signer}
	return ClientIdentity{p: &v}
}

// get is the identity's contents; nil for the zero ClientIdentity.
func (c ClientIdentity) get() *clientIdentity {
	if c.p == nil {
		return nil
	}
	return *c.p
}

// IsZero reports whether c is the zero ClientIdentity, which presents no
// certificate.
func (c ClientIdentity) IsZero() bool { return c.get() == nil }

// Chain is a copy of the chain, leaf first; nil for the zero ClientIdentity.
func (c ClientIdentity) Chain() [][]byte {
	if v := c.get(); v != nil {
		return cloneChain(v.chain)
	}
	return nil
}

// Signer is the leaf's key; nil for the zero ClientIdentity.
func (c ClientIdentity) Signer() crypto.Signer {
	if v := c.get(); v != nil {
		return v.signer
	}
	return nil
}

// String is "client identity (not printed)".
func (c ClientIdentity) String() string { return clientIdentityText }

// GoString is "client identity (not printed)".
func (c ClientIdentity) GoString() string { return clientIdentityText }

// Format writes "client identity (not printed)" for every verb.
func (c ClientIdentity) Format(f fmt.State, verb rune) {
	_, _ = io.WriteString(f, clientIdentityText)
}

// LogValue is slog.StringValue("client identity (not printed)").
func (c ClientIdentity) LogValue() slog.Value { return slog.StringValue(clientIdentityText) }

// MarshalJSON is the JSON string "client identity (not printed)". slog's
// JSONHandler encodes a struct attribute with encoding/json, which calls no
// LogValue below the top.
func (c ClientIdentity) MarshalJSON() ([]byte, error) { return json.Marshal(clientIdentityText) }

// ExchangeRequest is one exchange. It formats as "exchange request (not
// printed)".
type ExchangeRequest struct{ p **exchangeRequest }

type exchangeRequest struct {
	audience string
	tls      ClientIdentity
	subject  [][]byte
	scopes   []string
}

// NewExchangeRequest is one exchange. M3b's callers pass an audience and a
// client identity, with subject and scopes nil; the other two exist for
// M3a's chain shapes and negatives:
//   - audience: from Audience (Exchange's guard also admits I5's project-ID
//     form);
//   - client: what the handshake presents; the zero ClientIdentity presents no
//     client certificate at all (M3a's N6);
//   - subject: subject_token's chain, leaf first; nil: client's chain;
//   - scopes: nil or empty: [ScopeCloudPlatform] (D5); M3a's I2 sends two.
//
// It copies subject and scopes.
func NewExchangeRequest(audience string, client ClientIdentity, subject [][]byte, scopes []string) ExchangeRequest {
	var sc []string
	if scopes != nil {
		sc = append(make([]string, 0, len(scopes)), scopes...)
	}
	v := &exchangeRequest{audience: audience, tls: client, subject: cloneChain(subject), scopes: sc}
	return ExchangeRequest{p: &v}
}

// get is the request's contents; the zero request's are empty.
func (r ExchangeRequest) get() *exchangeRequest {
	if r.p == nil || *r.p == nil {
		return &exchangeRequest{}
	}
	return *r.p
}

// String is "exchange request (not printed)".
func (r ExchangeRequest) String() string { return exchangeRequestText }

// GoString is "exchange request (not printed)".
func (r ExchangeRequest) GoString() string { return exchangeRequestText }

// Format writes "exchange request (not printed)" for every verb.
func (r ExchangeRequest) Format(f fmt.State, verb rune) {
	_, _ = io.WriteString(f, exchangeRequestText)
}

// LogValue is slog.StringValue("exchange request (not printed)").
func (r ExchangeRequest) LogValue() slog.Value { return slog.StringValue(exchangeRequestText) }

// MarshalJSON is the JSON string "exchange request (not printed)", for the
// reason ClientIdentity's is.
func (r ExchangeRequest) MarshalJSON() ([]byte, error) { return json.Marshal(exchangeRequestText) }

// ExchangeAnswer is STS's answer. Exchange refuses an issued_token_type other
// than TokenTypeAccessToken and a token_type other than Bearer, so neither is
// returned. It formats as "exchange answer (not printed)"; a caller prints
// ExpiresIn and TLSVersion by name.
type ExchangeAnswer struct{ p **answerFields }

type answerFields struct {
	token      *auth.Token
	expiresIn  time.Duration
	tlsVersion uint16
}

// newExchangeAnswer holds an exchange's token, its stated lifetime and the
// negotiated TLS version.
func newExchangeAnswer(tok *auth.Token, expiresIn time.Duration, tlsVersion uint16) ExchangeAnswer {
	v := &answerFields{token: tok, expiresIn: expiresIn, tlsVersion: tlsVersion}
	return ExchangeAnswer{p: &v}
}

// get is the answer's contents; the zero answer's are empty.
func (a ExchangeAnswer) get() *answerFields {
	if a.p == nil || *a.p == nil {
		return &answerFields{}
	}
	return *a.p
}

// Token is the federated token: Value; Type "Bearer"; Expiry = received +
// ExpiresIn, on the wall clock. nil for the zero ExchangeAnswer.
func (a ExchangeAnswer) Token() *auth.Token { return a.get().token }

// ExpiresIn is expires_in, as STS stated it.
func (a ExchangeAnswer) ExpiresIn() time.Duration { return a.get().expiresIn }

// TLSVersion is what the exchange's handshake negotiated (resp.TLS.Version).
func (a ExchangeAnswer) TLSVersion() uint16 { return a.get().tlsVersion }

// String is "exchange answer (not printed)".
func (a ExchangeAnswer) String() string { return exchangeAnswerText }

// GoString is "exchange answer (not printed)".
func (a ExchangeAnswer) GoString() string { return exchangeAnswerText }

// Format writes "exchange answer (not printed)" for every verb.
func (a ExchangeAnswer) Format(f fmt.State, verb rune) {
	_, _ = io.WriteString(f, exchangeAnswerText)
}

// LogValue is slog.StringValue("exchange answer (not printed)").
func (a ExchangeAnswer) LogValue() slog.Value { return slog.StringValue(exchangeAnswerText) }

// MarshalJSON is the JSON string "exchange answer (not printed)".
func (a ExchangeAnswer) MarshalJSON() ([]byte, error) { return json.Marshal(exchangeAnswerText) }

// cloneChain copies a chain and each of its certificates; nil stays nil, and
// an empty chain stays empty, not nil.
func cloneChain(chain [][]byte) [][]byte {
	if chain == nil {
		return nil
	}
	out := make([][]byte, len(chain))
	for i, der := range chain {
		out[i] = bytes.Clone(der)
	}
	return out
}

// Federation exchanges a role's leaf at STS's mTLS endpoint, and impersonates
// the role's service account at IAM Credentials.
type Federation struct {
	sts, iam      federationHost
	now           func() time.Time // wallNow
	impersonation *http.Client
}

// federationHost is one destination: its origin, the name TLS verifies, its
// roots (nil: the system's), and, in loopback (test) mode, the one address the
// dialer may reach.
type federationHost struct {
	origin     string // "https://" + host[:port]
	host       string // the URL.Host a request must name exactly
	serverName string // tls.Config.ServerName
	roots      *x509.CertPool
	dialOnly   string // "" in Google mode
}

// googleFederationHost is a Google host on port 443, verified on the
// system roots under its own name.
func googleFederationHost(host string) federationHost {
	return federationHost{origin: "https://" + host, host: host, serverName: host}
}

// dialContext is the host's dialer: 30 s, and in loopback mode a Control
// that refuses every address but dialOnly before a connection is made.
func (h federationHost) dialContext() func(ctx context.Context, network, address string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	if h.dialOnly != "" {
		allowed := h.dialOnly
		d.Control = func(_, address string, _ syscall.RawConn) error {
			if address != allowed {
				return fmt.Errorf(msgLoopbackRefused, address)
			}
			return nil
		}
	}
	return d.DialContext
}

// NewFederation is the product constructor: Google's hosts, the system roots.
// It takes no URL and reads no file. The one environment variable it reads is
// GODEBUG's http2debug, through UnsafeEnvironment, which it calls first:
// under http2debug it returns ErrUnsafeEnvironment's refusal (msgHTTP2Debug)
// and builds nothing.
func NewFederation() (*Federation, error) {
	return newFederation(googleFederationHost(STSMTLSHost), googleFederationHost(IAMCredentialsHost))
}

// newFederation builds a Federation for two hosts, after UnsafeEnvironment.
func newFederation(sts, iam federationHost) (*Federation, error) {
	if err := UnsafeEnvironment(); err != nil {
		return nil, err
	}
	f := &Federation{sts: sts, iam: iam, now: wallNow}
	f.impersonation = f.impersonationClient()
	return f, nil
}

// exchangeClient is a fresh client for one exchange: HTTP/1.1 only, TLS 1.3
// at least, no keep-alive and no session cache, so one handshake carries one
// identity and nothing is resumed. With an identity, GetClientCertificate
// returns its chain whatever CAs the server lists; Certificates stays nil,
// because with it Go sends no certificate when the server's list leaves the
// anchor out. Without one, the handshake presents no certificate.
func (f *Federation) exchangeClient(id ClientIdentity, leaf *x509.Certificate) (*http.Client, *http.Transport) {
	tc := &tls.Config{
		MinVersion: exchangeMinTLS,
		RootCAs:    f.sts.roots,
		ServerName: f.sts.serverName,
		NextProtos: []string{"http/1.1"},
	}
	if v := id.get(); v != nil {
		cert := &tls.Certificate{Certificate: v.chain, PrivateKey: v.signer, Leaf: leaf}
		tc.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return cert, nil }
	}
	tr := &http.Transport{
		Proxy:                  nil,
		DialContext:            f.sts.dialContext(),
		TLSClientConfig:        tc,
		TLSNextProto:           map[string]func(string, *tls.Conn) http.RoundTripper{}, // HTTP/1.1 only
		ForceAttemptHTTP2:      false,
		DisableKeepAlives:      true,
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  responseHeaderTimeout,
		MaxResponseHeaderBytes: maxFederationHeader,
	}
	return &http.Client{
		Transport:     &identityTransport{inner: tr, host: f.sts.host, bearer: false},
		Timeout:       federationTimeout,
		CheckRedirect: noRedirect,
	}, tr
}

// impersonationClient is the Federation's one client for IAM Credentials:
// TLS 1.2 at least, HTTP/2 allowed, keep-alive on, and no client certificate
// of any kind. Its transport alone adds the federated bearer.
func (f *Federation) impersonationClient() *http.Client {
	tr := &http.Transport{
		Proxy:                  nil,
		DialContext:            f.iam.dialContext(),
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: f.iam.roots, ServerName: f.iam.serverName},
		ForceAttemptHTTP2:      true,
		DisableKeepAlives:      false,
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  responseHeaderTimeout,
		MaxResponseHeaderBytes: maxFederationHeader,
		IdleConnTimeout:        90 * time.Second,
		MaxIdleConnsPerHost:    2,
	}
	return &http.Client{
		Transport:     &identityTransport{inner: tr, host: f.iam.host, bearer: true},
		Timeout:       federationTimeout,
		CheckRedirect: noRedirect,
	}
}

// federatedBearerKey carries a federated token on a request's context, from
// Impersonate to identityTransport. It is distinct from the cluster's
// bearerKey, so neither transport ever finds the other's token.
type federatedBearerKey struct{}

func withFederatedBearer(ctx context.Context, tok *auth.Token) context.Context {
	return context.WithValue(ctx, federatedBearerKey{}, tok)
}

func federatedBearerFrom(ctx context.Context) *auth.Token {
	tok, _ := ctx.Value(federatedBearerKey{}).(*auth.Token)
	return tok
}

// identityTransport is both identity clients' RoundTripper. It sends only to
// its own host, over https, and with only the headers it chooses:
// User-Agent: farcast, Accept: application/json, the caller's Content-Type
// when it is the form's or JSON's, and, on the impersonation client alone,
// the federated bearer from the request's context. Nothing else the caller
// set survives: no x-goog-api-client, no caller Authorization, no cookie.
type identityTransport struct {
	inner  http.RoundTripper
	host   string
	bearer bool
}

func (t *identityTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil || req.URL.Scheme != "https" || req.URL.Host != t.host {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, refuse(ErrEndpointRefused, msgFederationHost)
	}
	r := req.Clone(req.Context())
	r.Host = "" // the Host header is the URL's host, the one just checked
	h := http.Header{}
	h.Set("User-Agent", UserAgent)
	h.Set("Accept", mediaJSON)
	if ct := req.Header.Get("Content-Type"); ct == mediaForm || ct == mediaJSON {
		h.Set("Content-Type", ct)
	}
	if t.bearer {
		if tok := federatedBearerFrom(r.Context()); tok != nil && tok.Value != "" {
			h.Set("Authorization", "Bearer "+tok.Value)
		}
	}
	r.Header = h
	resp, err := t.inner.RoundTrip(r)
	if err == nil && resp != nil {
		dropUnparsableLocation(r.URL, resp)
	}
	return resp, err
}

// dropUnparsableLocation removes a redirect's Location header when it does
// not parse against the request's URL. http.Client parses Location before it
// asks CheckRedirect (go1.27.4 src/net/http/client.go:662-666), and a parse
// failure becomes a *url.Error whose words quote the header whole: remote
// text, which on the impersonation path may name a service account. Without
// the header the client returns the 3xx itself (:655-661), which Exchange and
// Impersonate read as the answer, a refusal with its status and no text. A
// Location that parses is left for noRedirect to refuse.
func dropUnparsableLocation(u *url.URL, resp *http.Response) {
	loc := resp.Header.Get("Location")
	if loc == "" || resp.StatusCode < 300 || resp.StatusCode > 399 {
		return
	}
	if _, err := u.Parse(loc); err != nil {
		resp.Header.Del("Location")
	}
}

// Exchange posts one exchange. Before sending, with nothing dialled, it
// refuses (msgFederationRequest, ErrCredentialInvalid):
//   - an audience checkAudience refuses;
//   - a client identity (not the zero ClientIdentity) with an empty chain, a
//     chain entry that does not parse, or a signer whose public key is not the
//     leaf's;
//   - no client identity and no subject;
//   - a subject entry that does not parse;
//   - a scope that is not https://www.googleapis.com/auth/ followed by [a-z0-9._-].
func (f *Federation) Exchange(ctx context.Context, r ExchangeRequest) (*ExchangeAnswer, error) {
	form, leaf, err := exchangeRequestForm(r)
	if err != nil {
		return nil, err
	}
	hc, tr := f.exchangeClient(r.get().tls, leaf)
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.sts.origin+STSTokenPath, strings.NewReader(form))
	if err != nil {
		return nil, refuse(ErrCredentialInvalid, msgFederationRequest, "request")
	}
	req.Header.Set("Content-Type", mediaForm)
	req.Header.Set("Accept", mediaJSON)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, classifyFailure(ctx, StepExchange, err, false)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := readFederationAnswer(resp.Body)
	if err != nil {
		return nil, classifyFailure(ctx, StepExchange, err, true)
	}
	return exchangeAnswer(resp.StatusCode, body, negotiated(resp), f.now())
}

// exchangeRequestForm checks r as Exchange's comment lists, in that order, and
// returns the form to post and the client certificate's parsed leaf (nil
// without one). Nil or empty scopes are cloud-platform alone (D5).
func exchangeRequestForm(req ExchangeRequest) (string, *x509.Certificate, error) {
	r := req.get()
	if !checkAudience(r.audience) {
		return "", nil, refuse(ErrCredentialInvalid, msgFederationRequest, "audience")
	}
	var leaf *x509.Certificate
	if !r.tls.IsZero() {
		var ok bool
		if leaf, ok = clientLeaf(r.tls); !ok {
			return "", nil, refuse(ErrCredentialInvalid, msgFederationRequest, "client certificate")
		}
	}
	subject := r.subject
	if subject == nil {
		if r.tls.IsZero() {
			return "", nil, refuse(ErrCredentialInvalid, msgFederationRequest, "subject token")
		}
		subject = r.tls.get().chain
	}
	token, err := SubjectToken(subject)
	if err != nil {
		return "", nil, err
	}
	scopes := r.scopes
	if len(scopes) == 0 {
		scopes = []string{ScopeCloudPlatform}
	}
	for _, s := range scopes {
		if !isScope(s) {
			return "", nil, refuse(ErrCredentialInvalid, msgFederationRequest, "scope")
		}
	}
	return ExchangeForm(r.audience, TokenTypeMTLS, token, scopes), leaf, nil
}

// clientLeaf parses a client identity's chain and returns its leaf, when the
// chain is not empty, every entry parses, and the Signer's public key is the
// leaf's.
func clientLeaf(id ClientIdentity) (*x509.Certificate, bool) {
	c := id.get()
	if c == nil || len(c.chain) == 0 || c.signer == nil {
		return nil, false
	}
	var leaf *x509.Certificate
	for i, der := range c.chain {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, false
		}
		if i == 0 {
			leaf = cert
		}
	}
	pub, ok := c.signer.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(leaf.PublicKey) {
		return nil, false
	}
	return leaf, true
}

// Impersonate calls generateAccessToken for serviceAccount, with federated as
// the bearer, TokenScopes() and ImpersonationLifetime. Before sending it
// refuses a nil or empty federated token and a malformed email. It does not
// check federated's expiry; Google decides that (M3a's P7 times exactly that).
func (f *Federation) Impersonate(ctx context.Context, federated *auth.Token, serviceAccount string) (*auth.Token, error) {
	if federated == nil || federated.Value == "" {
		return nil, refuse(ErrCredentialInvalid, msgFederationRequest, "federated token")
	}
	path, err := GenerateAccessTokenPath(serviceAccount)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, refuse(ErrCredentialInvalid, msgFederationRequest, "request")
	}
	req, err := http.NewRequestWithContext(withFederatedBearer(ctx, federated), http.MethodPost, f.iam.origin+path, bytes.NewReader(ImpersonationBody()))
	if err != nil {
		return nil, refuse(ErrCredentialInvalid, msgFederationRequest, "request")
	}
	req.Header.Set("Content-Type", mediaJSON)
	req.Header.Set("Accept", mediaJSON)
	resp, err := f.impersonation.Do(req)
	if err != nil {
		return nil, classifyFailure(ctx, StepImpersonate, err, false)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := readFederationAnswer(resp.Body)
	if err != nil {
		return nil, classifyFailure(ctx, StepImpersonate, err, true)
	}
	return impersonationAnswer(resp.StatusCode, body, negotiated(resp), f.now())
}

// negotiated is the TLS version an answer came over, 0 without TLS.
func negotiated(resp *http.Response) uint16 {
	if resp.TLS == nil {
		return 0
	}
	return resp.TLS.Version
}

// readFederationAnswer reads at most maxFederationAnswer+1 bytes, so an
// answer larger than the cap is seen as larger, never cut to fit.
func readFederationAnswer(r io.Reader) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, maxFederationAnswer+1))
}

// exchangeAnswer reads STS's answer. Only 200 is success; any other status,
// a 3xx included (no redirect is followed), is a refusal. A 200 is unusable
// unless it is a JSON object whose access_token is a non-empty string of at
// most 12288 bytes, issued_token_type is TokenTypeAccessToken, token_type is
// Bearer (any case) and expires_in is a JSON integer above 0. Unknown fields
// are ignored. The token expires at now + expires_in, now being the wall clock
// when the answer was read.
func exchangeAnswer(code int, body []byte, tlsVersion uint16, now time.Time) (*ExchangeAnswer, error) {
	if code != http.StatusOK {
		return nil, refusedAnswer(StepExchange, code, body, tlsVersion)
	}
	m, field := answerObject(body)
	if field != "" {
		return nil, unusableAnswer(StepExchange, field, tlsVersion)
	}
	tok, ok := jsonString(m["access_token"])
	if !ok || tok == "" || len(tok) > maxFederatedToken {
		return nil, unusableAnswer(StepExchange, "access_token", tlsVersion)
	}
	if t, ok := jsonString(m["issued_token_type"]); !ok || t != TokenTypeAccessToken {
		return nil, unusableAnswer(StepExchange, "issued_token_type", tlsVersion)
	}
	if t, ok := jsonString(m["token_type"]); !ok || !strings.EqualFold(t, "Bearer") {
		return nil, unusableAnswer(StepExchange, "token_type", tlsVersion)
	}
	secs, ok := jsonPositiveInteger(m["expires_in"])
	if !ok {
		return nil, unusableAnswer(StepExchange, "expires_in", tlsVersion)
	}
	life := time.Duration(secs) * time.Second
	ans := newExchangeAnswer(&auth.Token{Value: tok, Type: "Bearer", Expiry: now.Add(life)}, life, tlsVersion)
	return &ans, nil
}

// impersonationAnswer reads generateAccessToken's answer. Only 200 is
// success. A 200 is unusable unless its accessToken is a non-empty string of
// at most 8192 bytes and its expireTime an RFC 3339 time [GAT: 0, 3, 6 or 9
// fractional digits] after now. The token's Expiry is that time in UTC, with
// no monotonic reading.
func impersonationAnswer(code int, body []byte, tlsVersion uint16, now time.Time) (*auth.Token, error) {
	if code != http.StatusOK {
		return nil, refusedAnswer(StepImpersonate, code, body, tlsVersion)
	}
	m, field := answerObject(body)
	if field != "" {
		return nil, unusableAnswer(StepImpersonate, field, tlsVersion)
	}
	tok, ok := jsonString(m["accessToken"])
	if !ok || tok == "" || len(tok) > maxServiceAccountToken {
		return nil, unusableAnswer(StepImpersonate, "accessToken", tlsVersion)
	}
	s, ok := jsonString(m["expireTime"])
	if !ok {
		return nil, unusableAnswer(StepImpersonate, "expireTime", tlsVersion)
	}
	expiry, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || !expiry.After(now) {
		return nil, unusableAnswer(StepImpersonate, "expireTime", tlsVersion)
	}
	return &auth.Token{Value: tok, Type: "Bearer", Expiry: expiry.UTC().Round(0)}, nil
}

// answerObject decodes a 200's body into its fields, read by their exact
// names. field is "" on success, else the words for what the answer is.
func answerObject(body []byte) (map[string]json.RawMessage, string) {
	if len(body) > maxFederationAnswer {
		return nil, answerOversize
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil || m == nil {
		return nil, answerNotObject
	}
	return m, ""
}

// jsonString is a JSON string value; false for a missing field, null or any
// other kind.
func jsonString(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// jsonPositiveInteger is a JSON number written as digits alone (no sign,
// fraction or exponent), above 0, small enough to be a time.Duration in
// seconds.
func jsonPositiveInteger(raw json.RawMessage) (int64, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	for _, c := range raw {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil || n <= 0 || n > int64(math.MaxInt64/int64(time.Second)) {
		return 0, false
	}
	return n, true
}

// errorCodes reads a refusal's codes, never its words: STS's OAuth error, the
// top-level "error" string in its shape, and Google's error.status in its
// shape when "error" is an object. error_description and message are never
// read.
func errorCodes(body []byte) (oauth, status string) {
	var m map[string]json.RawMessage
	if json.Unmarshal(body, &m) != nil {
		return "", ""
	}
	raw := m["error"]
	if len(raw) == 0 {
		return "", ""
	}
	switch raw[0] {
	case '"':
		if s, ok := jsonString(raw); ok && isOAuthCode(s) {
			return s, ""
		}
	case '{':
		var e map[string]json.RawMessage
		if json.Unmarshal(raw, &e) == nil {
			if s, ok := jsonString(e["status"]); ok && isGoogleStatus(s) {
				return "", s
			}
		}
	}
	return "", ""
}

// refusedAnswer is a non-200 answer as an error: its status and StatusText,
// and its code when one is in its shape. An answer larger than the cap
// carries no code. IAM Credentials' is Google's error.status alone.
func refusedAnswer(step Step, code int, body []byte, tlsVersion uint16) error {
	var oauth, status string
	if len(body) <= maxFederationAnswer {
		oauth, status = errorCodes(body)
	}
	format := msgExchangeRefused
	if step == StepImpersonate {
		format, oauth = msgImpersonateRefused, ""
	}
	suffix := ""
	switch {
	case oauth != "":
		suffix = ", OAuth error " + oauth
	case status != "":
		suffix = ", status " + status
	}
	return &FederationError{
		Step:         step,
		Status:       code,
		OAuthError:   oauth,
		GoogleStatus: status,
		TLSVersion:   tlsVersion,
		msg:          fmt.Sprintf(format, code, http.StatusText(code), suffix),
		sentinel:     ErrTokenRefused,
	}
}

// unusableAnswer is a 200 the decoder refused, by the field that failed.
func unusableAnswer(step Step, field string, tlsVersion uint16) error {
	format := msgExchangeUnusable
	if step == StepImpersonate {
		format = msgImpersonateUnusable
	}
	return &FederationError{
		Step:       step,
		Status:     http.StatusOK,
		Field:      field,
		TLSVersion: tlsVersion,
		msg:        fmt.Sprintf(format, field),
		sentinel:   ErrUnreadable,
	}
}

// classifyFailure classifies a failure to send a call (reading false) or to
// read its answer (reading true), in this order:
//  1. the caller's own context ended: its error's fixed text, with it as the
//     cause;
//  2. the host guard's refusal, which is returned as it is;
//  3. a TLS alert from the server (*net.OpError "remote error"), with the
//     alert's words when they are in the alert shape, also in Alert. Before
//     any answer came (reading false) it ended the call at the handshake, or
//     in TLS 1.3 just after it: at the exchange a refusal at the handshake,
//     at IAM Credentials unreachable. While an answer was read (reading true)
//     it ended no handshake and decided nothing: unreachable, with Handshake
//     false. The alert's words alone do not say whether the server refused
//     the certificate (an internal_error is an alert too), so a caller that
//     needs a decision reads Alert;
//  4. a *url.Error, and then
//  5. a read's own error: transportFailure's words and cause when the inner
//     error (the read's error) holds a failure Go's network stack described
//     itself; otherwise msgNoReadableAnswer, with no cause. The *url.Error
//     itself is always dropped, because its URL names the service account's
//     email on the impersonation path. A server's answer that net/http cannot
//     parse (a malformed status or header line, an HTTP/2 GOAWAY's debug
//     data, a bad chunk) is described in the server's own bytes, which may
//     echo the request: neither its words nor the error carrying them is
//     kept. Such an answer decides nothing, so it is unreachable too;
//  6. anything else: no answer within 30 s, with no cause.
func classifyFailure(ctx context.Context, step Step, err error, reading bool) error {
	format := msgExchangeUnreachable
	if step == StepImpersonate {
		format = msgImpersonateUnreachable
	}
	unreachable := func(why string, cause error) error {
		return &FederationError{Step: step, msg: fmt.Sprintf(format, why), sentinel: ErrUnreachable, cause: cause}
	}
	if cerr := ctx.Err(); cerr != nil {
		return unreachable(cerr.Error(), cerr)
	}
	var rf *refusal
	if errors.As(err, &rf) && errors.Is(rf, ErrEndpointRefused) {
		return rf
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "remote error" {
		words, alert := alertUnshaped, ""
		if opErr.Err != nil && isAlertWords(opErr.Err.Error()) {
			words = opErr.Err.Error()
			alert = words
		}
		switch {
		case reading:
			return &FederationError{Step: step, Alert: alert, msg: fmt.Sprintf(format, words), sentinel: ErrUnreachable}
		case step == StepExchange:
			return &FederationError{Step: step, Handshake: true, Alert: alert, msg: fmt.Sprintf(msgExchangeHandshake, words), sentinel: ErrTokenRefused}
		}
		return &FederationError{Step: step, Handshake: true, Alert: alert, msg: fmt.Sprintf(format, words), sentinel: ErrUnreachable}
	}
	var ue *url.Error
	inner := err
	if errors.As(err, &ue) && ue.Err != nil {
		inner = ue.Err
	} else if !reading || err == nil {
		return unreachable(fmt.Sprintf("no answer within %s", federationTimeout), nil)
	}
	if words, cause := transportFailure(inner); words != "" {
		return unreachable(words, cause)
	}
	return unreachable(msgNoReadableAnswer, nil)
}

// transportFailure is the words of a failure that Go's network stack wrote
// from nothing a server sent, and the error they belong to (nil for a fixed
// text), when err's tree holds one; "" and nil otherwise. The words are
// always that error's own, never a wrapper's, so no text around it is
// carried. In this order:
//   - a *net.OpError other than a server's alert (step 3): a dial, read or
//     write failure, or crypto/tls's own alert ("local error"). Its words
//     name an operation, addresses and a system or alert error;
//   - a *tls.CertificateVerificationError: the server's chain failed
//     verification, before any request was written, so nothing in it can
//     echo the request;
//   - a tls.RecordHeaderError: "tls: " and its Msg, which names at most a
//     record's version and length as numbers;
//   - context.Canceled or context.DeadlineExceeded anywhere in the tree,
//     net/http's timeouts included: the context error's own words;
//   - any other timeout (a net.Error whose Timeout is true, such as
//     net/http's TLS handshake timeout): msgTimedOut, with no cause;
//   - io.ErrUnexpectedEOF or io.EOF: their own words.
//
// Anything else is "": net/http's and net/textproto's parse errors,
// HTTP/2's GoAwayError and StreamError, and every error whose text Go
// formats from a server's bytes are among them.
func transportFailure(err error) (words string, cause error) {
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op != "remote error" {
		return opErr.Error(), opErr
	}
	var cve *tls.CertificateVerificationError
	if errors.As(err, &cve) {
		return cve.Error(), cve
	}
	var rhe tls.RecordHeaderError
	if errors.As(err, &rhe) {
		return rhe.Error(), nil
	}
	for _, sentinel := range []error{context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, sentinel) {
			return sentinel.Error(), sentinel
		}
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return msgTimedOut, nil
	}
	for _, sentinel := range []error{io.ErrUnexpectedEOF, io.EOF} {
		if errors.Is(err, sentinel) {
			return sentinel.Error(), sentinel
		}
	}
	return "", nil
}

// The shapes, each a byte loop (no regexp: it would be init-time state).

// isProjectNumber is ^[0-9]{1,20}$.
func isProjectNumber(s string) bool {
	return len(s) >= 1 && len(s) <= 20 && allBytes(s, isDigit)
}

// isPoolOrProviderID is ^[a-z0-9-]{4,32}$, not starting "gcp-" [MGMT].
func isPoolOrProviderID(s string) bool {
	return len(s) >= 4 && len(s) <= 32 && !strings.HasPrefix(s, "gcp-") &&
		allBytes(s, func(c byte) bool { return isLower(c) || isDigit(c) || c == '-' })
}

// isProjectID is ^[a-z][a-z0-9-]{4,28}[a-z0-9]$, which is also a service
// account's local part.
func isProjectID(s string) bool {
	if len(s) < 6 || len(s) > 30 || !isLower(s[0]) {
		return false
	}
	last := s[len(s)-1]
	if !isLower(last) && !isDigit(last) {
		return false
	}
	return allBytes(s, func(c byte) bool { return isLower(c) || isDigit(c) || c == '-' })
}

// isServiceAccountEmail is
// ^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$.
func isServiceAccountEmail(s string) bool {
	local, domain, ok := strings.Cut(s, "@")
	if !ok {
		return false
	}
	project, ok := strings.CutSuffix(domain, googleEmailSuffix)
	return ok && isProjectID(local) && isProjectID(project)
}

// isScope is https://www.googleapis.com/auth/ followed by [a-z0-9._-]+.
func isScope(s string) bool {
	rest, ok := strings.CutPrefix(s, scopePrefix)
	return ok && rest != "" &&
		allBytes(rest, func(c byte) bool { return isLower(c) || isDigit(c) || c == '.' || c == '_' || c == '-' })
}

// isOAuthCode is ^[a-z_]{1,64}$.
func isOAuthCode(s string) bool {
	return len(s) >= 1 && len(s) <= 64 && allBytes(s, func(c byte) bool { return isLower(c) || c == '_' })
}

// isGoogleStatus is ^[A-Z_]{1,64}$.
func isGoogleStatus(s string) bool {
	return len(s) >= 1 && len(s) <= 64 && allBytes(s, func(c byte) bool { return (c >= 'A' && c <= 'Z') || c == '_' })
}

// isAlertWords is ^tls: [a-z0-9 ()-]{1,64}$, a TLS alert's words as Go's
// crypto/tls writes them.
func isAlertWords(s string) bool {
	rest, ok := strings.CutPrefix(s, "tls: ")
	return ok && len(rest) >= 1 && len(rest) <= 64 &&
		allBytes(rest, func(c byte) bool {
			return isLower(c) || isDigit(c) || c == ' ' || c == '(' || c == ')' || c == '-'
		})
}

func allBytes(s string, ok func(byte) bool) bool {
	for i := 0; i < len(s); i++ {
		if !ok(s[i]) {
			return false
		}
	}
	return true
}

func isLower(c byte) bool { return c >= 'a' && c <= 'z' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// Step is which call of the identity path failed.
type Step string

const (
	StepExchange    Step = "exchange"
	StepImpersonate Step = "impersonate"
)

// FederationError is a failure on the identity path. Its text is exactly msg,
// built from the constants below. The only values in it are a status and its
// StatusText, a shape-checked code, a TLS alert's words, a field name, or the
// transport's inner words for an unreachable host, which are only those
// transportFailure takes: words Go's network stack wrote from nothing a
// server sent. An answer net/http could not parse is unreachable with fixed
// words, because Go quotes the server's bytes in such an error.
//
// Its sentinel is ErrTokenRefused (refused, at HTTP or at the handshake),
// ErrUnreachable or ErrUnreadable (an unusable 200). A refusal before sending
// is ErrCredentialInvalid, and the host guard's is ErrEndpointRefused, both
// through refuse, not a FederationError.
//
// Every TLS alert that ends an exchange before an answer comes is
// ErrTokenRefused with Handshake true, whatever the alert: certificate_required
// and internal_error alike. Which it was is Alert, so a caller that must tell
// a refusal of the certificate from a server's own failure reads it.
type FederationError struct {
	Step         Step
	Status       int    // the HTTP status; 0 when none came
	OAuthError   string // STS's OAuth "error", in its shape; else ""
	GoogleStatus string // Google's error.status, in its shape; else ""
	Handshake    bool   // a TLS alert ended the call before any answer: at the handshake, or in TLS 1.3 just after it
	Alert        string // the TLS alert's words, in their shape ("tls: certificate required"); "" for none, or words out of shape
	Field        string // for an unusable 200: the field, by name
	TLSVersion   uint16 // the negotiated version, when a handshake completed; else 0
	msg          string
	sentinel     error
	cause        error // ErrUnreachable only: never a *url.Error, and only an error transportFailure took
}

// Error is the message, exactly.
func (e *FederationError) Error() string { return e.msg }

// Unwrap is [sentinel], or [sentinel, cause] when there is a cause.
func (e *FederationError) Unwrap() []error {
	if e.cause == nil {
		return []error{e.sentinel}
	}
	return []error{e.sentinel, e.cause}
}

// The identity path's messages. These are exact, and the tests pin them.
const (
	msgExchangeRefused        = "kube: Google's token exchange refused the request (%d %s%s)"                        // %s%s: StatusText, then ", OAuth error <code>", ", status <STATUS>" or ""
	msgExchangeHandshake      = "kube: Google's token exchange refused the client certificate at the handshake (%s)" // e.g. "tls: certificate required"
	msgExchangeUnreachable    = "kube: Google's token exchange could not be reached: %s"
	msgExchangeUnusable       = "kube: Google's token exchange answered without a usable token (%s)"  // the field
	msgImpersonateRefused     = "kube: IAM Credentials refused the service account's token (%d %s%s)" // ", status <STATUS>" or ""
	msgImpersonateUnreachable = "kube: IAM Credentials could not be reached: %s"
	msgImpersonateUnusable    = "kube: IAM Credentials answered without a usable token (%s)"
	msgFederationRequest      = "kube: the federation request has no usable %s; nothing was sent" // audience, client certificate, subject token, scope, service account, federated token, request
	msgFederationHost         = "kube: the identity transport sends only to its own host; nothing was sent"
	msgNoReadableAnswer       = "no readable answer" // an unreachable's words when Go's own words would quote the server
	msgTimedOut               = "timed out"          // a timeout's words when it carries no context error
)
