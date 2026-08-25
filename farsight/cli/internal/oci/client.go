package oci

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// defaultMaxBlobSize caps how much a single blob may pull into memory. A
// registry is untrusted transport, and a hostile or broken one answering a
// 10 MB layer request with an endless body would otherwise exhaust the
// operator's machine. FarCast's own images are a few megabytes; the ceiling is
// generous enough never to bite a legitimate base.
const defaultMaxBlobSize = 512 << 20

// errorBodyLimit is how much of a registry's error response is kept for
// diagnostics. Enough for a JSON error document, not enough to paste a page of
// HTML into a terminal.
const errorBodyLimit = 4 << 10

// maxTokenSize bounds a token-endpoint response. Registry bearer tokens are
// JWTs and can run to several kilobytes, so this is deliberately generous —
// truncating one would surface as an unhelpful JSON decode error — while still
// refusing an unbounded body from a host we do not control.
const maxTokenSize = 64 << 10

// defaultHTTP is the transport used when a Client does not supply its own. The
// timeout is a backstop only — every call also carries a context, which is what
// actually governs cancellation.
var defaultHTTP = &http.Client{
	Timeout:       10 * time.Minute,
	CheckRedirect: checkRedirect,
}

// checkRedirect governs where a registry may send us, and with what.
//
// Go's own policy keeps the Authorization header across a redirect to a
// *subdomain* and does not care about a scheme downgrade. Neither is good
// enough here: this client's credential for Artifact Registry is a Google
// access token carrying every permission the installer service account holds,
// so a redirect must never carry it to a host that is not the one we chose to
// authenticate to. Redirects to a plaintext or non-loopback-HTTP target are
// refused outright, and any change of host strips the credential — the
// redirected request then either succeeds anonymously or gets a fresh
// challenge from that host.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("oci: stopped after 10 redirects")
	}
	// isSecure answers "may this URL carry a credential", which treats any
	// loopback address as safe. That is the wrong question for a destination:
	// a registry must not be able to redirect this process into an arbitrary
	// port on the operator's own machine (a local daemon, an admin UI, a
	// database) and choose the method and body. Plaintext is acceptable only
	// when the registry we started from was itself loopback.
	if req.URL.Scheme != "https" && !isLoopbackHost(hostOnly(via[0].URL.Host)) {
		return fmt.Errorf("oci: refusing to follow a registry redirect to %s over plaintext HTTP", req.URL.Host)
	}
	if prev := via[len(via)-1]; !sameEndpoint(prev.URL.Host, req.URL.Host) {
		req.Header.Del("Authorization")
	}
	return nil
}

// Client speaks the OCI distribution protocol to any number of registries. The
// zero value is usable and safe for concurrent use.
//
// One client can span registries because the interesting operation is a
// cross-registry copy: pull an untrusted public base, push to the instance's
// own registry. Credentials are therefore looked up per host rather than fixed
// at construction, so anonymous and authenticated hosts coexist in one copy
// without the client ever offering one host's credentials to another.
type Client struct {
	// HTTP is the transport for every registry call. Nil selects a shared
	// default.
	//
	// Whatever is supplied here, this package installs its own redirect policy
	// on a copy of it (see httpClient). That is deliberate: net/http keeps the
	// Authorization header across a redirect to a *subdomain* and ignores a
	// port change entirely, so relying on Go's own stripping would leave the
	// credential binding this package promises with a hole in it.
	HTTP *http.Client

	// Credentials returns the username and password to present to a registry
	// host, or two empty strings for anonymous access. For Artifact Registry
	// the username is the literal "oauth2accesstoken" and the password is a
	// short-lived OAuth2 access token minted in-process (ADR 0007) — which is
	// why this is a callback rather than a stored pair: the token can be
	// refreshed between calls without rebuilding the client.
	Credentials func(registry string) (username, password string)

	// MaxBlobSize caps a single blob read. Zero selects defaultMaxBlobSize.
	MaxBlobSize int64

	mu      sync.Mutex
	auth    map[string]string // cached Authorization header values, keyed by registry and scope
	wrapped *http.Client      // c.HTTP with this package's redirect policy applied
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP == nil {
		return defaultHTTP
	}
	// A caller-supplied client must not be able to opt out of the redirect
	// policy — silently or otherwise — so it is applied to a shallow copy,
	// leaving the caller's own client untouched.
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.wrapped == nil || c.wrapped.Transport != c.HTTP.Transport {
		cp := *c.HTTP
		cp.CheckRedirect = checkRedirect
		c.wrapped = &cp
	}
	return c.wrapped
}

func (c *Client) maxBlobSize() int64 {
	if c.MaxBlobSize > 0 {
		return c.MaxBlobSize
	}
	return defaultMaxBlobSize
}

func (c *Client) credentials(registry string) (string, string) {
	if c.Credentials == nil {
		return "", ""
	}
	return c.Credentials(registry)
}

// baseURL returns the registry API root for a host. Plaintext HTTP is used only
// for loopback addresses, which is what makes the httptest-backed tests work
// without a knob that could downgrade a real connection.
func baseURL(registry string) string {
	return schemeFor(registry) + "://" + registry
}

func schemeFor(registry string) string {
	if isLoopbackHost(hostOnly(registry)) {
		return "http"
	}
	return "https"
}

// sameEndpoint reports whether a URL host and a registry name address the same
// place. It compares host *and* port: registry.test:5000 and registry.test:6000
// are different endpoints, and a credential minted for one has no business
// reaching the other. A missing port means the scheme's default (443), so the
// common "no port anywhere" case compares equal.
func sameEndpoint(urlHost, registry string) bool {
	return normalizeEndpoint(urlHost) == normalizeEndpoint(registry)
}

// normalizeEndpoint reduces a host[:port] to a comparable form: bracket-free
// host, lowercased, without the trailing dot a fully-qualified name may carry,
// and with the scheme's default port made explicit. Getting this wrong in
// either direction is a security bug — too loose sends a credential to the
// wrong place, too strict refuses legitimate traffic — so the equivalences are
// spelled out rather than left to string equality.
func normalizeEndpoint(hostport string) string {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host, port = hostport, ""
	}
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
	if port == "" {
		// Loopback registries are plain HTTP (see schemeFor), so their implied
		// port is 80; everything else is TLS.
		port = "443"
		if isLoopbackHost(host) {
			port = "80"
		}
	}
	return host + ":" + port
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

func isLoopbackHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// isSecure reports whether a URL may carry a credential: TLS, or a loopback
// address where the traffic never leaves the operator's machine.
func isSecure(u *url.URL) bool {
	return u.Scheme == "https" || isLoopbackHost(hostOnly(u.Host))
}

// call is one registry request. Bodies are held in memory so a request can be
// replayed verbatim after an authentication challenge.
type call struct {
	method   string
	url      string
	registry string      // credential and cache key
	scope    string      // bearer scope, e.g. "repository:foo/bar:pull"
	header   http.Header // request headers, credentials excluded
	body     []byte
}

// do performs a call, answering an authentication challenge once. The first
// attempt is unauthenticated unless a token for the same scope is already
// cached, which is the protocol's own shape: the registry tells the client how
// to authenticate, so no credential is offered to a host that has not asked.
func (c *Client) do(ctx context.Context, cl call) (*http.Response, error) {
	authz := c.cachedAuth(cl.registry, cl.scope)
	resp, err := c.send(ctx, cl, authz)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}
	ch := parseChallenge(resp.Header.Get("WWW-Authenticate"))
	drain(resp)

	next, err := c.authorize(ctx, cl.registry, cl.scope, ch)
	if err != nil {
		return nil, err
	}
	if next == "" || next == authz {
		return nil, &Error{
			Op:     cl.method,
			Ref:    cl.url,
			Status: http.StatusUnauthorized,
			Body:   "registry rejected the supplied credentials",
		}
	}
	c.storeAuth(cl.registry, cl.scope, next)
	return c.send(ctx, cl, next)
}

func (c *Client) send(ctx context.Context, cl call, authz string) (*http.Response, error) {
	var body io.Reader
	if cl.body != nil {
		body = bytes.NewReader(cl.body)
	}
	req, err := http.NewRequestWithContext(ctx, cl.method, cl.url, body)
	if err != nil {
		return nil, fmt.Errorf("oci: build request: %w", err)
	}
	for k, vs := range cl.header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if cl.body != nil {
		payload := cl.body
		req.ContentLength = int64(len(payload))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(payload)), nil
		}
	}
	if authz != "" {
		if !isSecure(req.URL) {
			return nil, fmt.Errorf("oci: refusing to send registry credentials to %s over plaintext HTTP", req.URL.Host)
		}
		// A call's URL is not always one this package composed: an upload
		// Location header is chosen by the registry. The credential belongs to
		// cl.registry and goes nowhere else, whatever the registry asked for.
		if !sameEndpoint(req.URL.Host, cl.registry) {
			return nil, fmt.Errorf("oci: refusing to send %s credentials to %s", cl.registry, req.URL.Host)
		}
		req.Header.Set("Authorization", authz)
	}
	return c.httpClient().Do(req)
}

func (c *Client) cachedAuth(registry, scope string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.auth[registry+"|"+scope]
}

func (c *Client) storeAuth(registry, scope, authz string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.auth == nil {
		c.auth = make(map[string]string)
	}
	c.auth[registry+"|"+scope] = authz
}

// challenge is a parsed WWW-Authenticate header.
type challenge struct {
	scheme string
	params map[string]string
}

// parseChallenge parses a WWW-Authenticate header into a scheme and its
// parameters. Quoted values are taken literally: registries do not escape
// quotes inside them, and inventing an unescaping rule would be a parser
// FarCast has to defend rather than one it needs.
func parseChallenge(h string) challenge {
	h = strings.TrimSpace(h)
	if h == "" {
		return challenge{}
	}
	scheme, rest, _ := strings.Cut(h, " ")
	ch := challenge{scheme: strings.ToLower(strings.TrimSpace(scheme)), params: map[string]string{}}
	rest = strings.TrimSpace(rest)
	for rest != "" {
		key, after, ok := strings.Cut(rest, "=")
		if !ok {
			break
		}
		var value string
		rest = after
		if strings.HasPrefix(rest, `"`) {
			rest = rest[1:]
			value, rest, _ = strings.Cut(rest, `"`)
		} else {
			value, rest, _ = strings.Cut(rest, ",")
		}
		ch.params[strings.ToLower(strings.TrimSpace(key))] = value
		rest = strings.TrimLeft(rest, " ,")
	}
	return ch
}

// authorize turns a challenge into an Authorization header value.
//
// Basic is answered directly with the host's credentials (Artifact Registry
// accepts "oauth2accesstoken" plus an access token this way). Bearer runs the
// standard token dance: fetch a token from the challenge's realm, presenting
// the host's credentials there if we have any, and use it for the retry. An
// anonymous pull from gcr.io takes the same path with no credentials attached,
// which is how a public base image is fetched without an account anywhere.
func (c *Client) authorize(ctx context.Context, registry, scope string, ch challenge) (string, error) {
	user, pass := c.credentials(registry)
	switch ch.scheme {
	case "basic":
		if user == "" && pass == "" {
			return "", fmt.Errorf("oci: registry %s requires credentials and none were supplied", registry)
		}
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass)), nil
	case "bearer":
		token, err := c.fetchToken(ctx, registry, ch, scope, user, pass)
		if err != nil {
			return "", err
		}
		return "Bearer " + token, nil
	case "":
		// A 401 with no challenge leaves nothing to answer; if we hold
		// credentials, Basic is the only thing worth trying.
		if user != "" || pass != "" {
			return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass)), nil
		}
		return "", fmt.Errorf("oci: registry %s refused the request without an authentication challenge", registry)
	default:
		return "", fmt.Errorf("oci: registry %s asked for unsupported authentication scheme %q", registry, ch.scheme)
	}
}

// tokenResponse is the token-endpoint reply. Registries disagree about the
// field name, so both spellings are accepted.
type tokenResponse struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
}

func (c *Client) fetchToken(ctx context.Context, registry string, ch challenge, scope, user, pass string) (string, error) {
	realm := ch.params["realm"]
	if realm == "" {
		return "", fmt.Errorf("oci: bearer challenge without a realm")
	}
	u, err := url.Parse(realm)
	if err != nil {
		return "", fmt.Errorf("oci: bearer challenge realm %q is not a URL: %w", realm, err)
	}
	// The realm comes from the network, so it is untrusted input that decides
	// where a credential is sent. Two things constrain it. TLS (or loopback)
	// keeps a downgrading man-in-the-middle from harvesting the token; binding
	// the realm to the registry's own host keeps a hostile or compromised
	// registry from naming somewhere else and collecting the credential —
	// the flaw behind CVE-2026-33540 in the reference distribution client, and
	// the reason this package promises never to offer one host's credentials to
	// another. Both registries FarCast talks to (gcr.io and *-docker.pkg.dev)
	// serve their realm on the same host, so the strict rule costs nothing.
	if !isSecure(u) {
		return "", fmt.Errorf("oci: refusing to fetch a registry token from %s over plaintext HTTP", u.Host)
	}
	if !sameEndpoint(u.Host, registry) {
		return "", fmt.Errorf("oci: registry %s pointed its authentication realm at %s; refusing to send credentials there", registry, u.Host)
	}
	q := u.Query()
	if svc := ch.params["service"]; svc != "" {
		q.Set("service", svc)
	}
	if scope == "" {
		scope = ch.params["scope"]
	}
	if scope != "" {
		q.Set("scope", scope)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("oci: build token request: %w", err)
	}
	if user != "" || pass != "" {
		req.SetBasicAuth(user, pass)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("oci: fetch registry token: %w", err)
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		return "", newError("GET token", u.Redacted(), resp)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" && !strings.Contains(strings.ToLower(ct), "json") {
		return "", fmt.Errorf("oci: token endpoint %s answered with %q, not JSON", u.Host, ct)
	}
	var tr tokenResponse
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenSize))
	if err != nil {
		return "", fmt.Errorf("oci: read token response: %w", err)
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("oci: decode token response: %w", err)
	}
	if tr.Token != "" {
		return tr.Token, nil
	}
	if tr.AccessToken != "" {
		return tr.AccessToken, nil
	}
	return "", fmt.Errorf("oci: token endpoint %s returned no token", u.Host)
}

// pullScope and pushScope are the bearer scopes for the two things FarCast does
// with a repository.
func pullScope(repo string) string { return "repository:" + repo + ":pull" }
func pushScope(repo string) string { return "repository:" + repo + ":pull,push" }

// newError captures a failed response for the caller, truncating the body.
func newError(op, ref string, resp *http.Response) *Error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, errorBodyLimit))
	return &Error{
		Op:     op,
		Ref:    ref,
		Status: resp.StatusCode,
		Body:   strings.TrimSpace(string(body)),
	}
}

// drain consumes and closes a response body so the connection can be reused.
func drain(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, errorBodyLimit))
	_ = resp.Body.Close()
}
