package kube

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cloud.google.com/go/auth"
)

// TestRoleTokensTokenAndInvalidate: Token reuses the consumer's token until
// it is within 225 s of its expiry, returns its value and a wall-clock
// expiry, and never an empty value or a zero expiry; Invalidate drops the
// token only when it is the one named; a failed mint holds nothing.
func TestRoleTokensTokenAndInvalidate(t *testing.T) {
	m := &staticFederatedMint{life: time.Hour}
	rt := newRoleTokens(Reader, true, ScopesStorage, m.mint)
	v := rt.get()
	now := time.Now().Round(0)
	v.now = func() time.Time { return now }
	first, exp, err := rt.Token(t.Context())
	if err != nil || first != "sa-1" {
		t.Fatalf("Token = %q, %v", first, err)
	}
	if exp != exp.Round(0) || exp.IsZero() {
		t.Errorf("the expiry %v carries a monotonic reading or is zero", exp)
	}
	now = exp.Add(-226 * time.Second)
	if again, _, _ := rt.Token(t.Context()); again != first || m.calls() != 1 {
		t.Errorf("226 s before its expiry: %q after %d mints; want the held token", again, m.calls())
	}
	now = exp.Add(-224 * time.Second)
	second, _, _ := rt.Token(t.Context())
	if second == first || m.calls() != 2 {
		t.Errorf("224 s before its expiry: %q after %d mints; want a new token", second, m.calls())
	}
	now = time.Now().Round(0)
	rt.Invalidate(first) // not the held one: kept
	if kept, _, _ := rt.Token(t.Context()); kept != second || m.calls() != 2 {
		t.Error("invalidating a token already replaced dropped the held one")
	}
	rt.Invalidate(second)
	if third, _, _ := rt.Token(t.Context()); third == second || m.calls() != 3 {
		t.Error("invalidating the held token did not mint anew")
	}
	if rt.Role() != Reader || !rt.Federated() || rt.Scopes() != ScopesStorage {
		t.Errorf("Role %q, Federated %v, Scopes %d", rt.Role(), rt.Federated(), rt.Scopes())
	}

	for _, c := range []struct {
		name string
		tok  *auth.Token
		err  error
		want string
	}{
		{"an empty value", &auth.Token{Expiry: time.Now().Add(time.Hour)}, nil, "the token endpoint answered without a token"},
		{"no token", nil, nil, "the token endpoint answered without a token"},
		{"no expiry", &auth.Token{Value: fedSecretMarker}, nil, "the token endpoint answered without an expiry"},
	} {
		bad := newRoleTokens("", false, ScopesCluster, func(context.Context) (*auth.Token, error) { return c.tok, c.err })
		value, exp, err := bad.Token(t.Context())
		if value != "" || !exp.IsZero() || !errors.Is(err, ErrUnreadable) || err.Error() != c.want {
			t.Errorf("%s: %q, %v, %v; want ErrUnreadable %q", c.name, value, exp, err, c.want)
		}
		if bad.get().tok != nil {
			t.Errorf("%s: a token is held", c.name)
		}
	}
	failed := newRoleTokens("", false, ScopesCluster, func(context.Context) (*auth.Token, error) {
		return nil, refuse(ErrTokenRefused, "refused")
	})
	if _, _, err := failed.Token(t.Context()); !errors.Is(err, ErrTokenRefused) || failed.get().tok != nil {
		t.Errorf("a failed mint: %v, holding %v", err, failed.get().tok != nil)
	}
	// Nor does a failed mint keep the stale token it was replacing, which a
	// clock set back would find fresh again: the next Token mints.
	base := time.Now().Round(0)
	fail, mints := false, 0
	flaky := newRoleTokens(Reader, true, ScopesStorage, func(context.Context) (*auth.Token, error) {
		mints++
		if fail {
			return nil, refuse(ErrTokenRefused, "refused")
		}
		return &auth.Token{Value: fmt.Sprintf("flaky-%d", mints), Expiry: base.Add(time.Hour)}, nil
	})
	clock := base
	flaky.get().now = func() time.Time { return clock }
	if _, _, err := flaky.Token(t.Context()); err != nil {
		t.Fatal(err)
	}
	clock, fail = base.Add(time.Hour-224*time.Second), true
	if _, _, err := flaky.Token(t.Context()); !errors.Is(err, ErrTokenRefused) || flaky.get().tok != nil {
		t.Errorf("a failed mint of a stale token: %v, holding %v", err, flaky.get().tok != nil)
	}
	clock = base
	if v, _, err := flaky.Token(t.Context()); v != "" || !errors.Is(err, ErrTokenRefused) || mints != 3 {
		t.Errorf("after a failed mint, with the clock set back: %q, %v after %d mints; want a third mint, failing", v, err, mints)
	}

	var zero RoleTokens
	if _, _, err := zero.Token(t.Context()); !errors.Is(err, ErrCredentialInvalid) || err.Error() != "kube: the token source has no usable token source; nothing was sent" {
		t.Errorf("the zero RoleTokens: %v", err)
	}
	zero.Invalidate("x")
	if zero.Role() != "" || zero.Federated() || zero.Scopes() != 0 {
		t.Error("the zero RoleTokens' accessors are not empty")
	}
}

// roleTokensProvider is an auth.TokenProvider over a RoleTokens, as M3b.4's
// adapters in planck and datasphere will be. It counts the calls that came
// without the test's caller mark: the vendored cache's asynchronous
// refreshes, which it makes with context.Background().
type roleTokensProvider struct {
	rt    *RoleTokens
	async atomic.Int32
}

// callerMark marks the contexts the test's own goroutines pass.
type callerMark struct{}

func (p *roleTokensProvider) Token(ctx context.Context) (*auth.Token, error) {
	if ctx.Value(callerMark{}) == nil {
		p.async.Add(1)
	}
	v, exp, err := p.rt.Token(ctx)
	if err != nil {
		return nil, err
	}
	return &auth.Token{Value: v, Type: "Bearer", Expiry: exp}, nil
}

// TestRoleTokensConcurrentRefresh: many goroutines ask a RoleTokens for its
// token, some invalidating the one they got and some a value it never held,
// while the vendored cache that httptransport wraps every provider in
// (auth.NewCachedTokenProvider) refreshes it in the background. The tokens
// live ten minutes, so the RoleTokens holds each (its margin is 225 s); the
// outer cache's early expiry is eleven, so every token it holds is stale to
// it and each call it serves starts an asynchronous refresh, which the
// RoleTokens answers from what it holds. Under -race nothing races; no value
// is empty, no expiry zero, and every value is one the mint made; the
// asynchronous refreshes reached the RoleTokens; and it minted only for its
// first token and after an Invalidate of the one it held.
func TestRoleTokensConcurrentRefresh(t *testing.T) {
	m := &staticFederatedMint{life: 10 * time.Minute}
	rt := newRoleTokens(Writer, true, ScopesRegistry, m.mint)
	p := &roleTokensProvider{rt: rt}
	outer := auth.NewCachedTokenProvider(p, &auth.CachedTokenProviderOptions{ExpireEarly: 11 * time.Minute})
	caller := context.WithValue(context.Background(), callerMark{}, true)
	var bad, invalidated atomic.Int32
	var wg sync.WaitGroup
	check := func(v string, exp time.Time, err error) {
		if err != nil || v == "" || exp.IsZero() || !strings.HasPrefix(v, "sa-") {
			bad.Add(1)
		}
	}
	for i := range 32 {
		wg.Go(func() {
			for j := range 50 {
				switch (i + j) % 3 {
				case 0:
					v, exp, err := rt.Token(caller)
					check(v, exp, err)
					if j%7 == 0 {
						invalidated.Add(1)
						rt.Invalidate(v)
					}
				case 1:
					tok, err := outer.Token(caller)
					if err != nil {
						bad.Add(1)
						continue
					}
					check(tok.Value, tok.Expiry, nil)
				default:
					rt.Invalidate(fmt.Sprintf("never-%d", j)) // a value the mint never made: kept
				}
			}
		})
	}
	wg.Wait()
	if n := bad.Load(); n != 0 {
		t.Errorf("%d calls returned an error, an empty value, a zero expiry or a token the mint did not make", n)
	}
	// The refreshes run on goroutines of their own; wait, bounded, until one
	// has reached the RoleTokens.
	for deadline := time.Now().Add(10 * time.Second); p.async.Load() == 0 && time.Now().Before(deadline); {
		if _, err := outer.Token(caller); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
	}
	if p.async.Load() == 0 {
		t.Error("no asynchronous refresh of the outer cache reached the RoleTokens")
	}
	if mints, most := m.calls(), 1+int(invalidated.Load()); mints > most {
		t.Errorf("%d mints; at most %d (the first token, and one after each Invalidate of the held one): the RoleTokens did not hold its token", mints, most)
	}
}

// TestKeyTokenSourceLoggerDiscards: with GOOGLE_SDK_GO_LOGGING_LEVEL=debug
// and stderr captured, a key's RoleTokens builds its 2LO provider and mints,
// and stderr stays empty. A nil Logger would make the library log the signed
// assertion and the token there (twoLegged's comment);
// TestTokenLoggerDiscardsEvenWithTheDebugVariable holds the cluster client's.
func TestKeyTokenSourceLoggerDiscards(t *testing.T) {
	t.Setenv("GOOGLE_SDK_GO_LOGGING_LEVEL", "debug")
	e := &fedTokenEndpoint{body: `{"access_token":"` + fedSecretMarker + `","token_type":"Bearer","expires_in":3600}`}
	srv := quietTLSServer(t, http.HandlerFunc(e.serve))
	ep, err := ParseEndpoint(srv.Listener.Addr().String(), "", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	if err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	var captured bytes.Buffer
	copied := make(chan struct{})
	go func() {
		_, _ = io.Copy(&captured, r)
		close(copied)
	}()
	orig := os.Stderr
	var once sync.Once
	restore := func() {
		once.Do(func() {
			os.Stderr = orig
			_ = w.Close()
			<-copied
			_ = r.Close()
		})
	}
	defer restore()
	os.Stderr = w // before the provider is built: the library picks its logger then

	rt, err := tokenSourceFor(googleCredential(t), ScopesStorage, ep)
	if err == nil {
		_, _, err = rt.Token(t.Context())
	}
	restore()
	if err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	requests := len(e.scopes)
	e.mu.Unlock()
	if requests != 1 {
		t.Errorf("%d token requests, want 1", requests)
	}
	out := captured.String()
	if m := containsAnyOf(out, fedSecretMarker, "assertion", "access_token", "2LO"); m != "" {
		t.Errorf("stderr carries %q", m)
	}
	if out != "" {
		t.Errorf("stderr is not empty: %d bytes", len(out))
	}
}

// TestKeyTokenSourceHasNoProxy (R3): the token client a key's RoleTokens
// posts its assertion with has tokenHTTPClient's shape, with the proxy
// variables set: Proxy nil, so no proxy variable routes the assertion; TLS
// 1.2 at least against the system roots (Google's token endpoint), no client
// certificate, no redirects, 30 s, and tokenTransport, which sends no
// Authorization. A loopback request could not show it, because
// ProxyFromEnvironment never proxies a loopback host and reads the
// environment once per process. A federated credential's RoleTokens has no
// token client.
func TestKeyTokenSourceHasNoProxy(t *testing.T) {
	for _, v := range []string{"HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy"} {
		t.Setenv(v, "http://192.0.2.1:3128")
	}
	for _, s := range []Scopes{ScopesCluster, ScopesStorage, ScopesRegistry} {
		rt, err := TokenSourceFor(googleCredential(t), s)
		if err != nil {
			t.Fatal(err)
		}
		hc := rt.get().tokenClient
		if hc == nil {
			t.Fatalf("scopes %d: a key's RoleTokens keeps no token client", s)
		}
		if hc.Timeout != 30*time.Second || hc.CheckRedirect == nil || !errors.Is(hc.CheckRedirect(nil, nil), http.ErrUseLastResponse) {
			t.Errorf("scopes %d: Timeout %s, or the client follows redirects", s, hc.Timeout)
		}
		tt, ok := hc.Transport.(*tokenTransport)
		if !ok {
			t.Fatalf("scopes %d: the token client's transport is %T, not *tokenTransport", s, hc.Transport)
		}
		tr, ok := tt.inner.(*http.Transport)
		if !ok {
			t.Fatalf("scopes %d: the token transport's inner is %T", s, tt.inner)
		}
		if tr.Proxy != nil {
			t.Errorf("scopes %d: Proxy is set; it must be nil so no proxy variable routes the assertion", s)
		}
		if tr.DialContext == nil || !tr.ForceAttemptHTTP2 || tr.TLSHandshakeTimeout != 10*time.Second || tr.ResponseHeaderTimeout != 30*time.Second {
			t.Errorf("scopes %d: %+v is not §3.4's shape", s, tr)
		}
		tc := tr.TLSClientConfig
		switch {
		case tc == nil:
			t.Errorf("scopes %d: no TLS config", s)
		case tc.MinVersion != tls.VersionTLS12 || tc.RootCAs != nil || tc.ServerName != "":
			t.Errorf("scopes %d: MinVersion %s, RootCAs %v, ServerName %q; want TLS 1.2 against the system roots", s, tls.VersionName(tc.MinVersion), tc.RootCAs != nil, tc.ServerName)
		case tc.InsecureSkipVerify || tc.VerifyPeerCertificate != nil || tc.VerifyConnection != nil || tc.KeyLogWriter != nil:
			t.Errorf("scopes %d: the TLS config skips or replaces verification, or logs keys", s)
		case tc.Certificates != nil || tc.GetClientCertificate != nil:
			t.Errorf("scopes %d: the token client presents a certificate", s)
		}
	}
	fake := newFedFake(t)
	rt, err := TokenSourceFor(fake.credential(t, Reader), ScopesStorage)
	if err != nil {
		t.Fatal(err)
	}
	if rt.get().tokenClient != nil {
		t.Error("a federated credential's RoleTokens has a token client")
	}
}

// TestTokenSourceForRefusesBeforeSending: TokenSourceFor refuses, before
// anything is built or sent, a Scopes outside the consumers' closed list
// (the IAM reader's own included), and for a key, an email that is not a
// Google service account's, a key the 2LO signer cannot use, a token_uri
// other than Google's and a universe other than googleapis.com. Each names
// the part, never its value.
func TestTokenSourceForRefusesBeforeSending(t *testing.T) {
	fed, l := fedCountingFederation(t)
	id := newFedIdentity(t, fedHexID)
	federated, err := NewFederatedCredential(fed, fedAudience, NewClientIdentity([][]byte{id.leafDER}, id.key), fedEmail, Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := googleCredential(t)
	with := func(edit func(*Credential)) Credential {
		c := googleCredential(t)
		edit(&c)
		return c
	}
	for _, c := range []struct {
		name, part string
		cred       Credential
		s          Scopes
	}{
		{"a federated credential, the zero Scopes", "scopes", federated, 0},
		{"a federated credential, the IAM reader's scopes", "scopes", federated, scopesIAM},
		{"a federated credential, past the list", "scopes", federated, scopesIAM + 1},
		{"a key, the zero Scopes", "scopes", key, 0},
		{"a key, the IAM reader's scopes", "scopes", key, scopesIAM},
		{"a test identity's email", "service account", with(func(c *Credential) { c.Email = "writer@kubetest.invalid" }), ScopesCluster},
		{"no email", "service account", with(func(c *Credential) { c.Email = "" }), ScopesStorage},
		{"no key", "private key", with(func(c *Credential) { c.PrivateKeyPEM = nil }), ScopesRegistry},
		{"a key that is not one", "private key", with(func(c *Credential) { c.PrivateKeyPEM = []byte(fedSecretMarker) }), ScopesRegistry},
		{"another token endpoint", "token endpoint", with(func(c *Credential) { c.TokenURI = "https://evil.example/token" }), ScopesStorage},
		{"a loopback token endpoint", "token endpoint", with(func(c *Credential) { c.TokenURI = "https://127.0.0.1:6443/token" }), ScopesStorage},
		{"another universe", "universe", with(func(c *Credential) { c.UniverseDomain = "example.com" }), ScopesCluster},
	} {
		rt, err := TokenSourceFor(c.cred, c.s)
		want := "kube: the token source has no usable " + c.part + "; nothing was sent"
		if rt != nil || !errors.Is(err, ErrCredentialInvalid) || err.Error() != want {
			t.Errorf("%s: %v, %v; want %q", c.name, rt != nil, err, want)
		}
	}
	for name, c := range map[string]Credential{
		"a key with Google's token_uri and universe": with(func(c *Credential) {
			c.TokenURI, c.UniverseDomain = GoogleTokenURL, googleUniverse
		}),
		"a key with neither":     key,
		"a federated credential": federated,
	} {
		for _, s := range []Scopes{ScopesCluster, ScopesStorage, ScopesRegistry} {
			rt, err := TokenSourceFor(c, s)
			if err != nil || rt.Scopes() != s || rt.Federated() != c.Federated() || rt.Role() != c.Role() {
				t.Errorf("%s, scopes %d: %v", name, s, err)
			}
		}
	}
	if n := l.accepted(t); n != 0 {
		t.Errorf("%d connections were made", n)
	}
}

// fedTokenEndpoint is a loopback token endpoint for a key's RoleTokens: it
// records each assertion's scope claim and the request's header names, and
// answers with body.
type fedTokenEndpoint struct {
	mu     sync.Mutex
	scopes []string
	sent   []string // per request: "<User-Agent>, Authorization: <present>"
	body   string
	status int
}

func (e *fedTokenEndpoint) serve(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	var claims struct {
		Scope string `json:"scope"`
	}
	if parts := strings.Split(r.PostForm.Get("assertion"), "."); len(parts) == 3 {
		if b, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
			_ = json.Unmarshal(b, &claims)
		}
	}
	sent := fmt.Sprintf("%s, Authorization: %v", r.Header.Get("User-Agent"), r.Header.Get("Authorization") != "")
	e.mu.Lock()
	e.scopes = append(e.scopes, claims.Scope)
	e.sent = append(e.sent, sent)
	status, body := e.status, e.body
	e.mu.Unlock()
	if status != 0 {
		w.WriteHeader(status)
	}
	_, _ = io.WriteString(w, body)
}

// TestPerConsumerScopes is N9: each consumer's token carries its own scopes
// and no other. A federated credential's consumers each impersonate with
// their own body (the IAM reader with the cluster's set); a key's consumers
// each mint with their own scope claim, at Google's token URL's stand-in and
// never the key file's.
func TestPerConsumerScopes(t *testing.T) {
	fake := newFedFake(t)
	cred := fake.credential(t, Writer)
	for _, s := range []Scopes{ScopesCluster, ScopesStorage, ScopesRegistry} {
		rt, err := TokenSourceFor(cred, s)
		if err != nil {
			t.Fatal(err)
		}
		if rt.Role() != Writer || !rt.Federated() || rt.Scopes() != s {
			t.Errorf("the writer's RoleTokens for %d: Role %q, Federated %v, Scopes %d", s, rt.Role(), rt.Federated(), rt.Scopes())
		}
		if _, _, err := rt.Token(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if got := strings.Join(fake.impersonationBodies(), "\n"); got != strings.Join([]string{
		`{"scope":["https://www.googleapis.com/auth/cloud-platform","https://www.googleapis.com/auth/userinfo.email"],"lifetime":"3600s"}`,
		`{"scope":["https://www.googleapis.com/auth/devstorage.full_control"],"lifetime":"3600s"}`,
		`{"scope":["https://www.googleapis.com/auth/cloud-platform"],"lifetime":"3600s"}`,
	}, "\n") {
		t.Errorf("the impersonations' bodies:\n%s", got)
	}
	// A storage-scoped token is not the cluster's: the cluster stand-in
	// refuses it, as it takes the cluster's scopes alone.
	storage, err := TokenSourceFor(cred, ScopesStorage)
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := storage.Token(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, fake.cluster.URL+"/api/v1/namespaces", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := fake.cluster.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a storage-scoped token at the cluster: %d, want 401", resp.StatusCode)
	}

	// A key's tokens, minted at a loopback stand-in for Google's token URL.
	e := &fedTokenEndpoint{body: `{"access_token":"key-token","token_type":"Bearer","expires_in":3600}`}
	srv := quietTLSServer(t, http.HandlerFunc(e.serve))
	ep, err := ParseEndpoint(srv.Listener.Addr().String(), "", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	if err != nil {
		t.Fatal(err)
	}
	key := googleCredential(t)
	key.TokenURI = GoogleTokenURL // the key file's own; never dialled
	for _, s := range []Scopes{ScopesCluster, ScopesStorage, ScopesRegistry} {
		rt, err := tokenSourceFor(key, s, ep)
		if err != nil {
			t.Fatal(err)
		}
		v, exp, err := rt.Token(t.Context())
		if err != nil || v != "key-token" || exp != exp.Round(0) || time.Until(exp) < 59*time.Minute {
			t.Errorf("scopes %d: %q, %v, %v", s, v, exp, err)
		}
		if rt.Federated() || rt.Role() != "" || rt.Scopes() != s {
			t.Errorf("scopes %d: a key's RoleTokens reads as federated or with a role", s)
		}
	}
	e.mu.Lock()
	scopes, sent := e.scopes, e.sent
	e.mu.Unlock()
	if want := []string{ScopeCloudPlatform + " " + ScopeUserinfoEmail, ScopeDevstorageFullControl, ScopeCloudPlatform}; strings.Join(scopes, "|") != strings.Join(want, "|") {
		t.Errorf("the assertions' scope claims are %q, want %q", scopes, want)
	}
	for _, h := range sent {
		if h != "farcast, Authorization: false" {
			t.Errorf("a token request sent %q; want User-Agent farcast and no Authorization", h)
		}
	}
}

// TestKeyTokenSourceAnswers: a key's RoleTokens refuses an answer with no
// expiry as unreadable, and a refusal is ErrTokenRefused naming the email's
// domain and the status alone, never the body.
func TestKeyTokenSourceAnswers(t *testing.T) {
	e := &fedTokenEndpoint{}
	srv := quietTLSServer(t, http.HandlerFunc(e.serve))
	ep, err := ParseEndpoint(srv.Listener.Addr().String(), "", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	if err != nil {
		t.Fatal(err)
	}
	rt, err := tokenSourceFor(googleCredential(t), ScopesStorage, ep)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, body string
		status     int
		want       string
		sentinel   error
	}{
		{"no expires_in", `{"access_token":"` + fedSecretMarker + `","token_type":"Bearer"}`, 0,
			"the token endpoint answered without an expiry", ErrUnreadable},
		{"no token", `{"token_type":"Bearer","expires_in":3600}`, 0,
			"the token endpoint answered without a token", ErrUnreadable},
		{"a refusal", `{"error":"invalid_grant","error_description":"` + fedPlanted + `"}`, http.StatusBadRequest,
			"Google refused to mint a token for the " + googleDomain + " service account (400 Bad Request)", ErrTokenRefused},
	} {
		e.mu.Lock()
		e.body, e.status = c.body, c.status
		e.mu.Unlock()
		v, exp, err := rt.Token(t.Context())
		if v != "" || !exp.IsZero() || !errors.Is(err, c.sentinel) || err.Error() != c.want {
			t.Errorf("%s: %q, %v, %v; want %q", c.name, v, exp, err, c.want)
		}
		if err != nil && containsAnyOf(err.Error(), fedMarkers...) != "" {
			t.Errorf("%s: the error carries the answer", c.name)
		}
	}

	// R10 on the wire: an answer net/http cannot parse is described in the
	// server's own bytes, which may echo the signed assertion, so none of it
	// is in any error of the tree; a redirect whose Location does not parse
	// is the refusal its status names. The cluster client's 2LO mint
	// (twoLegged) shares tokenError and tokenTransport, and is held to the
	// same.
	for _, c := range []struct {
		name, raw string
		want      func(domain string) string
		sentinel  error
	}{
		{"a malformed status line", "XX " + fedPlanted + "\r\n\r\n", func(domain string) string {
			return "the token endpoint for the " + domain + " service account could not be reached: no readable answer"
		}, ErrUnreachable},
		{"a malformed header line", "HTTP/1.1 200 OK\r\n" + fedPlanted + "\r\nContent-Length: 0\r\n\r\n", func(domain string) string {
			return "the token endpoint for the " + domain + " service account could not be reached: no readable answer"
		}, ErrUnreachable},
		{"an unparsable Location", "HTTP/1.1 302 Found\r\nLocation: http://[" + fedPlanted + "\r\nContent-Length: 0\r\n\r\n", func(domain string) string {
			return "Google refused to mint a token for the " + domain + " service account (302 Found)"
		}, ErrTokenRefused},
	} {
		t.Run(c.name, func(t *testing.T) {
			raw := quietTLSServer(t, rawAnswer(c.raw))
			rawEP, err := ParseEndpoint(raw.Listener.Addr().String(), "", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw.Certificate().Raw}))
			if err != nil {
				t.Fatal(err)
			}
			check := func(name, domain string, err error) {
				t.Helper()
				if want := c.want(domain); err == nil || err.Error() != want || !errors.Is(err, c.sentinel) {
					t.Errorf("%s: %v; want %q", name, err, want)
				}
				if errors.As(err, new(*url.Error)) {
					t.Errorf("%s: a *url.Error is in the tree", name)
				}
				for _, e := range fedErrorTree(err) {
					if m := containsAnyOf(e.Error(), fedMarkers...); m != "" {
						t.Errorf("%s: the error tree carries %q: %v", name, m, e)
					}
				}
			}
			rt, err := tokenSourceFor(googleCredential(t), ScopesStorage, rawEP)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = rt.Token(t.Context())
			check("a key's RoleTokens", googleDomain, err)
			cluster, err := New(Config{Endpoint: rawEP, Credential: loopbackCredential(t), Identity: Writer})
			if err != nil {
				t.Fatal(err)
			}
			_, err = cluster.ListNamespaces(t.Context(), "")
			check("the cluster client", "kubetest.invalid", err)
		})
	}
}

// rawAnswer answers every request with raw, written to the connection as
// it is: an answer net/http could not have written.
func rawAnswer(raw string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		conn, buf, err := http.NewResponseController(w).Hijack()
		if err != nil {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		_, _ = buf.WriteString(raw)
		_ = buf.Flush()
		_ = conn.Close()
	}
}
