package kube_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
	tkube "github.com/sofmon/farcast/technocore/kube"
)

// assertionOf decodes the JWT a /token request carried: its header, its
// claims and its raw text.
func assertionOf(t *testing.T, r kubetest.Request) (header, claims map[string]any, raw string) {
	t.Helper()
	form, err := url.ParseQuery(string(r.Body))
	if err != nil {
		t.Fatalf("the token request's form: %v", err)
	}
	if g := form.Get("grant_type"); g != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		t.Errorf("grant_type = %q", g)
	}
	raw = form.Get("assertion")
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("the assertion has %d parts", len(parts))
	}
	for i, dst := range []*map[string]any{&header, &claims} {
		b, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			t.Fatal(err)
		}
		d := json.NewDecoder(bytes.NewReader(b))
		d.UseNumber()
		if err := d.Decode(dst); err != nil {
			t.Fatal(err)
		}
	}
	return header, claims, raw
}

func claimInt(t *testing.T, claims map[string]any, name string) int64 {
	t.Helper()
	n, ok := claims[name].(json.Number)
	if !ok {
		t.Fatalf("claim %s is %T, not a number", name, claims[name])
	}
	v, err := n.Int64()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestTokenAssertionClaims: the 2LO assertion a client signs is kubetest's
// to verify (the two scopes, exp − iat ≤ 3600), and this test pins it
// exactly: iss is the credential's email, aud the endpoint's own token URL,
// scope exactly cloud-platform then userinfo.email, space-separated (design
// A22-7: the DNS endpoint answered 401 to userinfo.email alone), exp − iat
// exactly 3600 (Expires left zero), kid the recorded key id, RS256, and no
// subject.
func TestTokenAssertionClaims(t *testing.T) {
	s := kubetest.New(t)
	ep, err := kube.ParseEndpoint(s.Endpoint(), "", s.CAPEM())
	if err != nil {
		t.Fatal(err)
	}
	cred := s.Credential("writer")
	c, err := kube.New(kube.Config{Endpoint: ep, Credential: cred, Identity: kube.Writer})
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now().Unix()
	if _, err := c.ListNamespaces(t.Context(), ""); err != nil {
		t.Fatalf("the first request, which mints: %v", err)
	}
	toks := tokenRequests(s)
	if len(toks) != 1 {
		t.Fatalf("%d token requests, want 1", len(toks))
	}
	r := toks[0]
	if r.Method != http.MethodPost || r.ContentType != "application/x-www-form-urlencoded" || r.As != "writer" {
		t.Errorf("token request: %s %s As %q", r.Method, r.ContentType, r.As)
	}
	if r.KeyID != cred.PrivateKeyID {
		t.Errorf("kid = %q, want the recorded key id %q", r.KeyID, cred.PrivateKeyID)
	}
	header, claims, _ := assertionOf(t, r)
	if header["alg"] != "RS256" || header["kid"] != cred.PrivateKeyID {
		t.Errorf("header = %v", header)
	}
	if claims["iss"] != cred.Email {
		t.Errorf("iss = %v, want %s", claims["iss"], cred.Email)
	}
	if claims["aud"] != ep.TokenURL() || ep.TokenURL() != "https://"+s.Endpoint()+"/token" {
		t.Errorf("aud = %v, want %s", claims["aud"], ep.TokenURL())
	}
	const wantScope = "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email"
	if claims["scope"] != wantScope {
		t.Errorf("scope = %v, want exactly %s", claims["scope"], wantScope)
	}
	if _, ok := claims["sub"]; ok {
		t.Errorf("the assertion names a subject %v", claims["sub"])
	}
	iat, exp := claimInt(t, claims, "iat"), claimInt(t, claims, "exp")
	if exp-iat != 3600 {
		t.Errorf("exp − iat = %d, want 3600 (Google's maximum is one hour)", exp-iat)
	}
	if iat < before-20 || iat > time.Now().Unix() {
		t.Errorf("iat = %d, not about now − 10 s (%d)", iat, before)
	}
}

// TestTokenLoggerDiscardsEvenWithTheDebugVariable: with
// GOOGLE_SDK_GO_LOGGING_LEVEL=debug and stderr captured, a client's mint and
// request show no assertion, no token and no log line at all. A nil Logger
// would make the library log both to stderr (§3.3).
func TestTokenLoggerDiscardsEvenWithTheDebugVariable(t *testing.T) {
	t.Setenv("GOOGLE_SDK_GO_LOGGING_LEVEL", "debug")
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
	os.Stderr = w

	s := kubetest.New(t)
	c, _ := connect(t, s, "writer") // the library picks its logger here
	_, err = c.ListNamespaces(t.Context(), "")
	restore()
	if err != nil {
		t.Fatal(err)
	}

	toks := tokenRequests(s)
	if len(toks) != 1 {
		t.Fatalf("%d token requests, want 1", len(toks))
	}
	_, _, assertion := assertionOf(t, toks[0])
	out := captured.String()
	if m := containsAny(out, assertion, "kubetest:writer:", "access_token", "assertion", "2LO"); m != "" {
		t.Errorf("stderr carries %q", m)
	}
	if out != "" {
		t.Errorf("stderr is not empty: %d bytes", len(out))
	}
}

// http2DebugChild marks the child run of
// TestHTTP2DebugLoggingNeverPrintsTheBearer.
const http2DebugChild = "FARCAST_KUBE_TEST_HTTP2DEBUG_CHILD"

// TestHTTP2DebugLoggingNeverPrintsTheBearer (S-F1): with GODEBUG=http2debug=2
// in its environment, Go's HTTP/2 client logs every request header, the
// bearer included, and every frame, the assertion and the minted token
// included, to stderr, as soon as net/http initializes; nothing the process
// does later can turn it off. The test runs itself again as a child with that
// environment. There New must refuse, and the fake must see no request; the
// child's stderr must carry neither a token nor the assertion. Were New to
// build a client, the child would go on to mint and read, and its stderr
// would show what the logging prints.
func TestHTTP2DebugLoggingNeverPrintsTheBearer(t *testing.T) {
	if os.Getenv(http2DebugChild) == "1" {
		http2DebugChildRun(t)
		return
	}
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GODEBUG=") && !strings.HasPrefix(kv, http2DebugChild+"=") {
			env = append(env, kv)
		}
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestHTTP2DebugLoggingNeverPrintsTheBearer$", "-test.count=1", "-test.v")
	cmd.Env = append(env, "GODEBUG=http2debug=2", http2DebugChild+"=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Errorf("the child run failed: %v\n%s", err, stdout.String())
	}
	if !strings.Contains(stdout.String(), "--- PASS: TestHTTP2DebugLoggingNeverPrintsTheBearer") {
		t.Errorf("the child did not pass the test:\n%s", stdout.String())
	}
	if m := containsAny(stderr.String(), "kubetest:", "Bearer", "authorization", "assertion", "access_token"); m != "" {
		t.Errorf("the child's stderr carries %q", m)
	}
}

// http2DebugChildRun is the child's half: GODEBUG=http2debug=2 is set.
func http2DebugChildRun(t *testing.T) {
	s := kubetest.New(t)
	ep, err := kube.ParseEndpoint(s.Endpoint(), "", s.CAPEM())
	if err != nil {
		t.Fatal(err)
	}
	c, err := kube.New(kube.Config{Endpoint: ep, Credential: s.Credential("writer"), Identity: kube.Writer})
	if err == nil {
		t.Error("New built a client while GODEBUG names http2debug")
		_, _ = c.ListNamespaces(t.Context(), "") // whatever the logging prints reaches the parent's check
	} else if !errors.Is(err, kube.ErrUnsafeEnvironment) || errors.Is(err, kube.ErrEndpointRefused) || !strings.Contains(err.Error(), "GODEBUG names http2debug") {
		t.Errorf("New: err = %v, want the GODEBUG refusal, ErrUnsafeEnvironment and not ErrEndpointRefused", err)
	}
	if n := len(s.Requests()); n != 0 {
		t.Errorf("the fake saw %d requests", n)
	}
}

// TestUnauthorizedRemintsOnce: a 401 drops the token the request carried,
// mints once more and retries once, for any method; a second 401 is the
// error (§3.4). Revoke makes the first token stale on the server.
func TestUnauthorizedRemintsOnce(t *testing.T) {
	s := kubetest.New(t)
	c, _ := connect(t, s, "writer")
	ctx := t.Context()

	if _, err := c.ListNamespaces(ctx, ""); err != nil {
		t.Fatal(err)
	}
	s.Revoke("kubetest:writer:1")
	if _, err := c.ListNamespaces(ctx, ""); err != nil {
		t.Fatalf("after a revoked token: %v; a 401 re-mints once and retries", err)
	}
	var as []string
	for _, r := range s.Requests() {
		as = append(as, r.Path+"/"+r.As)
	}
	want := []string{"/token/writer", "/api/v1/namespaces/writer", "/api/v1/namespaces/?", "/token/writer", "/api/v1/namespaces/writer"}
	if strings.Join(as, " ") != strings.Join(want, " ") {
		t.Errorf("requests = %v, want %v", as, want)
	}

	// Two 401s in a row: one re-mint, one retry, and the second is the error.
	s.Fail(http.MethodGet, "/api/v1/namespaces", http.StatusUnauthorized, kube.Status{})
	s.Fail(http.MethodGet, "/api/v1/namespaces", http.StatusUnauthorized, kube.Status{})
	before := len(requestsTo(s, http.MethodGet, "/api/v1/namespaces"))
	_, err := c.ListNamespaces(ctx, "")
	if !errors.Is(err, tkube.ErrUnauthorized) {
		t.Fatalf("two 401s: err = %v, want tkube.ErrUnauthorized", err)
	}
	if n := len(requestsTo(s, http.MethodGet, "/api/v1/namespaces")) - before; n != 2 {
		t.Errorf("two 401s: %d requests, want 2 (one retry, no more)", n)
	}
	if n := len(tokenRequests(s)); n != 3 {
		t.Errorf("%d mints in all, want 3", n)
	}
	if strings.Contains(err.Error(), "kubetest:") {
		t.Errorf("the error carries a token: %v", err)
	}

	// A POST is re-sent once too, body and all.
	s.Fail(http.MethodPost, "/api/v1/namespaces/web/configmaps", http.StatusUnauthorized, kube.Status{})
	pin := []byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"pin","namespace":"web"},"data":{"k":"v"}}`)
	if err := c.CreateConfigMap(ctx, pin); err != nil {
		t.Fatalf("a POST after a 401: %v", err)
	}
	posts := requestsTo(s, http.MethodPost, "/api/v1/namespaces/web/configmaps")
	if len(posts) != 2 || !bytes.Equal(posts[1].Body, pin) {
		t.Errorf("POSTs = %d, the retry's body %q", len(posts), posts[len(posts)-1].Body)
	}
	if cm, err := c.GetConfigMap(ctx, "web", "pin"); err != nil || cm.Data["k"] != "v" {
		t.Errorf("the re-sent POST did not create the ConfigMap: %+v, %v", cm, err)
	}
}

// TestTokenRefusalCarriesNoSecret: Google's refusal to mint is
// ErrTokenRefused, named by the identity's email domain and the status, and
// nothing is sent to the API.
func TestTokenRefusalCarriesNoSecret(t *testing.T) {
	const marker = "SECRET-MARKER"
	s := kubetest.New(t, kubetest.WithTokenAnswer(func(string) (int, []byte, bool) {
		return http.StatusBadRequest, []byte(`{"error":"invalid_grant","error_description":"` + marker + `"}`), true
	}))
	c, _ := connect(t, s, "writer")
	_, err := c.ListNamespaces(t.Context(), "")
	if !errors.Is(err, kube.ErrTokenRefused) {
		t.Fatalf("err = %v, want ErrTokenRefused", err)
	}
	if want := "Google refused to mint a token for the kubetest.invalid service account (400 Bad Request)"; err.Error() != want {
		t.Errorf("err = %q, want %q", err, want)
	}
	if strings.Contains(err.Error(), marker) {
		t.Errorf("the refusal carries the token endpoint's body")
	}
	if n := len(apiRequests(s)); n != 0 {
		t.Errorf("%d API requests after a refused mint", n)
	}
}

// TestEveryRequestSaysFarcast: every request, the token's and the API's,
// carries User-Agent: farcast and nothing more, and every API request asks
// for JSON.
func TestEveryRequestSaysFarcast(t *testing.T) {
	s := kubetest.New(t)
	c, _ := connect(t, s, "writer")
	ctx := t.Context()
	_, _ = c.ListNamespaces(ctx, "")
	_, _ = c.GetConfigMap(ctx, "web", "absent")
	_ = c.CreateConfigMap(ctx, []byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"p","namespace":"web"}}`))
	reqs := s.Requests()
	if len(reqs) < 4 {
		t.Fatalf("%d requests", len(reqs))
	}
	for _, r := range reqs {
		if r.UserAgent != "farcast" {
			t.Errorf("%s %s: User-Agent %q, want exactly farcast", r.Method, r.Path, r.UserAgent)
		}
		if r.Path != "/token" && r.Accept != "application/json" {
			t.Errorf("%s %s: Accept %q", r.Method, r.Path, r.Accept)
		}
	}
}
