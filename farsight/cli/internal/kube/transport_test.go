package kube

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cloud.google.com/go/auth"
)

// staticMint is a tokenFunc that always mints the same token value.
func staticMint(value string) tokenFunc {
	return func(context.Context) (*auth.Token, error) {
		return &auth.Token{Value: value, Type: "Bearer"}, nil
	}
}

// httptestClient is a loopback client of an httptest TLS server, trusting
// the server's own certificate as its cluster CA, with a static token.
func httptestClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	ep, err := ParseEndpoint(srv.Listener.Addr().String(), "", caPEM)
	if err != nil {
		t.Fatal(err)
	}
	c, err := newClient(Config{Endpoint: ep, Credential: Credential{Email: "writer@test.invalid"}, Identity: Writer}, staticMint("static-token"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// transportsOf are a client's three inner transports, white-box: the API's,
// a followed log's and the token endpoint's.
func transportsOf(t *testing.T, c *Client) (api, follow, token *http.Transport) {
	t.Helper()
	at, ok := c.api.Transport.(*apiTransport)
	if !ok {
		t.Fatalf("the API client's transport is %T, not *apiTransport", c.api.Transport)
	}
	ft, ok := c.follow.Transport.(*apiTransport)
	if !ok {
		t.Fatalf("the follow client's transport is %T, not *apiTransport", c.follow.Transport)
	}
	tt, ok := c.tokenHTTP.Transport.(*tokenTransport)
	if !ok {
		t.Fatalf("the token client's transport is %T, not *tokenTransport", c.tokenHTTP.Transport)
	}
	if ft.host != at.host {
		t.Errorf("the follow client sends its bearer to %q, the API client to %q", ft.host, at.host)
	}
	api, ok1 := at.inner.(*http.Transport)
	follow, ok2 := ft.inner.(*http.Transport)
	token, ok3 := tt.inner.(*http.Transport)
	if !ok1 || !ok2 || !ok3 {
		t.Fatalf("inner transports are %T, %T and %T, not *http.Transport", at.inner, ft.inner, tt.inner)
	}
	return api, follow, token
}

// TestTransportsHaveNoProxy asserts, white-box, Proxy == nil on both
// transports in both modes (§3.4): HTTPS_PROXY and the other proxy variables
// never route a bearer. A loopback request could not show it, because
// ProxyFromEnvironment never proxies a loopback host and reads the
// environment once per process. It checks the rest of §3.4's shared shape
// with it.
func TestTransportsHaveNoProxy(t *testing.T) {
	loopEP, err := ParseEndpoint("127.0.0.1:6443", "", testCAPEM())
	if err != nil {
		t.Fatal(err)
	}
	googleEP, err := ParseEndpoint("uid.us-central1.gke.goog", "us-central1", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []struct {
		name string
		cfg  Config
	}{
		{"Google", Config{Endpoint: googleEP, Credential: googleCredential(t), Identity: Writer}},
		{"loopback", Config{Endpoint: loopEP, Credential: loopbackCredential(t), Identity: Reader}},
	} {
		t.Run(m.name, func(t *testing.T) {
			c, err := New(m.cfg)
			if err != nil {
				t.Fatal(err)
			}
			api, follow, token := transportsOf(t, c)
			if api == token || api == follow || follow == token {
				t.Error("two of the API, follow and token clients share one transport")
			}
			for _, tr := range []struct {
				name          string
				t             *http.Transport
				headerTimeout time.Duration
			}{{"API", api, 30 * time.Second}, {"follow", follow, 0}, {"token", token, 30 * time.Second}} {
				if tr.t.Proxy != nil {
					t.Errorf("%s transport: Proxy is set; it must be nil so no proxy variable routes a bearer", tr.name)
				}
				tc := tr.t.TLSClientConfig
				if tc == nil || tc.MinVersion != tls.VersionTLS12 {
					t.Errorf("%s transport: TLS minimum is not 1.2", tr.name)
				} else {
					if tc.RootCAs != m.cfg.Endpoint.CA {
						t.Errorf("%s transport: RootCAs is not the endpoint's (nil, the system roots, in Google mode)", tr.name)
					}
					// A-A2-1: the server is verified against those roots
					// and nothing else, the client presents no certificate,
					// and no key is logged.
					if tc.InsecureSkipVerify || tc.VerifyPeerCertificate != nil || tc.VerifyConnection != nil || tc.ServerName != "" {
						t.Errorf("%s transport: the server's certificate is not verified as the endpoint names it", tr.name)
					}
					if tc.Certificates != nil || tc.GetClientCertificate != nil {
						t.Errorf("%s transport: the client presents a certificate", tr.name)
					}
					if tc.KeyLogWriter != nil {
						t.Errorf("%s transport: TLS keys are logged", tr.name)
					}
				}
				if !tr.t.ForceAttemptHTTP2 || tr.t.TLSHandshakeTimeout != 10*time.Second || tr.t.ResponseHeaderTimeout != tr.headerTimeout ||
					tr.t.IdleConnTimeout != 90*time.Second || tr.t.MaxIdleConnsPerHost != 4 {
					t.Errorf("%s transport: %+v is not §3.4's shape (ResponseHeaderTimeout %s)", tr.name, tr.t, tr.headerTimeout)
				}
				if tr.t.DialContext == nil {
					t.Errorf("%s transport: no dialer of its own", tr.name)
				}
			}
			if c.api.Timeout != 0 || c.follow.Timeout != 0 {
				t.Errorf("API client Timeout = %s, follow client %s; they have none, so a followed log is never cut off", c.api.Timeout, c.follow.Timeout)
			}
			if c.tokenHTTP.Timeout != 30*time.Second {
				t.Errorf("token client Timeout = %s, want 30s", c.tokenHTTP.Timeout)
			}
			if c.attemptTimeout != 60*time.Second {
				t.Errorf("attempt deadline = %s, want 60s", c.attemptTimeout)
			}
			// A-A2-4: each client's rule makes a 3xx the answer.
			for name, hc := range map[string]*http.Client{"API": c.api, "follow": c.follow, "token": c.tokenHTTP} {
				if hc.CheckRedirect == nil || !errors.Is(hc.CheckRedirect(nil, nil), http.ErrUseLastResponse) {
					t.Errorf("the %s client follows redirects", name)
				}
			}
		})
	}
}

// recordingRoundTripper records every request and answers 200.
type recordingRoundTripper struct {
	mu   sync.Mutex
	reqs []*http.Request
}

func (r *recordingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.reqs = append(r.reqs, req)
	r.mu.Unlock()
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("{}")), Request: req}, nil
}

// TestAuthorizationOnlyToTheEndpointHost drives the API RoundTripper
// directly, over a recording inner RoundTripper (§10.2): the bearer goes on
// an https request to the endpoint's own host and on nothing else, whatever
// the caller set. Every request says farcast.
func TestAuthorizationOnlyToTheEndpointHost(t *testing.T) {
	loopEP, err := ParseEndpoint("127.0.0.1:6443", "", testCAPEM())
	if err != nil {
		t.Fatal(err)
	}
	googleEP, err := ParseEndpoint("uid.us-central1.gke.goog", "us-central1", nil)
	if err != nil {
		t.Fatal(err)
	}
	tok := &auth.Token{Value: "bearer-marker", Type: "Bearer"}
	for _, m := range []struct {
		name  string
		ep    Endpoint
		cred  Credential
		cases map[string]bool // URL → whether it carries the bearer
	}{
		{"loopback", loopEP, Credential{Email: loopbackEmail}, map[string]bool{
			"https://127.0.0.1:6443/api/v1/namespaces": true,
			"https://evil.example/token":               false,
			"https://127.0.0.1:6444/api/v1/namespaces": false,
			"http://127.0.0.1:6443/api/v1/namespaces":  false,
			"https://127.0.0.2:6443/api/v1/namespaces": false,
			"https://localhost:6443/api/v1/namespaces": false,
		}},
		{"Google", googleEP, Credential{Email: googleEmail}, map[string]bool{
			"https://uid.us-central1.gke.goog/api/v1/namespaces":     true,
			"https://oauth2.googleapis.com/token":                    false,
			"https://storage.googleapis.com/b/o":                     false,
			"http://uid.us-central1.gke.goog/api/v1/namespaces":      false,
			"https://uid.us-central1.gke.goog:8443/api/v1/namespace": false,
			"https://other.us-central1.gke.goog/api/v1/namespaces":   false,
		}},
	} {
		t.Run(m.name, func(t *testing.T) {
			c, err := newClient(Config{Endpoint: m.ep, Credential: m.cred, Identity: Writer}, staticMint("unused"))
			if err != nil {
				t.Fatal(err)
			}
			rt := *c.api.Transport.(*apiTransport)
			rec := &recordingRoundTripper{}
			rt.inner = rec
			for target, carries := range m.cases {
				req, err := http.NewRequestWithContext(withBearer(context.Background(), tok), http.MethodGet, target, nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Authorization", "Bearer set-by-the-caller")
				resp, err := rt.RoundTrip(req)
				if err != nil {
					t.Fatal(err)
				}
				_ = resp.Body.Close()
				sent := rec.reqs[len(rec.reqs)-1]
				got := sent.Header.Get("Authorization")
				switch {
				case carries && got != "Bearer bearer-marker":
					t.Errorf("%s: Authorization = %q, want the endpoint's bearer", target, got)
				case !carries && got != "":
					t.Errorf("%s: Authorization = %q; a request for another host, port or scheme carries none", target, got)
				}
				if ua := sent.Header.Get("User-Agent"); ua != "farcast" {
					t.Errorf("%s: User-Agent = %q, want farcast", target, ua)
				}
				if req.Header.Get("Authorization") != "Bearer set-by-the-caller" {
					t.Errorf("%s: the RoundTripper changed its caller's request", target)
				}
			}

			// Without a token on the request, no request carries one.
			req, _ := http.NewRequest(http.MethodGet, m.ep.BaseURL()+"/api", nil)
			if _, err := rt.RoundTrip(req); err != nil {
				t.Fatal(err)
			}
			if got := rec.reqs[len(rec.reqs)-1].Header.Get("Authorization"); got != "" {
				t.Errorf("a request with no token carries %q", got)
			}
		})
	}

	// The token client never sends one.
	c, err := newClient(Config{Endpoint: loopEP, Credential: Credential{Email: loopbackEmail}, Identity: Writer}, staticMint("unused"))
	if err != nil {
		t.Fatal(err)
	}
	tt := *c.tokenHTTP.Transport.(*tokenTransport)
	rec := &recordingRoundTripper{}
	tt.inner = rec
	req, _ := http.NewRequestWithContext(withBearer(context.Background(), tok), http.MethodPost, loopEP.TokenURL(), nil)
	req.Header.Set("Authorization", "Bearer set-by-the-caller")
	if _, err := tt.RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	if got := rec.reqs[0].Header.Get("Authorization"); got != "" {
		t.Errorf("the token client sent Authorization %q", got)
	}
	if got := rec.reqs[0].Header.Get("User-Agent"); got != "farcast" {
		t.Errorf("the token client's User-Agent = %q", got)
	}
}

// TestNoRedirectIsFollowed: loopback server A answers 307 to another path on
// A; the client returns an APIError with code 307, and A saw exactly one
// request (§10.2). A redirect to another server would prove nothing: the
// loopback dialer refuses it anyway.
func TestNoRedirectIsFollowed(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/api/v1/namespaces/a/configmaps/x" {
			w.Header().Set("Location", "/api/v1/namespaces/a/configmaps/y")
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"kind":"ConfigMap","apiVersion":"v1","metadata":{"name":"y","namespace":"a"}}`)
	}))
	defer srv.Close()
	c := httptestClient(t, srv)

	_, err := c.GetConfigMap(t.Context(), "a", "x")
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status.Code != http.StatusTemporaryRedirect {
		t.Fatalf("err = %v, want an APIError with code 307", err)
	}
	if ae.KubernetesStatus {
		t.Error("an empty 307 body reads as a Kubernetes Status")
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("server A saw %d requests, want exactly 1: the redirect was followed", n)
	}
}

// TestOversizedAnswerIsUnreadableNotTruncated: an answer one cap and more
// long is ErrUnreadable with §3.4's message, never cut at the cap. The body is
// a small JSON object padded with whitespace, so cut at exactly 64 MiB it
// would still decode, and a silent truncation would pass as a success; an
// answer of exactly 64 MiB is read.
func TestOversizedAnswerIsUnreadableNotTruncated(t *testing.T) {
	const head = `{"kind":"ConfigMap","apiVersion":"v1","metadata":{"name":"big","namespace":"a"},"data":{"k":"v"}}`
	pad := make([]byte, 1<<20)
	for i := range pad {
		pad[i] = ' '
	}
	serve := func(size int) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, head)
			for left := size - len(head); left > 0; {
				n := min(left, len(pad))
				if _, err := w.Write(pad[:n]); err != nil {
					return
				}
				left -= n
			}
		}
	}

	over := httptest.NewTLSServer(serve(maxAnswer + 16))
	defer over.Close()
	_, err := httptestClient(t, over).GetConfigMap(t.Context(), "a", "big")
	if !errors.Is(err, ErrUnreadable) {
		t.Fatalf("an answer past 64 MiB: err = %v, want ErrUnreadable", err)
	}
	if want := "the API server's answer to GET /api/v1/namespaces/a/configmaps/big is larger than 64 MiB"; err.Error() != want {
		t.Errorf("err = %q, want %q", err, want)
	}

	exact := httptest.NewTLSServer(serve(maxAnswer))
	defer exact.Close()
	cm, err := httptestClient(t, exact).GetConfigMap(t.Context(), "a", "big")
	if err != nil || cm.Data["k"] != "v" {
		t.Fatalf("an answer of exactly 64 MiB: %+v, %v; it must be read", cm, err)
	}
}

// TestRetryWaitsHonourRetryAfterCappedAtTenSeconds: a 503 asking for 30 s
// waits 10 s, a 429 naming no wait waits 1 s, and a date waits 1 s (§3.4).
func TestRetryWaitsHonourRetryAfterCappedAtTenSeconds(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch n.Add(1) {
		case 1:
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusServiceUnavailable)
		case 2:
			w.WriteHeader(http.StatusTooManyRequests)
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"metadata":{"name":"x","namespace":"a"}}`)
		}
	}))
	defer srv.Close()
	c := httptestClient(t, srv)
	var waits []time.Duration
	c.sleep = func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}
	if _, err := c.GetConfigMap(t.Context(), "a", "x"); err != nil {
		t.Fatal(err)
	}
	if want := []time.Duration{10 * time.Second, time.Second}; !slices.Equal(waits, want) {
		t.Errorf("waits = %v, want %v", waits, want)
	}

	for _, c := range []struct {
		header string
		want   time.Duration
	}{
		{"", time.Second},
		{"0", 0},
		{"3", 3 * time.Second},
		{"10", 10 * time.Second},
		{"11", 10 * time.Second},
		{"-1", time.Second},
		{"Sat, 14 Nov 2026 09:00:00 GMT", time.Second},
		// A-A2-2: capped before it is multiplied, so no value overflows into
		// a negative or a short wait; one past int's range names none.
		{"9223372037", 10 * time.Second},
		{"18446744074", 10 * time.Second},
		{"27670116111", 10 * time.Second},
		{"99999999999999999999", time.Second},
	} {
		h := http.Header{}
		if c.header != "" {
			h.Set("Retry-After", c.header)
		}
		if got := retryAfter(h); got != c.want {
			t.Errorf("Retry-After %q: wait %s, want %s", c.header, got, c.want)
		}
	}
}

// TestSleepContext (F-F4): the product's wait between retries, the one every
// retry test replaces, waits d, or returns the context's error as soon as the
// context ends; d ≤ 0 waits nothing and reports a context already ended.
func TestSleepContext(t *testing.T) {
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	cases := []struct {
		name    string
		ctx     context.Context
		d       time.Duration
		want    error
		atLeast time.Duration
	}{
		{"zero, live", context.Background(), 0, nil, 0},
		{"negative, live", context.Background(), -time.Second, nil, 0},
		{"zero, ended", ended, 0, context.Canceled, 0},
		{"positive, live", context.Background(), 80 * time.Millisecond, nil, 80 * time.Millisecond},
		{"positive, ended", ended, 10 * time.Second, context.Canceled, 0},
	}
	for _, c := range cases {
		start := time.Now()
		err := sleepContext(c.ctx, c.d)
		elapsed := time.Since(start)
		if !errors.Is(err, c.want) || (c.want == nil && err != nil) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
		if elapsed < c.atLeast {
			t.Errorf("%s: returned after %s, before %s", c.name, elapsed, c.atLeast)
		}
		if elapsed > c.atLeast+5*time.Second {
			t.Errorf("%s: returned after %s", c.name, elapsed)
		}
	}

	// A context that ends during the wait ends it, with its own error.
	for _, end := range []struct {
		name string
		ctx  func() (context.Context, context.CancelFunc)
		want error
	}{
		{"cancelled", func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(50*time.Millisecond, cancel)
			return ctx, cancel
		}, context.Canceled},
		{"past its deadline", func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 50*time.Millisecond)
		}, context.DeadlineExceeded},
	} {
		ctx, cancel := end.ctx()
		start := time.Now()
		err := sleepContext(ctx, 10*time.Second)
		elapsed := time.Since(start)
		cancel()
		if !errors.Is(err, end.want) {
			t.Errorf("%s mid-wait: err = %v, want %v", end.name, err, end.want)
		}
		if elapsed > 5*time.Second {
			t.Errorf("%s mid-wait: returned after %s, not when the context ended", end.name, elapsed)
		}
	}
}

// TestHTTP2DebugLoggingRefusesEveryClient (S-F1): while GODEBUG has turned on
// Go's HTTP/2 logging, which prints every request header, the bearer
// included, to stderr, newClient refuses first, for New and for every other
// caller, and mints nothing. http2DebugLogging is net/http's own test of the
// variable (go1.27.4 src/net/http/internal/http2/http2.go, init).
func TestHTTP2DebugLoggingRefusesEveryClient(t *testing.T) {
	for godebug, want := range map[string]bool{
		"":             false,
		"http2debug=1": true,
		"http2debug=2": true,
		"x509sslcertoverrideplatform=1,http2debug=2": true,
		"http2debug=0":    false,
		"http2client=0":   false,
		"http2xconnect=1": false,
	} {
		if got := http2DebugLogging(godebug); got != want {
			t.Errorf("http2DebugLogging(%q) = %v, want %v", godebug, got, want)
		}
	}

	saved := http2Verbose
	t.Cleanup(func() { http2Verbose = saved })
	http2Verbose = true
	ep, err := ParseEndpoint("127.0.0.1:1", "", testCAPEM())
	if err != nil {
		t.Fatal(err)
	}
	m := &countingMint{}
	for name, build := range map[string]func() (*Client, error){
		"newClient": func() (*Client, error) {
			return newClient(Config{Endpoint: ep, Credential: loopbackCredential(t), Identity: Reader}, m.mint)
		},
		"New": func() (*Client, error) {
			return New(Config{Endpoint: ep, Credential: loopbackCredential(t), Identity: Writer})
		},
		"a pair that is refused too": func() (*Client, error) {
			return newClient(Config{Endpoint: ep, Credential: googleCredential(t), Identity: Writer}, m.mint)
		},
	} {
		c, err := build()
		if c != nil || !errors.Is(err, ErrUnsafeEnvironment) || errors.Is(err, ErrEndpointRefused) || err.Error() != msgHTTP2Debug {
			t.Errorf("%s: %v, %v; want the GODEBUG refusal, ErrUnsafeEnvironment and not ErrEndpointRefused", name, c, err)
		}
	}
	if m.calls() != 0 {
		t.Errorf("%d mints under the GODEBUG refusal", m.calls())
	}

	http2Verbose = false
	if _, err := newClient(Config{Endpoint: ep, Credential: loopbackCredential(t), Identity: Reader}, m.mint); err != nil {
		t.Errorf("without the logging: %v", err)
	}
}

// TestLoopbackDialerRefusesAnyOtherAddress: in loopback mode both transports
// dial only the endpoint's own address.
func TestLoopbackDialerRefusesAnyOtherAddress(t *testing.T) {
	other, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()
	ep, err := ParseEndpoint("127.0.0.1:6443", "", testCAPEM())
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{Endpoint: ep, Credential: loopbackCredential(t), Identity: Writer})
	if err != nil {
		t.Fatal(err)
	}
	api, follow, token := transportsOf(t, c)
	for name, tr := range map[string]*http.Transport{"API": api, "follow": follow, "token": token} {
		conn, err := tr.DialContext(t.Context(), "tcp", other.Addr().String())
		if err == nil {
			_ = conn.Close()
			t.Fatalf("%s transport dialled %s", name, other.Addr())
		}
		if want := fmt.Sprintf("kube: loopback client refused to dial %s", other.Addr()); !strings.Contains(err.Error(), want) {
			t.Errorf("%s transport: %v, want it to say %q", name, err, want)
		}
	}
}

// TestParseWarnings reads RFC 7234 §5.5's form as the API server writes it.
func TestParseWarnings(t *testing.T) {
	got := parseWarnings([]string{
		`299 - "a"`,
		`299 - "say \"hi\" \\ there"`,
		`299 - "x, with a comma", 299 - "y" "Sat, 14 Nov 2026 09:00:00 GMT"`,
		`199 - "not a 299"`,
		`garbage`,
		`299 - "unterminated`,
		`299 - "z" trailing`,
	})
	want := []string{"a", `say "hi" \ there`, "x, with a comma", "y", "z"}
	if !slices.Equal(got, want) {
		t.Errorf("parseWarnings = %q, want %q", got, want)
	}
}

// quietTLSServer is an httptest TLS server whose handshake failures are not
// logged to the test's output.
func quietTLSServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// TestAServerOffTheClusterCAIsRefused (A-A2-1): a TLS server whose certificate
// the endpoint's cluster CA did not issue gets no request at all, so neither
// the bearer (the API client) nor the signed assertion (the token client, in
// loopback mode) reaches it. The failed handshake is ErrUnreachable, with the
// x509 error as its cause and in its text, never "no answer within".
func TestAServerOffTheClusterCAIsRefused(t *testing.T) {
	var hits atomic.Int32
	srv := quietTLSServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	ep, err := ParseEndpoint(srv.Listener.Addr().String(), "", testCAPEM())
	if err != nil {
		t.Fatal(err)
	}
	refused := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, ErrUnreachable) {
			t.Errorf("%s: err = %v, want ErrUnreachable", name, err)
		}
		if !errors.As(err, new(x509.UnknownAuthorityError)) {
			t.Errorf("%s: err = %v; its cause is not the unknown authority", name, err)
		}
		if err != nil && (!strings.Contains(err.Error(), "x509") || strings.Contains(err.Error(), "no answer within")) {
			t.Errorf("%s: err = %q, want the x509 failure in its text", name, err)
		}
	}

	m := &countingMint{}
	c, err := newClient(Config{Endpoint: ep, Credential: Credential{Email: loopbackEmail}, Identity: Writer}, m.mint)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.ListNamespaces(t.Context(), "")
	refused("the API client", err)
	if m.calls() != 1 {
		t.Errorf("%d mints, want exactly 1: the handshake failure is not a 401", m.calls())
	}

	c, err = New(Config{Endpoint: ep, Credential: loopbackCredential(t), Identity: Writer})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.ListNamespaces(t.Context(), "")
	refused("the token client", err)

	if n := hits.Load(); n != 0 {
		t.Errorf("the server off the cluster CA saw %d requests, want 0", n)
	}
}

// TestTheTokenClientFollowsNoRedirect (A-A2-4): a token endpoint that answers
// 307 is refused as that answer; the token client never posts the signed
// assertion again to the Location it names. The Location is on the same
// server, because the loopback dialer would refuse any other.
func TestTheTokenClientFollowsNoRedirect(t *testing.T) {
	var token, redirected, api atomic.Int32
	srv := quietTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			token.Add(1)
			w.Header().Set("Location", "/token2")
			w.WriteHeader(http.StatusTemporaryRedirect)
		case "/token2":
			redirected.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"access_token":"redirected","token_type":"Bearer","expires_in":3600}`)
		default:
			api.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"kind":"NamespaceList","apiVersion":"v1","metadata":{},"items":[]}`)
		}
	}))
	c, err := New(Config{Endpoint: httptestClient(t, srv).ep, Credential: loopbackCredential(t), Identity: Writer})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.ListNamespaces(t.Context(), "")
	if !errors.Is(err, ErrTokenRefused) || !strings.Contains(err.Error(), "(307 Temporary Redirect)") {
		t.Errorf("err = %v, want the token endpoint's 307 as ErrTokenRefused", err)
	}
	if token.Load() != 1 || redirected.Load() != 0 || api.Load() != 0 {
		t.Errorf("requests: %d to /token, %d to its Location, %d to the API; want 1, 0, 0", token.Load(), redirected.Load(), api.Load())
	}
}

// TestANonStreamingAttemptHasADeadline (A-A2-5): a non-streaming attempt ends
// at its own deadline, before its caller's, whether the server stalls before
// its headers or after them, mid-body; ResponseHeaderTimeout would not cover
// the second. The deadline is shortened here; it is 60 s in a product client.
func TestANonStreamingAttemptHasADeadline(t *testing.T) {
	release := make(chan struct{})
	srv := quietTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/namespaces/a/configmaps/mid-body" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"kind":"ConfigMap",`)
			w.(http.Flusher).Flush()
		}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer close(release)
	c := httptestClient(t, srv)
	c.attemptTimeout = 200 * time.Millisecond

	for _, name := range []string{"before-headers", "mid-body"} {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		start := time.Now()
		_, err := c.GetConfigMap(ctx, "a", name)
		elapsed := time.Since(start)
		if !errors.Is(err, ErrUnreachable) || !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("%s: err = %v, want ErrUnreachable at the attempt's deadline", name, err)
		}
		if elapsed > 2*time.Second {
			t.Errorf("%s: returned after %s; the attempt has no deadline of its own", name, elapsed)
		}
		if ctx.Err() != nil {
			t.Errorf("%s: the caller's context ended first: %v", name, ctx.Err())
		}
		if name == "before-headers" && (err == nil || !strings.Contains(err.Error(), "no answer within 200ms")) {
			t.Errorf("%s: err = %v, want it to say no answer within 200ms", name, err)
		}
		cancel()
	}
}
