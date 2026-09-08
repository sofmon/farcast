package proxy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/sofmon/farcast/fatline/event"
	"github.com/sofmon/farcast/fatline/internal/allowlist"
	fcrypto "github.com/sofmon/farcast/fatline/internal/crypto"
	"github.com/sofmon/farcast/manifest/parser"
)

type capture struct {
	mu sync.Mutex
	ev []event.Event
}

func (c *capture) Emit(e event.Event) {
	c.mu.Lock()
	c.ev = append(c.ev, e)
	c.mu.Unlock()
}

func (c *capture) all() []event.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]event.Event(nil), c.ev...)
}

func (c *capture) kinds(k event.Kind) int {
	n := 0
	for _, e := range c.all() {
		if e.Kind == k {
			n++
		}
	}
	return n
}

// proxyClient wires an http.Client through a freshly served proxy. tlsCfg
// configures the inner (client→upstream) TLS leg.
func proxyClient(t *testing.T, p *Proxy, tlsCfg *tls.Config) *http.Client {
	t.Helper()
	ps := httptest.NewServer(p)
	t.Cleanup(ps.Close)
	pu, err := url.Parse(ps.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: tlsCfg}}
}

// proxyClientWithCredential is proxyClient with the credential in the proxy
// URL's userinfo — which is how an application actually presents it, and the
// reason ADR 0013 decision 2 can claim applications need no change: the
// standard library turns userinfo into Proxy-Authorization on its own.
func proxyClientWithCredential(t *testing.T, p *Proxy, tlsCfg *tls.Config, credential string) *http.Client {
	t.Helper()
	ps := httptest.NewServer(p)
	t.Cleanup(ps.Close)
	pu, err := url.Parse(ps.URL)
	if err != nil {
		t.Fatal(err)
	}
	if credential != "" {
		pu.User = url.UserPassword("app", credential)
	}
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: tlsCfg}}
}

// tlsUpstream starts a TLS server with a cert for host (signed by a fresh CA)
// that replies "ok", and returns its address plus the CA pool to trust it.
func tlsUpstream(t *testing.T, host string) (addr string, caPool *tls.Config) {
	t.Helper()
	ca, err := fcrypto.NewCA("upstream")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.IssueServer(host)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := leaf.TLSCertificate()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String(), &tls.Config{RootCAs: ca.CertPool(), MinVersion: tls.VersionTLS13}
}

// anyCaller identifies every request as one known application on the default
// tenant, which is what these tests were written against — they exercise the
// allowlist and the tunnel, not identity. The tests that exercise identity say
// so in their names.
func anyCaller(credential string) (Caller, bool) {
	return Caller{Tenant: "", Namespace: "ns", App: "app"}, true
}

func TestConnectDenied(t *testing.T) {
	cp := &capture{}
	p := New(Options{Identify: anyCaller, Allowlist: allowlist.New([]parser.External{{Host: "allowed.test"}}), Events: cp, EnforceSNI: true})
	client := proxyClient(t, p, nil)

	if _, err := client.Get("https://denied.test:443/"); err == nil {
		t.Fatal("expected an error for a CONNECT to a non-allowlisted host")
	}
	ev := cp.all()
	if len(ev) != 1 || ev[0].Kind != event.Deny || ev[0].Reason != event.ReasonNotInAllowlist {
		t.Fatalf("expected exactly one deny(not_in_allowlist) event, got %+v", ev)
	}
}

func TestCleartextDenied(t *testing.T) {
	cp := &capture{}
	// Cleartext is denied even for an allowlisted host: confidentiality is part
	// of deny-by-default.
	p := New(Options{Identify: anyCaller, Allowlist: allowlist.New([]parser.External{{Host: "allowed.test"}}), Events: cp})
	client := proxyClient(t, p, nil)

	resp, err := client.Get("http://allowed.test/")
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d, want 403", resp.StatusCode)
	}
	if ev := cp.all(); len(ev) != 1 || ev[0].Reason != event.ReasonCleartext {
		t.Fatalf("expected one deny(cleartext_not_allowed) event, got %+v", ev)
	}
}

func TestConnectAllowedTunnels(t *testing.T) {
	upAddr, clientTLS := tlsUpstream(t, "upstream.test")
	cp := &capture{}
	p := New(Options{
		Identify:   anyCaller,
		Allowlist:  allowlist.New([]parser.External{{Host: "upstream.test"}}),
		Events:     cp,
		EnforceSNI: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", upAddr)
		},
	})
	client := proxyClient(t, p, clientTLS)

	resp, err := client.Get("https://upstream.test:443/")
	if err != nil {
		t.Fatalf("get through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Fatalf("body=%q, want ok", body)
	}
	if cp.kinds(event.Allow) != 1 {
		t.Fatalf("expected one allow event, got %+v", cp.all())
	}
}

func TestConnectSNIMismatch(t *testing.T) {
	upAddr, clientTLS := tlsUpstream(t, "upstream.test")
	// Force the inner TLS SNI to a different name than the CONNECT authority.
	clientTLS.ServerName = "evil.test"
	cp := &capture{}
	p := New(Options{
		Identify:   anyCaller,
		Allowlist:  allowlist.New([]parser.External{{Host: "upstream.test"}}),
		Events:     cp,
		EnforceSNI: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", upAddr)
		},
	})
	client := proxyClient(t, p, clientTLS)

	if _, err := client.Get("https://upstream.test:443/"); err == nil {
		t.Fatal("expected the connection to be torn down on SNI mismatch")
	}
	mismatch := false
	for _, e := range cp.all() {
		if e.Kind == event.Deny && e.Reason == event.ReasonSNIMismatch {
			mismatch = true
		}
	}
	if !mismatch {
		t.Fatalf("expected a deny(sni_mismatch) event, got %+v", cp.all())
	}
}

// perApp is a two-application policy: each may reach its own host and nothing
// else. Credentials are the map keys.
func perApp() (*allowlist.List, IdentifyFunc) {
	list := allowlist.NewPerApp(map[string][]parser.External{
		"ns/alpha": {{Host: "alpha.test", Reason: "alpha's own"}},
		"ns/beta":  {{Host: "beta.test", Reason: "beta's own"}},
	})
	byCredential := map[string]Caller{
		"alpha-credential": {Tenant: "ns/alpha", Namespace: "ns", App: "alpha"},
		"beta-credential":  {Tenant: "ns/beta", Namespace: "ns", App: "beta"},
	}
	return list, func(c string) (Caller, bool) {
		caller, ok := byCredential[c]
		return caller, ok
	}
}

// The property PLAN 4.4 names: App A cannot use App B's external declarations.
func TestAnApplicationCannotUseAnothersDeclarations(t *testing.T) {
	list, identify := perApp()

	for name, tc := range map[string]struct {
		credential string
		host       string
		wantAllow  bool
	}{
		"alpha reaching its own host": {"alpha-credential", "alpha.test", true},
		"beta reaching its own host":  {"beta-credential", "beta.test", true},
		"alpha reaching beta's host":  {"alpha-credential", "beta.test", false},
		"beta reaching alpha's host":  {"beta-credential", "alpha.test", false},
		"an unknown caller":           {"nobody", "alpha.test", false},
		"no credential at all":        {"", "alpha.test", false},
	} {
		t.Run(name, func(t *testing.T) {
			cp := &capture{}
			p := New(Options{Allowlist: list, Identify: identify, Events: cp})
			client := proxyClientWithCredential(t, p, nil, tc.credential)

			_, err := client.Get("https://" + tc.host + ":443/")
			// Every case fails to complete — there is no upstream — so the
			// event is what says whether policy allowed it.
			_ = err
			ev := cp.all()
			if len(ev) == 0 {
				t.Fatal("no decision was emitted")
			}
			allowed := ev[0].Kind == event.Allow
			if allowed != tc.wantAllow {
				t.Fatalf("decision = %+v, want allowed=%v", ev[0], tc.wantAllow)
			}
		})
	}
}

// A denial has to say which application was denied, or an alert cannot act on
// it (ADR 0013 decision 7).
func TestEveryDecisionNamesTheApplication(t *testing.T) {
	list, identify := perApp()
	cp := &capture{}
	p := New(Options{Allowlist: list, Identify: identify, Events: cp})
	client := proxyClientWithCredential(t, p, nil, "alpha-credential")

	_, _ = client.Get("https://beta.test:443/")
	ev := cp.all()
	if len(ev) == 0 {
		t.Fatal("no decision was emitted")
	}
	if ev[0].App != "alpha" || ev[0].Tenant != "ns" {
		t.Errorf("decision = %+v, want it attributed to alpha in ns", ev[0])
	}
	if ev[0].Reason != event.ReasonNotInAllowlist {
		t.Errorf("reason = %q, want %q", ev[0].Reason, event.ReasonNotInAllowlist)
	}
}

// "I do not know who is asking" and "you may not reach that" are different
// problems with different fixes, so they are different reasons.
func TestAnUnidentifiedCallerIsItsOwnReason(t *testing.T) {
	list, identify := perApp()
	cp := &capture{}
	p := New(Options{Allowlist: list, Identify: identify, Events: cp})
	client := proxyClientWithCredential(t, p, nil, "not-a-credential")

	_, _ = client.Get("https://alpha.test:443/")
	ev := cp.all()
	if len(ev) == 0 || ev[0].Reason != event.ReasonUnknownApp {
		t.Fatalf("events = %+v, want a deny(unknown_app)", ev)
	}
}

// A proxy with no way to identify callers must deny everything rather than
// serve a policy it cannot attribute.
func TestAProxyWithNoIdentityDeniesEverything(t *testing.T) {
	cp := &capture{}
	p := New(Options{
		Allowlist: allowlist.NewPerApp(map[string][]parser.External{"ns/alpha": {{Host: "alpha.test"}}}),
		Events:    cp,
	})
	client := proxyClientWithCredential(t, p, nil, "alpha-credential")

	_, _ = client.Get("https://alpha.test:443/")
	ev := cp.all()
	if len(ev) == 0 || ev[0].Kind != event.Deny {
		t.Fatalf("events = %+v, want a denial", ev)
	}
	// And denied for the RIGHT reason. A proxy that cannot identify anyone is
	// misconfigured, which is a different problem from a host nobody declared
	// — and only one of them is fixed by editing a manifest.
	if ev[0].Reason != event.ReasonUnknownApp {
		t.Errorf("reason = %q, want %q", ev[0].Reason, event.ReasonUnknownApp)
	}
}

// There is no instance-wide allowlist to fall back on, and this is what proves
// it: a caller FatLine identifies but whose tenant it has no policy for must be
// denied rather than quietly checked against somebody else's list.
func TestAnIdentifiedCallerWithNoPolicyIsDenied(t *testing.T) {
	cp := &capture{}
	p := New(Options{
		Allowlist: allowlist.NewPerApp(map[string][]parser.External{
			"ns/alpha": {{Host: "alpha.test", Reason: "alpha's own"}},
		}),
		Identify: func(string) (Caller, bool) {
			return Caller{Tenant: "ns/ghost", Namespace: "ns", App: "ghost"}, true
		},
		Events: cp,
	})
	client := proxyClientWithCredential(t, p, nil, "whatever")

	_, _ = client.Get("https://alpha.test:443/")
	ev := cp.all()
	if len(ev) == 0 {
		t.Fatal("no decision was emitted")
	}
	if ev[0].Kind != event.Deny {
		t.Fatalf("decision = %+v; a tenant with no policy inherited one", ev[0])
	}
	if ev[0].App != "ghost" {
		t.Errorf("the denial does not name the caller: %+v", ev[0])
	}
}

// The credential must not appear anywhere FatLine reports.
func TestTheCredentialNeverReachesAnEvent(t *testing.T) {
	list, identify := perApp()
	cp := &capture{}
	p := New(Options{Allowlist: list, Identify: identify, Events: cp})
	client := proxyClientWithCredential(t, p, nil, "alpha-credential")

	_, _ = client.Get("https://beta.test:443/")
	for _, ev := range cp.all() {
		if strings.Contains(fmt.Sprintf("%+v", ev), "alpha-credential") {
			t.Fatalf("an event carries the credential: %+v", ev)
		}
	}
}

func TestCredentialFrom(t *testing.T) {
	basic := func(user, pass string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	}
	for name, tc := range map[string]struct {
		header string
		want   string
	}{
		"a normal credential":     {basic("api", "secret"), "secret"},
		"an empty username":       {basic("", "secret"), "secret"},
		"a colon in the password": {basic("api", "a:b"), "a:b"},
		"no header":               {"", ""},
		"a scheme we do not do":   {"Bearer secret", ""},
		"not base64":              {"Basic !!!!", ""},
		"no colon inside":         {"Basic " + base64.StdEncoding.EncodeToString([]byte("nocolon")), ""},
	} {
		t.Run(name, func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodConnect, "https://x.test:443", nil)
			if tc.header != "" {
				r.Header.Set("Proxy-Authorization", tc.header)
			}
			if got := credentialFrom(r); got != tc.want {
				t.Errorf("credentialFrom = %q, want %q", got, tc.want)
			}
		})
	}

	// Lower-case scheme names are legal on the wire.
	r, _ := http.NewRequest(http.MethodConnect, "https://x.test:443", nil)
	r.Header.Set("Proxy-Authorization", "basic "+base64.StdEncoding.EncodeToString([]byte("u:p")))
	if got := credentialFrom(r); got != "p" {
		t.Errorf("a lower-case scheme was rejected: %q", got)
	}
}
