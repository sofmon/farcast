package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestConnectDenied(t *testing.T) {
	cp := &capture{}
	p := New(Options{Allowlist: allowlist.New([]parser.External{{Host: "allowed.test"}}), Events: cp, EnforceSNI: true})
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
	p := New(Options{Allowlist: allowlist.New([]parser.External{{Host: "allowed.test"}}), Events: cp})
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
