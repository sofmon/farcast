package fatline

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/fatline/identity"
	fcrypto "github.com/sofmon/farcast/fatline/internal/crypto"
	"github.com/sofmon/farcast/manifest/parser"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := l.Addr().String()
	_ = l.Close()
	return a
}

func waitDial(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("listener %s did not come up", addr)
}

func TestNewRequiresListen(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("New must require at least one listen address")
	}
	if _, err := New(Config{EgressListen: "127.0.0.1:0"}); err != nil {
		t.Fatalf("egress-only New: %v", err)
	}
}

func TestStatusReflectsAllowlist(t *testing.T) {
	s, err := New(Config{EgressListen: "127.0.0.1:0", Allowlist: []parser.External{{Host: "a.com"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Status().Allowlist; len(got) != 1 || got[0] != "a.com" {
		t.Fatalf("status allowlist=%v", got)
	}
	s.ReloadAllowlist([]parser.External{{Host: "b.com"}})
	if got := s.Status().Allowlist; len(got) != 1 || got[0] != "b.com" {
		t.Fatalf("after reload, status allowlist=%v", got)
	}
}

func TestIngressStatusHandler(t *testing.T) {
	s, _ := New(Config{TunnelListen: "127.0.0.1:0", Instance: "inst", Allowlist: []parser.External{{Host: "a.com"}}, Endpoint: "edge.example"})
	ts := httptest.NewServer(s.ingressHandler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + StatusPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var st ConnStatus
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if !st.Connected || st.Endpoint != "edge.example" || len(st.Allowlist) != 1 {
		t.Fatalf("status=%+v", st)
	}
}

func TestServeEgressLifecycle(t *testing.T) {
	addr := freeAddr(t)
	s, _ := New(Config{EgressListen: addr, Allowlist: []parser.External{{Host: "allowed.test"}}})

	ctx, cancel := context.WithCancel(t.Context())
	errc := make(chan error, 1)
	go func() { errc <- s.Serve(ctx) }()
	waitDial(t, addr)

	pu, _ := url.Parse("http://" + addr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	if _, err := client.Get("https://denied.test:443/"); err == nil {
		t.Fatal("expected a denied CONNECT to error through the running server")
	}

	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("Serve returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after ctx cancel")
	}
}

func TestStringRedaction(t *testing.T) {
	ca, _ := fcrypto.NewCA("t")
	leaf, _ := ca.IssueServer("127.0.0.1")
	cert, _ := leaf.TLSCertificate()
	cfg := Config{TunnelListen: ":1", EgressListen: ":2", ServerCert: cert, Allowlist: []parser.External{{Host: "a"}}}
	s, _ := New(Config{EgressListen: "127.0.0.1:0", ServerCert: cert})

	// A non-trivial base64 chunk of the private key must never appear in any
	// stringification of Config or Server.
	var keyChunk string
	for ln := range strings.SplitSeq(string(leaf.KeyPEM), "\n") {
		if len(ln) > 20 && !strings.Contains(ln, "PRIVATE KEY") {
			keyChunk = ln
			break
		}
	}
	if keyChunk == "" {
		t.Fatal("could not extract a key chunk to test against")
	}
	for _, str := range []string{
		cfg.String(), fmt.Sprintf("%v", cfg), fmt.Sprintf("%+v", cfg),
		s.String(), fmt.Sprintf("%v", s),
	} {
		if strings.Contains(str, keyChunk) {
			t.Fatalf("private key material leaked in stringification: %q", str)
		}
	}
}

// The tunnel admits by a rule that needs the instance; with none, there is
// nothing it could admit, and it refuses to start rather than admit everything.
func TestNewRequiresInstanceForTunnel(t *testing.T) {
	if _, err := New(Config{TunnelListen: "127.0.0.1:0"}); err == nil {
		t.Error("a tunnel with no instance was accepted")
	}
	if _, err := New(Config{TunnelListen: "127.0.0.1:0", Instance: "inst"}); err != nil {
		t.Errorf("a tunnel with an instance was refused: %v", err)
	}
	if _, err := New(Config{EgressListen: "127.0.0.1:0"}); err != nil {
		t.Errorf("an egress-only FatLine needs no instance: %v", err)
	}
}

func TestTunnelAdmitsRule(t *testing.T) {
	admits := tunnelAdmits("prod")
	for uri, want := range map[string]bool{
		identity.OperatorURI("prod"):           true,
		identity.KeeperURI("prod", "laptop"):   true,
		identity.AppURI("prod", "shop", "api"): false,
		identity.DeviceURI("prod", "tablet"):   false,
		identity.OperatorURI("other"):          false,
		identity.OperatorURI("prod") + "x":     false,
		"x" + identity.OperatorURI("prod"):     false,
		identity.KeeperURI("prod", ""):         false,
		identity.KeeperURI("prod", "a/b"):      false,
		identity.KeeperURI("prod", "a?b"):      false,
		identity.KeeperURI("other", "laptop"):  false,
		"farcast://prod/intruder":              false,
		"":                                     false,
	} {
		if got := admits(uri); got != want {
			t.Errorf("admits(%q) = %v, want %v", uri, got, want)
		}
	}
	if tunnelAdmits("")("farcast:///operator") {
		t.Error("a tunnel with no instance admitted an empty-instance operator")
	}
}

// The handshake is the boundary; every request is checked again.
func TestAdmitChecksEachRequest(t *testing.T) {
	s, err := New(Config{TunnelListen: "127.0.0.1:0", Instance: "inst"})
	if err != nil {
		t.Fatal(err)
	}
	leaf := func(uri string) *tls.ConnectionState {
		u, err := url.Parse(uri)
		if err != nil {
			t.Fatal(err)
		}
		return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{URIs: []*url.URL{u}}}}
	}
	for name, tc := range map[string]struct {
		cs   *tls.ConnectionState
		want int
	}{
		"no TLS":         {nil, http.StatusForbidden},
		"no certificate": {&tls.ConnectionState{}, http.StatusForbidden},
		"an application": {leaf(identity.AppURI("inst", "shop", "api")), http.StatusForbidden},
		"a keeper":       {leaf(identity.KeeperURI("inst", "laptop")), http.StatusOK},
		"the operator":   {leaf(identity.OperatorURI("inst")), http.StatusOK},
	} {
		called := false
		h := s.admit(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { called = true }))
		req := httptest.NewRequest(http.MethodGet, StatusPath, nil)
		req.TLS = tc.cs
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.want || called != (tc.want == http.StatusOK) {
			t.Errorf("%s: status %d, handler called %v; want %d", name, rec.Code, called, tc.want)
		}
	}
}
