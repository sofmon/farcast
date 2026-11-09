package fatline_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sofmon/farcast/fatline"
	"github.com/sofmon/farcast/fatline/identity"
	fcrypto "github.com/sofmon/farcast/fatline/internal/crypto"
	"github.com/sofmon/farcast/fatline/tunnel"
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

func serverCert(t *testing.T, ca *fcrypto.CA, id string) tls.Certificate {
	t.Helper()
	leaf, err := ca.IssueServer(id)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := leaf.TLSCertificate()
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func clientCert(t *testing.T, ca *fcrypto.CA, id string) tls.Certificate {
	t.Helper()
	leaf, err := ca.IssueClient(id)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := leaf.TLSCertificate()
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// startServer launches a FatLine tunnel server and waits for it to listen. It
// is torn down when the test (and t.Context) completes.
func startServer(t *testing.T, cfg fatline.Config) {
	t.Helper()
	srv, err := fatline.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(t.Context()) }()
	waitDial(t, cfg.TunnelListen)
}

func TestTunnelEndToEnd(t *testing.T) {
	ca, _ := fcrypto.NewCA("inst")
	addr := freeAddr(t)
	startServer(t, fatline.Config{
		TunnelListen: addr,
		Instance:     "inst",
		ServerCert:   serverCert(t, ca, "127.0.0.1"),
		ClientCA:     ca.CertPool(),
		Allowlist:    []parser.External{{Host: "api.stripe.com"}},
		Endpoint:     addr,
	})

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	id := tunnel.ClientIdentity{Cert: clientCert(t, ca, "farcast://inst/operator"), CA: ca.CertPool(), ServerName: "127.0.0.1"}
	conn, err := tunnel.Connect(ctx, "https://"+addr, id)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close() }()

	st, err := conn.Status(ctx)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !st.Connected || len(st.Allowlist) != 1 || st.Allowlist[0] != "api.stripe.com" {
		t.Fatalf("status=%+v", st)
	}
}

func TestTunnelRejectsForeignClient(t *testing.T) {
	ca, _ := fcrypto.NewCA("inst")
	foreign, _ := fcrypto.NewCA("foreign")
	addr := freeAddr(t)
	startServer(t, fatline.Config{
		TunnelListen: addr,
		Instance:     "inst",
		ServerCert:   serverCert(t, ca, "127.0.0.1"),
		ClientCA:     ca.CertPool(),
	})

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	id := tunnel.ClientIdentity{Cert: clientCert(t, foreign, "farcast://x/op"), CA: ca.CertPool(), ServerName: "127.0.0.1"}
	if _, err := tunnel.Connect(ctx, "https://"+addr, id); err == nil {
		t.Fatal("expected the server to reject a client cert from a foreign CA")
	}
}

// The public tunnel admits this instance's operator and its named keepers,
// and nothing else its CA issues. It admitted every leaf: an application's,
// whose key rests in a Kubernetes Secret, opened the public carrier from
// anywhere and read every application's egress through the Shrike route.
func TestTunnelAdmitsOnlyOperatorAndKeepers(t *testing.T) {
	ca, _ := fcrypto.NewCA("inst")
	addr := freeAddr(t)
	startServer(t, fatline.Config{
		TunnelListen: addr,
		Instance:     "inst",
		ServerCert:   serverCert(t, ca, "127.0.0.1"),
		ClientCA:     ca.CertPool(),
		StreamRoutes: []fatline.StreamRoute{{Name: "shrike", Addr: startEchoPlain(t)}},
	})
	pool := ca.CertPool()

	for _, uri := range []string{identity.OperatorURI("inst"), identity.KeeperURI("inst", "laptop")} {
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		conn, err := tunnel.Connect(ctx, "https://"+addr, tunnel.ClientIdentity{Cert: clientCert(t, ca, uri), CA: pool, ServerName: "127.0.0.1"})
		if err != nil {
			cancel()
			t.Errorf("%s was refused: %v", uri, err)
			continue
		}
		if _, err := conn.Status(ctx); err != nil {
			t.Errorf("%s could not read status: %v", uri, err)
		}
		_ = conn.Close()
		cancel()
	}

	refused := map[string]tls.Certificate{
		"an application":                 clientCert(t, ca, identity.AppURI("inst", "shop", "api")),
		"a device":                       clientCert(t, ca, identity.DeviceURI("inst", "tablet")),
		"an unknown role":                clientCert(t, ca, "farcast://inst/intruder"),
		"another instance's operator":    clientCert(t, ca, identity.OperatorURI("other")),
		"an unnamed keeper":              clientCert(t, ca, "farcast://inst/keeper/"),
		"a keeper with a path":           clientCert(t, ca, "farcast://inst/keeper/a/b"),
		"a leaf with no identity at all": clientCert(t, ca, "laptop.example"),
	}
	for name, cert := range refused {
		client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
			TLSClientConfig:   fcrypto.ClientTLSConfig(cert, pool, "127.0.0.1"),
			ForceAttemptHTTP2: true,
		}}
		for _, req := range []struct{ method, path string }{
			{http.MethodGet, fatline.StatusPath},
			{http.MethodPost, fatline.StreamPathPrefix + "shrike"},
		} {
			r, _ := http.NewRequestWithContext(t.Context(), req.method, "https://"+addr+req.path, nil)
			// TLS 1.3 completes the client's half before the server's alert,
			// so the refusal arrives on the first exchange, not the dial: any
			// response at all means the request reached the handler.
			if resp, err := client.Do(r); err == nil {
				_ = resp.Body.Close()
				t.Errorf("%s reached %s %s (status %d); the handshake should have refused it", name, req.method, req.path, resp.StatusCode)
			}
		}
	}
}
