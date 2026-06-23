package fatline_test

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/sofmon/farcast/fatline"
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

func TestTunnelClientIdentityAuthorization(t *testing.T) {
	ca, _ := fcrypto.NewCA("inst")
	addr := freeAddr(t)
	startServer(t, fatline.Config{
		TunnelListen:        addr,
		ServerCert:          serverCert(t, ca, "127.0.0.1"),
		ClientCA:            ca.CertPool(),
		AllowClientIdentity: func(uri string) bool { return uri == "farcast://inst/operator" },
	})
	pool := ca.CertPool()

	ctx1, c1 := context.WithTimeout(t.Context(), 3*time.Second)
	defer c1()
	okID := tunnel.ClientIdentity{Cert: clientCert(t, ca, "farcast://inst/operator"), CA: pool, ServerName: "127.0.0.1"}
	if conn, err := tunnel.Connect(ctx1, "https://"+addr, okID); err != nil {
		t.Fatalf("authorized operator rejected: %v", err)
	} else {
		_ = conn.Close()
	}

	ctx2, c2 := context.WithTimeout(t.Context(), 3*time.Second)
	defer c2()
	badID := tunnel.ClientIdentity{Cert: clientCert(t, ca, "farcast://inst/intruder"), CA: pool, ServerName: "127.0.0.1"}
	if _, err := tunnel.Connect(ctx2, "https://"+addr, badID); err == nil {
		t.Fatal("expected an unauthorized client identity (valid CA cert, wrong SAN) to be rejected")
	}
}
