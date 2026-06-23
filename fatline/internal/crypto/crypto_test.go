package crypto

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// handshake drives a TLS 1.3 handshake between a server and client config over
// a loopback TCP pair, returning both sides' errors. (A TCP socket is buffered,
// so the close_notify on Close never deadlocks the way an unbuffered net.Pipe
// would; deadlines remain a safety net against a genuine hang.)
func handshake(t *testing.T, serverCfg, clientCfg *tls.Config) (clientErr, serverErr error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	errc := make(chan error, 1)
	go func() {
		raw, aerr := ln.Accept()
		if aerr != nil {
			errc <- aerr
			return
		}
		_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
		sc := tls.Server(raw, serverCfg)
		herr := sc.Handshake()
		_ = sc.Close()
		errc <- herr
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	cc := tls.Client(raw, clientCfg)
	clientErr = cc.Handshake()
	_ = cc.Close()
	serverErr = <-errc
	return clientErr, serverErr
}

func tlsCert(t *testing.T, l Leaf, err error) tls.Certificate {
	t.Helper()
	if err != nil {
		t.Fatalf("issue leaf: %v", err)
	}
	cert, err := l.TLSCertificate()
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return cert
}

func serverCert(t *testing.T, ca *CA, id string) tls.Certificate {
	t.Helper()
	l, err := ca.IssueServer(id)
	return tlsCert(t, l, err)
}

func clientCert(t *testing.T, ca *CA, id string) tls.Certificate {
	t.Helper()
	l, err := ca.IssueClient(id)
	return tlsCert(t, l, err)
}

func TestMutualTLSHandshake(t *testing.T) {
	ca, err := NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	sCert := serverCert(t, ca, "localhost")
	cCert := clientCert(t, ca, "farcast://test/operator")

	serverCfg := ServerTLSConfig(sCert, ca.CertPool(), nil)
	clientCfg := ClientTLSConfig(cCert, ca.CertPool(), "localhost")
	if cerr, serr := handshake(t, serverCfg, clientCfg); cerr != nil || serr != nil {
		t.Fatalf("handshake failed: client=%v server=%v", cerr, serr)
	}
}

func TestRejectsClientFromForeignCA(t *testing.T) {
	ca, _ := NewCA("test")
	foreign, _ := NewCA("foreign")
	sCert := serverCert(t, ca, "localhost")
	cCert := clientCert(t, foreign, "farcast://x/op") // signed by the wrong CA

	serverCfg := ServerTLSConfig(sCert, ca.CertPool(), nil)
	clientCfg := ClientTLSConfig(cCert, ca.CertPool(), "localhost")
	if cerr, serr := handshake(t, serverCfg, clientCfg); cerr == nil && serr == nil {
		t.Fatal("expected the server to reject a client cert from a foreign CA")
	}
}

func TestRejectsMissingClientCert(t *testing.T) {
	ca, _ := NewCA("test")
	sCert := serverCert(t, ca, "localhost")

	serverCfg := ServerTLSConfig(sCert, ca.CertPool(), nil)
	// Client presents no certificate at all.
	clientCfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: ca.CertPool(), ServerName: "localhost"}
	if cerr, serr := handshake(t, serverCfg, clientCfg); cerr == nil && serr == nil {
		t.Fatal("expected rejection when the client presents no certificate")
	}
}

func TestServerNamePinning(t *testing.T) {
	ca, _ := NewCA("test")
	sCert := serverCert(t, ca, "localhost")
	cCert := clientCert(t, ca, "farcast://test/operator")

	serverCfg := ServerTLSConfig(sCert, ca.CertPool(), nil)
	// Pin the wrong server name: the leaf is for localhost, not other.example.
	clientCfg := ClientTLSConfig(cCert, ca.CertPool(), "other.example")
	if cerr, serr := handshake(t, serverCfg, clientCfg); cerr == nil && serr == nil {
		t.Fatal("expected the client to reject a server name not in the cert SAN")
	}
}

func TestClientIdentityCheck(t *testing.T) {
	ca, _ := NewCA("test")
	sCert := serverCert(t, ca, "localhost")
	okCert := clientCert(t, ca, "farcast://test/operator")
	badCert := clientCert(t, ca, "farcast://test/intruder")

	authz := func(uri string) bool { return uri == "farcast://test/operator" }
	serverCfg := ServerTLSConfig(sCert, ca.CertPool(), authz)

	if cerr, serr := handshake(t, serverCfg, ClientTLSConfig(okCert, ca.CertPool(), "localhost")); cerr != nil || serr != nil {
		t.Fatalf("authorized identity rejected: client=%v server=%v", cerr, serr)
	}
	if cerr, serr := handshake(t, serverCfg, ClientTLSConfig(badCert, ca.CertPool(), "localhost")); cerr == nil && serr == nil {
		t.Fatal("expected an unauthorized client identity (valid CA cert, wrong SAN) to be rejected")
	}
}

func TestLoadCARoundTrip(t *testing.T) {
	ca, _ := NewCA("test")
	keyPEM, err := ca.KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCA(ca.CertPEM, keyPEM)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	// A leaf issued by the reloaded CA must validate against the original CA pool.
	sCert := serverCert(t, loaded, "localhost")
	cCert := clientCert(t, loaded, "farcast://test/operator")
	serverCfg := ServerTLSConfig(sCert, ca.CertPool(), nil)
	clientCfg := ClientTLSConfig(cCert, ca.CertPool(), "localhost")
	if cerr, serr := handshake(t, serverCfg, clientCfg); cerr != nil || serr != nil {
		t.Fatalf("round-tripped CA failed handshake: client=%v server=%v", cerr, serr)
	}
}

func TestServerIdentitySANTypes(t *testing.T) {
	ca, _ := NewCA("test")
	// An IP identity becomes an IP SAN, verifiable by pinning the IP as the
	// server name (the carrier-independent serverIdentity parameter, ADR 0005).
	ipCert := serverCert(t, ca, "127.0.0.1")
	serverCfg := ServerTLSConfig(ipCert, ca.CertPool(), nil)
	cCert := clientCert(t, ca, "farcast://test/operator")
	if cerr, serr := handshake(t, serverCfg, ClientTLSConfig(cCert, ca.CertPool(), "127.0.0.1")); cerr != nil || serr != nil {
		t.Fatalf("IP-SAN server cert failed: client=%v server=%v", cerr, serr)
	}
}
