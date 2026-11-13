package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"strings"
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

// requireP256PKCS8 holds a PEM private key to decision 1: PKCS#8, ECDSA, P-256.
func requireP256PKCS8(t *testing.T, what string, keyPEM []byte) {
	t.Helper()
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("%s: not a PKCS#8 PEM block", what)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	k, ok := key.(*ecdsa.PrivateKey)
	if !ok || !IsP256(&k.PublicKey) {
		t.Errorf("%s: key is %T, want ECDSA P-256", what, key)
	}
}

func leafCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	c, err := parseCert(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// newRequest is a fresh P-256 key and the minimal request for it.
func newRequest(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, der
}

// A-T1. ADR 0020 decision 1: every issuer emits ECDSA P-256 signed with
// SHA-256, and every key it hands out is P-256 PKCS#8.
func TestEveryIssuerEmitsP256(t *testing.T) {
	ca, err := NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	requireP256SHA256(t, "NewCA", ca.Cert)
	caKey, err := ca.KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	requireP256PKCS8(t, "CA.KeyPEM", caKey)

	loaded, err := LoadCA(ca.CertPEM, caKey)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	for _, issuer := range []struct {
		name string
		ca   *CA
	}{{"minted", ca}, {"reloaded", loaded}} {
		server, err := issuer.ca.IssueServer("localhost")
		if err != nil {
			t.Fatal(err)
		}
		client, err := issuer.ca.IssueClient("farcast://test/operator")
		if err != nil {
			t.Fatal(err)
		}
		for what, l := range map[string]Leaf{"IssueServer": server, "IssueClient": client} {
			requireP256SHA256(t, issuer.name+" "+what, leafCert(t, l.CertPEM))
			requireP256PKCS8(t, issuer.name+" "+what+" key", l.KeyPEM)
		}
		key, req := newRequest(t)
		certPEM, err := issuer.ca.IssueClientFromRequest(req, "farcast://test/keeper/phone", x509.ExtKeyUsageClientAuth)
		if err != nil {
			t.Fatalf("%s IssueClientFromRequest: %v", issuer.name, err)
		}
		byRequest := leafCert(t, certPEM)
		requireP256SHA256(t, issuer.name+" IssueClientFromRequest", byRequest)
		if !key.PublicKey.Equal(byRequest.PublicKey) {
			t.Errorf("%s IssueClientFromRequest certified another key", issuer.name)
		}
	}
}

// retiredCA is a CA certificate and PKCS#8 key over key, in the CA template:
// what an instance store from before ADR 0020 (or a hand-made one) holds.
func retiredCA(t *testing.T, key crypto.Signer) (certPEM, keyPEM []byte) {
	t.Helper()
	in, err := liveIssuance()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := caTemplate("test", in)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pemEncode("CERTIFICATE", der), pemEncode("PRIVATE KEY", keyDER)
}

// requireNoKeyBytes holds a refusal to its promise: it names the key, never
// its bytes.
func requireNoKeyBytes(t *testing.T, err error, keyPEM []byte) {
	t.Helper()
	block, _ := pem.Decode(keyPEM)
	body := strings.TrimSpace(string(keyPEM))
	for _, line := range strings.Split(body, "\n") {
		if len(line) >= 16 && !strings.HasPrefix(line, "-----") && strings.Contains(err.Error(), line[:16]) {
			t.Errorf("the refusal carries the key's PEM: %v", err)
		}
	}
	if block != nil && strings.Contains(err.Error(), string(block.Bytes)) {
		t.Errorf("the refusal carries the key's DER: %v", err)
	}
}

// A-T2. ADR 0020 decision 2: an Ed25519 CA — every store from before the ADR
// — is refused at load, with the ADR and the remedy named.
func TestLoadCARefusesEd25519(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := retiredCA(t, key)
	ca, err := LoadCA(certPEM, keyPEM)
	if err == nil {
		t.Fatal("LoadCA accepted an Ed25519 CA")
	}
	if ca != nil {
		t.Error("LoadCA returned a CA beside its refusal")
	}
	if !errors.Is(err, ErrRetiredAlgorithm) {
		t.Errorf("the refusal does not wrap ErrRetiredAlgorithm: %v", err)
	}
	for _, want := range []string{"ADR 0020", "release and reinstall", "Ed25519"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, err)
		}
	}
	requireNoKeyBytes(t, err, keyPEM)
}

// A-T3. LoadCA takes a P-256 key that its certificate certifies, and nothing
// else: another curve, RSA, and a P-256 key that is not the certificate's.
func TestLoadCARefusesOtherKeysAndMismatches(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := vectorRSA("load-ca-rsa")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		key  crypto.Signer
		says string
	}{{"P-384", p384, "ECDSA P-384"}, {"RSA-2048", rsaKey, "RSA-2048"}} {
		certPEM, keyPEM := retiredCA(t, c.key)
		_, err := LoadCA(certPEM, keyPEM)
		if err == nil {
			t.Errorf("LoadCA accepted a %s CA", c.name)
			continue
		}
		if !errors.Is(err, ErrRetiredAlgorithm) || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: the refusal does not name the key and ADR 0020: %v", c.name, err)
		}
		requireNoKeyBytes(t, err, keyPEM)
	}

	ca, err := NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := other.KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCA(ca.CertPEM, otherKey); err == nil || !strings.Contains(err.Error(), "not a pair") {
		t.Errorf("LoadCA accepted a P-256 key that is not the certificate's: %v", err)
	}
	caKey, err := ca.KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCA(ca.CertPEM, caKey); err != nil {
		t.Errorf("LoadCA refused the CA's own pair: %v", err)
	}
}

// A-T7. ADR 0020 decision 2's defence in depth: under the P-256 CA, a client
// leaf this CA signed and that carries the admitted identity is refused at
// the handshake when its key is not P-256 — with the identity rule and
// without one.
func TestServerTLSConfigRefusesANonP256PeerLeaf(t *testing.T) {
	ca, err := NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	const operator = "farcast://test/operator"
	sCert := serverCert(t, ca, "localhost")

	leafOver := func(key crypto.Signer) tls.Certificate {
		t.Helper()
		in, err := liveIssuance()
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.CreateCertificate(rand.Reader, leafTemplate(operator, x509.ExtKeyUsageClientAuth, nil, in), ca.Cert, key.Public(), ca.key)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := vectorRSA("server-tls-rsa")
	if err != nil {
		t.Fatal(err)
	}

	for _, rule := range []struct {
		name  string
		admit func(string) bool
	}{
		{"with the identity rule", func(uri string) bool { return uri == operator }},
		{"with no identity rule", nil},
	} {
		t.Run(rule.name, func(t *testing.T) {
			serverCfg := ServerTLSConfig(sCert, ca.CertPool(), rule.admit)
			for _, retired := range []struct {
				name string
				key  crypto.Signer
			}{{"Ed25519", edKey}, {"P-384", p384}, {"RSA-2048", rsaKey}} {
				_, serr := handshake(t, serverCfg, ClientTLSConfig(leafOver(retired.key), ca.CertPool(), "localhost"))
				if serr == nil {
					t.Errorf("a client leaf over %s from the instance CA was admitted", retired.name)
				} else if !errors.Is(serr, ErrRetiredAlgorithm) {
					t.Errorf("a client leaf over %s was refused, but not for its key: %v", retired.name, serr)
				}
			}
			p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			if cerr, serr := handshake(t, serverCfg, ClientTLSConfig(leafOver(p256), ca.CertPool(), "localhost")); cerr != nil || serr != nil {
				t.Errorf("a P-256 client leaf with the same identity was refused: client=%v server=%v", cerr, serr)
			}
		})
	}
}

func TestIsP256(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	var nilKey *ecdsa.PublicKey
	if !IsP256(&p256.PublicKey) {
		t.Error("IsP256 refused a P-256 key")
	}
	for name, pub := range map[string]any{"P-384": &p384.PublicKey, "Ed25519": edPub, "a private key": p256, "nil": nil, "a typed nil": nilKey} {
		if IsP256(pub) {
			t.Errorf("IsP256 accepted %s", name)
		}
	}
}
