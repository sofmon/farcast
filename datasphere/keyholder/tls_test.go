package keyholder

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func TestAllowPusher(t *testing.T) {
	allow := AllowPusher("prod")

	allowed := []string{
		"farcast://prod/operator",
		"farcast://prod/keeper/laptop",
		"farcast://prod/keeper/phone-2",
	}
	for _, uri := range allowed {
		if !allow(uri) {
			t.Errorf("AllowPusher refused %q", uri)
		}
	}

	refused := []string{
		"",
		"farcast://prod/keeper/",          // unnamed: could not be revoked alone
		"farcast://prod/keeper",           // not a device
		"farcast://staging/operator",      // another instance
		"farcast://staging/keeper/laptop", // another instance's keeper
		"farcast://prod/app/web",          // an application
		"farcast://prod/operator/extra",   // not the operator identity
		"farcast://prodx/operator",        // prefix confusion
		"https://prod/operator",           // wrong scheme
		"farcast://prod/OPERATOR",         // case matters
	}
	for _, uri := range refused {
		if allow(uri) {
			t.Errorf("AllowPusher accepted %q", uri)
		}
	}
}

func TestLoadTLSErrorsDoNotEchoMaterial(t *testing.T) {
	key := "-----BEGIN PRIVATE KEY-----\nSUPERSECRETKEYBYTES\n-----END PRIVATE KEY-----"
	_, err := LoadTLS([]byte("not a cert"), []byte(key))
	if err == nil {
		t.Fatal("LoadTLS accepted malformed material")
	}
	if got := err.Error(); containsAny(got, "SUPERSECRETKEYBYTES", "BEGIN PRIVATE KEY", "not a cert") {
		t.Fatalf("LoadTLS echoed its input: %q", got)
	}
}

func TestLoadCAPoolRejectsGarbage(t *testing.T) {
	if _, err := LoadCAPool([]byte("nothing here")); err == nil {
		t.Fatal("LoadCAPool accepted material with no certificate")
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 && len(s) >= len(sub) {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

// The data listener refuses at the HANDSHAKE, not in the handler. A listener
// that requested a certificate and proceeded without one would be the
// fail-open ADR 0018 decision 1 forbids, and no handler test can see the
// difference — only a real connection can.
func TestDataTLSRefusesTheUnidentifiedAtTheHandshake(t *testing.T) {
	ca := newHandshakeCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)

	var seen atomic.Value
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := identityFrom(r, "prod")
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		seen.Store(string(id.Role))
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = DataTLS(ca.issue(t, serverTemplate()), pool, AllowData("prod"))
	srv.StartTLS()
	defer srv.Close()

	// errHandler means the connection was ESTABLISHED and the handler said
	// no. For the cases below that is a failure of the listener: the ADR's
	// fail-open is precisely a listener that lets an unidentified peer reach
	// a handler that then has to refuse it.
	errHandler := errors.New("reached the handler")
	dial := func(leaf *tls.Certificate) error {
		cfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
		if leaf != nil {
			cfg.Certificates = []tls.Certificate{*leaf}
		}
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
		resp, err := client.Get(srv.URL + "/")
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return errHandler
		}
		return nil
	}
	refusedAtHandshake := func(t *testing.T, what string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s was admitted", what)
		}
		if errors.Is(err, errHandler) {
			t.Fatalf("%s reached the handler; the listener let it through", what)
		}
	}

	refusedAtHandshake(t, "a client with no certificate", dial(nil))
	keeper := ca.issue(t, clientTemplate("farcast://prod/keeper/laptop"))
	refusedAtHandshake(t, "a keeper leaf", dial(&keeper))
	// A leaf from a DIFFERENT authority, even with the right name, is refused
	// by verification rather than by the URI check.
	other := newHandshakeCA(t)
	stranger := other.issue(t, clientTemplate("farcast://prod/app/apps/web"))
	refusedAtHandshake(t, "a leaf from another CA", dial(&stranger))
	app := ca.issue(t, clientTemplate("farcast://prod/app/apps/web"))
	if err := dial(&app); err != nil {
		t.Fatalf("an application leaf was refused: %v", err)
	}
	if got, _ := seen.Load().(string); got != string(RoleApp) {
		t.Errorf("the handler saw role %q, want %q", got, RoleApp)
	}
}

// A minimal CA for the handshake test. This package cannot import
// fatline/internal/crypto, and the point of the test is the listener, not the
// issuance.
type handshakeCA struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
}

func newHandshakeCA(t *testing.T) *handshakeCA {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "prod CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &handshakeCA{cert: cert, key: key}
}

func (ca *handshakeCA) issue(t *testing.T, tmpl *x509.Certificate) tls.Certificate {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func serverTemplate() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "keyholder"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}, DNSNames: []string{"localhost"},
	}
}

func clientTemplate(uri string) *x509.Certificate {
	u, err := url.Parse(uri)
	if err != nil {
		panic(err)
	}
	return &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: uri},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs: []*url.URL{u},
	}
}
