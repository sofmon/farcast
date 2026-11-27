package kube_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cloud.google.com/go/auth"

	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
)

// The wire tests' coordinates: none is a real project, pool, provider or
// account.
const (
	wireProject  = "123456789012"
	wirePool     = "pool1234"
	wireReaderSA = "reader-sa1@proj-01.iam.gserviceaccount.com"
	wireWriterSA = "writer-sa1@proj-01.iam.gserviceaccount.com"
	wireMarker   = "SECRET-MARKER"
)

// wireRole is one role of one device, to D2's shape, built here with
// crypto/x509 (kube's tests cannot import devicekey, doc_test.go): a random
// 32-hex role ID; a self-signed P-256 anchor (CN the ID alone, CA with path
// length 0, keyCertSign, clientAuth, 390 days from an hour back, its subject
// key identifier set); and a P-256 leaf it issues (CN the same ID,
// digitalSignature, clientAuth, 90 days, its authority key identifier set
// explicitly, no subject key identifier).
type wireRole struct {
	id        string
	provider  string
	aud       string
	anchorDER []byte
	leafDER   []byte
	leafKey   *ecdsa.PrivateKey
}

func newWireRole(t *testing.T, provider string) wireRole {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	id := hex.EncodeToString(b[:])
	anchorKey := wireKey(t)
	leafKey := wireKey(t)
	pub, err := anchorKey.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	skid := sha256.Sum256(pub)
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	anchorT := &x509.Certificate{
		SerialNumber:          wireSerial(t),
		Subject:               pkix.Name{CommonName: id},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(390 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		SubjectKeyId:          skid[:20],
	}
	anchorDER, err := x509.CreateCertificate(rand.Reader, anchorT, anchorT, &anchorKey.PublicKey, anchorKey)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := x509.ParseCertificate(anchorDER)
	if err != nil {
		t.Fatal(err)
	}
	leafT := &x509.Certificate{
		SerialNumber:          wireSerial(t),
		Subject:               pkix.Name{CommonName: id},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(90 * 24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		AuthorityKeyId:        anchor.SubjectKeyId,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafT, anchor, &leafKey.PublicKey, anchorKey)
	if err != nil {
		t.Fatal(err)
	}
	aud, err := kube.Audience(wireProject, wirePool, provider)
	if err != nil {
		t.Fatal(err)
	}
	return wireRole{id: id, provider: provider, aud: aud, anchorDER: anchorDER, leafDER: leafDER, leafKey: leafKey}
}

func wireKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func wireSerial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	return n.Add(n, big.NewInt(1))
}

// identity is the role's client identity with chain as its TLS chain.
func (r wireRole) identity(chain ...[]byte) kube.ClientIdentity {
	if len(chain) == 0 {
		chain = [][]byte{r.leafDER}
	}
	return kube.NewClientIdentity(chain, r.leafKey)
}

// request is the plainest exchange: the leaf alone, in the handshake and in
// the subject token.
func (r wireRole) request() kube.ExchangeRequest {
	return kube.NewExchangeRequest(r.aud, r.identity(), nil, nil)
}

// wireSetup starts the fakes with opts and points a Federation at their
// three hosts.
func wireSetup(t *testing.T, opts ...kubetest.FederationOption) (*kubetest.Federation, *kube.Federation) {
	t.Helper()
	fake := kubetest.NewFederation(t, opts...)
	f, err := kube.NewLoopbackFederation(fake.STSAddr(), fake.IAMAddr(), fake.IAMAPIAddr(), fake.Roots())
	if err != nil {
		t.Fatal(err)
	}
	return fake, f
}

// addRole adds a role's provider to the STS fake.
func addRole(fake *kubetest.Federation, r wireRole) {
	fake.AddProvider(wireProject, wirePool, r.provider, r.anchorDER, r.id)
}

// requestsOf are the fake's requests to one server.
func requestsOf(fake *kubetest.Federation, server string) []kubetest.FederationRequest {
	var out []kubetest.FederationRequest
	for _, r := range fake.Requests() {
		if r.Server == server {
			out = append(out, r)
		}
	}
	return out
}

// handshakesOf are the fake's handshakes at one server.
func handshakesOf(fake *kubetest.Federation, server string) []kubetest.FederationHandshake {
	var out []kubetest.FederationHandshake
	for _, h := range fake.Handshakes() {
		if h.Server == server {
			out = append(out, h)
		}
	}
	return out
}

// federationError is err as a *kube.FederationError, or a failure.
func federationError(t *testing.T, err error) *kube.FederationError {
	t.Helper()
	var fe *kube.FederationError
	if !errors.As(err, &fe) {
		t.Fatalf("%v (%T) is not a *kube.FederationError", err, err)
	}
	return fe
}

// wireErrorTree is every error err's Unwrap reaches, err first.
func wireErrorTree(err error) []error {
	var out []error
	var walk func(error)
	walk = func(e error) {
		if e == nil {
			return
		}
		out = append(out, e)
		switch u := e.(type) {
		case interface{ Unwrap() []error }:
			for _, x := range u.Unwrap() {
				walk(x)
			}
		case interface{ Unwrap() error }:
			walk(u.Unwrap())
		}
	}
	walk(err)
	return out
}

// decodeSubject reads a recorded subject_token back into its DERs.
func decodeSubject(t *testing.T, token string) [][]byte {
	t.Helper()
	var items []string
	if err := json.Unmarshal([]byte(token), &items); err != nil {
		t.Fatalf("subject_token is not a JSON array of strings: %v", err)
	}
	var ders [][]byte
	for _, it := range items {
		der, err := base64.StdEncoding.DecodeString(it)
		if err != nil {
			t.Fatalf("a subject_token item is not padded standard base64: %v", err)
		}
		ders = append(ders, der)
	}
	return ders
}

func equalDERs(a, b [][]byte) bool {
	return slices.EqualFunc(a, b, bytes.Equal)
}

// TestExchangeSendsWhatTheX509PageAsks: in each of T1's four chain shapes the
// exchange is a POST of exactly the six form fields to /v1/token, with only
// Accept, Content-Type and User-Agent (no Authorization, even with a
// federated bearer on the context), presenting the TLS chain at a TLS 1.3
// handshake and carrying the subject chain in subject_token.
func TestExchangeSendsWhatTheX509PageAsks(t *testing.T) {
	fake, f := wireSetup(t)
	r := newWireRole(t, "provreader1")
	addRole(fake, r)
	leaf, anchor := r.leafDER, r.anchorDER
	ctx := kube.WithFederatedBearer(t.Context(), &auth.Token{Value: "federated-on-the-context", Type: "Bearer"})
	for _, s := range []struct {
		name          string
		tlsChain      [][]byte
		subject       [][]byte // nil: the TLS chain
		subjectWanted [][]byte
	}{
		{"S1: TLS [leaf], subject [leaf]", [][]byte{leaf}, nil, [][]byte{leaf}},
		{"S2: TLS [leaf], subject [leaf, anchor]", [][]byte{leaf}, [][]byte{leaf, anchor}, [][]byte{leaf, anchor}},
		{"S3: TLS [leaf, anchor], subject [leaf]", [][]byte{leaf, anchor}, [][]byte{leaf}, [][]byte{leaf}},
		{"S4: TLS [leaf, anchor], subject [leaf, anchor]", [][]byte{leaf, anchor}, nil, [][]byte{leaf, anchor}},
	} {
		t.Run(s.name, func(t *testing.T) {
			before := len(requestsOf(fake, "sts"))
			ans, err := f.Exchange(ctx, kube.NewExchangeRequest(r.aud, r.identity(s.tlsChain...), s.subject, nil))
			if err != nil {
				t.Fatal(err)
			}
			if ans.TLSVersion() != tls.VersionTLS13 {
				t.Errorf("TLSVersion = %s, want TLS 1.3", tls.VersionName(ans.TLSVersion()))
			}
			if ans.Token() == nil || ans.Token().Value == "" || ans.Token().Type != "Bearer" || ans.ExpiresIn() != 3599*time.Second {
				t.Errorf("the answer is not the fake's token")
			}
			reqs := requestsOf(fake, "sts")
			if len(reqs) != before+1 {
				t.Fatalf("%d requests, want one more than %d", len(reqs), before)
			}
			got := reqs[len(reqs)-1]
			if got.Method != http.MethodPost || got.Path != "/v1/token" || got.ContentType != "application/x-www-form-urlencoded" || got.UserAgent != "farcast" {
				t.Errorf("sent %s %s, Content-Type %q, User-Agent %q", got.Method, got.Path, got.ContentType, got.UserAgent)
			}
			if !slices.Equal(got.Headers, []string{"Accept", "Content-Type", "User-Agent"}) {
				t.Errorf("header names %q, want exactly Accept, Content-Type and User-Agent", got.Headers)
			}
			if got.As != "" {
				t.Errorf("As = %q; the exchange carries no bearer", got.As)
			}
			if !equalDERs(got.PeerCertificates, s.tlsChain) {
				t.Errorf("the handshake presented %d certificates, not the TLS chain", len(got.PeerCertificates))
			}
			if len(got.Form) != 6 {
				t.Errorf("the form has %d keys, want six", len(got.Form))
			}
			for k, want := range map[string]string{
				"audience":             r.aud,
				"grant_type":           kube.GrantTypeTokenExchange,
				"requested_token_type": kube.TokenTypeAccessToken,
				"subject_token_type":   kube.TokenTypeMTLS,
				"scope":                kube.ScopeCloudPlatform,
			} {
				if v := got.Form[k]; len(v) != 1 || v[0] != want {
					t.Errorf("%s = %q, want exactly [%q]", k, v, want)
				}
			}
			if st := got.Form["subject_token"]; len(st) != 1 || !equalDERs(decodeSubject(t, st[0]), s.subjectWanted) {
				t.Error("subject_token is not the subject chain, leaf first")
			}
		})
	}
}

// TestExchangeThenImpersonate: the federated token impersonates the role's
// own service account, and the IAM request is exactly generateAccessToken's,
// with the federated bearer and no client certificate. The other role's
// account refuses it.
func TestExchangeThenImpersonate(t *testing.T) {
	fake, f := wireSetup(t)
	reader := newWireRole(t, "provreader1")
	writer := newWireRole(t, "provwriter1")
	addRole(fake, reader)
	addRole(fake, writer)
	fake.Bind(reader.id, wireReaderSA)
	fake.Bind(writer.id, wireWriterSA)

	ans, err := f.Exchange(t.Context(), reader.request())
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	sa, err := f.Impersonate(t.Context(), ans.Token(), wireReaderSA, kube.ScopesCluster)
	if err != nil {
		t.Fatal(err)
	}
	if sa.Value == "" || sa.Value == ans.Token().Value || sa.Type != "Bearer" {
		t.Error("the service account token is not a fresh bearer")
	}
	if d := sa.Expiry.Sub(start); d < 59*time.Minute || d > 61*time.Minute {
		t.Errorf("the service account token expires %s from now, want about an hour", d)
	}
	iam := requestsOf(fake, "iam")
	if len(iam) != 1 {
		t.Fatalf("%d IAM requests, want 1", len(iam))
	}
	got := iam[0]
	if got.Method != http.MethodPost || got.Path != "/v1/projects/-/serviceAccounts/"+wireReaderSA+":generateAccessToken" {
		t.Errorf("sent %s %s", got.Method, got.Path)
	}
	if !bytes.Equal(got.Body, kube.ImpersonationBody(kube.ScopesCluster)) || got.ContentType != "application/json" || got.UserAgent != "farcast" {
		t.Errorf("body %s, Content-Type %q, User-Agent %q", got.Body, got.ContentType, got.UserAgent)
	}
	if got.As != reader.id {
		t.Error("the IAM request was not authorised by the reader's federated token")
	}
	if !slices.Equal(got.Headers, []string{"Accept", "Authorization", "Content-Type", "User-Agent"}) {
		t.Errorf("header names %q, want exactly Accept, Authorization, Content-Type and User-Agent", got.Headers)
	}
	if got.PeerCertificates != nil {
		t.Errorf("the IAM connection presented %d certificates", len(got.PeerCertificates))
	}

	// The reader's federated token does not reach the writer's account.
	_, err = f.Impersonate(t.Context(), ans.Token(), wireWriterSA, kube.ScopesCluster)
	fe := federationError(t, err)
	if !errors.Is(err, kube.ErrTokenRefused) || fe.Step != kube.StepImpersonate || fe.Status != http.StatusForbidden || fe.GoogleStatus != "PERMISSION_DENIED" {
		t.Errorf("the reader at the writer's account: %v", err)
	}
	// And a token STS never issued is unauthenticated.
	_, err = f.Impersonate(t.Context(), &auth.Token{Value: "not-issued"}, wireReaderSA, kube.ScopesCluster)
	if fe := federationError(t, err); fe.Status != http.StatusUnauthorized || fe.GoogleStatus != "UNAUTHENTICATED" {
		t.Errorf("an unissued token: %v", err)
	}
}

// TestNoClientCertificateReachesIAMCredentials: after several exchanges and
// impersonations through one Federation, no IAM Credentials handshake carried
// a certificate, while every STS one did.
func TestNoClientCertificateReachesIAMCredentials(t *testing.T) {
	fake, f := wireSetup(t)
	r := newWireRole(t, "provreader1")
	addRole(fake, r)
	fake.Bind(r.id, wireReaderSA)
	for range 3 {
		ans, err := f.Exchange(t.Context(), r.request())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Impersonate(t.Context(), ans.Token(), wireReaderSA, kube.ScopesCluster); err != nil {
			t.Fatal(err)
		}
	}
	iam := handshakesOf(fake, "iam")
	if len(iam) == 0 {
		t.Fatal("no IAM Credentials handshake was recorded")
	}
	for i, h := range iam {
		if len(h.PeerCertificates) != 0 {
			t.Errorf("IAM handshake %d presented %d certificates", i, len(h.PeerCertificates))
		}
	}
	for i, h := range handshakesOf(fake, "sts") {
		if len(h.PeerCertificates) == 0 || !bytes.Equal(h.PeerCertificates[0], r.leafDER) {
			t.Errorf("STS handshake %d did not present the leaf", i)
		}
	}
	for _, req := range requestsOf(fake, "iam") {
		if req.PeerCertificates != nil {
			t.Error("an IAM request's connection presented a certificate")
		}
	}
}

// TestEachExchangeHasItsOwnHandshake: two exchanges with two identities
// through one Federation are two STS handshakes, each presenting its own
// identity's leaf.
func TestEachExchangeHasItsOwnHandshake(t *testing.T) {
	fake, f := wireSetup(t)
	a := newWireRole(t, "provaaaa1")
	b := newWireRole(t, "provbbbb1")
	addRole(fake, a)
	addRole(fake, b)
	for _, r := range []wireRole{a, b} {
		if _, err := f.Exchange(t.Context(), r.request()); err != nil {
			t.Fatal(err)
		}
	}
	hs := handshakesOf(fake, "sts")
	if len(hs) != 2 {
		t.Fatalf("%d STS handshakes, want 2", len(hs))
	}
	for i, r := range []wireRole{a, b} {
		if len(hs[i].PeerCertificates) != 1 || !bytes.Equal(hs[i].PeerCertificates[0], r.leafDER) {
			t.Errorf("handshake %d did not present its own identity's leaf", i)
		}
		if hs[i].Version != tls.VersionTLS13 {
			t.Errorf("handshake %d negotiated %s", i, tls.VersionName(hs[i].Version))
		}
	}
	reqs := requestsOf(fake, "sts")
	if len(reqs) != 2 || !bytes.Equal(reqs[0].PeerCertificates[0], a.leafDER) || !bytes.Equal(reqs[1].PeerCertificates[0], b.leafDER) {
		t.Error("the requests' connections did not present their own identities' leaves")
	}
}

// TestExchangeSendsTheCertificateWhateverTheServerAsksFor: a server whose
// acceptable CAs leave the anchor out still gets the certificate, and the
// exchange passes.
func TestExchangeSendsTheCertificateWhateverTheServerAsksFor(t *testing.T) {
	unrelated := x509.NewCertPool()
	other := newWireRole(t, "provother1")
	otherAnchor, err := x509.ParseCertificate(other.anchorDER)
	if err != nil {
		t.Fatal(err)
	}
	unrelated.AddCert(otherAnchor)
	fake, f := wireSetup(t, kubetest.WithClientCAs(unrelated))
	r := newWireRole(t, "provreader1")
	addRole(fake, r)
	if _, err := f.Exchange(t.Context(), r.request()); err != nil {
		t.Fatalf("the exchange under unrelated acceptable CAs: %v", err)
	}
	hs := handshakesOf(fake, "sts")
	if len(hs) != 1 || len(hs[0].PeerCertificates) != 1 || !bytes.Equal(hs[0].PeerCertificates[0], r.leafDER) {
		t.Error("the leaf was not presented")
	}
}

// TestExchangeWithoutACertificateIsRefusedAtTheHandshake: with no client
// certificate, a server that requires one ends the TLS 1.3 handshake with
// "certificate required", which reads as a refusal at the handshake, not as
// an unreachable host.
func TestExchangeWithoutACertificateIsRefusedAtTheHandshake(t *testing.T) {
	fake, f := wireSetup(t)
	r := newWireRole(t, "provreader1")
	addRole(fake, r)
	_, err := f.Exchange(t.Context(), kube.NewExchangeRequest(r.aud, kube.ClientIdentity{}, [][]byte{r.leafDER}, nil))
	fe := federationError(t, err)
	want := "kube: Google's token exchange refused the client certificate at the handshake (tls: certificate required)"
	if !fe.Handshake || fe.Status != 0 || fe.Step != kube.StepExchange || !errors.Is(err, kube.ErrTokenRefused) || errors.Is(err, kube.ErrUnreachable) || err.Error() != want {
		t.Errorf("got %v (Handshake %v, Status %d); want %q", err, fe.Handshake, fe.Status, want)
	}
	if fe.Alert != "tls: certificate required" {
		t.Errorf("Alert %q, want the alert's words", fe.Alert)
	}
	if n := len(fake.Requests()); n != 0 {
		t.Errorf("%d requests reached the handler", n)
	}
}

// wireServerIdentity is a loopback server's certificate for 127.0.0.1, and
// the roots that verify it, for the alert tests' own servers.
func wireServerIdentity(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key := wireKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          wireSerial(t),
		Subject:               pkix.Name{CommonName: "loopback alert server"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}, roots
}

// wireAlertServer accepts loopback connections and hands each to serve, with
// a 10 s deadline, until the test ends. It returns the address.
func wireAlertServer(t *testing.T, serve func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(wg.Wait)
	t.Cleanup(func() { _ = ln.Close() })
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				serve(c)
			}()
		}
	}()
	return ln.Addr().String()
}

// TestAnAlertAtTheHandshakeKeepsItsWords: a server that fails on its own
// ends the handshake with internal_error. kube reads every alert before an
// answer as a refusal at the handshake, and says which alert it was in
// Alert, so a caller can tell a server's own failure from a refusal of the
// certificate.
func TestAnAlertAtTheHandshakeKeepsItsWords(t *testing.T) {
	_, roots := wireServerIdentity(t)
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return nil, errors.New("the server's own failure") // Go's server then sends internal_error
		},
	}
	addr := wireAlertServer(t, func(c net.Conn) { _ = tls.Server(c, cfg).Handshake() })
	f, err := kube.NewLoopbackFederation(addr, addr, addr, roots)
	if err != nil {
		t.Fatal(err)
	}
	r := newWireRole(t, "provreader1")
	_, err = f.Exchange(t.Context(), r.request())
	fe := federationError(t, err)
	want := "kube: Google's token exchange refused the client certificate at the handshake (tls: internal error)"
	if !fe.Handshake || fe.Alert != "tls: internal error" || fe.Status != 0 || !errors.Is(err, kube.ErrTokenRefused) || err.Error() != want {
		t.Errorf("got %v (Handshake %v, Alert %q, Status %d); want %q with Alert %q", err, fe.Handshake, fe.Alert, fe.Status, want, "tls: internal error")
	}
}

// alertingConn is a server's connection that, once oversize is set, reads a
// record header announcing more than TLS 1.3 allows, so the server's next
// read sends the client record_overflow, encrypted, after the handshake.
type alertingConn struct {
	net.Conn
	oversize atomic.Bool
}

func (c *alertingConn) Read(p []byte) (int, error) {
	if c.oversize.Load() {
		return copy(p, []byte{0x17, 0x03, 0x03, 0x48, 0x01}), nil
	}
	return c.Conn.Read(p)
}

// TestAnAlertWhileTheAnswerIsReadIsNoRefusal: a server answers 200, then
// sends an alert while its body is read. That ended no handshake and decided
// nothing: kube reads it as unreachable, with Handshake false and no status,
// and keeps the alert's words in Alert.
func TestAnAlertWhileTheAnswerIsReadIsNoRefusal(t *testing.T) {
	cert, roots := wireServerIdentity(t)
	cfg := &tls.Config{
		MinVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{cert},
		ClientAuth:             tls.RequestClientCert,
		SessionTicketsDisabled: true,
	}
	answered := make(chan struct{}, 1)
	addr := wireAlertServer(t, func(c net.Conn) {
		ac := &alertingConn{Conn: c}
		tc := tls.Server(ac, cfg)
		if tc.Handshake() != nil {
			return
		}
		req, err := http.ReadRequest(bufio.NewReader(tc))
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, req.Body)
		if _, err := io.WriteString(tc, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4096\r\n\r\n{\"access_token\":"); err != nil {
			return
		}
		answered <- struct{}{}
		ac.oversize.Store(true)
		_, _ = tc.Read(make([]byte, 1))
	})
	f, err := kube.NewLoopbackFederation(addr, addr, addr, roots)
	if err != nil {
		t.Fatal(err)
	}
	r := newWireRole(t, "provreader1")
	_, err = f.Exchange(t.Context(), r.request())
	select {
	case <-answered:
	default:
		t.Fatalf("the server never answered 200: %v", err)
	}
	fe := federationError(t, err)
	want := "kube: Google's token exchange could not be reached: tls: record overflow"
	if fe.Handshake || fe.Alert != "tls: record overflow" || fe.Status != 0 || !errors.Is(err, kube.ErrUnreachable) || errors.Is(err, kube.ErrTokenRefused) || err.Error() != want {
		t.Errorf("got %v (Handshake %v, Alert %q, Status %d); want %q, unreachable, Handshake false", err, fe.Handshake, fe.Alert, fe.Status, want)
	}
}

// TestTheExchangeRefusesTLS12: the exchange will not speak TLS 1.2, which
// sends the client certificate in clear, so a server capped at 1.2 ends the
// handshake and no request is made.
func TestTheExchangeRefusesTLS12(t *testing.T) {
	fake, f := wireSetup(t, kubetest.WithSTSMaxTLS12())
	r := newWireRole(t, "provreader1")
	addRole(fake, r)
	_, err := f.Exchange(t.Context(), r.request())
	fe := federationError(t, err)
	want := "kube: Google's token exchange refused the client certificate at the handshake (tls: protocol version not supported)"
	if !fe.Handshake || !errors.Is(err, kube.ErrTokenRefused) || err.Error() != want {
		t.Errorf("got %v; want %q", err, want)
	}
	if n := len(fake.Requests()); n != 0 {
		t.Errorf("%d requests were made over TLS 1.2", n)
	}
	if n := len(handshakesOf(fake, "sts")); n != 0 {
		t.Errorf("%d handshakes completed", n)
	}
}

// TestExchangeWithoutACertificateIsRefusedByTheServer: a server that only
// requests a certificate refuses the request with invalid_request.
func TestExchangeWithoutACertificateIsRefusedByTheServer(t *testing.T) {
	fake, f := wireSetup(t, kubetest.WithClientCertificateOptional())
	r := newWireRole(t, "provreader1")
	addRole(fake, r)
	_, err := f.Exchange(t.Context(), kube.NewExchangeRequest(r.aud, kube.ClientIdentity{}, [][]byte{r.leafDER}, nil))
	fe := federationError(t, err)
	want := "kube: Google's token exchange refused the request (400 Bad Request, OAuth error invalid_request)"
	if fe.Handshake || fe.Status != http.StatusBadRequest || fe.OAuthError != "invalid_request" || fe.TLSVersion != tls.VersionTLS13 ||
		!errors.Is(err, kube.ErrTokenRefused) || err.Error() != want {
		t.Errorf("got %v (%+v); want %q", err, *fe, want)
	}
	if reqs := fake.Requests(); len(reqs) != 1 || reqs[0].PeerCertificates != nil {
		t.Error("the request was not recorded as presenting no certificate")
	}
}

// wirePlanted is a refusal's description carrying every marker.
const wirePlanted = wireMarker + " " + wireReaderSA + " 0123456789abcdef0123456789abcdef"

// noMarker fails when any error in err's tree carries a planted value.
func noMarker(t *testing.T, err error, markers ...string) {
	t.Helper()
	for _, e := range wireErrorTree(err) {
		for _, m := range markers {
			if strings.Contains(e.Error(), m) {
				t.Errorf("an error in the tree carries %q: %s", m, e.Error())
			}
		}
	}
}

// TestExchangeRefusalCarriesNoSecret: a refusal's description and message are
// never read; only the shaped code is.
func TestExchangeRefusalCarriesNoSecret(t *testing.T) {
	fake, f := wireSetup(t, kubetest.WithExchangeAnswer(http.StatusBadRequest, `{"error":"invalid_grant","error_description":"`+wirePlanted+`","message":"`+wirePlanted+`"}`))
	r := newWireRole(t, "provreader1")
	addRole(fake, r)
	_, err := f.Exchange(t.Context(), r.request())
	want := "kube: Google's token exchange refused the request (400 Bad Request, OAuth error invalid_grant)"
	if err == nil || err.Error() != want || federationError(t, err).OAuthError != "invalid_grant" {
		t.Errorf("got %v; want %q", err, want)
	}
	noMarker(t, err, wireMarker, wireReaderSA, "0123456789abcdef0123456789abcdef")
}

// TestImpersonationRefusalCarriesNoSecret: IAM Credentials' message, which
// may name the account, is never read; only error.status is.
func TestImpersonationRefusalCarriesNoSecret(t *testing.T) {
	fake, f := wireSetup(t, kubetest.WithImpersonationAnswer(http.StatusForbidden,
		`{"error":{"code":403,"message":"`+wirePlanted+`","status":"PERMISSION_DENIED","details":[{"reason":"`+wireMarker+`"}]}}`))
	r := newWireRole(t, "provreader1")
	addRole(fake, r)
	ans, err := f.Exchange(t.Context(), r.request())
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Impersonate(t.Context(), ans.Token(), wireReaderSA, kube.ScopesCluster)
	want := "kube: IAM Credentials refused the service account's token (403 Forbidden, status PERMISSION_DENIED)"
	if err == nil || err.Error() != want || federationError(t, err).GoogleStatus != "PERMISSION_DENIED" {
		t.Errorf("got %v; want %q", err, want)
	}
	noMarker(t, err, wireMarker, wireReaderSA, "@", "serviceAccounts")
}

// TestOversizedFederationAnswerIsUnusable: an answer one byte over 64 KiB is
// refused whole. Each body is a valid answer padded with spaces, so a reader
// that cut it to 64 KiB would have taken it.
func TestOversizedFederationAnswerIsUnusable(t *testing.T) {
	const limit = 64 << 10
	pad := func(body string) string { return body + strings.Repeat(" ", limit+1-len(body)) }
	valid := `{"access_token":"tok-1","issued_token_type":"` + kube.TokenTypeAccessToken + `","token_type":"Bearer","expires_in":3599}`

	t.Run("200", func(t *testing.T) {
		fake, f := wireSetup(t, kubetest.WithExchangeAnswer(http.StatusOK, pad(valid)))
		r := newWireRole(t, "provreader1")
		addRole(fake, r)
		ans, err := f.Exchange(t.Context(), r.request())
		want := "kube: Google's token exchange answered without a usable token (the answer is larger than 64 KiB)"
		if ans != nil || !errors.Is(err, kube.ErrUnreadable) || err.Error() != want || federationError(t, err).Field != "the answer is larger than 64 KiB" {
			t.Errorf("got %v, %v; want %q", ans, err, want)
		}
	})
	t.Run("400", func(t *testing.T) {
		fake, f := wireSetup(t, kubetest.WithExchangeAnswer(http.StatusBadRequest, pad(`{"error":"invalid_grant"}`)))
		r := newWireRole(t, "provreader1")
		addRole(fake, r)
		_, err := f.Exchange(t.Context(), r.request())
		want := "kube: Google's token exchange refused the request (400 Bad Request)"
		if err == nil || err.Error() != want || federationError(t, err).OAuthError != "" {
			t.Errorf("got %v; want %q, with no code", err, want)
		}
	})
	t.Run("an endless 200", func(t *testing.T) {
		// A reader with no cap would read until the deadline; the cap stops at
		// 64 KiB + 1 and refuses at once.
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, valid)
			chunk := []byte(strings.Repeat(" ", 4096))
			for r.Context().Err() == nil {
				if _, err := w.Write(chunk); err != nil {
					return
				}
			}
		}))
		srv.Config.ErrorLog = log.New(io.Discard, "", 0)
		srv.StartTLS()
		defer srv.Close()
		roots := x509.NewCertPool()
		roots.AddCert(srv.Certificate())
		addr := srv.Listener.Addr().String()
		f, err := kube.NewLoopbackFederation(addr, addr, addr, roots)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		r := newWireRole(t, "provreader1")
		_, err = f.Exchange(ctx, kube.NewExchangeRequest(r.aud, kube.ClientIdentity{}, [][]byte{r.leafDER}, nil))
		if !errors.Is(err, kube.ErrUnreadable) || federationError(t, err).Field != "the answer is larger than 64 KiB" {
			t.Errorf("got %v; want the oversize refusal before the deadline", err)
		}
	})
	t.Run("impersonation 200", func(t *testing.T) {
		fake, f := wireSetup(t, kubetest.WithImpersonationAnswer(http.StatusOK,
			pad(`{"accessToken":"sa-1","expireTime":"`+time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)+`"}`)))
		r := newWireRole(t, "provreader1")
		addRole(fake, r)
		ans, err := f.Exchange(t.Context(), r.request())
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.Impersonate(t.Context(), ans.Token(), wireReaderSA, kube.ScopesCluster)
		if !errors.Is(err, kube.ErrUnreadable) || federationError(t, err).Field != "the answer is larger than 64 KiB" {
			t.Errorf("got %v", err)
		}
	})
}

// TestFederationFollowsNoRedirect: a 3xx is the answer. (a) STS's 307 to
// another server is a 307; (b) IAM Credentials' 307 to another path on its
// own host is a 307, and the bearer never goes there; (c) STS's 307 to its
// own /v1/token is one request, not a loop.
func TestFederationFollowsNoRedirect(t *testing.T) {
	t.Run("a: STS to another server", func(t *testing.T) {
		second := kubetest.NewFederation(t)
		fake, f := wireSetup(t, kubetest.WithExchangeRedirect("https://"+second.STSAddr()+"/v1/token"))
		r := newWireRole(t, "provreader1")
		addRole(fake, r)
		_, err := f.Exchange(t.Context(), r.request())
		if fe := federationError(t, err); fe.Status != http.StatusTemporaryRedirect || !errors.Is(err, kube.ErrTokenRefused) {
			t.Errorf("got %v; want a refusal with status 307", err)
		}
		if n := len(second.Requests()) + len(second.Handshakes()); n != 0 {
			t.Errorf("the second server saw %d requests or handshakes", n)
		}
	})
	t.Run("b: IAM Credentials to another path on its host", func(t *testing.T) {
		fake, f := wireSetup(t, kubetest.WithImpersonationRedirect("/v1/elsewhere"))
		r := newWireRole(t, "provreader1")
		addRole(fake, r)
		fake.Bind(r.id, wireReaderSA)
		ans, err := f.Exchange(t.Context(), r.request())
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.Impersonate(t.Context(), ans.Token(), wireReaderSA, kube.ScopesCluster)
		if fe := federationError(t, err); fe.Status != http.StatusTemporaryRedirect || !errors.Is(err, kube.ErrTokenRefused) {
			t.Errorf("got %v; want a refusal with status 307", err)
		}
		for _, req := range fake.Requests() {
			if req.Path == "/v1/elsewhere" {
				t.Error("the redirect was followed: the bearer went to /v1/elsewhere")
			}
		}
		if n := len(requestsOf(fake, "iam")); n != 1 {
			t.Errorf("%d IAM requests, want 1", n)
		}
	})
	t.Run("c: STS to its own /v1/token", func(t *testing.T) {
		fake, f := wireSetup(t, kubetest.WithExchangeRedirect("/v1/token"))
		r := newWireRole(t, "provreader1")
		addRole(fake, r)
		_, err := f.Exchange(t.Context(), r.request())
		if fe := federationError(t, err); fe.Status != http.StatusTemporaryRedirect {
			t.Errorf("got %v; want status 307", err)
		}
		if n := len(requestsOf(fake, "sts")); n != 1 {
			t.Errorf("%d STS requests, want 1", n)
		}
	})
	// d: a Location the client cannot parse. http.Client parses Location
	// before CheckRedirect, and its parse failure quotes the header whole, so
	// the transport drops such a header: the 307 is the answer, a refusal with
	// its status, and no error in the tree carries the server's words.
	const badLocation = "%zzREMOTE-TEXT-serviceAccounts/" + wireReaderSA + ":generateAccessToken"
	t.Run("d: STS with an unparsable Location", func(t *testing.T) {
		fake, f := wireSetup(t, kubetest.WithExchangeRedirect(badLocation))
		r := newWireRole(t, "provreader1")
		addRole(fake, r)
		_, err := f.Exchange(t.Context(), r.request())
		if fe := federationError(t, err); fe.Status != http.StatusTemporaryRedirect || !errors.Is(err, kube.ErrTokenRefused) || errors.Is(err, kube.ErrUnreachable) {
			t.Errorf("got %v; want a refusal with status 307", err)
		}
		if errors.As(err, new(*url.Error)) {
			t.Error("a *url.Error is in the tree")
		}
		noMarker(t, err, "REMOTE-TEXT", "%zz", "serviceAccounts", "@", "generateAccessToken", "Location")
		if n := len(requestsOf(fake, "sts")); n != 1 {
			t.Errorf("%d STS requests, want 1", n)
		}
	})
	t.Run("d: IAM Credentials with an unparsable Location", func(t *testing.T) {
		fake, f := wireSetup(t, kubetest.WithImpersonationRedirect(badLocation))
		r := newWireRole(t, "provreader1")
		addRole(fake, r)
		fake.Bind(r.id, wireReaderSA)
		ans, err := f.Exchange(t.Context(), r.request())
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.Impersonate(t.Context(), ans.Token(), wireReaderSA, kube.ScopesCluster)
		if fe := federationError(t, err); fe.Status != http.StatusTemporaryRedirect || !errors.Is(err, kube.ErrTokenRefused) || errors.Is(err, kube.ErrUnreachable) {
			t.Errorf("got %v; want a refusal with status 307", err)
		}
		if errors.As(err, new(*url.Error)) {
			t.Error("a *url.Error is in the tree")
		}
		noMarker(t, err, "REMOTE-TEXT", "%zz", "serviceAccounts", "@", "generateAccessToken", "Location")
		if n := len(requestsOf(fake, "iam")); n != 1 {
			t.Errorf("%d IAM requests, want 1", n)
		}
	})
}

// wireRawServer is a loopback TLS server that reads each HTTP/1.1 request
// whole and answers with raw, then closes. raw gets the request's path, so an
// answer can echo it as a misbehaving front end would. It returns the address
// and the roots that verify it.
func wireRawServer(t *testing.T, raw func(path string) string) (string, *x509.CertPool) {
	t.Helper()
	cert, roots := wireServerIdentity(t)
	cfg := &tls.Config{
		MinVersion:             tls.VersionTLS12,
		Certificates:           []tls.Certificate{cert},
		ClientAuth:             tls.RequestClientCert,
		SessionTicketsDisabled: true,
	}
	addr := wireAlertServer(t, func(c net.Conn) {
		tc := tls.Server(c, cfg)
		if tc.Handshake() != nil {
			return
		}
		req, err := http.ReadRequest(bufio.NewReader(tc))
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, req.Body)
		_, _ = io.WriteString(tc, raw(req.URL.Path))
		_ = tc.Close()
	})
	return addr, roots
}

// wireFrame writes one HTTP/2 frame.
func wireFrame(w io.Writer, typ, flags byte, stream uint32, payload []byte) error {
	n := len(payload)
	hdr := []byte{byte(n >> 16), byte(n >> 8), byte(n), typ, flags, byte(stream >> 24 & 0x7f), byte(stream >> 16), byte(stream >> 8), byte(stream)}
	_, err := w.Write(append(hdr, payload...))
	return err
}

// wireGoAwayServer is a loopback HTTP/2 server that reads the client's
// preface and frames up to its first HEADERS, answers ":status: 200" first
// when answer is set, and then sends GOAWAY for stream 1 whose debug data is
// debug, half-closes, and drains the client until it closes. It returns the
// address and the roots that verify it.
func wireGoAwayServer(t *testing.T, debug string, answer bool) (string, *x509.CertPool) {
	t.Helper()
	cert, roots := wireServerIdentity(t)
	cfg := &tls.Config{
		MinVersion:             tls.VersionTLS12,
		Certificates:           []tls.Certificate{cert},
		NextProtos:             []string{"h2"},
		SessionTicketsDisabled: true,
	}
	addr := wireAlertServer(t, func(c net.Conn) {
		tc := tls.Server(c, cfg)
		if tc.Handshake() != nil || tc.ConnectionState().NegotiatedProtocol != "h2" {
			return
		}
		preface := make([]byte, len("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
		if _, err := io.ReadFull(tc, preface); err != nil {
			return
		}
		if wireFrame(tc, 0x4, 0, 0, nil) != nil { // SETTINGS
			return
		}
		for {
			hdr := make([]byte, 9)
			if _, err := io.ReadFull(tc, hdr); err != nil {
				return
			}
			n := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
			if _, err := io.CopyN(io.Discard, tc, int64(n)); err != nil {
				return
			}
			if hdr[3] == 0x1 { // HEADERS
				break
			}
		}
		if answer && wireFrame(tc, 0x1, 0x4, 1, []byte{0x88}) != nil { // :status: 200, END_HEADERS
			return
		}
		payload := append([]byte{0, 0, 0, 1, 0, 0, 0, 0}, debug...) // last stream 1, NO_ERROR
		if wireFrame(tc, 0x7, 0, 0, payload) != nil {               // GOAWAY
			return
		}
		_ = tc.CloseWrite()
		_, _ = io.Copy(io.Discard, tc)
	})
	return addr, roots
}

// TestAnAnswerNetHTTPCannotParseNamesNothing: net/http quotes a server's
// bytes in the error for an answer it cannot parse, and HTTP/2 quotes a
// GOAWAY's debug data. A misbehaving front end can echo the request there,
// and on the impersonation path the request names the service account. kube
// reads every such answer as unreachable, with fixed words, no status, no
// cause and no *url.Error: nothing the server sent is in any error.
func TestAnAnswerNetHTTPCannotParseNamesNothing(t *testing.T) {
	planted := wireMarker + "-" + wireReaderSA
	check := func(t *testing.T, err error, step kube.Step) {
		t.Helper()
		fe := federationError(t, err)
		want := "kube: Google's token exchange could not be reached: no readable answer"
		if step == kube.StepImpersonate {
			want = "kube: IAM Credentials could not be reached: no readable answer"
		}
		if err.Error() != want || fe.Status != 0 || fe.Handshake || fe.Step != step || !errors.Is(err, kube.ErrUnreachable) || errors.Is(err, kube.ErrTokenRefused) {
			t.Errorf("got %q (Status %d, Handshake %v); want %q, unreachable", err.Error(), fe.Status, fe.Handshake, want)
		}
		if errors.As(err, new(*url.Error)) {
			t.Error("a *url.Error is in the tree")
		}
		noMarker(t, err, wireMarker, "@", "serviceAccounts", "generateAccessToken", "gserviceaccount")
		if len(wireErrorTree(err)) != 2 {
			t.Errorf("the tree holds %d errors; want the error and its sentinel alone", len(wireErrorTree(err)))
		}
	}
	for _, c := range []struct {
		name string
		raw  func(path string) string
	}{
		{"a malformed header line", func(path string) string {
			return "HTTP/1.1 400 Bad Request\r\n" + planted + path + "\r\nContent-Length: 0\r\n\r\n"
		}},
		{"a malformed status line", func(path string) string {
			return planted + path + "\r\n\r\n"
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			addr, roots := wireRawServer(t, c.raw)
			f, err := kube.NewLoopbackFederation(addr, addr, addr, roots)
			if err != nil {
				t.Fatal(err)
			}
			r := newWireRole(t, "provreader1")
			_, err = f.Exchange(t.Context(), r.request())
			check(t, err, kube.StepExchange)
			_, err = f.Impersonate(t.Context(), &auth.Token{Value: "x"}, wireReaderSA, kube.ScopesCluster)
			check(t, err, kube.StepImpersonate)
		})
	}
	for _, c := range []struct {
		name   string
		answer bool
	}{
		{"a GOAWAY's debug data before the answer", false},
		{"a GOAWAY's debug data while the answer is read", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			addr, roots := wireGoAwayServer(t, planted, c.answer)
			f, err := kube.NewLoopbackFederation(addr, addr, addr, roots)
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.Impersonate(t.Context(), &auth.Token{Value: "x"}, wireReaderSA, kube.ScopesCluster)
			check(t, err, kube.StepImpersonate)
		})
	}
}

// TestAServerOffTheRootsIsRefusedBeforeTheCertificate: with roots that lack
// the fakes' CA, each call is unreachable, and neither server completed a
// handshake or saw a request: the client refused the server before it sent
// its certificate or its bearer.
func TestAServerOffTheRootsIsRefusedBeforeTheCertificate(t *testing.T) {
	fake := kubetest.NewFederation(t)
	other := kubetest.NewFederation(t)
	f, err := kube.NewLoopbackFederation(fake.STSAddr(), fake.IAMAddr(), fake.IAMAPIAddr(), other.Roots())
	if err != nil {
		t.Fatal(err)
	}
	r := newWireRole(t, "provreader1")
	addRole(fake, r)
	fake.Bind(r.id, wireReaderSA)
	_, err = f.Exchange(t.Context(), r.request())
	if fe := federationError(t, err); !errors.Is(err, kube.ErrUnreachable) || fe.Handshake || fe.Status != 0 || !strings.Contains(err.Error(), "x509") {
		t.Errorf("the exchange: %v; want unreachable with the x509 words", err)
	}
	_, err = f.Impersonate(t.Context(), &auth.Token{Value: "x"}, wireReaderSA, kube.ScopesCluster)
	if !errors.Is(err, kube.ErrUnreachable) {
		t.Errorf("the impersonation: %v; want unreachable", err)
	}
	if hs, reqs := fake.Handshakes(), fake.Requests(); len(hs) != 0 || len(reqs) != 0 {
		t.Errorf("%d handshakes and %d requests reached the fakes", len(hs), len(reqs))
	}
}

// closedAddr is a loopback address nothing listens on.
func closedAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// TestUnreachableNamesNoURL: an unreachable host's error has the transport's
// words, no *url.Error (whose URL names the email on the impersonation path)
// anywhere in its tree, and no text of the path.
func TestUnreachableNamesNoURL(t *testing.T) {
	fake := kubetest.NewFederation(t)
	f, err := kube.NewLoopbackFederation(closedAddr(t), closedAddr(t), closedAddr(t), fake.Roots())
	if err != nil {
		t.Fatal(err)
	}
	r := newWireRole(t, "provreader1")
	_, exErr := f.Exchange(t.Context(), r.request())
	_, imErr := f.Impersonate(t.Context(), &auth.Token{Value: "x"}, wireReaderSA, kube.ScopesCluster)
	for name, err := range map[string]error{"exchange": exErr, "impersonation": imErr} {
		if !errors.Is(err, kube.ErrUnreachable) || !strings.Contains(err.Error(), "connect") {
			t.Errorf("%s: %v; want unreachable with the transport's words", name, err)
		}
		if errors.As(err, new(*url.Error)) {
			t.Errorf("%s: a *url.Error is in the tree", name)
		}
		noMarker(t, err, "serviceAccounts", "@", "generateAccessToken", "/v1/")
	}
}

// TestLoopbackFederationRefusesOffMachineAddresses: the loopback constructor
// takes 127.0.0.1 and [::1] with a port alone (R4), at each of its three
// hosts, and each host's dialer reaches its own address alone, refusing
// every other before it connects.
func TestLoopbackFederationRefusesOffMachineAddresses(t *testing.T) {
	fake := kubetest.NewFederation(t)
	roots := fake.Roots()
	api := newAcceptCounter(t) // stands for IAM's API: a listener that counts what reaches it
	for _, addr := range []string{
		"192.0.2.1:443", "198.51.100.7:8443", "203.0.113.5:443",
		"localhost:443", "sts.mtls.googleapis.com:443", "iam.googleapis.com:443",
		"127.0.0.1", "[::1]", "::1", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:0443", "127.0.0.1:+443",
		"[::ffff:127.0.0.1]:443", "", "127.0.0.1:443/x", "https://127.0.0.1:443", " 127.0.0.1:443",
		"127.8.9.10:1", "127.0.0.2:443", "127.1:443", "[127.0.0.1]:443", "::1:443", "[::1%lo0]:443",
		"[0:0:0:0:0:0:0:1]:443",
	} {
		for name, build := range map[string]func() (*kube.Federation, error){
			"sts": func() (*kube.Federation, error) {
				return kube.NewLoopbackFederation(addr, fake.IAMAddr(), api.addr(), roots)
			},
			"iam": func() (*kube.Federation, error) {
				return kube.NewLoopbackFederation(fake.STSAddr(), addr, api.addr(), roots)
			},
			"iamapi": func() (*kube.Federation, error) {
				return kube.NewLoopbackFederation(fake.STSAddr(), fake.IAMAddr(), addr, roots)
			},
		} {
			f, err := build()
			want := "kube: the loopback federation takes 127.0.0.1 or [::1] with a port from 1 to 65535, not " + strconv.Quote(addr) + "; nothing was sent"
			if f != nil || !errors.Is(err, kube.ErrEndpointRefused) || err.Error() != want {
				t.Errorf("%s %q: %v, %v; want refused", name, addr, f, err)
			}
		}
	}
	if f, err := kube.NewLoopbackFederation(fake.STSAddr(), fake.IAMAddr(), api.addr(), nil); f != nil || !errors.Is(err, kube.ErrEndpointRefused) ||
		err.Error() != "kube: the loopback federation needs its fakes' CA; nothing was sent" {
		t.Errorf("no roots: %v, %v; want refused", f, err)
	}
	for _, addr := range []string{"127.0.0.1:443", "127.0.0.1:1", "127.0.0.1:65535", "[::1]:443"} {
		if _, err := kube.NewLoopbackFederation(addr, addr, addr, roots); err != nil {
			t.Errorf("%q: %v", addr, err)
		}
	}

	// The dial guard, at each of the three hosts.
	f, err := kube.NewLoopbackFederation(fake.STSAddr(), fake.IAMAddr(), api.addr(), roots)
	if err != nil {
		t.Fatal(err)
	}
	own := map[string]string{"sts": fake.STSAddr(), "iam": fake.IAMAddr(), "iamapi": api.addr()}
	other := newAcceptCounter(t)
	for host := range own {
		for to, addr := range own {
			if to == host {
				continue
			}
			if err := kube.FederationDial(t.Context(), f, host, addr); err == nil || !strings.Contains(err.Error(), "loopback client refused to dial") {
				t.Errorf("%s to %s's address: %v; want the dial guard's refusal", host, to, err)
			}
		}
		if err := kube.FederationDial(t.Context(), f, host, other.addr()); err == nil || !strings.Contains(err.Error(), "loopback client refused to dial") {
			t.Errorf("%s to another listener: %v; want the dial guard's refusal", host, err)
		}
	}
	if n := other.count(t); n != 0 {
		t.Errorf("%d connections reached the other listener", n)
	}
	if n := api.count(t); n != 0 {
		t.Errorf("%d connections reached IAM's API's address from another host's dialer", n)
	}
	for host, addr := range own {
		if err := kube.FederationDial(t.Context(), f, host, addr); err != nil {
			t.Errorf("%s to its own address: %v", host, err)
		}
	}
	if err := kube.FederationDial(t.Context(), f, "nowhere", fake.STSAddr()); err == nil {
		t.Error("FederationDial took a host it does not name")
	}
}

// acceptCounter is a loopback listener that counts what it accepts.
type acceptCounter struct {
	ln     net.Listener
	mu     sync.Mutex
	remote []string
}

func newAcceptCounter(t *testing.T) *acceptCounter {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &acceptCounter{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			c.mu.Lock()
			c.remote = append(c.remote, conn.RemoteAddr().String())
			c.mu.Unlock()
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return c
}

func (c *acceptCounter) addr() string { return c.ln.Addr().String() }

// count is how many connections the listener accepted before the test's own
// dial, which it makes and waits for, so nothing in flight is missed.
func (c *acceptCounter) count(t *testing.T) int {
	t.Helper()
	conn, err := net.Dial("tcp", c.addr())
	if err != nil {
		t.Fatal(err)
	}
	mine := conn.LocalAddr().String()
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		c.mu.Lock()
		for i, r := range c.remote {
			if r == mine {
				c.mu.Unlock()
				return i
			}
		}
		c.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	t.Fatal("the listener never accepted the test's own connection")
	return 0
}
