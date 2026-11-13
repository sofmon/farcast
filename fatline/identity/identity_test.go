package identity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMintEmptyInstance(t *testing.T) {
	if _, err := Mint(""); err == nil {
		t.Fatal("expected an error for an empty instance name")
	}
}

func TestMintMaterial(t *testing.T) {
	m, err := Mint("prod")
	if err != nil {
		t.Fatal(err)
	}
	if m.ServerName != "prod.fatline.farcast" {
		t.Errorf("ServerName=%q, want prod.fatline.farcast", m.ServerName)
	}
	if m.OperatorURI != "farcast://prod/operator" {
		t.Errorf("OperatorURI=%q, want farcast://prod/operator", m.OperatorURI)
	}
	for name, p := range map[string][]byte{
		"ca.crt": m.CACertPEM, "ca.key": m.CAKeyPEM,
		"client.crt": m.ClientCertPEM, "client.key": m.ClientKeyPEM,
		"server.crt": m.ServerCertPEM, "server.key": m.ServerKeyPEM,
	} {
		if len(p) == 0 {
			t.Errorf("%s is empty", name)
		}
	}
}

func TestMintedLeavesChainToCA(t *testing.T) {
	m, err := Mint("prod")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(m.CACertPEM) {
		t.Fatal("CA certificate did not parse into a pool")
	}

	client := parseLeaf(t, m.ClientCertPEM)
	if _, err := client.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("operator client leaf does not chain to the CA as a client cert: %v", err)
	}
	if len(client.URIs) != 1 || client.URIs[0].String() != "farcast://prod/operator" {
		t.Fatalf("client URIs=%v, want [farcast://prod/operator]", client.URIs)
	}

	server := parseLeaf(t, m.ServerCertPEM)
	if _, err := server.Verify(x509.VerifyOptions{Roots: roots, DNSName: "prod.fatline.farcast", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("server leaf does not verify for its pinned SAN: %v", err)
	}
}

func TestDialTLS(t *testing.T) {
	m, err := Mint("prod")
	if err != nil {
		t.Fatal(err)
	}
	cert, pool, name, err := m.DialTLS()
	if err != nil {
		t.Fatal(err)
	}
	if name != "prod.fatline.farcast" {
		t.Errorf("server name=%q", name)
	}
	if len(cert.Certificate) == 0 {
		t.Error("empty client certificate")
	}
	if pool == nil {
		t.Error("nil CA pool")
	}

	// A disk-loaded Material carries only the dial fields; DialTLS must still work.
	partial := &Material{
		Instance:      "prod",
		CACertPEM:     m.CACertPEM,
		ClientCertPEM: m.ClientCertPEM,
		ClientKeyPEM:  m.ClientKeyPEM,
	}
	if _, _, n, err := partial.DialTLS(); err != nil || n != "prod.fatline.farcast" {
		t.Fatalf("partial DialTLS: name=%q err=%v", n, err)
	}
}

func parseLeaf(t *testing.T, pemBytes []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("no PEM block")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestKeyholderIdentityIsDistinctFromFatLine(t *testing.T) {
	if KeyholderServerName("prod") == ServerName("prod") {
		t.Fatal("the keyholder and FatLine share a server identity; a leaf for one would stand in for the other")
	}
	if KeeperURI("prod", "laptop") == OperatorURI("prod") {
		t.Fatal("a keeper shares the operator's identity; it could not be revoked separately")
	}
}

func TestIssueKeyholderServerChainsToTheCA(t *testing.T) {
	m, err := Mint("prod")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	certPEM, keyPEM, err := IssueKeyholderServer(m.CACertPEM, m.CAKeyPEM, "prod")
	if err != nil {
		t.Fatalf("IssueKeyholderServer: %v", err)
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatalf("the issued leaf is not a usable pair: %v", err)
	}
	leaf := parseLeaf(t, certPEM)

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(m.CACertPEM) {
		t.Fatal("could not build a pool from the CA")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		DNSName:   KeyholderServerName("prod"),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("the keyholder leaf does not verify against the instance CA: %v", err)
	}
	// It must NOT stand in for FatLine.
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		DNSName:   ServerName("prod"),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err == nil {
		t.Fatal("the keyholder leaf verified as FatLine's server name")
	}
}

func TestIssueKeyholderServerRefusesBadInput(t *testing.T) {
	m, _ := Mint("prod")
	if _, _, err := IssueKeyholderServer(m.CACertPEM, m.CAKeyPEM, ""); err == nil {
		t.Error("accepted an empty instance name")
	}
	if _, _, err := IssueKeyholderServer([]byte("not a ca"), m.CAKeyPEM, "prod"); err == nil {
		t.Error("accepted a malformed CA certificate")
	}
}

// Application and device identities (ADR 0018). The keyholder parses these by
// shape — it cannot import this package — so the shapes are pinned here and
// mirrored in datasphere/keyholder's own table.
func TestDataPathURIs(t *testing.T) {
	if got := AppURI("prod", "shop", "api"); got != "farcast://prod/app/shop/api" {
		t.Errorf("AppURI = %q", got)
	}
	if got := DeviceURI("prod", "tablet"); got != "farcast://prod/device/tablet" {
		t.Errorf("DeviceURI = %q", got)
	}
}

func TestIssueAppClientChainsToCAWithItsOwnURI(t *testing.T) {
	m, err := Mint("prod")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := IssueAppClient(m.CACertPEM, m.CAKeyPEM, "prod", "shop", "api")
	if err != nil {
		t.Fatalf("IssueAppClient: %v", err)
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatalf("the issued leaf and key do not pair: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(m.CACertPEM)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("the application leaf does not chain to the instance CA as a client: %v", err)
	}
	found := false
	for _, u := range leaf.URIs {
		if u.String() == "farcast://prod/app/shop/api" {
			found = true
		}
	}
	if !found {
		t.Errorf("leaf URIs = %v, want the application's own", leaf.URIs)
	}
	for _, bad := range [][3]string{{"", "shop", "api"}, {"prod", "", "api"}, {"prod", "shop", ""}} {
		if _, _, err := IssueAppClient(m.CACertPEM, m.CAKeyPEM, bad[0], bad[1], bad[2]); err == nil {
			t.Errorf("IssueAppClient(%q, %q, %q) succeeded with a blank", bad[0], bad[1], bad[2])
		}
	}
}

func TestInstanceFromServerName(t *testing.T) {
	if got, ok := InstanceFromServerName(ServerName("prod")); !ok || got != "prod" {
		t.Errorf("round trip = %q, %v", got, ok)
	}
	for _, name := range []string{"", "fatline.farcast", ".fatline.farcast", "a.b.fatline.farcast",
		"prod.datasphered.farcast", "prod.fatline.farcast.evil", "prod"} {
		if got, ok := InstanceFromServerName(name); ok {
			t.Errorf("InstanceFromServerName(%q) = %q; want refused", name, got)
		}
	}
}

// The same vector lives in datasphere/keyholder's tests: this package issues
// the digest and the keyholder checks it, and the two mirror rather than
// import.
func TestKeeperBundleDigestMirrorsTheKeyholder(t *testing.T) {
	const want = "66f2f344be17652ffb333e89fa3e3306f7efc493f5d77c7d1a663f63c20137d2"
	if got := KeeperBundleDigest([]byte("version: 1\n")); got != want {
		t.Errorf("KeeperBundleDigest = %s, want %s", got, want)
	}
}

// A keeper's leaf names the device first and the bundle second. The device URI
// is what every listener admits on; the bundle URI is what the keyholder holds
// the push to.
func TestAKeeperLeafBindsItsBundle(t *testing.T) {
	m, err := Mint("prod")
	if err != nil {
		t.Fatal(err)
	}
	bundle := []byte("version: 1\n")
	_, req := newRequest(t)
	certPEM, err := IssueKeeperClient(m.CACertPEM, m.CAKeyPEM, "prod", "laptop", bundle, req)
	if err != nil {
		t.Fatal(err)
	}
	cert := parseLeaf(t, certPEM)
	if len(cert.URIs) != 2 || cert.URIs[0].String() != KeeperURI("prod", "laptop") ||
		cert.URIs[1].String() != KeeperBundleURIPrefix+KeeperBundleDigest(bundle) {
		t.Errorf("URIs = %v; want the keeper, then its bundle", cert.URIs)
	}
	if cert.Subject.CommonName != KeeperURI("prod", "laptop") {
		t.Errorf("subject = %q", cert.Subject.CommonName)
	}
	if _, err := IssueKeeperClient(m.CACertPEM, m.CAKeyPEM, "prod", "laptop", nil, req); err == nil {
		t.Error("a keeper leaf was issued binding no bundle")
	}
}

// A leaf token is short, stable and domain-separated: the operator's machine
// records it at issuance and FatLine recomputes it from the verified leaf, so
// the two must agree on every byte of the recipe. The pinned vector
// (token.json) catches a changed label, body or truncation; the fingerprint
// comparison catches dropping the label, which would make the token joinable
// against any SHA-256 fingerprint of the leaf printed anywhere else.
func TestLeafTokenIsShortStableAndDomainSeparated(t *testing.T) {
	v := readTokenVector(t)
	leaf := parseLeaf(t, []byte(v.LeafPEM))
	if got := LeafToken(leaf); got != v.Token {
		t.Errorf("LeafToken = %s, want %s (token.json)", got, v.Token)
	}
	for what, b := range map[string][]byte{"signed body": leaf.RawTBSCertificate, "DER": leaf.Raw} {
		fingerprint := sha256.Sum256(b)
		if LeafToken(leaf) == hex.EncodeToString(fingerprint[:])[:16] {
			t.Errorf("the token is the leaf's plain %s fingerprint; it must be domain-separated", what)
		}
	}

	m, err := Mint("prod")
	if err != nil {
		t.Fatal(err)
	}
	_, req := newRequest(t)
	a, err := IssueKeeperClient(m.CACertPEM, m.CAKeyPEM, "prod", "laptop", []byte("version: 1\n"), req)
	if err != nil {
		t.Fatal(err)
	}
	b, err := IssueKeeperClient(m.CACertPEM, m.CAKeyPEM, "prod", "laptop", []byte("version: 1\n"), req)
	if err != nil {
		t.Fatal(err)
	}
	ta, tb := LeafToken(parseLeaf(t, a)), LeafToken(parseLeaf(t, b))
	if len(ta) != 16 {
		t.Errorf("token %q is %d characters, want 16", ta, len(ta))
	}
	// The same device re-enrolled is two leaves, and two tokens: a token names
	// a leaf, and an old leaf stays valid in the cluster until its NotAfter.
	// Even over one key, the serial keeps the signed bodies apart.
	if ta == tb {
		t.Error("two leaves for one device share a token")
	}
}

// The CLI computes the token from the PEM it issued, FatLine from the
// certificate the handshake verified. They must be the same bytes.
func TestLeafTokenPEMMatchesLeafToken(t *testing.T) {
	m, err := Mint("prod")
	if err != nil {
		t.Fatal(err)
	}
	got, err := LeafTokenPEM(m.ClientCertPEM)
	if err != nil {
		t.Fatal(err)
	}
	if want := LeafToken(parseLeaf(t, m.ClientCertPEM)); got != want {
		t.Errorf("LeafTokenPEM = %s, LeafToken over the parsed leaf = %s", got, want)
	}
	for _, bad := range [][]byte{nil, []byte("not pem"), m.ClientKeyPEM} {
		if _, err := LeafTokenPEM(bad); err == nil {
			t.Errorf("LeafTokenPEM accepted %.20q", bad)
		}
	}
}

// ---- ADR 0020 ----

// The conformance vectors fatline/internal/crypto writes. That package cannot
// import this one, so it writes this package's names as literals, and these
// tests hold the literals to the functions.
const pkiVectors = "../internal/crypto/testdata/pki"

func readPKIVector(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(pkiVectors, name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

type tokenVector struct {
	Label   string `json:"label"`
	LeafPEM string `json:"leaf_pem"`
	TwinPEM string `json:"twin_pem"`
	Token   string `json:"token"`
}

func readTokenVector(t *testing.T) tokenVector {
	t.Helper()
	var v tokenVector
	readPKIVector(t, "token.json", &v)
	if v.Token == "" || v.LeafPEM == "" || v.TwinPEM == "" {
		t.Fatal("token.json is missing a field")
	}
	return v
}

type requestVectors struct {
	Valid []struct {
		Name       string `json:"name"`
		RequestPEM string `json:"request_pem"`
		KeySHA256  string `json:"key_sha256"`
	} `json:"valid"`
	KeyOnly struct {
		RequestPEM string `json:"request_pem"`
		KeySHA256  string `json:"key_sha256"`
	} `json:"key_only"`
	Invalid []struct {
		Name       string `json:"name"`
		RequestPEM string `json:"request_pem"`
		Refusal    string `json:"refusal"`
	} `json:"invalid"`
}

func readRequestVectors(t *testing.T) requestVectors {
	t.Helper()
	var v requestVectors
	readPKIVector(t, "requests.json", &v)
	if len(v.Valid) == 0 || len(v.Invalid) == 0 {
		t.Fatal("requests.json holds no vectors")
	}
	return v
}

func pemBytes(t *testing.T, s string) []byte {
	t.Helper()
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		t.Fatal("no PEM block")
	}
	return block.Bytes
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

func requestPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// C2 and C4: the literals the vectors were written with are this package's.
func TestPKIVectorsUseThisPackagesNames(t *testing.T) {
	var p256 struct {
		Instance   string `json:"instance"`
		ServerName string `json:"server_name"`
		Server     struct {
			Identity string `json:"identity"`
		} `json:"server"`
		Client struct {
			Identity string `json:"identity"`
		} `json:"client"`
	}
	readPKIVector(t, "p256.json", &p256)
	if p256.ServerName != ServerName(p256.Instance) || p256.Server.Identity != ServerName(p256.Instance) {
		t.Errorf("p256.json server name %q, identity %q; ServerName(%q) = %q", p256.ServerName, p256.Server.Identity, p256.Instance, ServerName(p256.Instance))
	}
	if p256.Client.Identity != OperatorURI(p256.Instance) {
		t.Errorf("p256.json client %q; OperatorURI(%q) = %q", p256.Client.Identity, p256.Instance, OperatorURI(p256.Instance))
	}
	if v := readTokenVector(t); v.Label != leafTokenDomain {
		t.Errorf("token.json label %q, LeafToken's %q", v.Label, leafTokenDomain)
	}
	csr, err := x509.ParseCertificateRequest(pemBytes(t, readRequestVectors(t).KeyOnly.RequestPEM))
	if err != nil {
		t.Fatal(err)
	}
	bound := false
	for _, u := range csr.URIs {
		bound = bound || strings.HasPrefix(u.String(), KeeperBundleURIPrefix)
	}
	if !bound {
		t.Errorf("key_only asks for no URI under KeeperBundleURIPrefix: %v", csr.URIs)
	}
}

// A-T10. connect, run and the rehearsal refuse a store whose CA is Ed25519
// before they dial or apply anything (ADR 0020 decision 2).
func TestRequireP256CA(t *testing.T) {
	var ed struct {
		CA struct {
			CertPEM string `json:"cert_pem"`
		} `json:"ca"`
	}
	readPKIVector(t, "ed25519.json", &ed)
	err := RequireP256CA([]byte(ed.CA.CertPEM))
	if !errors.Is(err, ErrRetiredAlgorithm) {
		t.Fatalf("an Ed25519 CA: %v, want ErrRetiredAlgorithm", err)
	}
	for _, want := range []string{"Ed25519", "ADR 0020", "release and reinstall"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, err)
		}
	}
	m, err := Mint("prod")
	if err != nil {
		t.Fatal(err)
	}
	if err := RequireP256CA(m.CACertPEM); err != nil {
		t.Errorf("a P-256 CA was refused: %v", err)
	}
	if err := RequireP256CA([]byte("not a certificate")); err == nil {
		t.Error("RequireP256CA accepted something that is not a certificate")
	}
}

// A-T11. ADR 0020 decision 4: the token is over the signed body, so a leaf
// and its twin — the same certificate with the signature re-encoded as
// s' = n - s, which verifies as well — are one token.
func TestLeafTokenV2OverTheSignedBody(t *testing.T) {
	v := readTokenVector(t)
	leaf, twin := parseLeaf(t, []byte(v.LeafPEM)), parseLeaf(t, []byte(v.TwinPEM))
	if bytes.Equal(leaf.Raw, twin.Raw) {
		t.Fatal("the twin is the leaf; the vector proves nothing")
	}
	if LeafToken(leaf) != v.Token || LeafToken(twin) != v.Token {
		t.Errorf("LeafToken: leaf %s, twin %s; token.json says %s", LeafToken(leaf), LeafToken(twin), v.Token)
	}
	for _, p := range []string{v.LeafPEM, v.TwinPEM} {
		if got, err := LeafTokenPEM([]byte(p)); err != nil || got != v.Token {
			t.Errorf("LeafTokenPEM = %s, %v; want %s", got, err, v.Token)
		}
	}
	sum := func(parts ...[]byte) string {
		h := sha256.Sum256(bytes.Join(parts, nil))
		return hex.EncodeToString(h[:])[:16]
	}
	if want := sum([]byte("farcast-leaf-token-v2"), leaf.RawTBSCertificate); v.Token != want {
		t.Errorf("token %s, want SHA-256(farcast-leaf-token-v2 || TBS)[:8] = %s", v.Token, want)
	}
	if v.Token == sum(leaf.RawTBSCertificate) {
		t.Error("the token is the signed body's plain fingerprint")
	}
	if v.Token == sum([]byte("farcast-leaf-token-v1"), leaf.Raw) || v.Token == sum([]byte("farcast-leaf-token-v1"), leaf.RawTBSCertificate) {
		t.Error("the token is v1's")
	}
	if LeafToken(nil) != "" {
		t.Error("LeafToken(nil) named something")
	}
}

// A-T12. ADR 0020 decision 3: a keeper's leaf certifies the key its request
// carries; the operator's machine makes no key for it.
func TestIssueKeeperClientCertifiesTheRequestKey(t *testing.T) {
	m, err := Mint("prod")
	if err != nil {
		t.Fatal(err)
	}
	bundle := []byte("version: 1\n")
	key, req := newRequest(t)
	certPEM, err := IssueKeeperClient(m.CACertPEM, m.CAKeyPEM, "prod", "phone", bundle, req)
	if err != nil {
		t.Fatal(err)
	}
	cert := parseLeaf(t, certPEM)
	if !key.PublicKey.Equal(cert.PublicKey) {
		t.Error("the keeper leaf certifies a key the device does not hold")
	}
	if len(cert.URIs) != 2 || cert.URIs[0].String() != KeeperURI("prod", "phone") || cert.URIs[1].String() != KeeperBundleURIPrefix+KeeperBundleDigest(bundle) {
		t.Errorf("URIs %v", cert.URIs)
	}
	// The leaf and the device's key form a pair: the device can present it.
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})); err != nil {
		t.Errorf("the leaf and the device's key do not pair: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(m.CACertPEM)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("the keeper leaf does not chain to the CA as a client: %v", err)
	}

	for _, bad := range []struct {
		what             string
		instance, device string
		bundle           []byte
	}{{"no instance", "", "phone", bundle}, {"no device", "prod", "", bundle}, {"no bundle", "prod", "phone", nil}} {
		if c, err := IssueKeeperClient(m.CACertPEM, m.CAKeyPEM, bad.instance, bad.device, bad.bundle, req); err == nil || c != nil {
			t.Errorf("%s: a keeper leaf was issued", bad.what)
		}
	}
	for _, r := range readRequestVectors(t).Invalid {
		c, err := IssueKeeperClient(m.CACertPEM, m.CAKeyPEM, "prod", "phone", bundle, pemBytes(t, r.RequestPEM))
		var re *RequestError
		if err == nil || c != nil {
			t.Errorf("%s: a keeper leaf was issued", r.Name)
		} else if !errors.As(err, &re) || re.Refusal != r.Refusal {
			t.Errorf("%s: %v, want a RequestError with refusal %s", r.Name, err, r.Refusal)
		}
	}
}

// A-T13. A request file is one CERTIFICATE REQUEST block and nothing else.
func TestParseRequestPEM(t *testing.T) {
	key, der := newRequest(t)
	good := requestPEM(der)
	for name, in := range map[string][]byte{
		"bare":                  good,
		"surrounded by spaces":  append(append([]byte("\n  \r\n"), good...), []byte("\n\n  ")...),
		"without a final break": bytes.TrimRight(good, "\n"),
	} {
		r, err := ParseRequest(in)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		want, _ := KeyFingerprint(key.Public())
		if !bytes.Equal(r.DER, der) || r.KeySHA256 != want {
			t.Errorf("%s: DER or fingerprint is not the request's", name)
		}
	}

	m, err := Mint("prod")
	if err != nil {
		t.Fatal(err)
	}
	_, otherDER := newRequest(t)
	headed := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Headers: map[string]string{"Comment": "x"}, Bytes: der})
	for name, in := range map[string][]byte{
		"empty":                 nil,
		"not PEM":               []byte("a request"),
		"two blocks":            append(cloneBytes(good), requestPEM(otherDER)...),
		"a certificate block":   m.ClientCertPEM,
		"a request then a cert": append(cloneBytes(good), m.ClientCertPEM...),
		"trailing text":         append(cloneBytes(good), []byte("and some words\n")...),
		"leading text":          append([]byte("hello\n"), good...),
		"a block with headers":  headed,
		"over 64 KiB":           append(cloneBytes(good), bytes.Repeat([]byte(" "), 64<<10)...),
		"another block type":    pem.EncodeToMemory(&pem.Block{Type: "NEW CERTIFICATE REQUEST", Bytes: der}),
		// pem.Decode steps over a block it cannot decode to the next one;
		// ParseRequest must not.
		"a malformed BEGIN line before the block":         append([]byte("-----BEGIN junk\nnot pem\n"), good...),
		"a corrupt request block before a good one":       append([]byte("-----BEGIN CERTIFICATE REQUEST-----\n!!not base64!!\n-----END CERTIFICATE REQUEST-----\n"), good...),
		"an unterminated request block before a good one": append([]byte("-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n"), good...),
	} {
		_, err := ParseRequest(in)
		var re *RequestError
		if !errors.As(err, &re) || re.Refusal != RefusalMalformed {
			t.Errorf("%s: %v, want refusal %s", name, err, RefusalMalformed)
		}
	}
	// Decision 3's checks run on the block, with their own codes.
	for _, r := range readRequestVectors(t).Invalid {
		_, err := ParseRequest([]byte(r.RequestPEM))
		var re *RequestError
		if !errors.As(err, &re) || re.Refusal != r.Refusal {
			t.Errorf("%s: %v, want refusal %s", r.Name, err, r.Refusal)
		}
	}
	for _, r := range readRequestVectors(t).Valid {
		got, err := ParseRequest([]byte(r.RequestPEM))
		if err != nil || got.KeySHA256 != r.KeySHA256 {
			t.Errorf("%s: %v, fingerprint %s, want %s", r.Name, err, got.KeySHA256, r.KeySHA256)
		}
	}
}

func cloneBytes(b []byte) []byte { return append([]byte(nil), b...) }

// A-T14. The fingerprint as a person reads, types and confirms it.
func TestFingerprintText(t *testing.T) {
	const fp = "3f2a9c0144b8e2d17a6c5f0e9b3d28c1a4e7f6b2093d5c8e1f4a7b6c0d1b23ef"
	const formatted = "3f2a 9c01 44b8 e2d1 7a6c 5f0e 9b3d 28c1 a4e7 f6b2 093d 5c8e 1f4a 7b6c 0d1b 23ef"
	if got := FormatFingerprint(fp); got != formatted {
		t.Errorf("FormatFingerprint = %q", got)
	}
	if got := FingerprintTail(fp); got != "1f4a 7b6c 0d1b 23ef" {
		t.Errorf("FingerprintTail = %q, want the last 4 groups", got)
	}
	for _, notFP := range []string{"", "abc", fp[:63], fp + "0", strings.Replace(fp, "3f", "zz", 1)} {
		if FormatFingerprint(notFP) != notFP || FingerprintTail(notFP) != notFP {
			t.Errorf("%q was reformatted; only a fingerprint is", notFP)
		}
	}

	for _, in := range []string{fp, formatted, strings.ToUpper(formatted), strings.ReplaceAll(formatted, " ", ":"), "  " + formatted + "\n"} {
		if got, err := ParseFingerprint(in); err != nil || got != fp {
			t.Errorf("ParseFingerprint(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", fp[:63], fp + "a", strings.Replace(fp, "3f", "3g", 1), formatted[:len(formatted)-1]} {
		if _, err := ParseFingerprint(bad); err == nil {
			t.Errorf("ParseFingerprint accepted %q", bad)
		}
	}
	if _, err := ParseFingerprint(fp[:63] + "x"); err == nil || strings.Contains(err.Error(), fp[:8]) {
		t.Errorf("ParseFingerprint's refusal repeats its input or accepts it: %v", err)
	}

	groups := strings.Fields(formatted)
	last8 := strings.Join(groups[8:], " ")
	matches := []string{last8, strings.ToUpper(last8), strings.ReplaceAll(last8, " ", ":"), strings.ReplaceAll(last8, " ", ""), formatted, fp, strings.Join(groups[2:], " ")}
	for _, typed := range matches {
		if ok, err := FingerprintSuffixMatches(fp, typed); !ok || err != nil {
			t.Errorf("FingerprintSuffixMatches(%q) = %v, %v; want a match", typed, ok, err)
		}
	}
	notSuffix := []string{strings.Join(groups[:8], " "), strings.Join(groups[4:12], " "), strings.Join(groups[7:15], " ")}
	for _, typed := range notSuffix {
		if ok, err := FingerprintSuffixMatches(fp, typed); ok || err != nil {
			t.Errorf("FingerprintSuffixMatches(%q) = %v, %v; want no match and no error", typed, ok, err)
		}
	}
	tooShort := strings.Join(groups[12:], " ") // the last 4 groups: 16 hex
	for _, typed := range []string{tooShort, fp[33:], fp + "0", "", strings.Replace(last8, "a", "x", 1)} {
		if ok, err := FingerprintSuffixMatches(fp, typed); ok || err == nil {
			t.Errorf("FingerprintSuffixMatches(%q) = %v, %v; want an error", typed, ok, err)
		}
	}
	for _, badFP := range []string{"", fp[:63], strings.ToUpper(fp), formatted} {
		if ok, err := FingerprintSuffixMatches(badFP, last8); ok || err == nil {
			t.Errorf("FingerprintSuffixMatches with fp %q = %v, %v; want an error", badFP, ok, err)
		}
	}
}

// KeyFingerprint and CertKeyFingerprint agree on a certificate and its key.
func TestCertKeyFingerprint(t *testing.T) {
	m, err := Mint("prod")
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(m.ClientCertPEM, m.ClientKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	want, err := KeyFingerprint(pair.PrivateKey.(*ecdsa.PrivateKey).Public())
	if err != nil {
		t.Fatal(err)
	}
	if got, err := CertKeyFingerprint(m.ClientCertPEM); err != nil || got != want || len(got) != 64 {
		t.Errorf("CertKeyFingerprint = %s, %v; want %s", got, err, want)
	}
	if got, err := CertKeyFingerprint(append(cloneBytes(m.ClientKeyPEM), m.ClientCertPEM...)); err != nil || got != want {
		t.Errorf("CertKeyFingerprint skipping a key block = %s, %v", got, err)
	}
	for _, bad := range [][]byte{nil, m.ClientKeyPEM, []byte("x")} {
		if _, err := CertKeyFingerprint(bad); err == nil {
			t.Errorf("CertKeyFingerprint accepted %.20q", bad)
		}
	}
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if fp, err := KeyFingerprint(edPub); err != nil || len(fp) != 64 {
		t.Errorf("KeyFingerprint names any SPKI, Ed25519 included: %s, %v", fp, err)
	}
}
