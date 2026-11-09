package identity

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
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
	certPEM, _, err := IssueKeeperClient(m.CACertPEM, m.CAKeyPEM, "prod", "laptop", bundle)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.URIs) != 2 || cert.URIs[0].String() != KeeperURI("prod", "laptop") ||
		cert.URIs[1].String() != KeeperBundleURIPrefix+KeeperBundleDigest(bundle) {
		t.Errorf("URIs = %v; want the keeper, then its bundle", cert.URIs)
	}
	if cert.Subject.CommonName != KeeperURI("prod", "laptop") {
		t.Errorf("subject = %q", cert.Subject.CommonName)
	}
	if _, _, err := IssueKeeperClient(m.CACertPEM, m.CAKeyPEM, "prod", "laptop", nil); err == nil {
		t.Error("a keeper leaf was issued binding no bundle")
	}
}
