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
