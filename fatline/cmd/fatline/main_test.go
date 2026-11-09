package main

import (
	"crypto/tls"
	"testing"

	"github.com/sofmon/farcast/fatline/identity"
	fcrypto "github.com/sofmon/farcast/fatline/internal/crypto"
)

// FatLine reads which instance it serves from its own server leaf — the name
// every client pins — and refuses to open a tunnel when it cannot.
func TestTunnelInstanceComesFromTheServerLeaf(t *testing.T) {
	m, err := identity.Mint("prod")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(m.ServerCertPEM, m.ServerKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := tunnelInstance(cert); err != nil || got != "prod" {
		t.Errorf("tunnelInstance = %q, %v; want prod", got, err)
	}

	ca, err := fcrypto.NewCA("prod")
	if err != nil {
		t.Fatal(err)
	}
	for name, issue := range map[string]func() (fcrypto.Leaf, error){
		"an address-only server leaf": func() (fcrypto.Leaf, error) { return ca.IssueServer("127.0.0.1") },
		"a client leaf":               func() (fcrypto.Leaf, error) { return ca.IssueClient(identity.OperatorURI("prod")) },
	} {
		leaf, err := issue()
		if err != nil {
			t.Fatal(err)
		}
		c, err := leaf.TLSCertificate()
		if err != nil {
			t.Fatal(err)
		}
		if got, err := tunnelInstance(c); err == nil {
			t.Errorf("%s: tunnelInstance = %q; want a refusal", name, got)
		}
	}
	if _, err := tunnelInstance(tls.Certificate{}); err == nil {
		t.Error("an empty certificate was accepted")
	}
}
