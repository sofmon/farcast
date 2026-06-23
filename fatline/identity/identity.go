// Package identity is FatLine's operator-side mTLS provisioning surface: it
// mints and assembles the per-instance certificate material that `farcast
// connect` (2.3) needs, without exposing FatLine's internal crypto package.
//
// The trust root is one self-signed CA per instance — the instance's sovereign
// data-plane identity, with no public CA, ACME, or Google IAM in the path
// (ADR 0005). The CA issues an operator client leaf (URI SAN
// farcast://<instance>/operator) and a FatLine server leaf (DNS SAN
// <instance>.fatline.farcast, the pinned server name). The CA private key is
// the crown jewel: the operator holds it and it is NEVER shipped to the
// cluster — only the CA certificate and the server leaf+key are.
package identity

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	fcrypto "github.com/sofmon/farcast/fatline/internal/crypto"
)

// OperatorURI is the SPIFFE-style identity carried in the operator's client
// certificate (a URI SAN), authorized by FatLine's tunnel server.
func OperatorURI(instance string) string {
	return "farcast://" + instance + "/operator"
}

// ServerName is the FatLine server's pinned identity (a DNS SAN). It is a
// synthetic name verified against the per-instance CA — never resolved in
// public DNS — so the certificate is independent of whatever address the
// carrier actually listens on (ADR 0005's carrier-independent server identity).
func ServerName(instance string) string {
	return instance + ".fatline.farcast"
}

// Material is a per-instance mTLS identity, PEM-encoded for storage. CAKeyPEM is
// the crown jewel — it stays on the operator's machine; ClusterSecret carries
// only what FatLine needs in-cluster.
type Material struct {
	Instance    string
	ServerName  string
	OperatorURI string

	CACertPEM     []byte
	CAKeyPEM      []byte // never shipped to the cluster
	ClientCertPEM []byte
	ClientKeyPEM  []byte
	ServerCertPEM []byte
	ServerKeyPEM  []byte
}

// Mint creates a fresh per-instance CA and issues the operator client leaf and
// the FatLine server leaf from it.
func Mint(instance string) (*Material, error) {
	if instance == "" {
		return nil, errors.New("identity: empty instance name")
	}
	ca, err := fcrypto.NewCA(instance)
	if err != nil {
		return nil, err
	}
	caKey, err := ca.KeyPEM()
	if err != nil {
		return nil, err
	}
	client, err := ca.IssueClient(OperatorURI(instance))
	if err != nil {
		return nil, fmt.Errorf("identity: issue operator client cert: %w", err)
	}
	server, err := ca.IssueServer(ServerName(instance))
	if err != nil {
		return nil, fmt.Errorf("identity: issue server cert: %w", err)
	}
	return &Material{
		Instance:      instance,
		ServerName:    ServerName(instance),
		OperatorURI:   OperatorURI(instance),
		CACertPEM:     ca.CertPEM,
		CAKeyPEM:      caKey,
		ClientCertPEM: client.CertPEM,
		ClientKeyPEM:  client.KeyPEM,
		ServerCertPEM: server.CertPEM,
		ServerKeyPEM:  server.KeyPEM,
	}, nil
}

// DialTLS returns exactly what tunnel.ClientIdentity needs to dial the instance:
// the operator's client certificate, a verification pool trusting ONLY the
// per-instance CA, and the pinned server name — built from the (possibly
// disk-loaded) CA cert + client leaf, without touching FatLine internals.
func (m *Material) DialTLS() (cert tls.Certificate, caPool *x509.CertPool, serverName string, err error) {
	cert, err = tls.X509KeyPair(m.ClientCertPEM, m.ClientKeyPEM)
	if err != nil {
		return tls.Certificate{}, nil, "", fmt.Errorf("identity: parse client cert: %w", err)
	}
	caPool, err = fcrypto.PoolFromPEM(m.CACertPEM)
	if err != nil {
		return tls.Certificate{}, nil, "", err
	}
	name := m.ServerName
	if name == "" {
		name = ServerName(m.Instance)
	}
	return cert, caPool, name, nil
}
