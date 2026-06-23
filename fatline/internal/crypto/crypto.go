// Package crypto mints and loads FatLine's per-instance mutual-TLS identity and
// builds the pinned *tls.Config for both legs of the tunnel.
//
// The trust root is one per-instance, self-signed CA — the instance's sovereign
// identity, with no public CA, ACME, or cert-manager in the path (zero central
// dependency, ADR 0005). The CA issues a server leaf (ServerAuth) and an
// operator client leaf (ClientAuth). FatLine is shipped the CA *certificate*
// (to verify clients) plus its own server leaf+key — never the CA private key —
// so a compromise of the in-cluster Secret can read only the rotatable leaf,
// never mint new identities.
//
// Choices: TLS 1.3 only (a closed FarCast-to-FarCast channel), ed25519 keys,
// crypto/rand serials, CA validity ~2y and leaves 90d, all standard library.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"time"
)

const (
	caValidity   = 2 * 365 * 24 * time.Hour
	leafValidity = 90 * 24 * time.Hour
)

// CA is a per-instance certificate authority. The private key is unexported and
// never printed, so it cannot leak through a log or %+v.
type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	key     ed25519.PrivateKey
}

// Leaf is an issued certificate and its private key, PEM-encoded for storage.
type Leaf struct {
	CertPEM []byte
	KeyPEM  []byte
}

// TLSCertificate parses the leaf into a tls.Certificate.
func (l Leaf) TLSCertificate() (tls.Certificate, error) {
	return tls.X509KeyPair(l.CertPEM, l.KeyPEM)
}

// NewCA mints a fresh per-instance CA. instance labels the CA subject.
func NewCA(instance string) (*CA, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("fatline: generate CA key: %w", err)
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "FarCast Instance CA: " + instance},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, fmt.Errorf("fatline: create CA cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("fatline: parse CA cert: %w", err)
	}
	return &CA{Cert: cert, CertPEM: pemEncode("CERTIFICATE", der), key: priv}, nil
}

// KeyPEM returns the CA private key in PKCS#8 PEM. The operator persists this —
// the crown jewel — at 0600; it is never shipped to the cluster.
func (ca *CA) KeyPEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(ca.key)
	if err != nil {
		return nil, fmt.Errorf("fatline: marshal CA key: %w", err)
	}
	return pemEncode("PRIVATE KEY", der), nil
}

// LoadCA reconstructs a CA from its certificate and private key PEM (e.g. the
// operator-held ca.crt/ca.key). The key is required to issue new leaves.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	cert, err := parseCert(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := parseEd25519Key(keyPEM)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, CertPEM: certPEM, key: key}, nil
}

// IssueServer issues a server (ServerAuth) leaf. identity becomes the leaf SAN:
// an IP literal → IP SAN, a URI (with scheme) → URI SAN, otherwise a DNS SAN.
// This single parameter lets the same code serve whichever carrier 2.3 binds
// (a public DNS/IP, an in-cluster service name, or a URI identity).
func (ca *CA) IssueServer(identity string) (Leaf, error) {
	return ca.issue(identity, x509.ExtKeyUsageServerAuth)
}

// IssueClient issues a client (ClientAuth) leaf, e.g. for the operator with a
// URI SAN farcast://<instance>/operator.
func (ca *CA) IssueClient(identity string) (Leaf, error) {
	return ca.issue(identity, x509.ExtKeyUsageClientAuth)
}

func (ca *CA) issue(identity string, eku x509.ExtKeyUsage) (Leaf, error) {
	if identity == "" {
		return Leaf{}, errors.New("fatline: empty certificate identity")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Leaf{}, fmt.Errorf("fatline: generate leaf key: %w", err)
	}
	serial, err := randSerial()
	if err != nil {
		return Leaf{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: identity},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(leafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{eku},
		BasicConstraintsValid: true,
	}
	applyIdentitySAN(tmpl, identity)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.key)
	if err != nil {
		return Leaf{}, fmt.Errorf("fatline: create leaf cert: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return Leaf{}, fmt.Errorf("fatline: marshal leaf key: %w", err)
	}
	return Leaf{CertPEM: pemEncode("CERTIFICATE", der), KeyPEM: pemEncode("PRIVATE KEY", keyDER)}, nil
}

// CertPool returns a pool containing only this CA's certificate (no system
// roots), for verifying the peer.
func (ca *CA) CertPool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

// PoolFromPEM builds a verification pool from CA certificate PEM, for a client
// that holds only the CA certificate (not the CA object).
func PoolFromPEM(caPEM []byte) (*x509.CertPool, error) {
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("fatline: no CA certificate found in PEM")
	}
	return p, nil
}

// ServerTLSConfig builds the server leg: TLS 1.3 only, RequireAndVerifyClientCert
// against clientCA, and — when verifyClientIdentity is non-nil — an additional
// check that the verified peer carries an authorized URI-SAN identity, so a
// valid cert from our CA is necessary but not sufficient.
func ServerTLSConfig(serverCert tls.Certificate, clientCA *x509.CertPool, verifyClientIdentity func(uri string) bool) *tls.Config {
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCA,
	}
	if verifyClientIdentity != nil {
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("fatline: no client certificate")
			}
			for _, u := range cs.PeerCertificates[0].URIs {
				if verifyClientIdentity(u.String()) {
					return nil
				}
			}
			return errors.New("fatline: client identity not authorized")
		}
	}
	return cfg
}

// ClientTLSConfig builds the client leg: TLS 1.3 only, presents clientCert,
// trusts ONLY rootCA (no system-root fallback), and pins serverName.
func ClientTLSConfig(clientCert tls.Certificate, rootCA *x509.CertPool, serverName string) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      rootCA,
		ServerName:   serverName,
	}
}

// applyIdentitySAN routes identity to the appropriate SAN type.
func applyIdentitySAN(tmpl *x509.Certificate, identity string) {
	if ip := net.ParseIP(identity); ip != nil {
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		return
	}
	if u, err := url.Parse(identity); err == nil && u.Scheme != "" && (u.Host != "" || u.Opaque != "" || u.Path != "") {
		tmpl.URIs = append(tmpl.URIs, u)
		return
	}
	tmpl.DNSNames = append(tmpl.DNSNames, identity)
}

func randSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("fatline: serial: %w", err)
	}
	return n, nil
}

func pemEncode(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func parseCert(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("fatline: invalid certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("fatline: parse certificate: %w", err)
	}
	return cert, nil
}

func parseEd25519Key(keyPEM []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("fatline: invalid private key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("fatline: parse private key: %w", err)
	}
	ed, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("fatline: expected ed25519 key, got %T", key)
	}
	return ed, nil
}
