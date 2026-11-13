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
// Choices: TLS 1.3 only (a closed FarCast-to-FarCast channel); ECDSA P-256
// with SHA-256 for the CA and every leaf (ADR 0020: the one algorithm every
// platform TLS stack and hardware key store accepts; Ed25519 is refused, not
// tolerated); crypto/rand serials; CA validity ~2y and leaves 90d; all
// standard library. A keeper's leaf key is generated on its device and never
// seen here: IssueClientFromRequest certifies the key a PKCS#10 request
// carries and honours nothing else in it.
package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"time"
)

const (
	caValidity   = 2 * 365 * 24 * time.Hour
	leafValidity = 90 * 24 * time.Hour
)

// ErrRetiredAlgorithm marks a key, certificate or peer in an algorithm ADR 0020
// retired.
var ErrRetiredAlgorithm = errors.New("ADR 0020 moved the instance PKI to ECDSA P-256 (docs/adr/0020-instance-pki-ecdsa-p256.md)")

// CA is a per-instance certificate authority. The private key is unexported and
// never printed, so it cannot leak through a log or %+v.
type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	key     *ecdsa.PrivateKey
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

// issuance is what varies between two issuances from the same template: the
// clock, the serial and the signature's randomness. Production takes all
// three live (liveIssuance); the conformance vectors fix them, with rand nil
// so that ECDSA signs deterministically (RFC 6979) and the vectors regenerate
// byte for byte.
type issuance struct {
	now    time.Time
	serial *big.Int
	rand   io.Reader // nil only in vector tests: RFC 6979 signatures
}

func liveIssuance() (issuance, error) {
	serial, err := randSerial()
	if err != nil {
		return issuance{}, err
	}
	return issuance{now: time.Now(), serial: serial, rand: rand.Reader}, nil
}

// NewCA mints a fresh per-instance CA. instance labels the CA subject.
func NewCA(instance string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("fatline: generate CA key: %w", err)
	}
	in, err := liveIssuance()
	if err != nil {
		return nil, err
	}
	return newCAWith(instance, key, in)
}

// newCAWith is NewCA with its key and issuance given: the production template,
// which the conformance vectors reach through this seam rather than copy.
func newCAWith(instance string, key *ecdsa.PrivateKey, in issuance) (*CA, error) {
	if key == nil || !IsP256(&key.PublicKey) {
		return nil, fmt.Errorf("fatline: a CA key must be ECDSA P-256: %w", ErrRetiredAlgorithm)
	}
	tmpl := caTemplate(instance, in)
	der, err := x509.CreateCertificate(in.rand, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("fatline: create CA cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("fatline: parse CA cert: %w", err)
	}
	return &CA{Cert: cert, CertPEM: pemEncode("CERTIFICATE", der), key: key}, nil
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
//
// It accepts an ECDSA P-256 key and nothing else (ADR 0020 decision 2), and
// requires the certificate to certify that key. An Ed25519 CA — every
// instance store from before ADR 0020 — is refused with the ADR named: there
// is no CA rotation, so such an instance is released and reinstalled.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	cert, err := parseCert(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := parseP256Key(keyPEM)
	if err != nil {
		return nil, err
	}
	if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("fatline: the CA certificate and key are not a pair")
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

// IssueClientFromRequest certifies the public key a PKCS#10 request carries,
// and nothing else in it (ADR 0020 decision 3).
//
// The request is checked by CheckRequest and then read for its key alone: the
// subject, SANs, EKU, key usage, basic constraints and validity are this
// template's, and the identity and bindings are the operator's. The key is
// re-marshalled from its parsed form, never copied from the request's bytes.
// The leaf is a client leaf: server leaves stay operator-minted.
//
// bindings are further URI SANs after the identity, each an opaque URI — a
// keeper's bundle digest.
func (ca *CA) IssueClientFromRequest(requestDER []byte, identity string, eku x509.ExtKeyUsage, bindings ...string) (certPEM []byte, err error) {
	if eku != x509.ExtKeyUsageClientAuth {
		return nil, errors.New("fatline: a leaf issued by request is a client leaf; server leaves stay operator-minted (ADR 0020 decision 3)")
	}
	pub, err := CheckRequest(requestDER)
	if err != nil {
		return nil, err
	}
	urls, err := parseBindings(bindings)
	if err != nil {
		return nil, err
	}
	in, err := liveIssuance()
	if err != nil {
		return nil, err
	}
	der, err := ca.issueFor(pub, identity, eku, urls, in)
	if err != nil {
		return nil, err
	}
	return pemEncode("CERTIFICATE", der), nil
}

func (ca *CA) issue(identity string, eku x509.ExtKeyUsage) (Leaf, error) {
	if identity == "" {
		return Leaf{}, errors.New("fatline: empty certificate identity")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Leaf{}, fmt.Errorf("fatline: generate leaf key: %w", err)
	}
	in, err := liveIssuance()
	if err != nil {
		return Leaf{}, err
	}
	der, err := ca.issueFor(&key.PublicKey, identity, eku, nil, in)
	if err != nil {
		return Leaf{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Leaf{}, fmt.Errorf("fatline: marshal leaf key: %w", err)
	}
	return Leaf{CertPEM: pemEncode("CERTIFICATE", der), KeyPEM: pemEncode("PRIVATE KEY", keyDER)}, nil
}

// issueFor is the one leaf template: every leaf this CA signs, operator-minted
// or by request, is this certificate over pub. The conformance vectors reach
// it through this seam with a fixed issuance.
func (ca *CA) issueFor(pub *ecdsa.PublicKey, identity string, eku x509.ExtKeyUsage, bindings []*url.URL, in issuance) (der []byte, err error) {
	if identity == "" {
		return nil, errors.New("fatline: empty certificate identity")
	}
	if pub == nil || !IsP256(pub) {
		return nil, fmt.Errorf("fatline: a leaf's key must be ECDSA P-256: %w", ErrRetiredAlgorithm)
	}
	der, err = x509.CreateCertificate(in.rand, leafTemplate(identity, eku, bindings, in), ca.Cert, pub, ca.key)
	if err != nil {
		return nil, fmt.Errorf("fatline: create leaf cert: %w", err)
	}
	return der, nil
}

// caTemplate is the instance CA's certificate template.
func caTemplate(instance string, in issuance) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          in.serial,
		Subject:               pkix.Name{CommonName: "FarCast Instance CA: " + instance},
		NotBefore:             in.now.Add(-time.Minute),
		NotAfter:              in.now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
}

// leafTemplate is every leaf's certificate template: the identity as subject
// and first SAN, then the bindings as further URI SANs.
func leafTemplate(identity string, eku x509.ExtKeyUsage, bindings []*url.URL, in issuance) *x509.Certificate {
	tmpl := &x509.Certificate{
		SerialNumber:          in.serial,
		Subject:               pkix.Name{CommonName: identity},
		NotBefore:             in.now.Add(-time.Minute),
		NotAfter:              in.now.Add(leafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{eku},
		BasicConstraintsValid: true,
	}
	applyIdentitySAN(tmpl, identity)
	tmpl.URIs = append(tmpl.URIs, bindings...)
	return tmpl
}

// parseBindings parses each binding as an opaque URI (a scheme and an opaque
// part, as urn:farcast:keeper-bundle:sha256:… is).
func parseBindings(bindings []string) ([]*url.URL, error) {
	out := make([]*url.URL, 0, len(bindings))
	for _, b := range bindings {
		u, err := url.Parse(b)
		if err != nil || u.Scheme == "" || u.Opaque == "" {
			return nil, errors.New("fatline: a binding must be an opaque URI")
		}
		out = append(out, u)
	}
	return out, nil
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
// against clientCA, a refusal of any client leaf whose key is not ECDSA P-256
// (ADR 0020 decision 2, defence in depth: this CA issues nothing else), and —
// when verifyClientIdentity is non-nil — an additional check that the verified
// peer carries an authorized URI-SAN identity, so a valid cert from our CA is
// necessary but not sufficient. fatline.New never passes nil: the tunnel
// admits by a fixed rule (fatline/admit.go).
func ServerTLSConfig(serverCert tls.Certificate, clientCA *x509.CertPool, verifyClientIdentity func(uri string) bool) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCA,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("fatline: no client certificate")
			}
			if !IsP256(cs.PeerCertificates[0].PublicKey) {
				return fmt.Errorf("fatline: the client certificate's key is not ECDSA P-256: %w", ErrRetiredAlgorithm)
			}
			if verifyClientIdentity == nil {
				return nil
			}
			for _, u := range cs.PeerCertificates[0].URIs {
				if verifyClientIdentity(u.String()) {
					return nil
				}
			}
			return errors.New("fatline: client identity not authorized")
		},
	}
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

// IsP256 reports whether pub is an ECDSA public key on P-256, the one key
// type the instance PKI issues and accepts (ADR 0020 decision 1).
func IsP256(pub any) bool {
	k, ok := pub.(*ecdsa.PublicKey)
	return ok && k != nil && k.Curve == elliptic.P256()
}

// KeyFingerprint is the SHA-256 of pub's SubjectPublicKeyInfo DER, as 64
// lowercase hex characters: what a device shows for the key it made and the
// operator's machine confirms before it certifies it (ADR 0020 decision 3).
// It covers the SubjectPublicKeyInfo and not a request's or certificate's
// bytes, because an ECDSA signature has more than one valid encoding.
func KeyFingerprint(pub any) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("fatline: marshal public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// RequireP256CA refuses an instance CA certificate whose key is not ECDSA
// P-256, wrapping ErrRetiredAlgorithm. It reads only the certificate, so a
// command that never loads the CA key can still refuse a store from before
// ADR 0020 before it dials or applies anything.
func RequireP256CA(certPEM []byte) error {
	cert, err := parseCert(certPEM)
	if err != nil {
		return err
	}
	if !IsP256(cert.PublicKey) {
		return fmt.Errorf("the instance's CA is %s, and %w; there is no CA rotation, so release and reinstall the instance", keyName(cert.PublicKey), ErrRetiredAlgorithm)
	}
	return nil
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

// parseP256Key parses the CA's PKCS#8 private key and accepts ECDSA P-256
// alone. Its refusals name the key's algorithm and never its bytes.
func parseP256Key(keyPEM []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("fatline: invalid private key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("fatline: parse private key: %w", err)
	}
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		if IsP256(&k.PublicKey) {
			return k, nil
		}
	case ed25519.PrivateKey:
		return nil, fmt.Errorf("fatline: this instance's CA key is Ed25519, and %w: there is no CA rotation, so release and reinstall the instance", ErrRetiredAlgorithm)
	}
	what := fmt.Sprintf("%T", key)
	if s, ok := key.(crypto.Signer); ok {
		what = keyName(s.Public())
	}
	return nil, fmt.Errorf("fatline: the CA key is %s, not ECDSA P-256 — %w", what, ErrRetiredAlgorithm)
}

// keyName names a public key's algorithm (and curve or size) for a refusal.
func keyName(pub any) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k == nil || k.Curve == nil {
			return "ECDSA"
		}
		return "ECDSA " + k.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	case *rsa.PublicKey:
		if k == nil || k.N == nil {
			return "RSA"
		}
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	default:
		return fmt.Sprintf("%T", pub)
	}
}
