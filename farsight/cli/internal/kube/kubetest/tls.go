package kubetest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// certLifetime is how long the CA and the leaf are valid. A restarted server
// has a new CA, so the rehearsal rewrites cluster-ca.crt at every start (§10.1).
const certLifetime = 365 * 24 * time.Hour

// newCertificates makes the server's own CA, a P-256 key and a self-signed
// certificate, and a P-256 leaf it issues for exactly one IP address, ip.
// Nothing else is named: no DNS name, so the name localhost never verifies.
func newCertificates(ip net.IP) (caPEM []byte, leaf tls.Certificate, err error) {
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("generate the CA key: %w", err)
	}
	caSerial, err := serialNumber()
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "kubetest CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(certLifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("sign the CA certificate: %w", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("read the CA certificate back: %w", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("generate the leaf key: %w", err)
	}
	leafSerial, err := serialNumber()
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: "kubetest"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(certLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{ip},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("sign the leaf certificate: %w", err)
	}
	leaf = tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), leaf, nil
}

// serialNumber is 128 random bits.
func serialNumber() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("draw a serial number: %w", err)
	}
	return n, nil
}

// serverTLSConfig serves the leaf at TLS 1.2 or later. net/http adds h2 and
// http/1.1 to its protocols, so a client may speak either.
func serverTLSConfig(leaf tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{leaf},
		MinVersion:   tls.VersionTLS12,
	}
}
