package kube

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"time"
)

// The reader certificate's bounds (§7.2): `reader init --days N`, default 365,
// from 1 to 3650.
const (
	readerKeyBits    = 2048
	readerMinDays    = 1
	readerMaxDays    = 3650
	readerCommonName = "unused"
)

// NewReaderKey makes the reader identity's key and the certificate the human
// uploads for it in Cloud Shell (§7.2):
//   - an RSA-2048 key, because the 2LO assertion is always RS256, as PKCS#8 PEM;
//   - a self-signed X.509 certificate whose template sets only SerialNumber
//     (128 random bits from rnd), Subject CN=unused, NotBefore and NotAfter =
//     NotBefore + days × 24 h. No key usage, no extended key usage and no
//     other attribute: Google asks for "a generic subject" and no optional
//     attributes, so the certificate names neither the instance nor the
//     account.
//
// The key expires with its certificate. notBefore is truncated to the second,
// which is all a certificate's validity holds; days must be from 1 to 3650.
//
// Since Go 1.26 the key and the signature draw on the system's secure source
// whatever rnd is; rnd still supplies the serial number.
func NewReaderKey(rnd io.Reader, notBefore time.Time, days int) (keyPEM, certPEM []byte, err error) {
	if days < readerMinDays || days > readerMaxDays {
		return nil, nil, fmt.Errorf("kube: a reader certificate lasts from %d to %d days, not %d", readerMinDays, readerMaxDays, days)
	}
	var serialBytes [16]byte
	if _, err := io.ReadFull(rnd, serialBytes[:]); err != nil {
		return nil, nil, fmt.Errorf("kube: read the reader certificate's serial number: %w", err)
	}
	serial := new(big.Int).SetBytes(serialBytes[:])
	if serial.Sign() == 0 {
		return nil, nil, fmt.Errorf("kube: the random source gave a zero serial number")
	}
	key, err := rsa.GenerateKey(rnd, readerKeyBits)
	if err != nil {
		return nil, nil, fmt.Errorf("kube: make the reader key: %w", err)
	}
	nb := notBefore.UTC().Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: readerCommonName},
		NotBefore:    nb,
		NotAfter:     nb.Add(time.Duration(days) * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rnd, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("kube: make the reader certificate: %w", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("kube: encode the reader key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return keyPEM, certPEM, nil
}
