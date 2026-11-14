package kube

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

// readerNotBefore is a notBefore with a fraction of a second, which a
// certificate cannot hold.
var readerNotBefore = time.Date(2026, 11, 14, 9, 0, 0, 500_000_000, time.UTC)

// readerSerial is the 16 bytes the tests' random source yields first.
var readerSerial = bytes.Repeat([]byte{0xA5}, 16)

// readerKey is one key and certificate from NewReaderKey, made once.
var readerKey = sync.OnceValues(func() ([]byte, []byte) {
	keyPEM, certPEM, err := NewReaderKey(io.MultiReader(bytes.NewReader(readerSerial), rand.Reader), readerNotBefore, 365)
	if err != nil {
		panic(err)
	}
	return keyPEM, certPEM
})

// onePEM decodes exactly one PEM block of the type, with nothing after it.
func onePEM(t *testing.T, b []byte, typ string) []byte {
	t.Helper()
	block, rest := pem.Decode(b)
	if block == nil || block.Type != typ || len(block.Headers) != 0 || len(rest) != 0 {
		t.Fatalf("want exactly one %s block and nothing else, got %q", typ, b)
	}
	return block.Bytes
}

func parseReader(t *testing.T, keyPEM, certPEM []byte) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	k, err := x509.ParsePKCS8PrivateKey(onePEM(t, keyPEM, "PRIVATE KEY"))
	if err != nil {
		t.Fatalf("the key is not PKCS#8: %v", err)
	}
	key, ok := k.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("the key is %T, want RSA", k)
	}
	cert, err := x509.ParseCertificate(onePEM(t, certPEM, "CERTIFICATE"))
	if err != nil {
		t.Fatalf("the certificate does not parse: %v", err)
	}
	return key, cert
}

// TestNewReaderKeyIsRSA2048PKCS8: the key is RSA-2048 in PKCS#8 PEM, and the
// certificate carries its public key.
func TestNewReaderKeyIsRSA2048PKCS8(t *testing.T) {
	keyPEM, certPEM := readerKey()
	key, cert := parseReader(t, keyPEM, certPEM)
	if key.N.BitLen() != 2048 {
		t.Errorf("key size = %d bits, want 2048", key.N.BitLen())
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		t.Error("the certificate's public key is not the key's")
	}
	if cert.SignatureAlgorithm != x509.SHA256WithRSA {
		t.Errorf("signature algorithm = %v, want SHA256-RSA", cert.SignatureAlgorithm)
	}
	// CheckSignatureFrom would demand a CA parent; the signature is checked
	// against the certificate's own key directly.
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Errorf("the certificate is not self-signed by the key: %v", err)
	}
}

// TestReaderCertificateIsCNUnusedOnly: the certificate is generic, as Google
// asks: subject and issuer CN=unused and nothing else, no key usage, no
// extended key usage, no extension at all, and a 128-bit serial from rnd.
func TestReaderCertificateIsCNUnusedOnly(t *testing.T) {
	keyPEM, certPEM := readerKey()
	_, cert := parseReader(t, keyPEM, certPEM)
	wantName, err := asn1.Marshal(pkix.Name{CommonName: "unused"}.ToRDNSequence())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cert.RawSubject, wantName) || !bytes.Equal(cert.RawIssuer, wantName) {
		t.Errorf("subject %q, issuer %q; want exactly CN=unused for both", cert.Subject, cert.Issuer)
	}
	if cert.Subject.String() != "CN=unused" {
		t.Errorf("subject = %q", cert.Subject.String())
	}
	if len(cert.Extensions) != 0 {
		var ids []string
		for _, e := range cert.Extensions {
			ids = append(ids, e.Id.String())
		}
		t.Errorf("the certificate carries extensions %s; want none", strings.Join(ids, ", "))
	}
	if cert.KeyUsage != 0 || len(cert.ExtKeyUsage) != 0 || cert.BasicConstraintsValid || cert.IsCA ||
		len(cert.DNSNames)+len(cert.EmailAddresses)+len(cert.IPAddresses)+len(cert.URIs) != 0 {
		t.Errorf("the certificate carries an optional attribute: %+v", cert)
	}
	if want := new(big.Int).SetBytes(readerSerial); cert.SerialNumber.Cmp(want) != 0 {
		t.Errorf("serial = %x, want the 16 bytes rnd gave, %x", cert.SerialNumber, want)
	}
	if cert.SerialNumber.BitLen() > 128 || cert.SerialNumber.Sign() <= 0 {
		t.Errorf("serial %x is not a positive 128-bit number", cert.SerialNumber)
	}
}

// TestReaderCertificateValidityIsDaysFromNotBefore: the certificate is valid
// from notBefore, to the second, for exactly days × 24 hours, at both ends of
// the range.
func TestReaderCertificateValidityIsDaysFromNotBefore(t *testing.T) {
	want := readerNotBefore.Truncate(time.Second)
	keyPEM, certPEM := readerKey()
	_, cert := parseReader(t, keyPEM, certPEM)
	if !cert.NotBefore.Equal(want) || !cert.NotAfter.Equal(want.Add(365*24*time.Hour)) {
		t.Errorf("365 days: valid %v to %v, want %v to %v", cert.NotBefore, cert.NotAfter, want, want.Add(365*24*time.Hour))
	}
	for _, days := range []int{1, 3650} {
		keyPEM, certPEM, err := NewReaderKey(rand.Reader, readerNotBefore.In(time.FixedZone("x", 3600)), days)
		if err != nil {
			t.Fatalf("NewReaderKey(%d days): %v", days, err)
		}
		_, cert := parseReader(t, keyPEM, certPEM)
		if !cert.NotBefore.Equal(want) || !cert.NotAfter.Equal(want.Add(time.Duration(days)*24*time.Hour)) {
			t.Errorf("%d days: valid %v to %v", days, cert.NotBefore, cert.NotAfter)
		}
	}
}

// failingReader fails the test on any read: a refusal must not reach the
// random source, let alone make a key.
type failingReader struct{ t *testing.T }

func (r failingReader) Read([]byte) (int, error) {
	r.t.Error("the random source was read for a refused request")
	return 0, io.ErrUnexpectedEOF
}

// TestNewReaderKeyRefusesOutOfRangeDays: a lifetime outside 1 to 3650 days
// makes nothing; so does a random source that cannot give a serial.
func TestNewReaderKeyRefusesOutOfRangeDays(t *testing.T) {
	for _, days := range []int{0, -1, 3651, 1 << 30} {
		keyPEM, certPEM, err := NewReaderKey(failingReader{t}, readerNotBefore, days)
		if err == nil || keyPEM != nil || certPEM != nil {
			t.Errorf("NewReaderKey(%d days) = %d, %d bytes, %v; want a refusal", days, len(keyPEM), len(certPEM), err)
			continue
		}
		if !strings.Contains(err.Error(), "from 1 to 3650 days") {
			t.Errorf("NewReaderKey(%d days): %q does not name the range", days, err)
		}
	}
	if _, _, err := NewReaderKey(bytes.NewReader(make([]byte, 16)), readerNotBefore, 30); err == nil {
		t.Error("a zero serial was accepted")
	}
	if _, _, err := NewReaderKey(bytes.NewReader(make([]byte, 3)), readerNotBefore, 30); err == nil {
		t.Error("a random source shorter than a serial was accepted")
	}
}
