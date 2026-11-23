package devicekey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// The conformance vectors pin §1.4's templates byte for byte, for M5's Swift
// builder (ADR 0020:159-164), in fatline/internal/crypto/vectors_test.go's
// manner: every key is derived inside the test from a label, so no private
// key is committed, and each vector holds only public values and the
// to-be-signed bytes, which do not depend on the signature's randomness.

// anchorVector is testdata/anchor-tbs.json.
type anchorVector struct {
	KeyLabel  string `json:"keyLabel"`
	Point     string `json:"point"`
	Serial    string `json:"serial"`
	NotBefore string `json:"notBefore"`
	ID        string `json:"id"`
	TBS       string `json:"tbs"`
}

// leafVector is testdata/leaf-tbs.json.
type leafVector struct {
	KeyLabel       string `json:"keyLabel"`
	Point          string `json:"point"`
	Serial         string `json:"serial"`
	NotBefore      string `json:"notBefore"`
	ID             string `json:"id"`
	AnchorSKID     string `json:"anchorSKID"`
	AnchorNotAfter string `json:"anchorNotAfter"`
	TBS            string `json:"tbs"`
}

// vectorKey derives a P-256 key from label: d is SHA-256 of
// "devicekey-vector-key/<label>/<i>" for the first i the curve accepts.
func vectorKey(label string) *ecdsa.PrivateKey {
	for i := 0; ; i++ {
		d := sha256.Sum256([]byte("devicekey-vector-key/" + label + "/" + strconv.Itoa(i)))
		if k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d[:]); err == nil {
			return k
		}
	}
}

// readVector decodes testdata/name into v, refusing unknown fields.
func readVector(t *testing.T, name string, v any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

// vectorPoint checks that label's derived key has the vector's point.
func vectorPoint(t *testing.T, label, point string) *ecdsa.PrivateKey {
	t.Helper()
	key := vectorKey(label)
	got, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != point {
		t.Fatalf("the %q key's point is %x; the vector says %s", label, got, point)
	}
	return key
}

// vectorSerial parses a vector's 32-hex serial.
func vectorSerial(t *testing.T, s string) *big.Int {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 16 {
		t.Fatalf("serial %q is not 16 bytes of hex", s)
	}
	return new(big.Int).SetBytes(b)
}

// vectorTime parses a vector's RFC 3339 time, whole seconds, Z.
func vectorTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil || v.Nanosecond() != 0 || v.Format(time.RFC3339) != s || s[len(s)-1] != 'Z' {
		t.Fatalf("time %q is not RFC 3339 to the whole second in Z", s)
	}
	return v
}

// vectorAnchor builds and signs the anchor vector's certificate.
func vectorAnchor(t *testing.T, v anchorVector) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key := vectorPoint(t, v.KeyLabel, v.Point)
	id, err := ParseRoleID(v.ID)
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := AnchorTemplate(id, vectorSerial(t, v.Serial), vectorTime(t, v.NotBefore), &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// compareTBS fails with the computed TBS, all public, so a builder can fill
// the vector in the first time.
func compareTBS(t *testing.T, name string, cert *x509.Certificate, want string) {
	t.Helper()
	if got := hex.EncodeToString(cert.RawTBSCertificate); got != want {
		t.Errorf("%s's TBS differs from its vector; computed:\n%s", name, got)
	}
}

// TestAnchorTBSMatchesItsVector: AnchorTemplate, signed, gives the vector's
// to-be-signed bytes exactly, under the default GODEBUG and under
// x509sha256skid=0, with which a subject key identifier left to Go would be
// SHA-1's and the bytes would differ.
func TestAnchorTBSMatchesItsVector(t *testing.T) {
	var v anchorVector
	readVector(t, "anchor-tbs.json", &v)
	if v.KeyLabel != "anchor" {
		t.Fatalf("keyLabel = %q", v.KeyLabel)
	}
	for _, godebug := range []string{"", "x509sha256skid=0"} {
		t.Run("GODEBUG="+godebug, func(t *testing.T) {
			t.Setenv("GODEBUG", godebug)
			cert, _ := vectorAnchor(t, v)
			compareTBS(t, "the anchor", cert, v.TBS)
		})
	}
}

// TestLeafTBSMatchesItsVector: LeafTemplate under the anchor vector's
// certificate, signed with the anchor's key, gives the vector's to-be-signed
// bytes exactly.
func TestLeafTBSMatchesItsVector(t *testing.T) {
	var av anchorVector
	readVector(t, "anchor-tbs.json", &av)
	anchor, anchorKey := vectorAnchor(t, av)
	var v leafVector
	readVector(t, "leaf-tbs.json", &v)
	if v.KeyLabel != "leaf" {
		t.Fatalf("keyLabel = %q", v.KeyLabel)
	}
	if got := hex.EncodeToString(anchor.SubjectKeyId); got != v.AnchorSKID {
		t.Errorf("the anchor's SKID is %s; the leaf vector says %s", got, v.AnchorSKID)
	}
	if got := anchor.NotAfter.Format(time.RFC3339); got != v.AnchorNotAfter {
		t.Errorf("the anchor's NotAfter is %s; the leaf vector says %s", got, v.AnchorNotAfter)
	}
	key := vectorPoint(t, v.KeyLabel, v.Point)
	id, err := ParseRoleID(v.ID)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := LeafTemplate(id, vectorSerial(t, v.Serial), vectorTime(t, v.NotBefore), anchor)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, anchor, &key.PublicKey, anchorKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	compareTBS(t, "the leaf", cert, v.TBS)
	if err := cert.CheckSignatureFrom(anchor); err != nil {
		t.Errorf("the vector's leaf does not verify under the vector's anchor: %v", err)
	}
}
