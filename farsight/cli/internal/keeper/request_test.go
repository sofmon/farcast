package keeper

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/fatline/identity"
)

// B-T1. A key is made only once the directory has passed its rules: a synced
// folder, and a platform that cannot exclude it from backup (unless forced),
// are refused with no key generated at all — not merely none written, which a
// key made in memory and dropped would also satisfy. Not parallel: it swaps a
// package variable.
func TestRequestPreparesTheDirectoryBeforeTheKey(t *testing.T) {
	calls := 0
	original := generateKey
	generateKey = func() (*ecdsa.PrivateKey, error) {
		calls++
		return original()
	}
	defer func() { generateKey = original }()

	// A synced folder: refused, not overridable.
	synced := filepath.Join(t.TempDir(), "Dropbox", "farcast", "keepers", "prod")
	if _, _, err := NewRequest(synced, "prod", true, false, time.Now()); err == nil || !strings.Contains(err.Error(), "Dropbox") {
		t.Errorf("NewRequest in a synced folder = %v; want it refused naming the sync root", err)
	}
	if calls != 0 {
		t.Errorf("a key was generated %d time(s) for a synced folder", calls)
	}
	absent(t, synced, requestKeyFile, requestRecordFile)

	// No verifiable backup exclusion: refused unless forced.
	exclude := excludeFromBackup
	excludeFromBackup = func(string) error { return errors.New("no exclusion here") }
	defer func() { excludeFromBackup = exclude }()
	dir := filepath.Join(t.TempDir(), "prod")
	if _, _, err := NewRequest(dir, "prod", false, false, time.Now()); err == nil || !strings.Contains(err.Error(), "--accept-backup-risk") {
		t.Errorf("NewRequest without an exclusion = %v; want install's refusal", err)
	}
	if calls != 0 {
		t.Errorf("a key was generated %d time(s) for a directory the backup pipeline may copy", calls)
	}
	absent(t, dir, requestKeyFile, requestRecordFile)

	// Forced: one key, recorded as what the platform managed.
	now := time.Date(2026, 11, 13, 9, 30, 0, 0, time.UTC)
	rec, gen, err := NewRequest(dir, "prod", true, false, now)
	if err != nil {
		t.Fatalf("forced NewRequest: %v", err)
	}
	if calls != 1 {
		t.Errorf("generateKey called %d times; want 1", calls)
	}
	if rec.BackupExcluded || rec.BackupNote != "no exclusion here" || rec.KeyStore != KeyStoreFile ||
		rec.Instance != "prod" || !rec.CreatedAt.Equal(now) || rec.Version != requestVersion {
		t.Errorf("record = %+v", rec)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != dirMode {
		t.Errorf("dir: %v, %v; want mode %v", fi, err, os.FileMode(dirMode))
	}
	for _, f := range []string{requestKeyFile, requestRecordFile} {
		if fi, err := os.Stat(filepath.Join(dir, f)); err != nil || fi.Mode().Perm() != fileMode {
			t.Errorf("%s: %v, %v; want mode %v", f, fi, err, os.FileMode(fileMode))
		}
	}
	parsed, err := identity.ParseRequest(gen.RequestPEM)
	if err != nil {
		t.Fatalf("the request does not pass enrolment's checks: %v", err)
	}
	keyFP, err := heldKeyFingerprint(dir, requestKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.KeySHA256 != keyFP || rec.KeySHA256 != keyFP || gen.KeySHA256 != keyFP || !bytes.Equal(parsed.DER, gen.RequestDER) {
		t.Errorf("fingerprints: request %s, record %s, generated %s, key file %s", parsed.KeySHA256, rec.KeySHA256, gen.KeySHA256, keyFP)
	}
	// The record holds no key material, and the request no secret.
	if raw := readFile(t, filepath.Join(dir, requestRecordFile)); bytes.Contains(raw, []byte("PRIVATE")) || !bytes.Contains(raw, []byte("key_sha256: "+keyFP)) {
		t.Errorf("request.yaml:\n%s", raw)
	}
	if bytes.Contains(gen.RequestPEM, []byte("PRIVATE")) {
		t.Error("the request carries a private key")
	}
	// The request is the minimal template: an empty subject, no attributes.
	csr, err := x509.ParseCertificateRequest(gen.RequestDER)
	if err != nil {
		t.Fatal(err)
	}
	// version 0, an empty subject, a P-256 SPKI, and an empty attribute set.
	tbs := csr.RawTBSCertificateRequest
	if !bytes.HasPrefix(tbs[2:], []byte{0x02, 0x01, 0x00, 0x30, 0x00, 0x30, 0x59}) || !bytes.HasSuffix(tbs, []byte{0xa0, 0x00}) ||
		len(csr.Subject.Names) != 0 || len(csr.Extensions) != 0 {
		t.Errorf("the request is not the minimal template: %x", tbs)
	}
	// And an instance name that could leave the keepers directory makes
	// nothing either.
	if _, _, err := NewRequest(filepath.Join(t.TempDir(), "x"), "../x", true, false, now); err == nil || calls != 1 {
		t.Errorf("NewRequest for ../x = %v (generateKey calls %d)", err, calls)
	}
}

// B-T2. One pending request per device and instance: a second is refused
// unless it replaces the first, and a replacement is a new key.
func TestRequestRefusesAPendingOneUnlessReplaced(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "prod")
	first := request(t, dir)
	key := readFile(t, filepath.Join(dir, requestKeyFile))
	rec := readFile(t, filepath.Join(dir, requestRecordFile))
	if _, _, err := NewRequest(dir, "prod", true, false, time.Now()); !errors.Is(err, ErrPendingRequest) {
		t.Fatalf("a second NewRequest = %v; want ErrPendingRequest", err)
	}
	if !bytes.Equal(readFile(t, filepath.Join(dir, requestKeyFile)), key) || !bytes.Equal(readFile(t, filepath.Join(dir, requestRecordFile)), rec) {
		t.Fatal("a refused request changed the pending one")
	}
	r, gen, err := NewRequest(dir, "prod", true, true, time.Now())
	if err != nil {
		t.Fatalf("NewRequest with replace: %v", err)
	}
	if gen.KeySHA256 == first.KeySHA256 || r.KeySHA256 != gen.KeySHA256 {
		t.Errorf("the replacement kept the key: %s, %s", first.KeySHA256, gen.KeySHA256)
	}
	if pending, err := PendingRequest(dir); err != nil || pending == nil || pending.KeySHA256 != gen.KeySHA256 {
		t.Errorf("PendingRequest after replace = %+v, %v", pending, err)
	}
	if fp, err := heldKeyFingerprint(dir, requestKeyFile); err != nil || fp != gen.KeySHA256 {
		t.Errorf("request.key after replace = %s, %v; want the new key", fp, err)
	}
}

// testCA is a CA built here with x509.CreateCertificate, so a test can issue
// a leaf for a request's key with any usage and validity: what an install
// must refuse, and what it must accept although no FarCast issuer makes it.
type testCA struct {
	key     *ecdsa.PrivateKey
	cert    *x509.Certificate
	certPEM []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "FarCast Instance CA: prod"},
		NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{key: key, cert: cert, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca *testCA) issue(t *testing.T, requestDER []byte, eku []x509.ExtKeyUsage, notBefore, notAfter time.Time) []byte {
	t.Helper()
	csr, err := x509.ParseCertificateRequest(requestDER)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse(identity.KeeperURI("prod", "study-desktop"))
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: uri.String()},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: eku, BasicConstraintsValid: true, URIs: []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
