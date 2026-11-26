package devicekey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"sort"
	"strings"
	"testing"
	"time"
)

// bigOne is the serial number test certificates use where any will do.
func bigOne() *big.Int { return big.NewInt(1) }

// The extension OIDs the profile names.
var (
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtKeyUsage      = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidSubjectKeyID     = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidAuthorityKeyID   = asn1.ObjectIdentifier{2, 5, 29, 35}
)

// wantExtension is one extension a profile carries: its OID, criticality and
// exact DER value.
type wantExtension struct {
	name     string
	id       asn1.ObjectIdentifier
	critical bool
	value    []byte
}

// checkExtensions holds cert to exactly want, in any order. On a failure it
// lists the OIDs it found, as readerkey_test.go does.
func checkExtensions(t *testing.T, cert *x509.Certificate, want []wantExtension) {
	t.Helper()
	var found []string
	for _, e := range cert.Extensions {
		found = append(found, e.Id.String())
	}
	sort.Strings(found)
	if len(cert.Extensions) != len(want) {
		t.Errorf("the certificate carries extensions %s; want exactly %d", strings.Join(found, ", "), len(want))
	}
	for _, w := range want {
		var got *pkix.Extension
		for i := range cert.Extensions {
			if cert.Extensions[i].Id.Equal(w.id) {
				got = &cert.Extensions[i]
			}
		}
		switch {
		case got == nil:
			t.Errorf("no %s extension (%s); the certificate carries %s", w.name, w.id, strings.Join(found, ", "))
		case got.Critical != w.critical:
			t.Errorf("%s critical = %v, want %v", w.name, got.Critical, w.critical)
		case !bytes.Equal(got.Value, w.value):
			t.Errorf("%s value = %x, want %x", w.name, got.Value, w.value)
		}
	}
}

// octetString is v wrapped as an ASN.1 OCTET STRING, an SKID's or the inner
// form of an AKID's key identifier.
func octetString(t *testing.T, v []byte) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// dn is the exact DER of a DN holding only CN=cn.
func dn(t *testing.T, cn string) []byte {
	t.Helper()
	b, err := asn1.Marshal(pkix.Name{CommonName: cn}.ToRDNSequence())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// testAnchor makes an anchor for a new ID at now.
func testAnchor(t *testing.T, now time.Time) (RoleID, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	id, err := NewRoleID(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, key, err := newAnchor(rand.Reader, id, now)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return id, cert, key
}

// testLeaf issues a leaf under anchor at now.
func testLeaf(t *testing.T, anchor *x509.Certificate, anchorKey *ecdsa.PrivateKey, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	der, key, err := issueLeaf(rand.Reader, anchor, opaque{k: anchorKey}, now)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// TestSerialIs128RandomBits: exactly 16 bytes are read, zero is refused, and
// the result is positive.
func TestSerialIs128RandomBits(t *testing.T) {
	src := bytes.NewReader(append(bytes.Repeat([]byte{0xff}, 16), 0x01))
	serial, err := NewSerial(src)
	if err != nil {
		t.Fatal(err)
	}
	if src.Len() != 1 {
		t.Errorf("NewSerial left %d bytes of 17; want exactly 16 read", src.Len())
	}
	if serial.Sign() <= 0 || serial.BitLen() != 128 {
		t.Errorf("serial %x: sign %d, %d bits; want a positive 128-bit number", serial, serial.Sign(), serial.BitLen())
	}
	low := append(make([]byte, 15), 0x07)
	if s, err := NewSerial(bytes.NewReader(low)); err != nil || s.Int64() != 7 {
		t.Errorf("NewSerial of 15 zeros and 7 = %v, %v", s, err)
	}
	if _, err := NewSerial(bytes.NewReader(make([]byte, 16))); err == nil {
		t.Error("a zero serial was accepted")
	}
	if _, err := NewSerial(bytes.NewReader(make([]byte, 15))); err == nil {
		t.Error("a 15-byte draw was accepted")
	}
	if _, err := NewSerial(failingReader{}); err == nil {
		t.Error("a failing reader gave a serial")
	}
}

// TestAnchorProfile: an anchor is exactly D2's anchor.
func TestAnchorProfile(t *testing.T) {
	id, cert, key := testAnchor(t, t0)
	if cert.PublicKeyAlgorithm != x509.ECDSA || cert.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Errorf("algorithms %v / %v, want ECDSA / ECDSA-SHA256", cert.PublicKeyAlgorithm, cert.SignatureAlgorithm)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() || !key.PublicKey.Equal(pub) {
		t.Fatal("the anchor's key is not its P-256 anchor key")
	}
	name := dn(t, id.Hex())
	if !bytes.Equal(cert.RawSubject, name) || !bytes.Equal(cert.RawIssuer, name) {
		t.Errorf("subject %q, issuer %q; want exactly CN=<the role ID> for both", cert.Subject, cert.Issuer)
	}
	skid, err := SubjectKeyID(pub)
	if err != nil {
		t.Fatal(err)
	}
	checkExtensions(t, cert, []wantExtension{
		// SEQUENCE { BOOLEAN TRUE, INTEGER 0 }: CA, path length 0.
		{"basicConstraints", oidBasicConstraints, true, []byte{0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00}},
		// BIT STRING, keyCertSign (bit 5) only.
		{"keyUsage", oidKeyUsage, true, []byte{0x03, 0x02, 0x02, 0x04}},
		// SEQUENCE { id-kp-clientAuth }.
		{"extKeyUsage", oidExtKeyUsage, false, []byte{0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02}},
		{"subjectKeyIdentifier", oidSubjectKeyID, false, octetString(t, skid)},
	})
	if !cert.BasicConstraintsValid || !cert.IsCA || cert.MaxPathLen != 0 || !cert.MaxPathLenZero {
		t.Errorf("basic constraints: valid %v, CA %v, path length %d, zero %v", cert.BasicConstraintsValid, cert.IsCA, cert.MaxPathLen, cert.MaxPathLenZero)
	}
	if cert.KeyUsage != x509.KeyUsageCertSign {
		t.Errorf("key usage = %b, want certSign only", cert.KeyUsage)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(cert.UnknownExtKeyUsage) != 0 {
		t.Errorf("extended key usage = %v %v, want clientAuth only", cert.ExtKeyUsage, cert.UnknownExtKeyUsage)
	}
	if !bytes.Equal(cert.SubjectKeyId, skid) || len(cert.SubjectKeyId) != 20 {
		t.Errorf("SKID = %x, want SubjectKeyID(pub) = %x", cert.SubjectKeyId, skid)
	}
	if len(cert.AuthorityKeyId) != 0 || len(cert.DNSNames)+len(cert.EmailAddresses)+len(cert.IPAddresses)+len(cert.URIs) != 0 ||
		len(cert.OCSPServer)+len(cert.IssuingCertificateURL)+len(cert.CRLDistributionPoints) != 0 ||
		len(cert.PolicyIdentifiers)+len(cert.Policies) != 0 {
		t.Error("the anchor carries an AKID, a SAN, an AIA, a CRL DP or a policy")
	}
	if cert.SerialNumber.Sign() <= 0 || cert.SerialNumber.BitLen() > 128 {
		t.Errorf("serial %x is not a positive 128-bit number", cert.SerialNumber)
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("the self-signature does not verify: %v", err)
	}
}

// TestAnchorSubjectKeyIDIsWhatGoAdds: (a) the SKID the profile sets is the
// one Go adds to a CA by default; (b) with GODEBUG=x509sha256skid=0, under
// which Go adds SHA-1's instead, newAnchor's SKID is still SHA-256's.
//
// The spec runs (b) in a child process, as token_wire_test.go does. This
// build's rules start no process from any new file, so it sets GODEBUG
// in-process instead: the runtime re-reads GODEBUG when it is set (go1.27.4
// src/runtime/runtime.go:204), and the test first shows that the setting
// took, with a CA whose SKID Go then makes from SHA-1.
func TestAnchorSubjectKeyIDIsWhatGoAdds(t *testing.T) {
	id, err := NewRoleID(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := mustKey(t)
	point, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	sha256SKID := sha256.Sum256(point)
	sha1SKID := sha1.Sum(point)
	goAdds := func(t *testing.T) []byte {
		t.Helper()
		tmpl, err := AnchorTemplate(id, bigOne(), NotBefore(t0), &key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.SubjectKeyId = nil
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert.SubjectKeyId
	}

	t.Run("a: the default", func(t *testing.T) {
		t.Setenv("GODEBUG", "")
		want, err := SubjectKeyID(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(want, sha256SKID[:20]) {
			t.Fatalf("SubjectKeyID = %x, want SHA-256's first 20 bytes %x", want, sha256SKID[:20])
		}
		if got := goAdds(t); !bytes.Equal(got, want) {
			t.Errorf("Go adds %x to a CA without a SKID; the profile sets %x", got, want)
		}
	})

	t.Run("b: x509sha256skid=0", func(t *testing.T) {
		t.Setenv("GODEBUG", "x509sha256skid=0")
		if got := goAdds(t); !bytes.Equal(got, sha1SKID[:]) {
			t.Fatalf("with x509sha256skid=0 Go adds %x, not SHA-1's %x: the setting did not take, and the row would prove nothing", got, sha1SKID[:])
		}
		der, _, err := newAnchor(rand.Reader, id, t0)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		point, err := cert.PublicKey.(*ecdsa.PublicKey).Bytes()
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(point)
		if !bytes.Equal(cert.SubjectKeyId, sum[:20]) {
			t.Errorf("under x509sha256skid=0 newAnchor's SKID is %x, not SHA-256's first 20 bytes %x", cert.SubjectKeyId, sum[:20])
		}
	})
}

// TestLeafProfile: a leaf is exactly D2's leaf, and verifies under its anchor
// for client authentication.
func TestLeafProfile(t *testing.T) {
	id, anchor, anchorKey := testAnchor(t, t0)
	leaf, leafKey := testLeaf(t, anchor, anchorKey, t0)
	if leaf.Subject.CommonName != id.Hex() || !bytes.Equal(leaf.RawSubject, dn(t, id.Hex())) {
		t.Errorf("leaf subject %q, want exactly CN=<the role ID>", leaf.Subject)
	}
	if !bytes.Equal(leaf.RawIssuer, anchor.RawSubject) {
		t.Error("the leaf's issuer DN is not the anchor's subject DN, byte for byte")
	}
	if !leafKey.PublicKey.Equal(leaf.PublicKey) || leaf.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Error("the leaf is not its own P-256 key's, signed ECDSA-SHA256")
	}
	checkExtensions(t, leaf, []wantExtension{
		// SEQUENCE {}: not a CA.
		{"basicConstraints", oidBasicConstraints, true, []byte{0x30, 0x00}},
		// BIT STRING, digitalSignature (bit 0) only.
		{"keyUsage", oidKeyUsage, true, []byte{0x03, 0x02, 0x07, 0x80}},
		{"extKeyUsage", oidExtKeyUsage, false, []byte{0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02}},
		// SEQUENCE { [0] keyIdentifier }.
		{"authorityKeyIdentifier", oidAuthorityKeyID, false, append([]byte{0x30, 0x16, 0x80, 0x14}, anchor.SubjectKeyId...)},
	})
	if !leaf.BasicConstraintsValid || leaf.IsCA {
		t.Error("the leaf is a CA, or has no basic constraints")
	}
	if leaf.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("key usage = %b, want digitalSignature only (no keyEncipherment)", leaf.KeyUsage)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("extended key usage = %v, want clientAuth only", leaf.ExtKeyUsage)
	}
	if len(leaf.SubjectKeyId) != 0 {
		t.Error("the leaf carries a SKID")
	}
	if !bytes.Equal(leaf.AuthorityKeyId, anchor.SubjectKeyId) {
		t.Errorf("AKID = %x, want the anchor's SKID %x", leaf.AuthorityKeyId, anchor.SubjectKeyId)
	}
	roots := x509.NewCertPool()
	roots.AddCert(anchor)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: t0}); err != nil {
		t.Errorf("the leaf does not verify under its anchor for client authentication: %v", err)
	}
	if LeafTemplate(RoleID{}, bigOne(), t0, anchor) != nil || LeafTemplate(id, nil, t0, anchor) != nil || LeafTemplate(id, bigOne(), t0, nil) != nil {
		t.Error("LeafTemplate gave a template for a zero ID, a nil serial or a nil anchor")
	}
}

// TestAnchorValidityIsExactly390Days: NotBefore is now − 1 h, in UTC, to the
// whole second, and NotAfter is exactly 390 days later.
func TestAnchorValidityIsExactly390Days(t *testing.T) {
	now := time.Date(2026, 11, 22, 10, 11, 12, 987654321, time.FixedZone("UTC+5:30", 5*3600+1800))
	want := time.Date(2026, 11, 22, 3, 41, 12, 0, time.UTC)
	nb := NotBefore(now)
	if !nb.Equal(want) || nb.Location() != time.UTC || nb.Nanosecond() != 0 {
		t.Errorf("NotBefore(%v) = %v, want %v in UTC", now, nb, want)
	}
	_, cert, _ := testAnchor(t, now)
	if !cert.NotBefore.Equal(want) {
		t.Errorf("the anchor's NotBefore = %v, want %v", cert.NotBefore, want)
	}
	if d := cert.NotAfter.Sub(cert.NotBefore); d != 390*24*time.Hour {
		t.Errorf("NotAfter − NotBefore = %v, want exactly 390 × 24 h", d)
	}
	key := mustKey(t)
	id, err := NewRoleID(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := AnchorTemplate(id, bigOne(), nb, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !tmpl.NotBefore.Equal(want) || tmpl.NotAfter.Sub(tmpl.NotBefore) != AnchorLifetime {
		t.Errorf("AnchorTemplate's validity is %v to %v", tmpl.NotBefore, tmpl.NotAfter)
	}
}

// TestLeafValidityIs90DaysOrTheAnchorsEnd: a leaf lasts 90 days under a fresh
// anchor, and ends with its anchor when that is sooner.
func TestLeafValidityIs90DaysOrTheAnchorsEnd(t *testing.T) {
	_, anchor, anchorKey := testAnchor(t, t0)
	leaf, _ := testLeaf(t, anchor, anchorKey, t0)
	if d := leaf.NotAfter.Sub(leaf.NotBefore); d != 90*24*time.Hour {
		t.Errorf("a leaf under a fresh anchor lasts %v, want exactly 90 days", d)
	}
	if !leaf.NotBefore.Equal(NotBefore(t0)) {
		t.Errorf("the leaf's NotBefore = %v, want %v", leaf.NotBefore, NotBefore(t0))
	}
	late := t0.Add(350 * 24 * time.Hour)
	capped, _ := testLeaf(t, anchor, anchorKey, late)
	if !capped.NotAfter.Equal(anchor.NotAfter) {
		t.Errorf("a leaf issued 40 days before its anchor's end ends %v; want the anchor's end %v", capped.NotAfter, anchor.NotAfter)
	}
	if !capped.NotBefore.Equal(NotBefore(late)) {
		t.Errorf("the capped leaf's NotBefore = %v", capped.NotBefore)
	}
}

// TestLeafDueAtHalfLife: a leaf is due from half its life, when expired, and
// when its anchor did not issue it.
func TestLeafDueAtHalfLife(t *testing.T) {
	id, anchor, anchorKey := testAnchor(t, t0)
	leaf, _ := testLeaf(t, anchor, anchorKey, t0)
	half := leaf.NotBefore.Add(LeafLifetime / 2)
	if LeafDue(leaf, anchor, half.Add(-time.Second)) {
		t.Error("due one second before half its life")
	}
	if !LeafDue(leaf, anchor, half) {
		t.Error("not due at half its life")
	}
	if !LeafDue(leaf, anchor, leaf.NotAfter.Add(time.Second)) {
		t.Error("not due once expired")
	}
	if LeafDue(leaf, anchor, t0) {
		t.Error("due when new")
	}

	// An AKID that is not the anchor's, with a good signature.
	leafKey := mustKey(t)
	tmpl := LeafTemplate(id, bigOne(), NotBefore(t0), anchor)
	tmpl.AuthorityKeyId = bytes.Repeat([]byte{0x5a}, 20)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, anchor, &leafKey.PublicKey, anchorKey)
	if err != nil {
		t.Fatal(err)
	}
	wrongAKID, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if wrongAKID.CheckSignatureFrom(anchor) != nil {
		t.Fatal("the fixture's signature does not verify")
	}
	if !LeafDue(wrongAKID, anchor, t0) {
		t.Error("not due with an AKID that is not the anchor's")
	}

	// The anchor's AKID, with a signature another anchor of the same ID made:
	// that is, the anchor was replaced under the leaf.
	otherDER, otherKey, err := newAnchor(rand.Reader, id, t0)
	if err != nil {
		t.Fatal(err)
	}
	other, err := x509.ParseCertificate(otherDER)
	if err != nil {
		t.Fatal(err)
	}
	tmpl = LeafTemplate(id, bigOne(), NotBefore(t0), anchor) // AKID: the first anchor's
	der, err = x509.CreateCertificate(rand.Reader, tmpl, other, &leafKey.PublicKey, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	wrongSignature, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wrongSignature.AuthorityKeyId, anchor.SubjectKeyId) {
		t.Fatal("the fixture's AKID is not the anchor's")
	}
	if !LeafDue(wrongSignature, anchor, t0) {
		t.Error("not due with a signature the anchor did not make")
	}
	if !LeafDue(leaf, other, t0) {
		t.Error("not due under a replaced anchor")
	}
	if !LeafDue(nil, anchor, t0) || !LeafDue(leaf, nil, t0) {
		t.Error("a nil leaf or anchor is not due")
	}
}

// TestAnchorWarnsFrom45DaysBeforeItsEnd: the boundary, either side.
func TestAnchorWarnsFrom45DaysBeforeItsEnd(t *testing.T) {
	_, anchor, _ := testAnchor(t, t0)
	edge := anchor.NotAfter.Add(-45 * 24 * time.Hour)
	if AnchorWarns(anchor, edge.Add(-time.Second)) {
		t.Error("warns one second before 45 days from its end")
	}
	if !AnchorWarns(anchor, edge) || !AnchorWarns(anchor, anchor.NotAfter.Add(time.Hour)) {
		t.Error("does not warn at 45 days from its end, or past it")
	}
	if AnchorWarns(anchor, t0) {
		t.Error("warns when new")
	}
}

// TestAnchorWarnsAtAndExpiredAt: from a NotAfter alone, as a command reads it
// from the record (CurrentCertificates), AnchorWarnsAt warns exactly when
// AnchorWarns does, and AnchorExpiredAt holds exactly when the openers refuse
// the anchor: not at its NotAfter, and from a nanosecond after it. A zero
// NotAfter, which names no anchor, warns and has ended.
func TestAnchorWarnsAtAndExpiredAt(t *testing.T) {
	s, _, _ := enrolBoth(t)
	c, err := s.CurrentCertificates(Reader)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := x509.ParseCertificate(c.AnchorDER())
	if err != nil {
		t.Fatal(err)
	}
	notAfter := c.AnchorNotAfter()
	edge := notAfter.Add(-AnchorWarning)
	for _, now := range []time.Time{t0, edge.Add(-time.Nanosecond), edge, notAfter, notAfter.Add(time.Nanosecond)} {
		if AnchorWarnsAt(notAfter, now) != AnchorWarns(anchor, now) {
			t.Errorf("at %v AnchorWarnsAt and AnchorWarns differ", now)
		}
	}
	if AnchorWarnsAt(notAfter, edge.Add(-time.Nanosecond)) || !AnchorWarnsAt(notAfter, edge) {
		t.Error("AnchorWarnsAt's boundary is not 45 days before NotAfter, inclusive")
	}
	if AnchorExpiredAt(notAfter, notAfter) || !AnchorExpiredAt(notAfter, notAfter.Add(time.Nanosecond)) {
		t.Error("AnchorExpiredAt's boundary is not just after NotAfter")
	}
	if AnchorExpiredAt(notAfter, t0) {
		t.Error("AnchorExpiredAt holds for a new anchor")
	}
	// The openers agree at both instants.
	if _, err := s.OpenForRead(rand.Reader, notAfter); err != nil {
		t.Errorf("OpenForRead at the anchor's NotAfter: %v", err)
	}
	if _, err := s.OpenForRead(rand.Reader, notAfter.Add(time.Nanosecond)); !errors.Is(err, ErrAnchorExpired) {
		t.Errorf("OpenForRead just after the anchor's NotAfter: err = %v, want ErrAnchorExpired", err)
	}
	if !AnchorWarnsAt(time.Time{}, t0) || !AnchorExpiredAt(time.Time{}, t0) {
		t.Error("a zero NotAfter neither warns nor has ended")
	}
}

// TestProfileRefusesBadArguments: the profile's constructors refuse what
// would make another profile, before reading their random source.
func TestProfileRefusesBadArguments(t *testing.T) {
	id, err := NewRoleID(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := mustKey(t)
	if _, err := AnchorTemplate(RoleID{}, bigOne(), t0, &key.PublicKey); err == nil {
		t.Error("an anchor template with a zero ID")
	}
	if _, err := AnchorTemplate(id, big.NewInt(0), t0, &key.PublicKey); err == nil {
		t.Error("an anchor template with a zero serial")
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SubjectKeyID(&p384.PublicKey); err == nil {
		t.Error("a SKID from a P-384 key")
	}
	cr := &countingReader{}
	if _, _, err := newAnchor(cr, RoleID{}, t0); err == nil || cr.reads != 0 {
		t.Errorf("newAnchor with a zero ID: err = %v after %d reads; want a refusal before any read", err, cr.reads)
	}
	_, anchor, anchorKey := testAnchor(t, t0)
	if _, _, err := issueLeaf(cr, nil, opaque{k: anchorKey}, t0); err == nil || cr.reads != 0 {
		t.Errorf("issueLeaf with no anchor: err = %v after %d reads", err, cr.reads)
	}
	if _, _, err := issueLeaf(cr, anchor, nil, t0); err == nil || cr.reads != 0 {
		t.Errorf("issueLeaf with no anchor key: err = %v after %d reads", err, cr.reads)
	}
	if _, _, err := newAnchor(failingReader{}, id, t0); err == nil {
		t.Error("newAnchor with a failing random source")
	}
}

// countingReader counts its reads, and fails each.
type countingReader struct{ reads int }

func (c *countingReader) Read([]byte) (int, error) {
	c.reads++
	return 0, errors.New("the random source was read")
}
