package devicekey

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"
)

// The profile's lifetimes (D2).
const (
	// AnchorLifetime is an anchor's validity: [X509]'s 390-day maximum.
	AnchorLifetime = 390 * 24 * time.Hour
	// LeafLifetime is a leaf's validity, capped at its anchor's end.
	LeafLifetime = 90 * 24 * time.Hour
	// Backdate is how far NotBefore is set back from now.
	Backdate = time.Hour
	// AnchorWarning is how long before an anchor's end AnchorWarns holds.
	AnchorWarning = 45 * 24 * time.Hour
)

// serialLen is a serial number's length in bytes: 128 bits.
const serialLen = 16

// NotBefore is now, in UTC, one hour back, truncated to the second (D2;
// readerinit.go:209's precedent).
func NotBefore(now time.Time) time.Time {
	return now.Add(-Backdate).UTC().Truncate(time.Second)
}

// NewSerial reads exactly 16 bytes from rnd and refuses zero: 128 random bits.
func NewSerial(rnd io.Reader) (*big.Int, error) {
	if rnd == nil {
		return nil, errors.New("devicekey: a serial number needs a random source")
	}
	var b [serialLen]byte
	if _, err := io.ReadFull(rnd, b[:]); err != nil {
		return nil, fmt.Errorf("devicekey: draw a serial number: %w", err)
	}
	serial := new(big.Int).SetBytes(b[:])
	if serial.Sign() == 0 {
		return nil, errors.New("devicekey: the random source gave a zero serial number")
	}
	return serial, nil
}

// SubjectKeyID is the first 20 bytes of SHA-256 of pub.Bytes(), the P-256
// point's uncompressed encoding. That is what Go's crypto/x509 adds to a CA by
// default (go1.27.4 src/crypto/x509/x509.go:1875-1892, RFC 7093 method 1)
// [read]. It is set explicitly, so GODEBUG=x509sha256skid=0 cannot change the
// profile. It uses no deprecated field.
func SubjectKeyID(pub *ecdsa.PublicKey) ([]byte, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return nil, errors.New("devicekey: a subject key identifier is made from a P-256 public key only")
	}
	point, err := pub.Bytes()
	if err != nil {
		return nil, fmt.Errorf("devicekey: encode the public key: %w", err)
	}
	sum := sha256.Sum256(point)
	return sum[:20], nil
}

// AnchorTemplate is D2's anchor template.
//
//   - SerialNumber: serial (128 random bits);
//   - Subject: pkix.Name{CommonName: id.Hex()}, nothing else; the template is
//     its own parent;
//   - NotBefore: notBefore (callers pass NotBefore(now)); NotAfter:
//     notBefore.Add(AnchorLifetime);
//   - BasicConstraintsValid and IsCA, with MaxPathLen 0 and MaxPathLenZero;
//   - KeyUsage: x509.KeyUsageCertSign only; ExtKeyUsage: ClientAuth only;
//   - SubjectKeyId: SubjectKeyID(pub); no AuthorityKeyId;
//   - nothing else: no O, OU, SAN, policy, AIA, CRL DP or ExtraExtensions.
func AnchorTemplate(id RoleID, serial *big.Int, notBefore time.Time, pub *ecdsa.PublicKey) (*x509.Certificate, error) {
	if id.IsZero() {
		return nil, errors.New("devicekey: an anchor needs a role ID")
	}
	if serial == nil || serial.Sign() <= 0 {
		return nil, errors.New("devicekey: an anchor needs a positive serial number")
	}
	skid, err := SubjectKeyID(pub)
	if err != nil {
		return nil, err
	}
	return &x509.Certificate{
		SerialNumber:          new(big.Int).Set(serial),
		Subject:               pkix.Name{CommonName: id.Hex()},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(AnchorLifetime),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		SubjectKeyId:          skid,
	}, nil
}

// LeafTemplate is D2's leaf template under anchor, for id. M3a's probe passes
// another device's or role's ID, to make a negative that differs from a
// positive in its CN alone.
//
//   - SerialNumber: serial;
//   - Subject: pkix.Name{CommonName: id.Hex()}, nothing else;
//   - NotBefore: notBefore; NotAfter: min(notBefore.Add(LeafLifetime),
//     anchor.NotAfter);
//   - BasicConstraintsValid, not a CA;
//   - KeyUsage: x509.KeyUsageDigitalSignature only; ExtKeyUsage: ClientAuth
//     only;
//   - no SubjectKeyId; AuthorityKeyId: anchor.SubjectKeyId, set explicitly;
//   - nothing else.
//
// It is nil when id is zero, serial is not positive, or anchor is nil.
func LeafTemplate(id RoleID, serial *big.Int, notBefore time.Time, anchor *x509.Certificate) *x509.Certificate {
	if id.IsZero() || serial == nil || serial.Sign() <= 0 || anchor == nil {
		return nil
	}
	notAfter := notBefore.Add(LeafLifetime)
	if anchor.NotAfter.Before(notAfter) {
		notAfter = anchor.NotAfter
	}
	return &x509.Certificate{
		SerialNumber:          new(big.Int).Set(serial),
		Subject:               pkix.Name{CommonName: id.Hex()},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		AuthorityKeyId:        bytes.Clone(anchor.SubjectKeyId),
	}
}

// LeafDue reports whether a leaf must be renewed at now. It is due:
//   - at or after half its life, NotBefore + (NotAfter − NotBefore)/2;
//   - past its end;
//   - when anchor did not issue it: its signature does not verify under
//     anchor, or its authority key identifier is not anchor's subject key
//     identifier.
//
// A nil leaf or anchor is due.
func LeafDue(leaf, anchor *x509.Certificate, now time.Time) bool {
	if leaf == nil || anchor == nil {
		return true
	}
	half := leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2)
	if !now.Before(half) || now.After(leaf.NotAfter) {
		return true
	}
	if len(anchor.SubjectKeyId) == 0 || !bytes.Equal(leaf.AuthorityKeyId, anchor.SubjectKeyId) {
		return true
	}
	return leaf.CheckSignatureFrom(anchor) != nil
}

// AnchorWarns reports whether now is at or after anchor's NotAfter − 45 days.
// A nil anchor warns. It is AnchorWarnsAt of the anchor's NotAfter.
func AnchorWarns(anchor *x509.Certificate, now time.Time) bool {
	if anchor == nil {
		return true
	}
	return AnchorWarnsAt(anchor.NotAfter, now)
}

// AnchorWarnsAt reports whether now is at or after notAfter − 45 days
// (AnchorWarning), for an anchor whose NotAfter is notAfter: what a command
// reads from the record's AnchorNotAfter (CurrentCertificates), with no
// certificate at hand. A zero notAfter, which names no anchor, is the year 1,
// so it warns.
func AnchorWarnsAt(notAfter, now time.Time) bool {
	return !now.Before(notAfter.Add(-AnchorWarning))
}

// AnchorExpiredAt reports whether an anchor whose NotAfter is notAfter has
// ended at now: strictly after notAfter, the instant at which the openers
// refuse it (ErrAnchorExpired). At notAfter itself it has not. A zero
// notAfter, which names no anchor, is the year 1, so it has ended.
func AnchorExpiredAt(notAfter, now time.Time) bool {
	return now.After(notAfter)
}

// anchorExpired reports whether anchor's validity has ended at now.
func anchorExpired(anchor *x509.Certificate, now time.Time) bool {
	return AnchorExpiredAt(anchor.NotAfter, now)
}

// newKey makes a P-256 key. Since Go 1.26 key generation draws on the
// system's secure source whatever reader is passed, so it is given
// crypto/rand's; the caller's rnd supplies serials and IDs only
// (kube/readerkey.go:36-37).
func newKey() (*ecdsa.PrivateKey, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("devicekey: make a P-256 key: %w", err)
	}
	return k, nil
}

// newAnchor makes a new anchor key and the anchor for id at now: a serial
// from rnd, NotBefore(now), and AnchorTemplate, self-signed. The arguments are
// checked before rnd is read, so a refused call reads nothing.
func newAnchor(rnd io.Reader, id RoleID, now time.Time) (der []byte, key *ecdsa.PrivateKey, err error) {
	if id.IsZero() {
		return nil, nil, errors.New("devicekey: an anchor needs a role ID")
	}
	if rnd == nil {
		return nil, nil, errors.New("devicekey: an anchor needs a random source")
	}
	serial, err := NewSerial(rnd)
	if err != nil {
		return nil, nil, err
	}
	key, err = newKey()
	if err != nil {
		return nil, nil, err
	}
	template, err := AnchorTemplate(id, serial, NotBefore(now), &key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	der, err = x509.CreateCertificate(rnd, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("devicekey: sign the anchor: %w", err)
	}
	return der, key, nil
}

// issueLeaf makes a new leaf key and a leaf under anchor at now, signed with
// anchorKey: a serial from rnd, NotBefore(now), and LeafTemplate for the
// anchor's own role ID. The arguments are checked before rnd is read. It does
// not judge the anchor's validity; its callers refuse an expired anchor first.
func issueLeaf(rnd io.Reader, anchor *x509.Certificate, anchorKey crypto.Signer, now time.Time) (der []byte, key *ecdsa.PrivateKey, err error) {
	if anchor == nil || anchorKey == nil {
		return nil, nil, errors.New("devicekey: a leaf needs its anchor and the anchor's key")
	}
	if rnd == nil {
		return nil, nil, errors.New("devicekey: a leaf needs a random source")
	}
	id, err := ParseRoleID(anchor.Subject.CommonName)
	if err != nil {
		return nil, nil, fmt.Errorf("devicekey: the anchor's common name is not a role ID: %w", ErrInconsistent)
	}
	serial, err := NewSerial(rnd)
	if err != nil {
		return nil, nil, err
	}
	key, err = newKey()
	if err != nil {
		return nil, nil, err
	}
	template := LeafTemplate(id, serial, NotBefore(now), anchor)
	der, err = x509.CreateCertificate(rnd, template, anchor, &key.PublicKey, anchorKey)
	if err != nil {
		return nil, nil, fmt.Errorf("devicekey: sign the leaf: %w", err)
	}
	return der, key, nil
}
