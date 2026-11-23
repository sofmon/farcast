package cli

// The M3a probe's chains (ADR 0024 M3a; design §6; the runbook is
// docs/runbooks/adr-0024-m3a-probe.md). The probe itself is walkm3a_test.go,
// behind the walk tag. What it sends is built here, untagged and pure, so
// that the ordinary test run checks it: the four
// chain shapes, the variant and negative certificates, I5's audience, and V5's
// ES256 JWT and JWKS. Everything a certificate here carries is public; the
// keys these functions make stay in memory, or are written by the probe as
// 0600 PKCS#8 files under its own walk directory.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/devicekey"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
)

// m3aShape is one of T1's four chain shapes: what the TLS handshake carries,
// and what subject_token carries.
type m3aShape int

const (
	m3aS1 m3aShape = 1 + iota // TLS [leaf] / subject [leaf]
	m3aS2                     // TLS [leaf] / subject [leaf, anchor]
	m3aS3                     // TLS [leaf, anchor] / subject [leaf]
	m3aS4                     // TLS [leaf, anchor] / subject [leaf, anchor]
)

// m3aShapes are the four, simplest first: the order t1 tries them in and
// m3aSimplest reads them in.
var m3aShapes = [4]m3aShape{m3aS1, m3aS2, m3aS3, m3aS4}

// String is "S1" to "S4".
func (s m3aShape) String() string {
	if s < m3aS1 || s > m3aS4 {
		return "S?"
	}
	return "S" + strconv.Itoa(int(s))
}

// chains extends each part with mid (intermediates, leaf-side first) and
// then, where the shape carries it, the chain's own anchor: the root of that
// chain's issuer path. A nil anchor is never appended (V3's one certificate is
// its own anchor).
func (s m3aShape) chains(leaf []byte, mid [][]byte, anchor []byte) (tlsChain, subject [][]byte) {
	part := func(withAnchor bool) [][]byte {
		out := make([][]byte, 0, 2+len(mid))
		out = append(out, leaf)
		out = append(out, mid...)
		if withAnchor && anchor != nil {
			out = append(out, anchor)
		}
		return out
	}
	return part(s == m3aS3 || s == m3aS4), part(s == m3aS2 || s == m3aS4)
}

// parseM3aShape reads FARCAST_WALK_M3A_SHAPE: "S1" to "S4", and nothing else.
func parseM3aShape(s string) (m3aShape, error) {
	for _, sh := range m3aShapes {
		if s == sh.String() {
			return sh, nil
		}
	}
	return 0, errors.New("the shape must be one of S1, S2, S3 or S4")
}

// m3aSimplest is the lowest passing shape, the one the product sends.
func m3aSimplest(passed [4]bool) (m3aShape, bool) {
	for i, ok := range passed {
		if ok {
			return m3aShapes[i], true
		}
	}
	return 0, false
}

// m3aCert is a certificate the probe made, and its key when the probe holds
// it.
type m3aCert struct {
	der  []byte
	cert *x509.Certificate
	key  crypto.Signer
}

// m3aSign signs tmpl under parent with signer, for pub, and parses the result.
func m3aSign(rnd io.Reader, tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) (m3aCert, error) {
	der, err := x509.CreateCertificate(rnd, tmpl, parent, pub, signer)
	if err != nil {
		return m3aCert{}, err
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return m3aCert{}, err
	}
	return m3aCert{der: der, cert: c}, nil
}

// m3aNewKey is a new P-256 key.
func m3aNewKey(rnd io.Reader) (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rnd)
}

// errM3aTemplate is a devicekey template that came back nil.
var errM3aTemplate = errors.New("devicekey gave no template")

// m3aAnchorWith is D2's anchor for id from key, with its validity replaced
// when notAfter is not zero (V6, V7).
func m3aAnchorWith(rnd io.Reader, id devicekey.RoleID, key *ecdsa.PrivateKey, notBefore, notAfter time.Time) (m3aCert, error) {
	serial, err := devicekey.NewSerial(rnd)
	if err != nil {
		return m3aCert{}, err
	}
	tmpl, err := devicekey.AnchorTemplate(id, serial, notBefore, &key.PublicKey)
	if err != nil {
		return m3aCert{}, err
	}
	if tmpl == nil {
		return m3aCert{}, errM3aTemplate
	}
	if !notAfter.IsZero() {
		tmpl.NotAfter = notAfter
	}
	c, err := m3aSign(rnd, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return m3aCert{}, err
	}
	c.key = key
	return c, nil
}

// m3aAnchor is D2's anchor for id, from a new key, valid from NotBefore(now).
func m3aAnchor(rnd io.Reader, id devicekey.RoleID, now time.Time) (m3aCert, error) {
	key, err := m3aNewKey(rnd)
	if err != nil {
		return m3aCert{}, err
	}
	return m3aAnchorWith(rnd, id, key, devicekey.NotBefore(now), time.Time{})
}

// m3aLeafSpec says how a leaf differs from D2's: its CN, its validity and its
// key. Zero values are D2's.
type m3aLeafSpec struct {
	id        devicekey.RoleID
	cn        string        // "" is id.Hex(); V1y's leaf is id.Hex()+"-l"
	notBefore time.Time     // zero is NotBefore(now)
	notAfter  time.Time     // zero is the template's: 90 days, capped at the issuer's end
	key       crypto.Signer // nil is a new P-256 key
}

// m3aLeaf issues s's leaf under issuer, from devicekey.LeafTemplate, signed by
// issuer's key.
func m3aLeaf(rnd io.Reader, now time.Time, s m3aLeafSpec, issuer m3aCert) (m3aCert, error) {
	if issuer.key == nil {
		return m3aCert{}, errors.New("the issuer's key is not held")
	}
	key := s.key
	if key == nil {
		k, err := m3aNewKey(rnd)
		if err != nil {
			return m3aCert{}, err
		}
		key = k
	}
	serial, err := devicekey.NewSerial(rnd)
	if err != nil {
		return m3aCert{}, err
	}
	nb := s.notBefore
	if nb.IsZero() {
		nb = devicekey.NotBefore(now)
	}
	tmpl := devicekey.LeafTemplate(s.id, serial, nb, issuer.cert)
	if tmpl == nil {
		return m3aCert{}, errM3aTemplate
	}
	if s.cn != "" {
		tmpl.Subject = pkix.Name{CommonName: s.cn}
	}
	if !s.notAfter.IsZero() {
		tmpl.NotAfter = s.notAfter
	}
	c, err := m3aSign(rnd, tmpl, issuer.cert, key.Public(), issuer.key)
	if err != nil {
		return m3aCert{}, err
	}
	c.key = key
	return c, nil
}

// m3aIntermediate is an intermediate CA for id under issuer (N2 (b), N7): D2's
// anchor profile (CA, path length 0, keyCertSign, clientAuth, CN = id) from a
// new key, its authority key identifier the issuer's, valid as a leaf is.
func m3aIntermediate(rnd io.Reader, now time.Time, id devicekey.RoleID, issuer m3aCert) (m3aCert, error) {
	if issuer.key == nil {
		return m3aCert{}, errors.New("the issuer's key is not held")
	}
	key, err := m3aNewKey(rnd)
	if err != nil {
		return m3aCert{}, err
	}
	serial, err := devicekey.NewSerial(rnd)
	if err != nil {
		return m3aCert{}, err
	}
	nb := devicekey.NotBefore(now)
	tmpl, err := devicekey.AnchorTemplate(id, serial, nb, &key.PublicKey)
	if err != nil {
		return m3aCert{}, err
	}
	if tmpl == nil {
		return m3aCert{}, errM3aTemplate
	}
	tmpl.NotAfter = nb.Add(devicekey.LeafLifetime)
	if tmpl.NotAfter.After(issuer.cert.NotAfter) {
		tmpl.NotAfter = issuer.cert.NotAfter
	}
	tmpl.AuthorityKeyId = issuer.cert.SubjectKeyId
	c, err := m3aSign(rnd, tmpl, issuer.cert, &key.PublicKey, issuer.key)
	if err != nil {
		return m3aCert{}, err
	}
	c.key = key
	return c, nil
}

// m3aPair is a variant's anchor and leaf. V3's are one certificate.
type m3aPair struct{ anchor, leaf m3aCert }

// m3aVariantV1x is Google's example extensions verbatim [X509], on P-256: the
// CA with basicConstraints critical CA:TRUE and no path length, keyUsage
// keyCertSign non-critical, extendedKeyUsage clientAuth; the leaf with keyUsage
// critical digitalSignature and keyEncipherment, basicConstraints critical
// CA:FALSE, and no extendedKeyUsage. Both CNs are id, as D3's condition needs.
func m3aVariantV1x(rnd io.Reader, now time.Time, id devicekey.RoleID) (m3aPair, error) {
	caKey, err := m3aNewKey(rnd)
	if err != nil {
		return m3aPair{}, err
	}
	serial, err := devicekey.NewSerial(rnd)
	if err != nil {
		return m3aPair{}, err
	}
	// keyCertSign is bit 5: 0x04 in the first byte, six bits used.
	ku, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0x04}, BitLength: 6})
	if err != nil {
		return m3aPair{}, err
	}
	nb := devicekey.NotBefore(now)
	ca := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: id.Hex()},
		NotBefore:             nb,
		NotAfter:              nb.Add(devicekey.AnchorLifetime),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            -1,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions:       []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: false, Value: ku}},
	}
	anchor, err := m3aSign(rnd, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return m3aPair{}, err
	}
	anchor.key = caKey
	leafKey, err := m3aNewKey(rnd)
	if err != nil {
		return m3aPair{}, err
	}
	leafSerial, err := devicekey.NewSerial(rnd)
	if err != nil {
		return m3aPair{}, err
	}
	lt := &x509.Certificate{
		SerialNumber:          leafSerial,
		Subject:               pkix.Name{CommonName: id.Hex()},
		NotBefore:             nb,
		NotAfter:              nb.Add(devicekey.LeafLifetime),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		AuthorityKeyId:        anchor.cert.SubjectKeyId,
	}
	leaf, err := m3aSign(rnd, lt, anchor.cert, &leafKey.PublicKey, caKey)
	if err != nil {
		return m3aPair{}, err
	}
	leaf.key = leafKey
	return m3aPair{anchor: anchor, leaf: leaf}, nil
}

// m3aV1ySuffix is V1y's leaf CN suffix: a leaf whose DN differs from its
// issuer's.
const m3aV1ySuffix = "-l"

// m3aV1yCondition is V1y's condition, naming both CNs.
func m3aV1yCondition(idHex string) string {
	return "assertion.issuer.dn.cn == '" + idHex + "' && assertion.subject.dn.cn == '" + idHex + m3aV1ySuffix + "'"
}

// m3aVariantV1y is D2's extensions with a leaf whose CN is id+"-l".
func m3aVariantV1y(rnd io.Reader, now time.Time, id devicekey.RoleID) (m3aPair, error) {
	anchor, err := m3aAnchor(rnd, id, now)
	if err != nil {
		return m3aPair{}, err
	}
	leaf, err := m3aLeaf(rnd, now, m3aLeafSpec{id: id, cn: id.Hex() + m3aV1ySuffix}, anchor)
	if err != nil {
		return m3aPair{}, err
	}
	return m3aPair{anchor: anchor, leaf: leaf}, nil
}

// m3aVariantV2 is D2's anchor and leaf on one key.
func m3aVariantV2(rnd io.Reader, now time.Time, id devicekey.RoleID) (m3aPair, error) {
	key, err := m3aNewKey(rnd)
	if err != nil {
		return m3aPair{}, err
	}
	anchor, err := m3aAnchorWith(rnd, id, key, devicekey.NotBefore(now), time.Time{})
	if err != nil {
		return m3aPair{}, err
	}
	leaf, err := m3aLeaf(rnd, now, m3aLeafSpec{id: id, key: key}, anchor)
	if err != nil {
		return m3aPair{}, err
	}
	return m3aPair{anchor: anchor, leaf: leaf}, nil
}

// m3aVariantV3 is one self-signed CA:TRUE certificate with keyCertSign,
// digitalSignature and clientAuth, as anchor and leaf.
func m3aVariantV3(rnd io.Reader, now time.Time, id devicekey.RoleID) (m3aPair, error) {
	key, err := m3aNewKey(rnd)
	if err != nil {
		return m3aPair{}, err
	}
	serial, err := devicekey.NewSerial(rnd)
	if err != nil {
		return m3aPair{}, err
	}
	tmpl, err := devicekey.AnchorTemplate(id, serial, devicekey.NotBefore(now), &key.PublicKey)
	if err != nil {
		return m3aPair{}, err
	}
	if tmpl == nil {
		return m3aPair{}, errM3aTemplate
	}
	tmpl.KeyUsage |= x509.KeyUsageDigitalSignature
	c, err := m3aSign(rnd, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return m3aPair{}, err
	}
	c.key = key
	return m3aPair{anchor: c, leaf: c}, nil
}

// m3aVariantV4 is D2's profile on RSA-2048 keys. AnchorTemplate takes a P-256
// key, so the anchor's template is written out here with D2's fields, and Go
// adds its subject key identifier; the leaf is devicekey's.
func m3aVariantV4(rnd io.Reader, now time.Time, id devicekey.RoleID) (m3aPair, error) {
	caKey, err := rsa.GenerateKey(rnd, 2048)
	if err != nil {
		return m3aPair{}, err
	}
	serial, err := devicekey.NewSerial(rnd)
	if err != nil {
		return m3aPair{}, err
	}
	nb := devicekey.NotBefore(now)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: id.Hex()},
		NotBefore:             nb,
		NotAfter:              nb.Add(devicekey.AnchorLifetime),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	anchor, err := m3aSign(rnd, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return m3aPair{}, err
	}
	anchor.key = caKey
	leafKey, err := rsa.GenerateKey(rnd, 2048)
	if err != nil {
		return m3aPair{}, err
	}
	leaf, err := m3aLeaf(rnd, now, m3aLeafSpec{id: id, key: leafKey}, anchor)
	if err != nil {
		return m3aPair{}, err
	}
	return m3aPair{anchor: anchor, leaf: leaf}, nil
}

// m3aV6Backdate and m3aV6Life are V6's anchor: backdated 400 days, two years
// in all.
const (
	m3aV6Backdate = 400 * 24 * time.Hour
	m3aV6Life     = 730 * 24 * time.Hour
)

// m3aVariantV6 is D2's profile with the anchor backdated 400 days and valid
// two years in all, and a D2 leaf under it.
func m3aVariantV6(rnd io.Reader, now time.Time, id devicekey.RoleID) (m3aPair, error) {
	key, err := m3aNewKey(rnd)
	if err != nil {
		return m3aPair{}, err
	}
	nb := devicekey.NotBefore(now).Add(-m3aV6Backdate)
	anchor, err := m3aAnchorWith(rnd, id, key, nb, nb.Add(m3aV6Life))
	if err != nil {
		return m3aPair{}, err
	}
	leaf, err := m3aLeaf(rnd, now, m3aLeafSpec{id: id}, anchor)
	if err != nil {
		return m3aPair{}, err
	}
	return m3aPair{anchor: anchor, leaf: leaf}, nil
}

// m3aVariantV7 is D2's profile with a fresh anchor valid five years.
func m3aVariantV7(rnd io.Reader, now time.Time, id devicekey.RoleID) (m3aPair, error) {
	key, err := m3aNewKey(rnd)
	if err != nil {
		return m3aPair{}, err
	}
	nb := devicekey.NotBefore(now)
	anchor, err := m3aAnchorWith(rnd, id, key, nb, nb.AddDate(5, 0, 0))
	if err != nil {
		return m3aPair{}, err
	}
	leaf, err := m3aLeaf(rnd, now, m3aLeafSpec{id: id}, anchor)
	if err != nil {
		return m3aPair{}, err
	}
	return m3aPair{anchor: anchor, leaf: leaf}, nil
}

// m3aNegativeLeaves are the certificates design §6's negatives send, made fresh
// for one run of the negatives step under V1's reader anchor (whose key the
// probe read from device-a) and N1's foreign anchor.
type m3aNegativeLeaves struct {
	n1          m3aCert // under N1's anchor, CN V1's reader ID
	n2a         m3aCert // CN V1b's reader ID, under V1's reader anchor
	n2bMid, n2b m3aCert // an intermediate and a leaf, both CN V1b's reader ID
	n7rMid, n7r m3aCert // both CN V1's reader ID
	n7wMid, n7w m3aCert // both CN V1's writer ID
	n8Expired   m3aCert // NotBefore the anchor's, NotAfter now − 5 min
	n8NotYet    m3aCert // NotBefore now + 1 day, NotAfter a day later
	n9a         m3aCert // CN V1's writer ID, under V1's reader anchor
}

// m3aMakeNegativeLeaves makes the negatives' constructions.
func m3aMakeNegativeLeaves(rnd io.Reader, now time.Time, readerAnchor, n1Anchor m3aCert, readerID, writerID, v1bID devicekey.RoleID) (m3aNegativeLeaves, error) {
	var n m3aNegativeLeaves
	var err error
	if n.n1, err = m3aLeaf(rnd, now, m3aLeafSpec{id: readerID}, n1Anchor); err != nil {
		return n, fmt.Errorf("N1: %w", err)
	}
	if n.n2a, err = m3aLeaf(rnd, now, m3aLeafSpec{id: v1bID}, readerAnchor); err != nil {
		return n, fmt.Errorf("N2 (a): %w", err)
	}
	if n.n2bMid, err = m3aIntermediate(rnd, now, v1bID, readerAnchor); err != nil {
		return n, fmt.Errorf("N2 (b): %w", err)
	}
	if n.n2b, err = m3aLeaf(rnd, now, m3aLeafSpec{id: v1bID}, n.n2bMid); err != nil {
		return n, fmt.Errorf("N2 (b): %w", err)
	}
	if n.n7rMid, err = m3aIntermediate(rnd, now, readerID, readerAnchor); err != nil {
		return n, fmt.Errorf("N7 (i): %w", err)
	}
	if n.n7r, err = m3aLeaf(rnd, now, m3aLeafSpec{id: readerID}, n.n7rMid); err != nil {
		return n, fmt.Errorf("N7 (i): %w", err)
	}
	if n.n7wMid, err = m3aIntermediate(rnd, now, writerID, readerAnchor); err != nil {
		return n, fmt.Errorf("N7 (ii): %w", err)
	}
	if n.n7w, err = m3aLeaf(rnd, now, m3aLeafSpec{id: writerID}, n.n7wMid); err != nil {
		return n, fmt.Errorf("N7 (ii): %w", err)
	}
	if n.n8Expired, err = m3aLeaf(rnd, now, m3aLeafSpec{id: readerID, notBefore: readerAnchor.cert.NotBefore, notAfter: now.Add(-5 * time.Minute).UTC().Truncate(time.Second)}, readerAnchor); err != nil {
		return n, fmt.Errorf("N8: %w", err)
	}
	future := now.Add(24 * time.Hour).UTC().Truncate(time.Second)
	if n.n8NotYet, err = m3aLeaf(rnd, now, m3aLeafSpec{id: readerID, notBefore: future, notAfter: future.Add(24 * time.Hour)}, readerAnchor); err != nil {
		return n, fmt.Errorf("N8: %w", err)
	}
	if n.n9a, err = m3aLeaf(rnd, now, m3aLeafSpec{id: writerID}, readerAnchor); err != nil {
		return n, fmt.Errorf("N9 (a): %w", err)
	}
	return n, nil
}

// m3aI3Leaf is I3's: a D2 leaf under V1's reader anchor whose NotAfter is
// now + 20 minutes.
func m3aI3Leaf(rnd io.Reader, now time.Time, readerAnchor m3aCert, readerID devicekey.RoleID) (m3aCert, error) {
	return m3aLeaf(rnd, now, m3aLeafSpec{id: readerID, notAfter: now.Add(20 * time.Minute).UTC().Truncate(time.Second)}, readerAnchor)
}

// m3aI4Days are I4's: a leaf backdated 400 days, valid until now + 30 days.
const (
	m3aI4Backdate = 400 * 24 * time.Hour
	m3aI4Ahead    = 30 * 24 * time.Hour
)

// m3aI4Leaves are I4's two leaves. (a) is under V1's reader anchor, with
// NotBefore now − 400 days and NotAfter now + 30 days: it predates its issuer.
// (b) is under V6's anchor, with NotBefore that anchor's and NotAfter now + 30
// days, so it nests inside its issuer.
func m3aI4Leaves(rnd io.Reader, now time.Time, readerAnchor m3aCert, readerID devicekey.RoleID, v6Anchor m3aCert, v6ID devicekey.RoleID) (a, b m3aCert, err error) {
	end := now.Add(m3aI4Ahead).UTC().Truncate(time.Second)
	if a, err = m3aLeaf(rnd, now, m3aLeafSpec{id: readerID, notBefore: now.Add(-m3aI4Backdate).UTC().Truncate(time.Second), notAfter: end}, readerAnchor); err != nil {
		return a, b, fmt.Errorf("I4 (a): %w", err)
	}
	if b, err = m3aLeaf(rnd, now, m3aLeafSpec{id: v6ID, notBefore: v6Anchor.cert.NotBefore, notAfter: end}, v6Anchor); err != nil {
		return a, b, fmt.Errorf("I4 (b): %w", err)
	}
	return a, b, nil
}

// m3aProjectIDShape, m3aWIFIDShape: a project ID (6 to 30 characters, a
// letter first, no trailing hyphen) and a pool's or provider's ID (4 to 32 of
// [a-z0-9-], not starting gcp-) [MGMT]. Checked by hand.
func m3aProjectIDShape(s string) bool {
	if len(s) < 6 || len(s) > 30 || s[0] < 'a' || s[0] > 'z' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

func m3aWIFIDShape(s string) bool {
	if len(s) < 4 || len(s) > 32 || (len(s) >= 4 && s[:4] == "gcp-") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// m3aAudienceForProjectID is I5's audience: the documented audience with the
// project's ID in place of its number. kube.Audience takes a number only, and
// Exchange's audience guard admits this form. The error names the part,
// never the value.
func m3aAudienceForProjectID(projectID, pool, provider string) (string, error) {
	switch {
	case !m3aProjectIDShape(projectID):
		return "", errors.New("I5's audience: the project ID is not a project ID")
	case !m3aWIFIDShape(pool):
		return "", errors.New("I5's audience: the pool is not a pool ID")
	case !m3aWIFIDShape(provider):
		return "", errors.New("I5's audience: the provider is not a provider ID")
	}
	return "//iam.googleapis.com/projects/" + projectID + "/locations/global/workloadIdentityPools/" + pool + "/providers/" + provider, nil
}

// m3aJWTLife is V5's JWT's life: exp − iat.
const m3aJWTLife = 600

// m3aJWTHeader is the vendored jwt.Header's field order (internal/jwt/jwt.go:46-50).
type m3aJWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	KID string `json:"kid"`
}

// m3aJWTClaims are V5's claims [OIDC, STS], in this order.
type m3aJWTClaims struct {
	Aud string `json:"aud"`
	Exp int64  `json:"exp"`
	Iat int64  `json:"iat"`
	Iss string `json:"iss"`
	Sub string `json:"sub"`
}

// m3aV5Audience is the JWT's aud: the provider's full resource name, the
// default allowed audience [OIDC, PROV].
func m3aV5Audience(projectNumber, pool, provider string) string {
	return "https://iam.googleapis.com/projects/" + projectNumber + "/locations/global/workloadIdentityPools/" + pool + "/providers/" + provider
}

// m3aES256JWT is V5's JWT: header and claims as above, signed with ECDSA
// P-256 over SHA-256 of b64url(header).b64url(claims), the ASN.1 signature
// converted to raw R‖S with FillBytes (vendored jwt.go:119-151), every part
// base64url, unpadded.
func m3aES256JWT(rnd io.Reader, key crypto.Signer, kid, iss, sub, aud string, now time.Time) (string, error) {
	h, err := json.Marshal(m3aJWTHeader{Alg: "ES256", Typ: "JWT", KID: kid})
	if err != nil {
		return "", err
	}
	iat := now.Unix()
	c, err := json.Marshal(m3aJWTClaims{Aud: aud, Exp: iat + m3aJWTLife, Iat: iat, Iss: iss, Sub: sub})
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(h) + "." + enc.EncodeToString(c)
	digest := sha256.Sum256([]byte(input))
	der, err := key.Sign(rnd, digest[:], crypto.SHA256)
	if err != nil {
		return "", err
	}
	var rs struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &rs)
	if err != nil || len(rest) != 0 || rs.R == nil || rs.S == nil || rs.R.Sign() <= 0 || rs.S.Sign() <= 0 {
		return "", errors.New("V5's signature is not an ECDSA signature")
	}
	if rs.R.BitLen() > 256 || rs.S.BitLen() > 256 {
		return "", errors.New("V5's signature is not a P-256 signature")
	}
	sig := make([]byte, 64)
	rs.R.FillBytes(sig[:32])
	rs.S.FillBytes(sig[32:])
	return input + "." + enc.EncodeToString(sig), nil
}

// m3aJWK is one key of V5's JWKS [PROV, G-COIDC], in this order.
type m3aJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	KID string `json:"kid"`
}

// m3aJWKS is V5's single-key JWKS. x and y come from pub.Bytes(), the
// uncompressed point: no deprecated field is read.
func m3aJWKS(pub *ecdsa.PublicKey, kid string) ([]byte, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return nil, errors.New("V5's key is not a P-256 key")
	}
	p, err := pub.Bytes()
	if err != nil {
		return nil, err
	}
	if len(p) != 65 || p[0] != 4 {
		return nil, errors.New("V5's key is not an uncompressed P-256 point")
	}
	enc := base64.RawURLEncoding
	return json.Marshal(struct {
		Keys []m3aJWK `json:"keys"`
	}{Keys: []m3aJWK{{Kty: "EC", Crv: "P-256", X: enc.EncodeToString(p[1:33]), Y: enc.EncodeToString(p[33:65]), Alg: "ES256", Use: "sig", KID: kid}}})
}

// m3aTestRoleIDs draws n role IDs through devicekey, as the probe does.
func m3aTestRoleIDs(t *testing.T, n int) []devicekey.RoleID {
	t.Helper()
	out := make([]devicekey.RoleID, n)
	for i := range out {
		id, err := devicekey.NewRoleID(rand.Reader)
		if err != nil {
			t.Fatalf("devicekey.NewRoleID: %v", err)
		}
		out[i] = id
	}
	return out
}

// m3aWantCert checks a certificate's CN, its issuer's CN, that issuer signed
// it, and whether it is a CA.
func m3aWantCert(t *testing.T, name string, c m3aCert, cn string, issuer m3aCert, ca bool) {
	t.Helper()
	if c.cert == nil {
		t.Errorf("%s: no certificate", name)
		return
	}
	if c.cert.Subject.CommonName != cn {
		t.Errorf("%s: CN is not the one intended", name)
	}
	if c.cert.Issuer.CommonName != issuer.cert.Subject.CommonName || !bytes.Equal(c.cert.RawIssuer, issuer.cert.RawSubject) {
		t.Errorf("%s: the issuer DN is not its intended issuer's", name)
	}
	if err := c.cert.CheckSignatureFrom(issuer.cert); err != nil {
		t.Errorf("%s: does not verify under its intended issuer: %v", name, err)
	}
	if c.cert.IsCA != ca {
		t.Errorf("%s: IsCA = %v, want %v", name, c.cert.IsCA, ca)
	}
	if !ca && c.cert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("%s: a leaf's key usage is %v, want digitalSignature alone", name, c.cert.KeyUsage)
	}
	if len(c.cert.AuthorityKeyId) == 0 || !bytes.Equal(c.cert.AuthorityKeyId, issuer.cert.SubjectKeyId) {
		t.Errorf("%s: its authority key identifier is not its issuer's subject key identifier", name)
	}
}

// m3aWantIntermediate checks N2 (b)'s and N7's intermediates: a CA with path
// length 0, keyCertSign and clientAuth, under V1's reader anchor.
func m3aWantIntermediate(t *testing.T, name string, c m3aCert, cn string, readerAnchor m3aCert) {
	t.Helper()
	m3aWantCert(t, name, c, cn, readerAnchor, true)
	if !c.cert.BasicConstraintsValid || c.cert.MaxPathLen != 0 || !c.cert.MaxPathLenZero {
		t.Errorf("%s: not a CA with path length 0", name)
	}
	if c.cert.KeyUsage != x509.KeyUsageCertSign || len(c.cert.ExtKeyUsage) != 1 || c.cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("%s: key usage %v, EKU %v; want keyCertSign and clientAuth", name, c.cert.KeyUsage, c.cert.ExtKeyUsage)
	}
}

// TestWalkM3aNegativeChains: each negative's chain is what design §6 gives
// it. The CNs, the issuers and the path lengths are what make each negative
// differ from its control in the one property tested.
func TestWalkM3aNegativeChains(t *testing.T) {
	now := time.Now().UTC()
	ids := m3aTestRoleIDs(t, 4)
	readerID, writerID, v1bID, v6ID := ids[0], ids[1], ids[2], ids[3]
	readerAnchor, err := m3aAnchor(rand.Reader, readerID, now)
	if err != nil {
		t.Fatal(err)
	}
	n1Anchor, err := m3aAnchor(rand.Reader, readerID, now)
	if err != nil {
		t.Fatal(err)
	}
	v6, err := m3aVariantV6(rand.Reader, now, v6ID)
	if err != nil {
		t.Fatal(err)
	}
	n, err := m3aMakeNegativeLeaves(rand.Reader, now, readerAnchor, n1Anchor, readerID, writerID, v1bID)
	if err != nil {
		t.Fatal(err)
	}
	r, w, b := readerID.Hex(), writerID.Hex(), v1bID.Hex()

	// N1: a foreign anchor with V1's reader ID, so only the trust store can
	// refuse it.
	m3aWantCert(t, "N1", n.n1, r, n1Anchor, false)
	if n1Anchor.cert.Subject.CommonName != r || n.n1.cert.CheckSignatureFrom(readerAnchor.cert) == nil {
		t.Error("N1: its anchor must carry V1's reader ID and not be V1's reader anchor")
	}
	m3aWantCert(t, "N2 (a)", n.n2a, b, readerAnchor, false)
	m3aWantIntermediate(t, "N2 (b) intermediate", n.n2bMid, b, readerAnchor)
	m3aWantCert(t, "N2 (b)", n.n2b, b, n.n2bMid, false)
	m3aWantIntermediate(t, "N7 (i) intermediate", n.n7rMid, r, readerAnchor)
	m3aWantCert(t, "N7 (i)", n.n7r, r, n.n7rMid, false)
	m3aWantIntermediate(t, "N7 (ii) intermediate", n.n7wMid, w, readerAnchor)
	m3aWantCert(t, "N7 (ii)", n.n7w, w, n.n7wMid, false)
	m3aWantCert(t, "N8 expired", n.n8Expired, r, readerAnchor, false)
	if !n.n8Expired.cert.NotBefore.Equal(readerAnchor.cert.NotBefore) || !n.n8Expired.cert.NotAfter.Before(now) {
		t.Error("N8: the expired leaf must start with its anchor and end before now")
	}
	m3aWantCert(t, "N8 not yet valid", n.n8NotYet, r, readerAnchor, false)
	if !n.n8NotYet.cert.NotBefore.After(now.Add(23*time.Hour)) || n.n8NotYet.cert.NotAfter.Sub(n.n8NotYet.cert.NotBefore) != 24*time.Hour {
		t.Error("N8: the leaf not yet valid must start a day ahead and last a day")
	}
	m3aWantCert(t, "N9 (a)", n.n9a, w, readerAnchor, false)
	for name, c := range map[string]m3aCert{"N1": n.n1, "N2 (a)": n.n2a, "N2 (b)": n.n2b, "N7 (i)": n.n7r, "N7 (ii)": n.n7w, "N9 (a)": n.n9a} {
		if !c.cert.NotBefore.Before(now) || !c.cert.NotAfter.After(now) {
			t.Errorf("%s: not valid now", name)
		}
	}

	i3, err := m3aI3Leaf(rand.Reader, now, readerAnchor, readerID)
	if err != nil {
		t.Fatal(err)
	}
	m3aWantCert(t, "I3", i3, r, readerAnchor, false)
	if d := i3.cert.NotAfter.Sub(now); d > 20*time.Minute || d < 19*time.Minute {
		t.Errorf("I3: the leaf ends %v from now, want 20 minutes", d)
	}
	a, bb, err := m3aI4Leaves(rand.Reader, now, readerAnchor, readerID, v6.anchor, v6ID)
	if err != nil {
		t.Fatal(err)
	}
	m3aWantCert(t, "I4 (a)", a, r, readerAnchor, false)
	if d := now.Sub(a.cert.NotBefore); d < m3aI4Backdate || d >= m3aI4Backdate+time.Second {
		t.Errorf("I4 (a): NotBefore is %v back, want 400 days", d)
	}
	if !a.cert.NotBefore.Before(readerAnchor.cert.NotBefore) {
		t.Error("I4 (a): the leaf must predate its issuer, as the design builds it")
	}
	m3aWantCert(t, "I4 (b)", bb, v6ID.Hex(), v6.anchor, false)
	if bb.cert.NotBefore.Before(v6.anchor.cert.NotBefore) || bb.cert.NotAfter.After(v6.anchor.cert.NotAfter) {
		t.Error("I4 (b): the leaf's validity must lie inside V6's anchor's")
	}
	for name, c := range map[string]m3aCert{"I4 (a)": a, "I4 (b)": bb} {
		if d := c.cert.NotAfter.Sub(now); d > m3aI4Ahead || d < m3aI4Ahead-time.Second {
			t.Errorf("%s: NotAfter is %v ahead, want 30 days", name, d)
		}
	}
}

// m3aExtension is the certificate's extension with that OID, or nil.
func m3aExtension(c *x509.Certificate, oid asn1.ObjectIdentifier) *pkix.Extension {
	for i := range c.Extensions {
		if c.Extensions[i].Id.Equal(oid) {
			return &c.Extensions[i]
		}
	}
	return nil
}

// TestWalkM3aVariantProfiles: each P5 variant is the shape design §6 names.
func TestWalkM3aVariantProfiles(t *testing.T) {
	now := time.Now().UTC()
	ids := m3aTestRoleIDs(t, 7)
	oidKU, oidBC, oidEKU := asn1.ObjectIdentifier{2, 5, 29, 15}, asn1.ObjectIdentifier{2, 5, 29, 19}, asn1.ObjectIdentifier{2, 5, 29, 37}

	x, err := m3aVariantV1x(rand.Reader, now, ids[0])
	if err != nil {
		t.Fatal(err)
	}
	ca := x.anchor.cert
	if bc := m3aExtension(ca, oidBC); bc == nil || !bc.Critical || !ca.IsCA || ca.MaxPathLen != -1 || ca.MaxPathLenZero {
		t.Error("V1x CA: want basicConstraints critical, CA:TRUE, no path length")
	}
	if ku := m3aExtension(ca, oidKU); ku == nil || ku.Critical || ca.KeyUsage != x509.KeyUsageCertSign {
		t.Error("V1x CA: want keyUsage keyCertSign, not critical")
	}
	if len(ca.ExtKeyUsage) != 1 || ca.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Error("V1x CA: want extendedKeyUsage clientAuth")
	}
	leaf := x.leaf.cert
	if ku := m3aExtension(leaf, oidKU); ku == nil || !ku.Critical || leaf.KeyUsage != x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment {
		t.Error("V1x leaf: want keyUsage critical, digitalSignature and keyEncipherment")
	}
	if bc := m3aExtension(leaf, oidBC); bc == nil || !bc.Critical || leaf.IsCA {
		t.Error("V1x leaf: want basicConstraints critical, CA:FALSE")
	}
	if m3aExtension(leaf, oidEKU) != nil {
		t.Error("V1x leaf: want no extendedKeyUsage")
	}
	if leaf.Subject.CommonName != ids[0].Hex() || leaf.CheckSignatureFrom(ca) != nil {
		t.Error("V1x leaf: want CN the ID, signed by the CA")
	}

	y, err := m3aVariantV1y(rand.Reader, now, ids[1])
	if err != nil {
		t.Fatal(err)
	}
	m3aWantCert(t, "V1y leaf", y.leaf, ids[1].Hex()+"-l", y.anchor, false)
	cond := m3aV1yCondition(ids[1].Hex())
	if !strings.Contains(cond, "'"+ids[1].Hex()+"'") || !strings.Contains(cond, "'"+ids[1].Hex()+"-l'") {
		t.Errorf("V1y's condition must name both CNs")
	}

	v2, err := m3aVariantV2(rand.Reader, now, ids[2])
	if err != nil {
		t.Fatal(err)
	}
	m3aWantCert(t, "V2 leaf", v2.leaf, ids[2].Hex(), v2.anchor, false)
	if pub, ok := v2.anchor.cert.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(v2.leaf.cert.PublicKey) {
		t.Error("V2: the anchor and the leaf must share one key")
	}

	v3, err := m3aVariantV3(rand.Reader, now, ids[3])
	if err != nil {
		t.Fatal(err)
	}
	c3 := v3.anchor.cert
	if !bytes.Equal(v3.anchor.der, v3.leaf.der) || !c3.IsCA || c3.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature ||
		len(c3.ExtKeyUsage) != 1 || c3.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || c3.CheckSignatureFrom(c3) != nil {
		t.Error("V3: want one self-signed CA:TRUE certificate with keyCertSign, digitalSignature and clientAuth")
	}

	v4, err := m3aVariantV4(rand.Reader, now, ids[4])
	if err != nil {
		t.Fatal(err)
	}
	m3aWantCert(t, "V4 leaf", v4.leaf, ids[4].Hex(), v4.anchor, false)
	for name, c := range map[string]*x509.Certificate{"anchor": v4.anchor.cert, "leaf": v4.leaf.cert} {
		if k, ok := c.PublicKey.(*rsa.PublicKey); !ok || k.N.BitLen() != 2048 {
			t.Errorf("V4 %s: want an RSA-2048 key", name)
		}
	}
	if !v4.anchor.cert.IsCA || !v4.anchor.cert.MaxPathLenZero || v4.anchor.cert.KeyUsage != x509.KeyUsageCertSign {
		t.Error("V4 anchor: want D2's CA profile")
	}

	v6, err := m3aVariantV6(rand.Reader, now, ids[5])
	if err != nil {
		t.Fatal(err)
	}
	a6 := v6.anchor.cert
	if back := devicekey.NotBefore(now).Sub(a6.NotBefore); back != m3aV6Backdate || a6.NotAfter.Sub(a6.NotBefore) != 730*24*time.Hour {
		t.Errorf("V6: the anchor starts %v back and lasts %v; want 400 days back, two years in all", back, a6.NotAfter.Sub(a6.NotBefore))
	}
	m3aWantCert(t, "V6 leaf", v6.leaf, ids[5].Hex(), v6.anchor, false)

	v7, err := m3aVariantV7(rand.Reader, now, ids[6])
	if err != nil {
		t.Fatal(err)
	}
	a7 := v7.anchor.cert
	if !a7.NotAfter.Equal(a7.NotBefore.AddDate(5, 0, 0)) || !a7.NotBefore.Equal(devicekey.NotBefore(now)) {
		t.Error("V7: want a fresh anchor valid five years")
	}
}

// TestWalkM3aAudienceForProjectID: I5's audience is the documented one with
// the project's ID for its number; kube.Audience itself refuses that ID; and
// a bad part is refused without quoting it.
func TestWalkM3aAudienceForProjectID(t *testing.T) {
	const project, pool, provider = "probe-project-1", "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6", "q1r2s3t4u5v6w7x8y9z0a1b2c3d4e5f6"
	got, err := m3aAudienceForProjectID(project, pool, provider)
	if err != nil {
		t.Fatal(err)
	}
	if want := "//iam.googleapis.com/projects/probe-project-1/locations/global/workloadIdentityPools/" + pool + "/providers/" + provider; got != want {
		t.Errorf("I5's audience = %q, want %q", got, want)
	}
	if aud, err := kube.Audience(project, pool, provider); err == nil {
		t.Errorf("kube.Audience accepted a project ID: %q", aud)
	}
	for _, bad := range [][3]string{
		{"1probe-project", pool, provider},
		{"probe", pool, provider},
		{"probe-project-", pool, provider},
		{"Probe-project", pool, provider},
		{"123456789012", pool, provider},
		{project, "gcp-" + pool[4:], provider},
		{project, "abc", provider},
		{project, pool + "x", provider},
		{project, pool, "Q1r2"},
		{project, pool, "q1r2/x"},
	} {
		_, err := m3aAudienceForProjectID(bad[0], bad[1], bad[2])
		if err == nil {
			t.Errorf("m3aAudienceForProjectID(%q, %q, %q) was accepted", bad[0], bad[1], bad[2])
			continue
		}
		for _, v := range bad {
			if strings.Contains(err.Error(), v) {
				t.Errorf("the refusal quotes a value: %v", err)
			}
		}
	}
}

// TestWalkM3aES256JWT: V5's JWT is exactly the header and claims V5 sends,
// with a raw 64-byte R‖S signature that verifies, and no padding anywhere.
func TestWalkM3aES256JWT(t *testing.T) {
	key, err := m3aNewKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_900_000_000, 0)
	const kid, iss, sub, aud = "k1d", "https://abc123.invalid", "0123456789abcdef0123456789abcdef", "https://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/providers/q"
	jwt, err := m3aES256JWT(rand.Reader, key, kid, iss, sub, aud, now)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(jwt, "=") {
		t.Error("the JWT carries padding")
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("the JWT has %d parts, want 3", len(parts))
	}
	dec := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("a part is not unpadded base64url: %v", err)
		}
		return b
	}
	if h := string(dec(parts[0])); h != `{"alg":"ES256","typ":"JWT","kid":"k1d"}` {
		t.Errorf("header = %s", h)
	}
	if c, want := string(dec(parts[1])), `{"aud":"`+aud+`","exp":1900000600,"iat":1900000000,"iss":"`+iss+`","sub":"`+sub+`"}`; c != want {
		t.Errorf("claims = %s, want %s", c, want)
	}
	var claims m3aJWTClaims
	if err := json.Unmarshal(dec(parts[1]), &claims); err != nil || claims.Exp-claims.Iat != 600 {
		t.Errorf("exp − iat = %d, want 600", claims.Exp-claims.Iat)
	}
	sig := dec(parts[2])
	if len(sig) != 64 {
		t.Fatalf("the signature is %d bytes, want 64 (raw R‖S)", len(sig))
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&key.PublicKey, digest[:], r, s) {
		t.Error("the signature does not verify")
	}
}

// TestWalkM3aJWKS: one key with its fields, and x‖y, prefixed by 0x04, parses
// to the signing key's public key.
func TestWalkM3aJWKS(t *testing.T) {
	key, err := m3aNewKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := m3aJWKS(&key.PublicKey, "k1d")
	if err != nil {
		t.Fatal(err)
	}
	var set struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil || len(set.Keys) != 1 {
		t.Fatalf("the JWKS holds %d keys (%v), want 1", len(set.Keys), err)
	}
	k := set.Keys[0]
	for f, want := range map[string]string{"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "k1d"} {
		if k[f] != want {
			t.Errorf("%s = %q, want %q", f, k[f], want)
		}
	}
	if len(k) != 7 {
		t.Errorf("the key has %d fields, want 7", len(k))
	}
	x, errX := base64.RawURLEncoding.DecodeString(k["x"])
	y, errY := base64.RawURLEncoding.DecodeString(k["y"])
	if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
		t.Fatal("x and y must be 32 bytes each, unpadded base64url")
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(&key.PublicKey) {
		t.Error("x‖y is not the signing key's public key")
	}
	if strings.Contains(string(raw), "=") {
		t.Error("the JWKS carries padding")
	}
}

// m3aParseP256 parses an uncompressed P-256 point, as the state records V5's.
func m3aParseP256(point []byte) (*ecdsa.PublicKey, error) {
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
}
