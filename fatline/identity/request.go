package identity

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	fcrypto "github.com/sofmon/farcast/fatline/internal/crypto"
)

// ErrRetiredAlgorithm marks a key, certificate or peer in an algorithm ADR
// 0020 retired: an instance store from before it, whose CA is Ed25519.
var ErrRetiredAlgorithm = fcrypto.ErrRetiredAlgorithm

// RequireP256CA refuses an instance CA certificate whose key is not ECDSA
// P-256, wrapping ErrRetiredAlgorithm and saying to release and reinstall.
func RequireP256CA(caCertPEM []byte) error {
	return fcrypto.RequireP256CA(caCertPEM)
}

// RequestError is an enrolment request refused by decision 3's checks; its
// Refusal is one of the Refusal* codes.
type RequestError = fcrypto.RequestError

// The refusal codes of an enrolment request (ADR 0020 decision 3).
const (
	RefusalMalformed          = fcrypto.RefusalMalformed
	RefusalKeyAlgorithm       = fcrypto.RefusalKeyAlgorithm
	RefusalCurve              = fcrypto.RefusalCurve
	RefusalSignatureAlgorithm = fcrypto.RefusalSignatureAlgorithm
	RefusalSignature          = fcrypto.RefusalSignature
)

// maxRequestPEM bounds an enrolment request file. A P-256 request is under a
// kilobyte; the bound only keeps a hostile file from being read whole.
const maxRequestPEM = 64 << 10

// Request is an enrolment request that passed decision 3's checks.
type Request struct {
	DER       []byte // the PKCS#10 request as received
	KeySHA256 string // KeyFingerprint of its key
}

// ParseRequest takes exactly one PEM block of type "CERTIFICATE REQUEST", with
// nothing but whitespace around it, at most 64 KiB, and applies decision 3's
// checks. Any PEM problem is RefusalMalformed. The request travels
// unauthenticated, so its KeySHA256 is the sender's claim until the operator
// confirms it against the device's screen.
func ParseRequest(requestPEM []byte) (Request, error) {
	malformed := func(detail string) (Request, error) {
		return Request{}, &RequestError{Refusal: RefusalMalformed, Detail: detail}
	}
	if len(requestPEM) > maxRequestPEM {
		return malformed(fmt.Sprintf("it is %d bytes, over the %d a request may be", len(requestPEM), maxRequestPEM))
	}
	trimmed := bytes.TrimLeft(requestPEM, " \t\r\n")
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		return malformed("it does not start with a PEM block")
	}
	// pem.Decode skips a block it cannot decode and returns the next one, so
	// "one block, first" is held here rather than left to it: a malformed or
	// corrupt block in front of a good one is refused, not stepped over. With
	// one BEGIN line, at the start, the block Decode returns (if any) is that
	// one, and its type is checked below.
	if n := bytes.Count(trimmed, []byte("-----BEGIN")); n != 1 {
		return malformed(fmt.Sprintf("it holds %d PEM BEGIN lines; a request file holds one block and nothing else", n))
	}
	block, rest := pem.Decode(trimmed)
	if block == nil {
		return malformed("it holds no PEM block")
	}
	if block.Type != "CERTIFICATE REQUEST" {
		return malformed(fmt.Sprintf("its PEM block is %q, not \"CERTIFICATE REQUEST\"", block.Type))
	}
	if len(block.Headers) != 0 {
		return malformed("its PEM block carries headers")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return malformed("something follows its PEM block; a request file holds one block and nothing else")
	}
	pub, err := fcrypto.CheckRequest(block.Bytes)
	if err != nil {
		return Request{}, err
	}
	fp, err := KeyFingerprint(pub)
	if err != nil {
		return Request{}, err
	}
	return Request{DER: block.Bytes, KeySHA256: fp}, nil
}

// KeyFingerprint is the SHA-256 of pub's SubjectPublicKeyInfo DER, as 64
// lowercase hex characters: the fingerprint a device shows for the key it
// made, and the one the operator confirms (ADR 0020 decision 3).
func KeyFingerprint(pub any) (string, error) {
	return fcrypto.KeyFingerprint(pub)
}

// CertKeyFingerprint is KeyFingerprint of the key the first CERTIFICATE in
// certPEM certifies.
func CertKeyFingerprint(certPEM []byte) (string, error) {
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return "", errors.New("identity: no certificate in the PEM given")
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("identity: parse certificate: %w", err)
		}
		return KeyFingerprint(cert.PublicKey)
	}
}

// fingerprintHexLen is a SHA-256 fingerprint's length in hex.
const fingerprintHexLen = 64

// minSuffixHex is the shortest typed confirmation FingerprintSuffixMatches
// takes: the last 8 groups, 128 bits, P-256's security level.
const minSuffixHex = 32

// FormatFingerprint groups a fingerprint for reading aloud and comparing by
// eye: 16 groups of 4 hex characters, single spaces ("3f2a 9c01 … 3c21"). It
// returns its input unchanged when that is not 64 hex characters.
func FormatFingerprint(fp string) string {
	if !isHex(fp) || len(fp) != fingerprintHexLen {
		return fp
	}
	return group(fp)
}

// FingerprintTail is the last 4 groups of a fingerprint ("d1b2 6e57 90af
// 3c21"), for display beside a record. It is never a confirmation:
// FingerprintSuffixMatches is. It returns its input unchanged when that is not
// 64 hex characters.
func FingerprintTail(fp string) string {
	if !isHex(fp) || len(fp) != fingerprintHexLen {
		return fp
	}
	return group(fp[fingerprintHexLen-16:])
}

// ParseFingerprint reads a fingerprint as a person or a script gives it:
// spaces and colons are dropped, upper case is lowered, and exactly 64 hex
// characters must remain. The error never repeats the input.
func ParseFingerprint(s string) (string, error) {
	n := normalizeFingerprint(s)
	if !isHex(n) {
		return "", errors.New("identity: a key fingerprint is hexadecimal (0-9, a-f), optionally grouped by spaces or colons")
	}
	if len(n) != fingerprintHexLen {
		return "", fmt.Errorf("identity: a key fingerprint is %d hex characters (SHA-256), and %d were given", fingerprintHexLen, len(n))
	}
	return n, nil
}

// FingerprintSuffixMatches normalizes typed as ParseFingerprint does (spaces
// and colons stripped, lowercased) and reports whether it is a suffix of fp.
// It returns an error, and false, when fp is not 64 lowercase hex, or when
// typed is not 32 to 64 hex characters after normalizing: fewer than the last
// 8 groups would bind less than P-256's 128-bit security level.
//
// It is the one helper here that confirms anything.
func FingerprintSuffixMatches(fp, typed string) (bool, error) {
	if len(fp) != fingerprintHexLen || !isHex(fp) || strings.ToLower(fp) != fp {
		return false, errors.New("identity: the fingerprint to confirm is not 64 lowercase hex characters")
	}
	t := normalizeFingerprint(typed)
	if !isHex(t) {
		return false, errors.New("identity: a key fingerprint is hexadecimal (0-9, a-f), optionally grouped by spaces or colons")
	}
	if len(t) < minSuffixHex || len(t) > fingerprintHexLen {
		return false, fmt.Errorf("identity: confirm a key with at least its last 8 groups (%d to %d hex characters), and %d were given", minSuffixHex, fingerprintHexLen, len(t))
	}
	return strings.HasSuffix(fp, t), nil
}

// normalizeFingerprint drops the separators a fingerprint is shown or typed
// with (spaces, colons, and the whitespace a terminal adds) and lowers case.
func normalizeFingerprint(s string) string {
	return strings.ToLower(strings.Map(func(r rune) rune {
		switch r {
		case ' ', ':', '\t', '\r', '\n':
			return -1
		}
		return r
	}, s))
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// group splits hex into groups of 4 joined by single spaces.
func group(h string) string {
	var b strings.Builder
	for i := 0; i < len(h); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(h[i:min(i+4, len(h))])
	}
	return b.String()
}
