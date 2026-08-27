// Package crypto implements DataSphere's encryption layer: envelope
// encryption of object bodies, deterministic tokenization of object names,
// and the version-1 blob format that carries both.
//
// It is deliberately free of any cloud, provider, or file concept. Everything
// here operates on key material handed in by the caller and returns bytes;
// nothing in this package reads a file, opens a socket, or knows what a
// bucket is. That is what makes the layering above it — Store as the only
// holder of plaintext with a route to a cloud — enforceable rather than
// aspirational.
//
// The wire format and every derived key are specified in ../../README.md and
// frozen by the golden vectors in blob_test.go. Changing a constant here is
// silent data loss for every object already stored; the version byte is the
// only supported way to change the format.
package crypto

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Errors returned by this package. The root datasphere package re-exports
// them, so callers classify with errors.Is against either name.
var (
	// ErrIntegrity reports that stored bytes failed authentication — modified,
	// corrupted, truncated, or swapped. Every parse failure funnels here too:
	// a caller must not be able to tell "this is not a FarCast blob" from
	// "this blob was tampered with", and neither answer justifies returning
	// any plaintext.
	ErrIntegrity = errors.New("datasphere: stored data failed integrity check")

	// ErrUnknownKey reports that a blob names a key ID the keyring does not
	// hold. The key ID is cloud-writable plaintext read before authentication
	// can run, so this error is reachable by an adversary at will; nothing on
	// this path may recommend a destructive recovery.
	ErrUnknownKey = errors.New("datasphere: blob is sealed under a key the keyring does not hold")

	// ErrTooLarge reports a plaintext over MaxPlaintext.
	ErrTooLarge = errors.New("datasphere: object exceeds the size limit")

	// ErrInvalidKey reports a malformed logical key.
	ErrInvalidKey = errors.New("datasphere: invalid object key")
)

// Version is the buffered blob format: whole objects, held in memory. It is
// the first byte after the magic and is bound into every AAD, so a downgrade
// cannot pass authentication.
const Version byte = 0x01

// Version2 is the chunked, streaming blob format. Bytes 0 through the end of
// the sealed name are laid out identically to Version — same fields, same
// offsets — and everything v2 adds comes after. That ordering is the whole
// reason ParseHeader, HeaderName and Rekey are one version-free
// implementation, which is in turn what makes the promise hold that a bucket
// plus a keys file reconstruct every logical name with no local state: a
// recovery tool written today reads names out of formats that do not exist
// yet.
const Version2 byte = 0x02

// Magic marks a DataSphere blob. It is a plaintext header field — it tells
// recovery tooling what it is looking at — and is bound into both AADs so it
// cannot be rewritten without detection.
var Magic = [4]byte{'F', 'C', 'D', 'S'}

// Fixed sizes of the format's building blocks.
const (
	// KeyLen is the length of every symmetric key in this design: AES-256.
	KeyLen = 32
	// KeyIDLen is the length of a keyring entry's identifier. IDs are random
	// bytes minted with the key and are never derived from it — a key-derived
	// ID would be an offline key-check oracle for anyone holding a blob.
	KeyIDLen = 8
	// NonceLen is AES-GCM's standard 96-bit nonce.
	NonceLen = 12
	// TagLen is AES-GCM's 128-bit authentication tag.
	TagLen = 16
	// WrappedDEKLen is a wrapped 256-bit DEK: ciphertext plus tag.
	WrappedDEKLen = KeyLen + TagLen
	// SaltLen is the per-object frame-nonce salt v2 carries.
	SaltLen = 8
)

// Frame sizing for the chunked format. The size is stored as an exponent so
// one range check bounds it, and it is range-checked before it sizes any
// allocation — a hostile header must not be able to ask for a 4 GiB buffer.
const (
	// MinChunkExp and MaxChunkExp bound the frame size to 64 KiB … 64 MiB.
	MinChunkExp = 16
	MaxChunkExp = 26
	// DefaultChunkExp is 1 MiB. Read granularity is one frame, so a smaller
	// frame makes a small ranged read cheaper; the 16-byte tag per frame costs
	// 15 parts per million at this size.
	DefaultChunkExp = 20

	// MaxHeaderLen is the largest a header can be in any version: the fixed
	// 75-byte prefix, the longest possible sealed name, the salt, and the
	// exponent. A reader fetches exactly this many bytes and is guaranteed a
	// complete header in one request.
	MaxHeaderLen = HeaderLen + NonceLen + 1056 + TagLen + SaltLen + 1
)

// Header field offsets in a v1 blob. The header is fixed-width up to the
// sealed name, so a truncated blob is detected by length alone before any key
// is touched.
const (
	offMagic      = 0
	offVersion    = 4
	offKeyID      = 5
	offWrapNonce  = offKeyID + KeyIDLen           // 13
	offWrappedDEK = offWrapNonce + NonceLen       // 25
	offNameLen    = offWrappedDEK + WrappedDEKLen // 73
	// HeaderLen is the fixed prefix: everything up to and including the
	// sealed-name length field.
	HeaderLen = offNameLen + 2 // 75
)

// Limits on what may be stored.
const (
	// MaxPlaintext caps a single object at 64 MiB. The API holds whole objects
	// in []byte, so the cap is an honest statement of that: far under GCM's
	// per-invocation limit, and covering what a key-value API is for. Large
	// files arrive with 3.3's streaming `storage cp` as a chunked v2 format
	// behind the version byte; no v1 migration will be required.
	MaxPlaintext = 64 << 20

	// MaxKeyBytes and MaxKeySegments bound a logical key so its tokenized form
	// stays inside the cloud's object-name limit: 30 segments tokenize to
	// 30*32 + 29 = 989 bytes, under GCS's 1024.
	MaxKeyBytes    = 1024
	MaxKeySegments = 30

	// NamePadUnit rounds the sealed name's plaintext up to a multiple of 32
	// bytes, so a stored ciphertext's size reveals a name's length only to the
	// nearest 32-byte bucket.
	NamePadUnit = 32

	// TokenBytes is how much of each name HMAC is kept, rendered as 2*TokenBytes
	// lowercase hex characters. Truncation is load-bearing — it buys the
	// segment depth above — and the collision probability over distinct path
	// prefixes (~N²/2¹²⁹) is negligible at any realistic scale.
	TokenBytes = 16
)

// HKDF info strings. Every derived key in this design is a single-shot
// hkdf.Key with SHA-256, a nil salt, and a 32-byte output; only the info
// string differs. Two conforming implementations must produce identical bytes,
// so these are spec, not implementation detail.
const (
	infoNameToken       = "farcast/datasphere/v1/name-token"
	infoNameCryptPrefix = "farcast/datasphere/v1/name-crypt/"
)

// Key is one keyring entry reduced to what this package needs.
type Key struct {
	ID       [KeyIDLen]byte
	Material []byte // KeyLen bytes
}

// KeyLookup resolves a wrap key's material by its ID, reporting false when the
// keyring holds no such entry.
type KeyLookup func(id [KeyIDLen]byte) ([]byte, bool)

// ValidateLogicalKey enforces the logical-key rules. The key's exact bytes
// participate in authentication, so there is deliberately no normalization
// here — no Unicode folding, no slash collapsing, no trimming. A "helpful"
// canonicalization applied on write but not on read would turn valid data
// permanently unreadable.
func ValidateLogicalKey(key string) error {
	switch {
	case key == "":
		return wrapKeyErr("must not be empty")
	case !utf8.ValidString(key):
		return wrapKeyErr("must be valid UTF-8")
	case len(key) > MaxKeyBytes:
		return wrapKeyErr("must be at most %d bytes, got %d", MaxKeyBytes, len(key))
	case strings.HasSuffix(key, "/"):
		return wrapKeyErr("must not end in %q", "/")
	}
	segments := strings.Split(key, "/")
	if len(segments) > MaxKeySegments {
		return wrapKeyErr("must have at most %d %q-separated segments, got %d", MaxKeySegments, "/", len(segments))
	}
	for _, s := range segments {
		if s == "" {
			return wrapKeyErr("must not contain an empty segment")
		}
	}
	return nil
}

// derive is the one HKDF call shape this design uses. Pinning it in a single
// helper is what keeps the parameters from drifting per call site.
func derive(secret []byte, info string) ([]byte, error) {
	return hkdf.Key(sha256.New, secret, nil, info, KeyLen)
}

// wrapKeyErr builds an ErrInvalidKey carrying why the key was refused. The
// reason names the rule, never the key: a logical key is exactly the material
// this module exists to keep out of logs.
func wrapKeyErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidKey, fmt.Sprintf(format, args...))
}
