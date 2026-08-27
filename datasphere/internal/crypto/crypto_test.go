package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// The freeze notice. Read this before changing anything below it.
//
// Every hex literal in this package's tests is a golden known-answer vector,
// and none of them may ever be regenerated from this package's own output.
// That prohibition is the entire value of them: this is data at rest. Objects
// an operator stored months ago are readable only if the format holds byte for
// byte, so a vector a refactor can re-derive from the refactored code pins
// nothing at all. There is deliberately no -update flag and no regeneration
// path anywhere in these files.
//
// How they were produced, so a future reader can re-audit rather than re-run:
//
//   - The HKDF outputs and the chained name tokens — the FarCast-specific
//     constructions, the ones no external test vector covers — were computed
//     independently in Python 3 from hashlib/hmac, with HKDF-SHA-256 written
//     out from RFC 5869 (extract = HMAC(32 zero bytes, secret); expand =
//     T(1) = HMAC(prk, info ‖ 0x01)) and the tokens as HMAC-SHA-256 over the
//     joined logical path prefix truncated to 16 bytes. Go and Python agree.
//   - The AES-GCM layers are Go's stdlib as the reference implementation; what
//     is pinned here is the byte LAYOUT around them — field offsets, both AAD
//     compositions, the sealed-name interior — and the round trip.
//   - referenceHKDF below re-derives every subkey from crypto/hmac primitives
//     inside the test binary, so the spec's HKDF parameters are pinned
//     structurally too, not only as frozen strings.
//
// If one of these vectors fails, the change under test is a format change. A
// format change means a new version byte and a v1 reader that still works — it
// never means an edited constant.
// ---------------------------------------------------------------------------

// Golden key material. Counter-derived rather than random so that a reader can
// check by eye which bytes of a frozen blob came from a key and which from the
// rand seam. Production keys are 32 bytes from crypto/rand; nothing here is a
// suggestion about how to mint one.
const (
	goldenNameKeyHex = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
	goldenKEK1Hex    = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
	goldenKEK2Hex    = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"

	goldenKEK1IDHex = "8f3a19c2d4e5b607"
	goldenKEK2IDHex = "a1b2c3d4e5f60718"
	// goldenSiblingIDHex is goldenKEK1IDHex with the lowest bit of the last
	// byte flipped. The tamper suite needs a keyring that actually holds the ID
	// a one-bit edit of the header lands on, so that the key-ID region can be
	// shown to produce ErrIntegrity as well as ErrUnknownKey.
	goldenSiblingIDHex = "8f3a19c2d4e5b606"

	// goldenTokenKeyHex is HKDF-SHA-256(goldenNameKey, info
	// "farcast/datasphere/v1/name-token"). Cross-checked against the Python
	// reference described above.
	goldenTokenKeyHex = "0d80dbb2466b420adb85c741bf74c47ca47cdf2f7dcc9bfa60b4cc983cac57cf"
)

// countingReader is the injectable rand seam the golden vectors ride on: a
// byte counter, so every DEK and nonce in a frozen blob is legible from the
// seed alone and the vectors are reproducible without embedding a CSPRNG's
// state. It is emphatically not randomness and exists nowhere but these tests;
// the properties that need real entropy (one DEK per write) use crypto/rand.
type countingReader struct{ next byte }

func (r *countingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.next
		r.next++
	}
	return len(p), nil
}

// referenceHKDF is RFC 5869 HKDF-SHA-256 written out from HMAC, so that the
// spec's pinned parameters — SHA-256, a nil salt (which is hashlen zero
// bytes), a 32-byte single-block output — are asserted structurally rather
// than only as frozen strings. It deliberately does not call crypto/hkdf: a
// change in how derive invokes the stdlib has to fail against something that
// is not the stdlib call under test.
func referenceHKDF(secret []byte, info string) []byte {
	salt := make([]byte, sha256.Size)
	extract := hmac.New(sha256.New, salt)
	extract.Write(secret)
	prk := extract.Sum(nil)

	expand := hmac.New(sha256.New, prk)
	expand.Write([]byte(info))
	expand.Write([]byte{0x01})
	return expand.Sum(nil)[:KeyLen]
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return raw
}

func mustKeyID(t *testing.T, s string) [KeyIDLen]byte {
	t.Helper()
	raw := mustHex(t, s)
	if len(raw) != KeyIDLen {
		t.Fatalf("key id %q is %d bytes, want %d", s, len(raw), KeyIDLen)
	}
	var id [KeyIDLen]byte
	copy(id[:], raw)
	return id
}

func mustKey(t *testing.T, idHex, materialHex string) Key {
	t.Helper()
	return Key{ID: mustKeyID(t, idHex), Material: mustHex(t, materialHex)}
}

// keyringOf builds the KEK resolver a keyring would supply, holding exactly
// the entries given and nothing else.
func keyringOf(keys ...Key) KeyLookup {
	return func(id [KeyIDLen]byte) ([]byte, bool) {
		for _, k := range keys {
			if k.ID == id {
				return k.Material, true
			}
		}
		return nil, false
	}
}

func mustErrIs(t *testing.T, what string, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("%s: error = %v, want %v", what, err, target)
	}
}

// TestFormatConstantsFrozen pins the wire constants themselves. Everything
// else in these files is downstream of these numbers, so an edit here that
// slipped past the golden blobs would still be caught by name.
func TestFormatConstantsFrozen(t *testing.T) {
	if string(Magic[:]) != "FCDS" {
		t.Errorf("Magic = %q, want %q", Magic, "FCDS")
	}
	if Version != 0x01 {
		t.Errorf("Version = %#x, want 0x01", Version)
	}

	for _, tc := range []struct {
		name string
		got  int
		want int
	}{
		{"offMagic", offMagic, 0},
		{"offVersion", offVersion, 4},
		{"offKeyID", offKeyID, 5},
		{"offWrapNonce", offWrapNonce, 13},
		{"offWrappedDEK", offWrappedDEK, 25},
		{"offNameLen", offNameLen, 73},
		{"HeaderLen", HeaderLen, 75},
		{"KeyLen", KeyLen, 32},
		{"KeyIDLen", KeyIDLen, 8},
		{"NonceLen", NonceLen, 12},
		{"TagLen", TagLen, 16},
		{"WrappedDEKLen", WrappedDEKLen, 48},
		{"MaxPlaintext", MaxPlaintext, 64 << 20},
		{"MaxKeyBytes", MaxKeyBytes, 1024},
		{"MaxKeySegments", MaxKeySegments, 30},
		{"NamePadUnit", NamePadUnit, 32},
		{"TokenBytes", TokenBytes, 16},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
		}
	}
}

// TestHKDFInfoStringsFrozen pins the info strings verbatim. The spec, not the
// first implementation, defines them: two conforming implementations must
// derive identical bytes, and a typo here is silently unreadable data for
// every object written by the other one.
func TestHKDFInfoStringsFrozen(t *testing.T) {
	if infoNameToken != "farcast/datasphere/v1/name-token" {
		t.Errorf("infoNameToken = %q", infoNameToken)
	}
	if infoNameCryptPrefix != "farcast/datasphere/v1/name-crypt/" {
		t.Errorf("infoNameCryptPrefix = %q", infoNameCryptPrefix)
	}
}

// TestDeriveMatchesReferenceHKDF pins the derivation parameters against an
// implementation of RFC 5869 that lives in the test binary, and against a
// frozen literal that a third implementation (Python) produced. Three
// independent routes to the same 32 bytes is what "two conforming
// implementations must produce identical bytes" costs to actually assert.
func TestDeriveMatchesReferenceHKDF(t *testing.T) {
	nameKey := mustHex(t, goldenNameKeyHex)

	for _, info := range []string{
		infoNameToken,
		infoNameCryptPrefix + "f4648b0bc77e132321a61a18c7a32932",
		infoNameCryptPrefix, // the empty stored path: still a valid single-shot derivation
	} {
		got, err := derive(nameKey, info)
		if err != nil {
			t.Fatalf("derive(%q): %v", info, err)
		}
		if len(got) != KeyLen {
			t.Fatalf("derive(%q) returned %d bytes, want %d", info, len(got), KeyLen)
		}
		if want := referenceHKDF(nameKey, info); string(got) != string(want) {
			t.Errorf("derive(%q) = %x, reference HKDF = %x", info, got, want)
		}
	}

	tokenKey, err := NameTokenKey(nameKey)
	if err != nil {
		t.Fatalf("NameTokenKey: %v", err)
	}
	if got := hex.EncodeToString(tokenKey); got != goldenTokenKeyHex {
		t.Errorf("NameTokenKey = %s, want the frozen vector %s", got, goldenTokenKeyHex)
	}
}

// TestValidateLogicalKey covers the caps and every ErrInvalidKey case. The
// rules are a data-at-rest contract as much as the blob format is: the key's
// exact bytes are the data seal's AAD, so a rule loosened on write and not on
// read is data that can be stored and never read back.
func TestValidateLogicalKey(t *testing.T) {
	for _, tc := range []struct {
		name    string
		key     string
		wantErr bool
	}{
		{"single segment", "hello.txt", false},
		{"multi segment", "app/blue/web/config.json", false},
		{"reserved system prefix", "system/secrets/db", false},
		{"dot segments are ordinary bytes", "a/./../b", false},
		{"spaces and punctuation", "my notes/2026 Q3 (draft).md", false},
		{"non-normalized unicode", "notes/café.txt", false},
		{"exactly MaxKeyBytes", strings.Repeat("x", MaxKeyBytes), false},
		{"exactly MaxKeySegments", strings.Repeat("a/", MaxKeySegments-1) + "a", false},

		{"empty", "", true},
		{"over MaxKeyBytes", strings.Repeat("x", MaxKeyBytes+1), true},
		{"over MaxKeySegments", strings.Repeat("a/", MaxKeySegments) + "a", true},
		{"empty interior segment", "a//b", true},
		{"trailing slash", "a/b/", true},
		{"bare slash", "/", true},
		{"leading slash is an empty first segment", "/a", true},
		{"invalid utf-8", "bad\xffkey", true},
		{"invalid utf-8 mid-path", "a/\xc3/b", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateLogicalKey(tc.key)
			switch {
			case tc.wantErr && err == nil:
				t.Fatalf("ValidateLogicalKey(%q) = nil, want ErrInvalidKey", tc.name)
			case tc.wantErr:
				mustErrIs(t, "ValidateLogicalKey", err, ErrInvalidKey)
			case err != nil:
				t.Fatalf("ValidateLogicalKey(%s) = %v, want nil", tc.name, err)
			}
		})
	}
}

// TestValidateLogicalKeyErrorOmitsTheKey holds the line that the rest of this
// module exists to hold: a logical key is exactly the material the cloud must
// never see, and an error message is a string that ends up in logs, terminals,
// and bug reports. The reason names the rule, never the key.
func TestValidateLogicalKeyErrorOmitsTheKey(t *testing.T) {
	const secret = "lawsuit-2026/plaintiff-roster.csv/"

	err := ValidateLogicalKey(secret)
	mustErrIs(t, "ValidateLogicalKey", err, ErrInvalidKey)
	for _, leak := range []string{"lawsuit", "plaintiff", "roster"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error %q leaked %q from the logical key", err, leak)
		}
	}
}
