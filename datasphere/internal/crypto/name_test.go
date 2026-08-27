package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"io"
	"strings"
	"testing"
)

// Frozen name-tokenization vectors. Every token below is
// HMAC-SHA-256(tokenKey, the exact joined logical path prefix) truncated to
// TokenBytes and lowercase-hex encoded, where tokenKey is the frozen
// goldenTokenKeyHex. All of them were reproduced from an independent Python
// implementation before being written here; see the freeze notice in
// crypto_test.go. They are never to be regenerated from this package.
const (
	tokHelloTxt = "f4648b0bc77e132321a61a18c7a32932" // "hello.txt"
	tokApp      = "c9cecc9b7f4853102560820aaea1bb0a" // "app"
	tokAppBlue  = "f6b28c7a4db185596889bf9f43f6f0e5" // "app/blue"
	tokAppBlueW = "11a4f3a038c7fbabaae4c8cbff9b0adc" // "app/blue/web"
	tokAppCfg   = "cfff7e0e4703e6277a952ba8f926da33" // "app/blue/web/config.json"
	tokUsers    = "d9d6f79588dea3cfeb8942524f3811cd" // "users"
	tokUsersAl  = "c83b22024ff9fecac85fd25f35eb7e5f" // "users/alice"
	tokUsersPro = "f7d44d8c7abbd25f8503f59d4ec08703" // "users/alice/profile.json"

	storedHelloTxt = tokHelloTxt
	storedAppCfg   = tokApp + "/" + tokAppBlue + "/" + tokAppBlueW + "/" + tokAppCfg
	storedUsersPro = tokUsers + "/" + tokUsersAl + "/" + tokUsersPro
)

// goldenTokenKey resolves the frozen token key. Tests take it from the literal
// rather than from NameTokenKey so that a derivation regression shows up as
// the one dedicated failure in TestDeriveMatchesReferenceHKDF instead of
// cascading through every name test.
func goldenTokenKey(t *testing.T) []byte {
	t.Helper()
	return mustHex(t, goldenTokenKeyHex)
}

// sealRawName seals an arbitrary, possibly non-canonical plaintext as a name
// block for storedPath. It derives the per-object key through referenceHKDF
// and builds the AAD from storedPath literally, so the blocks it produces are
// valid to OpenName in every respect except the interior under test.
func sealRawName(t *testing.T, nameKey []byte, storedPath string, plaintext []byte, rnd io.Reader) []byte {
	t.Helper()
	block, err := aes.NewCipher(referenceHKDF(nameKey, infoNameCryptPrefix+storedPath))
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	nonce := make([]byte, NonceLen)
	if _, err := io.ReadFull(rnd, nonce); err != nil {
		t.Fatalf("read nonce: %v", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, []byte(storedPath))
}

// TestTokenPathGolden freezes the chained tokens. Truncation to TokenBytes is
// load-bearing — it is what buys ~31 segments of depth under GCS's 1024-byte
// object-name cap — so the width of these strings is part of the format, not a
// rendering choice.
func TestTokenPathGolden(t *testing.T) {
	tokenKey := goldenTokenKey(t)

	for _, tc := range []struct {
		logical string
		want    string
	}{
		{"hello.txt", storedHelloTxt},
		{"app", tokApp},
		{"app/blue", tokApp + "/" + tokAppBlue},
		{"app/blue/web", tokApp + "/" + tokAppBlue + "/" + tokAppBlueW},
		{"app/blue/web/config.json", storedAppCfg},
		{"users/alice/profile.json", storedUsersPro},
	} {
		if got := TokenPath(tokenKey, tc.logical); got != tc.want {
			t.Errorf("TokenPath(%q) = %s, want the frozen vector %s", tc.logical, got, tc.want)
		}
	}
}

// TestTokenPathIsChained pins the property the whole naming scheme is built
// on: every /-aligned logical prefix tokenizes to a prefix of the stored path,
// which is what lets a cloud-side prefix list work with no index at all.
func TestTokenPathIsChained(t *testing.T) {
	tokenKey := goldenTokenKey(t)
	const logical = "app/blue/web/config.json"

	full := TokenPath(tokenKey, logical)
	for _, prefix := range []string{"app", "app/blue", "app/blue/web", logical} {
		stored := TokenPath(tokenKey, prefix)
		if !strings.HasPrefix(full, stored) {
			t.Errorf("TokenPath(%q) = %s is not a prefix of TokenPath(%q) = %s", prefix, stored, logical, full)
		}
	}
	if got := strings.Count(full, "/"); got != 3 {
		t.Errorf("stored path has %d separators, want 3 — separator structure is preserved deliberately", got)
	}
}

// TestTokenPathConfinesEqualityToPathPrefixes is the reason the tokens are
// chained rather than per-segment. A per-segment construction would correlate
// every occurrence of a common leaf name bucket-wide — with the reserved
// "system/" and "app/" literals as known plaintext — which is strictly more
// than prefix listing requires any scheme to reveal.
func TestTokenPathConfinesEqualityToPathPrefixes(t *testing.T) {
	tokenKey := goldenTokenKey(t)

	alpha := TokenPath(tokenKey, "alpha/notes")
	beta := TokenPath(tokenKey, "beta/notes")
	_, alphaLeaf, okAlpha := strings.Cut(alpha, "/")
	_, betaLeaf, okBeta := strings.Cut(beta, "/")
	if !okAlpha || !okBeta {
		t.Fatalf("TokenPath produced no leaf token: %s / %s", alpha, beta)
	}
	if alphaLeaf == betaLeaf {
		t.Errorf("the leaf %q tokenized identically under two parents (%s), leaking segment equality", "notes", alphaLeaf)
	}

	// The same logical path always tokenizes the same way — determinism is
	// what makes the stored name computable client-side.
	if TokenPath(tokenKey, "alpha/notes") != alpha {
		t.Error("TokenPath is not deterministic")
	}
}

// TestTokenPrefix covers the alignment rule. A token is an HMAC of a whole
// segment, so anything after the last "/" cannot be tokenized; the listing
// narrows to the aligned part and the caller filters the recovered logical
// names against the full prefix.
func TestTokenPrefix(t *testing.T) {
	tokenKey := goldenTokenKey(t)

	for _, tc := range []struct {
		name   string
		prefix string
		want   string
	}{
		{"aligned with trailing slash", "users/", tokUsers + "/"},
		{"partial segment", "users/al", tokUsers + "/"},
		{"partial segment, deeper", "users/alice/prof", tokUsers + "/" + tokUsersAl + "/"},
		{"aligned two segments", "users/alice/", tokUsers + "/" + tokUsersAl + "/"},
		{"empty prefix lists everything", "", ""},
		{"single partial segment has nothing aligned", "user", ""},
		{"leading slash names an empty first segment", "/users", ""},
		{"bare slash", "/", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := TokenPrefix(tokenKey, tc.prefix); got != tc.want {
				t.Errorf("TokenPrefix(%q) = %q, want %q", tc.prefix, got, tc.want)
			}
		})
	}
}

// TestTokenPrefixAlignmentRule states the rule as an identity rather than as a
// pair of frozen strings: a non-aligned prefix must list under exactly the
// aligned part's stored path plus a separator. Anything else either over-lists
// the whole bucket or, far worse, narrows to a prefix that omits matching
// objects.
func TestTokenPrefixAlignmentRule(t *testing.T) {
	tokenKey := goldenTokenKey(t)

	if got, want := TokenPrefix(tokenKey, "users/al"), TokenPath(tokenKey, "users")+"/"; got != want {
		t.Errorf("TokenPrefix(%q) = %q, want TokenPath(%q)+\"/\" = %q", "users/al", got, "users", want)
	}

	// And the narrowing must actually contain the objects it claims to: the
	// stored path of a key under the logical prefix starts with it.
	stored := TokenPath(tokenKey, "users/alice/profile.json")
	if prefix := TokenPrefix(tokenKey, "users/al"); !strings.HasPrefix(stored, prefix) {
		t.Errorf("stored path %s is not under the listed prefix %s", stored, prefix)
	}
}

// TestPadNameGolden freezes the sealed name's interior: a uint16 big-endian
// length, the key's exact bytes, and zero padding of the whole thing to
// NamePadUnit. Padding the length prefix together with the name is what makes
// the encoding canonical — exactly one valid plaintext per name — and the
// 32-byte unit is what quantizes the name length the cloud can observe.
func TestPadNameGolden(t *testing.T) {
	for _, tc := range []struct {
		logical string
		want    string
	}{
		{"hello.txt", "0009" + "68656c6c6f2e747874" + strings.Repeat("00", 21)},
		{"app/blue/web/config.json", "0018" + "6170702f626c75652f7765622f636f6e6669672e6a736f6e" + strings.Repeat("00", 6)},
		{"a", "0001" + "61" + strings.Repeat("00", 29)},
	} {
		got, err := padName(tc.logical)
		if err != nil {
			t.Fatalf("padName(%q): %v", tc.logical, err)
		}
		if hex.EncodeToString(got) != tc.want {
			t.Errorf("padName(%q) = %x, want the frozen vector %s", tc.logical, got, tc.want)
		}
	}
}

// TestPadNameQuantization pins where the 32-byte buckets fall. The cloud sees
// the sealed name's length, so this is the exact resolution at which a logical
// name's length leaks — 30 bytes of name is the last that fits one unit.
func TestPadNameQuantization(t *testing.T) {
	for _, tc := range []struct {
		nameLen int
		want    int
	}{
		{1, 32}, {29, 32}, {30, 32}, {31, 64}, {62, 64}, {63, 96}, {MaxKeyBytes, 1056},
	} {
		got, err := padName(strings.Repeat("x", tc.nameLen))
		if err != nil {
			t.Fatalf("padName(%d bytes): %v", tc.nameLen, err)
		}
		if len(got) != tc.want {
			t.Errorf("padName(%d bytes) is %d bytes, want %d", tc.nameLen, len(got), tc.want)
		}
	}

	if _, err := padName(strings.Repeat("x", MaxKeyBytes+1)); err == nil {
		t.Error("padName accepted a name over MaxKeyBytes")
	} else {
		mustErrIs(t, "padName over MaxKeyBytes", err, ErrInvalidKey)
	}
}

// TestSealNameGolden freezes the sealed block and, separately, opens it with a
// hand-built AES-GCM whose key comes from referenceHKDF and whose AAD is the
// stored path written out literally. That second half is what pins the
// derivation info string and the AAD choice: the block would still round-trip
// through this package if both were changed together, and would not still open
// here.
func TestSealNameGolden(t *testing.T) {
	nameKey := mustHex(t, goldenNameKeyHex)

	for _, tc := range []struct {
		name         string
		logical      string
		stored       string
		seed         byte
		wantKey      string // the per-object seal key
		wantSealed   string
		wantInterior string
	}{
		{
			name:         "single segment",
			logical:      "hello.txt",
			stored:       storedHelloTxt,
			seed:         0x3c,
			wantKey:      "898636e5720bf934ed1b5669e8c49828c0e22e8fbd356af289545e479de8960a",
			wantSealed:   "3c3d3e3f4041424344454647" + "2a3466b369c01b4b17fb5f087a4a23f180ed74e3380c435732dff9de68e7e65e" + "2e1699dfd5a1c6f738453d2008d40418",
			wantInterior: "0009" + "68656c6c6f2e747874" + strings.Repeat("00", 21),
		},
		{
			name:         "multi segment",
			logical:      "app/blue/web/config.json",
			stored:       storedAppCfg,
			seed:         0xcc,
			wantKey:      "1e8ebc4a6c86ed66f246830dbe586d444a5fb35a7329ccdf15f9e73a69990562",
			wantSealed:   "cccdcecfd0d1d2d3d4d5d6d7" + "29e165e49c019ca17741009aec071c0b0b2a0a4d0582ad2d043e29097e02b550" + "d97c5ecc093027713621f30c33c3124e",
			wantInterior: "0018" + "6170702f626c75652f7765622f636f6e6669672e6a736f6e" + strings.Repeat("00", 6),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The per-object key, independently derived.
			if got := hex.EncodeToString(referenceHKDF(nameKey, infoNameCryptPrefix+tc.stored)); got != tc.wantKey {
				t.Fatalf("reference per-object key = %s, want the frozen vector %s", got, tc.wantKey)
			}

			sealed, err := SealName(nameKey, tc.stored, tc.logical, &countingReader{next: tc.seed})
			if err != nil {
				t.Fatalf("SealName: %v", err)
			}
			if got := hex.EncodeToString(sealed); got != tc.wantSealed {
				t.Fatalf("SealName = %s, want the frozen vector %s", got, tc.wantSealed)
			}
			if len(sealed) != NonceLen+len(tc.wantInterior)/2+TagLen {
				t.Errorf("sealed block is %d bytes, want nonce+interior+tag", len(sealed))
			}

			// Open it without this package: the seal key from referenceHKDF,
			// the AAD written out as the stored path's bytes.
			block, err := aes.NewCipher(referenceHKDF(nameKey, infoNameCryptPrefix+tc.stored))
			if err != nil {
				t.Fatalf("aes.NewCipher: %v", err)
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				t.Fatalf("cipher.NewGCM: %v", err)
			}
			interior, err := gcm.Open(nil, sealed[:NonceLen], sealed[NonceLen:], []byte(tc.stored))
			if err != nil {
				t.Fatalf("independent open of the sealed name: %v", err)
			}
			if got := hex.EncodeToString(interior); got != tc.wantInterior {
				t.Errorf("sealed-name interior = %s, want the frozen vector %s", got, tc.wantInterior)
			}

			// And the package's own reader agrees.
			name, err := OpenName(nameKey, tc.stored, sealed)
			if err != nil {
				t.Fatalf("OpenName: %v", err)
			}
			if name != tc.logical {
				t.Errorf("OpenName = %q, want %q", name, tc.logical)
			}
		})
	}
}

// TestSealNameRoundTrip covers the shapes the golden vectors do not: the
// boundaries of the padding unit, and the longest key the format accepts.
func TestSealNameRoundTrip(t *testing.T) {
	nameKey := mustHex(t, goldenNameKeyHex)
	tokenKey := goldenTokenKey(t)

	for _, logical := range []string{
		"a",
		strings.Repeat("x", 30),
		strings.Repeat("x", 31),
		"a/b/c/d/e/f/g",
		"notes/café.txt",
		strings.Repeat("x", MaxKeyBytes),
	} {
		stored := TokenPath(tokenKey, logical)
		sealed, err := SealName(nameKey, stored, logical, &countingReader{})
		if err != nil {
			t.Fatalf("SealName(%d-byte key): %v", len(logical), err)
		}
		got, err := OpenName(nameKey, stored, sealed)
		if err != nil {
			t.Fatalf("OpenName(%d-byte key): %v", len(logical), err)
		}
		if got != logical {
			t.Errorf("round trip of a %d-byte key returned %d bytes", len(logical), len(got))
		}
	}
}

// TestSealNameIsPerObjectKeyed pins the derivation that removes the name key's
// nonce budget. Two objects sealed with the identical nonce and the identical
// logical name must still produce different ciphertexts, because the key is
// derived from the stored path. The name key is the one key in this design
// that cannot rotate, so it must not be the key carrying a bound.
func TestSealNameIsPerObjectKeyed(t *testing.T) {
	nameKey := mustHex(t, goldenNameKeyHex)
	const logical = "hello.txt"

	a, err := SealName(nameKey, storedHelloTxt, logical, &countingReader{next: 0x3c})
	if err != nil {
		t.Fatalf("SealName: %v", err)
	}
	b, err := SealName(nameKey, storedUsersPro, logical, &countingReader{next: 0x3c})
	if err != nil {
		t.Fatalf("SealName: %v", err)
	}
	if string(a[:NonceLen]) != string(b[:NonceLen]) {
		t.Fatal("the two seals did not reuse the nonce; the test is not exercising what it claims")
	}
	if string(a) == string(b) {
		t.Error("identical name and nonce produced identical ciphertext under two stored paths — the seal key is not per-object")
	}
}

// TestOpenNameRejectsTransplant is the sealed-name transplant case: a mapping
// lifted from one object onto another must not authenticate. Two independent
// mechanisms refuse it — the per-object derived key and the stored-path AAD —
// and either alone would be enough, which is the point of belt and braces on a
// field the cloud can rewrite.
func TestOpenNameRejectsTransplant(t *testing.T) {
	nameKey := mustHex(t, goldenNameKeyHex)

	sealed, err := SealName(nameKey, storedHelloTxt, "hello.txt", &countingReader{next: 0x3c})
	if err != nil {
		t.Fatalf("SealName: %v", err)
	}
	if _, err := OpenName(nameKey, storedUsersPro, sealed); err == nil {
		t.Fatal("a sealed name opened under a foreign stored path")
	} else {
		mustErrIs(t, "OpenName transplanted", err, ErrIntegrity)
	}

	// A foreign name key is refused too — the sealed name is not a hint, it is
	// ciphertext.
	other := mustHex(t, goldenKEK2Hex)
	if _, err := OpenName(other, storedHelloTxt, sealed); err == nil {
		t.Fatal("a sealed name opened under a foreign name key")
	} else {
		mustErrIs(t, "OpenName with a foreign name key", err, ErrIntegrity)
	}
}

// TestOpenNameRejectsNonCanonicalInterior pins unpadName's canonicality rules.
// The blocks here are sealed with the object's real derived key and its real
// AAD, so they authenticate perfectly; only the interior is wrong. Both
// non-minimal padding and non-zero pad bytes are refused because either is a
// channel a writer could smuggle bytes through, invisible to every reader that
// only ever looked at the name it got back.
func TestOpenNameRejectsNonCanonicalInterior(t *testing.T) {
	nameKey := mustHex(t, goldenNameKeyHex)
	const logical = "hello.txt"

	padded := func(total int, n uint16, body string) []byte {
		out := make([]byte, total)
		binary.BigEndian.PutUint16(out, n)
		copy(out[2:], body)
		return out
	}

	canonical := padded(32, uint16(len(logical)), logical)
	for _, tc := range []struct {
		name      string
		interior  []byte
		wantOpen  bool
		wantError error
	}{
		{name: "canonical control", interior: canonical, wantOpen: true},
		{
			// paddedLen(2+9) is 32, so a 64-byte block is not the one
			// encoding of this name even though every pad byte is zero.
			name:      "non-minimal padding",
			interior:  padded(64, uint16(len(logical)), logical),
			wantError: ErrIntegrity,
		},
		{
			name: "non-zero pad byte",
			interior: func() []byte {
				b := padded(32, uint16(len(logical)), logical)
				b[31] = 0x01
				return b
			}(),
			wantError: ErrIntegrity,
		},
		{
			name:      "length overruns the block",
			interior:  padded(32, 0xffff, logical),
			wantError: ErrIntegrity,
		},
		{
			name:      "length shorter than the bytes present",
			interior:  padded(32, 4, logical),
			wantError: ErrIntegrity,
		},
		{
			name:      "not a multiple of NamePadUnit",
			interior:  padded(33, uint16(len(logical)), logical),
			wantError: ErrIntegrity,
		},
		{
			name:      "empty interior",
			interior:  []byte{},
			wantError: ErrIntegrity,
		},
		{
			name:      "invalid utf-8 name",
			interior:  padded(32, 2, "\xff\xfe"),
			wantError: ErrIntegrity,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sealed := sealRawName(t, nameKey, storedHelloTxt, tc.interior, &countingReader{next: 0x11})
			name, err := OpenName(nameKey, storedHelloTxt, sealed)
			if tc.wantOpen {
				if err != nil {
					t.Fatalf("OpenName: %v — the control block must open, or the other cases prove nothing", err)
				}
				if name != logical {
					t.Fatalf("OpenName = %q, want %q", name, logical)
				}
				return
			}
			if err == nil {
				t.Fatalf("OpenName accepted a non-canonical interior, returning %q", name)
			}
			mustErrIs(t, "OpenName", err, tc.wantError)
			if name != "" {
				t.Errorf("OpenName returned %q alongside an error", name)
			}
		})
	}
}

// TestOpenNameRejectsShortBlock covers the length check that runs before any
// key is touched: a block too small to hold a nonce and a tag is not a
// truncated name, it is not a name.
func TestOpenNameRejectsShortBlock(t *testing.T) {
	nameKey := mustHex(t, goldenNameKeyHex)

	for _, size := range []int{0, 1, NonceLen, NonceLen + TagLen - 1} {
		if _, err := OpenName(nameKey, storedHelloTxt, make([]byte, size)); err == nil {
			t.Errorf("OpenName accepted a %d-byte block", size)
		} else {
			mustErrIs(t, "OpenName short block", err, ErrIntegrity)
		}
	}
}
