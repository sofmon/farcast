package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// The freeze notice in crypto_test.go governs this file too, and governs it
// hardest: what is frozen below is the complete byte image of a stored object.
//
// Every literal here was produced by an independent implementation of the spec
// written in Python 3 — AES and GCM written out from FIPS 197 and SP 800-38D
// and validated against the published NIST GCM vectors, HKDF written out from
// RFC 5869 and validated against its test case 3 — and only then compared with
// this package. The two agreed byte for byte. That ordering is the whole point:
// a vector printed from the code under test freezes nothing, because the next
// refactor prints a new one just as happily.
//
// There is no -update flag, and adding one would defeat the file.

// Frozen magic and version, spelled as the bytes on the wire rather than
// referenced through the package's own constants — a vector that reads its
// expectations out of the code it tests is not a vector.
const (
	goldenMagicHex   = "46434453" // "FCDS"
	goldenVersionHex = "01"
)

// blobVector is one complete frozen blob, kept field by field so that the
// offsets are pinned by the literal's own structure: a field that moved would
// have to move here too, visibly, rather than hiding inside one long string.
type blobVector struct {
	name      string
	logical   string
	stored    string // the tokenized path, from the frozen name vectors
	plaintext string
	seed      byte // the counting reader's start byte

	keyID      string
	wrapNonce  string
	wrappedDEK string
	nameLen    string
	nameNonce  string
	nameCT     string
	nameTag    string
	dataNonce  string
	bodyCT     string
	bodyTag    string

	// The two AAD layouts, written out as bytes. data AAD = magic ‖ version ‖
	// logical key; wrap AAD = magic ‖ version ‖ key ID.
	wrapAAD string
	dataAAD string

	// rekeyedWrappedDEK is the same DEK re-wrapped under goldenKEK2 with a
	// 0x50-seeded wrap nonce — the header rewrite `storage rekey` performs.
	rekeyedWrappedDEK string
}

func (v blobVector) sealedNameHex() string { return v.nameNonce + v.nameCT + v.nameTag }

func (v blobVector) blobHex() string {
	return goldenMagicHex + goldenVersionHex + v.keyID + v.wrapNonce + v.wrappedDEK +
		v.nameLen + v.sealedNameHex() + v.dataNonce + v.bodyCT + v.bodyTag
}

// goldenBlobs are the two frozen cases the spec calls for: a simple ASCII key
// with a short body, and a multi-segment key with an empty body. The empty body
// is not a curiosity — a zero-byte object is legal, and it is the case where a
// length bug in the body slicing would otherwise pass unnoticed.
var goldenBlobs = []blobVector{
	{
		name:              "ascii key, short body",
		logical:           "hello.txt",
		stored:            storedHelloTxt,
		plaintext:         "hello, world",
		seed:              0x00,
		keyID:             goldenKEK1IDHex,
		wrapNonce:         "202122232425262728292a2b",
		wrappedDEK:        "9bbfd987523db6ef196800b652099a5c2cb6b6ecfc8479535620a8885059698048b70a3b504e24afecfc59c70871ad8a",
		nameLen:           "003c",
		nameNonce:         "2c2d2e2f3031323334353637",
		nameCT:            "87bd636400e7636a1420d55a1d4ddab1dfd73436842e7261d6742ff3a06abd6a",
		nameTag:           "05b237236615c7a6e4605a31e19e600c",
		dataNonce:         "38393a3b3c3d3e3f40414243",
		bodyCT:            "1419ce1ce7cca6f48864301e",
		bodyTag:           "e5c15750c6f678292267d0cf3ae0dc45",
		wrapAAD:           "46434453" + "01" + "8f3a19c2d4e5b607",
		dataAAD:           "46434453" + "01" + "68656c6c6f2e747874",
		rekeyedWrappedDEK: "783c18fb6e7e0b627698e92ca5381ffef3a3d3e78058e3c3a02e432278ca94153b0a04d8b50a8842024c905c7bde2fca",
	},
	{
		name:              "multi-segment key, empty body",
		logical:           "app/blue/web/config.json",
		stored:            storedAppCfg,
		plaintext:         "",
		seed:              0x80,
		keyID:             goldenKEK1IDHex,
		wrapNonce:         "a0a1a2a3a4a5a6a7a8a9aaab",
		wrappedDEK:        "808ef2b3d82515b7f6e68c3d088c04093dbb9422bb1d14ba58391ca09c4b4f436a844ddb9d0eefbbe88b900a2ce7bfb6",
		nameLen:           "003c",
		nameNonce:         "acadaeafb0b1b2b3b4b5b6b7",
		nameCT:            "53136378ee6cc5828098b9a691439f4b8a1dc6c77c8c19a3f3bab4cb42207393",
		nameTag:           "2b4e47bf6d9e44457f1cc3ed81a28495",
		dataNonce:         "b8b9babbbcbdbebfc0c1c2c3",
		bodyCT:            "",
		bodyTag:           "e9c5040a89713a8e35fe0793ae6404fd",
		wrapAAD:           "46434453" + "01" + "8f3a19c2d4e5b607",
		dataAAD:           "46434453" + "01" + "6170702f626c75652f7765622f636f6e6669672e6a736f6e",
		rekeyedWrappedDEK: "f8bc987beefe8be2f61869ac25b89f7e7323536700d8634320aec3a2f84a149562eb0c99f8fcb977fd1245d846d0c485",
	},
}

// sealGolden reproduces one frozen blob through the package's own Seal, driving
// the injectable rand seam with the counter the vector was derived from.
func sealGolden(t *testing.T, v blobVector) []byte {
	t.Helper()
	kek := mustKey(t, goldenKEK1IDHex, goldenKEK1Hex)
	blob, sealedName, err := Seal(
		kek, mustHex(t, goldenNameKeyHex), v.stored, v.logical,
		[]byte(v.plaintext), &countingReader{next: v.seed},
	)
	if err != nil {
		t.Fatalf("Seal(%s): %v", v.name, err)
	}
	// The mirror the caller stores in provider metadata and the copy inside the
	// blob must be the same bytes; List trusts the mirror and falls back to the
	// header, and the fallback is only sound because they are identical.
	if got := hex.EncodeToString(sealedName); got != v.sealedNameHex() {
		t.Fatalf("returned sealed name = %s, want the header's copy %s", got, v.sealedNameHex())
	}
	return blob
}

// TestSealGolden is the format freeze. If it fails, the change under test is a
// format change, and a format change means a new version byte plus a v1 reader
// that still works — never an edited literal.
func TestSealGolden(t *testing.T) {
	tokenKey := goldenTokenKey(t)

	for _, v := range goldenBlobs {
		t.Run(v.name, func(t *testing.T) {
			// A transcription slip in a hex literal would otherwise surface as
			// an inscrutable mismatch, so every frozen field is length-checked
			// against the format's fixed widths first.
			for _, f := range []struct {
				name string
				hex  string
				want int
			}{
				{"key ID", v.keyID, KeyIDLen},
				{"wrap nonce", v.wrapNonce, NonceLen},
				{"wrapped DEK", v.wrappedDEK, WrappedDEKLen},
				{"sealed-name length", v.nameLen, 2},
				{"name nonce", v.nameNonce, NonceLen},
				{"name tag", v.nameTag, TagLen},
				{"data nonce", v.dataNonce, NonceLen},
				{"body ciphertext", v.bodyCT, len(v.plaintext)},
				{"body tag", v.bodyTag, TagLen},
			} {
				if got := len(f.hex) / 2; got != f.want {
					t.Fatalf("frozen %s is %d bytes, want %d", f.name, got, f.want)
				}
			}

			// The stored path in the vector must be the one the tokenizer
			// actually produces, or the blob freezes a name nobody writes.
			if got := TokenPath(tokenKey, v.logical); got != v.stored {
				t.Fatalf("TokenPath(%q) = %s, want the frozen stored path %s", v.logical, got, v.stored)
			}

			blob := sealGolden(t, v)
			if got := hex.EncodeToString(blob); got != v.blobHex() {
				t.Fatalf("Seal(%s) =\n  %s\nwant the frozen vector\n  %s", v.name, got, v.blobHex())
			}

			// Fixed overhead is a number the spec quotes to operators and the
			// cost pillar reasons about; it falls out of the layout, so pin it.
			want := HeaderLen + len(v.sealedNameHex())/2 + NonceLen + len(v.plaintext) + TagLen
			if len(blob) != want {
				t.Errorf("blob is %d bytes, want %d", len(blob), want)
			}

			plaintext, err := Open(keyringOf(mustKey(t, goldenKEK1IDHex, goldenKEK1Hex)), v.logical, blob)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if string(plaintext) != v.plaintext {
				t.Errorf("Open returned %q, want %q", plaintext, v.plaintext)
			}

			name, err := HeaderName(mustHex(t, goldenNameKeyHex), v.stored, blob)
			if err != nil {
				t.Fatalf("HeaderName: %v", err)
			}
			if name != v.logical {
				t.Errorf("HeaderName = %q, want %q", name, v.logical)
			}
		})
	}
}

// TestAADLayoutsFrozen pins both AAD compositions as bytes and as structure.
//
// The layouts are fixed-width fields with the one variable field last, which is
// what makes them unambiguous without length prefixes; both carry the version
// byte, which is what makes a downgrade fail authentication rather than parse.
func TestAADLayoutsFrozen(t *testing.T) {
	for _, v := range goldenBlobs {
		t.Run(v.name, func(t *testing.T) {
			if got := hex.EncodeToString(dataAAD(v.logical)); got != v.dataAAD {
				t.Errorf("dataAAD(%q) = %s, want the frozen vector %s", v.logical, got, v.dataAAD)
			}
			if got := hex.EncodeToString(wrapAAD(Version, mustKeyID(t, v.keyID))); got != v.wrapAAD {
				t.Errorf("wrapAAD = %s, want the frozen vector %s", got, v.wrapAAD)
			}
		})
	}

	// Stated as structure as well, so that a change which edited both the code
	// and the literals in step would still have to argue with the spec's words.
	id := mustKeyID(t, goldenKEK1IDHex)
	if want := append(append([]byte("FCDS"), 0x01), id[:]...); !bytes.Equal(wrapAAD(Version, id), want) {
		t.Errorf("wrapAAD = %x, want magic‖version‖key ID = %x", wrapAAD(Version, id), want)
	}
	if want := append([]byte("FCDS"), append([]byte{0x01}, "a/b"...)...); !bytes.Equal(dataAAD("a/b"), want) {
		t.Errorf("dataAAD = %x, want magic‖version‖logical key = %x", dataAAD("a/b"), want)
	}

	// The key ID is deliberately absent from the data AAD; that exclusion is
	// what makes rekey a header rewrite, and TestRekeyLeavesTheBodyUntouched
	// depends on it holding.
	if bytes.Contains(dataAAD("hello.txt"), id[:]) {
		t.Error("the data AAD carries the key ID; rekey would then invalidate every body it touches")
	}
}

// TestGoldenBlobOpensUnderIndependentlyWrittenAADs takes the frozen blob apart
// with a hand-built AES-GCM whose AADs are assembled from literal bytes rather
// than from this package's helpers. Freezing dataAAD's output alone would not
// catch a change that edited the helper and the vector together; opening real
// ciphertext with an AAD written out by hand does.
func TestGoldenBlobOpensUnderIndependentlyWrittenAADs(t *testing.T) {
	for _, v := range goldenBlobs {
		t.Run(v.name, func(t *testing.T) {
			blob := mustHex(t, v.blobHex())

			kekGCM := rawGCM(t, mustHex(t, goldenKEK1Hex))
			dek, err := kekGCM.Open(nil,
				blob[offWrapNonce:offWrapNonce+NonceLen],
				blob[offWrappedDEK:offWrappedDEK+WrappedDEKLen],
				mustHex(t, v.wrapAAD))
			if err != nil {
				t.Fatalf("unwrap with a literal wrap AAD: %v", err)
			}

			// The DEK is the first 32 bytes the seeded reader produced, so the
			// vector's provenance is legible: this is the counter, not entropy.
			wantDEK := make([]byte, KeyLen)
			for i := range wantDEK {
				wantDEK[i] = v.seed + byte(i)
			}
			if !bytes.Equal(dek, wantDEK) {
				t.Fatalf("unwrapped DEK = %x, want the seeded counter %x", dek, wantDEK)
			}

			bodyOffset := HeaderLen + len(v.sealedNameHex())/2
			body := blob[bodyOffset:]
			plaintext, err := rawGCM(t, dek).Open(nil, body[:NonceLen], body[NonceLen:], mustHex(t, v.dataAAD))
			if err != nil {
				t.Fatalf("open the body with a literal data AAD: %v", err)
			}
			if string(plaintext) != v.plaintext {
				t.Errorf("body = %q, want %q", plaintext, v.plaintext)
			}

			// The third binding in the header: the sealed name, under a key
			// derived per object from the stored path and an AAD that is that
			// same path. Opening it here — with referenceHKDF for the key and
			// the path written out as the AAD — pins the derivation, the AAD
			// choice, and the interior's layout in one step.
			sealed := blob[HeaderLen:bodyOffset]
			interior, err := rawGCM(t, referenceHKDF(mustHex(t, goldenNameKeyHex), infoNameCryptPrefix+v.stored)).
				Open(nil, sealed[:NonceLen], sealed[NonceLen:], []byte(v.stored))
			if err != nil {
				t.Fatalf("open the sealed name with an independently derived key: %v", err)
			}
			// uint16 big-endian length ‖ the key's exact bytes ‖ zero padding to
			// a multiple of 32.
			wantInterior := make([]byte, NamePadUnit*((2+len(v.logical)+NamePadUnit-1)/NamePadUnit))
			binary.BigEndian.PutUint16(wantInterior, uint16(len(v.logical)))
			copy(wantInterior[2:], v.logical)
			if !bytes.Equal(interior, wantInterior) {
				t.Errorf("sealed-name interior = %x, want %x", interior, wantInterior)
			}
		})
	}
}

// rawGCM builds AES-256-GCM without going through this package's newGCM, so a
// test that claims to check the layout independently actually does.
func rawGCM(t *testing.T, key []byte) cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	return gcm
}

// mustNoPlaintext holds the rule that outranks every error-classification
// question in this package: a failed read hands back nothing. Partial or
// unauthenticated output is the failure mode the whole format exists to
// prevent, so it is asserted at every refusal rather than assumed.
func mustNoPlaintext(t *testing.T, plaintext []byte) {
	t.Helper()
	if plaintext != nil {
		t.Errorf("returned %d bytes of plaintext alongside an error", len(plaintext))
	}
}

// region is one named span of a blob. The tamper suite walks these, and it is
// only a claim about "every header region" because TestBlobRegionsTileTheBlob
// proves the list accounts for every byte.
type region struct {
	name  string
	start int
	end   int // exclusive
}

func blobRegions(t *testing.T, blob []byte) []region {
	t.Helper()
	h, err := ParseHeader(blob)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	return []region{
		{"magic", offMagic, offVersion},
		{"version", offVersion, offKeyID},
		{"key ID", offKeyID, offWrapNonce},
		{"wrap nonce", offWrapNonce, offWrappedDEK},
		{"wrapped DEK", offWrappedDEK, offNameLen},
		{"sealed-name length", offNameLen, HeaderLen},
		{"sealed name", HeaderLen, h.BodyOffset},
		{"data nonce", h.BodyOffset, h.BodyOffset + NonceLen},
		{"body ciphertext", h.BodyOffset + NonceLen, len(blob) - TagLen},
		{"body tag", len(blob) - TagLen, len(blob)},
	}
}

func TestBlobRegionsTileTheBlob(t *testing.T) {
	blob := sealGolden(t, goldenBlobs[0])
	at := 0
	for _, r := range blobRegions(t, blob) {
		if r.start != at {
			t.Fatalf("region %q starts at %d, want %d — the regions are not contiguous", r.name, r.start, at)
		}
		if r.end <= r.start {
			t.Fatalf("region %q is empty; the tamper suite would silently skip it", r.name)
		}
		at = r.end
	}
	if at != len(blob) {
		t.Fatalf("the named regions cover %d of %d bytes", at, len(blob))
	}
}

// TestTamperInEveryRegion flips one bit in every region of a blob — both the
// first byte's low bit and the last byte's high bit — and requires each edit to
// be refused. The cloud can write every one of these bytes, so each is an
// attack the format has to survive; anything that opens after an edit is a
// blob whose authentication does not cover the field.
func TestTamperInEveryRegion(t *testing.T) {
	v := goldenBlobs[0]
	blob := sealGolden(t, v)
	lookup := keyringOf(mustKey(t, goldenKEK1IDHex, goldenKEK1Hex))
	nameKey := mustHex(t, goldenNameKeyHex)

	for _, r := range blobRegions(t, blob) {
		for _, flip := range []struct {
			where string
			at    int
			mask  byte
		}{
			{"first byte, low bit", r.start, 0x01},
			{"last byte, high bit", r.end - 1, 0x80},
		} {
			t.Run(r.name+"/"+flip.where, func(t *testing.T) {
				damaged := append([]byte(nil), blob...)
				damaged[flip.at] ^= flip.mask

				plaintext, err := Open(lookup, v.logical, damaged)

				switch r.name {
				case "key ID":
					// The key ID is the header's routing field, read before any
					// authentication can run, so editing it makes the blob name
					// a key this keyring does not hold. That is ErrUnknownKey,
					// not ErrIntegrity — and the two being reachable from the
					// same one-bit edit is exactly why neither error's text may
					// recommend a destructive recovery.
					mustErrIs(t, "Open with a flipped key ID", err, ErrUnknownKey)
					mustNoPlaintext(t, plaintext)
				case "sealed name":
					// This region is the read path's deliberate boundary, and it
					// is the one place the spec's "bit-flip tamper in every
					// header region ⇒ ErrIntegrity" does not describe the code:
					// Open never touches the sealed name, so it still returns
					// the body.
					//
					// That is defensible and is asserted here rather than
					// worked around. The sealed name is a *mirror* of a name
					// the reader already supplied; the body is bound to that
					// logical key by the data AAD, so a damaged mirror cannot
					// produce wrong plaintext, only an unrecoverable name — and
					// refusing an otherwise perfect object because a copy of
					// its label is scratched trades data availability for
					// nothing. What must hold is that the name cannot be
					// *forged*, and that is what the second half asserts.
					if err != nil {
						t.Fatalf("Open: %v — the body must not depend on the sealed name", err)
					}
					if got := string(plaintext); got != v.plaintext {
						t.Errorf("Open returned %q, want %q", got, v.plaintext)
					}
					if _, err := HeaderName(nameKey, v.stored, damaged); err == nil {
						t.Fatal("a damaged sealed name still yielded a logical name")
					} else {
						mustErrIs(t, "HeaderName over a damaged sealed name", err, ErrIntegrity)
					}
				default:
					mustErrIs(t, "Open over a damaged "+r.name, err, ErrIntegrity)
					mustNoPlaintext(t, plaintext)
				}
			})
		}
	}
}

// TestTamperShiftsTheBodyByOne is the sealed-name-length edit that stays
// structurally valid: nameLen+1 leaves a parseable blob whose body is sliced
// one byte late. It takes a different path from the oversized-length edits — no
// bounds check fires, the DEK unwraps fine — and must still fail.
func TestTamperShiftsTheBodyByOne(t *testing.T) {
	v := goldenBlobs[0]
	blob := sealGolden(t, v)

	damaged := append([]byte(nil), blob...)
	binary.BigEndian.PutUint16(damaged[offNameLen:], binary.BigEndian.Uint16(damaged[offNameLen:])+1)
	if _, err := ParseHeader(damaged); err != nil {
		t.Fatalf("ParseHeader: %v — this case is only interesting while it still parses", err)
	}

	_, err := Open(keyringOf(mustKey(t, goldenKEK1IDHex, goldenKEK1Hex)), v.logical, damaged)
	mustErrIs(t, "Open with a body shifted one byte", err, ErrIntegrity)
}

// TestTamperedKeyIDLandingOnAHeldKey completes the key-ID story. When the
// flipped ID happens to name a key the keyring does hold, the lookup succeeds
// and the wrap AAD is what refuses the blob — which is the field's real
// protection, since ErrUnknownKey is only ever an accident of which IDs the
// operator happens to have.
func TestTamperedKeyIDLandingOnAHeldKey(t *testing.T) {
	v := goldenBlobs[0]
	blob := sealGolden(t, v)

	damaged := append([]byte(nil), blob...)
	damaged[offKeyID+KeyIDLen-1] ^= 0x01
	if got := hex.EncodeToString(damaged[offKeyID : offKeyID+KeyIDLen]); got != goldenSiblingIDHex {
		t.Fatalf("flipped key ID = %s, want the sibling %s", got, goldenSiblingIDHex)
	}

	// A keyring holding the sibling ID — under different material, as two
	// independently minted IDs would be.
	lookup := keyringOf(
		mustKey(t, goldenKEK1IDHex, goldenKEK1Hex),
		mustKey(t, goldenSiblingIDHex, goldenKEK2Hex),
	)
	_, err := Open(lookup, v.logical, damaged)
	mustErrIs(t, "Open with a key ID redirected to a held key", err, ErrIntegrity)
}

// TestSwappedBlobsBothFail is the cloud-side swap: two objects, their stored
// bytes exchanged. Neither read may succeed, and the mechanism is the data
// AAD's logical-key binding — proven by the control, which reads each blob
// under its own key and works.
func TestSwappedBlobsBothFail(t *testing.T) {
	a, b := goldenBlobs[0], goldenBlobs[1]
	blobA, blobB := sealGolden(t, a), sealGolden(t, b)
	lookup := keyringOf(mustKey(t, goldenKEK1IDHex, goldenKEK1Hex))

	for _, tc := range []struct {
		name    string
		key     string
		blob    []byte
		wantErr bool
	}{
		{"A's key, A's bytes", a.logical, blobA, false},
		{"B's key, B's bytes", b.logical, blobB, false},
		{"A's key, B's bytes", a.logical, blobB, true},
		{"B's key, A's bytes", b.logical, blobA, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plaintext, err := Open(lookup, tc.key, tc.blob)
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("Open: %v — the control must work, or the swap proves nothing", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("a swapped blob opened, returning %q", plaintext)
			}
			mustErrIs(t, "Open of a swapped blob", err, ErrIntegrity)
			if plaintext != nil {
				t.Error("Open returned plaintext alongside an error")
			}
		})
	}
}

// TestSealedNameTransplantDetected lifts one object's sealed-name block into
// another object's blob. Both the per-object derived seal key and the
// stored-path AAD refuse it, and either alone would be enough — belt and braces
// on a field the cloud can rewrite at will.
func TestSealedNameTransplantDetected(t *testing.T) {
	a, b := goldenBlobs[0], goldenBlobs[1]
	blobA, blobB := sealGolden(t, a), sealGolden(t, b)
	nameKey := mustHex(t, goldenNameKeyHex)

	headerA, err := ParseHeader(blobA)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	headerB, err := ParseHeader(blobB)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if len(headerA.SealedName) != len(headerB.SealedName) {
		t.Fatalf("the two sealed names differ in length (%d vs %d); the transplant would be a length edit, not a transplant",
			len(headerA.SealedName), len(headerB.SealedName))
	}

	transplanted := append([]byte(nil), blobB...)
	copy(transplanted[HeaderLen:headerB.BodyOffset], headerA.SealedName)

	if _, err := HeaderName(nameKey, b.stored, transplanted); err == nil {
		t.Fatal("a sealed name transplanted from another object authenticated")
	} else {
		mustErrIs(t, "HeaderName over a transplanted sealed name", err, ErrIntegrity)
	}

	// The body is untouched and stays readable — the damage is confined to the
	// name, which is what one-object-at-a-time degradation means.
	if _, err := Open(keyringOf(mustKey(t, goldenKEK1IDHex, goldenKEK1Hex)), b.logical, transplanted); err != nil {
		t.Errorf("Open: %v — a name transplant must not cost the body", err)
	}
}

// TestForeignKeyIDIsUnknown covers the untampered case: a blob whose KEK is
// simply not in this keyring. It is indistinguishable from a header edit by
// construction, which is why the sentinel exists and why nothing on this path
// may tell an operator to overwrite anything.
func TestForeignKeyIDIsUnknown(t *testing.T) {
	v := goldenBlobs[0]
	blob := sealGolden(t, v)

	for _, tc := range []struct {
		name   string
		lookup KeyLookup
	}{
		{"empty keyring", keyringOf()},
		{"keyring holding only another key", keyringOf(mustKey(t, goldenKEK2IDHex, goldenKEK2Hex))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plaintext, err := Open(tc.lookup, v.logical, blob)
			mustErrIs(t, "Open", err, ErrUnknownKey)
			if plaintext != nil {
				t.Error("Open returned plaintext alongside ErrUnknownKey")
			}
			// The message may name the ID — that is a cloud-visible header
			// field — but never the logical key it belongs to.
			if strings.Contains(err.Error(), v.logical) {
				t.Errorf("error %q leaked the logical key", err)
			}
		})
	}

	// Rekey reads the same field through the same path.
	if _, err := Rekey(keyringOf(), mustKey(t, goldenKEK2IDHex, goldenKEK2Hex), blob, &countingReader{}); err == nil {
		t.Error("Rekey accepted a blob whose KEK the keyring does not hold")
	} else {
		mustErrIs(t, "Rekey", err, ErrUnknownKey)
	}
}

// TestRekeyLeavesTheBodyUntouched is THE rekey property, and the reason the
// data AAD excludes the key ID.
//
// Rotation rewrites ~68 bytes of header — key ID, wrap nonce, wrapped DEK — and
// must not touch a byte from BodyOffset on, nor the sealed name. If the key ID
// were bound into the data AAD, every rekey would have to decrypt and re-encrypt
// every object; because it is not, `storage rekey` is a header splice, and this
// test is what keeps it one.
func TestRekeyLeavesTheBodyUntouched(t *testing.T) {
	oldKEK := mustKey(t, goldenKEK1IDHex, goldenKEK1Hex)
	newKEK := mustKey(t, goldenKEK2IDHex, goldenKEK2Hex)

	for _, v := range goldenBlobs {
		t.Run(v.name, func(t *testing.T) {
			before := sealGolden(t, v)
			after, err := Rekey(keyringOf(oldKEK), newKEK, before, &countingReader{next: 0x50})
			if err != nil {
				t.Fatalf("Rekey: %v", err)
			}
			if len(after) != len(before) {
				t.Fatalf("Rekey changed the blob length: %d -> %d", len(before), len(after))
			}

			h, err := ParseHeader(before)
			if err != nil {
				t.Fatalf("ParseHeader: %v", err)
			}

			// (a) the body and the sealed name are byte-identical.
			if !bytes.Equal(after[h.BodyOffset:], before[h.BodyOffset:]) {
				t.Error("Rekey rewrote the body; the data AAD must exclude the key ID")
			}
			if !bytes.Equal(after[HeaderLen:h.BodyOffset], before[HeaderLen:h.BodyOffset]) {
				t.Error("Rekey rewrote the sealed name")
			}
			if !bytes.Equal(after[offMagic:offKeyID], before[offMagic:offKeyID]) {
				t.Error("Rekey rewrote the magic or version")
			}

			// The wrap fields, and only those, changed — to the frozen values.
			if got := hex.EncodeToString(after[offKeyID : offKeyID+KeyIDLen]); got != goldenKEK2IDHex {
				t.Errorf("rekeyed key ID = %s, want %s", got, goldenKEK2IDHex)
			}
			if got := hex.EncodeToString(after[offWrapNonce : offWrapNonce+NonceLen]); got != "505152535455565758595a5b" {
				t.Errorf("rekeyed wrap nonce = %s, want the seeded counter", got)
			}
			if got := hex.EncodeToString(after[offWrappedDEK : offWrappedDEK+WrappedDEKLen]); got != v.rekeyedWrappedDEK {
				t.Errorf("rekeyed wrapped DEK = %s, want the frozen vector %s", got, v.rekeyedWrappedDEK)
			}

			// (b) it still opens — under the new KEK alone, so the old entry
			// can leave keys.yaml.
			plaintext, err := Open(keyringOf(newKEK), v.logical, after)
			if err != nil {
				t.Fatalf("Open after rekey: %v", err)
			}
			if string(plaintext) != v.plaintext {
				t.Errorf("Open after rekey returned %q, want %q", plaintext, v.plaintext)
			}

			// And the name survives untouched, which is the point of keeping
			// addressing structurally separate from rotation.
			name, err := HeaderName(mustHex(t, goldenNameKeyHex), v.stored, after)
			if err != nil {
				t.Fatalf("HeaderName after rekey: %v", err)
			}
			if name != v.logical {
				t.Errorf("HeaderName after rekey = %q, want %q", name, v.logical)
			}

			// The old KEK no longer opens it — a rekey that left the blob
			// readable under the retired key would retire nothing.
			if _, err := Open(keyringOf(oldKEK), v.logical, after); err == nil {
				t.Error("the rekeyed blob still opens under the old KEK")
			}
		})
	}
}

func TestRekeyRejectsDamagedBlobs(t *testing.T) {
	v := goldenBlobs[0]
	blob := sealGolden(t, v)
	lookup := keyringOf(mustKey(t, goldenKEK1IDHex, goldenKEK1Hex))
	newKEK := mustKey(t, goldenKEK2IDHex, goldenKEK2Hex)

	damaged := append([]byte(nil), blob...)
	damaged[offWrappedDEK] ^= 0x01
	if _, err := Rekey(lookup, newKEK, damaged, &countingReader{}); err == nil {
		t.Error("Rekey re-wrapped a DEK it could not authenticate")
	} else {
		mustErrIs(t, "Rekey", err, ErrIntegrity)
	}

	if _, err := Rekey(lookup, newKEK, blob[:HeaderLen-1], &countingReader{}); err == nil {
		t.Error("Rekey accepted a truncated blob")
	} else {
		mustErrIs(t, "Rekey", err, ErrIntegrity)
	}
}

// TestOneDEKPerWrite pins the invariant the whole nonce-budget argument rests
// on. Two writes of identical plaintext under identical keys must share
// nothing: a fresh DEK per object is what makes a data-nonce collision
// structurally impossible, and it is what a "reuse the DEK, it's the same
// object" optimization would quietly destroy.
//
// This is the one property that cannot be tested through the deterministic
// seam — a seeded reader would produce equal DEKs by construction — so it runs
// on crypto/rand, exactly as production does.
func TestOneDEKPerWrite(t *testing.T) {
	v := goldenBlobs[0]
	kek := mustKey(t, goldenKEK1IDHex, goldenKEK1Hex)
	nameKey := mustHex(t, goldenNameKeyHex)

	first, _, err := Seal(kek, nameKey, v.stored, v.logical, []byte(v.plaintext), rand.Reader)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	second, _, err := Seal(kek, nameKey, v.stored, v.logical, []byte(v.plaintext), rand.Reader)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	h1, err := ParseHeader(first)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	h2, err := ParseHeader(second)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}

	// The wrapped DEKs differing is necessary but nowhere near sufficient: a
	// fresh wrap nonce alone makes two wraps of the SAME DEK look different.
	// The property is about the key inside, so unwrap both and compare those.
	kekGCM := rawGCM(t, mustHex(t, goldenKEK1Hex))
	unwrap := func(h Header) []byte {
		t.Helper()
		dek, err := kekGCM.Open(nil, h.WrapNonce, h.WrappedDEK, mustHex(t, v.wrapAAD))
		if err != nil {
			t.Fatalf("unwrap: %v", err)
		}
		return dek
	}
	if bytes.Equal(unwrap(h1), unwrap(h2)) {
		t.Error("two writes wrapped the same DEK; a data-nonce collision is no longer structurally impossible")
	}
	if bytes.Equal(h1.WrappedDEK, h2.WrappedDEK) {
		t.Error("two writes produced the same wrapped DEK")
	}
	if bytes.Equal(h1.WrapNonce, h2.WrapNonce) {
		t.Error("two writes produced the same wrap nonce")
	}
	if bytes.Equal(h1.Body, h2.Body) {
		t.Error("two writes of identical plaintext produced identical bodies")
	}
	if bytes.Equal(h1.SealedName, h2.SealedName) {
		t.Error("two writes produced the same sealed name; the name nonce is not fresh")
	}
	if h1.KeyID != h2.KeyID {
		t.Error("the KEK changed between writes; only the DEK is per-write")
	}

	// Both still read back — freshness that broke the round trip would be a
	// worse bug than the one this test guards.
	for i, blob := range [][]byte{first, second} {
		got, err := Open(keyringOf(kek), v.logical, blob)
		if err != nil {
			t.Fatalf("Open write %d: %v", i, err)
		}
		if string(got) != v.plaintext {
			t.Errorf("write %d returned %q, want %q", i, got, v.plaintext)
		}
	}
}

// TestNonNormalizedUnicodeKeyRoundTrips is the spec's "no normalization, ever"
// rule as a test. The key's exact bytes are the data seal's AAD, so a helpful
// Unicode folding applied on write and not on read — or on read and not on
// write — turns stored data permanently unreadable.
//
// The two forms below are the same grapheme cluster written two ways:
// precomposed U+00E9, and "e" followed by the combining acute U+0301. They are
// different byte strings, so they are different objects, and they must stay
// different objects all the way down.
func TestNonNormalizedUnicodeKeyRoundTrips(t *testing.T) {
	const (
		// Spelled with escapes rather than literal glyphs: the two forms are
		// indistinguishable in an editor, and a source file that silently
		// normalized one of them would turn this test into a tautology.
		precomposed = "notes/caf\u00e9.txt"  // NFC: e-acute as one rune
		decomposed  = "notes/cafe\u0301.txt" // NFD: "e" plus combining acute
	)
	if precomposed == decomposed {
		t.Fatal("the two forms are the same string; the test proves nothing")
	}
	if len(precomposed) != 15 || len(decomposed) != 16 {
		t.Fatalf("unexpected encodings: NFC %d bytes, NFD %d bytes", len(precomposed), len(decomposed))
	}

	tokenKey := goldenTokenKey(t)
	nameKey := mustHex(t, goldenNameKeyHex)
	kek := mustKey(t, goldenKEK1IDHex, goldenKEK1Hex)

	storedNFC := TokenPath(tokenKey, precomposed)
	storedNFD := TokenPath(tokenKey, decomposed)
	if storedNFC == storedNFD {
		t.Fatal("the two forms tokenized to the same stored path; they would overwrite each other")
	}
	// The shared "notes" parent must still chain identically — the difference
	// belongs to the leaf, and prefix listing depends on that.
	if strings.SplitN(storedNFC, "/", 2)[0] != strings.SplitN(storedNFD, "/", 2)[0] {
		t.Error("the shared parent segment tokenized differently")
	}

	blobs := map[string][]byte{}
	for logical, stored := range map[string]string{precomposed: storedNFC, decomposed: storedNFD} {
		blob, _, err := Seal(kek, nameKey, stored, logical, []byte("body of "+logical), &countingReader{next: 0x11})
		if err != nil {
			t.Fatalf("Seal(%x): %v", logical, err)
		}
		blobs[logical] = blob

		got, err := Open(keyringOf(kek), logical, blob)
		if err != nil {
			t.Fatalf("Open(%x): %v", logical, err)
		}
		if want := "body of " + logical; string(got) != want {
			t.Errorf("round trip returned %q, want %q", got, want)
		}

		// The name comes back as the exact bytes that went in, not a
		// canonicalized twin.
		name, err := HeaderName(nameKey, stored, blob)
		if err != nil {
			t.Fatalf("HeaderName(%x): %v", logical, err)
		}
		if name != logical {
			t.Errorf("HeaderName = %x, want the exact bytes %x", name, logical)
		}
	}

	// And neither opens under the other's key: the AAD binding makes the two
	// forms non-interchangeable at read time, not merely at addressing time.
	if _, err := Open(keyringOf(kek), decomposed, blobs[precomposed]); err == nil {
		t.Error("the NFC object opened under the NFD key")
	} else {
		mustErrIs(t, "Open across normalization forms", err, ErrIntegrity)
	}
	if _, err := Open(keyringOf(kek), precomposed, blobs[decomposed]); err == nil {
		t.Error("the NFD object opened under the NFC key")
	}
}

// TestSealRejectsInvalidLogicalKeys keeps the validation on the write path
// rather than only in the layer above: Seal is what mints the AAD, so a key it
// accepts is a key that can be stored.
func TestSealRejectsInvalidLogicalKeys(t *testing.T) {
	kek := mustKey(t, goldenKEK1IDHex, goldenKEK1Hex)
	nameKey := mustHex(t, goldenNameKeyHex)

	for _, key := range []string{
		"",
		strings.Repeat("x", MaxKeyBytes+1),
		strings.Repeat("a/", MaxKeySegments) + "a",
		"a//b",
		"a/b/",
		"bad\xffkey",
	} {
		_, _, err := Seal(kek, nameKey, "stored", key, []byte("x"), &countingReader{})
		if err == nil {
			t.Errorf("Seal accepted the invalid key %q", key)
			continue
		}
		mustErrIs(t, "Seal", err, ErrInvalidKey)
	}
}

// TestSealRejectsOversizePlaintext exercises the 64 MiB cap.
//
// This is the one test in the package that allocates MaxPlaintext bytes. There
// is no cheaper route: the limit is a length check inside Seal, and a slice's
// length cannot be faked without unsafe. The cost is bounded in practice — Seal
// refuses before reading a byte, so the runtime's zeroed mapping is never
// faulted in — but it is a real allocation and it stays confined to this one
// test.
func TestSealRejectsOversizePlaintext(t *testing.T) {
	kek := mustKey(t, goldenKEK1IDHex, goldenKEK1Hex)
	nameKey := mustHex(t, goldenNameKeyHex)

	oversize := make([]byte, MaxPlaintext+1)
	blob, sealed, err := Seal(kek, nameKey, storedHelloTxt, "hello.txt", oversize, &countingReader{})
	mustErrIs(t, "Seal over MaxPlaintext", err, ErrTooLarge)
	if blob != nil || sealed != nil {
		t.Error("Seal returned bytes alongside ErrTooLarge")
	}
	// The message states sizes, which are already visible to the cloud, and not
	// the logical key, which is not.
	if strings.Contains(err.Error(), "hello.txt") {
		t.Errorf("error %q leaked the logical key", err)
	}
}

// TestParseHeaderRejectsMalformedBlobs covers the structural checks that run
// before any key is touched. All of them collapse to ErrIntegrity on purpose: a
// caller must not be able to tell "this is not a DataSphere blob" from "this
// blob was tampered with", and neither answer justifies returning plaintext.
func TestParseHeaderRejectsMalformedBlobs(t *testing.T) {
	good := sealGolden(t, goldenBlobs[0])

	edit := func(f func(b []byte)) []byte {
		b := append([]byte(nil), good...)
		f(b)
		return b
	}

	for _, tc := range []struct {
		name string
		blob []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"shorter than the fixed header", good[:HeaderLen-1]},
		{"header only, no name or body", good[:HeaderLen]},
		{"bad magic", edit(func(b []byte) { b[offMagic] = 'X' })},
		// 0x02 is the streaming format and is legitimately parseable; the
		// unknown-version case has to reach past every version this build
		// knows, which is the point of the check.
		{"unknown version", edit(func(b []byte) { b[offVersion] = 0x03 })},
		{"far future version", edit(func(b []byte) { b[offVersion] = 0xff })},
		{"version zero", edit(func(b []byte) { b[offVersion] = 0x00 })},
		{"sealed-name length zero", edit(func(b []byte) { binary.BigEndian.PutUint16(b[offNameLen:], 0) })},
		{"sealed-name length below a nonce and tag", edit(func(b []byte) {
			binary.BigEndian.PutUint16(b[offNameLen:], NonceLen+TagLen-1)
		})},
		{"sealed-name length past the end", edit(func(b []byte) {
			binary.BigEndian.PutUint16(b[offNameLen:], 0xffff)
		})},
		{"body truncated to less than a nonce and tag", good[:len(good)-len(goldenBlobs[0].bodyCT)/2-TagLen-1]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseHeader(tc.blob); err == nil {
				t.Fatal("ParseHeader accepted it")
			} else {
				mustErrIs(t, "ParseHeader", err, ErrIntegrity)
			}
			// Every caller funnels through ParseHeader, so none of them may
			// leak anything either.
			if plaintext, err := Open(keyringOf(mustKey(t, goldenKEK1IDHex, goldenKEK1Hex)), "hello.txt", tc.blob); err == nil {
				t.Errorf("Open accepted it, returning %q", plaintext)
			} else if plaintext != nil {
				t.Error("Open returned plaintext alongside an error")
			}
		})
	}
}

// TestParseHeaderFieldsMatchTheFrozenOffsets reads the header of a frozen blob
// and checks every field against the literal it was built from. It is the
// offsets themselves under test: a field that moved would still round-trip
// through Seal and Open, and would still be a format break.
func TestParseHeaderFieldsMatchTheFrozenOffsets(t *testing.T) {
	for _, v := range goldenBlobs {
		t.Run(v.name, func(t *testing.T) {
			blob := mustHex(t, v.blobHex())
			h, err := ParseHeader(blob)
			if err != nil {
				t.Fatalf("ParseHeader: %v", err)
			}
			for _, f := range []struct {
				name string
				got  string
				want string
			}{
				{"key ID", hex.EncodeToString(h.KeyID[:]), v.keyID},
				{"wrap nonce", hex.EncodeToString(h.WrapNonce), v.wrapNonce},
				{"wrapped DEK", hex.EncodeToString(h.WrappedDEK), v.wrappedDEK},
				{"sealed name", hex.EncodeToString(h.SealedName), v.sealedNameHex()},
				{"body", hex.EncodeToString(h.Body), v.dataNonce + v.bodyCT + v.bodyTag},
			} {
				if f.got != f.want {
					t.Errorf("%s = %s, want %s", f.name, f.got, f.want)
				}
			}
			if want := HeaderLen + len(v.sealedNameHex())/2; h.BodyOffset != want {
				t.Errorf("BodyOffset = %d, want %d", h.BodyOffset, want)
			}
			if got := binary.BigEndian.Uint16(blob[offNameLen:]); int(got) != len(h.SealedName) {
				t.Errorf("sealed-name length field = %d, want %d", got, len(h.SealedName))
			}
		})
	}
}

// TestSealRoundTripsShapesTheVectorsDoNotCover walks the sizes around the
// padding unit and the ends of the legal range, where an off-by-one in the
// name interior or the body slicing would live.
func TestSealRoundTripsShapesTheVectorsDoNotCover(t *testing.T) {
	kek := mustKey(t, goldenKEK1IDHex, goldenKEK1Hex)
	nameKey := mustHex(t, goldenNameKeyHex)
	tokenKey := goldenTokenKey(t)

	for _, tc := range []struct {
		name    string
		logical string
		body    []byte
	}{
		{"single-byte key, single-byte body", "a", []byte{0x00}},
		{"key at the padding boundary", strings.Repeat("x", 30), []byte("body")},
		{"key one past the padding boundary", strings.Repeat("x", 31), []byte("body")},
		{"longest legal key", strings.Repeat("x", MaxKeyBytes), []byte("body")},
		{"deepest legal key", strings.Repeat("a/", MaxKeySegments-1) + "a", []byte("body")},
		{"body of exactly one GCM block", "block", bytes.Repeat([]byte{0xa5}, 16)},
		{"body spanning blocks", "chunky", bytes.Repeat([]byte{0x5a}, 4096+7)},
		{"body of all zeroes", "zeroes", make([]byte, 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stored := TokenPath(tokenKey, tc.logical)
			blob, sealedName, err := Seal(kek, nameKey, stored, tc.logical, tc.body, &countingReader{next: 0x7f})
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			got, err := Open(keyringOf(kek), tc.logical, blob)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(got, tc.body) {
				t.Errorf("round trip returned %d bytes, want %d", len(got), len(tc.body))
			}
			name, err := OpenName(nameKey, stored, sealedName)
			if err != nil {
				t.Fatalf("OpenName: %v", err)
			}
			if name != tc.logical {
				t.Errorf("the mirror returned a %d-byte name, want %d bytes", len(name), len(tc.logical))
			}
		})
	}
}
