package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
)

// Golden vectors for blob format v2, frozen as fixed hex literals.
//
// Every literal below was produced by an INDEPENDENT implementation — AES
// written out from FIPS 197, GCM from SP 800-38D, HKDF from RFC 5869 — which
// self-tests against published NIST and RFC vectors BEFORE deriving anything,
// so its agreement with this package is not circular. They were then confirmed
// against Go. None was printed from this package and pasted back.
//
// They must never be regenerated. There is no -update flag, and adding one
// would defeat the file: these bytes are what every object already stored
// decodes as, so a change here that "fixes" a test is silent data loss for
// real data. If a vector fails, the format changed, and the format may only
// change behind a new version byte.

// The plaintext used by the multi-frame vector: a cheap deterministic pattern,
// defined identically in the reference implementation.
func goldenPattern(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte((i*31 + 7) & 0xFF)
	}
	return out
}

// sealStreamGolden reproduces one vector. The seeds mirror the reference: a byte
// counter from seed feeds the DEK, the wrap nonce and the frame salt (52 bytes
// in that order), and a counter from seed+52 feeds the name nonce.
func sealStreamGolden(t *testing.T, logical string, plaintext []byte, exp, seed byte) (blob, stored []byte, storedPath string) {
	t.Helper()
	nameKey := mustHex(t, goldenNameKeyHex)
	tokenKey, err := NameTokenKey(nameKey)
	if err != nil {
		t.Fatal(err)
	}
	storedPath = TokenPath(tokenKey, logical)
	sealedName, err := SealName(nameKey, storedPath, logical, &countingReader{next: seed + 52})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	err = SealStream(
		Key{ID: mustKeyID(t, goldenKEK1IDHex), Material: mustHex(t, goldenKEK1Hex)},
		storedPath, logical, sealedName, exp,
		bytes.NewReader(plaintext), &buf, &countingReader{next: seed},
	)
	if err != nil {
		t.Fatalf("SealStream: %v", err)
	}
	return buf.Bytes(), sealedName, storedPath
}

func goldenLookup(t *testing.T) KeyLookup {
	t.Helper()
	id1, id2 := mustKeyID(t, goldenKEK1IDHex), mustKeyID(t, goldenKEK2IDHex)
	k1, k2 := mustHex(t, goldenKEK1Hex), mustHex(t, goldenKEK2Hex)
	return func(id [KeyIDLen]byte) ([]byte, bool) {
		switch id {
		case id1:
			return k1, true
		case id2:
			return k2, true
		default:
			return nil, false
		}
	}
}

func TestSealStreamGoldenVectors(t *testing.T) {
	for _, v := range []struct {
		name      string
		logical   string
		plaintext []byte
		exp, seed byte
		blobHex   string // whole blob, when it is small enough to read
		blobLen   int
		blobSHA   string // for the vector too large to inline
	}{
		{
			name: "empty plaintext, e=16", logical: "hello.txt", plaintext: nil, exp: 16, seed: 0x00,
			blobHex: "46434453028f3a19c2d4e5b607202122232425262728292a2b9bbfd987523db6ef196800b652099a5c2cb6b6ecfc8479535620a8885059698016704c99f1928175f403dbcdba749ac3003c3435363738393a3b3c3d3e3f7cf52d11dfbd329287663f0c61348d95ad9791405215824b1332414a7e9a50a807e0227807acb2ca8a9fcb286c0873b02c2d2e2f30313233100a8bb1b4721d977706e6dd61a630e56d",
			blobLen: 160,
		},
		{
			name: "short plaintext, e=16", logical: "app/blue/web/config.json", plaintext: []byte("hello, world"), exp: 16, seed: 0x60,
			blobHex: "46434453028f3a19c2d4e5b607808182838485868788898a8b30d727525f262c84cf9a52e42c8a47cd522c4f5c2450a192c6726b322dcc48749e28b33b4d33ec39e5dfe1616e551090003c9495969798999a9b9c9d9e9fe1793c4db5a59ce2f56e724c8a4d610d7670a30dc4833dd786871b561d8c2688df09aeb07d4f01c67971b04342a2db7b8c8d8e8f90919293100c993741608c4dd56090b463667f88ad91318d1b6cf8dc1763f749cf",
			blobLen: 172,
		},
		{
			// The case that pins the self-terminating rule: a plaintext that is
			// an exact multiple of the frame size ends in a ZERO-LENGTH final
			// frame, so a full-size frame is never the last one and a reader
			// never needs the object's length to know where it stops.
			name: "exact multiple of the frame size, e=16", logical: "hello.txt", plaintext: goldenPattern(2 << 16), exp: 16, seed: 0xA0,
			blobLen: 131264,
			blobSHA: "e8fede8ee7e6bcc94c32e1de9184868e963cf31f43fa6480ec5ab31b2587b9a6",
		},
		{
			name: "default exponent e=20", logical: "users/alice/profile.json", plaintext: []byte("farcast"), exp: DefaultChunkExp, seed: 0xD0,
			blobHex: "46434453028f3a19c2d4e5b607f0f1f2f3f4f5f6f7f8f9fafb2def56f7b012ece726d0f2e9d29355928adbf02fb44ec23a3df62a98efb19a6fd5c314dab1b2054b8918ce80132d8497003c0405060708090a0b0c0d0e0fca1ba8018575dba3abc90a7e97fb374e39534fe860c7a6b855d99e5c0ccb088c81bc5dcff31d611a0a5bb7f5939fa8bbfcfdfeff0001020314b9984d430466354ea5a455018dd21167ef03b1e2cec41f",
			blobLen: 167,
		},
	} {
		t.Run(v.name, func(t *testing.T) {
			blob, _, _ := sealStreamGolden(t, v.logical, v.plaintext, v.exp, v.seed)
			if len(blob) != v.blobLen {
				t.Errorf("blob is %d bytes, want the frozen %d", len(blob), v.blobLen)
			}
			if v.blobHex != "" {
				if got := hex.EncodeToString(blob); got != v.blobHex {
					t.Errorf("blob = %s\nwant the frozen vector %s", got, v.blobHex)
				}
			}
			if v.blobSHA != "" {
				if got := hex.EncodeToString(sha256digest(blob)); got != v.blobSHA {
					t.Errorf("blob sha256 = %s, want the frozen %s", got, v.blobSHA)
				}
			}
			// A frozen blob that cannot be opened would be a frozen mistake.
			var out bytes.Buffer
			if err := OpenStream(goldenLookup(t), v.logical, bytes.NewReader(blob), &out); err != nil {
				t.Fatalf("OpenStream of the frozen blob: %v", err)
			}
			if !bytes.Equal(out.Bytes(), v.plaintext) {
				t.Errorf("round-trip returned %d bytes, want %d", out.Len(), len(v.plaintext))
			}
		})
	}
}

func sha256digest(b []byte) []byte { sum := sha256.Sum256(b); return sum[:] }

// TestV2SharesV1HeaderPrefix pins the property the whole layout was chosen for.
//
// Bytes 0 through the end of the sealed name are the same fields at the same
// offsets in both formats, so ParseHeader, HeaderName and Rekey are ONE
// implementation with no version awareness. That is the only mechanism holding
// up the module's promise that a bucket plus a keys file reconstruct every
// logical name with no local state — a recovery tool written today has to be
// able to read a name out of a format it has never seen.
func TestV2SharesV1HeaderPrefix(t *testing.T) {
	const logical = "app/blue/web/config.json"
	nameKey := mustHex(t, goldenNameKeyHex)
	tokenKey, err := NameTokenKey(nameKey)
	if err != nil {
		t.Fatal(err)
	}
	stored := TokenPath(tokenKey, logical)
	kek := Key{ID: mustKeyID(t, goldenKEK1IDHex), Material: mustHex(t, goldenKEK1Hex)}

	v1, _, err := Seal(kek, nameKey, stored, logical, []byte("hello, world"), &countingReader{next: 0x60})
	if err != nil {
		t.Fatal(err)
	}
	v2, _, _ := sealStreamGolden(t, logical, []byte("hello, world"), 16, 0x60)

	if v1[offVersion] != Version || v2[offVersion] != Version2 {
		t.Fatalf("version bytes are %d and %d", v1[offVersion], v2[offVersion])
	}
	// Same fields, same offsets, in both.
	for _, field := range []struct {
		name       string
		from, to   int
		mustBeSame bool
	}{
		{"magic", offMagic, offMagic + len(Magic), true},
		{"key ID", offKeyID, offKeyID + KeyIDLen, true},
		{"sealed-name length", offNameLen, HeaderLen, true},
	} {
		if same := bytes.Equal(v1[field.from:field.to], v2[field.from:field.to]); same != field.mustBeSame {
			t.Errorf("%s: equal=%v, want %v", field.name, same, field.mustBeSame)
		}
	}

	// The sealed name begins at offset 75 in BOTH, and both parse and unseal
	// through one code path.
	for _, tc := range []struct {
		name string
		blob []byte
	}{{"v1", v1}, {"v2", v2}} {
		t.Run(tc.name, func(t *testing.T) {
			h, err := ParseHeader(tc.blob)
			if err != nil {
				t.Fatalf("ParseHeader: %v", err)
			}
			if h.BodyOffset != HeaderLen+len(h.SealedName) {
				t.Errorf("sealed name does not start at offset %d", HeaderLen)
			}
			got, err := HeaderName(nameKey, stored, tc.blob)
			if err != nil {
				t.Fatalf("HeaderName: %v", err)
			}
			if got != logical {
				t.Errorf("HeaderName = %q, want %q", got, logical)
			}
		})
	}
}

// TestV2RekeyLeavesEverythingButTheWrapFields pins that a rekey is a header
// rewrite for streamed objects too — which is only true because the frame AAD
// excludes the key ID, exactly as v1's data AAD does.
func TestV2RekeyLeavesEverythingButTheWrapFields(t *testing.T) {
	const logical = "hello.txt"
	plaintext := goldenPattern(3 << 16)
	blob, _, _ := sealStreamGolden(t, logical, plaintext, 16, 0x11)

	newKEK := Key{ID: mustKeyID(t, goldenKEK2IDHex), Material: mustHex(t, goldenKEK2Hex)}
	rekeyed, err := Rekey(goldenLookup(t), newKEK, blob, &countingReader{next: 0x77})
	if err != nil {
		t.Fatalf("Rekey: %v", err)
	}
	if len(rekeyed) != len(blob) {
		t.Fatalf("rekeyed blob is %d bytes, want %d", len(rekeyed), len(blob))
	}
	// Everything past the wrap fields is byte-identical: the sealed name, the
	// salt, the exponent, and every frame.
	if !bytes.Equal(blob[offNameLen:], rekeyed[offNameLen:]) {
		t.Error("rekey touched bytes past the wrap fields; a rekey must never rewrite a body")
	}
	if bytes.Equal(blob[offKeyID:offNameLen], rekeyed[offKeyID:offNameLen]) {
		t.Error("rekey left the wrap fields unchanged")
	}
	var out bytes.Buffer
	if err := OpenStream(goldenLookup(t), logical, bytes.NewReader(rekeyed), &out); err != nil {
		t.Fatalf("OpenStream after rekey: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plaintext) {
		t.Error("plaintext changed across a rekey")
	}
}

// TestV2Tampering sweeps every region of a multi-frame blob.
func TestV2Tampering(t *testing.T) {
	const logical = "app/blue/web/config.json"
	plaintext := goldenPattern(2<<16 + 11)
	blob, sealedName, _ := sealStreamGolden(t, logical, plaintext, 16, 0x22)
	nameEnd := HeaderLen + len(sealedName)

	// The sealed name is deliberately absent from the sweep below and gets its
	// own assertion further down: OpenStream never reads it, exactly as v1's
	// Open does not (Decisions 12). It is a MIRROR of a name the reader already
	// supplied, and the body is bound to that logical key by the frame AAD, so
	// a damaged mirror can never produce wrong plaintext — only an
	// unrecoverable name. Refusing an otherwise perfect object because a copy
	// of its label is scratched would trade availability for nothing.
	for _, region := range []struct {
		name string
		at   int
	}{
		{"magic", offMagic},
		{"version", offVersion},
		{"key ID", offKeyID},
		{"wrap nonce", offWrapNonce},
		{"wrapped DEK", offWrappedDEK},
		{"sealed-name length", offNameLen},
		{"frame salt", nameEnd + 2},
		{"chunk exponent", nameEnd + SaltLen},
		{"first frame", nameEnd + SaltLen + 1 + 5},
		{"last byte", len(blob) - 1},
	} {
		t.Run(region.name, func(t *testing.T) {
			damaged := append([]byte(nil), blob...)
			damaged[region.at] ^= 1
			err := OpenStream(goldenLookup(t), logical, bytes.NewReader(damaged), io.Discard)
			if err == nil {
				t.Fatal("tampered blob was accepted")
			}
			// A flipped key-ID bit names a key the keyring does not hold, which
			// is the one distinguishable outcome; everything else is refused
			// without saying which byte gave it away.
			if region.name == "key ID" {
				mustErrIs(t, "OpenStream", err, ErrUnknownKey)
				return
			}
			mustErrIs(t, "OpenStream", err, ErrIntegrity)
		})
	}
}

// TestV2TruncationAndExtension covers the two attacks the self-terminating
// rule exists to catch.
func TestV2TruncationAndExtension(t *testing.T) {
	const logical = "hello.txt"
	frame := 1<<16 + TagLen
	plaintext := goldenPattern(2 << 16) // exactly two frames plus the empty terminator
	blob, _, _ := sealStreamGolden(t, logical, plaintext, 16, 0x33)

	for _, tc := range []struct {
		name string
		blob []byte
	}{
		{"a whole frame removed", blob[:len(blob)-TagLen]},
		{"truncated mid-frame", blob[:len(blob)-frame/2]},
		{"truncated to the header", blob[:HeaderLen+40]},
		{"one byte appended", append(append([]byte(nil), blob...), 0x00)},
		{"a frame appended", append(append([]byte(nil), blob...), goldenPattern(frame)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := OpenStream(goldenLookup(t), logical, bytes.NewReader(tc.blob), io.Discard); err == nil {
				t.Fatal("accepted")
			} else {
				mustErrIs(t, "OpenStream", err, ErrIntegrity)
			}
		})
	}
}

// TestV2FrameReordering: a frame is bound to its position by the index in its
// AAD, so moving one is a tag failure rather than scrambled plaintext.
func TestV2FrameReordering(t *testing.T) {
	const logical = "hello.txt"
	blob, sealedName, _ := sealStreamGolden(t, logical, goldenPattern(3<<16), 16, 0x44)
	body := HeaderLen + len(sealedName) + SaltLen + 1
	frame := 1<<16 + TagLen

	swapped := append([]byte(nil), blob...)
	first := append([]byte(nil), swapped[body:body+frame]...)
	copy(swapped[body:body+frame], swapped[body+frame:body+2*frame])
	copy(swapped[body+frame:body+2*frame], first)

	if err := OpenStream(goldenLookup(t), logical, bytes.NewReader(swapped), io.Discard); err == nil {
		t.Fatal("reordered frames were accepted")
	} else {
		mustErrIs(t, "OpenStream", err, ErrIntegrity)
	}

	duplicated := append([]byte(nil), blob[:body+frame]...)
	duplicated = append(duplicated, blob[body:]...)
	if err := OpenStream(goldenLookup(t), logical, bytes.NewReader(duplicated), io.Discard); err == nil {
		t.Fatal("a duplicated frame was accepted")
	}
}

// TestV2ChunkExponentIsBounded: the exponent is cloud-writable plaintext, and
// an unchecked one is a request to allocate gigabytes. It must be refused
// before it sizes anything.
func TestV2ChunkExponentIsBounded(t *testing.T) {
	const logical = "hello.txt"
	blob, sealedName, _ := sealStreamGolden(t, logical, []byte("x"), 16, 0x55)
	at := HeaderLen + len(sealedName) + SaltLen

	for _, exp := range []byte{0, 1, MinChunkExp - 1, MaxChunkExp + 1, 40, 0xff} {
		damaged := append([]byte(nil), blob...)
		damaged[at] = exp
		if err := OpenStream(goldenLookup(t), logical, bytes.NewReader(damaged), io.Discard); err == nil {
			t.Errorf("exponent %d was accepted", exp)
		} else {
			mustErrIs(t, "OpenStream", err, ErrIntegrity)
		}
	}
	// And the writer refuses to produce one.
	if err := SealStream(Key{ID: mustKeyID(t, goldenKEK1IDHex), Material: mustHex(t, goldenKEK1Hex)},
		"x", "x", make([]byte, NonceLen+TagLen), MaxChunkExp+1, bytes.NewReader(nil), io.Discard, &countingReader{}); err == nil {
		t.Error("SealStream accepted an out-of-range exponent")
	}
}

// TestV2CrossVersionAPIs: which API wrote an object is not something a caller
// should have to remember.
func TestV2CrossVersionAPIs(t *testing.T) {
	const logical = "hello.txt"
	nameKey := mustHex(t, goldenNameKeyHex)
	tokenKey, _ := NameTokenKey(nameKey)
	stored := TokenPath(tokenKey, logical)
	kek := Key{ID: mustKeyID(t, goldenKEK1IDHex), Material: mustHex(t, goldenKEK1Hex)}

	t.Run("OpenStream reads a v1 blob", func(t *testing.T) {
		v1, _, err := Seal(kek, nameKey, stored, logical, []byte("buffered"), &countingReader{next: 0x66})
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := OpenStream(goldenLookup(t), logical, bytes.NewReader(v1), &out); err != nil {
			t.Fatalf("OpenStream of a v1 blob: %v", err)
		}
		if out.String() != "buffered" {
			t.Errorf("got %q", out.String())
		}
	})

	t.Run("Open reads a v2 blob that fits", func(t *testing.T) {
		blob, _, _ := sealStreamGolden(t, logical, []byte("streamed"), 16, 0x77)
		got, err := Open(goldenLookup(t), logical, blob)
		if err != nil {
			t.Fatalf("Open of a v2 blob: %v", err)
		}
		if string(got) != "streamed" {
			t.Errorf("got %q", got)
		}
	})

	t.Run("Open refuses a v2 blob that does not fit", func(t *testing.T) {
		// Built at the smallest legal frame size so the cap is reached without
		// allocating anything near it.
		var buf bytes.Buffer
		sealedName, err := SealName(nameKey, stored, logical, &countingReader{next: 0x88})
		if err != nil {
			t.Fatal(err)
		}
		big := io.LimitReader(neverEnding{}, MaxPlaintext+1)
		if err := SealStream(kek, stored, logical, sealedName, MaxChunkExp, big, &buf, &countingReader{next: 0x99}); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(goldenLookup(t), logical, buf.Bytes()); err == nil {
			t.Fatal("Open accepted an object past the buffered cap")
		} else {
			mustErrIs(t, "Open", err, ErrTooLarge)
		}
	})
}

type neverEnding struct{}

func (neverEnding) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(i)
	}
	return len(p), nil
}

// TestV2RoundTripAcrossFrameBoundaries walks the sizes where framing decisions
// change, because that is where an off-by-one hides.
func TestV2RoundTripAcrossFrameBoundaries(t *testing.T) {
	const logical, exp = "sizes/probe", byte(16)
	frame := 1 << exp
	for _, size := range []int{0, 1, frame - 1, frame, frame + 1, 2 * frame, 2*frame + 7, 3 * frame} {
		plaintext := goldenPattern(size)
		blob, sealedName, _ := sealStreamGolden(t, logical, plaintext, exp, byte(size))
		var out bytes.Buffer
		if err := OpenStream(goldenLookup(t), logical, bytes.NewReader(blob), &out); err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if !bytes.Equal(out.Bytes(), plaintext) {
			t.Fatalf("size %d: round-trip mismatch", size)
		}
		// The final frame is always strictly shorter than a full one, which is
		// what makes the format self-terminating.
		body := len(blob) - HeaderLen - len(sealedName) - SaltLen - 1
		last := body % (frame + TagLen)
		if last == 0 {
			t.Errorf("size %d: body is a whole number of full frames, so nothing marks the end", size)
		}
	}
}

// TestV2OneDEKPerWrite uses real randomness: two writes of identical bytes
// under identical keys must share nothing.
func TestV2OneDEKPerWrite(t *testing.T) {
	const logical = "hello.txt"
	nameKey := mustHex(t, goldenNameKeyHex)
	tokenKey, _ := NameTokenKey(nameKey)
	stored := TokenPath(tokenKey, logical)
	kek := Key{ID: mustKeyID(t, goldenKEK1IDHex), Material: mustHex(t, goldenKEK1Hex)}

	seal := func() []byte {
		sealedName, err := SealName(nameKey, stored, logical, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if err := SealStream(kek, stored, logical, sealedName, 16, bytes.NewReader(goldenPattern(1<<17)), &buf, rand.Reader); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	a, b := seal(), seal()

	// Compare the DEKs themselves, not just the wrapped bytes: a fresh wrap
	// nonce alone makes two wraps of the SAME key look different, so wrapped
	// ciphertext inequality proves nothing on its own.
	ha, err := ParseHeader(a)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := ParseHeader(b)
	if err != nil {
		t.Fatal(err)
	}
	dekA, err := ha.unwrap(goldenLookup(t))
	if err != nil {
		t.Fatal(err)
	}
	dekB, err := hb.unwrap(goldenLookup(t))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(dekA, dekB) {
		t.Fatal("two writes shared a data key")
	}
	if bytes.Equal(a[HeaderLen+len(ha.SealedName):], b[HeaderLen+len(hb.SealedName):]) {
		t.Error("two writes produced identical bodies")
	}
}

// TestV2FrameAADAndNonce pins the two constructions a second implementation
// has to reproduce exactly, independent of any blob.
func TestV2FrameAADAndNonce(t *testing.T) {
	// magic ‖ version ‖ exponent ‖ index ‖ final ‖ logical key — fixed-width
	// fields with the one variable field last, per the format's rule.
	want := append([]byte("FCDS"), 0x02, 16)
	want = binary.BigEndian.AppendUint32(want, 7)
	want = append(want, 0x01)
	want = append(want, "hello.txt"...)
	if got := frameAAD(16, 7, true, "hello.txt"); !bytes.Equal(got, want) {
		t.Errorf("frameAAD = %x\nwant                %x", got, want)
	}
	if got := frameAAD(16, 7, false, "hello.txt"); bytes.Equal(got, want) {
		t.Error("the final flag does not change the AAD, so truncation would not be detected")
	}
	// The key ID is deliberately absent, which is what keeps a rekey a header
	// rewrite. If it ever appears here, every rekeyed object becomes
	// unreadable forever.
	id := mustKeyID(t, goldenKEK1IDHex)
	if strings.Contains(string(frameAAD(16, 0, false, "k")), string(id[:])) {
		t.Error("the frame AAD contains the key ID; rekey would break every object it touched")
	}
}

// TestOpenStreamRefusesAForeignKey: a blob naming a key the keyring lacks is
// the one distinguishable failure, and it must not leak anything else.
func TestOpenStreamRefusesAForeignKey(t *testing.T) {
	blob, _, _ := sealStreamGolden(t, "hello.txt", []byte("x"), 16, 0xAB)
	empty := func([KeyIDLen]byte) ([]byte, bool) { return nil, false }
	err := OpenStream(empty, "hello.txt", bytes.NewReader(blob), io.Discard)
	if !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("err = %v, want ErrUnknownKey", err)
	}
}

// TestV2SealedNameIsAuthenticatedWhereItIsRead pins the boundary the tamper
// sweep deliberately leaves out, so that it is asserted rather than merely
// unmentioned: damage to the sealed name does not stop a read, and does stop a
// name recovery.
func TestV2SealedNameIsAuthenticatedWhereItIsRead(t *testing.T) {
	const logical = "app/blue/web/config.json"
	plaintext := []byte("the body is fine")
	blob, _, stored := sealStreamGolden(t, logical, plaintext, 16, 0xCD)

	damaged := append([]byte(nil), blob...)
	damaged[HeaderLen+3] ^= 1

	var out bytes.Buffer
	if err := OpenStream(goldenLookup(t), logical, bytes.NewReader(damaged), &out); err != nil {
		t.Fatalf("OpenStream = %v, want success: the body is untouched and bound to the key the caller asked for", err)
	}
	if !bytes.Equal(out.Bytes(), plaintext) {
		t.Error("the plaintext changed, which a damaged name mirror must never be able to do")
	}
	// And the path that DOES read it refuses, loudly.
	if _, err := HeaderName(mustHex(t, goldenNameKeyHex), stored, damaged); err == nil {
		t.Fatal("HeaderName accepted a damaged sealed name")
	} else {
		mustErrIs(t, "HeaderName", err, ErrIntegrity)
	}
}
