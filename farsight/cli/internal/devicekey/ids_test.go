package devicekey

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

// TestObjectIDShapes: each kind's length, a letter first, [a-z0-9] after,
// never gcp-, and 1,000 draws all distinct.
func TestObjectIDShapes(t *testing.T) {
	for kind, n := range map[ObjectKind]int{PoolID: 32, ProviderID: 32, ServiceAccountID: 30} {
		seen := map[string]bool{}
		for range 1000 {
			id, err := NewObjectID(kind, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			if len(id) != n {
				t.Fatalf("kind %d: %d characters, want %d", kind, len(id), n)
			}
			if id[0] < 'a' || id[0] > 'z' {
				t.Fatalf("kind %d: the first character is not a lowercase letter", kind)
			}
			for i := 1; i < len(id); i++ {
				if c := id[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') {
					t.Fatalf("kind %d: character %d is outside [a-z0-9]", kind, i)
				}
			}
			if strings.HasPrefix(id, "gcp-") || strings.Contains(id, "-") {
				t.Fatalf("kind %d: a hyphen or the gcp- prefix", kind)
			}
			if seen[id] {
				t.Fatalf("kind %d: a repeated draw", kind)
			}
			seen[id] = true
		}
	}
	cr := &countingReader{}
	for _, kind := range []ObjectKind{0, 4, -1} {
		if _, err := NewObjectID(kind, cr); err == nil {
			t.Errorf("NewObjectID(%d) succeeded", kind)
		}
	}
	if cr.reads != 0 {
		t.Errorf("a refused kind read the random source %d times", cr.reads)
	}
	if _, err := NewObjectID(PoolID, failingReader{}); err == nil {
		t.Error("a failing reader gave an object ID")
	}
	if _, err := NewObjectID(PoolID, bytes.NewReader(bytes.Repeat([]byte{0xff}, 4096))); err == nil {
		t.Error("a source of unusable bytes gave an object ID")
	}
}

// TestObjectIDRejectsBiasedBytes: bytes at or above the largest multiple of
// the alphabet's size are skipped, so a stream of them then valid bytes draws
// what the valid bytes alone draw.
func TestObjectIDRejectsBiasedBytes(t *testing.T) {
	valid := make([]byte, 512)
	if _, err := (&detStream{seed: "devicekey-test/object-id"}).Read(valid); err != nil {
		t.Fatal(err)
	}
	biased := []byte{252, 253, 254, 255, 255, 252, 254}
	for _, kind := range []ObjectKind{PoolID, ProviderID, ServiceAccountID} {
		want, err := NewObjectID(kind, bytes.NewReader(valid))
		if err != nil {
			t.Fatal(err)
		}
		got, err := NewObjectID(kind, bytes.NewReader(append(bytes.Clone(biased), valid...)))
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("kind %d: %q after biased bytes, %q without; the biased bytes were used", kind, got, want)
		}
	}

	// The first character skips 234 to 255 (26 × 9 = 234); the rest skip 252
	// to 255 (36 × 7 = 252), and use 234 to 251.
	first := append([]byte{240, 233, 5}, make([]byte, 31)...)
	if got, err := NewObjectID(PoolID, bytes.NewReader(first)); err != nil || got != "zf"+strings.Repeat("a", 30) {
		t.Errorf("NewObjectID = %q, %v; want 240 skipped, 233 → z, 5 → f, then a", got, err)
	}
	rest := append([]byte{0, 252, 251, 234}, make([]byte, 29)...)
	if got, err := NewObjectID(PoolID, bytes.NewReader(rest)); err != nil || got != "a9s"+strings.Repeat("a", 29) {
		t.Errorf("NewObjectID = %q, %v; want 252 skipped, 251 → 9, 234 → s", got, err)
	}

	// It reads no byte past the last it uses.
	exact := bytes.NewReader(append(append(bytes.Clone(biased), valid[:40]...), 0x42))
	id, err := NewObjectID(PoolID, exact)
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 32 {
		t.Fatal(id)
	}
	if exact.Len() == 0 {
		t.Error("NewObjectID read past what it used")
	}
}
