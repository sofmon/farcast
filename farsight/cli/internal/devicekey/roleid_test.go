package devicekey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
)

// TestRoleIDIs128RandomBitsInLowerHex: an ID is exactly one 16-byte draw,
// written as lowercase hex; an all-zero draw, a short draw and a failing
// source are refused.
func TestRoleIDIs128RandomBitsInLowerHex(t *testing.T) {
	src := bytes.NewReader([]byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x77,
	})
	id, err := NewRoleID(src)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := id.Hex(), "0123456789abcdeffedcba9876543210"; got != want {
		t.Errorf("Hex = %q, want %q", got, want)
	}
	if src.Len() != 1 {
		t.Errorf("NewRoleID left %d of 17 bytes; want exactly 16 read", src.Len())
	}
	if id.IsZero() {
		t.Error("a drawn ID is zero")
	}
	if _, err := NewRoleID(bytes.NewReader(make([]byte, 16))); err == nil {
		t.Error("an all-zero draw was accepted")
	}
	if _, err := NewRoleID(bytes.NewReader(make([]byte, 15))); err == nil {
		t.Error("a 15-byte draw was accepted")
	}
	if _, err := NewRoleID(failingReader{}); err == nil {
		t.Error("a failing reader gave an ID")
	}
	if _, err := NewRoleID(nil); err == nil {
		t.Error("a nil reader gave an ID")
	}
	var zero RoleID
	if !zero.IsZero() || zero.Hex() != "" {
		t.Errorf("the zero RoleID: IsZero %v, Hex %q", zero.IsZero(), zero.Hex())
	}
}

// recordingReader records each read's bytes from a known stream.
type recordingReader struct {
	src   *detStream
	draws [][]byte
}

func (r *recordingReader) Read(p []byte) (int, error) {
	n, err := r.src.Read(p)
	r.draws = append(r.draws, bytes.Clone(p[:n]))
	return n, err
}

// TestEnrolDrawsTheRoleIDFromRnd: each role ID is one 16-byte draw from rnd,
// and none is derived from the anchor's key.
func TestEnrolDrawsTheRoleIDFromRnd(t *testing.T) {
	rec := &recordingReader{src: &detStream{seed: "devicekey-test/enrol"}}
	_, ids, err := Enrol(rec, filepath.Join(t.TempDir(), "identity"), []Role{Reader, Writer}, t0)
	if err != nil {
		t.Fatal(err)
	}
	first := make([]byte, 16)
	if _, err := (&detStream{seed: "devicekey-test/enrol"}).Read(first); err != nil {
		t.Fatal(err)
	}
	if ids[0].ID().Hex() != hex.EncodeToString(first) {
		t.Error("the reader's ID is not the stream's first 16 bytes, the first thing Enrol draws")
	}
	for _, id := range ids {
		h := id.ID().Hex()
		raw, err := hex.DecodeString(h)
		if err != nil || len(raw) != 16 {
			t.Fatalf("the %s ID is not 16 bytes of hex", id.Role())
		}
		drawn := 0
		for _, d := range rec.draws {
			if len(d) == 16 && bytes.Equal(d, raw) {
				drawn++
			}
		}
		if drawn != 1 {
			t.Errorf("the %s ID is %d of rnd's 16-byte draws; want exactly one", id.Role(), drawn)
		}
		anchor, err := x509.ParseCertificate(id.AnchorDER())
		if err != nil {
			t.Fatal(err)
		}
		point, err := anchor.PublicKey.(*ecdsa.PublicKey).Bytes()
		if err != nil {
			t.Fatal(err)
		}
		for name, data := range map[string][]byte{"point": point, "SPKI": anchor.RawSubjectPublicKeyInfo} {
			sum := sha256.Sum256(data)
			full := hex.EncodeToString(sum[:])
			if strings.Contains(full, h) || h == full[:32] || h == full[32:] {
				t.Errorf("the %s ID is derived from the anchor's %s", id.Role(), name)
			}
		}
		if anchor.Subject.CommonName != h {
			t.Errorf("the %s anchor's CN is not its ID", id.Role())
		}
	}
	if ids[0].ID().Equal(ids[1].ID()) {
		t.Error("the two roles share an ID")
	}
}

// TestParseRoleIDAcceptsOnlyItsShape: exactly 32 lowercase hex characters;
// the error never quotes its input; Equal is byte equality.
func TestParseRoleIDAcceptsOnlyItsShape(t *testing.T) {
	const good = "00112233445566778899aabbccddeeff"
	id, err := ParseRoleID(good)
	if err != nil {
		t.Fatal(err)
	}
	if id.Hex() != good {
		t.Errorf("Hex = %q", id.Hex())
	}
	for _, bad := range []string{
		strings.ToUpper(good),
		"00112233445566778899AABBCCDDEEFF",
		"00112233445566778899aabbccddeeFf",
		good[:31],
		good + "0",
		"g0112233445566778899aabbccddeeff",
		" " + good[1:],
		good[:31] + "\n",
		good[:16] + " " + good[17:],
		"0x112233445566778899aabbccddeeff",
		"",
		strings.Repeat("ü", 16),
	} {
		_, err := ParseRoleID(bad)
		if err == nil {
			t.Errorf("ParseRoleID(%q) succeeded", bad)
			continue
		}
		if bad != "" && (strings.Contains(err.Error(), bad) || strings.Contains(strings.ToLower(err.Error()), strings.ToLower(strings.TrimSpace(bad)))) {
			t.Errorf("the error %q quotes its input", err)
		}
	}
	again, err := ParseRoleID(good)
	if err != nil {
		t.Fatal(err)
	}
	if !id.Equal(again) || !again.Equal(id) {
		t.Error("two parses of one hex are not Equal")
	}
	if id == again {
		t.Error("two parses share one array; each must allocate its own")
	}
	other, err := ParseRoleID("00112233445566778899aabbccddeefe")
	if err != nil {
		t.Fatal(err)
	}
	if id.Equal(other) {
		t.Error("IDs differing in one bit are Equal")
	}
	var zero RoleID
	if !zero.Equal(RoleID{}) || zero.Equal(id) || id.Equal(zero) {
		t.Error("Equal mishandles the zero RoleID")
	}
}
