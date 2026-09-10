package datasphere

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

const armorPass = "correct-horse-battery-staple"

func TestArmorRoundTrip(t *testing.T) {
	want := []byte("scope keys and a device leaf")
	sealed, err := Armor(ArmorKeeperPacket, want, armorPass)
	if err != nil {
		t.Fatalf("Armor: %v", err)
	}
	if bytes.Contains(sealed, want) {
		t.Error("the armored file contains its own plaintext")
	}
	got, err := Unarmor(ArmorKeeperPacket, sealed, armorPass)
	if err != nil {
		t.Fatalf("Unarmor: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("round trip = %q, want %q", got, want)
	}
}

func TestArmorRefusals(t *testing.T) {
	sealed, err := Armor(ArmorKeeperPacket, []byte("material"), armorPass)
	if err != nil {
		t.Fatalf("Armor: %v", err)
	}

	if _, err := Unarmor(ArmorKeeperPacket, sealed, "wrong-passphrase-here"); !errors.Is(err, ErrExportInvalid) {
		t.Errorf("a wrong passphrase = %v, want ErrExportInvalid", err)
	}

	// One flipped byte anywhere in the payload must fail authentication.
	altered := append([]byte(nil), sealed...)
	i := bytes.Index(altered, []byte("payload: "))
	if i < 0 {
		t.Fatal("no payload field")
	}
	altered[i+12] ^= 0x01
	if _, err := Unarmor(ArmorKeeperPacket, altered, armorPass); !errors.Is(err, ErrExportInvalid) {
		t.Errorf("an altered payload = %v, want ErrExportInvalid", err)
	}

	// The derivation cost is authenticated, so it cannot be edited downwards.
	weakened := bytes.Replace(sealed, []byte("iterations: 600000"), []byte("iterations: 000001"), 1)
	if !bytes.Contains(weakened, []byte("iterations: 000001")) {
		t.Fatal("the iterations field was not where the test expected it")
	}
	if _, err := Unarmor(ArmorKeeperPacket, weakened, armorPass); !errors.Is(err, ErrExportInvalid) {
		t.Errorf("a weakened derivation = %v, want ErrExportInvalid", err)
	}

	if _, err := Armor(ArmorKeeperPacket, []byte("m"), "short"); err == nil {
		t.Error("Armor accepted a passphrase below the floor")
	}
	if _, err := Armor("", []byte("m"), armorPass); err == nil {
		t.Error("Armor accepted unlabelled material")
	}
}

// The label is what stops one artifact opening as another. A keyring export
// handed to a keeper must be refused by NAME, not merely fail to parse — the
// operator needs to see which file they picked up.
func TestArmorLabelsSeparateArtifacts(t *testing.T) {
	sealed, err := Armor(ArmorKeeperPacket, []byte("material"), armorPass)
	if err != nil {
		t.Fatalf("Armor: %v", err)
	}
	_, err = Unarmor(ArmorLabel("keyring-export"), sealed, armorPass)
	if !errors.Is(err, ErrExportInvalid) {
		t.Fatalf("a mislabelled open = %v, want ErrExportInvalid", err)
	}
	if !strings.Contains(err.Error(), "keeper-packet") {
		t.Errorf("the refusal does not name what the file actually holds: %v", err)
	}

	// And a keyring export is not a keeper packet, under any passphrase.
	keyring, err := NewKeyring()
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	export, err := ExportKeyring(keyring, armorPass)
	if err != nil {
		t.Fatalf("ExportKeyring: %v", err)
	}
	if _, err := Unarmor(ArmorKeeperPacket, export, armorPass); !errors.Is(err, ErrExportInvalid) {
		t.Errorf("a keyring export opened as a keeper packet: %v", err)
	}
}
