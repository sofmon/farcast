package datasphere

import (
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"crypto/rand"

	"github.com/goccy/go-yaml"

	"github.com/sofmon/farcast/datasphere/internal/crypto"
)

// Passphrase-armored transport for material that leaves this machine.
//
// `farcast storage key export` (keyexport.go) armors a keyring this way, and
// phase 5.4's keeper packet armors a scope bundle plus a device's own leaf the
// same way. They share one KDF and one AEAD deliberately: there is exactly one
// place in this module where a passphrase becomes a key, and a second
// implementation would be a second thing to get wrong.
//
// What separates the two artifacts is the LABEL, which is authenticated. A
// keyring export cannot be opened as a keeper packet and a keeper packet
// cannot be opened as a keyring, even under the right passphrase — so a file
// substituted for the other is refused rather than parsed into the wrong shape
// by a caller that was expecting one and got the other.

// ArmorLabel names the kind of material inside an armored file. It is bound
// into the ciphertext's associated data, so it cannot be edited.
type ArmorLabel string

const (
	// ArmorKeeperPacket is a keeper enrolment packet: one device's leaf and
	// the scope bundle it re-seeds with.
	ArmorKeeperPacket ArmorLabel = "keeper-packet"
)

// armorFile is the on-disk shape. Everything except the payload is public and
// all of it is authenticated, so an attacker cannot weaken the derivation by
// editing the file and still have the result open.
type armorFile struct {
	Version    int    `yaml:"version"`
	Label      string `yaml:"label"`
	KDF        string `yaml:"kdf"`
	Iterations int    `yaml:"iterations"`
	Salt       string `yaml:"salt"`
	Nonce      string `yaml:"nonce"`
	Payload    string `yaml:"payload"`
}

// Armor renders plaintext as a passphrase-armored file under a label.
//
// The passphrase floor is the same as a keyring export's, and for the same
// reason: what this protects is key material at rest on media the operator is
// about to move between machines.
func Armor(label ArmorLabel, plaintext []byte, passphrase string) ([]byte, error) {
	if label == "" {
		return nil, fmt.Errorf("datasphere: armored material must be labelled")
	}
	if len([]rune(passphrase)) < minPassphraseLen {
		return nil, fmt.Errorf("datasphere: the passphrase must be at least %d characters; it protects key material in transit between machines", minPassphraseLen)
	}
	salt := make([]byte, exportSaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("datasphere: read armor salt: %w", err)
	}
	nonce := make([]byte, crypto.NonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("datasphere: read armor nonce: %w", err)
	}
	gcm, err := exportCipher(passphrase, salt, exportIterations)
	if err != nil {
		return nil, err
	}
	file := armorFile{
		Version:    exportVersion,
		Label:      string(label),
		KDF:        exportKDF,
		Iterations: exportIterations,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
	}
	file.Payload = base64.StdEncoding.EncodeToString(gcm.Seal(nil, nonce, plaintext, armorAAD(file)))
	out, err := yaml.Marshal(file)
	if err != nil {
		return nil, fmt.Errorf("datasphere: encode armored material: %w", err)
	}
	return out, nil
}

// Unarmor opens armored material, refusing anything that is not the expected
// label.
//
// Every failure — wrong passphrase, wrong label, unknown version or KDF,
// malformed field, failed authentication — is one error. A caller learns the
// file did not open and nothing about which check refused it.
func Unarmor(label ArmorLabel, data []byte, passphrase string) ([]byte, error) {
	var file armorFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		// The parser renders a window of the source around an error, and this
		// file's source is armored key material. Only the shape is reported.
		return nil, fmt.Errorf("%w: the file is not armored material", ErrExportInvalid)
	}
	if file.Version != exportVersion || file.KDF != exportKDF {
		return nil, fmt.Errorf("%w: unsupported version or key-derivation function", ErrExportInvalid)
	}
	if !strings.EqualFold(file.Label, string(label)) {
		// Named on both sides. Handing a keyring export to a keeper is a
		// plausible mistake and the operator needs to see which file they
		// picked up, not merely that it failed to open.
		return nil, fmt.Errorf("%w: this file holds %q, and %q was expected",
			ErrExportInvalid, file.Label, label)
	}
	if file.Iterations < exportIterations {
		// A file may specify MORE work than today's default; less is either a
		// downgrade attempt or material from a build that protected it worse.
		return nil, fmt.Errorf("%w: the file specifies fewer derivation rounds than this build accepts", ErrExportInvalid)
	}
	salt, err := base64.StdEncoding.DecodeString(file.Salt)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed salt", ErrExportInvalid)
	}
	nonce, err := base64.StdEncoding.DecodeString(file.Nonce)
	if err != nil || len(nonce) != crypto.NonceLen {
		return nil, fmt.Errorf("%w: malformed nonce", ErrExportInvalid)
	}
	payload, err := base64.StdEncoding.DecodeString(file.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed payload", ErrExportInvalid)
	}
	gcm, err := exportCipher(passphrase, salt, file.Iterations)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, payload, armorAAD(file))
	if err != nil {
		return nil, fmt.Errorf("%w: the passphrase is wrong or the file has been altered", ErrExportInvalid)
	}
	return plaintext, nil
}

// armorAAD binds the ciphertext to the parameters and the label that produced
// it, so neither the derivation nor the kind of material can be edited.
func armorAAD(file armorFile) []byte {
	return fmt.Appendf(nil, "farcast/datasphere/armor/v%d\n%s\n%s\n%d\n%s",
		file.Version, file.Label, file.KDF, file.Iterations, file.Salt)
}
