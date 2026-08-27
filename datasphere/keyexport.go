package datasphere

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/goccy/go-yaml"
	"github.com/sofmon/farcast/datasphere/internal/crypto"
)

// A keyring leaves this machine exactly once and only in this shape:
// passphrase-armored, so the copy an operator carries to their offline backup
// is not a plaintext copy of the most dangerous file in the system.
//
// The supported backup remains the one the operator already owes the CA key —
// copy the instance directory offline — and this exists for the case that one
// does not cover: moving a keyring between machines, or handing it to a
// colleague, where the file is in transit through somewhere neither end
// controls.
const (
	exportVersion = 1
	exportKDF     = "pbkdf2-sha256"

	// exportIterations is deliberately expensive. The thing this passphrase
	// protects is every byte the instance has ever stored, and the file is
	// opened by a human at human intervals, so a slow derivation costs an
	// operator a moment and an attacker a fortune.
	exportIterations = 600_000

	exportSaltLen = 16

	// minPassphraseLen is a floor, not a policy. A four-character passphrase
	// over an offline copy of the keyring is not protection, and silently
	// accepting one would be worse than refusing it.
	minPassphraseLen = 12
)

// ErrExportInvalid reports an armored keyring that cannot be trusted: an
// unknown version or KDF, a malformed field, or a wrong passphrase.
var ErrExportInvalid = errors.New("datasphere: invalid keyring export")

// exportFile is the on-disk shape of an armored keyring. Everything except the
// payload is public, and all of it is authenticated: the KDF parameters are
// bound into the ciphertext's AAD, so an attacker cannot weaken a derivation
// by editing the file and have the result still open.
type exportFile struct {
	Version    int    `yaml:"version"`
	KDF        string `yaml:"kdf"`
	Iterations int    `yaml:"iterations"`
	Salt       string `yaml:"salt"`
	Nonce      string `yaml:"nonce"`
	Payload    string `yaml:"payload"`
}

// ExportKeyring renders a keyring as a passphrase-armored file.
func ExportKeyring(keyring Keyring, passphrase string) ([]byte, error) {
	if len([]rune(passphrase)) < minPassphraseLen {
		return nil, fmt.Errorf("datasphere: the passphrase must be at least %d characters; it protects every byte this instance has stored", minPassphraseLen)
	}
	plaintext, err := keyring.Marshal()
	if err != nil {
		return nil, err
	}
	salt := make([]byte, exportSaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("datasphere: read export salt: %w", err)
	}
	nonce := make([]byte, crypto.NonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("datasphere: read export nonce: %w", err)
	}
	gcm, err := exportCipher(passphrase, salt, exportIterations)
	if err != nil {
		return nil, err
	}
	file := exportFile{
		Version:    exportVersion,
		KDF:        exportKDF,
		Iterations: exportIterations,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
	}
	file.Payload = base64.StdEncoding.EncodeToString(gcm.Seal(nil, nonce, plaintext, exportAAD(file)))
	out, err := yaml.Marshal(file)
	if err != nil {
		return nil, fmt.Errorf("datasphere: encode keyring export: %w", err)
	}
	return out, nil
}

// ImportKeyring opens a passphrase-armored keyring.
//
// It returns the keyring the file held. Merging it into a live one is the
// caller's next step and must go through Keyring.Merge: an import that
// replaced a keyring would destroy every key added since the export, which is
// exactly the key-loss catastrophe a tampering cloud would steer an operator
// into.
func ImportKeyring(data []byte, passphrase string) (Keyring, error) {
	var file exportFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		// The parser renders a window of the source around an error, and this
		// file's source is armored key material. Only the shape is reported.
		return Keyring{}, fmt.Errorf("%w: the file is not a valid keyring export", ErrExportInvalid)
	}
	if file.Version != exportVersion || file.KDF != exportKDF {
		return Keyring{}, fmt.Errorf("%w: unsupported version %d / kdf %q", ErrExportInvalid, file.Version, file.KDF)
	}
	if file.Iterations < 1 {
		return Keyring{}, fmt.Errorf("%w: iteration count %d", ErrExportInvalid, file.Iterations)
	}
	salt, err := base64.StdEncoding.DecodeString(file.Salt)
	if err != nil {
		return Keyring{}, fmt.Errorf("%w: salt is not base64", ErrExportInvalid)
	}
	nonce, err := base64.StdEncoding.DecodeString(file.Nonce)
	if err != nil || len(nonce) != crypto.NonceLen {
		return Keyring{}, fmt.Errorf("%w: nonce is malformed", ErrExportInvalid)
	}
	payload, err := base64.StdEncoding.DecodeString(file.Payload)
	if err != nil {
		return Keyring{}, fmt.Errorf("%w: payload is not base64", ErrExportInvalid)
	}
	gcm, err := exportCipher(passphrase, salt, file.Iterations)
	if err != nil {
		return Keyring{}, err
	}
	plaintext, err := gcm.Open(nil, nonce, payload, exportAAD(file))
	if err != nil {
		// A wrong passphrase and a tampered file are indistinguishable here,
		// and saying which would tell an attacker which half they got right.
		return Keyring{}, fmt.Errorf("%w: wrong passphrase, or the file has been modified", ErrExportInvalid)
	}
	return ParseKeyring(plaintext)
}

// exportCipher derives the file's key from the passphrase.
func exportCipher(passphrase string, salt []byte, iterations int) (cipher.AEAD, error) {
	key, err := pbkdf2.Key(sha256.New, passphrase, salt, iterations, crypto.KeyLen)
	if err != nil {
		return nil, fmt.Errorf("datasphere: derive the export key: %w", err)
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// exportAAD binds the ciphertext to the parameters that produced it, so the
// KDF cannot be weakened by editing the file.
func exportAAD(file exportFile) []byte {
	return fmt.Appendf(nil, "farcast/datasphere/keyring-export/v%d\n%s\n%d\n%s",
		file.Version, file.KDF, file.Iterations, file.Salt)
}
