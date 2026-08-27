package datasphere

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/sofmon/farcast/datasphere/internal/crypto"
)

// The keys are the operator's, full stop. The keyring's rest state is the
// operator's disk, in the instance's local store, beside the mTLS CA key — the
// repo's one existing precedent for a secret whose loss is existential.
//
// This package never reads or writes that file. It parses bytes handed to it
// and marshals bytes back, exactly as Planck receives credentials and persists
// none; the CLI and the harness own the file, its directory, and their modes.
// The constants below exist so that every one of those callers agrees on where
// the file lives and how tightly it is closed.
const (
	// KeysDirName is the per-instance subdirectory holding the keyring:
	// <config>/instances/<name>/datasphere/.
	KeysDirName = "datasphere"
	// KeysFileName is the keyring file within it.
	KeysFileName = "keys.yaml"
	// KeysDirMode and KeysFileMode are the only modes this file may rest under.
	KeysDirMode  = 0o700
	KeysFileMode = 0o600

	// keyringVersion is the keys.yaml schema this package writes and accepts.
	keyringVersion = 1
)

// KeyLossWarning is the sentence every keygen and every key-related failure
// must carry, verbatim. It is a constant rather than prose at each call site
// because the statement is load-bearing: an operator who has not internalised
// it will treat the keyring like a config file, and this file is strictly more
// dangerous to lose than the CA key — losing the CA costs a re-mint, losing
// this costs the data.
//
// The supported backup is the one the operator already owes the CA key: copy
// the instance directory offline. Both crown jewels in one gesture.
const KeyLossWarning = "loss of keys.yaml is permanent, unrecoverable loss of all stored data — FarCast keeps no copy anywhere, by design."

// ErrKeyringInvalid reports a keys.yaml that cannot be trusted: an unknown
// schema version, a malformed entry, a wrong-length key, a duplicate ID, or a
// missing key list.
var ErrKeyringInvalid = errors.New("datasphere: invalid keyring")

// KeyID is a keyring entry's 8-byte identifier. It is random material minted
// alongside the key and is never derived from it: an ID that were a hash of
// the key would let anyone holding a blob test candidate keys offline.
type KeyID [crypto.KeyIDLen]byte

// String renders the ID as lowercase hex — the form keys.yaml stores.
func (k KeyID) String() string { return hex.EncodeToString(k[:]) }

// ParseKeyID reads a KeyID from its hex form.
//
// Its errors describe the input without quoting it. A key id is not itself a
// secret, but this function is reached while parsing a file whose other fields
// are the most dangerous material in the system, and a transposed or
// mis-indented keys.yaml puts key bytes in the id field. Nothing on a parse
// path may echo bytes it has not proved are safe.
func ParseKeyID(s string) (KeyID, error) {
	var id KeyID
	raw, err := hex.DecodeString(s)
	if err != nil {
		return id, fmt.Errorf("%w: key id is not hexadecimal", ErrKeyringInvalid)
	}
	if len(raw) != crypto.KeyIDLen {
		return id, fmt.Errorf("%w: key id must be %d bytes, got %d", ErrKeyringInvalid, crypto.KeyIDLen, len(raw))
	}
	copy(id[:], raw)
	return id, nil
}

// KeyEntry is one key in the keyring. The material itself is unexported so
// that no caller outside this package can print it by reaching through the
// struct; ID and Created are safe to display and are what tooling shows.
type KeyEntry struct {
	ID      KeyID
	Created time.Time

	key []byte // crypto.KeyLen bytes — sensitive
}

// String renders the entry without its key material, so accidental logging
// (%v/%s) cannot expose the one secret that is the data.
func (e KeyEntry) String() string {
	material := "<none>"
	if len(e.key) > 0 {
		material = fmt.Sprintf("<redacted %d bytes>", len(e.key))
	}
	return fmt.Sprintf("KeyEntry{ID:%s Created:%s Key:%s}", e.ID, e.Created.UTC().Format(time.RFC3339), material)
}

// Keyring is the instance's key material, in memory. It holds two structurally
// separate lists:
//
//   - Name keys are stable. Deterministic name tokens cannot survive a key
//     change without renaming every stored object, so addressing is decoupled
//     from rotation: a KEK rotation must never touch how objects are found.
//   - Key-encryption keys rotate. The first entry wraps new writes; the rest
//     stay present to decrypt older blobs, which name their KEK by ID.
//
// Both are lists from day one so that a future rename sweep — old and new name
// keys live simultaneously while objects migrate — is representable without
// migrating the most dangerous file in the system.
//
// The zero Keyring is unusable; build one with NewKeyring or ParseKeyring.
type Keyring struct {
	nameKeys []KeyEntry
	keys     []KeyEntry
}

// Seams for deterministic tests. Production always reads crypto/rand and the
// wall clock.
var (
	keyRand io.Reader = rand.Reader
	keyNow            = func() time.Time { return time.Now().UTC().Truncate(time.Second) }
)

// NewKey mints one keyring entry: 32 bytes of key material and an independent
// 8-byte identifier.
func NewKey() (KeyEntry, error) {
	e := KeyEntry{Created: keyNow(), key: make([]byte, crypto.KeyLen)}
	if _, err := io.ReadFull(keyRand, e.key); err != nil {
		return KeyEntry{}, fmt.Errorf("datasphere: mint key material: %w", err)
	}
	if _, err := io.ReadFull(keyRand, e.ID[:]); err != nil {
		return KeyEntry{}, fmt.Errorf("datasphere: mint key id: %w", err)
	}
	return e, nil
}

// NewKeyring mints a fresh keyring: one name key and one key-encryption key.
// Whatever writes the result to disk must carry KeyLossWarning to the operator.
func NewKeyring() (Keyring, error) {
	nameKey, err := NewKey()
	if err != nil {
		return Keyring{}, err
	}
	kek, err := NewKey()
	if err != nil {
		return Keyring{}, err
	}
	return Keyring{nameKeys: []KeyEntry{nameKey}, keys: []KeyEntry{kek}}, nil
}

// ActiveNameKey is the entry that tokenizes and seals new writes.
func (k Keyring) ActiveNameKey() (KeyEntry, error) {
	if len(k.nameKeys) == 0 {
		return KeyEntry{}, fmt.Errorf("%w: no name keys", ErrKeyringInvalid)
	}
	return k.nameKeys[0], nil
}

// ActiveKEK is the entry that wraps new writes.
func (k Keyring) ActiveKEK() (KeyEntry, error) {
	if len(k.keys) == 0 {
		return KeyEntry{}, fmt.Errorf("%w: no keys", ErrKeyringInvalid)
	}
	return k.keys[0], nil
}

// NameKeys returns the name keys, active first. The slice is a copy; the key
// material inside it is not.
func (k Keyring) NameKeys() []KeyEntry { return append([]KeyEntry(nil), k.nameKeys...) }

// KEKs returns the key-encryption keys, active first.
func (k Keyring) KEKs() []KeyEntry { return append([]KeyEntry(nil), k.keys...) }

// AddKEK prepends a key-encryption key, making it the one that wraps new
// writes and leaving every existing entry in place to keep decrypting older
// blobs. This is the whole of rotation's shape; the sweep that retires the old
// entry is 3.3's `storage rekey`.
func (k Keyring) AddKEK(e KeyEntry) Keyring {
	k.keys = append([]KeyEntry{e}, k.keys...)
	return k
}

// Merge adds entries from other that this keyring does not already hold, and
// changes nothing it does.
//
// Merge-only is a security control, not a convenience. A blob's key ID is
// cloud-writable plaintext, so a tampering cloud can make any object demand a
// key the keyring lacks; the natural "restore from backup" response, performed
// as an overwrite, would destroy every key appended since that backup. Every
// restore, import, and reconcile — 3.3's `key import` included — goes through
// here.
//
// An ID present on both sides under different key material is refused outright
// rather than resolved: two independently minted 64-bit IDs do not collide by
// chance, so one of the two files is corrupt or hostile, and merging either
// way would produce a keyring that silently cannot read something.
func (k Keyring) Merge(other Keyring) (Keyring, error) {
	names, err := mergeEntries(k.nameKeys, other.nameKeys, "name key")
	if err != nil {
		return Keyring{}, err
	}
	keks, err := mergeEntries(k.keys, other.keys, "key")
	if err != nil {
		return Keyring{}, err
	}
	return Keyring{nameKeys: names, keys: keks}, nil
}

func mergeEntries(live, incoming []KeyEntry, what string) ([]KeyEntry, error) {
	held := make(map[KeyID]KeyEntry, len(live))
	for _, e := range live {
		held[e.ID] = e
	}
	out := append([]KeyEntry(nil), live...)
	for _, e := range incoming {
		existing, ok := held[e.ID]
		if !ok {
			held[e.ID] = e
			out = append(out, e)
			continue
		}
		if string(existing.key) != string(e.key) {
			return nil, fmt.Errorf("%w: %s %s appears with two different values; refusing to merge", ErrKeyringInvalid, what, e.ID)
		}
	}
	return out, nil
}

// Valid reports whether the keyring is usable: both lists populated, every
// entry carrying a full-length key, and no duplicate IDs within a list.
func (k Keyring) Valid() error {
	if len(k.nameKeys) == 0 {
		return fmt.Errorf("%w: no name keys", ErrKeyringInvalid)
	}
	if len(k.keys) == 0 {
		return fmt.Errorf("%w: no keys", ErrKeyringInvalid)
	}
	if err := validEntries(k.nameKeys, "name key"); err != nil {
		return err
	}
	return validEntries(k.keys, "key")
}

func validEntries(entries []KeyEntry, what string) error {
	seen := make(map[KeyID]struct{}, len(entries))
	for _, e := range entries {
		if len(e.key) != crypto.KeyLen {
			return fmt.Errorf("%w: %s %s must be %d bytes, got %d", ErrKeyringInvalid, what, e.ID, crypto.KeyLen, len(e.key))
		}
		if _, dup := seen[e.ID]; dup {
			return fmt.Errorf("%w: duplicate %s id %s", ErrKeyringInvalid, what, e.ID)
		}
		seen[e.ID] = struct{}{}
	}
	return nil
}

// String renders the keyring without any key material.
func (k Keyring) String() string {
	ids := func(entries []KeyEntry) string {
		out := make([]string, len(entries))
		for i, e := range entries {
			out[i] = e.ID.String()
		}
		return "[" + strings.Join(out, " ") + "]"
	}
	return fmt.Sprintf("Keyring{NameKeys:%s Keys:%s Material:<redacted>}", ids(k.nameKeys), ids(k.keys))
}

// raw drops the KeyID's name for the crypto layer, which deliberately knows
// nothing of this package's types.
func (k KeyID) raw() [crypto.KeyIDLen]byte { return k }

// lookup adapts the keyring to the crypto layer's KEK resolver.
func (k Keyring) lookup() crypto.KeyLookup {
	return func(id [crypto.KeyIDLen]byte) ([]byte, bool) {
		for _, e := range k.keys {
			if e.ID == KeyID(id) {
				return e.key, true
			}
		}
		return nil, false
	}
}

// keyringFile is the on-disk shape of keys.yaml. It is versioned from day one
// because this is the file no operator can afford a migration accident in.
type keyringFile struct {
	Version  int            `yaml:"version"`
	NameKeys []keyEntryFile `yaml:"name_keys"`
	Keys     []keyEntryFile `yaml:"keys"`
}

type keyEntryFile struct {
	ID      string    `yaml:"id"`
	Key     string    `yaml:"key"`
	Created time.Time `yaml:"created"`
}

// ParseKeyring reads a keys.yaml. It validates before returning, so no caller
// ever holds a half-usable keyring.
func ParseKeyring(data []byte) (Keyring, error) {
	var file keyringFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return Keyring{}, fmt.Errorf("%w: %s", ErrKeyringInvalid, yamlErrorMessage(data, err))
	}
	if file.Version != keyringVersion {
		return Keyring{}, fmt.Errorf("%w: unsupported version %d (this build writes %d)", ErrKeyringInvalid, file.Version, keyringVersion)
	}
	nameKeys, err := parseEntries(file.NameKeys, "name key")
	if err != nil {
		return Keyring{}, err
	}
	keys, err := parseEntries(file.Keys, "key")
	if err != nil {
		return Keyring{}, err
	}
	k := Keyring{nameKeys: nameKeys, keys: keys}
	if err := k.Valid(); err != nil {
		return Keyring{}, err
	}
	return k, nil
}

func parseEntries(entries []keyEntryFile, what string) ([]KeyEntry, error) {
	out := make([]KeyEntry, 0, len(entries))
	for i, e := range entries {
		id, err := ParseKeyID(e.ID)
		if err != nil {
			// Named by position, not by value: until ParseKeyID succeeds there
			// is no proof that what sits in the id field is an id.
			return nil, fmt.Errorf("%s %d: %w", what, i+1, err)
		}
		material, err := base64.StdEncoding.DecodeString(e.Key)
		if err != nil {
			return nil, fmt.Errorf("%w: %s %s is not base64", ErrKeyringInvalid, what, e.ID)
		}
		if len(material) != crypto.KeyLen {
			return nil, fmt.Errorf("%w: %s %s must be %d bytes, got %d", ErrKeyringInvalid, what, e.ID, crypto.KeyLen, len(material))
		}
		out = append(out, KeyEntry{ID: id, Created: e.Created.UTC(), key: material})
	}
	return out, nil
}

// yamlErrorMessage renders a YAML failure without the source window the parser
// would otherwise print around it.
//
// This is not defensive tidiness. goccy/go-yaml renders three lines either side
// of the offending token verbatim, and keys.yaml is nine lines long — so the
// natural fmt.Errorf("%v", err) prints the base64 key material straight to
// whatever the caller's stderr happens to be: terminal scrollback, a shell
// redirect at umask 0644, a pasted bug report. The file the operator was told
// to guard with 0600 would leak because they mis-indented a line. The name key
// cannot rotate, so for stored names that exposure would be permanent.
//
// FormatError's source-free form keeps the position and the diagnosis, which is
// what an operator repairing a hand-edited file actually needs. The scan after
// it is belt and braces against a future library version that renders content
// some other way: if the message quotes any substantial line of the file, the
// message is withheld entirely rather than trusted.
func yamlErrorMessage(data []byte, err error) string {
	message := yaml.FormatError(err, false, false)
	for _, line := range strings.Split(string(data), "\n") {
		if trimmed := strings.TrimSpace(line); len(trimmed) >= 8 && strings.Contains(message, trimmed) {
			return "keys.yaml is not valid YAML (the parser's own message is withheld: it quotes the file, and this file holds key material)"
		}
	}
	return message
}

// Marshal renders the keyring as keys.yaml. The caller writes it at
// KeysFileMode and tells the operator KeyLossWarning.
func (k Keyring) Marshal() ([]byte, error) {
	if err := k.Valid(); err != nil {
		return nil, err
	}
	file := keyringFile{
		Version:  keyringVersion,
		NameKeys: marshalEntries(k.nameKeys),
		Keys:     marshalEntries(k.keys),
	}
	out, err := yaml.Marshal(file)
	if err != nil {
		return nil, fmt.Errorf("datasphere: encode keyring: %w", err)
	}
	return out, nil
}

func marshalEntries(entries []KeyEntry) []keyEntryFile {
	out := make([]keyEntryFile, len(entries))
	for i, e := range entries {
		out[i] = keyEntryFile{
			ID:      e.ID.String(),
			Key:     base64.StdEncoding.EncodeToString(e.key),
			Created: e.Created.UTC(),
		}
	}
	return out
}
