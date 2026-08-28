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

	// keyringVersion is the keys.yaml schema a keyring without scopes writes.
	keyringVersion = 1

	// keyringVersionScopes is written only once a keyring carries scopes.
	//
	// The bump is conditional on purpose. A file with no scopes marshals
	// byte-identically to what every previous build wrote, so no existing
	// keyring moves and no golden vector changes. A file that HAS grown
	// scopes is refused outright by an older binary rather than parsed with
	// the scope material silently dropped — which would leave the operator
	// holding a keyring that looks complete and cannot read a whole subtree.
	// Failing closed on the most dangerous file in the system is the only
	// acceptable direction.
	keyringVersionScopes = 2
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

	// scopes are named subtrees with their own key material, so that a
	// cluster can be given one subtree's keys without ever holding these.
	scopes []Scope
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

// Scopes returns the keyring's scopes. The slice is a copy; the key material
// inside it is not.
func (k Keyring) Scopes() []Scope { return append([]Scope(nil), k.scopes...) }

// ScopeNamed returns the scope with that name.
func (k Keyring) ScopeNamed(name string) (Scope, bool) {
	for _, s := range k.scopes {
		if s.Name == name {
			return s, true
		}
	}
	return Scope{}, false
}

// ScopeOwning returns the scope whose prefix contains the logical key. Keys
// outside every scope belong to the master keyring — the operator's own.
func (k Keyring) ScopeOwning(key string) (Scope, bool) {
	for _, s := range k.scopes {
		if s.Owns(key) {
			return s, true
		}
	}
	return Scope{}, false
}

// AddScope returns a keyring carrying one more scope.
//
// A duplicate name, or a prefix that overlaps one already present, is refused:
// a key addressable under two scopes would be stored twice under two different
// name keys, and neither copy would be visible from the other scope.
func (k Keyring) AddScope(s Scope) (Keyring, error) {
	if err := s.Valid(); err != nil {
		return Keyring{}, err
	}
	for _, existing := range k.scopes {
		if existing.Name == s.Name {
			return Keyring{}, fmt.Errorf("%w: scope %q already exists", ErrKeyringInvalid, s.Name)
		}
		if scopesOverlap(existing.Prefix, s.Prefix) {
			return Keyring{}, fmt.Errorf("%w: scope %q prefix %q overlaps scope %q prefix %q",
				ErrKeyringInvalid, s.Name, s.Prefix, existing.Name, existing.Prefix)
		}
	}
	k.scopes = append(append([]Scope(nil), k.scopes...), s)
	return k, nil
}

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
	scopes, err := mergeScopes(k.scopes, other.scopes)
	if err != nil {
		return Keyring{}, err
	}
	return Keyring{nameKeys: names, keys: keks, scopes: scopes}, nil
}

// mergeScopes applies the merge-only rule to scopes. A scope present on both
// sides has its key lists merged, so an import can add a rotated scope KEK
// without discarding the entry that still decrypts older objects. A scope
// whose prefix differs between the two files is refused: the same name over
// two subtrees means one of the files is wrong, and picking either would make
// part of the data unaddressable.
func mergeScopes(live, incoming []Scope) ([]Scope, error) {
	out := append([]Scope(nil), live...)
	at := make(map[string]int, len(out))
	for i, s := range out {
		at[s.Name] = i
	}
	for _, s := range incoming {
		i, ok := at[s.Name]
		if !ok {
			for _, existing := range out {
				if scopesOverlap(existing.Prefix, s.Prefix) {
					return nil, fmt.Errorf("%w: incoming scope %q prefix %q overlaps scope %q prefix %q",
						ErrKeyringInvalid, s.Name, s.Prefix, existing.Name, existing.Prefix)
				}
			}
			at[s.Name] = len(out)
			out = append(out, s)
			continue
		}
		if out[i].Prefix != s.Prefix {
			return nil, fmt.Errorf("%w: scope %q appears with two prefixes (%q and %q); refusing to merge",
				ErrKeyringInvalid, s.Name, out[i].Prefix, s.Prefix)
		}
		merged, err := out[i].keys.Merge(s.keys)
		if err != nil {
			return nil, fmt.Errorf("scope %q: %w", s.Name, err)
		}
		out[i].keys = merged
	}
	return out, nil
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
	if err := validEntries(k.keys, "key"); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(k.scopes))
	for _, s := range k.scopes {
		if err := s.Valid(); err != nil {
			return err
		}
		if _, dup := seen[s.Name]; dup {
			return fmt.Errorf("%w: duplicate scope %q", ErrKeyringInvalid, s.Name)
		}
		seen[s.Name] = struct{}{}
	}
	for i, a := range k.scopes {
		for _, b := range k.scopes[i+1:] {
			if scopesOverlap(a.Prefix, b.Prefix) {
				return fmt.Errorf("%w: scope %q prefix %q overlaps scope %q prefix %q",
					ErrKeyringInvalid, a.Name, a.Prefix, b.Name, b.Prefix)
			}
		}
	}
	return nil
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
	names := make([]string, len(k.scopes))
	for i, s := range k.scopes {
		names[i] = s.Name
	}
	return fmt.Sprintf("Keyring{NameKeys:%s Keys:%s Scopes:[%s] Material:<redacted>}",
		ids(k.nameKeys), ids(k.keys), strings.Join(names, " "))
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
	Scopes   []scopeFile    `yaml:"scopes,omitempty"`
}

// scopeFile is a scope's on-disk shape. Its key lists use the same entry shape
// as the master's, so one parser and one redaction discipline cover both.
type scopeFile struct {
	Name       string         `yaml:"name"`
	Prefix     string         `yaml:"prefix"`
	Created    time.Time      `yaml:"created"`
	Derivation string         `yaml:"derivation,omitempty"`
	NameKeys   []keyEntryFile `yaml:"name_keys"`
	Keys       []keyEntryFile `yaml:"keys"`
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
	if file.Version != keyringVersion && file.Version != keyringVersionScopes {
		return Keyring{}, fmt.Errorf("%w: unsupported version %d (this build writes %d, or %d once scopes are present)",
			ErrKeyringInvalid, file.Version, keyringVersion, keyringVersionScopes)
	}
	if file.Version == keyringVersion && len(file.Scopes) > 0 {
		return Keyring{}, fmt.Errorf("%w: version %d file carries scopes, which are version %d — refusing rather than guessing which half is right",
			ErrKeyringInvalid, keyringVersion, keyringVersionScopes)
	}
	nameKeys, err := parseEntries(file.NameKeys, "name key")
	if err != nil {
		return Keyring{}, err
	}
	keys, err := parseEntries(file.Keys, "key")
	if err != nil {
		return Keyring{}, err
	}
	scopes, err := parseScopes(file.Scopes)
	if err != nil {
		return Keyring{}, err
	}
	k := Keyring{nameKeys: nameKeys, keys: keys, scopes: scopes}
	if err := k.Valid(); err != nil {
		return Keyring{}, err
	}
	return k, nil
}

func parseScopes(entries []scopeFile) ([]Scope, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	out := make([]Scope, 0, len(entries))
	for i, s := range entries {
		// Named by position until the name is proved well-formed: a
		// mis-indented file can put key material in the name field, and
		// nothing on a parse path may echo bytes it has not vetted.
		if err := ValidateScopeName(s.Name); err != nil {
			return nil, fmt.Errorf("scope %d: %w", i+1, err)
		}
		if err := ValidateScopePrefix(s.Prefix); err != nil {
			return nil, fmt.Errorf("scope %q: %w", s.Name, err)
		}
		nameKeys, err := parseEntries(s.NameKeys, "name key")
		if err != nil {
			return nil, fmt.Errorf("scope %q: %w", s.Name, err)
		}
		keys, err := parseEntries(s.Keys, "key")
		if err != nil {
			return nil, fmt.Errorf("scope %q: %w", s.Name, err)
		}
		scope := Scope{
			Name:       s.Name,
			Prefix:     s.Prefix,
			Created:    s.Created.UTC(),
			Derivation: s.Derivation,
			keys:       Keyring{nameKeys: nameKeys, keys: keys},
		}
		if err := scope.Valid(); err != nil {
			return nil, fmt.Errorf("scope %q: %w", s.Name, err)
		}
		out = append(out, scope)
	}
	return out, nil
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
	version := keyringVersion
	if len(k.scopes) > 0 {
		version = keyringVersionScopes
	}
	file := keyringFile{
		Version:  version,
		NameKeys: marshalEntries(k.nameKeys),
		Keys:     marshalEntries(k.keys),
		Scopes:   marshalScopes(k.scopes),
	}
	out, err := yaml.Marshal(file)
	if err != nil {
		return nil, fmt.Errorf("datasphere: encode keyring: %w", err)
	}
	return out, nil
}

func marshalScopes(scopes []Scope) []scopeFile {
	if len(scopes) == 0 {
		return nil
	}
	out := make([]scopeFile, len(scopes))
	for i, s := range scopes {
		out[i] = scopeFile{
			Name:       s.Name,
			Prefix:     s.Prefix,
			Created:    s.Created.UTC(),
			Derivation: s.Derivation,
			NameKeys:   marshalEntries(s.keys.nameKeys),
			Keys:       marshalEntries(s.keys.keys),
		}
	}
	return out
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
