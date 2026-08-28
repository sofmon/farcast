package datasphere

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/sofmon/farcast/datasphere/internal/crypto"
)

// The keyring tests use fixed, printable key material rather than minted
// randomness wherever an assertion has to search output for the secret: a
// redaction test that looks for 32 random bytes proves nothing when it passes,
// because the failure it is guarding against is a String() that prints a
// recognisable encoding of them. Fixed material makes the search exact — and
// the tests that care about minting use NewKeyring alongside.
const (
	testNameKeyMaterial = "NAMEKEY-SECRET-MATERIAL-32-BYTE!"
	testKEKMaterial     = "KEYRING-SECRET-MATERIAL-32-BYTE!"
	testRotatedMaterial = "ROTATED-KEK-MATERIAL-32-BYTES-!!"
)

var testKeyCreated = time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC)

// testEntry builds one keyring entry from a hex id and literal material.
func testEntry(t *testing.T, id, material string) KeyEntry {
	t.Helper()
	parsed, err := ParseKeyID(id)
	if err != nil {
		t.Fatalf("ParseKeyID(%q): %v", id, err)
	}
	if len(material) != crypto.KeyLen {
		t.Fatalf("test key material must be %d bytes, got %d", crypto.KeyLen, len(material))
	}
	return KeyEntry{ID: parsed, Created: testKeyCreated, key: []byte(material)}
}

// testKeyring is the deterministic keyring the Store tests run over.
func testKeyring(t *testing.T) Keyring {
	t.Helper()
	k := Keyring{
		nameKeys: []KeyEntry{testEntry(t, "0102030405060708", testNameKeyMaterial)},
		keys:     []KeyEntry{testEntry(t, "1112131415161718", testKEKMaterial)},
	}
	if err := k.Valid(); err != nil {
		t.Fatalf("testKeyring is not valid: %v", err)
	}
	return k
}

func TestKeyIDRoundTrip(t *testing.T) {
	id, err := ParseKeyID("3c9d5f01a2b4e678")
	if err != nil {
		t.Fatalf("ParseKeyID: %v", err)
	}
	if got := id.String(); got != "3c9d5f01a2b4e678" {
		t.Errorf("String() = %q, want the lowercase hex it was parsed from", got)
	}
}

func TestParseKeyIDRejects(t *testing.T) {
	tests := []struct{ name, id string }{
		{"not hex", "zzzzzzzzzzzzzzzz"},
		{"too short", "01020304050607"},
		{"too long", "0102030405060708090a"},
		{"empty", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseKeyID(tc.id); !errors.Is(err, ErrKeyringInvalid) {
				t.Errorf("ParseKeyID(%q) error = %v, want ErrKeyringInvalid", tc.id, err)
			}
		})
	}
}

func TestKeyringMarshalParseRoundTrip(t *testing.T) {
	minted, err := NewKeyring()
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	if len(minted.NameKeys()) != 1 || len(minted.KEKs()) != 1 {
		t.Fatalf("NewKeyring() = %s, want one name key and one KEK", minted)
	}

	data, err := minted.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	back, err := ParseKeyring(data)
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}
	assertSameEntries(t, "name keys", minted.NameKeys(), back.NameKeys())
	assertSameEntries(t, "keys", minted.KEKs(), back.KEKs())
}

// TestKeyringMarshalWireFormat pins keys.yaml against the format the spec
// documents. The file is the one artefact in FarCast whose loss is
// unrecoverable, so its shape is a contract with every future reader of it —
// including a version of this code that no longer exists.
func TestKeyringMarshalWireFormat(t *testing.T) {
	ring := testKeyring(t)
	data, err := ring.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// Decoding through the documented field names is the assertion: a renamed
	// or dropped key leaves the corresponding field zero.
	var file struct {
		Version  int `yaml:"version"`
		NameKeys []struct {
			ID      string    `yaml:"id"`
			Key     string    `yaml:"key"`
			Created time.Time `yaml:"created"`
		} `yaml:"name_keys"`
		Keys []struct {
			ID      string    `yaml:"id"`
			Key     string    `yaml:"key"`
			Created time.Time `yaml:"created"`
		} `yaml:"keys"`
	}
	if err := yaml.Unmarshal(data, &file); err != nil {
		t.Fatalf("unmarshal marshalled keyring: %v\n%s", err, data)
	}
	if file.Version != 1 {
		t.Errorf("version = %d, want 1\n%s", file.Version, data)
	}
	if len(file.NameKeys) != 1 || len(file.Keys) != 1 {
		t.Fatalf("got %d name_keys and %d keys, want 1 and 1\n%s", len(file.NameKeys), len(file.Keys), data)
	}

	for _, entry := range []struct {
		what         string
		id, key      string
		created      time.Time
		wantID       string
		wantMaterial string
	}{
		{"name_keys[0]", file.NameKeys[0].ID, file.NameKeys[0].Key, file.NameKeys[0].Created,
			"0102030405060708", testNameKeyMaterial},
		{"keys[0]", file.Keys[0].ID, file.Keys[0].Key, file.Keys[0].Created,
			"1112131415161718", testKEKMaterial},
	} {
		if entry.id != entry.wantID {
			t.Errorf("%s id = %q, want %q", entry.what, entry.id, entry.wantID)
		}
		// Hex, not base64, and exactly the id length: the id is what an
		// operator matches against a blob header by eye.
		if raw, err := hex.DecodeString(entry.id); err != nil || len(raw) != crypto.KeyIDLen {
			t.Errorf("%s id %q is not %d hex-encoded bytes (err %v)", entry.what, entry.id, crypto.KeyIDLen, err)
		}
		material, err := base64.StdEncoding.DecodeString(entry.key)
		if err != nil {
			t.Errorf("%s key %q is not standard base64: %v", entry.what, entry.key, err)
		} else if string(material) != entry.wantMaterial {
			t.Errorf("%s key decodes to %q, want %q", entry.what, material, entry.wantMaterial)
		}
		if !entry.created.Equal(testKeyCreated) {
			t.Errorf("%s created = %s, want %s", entry.what, entry.created, testKeyCreated)
		}
	}

	// Nothing else may ride along in this file: an unrecognised top-level key
	// is either a format drift or a reader's silent assumption.
	var top map[string]any
	if err := yaml.Unmarshal(data, &top); err != nil {
		t.Fatalf("unmarshal into a generic map: %v", err)
	}
	for k := range top {
		switch k {
		case "version", "name_keys", "keys":
		default:
			t.Errorf("unexpected top-level key %q in keys.yaml\n%s", k, data)
		}
	}
	for _, list := range []string{"name_keys", "keys"} {
		entries, ok := top[list].([]any)
		if !ok {
			t.Errorf("%q is %T, want a list", list, top[list])
			continue
		}
		for i, e := range entries {
			m, ok := e.(map[string]any)
			if !ok {
				t.Errorf("%s[%d] is %T, want a mapping", list, i, e)
				continue
			}
			for k := range m {
				switch k {
				case "id", "key", "created":
				default:
					t.Errorf("unexpected key %q in %s[%d]", k, list, i)
				}
			}
		}
	}
}

func TestParseKeyringRejects(t *testing.T) {
	const goodID = "1112131415161718"
	goodKey := base64.StdEncoding.EncodeToString([]byte(testKEKMaterial))
	goodNameKey := base64.StdEncoding.EncodeToString([]byte(testNameKeyMaterial))

	// entry renders one list item; the callers below vary exactly one field so
	// that a failure names the rule that fired.
	entry := func(id, key string) string {
		return fmt.Sprintf("  - id: %q\n    key: %q\n    created: 2026-08-26T00:00:00Z\n", id, key)
	}
	file := func(version int, nameKeys, keys string) []byte {
		return []byte(fmt.Sprintf("version: %d\nname_keys:\n%skeys:\n%s", version, nameKeys, keys))
	}

	tests := []struct {
		name string
		data []byte
	}{
		// Version 2 is the scopes schema; an unknown version has to be one
		// this build has never written.
		{"unknown version", file(3, entry("0102030405060708", goodNameKey), entry(goodID, goodKey))},
		{"missing version", file(0, entry("0102030405060708", goodNameKey), entry(goodID, goodKey))},
		{"non-hex id", file(1, entry("0102030405060708", goodNameKey), entry("zzzzzzzzzzzzzzzz", goodKey))},
		{"short id", file(1, entry("0102030405060708", goodNameKey), entry("11121314151617", goodKey))},
		{"long id", file(1, entry("0102030405060708", goodNameKey), entry(goodID+"19", goodKey))},
		{"non-base64 key", file(1, entry("0102030405060708", goodNameKey), entry(goodID, "not base64!!"))},
		{"short key", file(1, entry("0102030405060708", goodNameKey),
			entry(goodID, base64.StdEncoding.EncodeToString([]byte("sixteen bytes!!!"))))},
		{"long key", file(1, entry("0102030405060708", goodNameKey),
			entry(goodID, base64.StdEncoding.EncodeToString([]byte(testKEKMaterial+testKEKMaterial))))},
		{"duplicate key id", file(1, entry("0102030405060708", goodNameKey), entry(goodID, goodKey)+entry(goodID, goodKey))},
		{"duplicate name key id", file(1, entry("0102030405060708", goodNameKey)+entry("0102030405060708", goodNameKey), entry(goodID, goodKey))},
		{"no keys", file(1, entry("0102030405060708", goodNameKey), "")},
		{"no name keys", file(1, "", entry(goodID, goodKey))},
		{"empty file", nil},
		{"not yaml", []byte("\tthis is not: [yaml")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			k, err := ParseKeyring(tc.data)
			if !errors.Is(err, ErrKeyringInvalid) {
				t.Fatalf("ParseKeyring error = %v, want ErrKeyringInvalid\n%s", err, tc.data)
			}
			if len(k.NameKeys()) != 0 || len(k.KEKs()) != 0 {
				t.Errorf("ParseKeyring returned %s alongside its error; a rejected keyring must be unusable", k)
			}
		})
	}
}

func TestParseKeyringAcceptsTheDocumentedFile(t *testing.T) {
	data := []byte("version: 1\n" +
		"name_keys:\n" +
		"  - id: 0102030405060708\n" +
		"    key: " + base64.StdEncoding.EncodeToString([]byte(testNameKeyMaterial)) + "\n" +
		"    created: 2026-08-26T00:00:00Z\n" +
		"keys:\n" +
		"  - id: 1112131415161718\n" +
		"    key: " + base64.StdEncoding.EncodeToString([]byte(testKEKMaterial)) + "\n" +
		"    created: 2026-08-26T00:00:00Z\n")

	k, err := ParseKeyring(data)
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}
	assertSameEntries(t, "name keys", testKeyring(t).NameKeys(), k.NameKeys())
	assertSameEntries(t, "keys", testKeyring(t).KEKs(), k.KEKs())
}

func TestActiveKeysOnAnEmptyKeyring(t *testing.T) {
	if _, err := (Keyring{}).ActiveNameKey(); !errors.Is(err, ErrKeyringInvalid) {
		t.Errorf("ActiveNameKey error = %v, want ErrKeyringInvalid", err)
	}
	if _, err := (Keyring{}).ActiveKEK(); !errors.Is(err, ErrKeyringInvalid) {
		t.Errorf("ActiveKEK error = %v, want ErrKeyringInvalid", err)
	}
}

// TestKeyMintingFailsClosed drives the package's own randomness seam dry. A
// mint that ran short and returned a partially filled entry anyway would be a
// key with predictable bytes in it — and, because a keyring is written once and
// then trusted forever, one nobody would ever look at again.
func TestKeyMintingFailsClosed(t *testing.T) {
	original := keyRand
	t.Cleanup(func() { keyRand = original })

	tests := []struct {
		name  string
		avail int // bytes of randomness before the reader runs dry
	}{
		{"no randomness at all", 0},
		{"runs out before the id", crypto.KeyLen},
		{"runs out during the second key", crypto.KeyLen + crypto.KeyIDLen},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keyRand = bytes.NewReader(make([]byte, tc.avail))
			if _, err := NewKeyring(); err == nil {
				t.Error("NewKeyring succeeded with an exhausted randomness source")
			}

			keyRand = bytes.NewReader(make([]byte, tc.avail))
			e, err := NewKey()
			if tc.avail >= crypto.KeyLen+crypto.KeyIDLen {
				return // this reader holds exactly one entry; the failure is NewKeyring's second mint
			}
			if err == nil {
				t.Fatal("NewKey succeeded with an exhausted randomness source")
			}
			if len(e.key) != 0 || e.ID != (KeyID{}) {
				t.Errorf("NewKey returned %s alongside its error; a failed mint must yield nothing", e)
			}
		})
	}
}

func TestMarshalRefusesAnInvalidKeyring(t *testing.T) {
	if _, err := (Keyring{}).Marshal(); !errors.Is(err, ErrKeyringInvalid) {
		t.Errorf("Marshal of the zero Keyring error = %v, want ErrKeyringInvalid", err)
	}
}

// TestKeyringMergeIsMergeOnly is a security test, not a convenience one. A
// blob's key ID is cloud-writable plaintext, so a tampering cloud can make any
// object demand a key the keyring lacks; the natural "restore from backup"
// response, performed as an overwrite, would destroy every KEK appended since
// that backup — precisely the key-loss catastrophe the tampering steers
// towards. Merge must therefore only ever add.
func TestKeyringMergeIsMergeOnly(t *testing.T) {
	original := testEntry(t, "1112131415161718", testKEKMaterial)
	rotated := testEntry(t, "2122232425262728", testRotatedMaterial)
	archived := testEntry(t, "3132333435363738", "ARCHIVED-KEK-MATERIAL-32-BYTE!!!")
	archivedName := testEntry(t, "4142434445464748", "ARCHIVED-NAMEKEY-MATERIAL-32-B!!")

	// The live keyring has rotated since the backup was taken: the rotated KEK
	// is active and the backup has never heard of it.
	live := testKeyring(t).AddKEK(rotated)
	liveActive, err := live.ActiveKEK()
	if err != nil {
		t.Fatalf("ActiveKEK: %v", err)
	}

	// The stale backup holds the original KEK plus two entries the live file
	// no longer (or does not yet) carry.
	stale := Keyring{
		nameKeys: []KeyEntry{testEntry(t, "0102030405060708", testNameKeyMaterial), archivedName},
		keys:     []KeyEntry{archived, original},
	}

	merged, err := live.Merge(stale)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}

	// The active KEK is unchanged: a restore may not demote the key new writes
	// are wrapped under.
	mergedActive, err := merged.ActiveKEK()
	if err != nil {
		t.Fatalf("ActiveKEK after merge: %v", err)
	}
	if mergedActive.ID != liveActive.ID {
		t.Errorf("ActiveKEK after merge = %s, want the live active key %s", mergedActive.ID, liveActive.ID)
	}
	if merged.KEKs()[0].ID != liveActive.ID {
		t.Errorf("merged KEKs = %s, want the live active key first", merged)
	}

	// Every live entry survives, and only the genuinely missing ones arrive.
	assertHasKeys(t, "merged KEKs", merged.KEKs(), rotated.ID, original.ID, archived.ID)
	assertHasKeys(t, "merged name keys", merged.NameKeys(), testKeyring(t).NameKeys()[0].ID, archivedName.ID)
	if got := len(merged.KEKs()); got != 3 {
		t.Errorf("merged holds %d KEKs, want 3 (2 live + 1 added)", got)
	}
	if got := len(merged.NameKeys()); got != 2 {
		t.Errorf("merged holds %d name keys, want 2 (1 live + 1 added)", got)
	}

	// Merging is a value operation: the live keyring is not mutated in place,
	// so a caller that discards the result still holds what it started with.
	if got := len(live.KEKs()); got != 2 {
		t.Errorf("live keyring now holds %d KEKs; Merge mutated its receiver", got)
	}

	// Merging an already-merged keyring is a no-op, so a re-run of an import
	// cannot grow the file.
	again, err := merged.Merge(stale)
	if err != nil {
		t.Fatalf("second Merge: %v", err)
	}
	if len(again.KEKs()) != len(merged.KEKs()) || len(again.NameKeys()) != len(merged.NameKeys()) {
		t.Errorf("re-merging changed the keyring: %s then %s", merged, again)
	}
}

// TestKeyringMergeRefusesConflictingMaterial pins the other half of the merge
// rule: two independently minted 64-bit IDs do not collide by chance, so an ID
// carrying two different keys means one of the files is corrupt or hostile.
// Resolving it either way yields a keyring that silently cannot read
// something, so it is refused outright.
func TestKeyringMergeRefusesConflictingMaterial(t *testing.T) {
	live := testKeyring(t)

	tests := []struct {
		name       string
		other      Keyring
		conflictID string
	}{
		{"a KEK id carrying different material", Keyring{
			keys: []KeyEntry{testEntry(t, "1112131415161718", testRotatedMaterial)},
		}, "1112131415161718"},
		{"a name key id carrying different material", Keyring{
			nameKeys: []KeyEntry{testEntry(t, "0102030405060708", testRotatedMaterial)},
		}, "0102030405060708"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			merged, err := live.Merge(tc.other)
			if !errors.Is(err, ErrKeyringInvalid) {
				t.Fatalf("Merge error = %v, want ErrKeyringInvalid", err)
			}
			if len(merged.KEKs()) != 0 || len(merged.NameKeys()) != 0 {
				t.Errorf("Merge returned %s alongside its refusal; a refused merge must yield nothing usable", merged)
			}
			// The refusal must name the offending id so the operator can find
			// it in both files.
			if !strings.Contains(err.Error(), tc.conflictID) {
				t.Errorf("error = %v, want it to name the conflicting id %s", err, tc.conflictID)
			}
			if len(live.KEKs()) != 1 || len(live.NameKeys()) != 1 {
				t.Errorf("live keyring changed during a refused merge: %s", live)
			}
		})
	}
}

// TestAddKEKRotatesWritesAndKeepsOldBlobsReadable exercises the whole of
// rotation's shape: prepend, new writes wrap under the new entry, and every
// older blob keeps decrypting because its header names the KEK it was written
// under.
func TestAddKEKRotatesWritesAndKeepsOldBlobsReadable(t *testing.T) {
	ctx := context.Background()
	before := testKeyring(t)
	firstKEK, err := before.ActiveKEK()
	if err != nil {
		t.Fatalf("ActiveKEK: %v", err)
	}

	fake := newFakeProvider()
	oldStore, err := NewStore(fake, "farcast-test-bucket", before)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	oldValue := []byte("written under the first KEK")
	if err := oldStore.Write(ctx, "system/before-rotation", oldValue); err != nil {
		t.Fatalf("Write: %v", err)
	}

	next := testEntry(t, "2122232425262728", testRotatedMaterial)
	after := before.AddKEK(next)

	if got, err := after.ActiveKEK(); err != nil || got.ID != next.ID {
		t.Fatalf("ActiveKEK after AddKEK = %s (err %v), want %s", got.ID, err, next.ID)
	}
	assertHasKeys(t, "rotated KEKs", after.KEKs(), next.ID, firstKEK.ID)
	if got, err := before.ActiveKEK(); err != nil || got.ID != firstKEK.ID {
		t.Errorf("AddKEK mutated its receiver: active is now %s", got.ID)
	}

	newStore, err := NewStore(fake, "farcast-test-bucket", after)
	if err != nil {
		t.Fatalf("NewStore after rotation: %v", err)
	}

	// (b) of the rotation contract: nothing already written moves, and it all
	// still reads.
	got, err := newStore.Read(ctx, "system/before-rotation")
	if err != nil {
		t.Fatalf("Read of a pre-rotation object: %v", err)
	}
	if string(got) != string(oldValue) {
		t.Errorf("Read = %q, want %q", got, oldValue)
	}
	if id := storedKeyID(t, fake, newStore, "system/before-rotation"); id != firstKEK.ID.raw() {
		t.Errorf("pre-rotation blob now names key %x; rotation must not rewrite existing headers", id)
	}

	// New writes wrap under the new entry.
	if err := newStore.Write(ctx, "system/after-rotation", []byte("written under the rotated KEK")); err != nil {
		t.Fatalf("Write after rotation: %v", err)
	}
	if id := storedKeyID(t, fake, newStore, "system/after-rotation"); id != next.ID.raw() {
		t.Errorf("post-rotation blob names key %x, want the rotated KEK %s", id, next.ID)
	}

	// And a reader still holding only the pre-rotation keyring is told the key
	// is missing — never handed plaintext, never told the data is corrupt.
	if _, err := oldStore.Read(ctx, "system/after-rotation"); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("Read with a stale keyring error = %v, want ErrUnknownKey", err)
	}
}

// TestKeyringStringRedactsMaterial and its KeyEntry sibling are the
// RegistryToken discipline applied to the one secret that *is* the data: no
// accidental log line, at any verb, may carry a key byte.
func TestKeyringStringRedactsMaterial(t *testing.T) {
	ring := testKeyring(t)
	secrets := append(secretForms([]byte(testNameKeyMaterial)), secretForms([]byte(testKEKMaterial))...)

	for _, verb := range []string{"%v", "%s", "%+v"} {
		rendered := fmt.Sprintf(verb, ring)
		assertNoSecrets(t, "Keyring "+verb, rendered, secrets)
		// Redaction still has to leave something useful behind: the ids are
		// what tooling shows and what an operator matches against a blob.
		for _, want := range []string{"0102030405060708", "1112131415161718"} {
			if !strings.Contains(rendered, want) {
				t.Errorf("Keyring %s = %q, want it to name key id %s", verb, rendered, want)
			}
		}
	}

	// Minted material has to be covered too — the fixed material above proves
	// the encodings are absent, this proves the real path is the same one.
	minted, err := NewKeyring()
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	var mintedSecrets []string
	for _, e := range append(minted.NameKeys(), minted.KEKs()...) {
		mintedSecrets = append(mintedSecrets, secretForms(e.key)...)
	}
	for _, verb := range []string{"%v", "%s", "%+v"} {
		assertNoSecrets(t, "minted Keyring "+verb, fmt.Sprintf(verb, minted), mintedSecrets)
	}

	// The zero value is rendered, not panicked on: redaction that only works
	// on well-formed values is redaction that fails in exactly the moment a
	// log line is being written about something going wrong.
	for _, verb := range []string{"%v", "%s", "%+v"} {
		if got := fmt.Sprintf(verb, Keyring{}); !strings.Contains(got, "Keyring{") {
			t.Errorf("zero Keyring %s = %q, want a rendered Keyring", verb, got)
		}
	}
}

func TestKeyEntryStringRedactsMaterial(t *testing.T) {
	entry := testEntry(t, "1112131415161718", testKEKMaterial)
	secrets := secretForms([]byte(testKEKMaterial))

	for _, verb := range []string{"%v", "%s", "%+v"} {
		rendered := fmt.Sprintf(verb, entry)
		assertNoSecrets(t, "KeyEntry "+verb, rendered, secrets)
		if !strings.Contains(rendered, "1112131415161718") {
			t.Errorf("KeyEntry %s = %q, want it to name the key id", verb, rendered)
		}
		if !strings.Contains(rendered, "redacted") {
			t.Errorf("KeyEntry %s = %q, want it to say the material was redacted", verb, rendered)
		}
	}

	minted, err := NewKey()
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	for _, verb := range []string{"%v", "%s", "%+v"} {
		assertNoSecrets(t, "minted KeyEntry "+verb, fmt.Sprintf(verb, minted), secretForms(minted.key))
	}

	for _, verb := range []string{"%v", "%s", "%+v"} {
		got := fmt.Sprintf(verb, KeyEntry{})
		if !strings.Contains(got, "KeyEntry{") {
			t.Errorf("zero KeyEntry %s = %q, want a rendered KeyEntry", verb, got)
		}
		if !strings.Contains(got, "<none>") {
			t.Errorf("zero KeyEntry %s = %q, want the absent material reported as <none>", verb, got)
		}
	}
}

// TestKeyLossWarningIsTheMandatedSentence pins the exact words the spec
// mandates. It is a constant precisely so every keygen and every key-related
// failure says the same thing; a reworded warning is a warning an operator
// might read as boilerplate. (The spec renders `keys.yaml` in backticks —
// markdown emphasis, not part of the sentence.)
func TestKeyLossWarningIsTheMandatedSentence(t *testing.T) {
	const want = "loss of keys.yaml is permanent, unrecoverable loss of all stored data — FarCast keeps no copy anywhere, by design."
	if KeyLossWarning != want {
		t.Errorf("KeyLossWarning =\n%q\nwant\n%q", KeyLossWarning, want)
	}
}

func TestKeysFileConstants(t *testing.T) {
	if KeysDirName != "datasphere" || KeysFileName != "keys.yaml" {
		t.Errorf("keys file location = %s/%s, want datasphere/keys.yaml", KeysDirName, KeysFileName)
	}
	if KeysDirMode != 0o700 || KeysFileMode != 0o600 {
		t.Errorf("keys file modes = dir %o file %o, want 700 and 600", KeysDirMode, KeysFileMode)
	}
}

// secretForms returns every rendering of secret that a leak could hide behind.
// A redaction test that searched only for the raw bytes would pass a String()
// that hex-dumped them — which is exactly the shape a debugging aid takes.
func secretForms(secret []byte) []string {
	if len(secret) == 0 {
		return nil
	}
	return []string{
		string(secret),
		hex.EncodeToString(secret),
		strings.ToUpper(hex.EncodeToString(secret)),
		base64.StdEncoding.EncodeToString(secret),
		base64.RawStdEncoding.EncodeToString(secret),
		base64.URLEncoding.EncodeToString(secret),
		fmt.Sprintf("%v", secret),
	}
}

func assertNoSecrets(t *testing.T, what, rendered string, secrets []string) {
	t.Helper()
	for _, s := range secrets {
		if s == "" {
			continue
		}
		if strings.Contains(rendered, s) {
			t.Errorf("%s leaked key material as %q: %s", what, s, rendered)
		}
	}
}

func assertSameEntries(t *testing.T, what string, want, got []KeyEntry) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatalf("%s: got %d entries, want %d", what, len(got), len(want))
	}
	for i := range want {
		if got[i].ID != want[i].ID {
			t.Errorf("%s[%d] id = %s, want %s", what, i, got[i].ID, want[i].ID)
		}
		if string(got[i].key) != string(want[i].key) {
			t.Errorf("%s[%d] key material did not survive the round trip", what, i)
		}
		if !got[i].Created.Equal(want[i].Created) {
			t.Errorf("%s[%d] created = %s, want %s", what, i, got[i].Created, want[i].Created)
		}
	}
}

func assertHasKeys(t *testing.T, what string, entries []KeyEntry, want ...KeyID) {
	t.Helper()
	for _, id := range want {
		found := false
		for _, e := range entries {
			if e.ID == id {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is missing key %s", what, id)
		}
	}
}

// storedKeyID reads the KEK id out of the blob the provider actually holds for
// key, which is the only place rotation is observable from outside.
func storedKeyID(t *testing.T, fake *fakeProvider, s *Store, key string) [crypto.KeyIDLen]byte {
	t.Helper()
	stored, err := s.StoredName(key)
	if err != nil {
		t.Fatalf("StoredName(%q): %v", key, err)
	}
	obj, ok := fake.object(stored)
	if !ok {
		t.Fatalf("provider holds no object for %q", key)
	}
	h, err := crypto.ParseHeader(obj.Data)
	if err != nil {
		t.Fatalf("ParseHeader for %q: %v", key, err)
	}
	return h.KeyID
}

// TestParseKeyringNeverEchoesKeyMaterial is the parse-path half of the
// invariant the redaction tests cover for String(): no key bytes reach any log.
//
// It exists because the obvious implementation violates it. goccy/go-yaml
// renders three lines either side of a parse error verbatim, and keys.yaml is
// nine lines long — so wrapping the raw parser error prints the base64 KEK and
// name key to whatever the caller's stderr is. Every corruption below was
// confirmed to leak before the fix, and the operator does not even have to do
// anything exotic to reach one: a mis-indented hand edit, a tab, or a partially
// copied backup is enough.
func TestParseKeyringNeverEchoesKeyMaterial(t *testing.T) {
	// Distinctive material, so a leak cannot hide behind a plausible-looking
	// base64 run.
	const (
		nameKeyB64 = "TkFNRUtFWU1BUkVSTkFNRUtFWU1BUkVSTkFNRUtFWTA9"
		kekB64     = "S0VLTUFSS0VSS0VLTUFSS0VSS0VLTUFSS0VSS0VLMDA9"
		idHex      = "3c9d5f01a2b4e678"
	)
	body := func(indent, tail string) string {
		return "version: 1\nname_keys:\n  - id: " + idHex + "\n" + indent + "key: " + nameKeyB64 +
			"\n    created: 2026-08-26T00:00:00Z\nkeys:\n  - id: 8f3a19c2d4e5b607\n    key: " + kekB64 + tail
	}

	for name, input := range map[string]string{
		"mis-indented entry":  body("     ", "\n    created: 2026-08-26T00:00:00Z\n"),
		"tab indentation":     "version: 1\nname_keys:\n\t- id: " + idHex + "\n\t  key: " + nameKeyB64 + "\nkeys:\n  - id: 8f3a19c2d4e5b607\n    key: " + kekB64 + "\n",
		"wrong type":          "version: notanumber\n" + strings.TrimPrefix(body("    ", "\n    created: 2026-08-26T00:00:00Z\n"), "version: 1\n"),
		"key material as id":  "version: 1\nname_keys:\n  - id: " + nameKeyB64 + "\n    key: " + kekB64 + "\n    created: 2026-08-26T00:00:00Z\nkeys:\n  - id: 8f3a19c2d4e5b607\n    key: " + kekB64 + "\n    created: 2026-08-26T00:00:00Z\n",
		"unterminated flow":   body("    ", "\n    created: 2026-08-26T00:00:00Z\nkeys: [\n"),
		"duplicate key field": body("    ", "\n    key: "+kekB64+"\n    created: 2026-08-26T00:00:00Z\n"),
	} {
		t.Run(name, func(t *testing.T) {
			keyring, err := ParseKeyring([]byte(input))
			if err == nil {
				// Some corruptions parse and are rejected later; either way the
				// point is what a failure prints, so only failures are asserted.
				t.Skipf("input parsed successfully; nothing to assert (keyring %s)", keyring)
			}
			message := err.Error()
			for label, secret := range map[string]string{"name key": nameKeyB64, "key-encryption key": kekB64} {
				if strings.Contains(message, secret) {
					t.Errorf("the %s appears verbatim in a parse error; keys.yaml is 0600 for a reason and this message goes to stderr\nerror: %s", label, message)
				}
				// The base64 is what a file holds, but check the raw bytes too:
				// a future formatter could decode before printing.
				raw, decErr := base64.StdEncoding.DecodeString(secret)
				if decErr == nil && strings.Contains(message, string(raw)) {
					t.Errorf("the %s appears as raw bytes in a parse error\nerror: %s", label, message)
				}
			}
			if !errors.Is(err, ErrKeyringInvalid) {
				t.Errorf("err = %v, want it to classify as ErrKeyringInvalid", err)
			}
		})
	}
}

// TestParseKeyringStillDiagnoses guards the fix from overcorrecting into
// uselessness: an operator repairing a hand-edited file needs to be told where
// the problem is, and withholding everything would be its own failure.
func TestParseKeyringStillDiagnoses(t *testing.T) {
	input := "version: 1\nname_keys:\n  - id: 3c9d5f01a2b4e678\n     key: QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=\n"
	_, err := ParseKeyring([]byte(input))
	if err == nil {
		t.Fatal("expected a parse failure")
	}
	if !strings.Contains(err.Error(), "[") {
		t.Errorf("err = %v, want a line:column position an operator can act on", err)
	}
}
