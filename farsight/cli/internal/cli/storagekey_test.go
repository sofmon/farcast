package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/sofmon/farcast/datasphere"
	dsdeploy "github.com/sofmon/farcast/datasphere/deploy"
	dskeyholder "github.com/sofmon/farcast/datasphere/keyholder"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
)

// `farcast storage key` addresses the file whose loss is the permanent loss of
// every object in the bucket. These tests drive the verbs against an in-memory
// provider and a real minted keyring; nothing here touches a cloud.

// Wire constants of the blob header, spelled out rather than imported.
// datasphere/internal/crypto is internal to that module and its layout is
// frozen by golden tests there, so restating the two offsets a rekey moves
// keeps this test independent of the implementation it is checking.
//
//	0–3 magic "FCDS" · 4 version · 5–12 key ID · 13–74 wrap fields · 75… sealed name, body
const (
	blobKeyIDOffset = 5
	blobKeyIDLen    = 8
	blobHeaderLen   = 75
)

const (
	testBucket     = "farcast-prod-0badc0de"
	testPassphrase = "correct-horse-battery-staple"
)

// fakeObjectStore is an in-memory datasphere.Provider — a whole object store,
// because the key verbs that touch a bucket (rekey) need one that behaves.
type fakeObjectStore struct {
	mu      sync.Mutex
	objects map[string]datasphere.Object

	// putStreamFailAt makes the nth PutStream call fail (1-based; 0 never
	// fails). It is how an interrupted rekey is staged without a cloud.
	putStreamFailAt int
	putStreams      int
}

func newFakeObjectStore() *fakeObjectStore {
	return &fakeObjectStore{objects: map[string]datasphere.Object{}}
}

func (*fakeObjectStore) Name() string { return "fake" }

func (*fakeObjectStore) Validate(context.Context, datasphere.BucketRef) error { return nil }

func (*fakeObjectStore) EnsureBucket(_ context.Context, spec datasphere.BucketSpec) (*datasphere.Bucket, error) {
	return &datasphere.Bucket{Ref: datasphere.BucketRef{Name: spec.Name, Location: spec.Location, Instance: spec.Instance}}, nil
}

func (*fakeObjectStore) DeleteBucket(context.Context, datasphere.BucketRef) error { return nil }

func (f *fakeObjectStore) Put(_ context.Context, _ string, obj datasphere.Object) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[obj.Name] = obj
	return nil
}

func (f *fakeObjectStore) Get(_ context.Context, _, name string) (*datasphere.Object, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj, ok := f.objects[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", datasphere.ErrObjectNotFound, name)
	}
	return &obj, nil
}

func (f *fakeObjectStore) List(_ context.Context, _, prefix string) ([]datasphere.ObjectInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []datasphere.ObjectInfo
	for name, obj := range f.objects {
		if strings.HasPrefix(name, prefix) {
			out = append(out, datasphere.ObjectInfo{Name: name, Size: int64(len(obj.Data)), Meta: obj.Meta})
		}
	}
	return out, nil
}

func (f *fakeObjectStore) Delete(_ context.Context, _, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.objects, name)
	return nil
}

func (f *fakeObjectStore) PutStream(ctx context.Context, bucket string, obj datasphere.StreamObject) error {
	data, err := io.ReadAll(obj.Data)
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.putStreams++
	fail := f.putStreamFailAt != 0 && f.putStreams == f.putStreamFailAt
	f.mu.Unlock()
	if fail {
		return errors.New("connection reset by peer")
	}
	return f.Put(ctx, bucket, datasphere.Object{Name: obj.Name, Data: data, Meta: obj.Meta})
}

func (f *fakeObjectStore) GetStream(ctx context.Context, bucket, name string, offset, length int64) (io.ReadCloser, error) {
	obj, err := f.Get(ctx, bucket, name)
	if err != nil {
		return nil, err
	}
	if offset > int64(len(obj.Data)) {
		offset = int64(len(obj.Data))
	}
	data := obj.Data[offset:]
	if length >= 0 && length < int64(len(data)) {
		data = data[:length]
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

// blob returns a stored object's raw bytes — what the cloud actually holds.
func (f *fakeObjectStore) blob(t *testing.T, stored string) []byte {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	obj, ok := f.objects[stored]
	if !ok {
		t.Fatalf("no stored object %q", stored)
	}
	return append([]byte(nil), obj.Data...)
}

// snapshot copies every stored blob, so a later comparison can prove that a
// command changed nothing.
func (f *fakeObjectStore) snapshot() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]string, len(f.objects))
	for name, obj := range f.objects {
		out[name] = string(obj.Data)
	}
	return out
}

// ---------------------------------------------------------------- fixtures

// newKeyringEnv is an env with an instance that has a keyring and nothing else.
// The verbs that do not touch a bucket must work on exactly this much.
func newKeyringEnv(t *testing.T, mode output.Mode) (*Env, *bytes.Buffer, *bytes.Buffer, config.Dir) {
	t.Helper()
	env, out, errb, dir := newInstallEnv(t, mode)
	if err := dir.CreateInstance("prod"); err != nil {
		t.Fatalf("CreateInstance: %v", err)
	}
	mintKeyring(t, dir, "prod")
	return env, out, errb, dir
}

// fakeObjectStoreSeq keeps registered provider names unique. datasphere's
// registry panics on a duplicate and has no removal, so the sequence — rather
// than the test name alone — is what lets one test open two instances.
var fakeObjectStoreSeq atomic.Uint64

// newStorageEnv adds a recorded, already-created bucket backed by an in-memory
// provider, for the verbs that sweep objects.
func newStorageEnv(t *testing.T, mode output.Mode) (*Env, *bytes.Buffer, *bytes.Buffer, config.Dir, *fakeObjectStore) {
	t.Helper()
	env, out, errb, dir := newInstallEnv(t, mode)
	f := newFakeObjectStore()
	provider := fmt.Sprintf("ds-fake-%d-%s", fakeObjectStoreSeq.Add(1), strings.ReplaceAll(t.Name(), "/", "-"))
	datasphere.Register(provider, func(datasphere.Config) (datasphere.Provider, error) { return f, nil })

	if err := dir.CreateInstance("prod"); err != nil {
		t.Fatalf("CreateInstance: %v", err)
	}
	stamp := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	meta := &config.InstanceMetadata{
		Name: "prod", Provider: "gke", Project: "proj-1", Region: "us-central1",
		Cluster: "farcast-prod", Status: config.InstanceRunning,
		Storage: &config.Storage{
			Bucket: testBucket, Location: "us-central1", Provider: provider,
			RecordedAt: stamp, CreatedAt: stamp.Add(time.Second),
		},
	}
	if err := dir.SaveInstanceMetadata("prod", meta); err != nil {
		t.Fatalf("SaveInstanceMetadata: %v", err)
	}
	if err := dir.SaveInstanceCredentials("prod", &config.InstanceCredentials{Provider: "gke"}); err != nil {
		t.Fatalf("SaveInstanceCredentials: %v", err)
	}
	mintKeyring(t, dir, "prod")
	return env, out, errb, dir, f
}

// newSharedStreamEnv puts one buffer behind both streams.
//
// Results go to stdout and diagnostics to stderr, so ordering between them is
// only observable where they are the same file — which is what a terminal is,
// and the only place the "warn before you ask" property can be seen at all.
func newSharedStreamEnv(t *testing.T) (*Env, *bytes.Buffer, config.Dir) {
	t.Helper()
	dir := config.Dir(filepath.Join(t.TempDir(), "cfg"))
	var buf bytes.Buffer
	env := &Env{
		Out: &buf, Err: &buf, In: strings.NewReader(""),
		Printer:   &output.Printer{Mode: output.ModeHuman, Out: &buf, Err: &buf},
		Config:    &config.Config{},
		ConfigDir: dir,
	}
	if err := dir.CreateInstance("prod"); err != nil {
		t.Fatalf("CreateInstance: %v", err)
	}
	mintKeyring(t, dir, "prod")
	return env, &buf, dir
}

func mintKeyring(t *testing.T, dir config.Dir, instance string) datasphere.Keyring {
	t.Helper()
	keyring, err := datasphere.NewKeyring()
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	data, err := keyring.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := dir.CreateInstanceKeyring(instance, data); err != nil {
		t.Fatalf("CreateInstanceKeyring: %v", err)
	}
	return keyring
}

func liveKeyring(t *testing.T, dir config.Dir, instance string) datasphere.Keyring {
	t.Helper()
	data, err := dir.LoadInstanceKeyring(instance)
	if err != nil {
		t.Fatalf("LoadInstanceKeyring: %v", err)
	}
	keyring, err := datasphere.ParseKeyring(data)
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}
	return keyring
}

func keyringBytes(t *testing.T, dir config.Dir, instance string) []byte {
	t.Helper()
	data, err := os.ReadFile(dir.InstanceKeyringPath(instance))
	if err != nil {
		t.Fatalf("read keys.yaml: %v", err)
	}
	return data
}

// storeFor builds a Store on whatever keyring is on disk right now.
func storeFor(t *testing.T, dir config.Dir, f *fakeObjectStore, instance string) *datasphere.Store {
	t.Helper()
	store, err := datasphere.NewStore(f, testBucket, liveKeyring(t, dir, instance))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return store
}

// keyMaterialOf returns the base64 key strings keys.yaml holds, and their raw
// bytes.
//
// datasphere.KeyEntry keeps its material unexported precisely so nothing
// outside that package can reach through and print it, so the file itself is
// where a test gets hold of the one thing a listing must never show.
func keyMaterialOf(t *testing.T, dir config.Dir, instance string) (encoded []string, raw [][]byte) {
	t.Helper()
	for _, line := range strings.Split(string(keyringBytes(t, dir, instance)), "\n") {
		field := strings.TrimPrefix(strings.TrimSpace(line), "- ")
		value, ok := strings.CutPrefix(field, "key: ")
		if !ok {
			continue
		}
		material, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			t.Fatalf("keys.yaml holds a non-base64 key: %v", err)
		}
		encoded = append(encoded, value)
		raw = append(raw, material)
	}
	if len(encoded) == 0 {
		t.Fatal("found no key material in keys.yaml; this test cannot prove a negative without it")
	}
	return encoded, raw
}

func passphraseFile(t *testing.T, passphrase string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passphrase")
	// A trailing newline is what a real file (or a pipe) carries.
	if err := os.WriteFile(path, []byte(passphrase+"\n"), 0o600); err != nil {
		t.Fatalf("write passphrase file: %v", err)
	}
	return path
}

func exportKeyring(t *testing.T, env *Env, instance, out, passphrase string) {
	t.Helper()
	cmd := &keyExportCommand{out: out, passphraseFile: passphraseFile(t, passphrase)}
	if err := cmd.Run(context.Background(), env, []string{instance}); err != nil {
		t.Fatalf("key export: %v", err)
	}
}

func importKeyring(t *testing.T, env *Env, instance, file, passphrase string) error {
	t.Helper()
	cmd := &keyImportCommand{passphraseFile: passphraseFile(t, passphrase)}
	return cmd.Run(context.Background(), env, []string{instance, file})
}

func rotateKeyring(t *testing.T, env *Env, instance string) {
	t.Helper()
	cmd := &keyRotateCommand{assumeYes: true}
	if err := cmd.Run(context.Background(), env, []string{instance}); err != nil {
		t.Fatalf("key rotate: %v", err)
	}
}

func activeKEK(t *testing.T, dir config.Dir, instance string) string {
	t.Helper()
	kek, err := liveKeyring(t, dir, instance).ActiveKEK()
	if err != nil {
		t.Fatalf("ActiveKEK: %v", err)
	}
	return kek.ID.String()
}

// headerKeyID reads the KEK id a stored blob names — the field a rekey moves.
func headerKeyID(t *testing.T, f *fakeObjectStore, stored string) string {
	t.Helper()
	blob := f.blob(t, stored)
	if len(blob) < blobHeaderLen {
		t.Fatalf("stored object %q is %d bytes, too short to hold a header", stored, len(blob))
	}
	return hex.EncodeToString(blob[blobKeyIDOffset : blobKeyIDOffset+blobKeyIDLen])
}

func storedNameOf(t *testing.T, store *datasphere.Store, key string) string {
	t.Helper()
	stored, err := store.StoredName(key)
	if err != nil {
		t.Fatalf("StoredName(%q): %v", key, err)
	}
	return stored
}

func mustRead(t *testing.T, store *datasphere.Store, key string) string {
	t.Helper()
	data, err := store.Read(context.Background(), key)
	if err != nil {
		t.Fatalf("read %q: %v", key, err)
	}
	return string(data)
}

// ---------------------------------------------------------------- key list

// A listing exists so an operator can see which keys they hold. It must never
// become a way to print them: key material on a terminal is key material in
// scrollback, in a screen share, and in a pasted bug report — and for the name
// key, which cannot rotate, that exposure is permanent.
func TestStorageKeyListShowsIDsAndNeverKeyMaterial(t *testing.T) {
	for _, mode := range []struct {
		name string
		mode output.Mode
	}{{"human", output.ModeHuman}, {"json", output.ModeJSON}} {
		t.Run(mode.name, func(t *testing.T) {
			env, out, errb, dir := newKeyringEnv(t, mode.mode)
			// Two KEKs, so "which one is active" is a real question.
			rotateKeyring(t, env, "prod")
			out.Reset()
			errb.Reset()

			keyring := liveKeyring(t, dir, "prod")
			if err := (&keyListCommand{}).Run(context.Background(), env, []string{"prod"}); err != nil {
				t.Fatalf("key list: %v", err)
			}
			stdout, stderr := out.String(), errb.String()

			for _, entry := range append(keyring.KEKs(), keyring.NameKeys()...) {
				if !strings.Contains(stdout, entry.ID.String()) {
					t.Errorf("listing omits key id %s:\n%s", entry.ID, stdout)
				}
			}
			encoded, raw := keyMaterialOf(t, dir, "prod")
			if len(encoded) != 3 {
				t.Fatalf("expected 3 keys on disk after a rotation, found %d", len(encoded))
			}
			for i, material := range encoded {
				if strings.Contains(stdout, material) || strings.Contains(stderr, material) {
					t.Errorf("key %d's base64 material reached the output", i)
				}
				if bytes.Contains(out.Bytes(), raw[i]) || bytes.Contains(errb.Bytes(), raw[i]) {
					t.Errorf("key %d's raw material reached the output", i)
				}
			}

			// The active entry is marked, and only the active entry.
			keks := keyring.KEKs()
			switch mode.mode {
			case output.ModeHuman:
				active, stale := lineWith(t, stdout, keks[0].ID.String()), lineWith(t, stdout, keks[1].ID.String())
				if !strings.Contains(active, "*") {
					t.Errorf("the active key is not marked: %q", active)
				}
				if strings.Contains(stale, "*") {
					t.Errorf("a retired key is marked active: %q", stale)
				}
			case output.ModeJSON:
				var result struct {
					NameKeys []keyInfo `json:"name_keys"`
					Keys     []keyInfo `json:"keys"`
				}
				if err := json.Unmarshal(out.Bytes(), &result); err != nil {
					t.Fatalf("output is not JSON: %v\n%s", err, stdout)
				}
				if len(result.Keys) != 2 || !result.Keys[0].Active || result.Keys[1].Active {
					t.Errorf("active flags = %+v, want only the first key active", result.Keys)
				}
				if result.Keys[0].ID != keks[0].ID.String() {
					t.Errorf("first key = %s, want the active KEK %s", result.Keys[0].ID, keks[0].ID)
				}
				if len(result.NameKeys) != 1 || !result.NameKeys[0].Active {
					t.Errorf("name keys = %+v, want one, active", result.NameKeys)
				}
			}
		})
	}
}

func lineWith(t *testing.T, text, needle string) string {
	t.Helper()
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	t.Fatalf("no line containing %q in:\n%s", needle, text)
	return ""
}

// ---------------------------------------------------------------- key export / import

func TestStorageKeyExportImportRoundTrip(t *testing.T) {
	env, out, errb, dir := newKeyringEnv(t, output.ModeHuman)
	path := filepath.Join(t.TempDir(), "prod-keys.enc")
	exportKeyring(t, env, "prod", path, testPassphrase)

	// Plaintext at 0600 was already the discipline; an armored copy that a
	// second account could read would hand them the passphrase attempt for
	// free, offline, forever.
	assertPerm(t, path, 0o600)
	armored, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	encoded, raw := keyMaterialOf(t, dir, "prod")
	for i, material := range encoded {
		if strings.Contains(string(armored), material) || bytes.Contains(armored, raw[i]) {
			t.Errorf("key %d's material is in the export in the clear", i)
		}
	}
	if !keyLossLine.MatchString(errb.String()) {
		t.Errorf("export must carry the key-loss warning on a line of its own:\n%s", errb.String())
	}

	// An export path that already holds something is not a place to write a
	// keyring: the file it would replace could be the only copy of another one.
	err = (&keyExportCommand{out: path, passphraseFile: passphraseFile(t, testPassphrase)}).
		Run(context.Background(), env, []string{"prod"})
	if err == nil {
		t.Fatal("a second export to the same path must be refused")
	}
	if !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Errorf("err = %v, want a refusal to overwrite", err)
	}
	if again, _ := os.ReadFile(path); !bytes.Equal(again, armored) {
		t.Error("the refused export rewrote the file anyway")
	}

	// Round trip, proved by the merge rule rather than by inspection: an
	// import of this instance's own export adds nothing, and it could only do
	// that if every id AND every byte of material survived the passphrase
	// round trip — a single altered byte under a matching id is refused.
	before := keyringBytes(t, dir, "prod")
	out.Reset()
	errb.Reset()
	if err := importKeyring(t, env, "prod", path, testPassphrase); err != nil {
		t.Fatalf("self-import: %v", err)
	}
	if !bytes.Equal(before, keyringBytes(t, dir, "prod")) {
		t.Error("importing an instance's own export must leave keys.yaml untouched")
	}
	if !strings.Contains(out.String(), "merged 0 new key(s)") {
		t.Errorf("expected a 0-key merge:\n%s", out.String())
	}

	// And the same export merged into a DIFFERENT instance carries the
	// material across intact — the move between machines export exists for.
	if err := dir.CreateInstance("staging"); err != nil {
		t.Fatalf("CreateInstance: %v", err)
	}
	mintKeyring(t, dir, "staging")
	stagingBefore := liveKeyring(t, dir, "staging")
	if err := importKeyring(t, env, "staging", path, testPassphrase); err != nil {
		t.Fatalf("cross-instance import: %v", err)
	}
	stagingAfter := keyringBytes(t, dir, "staging")
	for i, material := range encoded {
		if !strings.Contains(string(stagingAfter), material) {
			t.Errorf("prod's key %d did not survive the round trip into staging", i)
		}
	}
	for _, entry := range append(stagingBefore.KEKs(), stagingBefore.NameKeys()...) {
		if !strings.Contains(string(stagingAfter), entry.ID.String()) {
			t.Errorf("staging's own key %s was dropped by the import", entry.ID)
		}
	}
	// Merged in, not promoted: the receiving instance keeps its own active keys.
	merged := liveKeyring(t, dir, "staging")
	if got := merged.KEKs()[0].ID; got != stagingBefore.KEKs()[0].ID {
		t.Errorf("active KEK = %s, want staging's own %s — an import must not change what wraps new writes", got, stagingBefore.KEKs()[0].ID)
	}
}

// A wrong passphrase and a tampered file must be indistinguishable. Saying
// which would tell an attacker who has the file which half they got right.
func TestStorageKeyImportDoesNotDistinguishWrongPassphraseFromTampering(t *testing.T) {
	env, _, _, dir := newKeyringEnv(t, output.ModeHuman)
	path := filepath.Join(t.TempDir(), "prod-keys.enc")
	exportKeyring(t, env, "prod", path, testPassphrase)
	armored, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	before := keyringBytes(t, dir, "prod")

	wrong := importKeyring(t, env, "prod", path, "not-the-passphrase")
	if wrong == nil {
		t.Fatal("a wrong passphrase must fail")
	}

	tamperedPath := filepath.Join(t.TempDir(), "tampered.enc")
	if err := os.WriteFile(tamperedPath, tamper(t, armored, "payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	tampered := importKeyring(t, env, "prod", tamperedPath, testPassphrase)
	if tampered == nil {
		t.Fatal("a modified export must fail")
	}
	if wrong.Error() != tampered.Error() {
		t.Errorf("the two failures are distinguishable:\n  wrong passphrase: %v\n  tampered file:    %v", wrong, tampered)
	}
	for _, err := range []error{wrong, tampered} {
		if !errors.Is(err, datasphere.ErrExportInvalid) {
			t.Errorf("err = %v, want ErrExportInvalid", err)
		}
	}

	// The KDF parameters are authenticated too, so an attacker cannot weaken
	// the derivation by editing the file and have the result still open.
	weakenedPath := filepath.Join(t.TempDir(), "weakened.enc")
	if err := os.WriteFile(weakenedPath, tamper(t, armored, "iterations"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := importKeyring(t, env, "prod", weakenedPath, testPassphrase); err == nil {
		t.Error("an export with edited KDF parameters must not open")
	}

	// A truncated file — the half-copied backup — must fail, not half-import.
	truncatedPath := filepath.Join(t.TempDir(), "truncated.enc")
	if err := os.WriteFile(truncatedPath, armored[:len(armored)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	truncated := importKeyring(t, env, "prod", truncatedPath, testPassphrase)
	if truncated == nil {
		t.Fatal("a truncated export must fail")
	}
	if !errors.Is(truncated, datasphere.ErrExportInvalid) {
		t.Errorf("err = %v, want ErrExportInvalid", truncated)
	}

	if !bytes.Equal(before, keyringBytes(t, dir, "prod")) {
		t.Error("a failed import must not touch the live keyring")
	}
}

// tamper rewrites one field of an armored export. The file is YAML, so it is
// edited as YAML rather than by string surgery — a flipped base64 character
// would fail as "not base64" and prove nothing about authentication.
func tamper(t *testing.T, armored []byte, field string) []byte {
	t.Helper()
	var file map[string]any
	if err := yaml.Unmarshal(armored, &file); err != nil {
		t.Fatalf("parse export: %v", err)
	}
	switch field {
	case "payload":
		raw, err := base64.StdEncoding.DecodeString(fmt.Sprint(file["payload"]))
		if err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		raw[len(raw)/2] ^= 0x01
		file["payload"] = base64.StdEncoding.EncodeToString(raw)
	case "iterations":
		file["iterations"] = 1000
	default:
		t.Fatalf("unknown field %q", field)
	}
	out, err := yaml.Marshal(file)
	if err != nil {
		t.Fatalf("encode export: %v", err)
	}
	return out
}

// The most important behaviour in this file.
//
// Import is MERGE-ONLY and there is no flag to change that, because a blob's
// key id is cloud-writable plaintext: a tampering cloud can make any object
// demand a key the keyring lacks, and the operator's natural response —
// "restore the backup" — performed as an overwrite would destroy every key
// appended since that backup. That is the key-loss catastrophe, reached by an
// operator doing what the error message seemed to suggest.
//
// So: a stale export imported over a live keyring that has moved on must add
// what is missing, drop nothing, and leave what wraps new writes exactly where
// it was.
func TestStorageKeyImportIsMergeOnly(t *testing.T) {
	env, out, errb, dir := newKeyringEnv(t, output.ModeHuman)
	original := liveKeyring(t, dir, "prod")
	path := filepath.Join(t.TempDir(), "backup.enc")
	exportKeyring(t, env, "prod", path, testPassphrase)

	// The live keyring moves on: it now holds a key the export has never seen.
	rotateKeyring(t, env, "prod")
	rotated := activeKEK(t, dir, "prod")
	live := liveKeyring(t, dir, "prod")
	if len(live.KEKs()) != 2 {
		t.Fatalf("expected 2 KEKs after a rotation, got %d", len(live.KEKs()))
	}
	out.Reset()
	errb.Reset()

	if err := importKeyring(t, env, "prod", path, testPassphrase); err != nil {
		t.Fatalf("key import: %v", err)
	}

	merged := liveKeyring(t, dir, "prod")
	// Every key that was live before the import is still live after it.
	for _, entry := range append(live.KEKs(), live.NameKeys()...) {
		found := false
		for _, after := range append(merged.KEKs(), merged.NameKeys()...) {
			if after.ID == entry.ID {
				found = true
			}
		}
		if !found {
			t.Errorf("key %s did not survive the import — an import that removes a key is the key-loss catastrophe", entry.ID)
		}
	}
	if len(merged.KEKs()) != 2 || len(merged.NameKeys()) != 1 {
		t.Errorf("keyring holds %d KEKs and %d name keys, want 2 and 1", len(merged.KEKs()), len(merged.NameKeys()))
	}
	// The active KEK is unchanged and still first: importing a backup must not
	// silently move new writes back onto a retired key.
	if got := merged.KEKs()[0].ID.String(); got != rotated {
		t.Errorf("active KEK = %s, want the rotated key %s still first", got, rotated)
	}
	if merged.KEKs()[1].ID != original.KEKs()[0].ID {
		t.Errorf("second KEK = %s, want the pre-rotation key %s", merged.KEKs()[1].ID, original.KEKs()[0].ID)
	}

	// And the output says so, to teach the invariant to whoever came looking
	// for a --force that does not exist.
	if !strings.Contains(errb.String(), "removed: nothing — import is merge-only, by design.") {
		t.Errorf("expected the merge-only statement on stderr:\n%s", errb.String())
	}

	t.Run("json", func(t *testing.T) {
		env, out, errb, dir := newKeyringEnv(t, output.ModeJSON)
		path := filepath.Join(t.TempDir(), "backup.enc")
		exportKeyring(t, env, "prod", path, testPassphrase)
		rotateKeyring(t, env, "prod")
		out.Reset()
		errb.Reset()
		if err := importKeyring(t, env, "prod", path, testPassphrase); err != nil {
			t.Fatalf("key import: %v", err)
		}
		var result keyImportResult
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			t.Fatalf("output is not JSON: %v\n%s", err, out.String())
		}
		if result.Added != 0 || len(result.Removed) != 0 || !result.MergeOnly {
			t.Errorf("result = %+v, want nothing added, nothing removed, merge_only true", result)
		}
		if !strings.Contains(errb.String(), "removed: nothing") {
			t.Errorf("the merge-only statement must be made in every mode:\n%s", errb.String())
		}
		if len(liveKeyring(t, dir, "prod").KEKs()) != 2 {
			t.Error("the JSON path must merge exactly as the human path does")
		}
	})
}

// One id under two different keys means one of the two files is corrupt or
// hostile — two independently minted 64-bit ids do not collide by chance — and
// merging either way yields a keyring that silently cannot read something. It
// is refused outright, and the live file is not touched.
func TestStorageKeyImportRefusesACollidingKeyID(t *testing.T) {
	env, _, _, dir := newKeyringEnv(t, output.ModeHuman)
	live := liveKeyring(t, dir, "prod")
	liveKEK, err := live.ActiveKEK()
	if err != nil {
		t.Fatalf("ActiveKEK: %v", err)
	}
	before := keyringBytes(t, dir, "prod")

	// An export that claims the live KEK's id under different material.
	hostile := keyringDoc(t, "a1a2a3a4a5a6a7a8", 0xAA, liveKEK.ID.String(), 0xBB)
	armored, err := datasphere.ExportKeyring(hostile, testPassphrase)
	if err != nil {
		t.Fatalf("ExportKeyring: %v", err)
	}
	path := filepath.Join(t.TempDir(), "hostile.enc")
	if err := os.WriteFile(path, armored, 0o600); err != nil {
		t.Fatal(err)
	}

	err = importKeyring(t, env, "prod", path, testPassphrase)
	if err == nil {
		t.Fatal("an id collision under different material must be refused")
	}
	if !errors.Is(err, datasphere.ErrKeyringInvalid) {
		t.Errorf("err = %v, want ErrKeyringInvalid", err)
	}
	if !strings.Contains(err.Error(), "refusing to merge") {
		t.Errorf("err = %v, want it to say the merge was refused", err)
	}
	if !strings.Contains(err.Error(), liveKEK.ID.String()) {
		t.Errorf("err = %v, want it to name the colliding id", err)
	}
	if !bytes.Equal(before, keyringBytes(t, dir, "prod")) {
		t.Error("a refused import must leave keys.yaml byte-identical")
	}
}

// keyringDoc builds a keyring from chosen ids and filler material, which is
// the only way to construct a collision: KeyEntry's material is unexported and
// no constructor takes one.
func keyringDoc(t *testing.T, nameKeyID string, nameFill byte, kekID string, kekFill byte) datasphere.Keyring {
	t.Helper()
	fill := func(b byte) string {
		material := bytes.Repeat([]byte{b}, 32)
		return base64.StdEncoding.EncodeToString(material)
	}
	doc := fmt.Sprintf(""+
		"version: 1\n"+
		"name_keys:\n- id: %s\n  key: %s\n  created: 2026-01-01T00:00:00Z\n"+
		"keys:\n- id: %s\n  key: %s\n  created: 2026-01-01T00:00:00Z\n",
		nameKeyID, fill(nameFill), kekID, fill(kekFill))
	keyring, err := datasphere.ParseKeyring([]byte(doc))
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}
	return keyring
}

// ---------------------------------------------------------------- key rotate

// The scope warning has to arrive before the operator answers, not after the
// deed. An operator who believes rotation undoes a compromise has been
// actively misled, and a correction printed under the result is read by nobody
// who was already sure they knew what rotation did.
func TestStorageKeyRotateWarnsBeforeItAsks(t *testing.T) {
	t.Run("before the confirmation", func(t *testing.T) {
		env, _, errb, dir := newKeyringEnv(t, output.ModeHuman)
		before := keyringBytes(t, dir, "prod")

		// env.In is a buffer, so this is a non-interactive session.
		err := (&keyRotateCommand{}).Run(context.Background(), env, []string{"prod"})
		if _, ok := errors.AsType[*usageError](err); !ok {
			t.Fatalf("err = %v, want usageError (needs --yes)", err)
		}
		if !strings.Contains(errb.String(), rotationScopeWarning) {
			t.Errorf("the warning must already be out when the confirmation is reached:\n%s", errb.String())
		}
		if !strings.Contains(errb.String(), "NOT compromise recovery") {
			t.Errorf("the warning must say rotation is not compromise recovery:\n%s", errb.String())
		}
		if !bytes.Equal(before, keyringBytes(t, dir, "prod")) {
			t.Error("a refused rotation must not touch the keyring")
		}
	})

	t.Run("not after the result", func(t *testing.T) {
		env, buf, _ := newSharedStreamEnv(t)
		if err := (&keyRotateCommand{assumeYes: true}).Run(context.Background(), env, []string{"prod"}); err != nil {
			t.Fatalf("key rotate: %v", err)
		}
		text := buf.String()
		warning := strings.Index(text, rotationScopeWarning)
		result := strings.Index(text, "now wraps new writes")
		if warning < 0 || result < 0 {
			t.Fatalf("expected both the warning and the result:\n%s", text)
		}
		if warning > result {
			t.Errorf("the scope warning trails the result:\n%s", text)
		}
	})
}

// Rotation prepends: new writes move to the new key, and everything already
// stored keeps reading because every old key stays in the keyring.
func TestStorageKeyRotateKeepsOldObjectsReadable(t *testing.T) {
	env, _, _, dir, f := newStorageEnv(t, output.ModeHuman)
	ctx := context.Background()

	before := storeFor(t, dir, f, "prod")
	oldKEK := activeKEK(t, dir, "prod")
	if err := before.Write(ctx, "app/old.txt", []byte("written before the rotation")); err != nil {
		t.Fatalf("write: %v", err)
	}
	oldStored := storedNameOf(t, before, "app/old.txt")

	rotateKeyring(t, env, "prod")
	newKEK := activeKEK(t, dir, "prod")
	if newKEK == oldKEK {
		t.Fatal("rotate did not change the active key")
	}
	keyring := liveKeyring(t, dir, "prod")
	if keyring.KEKs()[1].ID.String() != oldKEK {
		t.Errorf("the old key must stay in the keyring, second: %v", keyring)
	}

	after := storeFor(t, dir, f, "prod")
	if got := mustRead(t, after, "app/old.txt"); got != "written before the rotation" {
		t.Errorf("object written under the old key reads back as %q", got)
	}
	if got := headerKeyID(t, f, oldStored); got != oldKEK {
		t.Errorf("the stored object's key id = %s, want the old key %s — rotation must not rewrite bodies", got, oldKEK)
	}

	if err := after.Write(ctx, "app/new.txt", []byte("written after")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := headerKeyID(t, f, storedNameOf(t, after, "app/new.txt")); got != newKEK {
		t.Errorf("new write wrapped under %s, want the rotated key %s", got, newKEK)
	}
}

// ---------------------------------------------------------------- key rekey

// writeObjects seeds the bucket and returns the plaintexts by logical key.
func writeObjects(t *testing.T, store *datasphere.Store, keys ...string) map[string]string {
	t.Helper()
	want := make(map[string]string, len(keys))
	for i, key := range keys {
		body := fmt.Sprintf("contents of %s, object %d", key, i)
		if err := store.Write(context.Background(), key, []byte(body)); err != nil {
			t.Fatalf("write %q: %v", key, err)
		}
		want[key] = body
	}
	return want
}

func TestStorageKeyRekeyDryRunChangesNothing(t *testing.T) {
	env, out, _, dir, f := newStorageEnv(t, output.ModeJSON)
	want := writeObjects(t, storeFor(t, dir, f, "prod"), "app/a.txt", "app/b.txt", "app/c.txt")
	rotateKeyring(t, env, "prod")
	before := f.snapshot()
	out.Reset()

	if err := (&keyRekeyCommand{dryRun: true}).Run(context.Background(), env, []string{"prod:"}); err != nil {
		t.Fatalf("key rekey --dry-run: %v", err)
	}
	var result keyRekeyResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out.String())
	}
	if !result.DryRun || result.Candidates != len(want) || result.Rewritten != 0 {
		t.Errorf("result = %+v, want a dry run reporting %d candidates and rewriting none", result, len(want))
	}
	if result.Bytes == 0 {
		t.Error("a dry run must report the bytes it would read and rewrite; that is its whole purpose")
	}
	if diff := changedBlobs(before, f.snapshot()); len(diff) != 0 {
		t.Errorf("--dry-run rewrote %v", diff)
	}
	// No confirmation is asked for either: a dry run is not a destructive act,
	// and this one ran non-interactively without --yes.
}

func TestStorageKeyRekeyRewritesHeadersAndKeepsPlaintext(t *testing.T) {
	env, out, _, dir, f := newStorageEnv(t, output.ModeJSON)
	store := storeFor(t, dir, f, "prod")
	want := writeObjects(t, store, "app/a.txt", "app/b.txt", "app/c.txt")
	oldKEK := activeKEK(t, dir, "prod")
	before := f.snapshot()

	rotateKeyring(t, env, "prod")
	newKEK := activeKEK(t, dir, "prod")
	out.Reset()

	if err := (&keyRekeyCommand{assumeYes: true}).Run(context.Background(), env, []string{"prod:"}); err != nil {
		t.Fatalf("key rekey: %v", err)
	}
	var result keyRekeyResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out.String())
	}
	if result.Rewritten != len(want) || result.Skipped != 0 {
		t.Errorf("result = %+v, want all %d objects rewritten", result, len(want))
	}

	after := storeFor(t, dir, f, "prod")
	for key, body := range want {
		stored := storedNameOf(t, after, key)
		if got := headerKeyID(t, f, stored); got != newKEK {
			t.Errorf("%q still names key %s, want the active key %s", key, got, newKEK)
		}
		if got := mustRead(t, after, key); got != body {
			t.Errorf("%q reads back as %q, want %q", key, got, body)
		}
		// Only the header moved. A rekey that re-encrypted bodies would cost
		// the operator a full re-encryption of the bucket instead of 68 bytes
		// per object, and would put every plaintext back through this process.
		old, now := []byte(before[stored]), f.blob(t, stored)
		if len(old) != len(now) {
			t.Fatalf("%q changed length %d → %d; the body was not left alone", key, len(old), len(now))
		}
		if !bytes.Equal(old[blobHeaderLen:], now[blobHeaderLen:]) {
			t.Errorf("%q: the sealed name and body must be byte-identical after a rekey", key)
		}
		if !bytes.Equal(old[:blobKeyIDOffset], now[:blobKeyIDOffset]) {
			t.Errorf("%q: the magic and version must not move", key)
		}
		if bytes.Equal(old[blobKeyIDOffset:blobHeaderLen], now[blobKeyIDOffset:blobHeaderLen]) {
			t.Errorf("%q: the wrap fields did not change, so nothing was rekeyed", key)
		}
	}

	// The old key is still in the keyring, so nothing became unreadable in the
	// window between the rotation and the sweep.
	if liveKeyring(t, dir, "prod").KEKs()[1].ID.String() != oldKEK {
		t.Error("the retired key must remain in the keyring")
	}
}

func TestStorageKeyRekeyASecondTimeIsANoOp(t *testing.T) {
	env, out, _, dir, f := newStorageEnv(t, output.ModeJSON)
	want := writeObjects(t, storeFor(t, dir, f, "prod"), "app/a.txt", "app/b.txt")
	rotateKeyring(t, env, "prod")

	out.Reset()
	if err := (&keyRekeyCommand{assumeYes: true}).Run(context.Background(), env, []string{"prod:"}); err != nil {
		t.Fatalf("first rekey: %v", err)
	}
	settled := f.snapshot()

	out.Reset()
	if err := (&keyRekeyCommand{assumeYes: true}).Run(context.Background(), env, []string{"prod:"}); err != nil {
		t.Fatalf("second rekey: %v", err)
	}
	var result keyRekeyResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out.String())
	}
	if result.Rewritten != 0 || result.Skipped != len(want) {
		t.Errorf("result = %+v, want everything skipped as already active", result)
	}
	if diff := changedBlobs(settled, f.snapshot()); len(diff) != 0 {
		t.Errorf("the second rekey rewrote %v; an object already under the active key must not be touched", diff)
	}
}

// A rekey is the most expensive command in the CLI, so it will be interrupted:
// by a laptop lid, a network drop, a Ctrl-C. Every object must stay readable
// through that, which is what keeping the old keys in the keyring buys — and
// the failure must say where it stopped so a re-run continues rather than
// starting over.
func TestStorageKeyRekeyInterruptedLeavesEveryObjectReadable(t *testing.T) {
	env, out, _, dir, f := newStorageEnv(t, output.ModeHuman)
	want := writeObjects(t, storeFor(t, dir, f, "prod"), "app/a.txt", "app/b.txt", "app/c.txt", "app/d.txt")
	oldKEK := activeKEK(t, dir, "prod")
	rotateKeyring(t, env, "prod")
	newKEK := activeKEK(t, dir, "prod")
	out.Reset()

	// The second object's upload fails, mid-sweep.
	f.mu.Lock()
	f.putStreams, f.putStreamFailAt = 0, 2
	f.mu.Unlock()

	err := (&keyRekeyCommand{assumeYes: true}).Run(context.Background(), env, []string{"prod:"})
	if err == nil {
		t.Fatal("the interrupted rekey must report its failure")
	}
	for _, phrase := range []string{"every object remains readable", "re-run"} {
		if !strings.Contains(err.Error(), phrase) {
			t.Errorf("err = %v, want it to say %q", err, phrase)
		}
	}
	if !strings.Contains(err.Error(), "app/b.txt") {
		t.Errorf("err = %v, want it to name where the sweep stopped", err)
	}

	after := storeFor(t, dir, f, "prod")
	var moved, untouched int
	for key, body := range want {
		if got := mustRead(t, after, key); got != body {
			t.Errorf("%q is unreadable after the interruption: got %q", key, got)
		}
		switch headerKeyID(t, f, storedNameOf(t, after, key)) {
		case newKEK:
			moved++
		case oldKEK:
			untouched++
		default:
			t.Errorf("%q names a key that is in neither generation", key)
		}
	}
	// The point of the assertion: the bucket is genuinely half-swept, and every
	// object in it still reads.
	if moved == 0 || untouched == 0 {
		t.Errorf("expected a half-swept bucket; %d moved and %d untouched", moved, untouched)
	}

	// A re-run finishes the job.
	f.mu.Lock()
	f.putStreamFailAt = 0
	f.mu.Unlock()
	if err := (&keyRekeyCommand{assumeYes: true}).Run(context.Background(), env, []string{"prod:"}); err != nil {
		t.Fatalf("re-run: %v", err)
	}
	for key, body := range want {
		if got := headerKeyID(t, f, storedNameOf(t, after, key)); got != newKEK {
			t.Errorf("%q still names %s after the re-run", key, got)
		}
		if got := mustRead(t, after, key); got != body {
			t.Errorf("%q reads back as %q after the re-run", key, got)
		}
	}
}

// changedBlobs names the stored objects whose bytes differ between two
// snapshots.
func changedBlobs(before, after map[string]string) []string {
	var changed []string
	for name, data := range after {
		if old, ok := before[name]; !ok || old != data {
			changed = append(changed, name)
		}
	}
	for name := range before {
		if _, ok := after[name]; !ok {
			changed = append(changed, name+" (gone)")
		}
	}
	return changed
}

// ---------------------------------------------------------------- argument handling

func TestStorageKeyVerbsRejectBadArguments(t *testing.T) {
	env, _, _, _ := newKeyringEnv(t, output.ModeHuman)
	ctx := context.Background()
	cases := []struct {
		name string
		run  func() error
	}{
		{"list without an instance", func() error { return (&keyListCommand{}).Run(ctx, env, nil) }},
		{"list with two instances", func() error { return (&keyListCommand{}).Run(ctx, env, []string{"a", "b"}) }},
		{"export without --out", func() error {
			return (&keyExportCommand{passphraseFile: passphraseFile(t, testPassphrase)}).Run(ctx, env, []string{"prod"})
		}},
		{"export without a passphrase file", func() error {
			return (&keyExportCommand{out: filepath.Join(t.TempDir(), "x")}).Run(ctx, env, []string{"prod"})
		}},
		{"import without a file", func() error {
			return (&keyImportCommand{passphraseFile: passphraseFile(t, testPassphrase)}).Run(ctx, env, []string{"prod"})
		}},
		{"rekey on a local path", func() error {
			return (&keyRekeyCommand{assumeYes: true}).Run(ctx, env, []string{"./local"})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run()
			if _, ok := errors.AsType[*usageError](err); !ok {
				t.Fatalf("err = %v, want a usage error (exit code 2)", err)
			}
		})
	}
}

// An empty passphrase file is a usage error rather than a passphrase: an
// export nobody has to know anything to open is a plaintext copy of the
// keyring with extra steps.
func TestStorageKeyExportRefusesAnEmptyPassphrase(t *testing.T) {
	env, _, _, _ := newKeyringEnv(t, output.ModeHuman)
	path := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(path, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "keys.enc")
	err := (&keyExportCommand{out: out, passphraseFile: path}).Run(context.Background(), env, []string{"prod"})
	if _, ok := errors.AsType[*usageError](err); !ok {
		t.Fatalf("err = %v, want a usage error", err)
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Error("nothing should have been written")
	}
}

// TestKeyImportCreatesAnAbsentKeyring covers the move-a-keyring-to-another-machine
// case the command's own help text names.
//
// Refusing here would be worse than useless: it pushes the operator toward
// running a storage command to mint a keyring first, and that fresh keyring's
// NAME key becomes the active one. A Store addresses objects only under the
// active name key, so after the subsequent merge every imported object would be
// unlistable and unreadable by name while the keyring looked perfectly healthy.
// Merging into nothing yields exactly what was imported, which is trivially
// safe and is what the operator asked for.
func TestKeyImportCreatesAnAbsentKeyring(t *testing.T) {
	env, _, _, dir := newKeyringEnv(t, output.ModeHuman)
	path := filepath.Join(t.TempDir(), "prod-keys.enc")
	exportKeyring(t, env, "prod", path, testPassphrase)
	exported := liveKeyring(t, dir, "prod")

	// Remove the keyring entirely: this is the instance that has never had one.
	if err := os.Remove(dir.InstanceKeyringPath("prod")); err != nil {
		t.Fatal(err)
	}
	if held, _ := dir.InstanceKeyringExists("prod"); held {
		t.Fatal("the keyring is still there; the test is not testing anything")
	}

	if err := importKeyring(t, env, "prod", path, testPassphrase); err != nil {
		t.Fatalf("import into an instance with no keyring: %v", err)
	}

	got := liveKeyring(t, dir, "prod")
	wantName, err := exported.ActiveNameKey()
	if err != nil {
		t.Fatal(err)
	}
	gotName, err := got.ActiveNameKey()
	if err != nil {
		t.Fatal(err)
	}
	// The part that matters: the imported NAME key is active, so everything it
	// addresses stays addressable.
	if gotName.ID != wantName.ID {
		t.Errorf("active name key = %s, want the imported %s; anything else makes every imported object unlistable", gotName.ID, wantName.ID)
	}
	if len(got.KEKs()) != len(exported.KEKs()) {
		t.Errorf("imported %d key-encryption keys, want %d", len(got.KEKs()), len(exported.KEKs()))
	}
	assertPerm(t, dir.InstanceKeyringPath("prod"), 0o600)
}

// ---------------------------------------------------------------- rotate's plan (ADR 0023 M2.6c)

// rotateRig is storage key rotate against writeInstance's fixture — its
// reader granted, a keyholder of two replicas deployed — over the keyring
// mint returns, which a fleet serves. Its plan reads the in-memory pin
// through the reader's view; its writer is that pin, every write recorded;
// and its keyholder is the fleet. Both answer farcast-system's uid u1.
type rotateRig struct {
	dir   config.Dir
	ps    *fakePinStore
	fleet *fakeStateKeyholder
	// kh is what the keyholder's opener hands out: the fleet, or a wrapper.
	kh sealStateClient
	// keyholders counts the keyholder's opens, and writers the writer's.
	keyholders, writers int
	// writerErr refuses the writer's open, onWriter runs as it opens, and
	// writerUIDErr fails its preflight, which answers writerUID when that is
	// set. realWriter leaves the writer's seam unset, so the pin opens
	// through defaultPinStore.
	writerErr, writerUIDErr error
	writerUID               string
	onWriter                func()
	realWriter              bool
	// writes are the pin writes the writer made, in order; beforeWrite runs
	// before the n-th (from 1) lands.
	writes      []seenPinWrite
	beforeWrite func(n int)
}

// seenPinWrite is one pin write: a create or a replace, at the
// resourceVersion it was made at, of the pin it carried, and the body it
// was sent with.
type seenPinWrite struct {
	method, rv string
	pin        dskeyholder.Pin
	body       []byte
}

// backdatedApps is a keyring of two applications' scopes whose every key was
// minted in 2020, so --confirm's clock has nothing to wait for.
func backdatedApps(t *testing.T) datasphere.Keyring {
	t.Helper()
	return backdated(t, appsKeyring(t, "web", "api"), "2020-01-01T00:00:00Z")
}

// newRotateRig is a rotateRig over the keyring mint returns, minted once the
// rest of the fixture is in place.
func newRotateRig(t *testing.T, mint func(t *testing.T) datasphere.Keyring) *rotateRig {
	t.Helper()
	dir, meta := writeInstance(t, kubetest.New(t), true)
	saveKeyring(t, dir, writeName, mint(t))
	env, _, _ := testEnvBoth(dir, output.ModeJSON)
	fleet := servingFleet(t, env, meta, dir)
	r := &rotateRig{dir: dir, ps: pinStoreOf(dir, writeName), fleet: fleet, kh: fleet}
	r.ps.uid = "u1"
	return r
}

// recordedPins is the rig's pin as the writer reaches it.
type recordedPins struct {
	*fakePinStore
	r *rotateRig
}

func (p *recordedPins) NamespaceUID(ctx context.Context, name string) (string, error) {
	if p.r.writerUIDErr != nil || p.r.writerUID != "" {
		return p.r.writerUID, p.r.writerUIDErr
	}
	return p.fakePinStore.NamespaceUID(ctx, name)
}

func (p *recordedPins) CreateConfigMap(ctx context.Context, manifest []byte) error {
	p.seen(manifest, plan.WriteCreate)
	return p.fakePinStore.CreateConfigMap(ctx, manifest)
}

func (p *recordedPins) ReplaceConfigMap(ctx context.Context, manifest []byte) error {
	p.seen(manifest, plan.WriteReplace)
	return p.fakePinStore.ReplaceConfigMap(ctx, manifest)
}

func (p *recordedPins) seen(manifest []byte, method string) {
	var doc struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
		Data map[string]string `json:"data"`
	}
	_ = json.Unmarshal(manifest, &doc)
	pin, _, _ := dskeyholder.ParsePin(doc.Data[dsdeploy.PinKey])
	p.r.writes = append(p.r.writes, seenPinWrite{method: method, rv: doc.Metadata.ResourceVersion, pin: pin, body: bytes.Clone(manifest)})
	if p.r.beforeWrite != nil {
		p.r.beforeWrite(len(p.r.writes))
	}
}

// cmd is storage key rotate with its flags parsed and the rig's seams.
func (r *rotateRig) cmd(t *testing.T, flags ...string) *keyRotateCommand {
	t.Helper()
	c := withFlags(t, &keyRotateCommand{}, flags...)
	c.newPlanReader = testPinPlanReader
	if !r.realWriter {
		c.newPinStore = func(ref clusterRef) (pinStore, error) {
			if ref.Identity != kube.Writer {
				return nil, fmt.Errorf("test: the pin opened as %q", ref.Identity)
			}
			r.writers++
			if r.onWriter != nil {
				r.onWriter()
			}
			if r.writerErr != nil {
				return nil, r.writerErr
			}
			r.ps.openedAs(ref.Identity)
			return &recordedPins{fakePinStore: r.ps, r: r}, nil
		}
	}
	c.newKeyholder = func(context.Context, *Env, string) (sealStateClient, func(), error) {
		r.keyholders++
		return r.kh, func() {}, nil
	}
	return c
}

// run runs rotate with flags, in JSON mode with no terminal.
func (r *rotateRig) run(t *testing.T, flags ...string) (stdout, stderr string, err error) {
	t.Helper()
	env, out, errb := testEnvBoth(r.dir, output.ModeJSON)
	err = r.cmd(t, flags...).Run(t.Context(), env, []string{writeName})
	return out.String(), errb.String(), err
}

// plan is rotate's --plan.
func (r *rotateRig) plan(t *testing.T) plan.Document {
	t.Helper()
	stdout, stderr, err := r.run(t, "--plan")
	if err != nil {
		t.Fatalf("storage key rotate --plan: %v\n%s", err, stderr)
	}
	return printedDocument(t, []byte(stdout))
}

// rotatePins is a rotate plan's pin facts and pin writes, in order: the hold
// stage's, then the final pin's.
func rotatePins(t *testing.T, b plan.Bound) (pins []plan.PinFact, writes []plan.WriteFact) {
	t.Helper()
	for _, f := range b.Facts {
		switch f := f.(type) {
		case plan.PinFact:
			pins = append(pins, f)
		case plan.WriteFact:
			writes = append(writes, f)
		}
	}
	if len(pins) != 2 || len(writes) != 2 {
		t.Fatalf("the plan carries %d pins and %d writes; want the hold's and the final pin's", len(pins), len(writes))
	}
	return pins, writes
}

// rotated is a rotation's printed result.
func rotated(t *testing.T, stdout string) keyRotateResult {
	t.Helper()
	var res keyRotateResult
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatalf("the result does not decode (%v):\n%s", err, stdout)
	}
	return res
}

// newKeysOf maps each scope's new key, as a rotation's result names it, to
// the placeholder id its plan listed it by.
func newKeysOf(t *testing.T, res keyRotateResult) map[datasphere.KeyID]datasphere.KeyID {
	t.Helper()
	ids := map[datasphere.KeyID]datasphere.KeyID{}
	for _, s := range res.Scopes {
		id, err := datasphere.ParseKeyID(s.Active)
		if err != nil {
			t.Fatal(err)
		}
		ids[id] = placeholderKeyID(s.Scope, 1)
	}
	if len(ids) == 0 {
		t.Fatal("the result names no scope's new key")
	}
	return ids
}

// ADR 0023 M2.6 (A23-45, mutation 86): under --confirm, rotate writes the
// pin twice, each time once, as the instance's writer, after the
// comparison: the hold, at the version the plan read (a create where there
// was no pin), and the final pin, a replace at the version the hold-stage
// write produced, read back after it. Each, its new keys mapped back to the
// placeholders the plan named them by, is the plan's: the hold requires the
// new keys and retires nothing new, and the final pin retires every key the
// scopes held before. The plan names no real key id, and the replicas end
// enforcing the final pin.
func TestRotateConfirmWritesTheHoldPinThenTheFinalPin(t *testing.T) {
	for _, tc := range []struct {
		name string
		pin  bool // a pin is there before the rotation
		// the hold's method and version, and the version the final pin is
		// written at
		method, rv, finalRV string
	}{
		{"no pin yet", false, plan.WriteCreate, "", "1"},
		{"over the pin there", true, plan.WriteReplace, "1", "2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRotateRig(t, backdatedApps)
			before := liveKeyring(t, r.dir, writeName)
			if tc.pin {
				r.ps.set(pinFor(before).Marshal())
			}
			doc := r.plan(t)
			pins, writes := rotatePins(t, decodedBound(t, doc))
			if writes[0].Method != tc.method || writes[0].ResourceVersion != tc.rv || writes[1].Method != plan.WriteReplace || writes[1].ResourceVersion != "" {
				t.Errorf("the plan writes %s at %q, then %s at %q; want %s at %q, then a replace at the version the hold produces",
					writes[0].Method, writes[0].ResourceVersion, writes[1].Method, writes[1].ResourceVersion, tc.method, tc.rv)
			}
			for _, s := range before.Scopes() {
				ph := placeholderKeyID(s.Name, 1).String()
				if !slices.Contains(pins[0].Require, ph) || !slices.Contains(pins[1].Require, ph) || slices.Contains(pins[1].Retired, ph) {
					t.Errorf("the plan's pins do not require %s's new key by its placeholder %s, or retire it: %+v", s.Name, ph, pins)
				}
				for _, e := range s.Keyring().KEKs() {
					if slices.Contains(pins[0].Retired, e.ID.String()) || !slices.Contains(pins[1].Retired, e.ID.String()) {
						t.Errorf("%s's key %s: the hold retires it, or the final pin does not", s.Name, e.ID)
					}
				}
			}
			if len(r.writes) != 0 || r.writers != 0 || r.keyholders != 0 {
				t.Fatalf("--plan wrote %d pins, opened the writer %d times and the keyholder %d times", len(r.writes), r.writers, r.keyholders)
			}

			stdout, stderr, err := r.run(t, "--confirm", doc.Digest)
			if err != nil {
				t.Fatalf("--confirm: %v\n%s", err, stderr)
			}
			// What the plan says, once, after the comparison (A23-26).
			if got := strings.Count(stderr, rotationScopeWarning); got != 1 {
				t.Errorf("--confirm printed the scope warning %d times; want once:\n%s", got, stderr)
			}
			res := rotated(t, stdout)
			if !res.Active || res.Unfinished != "" {
				t.Fatalf("the rotation is not in use: %+v", res)
			}
			if len(r.writes) != 2 {
				t.Fatalf("wrote the pin %d times; want the hold, then the final pin", len(r.writes))
			}
			hold, final := r.writes[0], r.writes[1]
			if hold.method != tc.method || hold.rv != tc.rv {
				t.Errorf("the hold was a %s at %q; want a %s at the plan's %q", hold.method, hold.rv, tc.method, tc.rv)
			}
			if final.method != plan.WriteReplace || final.rv != tc.finalRV {
				t.Errorf("the final pin was a %s at %q; want a replace at the hold's version, %q", final.method, final.rv, tc.finalRV)
			}
			ids := newKeysOf(t, res)
			if !mappedBack(hold.pin, ids).Equal(pinOfFact(t, pins[0])) || !mappedBack(final.pin, ids).Equal(pinOfFact(t, pins[1])) {
				t.Errorf("the pins written, mapped back, are %s and %s; the plan's are %+v",
					mappedBack(hold.pin, ids).Marshal(), mappedBack(final.pin, ids).Marshal(), pins)
			}
			if got := r.ps.openedBy(); !slices.Equal(got, []kube.Identity{kube.Reader, kube.Reader, kube.Writer}) || r.writers != 1 {
				t.Errorf("the pin was opened as %v, the writer %d times; want the reader for the plan and its recomputation, then the writer once", got, r.writers)
			}
			if !r.ps.pin(t).Equal(final.pin) {
				t.Errorf("the pin is %s; want the final pin", r.ps.value)
			}
			for i := range 2 {
				if p := r.fleet.replica(i).pin; p == nil || !p.Equal(final.pin) {
					t.Errorf("replica %d enforces %v; want the final pin", i, p)
				}
			}
		})
	}
}

// ADR 0023 M2.6 (A23-45, mutations 86b and 86c): under --confirm a pin
// another writer moved is plan_changed, never an unfinished rotation. Moved
// before the hold stage's write, the write conflicts: nothing is written
// over the other writer's pin, the new keys stay held by every replica and
// in use on none (heldChanged, not a keyring this machine could not save),
// and the command fails plan_changed, its result printed first. Moved
// between the final stage's read and its write, the final pin conflicts:
// the keys are in use, the pin stays the hold, and the command fails
// plan_changed, its pin line naming what is left — the pin, then the rekey
// — and that a restarted replica may still admit an older bundle, as an
// interactive rotation's says (ADR 0023 M2.6c), not the whole rotation
// planned again.
func TestRotateConfirmSurfacesPlanChanged(t *testing.T) {
	finalLine := fmt.Sprintf(msgRotateFinalPinChanged, pinRemedy(writeName), writeName)
	if !strings.Contains(finalLine, "a replica that restarts may still admit a bundle from before this rotation") ||
		strings.Contains(finalLine, msgPlanAgain) {
		t.Fatalf("guard: the final stage's pin line is %q", finalLine)
	}
	other := dskeyholder.Pin{Retired: []datasphere.KeyID{foreignID(t)}}.Marshal()
	t.Run("the hold stage", func(t *testing.T) {
		r := newRotateRig(t, backdatedApps)
		before := liveKeyring(t, r.dir, writeName)
		doc := r.plan(t)
		r.beforeWrite = func(n int) {
			if n == 1 {
				r.ps.set(other)
			}
		}
		stdout, _, err := r.run(t, "--confirm", doc.Digest)
		if err == nil || err.Error() != msgPinChanged || kindOf(classified(err)) != kindPlanChanged || exitCodeOf(err) != 1 {
			t.Fatalf("--confirm whose hold conflicted = %v (kind %s); want plan_changed, %q", err, kindOf(classified(err)), msgPinChanged)
		}
		res := rotated(t, stdout)
		if res.Active || res.Status != "held" || !strings.Contains(res.Keyholder, "every replica took the new keys to hold, but the key pin its plan listed was not written") ||
			strings.Contains(res.Keyholder, "could not save its keyring") {
			t.Errorf("the result says %+v; want the new keys held and unused, the pin named as why", res)
		}
		if res.Pin != "not written: "+msgPinChanged {
			t.Errorf("the pin line is %q", res.Pin)
		}
		if r.ps.value != other || len(r.writes) != 1 {
			t.Errorf("the pin is %s after %d writes; want the other writer's, and one attempt", r.ps.value, len(r.writes))
		}
		noSplit(t, r.fleet)
		for _, s := range before.Scopes() {
			was := s.Keyring().KEKs()[0].ID.String()
			for i := range 2 {
				if ids := r.fleet.replica(i).keys[s.Name]; len(ids) < 2 || ids[0] != was {
					t.Errorf("replica %d holds %s as %v; want the new key held and %s still in use", i, s.Name, ids, was)
				}
			}
		}
		if scopeKEK(liveKeyring(t, r.dir, writeName)) != scopeKEK(before) {
			t.Error("this machine writes under a new key no replica uses")
		}
	})
	t.Run("the final pin", func(t *testing.T) {
		r := newRotateRig(t, backdatedApps)
		doc := r.plan(t)
		r.beforeWrite = func(n int) {
			if n == 2 {
				r.ps.set(r.ps.value)
			}
		}
		stdout, _, err := r.run(t, "--confirm", doc.Digest)
		if err == nil || err.Error() != msgPinChanged || kindOf(classified(err)) != kindPlanChanged || exitCodeOf(err) != 1 {
			t.Fatalf("--confirm whose final pin conflicted = %v (kind %s); want plan_changed, %q", err, kindOf(classified(err)), msgPinChanged)
		}
		res := rotated(t, stdout)
		if !res.Active || res.Pin != finalLine {
			t.Errorf("the result says %+v; want the keys in use and the final pin not written, %q", res, finalLine)
		}
		if len(r.writes) != 2 || !r.ps.pin(t).Equal(r.writes[0].pin) {
			t.Errorf("the pin is %s after %d writes; want the hold, and one attempt at the final pin", r.ps.value, len(r.writes))
		}
	})
	// Moved between the two stages, as the replicas were handed the hold:
	// the final stage reads it again, finds it is not the hold, and writes
	// nothing over it.
	t.Run("between the stages", func(t *testing.T) {
		r := newRotateRig(t, backdatedApps)
		doc := r.plan(t)
		r.kh = &movesThePin{fakeStateKeyholder: r.fleet, move: func() { r.ps.set(other) }}
		stdout, _, err := r.run(t, "--confirm", doc.Digest)
		if err == nil || err.Error() != msgPinChanged || kindOf(classified(err)) != kindPlanChanged || exitCodeOf(err) != 1 {
			t.Fatalf("--confirm whose pin moved after the hold = %v (kind %s); want plan_changed, %q", err, kindOf(classified(err)), msgPinChanged)
		}
		if res := rotated(t, stdout); !res.Active || res.Pin != finalLine {
			t.Errorf("the result says %+v; want the keys in use and the final pin not written, %q", res, finalLine)
		}
		if r.ps.value != other || len(r.writes) != 1 {
			t.Errorf("the pin is %s after %d writes; want the other writer's, and the hold alone", r.ps.value, len(r.writes))
		}
	})
}

// movesThePin is a fleet that, as it is first handed a pin live, has
// another writer move the instance's pin (move).
type movesThePin struct {
	*fakeStateKeyholder
	move func()
}

func (m *movesThePin) RaisePin(ctx context.Context, i int, pin string, replace bool) (keyholder.State, error) {
	if m.move != nil {
		m.move()
		m.move = nil
	}
	return m.fakeStateKeyholder.RaisePin(ctx, i, pin, replace)
}

// twoKeyApps is a keyring of two applications' scopes, each holding a key
// minted in 2019 and the one it writes under, minted in 2020: so a final
// pin decided over this machine's keyring put back on its old keys retires
// the 2019 key and still differs from the one a rotation in use retires.
func twoKeyApps(t *testing.T) datasphere.Keyring {
	t.Helper()
	k, _, err := backdated(t, appsKeyring(t, "web", "api"), "2019-01-01T00:00:00Z").RotateScopeKEKs()
	if err != nil {
		t.Fatal(err)
	}
	data, err := k.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?m)^(\s*created:\s*)(.*)$`)
	data = re.ReplaceAllFunc(data, func(line []byte) []byte {
		if bytes.Contains(line, []byte("2019-01-01T00:00:00Z")) {
			return line
		}
		return re.ReplaceAll(line, []byte("${1}2020-01-01T00:00:00Z"))
	})
	out, err := datasphere.ParseKeyring(data)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// ADR 0023 M2.6 (A23-11, mutation 80b): under --confirm a hand-over that
// ends where its plan did not say writes no further pin. Every replica took
// the held keys, so the hold was written, and then refused the push that
// would have them used, so this machine was put back on its old keys: the
// final pin it would now write is not the plan's, and is not written. A
// replica that never took the held keys, silent or refusing them, stops the
// rotation before the hold, and no pin is written at all. Each result says
// so in A23-11's words, naming which way it ended, and the rotation fails
// unfinished, internal, never plan_changed.
func TestRotateConfirmPutBackWritesNoUnplannedPin(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fleet   func(base *fakeStateKeyholder) sealStateClient
		outcome string
		writes  int
	}{
		{"put back", func(base *fakeStateKeyholder) sealStateClient {
			return &flakyKeyholder{fakeStateKeyholder: base, refuseNth: map[int]int{0: 2, 1: 2}}
		}, outcomePutBack, 1},
		{"a replica silent", func(base *fakeStateKeyholder) sealStateClient {
			return &flakyKeyholder{fakeStateKeyholder: base, silent: map[int]bool{1: true}}
		}, outcomeNeverHeld, 0},
		{"a replica refusing", func(base *fakeStateKeyholder) sealStateClient {
			return &flakyKeyholder{fakeStateKeyholder: base, refuseNth: map[int]int{1: 1}}
		}, outcomeRefused, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRotateRig(t, twoKeyApps)
			before := liveKeyring(t, r.dir, writeName)
			doc := r.plan(t)
			r.kh = tc.fleet(r.fleet)
			stdout, _, err := r.run(t, "--confirm", doc.Digest)
			var unfinished rotationUnfinished
			if !errors.As(err, &unfinished) || kindOf(classified(err)) != kindInternal || exitCodeOf(err) != 1 {
				t.Fatalf("--confirm %s = %v (kind %s); want an unfinished rotation, internal", tc.name, err, kindOf(classified(err)))
			}
			if scopeKEK(liveKeyring(t, r.dir, writeName)) != scopeKEK(before) {
				t.Fatal("guard: this machine writes under a new key no replica uses")
			}
			res := rotated(t, stdout)
			if want := fmt.Sprintf(msgRotateUnplanned, tc.outcome, writeName); res.Pin != want {
				t.Errorf("the pin line is %q;\nwant %q", res.Pin, want)
			}
			if len(r.writes) != tc.writes || (tc.writes == 1 && !r.ps.pin(t).Equal(r.writes[0].pin)) || (tc.writes == 0 && r.ps.exists) {
				t.Errorf("wrote the pin %d times, and it is %s; want %d writes, the hold's at most", len(r.writes), r.ps.value, tc.writes)
			}
		})
	}
}

// intoAFreshSecond sleeps until just past the clock's next whole second, so
// what a test does next happens early in a second.
func intoAFreshSecond() {
	now := time.Now()
	time.Sleep(now.Truncate(time.Second).Add(time.Second + 5*time.Millisecond).Sub(now))
}

// rotateClock is a clock --confirm's wait reads (now) and sleeps on
// (sleep), which moves it forward by the wait at once: each wait is
// recorded, and before runs as one begins.
type rotateClock struct {
	at     time.Time
	sleeps []time.Duration
	before func()
}

func (c *rotateClock) now() time.Time { return c.at }

func (c *rotateClock) sleep(_ context.Context, d time.Duration) error {
	if c.before != nil {
		c.before()
	}
	c.sleeps = append(c.sleeps, d)
	c.at = c.at.Add(d)
	return nil
}

// confirmOn runs rotate --confirm doc's digest in JSON mode on clk.
func (r *rotateRig) confirmOn(t *testing.T, clk *rotateClock, doc plan.Document) (stdout string, err error) {
	t.Helper()
	c := r.cmd(t, "--confirm", doc.Digest)
	c.now, c.sleep = clk.now, clk.sleep
	env, out, _ := testEnvBoth(r.dir, output.ModeJSON)
	err = c.Run(t.Context(), env, []string{writeName})
	return out.String(), err
}

// ADR 0023 M2.6 (A23-32, mutation 79b, row O34): under --confirm rotate
// mints only once this machine's clock is past the newest key of every
// scope it mints into, waiting at most a second, on its own clock (now and
// sleep). A newest key in the current second is waited for once, for the
// rest of that second — a whole second at its very start — before anything
// is minted, saved, pinned or handed over, and the rotation then finishes as
// planned. A newest key more than a second ahead — a second and a half here,
// so a bound of two would wait — is refused before anything is minted, with
// nothing waited for: keys.yaml unchanged, no pin written, the keyholder
// never opened. A newest key in the past is not waited for. Last, on the
// real clock, a keyring minted in the current second by datasphere's own
// clock is rotated with the final pin the plan said: the two clocks agree.
func TestRotateWaitsForTheClockPastTheNewestKey(t *testing.T) {
	newest := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	keyring := func(at time.Time) func(t *testing.T) datasphere.Keyring {
		return func(t *testing.T) datasphere.Keyring {
			return backdated(t, appsKeyring(t, "web"), at.Format(time.RFC3339))
		}
	}
	for _, tc := range []struct {
		name  string
		after time.Duration // the clock past the newest key's second
		wait  time.Duration
	}{
		{"a key minted this second", 400 * time.Millisecond, 600 * time.Millisecond},
		{"a key minted at the start of this second", 0, time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRotateRig(t, keyring(newest))
			doc := r.plan(t)
			pins, _ := rotatePins(t, decodedBound(t, doc))
			before := keyringBytes(t, r.dir, writeName)
			clk := &rotateClock{at: newest.Add(tc.after)}
			clk.before = func() {
				if !bytes.Equal(before, keyringBytes(t, r.dir, writeName)) || len(r.writes) != 0 || r.keyholders != 0 {
					t.Errorf("before the wait it changed keys.yaml, wrote %d pins or opened the keyholder %d times", len(r.writes), r.keyholders)
				}
			}
			stdout, err := r.confirmOn(t, clk, doc)
			if err != nil {
				t.Fatalf("--confirm: %v", err)
			}
			if !slices.Equal(clk.sleeps, []time.Duration{tc.wait}) {
				t.Errorf("waited %v; want one wait of %v, before the mint", clk.sleeps, tc.wait)
			}
			if len(r.writes) != 2 {
				t.Fatalf("wrote the pin %d times; want the hold and the final pin", len(r.writes))
			}
			final := mappedBack(r.writes[1].pin, newKeysOf(t, rotated(t, stdout)))
			if !final.Equal(pinOfFact(t, pins[1])) {
				t.Errorf("the final pin written, mapped back, is %s; the plan's is %+v", final.Marshal(), pins[1])
			}
		})
	}
	t.Run("a clock more than a second behind", func(t *testing.T) {
		ahead := newest.Add(time.Second)
		r := newRotateRig(t, keyring(ahead))
		scope := liveKeyring(t, r.dir, writeName).Scopes()[0].Name
		doc := r.plan(t)
		before := keyringBytes(t, r.dir, writeName)
		clk := &rotateClock{at: newest.Add(500 * time.Millisecond)}
		stdout, err := r.confirmOn(t, clk, doc)
		want := fmt.Sprintf(msgClockBehind, scope, ahead.Format(time.RFC3339))
		if err == nil || err.Error() != want || kindOf(classified(err)) != kindInternal {
			t.Fatalf("--confirm 1.5 s behind the newest key = %v (kind %s);\nwant %q", err, kindOf(classified(err)), want)
		}
		if len(clk.sleeps) != 0 || !bytes.Equal(before, keyringBytes(t, r.dir, writeName)) || len(r.writes) != 0 || r.keyholders != 0 || stdout != "" {
			t.Errorf("before refusing it waited %v, changed keys.yaml, wrote %d pins, opened the keyholder %d times, or printed %q",
				clk.sleeps, len(r.writes), r.keyholders, stdout)
		}
	})
	t.Run("a key in the past", func(t *testing.T) {
		r := newRotateRig(t, keyring(newest))
		doc := r.plan(t)
		clk := &rotateClock{at: newest.Add(5 * time.Second)}
		if _, err := r.confirmOn(t, clk, doc); err != nil {
			t.Fatalf("--confirm: %v", err)
		}
		if len(clk.sleeps) != 0 || len(r.writes) != 2 {
			t.Errorf("waited %v and wrote the pin %d times; want no wait, and both pins", clk.sleeps, len(r.writes))
		}
	})
	// On the real clock: this cannot fail falsely, since --confirm waits
	// until its clock is past the newest key whenever it starts.
	t.Run("a key minted this second, on the real clock", func(t *testing.T) {
		r := newRotateRig(t, func(t *testing.T) datasphere.Keyring {
			intoAFreshSecond()
			return appsKeyring(t, "web")
		})
		doc := r.plan(t)
		pins, _ := rotatePins(t, decodedBound(t, doc))
		stdout, stderr, err := r.run(t, "--confirm", doc.Digest)
		if err != nil {
			t.Fatalf("--confirm: %v\n%s", err, stderr)
		}
		if len(r.writes) != 2 {
			t.Fatalf("wrote the pin %d times; want the hold and the final pin", len(r.writes))
		}
		final := mappedBack(r.writes[1].pin, newKeysOf(t, rotated(t, stdout)))
		if !final.Equal(pinOfFact(t, pins[1])) || len(final.Retired) != len(pins[1].Retired) {
			t.Errorf("the final pin written, mapped back, is %s; the plan's is %+v", final.Marshal(), pins[1])
		}
	})
}

// ADR 0023 M2.6c (A23-51 item 3): an interactive or --yes rotate reads the
// pin before it warns and asks, so a keyring behind the pin is refused
// first, with nothing minted.
func TestRotateReadsThePinBeforeItAsks(t *testing.T) {
	r := newRotateRig(t, backdatedApps)
	r.ps.set(pinRequiringForeign)
	before := keyringBytes(t, r.dir, writeName)
	env, _, errb := testEnvBoth(r.dir, output.ModeHuman) // stdin is no terminal
	err := r.cmd(t).Run(t.Context(), env, []string{writeName})
	if _, usage := errors.AsType[*usageError](err); err == nil || usage || !strings.Contains(err.Error(), "so nothing was rotated") {
		t.Fatalf("rotate from behind the pin, with no terminal = %v; want the keyring refused before the question", err)
	}
	if strings.Contains(errb.String(), rotationScopeWarning) {
		t.Errorf("the warning came before the pin was read:\n%s", errb)
	}
	if !bytes.Equal(before, keyringBytes(t, r.dir, writeName)) || r.keyholders != 0 {
		t.Errorf("a refused rotation changed keys.yaml, or opened the keyholder %d times", r.keyholders)
	}
}

// rotateRefusalNamesThePlan is TestNonInteractiveRefusalsNameThePlan's row
// for storage key rotate (ADR 0023 M2.6c): with no terminal and no --yes,
// it warns, then refuses naming the plan's route, with nothing minted.
func rotateRefusalNamesThePlan(t *testing.T) {
	r := newRotateRig(t, backdatedApps)
	before := keyringBytes(t, r.dir, writeName)
	env, _, errb := testEnvBoth(r.dir, output.ModeHuman) // stdin is no terminal
	err := r.cmd(t).Run(t.Context(), env, []string{writeName})
	if err == nil || err.Error() != msgRotateYes || exitCodeOf(err) != 2 || !strings.HasSuffix(msgRotateYes, consentSuffix) {
		t.Errorf("storage key rotate with no terminal = %v (exit %d); want %q", err, exitCodeOf(err), msgRotateYes)
	}
	if !strings.Contains(errb.String(), rotationScopeWarning) {
		t.Errorf("the refusal came without the warning:\n%s", errb)
	}
	if !bytes.Equal(before, keyringBytes(t, r.dir, writeName)) || r.keyholders != 0 {
		t.Errorf("a refused rotation changed keys.yaml, or opened the keyholder %d times", r.keyholders)
	}
}

// ADR 0023 M2.6 (A23-45 step 5): rotate's hold stage under --confirm writes
// the pin that holds the new keys only when it is, its new keys mapped back
// to their placeholders, the hold its plan listed. Decided over the keyring
// the hand-over pushed held, with each new key mapped to its placeholder, it
// is written, once, at the version the plan read; with the keys not mapped,
// or no held keyring, it is not the plan's, and nothing is written:
// plan_changed, in msgRotateHoldUnplanned's words.
func TestRotateHoldWritesOnlyThePlannedPin(t *testing.T) {
	r := newRotateRig(t, backdatedApps)
	meta, err := r.dir.LoadInstanceMetadata(writeName)
	if err != nil {
		t.Fatal(err)
	}
	keys := liveKeyring(t, r.dir, writeName)
	reader, err := testPinPlanReader(clusterRef{Dir: r.dir, Meta: meta, Identity: kube.Reader})
	if err != nil {
		t.Fatal(err)
	}
	p, _, err := (&keyRotateCommand{}).plan(t.Context(), meta, keys, reader, consentConfirm)
	if err != nil || !p.pins {
		t.Fatalf("the plan = %+v, %v; want one that writes the pins", p, err)
	}
	rotated, rots, err := keys.RotateScopeKEKs()
	if err != nil {
		t.Fatal(err)
	}
	previous, planned := map[string]datasphere.KeyID{}, map[datasphere.KeyID]datasphere.KeyID{}
	for _, rot := range rots {
		previous[rot.Scope], planned[rot.Active] = rot.Previous, placeholderKeyID(rot.Scope, 1)
	}
	held, err := rotated.WithScopeActive(previous)
	if err != nil {
		t.Fatal(err)
	}
	ps := &recordedPins{fakePinStore: r.ps, r: r}
	want := msgRotateHoldUnplanned + "; " + msgPlanAgain
	for name, tc := range map[string]struct {
		held    *datasphere.Keyring
		planned map[datasphere.KeyID]datasphere.KeyID
	}{
		"its new keys not the plan's": {&held, map[datasphere.KeyID]datasphere.KeyID{}},
		"no held keyring":             {nil, planned},
	} {
		if _, err := p.writeHold(t.Context(), ps, tc.held, tc.planned); err == nil || err.Error() != want || kindOf(classified(err)) != kindPlanChanged {
			t.Errorf("%s: the hold = %v (kind %s); want plan_changed, %q", name, err, kindOf(classified(err)), want)
		}
	}
	if len(r.writes) != 0 || r.ps.exists {
		t.Fatalf("a hold not the plan's wrote the pin %d times", len(r.writes))
	}
	w, err := p.writeHold(t.Context(), ps, &held, planned)
	if err != nil || len(r.writes) != 1 || r.writes[0].method != plan.WriteCreate || !mappedBack(w.Pin, planned).Equal(p.hold.pin) {
		t.Errorf("the planned hold = %+v, %v, after %d writes; want it created once, the plan's", w, err, len(r.writes))
	}
}

// ADR 0023 M2.6 (A23-1, A23-45): a rotate whose instance has no keyholder
// deployed plans and confirms with no reader at all: its plan reads no
// cluster (cluster_identity none, no uid), and its --confirm rotates the
// keyring, opening no writer and no keyholder and writing no pin. Its plan
// needs the instance's record, as an interactive run does not: with none it
// is refused in today's words.
func TestRotateWithNoKeyholderNeedsNoReader(t *testing.T) {
	t.Run("no keyholder, no reader", func(t *testing.T) {
		s := kubetest.New(t)
		dir, meta := writeInstance(t, s, true)
		meta.Keyholder, meta.Reader = nil, nil
		if err := dir.SaveInstanceMetadata(writeName, meta); err != nil {
			t.Fatal(err)
		}
		saveKeyring(t, dir, writeName, backdatedApps(t))
		before := liveKeyring(t, dir, writeName)
		r := &rotateRig{dir: dir, ps: pinStoreOf(dir, writeName)}
		doc := r.plan(t)
		if b := decodedBound(t, doc); b.ClusterIdentity != "none" || b.Target.SystemNamespaceUID != "" {
			t.Errorf("the plan reads the cluster as %q, binding the uid %q; want none", b.ClusterIdentity, b.Target.SystemNamespaceUID)
		}
		if _, stderr, err := r.run(t, "--confirm", doc.Digest); err != nil {
			t.Fatalf("--confirm: %v\n%s", err, stderr)
		}
		if scopeKEK(liveKeyring(t, dir, writeName)) == scopeKEK(before) {
			t.Error("--confirm did not rotate the keyring")
		}
		if len(s.Requests()) != 0 || r.writers+r.keyholders != 0 || r.ps.exists || len(r.ps.openedBy()) != 0 {
			t.Errorf("sent %d requests, opened the writer %d and the keyholder %d times, and wrote the pin %v", len(s.Requests()), r.writers, r.keyholders, r.ps.exists)
		}
	})
	t.Run("no record", func(t *testing.T) {
		env, out, _, dir := newKeyringEnv(t, output.ModeJSON)
		before := keyringBytes(t, dir, "prod")
		err := withFlags(t, &keyRotateCommand{}, "--plan").Run(t.Context(), env, []string{"prod"})
		if err == nil || !strings.HasPrefix(err.Error(), `load instance "prod": `) {
			t.Errorf("--plan with no record = %v; want the record's load refused", err)
		}
		if out.Len() != 0 || !bytes.Equal(before, keyringBytes(t, dir, "prod")) {
			t.Errorf("printed %q, or changed keys.yaml", out)
		}
	})
}
