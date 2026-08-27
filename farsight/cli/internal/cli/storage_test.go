package cli

// `farcast storage`'s data verbs — the locator, ls, cp, rm and usage.
//
// Nothing is stubbed above the cloud: every test drives a real
// datasphere.Store, resolved through the CLI's own storage.Open, over an
// in-memory provider. What these assertions see is real tokenized names, real
// ciphertext and the real chunked format cp streams through. What is faked is
// the cloud, and only the cloud.
//
// The locator gets the most attention, because a mistake there does not fail —
// it silently addresses the wrong thing, and both wrong things (the wrong
// bytes uploaded, the wrong file overwritten) are unrecoverable.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sofmon/farcast/datasphere"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/storage"
)

// ---------------------------------------------------------------- the fake cloud

const dataBucket = "farcast-prod-0d47ab1e"

// dataBlob is one object as the cloud holds it: ciphertext, the metadata map
// carrying the sealed-name mirror, and the creation time a listing reports.
type dataBlob struct {
	data    []byte
	meta    map[string]string
	created time.Time
}

// dataCloud is an in-memory object store standing in for a bucket.
//
// It implements the whole datasphere.Provider surface, PutStream/GetStream
// included, because cp streams in both directions — a fake without them would
// exercise a path the CLI never takes. It reports creation times, which the
// data verbs render (an age in `ls --long`, a write window in `usage`) and
// counts streamed writes separately from buffered ones, which is how a test
// tells cp streamed rather than buffered an object it promised not to.
type dataCloud struct {
	// The Provider contract permits concurrent calls, so the fake honours it
	// rather than modelling a provider that does not.
	mu      sync.Mutex
	objects map[string]dataBlob

	// owner is the instance this bucket belongs to. Validate refuses any
	// other, exactly as the GCS adapter does, so storage.Open's ownership
	// enforcement point is exercised rather than assumed.
	owner string

	puts       int // whole-object writes
	putStreams int // streamed writes
}

func newDataCloud(owner string) *dataCloud {
	return &dataCloud{objects: map[string]dataBlob{}, owner: owner}
}

func (*dataCloud) Name() string { return "data-cloud" }

func (f *dataCloud) Validate(_ context.Context, ref datasphere.BucketRef) error {
	if ref.Name == "" {
		return nil
	}
	if ref.Instance != f.owner {
		return fmt.Errorf("%w: bucket %q belongs to %q", datasphere.ErrNotOwned, ref.Name, f.owner)
	}
	return nil
}

func (f *dataCloud) EnsureBucket(_ context.Context, spec datasphere.BucketSpec) (*datasphere.Bucket, error) {
	if spec.Instance != f.owner {
		return nil, fmt.Errorf("%w: bucket %q belongs to %q", datasphere.ErrNotOwned, spec.Name, f.owner)
	}
	return &datasphere.Bucket{Ref: datasphere.BucketRef{Name: spec.Name, Location: spec.Location, Instance: spec.Instance}}, nil
}

func (f *dataCloud) DeleteBucket(_ context.Context, ref datasphere.BucketRef) error {
	if ref.Instance != f.owner {
		return fmt.Errorf("%w: bucket %q belongs to %q", datasphere.ErrNotOwned, ref.Name, f.owner)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects = map[string]dataBlob{}
	return nil
}

func (f *dataCloud) Put(_ context.Context, _ string, obj datasphere.Object) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.puts++
	f.keep(obj.Name, obj.Data, obj.Meta)
	return nil
}

func (f *dataCloud) PutStream(_ context.Context, _ string, obj datasphere.StreamObject) error {
	data, err := io.ReadAll(obj.Data)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.putStreams++
	f.keep(obj.Name, data, obj.Meta)
	return nil
}

// keep records one object. The caller holds the lock.
func (f *dataCloud) keep(name string, data []byte, meta map[string]string) {
	f.objects[name] = dataBlob{
		data:    append([]byte(nil), data...),
		meta:    meta,
		created: time.Now().UTC(),
	}
}

func (f *dataCloud) Get(_ context.Context, _, name string) (*datasphere.Object, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	blob, ok := f.objects[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", datasphere.ErrObjectNotFound, name)
	}
	// A copy: a caller that mutates what it read must not reach the store.
	return &datasphere.Object{Name: name, Data: append([]byte(nil), blob.data...), Meta: blob.meta}, nil
}

func (f *dataCloud) GetStream(ctx context.Context, bucket, name string, offset, length int64) (io.ReadCloser, error) {
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

// List returns entries in map order — deliberately unsorted, so a sorted
// listing proves the CLI sorts rather than inheriting one cloud's ordering.
func (f *dataCloud) List(_ context.Context, _, prefix string) ([]datasphere.ObjectInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []datasphere.ObjectInfo
	for name, blob := range f.objects {
		if strings.HasPrefix(name, prefix) {
			out = append(out, datasphere.ObjectInfo{
				Name: name, Size: int64(len(blob.data)), Created: blob.created, Meta: blob.meta,
			})
		}
	}
	return out, nil
}

func (f *dataCloud) Delete(_ context.Context, _, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.objects, name)
	return nil
}

// corrupt damages a stored blob's last byte.
//
// The metadata mirror is left intact, so the object still lists under its
// name; the damage is found only when the reader reaches the final frame,
// after the earlier ones have already been written out. That is the failure a
// staged download exists to survive, and this is the only way to stage it
// without a hostile cloud.
func (f *dataCloud) corrupt(t *testing.T, stored string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	blob, ok := f.objects[stored]
	if !ok {
		t.Fatalf("no stored object %q to corrupt", stored)
	}
	blob.data[len(blob.data)-1] ^= 0x01
}

// dataCloudSeq keeps every registration unique: datasphere.Register panics on
// a duplicate name and there is no unregister, so the name carries a counter
// rather than the test's name.
var dataCloudSeq atomic.Uint64

func registerDataCloud(t *testing.T, f *dataCloud) string {
	t.Helper()
	name := fmt.Sprintf("data-cloud-%d", dataCloudSeq.Add(1))
	datasphere.Register(name, func(datasphere.Config) (datasphere.Provider, error) { return f, nil })
	return name
}

// ---------------------------------------------------------------- fixtures

// newDataEnv is an env with one instance, "prod", whose bucket is recorded and
// already created — the state every storage command finds once the first one
// has run. There is deliberately no keyring yet: minting it is what the first
// command that writes does, and one test is about exactly that.
//
// The storage provider is recorded explicitly, and that is also what pins
// these tests to the fake: storage.Open prefers the recorded provider over the
// compute-provider table, which would otherwise resolve "gke" to the real GCS
// adapter and reach for a cloud.
func newDataEnv(t *testing.T, mode output.Mode) (*Env, *bytes.Buffer, *bytes.Buffer, config.Dir, *dataCloud) {
	t.Helper()
	env, out, errb, dir := newInstallEnv(t, mode)
	f := newDataCloud("prod")
	if err := dir.CreateInstance("prod"); err != nil {
		t.Fatalf("CreateInstance: %v", err)
	}
	stamp := time.Now().UTC().Truncate(time.Second)
	meta := &config.InstanceMetadata{
		Name: "prod", Provider: "gke", Project: "proj-1", Region: "us-central1",
		Cluster: "farcast-prod", Status: config.InstanceRunning,
		Storage: &config.Storage{
			Bucket: dataBucket, Location: "us-central1", Provider: registerDataCloud(t, f),
			RecordedAt: stamp, CreatedAt: stamp.Add(time.Second),
		},
	}
	if err := dir.SaveInstanceMetadata("prod", meta); err != nil {
		t.Fatalf("SaveInstanceMetadata: %v", err)
	}
	if err := dir.SaveInstanceCredentials("prod", &config.InstanceCredentials{Provider: "gke"}); err != nil {
		t.Fatalf("SaveInstanceCredentials: %v", err)
	}
	return env, out, errb, dir, f
}

// dataStore resolves the instance's Store through the CLI's own composition
// root, minting the keyring on first use exactly as cp does.
func dataStore(t *testing.T, env *Env) *datasphere.Store {
	t.Helper()
	session, err := storage.Open(context.Background(), storage.Options{
		Dir: env.ConfigDir, Instance: "prod", Mint: true,
	})
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	return session.Store
}

// seedData writes objects the way cp does — through the chunked streaming
// path, not the buffered one — so what the tests list, read and delete is
// shaped like what the CLI itself would have left behind.
func seedData(t *testing.T, store *datasphere.Store, objects map[string][]byte) {
	t.Helper()
	for key, data := range objects {
		if err := store.WriteStream(context.Background(), key, bytes.NewReader(data)); err != nil {
			t.Fatalf("seed %q: %v", key, err)
		}
	}
}

func storedNameFor(t *testing.T, store *datasphere.Store, key string) string {
	t.Helper()
	stored, err := store.StoredName(key)
	if err != nil {
		t.Fatalf("StoredName(%q): %v", key, err)
	}
	return stored
}

func readStored(t *testing.T, store *datasphere.Store, key string) string {
	t.Helper()
	data, err := store.Read(context.Background(), key)
	if err != nil {
		t.Fatalf("read %q: %v", key, err)
	}
	return string(data)
}

// storedKeys is what the bucket holds, read through a Store rather than
// through `ls`, so a test never checks a command against itself.
func storedKeys(t *testing.T, store *datasphere.Store, prefix string) []string {
	t.Helper()
	keys, err := store.List(context.Background(), prefix)
	if err != nil {
		t.Fatalf("list %q: %v", prefix, err)
	}
	return keys
}

func writeLocalFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readLocalFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

// framedPayload is larger than DataSphere's 1 MiB frame, so a copy of it is
// several authenticated frames rather than one — the streaming path cp
// promises to take whatever the size.
func framedPayload() []byte {
	b := make([]byte, 2*1024*1024+4096)
	for i := range b {
		b[i] = byte(i*31 + 7)
	}
	return b
}

// ---------------------------------------------------------------- the locator

func TestStorageLocator(t *testing.T) {
	_, _, _, dir := newInstallEnv(t, output.ModeHuman)
	if err := dir.CreateInstance("prod"); err != nil {
		t.Fatal(err)
	}
	// Colon-bearing operands resolve against the process's working directory,
	// because that is where an operator types them.
	work := t.TempDir()
	t.Chdir(work)
	writeLocalFile(t, filepath.Join(work, "weird:name"), []byte("local"))
	writeLocalFile(t, filepath.Join(work, "sub", "a:b"), []byte("local"))

	for _, tc := range []struct {
		name     string
		operand  string
		instance string
		key      string
		path     string
	}{
		{name: "plain local path", operand: "./q3.csv", path: "./q3.csv"},
		{name: "bare local name", operand: "q3.csv", path: "q3.csv"},
		{name: "remote object", operand: "prod:app/reports/q3.csv", instance: "prod", key: "app/reports/q3.csv"},
		{name: "remote prefix", operand: "prod:app/reports/", instance: "prod", key: "app/reports/"},
		{name: "whole bucket", operand: "prod:", instance: "prod", key: ""},
		// The colon falls after a separator, so the operand is a path whatever
		// the text before the colon happens to name.
		{name: "colon after slash", operand: "sub/a:b", path: "sub/a:b"},
		{name: "colon after dot slash", operand: "./prod:x", path: "./prod:x"},
		// Instance-shaped, but the instance does not exist and the file does.
		{name: "local file with a colon", operand: "weird:name", path: "weird:name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			loc, err := parseLocator(dir, tc.operand)
			if err != nil {
				t.Fatalf("parseLocator(%q): %v", tc.operand, err)
			}
			if tc.instance != "" {
				if !loc.Remote || loc.Instance != tc.instance || loc.Key != tc.key {
					t.Fatalf("parseLocator(%q) = %+v, want remote %s:%s", tc.operand, loc, tc.instance, tc.key)
				}
				return
			}
			if loc.Remote || loc.Path != tc.path {
				t.Fatalf("parseLocator(%q) = %+v, want local path %q", tc.operand, loc, tc.path)
			}
		})
	}
}

// An instance-shaped operand naming nothing is a mistyped instance name, not a
// mistyped filename. Saying so is the difference between a one-word fix and a
// hunt through the filesystem.
func TestStorageLocatorUnknownInstanceSaysSo(t *testing.T) {
	_, _, _, dir := newInstallEnv(t, output.ModeHuman)
	t.Chdir(t.TempDir())

	_, err := parseLocator(dir, "ghost:app/x")
	if err == nil {
		t.Fatal("parseLocator(ghost:app/x) = nil, want an error")
	}
	if !strings.Contains(err.Error(), "no such instance") || !strings.Contains(err.Error(), "ghost") {
		t.Errorf("err = %v, want it to name the missing instance", err)
	}
	if strings.Contains(err.Error(), "not a local path") {
		t.Errorf("err = %v, must not blame the local reading", err)
	}
}

// Both readings genuinely available: refusing beats guessing, because one
// guess uploads the wrong bytes and the other overwrites the wrong file.
func TestStorageLocatorAmbiguousIsAUsageError(t *testing.T) {
	_, _, _, dir := newInstallEnv(t, output.ModeHuman)
	if err := dir.CreateInstance("prod"); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	t.Chdir(work)
	writeLocalFile(t, filepath.Join(work, "prod:x"), []byte("local"))

	_, err := parseLocator(dir, "prod:x")
	if _, ok := errors.AsType[*usageError](err); !ok {
		t.Fatalf("err = %v, want a usageError", err)
	}
	if !strings.Contains(err.Error(), "./prod:x") {
		t.Errorf("err = %v, want the ./prod:x escape hatch spelled out", err)
	}
	// The advice has to work, or it is not advice.
	loc, err := parseLocator(dir, "./prod:x")
	if err != nil || loc.Remote || loc.Path != "./prod:x" {
		t.Fatalf("parseLocator(./prod:x) = %+v, %v; want the local file", loc, err)
	}
}

// ls and usage take an operand that can only ever name an instance, and both
// spell the colon as optional in their own usage lines.
func TestStorageInstanceOperandAcceptsABareName(t *testing.T) {
	_, _, _, dir := newInstallEnv(t, output.ModeHuman)
	if err := dir.CreateInstance("prod"); err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())

	for _, operand := range []string{"prod", "prod:"} {
		loc, err := instanceLocator(dir, "storage ls", operand)
		if err != nil || !loc.Remote || loc.Instance != "prod" || loc.Key != "" {
			t.Errorf("instanceLocator(%q) = %+v, %v; want the whole bucket", operand, loc, err)
		}
	}
	if _, err := instanceLocator(dir, "storage ls", "ghost"); err == nil ||
		!strings.Contains(err.Error(), "no such instance") {
		t.Errorf("err = %v, want no-such-instance", err)
	}
	if _, err := instanceLocator(dir, "storage ls", "./somewhere"); err == nil {
		t.Error("a local path is not an instance")
	}
}

// ---------------------------------------------------------------- ls

func TestStorageLsSortsAndSummarizes(t *testing.T) {
	env, out, _, _, _ := newDataEnv(t, output.ModeHuman)
	seedData(t, dataStore(t, env), map[string][]byte{
		"zz.bin":             []byte("z"),
		"app/reports/q3.csv": []byte("three"),
		"app/reports/q1.csv": []byte("one"),
		"app/notes.txt":      []byte("notes"),
	})

	cmd := &storageLsCommand{}
	if err := cmd.Run(context.Background(), env, []string{"prod:"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// The provider lists in map order, so a sorted listing is the CLI's doing.
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	want := []string{"app/notes.txt", "app/reports/q1.csv", "app/reports/q3.csv", "zz.bin"}
	if len(lines) != len(want)+1 {
		t.Fatalf("got %d lines, want %d keys plus a summary:\n%s", len(lines), len(want), out.String())
	}
	for i, key := range want {
		if lines[i] != key {
			t.Errorf("line %d = %q, want %q", i, lines[i], key)
		}
	}
	summary := lines[len(want)]
	if !strings.HasPrefix(summary, "4 object(s)") || !strings.Contains(summary, "stored") {
		t.Errorf("summary = %q, want the count and the stored size", summary)
	}

	// A prefix narrows the listing to the keys under it.
	out.Reset()
	if err := cmd.Run(context.Background(), env, []string{"prod:app/reports/"}); err != nil {
		t.Fatalf("Run(prefix): %v", err)
	}
	if got := out.String(); !strings.Contains(got, "q1.csv") || !strings.Contains(got, "q3.csv") ||
		strings.Contains(got, "notes.txt") || strings.Contains(got, "zz.bin") {
		t.Errorf("prefix listing = %q, want only the two reports", got)
	}
}

func TestStorageLsLongShowsSizes(t *testing.T) {
	env, out, _, _, _ := newDataEnv(t, output.ModeHuman)
	seedData(t, dataStore(t, env), map[string][]byte{"app/notes.txt": []byte("notes")})

	cmd := &storageLsCommand{long: true}
	if err := cmd.Run(context.Background(), env, []string{"prod:"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	line := strings.Split(strings.TrimSpace(out.String()), "\n")[0]
	fields := strings.Fields(line)
	if len(fields) != 4 || fields[1] != "B" || fields[2] != "0m" || fields[3] != "app/notes.txt" {
		t.Fatalf("--long line = %q, want \"<size> <unit> <age> <key>\"", line)
	}
	// The size is the ciphertext the cloud bills for, not the five bytes of
	// plaintext: the envelope is a real, permanent, billed cost.
	if fields[0] == "5" {
		t.Errorf("--long reported the plaintext size %q, not the stored size", fields[0])
	}
}

// --tokens is the transparency surface: hold the stored name next to the
// logical one and see for yourself that the cloud has neither.
func TestStorageLsTokensRevealNothingOfTheKey(t *testing.T) {
	env, out, _, _, f := newDataEnv(t, output.ModeHuman)
	const key = "app/reports/q3.csv"
	store := dataStore(t, env)
	seedData(t, store, map[string][]byte{key: []byte("payload")})

	cmd := &storageLsCommand{tokens: true}
	if err := cmd.Run(context.Background(), env, []string{"prod:"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	line := strings.Split(strings.TrimSpace(out.String()), "\n")[0]
	stored, logical, ok := strings.Cut(line, "\t")
	if !ok {
		t.Fatalf("--tokens line = %q, want the stored name beside the key", line)
	}
	if logical != key {
		t.Fatalf("logical name = %q, want %q", logical, key)
	}
	if stored == "" || stored == key {
		t.Fatalf("stored name = %q, want an opaque name", stored)
	}
	assertNothingInCommon(t, key, stored)
	// And it is genuinely the name the cloud holds, not a decoration.
	if want := storedNameFor(t, store, key); stored != want {
		t.Errorf("--tokens printed %q, but the object is stored at %q", stored, want)
	}
	if _, err := f.Get(context.Background(), dataBucket, stored); err != nil {
		t.Errorf("the cloud holds nothing at the printed name: %v", err)
	}
}

// assertNothingInCommon asserts the stored name leaks no run of the logical
// key. A stored name is hex tokens joined by "/", so any three-character run
// of a key that carries a character outside [0-9a-f/] cannot appear in one by
// chance; runs of one or two collide in hex and would prove nothing.
func assertNothingInCommon(t *testing.T, logical, stored string) {
	t.Helper()
	for i := 0; i+3 <= len(logical); i++ {
		if run := logical[i : i+3]; strings.Contains(stored, run) {
			t.Errorf("stored name %q carries %q from the logical key %q", stored, run, logical)
		}
	}
}

func TestStorageLsJSON(t *testing.T) {
	env, out, _, _, _ := newDataEnv(t, output.ModeJSON)
	seedData(t, dataStore(t, env), map[string][]byte{
		"app/notes.txt": []byte("notes"),
		"app/other.txt": []byte("other"),
		"zz.bin":        []byte("z"),
	})

	if err := (&storageLsCommand{tokens: true}).Run(context.Background(), env, []string{"prod:app/"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	var got struct {
		Instance    string `json:"instance"`
		Bucket      string `json:"bucket"`
		Prefix      string `json:"prefix"`
		Count       int    `json:"count"`
		StoredBytes int64  `json:"stored_bytes"`
		Objects     []struct {
			Key         string `json:"key"`
			StoredBytes int64  `json:"stored_bytes"`
			Created     string `json:"created"`
			StoredName  string `json:"stored_name"`
		} `json:"objects"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out.String())
	}
	if got.Instance != "prod" || got.Bucket != dataBucket || got.Prefix != "app/" || got.Count != 2 {
		t.Fatalf("unexpected result envelope: %+v", got)
	}
	if len(got.Objects) != 2 || got.Objects[0].Key != "app/notes.txt" || got.Objects[1].Key != "app/other.txt" {
		t.Fatalf("objects = %+v, want both keys under the prefix, sorted", got.Objects)
	}
	var sum int64
	for _, o := range got.Objects {
		if o.StoredBytes <= 0 || o.StoredName == "" || o.Created == "" {
			t.Errorf("object %+v is missing something --tokens promised", o)
		}
		sum += o.StoredBytes
	}
	if got.StoredBytes != sum {
		t.Errorf("stored_bytes = %d, want the sum over the listed objects (%d)", got.StoredBytes, sum)
	}

	// Without --tokens the opaque name is absent, not empty-stringed: a
	// scripted caller should not have to tell "not asked for" from "none".
	out.Reset()
	if err := (&storageLsCommand{}).Run(context.Background(), env, []string{"prod:"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.Contains(out.String(), "stored_name") {
		t.Errorf("stored_name should appear only with --tokens:\n%s", out.String())
	}
	// An empty listing is still a well-formed result, with an empty array.
	out.Reset()
	if err := (&storageLsCommand{}).Run(context.Background(), env, []string{"prod:nothing/"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(out.String(), `"objects":[]`) || !strings.Contains(out.String(), `"count":0`) {
		t.Errorf("empty listing = %s, want an empty array and a zero count", out.String())
	}
}

func TestStorageLsRejectsALocalPath(t *testing.T) {
	env, _, _, _, _ := newDataEnv(t, output.ModeHuman)
	err := (&storageLsCommand{}).Run(context.Background(), env, []string{"./somewhere"})
	if _, ok := errors.AsType[*usageError](err); !ok {
		t.Fatalf("err = %v, want a usageError", err)
	}
	if err := (&storageLsCommand{}).Run(context.Background(), env, []string{"prod:", "extra"}); err == nil {
		t.Error("ls takes exactly one operand")
	}
}

func TestStorageAgeRendersOperatorScale(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		stamp string
		want  string
	}{
		{stamp: "", want: "-"},
		{stamp: "not a timestamp", want: "-"},
		{stamp: now.Add(-30 * time.Minute).Format(time.RFC3339), want: "30m"},
		{stamp: now.Add(-5 * time.Hour).Format(time.RFC3339), want: "5h"},
		{stamp: now.Add(-72 * time.Hour).Format(time.RFC3339), want: "3d"},
	} {
		if got := age(tc.stamp); got != tc.want {
			t.Errorf("age(%q) = %q, want %q", tc.stamp, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------- cp

func TestStorageCpRoundTrip(t *testing.T) {
	env, out, errb, dir, _ := newDataEnv(t, output.ModeHuman)
	work := t.TempDir()
	payload := []byte("quarterly numbers\n")
	src := filepath.Join(work, "q3.csv")
	writeLocalFile(t, src, payload)

	cmd := &storageCpCommand{}
	if err := cmd.Run(context.Background(), env, []string{src, "prod:app/reports/q3.csv"}); err != nil {
		t.Fatalf("upload: %v", err)
	}
	if !strings.Contains(out.String(), "uploaded 1 object") {
		t.Errorf("upload result = %q", out.String())
	}
	if got := readStored(t, dataStore(t, env), "app/reports/q3.csv"); got != string(payload) {
		t.Fatalf("stored %q, want %q", got, payload)
	}

	// First storage use is what mints the keyring, and the mint says the one
	// thing an operator will only ever act on at the moment the file appears.
	if !strings.Contains(errb.String(), datasphere.KeyLossWarning) {
		t.Errorf("the mint must print the key-loss warning verbatim:\n%s", errb.String())
	}
	if !strings.Contains(errb.String(), dir.InstancePath("prod")) {
		t.Errorf("the mint must name what to back up:\n%s", errb.String())
	}
	assertPerm(t, dir.InstanceKeyringPath("prod"), 0o600)
	assertPerm(t, filepath.Dir(dir.InstanceKeyringPath("prod")), 0o700)

	// And back out again, into a directory that does not exist yet.
	out.Reset()
	dst := filepath.Join(work, "out", "q3.csv")
	if err := cmd.Run(context.Background(), env, []string{"prod:app/reports/q3.csv", dst}); err != nil {
		t.Fatalf("download: %v", err)
	}
	if got := readLocalFile(t, dst); got != string(payload) {
		t.Errorf("downloaded %q, want %q", got, payload)
	}
	// Decrypted plaintext is not something to leave world-readable.
	assertPerm(t, dst, 0o600)
	if !strings.Contains(out.String(), "downloaded 1 object") {
		t.Errorf("download result = %q", out.String())
	}
}

// A payload bigger than one frame proves cp takes the streaming path rather
// than buffering an object it promised not to.
func TestStorageCpStreamsLargePayloads(t *testing.T) {
	env, _, _, _, f := newDataEnv(t, output.ModeHuman)
	work := t.TempDir()
	payload := framedPayload()
	src := filepath.Join(work, "big.bin")
	writeLocalFile(t, src, payload)

	cmd := &storageCpCommand{}
	if err := cmd.Run(context.Background(), env, []string{src, "prod:archive/big.bin"}); err != nil {
		t.Fatalf("upload: %v", err)
	}
	// A buffered write would have gone to Put; only WriteStream reaches here.
	if f.putStreams != 1 || f.puts != 0 {
		t.Errorf("the cloud saw %d streamed and %d buffered writes, want 1 and 0", f.putStreams, f.puts)
	}
	stored, err := f.Get(context.Background(), dataBucket, storedNameFor(t, dataStore(t, env), "archive/big.bin"))
	if err != nil {
		t.Fatalf("stored object: %v", err)
	}
	if len(stored.Data) <= len(payload) {
		t.Errorf("stored %d bytes for a %d-byte payload; the framing is missing", len(stored.Data), len(payload))
	}

	dst := filepath.Join(work, "back.bin")
	if err := cmd.Run(context.Background(), env, []string{"prod:archive/big.bin", dst}); err != nil {
		t.Fatalf("download: %v", err)
	}
	if got := readLocalFile(t, dst); got != string(payload) {
		t.Fatalf("a %d-byte round trip came back %d bytes and different", len(payload), len(got))
	}
}

func TestStorageCpRefusesToOverwriteRemote(t *testing.T) {
	env, out, _, _, _ := newDataEnv(t, output.ModeHuman)
	store := dataStore(t, env)
	seedData(t, store, map[string][]byte{"app/q3.csv": []byte("first")})
	src := filepath.Join(t.TempDir(), "q3.csv")
	writeLocalFile(t, src, []byte("second"))

	err := (&storageCpCommand{}).Run(context.Background(), env, []string{src, "prod:app/q3.csv"})
	if _, ok := errors.AsType[*usageError](err); !ok {
		t.Fatalf("err = %v, want a usageError", err)
	}
	if !strings.Contains(err.Error(), "already exists") || !strings.Contains(err.Error(), "--force") {
		t.Errorf("err = %v, want what is there and the way past it", err)
	}
	if got := readStored(t, store, "app/q3.csv"); got != "first" {
		t.Fatalf("the object changed under a refusal: %q", got)
	}

	// --skip-existing leaves it alone, and says so rather than claiming a copy.
	if err := (&storageCpCommand{skipExisting: true}).Run(context.Background(), env, []string{src, "prod:app/q3.csv"}); err != nil {
		t.Fatalf("--skip-existing: %v", err)
	}
	if got := readStored(t, store, "app/q3.csv"); got != "first" {
		t.Errorf("--skip-existing overwrote the object: %q", got)
	}
	if !strings.Contains(out.String(), "uploaded 0 object") || !strings.Contains(out.String(), "skipped 1") {
		t.Errorf("--skip-existing result = %q, want nothing copied and one skipped", out.String())
	}

	// --force is the one thing that replaces it.
	if err := (&storageCpCommand{force: true}).Run(context.Background(), env, []string{src, "prod:app/q3.csv"}); err != nil {
		t.Fatalf("--force: %v", err)
	}
	if got := readStored(t, store, "app/q3.csv"); got != "second" {
		t.Errorf("--force left %q, want the new bytes", got)
	}
}

func TestStorageCpRefusesToOverwriteLocal(t *testing.T) {
	env, out, _, _, _ := newDataEnv(t, output.ModeHuman)
	seedData(t, dataStore(t, env), map[string][]byte{"app/q3.csv": []byte("remote")})
	dst := filepath.Join(t.TempDir(), "q3.csv")
	writeLocalFile(t, dst, []byte("mine"))

	err := (&storageCpCommand{}).Run(context.Background(), env, []string{"prod:app/q3.csv", dst})
	if _, ok := errors.AsType[*usageError](err); !ok {
		t.Fatalf("err = %v, want a usageError", err)
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("err = %v, want it to name the file it will not replace", err)
	}
	if got := readLocalFile(t, dst); got != "mine" {
		t.Fatalf("the local file changed under a refusal: %q", got)
	}

	if err := (&storageCpCommand{skipExisting: true}).Run(context.Background(), env, []string{"prod:app/q3.csv", dst}); err != nil {
		t.Fatalf("--skip-existing: %v", err)
	}
	if got := readLocalFile(t, dst); got != "mine" {
		t.Errorf("--skip-existing overwrote the file: %q", got)
	}
	if !strings.Contains(out.String(), "downloaded 0 object") || !strings.Contains(out.String(), "skipped 1") {
		t.Errorf("--skip-existing result = %q, want nothing copied and one skipped", out.String())
	}

	if err := (&storageCpCommand{force: true}).Run(context.Background(), env, []string{"prod:app/q3.csv", dst}); err != nil {
		t.Fatalf("--force: %v", err)
	}
	if got := readLocalFile(t, dst); got != "remote" {
		t.Errorf("--force left %q, want the downloaded bytes", got)
	}
	assertPerm(t, dst, 0o600)
}

func TestStorageCpOperandUsageErrors(t *testing.T) {
	env, _, _, _, f := newDataEnv(t, output.ModeHuman)
	work := t.TempDir()
	writeLocalFile(t, filepath.Join(work, "a"), []byte("a"))

	for _, tc := range []struct {
		name string
		cmd  *storageCpCommand
		args []string
		want string
	}{
		{
			name: "opposite flags",
			cmd:  &storageCpCommand{force: true, skipExisting: true},
			args: []string{filepath.Join(work, "a"), "prod:a"},
			want: "opposite",
		},
		{
			name: "two remote operands",
			cmd:  &storageCpCommand{},
			args: []string{"prod:a", "prod:b"},
			want: "two instances",
		},
		{
			name: "two local operands",
			cmd:  &storageCpCommand{},
			args: []string{filepath.Join(work, "a"), filepath.Join(work, "b")},
			want: "names an instance",
		},
		{
			name: "one operand",
			cmd:  &storageCpCommand{},
			args: []string{"prod:a"},
			want: "source and a destination",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cmd.Run(context.Background(), env, tc.args)
			if _, ok := errors.AsType[*usageError](err); !ok {
				t.Fatalf("err = %v, want a usageError", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
	// None of them may have written anything on the way to the refusal — and
	// a refused copy must not even have minted a keyring.
	if f.putStreams != 0 || f.puts != 0 {
		t.Errorf("a refused cp wrote %d object(s)", f.putStreams+f.puts)
	}
}

// A download that fails partway must leave nothing at the destination: the
// streaming format authenticates per frame, so damage is found only after
// earlier frames have been written, and a partial file that looks plausible is
// worse than no file at all.
func TestStorageCpDownloadLeavesNoPartialFile(t *testing.T) {
	env, _, _, _, f := newDataEnv(t, output.ModeHuman)
	store := dataStore(t, env)
	payload := framedPayload()
	seedData(t, store, map[string][]byte{"archive/big.bin": payload})
	f.corrupt(t, storedNameFor(t, store, "archive/big.bin"))

	// The damage really is late: the reader emits most of the object before it
	// reaches the frame that fails. That is what makes staging load-bearing
	// rather than tidy, and without it this test would prove nothing.
	var counted countingSink
	if err := store.ReadStream(context.Background(), "archive/big.bin", &counted); err == nil {
		t.Fatal("a corrupt object read clean")
	}
	if counted.n == 0 {
		t.Fatal("the read failed before writing anything; this no longer stages a partial write")
	}

	dstDir := t.TempDir()
	dst := filepath.Join(dstDir, "big.bin")
	err := (&storageCpCommand{}).Run(context.Background(), env, []string{"prod:archive/big.bin", dst})
	if err == nil {
		t.Fatal("cp reported success on a corrupt object")
	}
	if !errors.Is(err, datasphere.ErrIntegrity) {
		t.Errorf("err = %v, want it to carry ErrIntegrity", err)
	}
	if _, statErr := os.Lstat(dst); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("%s exists after a failed download (%v); a partial file is worse than none", dst, statErr)
	}
	// Not even the staging file, which is billed to nobody but is still a
	// half-decrypted copy of somebody's data.
	entries, err := os.ReadDir(dstDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("a failed download left %d file(s) behind: %v", len(entries), entries)
	}
}

type countingSink struct{ n int }

func (w *countingSink) Write(p []byte) (int, error) {
	w.n += len(p)
	return len(p), nil
}

// A recursive download must never be a path-traversal primitive. After 3.2 a
// logical key may have been written by an application inside the instance, and
// a key is any valid UTF-8 string — "..", escapes and separators included.
func TestStorageCpRecursiveDownloadStaysInsideTheDestination(t *testing.T) {
	env, out, errb, _, _ := newDataEnv(t, output.ModeHuman)
	escapes := []string{"..", "../escape.txt", "a/../../escape.txt", "."}
	objects := map[string][]byte{
		"safe.txt":     []byte("safe"),
		"sub/safe.txt": []byte("also safe"),
	}
	for _, key := range escapes {
		objects[key] = []byte("ESCAPED")
	}
	seedData(t, dataStore(t, env), objects)

	base := t.TempDir()
	root := filepath.Join(base, "out")
	if err := (&storageCpCommand{recursive: true}).Run(context.Background(), env, []string{"prod:", root}); err != nil {
		t.Fatalf("cp -r: %v", err)
	}

	// The safe keys arrive, with their structure.
	if got := readLocalFile(t, filepath.Join(root, "safe.txt")); got != "safe" {
		t.Errorf("safe.txt = %q", got)
	}
	if got := readLocalFile(t, filepath.Join(root, "sub", "safe.txt")); got != "also safe" {
		t.Errorf("sub/safe.txt = %q", got)
	}
	// And nothing else does — not beside the destination, and not over it.
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "out" || !entries[0].IsDir() {
		t.Fatalf("the destination's parent holds %v, want only the destination directory", entries)
	}
	// Every refusal is named: a key that did not arrive is not the operator's
	// to guess at.
	for _, key := range escapes {
		if !strings.Contains(errb.String(), fmt.Sprintf("%q", key)) {
			t.Errorf("no warning names the refused key %q:\n%s", key, errb.String())
		}
	}
	if !strings.Contains(out.String(), "downloaded 2 object") ||
		!strings.Contains(out.String(), fmt.Sprintf("skipped %d", len(escapes))) {
		t.Errorf("result = %q, want 2 copied and %d skipped", out.String(), len(escapes))
	}
}

// The mapping itself, including keys DataSphere would refuse to store: those
// can only arrive from a cloud that wrote them behind its back, which is
// exactly when the check has to hold.
func TestStorageLocalTargetRefusesEscapes(t *testing.T) {
	root := filepath.Join(t.TempDir(), "out")

	for _, tc := range []struct {
		key    string
		prefix string
		want   string // relative to root; empty means "must be refused"
	}{
		{key: "safe.txt", want: "safe.txt"},
		{key: "sub/safe.txt", want: filepath.Join("sub", "safe.txt")},
		{key: "..foo", want: "..foo"},
		{key: "a/..foo/b", want: filepath.Join("a", "..foo", "b")},
		// A leading "/" names the destination root, never the filesystem root.
		{key: "/etc/passwd", want: filepath.Join("etc", "passwd")},
		{key: ".."},
		{key: "../escape.txt"},
		{key: "a/../../escape.txt"},
		{key: "."},
		{key: "a/.."},
		{key: "exports/x", prefix: "exports/", want: "x"},
		{key: "exports/", prefix: "exports/"},
	} {
		t.Run(tc.key, func(t *testing.T) {
			got, err := localTarget(root, tc.prefix, tc.key, true)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("localTarget(%q) = %q, want a refusal", tc.key, got)
				}
				if !strings.Contains(err.Error(), tc.key) {
					t.Errorf("err = %v, want it to name the key", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("localTarget(%q): %v", tc.key, err)
			}
			if want := filepath.Join(root, tc.want); got != want {
				t.Errorf("localTarget(%q) = %q, want %q", tc.key, got, want)
			}
		})
	}
}

// Defence in depth for the case above: a key with a leading "/" cannot be
// written through the CLI's own Store at all, because a logical key may not
// carry an empty segment.
func TestStorageStoreRefusesALeadingSlashKey(t *testing.T) {
	env, _, _, _, _ := newDataEnv(t, output.ModeHuman)
	err := dataStore(t, env).WriteStream(context.Background(), "/etc/passwd", strings.NewReader("x"))
	if !errors.Is(err, datasphere.ErrInvalidKey) {
		t.Fatalf("err = %v, want ErrInvalidKey", err)
	}
}

// ---------------------------------------------------------------- rm

func TestStorageRmOneKey(t *testing.T) {
	env, out, _, _, _ := newDataEnv(t, output.ModeHuman)
	store := dataStore(t, env)
	seedData(t, store, map[string][]byte{"a/1": []byte("1"), "a/2": []byte("2")})

	if err := (&storageRmCommand{}).Run(context.Background(), env, []string{"prod:a/1"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(out.String(), "deleted 1 object") || !strings.Contains(out.String(), "final") {
		t.Errorf("result = %q, want the count and the finality", out.String())
	}
	if remaining := storedKeys(t, store, ""); len(remaining) != 1 || remaining[0] != "a/2" {
		t.Errorf("remaining = %v, want only a/2", remaining)
	}
}

// Non-interactive is the CI case, and a recursive delete that cannot ask must
// not proceed on silence.
func TestStorageRmRecursiveNeedsConfirmation(t *testing.T) {
	env, _, _, _, _ := newDataEnv(t, output.ModeHuman)
	store := dataStore(t, env)
	seedData(t, store, map[string][]byte{"a/1": []byte("1"), "a/2": []byte("2"), "b/1": []byte("3")})

	err := (&storageRmCommand{recursive: true}).Run(context.Background(), env, []string{"prod:a/"})
	if _, ok := errors.AsType[*usageError](err); !ok {
		t.Fatalf("err = %v, want a usageError", err)
	}
	if !strings.Contains(err.Error(), "--yes") {
		t.Errorf("err = %v, want it to name --yes", err)
	}
	if got := storedKeys(t, store, ""); len(got) != 3 {
		t.Fatalf("%v remains; nothing may be deleted without confirmation", got)
	}
}

func TestStorageRmRecursiveDeletesExactlyThePrefix(t *testing.T) {
	env, out, _, _, _ := newDataEnv(t, output.ModeHuman)
	store := dataStore(t, env)
	seedData(t, store, map[string][]byte{
		"a/1": []byte("1"), "a/2": []byte("2"), "a/deep/3": []byte("3"),
		"b/1": []byte("4"), "ab": []byte("5"),
	})

	cmd := &storageRmCommand{recursive: true, assumeYes: true}
	if err := cmd.Run(context.Background(), env, []string{"prod:a/"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(out.String(), "deleted 3 object") {
		t.Errorf("result = %q, want 3 deleted", out.String())
	}
	// "ab" begins with "a" but is not under "a/": the prefix is honoured
	// exactly rather than by blind string matching.
	got, want := storedKeys(t, store, ""), []string{"ab", "b/1"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("remaining = %v, want %v", got, want)
	}
}

// The prompt asks for the number of objects, not a keystroke: an operator who
// has not read the list cannot answer it by reflex.
func TestStorageRmConfirmRequiresTheCount(t *testing.T) {
	env, _, errb, _, _ := newDataEnv(t, output.ModeHuman)
	targets := []string{"a/1", "a/2"}
	cmd := &storageRmCommand{recursive: true}

	env.In = strings.NewReader("2\n")
	ok, err := cmd.confirm(true, env, targets)
	if err != nil || !ok {
		t.Fatalf("confirm(2) = %v, %v; want true, nil", ok, err)
	}
	if !strings.Contains(errb.String(), "a/1") || !strings.Contains(errb.String(), "a/2") {
		t.Errorf("the prompt must list what will go:\n%s", errb.String())
	}
	if !strings.Contains(errb.String(), "immediate and final") {
		t.Errorf("the prompt must say deletes are final:\n%s", errb.String())
	}

	env.In = strings.NewReader("y\n")
	ok, err = cmd.confirm(true, env, targets)
	if err != nil || ok {
		t.Fatalf("confirm(y) = %v, %v; want false, nil — a yes is not the count", ok, err)
	}
}

func TestStorageRmOperandUsageErrors(t *testing.T) {
	env, _, _, dir, _ := newDataEnv(t, output.ModeHuman)
	if err := dir.CreateInstance("staging"); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "no operands", args: nil, want: "at least one"},
		{name: "a local path", args: []string{"./file"}, want: "is not an <instance>:<key>"},
		{name: "two instances", args: []string{"prod:a", "staging:b"}, want: "one instance"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := (&storageRmCommand{}).Run(context.Background(), env, tc.args)
			if _, ok := errors.AsType[*usageError](err); !ok {
				t.Fatalf("err = %v, want a usageError", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------- usage

// An operator who has lost keys.yaml can no longer read a byte of their data,
// but they can still be billed for it — so they must still be able to see what
// they are paying for, and stop.
func TestStorageUsageWorksWithoutAKeyring(t *testing.T) {
	env, out, _, dir, _ := newDataEnv(t, output.ModeHuman)
	seedData(t, dataStore(t, env), map[string][]byte{
		"a/1": []byte("one"), "a/2": []byte("two"), "b/1": framedPayload(),
	})
	keyring := dir.InstanceKeyringPath("prod")
	if err := os.Remove(keyring); err != nil {
		t.Fatalf("remove the keyring: %v", err)
	}

	if err := (&storageUsageCommand{}).Run(context.Background(), env, []string{"prod"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "objects   3") {
		t.Errorf("usage did not report the object count:\n%s", got)
	}
	if !strings.Contains(got, "what the provider bills") || !strings.Contains(got, "MiB") {
		t.Errorf("usage did not report the stored bytes:\n%s", got)
	}
	if !strings.Contains(got, "written   ") {
		t.Errorf("usage did not report the write window:\n%s", got)
	}
	// Every figure carries its basis: a stale price stated as fact is worse
	// than no price at all.
	if !strings.Contains(got, "~$") || !strings.Contains(got, "prices as of "+priceTableAsOf) {
		t.Errorf("usage did not date its estimate:\n%s", got)
	}
	if _, err := os.Stat(keyring); !errors.Is(err, os.ErrNotExist) {
		t.Error("usage must not mint a keyring for an operator who lost one")
	}
}

func TestStorageUsageJSON(t *testing.T) {
	env, out, _, _, _ := newDataEnv(t, output.ModeJSON)
	payload := framedPayload()
	seedData(t, dataStore(t, env), map[string][]byte{"a/1": payload})

	if err := (&storageUsageCommand{}).Run(context.Background(), env, []string{"prod:"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	var got storageUsageResult
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out.String())
	}
	if got.Instance != "prod" || got.Bucket != dataBucket || got.Objects != 1 {
		t.Fatalf("unexpected result: %+v", got)
	}
	// The count and the bytes come from the provider, so they are what the
	// cloud bills for rather than what the plaintext measured.
	if got.StoredBytes <= int64(len(payload)) {
		t.Errorf("stored_bytes = %d, want more than the %d bytes written", got.StoredBytes, len(payload))
	}
	if got.PricesAsOf != priceTableAsOf || got.MonthlyUSD <= 0 {
		t.Errorf("the estimate is missing its basis: %+v", got)
	}
	if got.Oldest == "" || got.Newest == "" {
		t.Errorf("usage should report the write window: %+v", got)
	}
}

// ---------------------------------------------------------------- routing

// Every one of these is a documented invocation. `storage` is the CLI's only
// two-level command, so it is the only place where the router has to learn a
// subcommand's flags before it can parse the line at all.
func TestStorageRouterAcceptsSubcommandFlags(t *testing.T) {
	env, _, _, dir, _ := newDataEnv(t, output.ModeHuman)
	seedData(t, dataStore(t, env), map[string][]byte{"a/1": []byte("one"), "a/2": []byte("two")})
	export := filepath.Join(t.TempDir(), "keys.export")
	passphrase := filepath.Join(t.TempDir(), "passphrase")
	writeLocalFile(t, passphrase, []byte("correct-horse-battery-staple\n"))

	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "short flag before the operand", args: []string{"storage", "ls", "-l", "prod:"}},
		{name: "long flag before the operand", args: []string{"storage", "ls", "--tokens", "prod:"}},
		{name: "flag after the operand", args: []string{"storage", "ls", "prod:", "--tokens"}},
		{name: "global flag before the subcommand", args: []string{"storage", "--output", "json", "ls", "-l", "prod:"}},
		{name: "bare instance name", args: []string{"storage", "usage", "prod"}},
		{name: "third level", args: []string{"storage", "key", "export", "prod",
			"--out", export, "--passphrase-file", passphrase}},
		{name: "trailing short flag", args: []string{"storage", "rm", "prod:a/1", "-y"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			args := append([]string{"farcast", "--config", string(dir)}, tc.args...)
			if code := run(context.Background(), args, strings.NewReader(""), &out, &errb); code != 0 {
				t.Fatalf("%v exited %d\nstdout: %s\nstderr: %s", tc.args, code, out.String(), errb.String())
			}
		})
	}
}

func TestStorageRouterUsageErrors(t *testing.T) {
	_, _, _, dir, _ := newDataEnv(t, output.ModeHuman)

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "no subcommand", args: []string{"storage"}, want: "requires a subcommand"},
		{name: "unknown subcommand", args: []string{"storage", "list", "prod:"}, want: "unknown storage subcommand"},
		{name: "unknown flag", args: []string{"storage", "ls", "--nope", "prod:"}, want: "not defined"},
		{name: "unknown key subcommand", args: []string{"storage", "key", "dump", "prod"}, want: "unknown key subcommand"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			args := append([]string{"farcast", "--config", string(dir)}, tc.args...)
			if code := run(context.Background(), args, strings.NewReader(""), &out, &errb); code != 2 {
				t.Fatalf("%v exited %d, want 2\nstdout: %s\nstderr: %s", tc.args, code, out.String(), errb.String())
			}
			if !strings.Contains(errb.String(), tc.want) {
				t.Errorf("stderr = %q, want it to mention %q", errb.String(), tc.want)
			}
		})
	}
}
