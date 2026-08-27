package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sofmon/farcast/datasphere"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
)

// The ensure path is the only place in the CLI where getting the ORDER wrong
// costs the operator something no re-run can recover: a billable bucket under
// a 32-bit random name that exists nowhere else, or — worse — real data
// abandoned behind a freshly minted name nothing points at any more. These
// tests drive that ordering against an in-memory provider; nothing here
// touches a cloud.

// fakeProvider is an in-memory datasphere.Provider.
//
// EnsureBucket does one thing a plain stub cannot: it reads the instance's
// metadata.yaml at the moment it is called. That is what makes
// record-before-create observable rather than assumed — the record either was
// already on disk when the create was attempted, or it was not.
type fakeProvider struct {
	mu      sync.Mutex
	objects map[string]datasphere.Object

	// dir and instance let EnsureBucket look at local state as it stood when
	// the create was attempted.
	dir      config.Dir
	instance string

	// ensureErrs is consumed one per EnsureBucket call; a nil entry (or an
	// exhausted list) succeeds.
	ensureErrs []error

	ensured     []datasphere.BucketSpec
	recorded    []*config.Storage // metadata.yaml's storage block, per call
	validateErr error
	validated   []datasphere.BucketRef
}

func newFakeProvider(dir config.Dir, instance string) *fakeProvider {
	return &fakeProvider{objects: map[string]datasphere.Object{}, dir: dir, instance: instance}
}

func (f *fakeProvider) Name() string { return "fake" }

func (f *fakeProvider) Validate(_ context.Context, ref datasphere.BucketRef) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.validated = append(f.validated, ref)
	return f.validateErr
}

func (f *fakeProvider) EnsureBucket(_ context.Context, spec datasphere.BucketSpec) (*datasphere.Bucket, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensured = append(f.ensured, spec)

	// The record as it stood at create time. Captured here rather than after
	// the call because "before" is the whole property under test.
	var snapshot *config.Storage
	if meta, err := f.dir.LoadInstanceMetadata(f.instance); err == nil {
		snapshot = meta.Storage
	}
	f.recorded = append(f.recorded, snapshot)

	if len(f.ensureErrs) > 0 {
		err := f.ensureErrs[0]
		f.ensureErrs = f.ensureErrs[1:]
		if err != nil {
			return nil, err
		}
	}
	return &datasphere.Bucket{Ref: datasphere.BucketRef{Name: spec.Name, Location: spec.Location, Instance: spec.Instance}}, nil
}

func (f *fakeProvider) DeleteBucket(context.Context, datasphere.BucketRef) error { return nil }

func (f *fakeProvider) Put(_ context.Context, _ string, obj datasphere.Object) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[obj.Name] = obj
	return nil
}

func (f *fakeProvider) Get(_ context.Context, _, name string) (*datasphere.Object, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj, ok := f.objects[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", datasphere.ErrObjectNotFound, name)
	}
	return &obj, nil
}

func (f *fakeProvider) List(_ context.Context, _, prefix string) ([]datasphere.ObjectInfo, error) {
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

func (f *fakeProvider) Delete(_ context.Context, _, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.objects, name)
	return nil
}

func (f *fakeProvider) PutStream(ctx context.Context, bucket string, obj datasphere.StreamObject) error {
	data, err := io.ReadAll(obj.Data)
	if err != nil {
		return err
	}
	return f.Put(ctx, bucket, datasphere.Object{Name: obj.Name, Data: data, Meta: obj.Meta})
}

func (f *fakeProvider) GetStream(ctx context.Context, bucket, name string, offset, length int64) (io.ReadCloser, error) {
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
	return io.NopCloser(strings.NewReader(string(data))), nil
}

// registerFake registers f under a name unique to this test and returns the
// COMPUTE provider name an instance should record to reach it.
//
// The compute-to-storage table is extended rather than overwritten: pointing
// the shipped "gke" entry at a fake would let one test's plumbing leak into
// another's, and the table's contents are themselves part of what the ensure
// path reads.
func registerFake(t *testing.T, f *fakeProvider) string {
	t.Helper()
	suffix := strings.ReplaceAll(t.Name(), "/", "-")
	storageName := "ds-fake-" + suffix
	computeName := "compute-fake-" + suffix
	datasphere.Register(storageName, func(datasphere.Config) (datasphere.Provider, error) { return f, nil })
	storageProviders[computeName] = storageName
	t.Cleanup(func() { delete(storageProviders, computeName) })
	return computeName
}

// recordInstance writes an installed instance to local state, as install would.
func recordInstance(t *testing.T, dir config.Dir, name, provider string, store *config.Storage) {
	t.Helper()
	if err := dir.CreateInstance(name); err != nil {
		t.Fatalf("CreateInstance: %v", err)
	}
	meta := &config.InstanceMetadata{
		Name:     name,
		Provider: provider,
		Project:  "proj-1",
		Region:   "us-central1",
		Cluster:  "farcast-" + name,
		Status:   config.InstanceRunning,
		Storage:  store,
	}
	if err := dir.SaveInstanceMetadata(name, meta); err != nil {
		t.Fatalf("SaveInstanceMetadata: %v", err)
	}
	if err := dir.SaveInstanceCredentials(name, &config.InstanceCredentials{Provider: provider}); err != nil {
		t.Fatalf("SaveInstanceCredentials: %v", err)
	}
}

// newTestDir returns a config dir inside a fresh temp dir (not the 0755 temp
// dir itself, so Ensure creates it 0700).
func newTestDir(t *testing.T) config.Dir {
	t.Helper()
	return config.Dir(filepath.Join(t.TempDir(), "cfg"))
}

// ensuredBucket is the storage block of an already-created bucket.
func ensuredBucket(name, provider string) *config.Storage {
	return &config.Storage{
		Bucket:     name,
		Location:   "us-central1",
		Provider:   provider,
		RecordedAt: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
		CreatedAt:  time.Date(2026, 8, 1, 0, 0, 1, 0, time.UTC),
	}
}

func loadStorage(t *testing.T, dir config.Dir, name string) *config.Storage {
	t.Helper()
	meta, err := dir.LoadInstanceMetadata(name)
	if err != nil {
		t.Fatalf("LoadInstanceMetadata: %v", err)
	}
	return meta.Storage
}

// ---------------------------------------------------------------- record before create

// The bucket's name carries 32 bits of randomness that exist nowhere else once
// minted, and the name is deliberately not re-derivable from the instance. A
// bucket created before its name is recorded is therefore billable storage
// nobody is watching, under a name nobody can reconstruct — the exact failure
// the ordering exists to make impossible.
func TestEnsureRecordsTheBucketNameBeforeCreatingIt(t *testing.T) {
	dir := newTestDir(t)
	f := newFakeProvider(dir, "prod")
	provider := registerFake(t, f)
	recordInstance(t, dir, "prod", provider, nil)

	session, err := Open(context.Background(), Options{Dir: dir, Instance: "prod", Mint: true})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(f.ensured) != 1 {
		t.Fatalf("EnsureBucket called %d times, want 1", len(f.ensured))
	}
	recorded := f.recorded[0]
	if recorded == nil {
		t.Fatal("metadata.yaml held no storage block when EnsureBucket was called; the name would be unrecoverable if the create had succeeded and the CLI died")
	}
	if recorded.Bucket != f.ensured[0].Name {
		t.Errorf("recorded bucket %q != the bucket being created %q", recorded.Bucket, f.ensured[0].Name)
	}
	if recorded.RecordedAt.IsZero() {
		t.Error("recorded_at must be stamped when the name is minted")
	}
	// Recorded as an intent only: created_at is what later forbids re-minting.
	if !recorded.CreatedAt.IsZero() {
		t.Errorf("created_at = %v at create time, want zero — the bucket did not exist yet", recorded.CreatedAt)
	}
	if recorded.Provider != "ds-fake-"+t.Name() {
		t.Errorf("recorded storage provider = %q, want the storage provider the ensure used", recorded.Provider)
	}

	after := loadStorage(t, dir, "prod")
	if after.CreatedAt.IsZero() {
		t.Error("created_at must be stamped once the bucket exists")
	}
	if after.Bucket != session.Bucket || session.Bucket != f.ensured[0].Name {
		t.Errorf("record %q, session %q, created %q — all three must agree", after.Bucket, session.Bucket, f.ensured[0].Name)
	}
	if !session.BucketCreated {
		t.Error("BucketCreated must be reported so the caller can say so exactly once")
	}
}

// A create that fails must leave the record behind, because the record is the
// only way back to the name.
func TestEnsureKeepsTheRecordWhenTheCreateFails(t *testing.T) {
	dir := newTestDir(t)
	f := newFakeProvider(dir, "prod")
	f.ensureErrs = []error{errors.New("503 backend error")}
	provider := registerFake(t, f)
	recordInstance(t, dir, "prod", provider, nil)

	_, err := Open(context.Background(), Options{Dir: dir, Instance: "prod", Mint: true})
	if err == nil {
		t.Fatal("Open should fail when the create fails")
	}
	recorded := loadStorage(t, dir, "prod")
	if recorded == nil || recorded.Bucket != f.ensured[0].Name {
		t.Fatalf("record = %+v, want the name the failed create used", recorded)
	}
	if !recorded.CreatedAt.IsZero() {
		t.Error("created_at must stay empty when the create failed")
	}
}

// ---------------------------------------------------------------- ErrNotOwned, name not yet used

// While created_at is empty the recorded name is only an intent, so a
// collision in the cloud's global namespace is resolved by minting another —
// bounded, so three collisions in 32 bits of entropy stop and let a human look
// rather than spinning.
func TestEnsureMintsANewNameOnErrNotOwnedBeforeTheBucketExists(t *testing.T) {
	dir := newTestDir(t)
	f := newFakeProvider(dir, "prod")
	f.ensureErrs = []error{
		fmt.Errorf("%w: bucket is not ours", datasphere.ErrNotOwned),
		fmt.Errorf("%w: bucket is not ours", datasphere.ErrNotOwned),
		nil,
	}
	provider := registerFake(t, f)
	recordInstance(t, dir, "prod", provider, nil)

	session, err := Open(context.Background(), Options{Dir: dir, Instance: "prod", Mint: true})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(f.ensured) != 3 {
		t.Fatalf("EnsureBucket called %d times, want 3 (two refusals, then the one that took)", len(f.ensured))
	}
	names := map[string]bool{}
	for i, spec := range f.ensured {
		if names[spec.Name] {
			t.Errorf("attempt %d reused the refused name %q instead of minting", i+1, spec.Name)
		}
		names[spec.Name] = true
		// Every attempt must be recorded before it is tried, not just the first.
		if f.recorded[i] == nil || f.recorded[i].Bucket != spec.Name {
			t.Errorf("attempt %d: record = %+v, want %q recorded first", i+1, f.recorded[i], spec.Name)
		}
	}

	winner := f.ensured[2].Name
	recorded := loadStorage(t, dir, "prod")
	if recorded.Bucket != winner {
		t.Errorf("record names %q, want the bucket that actually succeeded (%q)", recorded.Bucket, winner)
	}
	if session.Bucket != winner {
		t.Errorf("session bucket = %q, want %q", session.Bucket, winner)
	}
	if recorded.CreatedAt.IsZero() {
		t.Error("created_at must be stamped for the bucket that succeeded")
	}
}

func TestEnsureBoundsTheMintRetryLoop(t *testing.T) {
	dir := newTestDir(t)
	f := newFakeProvider(dir, "prod")
	notOwned := fmt.Errorf("%w: bucket is not ours", datasphere.ErrNotOwned)
	f.ensureErrs = []error{notOwned, notOwned, notOwned, notOwned, notOwned}
	provider := registerFake(t, f)
	recordInstance(t, dir, "prod", provider, nil)

	_, err := Open(context.Background(), Options{Dir: dir, Instance: "prod", Mint: true})
	if err == nil {
		t.Fatal("Open should fail once the attempts are exhausted")
	}
	if !errors.Is(err, datasphere.ErrNotOwned) {
		t.Errorf("err = %v, want it to carry ErrNotOwned", err)
	}
	if !strings.Contains(err.Error(), "3 attempts") {
		t.Errorf("err = %v, want it to say how many attempts were made", err)
	}
	if len(f.ensured) != maxMintAttempts {
		t.Errorf("EnsureBucket called %d times, want the bound of %d", len(f.ensured), maxMintAttempts)
	}
}

// ---------------------------------------------------------------- ErrNotOwned, the bucket has held data

// The case this whole branch exists for.
//
// Once created_at is set the bucket was ensured successfully at least once, so
// ErrNotOwned no longer means "someone else got that name first" — it means
// something changed under a name that has held the operator's data. Minting a
// replacement here would silently abandon that data in a bucket nothing points
// at any more: still billing, still readable to whoever now owns it, and
// unfindable from local state because the name's random suffix existed only in
// the record that was just overwritten. Stopping is the only safe answer.
func TestEnsureRefusesToMintPastErrNotOwnedOnceTheBucketHasHeldData(t *testing.T) {
	dir := newTestDir(t)
	f := newFakeProvider(dir, "prod")
	f.ensureErrs = []error{fmt.Errorf("%w: labels name another instance", datasphere.ErrNotOwned)}
	provider := registerFake(t, f)
	recorded := ensuredBucket("farcast-prod-0badc0de", "")
	recordInstance(t, dir, "prod", provider, recorded)

	_, err := Open(context.Background(), Options{Dir: dir, Instance: "prod", Mint: true})
	if err == nil {
		t.Fatal("Open must fail rather than mint a replacement bucket")
	}
	if !errors.Is(err, datasphere.ErrNotOwned) {
		t.Errorf("err = %v, want it to carry ErrNotOwned", err)
	}
	if !strings.Contains(err.Error(), "farcast-prod-0badc0de") {
		t.Errorf("err = %v, must name the bucket the operator has to go and look at", err)
	}
	if !strings.Contains(err.Error(), "Inspect it") {
		t.Errorf("err = %v, must tell the operator to inspect the bucket before anything else", err)
	}

	if len(f.ensured) != 1 {
		t.Fatalf("EnsureBucket called %d times, want exactly 1 — a second call means a name was minted past the refusal", len(f.ensured))
	}
	after := loadStorage(t, dir, "prod")
	if after.Bucket != "farcast-prod-0badc0de" {
		t.Errorf("recorded bucket = %q, want it untouched; rewriting it loses the only pointer to the data", after.Bucket)
	}
	if !after.CreatedAt.Equal(recorded.CreatedAt) {
		t.Errorf("created_at = %v, want it untouched (%v)", after.CreatedAt, recorded.CreatedAt)
	}
}

// ---------------------------------------------------------------- convergence

// Any failure that is not a proven ownership refusal keeps the record, so the
// next run ensures the SAME name rather than minting a second billable bucket.
func TestEnsureConvergesAfterAPlainFailure(t *testing.T) {
	dir := newTestDir(t)
	f := newFakeProvider(dir, "prod")
	f.ensureErrs = []error{errors.New("429 rate limited")}
	provider := registerFake(t, f)
	recordInstance(t, dir, "prod", provider, nil)

	if _, err := Open(context.Background(), Options{Dir: dir, Instance: "prod", Mint: true}); err == nil {
		t.Fatal("the first Open should fail")
	}
	first := loadStorage(t, dir, "prod")
	if first == nil || first.Bucket == "" {
		t.Fatal("the record must survive a plain failure")
	}

	// Re-run: the fake's error list is spent, so the same name now takes.
	session, err := Open(context.Background(), Options{Dir: dir, Instance: "prod", Mint: true})
	if err != nil {
		t.Fatalf("re-run: %v", err)
	}
	if len(f.ensured) != 2 {
		t.Fatalf("EnsureBucket called %d times over two runs, want 2", len(f.ensured))
	}
	if f.ensured[1].Name != first.Bucket {
		t.Errorf("re-run ensured %q, want the recorded name %q — a new name is a second billable bucket", f.ensured[1].Name, first.Bucket)
	}
	if session.Bucket != first.Bucket {
		t.Errorf("session bucket = %q, want %q", session.Bucket, first.Bucket)
	}
	if loadStorage(t, dir, "prod").CreatedAt.IsZero() {
		t.Error("created_at must be stamped once the re-run succeeds")
	}
}

// The recorded bucket is proved to be this instance's before any Store exists
// to write through it, so tampered local metadata cannot point writes at a
// stranger's bucket.
func TestOpenValidatesTheRecordedBucketBeforeBuildingAStore(t *testing.T) {
	dir := newTestDir(t)
	f := newFakeProvider(dir, "prod")
	f.validateErr = fmt.Errorf("%w: bucket belongs to someone else", datasphere.ErrNotOwned)
	provider := registerFake(t, f)
	recordInstance(t, dir, "prod", provider, ensuredBucket("farcast-prod-0badc0de", ""))

	session, err := Open(context.Background(), Options{Dir: dir, Instance: "prod", Mint: true})
	if err == nil {
		t.Fatalf("Open must fail when the recorded bucket does not validate; got %+v", session)
	}
	if !strings.Contains(err.Error(), "did not validate") {
		t.Errorf("err = %v, want a validation failure", err)
	}
	if len(f.validated) != 1 || f.validated[0].Instance != "prod" {
		t.Errorf("validated = %+v, want one check carrying the instance from the local record", f.validated)
	}
	// The keyring is created after validation, so a refused bucket leaves none.
	if exists, _ := dir.InstanceKeyringExists("prod"); exists {
		t.Error("no keyring should be minted for a bucket that did not validate")
	}
}

// ---------------------------------------------------------------- what Mint gates

// A read-only command must not be able to provision anything: a mistyped
// instance name is a typo, not a request for a bucket and a keyring.
func TestOpenWithoutMintCreatesNothing(t *testing.T) {
	t.Run("no bucket", func(t *testing.T) {
		dir := newTestDir(t)
		f := newFakeProvider(dir, "prod")
		provider := registerFake(t, f)
		recordInstance(t, dir, "prod", provider, nil)

		_, err := Open(context.Background(), Options{Dir: dir, Instance: "prod"})
		if err == nil || !strings.Contains(err.Error(), "no storage yet") {
			t.Fatalf("err = %v, want a refusal naming the missing storage", err)
		}
		if len(f.ensured) != 0 {
			t.Errorf("EnsureBucket called %d times, want 0", len(f.ensured))
		}
		if loadStorage(t, dir, "prod") != nil {
			t.Error("no bucket name should be minted or recorded without Mint")
		}
		if exists, _ := dir.InstanceKeyringExists("prod"); exists {
			t.Error("no keyring should be minted without Mint")
		}
	})

	t.Run("no keyring", func(t *testing.T) {
		dir := newTestDir(t)
		f := newFakeProvider(dir, "prod")
		provider := registerFake(t, f)
		recordInstance(t, dir, "prod", provider, ensuredBucket("farcast-prod-0badc0de", ""))

		_, err := Open(context.Background(), Options{Dir: dir, Instance: "prod"})
		if err == nil || !strings.Contains(err.Error(), "no storage keyring yet") {
			t.Fatalf("err = %v, want a refusal naming the missing keyring", err)
		}
		if exists, _ := dir.InstanceKeyringExists("prod"); exists {
			t.Error("the keyring must not be created by a command that only reads")
		}
		// An already-created bucket is used, not re-ensured: a write call per
		// command would spend money to learn nothing.
		if len(f.ensured) != 0 {
			t.Errorf("EnsureBucket called %d times for an already-created bucket, want 0", len(f.ensured))
		}
	})
}

// WithoutKeyring is what release's teardown gate and a totals-only usage
// report use. It is not a convenience: an operator who has lost keys.yaml can
// no longer read a byte of their data but can still be billed for it, and must
// still be able to see that and stop it.
func TestOpenWithoutKeyringGivesAProviderAndNoStore(t *testing.T) {
	dir := newTestDir(t)
	f := newFakeProvider(dir, "prod")
	provider := registerFake(t, f)
	recordInstance(t, dir, "prod", provider, ensuredBucket("farcast-prod-0badc0de", ""))

	session, err := Open(context.Background(), Options{Dir: dir, Instance: "prod", WithoutKeyring: true})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if session.Provider == nil {
		t.Error("a keyringless session must still carry the provider — that is what counts the bytes being billed")
	}
	if session.Store != nil {
		t.Error("no Store may exist without a keyring; a Store is the only path to plaintext")
	}
	if session.Bucket != "farcast-prod-0badc0de" {
		t.Errorf("bucket = %q, want the recorded one", session.Bucket)
	}
	if exists, _ := dir.InstanceKeyringExists("prod"); exists {
		t.Error("WithoutKeyring must not mint a keyring")
	}
	if session.KeyringMinted {
		t.Error("KeyringMinted must be false")
	}
}

// ---------------------------------------------------------------- the keyring

// keys.yaml is the file whose loss is the permanent loss of everything the
// bucket holds, so its modes are not housekeeping and overwriting it is the
// key-loss catastrophe in one command.
func TestOpenMintsTheKeyringUnderStrictPermissions(t *testing.T) {
	dir := newTestDir(t)
	f := newFakeProvider(dir, "prod")
	provider := registerFake(t, f)
	recordInstance(t, dir, "prod", provider, nil)

	session, err := Open(context.Background(), Options{Dir: dir, Instance: "prod", Mint: true})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !session.KeyringMinted {
		t.Error("KeyringMinted must be reported so the caller can print the key-loss warning exactly once")
	}
	if session.Store == nil {
		t.Fatal("a minted keyring must yield a Store")
	}

	path := dir.InstanceKeyringPath("prod")
	assertPerm(t, filepath.Dir(path), 0o700)
	assertPerm(t, path, 0o600)

	// The refusal is the point: this file is never overwritten, only merged.
	err = dir.CreateInstanceKeyring("prod", []byte("version: 1\n"))
	if err == nil {
		t.Fatal("CreateInstanceKeyring must refuse to overwrite an existing keyring")
	}
	if !errors.Is(err, fs.ErrExist) {
		t.Errorf("err = %v, want an already-exists refusal", err)
	}
	before, err := dir.LoadInstanceKeyring("prod")
	if err != nil {
		t.Fatalf("LoadInstanceKeyring: %v", err)
	}
	if _, err := datasphere.ParseKeyring(before); err != nil {
		t.Errorf("the refused write must leave the keyring intact: %v", err)
	}

	// A second Open loads what is there rather than minting again.
	again, err := Open(context.Background(), Options{Dir: dir, Instance: "prod", Mint: true})
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	if again.KeyringMinted {
		t.Error("the second Open must load the keyring, not mint one")
	}
	after, err := dir.LoadInstanceKeyring("prod")
	if err != nil {
		t.Fatalf("LoadInstanceKeyring: %v", err)
	}
	if string(before) != string(after) {
		t.Error("an Open that loads an existing keyring must not rewrite it")
	}
}

func assertPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s perm = %#o, want %#o", path, got, want)
	}
}
