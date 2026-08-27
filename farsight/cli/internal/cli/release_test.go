package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sofmon/farcast/datasphere"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/planck"
)

// recordInstance writes a running instance to local state, as install would.
func recordInstance(t *testing.T, dir config.Dir, name, provider string) {
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
		Registry: &config.Registry{
			Prefix:     "us-central1-docker.pkg.dev/proj-1/farcast-" + name,
			Repository: "farcast-" + name,
			Location:   "us-central1",
		},
	}
	if err := dir.SaveInstanceMetadata(name, meta); err != nil {
		t.Fatalf("SaveInstanceMetadata: %v", err)
	}
	if err := dir.SaveInstanceCredentials(name, &config.InstanceCredentials{Provider: provider}); err != nil {
		t.Fatalf("SaveInstanceCredentials: %v", err)
	}
}

// fakeStorage is an in-memory datasphere.Provider, registered so release's
// storage gate and teardown run their real paths — datasphere.BucketUsage over
// List, and DeleteBucket — without a cloud.
//
// It is a whole store rather than a pair of stubs because the gate's claim is
// about what the PROVIDER holds, not about what a Store could name: counting
// has to work over the same listing an operator with no keyring would get.
type fakeStorage struct {
	// The Provider contract permits concurrent calls, so the fake honours it
	// rather than modelling a provider that does not.
	mu      sync.Mutex
	objects map[string]datasphere.Object

	// instance is the bucket's owner. Validate refuses any other, exactly as
	// the GCS adapter does, so the ownership check release resolves through is
	// exercised rather than simulated.
	instance string

	// absent makes Validate report the bucket as PROVEN gone, the way the
	// adapter reports a 404.
	absent bool

	// deleteErr is what DeleteBucket returns: either a plain failure (the
	// bucket may still exist, so nothing is cleared) or the ErrRetentionForced
	// sentinel, which accompanies a delete that DID succeed.
	deleteErr error
	listErr   error

	ensures    int
	deletes    int
	deletedRef datasphere.BucketRef

	// journal, when set, records this fake's destructive call alongside the
	// compute provider's, so their ORDER can be asserted.
	journal *teardownJournal
}

func newFakeStorage(instance string) *fakeStorage {
	return &fakeStorage{objects: map[string]datasphere.Object{}, instance: instance}
}

func (*fakeStorage) Name() string { return "fake-storage" }

func (f *fakeStorage) Validate(_ context.Context, ref datasphere.BucketRef) error {
	if ref.Name == "" {
		return nil
	}
	if f.absent {
		// Proven absent, as the real adapter reports a 404 — distinct from an
		// inspection that merely failed.
		return fmt.Errorf("%w: %s", datasphere.ErrBucketNotFound, ref.Name)
	}
	if ref.Instance != f.instance {
		return fmt.Errorf("%w: bucket %q belongs to %q", datasphere.ErrNotOwned, ref.Name, f.instance)
	}
	return nil
}

func (f *fakeStorage) EnsureBucket(_ context.Context, spec datasphere.BucketSpec) (*datasphere.Bucket, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensures++
	return &datasphere.Bucket{Ref: datasphere.BucketRef{Name: spec.Name, Location: spec.Location, Instance: spec.Instance}}, nil
}

func (f *fakeStorage) DeleteBucket(_ context.Context, ref datasphere.BucketRef) error {
	f.journal.record("bucket")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes++
	f.deletedRef = ref
	if f.deleteErr != nil && !errors.Is(f.deleteErr, datasphere.ErrRetentionForced) {
		return f.deleteErr
	}
	// Forced retention rides on a delete that genuinely emptied the bucket.
	f.objects = map[string]datasphere.Object{}
	return f.deleteErr
}

func (f *fakeStorage) Put(_ context.Context, _ string, obj datasphere.Object) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[obj.Name] = obj
	return nil
}

func (f *fakeStorage) Get(_ context.Context, _, name string) (*datasphere.Object, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj, ok := f.objects[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", datasphere.ErrObjectNotFound, name)
	}
	return &obj, nil
}

func (f *fakeStorage) List(_ context.Context, _, prefix string) ([]datasphere.ObjectInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []datasphere.ObjectInfo
	for name, obj := range f.objects {
		if strings.HasPrefix(name, prefix) {
			out = append(out, datasphere.ObjectInfo{Name: name, Size: int64(len(obj.Data)), Meta: obj.Meta})
		}
	}
	return out, nil
}

func (f *fakeStorage) Delete(_ context.Context, _, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.objects, name)
	return nil
}

func (f *fakeStorage) PutStream(ctx context.Context, bucket string, obj datasphere.StreamObject) error {
	data, err := io.ReadAll(obj.Data)
	if err != nil {
		return err
	}
	return f.Put(ctx, bucket, datasphere.Object{Name: obj.Name, Data: data, Meta: obj.Meta})
}

func (f *fakeStorage) GetStream(ctx context.Context, bucket, name string, offset, length int64) (io.ReadCloser, error) {
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

// count reports how many objects the bucket still physically holds.
func (f *fakeStorage) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.objects)
}

// teardownJournal records the destructive calls a release makes, in the order
// it makes them.
//
// The gate's promise about data is an ORDERING one — the bucket goes last, so a
// failure anywhere earlier leaves the data intact and the record in place — and
// an ordering claim cannot be checked by call counts.
type teardownJournal struct {
	mu    sync.Mutex
	steps []string
}

// record tolerates a nil journal so a fake can always call it.
func (j *teardownJournal) record(step string) {
	if j == nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.steps = append(j.steps, step)
}

func (j *teardownJournal) String() string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return strings.Join(j.steps, " → ")
}

// journalingProvider is the fake compute provider with its destructive calls
// journalled. It embeds the concrete fake rather than the planck.Provider
// interface, so the registry capability stays promoted and release still finds
// a RegistryProvider to delete through.
type journalingProvider struct {
	*fakeProvider
	journal *teardownJournal
}

func (p journalingProvider) DeleteCluster(ctx context.Context, ref planck.ClusterRef) error {
	p.journal.record("cluster")
	return p.fakeProvider.DeleteCluster(ctx, ref)
}

func (p journalingProvider) DeleteRegistry(ctx context.Context, ref planck.RegistryRef) error {
	p.journal.record("registry")
	return p.fakeProvider.DeleteRegistry(ctx, ref)
}

// registerStorage makes f the storage provider an instance resolves to. The
// name is unique per test and instance because datasphere.Register panics on a
// duplicate and the registry has no removal.
func registerStorage(t *testing.T, instance string, f *fakeStorage) string {
	t.Helper()
	name := "fake-storage-" + strings.ReplaceAll(t.Name(), "/", "-") + "-" + instance
	datasphere.Register(name, func(datasphere.Config) (datasphere.Provider, error) { return f, nil })
	return name
}

// giveStorage records a created bucket for an instance and registers an
// in-memory provider holding one object per size — the state a storage command
// that had written would have left behind.
//
// created_at is set because the bucket exists: while it is empty the recorded
// name is only an intent and Open would re-ensure it, and a release must bring
// nothing into existence.
func giveStorage(t *testing.T, dir config.Dir, name string, sizes ...int) *fakeStorage {
	t.Helper()
	f := newFakeStorage(name)
	for i, size := range sizes {
		key := fmt.Sprintf("obj-%d", i)
		f.objects[key] = datasphere.Object{Name: key, Data: make([]byte, size)}
	}
	meta, err := dir.LoadInstanceMetadata(name)
	if err != nil {
		t.Fatalf("LoadInstanceMetadata: %v", err)
	}
	meta.Storage = &config.Storage{
		Bucket:     "farcast-" + name + "-0badc0de",
		Location:   meta.Region,
		Provider:   registerStorage(t, name, f),
		RecordedAt: time.Now().UTC().Truncate(time.Second),
		CreatedAt:  time.Now().UTC().Truncate(time.Second),
	}
	if err := dir.SaveInstanceMetadata(name, meta); err != nil {
		t.Fatalf("SaveInstanceMetadata: %v", err)
	}
	return f
}

// giveKeyring writes an instance keyring, as first storage use would.
func giveKeyring(t *testing.T, dir config.Dir, name string) {
	t.Helper()
	if err := dir.CreateInstanceKeyring(name, []byte("keys: []\n")); err != nil {
		t.Fatalf("CreateInstanceKeyring: %v", err)
	}
}

func TestReleaseSuccess(t *testing.T) {
	f := &fakeProvider{}
	prov := registerFake(t, f)
	env, out, _, dir := newInstallEnv(t, output.ModeHuman)
	recordInstance(t, dir, "prod", prov)

	cmd := &releaseCommand{assumeYes: true}
	if err := cmd.Run(context.Background(), env, []string{"prod"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if f.deleteCalls != 1 {
		t.Errorf("DeleteCluster called %d times, want 1", f.deleteCalls)
	}
	if exists, _ := dir.InstanceExists("prod"); exists {
		t.Error("local state should be removed after a successful release")
	}
	if !strings.Contains(out.String(), "released") {
		t.Errorf("result missing 'released':\n%s", out.String())
	}
}

func TestReleaseDeletesTheInstanceRegistry(t *testing.T) {
	f := &fakeProvider{}
	prov := registerFake(t, f)
	env, out, _, dir := newInstallEnv(t, output.ModeHuman)
	recordInstance(t, dir, "prod", prov)

	cmd := &releaseCommand{assumeYes: true}
	if err := cmd.Run(context.Background(), env, []string{"prod"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(f.regDeleted) != 1 {
		t.Fatalf("DeleteRegistry called %d times, want 1", len(f.regDeleted))
	}
	if got := f.regDeleted[0]; got.Name != "farcast-prod" || got.Location != "us-central1" {
		t.Errorf("deleted registry ref = %+v, want the recorded repository", got)
	}
	if exists, _ := dir.InstanceExists("prod"); exists {
		t.Error("local state should be removed after a successful release")
	}
	if !strings.Contains(out.String(), "registry:") || !strings.Contains(out.String(), "farcast-prod (deleted)") {
		t.Errorf("result missing the deleted registry:\n%s", out.String())
	}
}

func TestReleaseRegistryFailureKeepsState(t *testing.T) {
	f := &fakeProvider{regDeleteErr: errors.New("api error")}
	prov := registerFake(t, f)
	env, _, _, dir := newInstallEnv(t, output.ModeHuman)
	recordInstance(t, dir, "stuck", prov)

	cmd := &releaseCommand{assumeYes: true}
	err := cmd.Run(context.Background(), env, []string{"stuck"})
	if err == nil || !strings.Contains(err.Error(), "re-run") {
		t.Fatalf("err = %v, want a registry failure with a retry hint", err)
	}
	if !strings.Contains(err.Error(), "farcast-stuck") {
		t.Errorf("err = %v, should name the registry it could not destroy", err)
	}
	// The cluster went first and the record is kept, so a re-run converges
	// (both deletes are idempotent).
	if f.deleteCalls != 1 {
		t.Errorf("DeleteCluster called %d times, want 1", f.deleteCalls)
	}
	if exists, _ := dir.InstanceExists("stuck"); !exists {
		t.Fatal("local state must be kept when a cloud delete fails")
	}
	meta, lerr := dir.LoadInstanceMetadata("stuck")
	if lerr != nil {
		t.Fatalf("state should be readable after a failed delete: %v", lerr)
	}
	if meta.Status != config.InstanceDeleting {
		t.Errorf("status = %q, want deleting", meta.Status)
	}
}

func TestReleaseWithoutRegistryCapability(t *testing.T) {
	f := &fakeProvider{}
	prov := registerProvider(t, clusterOnlyProvider{f})
	env, out, _, dir := newInstallEnv(t, output.ModeHuman)
	recordInstance(t, dir, "prod", prov)

	cmd := &releaseCommand{assumeYes: true}
	if err := cmd.Run(context.Background(), env, []string{"prod"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(f.regDeleted) != 0 {
		t.Error("a provider without the capability must not be asked to delete a registry")
	}
	if exists, _ := dir.InstanceExists("prod"); exists {
		t.Error("local state should still be removed")
	}
	if strings.Contains(out.String(), "registry:") {
		t.Errorf("nothing to report when there is no registry:\n%s", out.String())
	}
}

func TestReleaseSummaryNamesTheRegistry(t *testing.T) {
	meta := &config.InstanceMetadata{
		Name:     "prod",
		Cluster:  "farcast-prod",
		Registry: &config.Registry{Repository: "farcast-prod"},
	}
	var buf strings.Builder
	printReleaseSummary(&buf, meta)
	if !strings.Contains(buf.String(), "registry:  farcast-prod") {
		t.Errorf("the destruction summary must name the registry:\n%s", buf.String())
	}

	// An instance whose record predates the registry promises nothing.
	buf.Reset()
	printReleaseSummary(&buf, &config.InstanceMetadata{Name: "old", Cluster: "farcast-old"})
	if strings.Contains(buf.String(), "registry:") {
		t.Errorf("no registry line without a recorded registry:\n%s", buf.String())
	}
}

func TestReleaseUnknownInstance(t *testing.T) {
	env, _, _, _ := newInstallEnv(t, output.ModeHuman)
	cmd := &releaseCommand{assumeYes: true}
	err := cmd.Run(context.Background(), env, []string{"ghost"})
	if err == nil || !strings.Contains(err.Error(), "no such instance") {
		t.Fatalf("err = %v, want no-such-instance", err)
	}
}

func TestReleaseRequiresInstanceName(t *testing.T) {
	env, _, _, _ := newInstallEnv(t, output.ModeHuman)
	cmd := &releaseCommand{assumeYes: true}
	err := cmd.Run(context.Background(), env, nil)
	if _, ok := errors.AsType[*usageError](err); !ok {
		t.Fatalf("err = %v, want usageError for missing instance name", err)
	}
}

func TestReleaseDeleteFailureKeepsState(t *testing.T) {
	f := &fakeProvider{deleteErr: errors.New("api error")}
	prov := registerFake(t, f)
	env, _, _, dir := newInstallEnv(t, output.ModeHuman)
	recordInstance(t, dir, "stuck", prov)

	cmd := &releaseCommand{assumeYes: true}
	err := cmd.Run(context.Background(), env, []string{"stuck"})
	if err == nil || !strings.Contains(err.Error(), "re-run") {
		t.Fatalf("err = %v, want delete failure with a retry hint", err)
	}
	// The local record is kept (so the operator can re-run) and marked deleting.
	meta, lerr := dir.LoadInstanceMetadata("stuck")
	if lerr != nil {
		t.Fatalf("state should be kept after a failed delete: %v", lerr)
	}
	if meta.Status != config.InstanceDeleting {
		t.Errorf("status = %q, want deleting", meta.Status)
	}
}

func TestReleaseTwiceIsSafe(t *testing.T) {
	f := &fakeProvider{}
	prov := registerFake(t, f)
	env, _, _, dir := newInstallEnv(t, output.ModeHuman)
	recordInstance(t, dir, "x", prov)

	cmd := &releaseCommand{assumeYes: true}
	if err := cmd.Run(context.Background(), env, []string{"x"}); err != nil {
		t.Fatalf("first release: %v", err)
	}
	// The instance is gone; a second release is a graceful no-such-instance.
	err := cmd.Run(context.Background(), env, []string{"x"})
	if err == nil || !strings.Contains(err.Error(), "no such instance") {
		t.Fatalf("second release err = %v, want no-such-instance", err)
	}
}

func TestReleaseNonInteractiveRequiresYes(t *testing.T) {
	f := &fakeProvider{}
	prov := registerFake(t, f)
	env, _, _, dir := newInstallEnv(t, output.ModeHuman)
	recordInstance(t, dir, "x", prov)

	cmd := &releaseCommand{assumeYes: false} // env.In is a non-TTY buffer
	err := cmd.Run(context.Background(), env, []string{"x"})
	if _, ok := errors.AsType[*usageError](err); !ok {
		t.Fatalf("err = %v, want usageError (needs --yes)", err)
	}
	if f.deleteCalls != 0 {
		t.Error("DeleteCluster must not run without confirmation")
	}
	if exists, _ := dir.InstanceExists("x"); !exists {
		t.Error("local state should be kept when confirmation is refused")
	}
}

func TestReleaseConfirmRetypeName(t *testing.T) {
	meta := &config.InstanceMetadata{Name: "prod"}
	cmd := &releaseCommand{}

	ok, err := cmd.confirm(true, newPrompter(strings.NewReader("prod\n"), io.Discard), io.Discard, meta, datasphere.Usage{})
	if err != nil || !ok {
		t.Fatalf("confirm(correct name) = %v,%v; want true,nil", ok, err)
	}
	ok, err = cmd.confirm(true, newPrompter(strings.NewReader("nope\n"), io.Discard), io.Discard, meta, datasphere.Usage{})
	if err != nil || ok {
		t.Fatalf("confirm(wrong name) = %v,%v; want false,nil", ok, err)
	}
}

func TestReleaseJSONOutput(t *testing.T) {
	f := &fakeProvider{}
	prov := registerFake(t, f)
	env, out, _, dir := newInstallEnv(t, output.ModeJSON)
	recordInstance(t, dir, "p", prov)

	cmd := &releaseCommand{assumeYes: true}
	if err := cmd.Run(context.Background(), env, []string{"p"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out.String())
	}
	if m["cluster"] != "farcast-p" || m["status"] != "released" {
		t.Errorf("unexpected JSON result: %v", m)
	}
}

// ---------------------------------------------------------------------------
// Phase 3.3: release refuses while the instance bucket still holds data.
//
// The gate is DATA-triggered, not configuration-triggered, and --delete-data is
// a SCOPE flag rather than a consent flag. Both properties are load-bearing, so
// both are asserted from the outside: what the operator has to type, and what
// was destroyed by the time the command returned.
// ---------------------------------------------------------------------------

// TestReleaseWithAnEmptyBucketIsUngated is the case that keeps the gate from
// being a chore: an instance that installed, connected and released without
// ever writing behaves exactly as it did before 3.3 — no flag, no extra prompt,
// no warning — and its (free, empty) bucket still goes with it.
func TestReleaseWithAnEmptyBucketIsUngated(t *testing.T) {
	f := &fakeProvider{}
	prov := registerFake(t, f)
	env, out, errb, dir := newInstallEnv(t, output.ModeHuman)
	recordInstance(t, dir, "prod", prov)
	ds := giveStorage(t, dir, "prod") // no objects

	cmd := &releaseCommand{assumeYes: true} // no --delete-data
	if err := cmd.Run(context.Background(), env, []string{"prod"}); err != nil {
		t.Fatalf("Run: %v — an empty bucket must not gate a release", err)
	}
	if ds.deletes != 1 {
		t.Errorf("DeleteBucket called %d times, want 1; the bucket goes with the instance either way", ds.deletes)
	}
	if ds.ensures != 0 {
		t.Errorf("EnsureBucket called %d times; a release must bring nothing into existence", ds.ensures)
	}
	if exists, _ := dir.InstanceExists("prod"); exists {
		t.Error("local state should be removed after a successful release")
	}
	if !strings.Contains(out.String(), "it held nothing") {
		t.Errorf("result should say the bucket was empty:\n%s", out.String())
	}
	if strings.Contains(errb.String(), "Warning") {
		t.Errorf("an empty bucket is not worth a warning:\n%s", errb.String())
	}
}

// TestReleaseWithNoStorageRecordIsUnaffected covers the pre-3.3 instance. No
// storage provider is registered for it at all, so if the gate reached for one
// the release would fail — which is the assertion.
func TestReleaseWithNoStorageRecordIsUnaffected(t *testing.T) {
	f := &fakeProvider{}
	prov := registerFake(t, f)
	env, out, errb, dir := newInstallEnv(t, output.ModeHuman)
	recordInstance(t, dir, "old", prov) // no storage: block

	cmd := &releaseCommand{assumeYes: true}
	if err := cmd.Run(context.Background(), env, []string{"old"}); err != nil {
		t.Fatalf("Run: %v — an instance with no storage record must be untouched by the gate", err)
	}
	if f.deleteCalls != 1 || len(f.regDeleted) != 1 {
		t.Errorf("cluster deletes = %d, registry deletes = %d, want 1 and 1", f.deleteCalls, len(f.regDeleted))
	}
	if exists, _ := dir.InstanceExists("old"); exists {
		t.Error("local state should be removed after a successful release")
	}
	if strings.Contains(out.String(), "storage:") {
		t.Errorf("nothing to report when there is no bucket:\n%s", out.String())
	}
	if strings.Contains(errb.String(), "Warning") {
		t.Errorf("no warning is owed for an instance that never stored anything:\n%s", errb.String())
	}
}

// TestReleaseRefusesWhileTheBucketHoldsData is the gate itself. The refusal has
// to name the count, the bytes and the way out — and, more importantly, nothing
// may have been destroyed by the time it is delivered.
func TestReleaseRefusesWhileTheBucketHoldsData(t *testing.T) {
	f := &fakeProvider{}
	journal := &teardownJournal{}
	prov := registerProvider(t, journalingProvider{f, journal})
	env, _, _, dir := newInstallEnv(t, output.ModeHuman)
	recordInstance(t, dir, "prod", prov)
	ds := giveStorage(t, dir, "prod", 1024, 2048, 1024)
	ds.journal = journal

	cmd := &releaseCommand{} // neither --yes nor --delete-data
	err := cmd.Run(context.Background(), env, []string{"prod"})
	if _, ok := errors.AsType[*usageError](err); !ok {
		t.Fatalf("err = %v, want a usageError naming the stored data", err)
	}
	for _, want := range []string{"3 object(s)", "4.0 KiB", "farcast-prod-0badc0de", "farcast storage cp", "--delete-data"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal is missing %q:\n%s", want, err)
		}
	}

	// Nothing was destroyed. The gate runs before the confirmation and before
	// the first cloud call, so an operator who is refused has lost nothing —
	// not even the status field.
	if journal.String() != "" {
		t.Errorf("destructive calls made despite the refusal: %s", journal)
	}
	if f.deleteCalls != 0 || len(f.regDeleted) != 0 || ds.deletes != 0 {
		t.Errorf("cluster=%d registry=%d bucket=%d deletes; want none", f.deleteCalls, len(f.regDeleted), ds.deletes)
	}
	if ds.count() != 3 {
		t.Errorf("bucket holds %d objects, want the 3 it started with", ds.count())
	}
	if exists, _ := dir.InstanceExists("prod"); !exists {
		t.Fatal("local state must be kept when the release is refused")
	}
	meta, lerr := dir.LoadInstanceMetadata("prod")
	if lerr != nil {
		t.Fatalf("state should be readable after a refusal: %v", lerr)
	}
	if meta.Status != config.InstanceRunning {
		t.Errorf("status = %q, want it untouched at running", meta.Status)
	}
	if meta.Storage == nil || meta.Storage.Bucket != "farcast-prod-0badc0de" {
		t.Errorf("the storage record must survive a refusal: %+v", meta.Storage)
	}
}

// TestReleaseCannotReadAnEmptyBucketIntoAFailedCount is the gate failing closed.
// A bucket it could not inspect is not a bucket it found empty, and reading one
// as the other is how a teardown destroys data nobody agreed to lose.
func TestReleaseCannotReadAnEmptyBucketIntoAFailedCount(t *testing.T) {
	f := &fakeProvider{}
	journal := &teardownJournal{}
	prov := registerProvider(t, journalingProvider{f, journal})
	env, _, _, dir := newInstallEnv(t, output.ModeHuman)
	recordInstance(t, dir, "flaky", prov)
	ds := giveStorage(t, dir, "flaky", 1024)
	ds.journal = journal
	ds.listErr = errors.New("googleapi: Error 503: Backend Error")

	err := (&releaseCommand{assumeYes: true, deleteData: true}).Run(context.Background(), env, []string{"flaky"})
	if err == nil {
		t.Fatal("release proceeded on a bucket it could not count")
	}
	if !strings.Contains(err.Error(), "count the stored objects") || !strings.Contains(err.Error(), "re-run") {
		t.Errorf("err = %v, want a counting failure with a retry hint", err)
	}
	if journal.String() != "" {
		t.Errorf("destructive calls made before the count came back: %s", journal)
	}
	if exists, _ := dir.InstanceExists("flaky"); !exists {
		t.Error("local state must be kept — it is what names the bucket on the re-run")
	}
}

// TestReleaseYesNeverImpliesDeleteData is why --delete-data is a scope flag and
// not a consent flag: the confirmation an operator clicks through daily must not
// be able to destroy the one thing that derives from nothing.
func TestReleaseYesNeverImpliesDeleteData(t *testing.T) {
	f := &fakeProvider{}
	prov := registerFake(t, f)
	env, _, _, dir := newInstallEnv(t, output.ModeHuman)
	recordInstance(t, dir, "prod", prov)
	ds := giveStorage(t, dir, "prod", 1024, 2048, 1024)

	cmd := &releaseCommand{assumeYes: true} // --yes alone
	err := cmd.Run(context.Background(), env, []string{"prod"})
	if _, ok := errors.AsType[*usageError](err); !ok {
		t.Fatalf("err = %v, want --yes alone to be refused on a non-empty bucket", err)
	}
	if !strings.Contains(err.Error(), "--delete-data") {
		t.Errorf("the refusal must name the flag that would proceed:\n%s", err)
	}
	if f.deleteCalls != 0 || ds.deletes != 0 {
		t.Errorf("cluster=%d bucket=%d deletes; --yes must destroy nothing here", f.deleteCalls, ds.deletes)
	}
	if exists, _ := dir.InstanceExists("prod"); !exists {
		t.Error("local state must be kept when the release is refused")
	}
}

// TestReleaseDeleteDataDestroysTheBucket is the scoped release, and the order
// it destroys in: cluster, then registry, then the data, then local state.
func TestReleaseDeleteDataDestroysTheBucket(t *testing.T) {
	f := &fakeProvider{}
	journal := &teardownJournal{}
	prov := registerProvider(t, journalingProvider{f, journal})
	env, out, _, dir := newInstallEnv(t, output.ModeHuman)
	recordInstance(t, dir, "prod", prov)
	ds := giveStorage(t, dir, "prod", 1024, 2048, 1024)
	ds.journal = journal

	cmd := &releaseCommand{assumeYes: true, deleteData: true}
	if err := cmd.Run(context.Background(), env, []string{"prod"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := journal.String(); got != "cluster → registry → bucket" {
		t.Errorf("teardown order = %q; the data must go last, so a failure anywhere earlier leaves it intact", got)
	}
	if ds.deletes != 1 {
		t.Fatalf("DeleteBucket called %d times, want 1", ds.deletes)
	}
	if ds.deletedRef.Name != "farcast-prod-0badc0de" || ds.deletedRef.Location != "us-central1" || ds.deletedRef.Instance != "prod" {
		t.Errorf("deleted bucket ref = %+v, want the recorded bucket with its owning instance", ds.deletedRef)
	}
	if ds.count() != 0 {
		t.Errorf("bucket still holds %d objects", ds.count())
	}
	if ds.ensures != 0 {
		t.Errorf("EnsureBucket called %d times; a release must bring nothing into existence", ds.ensures)
	}
	if exists, _ := dir.InstanceExists("prod"); exists {
		t.Error("local state should be removed after a successful release")
	}
	if !strings.Contains(out.String(), "farcast-prod-0badc0de") ||
		!strings.Contains(out.String(), "3 objects are now permanently unreadable") {
		t.Errorf("result must name the bucket and what went with it:\n%s", out.String())
	}
}

// TestReleaseBucketFailureKeepsStateAndData closes the ordering argument from
// the other side: when the last delete fails, the cluster and registry are gone
// but the data and the record that names it are still there to re-run against.
func TestReleaseBucketFailureKeepsStateAndData(t *testing.T) {
	f := &fakeProvider{}
	journal := &teardownJournal{}
	prov := registerProvider(t, journalingProvider{f, journal})
	env, _, _, dir := newInstallEnv(t, output.ModeHuman)
	recordInstance(t, dir, "stuck", prov)
	ds := giveStorage(t, dir, "stuck", 512)
	ds.journal = journal
	ds.deleteErr = errors.New("api error")

	cmd := &releaseCommand{assumeYes: true, deleteData: true}
	err := cmd.Run(context.Background(), env, []string{"stuck"})
	if err == nil || !strings.Contains(err.Error(), "re-run") {
		t.Fatalf("err = %v, want a bucket failure with a retry hint", err)
	}
	if !strings.Contains(err.Error(), "--delete-data") {
		t.Errorf("the retry hint must carry the flag the re-run needs:\n%s", err)
	}
	if got := journal.String(); got != "cluster → registry → bucket" {
		t.Errorf("teardown order = %q", got)
	}
	if ds.count() != 1 {
		t.Errorf("bucket holds %d objects; a failed delete must not have emptied it", ds.count())
	}
	if exists, _ := dir.InstanceExists("stuck"); !exists {
		t.Fatal("local state must be kept when a cloud delete fails — it is what names the bucket")
	}
	meta, lerr := dir.LoadInstanceMetadata("stuck")
	if lerr != nil {
		t.Fatalf("state should be readable after a failed delete: %v", lerr)
	}
	if meta.Status != config.InstanceDeleting {
		t.Errorf("status = %q, want deleting", meta.Status)
	}
	if meta.Storage == nil || meta.Storage.Bucket != "farcast-stuck-0badc0de" {
		t.Errorf("the storage record must survive a failed delete: %+v", meta.Storage)
	}
}

// TestReleaseGatesWithoutAKeyring is the operator who lost keys.yaml. They can
// no longer read a byte of their data — and are still being billed for it, so
// they must still be gated on it and still be able to stop paying.
func TestReleaseGatesWithoutAKeyring(t *testing.T) {
	f := &fakeProvider{}
	prov := registerFake(t, f)
	env, out, _, dir := newInstallEnv(t, output.ModeHuman)
	recordInstance(t, dir, "lost", prov)
	ds := giveStorage(t, dir, "lost", 1024, 2048, 1024)
	giveKeyring(t, dir, "lost")
	if err := os.Remove(dir.InstanceKeyringPath("lost")); err != nil {
		t.Fatalf("remove the keyring: %v", err)
	}

	// The count comes from the provider, so it still knows what is there.
	err := (&releaseCommand{assumeYes: true}).Run(context.Background(), env, []string{"lost"})
	if _, ok := errors.AsType[*usageError](err); !ok {
		t.Fatalf("err = %v, want the gate to hold without a keyring", err)
	}
	if !strings.Contains(err.Error(), "3 object(s)") || !strings.Contains(err.Error(), "4.0 KiB") {
		t.Errorf("the gate must still name what is billable:\n%s", err)
	}
	if ds.deletes != 0 || f.deleteCalls != 0 {
		t.Errorf("bucket=%d cluster=%d deletes; want none", ds.deletes, f.deleteCalls)
	}

	// And the release they can no longer be talked out of still works.
	if err := (&releaseCommand{assumeYes: true, deleteData: true}).Run(context.Background(), env, []string{"lost"}); err != nil {
		t.Fatalf("Run with --delete-data: %v — a lost keyring must not trap the operator in a bill", err)
	}
	if ds.deletes != 1 {
		t.Errorf("DeleteBucket called %d times, want 1", ds.deletes)
	}
	if exists, _ := dir.InstanceExists("lost"); exists {
		t.Error("local state should be removed after a successful release")
	}
	if !strings.Contains(out.String(), "3 objects are now permanently unreadable") {
		t.Errorf("result must still report what went:\n%s", out.String())
	}
}

// TestReleaseWarnsAboutAKeyringWithNoRecordedBucket is the inverse loss: the
// record is gone but the keyring proves storage was used, so there is a bucket
// out there that release cannot find. Saying so beats pretending.
func TestReleaseWarnsAboutAKeyringWithNoRecordedBucket(t *testing.T) {
	f := &fakeProvider{}
	prov := registerFake(t, f)
	env, out, errb, dir := newInstallEnv(t, output.ModeHuman)
	recordInstance(t, dir, "orphan", prov) // no storage: block
	giveKeyring(t, dir, "orphan")

	if err := (&releaseCommand{assumeYes: true}).Run(context.Background(), env, []string{"orphan"}); err != nil {
		t.Fatalf("Run: %v — an unfindable bucket must not block the rest of the teardown", err)
	}
	if !strings.Contains(errb.String(), "Warning") || !strings.Contains(errb.String(), "farcast-orphan-*") {
		t.Errorf("expected a warning naming the bucket to go looking for:\n%s", errb.String())
	}
	if strings.Contains(out.String(), "storage:") {
		t.Errorf("the result must not claim a bucket it never found:\n%s", out.String())
	}
	if exists, _ := dir.InstanceExists("orphan"); exists {
		t.Error("local state should still be removed")
	}
}

// TestReleaseRetainedCopiesWarnButSucceed pins the cost-pillar behaviour: the
// bucket is gone, the cloud is still holding and billing for copies of what was
// in it, and the release says so instead of reporting nothing left billing.
func TestReleaseRetainedCopiesWarnButSucceed(t *testing.T) {
	f := &fakeProvider{}
	prov := registerFake(t, f)
	env, out, errb, dir := newInstallEnv(t, output.ModeHuman)
	recordInstance(t, dir, "held", prov)
	ds := giveStorage(t, dir, "held", 1024)
	ds.deleteErr = fmt.Errorf("%w: bucket %q retains deleted objects for 168h0m0s",
		datasphere.ErrRetentionForced, "farcast-held-0badc0de")

	cmd := &releaseCommand{assumeYes: true, deleteData: true}
	if err := cmd.Run(context.Background(), env, []string{"held"}); err != nil {
		t.Fatalf("Run: %v — a retention notice must not fail the teardown", err)
	}
	if !strings.Contains(errb.String(), "Warning") || !strings.Contains(errb.String(), "168h0m0s") {
		t.Errorf("expected a warning naming the retention window:\n%s", errb.String())
	}
	if !strings.Contains(out.String(), "released") || !strings.Contains(out.String(), "farcast-held-0badc0de") {
		t.Errorf("the release must still be reported as done:\n%s", out.String())
	}
	if exists, _ := dir.InstanceExists("held"); exists {
		t.Error("local state should be removed; the bucket itself is gone")
	}
}

// TestReleaseJSONReportsTheBucketAndDeletedObjects — the deleted-object count is
// the one number in the result that cannot be undone by reinstalling, so it has
// to survive into the machine-readable output too.
func TestReleaseJSONReportsTheBucketAndDeletedObjects(t *testing.T) {
	f := &fakeProvider{}
	prov := registerFake(t, f)
	env, out, _, dir := newInstallEnv(t, output.ModeJSON)
	recordInstance(t, dir, "p", prov)
	giveStorage(t, dir, "p", 1024, 2048, 1024)

	cmd := &releaseCommand{assumeYes: true, deleteData: true}
	if err := cmd.Run(context.Background(), env, []string{"p"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out.String())
	}
	if m["bucket"] != "farcast-p-0badc0de" || m["deleted_objects"] != float64(3) || m["status"] != "released" {
		t.Errorf("unexpected JSON result: %v", m)
	}
}

// TestReleaseConfirmationNamesTheStoredData covers the interactive half of the
// gate. DataSphere's spec requires the confirmation to name the bucket, its
// object count and byte size, and to say the data becomes permanently
// unreadable — and requires an empty bucket to add nothing at all.
func TestReleaseConfirmationNamesTheStoredData(t *testing.T) {
	meta := &config.InstanceMetadata{
		Name:    "prod",
		Cluster: "farcast-prod",
		Storage: &config.Storage{Bucket: "farcast-prod-0badc0de"},
	}
	cmd := &releaseCommand{}

	var buf strings.Builder
	ok, err := cmd.confirm(true, newPrompter(strings.NewReader("prod\n"), io.Discard), &buf,
		meta, datasphere.Usage{Objects: 3, StoredBytes: 4096})
	if err != nil || !ok {
		t.Fatalf("confirm = %v,%v; want true,nil", ok, err)
	}
	for _, want := range []string{"farcast-prod-0badc0de", "3 objects", "4.0 KiB", "PERMANENTLY UNREADABLE"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("the confirmation is missing %q:\n%s", want, buf.String())
		}
	}

	// An empty bucket produces no extra line, so a routine teardown reads
	// exactly as it did before the gate existed.
	buf.Reset()
	if _, err := cmd.confirm(true, newPrompter(strings.NewReader("prod\n"), io.Discard), &buf, meta, datasphere.Usage{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "storage:") {
		t.Errorf("an empty bucket must add nothing to the confirmation:\n%s", buf.String())
	}
}

// TestReleaseSucceedsWhenTheBucketIsAlreadyGone covers the state release itself
// creates.
//
// A bucket delete that succeeds followed by a local-cleanup failure — the exact
// partial state release warns about and tells the operator to re-run through —
// leaves a record pointing at a bucket that no longer exists. So does an
// interrupted release, and so does someone deleting the bucket in the console.
//
// Before ErrBucketNotFound existed, the gate opened a session, Validate turned
// the 404 into a hard error, and the release stopped before touching anything:
// a free, ALREADY-GONE bucket permanently blocked the teardown of the BILLABLE
// cluster beside it, while advising the operator to "re-run once it can be
// reached" — a condition that would never arrive. That inverts the cost pillar
// and contradicts this command's own promise that a release is always safe to
// repeat.
func TestReleaseSucceedsWhenTheBucketIsAlreadyGone(t *testing.T) {
	f := &fakeProvider{}
	prov := registerFake(t, f)
	env, _, errb, dir := newInstallEnv(t, output.ModeHuman)
	recordInstance(t, dir, "prod", prov)
	ds := giveStorage(t, dir, "prod")
	ds.absent = true

	cmd := &releaseCommand{assumeYes: true} // no --delete-data: there is no data
	if err := cmd.Run(context.Background(), env, []string{"prod"}); err != nil {
		t.Fatalf("Run: %v — an absent bucket must never block a teardown", err)
	}
	if f.deleteCalls != 1 {
		t.Errorf("cluster deletes = %d, want 1: the billable resource must still be destroyed", f.deleteCalls)
	}
	if ds.deletes != 0 {
		t.Errorf("bucket deletes = %d, want 0: there was nothing there to delete", ds.deletes)
	}
	if exists, _ := dir.InstanceExists("prod"); exists {
		t.Error("local state survived a successful release")
	}
	// And it is not silent: an operator re-running after a partial teardown
	// should be told which half had already happened.
	if !strings.Contains(errb.String(), "no longer exists") {
		t.Errorf("stderr = %q, want a note that the recorded bucket is already gone", errb.String())
	}
}
