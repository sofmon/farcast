package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/datasphere"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/planck"
)

func keyholderInstance(t *testing.T, deployed bool) (config.Dir, *Env) {
	t.Helper()
	dir := config.Dir(t.TempDir())
	// The config store refuses a world-readable directory; t.TempDir() is 0755.
	if err := os.Chmod(string(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := dir.CreateInstance("prod"); err != nil {
		t.Fatalf("CreateInstance: %v", err)
	}
	meta := &config.InstanceMetadata{Name: "prod", Provider: "gke", Region: "us-central1", Status: "running"}
	if deployed {
		meta.Keyholder = &config.Keyholder{Deployed: true, Replicas: 2}
	}
	if err := dir.SaveInstanceMetadata("prod", meta); err != nil {
		t.Fatalf("SaveInstanceMetadata: %v", err)
	}
	env, _ := testEnv(dir, output.ModeHuman)
	return dir, env
}

// unseal is the command an operator reaches for at 03:00. It must never
// deploy, apply or restart anything: an absent keyholder is reported and the
// command stops, so there is no way for it to make an outage worse.
func TestUnsealRefusesWhenNoKeyholderIsDeployed(t *testing.T) {
	_, env := keyholderInstance(t, false)
	err := (&storageUnsealCommand{}).Run(context.Background(), env, []string{"prod"})
	if err == nil {
		t.Fatal("unseal proceeded with no keyholder deployed")
	}
	msg := err.Error()
	if !strings.Contains(msg, "storage deploy") {
		t.Errorf("the refusal should name the command that fixes it: %q", msg)
	}
	if !strings.Contains(msg, "nothing to unseal") {
		t.Errorf("the refusal should say why: %q", msg)
	}
}

func TestStateRefusesWhenNoKeyholderIsDeployed(t *testing.T) {
	_, env := keyholderInstance(t, false)
	err := (&storageStateCommand{}).Run(context.Background(), env, []string{"prod"})
	if err == nil || !strings.Contains(err.Error(), "storage deploy") {
		t.Fatalf("state should refuse and name the fix, got %v", err)
	}
}

// An instance with a keyholder but no tunnel cannot be unsealed at all, and
// the message must say so plainly rather than reporting a storage fault: this
// is the recovery floor ADR 0008 recorded, and an operator chasing the wrong
// component at 03:00 is the failure it predicts.
func TestUnsealNamesFatLineWhenTheTunnelIsAbsent(t *testing.T) {
	_, env := keyholderInstance(t, true)
	err := (&storageUnsealCommand{}).Run(context.Background(), env, []string{"prod"})
	if err == nil {
		t.Fatal("unseal proceeded with no tunnel")
	}
	if !strings.Contains(err.Error(), "connect") {
		t.Errorf("the refusal should point at the tunnel: %q", err)
	}
}

// An unseal hands over what the keyring HOLDS and mints nothing.
//
// It used to mint the one shared application scope on the way past, which made
// recovery a moment that could bring key material into existence. Scopes are
// per application now and minted by `farcast run`, so unseal reads and pushes
// — and an instance with no applications yields an empty bundle rather than a
// refusal, because a keyholder that cannot unseal is one that never becomes
// ready.
func TestUnsealHandsOverWhatTheKeyringHoldsAndMintsNothing(t *testing.T) {
	dir, env := keyholderInstance(t, true)
	keys, err := datasphere.NewKeyring()
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	saveKeyring(t, dir, "prod", keys)
	kh := &fakeStateKeyholder{phase: "restart-sealed"}
	c := &storageUnsealCommand{newKeyholder: openerFor(kh)}

	if err := c.Run(context.Background(), env, []string{"prod"}); err != nil {
		t.Fatalf("an instance with no applications could not unseal: %v", err)
	}
	if got := len(liveKeyring(t, dir, "prod").Scopes()); got != 0 {
		t.Errorf("unseal minted %d scope(s)", got)
	}
	for i := range 2 {
		if r := kh.replica(i); r.phase != "unsealed" || len(r.keys) != 0 {
			t.Errorf("replica %d: %s holding %v; want unsealed with no scopes", i, r.phase, r.keys)
		}
	}

	// With applications deployed, every one of their scopes travels: a bundle
	// carrying a subset would restore storage for some and leave others
	// sealed.
	for _, app := range []string{"api", "web"} {
		scope, serr := datasphere.NewAppScope("apps", app)
		if serr != nil {
			t.Fatal(serr)
		}
		if keys, err = keys.AddScope(scope); err != nil {
			t.Fatal(err)
		}
	}
	saveKeyring(t, dir, "prod", keys)
	if err := c.Run(context.Background(), env, []string{"prod"}); err != nil {
		t.Fatalf("unseal: %v", err)
	}
	for i := range 2 {
		if !sameKeys(kh.replica(i).keys, heldKeys(keys)) {
			t.Errorf("replica %d holds %v; want both applications' scopes", i, kh.replica(i).keys)
		}
	}
}

// Generations only ever move forward: a keyholder refuses anything older, so a
// captured bundle cannot be replayed to reinstate retired keys.
func TestUnsealAdvancesTheGeneration(t *testing.T) {
	dir, env := keyholderInstance(t, true)
	scopedKeyring(t, dir, "prod", "demo", "alpha")
	c := &storageUnsealCommand{newKeyholder: openerFor(&fakeStateKeyholder{phase: "restart-sealed"})}

	var last uint64
	for i := range 3 {
		if err := c.Run(context.Background(), env, []string{"prod"}); err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		meta, err := dir.LoadInstanceMetadata("prod")
		if err != nil {
			t.Fatal(err)
		}
		if meta.Keyholder.Generation <= last {
			t.Fatalf("round %d: generation went backwards: %d after %d", i, meta.Keyholder.Generation, last)
		}
		last = meta.Keyholder.Generation
	}
}

// fakeKeyholder stands in for the replicas an unseal pushes to.
type fakeKeyholder struct {
	err   error
	calls int
}

// State answers as a replica that restarted and has never been unsealed.
func (f *fakeKeyholder) State(context.Context, int) (keyholder.State, error) {
	return keyholder.State{Phase: "restart-sealed"}, nil
}

func (f *fakeKeyholder) Unseal(_ context.Context, _ int, _ []byte, _ string) (keyholder.State, error) {
	f.calls++
	if f.err != nil {
		return keyholder.State{}, f.err
	}
	return keyholder.State{Phase: "unsealed"}, nil
}

// unsealWith wires an unseal command to a fake keyholder and gives the
// instance a keyring to push.
func unsealWith(t *testing.T, dir config.Dir, f *fakeKeyholder) *storageUnsealCommand {
	t.Helper()
	keys, err := datasphere.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := keys.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := dir.CreateInstanceKeyring("prod", encoded); err != nil {
		t.Fatal(err)
	}
	return &storageUnsealCommand{newKeyholder: openerFor(f)}
}

// An unseal that reaches no replica must not advance the generation.
//
// It used to: the counter was written before the first push. The usual reason
// every push fails is the keyholder crash-looping without its bucket grant —
// which an operator retries — so each attempt burned a generation and left the
// record describing a handover that never happened. Found on the Phase 4.4
// walk, alongside the grant ordering that causes it.
func TestAFailedUnsealDoesNotConsumeAGeneration(t *testing.T) {
	dir, env := keyholderInstance(t, true)
	f := &fakeKeyholder{err: errors.New("403 from the bucket")}
	c := unsealWith(t, dir, f)

	if err := c.Run(context.Background(), env, []string{"prod"}); err == nil {
		t.Fatal("an unseal that reached no replica reported success")
	}
	if f.calls == 0 {
		t.Fatal("it never tried to push")
	}
	meta, err := dir.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatal(err)
	}
	if meta.Keyholder.Generation != 0 {
		t.Errorf("a failed unseal consumed generation %d", meta.Keyholder.Generation)
	}
}

// And one that lands records it, so the next unseal moves forward. A keyholder
// refuses anything older than what it holds, so a generation that never
// advanced would make the next bundle unacceptable.
func TestASuccessfulUnsealRecordsTheGeneration(t *testing.T) {
	dir, env := keyholderInstance(t, true)
	c := unsealWith(t, dir, &fakeKeyholder{})

	if err := c.Run(context.Background(), env, []string{"prod"}); err != nil {
		t.Fatalf("unseal: %v", err)
	}
	meta, err := dir.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatal(err)
	}
	if meta.Keyholder.Generation != 1 {
		t.Errorf("generation = %d, want 1", meta.Keyholder.Generation)
	}
}

// "Most of them worked" is not success. A partial unseal leaves replicas that
// serve nothing; a partial seal leaves replicas that may still hold the keys
// an operator was trying to take away.
func TestPartialFailureIsNeverReportedAsSuccess(t *testing.T) {
	for _, verb := range []string{"unseal", "seal"} {
		if err := partialFailure(verb, 2, 2); err != nil {
			t.Errorf("%s: a complete fan-out reported %v", verb, err)
		}
		for _, done := range []int{0, 1} {
			err := partialFailure(verb, done, 2)
			if err == nil {
				t.Fatalf("%s: %d of 2 reported success", verb, done)
			}
			if !strings.Contains(err.Error(), "of 2") {
				t.Errorf("%s: the error should say how many: %q", verb, err)
			}
		}
	}
	// The two verbs must not share a message: an operator reading "still hold
	// key material" after a seal is being told something different from an
	// operator reading it after an unseal.
	if partialFailure("unseal", 1, 2).Error() == partialFailure("seal", 1, 2).Error() {
		t.Error("a partial seal and a partial unseal report the same thing")
	}
	if !strings.Contains(partialFailure("seal", 1, 2).Error(), "may still hold") {
		t.Error("a partial seal must warn that key material may still be held")
	}
}

// The keyholder is reachable only through the tunnel, so deploying it into an
// instance with no tunnel would produce something nobody could ever unseal.
func TestDeployRefusesWithoutATunnel(t *testing.T) {
	dir := config.Dir(t.TempDir())
	if err := os.Chmod(string(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := dir.CreateInstance("prod"); err != nil {
		t.Fatal(err)
	}
	meta := &config.InstanceMetadata{Name: "prod", Provider: "gke", Region: "us-central1", Status: "running"}
	if err := dir.SaveInstanceMetadata("prod", meta); err != nil {
		t.Fatal(err)
	}
	env, _ := testEnv(dir, output.ModeHuman)

	err := (&storageDeployCommand{}).Run(context.Background(), env, []string{"prod"})
	if err == nil {
		t.Fatal("deploy proceeded with no tunnel")
	}
	if !strings.Contains(err.Error(), "farcast connect") {
		t.Errorf("the refusal should name the fix: %q", err)
	}
}

// A keyholder with no bucket would start, pass its probes and refuse every
// write — a failure that reads as an application bug. So deploy must not
// proceed without one.
//
// It used to REFUSE, telling the operator to "run a 'farcast storage' command
// first so the bucket is minted" — and the only such command that mints is one
// that writes. The Phase 4.3 walk followed that literally, wrote to app/, and
// so placed an object under the master key space in the one window before the
// app scope exists; unseal then minted that scope over the prefix and the
// object became unreachable by its own name.
//
// Deploy now mints the bucket itself, which removes the window rather than
// documenting a way around it. This asserts it still does not proceed on a
// bucketless instance — it just gets there by creating one.
func TestDeployMintsTheBucketItNeeds(t *testing.T) {
	dir := config.Dir(t.TempDir())
	if err := os.Chmod(string(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := dir.CreateInstance("prod"); err != nil {
		t.Fatal(err)
	}
	meta := &config.InstanceMetadata{
		Name: "prod", Provider: "gke", Region: "us-central1", Status: "running",
		FatLineDeployed: true,
	}
	if err := dir.SaveInstanceMetadata("prod", meta); err != nil {
		t.Fatal(err)
	}
	env, _ := testEnv(dir, output.ModeHuman)

	var minted []string
	c := &storageDeployCommand{}
	// Consent first: since the Phase 4.4 walk the cost gate sits above the
	// bucket, so a deploy that never gets past it creates nothing at all.
	c.deployer.assumeYes = true
	c.ensureStorage = func(_ context.Context, _ *Env, instance string) error {
		minted = append(minted, instance)
		return errors.New("stop here")
	}

	err := c.Run(context.Background(), env, []string{"prod"})
	if err == nil {
		t.Fatal("deploy proceeded with no bucket at all")
	}
	if len(minted) != 1 || minted[0] != "prod" {
		t.Fatalf("deploy minted %v; it must create the bucket it needs rather than refuse", minted)
	}
	if !strings.Contains(err.Error(), "create storage") {
		t.Errorf("the failure does not say it was creating storage: %v", err)
	}
	if strings.Contains(err.Error(), "run a 'farcast storage' command first") {
		t.Error("deploy still tells the operator to mint a bucket by writing to it")
	}
}

// And an instance that already has a bucket is left alone: minting again would
// be a second bucket for an instance that has one.
func TestDeployDoesNotMintOverAnExistingBucket(t *testing.T) {
	dir := config.Dir(t.TempDir())
	if err := os.Chmod(string(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := dir.CreateInstance("prod"); err != nil {
		t.Fatal(err)
	}
	meta := &config.InstanceMetadata{
		Name: "prod", Provider: "gke", Region: "us-central1", Status: "running",
		FatLineDeployed: true,
		Storage:         &config.Storage{Bucket: "farcast-prod-abc", Location: "us-central1"},
	}
	if err := dir.SaveInstanceMetadata("prod", meta); err != nil {
		t.Fatal(err)
	}
	env, _ := testEnv(dir, output.ModeHuman)

	var minted []string
	c := &storageDeployCommand{}
	c.ensureStorage = func(_ context.Context, _ *Env, instance string) error {
		minted = append(minted, instance)
		return nil
	}
	_ = c.Run(context.Background(), env, []string{"prod"})
	if len(minted) != 0 {
		t.Fatalf("deploy minted storage for an instance that already has a bucket: %v", minted)
	}
}

// Nothing is created before the operator has agreed to the cost.
//
// The gate used to sit BELOW the bucket, so declining it — or running
// non-interactively without --yes — returned an error having already created a
// real, billable bucket and a keyring whose loss is unrecoverable. Found on the
// Phase 4.4 walk. Cost is the project's second pillar: spending must never be
// something a command does on the way to telling you it will not proceed.
func TestDeployCreatesNothingWithoutConsent(t *testing.T) {
	dir := config.Dir(t.TempDir())
	if err := os.Chmod(string(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := dir.CreateInstance("prod"); err != nil {
		t.Fatal(err)
	}
	// No Storage recorded: this instance has no bucket, so a deploy that got
	// as far as minting would create one.
	meta := &config.InstanceMetadata{
		Name: "prod", Provider: "gke", Region: "us-central1", Status: "running",
		FatLineDeployed: true,
	}
	if err := dir.SaveInstanceMetadata("prod", meta); err != nil {
		t.Fatal(err)
	}
	env, _ := testEnv(dir, output.ModeHuman)

	var minted []string
	c := &storageDeployCommand{} // assumeYes stays false; env is non-interactive
	c.ensureStorage = func(_ context.Context, _ *Env, instance string) error {
		minted = append(minted, instance)
		return nil
	}

	err := c.Run(context.Background(), env, []string{"prod"})
	if err == nil {
		t.Fatal("deploy provisioned without confirmation")
	}
	if len(minted) != 0 {
		t.Errorf("a refused deploy created storage anyway: %v", minted)
	}
	after, lerr := dir.LoadInstanceMetadata("prod")
	if lerr != nil {
		t.Fatal(lerr)
	}
	if after.Storage != nil && after.Storage.Bucket != "" {
		t.Errorf("a refused deploy recorded a bucket: %s", after.Storage.Bucket)
	}
	if after.Keyholder != nil {
		t.Error("a refused deploy recorded a keyholder")
	}
}

// Non-interactive runs must not provision standing compute without consent.
func TestDeployRequiresConsentForStandingCost(t *testing.T) {
	dir := config.Dir(t.TempDir())
	if err := os.Chmod(string(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := dir.CreateInstance("prod"); err != nil {
		t.Fatal(err)
	}
	meta := &config.InstanceMetadata{
		Name: "prod", Provider: "gke", Region: "us-central1", Status: "running",
		FatLineDeployed: true,
		Storage:         &config.Storage{Bucket: "b", Provider: "gcs"},
	}
	if err := dir.SaveInstanceMetadata("prod", meta); err != nil {
		t.Fatal(err)
	}
	env, _ := testEnv(dir, output.ModeHuman)

	err := (&storageDeployCommand{}).Run(context.Background(), env, []string{"prod"})
	if err == nil {
		t.Fatal("deploy provisioned standing compute with no confirmation")
	}
	if !strings.Contains(err.Error(), "--yes") || !strings.Contains(err.Error(), "month") {
		t.Errorf("the gate should name the cost and the flag: %q", err)
	}
	// And nothing was recorded, because nothing was created.
	after, _ := dir.LoadInstanceMetadata("prod")
	if after.Keyholder != nil {
		t.Error("a declined deploy recorded a keyholder")
	}
}

// The two system workloads must not share an image path, or one would
// overwrite the other in the instance's registry.
func TestSystemComponentsHaveDistinctImagePaths(t *testing.T) {
	if fatlineComponent.ImagePath == keyholderComponent.ImagePath {
		t.Fatal("FatLine and the keyholder share an image path")
	}
	if fatlineComponent.BinaryPath == keyholderComponent.BinaryPath {
		t.Fatal("FatLine and the keyholder share a binary path")
	}
	a := instanceSystemImage("reg.example/proj/inst", fatlineComponent)
	b := instanceSystemImage("reg.example/proj/inst", keyholderComponent)
	if a == b {
		t.Fatalf("both components resolve to %s", a)
	}
	if !strings.Contains(b, "system/datasphered") {
		t.Errorf("the keyholder image is not under system/: %s", b)
	}
}

// deployableInstance is connected AND has a bucket recorded — everything the
// keyholder deploy needs before it reaches the cluster.
func deployableInstance(t *testing.T, dir config.Dir, name string) *config.InstanceMetadata {
	t.Helper()
	meta := connectedInstance(t, dir, name)
	meta.Storage = &config.Storage{Bucket: "farcast-" + name + "-0a1b2c3d", Provider: "gcs", Location: "us-central1"}
	if err := dir.SaveInstanceMetadata(name, meta); err != nil {
		t.Fatal(err)
	}
	return meta
}

func testStorageDeploy(fp *fakeProvider, fb *fakeBuilder) *storageDeployCommand {
	c := &storageDeployCommand{}
	c.deployer.openProvider = func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) {
		return fp, nil
	}
	c.deployer.newBuilder = func(func(string)) imageBuilder { return fb }
	return c
}

// The keyholder is recorded BEFORE the apply, like every other billable thing
// this CLI creates. A workload running in a cluster that local state does not
// know about is one nobody will think to tear down — so an apply that FAILS
// must still leave the record behind.
func TestDeployRecordsTheKeyholderBeforeApplying(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	deployableInstance(t, dir, name)

	fc := &fakeCluster{applyErr: errors.New("the API server said no")}
	c := testStorageDeploy(&fakeProvider{}, &fakeBuilder{})
	c.deployer.assumeYes = true
	c.deployer.newCluster = func(string) clusterApplier { return fc }

	env, _ := testEnv(dir, output.ModeHuman)
	if err := c.Run(context.Background(), env, []string{name}); err == nil {
		t.Fatal("a failed apply reported success")
	}

	after, err := dir.LoadInstanceMetadata(name)
	if err != nil {
		t.Fatalf("LoadInstanceMetadata: %v", err)
	}
	if after.Keyholder == nil || !after.Keyholder.Deployed {
		t.Fatal("a failed apply left no record; a workload the cluster may be running would be untracked")
	}
	if after.Keyholder.Image == "" {
		t.Error("the recorded keyholder does not name the image the cluster was told to run")
	}
	if after.Keyholder.Replicas != keyholderReplicas {
		t.Errorf("recorded %d replicas, want %d", after.Keyholder.Replicas, keyholderReplicas)
	}
}

// withProject gives an instance the cloud project a real GKE instance always
// has. The shared fixture leaves it empty, and the grant is addressed to a
// project.
func withProject(t *testing.T, dir config.Dir, name string) {
	t.Helper()
	meta, err := dir.LoadInstanceMetadata(name)
	if err != nil {
		t.Fatal(err)
	}
	meta.Project = "farcast-proj"
	if err := dir.SaveInstanceMetadata(name, meta); err != nil {
		t.Fatal(err)
	}
}

// The bucket grant reaches the operator even when the deploy fails, because it
// is printed before the apply rather than as part of the success result.
//
// It used to live only in deployResult.Human, which never runs on a failure —
// and on the happy path it printed underneath a workload that was already
// crash-looping on the 403 it prevents. Two walks (3.2 and 4.4) lost time to a
// healthy instance that looked broken for want of a grant the tool had not yet
// mentioned.
func TestTheBucketGrantIsPrintedBeforeTheDeployNeedsIt(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	deployableInstance(t, dir, name)

	withProject(t, dir, name)

	fc := &fakeCluster{applyErr: errors.New("the API server said no")}
	c := testStorageDeploy(&fakeProvider{}, &fakeBuilder{})
	c.deployer.assumeYes = true
	c.deployer.newCluster = func(string) clusterApplier { return fc }

	env, _, errOut := testEnvBoth(dir, output.ModeHuman)
	if err := c.Run(context.Background(), env, []string{name}); err == nil {
		t.Fatal("a failed apply reported success")
	}
	got := errOut.String()
	for _, want := range []string{"add-iam-policy-binding", "roles/storage.objectAdmin", "roles/storage.legacyBucketReader"} {
		if !strings.Contains(got, want) {
			t.Errorf("the grant was not printed before the deploy that needs it; missing %q:\n%s", want, got)
		}
	}
}

// And it is on stderr, so --output json still carries it: a machine-readable
// result that silently drops the one manual step would be worse than no
// output at all.
func TestTheBucketGrantSurvivesJSONOutput(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	deployableInstance(t, dir, name)

	withProject(t, dir, name)

	c := testStorageDeploy(&fakeProvider{}, &fakeBuilder{})
	c.deployer.assumeYes = true
	c.deployer.newCluster = func(string) clusterApplier { return &fakeCluster{} }

	env, out, errOut := testEnvBoth(dir, output.ModeJSON)
	if err := c.Run(context.Background(), env, []string{name}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errOut.String(), "add-iam-policy-binding") {
		t.Errorf("the grant is missing from stderr in json mode:\n%s", errOut.String())
	}
	if strings.Contains(out.String(), "add-iam-policy-binding") {
		t.Error("the grant leaked into the json result on stdout")
	}
}

// The happy path deploys a digest-pinned image and does NOT wait for readiness:
// every replica comes up sealed and a sealed replica never becomes Ready, so a
// rollout wait would block until it timed out on the happy path.
func TestDeployDoesNotWaitForReadiness(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	deployableInstance(t, dir, name)

	fc := &fakeCluster{}
	c := testStorageDeploy(&fakeProvider{}, &fakeBuilder{})
	c.deployer.assumeYes = true
	c.deployer.newCluster = func(string) clusterApplier { return fc }

	env, out := testEnv(dir, output.ModeHuman)
	if err := c.Run(context.Background(), env, []string{name}); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if fc.rollouts != 0 {
		t.Errorf("deploy waited for a rollout %d times; sealed replicas never become Ready", fc.rollouts)
	}
	if len(fc.applied) != 1 {
		t.Fatalf("applied %d manifests, want 1", len(fc.applied))
	}
	rendered := string(fc.applied[0])
	if !strings.Contains(rendered, "kind: StatefulSet") || !strings.Contains(rendered, "system/datasphered") {
		t.Error("the applied manifest is not the keyholder workload")
	}
	// The operator is told the next step, because nothing works until it runs.
	if !strings.Contains(out.String(), "SEALED") || !strings.Contains(out.String(), "storage unseal "+name) {
		t.Errorf("the operator was not told to unseal: %q", out.String())
	}
}

// The default mint path, exercised rather than stubbed: deploy against an
// instance whose storage record has no bucket must actually create one.
//
// The seam above proves deploy DECIDES to mint. This proves the thing it calls
// mints — the join between them, which a seam test cannot see and which is
// where this kind of fix usually rots.
func TestDeployReallyMintsTheBucket(t *testing.T) {
	env, _, _, dir, _ := newDataEnv(t, output.ModeHuman)

	// Same instance, but with the bucket name cleared: a storage record that
	// names a provider and nothing else is the state a half-finished mint
	// leaves, and it must be treated as no storage at all.
	meta, err := dir.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatal(err)
	}
	meta.FatLineDeployed = true
	meta.Storage.Bucket = ""
	meta.Storage.CreatedAt = time.Time{}
	if err := dir.SaveInstanceMetadata("prod", meta); err != nil {
		t.Fatal(err)
	}

	c := &storageDeployCommand{}
	c.deployer.assumeYes = true
	// It will fail later, at the registry, with no cloud to reach. What
	// matters is what exists by then.
	_ = c.Run(context.Background(), env, []string{"prod"})

	got, err := dir.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatal(err)
	}
	if got.Storage == nil || got.Storage.Bucket == "" {
		t.Fatal("deploy did not mint the bucket it needs")
	}
	// And the keyring came with it, application scope and all, so the first
	// write to app/ cannot land in the master key space.
	raw, err := dir.LoadInstanceKeyring("prod")
	if err != nil {
		t.Fatalf("deploy minted no keyring: %v", err)
	}
	keys, err := datasphere.ParseKeyring(raw)
	if err != nil {
		t.Fatal(err)
	}
	// Deploy mints the keyring and no scopes: an application's scope arrives
	// with the application (ADR 0018 decision 5), so a fresh instance has a
	// keyring that can receive them and nothing standing in their way.
	if got := len(keys.Scopes()); got != 0 {
		t.Errorf("the keyring deploy minted carries %d scope(s), want none", got)
	}
}

// Upgrading the keyholder strands every application deployed before it: they
// hold no leaf and the new keyholder admits nothing without one. The failure
// the SDK reports looks like an outage, so the deploy has to say what it is.
func TestStorageDeploySaysToRedeployApplications(t *testing.T) {
	var buf bytes.Buffer
	if err := (deployResult{Instance: "prod", Replicas: 2, Image: "img"}).Human(&buf); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"storage identity", "farcast run"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("deploy output does not mention %q:\n%s", want, buf.String())
		}
	}
}

// unsealScoped is an unseal of an instance whose keyring holds application
// scopes — what every instance holds since ADR 0018 decision 5. The fixture
// above holds none, which makes "did it install the keys" trivially true.
func unsealScoped(t *testing.T, kh sealStateClient) (config.Dir, *Env, *storageUnsealCommand) {
	t.Helper()
	dir, env := keyholderInstance(t, true)
	scopedKeyring(t, dir, "prod", "demo", "alpha")
	return dir, env, &storageUnsealCommand{newKeyholder: openerFor(kh)}
}

// H2 in the remedy itself. 'storage unseal' is what every refusal in this CLI
// tells the operator to run, and it chose record+1 blindly. With the record one
// behind a serving replica, that was the number the replica already held: it
// installed nothing, and unseal reported success.
func TestUnsealClearsAGenerationTheRecordNeverSaw(t *testing.T) {
	kh := &fakeStateKeyholder{phase: "unsealed"}
	dir, env, c := unsealScoped(t, kh)
	// Replica 0 already serves generation 1 — from before alpha's scope was
	// minted — and the record says 0.
	kh.replica(0).generation, kh.replica(0).keys = 1, map[string][]string{}

	if err := c.Run(context.Background(), env, []string{"prod"}); err != nil {
		t.Fatalf("unseal: %v", err)
	}
	want := heldKeys(liveKeyring(t, dir, "prod"))
	for i := range 2 {
		if !sameKeys(kh.replica(i).keys, want) {
			t.Errorf("replica %d holds %v after unseal; want the keyring's %v", i, kh.replica(i).keys, want)
		}
	}
	meta, err := dir.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatal(err)
	}
	if meta.Keyholder.Generation <= 1 {
		t.Errorf("recorded generation %d; want above the 1 a replica already held", meta.Keyholder.Generation)
	}
}

func TestUnsealNeverReportsAnIgnoredPushAsSuccess(t *testing.T) {
	kh := &installsNothing{fakeStateKeyholder: &fakeStateKeyholder{phase: "restart-sealed"}}
	dir, env, c := unsealScoped(t, kh)

	err := c.Run(context.Background(), env, []string{"prod"})
	if err == nil {
		t.Fatal("an unseal no replica installed was reported as success")
	}
	entries, lerr := keyholder.ReadLedger(dir.InstanceUnsealLedgerPath("prod"))
	if lerr != nil {
		t.Fatal(lerr)
	}
	for _, e := range entries {
		if e.Result != "not-installed" {
			t.Errorf("ledger entry %+v; want not-installed", e)
		}
	}
	meta, merr := dir.LoadInstanceMetadata("prod")
	if merr != nil {
		t.Fatal(merr)
	}
	if meta.Keyholder.Generation != 0 {
		t.Errorf("recorded generation %d that no replica took", meta.Keyholder.Generation)
	}
}

// A replica serving no application scopes says so in words, rather than
// printing "scopes " and nothing after it.
func TestStateNamesAReplicaHoldingNoScopes(t *testing.T) {
	var b bytes.Buffer
	if err := (stateResult{Instance: "prod", Replicas: []replicaState{
		{Ordinal: 0, Phase: "unsealed", Generation: 3},
		{Ordinal: 1, Phase: "unsealed", Generation: 3, Scopes: []string{"app-a", "app-b"}},
	}}).Human(&b); err != nil {
		t.Fatal(err)
	}
	got := b.String()
	if !strings.Contains(got, "replica 0  unsealed   generation 3, holding no application scopes\n") {
		t.Errorf("an empty replica was not named as holding nothing:\n%s", got)
	}
	if !strings.Contains(got, "replica 1  unsealed   generation 3, scopes app-a,app-b\n") {
		t.Errorf("a replica's scopes were not listed:\n%s", got)
	}
	if strings.Contains(got, "scopes \n") {
		t.Errorf("an empty scope list was printed:\n%s", got)
	}
}

// A seal without --hold leaves the phase a keeper re-seeds. The token stays —
// it is the wire's — and the operator is told, once, what it means.
func TestSealWithoutHoldSaysAKeeperMayReseed(t *testing.T) {
	rows := []replicaState{{Ordinal: 0, Phase: "restart-sealed"}, {Ordinal: 1, Phase: "restart-sealed"}}
	var b bytes.Buffer
	if err := (sealResult{Instance: "prod", Replicas: rows}).Human(&b); err != nil {
		t.Fatal(err)
	}
	got := b.String()
	if !strings.Contains(got, "replica 0  restart-sealed\n") {
		t.Errorf("the phase token changed in the rows:\n%s", got)
	}
	if strings.Count(got, "Sealed without --hold") != 1 || !strings.Contains(got, "keeper device\nre-seeds unattended") ||
		!strings.Contains(got, "'farcast storage seal prod --hold'") {
		t.Errorf("an unheld seal did not say a keeper re-seeds it, once:\n%s", got)
	}

	b.Reset()
	held := []replicaState{{Ordinal: 0, Phase: "operator-hold"}}
	if err := (sealResult{Instance: "prod", Hold: true, Replicas: held}).Human(&b); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "Sealed without --hold") {
		t.Errorf("a held seal was told it was not held:\n%s", b.String())
	}
}

// stateOf runs 'storage state' over a fake fleet whose replicas run on the
// given nodes, and returns what the operator sees (human) and what a script
// reads (JSON).
func stateOf(t *testing.T, kh sealStateClient) (string, stateResult) {
	t.Helper()
	dir, _ := keyholderInstance(t, true)
	var res stateResult
	var text string
	for _, mode := range []output.Mode{output.ModeHuman, output.ModeJSON} {
		env, out, errb := testEnvBoth(dir, mode)
		if err := (&storageStateCommand{newKeyholder: openerFor(kh)}).Run(context.Background(), env, []string{"prod"}); err != nil {
			t.Fatalf("state (%v) should exit 0 whatever the placement: %v", mode, err)
		}
		if mode == output.ModeJSON {
			if err := json.Unmarshal(out.Bytes(), &res); err != nil {
				t.Fatalf("decode %q: %v", out.String(), err)
			}
		} else {
			text = out.String() + errb.String()
		}
	}
	return text, res
}

// fleetOn is a fleet of two replicas in phase, on these nodes.
func fleetOn(phase string, nodes ...string) *fakeStateKeyholder {
	kh := &fakeStateKeyholder{phase: phase}
	for i, n := range nodes {
		kh.replica(i).node = n
	}
	return kh
}

// Two replicas on one node are one node repair away from a fully sealed
// instance. Walk finding 2 found exactly this after an Autopilot eviction, and
// nothing said so.
func TestStorageStateFlagsReplicasSharingANode(t *testing.T) {
	text, res := stateOf(t, fleetOn("unsealed", "n1", "n1"))
	if !strings.Contains(text, "Replicas 0 and 1 run on one node (n1)") {
		t.Errorf("the shared node is not named:\n%s", text)
	}
	if !strings.Contains(text, "Nothing moves") || !strings.Contains(text, "moving one seals it") {
		t.Errorf("the report does not say nothing moves them, or what moving costs:\n%s", text)
	}
	if len(res.Colocated) != 1 || res.Colocated[0].Node != "n1" || !slices.Equal(res.Colocated[0].Replicas, []int{0, 1}) {
		t.Errorf("colocated = %+v, want n1:[0 1]", res.Colocated)
	}
	if res.Replicas[0].Node != "n1" || res.Replicas[1].Node != "n1" {
		t.Errorf("the per-replica node is missing from JSON: %+v", res.Replicas)
	}
	if len(res.PlacementUnknown) != 0 {
		t.Errorf("placement_unknown = %v for two replicas that both said", res.PlacementUnknown)
	}
}

// A spread fleet gets no line at all: a normal report does not grow, and
// "different nodes" is not offered as reassurance.
func TestStorageStateDoesNotWarnWhenSpread(t *testing.T) {
	text, res := stateOf(t, fleetOn("unsealed", "n1", "n2"))
	if strings.Contains(text, "node") {
		t.Errorf("a spread fleet's report talks about nodes:\n%s", text)
	}
	if len(res.Colocated) != 0 || len(res.PlacementUnknown) != 0 {
		t.Errorf("colocated = %+v, unknown = %v, want neither", res.Colocated, res.PlacementUnknown)
	}
}

// Silence is never a node. Two replicas that report nothing are not on one
// node, and one that reports nothing beside one that does is not a spread.
func TestStorageStateNeverInfersPlacementFromSilence(t *testing.T) {
	text, res := stateOf(t, fleetOn("unsealed", "", ""))
	if strings.Contains(text, "run on one node") || len(res.Colocated) != 0 {
		t.Errorf("two silent replicas were reported as sharing a node:\n%s\n%+v", text, res.Colocated)
	}
	if !slices.Equal(res.PlacementUnknown, []int{0, 1}) {
		t.Errorf("placement_unknown = %v, want [0 1]", res.PlacementUnknown)
	}
	if !strings.Contains(text, "cannot say whether replicas share one") {
		t.Errorf("unknown placement is not said:\n%s", text)
	}

	text, res = stateOf(t, fleetOn("unsealed", "", "n1"))
	if len(res.Colocated) != 0 || strings.Contains(text, "run on one node") {
		t.Errorf("one silent replica was placed: %+v\n%s", res.Colocated, text)
	}
	if !slices.Equal(res.PlacementUnknown, []int{0}) || !strings.Contains(text, "cannot say") {
		t.Errorf("placement_unknown = %v; the report must not read as a spread:\n%s", res.PlacementUnknown, text)
	}
}

// A sealed replica will be unsealed where it stands, so its node counts. An
// unreachable one said nothing, so it is neither placed nor unknown.
func TestStorageStateCountsASealedReplicasPlacement(t *testing.T) {
	kh := fleetOn("unsealed", "n1", "n1")
	kh.replica(1).phase = "restart-sealed"
	text, res := stateOf(t, kh)
	if len(res.Colocated) != 1 || !strings.Contains(text, "Replicas 0 and 1 run on one node") {
		t.Errorf("a sealed replica's placement was dropped: %+v\n%s", res.Colocated, text)
	}

	_, res = stateOf(t, &unreachableReplica{fakeStateKeyholder: fleetOn("unsealed", "n1", "n1"), down: 1})
	if len(res.Colocated) != 0 || len(res.PlacementUnknown) != 0 {
		t.Errorf("an unreachable replica was placed: colocated %+v, unknown %v", res.Colocated, res.PlacementUnknown)
	}
}

// unreachableReplica is a fleet in which one replica does not answer.
type unreachableReplica struct {
	*fakeStateKeyholder
	down int
}

func (u *unreachableReplica) State(ctx context.Context, i int) (keyholder.State, error) {
	if i == u.down {
		return keyholder.State{}, errors.New("no route to replica")
	}
	return u.fakeStateKeyholder.State(ctx, i)
}

// relayingFleet is a fleet reached through a FatLine replica on relay.
type relayingFleet struct {
	*fakeStateKeyholder
	relay string
}

func (r relayingFleet) RelayNode() string { return r.relay }

// The FatLine replica that answered is named only when it shares the
// keyholders' node, and nothing is said about the other FatLine replica.
func TestStorageStateNamesTheRelayOnlyWhenItShares(t *testing.T) {
	const tunnelLine = "The FatLine replica that answered this tunnel runs on that node too"
	text, res := stateOf(t, relayingFleet{fleetOn("unsealed", "n1", "n1"), "n1"})
	if !strings.Contains(text, tunnelLine) || res.RelayNode != "n1" {
		t.Errorf("a relay on the shared node is not said (relay_node %q):\n%s", res.RelayNode, text)
	}
	text, _ = stateOf(t, relayingFleet{fleetOn("unsealed", "n1", "n1"), "n2"})
	if strings.Contains(text, "FatLine") {
		t.Errorf("a relay elsewhere was talked about:\n%s", text)
	}
	text, _ = stateOf(t, relayingFleet{fleetOn("unsealed", "n1", "n2"), "n1"})
	if strings.Contains(text, "FatLine") {
		t.Errorf("a spread fleet's report talks about FatLine:\n%s", text)
	}
	text, _ = stateOf(t, fleetOn("unsealed", "n1", "n1"))
	if strings.Contains(text, "FatLine") {
		t.Errorf("a client that knows no relay printed one:\n%s", text)
	}
}

// The node is reported and never decides. An image that predates it reports
// "", and if that reached a decision it would become an unseal refusal.
func TestNodeNeverChangesAHandOver(t *testing.T) {
	var reports []string
	for _, nodes := range [][]string{{"", ""}, {"n1", "n1"}, {"n1", "n2"}} {
		dir, meta, env, _ := handOverInstance(t, "p140")
		k := scopedKeyring(t, dir, "p140", "demo", "alpha")
		kh := fleetOn("unsealed", nodes...)
		kh.replica(1).phase = "restart-sealed"
		res := handOverKeys(context.Background(), env, meta, openerFor(kh), liveKeyring(t, dir, meta.Name), handOverOptions{})
		var held []string
		for i := range 2 {
			held = append(held, fmt.Sprint(kh.replica(i).phase, sameKeys(kh.replica(i).keys, heldKeys(k))))
		}
		reports = append(reports, fmt.Sprintf("%+v %v %v", res.Complete(), kh.intents, held))
	}
	if reports[0] != reports[1] || reports[1] != reports[2] {
		t.Errorf("the node changed a hand-over:\n%s", strings.Join(reports, "\n"))
	}
	if outdatedImage(keyholder.State{Phase: "unsealed", Scopes: []string{"s"}, Keys: map[string][]string{"s": {"k"}}}) {
		t.Error("guard: a current image read as outdated")
	}
	if outdatedImage(keyholder.State{Phase: "unsealed", Scopes: []string{"s"}, Keys: map[string][]string{"s": {"k"}}, Node: ""}) !=
		outdatedImage(keyholder.State{Phase: "unsealed", Scopes: []string{"s"}, Keys: map[string][]string{"s": {"k"}}, Node: "n1"}) {
		t.Error("the node changed whether an image reads as outdated")
	}
}

// forgedRow is hostileText that also tries to forge a row of its own on the
// line below.
const forgedRow = hostileText + "\n  replica 9  unsealed   generation 9"

// keyholderRowsArePrintable fails unless out shows only printable runes, the
// forged row never stands on a line of its own, out carries the hostile text
// quoted rather than dropped, and exactly rows replica rows were printed.
func keyholderRowsArePrintable(t *testing.T, what, out string, rows int) {
	t.Helper()
	t.Log("\n" + out)
	onlyPrintable(t, what, out)
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "  replica 9") {
			t.Errorf("%s: the replica's text forged a row of its own:\n%s", what, out)
		}
		if strings.HasPrefix(line, "  replica ") {
			n++
		}
	}
	if n != rows {
		t.Errorf("%s: %d replica row(s); want %d — a row was joined or split:\n%s", what, n, rows, out)
	}
	if !strings.Contains(out, `\x1b]52`) {
		t.Errorf("%s: the replica's text is not shown, quoted:\n%s", what, out)
	}
}

// The per-replica rows of 'storage state', 'storage seal' and 'storage
// unseal' print what each replica reported — its phase and hold reason, an
// error carrying its refusal, a note or key difference naming a scope it
// sent. Every one of those goes through terminalText, like the rows added
// beside them; --json carries them as they came.
func TestKeyholderRowsQuoteWhatTheReplicaSent(t *testing.T) {
	render := func(r output.Result) string {
		t.Helper()
		var b bytes.Buffer
		if err := r.Human(&b); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}

	t.Run("storage state", func(t *testing.T) {
		r := stateResult{Instance: "prod", Replicas: []replicaState{
			{Ordinal: 0, Error: "keyholder replica 0: " + forgedRow},
			{Ordinal: 1, Phase: forgedRow, HoldReason: forgedRow, PinNote: forgedRow},
			{Ordinal: 2, Phase: "unsealed", Generation: 3, Scopes: []string{"app-demo-alpha"},
				KeysDiffer: "lacks scope " + forgedRow, PinNote: "behind this machine's keyring: " + forgedRow},
			{Ordinal: 3, Phase: "unsealed", Generation: 3,
				KeysDiffer: "serves a copy of " + forgedRow + " minted separately from this machine's"},
		}}
		out := render(r)
		keyholderRowsArePrintable(t, "storage state", out, 4)
		// The count reads the replica's note as it came, not as printed.
		if !strings.Contains(out, "1 replica(s) serve another machine's copy") {
			t.Errorf("a separately minted copy was not counted once quoted:\n%s", out)
		}

		var env bytes.Buffer
		if err := (&output.Printer{Mode: output.ModeJSON, Out: &env}).Print(r); err != nil {
			t.Fatal(err)
		}
		var back stateResult
		if err := json.Unmarshal(env.Bytes(), &back); err != nil {
			t.Fatal(err)
		}
		// encoding/json makes the one byte that is not UTF-8 into U+FFFD;
		// everything else arrives as the replica sent it.
		if raw := strings.ToValidUTF8(forgedRow, "�"); back.Replicas[1].Phase != raw || back.Replicas[1].HoldReason != raw ||
			back.Replicas[1].PinNote != raw || back.Replicas[2].KeysDiffer != "lacks scope "+raw {
			t.Errorf("--json no longer carries the replica's text as it came: %+v", back.Replicas)
		}
	})
	t.Run("storage seal", func(t *testing.T) {
		out := render(sealResult{Instance: "prod", Replicas: []replicaState{
			{Ordinal: 0, Error: "keyholder replica 0: " + forgedRow},
			{Ordinal: 1, Phase: forgedRow},
		}})
		keyholderRowsArePrintable(t, "storage seal", out, 2)
	})
	t.Run("storage unseal", func(t *testing.T) {
		out := render(unsealResult{Instance: "prod", Scopes: 1, Generation: 4, Loaded: 1, Total: 3,
			NotYetActive: forgedRow,
			Replicas: []replicaState{
				{Ordinal: 0, Error: "keyholder replica 0: " + forgedRow},
				{Ordinal: 1, Phase: forgedRow, Note: "holds this machine's keys, still writing under an older one (" + forgedRow + ")"},
				{Ordinal: 2, Phase: forgedRow, Generation: 4},
			}})
		keyholderRowsArePrintable(t, "storage unseal", out, 3)
		if !strings.Contains(out, "They do not write under this keyring's newest keys yet: \"x") {
			t.Errorf("why the newest keys are not in use is not shown, quoted:\n%s", out)
		}
	})
}

// forgedWarning is hostileText that also tries to forge a warning of its own
// on the line below.
const forgedWarning = hostileText + "\nwarning: keyholder replica 9 took the keys"

// hostileFleet is a fleet whose failures carry text chosen to act on the
// terminal: State fails for a silent replica, or — silentPushed — for any
// replica once it has been pushed; and a refused replica's push is refused
// with that text as the keyholder's reason.
type hostileFleet struct {
	*fakeStateKeyholder
	silent       map[int]bool
	silentPushed bool
	refuse       map[int]bool
	pushed       map[int]bool
}

func (f *hostileFleet) State(ctx context.Context, i int) (keyholder.State, error) {
	if f.silent[i] || (f.silentPushed && f.pushed[i]) {
		return keyholder.State{}, errors.New("tunnel: " + forgedWarning)
	}
	return f.fakeStateKeyholder.State(ctx, i)
}

func (f *hostileFleet) Unseal(ctx context.Context, i int, payload []byte, intent string) (keyholder.State, error) {
	if f.refuse[i] {
		return keyholder.State{}, &keyholder.Refusal{Ordinal: i, Reason: forgedWarning, Status: 400}
	}
	if f.pushed == nil {
		f.pushed = map[int]bool{}
	}
	f.pushed[i] = true
	return f.fakeStateKeyholder.Unseal(ctx, i, payload, intent)
}

// A hand-over's warnings name what a replica said when it did not answer or
// refused the keys: the tunnel's error, the keyholder's refusal. Each goes
// through terminalText, so none of it can act on the terminal or forge a
// warning line of its own.
func TestHandOverWarningsQuoteWhatTheReplicaSent(t *testing.T) {
	warned := func(t *testing.T, stderr, want string) {
		t.Helper()
		t.Log("\n" + stderr)
		if !strings.Contains(stderr, want) {
			t.Fatalf("guard: no %q warning:\n%s", want, stderr)
		}
		onlyPrintable(t, "hand-over warnings", stderr)
		for _, line := range strings.Split(stderr, "\n") {
			if strings.HasPrefix(line, "warning: keyholder replica 9") {
				t.Errorf("the replica's text forged a warning of its own:\n%s", stderr)
			}
		}
		if !strings.Contains(stderr, `\x1b]52`) {
			t.Errorf("the replica's text is not shown, quoted:\n%s", stderr)
		}
	}

	t.Run("did not answer", func(t *testing.T) {
		dir, meta, env, sees := handOverInstance(t, "p140")
		scopedKeyring(t, dir, "p140", "demo", "alpha")
		kh := &hostileFleet{fakeStateKeyholder: &fakeStateKeyholder{phase: "unsealed"}, silent: map[int]bool{1: true}}
		handOverKeys(context.Background(), env, meta, openerFor(kh), liveKeyring(t, dir, meta.Name), handOverOptions{})
		warned(t, sees.err.String(), "did not answer, so it is not handed the keys: \"tunnel: x")
	})
	t.Run("refused the keys", func(t *testing.T) {
		dir, meta, env, sees := handOverInstance(t, "p141")
		scopedKeyring(t, dir, "p141", "demo", "alpha")
		kh := &hostileFleet{fakeStateKeyholder: &fakeStateKeyholder{phase: "unsealed"}, refuse: map[int]bool{1: true}}
		handOverKeys(context.Background(), env, meta, openerFor(kh), liveKeyring(t, dir, meta.Name), handOverOptions{})
		// The refusal quotes the replica's reason itself (review finding
		// R3-3), so the warning carries it quoted inside this machine's words.
		warned(t, sees.err.String(), "refused the keys: replica 1 refused: \"x")
	})
	t.Run("did not answer when asked again", func(t *testing.T) {
		dir, meta, env, sees := handOverInstance(t, "p142")
		scopedKeyring(t, dir, "p142", "demo", "alpha")
		base := servingFleet(t, env, meta, dir)
		sees.err.Reset()
		rotateWith(t, env, "p142", &hostileFleet{fakeStateKeyholder: base, silentPushed: true})
		warned(t, sees.err.String(), "did not answer when asked again: \"tunnel: x")
	})
}
