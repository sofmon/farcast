package cli

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/sofmon/farcast/datasphere"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
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

// The scope must be recorded in the keyring BEFORE any push. Key material
// handed to a cluster but never written down is material whose data nobody can
// find again.
func TestEnsureScopeMintsAndRecordsBeforeAnyPush(t *testing.T) {
	dir, env := keyholderInstance(t, true)
	keys, err := datasphere.NewKeyring()
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	encoded, err := keys.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := dir.CreateInstanceKeyring("prod", encoded); err != nil {
		t.Fatalf("CreateInstanceKeyring: %v", err)
	}
	meta, _ := dir.LoadInstanceMetadata("prod")

	scope, generation, err := ensureScope(env, "prod", meta, keys)
	if err != nil {
		t.Fatalf("ensureScope: %v", err)
	}
	if scope.Name != DefaultScopeName || scope.Prefix != DefaultScopePrefix {
		t.Errorf("scope = %+v", scope)
	}
	if generation != 1 {
		t.Errorf("generation = %d, want 1", generation)
	}

	// It is on disk, in the keyring, before anything was pushed anywhere.
	saved, err := dir.LoadInstanceKeyring("prod")
	if err != nil {
		t.Fatalf("LoadInstanceKeyring: %v", err)
	}
	reloaded, err := datasphere.ParseKeyring(saved)
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}
	got, ok := reloaded.ScopeNamed(DefaultScopeName)
	if !ok {
		t.Fatal("the scope was not recorded in the keyring")
	}
	a, _ := got.Keyring().ActiveKEK()
	b, _ := scope.Keyring().ActiveKEK()
	if a.ID != b.ID {
		t.Error("the recorded scope is not the one that would have been pushed")
	}

	// And the metadata records where it went.
	meta2, _ := dir.LoadInstanceMetadata("prod")
	if meta2.Keyholder.Scope != DefaultScopeName || meta2.Keyholder.Generation != 1 {
		t.Errorf("metadata = %+v", meta2.Keyholder)
	}
}

// Generations only ever move forward: a keyholder refuses anything older, so a
// captured bundle cannot be replayed to reinstate retired keys.
func TestEnsureScopeAdvancesTheGeneration(t *testing.T) {
	dir, env := keyholderInstance(t, true)
	keys, _ := datasphere.NewKeyring()
	encoded, _ := keys.Marshal()
	_ = dir.CreateInstanceKeyring("prod", encoded)

	var last uint64
	for i := range 3 {
		meta, _ := dir.LoadInstanceMetadata("prod")
		reloadedKeys := keys
		if saved, err := dir.LoadInstanceKeyring("prod"); err == nil {
			if k, err := datasphere.ParseKeyring(saved); err == nil {
				reloadedKeys = k
			}
		}
		_, generation, err := ensureScope(env, "prod", meta, reloadedKeys)
		if err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		if generation <= last {
			t.Fatalf("generation went backwards: %d after %d", generation, last)
		}
		last = generation
	}
}

// The key-loss warning is mandated wording, not prose: an operator who has not
// internalised it will treat the keyring like a config file.
func TestMintingAScopeCarriesTheKeyLossWarning(t *testing.T) {
	dir, env := keyholderInstance(t, true)
	keys, _ := datasphere.NewKeyring()
	encoded, _ := keys.Marshal()
	_ = dir.CreateInstanceKeyring("prod", encoded)
	meta, _ := dir.LoadInstanceMetadata("prod")

	var errBuf strings.Builder
	env.Err = &errBuf
	if _, _, err := ensureScope(env, "prod", meta, keys); err != nil {
		t.Fatalf("ensureScope: %v", err)
	}
	if !strings.Contains(errBuf.String(), datasphere.KeyLossWarning) {
		t.Errorf("minting a scope did not carry the mandated warning: %q", errBuf.String())
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
// write — a failure that reads as an application bug.
func TestDeployRefusesWithoutABucket(t *testing.T) {
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

	err := (&storageDeployCommand{}).Run(context.Background(), env, []string{"prod"})
	if err == nil || !strings.Contains(err.Error(), "bucket") {
		t.Fatalf("deploy should refuse without a bucket, got %v", err)
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
