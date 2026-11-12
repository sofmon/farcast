package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	pfetch "github.com/sofmon/farcast/planck/fetch"
)

// ADR 0021 decision 2, amended 2026-11-12: a group is a namespace labelled
// with its repository. 'run' records, on this machine, what it deployed into
// each namespace, and refuses a namespace recorded under another repository.

func recordDeployment(t *testing.T, dir config.Dir, instance, namespace, repo string) {
	t.Helper()
	if _, err := dir.UpdateInstanceMetadata(instance, func(m *config.InstanceMetadata) error {
		m.Deployments = map[string]config.Deployment{namespace: {Repository: repo, Commit: "0000000"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// writes reports whether anything past the manifest read reached the
// cluster: a build Job, the egress policy, or a workload.
func wroteAnything(t *testing.T, f *fakeRunCluster) bool {
	t.Helper()
	for name := range appliedKinds(t, f) {
		if strings.HasPrefix(name, "Job/build-") || strings.HasPrefix(name, "Deployment/") || strings.HasPrefix(name, "ConfigMap/") {
			return true
		}
	}
	return false
}

// A first deploy, with no record, is accepted and recorded: repository, the
// ref the fetch resolved, the commit and digest it read, when, and whether
// storage was wired.
func TestRunRecordsWhatItDeployedIntoTheNamespace(t *testing.T) {
	dir := config.Dir(t.TempDir())
	runnableInstance(t, dir, "p43")
	env, _ := testEnv(dir, output.ModeHuman)
	f := newFakeRun(twoAppManifest)
	before := time.Now().UTC().Truncate(time.Second)
	if err := runCmd(f).Run(context.Background(), env, []string{"p43", "github.com/example/my-platform"}); err != nil {
		t.Fatal(err)
	}
	meta, err := dir.LoadInstanceMetadata("p43")
	if err != nil {
		t.Fatal(err)
	}
	dep, ok := meta.Deployments["my-platform"]
	if !ok {
		t.Fatalf("no provenance recorded: %+v", meta.Deployments)
	}
	if dep.Repository != "https://github.com/example/my-platform" || dep.Ref != "refs/heads/main" ||
		dep.Commit != testCommit || !strings.HasPrefix(dep.ManifestDigest, "sha256:") || dep.StorageWired {
		t.Errorf("recorded %+v", dep)
	}
	if dep.DeployedAt.Before(before) || dep.DeployedAt.Nanosecond() != 0 || dep.DeployedAt.Location() != time.UTC {
		t.Errorf("deployed_at %v is not this run's, in whole UTC seconds", dep.DeployedAt)
	}
	// The record is local: nothing written to the cluster carries it.
	for _, s := range f.applied {
		if strings.Contains(s, "manifest_digest") || strings.Contains(s, "deployments:") {
			t.Errorf("provenance reached the cluster:\n%s", s)
		}
	}
	// The images the run reviewed are still recorded beside it.
	if meta.Toolchain == nil || meta.Toolchain.Fetcher != fetcherDigest {
		t.Errorf("recording provenance lost the toolchain record: %+v", meta.Toolchain)
	}
}

// Without --namespace the namespace is the manifest's name, known only after
// the read: the refusal comes then, and before anything is built or deployed.
func TestRunRefusesANamespaceRecordedUnderAnotherRepository(t *testing.T) {
	dir := config.Dir(t.TempDir())
	runnableInstance(t, dir, "p43")
	recordDeployment(t, dir, "p43", "my-platform", "https://github.com/someone-else/platform")
	env, _ := testEnv(dir, output.ModeHuman)
	f := newFakeRun(twoAppManifest)
	err := runCmd(f).Run(context.Background(), env, []string{"p43", "github.com/example/my-platform"})
	if err == nil {
		t.Fatal("run deployed over a namespace recorded under another repository")
	}
	for _, want := range []string{"https://github.com/someone-else/platform", "https://github.com/example/my-platform",
		"--replace-repository", "nothing was built or deployed"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, err)
		}
	}
	if wroteAnything(t, f) {
		t.Errorf("something past the read reached the cluster: %v", appliedKinds(t, f))
	}
	if len(f.applied) != 1 {
		t.Errorf("applied %d streams, want only the manifest read", len(f.applied))
	}
}

// With --namespace the refusal comes before anything is read at all.
func TestRunRefusesAGivenNamespaceBeforeReading(t *testing.T) {
	dir := config.Dir(t.TempDir())
	runnableInstance(t, dir, "p43")
	recordDeployment(t, dir, "p43", "shared", "https://github.com/someone-else/platform")
	env, _ := testEnv(dir, output.ModeHuman)
	f := newFakeRun(twoAppManifest)
	c := runCmd(f)
	c.namespace = "shared"
	err := c.Run(context.Background(), env, []string{"p43", "github.com/example/my-platform"})
	if err == nil || !strings.Contains(err.Error(), "Nothing was read, built or deployed") {
		t.Fatalf("err = %v", err)
	}
	if len(f.applied) != 0 {
		t.Errorf("applied %d streams before refusing", len(f.applied))
	}
}

// --replace-repository says to replace it, and the record moves.
func TestRunReplacesARepositoryWhenTold(t *testing.T) {
	dir := config.Dir(t.TempDir())
	runnableInstance(t, dir, "p43")
	recordDeployment(t, dir, "p43", "my-platform", "https://github.com/someone-else/platform")
	env, _ := testEnv(dir, output.ModeHuman)
	f := newFakeRun(twoAppManifest)
	c := runCmd(f)
	c.replaceRepository = true
	if err := c.Run(context.Background(), env, []string{"p43", "github.com/example/my-platform"}); err != nil {
		t.Fatal(err)
	}
	meta, _ := dir.LoadInstanceMetadata("p43")
	if got := meta.Deployments["my-platform"].Repository; got != "https://github.com/example/my-platform" {
		t.Errorf("the record still names %q", got)
	}
}

// The same repository spelled with a trailing slash or .git is the same
// repository; anything else is not.
func TestRunComparesRepositoriesByWhatTheyName(t *testing.T) {
	for _, tc := range []struct {
		recorded string
		same     bool
	}{
		{"https://github.com/example/my-platform", true},
		{"https://github.com/example/my-platform/", true},
		{"https://github.com/example/my-platform.git", true},
		{"https://github.com/example/my-platform.git/", true},
		{"https://github.com/Example/my-platform", false},
		{"https://gitlab.com/example/my-platform", false},
	} {
		dir := config.Dir(t.TempDir())
		runnableInstance(t, dir, "p43")
		recordDeployment(t, dir, "p43", "my-platform", tc.recorded)
		env, _ := testEnv(dir, output.ModeHuman)
		err := runCmd(newFakeRun(twoAppManifest)).Run(context.Background(), env, []string{"p43", "github.com/example/my-platform"})
		if (err == nil) != tc.same {
			t.Errorf("recorded %q: err = %v, want same=%v", tc.recorded, err, tc.same)
		}
	}
}

// A run that wired storage says so in its record: the map draws storage lines
// only for namespaces whose run gave its applications a storage identity.
func TestRunRecordsThatItWiredStorage(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meta := runnableInstance(t, dir, "p43")
	meta.Keyholder = &config.Keyholder{Deployed: true}
	if err := dir.SaveInstanceMetadata("p43", meta); err != nil {
		t.Fatal(err)
	}
	mintKeyring(t, dir, "p43")
	env, _ := testEnv(dir, output.ModeHuman)
	if err := runCmd(newFakeRun(twoAppManifest)).Run(context.Background(), env, []string{"p43", "github.com/example/my-platform"}); err != nil {
		t.Fatal(err)
	}
	got, err := dir.LoadInstanceMetadata("p43")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Deployments["my-platform"].StorageWired {
		t.Errorf("a run that wired storage recorded %+v", got.Deployments["my-platform"])
	}
}

// A credential in a repository URL would be written into the fetch Job and
// into this machine's record, which every 'world' prints. run refuses it
// before anything is read, and the refusal does not repeat the credential.
func TestRunRefusesACredentialInTheRepositoryURL(t *testing.T) {
	for _, in := range []string{
		"https://x-access-token:ghp_planted@github.com/example/my-platform",
		"https://ghp_planted@github.com/example/my-platform",
	} {
		_, err := repoURL(in)
		if exitCodeOf(err) != 2 || !strings.Contains(err.Error(), "--git-secret") ||
			!strings.Contains(err.Error(), "https://github.com/example/my-platform") {
			t.Errorf("repoURL(%q): %v; want a usage error pointing at --git-secret", in, err)
		}
		if err != nil && strings.Contains(err.Error(), "ghp_planted") {
			t.Errorf("the refusal repeats the credential: %v", err)
		}
	}

	dir := config.Dir(t.TempDir())
	runnableInstance(t, dir, "p43")
	env, _ := testEnv(dir, output.ModeHuman)
	f := newFakeRun(twoAppManifest)
	if err := runCmd(f).Run(context.Background(), env, []string{"p43", "https://ghp_planted@github.com/example/my-platform"}); err == nil {
		t.Fatal("run accepted a credential in the repository URL")
	}
	if len(f.applied) != 0 {
		t.Errorf("applied %d streams before refusing", len(f.applied))
	}
	meta, _ := dir.LoadInstanceMetadata("p43")
	if len(meta.Deployments) != 0 {
		t.Errorf("recorded %+v", meta.Deployments)
	}
}

// The second lock: whatever reaches the provenance write has no credential
// in it, and a record from before the refusal compares — and is named in a
// refusal — without its credential.
func TestProvenanceNeverHoldsACredential(t *testing.T) {
	dir := config.Dir(t.TempDir())
	runnableInstance(t, dir, "p43")
	env, _ := testEnv(dir, output.ModeHuman)
	c := runCmd(newFakeRun(twoAppManifest))
	c.recordProvenance(env, "p43", "my-platform", "https://x-access-token:ghp_planted@github.com/example/my-platform", pfetch.Report{Commit: testCommit}, false)
	raw, err := os.ReadFile(filepath.Join(dir.InstancePath("p43"), "metadata.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "ghp_planted") || !strings.Contains(string(raw), "repository: https://github.com/example/my-platform") {
		t.Errorf("the record:\n%s", raw)
	}

	recordDeployment(t, dir, "p43", "my-platform", "https://ghp_planted@github.com/someone-else/platform")
	err = runCmd(newFakeRun(twoAppManifest)).Run(context.Background(), env, []string{"p43", "github.com/example/my-platform"})
	if err == nil || strings.Contains(err.Error(), "ghp_planted") || !strings.Contains(err.Error(), "https://github.com/someone-else/platform") {
		t.Errorf("the refusal: %v", err)
	}

	recordDeployment(t, dir, "p43", "my-platform", "https://ghp_planted@github.com/example/my-platform")
	if err := runCmd(newFakeRun(twoAppManifest)).Run(context.Background(), env, []string{"p43", "github.com/example/my-platform"}); err != nil {
		t.Errorf("the same repository, recorded with a credential, was refused: %v", err)
	}
}

// A manifest named like the instance's own namespace, or a managed one, is
// refused as --namespace would be: after the read, before anything is built,
// written to the policy or deployed.
func TestRunRefusesAManifestNamedLikeASystemNamespace(t *testing.T) {
	for _, ns := range []string{"farcast-system", "kube-public"} {
		t.Run(ns, func(t *testing.T) {
			dir := config.Dir(t.TempDir())
			runnableInstance(t, dir, "p43")
			env, _ := testEnv(dir, output.ModeHuman)
			f := newFakeRun(strings.Replace(twoAppManifest, "name: my-platform", "name: "+ns, 1))
			err := runCmd(f).Run(context.Background(), env, []string{"p43", "github.com/example/my-platform"})
			if err == nil {
				t.Fatalf("run deployed into %s", ns)
			}
			var usage *usageError
			if !errors.As(err, &usage) || !strings.Contains(err.Error(), "nothing was built or deployed") {
				t.Errorf("err = %v, want a usage error that says nothing was built or deployed", err)
			}
			if wroteAnything(t, f) {
				t.Errorf("something past the read reached the cluster: %v", appliedKinds(t, f))
			}
			if meta, _ := dir.LoadInstanceMetadata("p43"); len(meta.Deployments) != 0 {
				t.Errorf("a refused run recorded provenance: %+v", meta.Deployments)
			}
		})
	}
}
