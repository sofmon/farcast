package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/sofmon/farcast/datasphere"
	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/fatline/policy"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/manifest/parser"
	pbuild "github.com/sofmon/farcast/planck/build"
	pfetch "github.com/sofmon/farcast/planck/fetch"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
	"github.com/sofmon/farcast/technocore/kernel"
)

const (
	fetcherDigest = "cgr.dev/chainguard/git@sha256:" +
		"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	testCommit = "4f2a9c1e8b7d6a5f4e3c2b1a0f9e8d7c6b5a4938"
	testBranch = "refs/heads/main"
)

const twoAppManifest = `name: my-platform
apps:
  - name: api
    containerfile: services/api/Containerfile
    context: services/api
    external:
      - host: api.stripe.com
        reason: payment processing
      - host: sentry.io
        reason: error reporting
  - name: web
    containerfile: services/web/Containerfile
`

// fakeRunCluster answers each Job according to what it is: the fetch prints a
// manifest and reports a commit, a build reports a digest.
type fakeRunCluster struct {
	manifest string
	report   string

	applied    []string
	waited     []string
	rollouts   []string
	tails      []int
	jobs       map[string]bool
	configMaps map[string]string

	buildFails bool
	// buildLogs is what a failing build printed. It defaults to something
	// unremarkable so a test that cares about the OUTPUT has to say so.
	buildLogs  string
	fetchFails bool
	applyErr   error
	rolloutErr error
}

func (f *fakeRunCluster) Apply(_ context.Context, m []byte) error {
	f.applied = append(f.applied, string(m))
	if f.jobs == nil {
		f.jobs = map[string]bool{}
	}
	for _, d := range strings.Split(string(m), "\n---\n") {
		var doc struct {
			Kind     string `yaml:"kind"`
			Metadata struct {
				Name string `yaml:"name"`
			} `yaml:"metadata"`
		}
		if yaml.Unmarshal([]byte(d), &doc) == nil && doc.Kind == "Job" {
			f.jobs[doc.Metadata.Name] = true
		}
	}
	return f.applyErr
}

// WaitJob refuses to answer for a Job that was never created.
//
// A fake that answered by name PREFIX would let a caller wait on a Job the
// renderer did not produce — which is exactly the defect this caught: the ref
// is defaulted inside Render before the Job is named, so a caller deriving the
// name from its own config watched something that did not exist. Against a
// real cluster that is a timeout, and a timeout reads like a slow clone.
func (f *fakeRunCluster) WaitJob(_ context.Context, ns, name string, _ time.Duration) (cluster.JobResult, error) {
	f.waited = append(f.waited, name)
	if !f.jobs[name] {
		return cluster.JobResult{}, fmt.Errorf("no Job %q was ever applied; applied: %v", name, f.jobs)
	}
	if strings.HasPrefix(name, "fetch-") {
		return cluster.JobResult{Succeeded: !f.fetchFails, Message: f.report}, nil
	}
	if f.buildFails {
		return cluster.JobResult{Succeeded: false, Message: "boom"}, nil
	}
	return cluster.JobResult{Succeeded: true, Message: "sha256:" + strings.Repeat("c", 64)}, nil
}

// JobLogs honours the tail it is asked for, because a fetch's whole output IS
// the manifest: a caller that asks for the last N lines of it gets a document
// that parses and is missing its first applications.
func (f *fakeRunCluster) JobLogs(_ context.Context, _, job string, lines int) (string, error) {
	body := "build output\n"
	if f.buildLogs != "" {
		body = f.buildLogs
	}
	if strings.HasPrefix(job, "fetch-") {
		body = f.manifest
	}
	f.tails = append(f.tails, lines)
	if lines <= 0 {
		return body, nil
	}
	split := strings.SplitAfter(body, "\n")
	if len(split) > lines {
		split = split[len(split)-lines:]
	}
	return strings.Join(split, ""), nil
}

// ConfigMapValue answers the egress-policy read. An empty map is an instance
// that has never deployed an application.
func (f *fakeRunCluster) ConfigMapValue(_ context.Context, ns, name, key string) (string, bool, error) {
	v, ok := f.configMaps[ns+"/"+name+"/"+key]
	return v, ok, nil
}

func (f *fakeRunCluster) RolloutStatus(_ context.Context, ns, name string, _ time.Duration) error {
	f.rollouts = append(f.rollouts, ns+"/"+name)
	return f.rolloutErr
}

func reportFor(manifest string) string {
	sum := sha256.Sum256([]byte(manifest))
	return "commit=" + testCommit + " manifest=sha256:" + hex.EncodeToString(sum[:])
}

func newFakeRun(manifest string) *fakeRunCluster {
	return &fakeRunCluster{manifest: manifest, report: reportFor(manifest)}
}

func runnableInstance(t *testing.T, dir config.Dir, name string) *config.InstanceMetadata {
	t.Helper()
	meta := buildableInstance(t, dir, name)
	meta.Kernel = &config.Kernel{Deployed: true, Namespaces: []string{"farcast-system"}}
	meta.CostLimit = config.CostLimit{Amount: 500, Currency: "USD", Period: "monthly"}
	if err := dir.SaveInstanceMetadata(name, meta); err != nil {
		t.Fatal(err)
	}
	return meta
}

func runCmd(f *fakeRunCluster) *runCommand {
	c := &runCommand{assumeYes: true}
	c.newCluster = func(string) runCluster { return f }
	c.newBuilder = func(func(string)) imageBuilder { return &fakeBuilder{} }
	c.fetcherImage, c.builderImage = fetcherDigest, builderDigest
	return c
}

// applied returns the one applied stream containing the marker, and fails if
// there is not exactly one. Grepping the whole transcript is how the 4.2 walk
// produced three false passes.
func appliedWith(t *testing.T, f *fakeRunCluster, marker string) string {
	t.Helper()
	var hits []string
	for _, s := range f.applied {
		if strings.Contains(s, marker) {
			hits = append(hits, s)
		}
	}
	if len(hits) != 1 {
		t.Fatalf("%d applied streams contain %q, want 1", len(hits), marker)
	}
	return hits[0]
}

// docsIn parses an applied stream into (kind, name) pairs.
//
// Parsed, not grepped. The fetch's own NetworkPolicy carries a comment naming
// "farcast-builder" to explain why it is NOT that account, and a test that
// searched the text for it would report a build that never happened — which is
// the false pass the 4.2 walk produced three times.
func docsIn(t *testing.T, stream string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, d := range strings.Split(stream, "\n---\n") {
		if strings.TrimSpace(d) == "" {
			continue
		}
		var m struct {
			Kind     string `yaml:"kind"`
			Metadata struct {
				Name      string `yaml:"name"`
				Namespace string `yaml:"namespace"`
			} `yaml:"metadata"`
		}
		if err := yaml.Unmarshal([]byte(d), &m); err != nil {
			t.Fatalf("an applied document is not valid YAML: %v\n%s", err, d)
		}
		out[m.Kind+"/"+m.Metadata.Name] = m.Metadata.Namespace
	}
	return out
}

// applyedKinds is every (kind, name) the run applied, across all streams.
func appliedKinds(t *testing.T, f *fakeRunCluster) map[string]string {
	t.Helper()
	all := map[string]string{}
	for _, s := range f.applied {
		for k, v := range docsIn(t, s) {
			all[k] = v
		}
	}
	return all
}

func builtAnything(t *testing.T, f *fakeRunCluster) bool {
	t.Helper()
	for name := range appliedKinds(t, f) {
		if strings.HasPrefix(name, "Job/build-") || strings.HasPrefix(name, "Deployment/") {
			return true
		}
	}
	return false
}

// The property the whole design turns on: the operator approves what the
// instance READ, and what gets built is that same commit — never the branch,
// which may have moved between the two clones (ADR 0010 decision 11).
func TestRunBuildsTheCommitItRead(t *testing.T) {
	dir := config.Dir(t.TempDir())
	runnableInstance(t, dir, "p43")
	env, _ := testEnv(dir, output.ModeHuman)

	f := newFakeRun(twoAppManifest)
	c := runCmd(f)
	if err := c.Run(context.Background(), env, []string{"p43", "github.com/example/my-platform"}); err != nil {
		t.Fatal(err)
	}

	for _, app := range []string{"api", "web"} {
		job := pbuild.JobName("my-platform", app)
		stream := appliedWith(t, f, "name: "+job+"\n")
		if !strings.Contains(stream, "--context=git://github.com/example/my-platform#"+testCommit) {
			t.Errorf("the build of %s is not pinned to the commit that was read:\n%s", app, stream)
		}
		if strings.Contains(stream, "#"+testBranch) || strings.Contains(stream, "#refs/heads/") {
			t.Errorf("the build of %s clones a branch, so a push between the read and the build changes what runs", app)
		}
	}
}

// A read whose bytes do not match the digest the instance computed is not a
// read. Nothing may be built from it, because the operator would be approving
// one thing and deploying another.
func TestRunRefusesAManifestThatDidNotArriveWhole(t *testing.T) {
	dir := config.Dir(t.TempDir())
	runnableInstance(t, dir, "p43")
	env, _ := testEnv(dir, output.ModeHuman)

	f := newFakeRun(twoAppManifest)
	f.manifest = twoAppManifest + "  - name: smuggled\n    containerfile: x/Containerfile\n"

	c := runCmd(f)
	err := c.Run(context.Background(), env, []string{"p43", "github.com/example/my-platform"})
	if err == nil {
		t.Fatal("run accepted a manifest that does not match the digest the instance reported")
	}
	if !strings.Contains(err.Error(), "hashes to") {
		t.Errorf("unhelpful error: %v", err)
	}
	if builtAnything(t, f) {
		t.Errorf("something was built or deployed despite the manifest failing verification: %v", appliedKinds(t, f))
	}
}

// The gate is the declarations. Every host and every reason has to be in front
// of the operator, because FatLine will allow exactly these and nothing else.
func TestTheGateShowsEveryDeclarationAndWhatItIsFor(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meta := runnableInstance(t, dir, "p43")

	m, err := parseTestManifest(twoAppManifest)
	if err != nil {
		t.Fatal(err)
	}
	rev := review{
		Instance: "p43", Repo: "https://github.com/example/my-platform", Namespace: "my-platform",
		Manifest:        *m,
		Report:          pfetch.Report{Commit: testCommit, ManifestDigest: "sha256:" + strings.Repeat("e", 64)},
		FatLineDeployed: true, Limit: meta.CostLimit, Floor: floorNow(meta),
	}
	var b strings.Builder
	rev.print(&b)
	shown := b.String()

	for _, want := range []string{
		testCommit,
		"sha256:" + strings.Repeat("e", 64),
		"api.stripe.com", "payment processing",
		"sentry.io", "error reporting",
		"api", "web",
		"services/api/Containerfile",
	} {
		if !strings.Contains(shown, want) {
			t.Errorf("the review never shows %q:\n%s", want, shown)
		}
	}
	if !strings.Contains(shown, "reaches nothing outside the instance") {
		t.Errorf("an app with no declarations is not shown as reaching nothing:\n%s", shown)
	}
}

// FatLine is the only way out. Declaring hosts on an instance that has no
// tunnel is a deployment that will not work, and saying so before the build
// costs money is the point of a gate.
func TestTheGateWarnsWhenThereIsNoWayOut(t *testing.T) {
	m, err := parseTestManifest(twoAppManifest)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	review{Instance: "p43", Manifest: *m, FatLineDeployed: false,
		Limit: config.CostLimit{Amount: 500, Currency: "USD", Period: "monthly"}}.print(&b)
	if !strings.Contains(b.String(), "FatLine is not deployed") {
		t.Errorf("no warning that the declared hosts are unreachable:\n%s", b.String())
	}
}

// A build asks for a whole vCPU and 2 GiB, and Autopilot bills the request. Ten
// applications built in parallel is ten times the burn for the length of the
// slowest, which is a hole in the cost limit rather than a speed-up.
func TestBuildsRunOneAtATime(t *testing.T) {
	dir := config.Dir(t.TempDir())
	runnableInstance(t, dir, "p43")
	env, _ := testEnv(dir, output.ModeHuman)

	f := newFakeRun(twoAppManifest)
	if err := runCmd(f).Run(context.Background(), env, []string{"p43", "github.com/example/my-platform"}); err != nil {
		t.Fatal(err)
	}
	// fetch, api, web — each waited on before the next is applied.
	want := []string{
		pfetch.Config{Repo: "https://github.com/example/my-platform"}.Job(),
		pbuild.JobName("my-platform", "api"),
		pbuild.JobName("my-platform", "web"),
	}
	if len(f.waited) != len(want) {
		t.Fatalf("waited on %v, want %v", f.waited, want)
	}
	for i := range want {
		if f.waited[i] != want[i] {
			t.Errorf("waited on %q at position %d, want %q", f.waited[i], i, want[i])
		}
	}
}

func TestApplicationsAreDeployedByDigestNotByTag(t *testing.T) {
	dir := config.Dir(t.TempDir())
	runnableInstance(t, dir, "p43")
	env, _ := testEnv(dir, output.ModeHuman)

	f := newFakeRun(twoAppManifest)
	if err := runCmd(f).Run(context.Background(), env, []string{"p43", "github.com/example/my-platform"}); err != nil {
		t.Fatal(err)
	}
	workloads := appliedWith(t, f, "kind: Deployment")
	for _, line := range strings.Split(workloads, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "image:") {
			continue
		}
		if !strings.Contains(trimmed, "@sha256:") {
			t.Errorf("deployed by tag, not digest: %s", trimmed)
		}
		if strings.Contains(trimmed, ":"+shortCommit(testCommit)+"@") {
			t.Errorf("the reference keeps both a tag and a digest: %s", trimmed)
		}
	}
}

func TestRunMetersWhatItDeployed(t *testing.T) {
	dir := config.Dir(t.TempDir())
	runnableInstance(t, dir, "p43")
	env, _ := testEnv(dir, output.ModeHuman)

	f := newFakeRun(twoAppManifest)
	if err := runCmd(f).Run(context.Background(), env, []string{"p43", "github.com/example/my-platform"}); err != nil {
		t.Fatal(err)
	}
	// The kernel's own list, not one of the per-app ConfigMaps the translator
	// also emits.
	list := "ConfigMap/" + kernel.DefaultNamespacesName
	if ns, ok := appliedKinds(t, f)[list]; !ok {
		t.Fatalf("the kernel's namespace list was never applied: %v", appliedKinds(t, f))
	} else if ns != tcdeploy.DefaultNamespace {
		t.Errorf("the kernel's namespace list went to %q, want %q", ns, tcdeploy.DefaultNamespace)
	}
	if !strings.Contains(appliedWith(t, f, "ConfigMap\nmetadata:\n  name: "+kernel.DefaultNamespacesName), "my-platform") {
		t.Error("the kernel's namespace list does not mention the new namespace")
	}
	meta, err := dir.LoadInstanceMetadata("p43")
	if err != nil {
		t.Fatal(err)
	}
	if !contains(meta.Kernel.Namespaces, "my-platform") {
		t.Errorf("local state does not record %q as metered: %v", "my-platform", meta.Kernel.Namespaces)
	}
}

// Deploying without a kernel is allowed and is reported. Silence would leave
// applications running, billing, and outside the one guard that stops them.
func TestRunWithoutAKernelSaysSoLoudly(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meta := buildableInstance(t, dir, "p43")
	meta.CostLimit = config.CostLimit{Amount: 500, Currency: "USD", Period: "monthly"}
	if err := dir.SaveInstanceMetadata("p43", meta); err != nil {
		t.Fatal(err)
	}
	env, out := testEnv(dir, output.ModeHuman)

	f := newFakeRun(twoAppManifest)
	if err := runCmd(f).Run(context.Background(), env, []string{"p43", "github.com/example/my-platform"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "NOT METERED") {
		t.Errorf("a deployment nothing is counting did not say so:\n%s", out.String())
	}
}

func TestRunRecordsTheReviewedImagesSoTheNextRunNeedNotBeTold(t *testing.T) {
	dir := config.Dir(t.TempDir())
	runnableInstance(t, dir, "p43")
	env, _ := testEnv(dir, output.ModeHuman)

	f := newFakeRun(twoAppManifest)
	if err := runCmd(f).Run(context.Background(), env, []string{"p43", "github.com/example/my-platform"}); err != nil {
		t.Fatal(err)
	}
	meta, err := dir.LoadInstanceMetadata("p43")
	if err != nil {
		t.Fatal(err)
	}
	if meta.Toolchain == nil || meta.Toolchain.Fetcher != fetcherDigest || meta.Toolchain.Builder != builderDigest {
		t.Fatalf("the reviewed images were not recorded: %+v", meta.Toolchain)
	}

	// And a second run, told nothing, uses them.
	f2 := newFakeRun(twoAppManifest)
	c2 := &runCommand{assumeYes: true}
	c2.newCluster = func(string) runCluster { return f2 }
	c2.newBuilder = func(func(string)) imageBuilder { return &fakeBuilder{} }
	if err := c2.Run(context.Background(), env, []string{"p43", "github.com/example/my-platform"}); err != nil {
		t.Fatalf("a second run had to be told the images again: %v", err)
	}
	if !strings.Contains(appliedWith(t, f2, "farcast-fetcher\n"), fetcherDigest) {
		t.Error("the recorded fetcher image was not used")
	}
}

func TestRunRefusesAnUnpinnedImage(t *testing.T) {
	for name, mutate := range map[string]func(*runCommand){
		"an unpinned fetcher": func(c *runCommand) { c.fetcherImage = "cgr.dev/chainguard/git:latest-dev" },
		"an unpinned builder": func(c *runCommand) { c.builderImage = "cgr.dev/chainguard/kaniko:latest" },
		"no fetcher at all":   func(c *runCommand) { c.fetcherImage = "" },
		"no builder at all":   func(c *runCommand) { c.builderImage = "" },
	} {
		t.Run(name, func(t *testing.T) {
			dir := config.Dir(t.TempDir())
			runnableInstance(t, dir, "p43")
			env, _ := testEnv(dir, output.ModeHuman)
			f := newFakeRun(twoAppManifest)
			c := runCmd(f)
			mutate(c)
			if err := c.Run(context.Background(), env, []string{"p43", "github.com/example/my-platform"}); err == nil {
				t.Fatalf("run accepted %s", name)
			}
			if len(f.applied) != 0 {
				t.Errorf("%s still reached the cluster", name)
			}
		})
	}
}

func TestRepoURL(t *testing.T) {
	for in, want := range map[string]string{
		"github.com/user/repo":          "https://github.com/user/repo",
		"https://github.com/user/repo":  "https://github.com/user/repo",
		"github.com/user/repo/":         "https://github.com/user/repo",
		"  github.com/user/repo  ":      "https://github.com/user/repo",
		"gitlab.example.test/a/b/c":     "https://gitlab.example.test/a/b/c",
		"https://github.com/user/repo/": "https://github.com/user/repo",
	} {
		got, err := repoURL(in)
		if err != nil {
			t.Errorf("repoURL(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("repoURL(%q) = %q, want %q", in, got, want)
		}
	}
	for _, in := range []string{
		"", "  ",
		"http://github.com/user/repo",
		"git://github.com/user/repo",
		"ssh://git@github.com/user/repo",
		"git@github.com:user/repo.git",
		"/home/me/repo",
		"./repo",
		"justaword",
		"nodots/path",
	} {
		if got, err := repoURL(in); err == nil {
			t.Errorf("repoURL(%q) = %q, want an error", in, got)
		}
	}
}

func TestAbortingBuildsNothing(t *testing.T) {
	dir := config.Dir(t.TempDir())
	runnableInstance(t, dir, "p43")
	env, _ := testEnv(dir, output.ModeHuman)

	f := newFakeRun(twoAppManifest)
	c := runCmd(f)
	c.assumeYes = false // stdin is not a terminal, so it cannot be approved

	if err := c.Run(context.Background(), env, []string{"p43", "github.com/example/my-platform"}); err == nil {
		t.Fatal("a non-interactive run without --yes deployed without approval")
	}
	if builtAnything(t, f) {
		t.Errorf("something was built or deployed without approval: %v", appliedKinds(t, f))
	}
}

// A failed build stops everything. Deploying the applications that did build
// would leave half a manifest running, which is neither the old deployment nor
// the new one.
func TestAFailedBuildDeploysNothing(t *testing.T) {
	dir := config.Dir(t.TempDir())
	runnableInstance(t, dir, "p43")
	env, _ := testEnv(dir, output.ModeHuman)

	f := newFakeRun(twoAppManifest)
	f.buildFails = true
	err := runCmd(f).Run(context.Background(), env, []string{"p43", "github.com/example/my-platform"})
	if err == nil {
		t.Fatal("a failed build was not reported")
	}
	for name := range appliedKinds(t, f) {
		if strings.HasPrefix(name, "Deployment/") {
			t.Errorf("%s was deployed after a build failed", name)
		}
	}
	if len(f.rollouts) != 0 {
		t.Errorf("waited for rollouts after a build failed: %v", f.rollouts)
	}
}

func TestStorageIsWiredWhenTheInstanceHasAKeyholder(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meta := runnableInstance(t, dir, "p43")
	meta.Keyholder = &config.Keyholder{Deployed: true}
	if err := dir.SaveInstanceMetadata("p43", meta); err != nil {
		t.Fatal(err)
	}
	mintKeyring(t, dir, "p43")
	env, _ := testEnv(dir, output.ModeHuman)

	f := newFakeRun(twoAppManifest)
	if err := runCmd(f).Run(context.Background(), env, []string{"p43", "github.com/example/my-platform"}); err != nil {
		t.Fatal(err)
	}
	workloads := appliedWith(t, f, "kind: Deployment")
	for _, want := range []string{"FARCAST_STORAGE_SCOPE", "BEGIN CERTIFICATE"} {
		if !strings.Contains(workloads, want) {
			t.Errorf("storage is not wired into the translated workloads: no %s", want)
		}
	}
	// Each application is also given its identity on the data path, minted
	// from this machine's CA key (ADR 0018 decision 1).
	for _, want := range []string{"FARCAST_STORAGE_CLIENT_CERT", "FARCAST_STORAGE_CLIENT_KEY", "BEGIN PRIVATE KEY"} {
		if !strings.Contains(workloads, want) {
			t.Errorf("no storage identity reached the workloads: no %s", want)
		}
	}
}

// A machine without the CA key cannot mint an application's storage identity,
// and must say so rather than deploy an application that reaches nothing.
func TestRunRefusesStorageWithoutTheCAKey(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meta := runnableInstance(t, dir, "p43")
	meta.Keyholder = &config.Keyholder{Deployed: true}
	if err := dir.SaveInstanceMetadata("p43", meta); err != nil {
		t.Fatal(err)
	}
	mintKeyring(t, dir, "p43")
	mtls, err := dir.LoadInstanceMTLS("p43")
	if err != nil {
		t.Fatal(err)
	}
	mtls.CAKeyPEM = nil
	if err := dir.SaveInstanceMTLS("p43", mtls); err != nil {
		t.Fatal(err)
	}
	env, _ := testEnv(dir, output.ModeHuman)
	f := newFakeRun(twoAppManifest)
	err = runCmd(f).Run(context.Background(), env, []string{"p43", "github.com/example/my-platform"})
	if err == nil || !strings.Contains(err.Error(), "CA key") {
		t.Fatalf("err = %v, want a refusal naming the missing CA key", err)
	}
	for name := range appliedKinds(t, f) {
		if strings.HasPrefix(name, "Deployment/") {
			t.Errorf("%s was deployed without a storage identity", name)
		}
	}
}

func TestWithoutAKeyholderNoStorageIsWired(t *testing.T) {
	dir := config.Dir(t.TempDir())
	runnableInstance(t, dir, "p43")
	env, _ := testEnv(dir, output.ModeHuman)

	f := newFakeRun(twoAppManifest)
	if err := runCmd(f).Run(context.Background(), env, []string{"p43", "github.com/example/my-platform"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(appliedWith(t, f, "kind: Deployment"), "BEGIN CERTIFICATE") {
		t.Error("an instance with no key holder still got a CA wired into its applications")
	}
}

func parseTestManifest(s string) (*parser.Manifest, error) { return parser.Parse([]byte(s)) }

// A manifest longer than any sensible tail. The read must return all of it:
// the log IS the document, and a truncated one parses perfectly with its first
// applications simply absent.
func TestALongManifestIsReadWhole(t *testing.T) {
	var b strings.Builder
	b.WriteString("name: big\napps:\n")
	const apps = 20
	for i := range apps {
		fprintf(&b, "  - name: app-%02d\n    containerfile: svc/%02d/Containerfile\n    context: svc/%02d\n", i, i, i)
	}
	manifest := b.String()
	if n := strings.Count(manifest, "\n"); n <= 40 {
		t.Fatalf("the fixture is only %d lines; it must exceed the tail a failure would use", n)
	}

	dir := config.Dir(t.TempDir())
	runnableInstance(t, dir, "p43")
	env, _ := testEnv(dir, output.ModeHuman)

	f := newFakeRun(manifest)
	if err := runCmd(f).Run(context.Background(), env, []string{"p43", "github.com/example/big"}); err != nil {
		t.Fatal(err)
	}
	kinds := appliedKinds(t, f)
	for i := range apps {
		want := fmt.Sprintf("Deployment/app-%02d", i)
		if _, ok := kinds[want]; !ok {
			t.Errorf("%s was never deployed; the manifest was read short", want)
		}
	}
}

// A read that failed says why in its termination message — "no farcast at
// <commit> in <repo>" is the operator's answer, and restating it as "the read
// failed" would throw away the only useful part.
func TestAFailedReadReportsWhatTheInstanceSaid(t *testing.T) {
	dir := config.Dir(t.TempDir())
	runnableInstance(t, dir, "p43")
	env, _ := testEnv(dir, output.ModeHuman)

	f := newFakeRun(twoAppManifest)
	f.fetchFails = true
	f.report = "no farcast at " + testCommit + " in https://github.com/example/my-platform"

	err := runCmd(f).Run(context.Background(), env, []string{"p43", "github.com/example/my-platform"})
	if err == nil {
		t.Fatal("a failed read was reported as success")
	}
	if !strings.Contains(err.Error(), "no farcast at "+testCommit) {
		t.Errorf("the instance's own diagnosis was lost: %v", err)
	}
	if builtAnything(t, f) {
		t.Errorf("something was built after the read failed: %v", appliedKinds(t, f))
	}
}

// Deploying a manifest under a name it does not declare is how one deployment
// lands on top of another, so the gate says it rather than showing the target
// namespace as if the manifest had asked for it.
func TestTheGateSaysWhenTheNamespaceIsNotTheManifestsOwn(t *testing.T) {
	m, err := parseTestManifest(twoAppManifest)
	if err != nil {
		t.Fatal(err)
	}
	limit := config.CostLimit{Amount: 500, Currency: "USD", Period: "monthly"}

	var same, other strings.Builder
	review{Instance: "p43", Manifest: *m, Namespace: m.Name, Limit: limit, FatLineDeployed: true}.print(&same)
	review{Instance: "p43", Manifest: *m, Namespace: "staging", Limit: limit, FatLineDeployed: true}.print(&other)

	if strings.Contains(same.String(), "instead") {
		t.Errorf("deploying under the manifest's own name is reported as an override:\n%s", same.String())
	}
	if !strings.Contains(other.String(), `"staging"`) || !strings.Contains(other.String(), "instead") {
		t.Errorf("an overridden namespace is not called out:\n%s", other.String())
	}
}

// Checked before the fetch, because an unusable namespace discovered after a
// read and a build would have cost money to find out.
func TestAnUnusableNamespaceIsRefusedBeforeAnythingIsSpent(t *testing.T) {
	for name, ns := range map[string]string{
		"the system namespace": tcdeploy.DefaultNamespace,
		"not a DNS label":      "Not_A_Label",
		"leading hyphen":       "-nope",
	} {
		t.Run(name, func(t *testing.T) {
			dir := config.Dir(t.TempDir())
			runnableInstance(t, dir, "p43")
			env, _ := testEnv(dir, output.ModeHuman)

			f := newFakeRun(twoAppManifest)
			c := runCmd(f)
			c.namespace = ns
			if err := c.Run(context.Background(), env, []string{"p43", "github.com/example/my-platform"}); err == nil {
				t.Fatalf("run accepted --namespace %q", ns)
			}
			if len(f.applied) != 0 {
				t.Errorf("%q reached the cluster before being refused", ns)
			}
		})
	}
}

// policyIn returns the egress policy a run applied.
func policyIn(t *testing.T, f *fakeRunCluster) *policy.Document {
	t.Helper()
	stream := appliedWith(t, f, "ConfigMap\nmetadata:\n  name: "+fldeploy.PolicyConfigMap)
	var doc struct {
		Data map[string]string `yaml:"data"`
	}
	if err := yaml.Unmarshal([]byte(stream), &doc); err != nil {
		t.Fatalf("the applied policy is not valid YAML: %v", err)
	}
	parsed, err := policy.Parse([]byte(doc.Data[fldeploy.PolicyKey]))
	if err != nil {
		t.Fatalf("the applied policy does not parse: %v", err)
	}
	return parsed
}

// One FatLine serves every application on an instance, so a run that wrote only
// its own deployment would silently revoke every other one's egress. The same
// shape as the metering a redeploy erased on the 4.2 walk, reached from a
// different direction.
func TestRunKeepsOtherDeploymentsEgressPolicy(t *testing.T) {
	dir := config.Dir(t.TempDir())
	runnableInstance(t, dir, "p44")
	env, _ := testEnv(dir, output.ModeHuman)

	// An instance that already runs somebody else's deployment.
	existing := &policy.Document{Version: policy.Version, Apps: []policy.App{{
		Name: "worker", Namespace: "other-deployment",
		CredentialSHA256: policy.HashCredential("their-credential"),
		External:         []parser.External{{Host: "queue.example", Reason: "jobs"}},
	}}}
	body, err := existing.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	f := newFakeRun(twoAppManifest)
	f.configMaps = map[string]string{
		fldeploy.DefaultNamespace + "/" + fldeploy.PolicyConfigMap + "/" + fldeploy.PolicyKey: string(body),
	}

	if err := runCmd(f).Run(context.Background(), env, []string{"p44", "github.com/example/my-platform"}); err != nil {
		t.Fatal(err)
	}

	doc := policyIn(t, f)
	if _, ok := doc.Identify("their-credential"); !ok {
		t.Fatal("the other deployment's application lost its egress policy")
	}
	var mine int
	for _, app := range doc.Apps {
		if app.Namespace == "manifest-elsewhere" || app.Namespace == "my-platform" {
			mine++
		}
	}
	if mine != 2 {
		t.Errorf("this deployment contributed %d applications, want 2: %+v", mine, doc.Apps)
	}
}

// Each application gets its own credential and its own declarations, and the
// document carries neither in a form that reveals a credential.
func TestRunWritesAPerApplicationPolicy(t *testing.T) {
	dir := config.Dir(t.TempDir())
	runnableInstance(t, dir, "p44")
	env, _ := testEnv(dir, output.ModeHuman)

	f := newFakeRun(twoAppManifest)
	if err := runCmd(f).Run(context.Background(), env, []string{"p44", "github.com/example/my-platform"}); err != nil {
		t.Fatal(err)
	}
	doc := policyIn(t, f)

	byName := map[string]policy.App{}
	for _, app := range doc.Apps {
		byName[app.Name] = app
	}
	if len(byName["api"].External) != 2 {
		t.Errorf("api declared %v, want its two hosts", byName["api"].External)
	}
	if len(byName["web"].External) != 0 {
		t.Errorf("web inherited %v; it declares nothing", byName["web"].External)
	}
	if byName["api"].CredentialSHA256 == byName["web"].CredentialSHA256 {
		t.Fatal("both applications share a credential; they would be indistinguishable")
	}

	// The credential each app actually received must be the one the policy
	// recognises — the join between the Secret and the document.
	workloads := appliedWith(t, f, "kind: Deployment")
	for _, app := range []string{"api", "web"} {
		credential := credentialFromSecret(t, f, app)
		got, ok := doc.Identify(credential)
		if !ok {
			t.Fatalf("%s's credential is not in the policy FatLine will enforce", app)
		}
		if got.Name != app {
			t.Errorf("%s's credential identifies %q", app, got.Name)
		}
	}
	_ = workloads
}

// credentialFromSecret lifts an app's egress credential out of the Secret the
// translator rendered, the way the container will receive it.
func credentialFromSecret(t *testing.T, f *fakeRunCluster, app string) string {
	t.Helper()
	stream := appliedWith(t, f, "kind: Secret\nmetadata:\n  name: "+app+"-egress")
	for _, d := range strings.Split(stream, "\n---\n") {
		var m struct {
			Kind     string `yaml:"kind"`
			Metadata struct {
				Name string `yaml:"name"`
			} `yaml:"metadata"`
			StringData map[string]string `yaml:"stringData"`
		}
		if yaml.Unmarshal([]byte(d), &m) != nil || m.Metadata.Name != app+"-egress" {
			continue
		}
		raw := m.StringData["FARCAST_FATLINE_PROXY"]
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("%s's proxy address does not parse: %q", app, raw)
		}
		credential, _ := u.User.Password()
		if credential == "" {
			t.Fatalf("%s's proxy address carries no credential: %q", app, raw)
		}
		return credential
	}
	t.Fatalf("no egress Secret for %s", app)
	return ""
}

// An unreadable existing policy must stop the deploy, not be replaced: writing
// a fresh document would revoke every application already running.
func TestRunRefusesToReplaceAnUnreadablePolicy(t *testing.T) {
	dir := config.Dir(t.TempDir())
	runnableInstance(t, dir, "p44")
	env, _ := testEnv(dir, output.ModeHuman)

	f := newFakeRun(twoAppManifest)
	f.configMaps = map[string]string{
		fldeploy.DefaultNamespace + "/" + fldeploy.PolicyConfigMap + "/" + fldeploy.PolicyKey: "{ not json",
	}
	err := runCmd(f).Run(context.Background(), env, []string{"p44", "github.com/example/my-platform"})
	if err == nil {
		t.Fatal("run replaced a policy it could not read")
	}
	if !strings.Contains(err.Error(), "revoke every application") {
		t.Errorf("the refusal does not say what was at stake: %v", err)
	}
}

// An application removed from a manifest must stop being allowed anything.
// Merging naively would leave its old entry in force forever — an application
// nobody deploys any more, still permitted its old hosts, and still identified
// by a credential nothing rotates.
func TestRedeployingWithoutAnAppRevokesIt(t *testing.T) {
	dir := config.Dir(t.TempDir())
	runnableInstance(t, dir, "p44")
	env, _ := testEnv(dir, output.ModeHuman)

	// The instance already runs THIS deployment with a third app.
	existing := &policy.Document{Version: policy.Version, Apps: []policy.App{{
		Name: "retired", Namespace: "my-platform",
		CredentialSHA256: policy.HashCredential("retired-credential"),
		External:         []parser.External{{Host: "old.example", Reason: "gone"}},
	}}}
	body, err := existing.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	f := newFakeRun(twoAppManifest) // declares api and web, not retired
	f.configMaps = map[string]string{
		fldeploy.DefaultNamespace + "/" + fldeploy.PolicyConfigMap + "/" + fldeploy.PolicyKey: string(body),
	}

	if err := runCmd(f).Run(context.Background(), env, []string{"p44", "github.com/example/my-platform"}); err != nil {
		t.Fatal(err)
	}

	doc := policyIn(t, f)
	if _, ok := doc.Identify("retired-credential"); ok {
		t.Fatal("an application dropped from the manifest kept its egress credential")
	}
	for _, app := range doc.Apps {
		if app.Name == "retired" {
			t.Fatalf("the retired application is still in the policy: %+v", app)
		}
	}
}

// `run` printed the grant nowhere at all, though the 4.3 runbook recorded that
// it "prints it, like build does". Both halves of that sentence were wrong.
func TestRunNamesTheGrantWhenAPushIsRefused(t *testing.T) {
	dir := config.Dir(t.TempDir())
	runnableInstance(t, dir, "p42")
	env, _ := testEnv(dir, output.ModeHuman)

	f := newFakeRun(twoAppManifest)
	f.buildFails = true
	f.buildLogs = arDenial

	if err := runCmd(f).Run(context.Background(), env, []string{"p42", "github.com/example/my-platform"}); err == nil {
		t.Fatal("a failed build reported success")
	}
	errOut := env.Err.(interface{ String() string }).String()
	for _, want := range []string{"not a problem with the Containerfile", "add-iam-policy-binding farcast-p42"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("run does not name the grant (%q missing):\n%s", want, errOut)
		}
	}
}

// Every application gets its own scope, minted when it is deployed and
// recorded before anything is (ADR 0018 decision 5).
func TestRunMintsAScopePerApplication(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meta := runnableInstance(t, dir, "p43")
	meta.Keyholder = &config.Keyholder{Deployed: true}
	if err := dir.SaveInstanceMetadata("p43", meta); err != nil {
		t.Fatal(err)
	}
	mintKeyring(t, dir, "p43")
	env, _ := testEnv(dir, output.ModeHuman)

	f := newFakeRun(twoAppManifest)
	if err := runCmd(f).Run(context.Background(), env, []string{"p43", "github.com/example/my-platform"}); err != nil {
		t.Fatal(err)
	}

	raw, err := dir.LoadInstanceKeyring("p43")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := datasphere.ParseKeyring(raw)
	if err != nil {
		t.Fatal(err)
	}
	scopes := keys.Scopes()
	if len(scopes) != 2 {
		t.Fatalf("keyring holds %d scope(s), want one per application", len(scopes))
	}
	// Each owns its own subtree, and no two overlap — which is what makes the
	// separation cryptographic rather than a rule somebody enforces.
	seen := map[string]bool{}
	for _, s := range scopes {
		ns, app, ok := datasphere.ParseAppScopePrefix(s.Prefix)
		if !ok {
			t.Errorf("scope %q owns %q, which is not an application subtree", s.Name, s.Prefix)
			continue
		}
		seen[ns+"/"+app] = true
	}
	if !seen["my-platform/api"] || !seen["my-platform/web"] {
		t.Errorf("scopes = %v, want one for each application in the manifest", seen)
	}

	// The workloads carry each application's own scope and secrets subtree.
	workloads := appliedWith(t, f, "kind: Deployment")
	for _, want := range []string{"app-my-platform-api", "app/my-platform/api/secrets/", "app-my-platform-web"} {
		if !strings.Contains(workloads, want) {
			t.Errorf("the workloads do not carry %q", want)
		}
	}
}

// Redeploying reuses the scope already minted. A second scope for the same
// application would be a second key space, and the data written under the
// first would become unreachable by name.
func TestRunReusesAnApplicationsExistingScope(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meta := runnableInstance(t, dir, "p43")
	meta.Keyholder = &config.Keyholder{Deployed: true}
	if err := dir.SaveInstanceMetadata("p43", meta); err != nil {
		t.Fatal(err)
	}
	mintKeyring(t, dir, "p43")
	env, _ := testEnv(dir, output.ModeHuman)

	first := func() []datasphere.Scope {
		f := newFakeRun(twoAppManifest)
		if err := runCmd(f).Run(context.Background(), env, []string{"p43", "github.com/example/my-platform"}); err != nil {
			t.Fatal(err)
		}
		raw, err := dir.LoadInstanceKeyring("p43")
		if err != nil {
			t.Fatal(err)
		}
		keys, err := datasphere.ParseKeyring(raw)
		if err != nil {
			t.Fatal(err)
		}
		return keys.Scopes()
	}
	before := first()
	after := first()
	if len(after) != len(before) {
		t.Fatalf("a redeploy minted more scopes: %d then %d", len(before), len(after))
	}
	for i := range before {
		if before[i].Name != after[i].Name || before[i].Prefix != after[i].Prefix {
			t.Errorf("scope %d changed across a redeploy: %+v then %+v", i, before[i], after[i])
		}
	}
}

// Minting key material is the moment an operator will act on the warning, so
// it is carried there — and the operator is told the keyholder does not have
// the new scope until it is unsealed.
func TestRunSaysWhatMintingAScopeMeans(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meta := runnableInstance(t, dir, "p43")
	meta.Keyholder = &config.Keyholder{Deployed: true}
	if err := dir.SaveInstanceMetadata("p43", meta); err != nil {
		t.Fatal(err)
	}
	mintKeyring(t, dir, "p43")
	env, _, errBuf := testEnvBoth(dir, output.ModeHuman)

	f := newFakeRun(twoAppManifest)
	if err := runCmd(f).Run(context.Background(), env, []string{"p43", "github.com/example/my-platform"}); err != nil {
		t.Fatal(err)
	}
	out := errBuf.String()
	if !strings.Contains(out, datasphere.KeyLossWarning) {
		t.Errorf("minting a scope did not carry the mandated key-loss warning:\n%s", out)
	}
	if !strings.Contains(out, "storage unseal") {
		t.Errorf("nothing said the keyholder must be unsealed to receive the new scopes:\n%s", out)
	}
}
