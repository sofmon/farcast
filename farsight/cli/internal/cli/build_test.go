package cli

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	pbuild "github.com/sofmon/farcast/planck/build"
	"github.com/sofmon/farcast/technocore/pricing"
)

const builderDigest = "cgr.dev/chainguard/kaniko@sha256:" +
	"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

type fakeJobs struct {
	applied  [][]byte
	result   cluster.JobResult
	waitErr  error
	applyErr error
	logs     string
	waited   []string
	// uidReads counts the writer's preflight reads (A20-11), and uidErr
	// answers them.
	uidReads int
	uidErr   error
}

func (f *fakeJobs) NamespaceUID(context.Context, string) (string, error) {
	f.uidReads++
	return "", f.uidErr
}

func (f *fakeJobs) Apply(_ context.Context, m []byte) error {
	checkApplied(m)
	f.applied = append(f.applied, m)
	return f.applyErr
}

func (f *fakeJobs) WaitJob(_ context.Context, ns, name string, _ time.Duration) (cluster.JobResult, error) {
	f.waited = append(f.waited, ns+"/"+name)
	return f.result, f.waitErr
}

func (f *fakeJobs) JobLogs(_ context.Context, _, _ string, _ int) (string, error) {
	return f.logs, nil
}

func buildableInstance(t *testing.T, dir config.Dir, name string) *config.InstanceMetadata {
	t.Helper()
	meta := connectedInstance(t, dir, name)
	meta.Registry = &config.Registry{Prefix: "us-central1-docker.pkg.dev/proj-1/farcast-" + name}
	if err := dir.SaveInstanceMetadata(name, meta); err != nil {
		t.Fatal(err)
	}
	return meta
}

func buildCmd(fj *fakeJobs) *buildCommand {
	c := &buildCommand{assumeYes: true}
	c.newCluster = func(clusterRef) (jobWaiter, error) { return fj, nil }
	c.newBuilder = func(func(string)) imageBuilder { return &fakeBuilder{} }
	return c
}

func succeeded(digest string) cluster.JobResult {
	return cluster.JobResult{Succeeded: true, Message: digest}
}

func TestBuildRunsInTheInstanceAndPinsWhatItPushed(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p42")
	env, out := testEnv(dir, output.ModeHuman)

	sha := "sha256:" + strings.Repeat("c", 64)
	fj := &fakeJobs{result: succeeded(sha)}
	c := buildCmd(fj)
	c.repo, c.app, c.builderImage = "https://github.com/example/repo.git", "api", builderDigest

	if err := c.Run(context.Background(), env, []string{"p42"}); err != nil {
		t.Fatal(err)
	}
	if len(fj.applied) != 1 {
		t.Fatalf("applied %d streams, want 1", len(fj.applied))
	}
	m := string(fj.applied[0])
	if !strings.Contains(m, "kind: Job") || !strings.Contains(m, builderDigest) {
		t.Errorf("the applied stream is not the pinned build job:\n%s", m)
	}

	// It waited on the Job the renderer actually created.
	want := pbuild.Namespace + "/" + pbuild.JobName("p42", "api")
	if len(fj.waited) != 1 || fj.waited[0] != want {
		t.Errorf("waited on %v, want %q", fj.waited, want)
	}

	// The result is pinned by the digest the build reported, not by the tag.
	printed := out.String()
	if !strings.Contains(printed, "@"+sha) {
		t.Errorf("the result is not digest-pinned:\n%s", printed)
	}
	if strings.Contains(printed, "farcast-p42/app/p42/api:") {
		t.Error("the result still carries the mutable tag")
	}
}

// A builder image runs arbitrary build steps while holding a credential that
// can write to the instance's registry. Resolving a tag on every build would
// mean silently running whatever it points at next — trust-on-first-use, not
// pinning.
func TestABuilderTagIsRefusedWithTheDigestToUse(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p42")
	env, _ := testEnv(dir, output.ModeHuman)

	fj := &fakeJobs{}
	c := buildCmd(fj)
	c.repo, c.app = "https://github.com/example/repo.git", "api"
	c.builderImage = "cgr.dev/chainguard/kaniko:latest"

	err := c.Run(context.Background(), env, []string{"p42"})
	if err == nil {
		t.Fatal("a tagged builder image was accepted")
	}
	// Assert on THIS refusal, not merely on a string both refusals share.
	// planck/build also rejects an unpinned builder, and its message also
	// contains "@sha256:" — so a substring check passes even when the CLI
	// never resolved anything and the operator is told nothing useful.
	if !strings.Contains(err.Error(), "resolves today to") {
		t.Errorf("the refusal did not resolve the tag and report the digest to pin: %v", err)
	}
	if !strings.Contains(err.Error(), "trust-on-first-use") && !strings.Contains(err.Error(), "whatever it points at next") {
		t.Errorf("the refusal does not say why resolving on every build would be wrong: %v", err)
	}
	if len(fj.applied) != 0 {
		t.Error("a refused build reached the cluster")
	}
}

func TestABuilderImageIsRequired(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p42")
	env, _ := testEnv(dir, output.ModeHuman)
	c := buildCmd(&fakeJobs{})
	c.repo, c.app = "https://github.com/example/repo.git", "api"
	err := c.Run(context.Background(), env, []string{"p42"})
	if err == nil || !strings.Contains(err.Error(), "builder-image") {
		t.Fatalf("err = %v, want a refusal naming the missing builder", err)
	}
}

// A failed build must surface the build's own output. Repeating "the build
// failed" helps nobody; the Containerfile said why. Since ADR 0023 M2.7
// (A30-35) the error points at that output, printed above it, and names no
// tool the operator would need.
func TestAFailedBuildShowsTheBuildsOwnOutput(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p42")
	env, _ := testEnv(dir, output.ModeHuman)

	fj := &fakeJobs{
		result: cluster.JobResult{Succeeded: false},
		logs:   "error building image: failed to execute command: exit status 1",
	}
	c := buildCmd(fj)
	c.repo, c.app, c.builderImage = "https://github.com/example/repo.git", "api", builderDigest

	err := c.Run(context.Background(), env, []string{"p42"})
	if err == nil {
		t.Fatal("a failed build reported success")
	}
	errOut := env.Err.(interface{ String() string }).String()
	if !strings.Contains(errOut, "failed to execute command") {
		t.Errorf("the build's own output was not shown:\n%s", errOut)
	}
	if want := "the build of p42/api failed; the end of its log, when it could be read, is printed above"; err.Error() != want {
		t.Errorf("the failure = %q, want %q", err, want)
	}
}

// The image may have been pushed; without a digest it cannot be pinned, and
// deploying an unpinned image is what ADR 0007 decision 4 forbids.
func TestABuildThatReportsNoDigestIsAFailure(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p42")
	env, _ := testEnv(dir, output.ModeHuman)

	for name, msg := range map[string]string{
		"empty":        "",
		"not a digest": "build complete",
		"truncated":    "sha256:abc",
	} {
		fj := &fakeJobs{result: succeeded(msg)}
		c := buildCmd(fj)
		c.repo, c.app, c.builderImage = "https://github.com/example/repo.git", "api", builderDigest
		if err := c.Run(context.Background(), env, []string{"p42"}); err == nil {
			t.Errorf("%s: a build reporting %q was accepted", name, msg)
		}
	}
}

// The push grant needs permission to change a repository's IAM, which this
// CLI's credential is not required to carry. It is printed, like the
// keyholder's bucket grant.
func TestTheResultPrintsThePushGrant(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p42")
	env, out := testEnv(dir, output.ModeHuman)

	fj := &fakeJobs{result: succeeded("sha256:" + strings.Repeat("c", 64))}
	c := buildCmd(fj)
	c.repo, c.app, c.builderImage = "https://github.com/example/repo.git", "api", builderDigest
	if err := c.Run(context.Background(), env, []string{"p42"}); err != nil {
		t.Fatal(err)
	}
	printed := out.String()
	for _, want := range []string{"artifactregistry.writer", pbuild.ServiceAccount, "ONE repository"} {
		if !strings.Contains(printed, want) {
			t.Errorf("the result does not explain the push grant (%q missing):\n%s", want, printed)
		}
	}
}

func TestBuildRefusesWithoutARegistryOrRequiredFlags(t *testing.T) {
	dir := config.Dir(t.TempDir())
	env, _ := testEnv(dir, output.ModeHuman)

	// No registry recorded.
	connectedInstance(t, dir, "bare")
	c := buildCmd(&fakeJobs{})
	c.repo, c.app, c.builderImage = "https://github.com/example/repo.git", "api", builderDigest
	if err := c.Run(context.Background(), env, []string{"bare"}); err == nil {
		t.Error("an instance with no registry was accepted")
	}

	meteringInstance(t, dir, "p42")
	for name, mutate := range map[string]func(*buildCommand){
		"no repo": func(c *buildCommand) { c.repo = "" },
		"no app":  func(c *buildCommand) { c.app = "" },
	} {
		c := buildCmd(&fakeJobs{})
		c.repo, c.app, c.builderImage = "https://github.com/example/repo.git", "api", builderDigest
		mutate(c)
		if err := c.Run(context.Background(), env, []string{"p42"}); err == nil {
			t.Errorf("%s: expected a refusal", name)
		}
	}
}

func TestAWaitFailureSurfaces(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p42")
	env, _ := testEnv(dir, output.ModeHuman)
	fj := &fakeJobs{waitErr: errors.New("apiserver unreachable")}
	c := buildCmd(fj)
	c.repo, c.app, c.builderImage = "https://github.com/example/repo.git", "api", builderDigest
	if err := c.Run(context.Background(), env, []string{"p42"}); err == nil {
		t.Fatal("a wait failure did not surface")
	}
}

func TestTheDestinationFollowsTheRegistryPathConvention(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meta := meteringInstance(t, dir, "p42")
	env, _ := testEnv(dir, output.ModeHuman)

	fj := &fakeJobs{result: succeeded("sha256:" + strings.Repeat("c", 64))}
	c := buildCmd(fj)
	c.repo, c.app, c.builderImage = "https://github.com/example/repo.git", "api", builderDigest
	c.ref = "refs/heads/release"
	if err := c.Run(context.Background(), env, []string{"p42"}); err != nil {
		t.Fatal(err)
	}
	// ADR 0007 decision 6: app/<deployment>/<app>.
	want := meta.Registry.Prefix + "/app/p42/api:release"
	if !strings.Contains(string(fj.applied[0]), "--destination="+want) {
		t.Errorf("destination does not follow the path convention; want %q", want)
	}
}

// A refused push is not a Containerfile failure, and the raw output does not
// say so. The 5.1b walk paid for a clone and a build four times over before
// working out that the grant was missing — because the instruction that fixes
// it was printed only on the SUCCESS path, where it cannot be needed.
func TestAFailedBuildNamesTheGrantWhenThePushWasRefused(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p42")
	env, _ := testEnv(dir, output.ModeHuman)

	fj := &fakeJobs{result: cluster.JobResult{Succeeded: false}, logs: arDenial}
	c := buildCmd(fj)
	c.repo, c.app, c.builderImage = "https://github.com/example/repo.git", "api", builderDigest

	if err := c.Run(context.Background(), env, []string{"p42"}); err == nil {
		t.Fatal("a failed build reported success")
	}
	errOut := env.Err.(interface{ String() string }).String()
	for _, want := range []string{"not a problem with the Containerfile", "add-iam-policy-binding farcast-p42", "roles/artifactregistry.writer"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("the failure does not name the grant (%q missing):\n%s", want, errOut)
		}
	}
}

// A build is a billed Job in farcast-system, which only a kernel meters. With
// no kernel it is refused before the builder is even resolved.
func TestBuildWithoutAKernelRefusesBeforeAnythingIsSpent(t *testing.T) {
	dir := config.Dir(t.TempDir())
	buildableInstance(t, dir, "p42")
	env, _ := testEnv(dir, output.ModeHuman)
	fj := &fakeJobs{}
	c := buildCmd(fj)
	fb := &fakeBuilder{}
	c.newBuilder = func(func(string)) imageBuilder { return fb }
	c.repo, c.app = "https://github.com/example/app", "api"
	c.builderImage = "cgr.dev/chainguard/kaniko:latest" // a tag: resolving it would be the first thing spent

	err := c.Run(context.Background(), env, []string{"p42"})
	if err == nil || !strings.Contains(err.Error(), "farcast kernel deploy p42") {
		t.Fatalf("build = %v; want a refusal naming 'farcast kernel deploy p42'", err)
	}
	if len(fj.applied) != 0 || len(fb.resolved) != 0 {
		t.Errorf("build spent before refusing: %d applied, %d resolved", len(fj.applied), len(fb.resolved))
	}
}

// buildRefusalNamesThePlan is TestNonInteractiveRefusalsNameThePlan's row
// for build: its cost question, met with no terminal and no --yes, refuses,
// exit 2, naming its Job's vCPU and MiB and ending with the route that needs
// neither; nothing was opened or applied.
func buildRefusalNamesThePlan(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p42")
	env, _ := testEnv(dir, output.ModeHuman) // stdin is no terminal
	fj := &fakeJobs{}
	c := buildCmd(fj)
	c.assumeYes = false
	c.repo, c.app, c.builderImage = "https://github.com/example/repo.git", "api", builderDigest
	err := c.Run(context.Background(), env, []string{"p42"})
	want := "building runs a 1 vCPU / 2048 MiB Job in the instance until it finishes or its deadline expires; pass --yes to confirm" + consentSuffix
	if err == nil || err.Error() != want || exitCodeOf(err) != 2 {
		t.Errorf("build with no terminal = %v (exit %d); want %q", err, exitCodeOf(err), want)
	}
	if len(fj.applied) != 0 {
		t.Errorf("a refused build applied %d streams", len(fj.applied))
	}
}

// buildPlanCmd is build with its flags parsed, its builder counting its
// lookups and its writer counting its opens: the plan's view of build.
func buildPlanCmd(t *testing.T, fj *fakeJobs, fb *fakeBuilder, opened *int, flags ...string) *buildCommand {
	t.Helper()
	c := withFlags(t, &buildCommand{}, flags...)
	c.newBuilder = func(func(string)) imageBuilder { return fb }
	c.newCluster = func(clusterRef) (jobWaiter, error) {
		*opened++
		return fj, nil
	}
	return c
}

// ADR 0023 M2.6 (A23-37): build's plan binds the build, its Job's cost, the
// builder image as named or as the instance recorded it, and the three
// documents it applies, byte for byte as the build renders them; its
// options are its eight behaviour flags. It reads the record alone: it
// opens no writer, reads no installer key, looks nothing up for a pinned
// builder, prints nothing on stderr, and changes no file.
func TestBuildPlanBindsTheBuildItRuns(t *testing.T) {
	flags := []string{"--repo", "https://github.com/example/repo.git", "--app", "api", "--ref", "refs/heads/release",
		"--context", "svc", "--containerfile", "svc/Containerfile", "--git-secret", "repo-cred"}
	recordedBuilder := "cgr.dev/chainguard/kaniko@sha256:" + strings.Repeat("a", 64)
	for _, tc := range []struct {
		name    string
		flags   []string
		record  string
		action  string
		builder string
		current *plan.ImageCurrent
	}{
		{"a named builder", []string{"--builder-image", builderDigest}, "", plan.ImageNamed, builderDigest, nil},
		{"a named builder over a recorded one", []string{"--builder-image", builderDigest}, recordedBuilder, plan.ImageNamed, builderDigest,
			&plan.ImageCurrent{Image: recordedBuilder}},
		{"a recorded builder", nil, recordedBuilder, plan.ImageRecorded, recordedBuilder, &plan.ImageCurrent{Image: recordedBuilder}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := config.Dir(t.TempDir())
			meta := meteringInstance(t, dir, "p42")
			if tc.record != "" {
				meta.Toolchain = &config.Toolchain{Builder: tc.record}
				if err := dir.SaveInstanceMetadata("p42", meta); err != nil {
					t.Fatal(err)
				}
			}
			before := treeFiles(t, string(dir))
			reads := observeConfigReads(t)
			fb, opened := &fakeBuilder{}, 0
			c := buildPlanCmd(t, &fakeJobs{}, fb, &opened, append(append(slices.Clone(flags), tc.flags...), "--plan")...)
			env, out, errb := testEnvBoth(dir, output.ModeJSON)
			if err := c.Run(context.Background(), env, []string{"p42"}); err != nil {
				t.Fatalf("build --plan: %v", err)
			}
			b := decodedBound(t, printedDocument(t, out.Bytes()))

			const destination = "us-central1-docker.pkg.dev/proj-1/farcast-p42/app/p42/api:release"
			stream, err := pbuild.Render(pbuild.Config{
				Instance: "p42", Deployment: "p42", App: "api", Builder: tc.builder,
				Repo: "https://github.com/example/repo.git", Ref: "refs/heads/release",
				Containerfile: "svc/Containerfile", ContextSubPath: "svc", Destination: destination, GitSecret: "repo-cred",
				EgressHosts: []string{"github.com", "us-central1-docker.pkg.dev"},
			})
			if err != nil {
				t.Fatal(err)
			}
			cost := plan.CostFact{
				Type: plan.TypeCost, Currency: "USD", Period: "monthly", LimitCents: 10000, Standing: []plan.StandingCost{},
				OneOff:          []plan.OneOffCost{{What: costWhatBuild, Jobs: 1, CPUMilli: 1000, MemMiB: 2048, DeadlineS: 1800}},
				FloorMonthCents: cents(floorFull(meta).Total), BelowFloor: 100 < floorFull(meta).Total,
				Pricing: plan.Pricing{Region: pricing.Region, AsOf: pricing.AsOf},
			}
			want := append([]plan.Fact{
				plan.BuildFact{Type: plan.TypeBuild, Repository: "https://github.com/example/repo.git", Ref: "refs/heads/release",
					App: "api", Containerfile: "svc/Containerfile", Context: "svc", Tag: "release", Destination: destination},
				cost,
				plan.ImageFact{Type: plan.TypeImage, Component: "builder", Action: tc.action, Target: tc.builder, Current: tc.current},
			}, wantWrites(t, stream)...)
			if !reflect.DeepEqual(b.Facts, want) {
				t.Errorf("the plan binds\n%#v\nwant\n%#v", b.Facts, want)
			}
			if got := writeTargets(b); !slices.Equal(got, []string{"ServiceAccount farcast-system/farcast-builder",
				"NetworkPolicy farcast-system/build-p42-api", "Job farcast-system/build-p42-api"}) {
				t.Errorf("the plan writes %q; want the build's three documents", got)
			}
			builderFlag := ""
			if len(tc.flags) > 0 {
				builderFlag = builderDigest
			}
			wantOptions := []plan.Option{{Flag: "app", Value: "api"}, {Flag: "builder-image", Value: builderFlag},
				{Flag: "containerfile", Value: "svc/Containerfile"}, {Flag: "context", Value: "svc"}, {Flag: "git-secret", Value: "repo-cred"},
				{Flag: "ref", Value: "refs/heads/release"}, {Flag: "repo", Value: "https://github.com/example/repo.git"}, {Flag: "tag", Value: ""}}
			if !reflect.DeepEqual(b.Options, wantOptions) || b.Command != "build" || b.ClusterIdentity != "none" || b.Target.SystemNamespaceUID != "" {
				t.Errorf("the plan is %s, as %s, reading farcast-system %q, with options %+v", b.Command, b.ClusterIdentity, b.Target.SystemNamespaceUID, b.Options)
			}
			if opened != 0 || len(fb.resolved)+len(fb.built)+len(fb.embedded) != 0 || errb.Len() != 0 {
				t.Errorf("the plan opened the writer %d times, looked up %v and said %q", opened, fb.resolved, errb)
			}
			for _, p := range reads() {
				if filepath.Base(p) == "credentials.yaml" {
					t.Errorf("build --plan read %s", p)
				}
			}
			sameFiles(t, "build --plan", before, treeFiles(t, string(dir)))
		})
	}
}

// ADR 0023 M2.6 (A23-37): build --confirm compares the plan it recomputes
// with the digest given, and only then opens the writer and makes its
// preflight read, and applies exactly the documents the plan bound, then
// waits for the Job, asking nothing, with no terminal and no --yes. A plan
// that changed since (the cost limit, which its cost fact binds) is refused
// plan_changed with no writer opened and nothing applied.
func TestBuildConfirmAppliesThePlannedJobAfterTheComparison(t *testing.T) {
	flags := []string{"--repo", "https://github.com/example/repo.git", "--app", "api", "--builder-image", builderDigest}
	planOf := func(t *testing.T, dir config.Dir) plan.Document {
		t.Helper()
		opened := 0
		c := buildPlanCmd(t, &fakeJobs{}, &fakeBuilder{}, &opened, append(slices.Clone(flags), "--plan")...)
		env, out := testEnv(dir, output.ModeJSON)
		if err := c.Run(context.Background(), env, []string{"p42"}); err != nil {
			t.Fatal(err)
		}
		return printedDocument(t, out.Bytes())
	}

	t.Run("the same plan", func(t *testing.T) {
		dir := config.Dir(t.TempDir())
		meteringInstance(t, dir, "p42")
		doc := planOf(t, dir)
		fj, opened := &fakeJobs{result: succeeded("sha256:" + strings.Repeat("c", 64))}, 0
		c := buildPlanCmd(t, fj, &fakeBuilder{}, &opened, append(slices.Clone(flags), "--confirm", doc.Digest)...)
		env, out, errb := testEnvBoth(dir, output.ModeHuman) // no terminal, no --yes
		if err := c.Run(context.Background(), env, []string{"p42"}); err != nil {
			t.Fatalf("build --confirm: %v\n%s", err, errb)
		}
		if opened != 1 || fj.uidReads != 1 || len(fj.applied) != 1 || len(fj.waited) != 1 {
			t.Fatalf("opened the writer %d times, read %d times, applied %d streams and waited %d times; want each once",
				opened, fj.uidReads, len(fj.applied), len(fj.waited))
		}
		var planned []plan.Fact
		for _, f := range decodedBound(t, doc).Facts {
			if w, ok := f.(plan.WriteFact); ok {
				planned = append(planned, w)
			}
		}
		if got := wantWrites(t, fj.applied[0]); !reflect.DeepEqual(got, planned) {
			t.Errorf("applied\n%#v\nthe plan bound\n%#v", got, planned)
		}
		if strings.Contains(errb.String(), "[y/N]") || !strings.Contains(out.String(), "@sha256:"+strings.Repeat("c", 64)) {
			t.Errorf("--confirm asked, or printed no pinned result:\n%s%s", errb, out)
		}
	})
	t.Run("a changed plan", func(t *testing.T) {
		dir := config.Dir(t.TempDir())
		meteringInstance(t, dir, "p42")
		doc := planOf(t, dir)
		if _, err := dir.UpdateInstanceMetadata("p42", func(m *config.InstanceMetadata) error {
			m.CostLimit.Amount = 75
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		before := treeFiles(t, string(dir))
		fj, opened := &fakeJobs{}, 0
		c := buildPlanCmd(t, fj, &fakeBuilder{}, &opened, append(slices.Clone(flags), "--confirm", doc.Digest)...)
		env, _ := testEnv(dir, output.ModeJSON)
		err := c.Run(context.Background(), env, []string{"p42"})
		if kindOf(classified(err)) != kindPlanChanged || exitCodeOf(err) != 1 {
			t.Fatalf("--confirm of a changed plan = %v; want plan_changed", err)
		}
		if opened+len(fj.applied) != 0 {
			t.Errorf("a changed plan opened the writer %d times and applied %d streams", opened, len(fj.applied))
		}
		sameFiles(t, "a changed build plan", before, treeFiles(t, string(dir)))
	})
}
