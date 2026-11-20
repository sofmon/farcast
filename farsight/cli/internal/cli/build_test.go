package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	"github.com/sofmon/farcast/planck"
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
	// accounts are the ServiceAccounts its farcast-system holds, by name,
	// at their uids (accountMeta), none when nil; metaReads counts the
	// reads of them, and metaErr, when set, answers every read, and
	// metaErrApplied every read once a stream is applied.
	accounts       map[string]string
	metaReads      int
	metaErr        error
	metaErrApplied error
	// createAccount is the uid an applied stream that holds the builder's
	// ServiceAccount creates it at, when farcast-system does not hold it
	// yet, as the API server would; "" creates none.
	createAccount string
	// events is each apply, account read and wait, in order; onWait runs as
	// a wait is asked, before it answers.
	events []string
	onWait func()
}

func (f *fakeJobs) NamespaceUID(context.Context, string) (string, error) {
	f.uidReads++
	return "", f.uidErr
}

func (f *fakeJobs) GetMeta(_ context.Context, k kube.Kind, namespace, name string) (kube.Object, error) {
	f.metaReads++
	f.events = append(f.events, "meta "+namespace+"/"+name)
	switch {
	case f.metaErr != nil:
		return kube.Object{}, f.metaErr
	case f.metaErrApplied != nil && len(f.applied) > 0:
		return kube.Object{}, f.metaErrApplied
	}
	return accountMeta(f.accounts, k, namespace, name)
}

func (f *fakeJobs) Apply(_ context.Context, m []byte) error {
	checkApplied(m)
	f.applied = append(f.applied, m)
	f.events = append(f.events, "apply")
	if f.createAccount != "" && strings.HasPrefix(string(m), string(pbuild.RenderServiceAccount())) {
		if f.accounts == nil {
			f.accounts = map[string]string{}
		}
		if _, ok := f.accounts[pbuild.ServiceAccount]; !ok {
			f.accounts[pbuild.ServiceAccount] = f.createAccount
		}
	}
	return f.applyErr
}

func (f *fakeJobs) WaitJob(_ context.Context, ns, name string, _ time.Duration) (cluster.JobResult, error) {
	f.waited = append(f.waited, ns+"/"+name)
	f.events = append(f.events, "wait")
	if f.onWait != nil {
		f.onWait()
	}
	return f.result, f.waitErr
}

func (f *fakeJobs) JobLogs(_ context.Context, _, _ string, _ int) (string, error) {
	return f.logs, nil
}

// buildableInstance is a connected instance in project proj-1 whose
// registry is recorded as the ensure records it: its prefix, and its
// repository and location, which the push grant's read and its printed
// commands name (ADR 0023 M2.8, design §33 A33-15).
func buildableInstance(t *testing.T, dir config.Dir, name string) *config.InstanceMetadata {
	t.Helper()
	meta := connectedInstance(t, dir, name)
	meta.Project = "proj-1"
	meta.Registry = &config.Registry{Prefix: "us-central1-docker.pkg.dev/proj-1/farcast-" + name, Repository: "farcast-" + name, Location: "us-central1"}
	if err := dir.SaveInstanceMetadata(name, meta); err != nil {
		t.Fatal(err)
	}
	return meta
}

// buildCmd is build with --yes, its writer fj and its builder a fake; its
// provider, which the plan reads the push grant through (A33-22), answers
// as fakeProvider does: the fixture number, and every grant missing.
func buildCmd(fj *fakeJobs) *buildCommand {
	c := &buildCommand{assumeYes: true}
	c.newCluster = func(clusterRef) (jobWaiter, error) { return fj, nil }
	c.newBuilder = func(func(string)) imageBuilder { return &fakeBuilder{} }
	c.openProvider = providerOf(&fakeProvider{})
	return c
}

// loopbackBuildReader is build's plan reader seam over loopbackReader: the
// instance's reader, against a test's kubetest.
func loopbackBuildReader(r clusterRef) (buildPlanReader, error) {
	cl, err := loopbackReader(r)
	if err != nil {
		return nil, err
	}
	return cl, nil
}

// providerOf is a provider seam that opens p.
func providerOf(p planck.Provider) providerOpener {
	return func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) { return p, nil }
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

// TestBuildPrintsThePushGrantOnlyWhenNotPresent (design §33, A33-22,
// mutation 110d): the push grant is never applied, and its commands are a
// notice only when the repository's own policy does not hold the builder's
// uid principal, or still holds the shared one. A build whose plan read the
// grant present, the shared principal gone, binds no notice, prints no
// commands before it applies, and its result names none; one whose plan
// read it missing prints the notice before it applies, in the plan's words,
// and its result the commands, under the build. One whose plan read it
// present while the shared principal still holds the role prints the
// removal in its notice before it applies, and its result names no
// commands: they print under the result only when the plan's state was not
// present. Each result's JSON states the grant.
func TestBuildPrintsThePushGrantOnlyWhenNotPresent(t *testing.T) {
	member := "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/proj-1.svc.id.goog/" +
		"kubernetes.serviceaccount.uid/" + fixtureBuilderUID
	shared := builderSharedMember(fixtureProjectNumber, "proj-1")
	const add = "add-iam-policy-binding 'farcast-p42' --project 'proj-1' --location 'us-central1' --member '" // the uid principal's
	for _, tc := range []struct {
		name          string
		states        map[string]planck.GrantState
		state, shared string
		// printed is the commands under the result; notice the plan's
		// notice before the apply, "" for none.
		printed bool
		notice  string
	}{
		{"present", map[string]planck.GrantState{member: planck.GrantPresent}, plan.GrantPresent, plan.GrantMissing, false, ""},
		{"missing", nil, plan.GrantMissing, plan.GrantMissing, true, msgPushGrantMissing},
		{"present, the shared principal held", map[string]planck.GrantState{member: planck.GrantPresent, shared: planck.GrantPresent},
			plan.GrantPresent, plan.GrantPresent, false, fmt.Sprintf(msgPushGrantShared, "proj-1")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := config.Dir(t.TempDir())
			meteringInstance(t, dir, "p42")
			fj := &fakeJobs{result: succeeded("sha256:" + strings.Repeat("c", 64)), accounts: fixtureAccounts()}
			c := buildCmd(fj)
			c.openProvider = providerOf(&fakeProvider{grantStates: tc.states})
			c.repo, c.app, c.builderImage = "https://github.com/example/repo.git", "api", builderDigest
			env, out, errb := testEnvBoth(dir, output.ModeHuman)
			if err := c.Run(context.Background(), env, []string{"p42"}); err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(errb.String(), msgPushGrantMissing) && strings.Contains(errb.String(), add+member+"'"); got != tc.printed {
				t.Errorf("before the apply, the notice and its commands printed: %v, want %v\n%s", got, tc.printed, errb)
			}
			if got := strings.Contains(out.String(), add+member+"'"); got != tc.printed {
				t.Errorf("the result names the commands: %v, want %v\n%s", got, tc.printed, out)
			}
			if !tc.printed && strings.Contains(out.String(), "iam-policy-binding") {
				t.Errorf("the result of a build whose plan read the grant present prints commands:\n%s", out)
			}
			switch {
			case tc.notice == "" && (strings.Contains(errb.String()+out.String(), "iam-policy-binding") || strings.Contains(errb.String()+out.String(), "artifactregistry.writer")):
				t.Errorf("a grant read present printed a notice or commands:\n%s%s", errb, out)
			case tc.notice != "" && !strings.Contains(errb.String(), tc.notice):
				t.Errorf("before the apply, stderr was\n%s\nwant the notice %q", errb, tc.notice)
			}

			env, out = testEnv(dir, output.ModeJSON)
			fj.applied = nil
			if err := c.Run(context.Background(), env, []string{"p42"}); err != nil {
				t.Fatal(err)
			}
			var res struct {
				PushGrant pushGrantResult `json:"push_grant"`
			}
			if err := json.Unmarshal(out.Bytes(), &res); err != nil {
				t.Fatal(err)
			}
			if want := (pushGrantResult{Principal: member, State: tc.state, Shared: tc.shared}); res.PushGrant != want {
				t.Errorf("the result's push_grant is %+v; want %+v", res.PushGrant, want)
			}
		})
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

	fj := &fakeJobs{result: cluster.JobResult{Succeeded: false}, logs: arDenial, accounts: fixtureAccounts()}
	c := buildCmd(fj)
	c.repo, c.app, c.builderImage = "https://github.com/example/repo.git", "api", builderDigest

	if err := c.Run(context.Background(), env, []string{"p42"}); err == nil {
		t.Fatal("a failed build reported success")
	}
	errOut := env.Err.(interface{ String() string }).String()
	// The plan's notice named the grant before the build; the explanation
	// names it again, after the build's own output.
	_, explained, _ := strings.Cut(errOut, "not a problem with the Containerfile")
	for _, want := range []string{"add-iam-policy-binding 'farcast-p42' --project 'proj-1' --location 'us-central1'", "roles/artifactregistry.writer"} {
		if !strings.Contains(explained, want) {
			t.Errorf("the failure's explanation does not name the grant (%q missing):\n%s", want, errOut)
		}
	}

	// A grant the plan read present, the push refused all the same: the
	// explanation says what the plan read, and still prints the add (design
	// §33, A33-22).
	t.Run("a grant the plan read present", func(t *testing.T) {
		member := uidMember(fixtureProjectNumber, "proj-1", fixtureBuilderUID)
		env, _ := testEnv(dir, output.ModeHuman)
		fj := &fakeJobs{result: cluster.JobResult{Succeeded: false}, logs: arDenial, accounts: fixtureAccounts()}
		c := buildCmd(fj)
		c.openProvider = providerOf(&fakeProvider{grantStates: map[string]planck.GrantState{member: planck.GrantPresent}})
		c.repo, c.app, c.builderImage = "https://github.com/example/repo.git", "api", builderDigest
		if err := c.Run(context.Background(), env, []string{"p42"}); err == nil {
			t.Fatal("a failed build reported success")
		}
		errOut := env.Err.(interface{ String() string }).String()
		_, explained, _ := strings.Cut(errOut, "not a problem with the Containerfile")
		for _, want := range []string{"the repository's own policy granted it write access",
			"add-iam-policy-binding 'farcast-p42' --project 'proj-1' --location 'us-central1' --member '" + member + "'"} {
			if !strings.Contains(explained, want) {
				t.Errorf("the failure's explanation is missing %q:\n%s", want, errOut)
			}
		}
	})
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
// lookups and its writer counting its opens: the plan's view of build. Its
// plan's reader, opened only as the reader, is a fake of the same cluster,
// holding fj's ServiceAccounts (design §33, A33-21), and its provider
// answers as fakeProvider does: the fixture number, every grant missing.
func buildPlanCmd(t *testing.T, fj *fakeJobs, fb *fakeBuilder, opened *int, flags ...string) *buildCommand {
	t.Helper()
	c := withFlags(t, &buildCommand{}, flags...)
	c.newBuilder = func(func(string)) imageBuilder { return fb }
	c.newCluster = func(clusterRef) (jobWaiter, error) {
		*opened++
		return fj, nil
	}
	c.newPlanReader = func(r clusterRef) (buildPlanReader, error) {
		if r.Identity != kube.Reader {
			return nil, fmt.Errorf("test: build's plan reader was opened as %q", r.Identity)
		}
		return &fakeJobs{accounts: fj.accounts}, nil
	}
	c.openProvider = providerOf(&fakeProvider{})
	return c
}

// grantedReader records a reader 'reader grant' verified for instance name
// in project proj-1, and its key: build's plan reads the cluster as it
// (design §33, A33-21).
func grantedReader(t *testing.T, dir config.Dir, name string) {
	t.Helper()
	if _, err := dir.UpdateInstanceMetadata(name, func(m *config.InstanceMetadata) error {
		m.Reader = &config.Reader{Email: readerEmail(name, m.Project), KeyID: readerTestKeyID, GrantedAt: readerGrantedAt}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := dir.SaveReaderKey(name, []byte("not read"), []byte("not read")); err != nil {
		t.Fatal(err)
	}
}

// ADR 0023 M2.6 (A23-37): build's plan binds the build, its Job's cost, the
// builder image as named or as the instance recorded it, and the three
// documents it applies, byte for byte as the build renders them; its
// options are its eight behaviour flags. Since ADR 0023 M2.8 (design §33,
// A33-21, A33-22) it reads the cluster as the instance's reader, and binds
// the push grant right after the builder image: here the repository's
// policy grants the builder's uid principal, so there is no notice. It opens
// no writer, looks nothing up for a pinned builder, prints nothing on
// stderr, and changes no file; it reads the installer's key for Google.
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
			grantedReader(t, dir, "p42")
			if tc.record != "" {
				meta.Toolchain = &config.Toolchain{Builder: tc.record}
				if err := dir.SaveInstanceMetadata("p42", meta); err != nil {
					t.Fatal(err)
				}
			}
			before := treeFiles(t, string(dir))
			reads := observeConfigReads(t)
			fb, opened := &fakeBuilder{}, 0
			c := buildPlanCmd(t, &fakeJobs{accounts: fixtureAccounts()}, fb, &opened, append(append(slices.Clone(flags), tc.flags...), "--plan")...)
			member := "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/proj-1.svc.id.goog/" +
				"kubernetes.serviceaccount.uid/" + fixtureBuilderUID
			c.openProvider = providerOf(&fakeProvider{grantStates: map[string]planck.GrantState{member: planck.GrantPresent}})
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
				plan.GrantFact{Type: plan.TypeGrant, Name: plan.GrantPush, Target: "us-central1-docker.pkg.dev/proj-1/farcast-p42",
					ServiceAccount: "farcast-system/farcast-builder", Principal: member, Roles: []string{"roles/artifactregistry.writer"},
					State: plan.GrantPresent, SharedPrincipal: "principal://iam.googleapis.com/projects/123456789012/locations/global/" +
						"workloadIdentityPools/proj-1.svc.id.goog/subject/ns/farcast-system/sa/farcast-builder", Shared: plan.GrantMissing},
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
			if !reflect.DeepEqual(b.Options, wantOptions) || b.Command != "build" || b.ClusterIdentity != "reader" || b.Target.SystemNamespaceUID != "" {
				t.Errorf("the plan is %s, as %s, reading farcast-system %q, with options %+v", b.Command, b.ClusterIdentity, b.Target.SystemNamespaceUID, b.Options)
			}
			if opened != 0 || len(fb.resolved)+len(fb.built)+len(fb.embedded) != 0 || errb.Len() != 0 {
				t.Errorf("the plan opened the writer %d times, looked up %v and said %q", opened, fb.resolved, errb)
			}
			if !slices.ContainsFunc(reads(), func(p string) bool { return filepath.Base(p) == "credentials.yaml" }) {
				t.Errorf("build --plan read no installer key for the push grant (%q)", reads())
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
		grantedReader(t, dir, "p42")
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
		// The plan's notice, its account not created yet, printed once,
		// right after the comparison (A23-26, design §33 A33-22).
		if got := strings.Count(errb.String(), msgPushGrantPending+"\n"); got != 1 {
			t.Errorf("--confirm printed the push grant's notice %d times; want once:\n%s", got, errb)
		}
	})
	t.Run("a changed plan", func(t *testing.T) {
		dir := config.Dir(t.TempDir())
		meteringInstance(t, dir, "p42")
		grantedReader(t, dir, "p42")
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

// TestBuildPlanReadsTheBuilderAsTheReader (design §33, A33-21, mutation
// 136): build's plan reads the cluster as the instance's reader, under
// --plan and in --confirm's recomputation: farcast-system's uid, which it
// binds, and the builder's ServiceAccount, whose uid its push grant names.
// The writer opens only after the comparison. An interactive or --yes build
// reads the account through the writer it opened, and binds the uid its
// preflight read.
func TestBuildPlanReadsTheBuilderAsTheReader(t *testing.T) {
	row := planCommandNamed(t, "build", "a named builder")
	s, dir := planFixture(t, row)
	doc, _ := runPlan(t, dir, row, output.ModeJSON)
	b := decodedBound(t, doc)
	if b.ClusterIdentity != "reader" || b.Target.SystemNamespaceUID != planSystemUID {
		t.Errorf("the plan is read as %q and binds farcast-system %q; want the reader's %s", b.ClusterIdentity, b.Target.SystemNamespaceUID, planSystemUID)
	}
	var reads []string
	for _, r := range s.Requests() {
		if r.As != "reader" {
			t.Errorf("build --plan sent %s %s as %q; want the reader alone", r.Method, r.Path, r.As)
		}
		if r.Path != "/token" {
			reads = append(reads, r.Method+" "+r.Path)
		}
	}
	if want := []string{"GET /api/v1/namespaces", "GET " + builderAccountPath}; !slices.Equal(reads, want) {
		t.Errorf("build --plan read %q; want farcast-system's uid, then the builder's ServiceAccount", reads)
	}
	if !slices.Equal(row.fakes.readers, []kube.Identity{kube.Reader}) || row.fakes.writers != 0 {
		t.Errorf("build --plan opened its reader seam as %v and the writer %d times", row.fakes.readers, row.fakes.writers)
	}

	// --confirm recomputes as the reader, then opens the writer, which the
	// row refuses.
	sent := len(s.Requests())
	cmd := withFlags(t, row.cmd(), append(slices.Clone(row.flags), "--confirm", doc.Digest)...)
	env, _, _ := testEnvBoth(dir, output.ModeJSON)
	if err := cmd.Run(t.Context(), env, row.args); err == nil || !strings.Contains(err.Error(), "test: a plan opened the writer") {
		t.Fatalf("build --confirm = %v; want it past the comparison, at the writer's open", err)
	}
	if !slices.ContainsFunc(s.Requests()[sent:], func(r kubetest.Request) bool { return r.As == "reader" && r.Path == builderAccountPath }) {
		t.Error("build --confirm's recomputation did not read the builder's ServiceAccount as the reader")
	}
	if !slices.Equal(row.fakes.readers, []kube.Identity{kube.Reader, kube.Reader}) || row.fakes.writers != 1 {
		t.Errorf("build --confirm opened its reader seam as %v and the writer %d times; want the reader again, then the writer", row.fakes.readers, row.fakes.writers)
	}

	// --yes reads through the writer.
	d := config.Dir(t.TempDir())
	meteringInstance(t, d, "p42")
	fj := &fakeJobs{accounts: fixtureAccounts(), result: succeeded("sha256:" + strings.Repeat("c", 64))}
	c := buildCmd(fj)
	readers := 0
	c.newPlanReader = func(clusterRef) (buildPlanReader, error) {
		readers++
		return nil, errors.New("test: an interactive build opened its plan's reader")
	}
	c.repo, c.app, c.builderImage = "https://github.com/example/repo.git", "api", builderDigest
	env, _ = testEnv(d, output.ModeJSON)
	if err := c.Run(t.Context(), env, []string{"p42"}); err != nil {
		t.Fatal(err)
	}
	if readers != 0 || fj.metaReads != 1 || fj.uidReads != 1 {
		t.Errorf("build --yes opened the reader %d times; the writer read the account %d times and farcast-system %d times; want the writer's, once each", readers, fj.metaReads, fj.uidReads)
	}
}
