package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	pbuild "github.com/sofmon/farcast/planck/build"
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
}

func (f *fakeJobs) Apply(_ context.Context, m []byte) error {
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
	c.newCluster = func(string) jobWaiter { return fj }
	c.newBuilder = func(func(string)) imageBuilder { return &fakeBuilder{} }
	return c
}

func succeeded(digest string) cluster.JobResult {
	return cluster.JobResult{Succeeded: true, Message: digest}
}

func TestBuildRunsInTheInstanceAndPinsWhatItPushed(t *testing.T) {
	dir := config.Dir(t.TempDir())
	buildableInstance(t, dir, "p42")
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
	buildableInstance(t, dir, "p42")
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
	buildableInstance(t, dir, "p42")
	env, _ := testEnv(dir, output.ModeHuman)
	c := buildCmd(&fakeJobs{})
	c.repo, c.app = "https://github.com/example/repo.git", "api"
	err := c.Run(context.Background(), env, []string{"p42"})
	if err == nil || !strings.Contains(err.Error(), "builder-image") {
		t.Fatalf("err = %v, want a refusal naming the missing builder", err)
	}
}

// A failed build must surface the build's own output. Repeating "the build
// failed" helps nobody; the Containerfile said why.
func TestAFailedBuildShowsTheBuildsOwnOutput(t *testing.T) {
	dir := config.Dir(t.TempDir())
	buildableInstance(t, dir, "p42")
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
	if !strings.Contains(err.Error(), "logs job/") {
		t.Errorf("the failure does not say how to read more: %v", err)
	}
}

// The image may have been pushed; without a digest it cannot be pinned, and
// deploying an unpinned image is what ADR 0007 decision 4 forbids.
func TestABuildThatReportsNoDigestIsAFailure(t *testing.T) {
	dir := config.Dir(t.TempDir())
	buildableInstance(t, dir, "p42")
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
	buildableInstance(t, dir, "p42")
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

	buildableInstance(t, dir, "p42")
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
	buildableInstance(t, dir, "p42")
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
	meta := buildableInstance(t, dir, "p42")
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
	buildableInstance(t, dir, "p42")
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
