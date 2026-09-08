package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/planck"
)

type fakeMirror struct {
	mirrored []string
	dst      []string
	user     string
	resolved string
	err      error
}

func (f *fakeMirror) Resolve(_ context.Context, ref, _, _ string) (string, error) {
	if f.resolved != "" {
		return f.resolved, nil
	}
	return ref + "@sha256:" + strings.Repeat("f", 64), nil
}

func (f *fakeMirror) Mirror(_ context.Context, src, dst, user, _ string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	f.mirrored = append(f.mirrored, src)
	f.dst = append(f.dst, dst)
	f.user = user
	// A faithful copy keeps the digest, so the mirrored reference carries the
	// same one the source did.
	_, digest, _ := strings.Cut(src, "@")
	base, _, _ := strings.Cut(dst, ":")
	return base + "@" + digest, nil
}

func toolchainCmd(f *fakeMirror) *toolchainCommand {
	c := &toolchainCommand{}
	c.newBuilder = func(func(string)) mirroringBuilder { return f }
	c.openProvider = func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) {
		return &fakeProvider{token: planck.RegistryToken{Username: "oauth2accesstoken", Password: "tok"}}, nil
	}
	return c
}

// The property that makes a mirror reviewable: the digest an operator checked
// upstream is the digest their instance runs. Only the registry changes.
func TestMirroringKeepsTheReviewedDigest(t *testing.T) {
	dir := config.Dir(t.TempDir())
	buildableInstance(t, dir, "p43")
	env, out := testEnv(dir, output.ModeHuman)

	f := &fakeMirror{}
	c := toolchainCmd(f)
	c.builder = "cgr.dev/chainguard/kaniko@sha256:" + strings.Repeat("a", 64)
	c.fetcher = "cgr.dev/chainguard/git@sha256:" + strings.Repeat("b", 64)

	if err := c.Run(context.Background(), env, []string{"p43"}); err != nil {
		t.Fatal(err)
	}
	meta, err := dir.LoadInstanceMetadata("p43")
	if err != nil {
		t.Fatal(err)
	}
	if meta.Toolchain == nil {
		t.Fatal("nothing was recorded")
	}
	for what, got := range map[string]string{"builder": meta.Toolchain.Builder, "fetcher": meta.Toolchain.Fetcher} {
		if !strings.HasPrefix(got, meta.Registry.Prefix+"/system/") {
			t.Errorf("the recorded %s is not in the instance's own registry: %s", what, got)
		}
		if strings.Contains(got, "cgr.dev") {
			t.Errorf("the recorded %s still points at the third-party registry: %s", what, got)
		}
	}
	if !strings.HasSuffix(meta.Toolchain.Builder, "@sha256:"+strings.Repeat("a", 64)) {
		t.Errorf("the builder's reviewed digest did not survive the mirror: %s", meta.Toolchain.Builder)
	}
	if !strings.HasSuffix(meta.Toolchain.Fetcher, "@sha256:"+strings.Repeat("b", 64)) {
		t.Errorf("the fetcher's reviewed digest did not survive the mirror: %s", meta.Toolchain.Fetcher)
	}
	if !strings.Contains(out.String(), "nothing here has to be believed") {
		t.Errorf("the result does not say how to check the mirror:\n%s", out.String())
	}
}

// Mirroring an unreviewed tag would copy whatever it points at today into the
// one registry the instance runs code from.
func TestMirroringRefusesATag(t *testing.T) {
	dir := config.Dir(t.TempDir())
	buildableInstance(t, dir, "p43")
	env, _ := testEnv(dir, output.ModeHuman)

	f := &fakeMirror{}
	c := toolchainCmd(f)
	c.builder = "cgr.dev/chainguard/kaniko:latest"

	err := c.Run(context.Background(), env, []string{"p43"})
	if err == nil {
		t.Fatal("a tag was mirrored")
	}
	if !strings.Contains(err.Error(), "is a tag, not a digest") {
		t.Errorf("unhelpful refusal: %v", err)
	}
	if len(f.mirrored) != 0 {
		t.Errorf("it mirrored %v anyway", f.mirrored)
	}
}

func TestToolchainReportsWhatIsRecorded(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meta := buildableInstance(t, dir, "p43")
	meta.Toolchain = &config.Toolchain{Builder: "reg.example/system/kaniko@sha256:" + strings.Repeat("a", 64)}
	if err := dir.SaveInstanceMetadata("p43", meta); err != nil {
		t.Fatal(err)
	}
	env, out := testEnv(dir, output.ModeHuman)

	f := &fakeMirror{}
	if err := toolchainCmd(f).Run(context.Background(), env, []string{"p43"}); err != nil {
		t.Fatal(err)
	}
	if len(f.mirrored) != 0 {
		t.Error("reporting mirrored something")
	}
	if !strings.Contains(out.String(), "kaniko@sha256:") {
		t.Errorf("the recorded builder was not reported:\n%s", out.String())
	}
}

func TestAFailedMirrorRecordsNothing(t *testing.T) {
	dir := config.Dir(t.TempDir())
	buildableInstance(t, dir, "p43")
	env, _ := testEnv(dir, output.ModeHuman)

	f := &fakeMirror{err: errors.New("registry said no")}
	c := toolchainCmd(f)
	c.builder = "cgr.dev/chainguard/kaniko@sha256:" + strings.Repeat("a", 64)

	if err := c.Run(context.Background(), env, []string{"p43"}); err == nil {
		t.Fatal("a failed mirror was reported as success")
	}
	meta, err := dir.LoadInstanceMetadata("p43")
	if err != nil {
		t.Fatal(err)
	}
	if meta.Toolchain != nil && meta.Toolchain.Builder != "" {
		t.Errorf("a failed mirror was recorded anyway: %s", meta.Toolchain.Builder)
	}
}
