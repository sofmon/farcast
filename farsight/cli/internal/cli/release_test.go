package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
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

	ok, err := cmd.confirm(true, newPrompter(strings.NewReader("prod\n"), io.Discard), io.Discard, meta)
	if err != nil || !ok {
		t.Fatalf("confirm(correct name) = %v,%v; want true,nil", ok, err)
	}
	ok, err = cmd.confirm(true, newPrompter(strings.NewReader("nope\n"), io.Discard), io.Discard, meta)
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
