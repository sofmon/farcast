package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/planck"
)

// fakeProvider is a programmable planck.Provider for exercising install without
// a cloud.
type fakeProvider struct {
	validateErr error
	created     *planck.ClusterSpec
	cluster     *planck.Cluster
	createErr   error
	status      planck.ClusterStatus
	statusErr   error
	deleteErr   error
	deleteCalls int
}

func (*fakeProvider) Name() string                     { return "fake" }
func (f *fakeProvider) Validate(context.Context) error { return f.validateErr }

func (f *fakeProvider) DeleteCluster(context.Context, planck.ClusterRef) error {
	f.deleteCalls++
	return f.deleteErr
}

func (f *fakeProvider) CreateCluster(_ context.Context, spec planck.ClusterSpec) (*planck.Cluster, error) {
	f.created = &spec
	if f.createErr != nil {
		return nil, f.createErr
	}
	if f.cluster != nil {
		return f.cluster, nil
	}
	return &planck.Cluster{
		Ref:        planck.ClusterRef{Name: spec.Name, Location: spec.Location},
		Status:     planck.StatusRunning,
		Endpoint:   "uid.us-central1.gke.goog",
		Kubeconfig: []byte("apiVersion: v1\nkind: Config\n"),
	}, nil
}

func (f *fakeProvider) ClusterStatus(context.Context, planck.ClusterRef) (planck.ClusterStatus, error) {
	if f.statusErr != nil {
		return planck.StatusUnknown, f.statusErr
	}
	if f.status == "" {
		return planck.StatusRunning, nil
	}
	return f.status, nil
}

func registerFake(t *testing.T, f *fakeProvider) string {
	t.Helper()
	name := "fake-" + strings.ReplaceAll(t.Name(), "/", "-")
	planck.Register(name, func(planck.Config) (planck.Provider, error) { return f, nil })
	return name
}

func newInstallEnv(t *testing.T, mode output.Mode) (*Env, *bytes.Buffer, *bytes.Buffer, config.Dir) {
	t.Helper()
	// A fresh subdir (not the 0755 temp dir itself) so Ensure creates it 0700.
	dir := config.Dir(filepath.Join(t.TempDir(), "cfg"))
	var out, errb bytes.Buffer
	env := &Env{
		Out: &out, Err: &errb, In: strings.NewReader(""),
		Printer:   &output.Printer{Mode: mode, Out: &out, Err: &errb},
		Config:    &config.Config{},
		ConfigDir: dir,
	}
	return env, &out, &errb, dir
}

func assertPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s perm = %#o, want %#o", path, got, want)
	}
}

func TestInstallSuccess(t *testing.T) {
	f := &fakeProvider{}
	prov := registerFake(t, f)
	env, out, _, dir := newInstallEnv(t, output.ModeHuman)
	cmd := &installCommand{name: "prod", provider: prov, project: "proj-1", region: "us-central1", costLimit: 50, assumeYes: true}

	if err := cmd.Run(context.Background(), env, nil); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if f.created == nil || f.created.Name != "farcast-prod" {
		t.Fatalf("create spec = %+v, want cluster farcast-prod", f.created)
	}
	meta, err := dir.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatalf("LoadInstanceMetadata: %v", err)
	}
	if meta.Status != config.InstanceRunning {
		t.Errorf("status = %q, want running", meta.Status)
	}
	if meta.Cluster != "farcast-prod" || meta.Endpoint == "" || meta.CostLimit.Amount != 50 {
		t.Errorf("unexpected metadata: %+v", meta)
	}
	assertPerm(t, dir.InstancePath("prod"), 0o700)
	for _, name := range []string{"metadata.yaml", "credentials.yaml", "kubeconfig.yaml"} {
		assertPerm(t, filepath.Join(dir.InstancePath("prod"), name), 0o600)
	}
	if !strings.Contains(out.String(), "farcast-prod") {
		t.Errorf("result missing cluster name:\n%s", out.String())
	}
}

func TestInstallRequiresCostLimit(t *testing.T) {
	f := &fakeProvider{}
	prov := registerFake(t, f)
	env, _, _, _ := newInstallEnv(t, output.ModeHuman)
	cmd := &installCommand{name: "x", provider: prov, project: "p", costLimit: 0, assumeYes: true}

	err := cmd.Run(context.Background(), env, nil)
	if _, ok := errors.AsType[*usageError](err); !ok {
		t.Fatalf("err = %v, want usageError for missing cost limit", err)
	}
}

func TestInstallRequiresName(t *testing.T) {
	f := &fakeProvider{}
	prov := registerFake(t, f)
	env, _, _, _ := newInstallEnv(t, output.ModeHuman)
	cmd := &installCommand{provider: prov, project: "p", costLimit: 10, assumeYes: true}

	err := cmd.Run(context.Background(), env, nil)
	if _, ok := errors.AsType[*usageError](err); !ok {
		t.Fatalf("err = %v, want usageError for missing name", err)
	}
}

func TestInstallNonInteractiveRequiresYes(t *testing.T) {
	f := &fakeProvider{}
	prov := registerFake(t, f)
	env, _, _, dir := newInstallEnv(t, output.ModeHuman)
	cmd := &installCommand{name: "x", provider: prov, project: "p", costLimit: 10, assumeYes: false}

	err := cmd.Run(context.Background(), env, nil)
	if _, ok := errors.AsType[*usageError](err); !ok {
		t.Fatalf("err = %v, want usageError (needs --yes)", err)
	}
	if exists, _ := dir.InstanceExists("x"); exists {
		t.Error("no instance should be recorded when confirmation is refused")
	}
}

func TestInstallValidateFailureRecordsNothing(t *testing.T) {
	f := &fakeProvider{validateErr: errors.New("bad creds")}
	prov := registerFake(t, f)
	env, _, _, dir := newInstallEnv(t, output.ModeHuman)
	cmd := &installCommand{name: "x", provider: prov, project: "p", costLimit: 10, assumeYes: true}

	err := cmd.Run(context.Background(), env, nil)
	if err == nil || !strings.Contains(err.Error(), "validate credentials") {
		t.Fatalf("err = %v, want validate failure", err)
	}
	if f.created != nil {
		t.Error("CreateCluster must not run when validation fails")
	}
	if exists, _ := dir.InstanceExists("x"); exists {
		t.Error("no instance dir should be created when validation fails")
	}
}

func TestInstallRefusesExistingInstance(t *testing.T) {
	f := &fakeProvider{}
	prov := registerFake(t, f)
	env, _, _, dir := newInstallEnv(t, output.ModeHuman)
	if err := dir.CreateInstance("dup"); err != nil {
		t.Fatal(err)
	}
	cmd := &installCommand{name: "dup", provider: prov, project: "p", costLimit: 10, assumeYes: true}

	err := cmd.Run(context.Background(), env, nil)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("err = %v, want already-exists", err)
	}
	if f.created != nil {
		t.Error("CreateCluster must not run for an existing instance")
	}
}

func TestInstallCreateClusterFailureRecordsError(t *testing.T) {
	f := &fakeProvider{createErr: errors.New("quota exceeded")}
	prov := registerFake(t, f)
	env, _, _, dir := newInstallEnv(t, output.ModeHuman)
	cmd := &installCommand{name: "boom", provider: prov, project: "p", costLimit: 10, assumeYes: true}

	err := cmd.Run(context.Background(), env, nil)
	if err == nil || !strings.Contains(err.Error(), "release") {
		t.Fatalf("err = %v, want provisioning failure with a release hint", err)
	}
	// Record-before-create: the metadata exists and is marked error.
	meta, lerr := dir.LoadInstanceMetadata("boom")
	if lerr != nil {
		t.Fatalf("metadata should still exist after a failed create: %v", lerr)
	}
	if meta.Status != config.InstanceError {
		t.Errorf("status = %q, want error", meta.Status)
	}
}

func TestInstallUnreachableRecordsStatus(t *testing.T) {
	f := &fakeProvider{status: planck.StatusError} // health check sees non-running
	prov := registerFake(t, f)
	env, _, _, dir := newInstallEnv(t, output.ModeHuman)
	cmd := &installCommand{name: "sick", provider: prov, project: "p", costLimit: 10, assumeYes: true}

	err := cmd.Run(context.Background(), env, nil)
	if err == nil || !strings.Contains(err.Error(), "not reachable") {
		t.Fatalf("err = %v, want unreachable error", err)
	}
	meta, _ := dir.LoadInstanceMetadata("sick")
	if meta == nil || meta.Status != config.InstanceUnreachable {
		t.Errorf("status = %v, want unreachable", meta)
	}
}

func TestInstallRejectsBadName(t *testing.T) {
	f := &fakeProvider{}
	prov := registerFake(t, f)
	env, _, _, _ := newInstallEnv(t, output.ModeHuman)
	cmd := &installCommand{name: "Bad_Name", provider: prov, project: "p", costLimit: 10, assumeYes: true}

	err := cmd.Run(context.Background(), env, nil)
	if _, ok := errors.AsType[*usageError](err); !ok {
		t.Fatalf("err = %v, want usageError for a bad name", err)
	}
}

func TestInstallJSONOutput(t *testing.T) {
	f := &fakeProvider{}
	prov := registerFake(t, f)
	env, out, _, _ := newInstallEnv(t, output.ModeJSON)
	cmd := &installCommand{name: "p", provider: prov, project: "proj", costLimit: 25, assumeYes: true}

	if err := cmd.Run(context.Background(), env, nil); err != nil {
		t.Fatalf("Run: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out.String())
	}
	if m["cluster"] != "farcast-p" || m["status"] != "running" {
		t.Errorf("unexpected JSON result: %v", m)
	}
}
