package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/buildinfo"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/planck"
)

// fakeProvider is a programmable planck.Provider — and planck.RegistryProvider
// — for exercising install/connect/release without a cloud.
type fakeProvider struct {
	validateErr error
	created     *planck.ClusterSpec
	cluster     *planck.Cluster
	createErr   error
	status      planck.ClusterStatus
	statusErr   error
	deleteErr   error
	deleteCalls int

	// Instance registry (ADR 0007).
	ensured      []planck.RegistrySpec
	registry     *planck.Registry // overrides the derived default
	ensureErr    error
	regDeleted   []planck.RegistryRef
	regDeleteErr error
	token        planck.RegistryToken
	tokenErr     error
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
	// Mirrors the GKE adapter, which returns a cluster only once it has read
	// it back as system-only logging (ADR 0019), and, having found none under
	// the name, says it created it (ADR 0023 M2.7).
	return &planck.Cluster{
		Ref:            planck.ClusterRef{Name: spec.Name, Location: spec.Location},
		Status:         planck.StatusRunning,
		Endpoint:       "uid.us-central1.gke.goog",
		SystemLogsOnly: true,
		Created:        true,
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

func (f *fakeProvider) EnsureRegistry(_ context.Context, spec planck.RegistrySpec) (*planck.Registry, error) {
	f.ensured = append(f.ensured, spec)
	if f.ensureErr != nil {
		return nil, f.ensureErr
	}
	if f.registry != nil {
		return f.registry, nil
	}
	return derivedRegistry(spec), nil
}

func (f *fakeProvider) DeleteRegistry(_ context.Context, ref planck.RegistryRef) error {
	f.regDeleted = append(f.regDeleted, ref)
	return f.regDeleteErr
}

func (f *fakeProvider) RegistryToken(context.Context) (planck.RegistryToken, error) {
	if f.tokenErr != nil {
		return planck.RegistryToken{}, f.tokenErr
	}
	if f.token.Username != "" {
		return f.token, nil
	}
	return planck.RegistryToken{Username: "oauth2accesstoken", Password: "tok", Expiry: time.Unix(1, 0).UTC()}, nil
}

// derivedRegistry mirrors what the GKE adapter returns: the repository named
// after the instance, in the instance's region, with a repo-scoped puller.
func derivedRegistry(spec planck.RegistrySpec) *planck.Registry {
	repo := "farcast-" + spec.Name
	return &planck.Registry{
		Ref:    planck.RegistryRef{Name: repo, Location: spec.Location},
		Prefix: spec.Location + "-docker.pkg.dev/proj-1/" + repo,
		Puller: "serviceAccount:1234-compute@developer.gserviceaccount.com",
	}
}

// clusterOnlyProvider hides the registry capability: embedding the interface
// promotes only planck.Provider's methods, so the RegistryProvider type
// assertion fails — a cloud that can run a cluster but not host images.
type clusterOnlyProvider struct{ planck.Provider }

func registerFake(t *testing.T, f *fakeProvider) string {
	t.Helper()
	return registerProvider(t, f)
}

func registerProvider(t *testing.T, p planck.Provider) string {
	t.Helper()
	name := "fake-" + strings.ReplaceAll(t.Name(), "/", "-")
	planck.Register(name, func(planck.Config) (planck.Provider, error) { return p, nil })
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

// installKeyJSON is a service-account key file's JSON, made once per test
// binary: a Google key's shape with an RSA key in PKCS#8 PEM, which is what
// install now parses (as the instance's writer will) before anything else.
var installKeyJSON = sync.OnceValues(func() ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]string{
		"type": "service_account", "client_email": "installer@proj-1.iam.gserviceaccount.com",
		"private_key_id": "install-test", "private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
	})
})

// installKey is a --credentials file for a test install: a service-account
// key, in a file of its own. The provider is a fake, so nothing reads it but
// install.
func installKey(t *testing.T) string {
	t.Helper()
	b, err := installKeyJSON()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "key.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
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
	cmd := &installCommand{credentials: installKey(t), name: "prod", provider: prov, project: "proj-1", region: "us-central1", costLimit: 50, assumeYes: true}

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
	for _, name := range []string{"metadata.yaml", "credentials.yaml"} {
		assertPerm(t, filepath.Join(dir.InstancePath("prod"), name), 0o600)
	}
	// ADR 0023 M2.7 (A30-34): install writes no kubeconfig.yaml. Nothing reads
	// one: every cluster call runs in-process.
	if _, err := os.Lstat(filepath.Join(dir.InstancePath("prod"), "kubeconfig.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("kubeconfig.yaml after an install: %v; want it absent", err)
	}
	if !strings.Contains(out.String(), "farcast-prod") {
		t.Errorf("result missing cluster name:\n%s", out.String())
	}
}

func TestInstallRequiresCostLimit(t *testing.T) {
	f := &fakeProvider{}
	prov := registerFake(t, f)
	env, _, _, _ := newInstallEnv(t, output.ModeHuman)
	cmd := &installCommand{credentials: installKey(t), name: "x", provider: prov, project: "p", costLimit: 0, assumeYes: true}

	err := cmd.Run(context.Background(), env, nil)
	if _, ok := errors.AsType[*usageError](err); !ok {
		t.Fatalf("err = %v, want usageError for missing cost limit", err)
	}
}

func TestInstallRequiresName(t *testing.T) {
	f := &fakeProvider{}
	prov := registerFake(t, f)
	env, _, _, _ := newInstallEnv(t, output.ModeHuman)
	cmd := &installCommand{credentials: installKey(t), provider: prov, project: "p", costLimit: 10, assumeYes: true}

	err := cmd.Run(context.Background(), env, nil)
	if _, ok := errors.AsType[*usageError](err); !ok {
		t.Fatalf("err = %v, want usageError for missing name", err)
	}
}

func TestInstallNonInteractiveRequiresYes(t *testing.T) {
	f := &fakeProvider{}
	prov := registerFake(t, f)
	env, _, _, dir := newInstallEnv(t, output.ModeHuman)
	cmd := &installCommand{credentials: installKey(t), name: "x", provider: prov, project: "p", costLimit: 10, assumeYes: false}

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
	cmd := &installCommand{credentials: installKey(t), name: "x", provider: prov, project: "p", costLimit: 10, assumeYes: true}

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
	cmd := &installCommand{credentials: installKey(t), name: "dup", provider: prov, project: "p", costLimit: 10, assumeYes: true}

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
	cmd := &installCommand{credentials: installKey(t), name: "boom", provider: prov, project: "p", costLimit: 10, assumeYes: true}

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
	// A cluster that never passed the provider's read-back is never recorded
	// as keeping its logs from the provider (ADR 0019).
	if meta.CloudLogging != "" {
		t.Errorf("cloud_logging = %q after a failed create, want empty", meta.CloudLogging)
	}
	// Nor as migrated to server-side apply: install records that only at its
	// finalizing save, for a cluster the call created (ADR 0023 M2.7,
	// A30-25).
	if meta.ServerSideApply != nil {
		t.Errorf("a failed create recorded server_side_apply %+v", *meta.ServerSideApply)
	}
}

// TestInstallRecordsSystemOnlyLogging: the instance records, and the operator
// is told, that applications' output stays on the cluster — on the
// provider's word, and only then (ADR 0019).
func TestInstallRecordsSystemOnlyLogging(t *testing.T) {
	f := &fakeProvider{}
	prov := registerFake(t, f)
	env, out, _, dir := newInstallEnv(t, output.ModeHuman)
	cmd := &installCommand{credentials: installKey(t), name: "prod", provider: prov, project: "p", costLimit: 10, assumeYes: true}
	if err := cmd.Run(context.Background(), env, nil); err != nil {
		t.Fatalf("Run: %v", err)
	}
	meta, err := dir.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatalf("LoadInstanceMetadata: %v", err)
	}
	if meta.CloudLogging != config.CloudLoggingSystem {
		t.Errorf("cloud_logging = %q, want %q", meta.CloudLogging, config.CloudLoggingSystem)
	}
	if !strings.Contains(out.String(), "configured not to be sent to the provider's logging") {
		t.Errorf("result does not say where application logs go:\n%s", out.String())
	}
	// The read-back is the provider's word about its configuration; the
	// result must not present it as observed behaviour (review finding R-3).
	if strings.Contains(out.String(), "kept on the cluster's nodes, not sent") || !strings.Contains(out.String(), "unwalked") {
		t.Errorf("result presents the provider's read-back as observed:\n%s", out.String())
	}
}

// TestInstallDoesNotClaimUnverifiedLogging: a provider that returns a cluster
// without having verified its logging gets no "system" record and no claim.
func TestInstallDoesNotClaimUnverifiedLogging(t *testing.T) {
	f := &fakeProvider{cluster: &planck.Cluster{
		Ref:      planck.ClusterRef{Name: "farcast-prod", Location: "us-central1"},
		Status:   planck.StatusRunning,
		Endpoint: "uid.us-central1.gke.goog",
	}}
	prov := registerFake(t, f)
	env, out, _, dir := newInstallEnv(t, output.ModeJSON)
	cmd := &installCommand{credentials: installKey(t), name: "prod", provider: prov, project: "p", costLimit: 10, assumeYes: true}
	if err := cmd.Run(context.Background(), env, nil); err != nil {
		t.Fatalf("Run: %v", err)
	}
	meta, err := dir.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatalf("LoadInstanceMetadata: %v", err)
	}
	if meta.CloudLogging != "" {
		t.Errorf("cloud_logging = %q for an unverified cluster, want empty", meta.CloudLogging)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out.String())
	}
	if m["cloud_logging"] != "unverified" {
		t.Errorf("cloud_logging = %v, want unverified", m["cloud_logging"])
	}

	var b bytes.Buffer
	if err := (installResult{Name: "prod", CloudLogging: cloudLoggingResult(meta.CloudLogging)}).Human(&b); err != nil {
		t.Fatalf("Human: %v", err)
	}
	if strings.Contains(b.String(), "not to be sent to the provider's logging") || !strings.Contains(b.String(), "NOT verified") {
		t.Errorf("an unverified cluster must be said to be unverified, never kept from the provider:\n%s", b.String())
	}
}

// recordAtCreate is a fakeProvider that reads the instance's record as it
// stands when CreateCluster is called: the first record install saves.
type recordAtCreate struct {
	*fakeProvider
	dir      config.Dir
	name     string
	atCreate *config.InstanceMetadata
	err      error
}

func (p *recordAtCreate) CreateCluster(ctx context.Context, spec planck.ClusterSpec) (*planck.Cluster, error) {
	p.atCreate, p.err = p.dir.LoadInstanceMetadata(p.name)
	return p.fakeProvider.CreateCluster(ctx, spec)
}

// msgAdoptedCluster is install's warning on a cluster the provider found
// under the instance's name, for instance prod.
const msgAdoptedCluster = `Warning: cluster "farcast-prod" already existed, so this farcast cannot tell what wrote to it; ` +
	"run 'farcast migrate prod --plan' before any command that writes to it.\n"

// ADR 0023 M2.7 (design A30-25): install records an instance whose cluster it
// created as written with server-side apply, since the record was made and
// by this farcast, at its finalizing save only. The record it saves before
// the cluster is created carries none, so an install stopped while it
// provisions leaves an instance every writing command refuses, and nothing
// is said about an adopted cluster.
func TestInstallRecordsServerSideApply(t *testing.T) {
	env, _, errb, dir := newInstallEnv(t, output.ModeHuman)
	f := &recordAtCreate{fakeProvider: &fakeProvider{}, dir: dir, name: "prod"}
	prov := registerProvider(t, f)
	cmd := &installCommand{credentials: installKey(t), name: "prod", provider: prov, project: "proj-1", region: "us-central1", costLimit: 50, assumeYes: true}
	if err := cmd.Run(context.Background(), env, nil); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if f.err != nil || f.atCreate == nil {
		t.Fatalf("the first record, as the cluster was created: %v", f.err)
	}
	if f.atCreate.ServerSideApply != nil {
		t.Errorf("the first record carries server_side_apply %+v; want none until the cluster is created", *f.atCreate.ServerSideApply)
	}
	meta, err := dir.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatal(err)
	}
	ssa := meta.ServerSideApply
	switch {
	case ssa == nil:
		t.Fatal("install recorded no server_side_apply for a cluster it created")
	case meta.CreatedAt.IsZero() || !ssa.Since.Equal(meta.CreatedAt):
		t.Errorf("server_side_apply.since = %v; want created_at, %v", ssa.Since, meta.CreatedAt)
	case ssa.Farcast != buildinfo.Get().Version:
		t.Errorf("server_side_apply.farcast = %q; want this build's version %q", ssa.Farcast, buildinfo.Get().Version)
	}
	if strings.Contains(errb.String(), "already existed") {
		t.Errorf("install warned of an adopted cluster it created:\n%s", errb.String())
	}
}

// ADR 0023 M2.7 (design A30-25), mutation 97b: a cluster the provider found
// under the instance's name (Created false), which another machine's install
// of the same name made and may have written to with kubectl, is left
// unmigrated. install says so on stderr, once, naming the migration, and
// still succeeds.
func TestInstallOnAnAdoptedClusterLeavesItUnmigrated(t *testing.T) {
	for name, mode := range map[string]output.Mode{"human": output.ModeHuman, "json": output.ModeJSON} {
		t.Run(name, func(t *testing.T) {
			f := &fakeProvider{cluster: &planck.Cluster{
				Ref:            planck.ClusterRef{Name: "farcast-prod", Location: "us-central1"},
				Status:         planck.StatusRunning,
				Endpoint:       "uid.us-central1.gke.goog",
				SystemLogsOnly: true,
			}}
			prov := registerFake(t, f)
			env, out, errb, dir := newInstallEnv(t, mode)
			cmd := &installCommand{credentials: installKey(t), name: "prod", provider: prov, project: "proj-1", region: "us-central1", costLimit: 50, assumeYes: true}
			err := cmd.Run(context.Background(), env, nil)
			if err != nil || exitCodeOf(err) != 0 {
				t.Fatalf("Run = %v (exit %d); want success", err, exitCodeOf(err))
			}
			meta, lerr := dir.LoadInstanceMetadata("prod")
			if lerr != nil {
				t.Fatal(lerr)
			}
			if meta.ServerSideApply != nil {
				t.Errorf("an adopted cluster was recorded as migrated: %+v", *meta.ServerSideApply)
			}
			if meta.Status != config.InstanceRunning {
				t.Errorf("status = %q, want running", meta.Status)
			}
			if got := strings.Count(errb.String(), msgAdoptedCluster); got != 1 {
				t.Errorf("stderr holds the adopted-cluster warning %d times; want once:\n%s", got, errb.String())
			}
			if strings.Contains(out.String(), "already existed") {
				t.Errorf("the warning reached stdout:\n%s", out.String())
			}
		})
	}
}

func TestInstallUnreachableRecordsStatus(t *testing.T) {
	f := &fakeProvider{status: planck.StatusError} // health check sees non-running
	prov := registerFake(t, f)
	env, _, _, dir := newInstallEnv(t, output.ModeHuman)
	cmd := &installCommand{credentials: installKey(t), name: "sick", provider: prov, project: "p", costLimit: 10, assumeYes: true}

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
	cmd := &installCommand{credentials: installKey(t), name: "Bad_Name", provider: prov, project: "p", costLimit: 10, assumeYes: true}

	err := cmd.Run(context.Background(), env, nil)
	if _, ok := errors.AsType[*usageError](err); !ok {
		t.Fatalf("err = %v, want usageError for a bad name", err)
	}
}

func TestInstallEnsuresTheInstanceRegistry(t *testing.T) {
	f := &fakeProvider{}
	prov := registerFake(t, f)
	env, out, _, dir := newInstallEnv(t, output.ModeHuman)
	cmd := &installCommand{credentials: installKey(t), name: "prod", provider: prov, project: "proj-1", region: "us-central1", costLimit: 50, assumeYes: true}

	if err := cmd.Run(context.Background(), env, nil); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(f.ensured) != 1 {
		t.Fatalf("EnsureRegistry called %d times, want 1", len(f.ensured))
	}
	spec := f.ensured[0]
	if spec.Name != "prod" || spec.Location != "us-central1" || spec.Cluster.Name != "farcast-prod" {
		t.Errorf("registry spec = %+v, want the instance name, region and cluster", spec)
	}
	if spec.Labels["farcast-instance"] != "prod" {
		t.Errorf("registry labels = %v, want the instance labels", spec.Labels)
	}
	meta, err := dir.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatal(err)
	}
	if meta.Registry == nil {
		t.Fatal("the registry was not recorded in metadata")
	}
	if meta.Registry.Prefix != "us-central1-docker.pkg.dev/proj-1/farcast-prod" ||
		meta.Registry.Repository != "farcast-prod" ||
		meta.Registry.Location != "us-central1" ||
		meta.Registry.Puller == "" {
		t.Errorf("recorded registry = %+v", meta.Registry)
	}
	// Free, so it is stated plainly rather than gated.
	if !strings.Contains(out.String(), "registry:") || !strings.Contains(out.String(), "farcast-prod") {
		t.Errorf("result missing the registry line:\n%s", out.String())
	}
}

func TestInstallRegistryFailureLeavesTheInstanceUsable(t *testing.T) {
	f := &fakeProvider{ensureErr: errors.New("permission denied on artifactregistry.repositories.create")}
	prov := registerFake(t, f)
	env, _, errb, dir := newInstallEnv(t, output.ModeHuman)
	cmd := &installCommand{credentials: installKey(t), name: "prod", provider: prov, project: "proj-1", costLimit: 10, assumeYes: true}

	// The cluster is already created and billable, so a registry failure must
	// not abort the install.
	if err := cmd.Run(context.Background(), env, nil); err != nil {
		t.Fatalf("Run: %v, want the install to succeed without a registry", err)
	}
	meta, err := dir.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatal(err)
	}
	if meta.Status != config.InstanceRunning {
		t.Errorf("status = %q, want running", meta.Status)
	}
	if meta.Registry != nil {
		t.Errorf("no registry should be recorded when the ensure failed: %+v", meta.Registry)
	}
	if !strings.Contains(errb.String(), "Warning") || !strings.Contains(errb.String(), "connect") {
		t.Errorf("expected a warning naming the connect retry:\n%s", errb.String())
	}
}

func TestInstallWithoutRegistryCapabilitySkipsSilently(t *testing.T) {
	f := &fakeProvider{}
	prov := registerProvider(t, clusterOnlyProvider{f})
	env, out, errb, dir := newInstallEnv(t, output.ModeHuman)
	cmd := &installCommand{credentials: installKey(t), name: "prod", provider: prov, project: "proj-1", costLimit: 10, assumeYes: true}

	if err := cmd.Run(context.Background(), env, nil); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(f.ensured) != 0 {
		t.Error("a provider without the capability must not be asked for a registry")
	}
	if strings.Contains(errb.String(), "Warning") {
		t.Errorf("an unsupported registry must be skipped in silence:\n%s", errb.String())
	}
	if strings.Contains(out.String(), "registry:") {
		t.Errorf("no registry line without a registry:\n%s", out.String())
	}
	meta, _ := dir.LoadInstanceMetadata("prod")
	if meta.Registry != nil {
		t.Errorf("registry recorded for a provider that has none: %+v", meta.Registry)
	}
}

func TestInstallJSONOutput(t *testing.T) {
	f := &fakeProvider{}
	prov := registerFake(t, f)
	env, out, _, _ := newInstallEnv(t, output.ModeJSON)
	cmd := &installCommand{credentials: installKey(t), name: "p", provider: prov, project: "proj", costLimit: 25, assumeYes: true}

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
	if m["cloud_logging"] != config.CloudLoggingSystem {
		t.Errorf("cloud_logging = %v, want %q", m["cloud_logging"], config.CloudLoggingSystem)
	}
}

// ADR 0023 M2.5 (A20-1), mutation 71e: install refuses to provision without
// a service-account key. From M2.5 every cluster-writing command reads the
// cluster as the installer's stored key, so an instance installed with
// Application Default Credentials could only ever be released; the two
// refusals' texts are M2.7's (A30-25), which say those commands read and
// write it so and name no other command. The flag
// absent from a non-interactive run, a blank answer at the prompt, and a
// --credentials file holding no key the writer could open (empty, /dev/null,
// white space, or not a service-account key), are each a usage error naming
// why, before the provider is opened or anything is recorded; and neither the
// usage nor the prompt offers ADC any more.
func TestInstallRefusesAMissingCredentials(t *testing.T) {
	f := &fakeProvider{}
	prov := registerFake(t, f)
	for _, mode := range []output.Mode{output.ModeHuman, output.ModeJSON} {
		env, _, _, dir := newInstallEnv(t, mode)
		cmd := &installCommand{name: "prod", provider: prov, project: "proj-1", costLimit: 50, assumeYes: true}
		err := cmd.Run(context.Background(), env, nil)
		if _, ok := errors.AsType[*usageError](err); !ok || err.Error() != msgCredentialsRequired {
			t.Errorf("mode %v, no --credentials: err = %v; want the usage error %q", mode, err, msgCredentialsRequired)
		}
		if exists, _ := dir.InstanceExists("prod"); exists || f.created != nil {
			t.Errorf("mode %v: an install without a key recorded an instance or created a cluster", mode)
		}
	}
	if want := "--credentials is required: since ADR 0023 M2.7 the commands that write to an instance's cluster read and write it " +
		"as the service account whose key --credentials names, never as Application Default Credentials"; msgCredentialsRequired != want {
		t.Errorf("the refusal is %q; want %q", msgCredentialsRequired, want)
	}

	// Each layer refuses on its own: the inputs, with no prompt when nobody
	// is there to answer, and the read of the key file.
	var quiet bytes.Buffer
	c := &installCommand{name: "prod", provider: prov, project: "proj-1", region: "us-central1", costLimit: 50}
	if err := c.resolveInputs(false, newPrompter(strings.NewReader(""), &quiet)); err == nil || err.Error() != msgCredentialsRequired || quiet.Len() != 0 {
		t.Errorf("non-interactive inputs with no --credentials: err = %v, prompted %q", err, quiet.String())
	}
	if key, err := readCredentials(""); key != nil || err == nil || err.Error() != msgCredentialsRequired {
		t.Errorf("readCredentials(\"\") = %q, %v; want the refusal", key, err)
	}

	// A --credentials that names a file holding no key the writer could open
	// (S-F1): empty, /dev/null, only white space, or not a service-account
	// key farcast uses. Planck reads an empty key as Application Default
	// Credentials, so without this an install would create a cluster as this
	// machine's ADC and record an instance every writing command refuses.
	// Each is a usage error before the provider is opened, with nothing
	// recorded and no cluster created, and none echoes the file.
	dir := t.TempDir()
	keyFile := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, row := range []struct {
		name, path, want string
	}{
		{"a zero-byte file", keyFile("empty.json", ""), msgCredentialsEmpty},
		{"/dev/null", os.DevNull, msgCredentialsEmpty},
		{"white space", keyFile("blank.json", "  \n\t\n"), msgCredentialsEmpty},
		{"not a service-account key", keyFile("user.json", `{"type":"authorized_user","client_id":"c","refresh_token":"planted-refresh-token"}`),
			"--credentials does not hold a key the instance's writer could open, so nothing was created: " +
				"the stored service-account key is not a service-account key farcast uses (type)"},
		{"no private key", keyFile("nokey.json", `{"type":"service_account","client_email":"installer@proj-1.iam.gserviceaccount.com"}`),
			"--credentials does not hold a key the instance's writer could open, so nothing was created: " +
				"the stored service-account key is not a service-account key farcast uses (private_key)"},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := &fakeProvider{}
			opened := 0
			prov := "fake-" + strings.ReplaceAll(t.Name(), "/", "-")
			planck.Register(prov, func(planck.Config) (planck.Provider, error) { opened++; return f, nil })
			for _, mode := range []output.Mode{output.ModeHuman, output.ModeJSON} {
				env, out, errb, cfg := newInstallEnv(t, mode)
				cmd := &installCommand{credentials: row.path, name: "prod", provider: prov, project: "proj-1", costLimit: 50, assumeYes: true}
				err := cmd.Run(context.Background(), env, nil)
				if _, ok := errors.AsType[*usageError](err); !ok || err.Error() != row.want {
					t.Errorf("mode %v: err = %v; want the usage error %q", mode, err, row.want)
				}
				if exists, _ := cfg.InstanceExists("prod"); exists || f.created != nil || opened != 0 {
					t.Errorf("mode %v: recorded %v, created %+v, opened the provider %d times", mode, exists, f.created, opened)
				}
				if strings.Contains(out.String()+errb.String()+err.Error(), "planted-refresh-token") {
					t.Errorf("mode %v: the refusal echoes the file", mode)
				}
			}
			if key, err := readCredentials(row.path); key != nil || err == nil || err.Error() != row.want {
				t.Errorf("readCredentials(%s) = %q, %v; want %q", row.name, key, err, row.want)
			}
		})
	}
	if want := "--credentials names an empty file: since ADR 0023 M2.7 the commands that write to an instance's cluster read and write it " +
		"as the service account whose key --credentials names, never as Application Default Credentials"; msgCredentialsEmpty != want {
		t.Errorf("the empty-file refusal is %q; want %q", msgCredentialsEmpty, want)
	}

	// At the prompt: a blank answer is refused, never read as ADC.
	for _, answer := range []string{"\n", "   \n"} {
		var errb bytes.Buffer
		c := &installCommand{name: "prod", provider: prov, project: "proj-1", region: "us-central1", costLimit: 50}
		err := c.resolveInputs(true, newPrompter(strings.NewReader(answer), &errb))
		if _, ok := errors.AsType[*usageError](err); !ok || err.Error() != msgCredentialsRequired {
			t.Errorf("answer %q: err = %v; want the usage error %q", answer, err, msgCredentialsRequired)
		}
		if got := errb.String(); got != "Path to service-account key JSON: " {
			t.Errorf("answer %q: the prompt was %q", answer, got)
		}
	}
	// A path given at the prompt is taken.
	c = &installCommand{name: "prod", provider: prov, project: "proj-1", region: "us-central1", costLimit: 50}
	if err := c.resolveInputs(true, newPrompter(strings.NewReader("/keys/installer.json\n"), &bytes.Buffer{})); err != nil || c.credentials != "/keys/installer.json" {
		t.Errorf("a path at the prompt: err = %v, credentials = %q", err, c.credentials)
	}

	usage := (&installCommand{}).Usage()
	if !strings.Contains(usage, "--credentials <path>   Path to a service-account key JSON (required)") || strings.Contains(usage, "ADC") {
		t.Errorf("install's usage does not say --credentials is required, or still offers ADC:\n%s", usage)
	}
}
