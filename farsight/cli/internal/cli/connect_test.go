package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/buildinfo"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/image"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/fatline"
	"github.com/sofmon/farcast/fatline/identity"
	"github.com/sofmon/farcast/fatline/tunnel"
	"github.com/sofmon/farcast/planck"
)

type fakeCluster struct {
	applied  [][]byte
	rollouts int
	ip       string
	ipErr    error
	applyErr error
}

func (f *fakeCluster) Apply(_ context.Context, m []byte) error {
	f.applied = append(f.applied, m)
	return f.applyErr
}

func (f *fakeCluster) RolloutStatus(_ context.Context, _, _ string, _ time.Duration) error {
	f.rollouts++
	return nil
}

func (f *fakeCluster) WaitExternalIP(_ context.Context, _, _ string, _ time.Duration) (string, error) {
	if f.ipErr != nil {
		return "", f.ipErr
	}
	return f.ip, nil
}

type fakeConn struct {
	st     fatline.ConnStatus
	closed bool
}

func (f *fakeConn) Status(context.Context) (fatline.ConnStatus, error) { return f.st, nil }
func (f *fakeConn) Close() error                                       { f.closed = true; return nil }

// fakeBuilder stands in for the in-CLI image builder: it records what connect
// asked for and answers with what the test wants, so nothing is compiled and no
// registry is contacted.
type fakeBuilder struct {
	resolved   []string // refs Resolve was asked for, in order
	pinned     string   // Resolve's answer; derived from the ref when empty
	resolveErr error

	built    []image.Options // BuildAndPush calls, in order
	builtRef string          // BuildAndPush's answer; derived from the ref when empty
	buildErr error

	user, pass string // credentials the most recent call received
}

func (f *fakeBuilder) Resolve(_ context.Context, ref, user, pass string) (string, error) {
	f.resolved = append(f.resolved, ref)
	f.user, f.pass = user, pass
	if f.resolveErr != nil {
		return "", f.resolveErr
	}
	if f.pinned != "" {
		return f.pinned, nil
	}
	return pinnedRef(ref, "a"), nil
}

func (f *fakeBuilder) BuildAndPush(_ context.Context, opts image.Options, user, pass string) (string, error) {
	f.built = append(f.built, opts)
	f.user, f.pass = user, pass
	if f.buildErr != nil {
		return "", f.buildErr
	}
	if f.builtRef != "" {
		return f.builtRef, nil
	}
	return pinnedRef(opts.Ref, "b"), nil
}

// pinnedRef mimics what the real builder returns: the tag is dropped, because
// the digest is what identifies (and pins) the image.
func pinnedRef(ref, hexDigit string) string {
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref = ref[:i]
	}
	return ref + "@sha256:" + strings.Repeat(hexDigit, 64)
}

// testConnect wires every cloud-touching seam to a fake, so no connect test can
// open a cloud provider, reach a registry, or build an image by accident.
func testConnect(p planck.Provider, b imageBuilder) *connectCommand {
	c := newConnectCommand()
	c.openProvider = func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) {
		return p, nil
	}
	c.newBuilder = func(func(string)) imageBuilder { return b }
	c.findSource = func(string) (string, error) {
		return "", errors.New("no farcast checkout at or above the working directory")
	}
	return c
}

// connectedDial answers every dial with a healthy boundary.
func connectedDial(allowlist ...string) func(context.Context, string, tunnel.ClientIdentity) (tunnelConn, error) {
	return func(context.Context, string, tunnel.ClientIdentity) (tunnelConn, error) {
		return &fakeConn{st: fatline.ConnStatus{Connected: true, Allowlist: allowlist}}, nil
	}
}

// instanceImageRef is the default --fatline-image for the fake registry: the
// instance's own registry at the system path, tagged with this build's version.
func instanceImageRef(instance string) string {
	return "us-central1-docker.pkg.dev/proj-1/farcast-" + instance + "/system/fatline:" + buildinfo.Get().Version
}

func testEnv(dir config.Dir, mode output.Mode) (*Env, *bytes.Buffer) {
	var out, errb bytes.Buffer
	env := &Env{
		Out:       &out,
		Err:       &errb,
		In:        strings.NewReader(""), // not a terminal → non-interactive
		Printer:   &output.Printer{Mode: mode, Out: &out, Err: &errb},
		ConfigDir: dir,
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	return env, &out
}

func installedInstance(t *testing.T, dir config.Dir, name string) *config.InstanceMetadata {
	t.Helper()
	// t.TempDir() is 0755; the config store requires 0700 for credential safety.
	if err := os.Chmod(string(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := dir.CreateInstance(name); err != nil {
		t.Fatal(err)
	}
	meta := &config.InstanceMetadata{
		Name:      name,
		Provider:  "gke",
		Region:    "us-central1",
		Cluster:   "farcast-" + name,
		Status:    config.InstanceRunning,
		CostLimit: config.CostLimit{Amount: 50, Currency: "USD", Period: "monthly"},
	}
	if err := dir.SaveInstanceMetadata(name, meta); err != nil {
		t.Fatal(err)
	}
	if err := dir.SaveInstanceKubeconfig(name, []byte("fake-kubeconfig")); err != nil {
		t.Fatal(err)
	}
	// connect opens the provider from the stored credential to reach the
	// instance's registry, so an installed instance has one.
	if err := dir.SaveInstanceCredentials(name, &config.InstanceCredentials{Provider: "gke"}); err != nil {
		t.Fatal(err)
	}
	return meta
}

func TestConnectBootstrapsAndReports(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	installedInstance(t, dir, name)

	fc := &fakeCluster{ip: "34.0.0.1"}
	fb := &fakeBuilder{}
	var dialed string
	c := testConnect(&fakeProvider{}, fb)
	c.assumeYes = true
	c.fatlineImage = "img:test" // an explicit override: deployed as given
	c.newCluster = func(string) clusterApplier { return fc }
	c.dial = func(_ context.Context, endpoint string, id tunnel.ClientIdentity) (tunnelConn, error) {
		dialed = endpoint
		if id.ServerName != "prod.fatline.farcast" {
			t.Errorf("dial serverName=%q, want prod.fatline.farcast", id.ServerName)
		}
		if len(id.Cert.Certificate) == 0 || id.CA == nil {
			t.Error("dial identity missing client cert or CA pool")
		}
		return &fakeConn{st: fatline.ConnStatus{Connected: true, Allowlist: []string{"api.stripe.com"}}}, nil
	}

	env, out := testEnv(dir, output.ModeHuman)
	if err := c.Run(context.Background(), env, []string{name}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	if ok, _ := dir.InstanceMTLSExists(name); !ok {
		t.Fatal("expected the mTLS identity to be minted on first connect")
	}
	if len(fc.applied) != 1 || len(fc.applied[0]) == 0 {
		t.Fatalf("expected exactly one non-empty Apply; got %d", len(fc.applied))
	}
	if len(fb.resolved) != 0 || len(fb.built) != 0 {
		t.Fatalf("an explicit --fatline-image must not preflight or build: resolved=%v built=%v", fb.resolved, fb.built)
	}
	if !bytes.Contains(fc.applied[0], []byte("img:test")) {
		t.Fatalf("deploy did not use the overridden image:\n%s", fc.applied[0])
	}
	meta, _ := dir.LoadInstanceMetadata(name)
	if !meta.FatLineDeployed || meta.Carrier == nil || meta.Carrier.Endpoint != "34.0.0.1:8443" {
		t.Fatalf("carrier not recorded: deployed=%v carrier=%+v", meta.FatLineDeployed, meta.Carrier)
	}
	if meta.Carrier.ServerName != "prod.fatline.farcast" {
		t.Fatalf("carrier server name=%q", meta.Carrier.ServerName)
	}
	if dialed != "https://34.0.0.1:8443" {
		t.Fatalf("dialed=%q, want https://34.0.0.1:8443", dialed)
	}
	if !strings.Contains(out.String(), `connected to "prod"`) {
		t.Fatalf("output missing connected line:\n%s", out.String())
	}
}

func TestConnectCostGateRequiresYes(t *testing.T) {
	dir := config.Dir(t.TempDir())
	installedInstance(t, dir, "prod")

	fc := &fakeCluster{ip: "1.2.3.4"}
	c := testConnect(&fakeProvider{}, &fakeBuilder{}) // assumeYes stays false; env is non-interactive
	c.newCluster = func(string) clusterApplier { return fc }
	c.dial = func(context.Context, string, tunnel.ClientIdentity) (tunnelConn, error) {
		t.Fatal("must not dial without cost confirmation")
		return nil, nil
	}

	env, _ := testEnv(dir, output.ModeHuman)
	err := c.Run(context.Background(), env, []string{"prod"})
	var ue *usageError
	if !errors.As(err, &ue) {
		t.Fatalf("err=%v, want a usageError (cost not confirmed, non-interactive)", err)
	}
	if len(fc.applied) != 0 {
		t.Fatal("must not deploy without cost confirmation")
	}
	meta, _ := dir.LoadInstanceMetadata("prod")
	if meta.FatLineDeployed {
		t.Fatal("must not mark deployed when the cost gate was refused")
	}
}

func TestConnectStatusOnlyBeforeBootstrap(t *testing.T) {
	dir := config.Dir(t.TempDir())
	installedInstance(t, dir, "prod")

	fc := &fakeCluster{}
	c := testConnect(&fakeProvider{}, &fakeBuilder{})
	c.statusOnly = true
	c.newCluster = func(string) clusterApplier { return fc }
	c.dial = func(context.Context, string, tunnel.ClientIdentity) (tunnelConn, error) {
		t.Fatal("must not dial when not yet connected")
		return nil, nil
	}

	env, _ := testEnv(dir, output.ModeHuman)
	if err := c.Run(context.Background(), env, []string{"prod"}); err == nil {
		t.Fatal("expected an error for --status before the instance is connected")
	}
	if len(fc.applied) != 0 {
		t.Fatal("--status must never deploy")
	}
}

func TestConnectReconnectSkipsBootstrap(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	meta := installedInstance(t, dir, name)

	mat, err := identity.Mint(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := dir.SaveInstanceMTLS(name, toConfigMTLS(mat)); err != nil {
		t.Fatal(err)
	}
	meta.FatLineDeployed = true
	meta.Carrier = &config.Carrier{Type: "nlb", Endpoint: "9.9.9.9:8443", ServerName: identity.ServerName(name)}
	if err := dir.SaveInstanceMetadata(name, meta); err != nil {
		t.Fatal(err)
	}

	fc := &fakeCluster{}
	fp := &fakeProvider{}
	fb := &fakeBuilder{}
	var dialed string
	c := testConnect(fp, fb)
	c.newCluster = func(string) clusterApplier { return fc }
	c.dial = func(_ context.Context, endpoint string, _ tunnel.ClientIdentity) (tunnelConn, error) {
		dialed = endpoint
		return &fakeConn{st: fatline.ConnStatus{Connected: true}}, nil
	}

	env, _ := testEnv(dir, output.ModeHuman)
	if err := c.Run(context.Background(), env, []string{name}); err != nil {
		t.Fatal(err)
	}
	if len(fc.applied) != 0 {
		t.Fatal("a reconnect must not re-deploy")
	}
	if dialed != "https://9.9.9.9:8443" {
		t.Fatalf("dialed=%q, want the stored endpoint", dialed)
	}
	// The registry is still re-ensured (ADR 0007), so an instance installed
	// before it existed converges — but nothing is preflighted or built.
	if len(fp.ensured) != 1 {
		t.Fatalf("EnsureRegistry called %d times on reconnect, want 1", len(fp.ensured))
	}
	if len(fb.resolved) != 0 || len(fb.built) != 0 {
		t.Fatalf("a reconnect must not touch images: resolved=%v built=%v", fb.resolved, fb.built)
	}
	meta, _ = dir.LoadInstanceMetadata(name)
	if meta.Registry == nil || meta.Registry.Prefix == "" {
		t.Fatalf("the re-ensured registry was not recorded: %+v", meta.Registry)
	}
}

func TestConnectDefaultsImageToTheInstanceRegistry(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	installedInstance(t, dir, name)

	fc := &fakeCluster{ip: "34.0.0.1"}
	fp := &fakeProvider{}
	fb := &fakeBuilder{}
	c := testConnect(fp, fb)
	c.assumeYes = true
	c.newCluster = func(string) clusterApplier { return fc }
	c.dial = connectedDial()

	env, out := testEnv(dir, output.ModeHuman)
	if err := c.Run(context.Background(), env, []string{name}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	want := instanceImageRef(name)
	if len(fb.resolved) != 1 || fb.resolved[0] != want {
		t.Fatalf("preflighted %v, want [%s] derived from the instance registry", fb.resolved, want)
	}
	if len(fb.built) != 0 {
		t.Fatal("a preflight hit must not build anything")
	}
	if fb.user != "oauth2accesstoken" || fb.pass != "tok" {
		t.Errorf("preflight used %q/%q, want the minted registry token", fb.user, fb.pass)
	}
	// The deploy is pinned by digest, not by the tag that was looked up.
	pinned := pinnedRef(want, "a")
	if !bytes.Contains(fc.applied[0], []byte(pinned)) {
		t.Fatalf("deploy did not carry the digest-pinned image %s:\n%s", pinned, fc.applied[0])
	}
	meta, _ := dir.LoadInstanceMetadata(name)
	if meta.Registry == nil || meta.Registry.FatLineDigest != pinned {
		t.Fatalf("deployed digest not recorded: %+v", meta.Registry)
	}
	if !strings.Contains(out.String(), "registry:") || !strings.Contains(out.String(), "registry ~$0/mo") {
		t.Errorf("output missing the registry line and cost item:\n%s", out.String())
	}
}

func TestConnectBuildsTheImageWhenTheRegistryHasNone(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	installedInstance(t, dir, name)

	fc := &fakeCluster{ip: "34.0.0.1"}
	fb := &fakeBuilder{resolveErr: image.ErrNotFound}
	var askedFor string
	c := testConnect(&fakeProvider{}, fb)
	c.assumeYes = true
	c.sourceDir = "/checkouts/farcast"
	c.findSource = func(dir string) (string, error) { askedFor = dir; return "/checkouts/farcast", nil }
	c.newCluster = func(string) clusterApplier { return fc }
	c.dial = connectedDial()

	env, _ := testEnv(dir, output.ModeHuman)
	if err := c.Run(context.Background(), env, []string{name}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	if askedFor != "/checkouts/farcast" {
		t.Errorf("--source was not passed to the checkout lookup: %q", askedFor)
	}
	if len(fb.built) != 1 {
		t.Fatalf("BuildAndPush called %d times, want 1", len(fb.built))
	}
	opts := fb.built[0]
	if opts.SourceDir != "/checkouts/farcast" || opts.Package != "./fatline/cmd/fatline" ||
		opts.Ref != instanceImageRef(name) || opts.BinaryPath != "/fatline" ||
		len(opts.Entrypoint) != 1 || opts.Entrypoint[0] != "/fatline" {
		t.Fatalf("build options = %+v", opts)
	}
	if fb.user != "oauth2accesstoken" || fb.pass != "tok" {
		t.Errorf("push used %q/%q, want the minted registry token", fb.user, fb.pass)
	}
	pushed := pinnedRef(opts.Ref, "b")
	if !bytes.Contains(fc.applied[0], []byte(pushed)) {
		t.Fatalf("deploy did not carry the pushed digest %s:\n%s", pushed, fc.applied[0])
	}
	meta, _ := dir.LoadInstanceMetadata(name)
	if meta.Registry == nil || meta.Registry.FatLineDigest != pushed {
		t.Fatalf("pushed digest not recorded: %+v", meta.Registry)
	}
}

func TestConnectMissingImageWithoutCheckoutFails(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	installedInstance(t, dir, name)

	fc := &fakeCluster{ip: "34.0.0.1"}
	fb := &fakeBuilder{resolveErr: image.ErrNotFound}
	c := testConnect(&fakeProvider{}, fb) // findSource fails by default
	c.assumeYes = true
	c.newCluster = func(string) clusterApplier { return fc }
	c.dial = func(context.Context, string, tunnel.ClientIdentity) (tunnelConn, error) {
		t.Fatal("must not dial when there is no image to deploy")
		return nil, nil
	}

	env, _ := testEnv(dir, output.ModeHuman)
	err := c.Run(context.Background(), env, []string{name})
	if err == nil {
		t.Fatal("expected an error when the image is missing and there is no checkout")
	}
	// The message has to name what is missing and how to supply it.
	for _, want := range []string{instanceImageRef(name), "checkout", "--source"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	if len(fb.built) != 0 || len(fc.applied) != 0 {
		t.Fatal("nothing may be built or deployed without an image")
	}
}

func TestConnectMissingImageNonInteractiveRequiresYes(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	meta := installedInstance(t, dir, name)
	// A bootstrap interrupted after the deploy: the load balancer already
	// exists, so its cost gate is behind us and the build gate is what answers.
	meta.FatLineDeployed = true
	if err := dir.SaveInstanceMetadata(name, meta); err != nil {
		t.Fatal(err)
	}

	fc := &fakeCluster{ip: "34.0.0.1"}
	fb := &fakeBuilder{resolveErr: image.ErrNotFound}
	c := testConnect(&fakeProvider{}, fb) // assumeYes stays false; env is non-interactive
	c.findSource = func(string) (string, error) { return "/checkouts/farcast", nil }
	c.newCluster = func(string) clusterApplier { return fc }

	env, _ := testEnv(dir, output.ModeHuman)
	err := c.Run(context.Background(), env, []string{name})
	var ue *usageError
	if !errors.As(err, &ue) {
		t.Fatalf("err=%v, want a usageError (build not confirmed, non-interactive)", err)
	}
	if !strings.Contains(err.Error(), "/checkouts/farcast") || !strings.Contains(err.Error(), "--yes") {
		t.Errorf("usage error %q must name what it would build and how to allow it", err)
	}
	if len(fb.built) != 0 || len(fc.applied) != 0 {
		t.Fatal("must not build or deploy without confirmation")
	}
}

func TestConnectStatusDoesNoRegistryWork(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	meta := installedInstance(t, dir, name)

	mat, err := identity.Mint(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := dir.SaveInstanceMTLS(name, toConfigMTLS(mat)); err != nil {
		t.Fatal(err)
	}
	meta.FatLineDeployed = true
	meta.Carrier = &config.Carrier{Type: "nlb", Endpoint: "9.9.9.9:8443", ServerName: identity.ServerName(name)}
	if err := dir.SaveInstanceMetadata(name, meta); err != nil {
		t.Fatal(err)
	}

	fc := &fakeCluster{}
	c := newConnectCommand()
	c.statusOnly = true
	c.newCluster = func(string) clusterApplier { return fc }
	c.dial = connectedDial()
	// A status probe must work with no registry access at all: no provider is
	// opened, so no credential is read and no cloud API is called.
	c.openProvider = func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) {
		t.Error("--status must not open the cloud provider")
		return nil, errors.New("unreachable")
	}
	c.newBuilder = func(func(string)) imageBuilder {
		t.Error("--status must not preflight or build an image")
		return &fakeBuilder{}
	}

	env, _ := testEnv(dir, output.ModeHuman)
	if err := c.Run(context.Background(), env, []string{name}); err != nil {
		t.Fatalf("connect --status: %v", err)
	}
	if len(fc.applied) != 0 {
		t.Fatal("--status must never deploy")
	}
}

func TestConnectRegistryFailureDoesNotBreakReconnect(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	meta := installedInstance(t, dir, name)

	mat, err := identity.Mint(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := dir.SaveInstanceMTLS(name, toConfigMTLS(mat)); err != nil {
		t.Fatal(err)
	}
	meta.FatLineDeployed = true
	meta.Carrier = &config.Carrier{Type: "nlb", Endpoint: "9.9.9.9:8443", ServerName: identity.ServerName(name)}
	if err := dir.SaveInstanceMetadata(name, meta); err != nil {
		t.Fatal(err)
	}

	// The stored installer credential predates ADR 0007's role, so the
	// defensive ensure is refused — a working reconnect must survive it.
	fp := &fakeProvider{ensureErr: errors.New("permission denied on artifactregistry.repositories.create")}
	fc := &fakeCluster{}
	c := testConnect(fp, &fakeBuilder{})
	c.newCluster = func(string) clusterApplier { return fc }
	c.dial = connectedDial()

	env, out := testEnv(dir, output.ModeHuman)
	if err := c.Run(context.Background(), env, []string{name}); err != nil {
		t.Fatalf("a registry failure must not break a reconnect: %v", err)
	}
	if !strings.Contains(out.String(), `connected to "prod"`) {
		t.Fatalf("output missing the connected line:\n%s", out.String())
	}
	errb := env.Err.(*bytes.Buffer)
	if !strings.Contains(errb.String(), "Warning") || !strings.Contains(errb.String(), "permission denied") {
		t.Errorf("expected a warning naming the refusal:\n%s", errb.String())
	}
}

func TestConnectRegistryFailureStopsBootstrap(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	installedInstance(t, dir, name)

	fp := &fakeProvider{ensureErr: errors.New("permission denied on artifactregistry.repositories.create")}
	fc := &fakeCluster{ip: "34.0.0.1"}
	c := testConnect(fp, &fakeBuilder{})
	c.assumeYes = true
	c.newCluster = func(string) clusterApplier { return fc }
	c.dial = func(context.Context, string, tunnel.ClientIdentity) (tunnelConn, error) {
		t.Fatal("must not dial when the bootstrap has no image source")
		return nil, nil
	}

	env, _ := testEnv(dir, output.ModeHuman)
	err := c.Run(context.Background(), env, []string{name})
	if err == nil || !strings.Contains(err.Error(), "ensure the image registry") {
		t.Fatalf("err=%v, want the ensure failure (a first deploy needs the registry)", err)
	}
	if len(fc.applied) != 0 {
		t.Fatal("must not deploy without an image source")
	}
	meta, _ := dir.LoadInstanceMetadata(name)
	if meta.FatLineDeployed {
		t.Fatal("must not mark deployed when the bootstrap failed")
	}
}

func TestConnectExplicitImageSurvivesRegistryFailure(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	installedInstance(t, dir, name)

	fp := &fakeProvider{ensureErr: errors.New("permission denied")}
	fc := &fakeCluster{ip: "34.0.0.1"}
	c := testConnect(fp, &fakeBuilder{})
	c.assumeYes = true
	c.fatlineImage = "registry.example/fatline@sha256:" + strings.Repeat("c", 64)
	c.newCluster = func(string) clusterApplier { return fc }
	c.dial = connectedDial()

	env, _ := testEnv(dir, output.ModeHuman)
	if err := c.Run(context.Background(), env, []string{name}); err != nil {
		t.Fatalf("an operator-supplied image needs no registry: %v", err)
	}
	if !bytes.Contains(fc.applied[0], []byte(c.fatlineImage)) {
		t.Fatalf("deploy did not use the supplied image:\n%s", fc.applied[0])
	}
}

func TestConnectUnsupportedCarrier(t *testing.T) {
	dir := config.Dir(t.TempDir())
	installedInstance(t, dir, "prod")
	c := newConnectCommand()
	c.carrier = "cp-forward"
	env, _ := testEnv(dir, output.ModeHuman)
	err := c.Run(context.Background(), env, []string{"prod"})
	var ue *usageError
	if !errors.As(err, &ue) {
		t.Fatalf("err=%v, want a usageError for an unsupported carrier", err)
	}
}

func TestConnectJSONOutput(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	installedInstance(t, dir, name)

	fc := &fakeCluster{ip: "34.0.0.2"}
	c := testConnect(&fakeProvider{}, &fakeBuilder{})
	c.assumeYes = true
	c.newCluster = func(string) clusterApplier { return fc }
	c.dial = connectedDial("api.x")

	env, out := testEnv(dir, output.ModeJSON)
	if err := c.Run(context.Background(), env, []string{name}); err != nil {
		t.Fatal(err)
	}
	var res struct {
		Name      string `json:"name"`
		Connected bool   `json:"connected"`
		Carrier   string `json:"carrier"`
		Endpoint  string `json:"endpoint"`
		Identity  string `json:"identity"`
		Registry  string `json:"registry"`
		Image     string `json:"image"`
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("decode JSON result: %v\n%s", err, out.String())
	}
	if !res.Connected || res.Carrier != "nlb" || res.Endpoint != "34.0.0.2:8443" || res.Identity != "farcast://prod/operator" {
		t.Fatalf("result=%+v", res)
	}
	if res.Registry != "us-central1-docker.pkg.dev/proj-1/farcast-prod" || res.Image != pinnedRef(instanceImageRef(name), "a") {
		t.Fatalf("registry/image not reported: %+v", res)
	}
}

// TestConnectRejectsImageFlagsOnReconnect covers the flags that only a
// bootstrap can honour. A reconnect re-dials what is already running, so
// accepting --fatline-image there would print success while the old image kept
// serving — the worst possible answer when the flag is being used to roll out a
// FatLine fix.
func TestConnectRejectsImageFlagsOnReconnect(t *testing.T) {
	for _, tc := range []struct {
		name  string
		apply func(*connectCommand)
		want  string
	}{
		{"fatline-image", func(c *connectCommand) { c.fatlineImage = "example.test/repo/fatline:2" }, "--fatline-image"},
		{"source", func(c *connectCommand) { c.sourceDir = t.TempDir() }, "--source"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := config.Dir(t.TempDir())
			const name = "prod"
			meta := installedInstance(t, dir, name)
			mat, err := identity.Mint(name)
			if err != nil {
				t.Fatal(err)
			}
			if err := dir.SaveInstanceMTLS(name, toConfigMTLS(mat)); err != nil {
				t.Fatal(err)
			}
			meta.FatLineDeployed = true
			meta.Carrier = &config.Carrier{Type: "nlb", Endpoint: "9.9.9.9:8443", ServerName: identity.ServerName(name)}
			if err := dir.SaveInstanceMetadata(name, meta); err != nil {
				t.Fatal(err)
			}

			fc := &fakeCluster{}
			c := testConnect(&fakeProvider{}, &fakeBuilder{})
			c.newCluster = func(string) clusterApplier { return fc }
			c.dial = connectedDial()
			tc.apply(c)

			env, _ := testEnv(dir, output.ModeHuman)
			err = c.Run(context.Background(), env, []string{name})
			if err == nil {
				t.Fatal("reconnect accepted an image flag it cannot honour")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error does not name the ignored flag: %v", err)
			}
			if fc.applied != nil {
				t.Error("refused connect still applied a workload")
			}
		})
	}
}

// TestConnectStatusMintsNothing guards the trust root: --status on an instance
// that was installed but never connected must fail without creating the
// instance's CA. A read-only health probe that writes ca.key as a side effect is
// the kind of surprise a sovereign-identity design cannot afford.
func TestConnectStatusMintsNothing(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	installedInstance(t, dir, name)

	c := testConnect(&fakeProvider{}, &fakeBuilder{})
	c.statusOnly = true
	c.dial = connectedDial()

	env, _ := testEnv(dir, output.ModeHuman)
	if err := c.Run(context.Background(), env, []string{name}); err == nil {
		t.Fatal("--status succeeded against an instance that was never connected")
	}
	exists, err := dir.InstanceMTLSExists(name)
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Error("--status minted and stored the instance's mTLS identity; it must only ever load it")
	}
}

// TestConnectStatusRejectsImageFlags: --status deploys and builds nothing, so
// the image flags cannot mean anything there. Accepting them silently is the
// same defect as accepting them on a reconnect.
func TestConnectStatusRejectsImageFlags(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	meta := installedInstance(t, dir, name)
	mat, err := identity.Mint(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := dir.SaveInstanceMTLS(name, toConfigMTLS(mat)); err != nil {
		t.Fatal(err)
	}
	meta.FatLineDeployed = true
	meta.Carrier = &config.Carrier{Type: "nlb", Endpoint: "9.9.9.9:8443", ServerName: identity.ServerName(name)}
	if err := dir.SaveInstanceMetadata(name, meta); err != nil {
		t.Fatal(err)
	}

	c := testConnect(&fakeProvider{}, &fakeBuilder{})
	c.statusOnly = true
	c.fatlineImage = "example.test/repo/fatline:2"
	c.dial = connectedDial()

	env, _ := testEnv(dir, output.ModeHuman)
	if err := c.Run(context.Background(), env, []string{name}); err == nil {
		t.Fatal("--status accepted --fatline-image")
	} else if !strings.Contains(err.Error(), "no effect") {
		t.Errorf("err = %v, want it to say the flag has no effect", err)
	}
}

// TestConnectRefusesToRemintForADeployedInstance: FatLine already trusts a CA;
// minting a replacement would only produce a certificate it must reject, so the
// missing trust root has to be reported, not manufactured.
func TestConnectRefusesToRemintForADeployedInstance(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	meta := installedInstance(t, dir, name)
	meta.FatLineDeployed = true
	meta.Carrier = &config.Carrier{Type: "nlb", Endpoint: "9.9.9.9:8443", ServerName: identity.ServerName(name)}
	if err := dir.SaveInstanceMetadata(name, meta); err != nil {
		t.Fatal(err)
	} // note: no mTLS material saved

	c := testConnect(&fakeProvider{}, &fakeBuilder{})
	c.dial = connectedDial()

	env, _ := testEnv(dir, output.ModeHuman)
	err := c.Run(context.Background(), env, []string{name})
	if err == nil {
		t.Fatal("minted a fresh CA for an instance already running FatLine")
	}
	if !strings.Contains(err.Error(), "cannot be recovered") {
		t.Errorf("err = %v, want it to explain the trust root is unrecoverable", err)
	}
	exists, err := dir.InstanceMTLSExists(name)
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Error("a replacement CA was written for a deployed instance")
	}
}
