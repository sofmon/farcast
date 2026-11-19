package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/buildinfo"
	"github.com/sofmon/farcast/farsight/cli/internal/components"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/image"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
	"github.com/sofmon/farcast/farsight/cli/internal/oci"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	"github.com/sofmon/farcast/fatline"
	"github.com/sofmon/farcast/fatline/identity"
	"github.com/sofmon/farcast/fatline/tunnel"
	"github.com/sofmon/farcast/planck"
)

type fakeCluster struct {
	applied    [][]byte
	rollouts   int
	ip         string
	ipCalls    int
	ipErr      error
	applyErr   error
	rolloutErr error
	// onApply runs once each apply has landed.
	onApply func()

	// namespaces is what the cluster contains. Empty means an empty cluster,
	// deliberately: a fake that answers "yes, it exists" to everything is what
	// let kernel deploy build an image for a namespace that was not there.
	namespaces    []string
	namespacesErr error

	// uidReads counts the writer's preflight reads (A20-11), and uid and
	// uidErr answer them: farcast-system's uid, "" for none (A23-49).
	uidReads int
	uid      string
	uidErr   error
}

func (f *fakeCluster) NamespaceUID(context.Context, string) (string, error) {
	f.uidReads++
	if f.uidErr != nil {
		return "", f.uidErr
	}
	return f.uid, nil
}

func (f *fakeCluster) Apply(_ context.Context, m []byte) error {
	checkApplied(m)
	f.applied = append(f.applied, m)
	if f.onApply != nil {
		f.onApply()
	}
	return f.applyErr
}

func (f *fakeCluster) RolloutStatus(_ context.Context, _, _ string, _ time.Duration) error {
	f.rollouts++
	return f.rolloutErr
}

func (f *fakeCluster) Namespaces(context.Context) ([]string, error) {
	return f.namespaces, f.namespacesErr
}

func (f *fakeCluster) WaitExternalIP(_ context.Context, _, _ string, _ time.Duration) (string, error) {
	f.ipCalls++
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
	pinned     string   // Resolve's answer for a tag; derived from the ref when empty
	resolveErr error
	// resolveFn, when set, answers every Resolve instead of the fields above.
	resolveFn func(ref string) (string, error)

	built    []image.Options // BuildAndPush calls, in order
	builtRef string          // BuildAndPush's answer; derived from the repository when empty
	builtGo  string          // the Go BuildAndPush reports; "go1.27.5" when empty
	buildErr error

	embedded  []image.EmbeddedOptions // PushEmbedded calls, in order
	pushedRef string                  // PushEmbedded's answer; the Ref's repository @ opts.Manifest when empty
	pushErr   error

	user, pass string // credentials the most recent call received
}

// tagDigest is the hex digit a version tag resolves to by default: the one the
// fake carried components' manifests are made of, so a tag holds the image
// this farcast carries unless a test says otherwise.
const tagDigest = "e"

func (f *fakeBuilder) Resolve(_ context.Context, ref, user, pass string) (string, error) {
	f.resolved = append(f.resolved, ref)
	f.user, f.pass = user, pass
	if f.resolveFn != nil {
		return f.resolveFn(ref)
	}
	if f.resolveErr != nil {
		return "", f.resolveErr
	}
	if strings.Contains(ref, "@sha256:") {
		return ref, nil // a HEAD by digest answers with the digest it was asked for
	}
	if f.pinned != "" {
		return f.pinned, nil
	}
	return pinnedRef(ref, tagDigest), nil
}

func (f *fakeBuilder) BuildAndPush(_ context.Context, opts image.Options, user, pass string) (image.Pushed, error) {
	f.built = append(f.built, opts)
	f.user, f.pass = user, pass
	if f.buildErr != nil {
		return image.Pushed{}, f.buildErr
	}
	goV := f.builtGo
	if goV == "" {
		goV = "go1.27.5"
	}
	if f.builtRef != "" {
		return image.Pushed{Ref: f.builtRef, GoVersion: goV}, nil
	}
	return image.Pushed{Ref: pinnedRef(opts.Repository, "b"), GoVersion: goV}, nil
}

func (f *fakeBuilder) PushEmbedded(_ context.Context, opts image.EmbeddedOptions, user, pass string) (image.Pushed, error) {
	f.embedded = append(f.embedded, opts)
	f.user, f.pass = user, pass
	if f.pushErr != nil {
		return image.Pushed{}, f.pushErr
	}
	if f.pushedRef != "" {
		return image.Pushed{Ref: f.pushedRef, GoVersion: opts.GoVersion}, nil
	}
	return image.Pushed{Ref: pinnedRepository(opts.Ref) + "@" + opts.Manifest, GoVersion: opts.GoVersion}, nil
}

// The build a release farcast in these tests reports, and the revision its
// carried components were built at.
const (
	testVersion  = "v0.9.0"
	testRevision = "0123456789abcdef0123456789abcdef01234567"
	carriedGo    = "go1.27.4"
)

func releaseBuild() buildinfo.Info {
	return buildinfo.Info{Version: testVersion, Commit: testRevision[:7], Date: "2026-11-13T00:00:00Z", Revision: testRevision}
}

// sha is a digest made of one repeated hex digit.
func sha(hexDigit string) string { return "sha256:" + strings.Repeat(hexDigit, 64) }

// fakeCarried stands in for what a farcast carries (ADR 0023 decision 4): by
// default the four components, whose manifests are sha256:e…, built at
// testRevision against image.BaseImage. none is a source build: it carries
// nothing.
type fakeCarried struct {
	none     bool
	base     string
	revision string
	modified bool
	arts     map[string]components.Artifact
	layerErr error
}

func newFakeCarried() *fakeCarried {
	f := &fakeCarried{base: image.BaseImage, revision: testRevision, arts: map[string]components.Artifact{}}
	for _, c := range components.All() {
		f.arts[c.Name] = components.Artifact{
			Component: c, GoVersion: carriedGo,
			BinarySHA256: strings.Repeat("e", 64), BinarySize: 7,
			Layer: sha("e"), LayerSize: 5, DiffID: sha("e"), Config: sha("e"),
			Manifest: sha(tagDigest),
		}
	}
	return f
}

func (f *fakeCarried) Embedded() bool { return !f.none }
func (f *fakeCarried) Lookup(name string) (components.Artifact, bool) {
	if f.none {
		return components.Artifact{}, false
	}
	a, ok := f.arts[name]
	return a, ok
}
func (f *fakeCarried) Layer(name string) ([]byte, error) {
	if f.none {
		return nil, components.ErrNotEmbedded
	}
	if f.layerErr != nil {
		return nil, f.layerErr
	}
	return []byte("layer " + name), nil
}
func (f *fakeCarried) Base() string {
	if f.none {
		return ""
	}
	return f.base
}
func (f *fakeCarried) Revision() string {
	if f.none {
		return ""
	}
	return f.revision
}
func (f *fakeCarried) Modified() bool { return !f.none && f.modified }

// asRelease makes d a release farcast carrying c (newFakeCarried when nil).
func asRelease(d *fatlineDeployer, c *fakeCarried) {
	if c == nil {
		c = newFakeCarried()
	}
	d.carried = c
	d.build = releaseBuild
	d.now = func() time.Time { return time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC) }
}

// asSourceBuild makes d a farcast built from source: it carries nothing, and
// its version is whatever the test says.
func asSourceBuild(d *fatlineDeployer, version string) {
	d.carried = &fakeCarried{none: true}
	d.build = func() buildinfo.Info { return buildinfo.Info{Version: version, Commit: "none", Date: "unknown"} }
	d.now = func() time.Time { return time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC) }
}

// pinnedRepository is ref with its tag dropped: the repository an operator
// build is pushed to, under a tag of its own digest.
func pinnedRepository(ref string) string {
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		return ref[:i]
	}
	return ref
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
//
// It is a release farcast carrying the fake components; a test of a source
// build says so with asSourceBuild.
func testConnect(p planck.Provider, b imageBuilder) *connectCommand {
	c := newConnectCommand()
	c.openProvider = func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) {
		return p, nil
	}
	c.newBuilder = func(func(string)) imageBuilder { return b }
	c.findSource = func(string) (string, error) {
		return "", errors.New("no farcast checkout at or above the working directory")
	}
	c.findToolchain = fakeToolchain
	asRelease(&c.fatlineDeployer, nil)
	return c
}

// connectedDial answers every dial with a healthy boundary.
func connectedDial(allowlist ...string) func(context.Context, string, tunnel.ClientIdentity) (tunnelConn, error) {
	return func(context.Context, string, tunnel.ClientIdentity) (tunnelConn, error) {
		return &fakeConn{st: fatline.ConnStatus{Connected: true, Allowlist: allowlist}}, nil
	}
}

// instanceImageRef is FatLine's version tag in the fake registry: the
// instance's own registry at the system path, tagged with the test release's
// version.
func instanceImageRef(instance string) string {
	return instanceRepo(instance, "fatline") + ":" + testVersion
}

// instanceRepo is a component's repository in the fake registry.
func instanceRepo(instance, component string) string {
	return "us-central1-docker.pkg.dev/proj-1/farcast-" + instance + "/system/" + component
}

// onlyFatline filters image refs to FatLine's own, so a test about the
// boundary's image is not perturbed by the Shrike sidecar's, which is resolved
// through the same builder and pushed to the same registry.
func onlyFatline(refs []string) []string {
	var out []string
	for _, r := range refs {
		if !strings.Contains(r, "system/shrike") {
			out = append(out, r)
		}
	}
	return out
}

// refsOf pulls the target repositories out of recorded BuildAndPush calls.
func refsOf(opts []image.Options) []string {
	var out []string
	for _, o := range opts {
		out = append(out, o.Repository)
	}
	return out
}

// shrikeRefs is the complement: the sidecar's.
func shrikeRefs(refs []string) []string {
	var out []string
	for _, r := range refs {
		if strings.Contains(r, "system/shrike") {
			out = append(out, r)
		}
	}
	return out
}

func testEnv(dir config.Dir, mode output.Mode) (*Env, *bytes.Buffer) {
	env, out, _ := testEnvBoth(dir, mode)
	return env, out
}

// testEnvBoth is testEnv for a test that also has to read stderr: results go to
// stdout, warnings and progress to stderr, and some behaviour is only visible
// on the second one.
func testEnvBoth(dir config.Dir, mode output.Mode) (*Env, *bytes.Buffer, *bytes.Buffer) {
	var out, errb bytes.Buffer
	env := &Env{
		Out:       &out,
		Err:       &errb,
		In:        strings.NewReader(""), // not a terminal → non-interactive
		Printer:   &output.Printer{Mode: mode, Out: &out, Err: &errb},
		ConfigDir: dir,
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	return env, &out, &errb
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
	recordMigrated(meta)
	if err := dir.SaveInstanceMetadata(name, meta); err != nil {
		t.Fatal(err)
	}
	// The kubeconfig.yaml an install before ADR 0023 M2.7 wrote: nothing
	// writes it since, so it is written here as a file, for migrate's local
	// fact.
	if err := os.WriteFile(filepath.Join(dir.InstancePath(name), "kubeconfig.yaml"), []byte("fake-kubeconfig"), 0o600); err != nil {
		t.Fatal(err)
	}
	// connect opens the provider from the stored credential to reach the
	// instance's registry, so an installed instance has one. Its key is a
	// stand-in no fake reads: a plan refuses a blank one, an install with
	// Application Default Credentials, before it opens the provider (A23-24).
	if err := dir.SaveInstanceCredentials(name, &config.InstanceCredentials{Provider: "gke", ServiceAccountKey: standInKey}); err != nil {
		t.Fatal(err)
	}
	return meta
}

// standInKey is installedInstance's installer key: not blank, and not a key.
const standInKey = `{"type":"service_account","note":"a stand-in; no test parses it"}`

// connectedInstance is an installed instance that has been through a first
// connect: its mTLS material exists and its carrier is bound. That is the state
// a reconnect re-dials — and the precondition redeploy refuses to work without.
func connectedInstance(t *testing.T, dir config.Dir, name string) *config.InstanceMetadata {
	t.Helper()
	meta := installedInstance(t, dir, name)
	mat, err := identity.Mint(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := dir.SaveInstanceMTLS(name, toConfigMTLS(mat)); err != nil {
		t.Fatal(err)
	}
	meta.FatLineDeployed = true
	meta.Carrier = &config.Carrier{Type: "nlb", Endpoint: "192.0.2.10:8443", ServerName: identity.ServerName(name)}
	if err := dir.SaveInstanceMetadata(name, meta); err != nil {
		t.Fatal(err)
	}
	return meta
}

// testNamedImage is an operator-named image: digest-pinned, as every image flag
// must be.
var testNamedImage = "registry.example/fatline@" + sha("c")

func TestConnectBootstrapsAndReports(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	installedInstance(t, dir, name)

	fc := &fakeCluster{ip: "203.0.113.1"}
	fb := &fakeBuilder{}
	var dialed string
	c := testConnect(&fakeProvider{}, fb)
	c.assumeYes = true
	c.fatlineImage = testNamedImage // an explicit override: deployed as given
	c.newCluster = func(clusterRef) (clusterApplier, error) { return fc, nil }
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
	if got := onlyFatline(fb.resolved); len(got) != 0 || len(onlyFatline(refsOf(fb.built))) != 0 {
		t.Fatalf("an explicit --fatline-image must not preflight or build it: resolved=%v built=%v", got, fb.built)
	}
	// The sidecar is a separate image and --fatline-image does not name it, so
	// it is still resolved from the instance registry.
	if len(shrikeRefs(fb.resolved)) == 0 {
		t.Errorf("the Shrike sidecar's image was never resolved: %v", fb.resolved)
	}
	if !bytes.Contains(fc.applied[0], []byte(testNamedImage)) {
		t.Fatalf("deploy did not use the overridden image:\n%s", fc.applied[0])
	}
	meta, _ := dir.LoadInstanceMetadata(name)
	if !meta.FatLineDeployed || meta.Carrier == nil || meta.Carrier.Endpoint != "203.0.113.1:8443" {
		t.Fatalf("carrier not recorded: deployed=%v carrier=%+v", meta.FatLineDeployed, meta.Carrier)
	}
	if meta.Carrier.ServerName != "prod.fatline.farcast" {
		t.Fatalf("carrier server name=%q", meta.Carrier.ServerName)
	}
	if dialed != "https://203.0.113.1:8443" {
		t.Fatalf("dialed=%q, want https://203.0.113.1:8443", dialed)
	}
	if !strings.Contains(out.String(), `connected to "prod"`) {
		t.Fatalf("output missing connected line:\n%s", out.String())
	}
}

func TestConnectCostGateRequiresYes(t *testing.T) {
	dir := config.Dir(t.TempDir())
	installedInstance(t, dir, "prod")

	fc := &fakeCluster{ip: "198.51.100.4"}
	c := testConnect(&fakeProvider{}, &fakeBuilder{}) // assumeYes stays false; env is non-interactive
	c.newCluster = func(clusterRef) (clusterApplier, error) { return fc, nil }
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
	c.newCluster = func(clusterRef) (clusterApplier, error) { return fc, nil }
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
	connectedInstance(t, dir, name)

	fc := &fakeCluster{}
	fp := &fakeProvider{}
	fb := &fakeBuilder{}
	var dialed string
	c := testConnect(fp, fb)
	c.newCluster = func(clusterRef) (clusterApplier, error) { return fc, nil }
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
	if dialed != "https://192.0.2.10:8443" {
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
	meta, _ := dir.LoadInstanceMetadata(name)
	if meta.Registry == nil || meta.Registry.Prefix == "" {
		t.Fatalf("the re-ensured registry was not recorded: %+v", meta.Registry)
	}
}

// connect deploys the monitor with the boundary.
//
// Shrike was written at 2.2 and the two-container Pod was scoped to Planck at
// 4.2, where it did not ship — so for two phases every connected instance
// enforced egress correctly and told nobody when it refused something. This is
// the join, asserted on what actually reaches the cluster.
func TestConnectDeploysShrikeBesideFatLine(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	installedInstance(t, dir, name)
	env, _ := testEnv(dir, output.ModeHuman)

	fc := &fakeCluster{ip: "203.0.113.7"}
	fb := &fakeBuilder{}
	c := testConnect(&fakeProvider{token: planck.RegistryToken{Username: "oauth2accesstoken", Password: "tok"}}, fb)
	c.assumeYes = true
	c.newCluster = func(clusterRef) (clusterApplier, error) { return fc, nil }
	c.dial = connectedDial()

	if err := c.Run(context.Background(), env, []string{name}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if len(fc.applied) != 1 {
		t.Fatalf("applied %d manifests, want 1", len(fc.applied))
	}
	applied := string(fc.applied[0])
	if !strings.Contains(applied, "system/shrike") {
		t.Fatalf("the deployed workload carries no Shrike image:\n%s", applied)
	}
	// Both ends of the wire, in the manifest that actually lands.
	if !strings.Contains(applied, "--shrike-socket=") {
		t.Error("FatLine was not told where the sidecar listens")
	}
	if !strings.Contains(applied, "shrike-wire") {
		t.Error("no shared volume for the sidecar socket")
	}
}

func TestConnectDefaultsImageToTheInstanceRegistry(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	installedInstance(t, dir, name)

	fc := &fakeCluster{ip: "203.0.113.1"}
	fp := &fakeProvider{}
	fb := &fakeBuilder{}
	c := testConnect(fp, fb)
	c.assumeYes = true
	c.newCluster = func(clusterRef) (clusterApplier, error) { return fc, nil }
	c.dial = connectedDial()

	env, out := testEnv(dir, output.ModeHuman)
	if err := c.Run(context.Background(), env, []string{name}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	want := instanceImageRef(name)
	if got := onlyFatline(fb.resolved); len(got) != 1 || got[0] != want {
		t.Fatalf("preflighted %v, want [%s] derived from the instance registry", got, want)
	}
	if len(fb.built) != 0 || len(fb.embedded) != 0 {
		t.Fatal("a tag that already holds the carried image must not be built or pushed")
	}
	if fb.user != "oauth2accesstoken" || fb.pass != "tok" {
		t.Errorf("preflight used %q/%q, want the minted registry token", fb.user, fb.pass)
	}
	// The deploy is pinned by digest, not by the tag that was looked up.
	pinned := pinnedRef(want, tagDigest)
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

	fc := &fakeCluster{ip: "203.0.113.1"}
	fb := &fakeBuilder{resolveErr: image.ErrNotFound}
	var askedFor string
	c := testConnect(&fakeProvider{}, fb)
	c.assumeYes = true
	c.sourceDir = "/checkouts/farcast"
	c.findSource = func(dir string) (string, error) { askedFor = dir; return "/checkouts/farcast", nil }
	c.newCluster = func(clusterRef) (clusterApplier, error) { return fc, nil }
	c.dial = connectedDial()

	env, _ := testEnv(dir, output.ModeHuman)
	if err := c.Run(context.Background(), env, []string{name}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	if askedFor != "/checkouts/farcast" {
		t.Errorf("--source was not passed to the checkout lookup: %q", askedFor)
	}
	// Two images now: the boundary and its co-scheduled monitor.
	if len(fb.built) != 2 {
		t.Fatalf("BuildAndPush called %d times, want fatline + shrike", len(fb.built))
	}
	opts := fb.built[0]
	if opts.SourceDir != "/checkouts/farcast" || opts.Package != "./fatline/cmd/fatline" ||
		opts.Repository != pinnedRepository(instanceImageRef(name)) || opts.BinaryPath != "/fatline" {
		t.Fatalf("build options = %+v", opts)
	}
	if fb.user != "oauth2accesstoken" || fb.pass != "tok" {
		t.Errorf("push used %q/%q, want the minted registry token", fb.user, fb.pass)
	}
	pushed := pinnedRef(opts.Repository, "b")
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

	fc := &fakeCluster{ip: "203.0.113.1"}
	fb := &fakeBuilder{resolveErr: image.ErrNotFound}
	c := testConnect(&fakeProvider{}, fb) // findSource fails by default
	asSourceBuild(&c.fatlineDeployer, "dev")
	c.assumeYes = true
	c.newCluster = func(clusterRef) (clusterApplier, error) { return fc, nil }
	c.dial = func(context.Context, string, tunnel.ClientIdentity) (tunnelConn, error) {
		t.Fatal("must not dial when there is no image to deploy")
		return nil, nil
	}

	env, _ := testEnv(dir, output.ModeHuman)
	err := c.Run(context.Background(), env, []string{name})
	if err == nil {
		t.Fatal("expected an error when the image is missing and there is no checkout")
	}
	// The message has to name what is missing and how to supply it, and that
	// a release farcast would need none of it.
	for _, want := range []string{instanceRepo(name, "fatline"), "checkout", "--source", "a release farcast needs no checkout"} {
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

	fc := &fakeCluster{ip: "203.0.113.1"}
	fb := &fakeBuilder{resolveErr: image.ErrNotFound}
	c := testConnect(&fakeProvider{}, fb) // assumeYes stays false; env is non-interactive
	asSourceBuild(&c.fatlineDeployer, "dev")
	c.findSource = func(string) (string, error) { return "/checkouts/farcast", nil }
	c.newCluster = func(clusterRef) (clusterApplier, error) { return fc, nil }

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
	connectedInstance(t, dir, name)

	fc := &fakeCluster{}
	c := newConnectCommand()
	c.statusOnly = true
	c.newCluster = func(clusterRef) (clusterApplier, error) { return fc, nil }
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

// --status names the node of the FatLine replica that answered, and only that
// one: it prints nothing about placement when FatLine does not report it.
func TestConnectStatusNamesTheRelayingReplicasNode(t *testing.T) {
	for _, node := range []string{"n-7", ""} {
		dir := config.Dir(t.TempDir())
		connectedInstance(t, dir, "prod")
		c := newConnectCommand()
		c.statusOnly = true
		c.newCluster = func(clusterRef) (clusterApplier, error) { return &fakeCluster{}, nil }
		c.dial = func(context.Context, string, tunnel.ClientIdentity) (tunnelConn, error) {
			return &fakeConn{st: fatline.ConnStatus{Connected: true, Node: node}}, nil
		}
		env, out := testEnv(dir, output.ModeHuman)
		if err := c.Run(context.Background(), env, []string{"prod"}); err != nil {
			t.Fatalf("connect --status: %v", err)
		}
		text := out.String()
		if node != "" && !strings.Contains(text, "relayed by:  the FatLine replica on n-7") {
			t.Errorf("the relaying replica's node is missing:\n%s", text)
		}
		if node == "" && strings.Contains(text, "relayed by") {
			t.Errorf("an unknown node printed a relay line:\n%s", text)
		}
	}
}

func TestConnectRegistryFailureDoesNotBreakReconnect(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	connectedInstance(t, dir, name)

	// The stored installer credential predates ADR 0007's role, so the
	// defensive ensure is refused — a working reconnect must survive it.
	fp := &fakeProvider{ensureErr: errors.New("permission denied on artifactregistry.repositories.create")}
	fc := &fakeCluster{}
	c := testConnect(fp, &fakeBuilder{})
	c.newCluster = func(clusterRef) (clusterApplier, error) { return fc, nil }
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
	if !strings.Contains(errb.String(), "Continuing: this connect deploys nothing") {
		t.Errorf("expected the reconnect to say it deploys nothing:\n%s", errb.String())
	}
}

// A first deploy needs the instance's registry for its images, so a registry
// it cannot have stops it before anything is deployed: the ensure an
// interactive or --yes run makes first when no registry is recorded, and the
// ensure after consent, the plan's own (ADR 0023 M2.6, A23-24), which is
// refused with nothing pushed.
func TestConnectRegistryFailureStopsBootstrap(t *testing.T) {
	denied := errors.New("permission denied on artifactregistry.repositories.create")
	for _, tc := range []struct {
		name string
		rig  func(t *testing.T) *deployRig
		want string
	}{
		{"no registry recorded, its ensure refused", func(t *testing.T) *deployRig {
			return newConnectRig(t, recorded(func(m *config.InstanceMetadata) { m.Registry = nil }))
		}, "ensure the image registry"},
		{"the registry read, the ensure after consent refused", func(t *testing.T) *deployRig {
			return newConnectRig(t)
		}, "ensure the image registry for \"prod\": " + denied.Error() + "; nothing was pushed or deployed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.rig(t)
			r.fp.ensureErr = denied
			_, _, err := r.run(t, output.ModeHuman, "--yes")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v, want %q (a first deploy needs the registry)", err, tc.want)
			}
			if len(r.fc.applied) != 0 || len(r.fb.embedded)+len(r.fb.built) != 0 || r.dials != 0 {
				t.Fatalf("applied %d, pushed %d, built %d and dialled %d without an image source", len(r.fc.applied), len(r.fb.embedded), len(r.fb.built), r.dials)
			}
			if r.meta(t).FatLineDeployed {
				t.Fatal("must not mark deployed when the bootstrap failed")
			}
		})
	}
}

// --fatline-image names an image the operator vouches for, so outside --plan
// and --confirm a registry that cannot be read deploys FatLine alone, saying
// so (the break-glass path): with the ensure an interactive or --yes run
// makes first refused, and with the registry recorded and its read refused.
// A plan that read the registry and decided Shrike's image is another thing:
// its ensure after consent failing refuses the command, with nothing pushed
// or deployed, in every mode, and no image the plan listed is dropped
// (A23-5, A23-24).
func TestConnectExplicitImageSurvivesRegistryFailure(t *testing.T) {
	named := "registry.example/fatline@sha256:" + strings.Repeat("c", 64)
	unregistered := recorded(func(m *config.InstanceMetadata) { m.Registry = nil })
	refusingProvider := func(d *fatlineDeployer) {
		d.openProvider = func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) {
			return nil, errors.New("permission denied")
		}
	}
	for _, tc := range []struct {
		name      string
		rig       func(t *testing.T) *deployRig
		configure func(d *fatlineDeployer)
		mode      output.Mode
		in        func(t *testing.T) io.Reader
		flags     []string
	}{
		{"--yes, no registry recorded, its ensure refused", func(t *testing.T) *deployRig {
			return newConnectRig(t, unregistered)
		}, nil, output.ModeHuman, nil, []string{"--yes"}},
		{"--yes, the registry's read refused", func(t *testing.T) *deployRig {
			return newConnectRig(t)
		}, refusingProvider, output.ModeHuman, nil, []string{"--yes"}},
		// A resume asks no cost question, and a named FatLine and a Shrike
		// left out ask no build question: interactive, it asks nothing.
		{"interactive, no registry recorded, its ensure refused", func(t *testing.T) *deployRig {
			return newConnectRig(t, unregistered, resumed)
		}, nil, output.ModeHuman, devNullTerminal, nil},
		{"interactive, the registry's read refused", func(t *testing.T) *deployRig {
			return newConnectRig(t, resumed)
		}, refusingProvider, output.ModeHuman, devNullTerminal, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.rig(t)
			r.fp.ensureErr = errors.New("permission denied")
			r.configure = tc.configure
			r.in = tc.in
			_, errb, err := r.run(t, tc.mode, append([]string{"--fatline-image", named}, tc.flags...)...)
			if err != nil {
				t.Fatalf("an operator-supplied image needs no registry: %v\n%s", err, errb)
			}
			if len(r.fc.applied) != 1 || !bytes.Contains(r.fc.applied[0], []byte(named)) || bytes.Contains(r.fc.applied[0], []byte("system/shrike")) {
				t.Fatalf("deploy did not use the supplied image alone:\n%s", r.fc.applied)
			}
			// This connect deploys FatLine, so it does not claim to deploy nothing
			// (review finding CON2-2), and it says Shrike is left out.
			for _, want := range []string{"Warning: ", "permission denied", "--fatline-image names an image this connect neither looks up nor pushes", "deploying FatLine alone"} {
				if !strings.Contains(errb, want) {
					t.Errorf("stderr does not say %q:\n%s", want, errb)
				}
			}
			if strings.Contains(errb, "deploys nothing") || strings.Contains(errb, "[y/N]") {
				t.Errorf("a connect that deploys FatLine said it deploys nothing, or asked:\n%s", errb)
			}
		})
	}

	// The plan read the registry and decided Shrike's image; the ensure
	// after consent then fails. Refused, in --yes and --confirm alike.
	for _, answer := range []string{"--yes", "--confirm"} {
		t.Run(answer+", the registry read, the ensure after consent refused", func(t *testing.T) {
			r := newConnectRig(t)
			r.fb.resolveFn = notFoundForTags
			flags := []string{"--fatline-image", named}
			if answer == "--confirm" {
				flags = append(flags, "--confirm", r.plan(t, flags...).Digest)
			} else {
				flags = append(flags, answer)
			}
			r.fp.ensureErr = errors.New("permission denied")
			_, errb, err := r.run(t, output.ModeJSON, flags...)
			if err == nil || !strings.HasSuffix(err.Error(), "permission denied; nothing was pushed or deployed") {
				t.Fatalf("a failed ensure after consent = %v; want it refused, nothing pushed or deployed\n%s", err, errb)
			}
			if len(r.fc.applied)+len(r.fb.embedded)+len(r.fb.built)+r.dials != 0 {
				t.Errorf("applied %d, pushed %d, built %d, dialled %d after the ensure failed", len(r.fc.applied), len(r.fb.embedded), len(r.fb.built), r.dials)
			}
			if strings.Contains(errb, "deploying FatLine alone") || r.meta(t).FatLineDeployed {
				t.Errorf("the plan's Shrike was dropped:\n%s", errb)
			}
		})
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

	fc := &fakeCluster{ip: "203.0.113.2"}
	c := testConnect(&fakeProvider{}, &fakeBuilder{})
	c.assumeYes = true
	c.newCluster = func(clusterRef) (clusterApplier, error) { return fc, nil }
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
	if !res.Connected || res.Carrier != "nlb" || res.Endpoint != "203.0.113.2:8443" || res.Identity != "farcast://prod/operator" {
		t.Fatalf("result=%+v", res)
	}
	if res.Registry != "us-central1-docker.pkg.dev/proj-1/farcast-prod" || res.Image != pinnedRef(instanceImageRef(name), tagDigest) {
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
			connectedInstance(t, dir, name)

			fc := &fakeCluster{}
			c := testConnect(&fakeProvider{}, &fakeBuilder{})
			c.newCluster = func(clusterRef) (clusterApplier, error) { return fc, nil }
			c.dial = connectedDial()
			tc.apply(c)

			env, _ := testEnv(dir, output.ModeHuman)
			err := c.Run(context.Background(), env, []string{name})
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
	connectedInstance(t, dir, name)

	c := testConnect(&fakeProvider{}, &fakeBuilder{})
	c.statusOnly = true
	c.fatlineImage = testNamedImage
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
	meta.Carrier = &config.Carrier{Type: "nlb", Endpoint: "192.0.2.10:8443", ServerName: identity.ServerName(name)}
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

// TestImageTagIsAlwaysValid: the default image reference is built from the CLI's
// own version, and a source build's version is a Go pseudo-version — which ends
// in "+dirty" for a tree with uncommitted files. '+' is not legal in an OCI tag,
// so an unsanitised version made the default reference unusable for exactly the
// operators most likely to have one. (Caught by the first live Part B run.)
func TestImageTagIsAlwaysValid(t *testing.T) {
	for _, v := range []string{
		"v0.0.0-20260825182830-5d80f8cc5d00+dirty", // the case that failed live
		"v1.2.3",
		"dev",
		"1.0.0+build.5",
		"-leading-dash",
		".leading-dot",
		"",
		strings.Repeat("x", 200),
	} {
		got := imageTag(v)
		ref, err := oci.ParseReference("example.test/repo/system/fatline:" + got)
		if err != nil {
			t.Errorf("imageTag(%q) = %q, which is not a usable tag: %v", v, got, err)
			continue
		}
		if ref.Tag != got {
			t.Errorf("imageTag(%q) round-tripped to %q", v, ref.Tag)
		}
	}
}

// TestConnectRejectsBothImageFlags mirrors redeploy's guard. Image resolution is
// shared between the two commands and answers --fatline-image before it looks at
// --source, so accepting both would silently honour one — the outcome the guard
// exists to prevent, and the reason it must not live in only one command.
func TestConnectRejectsBothImageFlags(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	installedInstance(t, dir, name)

	fc := &fakeCluster{ip: "203.0.113.1"}
	c := testConnect(&fakeProvider{}, &fakeBuilder{})
	c.newCluster = func(clusterRef) (clusterApplier, error) { return fc, nil }
	c.dial = connectedDial()
	c.assumeYes = true
	c.fatlineImage = "example.test/repo/fatline:2"
	c.sourceDir = t.TempDir()

	env, _ := testEnv(dir, output.ModeHuman)
	if err := c.Run(context.Background(), env, []string{name}); err == nil {
		t.Fatal("accepted --fatline-image together with --source")
	} else if !strings.Contains(err.Error(), "one or the other") {
		t.Errorf("err = %v, want it to name the conflict", err)
	}
	if fc.applied != nil {
		t.Error("applied a workload despite the usage error")
	}
}

// A public L4 load balancer has an IP some time before it forwards. The 5.2
// walk's first connect failed on a healthy instance — both FatLine pods
// Running, endpoints populated — because the dial happened the moment the
// address appeared.
func TestABootstrapWaitsForTheCarrierToStartForwarding(t *testing.T) {
	dir := config.Dir(t.TempDir())
	installedInstance(t, dir, "warm")
	env, _, errb := testEnvBoth(dir, output.ModeHuman)

	c := testConnect(&fakeProvider{}, &fakeBuilder{})
	c.assumeYes = true
	c.fatlineImage = testNamedImage
	c.newCluster = func(clusterRef) (clusterApplier, error) { return &fakeCluster{ip: "203.0.113.9"}, nil }
	c.warmupRetry, c.warmupWindow = time.Millisecond, time.Second

	var attempts int
	c.dial = func(context.Context, string, tunnel.ClientIdentity) (tunnelConn, error) {
		attempts++
		if attempts < 3 {
			return nil, errors.New("dial tcp: operation timed out")
		}
		return &fakeConn{st: fatline.ConnStatus{Connected: true}}, nil
	}
	if err := c.Run(context.Background(), env, []string{"warm"}); err != nil {
		t.Fatalf("a carrier that came up on the third attempt failed the connect: %v", err)
	}
	if attempts < 3 {
		t.Errorf("dialled %d times; the warm-up did not retry", attempts)
	}
	if !strings.Contains(errb.String(), "not forwarding yet") {
		t.Errorf("the wait was silent:\n%s", errb.String())
	}
}

// --status is not a bootstrap: the carrier has been up for a while, so a
// timeout there is real news and two minutes of silence is the wrong answer.
func TestStatusDoesNotWaitOutATimeout(t *testing.T) {
	dir := config.Dir(t.TempDir())
	connectedInstance(t, dir, "cold")
	env, _, _ := testEnvBoth(dir, output.ModeHuman)

	c := testConnect(&fakeProvider{}, &fakeBuilder{})
	c.statusOnly = true
	c.newCluster = func(clusterRef) (clusterApplier, error) { return &fakeCluster{ip: "203.0.113.9"}, nil }
	var attempts int
	c.dial = func(context.Context, string, tunnel.ClientIdentity) (tunnelConn, error) {
		attempts++
		return nil, errors.New("dial tcp: operation timed out")
	}
	if err := c.Run(context.Background(), env, []string{"cold"}); err == nil {
		t.Fatal("a dead carrier reported success")
	}
	if attempts != 1 {
		t.Errorf("--status dialled %d times, want exactly one", attempts)
	}
}

// B-T15. A store minted before ADR 0020 holds an Ed25519 CA. connect refuses
// it before it dials anything or applies anything, and says the way out: there
// is no CA rotation, so release and install a new instance.
func TestConnectRefusesAnEd25519Store(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	connectedInstance(t, dir, name)
	mtls, err := dir.LoadInstanceMTLS(name)
	if err != nil {
		t.Fatal(err)
	}
	mtls.CACertPEM = ed25519CA(t, name)
	if err := dir.SaveInstanceMTLS(name, mtls); err != nil {
		t.Fatal(err)
	}

	for _, statusOnly := range []bool{true, false} {
		dialled := 0
		fc := &fakeCluster{}
		c := testConnect(&fakeProvider{}, &fakeBuilder{})
		c.statusOnly = statusOnly
		c.newCluster = func(clusterRef) (clusterApplier, error) { return fc, nil }
		c.dial = func(context.Context, string, tunnel.ClientIdentity) (tunnelConn, error) {
			dialled++
			return &fakeConn{st: fatline.ConnStatus{Connected: true}}, nil
		}
		env, _ := testEnv(dir, output.ModeHuman)
		err := c.Run(context.Background(), env, []string{name})
		if err == nil || !strings.Contains(err.Error(), "ADR 0020") || !strings.Contains(err.Error(), "'farcast release prod'") ||
			!errors.Is(err, identity.ErrRetiredAlgorithm) {
			t.Errorf("connect (status %v) over an Ed25519 store = %v; want a refusal naming ADR 0020 and 'farcast release'", statusOnly, err)
		}
		if dialled != 0 || len(fc.applied) != 0 {
			t.Errorf("connect (status %v) dialled %d time(s) and applied %d manifest(s) before refusing", statusOnly, dialled, len(fc.applied))
		}
	}
}

// ed25519CA is an instance CA certificate as a store minted before ADR 0020
// holds it: Ed25519, which connect and redeploy refuse.
func ed25519CA(t *testing.T, name string) []byte {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "FarCast Instance CA: " + name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// ADR 0023 M2.6 (review O-2): a first connect decides its identity before
// it takes the registry, as redeploy does and as connect did before M2.6,
// so a trust root it refuses (a CA that is not P-256, or a CA certificate
// it cannot read) refuses it before a record that names no registry is
// given one: no EnsureRegistry, a Google write, and nothing pushed, built,
// applied, minted or dialled. In every mode: --yes, and --plan, which
// would otherwise refuse the record for naming no registry first.
//
// M2.6c (A26-2), mutation A26-2m: so does material missing one of its six
// files, ca.key or server.key here, which deciding finds without opening
// a key; until then it was found only when the identity was loaded, after
// consent and after a --yes run had ensured the registry. Each row opens
// no provider and prints nothing but its error.
func TestConnectRefusesItsTrustRootBeforeTheRegistry(t *testing.T) {
	refusesItsTrustRootBeforeTheRegistry(t, newConnectRig, []trustRootRefusal{
		{"an Ed25519 CA", func(t *testing.T, dir config.Dir, meta *config.InstanceMetadata) {
			withMaterial(t, dir, meta)
			mtls, err := dir.LoadInstanceMTLS(meta.Name)
			if err != nil {
				t.Fatal(err)
			}
			mtls.CACertPEM = ed25519CA(t, meta.Name)
			if err := dir.SaveInstanceMTLS(meta.Name, mtls); err != nil {
				t.Fatal(err)
			}
		}, "ADR 0020"},
		{"a CA certificate it cannot read", func(t *testing.T, dir config.Dir, meta *config.InstanceMetadata) {
			if err := os.MkdirAll(filepath.Join(dir.InstancePath(meta.Name), "fatline", "ca.crt"), 0o700); err != nil {
				t.Fatal(err)
			}
		}, "load identity for"},
		withoutMaterialFile("ca.key"),
		withoutMaterialFile("server.key"),
	})
}

// trustRootRefusal is a trust root a command that deploys FatLine refuses:
// the fixture's edit that makes it, and what the refusal says.
type trustRootRefusal struct {
	trustRoot string
	edit      rigEdit
	want      string
}

// withoutMaterialFile is the instance's mTLS material, minted and then
// missing file, which deciding the identity refuses with the error loading
// it gives (A26-2).
func withoutMaterialFile(file string) trustRootRefusal {
	return trustRootRefusal{"material without " + file, func(t *testing.T, dir config.Dir, meta *config.InstanceMetadata) {
		withMaterial(t, dir, meta)
		if err := os.Remove(filepath.Join(dir.InstancePath(meta.Name), "fatline", file)); err != nil {
			t.Fatal(err)
		}
	}, fmt.Sprintf("load identity for %q: read %s: ", prodName, file)}
}

// refusesItsTrustRootBeforeTheRegistry runs newRig's command over each
// refused trust root, on an instance whose record names no registry, with
// --yes and with --plan: each must refuse, saying what the row wants,
// before the provider is opened or anything is ensured, pushed, built,
// applied or dialled, print nothing but its error, and change no file.
func refusesItsTrustRootBeforeTheRegistry(t *testing.T, newRig func(*testing.T, ...rigEdit) *deployRig, refusals []trustRootRefusal) {
	t.Helper()
	noRegistry := recorded(func(m *config.InstanceMetadata) { m.Registry = nil })
	for _, tc := range refusals {
		for _, flags := range [][]string{{"--yes"}, {"--plan"}} {
			t.Run(fmt.Sprintf("%s/%q", tc.trustRoot, flags), func(t *testing.T) {
				r := newRig(t, noRegistry, tc.edit)
				opened := countProviderOpens(r)
				before := r.files(t)
				stdout, errb, err := r.run(t, output.ModeHuman, flags...)
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("%s %q over %s = %v; want its refusal naming %q\n%s", r.name, flags, tc.trustRoot, err, tc.want, errb)
				}
				if *opened+len(r.fp.ensured)+len(r.fb.embedded)+len(r.fb.built)+len(r.fc.applied)+r.dials != 0 {
					t.Errorf("opened the provider %d times, ensured %d, pushed %d, built %d, applied %d and dialled %d before refusing its trust root",
						*opened, len(r.fp.ensured), len(r.fb.embedded), len(r.fb.built), len(r.fc.applied), r.dials)
				}
				if stdout != "" || errb != "" {
					t.Errorf("printed %q and, on stderr, %q before refusing its trust root", stdout, errb)
				}
				sameFiles(t, "a refused trust root", before, r.files(t))
			})
		}
	}
}

// countProviderOpens counts the opens of r's provider from now on, each
// still answered by r's own opener.
func countProviderOpens(r *deployRig) *int {
	opened := new(int)
	configure := r.configure
	r.configure = func(d *fatlineDeployer) {
		if configure != nil {
			configure(d)
		}
		open := d.openProvider
		d.openProvider = func(meta *config.InstanceMetadata, creds *config.InstanceCredentials) (planck.Provider, error) {
			*opened++
			return open(meta, creds)
		}
	}
	return opened
}

// ADR 0023 M2.6: connect's plan, and the commands that deploy FatLine run
// through --plan and --confirm.

// registeredInstance is installedInstance with its registry recorded, as an
// install's ensure records it: a plan reads it, and never ensures one.
func registeredInstance(t *testing.T, dir config.Dir, name string) *config.InstanceMetadata {
	t.Helper()
	meta := installedInstance(t, dir, name)
	recordRegistry(meta, derivedRegistry(registrySpec(meta)))
	if err := dir.SaveInstanceMetadata(name, meta); err != nil {
		t.Fatal(err)
	}
	return meta
}

// rigEdit changes a rig's fixture before the command runs.
type rigEdit func(t *testing.T, dir config.Dir, meta *config.InstanceMetadata)

// recorded is a rigEdit of the record alone.
func recorded(edit func(*config.InstanceMetadata)) rigEdit {
	return func(_ *testing.T, _ config.Dir, meta *config.InstanceMetadata) { edit(meta) }
}

// resumed is a bootstrap that deployed FatLine and stopped before its
// carrier was recorded: connect resumes it, with no cost question.
var resumed = recorded(func(m *config.InstanceMetadata) { m.FatLineDeployed, m.Carrier = true, nil })

// withMaterial saves the instance's mTLS material, as a first connect does.
func withMaterial(t *testing.T, dir config.Dir, meta *config.InstanceMetadata) {
	t.Helper()
	mat, err := identity.Mint(meta.Name)
	if err != nil {
		t.Fatal(err)
	}
	if err := dir.SaveInstanceMTLS(meta.Name, toConfigMTLS(mat)); err != nil {
		t.Fatal(err)
	}
}

// reconnected is an instance connected before: its material minted, and
// its carrier bound.
func reconnected(t *testing.T, dir config.Dir, meta *config.InstanceMetadata) {
	withMaterial(t, dir, meta)
	meta.FatLineDeployed = true
	meta.Carrier = &config.Carrier{Type: "nlb", Endpoint: "192.0.2.10:8443", ServerName: identity.ServerName(meta.Name)}
}

// devNullTerminal is stdin as /dev/null, a character device, which
// isTerminal takes for a terminal: an interactive run whose every question
// reads a closed input.
func devNullTerminal(t *testing.T) io.Reader {
	t.Helper()
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// deployRig is a command that deploys FatLine (connect or redeploy) against
// a fixture of its own, every seam that would leave this machine a fake,
// for the tests that drive it through --plan and --confirm: each run is a
// fresh command, its flags parsed as the router parses them.
type deployRig struct {
	name string
	dir  config.Dir
	args []string
	fp   *fakeProvider
	fb   *fakeBuilder
	fc   *fakeCluster
	// writers counts the writer's opens, and dials the carrier's.
	writers, dials int
	// cmd is a fresh command wired to the fakes above.
	cmd func() Command
	// configure, when set, changes the command's deployer after its flags
	// are parsed; in, when set, is its stdin (no terminal otherwise);
	// onWriter, when set, runs as the writer opens: under --confirm, right
	// after the comparison.
	configure func(d *fatlineDeployer)
	in        func(t *testing.T) io.Reader
	onWriter  func()
}

// deployRigs are the commands that deploy FatLine, each against an instance
// it deploys to, changed by edits, for the tests that hold them all to one
// rule (ADR 0023 M2.6b): connect, on a first deploy, and redeploy.
func deployRigs() []struct {
	name string
	rig  func(t *testing.T, edits ...rigEdit) *deployRig
} {
	return []struct {
		name string
		rig  func(t *testing.T, edits ...rigEdit) *deployRig
	}{
		{"connect", newConnectRig},
		{"redeploy", newRedeployRig},
	}
}

// newRedeployRig is redeploy against "prod", installed with its registry
// recorded, connected (its material minted, its carrier bound) and changed
// by edits, as a release farcast carrying the fake components.
func newRedeployRig(t *testing.T, edits ...rigEdit) *deployRig {
	t.Helper()
	dir := config.Dir(t.TempDir())
	meta := registeredInstance(t, dir, prodName)
	reconnected(t, dir, meta)
	for _, edit := range edits {
		edit(t, dir, meta)
	}
	if err := dir.SaveInstanceMetadata(prodName, meta); err != nil {
		t.Fatal(err)
	}
	r := &deployRig{name: "redeploy", dir: dir, args: []string{prodName}, fp: &fakeProvider{}, fb: &fakeBuilder{}, fc: &fakeCluster{}}
	r.cmd = func() Command {
		c := testRedeploy(r.fp, r.fb)
		c.newCluster = func(clusterRef) (clusterApplier, error) {
			r.writers++
			if r.onWriter != nil {
				r.onWriter()
			}
			return r.fc, nil
		}
		return c
	}
	return r
}

// newConnectRig is connect against "prod", installed with its registry
// recorded and changed by edits, as a release farcast carrying the fake
// components.
func newConnectRig(t *testing.T, edits ...rigEdit) *deployRig {
	t.Helper()
	return newConnectRigIn(t, config.Dir(t.TempDir()), edits...)
}

// newConnectRigIn is newConnectRig in a config directory the test chose.
func newConnectRigIn(t *testing.T, dir config.Dir, edits ...rigEdit) *deployRig {
	t.Helper()
	meta := registeredInstance(t, dir, prodName)
	for _, edit := range edits {
		edit(t, dir, meta)
	}
	if err := dir.SaveInstanceMetadata(prodName, meta); err != nil {
		t.Fatal(err)
	}
	r := &deployRig{name: "connect", dir: dir, args: []string{prodName}, fp: &fakeProvider{}, fb: &fakeBuilder{}, fc: &fakeCluster{ip: "203.0.113.1"}}
	r.cmd = func() Command {
		c := testConnect(r.fp, r.fb)
		c.newCluster = func(clusterRef) (clusterApplier, error) {
			r.writers++
			if r.onWriter != nil {
				r.onWriter()
			}
			return r.fc, nil
		}
		c.dial = func(context.Context, string, tunnel.ClientIdentity) (tunnelConn, error) {
			r.dials++
			return &fakeConn{st: fatline.ConnStatus{Connected: true}}, nil
		}
		return c
	}
	return r
}

// deployerOf is the deployer a command that deploys FatLine embeds.
func deployerOf(t *testing.T, cmd Command) *fatlineDeployer {
	t.Helper()
	switch c := cmd.(type) {
	case *connectCommand:
		return &c.fatlineDeployer
	case *redeployCommand:
		return &c.fatlineDeployer
	}
	t.Fatalf("%T deploys no FatLine", cmd)
	return nil
}

// run runs the rig's command once with flags, in mode, and returns what it
// printed.
func (r *deployRig) run(t *testing.T, mode output.Mode, flags ...string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := withFlags(t, r.cmd(), flags...)
	if r.configure != nil {
		r.configure(deployerOf(t, cmd))
	}
	env, out, errb := testEnvBoth(r.dir, mode)
	if r.in != nil {
		env.In = r.in(t)
	}
	err = cmd.Run(t.Context(), env, r.args)
	return out.String(), errb.String(), err
}

// plan is the rig's --plan with flags, in JSON, which must succeed and say
// nothing on stderr.
func (r *deployRig) plan(t *testing.T, flags ...string) plan.Document {
	t.Helper()
	out, errb, err := r.run(t, output.ModeJSON, append(slices.Clone(flags), "--plan")...)
	if err != nil {
		t.Fatalf("%s --plan: %v\nstderr: %s", r.name, err, errb)
	}
	if errb != "" {
		t.Errorf("%s --plan wrote on stderr: %q", r.name, errb)
	}
	return printedDocument(t, []byte(out))
}

// meta is the instance's record as the rig's fixture holds it now.
func (r *deployRig) meta(t *testing.T) *config.InstanceMetadata {
	t.Helper()
	meta, err := r.dir.LoadInstanceMetadata(prodName)
	if err != nil {
		t.Fatal(err)
	}
	return meta
}

// files is every file of the rig's fixture.
func (r *deployRig) files(t *testing.T) map[string]string {
	t.Helper()
	return treeFiles(t, string(r.dir))
}

// tagOrDigest answers a lookup as fakeBuilder does by default: a digest is
// itself, and a tag holds the image the fake release carries.
func tagOrDigest(ref string) (string, error) {
	if strings.Contains(ref, "@sha256:") {
		return ref, nil
	}
	return pinnedRef(ref, tagDigest), nil
}

// ADR 0023 M2.6 (A23-35), mutation 75a: a plan that said mint never mints
// over material that appeared after it was made. The material appears while
// the plan is recomputed (as the last image is looked up), after the
// identity was decided: --confirm compares equal, then refuses at the
// identity's realize step, plan_changed; a --yes run refuses there too, as
// internal. Nothing is written: the material is the one that appeared,
// untouched, and nothing is ensured, pushed, applied or recorded.
func TestConfirmRefusesACAMintedAfterThePlan(t *testing.T) {
	for _, answer := range []string{"--confirm", "--yes"} {
		t.Run(answer, func(t *testing.T) {
			r := newConnectRig(t)
			var appeared []byte
			armed := false
			r.fb.resolveFn = func(ref string) (string, error) {
				if armed && appeared == nil && strings.Contains(ref, "system/shrike") {
					mat, err := identity.Mint(prodName)
					if err != nil {
						t.Fatal(err)
					}
					if err := r.dir.SaveInstanceMTLS(prodName, toConfigMTLS(mat)); err != nil {
						t.Fatal(err)
					}
					appeared = mat.CACertPEM
				}
				return tagOrDigest(ref)
			}
			flags := []string{answer}
			if answer == "--confirm" {
				doc := r.plan(t)
				if b := decodedBound(t, doc); !slices.ContainsFunc(b.Facts, func(f plan.Fact) bool {
					m, ok := f.(plan.MintFact)
					return ok && m.What == plan.MintInstanceCA
				}) {
					t.Fatalf("the plan mints no CA: %s", doc.Bound)
				}
				flags = append(flags, doc.Digest)
			}
			armed = true
			_, errb, err := r.run(t, output.ModeJSON, flags...)

			want, kind := fmt.Sprintf(msgMaterialAppeared, prodName), kindInternal
			if answer == "--confirm" {
				want, kind = want+"; "+msgPlanAgain, kindPlanChanged
			}
			if err == nil || err.Error() != want || kindOf(classified(err)) != kind || exitCodeOf(err) != 1 {
				t.Fatalf("%s = %v (kind %s); want %q, %s\n%s", answer, err, kindOf(classified(err)), want, kind, errb)
			}
			if appeared == nil {
				t.Fatal("the material never appeared, so this test proved nothing")
			}
			got, err := r.dir.LoadInstanceCACert(prodName)
			if err != nil || !bytes.Equal(got, appeared) {
				t.Errorf("the CA that appeared was minted over (%v)", err)
			}
			if len(r.fp.ensured)+len(r.fb.embedded)+len(r.fb.built)+len(r.fc.applied)+r.dials != 0 {
				t.Errorf("ensured %d, pushed %d, built %d, applied %d, dialled %d after refusing",
					len(r.fp.ensured), len(r.fb.embedded), len(r.fb.built), len(r.fc.applied), r.dials)
			}
			if r.meta(t).FatLineDeployed {
				t.Error("a refused connect recorded FatLine as deployed")
			}
		})
	}
}

// ADR 0023 M2.6 (A23-35), mutation 91f: a reconnect's plan is the registry
// ensure alone. Under --confirm, an ensure that fails still prints its
// warning and the connection status, and then fails the command, exit 1,
// saying so; an interactive or --yes reconnect warns and succeeds. No
// reconnect opens a writer. M2.6c (A26-1) adds the ensure an instance
// installed with Application Default Credentials refuses, before the
// provider opens: credential_missing, exit 1, the status printed.
func TestReconnectConfirmFailsWhenItsEnsureFails(t *testing.T) {
	denied := errors.New("permission denied on artifactregistry.repositories.create")
	for _, answer := range []string{"--confirm", "--yes", ""} {
		t.Run("answer "+answer, func(t *testing.T) {
			r := newConnectRig(t, reconnected)
			var flags []string
			switch answer {
			case "--confirm":
				doc := r.plan(t)
				b := decodedBound(t, doc)
				want := []plan.Fact{
					plan.CloudFact{Type: plan.TypeCloud, Service: plan.CloudArtifactRegistry, Action: plan.CloudCreateRepository, Target: repoPrefix(prodName)},
					plan.CloudFact{Type: plan.TypeCloud, Service: plan.CloudArtifactRegistry, Action: plan.CloudSetPullGrant, Target: repoPrefix(prodName)},
				}
				if !reflect.DeepEqual(b.Facts, want) {
					t.Fatalf("a reconnect's plan binds %#v; want the registry ensure alone", b.Facts)
				}
				flags = []string{"--confirm", doc.Digest}
			case "--yes":
				flags = []string{"--yes"}
			}
			r.fp.ensureErr = denied
			stdout, errb, err := r.run(t, output.ModeJSON, flags...)
			if !strings.Contains(errb, "Warning: ensure the image registry for \"prod\": "+denied.Error()) ||
				!strings.Contains(errb, "Continuing: this connect deploys nothing") {
				t.Errorf("the reconnect did not warn:\n%s", errb)
			}
			if r.dials != 1 || !strings.Contains(stdout, `"connected":true`) {
				t.Errorf("dialled %d times and printed %q; want the status read and printed", r.dials, stdout)
			}
			if r.writers != 0 {
				t.Errorf("a reconnect opened the writer %d times", r.writers)
			}
			if answer != "--confirm" {
				if err != nil {
					t.Errorf("a reconnect %q failed for its ensure: %v", answer, err)
				}
				return
			}
			want := "the registry ensure this plan bound did not succeed: ensure the image registry for \"prod\": " + denied.Error() +
				"; the connection status above was read, and nothing else was written"
			if err == nil || err.Error() != want || exitCodeOf(err) != 1 {
				t.Errorf("--confirm = %v (exit %d); want exit 1, %q", err, exitCodeOf(err), want)
			}
		})
	}

	// M2.6c (A26-1): an instance installed with Application Default
	// Credentials. Its reconnect's plan reads no key, so it is made; under
	// --confirm the ensure refuses the blank key before the provider opens,
	// the warning and the status print, and the command fails, exit 1, with
	// the refusal's kind, credential_missing.
	t.Run("ADC/--confirm", func(t *testing.T) {
		r := newConnectRig(t, reconnected, installedWithADC)
		opened := countProviderOpens(r)
		reads := observeConfigReads(t)
		doc := r.plan(t)
		credentials := filepath.Join(r.dir.InstancePath(prodName), "credentials.yaml")
		if slices.Contains(reads(), credentials) {
			t.Errorf("a reconnect's plan read the installer's key: %v", reads())
		}
		stdout, errb, err := r.run(t, output.ModeJSON, "--confirm", doc.Digest)
		_, adc := loadInstallerKey(r.dir, prodName)
		want := fmt.Errorf(msgReconnectEnsureFailed, adc).Error()
		if err == nil || err.Error() != want || exitCodeOf(err) != 1 ||
			!errors.Is(err, errCredentialMissing) || kindOf(classified(err)) != kindCredentialMissing {
			t.Errorf("--confirm on an ADC instance = %v (exit %d, kind %s); want exit 1, credential_missing, %q",
				err, exitCodeOf(err), kindOf(classified(err)), want)
		}
		if !strings.Contains(errb, "Warning: "+adc.Error()+"\n") || !strings.Contains(errb, "Continuing: this connect deploys nothing") {
			t.Errorf("the reconnect did not warn with the installer key's refusal:\n%s", errb)
		}
		if r.dials != 1 || !strings.Contains(stdout, `"connected":true`) {
			t.Errorf("dialled %d times and printed %q; want the status read and printed", r.dials, stdout)
		}
		if *opened != 0 || len(r.fp.ensured) != 0 || r.writers != 0 {
			t.Errorf("opened the provider %d times, ensured %d times and opened the writer %d times", *opened, len(r.fp.ensured), r.writers)
		}
	})
}

// installedWithADC is an instance installed with Application Default
// Credentials: its credentials.yaml holds no service-account key.
func installedWithADC(t *testing.T, dir config.Dir, meta *config.InstanceMetadata) {
	t.Helper()
	if err := dir.SaveInstanceCredentials(meta.Name, &config.InstanceCredentials{Provider: "gke"}); err != nil {
		t.Fatal(err)
	}
}

// ADR 0023 M2.6c (A26-1), mutation A26-1m: a reconnect never ensures the
// registry as this machine's Application Default Credentials. On an
// instance installed without a key, an interactive, --yes or unanswered
// reconnect warns with the installer key's refusal, says it goes on, prints
// the status and succeeds, and the provider is never opened; with a key the
// ensure runs once, as it always has. (Under --confirm the same refusal
// fails the command: TestReconnectConfirmFailsWhenItsEnsureFails.)
func TestReconnectNeverEnsuresAsADC(t *testing.T) {
	for _, tc := range []struct {
		name  string
		adc   bool
		flags []string
		mode  output.Mode
		in    func(t *testing.T) io.Reader
		// status is what the printed status holds.
		status string
	}{
		{"ADC/interactive", true, nil, output.ModeHuman, devNullTerminal, `connected to "prod"`},
		{"ADC/--yes", true, []string{"--yes"}, output.ModeJSON, nil, `"connected":true`},
		{"ADC/no answer", true, nil, output.ModeJSON, nil, `"connected":true`},
		{"a stand-in key/interactive", false, nil, output.ModeHuman, devNullTerminal, `connected to "prod"`},
		{"a stand-in key/--yes", false, []string{"--yes"}, output.ModeJSON, nil, `"connected":true`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			edits := []rigEdit{reconnected}
			if tc.adc {
				edits = append(edits, installedWithADC)
			}
			r := newConnectRig(t, edits...)
			r.in = tc.in
			opened := countProviderOpens(r)
			stdout, errb, err := r.run(t, tc.mode, tc.flags...)
			if err != nil {
				t.Fatalf("a reconnect %q failed: %v\n%s", tc.flags, err, errb)
			}
			if r.dials != 1 || !strings.Contains(stdout, tc.status) {
				t.Errorf("dialled %d times and printed %q; want the status read and printed", r.dials, stdout)
			}
			if r.writers != 0 {
				t.Errorf("a reconnect opened the writer %d times", r.writers)
			}
			if !tc.adc {
				if *opened != 1 || len(r.fp.ensured) != 1 || strings.Contains(errb, "Warning:") {
					t.Errorf("with a key: opened the provider %d times and ensured %d times, and said %q; want one ensure, no warning", *opened, len(r.fp.ensured), errb)
				}
				return
			}
			_, adc := loadInstallerKey(r.dir, prodName)
			if !errors.Is(adc, errCredentialMissing) {
				t.Fatalf("the fixture's key is not refused as ADC: %v", adc)
			}
			if !strings.Contains(errb, "Warning: "+adc.Error()+"\n") || !strings.Contains(errb, "Continuing: this connect deploys nothing") {
				t.Errorf("the reconnect did not warn with the installer key's refusal:\n%s", errb)
			}
			if *opened != 0 || len(r.fp.ensured) != 0 {
				t.Errorf("an ADC reconnect opened the provider %d times and ensured the registry %d times", *opened, len(r.fp.ensured))
			}
		})
	}
}

// repoPrefix is an instance's registry as registeredInstance records it.
func repoPrefix(instance string) string {
	return "us-central1-docker.pkg.dev/proj-1/farcast-" + instance
}

// ADR 0023 M2.6 (A23-8): --status dials and reports, and writes nothing, so
// it has no plan. Beside --plan or --confirm it is a usage error, exit 2,
// raised before the record or anything else is read, and nothing is dialled.
func TestConnectStatusHasNoPlan(t *testing.T) {
	for _, answer := range [][]string{{"--plan"}, {"--confirm", sampleDigest}, {"--confirm=" + sampleDigest}} {
		t.Run(answer[0], func(t *testing.T) {
			r := newConnectRig(t, reconnected)
			before := r.files(t)
			reads := observeConfigReads(t)
			stdout, _, err := r.run(t, output.ModeJSON, append([]string{"--status"}, answer...)...)
			var ue *usageError
			if !errors.As(err, &ue) || err.Error() != msgStatusHasNoPlan || exitCodeOf(err) != 2 {
				t.Errorf("--status %q = %v; want the usage error %q", answer, err, msgStatusHasNoPlan)
			}
			if got := reads(); len(got) != 0 || stdout != "" || r.dials != 0 {
				t.Errorf("--status %q read %q, printed %q and dialled %d times before refusing", answer, got, stdout, r.dials)
			}
			sameFiles(t, "--status with a plan", before, r.files(t))
		})
	}
	// Through the router, too.
	r := newConnectRig(t, reconnected)
	if _, stderr, code := runLine([]string{"farcast", "--config", string(r.dir), "connect", prodName, "--plan", "--status"}); code != 2 ||
		!strings.Contains(stderr, msgStatusHasNoPlan) {
		t.Errorf("farcast connect --plan --status: exit %d, %q", code, stderr)
	}
}

// connectRefusalsNameThePlan is TestNonInteractiveRefusalsNameThePlan's rows
// for connect: its cost question and its build question, met with no
// terminal and no --yes, refuse, exit 2, ending with the route that needs
// neither. The build question is shared with every deployer command, each
// of which since ADR 0023 M2.6c has a plan; a deployer that registers no
// consent flags names none (consentFlags.suffix).
func connectRefusalsNameThePlan(t *testing.T) {
	t.Run("the cost", func(t *testing.T) {
		r := newConnectRig(t)
		_, _, err := r.run(t, output.ModeHuman)
		cost := connectCost(r.meta(t))
		want := fmt.Sprintf(msgConnectCostYes, amount(cost.Standing[0].MonthCents), amount(cost.Standing[1].MonthCents))
		if err == nil || err.Error() != want || exitCodeOf(err) != 2 || !strings.HasSuffix(want, consentSuffix) {
			t.Errorf("connect with no terminal = %v (exit %d); want %q", err, exitCodeOf(err), want)
		}
	})
	t.Run("a source build", func(t *testing.T) {
		r := newConnectRig(t, resumed)
		r.configure = func(d *fatlineDeployer) { d.findSource = func(dir string) (string, error) { return dir, nil } }
		_, _, err := r.run(t, output.ModeHuman, "--source", "/work/farcast")
		want := fmt.Sprintf(msgBuildYes, "fatline", "/work/farcast", repoOf("fatline")) + consentSuffix
		if err == nil || err.Error() != want || exitCodeOf(err) != 2 {
			t.Errorf("a source build with no terminal = %v (exit %d); want %q", err, exitCodeOf(err), want)
		}
	})
	// A deployer whose command registered no consent flags has no plan, so
	// its build question's refusal names none (consentFlags.suffix). Since
	// ADR 0023 M2.6c every command that holds a deployer registers them.
	t.Run("the build question of a command with no plan", func(t *testing.T) {
		var d fatlineDeployer
		d.component = components.Datasphered
		d.ensureDefaults()
		env, _ := testEnv(config.Dir(t.TempDir()), output.ModeHuman)
		dec := imageDecision{component: components.Datasphered, action: plan.ImageBuildSource, repo: repoOf("datasphered"), source: imageSource{dir: "/work/farcast"}}
		_, err := d.confirmBuild(env, dec)
		if want := fmt.Sprintf(msgBuildYes, "datasphered", "/work/farcast", repoOf("datasphered")); err == nil || err.Error() != want {
			t.Errorf("an unregistered deployer's build question with no terminal = %v; want %q, which names no plan", err, want)
		}
	})
}

// ADR 0023 M2.6 (§9.2, A23-34; review M-M26B-MUT-01 and -02): --confirm of
// a plan that builds from source builds both images from the checkout it
// bound and asks nothing: no build question, with a terminal or without
// one, and no refusal asking for --yes. Its plan is the consent to each
// build.
func TestConfirmBuildsTheSourceItsPlanBound(t *testing.T) {
	const source = "/work/farcast"
	for _, dr := range deployRigs() {
		for _, stdin := range []string{"no terminal", "a terminal"} {
			t.Run(dr.name+"/"+stdin, func(t *testing.T) {
				r := dr.rig(t)
				r.configure = func(d *fatlineDeployer) { d.findSource = func(dir string) (string, error) { return dir, nil } }
				doc := r.plan(t, "--source", source)
				if stdin == "a terminal" {
					r.in = devNullTerminal
				}
				_, errb, err := r.run(t, output.ModeHuman, "--source", source, "--confirm", doc.Digest)
				if err != nil {
					t.Fatalf("%s --confirm of a source-build plan: %v\n%s", dr.name, err, errb)
				}
				if len(r.fb.built) != 2 || strings.Contains(errb, "Build and push it now?") || strings.Contains(errb, "pass --yes to build it") {
					t.Errorf("%s --confirm built %d images, want 2, asking nothing; stderr:\n%s", dr.name, len(r.fb.built), errb)
				}
				for _, b := range r.fb.built {
					if b.SourceDir != source {
						t.Errorf("built from %q, want the checkout the plan bound, %q", b.SourceDir, source)
					}
				}
			})
		}
	}
}

// ADR 0023 M2.6 (A23-24, A23-51 item 1; review M-M26B-MUT-03): a first
// connect whose registry is recorded asks its cost question before it
// ensures the registry, a Google write. Unanswered, with no terminal or a
// closed one, it is refused with nothing ensured, pushed, built or applied.
func TestConnectAsksBeforeItEnsures(t *testing.T) {
	for _, stdin := range []string{"no terminal", "a terminal"} {
		t.Run(stdin, func(t *testing.T) {
			r := newConnectRig(t)
			if stdin == "a terminal" {
				r.in = devNullTerminal
			}
			_, errb, err := r.run(t, output.ModeHuman)
			if err == nil {
				t.Fatalf("connect with its cost unanswered went on\n%s", errb)
			}
			if len(r.fp.ensured)+len(r.fb.embedded)+len(r.fb.built)+len(r.fc.applied) != 0 {
				t.Errorf("before the cost was answered: ensured %d, pushed %d, built %d, applied %d",
					len(r.fp.ensured), len(r.fb.embedded), len(r.fb.built), len(r.fc.applied))
			}
		})
	}
}

// ADR 0023 M2.6 (A23-13, A23-30): a source build's plan binds the checkout's
// directory and the Go that builds from it, never what the checkout holds,
// and says so once per checkout. Each image's target, and its push, is the
// build placeholder. Another Go found when --confirm runs changes the plan,
// which is refused before anything is built.
func TestConnectSourcePlanBindsTheDirectoryAndItsGo(t *testing.T) {
	const source = "/work/farcast"
	r := newConnectRig(t)
	checkout := func(d *fatlineDeployer) { d.findSource = func(dir string) (string, error) { return dir, nil } }
	r.configure = checkout
	doc := r.plan(t, "--source", source)
	b := decodedBound(t, doc)
	var pushes []string
	images := map[string]plan.ImageFact{}
	for _, f := range b.Facts {
		switch f := f.(type) {
		case plan.ImageFact:
			images[f.Component] = f
		case plan.CloudFact:
			if f.Action == plan.CloudPushImage {
				pushes = append(pushes, f.Target)
			}
		}
	}
	var targets []string
	for _, c := range []string{"fatline", "shrike"} {
		img := images[c]
		want := plan.ImageSource{Dir: source, GoPath: "/usr/local/go/bin/go", GoVersion: "go1.27.5"}
		if img.Action != plan.ImageBuildSource || img.Source == nil || *img.Source != want || img.Target != buildPlaceholder(repoOf(c), c) {
			t.Errorf("%s's image fact is %+v (source %+v); want a source build of %s with its Go, at the build placeholder", c, img, img.Source, source)
		}
		targets = append(targets, img.Target)
	}
	if !slices.Equal(pushes, targets) {
		t.Errorf("the plan pushes %q; want the builds' placeholders %q", pushes, targets)
	}
	if got, want := noticesOf(b), []string{fmt.Sprintf(msgSourceBuildNotice, source)}; !slices.Equal(got, want) {
		t.Errorf("the plan's notices are %q; want %q", got, want)
	}

	r.configure = func(d *fatlineDeployer) {
		checkout(d)
		d.findToolchain = func(context.Context, []string, string) (image.Toolchain, error) {
			return image.Toolchain{Go: "/opt/go/bin/go", Version: "go1.27.6"}, nil
		}
	}
	_, _, err := r.run(t, output.ModeJSON, "--source", source, "--confirm", doc.Digest)
	if kindOf(classified(err)) != kindPlanChanged {
		t.Errorf("--confirm with another Go = %v; want plan_changed", err)
	}
	if len(r.fb.built)+len(r.fc.applied)+r.writers != 0 {
		t.Errorf("built %d, applied %d and opened the writer %d times for a changed plan", len(r.fb.built), len(r.fc.applied), r.writers)
	}
}

// ADR 0023 M2.6 (A23-35), M2.7 (A30-30): connect --confirm opens its
// writer, and reads once as it, before it mints the instance's identity. A
// first deploy, planned, then confirmed with the writer's token refused from
// the confirm on, is refused credential_refused with no CA on this machine.
// (TestCommandsThatApplyRefuseAMachineThatCannotApply pinned this order
// until applyReady went at M2.7; the writer's preflight is the check that
// remains.)
func TestConnectConfirmMintsNoIdentityBeforeItsWriterReads(t *testing.T) {
	p := applyingPlans(t)[0]
	if p.String() != "connect/first deploy" {
		t.Fatalf("applyingPlans' first plan is %s, not connect/first deploy", p)
	}
	var refuseWriter atomic.Bool
	mints := kubetest.WithTokenAnswer(func(email string) (int, []byte, bool) {
		if email != "writer@kubetest.invalid" || !refuseWriter.Load() {
			return 0, nil, false
		}
		return http.StatusBadRequest, []byte(`{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`), true
	})
	c := confirmApplying(t, p, func(_ *kubetest.Server, dir config.Dir, _ plan.Bound) {
		if _, err := dir.LoadInstanceCACert(writeName); err == nil {
			t.Fatal("the fixture already holds the instance's CA: its first deploy mints none")
		}
		refuseWriter.Store(true)
	}, mints)
	if kind := kindOf(classified(c.err)); kind != kindCredentialRefused {
		t.Fatalf("connect --confirm with its writer's token refused = %v; kind %q, want %q", c.err, kind, kindCredentialRefused)
	}
	if _, err := c.dir.LoadInstanceCACert(writeName); err == nil {
		t.Errorf("connect --confirm minted the instance's CA before its writer read the cluster, which refused it")
	}
}
