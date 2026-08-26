package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/image"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/planck"
)

// testRedeploy wires every cloud-touching seam to a fake, so no redeploy test
// can open a cloud provider, reach a registry, or build an image by accident —
// the same containment testConnect gives the command it shares that machinery
// with.
func testRedeploy(p planck.Provider, b imageBuilder) *redeployCommand {
	c := newRedeployCommand()
	c.openProvider = func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) {
		return p, nil
	}
	c.newBuilder = func(func(string)) imageBuilder { return b }
	c.findSource = func(string) (string, error) {
		return "", errors.New("no farcast checkout at or above the working directory")
	}
	return c
}

// recordRunningImage puts a digest into local state as the one the cluster was
// last told to run, so a redeploy has a "previous" to report against.
func recordRunningImage(t *testing.T, dir config.Dir, name, ref string) {
	t.Helper()
	meta, err := dir.LoadInstanceMetadata(name)
	if err != nil {
		t.Fatal(err)
	}
	recordDeployedImage(meta, ref)
	if err := dir.SaveInstanceMetadata(name, meta); err != nil {
		t.Fatal(err)
	}
}

// TestRedeployRefusesAnInstanceThatWasNeverConnected: redeploy replaces a
// workload, it does not create one. An instance with no carrier and no trust
// root needs connect's bootstrap — including the cost gate that guards it — so
// the refusal has to name that command rather than quietly doing its job.
func TestRedeployRefusesAnInstanceThatWasNeverConnected(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	installedInstance(t, dir, name)

	fc := &fakeCluster{}
	c := testRedeploy(&fakeProvider{}, &fakeBuilder{})
	c.assumeYes = true
	c.newCluster = func(string) clusterApplier { return fc }

	env, _ := testEnv(dir, output.ModeHuman)
	err := c.Run(context.Background(), env, []string{name})
	if err == nil {
		t.Fatal("redeployed an instance that was never connected")
	}
	if !strings.Contains(err.Error(), "farcast connect prod") {
		t.Errorf("err = %v, want it to direct the operator to connect", err)
	}
	if len(fc.applied) != 0 {
		t.Fatal("nothing may be applied to an instance with no deployment")
	}
	if exists, _ := dir.InstanceMTLSExists(name); exists {
		t.Error("redeploy minted an identity; only connect may create a trust root")
	}
}

// TestRedeployRefusesADeletingInstance mirrors connect: an instance on its way
// out is not a thing to push new code into.
func TestRedeployRefusesADeletingInstance(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	meta := connectedInstance(t, dir, name)
	meta.Status = config.InstanceDeleting
	if err := dir.SaveInstanceMetadata(name, meta); err != nil {
		t.Fatal(err)
	}

	fc := &fakeCluster{}
	c := testRedeploy(&fakeProvider{}, &fakeBuilder{})
	c.assumeYes = true
	c.newCluster = func(string) clusterApplier { return fc }

	env, _ := testEnv(dir, output.ModeHuman)
	err := c.Run(context.Background(), env, []string{name})
	if err == nil || !strings.Contains(err.Error(), "being released") {
		t.Fatalf("err = %v, want the being-released refusal", err)
	}
	if len(fc.applied) != 0 {
		t.Fatal("must not apply to an instance being released")
	}
}

// TestRedeployDeploysAnExplicitImageAsGiven: an operator-named reference is what
// the cluster is told to run, with no preflight and no registry lookup — the
// same contract connect gives --fatline-image.
func TestRedeployDeploysAnExplicitImageAsGiven(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	connectedInstance(t, dir, name)

	const explicit = "registry.example/fatline@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	fc := &fakeCluster{}
	fb := &fakeBuilder{}
	c := testRedeploy(&fakeProvider{}, fb)
	c.assumeYes = true
	c.fatlineImage = explicit
	c.newCluster = func(string) clusterApplier { return fc }

	env, _ := testEnv(dir, output.ModeHuman)
	if err := c.Run(context.Background(), env, []string{name}); err != nil {
		t.Fatalf("redeploy: %v", err)
	}
	if len(fc.applied) != 1 || !bytes.Contains(fc.applied[0], []byte(explicit)) {
		t.Fatalf("the supplied image was not deployed:\n%s", fc.applied)
	}
	if len(fb.resolved) != 0 || len(fb.built) != 0 {
		t.Fatalf("an explicit --fatline-image must not preflight or build: resolved=%v built=%v", fb.resolved, fb.built)
	}
	meta, _ := dir.LoadInstanceMetadata(name)
	if deployedImage(meta) != explicit {
		t.Fatalf("recorded image = %q, want the deployed reference", deployedImage(meta))
	}
}

// TestRedeployDeploysThePreflightedDigest: the default reference is the
// instance's own registry, deployed pinned by digest, and the carrier is left
// exactly as it was — no external IP is waited for, so no load balancer is
// re-provisioned and nothing new becomes billable.
func TestRedeployDeploysThePreflightedDigest(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	connectedInstance(t, dir, name)
	const previous = "us-central1-docker.pkg.dev/proj-1/farcast-prod/system/fatline@sha256:" +
		"0000000000000000000000000000000000000000000000000000000000000000"
	recordRunningImage(t, dir, name, previous)

	fc := &fakeCluster{}
	fp := &fakeProvider{}
	fb := &fakeBuilder{}
	c := testRedeploy(fp, fb)
	c.assumeYes = true
	c.newCluster = func(string) clusterApplier { return fc }

	env, out := testEnv(dir, output.ModeHuman)
	if err := c.Run(context.Background(), env, []string{name}); err != nil {
		t.Fatalf("redeploy: %v", err)
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
	if len(fp.ensured) != 1 {
		t.Fatalf("EnsureRegistry called %d times, want 1 (idempotent ensure)", len(fp.ensured))
	}
	pinned := pinnedRef(want, "a")
	if len(fc.applied) != 1 || !bytes.Contains(fc.applied[0], []byte(pinned)) {
		t.Fatalf("deploy did not carry the digest-pinned image %s:\n%s", pinned, fc.applied)
	}
	if fc.rollouts != 1 {
		t.Errorf("RolloutStatus called %d times, want 1", fc.rollouts)
	}
	if fc.ipCalls != 0 {
		t.Error("redeploy waited for an external IP; the carrier is connect's and must not be re-provisioned")
	}

	meta, _ := dir.LoadInstanceMetadata(name)
	if deployedImage(meta) != pinned {
		t.Fatalf("recorded image = %q, want the newly deployed digest", deployedImage(meta))
	}
	if meta.Carrier == nil || meta.Carrier.Endpoint != "9.9.9.9:8443" {
		t.Fatalf("the carrier was disturbed: %+v", meta.Carrier)
	}
	for _, want := range []string{"redeployed FatLine to \"prod\"", previous, pinned, "(unchanged)"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output does not report %q:\n%s", want, out.String())
		}
	}
}

// TestRedeployBuildsTheImageWhenTheRegistryHasNone: the redeploy path is the
// build path too, so a fix that only exists in the local checkout can be rolled
// out without a separate push step.
func TestRedeployBuildsTheImageWhenTheRegistryHasNone(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	connectedInstance(t, dir, name)

	fc := &fakeCluster{}
	fb := &fakeBuilder{resolveErr: image.ErrNotFound}
	var askedFor string
	c := testRedeploy(&fakeProvider{}, fb)
	c.assumeYes = true
	c.sourceDir = "/checkouts/farcast"
	c.findSource = func(dir string) (string, error) { askedFor = dir; return "/checkouts/farcast", nil }
	c.newCluster = func(string) clusterApplier { return fc }

	env, _ := testEnv(dir, output.ModeHuman)
	if err := c.Run(context.Background(), env, []string{name}); err != nil {
		t.Fatalf("redeploy: %v", err)
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
	pushed := pinnedRef(opts.Ref, "b")
	if len(fc.applied) != 1 || !bytes.Contains(fc.applied[0], []byte(pushed)) {
		t.Fatalf("deploy did not carry the pushed digest %s:\n%s", pushed, fc.applied)
	}
	meta, _ := dir.LoadInstanceMetadata(name)
	if deployedImage(meta) != pushed {
		t.Fatalf("pushed digest not recorded: %q", deployedImage(meta))
	}
}

// TestRedeployReappliesAnUnchangedImage is the case the command exists for: the
// live Phase 2 Part B failure was a workload-*template* defect (an mTLS Secret
// the container could not read) with the image byte-identical. A redeploy that
// no-opped on a matching digest would be useless for exactly that, so the apply
// must still happen — and the report must say plainly that the image did not
// change.
func TestRedeployReappliesAnUnchangedImage(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	connectedInstance(t, dir, name)
	pinned := pinnedRef(instanceImageRef(name), "a") // what the fake builder resolves to
	recordRunningImage(t, dir, name, pinned)

	fc := &fakeCluster{}
	c := testRedeploy(&fakeProvider{}, &fakeBuilder{})
	c.assumeYes = true
	c.newCluster = func(string) clusterApplier { return fc }

	env, out := testEnv(dir, output.ModeHuman)
	if err := c.Run(context.Background(), env, []string{name}); err != nil {
		t.Fatalf("redeploy: %v", err)
	}
	if len(fc.applied) != 1 || !bytes.Contains(fc.applied[0], []byte(pinned)) {
		t.Fatalf("an unchanged digest must still be re-rendered and re-applied; applies=%d", len(fc.applied))
	}
	if fc.rollouts != 1 {
		t.Errorf("RolloutStatus called %d times, want 1 — the re-applied workload must be waited for", fc.rollouts)
	}
	if !strings.Contains(out.String(), "unchanged; the workload template was re-applied") {
		t.Errorf("output does not say the image was unchanged:\n%s", out.String())
	}
	meta, _ := dir.LoadInstanceMetadata(name)
	if deployedImage(meta) != pinned {
		t.Fatalf("recorded image = %q, want it to stay the deployed digest", deployedImage(meta))
	}
}

// TestRedeployNonInteractiveRequiresYes: the consent gate is not about cost, but
// it is still consent — an unattended session that never asked for the change
// must not get it, and the refusal has to name what it would have changed.
func TestRedeployNonInteractiveRequiresYes(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	connectedInstance(t, dir, name)
	const previous = "us-central1-docker.pkg.dev/proj-1/farcast-prod/system/fatline@sha256:" +
		"0000000000000000000000000000000000000000000000000000000000000000"
	recordRunningImage(t, dir, name, previous)

	fc := &fakeCluster{}
	c := testRedeploy(&fakeProvider{}, &fakeBuilder{}) // assumeYes stays false; env is non-interactive
	c.newCluster = func(string) clusterApplier { return fc }

	env, _ := testEnv(dir, output.ModeHuman)
	err := c.Run(context.Background(), env, []string{name})
	var ue *usageError
	if !errors.As(err, &ue) {
		t.Fatalf("err=%v, want a usageError (change not confirmed, non-interactive)", err)
	}
	if !strings.Contains(err.Error(), previous) || !strings.Contains(err.Error(), "--yes") {
		t.Errorf("usage error %q must name the change and how to allow it", err)
	}
	if len(fc.applied) != 0 {
		t.Fatal("must not apply without confirmation")
	}
	meta, _ := dir.LoadInstanceMetadata(name)
	if deployedImage(meta) != previous {
		t.Fatalf("recorded image = %q, want it untouched by a refused redeploy", deployedImage(meta))
	}
}

// TestRedeployJSONOutput: automation gets exactly one JSON value on stdout and
// is never prompted.
func TestRedeployJSONOutput(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	connectedInstance(t, dir, name)
	const previous = "us-central1-docker.pkg.dev/proj-1/farcast-prod/system/fatline@sha256:" +
		"0000000000000000000000000000000000000000000000000000000000000000"
	recordRunningImage(t, dir, name, previous)

	fc := &fakeCluster{}
	c := testRedeploy(&fakeProvider{}, &fakeBuilder{})
	c.assumeYes = true
	c.newCluster = func(string) clusterApplier { return fc }

	env, out := testEnv(dir, output.ModeJSON)
	if err := c.Run(context.Background(), env, []string{name}); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
	var res struct {
		Name          string `json:"name"`
		Carrier       string `json:"carrier"`
		Endpoint      string `json:"endpoint"`
		Registry      string `json:"registry"`
		PreviousImage string `json:"previous_image"`
		Image         string `json:"image"`
		ImageChanged  bool   `json:"image_changed"`
		Status        string `json:"status"`
	}
	if err := dec.Decode(&res); err != nil {
		t.Fatalf("decode JSON result: %v\n%s", err, out.String())
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		t.Fatalf("expected exactly one JSON value on stdout, got more: %s", out.String())
	}
	if res.Name != name || res.Carrier != "nlb" || res.Endpoint != "9.9.9.9:8443" || res.Status != "redeployed" {
		t.Fatalf("result=%+v", res)
	}
	if res.Registry != "us-central1-docker.pkg.dev/proj-1/farcast-prod" ||
		res.PreviousImage != previous || res.Image != pinnedRef(instanceImageRef(name), "a") || !res.ImageChanged {
		t.Fatalf("images not reported: %+v", res)
	}
	if errb := env.Err.(*bytes.Buffer).String(); strings.Contains(errb, "[y/N]") {
		t.Errorf("JSON mode prompted:\n%s", errb)
	}
}

// TestRedeployNeverMintsIdentity guards approved decision 4: FatLine already
// trusts a CA, so a redeploy that minted a replacement would hand the operator a
// certificate the running instance can only reject — and overwrite the record of
// what it actually trusts. Minting stays connect's.
func TestRedeployNeverMintsIdentity(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	meta := installedInstance(t, dir, name)
	meta.FatLineDeployed = true
	meta.Carrier = &config.Carrier{Type: "nlb", Endpoint: "9.9.9.9:8443", ServerName: "prod.fatline.farcast"}
	if err := dir.SaveInstanceMetadata(name, meta); err != nil {
		t.Fatal(err)
	} // note: no mTLS material saved

	fc := &fakeCluster{}
	c := testRedeploy(&fakeProvider{}, &fakeBuilder{})
	c.assumeYes = true
	c.newCluster = func(string) clusterApplier { return fc }

	env, _ := testEnv(dir, output.ModeHuman)
	err := c.Run(context.Background(), env, []string{name})
	if err == nil {
		t.Fatal("redeploy minted a fresh CA for an instance already running FatLine")
	}
	if !strings.Contains(err.Error(), "cannot be recovered") {
		t.Errorf("err = %v, want it to explain the trust root is unrecoverable", err)
	}
	if exists, _ := dir.InstanceMTLSExists(name); exists {
		t.Error("a replacement CA was written for a deployed instance")
	}
	if len(fc.applied) != 0 {
		t.Fatal("must not apply without the instance's mTLS material")
	}
}

// TestRedeploySourceForcesARebuild is the whole point of the command's most
// important path. The image tag is derived from the *CLI's* version, which does
// not move when FatLine's own code changes — so a preflight against a connected
// instance always hits the image that is already there. If --source did not
// force a rebuild, an operator patching a FatLine security bug would redeploy
// their own stale image and be told it succeeded.
func TestRedeploySourceForcesARebuild(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	connectedInstance(t, dir, name)

	fc := &fakeCluster{}
	fb := &fakeBuilder{} // Resolve would succeed — the stale image is present
	c := testRedeploy(&fakeProvider{}, fb)
	c.newCluster = func(string) clusterApplier { return fc }
	c.sourceDir = t.TempDir()
	c.findSource = func(d string) (string, error) { return d, nil }
	c.assumeYes = true

	env, _ := testEnv(dir, output.ModeHuman)
	if err := c.Run(context.Background(), env, []string{name}); err != nil {
		t.Fatalf("redeploy --source: %v", err)
	}
	if len(fb.built) != 1 {
		t.Fatalf("--source did not rebuild: BuildAndPush calls = %d, resolves = %v", len(fb.built), fb.resolved)
	}
	if len(fb.resolved) != 0 {
		t.Errorf("preflighted anyway (%v); a forced rebuild has nothing to look up", fb.resolved)
	}
	if fc.applied == nil {
		t.Error("rebuilt but never applied the workload")
	}
}

// TestRedeployRejectsBothImageFlags: "deploy exactly this" and "build from here"
// are opposed intents, so accepting both would mean silently honouring one.
func TestRedeployRejectsBothImageFlags(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	connectedInstance(t, dir, name)

	fc := &fakeCluster{}
	c := testRedeploy(&fakeProvider{}, &fakeBuilder{})
	c.newCluster = func(string) clusterApplier { return fc }
	c.fatlineImage = "example.test/repo/fatline:2"
	c.sourceDir = t.TempDir()
	c.assumeYes = true

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

// TestRedeployKeepsTheRecordWhenTheRolloutFails: on one replica with the default
// strategy a failed rollout leaves the previous image serving, so local state
// must keep naming it — recording the new digest would name an image that never
// served a byte.
func TestRedeployKeepsTheRecordWhenTheRolloutFails(t *testing.T) {
	dir := config.Dir(t.TempDir())
	const name = "prod"
	meta := connectedInstance(t, dir, name)
	before := deployedImage(meta)

	fc := &fakeCluster{rolloutErr: errors.New("timed out waiting for the rollout")}
	c := testRedeploy(&fakeProvider{}, &fakeBuilder{})
	c.newCluster = func(string) clusterApplier { return fc }
	c.fatlineImage = "example.test/repo/fatline@sha256:" + strings.Repeat("b", 64)
	c.assumeYes = true

	env, _ := testEnv(dir, output.ModeHuman)
	if err := c.Run(context.Background(), env, []string{name}); err == nil {
		t.Fatal("a failed rollout reported success")
	}
	after, err := dir.LoadInstanceMetadata(name)
	if err != nil {
		t.Fatal(err)
	}
	if got := deployedImage(after); got != before {
		t.Errorf("recorded %q after a failed rollout; the previous image %q is what is still serving", got, before)
	}
}
