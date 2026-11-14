package cli

import (
	"context"
	"errors"
	"flag"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/planck"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
)

// testKernelDeploy wires every cloud-touching seam to a fake, so no test here
// can open a provider, reach a registry or build an image by accident.
func testKernelDeploy(fc *fakeCluster, b imageBuilder) *kernelDeployCommand {
	c := &kernelDeployCommand{}
	c.deployer.assumeYes = true
	c.deployer.openProvider = func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) {
		return &fakeProvider{}, nil
	}
	c.deployer.newBuilder = func(func(string)) imageBuilder { return b }
	c.deployer.newCluster = func(string) clusterApplier { return fc }
	c.deployer.findSource = func(string) (string, error) { return "/checkouts/farcast", nil }
	asRelease(&c.deployer, nil)
	// deploy refuses to meter a namespace that does not exist, so the ones
	// these tests meter have to be in the cluster. A test that wants the
	// refusal sets this itself.
	if fc.namespaces == nil {
		fc.namespaces = []string{"farcast-system", "farcast-apps"}
	}
	return c
}

// A namespace that does not exist is caught before anything is built.
//
// deploy renders a RoleBinding into every metered namespace, and the API
// server rejects one for a namespace that is not there. It used to reject it
// at the apply — after the kernel's image had been compiled and pushed into
// the instance's registry — so on the Phase 4.4 walk a mistyped namespace cost
// a build and a registry write before anything said so.
func TestKernelDeployRefusesAMissingNamespaceBeforeBuilding(t *testing.T) {
	dir := config.Dir(t.TempDir())
	connectedInstance(t, dir, "p44")
	env, _ := testEnv(dir, output.ModeHuman)

	fc := &fakeCluster{namespaces: []string{tcdeploy.DefaultNamespace}}
	b := &fakeBuilder{}
	c := testKernelDeploy(fc, b)
	c.namespaces = tcdeploy.DefaultNamespace + ",not-there,also-missing"

	err := c.Run(context.Background(), env, []string{"p44"})
	if err == nil {
		t.Fatal("deploy accepted a namespace the instance does not have")
	}
	// Both, not just the first: an operator who mistyped twice should not have
	// to run again to learn about the second one.
	for _, want := range []string{"not-there", "also-missing"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q:\n%v", want, err)
		}
	}
	if len(b.built) != 0 {
		t.Errorf("a refused deploy built and pushed an image anyway: %v", b.built)
	}
	if len(fc.applied) != 0 {
		t.Errorf("a refused deploy applied %d manifests", len(fc.applied))
	}
	meta, lerr := dir.LoadInstanceMetadata("p44")
	if lerr != nil {
		t.Fatal(lerr)
	}
	if meta.Kernel != nil {
		t.Error("a refused deploy recorded a kernel")
	}
}

// But an already-metered namespace that has since been deleted is dropped, not
// refused. Refusing would mean an operator who removed an application
// namespace without 'kernel meter --remove' could never deploy the kernel
// again — a worse failure than the one being fixed.
func TestKernelDeployDropsAMeteredNamespaceThatIsGone(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteredInstance(t, dir, "p44", tcdeploy.DefaultNamespace, "deleted-app")
	env, _, errOut := testEnvBoth(dir, output.ModeHuman)

	// The application namespace is gone from the cluster; the record still has it.
	fc := &fakeCluster{namespaces: []string{tcdeploy.DefaultNamespace}}
	c := testKernelDeploy(fc, &fakeBuilder{})
	c.namespaces = tcdeploy.DefaultNamespace

	if err := c.Run(context.Background(), env, []string{"p44"}); err != nil {
		t.Fatalf("a deleted namespace blocked the redeploy: %v", err)
	}
	meta, lerr := dir.LoadInstanceMetadata("p44")
	if lerr != nil {
		t.Fatal(lerr)
	}
	for _, n := range meta.Kernel.Namespaces {
		if n == "deleted-app" {
			t.Error("kept metering a namespace that no longer exists")
		}
	}
	// And it did not shrink the list silently.
	if !strings.Contains(errOut.String(), "deleted-app") {
		t.Errorf("dropping a metered namespace was not reported:\n%s", errOut.String())
	}
}

func TestKernelDeployAppliesTheWorkloadAndRecordsIt(t *testing.T) {
	dir := config.Dir(t.TempDir())
	connectedInstance(t, dir, "p41")
	env, _ := testEnv(dir, output.ModeHuman)
	fc := &fakeCluster{}
	c := testKernelDeploy(fc, &fakeBuilder{})

	if err := c.Run(context.Background(), env, []string{"p41"}); err != nil {
		t.Fatal(err)
	}
	if len(fc.applied) != 1 {
		t.Fatalf("applied %d manifests, want 1", len(fc.applied))
	}
	manifest := string(fc.applied[0])
	for _, want := range []string{"kind: ClusterRole", "kind: RoleBinding", "kind: Deployment", "--cost-limit=50"} {
		if !strings.Contains(manifest, want) {
			t.Errorf("applied manifest is missing %q", want)
		}
	}

	// Recorded BEFORE the apply, like every other billable thing this CLI
	// creates: a workload the local state does not know about is one nobody
	// will think to tear down.
	meta, err := dir.LoadInstanceMetadata("p41")
	if err != nil {
		t.Fatal(err)
	}
	if meta.Kernel == nil || !meta.Kernel.Deployed {
		t.Fatal("the kernel was applied but not recorded")
	}
	if meta.Kernel.Limit != 50 || meta.Kernel.Period != "monthly" {
		t.Errorf("recorded limit = %v %v, want 50 monthly", meta.Kernel.Limit, meta.Kernel.Period)
	}
	if !strings.Contains(meta.Kernel.Image, "@sha256:") {
		t.Errorf("recorded image %q is not digest-pinned", meta.Kernel.Image)
	}
	if len(meta.Kernel.Namespaces) != 1 || meta.Kernel.Namespaces[0] != tcdeploy.DefaultNamespace {
		t.Errorf("recorded namespaces = %v, want the default", meta.Kernel.Namespaces)
	}
}

// The limit the cluster enforces comes from the instance's recorded limit, so
// a kernel can never be deployed enforcing a number the operator never chose.
func TestKernelDeployCarriesTheInstancesOwnLimit(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meta := connectedInstance(t, dir, "p41")
	meta.CostLimit = config.CostLimit{Amount: 250, Currency: "EUR", Period: "monthly"}
	if err := dir.SaveInstanceMetadata("p41", meta); err != nil {
		t.Fatal(err)
	}
	env, _ := testEnv(dir, output.ModeHuman)
	fc := &fakeCluster{}
	if err := testKernelDeploy(fc, &fakeBuilder{}).Run(context.Background(), env, []string{"p41"}); err != nil {
		t.Fatal(err)
	}
	manifest := string(fc.applied[0])
	for _, want := range []string{"--cost-limit=250", "--cost-currency=EUR", "--cost-period=monthly"} {
		if !strings.Contains(manifest, want) {
			t.Errorf("manifest missing %q", want)
		}
	}
}

// A kernel deployed against an instance with no limit would meter it and never
// act — the one configuration that looks like cost control and is not.
func TestKernelDeployRefusesAnInstanceWithNoLimit(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meta := connectedInstance(t, dir, "p41")
	meta.CostLimit = config.CostLimit{}
	if err := dir.SaveInstanceMetadata("p41", meta); err != nil {
		t.Fatal(err)
	}
	env, _ := testEnv(dir, output.ModeHuman)
	fc := &fakeCluster{}
	err := testKernelDeploy(fc, &fakeBuilder{}).Run(context.Background(), env, []string{"p41"})
	if err == nil || !strings.Contains(err.Error(), "never act") {
		t.Fatalf("err = %v, want a refusal naming what a missing limit means", err)
	}
	if len(fc.applied) != 0 {
		t.Error("a refused deploy touched the cluster")
	}
}

func TestKernelDeployRefusesAnUnconnectedInstance(t *testing.T) {
	dir := config.Dir(t.TempDir())
	installedInstance(t, dir, "p41") // never connected
	env, _ := testEnv(dir, output.ModeHuman)
	fc := &fakeCluster{}
	err := testKernelDeploy(fc, &fakeBuilder{}).Run(context.Background(), env, []string{"p41"})
	if err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("err = %v, want a refusal to meter an instance with nothing running", err)
	}
	if len(fc.applied) != 0 {
		t.Error("a refused deploy touched the cluster")
	}
}

// The floor warning is the point of this command's gate: a limit below the
// floor is a configuration mistake, and deploying the enforcer is the last
// cheap moment to notice.
func TestKernelDeployGateNamesTheFloorNonInteractively(t *testing.T) {
	dir := config.Dir(t.TempDir())
	connectedInstance(t, dir, "p41") // USD 50: clears the metered ~$40, not the modelled ~$77
	env, _ := testEnv(dir, output.ModeHuman)

	c := testKernelDeploy(&fakeCluster{}, &fakeBuilder{})
	c.deployer.assumeYes = false
	meta, err := dir.LoadInstanceMetadata("p41")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := c.confirmCost(env, meta, []string{tcdeploy.DefaultNamespace})
	if ok {
		t.Fatal("expected a refusal without --yes")
	}
	if err == nil || !strings.Contains(err.Error(), "floor") {
		t.Fatalf("err = %v, want the refusal to name the floor", err)
	}
	warned := env.Err.(interface{ String() string }).String()
	if !strings.Contains(warned, "below what") || !strings.Contains(warned, "cannot observe") {
		t.Errorf("the gate did not explain the floor:\n%s", warned)
	}
}

// An instance whose limit clears the floor gets the ordinary cost gate, not
// the floor warning — crying wolf on every deploy is how a real warning gets
// clicked through.
func TestKernelDeployGateIsQuietWhenTheLimitClearsTheFloor(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meta := connectedInstance(t, dir, "p41")
	meta.CostLimit = config.CostLimit{Amount: 500, Currency: "USD", Period: "monthly"}
	if err := dir.SaveInstanceMetadata("p41", meta); err != nil {
		t.Fatal(err)
	}
	env, _ := testEnv(dir, output.ModeHuman)

	c := testKernelDeploy(&fakeCluster{}, &fakeBuilder{})
	c.deployer.assumeYes = false
	ok, err := c.confirmCost(env, meta, []string{tcdeploy.DefaultNamespace})
	if ok {
		t.Fatal("expected a refusal without --yes")
	}
	if err == nil || strings.Contains(err.Error(), "floor") {
		t.Fatalf("err = %v, want the ordinary standing-cost gate", err)
	}
	if strings.Contains(env.Err.(interface{ String() string }).String(), "below what") {
		t.Error("warned about a floor the limit clears")
	}
}

func TestKernelDeployMetersTheNamespacesItWasGiven(t *testing.T) {
	dir := config.Dir(t.TempDir())
	connectedInstance(t, dir, "p41")
	env, _ := testEnv(dir, output.ModeHuman)
	fc := &fakeCluster{}
	c := testKernelDeploy(fc, &fakeBuilder{})
	c.namespaces = "farcast-system, farcast-apps ,"

	if err := c.Run(context.Background(), env, []string{"p41"}); err != nil {
		t.Fatal(err)
	}
	manifest := string(fc.applied[0])
	if !strings.Contains(manifest, "--namespaces=farcast-system,farcast-apps") {
		t.Error("the metered namespaces did not reach the container")
	}
	// The grants must match the argument, or the kernel asks for namespaces it
	// cannot read and reports a permissions error as a cost.
	for _, ns := range []string{"namespace: farcast-system", "namespace: farcast-apps"} {
		if !strings.Contains(manifest, ns) {
			t.Errorf("no RoleBinding for %q", ns)
		}
	}
}

// farcast-system is metered whatever the flag says: every fetch and build Job
// runs there, and a kernel told to meter only applications left them
// uncounted.
func TestParseNamespacesAlwaysMetersFarCastsOwn(t *testing.T) {
	cases := map[string][]string{
		"":                               {tcdeploy.DefaultNamespace},
		"   ":                            {tcdeploy.DefaultNamespace},
		",,":                             {tcdeploy.DefaultNamespace},
		"a,b":                            {tcdeploy.DefaultNamespace, "a", "b"},
		" a , b ,":                       {tcdeploy.DefaultNamespace, "a", "b"},
		tcdeploy.DefaultNamespace:        {tcdeploy.DefaultNamespace},
		"a," + tcdeploy.DefaultNamespace: {tcdeploy.DefaultNamespace, "a"},
	}
	for in, want := range cases {
		got := parseNamespaces(in)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("parseNamespaces(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestKernelDeployTakesExactlyOneInstance(t *testing.T) {
	dir := config.Dir(t.TempDir())
	env, _ := testEnv(dir, output.ModeHuman)
	for _, args := range [][]string{{}, {"a", "b"}} {
		if err := testKernelDeploy(&fakeCluster{}, &fakeBuilder{}).Run(context.Background(), env, args); err == nil {
			t.Errorf("args %v: expected a usage error", args)
		}
	}
}

// The case that separates the two floors, and the reason floorFull exists.
//
// A connected instance with no keyholder yet costs about $62/month. A limit of
// $65 clears that — and is still below the ~$73 the same instance will cost
// once storage is deployed, which is two commands away. Checking against what
// happens to be running would pass a limit the operator is guaranteed to
// breach, and the warning would arrive after the money was committed.
func TestTheGateChecksTheProvisionedFloorNotTodaysWorkloads(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meta := connectedInstance(t, dir, "p41") // connected, no keyholder, no kernel
	between := (floorNow(meta).Total + floorFull(meta).Total) / 2
	if !(floorNow(meta).Total < between && between < floorFull(meta).Total) {
		t.Fatalf("test setup: %.2f is not between floorNow %.2f and floorFull %.2f",
			between, floorNow(meta).Total, floorFull(meta).Total)
	}
	meta.CostLimit = config.CostLimit{Amount: between, Currency: "USD", Period: "monthly"}
	if err := dir.SaveInstanceMetadata("p41", meta); err != nil {
		t.Fatal(err)
	}

	env, _ := testEnv(dir, output.ModeHuman)
	c := testKernelDeploy(&fakeCluster{}, &fakeBuilder{})
	c.deployer.assumeYes = false
	ok, err := c.confirmCost(env, meta, []string{tcdeploy.DefaultNamespace})
	if ok {
		t.Fatal("expected a refusal without --yes")
	}
	if err == nil || !strings.Contains(err.Error(), "floor") {
		t.Fatalf("err = %v; a limit below the PROVISIONED floor must be flagged even though "+
			"it clears what is running today", err)
	}
}

// deployKernelWith runs 'kernel deploy' with these flags, parsed the way the
// command line parses them, and returns the manifest it applied.
func deployKernelWith(t *testing.T, dir config.Dir, name string, flags ...string) (string, error) {
	t.Helper()
	fc := &fakeCluster{}
	c := testKernelDeploy(fc, &fakeBuilder{})
	fs := flag.NewFlagSet("deploy", flag.ContinueOnError)
	c.SetFlags(fs)
	c.deployer.assumeYes = true
	if err := fs.Parse(flags); err != nil {
		t.Fatalf("parse %v: %v", flags, err)
	}
	env, _ := testEnv(dir, output.ModeHuman)
	err := c.Run(context.Background(), env, []string{name})
	var applied string
	for _, m := range fc.applied {
		applied += string(m)
	}
	return applied, err
}

// The 5.2 walk's hand-patched cooldown, and the defect behind it: every
// 'kernel deploy' silently switched adapting off, because nothing recorded
// that it had been on.
func TestKernelDeployRecordsAndCarriesItsFlagsForward(t *testing.T) {
	dir := config.Dir(t.TempDir())
	connectedInstance(t, dir, "p50")

	applied, err := deployKernelWith(t, dir, "p50", "--adapt", "--adapt-cooldown=2m", "--interval=10s")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"- --adapt\n", "--adapt-cooldown=2m0s", "--interval=10s"} {
		if !strings.Contains(applied, want) {
			t.Errorf("the manifest lacks %q", want)
		}
	}
	meta, err := dir.LoadInstanceMetadata("p50")
	if err != nil {
		t.Fatal(err)
	}
	if k := meta.Kernel; !k.Adapt || k.AdaptCooldown != 2*time.Minute || k.Interval != 10*time.Second {
		t.Fatalf("recorded %+v", k)
	}

	// A redeploy that names nothing keeps all three.
	applied, err = deployKernelWith(t, dir, "p50")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"- --adapt\n", "--adapt-cooldown=2m0s", "--interval=10s"} {
		if !strings.Contains(applied, want) {
			t.Errorf("a redeploy dropped %q", want)
		}
	}

	// --adapt=false turns it off, and =0 restores a default.
	applied, err = deployKernelWith(t, dir, "p50", "--adapt=false", "--interval=0")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(applied, "--adapt") || strings.Contains(applied, "--interval") {
		t.Errorf("--adapt=false --interval=0 still rendered adapt or an interval")
	}
	if meta, _ = dir.LoadInstanceMetadata("p50"); meta.Kernel.Adapt || meta.Kernel.Interval != 0 || meta.Kernel.AdaptCooldown != 2*time.Minute {
		t.Errorf("recorded %+v; want adapting off, the default interval, and the cooldown kept", meta.Kernel)
	}
}

// A value outside the kernel's bounds is refused before anything is built or
// applied.
func TestKernelDeployRefusesAnIntervalOutsideTheBoundsBeforeBuilding(t *testing.T) {
	dir := config.Dir(t.TempDir())
	connectedInstance(t, dir, "p51")
	fc := &fakeCluster{}
	fb := &fakeBuilder{}
	c := testKernelDeploy(fc, fb)
	fs := flag.NewFlagSet("deploy", flag.ContinueOnError)
	c.SetFlags(fs)
	if err := fs.Parse([]string{"--interval=1s"}); err != nil {
		t.Fatal(err)
	}
	c.deployer.assumeYes = true
	env, _ := testEnv(dir, output.ModeHuman)
	if err := c.Run(context.Background(), env, []string{"p51"}); err == nil || !strings.Contains(err.Error(), "--interval") {
		t.Fatalf("--interval=1s = %v; want it refused naming the flag", err)
	}
	if len(fc.applied) != 0 || len(fb.built) != 0 {
		t.Errorf("a refused deploy built %d image(s) and applied %d manifest(s)", len(fb.built), len(fc.applied))
	}
}

// 'kernel confirm' writes the whole set it holds, so a redeploy that dropped
// the recorded confirmations would have the next one erase every figure
// before it — in the cluster too.
func TestKernelDeployKeepsTheRecordedConfirmations(t *testing.T) {
	dir := config.Dir(t.TempDir())
	connectedInstance(t, dir, "p52")
	if _, err := deployKernelWith(t, dir, "p52"); err != nil {
		t.Fatal(err)
	}
	if _, err := dir.UpdateInstanceMetadata("p52", func(m *config.InstanceMetadata) error {
		m.Kernel.Confirmations = []config.KernelConfirmation{{}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := deployKernelWith(t, dir, "p52"); err != nil {
		t.Fatal(err)
	}
	meta, err := dir.LoadInstanceMetadata("p52")
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.Kernel.Confirmations) != 1 {
		t.Errorf("a redeploy left %d confirmations; want the 1 recorded", len(meta.Kernel.Confirmations))
	}
}

// A kernel deploy whose apply failed leaves its record — so it can be torn
// down — and must not open the gate run and build check.
func TestAFailedKernelApplyKeepsRunAndBuildRefused(t *testing.T) {
	dir := config.Dir(t.TempDir())
	connectedInstance(t, dir, "p53")
	fc := &fakeCluster{applyErr: errors.New("the API server said no")}
	c := testKernelDeploy(fc, &fakeBuilder{})
	env, _ := testEnv(dir, output.ModeHuman)
	if err := c.Run(context.Background(), env, []string{"p53"}); err == nil {
		t.Fatal("a failed apply reported success")
	}
	meta, err := dir.LoadInstanceMetadata("p53")
	if err != nil {
		t.Fatal(err)
	}
	if meta.Kernel == nil || !meta.Kernel.Deployed {
		t.Fatal("guard: the failed deploy left no record to tear down")
	}
	if err := requireKernel("p53", meta, "this"); err == nil {
		t.Error("the gate opened for a kernel whose apply failed")
	}
	fc.applyErr = nil
	if err := c.Run(context.Background(), env, []string{"p53"}); err != nil {
		t.Fatal(err)
	}
	if meta, _ = dir.LoadInstanceMetadata("p53"); requireKernel("p53", meta, "this") != nil {
		t.Error("the gate stayed shut after a kernel deploy applied")
	}
}
