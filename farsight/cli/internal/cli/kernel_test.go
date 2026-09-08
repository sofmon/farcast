package cli

import (
	"context"
	"strings"
	"testing"

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
	connectedInstance(t, dir, "p41") // USD 50, below the ~$73 floor
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
	if !strings.Contains(warned, "below what") || !strings.Contains(warned, "never stops the tunnel") {
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

func TestParseNamespacesDefaultsToFarCastsOwn(t *testing.T) {
	cases := map[string][]string{
		"":                        {tcdeploy.DefaultNamespace},
		"   ":                     {tcdeploy.DefaultNamespace},
		",,":                      {tcdeploy.DefaultNamespace},
		"a,b":                     {"a", "b"},
		" a , b ,":                {"a", "b"},
		tcdeploy.DefaultNamespace: {tcdeploy.DefaultNamespace},
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
