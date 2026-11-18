package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
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
	c.deployer.newCluster = func(clusterRef) (clusterApplier, error) { return fc, nil }
	c.deployer.findSource = func(string) (string, error) { return "/checkouts/farcast", nil }
	c.deployer.findToolchain = fakeToolchain
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
	ok, err := c.confirmCost(env, meta, kernelCost(meta), []string{tcdeploy.DefaultNamespace})
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
	ok, err := c.confirmCost(env, meta, kernelCost(meta), []string{tcdeploy.DefaultNamespace})
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
	ok, err := c.confirmCost(env, meta, kernelCost(meta), []string{tcdeploy.DefaultNamespace})
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

// kernelDeployRefusalsNameThePlan is TestNonInteractiveRefusalsNameThePlan's
// rows for kernel deploy (ADR 0023 M2.6, A23-16): with no terminal and no
// --yes, its cost question refuses, exit 2, in exact cents, naming the
// plan's route, whether the limit clears the instance's floor or not, and
// before anything is ensured, pushed, recorded or applied. Its build
// question comes after the cost question, which no run without a terminal
// or --yes passes. On a record that names no registry such a run gives none
// first (ADR 0023 M2.6c): only a run that can pass the gate ensures before
// its plan, so it is refused in planRegistry's words, the provider never
// opened and the record as it was.
func kernelDeployRefusalsNameThePlan(t *testing.T) {
	for _, tc := range []struct {
		name     string
		limit    float64
		registry bool
		want     func(meta *config.InstanceMetadata) string
		exit     int
	}{
		{"the cost", 500, true, func(*config.InstanceMetadata) string {
			return fmt.Sprintf(msgKernelCostYes, amount(cents(kernelMonthlyUSD)))
		}, 2},
		{"below the floor", 50, true, func(meta *config.InstanceMetadata) string {
			return fmt.Sprintf(msgKernelBelowFloorYes, "USD 50.00", "monthly", money("USD", cents(floorFull(meta).Total)))
		}, 2},
		{"no registry recorded", 500, false, func(*config.InstanceMetadata) string {
			return fmt.Sprintf(msgNoRegistryRecorded, "p41", "p41")
		}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := config.Dir(t.TempDir())
			meta := connectedInstance(t, dir, "p41")
			if tc.registry {
				meta.Registry = &config.Registry{Prefix: "us-central1-docker.pkg.dev/proj-1/farcast-p41"}
			}
			meta.CostLimit.Amount = tc.limit
			if err := dir.SaveInstanceMetadata("p41", meta); err != nil {
				t.Fatal(err)
			}
			fc, fb := &fakeCluster{}, &fakeBuilder{resolveFn: notFoundForTags}
			c := testKernelDeploy(fc, fb)
			c.deployer.assumeYes = false
			fp, opened := &fakeProvider{}, 0
			c.deployer.openProvider = func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) {
				opened++
				return fp, nil
			}
			env, _ := testEnv(dir, output.ModeHuman) // stdin is no terminal
			err := c.Run(t.Context(), env, []string{"p41"})
			want := tc.want(meta)
			if err == nil || err.Error() != want || exitCodeOf(err) != tc.exit || (tc.exit == 2 && !strings.HasSuffix(want, consentSuffix)) {
				t.Errorf("kernel deploy with no terminal = %v (exit %d); want %q", err, exitCodeOf(err), want)
			}
			if len(fp.ensured)+len(fb.embedded)+len(fb.built)+len(fc.applied) != 0 || (!tc.registry && opened != 0) {
				t.Errorf("a refused deploy ensured %d registries, pushed %d, built %d and applied %d, and opened the provider %d times",
					len(fp.ensured), len(fb.embedded), len(fb.built), len(fc.applied), opened)
			}
			after, _ := dir.LoadInstanceMetadata("p41")
			if after.Kernel != nil {
				t.Errorf("a refused deploy recorded a kernel: %+v", after.Kernel)
			}
			if registryPrefix(after) != registryPrefix(meta) {
				t.Errorf("a refused deploy recorded the registry %q; want %q", registryPrefix(after), registryPrefix(meta))
			}
		})
	}
}

// ADR 0023 M2.6 (A23-33, A23-38, row 90): a cost limit below the instance's
// floor is a fact kernel deploy's plan states, never a block, as --yes
// deploys past it today. With no terminal, the plan is unblocked, its cost
// fact binds the limit, the floor of the instance fully provisioned and
// below_floor, and its rendering says so; its --confirm, with no terminal
// either, asks nothing and deploys.
func TestKernelDeployPlanCarriesBelowFloorAsAFact(t *testing.T) {
	row := planCommandNamed(t, "kernel deploy", "below the floor")
	_, dir := planFixture(t, row)
	meta, err := dir.LoadInstanceMetadata(writeName)
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := runPlan(t, dir, row, output.ModeJSON)
	b := decodedBound(t, doc)
	if len(b.Blocked) != 0 {
		t.Fatalf("a limit below the floor blocked the plan: %+v", b.Blocked)
	}
	var cost *plan.CostFact
	for _, f := range b.Facts {
		if c, ok := f.(plan.CostFact); ok {
			cost = &c
		}
	}
	if cost == nil || !cost.BelowFloor || cost.LimitCents != 5000 || cost.FloorMonthCents != cents(floorFull(meta).Total) ||
		len(cost.Standing) != 1 || cost.Standing[0].MonthCents != cents(kernelMonthlyUSD) {
		t.Errorf("the cost fact is %+v; want the limit USD 50.00 below the floor %d cents, and the kernel's cost", cost, cents(floorFull(meta).Total))
	}
	if _, text := runPlan(t, dir, row, output.ModeHuman); !strings.Contains(text, "; the cost limit is below it\n") {
		t.Errorf("the rendering does not say the limit is below the floor:\n%s", text)
	}

	// Its --confirm, with no terminal, through a writer that reaches the
	// plan's cluster, and a registry ensure that answers the planned one.
	row.fakes.provider.registry = &planck.Registry{Ref: registryRefFor(meta), Prefix: meta.Registry.Prefix}
	fc := &fakeCluster{uid: planSystemUID}
	c := withFlags(t, row.cmd().(*kernelDeployCommand), "--confirm", doc.Digest)
	c.deployer.newCluster = func(clusterRef) (clusterApplier, error) { return fc, nil }
	env, _, errb := testEnvBoth(dir, output.ModeHuman) // stdin is no terminal
	if err := c.Run(t.Context(), env, row.args); err != nil {
		t.Fatalf("--confirm below the floor = %v\n%s", err, errb)
	}
	if len(fc.applied) != 1 || strings.Contains(errb.String(), "[y/N]") {
		t.Errorf("--confirm applied %d streams and said %q; want it deployed, unasked", len(fc.applied), errb)
	}
}

// ADR 0023 M2.6 (A23-18, A23-38, row 74c): a namespace --namespaces names
// that the instance does not have blocks kernel deploy's plan, with today's
// text, kind internal. Computation stops at the block: the plan binds its
// target, farcast-system's uid among it, and its options, and no fact; and
// nothing more is read, Google included: no installer key, no provider, no
// lookup. Its --confirm compares, then refuses with the block's kind and
// text, exit 1, having opened no writer and written nothing.
func TestKernelDeployPlanBlocksAMissingNamespace(t *testing.T) {
	row := planCommandNamed(t, "kernel deploy", "a missing namespace")
	s, dir := planFixture(t, row)
	reads := observeConfigReads(t)
	doc, _ := runPlan(t, dir, row, output.ModeJSON)
	b := decodedBound(t, doc)
	want := plan.Block{Kind: kindInternal, Message: fmt.Sprintf(msgNoSuchNamespace, "web")}
	if !slices.Equal(b.Blocked, []plan.Block{want}) || len(b.Facts) != 0 {
		t.Fatalf("the plan blocks %+v with %d facts; want %+v and none", b.Blocked, len(b.Facts), want)
	}
	if b.Target.SystemNamespaceUID != planSystemUID || !slices.Contains(b.Options, plan.Option{Flag: "namespaces", Value: "web"}) {
		t.Errorf("the blocked plan binds the target %+v and the options %+v; want farcast-system's uid and --namespaces=web", b.Target, b.Options)
	}
	if f := row.fakes; f.opened+f.writers != 0 || len(f.builder.resolved) != 0 {
		t.Errorf("after the block it opened the provider %d times and the writer %d times, and looked up %q", f.opened, f.writers, f.builder.resolved)
	}
	for _, p := range reads() {
		if filepath.Base(p) == "credentials.yaml" {
			t.Errorf("after the block it read %s", p)
		}
	}

	before := treeFiles(t, string(dir))
	cmd := withFlags(t, row.cmd(), append(slices.Clone(row.flags), "--confirm", doc.Digest)...)
	env, out, _ := testEnvBoth(dir, output.ModeJSON)
	err := cmd.Run(t.Context(), env, row.args)
	if err == nil || err.Error() != want.Message || kindOf(classified(err)) != kindInternal || exitCodeOf(err) != 1 {
		t.Errorf("--confirm of the blocked plan = %v (kind %s, exit %d); want its block", err, kindOf(classified(err)), exitCodeOf(err))
	}
	if out.Len() != 0 || row.fakes.writers != 0 {
		t.Errorf("--confirm of the blocked plan printed %q and opened the writer %d times", out, row.fakes.writers)
	}
	onlyThePlansReads(t, row, s, consentConfirm)
	sameFiles(t, "a blocked kernel deploy", before, treeFiles(t, string(dir)))
}

// kernelRig is kernel deploy against writeInstance's fixture — its reader
// granted, a registry recorded — through fakes only: the provider answers
// the recorded registry, the builder's version tags are absent unless a test
// says otherwise, and one cluster, farcast-system's uid u1, is both the
// plan's reader and the writer, every apply recorded. onWriter runs as the
// writer opens, and opened counts the provider's opens.
type kernelRig struct {
	dir      config.Dir
	fp       *fakeProvider
	fb       *fakeBuilder
	fc       *fakeCluster
	onWriter func()
	opened   int
}

func newKernelRig(t *testing.T, edit func(meta *config.InstanceMetadata)) *kernelRig {
	t.Helper()
	dir, meta := writeInstance(t, kubetest.New(t), true)
	if edit != nil {
		edit(meta)
		if err := dir.SaveInstanceMetadata(writeName, meta); err != nil {
			t.Fatal(err)
		}
	}
	return &kernelRig{dir: dir,
		fp: &fakeProvider{registry: &planck.Registry{Ref: registryRefFor(meta), Prefix: meta.Registry.Prefix}},
		fb: &fakeBuilder{resolveFn: notFoundForTags},
		fc: &fakeCluster{uid: "u1", namespaces: []string{tcdeploy.DefaultNamespace}},
	}
}

// cmd is kernel deploy with its flags parsed and the rig's seams.
func (r *kernelRig) cmd(t *testing.T, flags ...string) *kernelDeployCommand {
	t.Helper()
	c := withFlags(t, &kernelDeployCommand{}, flags...)
	asRelease(&c.deployer, nil)
	c.deployer.openProvider = func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) {
		r.opened++
		return r.fp, nil
	}
	c.deployer.newBuilder = func(func(string)) imageBuilder { return r.fb }
	c.deployer.findToolchain = fakeToolchain
	c.newPlanReader = func(ref clusterRef) (kernelPlanReader, error) {
		if ref.Identity != kube.Reader {
			return nil, fmt.Errorf("test: the plan's reader opened as %q", ref.Identity)
		}
		return r.fc, nil
	}
	c.deployer.newCluster = func(clusterRef) (clusterApplier, error) {
		if r.onWriter != nil {
			r.onWriter()
		}
		return r.fc, nil
	}
	return c
}

// run runs kernel deploy with flags, in JSON mode with no terminal.
func (r *kernelRig) run(t *testing.T, flags ...string) (stdout, stderr string, err error) {
	t.Helper()
	env, out, errb := testEnvBoth(r.dir, output.ModeJSON)
	err = r.cmd(t, flags...).Run(t.Context(), env, []string{writeName})
	return out.String(), errb.String(), err
}

// plan is kernel deploy's --plan.
func (r *kernelRig) plan(t *testing.T, flags ...string) plan.Document {
	t.Helper()
	stdout, stderr, err := r.run(t, append([]string{"--plan"}, flags...)...)
	if err != nil {
		t.Fatalf("kernel deploy --plan: %v\n%s", err, stderr)
	}
	return printedDocument(t, []byte(stdout))
}

// kernelSettingsOf is a kernel deploy plan's kernel_settings fact.
func kernelSettingsOf(t *testing.T, doc plan.Document) plan.KernelSettingsFact {
	t.Helper()
	for _, f := range decodedBound(t, doc).Facts {
		if k, ok := f.(plan.KernelSettingsFact); ok {
			return k
		}
	}
	t.Fatal("the plan has no kernel_settings fact")
	return plan.KernelSettingsFact{}
}

// ADR 0023 M2.6 (A23-33, rows O24 and O45 of the M2.6c review): the
// kernel_settings fact binds what the kernel is deployed with. A record's
// knobs are carried forward when no flag names them — adapting on, a 10 s
// interval and a 2 h cooldown here — and a flag replaces the one it names.
func TestKernelSettingsFactCarriesTheRecordedKnobs(t *testing.T) {
	recorded := func(m *config.InstanceMetadata) {
		m.Kernel.Adapt, m.Kernel.Interval, m.Kernel.AdaptCooldown = true, 10*time.Second, 2*time.Hour
	}
	r := newKernelRig(t, recorded)
	if got := kernelSettingsOf(t, r.plan(t)); !got.Adapt || got.IntervalS != 10 || got.AdaptCooldownS != 7200 {
		t.Errorf("the kernel_settings fact is %+v; want adapting on, interval 10 s and cooldown 7200 s, as recorded", got)
	}
	got := kernelSettingsOf(t, r.plan(t, "--adapt=false", "--interval", "20s", "--adapt-cooldown", "3h"))
	if got.Adapt || got.IntervalS != 20 || got.AdaptCooldownS != 10800 {
		t.Errorf("with flags the kernel_settings fact is %+v; want adapting off, interval 20 s and cooldown 10800 s", got)
	}
}

// ADR 0023 M2.6c (O-3 of the M2.6c review): the kernel_settings fact states
// the interval and the cooldown in whole seconds, so nothing it shows can
// differ from what is applied. A flag that is not a whole number of seconds
// is a usage error in every mode, before anything is opened or read. A
// recorded knob that is not, which kernel deploy recorded as given before,
// is refused by a plan, internal, naming the knob and the flag that replaces
// it, with nothing printed — and the flag does replace it — while a --yes
// run, which shows no fact, deploys it as recorded.
func TestKernelDeployKnobsAreWholeSeconds(t *testing.T) {
	for _, flags := range [][]string{{"--interval", "5500ms"}, {"--adapt", "--adapt-cooldown", "90500ms"}} {
		for _, answer := range [][]string{{"--yes"}, {"--plan"}, {"--confirm", sampleDigest}} {
			t.Run(fmt.Sprint(flags, answer), func(t *testing.T) {
				r := newKernelRig(t, nil)
				stdout, _, err := r.run(t, append(slices.Clone(flags), answer...)...)
				flag := strings.TrimPrefix(flags[len(flags)-2], "--")
				want := fmt.Sprintf("--%s: %s is not a whole number of seconds", flag, map[string]string{
					"interval": "5.5s", "adapt-cooldown": "1m30.5s"}[flag])
				if err == nil || err.Error() != want || exitCodeOf(err) != 2 {
					t.Fatalf("kernel deploy %v %v = %v (exit %d); want %q, a usage error", flags, answer, err, exitCodeOf(err), want)
				}
				if stdout != "" || r.opened != 0 || len(r.fc.applied) != 0 {
					t.Errorf("printed %q, opened the provider %d times and applied %d", stdout, r.opened, len(r.fc.applied))
				}
			})
		}
	}
	subSecond := func(m *config.InstanceMetadata) { m.Kernel.Interval = 5500 * time.Millisecond }
	for _, answer := range [][]string{{"--plan"}, {"--confirm", sampleDigest}} {
		t.Run("a recorded interval/"+answer[0], func(t *testing.T) {
			r := newKernelRig(t, subSecond)
			stdout, _, err := r.run(t, answer...)
			want := fmt.Sprintf(msgKernelKnobNotWhole, writeName, "interval", "5.5s", "interval")
			if err == nil || err.Error() != want || kindOf(classified(err)) != kindInternal || exitCodeOf(err) != 1 {
				t.Fatalf("kernel deploy %s over a recorded 5.5s interval = %v (kind %s); want %q", answer[0], err, kindOf(classified(err)), want)
			}
			if stdout != "" || r.opened != 0 {
				t.Errorf("printed %q and opened the provider %d times", stdout, r.opened)
			}
		})
	}
	t.Run("a recorded interval/replaced by the flag", func(t *testing.T) {
		r := newKernelRig(t, subSecond)
		if got := kernelSettingsOf(t, r.plan(t, "--interval", "6s")); got.IntervalS != 6 {
			t.Errorf("the plan binds the interval %d s; want the flag's 6", got.IntervalS)
		}
	})
	t.Run("a recorded interval/--yes", func(t *testing.T) {
		r := newKernelRig(t, subSecond)
		if _, stderr, err := r.run(t, "--yes"); err != nil {
			t.Fatalf("kernel deploy --yes over a recorded 5.5s interval = %v\n%s", err, stderr)
		}
		meta, err := r.dir.LoadInstanceMetadata(writeName)
		if err != nil {
			t.Fatal(err)
		}
		if len(r.fc.applied) != 1 || meta.Kernel.Interval != 5500*time.Millisecond {
			t.Errorf("applied %d streams and recorded the interval %s; want the deploy, as recorded", len(r.fc.applied), meta.Kernel.Interval)
		}
	})
}
