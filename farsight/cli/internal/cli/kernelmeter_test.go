package cli

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
	"github.com/sofmon/farcast/technocore/kernel"
)

func meterCmd(fc *fakeCluster) *kernelMeterCommand {
	c := &kernelMeterCommand{}
	c.deployer.newCluster = func(string) clusterApplier { return fc }
	return c
}

func meteredInstance(t *testing.T, dir config.Dir, name string, metered ...string) *config.InstanceMetadata {
	t.Helper()
	meta := connectedInstance(t, dir, name)
	meta.Kernel = &config.Kernel{Deployed: true, Image: "img@sha256:x", Replicas: 1, Limit: 100, Namespaces: metered}
	if err := dir.SaveInstanceMetadata(name, meta); err != nil {
		t.Fatal(err)
	}
	return meta
}

// Both halves in one apply. A namespace with a binding and no listing is
// invisible to the meter; one listed without a binding makes every tick report
// an unreachable namespace. Applied separately, a failure between them leaves
// exactly one of those states.
func TestMeteringANamespaceGrantsAndListsItTogether(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteredInstance(t, dir, "p42", tcdeploy.DefaultNamespace)
	env, _ := testEnv(dir, output.ModeHuman)
	fc := &fakeCluster{}

	if err := meterCmd(fc).Run(context.Background(), env, []string{"p42", "demo"}); err != nil {
		t.Fatal(err)
	}
	if len(fc.applied) != 1 {
		t.Fatalf("applied %d streams, want 1 — the binding and the list must go together", len(fc.applied))
	}
	m := string(fc.applied[0])
	if !strings.Contains(m, "kind: RoleBinding") || !strings.Contains(m, "namespace: demo") {
		t.Errorf("no RoleBinding for demo:\n%s", m)
	}
	// Parse the document rather than grep the stream: "farcast-system" also
	// appears as the ConfigMap's own namespace, so a substring check passes
	// even when the DATA lists only the newly added namespace.
	got := writtenMeterList(t, m)
	if strings.Join(got, ",") != "demo,farcast-system" {
		t.Errorf("the written list is %v; it must carry the whole metered set, not only what changed", got)
	}

	meta, err := dir.LoadInstanceMetadata("p42")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(meta.Kernel.Namespaces, ",") != "demo,farcast-system" {
		t.Errorf("recorded %v, want the sorted union", meta.Kernel.Namespaces)
	}
}

// The kernel is single-replica and Recreate, so restarting it would stop the
// cost meter at the moment new spending starts. Metering must never redeploy.
func TestMeteringNeverRestartsTheKernel(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteredInstance(t, dir, "p42", tcdeploy.DefaultNamespace)
	env, _ := testEnv(dir, output.ModeHuman)
	fc := &fakeCluster{}

	if err := meterCmd(fc).Run(context.Background(), env, []string{"p42", "demo"}); err != nil {
		t.Fatal(err)
	}
	if fc.rollouts != 0 {
		t.Errorf("the kernel was rolled out %d times; metering must not restart it", fc.rollouts)
	}
	if strings.Contains(string(fc.applied[0]), "kind: Deployment") {
		t.Error("metering re-applied the kernel's workload")
	}
}

// Only the newly added namespaces need a binding; re-applying one that is
// already metered is noise in an apply stream an operator may read.
func TestOnlyNewNamespacesGetABinding(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteredInstance(t, dir, "p42", tcdeploy.DefaultNamespace, "demo")
	env, _ := testEnv(dir, output.ModeHuman)
	fc := &fakeCluster{}

	if err := meterCmd(fc).Run(context.Background(), env, []string{"p42", "demo", "other"}); err != nil {
		t.Fatal(err)
	}
	m := string(fc.applied[0])
	if strings.Count(m, "kind: RoleBinding") != 1 {
		t.Errorf("expected one RoleBinding (for `other` only), got %d:\n%s", strings.Count(m, "kind: RoleBinding"), m)
	}
	if !strings.Contains(m, "namespace: other") {
		t.Error("no binding for the newly added namespace")
	}
}

func TestMeteringIsIdempotent(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteredInstance(t, dir, "p42", tcdeploy.DefaultNamespace, "demo")
	env, _ := testEnv(dir, output.ModeHuman)
	fc := &fakeCluster{}

	if err := meterCmd(fc).Run(context.Background(), env, []string{"p42", "demo"}); err != nil {
		t.Fatal(err)
	}
	if len(fc.applied) != 0 {
		t.Error("re-metering an already-metered namespace touched the cluster")
	}
}

func TestRemovingStopsMeteringAndSaysWhatItLeaves(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteredInstance(t, dir, "p42", tcdeploy.DefaultNamespace, "demo")
	env, _ := testEnv(dir, output.ModeHuman)
	fc := &fakeCluster{}

	c := meterCmd(fc)
	c.remove = true
	if err := c.Run(context.Background(), env, []string{"p42", "demo"}); err != nil {
		t.Fatal(err)
	}
	m := string(fc.applied[0])
	if strings.Contains(m, "kind: RoleBinding") {
		t.Error("removal should not apply bindings")
	}
	meta, err := dir.LoadInstanceMetadata("p42")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(meta.Kernel.Namespaces, ",") != tcdeploy.DefaultNamespace {
		t.Errorf("recorded %v after removal", meta.Kernel.Namespaces)
	}
}

// The instance's own components live in farcast-system. Un-metering it would
// stop them being counted, which is the under-reporting this whole component
// exists to prevent.
func TestFarCastsOwnNamespaceCannotBeUnmetered(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteredInstance(t, dir, "p42", tcdeploy.DefaultNamespace)
	env, _ := testEnv(dir, output.ModeHuman)
	c := meterCmd(&fakeCluster{})
	c.remove = true
	if err := c.Run(context.Background(), env, []string{"p42", tcdeploy.DefaultNamespace}); err == nil {
		t.Fatal("expected a refusal")
	}
}

func TestMeterRefusesBadNamespacesAndMissingKernels(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteredInstance(t, dir, "p42", tcdeploy.DefaultNamespace)
	env, _ := testEnv(dir, output.ModeHuman)

	for _, ns := range []string{"kube-system", "Has-Capitals", "-leading", "with space", ""} {
		fc := &fakeCluster{}
		if err := meterCmd(fc).Run(context.Background(), env, []string{"p42", ns}); err == nil {
			t.Errorf("namespace %q was accepted", ns)
		}
		if len(fc.applied) != 0 {
			t.Errorf("namespace %q reached the cluster", ns)
		}
	}

	// An instance with no kernel has nothing to meter with.
	connectedInstance(t, dir, "bare")
	if err := meterCmd(&fakeCluster{}).Run(context.Background(), env, []string{"bare", "demo"}); err == nil {
		t.Fatal("expected a refusal for an instance with no kernel")
	}
}

// A namespace the cluster meters and local state does not know about is one
// the next change would silently drop.
func TestAFailedApplyRollsBackLocalState(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteredInstance(t, dir, "p42", tcdeploy.DefaultNamespace)
	env, _ := testEnv(dir, output.ModeHuman)
	fc := &fakeCluster{applyErr: errors.New("apiserver said no")}

	if err := meterCmd(fc).Run(context.Background(), env, []string{"p42", "demo"}); err == nil {
		t.Fatal("expected the apply failure to surface")
	}
	meta, err := dir.LoadInstanceMetadata("p42")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(meta.Kernel.Namespaces, ",") != tcdeploy.DefaultNamespace {
		t.Errorf("local state kept %v after a failed apply", meta.Kernel.Namespaces)
	}
}

func TestMeterWithNoNamespacesReports(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteredInstance(t, dir, "p42", tcdeploy.DefaultNamespace, "demo")
	env, out := testEnv(dir, output.ModeHuman)
	fc := &fakeCluster{}
	if err := meterCmd(fc).Run(context.Background(), env, []string{"p42"}); err != nil {
		t.Fatal(err)
	}
	if len(fc.applied) != 0 {
		t.Error("a report touched the cluster")
	}
	if !strings.Contains(out.String(), "demo") {
		t.Errorf("the report does not list what is metered:\n%s", out.String())
	}
}

// kernel deploy seeds the same list its own bindings cover, so the two views
// never start out disagreeing.
func TestKernelDeploySeedsTheMeteredList(t *testing.T) {
	dir := config.Dir(t.TempDir())
	connectedInstance(t, dir, "p42")
	env, _ := testEnv(dir, output.ModeHuman)
	fc := &fakeCluster{}
	c := testKernelDeploy(fc, &fakeBuilder{})
	c.namespaces = "farcast-system,farcast-apps"

	if err := c.Run(context.Background(), env, []string{"p42"}); err != nil {
		t.Fatal(err)
	}
	m := string(fc.applied[0])
	if !strings.Contains(m, "name: "+kernel.DefaultNamespacesName) {
		t.Fatal("kernel deploy did not seed the metered-namespace list")
	}
	if !strings.Contains(m, "farcast-apps") {
		t.Error("the seeded list does not match the deployed bindings")
	}
}

// writtenMeterList extracts the namespaces the applied stream tells the kernel
// to meter.
func writtenMeterList(t *testing.T, manifest string) []string {
	t.Helper()
	for _, doc := range strings.Split(manifest, "---\n") {
		var cm struct {
			Kind     string
			Metadata struct{ Name string }
			Data     map[string]string
		}
		if err := yaml.Unmarshal([]byte(doc), &cm); err != nil {
			continue
		}
		if cm.Metadata.Name != kernel.DefaultNamespacesName {
			continue
		}
		var payload struct {
			Version int      `json:"version"`
			Meter   []string `json:"meter"`
		}
		if err := json.Unmarshal([]byte(cm.Data[kernel.NamespacesKey()]), &payload); err != nil {
			t.Fatalf("the written list is not the document the kernel reads: %v", err)
		}
		if payload.Version != kernel.NamespacesVersion {
			t.Errorf("wrote version %d, kernel reads %d", payload.Version, kernel.NamespacesVersion)
		}
		sort.Strings(payload.Meter)
		return payload.Meter
	}
	t.Fatal("no metered-namespace document in the applied stream")
	return nil
}

// A routine kernel redeploy must not stop metering the instance's
// applications.
//
// Found on the 4.2 walk: `kernel deploy` seeded the metered list from
// --namespaces alone, silently discarding everything `kernel meter` had added.
// An image bump or a changed limit would have stopped counting every
// application, and the only symptom would have been spending that quietly
// went unattributed.
func TestRedeployingTheKernelKeepsWhatIsAlreadyMetered(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteredInstance(t, dir, "p42", tcdeploy.DefaultNamespace, "with-build")
	env, _ := testEnv(dir, output.ModeHuman)
	// Both namespaces are really there: with-build is a deployed application,
	// which is why it is metered.
	fc := &fakeCluster{namespaces: []string{tcdeploy.DefaultNamespace, "with-build"}}

	c := testKernelDeploy(fc, &fakeBuilder{})
	c.namespaces = tcdeploy.DefaultNamespace // as a plain redeploy would pass
	if err := c.Run(context.Background(), env, []string{"p42"}); err != nil {
		t.Fatal(err)
	}

	got := writtenMeterList(t, string(fc.applied[0]))
	if strings.Join(got, ",") != "farcast-system,with-build" {
		t.Errorf("redeploy wrote %v; it dropped a metered namespace", got)
	}
	meta, err := dir.LoadInstanceMetadata("p42")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(meta.Kernel.Namespaces, ",") != "farcast-system,with-build" {
		t.Errorf("local record became %v after a redeploy", meta.Kernel.Namespaces)
	}
}
