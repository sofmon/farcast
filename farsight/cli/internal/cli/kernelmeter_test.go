package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
	"github.com/sofmon/farcast/technocore/kernel"
)

func meterCmd(fc *fakeCluster) *kernelMeterCommand {
	c := &kernelMeterCommand{}
	c.deployer.newCluster = func(clusterRef) (clusterApplier, error) { return fc, nil }
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

// ADR 0023 M2.6 (A23-8): kernel meter with no namespace only reports, so it
// has nothing to plan or confirm: --plan and --confirm without namespaces are
// a usage error, raised before anything is read.
func TestKernelMeterPlanNeedsNamespaces(t *testing.T) {
	const want = "kernel meter --plan and --confirm need namespaces to add or remove; with none it only reports what is metered"
	dir := config.Dir(t.TempDir())
	meteredInstance(t, dir, "p42", tcdeploy.DefaultNamespace, "demo")
	for _, answer := range [][]string{{"--plan"}, {"--confirm", sampleDigest}} {
		fc := &fakeCluster{}
		c := withFlags(t, meterCmd(fc), answer...)
		env, out, errb := testEnvBoth(dir, output.ModeJSON)
		reads := observeConfigReads(t)
		err := c.Run(t.Context(), env, []string{"p42"})
		var ue *usageError
		if !errors.As(err, &ue) || err.Error() != want || exitCodeOf(err) != 2 {
			t.Errorf("kernel meter p42 %q = %v (exit %d); want the usage error %q", answer, err, exitCodeOf(err), want)
		}
		if len(reads()) != 0 || len(fc.applied) != 0 || out.Len() != 0 || errb.Len() != 0 {
			t.Errorf("kernel meter p42 %q read %q, applied %d streams and printed %q %q", answer, reads(), len(fc.applied), out, errb)
		}
	}
	if _, stderr, code := farcastIn(t, dir, "kernel", "meter", "p42", "--plan"); code != 2 || !strings.Contains(stderr, want) {
		t.Errorf("through the router: exit %d, %q; want exit 2 and %q", code, stderr, want)
	}
}

// ADR 0023 M2.6 (A23-8, mutation 90c): a request that changes nothing is
// still a plan, the meter fact and the line it prints, with no write. Its
// --confirm compares it before it says anything: a changed one says nothing
// and opens nothing; the same one prints today's line and result, and opens
// nothing either.
func TestKernelMeterConfirmOfANoOpIsComparedFirst(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteredInstance(t, dir, "p42", tcdeploy.DefaultNamespace, "demo")
	opened := 0
	cmd := func(flags ...string) *kernelMeterCommand {
		c := withFlags(t, &kernelMeterCommand{}, flags...)
		c.deployer.newCluster = func(clusterRef) (clusterApplier, error) {
			opened++
			return &fakeCluster{}, nil
		}
		return c
	}

	env, out := testEnv(dir, output.ModeJSON)
	if err := cmd("--plan").Run(t.Context(), env, []string{"p42", "demo"}); err != nil {
		t.Fatal(err)
	}
	doc := printedDocument(t, out.Bytes())
	b := decodedBound(t, doc)
	meta, err := dir.LoadInstanceMetadata("p42")
	if err != nil {
		t.Fatal(err)
	}
	want := newBound("kernel meter", meta, "none", "")
	want.Options = []plan.Option{{Flag: "remove", Value: "false"}}
	want.Facts = []plan.Fact{
		plan.MeterFact{Type: plan.TypeMeter, Add: []string{"demo"}, MeteredAfter: []string{"demo", tcdeploy.DefaultNamespace}},
		plan.NoticeFact{Type: plan.TypeNotice, Text: "Already metering demo."},
	}
	if got := string(doc.Bound); got != mustCanonical(t, want) {
		t.Errorf("the no-op's plan is\n%s\nwant\n%s", got, mustCanonical(t, want))
	}
	if len(writeTargets(b)) != 0 {
		t.Errorf("the no-op's plan writes %q", writeTargets(b))
	}

	env, out, errb := testEnvBoth(dir, output.ModeHuman)
	err = cmd("--confirm", sampleDigest).Run(t.Context(), env, []string{"p42", "demo"})
	if kindOf(classified(err)) != kindPlanChanged {
		t.Fatalf("--confirm of a changed no-op = %v; want plan_changed", err)
	}
	if errb.Len() != 0 || out.Len() != 0 {
		t.Errorf("a changed no-op said %q %q before its comparison refused it", out, errb)
	}

	env, out, errb = testEnvBoth(dir, output.ModeHuman)
	if err := cmd("--confirm", doc.Digest).Run(t.Context(), env, []string{"p42", "demo"}); err != nil {
		t.Fatalf("--confirm of the no-op: %v", err)
	}
	if errb.String() != "Already metering demo.\n" || !strings.Contains(out.String(), "\"p42\" meters:\n") {
		t.Errorf("--confirm of the no-op printed %q and %q; want today's line and result", errb, out)
	}
	if opened != 0 {
		t.Errorf("a no-op opened the writer %d times", opened)
	}
}

// ADR 0023 M2.6 (A23-39, P3): once 'reader grant' recorded its scope, kernel
// meter's plan names the reader it binds and where, beside the kernel's own
// bindings, and the bindings are among its writes; with the reader recorded
// but not granted, it binds none.
func TestKernelMeterPlanNamesReaderBindings(t *testing.T) {
	for _, state := range []string{"metered", "recorded"} {
		t.Run(state, func(t *testing.T) {
			dir := config.Dir(t.TempDir())
			meteredInstance(t, dir, "p42", tcdeploy.DefaultNamespace)
			withReader(t, dir, "p42", state)
			email := readerEmail("p42", "proj-test1")
			c := withFlags(t, meterCmd(&fakeCluster{}), "--plan")
			env, out := testEnv(dir, output.ModeJSON)
			if err := c.Run(t.Context(), env, []string{"p42", "demo", "other"}); err != nil {
				t.Fatal(err)
			}
			b := decodedBound(t, printedDocument(t, out.Bytes()))
			reader, bindings := "", []string{}
			targets := []string{"RoleBinding demo/technocore", "RoleBinding other/technocore", "ConfigMap farcast-system/technocore-namespaces"}
			if state == "metered" {
				reader, bindings = email, []string{"demo", "other"}
				targets = []string{"RoleBinding demo/technocore", "RoleBinding demo/farcast-reader",
					"RoleBinding other/technocore", "RoleBinding other/farcast-reader", "ConfigMap farcast-system/technocore-namespaces"}
			}
			meter, ok := b.Facts[0].(plan.MeterFact)
			if !ok || meter.Reader != reader || !slices.Equal(meter.ReaderBindingsCreated, bindings) ||
				!slices.Equal(meter.Add, []string{"demo", "other"}) || !slices.Equal(meter.BindingsCreated, []string{"demo", "other"}) ||
				!slices.Equal(meter.MeteredAfter, []string{"demo", tcdeploy.DefaultNamespace, "other"}) {
				t.Errorf("the plan's first fact is %+v", b.Facts[0])
			}
			if got := writeTargets(b); !slices.Equal(got, targets) {
				t.Errorf("the plan writes %q; want %q", got, targets)
			}
			manifest, err := meterManifest([]string{"demo", tcdeploy.DefaultNamespace, "other"}, []string{"demo", "other"}, reader)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := b.Facts[1:len(targets)+1], wantWrites(t, manifest); mustCanonical(t, plan.Bound{Protocol: plan.Protocol, Facts: got}) !=
				mustCanonical(t, plan.Bound{Protocol: plan.Protocol, Facts: want}) {
				t.Errorf("the plan's writes are not the stream's documents:\n%+v\n%+v", got, want)
			}

			c = withFlags(t, meterCmd(&fakeCluster{}), "--plan")
			env, out = testEnv(dir, output.ModeHuman)
			if err := c.Run(t.Context(), env, []string{"p42", "demo", "other"}); err != nil {
				t.Fatal(err)
			}
			line := "  no reader binding is added\n"
			if state == "metered" {
				line = "  the reader " + email + " is bound in: demo, other\n"
			}
			if !strings.Contains(out.String(), line) {
				t.Errorf("the rendering does not say %q:\n%s", line, out)
			}
		})
	}
}

// ADR 0023 M2.6 (A23-39, A23-40; row 71a holds): kernel meter and kernel
// confirm open the writer only to write. --plan opens nothing; --confirm of
// a changed plan opens nothing and writes nothing; --confirm of the plan
// opens the writer once, after the comparison and before the record
// changes, records, and applies the planned stream.
func TestKernelMeterAndConfirmOpenTheWriterOnlyAfterTheCompare(t *testing.T) {
	for _, row := range []struct {
		name   string
		setup  func(t *testing.T, dir config.Dir)
		cmd    func() Command
		args   []string
		flags  []string
		change func(m *config.InstanceMetadata)
		record func(m *config.InstanceMetadata) string
	}{
		{"kernel meter", func(t *testing.T, dir config.Dir) { meteredInstance(t, dir, "p42", tcdeploy.DefaultNamespace) },
			func() Command { return &kernelMeterCommand{} }, []string{"p42", "demo"}, nil,
			func(m *config.InstanceMetadata) { m.Kernel.Namespaces = append(m.Kernel.Namespaces, "other") },
			func(m *config.InstanceMetadata) string { return strings.Join(m.Kernel.Namespaces, ",") }},
		{"kernel confirm", func(t *testing.T, dir config.Dir) { kernelInstance(t, dir, "p42") },
			func() Command {
				c := &kernelConfirmCommand{}
				c.deployer.now = planClock
				return c
			}, []string{"p42"}, []string{"--amount", "2.5", "--from", planMonth(1), "--to", planMonth(2)},
			func(m *config.InstanceMetadata) {
				m.Kernel.Confirmations = []config.KernelConfirmation{{Start: day(planMonth(3)), End: day(planMonth(4)), USD: 1}}
			},
			func(m *config.InstanceMetadata) string { return fmt.Sprint(len(m.Kernel.Confirmations)) }},
	} {
		t.Run(row.name, func(t *testing.T) {
			var dir config.Dir
			fresh := func() {
				dir = config.Dir(t.TempDir())
				row.setup(t, dir)
			}
			fresh()
			var opens []string // the record as each open found it
			var fc *fakeCluster
			cmd := func(flags ...string) Command {
				c := withFlags(t, row.cmd(), append(slices.Clone(row.flags), flags...)...)
				fc = &fakeCluster{}
				seam := func(r clusterRef) (clusterApplier, error) {
					m, err := dir.LoadInstanceMetadata("p42")
					if err != nil {
						t.Fatal(err)
					}
					if r.Identity != kube.Writer {
						t.Errorf("the writer's seam was opened as %v", r.Identity)
					}
					opens = append(opens, row.record(m))
					return fc, nil
				}
				switch c := c.(type) {
				case *kernelMeterCommand:
					c.deployer.newCluster = seam
				case *kernelConfirmCommand:
					c.deployer.newCluster = seam
				}
				return c
			}
			load := func() string {
				m, err := dir.LoadInstanceMetadata("p42")
				if err != nil {
					t.Fatal(err)
				}
				return row.record(m)
			}

			env, out := testEnv(dir, output.ModeJSON)
			if err := cmd("--plan").Run(t.Context(), env, row.args); err != nil {
				t.Fatal(err)
			}
			digest := printedDocument(t, out.Bytes()).Digest
			if len(opens) != 0 || len(fc.applied) != 0 {
				t.Fatalf("--plan opened the writer %d times and applied %d streams", len(opens), len(fc.applied))
			}

			env, _ = testEnv(dir, output.ModeJSON)
			if err := cmd("--confirm", sampleDigest).Run(t.Context(), env, row.args); kindOf(classified(err)) != kindPlanChanged {
				t.Fatalf("--confirm of another plan = %v; want plan_changed", err)
			}
			if len(opens) != 0 || len(fc.applied) != 0 {
				t.Errorf("a changed plan opened the writer %d times and applied %d streams", len(opens), len(fc.applied))
			}

			before := load()
			env, _ = testEnv(dir, output.ModeJSON)
			if err := cmd("--confirm", digest).Run(t.Context(), env, row.args); err != nil {
				t.Fatalf("--confirm of the plan: %v", err)
			}
			if !slices.Equal(opens, []string{before}) {
				t.Errorf("the writer opened with the record at %q; want once, before it changed (%q)", opens, before)
			}
			if len(fc.applied) != 1 || load() == before {
				t.Errorf("--confirm applied %d streams and recorded %q; want one, and the record changed", len(fc.applied), load())
			}

			// A plan that changed between --plan and --confirm, by the record.
			fresh()
			opens = nil
			env, out = testEnv(dir, output.ModeJSON)
			if err := cmd("--plan").Run(t.Context(), env, row.args); err != nil {
				t.Fatal(err)
			}
			digest = printedDocument(t, out.Bytes()).Digest
			if _, err := dir.UpdateInstanceMetadata("p42", func(m *config.InstanceMetadata) error {
				row.change(m)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			changed := load()
			env, _ = testEnv(dir, output.ModeJSON)
			if err := cmd("--confirm", digest).Run(t.Context(), env, row.args); kindOf(classified(err)) != kindPlanChanged {
				t.Fatalf("--confirm after the record changed = %v; want plan_changed", err)
			}
			if len(opens) != 0 || len(fc.applied) != 0 || load() != changed {
				t.Errorf("a plan the record changed opened the writer %d times, applied %d streams and recorded %q", len(opens), len(fc.applied), load())
			}
		})
	}
}

// ADR 0023 M2.6 (A23-39; C-L9-2, M-M26A-MUT-02, -03, -11): a --remove plan
// says what removing leaves behind, after its writes: that the cost guard
// stops counting the namespaces, and, on an instance that records a reader,
// granted or not, that the reader's binding there stays and still reads.
// Removing a namespace that is not metered is not the add's no-op: it
// writes the list again and says the same, never "Already metering". The
// notices are the plan's only: outside it the result says them.
func TestKernelMeterRemovePlanNamesWhatStays(t *testing.T) {
	stops := fmt.Sprintf(msgMeterStopsCounting, "demo")
	for _, row := range []struct {
		name    string
		reader  string
		metered []string
		left    []string
		notices []string
	}{
		{"a reader granted", "metered", []string{tcdeploy.DefaultNamespace, "demo"}, []string{"demo"}, []string{stops, msgReaderBindingStays}},
		{"a reader recorded", "recorded", []string{tcdeploy.DefaultNamespace, "demo"}, []string{"demo"}, []string{stops, msgReaderBindingStays}},
		{"no reader", "none", []string{tcdeploy.DefaultNamespace, "demo"}, []string{"demo"}, []string{stops}},
		{"demo not metered", "none", []string{tcdeploy.DefaultNamespace}, nil, []string{stops}},
	} {
		t.Run(row.name, func(t *testing.T) {
			dir := config.Dir(t.TempDir())
			meteredInstance(t, dir, "p42", row.metered...)
			withReader(t, dir, "p42", row.reader)
			meta, err := dir.LoadInstanceMetadata("p42")
			if err != nil {
				t.Fatal(err)
			}
			manifest, err := meterManifest([]string{tcdeploy.DefaultNamespace}, nil, "")
			if err != nil {
				t.Fatal(err)
			}
			want := newBound("kernel meter", meta, "none", "")
			want.Options = []plan.Option{{Flag: "remove", Value: "true"}}
			want.Facts = append([]plan.Fact{plan.MeterFact{Type: plan.TypeMeter, Remove: []string{"demo"}, BindingsLeft: row.left,
				MeteredAfter: []string{tcdeploy.DefaultNamespace}}}, wantWrites(t, manifest)...)
			for _, n := range row.notices {
				want.Facts = append(want.Facts, plan.NoticeFact{Type: plan.TypeNotice, Text: n})
			}

			env, out, errb := testEnvBoth(dir, output.ModeJSON)
			if err := withFlags(t, meterCmd(&fakeCluster{}), "--remove", "--plan").Run(t.Context(), env, []string{"p42", "demo"}); err != nil {
				t.Fatal(err)
			}
			if got := string(printedDocument(t, out.Bytes()).Bound); got != mustCanonical(t, want) {
				t.Errorf("the --remove plan binds\n%s\nwant\n%s", got, mustCanonical(t, want))
			}
			if errb.Len() != 0 {
				t.Errorf("--plan printed %q on stderr", errb)
			}

			env, out = testEnv(dir, output.ModeHuman)
			if err := withFlags(t, meterCmd(&fakeCluster{}), "--remove", "--plan").Run(t.Context(), env, []string{"p42", "demo"}); err != nil {
				t.Fatal(err)
			}
			for _, n := range row.notices {
				first, _, _ := strings.Cut(n, "\n")
				if !strings.Contains(out.String(), "notice: "+first+"\n") {
					t.Errorf("the rendering does not show the notice %q:\n%s", first, out)
				}
			}

			fc := &fakeCluster{}
			env, _, errb = testEnvBoth(dir, output.ModeHuman)
			if err := withFlags(t, meterCmd(fc), "--remove").Run(t.Context(), env, []string{"p42", "demo"}); err != nil {
				t.Fatal(err)
			}
			if len(fc.applied) != 1 || errb.Len() != 0 {
				t.Errorf("outside a plan --remove applied %d streams and printed %q; want one, and its notices left to the result", len(fc.applied), errb)
			}
		})
	}
}

// ADR 0023 M2.6 (design §9.2, A23-39, A23-40; M-M26A-MUT-01): --confirm
// executes only from the recomputed plan, so what it applies is exactly the
// documents its write facts bind, in their order, each with its hash, even
// when the namespaces are given out of order.
func TestKernelMeterAndConfirmApplyExactlyThePlannedWrites(t *testing.T) {
	for _, row := range []struct {
		name  string
		setup func(t *testing.T, dir config.Dir)
		cmd   func(fc *fakeCluster) Command
		args  []string
		flags []string
	}{
		{"kernel meter", func(t *testing.T, dir config.Dir) {
			meteredInstance(t, dir, "p42", tcdeploy.DefaultNamespace)
			withReader(t, dir, "p42", "metered")
		}, func(fc *fakeCluster) Command { return meterCmd(fc) }, []string{"p42", "other", "demo"}, nil},
		{"kernel confirm", func(t *testing.T, dir config.Dir) { kernelInstance(t, dir, "p42") }, func(fc *fakeCluster) Command {
			c := confirmCmd(fc)
			c.deployer.now = planClock
			return c
		}, []string{"p42"}, []string{"--amount", "2.5", "--from", planMonth(1), "--to", planMonth(2)}},
	} {
		t.Run(row.name, func(t *testing.T) {
			dir := config.Dir(t.TempDir())
			row.setup(t, dir)
			env, out := testEnv(dir, output.ModeJSON)
			if err := withFlags(t, row.cmd(&fakeCluster{}), append(slices.Clone(row.flags), "--plan")...).Run(t.Context(), env, row.args); err != nil {
				t.Fatal(err)
			}
			doc := printedDocument(t, out.Bytes())
			var planned []plan.Fact
			for _, f := range decodedBound(t, doc).Facts {
				if w, ok := f.(plan.WriteFact); ok {
					planned = append(planned, w)
				}
			}

			fc := &fakeCluster{}
			env, _ = testEnv(dir, output.ModeJSON)
			if err := withFlags(t, row.cmd(fc), append(slices.Clone(row.flags), "--confirm", doc.Digest)...).Run(t.Context(), env, row.args); err != nil {
				t.Fatalf("--confirm of the plan: %v", err)
			}
			if len(fc.applied) != 1 {
				t.Fatalf("--confirm applied %d streams; want one", len(fc.applied))
			}
			got := mustCanonical(t, plan.Bound{Protocol: plan.Protocol, Facts: wantWrites(t, fc.applied[0])})
			if want := mustCanonical(t, plan.Bound{Protocol: plan.Protocol, Facts: planned}); got != want {
				t.Errorf("--confirm applied\n%s\nthe plan bound\n%s", got, want)
			}
		})
	}
}

// ADR 0023 M2.6 (A23-27, row 81b; M-M26A-MUT-04): a namespace a hand-edited
// record meters reaches the plan unchecked (the record's loader does not
// validate it), and the rendering prints it Go-quoted, never raw.
func TestKernelMeterPlanQuotesARecordedNamespace(t *testing.T) {
	const hostile = "a\x1b[2Kb\u202ec"
	dir := config.Dir(t.TempDir())
	meteredInstance(t, dir, "p42", tcdeploy.DefaultNamespace, hostile)
	env, out := testEnv(dir, output.ModeHuman)
	if err := withFlags(t, meterCmd(&fakeCluster{}), "--plan").Run(t.Context(), env, []string{"p42", "demo"}); err != nil {
		t.Fatalf("--plan: %v", err)
	}
	if strings.Contains(out.String(), "\x1b") || strings.Contains(out.String(), "\u202e") {
		t.Errorf("the plan prints a recorded namespace raw:\n%q", out)
	}
	if want := "metered afterwards: " + strconv.QuoteToGraphic(hostile); !strings.Contains(out.String(), want) {
		t.Errorf("the plan does not show the recorded namespace quoted, %q:\n%q", want, out)
	}
}

// S-R5-4: a record field that is not valid UTF-8, as a hand-edited
// metadata.yaml can hold one (a !!binary value), is refused by the plan, not
// written as U+FFFD: otherwise a plan made against one invalid byte would
// confirm against another. --plan prints nothing, and --confirm refuses
// before any digest is compared, opening nothing.
func TestKernelMeterPlanRefusesARecordThatIsNotUTF8(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteredInstance(t, dir, "p42", tcdeploy.DefaultNamespace)
	withReader(t, dir, "p42", "none")
	record := filepath.Join(dir.InstancePath("p42"), "metadata.yaml")
	b, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(b), "project: proj-test1\n", "project: !!binary cHJvai3/\n", 1)
	if edited == string(b) {
		t.Fatalf("the record names no project to edit:\n%s", b)
	}
	if err := os.WriteFile(record, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	if meta, err := dir.LoadInstanceMetadata("p42"); err != nil || meta.Project != "proj-\xff" {
		t.Fatalf("the edited record loads as %q (%v); want the bytes proj- and 0xff", meta.Project, err)
	}
	const want = "plan: bound.target.project is not valid UTF-8"
	for _, flags := range [][]string{{"--plan"}, {"--confirm", sampleDigest}} {
		opened := 0
		c := withFlags(t, &kernelMeterCommand{}, flags...)
		c.deployer.newCluster = func(clusterRef) (clusterApplier, error) {
			opened++
			return &fakeCluster{}, nil
		}
		env, out := testEnv(dir, output.ModeJSON)
		err := c.Run(t.Context(), env, []string{"p42", "demo"})
		if err == nil || err.Error() != want || kindOf(classified(err)) != kindInternal {
			t.Errorf("%q against a record that is not UTF-8 = %v; want %q", flags, err, want)
		}
		if out.Len() != 0 || opened != 0 {
			t.Errorf("%q printed %q and opened the writer %d times", flags, out, opened)
		}
	}
}

// day is a YYYY-MM-DD date as a time.
func day(s string) time.Time {
	t, err := time.Parse(time.DateOnly, s)
	if err != nil {
		panic(err)
	}
	return t
}
