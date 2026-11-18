package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	dsdeploy "github.com/sofmon/farcast/datasphere/deploy"
	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/fatline/policy"
	"github.com/sofmon/farcast/technocore/cost"
	"github.com/sofmon/farcast/technocore/deploy"
	"github.com/sofmon/farcast/technocore/kernel"
	tkube "github.com/sofmon/farcast/technocore/kube"
)

// P1 for interactive and --yes runs (ADR 0023 Choices 6; design §5.4, A23-2,
// A23-6, A23-48, A28-1 to A28-6, A28-12): the review's reset lines, the gate
// that keeps run --yes from deploying while the spending is at its limit,
// and the re-read after the builds. Every ledger here is written by the
// kernel's own ConfigMapStore.Save, never by hand.

// runClock is run's clock in these tests: the ledger's staleness is read
// against it (A28-2).
var runClock = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

// ledgerKey is where fakeRunCluster answers the kernel's ledger.
var ledgerKey = deploy.DefaultNamespace + "/" + kernel.DefaultCheckpointName + "/" + kernel.CheckpointKey()

// checkpointClient is the kernel's ConfigMapClient in memory: not found
// until saved, as the API server answers a first save.
type checkpointClient struct{ saved map[string]tkube.ConfigMap }

func (c *checkpointClient) GetConfigMap(_ context.Context, ns, name string) (*tkube.ConfigMap, error) {
	cm, ok := c.saved[ns+"/"+name]
	if !ok {
		return nil, fmt.Errorf("configmap %s/%s: %w", ns, name, tkube.ErrNotFound)
	}
	return &cm, nil
}

func (c *checkpointClient) SaveConfigMap(_ context.Context, ns string, cm tkube.ConfigMap) error {
	if c.saved == nil {
		c.saved = map[string]tkube.ConfigMap{}
	}
	c.saved[ns+"/"+cm.Metadata.Name] = cm
	return nil
}

// saveCheckpoint is cp as the kernel stores it: saved through its own
// ConfigMapStore, whatever cp holds, and read back as the value of the key
// run reads.
func saveCheckpoint(t *testing.T, cp kernel.Checkpoint) string {
	t.Helper()
	cl := &checkpointClient{}
	if err := kernel.NewConfigMapStore(cl).Save(context.Background(), cp); err != nil {
		t.Fatal(err)
	}
	cm, err := cl.GetConfigMap(context.Background(), deploy.DefaultNamespace, kernel.DefaultCheckpointName)
	if err != nil {
		t.Fatal(err)
	}
	return cm.Data[kernel.CheckpointKey()]
}

// validCheckpoint is a checkpoint the kernel would write: its ledger a
// cost.NewLedger snapshot (a zero one is unreadable, A28-4), observed at at
// at the given level, with its stops.
func validCheckpoint(t *testing.T, level string, at time.Time, stops ...kernel.Stop) kernel.Checkpoint {
	t.Helper()
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	ledger, err := cost.NewLedger(start, start.AddDate(0, 1, 0))
	if err != nil {
		t.Fatal(err)
	}
	return kernel.Checkpoint{
		Ledger:   ledger.Snapshot(),
		Last:     at,
		Observed: kernel.Observation{At: at, Level: level, Limit: 500},
		Stops:    stops,
	}
}

// savedCheckpoint is a valid checkpoint at level, observed at at, saved
// through the kernel's ConfigMapStore.
func savedCheckpoint(t *testing.T, level string, at time.Time, stops ...kernel.Stop) string {
	t.Helper()
	return saveCheckpoint(t, validCheckpoint(t, level, at, stops...))
}

// freshAt is a time the ledger was observed at that is not stale.
var freshAt = runClock.Add(-time.Minute)

// guardStop is the kernel's record of stopping ns/app to contain cost.
func guardStop(ns, app string) kernel.Stop {
	return kernel.Stop{Namespace: ns, Deployment: app, At: freshAt, Reason: kernel.StopReasonCostGuard, HourlyUSD: 0.01}
}

// withLedger answers the kernel's ledger with raw.
func withLedger(f *fakeRunCluster, raw string) {
	if f.configMaps == nil {
		f.configMaps = map[string]string{}
	}
	f.configMaps[ledgerKey] = raw
}

// liveApp is a Deployment of app as run reads it: replicas, and the requests of
// the container named after it.
func liveApp(app string, replicas int32, cpu, mem int64) cluster.DeploymentState {
	return cluster.DeploymentState{
		Present: true, Replicas: &replicas,
		Requests:      map[string]cluster.Requests{app: {CPUMilli: cpu, MemMiB: mem}},
		LastAppliedAt: runClock.Add(-time.Hour),
	}
}

// deployed puts the target namespace in the cluster, with these Deployments.
func deployed(f *fakeRunCluster, apps map[string]cluster.DeploymentState) {
	f.namespaces = append(f.namespaces, "kube-system", "my-platform")
	f.deployments = map[string]cluster.DeploymentState{}
	for app, st := range apps {
		f.deployments["my-platform/"+app] = st
	}
}

// p1Cmd is runCmd on run's test clock.
func p1Cmd(f *fakeRunCluster) *runCommand {
	c := runCmd(f)
	c.now = func() time.Time { return runClock }
	return c
}

var runArgs = []string{"p43", "github.com/example/my-platform"}

// p1Run runs c against a fresh runnable instance and returns its stderr and
// error.
func p1Run(t *testing.T, c *runCommand, in string) (string, error) {
	t.Helper()
	dir := config.Dir(t.TempDir())
	runnableInstance(t, dir, "p43")
	env, _, errb := testEnvBoth(dir, output.ModeHuman)
	if in != "" {
		env.In = &typed{lines: strings.SplitAfter(in, "\n")}
	}
	err := c.Run(context.Background(), env, runArgs)
	return errb.String(), err
}

// typed is stdin as a terminal in canonical mode delivers it: at most one
// line per read. Each question reads through a prompter of its own, so a
// reader that handed over every answer at once would leave the second
// question none.
type typed struct{ lines []string }

func (r *typed) Read(p []byte) (int, error) {
	for len(r.lines) > 0 && r.lines[0] == "" {
		r.lines = r.lines[1:]
	}
	if len(r.lines) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.lines[0])
	r.lines[0] = r.lines[0][n:]
	return n, nil
}

// interactively is c answering its questions from its stdin, as a terminal.
func interactively(c *runCommand) *runCommand {
	c.assumeYes = false
	c.interactive = func(*Env) bool { return true }
	return c
}

// gateText is the gate's refusal (A28-1) for my-platform at reason, with
// the restart clause and the ending.
func gateText(reason, restarts, ending string) string {
	if restarts != "" {
		restarts = ", and would restart " + restarts
	}
	return `run --yes would deploy "my-platform" while the instance's spending is at its limit (` + reason + `)` + restarts +
		`; confirm it interactively, or run the same command with --plan in place of --yes and confirm the plans it prints. ` + ending
}

// refusedByTheGate checks that err is exactly the gate's refusal, a usage
// error (exit 2, A28-12).
func refusedByTheGate(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("run --yes deployed; want the gate's refusal:\n%s", want)
	}
	if err.Error() != want {
		t.Errorf("refusal:\n got %s\nwant %s", err, want)
	}
	if code := exitCodeOf(err); code != 2 {
		t.Errorf("exit code %d, want 2 (a usage error)", code)
	}
}

// appliedAfterTheBuilds reports the egress policy and the workloads among
// what the run applied: what the re-read must keep from being written.
func appliedAfterTheBuilds(t *testing.T, f *fakeRunCluster) []string {
	t.Helper()
	var out []string
	for kind := range appliedKinds(t, f) {
		if kind == "ConfigMap/"+fldeploy.PolicyConfigMap || strings.HasPrefix(kind, "Deployment/") {
			out = append(out, kind)
		}
	}
	return out
}

// builds is the build Jobs the run applied.
func builds(t *testing.T, f *fakeRunCluster) []string {
	t.Helper()
	var out []string
	for kind := range appliedKinds(t, f) {
		if strings.HasPrefix(kind, "Job/build-") {
			out = append(out, kind)
		}
	}
	return out
}

// A28-1 (mutation 89e): at the limit, run --yes deploys nothing, even when
// every application is new. A build is a Job the kernel never stops, so a
// script that looped on run --yes would otherwise keep spending.
func TestYesNeverDeploysAtTheLimit(t *testing.T) {
	f := newFakeRun(twoAppManifest)
	withLedger(f, savedCheckpoint(t, cost.LevelReached.String(), freshAt))
	stderr, err := p1Run(t, p1Cmd(f), "")
	refusedByTheGate(t, err, gateText("limit reached", "", msgNothingBuilt))
	if b := builds(t, f); len(b) > 0 || builtAnything(t, f) {
		t.Errorf("built or deployed at the limit: %v", appliedKinds(t, f))
	}
	if len(f.stateReads) != 0 {
		t.Errorf("read Deployments %v in a namespace that does not exist", f.stateReads)
	}
	for _, want := range []string{"2 applications in", limitLine("limit reached")} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the review before the refusal never says %q:\n%s", want, stderr)
		}
	}
	if strings.Contains(stderr, "Approved with --yes") || strings.Contains(stderr, "Resets:") {
		t.Errorf("the review of new applications at the limit says too much:\n%s", stderr)
	}
}

// A28-1, A23-6 (mutant O09): a run with no terminal and no --yes keeps its
// refusal at the limit too, whatever stdin carries: it is never asked, and
// nothing is built.
func TestNoTerminalAtTheLimitKeepsItsRefusal(t *testing.T) {
	f := newFakeRun(twoAppManifest)
	withLedger(f, savedCheckpoint(t, cost.LevelReached.String(), freshAt))
	c := p1Cmd(f)
	c.assumeYes = false
	_, err := p1Run(t, c, "y\n")
	if err == nil || err.Error() != msgRunYes || exitCodeOf(err) != 2 {
		t.Fatalf("a run with no terminal at the limit = %v (exit %d); want %q", err, exitCodeOf(err), msgRunYes)
	}
	if builtAnything(t, f) {
		t.Errorf("built or deployed: %v", appliedKinds(t, f))
	}
}

// §5.4, A23-48, A28-5 (mutation 89 and "adapted before stopped"): an
// application at zero replicas is named in the review and in the refusal as
// what the deploy would restart, whoever stopped it; one the kernel adapted
// and then stopped is stopped, not adapted.
func TestYesNeverRestartsAStoppedAppAtTheLimit(t *testing.T) {
	adaptedThenStopped := liveApp("web", 0, 250, 512)
	adaptedThenStopped.AdaptedAt = runClock.Add(-10 * time.Minute)
	for _, row := range []struct {
		name   string
		web    cluster.DeploymentState
		stops  []kernel.Stop
		who    string
		review string
	}{
		{"stopped by the cost guard", liveApp("web", 0, 100, 128), []kernel.Stop{guardStop("my-platform", "web")},
			"stopped by the cost guard", "web: running 0 replicas (stopped by the cost guard); this deploy sets 1"},
		{"adapted, then stopped by the cost guard", adaptedThenStopped, []kernel.Stop{guardStop("my-platform", "web")},
			"stopped by the cost guard", "web: running 0 replicas (stopped by the cost guard); this deploy sets 1"},
		{"scaled to 0 by someone else", liveApp("web", 0, 100, 128), nil,
			"scaled to 0 replicas", "web: running 0 replicas (scaled to 0 replicas); this deploy sets 1"},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newFakeRun(twoAppManifest)
			withLedger(f, savedCheckpoint(t, cost.LevelReached.String(), freshAt, row.stops...))
			deployed(f, map[string]cluster.DeploymentState{"api": liveApp("api", 1, 100, 128), "web": row.web})
			stderr, err := p1Run(t, p1Cmd(f), "")
			refusedByTheGate(t, err, gateText("limit reached", "my-platform/web ("+row.who+")", msgNothingBuilt))
			if builtAnything(t, f) {
				t.Errorf("built or deployed: %v", appliedKinds(t, f))
			}
			if !strings.Contains(stderr, "Resets:\n  "+row.review+"\n") {
				t.Errorf("the review never says %q:\n%s", row.review, stderr)
			}
			if strings.Contains(stderr, "adapted by the kernel") || strings.Contains(stderr, "api:") {
				t.Errorf("the review names a reset that is not there:\n%s", stderr)
			}
		})
	}
}

// A23-2 (mutation 89a): the kernel acts between its ticks, and a build takes
// minutes, so the gate applies again after the builds, before the egress
// policy and the workloads are written: in both rows the review passed, and
// the re-read refuses.
func TestYesNeverRestartsAnAppStoppedDuringTheBuild(t *testing.T) {
	for _, row := range []struct {
		name      string
		atReview  cluster.DeploymentState
		reviewHas string
	}{
		{"stopped during the build", liveApp("web", 1, 100, 128), "Approved with --yes"},
		{"stopped at the review, the limit reached during the build", liveApp("web", 0, 100, 128),
			"web: running 0 replicas (scaled to 0 replicas); this deploy sets 1"},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newFakeRun(twoAppManifest)
			withLedger(f, savedCheckpoint(t, cost.LevelWarn90.String(), freshAt))
			deployed(f, map[string]cluster.DeploymentState{"api": liveApp("api", 1, 100, 128), "web": row.atReview})
			f.onBuild = func(string) {
				f.deployments["my-platform/web"] = liveApp("web", 0, 100, 128)
				withLedger(f, savedCheckpoint(t, cost.LevelReached.String(), freshAt, guardStop("my-platform", "web")))
			}
			stderr, err := p1Run(t, p1Cmd(f), "")
			for _, want := range []string{row.reviewHas, "Approved with --yes"} {
				if !strings.Contains(stderr, want) {
					t.Fatalf("the review at 90%% did not pass with %q:\n%s", want, stderr)
				}
			}
			refusedByTheGate(t, err, gateText("limit reached", "my-platform/web (stopped by the cost guard)", msgBuildsWritten))
			if b := builds(t, f); len(b) != 2 {
				t.Errorf("builds %v, want both written before the re-read", b)
			}
			if after := appliedAfterTheBuilds(t, f); len(after) > 0 {
				t.Errorf("written after the re-read refused: %v", after)
			}
		})
	}
}

// §5.4 (mutation 89b): the gate compares the kernel's own level string,
// cost.LevelReached.String(), with nothing written by hand: every level
// below it deploys, and it alone refuses.
func TestYesGateReadsTheKernelsOwnLevelString(t *testing.T) {
	for _, level := range []cost.Level{cost.LevelOK, cost.LevelWarn50, cost.LevelWarn75, cost.LevelWarn90, cost.LevelReached} {
		t.Run(level.String(), func(t *testing.T) {
			f := newFakeRun(twoAppManifest)
			withLedger(f, savedCheckpoint(t, level.String(), freshAt))
			stderr, err := p1Run(t, p1Cmd(f), "")
			if level == cost.LevelReached {
				refusedByTheGate(t, err, gateText("limit reached", "", msgNothingBuilt))
				return
			}
			if err != nil {
				t.Fatalf("at %s: %v", level, err)
			}
			if !strings.Contains(stderr, "Approved with --yes") || strings.Contains(stderr, "at its limit") {
				t.Errorf("at %s the review reads the limit reached:\n%s", level, stderr)
			}
			if len(appliedAfterTheBuilds(t, f)) == 0 {
				t.Errorf("at %s nothing was deployed", level)
			}
		})
	}
}

// A23-6 (mutation 89c): an application that cannot be read is listed as
// not read, and at the limit --yes deploys nothing over it: it may be one
// the cost guard stopped.
func TestYesNeverDeploysOverAnUnreadAppAtTheLimit(t *testing.T) {
	noContainer := liveApp("web", 1, 100, 128)
	noContainer.Requests = map[string]cluster.Requests{"sidecar": {CPUMilli: 100, MemMiB: 128}}
	noReplicas := liveApp("web", 1, 100, 128)
	noReplicas.Replicas = nil
	for _, row := range []struct {
		name string
		web  cluster.DeploymentState
		err  error
		kind string
	}{
		{"the read failed", cluster.DeploymentState{}, fmt.Errorf("deployment my-platform/web: %w", kube.ErrUnreachable), kindClusterUnreachable},
		{"the writer was refused", cluster.DeploymentState{}, fmt.Errorf("deployment my-platform/web: %w", tkube.ErrForbidden), kindForbidden},
		{"a request it cannot read", cluster.DeploymentState{}, fmt.Errorf("deployment my-platform/web: %w", kube.ErrUnreadable), kindDocumentUnreadable},
		{"no container named after it", noContainer, nil, kindDocumentUnreadable},
		{"no replica count", noReplicas, nil, kindDocumentUnreadable},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newFakeRun(twoAppManifest)
			withLedger(f, savedCheckpoint(t, cost.LevelReached.String(), freshAt))
			deployed(f, map[string]cluster.DeploymentState{"api": liveApp("api", 1, 100, 128), "web": row.web})
			if row.err != nil {
				f.deployErrs = map[string]error{"my-platform/web": row.err}
			}
			stderr, err := p1Run(t, p1Cmd(f), "")
			refusedByTheGate(t, err, gateText("limit reached", "my-platform/web (not read)", msgNothingBuilt))
			if builtAnything(t, f) {
				t.Errorf("built or deployed: %v", appliedKinds(t, f))
			}
			want := "web: its live state could not be read (" + row.kind + "); what this deploy changes there is not known"
			if !strings.Contains(stderr, want) {
				t.Errorf("the review never says %q:\n%s", want, stderr)
			}
		})
	}
}

// A23-48 (mutation 89d): the review says the cost guard stopped an
// application only when the kernel's ledger records the cost guard stopping
// that very application, in that namespace, and it is still at zero.
// Otherwise it says the application is scaled to 0. It also says what the
// deploy does to one the kernel adapted.
func TestRunReviewSaysWhoStoppedAnApp(t *testing.T) {
	adapted := liveApp("web", 1, 250, 512)
	adapted.AdaptedAt = runClock.Add(-10 * time.Minute)
	appliedSince := liveApp("web", 1, 250, 512)
	appliedSince.AdaptedAt = runClock.Add(-2 * time.Hour)
	for _, row := range []struct {
		name   string
		ledger bool
		web    cluster.DeploymentState
		stops  []kernel.Stop
		want   string
	}{
		{"the cost guard stopped it", true, liveApp("web", 0, 100, 128), []kernel.Stop{guardStop("my-platform", "web")},
			"web: running 0 replicas (stopped by the cost guard); this deploy sets 1"},
		{"no stop is recorded", true, liveApp("web", 0, 100, 128), nil,
			"web: running 0 replicas (scaled to 0 replicas); this deploy sets 1"},
		{"the cost guard stopped another namespace's web", true, liveApp("web", 0, 100, 128), []kernel.Stop{guardStop("other", "web")},
			"web: running 0 replicas (scaled to 0 replicas); this deploy sets 1"},
		{"a stop for another reason", true, liveApp("web", 0, 100, 128),
			[]kernel.Stop{{Namespace: "my-platform", Deployment: "web", At: freshAt, Reason: "operator"}},
			"web: running 0 replicas (scaled to 0 replicas); this deploy sets 1"},
		{"no ledger to say who", false, liveApp("web", 0, 100, 128), nil,
			"web: running 0 replicas (scaled to 0 replicas); this deploy sets 1"},
		{"the kernel adapted it", true, adapted, nil,
			"web: requests 250m/512Mi (adapted by the kernel at 2026-11-17T11:50:00Z); this deploy renders 100m/128Mi, " +
				"which Autopilot raises to its 250m/512Mi floor on a cluster without bursting, until the kernel adapts it again"},
		{"running again since the cost guard stopped it", true, liveApp("web", 1, 100, 128), []kernel.Stop{guardStop("my-platform", "web")}, ""},
		{"applied since the kernel adapted it", true, appliedSince, nil, ""},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newFakeRun(twoAppManifest)
			if row.ledger {
				withLedger(f, savedCheckpoint(t, cost.LevelWarn90.String(), freshAt, row.stops...))
			}
			deployed(f, map[string]cluster.DeploymentState{"api": liveApp("api", 1, 100, 128), "web": row.web})
			stderr, err := p1Run(t, p1Cmd(f), "")
			if err != nil {
				t.Fatalf("below the limit the run refused: %v", err)
			}
			if row.want == "" {
				if strings.Contains(stderr, "Resets:") {
					t.Errorf("the review names a reset that is not there:\n%s", stderr)
				}
				return
			}
			if !strings.Contains(stderr, "Resets:\n  "+row.want+"\n") {
				t.Errorf("the review never says %q:\n%s", row.want, stderr)
			}
			if strings.Count(stderr, "Resets:") != 1 || strings.Contains(stderr, "api:") {
				t.Errorf("the review names more than web's reset:\n%s", stderr)
			}
		})
	}
}

// A28-2 (mutation 89g): a ledger whose kernel last looked more than fifteen
// minutes before run's clock, or never, is stale, and reads as at the limit:
// a kernel that stopped reporting no longer guards the spending. World's
// rule: the observation's time, or the last accrual's when it has none.
func TestYesGateCountsAStaleLedgerAsReached(t *testing.T) {
	for _, row := range []struct {
		name     string
		observed time.Time
		last     time.Time
		stale    bool
	}{
		{"saved 16 minutes ago", runClock.Add(-16 * time.Minute), runClock.Add(-16 * time.Minute), true},
		{"saved 14 minutes ago", runClock.Add(-14 * time.Minute), runClock.Add(-14 * time.Minute), false},
		{"no observation, an accrual 16 minutes ago", time.Time{}, runClock.Add(-16 * time.Minute), true},
		{"no observation, an accrual 14 minutes ago", time.Time{}, runClock.Add(-14 * time.Minute), false},
		{"neither", time.Time{}, time.Time{}, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			cp := validCheckpoint(t, cost.LevelWarn90.String(), row.observed)
			cp.Last = row.last
			f := newFakeRun(twoAppManifest)
			withLedger(f, saveCheckpoint(t, cp))
			stderr, err := p1Run(t, p1Cmd(f), "")
			if row.stale {
				refusedByTheGate(t, err, gateText("ledger stale", "", msgNothingBuilt))
				return
			}
			if err != nil || !strings.Contains(stderr, "Approved with --yes") {
				t.Errorf("a ledger %s did not pass the review: %v\n%s", row.name, err, stderr)
			}
		})
	}
}

// run's usage states A28-2's rule as the gate applies it: by when the kernel
// last looked, or never, and not by when the ledger was last written, which
// can be later than the observation it carries.
func TestRunUsageStatesTheStalenessRule(t *testing.T) {
	usage := strings.Join(strings.Fields((&runCommand{}).Usage()), " ")
	if !strings.Contains(usage, "says the kernel last looked more than 15 minutes ago or never") || strings.Contains(usage, "last written") {
		t.Errorf("run's usage does not state the staleness rule by the kernel's last look:\n%s", usage)
	}
}

// A28-4: the ledger rule. Absent is only not found with no error; anything
// else that is not a checkpoint this build reads is unreadable and reads as
// at the limit, and so does a level the kernel does not write.
func TestTheLedgerRuleFailsClosed(t *testing.T) {
	forbidden := fmt.Errorf("read: %w", &kube.APIError{Method: "GET", Path: "/api/v1/namespaces/farcast-system/configmaps/technocore-ledger",
		Status: kube.Status{Status: tkube.Status{Code: http.StatusForbidden}}, KubernetesStatus: true})
	notTheServers := fmt.Errorf("read: %w", &kube.APIError{Method: "GET", Path: "/api/v1/namespaces/farcast-system/configmaps/technocore-ledger",
		Status: kube.Status{Status: tkube.Status{Code: http.StatusNotFound}}})
	version9 := func(t *testing.T) string {
		var doc map[string]any
		if err := json.Unmarshal([]byte(savedCheckpoint(t, cost.LevelWarn90.String(), freshAt)), &doc); err != nil {
			t.Fatal(err)
		}
		doc["version"] = 9
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	zeroLedger := func(t *testing.T) string {
		return saveCheckpoint(t, kernel.Checkpoint{Last: freshAt, Observed: kernel.Observation{At: freshAt, Level: cost.LevelWarn90.String()}})
	}
	level := func(l string) func(*testing.T) string {
		return func(t *testing.T) string { return savedCheckpoint(t, l, freshAt) }
	}
	for _, row := range []struct {
		name   string
		raw    func(*testing.T) string
		fail   *cmFailure
		reason string // "" deploys
	}{
		{"absent", nil, nil, ""},
		{"fresh, at 90%", level(cost.LevelWarn90.String()), nil, ""},
		{"a 403", nil, &cmFailure{found: false, err: forbidden}, limitReasonUnreadable},
		{"a 404 that is not the API server's", nil, &cmFailure{found: false, err: notTheServers}, limitReasonUnreadable},
		{"the key missing", nil, &cmFailure{found: true, err: errors.New(`configmap farcast-system/technocore-ledger has no key "checkpoint.json"`)}, limitReasonUnreadable},
		{"an empty value", func(*testing.T) string { return " \n" }, nil, limitReasonUnreadable},
		{"not a checkpoint", func(*testing.T) string { return "{" }, nil, limitReasonUnreadable},
		{"version 9", version9, nil, limitReasonUnreadable},
		{"a zero ledger", zeroLedger, nil, limitReasonUnreadable},
		{"an unknown level", level("eleventy percent"), nil, limitReasonUnknown},
		{"no level", level(""), nil, limitReasonUnknown},
		{"stale", func(t *testing.T) string {
			return savedCheckpoint(t, cost.LevelWarn90.String(), runClock.Add(-16*time.Minute))
		}, nil, limitReasonStale},
		{"the limit reached", level(cost.LevelReached.String()), nil, limitReasonReached},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newFakeRun(twoAppManifest)
			if row.raw != nil {
				withLedger(f, row.raw(t))
			}
			if row.fail != nil {
				f.cmErrs = map[string]cmFailure{ledgerKey: *row.fail}
			}
			stderr, err := p1Run(t, p1Cmd(f), "")
			if row.reason != "" {
				refusedByTheGate(t, err, gateText(row.reason, "", msgNothingBuilt))
				return
			}
			if err != nil || !strings.Contains(stderr, "Approved with --yes") {
				t.Errorf("a ledger %s did not pass the review: %v\n%s", row.name, err, stderr)
			}
		})
	}
}

// A28-1, A23-48: an interactive run at the limit is told what this deploy
// may restart, each application in its own words, and asked as before.
func TestAnInteractiveRunAtTheLimitSaysWhatItMayRestart(t *testing.T) {
	for _, row := range []struct {
		name  string
		stops []kernel.Stop
		web   string
	}{
		{"stopped by the cost guard", []kernel.Stop{guardStop("my-platform", "web")},
			"the cost guard stopped my-platform/web at the limit; deploying restarts it, and it bills until the kernel's next tick stops it again"},
		{"scaled to 0", nil,
			"my-platform/web is scaled to 0 replicas while the instance's spending is at its limit; deploying restarts it, and the kernel may stop it again at its next tick"},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newFakeRun(twoAppManifest)
			withLedger(f, savedCheckpoint(t, cost.LevelReached.String(), freshAt, row.stops...))
			deployed(f, map[string]cluster.DeploymentState{"web": liveApp("web", 0, 100, 128)})
			f.deployErrs = map[string]error{"my-platform/api": fmt.Errorf("deployment my-platform/api: %w", kube.ErrUnreachable)}
			stderr, err := p1Run(t, interactively(p1Cmd(f)), "n\n")
			if err != nil {
				t.Fatal(err)
			}
			api := "my-platform/api could not be read while the instance's spending is at its limit; if the cost guard stopped it, deploying restarts it"
			order := []string{limitLine("limit reached"), api, row.web, `Deploy "my-platform"? [y/N]`, "Aborted. Nothing was built and nothing was deployed."}
			at := 0
			for _, want := range order {
				i := strings.Index(stderr[at:], want)
				if i < 0 {
					t.Fatalf("stderr does not say %q after what came before it:\n%s", want, stderr)
				}
				at += i + len(want)
			}
			if builtAnything(t, f) {
				t.Errorf("a declined run built or deployed: %v", appliedKinds(t, f))
			}
		})
	}
}

// A28-1, A23-48 (and mutant O11): an interactive run is asked again after
// the builds when the limit was reached since the review, or an application
// it may restart — stopped, or one it can no longer read — was not one at
// the review; a decline then leaves only the builds written. Nothing new is
// not asked about twice.
func TestAnInteractiveRunIsAskedAgainAfterTheBuilds(t *testing.T) {
	webLine := "the cost guard stopped my-platform/web at the limit; deploying restarts it, and it bills until the kernel's next tick stops it again"
	apiLine := "the cost guard stopped my-platform/api at the limit; deploying restarts it, and it bills until the kernel's next tick stops it again"
	apiUnread := "my-platform/api could not be read while the instance's spending is at its limit; if the cost guard stopped it, deploying restarts it"
	for _, row := range []struct {
		name string
		// atReview is the ledger's level at the review, and web's replicas.
		atReview    string
		webReplicas int32
		// during is what the kernel does while the builds run.
		during func(t *testing.T, f *fakeRunCluster)
		in     string
		asked  int
		says   []string
		silent []string
		deploy bool
	}{
		{"the limit reached during the build, declined", cost.LevelWarn90.String(), 1, func(t *testing.T, f *fakeRunCluster) {
			f.deployments["my-platform/web"] = liveApp("web", 0, 100, 128)
			withLedger(f, savedCheckpoint(t, cost.LevelReached.String(), freshAt, guardStop("my-platform", "web")))
		}, "y\nn\n", 2, []string{limitLine("limit reached"), webLine, "Aborted. " + msgBuildsWritten}, []string{apiLine}, false},
		{"the limit reached during the build, approved again", cost.LevelWarn90.String(), 1, func(t *testing.T, f *fakeRunCluster) {
			f.deployments["my-platform/web"] = liveApp("web", 0, 100, 128)
			withLedger(f, savedCheckpoint(t, cost.LevelReached.String(), freshAt, guardStop("my-platform", "web")))
		}, "y\ny\n", 2, []string{limitLine("limit reached"), webLine}, nil, true},
		{"the limit reached during the build, nothing stopped", cost.LevelWarn90.String(), 1, func(t *testing.T, f *fakeRunCluster) {
			withLedger(f, savedCheckpoint(t, cost.LevelReached.String(), freshAt))
		}, "y\nn\n", 2, []string{limitLine("limit reached"), "Aborted. " + msgBuildsWritten}, []string{webLine}, false},
		{"another application stopped during the build", cost.LevelReached.String(), 0, func(t *testing.T, f *fakeRunCluster) {
			f.deployments["my-platform/api"] = liveApp("api", 0, 100, 128)
			withLedger(f, savedCheckpoint(t, cost.LevelReached.String(), freshAt, guardStop("my-platform", "web"), guardStop("my-platform", "api")))
		}, "y\nn\n", 2, []string{apiLine, "Aborted. " + msgBuildsWritten}, []string{webLine, limitLine("limit reached")}, false},
		{"another application unreadable after the build", cost.LevelReached.String(), 0, func(t *testing.T, f *fakeRunCluster) {
			f.deployErrs = map[string]error{"my-platform/api": fmt.Errorf("deployment my-platform/api: %w", kube.ErrUnreachable)}
		}, "y\nn\n", 2, []string{apiUnread, "Aborted. " + msgBuildsWritten}, []string{webLine, limitLine("limit reached")}, false},
		{"nothing new at the limit", cost.LevelReached.String(), 0, func(*testing.T, *fakeRunCluster) {}, "y\n", 1, nil, nil, true},
		{"below the limit after the builds", cost.LevelWarn90.String(), 1, func(t *testing.T, f *fakeRunCluster) {
			f.deployments["my-platform/web"] = liveApp("web", 0, 100, 128)
		}, "y\n", 1, nil, nil, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newFakeRun(twoAppManifest)
			withLedger(f, savedCheckpoint(t, row.atReview, freshAt, guardStop("my-platform", "web")))
			deployed(f, map[string]cluster.DeploymentState{"api": liveApp("api", 1, 100, 128), "web": liveApp("web", row.webReplicas, 100, 128)})
			f.onBuild = func(string) { row.during(t, f) }
			stderr, err := p1Run(t, interactively(p1Cmd(f)), row.in)
			if err != nil {
				t.Fatalf("%v\n%s", err, stderr)
			}
			if n := strings.Count(stderr, `Deploy "my-platform"? [y/N]`); n != row.asked {
				t.Errorf("asked %d times, want %d:\n%s", n, row.asked, stderr)
			}
			// What it says after the review's question is what the re-read
			// says.
			question := `Deploy "my-platform"? [y/N]`
			afterBuilds := stderr[strings.Index(stderr, question)+len(question):]
			for _, want := range row.says {
				if !strings.Contains(afterBuilds, want) {
					t.Errorf("after the builds, never says %q:\n%s", want, stderr)
				}
			}
			for _, not := range row.silent {
				if strings.Contains(afterBuilds, not) {
					t.Errorf("after the builds, says %q, which is not new:\n%s", not, stderr)
				}
			}
			if b := builds(t, f); len(b) != 2 {
				t.Errorf("builds %v, want both", b)
			}
			if after := appliedAfterTheBuilds(t, f); (len(after) > 0) != row.deploy {
				t.Errorf("written after the builds: %v; want deployed %v", after, row.deploy)
			}
		})
	}
}

// A28-1, A23-48 (mutant O51): at the limit an interactive run names only
// what the deploy may restart. A running application gets no at-the-limit
// line, which would tell the operator it is at 0 replicas.
func TestAnInteractiveRunAtTheLimitNamesOnlyWhatItMayRestart(t *testing.T) {
	f := newFakeRun(twoAppManifest)
	withLedger(f, savedCheckpoint(t, cost.LevelReached.String(), freshAt, guardStop("my-platform", "web")))
	deployed(f, map[string]cluster.DeploymentState{"api": liveApp("api", 1, 100, 128), "web": liveApp("web", 0, 100, 128)})
	stderr, err := p1Run(t, interactively(p1Cmd(f)), "n\n")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stderr, "my-platform/api") {
		t.Errorf("the review names the running api as one the deploy restarts:\n%s", stderr)
	}
	if !strings.Contains(stderr, "the cost guard stopped my-platform/web at the limit") {
		t.Errorf("the review never names web:\n%s", stderr)
	}
}

// A23-2, A28-10 (mutant O31): only --confirm compares the egress policy's
// resourceVersion with its plan's. An interactive or --yes run merges a
// policy another run wrote while it built, as it always has, and keeps both
// runs' applications.
func TestAYesRunMergesAPolicyWrittenDuringTheBuilds(t *testing.T) {
	f := newFakeRun(twoAppManifest)
	f.onBuild = once(func() {
		other := &policy.Document{Version: policy.Version, Apps: []policy.App{{Name: "worker", Namespace: "other", CredentialSHA256: policy.HashCredential("theirs")}}}
		body, err := other.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if f.configMaps == nil {
			f.configMaps = map[string]string{}
		}
		f.configMaps[fldeploy.DefaultNamespace+"/"+fldeploy.PolicyConfigMap+"/"+fldeploy.PolicyKey] = string(body)
		f.rvs = map[string]string{fldeploy.DefaultNamespace + "/" + fldeploy.PolicyConfigMap: "7"}
	})
	stderr, err := p1Run(t, p1Cmd(f), "")
	if err != nil {
		t.Fatalf("a --yes run whose policy another run wrote during the builds = %v\n%s", err, stderr)
	}
	written := ""
	for _, s := range f.applied {
		if _, ok := docsIn(t, s)["ConfigMap/"+fldeploy.PolicyConfigMap]; ok {
			written = s
		}
	}
	if !strings.Contains(written, "worker") || !strings.Contains(written, "my-platform") {
		t.Errorf("the policy written is not the merge of both runs':\n%s", written)
	}
}

// A28-8, A23-18 (mutant O47): an interactive or --yes run reads no key pin
// in its deploy plan: it raises the pin with its loop at the hand-over, so a
// pin that cannot be read refuses nothing before the builds.
func TestAYesRunReadsNoPinInItsPlan(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meta := runnableInstance(t, dir, "p43")
	meta.Keyholder = &config.Keyholder{Deployed: true}
	if err := dir.SaveInstanceMetadata("p43", meta); err != nil {
		t.Fatal(err)
	}
	mintKeyring(t, dir, "p43")
	env, _, errb := testEnvBoth(dir, output.ModeHuman)
	f := newFakeRun(twoAppManifest)
	f.dataErrs = map[string]error{dsdeploy.DefaultNamespace + "/" + dsdeploy.PinConfigMapName(""): errors.New("the pin cannot be read")}
	c := runCmd(f)
	c.now = func() time.Time { return runClock }
	if err := c.Run(context.Background(), env, runArgs); err != nil {
		t.Fatalf("a --yes run with an unreadable pin = %v\n%s", err, errb)
	}
	if got := appliedAfterTheBuilds(t, f); len(got) == 0 {
		t.Error("deployed nothing")
	}
}

// A28-6: a namespace list that fails is never read as the target namespace
// being absent, which would read every application as new and open the
// gate: the run stops, at the review with nothing built, and at the re-read
// with only the builds written.
func TestRunNeverReadsAFailedNamespaceListAsAbsent(t *testing.T) {
	failed := fmt.Errorf("list namespaces: %w", kube.ErrUnreachable)
	t.Run("at the review", func(t *testing.T) {
		f := newFakeRun(twoAppManifest)
		f.nsErr = failed
		_, err := p1Run(t, p1Cmd(f), "")
		if err == nil || !errors.Is(err, kube.ErrUnreachable) ||
			!strings.HasSuffix(err.Error(), "; the manifest was read, and nothing was built or deployed") {
			t.Fatalf("err = %v, want the namespace list's failure", err)
		}
		if builtAnything(t, f) || len(f.stateReads) > 0 {
			t.Errorf("went on after the namespace list failed: built %v, read %v", appliedKinds(t, f), f.stateReads)
		}
	})
	t.Run("at the re-read", func(t *testing.T) {
		f := newFakeRun(twoAppManifest)
		deployed(f, map[string]cluster.DeploymentState{"web": liveApp("web", 1, 100, 128)})
		f.onBuild = func(string) { f.nsErr = failed }
		_, err := p1Run(t, p1Cmd(f), "")
		if err == nil || !errors.Is(err, kube.ErrUnreachable) ||
			!strings.HasSuffix(err.Error(), "; the builds were written, and nothing after them was") {
			t.Fatalf("err = %v, want the namespace list's failure", err)
		}
		if after := appliedAfterTheBuilds(t, f); len(after) > 0 {
			t.Errorf("written after the re-read failed: %v", after)
		}
	})
}

// A28-6: an application's failed read is unknown, with its kind, in an
// interactive or --yes run, whose reads are the writer's; under --plan or
// --confirm a reader's 403 is the plan's read error, once, as the reader's.
func TestAnAppsFailedReadIsUnknownExceptAPlansRefusal(t *testing.T) {
	m, err := parseTestManifest(twoAppManifest)
	if err != nil {
		t.Fatal(err)
	}
	refused := fmt.Errorf("deployment my-platform/web: %w", &kube.APIError{Method: "GET", Path: "/apis/apps/v1/namespaces/my-platform/deployments/web",
		Status: kube.Status{Status: tkube.Status{Code: http.StatusForbidden}}, KubernetesStatus: true})
	f := newFakeRun(twoAppManifest)
	deployed(f, map[string]cluster.DeploymentState{"api": liveApp("api", 1, 100, 128)})
	f.deployErrs = map[string]error{"my-platform/web": refused}

	apps, err := readApps(context.Background(), f, "my-platform", *m, limitState{}, consentNone, "p43")
	if err != nil {
		t.Fatal(err)
	}
	if apps[0].state() != "" || apps[1].state() != plan.ResetUnknown || apps[1].kind() != kindForbidden || !apps[1].restarts() {
		t.Errorf("states %q (%v) and %q (%v), want no reset and unknown (forbidden)", apps[0].state(), apps[0].Err, apps[1].state(), apps[1].Err)
	}
	for _, mode := range []consentMode{consentPlan, consentConfirm} {
		_, err := readApps(context.Background(), f, "my-platform", *m, limitState{}, mode, "p43")
		var reader *readerPhaseError
		if !errors.As(err, &reader) || !errors.Is(err, tkube.ErrForbidden) ||
			strings.Count(err.Error(), "run 'farcast reader grant p43'") != 1 {
			t.Errorf("mode %d: err = %v, want the reader's 403, its remedy once", mode, err)
		}
	}
}

// A28-5: an application's state, in precedence order (unknown, then
// stopped, adapted or not, then adapted), and what the gate keys on, which
// is never the state word: zero replicas, or a read that failed. The cost
// guard stopped an application only while it is still at zero.
func TestAnApplicationsStateTakesItsPrecedence(t *testing.T) {
	stops := limitState{costStops: map[string]bool{"my-platform/web": true}}
	adapted := liveApp("web", 1, 250, 512)
	adapted.AdaptedAt = runClock.Add(-time.Minute)
	adaptedThenStopped := liveApp("web", 0, 250, 512)
	adaptedThenStopped.AdaptedAt = runClock.Add(-time.Minute)
	for _, row := range []struct {
		name     string
		st       cluster.DeploymentState
		err      error
		state    string
		restarts bool
		guard    bool
	}{
		{"absent", cluster.DeploymentState{}, nil, "", false, false},
		{"running as rendered", liveApp("web", 1, 100, 128), nil, "", false, false},
		{"running again since the cost guard stopped it", liveApp("web", 2, 100, 128), nil, "", false, false},
		{"stopped", liveApp("web", 0, 100, 128), nil, plan.ResetStopped, true, true},
		{"adapted", adapted, nil, plan.ResetAdapted, false, false},
		{"adapted, then stopped", adaptedThenStopped, nil, plan.ResetStopped, true, true},
		{"unknown", cluster.DeploymentState{}, fmt.Errorf("x: %w", kube.ErrUnreachable), plan.ResetUnknown, true, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			a := classifyApp("my-platform", "web", row.st, row.err, stops)
			if a.state() != row.state || a.restarts() != row.restarts || a.StoppedByCostGuard != row.guard {
				t.Errorf("state %q, restarts %v, stopped by the cost guard %v; want %q, %v, %v",
					a.state(), a.restarts(), a.StoppedByCostGuard, row.state, row.restarts, row.guard)
			}
		})
	}
}
