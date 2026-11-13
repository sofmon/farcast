package cli

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/technocore/cost"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
	"github.com/sofmon/farcast/technocore/kernel"
)

// checkpointFor builds a real kernel checkpoint, so this test cannot drift
// from what the kernel actually writes.
func checkpointFor(t *testing.T, limit, rate float64, byApp map[string]float64, confirmed *cost.Confirmation) string {
	t.Helper()
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	ledger, err := cost.NewLedger(start, end)
	if err != nil {
		t.Fatal(err)
	}
	at := start.Add(48 * time.Hour)
	for app, usd := range byApp {
		ledger.Accrue(at, app, usd, time.Hour)
	}
	if confirmed != nil {
		if _, err := ledger.Confirm(*confirmed); err != nil {
			t.Fatal(err)
		}
	}
	cp := kernel.Checkpoint{
		Version: kernel.CheckpointVersion,
		Ledger:  ledger.Snapshot(),
		Last:    at,
		Observed: kernel.Observation{
			At: at, Pods: 6, RateHourlyUSD: rate, Level: "ok", Limit: limit,
		},
	}
	raw, err := json.Marshal(cp)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func costsReader(t *testing.T, body string) *fakeReader {
	t.Helper()
	return &fakeReader{configMaps: map[string]string{
		tcdeploy.DefaultNamespace + "/" + kernel.DefaultCheckpointName + "/" + kernel.CheckpointKey(): body,
	}}
}

func TestCostsReportsBothFiguresAndTheDistanceToTheLimit(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p43")
	env, out := testEnv(dir, output.ModeHuman)

	f := costsReader(t, checkpointFor(t, 100, 0.0304, map[string]float64{"api": 20, "web": 10}, nil))
	c := &costsCommand{}
	c.newCluster = func(string) configMapReader { return f }
	if err := c.Run(context.Background(), env, []string{"p43"}); err != nil {
		t.Fatal(err)
	}
	shown := out.String()
	for _, want := range []string{"expected", "confirmed", "total", "limit", "api", "web", "0.0304", "6 pods"} {
		if !strings.Contains(shown, want) {
			t.Errorf("costs does not report %q:\n%s", want, shown)
		}
	}
	// The one thing a missing feed must never look like.
	if strings.Contains(shown, "confirmed  USD     0.00") {
		t.Errorf("an unconfirmed period is shown as a confirmed zero:\n%s", shown)
	}
	if !strings.Contains(shown, "confirmed nothing yet") {
		t.Errorf("the absence of a confirmation is not stated:\n%s", shown)
	}
}

// Attribution can only ever come from the local model: the provider bills the
// instance, not the applications in it.
func TestCostsSaysAttributionIsLocalOnly(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p43")
	env, out := testEnv(dir, output.ModeHuman)

	f := costsReader(t, checkpointFor(t, 100, 0.03, map[string]float64{"api": 20}, nil))
	c := &costsCommand{}
	c.newCluster = func(string) configMapReader { return f }
	if err := c.Run(context.Background(), env, []string{"p43"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "expected") || !strings.Contains(out.String(), "bills the instance") {
		t.Errorf("the per-app breakdown does not say which figure it comes from:\n%s", out.String())
	}
}

// The kernel enforces the limit it was deployed with. When local state says
// something else, the cluster is still acting on its own — and a report that
// showed the local figure would describe an enforcement that is not happening.
func TestCostsAssessesAgainstTheLimitTheKernelHolds(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p43") // records 100
	env, out := testEnv(dir, output.ModeHuman)

	f := costsReader(t, checkpointFor(t, 40, 0.03, map[string]float64{"api": 30}, nil))
	c := &costsCommand{}
	c.newCluster = func(string) configMapReader { return f }
	if err := c.Run(context.Background(), env, []string{"p43"}); err != nil {
		t.Fatal(err)
	}
	shown := out.String()
	if !strings.Contains(shown, "enforcing USD 40.00") {
		t.Errorf("the divergence between the enforced and recorded limits is not reported:\n%s", shown)
	}
	if !strings.Contains(shown, "75%") {
		t.Errorf("the assessment used the recorded limit rather than the enforced one:\n%s", shown)
	}
}

func TestCostsWithoutACheckpointSaysSo(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p43")
	env, _ := testEnv(dir, output.ModeHuman)

	f := costsReader(t, "")
	f.cmMissing = true
	c := &costsCommand{}
	c.newCluster = func(string) configMapReader { return f }
	err := c.Run(context.Background(), env, []string{"p43"})
	if err == nil || !strings.Contains(err.Error(), "not checkpointed") {
		t.Fatalf("a kernel that has not checkpointed was not reported clearly: %v", err)
	}
}

func TestCostsWithoutAKernelRefuses(t *testing.T) {
	dir := config.Dir(t.TempDir())
	buildableInstance(t, dir, "p43")
	env, _ := testEnv(dir, output.ModeHuman)

	c := &costsCommand{}
	c.newCluster = func(string) configMapReader { return costsReader(t, "") }
	err := c.Run(context.Background(), env, []string{"p43"})
	if err == nil || !strings.Contains(err.Error(), "kernel deploy") {
		t.Fatalf("costs without a kernel did not say what to do: %v", err)
	}
}

// overheadCheckpoint is checkpointFor with a carrier on the ledger and in the
// observation, in the state the kernel last saw it.
func overheadCheckpoint(t *testing.T, byApp map[string]float64, carrierUSD float64, state kernel.CarrierState) string {
	t.Helper()
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	ledger, err := cost.NewLedger(start, start.AddDate(0, 1, 0))
	if err != nil {
		t.Fatal(err)
	}
	at := start.Add(48 * time.Hour)
	for app, usd := range byApp {
		ledger.Accrue(at, app, usd, time.Hour)
	}
	ledger.AccrueOverhead(at, kernel.OverheadCarrier, carrierUSD, time.Hour)
	raw, err := json.Marshal(kernel.Checkpoint{
		Version: kernel.CheckpointVersion,
		Ledger:  ledger.Snapshot(),
		Last:    at,
		Observed: kernel.Observation{
			At: at, Pods: 6, RateHourlyUSD: 0.06, Overhead: 0.025, Carrier: string(state),
			Level: "ok", Limit: 100,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func runCosts(t *testing.T, body string, mode output.Mode) string {
	t.Helper()
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p43")
	env, out := testEnv(dir, mode)
	f := costsReader(t, body)
	c := &costsCommand{}
	c.newCluster = func(string) configMapReader { return f }
	if err := c.Run(context.Background(), env, []string{"p43"}); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

// The carrier counts against the limit but belongs to no application: shown
// inside the breakdown it would read as something stopping an app removes.
func TestCostsShowsOverheadOutsideTheAppBreakdown(t *testing.T) {
	shown := runCosts(t, overheadCheckpoint(t, map[string]float64{"api": 20}, 7, kernel.CarrierLoadBalancer), output.ModeHuman)

	apps, rest, ok := strings.Cut(shown, "By application:")
	if !ok {
		t.Fatalf("no application breakdown:\n%s", shown)
	}
	byApp, overhead, ok := strings.Cut(rest, "Instance overhead")
	if !ok {
		t.Fatalf("no overhead section:\n%s", shown)
	}
	if strings.Contains(byApp, "carrier") {
		t.Errorf("the carrier is listed as an application:\n%s", byApp)
	}
	if !strings.Contains(overhead, "carrier") || !strings.Contains(overhead, "7.00") {
		t.Errorf("the overhead section does not show the carrier's 7.00:\n%s", overhead)
	}
	if !strings.Contains(apps, "27.00") {
		t.Errorf("expected does not include the carrier (want 27.00):\n%s", apps)
	}
	if !strings.Contains(shown, "and the carrier") {
		t.Errorf("the rate line does not say it includes the carrier:\n%s", shown)
	}
	if strings.Contains(shown, "billing it as present") {
		t.Errorf("an observed carrier is reported as unobserved:\n%s", shown)
	}

	js := runCosts(t, overheadCheckpoint(t, map[string]float64{"api": 20}, 7, kernel.CarrierLoadBalancer), output.ModeJSON)
	var res struct {
		Apps     []appCost `json:"apps"`
		Overhead []appCost `json:"overhead"`
	}
	if err := json.Unmarshal([]byte(js), &res); err != nil {
		t.Fatalf("%v:\n%s", err, js)
	}
	if len(res.Apps) != 1 || res.Apps[0].Name != "api" {
		t.Errorf("apps = %+v, want api alone", res.Apps)
	}
	if len(res.Overhead) != 1 || res.Overhead[0].Name != kernel.OverheadCarrier || res.Overhead[0].USD != 7 {
		t.Errorf("overhead = %+v, want the carrier at 7", res.Overhead)
	}
}

func TestCostsSaysWhenTheCarrierWasNotObserved(t *testing.T) {
	shown := runCosts(t, overheadCheckpoint(t, nil, 1, kernel.CarrierUnobserved), output.ModeHuman)
	if !strings.Contains(shown, "billing it as present") {
		t.Errorf("an unobserved carrier is not called out:\n%s", shown)
	}
}

// What the kernel cannot see is named every time, including when nothing
// else is wrong: a report that looks complete is the failure.
func TestCostsNamesWhatTheMeterCannotSee(t *testing.T) {
	for name, body := range map[string]string{
		"apps only":    checkpointFor(t, 100, 0.03, map[string]float64{"api": 20}, nil),
		"with carrier": overheadCheckpoint(t, nil, 1, kernel.CarrierLoadBalancer),
		"empty":        checkpointFor(t, 100, 0, nil, nil),
	} {
		shown := runCosts(t, body, output.ModeHuman)
		for _, want := range []string{"Not metered", "carrier", "bucket storage", "registry storage", "managed workloads", "cluster fee", "'confirmed' is what catches them"} {
			if !strings.Contains(shown, want) {
				t.Errorf("%s: the report does not name %q:\n%s", name, want, shown)
			}
		}
	}
}

// stopsCheckpoint is a version 2 checkpoint as a kernel at its floor writes
// it: namespaced spending beside one figure a version 1 kernel accrued, two
// recorded stops, and the floor with its levers.
func stopsCheckpoint(t *testing.T, version int) string {
	t.Helper()
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	ledger, err := cost.NewLedger(start, start.AddDate(0, 1, 0))
	if err != nil {
		t.Fatal(err)
	}
	at := start.Add(48 * time.Hour)
	ledger.Accrue(at, kernel.AppKey("shop", "web"), 20, time.Hour)
	ledger.Accrue(at, kernel.AppKey("blog", "web"), 10, time.Hour)
	ledger.Accrue(at, "worker", 5, time.Hour)
	cp := kernel.Checkpoint{
		Version: version, Ledger: ledger.Snapshot(), Last: at,
		Observed: kernel.Observation{At: at, Pods: 2, RateHourlyUSD: 0.1, Level: "reached", Limit: 30},
		Stops: []kernel.Stop{
			{Namespace: "blog", Deployment: "web", At: at.Add(-time.Hour), Reason: kernel.StopReasonCostGuard, HourlyUSD: 0.25},
			{Namespace: "shop", Deployment: "web", At: at.Add(-time.Hour), Reason: kernel.StopReasonCostGuard, HourlyUSD: 0.5},
		},
		Floor: &kernel.Floor{Since: at, HourlyUSD: 0.105, Levers: []string{kernel.LeverCarrier, kernel.LeverRelease}},
	}
	raw, err := json.Marshal(cp)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// Two namespaces' web are two applications, each with its own figure; a
// figure from before namespaces were recorded is shown as it was kept, with
// no namespace and a note, never given one.
func TestCostsNamesEachApplicationByNamespace(t *testing.T) {
	shown := runCosts(t, stopsCheckpoint(t, kernel.CheckpointVersion), output.ModeHuman)
	for _, want := range []string{"shop/web", "blog/web", "20.00", "10.00", "worker", "*", "accrued before the kernel recorded namespaces"} {
		if !strings.Contains(shown, want) {
			t.Errorf("costs does not show %q:\n%s", want, shown)
		}
	}

	var res struct {
		Apps []appCost `json:"apps"`
	}
	js := runCosts(t, stopsCheckpoint(t, kernel.CheckpointVersion), output.ModeJSON)
	if err := json.Unmarshal([]byte(js), &res); err != nil {
		t.Fatalf("%v:\n%s", err, js)
	}
	want := []appCost{
		{Namespace: "shop", Name: "web", USD: 20},
		{Namespace: "blog", Name: "web", USD: 10},
		{Namespace: "", Name: "worker", USD: 5, Note: legacyNote},
	}
	if len(res.Apps) != len(want) {
		t.Fatalf("apps = %+v, want %+v", res.Apps, want)
	}
	for i := range want {
		if res.Apps[i] != want[i] {
			t.Errorf("apps[%d] = %+v, want %+v", i, res.Apps[i], want[i])
		}
	}
	if !strings.Contains(js, `"namespace":""`) {
		t.Errorf("a legacy entry does not carry its empty namespace:\n%s", js)
	}
}

// What the kernel stopped, and the floor with the levers it leaves to the
// operator: in the report a person reads, and in the one a program reads.
func TestCostsShowsTheStopsAndTheFloor(t *testing.T) {
	shown := runCosts(t, stopsCheckpoint(t, kernel.CheckpointVersion), output.ModeHuman)
	for _, want := range []string{
		"Stopped by the cost guard", "shop/web", "saving USD 0.5000/hour", "blog/web", "never starts them again",
		"At the instance floor since 2026-09-03 00:00", "Still burning USD 0.1050/hour",
		"drop the load-balancer carrier, or release the instance",
	} {
		if !strings.Contains(shown, want) {
			t.Errorf("costs does not say %q:\n%s", want, shown)
		}
	}

	var res struct {
		RecordsStops bool          `json:"records_stops"`
		Stops        []kernel.Stop `json:"stops"`
		Floor        *kernel.Floor `json:"floor"`
	}
	js := runCosts(t, stopsCheckpoint(t, kernel.CheckpointVersion), output.ModeJSON)
	if err := json.Unmarshal([]byte(js), &res); err != nil {
		t.Fatalf("%v:\n%s", err, js)
	}
	if !res.RecordsStops || len(res.Stops) != 2 || res.Stops[1].Deployment != "web" || res.Stops[1].Namespace != "shop" ||
		res.Stops[1].Reason != kernel.StopReasonCostGuard || res.Stops[1].HourlyUSD != 0.5 {
		t.Errorf("stops = %+v (records %v)", res.Stops, res.RecordsStops)
	}
	if res.Floor == nil || res.Floor.HourlyUSD != 0.105 || len(res.Floor.Levers) != 2 || res.Floor.Levers[1] != kernel.LeverRelease {
		t.Errorf("floor = %+v", res.Floor)
	}
	for _, key := range []string{`"saving_per_hour"`, `"still_burning_per_hour"`, `"levers"`} {
		if !strings.Contains(js, key) {
			t.Errorf("the JSON does not carry %s:\n%s", key, js)
		}
	}
}

// An older kernel's checkpoint is read rather than refused: its spending is
// all bare-keyed, and its silence about stops is said, not shown as none.
func TestCostsReadsAnOlderKernelAndSaysWhatItDoesNotRecord(t *testing.T) {
	shown := runCosts(t, stopsCheckpoint(t, 1), output.ModeHuman)
	if !strings.Contains(shown, "keeps no record of what it stops") {
		t.Errorf("a version 1 kernel's silence about stops is not said:\n%s", shown)
	}
	for _, never := range []string{"Stopped by the cost guard", "At the instance floor"} {
		if strings.Contains(shown, never) {
			t.Errorf("a version 1 checkpoint showed %q, which that kernel never wrote:\n%s", never, shown)
		}
	}
	var res struct {
		RecordsStops bool `json:"records_stops"`
	}
	if err := json.Unmarshal([]byte(runCosts(t, stopsCheckpoint(t, 1), output.ModeJSON)), &res); err != nil || res.RecordsStops {
		t.Errorf("records_stops = %v, %v", res.RecordsStops, err)
	}
}

// A version this build does not read is still refused, as before, with the
// kind the app tells apart.
func TestCostsRefusesACheckpointFromANewerKernel(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p43")
	env, _ := testEnv(dir, output.ModeHuman)
	f := costsReader(t, stopsCheckpoint(t, kernel.CheckpointVersion+1))
	c := &costsCommand{}
	c.newCluster = func(string) configMapReader { return f }
	err := c.Run(context.Background(), env, []string{"p43"})
	if kindOf(err) != kindVersionSkew || !strings.Contains(err.Error(), "older than the other") {
		t.Fatalf("a newer kernel's checkpoint: %v (%s)", err, kindOf(err))
	}
}

// After the upgrade one application can hold two figures in one period:
// what a version 1 kernel accrued under its bare name, and what has been
// accrued since under its namespace. Both are shown, each as it was kept —
// the old one with no namespace and the note — and nothing is lost between
// them: the rows add up to what the ledger holds.
func TestCostsShowsAnApplicationsFiguresFromBeforeAndAfterNamespaces(t *testing.T) {
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	ledger, err := cost.NewLedger(start, start.AddDate(0, 1, 0))
	if err != nil {
		t.Fatal(err)
	}
	at := start.Add(48 * time.Hour)
	ledger.Accrue(at, "web", 2, time.Hour)
	ledger.Accrue(at, kernel.AppKey("shop", "web"), 3, time.Hour)
	raw, err := json.Marshal(kernel.Checkpoint{
		Version: kernel.CheckpointVersion, Ledger: ledger.Snapshot(), Last: at,
		Observed: kernel.Observation{At: at, Pods: 1, RateHourlyUSD: 3, Level: "ok", Limit: 100},
	})
	if err != nil {
		t.Fatal(err)
	}

	var res struct {
		Total float64   `json:"total"`
		Apps  []appCost `json:"apps"`
	}
	js := runCosts(t, string(raw), output.ModeJSON)
	if err := json.Unmarshal([]byte(js), &res); err != nil {
		t.Fatalf("%v:\n%s", err, js)
	}
	want := []appCost{
		{Namespace: "shop", Name: "web", USD: 3},
		{Namespace: "", Name: "web", USD: 2, Note: legacyNote},
	}
	if len(res.Apps) != len(want) || res.Apps[0] != want[0] || res.Apps[1] != want[1] {
		t.Fatalf("apps = %+v, want %+v", res.Apps, want)
	}
	if sum := res.Apps[0].USD + res.Apps[1].USD; sum != 5 || res.Total != sum {
		t.Errorf("the rows add to %v and the total is %v; want both 5", sum, res.Total)
	}

	shown := runCosts(t, string(raw), output.ModeHuman)
	if !strings.Contains(shown, "shop/web") || !strings.Contains(shown, "*") || !strings.Contains(shown, legacyNote) {
		t.Errorf("both figures are not shown, each as kept:\n%s", shown)
	}
}

// A record with a reason this build does not know is not listed as the cost
// guard's — 'world' would not label it so either — but it is not hidden.
func TestCostsListsOnlyTheCostGuardsStopsAsTheCostGuards(t *testing.T) {
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	ledger, err := cost.NewLedger(start, start.AddDate(0, 1, 0))
	if err != nil {
		t.Fatal(err)
	}
	at := start.Add(48 * time.Hour)
	raw, err := json.Marshal(kernel.Checkpoint{
		Version: kernel.CheckpointVersion, Ledger: ledger.Snapshot(), Last: at,
		Observed: kernel.Observation{At: at, Level: "reached", Limit: 1},
		Stops: []kernel.Stop{
			{Namespace: "shop", Deployment: "api", At: at, Reason: kernel.StopReasonCostGuard, HourlyUSD: 0.5},
			{Namespace: "shop", Deployment: "batch", At: at, Reason: "maintenance", HourlyUSD: 0.25},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	shown := runCosts(t, string(raw), output.ModeHuman)
	guard, rest, ok := strings.Cut(shown, "Stopped by the cost guard")
	if !ok {
		t.Fatalf("no cost guard section:\n%s", shown)
	}
	section, after, _ := strings.Cut(rest, "never starts them again")
	if !strings.Contains(section, "shop/api") || strings.Contains(section, "shop/batch") {
		t.Errorf("the cost guard's section is wrong:\n%s", section)
	}
	if strings.Contains(guard, "shop/batch") || !strings.Contains(after, "shop/batch") || !strings.Contains(after, `"maintenance"`) {
		t.Errorf("the other stop is not shown apart, with its reason:\n%s", shown)
	}
}
