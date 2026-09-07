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
