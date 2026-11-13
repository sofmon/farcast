package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/technocore/cost"
	"github.com/sofmon/farcast/technocore/kernel"
)

// appOf is the app the document holds for namespace/name.
func appOf(t *testing.T, doc worldDoc, ns, name string) worldApp {
	t.Helper()
	for _, g := range doc.Groups {
		if g.Namespace != ns {
			continue
		}
		for _, a := range g.Apps {
			if a.Name == name {
				return a
			}
		}
	}
	t.Fatalf("no %s/%s in the document", ns, name)
	return worldApp{}
}

// stopped_by says the kernel did it only while the record and the cluster
// agree: a record for the Deployment, and the Deployment still at zero. A
// StatefulSet of the same name is not what the kernel stopped — it stops
// Deployments only — and a record whose reason this build does not know
// labels nothing.
func TestStoppedByNeedsTheRecordAndTheClusterToAgree(t *testing.T) {
	in := healthyInputs(t)
	in.Spend.Raw = vectorCheckpoint(t, func(cp *kernel.Checkpoint) {
		cp.Stops = []kernel.Stop{
			{Namespace: "shop", Deployment: "api", At: vectorNow.Add(-time.Hour), Reason: kernel.StopReasonCostGuard},
			{Namespace: "shop", Deployment: "db", At: vectorNow.Add(-time.Hour), Reason: kernel.StopReasonCostGuard},
			{Namespace: "shop", Deployment: "web", At: vectorNow.Add(-time.Hour), Reason: "operator"},
		}
	})
	in.Apps.Workloads["shop"] = []cluster.Workload{
		wl("Deployment", "shop", "api", 0, 0),
		wl("StatefulSet", "shop", "db", 0, 0),
		wl("Deployment", "shop", "web", 0, 0),
	}
	doc := buildWorld(in)
	if a := appOf(t, doc, "shop", "api"); a.StoppedBy == nil || *a.StoppedBy != "cost_guard" {
		t.Errorf("shop/api: stopped_by %v, want cost_guard", a.StoppedBy)
	}
	for _, name := range []string{"db", "web"} {
		if a := appOf(t, doc, "shop", name); a.StoppedBy != nil {
			t.Errorf("shop/%s: stopped_by %q, want none", name, *a.StoppedBy)
		}
	}
}

// Spending not read is no stop record either: an application at zero is
// stopped, and why is not known.
func TestStoppedByIsNotSaidWithoutTheCheckpoint(t *testing.T) {
	in := healthyInputs(t)
	in.Spend = spendInput{Problem: &sectionProblem{Kind: kindTimeout, Message: "not asked"}}
	in.Apps.Workloads["shop"] = []cluster.Workload{wl("Deployment", "shop", "api", 0, 0)}
	if a := appOf(t, buildWorld(in), "shop", "api"); a.StoppedBy != nil || a.State != stateStopped {
		t.Errorf("shop/api: state %s, stopped_by %v", a.State, a.StoppedBy)
	}
}

// The floor's alert names what is left — only the instance, when no carrier
// is billed — and the cost alert keeps its own rule beside it.
func TestTheFloorAlertNamesTheLeversItWasGiven(t *testing.T) {
	in := healthyInputs(t)
	in.Spend.Raw = vectorCheckpoint(t, func(cp *kernel.Checkpoint) {
		cp.Observed.Level = cost.LevelReached.String()
		cp.Floor = &kernel.Floor{Since: vectorNow.Add(-time.Hour), HourlyUSD: 0.05, Levers: []string{kernel.LeverRelease}}
	})
	doc := buildWorld(in)
	var floor, costAlert *worldAlert
	for i, a := range doc.Alerts {
		switch a.Kind {
		case "at_floor":
			floor = &doc.Alerts[i]
		case "cost":
			costAlert = &doc.Alerts[i]
		}
	}
	if floor == nil || floor.Severity != severityCritical || floor.Subject.Component != roleKernel {
		t.Fatalf("at_floor alert: %+v", floor)
	}
	if !strings.Contains(floor.Title, "release the instance") || strings.Contains(floor.Title, "carrier") {
		t.Errorf("title %q", floor.Title)
	}
	if costAlert == nil || costAlert.Severity != severityCritical {
		t.Errorf("the cost alert did not keep its rule: %+v", costAlert)
	}
	s := doc.Instance.Spend.(worldSpend)
	if s.AtFloor == nil || !*s.AtFloor || s.Floor == nil || s.Floor.StillBurningMonthCents != 3650 {
		t.Errorf("spend at_floor %v, floor %+v", s.AtFloor, s.Floor)
	}

	var b strings.Builder
	if err := doc.Human(&b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "at the instance floor") {
		t.Errorf("the human reading does not say the floor:\n%s", b.String())
	}
}

func TestTheHumanReadingCountsTheCostGuardsStops(t *testing.T) {
	in := healthyInputs(t)
	in.Spend.Raw = vectorCheckpoint(t, func(cp *kernel.Checkpoint) {
		cp.Stops = []kernel.Stop{{Namespace: "shop", Deployment: "api", Reason: kernel.StopReasonCostGuard}}
	})
	in.Apps.Workloads["shop"][1] = wl("Deployment", "shop", "api", 0, 0)
	var b strings.Builder
	if err := buildWorld(in).Human(&b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "1 stopped by the cost guard") {
		t.Errorf("the human reading does not count the stop:\n%s", b.String())
	}
}

// The state a period is in after the upgrade: what a version 1 kernel
// accrued for web under its bare name, and what the version 2 kernel has
// accrued since under shop/web, side by side in one ledger. web runs in shop
// alone, so its figure is the two together — neither part dropped — and the
// caveat says part of it predates the namespaces.
func TestAnAppsFigureAddsWhatWasAccruedBeforeNamespacesToWhatCameAfter(t *testing.T) {
	in := healthyInputs(t)
	rates := vectorRates()
	before, after := 0.0078125, rates["shop/web"]-0.0078125
	rates["web"], rates["shop/web"] = before, after
	in.Spend.Raw = vectorCheckpointOf(t, rates, nil)
	doc := buildWorld(in)

	// Both halves are binary fractions over 132 hours, so the sum is exact.
	want := cents((before + after) * 132)
	if web := appOf(t, doc, "shop", "web"); web.MonthCents == nil || *web.MonthCents != want {
		t.Errorf("shop/web month_cents %v, want %d: the bare and the namespaced share together", web.MonthCents, want)
	}
	if api := appOf(t, doc, "shop", "api"); api.MonthCents == nil || *api.MonthCents != cents(rates["shop/api"]*132) {
		t.Errorf("shop/api month_cents %v: a name with no bare share moved", api.MonthCents)
	}
	s := doc.Instance.Spend.(worldSpend)
	found := false
	for _, c := range s.Caveats {
		found = found || strings.Contains(c, "accrued before the kernel recorded namespaces")
	}
	if !found {
		t.Errorf("no caveat says part of the spending predates the namespaces: %q", s.Caveats)
	}
}
