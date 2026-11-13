package kernel

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/sofmon/farcast/technocore/cost"
	"github.com/sofmon/farcast/technocore/kube"
	"github.com/sofmon/farcast/technocore/tier"
	"github.com/sofmon/farcast/technocore/usage"
)

// twoWebs is two namespaces each running an application called web, at
// different sizes, so their shares differ.
func twoWebs() *fakeCluster {
	return &fakeCluster{
		byNS: map[string][]kube.Pod{
			"shop": {podFor("web-1", "shop", "web", tier.App, "100m", "128Mi")},
			"blog": {podFor("web-1", "blog", "web", tier.App, "500m", "512Mi")},
		},
		depsNS: map[string][]kube.Deployment{
			"shop": {deployment("web", "shop", "web", tier.App, 1)},
			"blog": {deployment("web", "blog", "web", tier.App, 1)},
		},
	}
}

// The bug this keying fixes: by name alone, two namespaces' "web" were one
// ledger entry, and neither share could be told apart.
func TestTheLedgerKeysSpendingByNamespaceAndName(t *testing.T) {
	r := reconciler(t, twoWebs(), "shop", "blog")
	rep := twoTicks(t, r)

	by := r.Ledger.ByApp()
	if len(by) != 2 {
		t.Fatalf("ledger holds %v, want one entry per namespace", by)
	}
	shop, blog := by[AppKey("shop", "web")], by[AppKey("blog", "web")]
	if shop <= 0 || blog <= shop {
		t.Errorf("shop/web %.6f, blog/web %.6f: want each its own, blog's the larger", shop, blog)
	}
	if _, ok := by["web"]; ok {
		t.Error("a bare name was accrued")
	}
	if !near(rep.RateByApp[AppKey("shop", "web")]+rep.RateByApp[AppKey("blog", "web")], rep.RateHourlyUSD) {
		t.Errorf("the per-application rate %v does not add up to %v", rep.RateByApp, rep.RateHourlyUSD)
	}
}

func TestAnAppKeyReadsBack(t *testing.T) {
	if ns, app, ok := SplitAppKey(AppKey("shop", "web")); ns != "shop" || app != "web" || !ok {
		t.Errorf("qualified: %q %q %v", ns, app, ok)
	}
	if ns, app, ok := SplitAppKey("web"); ns != "" || app != "web" || ok {
		t.Errorf("bare: %q %q %v", ns, app, ok)
	}
}

// The usage profiles are keyed as the ledger is: a profile from one
// namespace never sizes the other namespace's workload of the same name.
func TestAProfileSizesOnlyTheWorkloadInItsOwnNamespace(t *testing.T) {
	now := start.Add(time.Hour)
	r := reconciler(t, twoWebs(), "shop", "blog")
	r.Usage = usage.New(24)
	for i := 0; i < usage.MinSamples; i++ {
		r.Usage.Record(now, AppKey("blog", "web"), []usage.PodUsage{
			{Pod: "web-1", CPUMilli: 40, MemMiB: 60, RequestCPUMilli: 500, RequestMemMiB: 512},
		})
	}
	rep, err := r.Reconcile(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	advice := r.Advise(rep, now)
	byNS := map[string]Adaptation{}
	for _, a := range advice {
		byNS[a.Namespace] = a
	}
	if !byNS["blog"].Act {
		t.Errorf("blog/web, which has the profile, was not advised: %+v", byNS["blog"])
	}
	if byNS["shop"].Act || byNS["shop"].Hold != "no usage profile for this workload yet" {
		t.Errorf("shop/web was sized on blog/web's readings: %+v", byNS["shop"])
	}
}

// What sampleUsage records is named by the same key the ledger accrues
// under, so the profile set never names something the cost path does not.
func TestEveryProfileIsAKeyTheLedgerHolds(t *testing.T) {
	now := start.Add(time.Hour)
	f := twoWebs()
	f.metricsNS = map[string][]kube.PodMetrics{
		"shop": {reading("web-1", "shop", "40m", "100Mi", now)},
		"blog": {reading("web-1", "blog", "60m", "120Mi", now)},
	}
	r := reconciler(t, f, "shop", "blog")
	r.Usage = usage.New(24)
	if _, err := r.Reconcile(context.Background(), start); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	ledger := r.Ledger.ByApp()
	sums := r.Usage.Summarize(now)
	if len(sums) != 2 {
		t.Fatalf("profiled %d applications, want the two webs apart", len(sums))
	}
	for _, s := range sums {
		if _, ok := ledger[s.App]; !ok {
			t.Errorf("profile %q names nothing the ledger holds (%v)", s.App, slices.Sorted(maps.Keys(ledger)))
		}
	}
}

// v1Checkpoint is a checkpoint as a version 1 kernel wrote it: per-app keys
// with no namespace, a confirmation that calibrates, and the carrier. Every
// figure is a binary fraction over whole hours, so sums are exact whatever
// order a map is walked in.
func v1Checkpoint(t *testing.T) (string, *cost.Ledger) {
	t.Helper()
	l, err := cost.NewLedger(start, stop)
	if err != nil {
		t.Fatal(err)
	}
	at := start.Add(96 * time.Hour)
	l.Accrue(at, "web", 0.0625, 96*time.Hour)
	l.Accrue(at, "fatline", 0.03125, 96*time.Hour)
	l.AccrueOverhead(at, OverheadCarrier, 0.015625, 96*time.Hour)
	// A quarter more than the model said for the first two days: a
	// calibration of 1.25, inside the clamp.
	if _, err := l.Confirm(cost.Confirmation{
		Start: start, End: start.Add(48 * time.Hour), USD: 0.109375 * 48 * 1.25, AsOf: start.Add(72 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{
		"version":        1,
		"ledger":         l.Snapshot(),
		"last_reconcile": at,
		"observed":       Observation{At: at, Pods: 2, RateHourlyUSD: 0.109375, Level: "ok", Limit: 50},
		// A version 1 kernel wrote no stops. One claiming to is not trusted.
		"stops": []Stop{{Namespace: "shop", Deployment: "web", Reason: StopReasonCostGuard}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw), l
}

// The upgrade must not lose or change a single accrued figure: a meter that
// forgot part of its period would under-report in the flattering direction.
func TestAVersion1CheckpointRestoresEveryFigureExactly(t *testing.T) {
	raw, want := v1Checkpoint(t)
	store := &ConfigMapStore{Client: &fakeConfigMaps{cm: &kube.ConfigMap{Data: map[string]string{checkpointKey: raw}}}}
	r := reconciler(t, runningApp(), "farcast-apps")
	restored, err := r.Restore(context.Background(), store)
	if err != nil || !restored {
		t.Fatalf("restore: %v, %v", restored, err)
	}
	got, exp := r.Ledger.Accrued(), want.Accrued()
	if got.Total != exp.Total || got.Expected != exp.Expected || got.Confirmed != exp.Confirmed ||
		got.Calibration != exp.Calibration || got.HasConfirmation != exp.HasConfirmation ||
		!got.ConfirmedThrough.Equal(exp.ConfirmedThrough) || len(got.Discrepancies) != len(exp.Discrepancies) {
		t.Errorf("restored %+v\nwant     %+v", got, exp)
	}
	if exp.Calibration != 1.25 {
		t.Fatalf("guard: the fixture's calibration is %v, not the 1.25 it was built for", exp.Calibration)
	}
	if !maps.Equal(r.Ledger.ByApp(), want.ByApp()) || !maps.Equal(r.Ledger.ByOverhead(), want.ByOverhead()) {
		t.Errorf("per-app %v overhead %v; want %v %v", r.Ledger.ByApp(), r.Ledger.ByOverhead(), want.ByApp(), want.ByOverhead())
	}
	if len(r.Stops) != 0 {
		t.Errorf("a version 1 checkpoint brought stops: %+v", r.Stops)
	}

	// Written back as version 2, and read again, nothing moves.
	backing := &fakeConfigMaps{}
	if err := r.Save(context.Background(), &ConfigMapStore{Client: backing}); err != nil {
		t.Fatal(err)
	}
	cp, err := DecodeCheckpoint([]byte(backing.cm.Data[checkpointKey]))
	if err != nil || cp.Version != CheckpointVersion {
		t.Fatalf("rewritten as %d: %v", cp.Version, err)
	}
	again, err := cost.Restore(cp.Ledger)
	if err != nil {
		t.Fatal(err)
	}
	if again.Accrued().Total != exp.Total || !maps.Equal(again.ByApp(), want.ByApp()) {
		t.Errorf("the rewritten checkpoint holds %v and %v", again.Accrued().Total, again.ByApp())
	}
}

// The choice made for bare keys: kept as written, never re-keyed — even here,
// where exactly one workload in exactly one namespace carries the name, and
// a re-key would have been a plausible guess. New spending accrues beside it
// under the namespaced key, and the total is the old one plus exactly that.
func TestBareKeysAreKeptAndNewSpendingAccruesBesideThem(t *testing.T) {
	raw, want := v1Checkpoint(t)
	store := &ConfigMapStore{Client: &fakeConfigMaps{cm: &kube.ConfigMap{Data: map[string]string{checkpointKey: raw}}}}
	r := reconciler(t, runningApp(), "farcast-apps")
	if _, err := r.Restore(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	before := r.Ledger.Accrued()
	rep, err := r.Reconcile(context.Background(), r.Last.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Billed != time.Hour {
		t.Fatalf("billed %v, want the hour since the checkpoint", rep.Billed)
	}
	by := r.Ledger.ByApp()
	if by["web"] != want.ByApp()["web"] || by["fatline"] != want.ByApp()["fatline"] {
		t.Errorf("a bare entry moved: %v, want %v", by, want.ByApp())
	}
	if !near(by[AppKey("farcast-apps", "web")], rep.RateHourlyUSD) {
		t.Errorf("farcast-apps/web holds %v, want this hour's %v", by[AppKey("farcast-apps", "web")], rep.RateHourlyUSD)
	}
	// The open window is scaled by the calibration, as every expected figure
	// is: nothing restored was lost, and nothing was counted twice.
	if !near(rep.Accrual.Total, before.Total+rep.RateHourlyUSD*before.Calibration) {
		t.Errorf("total %v, want %v plus the hour's %v at calibration %v",
			rep.Accrual.Total, before.Total, rep.RateHourlyUSD, before.Calibration)
	}
	if rep.Accrual.Confirmed != before.Confirmed || rep.Accrual.Calibration != before.Calibration {
		t.Errorf("confirmed %v calibration %v; want %v %v", rep.Accrual.Confirmed, rep.Accrual.Calibration, before.Confirmed, before.Calibration)
	}
	if r.Ledger.ByOverhead()[OverheadCarrier] != want.ByOverhead()[OverheadCarrier] {
		t.Error("the restored overhead moved")
	}
}

func TestCheckpointVersionsOutsideTheRangeAreRefused(t *testing.T) {
	for _, v := range []int{0, CheckpointVersion + 1} {
		cp, err := DecodeCheckpoint([]byte(`{"version":` + strconv.Itoa(v) + `}`))
		if !errors.Is(err, ErrCheckpointVersion) || cp.Version != v {
			t.Errorf("version %d: %v (read as %d)", v, err, cp.Version)
		}
	}
	if _, err := DecodeCheckpoint([]byte("{{")); err == nil || errors.Is(err, ErrCheckpointVersion) {
		t.Errorf("garbage: %v", err)
	}
	for _, v := range []int{OldestCheckpointVersion, CheckpointVersion} {
		cp, err := DecodeCheckpoint([]byte(`{"version":` + strconv.Itoa(v) + `,"stops":[{"namespace":"a","deployment":"b"}]}`))
		if err != nil || cp.RecordsStops() != (v >= 2) || (len(cp.Stops) == 1) != (v >= 2) {
			t.Errorf("version %d: %v, records stops %v, %d stops", v, err, cp.RecordsStops(), len(cp.Stops))
		}
	}
}

// A cost stop is recorded where the kernel keeps state, with what a report
// needs to say why the application is stopped and what stopping it saved.
func TestAStopIsRecordedWithItsReasonAndSaving(t *testing.T) {
	f := mixedInstance()
	r, rep := overLimit(t, f, "farcast-system", "farcast-apps")
	now := start.Add(time.Hour)
	res, err := r.Shutdown(context.Background(), rep, now)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Recorded {
		t.Error("a shutdown that stopped applications did not say it changed the record")
	}
	if len(r.Stops) != len(res.Stopped) || len(r.Stops) != 2 {
		t.Fatalf("recorded %+v for %d stopped", r.Stops, len(res.Stopped))
	}
	for _, target := range res.Stopped {
		i := slices.IndexFunc(r.Stops, func(s Stop) bool { return s.Namespace == target.Namespace && s.Deployment == target.Name })
		if i < 0 {
			t.Errorf("%s/%s stopped and not recorded", target.Namespace, target.Name)
			continue
		}
		s := r.Stops[i]
		if s.Reason != StopReasonCostGuard || !s.At.Equal(now) || s.HourlyUSD != target.HourlyUSD || s.HourlyUSD <= 0 {
			t.Errorf("record %+v for target %+v", s, target)
		}
	}
	// Recorded in the kernel's state, and nowhere on the workload: the only
	// writes are the scales to zero.
	if len(f.resized) != 0 || len(f.resizeAnns) != 0 {
		t.Errorf("a stop wrote to the workload beyond its scale: %v %v", f.resized, f.resizeAnns)
	}
}

func TestAStopRecordSurvivesARestart(t *testing.T) {
	f := mixedInstance()
	r, rep := overLimit(t, f, "farcast-system", "farcast-apps")
	if _, err := r.Shutdown(context.Background(), rep, start.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	store := &ConfigMapStore{Client: &fakeConfigMaps{}}
	if err := r.Save(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	next := reconciler(t, f, "farcast-system", "farcast-apps")
	if _, err := next.Restore(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	if !slices.EqualFunc(next.Stops, r.Stops, func(a, b Stop) bool {
		return a.Namespace == b.Namespace && a.Deployment == b.Deployment && a.At.Equal(b.At) && a.Reason == b.Reason && a.HourlyUSD == b.HourlyUSD
	}) {
		t.Errorf("restored %+v, want %+v", next.Stops, r.Stops)
	}
}

// scaledTo sets a fake Deployment's replicas, as the cluster would report it
// after a scale call or an operator's own.
func scaledTo(f *fakeCluster, ns, name string, replicas int) {
	for i := range f.depsNS[ns] {
		if f.depsNS[ns][i].Metadata.Name == name {
			r := replicas
			f.depsNS[ns][i].Spec.Replicas = &r
			f.depsNS[ns][i].Status.Replicas = replicas
		}
	}
}

// A record says why an application is stopped only while it is: one brought
// back is no longer the cost guard's, and one deleted is no longer anyone's.
func TestAStopRecordEndsWhenTheWorkloadRunsAgainOrIsGone(t *testing.T) {
	f := mixedInstance()
	r, rep := overLimit(t, f, "farcast-system", "farcast-apps")
	if _, err := r.Shutdown(context.Background(), rep, start.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	r.Limit = 1e9 // spending is no longer over, so nothing is stopped again
	scaledTo(f, "farcast-apps", "big", 0)
	scaledTo(f, "farcast-apps", "small", 0)

	tick := func(at time.Duration) {
		t.Helper()
		if _, err := r.Reconcile(context.Background(), start.Add(at)); err != nil {
			t.Fatal(err)
		}
	}
	names := func() []string {
		var out []string
		for _, s := range r.Stops {
			out = append(out, s.Namespace+"/"+s.Deployment)
		}
		return out
	}

	tick(2 * time.Hour)
	if got := names(); !slices.Equal(got, []string{"farcast-apps/big", "farcast-apps/small"}) {
		t.Fatalf("still at zero, the records are %v", got)
	}

	// Its namespace cannot be listed: nothing is known, so nothing is
	// forgotten.
	f.nsErr = map[string]error{"farcast-apps": errors.New("forbidden")}
	tick(3 * time.Hour)
	if got := names(); len(got) != 2 {
		t.Fatalf("an unreadable namespace dropped records: %v", got)
	}
	f.nsErr = nil

	scaledTo(f, "farcast-apps", "small", 1)
	tick(4 * time.Hour)
	if got := names(); !slices.Equal(got, []string{"farcast-apps/big"}) {
		t.Fatalf("after small was brought back, the records are %v", got)
	}

	f.depsNS["farcast-apps"] = slices.DeleteFunc(f.depsNS["farcast-apps"], func(d kube.Deployment) bool { return d.Metadata.Name == "big" })
	tick(5 * time.Hour)
	if got := names(); len(got) != 0 {
		t.Fatalf("after big was deleted, the records are %v", got)
	}
}

// floorInstance runs nothing a shutdown may stop: FarCast's own components,
// and the load-balancer carrier.
func floorInstance() *fakeCluster {
	return &fakeCluster{
		byNS: map[string][]kube.Pod{"farcast-system": {
			pod("fatline-1", "farcast-system", "fatline", tier.System, kube.PodRunning, "100m", "128Mi"),
			pod("tc-1", "farcast-system", "technocore", tier.Kernel, kube.PodRunning, "100m", "128Mi"),
		}},
		depsNS: map[string][]kube.Deployment{"farcast-system": {
			deployment("fatline", "farcast-system", "fatline", tier.System, 1),
			deployment("technocore", "farcast-system", "technocore", tier.Kernel, 1),
		}},
		services: carrierOfType(kube.ServiceTypeLoadBalancer),
	}
}

// ADR 0009 decision 8, as state: the floor, since when, what still burns, and
// the levers the kernel names and takes neither of.
func TestTheFloorIsRecordedWithWhatStillBurnsAndTheLevers(t *testing.T) {
	r, rep := overLimit(t, floorInstance(), "farcast-system")
	first := start.Add(time.Hour)
	res, err := r.Shutdown(context.Background(), rep, first)
	if err != nil {
		t.Fatal(err)
	}
	if !res.AtFloor || !res.Recorded || r.Floor == nil {
		t.Fatalf("at floor %v, recorded %v, floor %+v", res.AtFloor, res.Recorded, r.Floor)
	}
	if !r.Floor.Since.Equal(first) || !near(r.Floor.HourlyUSD, rep.FloorHourlyUSD()) || r.Floor.HourlyUSD <= rep.RateOverheadUSD {
		t.Errorf("floor %+v; want since %v, still burning %v", r.Floor, first, rep.FloorHourlyUSD())
	}
	if !slices.Equal(r.Floor.Levers, []string{LeverCarrier, LeverRelease}) {
		t.Errorf("levers %v", r.Floor.Levers)
	}

	// Still there an hour later: the record keeps when it began, and the
	// shutdown has nothing new for the checkpoint.
	rep, err = r.Reconcile(context.Background(), start.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	res, err = r.Shutdown(context.Background(), rep, start.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if res.Recorded || r.Floor == nil || !r.Floor.Since.Equal(first) {
		t.Errorf("recorded %v, floor %+v; want the floor since %v, unchanged", res.Recorded, r.Floor, first)
	}

	// Below the limit again — a confirmation, a larger limit — and it is
	// gone on the first tick that shows it.
	r.Limit = 1e9
	if _, err := r.Reconcile(context.Background(), start.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if r.Floor != nil {
		t.Errorf("below the limit, the floor is still recorded: %+v", r.Floor)
	}
}

// With no carrier billed, dropping it is not a lever.
func TestWithoutABilledCarrierTheOnlyLeverIsTheInstance(t *testing.T) {
	f := floorInstance()
	f.services = nil
	r, rep := overLimit(t, f, "farcast-system")
	if _, err := r.Shutdown(context.Background(), rep, start.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if r.Floor == nil || !slices.Equal(r.Floor.Levers, []string{LeverRelease}) {
		t.Errorf("floor %+v", r.Floor)
	}
}

// Stops are about workloads, so they outlive the month; the floor is about
// the month's money, so it does not.
func TestStopsOutliveAPeriodAndTheFloorDoesNot(t *testing.T) {
	old, err := cost.NewLedger(start.AddDate(0, -1, 0), start)
	if err != nil {
		t.Fatal(err)
	}
	backing := &fakeConfigMaps{}
	store := &ConfigMapStore{Client: backing}
	stopped := Stop{Namespace: "farcast-apps", Deployment: "web", At: start.Add(-time.Hour), Reason: StopReasonCostGuard, HourlyUSD: 0.5}
	if err := store.Save(context.Background(), Checkpoint{
		Ledger: old.Snapshot(), Last: start, Stops: []Stop{stopped, {Namespace: "", Deployment: "nameless"}},
		Floor: &Floor{Since: start.Add(-time.Hour), HourlyUSD: 0.1, Levers: []string{LeverRelease}},
	}); err != nil {
		t.Fatal(err)
	}
	r := reconciler(t, runningApp(), "farcast-apps")
	restored, err := r.Restore(context.Background(), store)
	if err != nil || restored {
		t.Fatalf("restored %v, %v; want last period's ledger ignored", restored, err)
	}
	if len(r.Stops) != 1 || r.Stops[0].Deployment != "web" || r.Floor != nil {
		t.Errorf("stops %+v, floor %+v", r.Stops, r.Floor)
	}
}

// A namespace the kernel stops metering takes its records with it: the
// kernel would never list it again to see the workload brought back or
// deleted, so a record kept would outlive both — through every period, and
// reported as the cost guard's after the namespace itself was gone. A
// namespace still metered but unreadable keeps them (above).
func TestAStopRecordEndsWhenItsNamespaceIsNoLongerMetered(t *testing.T) {
	f := mixedInstance()
	r, rep := overLimit(t, f, "farcast-system", "farcast-apps")
	if _, err := r.Shutdown(context.Background(), rep, start.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(r.Stops) != 2 {
		t.Fatalf("guard: recorded %+v", r.Stops)
	}
	r.Limit = 1e9
	scaledTo(f, "farcast-apps", "big", 0)
	scaledTo(f, "farcast-apps", "small", 0)

	// 'farcast kernel meter --remove farcast-apps': the namespace and its
	// Deployments are still there, at zero, and no longer the kernel's.
	r.Namespaces = []string{"farcast-system"}
	if _, err := r.Reconcile(context.Background(), start.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(r.Stops) != 0 {
		t.Errorf("records for a namespace the kernel no longer meters were kept: %+v", r.Stops)
	}
}

// Within its period the floor comes back from the checkpoint as it was
// written, so a restarted kernel still at the floor neither forgets when it
// began nor counts it as newly reached — which would date it again and
// write the checkpoint off its schedule for nothing.
func TestTheFloorIsRestoredWithinItsPeriodAsItWasWritten(t *testing.T) {
	f := floorInstance()
	r, rep := overLimit(t, f, "farcast-system")
	first := start.Add(time.Hour)
	if _, err := r.Shutdown(context.Background(), rep, first); err != nil {
		t.Fatal(err)
	}
	if r.Floor == nil {
		t.Fatal("guard: the floor was not reached")
	}
	want := *r.Floor
	store := &ConfigMapStore{Client: &fakeConfigMaps{}}
	if err := r.Save(context.Background(), store); err != nil {
		t.Fatal(err)
	}

	next := reconciler(t, f, "farcast-system")
	next.Limit = r.Limit
	restored, err := next.Restore(context.Background(), store)
	if err != nil || !restored {
		t.Fatalf("restore: %v, %v", restored, err)
	}
	if next.Floor == nil || !next.Floor.Since.Equal(want.Since) || next.Floor.HourlyUSD != want.HourlyUSD ||
		!slices.Equal(next.Floor.Levers, want.Levers) {
		t.Fatalf("restored floor %+v, want %+v", next.Floor, want)
	}

	rep, err = next.Reconcile(context.Background(), start.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if next.Floor == nil {
		t.Fatal("the first tick after the restart cleared a floor that still holds")
	}
	res, err := next.Shutdown(context.Background(), rep, start.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !res.AtFloor || res.Recorded || next.Floor == nil || !next.Floor.Since.Equal(first) {
		t.Errorf("at floor %v, recorded %v, floor %+v; want the floor since %v, nothing new to record",
			res.AtFloor, res.Recorded, next.Floor, first)
	}
}

// Something stoppable running again — an operator bringing an application
// back while still over the limit, with enforcement off or before the next
// shutdown — ends the floor on the tick that sees it: "every application is
// stopped" is no longer true, whatever the money says.
func TestTheFloorEndsWhenSomethingStoppableRunsAgain(t *testing.T) {
	f := floorInstance()
	r, rep := overLimit(t, f, "farcast-system", "farcast-apps")
	if _, err := r.Shutdown(context.Background(), rep, start.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if r.Floor == nil {
		t.Fatal("guard: the floor was not reached")
	}

	f.byNS["farcast-apps"] = []kube.Pod{pod("web-1", "farcast-apps", "web", tier.App, kube.PodRunning, "100m", "128Mi")}
	f.depsNS["farcast-apps"] = []kube.Deployment{deployment("web", "farcast-apps", "web", tier.App, 1)}
	rep, err := r.Reconcile(context.Background(), start.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Assessment.Level.Acts() || len(rep.Stoppable()) != 1 {
		t.Fatalf("guard: level %v, stoppable %v; want still over, with web to stop", rep.Assessment.Level, rep.Stoppable())
	}
	if r.Floor != nil {
		t.Errorf("an application is running and the floor is still recorded: %+v", r.Floor)
	}
}
