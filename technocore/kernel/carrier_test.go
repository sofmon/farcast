package kernel

import (
	"context"
	"math"
	"slices"
	"testing"
	"time"

	"github.com/sofmon/farcast/technocore/kube"
	"github.com/sofmon/farcast/technocore/pricing"
	"github.com/sofmon/farcast/technocore/tier"
)

func carrierOfType(typ string) map[string]kube.Service {
	return map[string]kube.Service{CarrierNamespace + "/" + CarrierService: {Spec: kube.ServiceSpec{Type: typ}}}
}

func twoTicks(t *testing.T, r *Reconciler) Report {
	t.Helper()
	if _, err := r.Reconcile(context.Background(), start); err != nil {
		t.Fatal(err)
	}
	rep, err := r.Reconcile(context.Background(), start.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// ADR 0009 decision 4: expected includes the load balancer. It used to be
// metered nowhere — the limit fired about $18 a month late, and the first
// confirmed window would have scaled every Pod price up by the gap.
func TestALoadBalancerCarrierIsMeteredAsInstanceOverhead(t *testing.T) {
	f := &fakeCluster{byNS: map[string][]kube.Pod{
		"farcast-apps": {pod("web-1", "farcast-apps", "web", tier.App, kube.PodRunning, "100m", "128Mi")},
	}, services: carrierOfType(kube.ServiceTypeLoadBalancer)}
	r := reconciler(t, f, "farcast-apps")
	rep := twoTicks(t, r)

	pods := rep.RateHourlyUSD - pricing.CarrierHourlyUSD
	if rep.Carrier != CarrierLoadBalancer || !near(rep.RateOverheadUSD, pricing.CarrierHourlyUSD) || pods <= 0 {
		t.Fatalf("carrier %s, overhead %v, rate %v", rep.Carrier, rep.RateOverheadUSD, rep.RateHourlyUSD)
	}
	if !near(rep.Accrual.Expected, rep.RateHourlyUSD) {
		t.Errorf("an hour accrued %.6f; want pods plus the carrier, %.6f", rep.Accrual.Expected, rep.RateHourlyUSD)
	}
	// Never an application's, never something to stop.
	if _, ok := r.Ledger.ByApp()[OverheadCarrier]; ok {
		t.Error("the carrier was attributed to an application")
	}
	if got := r.Ledger.ByOverhead()[OverheadCarrier]; !near(got, pricing.CarrierHourlyUSD) {
		t.Errorf("the ledger's overhead holds %v for the carrier", got)
	}
	if _, ok := rep.RateByApp[OverheadCarrier]; ok {
		t.Error("the carrier appears in the per-application rate")
	}
	for _, w := range rep.Workloads {
		if w.App == OverheadCarrier {
			t.Error("the carrier is a workload")
		}
	}
	if r.Observed.Overhead != rep.RateOverheadUSD || r.Observed.Carrier != string(CarrierLoadBalancer) {
		t.Errorf("the observation does not carry the carrier: %+v", r.Observed)
	}
}

func TestOnlyALoadBalancerCarrierCostsAnything(t *testing.T) {
	for name, services := range map[string]map[string]kube.Service{
		"internal (ClusterIP)": carrierOfType("ClusterIP"),
		"not connected":        nil,
	} {
		f := &fakeCluster{byNS: map[string][]kube.Pod{}, services: services}
		rep := twoTicks(t, reconciler(t, f, "farcast-system"))
		if rep.RateOverheadUSD != 0 || len(rep.Overhead) != 0 || rep.RateHourlyUSD != 0 {
			t.Errorf("%s: overhead %v, rate %v; want nothing", name, rep.RateOverheadUSD, rep.RateHourlyUSD)
		}
	}
}

// A failed read is billed as present — under-reporting is the worse failure —
// and it neither fails the tick nor counts as an unreachable namespace, which
// on a one-namespace kernel would turn it into "nothing could be read".
func TestAnUnreadableCarrierIsBilledAsPresent(t *testing.T) {
	f := &fakeCluster{byNS: map[string][]kube.Pod{}, serviceErr: &kube.APIError{Status: kube.Status{Code: 403, Reason: "Forbidden", Message: "forbidden"}}}
	r := reconciler(t, f, "farcast-system")
	rep := twoTicks(t, r)
	if rep.Carrier != CarrierUnobserved || len(rep.Overhead) != 1 || !rep.Overhead[0].Assumed || !near(rep.RateOverheadUSD, pricing.CarrierHourlyUSD) {
		t.Fatalf("carrier %s, overhead %+v; want it billed, marked assumed", rep.Carrier, rep.Overhead)
	}
	if !rep.Complete() || len(rep.Unreachable) != 0 {
		t.Errorf("a carrier read failure made the tick incomplete: %v", rep.Unreachable)
	}
	if rep.CarrierErr == "" {
		t.Error("the read failure is not reported")
	}
}

// The carrier is read from farcast-system, once a tick, whatever is metered.
func TestTheCarrierIsReadFromFarcastSystemOnly(t *testing.T) {
	f := &fakeCluster{byNS: map[string][]kube.Pod{}}
	twoTicks(t, reconciler(t, f, "farcast-apps", "shop"))
	if !slices.Equal(f.serviceHit, []string{"farcast-system/fatline", "farcast-system/fatline"}) {
		t.Errorf("service reads: %v; want farcast-system/fatline once per tick", f.serviceHit)
	}
}

// A shutdown stops applications only; the carrier is never a target, and once
// they are all stopped it is part of what still burns.
func TestAShutdownNeverReachesTheCarrier(t *testing.T) {
	f := mixedInstance()
	f.services = carrierOfType(kube.ServiceTypeLoadBalancer)
	r, rep := overLimit(t, f, "farcast-system", "farcast-apps")
	for _, tg := range rep.Stoppable() {
		if tg.Name == OverheadCarrier || tg.Name == CarrierService {
			t.Fatalf("the carrier is a shutdown target: %+v", tg)
		}
	}
	if _, err := r.Shutdown(context.Background(), rep, start.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if !near(rep.FloorHourlyUSD(), rep.SystemProtected()+pricing.CarrierHourlyUSD) {
		t.Errorf("the floor %v leaves out the carrier", rep.FloorHourlyUSD())
	}
}
