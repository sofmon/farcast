package kernel

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/sofmon/farcast/technocore/cost"
	"github.com/sofmon/farcast/technocore/kube"
	"github.com/sofmon/farcast/technocore/pricing"
	"github.com/sofmon/farcast/technocore/tier"
)

var (
	start = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	stop  = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
)

type fakeCluster struct {
	byNS    map[string][]kube.Pod
	depsNS  map[string][]kube.Deployment
	err     error
	depErr  error
	scaleAt map[string]error
	seen    []string
	scaled  []string
}

func (f *fakeCluster) ListPods(_ context.Context, ns, selector string) ([]kube.Pod, error) {
	f.seen = append(f.seen, ns+"|"+selector)
	if f.err != nil {
		return nil, f.err
	}
	return f.byNS[ns], nil
}

func (f *fakeCluster) ListDeployments(_ context.Context, ns, _ string) ([]kube.Deployment, error) {
	if f.depErr != nil {
		return nil, f.depErr
	}
	return f.depsNS[ns], nil
}

func (f *fakeCluster) Scale(_ context.Context, ns, name string, replicas int) error {
	key := ns + "/" + name
	f.scaled = append(f.scaled, fmt.Sprintf("%s=%d", key, replicas))
	return f.scaleAt[key]
}

// deployment builds a Deployment claiming pods labelled app.kubernetes.io/name=app.
func deployment(name, ns, app string, tr tier.Tier, replicas int) kube.Deployment {
	labels := map[string]string{"app.kubernetes.io/name": app}
	if tr != tier.Unknown {
		labels[tier.Label] = string(tr)
	}
	r := replicas
	return kube.Deployment{
		Metadata: kube.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
		Spec: kube.DeploymentSpec{
			Replicas: &r,
			Selector: &kube.LabelSelector{MatchLabels: map[string]string{"app.kubernetes.io/name": app}},
		},
		Status: kube.DeploymentStatus{Replicas: replicas},
	}
}

func pod(name, ns, app string, tr tier.Tier, phase, cpu, mem string) kube.Pod {
	labels := map[string]string{"app.kubernetes.io/name": app}
	if tr != tier.Unknown {
		labels[tier.Label] = string(tr)
	}
	return kube.Pod{
		Metadata: kube.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
		Spec: kube.PodSpec{Containers: []kube.Container{
			{Name: "c", Resources: kube.ResourceRequirements{Requests: kube.ResourceList{CPU: cpu, Memory: mem}}},
		}},
		Status: kube.PodStatus{Phase: phase},
	}
}

func reconciler(t *testing.T, pods *fakeCluster, namespaces ...string) *Reconciler {
	t.Helper()
	l, err := cost.NewLedger(start, stop)
	if err != nil {
		t.Fatal(err)
	}
	return &Reconciler{
		Cluster: pods, Namespaces: namespaces, Ledger: l,
		Limit: 50, Interval: 30 * time.Second, Selector: ManagedBy,
	}
}

// The first tick of a process charges nothing — there is no prior observation,
// so any interval would be invented. Billing one on the first tick is how a
// restarting kernel double-charges.
func TestTheFirstReconcileObservesButDoesNotBill(t *testing.T) {
	f := &fakeCluster{byNS: map[string][]kube.Pod{
		"farcast-apps": {pod("web-1", "farcast-apps", "web", tier.App, kube.PodRunning, "100m", "128Mi")},
	}}
	r := reconciler(t, f, "farcast-apps")

	rep, err := r.Reconcile(context.Background(), start.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Billed != 0 {
		t.Errorf("first tick billed %v, want 0", rep.Billed)
	}
	if rep.Accrual.Total != 0 {
		t.Errorf("first tick accrued $%.4f, want 0", rep.Accrual.Total)
	}
	// It still observes: the rate is known immediately.
	if len(rep.Workloads) != 1 {
		t.Fatalf("observed %d workloads, want 1", len(rep.Workloads))
	}
	if rep.RateHourlyUSD != pricing.PodHourlyUSD(100, 128) {
		t.Errorf("rate = %.6f, want the pod's hourly price", rep.RateHourlyUSD)
	}
	if f.seen[0] != "farcast-apps|"+ManagedBy {
		t.Errorf("listed %q; a kernel that metered everything would bill the cluster's own add-ons", f.seen[0])
	}
}

func TestSubsequentReconcilesBillTheElapsedInterval(t *testing.T) {
	f := &fakeCluster{byNS: map[string][]kube.Pod{
		"farcast-apps": {pod("web-1", "farcast-apps", "web", tier.App, kube.PodRunning, "100m", "128Mi")},
	}}
	r := reconciler(t, f, "farcast-apps")

	if _, err := r.Reconcile(context.Background(), start); err != nil {
		t.Fatal(err)
	}
	rep, err := r.Reconcile(context.Background(), start.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Billed != 2*time.Hour {
		t.Errorf("billed %v, want 2h", rep.Billed)
	}
	want := 2 * pricing.PodHourlyUSD(100, 128)
	if diff := rep.Accrual.Total - want; diff > 0.0001 || diff < -0.0001 {
		t.Errorf("accrued $%.6f, want $%.6f", rep.Accrual.Total, want)
	}
	if rep.Accrual.HasConfirmation {
		t.Error("nothing has been confirmed")
	}
}

// A restart leaves a gap that still billed. Assuming the observed set ran
// throughout is the approximation ADR 0009 records — and it must be reported,
// not hidden, because it is the one number in the ledger that was inferred.
func TestARestartGapIsBilledAndFlagged(t *testing.T) {
	f := &fakeCluster{byNS: map[string][]kube.Pod{
		"farcast-apps": {pod("web-1", "farcast-apps", "web", tier.App, kube.PodRunning, "100m", "128Mi")},
	}}
	r := reconciler(t, f, "farcast-apps")
	// A checkpoint restored from before the outage.
	r.Last = start

	rep, err := r.Reconcile(context.Background(), start.Add(6*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Billed != 6*time.Hour {
		t.Errorf("billed %v, want the whole 6h gap", rep.Billed)
	}
	if !rep.Reconstructed {
		t.Error("a gap far larger than the interval must be flagged as reconstructed")
	}
}

// A zero or corrupt Last must not bill from the epoch — that would blow every
// threshold at once, on an instance that had done nothing wrong.
func TestBillingIsFlooredAtThePeriodStart(t *testing.T) {
	f := &fakeCluster{byNS: map[string][]kube.Pod{
		"farcast-apps": {pod("web-1", "farcast-apps", "web", tier.App, kube.PodRunning, "100m", "128Mi")},
	}}
	r := reconciler(t, f, "farcast-apps")
	r.Last = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)

	rep, err := r.Reconcile(context.Background(), start.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Billed != time.Hour {
		t.Errorf("billed %v, want 1h — the interval before the period start is not this period's", rep.Billed)
	}
}

// Time going backwards (a corrected clock, a replayed checkpoint) must not
// produce a negative interval or a credit.
func TestTimeGoingBackwardsBillsNothing(t *testing.T) {
	f := &fakeCluster{byNS: map[string][]kube.Pod{
		"farcast-apps": {pod("web-1", "farcast-apps", "web", tier.App, kube.PodRunning, "100m", "128Mi")},
	}}
	r := reconciler(t, f, "farcast-apps")
	if _, err := r.Reconcile(context.Background(), start.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	rep, err := r.Reconcile(context.Background(), start.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Billed != 0 || rep.Accrual.Total != 0 {
		t.Errorf("billed %v accrued %.4f going backwards; want zero of both", rep.Billed, rep.Accrual.Total)
	}
}

func TestTerminalPodsAreNotMetered(t *testing.T) {
	f := &fakeCluster{byNS: map[string][]kube.Pod{
		"farcast-apps": {
			pod("a", "farcast-apps", "web", tier.App, kube.PodRunning, "100m", "128Mi"),
			pod("b", "farcast-apps", "web", tier.App, kube.PodSucceeded, "100m", "128Mi"),
			pod("c", "farcast-apps", "web", tier.App, kube.PodFailed, "100m", "128Mi"),
			// Pending holds reserved capacity and does bill.
			pod("d", "farcast-apps", "web", tier.App, kube.PodPending, "100m", "128Mi"),
		},
	}}
	r := reconciler(t, f, "farcast-apps")
	rep, err := r.Reconcile(context.Background(), start)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Workloads) != 2 {
		t.Fatalf("metered %d pods, want 2 (Running and Pending)", len(rep.Workloads))
	}
}

// The classification is what a cost shutdown acts on. System workloads must
// never appear in the stoppable set, and applications must come out most
// expensive first.
func TestStoppableExcludesTheSystemTierAndOrdersByCost(t *testing.T) {
	f := &fakeCluster{byNS: map[string][]kube.Pod{
		"farcast-system": {
			pod("fatline-1", "farcast-system", "fatline", tier.System, kube.PodRunning, "100m", "128Mi"),
			pod("technocore-1", "farcast-system", "technocore", tier.Kernel, kube.PodRunning, "100m", "128Mi"),
		},
		"farcast-apps": {
			pod("small", "farcast-apps", "small", tier.App, kube.PodRunning, "100m", "128Mi"),
			pod("big", "farcast-apps", "big", tier.App, kube.PodRunning, "2", "4Gi"),
			pod("nolabel", "farcast-apps", "mystery", tier.Unknown, kube.PodRunning, "100m", "128Mi"),
		},
	}}
	f.depsNS = map[string][]kube.Deployment{
		"farcast-system": {deployment("fatline", "farcast-system", "fatline", tier.System, 2)},
		"farcast-apps": {
			deployment("small", "farcast-apps", "small", tier.App, 1),
			deployment("big", "farcast-apps", "big", tier.App, 1),
			deployment("mystery", "farcast-apps", "mystery", tier.Unknown, 1),
		},
	}
	r := reconciler(t, f, "farcast-system", "farcast-apps")
	rep, err := r.Reconcile(context.Background(), start)
	if err != nil {
		t.Fatal(err)
	}

	got := rep.Stoppable()
	if len(got) != 2 {
		t.Fatalf("stoppable = %d targets, want 2 (the two app deployments)", len(got))
	}
	if got[0].Name != "big" || got[1].Name != "small" {
		t.Errorf("stoppable order = %s, %s; want the expensive one first", got[0].Name, got[1].Name)
	}
	for _, w := range got {
		if w.Tier == tier.System || w.Tier == tier.Kernel {
			t.Errorf("%s is %q and must never be stoppable", w.Name, w.Tier)
		}
	}
	// The unlabelled deployment is protected, not stopped.
	for _, w := range got {
		if w.Name == "mystery" {
			t.Error("an unlabelled deployment must not be stoppable")
		}
	}
	// Each target carries the cost of the pods its selector claims.
	if got[0].Pods != 1 || got[0].HourlyUSD <= got[1].HourlyUSD {
		t.Errorf("target costs did not follow the pods: %+v vs %+v", got[0], got[1])
	}

	// The unlabelled pod is metered and protected, and its existence is
	// surfaced so the operator knows a shutdown will be less effective than
	// they expect.
	if rep.Unclassified != 1 {
		t.Errorf("Unclassified = %d, want 1", rep.Unclassified)
	}
	if rep.RateByTier[tier.System] == 0 || rep.RateByTier[tier.Kernel] == 0 {
		t.Error("system and kernel workloads are still metered even though they cannot be stopped")
	}
}

// Every stoppable workload already stopped, and still over: there is nothing
// further a kernel may do, and decision 8 says it reports rather than reaching
// for the levers that destroy data.
func TestAtFloorWhenNothingStoppableRemains(t *testing.T) {
	f := &fakeCluster{byNS: map[string][]kube.Pod{
		"farcast-system": {pod("fatline-1", "farcast-system", "fatline", tier.System, kube.PodRunning, "100m", "128Mi")},
	}}
	r := reconciler(t, f, "farcast-system")
	r.Limit = 0.0001 // already blown by anything at all
	if _, err := r.Reconcile(context.Background(), start); err != nil {
		t.Fatal(err)
	}
	rep, err := r.Reconcile(context.Background(), start.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Assessment.Level.Acts() {
		t.Fatalf("expected the limit to be reached, got %v", rep.Assessment.Level)
	}
	if !rep.AtFloor() {
		t.Error("with only system workloads left, the instance is at its floor")
	}
}

func TestNotAtFloorWhileApplicationsRemain(t *testing.T) {
	f := &fakeCluster{
		byNS: map[string][]kube.Pod{
			"farcast-apps": {pod("web", "farcast-apps", "web", tier.App, kube.PodRunning, "100m", "128Mi")},
		},
		depsNS: map[string][]kube.Deployment{
			"farcast-apps": {deployment("web", "farcast-apps", "web", tier.App, 1)},
		},
	}
	r := reconciler(t, f, "farcast-apps")
	r.Limit = 0.0001
	if _, err := r.Reconcile(context.Background(), start); err != nil {
		t.Fatal(err)
	}
	rep, _ := r.Reconcile(context.Background(), start.Add(time.Hour))
	if rep.AtFloor() {
		t.Error("an instance with a stoppable application is not at its floor")
	}
}

// A pod whose requests do not parse is a pod whose cost is unknown. Metering
// it as zero would be the flattering answer; the loop refuses instead.
func TestAnUnparseableRequestFailsTheTick(t *testing.T) {
	f := &fakeCluster{byNS: map[string][]kube.Pod{
		"farcast-apps": {pod("web", "farcast-apps", "web", tier.App, kube.PodRunning, "100 potatoes", "128Mi")},
	}}
	r := reconciler(t, f, "farcast-apps")
	if _, err := r.Reconcile(context.Background(), start); err == nil {
		t.Fatal("expected an error rather than a pod silently metered at zero")
	}
}

func TestAListFailureFailsTheTick(t *testing.T) {
	f := &fakeCluster{err: errors.New("api server said no")}
	r := reconciler(t, f, "farcast-apps")
	if _, err := r.Reconcile(context.Background(), start); err == nil {
		t.Fatal("expected the list failure to surface")
	}
}

// Attribution falls back rather than pooling unlabelled workloads into one
// anonymous bucket the operator cannot act on.
func TestAttributionFallsBackToTheWorkloadName(t *testing.T) {
	p := kube.Pod{
		Metadata: kube.ObjectMeta{Name: "orphan-xyz", Namespace: "farcast-apps"},
		Spec:     kube.PodSpec{Containers: []kube.Container{{Name: "c"}}},
		Status:   kube.PodStatus{Phase: kube.PodRunning},
	}
	f := &fakeCluster{byNS: map[string][]kube.Pod{"farcast-apps": {p}}}
	r := reconciler(t, f, "farcast-apps")
	rep, err := r.Reconcile(context.Background(), start)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Workloads[0].App != "orphan-xyz" {
		t.Errorf("App = %q, want the pod name as a fallback", rep.Workloads[0].App)
	}
	// A pod that declares nothing is not free: pricing floors it.
	if rep.Workloads[0].HourlyUSD <= 0 {
		t.Error("a pod with no declared requests is still billed at Autopilot's floor")
	}
}
