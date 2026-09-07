package kernel

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/sofmon/farcast/technocore/kube"
)

// The kernel is the only place the cost model lives. An operator's machine
// reports spending by reading what the kernel published — so if the kernel
// stopped publishing it, `farcast costs` would show an instance running
// nothing, at no cost, while it billed.
func TestReconcilePublishesWhatItSaw(t *testing.T) {
	f := runningApp()
	r := reconciler(t, f, "farcast-apps")

	rep, err := r.Reconcile(context.Background(), start)
	if err != nil {
		t.Fatal(err)
	}
	got := r.Observed
	if !got.At.Equal(start) {
		t.Errorf("observed at %v, want %v", got.At, start)
	}
	if got.Pods != len(rep.Workloads) {
		t.Errorf("pods = %d, want %d", got.Pods, len(rep.Workloads))
	}
	if got.RateHourlyUSD != rep.RateHourlyUSD {
		t.Errorf("rate = %v, want the report's %v", got.RateHourlyUSD, rep.RateHourlyUSD)
	}
	if got.RateHourlyUSD == 0 {
		t.Error("a running pod produced a rate of zero, which is the one figure a cost report must never invent")
	}
	if got.Limit != r.Limit {
		t.Errorf("limit = %v, want the one being enforced, %v", got.Limit, r.Limit)
	}
	if got.Level != rep.Assessment.Level.String() {
		t.Errorf("level = %q, want %q", got.Level, rep.Assessment.Level.String())
	}
	if got.Incomplete {
		t.Error("a complete read was published as incomplete")
	}
}

// A report built on a partial picture must say so: the namespace the kernel
// could not read may hold the most expensive thing running.
func TestAPartialReadIsPublishedAsPartial(t *testing.T) {
	f := runningApp()
	f.nsErr = map[string]error{"farcast-other": errors.New("forbidden")}
	f.byNS["farcast-other"] = nil

	r := reconciler(t, f, "farcast-apps", "farcast-other")
	if _, err := r.Reconcile(context.Background(), start); err != nil {
		t.Fatal(err)
	}
	if !r.Observed.Incomplete {
		t.Fatal("a namespace the kernel could not read was published as a complete picture")
	}
	if len(r.Observed.Unreachable) == 0 {
		t.Error("nothing says which namespace could not be read")
	}
}

// The join `farcast costs` depends on: what Save writes must be what a reader
// on the operator's machine decodes. Both halves passing their own tests is
// not the same as the two agreeing.
func TestTheObservationSurvivesTheCheckpointRoundTrip(t *testing.T) {
	backing := &fakeConfigMaps{}
	store := NewConfigMapStore(backing)
	r := reconciler(t, runningApp(), "farcast-apps")
	if _, err := r.Reconcile(context.Background(), start); err != nil {
		t.Fatal(err)
	}
	if err := r.Save(context.Background(), store); err != nil {
		t.Fatal(err)
	}

	// Decoded exactly as an operator's machine decodes it: from the bytes in
	// the ConfigMap, through the exported type, with no access to the
	// reconciler that wrote them.
	var cp Checkpoint
	if err := json.Unmarshal([]byte(backing.saves[0].Data[CheckpointKey()]), &cp); err != nil {
		t.Fatal(err)
	}
	if cp.Observed.Pods != r.Observed.Pods || cp.Observed.RateHourlyUSD != r.Observed.RateHourlyUSD {
		t.Fatalf("what was written (%+v) is not what the kernel saw (%+v)", cp.Observed, r.Observed)
	}
	if cp.Observed.Limit != r.Limit {
		t.Errorf("the enforced limit did not reach the checkpoint: %v", cp.Observed.Limit)
	}
	if cp.Observed.At.IsZero() {
		t.Error("the observation has no timestamp, so a reader cannot tell how stale it is")
	}
}

// A restart leaves a gap before the first reconcile. Showing an instance that
// appears to be running nothing during it would be worse than showing the last
// thing that was true, timestamped.
func TestARestoredKernelCarriesTheLastObservation(t *testing.T) {
	backing := &fakeConfigMaps{}
	store := NewConfigMapStore(backing)
	first := reconciler(t, runningApp(), "farcast-apps")
	if _, err := first.Reconcile(context.Background(), start); err != nil {
		t.Fatal(err)
	}
	if err := first.Save(context.Background(), store); err != nil {
		t.Fatal(err)
	}

	second := reconciler(t, runningApp(), "farcast-apps")
	restored, err := second.Restore(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	if !restored {
		t.Fatal("the checkpoint was not restored")
	}
	if second.Observed.Pods != first.Observed.Pods || second.Observed.At.IsZero() {
		t.Errorf("the observation did not survive the restart: %+v", second.Observed)
	}
}

// An instance running nothing is a real state, and it is not the same as a
// kernel that has stopped looking. Both show zero pods; only one has a
// timestamp that keeps moving.
func TestAnEmptyClusterStillPublishesAnObservation(t *testing.T) {
	f := &fakeCluster{byNS: map[string][]kube.Pod{"farcast-apps": nil}}
	r := reconciler(t, f, "farcast-apps")
	if _, err := r.Reconcile(context.Background(), start); err != nil {
		t.Fatal(err)
	}
	if r.Observed.At.IsZero() {
		t.Error("an instance running nothing published no observation at all")
	}
	if r.Observed.Pods != 0 || r.Observed.RateHourlyUSD != 0 {
		t.Errorf("an empty cluster reported %+v", r.Observed)
	}
}
