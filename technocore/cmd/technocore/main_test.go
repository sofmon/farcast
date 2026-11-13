package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/technocore/cost"
	"github.com/sofmon/farcast/technocore/kernel"
	"github.com/sofmon/farcast/technocore/kube"
	"github.com/sofmon/farcast/technocore/tier"
	"github.com/sofmon/farcast/technocore/usage"
)

// A value outside the bounds is refused before the kernel reaches for the
// cluster: these run outside one, so getting as far as the in-cluster client
// would fail with something else entirely.
func TestServeRefusesAnIntervalOrCooldownOutsideTheBounds(t *testing.T) {
	base := []string{"serve", "--instance=x", "--cost-limit=1"}
	for flag, value := range map[string]string{
		"--interval":       "1s",
		"--adapt-cooldown": "10s",
	} {
		err := run(append(base, flag+"="+value))
		if err == nil || !strings.Contains(err.Error(), flag) {
			t.Errorf("%s=%s = %v; want a refusal naming the flag", flag, value, err)
		}
	}
	if err := run(append(base, "--interval=-1s")); err == nil || !strings.Contains(err.Error(), "negative") {
		t.Errorf("a negative interval = %v; want it refused", err)
	}
}

// A tick where every reading was one the metrics server had not refreshed is
// the dedupe working, and it has to reach the log for anyone to see it.
func TestATickOfUnrefreshedReadingsIsLogged(t *testing.T) {
	var buf bytes.Buffer
	s := &supervisor{
		log:             slog.New(slog.NewTextHandler(&buf, nil)),
		reconciler:      &kernel.Reconciler{},
		checkpointEvery: time.Hour,
		lastCheckpoint:  time.Now(),
	}
	s.observe(kernel.Report{UsageRepeated: 3}, nil)
	if !strings.Contains(buf.String(), "observed usage") || !strings.Contains(buf.String(), "unrefreshed=3") {
		t.Errorf("a tick of unrefreshed readings was not logged:\n%s", buf.String())
	}
}

// stopCluster is one application over its limit: the slice of a cluster a
// supervisor test needs, and nothing else. Once scaled to zero it lists the
// Deployment at zero and its Pod gone, as a cluster would.
type stopCluster struct{ scaled []string }

func (c *stopCluster) stopped() bool { return slices.Contains(c.scaled, "apps/web=0") }

func (c *stopCluster) ListPods(_ context.Context, ns, _ string) ([]kube.Pod, error) {
	if ns != "apps" || c.stopped() {
		return nil, nil
	}
	return []kube.Pod{{
		Metadata: kube.ObjectMeta{Name: "web-1", Namespace: "apps", Labels: map[string]string{
			"app.kubernetes.io/name": "web", tier.Label: string(tier.App)}},
		Spec: kube.PodSpec{Containers: []kube.Container{{Name: "web",
			Resources: kube.ResourceRequirements{Requests: kube.ResourceList{CPU: "1", Memory: "1Gi"}}}}},
		Status: kube.PodStatus{Phase: kube.PodRunning},
	}}, nil
}

func (c *stopCluster) ListDeployments(_ context.Context, ns, _ string) ([]kube.Deployment, error) {
	if ns != "apps" {
		return nil, nil
	}
	one := 1
	if c.stopped() {
		one = 0
	}
	return []kube.Deployment{{
		Metadata: kube.ObjectMeta{Name: "web", Namespace: "apps", Labels: map[string]string{tier.Label: string(tier.App)}},
		Spec: kube.DeploymentSpec{Replicas: &one,
			Selector: &kube.LabelSelector{MatchLabels: map[string]string{"app.kubernetes.io/name": "web"}}},
	}}, nil
}

func (c *stopCluster) ListPodMetrics(context.Context, string, string) ([]kube.PodMetrics, error) {
	return nil, kube.ErrNotFound
}

func (c *stopCluster) Scale(_ context.Context, ns, name string, replicas int) error {
	c.scaled = append(c.scaled, fmt.Sprintf("%s/%s=%d", ns, name, replicas))
	return nil
}

func (c *stopCluster) SetRequests(context.Context, string, string, string, int, int, map[string]string) (int, int, error) {
	return 0, 0, errors.New("not in this test")
}

func (c *stopCluster) GetService(context.Context, string, string) (*kube.Service, error) {
	return nil, kube.ErrNotFound
}

// order records which store was written, in sequence.
type order struct{ writes []string }

type ledgerStore struct {
	o   *order
	cps []kernel.Checkpoint
	// fail is how many of the next writes are refused.
	fail int
}

func (s *ledgerStore) Load(context.Context) (kernel.Checkpoint, bool, error) {
	return kernel.Checkpoint{}, false, nil
}

func (s *ledgerStore) Save(_ context.Context, cp kernel.Checkpoint) error {
	if s.fail > 0 {
		s.fail--
		s.o.writes = append(s.o.writes, "ledger refused")
		return errors.New("the API server is unavailable")
	}
	s.o.writes = append(s.o.writes, "ledger")
	s.cps = append(s.cps, cp)
	return nil
}

type profileStore struct{ o *order }

func (s *profileStore) Load(context.Context) (kernel.Profiles, bool, error) {
	return kernel.Profiles{}, false, nil
}

func (s *profileStore) Save(context.Context, kernel.Profiles) error {
	s.o.writes = append(s.o.writes, "profiles")
	return nil
}

func (s *profileStore) Budget() int { return usage.DefaultBudget }

// A stop is written to the checkpoint on the tick that made it, not on the
// five-minute schedule: a kernel that crashed in between would come back with
// no record of why the application is stopped. The off-schedule write is the
// ledger alone — the profiles hold no record of a stop, and wait for the
// schedule rather than add a second write the provider's audit log dates.
func TestAStopIsCheckpointedAtOnceLedgerFirst(t *testing.T) {
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	ledger, err := cost.NewLedger(start, start.AddDate(0, 1, 0))
	if err != nil {
		t.Fatal(err)
	}
	c := &stopCluster{}
	r := &kernel.Reconciler{Cluster: c, Namespaces: []string{"apps"}, Ledger: ledger, Limit: 0.0001,
		Interval: 30 * time.Second, Usage: usage.New(24)}
	o := &order{}
	store := &ledgerStore{o: o}
	var buf bytes.Buffer
	s := &supervisor{
		log: slog.New(slog.NewTextHandler(&buf, nil)), reconciler: r, store: store, profiles: &profileStore{o: o},
		enforce: true, checkpointEvery: 24 * time.Hour,
	}

	// The first tick bills nothing and takes the scheduled checkpoint.
	rep, err := r.Reconcile(context.Background(), start)
	if err != nil {
		t.Fatal(err)
	}
	s.observe(rep, nil)
	if len(store.cps) != 1 {
		t.Fatalf("the first tick wrote %d checkpoints, want the scheduled one", len(store.cps))
	}

	// An hour later the limit is passed. The schedule says not yet; the stop
	// says now.
	rep, err = r.Reconcile(context.Background(), start.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Assessment.Level.Acts() {
		t.Fatalf("guard: level %v does not act", rep.Assessment.Level)
	}
	s.observe(rep, nil)
	if len(c.scaled) != 1 || c.scaled[0] != "apps/web=0" {
		t.Fatalf("scaled %v", c.scaled)
	}
	if len(store.cps) != 2 {
		t.Fatalf("after the stop, %d checkpoints were written; want the stop saved at once", len(store.cps))
	}
	stops := store.cps[1].Stops
	if len(stops) != 1 || stops[0].Namespace != "apps" || stops[0].Deployment != "web" ||
		stops[0].Reason != kernel.StopReasonCostGuard || !stops[0].At.Equal(start.Add(time.Hour)) {
		t.Errorf("the saved checkpoint holds %+v", stops)
	}
	if !slices.Equal(o.writes, []string{"ledger", "profiles", "ledger"}) {
		t.Errorf("writes went %v; want the scheduled pair, then the ledger alone for the stop", o.writes)
	}
}

// At the floor the log names the levers the kernel records, and the floor
// newly reached is saved at once too.
func TestTheFloorIsLoggedWithItsLeversAndSavedAtOnce(t *testing.T) {
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	ledger, err := cost.NewLedger(start, start.AddDate(0, 1, 0))
	if err != nil {
		t.Fatal(err)
	}
	c := &stopCluster{}
	r := &kernel.Reconciler{Cluster: c, Namespaces: []string{"apps"}, Ledger: ledger, Limit: 0.0001, Interval: 30 * time.Second}
	o := &order{}
	store := &ledgerStore{o: o}
	var buf bytes.Buffer
	s := &supervisor{log: slog.New(slog.NewTextHandler(&buf, nil)), reconciler: r, store: store, enforce: true, checkpointEvery: 24 * time.Hour}
	for i, at := range []time.Duration{0, time.Hour} {
		rep, err := r.Reconcile(context.Background(), start.Add(at))
		if err != nil {
			t.Fatal(err)
		}
		s.observe(rep, nil)
		if i == 1 && len(store.cps) != 2 {
			t.Fatalf("the stop was not saved at once: %d checkpoints", len(store.cps))
		}
	}
	// The next tick finds web at zero and nothing else to stop: the floor.
	rep, err := r.Reconcile(context.Background(), start.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	s.observe(rep, nil)
	if len(store.cps) != 3 || store.cps[2].Floor == nil || len(store.cps[2].Stops) != 1 {
		t.Fatalf("the floor was not saved at once: %d checkpoints, last %+v", len(store.cps), store.cps[len(store.cps)-1])
	}
	if !strings.Contains(buf.String(), "at the instance floor") || !strings.Contains(buf.String(), "release the instance") {
		t.Errorf("the floor was not logged with its levers:\n%s", buf.String())
	}
}

// A write of the stop that fails is tried again on the next tick, not left
// for the schedule: the record is what a crash in between would lose. The
// schedule itself is not moved, and the ledger is still written before the
// profiles whenever both are.
func TestARefusedWriteOfAStopIsTriedAgainOnTheNextTick(t *testing.T) {
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	ledger, err := cost.NewLedger(start, start.AddDate(0, 1, 0))
	if err != nil {
		t.Fatal(err)
	}
	c := &stopCluster{}
	r := &kernel.Reconciler{Cluster: c, Namespaces: []string{"apps"}, Ledger: ledger, Limit: 0.0001,
		Interval: 30 * time.Second, Usage: usage.New(24)}
	o := &order{}
	store := &ledgerStore{o: o}
	var buf bytes.Buffer
	s := &supervisor{
		log: slog.New(slog.NewTextHandler(&buf, nil)), reconciler: r, store: store, profiles: &profileStore{o: o},
		enforce: true, checkpointEvery: 24 * time.Hour,
	}
	tick := func(at time.Duration) {
		t.Helper()
		rep, err := r.Reconcile(context.Background(), start.Add(at))
		if err != nil {
			t.Fatal(err)
		}
		s.observe(rep, nil)
	}

	tick(0)
	store.fail = 1
	tick(time.Hour)
	if len(c.scaled) != 1 || len(store.cps) != 1 || !s.unsaved {
		t.Fatalf("scaled %v, %d written, unsaved %v; want the stop made and its write refused", c.scaled, len(store.cps), s.unsaved)
	}

	// Spending is no longer over — a confirmation, a larger limit — so
	// there is no shutdown on this tick and nothing new to record. The
	// refused write is made all the same.
	r.Limit = 1e9
	tick(time.Hour + time.Minute)
	if len(store.cps) != 2 || s.unsaved {
		t.Fatalf("%d written, unsaved %v; want the refused write made on the next tick", len(store.cps), s.unsaved)
	}
	stops := store.cps[1].Stops
	if len(stops) != 1 || stops[0].Deployment != "web" || !stops[0].At.Equal(start.Add(time.Hour)) {
		t.Errorf("the retried checkpoint holds %+v", stops)
	}
	if !slices.Equal(o.writes, []string{"ledger", "profiles", "ledger refused", "ledger"}) {
		t.Errorf("writes went %v", o.writes)
	}

	// Written, it is not written again off the schedule.
	tick(time.Hour + 2*time.Minute)
	if len(o.writes) != 4 {
		t.Errorf("a tick with nothing new wrote again: %v", o.writes)
	}
	if !s.lastCheckpoint.Equal(start) {
		t.Errorf("the schedule moved to %v; a stop's write adds one and moves none", s.lastCheckpoint)
	}
}
