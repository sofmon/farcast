package kernel

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/technocore/kube"
	"github.com/sofmon/farcast/technocore/tier"
)

// overLimit drives an instance past its limit and returns the tick's report.
func overLimit(t *testing.T, f *fakeCluster, namespaces ...string) (*Reconciler, Report) {
	t.Helper()
	r := reconciler(t, f, namespaces...)
	r.Limit = 0.0001
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
	return r, rep
}

func mixedInstance() *fakeCluster {
	return &fakeCluster{
		byNS: map[string][]kube.Pod{
			"farcast-system": {
				pod("fatline-1", "farcast-system", "fatline", tier.System, kube.PodRunning, "100m", "128Mi"),
				pod("tc-1", "farcast-system", "technocore", tier.Kernel, kube.PodRunning, "100m", "128Mi"),
			},
			"farcast-apps": {
				pod("small-1", "farcast-apps", "small", tier.App, kube.PodRunning, "100m", "128Mi"),
				pod("big-1", "farcast-apps", "big", tier.App, kube.PodRunning, "2", "4Gi"),
				pod("myst-1", "farcast-apps", "mystery", tier.Unknown, kube.PodRunning, "500m", "1Gi"),
			},
		},
		depsNS: map[string][]kube.Deployment{
			"farcast-system": {
				deployment("fatline", "farcast-system", "fatline", tier.System, 2),
				deployment("technocore", "farcast-system", "technocore", tier.Kernel, 1),
			},
			"farcast-apps": {
				deployment("small", "farcast-apps", "small", tier.App, 1),
				deployment("big", "farcast-apps", "big", tier.App, 3),
				deployment("mystery", "farcast-apps", "mystery", tier.Unknown, 1),
			},
		},
	}
}

// The rule ADR 0008 found and ADR 0009 decision 6 encodes: a cost shutdown
// stops applications and nothing else. Stopping the tunnel would leave storage
// impossible to unseal while the instance carried on billing.
func TestShutdownStopsApplicationsAndNothingElse(t *testing.T) {
	f := mixedInstance()
	r, rep := overLimit(t, f, "farcast-system", "farcast-apps")

	res, err := r.Shutdown(context.Background(), rep, start.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Stopped) != 2 {
		t.Fatalf("stopped %d targets, want the 2 applications: %+v", len(res.Stopped), res.Stopped)
	}
	for _, call := range f.scaled {
		if strings.HasPrefix(call, "farcast-system/") {
			t.Errorf("a cost shutdown scaled %q; the system tier is last-to-die", call)
		}
		if strings.Contains(call, "mystery") {
			t.Error("an unclassified workload was stopped; the tie must go to not stopping")
		}
	}
	// Expensive first, so a partial failure leaves the costly ones stopped.
	if f.scaled[0] != "farcast-apps/big=0" {
		t.Errorf("first scale was %q, want the most expensive application", f.scaled[0])
	}
	if res.Unclassified != 1 {
		t.Errorf("Unclassified = %d, want 1 — the operator should know the shutdown was partial", res.Unclassified)
	}
	if res.StoppedUSDPerHour() <= 0 {
		t.Error("stopping two running applications removed no burn rate")
	}
}

// Everything TechnoCore writes is a zero. Bringing an application back up is
// an operator decision, and nothing in the kernel can make it.
func TestShutdownOnlyEverScalesToZero(t *testing.T) {
	f := mixedInstance()
	r, rep := overLimit(t, f, "farcast-system", "farcast-apps")
	if _, err := r.Shutdown(context.Background(), rep, start); err != nil {
		t.Fatal(err)
	}
	for _, call := range f.scaled {
		if !strings.HasSuffix(call, "=0") {
			t.Errorf("scale call %q writes a non-zero replica count", call)
		}
	}
}

// Warn on a projection, act on an accrual. A caller reaching for a shutdown
// on a forecast has a bug, and a bug that stops applications should be
// impossible to overlook.
func TestShutdownRefusesWithoutAuthorisation(t *testing.T) {
	f := mixedInstance()
	r := reconciler(t, f, "farcast-apps")
	r.Limit = 1e9 // nowhere near
	if _, err := r.Reconcile(context.Background(), start); err != nil {
		t.Fatal(err)
	}
	rep, err := r.Reconcile(context.Background(), start.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Assessment.Level.Acts() {
		t.Fatal("test setup: the limit should not be reached")
	}
	res, err := r.Shutdown(context.Background(), rep, start)
	if !errors.Is(err, ErrNotAuthorised) {
		t.Fatalf("err = %v, want ErrNotAuthorised", err)
	}
	if len(res.Stopped) != 0 || len(f.scaled) != 0 {
		t.Errorf("an unauthorised shutdown touched the cluster: %v", f.scaled)
	}
}

// A shutdown is not atomic. One failing scale call must not abort the rest —
// the whole point of the ordering is that the expensive ones go first and the
// remainder are still attempted.
func TestShutdownContinuesPastAFailureAndReportsIt(t *testing.T) {
	f := mixedInstance()
	f.scaleAt = map[string]error{"farcast-apps/big": errors.New("forbidden")}
	r, rep := overLimit(t, f, "farcast-system", "farcast-apps")

	res, err := r.Shutdown(context.Background(), rep, start)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Failed) != 1 || res.Failed[0].Target.Name != "big" {
		t.Fatalf("Failed = %+v, want the one refused target", res.Failed)
	}
	if len(res.Stopped) != 1 || res.Stopped[0].Name != "small" {
		t.Errorf("Stopped = %+v, want the other application still stopped", res.Stopped)
	}
	// A failed scale is a problem to report, not evidence the instance has
	// run out of options.
	if res.AtFloor {
		t.Error("a failed scale call must not be reported as the instance floor")
	}
}

// A deployment already at zero is not scaled again on every tick.
func TestShutdownSkipsWhatIsAlreadyStopped(t *testing.T) {
	f := mixedInstance()
	f.depsNS["farcast-apps"] = []kube.Deployment{
		deployment("small", "farcast-apps", "small", tier.App, 0),
		deployment("big", "farcast-apps", "big", tier.App, 0),
	}
	r, rep := overLimit(t, f, "farcast-system", "farcast-apps")
	res, err := r.Shutdown(context.Background(), rep, start)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.scaled) != 0 {
		t.Errorf("re-scaled workloads already at zero: %v", f.scaled)
	}
	if !res.AtFloor {
		t.Error("with every application already stopped, the instance is at its floor")
	}
}

// Decision 8: at the floor the kernel reports and does not reach for the
// levers that destroy capability or data.
func TestAtTheFloorTheKernelReportsWhatIsStillBurning(t *testing.T) {
	f := &fakeCluster{
		byNS: map[string][]kube.Pod{"farcast-system": {
			pod("fatline-1", "farcast-system", "fatline", tier.System, kube.PodRunning, "100m", "128Mi"),
			pod("tc-1", "farcast-system", "technocore", tier.Kernel, kube.PodRunning, "100m", "128Mi"),
		}},
		depsNS: map[string][]kube.Deployment{"farcast-system": {
			deployment("fatline", "farcast-system", "fatline", tier.System, 2),
		}},
	}
	r, rep := overLimit(t, f, "farcast-system")
	res, err := r.Shutdown(context.Background(), rep, start)
	if err != nil {
		t.Fatal(err)
	}
	if !res.AtFloor || len(res.Stopped) != 0 {
		t.Fatalf("expected the floor with nothing stopped, got %+v", res)
	}
	if len(f.scaled) != 0 {
		t.Errorf("the kernel scaled something at the floor: %v", f.scaled)
	}
	// The floor is reported as a number, not a shrug.
	if rep.SystemProtected() <= 0 {
		t.Error("SystemProtected must say what the instance still burns")
	}
	if len(rep.Protected()) == 0 {
		t.Error("Protected must name what is still running and why")
	}
}

// The floor means "there was nothing left to stop", not "nothing was stopped".
// An instance whose every scale call was refused has plenty left to stop and a
// permissions problem — reporting that as the floor would tell the operator
// the kernel had done all it could when it had in fact done nothing.
func TestEveryScaleFailingIsNotTheFloor(t *testing.T) {
	f := mixedInstance()
	f.scaleAt = map[string]error{
		"farcast-apps/big":   errors.New("forbidden"),
		"farcast-apps/small": errors.New("forbidden"),
	}
	r, rep := overLimit(t, f, "farcast-system", "farcast-apps")

	res, err := r.Shutdown(context.Background(), rep, start)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Stopped) != 0 || len(res.Failed) != 2 {
		t.Fatalf("expected two failures and nothing stopped, got %+v", res)
	}
	if res.AtFloor {
		t.Error("every scale call failing is a permissions problem, not the instance floor")
	}
}
