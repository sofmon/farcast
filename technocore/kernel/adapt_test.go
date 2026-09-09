package kernel

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/technocore/kube"
	"github.com/sofmon/farcast/technocore/tier"
	"github.com/sofmon/farcast/technocore/usage"
)

// profiled seeds a reconciler with a settled profile for one application:
// well-covered, and using far less than it reserves.
func profiled(t *testing.T, r *Reconciler, at time.Time, app string, cpu, mem, reqCPU, reqMem int) {
	t.Helper()
	if r.Usage == nil {
		r.Usage = usage.New(24)
	}
	for i := 0; i < usage.MinSamples; i++ {
		r.Usage.Record(at, app, []usage.PodUsage{
			{Pod: app + "-1", CPUMilli: cpu, MemMiB: mem, RequestCPUMilli: reqCPU, RequestMemMiB: reqMem},
		})
	}
}

// podFor builds an app pod with one named container.
func podFor(name, ns, app string, tr tier.Tier, cpu, mem string) kube.Pod {
	p := pod(name, ns, app, tr, kube.PodRunning, cpu, mem)
	p.Spec.Containers[0].Name = app
	return p
}

func adviseOnce(t *testing.T, f *fakeCluster, now time.Time, setup func(*Reconciler)) (*Reconciler, []Adaptation) {
	t.Helper()
	r := reconciler(t, f, "farcast-apps")
	r.Usage = usage.New(24)
	if setup != nil {
		setup(r)
	}
	rep, err := r.Reconcile(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	return r, r.Advise(rep, now)
}

// The same reasoning that stops a cost shutdown touching FatLine: an operator
// recovers an instance THROUGH the tunnel and the key holder, and a kernel
// that could resize them could take away the means of fixing its own mistake.
func TestOnlyApplicationsAreEverResized(t *testing.T) {
	now := start.Add(time.Hour)
	f := &fakeCluster{
		byNS: map[string][]kube.Pod{"farcast-apps": {
			podFor("web-1", "farcast-apps", "web", tier.App, "500m", "512Mi"),
			podFor("fl-1", "farcast-apps", "fatline", tier.System, "500m", "512Mi"),
			podFor("tc-1", "farcast-apps", "technocore", tier.Kernel, "500m", "512Mi"),
		}},
		depsNS: map[string][]kube.Deployment{"farcast-apps": {
			deployment("web", "farcast-apps", "web", tier.App, 1),
			deployment("fatline", "farcast-apps", "fatline", tier.System, 2),
			deployment("technocore", "farcast-apps", "technocore", tier.Kernel, 1),
		}},
	}
	_, advice := adviseOnce(t, f, now, func(r *Reconciler) {
		for _, app := range []string{"web", "fatline", "technocore"} {
			profiled(t, r, now, app, 40, 60, 500, 512)
		}
	})
	if len(advice) != 1 || advice[0].App != "web" {
		t.Fatalf("advised %+v, want only the application tier", advice)
	}
	if !advice[0].Act {
		t.Errorf("an application using 40m of 500m was not advised: %+v", advice[0])
	}
}

// ADR 0014 decision 3's stated revisit trigger, firing: the profile is per
// POD, so on a multi-container pod nothing can say which container's
// reservation the measurement justifies.
func TestAMultiContainerPodIsHeldRatherThanGuessed(t *testing.T) {
	now := start.Add(time.Hour)
	p := podFor("web-1", "farcast-apps", "web", tier.App, "500m", "512Mi")
	p.Spec.Containers = append(p.Spec.Containers, kube.Container{
		Name:      "sidecar",
		Resources: kube.ResourceRequirements{Requests: kube.ResourceList{CPU: "50m", Memory: "64Mi"}},
	})
	f := &fakeCluster{
		byNS:   map[string][]kube.Pod{"farcast-apps": {p}},
		depsNS: map[string][]kube.Deployment{"farcast-apps": {deployment("web", "farcast-apps", "web", tier.App, 1)}},
	}
	_, advice := adviseOnce(t, f, now, func(r *Reconciler) { profiled(t, r, now, "web", 40, 60, 550, 576) })
	if len(advice) != 1 {
		t.Fatalf("advised %+v", advice)
	}
	if advice[0].Act {
		t.Errorf("resized a multi-container pod: %+v", advice[0])
	}
	if !strings.Contains(advice[0].Hold, "2 containers") {
		t.Errorf("hold is %q, want it to name the shape it cannot size", advice[0].Hold)
	}
}

// A workload the kernel is deliberately leaving alone is what an operator
// staring at an over-provisioned application needs to see. Omitting it would
// make "nothing to do" and "not considered" identical.
func TestAWorkloadWithNoProfileIsReportedNotOmitted(t *testing.T) {
	now := start.Add(time.Hour)
	f := &fakeCluster{
		byNS:   map[string][]kube.Pod{"farcast-apps": {podFor("web-1", "farcast-apps", "web", tier.App, "500m", "512Mi")}},
		depsNS: map[string][]kube.Deployment{"farcast-apps": {deployment("web", "farcast-apps", "web", tier.App, 1)}},
	}
	_, advice := adviseOnce(t, f, now, nil) // no profile seeded
	if len(advice) != 1 || advice[0].Act {
		t.Fatalf("advised %+v", advice)
	}
	if !strings.Contains(advice[0].Hold, "no usage profile") {
		t.Errorf("hold is %q", advice[0].Hold)
	}
}

// Every resize is a rollout, and the profile justifying the next one has to
// be built from readings taken after the last. The stamp lives on the object
// so a restarted kernel can still see it.
func TestACooldownIsReadFromTheWorkloadItself(t *testing.T) {
	now := start.Add(48 * time.Hour)
	d := deployment("web", "farcast-apps", "web", tier.App, 1)
	d.Metadata.Annotations = map[string]string{AdaptedAtLabel: now.Add(-time.Hour).Format(time.RFC3339)}
	f := &fakeCluster{
		byNS:   map[string][]kube.Pod{"farcast-apps": {podFor("web-1", "farcast-apps", "web", tier.App, "500m", "512Mi")}},
		depsNS: map[string][]kube.Deployment{"farcast-apps": {d}},
	}
	_, advice := adviseOnce(t, f, now, func(r *Reconciler) { profiled(t, r, now, "web", 40, 60, 500, 512) })
	if advice[0].Act {
		t.Fatalf("resized a workload changed an hour ago: %+v", advice[0])
	}
	if !strings.Contains(advice[0].Hold, "resized recently") {
		t.Errorf("hold is %q", advice[0].Hold)
	}

	// A stamp older than the cooldown does not hold it back.
	d.Metadata.Annotations[AdaptedAtLabel] = now.Add(-24 * time.Hour).Format(time.RFC3339)
	f.depsNS["farcast-apps"] = []kube.Deployment{d}
	_, advice = adviseOnce(t, f, now, func(r *Reconciler) { profiled(t, r, now, "web", 40, 60, 500, 512) })
	if !advice[0].Act {
		t.Errorf("a stamp a day old still held the workload: %+v", advice[0])
	}

	// A stamp nobody can parse is "never resized" — a typo must not freeze a
	// reservation forever, which is worse than one extra rollout.
	d.Metadata.Annotations[AdaptedAtLabel] = "yesterday-ish"
	f.depsNS["farcast-apps"] = []kube.Deployment{d}
	_, advice = adviseOnce(t, f, now, func(r *Reconciler) { profiled(t, r, now, "web", 40, 60, 500, 512) })
	if !advice[0].Act {
		t.Errorf("an unparseable stamp froze the reservation: %+v", advice[0])
	}
}

// The cost pillar applied to the one code path in TechnoCore that can make an
// instance cost MORE. The operator approved a limit, not an open budget.
func TestAnIncreaseIsRefusedWhenItWouldReachTheLimit(t *testing.T) {
	now := start.Add(time.Hour)
	f := &fakeCluster{
		byNS:   map[string][]kube.Pod{"farcast-apps": {podFor("web-1", "farcast-apps", "web", tier.App, "100m", "128Mi")}},
		depsNS: map[string][]kube.Deployment{"farcast-apps": {deployment("web", "farcast-apps", "web", tier.App, 1)}},
	}
	// A workload wanting far more than it has, on an instance with almost no
	// room left in its limit.
	r, advice := adviseOnce(t, f, now, func(r *Reconciler) {
		r.Limit = 0.01
		profiled(t, r, now, "web", 5000, 6000, 100, 128)
	})
	_ = r
	if advice[0].Act {
		t.Fatalf("grew a reservation on an instance at its limit: %+v", advice[0])
	}
	if !strings.Contains(advice[0].Hold, "on course to reach its limit") {
		t.Errorf("hold is %q", advice[0].Hold)
	}

	// The same shortfall on an instance with room is acted on.
	_, advice = adviseOnce(t, f, now, func(r *Reconciler) {
		r.Limit = 1000
		profiled(t, r, now, "web", 5000, 6000, 100, 128)
	})
	if !advice[0].Act {
		t.Errorf("an instance with room still refused to grow a starved workload: %+v", advice[0])
	}
}

// Shrinking saves money, so the cost gate must never stand in its way — not
// even on an instance already over its limit, where shrinking is the only
// thing that helps.
func TestShrinkingIsNeverBlockedByCost(t *testing.T) {
	now := start.Add(time.Hour)
	f := &fakeCluster{
		byNS:   map[string][]kube.Pod{"farcast-apps": {podFor("web-1", "farcast-apps", "web", tier.App, "2000m", "2048Mi")}},
		depsNS: map[string][]kube.Deployment{"farcast-apps": {deployment("web", "farcast-apps", "web", tier.App, 1)}},
	}
	_, advice := adviseOnce(t, f, now, func(r *Reconciler) {
		r.Limit = 0.01 // hopelessly over
		profiled(t, r, now, "web", 40, 60, 2000, 2048)
	})
	if !advice[0].Act || advice[0].CPUMilli >= 2000 {
		t.Fatalf("an over-limit instance refused to shrink an idle workload: %+v", advice[0])
	}
}

func TestAdaptPatchesTheNamedContainerAndStampsTheWorkload(t *testing.T) {
	now := start.Add(time.Hour)
	f := &fakeCluster{
		byNS:   map[string][]kube.Pod{"farcast-apps": {podFor("web-1", "farcast-apps", "web", tier.App, "500m", "512Mi")}},
		depsNS: map[string][]kube.Deployment{"farcast-apps": {deployment("web", "farcast-apps", "web", tier.App, 1)}},
	}
	r, advice := adviseOnce(t, f, now, func(r *Reconciler) { profiled(t, r, now, "web", 40, 60, 500, 512) })
	res := r.Adapt(context.Background(), advice, now)
	if len(res.Applied) != 1 || len(res.Failed) != 0 {
		t.Fatalf("applied %+v failed %+v", res.Applied, res.Failed)
	}
	if len(f.resized) != 1 || !strings.HasPrefix(f.resized[0], "farcast-apps/web:web=") {
		t.Fatalf("resized %v, want the named container patched", f.resized)
	}
	anns := f.resizeAnns["farcast-apps/web"]
	if anns[AdaptedAtLabel] == "" {
		t.Error("the resize left no record of when it happened")
	}
	if anns[AdaptedFromLabel] != "500m/512Mi" {
		t.Errorf("the resize recorded %q as the previous reservation", anns[AdaptedFromLabel])
	}
}

// Independent changes: one deployment the kernel cannot patch must not freeze
// every other application's reservation.
func TestOneFailedResizeDoesNotStopTheRest(t *testing.T) {
	now := start.Add(time.Hour)
	f := &fakeCluster{
		byNS: map[string][]kube.Pod{"farcast-apps": {
			podFor("web-1", "farcast-apps", "web", tier.App, "500m", "512Mi"),
			podFor("api-1", "farcast-apps", "api", tier.App, "500m", "512Mi"),
		}},
		depsNS: map[string][]kube.Deployment{"farcast-apps": {
			deployment("web", "farcast-apps", "web", tier.App, 1),
			deployment("api", "farcast-apps", "api", tier.App, 1),
		}},
		resizeErr: map[string]error{"farcast-apps/web": errors.New("forbidden")},
	}
	r, advice := adviseOnce(t, f, now, func(r *Reconciler) {
		profiled(t, r, now, "web", 40, 60, 500, 512)
		profiled(t, r, now, "api", 40, 60, 500, 512)
	})
	res := r.Adapt(context.Background(), advice, now)
	if len(res.Applied) != 1 || res.Applied[0].App != "api" {
		t.Errorf("applied %+v, want api to have gone through", res.Applied)
	}
	if len(res.Failed) != 1 || res.Failed[0].Adaptation.App != "web" {
		t.Errorf("failed %+v", res.Failed)
	}
}

// Nothing is written unless the caller asks. Advise is the read half and must
// have no side effects at all.
func TestAdviseWritesNothing(t *testing.T) {
	now := start.Add(time.Hour)
	f := &fakeCluster{
		byNS:   map[string][]kube.Pod{"farcast-apps": {podFor("web-1", "farcast-apps", "web", tier.App, "500m", "512Mi")}},
		depsNS: map[string][]kube.Deployment{"farcast-apps": {deployment("web", "farcast-apps", "web", tier.App, 1)}},
	}
	_, advice := adviseOnce(t, f, now, func(r *Reconciler) { profiled(t, r, now, "web", 40, 60, 500, 512) })
	if !advice[0].Act {
		t.Fatal("expected advice to act, so the absence of a write means something")
	}
	if len(f.resized) != 0 || len(f.scaled) != 0 {
		t.Errorf("Advise wrote to the cluster: resized=%v scaled=%v", f.resized, f.scaled)
	}
}

// Collection off means the whole feature is off.
func TestWithNoProfilesThereIsNoAdvice(t *testing.T) {
	now := start.Add(time.Hour)
	f := &fakeCluster{
		byNS:   map[string][]kube.Pod{"farcast-apps": {podFor("web-1", "farcast-apps", "web", tier.App, "500m", "512Mi")}},
		depsNS: map[string][]kube.Deployment{"farcast-apps": {deployment("web", "farcast-apps", "web", tier.App, 1)}},
	}
	r := reconciler(t, f, "farcast-apps") // r.Usage stays nil
	rep, err := r.Reconcile(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Advise(rep, now); got != nil {
		t.Errorf("advised %+v with collection off", got)
	}
}

// A held advice must not describe a target it no longer carries. The 5.2
// walk's published document showed a cooled-down workload still flagged as
// "a bounded step", which reads as something about to happen.
func TestAHeldAdviceCarriesNoTargetAndNoStep(t *testing.T) {
	now := start.Add(48 * time.Hour)
	d := deployment("web", "farcast-apps", "web", tier.App, 1)
	d.Metadata.Annotations = map[string]string{AdaptedAtLabel: now.Add(-time.Minute).Format(time.RFC3339)}
	f := &fakeCluster{
		byNS:   map[string][]kube.Pod{"farcast-apps": {podFor("web-1", "farcast-apps", "web", tier.App, "4000m", "4096Mi")}},
		depsNS: map[string][]kube.Deployment{"farcast-apps": {d}},
	}
	_, advice := adviseOnce(t, f, now, func(r *Reconciler) { profiled(t, r, now, "web", 10, 10, 4000, 4096) })
	got := advice[0]
	if got.Act {
		t.Fatalf("the cooldown did not hold: %+v", got)
	}
	if got.Stepped {
		t.Error("a held advice is flagged as a bounded step")
	}
	if got.CPUMilli != got.CurrentCPUMilli || got.MemMiB != got.CurrentMemMiB {
		t.Errorf("a held advice carries a target: %+v", got)
	}
}

// The 5.2 walk watched the kernel ask Autopilot for 25m, be answered 200, and
// announce a resize to 25m — while the cluster had already replaced it with
// its own 50m floor, in the pod template. It then read 50m back and asked
// again on the next cooldown, forever. What is reported has to be what the
// cluster KEPT.
func TestAResizeReportsWhatTheClusterKept(t *testing.T) {
	now := start.Add(time.Hour)
	f := &fakeCluster{
		byNS:   map[string][]kube.Pod{"farcast-apps": {podFor("web-1", "farcast-apps", "web", tier.App, "500m", "512Mi")}},
		depsNS: map[string][]kube.Deployment{"farcast-apps": {deployment("web", "farcast-apps", "web", tier.App, 1)}},
		// An admission controller with a floor of its own.
		storeCPU: 250, storeMem: 512,
	}
	r, advice := adviseOnce(t, f, now, func(r *Reconciler) { profiled(t, r, now, "web", 40, 60, 500, 512) })
	asked := advice[0].CPUMilli
	res := r.Adapt(context.Background(), advice, now)
	if len(res.Applied) != 1 {
		t.Fatalf("applied %+v", res.Applied)
	}
	got := res.Applied[0]
	if !got.Overridden {
		t.Error("an override went unreported")
	}
	if got.CPUMilli != 250 || got.MemMiB != 512 {
		t.Errorf("reported %dm/%dMi, want what the cluster kept (250m/512Mi)", got.CPUMilli, got.MemMiB)
	}
	if got.AskedCPUMilli != asked {
		t.Errorf("the asked-for value was lost: %dm, want %dm", got.AskedCPUMilli, asked)
	}
}

// The ordinary case must not be reported as an override.
func TestAnAcceptedResizeIsNotAnOverride(t *testing.T) {
	now := start.Add(time.Hour)
	f := &fakeCluster{
		byNS:   map[string][]kube.Pod{"farcast-apps": {podFor("web-1", "farcast-apps", "web", tier.App, "500m", "512Mi")}},
		depsNS: map[string][]kube.Deployment{"farcast-apps": {deployment("web", "farcast-apps", "web", tier.App, 1)}},
	}
	r, advice := adviseOnce(t, f, now, func(r *Reconciler) { profiled(t, r, now, "web", 40, 60, 500, 512) })
	res := r.Adapt(context.Background(), advice, now)
	if res.Applied[0].Overridden {
		t.Error("a resize the cluster accepted was reported as an override")
	}
}
