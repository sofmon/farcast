package kernel

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/technocore/kube"
	"github.com/sofmon/farcast/technocore/tier"
	"github.com/sofmon/farcast/technocore/usage"
)

func reading(name, ns, cpu, mem string, at time.Time) kube.PodMetrics {
	return kube.PodMetrics{
		Metadata:  kube.ObjectMeta{Name: name, Namespace: ns},
		Timestamp: at,
		Window:    "20s",
		Containers: []kube.ContainerMetrics{
			{Name: "c", Usage: kube.ResourceList{CPU: cpu, Memory: mem}},
		},
	}
}

// Usage collection is off unless a store is attached, and turning it off must
// not change a single thing about metering.
func TestWithNoStoreNothingIsEvenAsked(t *testing.T) {
	f := &fakeCluster{byNS: map[string][]kube.Pod{
		"farcast-apps": {pod("web-1", "farcast-apps", "web", tier.App, kube.PodRunning, "100m", "128Mi")},
	}}
	r := reconciler(t, f, "farcast-apps")

	rep, err := r.Reconcile(context.Background(), start.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.metricsHit) != 0 {
		t.Errorf("the metrics API was called %d times with collection off", len(f.metricsHit))
	}
	if rep.UsageSampled != 0 || len(rep.UsageUnavailable) != 0 {
		t.Errorf("report claims usage: %+v", rep)
	}
}

func TestReadingsAreProfiledPerApplication(t *testing.T) {
	now := start.Add(time.Hour)
	f := &fakeCluster{
		byNS: map[string][]kube.Pod{"farcast-apps": {
			pod("web-1", "farcast-apps", "web", tier.App, kube.PodRunning, "500m", "512Mi"),
			pod("web-2", "farcast-apps", "web", tier.App, kube.PodRunning, "500m", "512Mi"),
		}},
		metricsNS: map[string][]kube.PodMetrics{"farcast-apps": {
			reading("web-1", "farcast-apps", "40m", "100Mi", now),
			reading("web-2", "farcast-apps", "60m", "120Mi", now),
		}},
	}
	r := reconciler(t, f, "farcast-apps")
	r.Usage = usage.New(24)

	rep, err := r.Reconcile(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if rep.UsageSampled != 2 {
		t.Fatalf("sampled %d readings, want 2", rep.UsageSampled)
	}
	if len(f.metricsHit) != 1 || !strings.HasPrefix(f.metricsHit[0], "farcast-apps|") {
		t.Errorf("metrics were asked for as %v", f.metricsHit)
	}
	if !strings.Contains(f.metricsHit[0], ManagedBy) {
		t.Errorf("metrics were asked for without the managed-by selector: %q", f.metricsHit[0])
	}

	sums := r.Usage.Summarize(now)
	if len(sums) != 1 || sums[0].App != "web" {
		t.Fatalf("profiled %+v, want one application called web", sums)
	}
	got := sums[0]
	if got.Pods != 2 {
		t.Errorf("pods is %d, want 2", got.Pods)
	}
	// One pod's worth, not the sum of the replicas.
	if got.CPU.Day.Peak != 60 {
		t.Errorf("peak CPU is %dm, want one pod's 60m rather than both pods' 100m", got.CPU.Day.Peak)
	}
	if got.RequestCPUMilli != 500 || got.RequestMemMiB != 512 {
		t.Errorf("request recorded as %dm/%dMi, want 500m/512Mi", got.RequestCPUMilli, got.RequestMemMiB)
	}
}

// The meter is the authority on what exists. A reading for a pod it did not
// see is dropped rather than filed under a guessed application.
func TestAReadingForAnUnmeteredPodIsDropped(t *testing.T) {
	now := start.Add(time.Hour)
	f := &fakeCluster{
		byNS: map[string][]kube.Pod{"farcast-apps": {
			pod("web-1", "farcast-apps", "web", tier.App, kube.PodRunning, "500m", "512Mi"),
		}},
		metricsNS: map[string][]kube.PodMetrics{"farcast-apps": {
			reading("web-1", "farcast-apps", "40m", "100Mi", now),
			reading("stranger", "farcast-apps", "900m", "900Mi", now),
		}},
	}
	r := reconciler(t, f, "farcast-apps")
	r.Usage = usage.New(24)

	rep, err := r.Reconcile(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if rep.UsageSampled != 1 {
		t.Fatalf("sampled %d readings, want only the metered one", rep.UsageSampled)
	}
	if got := r.Usage.Apps(); got != 1 {
		t.Errorf("profiled %d applications, want 1", got)
	}
}

// metrics-server serves the same reading until it refreshes. Counting the
// repeat would weight the distribution toward whatever the sampler caught.
func TestAnUnrefreshedReadingIsNotCountedTwice(t *testing.T) {
	taken := start.Add(30 * time.Minute)
	f := &fakeCluster{
		byNS: map[string][]kube.Pod{"farcast-apps": {
			pod("web-1", "farcast-apps", "web", tier.App, kube.PodRunning, "500m", "512Mi"),
		}},
		metricsNS: map[string][]kube.PodMetrics{"farcast-apps": {
			reading("web-1", "farcast-apps", "40m", "100Mi", taken),
		}},
	}
	r := reconciler(t, f, "farcast-apps")
	r.Usage = usage.New(24)

	now := start.Add(time.Hour)
	for i := 0; i < 3; i++ {
		if _, err := r.Reconcile(context.Background(), now.Add(time.Duration(i)*30*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if got := r.Usage.Summarize(now)[0].CPU.Day.Samples; got != 1 {
		t.Errorf("took %d samples from one unrefreshed reading, want 1", got)
	}

	// A refreshed reading is a new sample.
	f.metricsNS["farcast-apps"] = []kube.PodMetrics{
		reading("web-1", "farcast-apps", "80m", "100Mi", taken.Add(time.Minute)),
	}
	if _, err := r.Reconcile(context.Background(), now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := r.Usage.Summarize(now)[0].CPU.Day.Samples; got != 2 {
		t.Errorf("a refreshed reading gave %d samples, want 2", got)
	}
}

// The asymmetry with metering, stated as a test: every namespace refusing
// metrics is still only a finding. Metering that reads nothing is fatal
// because it would report $0 for an instance that is spending; a profile that
// reads nothing means a resize declines, which is the safe direction.
func TestNoMetricsAPIAtAllIsAFindingNotAFault(t *testing.T) {
	now := start.Add(time.Hour)
	f := &fakeCluster{byNS: map[string][]kube.Pod{"farcast-apps": {
		pod("web-1", "farcast-apps", "web", tier.App, kube.PodRunning, "500m", "512Mi"),
	}}} // metricsNS nil: no metrics API
	r := reconciler(t, f, "farcast-apps")
	r.Usage = usage.New(24)

	rep, err := r.Reconcile(context.Background(), now)
	if err != nil {
		t.Fatalf("a cluster with no metrics API failed the tick: %v", err)
	}
	if len(rep.Workloads) != 1 || rep.RateHourlyUSD == 0 {
		t.Errorf("metering was affected: %d workloads at %v/h", len(rep.Workloads), rep.RateHourlyUSD)
	}
	if len(rep.UsageUnavailable) != 1 || !strings.Contains(rep.UsageUnavailable[0], "farcast-apps") {
		t.Errorf("unavailable is %v, want the namespace named", rep.UsageUnavailable)
	}
}

// A namespace whose pods could not be listed is not asked for metrics: it
// contributed no workloads, so any reading from it could not be attributed.
func TestAnUnreadableNamespaceIsNotAskedForMetrics(t *testing.T) {
	now := start.Add(time.Hour)
	f := &fakeCluster{
		byNS: map[string][]kube.Pod{"farcast-system": {
			pod("fatline-1", "farcast-system", "fatline", tier.System, kube.PodRunning, "100m", "128Mi"),
		}},
		nsErr:     map[string]error{"farcast-apps": kube.ErrForbidden},
		metricsNS: map[string][]kube.PodMetrics{},
	}
	r := reconciler(t, f, "farcast-system", "farcast-apps")
	r.Usage = usage.New(24)

	if _, err := r.Reconcile(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	for _, hit := range f.metricsHit {
		if strings.HasPrefix(hit, "farcast-apps|") {
			t.Errorf("metrics were asked for in a namespace whose pods could not be listed: %v", f.metricsHit)
		}
	}
}

func TestAnUnreadableReadingIsSkippedNotFatal(t *testing.T) {
	now := start.Add(time.Hour)
	f := &fakeCluster{
		byNS: map[string][]kube.Pod{"farcast-apps": {
			pod("web-1", "farcast-apps", "web", tier.App, kube.PodRunning, "500m", "512Mi"),
		}},
		metricsNS: map[string][]kube.PodMetrics{"farcast-apps": {
			reading("web-1", "farcast-apps", "12X", "100Mi", now),
		}},
	}
	r := reconciler(t, f, "farcast-apps")
	r.Usage = usage.New(24)

	rep, err := r.Reconcile(context.Background(), now)
	if err != nil {
		t.Fatalf("an unreadable quantity failed the tick: %v", err)
	}
	if rep.UsageSampled != 0 || len(rep.UsageUnavailable) != 1 {
		t.Errorf("sampled %d and reported %v", rep.UsageSampled, rep.UsageUnavailable)
	}
}

// fakeProfiles is a ProfileStore that records what it was given.
type fakeProfiles struct {
	doc      Profiles
	has      bool
	loadErr  error
	saveErr  error
	maxBytes int
	saves    int
}

func (f *fakeProfiles) Load(context.Context) (Profiles, bool, error) {
	return f.doc, f.has, f.loadErr
}

func (f *fakeProfiles) Save(_ context.Context, p Profiles) error {
	f.saves++
	if f.saveErr != nil {
		return f.saveErr
	}
	f.doc, f.has = p, true
	return nil
}

func (f *fakeProfiles) Budget() int {
	if f.maxBytes > 0 {
		return f.maxBytes
	}
	return usage.DefaultBudget
}

func TestProfilesSurviveARestart(t *testing.T) {
	now := start.Add(time.Hour)
	store := &fakeProfiles{}
	r := reconciler(t, &fakeCluster{}, "farcast-apps")
	r.Usage = usage.New(24)
	r.Usage.Record(now, "web", []usage.PodUsage{{CPUMilli: 40, MemMiB: 100, RequestCPUMilli: 500, RequestMemMiB: 512}})

	if err := r.SaveUsage(context.Background(), store, now); err != nil {
		t.Fatal(err)
	}
	if store.doc.At != now || store.doc.Version != ProfilesVersion {
		t.Errorf("document is %+v", store.doc)
	}

	next := reconciler(t, &fakeCluster{}, "farcast-apps")
	next.Usage = usage.New(24)
	restored, err := next.RestoreUsage(context.Background(), store)
	if err != nil || !restored {
		t.Fatalf("restore returned %v, %v", restored, err)
	}
	sums := next.Usage.Summarize(now)
	if len(sums) != 1 || sums[0].CPU.Day.Peak != 40 {
		t.Errorf("restored %+v", sums)
	}
}

// The opposite of the ledger, and deliberately: an unreadable checkpoint is
// fatal because carrying on from zero would silently reset the meter. An
// unreadable usage document costs a day of advisory history, so the caller is
// told and carries on.
func TestAnUnreadableUsageDocumentIsReportedNotFatal(t *testing.T) {
	store := &fakeProfiles{loadErr: errors.New("decode: unexpected end of JSON input")}
	r := reconciler(t, &fakeCluster{}, "farcast-apps")
	fresh := usage.New(24)
	r.Usage = fresh

	restored, err := r.RestoreUsage(context.Background(), store)
	if restored {
		t.Error("claimed to restore a document it could not read")
	}
	if err == nil {
		t.Fatal("the caller was not told the document was discarded")
	}
	if r.Usage != fresh {
		t.Error("the usable, empty store was replaced by something else")
	}
}

func TestNoStoreMeansNothingIsSavedOrLoaded(t *testing.T) {
	store := &fakeProfiles{}
	r := reconciler(t, &fakeCluster{}, "farcast-apps") // r.Usage is nil
	if err := r.SaveUsage(context.Background(), store, start); err != nil {
		t.Fatal(err)
	}
	if _, err := r.RestoreUsage(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	if store.saves != 0 || store.has {
		t.Errorf("a kernel with collection off wrote %d documents", store.saves)
	}
}

// A published document that is short because the budget shortened it must say
// so, or a reader concludes the instance has only just started.
func TestATrimmedDocumentSaysItWasTrimmed(t *testing.T) {
	now := start.Add(24 * time.Hour)
	store := &fakeProfiles{maxBytes: 2000}
	r := reconciler(t, &fakeCluster{}, "farcast-apps")
	r.Usage = usage.New(24)
	for h := 0; h < 24; h++ {
		when := now.Add(time.Duration(h) * time.Hour)
		for _, app := range []string{"alpha", "beta"} {
			for i := 0; i < 30; i++ {
				r.Usage.Record(when, app, []usage.PodUsage{
					{CPUMilli: 10 + i*17, MemMiB: 20 + i*11, RequestCPUMilli: 500, RequestMemMiB: 512},
				})
			}
		}
	}
	if err := r.SaveUsage(context.Background(), store, now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	blob, err := json.Marshal(store.doc)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("document is %d bytes, trimmed to %dh, dropped %v", len(blob), store.doc.TrimmedTo, store.doc.Dropped)
	if store.doc.TrimmedTo == 0 && len(store.doc.Dropped) == 0 {
		t.Error("the document fitted a 2000-byte budget without saying anything was given up")
	}
	if store.doc.TrimmedTo >= 24 {
		t.Errorf("trimmed_to is %d, want a shortened window", store.doc.TrimmedTo)
	}
}

// An application gone for longer than the window leaves an empty shell that
// would otherwise accumulate for the life of the instance.
func TestSavingForgetsWhatHasAgedOut(t *testing.T) {
	store := &fakeProfiles{}
	r := reconciler(t, &fakeCluster{}, "farcast-apps")
	r.Usage = usage.New(24)
	r.Usage.Record(start, "gone", []usage.PodUsage{{CPUMilli: 1}})
	r.Usage.Record(start.Add(48*time.Hour), "here", []usage.PodUsage{{CPUMilli: 1}})

	if err := r.SaveUsage(context.Background(), store, start.Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.doc.Store.Profiles["gone"]; ok {
		t.Error("an application last seen two days ago is still in the document")
	}
	if _, ok := store.doc.Store.Profiles["here"]; !ok {
		t.Error("the application seen this hour was forgotten")
	}
}
