package cli

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
	"github.com/sofmon/farcast/technocore/kernel"
	"github.com/sofmon/farcast/technocore/usage"
)

// profilesFor builds a real kernel usage document through the real store, so
// this test cannot drift from what the kernel actually writes.
func profilesFor(t *testing.T, at time.Time, build func(*usage.Store), unavailable []string) string {
	t.Helper()
	store := usage.New(24)
	build(store)
	doc := kernel.Profiles{
		Version: kernel.ProfilesVersion, At: at, Store: store.Snapshot(), Unavailable: unavailable,
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func usageReader(t *testing.T, body string) *fakeReader {
	t.Helper()
	return &fakeReader{configMaps: map[string]string{
		tcdeploy.DefaultNamespace + "/" + kernel.DefaultProfilesName + "/" + kernel.ProfilesKey(): body,
	}}
}

func runUsage(t *testing.T, dir config.Dir, body string, mode output.Mode) string {
	t.Helper()
	env, out := testEnv(dir, mode)
	c := &usageCommand{}
	f := usageReader(t, body)
	c.newCluster = func(string) configMapReader { return f }
	if err := c.Run(context.Background(), env, []string{"p51"}); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestUsageReportsWhatOnePodUsedAgainstWhatItReserves(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p51")
	at := time.Date(2026, 9, 9, 12, 30, 0, 0, time.UTC)

	body := profilesFor(t, at, func(s *usage.Store) {
		for h := 0; h < 24; h++ {
			when := at.Add(-time.Duration(23-h) * time.Hour)
			for i := 0; i < 120; i++ {
				s.Record(when, "api", []usage.PodUsage{
					{Pod: "api-1", CPUMilli: 40, MemMiB: 110, RequestCPUMilli: 500, RequestMemMiB: 512},
					{Pod: "api-2", CPUMilli: 44, MemMiB: 118, RequestCPUMilli: 500, RequestMemMiB: 512},
				})
			}
		}
	}, nil)

	shown := runUsage(t, dir, body, output.ModeHuman)
	t.Log("\n" + shown)
	for _, want := range []string{"Observed usage", "24h window", "api", "500m", "512Mi", "ONE POD", "Phase 5.2"} {
		if !strings.Contains(shown, want) {
			t.Errorf("output is missing %q", want)
		}
	}
	// 500m reserved against a p95 of 44m is eleven times over, and 512Mi
	// against 118Mi is four. Both are what an operator would act on, so both
	// are asserted exactly rather than as "some ratio appeared".
	for _, want := range []string{"11.4x", "4.3x", "steady"} {
		if !strings.Contains(shown, want) {
			t.Errorf("output is missing the %q ratio", want)
		}
	}
}

// The distinction the whole command turns on: two pods using 40m each are a
// pod that uses 40m, not one that uses 80m.
func TestUsageNeverSumsReplicasIntoOnePod(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p51")
	at := time.Date(2026, 9, 9, 12, 30, 0, 0, time.UTC)

	body := profilesFor(t, at, func(s *usage.Store) {
		for i := 0; i < 200; i++ {
			s.Record(at, "api", []usage.PodUsage{
				{Pod: "api-1", CPUMilli: 40, MemMiB: 100, RequestCPUMilli: 500, RequestMemMiB: 512},
				{Pod: "api-2", CPUMilli: 40, MemMiB: 100, RequestCPUMilli: 500, RequestMemMiB: 512},
				{Pod: "api-3", CPUMilli: 40, MemMiB: 100, RequestCPUMilli: 500, RequestMemMiB: 512},
			})
		}
	}, nil)

	var res usageResult
	if err := json.Unmarshal([]byte(runUsage(t, dir, body, output.ModeJSON)), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Apps) != 1 {
		t.Fatalf("reported %d applications", len(res.Apps))
	}
	got := res.Apps[0]
	if got.Pods != 3 {
		t.Errorf("pods is %d, want 3", got.Pods)
	}
	if got.CPU.Day.P95 > 45 {
		t.Errorf("p95 is %dm — three pods at 40m were summed into one", got.CPU.Day.P95)
	}
}

// "Not measured" and "measured as zero" are different states, and an operator
// acting on the second when the first is true would draw exactly the wrong
// conclusion about an application that looks idle.
func TestUsageSaysWhatItCouldNotMeasure(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p51")
	at := time.Date(2026, 9, 9, 12, 30, 0, 0, time.UTC)

	body := profilesFor(t, at, func(*usage.Store) {}, []string{"farcast-apps: kube: object not found"})
	shown := runUsage(t, dir, body, output.ModeHuman)
	t.Log("\n" + shown)
	for _, want := range []string{"Not measured", "not the same as zero", "farcast-apps", "Redeploying the kernel"} {
		if !strings.Contains(shown, want) {
			t.Errorf("output is missing %q", want)
		}
	}
}

// Too few readings must read as "thin", never as a confident ratio built on
// three samples.
func TestUsageSaysThinRatherThanGuessing(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p51")
	at := time.Date(2026, 9, 9, 12, 30, 0, 0, time.UTC)

	body := profilesFor(t, at, func(s *usage.Store) {
		s.Record(at, "api", []usage.PodUsage{{Pod: "api-1", CPUMilli: 40, MemMiB: 100, RequestCPUMilli: 500, RequestMemMiB: 512}})
	}, nil)
	shown := runUsage(t, dir, body, output.ModeHuman)
	t.Log("\n" + shown)
	if !strings.Contains(shown, "thin") {
		t.Error("a single reading did not read as thin")
	}
	if !strings.Contains(shown, "collecting") {
		t.Error("the trend column claimed to know a direction from one reading")
	}
}

// A short window because the budget shortened it looks identical to an
// instance that just started, unless it says so.
func TestUsageSaysWhenTheBudgetShortenedTheWindow(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p51")
	at := time.Date(2026, 9, 9, 12, 30, 0, 0, time.UTC)

	store := usage.New(6)
	store.Record(at, "api", []usage.PodUsage{{CPUMilli: 40, RequestCPUMilli: 500}})
	doc := kernel.Profiles{
		Version: kernel.ProfilesVersion, At: at, Store: store.Snapshot(),
		TrimmedTo: 6, Dropped: []string{"batch"},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	shown := runUsage(t, dir, string(raw), output.ModeHuman)
	t.Log("\n" + shown)
	for _, want := range []string{"shortened to 6h", "size budget", "batch"} {
		if !strings.Contains(shown, want) {
			t.Errorf("output is missing %q", want)
		}
	}
}

func TestUsageRefusesAnInstanceWithNoKernel(t *testing.T) {
	dir := config.Dir(t.TempDir())
	buildableInstance(t, dir, "bare")
	env, _ := testEnv(dir, output.ModeHuman)
	c := &usageCommand{}
	c.newCluster = func(string) configMapReader { return &fakeReader{} }
	err := c.Run(context.Background(), env, []string{"bare"})
	if err == nil || !strings.Contains(err.Error(), "kernel deploy") {
		t.Fatalf("error is %v, want one naming the command that fixes it", err)
	}
}

func TestUsageSaysWhenNothingHasBeenWrittenYet(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p51")
	env, _ := testEnv(dir, output.ModeHuman)
	c := &usageCommand{}
	c.newCluster = func(string) configMapReader { return &fakeReader{cmMissing: true} }
	err := c.Run(context.Background(), env, []string{"p51"})
	if err == nil || !strings.Contains(err.Error(), "has not written any usage profiles yet") {
		t.Fatalf("error is %v", err)
	}
}

// A document from another build is refused rather than half-read: these
// numbers exist to become a resource reservation.
func TestUsageRefusesAnUnknownDocumentVersion(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meteringInstance(t, dir, "p51")
	env, _ := testEnv(dir, output.ModeHuman)
	c := &usageCommand{}
	f := usageReader(t, `{"version":99,"at":"2026-09-09T12:00:00Z","store":{"version":1,"hours":24}}`)
	c.newCluster = func(string) configMapReader { return f }
	err := c.Run(context.Background(), env, []string{"p51"})
	if err == nil || !strings.Contains(err.Error(), "older than the other") {
		t.Fatalf("error is %v", err)
	}
}
