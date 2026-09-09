package usage

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func find(t *testing.T, sums []Summary, app string) Summary {
	t.Helper()
	for _, s := range sums {
		if s.App == app {
			return s
		}
	}
	t.Fatalf("no summary for %q", app)
	return Summary{}
}

func pod(name string, cpu, mem int) PodUsage {
	return PodUsage{Pod: name, CPUMilli: cpu, MemMiB: mem, RequestCPUMilli: 500, RequestMemMiB: 512}
}

// The load-bearing decision in this package: a profile describes ONE pod.
// Summing three replicas and handing the total to a resize would reserve
// three times what a pod needs, on every pod.
func TestAProfileDescribesOnePodNotTheSumOfReplicas(t *testing.T) {
	s := New(24)
	now := at(3, 0)
	s.Record(now, "api", []PodUsage{pod("a", 100, 200), pod("b", 100, 200), pod("c", 100, 200)})

	sum := s.Summarize(now)
	if len(sum) != 1 {
		t.Fatalf("summarized %d applications, want 1", len(sum))
	}
	got := sum[0]
	if got.Pods != 3 {
		t.Errorf("pods is %d, want 3", got.Pods)
	}
	if got.CPU.Day.Samples != 3 {
		t.Errorf("samples is %d, want one per pod", got.CPU.Day.Samples)
	}
	if got.CPU.Day.Peak != 100 {
		t.Errorf("peak CPU is %d, want one pod's 100 rather than three pods' 300", got.CPU.Day.Peak)
	}
	if got.Mem.Day.Peak != 200 {
		t.Errorf("peak memory is %d, want one pod's 200", got.Mem.Day.Peak)
	}
}

// The request travels with the usage so the ratio between them means
// something, and it is the CURRENT request — a profile read after a resize
// must describe the reservation now in force.
func TestTheRecordedRequestIsTheCurrentOneNotTheLargestEver(t *testing.T) {
	s := New(24)
	s.Record(at(1, 0), "api", []PodUsage{{CPUMilli: 40, RequestCPUMilli: 1000, RequestMemMiB: 1024}})
	s.Record(at(2, 0), "api", []PodUsage{{CPUMilli: 40, RequestCPUMilli: 200, RequestMemMiB: 256}})

	got := s.Summarize(at(2, 30))[0]
	if got.RequestCPUMilli != 200 || got.RequestMemMiB != 256 {
		t.Errorf("request is %dm/%dMi, want the current 200m/256Mi", got.RequestCPUMilli, got.RequestMemMiB)
	}
}

// The largest across an application's pods, not the first one seen: a pod
// mid-rollout may still carry the old reservation.
func TestTheRequestIsTheLargestAcrossAnApplicationsPods(t *testing.T) {
	s := New(24)
	s.Record(at(1, 0), "api", []PodUsage{
		{CPUMilli: 10, RequestCPUMilli: 200, RequestMemMiB: 256},
		{CPUMilli: 10, RequestCPUMilli: 500, RequestMemMiB: 128},
	})
	got := s.Summarize(at(1, 30))[0]
	if got.RequestCPUMilli != 500 || got.RequestMemMiB != 256 {
		t.Errorf("request is %dm/%dMi, want 500m/256Mi", got.RequestCPUMilli, got.RequestMemMiB)
	}
}

func TestHeadroomRefusesWhatItCannotDivide(t *testing.T) {
	s := New(24)
	now := at(4, 0)
	// Too few samples to size anything from.
	s.Record(now, "thin", []PodUsage{pod("a", 100, 200)})
	if _, ok := find(t, s.Summarize(now), "thin").CPUHeadroom(); ok {
		t.Error("a single sample produced a headroom ratio")
	}

	// Enough samples, and a real request: the ratio is available.
	for i := 0; i < MinSamples; i++ {
		s.Record(now, "busy", []PodUsage{pod("a", 100, 256)})
	}
	got := find(t, s.Summarize(now), "busy")
	ratio, ok := got.CPUHeadroom()
	if !ok {
		t.Fatalf("no headroom for %d samples", got.CPU.Day.Samples)
	}
	if ratio < 4.5 || ratio > 5.1 {
		t.Errorf("headroom is %.2f, want about 5 (500m reserved against 100m used)", ratio)
	}

	// No request at all is not a ratio of infinity.
	for i := 0; i < MinSamples; i++ {
		s.Record(now, "unset", []PodUsage{{CPUMilli: 10}})
	}
	for _, sum := range s.Summarize(now) {
		if sum.App != "unset" {
			continue
		}
		if _, ok := sum.CPUHeadroom(); ok {
			t.Error("an application with no request produced a headroom ratio")
		}
	}
}

func TestRecordIgnoresNothingToRecord(t *testing.T) {
	s := New(24)
	s.Record(at(1, 0), "", []PodUsage{pod("a", 1, 1)})
	s.Record(at(1, 0), "api", nil)
	if s.Apps() != 0 {
		t.Errorf("recorded %d applications from nothing", s.Apps())
	}
}

func TestStoreSurvivesASnapshot(t *testing.T) {
	s := New(24)
	now := at(6, 0)
	for h := 0; h <= 6; h++ {
		s.Record(at(h, 0), "api", []PodUsage{pod("a", 100+h, 200+h)})
	}
	blob, err := json.Marshal(s.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var snap Snapshot
	if err := json.Unmarshal(blob, &snap); err != nil {
		t.Fatal(err)
	}
	back, err := Restore(snap)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := back.Summarize(now), s.Summarize(now); len(got) != len(want) || got[0] != want[0] {
		t.Errorf("round trip changed the profile:\n got %+v\nwant %+v", got, want)
	}
}

// These are advisory numbers that something else turns into a reservation.
// Half-understood ones are worse than none.
func TestASnapshotFromAnotherVersionIsRefused(t *testing.T) {
	_, err := Restore(Snapshot{Version: SnapshotVersion + 1})
	if err == nil || !strings.Contains(err.Error(), "this build reads") {
		t.Fatalf("error is %v, want a refusal naming both versions", err)
	}
}

func TestForgetDropsWhatHasNotBeenSeen(t *testing.T) {
	s := New(24)
	s.Record(at(1, 0), "gone", []PodUsage{pod("a", 1, 1)})
	s.Record(at(10, 0), "here", []PodUsage{pod("a", 1, 1)})
	if got := s.Forget(at(5, 0)); len(got) != 1 || got[0] != "gone" {
		t.Fatalf("forgot %v, want just [gone]", got)
	}
	if s.Apps() != 1 {
		t.Errorf("%d applications remain, want 1", s.Apps())
	}
}

// ADR 0014 decision 6: everybody loses an hour before anybody loses a
// profile. Dropping first would leave some applications perfect and others
// invisible, which is the worse of the two ways to be over budget.
func TestTrimShortensTheWindowBeforeDroppingAnybody(t *testing.T) {
	s := New(24)
	base := at(0, 0)
	for h := 0; h < 24; h++ {
		when := base.Add(time.Duration(h) * time.Hour)
		for _, app := range []string{"alpha", "beta", "gamma"} {
			for i := 0; i < 40; i++ {
				s.Record(when, app, []PodUsage{pod("p", 10+i*13, 50+i*7)})
			}
		}
	}
	full, err := json.Marshal(s.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	budget := len(full) / 3
	got, err := s.Trim(budget)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d bytes trimmed to %d within a %d budget, window now %dh", len(full), got.Bytes, budget, got.Hours)
	if got.Bytes > budget {
		t.Fatalf("trimmed to %d bytes, over the %d budget", got.Bytes, budget)
	}
	if len(got.Dropped) != 0 {
		t.Errorf("dropped %v while there was still window to give up", got.Dropped)
	}
	if got.Hours >= 24 || got.Hours < 1 {
		t.Errorf("window is %d hours, want it shortened but not gone", got.Hours)
	}
	if s.Apps() != 3 {
		t.Errorf("%d applications remain, want all 3", s.Apps())
	}
	if !got.Shortened(24) {
		t.Error("the trim reported nothing was given up")
	}
}

// Only when there is no window left to give up does an application go, and
// the least recently seen goes first.
func TestTrimDropsTheLeastRecentlySeenFirst(t *testing.T) {
	s := New(24)
	// All three inside one hour, so shortening the window costs nothing and
	// the trim has to reach for dropping.
	for i, app := range []string{"oldest", "middle", "newest"} {
		when := at(1, 10*i)
		for j := 0; j < 200; j++ {
			s.Record(when, app, []PodUsage{pod("p", 7+j*11, 3+j*5)})
		}
	}
	full, err := json.Marshal(s.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	budget := len(full) * 3 / 4
	got, err := s.Trim(budget)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d bytes trimmed to %d within a %d budget, dropped %v", len(full), got.Bytes, budget, got.Dropped)
	if got.Bytes > budget {
		t.Fatalf("trimmed to %d bytes, over the %d budget", got.Bytes, budget)
	}
	if len(got.Dropped) == 0 {
		t.Fatal("nothing was dropped, but the budget cannot hold all three")
	}
	if got.Dropped[0] != "oldest" {
		t.Errorf("dropped %q first, want the least recently seen", got.Dropped[0])
	}
	if s.Apps() == 0 {
		t.Error("everything was dropped for a budget that fits most of it")
	}
}

// A budget nothing can fit must terminate rather than spin.
func TestTrimStopsWhenThereIsNothingLeftToGiveUp(t *testing.T) {
	s := New(24)
	s.Record(at(1, 0), "api", []PodUsage{pod("a", 1, 1)})
	got, err := s.Trim(1)
	if err != nil {
		t.Fatal(err)
	}
	if s.Apps() != 0 || len(got.Dropped) != 1 {
		t.Errorf("store holds %d applications and dropped %v", s.Apps(), got.Dropped)
	}
}
