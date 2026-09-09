package adapt

import (
	"strings"
	"testing"

	"github.com/sofmon/farcast/technocore/usage"
)

// summary builds a profile with enough readings to be acted on.
func summary(app string, reqCPU, reqMem int, cpuP95, cpuPeak, memP95, memPeak int) usage.Summary {
	return usage.Summary{
		App:             app,
		Pods:            1,
		RequestCPUMilli: reqCPU,
		RequestMemMiB:   reqMem,
		CPU:             usage.Windows{Day: usage.Stat{Samples: usage.MinSamples, P95: cpuP95, Peak: cpuPeak}},
		Mem:             usage.Windows{Day: usage.Stat{Samples: usage.MinSamples, P95: memP95, Peak: memPeak}},
	}
}

// The load-bearing asymmetry: CPU is a rate and memory is a level. A process
// at the 95th percentile of its CPU is briefly throttled; a process at the
// 95th percentile of its memory is killed one time in twenty.
func TestMemoryIsSizedFromThePeakAndCPUFromThePercentile(t *testing.T) {
	// A workload that idles but spikes: the p95 sits far below the peak in
	// both dimensions, so a package that used the same statistic for both
	// could not be told apart from one that does not. Sized so neither the
	// step clamp nor the floors bind, and the two dimensions move opposite
	// ways — which is itself the asymmetry, visible.
	s := summary("api", 500, 512, 200, 450, 200, 400)
	got := Recommend(s, Config{})
	if !got.Act {
		t.Fatalf("no advice: %+v", got)
	}
	if want := 260; got.CPUMilli != want { // p95 200 * 1.3
		t.Errorf("cpu is %dm, want %dm — the p95 with headroom", got.CPUMilli, want)
	}
	if want := 600; got.MemMiB != want { // PEAK 400 * 1.5, not the p95's 300
		t.Errorf("memory is %dMi, want %dMi — the PEAK with headroom, not the p95's 300", got.MemMiB, want)
	}
}

func TestThinCoverageIsRefusedAndSaysWhatItIsWaitingFor(t *testing.T) {
	s := summary("api", 100, 128, 10, 20, 10, 20)
	s.CPU.Day.Samples = 3
	s.Mem.Day.Samples = 3
	got := Recommend(s, Config{})
	if got.Act {
		t.Fatalf("acted on three readings: %+v", got)
	}
	if !strings.Contains(got.Hold, "readings") || !strings.Contains(got.Hold, "needed") {
		t.Errorf("hold is %q, want it to name what it is waiting for", got.Hold)
	}
	// An advice that does not act must not carry a half-formed target.
	if got.CPUMilli != s.RequestCPUMilli || got.MemMiB != s.RequestMemMiB {
		t.Errorf("a declining advice carries a target: %+v", got)
	}
}

// Every resize is a rollout. A workload re-rolled for a 5% correction is a
// workload restarted for nothing.
func TestASmallDifferenceIsNotWorthARollout(t *testing.T) {
	// 100m reserved, p95 75m → target 97m, inside the deadband.
	s := summary("api", 100, 128, 75, 80, 80, 85)
	got := Recommend(s, Config{})
	if got.Act {
		t.Fatalf("rolled a workload for a small correction: %+v", got)
	}
	if !strings.Contains(got.Hold, "already within") {
		t.Errorf("hold is %q", got.Hold)
	}
}

// A profile built on a quiet hour must not be able to collapse a workload in
// one move, and one built on a spike must not multiply the bill.
func TestOneAdjustmentIsBounded(t *testing.T) {
	down := Recommend(summary("api", 4000, 4096, 10, 20, 10, 20), Config{})
	if !down.Act || !down.Stepped {
		t.Fatalf("a huge drop was not clamped: %+v", down)
	}
	if down.CPUMilli != 2000 || down.MemMiB != 2048 {
		t.Errorf("clamped to %dm/%dMi, want half of the current reservation", down.CPUMilli, down.MemMiB)
	}

	up := Recommend(summary("api", 100, 128, 5000, 6000, 5000, 6000), Config{})
	if !up.Act || !up.Stepped {
		t.Fatalf("a huge rise was not clamped: %+v", up)
	}
	if up.CPUMilli != 200 || up.MemMiB != 256 {
		t.Errorf("clamped to %dm/%dMi, want double the current reservation", up.CPUMilli, up.MemMiB)
	}
}

// An idle process still has to start. A reservation small enough to make
// start-up fail turns an over-provisioned application into a broken one.
func TestNothingIsSizedBelowTheFloors(t *testing.T) {
	// Repeatedly apply until it settles, so the step clamp cannot hide the
	// floor by never reaching it.
	cur := summary("idle", 4000, 4096, 0, 0, 0, 0)
	for i := 0; i < 20; i++ {
		got := Recommend(cur, Config{})
		if !got.Act {
			break
		}
		cur.RequestCPUMilli, cur.RequestMemMiB = got.CPUMilli, got.MemMiB
	}
	t.Logf("a workload using nothing settled at %dm/%dMi", cur.RequestCPUMilli, cur.RequestMemMiB)
	if cur.RequestCPUMilli < MinCPUMilli || cur.RequestMemMiB < MinMemMiB {
		t.Fatalf("settled at %dm/%dMi, below the floors %dm/%dMi",
			cur.RequestCPUMilli, cur.RequestMemMiB, MinCPUMilli, MinMemMiB)
	}
	// It settles just above the floor rather than on it, because the last
	// step down is inside the deadband — the two guards meeting, not one of
	// them failing. Sizing to within a hair of the floor would cost a rollout
	// to save nothing.
	if cur.RequestCPUMilli > 2*MinCPUMilli || cur.RequestMemMiB > 2*MinMemMiB {
		t.Errorf("settled at %dm/%dMi, further above the floors than one deadband explains",
			cur.RequestCPUMilli, cur.RequestMemMiB)
	}
}

// Stepping must converge rather than oscillate: repeated evaluation has to
// reach a resting point and stay there.
func TestRepeatedAdjustmentConverges(t *testing.T) {
	cases := []struct {
		name                     string
		cpuP95, cpuPeak, memPeak int
	}{
		{"over-provisioned", 40, 60, 100},
		{"under-provisioned", 900, 1200, 900},
		{"about right", 70, 90, 90},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cur := summary("api", 500, 512, tc.cpuP95, tc.cpuPeak, tc.cpuP95, tc.memPeak)
			var last Advice
			steps := 0
			for i := 0; i < 25; i++ {
				last = Recommend(cur, Config{})
				if !last.Act {
					break
				}
				steps++
				cur.RequestCPUMilli, cur.RequestMemMiB = last.CPUMilli, last.MemMiB
			}
			if last.Act {
				t.Fatalf("still moving after %d adjustments: now %dm/%dMi", steps, cur.RequestCPUMilli, cur.RequestMemMiB)
			}
			t.Logf("settled at %dm/%dMi after %d adjustments (%s)",
				cur.RequestCPUMilli, cur.RequestMemMiB, steps, last.Hold)
			// And the resting point must still cover the peak.
			if cur.RequestMemMiB < tc.memPeak {
				t.Errorf("settled at %dMi, below the observed peak of %dMi", cur.RequestMemMiB, tc.memPeak)
			}
		})
	}
}

func TestAnUnknownReservationIsNothingToChangeFrom(t *testing.T) {
	s := summary("api", 0, 0, 10, 20, 10, 20)
	got := Recommend(s, Config{})
	if got.Act || !strings.Contains(got.Hold, "nothing to change from") {
		t.Errorf("advice is %+v", got)
	}
}

func TestTheSavingIsReportedAsANegativeDelta(t *testing.T) {
	got := Recommend(summary("api", 500, 512, 40, 60, 40, 60), Config{})
	if !got.Act {
		t.Fatal("no advice")
	}
	if d := got.MonthlyDeltaUSD(); d >= 0 {
		t.Errorf("shrinking a reservation reported a delta of %v, want a saving", d)
	}
	grew := Recommend(summary("api", 100, 128, 500, 600, 500, 600), Config{})
	if d := grew.MonthlyDeltaUSD(); d <= 0 {
		t.Errorf("growing a reservation reported a delta of %v, want a cost", d)
	}
}
