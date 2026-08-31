package pricing

import (
	"math"
	"testing"
)

func closeTo(t *testing.T, got, want float64, what string) {
	t.Helper()
	if math.Abs(got-want) > 0.01 {
		t.Errorf("%s = %.4f, want %.4f", what, got, want)
	}
}

// The arithmetic, checked against ADR 0003's rate card by hand rather than
// against the implementation: 0.1 vCPU * $0.0445 * 730 + 0.125 GiB * $0.0049 *
// 730. Every system Pod FarCast deploys requests exactly this.
func TestPodMonthlyUSDMatchesTheRateCardByHand(t *testing.T) {
	closeTo(t, PodMonthlyUSD(100, 128), 3.6956, "100m/128Mi per month")
	closeTo(t, PodMonthlyUSDNoBursting(100, 128), 9.9098, "100m/128Mi without bursting")
}

// The bug this package was written to stop repeating: two replicas of the
// keyholder are ~$7.39/month, not the ~$4 a call site quoted after copying
// ADR 0008 decision 6's marginal figure.
func TestWorkloadCostIsNotTheMarginalReplicaCost(t *testing.T) {
	pair := WorkloadMonthlyUSD(2, 100, 128)
	marginal := MarginalReplicaMonthlyUSD(100, 128)
	closeTo(t, pair, 7.3912, "two replicas")
	closeTo(t, marginal, 3.6956, "one more replica")
	if pair <= marginal {
		t.Fatalf("a pair (%.2f) must cost more than one more replica (%.2f)", pair, marginal)
	}
	if math.Abs(pair-2*marginal) > 0.01 {
		t.Errorf("the pair should be exactly twice the marginal replica; got %.4f vs %.4f", pair, 2*marginal)
	}
}

// A Pod under the per-Pod floor is billed at the floor. Quoting its declared
// request would report a price nobody is charged — in the flattering
// direction, which is the one this project treats as the real failure.
func TestRequestsBelowTheFloorAreBilledAtTheFloor(t *testing.T) {
	tiny := PodMonthlyUSD(1, 1)
	floor := PodMonthlyUSD(BurstingMinCPUMilli, BurstingMinMemMiB)
	closeTo(t, tiny, floor, "a 1m/1Mi Pod")
	if tiny <= 0 {
		t.Fatal("a Pod that runs is never free")
	}

	// And the two floors are genuinely different prices, which is why a
	// single estimate cannot cover both cluster kinds.
	if PodMonthlyUSDNoBursting(1, 1) <= tiny {
		t.Error("the no-bursting floor must cost more than the bursting floor")
	}
}

// Above the floor, the declared request is what is billed — the floor must not
// leak into the arithmetic as a constant addition.
func TestRequestsAboveTheFloorAreBilledAsDeclared(t *testing.T) {
	closeTo(t, PodMonthlyUSD(1000, 1024), (1*VCPUHourUSD+1*GiBHourUSD)*HoursPerMonth, "1 vCPU / 1 GiB")
	// Doubling a request above the floor doubles the price.
	closeTo(t, PodMonthlyUSD(2000, 2048), 2*PodMonthlyUSD(1000, 1024), "2 vCPU / 2 GiB")
}

func TestReplicaCountsThatCannotBillAreFree(t *testing.T) {
	for _, n := range []int{0, -1} {
		if got := WorkloadMonthlyUSD(n, 100, 128); got != 0 {
			t.Errorf("WorkloadMonthlyUSD(%d) = %.4f, want 0", n, got)
		}
	}
}

// HoursPerMonth is the billing convention. 720 (30 days) would understate
// every monthly figure by 1.4%, always downward.
func TestMonthIsSevenThirtyHours(t *testing.T) {
	if HoursPerMonth != 730 {
		t.Fatalf("HoursPerMonth = %d, want 730 (365*24/12)", HoursPerMonth)
	}
}
