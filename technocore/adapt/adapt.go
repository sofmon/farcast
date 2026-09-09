// Package adapt decides what an application's resource requests should be,
// given what it has actually used.
//
// It is pure arithmetic over a [usage.Summary] and the current reservation:
// no cluster, no clock, no side effects. That separation is the point —
// everything dangerous about resizing a running workload lives in the
// decision, and a decision that can be tested exhaustively without a cluster
// is one that can be argued about before it is trusted.
//
// [ADR 0016] is the specification. The one insight the rest follows from:
//
//	CPU is a rate. Memory is a level.
//
// A process sitting at the 95th percentile of its CPU usage is a process
// being briefly throttled, which is a latency cost and recoverable. A process
// sitting at the 95th percentile of its memory usage is a process that is
// killed 5% of the time. So CPU is sized from a percentile and memory is
// sized from the observed PEAK, and the two are not symmetric no matter how
// much tidier it would be if they were.
//
// [ADR 0016]: ../../docs/adr/0016-adaptive-resources.md
package adapt

import (
	"fmt"
	"math"

	"github.com/sofmon/farcast/technocore/pricing"
	"github.com/sofmon/farcast/technocore/usage"
)

// Defaults. Each is a judgement, and each is stated where it is made.
const (
	// DefaultCPUHeadroom multiplies the observed p95. A third again leaves
	// room for the ordinary variation a percentile already smoothed away.
	DefaultCPUHeadroom = 1.3

	// DefaultMemHeadroom multiplies the observed PEAK, not a percentile. It
	// is larger than the CPU factor because the failure it guards against is
	// a kill rather than a delay, and because a peak seen over a day is a
	// lower bound on the peak a week would show.
	DefaultMemHeadroom = 1.5

	// DefaultDeadband is how far the target must sit from the current
	// reservation before it is worth acting on. Every resize is a rollout,
	// and a workload that is re-rolled for a 5% correction is a workload
	// being restarted for nothing.
	DefaultDeadband = 0.25

	// DefaultMaxStep bounds one adjustment. A profile built on a quiet hour
	// must not be able to collapse a workload in a single move, and one
	// built on a spike must not be able to multiply the bill. Repeated ticks
	// converge; a single tick cannot leap.
	DefaultMaxStep = 2.0

	// MinCPUMilli and MinMemMiB are absolute floors. Nothing is sized below
	// them however little it appears to use — an idle process still has to
	// start, and a request small enough to make start-up fail turns an
	// over-provisioned application into a broken one.
	MinCPUMilli = 25
	MinMemMiB   = 64
)

// Config bounds what a recommendation may say. The zero value uses the
// defaults above.
type Config struct {
	CPUHeadroom float64
	MemHeadroom float64
	Deadband    float64
	MaxStep     float64
	MinCPUMilli int
	MinMemMiB   int
}

func (c Config) withDefaults() Config {
	if c.CPUHeadroom <= 0 {
		c.CPUHeadroom = DefaultCPUHeadroom
	}
	if c.MemHeadroom <= 0 {
		c.MemHeadroom = DefaultMemHeadroom
	}
	if c.Deadband <= 0 {
		c.Deadband = DefaultDeadband
	}
	if c.MaxStep <= 1 {
		c.MaxStep = DefaultMaxStep
	}
	if c.MinCPUMilli <= 0 {
		c.MinCPUMilli = MinCPUMilli
	}
	if c.MinMemMiB <= 0 {
		c.MinMemMiB = MinMemMiB
	}
	return c
}

// Advice is what one application's reservation should be, and why.
type Advice struct {
	App string `json:"app"`

	// CurrentCPUMilli and CurrentMemMiB are what one pod reserves now.
	CurrentCPUMilli int `json:"current_cpu_milli"`
	CurrentMemMiB   int `json:"current_mem_mib"`

	// CPUMilli and MemMiB are what it should reserve. When Act is false they
	// are the current values — an advice that does not act does not carry a
	// half-formed suggestion somebody could act on by mistake.
	CPUMilli int `json:"cpu_milli"`
	MemMiB   int `json:"mem_mib"`

	// Act says the reservation should change.
	Act bool `json:"act"`

	// Hold is why not, in the operator's language, and is empty when Act.
	// A recommendation that declines has to say what it is waiting for, or
	// an operator watching an over-provisioned workload never learns whether
	// the system is thinking or broken.
	Hold string `json:"hold,omitempty"`

	// Stepped records that the target was clamped by MaxStep, so the next
	// evaluation will move further in the same direction rather than this
	// being the final answer.
	Stepped bool `json:"stepped,omitempty"`
}

// MonthlyDeltaUSD is what acting would do to this workload's monthly bill,
// per pod. Negative is a saving.
func (a Advice) MonthlyDeltaUSD() float64 {
	return pricing.PodMonthlyUSD(a.CPUMilli, a.MemMiB) -
		pricing.PodMonthlyUSD(a.CurrentCPUMilli, a.CurrentMemMiB)
}

// Recommend decides what one application should reserve.
//
// It never returns an Act on coverage it considers too thin, and it never
// returns a target below the floors — both of which are refusals rather than
// approximations, because the cost of being wrong here is an application that
// stops working rather than a number that reads oddly.
func Recommend(s usage.Summary, cfg Config) Advice {
	cfg = cfg.withDefaults()
	a := Advice{
		App:             s.App,
		CurrentCPUMilli: s.RequestCPUMilli,
		CurrentMemMiB:   s.RequestMemMiB,
		CPUMilli:        s.RequestCPUMilli,
		MemMiB:          s.RequestMemMiB,
	}

	if s.RequestCPUMilli <= 0 || s.RequestMemMiB <= 0 {
		a.Hold = "the current reservation is unknown, so there is nothing to change from"
		return a
	}
	if s.CPU.Day.Thin() || s.Mem.Day.Thin() {
		a.Hold = fmt.Sprintf("only %d readings so far; %d are needed before sizing anything from them",
			min(s.CPU.Day.Samples, s.Mem.Day.Samples), usage.MinSamples)
		return a
	}

	// CPU from a percentile: brief excursions above it are throttling, which
	// costs latency and recovers.
	cpu := scale(s.CPU.Day.P95, cfg.CPUHeadroom, cfg.MinCPUMilli)
	// Memory from the PEAK: excursions above a memory reservation are not
	// throttled, they are killed. There is no percentile of a level that is
	// safe to reserve for.
	mem := scale(s.Mem.Day.Peak, cfg.MemHeadroom, cfg.MinMemMiB)

	cpu, cpuStepped := step(s.RequestCPUMilli, cpu, cfg.MaxStep, cfg.MinCPUMilli)
	mem, memStepped := step(s.RequestMemMiB, mem, cfg.MaxStep, cfg.MinMemMiB)

	cpuMoves := outsideDeadband(s.RequestCPUMilli, cpu, cfg.Deadband)
	memMoves := outsideDeadband(s.RequestMemMiB, mem, cfg.Deadband)
	if !cpuMoves && !memMoves {
		a.Hold = "the reservation is already within a quarter of what the workload uses"
		return a
	}

	// One of the two moving is enough to justify the rollout, and once a
	// rollout is happening both are set: leaving the other at a value this
	// package has already decided is wrong would mean re-rolling for it later.
	a.CPUMilli, a.MemMiB = cpu, mem
	a.Act = true
	a.Stepped = cpuStepped || memStepped
	return a
}

// scale applies headroom to an observation and floors it.
func scale(observed int, headroom float64, floor int) int {
	v := int(math.Ceil(float64(observed) * headroom))
	return max(v, floor)
}

// step clamps a target to within a factor of the current reservation.
func step(current, target int, maxStep float64, floor int) (int, bool) {
	upper := int(math.Ceil(float64(current) * maxStep))
	lower := max(int(math.Ceil(float64(current)/maxStep)), floor)
	switch {
	case target > upper:
		return upper, true
	case target < lower:
		return lower, true
	default:
		return target, false
	}
}

// outsideDeadband reports whether the target is far enough from the current
// reservation to be worth a rollout.
func outsideDeadband(current, target int, band float64) bool {
	if current <= 0 {
		return target > 0
	}
	return math.Abs(float64(target-current))/float64(current) > band
}
