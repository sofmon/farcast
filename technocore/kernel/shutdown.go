package kernel

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sofmon/farcast/technocore/tier"
)

// ErrNotAuthorised is returned when Shutdown is called against an assessment
// that does not authorise action.
//
// It is an error rather than a quiet no-op on purpose. [ADR 0009] decision 9
// says warn on a projection, act on an accrual — so a caller that reaches for
// a shutdown on a forecast has a bug, and a bug that stops an operator's
// applications should be impossible to overlook.
//
// [ADR 0009]: ../../docs/adr/0009-technocore-kernel-and-cost-metering.md
var ErrNotAuthorised = errors.New("kernel: the cost assessment does not authorise a shutdown")

// StopFailure records a target that could not be stopped.
type StopFailure struct {
	Target Target
	Err    error
}

// ShutdownResult is what a protective shutdown did.
type ShutdownResult struct {
	At      time.Time
	Stopped []Target
	Failed  []StopFailure

	// AtFloor is set when there was nothing left to stop and spending is
	// still over the limit. What remains is the instance's own standing
	// cost, and the levers that would reduce it — dropping the load-balancer
	// carrier, releasing the instance — destroy operator-visible capability
	// or data. Decision 8 says a kernel reports that rather than taking
	// either, so this field is the report.
	AtFloor bool

	// Unclassified is how many workloads carried no tier label and were
	// therefore protected rather than stopped. A non-zero value means the
	// shutdown was less effective than the operator may expect, and saying
	// so is the point.
	Unclassified int
}

// StoppedUSDPerHour is the burn rate this shutdown removed.
func (r ShutdownResult) StoppedUSDPerHour() float64 {
	var sum float64
	for _, t := range r.Stopped {
		sum += t.HourlyUSD
	}
	return sum
}

// Shutdown stops every stoppable application, most expensive first.
//
// Not "enough to get under the limit": by the time this runs the limit has
// already been reached, so the money is spent and every further dollar is an
// over-limit dollar. Ordering still matters because a shutdown is not atomic —
// if only some scale calls succeed, the ones that did should be the ones that
// were costing the most.
//
// It scales to zero and never to anything else. Bringing an operator's
// application back up is not a kernel's decision, and nothing here can make
// it: a `confirmed` correction that dropped accrued spend below the limit
// would leave the applications stopped and the operator informed, which is
// the right way round.
func (r *Reconciler) Shutdown(ctx context.Context, rep Report, now time.Time) (ShutdownResult, error) {
	if !rep.Assessment.Level.Acts() {
		return ShutdownResult{}, fmt.Errorf("%w (level %v, %.0f%% of the limit)",
			ErrNotAuthorised, rep.Assessment.Level, rep.Assessment.Fraction*100)
	}

	out := ShutdownResult{At: now, Unclassified: rep.Unclassified}
	for _, t := range rep.Stoppable() {
		// Belt and braces. Stoppable already filters, and this is the last
		// line before an irreversible call against a live cluster — the one
		// place where a refactor upstream turning "app" into "everything"
		// would take the tunnel down with it.
		if !t.Tier.Stoppable() {
			continue
		}
		if err := r.Cluster.Scale(ctx, t.Namespace, t.Name, 0); err != nil {
			out.Failed = append(out.Failed, StopFailure{Target: t, Err: err})
			continue
		}
		out.Stopped = append(out.Stopped, t)
	}

	// The floor is reached when nothing was available to stop, not when
	// nothing was stopped successfully: a failed scale call is a problem to
	// report, not evidence that the instance has run out of options.
	out.AtFloor = len(rep.Stoppable()) == 0
	return out, nil
}

// Protected lists the workloads a shutdown may not touch, for a report that
// explains what is still running and why.
func (rep Report) Protected() []Target {
	var out []Target
	for _, t := range rep.Targets {
		if !t.Tier.Stoppable() {
			out = append(out, t)
		}
	}
	return out
}

// AtFloor reports that every stoppable workload is already stopped and
// spending is still over the limit.
func (rep Report) AtFloor() bool {
	return rep.Assessment.Level.Acts() && len(rep.Stoppable()) == 0
}

// SystemProtected is the reason the floor exists, stated as a number: what the
// instance still burns after every application is stopped.
func (rep Report) SystemProtected() float64 {
	var sum float64
	for _, w := range rep.Workloads {
		if w.Tier == tier.System || w.Tier == tier.Kernel {
			sum += w.HourlyUSD
		}
	}
	return sum
}
