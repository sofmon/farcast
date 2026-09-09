package kernel

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/sofmon/farcast/technocore/adapt"
	"github.com/sofmon/farcast/technocore/cost"
	"github.com/sofmon/farcast/technocore/pricing"
	"github.com/sofmon/farcast/technocore/tier"
)

// DefaultCooldown is how long a workload is left alone after being resized.
//
// Every resize is a rollout, and the profile that justified the next one has
// to be built mostly from readings taken AFTER the last. A kernel that
// re-evaluated every thirty seconds would chase its own tail: the new pods'
// start-up spike would look like load, and the workload would be re-rolled on
// the strength of the previous roll.
const DefaultCooldown = 6 * time.Hour

// The annotations a resize leaves behind. They are the record, and they live
// on the workload rather than in the kernel because [ADR 0009] decision 1
// makes the cluster the registry: a restarted kernel must be able to see that
// it changed something, or the cooldown means nothing across a restart.
//
// [ADR 0009]: ../../docs/adr/0009-technocore-kernel-and-cost-metering.md
const (
	AdaptedAtLabel   = "farcast.sofmon.com/adapted-at"
	AdaptedFromLabel = "farcast.sofmon.com/adapted-from"
)

// Adaptation is one workload's advice, resolved against the cluster.
type Adaptation struct {
	adapt.Advice
	Namespace  string `json:"namespace"`
	Deployment string `json:"deployment"`
	// Container is the one whose requests would change. A resize must name
	// it: patching by position would silently move whichever container
	// happened to be first.
	Container string `json:"container,omitempty"`
	Replicas  int    `json:"replicas,omitempty"`
}

// MonthlyDeltaUSD is what acting would do to the bill across every replica.
func (a Adaptation) MonthlyDeltaUSD() float64 {
	return a.Advice.MonthlyDeltaUSD() * float64(max(a.Replicas, 1))
}

// Advise works out what every application's reservation should be.
//
// It returns advice for every application-tier workload, acting or not — a
// workload the kernel is deliberately leaving alone is exactly what an
// operator staring at an over-provisioned application needs to see, and
// omitting it would make "nothing to do" and "not considered" identical.
//
// Nothing here writes anything.
func (r *Reconciler) Advise(rep Report, now time.Time) []Adaptation {
	if r.Usage == nil {
		return nil
	}
	profiles := map[string]int{}
	summaries := r.Usage.Summarize(now)
	for i, s := range summaries {
		profiles[s.App] = i
	}

	var out []Adaptation
	for _, t := range rep.Targets {
		// Applications only, for the reason a cost shutdown stops
		// applications only: FatLine and the key holder are what an operator
		// recovers an instance THROUGH, and a kernel that could resize the
		// tunnel could take away the means of fixing its own mistake. The
		// kernel resizing itself is the same hazard with a shorter loop.
		if t.Tier != tier.App {
			continue
		}
		a := Adaptation{
			Namespace: t.Namespace, Deployment: t.Name, Replicas: t.Replicas,
			Advice: adapt.Advice{App: t.App, CurrentCPUMilli: t.CPUMilli, CurrentMemMiB: t.MemMiB,
				CPUMilli: t.CPUMilli, MemMiB: t.MemMiB},
		}
		i, ok := profiles[t.App]
		if !ok {
			a.Hold = "no usage profile for this workload yet"
			out = append(out, a)
			continue
		}
		// One container, or none of this applies. The profile is per POD
		// (ADR 0014 decision 3), so on a multi-container pod there is no way
		// to say which container's reservation the measurement justifies —
		// the revisit trigger that ADR named, refused rather than guessed.
		if len(t.Containers) != 1 {
			a.Hold = fmt.Sprintf("the pod has %d containers, and a per-pod profile cannot say which one to resize", len(t.Containers))
			out = append(out, a)
			continue
		}
		a.Container = t.Containers[0]

		advice := adapt.Recommend(summaries[i], r.Advice)
		advice.App = t.App
		a.Advice = advice
		if a.Act {
			if hold := r.holdReason(t, rep, a, now); hold != "" {
				a.Act, a.Hold = false, hold
				a.CPUMilli, a.MemMiB = a.CurrentCPUMilli, a.CurrentMemMiB
			}
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].App < out[j].App })
	r.lastAdvice = out
	return out
}

// holdReason is the cluster's veto over an otherwise sound recommendation.
func (r *Reconciler) holdReason(t Target, rep Report, a Adaptation, now time.Time) string {
	if left := r.cooldownLeft(t, now); left > 0 {
		return fmt.Sprintf("resized recently; leaving it alone for another %s", left.Round(time.Minute))
	}
	// An increase spends money. The operator approved a limit, not an
	// open-ended budget, so the kernel may spend up to that limit and not
	// past it — the cost pillar applied to the one code path in TechnoCore
	// that can make an instance cost MORE.
	if delta := a.MonthlyDeltaUSD(); delta > 0 {
		hourly := rep.RateHourlyUSD + hourlyDelta(a)
		_, periodEnd := r.Ledger.Period()
		after := cost.Assess(rep.Accrual.Total, r.Limit, hourly, now, periodEnd)
		if after.ProjectedOver || after.Level.Acts() {
			return fmt.Sprintf("growing this reservation by %s %.2f/month would put the instance on course to reach its limit",
				"USD", delta)
		}
	}
	return ""
}

// hourlyDelta is what acting would add to the instance's burn rate.
func hourlyDelta(a Adaptation) float64 {
	per := pricing.PodHourlyUSD(a.CPUMilli, a.MemMiB) - pricing.PodHourlyUSD(a.CurrentCPUMilli, a.CurrentMemMiB)
	return per * float64(max(a.Replicas, 1))
}

// cooldownLeft is how long remains before this workload may be resized again.
//
// An unparseable or absent stamp is treated as "never resized". The
// alternative — refusing to act on a workload whose annotation somebody
// hand-edited — would make a typo permanently freeze a reservation, which is
// a worse failure than one extra rollout.
func (r *Reconciler) cooldownLeft(t Target, now time.Time) time.Duration {
	cd := r.Cooldown
	if cd <= 0 {
		cd = DefaultCooldown
	}
	last, ok := t.AdaptedAt()
	if !ok {
		return 0
	}
	if left := cd - now.Sub(last); left > 0 {
		return left
	}
	return 0
}

// AdaptResult is what one adaptation pass did.
type AdaptResult struct {
	Applied []Adaptation
	Failed  []AdaptFailure
}

// AdaptFailure is one resize the API server refused.
type AdaptFailure struct {
	Adaptation Adaptation
	Err        error
}

// Adapt applies the advice that says to act.
//
// A failure on one workload does not stop the rest: they are independent
// changes, and a single deployment the kernel cannot patch must not freeze
// every other application's reservation.
func (r *Reconciler) Adapt(ctx context.Context, advice []Adaptation, now time.Time) AdaptResult {
	var res AdaptResult
	for _, a := range advice {
		if !a.Act {
			continue
		}
		stamp := map[string]string{
			AdaptedAtLabel: now.UTC().Format(time.RFC3339),
			// What it was, so an operator can put it back by reading the
			// object rather than by finding a log line.
			AdaptedFromLabel: fmt.Sprintf("%dm/%dMi", a.CurrentCPUMilli, a.CurrentMemMiB),
		}
		err := r.Cluster.SetRequests(ctx, a.Namespace, a.Deployment, a.Container, a.CPUMilli, a.MemMiB, stamp)
		if err != nil {
			res.Failed = append(res.Failed, AdaptFailure{Adaptation: a, Err: err})
			continue
		}
		res.Applied = append(res.Applied, a)
	}
	return res
}
