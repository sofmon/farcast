// Package kernel is TechnoCore's reconcile loop: the thing that actually
// watches an instance.
//
// It polls rather than watches, per [ADR 0009] decision 3. For a kernel, a
// loop that cannot silently stop reconciling is worth more than freshness
// measured in seconds — a wedged watch looks exactly like a cluster with
// nothing happening in it, and the cost guard would go quiet at precisely the
// moment it mattered.
//
// It holds no state of its own beyond the ledger it accrues into: declared
// intent lives on the workloads as labels, observed state is read fresh every
// tick, and nothing is cached between them.
//
// [ADR 0009]: ../../docs/adr/0009-technocore-kernel-and-cost-metering.md
package kernel

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/sofmon/farcast/technocore/cost"
	"github.com/sofmon/farcast/technocore/kube"
	"github.com/sofmon/farcast/technocore/pricing"
	"github.com/sofmon/farcast/technocore/tier"
)

// DefaultInterval is how often the loop reconciles. Seconds would buy
// freshness nothing here needs and cost an API call every time; an hour would
// leave a runaway workload unbilled for an hour.
const DefaultInterval = 30 * time.Second

// PodLister is the slice of the Kubernetes client this loop needs. It is an
// interface so the loop is tested against fixtures rather than a cluster.
type PodLister interface {
	ListPods(ctx context.Context, namespace, selector string) ([]kube.Pod, error)
}

// ManagedBy selects the workloads FarCast created. A kernel that metered
// everything in its namespaces would bill the operator for the cluster's own
// managed add-ons as though an application had asked for them.
const ManagedBy = "app.kubernetes.io/managed-by=farcast"

// Reconciler meters an instance against its cost limit.
type Reconciler struct {
	Pods       PodLister
	Namespaces []string
	Ledger     *cost.Ledger
	Limit      float64
	Interval   time.Duration

	// Selector narrows what is metered. Empty means everything in the listed
	// namespaces, which is almost never what a caller wants.
	Selector string

	// Last is when the loop last accrued. It is exported so a restored
	// checkpoint can seed it after a restart: spend between the last
	// checkpoint and the restart is otherwise invisible, and an instance that
	// forgot an outage's worth of spending would under-report in the
	// flattering direction.
	Last time.Time
}

// Workload is one metered pod, as the kernel sees it.
type Workload struct {
	Namespace string
	Name      string
	App       string
	Tier      tier.Tier
	CPUMilli  int
	MemMiB    int
	HourlyUSD float64
}

// Report is one tick's observation. It is a value, not a log line: the caller
// decides what to warn about, what to act on and what to print.
type Report struct {
	At    time.Time
	Since time.Time
	// Billed is the interval this tick accrued for. It is the elapsed time
	// since the last reconcile, which after a restart is the whole gap.
	Billed time.Duration
	// Reconstructed is set when Billed substantially exceeded the reconcile
	// interval — the gap after a restart or a stall, accrued by assuming the
	// observed workload set ran throughout. The approximation is reported
	// rather than hidden.
	Reconstructed bool

	Workloads []Workload
	// Unclassified counts workloads carrying no tier label. They are
	// metered like anything else and protected from a cost shutdown, so a
	// non-zero count is the operator's signal that a shutdown would be less
	// effective than they expect.
	Unclassified int

	// The Rate* fields are dollars per HOUR at this instant — what the
	// instance is currently burning. Ledger.ByApp is dollars ACCRUED for the
	// period. Two different quantities that read identically in prose, so
	// they are not allowed to share a name.
	RateHourlyUSD float64
	RateByTier    map[tier.Tier]float64
	RateByApp     map[string]float64
	Accrual       cost.Accrual
	Assessment    cost.Assessment
}

// Stoppable returns the workloads a cost shutdown may stop, most expensive
// first. It is the ordering [ADR 0009] decision 6 specifies, computed once
// here rather than re-derived at each call site.
func (r Report) Stoppable() []Workload {
	var out []Workload
	for _, w := range r.Workloads {
		if w.Tier.Stoppable() {
			out = append(out, w)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].HourlyUSD != out[j].HourlyUSD {
			return out[i].HourlyUSD > out[j].HourlyUSD
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// AtFloor reports that every stoppable workload is already stopped and
// spending is still over the limit. There is nothing further the kernel may
// do: what remains is the instance's own standing cost, and the levers that
// would reduce it — dropping the load-balancer carrier, releasing the
// instance — destroy operator-visible capability or data. Decision 8 says a
// kernel reports that rather than taking either.
func (r Report) AtFloor() bool {
	return r.Assessment.Level.Acts() && len(r.Stoppable()) == 0
}

// Reconcile observes the instance once and accrues the elapsed interval.
func (r *Reconciler) Reconcile(ctx context.Context, now time.Time) (Report, error) {
	rep := Report{
		At:         now,
		Since:      r.Last,
		RateByTier: map[tier.Tier]float64{},
		RateByApp:  map[string]float64{},
	}

	for _, ns := range r.Namespaces {
		pods, err := r.Pods.ListPods(ctx, ns, r.Selector)
		if err != nil {
			return Report{}, fmt.Errorf("kernel: list pods in %s: %w", ns, err)
		}
		for _, p := range pods {
			if !p.Billable() {
				continue
			}
			cpu, mem, err := p.Requests()
			if err != nil {
				return Report{}, fmt.Errorf("kernel: pod %s/%s: %w", ns, p.Metadata.Name, err)
			}
			w := Workload{
				Namespace: p.Metadata.Namespace,
				Name:      p.Metadata.Name,
				App:       appOf(p),
				Tier:      tier.Of(p.Metadata.Labels),
				CPUMilli:  cpu,
				MemMiB:    mem,
				HourlyUSD: pricing.PodHourlyUSD(cpu, mem),
			}
			if w.Namespace == "" {
				w.Namespace = ns
			}
			if w.Tier == tier.Unknown {
				rep.Unclassified++
			}
			rep.Workloads = append(rep.Workloads, w)
			rep.RateHourlyUSD += w.HourlyUSD
			rep.RateByTier[w.Tier] += w.HourlyUSD
			rep.RateByApp[w.App] += w.HourlyUSD
		}
	}

	billed := r.billableInterval(now)
	rep.Billed = billed
	rep.Reconstructed = r.Interval > 0 && billed > 2*r.Interval

	if billed > 0 {
		for _, w := range rep.Workloads {
			r.Ledger.Accrue(now, w.App, w.HourlyUSD, billed)
		}
	}
	r.Last = now

	rep.Accrual = r.Ledger.Accrued()
	_, periodEnd := r.Ledger.Period()
	rep.Assessment = cost.Assess(rep.Accrual.Total, r.Limit, rep.RateHourlyUSD, now, periodEnd)
	return rep, nil
}

// billableInterval is how long to charge for.
//
// The first reconcile of a process charges nothing: there is no prior
// observation, so any interval would be invented. After that it is the whole
// elapsed gap, which after a restart means the outage is billed by assuming
// the observed set ran throughout — the approximation [ADR 0009] records,
// surfaced as Report.Reconstructed rather than hidden.
//
// It is floored at the ledger's period start, so a zero or corrupt Last
// cannot bill from the epoch.
func (r *Reconciler) billableInterval(now time.Time) time.Duration {
	if r.Last.IsZero() {
		return 0
	}
	from := r.Last
	if start, _ := r.Ledger.Period(); from.Before(start) {
		from = start
	}
	if !now.After(from) {
		return 0
	}
	return now.Sub(from)
}

// Run reconciles until the context is cancelled, handing each report to the
// caller. An error from a single tick is reported and the loop continues: a
// kernel that exits on one failed API call is a kernel that stops metering
// the moment the cluster is briefly unhappy.
func (r *Reconciler) Run(ctx context.Context, observe func(Report, error)) error {
	interval := r.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		rep, err := r.Reconcile(ctx, time.Now().UTC())
		if observe != nil {
			observe(rep, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// appOf is the attribution key. Planck stamps a canonical name at 4.2; until
// then the conventional Kubernetes labels are tried in order, falling back to
// the pod's own name so that an unlabelled workload is still attributed to
// something an operator can find, rather than silently pooled into "".
func appOf(p kube.Pod) string {
	for _, k := range []string{"app.kubernetes.io/name", "app"} {
		if v := p.Metadata.Labels[k]; v != "" {
			return v
		}
	}
	return p.Metadata.Name
}
