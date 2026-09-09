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
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/sofmon/farcast/technocore/adapt"
	"github.com/sofmon/farcast/technocore/cost"
	"github.com/sofmon/farcast/technocore/kube"
	"github.com/sofmon/farcast/technocore/pricing"
	"github.com/sofmon/farcast/technocore/tier"
	"github.com/sofmon/farcast/technocore/usage"
)

// DefaultInterval is how often the loop reconciles. Seconds would buy
// freshness nothing here needs and cost an API call every time; an hour would
// leave a runaway workload unbilled for an hour.
const DefaultInterval = 30 * time.Second

// Cluster is the slice of the Kubernetes client this loop needs. It is an
// interface so the loop is tested against fixtures rather than a cluster.
//
// Pods and Deployments are both listed, and for different jobs: pods are what
// Autopilot bills, so they are what the meter reads; deployments are what can
// actually be stopped, because deleting a pod only makes its controller
// create another one. Pod metrics are a third thing again — what a pod
// USES rather than what it reserves — and nothing that enforces anything
// reads them.
type Cluster interface {
	ListPods(ctx context.Context, namespace, selector string) ([]kube.Pod, error)
	ListDeployments(ctx context.Context, namespace, selector string) ([]kube.Deployment, error)
	ListPodMetrics(ctx context.Context, namespace, selector string) ([]kube.PodMetrics, error)
	Scale(ctx context.Context, namespace, name string, replicas int) error
	// SetRequests is the only thing the kernel writes to a workload that is
	// not a zero (ADR 0016). Everything dangerous about this phase is on the
	// other side of this one call.
	// It returns what the cluster STORED, which is not always what was asked
	// for: a mutating admission controller sits between the two, and the 5.2
	// walk watched Autopilot raise a below-floor request in the pod template
	// itself while answering 200.
	SetRequests(ctx context.Context, namespace, name, container string, cpuMilli, memMiB int, annotations map[string]string) (int, int, error)
}

// ManagedBy selects the workloads FarCast created. A kernel that metered
// everything in its namespaces would bill the operator for the cluster's own
// managed add-ons as though an application had asked for them.
const ManagedBy = "app.kubernetes.io/managed-by=farcast"

// DefaultNamespace is where FarCast's own workloads live, and the namespace a
// kernel meters when told nothing else.
const DefaultNamespace = "farcast-system"

// Reconciler meters an instance against its cost limit.
type Reconciler struct {
	Cluster    Cluster
	Namespaces []string
	Ledger     *cost.Ledger
	Limit      float64
	Interval   time.Duration

	// Discover supplies namespaces to meter beyond the configured ones, so
	// deploying an application does not require restarting the kernel. Nil
	// means the configured list is the whole set.
	Discover NamespaceSource

	// Confirmations supplies the provider's own figures for closed windows.
	// Nil means none are available, which is a state the reports name rather
	// than a failure: the instance runs on `expected` alone.
	Confirmations ConfirmationSource

	// Period names the accounting window the limit applies to — "monthly" or
	// "daily", as captured at install. It is what Roll uses to open the next
	// ledger when the current one ends.
	Period string

	// Selector narrows what is metered. Empty means everything in the listed
	// namespaces, which is almost never what a caller wants.
	Selector string

	// Last is when the loop last accrued. It is exported so a restored
	// checkpoint can seed it after a restart: spend between the last
	// checkpoint and the restart is otherwise invisible, and an instance that
	// forgot an outage's worth of spending would under-report in the
	// flattering direction.
	Last time.Time

	// Observed is the last reconcile's view, kept so the next checkpoint can
	// publish it. It is what `farcast costs` reads, and it is deliberately the
	// kernel's own figures rather than a second model of them.
	Observed Observation

	// Usage accumulates what workloads actually consume, as opposed to what
	// they reserve. Nil turns collection off entirely, and everything else
	// here behaves identically — nothing in the cost path reads it.
	Usage *usage.Store

	// lastReading is the timestamp of the most recent metrics reading taken
	// for each pod, so a server that has not refreshed is not counted twice.
	lastReading map[string]time.Time

	// Advice bounds what a resize recommendation may say. The zero value uses
	// the adapt package's own defaults.
	Advice adapt.Config

	// Cooldown is how long a workload is left alone after being resized.
	// Zero means DefaultCooldown.
	Cooldown time.Duration

	// Adapting says the kernel acts on its own advice rather than only
	// publishing it. It is off by default and it is the only switch in
	// TechnoCore that lets the kernel write something to a workload that is
	// not a zero.
	Adapting bool

	// lastAdvice is the most recent pass, kept so the published document can
	// carry it. In-memory bookkeeping only — Advise writes nothing to the
	// cluster, and a test asserts it.
	lastAdvice []Adaptation

	// usageUnavailable is the last tick's list of namespaces whose metrics
	// could not be read, carried so the published document can say "not
	// measured" rather than leave a reader to infer it from emptiness.
	usageUnavailable []string
}

// Workload is one metered pod, as the kernel sees it.
type Workload struct {
	Namespace string
	Name      string
	App       string
	Tier      tier.Tier
	// Labels are kept so a deployment's selector can claim this pod without
	// a second API call.
	Labels map[string]string
	// Containers names the pod's containers. A resize has to name the one it
	// changes, and a pod with more than one cannot be sized from a per-pod
	// profile at all.
	Containers []string
	CPUMilli   int
	MemMiB     int
	HourlyUSD  float64
}

// mergeNames appends names not already present, preserving order.
func mergeNames(into []string, add []string) []string {
	for _, n := range add {
		if !slices.Contains(into, n) {
			into = append(into, n)
		}
	}
	return into
}

// Target is a workload a cost shutdown could act on: a Deployment, with the
// cost of the pods its selector claims.
//
// The distinction from Workload is the whole point. A Workload is a pod —
// what bills. A Target is a Deployment — what can be stopped. Conflating them
// produces a shutdown that deletes pods and watches their controllers put
// them straight back.
type Target struct {
	Namespace string
	Name      string
	Tier      tier.Tier
	Replicas  int
	Pods      int
	HourlyUSD float64

	// App and Containers come from the pods this deployment claims, and
	// exist so an adaptation can find the workload a usage profile belongs
	// to without a second API call. Containers is every container name in
	// the claimed pods: a resize needs to name one, and a pod with more than
	// one is a shape the per-pod profile cannot attribute (ADR 0014's stated
	// limitation, and ADR 0016 decision 5's refusal).
	App        string
	Containers []string
	// CPUMilli and MemMiB are what ONE of its pods reserves.
	CPUMilli int
	MemMiB   int
	// Annotations are the deployment's own, read so a resize can see when it
	// last changed this workload without a second call.
	Annotations map[string]string
}

// AdaptedAt is when the kernel last resized this workload, from the stamp it
// left on the object itself.
func (t Target) AdaptedAt() (time.Time, bool) {
	v := t.Annotations[AdaptedAtLabel]
	if v == "" {
		return time.Time{}, false
	}
	at, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, false
	}
	return at, true
}

// Report is one tick's observation. It is a value, not a log line: the caller
// decides what to warn about, what to act on and what to print.
type Report struct {
	At    time.Time
	Since time.Time
	// Billed is the interval this tick accrued for. It is the elapsed time
	// since the last reconcile, which after a restart is the whole gap.
	Billed time.Duration
	// Rolled is set when this tick opened a new accounting period.
	Rolled bool

	// Metered is the namespace set this tick actually read, and Unreachable
	// is the subset that refused. A namespace the operator asked for but the
	// kernel cannot list is almost always a missing RoleBinding — and it means
	// the workloads there are running, billing, and counted nowhere.
	Metered     []string
	Unreachable []string

	// ConfirmationsApplied counts the provider figures this tick took in;
	// ConfirmationsRefused counts how many of those the clamp would not let
	// calibrate the model. A refusal is the most interesting thing the cost
	// system can learn, so it is counted rather than buried in the accrual.
	ConfirmationsApplied int
	ConfirmationsRefused int

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

	// Targets are the deployments this tick saw, with the cost of the pods
	// each one claims.
	Targets []Target

	// UsageSampled counts pod readings folded into the profiles this tick.
	// UsageRepeated counts readings the metrics server had not refreshed
	// since the last tick, which are skipped rather than counted twice.
	UsageSampled  int
	UsageRepeated int
	// UsageUnavailable names namespaces whose metrics could not be read. It
	// is a finding and never a fault, even when it names every namespace:
	// the meter reads requests, and a profile that cannot be built means a
	// resize declines. Metering that read nothing would report $0 for an
	// instance that is spending, which is why THAT one is fatal and this is
	// not.
	UsageUnavailable []string
}

// Complete reports whether this tick saw every namespace it was asked to.
//
// An incomplete tick still meters and still warns — under-reporting is better
// than not reporting — but it must never claim the instance floor, because the
// kernel cannot know what it is leaving running in a namespace it could not
// read.
func (rep Report) Complete() bool { return len(rep.Unreachable) == 0 }

// Stoppable returns the deployments a cost shutdown may stop, most expensive
// first, excluding any already scaled to zero.
//
// The ordering is [ADR 0009] decision 6's, computed once here rather than
// re-derived at each call site with a subtly different opinion. It matters
// because a shutdown is not atomic: if only some scale calls succeed, the
// ones that did should be the ones that were costing the most.
func (r Report) Stoppable() []Target {
	var out []Target
	for _, t := range r.Targets {
		if t.Tier.Stoppable() && t.Replicas > 0 {
			out = append(out, t)
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

// Reconcile observes the instance once and accrues the elapsed interval.
func (r *Reconciler) Reconcile(ctx context.Context, now time.Time) (Report, error) {
	// Rolling happens BEFORE anything is metered, not after. A tick that
	// crosses a period boundary would otherwise bill its whole interval to
	// the period that has already closed — a small error at a 30-second
	// cadence, and a silent one, which is the kind this package exists to
	// avoid. Rolling first means the interval lands where the floor at the
	// new period's start puts it, which is the new period.
	rolled, err := r.Roll(now)
	if err != nil {
		return Report{}, err
	}

	rep := Report{
		Rolled:     rolled,
		At:         now,
		Since:      r.Last,
		RateByTier: map[tier.Tier]float64{},
		RateByApp:  map[string]float64{},
	}

	// Confirmations are applied before anything is metered, so this tick's
	// assessment already reflects them. Applying them afterwards would leave
	// one tick's worth of decisions made against a figure the provider had
	// already corrected.
	if err := r.applyConfirmations(ctx, &rep); err != nil {
		return Report{}, err
	}

	metered, err := r.meteredNamespaces(ctx)
	if err != nil {
		return Report{}, err
	}
	rep.Metered = metered

	var read []string
	for _, ns := range metered {
		pods, err := r.Cluster.ListPods(ctx, ns, r.Selector)
		if err != nil {
			// One namespace refusing must not stop the meter reading the
			// rest: a single missing RoleBinding would otherwise disable cost
			// enforcement for the whole instance. It is recorded instead, and
			// Report.Complete is what stops the kernel acting on a picture it
			// knows is partial.
			rep.Unreachable = append(rep.Unreachable, fmt.Sprintf("%s: %v", ns, safeNamespaceError(err)))
			continue
		}
		read = append(read, ns)
		for _, p := range pods {
			if !p.Billable() {
				continue
			}
			cpu, mem, err := p.Requests()
			if err != nil {
				return Report{}, fmt.Errorf("kernel: pod %s/%s: %w", ns, p.Metadata.Name, err)
			}
			w := Workload{
				Namespace:  p.Metadata.Namespace,
				Name:       p.Metadata.Name,
				App:        appOf(p),
				Tier:       tier.Of(p.Metadata.Labels),
				Labels:     p.Metadata.Labels,
				Containers: containerNames(p),
				CPUMilli:   cpu,
				MemMiB:     mem,
				HourlyUSD:  pricing.PodHourlyUSD(cpu, mem),
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

	// Partial visibility is workable; none is not. If every namespace refused,
	// the kernel has lost its permissions rather than met one misconfigured
	// application — and carrying on would report $0 for an instance that is
	// still spending, which is the exact failure this package is built to
	// avoid. One namespace failing is a finding; all of them is a fault.
	if len(rep.Unreachable) > 0 && len(rep.Unreachable) >= len(rep.Metered) {
		return Report{}, fmt.Errorf("kernel: no metered namespace could be read (%s)",
			strings.Join(rep.Unreachable, "; "))
	}

	if err := r.collectTargets(ctx, &rep); err != nil {
		return Report{}, err
	}

	// After the workloads are known and before anything is accrued: a
	// reading is only attributed to an application the meter has already
	// seen, so the profile set can never name something the cost path does
	// not.
	r.sampleUsage(ctx, read, &rep)

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
	r.Observed = Observation{
		At:            now,
		Pods:          len(rep.Workloads),
		Unclassified:  rep.Unclassified,
		RateHourlyUSD: rep.RateHourlyUSD,
		Level:         rep.Assessment.Level.String(),
		Limit:         r.Limit,
		Incomplete:    !rep.Complete(),
		Unreachable:   rep.Unreachable,
	}
	return rep, nil
}

// collectTargets lists the deployments in each namespace and attributes the
// pods already metered to whichever one claims them.
//
// A pod matching no deployment is simply not attributed: datasphered's pods
// belong to a StatefulSet, and the system tier is never stopped anyway, so
// there is nothing to gain from teaching this to walk owner references.
// safeNamespaceError keeps a per-namespace failure short enough to log every
// tick without drowning the reports that matter.
func safeNamespaceError(err error) string {
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

func (r *Reconciler) collectTargets(ctx context.Context, rep *Report) error {
	for _, ns := range rep.Metered {
		deps, err := r.Cluster.ListDeployments(ctx, ns, r.Selector)
		if err != nil {
			rep.Unreachable = append(rep.Unreachable, fmt.Sprintf("%s (deployments): %v", ns, safeNamespaceError(err)))
			continue
		}
		for _, d := range deps {
			t := Target{
				Namespace:   ns,
				Name:        d.Metadata.Name,
				Tier:        tier.Of(d.Metadata.Labels),
				Replicas:    d.Status.Replicas,
				Annotations: d.Metadata.Annotations,
			}
			if d.Spec.Replicas != nil {
				t.Replicas = *d.Spec.Replicas
			}
			for _, w := range rep.Workloads {
				if w.Namespace == ns && d.Spec.Selector.Matches(w.Labels) {
					t.Pods++
					t.HourlyUSD += w.HourlyUSD
					t.App = w.App
					t.CPUMilli, t.MemMiB = w.CPUMilli, w.MemMiB
					t.Containers = mergeNames(t.Containers, w.Containers)
				}
			}
			rep.Targets = append(rep.Targets, t)
		}
	}
	return nil
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

// containerNames lists a pod's main containers. Init containers are excluded:
// they have finished by the time anything is measured, so a resize could not
// be justified from a profile that never saw them run.
func containerNames(p kube.Pod) []string {
	out := make([]string, 0, len(p.Spec.Containers))
	for _, c := range p.Spec.Containers {
		out = append(out, c.Name)
	}
	return out
}

// Roll opens a new ledger when now has passed the end of the current period,
// reporting whether it did. Reconcile calls it first thing on every tick; it
// is exported so a caller can roll explicitly, and it is a no-op inside a
// period.
//
// A Reconciler with no Period never rolls. That is the shape a test or a
// one-shot observation wants, and it keeps a missing configuration from
// silently resetting an instance's accounting.
//
// The old ledger is dropped rather than archived: a limit applies to a period,
// and the kernel's job is enforcing the current one. What the previous period
// cost is a question for the bill, and for `farcast costs` at 4.3.
//
// Last is deliberately NOT reset. It stays where it was, in the period that
// just ended, and billableInterval's floor at the new period's start does the
// rest — so the hours between the boundary and the first tick of the new
// period are billed to the new period exactly once, with no special case.
func (r *Reconciler) Roll(now time.Time) (bool, error) {
	if r.Period == "" {
		return false, nil
	}
	_, end := r.Ledger.Period()
	if now.Before(end) {
		return false, nil
	}
	start, newEnd, err := cost.PeriodFor(now, r.Period)
	if err != nil {
		return false, fmt.Errorf("kernel: roll the accounting period: %w", err)
	}
	ledger, err := cost.NewLedger(start, newEnd)
	if err != nil {
		return false, fmt.Errorf("kernel: roll the accounting period: %w", err)
	}
	r.Ledger = ledger
	return true, nil
}
