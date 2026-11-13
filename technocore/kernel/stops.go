package kernel

import (
	"slices"
	"strings"
	"time"
)

// AppKey is how the ledger and the usage profiles name an application: its
// namespace and its name, "<namespace>/<app>".
//
// The name alone is not an application. Two namespaces may each run a "web",
// and a ledger keyed by the bare name adds their spending together, so
// neither share can be told apart — nor stopped, nor resized, on the strength
// of a figure that is half someone else's. Neither part can hold a "/": a
// namespace is a DNS label, and the name is a label value or a Pod name.
func AppKey(namespace, app string) string { return namespace + "/" + app }

// SplitAppKey reads a key back. A key with no namespace was accrued before
// the kernel recorded namespaces (CheckpointVersion 1); it is reported with
// qualified false and an empty namespace, never assigned one.
func SplitAppKey(key string) (namespace, app string, qualified bool) {
	ns, name, ok := strings.Cut(key, "/")
	if !ok {
		return "", key, false
	}
	return ns, name, true
}

// StopReasonCostGuard is why the kernel stops a workload: to contain cost. It
// is the only reason it has, and the only thing it ever scales to.
const StopReasonCostGuard = "cost_guard"

// Stop is one workload the kernel scaled to zero to contain cost.
//
// It is kept in the checkpoint so a restarted kernel — and every report read
// from that checkpoint — can still say why an application is stopped. It is
// removed when the kernel next sees the workload with replicas above zero
// (someone brought it back), sees its namespace without it (it is gone), or
// no longer meters its namespace (it can see neither).
// Until then it is a record of what the kernel did, not a claim about now: a
// reader labels an application stopped by the cost guard only while it is
// still at zero.
type Stop struct {
	Namespace  string    `json:"namespace"`
	Deployment string    `json:"deployment"`
	At         time.Time `json:"at"`
	Reason     string    `json:"reason"`
	// HourlyUSD is what the workload's Pods were reserving when it was
	// stopped: the burn rate the stop removed.
	HourlyUSD float64 `json:"saving_per_hour"`
}

// The levers ADR 0009 decision 8 names at the instance floor. The kernel
// records which remain and takes neither: both destroy operator-visible
// capability or data.
const (
	// LeverCarrier is dropping the load-balancer carrier, FatLine's public
	// point of presence. It is a lever only while the carrier is billed.
	LeverCarrier = "drop_carrier"
	// LeverRelease is releasing the instance.
	LeverRelease = "release_instance"
)

// LeverText is a lever as a report says it. A lever this build does not know
// is returned as written.
func LeverText(lever string) string {
	switch lever {
	case LeverCarrier:
		return "drop the load-balancer carrier"
	case LeverRelease:
		return "release the instance"
	default:
		return lever
	}
}

// Floor records that the kernel reached the instance floor (ADR 0009
// decision 8): every application stopped, and spending still over the limit.
// It is cleared on the first tick that is no longer there — below the limit,
// a new period, or something stoppable running again.
type Floor struct {
	// Since is the first shutdown that found nothing left to stop.
	Since time.Time `json:"since"`
	// HourlyUSD is what still burns: the protected Pods and the overhead no
	// shutdown can reach, as of the last shutdown that found the floor.
	HourlyUSD float64 `json:"still_burning_per_hour"`
	// Levers are what remains, from LeverCarrier and LeverRelease.
	Levers []string `json:"levers"`
}

// floorLevers are the levers left when the kernel is at the floor: the
// carrier only while it is billed, and the instance always.
func floorLevers(rep Report) []string {
	var out []string
	if rep.Carrier == CarrierLoadBalancer || rep.Carrier == CarrierUnobserved {
		out = append(out, LeverCarrier)
	}
	return append(out, LeverRelease)
}

// recordStop remembers a workload the kernel has just stopped, replacing any
// older record for the same workload.
func (r *Reconciler) recordStop(t Target, now time.Time) {
	s := Stop{Namespace: t.Namespace, Deployment: t.Name, At: now, Reason: StopReasonCostGuard, HourlyUSD: t.HourlyUSD}
	r.Stops = slices.DeleteFunc(r.Stops, func(old Stop) bool {
		return old.Namespace == s.Namespace && old.Deployment == s.Deployment
	})
	r.Stops = append(r.Stops, s)
	slices.SortFunc(r.Stops, func(a, b Stop) int {
		if c := strings.Compare(a.Namespace, b.Namespace); c != 0 {
			return c
		}
		return strings.Compare(a.Deployment, b.Deployment)
	})
}

// pruneStops forgets a stop once the tick shows it is over: the workload is
// running again, or its namespace was listed and it is not there. A metered
// namespace whose Deployments could not be listed says nothing either way,
// so its records are kept.
//
// A namespace the kernel no longer meters is forgotten with its records. The
// kernel no longer accounts for it, and would never list it again to see the
// workload brought back or deleted, so its records would otherwise be kept
// for good — through every period, and reported as the cost guard's after
// the namespace itself is gone. rep.Metered is authoritative here: a tick
// that could not read the metered list fails before this runs.
func (r *Reconciler) pruneStops(rep Report) {
	if len(r.Stops) == 0 {
		return
	}
	metered := make(map[string]bool, len(rep.Metered))
	for _, ns := range rep.Metered {
		metered[ns] = true
	}
	r.Stops = slices.DeleteFunc(r.Stops, func(s Stop) bool {
		if !metered[s.Namespace] {
			return true
		}
		for _, t := range rep.Targets {
			if t.Namespace == s.Namespace && t.Name == s.Deployment {
				return t.Replicas > 0
			}
		}
		return rep.listed[s.Namespace]
	})
	if len(r.Stops) == 0 {
		r.Stops = nil
	}
}

// observeFloor clears the floor record on a tick that shows the kernel is no
// longer there. A tick that cannot tell — over the limit, nothing stoppable
// seen, but a namespace unread — keeps it; Shutdown is what sets it.
func (r *Reconciler) observeFloor(rep Report) {
	if !rep.Assessment.Level.Acts() || len(rep.Stoppable()) > 0 {
		r.Floor = nil
	}
}
