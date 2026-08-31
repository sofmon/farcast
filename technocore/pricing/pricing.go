// Package pricing turns declared Pod resource requests into money.
//
// It exists because GKE Autopilot bills a Pod's *requests* — not its usage —
// so the standing cost of a FarCast workload is a pure function of numbers
// FarCast itself writes into a manifest. That makes cost a quantity this
// repository can compute exactly rather than wait for an invoice to reveal,
// which is what lets [ADR 0009] meter spending in real time without ever
// putting a billing credential in the cluster.
//
// The rate card below is compiled in, and that is a deliberate trade with a
// stated failure mode: prices change, this table does not, and every figure
// derived from it is a MODEL of a published rate card rather than a bill.
// Callers must present it as an estimate. AsOf and Region exist so the
// staleness is visible at the point of use instead of inferred.
//
// This package has no dependencies and reads no cluster state. It is the
// arithmetic only; who applies it to which Pods is TechnoCore's business.
//
// [ADR 0009]: ../../docs/adr/0009-technocore-kernel-and-cost-metering.md
package pricing

// The Autopilot general-purpose rate card recorded in ADR 0003 (§1). Both
// figures are per hour, and both are what Autopilot charges for *requested*
// capacity.
const (
	VCPUHourUSD = 0.0445
	GiBHourUSD  = 0.0049

	// Region and AsOf date the two constants above. Every operator-facing
	// figure derived from them should carry these, because a rate card with
	// no date reads as a fact.
	Region = "us-central1"
	AsOf   = "2026-06"

	// HoursPerMonth is 365*24/12 — the billing convention, not 30*24. Using
	// 720 would understate every monthly figure by 1.4%, which is small and
	// wrong in the direction that flatters us.
	HoursPerMonth = 730
)

// Autopilot raises a Pod's billed requests to a per-Pod floor, and the floor
// differs between clusters: one that supports bursting bills from 50m/52Mi,
// one that does not bills from 250m/512Mi. The difference is not academic —
// for FarCast's small system Pods it is the difference between $3.70 and
// $9.91 a month each, so a single estimate cannot honestly cover both.
const (
	BurstingMinCPUMilli = 50
	BurstingMinMemMiB   = 52

	NoBurstingMinCPUMilli = 250
	NoBurstingMinMemMiB   = 512
)

// PodMonthlyUSD is the standing monthly cost of one Pod requesting cpuMilli
// millicores and memMiB mebibytes, on a cluster that supports bursting.
//
// Requests below the bursting floor are raised to it, because that is what
// Autopilot bills — quoting the declared request for a Pod under the floor
// would report a price nobody is charged.
func PodMonthlyUSD(cpuMilli, memMiB int) float64 {
	return podMonthlyUSD(cpuMilli, memMiB, BurstingMinCPUMilli, BurstingMinMemMiB)
}

// PodMonthlyUSDNoBursting is PodMonthlyUSD on a cluster without bursting
// support, where the per-Pod floor is five times higher. It is the upper end
// of the honest range for a small Pod, and callers that quote a single number
// to an operator should quote this one alongside it.
func PodMonthlyUSDNoBursting(cpuMilli, memMiB int) float64 {
	return podMonthlyUSD(cpuMilli, memMiB, NoBurstingMinCPUMilli, NoBurstingMinMemMiB)
}

func podMonthlyUSD(cpuMilli, memMiB, minCPUMilli, minMemMiB int) float64 {
	if cpuMilli < minCPUMilli {
		cpuMilli = minCPUMilli
	}
	if memMiB < minMemMiB {
		memMiB = minMemMiB
	}
	if cpuMilli < 0 || memMiB < 0 {
		return 0
	}
	vcpu := float64(cpuMilli) / 1000
	gib := float64(memMiB) / 1024
	return (vcpu*VCPUHourUSD + gib*GiBHourUSD) * HoursPerMonth
}

// WorkloadMonthlyUSD is the standing cost of replicas identical Pods.
//
// Its whole reason to exist is that "the cost of this workload" and "the cost
// of one more replica" are different numbers that read the same in prose, and
// the repository has already conflated them once: ADR 0008 decision 6's
// "~$4/month" is the marginal second replica, and a call site copied it as the
// cost of the pair. Callers should say which they mean and call the matching
// function.
func WorkloadMonthlyUSD(replicas, cpuMilli, memMiB int) float64 {
	if replicas <= 0 {
		return 0
	}
	return float64(replicas) * PodMonthlyUSD(cpuMilli, memMiB)
}

// MarginalReplicaMonthlyUSD is what adding one more replica of a workload
// costs — the figure that belongs in a decision about availability, where the
// question is never "what does this workload cost" but "what does the second
// one buy and cost".
func MarginalReplicaMonthlyUSD(cpuMilli, memMiB int) float64 {
	return PodMonthlyUSD(cpuMilli, memMiB)
}
