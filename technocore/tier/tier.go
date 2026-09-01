// Package tier classifies FarCast workloads by what a cost shutdown is
// allowed to do to them.
//
// [ADR 0008] found the failure this exists to prevent: every unseal and every
// future keeper reseed rides the FatLine tunnel, so a cost shutdown that stops
// FatLine leaves storage impossible to unseal *while the instance keeps
// billing*. At [ADR 0003]'s rates the whole system tier is about $15/month
// against an instance floor near $73 — so stopping it trades recovery for a
// fifth of the bill. [ADR 0009] decision 6 makes that a rule the code
// enforces rather than a caution in a document.
//
// [ADR 0003]: ../../docs/adr/0003-gke-autopilot.md
// [ADR 0008]: ../../docs/adr/0008-in-cluster-key-delivery.md
// [ADR 0009]: ../../docs/adr/0009-technocore-kernel-and-cost-metering.md
package tier

// Label is the key every FarCast-managed workload carries, on the workload
// and on its pod template — TechnoCore reads pods to meter and workloads to
// scale, and a label on only one of the two is a classification with a hole
// in it.
const Label = "farcast.sofmon.com/tier"

// Tier is what a workload is to the kernel.
type Tier string

const (
	// Kernel is TechnoCore itself. It never stops itself: something has to
	// stay alive to report why everything else stopped.
	Kernel Tier = "kernel"

	// System is the instance's own machinery — datasphered, FatLine, Shrike.
	// A cost shutdown never touches it.
	System Tier = "system"

	// App is an operator's application. These are what a cost shutdown
	// stops, most expensive first.
	App Tier = "app"

	// Unknown is a workload carrying no tier label.
	Unknown Tier = ""
)

// Of reads a workload's tier from its labels.
func Of(labels map[string]string) Tier {
	switch t := Tier(labels[Label]); t {
	case Kernel, System, App:
		return t
	default:
		return Unknown
	}
}

// Stoppable reports whether a cost shutdown may stop this tier.
//
// Only App is, and the asymmetry for Unknown is deliberate. An unlabelled
// workload could be a mislabelled application — stopping it saves money — or
// a system component whose label was lost, and stopping *that* costs an
// instance nobody can unseal while it carries on billing. The two mistakes
// are not equally bad, so the tie goes to not stopping, and the kernel
// reports what it could not classify instead of guessing.
//
// The cost of this choice is real and belongs in the record: on an instance
// whose workloads carry no labels, a cost shutdown does nothing but say so.
// That is the correct behaviour for a kernel that cannot tell what it is
// looking at.
func (t Tier) Stoppable() bool { return t == App }

// Rank orders a shutdown: lower goes first. It exists so the ordering lives
// next to the classification rather than being re-derived at each call site
// with a subtly different opinion about what comes last.
func (t Tier) Rank() int {
	switch t {
	case App:
		return 0
	case Unknown:
		return 1
	case System:
		return 2
	case Kernel:
		return 3
	default:
		return 1
	}
}

// Valid reports whether a tier is one of the three a manifest may declare.
func (t Tier) Valid() bool { return t == Kernel || t == System || t == App }
