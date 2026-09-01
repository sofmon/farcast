package cli

import (
	"fmt"
	"io"
	"sort"

	dsdeploy "github.com/sofmon/farcast/datasphere/deploy"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
	"github.com/sofmon/farcast/technocore/pricing"
)

// emptyClusterMonthlyUSD is what an Autopilot cluster costs before FarCast
// runs anything on it: the managed workloads Google schedules and bills for.
//
// It is ADR 0003 §1's modelled figure, not a measured one, and it dominates
// the floor — which is why every figure derived from it is presented as an
// estimate and why ADR 0009 decision 10 makes reconciling against one real
// invoice a phase deliverable rather than a nice-to-have.
const emptyClusterMonthlyUSD = 37

// kernelMonthlyUSD is the kernel's own standing compute, derived from the
// requests its manifest declares so the two cannot disagree. It lives here
// rather than beside the command because it is one line of the floor below,
// and a second copy of the arithmetic is how the prompt and the breakdown
// would eventually quote different numbers.
var kernelMonthlyUSD = pricing.WorkloadMonthlyUSD(tcdeploy.Replicas,
	tcdeploy.RequestCPUMilli, tcdeploy.RequestMemMiB)

// instanceFloor is the standing monthly cost of an instance's own machinery —
// what it costs with no application running at all.
//
// It exists because a cost limit below the floor is not a limit: TechnoCore
// would reach it before a single application started, stop everything it is
// allowed to stop, and still be over. That is a configuration mistake, and it
// should be caught when the number is chosen rather than discovered at 90%.
type instanceFloor struct {
	Items []floorItem
	Total float64
}

type floorItem struct {
	Name       string
	MonthlyUSD float64
	Why        string
}

func (f instanceFloor) print(w io.Writer, currency string) {
	items := append([]floorItem(nil), f.Items...)
	sort.SliceStable(items, func(i, j int) bool { return items[i].MonthlyUSD > items[j].MonthlyUSD })
	for _, it := range items {
		fmt.Fprintf(w, "  %-14s ~%s %6.2f/mo  %s\n", it.Name, currency, it.MonthlyUSD, it.Why)
	}
	fmt.Fprintf(w, "  %-14s ~%s %6.2f/mo\n", "total", currency, f.Total)
}

// floorNow is the standing cost of what this instance actually runs today.
func floorNow(meta *config.InstanceMetadata) instanceFloor {
	f := instanceFloor{}
	f.add("cluster", emptyClusterMonthlyUSD, "Autopilot's own managed workloads (ADR 0003, modelled)")
	if meta.Carrier != nil && meta.Carrier.Endpoint != "" {
		f.add("carrier", nlbMonthlyUSD, "the public mTLS load balancer (ADR 0005)")
	}
	if meta.FatLineDeployed {
		f.add("fatline", pricing.WorkloadMonthlyUSD(fldeploy.DefaultReplicas,
			fldeploy.RequestCPUMilli, fldeploy.RequestMemMiB), "the tunnel, two replicas (ADR 0009 decision 11)")
	}
	if meta.Keyholder != nil && meta.Keyholder.Deployed {
		f.add("keyholder", pricing.WorkloadMonthlyUSD(keyholderReplicas,
			dsdeploy.RequestCPUMilli, dsdeploy.RequestMemMiB), "storage's key holder, two replicas (ADR 0008 decision 6)")
	}
	if meta.Kernel != nil && meta.Kernel.Deployed {
		f.add("technocore", pricing.WorkloadMonthlyUSD(tcdeploy.Replicas,
			tcdeploy.RequestCPUMilli, tcdeploy.RequestMemMiB), "the kernel itself, one replica")
	}
	return f
}

// floorFull is the standing cost of a fully provisioned instance: connected,
// with storage, with a kernel.
//
// This is the figure a cost limit has to clear, not floorNow. An instance
// installed today has almost nothing running and a floor of about the cluster
// fee alone — checking against that would pass a limit the operator is
// guaranteed to breach two commands later.
func floorFull(meta *config.InstanceMetadata) instanceFloor {
	f := instanceFloor{}
	f.add("cluster", emptyClusterMonthlyUSD, "Autopilot's own managed workloads (ADR 0003, modelled)")
	f.add("carrier", nlbMonthlyUSD, "the public mTLS load balancer (ADR 0005)")
	f.add("fatline", pricing.WorkloadMonthlyUSD(fldeploy.DefaultReplicas,
		fldeploy.RequestCPUMilli, fldeploy.RequestMemMiB), "the tunnel, two replicas (ADR 0009 decision 11)")
	f.add("keyholder", pricing.WorkloadMonthlyUSD(keyholderReplicas,
		dsdeploy.RequestCPUMilli, dsdeploy.RequestMemMiB), "storage's key holder, two replicas (ADR 0008 decision 6)")
	f.add("technocore", pricing.WorkloadMonthlyUSD(tcdeploy.Replicas,
		tcdeploy.RequestCPUMilli, tcdeploy.RequestMemMiB), "the kernel itself, one replica")
	return f
}

func (f *instanceFloor) add(name string, usd float64, why string) {
	f.Items = append(f.Items, floorItem{Name: name, MonthlyUSD: usd, Why: why})
	f.Total += usd
}

// warnIfBelowFloor tells the operator when a limit cannot be met, and says by
// how much and out of what.
//
// It warns rather than refuses. The figures are a model of a published rate
// card (ADR 0009 decisions 4 and 10), the cluster line dominates and has never
// been checked against an invoice, and a tool that refused a limit on the
// strength of its own unverified arithmetic would be claiming more certainty
// than it has. Refusing would also be the wrong shape for the one case where a
// low limit is deliberate: an operator who intends to tear the instance down
// within the month.
//
// It reports whether the limit is below the floor, so a caller can decide
// whether to gate on it.
func warnIfBelowFloor(w io.Writer, limit config.CostLimit, f instanceFloor, what string) bool {
	if limit.Amount <= 0 || limit.Amount >= f.Total {
		return false
	}
	fmt.Fprintf(w, "\nThe cost limit is below what %s costs standing still.\n", what)
	fmt.Fprintf(w, "  limit          %s %.2f/%s\n", limit.Currency, limit.Amount, limit.Period)
	f.print(w, limit.Currency)
	fmt.Fprintf(w, "\nTechnoCore would reach the limit before a single application ran, stop every\n"+
		"application it is allowed to stop, and still be over — it never stops the tunnel\n"+
		"or the key holder, because that would make storage impossible to unseal while the\n"+
		"instance kept billing.\n")
	fmt.Fprintf(w, "These are estimates from published prices, not a bill; the cluster line dominates\n"+
		"and is the least certain of them.\n")
	return true
}
