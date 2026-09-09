package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/technocore/deploy"
	"github.com/sofmon/farcast/technocore/kernel"
	"github.com/sofmon/farcast/technocore/usage"
)

type usageCommand struct {
	newCluster func(kubeconfigPath string) configMapReader
}

func (*usageCommand) Name() string { return "usage" }
func (*usageCommand) Synopsis() string {
	return "Show what applications actually use, against what they reserve"
}

func (*usageCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast usage <instance>

What one POD of each application actually consumed, against what it reserves.
Per pod, not per application: summing replicas and reserving the total would
be wrong by the replica count.

The numbers come from the kernel's own profiles (ADR 0014), collected on its
reconcile tick from the same reading 'kubectl top' shows. They are advisory —
nothing in the cost path reads them, and a cluster that serves no metrics is
reported as unmeasured rather than as zero.

Quantiles are bucketed and rounded UP, so a figure here is at or above what
was observed, never below it. Nothing adjusts anything yet; that is 5.2.

For storage consumption, see 'farcast storage usage'.`)
}

func (c *usageCommand) SetFlags(*flag.FlagSet) {}

func (c *usageCommand) ensureDefaults() {
	if c.newCluster == nil {
		c.newCluster = func(kc string) configMapReader { return cluster.New(kc) }
	}
}

func (c *usageCommand) Run(ctx context.Context, env *Env, args []string) error {
	if len(args) != 1 {
		return usagef("usage takes one instance argument")
	}
	name := args[0]
	c.ensureDefaults()

	meta, err := env.ConfigDir.LoadInstanceMetadata(name)
	if err != nil {
		return fmt.Errorf("load instance %q: %w", name, err)
	}
	if meta.Kernel == nil || !meta.Kernel.Deployed {
		return fmt.Errorf("instance %q has no kernel, so nothing is watching it; run 'farcast kernel deploy %s'", name, name)
	}

	cl := c.newCluster(env.ConfigDir.InstanceKubeconfigPath(name))
	raw, found, err := cl.ConfigMapValue(ctx, deploy.DefaultNamespace, kernel.DefaultProfilesName, kernel.ProfilesKey())
	if err != nil {
		return fmt.Errorf("read the kernel's usage profiles: %w", err)
	}
	if !found {
		return fmt.Errorf("the kernel in %q has not written any usage profiles yet; it writes them on the same schedule as the ledger, within a few minutes of starting", name)
	}
	var doc kernel.Profiles
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return fmt.Errorf("decode the kernel's usage profiles: %w", err)
	}
	if doc.Version != kernel.ProfilesVersion {
		return fmt.Errorf("the kernel wrote usage profiles version %d and this build reads %d; one of them is older than the other",
			doc.Version, kernel.ProfilesVersion)
	}
	store, err := usage.Restore(doc.Store)
	if err != nil {
		return fmt.Errorf("restore the kernel's usage profiles: %w", err)
	}

	// Summarised as of when the KERNEL wrote the document, not now. Sliding
	// the window forward to the local clock would report "the last hour" from
	// a document written ten minutes ago as empty, and read as an instance
	// that had gone quiet.
	res := usageResult{
		Instance:    name,
		At:          doc.At,
		Ago:         since(doc.At),
		Hours:       store.Hours(),
		Unavailable: doc.Unavailable,
		TrimmedTo:   doc.TrimmedTo,
		Dropped:     doc.Dropped,
		Apps:        store.Summarize(doc.At),
	}
	return env.Printer.Print(res)
}

type usageResult struct {
	Instance string    `json:"instance"`
	At       time.Time `json:"at"`
	Ago      string    `json:"ago,omitempty"`
	Hours    int       `json:"hours"`

	// Unavailable names namespaces the kernel could not read metrics for.
	// "Not measured" and "measured as zero" are different states and an
	// operator has to be able to tell them apart.
	Unavailable []string `json:"unavailable,omitempty"`
	TrimmedTo   int      `json:"trimmed_to,omitempty"`
	Dropped     []string `json:"dropped,omitempty"`

	Apps []usage.Summary `json:"apps,omitempty"`
}

func (r usageResult) Human(w io.Writer) error {
	fprintf(w, "Observed usage in %q — %dh window", r.Instance, r.Hours)
	if r.Ago != "" {
		fprintf(w, ", written %s ago", r.Ago)
	}
	fprintln(w)
	fprintln(w, "What ONE POD of each application used, against what one pod reserves.")
	fprintln(w)

	if len(r.Apps) == 0 {
		fprintln(w, "  Nothing profiled yet.")
	} else {
		fprintf(w, "  %-20s %4s  %9s %9s %8s   %9s %9s %8s  %s\n",
			"application", "pods", "cpu p95", "reserved", "spare", "mem p95", "reserved", "spare", "last hour")
		for _, a := range r.Apps {
			fprintf(w, "  %-20s %4d  %9s %9s %8s   %9s %9s %8s  %s\n",
				a.App, a.Pods,
				milli(a.CPU.Day.P95), milli(a.RequestCPUMilli), spare(a.CPUHeadroom()),
				mib(a.Mem.Day.P95), mib(a.RequestMemMiB), spare(a.MemHeadroom()),
				trend(a.CPU))
		}
		fprintln(w)
		fprintln(w, "  'spare' is what a pod reserves divided by its p95 — 4.0x means four times")
		fprintln(w, "  the observed need is being paid for. 'thin' means too few readings to say.")
	}

	if len(r.Unavailable) > 0 {
		fprintln(w)
		fprintln(w, "Not measured — these were not read, which is not the same as zero:")
		for _, u := range r.Unavailable {
			fprintf(w, "  %s\n", u)
		}
		fprintln(w, "A cluster with no metrics API, or a kernel deployed before it was granted")
		fprintln(w, "metrics.k8s.io, reports exactly this. Redeploying the kernel grants it.")
	}

	if r.TrimmedTo > 0 || len(r.Dropped) > 0 {
		fprintln(w)
		if r.TrimmedTo > 0 {
			fprintf(w, "The window was shortened to %dh to fit the profile document's size budget.\n", r.TrimmedTo)
		}
		if len(r.Dropped) > 0 {
			fprintf(w, "Dropped to fit, least recently seen first: %s\n", strings.Join(r.Dropped, ", "))
		}
	}

	fprintln(w)
	fprintln(w, "Nothing adjusts anything on the strength of this yet — TechnoCore reports it")
	fprintln(w, "and the reservations stay as declared. Acting on it is Phase 5.2.")
	return nil
}

// spare renders a headroom ratio, or says why there is not one.
func spare(ratio float64, ok bool) string {
	if !ok {
		return "thin"
	}
	return fmt.Sprintf("%.1fx", ratio)
}

func milli(v int) string {
	if v <= 0 {
		return "—"
	}
	return fmt.Sprintf("%dm", v)
}

func mib(v int) string {
	if v <= 0 {
		return "—"
	}
	return fmt.Sprintf("%dMi", v)
}

// trend compares the last hour against the whole window. It is what "trend"
// means with a bounded distribution and no stored series: whether the recent
// hour sits above the day, not how it got there.
func trend(w usage.Windows) string {
	if w.Day.Thin() {
		return "collecting"
	}
	if w.Hour.Samples == 0 || w.Day.P95 == 0 {
		return "—"
	}
	switch ratio := float64(w.Hour.P95) / float64(w.Day.P95); {
	case ratio > 1.25:
		return "rising"
	case ratio < 0.8:
		return "falling"
	default:
		return "steady"
	}
}
