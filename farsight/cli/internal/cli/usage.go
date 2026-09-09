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
	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/shrike"
	"github.com/sofmon/farcast/technocore/deploy"
	"github.com/sofmon/farcast/technocore/kernel"
	"github.com/sofmon/farcast/technocore/usage"
)

// usageReader is what the compute half needs from the cluster, plus the one
// thing the network half needs: how many FatLine replicas there are. A
// picture read from one of several is a share, not a total, and the report
// cannot say so without knowing the count.
type usageReaderIface interface {
	configMapReader
	Workloads(ctx context.Context, namespace string) ([]cluster.Workload, error)
}

type usageCommand struct {
	newCluster func(kubeconfigPath string) usageReaderIface
	// newDialer opens the tunnel the network half is read through. It is a
	// seam so the report can be tested without a cluster, and it is separate
	// from newCluster because the two halves come from two places and either
	// can be unavailable on its own.
	newDialer func(ctx context.Context, env *Env, instance string) (streamDialer, func(), error)
	noNetwork bool
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

Compute comes from the kernel's own profiles (ADR 0014), collected on its
reconcile tick from the same reading 'kubectl top' shows. Network comes from
Shrike, through the FatLine tunnel, because the boundary is the only place
that sees an application's traffic at all. Both are advisory — nothing in the
cost path reads them, and what could not be measured is reported as unmeasured
rather than as zero.

The network latency is CONNECTION latency, not request latency: FatLine
tunnels CONNECT opaquely and never terminates TLS, so what happens inside a
connection is ciphertext by construction.

Quantiles are bucketed and rounded UP, so a figure here is at or above what
was observed, never below it. Nothing adjusts anything yet; that is 5.2.

For storage consumption, see 'farcast storage usage'.`)
}

func (c *usageCommand) SetFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.noNetwork, "no-network", false, "skip the network half; do not open the tunnel")
}

func (c *usageCommand) ensureDefaults() {
	if c.newCluster == nil {
		c.newCluster = func(kc string) usageReaderIface { return cluster.New(kc) }
	}
	if c.newDialer == nil {
		c.newDialer = func(ctx context.Context, env *Env, instance string) (streamDialer, func(), error) {
			conn, _, err := instanceTunnel(ctx, env, instance)
			if err != nil {
				return nil, nil, err
			}
			return conn, func() { _ = conn.Close() }, nil
		}
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
	c.addNetwork(ctx, env, name, &res)
	res.Replicas = fatlineReplicas(ctx, cl)
	return env.Printer.Print(res)
}

// addNetwork fills in the network half, or records why it could not.
//
// It never fails the command. The two halves are read from two places — the
// kernel's ConfigMap through the API server, and Shrike's picture through the
// tunnel — and an operator whose tunnel is down should still be told what
// their applications are using, with the missing half named rather than shown
// as zeros.
func (c *usageCommand) addNetwork(ctx context.Context, env *Env, name string, res *usageResult) {
	if c.noNetwork {
		res.NetworkSkipped = true
		return
	}
	dialer, done, err := c.newDialer(ctx, env, name)
	if err != nil {
		res.NetworkError = err.Error()
		return
	}
	defer done()
	snap, err := fetchNetwork(ctx, dialer)
	if err != nil {
		res.NetworkError = err.Error()
		return
	}
	res.Network = snap.Apps
	res.NetworkSince = snap.Since
	res.NetworkEvents = snap.Events
	res.NetworkReplica = snap.Replica
}

// fatlineReplicas is how many FatLine pods are keeping their own picture.
//
// Zero means it could not be determined, which the report says rather than
// guessing one — claiming a single replica when there are two would turn a
// partial count into an apparent total.
func fatlineReplicas(ctx context.Context, cl usageReaderIface) int {
	loads, err := cl.Workloads(ctx, deploy.DefaultNamespace)
	if err != nil {
		return 0
	}
	for _, w := range loads {
		if w.Name == fldeploy.DefaultName {
			return w.Desired
		}
	}
	return 0
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

	// Network is the per-application traffic picture from Shrike, and
	// NetworkError is why there is none. A report with neither is an instance
	// whose applications have made no outbound connection at all — which is a
	// real answer, and a different one from "the monitor could not be read".
	Network       []shrike.AppStat `json:"network,omitempty"`
	NetworkSince  time.Time        `json:"network_since,omitzero"`
	NetworkEvents int64            `json:"network_events,omitempty"`
	NetworkError  string           `json:"network_error,omitempty"`
	// NetworkReplica is the FatLine pod the picture came from, and Replicas
	// how many there are. Each replica keeps its own picture, so with more
	// than one these counts are that replica's share of the instance's
	// traffic — reporting them as a total would be wrong, and would change
	// between two consecutive reads.
	NetworkReplica string `json:"network_replica,omitempty"`
	Replicas       int    `json:"fatline_replicas,omitempty"`
	// NetworkSkipped records that --no-network was given, so an empty section
	// is never mistaken for an instance that is not talking to anything.
	NetworkSkipped bool `json:"network_skipped,omitempty"`
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

	r.writeNetwork(w)

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

// writeNetwork renders the traffic half, or says why there is none.
func (r usageResult) writeNetwork(w io.Writer) {
	fprintln(w)
	switch {
	case r.NetworkSkipped:
		fprintln(w, "Network not read — --no-network was given.")
		return
	case r.NetworkError != "":
		fprintln(w, "Network not measured — this was not read, which is not the same as zero:")
		fprintf(w, "  %s\n", r.NetworkError)
		fprintln(w, "The monitor is read through the FatLine tunnel; 'farcast connect <instance> --status'")
		fprintln(w, "says whether that is up. An instance running FatLine alone has no monitor to read.")
		return
	}

	fprintf(w, "Network — what crossed the boundary, per application")
	if !r.NetworkSince.IsZero() {
		fprintf(w, ", since %s", r.NetworkSince.Format("2006-01-02 15:04"))
	}
	fprintln(w)
	r.writeReplicaCaveat(w)
	if len(r.Network) == 0 {
		fprintln(w, "  No application has made an outbound connection.")
		return
	}
	fprintf(w, "  %-20s %5s %6s %6s %6s %10s %10s  %s\n",
		"application", "hosts", "conns", "failed", "denied", "out", "in", "connect")
	for _, a := range r.Network {
		name := a.App
		if name == "" {
			// FatLine could not identify the caller. It is the row an
			// operator most needs to see, so it is named as what it is
			// rather than left blank.
			name = "(unidentified)"
		}
		fprintf(w, "  %-20s %5d %6d %6d %6d %10s %10s  %s\n",
			name, a.Hosts, a.Allows, a.Fails, a.Denies,
			humanBytes(a.BytesUp), humanBytes(a.BytesDown), connectTime(a.Latency))
	}
	fprintln(w)
	fprintln(w, "  'connect' is how long establishing the connection took, at the 90th")
	fprintln(w, "  percentile. Not request latency: FatLine never opens the tunnel it carries.")
}

// writeReplicaCaveat says whose picture this is.
//
// A FatLine with two replicas keeps two pictures, and a read lands on
// whichever pod terminated the tunnel — so consecutive reports alternate
// between two different partial counts. Saying so is the difference between a
// number an operator can use and one that quietly contradicts itself.
func (r usageResult) writeReplicaCaveat(w io.Writer) {
	// The warning turns on the REPLICA COUNT, not on the monitor naming
	// itself. A sidecar older than this build sends no name, and that must
	// not be the thing that decides whether an operator is told their counts
	// are a share — the count comes from the cluster and is enough on its own.
	who := ""
	if r.NetworkReplica != "" {
		who = " " + r.NetworkReplica
	}
	switch {
	case r.Replicas > 1:
		fprintf(w, "  Seen by one FatLine replica%s, of %d. Each keeps its own picture, so these\n", who, r.Replicas)
		fprintf(w, "  are that replica's share of the instance's traffic, not the total.\n")
	case r.Replicas == 1:
		fprintf(w, "  Seen by the only FatLine replica%s — this is the whole picture.\n", who)
	default:
		fprintf(w, "  Seen by one FatLine replica%s. How many replicas there are could not be read,\n", who)
		fprintf(w, "  so whether this is the whole picture or one replica's share is unknown.\n")
	}
}

// connectTime renders the connection-time band and peak.
func connectTime(l shrike.Latency) string {
	if l.Count == 0 {
		return "—"
	}
	return fmt.Sprintf("%s (max %s)", l.Band(0.90), humanMillis(l.MaxMillis))
}

// humanMillis renders a duration the way an operator reads one: milliseconds
// until they stop being legible as milliseconds.
func humanMillis(ms int64) string {
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	return fmt.Sprintf("%.1fs", float64(ms)/1000)
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
