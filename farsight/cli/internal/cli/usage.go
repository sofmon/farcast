package cli

import (
	"cmp"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/fatline/identity"
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

The Tunnel section is the operator's and keepers' own streams into the
instance, kept apart from application traffic. The monitor knows each peer
only by an opaque token of its leaf; the device names come from this
machine's record of the keepers it enrolled. A keeper enrolled elsewhere, or
before 2026-11-10, shows as not enrolled from this machine until re-enrolled.

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
	if doc.Version < oldestProfilesVersion || doc.Version > kernel.ProfilesVersion {
		return fmt.Errorf("the kernel wrote usage profiles version %d and this build reads versions %d to %d; one of them is older than the other",
			doc.Version, oldestProfilesVersion, kernel.ProfilesVersion)
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
		Apps:        appUsages(store.Summarize(doc.At)),
		Advice:      doc.Advice,
		Adapting:    doc.Adapting,
	}
	c.addNetwork(ctx, env, name, meta.Keepers, &res)
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
func (c *usageCommand) addNetwork(ctx context.Context, env *Env, name string, keepers []config.Keeper, res *usageResult) {
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

	// The tunnel half is named here, on the operator's machine, and nowhere
	// else: the monitor holds tokens, and this machine holds the fleet it
	// enrolled. The operator's own leaf is read alone — never the CA key —
	// and when it cannot be read, operator rows are still named by the role
	// FatLine verified.
	var operatorToken string
	if leaf, err := env.ConfigDir.LoadOperatorLeaf(name); err == nil {
		operatorToken, _ = identity.LeafTokenPEM(leaf)
	}
	res.Tunnel = attributeTunnel(snap.Tunnel, keepers, operatorToken, time.Now())
	res.TunnelSeparated = snap.TunnelSeparated
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

	Apps []appUsage `json:"apps,omitempty"`

	// Advice is what the kernel would set each application's reservation to,
	// and what it is waiting for where it holds. Adapting says whether it is
	// acting on it — without that, a report cannot tell a kernel holding back
	// from one merely thinking out loud.
	Advice   []kernel.Adaptation `json:"advice,omitempty"`
	Adapting bool                `json:"adapting,omitempty"`

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

	// Tunnel is the operator's and keepers' streams into the instance, each
	// peer named from this machine's records. Device names appear here — the
	// operator's own terminal and --json — and nowhere the provider reads.
	Tunnel []tunnelRow `json:"tunnel,omitempty"`
	// TunnelSeparated says the monitor kept tunnel streams out of the
	// application rows. False from a monitor older than that, whose
	// "(unidentified)" row includes them.
	TunnelSeparated bool `json:"tunnel_separated,omitempty"`
}

// oldestProfilesVersion is the oldest usage document this report reads.
//
// Version 1 named each profile by the application's bare name. The kernel
// discards one at restore, because it could never match it to a workload
// again; this report only shows it, so it reads it, names each profile as
// written, and says so — an operator who has updated this machine and not yet
// the kernel still sees what their applications use.
const oldestProfilesVersion = 1

// profileNote is what a profile named without its namespace says.
const profileNote = "profiled before the kernel recorded namespaces"

// appUsage is one application's profile, named by namespace and name as the
// kernel keys it. A profile with no namespace — from a kernel older than
// namespaced profiles — keeps an empty one and a note, never a guessed one.
type appUsage struct {
	Namespace string `json:"namespace"`
	Note      string `json:"note,omitempty"`
	usage.Summary
}

// label is the application as the report names it.
func (a appUsage) label() string {
	if a.Namespace == "" {
		return a.App
	}
	return kernel.AppKey(a.Namespace, a.App)
}

func appUsages(sums []usage.Summary) []appUsage {
	out := make([]appUsage, 0, len(sums))
	for _, s := range sums {
		ns, name, qualified := kernel.SplitAppKey(s.App)
		s.App = name
		a := appUsage{Namespace: ns, Summary: s}
		if !qualified {
			a.Note = profileNote
		}
		out = append(out, a)
	}
	return out
}

// adviceLabel is an advised workload as the report names it: as the profile
// table names it, by namespace and name.
func adviceLabel(a kernel.Adaptation) string {
	if a.Namespace == "" {
		return a.App
	}
	return kernel.AppKey(a.Namespace, a.App)
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
		fprintf(w, "  %-28s %4s  %9s %9s %8s   %9s %9s %8s  %s\n",
			"application", "pods", "cpu p95", "reserved", "spare", "mem p95", "reserved", "spare", "last hour")
		bare := false
		for _, a := range r.Apps {
			name := a.label()
			if a.Namespace == "" {
				name, bare = name+" *", true
			}
			fprintf(w, "  %-28s %4d  %9s %9s %8s   %9s %9s %8s  %s\n",
				name, a.Pods,
				milli(a.CPU.Day.P95), milli(a.RequestCPUMilli), spare(a.CPUHeadroom()),
				mib(a.Mem.Day.P95), mib(a.RequestMemMiB), spare(a.MemHeadroom()),
				trend(a.CPU))
		}
		if bare {
			fprintf(w, "  * %s; which namespace it ran in was not recorded.\n", profileNote)
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

	r.writeAdvice(w)
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

	// No closing note when there is advice: the right-sizing section above
	// already says what will and will not happen, and repeating it in weaker
	// words is how a report starts contradicting itself.
	if len(r.Advice) == 0 && len(r.Apps) > 0 {
		fprintln(w)
		fprintln(w, "The kernel has not published any sizing advice yet. It does so once a")
		fprintln(w, "workload has enough readings to size from — and it never sizes itself,")
		fprintln(w, "FatLine or the key holder, only applications.")
	}
	return nil
}

// writeAdvice renders what the kernel would do to each reservation.
//
// It is printed whether or not the kernel is acting on it, because an
// operator deciding whether to switch adapting on needs to see what it would
// have done to their own instance rather than to an example.
func (r usageResult) writeAdvice(w io.Writer) {
	if len(r.Advice) == 0 {
		return
	}
	fprintln(w)
	fprintln(w, "Right-sizing — what TechnoCore makes of that, per pod")
	fprintf(w, "  %-28s %14s %14s %10s  %s\n", "application", "reserved now", "would be", "per month", "")
	for _, a := range r.Advice {
		now := fmt.Sprintf("%dm/%dMi", a.CurrentCPUMilli, a.CurrentMemMiB)
		if !a.Act {
			fprintf(w, "  %-28s %14s %14s %10s  holding: %s\n", adviceLabel(a), now, "—", "—", a.Hold)
			continue
		}
		note := ""
		if a.Stepped {
			// Said out loud, or an operator reads a clamped step as the
			// system's final opinion and concludes it got the answer wrong.
			note = "a bounded step; it will move further next time"
		}
		fprintf(w, "  %-28s %14s %14s %10s  %s\n",
			adviceLabel(a), now, fmt.Sprintf("%dm/%dMi", a.CPUMilli, a.MemMiB),
			signedUSD(a.MonthlyDeltaUSD()), note)
	}
	fprintln(w)
	if r.Adapting {
		fprintln(w, "  Adapting is ON: the kernel applies this itself, one workload at a time,")
		fprintln(w, "  and leaves each alone for a cooldown afterwards. Every resize is a rollout.")
	} else {
		fprintln(w, "  Adapting is OFF: the kernel publishes this and changes nothing. Turn it on")
		fprintf(w, "  with 'farcast kernel deploy %s --adapt'.\n", r.Instance)
	}
}

// signedUSD renders a monthly delta so a saving reads as one.
func signedUSD(v float64) string {
	if v > -0.005 && v < 0.005 {
		return "—"
	}
	return fmt.Sprintf("%+.2f", v)
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
		// It can carry the monitor's own words ("the monitor answered …").
		fprintf(w, "  %s\n", terminalText(r.NetworkError))
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
	r.writeApplicationNetwork(w)
	r.writeTunnel(w)
}

// writeApplicationNetwork renders application egress, one row per application.
func (r usageResult) writeApplicationNetwork(w io.Writer) {
	if len(r.Network) == 0 {
		fprintln(w, "  No application has made an outbound connection.")
		return
	}
	unidentified := false
	fprintf(w, "  %-20s %5s %6s %6s %6s %10s %10s  %s\n",
		"application", "hosts", "conns", "failed", "denied", "out", "in", "connect")
	for _, a := range r.Network {
		// The monitor's report, like every string in this section.
		name := terminalText(a.App)
		if name == "" {
			// FatLine could not identify the caller. It is the row an
			// operator most needs to see, so it is named as what it is
			// rather than left blank.
			name = "(unidentified)"
			unidentified = true
		}
		fprintf(w, "  %-20s %5d %6d %6d %6d %10s %10s  %s\n",
			name, a.Hosts, a.Allows, a.Fails, a.Denies,
			humanBytes(a.BytesUp), humanBytes(a.BytesDown), connectTime(a.Latency))
	}
	fprintln(w)
	fprintln(w, "  'connect' is how long establishing the connection took, at the 90th")
	fprintln(w, "  percentile. Not request latency: FatLine never opens the tunnel it carries.")
	if unidentified && !r.TunnelSeparated {
		// An older monitor folded the operator's and keepers' streams into
		// the application tables, under no application. Said, so a keeper's
		// re-seed is not read as an application nobody can identify.
		fprintln(w, "  '(unidentified)' includes the operator's and keepers' tunnel streams;")
		fprintln(w, "  this monitor predates separating them.")
	}
}

// writeTunnel renders the operator's and keepers' streams into the instance.
//
// Kept apart from the application table because it is a different question:
// not what an application reached, but who came in through the tunnel and
// what FatLine let them open.
//
// The route is the PEER's word: for a route FatLine does not serve, it is
// whatever path the peer asked for, percent-decoded — and a keeper leaf is a
// peer, the one this table exists to catch misbehaving. Printed raw, an escape
// in it could erase the row that names its own refusal, or write the
// operator's clipboard. So every string here goes through terminalText, and
// the columns are measured on what is printed, not on what was sent. --json
// carries them as they came.
func (r usageResult) writeTunnel(w io.Writer) {
	if len(r.Tunnel) == 0 {
		return
	}
	fprintln(w)
	fprintln(w, "Tunnel — the operator's and keepers' streams into the instance")
	type shown struct{ who, route string }
	rows := make([]shown, len(r.Tunnel))
	whoWidth, routeWidth := len("who"), 10
	for i, t := range r.Tunnel {
		rows[i] = shown{who: terminalText(t.Who), route: terminalText(t.Route)}
		whoWidth = max(whoWidth, utf8.RuneCountInString(rows[i].who))
		routeWidth = max(routeWidth, utf8.RuneCountInString(rows[i].route))
	}
	fprintf(w, "  %-*s %-*s %7s %7s %6s %10s %10s  %-10s %s\n",
		whoWidth, "who", routeWidth, "route", "relayed", "refused", "failed", "out", "in", "last seen", "refused because")
	unnamed := false
	for i, t := range r.Tunnel {
		if t.Who == unnamedKeeper {
			unnamed = true
		}
		last := "—"
		if !t.LastSeen.IsZero() {
			last = since(t.LastSeen) + " ago"
		}
		fprintf(w, "  %-*s %-*s %7d %7d %6d %10s %10s  %-10s %s\n",
			whoWidth, rows[i].who, routeWidth, rows[i].route, t.Relayed, t.Refused, t.Failed,
			humanBytes(t.BytesUp), humanBytes(t.BytesDown), last, reasons(t.Reasons))
	}
	if unnamed {
		fprintln(w)
		fprintln(w, "  A keeper this machine cannot name was enrolled elsewhere, or before")
		fprintln(w, "  enrolment recorded leaf tokens (2026-11-10). Re-enrolling it from here")
		fprintln(w, "  names it; until then its leaf stays valid to its own expiry.")
	}
}

// reasons renders a refusal breakdown, most frequent first. The reasons are
// FatLine's codes as the monitor reported them, so each goes through
// terminalText like every other string from the monitor.
func reasons(m map[string]int64) string {
	if len(m) == 0 {
		return ""
	}
	keys := slices.Collect(maps.Keys(m))
	slices.SortFunc(keys, func(a, b string) int {
		if c := cmp.Compare(m[b], m[a]); c != 0 {
			return c
		}
		return strings.Compare(a, b)
	})
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s %d", terminalText(k), m[k])
	}
	return strings.Join(parts, ", ")
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
		// The monitor names its own pod; its word, so terminalText.
		who = ", " + terminalText(r.NetworkReplica)
	}
	switch {
	case r.Replicas > 1:
		fprintf(w, "  Seen by one FatLine replica of %d%s.\n", r.Replicas, who)
		fprintf(w, "  Each keeps its own picture, so these are that replica's share, not the total.\n")
	case r.Replicas == 1:
		fprintf(w, "  Seen by the only FatLine replica%s — this is the whole picture.\n", who)
	default:
		fprintf(w, "  Seen by one FatLine replica%s, of an unknown number.\n", who)
		fprintf(w, "  Whether this is the whole picture or one replica's share cannot be said.\n")
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
