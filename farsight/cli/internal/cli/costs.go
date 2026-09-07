package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/technocore/cost"
	"github.com/sofmon/farcast/technocore/deploy"
	"github.com/sofmon/farcast/technocore/kernel"
)

// configMapReader is the slice of the cluster client a cost report needs.
type configMapReader interface {
	ConfigMapValue(ctx context.Context, namespace, name, key string) (string, bool, error)
}

type costsCommand struct {
	newCluster func(kubeconfigPath string) configMapReader
}

func (*costsCommand) Name() string { return "costs" }
func (*costsCommand) Synopsis() string {
	return "Show spending and distance to the cost limit"
}

func (*costsCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast costs <instance>

What the instance has spent this period, broken down by application, and how
far it is from its limit.

Two figures, not one (ADR 0009). 'expected' is metered locally from Pod
requests in real time and is what protective action fires on. 'confirmed' is
the provider's own number for a window that has closed, arrives about a day
later, and never drives an action — it corrects 'expected' and calibrates the
model behind it, within a clamp.

Every figure comes from the kernel's own checkpoint rather than being modelled
again here, so what is shown is what enforcement is acting on. It is as recent
as the last checkpoint, and says when that was.`)
}

func (c *costsCommand) SetFlags(*flag.FlagSet) {}

func (c *costsCommand) ensureDefaults() {
	if c.newCluster == nil {
		c.newCluster = func(kc string) configMapReader { return cluster.New(kc) }
	}
}

func (c *costsCommand) Run(ctx context.Context, env *Env, args []string) error {
	if len(args) != 1 {
		return usagef("costs takes one instance argument")
	}
	name := args[0]
	c.ensureDefaults()

	meta, err := env.ConfigDir.LoadInstanceMetadata(name)
	if err != nil {
		return fmt.Errorf("load instance %q: %w", name, err)
	}
	if meta.Kernel == nil || !meta.Kernel.Deployed {
		return fmt.Errorf("instance %q has no kernel, so nothing is metering it; run 'farcast kernel deploy %s'", name, name)
	}

	cl := c.newCluster(env.ConfigDir.InstanceKubeconfigPath(name))
	raw, found, err := cl.ConfigMapValue(ctx, deploy.DefaultNamespace, kernel.DefaultCheckpointName, kernel.CheckpointKey())
	if err != nil {
		return fmt.Errorf("read the kernel's ledger: %w", err)
	}
	if !found {
		return fmt.Errorf("the kernel in %q has not checkpointed yet; it writes one within a few minutes of starting", name)
	}
	var cp kernel.Checkpoint
	if err := json.Unmarshal([]byte(raw), &cp); err != nil {
		return fmt.Errorf("decode the kernel's ledger: %w", err)
	}
	if cp.Version != kernel.CheckpointVersion {
		return fmt.Errorf("the kernel wrote ledger version %d and this build reads %d; one of them is older than the other",
			cp.Version, kernel.CheckpointVersion)
	}
	ledger, err := cost.Restore(cp.Ledger)
	if err != nil {
		return fmt.Errorf("restore the kernel's ledger: %w", err)
	}

	accrual := ledger.Accrued()
	start, end := ledger.Period()
	now := time.Now().UTC()

	// Assessed against the limit the KERNEL holds, not the one recorded here.
	// When they differ the cluster is still acting on its own, and a report
	// that quietly used the local figure would describe an enforcement that
	// is not happening.
	limit := cp.Observed.Limit
	if limit <= 0 {
		limit = meta.CostLimit.Amount
	}
	res := costsResult{
		Instance: name, Currency: currencyOf(meta),
		Period: meta.CostLimit.Period, PeriodStart: start, PeriodEnd: end,
		Expected: accrual.Expected, Confirmed: accrual.Confirmed, Total: accrual.Total,
		HasConfirmation: accrual.HasConfirmation, ConfirmedThrough: accrual.ConfirmedThrough,
		Calibration:   accrual.Calibration,
		Assessment:    cost.Assess(accrual.Total, limit, cp.Observed.RateHourlyUSD, now, end),
		Observed:      cp.Observed,
		ObservedAgo:   since(cp.Observed.At),
		RecordedLimit: meta.CostLimit.Amount,
		Apps:          appSpend(ledger.ByApp()),
	}
	for _, d := range accrual.Discrepancies {
		res.Discrepancies = append(res.Discrepancies, d.String())
	}
	return env.Printer.Print(res)
}

func appSpend(byApp map[string]float64) []appCost {
	out := make([]appCost, 0, len(byApp))
	for name, usd := range byApp {
		if name == "" {
			name = "(unattributed)"
		}
		out = append(out, appCost{Name: name, USD: usd})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].USD != out[j].USD {
			return out[i].USD > out[j].USD
		}
		return out[i].Name < out[j].Name
	})
	return out
}

type appCost struct {
	Name string  `json:"name"`
	USD  float64 `json:"usd"`
}

type costsResult struct {
	Instance    string    `json:"instance"`
	Currency    string    `json:"currency"`
	Period      string    `json:"period,omitempty"`
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`

	Expected         float64   `json:"expected"`
	Confirmed        float64   `json:"confirmed"`
	Total            float64   `json:"total"`
	HasConfirmation  bool      `json:"has_confirmation"`
	ConfirmedThrough time.Time `json:"confirmed_through,omitzero"`
	Calibration      float64   `json:"calibration"`

	Assessment    cost.Assessment    `json:"assessment"`
	Observed      kernel.Observation `json:"observed"`
	ObservedAgo   string             `json:"observed_ago,omitempty"`
	RecordedLimit float64            `json:"recorded_limit,omitempty"`

	Apps          []appCost `json:"apps,omitempty"`
	Discrepancies []string  `json:"discrepancies,omitempty"`
}

func (r costsResult) Human(w io.Writer) error {
	cur := r.Currency
	fmt.Fprintf(w, "Spending in %q", r.Instance)
	if r.Period != "" {
		fmt.Fprintf(w, " — %s period", r.Period)
	}
	fmt.Fprintf(w, ", %s to %s\n\n", r.PeriodStart.Format("2006-01-02"), r.PeriodEnd.Format("2006-01-02"))

	fmt.Fprintf(w, "  expected   %s %8.2f  metered locally from Pod requests, in real time\n", cur, r.Expected)
	if r.HasConfirmation {
		fmt.Fprintf(w, "  confirmed  %s %8.2f  the provider's own figure, through %s\n",
			cur, r.Confirmed, r.ConfirmedThrough.Format("2006-01-02 15:04"))
	} else {
		// Never printed as a confirmed zero. A missing feed and a period that
		// genuinely cost nothing look identical in a number and are not the
		// same thing (ADR 0009 decision 5).
		fmt.Fprintf(w, "  confirmed  %8s      the provider has confirmed nothing yet\n", "—")
	}
	fmt.Fprintf(w, "  total      %s %8.2f  what enforcement compares against the limit\n", cur, r.Total)

	a := r.Assessment
	if a.Limit > 0 {
		fmt.Fprintf(w, "  limit      %s %8.2f  %.0f%% of it, %s\n", cur, a.Limit, a.Fraction*100, a.Level.String())
		fmt.Fprintf(w, "  remaining  %s %8.2f\n", cur, max(a.Limit-a.Total, 0))
	} else {
		fmt.Fprintf(w, "  limit      none recorded — nothing will be stopped\n")
	}

	if r.RecordedLimit > 0 && a.Limit > 0 && r.RecordedLimit != a.Limit {
		fmt.Fprintf(w, "\nThe kernel is enforcing %s %.2f; this machine has %s %.2f recorded.\n",
			cur, a.Limit, cur, r.RecordedLimit)
		fmt.Fprintf(w, "The cluster acts on its own until 'farcast kernel deploy %s' redeploys it.\n", r.Instance)
	}

	fmt.Fprintf(w, "\n  rate       %s %.4f/hour across %s",
		cur, r.Observed.RateHourlyUSD, plural(r.Observed.Pods, "pod", "pods"))
	if r.ObservedAgo != "" {
		fmt.Fprintf(w, ", observed %s ago", r.ObservedAgo)
	}
	fmt.Fprintln(w)

	if a.ProjectedOver {
		fmt.Fprintf(w, "\nOn course to reach the limit on %s, at %s %.2f for the period.\n",
			a.ProjectedAt.Format("2006-01-02 15:04"), cur, a.Projected)
		fmt.Fprintf(w, "That is a warning and nothing acts on it: a projection is not spending.\n")
	}

	if len(r.Apps) > 0 {
		fmt.Fprintf(w, "\nBy application:\n")
		for _, app := range r.Apps {
			fmt.Fprintf(w, "  %-24s %s %8.2f\n", app.Name, cur, app.USD)
		}
		// Attribution is always local. The provider bills an instance, not an
		// application, so `confirmed` cannot be broken down and saying which
		// figure this is matters.
		fmt.Fprintf(w, "\nAttribution is from 'expected' only — the provider bills the instance, not\n")
		fmt.Fprintf(w, "the applications in it, so a confirmed total can never be split this way.\n")
	}

	if r.Observed.Unclassified > 0 {
		fmt.Fprintf(w, "\n%s carry no tier label and are protected from a cost shutdown as a result.\n",
			plural(r.Observed.Unclassified, "pod", "pods"))
	}
	if r.Observed.Incomplete {
		fmt.Fprintf(w, "\nThe kernel could not read every namespace it meters:\n")
		for _, u := range r.Observed.Unreachable {
			fmt.Fprintf(w, "  %s\n", u)
		}
		fmt.Fprintf(w, "These figures are a floor, not a total.\n")
	}
	for _, d := range r.Discrepancies {
		fmt.Fprintf(w, "\nBilling disagrees with the model beyond the clamp; the estimate stands: %s\n", d)
	}
	if r.Calibration != 0 && r.Calibration != 1 {
		fmt.Fprintf(w, "\nThe local model is calibrated by %.3f against confirmed figures.\n", r.Calibration)
	}
	return nil
}
