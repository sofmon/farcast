package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/technocore/cost"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
	"github.com/sofmon/farcast/technocore/kernel"
)

// kernelConfirmCommand pushes the cloud provider's own figure for a closed
// window into an instance.
//
// This is channel B1 of [ADR 0009] decision 4: the operator's machine already
// holds the cloud credential, so it reads the bill and pushes the number. The
// kernel never holds a billing credential — reading billing in-cluster would
// need a grant scoped to a *billing account*, which spans every project the
// operator owns and not just FarCast's.
//
// [ADR 0009]: ../../../../docs/adr/0009-technocore-kernel-and-cost-metering.md
type kernelConfirmCommand struct {
	deployer fatlineDeployer
	from     string
	to       string

	// amount is tracked with an explicit "was it given" flag rather than a
	// sentinel value, because zero is a real answer: an idle window genuinely
	// cost nothing. A -1 sentinel only exists once SetFlags has run, so a
	// command constructed any other way would read "unspecified" as
	// "confirmed zero" — the same distinction the kernel keeps between no
	// confirmation and a confirmed zero, and it has to hold here too.
	amount    float64
	amountSet bool
}

func (*kernelConfirmCommand) Name() string { return "confirm" }
func (*kernelConfirmCommand) Synopsis() string {
	return "Push the provider's confirmed cost for a closed window into an instance"
}

func (*kernelConfirmCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast kernel confirm <instance> --amount <n> [--from YYYY-MM-DD] [--to YYYY-MM-DD]

Tell the kernel what the cloud provider actually charged for a window that has
closed.

The kernel meters continuously from declared resource requests — that figure is
'expected', and it is what protective action fires on. This command supplies
'confirmed': the provider's own number, which arrives late, never drives an
action, and exists to correct the estimate and calibrate the model behind it.

Windows must not overlap. With no --from, this continues from the end of the
last window pushed for the current period (or the period's start); with no --to,
it ends at today's UTC midnight — so running this daily appends one window per
day without any bookkeeping on your part.

A confirmation cannot switch the guard off. If it disagrees with the local
model by more than a factor of two the kernel refuses the correction, keeps the
more conservative of the two figures, and reports the disagreement.`)
}

func (c *kernelConfirmCommand) SetFlags(fs *flag.FlagSet) {
	fs.Func("amount", "what the provider charged for the window (required)", func(v string) error {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return fmt.Errorf("want a number, got %q", v)
		}
		c.amount, c.amountSet = f, true
		return nil
	})
	fs.StringVar(&c.from, "from", "", "window start, YYYY-MM-DD (default: where the last push ended)")
	fs.StringVar(&c.to, "to", "", "window end, YYYY-MM-DD exclusive (default: today, UTC)")
	c.deployer.setYesFlag(fs, "unused; accepted so scripts can pass it uniformly")
}

func (c *kernelConfirmCommand) Run(ctx context.Context, env *Env, args []string) error {
	if len(args) != 1 {
		return usagef("kernel confirm takes one instance argument")
	}
	name := args[0]
	c.deployer.ensureDefaults()

	meta, err := env.ConfigDir.LoadInstanceMetadata(name)
	if err != nil {
		return fmt.Errorf("load instance %q: %w", name, err)
	}
	if meta.Kernel == nil || !meta.Kernel.Deployed {
		return fmt.Errorf("instance %q has no kernel; run 'farcast kernel deploy %s' first", name, name)
	}
	if !c.amountSet {
		return usagef("--amount is required (what the provider charged for the window)")
	}
	if c.amount < 0 {
		return usagef("--amount must not be negative, got %v", c.amount)
	}

	now := time.Now().UTC()
	periodStart, periodEnd, err := cost.PeriodFor(now, limitPeriod(meta.CostLimit))
	if err != nil {
		return err
	}

	from, err := c.resolveFrom(meta, periodStart)
	if err != nil {
		return err
	}
	to, err := resolveDay(c.to, dayStart(now))
	if err != nil {
		return usagef("--to: %v", err)
	}

	if !to.After(from) {
		// Not an error: a daily push that runs twice in one day has nothing
		// new to confirm, and failing would make a cron job noisy for doing
		// exactly the right thing.
		fprintf(env.Err, "Nothing to confirm: the window from %s to %s is empty.\n",
			from.Format(time.DateOnly), to.Format(time.DateOnly))
		return env.Printer.Print(confirmResult{Instance: name, Confirmed: false})
	}
	if from.Before(periodStart) || to.After(periodEnd) {
		return usagef("the window %s..%s falls outside the current %s period (%s..%s); the kernel only accounts for the period it is in",
			from.Format(time.DateOnly), to.Format(time.DateOnly), limitPeriod(meta.CostLimit),
			periodStart.Format(time.DateOnly), periodEnd.Format(time.DateOnly))
	}

	next := config.KernelConfirmation{Start: from, End: to, USD: c.amount, AsOf: now}
	kept, err := mergeConfirmations(meta.Kernel.Confirmations, next, periodStart, periodEnd)
	if err != nil {
		return err
	}

	// Recorded before the apply, like every other thing this CLI changes in a
	// cluster: a confirmation the cluster has and local state does not is one
	// the next push would try to add again.
	previous := meta.Kernel.Confirmations
	meta.Kernel.Confirmations = kept
	meta.UpdatedAt = now
	if err := env.ConfigDir.SaveInstanceMetadata(name, meta); err != nil {
		return fmt.Errorf("record the confirmation before pushing it: %w", err)
	}

	manifest, err := kernel.RenderConfigMap(tcdeploy.DefaultNamespace, kernel.DefaultConfirmationsName, toCostConfirmations(kept))
	if err != nil {
		return err
	}
	cl := c.deployer.newCluster(env.ConfigDir.InstanceKubeconfigPath(name))
	if err := cl.Apply(ctx, manifest); err != nil {
		// Put local state back: a recorded confirmation the cluster never
		// received would silently be skipped by the next push, and the window
		// would go unconfirmed forever.
		meta.Kernel.Confirmations = previous
		if saveErr := env.ConfigDir.SaveInstanceMetadata(name, meta); saveErr != nil {
			return fmt.Errorf("push the confirmation: %w (and local state could not be rolled back: %v)", err, saveErr)
		}
		return fmt.Errorf("push the confirmation: %w", err)
	}

	return env.Printer.Print(confirmResult{
		Instance: name, Confirmed: true,
		From: from, To: to, Amount: c.amount,
		Currency: meta.CostLimit.Currency, Windows: len(kept),
	})
}

// resolveFrom continues from where the last push ended, so running this daily
// appends one window per day with no bookkeeping by the operator.
func (c *kernelConfirmCommand) resolveFrom(meta *config.InstanceMetadata, periodStart time.Time) (time.Time, error) {
	if c.from != "" {
		t, err := resolveDay(c.from, time.Time{})
		if err != nil {
			return time.Time{}, usagef("--from: %v", err)
		}
		return t, nil
	}
	latest := periodStart
	for _, k := range meta.Kernel.Confirmations {
		if !k.End.Before(periodStart) && k.End.After(latest) {
			latest = k.End
		}
	}
	return latest, nil
}

func resolveDay(v string, fallback time.Time) (time.Time, error) {
	if v == "" {
		return fallback, nil
	}
	t, err := time.Parse(time.DateOnly, v)
	if err != nil {
		return time.Time{}, fmt.Errorf("want YYYY-MM-DD, got %q", v)
	}
	return t.UTC(), nil
}

func dayStart(t time.Time) time.Time {
	u := t.UTC()
	return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
}

// limitPeriod is the instance's limit period, defaulting to monthly for
// instances recorded before the field was written.
func limitPeriod(l config.CostLimit) string {
	if l.Period == "" {
		return cost.PeriodMonthly
	}
	return l.Period
}

// mergeConfirmations adds one window to the set, dropping anything from an
// earlier period and refusing an overlap.
//
// Overlaps are refused here rather than left to the kernel because the kernel's
// only recourse is to skip the window silently — it cannot ask. Refusing at the
// point of entry means the operator finds out while they still have the invoice
// open.
func mergeConfirmations(existing []config.KernelConfirmation, next config.KernelConfirmation,
	periodStart, periodEnd time.Time) ([]config.KernelConfirmation, error) {
	out := make([]config.KernelConfirmation, 0, len(existing)+1)
	for _, k := range existing {
		if k.End.Before(periodStart) || k.Start.After(periodEnd) {
			continue // a previous period's; the kernel would skip it anyway
		}
		if next.Start.Before(k.End) && k.Start.Before(next.End) {
			return nil, usagef("the window %s..%s overlaps one already confirmed (%s..%s, %.2f); "+
				"confirmations must not overlap",
				next.Start.Format(time.DateOnly), next.End.Format(time.DateOnly),
				k.Start.Format(time.DateOnly), k.End.Format(time.DateOnly), k.USD)
		}
		out = append(out, k)
	}
	out = append(out, next)
	sort.Slice(out, func(i, j int) bool { return out[i].Start.Before(out[j].Start) })
	return out, nil
}

func toCostConfirmations(ks []config.KernelConfirmation) []cost.Confirmation {
	out := make([]cost.Confirmation, 0, len(ks))
	for _, k := range ks {
		out = append(out, cost.Confirmation{Start: k.Start, End: k.End, USD: k.USD, AsOf: k.AsOf})
	}
	return out
}

type confirmResult struct {
	Instance  string    `json:"instance"`
	Confirmed bool      `json:"confirmed"`
	From      time.Time `json:"from,omitempty"`
	To        time.Time `json:"to,omitempty"`
	Amount    float64   `json:"amount,omitempty"`
	Currency  string    `json:"currency,omitempty"`
	Windows   int       `json:"windows,omitempty"`
}

func (r confirmResult) Human(w io.Writer) error {
	if !r.Confirmed {
		fmt.Fprintf(w, "Nothing new to confirm for %q.\n", r.Instance)
		return nil
	}
	fmt.Fprintf(w, "Confirmed %s %.2f for %s..%s on %q (%d window(s) pushed)\n",
		r.Currency, r.Amount, r.From.Format(time.DateOnly), r.To.Format(time.DateOnly), r.Instance, r.Windows)
	fmt.Fprintf(w, "\nThe kernel will correct its estimate on its next reconcile. It never acts on\n")
	fmt.Fprintf(w, "this figure — 'expected' enforces, 'confirmed' corrects.\n")
	return nil
}
