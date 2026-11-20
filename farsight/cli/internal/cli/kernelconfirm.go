package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
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
Usage: farcast kernel confirm <instance> --amount <n> [--from YYYY-MM-DD] [--to YYYY-MM-DD] [--plan | --confirm <digest>]

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
more conservative of the two figures, and reports the disagreement.

Each confirmation is dated the UTC day it is made. --plan prints what the
command would push, and changes nothing: the window, its amount, the windows
recorded after it, and the document it would apply, with the plan's digest.
It reads no cluster. --confirm <digest> does exactly the plan with that
digest, and refuses, having written nothing, if anything the plan binds has
changed since. A plan made on one UTC day is not the next day's: its window's
default end and its date both move, so it is made again.

The command asks nothing, so --yes is unused. It is accepted so scripts can
pass it uniformly, except beside --plan or --confirm, which are answers too.`)
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
	c.deployer.setYesFlag(fs, yesUnusedUsage)
	c.deployer.consent.register(fs)
}

// The texts of kernel confirm.
const (
	// msgNothingToConfirm is the empty window's line, with its two dates.
	msgNothingToConfirm = "Nothing to confirm: the window from %s to %s is empty."
	// msgAmountNotFinite refuses NaN and ±Inf, which no bill holds and no
	// document of the kernel's can carry (A23-40).
	msgAmountNotFinite = "--amount must be a finite number, got %v"
	// msgAmountTooLarge refuses an amount of maxAmount or more, whose cents a
	// plan could not state (S-R5-3).
	msgAmountTooLarge = "--amount must be less than 10000000000000, got %v"
	// msgWindowNotStated refuses a recorded window whose amount a plan
	// could not state: the instance, the window, and the amount.
	msgWindowNotStated = "instance %q records the confirmed window %s..%s at %v, which is not a finite amount below 10000000000000; " +
		"a plan cannot state it in cents, so correct it in the instance's metadata.yaml"
)

// maxAmount bounds every amount kernel confirm states, --amount's and each
// recorded window's. Below it an amount's cents are an integer that a
// float64 holds exactly and an int64 holds on every platform, so a plan
// states, to the cent, the amount it pushes; far above it, cents() wraps,
// and the plan would show one amount and push another.
const maxAmount = 1e13

func (c *kernelConfirmCommand) Run(ctx context.Context, env *Env, args []string) (err error) {
	// A 403 the writer met says whose it was, once (A20-9).
	var meta *config.InstanceMetadata
	defer func() { err = writerRefused(err, meta) }()
	if len(args) != 1 {
		return usagef("kernel confirm takes one instance argument")
	}
	mode, digest, err := c.deployer.consent.mode(c.deployer.assumeYes)
	if err != nil {
		return err
	}
	name := args[0]
	c.deployer.ensureDefaults()

	meta, err = env.ConfigDir.LoadInstanceMetadata(name)
	if err != nil {
		return fmt.Errorf("load instance %q: %w", name, err)
	}
	if err := recordNamed(meta, name); err != nil {
		return err
	}
	if meta.Kernel == nil || !meta.Kernel.Deployed {
		return fmt.Errorf("instance %q has no kernel; run 'farcast kernel deploy %s' first", name, name)
	}
	if !c.amountSet {
		return usagef("--amount is required (what the provider charged for the window)")
	}
	if math.IsNaN(c.amount) || math.IsInf(c.amount, 0) {
		return usagef(msgAmountNotFinite, c.amount)
	}
	if c.amount < 0 {
		return usagef("--amount must not be negative, got %v", c.amount)
	}
	if c.amount >= maxAmount {
		return usagef(msgAmountTooLarge, c.amount)
	}

	now := c.deployer.now().UTC()
	p, b, err := c.plan(ctx, env, meta, now)
	if err != nil {
		// Under --confirm too: a recomputation that refuses is its own
		// answer, given before any digest is compared (A23-19).
		return err
	}
	switch mode {
	case consentPlan:
		return printPlan(env, b, now)
	case consentConfirm:
		// The empty window is compared too, before it says anything (A23-8).
		if err := confirmPlan(b, digest); err != nil {
			return err
		}
	}
	printNotices(env.Err, b)
	if p.empty {
		// Not an error: a daily push that runs twice in one day has nothing
		// new to confirm, and failing would make a cron job noisy for doing
		// exactly the right thing.
		return env.Printer.Print(confirmResult{Instance: name, Confirmed: false})
	}

	// The writer is opened before the record changes (ADR 0023 M2.5,
	// A20-10): opening sends nothing, so an instance this machine cannot
	// write as is refused with its record as it was, and never left holding
	// a confirmation the cluster never got, which the next push would skip.
	// Under --confirm it opens only after the comparison.
	cl, err := c.deployer.newCluster(clusterRef{Dir: env.ConfigDir, Meta: meta, Identity: kube.Writer, Warn: env.Err})
	if err != nil {
		return err
	}

	// Recorded before the apply, like every other thing this CLI changes in a
	// cluster: a confirmation the cluster has and local state does not is one
	// the next push would try to add again.
	previous := meta.Kernel.Confirmations
	meta.Kernel.Confirmations = p.kept
	meta.UpdatedAt = now
	if err := env.ConfigDir.SaveInstanceMetadata(name, meta); err != nil {
		return fmt.Errorf("record the confirmation before pushing it: %w", err)
	}

	if err := cl.Apply(ctx, p.manifest); err != nil {
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
		From: p.from, To: p.to, Amount: c.amount,
		Currency: meta.CostLimit.Currency, Windows: len(p.kept),
	})
}

// preparedKernelConfirm is every decision kernel confirm executes, made once
// by its plan: interactive runs, --yes and --confirm all execute from it.
type preparedKernelConfirm struct {
	from, to time.Time
	// empty is a window with nothing in it: the command says so and writes
	// nothing.
	empty bool
	// kept is every window the record holds after the push, and manifest
	// the ConfigMap that carries them, rendered before anything is saved.
	kept     []config.KernelConfirmation
	manifest []byte
}

// plan is kernel confirm's plan (design §9.4, A23-40): it reads the record
// alone, never the cluster. Its facts are the confirmation, then the one
// ConfigMap it applies; an empty window has the confirmation and its line,
// and no write (A23-8). The day now falls on is bound, as the window's
// default end and as the confirmation's date (AsOf), so a plan does not
// outlive its UTC day. Its options are --amount as the number it parsed
// to, and --from and --to as the days they resolve to (A23-28). kernel
// confirm has no block: a window outside the period, or one that overlaps,
// is a usage error.
func (c *kernelConfirmCommand) plan(_ context.Context, _ *Env, meta *config.InstanceMetadata, now time.Time) (preparedKernelConfirm, plan.Bound, error) {
	var p preparedKernelConfirm
	periodStart, periodEnd, err := cost.PeriodFor(now, limitPeriod(meta.CostLimit))
	if err != nil {
		return p, plan.Bound{}, err
	}
	if p.from, err = c.resolveFrom(meta, periodStart); err != nil {
		return p, plan.Bound{}, err
	}
	if p.to, err = resolveDay(c.to, dayStart(now)); err != nil {
		return p, plan.Bound{}, usagef("--to: %v", err)
	}
	from, to := p.from.Format(time.DateOnly), p.to.Format(time.DateOnly)
	asOf := dayStart(now)

	b := newBound("kernel confirm", meta, "none", "")
	b.Options = []plan.Option{
		{Flag: "amount", Value: strconv.FormatFloat(c.amount, 'f', -1, 64)},
		{Flag: "from", Value: from},
		{Flag: "to", Value: to},
	}
	confirmation := plan.ConfirmationFact{
		Type: plan.TypeConfirmation, From: from, To: to, AmountCents: cents(c.amount), AsOfDay: asOf.Format(time.DateOnly),
	}

	if !p.to.After(p.from) {
		p.empty = true
		if confirmation.WindowsAfter, err = confirmationWindows(meta.Name, meta.Kernel.Confirmations); err != nil {
			return p, plan.Bound{}, err
		}
		b.Facts = []plan.Fact{confirmation, noticeFact(fmt.Sprintf(msgNothingToConfirm, from, to))}
		return p, b, nil
	}
	if p.from.Before(periodStart) || p.to.After(periodEnd) {
		return p, plan.Bound{}, usagef("the window %s..%s falls outside the current %s period (%s..%s); the kernel only accounts for the period it is in",
			from, to, limitPeriod(meta.CostLimit), periodStart.Format(time.DateOnly), periodEnd.Format(time.DateOnly))
	}

	// AsOf is the day, not the instant: it is informational, and a plan that
	// bound the instant would never be confirmed (design §9.4, the clock).
	next := config.KernelConfirmation{Start: p.from, End: p.to, USD: c.amount, AsOf: asOf}
	if p.kept, err = mergeConfirmations(meta.Kernel.Confirmations, next, periodStart, periodEnd); err != nil {
		return p, plan.Bound{}, err
	}
	if p.manifest, err = kernel.RenderConfigMap(tcdeploy.DefaultNamespace, kernel.DefaultConfirmationsName, toCostConfirmations(p.kept)); err != nil {
		return p, plan.Bound{}, err
	}
	writes, err := applyFacts(p.manifest)
	if err != nil {
		return p, plan.Bound{}, err
	}
	if confirmation.WindowsAfter, err = confirmationWindows(meta.Name, p.kept); err != nil {
		return p, plan.Bound{}, err
	}
	b.Facts = append([]plan.Fact{confirmation}, writes...)
	return p, b, nil
}

// confirmationWindows is ks, the windows instance name records, as a plan
// binds them: days, and cents. A window whose amount is not finite and
// below maxAmount is refused: its cents could not be stated (S-R5-3).
func confirmationWindows(name string, ks []config.KernelConfirmation) ([]plan.ConfirmationWindow, error) {
	out := make([]plan.ConfirmationWindow, 0, len(ks))
	for _, k := range ks {
		from, to := k.Start.UTC().Format(time.DateOnly), k.End.UTC().Format(time.DateOnly)
		if math.IsNaN(k.USD) || math.IsInf(k.USD, 0) || math.Abs(k.USD) >= maxAmount {
			return nil, fmt.Errorf(msgWindowNotStated, name, from, to, k.USD)
		}
		out = append(out, plan.ConfirmationWindow{From: from, To: to, AmountCents: cents(k.USD)})
	}
	return out, nil
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
		fprintf(w, "Nothing new to confirm for %q.\n", r.Instance)
		return nil
	}
	fprintf(w, "Confirmed %s %.2f for %s..%s on %q (%d window(s) pushed)\n",
		r.Currency, r.Amount, r.From.Format(time.DateOnly), r.To.Format(time.DateOnly), r.Instance, r.Windows)
	fprintf(w, "\nThe kernel will correct its estimate on its next reconcile. It never acts on\n")
	fprintf(w, "this figure — 'expected' enforces, 'confirmed' corrects.\n")
	return nil
}
