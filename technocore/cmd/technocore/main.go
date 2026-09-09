// Command technocore is the FarCast kernel: it watches an instance, meters
// what it costs, and enforces the cost limit the instance was installed with.
//
// It runs in-cluster as a single replica. See [ADR 0009] for why it is
// stateless apart from one ConfigMap, why it polls rather than watches, and
// why a cost shutdown stops applications and nothing else.
//
// [ADR 0009]: ../../../docs/adr/0009-technocore-kernel-and-cost-metering.md
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sofmon/farcast/technocore/cost"
	"github.com/sofmon/farcast/technocore/kernel"
	"github.com/sofmon/farcast/technocore/kube"
	"github.com/sofmon/farcast/technocore/pricing"
	"github.com/sofmon/farcast/technocore/usage"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "technocore: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 || args[0] != "serve" {
		return fmt.Errorf("usage: technocore serve --instance <name> --namespaces <a,b> --cost-limit <n>")
	}

	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	instance := fs.String("instance", "", "the instance this kernel belongs to")
	namespaces := fs.String("namespaces", kernel.DefaultNamespace, "comma-separated namespaces to meter")
	limit := fs.Float64("cost-limit", 0, "the instance's cost limit for one period")
	currency := fs.String("cost-currency", "USD", "the limit's currency")
	period := fs.String("cost-period", cost.PeriodMonthly, "the limit's period")
	interval := fs.Duration("interval", kernel.DefaultInterval, "how often to reconcile")
	checkpointEvery := fs.Duration("checkpoint-interval", 5*time.Minute, "how often to write the ledger")
	enforce := fs.Bool("enforce", true, "stop applications when the limit is reached")
	usageHours := fs.Int("usage-hours", usage.DefaultHours, "how many hours of observed usage to profile; 0 turns collection off")
	adaptResources := fs.Bool("adapt", false, "act on resize advice rather than only publishing it")
	cooldown := fs.Duration("adapt-cooldown", kernel.DefaultCooldown, "how long a workload is left alone after being resized")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *instance == "" {
		return errors.New("--instance is required")
	}
	// A kernel with no limit meters an instance and never acts, which is the
	// one configuration that looks like cost control and is not. The deploy
	// package refuses to render it; this refuses to run it, because a
	// hand-applied manifest does not pass through the deploy package.
	if *limit <= 0 {
		return fmt.Errorf("--cost-limit must be positive, got %v — a kernel with no limit enforces nothing", *limit)
	}

	var meter []string
	for _, ns := range strings.Split(*namespaces, ",") {
		if ns = strings.TrimSpace(ns); ns != "" {
			meter = append(meter, ns)
		}
	}
	if len(meter) == 0 {
		return errors.New("--namespaces named nothing to meter")
	}

	client, err := kube.InCluster()
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	start, end, err := cost.PeriodFor(now, *period)
	if err != nil {
		return err
	}
	ledger, err := cost.NewLedger(start, end)
	if err != nil {
		return err
	}

	r := &kernel.Reconciler{
		Cluster:    client,
		Namespaces: meter,
		Ledger:     ledger,
		Limit:      *limit,
		Period:     *period,
		Interval:   *interval,
		Selector:   kernel.ManagedBy,
	}
	store := kernel.NewConfigMapStore(client)
	r.Confirmations = kernel.NewConfigMapConfirmations(client)
	// Observed usage, per ADR 0014. Nothing in the cost path reads it: the
	// meter reads requests, which is what Autopilot bills, and this exists so
	// that a later resize has something better than a guess to act on.
	var profiles kernel.ProfileStore
	if *usageHours > 0 {
		r.Usage = usage.New(*usageHours)
		profiles = kernel.NewConfigMapProfiles(client)
	}
	// The one switch that lets the kernel write something to a workload that
	// is not a zero (ADR 0016). Off by default: everything TechnoCore has
	// written until now removes capacity, and the failure mode of this one is
	// an application that stops working rather than a bill that stops
	// growing. The advice is published either way, so an operator decides
	// with the instance's own numbers in front of them.
	r.Adapting = *adaptResources && *usageHours > 0
	r.Cooldown = *cooldown
	// Without this the kernel meters only the namespaces baked into its
	// arguments, and every namespace added later is invisible: the
	// applications there run, bill, and are counted nowhere. The 4.2 walk
	// found exactly that — `kernel meter` wrote the list and nothing read it.
	r.Discover = kernel.NewConfigMapNamespaces(client)

	// A checkpoint that cannot be read is a failure, not a fresh start:
	// carrying on from zero would silently reset the meter and the limit
	// would never trip.
	restored, err := r.Restore(context.Background(), store)
	if err != nil {
		return fmt.Errorf("restore the ledger: %w", err)
	}
	// The opposite policy to the ledger above, and deliberately: a usage
	// document that cannot be read is discarded and said out loud. Carrying
	// on from zero here costs a day of advisory history; doing the same with
	// the ledger would silently reset the meter.
	usageRestored, err := r.RestoreUsage(context.Background(), profiles)
	if err != nil {
		log.Warn("the stored usage profiles could not be read and were discarded; collection starts again from nothing", "err", err)
	}

	log.Info("technocore starting",
		"instance", *instance, "namespaces", meter,
		"limit", fmt.Sprintf("%s %.2f/%s", *currency, *limit, *period),
		"period", fmt.Sprintf("%s..%s", start.Format(time.RFC3339), end.Format(time.RFC3339)),
		"restored", restored, "usage_restored", usageRestored, "usage_hours", *usageHours,
		"enforce", *enforce, "adapt", r.Adapting, "adapt_cooldown", cooldown.String(),
		"prices", fmt.Sprintf("%s as of %s", pricing.Region, pricing.AsOf))

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	s := &supervisor{
		log: log, reconciler: r, store: store, profiles: profiles,
		currency: *currency, enforce: *enforce, checkpointEvery: *checkpointEvery,
	}
	err = r.Run(ctx, s.observe)
	// A clean shutdown must not lose the period's accounting.
	if saveErr := r.Save(context.Background(), store); saveErr != nil {
		log.Error("final checkpoint failed", "err", saveErr)
	}
	if saveErr := r.SaveUsage(context.Background(), profiles, time.Now().UTC()); saveErr != nil {
		log.Warn("final usage write failed", "err", saveErr)
	}
	if errors.Is(err, context.Canceled) {
		log.Info("technocore stopped")
		return nil
	}
	return err
}

// supervisor turns each report into logs, checkpoints and — when the limit is
// actually reached — a protective shutdown.
type supervisor struct {
	log             *slog.Logger
	reconciler      *kernel.Reconciler
	store           kernel.CheckpointStore
	profiles        kernel.ProfileStore
	currency        string
	enforce         bool
	checkpointEvery time.Duration

	lastLevel      cost.Level
	lastCheckpoint time.Time
	warnedProject  bool
}

func (s *supervisor) observe(rep kernel.Report, err error) {
	ctx := context.Background()
	if err != nil {
		// One failed tick is not fatal. A kernel that exited on a transient
		// API error would stop metering exactly when the cluster is unhappy.
		s.log.Error("reconcile failed", "err", err)
		return
	}

	// Reconcile rolls the period itself, before metering. This only reacts.
	if rep.Rolled {
		s.log.Info("new accounting period", "at", rep.At)
		s.lastLevel, s.warnedProject = cost.LevelOK, false
	}

	a := rep.Assessment
	if rep.ConfirmationsApplied > 0 {
		s.log.Info("took in confirmed figures from the provider",
			"applied", rep.ConfirmationsApplied, "refused_by_clamp", rep.ConfirmationsRefused,
			"confirmed_through", rep.Accrual.ConfirmedThrough.Format(time.RFC3339),
			"calibration", fmt.Sprintf("%.3f", rep.Accrual.Calibration))
	}

	s.log.Info("reconciled",
		"pods", len(rep.Workloads), "unclassified", rep.Unclassified,
		"rate_per_hour", round(rep.RateHourlyUSD),
		"expected", round(rep.Accrual.Expected), "confirmed", round(rep.Accrual.Confirmed),
		"has_confirmation", rep.Accrual.HasConfirmation,
		"total", round(a.Total), "limit", round(a.Limit), "level", a.Level.String(),
		"billed", rep.Billed.String(), "reconstructed", rep.Reconstructed)

	if rep.UsageSampled > 0 || len(rep.UsageUnavailable) > 0 {
		s.log.Info("observed usage",
			"sampled", rep.UsageSampled, "unrefreshed", rep.UsageRepeated,
			"unavailable", rep.UsageUnavailable)
	}

	for _, d := range rep.Accrual.Discrepancies {
		s.log.Warn("billing disagrees with the local model beyond the clamp; the estimate stands", "detail", d.String())
	}
	if a.Level != s.lastLevel {
		if a.Level > s.lastLevel {
			s.log.Warn("cost threshold crossed",
				"level", a.Level.String(), "spent", round(a.Total), "limit", round(a.Limit), "currency", s.currency)
		}
		s.lastLevel = a.Level
	}
	if a.ProjectedOver && !s.warnedProject {
		s.log.Warn("on course to exceed the limit before the period ends",
			"projected", round(a.Projected), "limit", round(a.Limit), "at", a.ProjectedAt.Format(time.RFC3339))
		s.warnedProject = true
	}

	if a.Level.Acts() {
		s.act(ctx, rep)
	}
	s.adapt(ctx, rep)
	s.checkpoint(ctx, rep.At)
}

// adapt works out what every application should reserve, and — only when the
// operator has switched it on — changes it.
//
// The advice is computed on every tick regardless, because it is published
// with the profiles and an operator deciding whether to switch this on needs
// to see what it would have done to their instance.
func (s *supervisor) adapt(ctx context.Context, rep kernel.Report) {
	advice := s.reconciler.Advise(rep, rep.At)
	if len(advice) == 0 {
		return
	}
	if !s.reconciler.Adapting {
		for _, a := range advice {
			if a.Act {
				s.log.Info("would resize, but adapting is off",
					"app", a.App, "namespace", a.Namespace,
					"from", fmt.Sprintf("%dm/%dMi", a.CurrentCPUMilli, a.CurrentMemMiB),
					"to", fmt.Sprintf("%dm/%dMi", a.CPUMilli, a.MemMiB),
					"monthly_delta", round(a.MonthlyDeltaUSD()))
			}
		}
		return
	}
	res := s.reconciler.Adapt(ctx, advice, rep.At)
	for _, a := range res.Applied {
		s.log.Warn("resized an application",
			"app", a.App, "namespace", a.Namespace, "deployment", a.Deployment, "container", a.Container,
			"from", fmt.Sprintf("%dm/%dMi", a.CurrentCPUMilli, a.CurrentMemMiB),
			"to", fmt.Sprintf("%dm/%dMi", a.CPUMilli, a.MemMiB),
			"monthly_delta", round(a.MonthlyDeltaUSD()), "stepped", a.Stepped)
	}
	for _, f := range res.Failed {
		s.log.Error("could not resize an application",
			"app", f.Adaptation.App, "namespace", f.Adaptation.Namespace, "err", f.Err)
	}
}

func (s *supervisor) act(ctx context.Context, rep kernel.Report) {
	if !s.enforce {
		s.log.Warn("cost limit reached but enforcement is off; nothing stopped",
			"would_stop", len(rep.Stoppable()))
		return
	}
	res, err := s.reconciler.Shutdown(ctx, rep, rep.At)
	if err != nil {
		s.log.Error("protective shutdown failed", "err", err)
		return
	}
	for _, f := range res.Failed {
		s.log.Error("could not stop a workload", "namespace", f.Target.Namespace, "name", f.Target.Name, "err", f.Err)
	}
	for _, t := range res.Stopped {
		s.log.Warn("stopped to contain cost", "namespace", t.Namespace, "name", t.Name, "per_hour", round(t.HourlyUSD))
	}
	if res.Unclassified > 0 {
		s.log.Warn("workloads carry no tier label and were left running",
			"count", res.Unclassified, "label", "farcast.sofmon.com/tier")
	}
	if res.AtFloor {
		// Decision 8: what remains is the instance's own standing cost, and
		// the levers that would reduce it destroy operator-visible capability
		// or data. The kernel names them and takes neither.
		s.log.Error("at the instance floor: every application is stopped and spending is still over",
			"still_burning_per_hour", round(rep.SystemProtected()),
			"remaining_levers", "release the load-balancer carrier, or release the instance")
	}
}

func (s *supervisor) checkpoint(ctx context.Context, now time.Time) {
	if !s.lastCheckpoint.IsZero() && now.Sub(s.lastCheckpoint) < s.checkpointEvery {
		return
	}
	if err := s.reconciler.Save(ctx, s.store); err != nil {
		// Not fatal, and deliberately loud: the kernel keeps metering in
		// memory, but a restart from here would lose whatever the last good
		// checkpoint does not cover.
		s.log.Error("checkpoint failed; a restart would lose accounting since the last good one", "err", err)
		return
	}
	s.lastCheckpoint = now
	// Written after the ledger, never instead of it. A usage document that
	// cannot be written is advisory history lost and nothing more, so it is a
	// warning — and it comes second so that a failure here can never be the
	// reason the ledger went unwritten.
	if err := s.reconciler.SaveUsage(ctx, s.profiles, now); err != nil {
		s.log.Warn("the usage profiles could not be written; metering is unaffected", "err", err)
	}
}

func round(v float64) string { return fmt.Sprintf("%.4f", v) }
