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

	// A checkpoint that cannot be read is a failure, not a fresh start:
	// carrying on from zero would silently reset the meter and the limit
	// would never trip.
	restored, err := r.Restore(context.Background(), store)
	if err != nil {
		return fmt.Errorf("restore the ledger: %w", err)
	}

	log.Info("technocore starting",
		"instance", *instance, "namespaces", meter,
		"limit", fmt.Sprintf("%s %.2f/%s", *currency, *limit, *period),
		"period", fmt.Sprintf("%s..%s", start.Format(time.RFC3339), end.Format(time.RFC3339)),
		"restored", restored, "enforce", *enforce,
		"prices", fmt.Sprintf("%s as of %s", pricing.Region, pricing.AsOf))

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	s := &supervisor{
		log: log, reconciler: r, store: store,
		currency: *currency, enforce: *enforce, checkpointEvery: *checkpointEvery,
	}
	err = r.Run(ctx, s.observe)
	// A clean shutdown must not lose the period's accounting.
	if saveErr := r.Save(context.Background(), store); saveErr != nil {
		log.Error("final checkpoint failed", "err", saveErr)
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
	s.log.Info("reconciled",
		"pods", len(rep.Workloads), "unclassified", rep.Unclassified,
		"rate_per_hour", round(rep.RateHourlyUSD),
		"expected", round(rep.Accrual.Expected), "confirmed", round(rep.Accrual.Confirmed),
		"has_confirmation", rep.Accrual.HasConfirmation,
		"total", round(a.Total), "limit", round(a.Limit), "level", a.Level.String(),
		"billed", rep.Billed.String(), "reconstructed", rep.Reconstructed)

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
	s.checkpoint(ctx, rep.At)
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
}

func round(v float64) string { return fmt.Sprintf("%.4f", v) }
