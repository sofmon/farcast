package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/sofmon/farcast/datasphere"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/keeper"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/storage"
	"github.com/sofmon/farcast/planck"
	_ "github.com/sofmon/farcast/planck/providers" // register cloud adapters (gke)
)

type releaseCommand struct {
	assumeYes  bool
	deleteData bool

	now func() time.Time // the clock the provider-log dates run from; nil = time.Now
}

func (*releaseCommand) Name() string     { return "release" }
func (*releaseCommand) Synopsis() string { return "Destroy an instance and clean up local state" }

func (*releaseCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast release <instance> [flags]

Destroy a FarCast instance: tear down its cloud cluster through Planck and
remove its local state. Destructive and irreversible.

Provider, project, region, and credentials all come from the recorded
instance — release takes no cloud flags, only the instance name.

Flags:
  -y, --yes           Skip the confirmation prompt (required when non-interactive)
      --delete-data   Also destroy the instance's stored data

release refuses while the instance's storage bucket still holds objects.
Stored data is the one thing in FarCast that derives from nothing — a cluster
is re-provisionable and every registry image rebuilds from Git — and soft
delete is disabled on the bucket by design, so its deletion is immediate and
final. Copy it out with 'farcast storage cp' first, or pass --delete-data.

--delete-data is a scope flag, not a consent flag: --yes never implies it, so
the confirmation you click through daily cannot destroy the irreplaceable
thing. A bucket with no objects needs neither.

release waits until the cloud reports the cluster gone, up to 15 minutes.
Interrupting it, or the wait running out, once the cloud has accepted the
delete stops the waiting and not the delete: the cloud carries on, the
instance record is kept, and running release again waits for that same
delete. Stopped before the cloud confirmed a delete, it says so — the cluster
may still be running — and the record is kept just the same.

A keeper on this machine for the released instance — proven by its CA, not by
its name — has its bundle and leaf key wiped. Its ledger is kept: it is the
record of what that device did with key material. Keepers on other devices are
named; release cannot reach them, and 'farcast keeper uninstall' on each does
the same there.

release cannot remove what the cloud provider has already logged or measured
about the instance (ADR 0019). Its audit log keeps a record of every create,
update and delete on the cluster's Kubernetes API — object names, times and
callers, and the full spec of every workload — for 400 days from each write.
(Status updates, such as a Pod's readiness, go to its Data Access log, which
is off unless the project or a parent turned it on.) Its logging keeps the
cluster's system logs and events for the project's retention, 30 days by
default. Its monitoring keeps metrics about the instance's Pods — names,
states such as readiness, and resource use — for 24 months from each sample.
release names the dates and deletes nothing there: those records belong to
the project, not to the instance. An instance installed before ADR 0019 also
sent its applications' output to that logging.

With --output json the command prints one JSON result and never prompts.`)
}

func (c *releaseCommand) SetFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.assumeYes, "yes", false, "skip the confirmation prompt")
	fs.BoolVar(&c.assumeYes, "y", false, "skip the confirmation prompt")
	fs.BoolVar(&c.deleteData, "delete-data", false, "also destroy the instance's stored data")
}

func (c *releaseCommand) Run(ctx context.Context, env *Env, args []string) error {
	if len(args) == 0 {
		return usagef("release requires an instance name")
	}
	if len(args) > 1 {
		return usagef("release takes one instance name; got %d arguments", len(args))
	}
	name := args[0]

	exists, err := env.ConfigDir.InstanceExists(name)
	if err != nil {
		return fmt.Errorf("check instance %q: %w", name, err)
	}
	if !exists {
		return fmt.Errorf("no such instance %q", name)
	}
	meta, err := env.ConfigDir.LoadInstanceMetadata(name)
	if err != nil {
		return fmt.Errorf("load instance %q: %w", name, err)
	}
	creds, err := env.ConfigDir.LoadInstanceCredentials(name)
	if err != nil {
		return fmt.Errorf("load credentials for %q: %w", name, err)
	}

	// The storage gate runs BEFORE the confirmation, so an operator is never
	// asked to confirm a teardown whose scope they have not been shown.
	stored, err := c.gateOnStoredData(ctx, env, name, meta)
	if err != nil {
		return err
	}

	plan := planKeeper(env, name, meta)

	interactive := env.Printer.Mode == output.ModeHuman && isTerminal(env.In)
	ok, err := c.confirm(interactive, newPrompter(env.In, env.Err), env.Err, meta, stored, plan)
	if err != nil {
		return err
	}
	if !ok {
		fprintln(env.Err, "Aborted.")
		return nil
	}

	// Open the provider from the recorded config.
	p, err := planck.Open(meta.Provider, planck.Config{
		Project:     meta.Project,
		Location:    meta.Region,
		Credentials: []byte(creds.ServiceAccountKey),
	})
	if err != nil {
		return err
	}

	// Mark deleting so an interrupted release stays visible in local state.
	meta.Status = config.InstanceDeleting
	meta.UpdatedAt = time.Now().UTC()
	_ = env.ConfigDir.SaveInstanceMetadata(name, meta)

	// Destroy the cloud resource BEFORE local state, so a failure never strands
	// a billable cluster with no record to find it again. DeleteCluster is
	// idempotent, so a re-run after a partial failure converges.
	//
	// Said in every human session, -y included: the 2026-11-10 walk sat six
	// minutes in front of a release that printed nothing at all.
	human := env.Printer.Mode == output.ModeHuman
	if human || env.Verbose {
		fprintf(env.Err, "Destroying %s — this can take several minutes…\n", meta.Cluster)
	}
	// DeleteCluster returns once the cluster is gone, and a re-run while the
	// cloud is still deleting waits on that delete rather than asking again.
	ref := planck.ClusterRef{Name: meta.Cluster, Location: meta.Region}
	dctx, cancel := context.WithTimeout(ctx, clusterDeleteTimeout)
	defer cancel()
	stopNotice := func() {}
	if human {
		stopNotice = waitNotice(dctx, env.Err, meta.Cluster, time.Now(), releaseProgressEvery, clusterDeleteTimeout)
	}
	err = p.DeleteCluster(dctx, ref)
	// Stopped before anything else writes to env.Err: the notice runs on its
	// own goroutine, and stopNotice returns only once that goroutine has.
	stopNotice()
	if err != nil {
		switch {
		case errors.Is(err, planck.ErrDeleteInProgress):
			return fmt.Errorf("cluster %q is still being deleted: %w; the cloud continues the delete without this command, "+
				"and the instance is kept — re-run 'farcast release %s' to wait for it to finish", meta.Cluster, err, name)
		case dctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
			// Stopped before the cloud confirmed a delete: it may never have
			// been sent, and the cluster may be running — and billing — as
			// before. Saying "the cloud continues" here would be a guess.
			return fmt.Errorf("release stopped before the cloud confirmed deleting cluster %q (%w); it may still be running and billing. "+
				"The instance is kept — re-run 'farcast release %s'", meta.Cluster, err, name)
		}
		return fmt.Errorf("destroying cluster %q failed: %w; the instance is kept — re-run 'farcast release %s'",
			meta.Cluster, err, name)
	}

	// The instance's image registry goes with it (ADR 0007). Nothing sovereign
	// is lost — every image in it is derivable from Git — while keeping it would
	// leave billable storage nobody is watching, which the cost pillar does not
	// tolerate. The cluster goes first because it is the expensive resource;
	// this delete follows the same discipline, before local state is removed, so
	// a failure leaves a record to re-run against. Both deletes are idempotent,
	// so a re-run converges.
	registry, err := deleteRegistry(ctx, p, meta)
	if err != nil {
		return fmt.Errorf("cluster destroyed but destroying the image registry %q failed: %w; the instance is kept — re-run 'farcast release %s'",
			registryRefFor(meta).Name, err, name)
	}

	// The bucket goes last of the cloud resources: it is the only one whose
	// contents cannot be rebuilt, so a failure anywhere earlier leaves the data
	// intact and the record in place for a re-run.
	bucket, err := deleteBucket(ctx, env, name, meta)
	if err != nil {
		return fmt.Errorf("cluster and registry destroyed but destroying the storage bucket failed: %w; the instance is kept — re-run 'farcast release %s --delete-data'", err, name)
	}

	// After every cloud resource, before local state: a failure here leaves
	// the record a re-run proves the keeper against. Nothing billable rides
	// on it, so a failure is a warning.
	keeperDone := plan.execute(env)
	elsewhere := keepersElsewhere(meta.Keepers, plan)

	if err := env.ConfigDir.RemoveInstance(name); err != nil {
		return fmt.Errorf("cloud resources destroyed but removing local state failed: %w", err)
	}

	now := time.Now
	if c.now != nil {
		now = c.now
	}
	return env.Printer.Print(releaseResult{
		Name:        name,
		Provider:    meta.Provider,
		Cluster:     meta.Cluster,
		Registry:    registry,
		Bucket:      bucket,
		DeletedData: stored.Objects,
		Keeper:      keeperDone,
		Elsewhere:   elsewhere,
		CloudLogs:   cloudLogsAfterRelease(meta, now()),
		Status:      "released",
	})
}

// logRetention is how long a provider keeps what it logged or measured about
// a cluster.
type logRetention struct {
	audit  time.Duration // the audit log of API writes; fixed by the provider
	system time.Duration // system logs and events; the provider's default
	// metricsMonths is how long metrics about the cluster's Pods are kept, in
	// calendar months because that is how the provider states it.
	metricsMonths int
}

// providerLogRetention is per Planck provider. GKE: Admin Activity audit logs
// sit in the _Required bucket for 400 days, which a project cannot change or
// empty; the _Default bucket keeps everything else 30 days unless the project
// configured otherwise. Cloud Monitoring keeps Managed Service for Prometheus
// data — GKE's default kube state and cAdvisor/Kubelet packages ride it — and
// most GKE system metrics for 24 months, and only deleting the project
// guarantees they go sooner (ADR 0019). A variable so tests can name their
// fake.
var providerLogRetention = map[string]logRetention{
	"gke": {audit: 400 * 24 * time.Hour, system: 30 * 24 * time.Hour, metricsMonths: 24},
}

// releaseCloudLogs is what outlives the instance in the provider's logging
// and monitoring.
type releaseCloudLogs struct {
	// AuditUntil, SystemUntil and MetricsUntil are dates (YYYY-MM-DD),
	// approximate: audit entries expire 400 days after each write, the
	// system-log date assumes the project's default retention, and metric
	// points expire 24 months after each sample. Empty when the provider's
	// retention is not known to FarCast.
	AuditUntil  string `json:"audit_log_until,omitempty"`
	SystemUntil string `json:"system_logs_until,omitempty"`
	// MetricsUntil covers the metrics about the instance's Pods: their names,
	// states such as readiness, and resource use.
	MetricsUntil string `json:"metrics_until,omitempty"`
	// WorkloadLogs is true when the instance was not recorded as configured to
	// keep its applications' output from the provider's logging (installed
	// before ADR 0019). False is that configuration, as the provider read it
	// back at install — its word, unwalked on Autopilot — and not an
	// observation that no application output reached it.
	WorkloadLogs bool `json:"workload_logs"`
}

// cloudLogsAfterRelease reports, and only reports: those logs are the
// project's, keyed by names every cluster in it shares, and deleting them —
// or installing a standing exclusion — is not release's to do.
func cloudLogsAfterRelease(meta *config.InstanceMetadata, now time.Time) *releaseCloudLogs {
	r := &releaseCloudLogs{WorkloadLogs: meta.CloudLogging != config.CloudLoggingSystem}
	if ret, ok := providerLogRetention[meta.Provider]; ok {
		const day = "2006-01-02"
		r.AuditUntil = now.Add(ret.audit).UTC().Format(day)
		r.SystemUntil = now.Add(ret.system).UTC().Format(day)
		if ret.metricsMonths > 0 {
			r.MetricsUntil = now.UTC().AddDate(0, ret.metricsMonths, 0).Format(day)
		}
	}
	return r
}

// gateOnStoredData refuses a release that would destroy data, unless the
// operator has explicitly scoped the release to include it.
//
// The gate is DATA-triggered, not configuration-triggered: a bucket with no
// objects produces no gate, no flag and no extra prompt, so a test instance
// that installed, connected and released without ever writing behaves exactly
// as it did before this existed.
//
// The count comes from the provider, with no keyring and nothing decrypted.
// That is deliberate: an operator who has lost keys.yaml cannot read a byte of
// their data but can still be billed for it, and a gate built on what the
// keyring can NAME would announce an empty bucket while billable ciphertext
// sat in it.
func (c *releaseCommand) gateOnStoredData(ctx context.Context, env *Env, name string, meta *config.InstanceMetadata) (datasphere.Usage, error) {
	if meta.Storage == nil || meta.Storage.Bucket == "" {
		// Nothing was ever minted. If a keyring exists anyway, storage was used
		// and the record was lost — which is exactly what losing the record
		// costs, and saying so is more useful than pretending.
		if held, _ := env.ConfigDir.InstanceKeyringExists(name); held {
			fprintf(env.Err, "Warning: %q has a storage keyring but no recorded bucket, so its bucket cannot be found or deleted.\n"+
				"         Look for a bucket named farcast-%s-* in the cloud console.\n", name, name)
		}
		return datasphere.Usage{}, nil
	}

	session, err := storage.Open(ctx, storage.Options{Dir: env.ConfigDir, Instance: name, WithoutKeyring: true})
	if errors.Is(err, datasphere.ErrBucketNotFound) {
		// The bucket is already gone — a partial earlier release, or someone
		// deleted it in the console. There is nothing to gate on, and refusing
		// here would let a free, absent bucket permanently block the teardown of
		// the billable cluster beside it.
		fprintf(env.Err, "Note: the recorded storage bucket %s no longer exists; nothing to delete.\n", meta.Storage.Bucket)
		return datasphere.Usage{}, nil
	}
	if err != nil {
		return datasphere.Usage{}, fmt.Errorf("inspect the storage for %q: %w; re-run once it can be reached, or the bucket may be left behind", name, err)
	}
	usage, err := datasphere.BucketUsage(ctx, session.Provider, session.Bucket)
	if err != nil {
		return datasphere.Usage{}, fmt.Errorf("count the stored objects for %q: %w; re-run once it can be reached", name, err)
	}
	if usage.Objects == 0 || c.deleteData {
		return usage, nil
	}
	return usage, usagef("%q still holds %d object(s) (%s) in storage bucket %s.\n"+
		"Stored data derives from nothing and soft delete is disabled on this bucket, so deleting it is immediate and final.\n"+
		"Copy it out first with 'farcast storage cp -r %s: <dir>', or pass --delete-data to destroy it with the instance.",
		name, usage.Objects, humanBytes(usage.StoredBytes), meta.Storage.Bucket, name)
}

// deleteBucket destroys the instance's storage bucket. An instance that never
// had one has nothing to delete.
func deleteBucket(ctx context.Context, env *Env, name string, meta *config.InstanceMetadata) (string, error) {
	if meta.Storage == nil || meta.Storage.Bucket == "" {
		return "", nil
	}
	session, err := storage.Open(ctx, storage.Options{Dir: env.ConfigDir, Instance: name, WithoutKeyring: true})
	if errors.Is(err, datasphere.ErrBucketNotFound) {
		// Already gone. Teardown is idempotent by design, and a release must
		// always be safe to repeat.
		return "", nil
	}
	if err != nil {
		return "", err
	}
	ref := datasphere.BucketRef{Name: session.Bucket, Location: session.Location, Instance: name}
	if err := session.Provider.DeleteBucket(ctx, ref); err != nil {
		if !errors.Is(err, datasphere.ErrRetentionForced) {
			return "", err
		}
		// Deleted, but the cloud is still holding — and billing for — copies.
		// Saying so is the whole point of the sentinel.
		fprintf(env.Err, "Warning: %v\n", err)
	}
	return session.Bucket, nil
}

// humanBytes renders a byte count for an operator rather than a machine.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for size := n / unit; size >= unit; size /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// deleteRegistry removes the instance's image registry and returns the name of
// what it destroyed.
//
// A provider with no registry capability has nothing to delete, which is success
// rather than an error — the same reasoning that lets install skip it. Deleting
// an absent registry is likewise success (the provider contract), so this is
// safe to repeat after a partial teardown. The returned name is empty when
// nothing was recorded to name: the delete is still attempted for an instance
// whose record predates registries, but the report claims only what is known.
func deleteRegistry(ctx context.Context, p planck.Provider, meta *config.InstanceMetadata) (string, error) {
	rp, ok := p.(planck.RegistryProvider)
	if !ok {
		return "", nil
	}
	if err := rp.DeleteRegistry(ctx, registryRefFor(meta)); err != nil {
		return "", err
	}
	if meta.Registry == nil {
		return "", nil
	}
	return meta.Registry.Repository, nil
}

// confirm decides whether to proceed with destruction. With --yes it proceeds
// silently. Otherwise it requires an interactive session and asks the operator
// to retype the instance name (stronger than a y/N, because release is
// destructive); a non-interactive session without --yes is a usage error.
func (c *releaseCommand) confirm(interactive bool, p *prompter, errw io.Writer, meta *config.InstanceMetadata, stored datasphere.Usage, plan *keeperPlan) (bool, error) {
	if c.assumeYes {
		return true, nil
	}
	if !interactive {
		return false, usagef("refusing to destroy %q without confirmation; pass --yes", meta.Name)
	}
	printReleaseSummary(errw, meta)
	if stored.Objects > 0 {
		fprintf(errw, "  storage:     %s (%d objects, %s) — PERMANENTLY UNREADABLE after this\n",
			meta.Storage.Bucket, stored.Objects, humanBytes(stored.StoredBytes))
	}
	if plan != nil && plan.store != nil {
		fprintf(errw, "  keeper:      this machine's bundle and leaf key for %q — its ledger is kept\n", meta.Name)
	}
	if others := keepersElsewhere(meta.Keepers, plan); len(others) > 0 {
		fprintf(errw, "  keepers:     %d other device(s) hold this instance's bundle; release cannot reach them\n", len(others))
	}
	typed, err := p.line(fmt.Sprintf("Retype the instance name %q to confirm destruction", meta.Name))
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(typed) == meta.Name, nil
}

func printReleaseSummary(w io.Writer, meta *config.InstanceMetadata) {
	fprintln(w, "About to PERMANENTLY destroy this instance:")
	fprintf(w, "  name:      %s\n", meta.Name)
	fprintf(w, "  provider:  %s\n", meta.Provider)
	fprintf(w, "  region:    %s\n", meta.Region)
	fprintf(w, "  cluster:   %s\n", meta.Cluster)
	// Named only when the instance is recorded as owning one, so the summary
	// never promises to destroy something that was never created. Release still
	// attempts the (idempotent) delete either way.
	if meta.Registry != nil && meta.Registry.Repository != "" {
		fprintf(w, "  registry:  %s (and every image in it)\n", meta.Registry.Repository)
	}
	fprintln(w, "This deletes the cloud cluster and the instance's images, and cannot be undone.")
}

type releaseResult struct {
	Name     string `json:"name"`
	Provider string `json:"provider"`
	Cluster  string `json:"cluster"`
	Registry string `json:"registry,omitempty"`
	Bucket   string `json:"bucket,omitempty"`
	// DeletedData is how many stored objects went with the instance. It is
	// reported because it is the one number in this result that cannot be
	// undone by reinstalling.
	DeletedData int64 `json:"deleted_objects,omitempty"`
	// Keeper is what happened to a keeper on this machine for the instance.
	Keeper *releaseKeeper `json:"keeper,omitempty"`
	// Elsewhere are keeper devices still holding the instance's bundle.
	Elsewhere []string `json:"keepers_elsewhere,omitempty"`
	// CloudLogs is what the provider keeps about the instance after it is
	// gone (ADR 0019).
	CloudLogs *releaseCloudLogs `json:"cloud_logs,omitempty"`
	Status    string            `json:"status"`
}

func (r releaseResult) Human(w io.Writer) error {
	fprintf(w, "✓ instance %q released\n", r.Name)
	fprintf(w, "  provider:    %s\n", r.Provider)
	fprintf(w, "  cluster:     %s (deleted)\n", r.Cluster)
	if r.Registry != "" {
		fprintf(w, "  registry:    %s (deleted)\n", r.Registry)
	}
	if r.Bucket != "" {
		if r.DeletedData > 0 {
			fprintf(w, "  storage:     %s (deleted — %d objects are now permanently unreadable)\n", r.Bucket, r.DeletedData)
		} else {
			fprintf(w, "  storage:     %s (deleted — it held nothing)\n", r.Bucket)
		}
	}
	if k := r.Keeper; k != nil {
		switch k.Action {
		case "wiped":
			fprintf(w, "  keeper:      bundle and leaf key wiped; ledger kept at %s — 'farcast keeper status' still reads it\n", k.Ledger)
		case "failed":
			fprintf(w, "  keeper:      NOT wiped — %s\n", k.Reason)
		default:
			fprintf(w, "  keeper:      %s %s — %s\n", k.Dir, k.Action, k.Reason)
		}
	}
	if len(r.Elsewhere) > 0 {
		n := len(r.Elsewhere)
		fprintf(w, "  elsewhere:   %s %s this instance's bundle — run 'farcast keeper uninstall %s' %s\n",
			strings.Join(r.Elsewhere, ", "), noun(n, "still holds", "still hold"), r.Name, noun(n, "on it", "on each"))
	}
	if l := r.CloudLogs; l != nil {
		if l.AuditUntil != "" {
			fprintf(w, "  cloud logs:  kept by the provider; release cannot remove them — its audit log of this instance's\n"+
				"               API writes until about %s, its system logs and events until about %s (default retention)",
				l.AuditUntil, l.SystemUntil)
			if l.MetricsUntil != "" {
				fprintf(w, ",\n               its metrics about the instance's Pods (names, states, resource use) until about %s",
					l.MetricsUntil)
			}
			fprintln(w)
		} else {
			fprintln(w, "  cloud logs:  whatever the provider logged or measured about this instance is kept by it; release cannot remove it")
		}
		if l.WorkloadLogs {
			fprintln(w, "               this instance was not verified as system-only logging: its applications' output may be among them")
		}
	}
	fprintln(w, "  state:       removed")
	return nil
}

// clusterDeleteTimeout bounds how long release waits for the cluster to be
// gone. The 5.3 re-walk measured ~200 s after the delete was accepted. Expiry
// stops the wait, not the delete: the cloud continues it, and a re-run waits
// on it.
var clusterDeleteTimeout = 15 * time.Minute

// releaseProgressEvery is how often a human release says it is still waiting
// on the cluster delete: about six lines over the walk's six-minute wait.
var releaseProgressEvery = time.Minute

// waitNotice prints, every interval until stop is called or ctx ends, that
// release is still waiting for the cloud. It reports elapsed time only and
// claims nothing about the cluster's state, which it does not know.
//
// stop is synchronous: it returns once the goroutine has exited, so nothing
// the caller writes to w afterwards can race it.
func waitNotice(ctx context.Context, w io.Writer, cluster string, start time.Time, every, limit time.Duration) (stop func()) {
	quit, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(every)
		defer tick.Stop()
		for {
			select {
			case <-quit:
				return
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			// A tick that raced stop or the deadline prints nothing.
			select {
			case <-quit:
				return
			case <-ctx.Done():
				return
			default:
			}
			fprintf(w, "  still waiting for the cloud to report %s gone — %s so far, of at most %s\n",
				cluster, keeper.HumanWindow(time.Since(start).Round(time.Second)), keeper.HumanWindow(limit))
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() { close(quit) })
		<-done
	}
}

// releaseKeeper is what release did with a keeper on this machine.
type releaseKeeper struct {
	Dir    string `json:"dir"`
	Action string `json:"action"` // wiped | kept | untouched | failed
	Reason string `json:"reason,omitempty"`
	Ledger string `json:"ledger,omitempty"`
}

// keeperPlan is decided before the confirmation and carried out after the
// cloud resources are gone.
type keeperPlan struct {
	report releaseKeeper
	store  *keeper.Store // set when the material is to be wiped
	device string
}

// planKeeper decides what release does with a keeper on this machine for the
// instance — read-only, before anything is confirmed.
//
// The bundle and leaf key go with the instance, when provably its: release
// already destroys the keyring they derive from, and afterwards they have no
// lawful use — only the power to open ciphertext the cloud may still hold. A
// renewal request pending beside them goes too (keeper.Store.Wipe). The
// ledger never goes.
func planKeeper(env *Env, name string, meta *config.InstanceMetadata) *keeperPlan {
	dir := env.ConfigDir.KeeperDir(name)
	store, err := keeper.OpenStore(dir)
	if err != nil {
		// A request made here and never installed proves nothing about
		// which instance it was for — no certificate came back to compare —
		// so it is left, and said.
		if pending, perr := keeper.PendingRequest(dir); perr == nil && pending != nil {
			return &keeperPlan{report: releaseKeeper{
				Dir: dir, Action: "untouched",
				Reason: fmt.Sprintf("a pending request for an instance named %q, which nothing proves is this one; 'farcast keeper uninstall %s' discards it", name, name),
			}}
		}
		return nil // nothing enrolled here
	}
	plan := &keeperPlan{report: releaseKeeper{Dir: dir, Ledger: store.LedgerPath()}}
	if cfg, err := store.Config(); err == nil {
		plan.device = cfg.Device
	}
	mine, err := env.ConfigDir.LoadInstanceCACert(name)
	theirs, terr := store.CACert()
	switch {
	case err != nil || terr != nil:
		plan.report.Action, plan.report.Reason = "untouched", "nothing proves it belongs to this instance (no CA to compare)"
	case !bytes.Equal(mine, theirs):
		plan.report.Action, plan.report.Reason = "untouched", fmt.Sprintf("it keeps a different instance also named %q", name)
	case (meta.Storage == nil || meta.Storage.Bucket == "") && keyringHeld(env, name):
		plan.report.Action, plan.report.Reason = "kept", "a bucket this release could not find may hold data only this bundle opens"
	default:
		plan.store = store
	}
	return plan
}

func keyringHeld(env *Env, name string) bool {
	held, err := env.ConfigDir.InstanceKeyringExists(name)
	return err == nil && held
}

// execute wipes what the plan said to, and reports.
func (p *keeperPlan) execute(env *Env) *releaseKeeper {
	if p == nil {
		return nil
	}
	if p.store == nil {
		return &p.report
	}
	if err := p.store.Wipe("instance released", time.Now()); err != nil {
		fprintf(env.Err, "warning: this machine's keeper material was not wiped: %v\n", err)
		p.report.Action = "failed"
		p.report.Reason = fmt.Sprintf("%v — delete bundle.yaml and leaf.key in %s by hand, and keep ledger.jsonl", err, p.report.Dir)
		return &p.report
	}
	p.report.Action = "wiped"
	return &p.report
}

// keepersElsewhere names every enrolled device other than this machine's
// wiped keeper. A revoked one is named too: revoke does not reach the device,
// so it still holds a bundle.
func keepersElsewhere(keepers []config.Keeper, plan *keeperPlan) []string {
	var out []string
	for _, k := range keepers {
		if plan != nil && plan.store != nil && k.Device == plan.device {
			continue
		}
		name := k.Device
		if k.Revoked {
			name += " (revoked)"
		}
		out = append(out, name)
	}
	return out
}
