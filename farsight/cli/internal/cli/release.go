package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sofmon/farcast/datasphere"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/storage"
	"github.com/sofmon/farcast/planck"
	_ "github.com/sofmon/farcast/planck/providers" // register cloud adapters (gke)
)

type releaseCommand struct {
	assumeYes  bool
	deleteData bool
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

	interactive := env.Printer.Mode == output.ModeHuman && isTerminal(env.In)
	ok, err := c.confirm(interactive, newPrompter(env.In, env.Err), env.Err, meta, stored)
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
	if interactive || env.Verbose {
		fprintf(env.Err, "Destroying %s — this can take several minutes…\n", meta.Cluster)
	}
	ref := planck.ClusterRef{Name: meta.Cluster, Location: meta.Region}
	if err := p.DeleteCluster(ctx, ref); err != nil {
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

	if err := env.ConfigDir.RemoveInstance(name); err != nil {
		return fmt.Errorf("cloud resources destroyed but removing local state failed: %w", err)
	}

	return env.Printer.Print(releaseResult{
		Name:        name,
		Provider:    meta.Provider,
		Cluster:     meta.Cluster,
		Registry:    registry,
		Bucket:      bucket,
		DeletedData: stored.Objects,
		Status:      "released",
	})
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
func (c *releaseCommand) confirm(interactive bool, p *prompter, errw io.Writer, meta *config.InstanceMetadata, stored datasphere.Usage) (bool, error) {
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
	DeletedData int64  `json:"deleted_objects,omitempty"`
	Status      string `json:"status"`
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
	fprintln(w, "  state:       removed")
	return nil
}
