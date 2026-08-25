package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/planck"
	_ "github.com/sofmon/farcast/planck/providers" // register cloud adapters (gke)
)

type releaseCommand struct {
	assumeYes bool
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
  -y, --yes   Skip the confirmation prompt (required when non-interactive)

With --output json the command prints one JSON result and never prompts.`)
}

func (c *releaseCommand) SetFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.assumeYes, "yes", false, "skip the confirmation prompt")
	fs.BoolVar(&c.assumeYes, "y", false, "skip the confirmation prompt")
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

	interactive := env.Printer.Mode == output.ModeHuman && isTerminal(env.In)
	ok, err := c.confirm(interactive, newPrompter(env.In, env.Err), env.Err, meta)
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

	if err := env.ConfigDir.RemoveInstance(name); err != nil {
		return fmt.Errorf("cloud resources destroyed but removing local state failed: %w", err)
	}

	return env.Printer.Print(releaseResult{
		Name:     name,
		Provider: meta.Provider,
		Cluster:  meta.Cluster,
		Registry: registry,
		Status:   "released",
	})
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
func (c *releaseCommand) confirm(interactive bool, p *prompter, errw io.Writer, meta *config.InstanceMetadata) (bool, error) {
	if c.assumeYes {
		return true, nil
	}
	if !interactive {
		return false, usagef("refusing to destroy %q without confirmation; pass --yes", meta.Name)
	}
	printReleaseSummary(errw, meta)
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
	Status   string `json:"status"`
}

func (r releaseResult) Human(w io.Writer) error {
	fprintf(w, "✓ instance %q released\n", r.Name)
	fprintf(w, "  provider:    %s\n", r.Provider)
	fprintf(w, "  cluster:     %s (deleted)\n", r.Cluster)
	if r.Registry != "" {
		fprintf(w, "  registry:    %s (deleted)\n", r.Registry)
	}
	fprintln(w, "  state:       removed")
	return nil
}
