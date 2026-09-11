package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	dsdeploy "github.com/sofmon/farcast/datasphere/deploy"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/fatline/identity"
	"github.com/sofmon/farcast/technocore/pricing"
)

// keyholderMonthlyUSD is the standing Autopilot cost of ALL of the keyholder's
// replicas at the requests the workload declares, and keyholderMonthlyUSDMax
// is the same fleet on a cluster without bursting support, where Autopilot
// raises every small Pod to a five-times-higher per-Pod floor.
//
// Both are ESTIMATES and are printed as such — a model of a published rate
// card, not a bill. They are computed from datasphere/deploy's own exported
// requests so the figure quoted here cannot drift from the manifest applied.
//
// This used to be a hand-written 4, copied from ADR 0008 decision 6 — where
// "~$4/month" is the cost of the SECOND replica, not of the pair. The prompt
// therefore understated the standing cost by half. Deriving it removes the
// class of error rather than the instance.
var (
	keyholderMonthlyUSD    = pricing.WorkloadMonthlyUSD(keyholderReplicas, dsdeploy.RequestCPUMilli, dsdeploy.RequestMemMiB)
	keyholderMonthlyUSDMax = float64(keyholderReplicas) * pricing.PodMonthlyUSDNoBursting(dsdeploy.RequestCPUMilli, dsdeploy.RequestMemMiB)
)

// keyholderReplicas is what the workload deploys. Two survives the common
// events — a single-pod OOM, one node's repair, a rollout, an eviction — and
// does not survive a full pool walk. Both halves of that are true.
const keyholderReplicas = 2

type storageDeployCommand struct {
	deployer fatlineDeployer
	image    string

	// ensureStorage mints the bucket and keyring when the instance has none.
	// A seam, because whether this command mints at all is the fix for a real
	// defect and deserves a test that does not need a cloud.
	ensureStorage func(ctx context.Context, env *Env, instance string) error
}

func (c *storageDeployCommand) ensureDefaults() {
	if c.ensureStorage == nil {
		c.ensureStorage = func(ctx context.Context, env *Env, instance string) error {
			_, err := openSession(ctx, env, instance, true)
			return err
		}
	}
}

func (*storageDeployCommand) Name() string { return "deploy" }
func (*storageDeployCommand) Synopsis() string {
	return "Deploy the in-cluster keyholder that serves storage to applications"
}

func (*storageDeployCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast storage deploy <instance> [--datasphered-image REF] [--source DIR] [-y]

Deploy the keyholder: the one in-cluster process that holds DataSphere key
material, and holds it only in memory.

It comes up SEALED and stays sealed until you run 'farcast storage unseal'.
That is not a defect — key material never rests on cloud infrastructure, so it
has to arrive from this machine, and any restart returns the replica to the
same state. Applications receive ErrStorageSealed meanwhile.

Two replicas run behind a PodDisruptionBudget, spread across hosts. That
survives a single pod's OOM, one node's repair, a rollout and an eviction; it
does not survive every node being replaced at once.

This command changes the cluster. 'farcast storage unseal' deliberately does
not, so the command you reach for during an outage cannot make one worse.`)
}

func (c *storageDeployCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.image, "datasphered-image", "", "keyholder container image (default: the instance registry's system/datasphered)")
	fs.StringVar(&c.deployer.sourceDir, "source", "", "farcast checkout to build the image from (default: auto-detected)")
	c.deployer.setYesFlag(fs, "skip the cost confirmation")
}

func (c *storageDeployCommand) Run(ctx context.Context, env *Env, args []string) error {
	if len(args) != 1 {
		return usagef("storage deploy takes one instance argument")
	}
	name := args[0]
	c.ensureDefaults()
	c.deployer.component = keyholderComponent
	c.deployer.fatlineImage = c.image
	c.deployer.ensureDefaults()

	meta, err := env.ConfigDir.LoadInstanceMetadata(name)
	if err != nil {
		return fmt.Errorf("load instance %q: %w", name, err)
	}
	if !meta.FatLineDeployed {
		// The keyholder is only reachable through the tunnel, so deploying it
		// into an instance with no tunnel would produce something nobody can
		// ever unseal.
		return fmt.Errorf("instance %q is not connected; run 'farcast connect %s' first — "+
			"the keyholder is reachable only through the FatLine tunnel", name, name)
	}
	// Ask before creating anything, not after.
	//
	// The cost gate used to sit below the bucket, so declining it — or running
	// non-interactively without --yes — exited non-zero having already created
	// a real bucket and keyring. The Phase 4.4 walk hit exactly that. Nothing
	// was stranded, because the bucket is recorded and 'farcast release'
	// destroys it, but a command that reports failure after provisioning is
	// one an operator cannot reason about, and this project's second pillar is
	// that spending is never a side effect.
	//
	// Nothing below the gate is needed to describe the cost: the figure is the
	// keyholder's standing compute, which does not depend on storage existing.
	ok, err := c.confirmCost(env, meta)
	if err != nil {
		return err
	}
	if !ok {
		fprintln(env.Err, "Aborted.")
		return nil
	}

	// Mint the bucket and the keyring here rather than sending the operator
	// away to create them.
	//
	// This used to refuse, telling the operator to "run a 'farcast storage'
	// command first so the bucket is minted" — and the only such command that
	// mints is one that writes. The Phase 4.3 walk followed that instruction
	// literally, wrote to app/, and so put an object under the MASTER key
	// space at the one moment before the app scope exists. Unseal then minted
	// that scope over the prefix, and the object became unreachable by its own
	// name. A bring-up order whose documented happy path orphans data is a
	// trap in the order, not a mistake by whoever walked it.
	//
	// Minting the keyring here is deliberate too: it is needed by the unseal
	// that follows immediately, and the key-loss warning it prints belongs at
	// the moment storage is brought up rather than buried in the output of a
	// file copy.
	if meta.Storage == nil || meta.Storage.Bucket == "" {
		if err := c.ensureStorage(ctx, env, name); err != nil {
			return fmt.Errorf("create storage for %q: %w", name, err)
		}
		if meta, err = env.ConfigDir.LoadInstanceMetadata(name); err != nil {
			return fmt.Errorf("re-read instance %q after creating its storage: %w", name, err)
		}
	}

	reg, err := c.deployer.ensureRegistry(ctx, env, name, meta)
	if err != nil {
		return err
	}
	img, err := c.deployer.resolveImage(ctx, env, reg)
	if err != nil {
		return err
	}

	mtls, err := env.ConfigDir.LoadInstanceMTLS(name)
	if err != nil {
		return fmt.Errorf("load the mTLS identity for %q: %w", name, err)
	}
	// The keyholder gets its OWN server leaf, distinct from FatLine's, so the
	// operator's session verifies that it is talking to the keyholder and not
	// to the tunnel that carried it. The CA private key never leaves here.
	certPEM, keyPEM, err := identity.IssueKeyholderServer(mtls.CACertPEM, mtls.CAKeyPEM, name)
	if err != nil {
		return fmt.Errorf("issue the keyholder's server identity: %w", err)
	}

	manifests, err := dsdeploy.Render(dsdeploy.Config{
		Image:         img,
		Replicas:      keyholderReplicas,
		Instance:      name,
		Bucket:        meta.Storage.Bucket,
		Provider:      meta.Storage.Provider,
		Project:       meta.Project,
		Location:      meta.Storage.Location,
		CACertPEM:     mtls.CACertPEM,
		ServerCertPEM: certPEM,
		ServerKeyPEM:  keyPEM,
	})
	if err != nil {
		return err
	}

	// Recorded BEFORE the apply, like every other billable thing this CLI
	// creates: a workload running in a cluster that local state does not know
	// about is one nobody will think to tear down.
	previous := meta.Keyholder
	meta.Keyholder = &config.Keyholder{
		Deployed: true, Image: img, Replicas: keyholderReplicas,
		RecordedAt: time.Now().UTC(),
	}
	if previous != nil {
		meta.Keyholder.Scope = previous.Scope
		meta.Keyholder.ScopePrefix = previous.ScopePrefix
		meta.Keyholder.Generation = previous.Generation
	}
	meta.UpdatedAt = time.Now().UTC()
	if err := env.ConfigDir.SaveInstanceMetadata(name, meta); err != nil {
		return fmt.Errorf("record the keyholder before deploying it: %w", err)
	}

	// Before the workload exists, not after: a replica that starts without
	// this grant crash-loops, and an operator reading the fix underneath a
	// deploy that has already failed is the wrong order. On stderr so it
	// survives --output json, where the human result is never rendered.
	writeBucketGrant(env.Err, meta.Project, meta.Storage.Bucket, dsdeploy.DefaultNamespace, dsdeploy.DefaultName)

	cl := c.deployer.newCluster(env.ConfigDir.InstanceKubeconfigPath(name))
	if isInteractive(env) || env.Verbose {
		fprintf(env.Err, "Deploying the keyholder to %q…\n", name)
	}
	if err := cl.Apply(ctx, manifests); err != nil {
		return fmt.Errorf("deploy the keyholder: %w", err)
	}

	// Deliberately NO rollout wait. Every replica comes up sealed and a sealed
	// replica never becomes Ready, so waiting for readiness here would block
	// until it timed out — on the happy path — and teach the operator to
	// interrupt the tool. The next step is the unseal, and it is said plainly.
	return env.Printer.Print(deployResult{
		Instance: name, Image: img, Replicas: keyholderReplicas,
		Project: meta.Project, Bucket: meta.Storage.Bucket,
		Namespace: dsdeploy.DefaultNamespace, ServiceAccount: dsdeploy.DefaultName,
	})
}

func (c *storageDeployCommand) confirmCost(env *Env, meta *config.InstanceMetadata) (bool, error) {
	if c.deployer.assumeYes {
		return true, nil
	}
	if !isInteractive(env) {
		return false, usagef("deploying the keyholder adds ~$%.0f/month of standing compute (%d replicas); pass --yes to confirm",
			keyholderMonthlyUSD, keyholderReplicas)
	}
	fprintf(env.Err, "Deploying the keyholder to %q runs %d replicas continuously (~$%.0f/month estimated, "+
		"against the cost limit %s %.0f/%s).\n",
		meta.Name, keyholderReplicas, keyholderMonthlyUSD,
		meta.CostLimit.Currency, meta.CostLimit.Amount, meta.CostLimit.Period)
	fprintf(env.Err, "That figure models %s prices as of %s from the workload's declared requests. On a cluster "+
		"without bursting support Autopilot raises small Pods to a higher floor, which puts the same fleet "+
		"nearer $%.0f/month.\n",
		pricing.Region, pricing.AsOf, keyholderMonthlyUSDMax)
	return newPrompter(env.In, env.Err).yesNo("Deploy it?")
}

type deployResult struct {
	Instance       string `json:"instance"`
	Image          string `json:"image"`
	Replicas       int    `json:"replicas"`
	Project        string `json:"project,omitempty"`
	Bucket         string `json:"bucket,omitempty"`
	Namespace      string `json:"namespace,omitempty"`
	ServiceAccount string `json:"service_account,omitempty"`
}

func (r deployResult) Human(w io.Writer) error {
	fprintf(w, "Keyholder deployed to %q (%d replicas)\n", r.Instance, r.Replicas)
	fprintf(w, "  image  %s\n", r.Image)
	fprintf(w, "\nEvery replica is SEALED and will not become ready until you unseal it.\n")
	fprintf(w, "Run: farcast storage unseal %s\n", r.Instance)

	// The keyholder admits only callers that present a leaf (ADR 0018
	// decision 1), and a leaf is issued at 'farcast run'. An application
	// deployed before this keyholder holds none and is refused the moment
	// the new one starts — as ErrStorageUnavailable, which looks like an
	// outage to whoever did not read this line.
	fprintf(w, "\nApplications deployed before this keyholder hold no storage identity and will be\n")
	fprintf(w, "refused by it. Run 'farcast run' again for each of them to issue one.\n")

	// The grant itself was printed BEFORE the deploy — see writeBucketGrant.
	// All that belongs here is the reminder that it has to be in place before
	// the unseal above will work.
	if r.Project != "" && r.Bucket != "" {
		fprintf(w, "\nThe bucket grant printed above has to be in place first. Without it the\n")
		fprintf(w, "replicas crash-loop on a 403 at start-up and the unseal fails.\n")
	}
	return nil
}

// writeBucketGrant prints the IAM binding the keyholder needs before it runs.
//
// The keyholder reads and writes the bucket with a cloud-side identity (ADR
// 0008 decision 8). FarCast does not apply it: that needs permission to change
// a bucket's IAM, which the operator's credential is not required to carry and
// which this CLI deliberately never asks for.
//
// It is printed BEFORE the workload is applied. It used to be printed after,
// as part of the result — so the replicas were already crash-looping on a 403
// by the time the operator read how to prevent it, and the instance looked
// broken. That happened twice, on the Phase 3.2 and Phase 4.4 walks, and the
// second time cost a failed unseal as well (which is why unseal no longer
// consumes a generation when every push fails).
func writeBucketGrant(w io.Writer, project, bucket, namespace, serviceAccount string) {
	if project == "" || bucket == "" {
		return
	}
	fprintf(w, "\nBefore this keyholder can start, it needs read/write access to the bucket\n")
	fprintf(w, "under its own identity. If you have not granted it for this instance yet, run:\n\n")
	fprintf(w, "  PROJNUM=$(gcloud projects describe %s --format='value(projectNumber)')\n", project)
	fprintf(w, "  PRINCIPAL=\"principal://iam.googleapis.com/projects/$PROJNUM/locations/global/workloadIdentityPools/%s.svc.id.goog/subject/ns/%s/sa/%s\"\n",
		project, namespace, serviceAccount)
	fprintf(w, "  gcloud storage buckets add-iam-policy-binding gs://%s \\\n", bucket)
	fprintf(w, "    --member \"$PRINCIPAL\" --role roles/storage.objectAdmin\n")
	fprintf(w, "  gcloud storage buckets add-iam-policy-binding gs://%s \\\n", bucket)
	fprintf(w, "    --member \"$PRINCIPAL\" --role roles/storage.legacyBucketReader\n")
	fprintf(w, "\nThe grant is on the BUCKET, not the project, and object access is\n")
	fprintf(w, "separated from bucket reads so the keyholder cannot delete its own bucket.\n\n")
}
