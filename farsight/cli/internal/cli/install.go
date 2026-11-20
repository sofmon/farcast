package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/buildinfo"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/planck"
	_ "github.com/sofmon/farcast/planck/providers" // register cloud adapters (gke)
)

const (
	defaultProvider = "gke"
	defaultRegion   = "us-central1" // FarCast/GKE default (ADR 0003); per-provider later
	clusterPrefix   = "farcast-"
	costCurrency    = "USD"
	costPeriod      = "monthly"
	maxInstanceName = 32 // so clusterPrefix+name stays within GKE's 40-char limit
)

type installCommand struct {
	name        string
	provider    string
	project     string
	region      string
	credentials string
	costLimit   float64
	assumeYes   bool
}

func (*installCommand) Name() string     { return "install" }
func (*installCommand) Synopsis() string { return "Provision a new instance on a cloud provider" }

func (*installCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast install [flags]

Provision a new FarCast instance: validate cloud credentials, create a managed
Kubernetes cluster through Planck, health-check it, and store the instance's
metadata and credentials locally. Interactive by default; every prompt has a
matching flag for unattended use.

Flags:
  --name <name>          Instance name (DNS label); basis for the cluster name farcast-<name>
  --provider <id>        Cloud provider (default: gke)
  --project <id>         Cloud project (GCP project ID; required for gke)
  --region <region>      Cloud region (default: us-central1)
  --credentials <path>   Path to a service-account key JSON (required)
  --cost-limit <amount>  Monthly spend ceiling in USD (REQUIRED, > 0; no default, no "unlimited")
  -y, --yes              Skip the confirmation prompt (required when non-interactive)

With --output json the command prints one JSON result and never prompts.`)
}

func (c *installCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.name, "name", "", "instance name")
	fs.StringVar(&c.provider, "provider", "", "cloud provider")
	fs.StringVar(&c.project, "project", "", "cloud project / GCP project ID")
	fs.StringVar(&c.region, "region", "", "cloud region")
	fs.StringVar(&c.credentials, "credentials", "", "path to a service-account key JSON (required)")
	fs.Float64Var(&c.costLimit, "cost-limit", 0, "monthly spend ceiling in USD (required, > 0)")
	fs.BoolVar(&c.assumeYes, "yes", false, "skip the confirmation prompt")
	fs.BoolVar(&c.assumeYes, "y", false, "skip the confirmation prompt")
}

func (c *installCommand) Run(ctx context.Context, env *Env, args []string) error {
	if len(args) > 0 {
		return usagef("install takes no positional arguments; got %q", args[0])
	}

	interactive := env.Printer.Mode == output.ModeHuman && isTerminal(env.In)
	prompt := newPrompter(env.In, env.Err)

	if c.provider == "" {
		c.provider = defaultProviderName()
	}
	if err := c.resolveInputs(interactive, prompt); err != nil {
		return err
	}
	if err := validateInstanceName(c.name); err != nil {
		return usagef("%v", err)
	}

	region := c.region
	if region == "" {
		region = defaultRegion
	}
	clusterName := clusterPrefix + c.name

	cred, err := readCredentials(c.credentials)
	if err != nil {
		return err
	}

	// Open the provider and validate credentials before creating anything.
	p, err := planck.Open(c.provider, planck.Config{Project: c.project, Location: region, Credentials: cred})
	if err != nil {
		return err
	}
	if err := p.Validate(ctx); err != nil {
		return fmt.Errorf("validate credentials: %w", err)
	}

	// Refuse to clobber an existing instance.
	exists, err := env.ConfigDir.InstanceExists(c.name)
	if err != nil {
		return fmt.Errorf("check existing instances: %w", err)
	}
	if exists {
		return fmt.Errorf("instance %q already exists; choose another name or run 'farcast release %s' first", c.name, c.name)
	}

	// The floor check runs on EVERY install path, before the confirmation gate
	// and regardless of --yes.
	//
	// It lived inside printSummary until the 2026-09-01 runbook walk, which is
	// to say it ran only when a human was watching. Unattended installs — the
	// place a limit that cannot be met would sit unnoticed for months — never
	// saw it. Information about money is not a prompt decoration.
	warnIfBelowFloor(env.Err, config.CostLimit{Amount: c.costLimit, Currency: costCurrency, Period: costPeriod},
		floorFull(&config.InstanceMetadata{}), "a fully provisioned instance")

	// Confirm before spending money.
	if !c.assumeYes {
		if !interactive {
			return usagef("refusing to provision without confirmation; pass --yes")
		}
		c.printSummary(env.Err, region, clusterName)
		ok, perr := prompt.yesNo("Proceed with installation?")
		if perr != nil {
			return perr
		}
		if !ok {
			fprintln(env.Err, "Aborted.")
			return nil
		}
	}

	// Record intent BEFORE provisioning, so a cluster can never exist
	// un-recorded (cost-safety, ADR 0004 / install spec).
	if err := env.ConfigDir.CreateInstance(c.name); err != nil {
		return err
	}
	now := time.Now().UTC()
	meta := &config.InstanceMetadata{
		Name:      c.name,
		Provider:  c.provider,
		Project:   c.project,
		Region:    region,
		Cluster:   clusterName,
		Status:    config.InstanceProvisioning,
		CostLimit: config.CostLimit{Amount: c.costLimit, Currency: costCurrency, Period: costPeriod},
		Version:   buildinfo.Get().Version,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := env.ConfigDir.SaveInstanceCredentials(c.name, &config.InstanceCredentials{
		Provider:          c.provider,
		ServiceAccountKey: string(cred),
	}); err != nil {
		return err
	}
	if err := env.ConfigDir.SaveInstanceMetadata(c.name, meta); err != nil {
		return err
	}

	// Provision (blocks until RUNNING; minutes).
	if interactive || env.Verbose {
		fprintf(env.Err, "Provisioning %s in %s — this can take several minutes…\n", clusterName, region)
	}
	cluster, err := p.CreateCluster(ctx, planck.ClusterSpec{
		Name:     clusterName,
		Location: region,
		Labels:   instanceLabels(c.name),
	})
	if err != nil {
		meta.Status = config.InstanceError
		meta.UpdatedAt = time.Now().UTC()
		_ = env.ConfigDir.SaveInstanceMetadata(c.name, meta)
		return fmt.Errorf("provisioning failed: %w; run 'farcast release %s' to clean up", err, c.name)
	}

	// Finalize: record the endpoint, then health-check.
	meta.Region = cluster.Ref.Location
	meta.Endpoint = cluster.Endpoint
	// Recorded only on the provider's word that it read the cluster back as
	// system-only (ADR 0019). The GKE adapter fails CreateCluster otherwise, so
	// an instance that exports its applications' logs is never installed.
	if cluster.SystemLogsOnly {
		meta.CloudLogging = config.CloudLoggingSystem
	}
	meta.UpdatedAt = time.Now().UTC()

	// The instance's own image registry (ADR 0007). It is instance identity,
	// like the cluster and the CA, and it must exist before the first image
	// push — which precedes the first connect. The result lands in meta and is
	// persisted by the finalizing save below.
	c.ensureRegistry(ctx, env, p, meta)

	healthy := healthCheck(ctx, p, cluster)
	if healthy {
		meta.Status = config.InstanceRunning
	} else {
		meta.Status = config.InstanceUnreachable
	}
	meta.UpdatedAt = time.Now().UTC()
	if err := env.ConfigDir.SaveInstanceMetadata(c.name, meta); err != nil {
		return err
	}
	// A cluster the provider found under the name, which is the instance's
	// own, was not made by this call: a leftover, or another machine's install
	// of the same instance (ADR 0023 M2.7, M2.9a). Install records nothing
	// about it and goes on, and says so once.
	if !cluster.Created {
		fprintf(env.Err, msgAdoptedCluster, clusterName)
	}

	if !healthy {
		// The cluster is kept (it is billable and the failure may be transient);
		// recorded as unreachable, surfaced as an error so automation notices.
		return fmt.Errorf("instance %q provisioned but its control plane is not reachable (recorded 'unreachable' at %s)",
			c.name, env.ConfigDir.InstancePath(c.name))
	}

	return env.Printer.Print(installResult{
		Name:         meta.Name,
		Provider:     meta.Provider,
		Region:       meta.Region,
		Cluster:      meta.Cluster,
		Endpoint:     meta.Endpoint,
		Registry:     registryPrefix(meta),
		Status:       meta.Status,
		CostLimit:    costLimitResult(meta.CostLimit),
		CloudLogging: cloudLoggingResult(meta.CloudLogging),
		ConfigPath:   env.ConfigDir.InstancePath(c.name),
	})
}

// ensureRegistry creates the instance's image registry and grants its cluster
// pull access on it (ADR 0007), recording the result in meta.
//
// It reports rather than returns failure, on purpose. The cluster above is
// already created and already billable, so aborting the install here would
// strand it — the exact outcome the record-before-create ordering exists to
// prevent. An instance without a registry is still a usable instance: the next
// `farcast connect` re-ensures it. A provider that cannot host images is skipped
// in silence; it is still a perfectly good provider for a cluster.
func (c *installCommand) ensureRegistry(ctx context.Context, env *Env, p planck.Provider, meta *config.InstanceMetadata) {
	rp, ok := p.(planck.RegistryProvider)
	if !ok {
		return
	}
	reg, err := rp.EnsureRegistry(ctx, registrySpec(meta))
	if err != nil {
		fprintf(env.Err, "Warning: the instance's image registry could not be created: %v\n", err)
		fprintf(env.Err, "The instance is usable; 'farcast connect %s' will try again.\n", meta.Name)
		return
	}
	recordRegistry(meta, reg)
}

// instanceLabels are the cloud resource labels every resource an instance owns
// carries, so one instance reads as one recognisable group in a console and in
// a bill — which is what makes per-instance cost attribution possible at all.
func instanceLabels(name string) map[string]string {
	return map[string]string{"managed-by": "farcast", "farcast-instance": name}
}

// resolveInputs fills required values from flags, prompting when interactive
// and erroring (usage) when not. The cost limit is mandatory and never
// defaulted.
func (c *installCommand) resolveInputs(interactive bool, p *prompter) error {
	if c.name == "" {
		if !interactive {
			return usagef("--name is required")
		}
		v, err := p.line("Instance name")
		if err != nil {
			return err
		}
		c.name = strings.TrimSpace(v)
	}
	if c.project == "" && c.provider == defaultProvider {
		if !interactive {
			return usagef("--project is required for the %q provider", c.provider)
		}
		v, err := p.line("GCP project ID")
		if err != nil {
			return err
		}
		c.project = strings.TrimSpace(v)
	}
	if c.region == "" && interactive {
		v, err := p.lineDefault("Region", defaultRegion)
		if err != nil {
			return err
		}
		c.region = strings.TrimSpace(v)
	}
	if c.credentials == "" {
		if !interactive {
			return usagef("%s", msgCredentialsRequired)
		}
		v, err := p.line("Path to service-account key JSON")
		if err != nil {
			return err
		}
		if c.credentials = strings.TrimSpace(v); c.credentials == "" {
			return usagef("%s", msgCredentialsRequired)
		}
	}
	if c.costLimit <= 0 {
		if !interactive {
			return usagef(`--cost-limit is required and must be > 0 (no default, no "unlimited")`)
		}
		v, err := p.positiveFloat("Monthly cost limit in USD (required, > 0)")
		if err != nil {
			return err
		}
		c.costLimit = v
	}
	return nil
}

func (c *installCommand) printSummary(w io.Writer, region, clusterName string) {
	fprintln(w, "About to install a FarCast instance:")
	fprintf(w, "  name:        %s\n", c.name)
	fprintf(w, "  provider:    %s\n", c.provider)
	fprintf(w, "  project:     %s\n", c.project)
	fprintf(w, "  region:      %s\n", region)
	fprintf(w, "  cluster:     %s\n", clusterName)
	fprintf(w, "  cost limit:  %s %.2f / %s\n", costCurrency, c.costLimit, costPeriod)
	fprintln(w, "This creates billable cloud resources.")
}

// healthCheck confirms the instance is alive without assuming a public control-
// plane IP (ADR 0004): the install must have produced a DNS endpoint, and the
// management API must still report the cluster RUNNING (ClusterStatus). A
// deeper, in-cluster check arrives with TechnoCore.
func healthCheck(ctx context.Context, p planck.Provider, cluster *planck.Cluster) bool {
	if cluster.Endpoint == "" {
		return false
	}
	st, err := p.ClusterStatus(ctx, cluster.Ref)
	return err == nil && st == planck.StatusRunning
}

// msgAdoptedCluster is install's warning, on stderr, about a cluster the
// provider found under the instance's name rather than created (ADR 0023
// M2.7; reworded at M2.9a, design A37-4): the cluster's name. Install still
// succeeds.
const msgAdoptedCluster = "Warning: cluster %q already existed under this instance's name, " +
	"so this farcast did not create it and cannot tell what else wrote to it.\n"

// msgCredentialsRequired is install's refusal of a missing --credentials
// (ADR 0023 M2.5, A20-1; its text since M2.7, design A30-25): every
// cluster-writing command reads and writes the cluster as the installer's
// stored key, so an instance installed without one could never be connected
// or deployed into, only released. It names the writing commands alone:
// world, ps, costs, usage, logs and the reader's plans read as the instance's
// reader.
const msgCredentialsRequired = "--credentials is required: since ADR 0023 M2.7 the commands that write to an instance's cluster read and write it " +
	"as the service account whose key --credentials names, never as Application Default Credentials"

// msgCredentialsEmpty is install's refusal of a --credentials file that holds
// nothing: /dev/null, an empty process substitution, a key whose download
// failed. Planck reads an empty key as "use Application Default Credentials"
// (planck.Config), so such an install would create, and bill, a cluster as
// whatever this machine's ADC is, and record an instance every writing
// command then refuses.
const msgCredentialsEmpty = "--credentials names an empty file: since ADR 0023 M2.7 the commands that write to an instance's cluster read and write it " +
	"as the service account whose key --credentials names, never as Application Default Credentials"

// readCredentials loads the service-account key file --credentials names, and
// refuses, before the provider is opened or anything is recorded, every key
// the instance's writer could never open (openCluster's writerCredential): an
// empty path, as resolveInputs refuses it; a file that is empty or holds only
// white space; and one that is not a service-account key farcast uses, by the
// writer's own parse. farcast no longer installs an instance with Application
// Default Credentials. No refusal holds the file's bytes.
func readCredentials(path string) ([]byte, error) {
	if path == "" {
		return nil, usagef("%s", msgCredentialsRequired)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read credentials file: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, usagef("%s", msgCredentialsEmpty)
	}
	if _, err := kube.ParseServiceAccountJSON(data); err != nil {
		return nil, usagef("--credentials does not hold a key the instance's writer could open, so nothing was created: %v", err)
	}
	return data, nil
}

// defaultProviderName picks the provider when none is given: the sole
// registered one, else the GKE default.
func defaultProviderName() string {
	if provs := planck.Providers(); len(provs) == 1 {
		return provs[0]
	}
	return defaultProvider
}

// validateInstanceName enforces that the instance name yields a legal GKE
// cluster name (clusterPrefix + name): lowercase letters/digits/hyphens,
// starting with a letter, not ending with a hyphen, and short enough.
func validateInstanceName(name string) error {
	if name == "" {
		return errors.New("instance name is required")
	}
	if len(name) > maxInstanceName {
		return fmt.Errorf("instance name %q is too long (max %d characters)", name, maxInstanceName)
	}
	if name[0] < 'a' || name[0] > 'z' {
		return fmt.Errorf("instance name %q must start with a lowercase letter", name)
	}
	if name[len(name)-1] == '-' {
		return fmt.Errorf("instance name %q must not end with a hyphen", name)
	}
	for i := 0; i < len(name); i++ {
		ch := name[i]
		switch {
		case ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9', ch == '-':
		default:
			return fmt.Errorf("instance name %q has an invalid character %q (use lowercase letters, digits, hyphens)", name, string(ch))
		}
	}
	return nil
}

type installResult struct {
	Name      string          `json:"name"`
	Provider  string          `json:"provider"`
	Region    string          `json:"region"`
	Cluster   string          `json:"cluster"`
	Endpoint  string          `json:"endpoint"`
	Registry  string          `json:"registry,omitempty"`
	Status    string          `json:"status"`
	CostLimit costLimitResult `json:"cost_limit"`
	// CloudLogging is the provider's logging configuration as it read the
	// cluster back: "system" (configured to collect its mandatory system logs
	// and Events only — the provider's word, unwalked; ADR 0019) or
	// "unverified".
	CloudLogging string `json:"cloud_logging"`
	ConfigPath   string `json:"config_path"`
}

// cloudLoggingResult reports an instance's recorded CloudLogging, naming the
// empty value for what it is rather than leaving it blank.
func cloudLoggingResult(v string) string {
	if v == config.CloudLoggingSystem {
		return v
	}
	return "unverified"
}

type costLimitResult struct {
	Amount   float64 `json:"amount"`
	Currency string  `json:"currency"`
	Period   string  `json:"period"`
}

func (r installResult) Human(w io.Writer) error {
	fprintf(w, "✓ instance %q installed\n", r.Name)
	fprintf(w, "  provider:    %s\n", r.Provider)
	fprintf(w, "  region:      %s\n", r.Region)
	fprintf(w, "  cluster:     %s\n", r.Cluster)
	fprintf(w, "  endpoint:    %s\n", r.Endpoint)
	if r.Registry != "" {
		// Stated plainly, with no confirmation gate: image storage at this
		// scale is effectively free (ADR 0007 decision 8), and the operator
		// should still see every cloud resource their instance owns.
		fprintf(w, "  registry:    %s (instance images, %s/mo)\n", r.Registry, registryMonthlyCost)
	}
	fprintf(w, "  cost limit:  %s %.2f / %s\n", r.CostLimit.Currency, r.CostLimit.Amount, r.CostLimit.Period)
	if r.CloudLogging == config.CloudLoggingSystem {
		// Said at install because it is a property of the cluster, fixed at
		// creation (ADR 0019).
		// "Configured", and no more: the read-back is the provider's word
		// about its configuration, and only the next walk's count of the
		// entries it received shows it is honoured.
		fprintln(w, "  app logs:    kept on the cluster's nodes, configured not to be sent to the provider's logging")
		fprintln(w, "               (the provider's read-back; that it is honoured is unwalked, ADR 0019)")
		fprintln(w, "               (the provider still keeps its system logs, events, audit log and metrics)")
	} else {
		fprintln(w, "  app logs:    NOT verified as kept from the provider's logging")
	}
	fprintf(w, "  state:       %s\n", r.Status)
	fprintf(w, "  config:      %s\n", r.ConfigPath)
	// Said where the region is CHOSEN and the limit is set, which is the one
	// moment an operator can still act on it.
	writeRegionCaveat(w, r.Region)
	return nil
}
