package cli

import (
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
  --credentials <path>   Path to a service-account key JSON; omit to use ADC
  --cost-limit <amount>  Monthly spend ceiling in USD (REQUIRED, > 0; no default, no "unlimited")
  -y, --yes              Skip the confirmation prompt (required when non-interactive)

With --output json the command prints one JSON result and never prompts.`)
}

func (c *installCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.name, "name", "", "instance name")
	fs.StringVar(&c.provider, "provider", "", "cloud provider")
	fs.StringVar(&c.project, "project", "", "cloud project / GCP project ID")
	fs.StringVar(&c.region, "region", "", "cloud region")
	fs.StringVar(&c.credentials, "credentials", "", "path to a service-account key JSON")
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
		Labels:   map[string]string{"managed-by": "farcast", "farcast-instance": c.name},
	})
	if err != nil {
		meta.Status = config.InstanceError
		meta.UpdatedAt = time.Now().UTC()
		_ = env.ConfigDir.SaveInstanceMetadata(c.name, meta)
		return fmt.Errorf("provisioning failed: %w; run 'farcast release %s' to clean up", err, c.name)
	}

	// Finalize: persist the kubeconfig + endpoint, then health-check.
	meta.Region = cluster.Ref.Location
	meta.Endpoint = cluster.Endpoint
	meta.UpdatedAt = time.Now().UTC()
	if err := env.ConfigDir.SaveInstanceKubeconfig(c.name, cluster.Kubeconfig); err != nil {
		return err
	}

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

	if !healthy {
		// The cluster is kept (it is billable and the failure may be transient);
		// recorded as unreachable, surfaced as an error so automation notices.
		return fmt.Errorf("instance %q provisioned but its control plane is not reachable (recorded 'unreachable' at %s)",
			c.name, env.ConfigDir.InstancePath(c.name))
	}

	return env.Printer.Print(installResult{
		Name:       meta.Name,
		Provider:   meta.Provider,
		Region:     meta.Region,
		Cluster:    meta.Cluster,
		Endpoint:   meta.Endpoint,
		Status:     meta.Status,
		CostLimit:  costLimitResult(meta.CostLimit),
		ConfigPath: env.ConfigDir.InstancePath(c.name),
	})
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
	if c.credentials == "" && interactive {
		v, err := p.lineDefault("Path to service-account key JSON (blank = ADC)", "")
		if err != nil {
			return err
		}
		c.credentials = strings.TrimSpace(v)
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
// plane IP (ADR 0004): the install must have produced a DNS endpoint and a
// kubeconfig, and the management API must still report the cluster RUNNING. A
// deeper, in-cluster check arrives with TechnoCore.
func healthCheck(ctx context.Context, p planck.Provider, cluster *planck.Cluster) bool {
	if cluster.Endpoint == "" || len(cluster.Kubeconfig) == 0 {
		return false
	}
	st, err := p.ClusterStatus(ctx, cluster.Ref)
	return err == nil && st == planck.StatusRunning
}

// readCredentials loads a credential file when a path is given; an empty path
// means ambient / Application Default Credentials.
func readCredentials(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read credentials file: %w", err)
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
	Name       string          `json:"name"`
	Provider   string          `json:"provider"`
	Region     string          `json:"region"`
	Cluster    string          `json:"cluster"`
	Endpoint   string          `json:"endpoint"`
	Status     string          `json:"status"`
	CostLimit  costLimitResult `json:"cost_limit"`
	ConfigPath string          `json:"config_path"`
}

type costLimitResult struct {
	Amount   float64 `json:"amount"`
	Currency string  `json:"currency"`
	Period   string  `json:"period"`
}

func (r installResult) Human(w io.Writer) error {
	_, err := fmt.Fprintf(w,
		"✓ instance %q installed\n"+
			"  provider:    %s\n  region:      %s\n  cluster:     %s\n  endpoint:    %s\n"+
			"  cost limit:  %s %.2f / %s\n  state:       %s\n  config:      %s\n",
		r.Name, r.Provider, r.Region, r.Cluster, r.Endpoint,
		r.CostLimit.Currency, r.CostLimit.Amount, r.CostLimit.Period, r.Status, r.ConfigPath)
	return err
}
