package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
	"github.com/sofmon/farcast/technocore/kernel"
)

const (
	// technocore is the kernel's component identity in the instance registry
	// (ADR 0007 decision 6: system/<component>).
	technocoreImagePath = "system/technocore"
	technocorePackage   = "./technocore/cmd/technocore"
	technocoreBinary    = "/technocore"
)

var technocoreComponent = systemComponent{
	Name: "technocore", ImagePath: technocoreImagePath,
	Package: technocorePackage, BinaryPath: technocoreBinary,
}

// newKernelCommand builds the `farcast kernel` group.
func newKernelCommand() Command {
	subs := NewRegistry()
	subs.Register(&kernelDeployCommand{})
	subs.Register(&kernelConfirmCommand{})
	subs.Register(&kernelMeterCommand{})
	return &group{
		name:     "kernel",
		synopsis: "The in-cluster kernel that enforces the cost limit (deploy, confirm, meter)",
		subs:     subs,
		usage: `
Usage: farcast kernel <deploy|confirm|meter> [flags] [arguments]

TechnoCore, the kernel: it watches what an instance runs, meters what that
costs, and enforces the cost limit the instance was installed with.

It stops applications and nothing else. The tunnel and the key holder are
classified last-to-die: stopping them would make storage impossible to unseal
while the instance carried on billing, which trades recovery for a fraction of
the bill.`,
	}
}

type kernelDeployCommand struct {
	deployer   fatlineDeployer
	image      string
	namespaces string
}

func (*kernelDeployCommand) Name() string { return "deploy" }
func (*kernelDeployCommand) Synopsis() string {
	return "Deploy the kernel that meters this instance and enforces its cost limit"
}

func (*kernelDeployCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast kernel deploy <instance> [--technocore-image REF] [--namespaces a,b] [--source DIR] [-y]

Deploy TechnoCore into an instance.

It meters what the instance costs from the resource requests its workloads
declare — the quantity GKE Autopilot actually bills — warns at 50%, 75% and 90%
of the limit, and stops applications when the limit is reached.

It stops APPLICATIONS ONLY. The tunnel and the key holder are last-to-die and a
cost shutdown never touches them.

The kernel holds no key material and reads no billing credential. Its
permissions are: list pods and deployments in the namespaces named here, scale
deployments, and maintain one ConfigMap of its own.`)
}

func (c *kernelDeployCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.image, "technocore-image", "", "kernel container image (default: the instance registry's system/technocore)")
	fs.StringVar(&c.namespaces, "namespaces", "", "comma-separated namespaces to meter (default: farcast-system)")
	fs.StringVar(&c.deployer.sourceDir, "source", "", "farcast checkout to build the image from (default: auto-detected)")
	c.deployer.setYesFlag(fs, "skip the cost confirmation")
}

func (c *kernelDeployCommand) Run(ctx context.Context, env *Env, args []string) error {
	if len(args) != 1 {
		return usagef("kernel deploy takes one instance argument")
	}
	name := args[0]
	c.deployer.component = technocoreComponent
	c.deployer.fatlineImage = c.image
	c.deployer.ensureDefaults()

	meta, err := env.ConfigDir.LoadInstanceMetadata(name)
	if err != nil {
		return fmt.Errorf("load instance %q: %w", name, err)
	}
	// The kernel needs no tunnel of its own — it talks to the API server, not
	// through FatLine. But an instance with no FatLine has no workloads worth
	// metering yet, and deploying a cost enforcer before there is anything to
	// enforce against is a standing charge for nothing.
	if !meta.FatLineDeployed {
		return fmt.Errorf("instance %q is not connected; run 'farcast connect %s' first — "+
			"there is nothing to meter yet", name, name)
	}
	if meta.CostLimit.Amount <= 0 {
		return fmt.Errorf("instance %q has no cost limit recorded; the kernel would meter it and never act", name)
	}

	// The union of what was asked for and what is already metered.
	//
	// Seeding from --namespaces alone would silently drop every namespace
	// `kernel meter` had added — so a routine redeploy (an image bump, a
	// changed limit) would stop counting every application on the instance,
	// and nothing would say so. Found on the 4.2 walk, immediately after
	// fixing the gap that made the list matter at all.
	namespaces := parseNamespaces(c.namespaces)
	if meta.Kernel != nil {
		namespaces = unionNamespaces(namespaces, meta.Kernel.Namespaces)
	}
	ok, err := c.confirmCost(env, meta, namespaces)
	if err != nil {
		return err
	}
	if !ok {
		fprintln(env.Err, "Aborted.")
		return nil
	}

	reg, err := c.deployer.ensureRegistry(ctx, env, name, meta)
	if err != nil {
		return err
	}
	img, err := c.deployer.resolveImage(ctx, env, reg)
	if err != nil {
		return err
	}

	manifests, err := tcdeploy.Render(tcdeploy.Config{
		Image:        img,
		Instance:     name,
		Meter:        namespaces,
		CostLimit:    meta.CostLimit.Amount,
		CostCurrency: meta.CostLimit.Currency,
		CostPeriod:   meta.CostLimit.Period,
	})
	if err != nil {
		return err
	}
	// Seed the list the kernel re-reads with the same namespaces its own
	// bindings cover. Without this the two views start disagreeing: the
	// workload can list them and the kernel has not been told they exist, so
	// nothing in them is counted until the first `kernel meter`.
	seed, err := kernel.RenderNamespacesConfigMap(tcdeploy.DefaultNamespace, kernel.DefaultNamespacesName, namespaces)
	if err != nil {
		return err
	}
	manifests = append(manifests, []byte("---\n")...)
	manifests = append(manifests, seed...)

	// Recorded BEFORE the apply, like every other billable thing this CLI
	// creates: a workload running in a cluster that local state does not know
	// about is one nobody will think to tear down.
	meta.Kernel = &config.Kernel{
		Deployed: true, Image: img, Replicas: tcdeploy.Replicas,
		Namespaces: namespaces,
		Limit:      meta.CostLimit.Amount,
		Currency:   meta.CostLimit.Currency,
		Period:     meta.CostLimit.Period,
		RecordedAt: time.Now().UTC(),
	}
	meta.UpdatedAt = time.Now().UTC()
	if err := env.ConfigDir.SaveInstanceMetadata(name, meta); err != nil {
		return fmt.Errorf("record the kernel before deploying it: %w", err)
	}

	cl := c.deployer.newCluster(env.ConfigDir.InstanceKubeconfigPath(name))
	if isInteractive(env) || env.Verbose {
		fprintf(env.Err, "Deploying the kernel to %q…\n", name)
	}
	if err := cl.Apply(ctx, manifests); err != nil {
		return fmt.Errorf("deploy the kernel: %w", err)
	}
	if err := cl.RolloutStatus(ctx, tcdeploy.DefaultNamespace, tcdeploy.DefaultName, fatlineRolloutTimeout); err != nil {
		// The workload is applied and recorded; a rollout that has not settled
		// yet is not a reason to make the operator think nothing happened.
		fprintf(env.Err, "Warning: the kernel did not report ready in time: %v\n", err)
	}

	return env.Printer.Print(kernelDeployResult{
		Instance: name, Image: img, Replicas: tcdeploy.Replicas,
		Namespaces: namespaces, Namespace: tcdeploy.DefaultNamespace,
		ServiceAccount: tcdeploy.DefaultName,
		CostLimit:      costLimitResult(meta.CostLimit),
		Floor:          floorFull(meta).Total,
	})
}

// unionNamespaces merges two metered sets, sorted and deduplicated. Metering
// only ever widens here: narrowing it is `kernel meter --remove`, which is an
// explicit act rather than a side effect of redeploying.
func unionNamespaces(a, b []string) []string {
	set := map[string]bool{}
	for _, ns := range append(append([]string{}, a...), b...) {
		if ns = strings.TrimSpace(ns); ns != "" {
			set[ns] = true
		}
	}
	out := make([]string, 0, len(set))
	for ns := range set {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out
}

// parseNamespaces splits the --namespaces flag, defaulting to FarCast's own.
func parseNamespaces(flagValue string) []string {
	var out []string
	for _, ns := range strings.Split(flagValue, ",") {
		if ns = strings.TrimSpace(ns); ns != "" {
			out = append(out, ns)
		}
	}
	if len(out) == 0 {
		out = []string{tcdeploy.DefaultNamespace}
	}
	return out
}

func (c *kernelDeployCommand) confirmCost(env *Env, meta *config.InstanceMetadata, namespaces []string) (bool, error) {
	// The floor is shown whether or not the operator is being prompted: a
	// limit that cannot be met is a configuration mistake, and the moment the
	// enforcer is deployed is the last moment it is cheap to notice.
	full := floorFull(meta)
	below := warnIfBelowFloor(env.Err, meta.CostLimit, full, "this instance fully provisioned")

	if c.deployer.assumeYes {
		return true, nil
	}
	if !isInteractive(env) {
		if below {
			return false, usagef("the cost limit %s %.2f/%s is below this instance's floor of ~%s %.2f/mo; "+
				"pass --yes to deploy the kernel anyway",
				meta.CostLimit.Currency, meta.CostLimit.Amount, meta.CostLimit.Period,
				meta.CostLimit.Currency, full.Total)
		}
		return false, usagef("deploying the kernel adds ~$%.0f/month of standing compute; pass --yes to confirm",
			kernelMonthlyUSD)
	}
	fprintf(env.Err, "\nDeploying the kernel to %q runs %d replica continuously (~$%.0f/month estimated) and\n"+
		"meters %s.\n",
		meta.Name, tcdeploy.Replicas, kernelMonthlyUSD, strings.Join(namespaces, ", "))
	fprintf(env.Err, "Once running it will stop applications — and only applications — if spending\n"+
		"reaches %s %.2f/%s.\n",
		meta.CostLimit.Currency, meta.CostLimit.Amount, meta.CostLimit.Period)
	return newPrompter(env.In, env.Err).yesNo("Deploy it?")
}

type kernelDeployResult struct {
	Instance       string          `json:"instance"`
	Image          string          `json:"image"`
	Replicas       int             `json:"replicas"`
	Namespaces     []string        `json:"namespaces"`
	Namespace      string          `json:"namespace,omitempty"`
	ServiceAccount string          `json:"service_account,omitempty"`
	CostLimit      costLimitResult `json:"cost_limit"`
	Floor          float64         `json:"instance_floor_monthly_usd"`
}

func (r kernelDeployResult) Human(w io.Writer) error {
	fmt.Fprintf(w, "Kernel deployed to %q (%d replica)\n", r.Instance, r.Replicas)
	fmt.Fprintf(w, "  image      %s\n", r.Image)
	fmt.Fprintf(w, "  meters     %s\n", strings.Join(r.Namespaces, ", "))
	fmt.Fprintf(w, "  limit      %s %.2f/%s\n", r.CostLimit.Currency, r.CostLimit.Amount, r.CostLimit.Period)
	fmt.Fprintf(w, "  floor      ~%s %.2f/mo fully provisioned (estimated)\n", r.CostLimit.Currency, r.Floor)
	fmt.Fprintf(w, "\nIt stops applications only. The tunnel and the key holder are last-to-die:\n")
	fmt.Fprintf(w, "stopping them would make storage impossible to unseal while the instance kept\n")
	fmt.Fprintf(w, "billing.\n")
	return nil
}
