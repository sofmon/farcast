package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
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
	// adapt lets the kernel change what applications reserve. Off by
	// default, and rendered as an argument on the workload, so the answer to
	// "is this kernel allowed to resize my applications" is visible in the
	// cluster rather than only in whoever ran this command.
	//
	// It, the interval and the cooldown are recorded and carried forward: a
	// redeploy that does not name them keeps what the kernel was deployed
	// with. Before that, every 'kernel deploy' — an image bump, a changed
	// limit — silently switched adapting off.
	adapt    optionalBool
	interval optionalDuration
	cooldown optionalDuration
}

// optionalBool is a boolean flag that knows whether it was given, so an
// absent flag can mean "as before" rather than "false". Bare --adapt still
// means true.
type optionalBool struct{ set, value bool }

func (b *optionalBool) String() string {
	if b == nil {
		return "false"
	}
	return strconv.FormatBool(b.value)
}

func (b *optionalBool) Set(s string) error {
	v, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}
	b.set, b.value = true, v
	return nil
}

func (b *optionalBool) IsBoolFlag() bool { return true }

// optionalDuration is a duration flag that knows whether it was given.
type optionalDuration struct {
	set   bool
	value time.Duration
}

func (d *optionalDuration) String() string {
	if d == nil || !d.set {
		return ""
	}
	return d.value.String()
}

func (d *optionalDuration) Set(s string) error {
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.set, d.value = true, v
	return nil
}

func (*kernelDeployCommand) Name() string { return "deploy" }
func (*kernelDeployCommand) Synopsis() string {
	return "Deploy the kernel that meters this instance and enforces its cost limit"
}

func (*kernelDeployCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast kernel deploy <instance> [--technocore-image REF] [--namespaces a,b] [--source DIR]
                              [--adapt[=false]] [--adapt-cooldown D] [--interval D] [-y]

Deploy TechnoCore into an instance.

It meters what the instance costs from the resource requests its workloads
declare — the quantity GKE Autopilot actually bills — warns at 50%, 75% and 90%
of the limit, and stops applications when the limit is reached.

It stops APPLICATIONS ONLY. The tunnel and the key holder are last-to-die and a
cost shutdown never touches them.

The kernel holds no key material and reads no billing credential. Its
permissions are: in each namespace it meters, list pods and their metrics,
list deployments and scale them, and patch them — which it does only to
resize applications with --adapt; in farcast-system, create ConfigMaps
(Kubernetes cannot pin a create to a name), maintain its ledger and usage
ConfigMaps, read the confirmations and namespaces ConfigMaps the operator
writes, and read the fatline Service to see whether the instance pays for the
load balancer.

--adapt lets it resize applications to what they use (ADR 0016); it is off by
default and shows on the workload as an argument. --adapt-cooldown sets how
long a resized workload is left alone (default 6h, 1m–720h), and --interval
how often it reconciles (default 30s, 5s–5m). All three are recorded and
carried forward: a redeploy that does not name them keeps what was deployed.
--adapt=false turns adapting off; =0 restores a duration's default. Values
below the defaults exist for walking a behaviour in minutes.`)
}

func (c *kernelDeployCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.image, "technocore-image", "", "kernel container image (default: the instance registry's system/technocore)")
	fs.StringVar(&c.namespaces, "namespaces", "", "comma-separated namespaces to meter (default: farcast-system)")
	fs.StringVar(&c.deployer.sourceDir, "source", "", "farcast checkout to build the image from (default: auto-detected)")
	fs.Var(&c.adapt, "adapt", "let the kernel resize applications to what they actually use (off by default; recorded)")
	fs.Var(&c.cooldown, "adapt-cooldown", "how long a resized application is left alone (default 6h; 0 restores it; recorded)")
	fs.Var(&c.interval, "interval", "how often the kernel reconciles (default 30s; 0 restores it; recorded)")
	c.deployer.setYesFlag(fs, "skip the cost confirmation")
}

// existingNamespaces is the set of namespaces the instance actually has.
func existingNamespaces(ctx context.Context, cl clusterApplier) (map[string]bool, error) {
	have, err := cl.Namespaces(ctx)
	if err != nil {
		return nil, fmt.Errorf("list the instance's namespaces: %w", err)
	}
	set := make(map[string]bool, len(have))
	for _, n := range have {
		set[n] = true
	}
	return set, nil
}

// partitionByExistence splits names into those the cluster has and those it
// does not, preserving order.
func partitionByExistence(present map[string]bool, names []string) (have, missing []string) {
	for _, n := range names {
		if present[n] {
			have = append(have, n)
			continue
		}
		missing = append(missing, n)
	}
	return have, missing
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

	// Settle the metered list against what the instance actually has, before
	// anything is built.
	//
	// deploy renders a RoleBinding into every metered namespace and the API
	// server rejects one for a namespace that is not there — but it rejected
	// it at the apply, which is after the kernel's image has been compiled and
	// pushed into the instance's registry. On the Phase 4.4 walk a namespace
	// that did not exist yet cost a build and a registry write before anything
	// said so. One API call settles it here instead.
	cl := c.deployer.newCluster(env.ConfigDir.InstanceKubeconfigPath(name))
	present, err := existingNamespaces(ctx, cl)
	if err != nil {
		return err
	}

	// What --namespaces names is this operator's input for this run, so a name
	// that does not exist is a mistake worth stopping for.
	requested := parseNamespaces(c.namespaces)
	if _, missing := partitionByExistence(present, requested); len(missing) > 0 {
		return fmt.Errorf("cannot meter %s: no such namespace in this instance.\n"+
			"The kernel binds a role in every namespace it meters, so each one has to exist before it "+
			"deploys.\nCreate it with 'kubectl create namespace <name>', or deploy into it with "+
			"'farcast run', which creates the namespace it is given.", strings.Join(missing, ", "))
	}

	// What is ALREADY metered is carried forward, because seeding from
	// --namespaces alone would silently drop every namespace `kernel meter`
	// had added — so a routine redeploy (an image bump, a changed limit) would
	// stop counting every application on the instance, and nothing would say
	// so. Found on the 4.2 walk, immediately after fixing the gap that made
	// the list matter at all.
	//
	// A carried namespace that has since been deleted is dropped rather than
	// refused. Refusing would mean an operator who removed an application
	// namespace without 'kernel meter --remove' could no longer deploy the
	// kernel at all — trading a defect for a worse one. Nothing runs in a
	// namespace that does not exist, so dropping it cannot under-meter
	// anything; it is said out loud so the list does not shrink silently.
	namespaces := requested
	if meta.Kernel != nil {
		kept, gone := partitionByExistence(present, meta.Kernel.Namespaces)
		for _, n := range gone {
			fprintf(env.Err, "no longer metering %q: the namespace does not exist in this instance any more.\n", n)
		}
		namespaces = unionNamespaces(namespaces, kept)
	}

	// What the kernel runs with: the flag when given, what was deployed
	// before when not. Checked here, before anything is built.
	knobs := kernelKnobs{}
	if meta.Kernel != nil {
		knobs = kernelKnobs{Adapt: meta.Kernel.Adapt, Interval: meta.Kernel.Interval, AdaptCooldown: meta.Kernel.AdaptCooldown}
	}
	if c.adapt.set {
		knobs.Adapt = c.adapt.value
	}
	if c.interval.set {
		knobs.Interval = c.interval.value
	}
	if c.cooldown.set {
		knobs.AdaptCooldown = c.cooldown.value
	}
	if knobs.Interval < 0 || knobs.AdaptCooldown < 0 {
		return usagef("--interval and --adapt-cooldown must not be negative")
	}
	if err := kernel.CheckInterval(knobs.Interval); err != nil {
		return usagef("--interval: %v", err)
	}
	if err := kernel.CheckCooldown(knobs.AdaptCooldown); err != nil {
		return usagef("--adapt-cooldown: %v", err)
	}
	if !knobs.Adapt && knobs.AdaptCooldown != 0 {
		fprintf(env.Err, "The adapt cooldown %s is recorded; it takes effect only with --adapt.\n", knobs.AdaptCooldown)
	}
	if (knobs.Interval != 0 && knobs.Interval < kernel.DefaultInterval) || (knobs.AdaptCooldown != 0 && knobs.AdaptCooldown < kernel.DefaultCooldown) {
		fprintf(env.Err, "These are validation values, below the kernel's defaults; '--interval=0 --adapt-cooldown=0' restores them.\n")
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
		Adapt:        knobs.Adapt,
		// The cooldown only means something with adapting on; recorded
		// either way, rendered only then.
		AdaptCooldown: adaptOnly(knobs),
		Interval:      knobs.Interval,
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
	var confirmations []config.KernelConfirmation
	if meta.Kernel != nil {
		// Carried, not dropped: 'kernel confirm' writes the whole set it
		// holds, so a redeploy that forgot it would have the next confirm
		// erase every figure before it from the cluster too.
		confirmations = meta.Kernel.Confirmations
	}
	meta.Kernel = &config.Kernel{
		Deployed: true, Image: img, Replicas: tcdeploy.Replicas,
		Namespaces:    namespaces,
		Limit:         meta.CostLimit.Amount,
		Currency:      meta.CostLimit.Currency,
		Period:        meta.CostLimit.Period,
		Adapt:         knobs.Adapt,
		Interval:      knobs.Interval,
		AdaptCooldown: knobs.AdaptCooldown,
		Confirmations: confirmations,
		RecordedAt:    time.Now().UTC(),
	}
	meta.UpdatedAt = time.Now().UTC()
	if err := env.ConfigDir.SaveInstanceMetadata(name, meta); err != nil {
		return fmt.Errorf("record the kernel before deploying it: %w", err)
	}

	if isInteractive(env) || env.Verbose {
		fprintf(env.Err, "Deploying the kernel to %q…\n", name)
	}
	if err := cl.Apply(ctx, manifests); err != nil {
		return fmt.Errorf("deploy the kernel: %w — 'farcast run' and 'farcast build' stay refused until a kernel deploy applies", err)
	}
	// Only now may anything spend: the record above is written before the
	// apply so a failed one can be torn down, and a gate that read it would
	// let run and build bill with no kernel there to count them.
	meta.Kernel.Applied = true
	meta.UpdatedAt = time.Now().UTC()
	if err := env.ConfigDir.SaveInstanceMetadata(name, meta); err != nil {
		return fmt.Errorf("the kernel was applied but recording it failed: %w", err)
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
		Adapt:          knobs.Adapt,
		Interval:       effective(knobs.Interval, kernel.DefaultInterval),
		AdaptCooldown:  effective(knobs.AdaptCooldown, kernel.DefaultCooldown),
	})
}

// kernelKnobs is what the kernel runs with beyond its limit and namespaces.
type kernelKnobs struct {
	Adapt         bool
	Interval      time.Duration
	AdaptCooldown time.Duration
}

func adaptOnly(k kernelKnobs) time.Duration {
	if !k.Adapt {
		return 0
	}
	return k.AdaptCooldown
}

// effective names the duration the kernel actually uses.
func effective(d, def time.Duration) string {
	if d == 0 {
		return def.String() + " (default)"
	}
	return d.String()
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
	// farcast-system always: every fetch and build Job runs there, and a
	// kernel told to meter only applications would leave those uncounted —
	// the same reason 'kernel meter' refuses to remove it.
	out := []string{tcdeploy.DefaultNamespace}
	for _, ns := range strings.Split(flagValue, ",") {
		if ns = strings.TrimSpace(ns); ns != "" && !slices.Contains(out, ns) {
			out = append(out, ns)
		}
	}
	return out
}

// requireKernel refuses to spend on an instance nothing is metering.
//
// A namespace the kernel does not meter has no expected spend (ADR 0009
// decision 4) and cannot be stopped by a cost shutdown — the kernel's grant is
// bound per metered namespace — so a workload there is outside the limit
// entirely. There is no override: the limit is mandatory (AGENTS.md), and the
// kernel that enforces it is a few dollars a month.
//
// It requires a kernel whose apply succeeded, not merely one recorded: the
// record is written before the apply, and a deploy that failed there leaves
// one behind.
func requireKernel(name string, meta *config.InstanceMetadata, what string) error {
	if meta.Kernel != nil && meta.Kernel.Deployed && meta.Kernel.Applied {
		return nil
	}
	return fmt.Errorf("instance %q has no kernel, so nothing would count %s against its cost limit; "+
		"run 'farcast kernel deploy %s' first", name, what, name)
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
	Adapt          bool            `json:"adapt"`
	Interval       string          `json:"interval"`
	AdaptCooldown  string          `json:"adapt_cooldown"`
}

func (r kernelDeployResult) Human(w io.Writer) error {
	fprintf(w, "Kernel deployed to %q (%d replica)\n", r.Instance, r.Replicas)
	fprintf(w, "  image      %s\n", r.Image)
	fprintf(w, "  meters     %s\n", strings.Join(r.Namespaces, ", "))
	fprintf(w, "  limit      %s %.2f/%s\n", r.CostLimit.Currency, r.CostLimit.Amount, r.CostLimit.Period)
	fprintf(w, "  floor      ~%s %.2f/mo fully provisioned (estimated)\n", r.CostLimit.Currency, r.Floor)
	fprintf(w, "  interval   %s\n", r.Interval)
	if r.Adapt {
		fprintf(w, "  adapting   on, cooldown %s\n", r.AdaptCooldown)
	} else {
		fprintf(w, "  adapting   off\n")
	}
	fprintf(w, "\nIt stops applications only. The tunnel and the key holder are last-to-die:\n")
	fprintf(w, "stopping them would make storage impossible to unseal while the instance kept\n")
	fprintf(w, "billing.\n")
	return nil
}
