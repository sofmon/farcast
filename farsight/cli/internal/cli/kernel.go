package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/components"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	pbuild "github.com/sofmon/farcast/planck/build"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
	"github.com/sofmon/farcast/technocore/kernel"
)

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

	// newPlanReader opens what the plan reads the cluster through under
	// --plan and --confirm: the instance's reader (ADR 0023 M2.6, A23-20),
	// openReaderDefault when unset, and never the writer. An interactive or
	// --yes run reads through the writer it opened instead (design §7.3).
	newPlanReader func(clusterRef) (kernelPlanReader, error)
}

// kernelPlanReader is what kernel deploy's plan reads the cluster through
// (A23-20): the namespaces the instance has, and farcast-system's uid, which
// the plan binds as its target. The reader is it under --plan and --confirm,
// and the writer, a clusterApplier, in an interactive or --yes run.
type kernelPlanReader interface {
	Namespaces(ctx context.Context) ([]string, error)
	preflighter
}

// ensureDefaults sets the deployer's seams, and the plan's reader seam, that
// a test left unset.
func (c *kernelDeployCommand) ensureDefaults() {
	c.deployer.ensureDefaults()
	if c.newPlanReader == nil {
		c.newPlanReader = func(r clusterRef) (kernelPlanReader, error) {
			// A refusal returns a nil reader, never a nil *cluster.Client
			// inside a non-nil one.
			cl, err := openReaderDefault(r)
			if err != nil {
				return nil, err
			}
			return cl, nil
		}
	}
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
Usage: farcast kernel deploy <instance> [--technocore-image REF@sha256:… | --source DIR | --embedded]
                              [--namespaces a,b] [--adapt[=false]] [--adapt-cooldown D] [--interval D] [-y]
                              [--plan | --confirm <digest>]

Deploy TechnoCore into an instance. It also creates the builder's
ServiceAccount, so the push grant can name it by its uid before the first
build.

Its image is the one this farcast carries, pushed into the instance's own
registry when the version tag does not already hold it. --technocore-image
deploys a digest-pinned image as given; --source builds one from a farcast
checkout with this machine's Go and records it as operator-built, which later
deploys keep until --embedded or --source. A release farcast replaces an image
another farcast version deployed only with --embedded.

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
how often it reconciles (default 30s, 5s–5m), each in whole seconds. All
three are recorded and carried forward: a redeploy that does not name them
keeps what was deployed. --adapt=false turns adapting off; =0 restores a
duration's default. Values below the defaults exist for walking a behaviour
in minutes. A plan refuses a recorded duration that is not whole seconds,
which an earlier farcast could record; either flag replaces it.

It reads the namespaces the instance has and decides the image before it
asks anything: it reads the instance's recorded registry with the
installer's key, and ensures the registry, pushes and builds only once the
deploy is confirmed. On an instance that records no registry, an interactive
or --yes run ensures it first.

--plan prints what the deploy would do, and changes nothing: its cost
against the cost limit and the instance's floor, the image and where it
comes from, the kernel's settings, the registry calls, each document it
would apply, and what it would print, with the plan's digest. It reads the
cluster as the instance's reader, which 'farcast reader grant' must have
verified read-only (there is no fallback to the installer's account), and
the registry with the installer's key; it opens no writer. A namespace that
does not exist is a block: the plan says so, and its --confirm refuses it.
A limit below the floor is no block: the plan states it, and confirming the
plan consents to it, as --yes does.

--confirm <digest> does exactly the plan with that digest, asking nothing,
and refuses, having written nothing, if anything it binds has changed since.
It recomputes the plan as the reader, and opens the writer only after the
comparison, refusing if the writer reaches another cluster than the one the
plan read. Its plan is the consent to replacing an image another farcast
version deployed; --yes never is, and never implies --embedded.`)
}

// The texts of kernel deploy's gates and notices (ADR 0023 M2.6, A23-38):
// the refusals without a terminal and without --yes, which name the plan's
// route, and the lines the plan carries as notices.
const (
	// msgKernelBelowFloorYes is the limit, its period and the floor.
	msgKernelBelowFloorYes = "the cost limit %s/%s is below this instance's floor of ~%s/mo; pass --yes to deploy the kernel anyway" + consentSuffix
	// msgKernelCostYes is the kernel's monthly cost.
	msgKernelCostYes = "deploying the kernel adds ~$%s/month of standing compute; pass --yes to confirm" + consentSuffix
	// msgNoSuchNamespace is the block of a plan that would meter namespaces
	// the instance does not have, joined by ", ".
	msgNoSuchNamespace = "cannot meter %s: no such namespace in this instance.\n" +
		"The kernel binds a role in every namespace it meters, so each one has to exist before it " +
		"deploys.\nDeploy into it with 'farcast run', which creates the namespace it is given."
	msgNoLongerMetering = "no longer metering %q: the namespace does not exist in this instance any more."
	msgCooldownRecorded = "The adapt cooldown %s is recorded; it takes effect only with --adapt."
	msgValidationValues = "These are validation values, below the kernel's defaults; '--interval=0 --adapt-cooldown=0' restores them."
	// msgKernelKnobNotWhole is a plan's refusal of a recorded knob that is
	// not a whole number of seconds (wholeSecondKnobs): the instance, the
	// knob, its value, and the flag that replaces it.
	msgKernelKnobNotWhole = "instance %q's record holds the kernel's %s as %s, which is not a whole number of seconds, " +
		"and a plan states it in seconds; pass --%s in whole seconds (0 restores the default) to replace it"
)

func (c *kernelDeployCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.image, "technocore-image", "", imageFlagUsage("TechnoCore", components.TechnoCore))
	fs.StringVar(&c.namespaces, "namespaces", "", "comma-separated namespaces to meter (default: farcast-system)")
	fs.StringVar(&c.deployer.sourceDir, "source", "", "farcast checkout to build TechnoCore's image from with this machine's Go; recorded as operator-built")
	c.deployer.setEmbeddedFlag(fs)
	fs.Var(&c.adapt, "adapt", "let the kernel resize applications to what they actually use (off by default; recorded)")
	fs.Var(&c.cooldown, "adapt-cooldown", "how long a resized application is left alone (default 6h; 0 restores it; recorded)")
	fs.Var(&c.interval, "interval", "how often the kernel reconciles (default 30s; 0 restores it; recorded)")
	c.deployer.setYesFlag(fs, "skip the cost confirmation and, for --source or a source build, the build confirmation; never implies --embedded")
	c.deployer.consent.register(fs)
}

// existingNamespaces is the set of namespaces the instance actually has.
func existingNamespaces(ctx context.Context, cl interface {
	Namespaces(context.Context) ([]string, error)
}) (map[string]bool, error) {
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

func (c *kernelDeployCommand) Run(ctx context.Context, env *Env, args []string) (err error) {
	// A 403 the writer met says whose it was, once (A20-9); one a plan's
	// reader met says so already (A23-22), and writerRefused leaves it.
	var meta *config.InstanceMetadata
	defer func() { err = writerRefused(err, meta) }()
	if len(args) != 1 {
		return usagef("kernel deploy takes one instance argument")
	}
	mode, digest, err := c.deployer.consent.mode(c.deployer.assumeYes)
	if err != nil {
		return err
	}
	name := args[0]
	c.deployer.component = components.TechnoCore
	c.deployer.fatlineImage = c.image
	c.ensureDefaults()
	if err := c.deployer.checkImageFlags(); err != nil {
		return err
	}
	// Before the record is read: a farcast whose carried components it must
	// not push is refused before anything is asked or called, in every mode,
	// --plan included, before any plan is computed (A23-10).
	if err := c.deployer.precheck(); err != nil {
		return err
	}

	meta, err = env.ConfigDir.LoadInstanceMetadata(name)
	if err != nil {
		return fmt.Errorf("load instance %q: %w", name, err)
	}
	if err := recordNamed(meta, name); err != nil {
		return err
	}
	if err := refuseUnmigrated(name, meta); err != nil {
		return err
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
	// What the kernel runs with is checked from the flags and the record
	// alone, before anything is opened, read or built: a value outside the
	// kernel's bounds is a usage error (A23-18).
	knobs, err := c.knobs(meta)
	if err != nil {
		return err
	}
	if mode != consentNone {
		if err := wholeSecondKnobs(name, knobs); err != nil {
			return err
		}
	}

	// Settle the metered list against what the instance actually has, before
	// anything is built: the plan's first read.
	//
	// deploy renders a RoleBinding into every metered namespace and the API
	// server rejects one for a namespace that is not there — but it rejected
	// it at the apply, which is after the kernel's image has been compiled and
	// pushed into the instance's registry. On the Phase 4.4 walk a namespace
	// that did not exist yet cost a build and a registry write before anything
	// said so. One API call settles it instead, before anything is asked,
	// built or written.
	//
	// An interactive or --yes run reads it as the writer (ADR 0023 M2.5): the
	// first in-process call, so no cost is asked, image pushed or kernel
	// recorded for a deploy whose writer the cluster refuses. --plan and
	// --confirm read it as the instance's reader, which must be one 'reader
	// grant' has verified (A23-21): the writer is never opened for a plan,
	// and under --confirm only after the comparison (A23-23).
	ref := clusterRef{Dir: env.ConfigDir, Meta: meta, Warn: env.Err}
	var cl clusterApplier
	var rd kernelPlanReader
	if mode == consentNone {
		ref.Identity = kube.Writer
		if cl, err = c.deployer.newCluster(ref); err != nil {
			return err
		}
		defer afterWrites(env, name, cl)
		rd = cl
	} else {
		if err := requireGrantedReader(env.ConfigDir, meta, "kernel deploy", mode); err != nil {
			return err
		}
		ref.Identity = kube.Reader
		if rd, err = c.newPlanReader(ref); err != nil {
			return err
		}
	}

	// Only a run that can pass the cost gate ensures a registry the record
	// does not name before its plan (A23-24's exception): one with no
	// terminal and no --yes is refused, and writes nothing.
	ensure := mode == consentNone && (c.deployer.assumeYes || isInteractive(env))
	p, b, err := c.plan(ctx, env, meta, rd, knobs, mode, ensure)
	if err != nil {
		if mode == consentNone {
			return p.refusal(env, c.deployer.embedded, err)
		}
		return err
	}
	switch mode {
	case consentPlan:
		return printPlan(env, b, c.deployer.now())
	case consentConfirm:
		if err := confirmPlan(b, digest); err != nil {
			return err
		}
	default:
		if len(b.Blocked) > 0 {
			return refuseBlocked(b)
		}
	}
	// What the plan says, once: before anything is asked or, under
	// --confirm, right after the comparison (A23-26). An interactive or
	// --yes run refuses a version skew there, before the image's own lines
	// (A25-23); under --confirm the plan is the consent to the replacement.
	if err := p.say(env, c.deployer.embedded || mode == consentConfirm); err != nil {
		return err
	}
	if mode == consentConfirm {
		if cl, err = openConfirmed(ctx, env, meta, b, c.deployer.newCluster); err != nil {
			return err
		}
		defer afterWrites(env, name, cl)
	} else if proceed, err := c.consented(env, meta, p); err != nil || !proceed {
		return err
	}

	// After consent: the registry ensure the plan bound, then the image the
	// plan decided, pushed or built and never looked up again (A23-34).
	reg, err := c.deployer.realizeRegistry(ctx, env, name, meta, p.reg, mode)
	if err != nil {
		return err
	}
	resolved, err := c.deployer.realizeAndNote(ctx, env, reg, p.image)
	if err != nil {
		return err
	}
	img := resolved.Ref
	manifests, err := kernelManifests(p.config(meta, img), p.reader)
	if err != nil {
		return err
	}

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
		Namespaces:    p.namespaces,
		Limit:         meta.CostLimit.Amount,
		Currency:      meta.CostLimit.Currency,
		Period:        meta.CostLimit.Period,
		Adapt:         p.knobs.Adapt,
		Interval:      p.knobs.Interval,
		AdaptCooldown: p.knobs.AdaptCooldown,
		Confirmations: confirmations,
		RecordedAt:    time.Now().UTC(),
	}
	recordSystemImage(meta, components.TechnoCore.Name, resolved.Record)
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
		fprintf(env.Err, "Warning: the kernel did not report ready in time: %s\n", terminalText(err.Error()))
	}

	return env.Printer.Print(kernelDeployResult{
		Instance: name, Image: img, Replicas: tcdeploy.Replicas,
		Namespaces: p.namespaces, Namespace: tcdeploy.DefaultNamespace,
		ServiceAccount: tcdeploy.DefaultName,
		CostLimit:      costLimitResult(meta.CostLimit),
		Floor:          floorFull(meta).Total,
		Adapt:          p.knobs.Adapt,
		Interval:       effective(p.knobs.Interval, kernel.DefaultInterval),
		AdaptCooldown:  effective(p.knobs.AdaptCooldown, kernel.DefaultCooldown),
		Reader:         p.reader,
		ReaderBindings: readerBindingsFor(p.reader, p.namespaces),
	})
}

// knobs is what the kernel runs with beyond its limit and namespaces: each
// flag when given, what was deployed before when not. A value outside the
// kernel's bounds is a usage error.
func (c *kernelDeployCommand) knobs(meta *config.InstanceMetadata) (kernelKnobs, error) {
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
		return kernelKnobs{}, usagef("--interval and --adapt-cooldown must not be negative")
	}
	if err := kernel.CheckInterval(knobs.Interval); err != nil {
		return kernelKnobs{}, usagef("--interval: %v", err)
	}
	if err := kernel.CheckCooldown(knobs.AdaptCooldown); err != nil {
		return kernelKnobs{}, usagef("--adapt-cooldown: %v", err)
	}
	// Whole seconds, as the plan states them (kernel_settings): a flag that
	// is not is refused in every mode (ADR 0023 M2.6c).
	if c.interval.set && c.interval.value%time.Second != 0 {
		return kernelKnobs{}, usagef("--interval: %s is not a whole number of seconds", c.interval.value)
	}
	if c.cooldown.set && c.cooldown.value%time.Second != 0 {
		return kernelKnobs{}, usagef("--adapt-cooldown: %s is not a whole number of seconds", c.cooldown.value)
	}
	return knobs, nil
}

// wholeSecondKnobs is a plan's refusal of knobs it cannot state as they
// are (ADR 0023 M2.6c): the kernel_settings fact binds the interval and the
// cooldown in seconds, so one that is not a whole number of them — only the
// record can hold one now, as kernel deploy recorded what it was given
// before — would be shown other than it is applied. An interactive or --yes
// run, which shows no fact, deploys it as recorded.
func wholeSecondKnobs(name string, k kernelKnobs) error {
	for _, knob := range []struct {
		what, flag string
		d          time.Duration
	}{{"interval", "interval", k.Interval}, {"adapt cooldown", "adapt-cooldown", k.AdaptCooldown}} {
		if knob.d%time.Second != 0 {
			return fmt.Errorf(msgKernelKnobNotWhole, name, knob.what, knob.d, knob.flag)
		}
	}
	return nil
}

// preparedKernelDeploy is every decision kernel deploy executes, made once
// by its plan (ADR 0023 M2.6, A23-38): interactive runs, --yes and --confirm
// all execute from it.
type preparedKernelDeploy struct {
	// namespaces is what the kernel meters: the requested ones, and the
	// recorded ones the instance still has.
	namespaces []string
	knobs      kernelKnobs
	// reader is the reader bound beside the kernel in every metered
	// namespace, or "", and readerWarning the line saying why none is when
	// the record cannot be rendered from (meteredReaderNote).
	reader, readerWarning string
	// notices are the kernel's own lines, in today's words: a metered
	// namespace dropped, and the knobs.
	notices []string
	// reg is the registry the plan read; image is TechnoCore's image as it
	// decided it.
	reg   *registryAccess
	image imageDecision
	// cost is the plan's cost fact, which the question is asked from.
	cost plan.CostFact
}

// config is the kernel's workload, rendered over img.
func (p preparedKernelDeploy) config(meta *config.InstanceMetadata, img string) tcdeploy.Config {
	return tcdeploy.Config{
		Image:        img,
		Instance:     meta.Name,
		Meter:        p.namespaces,
		CostLimit:    meta.CostLimit.Amount,
		CostCurrency: meta.CostLimit.Currency,
		CostPeriod:   meta.CostLimit.Period,
		Adapt:        p.knobs.Adapt,
		// The cooldown only means something with adapting on; recorded
		// either way, rendered only then.
		AdaptCooldown: adaptOnly(p.knobs),
		Interval:      p.knobs.Interval,
	}
}

// plan is kernel deploy's plan (design §9.4, A23-38). It reads the cluster
// through rd: the instance's namespaces, then farcast-system's uid, which it
// binds as its target. A requested namespace the instance does not have
// blocks it, and nothing more is read, Google included (A23-18). Otherwise
// it reads the registry the record names, with the installer's key
// (planRegistry, A23-24), and decides TechnoCore's image (decideImage). Its
// facts are the cost, with whether the limit is below the instance's floor
// (a fact, never a block); the image; the kernel's settings; the registry's
// cloud facts; each document of the stream it would apply, rendered over the
// image it names; and its notices.
//
// Under --plan and --confirm, rd is the reader, and its errors are the
// reader's (planRead). Outside them rd is the writer, and, with ensure (an
// interactive or --yes run, decided by the caller), a record that names no
// registry is first given one (A23-24's exception), after the block, so a
// namespace that does not exist is still refused before any Google write.
// It reads no terminal, and, but for that ensure, writes nothing.
//
// On an error the prepared decisions hold what was decided before it, so an
// interactive or --yes run says what it always said first (refusal).
func (c *kernelDeployCommand) plan(ctx context.Context, env *Env, meta *config.InstanceMetadata, rd kernelPlanReader,
	knobs kernelKnobs, m consentMode, ensure bool) (preparedKernelDeploy, plan.Bound, error) {
	name := meta.Name
	p := preparedKernelDeploy{knobs: knobs}
	present, err := existingNamespaces(ctx, rd)
	if err != nil {
		return p, plan.Bound{}, planRead(m, err, name)
	}
	uid, err := rd.NamespaceUID(ctx, tcdeploy.DefaultNamespace)
	if err != nil {
		return p, plan.Bound{}, planRead(m, fmt.Errorf("read the uid of the instance's %s namespace: %w", tcdeploy.DefaultNamespace, err), name)
	}
	b := newBound("kernel deploy", meta, "reader", uid)
	b.Options = c.options()

	// What --namespaces names is this operator's input for this run, so a
	// name that does not exist is a mistake worth stopping for.
	requested := parseNamespaces(c.namespaces)
	if _, missing := partitionByExistence(present, requested); len(missing) > 0 {
		b.Blocked = []plan.Block{blockOf(fmt.Errorf(msgNoSuchNamespace, strings.Join(missing, ", ")))}
		return p, b, nil
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
	p.namespaces = requested
	if meta.Kernel != nil {
		kept, gone := partitionByExistence(present, meta.Kernel.Namespaces)
		for _, n := range gone {
			p.notices = append(p.notices, fmt.Sprintf(msgNoLongerMetering, n))
		}
		p.namespaces = unionNamespaces(requested, kept)
	}
	if !knobs.Adapt && knobs.AdaptCooldown != 0 {
		p.notices = append(p.notices, fmt.Sprintf(msgCooldownRecorded, knobs.AdaptCooldown))
	}
	if (knobs.Interval != 0 && knobs.Interval < kernel.DefaultInterval) || (knobs.AdaptCooldown != 0 && knobs.AdaptCooldown < kernel.DefaultCooldown) {
		p.notices = append(p.notices, msgValidationValues)
	}

	if p.reg, err = c.deployer.deployRegistry(ctx, env, meta, ensure); err != nil {
		return p, plan.Bound{}, err
	}
	if p.image, err = c.deployer.decideImage(ctx, env, p.reg, meta); err != nil {
		return p, plan.Bound{}, err
	}

	// The reader is bound in every metered namespace too, when 'reader grant'
	// recorded that scope (design §7.2).
	p.reader, p.readerWarning = meteredReaderNote(env, name, meta)
	manifests, err := kernelManifests(p.config(meta, p.image.planTarget()), p.reader)
	if err != nil {
		return p, plan.Bound{}, err
	}
	writes, err := applyFacts(manifests)
	if err != nil {
		return p, plan.Bound{}, err
	}
	p.cost = kernelCost(meta)

	facts := []plan.Fact{p.cost, p.image.imageFact(meta), plan.KernelSettingsFact{
		Type: plan.TypeKernelSettings, Adapt: knobs.Adapt,
		AdaptCooldownS: int64(knobs.AdaptCooldown / time.Second), IntervalS: int64(knobs.Interval / time.Second),
		Namespaces: slices.Clone(p.namespaces), Reader: p.reader, ReaderBindingsCreated: readerBindingsFor(p.reader, p.namespaces),
	}}
	facts = append(facts, registryFacts(meta, p.image)...)
	facts = append(facts, writes...)
	for _, line := range p.notices {
		facts = append(facts, noticeFact(line))
	}
	for _, line := range p.image.said() {
		facts = append(facts, noticeFact(line))
	}
	if p.readerWarning != "" {
		facts = append(facts, noticeFact(p.readerWarning))
	}
	b.Facts = append(facts, sourceNotices(p.image)...)
	return p, b, nil
}

// options are kernel deploy's behaviour flags as its plan binds them
// (A23-28): the image flags, --namespaces as given, and --adapt,
// --adapt-cooldown and --interval as given, or "" when not, since their
// effective values are the kernel_settings fact's.
func (c *kernelDeployCommand) options() []plan.Option {
	adapt := ""
	if c.adapt.set {
		adapt = c.adapt.String()
	}
	return sortedOptions(append(c.deployer.imageOptions(),
		plan.Option{Flag: "adapt", Value: adapt},
		plan.Option{Flag: "adapt-cooldown", Value: c.cooldown.String()},
		plan.Option{Flag: "interval", Value: c.interval.String()},
		plan.Option{Flag: "namespaces", Value: c.namespaces}))
}

// say prints, outside a plan, what the plan says (A23-26): the kernel's own
// lines, then the image's, then the reader's warning, each once and through
// terminalText. A version-skew refusal the image stands for (embedded is
// --embedded, or true under --confirm) ends it before the image's lines
// (imageDecision.say, A25-23), and is returned.
func (p preparedKernelDeploy) say(env *Env, embedded bool) error {
	for _, line := range p.notices {
		fprintln(env.Err, terminalText(line))
	}
	if err := p.image.say(env, embedded); err != nil {
		return err
	}
	if p.readerWarning != "" {
		fprintln(env.Err, terminalText(p.readerWarning))
	}
	return nil
}

// refusal is how an interactive or --yes run refuses a plan it could not
// make: what the plan said up to the error, or a version skew it stands for
// (say), then the error.
func (p preparedKernelDeploy) refusal(env *Env, embedded bool, err error) error {
	if skew := p.say(env, embedded); skew != nil {
		return skew
	}
	return err
}

// consented is an interactive or --yes run's consent to its plan (A23-38):
// the cost, asked from the plan's cost fact, then the build question when
// the image is built from source. A version skew was refused before either
// (say). A declined cost is no error, as it never was; a declined build is.
func (c *kernelDeployCommand) consented(env *Env, meta *config.InstanceMetadata, p preparedKernelDeploy) (bool, error) {
	ok, err := c.confirmCost(env, meta, p.cost, p.namespaces)
	if err != nil {
		return false, err
	}
	if !ok {
		fprintln(env.Err, "Aborted.")
		return false, nil
	}
	return true, c.deployer.buildConsent(env, p.image)
}

// kernelManifests is the one stream 'kernel deploy' applies: TechnoCore's
// workload, then the seed of the namespace list the kernel re-reads. The
// builder's ServiceAccount (pbuild.RenderServiceAccount, the document every
// build applies first) is the stream's second document, right after the
// Namespace TechnoCore's workload begins with and before any TechnoCore
// object (ADR 0023 M2.8, design §33 A33-20): the push grant names it by its
// uid, which exists only once the account does, and with no account before
// the first build that build would fail at its push, billed. The kernel
// does not need it, so an apply of it that fails stops the stream before
// TechnoCore's workload, its RoleBindings and the seed change. The seed
// comes last, after the RoleBindings the workload holds, for meterManifest's
// reason: a stream stopped between them must not leave the kernel told to
// meter a namespace it cannot read (TestTheMeteredListIsAppliedAfterItsBindings).
//
// The seed holds the same namespaces the workload's own bindings cover, for
// the non-empty cfg.Meter kernel deploy always passes (parseNamespaces starts
// it with farcast-system); an empty one would seed an empty list while the
// workload still bound farcast-system. Without it the two views start disagreeing: the workload can list them and
// the kernel has not been told they exist, so nothing in them is counted until
// the first 'kernel meter'.
//
// With a readerEmail, a binding of the reader's rule set in every metered
// namespace (renderReaderBinding) follows the workload, and the seed still
// comes after them: world reads the list as the reader, so a stream stopped
// between them must not name a namespace the reader cannot read either. An
// empty readerEmail, an instance whose reader was never granted the metered
// scope, adds none.
func kernelManifests(cfg tcdeploy.Config, readerEmail string) ([]byte, error) {
	workload, err := tcdeploy.Render(cfg)
	if err != nil {
		return nil, err
	}
	namespace, rest, ok := bytes.Cut(workload, []byte("\n---\n"))
	if !ok || !bytes.HasPrefix(namespace, []byte("apiVersion: v1\nkind: Namespace\n")) {
		return nil, errors.New("kernel deploy: TechnoCore's stream does not begin with its Namespace, which the builder's ServiceAccount follows")
	}
	manifests := slices.Concat(namespace, []byte("\n---\n"), pbuild.RenderServiceAccount(), []byte("---\n"), rest)
	if readerEmail != "" {
		for _, ns := range cfg.Meter {
			b, err := renderReaderBinding(readerEmail, ns)
			if err != nil {
				return nil, err
			}
			manifests = append(manifests, []byte("---\n")...)
			manifests = append(manifests, b...)
		}
	}
	seed, err := kernel.RenderNamespacesConfigMap(tcdeploy.DefaultNamespace, kernel.DefaultNamespacesName, cfg.Meter)
	if err != nil {
		return nil, err
	}
	manifests = append(manifests, []byte("---\n")...)
	return append(manifests, seed...), nil
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

// costWhatKernel is the kernel's standing cost, as its cost fact names it.
const costWhatKernel = "the kernel"

// kernelCost is kernel deploy's cost fact (A23-33): the kernel's replica,
// standing, against the instance's cost limit, and the instance's floor
// fully provisioned (floorFull), with whether the limit is below it. Below
// the floor is a fact the operator consents to by confirming, as --yes
// deploys past it, never a block. The question and the refusals are asked
// from it, so they say what the plan binds.
func kernelCost(meta *config.InstanceMetadata) plan.CostFact {
	f := fullFloorCost(meta)
	f.Standing = []plan.StandingCost{{What: costWhatKernel, Replicas: tcdeploy.Replicas,
		CPUMilli: int64(tcdeploy.RequestCPUMilli), MemMiB: int64(tcdeploy.RequestMemMiB), MonthCents: cents(kernelMonthlyUSD)}}
	return f
}

// kernelCostQuestion is the cost gate's question, from the cost fact, in
// exact cents.
func kernelCostQuestion(name string, f plan.CostFact, namespaces []string) string {
	k := f.Standing[0]
	return fmt.Sprintf("\nDeploying the kernel to %q runs %d replica continuously (~$%s/month estimated) and\n"+
		"meters %s.\nOnce running it will stop applications — and only applications — if spending\nreaches %s/%s.",
		name, k.Replicas, amount(k.MonthCents), listText(namespaces), money(f.Currency, f.LimitCents), terminalText(f.Period))
}

// confirmCost is kernel deploy's cost gate, asked from the plan's cost fact
// f. --yes proceeds; a session with no terminal and no --yes is a usage
// error, which names the plan's route.
func (c *kernelDeployCommand) confirmCost(env *Env, meta *config.InstanceMetadata, f plan.CostFact, namespaces []string) (bool, error) {
	// The floor is shown whether or not the operator is being prompted: a
	// limit that cannot be met is a configuration mistake, and the moment the
	// enforcer is deployed is the last moment it is cheap to notice.
	warnIfBelowFloor(env.Err, meta.CostLimit, floorFull(meta), "this instance fully provisioned")

	if c.deployer.assumeYes {
		return true, nil
	}
	if !isInteractive(env) {
		if f.BelowFloor {
			return false, usagef(msgKernelBelowFloorYes, money(f.Currency, f.LimitCents), terminalText(f.Period), money(f.Currency, f.FloorMonthCents))
		}
		return false, usagef(msgKernelCostYes, amount(f.Standing[0].MonthCents))
	}
	fprintln(env.Err, kernelCostQuestion(meta.Name, f, namespaces))
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
	// Reader is the reader bound in ReaderBindings, every metered namespace;
	// both are empty unless 'reader grant' recorded the metered scope.
	Reader         string   `json:"reader,omitempty"`
	ReaderBindings []string `json:"reader_bindings_created,omitempty"`
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
	printReaderBindings(w, r.Reader, r.ReaderBindings)
	fprintf(w, "\nIt stops applications only. The tunnel and the key holder are last-to-die:\n")
	fprintf(w, "stopping them would make storage impossible to unseal while the instance kept\n")
	fprintf(w, "billing.\n")
	return nil
}
