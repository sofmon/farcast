package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/components"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	"github.com/sofmon/farcast/fatline/deploy"
)

// redeployCommand re-renders and re-applies FatLine's workload for an instance
// that is already connected.
//
// It exists because the alternative was destroying the instance. FatLine is the
// instance's network boundary, so a security fix in it — or in the workload that
// runs it — has to be rollable-out on its own; before this command the only
// supported way to change either was `release` plus a reinstall, which takes the
// whole instance with it. That is not a price anyone should pay to fix the thing
// guarding their data, so the operator reaches for the reinstall late, which is
// precisely the wrong incentive on a security boundary.
//
// What it deliberately does *not* touch is the carrier and the mTLS identity.
// Those are `connect`'s: the load balancer is the standing cost (ADR 0005) and
// the per-instance CA is the sovereign trust root, and neither should move
// because someone rolled a new image.
type redeployCommand struct {
	// The same image-resolution and cluster-apply machinery connect uses. Shared
	// rather than copied so the two commands cannot drift on where the
	// instance's network boundary gets its code from (ADR 0007).
	fatlineDeployer
}

func newRedeployCommand() *redeployCommand {
	c := &redeployCommand{}
	c.ensureDefaults()
	return c
}

func (*redeployCommand) Name() string { return "redeploy" }
func (*redeployCommand) Synopsis() string {
	return "Re-apply FatLine's workload to a connected instance"
}

func (*redeployCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast redeploy <instance> [flags] [--plan | --confirm <digest>]

Re-render and re-apply FatLine's workload for an instance that is already
connected: resolve FatLine's and Shrike's images exactly as connect does (the
images this farcast carries, pushed into the instance's own registry when the
version tag does not already hold them), render the workload for the carrier
the instance is already bound to, apply it, and wait for the rollout. Use it to
roll out a FatLine fix without destroying the instance.

It decides both images before it asks anything, reading the instance's
recorded registry with the installer's key, and ensures the registry, pushes
and builds only once the change is confirmed. On an instance that records no
registry, an interactive or --yes run ensures it first, as connect does.

A release farcast keeps an operator-built image (--source) recorded for this
instance until --embedded or --source is passed, and an image another farcast
version deployed too: replacing either is said, and needs --embedded. A farcast
built from source carries no images. With no --source, it keeps an operator or
development build recorded for this instance, and compiles any image it does
not keep from a farcast checkout on this machine with its Go, after its build
confirmation (which --yes answers), recording it as a development build.

--fatline-image deploys FatLine's image exactly as given, with nothing looked
up or pushed for it. When the instance's registry cannot be had (none
recorded and its ensure failing, the installer's key refused, or the
provider not opened), Shrike is then not deployed, and the command says so.
That is a break-glass step, taken interactively or with --yes only: --plan
and --confirm never deploy FatLine without Shrike. A registry that is read
but then fails its ensure after the change is confirmed refuses the
redeploy, with nothing pushed or deployed. Otherwise Shrike's image is still
resolved as above, so --embedded beside it replaces Shrike's alone, and
needs the registry.

It never provisions a carrier and never mints an mTLS identity — those stay
'farcast connect's job — so nothing new becomes billable and the public
endpoint does not change. The instance must already be connected.

It re-applies even when the image digest is unchanged, because a fix can live
in the workload template rather than in the image; it says so plainly when that
is what happened.

Flags:
  -y, --yes         Skip the confirmation of what will change and, for --source
                    or a source build, the build confirmation (required
                    non-interactively, unless --plan and then --confirm). It
                    never implies --embedded
  --fatline-image   FatLine image to deploy, digest-pinned
                    (repository@sha256:…) (default: the image this farcast
                    carries, pushed to the instance registry's system/fatline)
  --source <dir>    farcast checkout to build the images from with this
                    machine's Go (a release farcast needs none); recorded as
                    operator-built
  --embedded        Deploy the images this farcast carries, replacing an
                    operator-built image or one another farcast version
                    deployed (never implied by --yes). Beside --fatline-image
                    it governs Shrike's image alone
  --plan            Print what this redeploy would do, and change nothing:
                    each image and where it comes from, its registry calls,
                    each document it would apply, and what it would print,
                    with the plan's digest. It reads the instance's recorded
                    registry with the installer's key, the CA certificate on
                    this machine (never its key), and no cluster. It needs the
                    registry recorded, and never plans FatLine without Shrike
  --confirm <digest>
                    Do exactly the plan with that digest, asking nothing, and
                    refuse, having written nothing, if anything it binds has
                    changed since. Its plan is the consent: one that lists the
                    replacement of an image another farcast version deployed
                    replaces it, with or without --embedded

A plan binds a source build's checkout directory and Go, not what the checkout
holds when --confirm runs.

With --output json the command prints one JSON result and never prompts.`)
}

func (c *redeployCommand) SetFlags(fs *flag.FlagSet) {
	c.setYesFlag(fs, "skip the change confirmation and, for --source or a source build, the build confirmation")
	c.setImageFlags(fs)
	c.consent.register(fs)
}

// msgInspectFatline is redeploy's hint after a rollout that did not complete:
// the instance. The crashed container is the one --previous reads.
const msgInspectFatline = "Inspect it with: farcast logs %s fatline --previous"

// msgRedeployYes is redeploy's refusal without a terminal and without --yes:
// the change it would make (describeRedeploy), and the two routes that need
// no terminal.
const msgRedeployYes = "%s; pass --yes to confirm" + consentSuffix

// preparedRedeploy is every decision a redeploy executes, made once by its
// plan (ADR 0023 M2.6, A23-36): interactive runs, --yes and --confirm all
// execute from it. A redeploy only loads the instance's mTLS material, so
// its identity decision never mints.
type preparedRedeploy struct {
	identity identityDecision
	// carrier is the carrier the instance is bound to, which the workload is
	// rendered for, and previous the image the record says FatLine runs.
	carrier  deploy.Carrier
	previous string
	workloadImages
}

func (c *redeployCommand) Run(ctx context.Context, env *Env, args []string) (err error) {
	// A 403 the writer met says whose it was, once (A20-9).
	var meta *config.InstanceMetadata
	defer func() { err = writerRefused(err, meta) }()
	c.ensureDefaults()
	// The image flags are opposed intents — "deploy exactly this", "build from
	// here and deploy that", "deploy what this farcast carries" — so accepting
	// two for the same image would mean silently honouring one. Naming the
	// conflict beats guessing. --fatline-image and --embedded are not such a
	// pair: the first names FatLine's image, the second then governs Shrike's.
	if err := c.checkImageFlags(); err != nil {
		return err
	}
	if len(args) == 0 {
		return usagef("redeploy requires an instance name")
	}
	if len(args) > 1 {
		return usagef("redeploy takes one instance name; got %d arguments", len(args))
	}
	mode, digest, err := c.consent.mode(c.assumeYes)
	if err != nil {
		return err
	}
	name := args[0]
	// Before the record is read: a farcast whose carried components it must
	// not push is refused before anything is asked or called, in every mode,
	// --plan included, before any plan is computed (A23-10).
	if err := c.precheck(); err != nil {
		return err
	}

	meta, err = env.ConfigDir.LoadInstanceMetadata(name)
	if err != nil {
		return fmt.Errorf("no such instance %q (run 'farcast install' first): %w", name, err)
	}
	if err := recordNamed(meta, name); err != nil {
		return err
	}
	if meta.Status == config.InstanceDeleting {
		return fmt.Errorf("instance %q is being released", name)
	}
	// Redeploy replaces a workload; it does not create one. An instance that was
	// never connected has no carrier and no trust root, and inventing either
	// here would quietly duplicate connect's bootstrap — including its billable
	// half — behind a verb that promises not to.
	if !meta.FatLineDeployed || meta.Carrier == nil {
		return fmt.Errorf("instance %q has no FatLine deployment to replace — run 'farcast connect %s' first", name, name)
	}
	carrier, err := deployCarrier(meta.Carrier)
	if err != nil {
		return err
	}

	// An interactive or --yes run opens the writer, and reads once as it,
	// before anything is decided, ensured, pushed or asked (ADR 0023 M2.5,
	// A20-10 and A20-11): an instance this machine cannot write as is refused
	// with nothing changed, and an endpoint that refuses the installer's key
	// refuses it before anything is applied. --plan never opens it, and
	// --confirm right after the comparison (A23-23).
	var cl clusterApplier
	if mode == consentNone {
		if cl, err = c.readyWriter(ctx, env, meta); err != nil {
			return err
		}
	}

	// The instance's mTLS material is loaded, never minted: deciding as a
	// connected instance keeps this on the load-or-explain path, so a lost
	// trust root is reported as unrecoverable, before the registry is read or
	// ensured, instead of being replaced by a CA the running FatLine has
	// never heard of. Deciding reads the CA certificate alone (A23-25), and
	// looks for the other five files without opening them, so material
	// missing one, ca.key or a leaf's key, is refused here too (A26-2).
	id, err := decideIdentity(env, name, true)
	if err != nil {
		return err
	}

	// The registry the plan reads (A23-24). A failure stops a redeploy that
	// needs it; with an explicit --fatline-image nothing is looked up or
	// pushed for FatLine, so an interactive or --yes run on an instance whose
	// stored credential predates ADR 0007's role can still be repaired,
	// FatLine alone. --embedded beside it needs the registry for Shrike's
	// image, and no plan deploys FatLine without Shrike (A23-5).
	reg, err := c.registryForPlan(ctx, env, name, meta, mode, "redeploy")
	if err != nil {
		return err
	}

	p, b, err := c.plan(ctx, env, meta, carrier, id, reg)
	if err != nil {
		if mode == consentNone {
			return p.refusal(env, c.embedded, err)
		}
		return err
	}
	switch mode {
	case consentPlan:
		return printPlan(env, b, c.now())
	case consentConfirm:
		if err := confirmPlan(b, digest); err != nil {
			return err
		}
	}
	// What deciding the images said, once (say): before anything is asked
	// or, under --confirm, right after the comparison (A23-26). An
	// interactive or --yes run refuses a version skew there, before it says
	// the lines of the decision it refuses.
	if err := p.say(env, c.embedded || mode == consentConfirm); err != nil {
		return err
	}

	// The consent gate comes after the images are decided and before any of
	// them is pushed or built: the operator, or the plan, is asked about
	// what the apply will make the boundary run — the digest each image is
	// pinned to, or, for a source build, the checkout it is compiled from —
	// and nothing reaches the registry before the answer. A push changes
	// nothing the instance runs, but it is a write to the one place the
	// instance runs code from, so it waits for consent like the apply.
	if mode == consentConfirm {
		if cl, err = c.readyWriter(ctx, env, meta); err != nil {
			return err
		}
	} else if err := c.consented(env, name, p); err != nil {
		return err
	}

	mtls, err := realizeIdentity(env, name, p.identity, mode)
	if err != nil {
		return err
	}
	// A redeploy is how an instance connected before the monitor shipped gets
	// one: the sidecar's image is decided the same way FatLine's is, and
	// pushed if the registry does not have it yet.
	resolved, shrike, err := c.realizeWorkloadImages(ctx, env, name, meta, p.workloadImages, mode)
	if err != nil {
		return err
	}
	img, previous := resolved.Ref, p.previous

	manifests, err := renderWorkload(img, shrike.Ref, p.carrier, mtls)
	if err != nil {
		return err
	}

	if isInteractive(env) || env.Verbose {
		fprintf(env.Err, "Re-applying FatLine's workload to %q…\n", name)
	}
	if err := cl.Apply(ctx, manifests); err != nil {
		return fmt.Errorf("re-apply FatLine: %w", err)
	}

	// The recorded digest is what the instance is *running*, so it is written
	// only once the rollout has actually succeeded. Connect records its own
	// deploy before waiting, but for the opposite reason: there it is racing to
	// record a billable load balancer. Nothing new becomes billable here, and
	// the Deployment carries two replicas under the default rolling strategy,
	// which at two adds a new pod before it removes an old one
	// (maxUnavailable rounds to 0, maxSurge to 1) — so a rollout that fails
	// leaves the *previous* image still serving. Recording early would name
	// an image that never served a byte, on the exact path this command
	// exists for: a deploy that crash-loops.
	if err := cl.RolloutStatus(ctx, deploy.DefaultNamespace, deploy.DefaultName, fatlineRolloutTimeout); err != nil {
		if previous != "" {
			fprintf(env.Err, "The rollout did not complete; %s is still the image serving traffic.\n", previous)
			fprintf(env.Err, msgInspectFatline+"\n", name)
		}
		return fmt.Errorf("FatLine rollout: %w", err)
	}

	recordDeployedImage(meta, img)
	recordSystemImage(meta, components.FatLine.Name, resolved.Record)
	recordSystemImage(meta, components.Shrike.Name, shrike.Record)
	meta.UpdatedAt = time.Now().UTC()
	if err := env.ConfigDir.SaveInstanceMetadata(name, meta); err != nil {
		fprintf(env.Err, "Warning: %s is running, but recording that locally failed: %v\n", img, err)
		fprintf(env.Err, "Local state still names the previous image; re-run 'farcast redeploy %s' to converge it.\n", name)
	}

	return env.Printer.Print(redeployResult{
		Name:          name,
		Carrier:       meta.Carrier.Type,
		Endpoint:      meta.Carrier.Endpoint,
		Registry:      registryPrefix(meta),
		PreviousImage: previous,
		Image:         img,
		ImageChanged:  previous != "" && previous != img,
		Status:        "redeployed",
	})
}

// plan is redeploy's plan (design §9.4, A23-36): FatLine's and Shrike's
// images, the registry's cloud facts (the ensure, then the pushes), each
// document of FatLine's workload rendered for the instance's carrier over
// placeholder leaves and the instance's real CA certificate, and its
// notices. It binds no mint and no restart: a redeploy only loads the
// instance's material. It reads the record, the CA certificate (never
// ca.key, never a server key) and, through reg, the registry; it writes
// nothing, and reads no cluster and no terminal. redeploy has no block.
//
// On an error the prepared decisions hold what was decided before it, so an
// interactive or --yes run says what it always said first (refusal).
func (c *redeployCommand) plan(ctx context.Context, env *Env, meta *config.InstanceMetadata, carrier deploy.Carrier,
	id identityDecision, reg *registryAccess) (preparedRedeploy, plan.Bound, error) {
	p := preparedRedeploy{identity: id, carrier: carrier, previous: deployedImage(meta)}
	b := newBound("redeploy", meta, "none", "")
	b.Options = sortedOptions(c.imageOptions())

	var err error
	if p.workloadImages, err = c.decideWorkloadImages(ctx, env, reg, meta); err != nil {
		return p, plan.Bound{}, err
	}
	writes, err := p.writeFacts(carrier, placeholderMTLS(meta.Name, id))
	if err != nil {
		return p, plan.Bound{}, err
	}
	facts := append(p.imageFacts(meta), p.cloudFacts(meta)...)
	facts = append(facts, writes...)
	b.Facts = append(facts, p.noticeFacts()...)
	return p, b, nil
}

// consented is an interactive or --yes run's consent to its plan, asked from
// it: a component another farcast version deployed is refused unless
// --embedded was given, before anything is asked (ADR 0023 decision 4; --yes
// never implies it), as say already refused it, before its lines; then each
// build, and then the change, in the order the questions came before the
// decisions were split from the pushes. Nothing is built or pushed until
// every answer is in.
func (c *redeployCommand) consented(env *Env, name string, p preparedRedeploy) error {
	if err := p.skewRefusal(c.embedded); err != nil {
		return err
	}
	if err := c.buildConsents(env, p.workloadImages); err != nil {
		return err
	}
	ok, err := c.confirm(env, name, p)
	if err != nil {
		return err
	}
	if !ok {
		fprintln(env.Err, "Aborted.")
		return errors.New("redeploy not confirmed")
	}
	return nil
}

// confirm is redeploy's consent gate.
//
// It is deliberately *not* a cost gate. The load balancer already exists and a
// redeploy makes nothing new billable, so re-asking the ~$18/mo question here
// would spend the credibility of the one prompt that guards real money (ADR
// 0005) on an answer that is always "yes, nothing changes". What it asks about
// instead is the change itself: which image the instance's network boundary is
// about to be told to run, as the plan decided it. --yes waives it; a
// non-interactive session without --yes is a usage error, the same shape as
// connect's gates, which names the plan's route too.
func (c *redeployCommand) confirm(env *Env, name string, p preparedRedeploy) (bool, error) {
	if c.assumeYes {
		return true, nil
	}
	change := describeRedeploy(name, p.previous, p.fatline)
	if !isInteractive(env) {
		return false, usagef(msgRedeployYes, change)
	}
	fprintf(env.Err, "%s.\n", change)
	return newPrompter(env.In, env.Err).yesNo("Re-apply FatLine's workload now?")
}

// describeRedeploy states what the redeploy will do, from FatLine's image as
// the plan decided it, in one line used both by the prompt and by the usage
// error that stands in for it when nobody is there to answer.
//
// An unchanged digest is stated plainly rather than treated as a no-op: the
// failure this command was built for was a change to the workload *template* —
// an mTLS Secret the container could not read — with the image byte-identical,
// so a redeploy that stopped at "nothing to do" would be useless for the exact
// case it exists for.
//
// A source build's digest exists only once it is built, which is after the
// question, so the line names the checkout it is compiled from instead
// (A23-36).
//
// The images and the checkout are the record's and argv's, so each goes
// through terminalText: printable text is unchanged.
func describeRedeploy(name, previous string, fl imageDecision) string {
	was := terminalText(previous)
	if fl.builds() {
		dir := terminalText(fl.source.dir)
		if previous == "" {
			return fmt.Sprintf("this redeploys %q with a source build of %s; local state does not record what it runs today", name, dir)
		}
		return fmt.Sprintf("this replaces the image %q runs: %s → a source build of %s, pushed once it is built", name, was, dir)
	}
	img := fl.target
	switch previous {
	case "":
		return fmt.Sprintf("this redeploys %q with %s; local state does not record what it runs today", name, terminalText(img))
	case img:
		return fmt.Sprintf("%q already runs %s — image unchanged; re-applying the workload template", name, terminalText(img))
	default:
		return fmt.Sprintf("this replaces the image %q runs: %s → %s", name, was, terminalText(img))
	}
}

type redeployResult struct {
	Name          string `json:"name"`
	Carrier       string `json:"carrier"`
	Endpoint      string `json:"endpoint"`
	Registry      string `json:"registry,omitempty"`
	PreviousImage string `json:"previous_image,omitempty"`
	Image         string `json:"image"`
	ImageChanged  bool   `json:"image_changed"`
	Status        string `json:"status"`
}

func (r redeployResult) Human(w io.Writer) error {
	fprintf(w, "✓ redeployed FatLine to %q\n", r.Name)
	fprintf(w, "  carrier:     public mTLS NLB  %s (unchanged)\n", r.Endpoint)
	if r.Registry != "" {
		fprintf(w, "  registry:    %s\n", r.Registry)
	}
	switch {
	case r.PreviousImage == "":
		// Nothing recorded to compare against, so claiming "unchanged" would be
		// a guess dressed as a fact.
		fprintf(w, "  image:       %s\n", r.Image)
	case r.ImageChanged:
		fprintf(w, "  previous:    %s\n", r.PreviousImage)
		fprintf(w, "  image:       %s\n", r.Image)
	default:
		fprintf(w, "  image:       %s (unchanged; the workload template was re-applied)\n", r.Image)
	}
	fprintln(w, "  rollout:     complete")
	return nil
}
