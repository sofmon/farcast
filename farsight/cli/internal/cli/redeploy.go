package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
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
Usage: farcast redeploy <instance> [flags]

Re-render and re-apply FatLine's workload for an instance that is already
connected: resolve the image (building and pushing it into the instance's own
registry when it is missing, exactly as connect does), render the workload for
the carrier the instance is already bound to, apply it, and wait for the
rollout. Use it to roll out a FatLine fix without destroying the instance.

It never provisions a carrier and never mints an mTLS identity — those stay
'farcast connect's job — so nothing new becomes billable and the public
endpoint does not change. The instance must already be connected.

It re-applies even when the image digest is unchanged, because a fix can live
in the workload template rather than in the image; it says so plainly when that
is what happened.

Flags:
  -y, --yes         Skip the confirmation of what will change, and the build
                    confirmation (required non-interactively)
  --fatline-image   FatLine container image to deploy (default: this instance's
                    own registry, at system/fatline for this farcast version)
  --source <dir>    farcast checkout to build FatLine's image from
                    (default: auto-detected from the working directory)

With --output json the command prints one JSON result and never prompts.`)
}

func (c *redeployCommand) SetFlags(fs *flag.FlagSet) {
	c.setYesFlag(fs, "skip the change confirmation and the build confirmation")
	c.setImageFlags(fs)
}

func (c *redeployCommand) Run(ctx context.Context, env *Env, args []string) error {
	c.ensureDefaults()
	// The two image flags are opposed intents — "deploy exactly this" versus
	// "build from here and deploy that" — so accepting both would mean silently
	// honouring one. Naming the conflict beats guessing.
	if c.fatlineImage != "" && c.sourceDir != "" {
		return usagef("--fatline-image deploys an image as given and --source builds a new one; pass one or the other")
	}
	if len(args) == 0 {
		return usagef("redeploy requires an instance name")
	}
	if len(args) > 1 {
		return usagef("redeploy takes one instance name; got %d arguments", len(args))
	}
	name := args[0]

	meta, err := env.ConfigDir.LoadInstanceMetadata(name)
	if err != nil {
		return fmt.Errorf("no such instance %q (run 'farcast install' first): %w", name, err)
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

	// The instance's mTLS material is loaded, never minted: passing connected
	// keeps this on ensureIdentity's load-or-explain path, so a lost trust root
	// is reported as unrecoverable instead of being replaced by a CA the running
	// FatLine has never heard of.
	mtls, err := ensureIdentity(env, name, true)
	if err != nil {
		return err
	}

	// The registry ensure is idempotent and comes first because the image may
	// have to be built and pushed into it. A failure only stops a redeploy that
	// needs it: with an explicit --fatline-image nothing is looked up or pushed,
	// so an instance whose stored credential predates ADR 0007's role can still
	// be repaired.
	reg, err := c.ensureRegistry(ctx, env, name, meta)
	if err != nil {
		if c.fatlineImage == "" {
			return err
		}
		fprintf(env.Err, "Warning: %v\n", err)
		fprintln(env.Err, "Continuing: --fatline-image names an image this redeploy neither looks up nor pushes.")
	}

	img, err := c.resolveImage(ctx, env, reg)
	if err != nil {
		return err
	}
	previous := deployedImage(meta)

	// The consent gate. Note it follows image resolution, which may itself have
	// built and pushed: a push changes nothing about what the instance is
	// running, so the operator is asked about the change that actually lands —
	// the apply — with the resulting digest in hand rather than in the abstract.
	ok, err := c.confirm(env, name, previous, img)
	if err != nil {
		return err
	}
	if !ok {
		fprintln(env.Err, "Aborted.")
		return errors.New("redeploy not confirmed")
	}

	manifests, err := renderWorkload(img, carrier, mtls)
	if err != nil {
		return err
	}

	cl := c.newCluster(env.ConfigDir.InstanceKubeconfigPath(name))
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
	// the Deployment carries one replica with the default strategy — so a
	// rollout that fails leaves the *previous* image still serving. Recording
	// early would name an image that never served a byte, on the exact path
	// this command exists for: a deploy that crash-loops.
	if err := cl.RolloutStatus(ctx, deploy.DefaultNamespace, deploy.DefaultName, fatlineRolloutTimeout); err != nil {
		if previous != "" {
			fprintf(env.Err, "The rollout did not complete; %s is still the image serving traffic.\n", previous)
			fprintf(env.Err, "Inspect it with: kubectl -n %s describe pod -l app.kubernetes.io/name=%s\n", deploy.DefaultNamespace, deploy.DefaultName)
		}
		return fmt.Errorf("FatLine rollout: %w", err)
	}

	recordDeployedImage(meta, img)
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

// confirm is redeploy's consent gate.
//
// It is deliberately *not* a cost gate. The load balancer already exists and a
// redeploy makes nothing new billable, so re-asking the ~$18/mo question here
// would spend the credibility of the one prompt that guards real money (ADR
// 0005) on an answer that is always "yes, nothing changes". What it asks about
// instead is the change itself: which image the instance's network boundary is
// about to be told to run. --yes waives it; a non-interactive session without
// --yes is a usage error, the same shape as connect's gates.
func (c *redeployCommand) confirm(env *Env, name, previous, img string) (bool, error) {
	if c.assumeYes {
		return true, nil
	}
	change := describeRedeploy(name, previous, img)
	if !isInteractive(env) {
		return false, usagef("%s; pass --yes to confirm", change)
	}
	fprintf(env.Err, "%s.\n", change)
	return newPrompter(env.In, env.Err).yesNo("Re-apply FatLine's workload now?")
}

// describeRedeploy states what the redeploy will do, in one line used both by
// the prompt and by the usage error that stands in for it when nobody is there
// to answer.
//
// An unchanged digest is stated plainly rather than treated as a no-op: the
// failure this command was built for was a change to the workload *template* —
// an mTLS Secret the container could not read — with the image byte-identical,
// so a redeploy that stopped at "nothing to do" would be useless for the exact
// case it exists for.
func describeRedeploy(name, previous, img string) string {
	switch previous {
	case "":
		return fmt.Sprintf("this redeploys %q with %s; local state does not record what it runs today", name, img)
	case img:
		return fmt.Sprintf("%q already runs %s — image unchanged; re-applying the workload template", name, img)
	default:
		return fmt.Sprintf("this replaces the image %q runs: %s → %s", name, previous, img)
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
