package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sofmon/farcast/datasphere"
	dskeyholder "github.com/sofmon/farcast/datasphere/keyholder"
	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/fatline/identity"
	"github.com/sofmon/farcast/fatline/policy"
	"github.com/sofmon/farcast/manifest/parser"
	pbuild "github.com/sofmon/farcast/planck/build"
	pfetch "github.com/sofmon/farcast/planck/fetch"
	"github.com/sofmon/farcast/planck/translate"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
	tkube "github.com/sofmon/farcast/technocore/kube"
	"github.com/sofmon/farcast/technocore/pricing"
)

// rolloutTimeout bounds the wait for a translated application to come up. It
// is generous because the first pull of a fresh image on a cold Autopilot node
// is the slow case, and short enough that a CrashLoopBackOff is reported as
// one rather than waited on forever.
const rolloutTimeout = 5 * time.Minute

// runPlanReader is what run's deploy plan reads the cluster through (ADR 0023
// M2.6, A23-20, A23-47, A28-8): the fetch Job, its outcome and its log
// (fetchReader, JobState); the kernel's ledger, the namespaces and each
// application's Deployment (liveReader); the egress policy and the key pin
// whole, with their resourceVersions (configMapDataReader); the target
// namespace's other workloads (lister); farcast-system's uid, which the
// plan binds as its target; and the builder's ServiceAccount, whose uid the
// push grant names (serviceAccountReader, design §33 A33-18). Under
// --confirm it is the instance's reader; an interactive or --yes run passes
// the writer it opened.
type runPlanReader interface {
	fetchReader
	liveReader
	configMapDataReader
	lister
	preflighter
	serviceAccountReader
	JobState(ctx context.Context, namespace, name string) (cluster.JobResult, bool, error)
}

// runCluster is the slice of the cluster client `run` writes through: what
// its plan reads, and the applies of the fetch, the builds, the workloads and
// the meter, the egress policy's at the resourceVersion it was read at
// (ApplyAt, A30-40), and the workloads' rollout.
type runCluster interface {
	runPlanReader
	jobWaiter
	ApplyAt(ctx context.Context, manifest []byte, resourceVersion string) error
	RolloutStatus(ctx context.Context, namespace, name string, timeout time.Duration) error
}

type runCommand struct {
	ref          string
	gitSecret    string
	builderImage string
	fetcherImage string
	manifestPath string
	namespace    string
	assumeYes    bool
	// replaceRepository lets a run replace a namespace this machine recorded
	// under another repository.
	replaceRepository bool
	// consent is --plan and --confirm <digest> (ADR 0023 M2.6d).
	consent consentFlags

	// Seams, overridable in tests.
	newCluster func(clusterRef) (runCluster, error)
	// newPlanReader opens what the deploy plan reads the cluster through
	// under --confirm: the instance's reader (A23-20), openReaderDefault when
	// unset, and never the writer. An interactive or --yes run reads through
	// the writer it opened instead (design §7.3).
	newPlanReader func(clusterRef) (runPlanReader, error)
	// openProvider opens the cloud provider the deploy plan reads the
	// project number and the repository's IAM policy through, as the
	// installer key, in every mode (design §33, A33-1, A33-22):
	// openProviderDefault when unset. The fetch plan reads no Google.
	openProvider providerOpener
	newBuilder   func(progress func(string)) imageBuilder
	// newKeyholder opens the session that hands new scopes to a running
	// keyholder. It is a seam because the decision it guards — never unseal a
	// sealed replica — is one no unit test could otherwise reach: the real
	// path needs a tunnel and a cluster.
	newKeyholder func(ctx context.Context, env *Env, instance string) (sealStateClient, func(), error)
	// newPinStore reaches the key pin; nil reaches the cluster.
	newPinStore pinStoreOpener
	// mintCredential mints each application's egress credential once the
	// deploy is past its re-read and, under --confirm, the policy's
	// comparison (A28-10); mintEgressCredential unless a test counts them.
	mintCredential credentialMinter
	// now is run's clock, against which the kernel's ledger is stale
	// (A28-2), and a printed plan is dated (generated_at); interactive is
	// whether a question can be asked.
	now         func() time.Time
	interactive func(*Env) bool
}

// sealStateClient is the part of the keyholder client a deploy uses: ask what
// a replica is, and hand it key material if it is already serving.
type sealStateClient interface {
	State(ctx context.Context, ordinal int) (keyholder.State, error)
	Unseal(ctx context.Context, ordinal int, bundle []byte, intent string) (keyholder.State, error)
}

func (*runCommand) Name() string { return "run" }
func (*runCommand) Synopsis() string {
	return "Deploy a Git repository to an instance"
}

func (*runCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast run <instance> <repository> [--ref <git-ref>] [--git-secret <name>]
                   [--namespace <name>] [--manifest <path>] [--replace-repository]
                   [--fetcher-image <ref@sha256:…>] [--builder-image <ref@sha256:…>]
                   [-y] [--plan | --confirm <digest>]

Read a repository's ./farcast manifest, show you what it declares, and — once
you approve — build every application in it and deploy them.

A run has two plans, because what it deploys is known only once the instance
has read the manifest. --plan prints the first, the read, and changes
nothing: the Job that reads the manifest, its cost, the fetcher image and the
three documents it applies. It reads the instance's record and keys.yaml, and
no cluster. --confirm with that plan's digest runs the read and prints the
second, the deploy, which it computes as the instance's reader ('farcast
reader grant' must have verified it): what is built, its cost, the builder's
push grant, the egress credentials, storage scopes and identities it would
mint, every document it would write, what it resets of what runs now, and
whether the instance's spending is at its limit. Nothing but the read is
written. Before the read is applied, the reader reads the builder's
ServiceAccount, which the deploy plan needs. The deploy plan also reads the
project number and the repository's IAM policy with the installer's key, in
every mode; under --confirm with the fetch plan's digest those reads come
after the read, which has billed, so a failure there prints no deploy plan.
--confirm with the deploy plan's digest computes that plan again and deploys
exactly it, asking nothing; it refuses, having written nothing, if anything
the plan binds has changed, and, once the builds are written, if the ledger,
an application, the egress policy or the key pin moved while they ran. A
deploy digest is good while the fetch Job it read exists: 15 minutes after it
finishes.

The instance does the reading and the building. It clones the repository
itself, so this works the same from a laptop that has never seen the source as
from the one that wrote it (ADR 0010). What it reports back is the resolved
commit and a digest of the manifest it parsed, and the build is pinned to that
same commit: a branch that moves between the read and the build cannot change
what you approved.

The builder pushes under its own ServiceAccount, farcast-system/farcast-builder,
whose push grant this command never applies. When the repository's own
policy does not hold it by the account's uid, the review prints the commands
that grant it and remove the principal every FarCast instance in the project
shares (a grant at the project, through a group or by a wider role does not
show there), and an account that does not exist yet gets them right after
the first build starts. The uid member on a repository's policy is
unverified until the M2 walk.

The gate is the external service declarations. Nothing an application can reach
is implicit — FatLine denies every outbound host that the manifest does not
name, so what is listed at the prompt is the whole of it. -y answers the
question and skips nothing else: the review is still printed, to stderr, and
the result lists every host each application may now reach and why.

A deploy sets every application back to one replica and to the requests it
renders, so the review says which running application it restarts or resets.

While the kernel's ledger says the instance's spending is at its limit, or
cannot be read, or says the kernel last looked more than 15 minutes ago or
never, -y deploys nothing. An interactive run is told what the deploy would
restart, and then asked. A deploy plan made at the limit says so, and
confirming it is the consent. The ledger and the applications are read again
after the builds, before anything else is written, and the same rule applies
to what is true then.

An instance with no kernel is refused before anything is read. The read, the
builds and the applications all bill, and a namespace the kernel does not meter
is neither counted against the cost limit nor stoppable by it — run
'farcast kernel deploy <instance>' first.

Both images this runs inside the instance are third-party and must be
digest-pinned. Pass each once and the instance remembers it.

One namespace holds one repository. A successful run records, on this machine
and never in the cluster, the repository, ref, commit and manifest digest it
deployed into the namespace. A later run into that namespace from another
repository is refused — it would replace the first one's egress entries and
reuse its applications' storage scopes — unless --replace-repository says to
replace it. With --namespace the refusal comes before anything is read; without
it the namespace is the manifest's name, so it comes after the manifest read
and before anything is built or deployed. The record belongs to this machine: a
deploy from another machine is not in it.`)
}

func (c *runCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.ref, "ref", "", "branch, tag or commit to deploy (default refs/heads/main)")
	fs.StringVar(&c.gitSecret, "git-secret", "", "Secret holding a read-only Git credential (private repositories)")
	fs.StringVar(&c.namespace, "namespace", "", "deploy into this namespace instead of the manifest's name")
	fs.StringVar(&c.manifestPath, "manifest", "", "path of the manifest within the repository (default ./farcast)")
	fs.StringVar(&c.fetcherImage, "fetcher-image", "", "digest-pinned image with git in it")
	fs.StringVar(&c.builderImage, "builder-image", "", "digest-pinned Kaniko image")
	fs.BoolVar(&c.assumeYes, "yes", false, "show the review but do not ask")
	fs.BoolVar(&c.assumeYes, "y", false, "show the review but do not ask")
	fs.BoolVar(&c.replaceRepository, "replace-repository", false,
		"deploy into a namespace this machine recorded under another repository, replacing it")
	c.consent.register(fs)
}

func (c *runCommand) ensureDefaults() {
	if c.newCluster == nil {
		c.newCluster = func(r clusterRef) (runCluster, error) {
			// A refusal returns a nil cluster, never a nil *cluster.Client
			// inside a non-nil one.
			cl, err := openWriter(r)
			if err != nil {
				return nil, err
			}
			return cl, nil
		}
	}
	if c.newPlanReader == nil {
		c.newPlanReader = func(r clusterRef) (runPlanReader, error) {
			// A refusal returns a nil reader, never a nil *cluster.Client
			// inside a non-nil one.
			cl, err := openReaderDefault(r)
			if err != nil {
				return nil, err
			}
			return cl, nil
		}
	}
	if c.newBuilder == nil {
		c.newBuilder = newBuilderDefault
	}
	if c.openProvider == nil {
		c.openProvider = openProviderDefault
	}
	if c.mintCredential == nil {
		c.mintCredential = mintEgressCredential
	}
	// The keyholder's opener, which the package's tests refuse unless one
	// is set (A27-11, A28-11).
	if c.newKeyholder == nil {
		c.newKeyholder = openKeyholderDefault
	}
	if c.now == nil {
		c.now = runNowDefault
	}
	if c.interactive == nil {
		c.interactive = isInteractive
	}
}

// runNowDefault is run's clock when the command's own is unset: time.Now. It
// is a variable for deployerNowDefault's reason (fatline.go): a test that
// runs run through the router, where it cannot set the command's own clock,
// fixes it here, so a ledger it seeded reads fresh or stale by the test's
// clock (A28-2) and not by the day the test happens to run.
var runNowDefault = time.Now

// msgRunYes is run's refusal without a terminal and without --yes: the two
// routes that need no terminal.
const msgRunYes = "running a repository builds and deploys code this machine has not read; pass --yes to confirm" + consentSuffix

// msgRunNeedsReader is run's refusal under --confirm, of either plan, when
// the instance has no reader 'reader grant' has verified (design §9.4,
// A23-21): the instance, the reader's state as 'instances' prints it, and
// what to do from that state (readerRemedy). The deploy plan is computed as
// the reader, so --confirm needs one whichever digest it is given; --plan,
// which prints the fetch plan and reads no cluster, does not.
const msgRunNeedsReader = "'farcast run --confirm' computes the deploy plan as instance %q's reader, whose state is %s; %s, " +
	"or run 'farcast run' in a terminal. Nothing was written."

// msgFetchJobGone is --confirm's refusal of a deploy digest when the fetch
// Job its plan read is not there (A23-47): the fetch plan is now another,
// whose Job has another name, or the Job was removed once its time ran out.
// The verb is how long a finished fetch Job is kept, in minutes.
const msgFetchJobGone = "the plan's fetch stage changed, or the fetch Job its deploy plan read is gone " +
	"(a fetch Job is kept %d minutes after it finishes)"

// msgRunBuildFailed is run's error for a failed build: the app. The end of
// the build's log, when JobLogs could read it, is printed above it.
const msgRunBuildFailed = "the build of %s failed; nothing was deployed. The end of its log, when it could be read, is printed above"

// msgNothingDeployed ends an error met once the manifest was read and before
// anything was built.
const msgNothingDeployed = "the manifest was read, and nothing was built or deployed"

func (c *runCommand) Run(ctx context.Context, env *Env, args []string) (err error) {
	// A 403 the writer met says whose it was, once (A20-9); one the deploy
	// plan's reader met says so already (A23-22), and writerRefused leaves it.
	var meta *config.InstanceMetadata
	defer func() { err = writerRefused(err, meta) }()
	if len(args) != 2 {
		return usagef("run takes an instance and a repository, e.g. 'farcast run prod github.com/user/repo'")
	}
	mode, given, err := c.consent.mode(c.assumeYes)
	if err != nil {
		return err
	}
	name := args[0]
	c.ensureDefaults()

	repo, err := repoURL(args[1])
	if err != nil {
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
	if meta.Registry == nil || meta.Registry.Prefix == "" {
		return fmt.Errorf("instance %q has no image registry recorded; run 'farcast connect %s' first", name, name)
	}
	// The deploy plan reads the repository's IAM policy by the repository
	// the record names, and prints commands from the record's project, its
	// repository and its location (design §33, A33-15): a record that names
	// none, or holds a value Google does not issue, is refused before the
	// fetch, which bills, as one with no registry is.
	if _, _, _, err := pushGrantRecord(meta); err != nil {
		return err
	}
	// The fetch plan's refusals, read from the record and keys.yaml alone,
	// before anything is opened, resolved or fetched, in every mode (A23-18,
	// A28-8). An interactive or --yes run is refused with each as the error
	// it always was; a plan carries it as its block.
	blocked, err := c.fetchRefusal(env, meta, repo)
	if err != nil {
		return err
	}
	if blocked != nil && mode == consentNone {
		return blocked
	}

	// An interactive or --yes run opens the writer, and reads once as it,
	// before any toolchain image is resolved or pushed, anything is fetched
	// or asked (ADR 0023 M2.5, A20-10 and A20-11): an instance this machine
	// cannot write as is refused with nothing spent, and an endpoint that
	// refuses the installer's key refuses it before the fetch is applied.
	// --plan never opens it, and --confirm only after a comparison (A23-23,
	// A23-47).
	var cl runCluster
	var uid string
	if mode == consentNone {
		if cl, uid, err = openReadyAt(ctx, env, meta, c.newCluster); err != nil {
			return err
		}
		defer afterWrites(env, name, cl)
	}
	pf, fb, err := c.fetchPlan(ctx, env, meta, repo, blocked)
	if err != nil {
		return err
	}
	switch mode {
	case consentPlan:
		return printPlan(env, fb, c.now())
	case consentConfirm:
		return c.confirmed(ctx, env, meta, pf, fb, given)
	}

	// 1. The instance reads the manifest and reports what it read.
	if err := applyFetch(ctx, env, cl, pf.cfg); err != nil {
		return err
	}
	read, err := readFetch(ctx, env, cl, pf.cfg)
	if err != nil {
		return err
	}
	// What this deploys, decided once, read as the writer, which may read
	// every namespace: a block is refused as the error it always was, so a
	// manifest named like a system namespace stays a usage error (A28-8).
	p, _, err := c.deployPlan(ctx, env, meta, pf, read, cl, consentNone, uid)
	if err != nil {
		return fmt.Errorf("%w; %s", err, msgNothingDeployed)
	}
	if p.blocked != nil {
		return p.blocked
	}

	// 2. The operator sees what it declares, and decides.
	ok, err := c.confirm(env, p.review(meta))
	if err != nil {
		return err
	}
	if !ok {
		fprintln(env.Err, "Aborted. Nothing was built and nothing was deployed.")
		return nil
	}
	return c.deploy(ctx, env, meta, cl, p, consentNone)
}

// confirmed is run under --confirm (ADR 0023 M2.6d, A23-47, A28-8). given is
// the digest confirmed, and pf and fb the fetch plan, computed again.
//
// The fetch plan's own digest runs the manifest read and prints the deploy
// plan, computed as the instance's reader from what the read reported; it
// writes nothing else, and exits 0. The reader is checked first, then opened,
// and only then the writer, which applies the fetch: a machine whose reader
// cannot compute the deploy plan never starts the read.
//
// Any other digest is a deploy plan's. The fetch Job the fetch plan names is
// read, never applied again (§9.4): the deploy plan is computed again from
// it as the reader, compared, and executed from what was compared, the
// writer opened only after the comparison and its cluster checked to be the
// one the plan read.
func (c *runCommand) confirmed(ctx context.Context, env *Env, meta *config.InstanceMetadata, pf preparedFetch, fb plan.Bound, given string) error {
	name := meta.Name
	reader := clusterRef{Dir: env.ConfigDir, Meta: meta, Identity: kube.Reader, Warn: env.Err}
	if given == pf.digest {
		if err := confirmPlan(fb, given); err != nil {
			return err
		}
		if err := requireRunReader(env.ConfigDir, meta); err != nil {
			return err
		}
		rd, err := c.newPlanReader(reader)
		if err != nil {
			return err
		}
		// The deploy plan reads the builder's ServiceAccount as the
		// reader; a reader that may not is refused now, before the fetch
		// Job bills, not after it (design §33, A33-22, OQ-C).
		if _, err := readServiceAccountUID(ctx, rd, consentConfirm, name, tcdeploy.DefaultNamespace, pbuild.ServiceAccount, plan.GrantPush); err != nil {
			return fmt.Errorf("%w Nothing was written.", err)
		}
		cl, err := openConfirmed(ctx, env, meta, fb, c.newCluster)
		if err != nil {
			return err
		}
		defer afterWrites(env, name, cl)
		if err := applyFetch(ctx, env, cl, pf.cfg); err != nil {
			return err
		}
		read, err := readFetch(ctx, env, rd, pf.cfg)
		if err != nil {
			return planRead(consentConfirm, err, name)
		}
		// The deploy plan is what --confirm <fetch digest> prints. Its
		// notices are facts in it, printed by nothing else (A28-8).
		_, db, err := c.deployPlan(ctx, env, meta, pf, read, rd, consentConfirm, "")
		if err != nil {
			return fmt.Errorf("%w; %s", err, msgNothingDeployed)
		}
		return printPlan(env, db, c.now())
	}

	// A blocked fetch plan has no deploy plan: the digest given is not one
	// it could have printed (A28-8).
	if len(fb.Blocked) > 0 {
		return planChanged(pf.digest, given)
	}
	if err := requireRunReader(env.ConfigDir, meta); err != nil {
		return err
	}
	rd, err := c.newPlanReader(reader)
	if err != nil {
		return err
	}
	job := pf.cfg.Job()
	if _, found, err := rd.JobState(ctx, pfetch.Namespace, job); err != nil {
		return planRead(consentConfirm, fmt.Errorf("read the fetch Job %s/%s: %w", pfetch.Namespace, job, err), name)
	} else if !found {
		return changedAfterPlan(consentConfirm, fmt.Sprintf(msgFetchJobGone, pfetch.TTLSeconds/60))
	}
	read, err := readFetch(ctx, env, rd, pf.cfg)
	if err != nil {
		return planRead(consentConfirm, err, name)
	}
	p, db, err := c.deployPlan(ctx, env, meta, pf, read, rd, consentConfirm, "")
	if err != nil {
		return err
	}
	if err := confirmPlan(db, given); err != nil {
		return err
	}
	// What the plan says, once, right after the comparison, in the words a
	// review prints (A23-26, A28-8); no review is printed.
	for _, line := range p.notices {
		fprintln(env.Err, line)
	}
	cl, err := openConfirmed(ctx, env, meta, db, c.newCluster)
	if err != nil {
		return err
	}
	defer afterWrites(env, name, cl)
	return c.deploy(ctx, env, meta, cl, p, consentConfirm)
}

// requireRunReader is run's check, under --confirm, that the instance has a
// reader 'reader grant' has verified (A23-21): its deploy plan is computed as
// the reader, with no fallback to the writer. It reads the record and the
// presence of reader.key, never the key, and opens nothing.
func requireRunReader(dir config.Dir, meta *config.InstanceMetadata) error {
	state, err := ungrantedReader(dir, meta)
	if err != nil || state == "" {
		return err
	}
	return refuse(errCredentialMissing, msgRunNeedsReader, meta.Name, strings.ReplaceAll(state, "_", " "), readerRemedy(state, meta.Name))
}

// options are run's behaviour flags as both its plans bind them (A23-28,
// A28-8): each as given, "" when not.
func (c *runCommand) options() []plan.Option {
	return sortedOptions([]plan.Option{
		{Flag: "builder-image", Value: c.builderImage},
		{Flag: "fetcher-image", Value: c.fetcherImage},
		{Flag: "git-secret", Value: c.gitSecret},
		{Flag: "manifest", Value: c.manifestPath},
		{Flag: "namespace", Value: c.namespace},
		{Flag: "ref", Value: c.ref},
		{Flag: "replace-repository", Value: strconv.FormatBool(c.replaceRepository)},
	})
}

// fetchRefusal is the fetch plan's block, when there is one (A23-18, A28-8):
// an instance with no kernel; a keyring holding the scope every application
// shared, which no application's own scope can be minted beside; and a
// --namespace this machine recorded under another repository. Each reads the
// record and keys.yaml alone, and each is checked before anything is fetched:
// the read, every build and the workloads all bill, and on an instance with
// no kernel none of it is counted against the limit or stoppable by it. err
// is a --namespace that is no namespace run deploys into, a usage error and
// never a block.
func (c *runCommand) fetchRefusal(env *Env, meta *config.InstanceMetadata, repo string) (blocked, err error) {
	name := meta.Name
	if err := requireKernel(name, meta, "what this deploys"); err != nil {
		return err, nil
	}
	// A keyring no application's scope can be minted into: found after the
	// fetch and the builds, those would have been spent for nothing.
	if wiresStorage(meta) {
		if k, err := keyringOf(env, name); err == nil {
			if err := refuseSharedAppScope(name, k); err != nil {
				return err, nil
			}
		}
	}
	// An unusable namespace found after the read and the builds would have
	// cost real money to discover.
	if c.namespace != "" {
		if err := deployableNamespace(c.namespace); err != nil {
			return nil, err
		}
		if err := c.refuseOtherRepository(meta, name, c.namespace, repo, false); err != nil {
			return err, nil
		}
	}
	return nil, nil
}

// costWhatFetch and costWhatBuilds are run's one-off Jobs as its cost facts
// name them.
const (
	costWhatFetch  = "the manifest read"
	costWhatBuilds = "the builds"
)

// preparedFetch is run's fetch stage as its plan decided it (ADR 0023 M2.6d,
// A23-47): the read's Job, with the fetcher image; the builder image,
// resolved with it so a builder named by tag is refused before the read
// bills (A28-8), and where it came from; the fetch fact, which the deploy
// plan carries too; and the fetch plan's digest, which the deploy plan binds.
type preparedFetch struct {
	cfg           pfetch.Config
	builder       string
	builderSource string
	fact          plan.FetchFact
	digest        string
}

// fetchPlan is run's fetch plan, stage fetch (design §9.4, A23-47, A28-8):
// the manifest read, its Job's cost against the instance's limit, the
// fetcher image as named or recorded, and the three documents the read
// applies. It reads the record alone, and no cluster and no terminal; a
// toolchain image named by tag is looked up anonymously, only to be refused.
// With blocked, the refusal fetchRefusal found, it carries that block and no
// fact, and resolves nothing.
func (c *runCommand) fetchPlan(ctx context.Context, env *Env, meta *config.InstanceMetadata, repo string, blocked error) (preparedFetch, plan.Bound, error) {
	b := newBound("run", meta, "none", "")
	b.Stage, b.Options = "fetch", c.options()
	var pf preparedFetch
	if blocked != nil {
		b.Blocked = []plan.Block{blockOf(blocked)}
	} else {
		fetcher, fetcherSource, err := resolveToolchainSource(ctx, env, meta, fetcherKind, c.fetcherImage, c.newBuilder)
		if err != nil {
			return pf, plan.Bound{}, err
		}
		if pf.builder, pf.builderSource, err = resolveToolchainSource(ctx, env, meta, builderKind, c.builderImage, c.newBuilder); err != nil {
			return pf, plan.Bound{}, err
		}
		pf.cfg = pfetch.Config{
			Instance:    meta.Name,
			Fetcher:     fetcher,
			Repo:        repo,
			Ref:         c.ref,
			Manifest:    c.manifestPath,
			GitSecret:   c.gitSecret,
			EgressHosts: []string{hostOf(repo)},
		}
		stream, err := pfetch.Render(pf.cfg)
		if err != nil {
			return pf, plan.Bound{}, err
		}
		writes, err := applyFacts(stream)
		if err != nil {
			return pf, plan.Bound{}, err
		}
		pf.fact = plan.FetchFact{Type: plan.TypeFetch, Repository: repo, Ref: c.ref, Manifest: c.manifestPath, Job: pf.cfg.Job(), Fetcher: fetcher}
		cost := floorCost(meta, floorNow(meta))
		cost.OneOff = []plan.OneOffCost{{
			What: costWhatFetch, Jobs: 1, CPUMilli: pfetch.RequestCPUMilli, MemMiB: pfetch.RequestMemMiB, DeadlineS: pfetch.DeadlineSeconds,
		}}
		b.Facts = append([]plan.Fact{pf.fact, cost, toolchainImageFact(meta, fetcherKind, fetcher, fetcherSource)}, writes...)
	}
	digest, err := boundDigest(b)
	if err != nil {
		return pf, plan.Bound{}, err
	}
	pf.digest = digest
	return pf, b, nil
}

// msgUnmeteredNamespace is the deploy plan's block of a target namespace
// that exists and is not metered (design §5.4, P3): the reader is bound
// only where the kernel meters, so it could read nothing there.
const msgUnmeteredNamespace = "namespace %q exists and is not metered, so its reader cannot read it; run 'farcast kernel meter %s %s' first"

// msgRunHandOver is the notice of a deploy plan that hands new scopes to the
// keyholder (design §9.4).
const msgRunHandOver = "the new scopes are handed to the keyholder replicas that are serving; which replicas answer is decided when the deploy runs, outside this plan"

// appBuild is one application's build, as the deploy plan rendered it: the
// image it pushes, tagged, the Job's name, and the stream that starts it.
type appBuild struct {
	app         string
	destination string
	job         string
	manifest    []byte
}

// preparedDeploy is every decision a run's deploy executes, made once by its
// plan (ADR 0023 M2.6d, A23-47): an interactive run, --yes and --confirm all
// execute from it.
type preparedDeploy struct {
	repo    string
	read    fetched
	fetcher string
	builder string
	m       parser.Manifest
	// namespace is where the applications go; storageWired whether they are
	// wired to storage, decided now and by nothing later: an application
	// deployed before 'storage deploy' has no storage identity, whatever the
	// record says about the keyholder afterwards.
	namespace    string
	storageWired bool
	// live is what the plan read of the instance: the ledger, whether the
	// namespace exists, and each application's Deployment.
	live   runLive
	builds []appBuild
	// policyRV is the egress policy's resourceVersion as the plan read it.
	policyRV string
	// newScopes are the applications whose storage scope the deploy mints,
	// in manifest order.
	newScopes []string
	// pin is the key pin the plan decided over the new scopes, under --plan
	// and --confirm.
	pin runPinPlan
	// reader is the reader bound where the deploy starts metering, or "";
	// readerWarning the line that says why none is.
	reader        string
	readerWarning string
	// notices are the lines a review prints that the plan carries (A23-26,
	// A28-8), in order.
	notices []string
	// push is the builder's push grant as the plan read it, and pushNotice
	// its notice, "" when none is due (design §33, A33-22): the last of
	// notices, which the review prints too.
	push       pushGrant
	pushNotice string
	// blocked is the plan's block as the error it was found as, for an
	// interactive or --yes run (A28-8).
	blocked error
}

// review is what an interactive or --yes run shows before it is asked.
func (p preparedDeploy) review(meta *config.InstanceMetadata) review {
	rev := review{
		Instance: meta.Name, Repo: p.repo, Namespace: p.namespace,
		Manifest: p.m, Report: p.read.Report,
		FatLineDeployed: meta.FatLineDeployed,
		Limit:           meta.CostLimit,
		Floor:           floorNow(meta),
		Live:            p.live,
	}
	if p.readerWarning != "" {
		rev.Notices = []string{p.readerWarning}
	}
	if p.pushNotice != "" {
		rev.Notices = append(rev.Notices, p.pushNotice)
	}
	return rev
}

// runPinPlan is the key pin a deploy plan decided over the scopes it mints
// (A23-48, A28-10): the pin as the plan read it, and the decision, whose pin
// names each new key by its placeholder id. writes is false when the plan
// writes none; behind holds why, when this keyring is behind the pin, which
// the plan says and --confirm warns of as an interactive run does. ids, set
// by --confirm once the scopes are minted, maps each new key's real id to
// its placeholder.
type runPinPlan struct {
	cur     dskeyholder.Pin
	present bool
	invalid error
	dec     pinDecision
	writes  bool
	behind  *pinBehind
	ids     map[datasphere.KeyID]datasphere.KeyID
}

// write writes the planned pin once (A28-10): decided again over keys, the
// keyring the scopes were minted into, from the pin as the plan read it, it
// must be the plan's pin once each new key's id is mapped back to its
// placeholder, and it is written at the resourceVersion the plan read, with
// no retry and no union (writePinOnce). Otherwise, or on a conflict, the pin
// changed since the plan was made: plan_changed, with nothing written over
// it. Run never waits on the clock before it mints (A28-10): it mints only
// fresh scopes and retires no key, so no key's time is in the pin.
func (pp runPinPlan) write(ctx context.Context, ps pinStore, keys datasphere.Keyring) (pinWrite, error) {
	if pp.behind != nil {
		return pinWrite{}, pp.behind
	}
	if !pp.writes {
		return pinWrite{Pin: pp.dec.pin}, nil
	}
	dec, err := decidePin(pp.cur, pp.present, pp.dec.rv, pp.invalid, kekLists(keys), false, false)
	if err != nil || !mappedBack(dec.pin, pp.ids).Equal(pp.dec.pin) {
		return pinWrite{}, withKind(kindPlanChanged, errors.New(msgPinChanged))
	}
	return writePinOnce(ctx, ps, dec.pin, pp.dec.rv)
}

// deployPlan is run's deploy plan, stage deploy (design §9.4, §5.4, A23-47,
// A28-1, A28-8): what the manifest read reports, deployed. rd is what it
// reads the cluster through — the reader under --confirm, its errors the
// reader's (planRead), and in an interactive or --yes run the writer — and m
// the run's answer. writerUID is the uid of farcast-system the writer's
// preflight read, which an interactive or --yes run binds rather than read
// it again; under --confirm it is read through rd.
//
// Its blocks (A23-18), each ending the computation with nothing more read: a
// manifest that does not parse; one whose name is no namespace run deploys
// into, or one this machine recorded under another repository; no CA key on
// this machine while storage is wired (A28-9), in every mode; and, under
// --plan and --confirm only, a target namespace that exists and is not
// metered, which the reader could not read (P3), and a key pin decidePin
// refuses. Then it reads the kernel's ledger, the namespaces, each
// application's Deployment and the namespace's other workloads where the
// namespace exists (and nothing in one that does not), the egress policy at
// its resourceVersion, and, under --plan and --confirm, the key pin when the
// deploy mints a scope. It reads keys.yaml's ids and times and the CA
// certificate, never a key (A23-25), and mints nothing: every secret it
// renders is a placeholder (A23-30).
//
// Past every block, it reads the builder's ServiceAccount's uid through rd,
// and the push grant as the installer key, in every mode (design §33,
// A33-22): the project number and the repository's IAM policy. A blocked
// plan reads neither.
//
// Its facts are the fetch plan's fetch fact, never its writes (A23-47); the
// run; the cost; the builder image; the push grant; what it would mint;
// every document it would write, in the order it writes them; the key pin;
// what it resets of what runs now; and its notices, the push grant's last.
func (c *runCommand) deployPlan(ctx context.Context, env *Env, meta *config.InstanceMetadata, pf preparedFetch, read fetched,
	rd runPlanReader, m consentMode, writerUID string) (preparedDeploy, plan.Bound, error) {
	name := meta.Name
	p := preparedDeploy{repo: pf.cfg.Repo, read: read, fetcher: pf.cfg.Fetcher, builder: pf.builder}
	uid := writerUID
	if m != consentNone {
		var err error
		if uid, err = rd.NamespaceUID(ctx, tcdeploy.DefaultNamespace); err != nil {
			return p, plan.Bound{}, planRead(m, fmt.Errorf("read the uid of the instance's %s namespace: %w", tcdeploy.DefaultNamespace, err), name)
		}
	}
	b := newBound("run", meta, "reader", uid)
	b.Stage, b.Options = "deploy", c.options()
	blocked := func(err error) (preparedDeploy, plan.Bound, error) {
		p.blocked = err
		b.Blocked = []plan.Block{blockOf(err)}
		return p, b, nil
	}

	parsed, err := parser.Parse(read.Manifest)
	if err != nil {
		return blocked(fmt.Errorf("the manifest at %s in %s is not valid: %w", read.Report.Commit, p.repo, err))
	}
	p.m = *parsed
	p.namespace = c.namespace
	if p.namespace == "" {
		p.namespace = p.m.Name
		// Known only now. The read has run and billed; nothing has been
		// built or deployed, and nothing will be if this refuses. A manifest
		// is held to the same namespace rules as --namespace: one named
		// farcast-system, or kube-anything, would otherwise put applications
		// beside the instance's own components or into the managed ones.
		if err := deployableNamespace(p.namespace); err != nil {
			return blocked(fmt.Errorf("the manifest's name: %w; %s", err, msgNothingDeployed))
		}
		if err := c.refuseOtherRepository(meta, name, p.namespace, p.repo, true); err != nil {
			return blocked(err)
		}
	}
	ns := p.namespace
	p.storageWired = wiresStorage(meta)
	// A machine without the CA key cannot give an application a storage
	// identity. Found after the builds, they would have billed for nothing
	// (A23-51 item 5): it is refused now, with only the read spent. A key
	// that cannot be checked is an error met while computing, never the
	// block (A23-18).
	if noKey, err := refuseNoCAKey(env.ConfigDir, meta); err != nil {
		return p, plan.Bound{}, err
	} else if noKey != nil {
		return blocked(noKey)
	}

	// What this deploy resets of what runs now, and whether the instance's
	// spending is at its limit (ADR 0023 Choices 6, P1; A28-1).
	p.live.Limit = readLimit(ctx, rd, c.now())
	if p.live.NamespaceExists, err = namespaceExists(ctx, rd, ns, m, name); err != nil {
		return p, plan.Bound{}, err
	}
	if p.live.NamespaceExists && m != consentNone && !meteredNamespace(meta, ns) {
		return blocked(withKind(kindForbidden, fmt.Errorf(msgUnmeteredNamespace, ns, name, ns)))
	}
	if p.live.Apps, err = liveApps(ctx, rd, ns, p.m, p.live.Limit, p.live.NamespaceExists, m, name); err != nil {
		return p, plan.Bound{}, err
	}
	others, err := otherWorkloads(ctx, rd, ns, p.m, p.live.NamespaceExists, m, name)
	if err != nil {
		return p, plan.Bound{}, err
	}

	// The egress policy, merged, each application's credential a
	// placeholder, rendered at the resourceVersion it was read at, which its
	// document carries and its write binds (A30-40).
	existing, rv, err := readEgressPolicyAt(ctx, rd)
	if err != nil {
		return p, plan.Bound{}, planRead(m, err, name)
	}
	p.policyRV = rv
	doc, credentials, err := egressPolicy(existing, ns, p.m, placeholderCredential)
	if err != nil {
		return p, plan.Bound{}, err
	}
	policyStream, err := fldeploy.RenderPolicyConfigMap(fldeploy.DefaultNamespace, doc, rv)
	if err != nil {
		return p, plan.Bound{}, err
	}
	policyWrites, err := applyFactsAt(policyStream, rv)
	if err != nil {
		return p, plan.Bound{}, err
	}

	// The builds, and each application's image by a placeholder digest.
	if p.builds, err = c.planBuilds(meta, p.builder, p.repo, read.Report.Commit, p.m); err != nil {
		return p, plan.Bound{}, err
	}
	images := make(map[string]string, len(p.builds))
	var buildWrites []plan.Fact
	for _, bld := range p.builds {
		images[bld.app] = buildPlaceholder(untagged(bld.destination), ns+"/"+bld.app)
		writes, err := applyFacts(bld.manifest)
		if err != nil {
			return p, plan.Bound{}, err
		}
		buildWrites = append(buildWrites, writes...)
	}

	// Storage: each application's scope, the new ones named and never
	// minted, the CA certificate and placeholder leaves; and, under --plan
	// and --confirm, the pin the new scopes raise (A28-10).
	var scopes map[string]datasphere.Scope
	var caCertPEM []byte
	var issue appLeafIssuer
	var pinWrites []plan.Fact
	if p.storageWired {
		keys, _, err := appScopesKeyring(env, name)
		if err != nil {
			return p, plan.Bound{}, err
		}
		lists := kekLists(keys)
		scopes = make(map[string]datasphere.Scope, len(p.m.Apps))
		for _, app := range p.m.Apps {
			scope, err := datasphere.AppScopeName(ns, app.Name)
			if err != nil {
				return p, plan.Bound{}, err
			}
			scopes[app.Name] = datasphere.Scope{Name: scope}
			if _, ok := keys.ScopeNamed(scope); ok {
				continue
			}
			p.newScopes = append(p.newScopes, app.Name)
			lists = append(lists, scopeKEKs{Name: scope, KEKs: []datasphere.KeyEntry{placeholderEntry(scope, 1, nil)}})
		}
		if caCertPEM, err = env.ConfigDir.LoadInstanceCACert(name); err != nil {
			return p, plan.Bound{}, fmt.Errorf("read the instance CA so applications can verify the key holder: %w", err)
		}
		issue = placeholderAppLeaf
		// An interactive or --yes run reads no pin here: it raises it with
		// its loop, as it always has (A28-8).
		if m != consentNone && len(p.newScopes) > 0 {
			cur, present, pinRV, invalid, err := readPin(ctx, rd)
			if err != nil {
				return p, plan.Bound{}, planRead(m, err, name)
			}
			p.pin = runPinPlan{cur: cur, present: present, invalid: invalid}
			dec, err := decidePin(cur, present, pinRV, invalid, lists, false, false)
			var behind *pinBehind
			switch {
			case errors.As(err, &behind):
				// No pin is written. The new scopes are still handed to
				// the replicas that serve, which refuse them only if one
				// of them has loaded the pin; replicas started before it
				// moved take them (design §9.4's run-deploy row).
				p.pin.behind = behind
				pinWrites = []plan.Fact{noticeFact(msgRunHandOver), noticeFact(behindWarning(behind))}
			case err != nil:
				return blocked(err)
			default:
				p.pin.dec, p.pin.writes = dec, dec.writes()
				if pinWrites, err = pinFacts(dec, nil); err != nil {
					return p, plan.Bound{}, err
				}
				pinWrites = append(pinWrites, noticeFact(msgRunHandOver))
			}
		}
	}
	workloads, err := c.translate(meta, ns, p.m, images, credentials, scopes, caCertPEM, issue)
	if err != nil {
		return p, plan.Bound{}, err
	}
	workloadWrites, err := applyFacts(workloads)
	if err != nil {
		return p, plan.Bound{}, err
	}

	// Metering, when the namespace is new to the kernel.
	var meterWrites []plan.Fact
	var metered []string
	if meta.Kernel != nil {
		metered = meta.Kernel.Namespaces
	}
	next, added := applyMeterChange(metered, []string{ns}, false)
	if len(added) > 0 {
		p.reader, p.readerWarning = meteredReaderNote(env, name, meta)
		stream, err := meterManifest(next, added, p.reader)
		if err != nil {
			return p, plan.Bound{}, err
		}
		if meterWrites, err = applyFacts(stream); err != nil {
			return p, plan.Bound{}, err
		}
	}

	if line := noWayOutWarning(name, p.m, meta.FatLineDeployed); line != "" {
		p.notices = append(p.notices, line)
	}
	if p.readerWarning != "" {
		p.notices = append(p.notices, p.readerWarning)
	}

	// The push grant, after every block (A33-22): the builder's uid, then
	// the installer key's reads.
	builderUID, err := readServiceAccountUID(ctx, rd, m, name, tcdeploy.DefaultNamespace, pbuild.ServiceAccount, plan.GrantPush)
	if err != nil {
		return p, plan.Bound{}, err
	}
	var grant plan.GrantFact
	if p.push, grant, err = readPushGrant(ctx, env, meta, c.openProvider, builderUID); err != nil {
		return p, plan.Bound{}, err
	}
	if p.pushNotice, err = p.push.notice(); err != nil {
		return p, plan.Bound{}, err
	}
	if p.pushNotice != "" {
		p.notices = append(p.notices, p.pushNotice)
	}

	facts := []plan.Fact{pf.fact, plan.RunFact{
		Type: plan.TypeRun, JobUID: read.UID, FetchPlanDigest: pf.digest,
		Commit: read.Report.Commit, ManifestDigest: read.Report.ManifestDigest,
		Namespace: ns, ReplacesRepository: c.replacedRepository(meta, ns, p.repo),
		Apps: runApps(p.m), OtherDeploymentsKept: others, MeteringAdded: len(added) > 0,
		LimitReached: p.live.Limit.Reached, LimitReason: p.live.Limit.Reason,
	}, deployCost(meta, p.m), toolchainImageFact(meta, builderKind, p.builder, pf.builderSource), grant}
	if p.storageWired {
		for _, app := range p.m.Apps {
			facts = append(facts, plan.MintFact{Type: plan.TypeMint, What: plan.MintAppLeaf, Subject: ns + "/" + app.Name})
		}
	}
	for _, app := range p.m.Apps {
		facts = append(facts, plan.MintFact{Type: plan.TypeMint, What: plan.MintEgressCredential, Subject: ns + "/" + app.Name})
	}
	for _, app := range p.newScopes {
		scope := scopes[app].Name
		facts = append(facts, plan.MintFact{Type: plan.TypeMint, What: plan.MintAppScope, Subject: scope},
			plan.MintFact{Type: plan.TypeMint, What: plan.MintKey, Subject: scope})
	}
	facts = append(facts, buildWrites...)
	facts = append(facts, policyWrites...)
	facts = append(facts, workloadWrites...)
	facts = append(facts, meterWrites...)
	facts = append(facts, pinWrites...)
	for _, a := range p.live.Apps {
		if f, ok := a.resetFact(p.live.Limit); ok {
			facts = append(facts, f)
		}
	}
	for _, line := range p.notices {
		facts = append(facts, noticeFact(line))
	}
	b.Facts = facts
	return p, b, nil
}

// planBuilds renders each application's build, pinned to the commit that
// was read: the commit, never the branch, is what makes the tree that was
// approved the tree that is built (ADR 0010 decision 11).
func (c *runCommand) planBuilds(meta *config.InstanceMetadata, builder, repo, commit string, m parser.Manifest) ([]appBuild, error) {
	builds := make([]appBuild, 0, len(m.Apps))
	for _, app := range m.Apps {
		destination := fmt.Sprintf("%s/app/%s/%s:%s", meta.Registry.Prefix, m.Name, app.Name, imageTag(shortCommit(commit)))
		manifest, err := pbuild.Render(pbuild.Config{
			Instance:       meta.Name,
			Deployment:     m.Name,
			App:            app.Name,
			Builder:        builder,
			Repo:           repo,
			Ref:            commit,
			Containerfile:  app.Containerfile,
			ContextSubPath: app.Context,
			Destination:    destination,
			GitSecret:      c.gitSecret,
			EgressHosts:    []string{hostOf(repo), hostOf(meta.Registry.Prefix)},
		})
		if err != nil {
			return nil, err
		}
		builds = append(builds, appBuild{app: app.Name, destination: destination, job: pbuild.JobName(m.Name, app.Name), manifest: manifest})
	}
	return builds, nil
}

// deployCost is the deploy plan's cost fact (A23-33): each application,
// standing, at the replicas and requests translate renders; the builds, one
// at a time, as one-off Jobs; against the instance's limit, with the floor
// as the review states it, the instance as it stands with these
// applications in it.
func deployCost(meta *config.InstanceMetadata, m parser.Manifest) plan.CostFact {
	f := floorCost(meta, withApplications(floorNow(meta), len(m.Apps)))
	month := cents(pricing.WorkloadMonthlyUSD(appReplicas, translate.RequestCPUMilli, translate.RequestMemMiB))
	for _, app := range m.Apps {
		f.Standing = append(f.Standing, plan.StandingCost{
			What: app.Name, Replicas: appReplicas, CPUMilli: translate.RequestCPUMilli, MemMiB: translate.RequestMemMiB, MonthCents: month,
		})
	}
	f.OneOff = []plan.OneOffCost{{
		What: costWhatBuilds, Jobs: len(m.Apps), CPUMilli: pbuild.RequestCPUMilli, MemMiB: pbuild.RequestMemMiB, DeadlineS: pbuild.DeadlineSeconds,
	}}
	return f
}

// runApps is the manifest's applications as the run fact binds them, in
// manifest order, each with the hosts it declares.
func runApps(m parser.Manifest) []plan.RunApp {
	apps := make([]plan.RunApp, 0, len(m.Apps))
	for _, a := range m.Apps {
		hosts := make([]plan.RunHost, 0, len(a.External))
		for _, e := range a.External {
			hosts = append(hosts, plan.RunHost{Host: e.Host, Reason: e.Reason})
		}
		apps = append(apps, plan.RunApp{Name: a.Name, Containerfile: a.Containerfile, Context: a.Context, External: hosts})
	}
	return apps
}

// replacedRepository is the repository this machine recorded namespace ns
// under that a run of repo replaces, which only --replace-repository lets
// it (refuseOtherRepository), or "" when it replaces none.
func (c *runCommand) replacedRepository(meta *config.InstanceMetadata, ns, repo string) string {
	dep, ok := meta.Deployments[ns]
	if !ok || !c.replaceRepository || normalisedRepository(dep.Repository) == normalisedRepository(repo) {
		return ""
	}
	return withoutUserinfo(dep.Repository)
}

// meteredNamespace reports whether the kernel meters ns, as this machine
// records it: where the reader is bound (P3).
func meteredNamespace(meta *config.InstanceMetadata, ns string) bool {
	return meta.Kernel != nil && slices.Contains(meta.Kernel.Namespaces, ns)
}

// otherWorkloads is the target namespace's workloads that the manifest does
// not deploy, which a run keeps (the run fact's other_deployments_kept): its
// Deployments that are none of the manifest's applications, and its
// StatefulSets, each as <kind>/<name>, sorted. In a namespace that does not
// exist it reads nothing, and there are none (§5.4). A failed list is an
// error, never "none" (A28-6).
func otherWorkloads(ctx context.Context, rd lister, ns string, m parser.Manifest, exists bool, mode consentMode, name string) ([]string, error) {
	out := []string{}
	if !exists {
		return out, nil
	}
	listed, err := rd.Workloads(ctx, ns)
	if err != nil {
		return nil, planRead(mode, fmt.Errorf("list the workloads in %q: %w", ns, err), name)
	}
	declared := make(map[string]bool, len(m.Apps))
	for _, a := range m.Apps {
		declared[a.Name] = true
	}
	for _, w := range listed {
		if w.Kind == "Deployment" && declared[w.Name] {
			continue
		}
		out = append(out, strings.ToLower(w.Kind)+"/"+w.Name)
	}
	slices.Sort(out)
	return out, nil
}

// placeholderCredential is the egress credential a plan renders for
// namespace/app (A23-30): a plan mints none.
func placeholderCredential(namespace, app string) (string, error) {
	return "farcast-placeholder:egress_credential:" + namespace + "/" + app, nil
}

// placeholderAppLeaf is the storage identity a plan renders for
// namespace/app (A23-30): a plan issues no leaf and opens no CA key.
func placeholderAppLeaf(namespace, app string) ([]byte, []byte, error) {
	leaf := "farcast-placeholder:app_leaf:" + namespace + "/" + app
	return []byte(leaf + ":cert"), []byte(leaf + ":key"), nil
}

// The --confirm re-read's refusals (A23-48, A28-1, A28-10), and the egress
// policy's 409 in every mode (A30-40): what changed while the builds ran,
// and that the builds alone were written.
const (
	msgAppsChanged          = "%s changed since the plan was made (the kernel stopped or resized it); " + msgBuildsWrittenClause
	msgLimitReachedSince    = "the instance's spending reached its limit, or its kernel's ledger became unreadable or stale, since the plan was made; " + msgBuildsWrittenClause
	msgPinChangedSince      = "the instance's key pin changed since the plan was made; " + msgBuildsWrittenClause
	msgPolicyChangedSince   = "the instance's egress policy changed since the plan was made; " + msgBuildsWrittenClause
	msgBuildsWrittenClause  = "the builds were written, and nothing after them was"
	msgScopesChangedSince   = "the storage scopes this deploy would mint (%s) are not the ones its plan listed (%s): keys.yaml changed since the plan was made; nothing was minted; " + msgPolicyWrittenOnly
	msgPinChangedAtHandOver = "the instance's key pin changed since the plan was made; nothing was written over it; " +
		"the builds, the egress policy and the new storage scopes (saved in keys.yaml, not handed to the keyholder) were written, and the workloads were not: " + msgCredentialsStranded
	msgPolicyWrittenOnly   = "the builds and the egress policy were written, and the workloads were not: " + msgCredentialsStranded
	msgCredentialsStranded = "until a run succeeds, this namespace's running applications hold egress credentials the new policy does not list"
)

// deploy executes the deploy plan p (design §9.4): it builds, reads the
// ledger and the applications again, writes the egress policy, mints and
// hands over the storage scopes, applies the workloads and meters them, from
// p's decisions alone. cl is the writer. Under --confirm (m) every write
// after the builds is checked against the plan first (§9.5, A23-48, A28-10),
// and in every mode the egress policy is written at the resourceVersion read
// just before it (A30-40).
func (c *runCommand) deploy(ctx context.Context, env *Env, meta *config.InstanceMetadata, cl runCluster, p preparedDeploy, m consentMode) error {
	name, namespace := meta.Name, p.namespace

	// 3. Build each application, pinned to the commit that was approved.
	images, err := c.buildAll(ctx, env, cl, meta, p.builds, p.push)
	if err != nil {
		return err
	}

	// The builds take minutes, and the kernel acts between its ticks, so
	// the ledger and the applications are read again before anything else
	// is written (A23-2): the gate applies again to what is true now, and
	// under --confirm what the plan said must still be so.
	if m == consentConfirm {
		if err := c.recheckPlanned(ctx, env, cl, meta, p); err != nil {
			return err
		}
	} else if ok, err := c.recheck(ctx, env, cl, p.review(meta)); err != nil || !ok {
		if err == nil {
			fprintln(env.Err, "Aborted. "+msgBuildsWritten)
		}
		return err
	}

	// 4. Mint this deployment's egress credentials and write the instance's
	//    policy, merged with every other deployment's (ADR 0013). The read
	//    comes first, then, under --confirm, its comparison with the plan's,
	//    and the mint after both (A28-10); the write is at the read's
	//    resourceVersion (A30-40).
	existing, rv, err := readEgressPolicyAt(ctx, cl)
	if err != nil {
		return err
	}
	if m == consentConfirm && rv != p.policyRV {
		return changedAfterPlan(m, msgPolicyChangedSince)
	}
	doc, credentials, err := egressPolicy(existing, namespace, p.m, c.mintCredential)
	if err != nil {
		return err
	}
	policyManifest, err := fldeploy.RenderPolicyConfigMap(fldeploy.DefaultNamespace, doc, rv)
	if err != nil {
		return err
	}
	// Before the workloads, so FatLine has the chance to learn an application
	// before that application starts asking. It polls, so the window is not
	// zero — but an application that starts first is denied for a few seconds,
	// where one whose policy never arrives is denied forever.
	//
	// The policy carries the resourceVersion just read, and the API server
	// holds the apply to it (A30-40, A31-2): a policy another run wrote since
	// that read is a 409 and is not written over. In every mode that is what
	// this deploy relied on changing after it was decided, with one attempt
	// and no merge again: a retry would merge with credentials this run
	// already minted, for a race only two concurrent runs meet. A policy that
	// was absent carries no resourceVersion, since server-side apply cannot
	// say "create only", and one deleted after the read is recreated from
	// this merge: the precondition sees neither.
	if err := cl.ApplyAt(ctx, policyManifest, rv); err != nil {
		if errors.Is(err, tkube.ErrConflict) {
			return changedAfterPlan(m, msgPolicyChangedSince)
		}
		return fmt.Errorf("write the egress policy: %w", err)
	}

	// 5. Give every application its own slice of storage, translate, and
	//    apply.
	//
	// The scopes are minted and handed to the keyholder BEFORE the workloads
	// exist, so an application does not start into a keyholder that has never
	// heard of it. The reverse order would work eventually — the keyholder
	// would learn the scope at the next unseal — and "eventually" is an
	// outage an operator has to notice first.
	var scopes map[string]datasphere.Scope
	var minted []string
	var ids map[datasphere.KeyID]datasphere.KeyID
	var caCertPEM []byte
	var issue appLeafIssuer
	if p.storageWired {
		if scopes, minted, ids, err = c.ensureAppScopes(env, name, namespace, p.m, m, p.newScopes); err != nil {
			return err
		}
		if caCertPEM, issue, err = issueAppLeaves(env.ConfigDir, meta); err != nil {
			return err
		}
	}
	workloads, err := c.translate(meta, namespace, p.m, images, credentials, scopes, caCertPEM, issue)
	if err != nil {
		return err
	}
	if len(minted) > 0 {
		var planned *runPinPlan
		if m == consentConfirm {
			pp := p.pin
			pp.ids = ids
			planned = &pp
		}
		if err := c.handScopesToTheKeyholder(ctx, env, meta, minted, cl, planned); err != nil {
			return err
		}
	}
	if err := cl.Apply(ctx, workloads); err != nil {
		return fmt.Errorf("deploy %q: %w", namespace, err)
	}

	// 6. Meter it. An application the kernel does not count is an application
	// the cost limit does not protect against — and the limit is the pillar,
	// not the feature.
	metered, readerBound, meterErr := c.meter(ctx, env, cl, meta, name, namespace, p.reader)

	// Recorded before the wait: the workloads exist whether or not they come
	// up, and an instance whose local state has not heard of them is one
	// nobody will think to tear down.
	c.record(env, meta, name, p.fetcher, p.builder)
	c.recordProvenance(env, name, namespace, p.repo, p.read.Report, p.storageWired)

	var slow []string
	for _, app := range p.m.Apps {
		if err := cl.RolloutStatus(ctx, namespace, app.Name, rolloutTimeout); err != nil {
			slow = append(slow, app.Name)
			fprintf(env.Err, "%s did not roll out: %s\n", app.Name, terminalText(err.Error()))
		}
	}

	return env.Printer.Print(runResult{
		Instance: name, Repo: p.repo, Namespace: namespace,
		Deployment: p.m.Name, Commit: p.read.Report.Commit,
		ManifestDigest: p.read.Report.ManifestDigest,
		Apps:           appResults(p.m, images, doc, namespace),
		Egress:         summarise(doc, namespace),
		Metered:        metered, MeterError: errString(meterErr),
		NotReady: slow,
		Reader:   readerBound, ReaderBindings: readerBindingsFor(readerBound, []string{namespace}),
	})
}

// recheckPlanned is --confirm's re-read, after the builds and before the
// egress policy (A23-2, A23-48, A28-1, A28-10): as the writer, each
// application must be as the plan read it, a failed read counting as a
// change and an application the plan could not read satisfied by one that
// shows no reset; the ledger may not read the limit reached unless the plan
// said it did; and the key pin, when the plan writes it, must be at the
// resourceVersion the plan read. Otherwise it refuses, plan_changed, with
// only the builds written.
func (c *runCommand) recheckPlanned(ctx context.Context, env *Env, cl runCluster, meta *config.InstanceMetadata, p preparedDeploy) error {
	now, err := readLive(ctx, cl, p.namespace, p.m, c.now(), consentNone, meta.Name)
	if err != nil {
		return fmt.Errorf("%w; %s", err, msgBuildsWrittenClause)
	}
	var changed []string
	for i, planned := range p.live.Apps {
		if !planned.unchangedAt(now.Apps[i]) {
			changed = append(changed, terminalText(tenantOf(planned.Namespace, planned.App)))
		}
	}
	if len(changed) > 0 {
		return changedAfterPlan(consentConfirm, fmt.Sprintf(msgAppsChanged, strings.Join(changed, ", ")))
	}
	if now.Limit.Reached && !p.live.Limit.Reached {
		return changedAfterPlan(consentConfirm, msgLimitReachedSince)
	}
	if !p.pin.writes {
		return nil
	}
	ps, err := pinStoreFor(c.newPinStore, clusterRef{Dir: env.ConfigDir, Meta: meta, Identity: kube.Writer, Warn: env.Err}, cl)
	if err != nil {
		return fmt.Errorf("the key pin could not be reached: %w; %s", err, msgBuildsWrittenClause)
	}
	if err := checkPlannedPin(ctx, ps, p.pin.dec); err != nil {
		if kindOf(err) == kindPlanChanged {
			return changedAfterPlan(consentConfirm, msgPinChangedSince)
		}
		return fmt.Errorf("%w; %s", err, msgBuildsWrittenClause)
	}
	return nil
}

// buildAll builds every application in the manifest, one at a time, from
// the streams its plan rendered.
//
// One at a time on purpose. A build asks for 1 vCPU and 2 GiB and Autopilot
// bills the request, so three in parallel is three times the burn for the
// length of the slowest — and a manifest with a dozen applications would open
// a hole in the cost limit large enough to matter.
//
// push is the builder's push grant as the plan read it: when the plan bound
// the uid placeholder, the commands that grant it print once, after the
// first build's apply, from when the account exists (A33-22), and a refused
// push names them.
func (c *runCommand) buildAll(ctx context.Context, env *Env, cl jobWaiter, meta *config.InstanceMetadata, builds []appBuild, push pushGrant) (map[string]string, error) {
	images := make(map[string]string, len(builds))
	builderUID := push.uid
	for i, b := range builds {
		if isInteractive(env) || env.Verbose {
			fprintf(env.Err, "\n[%d/%d] Building %s inside %q…\n", i+1, len(builds), b.app, meta.Name)
		}
		if err := cl.Apply(ctx, b.manifest); err != nil {
			return nil, fmt.Errorf("start the build of %s: %w", b.app, err)
		}
		if i == 0 {
			builderUID = pushGrantNow(ctx, env, cl, push)
		}
		res, err := cl.WaitJob(ctx, pbuild.Namespace, b.job, buildTimeout)
		if err != nil {
			return nil, fmt.Errorf("wait for the build of %s: %w", b.app, err)
		}
		if !res.Succeeded {
			var logs string
			if l, lerr := cl.JobLogs(ctx, pbuild.Namespace, b.job, 40); lerr == nil && strings.TrimSpace(l) != "" {
				logs = l
				fprintf(env.Err, "\n%s\n", strings.TrimRight(l, "\n"))
			}
			// `run` never said this at all. The 4.3 runbook recorded that it
			// "prints it, like build does" — build printed it only on SUCCESS,
			// and run printed it nowhere. The 5.1b walk spent four attempts and
			// a mirrored toolchain finding that out.
			explainPushDenial(env.Err, logs, push.fact.State, func() string { return grantText(ctx, cl, push.denied(), &builderUID) })
			return nil, fmt.Errorf(msgRunBuildFailed, b.app)
		}
		digest := strings.TrimSpace(res.Message)
		if !isSHA256(digest) {
			return nil, fmt.Errorf("the build of %s reported %q instead of a sha256 digest; the image may have been "+
				"pushed but cannot be pinned, and an unpinned image is not deployable (ADR 0007 decision 4)",
				b.app, digest)
		}
		images[b.app] = pinByDigest(b.destination, digest)
	}
	return images, nil
}

// translate renders the workloads, wiring storage when the instance has a key
// holder to wire it to: each application verifies the keyholder against
// caCertPEM, and presents the leaf issue gives it (ADR 0018 decision 1). A
// run that deploys issues real leaves (issueAppLeaves); a plan renders
// placeholders, and opens no key (A23-25, A23-30).
func (c *runCommand) translate(meta *config.InstanceMetadata, namespace string, m parser.Manifest, images, credentials map[string]string,
	scopes map[string]datasphere.Scope, caCertPEM []byte, issue appLeafIssuer) ([]byte, error) {
	cfg := translate.Config{
		Manifest:    m,
		Namespace:   namespace,
		Images:      images,
		Instance:    meta.Name,
		Credentials: credentials,
	}
	if wiresStorage(meta) {
		cfg.StorageCAPEM = caCertPEM
		cfg.StorageServerName = identity.KeyholderServerName(meta.Name)
		if len(scopes) == 0 {
			return nil, fmt.Errorf("no storage scopes were resolved for %q; this is a bug in the deploy order", namespace)
		}
		if issue == nil {
			return nil, fmt.Errorf("no storage identities can be issued for %q; this is a bug in the deploy order", namespace)
		}
		cfg.Storage = make(map[string]translate.AppStorage, len(m.Apps))
		for _, app := range m.Apps {
			certPEM, keyPEM, err := issue(namespace, app.Name)
			if err != nil {
				return nil, fmt.Errorf("issue a storage identity for %s: %w", app.Name, err)
			}
			cfg.Storage[app.Name] = translate.AppStorage{
				CertPEM: certPEM, KeyPEM: keyPEM,
				Scope:         scopes[app.Name].Name,
				SecretsPrefix: datasphere.AppSecretsPrefix(namespace, app.Name),
			}
		}
	}
	return translate.Render(cfg)
}

// wiresStorage is whether a run wires its applications to storage: whether
// the instance's keyholder is deployed.
func wiresStorage(meta *config.InstanceMetadata) bool {
	return meta.Keyholder != nil && meta.Keyholder.Deployed
}

// appLeafIssuer gives namespace/app its leaf for the keyholder's data path:
// the certificate and its key, PEM.
type appLeafIssuer func(namespace, app string) (certPEM, keyPEM []byte, err error)

// issueAppLeaves is what a run that deploys wires storage with: the instance
// CA's certificate, and an issuer of real leaves under it, minted here
// because this is the machine that holds the CA key (ADR 0018 decision 1).
// It loads the instance's mTLS material, ca.key among it, so a plan never
// calls it (A23-25).
func issueAppLeaves(dir config.Dir, meta *config.InstanceMetadata) ([]byte, appLeafIssuer, error) {
	mtls, err := dir.LoadInstanceMTLS(meta.Name)
	if err != nil {
		return nil, nil, fmt.Errorf("read the instance CA so applications can verify the key holder: %w", err)
	}
	// refuseNoCAKey said so before the builds; a key emptied since is
	// refused in the same words.
	if len(mtls.CAKeyPEM) == 0 {
		return nil, nil, noCAKey(meta.Name)
	}
	return mtls.CACertPEM, func(namespace, app string) ([]byte, []byte, error) {
		return identity.IssueAppClient(mtls.CACertPEM, mtls.CAKeyPEM, meta.Name, namespace, app)
	}, nil
}

// refuseNoCAKey refuses a run that wires storage from a machine that holds
// no CA key for the instance (A23-47, A28-9): it could give no application
// a storage identity, and a machine without it cannot deploy an application
// that uses storage, so it says so rather than deploying one that reaches
// nothing. It is checked before anything is built (A23-51 item 5). It stats
// ca.key and never opens it (InstanceCAKeyExists), so a plan may check it
// too. Another mTLS file that is missing still fails when the leaves are
// issued, after the builds.
//
// noKey is that refusal, a deploy plan's block; err is a key that could not
// be checked — a stat that failed other than for a missing file — which a
// plan returns as an error and never as the block (A23-18), as fetchRefusal
// splits its own two.
func refuseNoCAKey(dir config.Dir, meta *config.InstanceMetadata) (noKey, err error) {
	if !wiresStorage(meta) {
		return nil, nil
	}
	ok, err := dir.InstanceCAKeyExists(meta.Name)
	if err != nil {
		return nil, fmt.Errorf("check for this machine's CA key for %q: %w", meta.Name, err)
	}
	if !ok {
		return noCAKey(meta.Name), nil
	}
	return nil, nil
}

// noCAKey is the refusal of a storage deploy from a machine that holds no CA
// key for instance.
func noCAKey(instance string) error {
	return fmt.Errorf("this machine holds no CA key for %q, so it cannot give applications a storage identity; "+
		"deploy from the machine that installed the instance", instance)
}

// ensureAppScopes gives every application in this deployment its own slice of
// the instance's storage, minting what is not there yet.
//
// One scope per application is what makes the separation between them
// cryptographic rather than a rule the keyholder enforces: an application's
// keys cannot compute the stored name of a neighbour's object, let alone open
// it (ADR 0018 decision 5).
//
// The scope is keyed on NAMESPACE and application, which is what the
// application's own leaf names, so the two agree by construction. That has a
// consequence worth knowing before it is discovered: the same manifest
// deployed under a second namespace is a second set of applications with a
// second set of scopes, and it does not see the first's data. Redeploying the
// same manifest to the same namespace reuses the scope already minted.
//
// Minting is idempotent and additive. The keyring is written before anything
// is deployed, because a scope recorded nowhere is key material whose data
// nobody can find again.
//
// It also returns, for each scope it minted, its key-encryption key's real
// id and the placeholder id a plan lists that key as (placeholderKeyID, the
// scope's first; A23-32): a pin --confirm would write is compared with its
// plan's over them (mappedBack).
//
// Under --confirm (mode) the applications whose scopes it would mint must be
// planned, the ones the plan listed: otherwise keys.yaml changed since the
// plan was made, and it refuses, plan_changed, before it saves anything
// (A28-10).
func (c *runCommand) ensureAppScopes(env *Env, instance, namespace string, m parser.Manifest, mode consentMode, planned []string) (map[string]datasphere.Scope, []string, map[datasphere.KeyID]datasphere.KeyID, error) {
	keys, raw, err := appScopesKeyring(env, instance)
	if err != nil {
		return nil, nil, nil, err
	}

	out := make(map[string]datasphere.Scope, len(m.Apps))
	minted := make([]string, 0, len(m.Apps))
	ids := map[datasphere.KeyID]datasphere.KeyID{}
	for _, app := range m.Apps {
		name, err := datasphere.AppScopeName(namespace, app.Name)
		if err != nil {
			return nil, nil, nil, err
		}
		if existing, ok := keys.ScopeNamed(name); ok {
			out[app.Name] = existing
			continue
		}
		fresh, err := datasphere.NewAppScope(namespace, app.Name)
		if err != nil {
			return nil, nil, nil, err
		}
		grown, err := keys.AddScope(fresh)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("mint a storage scope for %s: %w", app.Name, err)
		}
		keys = grown
		out[app.Name] = fresh
		minted = append(minted, app.Name)
		// A fresh scope holds one key-encryption key: the first a plan
		// lists for the scope.
		if keks := fresh.Keyring().KEKs(); len(keks) > 0 {
			ids[keks[0].ID] = placeholderKeyID(name, 1)
		}
	}
	if mode == consentConfirm && !slices.Equal(minted, planned) {
		return nil, nil, nil, changedAfterPlan(mode, fmt.Sprintf(msgScopesChangedSince, tenantList(namespace, minted), tenantList(namespace, planned)))
	}
	if len(minted) == 0 {
		return out, nil, ids, nil
	}

	encoded, err := keys.Marshal()
	if err != nil {
		return nil, nil, nil, err
	}
	if err := env.ConfigDir.SaveInstanceKeyring(instance, raw, encoded); err != nil {
		if errors.Is(err, config.ErrKeyringChanged) {
			return nil, nil, nil, fmt.Errorf("record the new storage scopes: %w — another farcast command wrote it meanwhile; nothing was deployed, so run this again", err)
		}
		return nil, nil, nil, fmt.Errorf("record the new storage scopes: %w — nothing was deployed", err)
	}
	fprintf(env.Err, "Minted a storage scope for %s in %q.\n", strings.Join(minted, ", "), namespace)
	warnKeyLoss(env.Err)
	// The actionable half: the keys just minted exist in this keyring and
	// nowhere else, so a copy taken earlier cannot restore what is written
	// under them.
	fprintf(env.Err, "A backup of keys.yaml made before now does not hold these keys; back it up again: %s\n",
		terminalText(env.ConfigDir.InstanceKeyringPath(instance)))
	return out, minted, ids, nil
}

// appScopesKeyring is the keyring an application's scope is minted into, as
// this machine holds it, with its bytes, which a save must still find on
// disk: refused when it cannot be read, or when it holds the scope every
// application shared (refuseSharedAppScope). The deploy plan reads its ids
// and times, and ensureAppScopes mints into it.
func appScopesKeyring(env *Env, instance string) (datasphere.Keyring, []byte, error) {
	raw, err := env.ConfigDir.LoadInstanceKeyring(instance)
	if err != nil {
		return datasphere.Keyring{}, nil, fmt.Errorf("read the storage keyring for %q, which is where an application's scope is minted: %w", instance, err)
	}
	keys, err := datasphere.ParseKeyring(raw)
	if err != nil {
		return datasphere.Keyring{}, nil, err
	}
	if err := refuseSharedAppScope(instance, keys); err != nil {
		return datasphere.Keyring{}, nil, err
	}
	return keys, raw, nil
}

// tenantList is apps in namespace as a refusal lists them, each
// <namespace>/<app>, or "none".
func tenantList(namespace string, apps []string) string {
	if len(apps) == 0 {
		return "none"
	}
	out := make([]string, len(apps))
	for i, app := range apps {
		out[i] = terminalText(tenantOf(namespace, app))
	}
	return strings.Join(out, ", ")
}

// pinScopes is the hand-over's beforePush for 'farcast run': it raises the
// instance's key pin to require the scopes just minted, once the hand-over has
// checked this keyring against every replica that answered and before any
// replica is handed them. From then on a replica that restarts refuses a
// keeper's bundle that lacks them, rather than serving without them and
// refusing those applications' requests. Run never retires a key.
//
// Not before the check: a pin raised from a keyring the fleet then refuses as
// behind would lock out the machine whose keys the fleet serves. And like the
// hand-over, nothing here fails the deploy.
//
// cl is the writer run opened: the pin is reached through it (pinStoreFor),
// so a run that raises the pin mints the installer's token once, not once
// more for a second writer (C-F1).
//
// Under --confirm, planned is the pin its plan listed, written once and only
// as listed (A28-10); nil otherwise, for the loop an interactive or --yes run
// raises it with. A pin that changed since the plan was made stops the
// hand-over before any push: the error is kept in *failed, which the caller
// owns, and returned.
func (c *runCommand) pinScopes(ctx context.Context, env *Env, meta *config.InstanceMetadata, keys datasphere.Keyring, cl any,
	planned *runPinPlan, failed *error) func(sealStateClient) error {
	return func(client sealStateClient) error {
		if err := c.raiseScopePin(ctx, env, meta, keys, client, cl, planned); err != nil {
			*failed = err
			return err
		}
		return nil
	}
}

// raiseScopePin raises the pin to require the scopes just minted, and hands
// it to the replicas. Any failure is a warning, and nothing here fails the
// deploy, but one: under --confirm a pin that is not the one planned is
// plan_changed, returned with nothing written over it.
func (c *runCommand) raiseScopePin(ctx context.Context, env *Env, meta *config.InstanceMetadata, keys datasphere.Keyring, client sealStateClient, cl any,
	planned *runPinPlan) error {
	ps, err := pinStoreFor(c.newPinStore, clusterRef{Dir: env.ConfigDir, Meta: meta, Identity: kube.Writer, Warn: env.Err}, cl)
	var w pinWrite
	switch {
	case err != nil:
	case planned == nil:
		w, err = writePinLoop(ctx, ps, keys, false, false)
	default:
		if w, err = planned.write(ctx, ps, keys); kindOf(err) == kindPlanChanged {
			return err
		}
	}
	var behind *pinBehind
	switch {
	case errors.As(err, &behind):
		fprintln(env.Err, behindWarning(behind))
		return nil
	case err != nil:
		fprintf(env.Err, "warning: the instance's key pin was not raised (%s): a replica that restarts still admits a keeper's bundle without "+
			"the new scope. %s raises it.\n", terminalText(err.Error()), pinRemedy(meta.Name))
		return nil
	case !w.Changed:
		return nil
	}
	for _, row := range raisePins(ctx, client, replicaCount(meta), w.Pin, false, meta.Name, heldKeys(keys)) {
		if !row.Raised {
			fprintf(env.Err, "warning: keyholder replica %d %s\n", row.Ordinal, row.Note)
		}
	}
	return nil
}

// behindWarning is run's warning that this keyring is behind the
// instance's key pin: printed at the hand-over, and a notice in a deploy
// plan, beside msgRunHandOver. The hand-over stops only when a replica has
// loaded the pin, which a replica reads from its environment as it starts
// (pinRefuses); a fleet started before the pin moved takes the keys.
func behindWarning(behind *pinBehind) string {
	return fmt.Sprintf("warning: %v; if any keyholder replica has loaded this pin, the hand-over is refused.", behind)
}

// refuseSharedAppScope refuses a keyring holding the scope every application
// shared before ADR 0018 decision 5: one owning the whole application root.
// No application's own scope can be minted beside it, and there is no
// migration from it.
func refuseSharedAppScope(instance string, k datasphere.Keyring) error {
	for _, s := range k.Scopes() {
		if s.Prefix != datasphere.AppScopeRoot+datasphere.ScopePrefixSuffix {
			continue
		}
		return fmt.Errorf("instance %q's keyring holds %q, the one application scope every application shared before "+
			"per-application scopes (ADR 0018 decision 5). It owns all of %s, so no application's own scope can be minted beside it, "+
			"and FarCast has no migration from it: its objects are named under its name key, which no per-application scope holds. "+
			"Nothing was deployed. Copy out what you need ('farcast storage cp'), then release the instance and install a new one",
			instance, s.Name, s.Prefix)
	}
	return nil
}

// handScopesToTheKeyholder gives a running keyholder the scopes just minted.
//
// A new application's keys exist on this machine the moment they are minted
// and nowhere else, so without this the application deploys, starts, and gets
// ErrStorageSealed until somebody notices and unseals. Doing it here closes
// that window on the ordinary path.
//
// It will NOT unseal a sealed keyholder, and that restraint is the whole
// design of this function. Pushing a bundle to a sealed keyholder IS an
// unseal: the same call, the same material. Unsealing is a deliberate act an
// operator takes knowing the instance was sealed — after a restart, or after
// they sealed it themselves — and a deploy performing it as a side effect
// would hide a seal the operator has not seen, and would clear an operator
// hold with a command whose subject is an application. So every replica is
// asked what it is first, and only the ones already serving are handed
// anything.
//
// Nothing here fails the deploy. The workloads are what the operator asked
// for, and an application that starts into ErrStorageSealed is in a
// documented, recoverable state that one command fixes — where a deploy
// abandoned halfway is not. The one exception is --confirm's: planned is
// the key pin its plan listed (nil otherwise), and a pin that changed since
// the plan was made stops the hand-over before any push and is returned,
// plan_changed, before the workloads are applied (A23-48, A28-10).
func (c *runCommand) handScopesToTheKeyholder(ctx context.Context, env *Env, meta *config.InstanceMetadata, minted []string, cl any,
	planned *runPinPlan) error {
	apps := strings.Join(minted, ", ")
	keys, err := keyringOf(env, meta.Name)
	if err != nil {
		// Its error names keys.yaml's path, and is several lines by design
		// (KeyLossWarning): each line kept, nothing in it acting on the
		// terminal (A28-3).
		c.sealedNotice(env, meta.Name, minted, output.ErrorText(err.Error()))
		return nil
	}
	var failed error
	res := handOverKeys(ctx, env, meta, keyholderOpener(c.newKeyholder), keys,
		handOverOptions{beforePush: c.pinScopes(ctx, env, meta, keys, cl, planned, &failed)})
	if failed != nil {
		return changedAfterPlan(consentConfirm, msgPinChangedAtHandOver)
	}
	switch {
	case res.Unsafe:
		// Not a seal, and an unseal now would refuse for the same reason: the
		// refusal says what to fix first. Re-running this deploy afterwards
		// would not hand the scope over — it exists by then, and only a scope
		// minted by this run is handed over — so the step after the fix is an
		// unseal.
		fprintf(env.Err, "The keyholder was not handed %s's scope: %s.\n", apps, res.Problem)
		fprintf(env.Err, "Once that is fixed, 'farcast storage unseal %s' hands it over. Until then a replica without the scope\n"+
			"refuses those applications' storage requests (ErrPermission), and a sealed one answers ErrStorageSealed.\n", meta.Name)
	case res.Behind != "":
		fprintf(env.Err, "The keyholder was not handed %s's scope everywhere: %s.\n", apps, res.Behind)
		fprintf(env.Err, "Once this keyring is up to date, 'farcast storage unseal %s' hands it over. Until then a replica without the scope\n"+
			"refuses those applications' storage requests (ErrPermission), and a sealed one answers ErrStorageSealed.\n", meta.Name)
	case res.Problem != "":
		c.sealedNotice(env, meta.Name, minted, res.Problem)
	case !res.Activated && res.Cause == heldNoneServing:
		c.sealedNotice(env, meta.Name, minted, res.Reason)
	case !res.Activated:
		// The new scope went over with the first push — no replica held it,
		// so nothing was held back for it. Another application's key was: a
		// serving replica lacked it, and the hand-over stopped before using
		// it. Which replicas still hold the scope, a later read says.
		fprintf(env.Err, "The keyholder took %s's scope with the first of two pushes (generation %d), but another application's\n"+
			"current key is not in use yet, because %s.\n", apps, res.Generation, res.Reason)
		fprintf(env.Err, "Run 'farcast storage state %s' to see each replica, and 'farcast storage unseal %s' once they answer.\n",
			meta.Name, meta.Name)
	case res.Complete():
		fprintf(env.Err, "The keyholder now holds %s's scope (generation %d).\n", apps, res.Generation)
	case len(res.Waiting) > 0:
		c.sealedNotice(env, meta.Name, minted,
			fmt.Sprintf("%d of %d keyholder replicas are sealed", len(res.Waiting), res.Total))
	case len(res.Loaded)+len(res.HeldOnly) == 0:
		c.sealedNotice(env, meta.Name, minted, "no replica took them")
	default:
		// Some replicas hold the scope and some did not answer or declined.
		// Not a success: a request routed to one without it is refused. A
		// replica that took only the first of two pushes holds the scope
		// too — the push carried it — and serves it.
		fprintf(env.Err, "The keyholder holds %s's scope on %d of %d replicas (generation %d); the rest are named above.\n",
			apps, len(res.Loaded)+len(res.HeldOnly), res.Total, res.Generation)
		fprintf(env.Err, "Run 'farcast storage state %s' to see each replica, and 'farcast storage unseal %s' once they answer.\n",
			meta.Name, meta.Name)
	}
	// Said whether or not the hand-over finished: the next unseal gives the
	// replicas the new scope either way. A keeper's bundle carries only the
	// scopes that existed when it was enrolled, and a keyholder replaces its
	// whole set on a push — so a keeper re-seeding a restarted replica now
	// would leave it serving, and refusing every request for the new
	// application. Keepers see the new scope on a serving replica and refuse
	// to re-seed instead — and a replica that loaded the key pin refuses them
	// itself, serving replica or none — which is right and, unannounced, a
	// fleet quietly switched off.
	if kept := keepersToReenrol(meta); len(kept) > 0 {
		fprintf(env.Err, "\nEvery keeper's bundle predates %s, so each refuses to re-seed a replica that restarts\n"+
			"until it is re-enrolled — a replica restored without %s would refuse its requests:\n", apps, apps)
		// Each line names a keeper device as the record holds it: enrolment
		// validated it, and the record is not checked again when it is read,
		// so it goes through terminalText, as rotate's lines do (A28-3).
		for _, line := range reenrolLines(meta.Name, kept) {
			fprintf(env.Err, "      %s\n", terminalText(line))
		}
	}
	return nil
}

// sealedNotice says the new scopes did not reach the keyholder, and what to do.
func (c *runCommand) sealedNotice(env *Env, instance string, minted []string, why string) {
	fprintf(env.Err, "The keyholder does not hold %s's scope yet — %s.\n", strings.Join(minted, ", "), why)
	fprintf(env.Err, "Until it does, those applications receive ErrStorageSealed. Run:\n\n  farcast storage unseal %s\n\n", instance)
}

// meter adds the new namespace to what the kernel counts, reusing the same
// manifest `farcast kernel meter` applies. reader is the reader the deploy
// plan bound there, when 'reader grant' recorded the metered scope (its
// warning, when it binds none, was said with the plan); the result's reader
// is it, or "" when no reader binding was applied.
//
// A failure here is reported and does not undo the deployment: the workloads
// are already running and billing, and unmetering them is not a fix for not
// being able to meter them.
func (c *runCommand) meter(ctx context.Context, env *Env, cl jobWaiter, meta *config.InstanceMetadata, name, namespace, reader string) (metered bool, bound string, err error) {
	// Unreachable from Run, which refuses an instance with no kernel before
	// anything is read; kept because the line below dereferences Kernel.
	if meta.Kernel == nil || !meta.Kernel.Deployed {
		return false, "", fmt.Errorf("instance %q has no kernel, so %q is not counted against the cost limit; "+
			"run 'farcast kernel deploy %s'", name, namespace, name)
	}
	previous := append([]string(nil), meta.Kernel.Namespaces...)
	next, added := applyMeterChange(previous, []string{namespace}, false)
	if len(added) == 0 {
		return true, "", nil
	}
	manifest, err := meterManifest(next, added, reader)
	if err != nil {
		return false, "", err
	}
	meta.Kernel.Namespaces = next
	meta.UpdatedAt = time.Now().UTC()
	if err := env.ConfigDir.SaveInstanceMetadata(name, meta); err != nil {
		return false, "", fmt.Errorf("record the metered namespaces before applying them: %w", err)
	}
	if err := cl.Apply(ctx, manifest); err != nil {
		meta.Kernel.Namespaces = previous
		if saveErr := env.ConfigDir.SaveInstanceMetadata(name, meta); saveErr != nil {
			return false, "", fmt.Errorf("meter %q: %w (and local state could not be rolled back: %v)", namespace, err, saveErr)
		}
		return false, "", fmt.Errorf("meter %q: %w", namespace, err)
	}
	return true, reader, nil
}

// record writes down the two reviewed images so the next run need not be told
// them again.
//
// It warns rather than fails: the applications are built and deployed by this
// point, and a metadata write that did not land is a nuisance, not a reason to
// report a successful deployment as an error.
func (c *runCommand) record(env *Env, meta *config.InstanceMetadata, name, fetcher, builder string) {
	now := time.Now().UTC()
	changed := recordToolchainImage(meta, fetcherKind, fetcher, now)
	if recordToolchainImage(meta, builderKind, builder, now) {
		changed = true
	}
	if !changed {
		return
	}
	meta.UpdatedAt = now
	if err := env.ConfigDir.SaveInstanceMetadata(name, meta); err != nil {
		fprintf(env.Err, "warning: could not record the fetcher and builder images for %q: %v\n", name, err)
		fprintf(env.Err, "         pass --fetcher-image and --builder-image again next time.\n")
	}
}

// normalisedRepository is a repository URL compared by what it names: a
// trailing slash and a trailing .git are the only differences ignored — and a
// credential, which no record should hold but one written before it was
// refused might.
func normalisedRepository(s string) string {
	return strings.TrimSuffix(strings.TrimRight(strings.TrimSpace(withoutUserinfo(s)), "/"), ".git")
}

// refuseOtherRepository refuses a namespace this machine recorded under a
// different repository, unless --replace-repository was given (ADR 0021
// decision 2, amended 2026-11-12). Two repositories in one namespace is the
// second replacing the first's egress entries and reusing its applications'
// storage scopes — reading their data.
//
// A namespace with no record here is accepted: every namespace deployed
// before records existed, and any deployed from another machine.
func (c *runCommand) refuseOtherRepository(meta *config.InstanceMetadata, instance, namespace, repo string, afterRead bool) error {
	dep, ok := meta.Deployments[namespace]
	if !ok || c.replaceRepository || normalisedRepository(dep.Repository) == normalisedRepository(repo) {
		return nil
	}
	what := "Nothing was read, built or deployed."
	if afterRead {
		what = "The manifest was read inside the instance; nothing was built or deployed."
	}
	return fmt.Errorf("namespace %q in %q was deployed from %s, and this run is %s. One namespace holds one repository: "+
		"deploying this one there would replace the other's egress entries and reuse its applications' storage scopes. %s "+
		"Pass --replace-repository to replace it, or --namespace to deploy beside it",
		namespace, instance, withoutUserinfo(dep.Repository), withoutUserinfo(repo), what)
}

// recordProvenance writes down, on this machine, what this run deployed into
// the namespace: the map labels the namespace's group with it, and the next
// run checks against it. Nothing new reaches the cluster.
//
// It warns rather than fails, as record does: the workloads exist by now, and
// a record that did not land is a label missing from the map, not a failed
// deployment.
func (c *runCommand) recordProvenance(env *Env, instance, namespace, repo string, report pfetch.Report, storageWired bool) {
	ref := c.ref
	if ref == "" {
		ref = fetchDefaultRef // what the fetch resolves when no ref is given
	}
	dep := config.Deployment{
		// repoURL refuses a credential in the URL; this is the second lock.
		Repository: withoutUserinfo(repo), Ref: ref, Commit: report.Commit, ManifestDigest: report.ManifestDigest,
		DeployedAt: time.Now().UTC().Truncate(time.Second), StorageWired: storageWired,
	}
	if _, err := env.ConfigDir.UpdateInstanceMetadata(instance, func(m *config.InstanceMetadata) error {
		if m.Deployments == nil {
			m.Deployments = map[string]config.Deployment{}
		}
		m.Deployments[namespace] = dep
		return nil
	}); err != nil {
		fprintf(env.Err, "warning: could not record which repository %q was deployed from: %v\n", namespace, err)
	}
}

// confirm shows the review and asks for it to be approved.
//
// The review is printed whether or not -y was passed. AGENTS.md makes the
// declarations the gate, and -y waives the question, not the reading: an
// approval given in advance is still an approval of these hosts, and the
// warnings in the review — FatLine not deployed, a cost limit below what this
// would bill — are the ones an unattended run most needs on record. It is also
// the only record if the run fails after the egress policy is written and
// before a result is printed. Like every prompt it goes to stderr, so stdout
// carries only the result.
//
// While the instance's spending reads as at its limit, --yes deploys
// nothing (A28-1): it refuses after the review, before anything is built,
// as a usage error (A28-12). An interactive run is told what this deploy
// may restart, and asked.
func (c *runCommand) confirm(env *Env, rev review) (bool, error) {
	rev.print(env.Err)
	if c.assumeYes {
		if rev.Live.Limit.Reached {
			return false, atTheLimit(rev.Namespace, rev.Live, msgNothingBuilt)
		}
		fprintln(env.Err, "\nApproved with --yes; nothing was asked.")
		return true, nil
	}
	if !c.interactive(env) {
		return false, usagef(msgRunYes)
	}
	if rev.Live.Limit.Reached {
		printAtTheLimit(env.Err, rev.Live.Apps)
	}
	return newPrompter(env.In, env.Err).yesNo(fmt.Sprintf("Deploy %q?", rev.Namespace))
}

// recheck reads the ledger and the applications again, after the builds and
// before the egress policy (A23-2), and reports whether the deploy goes on.
//
// While the spending reads as at its limit now, --yes refuses with the
// gate's text, ending with what was written (A28-1). An interactive run is
// asked again when the limit was not reached at the review and is now, or
// when an application it may restart was not one at the review: it is told
// which, and false is a decline. Otherwise nothing is asked again.
func (c *runCommand) recheck(ctx context.Context, env *Env, cl liveReader, rev review) (bool, error) {
	now, err := readLive(ctx, cl, rev.Namespace, rev.Manifest, c.now(), consentNone, rev.Instance)
	if err != nil {
		return false, fmt.Errorf("%w; %s", err, msgBuildsWrittenClause)
	}
	if !now.Limit.Reached {
		return true, nil
	}
	if c.assumeYes {
		return false, atTheLimit(rev.Namespace, now, msgBuildsWritten)
	}
	newly := !rev.Live.Limit.Reached
	var fresh []appState
	for i, a := range now.Apps {
		if a.restarts() && (newly || !rev.Live.Apps[i].restarts()) {
			fresh = append(fresh, a)
		}
	}
	if !newly && len(fresh) == 0 {
		return true, nil
	}
	fprintln(env.Err)
	if newly {
		fprintln(env.Err, limitLine(now.Limit.Reason))
	}
	printAtTheLimit(env.Err, fresh)
	return newPrompter(env.In, env.Err).yesNo(fmt.Sprintf("Deploy %q?", rev.Namespace))
}

// pinByDigest replaces a tagged reference's tag with the digest that was
// built. The tag is dropped, not kept alongside: the digest is what identifies
// the image, and a reference carrying both invites reading the wrong one.
func pinByDigest(destination, digest string) string {
	return untagged(destination) + "@" + digest
}

// untagged is a tagged reference without its tag: what a build's image is
// pinned by its digest under, and a deploy plan by its placeholder digest
// (A23-30).
func untagged(destination string) string {
	if i := strings.LastIndex(destination, ":"); i > strings.LastIndex(destination, "/") {
		return destination[:i]
	}
	return destination
}

// shortCommit is what an image gets tagged with. The digest is what it is
// deployed by; the tag exists so a human reading the registry can tell which
// commit produced what.
func shortCommit(commit string) string {
	if len(commit) > 12 {
		return commit[:12]
	}
	return commit
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// appResults is each application the manifest deployed, in manifest order,
// with what it may now reach.
//
// The declarations come from the egress policy that was written — the
// document FatLine enforces — and not from the manifest again. That is where
// the summary's count comes from too, so the count and the list cannot
// disagree, and what the result says an application may reach is what the
// boundary was told. An application the document has no entry for may reach
// nothing, and is listed as reaching nothing rather than left out.
func appResults(m parser.Manifest, images map[string]string, doc *policy.Document, namespace string) []runApp {
	out := make([]runApp, 0, len(m.Apps))
	for _, a := range m.Apps {
		r := runApp{Name: a.Name, Image: images[a.Name], External: []parser.External{}}
		for _, p := range doc.Apps {
			if p.Namespace == namespace && p.Name == a.Name {
				r.External = append(r.External, p.External...)
				break
			}
		}
		out = append(out, r)
	}
	return out
}

// runApp is one deployed application. External is never omitted, and is the
// same {host, reason} shape as .apps[].external in the policy ConfigMap: an
// application that may reach nothing says so with [], rather than by a
// missing key a reader has to know the meaning of.
type runApp struct {
	Name     string            `json:"name"`
	Image    string            `json:"image"`
	External []parser.External `json:"external"`
}

type runResult struct {
	Instance       string        `json:"instance"`
	Repo           string        `json:"repo"`
	Deployment     string        `json:"deployment"`
	Namespace      string        `json:"namespace"`
	Commit         string        `json:"commit"`
	ManifestDigest string        `json:"manifest_digest"`
	Apps           []runApp      `json:"apps"`
	Egress         egressSummary `json:"egress"`
	Metered        bool          `json:"metered"`
	MeterError     string        `json:"meter_error,omitempty"`
	NotReady       []string      `json:"not_ready,omitempty"`
	// Reader is the reader bound in ReaderBindings, the namespace this run
	// started metering; both are empty unless 'reader grant' recorded the
	// metered scope.
	Reader         string   `json:"reader,omitempty"`
	ReaderBindings []string `json:"reader_bindings_created,omitempty"`
}

func (r runResult) Human(w io.Writer) error {
	fprintf(w, "Deployed %s into %q, namespace %q\n", r.Deployment, r.Instance, r.Namespace)
	fprintf(w, "  from    %s at %s\n", r.Repo, r.Commit)
	fprintf(w, "  reading %s\n", r.ManifestDigest)
	for _, a := range r.Apps {
		fprintf(w, "  %-16s %s\n", terminalText(a.Name), a.Image)
	}
	// What each application may now reach, and the fact that it is per
	// application rather than per instance — which is the promise the review
	// gate makes and, until ADR 0013, the one the enforcement point could not
	// keep.
	fprintf(w, "\nEgress: %s across %s, enforced per application.\n",
		plural(r.Egress.Hosts, "declared host", "declared hosts"),
		plural(r.Egress.Applications, "application", "applications"))
	// And what they are. A count alone is what the Phase 5 Session A walk
	// found an operator approving with -y was left with: a number, and not
	// the hosts it stood for. The lines are the review's own (printDeclared).
	for _, a := range r.Apps {
		// The manifest's text, like the review's: the parser admits only DNS
		// labels here, and the printer should not have to know that.
		fprintf(w, "  %s\n", terminalText(a.Name))
		printDeclared(w, a.External)
	}
	if r.Egress.Others > 0 {
		fprintf(w, "%s from other deployments on this instance kept their own.\n",
			plural(r.Egress.Others, "application", "applications"))
	}
	if len(r.NotReady) > 0 {
		fprintf(w, "\nNot ready yet: %s\n", strings.Join(r.NotReady, ", "))
		fprintf(w, "They are deployed and billing. 'farcast logs %s <app>' says why.\n", r.Instance)
	}
	if !r.Metered {
		fprintf(w, "\nNOT METERED: %s\n", r.MeterError)
		fprintf(w, "These applications are running and are not counted against the cost limit.\n")
		fprintf(w, "Run 'farcast kernel meter %s %s' to count them.\n", r.Instance, r.Namespace)
	}
	printReaderBindings(w, r.Reader, r.ReaderBindings)

	// The commit and the digest are the whole of what a device that cannot
	// reach the repository can check later (ADR 0010 decision 6), so they are
	// worth telling the operator how to use rather than only printing.
	fprintf(w, "\nTo verify out of band, from any machine that can reach the repository:\n")
	fprintf(w, "  git ls-remote %s | grep %s\n", r.Repo, shortCommit(r.Commit))
	return nil
}

// applicationsMonthlyUSD is what a translated manifest costs standing still.
func applicationsMonthlyUSD(apps int) float64 {
	return float64(apps) * pricing.WorkloadMonthlyUSD(appReplicas, translate.RequestCPUMilli, translate.RequestMemMiB)
}

// deployableNamespace is the one rule for where run may put applications,
// whether the namespace came from --namespace or from the manifest's name: a
// DNS label, outside the provider's managed kube- namespaces, and never the
// namespace that holds the instance's own components.
func deployableNamespace(ns string) error {
	if err := validNamespace(ns); err != nil {
		return usagef("namespace %q: %v", ns, err)
	}
	if ns == tcdeploy.DefaultNamespace {
		return usagef("refusing to deploy applications into %q; it holds the instance's own components, "+
			"and mixing them makes the tier labels a cost shutdown reads harder to trust than they should be",
			tcdeploy.DefaultNamespace)
	}
	return nil
}
