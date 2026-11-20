package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	pbuild "github.com/sofmon/farcast/planck/build"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
)

const (
	// buildTimeout bounds how long the CLI waits. The Job carries its own,
	// shorter deadline; this is the operator's patience, not the build's.
	buildTimeout = 35 * time.Minute
)

// jobWaiter is the slice of the cluster client a build needs (injectable):
// its applies, its wait and its log, its preflight, and, as the writer, the
// builder's ServiceAccount, whose uid an interactive or --yes plan and the
// printed push grant name (ADR 0023 M2.8, design §33 A33-18, A33-22).
type jobWaiter interface {
	Apply(ctx context.Context, manifests []byte) error
	WaitJob(ctx context.Context, namespace, name string, timeout time.Duration) (cluster.JobResult, error)
	JobLogs(ctx context.Context, namespace, job string, lines int) (string, error)
	preflighter
	serviceAccountReader
}

// buildPlanReader is what build's plan reads the cluster through under
// --plan and --confirm (design §33, A33-21): farcast-system's uid, which
// the plan binds as its target, and the builder's ServiceAccount, whose uid
// the push grant names.
type buildPlanReader interface {
	serviceAccountReader
	preflighter
}

type buildCommand struct {
	repo          string
	ref           string
	app           string
	containerfile string
	contextPath   string
	gitSecret     string
	builderImage  string
	tag           string
	assumeYes     bool
	// consent is --plan and --confirm <digest> (ADR 0023 M2.6).
	consent consentFlags

	// Seams, overridable in tests.
	newCluster func(clusterRef) (jobWaiter, error)
	// newPlanReader opens what the plan reads the cluster through under
	// --plan and --confirm: the instance's reader (design §33, A33-21),
	// openReaderDefault when unset, and never the writer. An interactive or
	// --yes run reads through the writer it opened instead.
	newPlanReader func(clusterRef) (buildPlanReader, error)
	// openProvider opens the cloud provider the plan reads the project
	// number and the repository's IAM policy through, as the installer key,
	// in every mode (A33-1, A33-22): openProviderDefault when unset.
	openProvider providerOpener
	newBuilder   func(progress func(string)) imageBuilder
	// now is the clock a printed plan is dated by (generated_at).
	now func() time.Time
}

func (*buildCommand) Name() string { return "build" }
func (*buildCommand) Synopsis() string {
	return "Build an application's image inside the instance"
}

func (*buildCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast build <instance> --repo <url> --app <name> --builder-image <ref@sha256:…>
                     [--ref <git-ref>] [--containerfile <path>] [--context <subpath>]
                     [--git-secret <name>] [--tag <tag>] [-y] [--plan | --confirm <digest>]

Build an application's Containerfile into an image in the instance's own
registry — inside the instance, not on this machine.

The instance clones the repository itself, so building does not depend on this
machine having the source, a container engine, or the repository's credentials
(ADR 0010). What it does need is a repository-scoped, read-only credential in
the cluster when the repository is private: --git-secret names the Secret
holding it.

The build runs as a one-shot Job with its own deadline, is stopped by nothing
except that deadline, and reports the digest it pushed through the Pod's
status. Deploying that image pins it by digest.

An instance with no kernel is refused: the build is a billed Job, and nothing
would count it against the cost limit.

The builder pushes under its own ServiceAccount, farcast-system/farcast-builder,
whose push grant this command never applies: push access to the registry the
instance runs from is a decision for a human. Every build reads the grant's
state from the repository's own IAM policy, with the installer's key, and
prints the commands that grant it by the account's uid, and remove the
principal every FarCast instance in the project shares, when the policy does
not hold it (a grant at the project, through a group or by a wider role does
not show there). An account that does not exist yet gets its commands right
after the build starts; 'farcast kernel deploy' creates it ahead of any
build. The uid member on a repository's policy is unverified until the M2
walk.

--plan prints what the build would do, and changes nothing: the build, its
Job's cost, the builder image (--builder-image's, or the one the instance
recorded), the push grant's state, and the three documents it would apply,
with the plan's digest. It reads farcast-system's uid and the builder's
ServiceAccount as the instance's reader, which 'farcast reader grant' must
have verified read-only (there is no fallback to the installer's account),
and the project number and the repository's IAM policy with the installer's
key; it opens no writer. A builder given by tag is looked up anonymously, as
without --plan, only to be refused with the digest to pin. --confirm
<digest> does exactly the plan with that digest, asking nothing, and
refuses, having written nothing, if anything it binds has changed since: a
push grant applied after the plan was made is such a change. It recomputes
the plan as the reader, and opens the writer only after the comparison,
refusing if the writer reaches another cluster than the one the plan read.

'farcast run' reads a repository's manifest and builds every application in it;
this builds one, with its Containerfile given explicitly.`)
}

func (c *buildCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.repo, "repo", "", "the Git repository to build (https:// or git://)")
	fs.StringVar(&c.ref, "ref", "", "branch, tag or commit (default refs/heads/main)")
	fs.StringVar(&c.app, "app", "", "the application's name, which is also its image path")
	fs.StringVar(&c.containerfile, "containerfile", "", "path to the Containerfile within the repository")
	fs.StringVar(&c.contextPath, "context", "", "build context subdirectory (default: the repository root)")
	fs.StringVar(&c.gitSecret, "git-secret", "", "Secret holding a read-only Git credential (private repositories)")
	fs.StringVar(&c.builderImage, "builder-image", "", "digest-pinned Kaniko image")
	fs.StringVar(&c.tag, "tag", "", "tag to push (default: the git ref)")
	fs.BoolVar(&c.assumeYes, "yes", false, "skip the cost confirmation")
	fs.BoolVar(&c.assumeYes, "y", false, "skip the cost confirmation")
	c.consent.register(fs)
}

func (c *buildCommand) ensureDefaults() {
	if c.newCluster == nil {
		c.newCluster = func(r clusterRef) (jobWaiter, error) {
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
		c.newPlanReader = func(r clusterRef) (buildPlanReader, error) {
			// A refusal returns a nil reader, never a nil *cluster.Client
			// inside a non-nil one.
			cl, err := openReaderDefault(r)
			if err != nil {
				return nil, err
			}
			return cl, nil
		}
	}
	if c.openProvider == nil {
		c.openProvider = openProviderDefault
	}
	if c.newBuilder == nil {
		c.newBuilder = newBuilderDefault
	}
	if c.now == nil {
		c.now = time.Now
	}
}

// msgBuildFailed is a failed build's error: the deployment and the app. The
// end of the build's log, when JobLogs could read it, is printed above it.
const msgBuildFailed = "the build of %s/%s failed; the end of its log, when it could be read, is printed above"

// msgBuildCostYes is the build's refusal without a terminal and without
// --yes: its Job's vCPU and MiB, and the two routes that need no terminal.
const msgBuildCostYes = "building runs a %d vCPU / %d MiB Job in the instance until it finishes or its deadline expires; pass --yes to confirm" + consentSuffix

// costWhatBuild is the build's one-off Job as its cost fact names it.
const costWhatBuild = "the build Job"

// preparedBuild is every decision a build executes, made once by its plan
// (ADR 0023 M2.6, A23-37): interactive runs, --yes and --confirm all execute
// from it.
type preparedBuild struct {
	// builder is the Kaniko image, digest-pinned; destination the tagged
	// reference the build pushes to; manifest the stream it applies.
	builder     string
	tag         string
	destination string
	manifest    []byte
	// cost is the build's cost fact, which its question is asked from.
	cost plan.CostFact
	// push is the builder's push grant as the plan read it (A33-22).
	push pushGrant
}

// plan is build's plan (design §9.4, A23-37, §33 A33-21, A33-22): the
// build, its Job's cost against the instance's limit, the builder image as
// named or recorded, the builder's push grant, the three documents the
// build applies (its ServiceAccount, NetworkPolicy and Job), and the push
// grant's notice when it is due. rd is what it reads the cluster through:
// the reader under --plan and --confirm, its errors the reader's
// (planRead), and in an interactive or --yes run (m) the writer, whose
// preflight read farcast-system's uid, writerUID, which the plan binds
// rather than read it again.
//
// It reads, in order: farcast-system's uid; the builder image, a tag only
// to refuse it, anonymously; the render; farcast-builder's uid
// (readServiceAccountUID); and, as the installer key, the project number
// and the repository's IAM policy (readPushGrant). It reads no terminal and
// writes nothing. build has no block: a push grant that is not present is a
// notice.
func (c *buildCommand) plan(ctx context.Context, env *Env, meta *config.InstanceMetadata, rd buildPlanReader, m consentMode, writerUID string) (preparedBuild, plan.Bound, error) {
	uid := writerUID
	if m != consentNone {
		var err error
		if uid, err = rd.NamespaceUID(ctx, tcdeploy.DefaultNamespace); err != nil {
			return preparedBuild{}, plan.Bound{}, planRead(m, fmt.Errorf("read the uid of the instance's %s namespace: %w", tcdeploy.DefaultNamespace, err), meta.Name)
		}
	}
	b := newBound("build", meta, "reader", uid)
	b.Options = sortedOptions([]plan.Option{
		{Flag: "app", Value: c.app},
		{Flag: "builder-image", Value: c.builderImage},
		{Flag: "containerfile", Value: c.containerfile},
		{Flag: "context", Value: c.contextPath},
		{Flag: "git-secret", Value: c.gitSecret},
		{Flag: "ref", Value: c.ref},
		{Flag: "repo", Value: c.repo},
		{Flag: "tag", Value: c.tag},
	})

	builder, source, err := resolveToolchainSource(ctx, env, meta, builderKind, c.builderImage, c.newBuilder)
	if err != nil {
		return preparedBuild{}, plan.Bound{}, err
	}
	p := preparedBuild{builder: builder, tag: c.tag}
	deployment := meta.Name
	if p.tag == "" {
		p.tag = imageTag(refTag(c.ref))
	}
	p.destination = fmt.Sprintf("%s/app/%s/%s:%s", meta.Registry.Prefix, deployment, c.app, p.tag)

	p.manifest, err = pbuild.Render(pbuild.Config{
		Instance:       meta.Name,
		Deployment:     deployment,
		App:            c.app,
		Builder:        builder,
		Repo:           c.repo,
		Ref:            c.ref,
		Containerfile:  c.containerfile,
		ContextSubPath: c.contextPath,
		Destination:    p.destination,
		GitSecret:      c.gitSecret,
		EgressHosts:    []string{hostOf(c.repo), hostOf(meta.Registry.Prefix)},
	})
	if err != nil {
		return preparedBuild{}, plan.Bound{}, err
	}
	writes, err := applyFacts(p.manifest)
	if err != nil {
		return preparedBuild{}, plan.Bound{}, err
	}
	p.cost = buildCost(meta)
	builderUID, err := readServiceAccountUID(ctx, rd, m, meta.Name, tcdeploy.DefaultNamespace, pbuild.ServiceAccount, plan.GrantPush)
	if err != nil {
		return preparedBuild{}, plan.Bound{}, err
	}
	var grant plan.GrantFact
	if p.push, grant, err = readPushGrant(ctx, env, meta, c.openProvider, builderUID); err != nil {
		return preparedBuild{}, plan.Bound{}, err
	}
	notice, err := p.push.notice()
	if err != nil {
		return preparedBuild{}, plan.Bound{}, err
	}
	b.Facts = append([]plan.Fact{
		plan.BuildFact{
			Type: plan.TypeBuild, Repository: c.repo, Ref: c.ref, App: c.app,
			Containerfile: c.containerfile, Context: c.contextPath, Tag: p.tag, Destination: p.destination,
		},
		p.cost,
		toolchainImageFact(meta, builderKind, builder, source),
		grant,
	}, writes...)
	if notice != "" {
		b.Facts = append(b.Facts, noticeFact(notice))
	}
	return p, b, nil
}

// buildCost is the build's cost fact (A23-33): its one Job, with the vCPU,
// MiB and deadline the build renders it with, against the instance's limit;
// nothing standing; and the instance's floor fully provisioned.
func buildCost(meta *config.InstanceMetadata) plan.CostFact {
	f := fullFloorCost(meta)
	f.OneOff = []plan.OneOffCost{{
		What: costWhatBuild, Jobs: 1, CPUMilli: pbuild.RequestCPUMilli, MemMiB: pbuild.RequestMemMiB, DeadlineS: pbuild.DeadlineSeconds,
	}}
	return f
}

func (c *buildCommand) Run(ctx context.Context, env *Env, args []string) (err error) {
	// A 403 the writer met says whose it was, once (A20-9).
	var meta *config.InstanceMetadata
	defer func() { err = writerRefused(err, meta) }()
	if len(args) != 1 {
		return usagef("build takes one instance argument")
	}
	mode, given, err := c.consent.mode(c.assumeYes)
	if err != nil {
		return err
	}
	name := args[0]
	c.ensureDefaults()

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
	if c.repo == "" || c.app == "" {
		return usagef("--repo and --app are required")
	}
	if meta.Registry == nil || meta.Registry.Prefix == "" {
		return fmt.Errorf("instance %q has no image registry recorded; run 'farcast connect %s' first", name, name)
	}
	// The push grant's read and its commands take the record's project, its
	// repository and its location, checked before anything is read (design
	// §33, A33-15).
	if _, _, _, err := pushGrantRecord(meta); err != nil {
		return err
	}
	// Before the builder is resolved: the build is a billed Job in
	// farcast-system, which only a kernel meters.
	if err := requireKernel(name, meta, "this build"); err != nil {
		return err
	}
	// The plan reads the cluster as the reader under --plan and --confirm,
	// with no fallback to the writer (design §33, A33-21).
	if err := requireGrantedReader(env.ConfigDir, meta, "build", mode); err != nil {
		return err
	}

	// An interactive or --yes run opens the writer, and reads once as it,
	// before the builder image is resolved and before anything is asked (ADR
	// 0023 M2.5, A20-10 and A20-11): an instance this machine cannot write as
	// is refused with nothing spent, and an endpoint that refuses the
	// installer's key refuses it before anything is applied. Its plan reads
	// through it, and binds the uid its preflight read. --plan never opens
	// it, and --confirm right after the comparison (A23-23, A23-37); both
	// read through the reader.
	var cl jobWaiter
	var rd buildPlanReader
	var uid string
	if mode == consentNone {
		if cl, uid, err = openReadyAt(ctx, env, meta, c.newCluster); err != nil {
			return err
		}
		defer afterWrites(env, name, cl)
		rd = cl
	} else if rd, err = c.newPlanReader(clusterRef{Dir: env.ConfigDir, Meta: meta, Identity: kube.Reader, Warn: env.Err}); err != nil {
		return err
	}

	p, b, err := c.plan(ctx, env, meta, rd, mode, uid)
	if err != nil {
		return err
	}
	switch mode {
	case consentPlan:
		return printPlan(env, b, c.now())
	case consentConfirm:
		if err := confirmPlan(b, given); err != nil {
			return err
		}
		// What the plan says, once, right after the comparison (A23-26).
		printNotices(env.Err, b)
		if cl, err = openConfirmed(ctx, env, meta, b, c.newCluster); err != nil {
			return err
		}
		defer afterWrites(env, name, cl)
	default:
		ok, err := c.confirm(env, meta, p, b)
		if err != nil {
			return err
		}
		if !ok {
			fprintln(env.Err, "Aborted.")
			return nil
		}
	}
	deployment, builder, tag, destination := meta.Name, p.builder, p.tag, p.destination

	if err := cl.Apply(ctx, p.manifest); err != nil {
		return fmt.Errorf("start the build: %w", err)
	}
	// The builder's ServiceAccount exists from the apply on: a plan that
	// bound the uid placeholder prints the push grant now, while the build
	// runs (A33-22).
	builderUID := pushGrantNow(ctx, env, cl, p.push)
	job := pbuild.JobName(deployment, c.app)
	if isInteractive(env) || env.Verbose {
		fprintf(env.Err, "Building %s/%s inside %q — this runs in the instance, not here.\n", deployment, c.app, name)
	}

	res, err := cl.WaitJob(ctx, pbuild.Namespace, job, buildTimeout)
	if err != nil {
		return fmt.Errorf("wait for the build: %w", err)
	}
	if !res.Succeeded {
		// The operator needs the build's own output, not ours: a Containerfile
		// that failed says why, and repeating "the build failed" helps nobody.
		var logs string
		if l, lerr := cl.JobLogs(ctx, pbuild.Namespace, job, 40); lerr == nil && strings.TrimSpace(l) != "" {
			logs = l
			fprintf(env.Err, "\n%s\n", strings.TrimRight(l, "\n"))
		}
		// One failure is not a Containerfile problem, and the raw output does
		// not say so: a refused push means the build worked and the grant is
		// missing. Naming it here is the whole point — the alternative is what
		// the 5.1b walk did, which was to pay for a clone and a build and be
		// handed a permission string.
		explainPushDenial(env.Err, logs, p.push.fact.State, func() string { return grantText(ctx, cl, p.push.denied(), &builderUID) })
		return fmt.Errorf(msgBuildFailed, deployment, c.app)
	}

	// The whole digest, not just its prefix. A truncated one would build a
	// reference that looks pinned and names nothing — and the image may well
	// have been pushed, so failing loudly here is the difference between "you
	// must re-run" and "you are deploying something unresolvable".
	digest := strings.TrimSpace(res.Message)
	if !isSHA256(digest) {
		return fmt.Errorf("the build reported %q instead of a sha256 digest; the image may have been pushed "+
			"but cannot be pinned, and an unpinned image is not deployable (ADR 0007 decision 4)", digest)
	}
	pinned := strings.SplitN(destination, ":", 2)[0]
	if i := strings.LastIndex(destination, ":"); i > strings.LastIndex(destination, "/") {
		pinned = destination[:i]
	}
	pinned += "@" + digest

	result := buildResult{
		Instance: name, App: c.app, Deployment: deployment,
		Repo: c.repo, Ref: c.ref, Tag: tag,
		Image: pinned, Builder: builder,
		ServiceAccount: pbuild.ServiceAccount, Namespace: pbuild.Namespace,
		Project: meta.Project, Region: meta.Region,
		PushGrant: p.push.result(builderUID),
	}
	// The commands again, under the result, only when the plan did not read
	// the grant present (A33-22).
	if p.push.fact.State != plan.GrantPresent {
		result.grant = grantText(ctx, cl, p.push, &builderUID)
		result.PushGrant = p.push.result(builderUID)
	}
	return env.Printer.Print(result)
}

// refTag turns a git ref into something usable as an image tag.
func refTag(ref string) string {
	if ref == "" {
		return "main"
	}
	if i := strings.LastIndex(ref, "/"); i >= 0 {
		ref = ref[i+1:]
	}
	return ref
}

// hostOf is the registry or repository host, recorded on the build's policy
// for the operator's benefit.
func hostOf(s string) string {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "git://")
	if i := strings.IndexAny(s, "/:"); i >= 0 {
		s = s[:i]
	}
	return s
}

// confirm is the build's cost gate, asked from the plan's cost fact and
// destination: the Job's requests and deadline, and where it pushes. The
// plan's notices, the push grant's, print first, once, in the plan's words
// (A23-26, A33-22). --yes proceeds; a non-interactive session without --yes
// is a usage error, which names the plan's route too, and prints nothing.
func (c *buildCommand) confirm(env *Env, meta *config.InstanceMetadata, p preparedBuild, b plan.Bound) (bool, error) {
	job := p.cost.OneOff[0]
	if !c.assumeYes && !isInteractive(env) {
		return false, usagef(msgBuildCostYes, job.CPUMilli/1000, job.MemMiB)
	}
	printNotices(env.Err, b)
	if c.assumeYes {
		return true, nil
	}
	fprintf(env.Err, "Building inside %q runs a Job requesting %dm CPU and %dMi, bounded by a %d-minute deadline.\n",
		meta.Name, job.CPUMilli, job.MemMiB, job.DeadlineS/60)
	fprintf(env.Err, "It pushes to %s.\n", p.destination)
	fprintf(env.Err, "The instance clones the repository itself; this machine never sees the source.\n")
	return newPrompter(env.In, env.Err).yesNo("Build it?")
}

type buildResult struct {
	Instance       string `json:"instance"`
	Deployment     string `json:"deployment"`
	App            string `json:"app"`
	Repo           string `json:"repo"`
	Ref            string `json:"ref,omitempty"`
	Tag            string `json:"tag"`
	Image          string `json:"image"`
	Builder        string `json:"builder"`
	ServiceAccount string `json:"service_account"`
	Namespace      string `json:"namespace"`
	Project        string `json:"project,omitempty"`
	Region         string `json:"region,omitempty"`
	// PushGrant is the builder's push grant as the plan read it (design
	// §33, A33-22): its uid principal, the uid one once the account exists,
	// and the two states.
	PushGrant pushGrantResult `json:"push_grant"`
	// grant is the commands Human prints, when the plan did not read the
	// grant present: for the builder's uid, or the one line that says it
	// could not be read.
	grant string
}

func (r buildResult) Human(w io.Writer) error {
	fprintf(w, "Built %s/%s in %q\n", r.Deployment, r.App, r.Instance)
	fprintf(w, "  from   %s", r.Repo)
	if r.Ref != "" {
		fprintf(w, " at %s", r.Ref)
	}
	fprintln(w)
	fprintf(w, "  image  %s\n", r.Image)

	// The push grant is not FarCast's to apply: push access means code
	// FarCast did not write can put images into the one registry the
	// instance runs from, a decision for a human, once (writePushGrant).
	// The commands print only when the plan did not read it present.
	if r.grant == "" {
		return nil
	}
	fprintf(w, "\nThe builder pushes under its own cloud identity, and when the build was\n")
	fprintf(w, "planned the repository's own policy did not show its grant. In Cloud Shell:\n\n")
	fprintln(w, r.grant)
	fprintf(w, "\nThe grant is on the ONE repository, not the project.\n")
	return nil
}
