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
	"github.com/sofmon/farcast/farsight/cli/internal/image"
	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/fatline/identity"
	"github.com/sofmon/farcast/manifest/parser"
	pbuild "github.com/sofmon/farcast/planck/build"
	pfetch "github.com/sofmon/farcast/planck/fetch"
	"github.com/sofmon/farcast/planck/translate"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
	"github.com/sofmon/farcast/technocore/pricing"
)

// rolloutTimeout bounds the wait for a translated application to come up. It
// is generous because the first pull of a fresh image on a cold Autopilot node
// is the slow case, and short enough that a CrashLoopBackOff is reported as
// one rather than waited on forever.
const rolloutTimeout = 5 * time.Minute

// runCluster is the slice of the cluster client `run` needs.
type runCluster interface {
	jobWaiter
	policyReader
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

	// Seams, overridable in tests.
	newCluster func(kubeconfigPath string) runCluster
	newBuilder func(progress func(string)) imageBuilder
}

func (*runCommand) Name() string { return "run" }
func (*runCommand) Synopsis() string {
	return "Deploy a Git repository to an instance"
}

func (*runCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast run <instance> <repository> [--ref <git-ref>] [--git-secret <name>]
                   [--namespace <name>] [--manifest <path>]
                   [--fetcher-image <ref@sha256:…>] [--builder-image <ref@sha256:…>] [-y]

Read a repository's ./farcast manifest, show you what it declares, and — once
you approve — build every application in it and deploy them.

The instance does the reading and the building. It clones the repository
itself, so this works the same from a laptop that has never seen the source as
from the one that wrote it (ADR 0010). What it reports back is the resolved
commit and a digest of the manifest it parsed, and the build is pinned to that
same commit: a branch that moves between the read and the build cannot change
what you approved.

The gate is the external service declarations. Nothing an application can reach
is implicit — FatLine denies every outbound host that the manifest does not
name, so what is listed at the prompt is the whole of it.

Both images this runs inside the instance are third-party and must be
digest-pinned. Pass each once and the instance remembers it.`)
}

func (c *runCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.ref, "ref", "", "branch, tag or commit to deploy (default refs/heads/main)")
	fs.StringVar(&c.gitSecret, "git-secret", "", "Secret holding a read-only Git credential (private repositories)")
	fs.StringVar(&c.namespace, "namespace", "", "deploy into this namespace instead of the manifest's name")
	fs.StringVar(&c.manifestPath, "manifest", "", "path of the manifest within the repository (default ./farcast)")
	fs.StringVar(&c.fetcherImage, "fetcher-image", "", "digest-pinned image with git in it")
	fs.StringVar(&c.builderImage, "builder-image", "", "digest-pinned Kaniko image")
	fs.BoolVar(&c.assumeYes, "yes", false, "skip the review prompt")
	fs.BoolVar(&c.assumeYes, "y", false, "skip the review prompt")
}

func (c *runCommand) ensureDefaults() {
	if c.newCluster == nil {
		c.newCluster = func(kc string) runCluster { return cluster.New(kc) }
	}
	if c.newBuilder == nil {
		c.newBuilder = func(progress func(string)) imageBuilder {
			return &image.Builder{Progress: progress}
		}
	}
}

func (c *runCommand) Run(ctx context.Context, env *Env, args []string) error {
	if len(args) != 2 {
		return usagef("run takes an instance and a repository, e.g. 'farcast run prod github.com/user/repo'")
	}
	name := args[0]
	c.ensureDefaults()

	repo, err := repoURL(args[1])
	if err != nil {
		return err
	}
	meta, err := env.ConfigDir.LoadInstanceMetadata(name)
	if err != nil {
		return fmt.Errorf("load instance %q: %w", name, err)
	}
	if meta.Registry == nil || meta.Registry.Prefix == "" {
		return fmt.Errorf("instance %q has no image registry recorded; run 'farcast connect %s' first", name, name)
	}
	// Checked before anything is fetched. An unusable namespace found after
	// the read and the builds would have cost real money to discover.
	if c.namespace != "" {
		if err := validNamespace(c.namespace); err != nil {
			return usagef("namespace %q: %v", c.namespace, err)
		}
		if c.namespace == tcdeploy.DefaultNamespace {
			return usagef("refusing to deploy applications into %q; it holds the instance's own components, "+
				"and mixing them makes the tier labels a cost shutdown reads harder to trust than they should be",
				tcdeploy.DefaultNamespace)
		}
	}

	fetcher, err := resolveToolchainImage(ctx, env, meta, fetcherKind, c.fetcherImage, c.newBuilder)
	if err != nil {
		return err
	}
	builder, err := resolveToolchainImage(ctx, env, meta, builderKind, c.builderImage, c.newBuilder)
	if err != nil {
		return err
	}

	cl := c.newCluster(env.ConfigDir.InstanceKubeconfigPath(name))

	// 1. The instance reads the manifest and reports what it read.
	read, err := readManifest(ctx, env, cl, pfetch.Config{
		Instance:    name,
		Fetcher:     fetcher,
		Repo:        repo,
		Ref:         c.ref,
		Manifest:    c.manifestPath,
		GitSecret:   c.gitSecret,
		EgressHosts: []string{hostOf(repo)},
	})
	if err != nil {
		return err
	}
	m, err := parser.Parse(read.Manifest)
	if err != nil {
		return fmt.Errorf("the manifest at %s in %s is not valid: %w", read.Report.Commit, repo, err)
	}

	namespace := c.namespace
	if namespace == "" {
		namespace = m.Name
	}

	// 2. The operator sees what it declares, and decides.
	rev := review{
		Instance: name, Repo: repo, Namespace: namespace,
		Manifest: *m, Report: read.Report,
		FatLineDeployed: meta.FatLineDeployed,
		Limit:           meta.CostLimit,
		Floor:           floorNow(meta),
	}
	ok, err := c.confirm(env, rev)
	if err != nil {
		return err
	}
	if !ok {
		fprintln(env.Err, "Aborted. Nothing was built and nothing was deployed.")
		return nil
	}

	// 3. Build each application, pinned to the commit that was approved.
	images, err := c.buildAll(ctx, env, cl, meta, builder, repo, read.Report.Commit, *m)
	if err != nil {
		return err
	}

	// 4. Mint this deployment's egress credentials and write the instance's
	//    policy, merged with every other deployment's (ADR 0013).
	doc, credentials, err := egressPolicy(ctx, cl, namespace, *m)
	if err != nil {
		return err
	}
	policyManifest, err := fldeploy.RenderPolicyConfigMap(fldeploy.DefaultNamespace, doc)
	if err != nil {
		return err
	}
	// Before the workloads, so FatLine has the chance to learn an application
	// before that application starts asking. It polls, so the window is not
	// zero — but an application that starts first is denied for a few seconds,
	// where one whose policy never arrives is denied forever.
	if err := cl.Apply(ctx, policyManifest); err != nil {
		return fmt.Errorf("write the egress policy: %w", err)
	}

	// 5. Translate and apply.
	workloads, err := c.translate(env, meta, namespace, *m, images, credentials)
	if err != nil {
		return err
	}
	if err := cl.Apply(ctx, workloads); err != nil {
		return fmt.Errorf("deploy %q: %w", namespace, err)
	}

	// 6. Meter it. An application the kernel does not count is an application
	// the cost limit does not protect against — and the limit is the pillar,
	// not the feature.
	metered, meterErr := c.meter(ctx, env, cl, meta, name, namespace)

	// Recorded before the wait: the workloads exist whether or not they come
	// up, and an instance whose local state has not heard of them is one
	// nobody will think to tear down.
	c.record(env, meta, name, fetcher, builder)

	var slow []string
	for _, app := range m.Apps {
		if err := cl.RolloutStatus(ctx, namespace, app.Name, rolloutTimeout); err != nil {
			slow = append(slow, app.Name)
			fprintf(env.Err, "%s did not roll out: %v\n", app.Name, err)
		}
	}

	return env.Printer.Print(runResult{
		Instance: name, Repo: repo, Namespace: namespace,
		Deployment: m.Name, Commit: read.Report.Commit,
		ManifestDigest: read.Report.ManifestDigest,
		Apps:           appResults(*m, images),
		Egress:         summarise(doc, namespace),
		Metered:        metered, MeterError: errString(meterErr),
		NotReady: slow,
	})
}

// buildAll builds every application in the manifest, one at a time.
//
// One at a time on purpose. A build asks for 1 vCPU and 2 GiB and Autopilot
// bills the request, so three in parallel is three times the burn for the
// length of the slowest — and a manifest with a dozen applications would open
// a hole in the cost limit large enough to matter.
func (c *runCommand) buildAll(ctx context.Context, env *Env, cl jobWaiter, meta *config.InstanceMetadata, builder, repo, commit string, m parser.Manifest) (map[string]string, error) {
	images := make(map[string]string, len(m.Apps))
	for i, app := range m.Apps {
		if isInteractive(env) || env.Verbose {
			fprintf(env.Err, "\n[%d/%d] Building %s inside %q…\n", i+1, len(m.Apps), app.Name, meta.Name)
		}
		destination := fmt.Sprintf("%s/app/%s/%s:%s", meta.Registry.Prefix, m.Name, app.Name, imageTag(shortCommit(commit)))
		manifest, err := pbuild.Render(pbuild.Config{
			Instance:   meta.Name,
			Deployment: m.Name,
			App:        app.Name,
			Builder:    builder,
			Repo:       repo,
			// The commit, never the branch. This is what makes the tree that
			// was approved the tree that is built (ADR 0010 decision 11).
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
		if err := cl.Apply(ctx, manifest); err != nil {
			return nil, fmt.Errorf("start the build of %s: %w", app.Name, err)
		}
		job := pbuild.JobName(m.Name, app.Name)
		res, err := cl.WaitJob(ctx, pbuild.Namespace, job, buildTimeout)
		if err != nil {
			return nil, fmt.Errorf("wait for the build of %s: %w", app.Name, err)
		}
		if !res.Succeeded {
			if logs, lerr := cl.JobLogs(ctx, pbuild.Namespace, job, 40); lerr == nil && strings.TrimSpace(logs) != "" {
				fprintf(env.Err, "\n%s\n", strings.TrimRight(logs, "\n"))
			}
			return nil, fmt.Errorf("the build of %s failed; nothing was deployed. Its Job survives for an hour, "+
				"so 'kubectl -n %s logs job/%s' still works", app.Name, pbuild.Namespace, job)
		}
		digest := strings.TrimSpace(res.Message)
		if !isSHA256(digest) {
			return nil, fmt.Errorf("the build of %s reported %q instead of a sha256 digest; the image may have been "+
				"pushed but cannot be pinned, and an unpinned image is not deployable (ADR 0007 decision 4)",
				app.Name, digest)
		}
		images[app.Name] = pinByDigest(destination, digest)
	}
	return images, nil
}

// translate renders the workloads, wiring storage when the instance has a key
// holder to wire it to.
func (c *runCommand) translate(env *Env, meta *config.InstanceMetadata, namespace string, m parser.Manifest, images, credentials map[string]string) ([]byte, error) {
	cfg := translate.Config{
		Manifest:    m,
		Namespace:   namespace,
		Images:      images,
		Instance:    meta.Name,
		Credentials: credentials,
	}
	if meta.Keyholder != nil && meta.Keyholder.Deployed && meta.Keyholder.Scope != "" {
		mtls, err := env.ConfigDir.LoadInstanceMTLS(meta.Name)
		if err != nil {
			return nil, fmt.Errorf("read the instance CA so applications can verify the key holder: %w", err)
		}
		cfg.StorageScope = meta.Keyholder.Scope
		cfg.StorageCAPEM = mtls.CACertPEM
		cfg.StorageServerName = identity.KeyholderServerName(meta.Name)
	}
	return translate.Render(cfg)
}

// meter adds the new namespace to what the kernel counts, reusing the same
// manifest `farcast kernel meter` applies.
//
// A failure here is reported and does not undo the deployment: the workloads
// are already running and billing, and unmetering them is not a fix for not
// being able to meter them.
func (c *runCommand) meter(ctx context.Context, env *Env, cl jobWaiter, meta *config.InstanceMetadata, name, namespace string) (bool, error) {
	if meta.Kernel == nil || !meta.Kernel.Deployed {
		return false, fmt.Errorf("instance %q has no kernel, so %q is not counted against the cost limit; "+
			"run 'farcast kernel deploy %s'", name, namespace, name)
	}
	previous := append([]string(nil), meta.Kernel.Namespaces...)
	next, added := applyMeterChange(previous, []string{namespace}, false)
	if len(added) == 0 {
		return true, nil
	}
	manifest, err := meterManifest(next, added)
	if err != nil {
		return false, err
	}
	meta.Kernel.Namespaces = next
	meta.UpdatedAt = time.Now().UTC()
	if err := env.ConfigDir.SaveInstanceMetadata(name, meta); err != nil {
		return false, fmt.Errorf("record the metered namespaces before applying them: %w", err)
	}
	if err := cl.Apply(ctx, manifest); err != nil {
		meta.Kernel.Namespaces = previous
		if saveErr := env.ConfigDir.SaveInstanceMetadata(name, meta); saveErr != nil {
			return false, fmt.Errorf("meter %q: %w (and local state could not be rolled back: %v)", namespace, err, saveErr)
		}
		return false, fmt.Errorf("meter %q: %w", namespace, err)
	}
	return true, nil
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

func (c *runCommand) confirm(env *Env, rev review) (bool, error) {
	if c.assumeYes {
		return true, nil
	}
	rev.print(env.Err)
	if !isInteractive(env) {
		return false, usagef("running a repository builds and deploys code this machine has not read; pass --yes to confirm")
	}
	return newPrompter(env.In, env.Err).yesNo(fmt.Sprintf("Deploy %q?", rev.Namespace))
}

// pinByDigest replaces a tagged reference's tag with the digest that was
// built. The tag is dropped, not kept alongside: the digest is what identifies
// the image, and a reference carrying both invites reading the wrong one.
func pinByDigest(destination, digest string) string {
	pinned := destination
	if i := strings.LastIndex(destination, ":"); i > strings.LastIndex(destination, "/") {
		pinned = destination[:i]
	}
	return pinned + "@" + digest
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

func appResults(m parser.Manifest, images map[string]string) []runApp {
	out := make([]runApp, 0, len(m.Apps))
	for _, a := range m.Apps {
		r := runApp{Name: a.Name, Image: images[a.Name]}
		for _, e := range a.External {
			r.External = append(r.External, e.Host)
		}
		out = append(out, r)
	}
	return out
}

type runApp struct {
	Name     string   `json:"name"`
	Image    string   `json:"image"`
	External []string `json:"external,omitempty"`
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
}

func (r runResult) Human(w io.Writer) error {
	fmt.Fprintf(w, "Deployed %s into %q, namespace %q\n", r.Deployment, r.Instance, r.Namespace)
	fmt.Fprintf(w, "  from    %s at %s\n", r.Repo, r.Commit)
	fmt.Fprintf(w, "  reading %s\n", r.ManifestDigest)
	for _, a := range r.Apps {
		fmt.Fprintf(w, "  %-16s %s\n", a.Name, a.Image)
	}
	// What each application may now reach, and the fact that it is per
	// application rather than per instance — which is the promise the review
	// gate makes and, until ADR 0013, the one the enforcement point could not
	// keep.
	fmt.Fprintf(w, "\nEgress: %s across %s, enforced per application.\n",
		plural(r.Egress.Hosts, "declared host", "declared hosts"),
		plural(r.Egress.Applications, "application", "applications"))
	if r.Egress.Others > 0 {
		fmt.Fprintf(w, "%s from other deployments on this instance kept their own.\n",
			plural(r.Egress.Others, "application", "applications"))
	}
	if len(r.NotReady) > 0 {
		fmt.Fprintf(w, "\nNot ready yet: %s\n", strings.Join(r.NotReady, ", "))
		fmt.Fprintf(w, "They are deployed and billing. 'farcast logs %s <app>' says why.\n", r.Instance)
	}
	if !r.Metered {
		fmt.Fprintf(w, "\nNOT METERED: %s\n", r.MeterError)
		fmt.Fprintf(w, "These applications are running and are not counted against the cost limit.\n")
	}

	// The commit and the digest are the whole of what a device that cannot
	// reach the repository can check later (ADR 0010 decision 6), so they are
	// worth telling the operator how to use rather than only printing.
	fmt.Fprintf(w, "\nTo verify out of band, from any machine that can reach the repository:\n")
	fmt.Fprintf(w, "  git ls-remote %s | grep %s\n", r.Repo, shortCommit(r.Commit))
	return nil
}

// applicationsMonthlyUSD is what a translated manifest costs standing still.
func applicationsMonthlyUSD(apps int) float64 {
	return float64(apps) * pricing.WorkloadMonthlyUSD(1, translate.RequestCPUMilli, translate.RequestMemMiB)
}
