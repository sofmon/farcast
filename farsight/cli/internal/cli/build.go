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
	pbuild "github.com/sofmon/farcast/planck/build"
)

const (
	// buildTimeout bounds how long the CLI waits. The Job carries its own,
	// shorter deadline; this is the operator's patience, not the build's.
	buildTimeout = 35 * time.Minute

	// kanikoRepo is where the maintained Kaniko lives. Google archived the
	// original in June 2025 (ADR 0010 decision 10); this is the fork.
	//
	// It is a repository, deliberately not a pinned reference. Shipping a
	// digest nobody in this project has verified would be worse than asking
	// for one — see the refusal in resolveBuilder.
	kanikoRepo = "cgr.dev/chainguard/kaniko"
)

// jobWaiter is the slice of the cluster client a build needs (injectable).
type jobWaiter interface {
	Apply(ctx context.Context, manifests []byte) error
	WaitJob(ctx context.Context, namespace, name string, timeout time.Duration) (cluster.JobResult, error)
	JobLogs(ctx context.Context, namespace, job string, lines int) (string, error)
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

	// Seams, overridable in tests.
	newCluster func(kubeconfigPath string) jobWaiter
	newBuilder func(progress func(string)) imageBuilder
}

func (*buildCommand) Name() string { return "build" }
func (*buildCommand) Synopsis() string {
	return "Build an application's image inside the instance"
}

func (*buildCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast build <instance> --repo <url> --app <name> --builder-image <ref@sha256:…>
                     [--ref <git-ref>] [--containerfile <path>] [--context <subpath>]
                     [--git-secret <name>] [--tag <tag>] [-y]

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

At 4.3 'farcast run' will read the manifest and call this for each app; today
the app and its Containerfile are given explicitly.`)
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
}

func (c *buildCommand) ensureDefaults() {
	if c.newCluster == nil {
		c.newCluster = func(kc string) jobWaiter { return cluster.New(kc) }
	}
	if c.newBuilder == nil {
		c.newBuilder = func(progress func(string)) imageBuilder {
			return &image.Builder{Progress: progress}
		}
	}
}

func (c *buildCommand) Run(ctx context.Context, env *Env, args []string) error {
	if len(args) != 1 {
		return usagef("build takes one instance argument")
	}
	name := args[0]
	c.ensureDefaults()

	meta, err := env.ConfigDir.LoadInstanceMetadata(name)
	if err != nil {
		return fmt.Errorf("load instance %q: %w", name, err)
	}
	if c.repo == "" || c.app == "" {
		return usagef("--repo and --app are required")
	}
	if meta.Registry == nil || meta.Registry.Prefix == "" {
		return fmt.Errorf("instance %q has no image registry recorded; run 'farcast connect %s' first", name, name)
	}

	builder, err := c.resolveBuilder(ctx, env)
	if err != nil {
		return err
	}

	deployment := meta.Name
	tag := c.tag
	if tag == "" {
		tag = imageTag(refTag(c.ref))
	}
	destination := fmt.Sprintf("%s/app/%s/%s:%s", meta.Registry.Prefix, deployment, c.app, tag)

	manifest, err := pbuild.Render(pbuild.Config{
		Instance:       name,
		Deployment:     deployment,
		App:            c.app,
		Builder:        builder,
		Repo:           c.repo,
		Ref:            c.ref,
		Containerfile:  c.containerfile,
		ContextSubPath: c.contextPath,
		Destination:    destination,
		GitSecret:      c.gitSecret,
		EgressHosts:    []string{hostOf(c.repo), hostOf(meta.Registry.Prefix)},
	})
	if err != nil {
		return err
	}

	ok, err := c.confirm(env, meta, destination)
	if err != nil {
		return err
	}
	if !ok {
		fprintln(env.Err, "Aborted.")
		return nil
	}

	cl := c.newCluster(env.ConfigDir.InstanceKubeconfigPath(name))
	if err := cl.Apply(ctx, manifest); err != nil {
		return fmt.Errorf("start the build: %w", err)
	}
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
		if logs, lerr := cl.JobLogs(ctx, pbuild.Namespace, job, 40); lerr == nil && strings.TrimSpace(logs) != "" {
			fprintf(env.Err, "\n%s\n", strings.TrimRight(logs, "\n"))
		}
		return fmt.Errorf("the build of %s/%s failed; its Job survives for an hour so 'kubectl -n %s logs job/%s' still works",
			deployment, c.app, pbuild.Namespace, job)
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

	return env.Printer.Print(buildResult{
		Instance: name, App: c.app, Deployment: deployment,
		Repo: c.repo, Ref: c.ref, Tag: tag,
		Image: pinned, Builder: builder,
		ServiceAccount: pbuild.ServiceAccount, Namespace: pbuild.Namespace,
		Project: meta.Project,
	})
}

// resolveBuilder insists on a digest-pinned builder, and helps get one.
//
// The builder runs arbitrary build steps while holding a credential that can
// write to the instance's registry, so a floating tag there is the single
// worst place in FarCast to accept one. When a tag is given the CLI resolves
// it and reports the digest — then refuses, because resolving at build time is
// trust-on-first-use, not pinning: the next build would silently get whatever
// the tag points at then. ADR 0010 decision 10 wants a reviewed constant, and
// this is how the operator obtains one.
func (c *buildCommand) resolveBuilder(ctx context.Context, env *Env) (string, error) {
	ref := c.builderImage
	if ref == "" {
		return "", usagef("--builder-image is required and must be digest-pinned.\n"+
			"Kaniko was archived by Google in June 2025 and continues as a fork at %s.\n"+
			"Pass that repository with a tag once and this command will report the digest to pin.", kanikoRepo)
	}
	if isDigestPinned(ref) {
		return ref, nil
	}
	b := c.newBuilder(func(msg string) { fprintf(env.Err, "  %s\n", msg) })
	pinned, err := b.Resolve(ctx, ref, "", "")
	if err != nil {
		return "", fmt.Errorf("resolve the builder image %q: %w", ref, err)
	}
	return "", usagef("--builder-image %q is a tag, not a digest.\n"+
		"It resolves today to:\n\n  %s\n\n"+
		"Pass that, and record it: a builder image runs arbitrary build steps while holding a\n"+
		"credential for your registry, so resolving a tag on every build would mean silently\n"+
		"running whatever it points at next.", ref, pinned)
}

func isDigestPinned(ref string) bool {
	_, digest, ok := strings.Cut(ref, "@")
	return ok && isSHA256(digest)
}

// isSHA256 accepts only a complete, lowercase-hex sha256 digest.
func isSHA256(s string) bool {
	hex, ok := strings.CutPrefix(s, "sha256:")
	if !ok || len(hex) != 64 {
		return false
	}
	for i := range len(hex) {
		switch ch := hex[i]; {
		case ch >= '0' && ch <= '9', ch >= 'a' && ch <= 'f':
		default:
			return false
		}
	}
	return true
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

func (c *buildCommand) confirm(env *Env, meta *config.InstanceMetadata, destination string) (bool, error) {
	if c.assumeYes {
		return true, nil
	}
	if !isInteractive(env) {
		return false, usagef("building runs a %d vCPU / %d MiB Job in the instance until it finishes or its deadline expires; pass --yes to confirm",
			pbuild.RequestCPUMilli/1000, pbuild.RequestMemMiB)
	}
	fprintf(env.Err, "Building inside %q runs a Job requesting %dm CPU and %dMi, bounded by a %d-minute deadline.\n",
		meta.Name, pbuild.RequestCPUMilli, pbuild.RequestMemMiB, pbuild.DeadlineSeconds/60)
	fprintf(env.Err, "It pushes to %s.\n", destination)
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
}

func (r buildResult) Human(w io.Writer) error {
	fmt.Fprintf(w, "Built %s/%s in %q\n", r.Deployment, r.App, r.Instance)
	fmt.Fprintf(w, "  from   %s", r.Repo)
	if r.Ref != "" {
		fmt.Fprintf(w, " at %s", r.Ref)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  image  %s\n", r.Image)

	// The push grant is not FarCast's to apply: granting it needs permission
	// to change a repository's IAM, which this CLI's credential is not
	// required to carry — the same reasoning as the keyholder's bucket grant
	// (ADR 0008 decision 8). Without it the build fails on a 403 at push.
	fmt.Fprintf(w, "\nThe builder pushes under its own cloud identity. If you have not granted it\n")
	fmt.Fprintf(w, "for this instance yet, run:\n\n")
	fmt.Fprintf(w, "  PROJNUM=$(gcloud projects describe %s --format='value(projectNumber)')\n", orPlaceholder(r.Project))
	fmt.Fprintf(w, "  PRINCIPAL=\"principal://iam.googleapis.com/projects/$PROJNUM/locations/global/workloadIdentityPools/%s.svc.id.goog/subject/ns/%s/sa/%s\"\n",
		orPlaceholder(r.Project), r.Namespace, r.ServiceAccount)
	fmt.Fprintf(w, "  gcloud artifacts repositories add-iam-policy-binding farcast-%s \\\n", r.Instance)
	fmt.Fprintf(w, "    --location <region> --member \"$PRINCIPAL\" --role roles/artifactregistry.writer\n")
	fmt.Fprintf(w, "\nThe grant is on the ONE repository, not the project.\n")
	return nil
}

func orPlaceholder(s string) string {
	if s == "" {
		return "<project>"
	}
	return s
}
