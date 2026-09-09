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

	builder, err := c.resolveBuilder(ctx, env, meta)
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
		explainPushDenial(env.Err, logs, pushGrant{
			Instance: name, Project: meta.Project, Region: meta.Region,
			Namespace: pbuild.Namespace, ServiceAccount: pbuild.ServiceAccount,
		})
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
		Project: meta.Project, Region: meta.Region,
	})
}

// resolveBuilder settles the Kaniko image, from the flag or from what this
// instance already recorded. See resolveToolchainImage for why a tag is
// reported and then refused.
func (c *buildCommand) resolveBuilder(ctx context.Context, env *Env, meta *config.InstanceMetadata) (string, error) {
	return resolveToolchainImage(ctx, env, meta, builderKind, c.builderImage, c.newBuilder)
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
	// Region completes the grant command. Without it the printed instruction
	// carried a <region> placeholder the operator had to fill in from memory,
	// on a command whose whole purpose is to be copied.
	Region string `json:"region,omitempty"`
}

func (r buildResult) Human(w io.Writer) error {
	fprintf(w, "Built %s/%s in %q\n", r.Deployment, r.App, r.Instance)
	fprintf(w, "  from   %s", r.Repo)
	if r.Ref != "" {
		fprintf(w, " at %s", r.Ref)
	}
	fprintln(w)
	fprintf(w, "  image  %s\n", r.Image)

	// The push grant is not FarCast's to apply: granting it needs permission
	// to change a repository's IAM, which this CLI's credential is not
	// required to carry — the same reasoning as the keyholder's bucket grant
	// (ADR 0008 decision 8). Without it the build fails on a 403 at push.
	fprintf(w, "\nThe builder pushes under its own cloud identity. If you have not granted it\n")
	fprintf(w, "for this instance yet, run:\n\n")
	writePushGrant(w, pushGrant{
		Instance: r.Instance, Project: r.Project, Region: r.Region,
		Namespace: r.Namespace, ServiceAccount: r.ServiceAccount,
	})
	fprintf(w, "\nThe grant is on the ONE repository, not the project.\n")
	return nil
}

func orPlaceholder(s string) string {
	if s == "" {
		return "<project>"
	}
	return s
}
