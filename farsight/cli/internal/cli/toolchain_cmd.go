package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/image"
)

// systemPathFor is where a mirrored third-party image lands in the instance's
// own registry, beside FarCast's own components (ADR 0007 decision 6).
func systemPathFor(prefix, name string) string {
	return fmt.Sprintf("%s/system/%s", prefix, name)
}

type toolchainCommand struct {
	builder string
	fetcher string

	newBuilder   func(progress func(string)) mirroringBuilder
	openProvider providerOpener
}

// mirroringBuilder is the slice of *image.Builder this command needs.
type mirroringBuilder interface {
	Resolve(ctx context.Context, ref, user, pass string) (string, error)
	Mirror(ctx context.Context, src, dst, dstUser, dstPass string) (string, error)
}

func (*toolchainCommand) Name() string { return "toolchain" }
func (*toolchainCommand) Synopsis() string {
	return "Mirror and record the images an instance builds applications with"
}

func (*toolchainCommand) Usage() string {
	return strings.TrimSpace(`
Usage: farcast toolchain <instance> [--builder <ref@sha256:…>] [--fetcher <ref@sha256:…>]

Copy the third-party images an instance needs to read and build application
source into the instance's own registry, and record them.

With no flags, report what is recorded.

Two images are involved (ADR 0010): a builder, which executes an application's
Containerfile, and a fetcher, which has git in it and reads the manifest. They
are not FarCast's code, and both run inside the instance.

Mirroring them ends a dependency on somebody else's catalogue policy. The
Phase 4.3 walk found the builder withdrawn from its registry's free tier a week
after it was reviewed, which left the instance unable to build anything. After
mirroring, the instance pulls from its own registry with the grant it already
has, and nothing outside it has to stay available.

The copy keeps the digest of the platform manifest it copied, so a mirrored
image can be checked against the upstream one it came from without trusting
this command.`)
}

func (c *toolchainCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.builder, "builder", "", "digest-pinned builder image to mirror (Kaniko)")
	fs.StringVar(&c.fetcher, "fetcher", "", "digest-pinned fetcher image to mirror (git)")
}

func (c *toolchainCommand) ensureDefaults() {
	if c.newBuilder == nil {
		c.newBuilder = func(progress func(string)) mirroringBuilder {
			return &image.Builder{Progress: progress}
		}
	}
	if c.openProvider == nil {
		c.openProvider = defaultProviderOpener
	}
}

func (c *toolchainCommand) Run(ctx context.Context, env *Env, args []string) error {
	if len(args) != 1 {
		return usagef("toolchain takes one instance argument")
	}
	name := args[0]
	c.ensureDefaults()

	meta, err := env.ConfigDir.LoadInstanceMetadata(name)
	if err != nil {
		return fmt.Errorf("load instance %q: %w", name, err)
	}
	if c.builder == "" && c.fetcher == "" {
		return env.Printer.Print(toolchainResult{Instance: name, Toolchain: meta.Toolchain})
	}
	if meta.Registry == nil || meta.Registry.Prefix == "" {
		return fmt.Errorf("instance %q has no image registry recorded; run 'farcast connect %s' first", name, name)
	}

	b := c.newBuilder(func(msg string) { fprintf(env.Err, "  %s\n", msg) })

	// Settle every image before copying any of them.
	//
	// This used to check and mirror in one pass, so a digest-pinned builder
	// beside a tagged fetcher mirrored the builder and *then* refused. The
	// Phase 4.4 walk caught it: the command exited 2 and the instance's
	// registry held one image more than before it ran. A refusal that leaves
	// a third-party image in the one registry the instance runs code from is
	// not a refusal.
	plan, err := c.settle(ctx, b)
	if err != nil {
		return err
	}

	// The credential is minted once, held for these two pushes, and never
	// written anywhere — a push credential for the instance's registry is a
	// foothold on everything the cluster runs (ADR 0007 decision 5).
	access, err := ensureRegistry(ctx, env, name, meta, c.openProvider)
	if err != nil {
		return err
	}
	user, pass, err := access.credentials(ctx)
	if err != nil {
		return err
	}

	res := toolchainResult{Instance: name}
	for _, m := range plan {
		dst := systemPathFor(meta.Registry.Prefix, m.path) + ":" + imageTag(digestTag(m.src))
		mirrored, merr := b.Mirror(ctx, m.src, dst, user, pass)
		if merr != nil {
			return merr
		}
		recordToolchainImage(meta, m.kind, mirrored, time.Now().UTC())
		res.Mirrored = append(res.Mirrored, mirroredImage{Kind: m.kind.what, From: m.src, To: mirrored})
	}

	meta.UpdatedAt = time.Now().UTC()
	if err := env.ConfigDir.SaveInstanceMetadata(name, meta); err != nil {
		return fmt.Errorf("record the mirrored images for %q: %w", name, err)
	}
	res.Toolchain = meta.Toolchain
	return env.Printer.Print(res)
}

// mirrorRequest is one image this invocation was asked to mirror, once it has
// been checked and is safe to copy.
type mirrorRequest struct {
	kind toolchainKind
	src  string
	path string
}

// settle checks every requested image and copies none of them. It reports
// everything wrong at once: an operator who passed two tags should learn that
// from one run rather than fix the builder, run again, and be told about the
// fetcher.
func (c *toolchainCommand) settle(ctx context.Context, b mirroringBuilder) ([]mirrorRequest, error) {
	var plan []mirrorRequest
	var problems []string
	for _, m := range []mirrorRequest{
		{builderKind, c.builder, "kaniko"},
		{fetcherKind, c.fetcher, "git"},
	} {
		if m.src == "" {
			continue
		}
		if isDigestPinned(m.src) {
			plan = append(plan, m)
			continue
		}
		// Resolving is a read against the source registry: it tells the
		// operator what the tag means today without copying anything.
		pinned, err := b.Resolve(ctx, m.src, "", "")
		if err != nil {
			return nil, fmt.Errorf("resolve the %s image %q: %w", m.kind.what, m.src, err)
		}
		problems = append(problems, fmt.Sprintf(
			"--%s %q is a tag, not a digest.\nIt resolves today to:\n\n  %s\n",
			m.kind.what, m.src, pinned))
	}
	if len(problems) == 0 {
		return plan, nil
	}
	pass := "Pass that."
	if len(problems) > 1 {
		pass = "Pass those."
	}
	return nil, usagef("%s\n%s Mirroring an unreviewed tag would copy whatever it points at today "+
		"into the one registry your instance runs code from.", strings.Join(problems, "\n"), pass)
}

// digestTag turns a digest-pinned reference into a short, human-readable tag
// for the mirrored copy. The digest is what pins it; the tag is so a console
// listing is legible.
func digestTag(ref string) string {
	_, digest, ok := strings.Cut(ref, "@sha256:")
	if !ok || len(digest) < 12 {
		return "mirrored"
	}
	return digest[:12]
}

type mirroredImage struct {
	Kind string `json:"kind"`
	From string `json:"from"`
	To   string `json:"to"`
}

type toolchainResult struct {
	Instance  string            `json:"instance"`
	Mirrored  []mirroredImage   `json:"mirrored,omitempty"`
	Toolchain *config.Toolchain `json:"toolchain,omitempty"`
}

func (r toolchainResult) Human(w io.Writer) error {
	for _, m := range r.Mirrored {
		fprintf(w, "Mirrored the %s into %q\n", m.Kind, r.Instance)
		fprintf(w, "  from  %s\n", m.From)
		fprintf(w, "  to    %s\n", m.To)
	}
	if r.Toolchain == nil || (r.Toolchain.Builder == "" && r.Toolchain.Fetcher == "") {
		fprintf(w, "\nNothing recorded for %q yet. 'farcast run' will ask for both images.\n", r.Instance)
		return nil
	}
	if len(r.Mirrored) > 0 {
		fprintln(w)
	}
	fprintf(w, "Recorded for %q:\n", r.Instance)
	if r.Toolchain.Builder != "" {
		fprintf(w, "  builder  %s\n", r.Toolchain.Builder)
	}
	if r.Toolchain.Fetcher != "" {
		fprintf(w, "  fetcher  %s\n", r.Toolchain.Fetcher)
	}
	if len(r.Mirrored) > 0 {
		// The mirror keeps the digest of the platform manifest it copied, and
		// saying how to check that is the difference between a verifiable
		// claim and a request for trust.
		fprintf(w, "\nEach digest above is the upstream image's own, for linux/amd64. To check one\n")
		fprintf(w, "against where it came from, resolve the upstream reference for that platform\n")
		fprintf(w, "and compare — nothing here has to be believed.\n")
	}
	return nil
}
