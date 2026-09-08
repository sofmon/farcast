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
	for _, m := range []struct {
		kind toolchainKind
		src  string
		path string
	}{
		{builderKind, c.builder, "kaniko"},
		{fetcherKind, c.fetcher, "git"},
	} {
		if m.src == "" {
			continue
		}
		if !isDigestPinned(m.src) {
			pinned, rerr := b.Resolve(ctx, m.src, "", "")
			if rerr != nil {
				return fmt.Errorf("resolve the %s image %q: %w", m.kind.what, m.src, rerr)
			}
			return usagef("--%s %q is a tag, not a digest.\nIt resolves today to:\n\n  %s\n\n"+
				"Pass that. Mirroring an unreviewed tag would copy whatever it points at today "+
				"into the one registry your instance runs code from.", m.kind.what, m.src, pinned)
		}
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
		fmt.Fprintf(w, "Mirrored the %s into %q\n", m.Kind, r.Instance)
		fmt.Fprintf(w, "  from  %s\n", m.From)
		fmt.Fprintf(w, "  to    %s\n", m.To)
	}
	if r.Toolchain == nil || (r.Toolchain.Builder == "" && r.Toolchain.Fetcher == "") {
		fmt.Fprintf(w, "\nNothing recorded for %q yet. 'farcast run' will ask for both images.\n", r.Instance)
		return nil
	}
	if len(r.Mirrored) > 0 {
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "Recorded for %q:\n", r.Instance)
	if r.Toolchain.Builder != "" {
		fmt.Fprintf(w, "  builder  %s\n", r.Toolchain.Builder)
	}
	if r.Toolchain.Fetcher != "" {
		fmt.Fprintf(w, "  fetcher  %s\n", r.Toolchain.Fetcher)
	}
	if len(r.Mirrored) > 0 {
		// The mirror keeps the digest of the platform manifest it copied, and
		// saying how to check that is the difference between a verifiable
		// claim and a request for trust.
		fmt.Fprintf(w, "\nEach digest above is the upstream image's own, for linux/amd64. To check one\n")
		fmt.Fprintf(w, "against where it came from, resolve the upstream reference for that platform\n")
		fmt.Fprintf(w, "and compare — nothing here has to be believed.\n")
	}
	return nil
}
