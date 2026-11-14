// Package image publishes FarCast's own container images to the instance's
// registry from the operator's machine, with no container engine anywhere in
// the loop (ADR 0007).
//
// A released farcast pushes the components it carries. The build anchor is the
// released, reproducible layers: farcast-release compiles the four components
// with exactly go.mod's toolchain Go, packs each into a deterministic layer,
// assembles it on the digest-pinned distroless base, and compiles the layers and
// their manifest digests into farcast (ADR 0023 decision 4, amending ADR 0010
// decision 8). PushEmbedded assembles the carried layer on the same base, and
// refuses before anything is uploaded unless the result is the manifest the
// release recorded.
//
// Compiling is the --source path, the operator's own patch path, and the
// development fallback of a farcast that carries no components. It uses the Go
// on the operator's PATH under an allowlisted environment, never downloads, and
// tags what it pushes by its own digest (source-<12 hex>), so an operator build
// never overwrites the version tag.
//
// Either way, nothing but the base image enters from outside, and the base
// enters by digest: gcr.io is untrusted transport, not an authority. What comes
// back out is a digest-pinned reference, because a deploy that names a tag can
// be redirected by whoever can write that tag.
package image

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/sofmon/farcast/farsight/cli/internal/oci"
)

// BaseImage is the one external input to a FarCast system image, pinned by
// digest so that a compromise of gcr.io cannot change what FarCast ships.
// The tag is kept beside the digest for human readability only — the digest is
// what resolves. Bumping it is a deliberate, reviewed commit, exactly like a
// vendored dependency.
//
// The pin names an OCI image index; the linux/amd64 entry is selected at pull
// time (GKE Autopilot nodes are amd64).
const BaseImage = "gcr.io/distroless/static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7"

// Module is the Go module path a checkout must declare to be a FarCast source
// tree (see FindSource).
const Module = "github.com/sofmon/farcast"

// binaryMode is the permission the compiled binary carries inside the image.
// Distroless runs as a non-root user, so the bit that matters is world-execute.
const binaryMode = 0o755

// ErrNotFound reports that a reference does not exist in the registry. It is
// what `farcast connect`'s preflight tests for: a miss means "offer to build
// and push", while any other failure means "stop and tell the operator".
var ErrNotFound = oci.ErrNotFound

// Builder assembles and pushes FarCast's own container images without a
// container engine on the operator's machine (ADR 0007).
type Builder struct {
	// Compile builds the Go package at pkg (e.g. "./fatline/cmd/fatline") inside
	// sourceDir for ComponentPlatform and returns the static binary with the Go
	// release that compiled it. Nil uses the local Go toolchain; tests inject a
	// fake.
	Compile func(ctx context.Context, sourceDir, pkg string) (Binary, error)
	// Progress, when set, receives short human-readable progress lines.
	Progress func(string)

	// base overrides the pinned base image. It is a test seam only — production
	// callers get BaseImage, which is the point of pinning it.
	base string
}

// CreatedBy is the history line of a component's layer: "farcast: " + pkg.
func CreatedBy(pkg string) string {
	return "farcast: " + pkg
}

// ComponentLayer is a component's layer: one regular file at binaryPath, mode
// 0755, built by oci.BuildLayer. The one layer recipe, for the release step and
// every push.
func ComponentLayer(binaryPath string, data []byte) (oci.Layer, error) {
	return oci.BuildLayer([]oci.File{{Path: binaryPath, Mode: binaryMode, Data: data}})
}

// Assemble appends a component's layer to base for ComponentPlatform, with
// Entrypoint []string{binaryPath} and CreatedBy(pkg). The one assembly, for the
// release step and both pushes.
func Assemble(base *oci.Image, layer oci.Layer, pkg, binaryPath string) (*oci.Image, error) {
	return oci.AppendLayer(base, layer, oci.AppendOptions{
		Platform:   ComponentPlatform,
		Entrypoint: []string{binaryPath},
		CreatedBy:  CreatedBy(pkg),
	})
}

// SourceTag is the tag an operator build is pushed under: "source-" + the first
// 12 hex characters of its manifest digest.
func SourceTag(manifestDigest string) string {
	hex := strings.TrimPrefix(manifestDigest, "sha256:")
	if len(hex) > 12 {
		hex = hex[:12]
	}
	return "source-" + hex
}

// Pushed is what a push returns.
type Pushed struct {
	Ref       string // repository@sha256:…, the tag dropped
	GoVersion string // the Go release that compiled the binary in the top layer
}

// Options describes one operator build (--source, or the development fallback).
type Options struct {
	SourceDir  string // checkout root
	Package    string // e.g. "./fatline/cmd/fatline"
	Repository string // <prefix>/system/<component>, with no tag; pushed as :SourceTag(digest)
	BinaryPath string // e.g. "/fatline"; the entrypoint is []string{BinaryPath}
}

// validate rejects an incomplete build before anything is compiled, pulled, or
// billed.
//
// Repository is checked on the raw string before it is parsed, because
// oci.ParseReference fills in "latest" when a reference has neither a tag nor a
// digest: a parsed reference can never show that a tag was absent.
func (o Options) validate() error {
	switch {
	case o.SourceDir == "":
		return errors.New("image: no source directory — the build needs a farcast checkout")
	case o.Package == "":
		return errors.New("image: no Go package to compile")
	case o.Repository == "":
		return errors.New("image: no target repository")
	case strings.Contains(o.Repository, "@"):
		return fmt.Errorf("image: repository %q must not carry a digest: an operator build is tagged by its own", o.Repository)
	case strings.LastIndex(o.Repository, ":") > strings.LastIndex(o.Repository, "/"):
		return fmt.Errorf("image: repository %q must not carry a tag: an operator build is tagged by its own digest", o.Repository)
	case o.BinaryPath == "" || !strings.HasPrefix(o.BinaryPath, "/"):
		return fmt.Errorf("image: binary path %q must be absolute inside the image", o.BinaryPath)
	}
	if _, err := oci.ParseReference(o.Repository); err != nil {
		return err
	}
	return nil
}

// BuildAndPush compiles, assembles onto the digest-pinned distroless base, and
// pushes under SourceTag of the manifest digest, so an operator build never
// overwrites the version tag. It returns the digest-pinned reference of what it
// pushed and the Go release that compiled it.
//
// user and pass authenticate to the target registry only: for Artifact Registry
// they are the literal "oauth2accesstoken" and a short-lived access token minted
// in-process from the stored service-account key. They are scoped to that host
// so the base-image pull stays anonymous — the instance's credentials are never
// offered to a registry the operator does not own.
func (b *Builder) BuildAndPush(ctx context.Context, opts Options, user, pass string) (Pushed, error) {
	if err := opts.validate(); err != nil {
		return Pushed{}, err
	}
	repo, err := oci.ParseReference(opts.Repository)
	if err != nil {
		return Pushed{}, err
	}
	base, err := oci.ParseReference(b.baseRef())
	if err != nil {
		return Pushed{}, fmt.Errorf("image: base image %q: %w", b.baseRef(), err)
	}
	if base.Digest == "" {
		return Pushed{}, fmt.Errorf("image: base image %s is not pinned by digest", base)
	}

	b.progress("compiling %s for %s", opts.Package, ComponentPlatform)
	bin, err := b.compile()(ctx, opts.SourceDir, opts.Package)
	if err != nil {
		return Pushed{}, err
	}
	if len(bin.Data) == 0 {
		return Pushed{}, fmt.Errorf("image: compiling %s produced an empty binary", opts.Package)
	}

	client := b.client(repo.Registry, user, pass)

	b.progress("fetching base image %s", base)
	baseImage, err := client.Pull(ctx, base, ComponentPlatform)
	if err != nil {
		return Pushed{}, fmt.Errorf("image: pull base %s: %w", base, err)
	}

	layer, err := ComponentLayer(opts.BinaryPath, bin.Data)
	if err != nil {
		return Pushed{}, err
	}
	assembled, err := Assemble(baseImage, layer, opts.Package, opts.BinaryPath)
	if err != nil {
		return Pushed{}, err
	}
	_, digest, err := assembled.ManifestBytes()
	if err != nil {
		return Pushed{}, err
	}
	b.progress("assembled %d layers, %s of new content", len(assembled.Layers), mib(len(layer.Blob)))

	target := repo
	target.Tag, target.Digest = SourceTag(digest), ""
	b.progress("pushing %s", target)
	pushed, err := client.Push(ctx, target, assembled)
	if err != nil {
		return Pushed{}, fmt.Errorf("image: push %s: %w", target, err)
	}
	if pushed != digest {
		return Pushed{}, fmt.Errorf("image: pushed %s as %s, not the %s assembled here", target, pushed, digest)
	}
	pinned := target.WithDigest(digest).String()
	b.progress("pushed %s", pinned)
	return Pushed{Ref: pinned, GoVersion: bin.GoVersion}, nil
}

// Resolve returns the digest-pinned reference for ref, or ErrNotFound.
//
// This is the preflight before a deploy: a hit is deployed by digest so a later
// registry write cannot swap the image under a running Deployment, and a miss is
// an invitation to build rather than a failure.
func (b *Builder) Resolve(ctx context.Context, ref, user, pass string) (string, error) {
	parsed, err := oci.ParseReference(ref)
	if err != nil {
		return "", err
	}
	digest, err := b.client(parsed.Registry, user, pass).Resolve(ctx, parsed)
	if err != nil {
		return "", err
	}
	return parsed.WithDigest(digest).String(), nil
}

// client builds an OCI client whose credentials reach exactly one host.
func (b *Builder) client(registry, user, pass string) *oci.Client {
	return &oci.Client{Credentials: func(host string) (string, string) {
		if host == registry {
			return user, pass
		}
		return "", ""
	}}
}

func (b *Builder) baseRef() string {
	if b.base != "" {
		return b.base
	}
	return BaseImage
}

func (b *Builder) compile() func(context.Context, string, string) (Binary, error) {
	if b.Compile != nil {
		return b.Compile
	}
	return goCompile
}

func (b *Builder) progress(format string, args ...any) {
	if b.Progress == nil {
		return
	}
	b.Progress(fmt.Sprintf(format, args...))
}

// mib renders a byte count for a progress line.
func mib(n int) string {
	return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
}

// Mirror copies a third-party image into the instance's own registry, keeping
// the digest of the platform manifest it copied.
//
// The Phase 4.3 walk found the builder [ADR 0010] decision 10 names withdrawn
// from its registry's free catalogue a week after it was reviewed, which left
// an instance unable to build anything. A third-party registry's availability
// is somebody else's policy decision, and an instance that cannot deploy
// because of one is not sovereign in the sense this project means.
//
// Source access is anonymous. Every image FarCast mirrors is a public one, and
// a credential offered to a registry that did not ask for it is a credential
// that can be collected by a registry that lies about needing it.
//
// [ADR 0010]: ../../../../docs/adr/0010-application-image-builds.md
func (b *Builder) Mirror(ctx context.Context, src, dst, dstUser, dstPass string) (string, error) {
	from, err := oci.ParseReference(src)
	if err != nil {
		return "", err
	}
	to, err := oci.ParseReference(dst)
	if err != nil {
		return "", err
	}
	if from.Registry == to.Registry && from.Repository == to.Repository {
		return "", fmt.Errorf("image: %s is already in the instance's registry", src)
	}
	b.progress("mirroring %s", src)
	digest, err := b.client(to.Registry, dstUser, dstPass).Copy(ctx, from, to, ComponentPlatform)
	if err != nil {
		return "", fmt.Errorf("mirror %s into %s: %w", src, to.Repository, err)
	}
	pinned := to.WithDigest(digest).String()
	b.progress("mirrored to %s", pinned)
	return pinned, nil
}
