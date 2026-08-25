// Package image builds and publishes FarCast's own container images from the
// operator's machine, with no container engine anywhere in the loop (ADR 0007).
//
// The instance owns its registry, and the operator's machine is the only build
// anchor for the images the instance runs — that is what keeps the trust chain
// Git repo → operator's machine → the instance's own registry → the instance,
// with no third party in the runtime path. FarCast's system images earn that
// treatment cheaply: a static, cross-compiled Go binary laid onto a
// digest-pinned distroless base has no build steps to execute, so there is
// nothing a container engine would do here that this package cannot.
//
// The shape is therefore: compile with the local Go toolchain (the one tool a
// source-built farcast already requires), pack the binary into a deterministic
// layer, append it to the pinned base pulled through the oci package, and push
// to the instance's registry. Nothing but the base image enters from outside,
// and the base enters by digest — gcr.io is untrusted transport, not an
// authority. What comes back out is a digest-pinned reference, because a deploy
// that names a tag can be redirected by whoever can write that tag.
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

// targetPlatform is what FarCast's system images are built for. GKE Autopilot
// nodes are amd64, and a mismatch here is the classic silent failure: the
// kubelet pulls happily and the container dies with an exec format error.
var targetPlatform = oci.Platform{OS: "linux", Architecture: "amd64"}

// ErrNotFound reports that a reference does not exist in the registry. It is
// what `farcast connect`'s preflight tests for: a miss means "offer to build
// and push", while any other failure means "stop and tell the operator".
var ErrNotFound = oci.ErrNotFound

// Builder assembles and pushes FarCast's own container images without a
// container engine on the operator's machine (ADR 0007).
type Builder struct {
	// Compile builds the Go package at pkg (e.g. "./fatline/cmd/fatline") inside
	// sourceDir for linux/amd64 and returns the static binary. Nil uses the local
	// Go toolchain; tests inject a fake.
	Compile func(ctx context.Context, sourceDir, pkg string) ([]byte, error)
	// Progress, when set, receives short human-readable progress lines.
	Progress func(string)

	// base overrides the pinned base image. It is a test seam only — production
	// callers get BaseImage, which is the point of pinning it.
	base string
}

// Options describes one image build.
type Options struct {
	SourceDir  string   // repo checkout root
	Package    string   // Go package to compile, e.g. "./fatline/cmd/fatline"
	Ref        string   // target reference, e.g. <prefix>/system/fatline:<version>
	BinaryPath string   // path of the binary inside the image, e.g. "/fatline"
	Entrypoint []string // image entrypoint, e.g. []string{"/fatline"}
}

// validate rejects an incomplete build before anything is compiled, pulled, or
// billed.
func (o Options) validate() error {
	switch {
	case o.SourceDir == "":
		return errors.New("image: no source directory — the build needs a farcast checkout")
	case o.Package == "":
		return errors.New("image: no Go package to compile")
	case o.Ref == "":
		return errors.New("image: no target image reference")
	case o.BinaryPath == "" || !strings.HasPrefix(o.BinaryPath, "/"):
		return fmt.Errorf("image: binary path %q must be absolute inside the image", o.BinaryPath)
	case len(o.Entrypoint) == 0:
		return errors.New("image: no entrypoint — the distroless base defines none, so the container would have nothing to run")
	}
	return nil
}

// BuildAndPush compiles, assembles onto the digest-pinned distroless base, and
// pushes. It returns the digest-pinned reference of what it pushed.
//
// user and pass authenticate to the target registry only: for Artifact Registry
// they are the literal "oauth2accesstoken" and a short-lived access token minted
// in-process from the stored service-account key. They are scoped to that host
// so the base-image pull stays anonymous — the instance's credentials are never
// offered to a registry the operator does not own.
func (b *Builder) BuildAndPush(ctx context.Context, opts Options, user, pass string) (string, error) {
	if err := opts.validate(); err != nil {
		return "", err
	}
	target, err := oci.ParseReference(opts.Ref)
	if err != nil {
		return "", err
	}
	base, err := oci.ParseReference(b.baseRef())
	if err != nil {
		return "", fmt.Errorf("image: base image %q: %w", b.baseRef(), err)
	}
	if base.Digest == "" {
		return "", fmt.Errorf("image: base image %s is not pinned by digest", base)
	}

	b.progress("compiling %s for %s", opts.Package, targetPlatform)
	binary, err := b.compile()(ctx, opts.SourceDir, opts.Package)
	if err != nil {
		return "", err
	}
	if len(binary) == 0 {
		return "", fmt.Errorf("image: compiling %s produced an empty binary", opts.Package)
	}

	client := b.client(target.Registry, user, pass)

	b.progress("fetching base image %s", base)
	baseImage, err := client.Pull(ctx, base, targetPlatform)
	if err != nil {
		return "", fmt.Errorf("image: pull base %s: %w", base, err)
	}

	layer, err := oci.BuildLayer([]oci.File{{Path: opts.BinaryPath, Mode: binaryMode, Data: binary}})
	if err != nil {
		return "", err
	}
	assembled, err := oci.AppendLayer(baseImage, layer, oci.AppendOptions{
		Platform:   targetPlatform,
		Entrypoint: opts.Entrypoint,
		CreatedBy:  "farcast: " + opts.Package,
	})
	if err != nil {
		return "", err
	}
	b.progress("assembled %d layers, %s of new content", len(assembled.Layers), mib(len(layer.Blob)))

	b.progress("pushing %s", target)
	digest, err := client.Push(ctx, target, assembled)
	if err != nil {
		return "", fmt.Errorf("image: push %s: %w", target, err)
	}
	pinned := target.WithDigest(digest).String()
	b.progress("pushed %s", pinned)
	return pinned, nil
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

func (b *Builder) compile() func(context.Context, string, string) ([]byte, error) {
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
