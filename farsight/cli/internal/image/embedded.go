package image

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/sofmon/farcast/farsight/cli/internal/oci"
)

// ErrNotTheReleasedImage reports that the image assembled from a carried layer
// is not the one this farcast was released with. Nothing has been uploaded when
// it is returned.
var ErrNotTheReleasedImage = errors.New("image: not the image this farcast was released with")

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// EmbeddedOptions describes pushing a component this executable carries.
type EmbeddedOptions struct {
	Ref         string // <prefix>/system/<component>:<version>, the tag it is pushed under
	Package     string
	BinaryPath  string
	Layer       []byte // the carried gzip'd tar
	LayerDigest string // the compiled-in digests, from components.Artifact
	LayerSize   int64
	DiffID      string
	Manifest    string
	GoVersion   string
}

// validate rejects an incomplete push before anything leaves the machine.
//
// Ref is checked on the raw string before it is parsed, because
// oci.ParseReference reads a reference with neither a tag nor a digest as
// :latest, and the carried image must never be pushed there.
func (o EmbeddedOptions) validate() error {
	switch {
	case o.Ref == "":
		return errors.New("image: no target reference")
	case strings.Contains(o.Ref, "@"):
		return fmt.Errorf("image: %s must not carry a digest: the carried image is pushed under its version tag", o.Ref)
	case strings.LastIndex(o.Ref, ":") <= strings.LastIndex(o.Ref, "/"):
		return fmt.Errorf("image: %s carries no tag: the carried image is pushed under an explicit version tag, never as latest", o.Ref)
	case o.Package == "":
		return errors.New("image: no Go package named for the carried component")
	case o.BinaryPath == "" || !strings.HasPrefix(o.BinaryPath, "/"):
		return fmt.Errorf("image: binary path %q must be absolute inside the image", o.BinaryPath)
	case len(o.Layer) == 0:
		return fmt.Errorf("image: no carried layer for %s", o.BinaryPath)
	case o.LayerSize <= 0:
		return fmt.Errorf("image: the carried %s layer's size %d is not positive", o.BinaryPath, o.LayerSize)
	}
	for _, d := range []struct{ name, value string }{
		{"layer digest", o.LayerDigest}, {"diffID", o.DiffID}, {"manifest digest", o.Manifest},
	} {
		if !digestPattern.MatchString(d.value) {
			return fmt.Errorf("image: the carried %s's %s %q is not sha256:<64 hex>", o.BinaryPath, d.name, d.value)
		}
	}
	if _, err := oci.ParseReference(o.Ref); err != nil {
		return err
	}
	return nil
}

// PushEmbedded assembles a carried component's image on the pinned base and
// pushes it under opts.Ref, after checking that the assembly is the manifest
// this farcast was released with (ADR 0023 decision 4). No request leaves the
// machine before the carried layer has been checked against its compiled-in
// digests, and nothing is uploaded before the assembled manifest has been
// compared with the released one.
//
// user and pass authenticate to the target registry only; the base is pulled
// anonymously, by digest, as BuildAndPush pulls it.
func (b *Builder) PushEmbedded(ctx context.Context, opts EmbeddedOptions, user, pass string) (Pushed, error) {
	// 1. Validation.
	if err := opts.validate(); err != nil {
		return Pushed{}, err
	}
	target, err := oci.ParseReference(opts.Ref)
	if err != nil {
		return Pushed{}, err
	}
	component := path.Base(target.Repository)

	// 2. The carried layer is the released one.
	sum := sha256.Sum256(opts.Layer)
	diffID, diffErr := oci.DiffIDOf(opts.Layer)
	if "sha256:"+hex.EncodeToString(sum[:]) != opts.LayerDigest || int64(len(opts.Layer)) != opts.LayerSize ||
		diffErr != nil || diffID != opts.DiffID {
		return Pushed{}, fmt.Errorf("image: the carried %s layer is not the one this farcast was released with; nothing was pushed", opts.BinaryPath)
	}

	// 3. The base is pinned.
	base, err := oci.ParseReference(b.baseRef())
	if err != nil {
		return Pushed{}, fmt.Errorf("image: base image %q: %w", b.baseRef(), err)
	}
	if base.Digest == "" {
		return Pushed{}, fmt.Errorf("image: base image %s is not pinned by digest", base)
	}

	// 4. Pull the base anonymously.
	client := b.client(target.Registry, user, pass)
	b.progress("fetching base image %s", base)
	baseImage, err := client.Pull(ctx, base, ComponentPlatform)
	if err != nil {
		return Pushed{}, fmt.Errorf("image: pull base %s: %w", base, err)
	}

	// 5–6. The carried layer on the base, assembled exactly as the release step
	// assembled it.
	layer := oci.Layer{
		Descriptor: oci.Descriptor{MediaType: oci.MediaTypeOCILayerGzip, Digest: opts.LayerDigest, Size: opts.LayerSize},
		Blob:       opts.Layer,
		DiffID:     opts.DiffID,
	}
	im, err := Assemble(baseImage, layer, opts.Package, opts.BinaryPath)
	if err != nil {
		return Pushed{}, err
	}

	// 7. The released manifest, before anything is uploaded.
	_, digest, err := im.ManifestBytes()
	if err != nil {
		return Pushed{}, err
	}
	if digest != opts.Manifest {
		return Pushed{}, &wrapped{
			msg: fmt.Sprintf("image: %s assembled here is %s, not the %s this farcast was released with; nothing was pushed", component, digest, opts.Manifest),
			err: ErrNotTheReleasedImage,
		}
	}

	// 8–9. Push, and hold the registry to the released digest.
	b.progress("pushing %s (carried, %s)", target, opts.GoVersion)
	pushed, err := client.Push(ctx, target, im)
	if err != nil {
		return Pushed{}, fmt.Errorf("image: push %s: %w", target, err)
	}
	if pushed != opts.Manifest {
		return Pushed{}, fmt.Errorf("image: pushed %s as %s, not the %s this farcast was released with", target, pushed, opts.Manifest)
	}

	// 10.
	pinned := target.WithDigest(opts.Manifest).String()
	b.progress("pushed %s", pinned)
	return Pushed{Ref: pinned, GoVersion: opts.GoVersion}, nil
}
