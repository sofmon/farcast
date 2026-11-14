package image

import (
	"embed"
	"fmt"

	"github.com/sofmon/farcast/farsight/cli/internal/oci"
)

// baseDocuments holds the pinned base's three documents, committed under base/
// as the registry's exact bytes: the OCI index BaseImage pins (index.json), its
// linux/amd64 manifest (manifest.json) and that manifest's config
// (config.json). They let the release step, the golden tests and ./check.sh
// compute manifest digests offline (ADR 0023 M1). The distroless layer bytes
// are not committed: PushEmbedded pulls them at run time, by digest.
//
// The names are explicit, so a tree with one of them missing does not compile.
// 'farcast-release base -write' is the procedure for a base bump: change
// BaseImage, run base -write, review, commit. TestPinnedBaseChainsToBaseImage
// fails while BaseImage and these documents disagree.
//
//go:embed base/index.json base/manifest.json base/config.json
var baseDocuments embed.FS

// PinnedBase is BaseImage's linux/amd64 image from the committed documents under
// base/: manifest, config and layer descriptors, with no layer bytes, verified
// against BaseImage.
func PinnedBase() (*oci.Image, error) {
	var docs [3][]byte
	for i, name := range []string{"base/index.json", "base/manifest.json", "base/config.json"} {
		data, err := baseDocuments.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("image: read the committed %s: %w", name, err)
		}
		docs[i] = data
	}
	return pinnedBaseFrom(BaseImage, docs[0], docs[1], docs[2])
}

// pinnedBaseFrom is PinnedBase over given documents: the image they describe for
// ComponentPlatform, verified against the reference pin, which must name an
// index by digest.
func pinnedBaseFrom(pin string, index, manifest, config []byte) (*oci.Image, error) {
	ref, err := oci.ParseReference(pin)
	if err != nil {
		return nil, fmt.Errorf("image: base image %q: %w", pin, err)
	}
	if ref.Digest == "" {
		return nil, fmt.Errorf("image: base image %s is not pinned by digest", ref)
	}
	im, err := oci.ImageFromDocuments(ref, index, manifest, config, ComponentPlatform)
	if err != nil {
		return nil, fmt.Errorf("image: the committed base documents are not %s's: %w", ref, err)
	}
	return im, nil
}
