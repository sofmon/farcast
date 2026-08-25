package oci

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// maxManifestSize bounds a manifest read. Manifests are kilobytes; the ceiling
// exists so a hostile registry cannot stream an unbounded "manifest" into
// memory, and it is deliberately separate from the blob ceiling so tightening
// the latter cannot break a legitimate pull.
const maxManifestSize = 8 << 20

// acceptManifest is the Accept header sent with every manifest request. Listing
// both flavours of manifest and both flavours of index lets one code path
// handle an OCI base (gcr.io's distroless) and a Docker-flavoured one without
// the caller knowing which it asked for.
var acceptManifest = strings.Join([]string{
	MediaTypeOCIIndex,
	MediaTypeOCIManifest,
	MediaTypeDockerIndex,
	MediaTypeDockerManifest,
}, ", ")

// Resolve returns the manifest digest of ref, or an error wrapping ErrNotFound
// when the reference does not exist.
//
// This is the preflight `farcast connect` runs before deploying: present means
// deploy pinned by digest, absent means build and push in place. The two
// outcomes must be distinguishable from a permission failure, which is why a
// miss is a typed sentinel and everything else is an error with the registry's
// own words attached.
func (c *Client) Resolve(ctx context.Context, ref Reference) (string, error) {
	u := c.manifestURL(ref)
	header := http.Header{"Accept": []string{acceptManifest}}
	resp, err := c.do(ctx, call{
		method:   http.MethodHead,
		url:      u,
		registry: ref.Registry,
		scope:    pullScope(ref.Repository),
		header:   header,
	})
	if err != nil {
		return "", err
	}
	switch resp.StatusCode {
	case http.StatusOK:
		digest := resp.Header.Get("Docker-Content-Digest")
		drain(resp)
		if digestPattern.MatchString(digest) {
			if ref.Digest != "" && digest != ref.Digest {
				return "", fmt.Errorf("oci: registry answered %s with digest %s", ref, digest)
			}
			return digest, nil
		}
		// A registry that omits the digest header is still conformant; fall
		// back to hashing the manifest ourselves, which is the authoritative
		// answer anyway.
	case http.StatusNotFound:
		defer drain(resp)
		return "", fmt.Errorf("oci: %s: %w", ref, ErrNotFound)
	default:
		defer drain(resp)
		return "", newError("HEAD manifest", ref.String(), resp)
	}
	_, _, digest, err := c.fetchManifest(ctx, ref)
	return digest, err
}

// Pull fetches ref into memory, selecting plat when ref names a multi-platform
// index. The returned image carries every layer's bytes so it can be re-pushed
// to a different registry (ADR 0007's cross-registry copy: an untrusted public
// base becomes content in the instance's own registry).
//
// Nothing the registry says is taken on trust: the manifest is checked against
// a pinned digest when one was given, each child manifest against the
// descriptor that referenced it, and every blob against its own descriptor.
func (c *Client) Pull(ctx context.Context, ref Reference, plat Platform) (*Image, error) {
	body, mediaType, digest, err := c.fetchManifest(ctx, ref)
	if err != nil {
		return nil, err
	}
	if mediaType == MediaTypeOCIIndex || mediaType == MediaTypeDockerIndex {
		var idx Index
		if err := json.Unmarshal(body, &idx); err != nil {
			return nil, fmt.Errorf("oci: decode index %s: %w", ref, err)
		}
		desc, err := selectPlatform(idx.Manifests, plat)
		if err != nil {
			return nil, fmt.Errorf("oci: %s: %w", ref, err)
		}
		child := ref.WithDigest(desc.Digest)
		body, mediaType, digest, err = c.fetchManifest(ctx, child)
		if err != nil {
			return nil, err
		}
		if mediaType == MediaTypeOCIIndex || mediaType == MediaTypeDockerIndex {
			return nil, fmt.Errorf("oci: %s: index entry %s is itself an index", ref, desc.Digest)
		}
	}

	var m Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("oci: decode manifest %s: %w", ref, err)
	}
	if m.MediaType == "" {
		// Older Docker manifests carry the media type only in the response
		// header; record it so the assembled image keeps the base's flavour.
		m.MediaType = mediaType
	}
	if m.Config.Digest == "" {
		return nil, fmt.Errorf("oci: manifest %s has no config descriptor", ref)
	}

	cfg, err := c.fetchBlob(ctx, ref, m.Config)
	if err != nil {
		return nil, err
	}
	var parsed ImageConfig
	if err := json.Unmarshal(cfg, &parsed); err != nil {
		return nil, fmt.Errorf("oci: decode image config %s: %w", ref, err)
	}

	layers := make([]Layer, 0, len(m.Layers))
	for i, desc := range m.Layers {
		blob, err := c.fetchBlob(ctx, ref, desc)
		if err != nil {
			return nil, err
		}
		layer := Layer{Descriptor: desc, Blob: blob}
		// diffIDs are positional: rootfs.diff_ids[i] is the uncompressed digest
		// of layers[i]. Carrying them makes an appended image's config
		// verifiable without decompressing the base again.
		if i < len(parsed.RootFS.DiffIDs) {
			layer.DiffID = parsed.RootFS.DiffIDs[i]
		}
		layers = append(layers, layer)
	}

	return &Image{Manifest: m, Config: cfg, Layers: layers, Digest: digest}, nil
}

// fetchManifest GETs a manifest and returns its bytes, resolved media type, and
// digest. A pinned reference is verified: if the bytes do not hash to the
// requested digest the registry is lying, and the pull fails rather than
// quietly running something else.
func (c *Client) fetchManifest(ctx context.Context, ref Reference) (body []byte, mediaType, digest string, err error) {
	resp, err := c.do(ctx, call{
		method:   http.MethodGet,
		url:      c.manifestURL(ref),
		registry: ref.Registry,
		scope:    pullScope(ref.Repository),
		header:   http.Header{"Accept": []string{acceptManifest}},
	})
	if err != nil {
		return nil, "", "", err
	}
	defer drain(resp)
	if resp.StatusCode == http.StatusNotFound {
		return nil, "", "", fmt.Errorf("oci: %s: %w", ref, ErrNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", "", newError("GET manifest", ref.String(), resp)
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, maxManifestSize))
	if err != nil {
		return nil, "", "", fmt.Errorf("oci: read manifest %s: %w", ref, err)
	}
	digest = digestOf(body)
	if ref.Digest != "" && digest != ref.Digest {
		return nil, "", "", fmt.Errorf("oci: %s: content digest %s does not match the pinned digest", ref, digest)
	}
	mediaType, err = detectMediaType(resp.Header.Get("Content-Type"), body)
	if err != nil {
		return nil, "", "", fmt.Errorf("oci: %s: %w", ref, err)
	}
	return body, mediaType, digest, nil
}

// detectMediaType decides what a manifest response actually is. The
// Content-Type header is authoritative when it names a type we know; otherwise
// the document's own mediaType field, and failing that its shape, decides —
// registries and older tooling are inconsistent enough that trusting only the
// header would break real pulls.
func detectMediaType(contentType string, body []byte) (string, error) {
	mt, _, _ := strings.Cut(contentType, ";")
	switch mt = strings.TrimSpace(mt); mt {
	case MediaTypeOCIIndex, MediaTypeOCIManifest, MediaTypeDockerIndex, MediaTypeDockerManifest:
		return mt, nil
	}
	var probe struct {
		MediaType string          `json:"mediaType"`
		Manifests json.RawMessage `json:"manifests"`
		Config    json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return "", fmt.Errorf("response is not a manifest: %w", err)
	}
	switch probe.MediaType {
	case MediaTypeOCIIndex, MediaTypeOCIManifest, MediaTypeDockerIndex, MediaTypeDockerManifest:
		return probe.MediaType, nil
	}
	switch {
	case len(probe.Manifests) > 0:
		return MediaTypeOCIIndex, nil
	case len(probe.Config) > 0:
		return MediaTypeOCIManifest, nil
	}
	return "", fmt.Errorf("response media type %q is not a manifest or index", contentType)
}

// selectPlatform picks the index entry for plat. Attestation and unknown-platform
// entries simply fail to match; an outright miss lists what the index did offer,
// because "no linux/amd64 in this base" is an operator-fixable fact.
func selectPlatform(entries []Descriptor, plat Platform) (Descriptor, error) {
	var available []string
	for _, d := range entries {
		if d.Platform == nil {
			continue
		}
		available = append(available, d.Platform.String())
		if d.Platform.OS != plat.OS || d.Platform.Architecture != plat.Architecture {
			continue
		}
		if plat.Variant != "" && d.Platform.Variant != plat.Variant {
			continue
		}
		// The digest is registry-supplied and is about to be interpolated into
		// a request URL, so it must prove it is a digest before it is used.
		if !digestPattern.MatchString(d.Digest) {
			return Descriptor{}, fmt.Errorf("index entry for %s carries %q, which is not a sha256 digest", plat, d.Digest)
		}
		return d, nil
	}
	return Descriptor{}, fmt.Errorf("index has no %s entry (offers %s)", plat, strings.Join(available, ", "))
}

// fetchBlob downloads and verifies one blob. The digest is computed while the
// body streams, and a mismatch — or a body longer than the descriptor or the
// size ceiling allows — fails the pull: this is the check that makes a pinned
// base safe to fetch from a registry FarCast does not control.
func (c *Client) fetchBlob(ctx context.Context, ref Reference, desc Descriptor) ([]byte, error) {
	// Descriptor digests come from a registry-supplied manifest and are
	// interpolated into the blob URL, so they are validated before use.
	if !digestPattern.MatchString(desc.Digest) {
		return nil, fmt.Errorf("oci: manifest of %s lists %q, which is not a sha256 digest", ref, desc.Digest)
	}
	limit := c.maxBlobSize()
	if desc.Size > limit {
		return nil, fmt.Errorf("oci: blob %s is %d bytes, over the %d-byte ceiling", desc.Digest, desc.Size, limit)
	}
	resp, err := c.do(ctx, call{
		method:   http.MethodGet,
		url:      c.blobURL(ref, desc.Digest),
		registry: ref.Registry,
		scope:    pullScope(ref.Repository),
	})
	if err != nil {
		return nil, err
	}
	defer drain(resp)
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("oci: blob %s in %s: %w", desc.Digest, ref.Repository, ErrNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, newError("GET blob "+desc.Digest, ref.String(), resp)
	}

	// Pre-allocate from the descriptor, but only up to a modest cap: the size is
	// registry-supplied, and honouring it verbatim lets a hostile or broken
	// registry make this process reserve hundreds of megabytes for a response
	// that turns out to be empty. The buffer grows naturally as real bytes
	// arrive; the ceiling and the digest are what actually bound the read.
	const maxPrealloc = 1 << 20
	var buf bytes.Buffer
	buf.Grow(int(min(desc.Size, maxPrealloc)))
	hasher := sha256.New()
	n, err := io.Copy(io.MultiWriter(&buf, hasher), io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("oci: read blob %s: %w", desc.Digest, err)
	}
	if n > limit {
		return nil, fmt.Errorf("oci: blob %s exceeds the %d-byte ceiling", desc.Digest, limit)
	}
	// The descriptor's size is checked unconditionally: treating 0 as "unknown"
	// would let a descriptor opt out of the length check entirely and stream up
	// to the whole ceiling before the digest rejects it.
	if n != desc.Size {
		return nil, fmt.Errorf("oci: blob %s is %d bytes, descriptor says %d", desc.Digest, n, desc.Size)
	}
	got := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	if got != desc.Digest {
		return nil, fmt.Errorf("oci: blob content digest %s does not match descriptor %s", got, desc.Digest)
	}
	return buf.Bytes(), nil
}

func (c *Client) manifestURL(ref Reference) string {
	return baseURL(ref.Registry) + "/v2/" + ref.Repository + "/manifests/" + ref.Identifier()
}

func (c *Client) blobURL(ref Reference, digest string) string {
	return baseURL(ref.Registry) + "/v2/" + ref.Repository + "/blobs/" + digest
}

// DecodeConfig returns the modelled view of the image configuration.
func (im *Image) DecodeConfig() (ImageConfig, error) {
	var cfg ImageConfig
	if err := json.Unmarshal(im.Config, &cfg); err != nil {
		return ImageConfig{}, fmt.Errorf("oci: decode image config: %w", err)
	}
	return cfg, nil
}
