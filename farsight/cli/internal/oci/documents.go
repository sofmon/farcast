package oci

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
)

// maxDiffIDBytes bounds how much DiffIDOf decompresses: a layer is a few
// megabytes, and a gzip stream that expands past this is refused rather than
// hashed for ever.
const maxDiffIDBytes = 1 << 30

// ManifestBytes is the manifest exactly as Push sends it, and its digest. Push
// calls it, so a digest computed before a push is the digest that push
// produces: that is what lets a released farcast compare an image it has
// assembled with the one it was released with before anything is uploaded
// (ADR 0023 decision 4).
func (im *Image) ManifestBytes() (body []byte, digest string, err error) {
	if im == nil {
		return nil, "", errors.New("oci: no image to encode")
	}
	body, err = json.Marshal(im.Manifest)
	if err != nil {
		return nil, "", fmt.Errorf("oci: encode manifest: %w", err)
	}
	return body, digestOf(body), nil
}

// ImageFromDocuments assembles an image's metadata, with no layer bytes, from
// its documents, verified as Pull verifies them:
//   - index (nil when pin names a manifest): sha256(index) == pin.Digest; its plat entry selected;
//   - manifest: its digest == that entry's (or the pin's); not itself an index;
//   - config: its digest and size == manifest.Config.
//
// Layers carry their descriptors and the positional diffIDs from the config;
// Blob is nil. Image.Digest is the manifest digest.
//
// It is what lets a manifest digest be computed offline, from documents
// committed beside the pin, and it trusts nothing but the pin: a document that
// does not chain to it is refused, naming the link that broke.
func ImageFromDocuments(pin Reference, index, manifest, config []byte, plat Platform) (*Image, error) {
	if !digestPattern.MatchString(pin.Digest) {
		return nil, fmt.Errorf("oci: %s is not pinned by digest, so its documents cannot be verified", pin)
	}

	wantManifest := pin.Digest
	var wantManifestSize int64 = -1
	if index != nil {
		if d := digestOf(index); d != pin.Digest {
			return nil, fmt.Errorf("oci: the index of %s hashes to %s, not the pinned digest", pin, d)
		}
		mt, err := detectMediaType("", index)
		if err != nil {
			return nil, fmt.Errorf("oci: the index of %s: %w", pin, err)
		}
		if mt != MediaTypeOCIIndex && mt != MediaTypeDockerIndex {
			return nil, fmt.Errorf("oci: the pinned document of %s is a %s, not an index", pin, mt)
		}
		var idx Index
		if err := json.Unmarshal(index, &idx); err != nil {
			return nil, fmt.Errorf("oci: decode the index of %s: %w", pin, err)
		}
		desc, err := selectPlatform(idx.Manifests, plat)
		if err != nil {
			return nil, fmt.Errorf("oci: the index of %s: %w", pin, err)
		}
		wantManifest, wantManifestSize = desc.Digest, desc.Size
	}

	if d := digestOf(manifest); d != wantManifest {
		return nil, fmt.Errorf("oci: the %s manifest of %s hashes to %s, not the %s its pin names", plat, pin, d, wantManifest)
	}
	if wantManifestSize >= 0 && int64(len(manifest)) != wantManifestSize {
		return nil, fmt.Errorf("oci: the %s manifest of %s is %d bytes, not the %d the index says", plat, pin, len(manifest), wantManifestSize)
	}
	mt, err := detectMediaType("", manifest)
	if err != nil {
		return nil, fmt.Errorf("oci: the %s manifest of %s: %w", plat, pin, err)
	}
	if mt == MediaTypeOCIIndex || mt == MediaTypeDockerIndex {
		return nil, fmt.Errorf("oci: %s: index entry %s is itself an index", pin, wantManifest)
	}
	var m Manifest
	if err := json.Unmarshal(manifest, &m); err != nil {
		return nil, fmt.Errorf("oci: decode the %s manifest of %s: %w", plat, pin, err)
	}
	if m.MediaType == "" {
		m.MediaType = mt
	}
	if !digestPattern.MatchString(m.Config.Digest) {
		return nil, fmt.Errorf("oci: the manifest of %s names config %q, which is not a sha256 digest", pin, m.Config.Digest)
	}

	if d := digestOf(config); d != m.Config.Digest {
		return nil, fmt.Errorf("oci: the config of %s hashes to %s, not the %s its manifest names", pin, d, m.Config.Digest)
	}
	if int64(len(config)) != m.Config.Size {
		return nil, fmt.Errorf("oci: the config of %s is %d bytes, not the %d its manifest says", pin, len(config), m.Config.Size)
	}
	var parsed ImageConfig
	if err := json.Unmarshal(config, &parsed); err != nil {
		return nil, fmt.Errorf("oci: decode the config of %s: %w", pin, err)
	}
	if len(parsed.RootFS.DiffIDs) != len(m.Layers) {
		return nil, fmt.Errorf("oci: the config of %s lists %d diffIDs for %d layers", pin, len(parsed.RootFS.DiffIDs), len(m.Layers))
	}

	layers := make([]Layer, 0, len(m.Layers))
	for i, desc := range m.Layers {
		if !digestPattern.MatchString(desc.Digest) {
			return nil, fmt.Errorf("oci: the manifest of %s lists layer %q, which is not a sha256 digest", pin, desc.Digest)
		}
		layers = append(layers, Layer{Descriptor: desc, DiffID: parsed.RootFS.DiffIDs[i]})
	}
	return &Image{Manifest: m, Config: slices.Clone(config), Layers: layers, Digest: wantManifest}, nil
}

// Documents fetches pin's index (when it is one), its plat manifest and its
// config, verified as ImageFromDocuments verifies them. Used only by
// 'farcast-release base -write'.
func (c *Client) Documents(ctx context.Context, pin Reference, plat Platform) (index, manifest, config []byte, err error) {
	if !digestPattern.MatchString(pin.Digest) {
		return nil, nil, nil, fmt.Errorf("oci: %s is not pinned by digest, so its documents cannot be verified", pin)
	}
	body, mt, _, err := c.fetchManifest(ctx, pin)
	if err != nil {
		return nil, nil, nil, err
	}
	manifest = body
	if mt == MediaTypeOCIIndex || mt == MediaTypeDockerIndex {
		index = body
		var idx Index
		if err := json.Unmarshal(index, &idx); err != nil {
			return nil, nil, nil, fmt.Errorf("oci: decode index %s: %w", pin, err)
		}
		desc, err := selectPlatform(idx.Manifests, plat)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("oci: %s: %w", pin, err)
		}
		manifest, mt, _, err = c.fetchManifest(ctx, pin.WithDigest(desc.Digest))
		if err != nil {
			return nil, nil, nil, err
		}
		if mt == MediaTypeOCIIndex || mt == MediaTypeDockerIndex {
			return nil, nil, nil, fmt.Errorf("oci: %s: index entry %s is itself an index", pin, desc.Digest)
		}
	}
	var m Manifest
	if err := json.Unmarshal(manifest, &m); err != nil {
		return nil, nil, nil, fmt.Errorf("oci: decode manifest %s: %w", pin, err)
	}
	config, err = c.fetchBlob(ctx, pin, m.Config)
	if err != nil {
		return nil, nil, nil, err
	}
	if _, err := ImageFromDocuments(pin, index, manifest, config, plat); err != nil {
		return nil, nil, nil, err
	}
	return index, manifest, config, nil
}

// DiffIDOf is sha256 over a gzip layer's uncompressed bytes. It reads at most
// 1 GiB uncompressed and refuses beyond that.
func DiffIDOf(gz []byte) (string, error) {
	return diffIDOf(gz, maxDiffIDBytes)
}

func diffIDOf(gz []byte, limit int64) (string, error) {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return "", fmt.Errorf("oci: the layer is not gzip: %w", err)
	}
	defer func() { _ = zr.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(zr, limit+1))
	if err != nil {
		return "", fmt.Errorf("oci: decompress the layer: %w", err)
	}
	if n > limit {
		return "", fmt.Errorf("oci: the layer decompresses to more than %d bytes", limit)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
