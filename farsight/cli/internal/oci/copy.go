package oci

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// Copy mirrors one platform's image from src to dst, byte for byte.
//
// It exists because a third-party registry's availability is a policy decision
// somebody else makes. The Phase 4.3 walk found the builder [ADR 0010]
// decision 10 chose withdrawn from its registry's free catalogue a week after
// it was reviewed, which stopped an instance being able to build anything.
// Mirroring a reviewed image into the instance's own registry ends that
// dependency.
//
// The manifest is PUT exactly as it was fetched rather than re-encoded, so its
// digest is preserved and checking the copy needs no trust in this code. Push
// cannot do that — it re-marshals a parsed manifest, which is right for an
// image assembled here and wrong for a copy.
//
// What is preserved is the digest of the manifest actually copied, and for a
// multi-platform source that is the PLATFORM manifest, not the index. An index
// is resolved to plat first, because what a cluster runs is one platform's
// image and copying an index would drag in architectures nothing here will
// ever pull. So an operator verifying a mirror follows two hops — the reviewed
// index, its entry for this platform, then the instance — and the second hop
// is the digest this returns. Callers should report both rather than implying
// one number covers it.
//
// [ADR 0010]: ../../../../docs/adr/0010-application-image-builds.md
func (c *Client) Copy(ctx context.Context, src, dst Reference, plat Platform) (string, error) {
	body, mediaType, digest, err := c.fetchManifest(ctx, src)
	if err != nil {
		return "", err
	}
	if mediaType == MediaTypeOCIIndex || mediaType == MediaTypeDockerIndex {
		var idx Index
		if err := json.Unmarshal(body, &idx); err != nil {
			return "", fmt.Errorf("oci: decode index %s: %w", src, err)
		}
		desc, err := selectPlatform(idx.Manifests, plat)
		if err != nil {
			return "", fmt.Errorf("oci: %s: %w", src, err)
		}
		src = src.WithDigest(desc.Digest)
		body, mediaType, digest, err = c.fetchManifest(ctx, src)
		if err != nil {
			return "", err
		}
		if mediaType == MediaTypeOCIIndex || mediaType == MediaTypeDockerIndex {
			return "", fmt.Errorf("oci: %s: index entry %s is itself an index", src, desc.Digest)
		}
	}

	var m Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return "", fmt.Errorf("oci: decode manifest %s: %w", src, err)
	}
	if m.Config.Digest == "" {
		return "", fmt.Errorf("oci: manifest %s has no config descriptor", src)
	}
	if m.MediaType == "" {
		m.MediaType = mediaType
	}

	// Every blob first. A manifest naming a blob the registry does not hold is
	// an image that fails at pull time, in the cluster, as an
	// ImagePullBackOff that says nothing about why.
	scope := pushScope(dst.Repository)
	for _, desc := range append([]Descriptor{m.Config}, m.Layers...) {
		blob, err := c.fetchBlob(ctx, src, desc)
		if err != nil {
			return "", err
		}
		if err := c.pushBlob(ctx, dst, scope, desc, blob); err != nil {
			return "", err
		}
	}

	resp, err := c.do(ctx, call{
		method:   http.MethodPut,
		url:      c.manifestURL(dst),
		registry: dst.Registry,
		scope:    scope,
		header:   http.Header{"Content-Type": []string{mediaType}},
		body:     body,
	})
	if err != nil {
		return "", err
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", newError("PUT manifest", dst.String(), resp)
	}
	// The whole point of copying the bytes rather than re-encoding them. If the
	// destination stored something under a different digest, the reference the
	// operator reviewed upstream is not the reference their instance runs, and
	// the mirror has quietly become a different image.
	if got := resp.Header.Get("Docker-Content-Digest"); got != "" && got != digest {
		return "", fmt.Errorf("oci: mirrored %s to %s but the registry stored it as %s; "+
			"the copy is not the image that was reviewed", src, digest, got)
	}
	return digest, nil
}
