package oci

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Push uploads an image and returns the digest of the manifest it wrote. That
// digest — not the tag it was pushed under — is what a deploy pins: a later
// registry compromise can move the tag, but it cannot make the old digest
// resolve to different content.
//
// Blobs already present in the target repository are skipped, which is what
// makes rebuilding cheap: only the layer holding the recompiled binary moves,
// the base's layers having been uploaded once.
func (c *Client) Push(ctx context.Context, ref Reference, im *Image) (string, error) {
	if im == nil {
		return "", fmt.Errorf("oci: nothing to push to %s", ref)
	}
	if err := im.validate(); err != nil {
		return "", err
	}
	scope := pushScope(ref.Repository)

	if err := c.pushBlob(ctx, ref, scope, im.Manifest.Config, im.Config); err != nil {
		return "", err
	}
	for _, layer := range im.Layers {
		if err := c.pushBlob(ctx, ref, scope, layer.Descriptor, layer.Blob); err != nil {
			return "", err
		}
	}

	body, err := json.Marshal(im.Manifest)
	if err != nil {
		return "", fmt.Errorf("oci: encode manifest: %w", err)
	}
	digest := digestOf(body)

	resp, err := c.do(ctx, call{
		method:   http.MethodPut,
		url:      c.manifestURL(ref),
		registry: ref.Registry,
		scope:    scope,
		header:   http.Header{"Content-Type": []string{im.Manifest.MediaType}},
		body:     body,
	})
	if err != nil {
		return "", err
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", newError("PUT manifest", ref.String(), resp)
	}
	// The registry echoes what it stored. Disagreement means it did not store
	// what we sent, so the digest we are about to hand a deploy would be wrong.
	if got := resp.Header.Get("Docker-Content-Digest"); got != "" && got != digest {
		return "", fmt.Errorf("oci: registry stored %s as %s, not the %s we pushed", ref, got, digest)
	}
	return digest, nil
}

// validate re-checks an image against its own descriptors before it leaves the
// machine. It is cheap next to the upload and it catches an assembly bug here,
// where the message is clear, rather than as a puzzling ImagePullBackOff later.
func (im *Image) validate() error {
	if im.Manifest.MediaType == "" {
		return fmt.Errorf("oci: image manifest has no media type")
	}
	if d := digestOf(im.Config); d != im.Manifest.Config.Digest {
		return fmt.Errorf("oci: image config hashes to %s but the manifest says %s", d, im.Manifest.Config.Digest)
	}
	if int64(len(im.Config)) != im.Manifest.Config.Size {
		return fmt.Errorf("oci: image config is %d bytes but the manifest says %d", len(im.Config), im.Manifest.Config.Size)
	}
	if len(im.Layers) != len(im.Manifest.Layers) {
		return fmt.Errorf("oci: image holds %d layers but the manifest lists %d", len(im.Layers), len(im.Manifest.Layers))
	}
	for i, layer := range im.Layers {
		desc := im.Manifest.Layers[i]
		if d := digestOf(layer.Blob); d != desc.Digest {
			return fmt.Errorf("oci: layer %d hashes to %s but the manifest says %s", i, d, desc.Digest)
		}
		if int64(len(layer.Blob)) != desc.Size {
			return fmt.Errorf("oci: layer %d is %d bytes but the manifest says %d", i, len(layer.Blob), desc.Size)
		}
	}
	return nil
}

// pushBlob uploads one blob unless the registry already has it.
func (c *Client) pushBlob(ctx context.Context, ref Reference, scope string, desc Descriptor, blob []byte) error {
	exists, err := c.blobExists(ctx, ref, scope, desc.Digest)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return c.uploadBlob(ctx, ref, scope, desc.Digest, blob)
}

func (c *Client) blobExists(ctx context.Context, ref Reference, scope, digest string) (bool, error) {
	resp, err := c.do(ctx, call{
		method:   http.MethodHead,
		url:      c.blobURL(ref, digest),
		registry: ref.Registry,
		scope:    scope,
	})
	if err != nil {
		return false, err
	}
	defer drain(resp)
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, newError("HEAD blob "+digest, ref.String(), resp)
	}
}

// uploadBlob performs the two-step upload: ask for a session, then write the
// whole blob in one PUT. Chunking exists for blobs too large to retry; FarCast's
// are a few megabytes, so the monolithic form is both simpler and fewer round
// trips.
func (c *Client) uploadBlob(ctx context.Context, ref Reference, scope, digest string, blob []byte) error {
	start := baseURL(ref.Registry) + "/v2/" + ref.Repository + "/blobs/uploads/"
	resp, err := c.do(ctx, call{
		method:   http.MethodPost,
		url:      start,
		registry: ref.Registry,
		scope:    scope,
	})
	if err != nil {
		return err
	}
	location := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusCreated {
		// Keep the registry's own error document: a first push against a new
		// project fails here (API not enabled, missing role, wrong repository),
		// and the registry says which far better than a bare status code.
		defer drain(resp)
		return newError("POST blob upload "+digest, ref.String(), resp)
	}
	drain(resp)
	if location == "" {
		return fmt.Errorf("oci: start upload of %s to %s: registry returned no upload location", digest, ref.Repository)
	}
	target, err := resolveLocation(start, location, ref.Registry)
	if err != nil {
		return err
	}

	put, err := c.do(ctx, call{
		method:   http.MethodPut,
		url:      appendDigestQuery(target, digest),
		registry: ref.Registry,
		scope:    scope,
		header:   http.Header{"Content-Type": []string{"application/octet-stream"}},
		body:     blob,
	})
	if err != nil {
		return err
	}
	defer drain(put)
	if put.StatusCode != http.StatusCreated && put.StatusCode != http.StatusOK {
		return newError("PUT blob "+digest, ref.String(), put)
	}
	return nil
}

// resolveLocation turns the upload Location header — which may be absolute or
// relative — into a URL to PUT to.
//
// The header is registry-chosen input that names where the blob and the
// credential go, so the resolved target is bound to the registry we are
// pushing to. Client.send enforces the same rule for every request; catching it
// here as well turns a hostile or misconfigured Location into a precise error
// naming the upload, rather than a generic refusal further down.
func resolveLocation(requestURL, location, registry string) (string, error) {
	base, err := url.Parse(requestURL)
	if err != nil {
		return "", fmt.Errorf("oci: parse upload request URL: %w", err)
	}
	loc, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("oci: parse upload location %q: %w", location, err)
	}
	target := base.ResolveReference(loc)
	// A fragment is meaningless to a registry and actively harmful here:
	// appendDigestQuery would put the required ?digest= after it, where
	// url.Parse reads the whole thing as the fragment and the parameter never
	// reaches the wire.
	target.Fragment, target.RawFragment = "", ""
	if !sameEndpoint(target.Host, registry) {
		return "", fmt.Errorf("oci: registry %s directed the upload to %s; refusing to send the blob and credential there", registry, target.Host)
	}
	return target.String(), nil
}

// appendDigestQuery adds the digest parameter without re-encoding whatever
// query the registry put in the Location header. Some registries carry opaque
// session state there, and round-tripping it through url.Values can change its
// escaping and invalidate the session.
func appendDigestQuery(rawURL, digest string) string {
	sep := "?"
	if strings.Contains(rawURL, "?") {
		sep = "&"
	}
	return rawURL + sep + "digest=" + url.QueryEscape(digest)
}
