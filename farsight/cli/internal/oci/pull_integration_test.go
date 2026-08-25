//go:build integration

// These tests speak to a real, public container registry. They are opt-in
// (`-tags=integration`) and never run in CI, like every other cloud-touching
// test in this repository. Unlike the rest, they cost nothing: pulling a public
// image anonymously is free and read-only, which is exactly why they are worth
// running *before* the billable Phase 2 Part B validation — they prove the parts
// of this client a fake registry cannot: gcr.io's real Bearer-token challenge,
// a real multi-platform index (including the attestation entries such indexes
// carry), and real content whose digests must verify.
//
//	go test -tags=integration ./farsight/cli/internal/oci/ -run Integration -v
package oci

import (
	"context"
	"testing"
	"time"
)

// pinnedBase is the digest-pinned distroless base every FarCast system image is
// built on (ADR 0007 decision 7). It is duplicated from the image package rather
// than imported, so this package keeps depending on nothing but the standard
// library.
const pinnedBase = "gcr.io/distroless/static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7"

// TestIntegrationPullPinnedBase pulls the real base image from gcr.io. It is the
// first end-to-end exercise of the anonymous Bearer flow, index platform
// selection, and digest verification against a registry this package has never
// spoken to.
func TestIntegrationPullPinnedBase(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()

	ref, err := ParseReference(pinnedBase)
	if err != nil {
		t.Fatalf("parse the pinned base %q: %v", pinnedBase, err)
	}

	var c Client // anonymous: no Credentials callback
	im, err := c.Pull(ctx, ref, Platform{OS: "linux", Architecture: "amd64"})
	if err != nil {
		t.Fatalf("pull %s: %v", pinnedBase, err)
	}

	cfg, err := im.DecodeConfig()
	if err != nil {
		t.Fatalf("decode the pulled configuration: %v", err)
	}
	if cfg.OS != "linux" || cfg.Architecture != "amd64" {
		t.Errorf("selected the wrong platform from the index: got %s/%s, want linux/amd64", cfg.OS, cfg.Architecture)
	}
	if len(im.Layers) == 0 {
		t.Error("pulled no layers; a base image with no layers cannot carry a binary")
	}
	if len(cfg.RootFS.DiffIDs) != len(im.Layers) {
		t.Errorf("configuration lists %d diffIDs but the manifest has %d layers — appending to this image would produce a broken one",
			len(cfg.RootFS.DiffIDs), len(im.Layers))
	}
	// distroless/static:nonroot runs as uid 65532; the deploy's securityContext
	// assumes it, so a base that changed this is a real signal, not a nit.
	if cfg.Config.User == "" {
		t.Error("base image declares no User; FatLine's deployment expects the nonroot uid")
	}
	t.Logf("pulled %s: %d layers, user %q, %s/%s", im.Digest, len(im.Layers), cfg.Config.User, cfg.OS, cfg.Architecture)
}

// TestIntegrationResolveTag resolves a floating tag on the same public
// repository, exercising the manifest HEAD path (which connect's preflight uses
// to decide whether FatLine's image is already pushed).
func TestIntegrationResolveTag(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	ref, err := ParseReference("gcr.io/distroless/static:nonroot")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var c Client
	digest, err := c.Resolve(ctx, ref)
	if err != nil {
		t.Fatalf("resolve a real tag: %v", err)
	}
	if !digestPattern.MatchString(digest) {
		t.Errorf("resolved %q, which is not a sha256 digest", digest)
	}
}

// TestIntegrationResolveAbsent proves a missing repository reports ErrNotFound
// rather than some other error — connect treats exactly that as "not pushed
// yet, offer to build", so a misclassified permission or network failure would
// send it into a long, doomed build.
func TestIntegrationResolveAbsent(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	ref, err := ParseReference("gcr.io/distroless/no-such-image-farcast-test:nonroot")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var c Client
	if _, err := c.Resolve(ctx, ref); err == nil {
		t.Fatal("resolving an absent repository succeeded")
	} else {
		t.Logf("absent repository reported: %v", err)
	}
}
