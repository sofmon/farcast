package oci

import (
	"testing"
)

// The property the whole mirror rests on: what an operator reviewed upstream
// and what their instance runs are the same digest, checkable without trusting
// this code.
//
// Push cannot give this — it re-marshals a parsed manifest, so a byte of
// whitespace or a reordered key changes the digest. Copy PUTs the fetched
// bytes.
func TestCopyPreservesTheDigest(t *testing.T) {
	src := newFakeRegistry(t)
	dst := newFakeRegistry(t)
	seedIndexedImage(t, src, "chainguard/kaniko", "latest")

	srcRef, err := ParseReference(src.host() + "/chainguard/kaniko:latest")
	if err != nil {
		t.Fatal(err)
	}
	// The digest that must survive is the one for THIS platform, which for a
	// multi-platform source is the index's child rather than the index itself.
	upstream, err := (&Client{}).Pull(t.Context(), srcRef, linuxAMD64)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest := upstream.Digest
	if wantDigest == "" {
		t.Fatal("the source pull reported no digest, so there is nothing to compare")
	}

	dstRef, err := ParseReference(dst.host() + "/farcast-p43/system/kaniko:mirrored")
	if err != nil {
		t.Fatal(err)
	}
	// One client reaching both registries: the source anonymously, the
	// destination with whatever the instance's registry wants.
	c := &Client{}
	got, err := c.Copy(t.Context(), srcRef, dstRef, linuxAMD64)
	if err != nil {
		t.Fatal(err)
	}
	if got != wantDigest {
		t.Fatalf("mirrored digest %s, upstream %s — the reviewed reference is not the one the instance would run", got, wantDigest)
	}

	// And it is really there, pullable, and identical.
	pulled, err := c.Pull(t.Context(), dstRef.WithDigest(got), linuxAMD64)
	if err != nil {
		t.Fatalf("the mirrored image is not pullable: %v", err)
	}
	if pulled.Digest != wantDigest {
		t.Errorf("pulled %s from the mirror, want %s", pulled.Digest, wantDigest)
	}
}
