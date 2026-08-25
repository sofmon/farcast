package oci

import (
	"bytes"
	"strings"
	"testing"
)

func TestPushUploadsBlobsAndManifest(t *testing.T) {
	reg := newFakeRegistry(t)
	const repo = "proj/farcast-alpha/system/fatline"
	img := assembledImage(t)
	ref, err := ParseReference(reg.host() + "/" + repo + ":0.2.0")
	if err != nil {
		t.Fatal(err)
	}

	digest, err := (&Client{}).Push(t.Context(), ref, img)
	if err != nil {
		t.Fatal(err)
	}
	if !reg.hasBlob(repo, img.Manifest.Config.Digest) {
		t.Fatal("the config blob was not uploaded")
	}
	for i, layer := range img.Layers {
		if !reg.hasBlob(repo, layer.Descriptor.Digest) {
			t.Fatalf("layer %d was not uploaded", i)
		}
	}
	reg.mu.Lock()
	stored, ok := reg.manifests[repo+":0.2.0"]
	reg.mu.Unlock()
	if !ok {
		t.Fatal("the manifest was not stored under its tag")
	}
	if digestOf(stored.body) != digest {
		t.Fatalf("Push returned %s but the registry holds %s", digest, digestOf(stored.body))
	}
	if stored.mediaType != img.Manifest.MediaType {
		t.Fatalf("manifest stored as %q, want %q", stored.mediaType, img.Manifest.MediaType)
	}
}

func TestPushSkipsBlobsTheRegistryAlreadyHas(t *testing.T) {
	reg := newFakeRegistry(t)
	const repo = "proj/farcast-alpha/system/fatline"
	img := assembledImage(t)
	// Pretend an earlier push already put the base's layer and the config
	// there: a rebuild must move only what changed.
	reg.addBlob(repo, img.Config)
	reg.addBlob(repo, img.Layers[0].Blob)

	ref, _ := ParseReference(reg.host() + "/" + repo + ":0.2.0")
	if _, err := (&Client{}).Push(t.Context(), ref, img); err != nil {
		t.Fatal(err)
	}
	if n := reg.countCalls("POST /v2/" + repo + "/blobs/uploads/"); n != 1 {
		t.Fatalf("started %d uploads, want 1 (only the new layer)", n)
	}
	if n := reg.countCalls("HEAD /v2/" + repo + "/blobs/"); n != len(img.Layers)+1 {
		t.Fatalf("made %d existence checks, want one per blob", n)
	}
}

func TestPushRejectsInconsistentImage(t *testing.T) {
	reg := newFakeRegistry(t)
	img := assembledImage(t)
	img.Manifest.Layers[1].Digest = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	ref, _ := ParseReference(reg.host() + "/proj/farcast-alpha/system/fatline:0.2.0")

	_, err := (&Client{}).Push(t.Context(), ref, img)
	if err == nil || !strings.Contains(err.Error(), "layer 1 hashes to") {
		t.Fatalf("err = %v, want the mismatch caught before anything is uploaded", err)
	}
	if len(reg.calls()) != 0 {
		t.Fatalf("a malformed image reached the network: %v", reg.calls())
	}
}

func TestPushRejectsDigestDisagreement(t *testing.T) {
	reg := newFakeRegistry(t)
	// A registry that stores something other than what we sent must not hand a
	// deploy a digest that resolves to content we never built.
	reg.putDigestLie = "sha256:0000000000000000000000000000000000000000000000000000000000000002"
	ref, _ := ParseReference(reg.host() + "/proj/farcast-alpha/system/fatline:0.2.0")

	_, err := (&Client{}).Push(t.Context(), ref, assembledImage(t))
	if err == nil || !strings.Contains(err.Error(), "not the") {
		t.Fatalf("err = %v, want the stored digest to be checked against ours", err)
	}
}

// TestCrossRegistryRoundTrip is the whole ADR 0007 data plane in one test: pull
// a multi-platform base from an anonymous public registry, lay FarCast's binary
// on top, push to an authenticated registry the instance owns, and read back
// what the cluster would pull.
func TestCrossRegistryRoundTrip(t *testing.T) {
	public := newFakeRegistry(t)
	seedIndexedImage(t, public, "distroless/static", "nonroot")

	instance := newFakeRegistry(t)
	instance.mode = authBearer
	instance.user, instance.pass = "oauth2accesstoken", "ya29.short-lived"

	instanceHost := instance.host()
	c := &Client{Credentials: func(registry string) (string, string) {
		if registry == instanceHost {
			return instance.user, instance.pass
		}
		return "", "" // the public base is fetched anonymously
	}}

	baseRef, _ := ParseReference(public.host() + "/distroless/static:nonroot")
	base, err := c.Pull(t.Context(), baseRef, linuxAMD64)
	if err != nil {
		t.Fatalf("pull base: %v", err)
	}

	binary := []byte("\x7fELF fatline")
	layer, err := BuildLayer([]File{{Path: "/fatline", Mode: 0o755, Data: binary}})
	if err != nil {
		t.Fatal(err)
	}
	img, err := AppendLayer(base, layer, AppendOptions{
		Platform:   linuxAMD64,
		Entrypoint: []string{"/fatline"},
		CreatedBy:  "farcast: fatline",
	})
	if err != nil {
		t.Fatal(err)
	}

	targetRef, _ := ParseReference(instanceHost + "/proj/farcast-alpha/system/fatline:0.2.0")
	digest, err := c.Push(t.Context(), targetRef, img)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if public.sawCredentials() {
		t.Fatal("the instance's registry credentials were offered to the public base registry")
	}

	pulled, err := c.Pull(t.Context(), targetRef.WithDigest(digest), linuxAMD64)
	if err != nil {
		t.Fatalf("pull back what was pushed: %v", err)
	}
	if pulled.Digest != digest {
		t.Fatalf("read back %s, pushed %s", pulled.Digest, digest)
	}
	cfg, err := pulled.DecodeConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OS != "linux" || cfg.Architecture != "amd64" {
		t.Fatalf("config platform = %s/%s", cfg.OS, cfg.Architecture)
	}
	if len(cfg.Config.Entrypoint) != 1 || cfg.Config.Entrypoint[0] != "/fatline" {
		t.Fatalf("entrypoint = %v", cfg.Config.Entrypoint)
	}
	if len(cfg.RootFS.DiffIDs) != 2 || cfg.RootFS.DiffIDs[1] != layer.DiffID {
		t.Fatalf("rootfs = %v, want the appended diffID last", cfg.RootFS.DiffIDs)
	}
	if len(pulled.Layers) != 2 {
		t.Fatalf("pulled %d layers, want the base's plus ours", len(pulled.Layers))
	}
	// The base's layer moved across registries byte-for-byte, so its digest —
	// and anything pinned to it — survived the copy.
	if !bytes.Equal(pulled.Layers[0].Blob, base.Layers[0].Blob) {
		t.Fatal("the base layer was not copied verbatim")
	}
	if !bytes.Contains(gunzip(t, pulled.Layers[1].Blob), binary) {
		t.Fatal("the compiled binary is not in the appended layer")
	}
}

// assembledImage returns a two-layer image ready to push.
func assembledImage(t *testing.T) *Image {
	t.Helper()
	base := handBuiltBase(t, MediaTypeOCIManifest)
	layer, err := BuildLayer([]File{{Path: "/fatline", Mode: 0o755, Data: []byte("binary")}})
	if err != nil {
		t.Fatal(err)
	}
	img, err := AppendLayer(base, layer, AppendOptions{Platform: linuxAMD64, Entrypoint: []string{"/fatline"}})
	if err != nil {
		t.Fatal(err)
	}
	return img
}
