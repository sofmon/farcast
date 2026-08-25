package oci

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestPullSelectsPlatformFromIndex(t *testing.T) {
	reg := newFakeRegistry(t)
	_, amd64Digest := seedIndexedImage(t, reg, "distroless/static", "nonroot")
	c := &Client{}
	ref, err := ParseReference(reg.host() + "/distroless/static:nonroot")
	if err != nil {
		t.Fatal(err)
	}

	amd, err := c.Pull(t.Context(), ref, linuxAMD64)
	if err != nil {
		t.Fatalf("pull amd64: %v", err)
	}
	if amd.Digest != amd64Digest {
		t.Fatalf("pulled %s, want the amd64 manifest %s", amd.Digest, amd64Digest)
	}
	if amd.Manifest.MediaType != MediaTypeOCIManifest {
		t.Fatalf("manifest media type = %q, want the image manifest, not the index", amd.Manifest.MediaType)
	}

	arm, err := c.Pull(t.Context(), ref, Platform{OS: "linux", Architecture: "arm64"})
	if err != nil {
		t.Fatalf("pull arm64: %v", err)
	}
	if arm.Digest == amd.Digest {
		t.Fatal("both platforms resolved to the same manifest — the index entry was not selected")
	}
}

func TestPullFillsLayerBytesAndDiffIDs(t *testing.T) {
	reg := newFakeRegistry(t)
	seedIndexedImage(t, reg, "distroless/static", "nonroot")
	ref, _ := ParseReference(reg.host() + "/distroless/static:nonroot")

	img, err := (&Client{}).Pull(t.Context(), ref, linuxAMD64)
	if err != nil {
		t.Fatal(err)
	}
	if len(img.Layers) != 1 {
		t.Fatalf("got %d layers, want 1", len(img.Layers))
	}
	layer := img.Layers[0]
	if len(layer.Blob) == 0 {
		t.Fatal("layer bytes were not retained — a cross-registry copy needs them")
	}
	if digestOf(layer.Blob) != layer.Descriptor.Digest {
		t.Fatal("retained layer bytes do not hash to their descriptor")
	}
	cfg, err := img.DecodeConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.RootFS.DiffIDs) != 1 || layer.DiffID != cfg.RootFS.DiffIDs[0] {
		t.Fatalf("layer diffID %q was not taken from rootfs %v", layer.DiffID, cfg.RootFS.DiffIDs)
	}
}

func TestPullRejectsTamperedBlob(t *testing.T) {
	reg := newFakeRegistry(t)
	seedIndexedImage(t, reg, "distroless/static", "nonroot")
	ref, _ := ParseReference(reg.host() + "/distroless/static:nonroot")

	img, err := (&Client{}).Pull(t.Context(), ref, linuxAMD64)
	if err != nil {
		t.Fatal(err)
	}
	// The registry is transport, not an authority: content that does not hash
	// to its descriptor must never reach the assembled image.
	reg.mu.Lock()
	reg.corrupt[img.Layers[0].Descriptor.Digest] = true
	reg.mu.Unlock()

	_, err = (&Client{}).Pull(t.Context(), ref, linuxAMD64)
	if err == nil || !strings.Contains(err.Error(), "does not match descriptor") {
		t.Fatalf("err = %v, want a blob digest mismatch", err)
	}
}

func TestPullRejectsManifestThatBreaksItsPin(t *testing.T) {
	reg := newFakeRegistry(t)
	seedIndexedImage(t, reg, "distroless/static", "nonroot")
	// Serve an unrelated document under a digest a caller pinned — the shape a
	// compromised registry takes when it tries to swap a base image.
	const lie = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	reg.mu.Lock()
	reg.manifests["distroless/static:"+lie] = stored{
		body:      []byte(`{"schemaVersion":2,"mediaType":"` + MediaTypeOCIManifest + `","config":{"digest":"sha256:dead","size":1},"layers":[]}`),
		mediaType: MediaTypeOCIManifest,
	}
	reg.mu.Unlock()

	ref, _ := ParseReference(reg.host() + "/distroless/static@" + lie)
	_, err := (&Client{}).Pull(t.Context(), ref, linuxAMD64)
	if err == nil || !strings.Contains(err.Error(), "pinned digest") {
		t.Fatalf("err = %v, want the pin to be enforced against the content", err)
	}
}

func TestPullRefusesOversizeBlob(t *testing.T) {
	reg := newFakeRegistry(t)
	seedIndexedImage(t, reg, "distroless/static", "nonroot")
	ref, _ := ParseReference(reg.host() + "/distroless/static:nonroot")

	// A registry is untrusted transport; an unbounded body must not be able to
	// exhaust the operator's machine.
	c := &Client{MaxBlobSize: 32}
	_, err := c.Pull(t.Context(), ref, linuxAMD64)
	if err == nil || !strings.Contains(err.Error(), "ceiling") {
		t.Fatalf("err = %v, want the blob size ceiling to refuse it", err)
	}
}

func TestPullMissingPlatform(t *testing.T) {
	reg := newFakeRegistry(t)
	seedIndexedImage(t, reg, "distroless/static", "nonroot")
	ref, _ := ParseReference(reg.host() + "/distroless/static:nonroot")

	_, err := (&Client{}).Pull(t.Context(), ref, Platform{OS: "windows", Architecture: "amd64"})
	if err == nil || !strings.Contains(err.Error(), "linux/amd64") {
		t.Fatalf("err = %v, want the miss to name what the index does offer", err)
	}
}

func TestPullNotFound(t *testing.T) {
	reg := newFakeRegistry(t)
	ref, _ := ParseReference(reg.host() + "/farcast/system/fatline:0.2.0")

	_, err := (&Client{}).Pull(t.Context(), ref, linuxAMD64)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestResolveReturnsDigest(t *testing.T) {
	reg := newFakeRegistry(t)
	indexDigest, _ := seedIndexedImage(t, reg, "farcast/system/fatline", "0.2.0")
	ref, _ := ParseReference(reg.host() + "/farcast/system/fatline:0.2.0")

	got, err := (&Client{}).Resolve(t.Context(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if got != indexDigest {
		t.Fatalf("Resolve = %s, want %s", got, indexDigest)
	}
	if reg.countCalls("HEAD /v2/farcast/system/fatline/manifests/0.2.0") != 1 {
		t.Fatalf("preflight did not use HEAD: %v", reg.calls())
	}
}

func TestResolveHashesManifestWhenHeaderMissing(t *testing.T) {
	reg := newFakeRegistry(t)
	reg.omitDigestHeader = true // conformant, but leaves the digest to us
	indexDigest, _ := seedIndexedImage(t, reg, "farcast/system/fatline", "0.2.0")
	ref, _ := ParseReference(reg.host() + "/farcast/system/fatline:0.2.0")

	got, err := (&Client{}).Resolve(t.Context(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if got != indexDigest {
		t.Fatalf("Resolve = %s, want %s", got, indexDigest)
	}
}

func TestResolveNotFound(t *testing.T) {
	reg := newFakeRegistry(t)
	ref, _ := ParseReference(reg.host() + "/farcast/system/fatline:0.2.0")

	_, err := (&Client{}).Resolve(t.Context(), ref)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound so connect can offer to build instead", err)
	}
}

func TestDetectMediaType(t *testing.T) {
	index, _ := json.Marshal(Index{SchemaVersion: 2, Manifests: []Descriptor{{Digest: "sha256:x"}}})
	manifest, _ := json.Marshal(Manifest{SchemaVersion: 2, Config: Descriptor{Digest: "sha256:x"}})

	tests := []struct {
		name        string
		contentType string
		body        []byte
		want        string
	}{
		{"header wins", MediaTypeDockerIndex + "; charset=utf-8", index, MediaTypeDockerIndex},
		{"falls back to shape for an index", "application/json", index, MediaTypeOCIIndex},
		{"falls back to shape for a manifest", "", manifest, MediaTypeOCIManifest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := detectMediaType(tc.contentType, tc.body)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("detectMediaType = %q, want %q", got, tc.want)
			}
		})
	}
	if _, err := detectMediaType("text/html", []byte("<html>")); err == nil {
		t.Fatal("a non-manifest response must be rejected, not guessed at")
	}
}
