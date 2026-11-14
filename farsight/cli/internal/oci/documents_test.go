package oci

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// seededDocuments seeds a two-platform index and returns its pin and the three
// documents a release commits: the index, the linux/amd64 manifest and its
// config, exactly as the registry holds them.
func seededDocuments(t *testing.T, reg *fakeRegistry) (pin Reference, index, manifest, config []byte) {
	t.Helper()
	const repo = "distroless/static"
	indexDigest, amd64Digest := seedIndexedImage(t, reg, repo, "nonroot")
	pin, err := ParseReference(reg.host() + "/" + repo + ":nonroot@" + indexDigest)
	if err != nil {
		t.Fatal(err)
	}
	reg.mu.Lock()
	index = reg.manifests[repo+":"+indexDigest].body
	manifest = reg.manifests[repo+":"+amd64Digest].body
	reg.mu.Unlock()
	var m Manifest
	if err := json.Unmarshal(manifest, &m); err != nil {
		t.Fatal(err)
	}
	reg.mu.Lock()
	config = reg.blobs[repo+"@"+m.Config.Digest]
	reg.mu.Unlock()
	return pin, index, manifest, config
}

func TestManifestBytesIsWhatPushSends(t *testing.T) {
	reg := newFakeRegistry(t)
	const repo = "proj/farcast-alpha/system/fatline"
	img := assembledImage(t)
	_, want, err := img.ManifestBytes()
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := ParseReference(reg.host() + "/" + repo + ":0.2.0")
	if _, err := (&Client{}).Push(t.Context(), ref, img); err != nil {
		t.Fatal(err)
	}
	reg.mu.Lock()
	stored := reg.manifests[repo+":0.2.0"]
	reg.mu.Unlock()
	if got := digestOf(stored.body); got != want {
		t.Fatalf("the registry received a manifest hashing to %s; ManifestBytes said %s", got, want)
	}
}

func TestImageFromDocumentsVerifiesTheChain(t *testing.T) {
	reg := newFakeRegistry(t)
	pin, index, manifest, config := seededDocuments(t, reg)

	im, err := ImageFromDocuments(pin, index, manifest, config, linuxAMD64)
	if err != nil {
		t.Fatal(err)
	}
	pulled, err := (&Client{}).Pull(t.Context(), pin, linuxAMD64)
	if err != nil {
		t.Fatal(err)
	}
	if im.Digest != pulled.Digest || !bytes.Equal(im.Config, pulled.Config) {
		t.Fatalf("the documents give %s, Pull gives %s", im.Digest, pulled.Digest)
	}
	if len(im.Layers) != len(pulled.Layers) {
		t.Fatalf("%d layers from the documents, %d pulled", len(im.Layers), len(pulled.Layers))
	}
	for i, l := range im.Layers {
		if l.Blob != nil || l.Descriptor != pulled.Layers[i].Descriptor || l.DiffID != pulled.Layers[i].DiffID {
			t.Fatalf("layer %d = %+v, want the pulled descriptor and diffID with no bytes", i, l)
		}
	}

	// A manifest pinned directly, with no index.
	direct := pin.WithDigest(im.Digest)
	if _, err := ImageFromDocuments(direct, nil, manifest, config, linuxAMD64); err != nil {
		t.Fatalf("a manifest pin: %v", err)
	}

	var idx Index
	if err := json.Unmarshal(index, &idx); err != nil {
		t.Fatal(err)
	}
	arm64 := idx.Manifests[1]
	reg.mu.Lock()
	arm64Manifest := reg.manifests["distroless/static:"+arm64.Digest].body
	reg.mu.Unlock()

	onlyARM, _ := json.Marshal(Index{SchemaVersion: 2, MediaType: MediaTypeOCIIndex, Manifests: []Descriptor{arm64}})
	nested, _ := json.Marshal(Index{SchemaVersion: 2, MediaType: MediaTypeOCIIndex, Manifests: []Descriptor{{
		MediaType: MediaTypeOCIIndex, Digest: digestOf(index), Size: int64(len(index)), Platform: &linuxAMD64,
	}}})
	flipped := bytes.Clone(config)
	flipped[len(flipped)-2] ^= 0x01

	cases := map[string]struct {
		pin                     Reference
		index, manifest, config []byte
		want                    string
	}{
		"an index that does not hash to the pin": {
			pin: pin, index: append(bytes.Clone(index), ' '), manifest: manifest, config: config, want: "not the pinned digest",
		},
		"a manifest that is not the platform entry": {
			pin: pin, index: index, manifest: arm64Manifest, config: config, want: "not the sha256:",
		},
		"a changed config byte": {
			pin: pin, index: index, manifest: manifest, config: flipped, want: "config of",
		},
		"no linux/amd64 entry": {
			pin: pin.WithDigest(digestOf(onlyARM)), index: onlyARM, manifest: manifest, config: config, want: "no linux/amd64 entry",
		},
		"a child that is itself an index": {
			pin: pin.WithDigest(digestOf(nested)), index: nested, manifest: index, config: config, want: "is itself an index",
		},
		"an unpinned reference": {
			pin: Reference{Registry: pin.Registry, Repository: pin.Repository, Tag: "nonroot"}, index: index, manifest: manifest, config: config, want: "not pinned by digest",
		},
		"a manifest pin that the manifest does not hash to": {
			pin: pin.WithDigest(arm64.Digest), manifest: manifest, config: config, want: "hashes to",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			im, err := ImageFromDocuments(c.pin, c.index, c.manifest, c.config, linuxAMD64)
			if err == nil {
				t.Fatalf("accepted, giving %s", im.Digest)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to say %q", err, c.want)
			}
		})
	}
}

func TestDocumentsFetchesTheVerifiedChain(t *testing.T) {
	reg := newFakeRegistry(t)
	pin, index, manifest, config := seededDocuments(t, reg)

	gotIndex, gotManifest, gotConfig, err := (&Client{}).Documents(t.Context(), pin, linuxAMD64)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotIndex, index) || !bytes.Equal(gotManifest, manifest) || !bytes.Equal(gotConfig, config) {
		t.Fatal("Documents did not return the registry's exact bytes")
	}
	if n := reg.countCalls("GET /v2/distroless/static/blobs/"); n != 1 {
		t.Fatalf("fetched %d blobs, want only the config", n)
	}
	if reg.sawCredentials() {
		t.Fatal("Documents offered a credential")
	}

	t.Run("a tampered config", func(t *testing.T) {
		var m Manifest
		if err := json.Unmarshal(manifest, &m); err != nil {
			t.Fatal(err)
		}
		reg.mu.Lock()
		reg.corrupt[m.Config.Digest] = true
		reg.mu.Unlock()
		defer func() {
			reg.mu.Lock()
			delete(reg.corrupt, m.Config.Digest)
			reg.mu.Unlock()
		}()
		if _, _, _, err := (&Client{}).Documents(t.Context(), pin, linuxAMD64); err == nil {
			t.Fatal("a config that does not match its descriptor was accepted")
		}
	})

	t.Run("an unpinned reference", func(t *testing.T) {
		unpinned := pin
		unpinned.Digest = ""
		if _, _, _, err := (&Client{}).Documents(t.Context(), unpinned, linuxAMD64); err == nil {
			t.Fatal("an unpinned reference was fetched")
		}
	})
}

func gzipped(t *testing.T, raw []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestDiffIDOf(t *testing.T) {
	layer, err := BuildLayer([]File{{Path: "/fatline", Mode: 0o755, Data: []byte("a binary")}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := DiffIDOf(layer.Blob)
	if err != nil {
		t.Fatal(err)
	}
	if got != layer.DiffID {
		t.Fatalf("DiffIDOf = %s, want BuildLayer's %s", got, layer.DiffID)
	}
	sum := sha256.Sum256([]byte("hello"))
	if got, err := DiffIDOf(gzipped(t, []byte("hello"))); err != nil || got != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("DiffIDOf(gzip(hello)) = %s, %v", got, err)
	}
	if _, err := DiffIDOf([]byte("not gzip")); err == nil {
		t.Fatal("bytes that are not gzip were accepted")
	}
	if _, err := DiffIDOf(layer.Blob[:len(layer.Blob)-4]); err == nil {
		t.Fatal("a truncated stream was accepted")
	}
}

func TestDiffIDOfRefusesAnOversizeLayer(t *testing.T) {
	if maxDiffIDBytes != 1<<30 {
		t.Fatalf("the ceiling is %d bytes, want 1 GiB", maxDiffIDBytes)
	}
	raw := bytes.Repeat([]byte{0}, 4096)
	gz := gzipped(t, raw)
	if _, err := diffIDOf(gz, 4096); err != nil {
		t.Fatalf("a layer exactly at the ceiling was refused: %v", err)
	}
	if _, err := diffIDOf(gz, 4095); err == nil || !strings.Contains(err.Error(), "more than 4095 bytes") {
		t.Fatalf("err = %v, want a layer one byte over the ceiling refused", err)
	}
}
