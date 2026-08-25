package oci

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestBuildLayerIsDeterministic(t *testing.T) {
	files := []File{
		{Path: "/fatline", Mode: 0o755, Data: []byte("ELF-ish binary")},
		{Path: "/etc/farcast/note", Mode: 0o644, Data: []byte("hello")},
	}
	first, err := BuildLayer(files)
	if err != nil {
		t.Fatal(err)
	}
	// Reversed input: ordering must not leak into the digest, or two identical
	// builds would push two different layers.
	second, err := BuildLayer([]File{files[1], files[0]})
	if err != nil {
		t.Fatal(err)
	}
	if first.Descriptor.Digest != second.Descriptor.Digest || first.DiffID != second.DiffID {
		t.Fatalf("layer digests differ across identical builds:\n %s / %s\n %s / %s",
			first.Descriptor.Digest, first.DiffID, second.Descriptor.Digest, second.DiffID)
	}
	if first.Descriptor.Size != int64(len(first.Blob)) {
		t.Fatalf("descriptor size %d, blob %d bytes", first.Descriptor.Size, len(first.Blob))
	}
	if digestOf(first.Blob) != first.Descriptor.Digest {
		t.Fatal("layer blob does not hash to its descriptor")
	}
}

func TestBuildLayerTarIsReproducibleAndComplete(t *testing.T) {
	layer, err := BuildLayer([]File{
		{Path: "/fatline", Mode: 0o755, Data: []byte("binary")},
		{Path: "/usr/local/share/farcast/ca.pem", Mode: 0o644, Data: []byte("pem")},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := gunzip(t, layer.Blob)
	if got := "sha256:" + hex.EncodeToString(sha256Sum(raw)); got != layer.DiffID {
		t.Fatalf("diffID %s is not the digest of the uncompressed tar %s", layer.DiffID, got)
	}

	var names []string
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, hdr.Name)
		if !hdr.ModTime.Equal(time.Unix(0, 0).UTC()) {
			t.Errorf("%s carries mtime %s, want the fixed epoch", hdr.Name, hdr.ModTime)
		}
		if hdr.Uid != 0 || hdr.Gid != 0 || hdr.Uname != "" || hdr.Gname != "" {
			t.Errorf("%s carries owner metadata %d/%d %q/%q", hdr.Name, hdr.Uid, hdr.Gid, hdr.Uname, hdr.Gname)
		}
		if hdr.Name == "fatline" {
			if hdr.FileInfo().Mode().Perm() != 0o755 {
				t.Errorf("fatline mode = %o, want 755 — a non-executable entrypoint fails at runtime", hdr.FileInfo().Mode().Perm())
			}
			body, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			if string(body) != "binary" {
				t.Errorf("fatline content = %q", body)
			}
		}
	}
	want := []string{"fatline", "usr/", "usr/local/", "usr/local/share/", "usr/local/share/farcast/", "usr/local/share/farcast/ca.pem"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("tar entries = %v, want %v (parents present, sorted)", names, want)
	}
}

func TestBuildLayerRejectsEmptyInput(t *testing.T) {
	if _, err := BuildLayer(nil); err == nil {
		t.Fatal("expected an error for an empty layer")
	}
	if _, err := BuildLayer([]File{{Path: "/", Data: nil}}); err == nil {
		t.Fatal("expected an error for a path that is not a file")
	}
}

func TestAppendLayerUpdatesConfigAndManifest(t *testing.T) {
	base := handBuiltBase(t, MediaTypeOCIManifest)
	baseConfigCopy := append([]byte(nil), base.Config...)

	layer, err := BuildLayer([]File{{Path: "/fatline", Mode: 0o755, Data: []byte("binary")}})
	if err != nil {
		t.Fatal(err)
	}
	img, err := AppendLayer(base, layer, AppendOptions{
		Platform:   linuxAMD64,
		Entrypoint: []string{"/fatline"},
		CreatedBy:  "farcast: fatline 0.2.0",
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := img.DecodeConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OS != "linux" || cfg.Architecture != "amd64" {
		t.Fatalf("config platform = %s/%s, want linux/amd64", cfg.OS, cfg.Architecture)
	}
	if len(cfg.RootFS.DiffIDs) != 2 || cfg.RootFS.DiffIDs[1] != layer.DiffID {
		t.Fatalf("rootfs diff_ids = %v, want the appended layer %s last", cfg.RootFS.DiffIDs, layer.DiffID)
	}
	if len(cfg.Config.Entrypoint) != 1 || cfg.Config.Entrypoint[0] != "/fatline" {
		t.Fatalf("entrypoint = %v, want [/fatline]", cfg.Config.Entrypoint)
	}
	if len(cfg.Config.Cmd) != 0 {
		t.Fatalf("Cmd = %v, want it cleared — the base's default args must not become our argv", cfg.Config.Cmd)
	}
	if cfg.Config.User != "65532:65532" {
		t.Fatalf("User = %q, want the base's nonroot user preserved", cfg.Config.User)
	}
	if len(cfg.Config.Env) != 2 {
		t.Fatalf("Env = %v, want the base's environment preserved", cfg.Config.Env)
	}

	// Fields this package does not model must survive byte-faithfully, integers
	// included — a float round trip would rewrite 42 as 42.0.
	var doc map[string]any
	if err := json.Unmarshal(img.Config, &doc); err != nil {
		t.Fatal(err)
	}
	ext, ok := doc["vendor.extension"].(map[string]any)
	if !ok || ext["keep"] != true {
		t.Fatalf("unmodelled config fields were dropped: %v", doc["vendor.extension"])
	}
	if !strings.Contains(string(img.Config), `"count":42`) {
		t.Fatalf("integer was rewritten during the round trip: %s", img.Config)
	}
	history, _ := doc["history"].([]any)
	if len(history) != 2 {
		t.Fatalf("history has %d entries, want the base's plus ours", len(history))
	}

	if img.Manifest.MediaType != MediaTypeOCIManifest || img.Manifest.Config.MediaType != MediaTypeOCIConfig {
		t.Fatalf("manifest flavour drifted: %+v", img.Manifest)
	}
	if img.Manifest.Config.Digest != digestOf(img.Config) || img.Manifest.Config.Size != int64(len(img.Config)) {
		t.Fatal("config descriptor does not describe the re-serialised config")
	}
	if len(img.Manifest.Layers) != 2 || img.Manifest.Layers[1].Digest != layer.Descriptor.Digest {
		t.Fatalf("manifest layers = %+v", img.Manifest.Layers)
	}
	if img.Manifest.Layers[1].MediaType != MediaTypeOCILayerGzip {
		t.Fatalf("appended layer media type = %q", img.Manifest.Layers[1].MediaType)
	}
	if len(img.Layers) != 2 || !bytes.Equal(img.Layers[1].Blob, layer.Blob) {
		t.Fatal("appended layer bytes are missing from the image")
	}
	if !bytes.Equal(base.Config, baseConfigCopy) || len(base.Layers) != 1 {
		t.Fatal("AppendLayer mutated the base image")
	}
}

func TestAppendLayerKeepsDockerFlavour(t *testing.T) {
	base := handBuiltBase(t, MediaTypeDockerManifest)
	layer, err := BuildLayer([]File{{Path: "/fatline", Mode: 0o755, Data: []byte("binary")}})
	if err != nil {
		t.Fatal(err)
	}
	img, err := AppendLayer(base, layer, AppendOptions{Platform: linuxAMD64, Entrypoint: []string{"/fatline"}})
	if err != nil {
		t.Fatal(err)
	}
	if img.Manifest.MediaType != MediaTypeDockerManifest ||
		img.Manifest.Config.MediaType != MediaTypeDockerConfig ||
		img.Manifest.Layers[1].MediaType != MediaTypeDockerLayerGzip {
		t.Fatalf("a Docker-flavoured base produced a mixed manifest: %+v", img.Manifest)
	}
}

func TestAppendLayerValidatesInput(t *testing.T) {
	base := handBuiltBase(t, MediaTypeOCIManifest)
	good, err := BuildLayer([]File{{Path: "/fatline", Mode: 0o755, Data: []byte("binary")}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AppendLayer(nil, good, AppendOptions{Platform: linuxAMD64}); err == nil {
		t.Error("expected an error without a base image")
	}
	if _, err := AppendLayer(base, Layer{}, AppendOptions{Platform: linuxAMD64}); err == nil {
		t.Error("expected an error for a layer with no digest or diffID")
	}
	if _, err := AppendLayer(base, good, AppendOptions{}); err == nil {
		t.Error("expected an error without a platform — a silent mismatch fails only at runtime")
	}
}

// handBuiltBase assembles a base image in memory, standing in for a pulled one.
func handBuiltBase(t *testing.T, manifestType string) *Image {
	t.Helper()
	f := flavourOf(manifestType)
	layer, err := BuildLayer([]File{{Path: "/base", Mode: 0o644, Data: []byte("base")}})
	if err != nil {
		t.Fatal(err)
	}
	layer.Descriptor.MediaType = f.layer
	cfg := baseConfigJSON(layer.DiffID)
	return &Image{
		Manifest: Manifest{
			SchemaVersion: 2,
			MediaType:     manifestType,
			Config:        Descriptor{MediaType: f.config, Digest: digestOf(cfg), Size: int64(len(cfg))},
			Layers:        []Descriptor{layer.Descriptor},
		},
		Config: cfg,
		Layers: []Layer{layer},
	}
}

func gunzip(t *testing.T, blob []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = zr.Close() }()
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
