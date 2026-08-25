package image

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/oci"
)

func sha256Ref(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

const fakeBinary = "\x7fELF fatline, compiled"

// fixedCompile is the Compile seam a test injects in place of the Go toolchain:
// it records what it was asked to build and returns a stand-in binary.
func fixedCompile(sourceDir, pkg *string) func(context.Context, string, string) ([]byte, error) {
	return func(_ context.Context, dir, p string) ([]byte, error) {
		*sourceDir, *pkg = dir, p
		return []byte(fakeBinary), nil
	}
}

func TestBuildAndPushEndToEnd(t *testing.T) {
	reg := newTestRegistry(t)
	base := seedBase(t, reg, "distroless/static", "nonroot")

	const repo = "proj-1/farcast-alpha/system/fatline"
	var gotDir, gotPkg string
	var progress []string
	b := &Builder{
		Compile:  fixedCompile(&gotDir, &gotPkg),
		Progress: func(line string) { progress = append(progress, line) },
		base:     base,
	}

	pinned, err := b.BuildAndPush(t.Context(), Options{
		SourceDir:  "/checkout/farcast",
		Package:    "./fatline/cmd/fatline",
		Ref:        reg.host() + "/" + repo + ":0.2.0",
		BinaryPath: "/fatline",
		Entrypoint: []string{"/fatline"},
	}, "", "")
	if err != nil {
		t.Fatalf("BuildAndPush: %v", err)
	}

	if gotDir != "/checkout/farcast" || gotPkg != "./fatline/cmd/fatline" {
		t.Fatalf("compile was asked for %s in %s", gotPkg, gotDir)
	}

	// What comes back must be a digest, not a tag: the deploy pins content, so
	// a later write to the tag cannot swap the image under a running workload.
	wantPrefix := reg.host() + "/" + repo + "@sha256:"
	if !strings.HasPrefix(pinned, wantPrefix) {
		t.Fatalf("returned %q, want a digest-pinned %q…", pinned, wantPrefix)
	}
	digest := strings.TrimPrefix(pinned, reg.host()+"/"+repo+"@")

	// The image is reachable by both the tag it was pushed under and its digest.
	byTag, ok := reg.manifest(repo, "0.2.0")
	if !ok {
		t.Fatal("nothing was stored under the tag")
	}
	byDigest, ok := reg.manifest(repo, digest)
	if !ok || !bytes.Equal(byTag, byDigest) {
		t.Fatal("the returned digest does not address what was pushed")
	}

	var manifest oci.Manifest
	if err := json.Unmarshal(byTag, &manifest); err != nil {
		t.Fatalf("pushed manifest is not valid JSON: %v", err)
	}
	if manifest.SchemaVersion != 2 || manifest.MediaType != oci.MediaTypeOCIManifest {
		t.Fatalf("manifest = %+v, want a schema 2 OCI manifest", manifest)
	}
	if len(manifest.Layers) != 2 {
		t.Fatalf("manifest lists %d layers, want the base's plus ours", len(manifest.Layers))
	}

	configBlob := reg.blob(repo, manifest.Config.Digest)
	if configBlob == nil {
		t.Fatal("the config blob was not pushed")
	}
	var cfg oci.ImageConfig
	if err := json.Unmarshal(configBlob, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.OS != "linux" || cfg.Architecture != "amd64" {
		t.Fatalf("config platform = %s/%s, want linux/amd64 (Autopilot nodes are amd64)", cfg.OS, cfg.Architecture)
	}
	if len(cfg.Config.Entrypoint) != 1 || cfg.Config.Entrypoint[0] != "/fatline" {
		t.Fatalf("entrypoint = %v, want [/fatline]", cfg.Config.Entrypoint)
	}
	if cfg.Config.User != "65532:65532" {
		t.Fatalf("User = %q, want the distroless nonroot user preserved", cfg.Config.User)
	}
	if len(cfg.RootFS.DiffIDs) != 2 {
		t.Fatalf("rootfs diff_ids = %v, want two", cfg.RootFS.DiffIDs)
	}

	// The appended layer must actually contain the compiled binary, executable,
	// at the path the entrypoint names.
	top := reg.blob(repo, manifest.Layers[1].Digest)
	if top == nil {
		t.Fatal("the appended layer was not pushed")
	}
	raw := gunzip(t, top)
	if sha256Ref(raw) != cfg.RootFS.DiffIDs[1] {
		t.Fatal("the appended layer's diffID is not the digest of its uncompressed tar")
	}
	found := false
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Name != "fatline" {
			continue
		}
		found = true
		if perm := hdr.FileInfo().Mode().Perm(); perm != 0o755 {
			t.Errorf("binary mode = %o, want 755", perm)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != fakeBinary {
			t.Errorf("layer holds %q, want the compiled binary", body)
		}
	}
	if !found {
		t.Fatal("the compiled binary is not in the pushed layer")
	}

	joined := strings.Join(progress, "\n")
	for _, want := range []string{"compiling ./fatline/cmd/fatline", "fetching base image", "pushing", "pushed "} {
		if !strings.Contains(joined, want) {
			t.Errorf("progress lines %q do not mention %q", joined, want)
		}
	}
}

func TestBuildAndPushKeepsCredentialsOffThePublicBase(t *testing.T) {
	public := newTestRegistry(t)
	base := seedBase(t, public, "distroless/static", "nonroot")

	instance := newTestRegistry(t)
	instance.requireAuth = true
	instance.user, instance.pass = "oauth2accesstoken", "ya29.short-lived"

	b := &Builder{Compile: fixedCompile(new(string), new(string)), base: base}
	if _, err := b.BuildAndPush(t.Context(), Options{
		SourceDir:  "/checkout/farcast",
		Package:    "./fatline/cmd/fatline",
		Ref:        instance.host() + "/proj-1/farcast-alpha/system/fatline:0.2.0",
		BinaryPath: "/fatline",
		Entrypoint: []string{"/fatline"},
	}, instance.user, instance.pass); err != nil {
		t.Fatal(err)
	}
	if public.sawCredentials() {
		t.Fatal("the instance's registry token was offered to the public base registry")
	}
	if !instance.sawCredentials() {
		t.Fatal("the instance's registry was never authenticated to")
	}
}

func TestBuildAndPushRejectsIncompleteOptions(t *testing.T) {
	full := Options{
		SourceDir:  "/checkout/farcast",
		Package:    "./fatline/cmd/fatline",
		Ref:        "127.0.0.1:5000/farcast/system/fatline:0.2.0",
		BinaryPath: "/fatline",
		Entrypoint: []string{"/fatline"},
	}
	tests := map[string]func(*Options){
		"no source":                   func(o *Options) { o.SourceDir = "" },
		"no package":                  func(o *Options) { o.Package = "" },
		"no ref":                      func(o *Options) { o.Ref = "" },
		"relative binary":             func(o *Options) { o.BinaryPath = "fatline" },
		"no entrypoint":               func(o *Options) { o.Entrypoint = nil },
		"unparseable ref":             func(o *Options) { o.Ref = "fatline:0.2.0" },
		"ref without a registry host": func(o *Options) { o.Ref = "no-host/fatline:0.2.0" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			opts := full
			mutate(&opts)
			b := &Builder{Compile: func(context.Context, string, string) ([]byte, error) {
				t.Fatal("compilation started before the options were validated")
				return nil, nil
			}}
			if _, err := b.BuildAndPush(t.Context(), opts, "", ""); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestBuildAndPushPropagatesCompileFailure(t *testing.T) {
	reg := newTestRegistry(t)
	base := seedBase(t, reg, "distroless/static", "nonroot")
	boom := errors.New("go build: undefined: Foo")
	b := &Builder{
		base:    base,
		Compile: func(context.Context, string, string) ([]byte, error) { return nil, boom },
	}
	_, err := b.BuildAndPush(t.Context(), Options{
		SourceDir:  "/checkout/farcast",
		Package:    "./fatline/cmd/fatline",
		Ref:        reg.host() + "/farcast/system/fatline:0.2.0",
		BinaryPath: "/fatline",
		Entrypoint: []string{"/fatline"},
	}, "", "")
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the compiler's own failure", err)
	}
}

func TestBuildAndPushRejectsAnUnpinnedBase(t *testing.T) {
	reg := newTestRegistry(t)
	b := &Builder{
		base:    reg.host() + "/distroless/static:nonroot", // tag only
		Compile: fixedCompile(new(string), new(string)),
	}
	_, err := b.BuildAndPush(t.Context(), Options{
		SourceDir:  "/checkout/farcast",
		Package:    "./fatline/cmd/fatline",
		Ref:        reg.host() + "/farcast/system/fatline:0.2.0",
		BinaryPath: "/fatline",
		Entrypoint: []string{"/fatline"},
	}, "", "")
	if err == nil || !strings.Contains(err.Error(), "not pinned by digest") {
		t.Fatalf("err = %v, want a refusal to build on an unpinned base", err)
	}
}

func TestBaseImageConstantIsPinned(t *testing.T) {
	ref, err := oci.ParseReference(BaseImage)
	if err != nil {
		t.Fatalf("BaseImage does not parse: %v", err)
	}
	if ref.Digest == "" {
		t.Fatal("BaseImage must be pinned by digest — gcr.io is transport, not an authority")
	}
	if ref.Registry != "gcr.io" || ref.Repository != "distroless/static" {
		t.Fatalf("BaseImage = %s, want the distroless static base", BaseImage)
	}
}

func TestResolveReturnsPinnedReference(t *testing.T) {
	reg := newTestRegistry(t)
	pinnedBase := seedBase(t, reg, "farcast/system/fatline", "0.2.0")
	_, digest, _ := strings.Cut(pinnedBase, "@")

	b := &Builder{}
	got, err := b.Resolve(t.Context(), reg.host()+"/farcast/system/fatline:0.2.0", "", "")
	if err != nil {
		t.Fatal(err)
	}
	want := reg.host() + "/farcast/system/fatline@" + digest
	if got != want {
		t.Fatalf("Resolve = %q, want %q", got, want)
	}
}

func TestResolveNotFound(t *testing.T) {
	reg := newTestRegistry(t)
	b := &Builder{}
	// A miss is what tells connect to offer a build; it must be distinguishable
	// from a permission or transport failure.
	_, err := b.Resolve(t.Context(), reg.host()+"/farcast/system/fatline:0.2.0", "", "")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
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
