package release

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/components"
	"github.com/sofmon/farcast/farsight/cli/internal/image"
	"github.com/sofmon/farcast/farsight/cli/internal/oci"
)

const testPin = "go1.27.4"

// fakeSource is a checkout with nothing but what a release reads before it
// compiles: go.mod with the pin, and the committed notices.
func fakeSource(t *testing.T) string {
	t.Helper()
	src := t.TempDir()
	files := map[string]string{
		"go.mod":              "module github.com/sofmon/farcast\n\ngo 1.26\n\ntoolchain " + testPin + "\n",
		"THIRD_PARTY_NOTICES": "the notices\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(src, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return src
}

// fakeGitPath is a PATH holding an executable named git, which nothing runs.
func fakeGitPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	name := "git"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return "PATH=" + dir
}

// syntheticBase is a small base image standing in for PinnedBase.
func syntheticBase(t *testing.T) *oci.Image {
	t.Helper()
	layer, err := oci.BuildLayer([]oci.File{{Path: "/etc/base", Mode: 0o644, Data: []byte("base")}})
	if err != nil {
		t.Fatal(err)
	}
	config := []byte(`{"architecture":"amd64","os":"linux","config":{"User":"65532"},"rootfs":{"type":"layers","diff_ids":["` + layer.DiffID + `"]}}`)
	sum := sha256.Sum256(config)
	return &oci.Image{
		Manifest: oci.Manifest{
			SchemaVersion: 2,
			MediaType:     oci.MediaTypeOCIManifest,
			Config:        oci.Descriptor{MediaType: oci.MediaTypeOCIConfig, Digest: "sha256:" + hex.EncodeToString(sum[:]), Size: int64(len(config))},
			Layers:        []oci.Descriptor{layer.Descriptor},
		},
		Config: config,
		Layers: []oci.Layer{layer},
	}
}

func buildInfo(revision, modified string) *debug.BuildInfo {
	info := &debug.BuildInfo{GoVersion: testPin, Settings: []debug.BuildSetting{
		{Key: "-tags", Value: "farcast_embedded"},
		{Key: "-trimpath", Value: "true"},
		{Key: "CGO_ENABLED", Value: "0"},
	}}
	if revision != "" {
		info.Settings = append(info.Settings, debug.BuildSetting{Key: "vcs.revision", Value: revision})
	}
	if modified != "" {
		info.Settings = append(info.Settings, debug.BuildSetting{Key: "vcs.modified", Value: modified})
	}
	return info
}

var revisionA = strings.Repeat("a", 40)

// fakeRelease stands in for the go command and the build info a release reads.
type fakeRelease struct {
	probe  *debug.BuildInfo
	target *debug.BuildInfo

	mu   sync.Mutex
	runs [][]string // each go command line
}

func (f *fakeRelease) seams(t *testing.T) seams {
	base := syntheticBase(t)
	return seams{
		findToolchain: func(context.Context, []string, string) (image.Toolchain, error) {
			return image.Toolchain{Go: "/fake/go/bin/go", GOROOT: "/fake/go", Version: testPin, GOMODCACHE: "/fake/mod", GOCACHE: "/fake/cache"}, nil
		},
		runGo: func(_ context.Context, _ image.Toolchain, _ string, _ []string, args []string) error {
			f.mu.Lock()
			f.runs = append(f.runs, slices.Clone(args))
			f.mu.Unlock()
			i := slices.Index(args, "-o")
			out := args[i+1]
			if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
				return err
			}
			return os.WriteFile(out, []byte("a binary of "+args[len(args)-1]+" for "+filepath.Base(out)), 0o755)
		},
		buildInfo: func(path string) (*debug.BuildInfo, error) {
			if filepath.Base(filepath.Dir(path)) == "probe" {
				return f.probe, nil
			}
			return f.target, nil
		},
		checkBinary: func([]byte) (string, error) { return testPin, nil },
		pinnedBase:  func() (*oci.Image, error) { return base, nil },
		notices: func(_ string, w io.Writer) error {
			_, err := io.WriteString(w, "the notices\n")
			return err
		},
	}
}

// compiled lists the packages the fake go was asked to build, in order.
func (f *fakeRelease) compiled() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.runs {
		out = append(out, r[len(r)-1])
	}
	return out
}

// run runs farcast-release with s and returns the exit code and stderr.
func run(t *testing.T, s seams, env []string, runtimeVersion string, args ...string) (int, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := s.run(t.Context(), args, env, &stdout, &stderr, runtimeVersion)
	return code, stderr.String()
}

func TestPinReadsTheToolchainLine(t *testing.T) {
	src := fakeSource(t)
	if pin, err := Pin(src); err != nil || pin != testPin {
		t.Fatalf("Pin = %q, %v; want %s", pin, err, testPin)
	}
	none := t.TempDir()
	if err := os.WriteFile(filepath.Join(none, "go.mod"), []byte("module x\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Pin(none); err == nil {
		t.Fatal("a go.mod without a toolchain line gave a pin")
	}
	repo, err := image.FindSource("")
	if err != nil {
		t.Fatal(err)
	}
	pin, err := Pin(repo)
	if err != nil || !regexp.MustCompile(`^go1\.\d+\.\d+$`).MatchString(pin) {
		t.Fatalf("the repository's pin = %q, %v; want an exact go1.x.y release", pin, err)
	}
}

func TestBuildRefusesTheWrongGo(t *testing.T) {
	src := fakeSource(t)
	for _, sub := range []string{"build", "layers"} {
		out := filepath.Join(t.TempDir(), "out")
		var stdout, stderr bytes.Buffer
		code := Run(t.Context(), []string{sub, "-src", src, "-out", out}, os.Environ(), &stdout, &stderr, "go1.27.3")
		if code != 2 {
			t.Fatalf("%s under go1.27.3 exited %d, want 2", sub, code)
		}
		want := "run me with exactly " + testPin + ": GOTOOLCHAIN=" + testPin + " go run ./farsight/cli/cmd/farcast-release " + sub
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr = %q, want it to say %q", stderr.String(), want)
		}
		if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s wrote %s before refusing", sub, out)
		}
	}
}

func TestBuildRefusesANonEmptyOrInsideOut(t *testing.T) {
	src := fakeSource(t)
	nonEmpty := t.TempDir()
	if err := os.WriteFile(filepath.Join(nonEmpty, "left-over"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	f := &fakeRelease{probe: buildInfo(revisionA, "false"), target: buildInfo(revisionA, "false")}
	for name, out := range map[string]string{
		"not empty":               nonEmpty,
		"the source":              src,
		"inside":                  filepath.Join(src, "release"),
		"deeper inside":           filepath.Join(src, "a", "b"),
		"inside via ..":           filepath.Join(src, "x", "..", "out"),
		"a file, not a directory": filepath.Join(src, "go.mod"),
	} {
		t.Run(name, func(t *testing.T) {
			code, stderr := run(t, f.seams(t), []string{fakeGitPath(t)}, testPin, "build", "-src", src, "-out", out)
			if code != 2 {
				t.Fatalf("exited %d (%s), want 2", code, stderr)
			}
			if len(f.compiled()) != 0 {
				t.Fatalf("compiled %v before refusing", f.compiled())
			}
		})
	}
	if entries, _ := os.ReadDir(src); len(entries) != 2 {
		t.Fatalf("the source gained files: %v", entries)
	}
	empty := t.TempDir()
	if code, stderr := run(t, f.seams(t), []string{fakeGitPath(t)}, testPin, "build", "-src", src, "-out", empty); code != 0 {
		t.Fatalf("an empty, existing -out was refused (%d): %s", code, stderr)
	}
}

// fullBuild runs a fake build into a new directory and returns it.
func fullBuild(t *testing.T, f *fakeRelease, src string, extra ...string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "rel")
	args := append([]string{"build", "-src", src, "-out", out}, extra...)
	if code, stderr := run(t, f.seams(t), []string{fakeGitPath(t), "HOME=" + t.TempDir()}, testPin, args...); code != 0 {
		t.Fatalf("build exited %d: %s", code, stderr)
	}
	return out
}

func TestSHA256SUMSFormat(t *testing.T) {
	f := &fakeRelease{probe: buildInfo(revisionA, "false"), target: buildInfo(revisionA, "false")}
	out := fullBuild(t, f, fakeSource(t), "-targets", "linux/amd64,windows/amd64")
	data, err := os.ReadFile(filepath.Join(out, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(data, []byte("\n")) || bytes.Contains(data, []byte("\r")) {
		t.Fatal("SHA256SUMS is not LF-terminated lines")
	}
	line := regexp.MustCompile(`^([0-9a-f]{64})  (\S+)$`)
	var paths []string
	for _, l := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		m := line.FindStringSubmatch(l)
		if m == nil {
			t.Fatalf("line %q is not <64 hex><two spaces><path>", l)
		}
		body, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(m[2])))
		if err != nil {
			t.Fatal(err)
		}
		if sum := sha256.Sum256(body); hex.EncodeToString(sum[:]) != m[1] {
			t.Fatalf("%s's line does not hash the file", m[2])
		}
		paths = append(paths, m[2])
	}
	want := []string{
		"THIRD_PARTY_NOTICES",
		"components/datasphered", "components/fatline", "components/shrike", "components/technocore",
		"farcast-linux-amd64", "farcast-windows-amd64.exe",
		"layers/datasphered.tar.gz", "layers/digests.json", "layers/fatline.tar.gz", "layers/shrike.tar.gz", "layers/technocore.tar.gz",
	}
	if !slices.Equal(paths, want) {
		t.Fatalf("SHA256SUMS lists\n%s\nwant (byte order, no overlay.json)\n%s", strings.Join(paths, "\n"), strings.Join(want, "\n"))
	}
	if _, err := os.Stat(filepath.Join(out, "overlay.json")); err != nil {
		t.Fatal("the build wrote no overlay.json")
	}
	if _, err := os.Stat(filepath.Join(out, "probe")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the revision probe was left behind")
	}

	// The table the release wrote parses and binds the revision.
	table, err := os.ReadFile(filepath.Join(out, "layers", "digests.json"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := components.ParseTable(table)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Revision != revisionA || parsed.Modified || parsed.Go != testPin || parsed.Base != image.BaseImage {
		t.Fatalf("table = %+v", parsed)
	}
}

func TestLayersWritesNoFarcastAndNoRevision(t *testing.T) {
	f := &fakeRelease{}
	out := filepath.Join(t.TempDir(), "rel")
	// No git on PATH: layers needs none.
	if code, stderr := run(t, f.seams(t), []string{"PATH=" + t.TempDir()}, testPin, "layers", "-src", fakeSource(t), "-out", out); code != 0 {
		t.Fatalf("layers exited %d: %s", code, stderr)
	}
	if got := f.compiled(); !slices.Equal(got, []string{"./datasphere/cmd/datasphere", "./fatline/cmd/fatline", "./shrike/cmd/shrike", "./technocore/cmd/technocore"}) {
		t.Fatalf("layers built %v, want the four components only", got)
	}
	table, err := os.ReadFile(filepath.Join(out, "layers", "digests.json"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := components.ParseTable(table)
	if err != nil || parsed.Revision != "" {
		t.Fatalf("table = %+v, %v; want an empty revision", parsed, err)
	}
	sums, err := os.ReadFile(filepath.Join(out, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(sums), "\n") != 9 || strings.Contains(string(sums), "farcast-") {
		t.Fatalf("SHA256SUMS =\n%s\nwant the 4 components, 4 layers and the table", sums)
	}
}

func TestOverlayMapsEveryLayerFile(t *testing.T) {
	src, out := "/src/farcast", "/rel/out"
	if runtime.GOOS == "windows" {
		t.Skip("POSIX paths")
	}
	data, err := overlayJSON(src, out)
	if err != nil {
		t.Fatal(err)
	}
	var overlay struct{ Replace map[string]string }
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&overlay); err != nil {
		t.Fatal(err)
	}
	// Exactly what carried_on.go embeds.
	want := map[string]string{}
	for _, f := range []string{"datasphered.tar.gz", "fatline.tar.gz", "shrike.tar.gz", "technocore.tar.gz", "digests.json"} {
		want["/src/farcast/farsight/cli/internal/components/layers/"+f] = "/rel/out/layers/" + f
	}
	if len(overlay.Replace) != len(want) {
		t.Fatalf("overlay = %v, want %v", overlay.Replace, want)
	}
	for k, v := range want {
		if overlay.Replace[k] != v {
			t.Fatalf("overlay[%s] = %q, want %q", k, overlay.Replace[k], v)
		}
	}
	again, _ := overlayJSON(src, out)
	if !bytes.Equal(data, again) {
		t.Fatal("the overlay encoding is not stable")
	}
}

func TestOverlayKeysAreThePhysicalSource(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks")
	}
	real := fakeSource(t)
	physicalSrc, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "checkout")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	f := &fakeRelease{probe: buildInfo(revisionA, "false"), target: buildInfo(revisionA, "false")}
	out := fullBuild(t, f, link, "-targets", "linux/amd64")
	data, err := os.ReadFile(filepath.Join(out, "overlay.json"))
	if err != nil {
		t.Fatal(err)
	}
	var overlay struct{ Replace map[string]string }
	if err := json.Unmarshal(data, &overlay); err != nil {
		t.Fatal(err)
	}
	physicalOut, err := filepath.EvalSymlinks(out)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range overlay.Replace {
		if !strings.HasPrefix(k, physicalSrc+string(filepath.Separator)) {
			t.Fatalf("overlay key %s is not under the physical source %s", k, physicalSrc)
		}
		if !strings.HasPrefix(v, physicalOut+string(filepath.Separator)) {
			t.Fatalf("overlay value %s is not under the physical out %s", v, physicalOut)
		}
	}

	// The inside-src refusal sees through the link, both ways.
	for _, c := range []struct{ src, out string }{
		{link, filepath.Join(real, "out")},
		{real, filepath.Join(link, "out")},
		{link, filepath.Join(physicalSrc, "out")},
	} {
		code, stderr := run(t, f.seams(t), []string{fakeGitPath(t)}, testPin, "build", "-src", c.src, "-out", c.out)
		if code != 2 || !strings.Contains(stderr, "lies inside -src") {
			t.Fatalf("-src %s -out %s exited %d (%s), want the inside-src refusal", c.src, c.out, code, stderr)
		}
	}
}

func TestBuildRecordsTheRevisionFromItsProbe(t *testing.T) {
	src := fakeSource(t)
	git := fakeGitPath(t)
	cases := []struct {
		name          string
		probe, target *debug.BuildInfo
		args          []string
		want          string
		compiles      bool // whether any component was built before the refusal
	}{
		{name: "a dirty probe", probe: buildInfo(revisionA, "true"), target: buildInfo(revisionA, "true"), want: errDirty},
		{name: "no revision", probe: buildInfo("", ""), target: buildInfo("", ""), want: errNeedsGit},
		{name: "the tree moved", probe: buildInfo(revisionA, "false"), target: buildInfo(strings.Repeat("b", 40), "false"), want: "moved to another commit", compiles: true},
		{name: "a dirty target", probe: buildInfo(revisionA, "false"), target: buildInfo(revisionA, "true"), want: errDirty, compiles: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeRelease{probe: c.probe, target: c.target}
			args := append([]string{"build", "-src", src, "-out", filepath.Join(t.TempDir(), "rel"), "-targets", "linux/amd64"}, c.args...)
			code, stderr := run(t, f.seams(t), []string{git}, testPin, args...)
			if code != 1 || !strings.Contains(stderr, c.want) {
				t.Fatalf("exited %d with %q, want 1 and %q", code, stderr, c.want)
			}
			built := slices.ContainsFunc(f.compiled(), func(p string) bool { return strings.HasPrefix(p, "./") && p != farcastPackage })
			if built != c.compiles {
				t.Fatalf("components built: %v, want %v (go was run for %v)", built, c.compiles, f.compiled())
			}
		})
	}

	t.Run("no git on PATH", func(t *testing.T) {
		f := &fakeRelease{probe: buildInfo(revisionA, "false"), target: buildInfo(revisionA, "false")}
		code, stderr := run(t, f.seams(t), []string{"PATH=" + t.TempDir()}, testPin, "build", "-src", src, "-out", filepath.Join(t.TempDir(), "rel"))
		if code != 1 || !strings.Contains(stderr, errNeedsGit) || len(f.compiled()) != 0 {
			t.Fatalf("exited %d with %q after %v, want the git refusal before anything is built", code, stderr, f.compiled())
		}
	})

	t.Run("-allow-dirty records a modified tree", func(t *testing.T) {
		f := &fakeRelease{probe: buildInfo(revisionA, "true"), target: buildInfo(revisionA, "true")}
		out := fullBuild(t, f, src, "-allow-dirty", "-targets", "linux/amd64")
		table, err := os.ReadFile(filepath.Join(out, "layers", "digests.json"))
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := components.ParseTable(table)
		if err != nil || parsed.Revision != revisionA || !parsed.Modified {
			t.Fatalf("table = %+v, %v; want the probe's revision, modified", parsed, err)
		}
		if f.compiled()[0] != farcastPackage {
			t.Fatalf("the probe was not the first build: %v", f.compiled())
		}
	})
}

func TestBuildRefusesNoticesThatDiffer(t *testing.T) {
	src := fakeSource(t)
	if err := os.WriteFile(filepath.Join(src, "THIRD_PARTY_NOTICES"), []byte("stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := &fakeRelease{probe: buildInfo(revisionA, "false"), target: buildInfo(revisionA, "false")}
	code, stderr := run(t, f.seams(t), []string{fakeGitPath(t)}, testPin, "build", "-src", src, "-out", filepath.Join(t.TempDir(), "rel"), "-targets", "linux/amd64")
	if code != 1 || !strings.Contains(stderr, "THIRD_PARTY_NOTICES is not what vendor/ and the pinned Go give") {
		t.Fatalf("exited %d with %q", code, stderr)
	}
}

func TestBaseWritesTheVerifiedDocuments(t *testing.T) {
	src := fakeSource(t)
	docs := [3][]byte{[]byte(`{"index":1}`), []byte(`{"manifest":1}`), []byte(`{"config":1}`)}
	s := (&fakeRelease{}).seams(t)
	var asked oci.Reference
	s.documents = func(_ context.Context, pin oci.Reference, plat oci.Platform, _ io.Writer) ([]byte, []byte, []byte, error) {
		asked = pin
		if plat != image.ComponentPlatform {
			t.Errorf("asked for %s", plat)
		}
		return docs[0], docs[1], docs[2], nil
	}
	if code, stderr := run(t, s, nil, "go1.0.0", "base", "-src", src, "-write"); code != 0 {
		t.Fatalf("base exited %d: %s", code, stderr)
	}
	if asked.String() != image.BaseImage {
		t.Fatalf("fetched %s, want %s", asked, image.BaseImage)
	}
	for i, name := range []string{"index.json", "manifest.json", "config.json"} {
		got, err := os.ReadFile(filepath.Join(src, "farsight/cli/internal/image/base", name))
		if err != nil || !bytes.Equal(got, docs[i]) {
			t.Fatalf("%s = %q, %v; want the registry's exact bytes", name, got, err)
		}
	}
	if code, _ := run(t, s, nil, "go1.0.0", "base", "-src", src); code != 2 {
		t.Fatal("base without -write was not a usage error")
	}
}

func TestReleaseAndSourceBuildsAreTheSameBytes(t *testing.T) {
	// The layers. Each one the release writes must be image.ComponentLayer of
	// the binary it compiled, the one function the source path lays a binary
	// with, and each manifest in its table image.Assemble of that layer on the
	// base. This half needs no Go and always runs. With the binaries equal
	// (below), the release's layers and manifests are then the source path's.
	t.Run("layers", func(t *testing.T) {
		f := &fakeRelease{probe: buildInfo(revisionA, "false"), target: buildInfo(revisionA, "false")}
		out := fullBuild(t, f, fakeSource(t), "-targets", "linux/amd64")
		data, err := os.ReadFile(filepath.Join(out, "layers", "digests.json"))
		if err != nil {
			t.Fatal(err)
		}
		table, err := components.ParseTable(data)
		if err != nil {
			t.Fatal(err)
		}
		base := syntheticBase(t)
		for _, c := range components.All() {
			bin, err := os.ReadFile(filepath.Join(out, "components", c.Name))
			if err != nil {
				t.Fatal(err)
			}
			want, err := image.ComponentLayer(c.BinaryPath, bin)
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(filepath.Join(out, "layers", c.Name+".tar.gz"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want.Blob) {
				t.Errorf("%s: the release's layer is not image.ComponentLayer of its binary", c.Name)
			}
			im, err := image.Assemble(base, want, c.Package, c.BinaryPath)
			if err != nil {
				t.Fatal(err)
			}
			_, manifest, err := im.ManifestBytes()
			if err != nil {
				t.Fatal(err)
			}
			i := slices.IndexFunc(table.Components, func(e components.Entry) bool { return e.Name == c.Name })
			if i < 0 {
				t.Fatalf("%s is not in the table", c.Name)
			}
			if e := table.Components[i]; e.Layer != want.Descriptor.Digest || e.DiffID != want.DiffID || e.Manifest != manifest {
				t.Errorf("%s: the table records layer %s, diffID %s, manifest %s; the source path gives %s, %s, %s",
					c.Name, e.Layer, e.DiffID, e.Manifest, want.Descriptor.Digest, want.DiffID, manifest)
			}
		}
	})

	src, err := image.FindSource("")
	if err != nil {
		t.Fatal(err)
	}
	pin, err := Pin(src)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Version() != pin {
		t.Skipf("this test runs only under exactly %s (./check.sh), not %s", pin, runtime.Version())
	}
	s := defaultSeams()
	tc, err := s.findToolchain(t.Context(), os.Environ(), src)
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	if err := os.MkdirAll(filepath.Join(out, "components"), 0o755); err != nil {
		t.Fatal(err)
	}
	released, err := s.compileComponent(t.Context(), tc, pin, src, out, os.Environ(), components.TechnoCore)
	if err != nil {
		t.Fatal(err)
	}
	source, err := image.GoCompile(t.Context(), src, components.TechnoCore.Package)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(released, source.Data) {
		t.Fatalf("the release's technocore (%d bytes) and goCompile's (%d bytes) differ", len(released), len(source.Data))
	}
	// The layers are then identical too: the "layers" half above holds the
	// release to image.ComponentLayer, which the source path uses and
	// TestGoldenManifestDigests pins. They are not recomputed from these
	// binaries, because gzip at BestCompression over two 7 MB binaries costs
	// about 30 s under -race.
}
