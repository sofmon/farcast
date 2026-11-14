// Package release is farcast-release: it builds FarCast's four components with
// exactly go.mod's toolchain Go, writes their layers and the digests a released
// farcast carries, builds farcast with them embedded, and writes SHA256SUMS
// (ADR 0023 decision 4). It also writes THIRD_PARTY_NOTICES and the committed
// base-image documents.
//
// It is a development tool and is never linked into farcast. It is a Go command
// rather than a script because a release host already needs exactly Go and git,
// and a script would add tar, gzip, a sha256 tool and a JSON tool whose
// behaviour differs between macOS and Linux, and a second copy of the layer
// recipe. It reuses oci, image and components directly instead.
package release

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"

	"github.com/sofmon/farcast/farsight/cli/internal/components"
	"github.com/sofmon/farcast/farsight/cli/internal/image"
	"github.com/sofmon/farcast/farsight/cli/internal/oci"
)

// defaultTargets are the platforms 'build' makes farcast for when -targets is
// not given.
const defaultTargets = "darwin/arm64,darwin/amd64,linux/amd64,linux/arm64"

// allowedTargets are the platforms 'build' accepts in -targets.
var allowedTargets = []string{"darwin/arm64", "darwin/amd64", "linux/amd64", "linux/arm64", "windows/amd64"}

// farcastPackage is what 'build' links, with the components embedded.
const farcastPackage = "./farsight/cli/cmd/farcast"

// layersDir is where the components package embeds its layers from, relative to
// the checkout. The release tool never writes there: it overlays it.
const layersDir = "farsight/cli/internal/components/layers"

// baseDir is where the committed base-image documents live, relative to the
// checkout.
const baseDir = "farsight/cli/internal/image/base"

// The refusals a release build gives, word for word.
const (
	errNeedsGit = "farcast-release build needs git and a repository: farcast is stamped with its commit"
	errDirty    = "the tree has uncommitted changes; a release is built from a clean commit (-allow-dirty builds one that refuses its own components)"
)

const usage = `usage: GOTOOLCHAIN=<pin> go run ./farsight/cli/cmd/farcast-release <subcommand> [flags]

subcommands:
  build      build the four components, their layers and digest table, and farcast with them embedded
  layers     build the four components, their layers and digest table only
  notices    write THIRD_PARTY_NOTICES
  base       fetch the pinned base image's three documents into farsight/cli/internal/image/base/ (network)
  execsites  list what FarCast's shipped binaries can start (the exec gate)
`

// errUsage marks a usage error: exit 2.
var errUsage = errors.New("usage")

// usageError is a refusal that exits 2: the invocation, not the tree, is wrong.
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

// options is one invocation's parsed flags.
type options struct {
	args       []string // the arguments after the program name, for messages
	out        string
	src        string
	targets    []string
	allowDirty bool
	output     string // notices -o; "" is stdout
	write      bool   // base -write
}

// seams are the process boundaries of a release, replaceable in tests.
type seams struct {
	findToolchain func(ctx context.Context, parent []string, dir string) (image.Toolchain, error)
	runGo         func(ctx context.Context, tc image.Toolchain, dir string, env, args []string) error
	buildInfo     func(path string) (*debug.BuildInfo, error)
	checkBinary   func(data []byte) (string, error)
	pinnedBase    func() (*oci.Image, error)
	notices       func(src string, w io.Writer) error
	documents     func(ctx context.Context, pin oci.Reference, plat oci.Platform, progress io.Writer) (index, manifest, config []byte, err error)
}

func defaultSeams() seams {
	return seams{
		findToolchain: image.FindToolchain,
		runGo:         runGo,
		buildInfo:     buildinfo.ReadFile,
		checkBinary:   image.CheckBinary,
		pinnedBase:    image.PinnedBase,
		notices:       Notices,
		documents: func(ctx context.Context, pin oci.Reference, plat oci.Platform, progress io.Writer) ([]byte, []byte, []byte, error) {
			// Anonymous: no Credentials, so nothing is offered to the registry.
			// Every request is listed, so the operator sees what the fetch touched.
			client := &oci.Client{HTTP: &http.Client{Transport: listedTransport{progress}}}
			return client.Documents(ctx, pin, plat)
		},
	}
}

// Run is farcast-release with its process seams made explicit, so that the
// runtime check and every refusal can be tested: args are the arguments after
// the program name, and runtimeVersion is runtime.Version() in production. The
// exit codes are 0 for success, 1 for a failure and 2 for a usage error.
// Progress goes to stderr; stdout is used only by notices (and execsites,
// which the command itself dispatches to execgate.Run).
func Run(ctx context.Context, args []string, env []string, stdout, stderr io.Writer, runtimeVersion string) int {
	return defaultSeams().run(ctx, args, env, stdout, stderr, runtimeVersion)
}

func (s seams) run(ctx context.Context, args []string, env []string, stdout, stderr io.Writer, runtimeVersion string) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	sub, rest := args[0], args[1:]
	opts, err := parseFlags(sub, rest, stderr)
	if err != nil {
		if !errors.Is(err, errUsage) {
			_, _ = fmt.Fprintf(stderr, "farcast-release %s: %v\n", sub, err)
		}
		return 2
	}
	opts.args = args

	switch sub {
	case "build":
		err = s.build(ctx, opts, env, stderr, runtimeVersion, true)
	case "layers":
		err = s.build(ctx, opts, env, stderr, runtimeVersion, false)
	case "notices":
		err = s.writeNotices(opts, stdout)
	case "base":
		err = s.base(ctx, opts, stderr)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "farcast-release %s: %v\n", sub, err)
		var u *usageError
		if errors.As(err, &u) {
			return 2
		}
		return 1
	}
	return 0
}

// parseFlags parses one subcommand's flags. Any error is a usage error.
func parseFlags(sub string, args []string, stderr io.Writer) (options, error) {
	var opts options
	fs := flag.NewFlagSet("farcast-release "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var targets string
	switch sub {
	case "build":
		fs.StringVar(&opts.out, "out", "", "the output directory (required; absent or empty; outside -src)")
		fs.StringVar(&opts.src, "src", "", "the farcast checkout (default: the one containing the working directory)")
		fs.StringVar(&targets, "targets", defaultTargets, "the platforms farcast is built for, comma-separated: "+strings.Join(allowedTargets, ", "))
		fs.BoolVar(&opts.allowDirty, "allow-dirty", false, "build from a tree with uncommitted changes (the result refuses its own components)")
	case "layers":
		fs.StringVar(&opts.out, "out", "", "the output directory (required; absent or empty; outside -src)")
		fs.StringVar(&opts.src, "src", "", "the farcast checkout (default: the one containing the working directory)")
	case "notices":
		fs.StringVar(&opts.src, "src", "", "the farcast checkout (default: the one containing the working directory)")
		fs.StringVar(&opts.output, "o", "", "the file to write (default: stdout)")
	case "base":
		fs.StringVar(&opts.src, "src", "", "the farcast checkout (default: the one containing the working directory)")
		fs.BoolVar(&opts.write, "write", false, "fetch the documents and write them (required)")
	case "execsites":
		return options{}, errors.New("execsites is dispatched by the farcast-release command to execgate.Run")
	default:
		return options{}, fmt.Errorf("unknown subcommand %q\n%s", sub, usage)
	}
	if err := fs.Parse(args); err != nil {
		return options{}, errUsage
	}
	if fs.NArg() != 0 {
		return options{}, fmt.Errorf("unexpected arguments %q", fs.Args())
	}

	switch sub {
	case "build", "layers":
		if opts.out == "" {
			return options{}, errors.New("-out is required")
		}
	case "base":
		if !opts.write {
			return options{}, errors.New("-write is required: base fetches the pinned base image's documents from its registry and writes them into the tree")
		}
	}
	if sub == "build" {
		for t := range strings.SplitSeq(targets, ",") {
			t = strings.TrimSpace(t)
			if !slices.Contains(allowedTargets, t) {
				return options{}, fmt.Errorf("-targets: %q is not one of %s", t, strings.Join(allowedTargets, ", "))
			}
			if !slices.Contains(opts.targets, t) {
				opts.targets = append(opts.targets, t)
			}
		}
	}
	if opts.src == "" {
		src, err := image.FindSource("")
		if err != nil {
			return options{}, fmt.Errorf("-src: %w", err)
		}
		opts.src = src
	}
	return opts, nil
}

// Pin is the Go release FarCast is built with: the second field of the line in
// <src>/go.mod whose first field is toolchain.
func Pin(src string) (string, error) {
	pin, err := image.ToolchainFloor(src)
	if err != nil {
		return "", err
	}
	if pin == "" {
		return "", fmt.Errorf("release: %s has no toolchain line, and a release is built with exactly the Go it names", filepath.Join(src, "go.mod"))
	}
	return pin, nil
}

// physical is p made absolute and symlink-resolved. A p that does not exist yet
// resolves through its nearest existing ancestor.
//
// The go child gets an explicit environment without PWD, so it computes package
// directories from the physical working directory; an overlay keyed by a
// logical path (one under /tmp, a symlink to /private/tmp on macOS) would match
// nothing and the tagged build would fail.
func physical(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	var rest []string
	for at := abs; ; {
		resolved, err := filepath.EvalSymlinks(at)
		if err == nil {
			return filepath.Join(append([]string{resolved}, rest...)...), nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(at)
		if parent == at {
			return "", err
		}
		rest = append([]string{filepath.Base(at)}, rest...)
		at = parent
	}
}

// inside reports whether p is dir or lies under it; both are physical paths.
func inside(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// build is the 'build' subcommand (design §1.3.7, steps 1–10), and with full
// false the 'layers' subcommand: steps 1–6, with no farcast, no git and an
// empty revision.
func (s seams) build(ctx context.Context, opts options, env []string, progress io.Writer, runtimeVersion string, full bool) error {
	say := func(format string, args ...any) {
		_, _ = fmt.Fprintf(progress, "farcast-release: "+format+"\n", args...)
	}

	// 1. The pin, the source and the out directory.
	src, err := filepath.Abs(opts.src)
	if err == nil {
		src, err = filepath.EvalSymlinks(src)
	}
	if err != nil {
		return &usageError{fmt.Sprintf("-src %s: %v", opts.src, err)}
	}
	out, err := physical(opts.out)
	if err != nil {
		return &usageError{fmt.Sprintf("-out %s: %v", opts.out, err)}
	}
	pin, err := Pin(src)
	if err != nil {
		return err
	}
	if runtimeVersion != pin {
		return &usageError{fmt.Sprintf("run me with exactly %s: GOTOOLCHAIN=%s go run ./farsight/cli/cmd/farcast-release %s", pin, pin, strings.Join(opts.args, " "))}
	}
	if inside(out, src) {
		return &usageError{fmt.Sprintf("-out %s lies inside -src %s: a release never writes into the tree it is built from", out, src)}
	}
	if entries, err := os.ReadDir(out); err == nil && len(entries) > 0 {
		return &usageError{fmt.Sprintf("-out %s exists and is not empty: give a new or empty directory", out)}
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return &usageError{fmt.Sprintf("-out %s: %v", out, err)}
	}

	// 2. The toolchain: under go run, the go on PATH is the pinned one.
	tc, err := s.findToolchain(ctx, env, src)
	if err != nil {
		return err
	}
	if tc.Version != pin {
		return fmt.Errorf("the go on PATH is %s (%s), not %s: run me as GOTOOLCHAIN=%s go run ./farsight/cli/cmd/farcast-release", tc.Version, tc.Go, pin, pin)
	}
	if !filepath.IsAbs(tc.GOMODCACHE) || !filepath.IsAbs(tc.GOCACHE) {
		return fmt.Errorf("go env reports GOMODCACHE %q and GOCACHE %q; a release needs both to be absolute paths", tc.GOMODCACHE, tc.GOCACHE)
	}
	say("building with %s (%s), from %s into %s", pin, tc.GOROOT, src, out)
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}

	// 3. The source revision, from an untagged probe build of farcast.
	var revision, gitDir string
	var modified bool
	if full {
		git, ok := lookPath("git", envValue(env, "PATH"))
		if !ok {
			return errors.New(errNeedsGit)
		}
		gitDir = filepath.Dir(git)
		revision, modified, err = s.probeRevision(ctx, tc, pin, src, out, env, gitDir)
		if err != nil {
			return err
		}
		if revision == "" {
			return errors.New(errNeedsGit)
		}
		if modified && !opts.allowDirty {
			return errors.New(errDirty)
		}
		say("source revision %s (modified: %t)", revision, modified)
	}

	// 4. The base, from the committed documents.
	base, err := s.pinnedBase()
	if err != nil {
		return err
	}

	// 5. The components.
	for _, dir := range []string{"components", "layers"} {
		if err := os.MkdirAll(filepath.Join(out, dir), 0o755); err != nil {
			return err
		}
	}
	table := components.Table{
		Format:   1,
		Go:       pin,
		Base:     image.BaseImage,
		Platform: image.ComponentPlatform.String(),
		Revision: revision,
		Modified: modified,
	}
	for _, c := range components.All() {
		say("compiling %s (%s)", c.Name, c.Package)
		data, err := s.compileComponent(ctx, tc, pin, src, out, env, c)
		if err != nil {
			return err
		}
		layer, err := image.ComponentLayer(c.BinaryPath, data)
		if err != nil {
			return err
		}
		im, err := image.Assemble(base, layer, c.Package, c.BinaryPath)
		if err != nil {
			return err
		}
		_, manifest, err := im.ManifestBytes()
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(out, "layers", c.Name+".tar.gz"), layer.Blob, 0o644); err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		table.Components = append(table.Components, components.Entry{
			Name:         c.Name,
			Package:      c.Package,
			BinaryPath:   c.BinaryPath,
			Go:           pin,
			BinarySHA256: hex.EncodeToString(sum[:]),
			BinarySize:   int64(len(data)),
			Layer:        layer.Descriptor.Digest,
			LayerSize:    layer.Descriptor.Size,
			DiffID:       layer.DiffID,
			Config:       im.Manifest.Config.Digest,
			Manifest:     manifest,
		})
		say("  %s: %d bytes, layer %s (%d bytes), manifest %s", c.Name, len(data), layer.Descriptor.Digest, layer.Descriptor.Size, manifest)
	}

	// 6. The table.
	encoded, err := components.EncodeTable(table)
	if err != nil {
		return err
	}
	if _, err := components.ParseTable(encoded); err != nil {
		return fmt.Errorf("the table written here does not parse: %w", err)
	}
	if err := os.WriteFile(filepath.Join(out, "layers", "digests.json"), encoded, 0o644); err != nil {
		return err
	}
	if !full {
		return writeSums(out)
	}

	// 7. The overlay.
	overlay, err := overlayJSON(src, out)
	if err != nil {
		return err
	}
	overlayPath := filepath.Join(out, "overlay.json")
	if err := os.WriteFile(overlayPath, overlay, 0o644); err != nil {
		return err
	}

	// 8. farcast, per target, with the components embedded.
	for _, target := range opts.targets {
		goos, goarch, _ := strings.Cut(target, "/")
		name := "farcast-" + goos + "-" + goarch
		if goos == "windows" {
			name += ".exe"
		}
		say("linking %s", name)
		bin := filepath.Join(out, name)
		args := []string{"build", "-trimpath", "-mod=vendor", "-buildvcs=true", "-tags=farcast_embedded", "-ldflags=-s -w", "-overlay", overlayPath, "-o", bin, farcastPackage}
		if err := s.runGo(ctx, tc, src, farcastEnviron(env, tc, pin, gitDir, goos, goarch), args); err != nil {
			return err
		}
		info, err := s.buildInfo(bin)
		if err != nil {
			return fmt.Errorf("read the build info of %s: %w", name, err)
		}
		if err := checkRelease(info, pin, revision, opts.allowDirty); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}

	// 9. The notices.
	var notices bytes.Buffer
	if err := s.notices(src, &notices); err != nil {
		return err
	}
	committed, err := os.ReadFile(filepath.Join(src, "THIRD_PARTY_NOTICES"))
	if err != nil {
		return fmt.Errorf("read the committed THIRD_PARTY_NOTICES: %w", err)
	}
	if !bytes.Equal(committed, notices.Bytes()) {
		return errors.New("THIRD_PARTY_NOTICES is not what vendor/ and the pinned Go give; regenerate it with 'go run ./farsight/cli/cmd/farcast-release notices -o THIRD_PARTY_NOTICES' and review the diff")
	}
	if err := os.WriteFile(filepath.Join(out, "THIRD_PARTY_NOTICES"), committed, 0o644); err != nil {
		return err
	}

	// 10. The checksums.
	if err := writeSums(out); err != nil {
		return err
	}
	say("done: %s", filepath.Join(out, "SHA256SUMS"))
	return nil
}

// probeRevision links farcast untagged for this host into <out>/probe and
// reads its VCS stamp, so the tool learns the revision without running git
// itself. The probe is deleted.
func (s seams) probeRevision(ctx context.Context, tc image.Toolchain, pin, src, out string, env []string, gitDir string) (string, bool, error) {
	dir := filepath.Join(out, "probe")
	defer func() { _ = os.RemoveAll(dir) }()
	bin := filepath.Join(dir, "farcast")
	args := []string{"build", "-trimpath", "-mod=vendor", "-buildvcs=true", "-ldflags=-s -w", "-o", bin, farcastPackage}
	if err := s.runGo(ctx, tc, src, farcastEnviron(env, tc, pin, gitDir, runtime.GOOS, runtime.GOARCH), args); err != nil {
		return "", false, err
	}
	info, err := s.buildInfo(bin)
	if err != nil {
		return "", false, fmt.Errorf("read the probe's build info: %w", err)
	}
	return setting(info, "vcs.revision"), setting(info, "vcs.modified") == "true", nil
}

// compileComponent is the release's component build: the recipe, with the pin
// and the release host's module cache, into <out>/components/<name>. Its bytes
// must equal goCompile's for the same source and Go.
func (s seams) compileComponent(ctx context.Context, tc image.Toolchain, pin, src, out string, env []string, c components.Component) ([]byte, error) {
	bin := filepath.Join(out, "components", c.Name)
	if err := s.runGo(ctx, tc, src, image.BuildEnviron(env, tc, pin, tc.GOMODCACHE), image.BuildFlags(bin, c.Package)); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(bin)
	if err != nil {
		return nil, err
	}
	v, err := s.checkBinary(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", c.Name, err)
	}
	if v != pin {
		return nil, fmt.Errorf("%s was built with %s, not %s", c.Name, v, pin)
	}
	return data, nil
}

// checkRelease checks a linked farcast's build info against the release.
func checkRelease(info *debug.BuildInfo, pin, revision string, allowDirty bool) error {
	if info.GoVersion != pin {
		return fmt.Errorf("built with %s, not %s", info.GoVersion, pin)
	}
	for _, want := range [...]struct{ key, value string }{{"-tags", "farcast_embedded"}, {"-trimpath", "true"}, {"CGO_ENABLED", "0"}} {
		if got := setting(info, want.key); got != want.value {
			return fmt.Errorf("built with %s=%q, not %s=%s", want.key, got, want.key, want.value)
		}
	}
	if setting(info, "vcs.revision") != revision {
		return fmt.Errorf("the tree moved to another commit during the build (%s, not %s)", setting(info, "vcs.revision"), revision)
	}
	if setting(info, "vcs.modified") != "false" && !allowDirty {
		return errors.New(errDirty)
	}
	return nil
}

func setting(info *debug.BuildInfo, key string) string {
	for _, s := range info.Settings {
		if s.Key == key {
			return s.Value
		}
	}
	return ""
}

// farcastEnviron is BuildEnviron for linking farcast for goos/goarch: the
// target's GOOS and GOARCH, GOAMD64=v1 or GOARM64=v8.0, and git after the
// toolchain on PATH for the VCS stamp.
func farcastEnviron(parent []string, tc image.Toolchain, pin, gitDir, goos, goarch string) []string {
	env := map[string]string{}
	for _, kv := range image.BuildEnviron(parent, tc, pin, tc.GOMODCACHE) {
		k, v, _ := strings.Cut(kv, "=")
		env[k] = v
	}
	env["GOOS"], env["GOARCH"] = goos, goarch
	delete(env, "GOAMD64")
	switch goarch {
	case "amd64":
		env["GOAMD64"] = "v1"
	case "arm64":
		env["GOARM64"] = "v8.0"
	}
	if gitDir != "" {
		env["PATH"] = filepath.Dir(tc.Go) + string(filepath.ListSeparator) + gitDir
	}
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	slices.Sort(out)
	return out
}

// layerFiles are the files the overlay supplies to the components package.
func layerFiles() []string {
	var files []string
	for _, c := range components.All() {
		files = append(files, c.Name+".tar.gz")
	}
	return append(files, "digests.json")
}

// overlayJSON maps each file the components package embeds onto the one this
// release wrote. Both sides are physical paths.
func overlayJSON(src, out string) ([]byte, error) {
	replace := map[string]string{}
	for _, f := range layerFiles() {
		replace[filepath.Join(src, filepath.FromSlash(layersDir), f)] = filepath.Join(out, "layers", f)
	}
	return json.Marshal(struct {
		Replace map[string]string
	}{replace})
}

// writeSums writes <out>/SHA256SUMS over components/*, layers/*, farcast-* and
// THIRD_PARTY_NOTICES: one "<64 hex>  <path>" line per file, LF, sorted by path
// in byte order. overlay.json, which holds absolute paths, is never listed.
func writeSums(out string) error {
	var files []string
	for _, dir := range []string{"components", "layers"} {
		entries, err := os.ReadDir(filepath.Join(out, dir))
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.Type().IsRegular() {
				files = append(files, path.Join(dir, e.Name()))
			}
		}
	}
	entries, err := os.ReadDir(out)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Type().IsRegular() && (strings.HasPrefix(e.Name(), "farcast-") || e.Name() == "THIRD_PARTY_NOTICES") {
			files = append(files, e.Name())
		}
	}
	slices.Sort(files)
	var b bytes.Buffer
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(f)))
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(sum[:]), f)
	}
	return os.WriteFile(filepath.Join(out, "SHA256SUMS"), b.Bytes(), 0o644)
}

// writeNotices is the 'notices' subcommand: THIRD_PARTY_NOTICES to -o, or
// stdout. The file is generated in full before anything is written, so a
// failure never leaves a partial one behind.
func (s seams) writeNotices(opts options, stdout io.Writer) error {
	var buf bytes.Buffer
	if err := s.notices(opts.src, &buf); err != nil {
		return err
	}
	if opts.output == "" {
		_, err := stdout.Write(buf.Bytes())
		return err
	}
	return os.WriteFile(opts.output, buf.Bytes(), 0o644)
}

// base is the 'base' subcommand: the network fetch of the pinned base image's
// index, linux/amd64 manifest and config into farsight/cli/internal/image/base/,
// anonymously, verified against image.BaseImage. It is the documented procedure
// for a base bump: change BaseImage, run base -write, review, commit.
func (s seams) base(ctx context.Context, opts options, progress io.Writer) error {
	src, err := filepath.Abs(opts.src)
	if err == nil {
		src, err = filepath.EvalSymlinks(src)
	}
	if err != nil {
		return &usageError{fmt.Sprintf("-src %s: %v", opts.src, err)}
	}
	pin, err := oci.ParseReference(image.BaseImage)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(progress, "farcast-release: fetching the %s documents of %s, anonymously\n", image.ComponentPlatform, pin)
	index, manifest, config, err := s.documents(ctx, pin, image.ComponentPlatform, progress)
	if err != nil {
		return err
	}
	if index == nil {
		return fmt.Errorf("%s pins a manifest, not an index; the committed documents are an index, its %s manifest and its config", pin, image.ComponentPlatform)
	}
	dir := filepath.Join(src, filepath.FromSlash(baseDir))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, f := range []struct {
		name string
		data []byte
	}{{"index.json", index}, {"manifest.json", manifest}, {"config.json", config}} {
		p := filepath.Join(dir, f.name)
		if err := os.WriteFile(p, f.data, 0o644); err != nil {
			return err
		}
		sum := sha256.Sum256(f.data)
		_, _ = fmt.Fprintf(progress, "farcast-release: wrote %s: %d bytes, sha256:%s\n", p, len(f.data), hex.EncodeToString(sum[:]))
	}
	return nil
}

// listedTransport lists each request's method, host and path (never its query
// or headers) and the answer, so 'base -write' says exactly where it went.
type listedTransport struct{ w io.Writer }

func (t listedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := http.DefaultTransport.RoundTrip(req)
	status := "failed"
	if err == nil {
		status = resp.Status
	}
	_, _ = fmt.Fprintf(t.w, "farcast-release:   %s %s://%s%s: %s\n", req.Method, req.URL.Scheme, req.URL.Host, req.URL.Path, status)
	return resp, err
}

// runGo runs the toolchain's go with exactly env, in dir.
func runGo(ctx context.Context, tc image.Toolchain, dir string, env, args []string) error {
	cmd := exec.CommandContext(ctx, tc.Go, args...)
	cmd.Dir = dir
	cmd.Env = env
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(output.String())
		if msg != "" {
			msg = ":\n" + msg
		}
		return fmt.Errorf("go %s: %w%s", strings.Join(args, " "), err, msg)
	}
	return nil
}

// lookPath finds name on pathValue: absolute entries only, a regular
// executable file, never symlink-resolved.
func lookPath(name, pathValue string) (string, bool) {
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	for _, dir := range filepath.SplitList(pathValue) {
		if dir == "" || !filepath.IsAbs(dir) {
			continue
		}
		p := filepath.Join(dir, name)
		info, err := os.Stat(p)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
			continue
		}
		return p, true
	}
	return "", false
}

// envValue is the value of key in env, the last entry winning; "" when absent.
func envValue(env []string, key string) string {
	var v string
	for _, kv := range env {
		if k, val, ok := strings.Cut(kv, "="); ok && k == key {
			v = val
		}
	}
	return v
}
