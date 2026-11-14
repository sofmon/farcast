package image

import (
	"bufio"
	"bytes"
	"context"
	"debug/buildinfo"
	"debug/elf"
	"errors"
	"fmt"
	"go/version"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"

	"github.com/sofmon/farcast/farsight/cli/internal/oci"
)

// This file is the one recipe for compiling a FarCast component (ADR 0023 M0):
// goCompile (--source and the development fallback) and farcast-release's
// component build both use it, so that the two give byte-identical binaries for
// the same source and the same Go release.

// ComponentPlatform is what every component is compiled for (GKE Autopilot: amd64).
var ComponentPlatform = oci.Platform{OS: "linux", Architecture: "amd64"}

// BuildFlags is the go command line for a component, without the binary name:
//
//	build -trimpath -mod=vendor -buildvcs=false -ldflags=-s -w -o <out> <pkg>
//
// "-ldflags=-s -w" is ONE argv element.
//
// -buildvcs=false keeps a component's digest independent of the commit it was
// built at and keeps git out of the build; -s -w strips the symbol table and the
// DWARF sections, which CheckBinary verifies because -trimpath hides -ldflags
// from the build info.
func BuildFlags(out, pkg string) []string {
	return []string{"build", "-trimpath", "-mod=vendor", "-buildvcs=false", "-ldflags=-s -w", "-o", out, pkg}
}

// Toolchain is the Go a component is compiled with, as the go on PATH reports it.
type Toolchain struct {
	Go         string // <GOROOT>/bin/go (go.exe on Windows): what is executed
	GOROOT     string // absolute
	Version    string // "go1.27.4"
	GOMODCACHE string // absolute; passed on by the release step only
	GOCACHE    string // as go env prints it; may be "off"
}

// ErrNoGo reports that the parent's PATH holds no go.
var ErrNoGo = errors.New("image: the Go toolchain is not on PATH")

// ErrGoTooOld reports a Go older than the checkout's go.mod toolchain line.
var ErrGoTooOld = errors.New("image: the Go toolchain is older than the checkout's toolchain line")

// FindToolchain asks the go that parent's PATH finds (absolute entries only, as
// cluster.lookPathIn does; never symlink-resolved) where its toolchain lives. It
// runs it once, in dir, as `go env GOROOT GOVERSION GOMODCACHE GOCACHE`, with
// parent's environment, any GOTOOLCHAIN entry removed and GOTOOLCHAIN=local
// appended. A version manager's shim (an asdf or goenv script, or a mise symlink
// to its multi-call binary) therefore picks the Go it would pick for dir, and
// that Go names its own GOROOT. It requires an absolute GOROOT, a regular file at
// <GOROOT>/bin/go, and a GOVERSION that go/version accepts. ErrNoGo when PATH has
// no go.
//
// The query runs with the parent's environment because it only reads, and
// GOTOOLCHAIN=local stops it from switching or downloading. What it reports is
// then executed under BuildEnviron, never the shim itself.
func FindToolchain(ctx context.Context, parent []string, dir string) (Toolchain, error) {
	goOnPath, ok := lookGo(envValue(parent, "PATH"))
	if !ok {
		return Toolchain{}, ErrNoGo
	}

	env := make([]string, 0, len(parent)+1)
	for _, kv := range parent {
		if k, _, _ := strings.Cut(kv, "="); k != "GOTOOLCHAIN" {
			env = append(env, kv)
		}
	}
	env = append(env, "GOTOOLCHAIN=local")

	cmd := exec.CommandContext(ctx, goOnPath, "env", "GOROOT", "GOVERSION", "GOMODCACHE", "GOCACHE")
	cmd.Dir = dir
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return Toolchain{}, fmt.Errorf("image: asking %s where its toolchain lives (go env, in %s) failed: %w%s", goOnPath, dir, err, printed(stderr.String()))
	}

	lines := strings.Split(strings.TrimRight(strings.ReplaceAll(stdout.String(), "\r\n", "\n"), "\n"), "\n")
	if len(lines) != 4 {
		return Toolchain{}, fmt.Errorf("image: %s printed %d lines for go env GOROOT GOVERSION GOMODCACHE GOCACHE, not 4%s", goOnPath, len(lines), printed(stdout.String()))
	}
	tc := Toolchain{GOROOT: lines[0], Version: lines[1], GOMODCACHE: lines[2], GOCACHE: lines[3]}
	if !filepath.IsAbs(tc.GOROOT) {
		return Toolchain{}, fmt.Errorf("image: %s reported GOROOT %q, which is not an absolute path", goOnPath, tc.GOROOT)
	}
	tc.Go = filepath.Join(tc.GOROOT, "bin", "go"+exeSuffix())
	if info, err := os.Stat(tc.Go); err != nil || !info.Mode().IsRegular() {
		return Toolchain{}, fmt.Errorf("image: %s reported GOROOT %s, which holds no go at %s", goOnPath, tc.GOROOT, tc.Go)
	}
	if !version.IsValid(tc.Version) {
		return Toolchain{}, fmt.Errorf("image: %s reported GOVERSION %q, which is not a Go version", goOnPath, tc.Version)
	}
	return tc, nil
}

// lookGo finds go on pathValue as cluster.lookPathIn finds kubectl: absolute
// entries only, a regular executable file. The path returned is the one on PATH,
// never symlink-resolved, so a multi-call binary still sees itself invoked as go.
func lookGo(pathValue string) (string, bool) {
	name := "go" + exeSuffix()
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

// BuildEnviron is go build's WHOLE environment for a component; nothing else is
// inherited.
//
//	gotoolchain: "local" (goCompile) or an exact "goX.Y.Z" (the release step).
//	gomodcache: "" (goCompile: not passed) or tc.GOMODCACHE (the release step).
//
// Every variable it drops (GOROOT, GOPATH, GOCACHEPROG, GOAUTH, GOINSECURE,
// GONOSUMDB, GONOPROXY, GOPRIVATE, GOSUMDB, GODEBUG, GIT_*, CC and CGO_* among
// them) changed or could change what is built, or ran something. The result is
// sorted, and every key appears once.
func BuildEnviron(parent []string, tc Toolchain, gotoolchain, gomodcache string) []string {
	env := map[string]string{
		"PATH":         filepath.Dir(tc.Go),
		"GOENV":        "off",
		"GOFLAGS":      "",
		"GOWORK":       "off",
		"GOTOOLCHAIN":  gotoolchain,
		"GOPROXY":      "off",
		"GOAMD64":      "v1",
		"GOEXPERIMENT": "",
		"GOFIPS140":    "off",
		"CGO_ENABLED":  "0",
		"GOOS":         ComponentPlatform.OS,
		"GOARCH":       ComponentPlatform.Architecture,
	}
	for _, k := range []string{"HOME", "TMPDIR"} {
		if v := envValue(parent, k); filepath.IsAbs(v) {
			env[k] = v
		}
	}
	if filepath.IsAbs(tc.GOCACHE) {
		env["GOCACHE"] = tc.GOCACHE
	} else if dir, err := os.UserCacheDir(); err == nil {
		env["GOCACHE"] = filepath.Join(dir, "go-build")
	}
	if gomodcache != "" {
		env["GOMODCACHE"] = gomodcache
	}
	if runtime.GOOS == "windows" {
		// Untested until M4.
		for _, k := range []string{"SYSTEMROOT", "TEMP", "TMP", "USERPROFILE", "LOCALAPPDATA"} {
			if v, ok := lookupEnv(parent, k); ok {
				env[k] = v
			}
		}
	}
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	slices.Sort(out)
	return out
}

// requiredSettings are the build settings a component built by this recipe
// records, exactly. -trimpath hides -ldflags from the build info, which is why
// CheckBinary also reads the ELF sections.
var requiredSettings = map[string]string{
	"-buildmode":  "exe",
	"-compiler":   "gc",
	"-trimpath":   "true",
	"CGO_ENABLED": "0",
	"GOARCH":      "amd64",
	"GOOS":        "linux",
	"GOAMD64":     "v1",
}

// CheckBinary verifies data is a component built by exactly this recipe and
// returns its Go version.
func CheckBinary(data []byte) (goVersion string, err error) {
	info, err := buildinfo.Read(bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("image: read the component's build info: %w", err)
	}
	v, err := checkSettings(info)
	if err != nil {
		return "", err
	}
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("image: the component is not an ELF executable: %w", err)
	}
	defer func() { _ = f.Close() }()
	if f.Class != elf.ELFCLASS64 || f.Machine != elf.EM_X86_64 {
		return "", fmt.Errorf("image: the component is %v %v, not a 64-bit x86-64 executable", f.Class, f.Machine)
	}
	for _, s := range f.Sections {
		if s.Name == ".symtab" || strings.HasPrefix(s.Name, ".debug_") || strings.HasPrefix(s.Name, ".zdebug_") {
			return "", fmt.Errorf("image: the component carries a %s section: it was not built with -ldflags=-s -w", s.Name)
		}
	}
	return v, nil
}

// checkSettings is CheckBinary's build-info half: the settings must be exactly
// requiredSettings, plus DefaultGODEBUG with any value (present when the
// module's go line implies GODEBUG defaults). Anything else — a vcs* stamp,
// -tags, -gcflags, -asmflags, GOEXPERIMENT, GOFIPS140 — is refused.
func checkSettings(info *debug.BuildInfo) (string, error) {
	if info.GoVersion == "" {
		return "", errors.New("image: the component's build info names no Go version")
	}
	if info.Main.Version != "(devel)" {
		return "", fmt.Errorf("image: the component's main module version is %q, not (devel): it was not built from a checkout by this recipe", info.Main.Version)
	}
	seen := map[string]bool{}
	for _, s := range info.Settings {
		if seen[s.Key] {
			return "", fmt.Errorf("image: the component's build info records %s twice", s.Key)
		}
		seen[s.Key] = true
		if s.Key == "DefaultGODEBUG" {
			continue
		}
		want, ok := requiredSettings[s.Key]
		if !ok {
			return "", fmt.Errorf("image: the component was built with %s=%s, which the recipe never sets", s.Key, s.Value)
		}
		if s.Value != want {
			return "", fmt.Errorf("image: the component was built with %s=%s, not %s=%s", s.Key, s.Value, s.Key, want)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(requiredSettings)) {
		if !seen[k] {
			return "", fmt.Errorf("image: the component's build info does not record %s=%s", k, requiredSettings[k])
		}
	}
	return info.GoVersion, nil
}

// ToolchainFloor reads <sourceDir>/go.mod's toolchain line ("go1.27.4"); "" when
// absent. The line is the one whose first field is toolchain, and the value is
// its second field: the same rule ./check.sh and farcast-release use.
func ToolchainFloor(sourceDir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(sourceDir, "go.mod"))
	if err != nil {
		return "", fmt.Errorf("image: read the checkout's go.mod: %w", err)
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 || fields[0] != "toolchain" {
			continue
		}
		if len(fields) < 2 || !version.IsValid(fields[1]) {
			return "", fmt.Errorf("image: %s's toolchain line %q names no Go version", filepath.Join(sourceDir, "go.mod"), sc.Text())
		}
		return fields[1], nil
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("image: read the checkout's go.mod: %w", err)
	}
	return "", nil
}

// checkFloor refuses a Go older than the checkout's toolchain line. A newer Go
// is allowed: that is ADR 0023 decision 6's operator-chosen toolchain.
func checkFloor(goPath, have, floor string) error {
	if floor != "" && version.Compare(have, floor) < 0 {
		return fmt.Errorf("image: %s is %s, older than this checkout's toolchain line %s; use a Go at or above it: %w", goPath, have, floor, ErrGoTooOld)
	}
	return nil
}

// envValue is the value of key in env, last entry winning as in os/exec; "" when
// absent.
func envValue(env []string, key string) string {
	v, _ := lookupEnv(env, key)
	return v
}

func lookupEnv(env []string, key string) (string, bool) {
	var v string
	var found bool
	for _, kv := range env {
		k, val, ok := strings.Cut(kv, "=")
		if ok && k == key {
			v, found = val, true
		}
	}
	return v, found
}

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// printed renders a subprocess's output for an error message.
func printed(s string) string {
	if s = strings.TrimSpace(s); s == "" {
		return ""
	}
	return ": " + s
}
