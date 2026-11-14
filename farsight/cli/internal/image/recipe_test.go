package image

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"testing"
)

func TestBuildFlagsAreTheRecipe(t *testing.T) {
	got := BuildFlags("/out/fatline", "./fatline/cmd/fatline")
	want := []string{"build", "-trimpath", "-mod=vendor", "-buildvcs=false", "-ldflags=-s -w", "-o", "/out/fatline", "./fatline/cmd/fatline"}
	if !slices.Equal(got, want) {
		t.Fatalf("BuildFlags = %q, want %q", got, want)
	}
}

func TestBuildEnvironIsAnAllowlist(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows rows are untested until M4")
	}
	parent := []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=/home/operator",
		"TMPDIR=/private/tmp/operator",
		"GOFLAGS=-tags=netgo",
		"GOENV=/home/operator/go.env",
		"GOAMD64=v3",
		"GOEXPERIMENT=noregabiwrappers",
		"GOFIPS140=v1.0.0",
		"GOTOOLCHAIN=auto",
		"GOCACHEPROG=/home/operator/cacheprog",
		"GIT_DIR=/elsewhere/.git",
		"GOROOT=/elsewhere/go",
		"GOWORK=/home/operator/go.work",
		"GOPROXY=https://proxy.example",
		"GOAUTH=git",
		"GOINSECURE=*",
		"GODEBUG=gotypesalias=0",
		"GOCACHE=relative/cache",
		"GOMODCACHE=/parent/modcache",
		"GOPATH=/parent/gopath",
		"CC=/usr/bin/evilcc",
		"CGO_CFLAGS=-O0",
	}
	tc := Toolchain{
		Go:         "/opt/go/bin/go",
		GOROOT:     "/opt/go",
		Version:    "go1.27.4",
		GOMODCACHE: "/home/operator/go/pkg/mod",
		GOCACHE:    "/home/operator/.cache/go-build",
	}

	t.Run("the release step", func(t *testing.T) {
		got := BuildEnviron(parent, tc, "go1.27.4", tc.GOMODCACHE)
		want := []string{
			"CGO_ENABLED=0",
			"GOAMD64=v1",
			"GOARCH=amd64",
			"GOCACHE=/home/operator/.cache/go-build",
			"GOENV=off",
			"GOEXPERIMENT=",
			"GOFIPS140=off",
			"GOFLAGS=",
			"GOMODCACHE=/home/operator/go/pkg/mod",
			"GOOS=linux",
			"GOPROXY=off",
			"GOTOOLCHAIN=go1.27.4",
			"GOWORK=off",
			"HOME=/home/operator",
			"PATH=/opt/go/bin",
			"TMPDIR=/private/tmp/operator",
		}
		if !slices.Equal(got, want) {
			t.Fatalf("BuildEnviron =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	})

	t.Run("goCompile", func(t *testing.T) {
		got := BuildEnviron(parent, tc, "local", "")
		want := []string{
			"CGO_ENABLED=0",
			"GOAMD64=v1",
			"GOARCH=amd64",
			"GOCACHE=/home/operator/.cache/go-build",
			"GOENV=off",
			"GOEXPERIMENT=",
			"GOFIPS140=off",
			"GOFLAGS=",
			"GOOS=linux",
			"GOPROXY=off",
			"GOTOOLCHAIN=local",
			"GOWORK=off",
			"HOME=/home/operator",
			"PATH=/opt/go/bin",
			"TMPDIR=/private/tmp/operator",
		}
		if !slices.Equal(got, want) {
			t.Fatalf("BuildEnviron =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	})

	t.Run("a relative HOME and a cache go env calls off", func(t *testing.T) {
		cacheDir, err := os.UserCacheDir()
		if err != nil {
			t.Skip("no user cache directory here")
		}
		off := tc
		off.GOCACHE = "off"
		got := BuildEnviron([]string{"HOME=relative", "TMPDIR="}, off, "local", "")
		if slices.ContainsFunc(got, func(kv string) bool { return strings.HasPrefix(kv, "HOME=") || strings.HasPrefix(kv, "TMPDIR=") }) {
			t.Fatalf("a relative HOME or an empty TMPDIR was passed: %q", got)
		}
		if want := "GOCACHE=" + filepath.Join(cacheDir, "go-build"); !slices.Contains(got, want) {
			t.Fatalf("BuildEnviron = %q, want Go's own default %s", got, want)
		}
	})
}

// recipeBuildInfo is what a component built by the recipe records.
func recipeBuildInfo() *debug.BuildInfo {
	return &debug.BuildInfo{
		GoVersion: "go1.27.4",
		Path:      "github.com/sofmon/farcast/fatline/cmd/fatline",
		Main:      debug.Module{Path: "github.com/sofmon/farcast", Version: "(devel)"},
		Settings: []debug.BuildSetting{
			{Key: "-buildmode", Value: "exe"},
			{Key: "-compiler", Value: "gc"},
			{Key: "-trimpath", Value: "true"},
			{Key: "DefaultGODEBUG", Value: "gotypesalias=0"},
			{Key: "CGO_ENABLED", Value: "0"},
			{Key: "GOARCH", Value: "amd64"},
			{Key: "GOOS", Value: "linux"},
			{Key: "GOAMD64", Value: "v1"},
		},
	}
}

func TestCheckSettings(t *testing.T) {
	v, err := checkSettings(recipeBuildInfo())
	if err != nil || v != "go1.27.4" {
		t.Fatalf("checkSettings(the recipe's set) = %q, %v; want go1.27.4", v, err)
	}
	withoutGODEBUG := recipeBuildInfo()
	withoutGODEBUG.Settings = slices.DeleteFunc(withoutGODEBUG.Settings, func(s debug.BuildSetting) bool { return s.Key == "DefaultGODEBUG" })
	if _, err := checkSettings(withoutGODEBUG); err != nil {
		t.Fatalf("DefaultGODEBUG is optional, but its absence was refused: %v", err)
	}

	add := func(k, v string) func(*debug.BuildInfo) {
		return func(i *debug.BuildInfo) { i.Settings = append(i.Settings, debug.BuildSetting{Key: k, Value: v}) }
	}
	set := func(k, v string) func(*debug.BuildInfo) {
		return func(i *debug.BuildInfo) {
			for n := range i.Settings {
				if i.Settings[n].Key == k {
					i.Settings[n].Value = v
				}
			}
		}
	}
	refused := map[string]func(*debug.BuildInfo){
		"vcs.revision":     add("vcs.revision", "006e479afcf0aaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		"-tags=netgo":      add("-tags", "netgo"),
		"GOAMD64=v3":       set("GOAMD64", "v3"),
		"GOFIPS140=v1.0.0": add("GOFIPS140", "v1.0.0"),
		"GOEXPERIMENT=x":   add("GOEXPERIMENT", "x"),
		"-gcflags":         add("-gcflags", "all=-N"),
		"no -trimpath=true": func(i *debug.BuildInfo) {
			i.Settings = slices.DeleteFunc(i.Settings, func(s debug.BuildSetting) bool { return s.Key == "-trimpath" })
		},
		"-trimpath=false":      set("-trimpath", "false"),
		"a version, not devel": func(i *debug.BuildInfo) { i.Main.Version = "v0.1.0" },
		"no Go version":        func(i *debug.BuildInfo) { i.GoVersion = "" },
		"a setting twice":      add("GOOS", "linux"),
		"CGO_ENABLED=1":        set("CGO_ENABLED", "1"),
		"another target":       set("GOARCH", "arm64"),
		"-buildmode=pie":       set("-buildmode", "pie"),
		"an unknown key":       add("-ldflags", "-s -w"),
		"DefaultGODEBUG twice": add("DefaultGODEBUG", "x=1"),
		"no GOAMD64 at all": func(i *debug.BuildInfo) {
			i.Settings = slices.DeleteFunc(i.Settings, func(s debug.BuildSetting) bool { return s.Key == "GOAMD64" })
		},
		"vcs.modified":          add("vcs.modified", "false"),
		"-asmflags":             add("-asmflags", "all=-x"),
		"the race detector on":  add("-race", "true"),
		"a mismatched compiler": set("-compiler", "gccgo"),
	}
	for name, mutate := range refused {
		t.Run(name, func(t *testing.T) {
			info := recipeBuildInfo()
			mutate(info)
			if v, err := checkSettings(info); err == nil {
				t.Fatalf("checkSettings accepted %+v (Go %s)", info.Settings, v)
			}
		})
	}
}

func TestToolchainFloor(t *testing.T) {
	cases := map[string]struct {
		gomod string
		want  string
		fails bool
	}{
		"the pin":          {gomod: "module example.com/m\n\ngo 1.26\n\ntoolchain go1.27.4\n", want: "go1.27.4"},
		"no toolchain":     {gomod: "module example.com/m\n\ngo 1.26\n", want: ""},
		"extra spaces":     {gomod: "module example.com/m\ngo 1.26\n  toolchain\tgo1.28rc1  // a comment\n", want: "go1.28rc1"},
		"a toolchain dep":  {gomod: "module example.com/m\ngo 1.26\nrequire golang.org/toolchain v0.0.1\n", want: ""},
		"no version":       {gomod: "module example.com/m\ngo 1.26\ntoolchain\n", fails: true},
		"not a go version": {gomod: "module example.com/m\ngo 1.26\ntoolchain default\n", fails: true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(c.gomod), 0o644); err != nil {
				t.Fatal(err)
			}
			got, err := ToolchainFloor(dir)
			if c.fails {
				if err == nil {
					t.Fatalf("ToolchainFloor = %q, want an error", got)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("ToolchainFloor = %q, %v; want %q", got, err, c.want)
			}
		})
	}
	if _, err := ToolchainFloor(t.TempDir()); err == nil {
		t.Fatal("a directory with no go.mod was accepted")
	}
}

func TestGoTooOld(t *testing.T) {
	cases := []struct {
		have, floor string
		old         bool
	}{
		{"go1.27.3", "go1.27.4", true},
		{"go1.27.4", "go1.27.4", false},
		{"go1.27.5", "go1.27.4", false},
		{"go1.28.0", "go1.27.4", false},
		{"go1.28rc1", "go1.27.4", false},
		{"go1.28rc1", "go1.28.0", true},
		{"go1.26.9", "go1.27.0", true},
		{"go1.27.4", "", false},
	}
	for _, c := range cases {
		err := checkFloor("/opt/go/bin/go", c.have, c.floor)
		if got := errors.Is(err, ErrGoTooOld); got != c.old {
			t.Errorf("checkFloor(%s, floor %q) = %v, want too old %v", c.have, c.floor, err, c.old)
		}
		if c.old && !strings.Contains(err.Error(), "older than this checkout's toolchain line "+c.floor) {
			t.Errorf("the refusal does not name the floor: %v", err)
		}
	}
}

// --- the real go -----------------------------------------------------------
//
// These tests run the Go on PATH. go test puts its own GOROOT/bin first, so
// under ./check.sh (GOTOOLCHAIN=<pin>) that is the pin. Under GOTOOLCHAIN=local
// with a Go older than the checkout's toolchain line they fail with
// ErrGoTooOld, by design: they do not skip.

// realGo is the absolute path of the go this test process would run.
func realGo(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("these tests need a Go on PATH: %v", err)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

// realGOROOT is what the real go reports as its GOROOT.
func realGOROOT(t *testing.T, goPath string) string {
	t.Helper()
	cmd := exec.Command(goPath, "env", "GOROOT")
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go env GOROOT: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// checkout is the farcast checkout these tests run in.
func checkout(t *testing.T) string {
	t.Helper()
	src, err := FindSource("")
	if err != nil {
		t.Fatal(err)
	}
	return src
}

func needShell(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake go is a shell script")
	}
}

// writeScript writes an executable shell script.
func writeScript(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
}

// withPath is env with PATH replaced.
func withPath(env []string, path string) []string {
	out := slices.DeleteFunc(slices.Clone(env), func(kv string) bool { return strings.HasPrefix(kv, "PATH=") })
	return append(out, "PATH="+path)
}

func TestFindToolchainAsksTheShim(t *testing.T) {
	needShell(t)
	goPath := realGo(t)
	goroot := realGOROOT(t, goPath)
	src := checkout(t)

	t.Run("a script shim", func(t *testing.T) {
		shims := t.TempDir()
		writeScript(t, filepath.Join(shims, "go"), "exec '"+goPath+"' \"$@\"\n")
		t.Setenv("PATH", shims+":/bin:/usr/bin")

		tc, err := FindToolchain(t.Context(), os.Environ(), src)
		if err != nil {
			t.Fatal(err)
		}
		if tc.GOROOT != goroot {
			t.Fatalf("GOROOT = %s, want the real one, %s", tc.GOROOT, goroot)
		}
		if want := filepath.Join(goroot, "bin", "go"); tc.Go != want || tc.Go == filepath.Join(shims, "go") {
			t.Fatalf("Go = %s, want %s and never the shim", tc.Go, want)
		}

		bin, err := goCompile(t.Context(), src, "./technocore/cmd/technocore")
		if err != nil {
			t.Fatalf("goCompile through the shim: %v", err)
		}
		if bin.GoVersion != tc.Version {
			t.Fatalf("built with %s, want %s", bin.GoVersion, tc.Version)
		}
	})

	t.Run("a multi-call symlink", func(t *testing.T) {
		shims := t.TempDir()
		multi := filepath.Join(shims, "multi")
		writeScript(t, multi, `case "$(basename "$0")" in
go) exec '`+goPath+`' "$@" ;;
*) echo "multi: invoked as $0, not as go" >&2; exit 64 ;;
esac
`)
		if err := os.Symlink(multi, filepath.Join(shims, "go")); err != nil {
			t.Fatal(err)
		}
		tc, err := FindToolchain(t.Context(), withPath(os.Environ(), shims+":/bin:/usr/bin"), src)
		if err != nil {
			t.Fatalf("FindToolchain did not invoke the symlink by its own name: %v", err)
		}
		if tc.GOROOT != goroot {
			t.Fatalf("GOROOT = %s, want %s", tc.GOROOT, goroot)
		}
	})
}

func TestFindToolchainRefusesWhatItCannotUse(t *testing.T) {
	needShell(t)
	emptyRoot := t.TempDir()
	cases := map[string]string{
		"a relative GOROOT":    "printf '%s\\n' relative/goroot go1.27.4 /mc /gc\n",
		"a GOROOT with no go":  "printf '%s\\n' '" + emptyRoot + "' go1.27.4 /mc /gc\n",
		"a malformed version":  "printf '%s\\n' '" + filepath.Dir(filepath.Dir(realGo(t))) + "' 'go one' /mc /gc\n",
		"too few lines":        "printf '%s\\n' /opt/go go1.27.4\n",
		"go env fails":         "echo 'go: something went wrong' >&2; exit 1\n",
		"an empty GOVERSION":   "printf '%s\\n' '" + filepath.Dir(filepath.Dir(realGo(t))) + "' '' /mc /gc\n",
		"no GOROOT at all":     "printf '\\n%s\\n%s\\n%s\\n' go1.27.4 /mc /gc\n",
		"a GOROOT that is bin": "printf '%s\\n' '" + filepath.Dir(realGo(t)) + "' go1.27.4 /mc /gc\n",
	}
	for name, script := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeScript(t, filepath.Join(dir, "go"), script)
			if tc, err := FindToolchain(t.Context(), []string{"PATH=" + dir + ":/bin:/usr/bin"}, t.TempDir()); err == nil {
				t.Fatalf("FindToolchain accepted %+v", tc)
			}
		})
	}

	t.Run("no go on PATH", func(t *testing.T) {
		dir := t.TempDir()
		// A go that is not executable, and one in a relative entry, are not found.
		if err := os.WriteFile(filepath.Join(dir, "go"), []byte("#!/bin/sh\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := FindToolchain(t.Context(), []string{"PATH=" + dir + ":relative/bin:"}, t.TempDir())
		if !errors.Is(err, ErrNoGo) {
			t.Fatalf("err = %v, want ErrNoGo", err)
		}
	})
}

func TestCheckBinaryRefusesAnUnstrippedBuild(t *testing.T) {
	src := checkout(t)
	tc, err := FindToolchain(t.Context(), os.Environ(), src)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "technocore")
	flags := slices.DeleteFunc(BuildFlags(out, "./technocore/cmd/technocore"), func(f string) bool { return f == "-ldflags=-s -w" })
	cmd := exec.CommandContext(t.Context(), tc.Go, flags...)
	cmd.Dir = src
	cmd.Env = BuildEnviron(os.Environ(), tc, "local", "")
	if msg, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, msg)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckBinary(data); err == nil || !strings.Contains(err.Error(), "-ldflags=-s -w") {
		t.Fatalf("CheckBinary(an unstripped build) = %v, want a refusal naming -s -w", err)
	}
}

// compileTechnoCore is goCompile on the checkout's technocore.
func compileTechnoCore(ctx context.Context, t *testing.T) Binary {
	t.Helper()
	bin, err := goCompile(ctx, checkout(t), "./technocore/cmd/technocore")
	if err != nil {
		t.Fatal(err)
	}
	return bin
}

// sections lists an ELF file's section names.
func sections(t *testing.T, data []byte) []string {
	t.Helper()
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range f.Sections {
		names = append(names, s.Name)
	}
	return names
}
