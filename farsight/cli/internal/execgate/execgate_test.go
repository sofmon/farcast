package execgate

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// The scan resolves each file's import names and sees references, not call
// shapes: every form below is a way to reach something that starts a
// process, and each must produce its line.
func TestScanSeesEveryForm(t *testing.T) {
	files := []srcFile{
		{"p/a.go", []byte("package p\n\nimport \"os/exec\"\n\nfunc A() { _ = exec.Command(\"a\"); _ = exec.Command(\"b\") }\n")},
		// An aliased import, in a package that already imports os/exec.
		{"p/b.go", []byte("package p\n\nimport ex \"os/exec\"\n\nfunc B() { _ = ex.Command(\"sh\") }\n")},
		{"p/c.go", []byte("package p\n\nimport . \"os/exec\"\n\nfunc C() { _ = Command(\"sh\") }\n")},
		{"p/d.go", []byte("package p\n\nimport \"os/exec\"\n\nfunc D() { f := exec.CommandContext; _ = f }\n")},
		{"p/e.go", []byte("package p\n\nimport \"os/exec\"\n\nfunc E() *exec.Cmd { return new(exec.Cmd) }\n")},
		{"p/f.go", []byte("package p\n\nimport \"os/exec\"\n\nvar c exec.Cmd\n")},
		// A selector split after the dot.
		{"p/g.go", []byte("package p\n\nimport \"os/exec\"\n\nfunc G() {\n\t_ = exec.\n\t\tCommand(\"sh\")\n}\n")},
		{"p/h.go", []byte("package p\n\nimport \"syscall\"\n\nfunc H() { _ = syscall.CreateProcess(nil, nil, nil, nil, false, 0, nil, nil, nil, nil) }\n")},
		{"p/i.go", []byte("package p\n\nimport \"golang.org/x/sys/windows\"\n\nfunc I() { _ = windows.ShellExecute(0, nil, nil, nil, nil, 0) }\n")},
		{"p/j.go", []byte("package p\n\nimport \"golang.org/x/sys/unix\"\n\nfunc J() { unix.Syscall(unix.SYS_EXECVE, 0, 0, 0) }\n")},
		{"p/k.go", []byte("package p\n\nimport _ \"unsafe\"\n\n//go:linkname startProcess os.startProcess\nfunc startProcess()\n\n//go:linkname nanotime runtime.nanotime\nfunc nanotime() int64\n")},
		// A function literal counts towards the method that holds it.
		{"p/m.go", []byte("package p\n\nimport \"os\"\n\ntype T struct{}\n\nfunc (t *T) M() { go func() { _, _ = os.StartProcess(\"x\", nil, nil) }() }\n")},
		// A local that shadows the import is not the package; a field or a
		// method named like a watched name is not one either.
		{"p/n.go", []byte("package p\n\nimport \"os/exec\"\n\ntype R struct{ Command func() }\n\nfunc N(r R) {\n\texec := struct{ Command func() }{}\n\texec.Command()\n\tr.Command()\n}\n")},
	}
	got, err := scanPackage("example.com/p", files)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"import example.com/p os/exec",
		"linkname p/k.go startProcess os.startProcess",
		"ref p/a.go A os/exec.Command 2x",
		"ref p/b.go B os/exec.Command 1x",
		"ref p/c.go C os/exec.Command 1x",
		"ref p/d.go D os/exec.CommandContext 1x",
		"ref p/e.go E os/exec.Cmd 2x",
		"ref p/f.go - os/exec.Cmd 1x",
		"ref p/g.go G os/exec.Command 1x",
		"ref p/h.go H syscall.CreateProcess 1x",
		"ref p/i.go I golang.org/x/sys/windows.ShellExecute 1x",
		"ref p/j.go J golang.org/x/sys/unix.SYS_EXECVE 1x",
		"ref p/m.go T.M os.StartProcess 1x",
	}
	if !slices.Equal(got, want) {
		t.Errorf("scan\n got %q\nwant %q", got, want)
	}

	// Inside a watched package's own source, a bare reference to one of its
	// own watched names is a site, in the file that declares it or another;
	// the declaration is not.
	got, err = scanPackage("golang.org/x/sys/windows", []srcFile{
		{"vendor/golang.org/x/sys/windows/z.go", []byte("package windows\n\nfunc CreateProcess() error { return nil }\n\nfunc again() error { return CreateProcess() }\n")},
		{"vendor/golang.org/x/sys/windows/w.go", []byte("package windows\n\nfunc run() error { return CreateProcess() }\n\nfunc shadow() { CreateProcess := 1; _ = CreateProcess }\n")},
	})
	if err != nil {
		t.Fatal(err)
	}
	want = []string{
		"ref vendor/golang.org/x/sys/windows/w.go run golang.org/x/sys/windows.CreateProcess 1x",
		"ref vendor/golang.org/x/sys/windows/z.go again golang.org/x/sys/windows.CreateProcess 1x",
	}
	if !slices.Equal(got, want) {
		t.Errorf("scan of x/sys/windows\n got %q\nwant %q", got, want)
	}

	if _, err := scanPackage("example.com/p", []srcFile{{"p/bad.go", []byte("package p\n\nfunc (\n")}}); err == nil {
		t.Error("a file that does not parse was scanned")
	}
}

// writeModule writes a module named like the repository, with no
// dependencies, holding files (path → contents), and returns its directory.
func writeModule(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	all := map[string]string{
		"go.mod":                     "module github.com/sofmon/farcast\n\ngo 1.26\n",
		"vendor/modules.txt":         "",
		"farsight/cli/cmd/x/main.go": "package main\n\nimport _ \"github.com/sofmon/farcast/farsight/cli/internal/components\"\n\nfunc main() {}\n",
		"farsight/cli/internal/components/off.go": "package components\n",
		// The configuration a release builds: it embeds a layer file that
		// only the release's overlay provides, and it imports os/exec.
		"farsight/cli/internal/components/on.go": "//go:build farcast_embedded\n\npackage components\n\nimport (\n\t_ \"embed\"\n\t\"os/exec\"\n)\n\n//go:embed layers/x.tar.gz\nvar layer []byte\n\nvar _ = exec.Command\n",
	}
	for p, body := range files {
		all[p] = body
	}
	for p, body := range all {
		path := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// listEnviron is this process's environment, offline.
func listEnviron() []string { return append(os.Environ(), "GOPROXY=off") }

// The tagged configuration is listed too, although the layer file its embed
// names does not exist: a site only the release's farcast links is a line.
func TestListingIncludesTaggedFiles(t *testing.T) {
	// The gate's own targets, exactly: farcast on its five platforms, listed
	// with -tags farcast_embedded too, and the four components for
	// linux/amd64. Neither the tagged listing nor fatline, shrike or
	// technocore adds a line today, so dropping one would shrink what step 1b
	// sees with no line of its output changing.
	wantShipped := []target{
		{"farcast", "./farsight/cli/cmd/farcast", []string{"darwin/arm64", "darwin/amd64", "linux/amd64", "linux/arm64", "windows/amd64"}, true},
		{"fatline", "./fatline/cmd/fatline", []string{"linux/amd64"}, false},
		{"shrike", "./shrike/cmd/shrike", []string{"linux/amd64"}, false},
		{"technocore", "./technocore/cmd/technocore", []string{"linux/amd64"}, false},
		{"datasphered", "./datasphere/cmd/datasphere", []string{"linux/amd64"}, false},
	}
	if !reflect.DeepEqual(shipped, wantShipped) {
		t.Errorf("the gate lists\n%+v\nwant exactly\n%+v", shipped, wantShipped)
	}

	dir := writeModule(t, nil)
	x := target{binary: "x", pkg: "./farsight/cli/cmd/x", platforms: []string{"linux/amd64"}}

	untagged, err := list(context.Background(), dir, listEnviron(), []target{x})
	if err != nil {
		t.Fatal(err)
	}
	if len(untagged) != 0 {
		t.Errorf("untagged, the module starts nothing; got %q", untagged)
	}

	x.tagged = true
	got, err := list(context.Background(), dir, listEnviron(), []target{x})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"x linux/amd64 import github.com/sofmon/farcast/farsight/cli/internal/components os/exec",
		"x linux/amd64 ref farsight/cli/internal/components/on.go - os/exec.Command 1x",
	}
	if !slices.Equal(got, want) {
		t.Errorf("tagged listing\n got %q\nwant %q", got, want)
	}
}

// A build constraint set in the caller's go env file does not hide a file
// from the listing: an empty GOFLAGS falls back to that file, so the listing
// turns the file off, whether GOENV names it or it sits where go looks by
// default.
func TestListingIgnoresTheCallersGoEnvFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the default go env file is under AppData")
	}
	dir := writeModule(t, map[string]string{
		"farsight/cli/cmd/x/site.go": "//go:build !hidden\n\npackage main\n\nimport \"os/exec\"\n\nvar _ = exec.Command\n",
	})
	envFile := func(t *testing.T, path string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("GOFLAGS=-tags=hidden\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	named := filepath.Join(t.TempDir(), "env")
	envFile(t, named)
	// os.UserConfigDir's go/env, on darwin and on other Unix.
	home := t.TempDir()
	envFile(t, filepath.Join(home, "Library", "Application Support", "go", "env"))
	envFile(t, filepath.Join(home, ".config", "go", "env"))

	x := target{binary: "x", pkg: "./farsight/cli/cmd/x", platforms: []string{"linux/amd64"}}
	want := []string{
		"x linux/amd64 import github.com/sofmon/farcast/farsight/cli/cmd/x os/exec",
		"x linux/amd64 ref farsight/cli/cmd/x/site.go - os/exec.Command 1x",
	}
	for what, extra := range map[string][]string{
		"GOENV names it":   {"GOENV=" + named, "HOME=" + t.TempDir()},
		"the default file": {"HOME=" + home, "XDG_CONFIG_HOME=" + filepath.Join(home, ".config")},
	} {
		extra = append(extra, "GOCACHE="+t.TempDir())
		env := slices.DeleteFunc(listEnviron(), func(kv string) bool {
			return strings.HasPrefix(kv, "GOENV=") || strings.HasPrefix(kv, "HOME=") || strings.HasPrefix(kv, "XDG_CONFIG_HOME=")
		})
		got, err := list(context.Background(), dir, append(append(env, "GOFLAGS="), extra...), []target{x})
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s, with -tags=hidden in the go env file\n got %q\nwant %q", what, got, want)
		}
	}
}

// The embed-pattern error of the tagged components package is the only
// package error a listing accepts: a syntax error anywhere else fails it, as
// does the same embed error in any other package.
func TestListingRefusesAnyOtherPackageError(t *testing.T) {
	x := target{binary: "x", pkg: "./farsight/cli/cmd/x", platforms: []string{"linux/amd64"}, tagged: true}
	for name, files := range map[string]map[string]string{
		"a syntax error": {"farsight/cli/cmd/x/broken.go": "package main\n\nfunc broken( {\n"},
		"an embed error elsewhere": {
			"farsight/cli/cmd/x/main.go":  "package main\n\nimport (\n\t_ \"embed\"\n\n\t_ \"github.com/sofmon/farcast/farsight/cli/internal/components\"\n)\n\n//go:embed missing.txt\nvar s string\n\nfunc main() {}\n",
			"farsight/cli/cmd/x/other.go": "package main\n",
		},
	} {
		dir := writeModule(t, files)
		lines, err := list(context.Background(), dir, listEnviron(), []target{x})
		if err == nil {
			t.Errorf("%s: the listing succeeded: %q", name, lines)
		}
	}
}

// Run takes no arguments, and lists only from the repository root.
func TestRunTakesNoArguments(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Run(context.Background(), []string{"-v"}, listEnviron(), &out, &errb); code != 2 || out.Len() != 0 {
		t.Errorf("with an argument: exit %d, stdout %q", code, out.String())
	}
	t.Chdir(t.TempDir())
	errb.Reset()
	if code := Run(context.Background(), nil, listEnviron(), &out, &errb); code != 1 || !strings.Contains(errb.String(), "repository root") {
		t.Errorf("outside the repository: exit %d, stderr %q", code, errb.String())
	}
}
