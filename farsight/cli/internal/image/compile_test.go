package image

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoCompileIgnoresTheCallersGoEnvironment(t *testing.T) {
	needShell(t)
	scratch := t.TempDir()
	goenv := filepath.Join(scratch, "go.env")
	if err := os.WriteFile(goenv, []byte("GOAMD64=v3\nGOFLAGS=-tags=netgo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(scratch, "cacheprog-ran")
	cacheprog := filepath.Join(scratch, "cacheprog")
	writeScript(t, cacheprog, "touch '"+marker+"'\nexit 1\n")

	t.Setenv("GOFLAGS", "-tags=netgo -gcflags=all=-N")
	t.Setenv("GOAMD64", "v3")
	t.Setenv("GOEXPERIMENT", "noregabiwrappers")
	t.Setenv("GOFIPS140", "v1.0.0")
	t.Setenv("GOENV", goenv)
	t.Setenv("GOCACHEPROG", cacheprog)

	bin := compileTechnoCore(t.Context(), t)
	if _, err := CheckBinary(bin.Data); err != nil {
		t.Fatalf("the caller's Go environment reached the build: %v", err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("GOCACHEPROG was started (stat %s: %v)", marker, err)
	}
}

func TestGoCompileBinaryIsStripped(t *testing.T) {
	bin := compileTechnoCore(t.Context(), t)
	for _, name := range sections(t, bin.Data) {
		if name == ".symtab" || strings.HasPrefix(name, ".debug_") || strings.HasPrefix(name, ".zdebug_") {
			t.Fatalf("the component carries a %s section", name)
		}
	}
}

func TestGoCompileRefusesAGoOlderThanTheCheckout(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":             "module example.com/old\n\ngo 1.26\n\ntoolchain go1.99.0\n",
		"main.go":            "package main\n\nfunc main() {}\n",
		"vendor/modules.txt": "",
	}
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_, err := goCompile(t.Context(), dir, ".")
	if !errors.Is(err, ErrGoTooOld) {
		t.Fatalf("err = %v, want ErrGoTooOld before anything is compiled", err)
	}
	if !strings.Contains(err.Error(), "go1.99.0") {
		t.Fatalf("the refusal does not name the checkout's toolchain line: %v", err)
	}
}

func TestGoCompileSaysWhenThereIsNoGo(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	_, err := goCompile(t.Context(), checkout(t), "./technocore/cmd/technocore")
	if !errors.Is(err, ErrNoGo) || !strings.Contains(err.Error(), "a release farcast needs none") {
		t.Fatalf("err = %v, want ErrNoGo saying a release farcast needs no Go", err)
	}
}
