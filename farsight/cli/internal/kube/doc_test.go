package kube

import (
	"fmt"
	"go/build"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// kubeAllowedImports are the four non-standard imports the package may make
// (§2.1). Everything else must be the standard library.
var kubeAllowedImports = []string{
	"github.com/sofmon/farcast/technocore/kube",
	"cloud.google.com/go/auth",
	"github.com/goccy/go-yaml",
	"github.com/goccy/go-yaml/parser",
	"github.com/goccy/go-yaml/ast",
}

// kubeTestOnlyImports are what the package's tests may import beyond those:
// the package itself (from package kube_test) and its fake.
var kubeTestOnlyImports = []string{
	"github.com/sofmon/farcast/farsight/cli/internal/kube",
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest",
}

// isStandard reports whether path is a standard-library package: go/build
// finds it under GOROOT. With no source directory go/build never asks the go
// command, so this runs offline.
func isStandard(path string) bool {
	p, err := build.Default.Import(path, "", build.FindOnly)
	return err == nil && p.Goroot
}

// TestKubeImportsOnlyItsFour holds the package to the standard library and
// the four packages §2.1 names: technocore/kube, cloud.google.com/go/auth
// (the root package only), and go-yaml with its parser and ast.
func TestKubeImportsOnlyItsFour(t *testing.T) {
	pkg, faults, err := importFaults(build.Default, ".")
	if err != nil {
		t.Fatalf("list the package's imports: %v", err)
	}
	if pkg.Name != "kube" {
		t.Fatalf("package name = %q, want kube", pkg.Name)
	}
	if len(pkg.Imports) == 0 {
		t.Fatal("go/build listed no imports at all; the listing is not reading the package")
	}
	for _, f := range faults {
		t.Error(f)
	}
}

// importFaults lists the package in dir as ctx reads it, and what is wrong
// with its imports. Every file is read, whatever its build constraints, so a
// file for another platform cannot carry an import past it. Cgo is on for the
// listing whatever ctx (CGO_ENABLED) says: with it off, go/build sets a cgo
// file aside with its imports unread (go1.27.4 src/go/build/build.go,
// Context.Import), so a run under CGO_ENABLED=0 would pass any import a cgo
// file made. And the package may have no cgo file at all: it is pure Go.
func importFaults(ctx build.Context, dir string) (*build.Package, []string, error) {
	ctx.UseAllFiles = true
	ctx.CgoEnabled = true
	pkg, err := ctx.ImportDir(dir, 0)
	if err != nil {
		return nil, nil, err
	}
	var faults []string
	if len(pkg.CgoFiles) != 0 {
		faults = append(faults, fmt.Sprintf("kube has cgo files %v; it is pure Go", pkg.CgoFiles))
	}
	for _, imp := range pkg.Imports {
		if imp == "C" || slices.Contains(kubeAllowedImports, imp) || isStandard(imp) {
			continue
		}
		faults = append(faults, fmt.Sprintf("kube imports %s, which is neither the standard library nor one of its four (ADR 0023 M2 §2.1)", imp))
	}
	tests := append(slices.Clone(pkg.TestImports), pkg.XTestImports...)
	for _, imp := range tests {
		if slices.Contains(kubeAllowedImports, imp) || slices.Contains(kubeTestOnlyImports, imp) || isStandard(imp) {
			continue
		}
		faults = append(faults, fmt.Sprintf("kube's tests import %s; they may import only the standard library, the package's four, the package itself and kubetest", imp))
	}
	return pkg, faults, nil
}

// TestTheImportCheckReadsCgoFilesWithCgoOff (C-C2-3): a cgo file's imports are
// checked, and the file itself refused, even when the listing context has cgo
// off, as it does under CGO_ENABLED=0.
func TestTheImportCheckReadsCgoFilesWithCgoOff(t *testing.T) {
	dir := t.TempDir()
	for name, src := range map[string]string{
		"a.go":      "package kube\n\nimport \"fmt\"\n\nvar _ = fmt.Sprint\n",
		"zz_cgo.go": "package kube\n\nimport \"C\"\n\nimport _ \"cloud.google.com/go/auth/httptransport\"\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ctx := build.Default
	ctx.CgoEnabled = false
	_, faults, err := importFaults(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(faults, "\n")
	for _, want := range []string{"kube has cgo files [zz_cgo.go]", "kube imports cloud.google.com/go/auth/httptransport"} {
		if !strings.Contains(all, want) {
			t.Errorf("with cgo off, the check missed %q; it said:\n%s", want, all)
		}
	}
}

// TestIsStandardTellsTheStandardLibraryApart keeps the import test honest: a
// classifier that called everything standard would pass any import.
func TestIsStandardTellsTheStandardLibraryApart(t *testing.T) {
	for _, p := range []string{"net/http", "crypto/x509", "encoding/json"} {
		if !isStandard(p) {
			t.Errorf("isStandard(%q) = false, want true", p)
		}
	}
	for _, p := range []string{
		"github.com/sofmon/farcast/farsight/cli/internal/config",
		"cloud.google.com/go/auth/httptransport",
		"golang.org/x/net/http2",
		"example/notstd",
	} {
		if isStandard(p) {
			t.Errorf("isStandard(%q) = true, want false", p)
		}
	}
}
