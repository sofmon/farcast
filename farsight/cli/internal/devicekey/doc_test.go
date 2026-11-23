package devicekey

import (
	"fmt"
	"go/build"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// devicekeyImportPath is the package's own import path.
const devicekeyImportPath = "github.com/sofmon/farcast/farsight/cli/internal/devicekey"

// devicekeyTestOnlyImports are what the package's tests may import beyond the
// standard library: the package itself, and go-yaml's root package, to parse
// the trust store document.
var devicekeyTestOnlyImports = []string{
	devicekeyImportPath,
	"github.com/goccy/go-yaml",
}

// isStandardPackage reports whether path is a standard-library package:
// go/build finds it under GOROOT. With no source directory go/build never
// asks the go command, so this runs offline.
func isStandardPackage(path string) bool {
	p, err := build.Default.Import(path, "", build.FindOnly)
	return err == nil && p.Goroot
}

// devicekeyImportFaults lists the package in dir as ctx reads it, and what is
// wrong with its imports, as kube/doc_test.go's importFaults does: every file
// is read whatever its build constraints, and cgo is on for the listing, so
// neither a file for another platform nor a cgo file can carry an import
// past it.
func devicekeyImportFaults(ctx build.Context, dir string) (*build.Package, []string, error) {
	ctx.UseAllFiles = true
	ctx.CgoEnabled = true
	pkg, err := ctx.ImportDir(dir, 0)
	if err != nil {
		return nil, nil, err
	}
	var faults []string
	if len(pkg.CgoFiles) != 0 {
		faults = append(faults, fmt.Sprintf("devicekey has cgo files %v; it is pure Go", pkg.CgoFiles))
	}
	for _, imp := range pkg.Imports {
		if imp == "C" || !isStandardPackage(imp) {
			faults = append(faults, fmt.Sprintf("devicekey imports %s; its production files import the standard library only (spec §1.1)", imp))
		}
	}
	for _, imp := range append(slices.Clone(pkg.TestImports), pkg.XTestImports...) {
		if slices.Contains(devicekeyTestOnlyImports, imp) || isStandardPackage(imp) {
			continue
		}
		faults = append(faults, fmt.Sprintf("devicekey's tests import %s; they may import only the standard library, devicekey and github.com/goccy/go-yaml", imp))
	}
	return pkg, faults, nil
}

// TestDevicekeyImportsOnlyTheStandardLibrary holds §1.1's import rule:
// production files import the standard library only, and tests the standard
// library, devicekey itself and go-yaml's root package.
func TestDevicekeyImportsOnlyTheStandardLibrary(t *testing.T) {
	pkg, faults, err := devicekeyImportFaults(build.Default, ".")
	if err != nil {
		t.Fatalf("list the package's imports: %v", err)
	}
	if pkg.Name != "devicekey" {
		t.Fatalf("package name = %q, want devicekey", pkg.Name)
	}
	if len(pkg.Imports) == 0 || len(pkg.TestImports) == 0 {
		t.Fatal("go/build listed no imports; the listing is not reading the package")
	}
	if !slices.Contains(pkg.TestImports, "github.com/goccy/go-yaml") {
		t.Error("the listing does not show the tests' go-yaml import; it is not reading the test files")
	}
	for _, f := range faults {
		t.Error(f)
	}
}

// TestTheDevicekeyImportCheckRefuses keeps the import test honest: a
// production file importing kube or go-yaml, a test importing a go-yaml
// subpackage, and a cgo file are each refused, even when the listing context
// has cgo off.
func TestTheDevicekeyImportCheckRefuses(t *testing.T) {
	dir := t.TempDir()
	for name, src := range map[string]string{
		"a.go":      "package devicekey\n\nimport \"fmt\"\n\nvar _ = fmt.Sprint\n",
		"b.go":      "package devicekey\n\nimport _ \"github.com/sofmon/farcast/farsight/cli/internal/kube\"\n",
		"c.go":      "package devicekey\n\nimport _ \"github.com/goccy/go-yaml\"\n",
		"d_test.go": "package devicekey\n\nimport _ \"github.com/goccy/go-yaml/ast\"\n",
		"zz_cgo.go": "package devicekey\n\nimport \"C\"\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ctx := build.Default
	ctx.CgoEnabled = false
	_, faults, err := devicekeyImportFaults(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(faults, "\n")
	for _, want := range []string{
		"devicekey has cgo files [zz_cgo.go]",
		"devicekey imports github.com/sofmon/farcast/farsight/cli/internal/kube",
		"devicekey imports github.com/goccy/go-yaml;",
		"tests import github.com/goccy/go-yaml/ast",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("the check missed %q; it said:\n%s", want, all)
		}
	}
	if !isStandardPackage("crypto/x509") || isStandardPackage("github.com/goccy/go-yaml") || isStandardPackage(devicekeyImportPath) {
		t.Error("isStandardPackage does not tell the standard library apart")
	}
}
