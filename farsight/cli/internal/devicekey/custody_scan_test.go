package devicekey

import (
	"bufio"
	"fmt"
	"go/ast"
	goparser "go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The call-site guard (spec §1.7.1). Consent records an intent, and the type
// cannot stop any code in the module calling GiveConsent; so the review is
// enforced at the call sites, as cli/readerrbac_test.go scans its own.

// farcastModule is the module whose files the guard scans.
const farcastModule = "github.com/sofmon/farcast"

// custodyImporters lists the files outside devicekey and outside tests that
// may import it, each a slash path from the module root. Empty in M3a: only
// tests and the walk probe import devicekey, so farcast does not link it.
// Every file added here is reviewed under ADR 0024's custody rules.
var custodyImporters = []string{}

// custodyCallers maps each watched function or method to the sites outside
// tests allowed to name it, each "<file>:<function>". Empty in M3a, so every
// M3b caller is added on purpose and reviewed.
var custodyCallers = map[string][]string{}

// custodyPackageFuncs are the watched package-level functions, found through
// the file's import name for devicekey, an alias or a dot import included.
var custodyPackageFuncs = []string{"GiveConsent", "Enrol"}

// custodyMethods are the watched methods of *Store. A method is named without
// the import (s.OpenForWrite), and a file can reach a *Store without
// importing devicekey, so any selector with one of these names, in any file,
// counts: an over-approximation a reviewer clears by listing the site.
var custodyMethods = []string{"OpenForWrite", "RenewWriterLeaf", "RenewAnchor", "OpenStaged", "CommitAnchor", "AddRole"}

// minShippedFiles is the fewest non-test files a scan of this module may
// parse. There are about 233; a walk that skips the tree by mistake parses
// none, and must not pass.
const minShippedFiles = 100

// moduleRoot walks up from dir to the go.mod whose module line is module.
func moduleRoot(dir, module string) (string, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for {
		if modulePath(filepath.Join(dir, "go.mod")) == module {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.mod for %s above the test's directory", module)
		}
		dir = parent
	}
}

// modulePath is the module line of the go.mod at p, or "".
func modulePath(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "module "); ok {
			if q, err := strconv.Unquote(strings.TrimSpace(rest)); err == nil {
				return q
			}
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

// shippedGoFiles lists the module's non-test Go files, as slash paths from
// root. It skips vendor/ and sdk/ (its own module) at the root, every
// testdata/, every directory holding a go.mod of its own, and every directory
// whose own name starts with '.'. A directory is judged by its name relative
// to root, never by its absolute path: a worktree itself lives under .claude/.
func shippedGoFiles(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "." {
				return nil
			}
			name := d.Name()
			if rel == "vendor" || rel == "sdk" || name == "testdata" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			if _, err := os.Lstat(filepath.Join(p, "go.mod")); err == nil {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(rel, ".go") && !strings.HasSuffix(rel, "_test.go") {
			files = append(files, rel)
		}
		return nil
	})
	return files, err
}

// devicekeyRel is the package's directory, as a slash path from the root.
const devicekeyRel = "farsight/cli/internal/devicekey"

// custodyScan is what a scan of a module found.
type custodyScan struct {
	parsed    int
	importers []string            // files outside devicekey that import it
	sites     map[string][]string // watched name → "<file>:<function>"
}

// scanCustody parses every shipped file of the module at root and lists who
// imports devicekey and who names a watched function or method.
func scanCustody(root string) (*custodyScan, error) {
	files, err := shippedGoFiles(root)
	if err != nil {
		return nil, err
	}
	scan := &custodyScan{sites: map[string][]string{}}
	fset := token.NewFileSet()
	for _, rel := range files {
		file, err := goparser.ParseFile(fset, filepath.Join(root, filepath.FromSlash(rel)), nil, goparser.SkipObjectResolution)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", rel, err)
		}
		scan.parsed++
		if path.Dir(rel) == devicekeyRel {
			continue
		}
		names, dot, imports := devicekeyImportNames(file)
		if imports {
			scan.importers = append(scan.importers, rel)
		}
		for name, fns := range custodySites(file, names, dot) {
			for _, fn := range fns {
				scan.sites[name] = append(scan.sites[name], rel+":"+fn)
			}
		}
	}
	return scan, nil
}

// devicekeyImportNames is the names file imports devicekey under, whether one
// is a dot import, and whether it imports devicekey at all.
func devicekeyImportNames(file *ast.File) (names []string, dot, imports bool) {
	for _, spec := range file.Imports {
		p, err := strconv.Unquote(spec.Path.Value)
		if err != nil || p != devicekeyImportPath {
			continue
		}
		imports = true
		switch {
		case spec.Name == nil:
			names = append(names, "devicekey")
		case spec.Name.Name == ".":
			dot = true
		case spec.Name.Name != "_":
			names = append(names, spec.Name.Name)
		}
	}
	return names, dot, imports
}

// custodySites lists, per watched name, the functions of file that name it:
// a package function through one of names, or bare under a dot import; a
// method through any selector.
func custodySites(file *ast.File, names []string, dot bool) map[string][]string {
	sites := map[string][]string{}
	var visit func(fn string) func(ast.Node) bool
	visit = func(fn string) func(ast.Node) bool {
		return func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.SelectorExpr:
				if x, ok := n.X.(*ast.Ident); ok && slices.Contains(names, x.Name) && slices.Contains(custodyPackageFuncs, n.Sel.Name) {
					sites[n.Sel.Name] = append(sites[n.Sel.Name], fn)
				}
				if slices.Contains(custodyMethods, n.Sel.Name) {
					sites[n.Sel.Name] = append(sites[n.Sel.Name], fn)
				}
				ast.Inspect(n.X, visit(fn)) // not n.Sel: it is not a bare name
				return false
			case *ast.Ident:
				if dot && slices.Contains(custodyPackageFuncs, n.Name) {
					sites[n.Name] = append(sites[n.Name], fn)
				}
			}
			return true
		}
	}
	for _, decl := range file.Decls {
		fn := "package level"
		if f, ok := decl.(*ast.FuncDecl); ok {
			fn = f.Name.Name
			if f.Recv != nil && len(f.Recv.List) == 1 {
				fn = receiverName(f.Recv.List[0].Type) + "." + fn
			}
			if f.Body == nil {
				continue
			}
			ast.Inspect(f.Body, visit(fn))
			continue
		}
		ast.Inspect(decl, visit(fn))
	}
	return sites
}

// receiverName is a method's receiver type as written: T or (*T).
func receiverName(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.StarExpr:
		return "(*" + receiverName(e.X) + ")"
	case *ast.Ident:
		return e.Name
	case *ast.IndexExpr:
		return receiverName(e.X)
	case *ast.IndexListExpr:
		return receiverName(e.X)
	}
	return "?"
}

// thisModule finds the module root above the test's directory.
func thisModule(t *testing.T) string {
	t.Helper()
	root, err := moduleRoot(".", farcastModule)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// TestNothingShippedImportsDevicekey: no non-test file outside devicekey
// imports it, but those custodyImporters lists (none in M3a), so farcast does
// not link it. The files are parsed for their imports only.
func TestNothingShippedImportsDevicekey(t *testing.T) {
	root := thisModule(t)
	files, err := shippedGoFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var importers []string
	parsed := 0
	for _, rel := range files {
		file, err := goparser.ParseFile(fset, filepath.Join(root, filepath.FromSlash(rel)), nil, goparser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}
		parsed++
		if path.Dir(rel) == devicekeyRel {
			continue
		}
		if _, _, imports := devicekeyImportNames(file); imports {
			importers = append(importers, rel)
		}
	}
	if parsed < minShippedFiles {
		t.Fatalf("parsed %d non-test files under %s; want at least %d: the walk is skipping the tree", parsed, root, minShippedFiles)
	}
	sort.Strings(importers)
	if want := sortedSet(custodyImporters); !slices.Equal(importers, want) {
		t.Errorf("files outside tests that import devicekey: %v; custodyImporters allows %v. Each importer is reviewed under ADR 0024's custody rules and listed there on purpose.", importers, want)
	}
}

// TestCustodyCallSitesAreReviewed: every site outside tests that names
// GiveConsent, Enrol or a writer-, renewal- or enrolment-purpose method is in
// custodyCallers (none in M3a). A _test.go file is never scanned: the walk
// probe forges consent, and says so.
func TestCustodyCallSitesAreReviewed(t *testing.T) {
	scan, err := scanCustody(thisModule(t))
	if err != nil {
		t.Fatal(err)
	}
	if scan.parsed < minShippedFiles {
		t.Fatalf("parsed %d non-test files; want at least %d: the walk is skipping the tree", scan.parsed, minShippedFiles)
	}
	for _, name := range append(slices.Clone(custodyPackageFuncs), custodyMethods...) {
		got := sortedSet(scan.sites[name])
		if want := sortedSet(custodyCallers[name]); !slices.Equal(got, want) {
			t.Errorf("sites naming %s: %v; custodyCallers allows %v. Each is reviewed under ADR 0024's custody rules and listed there on purpose.", name, got, want)
		}
	}
	for name := range custodyCallers {
		if !slices.Contains(custodyPackageFuncs, name) && !slices.Contains(custodyMethods, name) {
			t.Errorf("custodyCallers lists %s, which the scan does not watch", name)
		}
	}
}

// TestCustodyScanSeesEveryForm keeps the two scans honest on a module made
// for the purpose, under a directory whose name starts with '.', as this
// worktree's does: an aliased, a dot and a blank import; a method named with
// no import; and the files the walk must skip.
func TestCustodyScanSeesEveryForm(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".claude", "worktrees", "wt")
	imp := strconv.Quote(devicekeyImportPath)
	files := map[string]string{
		"go.mod":                                 "module " + farcastModule + "\n\ngo 1.26\n",
		"a/a.go":                                 "package a\n\nimport dk " + imp + "\n\nfunc F() { _ = dk.GiveConsent(dk.ConsentConfirmed) }\n",
		"b/b.go":                                 "package b\n\nimport . " + imp + "\n\ntype T struct{}\n\nfunc (t *T) G() { _, _, _ = Enrol(nil, \"\", nil, Zero) }\n",
		"c/c.go":                                 "package c\n\ntype S interface{ OpenForWrite() }\n\nfunc H(s S) { s.OpenForWrite() }\n\nvar V = (*int).AddRole\n",
		"c/c_test.go":                            "package c\n\nimport " + imp + "\n\nfunc X() { devicekey.GiveConsent(1) }\n",
		"d/d.go":                                 "package d\n\nimport _ " + imp + "\n",
		"e/e.go":                                 "package e\n\nimport " + imp + "\n\nvar C = devicekey.GiveConsent\n",
		"vendor/v/v.go":                          "package v\n\nimport " + imp + "\n\nfunc F() { devicekey.GiveConsent(1) }\n",
		"sdk/s.go":                               "package s\n\nimport " + imp + "\n",
		"x/testdata/t.go":                        "package t\n\nimport " + imp + "\n",
		"x/.hidden/h.go":                         "package h\n\nimport " + imp + "\n",
		"nested/go.mod":                          "module example.com/nested\n",
		"nested/n.go":                            "package n\n\nimport " + imp + "\n",
		devicekeyRel + "/own.go":                 "package devicekey\n\nfunc own() { _ = GiveConsent(1); var s *Store; _, _ = s.AddRole(0, nil, Zero) }\n",
		"farsight/cli/internal/cli/caller.go":    "package cli\n\nimport \"github.com/sofmon/farcast/farsight/cli/internal/devicekey\"\n\nfunc (c cmd) run() { var s *devicekey.Store; _, _ = s.OpenStaged(devicekey.Reader, devicekey.Consent{}); _, _ = s.RenewAnchor(1, nil, z); _ = s.CommitAnchor(1) }\n",
		"farsight/cli/internal/cli/nocall.go":    "package cli\n\nfunc renew(s interface{ RenewWriterLeaf() }) { s.RenewWriterLeaf() }\n",
		"farsight/cli/internal/cli/unrelated.go": "package cli\n\nfunc unrelated() {}\n",
	}
	for name, src := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	found, err := moduleRoot(filepath.Join(root, "a"), farcastModule)
	if err != nil || found != root {
		t.Fatalf("moduleRoot = %q, %v; want %q", found, err, root)
	}
	if _, err := moduleRoot(filepath.Join(root, "nested"), "example.com/elsewhere"); err == nil {
		t.Error("moduleRoot found a module that is not there")
	}
	scan, err := scanCustody(root)
	if err != nil {
		t.Fatal(err)
	}
	if scan.parsed != 9 {
		t.Errorf("parsed %d files; want the 9 the walk keeps", scan.parsed)
	}
	wantImporters := []string{"a/a.go", "b/b.go", "d/d.go", "e/e.go", "farsight/cli/internal/cli/caller.go"}
	if got := sortedSet(scan.importers); !slices.Equal(got, wantImporters) {
		t.Errorf("importers %v, want %v", got, wantImporters)
	}
	want := map[string][]string{
		"GiveConsent":     {"a/a.go:F", "e/e.go:package level"},
		"Enrol":           {"b/b.go:(*T).G"},
		"OpenForWrite":    {"c/c.go:H"},
		"AddRole":         {"c/c.go:package level"},
		"OpenStaged":      {"farsight/cli/internal/cli/caller.go:cmd.run"},
		"RenewAnchor":     {"farsight/cli/internal/cli/caller.go:cmd.run"},
		"CommitAnchor":    {"farsight/cli/internal/cli/caller.go:cmd.run"},
		"RenewWriterLeaf": {"farsight/cli/internal/cli/nocall.go:renew"},
	}
	for _, name := range append(slices.Clone(custodyPackageFuncs), custodyMethods...) {
		if got := sortedSet(scan.sites[name]); !slices.Equal(got, sortedSet(want[name])) {
			t.Errorf("sites of %s: %v, want %v", name, got, want[name])
		}
	}
	if _, err := moduleRoot(t.TempDir(), "example.com/none"); err == nil {
		t.Error("moduleRoot found a module under an empty directory")
	}
}
