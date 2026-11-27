package kube

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The module the source scans walk, and the one directory whose shipped
// files may build a loopback Federation: the rehearsal, which farcast never
// links (execgate's fakeTrees).
const (
	scanModule       = "github.com/sofmon/farcast"
	scanRehearsalDir = "farsight/cli/internal/rehearsal/"
	// scanMinFiles is the fewest shipped files a walk of the module may
	// parse; one that skips the tree by mistake parses none, and must not
	// pass.
	scanMinFiles = 100
)

// scanRoot walks up from the test's directory to the module's go.mod.
func scanRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for {
		if scanModulePath(filepath.Join(dir, "go.mod")) == scanModule {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.mod for %s above the test's directory", scanModule)
		}
		dir = parent
	}
}

// scanModulePath is the module line of the go.mod at p, or "".
func scanModulePath(p string) string {
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

// scanShippedFiles lists the module's non-test Go files, as slash paths from
// root, as devicekey's custody scan does: it skips vendor/ and sdk/ (its own
// module) at the root, every testdata/, every directory holding a go.mod of
// its own, and every directory whose own name starts with '.'. A directory
// is judged by its name relative to root, never by its absolute path: a
// worktree itself lives under .claude/.
func scanShippedFiles(root string) ([]string, error) {
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

// loopbackFederationSites are the places a Go file names
// NewLoopbackFederation, other than its own declaration.
func loopbackFederationSites(fset *token.FileSet, file *ast.File) []string {
	decl := map[*ast.Ident]bool{}
	for _, d := range file.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == "NewLoopbackFederation" {
			decl[fd.Name] = true
		}
	}
	var sites []string
	ast.Inspect(file, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == "NewLoopbackFederation" && !decl[id] {
			sites = append(sites, fset.Position(id.Pos()).String())
		}
		return true
	})
	return sites
}

// knobbedExchanges are the places a Go file could make an exchange with a
// subject or scopes: every NewExchangeRequest identifier, bare or a
// selector's, except the function's own declaration and the function of a
// call with exactly four arguments whose third and fourth are the identifier
// nil. So a function value, a local alias and a method value are each a
// site, whatever is later passed to them. Every declaration of an identifier
// named nil is a site too, since it would make a literal nil mean something
// else in its scope.
func knobbedExchanges(fset *token.FileSet, file *ast.File) []string {
	allowed := map[*ast.Ident]bool{}
	for _, d := range file.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == "NewExchangeRequest" {
			allowed[fd.Name] = true
		}
	}
	isNil := func(e ast.Expr) bool {
		id, ok := e.(*ast.Ident)
		return ok && id.Name == "nil"
	}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 4 || call.Ellipsis.IsValid() || !isNil(call.Args[2]) || !isNil(call.Args[3]) {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			allowed[fn] = true
		case *ast.SelectorExpr:
			allowed[fn.Sel] = true
		}
		return true
	})
	var sites []string
	ast.Inspect(file, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == "NewExchangeRequest" && !allowed[id] {
			sites = append(sites, fset.Position(id.Pos()).String())
		}
		return true
	})
	for _, id := range nilDeclarations(file) {
		sites = append(sites, fset.Position(id.Pos()).String())
	}
	return sites
}

// nilDeclarations are the identifiers named nil a file declares: in a var,
// const or type spec, an import's name, a function's name, a field, a
// parameter, a result, a receiver or a type parameter, and on the left of a
// := or a range :=.
func nilDeclarations(file *ast.File) []*ast.Ident {
	var out []*ast.Ident
	add := func(ids ...*ast.Ident) {
		for _, id := range ids {
			if id != nil && id.Name == "nil" {
				out = append(out, id)
			}
		}
	}
	addExprs := func(es ...ast.Expr) {
		for _, e := range es {
			if id, ok := e.(*ast.Ident); ok {
				add(id)
			}
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.ValueSpec:
			add(x.Names...)
		case *ast.TypeSpec:
			add(x.Name)
		case *ast.ImportSpec:
			add(x.Name)
		case *ast.FuncDecl:
			add(x.Name)
		case *ast.Field:
			add(x.Names...)
		case *ast.AssignStmt:
			if x.Tok == token.DEFINE {
				addExprs(x.Lhs...)
			}
		case *ast.RangeStmt:
			if x.Tok == token.DEFINE {
				addExprs(x.Key, x.Value)
			}
		}
		return true
	})
	return out
}

// scanTree parses every shipped file under root (scanShippedFiles), each
// under its path from root, so a site's position names that path, and gives
// it to visit. It returns the paths it parsed, in the walk's order.
func scanTree(root string, visit func(rel string, fset *token.FileSet, file *ast.File)) ([]string, error) {
	files, err := scanShippedFiles(root)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	for _, rel := range files {
		src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return nil, err
		}
		file, err := parser.ParseFile(fset, rel, src, parser.SkipObjectResolution)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", rel, err)
		}
		visit(rel, fset, file)
	}
	return files, nil
}

// scanFederationFile is where NewLoopbackFederation and NewExchangeRequest
// are declared.
const scanFederationFile = "farsight/cli/internal/kube/federated.go"

// loopbackScan is what one scan of a module for NewLoopbackFederation found:
// the shipped files it parsed, the sites outside the rehearsal ("<path>:<line>:<column>"),
// and how many times scanFederationFile declares the function.
type loopbackScan struct {
	parsed   []string
	sites    []string
	declared int
}

// scanLoopbackFederation is TestOnlyTheRehearsalCallsNewLoopbackFederation's
// scan of the module at root. A file under scanRehearsalDir is parsed, and
// its sites are not kept.
func scanLoopbackFederation(root string) (loopbackScan, error) {
	var s loopbackScan
	parsed, err := scanTree(root, func(rel string, fset *token.FileSet, file *ast.File) {
		if rel == scanFederationFile {
			for _, d := range file.Decls {
				if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == "NewLoopbackFederation" {
					s.declared++
				}
			}
		}
		if strings.HasPrefix(rel, scanRehearsalDir) {
			return
		}
		s.sites = append(s.sites, loopbackFederationSites(fset, file)...)
	})
	s.parsed = parsed
	return s, err
}

// exchangeScan is what one scan of a module for knobbed exchanges found: the
// shipped files it parsed, the sites knobbedExchanges names, and the calls
// of NewExchangeRequest it saw, knobbed or not.
type exchangeScan struct {
	parsed []string
	sites  []string
	calls  int
}

// scanExchanges is TestProductExchangesCarryNoKnobs's scan of the module at
// root. No directory is exempt: the rehearsal's exchanges carry no knobs
// either.
func scanExchanges(root string) (exchangeScan, error) {
	var s exchangeScan
	parsed, err := scanTree(root, func(_ string, fset *token.FileSet, file *ast.File) {
		ast.Inspect(file, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				switch fn := call.Fun.(type) {
				case *ast.Ident:
					if fn.Name == "NewExchangeRequest" {
						s.calls++
					}
				case *ast.SelectorExpr:
					if fn.Sel.Name == "NewExchangeRequest" {
						s.calls++
					}
				}
			}
			return true
		})
		s.sites = append(s.sites, knobbedExchanges(fset, file)...)
	})
	s.parsed = parsed
	return s, err
}

// parsedUnder reports whether a scan parsed a file under dir ("a/b/").
func parsedUnder(parsed []string, dir string) bool {
	return slices.ContainsFunc(parsed, func(rel string) bool { return strings.HasPrefix(rel, dir) })
}

// sitesFiles are the paths a scan's sites name, sorted, each once.
func sitesFiles(sites []string) []string {
	var files []string
	for _, s := range sites {
		file, _, _ := strings.Cut(s, ":")
		if !slices.Contains(files, file) {
			files = append(files, file)
		}
	}
	slices.Sort(files)
	return files
}

// parsePlanted parses a planted source for the scans' self-checks.
func parsePlanted(t *testing.T, src string) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "planted.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	return fset, file
}

// TestOnlyTheRehearsalCallsNewLoopbackFederation (R4): no shipped file of the
// module but the rehearsal's names NewLoopbackFederation, other than its own
// declaration in federated.go, so farcast never points a Federation at a
// loopback address. Tests may; the rehearsal, which farcast never links,
// may. The walk is checked on a planted module (TestSourceScansWalkTheModule)
// and the detector on planted sources.
func TestOnlyTheRehearsalCallsNewLoopbackFederation(t *testing.T) {
	s, err := scanLoopbackFederation(scanRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, site := range s.sites {
		t.Errorf("NewLoopbackFederation is named at %s: only the rehearsal and tests may", site)
	}
	if len(s.parsed) < scanMinFiles {
		t.Fatalf("the walk parsed %d shipped files, fewer than %d: it skipped the tree", len(s.parsed), scanMinFiles)
	}
	if s.declared != 1 {
		t.Fatalf("federated.go declares NewLoopbackFederation %d times; the scan is not looking at it", s.declared)
	}
	for _, dir := range []string{"farsight/cli/internal/cli/", "farsight/cli/internal/kube/", scanRehearsalDir} {
		if !parsedUnder(s.parsed, dir) {
			t.Errorf("the walk parsed no shipped file under %s", dir)
		}
	}
	for name, c := range map[string]struct {
		src  string
		want int
	}{
		"a call":                {"package x\nimport \"k\"\nvar _ = f()\nfunc f() any { f, _ := k.NewLoopbackFederation(\"\", \"\", \"\", nil); return f }\n", 1},
		"a function value":      {"package x\nimport \"k\"\nvar g = k.NewLoopbackFederation\n", 1},
		"a dot import's call":   {"package x\nimport . \"k\"\nfunc f() { NewLoopbackFederation(\"\", \"\", \"\", nil) }\n", 1},
		"its own declaration":   {"package kube\nfunc NewLoopbackFederation() {}\n", 0},
		"a declaration and use": {"package kube\nfunc NewLoopbackFederation() {}\nfunc g() { NewLoopbackFederation() }\n", 1},
		"another name":          {"package x\nimport \"k\"\nfunc f() { k.NewFederation() }\n", 0},
	} {
		fset, file := parsePlanted(t, c.src)
		if got := len(loopbackFederationSites(fset, file)); got != c.want {
			t.Errorf("the scan finds %d sites in %s, want %d", got, name, c.want)
		}
	}
}

// TestProductExchangesCarryNoKnobs (DES:1259): no shipped file of the module
// makes an exchange with a subject chain or scopes: every NewExchangeRequest
// it names is called with the literal nil for both, so every product exchange
// presents the leaf alone and asks for cloud-platform alone (D5.1). Tests
// and the walk probe keep M3a's knobs. The walk is checked on a planted
// module (TestSourceScansWalkTheModule) and the detector on planted sources.
func TestProductExchangesCarryNoKnobs(t *testing.T) {
	s, err := scanExchanges(scanRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, site := range s.sites {
		t.Errorf("NewExchangeRequest may carry a subject or scopes at %s: a product exchange passes nil for both", site)
	}
	if len(s.parsed) < scanMinFiles {
		t.Fatalf("the walk parsed %d shipped files, fewer than %d", len(s.parsed), scanMinFiles)
	}
	if s.calls == 0 {
		t.Fatal("no shipped call of NewExchangeRequest was found; productExchange's is one, so the scan is not looking")
	}
	for _, dir := range []string{"farsight/cli/internal/cli/", "farsight/cli/internal/kube/", scanRehearsalDir} {
		if !parsedUnder(s.parsed, dir) {
			t.Errorf("the walk parsed no shipped file under %s", dir)
		}
	}
	for name, c := range map[string]struct {
		src  string
		want int
	}{
		"nil and nil":              {"package x\nfunc f() { NewExchangeRequest(a, b, nil, nil) }\n", 0},
		"a selector's nil and nil": {"package x\nfunc f() { k.NewExchangeRequest(a, b, nil, nil) }\n", 0},
		"its own declaration":      {"package kube\nfunc NewExchangeRequest(a string, c ClientIdentity, s [][]byte, x []string) ExchangeRequest { return ExchangeRequest{} }\n", 0},
		"a subject":                {"package x\nfunc f() { NewExchangeRequest(a, b, s, nil) }\n", 1},
		"scopes":                   {"package x\nfunc f() { k.NewExchangeRequest(a, b, nil, []string{x}) }\n", 1},
		"an empty slice":           {"package x\nfunc f() { k.NewExchangeRequest(a, b, nil, []string{}) }\n", 1},
		"a nil-valued var":         {"package x\nvar none []string\nfunc f() { k.NewExchangeRequest(a, b, nil, none) }\n", 1},
		"too few arguments":        {"package x\nfunc f() { k.NewExchangeRequest(a, b, nil) }\n", 1},
		"another function":         {"package x\nfunc f() { k.Exchange(a, b, s, x) }\n", 0},
		"a call in a closure":      {"package x\nvar g = func() { NewExchangeRequest(a, b, nil, x) }\n", 1},
		"a function value":         {"package x\nvar mk = k.NewExchangeRequest\nfunc f() { mk(a, b, chain, scopes) }\n", 1},
		"a local alias":            {"package x\nfunc f() { mk := k.NewExchangeRequest; mk(a, b, chain, scopes) }\n", 1},
		"a parenthesised call":     {"package x\nfunc f() { (k.NewExchangeRequest)(a, b, nil, nil) }\n", 1},
		"a shadowed nil":           {"package x\nfunc f() { nil := []string{\"x\"}; k.NewExchangeRequest(a, b, nil, nil) }\n", 1},
		"a package-level nil":      {"package x\nvar nil = []string{\"x\"}\n", 1},
		"a parameter named nil":    {"package x\nfunc f(nil []string) { k.NewExchangeRequest(a, b, nil, nil) }\n", 1},
		"a range over nil":         {"package x\nfunc f() { for _, nil := range xs { k.NewExchangeRequest(a, b, nil, nil) } }\n", 1},
	} {
		fset, file := parsePlanted(t, c.src)
		if got := len(knobbedExchanges(fset, file)); got != c.want {
			t.Errorf("the scan finds %d sites in %s, want %d", got, name, c.want)
		}
	}
}

// TestSourceScansWalkTheModule keeps the two scans' walk honest on a module
// made for the purpose, under a directory whose name starts with '.', as
// this worktree's does: the files the walk keeps and skips, the rehearsal's
// exemption (its directory alone, not a sibling whose name begins the same
// way, and for NewLoopbackFederation alone), and the sites each scan names.
func TestSourceScansWalkTheModule(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".claude", "worktrees", "wt")
	loopback := "package p\n\nimport k \"github.com/sofmon/farcast/farsight/cli/internal/kube\"\n\nfunc f() { _, _ = k.NewLoopbackFederation(\"\", \"\", \"\", nil) }\n"
	knobbed := "package p\n\nimport k \"github.com/sofmon/farcast/farsight/cli/internal/kube\"\n\nfunc g() { _ = k.NewExchangeRequest(\"\", k.ClientIdentity{}, nil, []string{\"x\"}) }\n"
	both := loopback + "\nfunc g() { _ = k.NewExchangeRequest(\"\", k.ClientIdentity{}, nil, []string{\"x\"}) }\n"
	files := map[string]string{
		"go.mod":                                    "module " + scanModule + "\n\ngo 1.26\n",
		scanFederationFile:                          "package kube\n\nfunc NewLoopbackFederation() {}\n\nfunc NewExchangeRequest(a, b, c, d any) {}\n\nfunc productExchange() { NewExchangeRequest(1, 2, nil, nil) }\n",
		"farsight/cli/internal/cli/x.go":            loopback,
		"farsight/cli/internal/cli/ok.go":           "package cli\n\nfunc ok() { k.NewExchangeRequest(a, b, nil, nil) }\n",
		"farsight/cli/internal/cli/x_test.go":       both,
		"farsight/cli/internal/rehearsal/r.go":      loopback,
		"farsight/cli/internal/rehearsal/k.go":      knobbed,
		"farsight/cli/internal/rehearsalx/r.go":     loopback,
		"farsight/cli/internal/rehearsal/notes.txt": both,
		"vendor/v/v.go":                             both,
		"sdk/s.go":                                  both,
		"x/testdata/t.go":                           both,
		"x/.hidden/h.go":                            both,
		"nested/go.mod":                             "module example.com/nested\n",
		"nested/n.go":                               both,
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
	wantParsed := []string{
		"farsight/cli/internal/cli/ok.go",
		"farsight/cli/internal/cli/x.go",
		scanFederationFile,
		"farsight/cli/internal/rehearsal/k.go",
		"farsight/cli/internal/rehearsal/r.go",
		"farsight/cli/internal/rehearsalx/r.go",
	}
	l, err := scanLoopbackFederation(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := slices.Sorted(slices.Values(l.parsed)); !slices.Equal(got, wantParsed) {
		t.Errorf("the NewLoopbackFederation scan parsed %q, want %q", got, wantParsed)
	}
	if want := []string{"farsight/cli/internal/cli/x.go", "farsight/cli/internal/rehearsalx/r.go"}; !slices.Equal(sitesFiles(l.sites), want) || len(l.sites) != 2 {
		t.Errorf("the NewLoopbackFederation scan found %q, want one site in each of %q", l.sites, want)
	}
	if l.declared != 1 {
		t.Errorf("the NewLoopbackFederation scan counted %d declarations, want 1", l.declared)
	}
	e, err := scanExchanges(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := slices.Sorted(slices.Values(e.parsed)); !slices.Equal(got, wantParsed) {
		t.Errorf("the exchange scan parsed %q, want %q", got, wantParsed)
	}
	if want := []string{"farsight/cli/internal/rehearsal/k.go"}; !slices.Equal(sitesFiles(e.sites), want) || len(e.sites) != 1 {
		t.Errorf("the exchange scan found %q, want one site in %q", e.sites, want)
	}
	if e.calls != 3 {
		t.Errorf("the exchange scan saw %d calls, want 3 (federated.go's, ok.go's and the rehearsal's)", e.calls)
	}
}
