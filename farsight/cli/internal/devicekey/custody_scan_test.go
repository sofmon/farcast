package devicekey

import (
	"bufio"
	"fmt"
	"go/ast"
	goparser "go/parser"
	"go/token"
	"io/fs"
	"maps"
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

// custodyCallers maps each watched key to the sites outside tests allowed to
// name it, each "<file>:<function>". A key is a watched function or method,
// or one of a role method's two forms, "OpenForEnrolment(Reader)" and
// "OpenForEnrolment(Writer)" (custodyRoleMethods). Empty in M3a, so every M3b
// caller is added on purpose and reviewed.
var custodyCallers = map[string][]string{}

// custodyPackageFuncs are the watched package-level functions, found through
// the file's import name for devicekey, an alias or a dot import included.
var custodyPackageFuncs = []string{"GiveConsent", "Enrol"}

// custodyMethods are the watched methods of *Store. A method is named without
// the import (s.OpenForWrite), and a file can reach a *Store without
// importing devicekey, so any selector with one of these names, in any file,
// counts: an over-approximation a reviewer clears by listing the site.
var custodyMethods = []string{"OpenForWrite", "RenewWriterLeaf", "RenewAnchor", "OpenStaged", "CommitAnchor", "AddRole", "OpenForEnrolment"}

// custodyRoleMethods are the watched methods whose site is keyed by the role
// it names, because the reader's form is harmless and the writer's is not:
// "<method>(Reader)" when the call's first argument is devicekey's Reader,
// named through one of the file's import names for devicekey (parentheses
// aside), and "<method>(Writer)" for anything else: Writer, a variable, any
// other expression, a dot import's bare Reader, or a method value with no
// call. So clearing a reader's site never clears a writer's in the same
// function. Like every site, it is judged by function: a later edit inside a
// listed function is the reviewer's to see.
var custodyRoleMethods = []string{"OpenForEnrolment"}

// custodyUnwatched are devicekey's exported functions and *Store methods
// that neither open an existing writer key nor make keys, each with why no
// call site needs a review. TestEveryExportedFunctionIsClassified requires
// every exported package function and *Store method to be watched or listed
// here, so a new opener cannot ship unwatched.
var custodyUnwatched = map[string]string{
	// *Store methods.
	"OpenForRead":         "opens the reader's keys only",
	"RenewReaderLeaf":     "opens the reader's keys only",
	"Roles":               "stats only",
	"Certificates":        "reads certificates, never a key",
	"CurrentCertificates": "reads certificates, never a key",
	"StagedCertificates":  "reads certificates, never a key",
	"RemoveRole":          "opens no file; it removes keys",
	"Erase":               "opens no file; it removes keys",
	"DiscardStaged":       "opens no file; it removes staged keys Google does not trust",
	"EnrolmentVerified":   "opens no file; it closes an enrolment window",
	// Package functions.
	"Open":                "stats only",
	"NewRoleID":           "draws an ID; no key",
	"ParseRoleID":         "parses text; no key",
	"NewObjectID":         "draws an ID; no key",
	"NewSerial":           "draws a serial; no key",
	"NotBefore":           "a time",
	"AnchorTemplate":      "a template; no key",
	"LeafTemplate":        "a template; no key",
	"SubjectKeyID":        "hashes a public key",
	"LeafDue":             "reads certificates it is given",
	"AnchorWarns":         "reads a certificate it is given",
	"AnchorWarnsAt":       "compares times",
	"AnchorExpiredAt":     "compares times",
	"AttributeCondition":  "renders text",
	"RoleIDFromCondition": "parses text",
	"Principal":           "renders text",
	"TrustStoreYAML":      "renders public material",
	"CheckProvider":       "parses an answer; probe-only (probeOnlyFuncs)",
	"CheckNamedProvider":  "parses an answer",
	"ParseProviders":      "parses an answer",
	"ParseProvider":       "parses an answer",
}

// probeOnlyFuncs are devicekey's package functions only the M3a walk probe,
// a _test.go file, may name: no shipped file does
// (TestProbeOnlyFunctionsAreNotShipped). CheckProvider accepts an answer for
// any provider holding the device's anchor and condition; product code calls
// CheckNamedProvider, which also checks the provider's whole name.
var probeOnlyFuncs = []string{"CheckProvider"}

// watchList is what one scan watches.
type watchList struct {
	funcs       []string // package functions, through an import name or a dot import
	methods     []string // methods, through any selector
	roleMethods []string // of methods, those keyed by their role (custodyRoleMethods)
}

// custodyWatch is the custody scan's watch list.
func custodyWatch() watchList {
	return watchList{funcs: custodyPackageFuncs, methods: custodyMethods, roleMethods: custodyRoleMethods}
}

// probeOnlyWatch is the probe-only scan's watch list.
func probeOnlyWatch() watchList { return watchList{funcs: probeOnlyFuncs} }

// keys are the names a scan of w records sites under: each function and
// method, and a role method's two forms in its place.
func (w watchList) keys() []string {
	keys := slices.Clone(w.funcs)
	for _, m := range w.methods {
		if slices.Contains(w.roleMethods, m) {
			keys = append(keys, roleKey(m, true), roleKey(m, false))
			continue
		}
		keys = append(keys, m)
	}
	return keys
}

// roleKey is a role method's site key: its reader's or its writer's form.
func roleKey(method string, reader bool) string {
	if reader {
		return method + "(Reader)"
	}
	return method + "(Writer)"
}

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
	sites     map[string][]string // watched key → "<file>:<function>"
}

// scanCustody parses every shipped file of the module at root and lists who
// imports devicekey and who names a watched function or method.
func scanCustody(root string) (*custodyScan, error) { return scanModule(root, custodyWatch()) }

// scanModule is scanCustody for the watch list w.
func scanModule(root string, w watchList) (*custodyScan, error) {
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
		for name, fns := range watchedSites(file, names, dot, w) {
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

// watchedSites lists, per watched key of w, the functions of file that name
// it: a package function through one of names, or bare under a dot import; a
// method through any selector, a role method under the form its call names
// (custodyRoleMethods).
func watchedSites(file *ast.File, names []string, dot bool, w watchList) map[string][]string {
	sites := map[string][]string{}
	// readerCalls are the role methods' selectors whose call names Reader;
	// a CallExpr is visited before its Fun.
	readerCalls := map[*ast.SelectorExpr]bool{}
	var visit func(fn string) func(ast.Node) bool
	visit = func(fn string) func(ast.Node) bool {
		return func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				if sel, ok := n.Fun.(*ast.SelectorExpr); ok && slices.Contains(w.roleMethods, sel.Sel.Name) &&
					len(n.Args) > 0 && readerArg(n.Args[0], names) {
					readerCalls[sel] = true
				}
			case *ast.SelectorExpr:
				if x, ok := n.X.(*ast.Ident); ok && slices.Contains(names, x.Name) && slices.Contains(w.funcs, n.Sel.Name) {
					sites[n.Sel.Name] = append(sites[n.Sel.Name], fn)
				}
				if slices.Contains(w.methods, n.Sel.Name) {
					key := n.Sel.Name
					if slices.Contains(w.roleMethods, key) {
						key = roleKey(key, readerCalls[n])
					}
					sites[key] = append(sites[key], fn)
				}
				ast.Inspect(n.X, visit(fn)) // not n.Sel: it is not a bare name
				return false
			case *ast.Ident:
				if dot && slices.Contains(w.funcs, n.Name) {
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

// readerArg reports whether e is devicekey's Reader, named through one of
// the file's import names for devicekey, parentheses aside. A name that
// shadows the import is beyond it, as it is for the package functions.
func readerArg(e ast.Expr, names []string) bool {
	sel, ok := ast.Unparen(e).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Reader" {
		return false
	}
	x, ok := sel.X.(*ast.Ident)
	return ok && slices.Contains(names, x.Name)
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
	for _, problem := range unreviewedSites(scan, custodyWatch(), custodyCallers) {
		t.Errorf("%s. Each is reviewed under ADR 0024's custody rules and listed there on purpose.", problem)
	}
}

// unreviewedSites describes each watched key of w whose sites in scan are not
// exactly the ones callers allows, and each key callers lists that w does not
// watch. Each key is judged on its own: a role method's reader sites allowed
// clear none of its writer sites.
func unreviewedSites(scan *custodyScan, w watchList, callers map[string][]string) []string {
	keys := w.keys()
	var out []string
	for _, name := range keys {
		got := sortedSet(scan.sites[name])
		if want := sortedSet(callers[name]); !slices.Equal(got, want) {
			out = append(out, fmt.Sprintf("sites naming %s: %v; custodyCallers allows %v", name, got, want))
		}
	}
	for _, name := range sortedSet(slices.Collect(maps.Keys(callers))) {
		if !slices.Contains(keys, name) {
			out = append(out, fmt.Sprintf("custodyCallers lists %s, which the scan does not watch", name))
		}
	}
	return out
}

// TestProbeOnlyFunctionsAreNotShipped: no non-test file of the module names
// a probe-only function (probeOnlyFuncs). The walk probe is a _test.go file,
// which the scan never reads.
func TestProbeOnlyFunctionsAreNotShipped(t *testing.T) {
	scan, err := scanModule(thisModule(t), probeOnlyWatch())
	if err != nil {
		t.Fatal(err)
	}
	if scan.parsed < minShippedFiles {
		t.Fatalf("parsed %d non-test files; want at least %d: the walk is skipping the tree", scan.parsed, minShippedFiles)
	}
	for _, name := range probeOnlyFuncs {
		if sites := scan.sites[name]; len(sites) != 0 {
			t.Errorf("shipped sites naming %s: %v. It is the walk probe's only; product code calls CheckNamedProvider.", name, sortedSet(sites))
		}
	}
}

// exportedAPI lists the exported package functions and the exported methods
// of Store or *Store declared in dir's non-test Go files.
func exportedAPI(dir string) (funcs, methods []string, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := goparser.ParseFile(fset, filepath.Join(dir, name), nil, goparser.SkipObjectResolution)
		if err != nil {
			return nil, nil, err
		}
		for _, decl := range file.Decls {
			f, ok := decl.(*ast.FuncDecl)
			if !ok || !f.Name.IsExported() {
				continue
			}
			switch {
			case f.Recv == nil:
				funcs = append(funcs, f.Name.Name)
			case len(f.Recv.List) == 1 && strings.TrimPrefix(strings.TrimSuffix(receiverName(f.Recv.List[0].Type), ")"), "(*") == "Store":
				methods = append(methods, f.Name.Name)
			}
		}
	}
	return funcs, methods, nil
}

// unclassified describes each of funcs and methods that is not exactly one
// of watched (custodyPackageFuncs or custodyMethods) and listed in
// custodyUnwatched.
func unclassified(funcs, methods []string) []string {
	var out []string
	check := func(kind, name string, watchedList []string) {
		watched, cleared := slices.Contains(watchedList, name), custodyUnwatched[name] != ""
		if watched == cleared {
			out = append(out, fmt.Sprintf("%s %s: watched %v, in custodyUnwatched %v", kind, name, watched, cleared))
		}
	}
	for _, f := range funcs {
		check("package function", f, custodyPackageFuncs)
	}
	for _, m := range methods {
		check("*Store method", m, custodyMethods)
	}
	return out
}

// TestEveryExportedFunctionIsClassified: every exported package function and
// every exported *Store method in devicekey's own non-test files is watched
// (custodyPackageFuncs, custodyMethods) or listed in custodyUnwatched, never
// both; every probe-only function is listed as one; and neither list names
// a function that is not there. The classifier itself is checked on a
// package made for the purpose, where a new opener is unclassified.
func TestEveryExportedFunctionIsClassified(t *testing.T) {
	funcs, methods, err := exportedAPI(filepath.Join(thisModule(t), filepath.FromSlash(devicekeyRel)))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(funcs, "Enrol") || !slices.Contains(methods, "OpenForWrite") {
		t.Fatalf("found functions %v and methods %v: the parse is missing the package", funcs, methods)
	}
	for _, problem := range unclassified(funcs, methods) {
		t.Errorf("%s; want exactly one", problem)
	}

	made := t.TempDir()
	src := "package devicekey\n\ntype Store struct{}\n\ntype Certs struct{}\n\n" +
		"func Enrol() {}\n\nfunc NewOpener() {}\n\nfunc helper() {}\n\n" +
		"func (s *Store) OpenForRead() {}\n\nfunc (s *Store) OpenForWrite() {}\n\nfunc (s *Store) OpenWriterKey() {}\n\n" +
		"func (s Store) Peek() {}\n\nfunc (s *Store) open() {}\n\nfunc (c Certs) Leak() {}\n"
	for name, body := range map[string]string{"a.go": src, "a_test.go": "package devicekey\n\nfunc (s *Store) TestOnly() {}\n"} {
		if err := os.WriteFile(filepath.Join(made, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	gotFuncs, gotMethods, err := exportedAPI(made)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"Enrol", "NewOpener"}; !slices.Equal(sortedSet(gotFuncs), want) {
		t.Errorf("exportedAPI's functions %v, want %v", gotFuncs, want)
	}
	if want := []string{"OpenForRead", "OpenForWrite", "OpenWriterKey", "Peek"}; !slices.Equal(sortedSet(gotMethods), want) {
		t.Errorf("exportedAPI's methods %v, want %v", gotMethods, want)
	}
	problems := strings.Join(unclassified(gotFuncs, gotMethods), "\n")
	for _, name := range []string{"NewOpener", "OpenWriterKey", "Peek"} {
		if !strings.Contains(problems, " "+name+":") {
			t.Errorf("the classifier let the new %s through: %q", name, problems)
		}
	}
	for _, name := range []string{"Enrol", "OpenForRead", "OpenForWrite"} {
		if strings.Contains(problems, " "+name+":") {
			t.Errorf("the classifier refused %s, which is classified: %q", name, problems)
		}
	}

	for _, name := range append(append(slices.Clone(custodyPackageFuncs), custodyMethods...), slices.Collect(maps.Keys(custodyUnwatched))...) {
		if !slices.Contains(funcs, name) && !slices.Contains(methods, name) {
			t.Errorf("%s is listed, and devicekey has no such exported function or *Store method", name)
		}
	}
	for _, name := range custodyRoleMethods {
		if !slices.Contains(custodyMethods, name) {
			t.Errorf("custodyRoleMethods lists %s, which custodyMethods does not watch", name)
		}
	}
	for _, name := range probeOnlyFuncs {
		if !slices.Contains(funcs, name) || custodyUnwatched[name] == "" {
			t.Errorf("probe-only %s is not an exported function listed in custodyUnwatched", name)
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
		"go.mod": "module " + farcastModule + "\n\ngo 1.26\n",
		"a/a.go": "package a\n\nimport dk " + imp + "\n\nfunc F() { _ = dk.GiveConsent(dk.ConsentConfirmed) }\n" +
			"\nfunc R(s *dk.Store) { _, _ = s.OpenForEnrolment(dk.Reader, nil, dk.Zero); _, _ = s.OpenForEnrolment((dk.Reader), nil, dk.Zero) }\n" +
			"\nfunc W(s *dk.Store, r dk.Role) { _, _ = s.OpenForEnrolment(r, nil, dk.Zero); f := s.OpenForEnrolment; _, _ = f(dk.Reader, nil, dk.Zero) }\n" +
			"\nfunc X(s *dk.Store) { _, _ = s.OpenForEnrolment(other.Reader, nil, dk.Zero); _, _ = s.OpenForEnrolment(dk.Writer, nil, dk.Zero) }\n",
		"b/b.go": "package b\n\nimport . " + imp + "\n\ntype T struct{}\n\nfunc (t *T) G() { _, _, _ = Enrol(nil, \"\", nil, Zero) }\n" +
			"\nfunc (t *T) R(s *Store) { _, _ = s.OpenForEnrolment(Reader, nil, Zero) }\n",
		"f/f.go":                                 "package f\n\nimport dk " + imp + "\n\nfunc P() { _ = dk.CheckProvider(nil, nil, dk.RoleID{}); _ = dk.CheckNamedProvider }\n",
		"f/f_test.go":                            "package f\n\nimport dk " + imp + "\n\nfunc Q() { _ = dk.CheckProvider(nil, nil, dk.RoleID{}) }\n",
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
		"farsight/cli/internal/cli/caller.go":    "package cli\n\nimport \"github.com/sofmon/farcast/farsight/cli/internal/devicekey\"\n\nfunc (c cmd) run() { var s *devicekey.Store; _, _ = s.OpenStaged(devicekey.Reader, devicekey.Consent{}); _, _ = s.RenewAnchor(1, nil, z); _ = s.CommitAnchor(1) }\n\nfunc resume(s *devicekey.Store) { _, _ = s.OpenForEnrolment(devicekey.Writer, nil, z) }\n",
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
	if scan.parsed != 10 {
		t.Errorf("parsed %d files; want the 10 the walk keeps", scan.parsed)
	}
	wantImporters := []string{"a/a.go", "b/b.go", "d/d.go", "e/e.go", "f/f.go", "farsight/cli/internal/cli/caller.go"}
	if got := sortedSet(scan.importers); !slices.Equal(got, wantImporters) {
		t.Errorf("importers %v, want %v", got, wantImporters)
	}
	// The watched keys, written out, so a name dropped from a watched list
	// fails here.
	wantKeys := []string{
		"AddRole", "CommitAnchor", "Enrol", "GiveConsent",
		"OpenForEnrolment(Reader)", "OpenForEnrolment(Writer)",
		"OpenForWrite", "OpenStaged", "RenewAnchor", "RenewWriterLeaf",
	}
	want := map[string][]string{
		"GiveConsent":              {"a/a.go:F", "e/e.go:package level"},
		"Enrol":                    {"b/b.go:(*T).G"},
		"OpenForWrite":             {"c/c.go:H"},
		"AddRole":                  {"c/c.go:package level"},
		"OpenStaged":               {"farsight/cli/internal/cli/caller.go:cmd.run"},
		"RenewAnchor":              {"farsight/cli/internal/cli/caller.go:cmd.run"},
		"CommitAnchor":             {"farsight/cli/internal/cli/caller.go:cmd.run"},
		"RenewWriterLeaf":          {"farsight/cli/internal/cli/nocall.go:renew"},
		"OpenForEnrolment(Reader)": {"a/a.go:R"},
		"OpenForEnrolment(Writer)": {"a/a.go:W", "a/a.go:X", "b/b.go:(*T).R", "farsight/cli/internal/cli/caller.go:resume"},
	}
	keys := custodyWatch().keys()
	if got := sortedSet(keys); !slices.Equal(got, wantKeys) {
		t.Errorf("the custody scan watches %v, want %v", got, wantKeys)
	}
	if got := sortedSet(slices.Collect(maps.Keys(want))); !slices.Equal(got, wantKeys) {
		t.Errorf("this test expects sites of %v, want every watched key %v", got, wantKeys)
	}
	for _, name := range keys {
		if got := sortedSet(scan.sites[name]); !slices.Equal(got, sortedSet(want[name])) {
			t.Errorf("sites of %s: %v, want %v", name, got, want[name])
		}
	}
	for name := range scan.sites {
		if !slices.Contains(keys, name) {
			t.Errorf("the scan recorded sites of %s, which it does not watch", name)
		}
	}
	// The review of the sites (unreviewedSites), on this module: every site
	// allowed passes; with a role method's reader sites allowed and its
	// writer sites not, each writer site is still refused; the writer's sites
	// allowed under the reader's key clear neither; and a key the scan does
	// not watch is refused.
	if problems := unreviewedSites(scan, custodyWatch(), want); len(problems) != 0 {
		t.Errorf("with every site allowed, the review refused %v", problems)
	}
	readerOnly := maps.Clone(want)
	delete(readerOnly, "OpenForEnrolment(Writer)")
	if problems := unreviewedSites(scan, custodyWatch(), readerOnly); len(problems) != 1 ||
		!strings.Contains(problems[0], "sites naming OpenForEnrolment(Writer): ") {
		t.Errorf("with the reader's sites alone allowed, the review gave %v; want the writer's sites refused", problems)
	}
	swapped := maps.Clone(want)
	swapped["OpenForEnrolment(Reader)"] = append(slices.Clone(want["OpenForEnrolment(Reader)"]), want["OpenForEnrolment(Writer)"]...)
	delete(swapped, "OpenForEnrolment(Writer)")
	if problems := unreviewedSites(scan, custodyWatch(), swapped); len(problems) != 2 {
		t.Errorf("with the writer's sites allowed as the reader's, the review gave %v; want both keys refused", problems)
	}
	unwatched := maps.Clone(want)
	unwatched["OpenForEnrolment"] = []string{"a/a.go:R"}
	if problems := unreviewedSites(scan, custodyWatch(), unwatched); len(problems) != 1 ||
		problems[0] != "custodyCallers lists OpenForEnrolment, which the scan does not watch" {
		t.Errorf("with an unwatched key listed, the review gave %v", problems)
	}

	// The probe-only scan: a shipped file naming CheckProvider is a site; a
	// _test.go file is not read, and CheckNamedProvider is not watched.
	probe, err := scanModule(root, probeOnlyWatch())
	if err != nil {
		t.Fatal(err)
	}
	if got, wantProbe := sortedSet(probe.sites["CheckProvider"]), []string{"f/f.go:P"}; !slices.Equal(got, wantProbe) {
		t.Errorf("probe-only sites of CheckProvider: %v, want %v", got, wantProbe)
	}
	if len(probe.sites) != 1 {
		t.Errorf("the probe-only scan recorded %d keys, want CheckProvider's alone", len(probe.sites))
	}
	if _, err := moduleRoot(t.TempDir(), "example.com/none"); err == nil {
		t.Error("moduleRoot found a module under an empty directory")
	}
}
