// Package execgate lists what FarCast's shipped binaries can start: every
// package each one links, in the release's tagged configuration too, checked
// with go/ast against a reviewed allowlist by ./check.sh (ADR 0023 decision 1).
// farcast-release runs it as its execsites subcommand.
//
// It keeps two layers apart. The listing asks `go list` which packages, and
// which of their files, each binary links on each platform. The scan parses
// one package's files, given as an import path and file contents, and reports
// what in them can start a process. Each file is parsed once, however many
// binaries and platforms link it.
//
// What the scan reports, one line per site:
//
//	<binary> <goos/goarch> import <importpath> os/exec
//	<binary> <goos/goarch> ref <file> <func> <package>.<Name> <n>x
//	<binary> <goos/goarch> linkname <file> <local> <target>
//
// An import line names every listed package that imports os/exec, under any
// name. A ref line names every reference to a watched name (watched, below): a
// call, a function value, a type, a composite literal or a constant, reached
// through the import's default name, an alias or a dot import, counted per
// enclosing top-level function. Inside a watched package's own source (the
// vendored golang.org/x/sys/unix and golang.org/x/sys/windows), a bare
// reference to one of its own watched names, outside its declaration, is
// reported the same way. A linkname line names every //go:linkname directive
// whose target's last element, lower-cased, contains exec, fork, spawn or
// startprocess. No line carries a line number, so moving code does not trip
// the gate; the count catches a second site in the same function.
//
// What it does not see: a raw Syscall whose number is a literal rather than a
// SYS_* name; assembly (.s) files; a //go:linkname to an innocuously named
// function; a process started through a procedure looked up by name, such as
// NewProc("CreateProcessW") on a lazily loaded DLL (x/sys/windows or
// syscall), or a new caller of x/sys/windows's procCreateProcessW,
// procCreateProcessAsUserW or procShellExecuteW under another name; and a
// darwin //go:cgo_import_dynamic of an exec or spawn symbol with its
// trampoline. exec-allowlist.txt states these limits in its header.
package execgate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// sysNumbers are the system-call numbers that start a process, watched in
// both syscall and golang.org/x/sys/unix.
var sysNumbers = []string{"SYS_EXECVE", "SYS_EXECVEAT", "SYS_FORK", "SYS_VFORK", "SYS_CLONE", "SYS_CLONE3", "SYS_POSIX_SPAWN"}

// watched are the names, by package, that can start a process.
var watched = map[string]map[string]bool{
	"os/exec":                  set("Command", "CommandContext", "Cmd"),
	"os":                       set("StartProcess"),
	"syscall":                  set(append([]string{"ForkExec", "StartProcess", "Exec", "CreateProcess", "CreateProcessAsUser"}, sysNumbers...)...),
	"golang.org/x/sys/unix":    set(append([]string{"Exec"}, sysNumbers...)...),
	"golang.org/x/sys/windows": set("CreateProcess", "CreateProcessAsUser", "ShellExecute"),
}

// defaultNames are the names the watched packages are imported under when an
// import gives none: each package clause's own name.
var defaultNames = map[string]string{
	"os/exec":                  "exec",
	"os":                       "os",
	"syscall":                  "syscall",
	"golang.org/x/sys/unix":    "unix",
	"golang.org/x/sys/windows": "windows",
}

func set(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// linknameWords mark a //go:linkname target that can start a process.
var linknameWords = []string{"exec", "fork", "spawn", "startprocess"}

// target is one shipped binary: its main package, the platforms it ships
// for, and whether it is also listed with -tags farcast_embedded, the
// configuration the release builds it in.
type target struct {
	binary    string
	pkg       string
	platforms []string
	tagged    bool
}

// shipped are the binaries the gate covers. The dev tools (farcast-release,
// farcast-rehearsal) and the planck harness are not shipped; the harness links
// no non-standard package farcast does not, and its main starts nothing.
var shipped = []target{
	{"farcast", "./farsight/cli/cmd/farcast", []string{"darwin/arm64", "darwin/amd64", "linux/amd64", "linux/arm64", "windows/amd64"}, true},
	{"fatline", "./fatline/cmd/fatline", []string{"linux/amd64"}, false},
	{"shrike", "./shrike/cmd/shrike", []string{"linux/amd64"}, false},
	{"technocore", "./technocore/cmd/technocore", []string{"linux/amd64"}, false},
	{"datasphered", "./datasphere/cmd/datasphere", []string{"linux/amd64"}, false},
}

// embeddedTag is the build tag the release builds farcast with.
const embeddedTag = "farcast_embedded"

// componentsPath is the one package whose listing may fail, tagged: its
// //go:embed patterns name layer files that only a release build overlays.
const componentsPath = "github.com/sofmon/farcast/farsight/cli/internal/components"

// Run lists what the shipped binaries can start, one line per site, sorted and
// unique, on stdout. Exit 0 when listed, 1 on a failure (a go list error, a
// parse error), 2 on a usage error.
func Run(ctx context.Context, args []string, env []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		_, _ = fmt.Fprintln(stderr, "usage: farcast-release execsites (no arguments; run it in the repository root)")
		return 2
	}
	root, err := os.Getwd()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "execsites: %v\n", err)
		return 1
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		_, _ = fmt.Fprintln(stderr, "execsites: run me in the repository root: there is no go.mod here")
		return 1
	}
	lines, err := list(ctx, root, env, shipped)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "execsites: %v\n", err)
		return 1
	}
	var b bytes.Buffer
	for _, l := range lines {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	if _, err := stdout.Write(b.Bytes()); err != nil {
		_, _ = fmt.Fprintf(stderr, "execsites: %v\n", err)
		return 1
	}
	return 0
}

// listedPackage is what go list says about one package.
type listedPackage struct {
	ImportPath string
	Dir        string
	Standard   bool
	GoFiles    []string
	Error      *struct{ Err string }
}

// job is one go list: a binary on one platform, untagged or tagged.
type job struct {
	t        target
	platform string
	tagged   bool
	pkgs     []listedPackage
	err      error
}

// list runs every target's listing in root and returns the sorted, unique
// lines.
func list(ctx context.Context, root string, env []string, targets []target) ([]string, error) {
	real, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	goBin, ok := lookPath("go", envValue(env, "PATH"))
	if !ok {
		return nil, errors.New("the go command is not on PATH")
	}

	var jobs []*job
	for _, t := range targets {
		for _, p := range t.platforms {
			jobs = append(jobs, &job{t: t, platform: p})
			if t.tagged {
				jobs = append(jobs, &job{t: t, platform: p, tagged: true})
			}
		}
	}
	limit := make(chan struct{}, max(1, min(4, runtime.NumCPU())))
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			limit <- struct{}{}
			defer func() { <-limit }()
			j.pkgs, j.err = goList(ctx, goBin, real, env, j)
		}()
	}
	wg.Wait()
	for _, j := range jobs {
		if j.err != nil {
			return nil, j.err
		}
	}

	// Every file any job links, each scanned once.
	type fileKey struct{ importPath, path string }
	files := map[fileKey]*fileSites{}
	dirs := map[string]string{}
	rel := func(dir string) (string, error) {
		if r, ok := dirs[dir]; ok {
			return r, nil
		}
		d, err := filepath.EvalSymlinks(dir)
		if err != nil {
			return "", err
		}
		r, err := filepath.Rel(real, d)
		if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("package directory %s is outside the repository", dir)
		}
		dirs[dir] = filepath.ToSlash(r)
		return dirs[dir], nil
	}
	for _, j := range jobs {
		for _, p := range j.pkgs {
			d, err := rel(p.Dir)
			if err != nil {
				return nil, err
			}
			for _, f := range p.GoFiles {
				k := fileKey{p.ImportPath, pathJoin(d, f)}
				if files[k] == nil {
					files[k] = &fileSites{}
				}
			}
		}
	}
	keys := make([]fileKey, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	work := make(chan fileKey)
	errs := make([]error, len(keys))
	index := map[fileKey]int{}
	for i, k := range keys {
		index[k] = i
	}
	for range max(1, runtime.NumCPU()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := range work {
				src, err := os.ReadFile(filepath.Join(real, filepath.FromSlash(k.path)))
				if err == nil {
					*files[k], err = scanFile(token.NewFileSet(), k.importPath, k.path, src)
				}
				errs[index[k]] = err
			}
		}()
	}
	for _, k := range keys {
		work <- k
	}
	close(work)
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	for _, j := range jobs {
		prefix := j.t.binary + " " + j.platform + " "
		for _, p := range j.pkgs {
			d, _ := rel(p.Dir)
			var sites []*fileSites
			for _, f := range p.GoFiles {
				sites = append(sites, files[fileKey{p.ImportPath, pathJoin(d, f)}])
			}
			for _, l := range packageLines(p.ImportPath, sites) {
				seen[prefix+l] = true
			}
		}
	}
	lines := make([]string, 0, len(seen))
	for l := range seen {
		lines = append(lines, l)
	}
	sort.Strings(lines)
	return lines, nil
}

func pathJoin(dir, file string) string {
	if dir == "." {
		return file
	}
	return dir + "/" + file
}

// goList lists one job's packages: every non-standard package the binary
// links, with the files it compiles on that platform.
func goList(ctx context.Context, goBin, root string, env []string, j *job) ([]listedPackage, error) {
	goos, goarch, ok := strings.Cut(j.platform, "/")
	if !ok {
		return nil, fmt.Errorf("platform %q is not goos/goarch", j.platform)
	}
	args := []string{"list", "-e", "-mod=vendor", "-deps", "-json"}
	if j.tagged {
		args = append(args, "-tags", embeddedTag)
	}
	args = append(args, j.t.pkg)
	cmd := exec.CommandContext(ctx, goBin, args...)
	cmd.Dir = root
	cmd.Env = listEnv(env, root, goos, goarch)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	what := j.t.binary + " " + j.platform
	if j.tagged {
		what += " -tags " + embeddedTag
	}
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("go list for %s: %v: %s", what, err, strings.TrimSpace(errb.String()))
	}
	var pkgs []listedPackage
	dec := json.NewDecoder(&out)
	for {
		var p listedPackage
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("go list for %s: %w", what, err)
		}
		if p.Error != nil && !tolerated(j, p) {
			return nil, fmt.Errorf("go list for %s: %s: %s", what, p.ImportPath, p.Error.Err)
		}
		if p.Standard {
			continue
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}

// tolerated is the one package error a listing accepts: the tagged
// components package, whose embedded layer files exist only in a release
// build's overlay.
func tolerated(j *job, p listedPackage) bool {
	return j.tagged && p.ImportPath == componentsPath &&
		strings.HasPrefix(p.Error.Err, "pattern ") && strings.HasSuffix(p.Error.Err, ": no matching files found")
}

// listEnv is env with the platform set, cgo off, and nothing ambient that
// changes which files a package compiles: no GOFLAGS, no workspace, the
// release's GOAMD64 and GOARM64, and no experiments. GOENV=off, because an
// empty GOFLAGS or GOEXPERIMENT does not override a value set with 'go env -w':
// cmd/go falls back to the go env file when the variable is empty, so its
// -tags could hide a file from the listing. The listing needs nothing that
// file could hold: it reads vendor/, and under the release tool's invocation,
// GOTOOLCHAIN=<pin> go run, the go on PATH is the pinned one: go run puts its
// own GOROOT/bin first on the PATH of the program it runs, so that go switches
// to nothing. A farcast-release binary run directly, with another go first on
// PATH, can fail here when the switch to the pin needs a module cache that
// only the go env file names.
func listEnv(env []string, root, goos, goarch string) []string {
	drop := set("GOOS", "GOARCH", "CGO_ENABLED", "GOFLAGS", "GOWORK", "GOAMD64", "GOARM64", "GOEXPERIMENT", "GOENV", "PWD")
	out := make([]string, 0, len(env)+10)
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if !drop[k] {
			out = append(out, kv)
		}
	}
	out = append(out, "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0", "GOFLAGS=", "GOWORK=off", "GOEXPERIMENT=", "GOENV=off", "PWD="+root)
	switch goarch {
	case "amd64":
		out = append(out, "GOAMD64=v1")
	case "arm64":
		out = append(out, "GOARM64=v8.0")
	}
	return out
}

// fileSites is what one file holds, whichever binary links it.
type fileSites struct {
	importsExec bool
	lines       []string // ref and linkname lines, without binary and platform
}

// srcFile is one file of a package, for scanPackage.
type srcFile struct {
	path string // repository-relative, with forward slashes
	src  []byte
}

// scanPackage scans one package's files and returns its lines, without binary
// and platform, sorted.
func scanPackage(importPath string, files []srcFile) ([]string, error) {
	sites := make([]*fileSites, 0, len(files))
	for _, f := range files {
		s, err := scanFile(token.NewFileSet(), importPath, f.path, f.src)
		if err != nil {
			return nil, err
		}
		sites = append(sites, &s)
	}
	lines := packageLines(importPath, sites)
	sort.Strings(lines)
	return lines, nil
}

// packageLines are one package's lines, from the files a target compiles.
func packageLines(importPath string, sites []*fileSites) []string {
	var lines []string
	importsExec := false
	for _, s := range sites {
		importsExec = importsExec || s.importsExec
		lines = append(lines, s.lines...)
	}
	if importsExec {
		lines = append(lines, "import "+importPath+" os/exec")
	}
	return lines
}

// scanFile parses one file of the package importPath and reports its sites.
func scanFile(fset *token.FileSet, importPath, path string, src []byte) (fileSites, error) {
	f, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		return fileSites{}, fmt.Errorf("parse %s: %w", path, err)
	}
	var out fileSites

	named := map[string]string{} // local name → watched import path
	var dots []string            // watched import paths imported with "."
	for _, is := range f.Imports {
		p, err := strconv.Unquote(is.Path.Value)
		if err != nil {
			return fileSites{}, fmt.Errorf("parse %s: import %s: %w", path, is.Path.Value, err)
		}
		if p == "os/exec" {
			out.importsExec = true
		}
		if watched[p] == nil {
			continue
		}
		switch {
		case is.Name == nil:
			named[defaultNames[p]] = p
		case is.Name.Name == ".":
			dots = append(dots, p)
		case is.Name.Name == "_":
		default:
			named[is.Name.Name] = p
		}
	}

	// Package-level declarations of this file: a bare identifier resolved to
	// one of them refers to the package's own name, not to a local.
	topLevel := map[any]bool{}
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			topLevel[d] = true
		case *ast.GenDecl:
			for _, s := range d.Specs {
				topLevel[s] = true
			}
		}
	}
	own := watched[importPath]

	type key struct{ fn, name string }
	counts := map[key]int{}
	for _, d := range f.Decls {
		fn := "-"
		var declName *ast.Ident
		if fd, ok := d.(*ast.FuncDecl); ok {
			fn = funcName(fd)
			declName = fd.Name
		}
		var visit func(n ast.Node) bool
		visit = func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.SelectorExpr:
				if x, ok := n.X.(*ast.Ident); ok && x.Obj == nil {
					if p, ok := named[x.Name]; ok {
						if watched[p][n.Sel.Name] {
							counts[key{fn, p + "." + n.Sel.Name}]++
						}
						return false
					}
				}
				// The selected name is a field or a method, never a bare
				// reference; what it is selected from may hold one.
				ast.Inspect(n.X, visit)
				return false
			case *ast.Ident:
				if n == declName {
					return false
				}
				for _, p := range dots {
					if n.Obj == nil && watched[p][n.Name] {
						counts[key{fn, p + "." + n.Name}]++
					}
				}
				if own[n.Name] && refersToPackage(n, topLevel) {
					counts[key{fn, importPath + "." + n.Name}]++
				}
			}
			return true
		}
		ast.Inspect(d, visit)
	}
	for k, n := range counts {
		out.lines = append(out.lines, fmt.Sprintf("ref %s %s %s %dx", path, k.fn, k.name, n))
	}

	for _, cg := range f.Comments {
		for _, c := range cg.List {
			rest, ok := strings.CutPrefix(c.Text, "//go:linkname ")
			if !ok {
				continue
			}
			fields := strings.Fields(rest)
			if len(fields) == 0 {
				continue
			}
			local, tgt := fields[0], "-"
			sym := local
			if len(fields) > 1 {
				tgt, sym = fields[1], fields[1]
			}
			if startsProcess(sym) {
				out.lines = append(out.lines, fmt.Sprintf("linkname %s %s %s", path, local, tgt))
			}
		}
	}
	sort.Strings(out.lines)
	return out, nil
}

// refersToPackage reports whether a bare identifier refers to a package-level
// name: unresolved within its file (declared in another file of the package),
// or resolved to one of this file's top-level declarations. A declaration's
// own name, and a local that shadows the package's name, do not.
func refersToPackage(id *ast.Ident, topLevel map[any]bool) bool {
	if id.Obj == nil {
		return true
	}
	if !topLevel[id.Obj.Decl] {
		return false
	}
	switch d := id.Obj.Decl.(type) {
	case *ast.ValueSpec:
		for _, n := range d.Names {
			if n == id {
				return false
			}
		}
	case *ast.TypeSpec:
		return d.Name != id
	case *ast.FuncDecl:
		return d.Name != id
	}
	return true
}

// startsProcess reports whether a linkname symbol's last element names
// something that starts a process.
func startsProcess(sym string) bool {
	last := sym[strings.LastIndex(sym, "/")+1:]
	last = strings.ToLower(last[strings.LastIndex(last, ".")+1:])
	for _, w := range linknameWords {
		if strings.Contains(last, w) {
			return true
		}
	}
	return false
}

// funcName is a top-level function's name, or Type.Method for a method.
func funcName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	t := fd.Recv.List[0].Type
	for {
		switch x := t.(type) {
		case *ast.StarExpr:
			t = x.X
			continue
		case *ast.ParenExpr:
			t = x.X
			continue
		case *ast.IndexExpr:
			t = x.X
			continue
		case *ast.IndexListExpr:
			t = x.X
			continue
		case *ast.Ident:
			return x.Name + "." + fd.Name.Name
		}
		return "?." + fd.Name.Name
	}
}

// envValue is the last value env gives key.
func envValue(env []string, key string) string {
	v := ""
	for _, kv := range env {
		if k, val, ok := strings.Cut(kv, "="); ok && k == key {
			v = val
		}
	}
	return v
}

// lookPath finds an executable on a PATH value, searching absolute entries
// only.
func lookPath(name, pathValue string) (string, bool) {
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	for _, dir := range filepath.SplitList(pathValue) {
		if dir == "" || !filepath.IsAbs(dir) {
			continue
		}
		p := filepath.Join(dir, name)
		if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() {
			return p, true
		}
	}
	return "", false
}
