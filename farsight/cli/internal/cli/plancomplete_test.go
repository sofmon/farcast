package cli

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/output"
)

// ADR 0023 M2.6d (A23-16, A23-28, design §28's step 9b): the completeness
// guards. The consent tests run over tables (writeCommands, planCommands,
// runDeployRows, the gates of TestNonInteractiveRefusalsNameThePlan), and a
// table that leaves a command, a flag or a gate out lets it go untested
// while every test passes. These guards derive what the tables must hold
// from farcast itself — the commands its router reaches, built by the
// constructors it uses (defaultRegistry), each one's flags as its own
// SetFlags registers them, and the refusals in this package's source — and
// fail when a table holds less.

// consentCommands is every command farcast's router reaches that registers
// --plan or --confirm, by the name a command line gives it ("kernel
// deploy"), each built by defaultRegistry, as farcast builds it: the
// commands that have plans.
func consentCommands(t *testing.T) map[string]Command {
	t.Helper()
	found := map[string]Command{}
	var walk func(prefix string, reg *Registry)
	walk = func(prefix string, reg *Registry) {
		for _, c := range reg.Commands() {
			name := strings.TrimSpace(prefix + " " + c.Name())
			if g, ok := c.(*group); ok {
				walk(name, g.subs)
				continue
			}
			if fs := commandFlags(c); fs.Lookup("plan") != nil || fs.Lookup("confirm") != nil {
				found[name] = c
			}
		}
	}
	walk("", defaultRegistry())
	if len(found) == 0 {
		t.Fatal("farcast's router reaches no command that registers --plan")
	}
	return found
}

// commandFlags is c's flag set as the router builds it for a command line:
// the global flags (registerCommon), then the command's own.
func commandFlags(c Command) *flag.FlagSet {
	var opts globalOpts
	fs := flag.NewFlagSet(c.Name(), flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	opts.registerCommon(fs)
	c.SetFlags(fs)
	return fs
}

// unboundFlags are the flags a plan never binds (A23-28): the global flags,
// whatever registerCommon registers, and the answers, --plan, --confirm,
// --yes and -y.
func unboundFlags() map[string]bool {
	var opts globalOpts
	fs := flag.NewFlagSet("global", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	opts.registerCommon(fs)
	exempt := map[string]bool{"plan": true, "confirm": true, "yes": true, "y": true}
	fs.VisitAll(func(f *flag.Flag) { exempt[f.Name] = true })
	return exempt
}

// behaviourFlags is every flag c registers that changes what it does, which
// its plans must bind (A23-28): all of them but unboundFlags, sorted.
func behaviourFlags(c Command) []string {
	exempt := unboundFlags()
	var names []string
	commandFlags(c).VisitAll(func(f *flag.Flag) {
		if !exempt[f.Name] {
			names = append(names, f.Name)
		}
	})
	slices.Sort(names)
	return names
}

// everyPlanShape is every plan the cross-cutting plan tests run: each
// planCommands row, a shape --plan prints, then each runDeployRows row,
// run's deploy plans, which --confirm with a fetch plan's digest prints
// (A28-11). It fails the test unless every writeCommands command, and every
// command with a plan that farcast's router reaches, has a planCommands
// row; unless every planCommands row is a writeCommands command's; and
// unless a command whose plans have a fetch stage has rows of its deploy
// stage too. A command left out of planCommands, or run's deploy plans left
// out, fails every test that runs over this.
func everyPlanShape(t *testing.T) []planCommand {
	t.Helper()
	printed := planCommands()
	rows := append(slices.Clone(printed), runDeployRows(t)...)
	planned := map[string]bool{} // the commands with a planCommands row
	for _, row := range printed {
		planned[row.name] = true
	}
	shapes := map[string]map[string]int{} // command → stage → rows
	for _, row := range rows {
		if shapes[row.name] == nil {
			shapes[row.name] = map[string]int{}
		}
		shapes[row.name][row.stage]++
	}
	writes := map[string]bool{}
	for _, wc := range writeCommands() {
		writes[wc.name] = true
		if !planned[wc.name] {
			t.Errorf("%s writes to the cluster and has no planCommands row, so no plan test runs its plan", wc.name)
		}
	}
	for name := range consentCommands(t) {
		if !planned[name] {
			t.Errorf("%s has a plan and no planCommands row, so no plan test runs it", name)
		}
	}
	for name, stages := range shapes {
		if !writes[name] {
			t.Errorf("planCommands has plans of %s, which is no writeCommands command", name)
		}
		if stages["fetch"] > 0 && stages["deploy"] == 0 {
			t.Errorf("%s's plans have a fetch stage and no row of its deploy stage", name)
		}
	}
	return rows
}

// ADR 0023 M2.6d (design §28's step 9b): every command that writes to an
// instance's cluster has its plan run by the plan tests: everyPlanShape's
// guard. And each row says who its plan reads the cluster as (M2.7,
// A30-26): its identity, reader, writer or none, is the cluster_identity of
// the plan it prints, and a row that reads the cluster as the reader says
// so (readsCluster) exactly when its identity is the reader.
func TestEveryWritingCommandHasAPlanRow(t *testing.T) {
	rows := everyPlanShape(t)
	if len(rows) == 0 {
		t.Fatal("no plan shape")
	}
	for _, row := range rows {
		t.Run(row.String(), func(t *testing.T) {
			if !slices.Contains([]string{"reader", "writer", "none"}, row.identity) {
				t.Fatalf("%s's identity is %q; say who its plan reads the cluster as: reader, writer or none", row, row.identity)
			}
			if row.readsCluster != (row.identity == "reader") {
				t.Errorf("%s reads the cluster as the reader: %v, and its identity is %q", row, row.readsCluster, row.identity)
			}
			_, dir := planFixture(t, row)
			doc, _ := runPrintedPlan(t, dir, row, output.ModeJSON)
			if got := decodedBound(t, doc).ClusterIdentity; got != row.identity {
				t.Errorf("%s's plan reads the cluster as %q; its row says %q", row, got, row.identity)
			}
		})
	}
}

// writeMethods are the methods of a seam that writes to a cluster: an apply,
// the pin's create and replace, migrate's rewrite (A30-26), and
// git-credential rm's delete (ADR 0023 M2.8, design §33, A33-32, row 93d),
// so a seam that only deletes is a writer too.
var writeMethods = []string{"Apply", "CreateConfigMap", "ReplaceConfigMap", "PatchManagedFields", "DeleteSecret"}

// productionWriters is every command farcast's router reaches, by the name
// a command line gives it, each built by defaultRegistry and walked down
// every group (storage key among them), that holds a seam that writes to a
// cluster, with the path of its first such seam (ADR 0023 M2.7, A30-26,
// RV-3). A seam is a field of the command whose type is a func, named
// (pinStoreOpener) or not, or such a field of a field of type
// fatlineDeployer, embedded (connect, redeploy) or named (kernel deploy's
// deployer); it writes when its first result is an interface whose method
// set holds one of writeMethods.
func productionWriters(t *testing.T) map[string]string {
	t.Helper()
	deployer := reflect.TypeFor[fatlineDeployer]()
	writing := func(ft reflect.Type) bool {
		if ft.Kind() != reflect.Func || ft.NumOut() == 0 || ft.Out(0).Kind() != reflect.Interface {
			return false
		}
		return slices.ContainsFunc(writeMethods, func(m string) bool {
			_, ok := ft.Out(0).MethodByName(m)
			return ok
		})
	}
	seamOf := func(typ reflect.Type) string {
		for i := range typ.NumField() {
			f := typ.Field(i)
			if writing(f.Type) {
				return f.Name
			}
			if f.Type != deployer {
				continue
			}
			for j := range deployer.NumField() {
				if d := deployer.Field(j); writing(d.Type) {
					return f.Name + "." + d.Name
				}
			}
		}
		return ""
	}
	found := map[string]string{}
	var walk func(prefix string, reg *Registry)
	walk = func(prefix string, reg *Registry) {
		for _, c := range reg.Commands() {
			name := strings.TrimSpace(prefix + " " + c.Name())
			if g, ok := c.(*group); ok {
				walk(name, g.subs)
				continue
			}
			typ := reflect.TypeOf(c)
			if typ.Kind() == reflect.Pointer {
				typ = typ.Elem()
			}
			if typ.Kind() != reflect.Struct {
				continue
			}
			if seam := seamOf(typ); seam != "" {
				found[name] = seam
			}
		}
	}
	walk("", defaultRegistry())
	if len(found) == 0 {
		t.Fatal("farcast's router reaches no command that writes to a cluster")
	}
	return found
}

// refusingTypes is every type in this package's non-test source with a
// method whose body calls refuseUnmigrated. It reads the source files from
// disk, so a mutation made through go test -overlay is not in what it reads.
func refusingTypes(dir string) (map[string]bool, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	found := map[string]bool{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Recv == nil || len(fn.Recv.List) != 1 {
				continue
			}
			rt := fn.Recv.List[0].Type
			if star, ok := rt.(*ast.StarExpr); ok {
				rt = star.X
			}
			id, ok := rt.(*ast.Ident)
			if !ok {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if fun, ok := call.Fun.(*ast.Ident); ok && fun.Name == "refuseUnmigrated" {
						found[id.Name] = true
					}
				}
				return true
			})
		}
	}
	return found, nil
}

// ADR 0023 M2.7 (A30-26, RV-3; §10.5 row 93c): every command in production
// that can write to a cluster is a writeCommands row, so the tests over
// writeCommands, and the refusal of an unmigrated instance with them, run
// it. The writers are derived from farcast itself (productionWriters), never
// listed: their names must be exactly writeCommands' names. The walk reaches
// a seam held in an embedded fatlineDeployer (connect), in a named one
// (kernel meter's deployer), of a named func type (storage key pin's
// pinStoreOpener), and git-credential rm's, whose writer deletes (ADR 0023
// M2.8, row 93d). And every such command's type but migrateCommand has a
// method that calls refuseUnmigrated, while migrateCommand has none: migrate
// never refuses an unmigrated instance, which is how one comes to be
// recorded (A30-20).
func TestEveryProductionWriterIsAWriteCommand(t *testing.T) {
	writers := productionWriters(t)
	var got, want []string
	for name := range writers {
		got = append(got, name)
	}
	for _, wc := range writeCommands() {
		want = append(want, wc.name)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("the commands farcast's router reaches that write to a cluster are %q; writeCommands holds %q", got, want)
	}
	for name, seam := range map[string]string{
		"kernel meter":      "deployer.newCluster",
		"connect":           "fatlineDeployer.newCluster",
		"storage key pin":   "newPinStore",
		"migrate":           "newCluster",
		"git-credential rm": "newCluster",
	} {
		if writers[name] != seam {
			t.Errorf("%s writes through %q; want it found through %q", name, writers[name], seam)
		}
	}

	refusing, err := refusingTypes(".")
	if err != nil {
		t.Fatal(err)
	}
	commands := map[string]Command{}
	var index func(prefix string, reg *Registry)
	index = func(prefix string, reg *Registry) {
		for _, c := range reg.Commands() {
			name := strings.TrimSpace(prefix + " " + c.Name())
			if g, ok := c.(*group); ok {
				index(name, g.subs)
				continue
			}
			commands[name] = c
		}
	}
	index("", defaultRegistry())
	for name := range writers {
		typ := reflect.TypeOf(commands[name])
		if typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		switch {
		case typ.Name() == "migrateCommand" && refusing[typ.Name()]:
			t.Errorf("%s (%s) calls refuseUnmigrated; migrate never refuses an unmigrated instance", name, typ.Name())
		case typ.Name() != "migrateCommand" && !refusing[typ.Name()]:
			t.Errorf("%s (%s) writes to a cluster, and no method of it calls refuseUnmigrated", name, typ.Name())
		}
	}

	// refusingTypes finds a method's call, through a value or a pointer
	// receiver, and not a function's, a method's that calls something else,
	// or a test file's.
	t.Run("refusingTypes", func(t *testing.T) {
		dir := t.TempDir()
		src := `package fake

type value struct{}
type pointer struct{}
type other struct{}

func refuseUnmigrated(string) error { return nil }

func (value) Run() error     { return refuseUnmigrated("a") }
func (p *pointer) plan() error {
	if true {
		return refuseUnmigrated("b")
	}
	return nil
}
func (other) Run() error { return nil }
func free() error        { return refuseUnmigrated("c") }
`
		if err := os.WriteFile(filepath.Join(dir, "fake.go"), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
		test := "package fake\n\ntype tested struct{}\n\nfunc (tested) Run() error { return refuseUnmigrated(\"d\") }\n"
		if err := os.WriteFile(filepath.Join(dir, "fake_test.go"), []byte(test), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := refusingTypes(dir)
		if err != nil {
			t.Fatal(err)
		}
		if want := map[string]bool{"value": true, "pointer": true}; !reflect.DeepEqual(got, want) {
			t.Errorf("refusingTypes = %v; want %v", got, want)
		}
	})
}

// ADR 0023 M2.6 (A23-28; design §28's step 9b): every flag that changes what
// a command does is bound into its plan, so --confirm of a plan made without
// it refuses a run with it, and no option names a flag the command does not
// have. For every command with a plan, the flags its own SetFlags registers
// — on the command defaultRegistry builds, as farcast's router does — minus
// the global flags, --plan, --confirm, --yes and -y, are exactly the flags
// of the options every one of its plans binds, its blocked plans' and run's
// deploy plans' among them. Each option binds its flag's parsed value, but
// for A23-28's exceptions: kernel confirm's --amount, --from and --to bind
// their resolved values, and kernel deploy's --adapt, --adapt-cooldown and
// --interval bind "" when not given, their effective values being the
// kernel_settings fact's. And one pinned exemption (ADR 0023 M2.8, design
// §33, A33-32, row 111a): git-credential set binds neither --username nor
// --token-file, which supply the Secret's data, rendered in a plan from
// placeholders, and no option of any plan names either.
func TestEveryBehaviourFlagIsBound(t *testing.T) {
	resolved := map[string][]string{"kernel confirm": {"amount", "from", "to"}}
	emptyUnlessGiven := map[string][]string{"kernel deploy": {"adapt", "adapt-cooldown", "interval"}}
	dataFlags := map[string][]string{"git-credential set": {"username", "token-file"}}
	commands := consentCommands(t)
	for _, row := range everyPlanShape(t) {
		t.Run(row.String(), func(t *testing.T) {
			c, ok := commands[row.name]
			if !ok {
				t.Fatalf("%s is no command with a plan that farcast's router reaches", row.name)
			}
			flags := behaviourFlags(c)
			for _, f := range dataFlags[row.name] {
				if !slices.Contains(flags, f) {
					t.Errorf("%s registers no --%s; this test's exemption is stale", row.name, f)
				}
			}
			want := slices.DeleteFunc(flags, func(f string) bool { return slices.Contains(dataFlags[row.name], f) })
			_, dir := planFixture(t, row)
			doc, _ := runPrintedPlan(t, dir, row, output.ModeJSON)
			b := decodedBound(t, doc)
			var got []string
			for _, o := range b.Options {
				got = append(got, o.Flag)
				if slices.Contains(dataFlags["git-credential set"], o.Flag) {
					t.Errorf("%s's plan binds --%s, which supplies a Git credential's data and is never bound", row, o.Flag)
				}
			}
			slices.Sort(got)
			if !slices.Equal(got, want) {
				t.Errorf("%s's plan binds the options %q; its behaviour flags are %q", row, got, want)
			}

			// The values, from the row's flags parsed as the router parses
			// them into a command defaultRegistry builds.
			fs := commandFlags(consentCommands(t)[row.name])
			if err := fs.Parse(row.flags); err != nil {
				t.Fatal(err)
			}
			given := map[string]bool{}
			fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
			for _, o := range b.Options {
				f := fs.Lookup(o.Flag)
				if f == nil || slices.Contains(resolved[row.name], o.Flag) {
					continue
				}
				value := f.Value.String()
				if slices.Contains(emptyUnlessGiven[row.name], o.Flag) && !given[o.Flag] {
					value = ""
				}
				if o.Value != value {
					t.Errorf("%s's plan binds --%s=%q; the flag parsed is %q", row, o.Flag, o.Value, value)
				}
			}
		})
	}
}

// suffixedRefusals is every usage error (usagef) in this package's source
// whose format names the route that needs no terminal, consentSuffix
// (scanRefusals), each once. It fails the test for a usage error, in a
// method of a command that has a plan (planned), that asks for --yes and
// names no such route.
//
// It reads the source files from disk, so a mutation made through go test
// -overlay is not in what it reads.
func suffixedRefusals(t *testing.T, planned map[string]Command) []string {
	t.Helper()
	types := map[string]bool{}
	for _, c := range planned {
		typ := reflect.TypeOf(c)
		if typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		types[typ.Name()] = true
	}
	found, unnamed, err := scanRefusals(".", types)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range unnamed {
		t.Errorf("%s, which asks for --yes and names no plan: end it with consentSuffix", u)
	}
	if len(found) == 0 {
		t.Fatal("found no usage error naming the plan in this package's source")
	}
	return found
}

// scanRefusals reads the non-test Go files in dir and returns, once each,
// the format of every usagef call whose format, its constants resolved,
// holds consentSuffix: a constant that appends it, or a deployer's
// consent.suffix(), which is consentSuffix on a command that has a plan (the
// build question every deployer shares). unnamed is each usagef call in a
// method of one of the types named in planned whose format asks for --yes
// ("pass --yes") and holds no consentSuffix, as "position:
// receiver.method refuses <format>". A format that is not a constant
// expression of strings is neither.
func scanRefusals(dir string, planned map[string]bool) (found, unnamed []string, err error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, nil, err
	}
	fset := token.NewFileSet()
	var parsed []*ast.File
	consts := map[string]ast.Expr{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, nil, err
		}
		parsed = append(parsed, f)
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, s := range gd.Specs {
				vs := s.(*ast.ValueSpec)
				for i, name := range vs.Names {
					if i < len(vs.Values) {
						consts[name.Name] = vs.Values[i]
					}
				}
			}
		}
	}
	var text func(e ast.Expr, depth int) (string, bool)
	text = func(e ast.Expr, depth int) (string, bool) {
		if depth > 32 {
			return "", false
		}
		switch e := e.(type) {
		case *ast.BasicLit:
			if e.Kind != token.STRING {
				return "", false
			}
			s, err := strconv.Unquote(e.Value)
			return s, err == nil
		case *ast.Ident:
			v, ok := consts[e.Name]
			if !ok {
				return "", false
			}
			return text(v, depth+1)
		case *ast.ParenExpr:
			return text(e.X, depth+1)
		case *ast.BinaryExpr:
			if e.Op != token.ADD {
				return "", false
			}
			x, okX := text(e.X, depth+1)
			y, okY := text(e.Y, depth+1)
			return x + y, okX && okY
		case *ast.CallExpr:
			// <deployer>.consent.suffix()
			if sel, ok := e.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "suffix" && len(e.Args) == 0 {
				if inner, ok := sel.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "consent" {
					return text(ast.NewIdent("consentSuffix"), depth+1)
				}
			}
		}
		return "", false
	}
	if suffix, ok := text(ast.NewIdent("consentSuffix"), 0); !ok || suffix != consentSuffix {
		return nil, nil, fmt.Errorf("consentSuffix reads %q in %s; want %q", suffix, dir, consentSuffix)
	}

	for _, f := range parsed {
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			receiver := ""
			if fn.Recv != nil && len(fn.Recv.List) == 1 {
				rt := fn.Recv.List[0].Type
				if star, ok := rt.(*ast.StarExpr); ok {
					rt = star.X
				}
				if id, ok := rt.(*ast.Ident); ok {
					receiver = id.Name
				}
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) == 0 {
					return true
				}
				if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != "usagef" {
					return true
				}
				format, ok := text(call.Args[0], 0)
				switch {
				case !ok:
				case strings.Contains(format, consentSuffix):
					if !slices.Contains(found, format) {
						found = append(found, format)
					}
				case strings.Contains(format, "pass --yes") && planned[receiver]:
					unnamed = append(unnamed, fmt.Sprintf("%s: %s.%s refuses %q", fset.Position(call.Pos()), receiver, fn.Name.Name, format))
				}
				return true
			})
		}
	}
	return found, unnamed, nil
}

// TestScanRefusalsReadsEveryRoute: scanRefusals, which
// TestNonInteractiveRefusalsNameThePlan derives its gates from, finds a
// refusal whose constant appends consentSuffix, through a constant naming
// another, and one whose use appends a deployer's consent.suffix(); finds
// no refusal that does neither; reports a method of a command with a plan
// that asks for --yes without the route, and not a method of another type,
// a function, or a format that is no constant.
func TestScanRefusalsReadsEveryRoute(t *testing.T) {
	dir := t.TempDir()
	src := `package fake

const consentSuffix = ` + strconv.Quote(consentSuffix) + `

const (
	msgGate   = "gated; pass --yes to confirm" + consentSuffix
	msgViaOne = msgGate
	msgBuild  = "built; pass --yes to build it"
	msgOther  = "refusing; pass --yes"
)

type planned struct{ consent flags }
type flags struct{}
type other struct{}

func (flags) suffix() string { return consentSuffix }
func usagef(string, ...any) error { return nil }

func (p *planned) gate() error      { return usagef(msgViaOne) }
func (p *planned) build() error     { return usagef(msgBuild+p.consent.suffix(), 1) }
func (p planned) unnamed() error    { return usagef(msgOther) }
func (p *planned) inline() error    { return usagef("inline; pass --yes") }
func (p *planned) variable(s string) error { return usagef(s + consentSuffix) }
func (o *other) elsewhere() error   { return usagef(msgOther) }
func free() error                    { return usagef("free; pass --yes") }
func asked() error                   { return usagef("asked; confirm it in a terminal") }
`
	if err := os.WriteFile(filepath.Join(dir, "fake.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fake_test.go"), []byte("package fake\n\nfunc t() error { return usagef(\"test; pass --yes\") }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	found, unnamed, err := scanRefusals(dir, map[string]bool{"planned": true})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(found)
	if want := []string{"built; pass --yes to build it" + consentSuffix, "gated; pass --yes to confirm" + consentSuffix}; !slices.Equal(found, want) {
		t.Errorf("found %q; want %q", found, want)
	}
	var methods []string
	for _, u := range unnamed {
		_, rest, _ := strings.Cut(u, ": ")
		method, _, _ := strings.Cut(rest, " ")
		methods = append(methods, method)
	}
	if want := []string{"planned.unnamed", "planned.inline"}; !slices.Equal(methods, want) {
		t.Errorf("unnamed = %q; want the refusals of %q", unnamed, want)
	}

	// A source whose consentSuffix is not this package's is refused.
	if err := os.WriteFile(filepath.Join(dir, "fake.go"), []byte("package fake\n\nconst consentSuffix = \", or --yes\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := scanRefusals(dir, nil); err == nil {
		t.Error("scanRefusals read a consentSuffix that is not this package's")
	}
}
