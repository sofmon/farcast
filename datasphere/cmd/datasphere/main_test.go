package main

import (
	"flag"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/sofmon/farcast/datasphere"
)

// The harness is exercised through run(args, out, errw), which takes explicit
// writers and returns an exit code precisely so these tests need no process, no
// credentials, and no network. Nothing here runs a verb that opens a provider:
// those reach a cloud on the first call, and a test that needs a cloud is an
// integration test, not this.

// TestHoistFlags covers the argument reordering that lets an operator type
// either order. The parse assertions matter more than the reordering itself —
// hoisting is only correct if what comes out the far side of flag.Parse is the
// same flags and the same operands in the same order.
func TestHoistFlags(t *testing.T) {
	cases := []struct {
		name         string
		args         []string
		wantHoisted  []string
		wantBucket   string
		wantOperands []string
	}{
		{
			name:         "operands first, the shape the usage text shows",
			args:         []string{"app/config", "file.bin", "--bucket", "farcast-a-0011aabb"},
			wantHoisted:  []string{"--bucket", "farcast-a-0011aabb", "app/config", "file.bin"},
			wantBucket:   "farcast-a-0011aabb",
			wantOperands: []string{"app/config", "file.bin"},
		},
		{
			name:         "flags first, the shape the flag package expects",
			args:         []string{"--bucket", "farcast-a-0011aabb", "app/config", "file.bin"},
			wantHoisted:  []string{"--bucket", "farcast-a-0011aabb", "app/config", "file.bin"},
			wantBucket:   "farcast-a-0011aabb",
			wantOperands: []string{"app/config", "file.bin"},
		},
		{
			// A flag's VALUE does not start with "-" either, so a hoist that
			// only looked for leading non-flag arguments could tear a flag away
			// from its value. Nothing is moved when the arguments already open
			// with a flag.
			name:         "a flag value is not mistaken for an operand",
			args:         []string{"--keys", "keys.yaml", "app/config"},
			wantHoisted:  []string{"--keys", "keys.yaml", "app/config"},
			wantOperands: []string{"app/config"},
		},
		{
			// "-" is the documented stdin/stdout operand, not a flag — the flag
			// package reads it the same way. Treating it as the start of the
			// flag section would leave every flag behind the terminator.
			name:         "the stdin operand stays an operand",
			args:         []string{"app/config", "-", "--bucket", "farcast-a-0011aabb"},
			wantHoisted:  []string{"--bucket", "farcast-a-0011aabb", "app/config", "-"},
			wantBucket:   "farcast-a-0011aabb",
			wantOperands: []string{"app/config", "-"},
		},
		{
			name:         "no flags at all",
			args:         []string{"app/config"},
			wantHoisted:  []string{"app/config"},
			wantOperands: []string{"app/config"},
		},
		{
			name:        "nothing at all",
			args:        []string{},
			wantHoisted: []string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := hoistFlags(tc.args)
			if strings.Join(got, " ") != strings.Join(tc.wantHoisted, " ") {
				t.Errorf("hoistFlags(%q) = %q, want %q", tc.args, got, tc.wantHoisted)
			}

			// The flag set mirrors run's, minus the verbs: run parses and then
			// immediately dispatches to something that wants credentials, so
			// the parse step is re-created here rather than driven through it.
			fs := flag.NewFlagSet("datasphere put", flag.ContinueOnError)
			fs.SetOutput(new(strings.Builder))
			bucket := fs.String("bucket", "", "bucket name")
			fs.String("keys", "keys.yaml", "path to the instance keyring")
			if err := fs.Parse(got); err != nil {
				t.Fatalf("parsing the hoisted %q: %v", got, err)
			}
			if *bucket != tc.wantBucket {
				t.Errorf("--bucket = %q, want %q", *bucket, tc.wantBucket)
			}
			if strings.Join(fs.Args(), " ") != strings.Join(tc.wantOperands, " ") {
				t.Errorf("operands = %q, want %q", fs.Args(), tc.wantOperands)
			}
		})
	}
}

// TestKeygenWritesProtectedKeyring covers the whole of what keygen owes the
// operator: a parseable keyring, closed to everyone else on the machine, and
// the warning that this file is the data.
func TestKeygenWritesProtectedKeyring(t *testing.T) {
	path := filepath.Join(t.TempDir(), "instance", datasphere.KeysDirName, datasphere.KeysFileName)

	var out, errw strings.Builder
	if code := run([]string{"datasphere", "keygen", "--keys", path}, &out, &errw); code != 0 {
		t.Fatalf("keygen = %d, want 0 (stderr: %s)", code, errw.String())
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat the keyring: %v", err)
	}
	// The mode is the whole of this file's access control. Anyone else with an
	// account on the machine reading it holds every byte the instance stores.
	if perm := info.Mode().Perm(); perm != datasphere.KeysFileMode {
		t.Errorf("keyring mode = %04o, want %04o", perm, datasphere.KeysFileMode)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the keyring: %v", err)
	}
	keyring, err := datasphere.ParseKeyring(data)
	if err != nil {
		t.Fatalf("ParseKeyring on what keygen wrote: %v", err)
	}
	if len(keyring.NameKeys()) != 1 || len(keyring.KEKs()) != 1 {
		t.Errorf("keyring = %v, want one name key and one KEK", keyring)
	}

	// Verbatim, not paraphrased: an operator who reads a softened version of
	// this sentence will back the file up like a config file.
	if !strings.Contains(out.String(), datasphere.KeyLossWarning) {
		t.Errorf("keygen output does not carry the key-loss warning verbatim.\ngot:  %s\nwant: %s", out.String(), datasphere.KeyLossWarning)
	}

	// Nothing that mints a key may print one. The keyring's own String()
	// redacts; this checks the harness did not route around it.
	printed := out.String() + errw.String()
	material := regexp.MustCompile(`(?m)^\s*key:\s*(\S+)`).FindAllStringSubmatch(string(data), -1)
	if len(material) != 2 {
		t.Fatalf("expected 2 key entries in the written file, found %d", len(material))
	}
	for _, m := range material {
		if strings.Contains(printed, m[1]) {
			t.Errorf("keygen printed key material (%q) to its output", m[1])
		}
	}
}

// TestKeygenRefusesToOverwrite is the key-loss catastrophe in miniature. A
// second keygen over a live keyring destroys every key in it, and every object
// those keys address becomes permanently unreadable — the same failure a stale
// backup restored over the live file causes, which is why restores are
// merge-only. The create is exclusive, so the second attempt fails instead.
func TestKeygenRefusesToOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.yaml")

	var out, errw strings.Builder
	if code := run([]string{"datasphere", "keygen", "--keys", path}, &out, &errw); code != 0 {
		t.Fatalf("first keygen = %d, want 0 (stderr: %s)", code, errw.String())
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the keyring: %v", err)
	}

	out.Reset()
	errw.Reset()
	code := run([]string{"datasphere", "keygen", "--keys", path}, &out, &errw)
	if code != 1 {
		t.Errorf("second keygen = %d, want 1", code)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the keyring after the refused keygen: %v", err)
	}
	if string(after) != string(before) {
		t.Fatal("the second keygen replaced the keyring: every key it held is gone, and so is every object stored under them")
	}
	if !strings.Contains(errw.String(), "refusing to overwrite") {
		t.Errorf("refusal did not say what it refused: %s", errw.String())
	}
	// The refusal is one of the moments the operator most needs to hear why.
	if !strings.Contains(errw.String(), datasphere.KeyLossWarning) {
		t.Errorf("refusal does not carry the key-loss warning verbatim: %s", errw.String())
	}
}

// TestMintName covers the name the operator is expected to write down before
// anything billable exists under it.
func TestMintName(t *testing.T) {
	var out, errw strings.Builder
	if code := run([]string{"datasphere", "mint-name", "--instance", "alpha"}, &out, &errw); code != 0 {
		t.Fatalf("mint-name = %d, want 0 (stderr: %s)", code, errw.String())
	}
	// farcast-<instance>-<8 lowercase hex>: the prefix is what an operator
	// recognises in a cloud console, the suffix is the 32 bits that keep a
	// globally shared namespace from being squattable and probeable.
	if !regexp.MustCompile(`^farcast-alpha-[0-9a-f]{8}\n$`).MatchString(out.String()) {
		t.Errorf("mint-name printed %q, want farcast-alpha-<8 lowercase hex>", out.String())
	}
	// The harness has no local record to write the name into, so the notice is
	// the record-before-create discipline: the minted suffix exists nowhere
	// else, and an unrecorded bucket is billable storage nobody is watching.
	if !strings.Contains(errw.String(), "Record this name before creating the bucket") {
		t.Errorf("mint-name did not tell the operator to record the name first: %s", errw.String())
	}

	out.Reset()
	errw.Reset()
	if code := run([]string{"datasphere", "mint-name"}, &out, &errw); code != 1 {
		t.Errorf("mint-name without --instance = %d, want 1", code)
	}
	if out.String() != "" {
		t.Errorf("a failed mint-name printed a name on stdout: %q", out.String())
	}
}

// TestUsageAndOperandErrors pins the exit codes, because they are what a
// script wrapping the harness branches on: 2 for "this command is not
// something I can run", 1 for "I ran it and it failed".
func TestUsageAndOperandErrors(t *testing.T) {
	cases := []struct {
		name      string
		args      []string
		wantCode  int
		wantUsage bool
		wantErr   string
	}{
		{
			name:      "no verb",
			args:      []string{"datasphere"},
			wantCode:  2,
			wantUsage: true,
		},
		{
			name:      "unknown verb",
			args:      []string{"datasphere", "encrypt-nothing"},
			wantCode:  2,
			wantUsage: true,
		},
		{
			name:     "unknown flag",
			args:     []string{"datasphere", "keygen", "--nonesuch"},
			wantCode: 2,
		},
		{
			// The operands are only reached after a Store exists, and a Store
			// only exists once the recorded bucket has been validated — so a
			// missing bucket is caught before anything is read from disk.
			name:     "put without a bucket or instance",
			args:     []string{"datasphere", "put", "app/config", "file.bin"},
			wantCode: 1,
			wantErr:  "--bucket and --instance are both required",
		},
		{
			name:     "delete-bucket without a project",
			args:     []string{"datasphere", "delete-bucket", "--bucket", "farcast-a-0011aabb", "--instance", "alpha"},
			wantCode: 1,
			wantErr:  "project is required",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errw strings.Builder
			if code := run(tc.args, &out, &errw); code != tc.wantCode {
				t.Errorf("run(%q) = %d, want %d (stderr: %s)", tc.args, code, tc.wantCode, errw.String())
			}
			if tc.wantUsage && !strings.Contains(errw.String(), "usage:") {
				t.Errorf("run(%q) printed no usage: %s", tc.args, errw.String())
			}
			if tc.wantErr != "" && !strings.Contains(errw.String(), tc.wantErr) {
				t.Errorf("run(%q) stderr = %q, want it to mention %q", tc.args, errw.String(), tc.wantErr)
			}
			if out.String() != "" {
				t.Errorf("a failed command wrote to stdout: %q", out.String())
			}
		})
	}
}

// dataVerbs are the harness verbs that touch stored data. Every one of them
// must reach the cloud through the encrypting Store and through nothing else.
var dataVerbs = []string{"put", "get", "ls", "rm"}

// bypassVocabulary is how a plaintext bypass would be spelled if one were ever
// added. It is matched against flag NAMES rather than help text, so that a
// usage string may go on saying the word "plaintext" in a warning.
var bypassVocabulary = []string{"raw", "plain", "cleartext", "unencrypted", "noencrypt", "no-encrypt", "bypass", "insecure", "nocrypt"}

// TestNoPlaintextBypass is an invariant, not a feature test. There must be no
// flag, no verb, and no code path in this harness that hands a provider a byte
// the encrypting layer has not sealed.
//
// A debug flag that ships plaintext to a bucket is a standing footgun aimed at
// the module's reason to exist: it takes "the cloud provider sees only
// encrypted blobs" from a structural fact — true because no plaintext can
// physically reach an adapter — back down to a promise that holds only while
// nobody passes the wrong flag. The bypass would be used exactly when someone
// is debugging, on exactly the data they are debugging, and it would leave that
// data in the cloud forever afterwards. So the invariant is enforced here, on
// the harness's actual flag set and its actual source, rather than trusted to a
// comment in the file it is meant to constrain.
func TestNoPlaintextBypass(t *testing.T) {
	t.Run("the flag surface offers no bypass", func(t *testing.T) {
		// -h renders the real flag set — whatever it contains today, including
		// a flag added after this test was written.
		var out, errw strings.Builder
		if code := run([]string{"datasphere", "put", "-h"}, &out, &errw); code != 2 {
			t.Fatalf("run(put -h) = %d, want 2", code)
		}
		matches := regexp.MustCompile(`(?m)^\s+-([\w.-]+)`).FindAllStringSubmatch(errw.String(), -1)
		var names []string
		for _, m := range matches {
			names = append(names, strings.ToLower(m[1]))
		}
		// Guard the guard: an extraction that silently matched nothing would
		// make every assertion below vacuously true.
		if len(names) < 5 || !slices.Contains(names, "bucket") {
			t.Fatalf("could not read the flag set out of the help output (%q); the check below would pass vacuously", errw.String())
		}
		for _, name := range names {
			for _, word := range bypassVocabulary {
				if strings.Contains(name, word) {
					t.Errorf("flag --%s reads like a plaintext bypass; the harness must not offer one", name)
					break
				}
			}
		}
	})

	file := harnessSource(t)

	t.Run("every data verb goes through openStore", func(t *testing.T) {
		runDecl := funcDecl(t, file, "run")
		var dispatched bool
		ast.Inspect(runDecl, func(n ast.Node) bool {
			clause, ok := n.(*ast.CaseClause)
			if !ok || !containsAny(caseLiterals(clause), dataVerbs) {
				return true
			}
			dispatched = true
			if got := caseLiterals(clause); !sameSet(got, dataVerbs) {
				t.Errorf("the data-verb case handles %q, want exactly %q — a data verb dispatched elsewhere is a path this test does not watch", got, dataVerbs)
			}
			if !calls(clause, "object") {
				t.Error("the data-verb case does not dispatch to object(), which is the only function that opens a Store")
			}
			return true
		})
		if !dispatched {
			t.Fatalf("no case in run() dispatches %q; the dispatch has moved and this invariant is no longer being checked", dataVerbs)
		}

		objectDecl := funcDecl(t, file, "object")
		if !calls(objectDecl, "openStore") {
			t.Error("object() does not obtain its Store from openStore(), which is where the recorded bucket is validated before anything is written")
		}
		// openStore is the composition root's enforcement point. A data verb
		// that built its own provider would skip the ownership check as well as
		// the encryption.
		for _, opener := range []string{"openProvider", "datasphere.Open"} {
			if calls(objectDecl, opener) {
				t.Errorf("object() reaches a provider directly via %s(); data verbs may only touch a cloud through the Store", opener)
			}
		}

		// One constructor, one call site: NewStore is the only way to a Store
		// and there is no unencrypted alternative to reach for.
		var sites int
		ast.Inspect(file, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok && callee(call) == "datasphere.NewStore" {
				sites++
			}
			return true
		})
		if sites != 1 {
			t.Errorf("datasphere.NewStore is called %d times, want exactly 1 (inside openStore)", sites)
		}
		if !calls(funcDecl(t, file, "openStore"), "datasphere.NewStore") {
			t.Error("openStore does not construct the Store; the single NewStore call has moved somewhere unvalidated")
		}
	})

	t.Run("no provider object call anywhere in the harness", func(t *testing.T) {
		// The four Provider methods that move object bytes. The harness may
		// call the bucket-lifecycle methods — they carry no data — but the
		// moment it calls one of these it is putting or fetching bytes that the
		// Store never sealed.
		dataMethods := map[string]bool{"Put": true, "Get": true, "List": true, "Delete": true}

		providers := boundTo(file, map[string]bool{"openProvider": true, "datasphere.Open": true})
		if len(providers) == 0 {
			t.Fatal("found no variable holding a datasphere.Provider; the check below would pass vacuously")
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			recv, ok := sel.X.(*ast.Ident)
			if !ok || !providers[recv.Name] || !dataMethods[sel.Sel.Name] {
				return true
			}
			t.Errorf("%s.%s() calls a Provider object method directly: whatever it passes has not been through the encrypting Store", recv.Name, sel.Sel.Name)
			return true
		})
	})
}

// harnessSource parses the harness. The bypass invariant is a property of the
// code rather than of any single run, so the test reads the code — go test runs
// with the package directory as its working directory.
func harnessSource(t *testing.T) *ast.File {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}
	return file
}

func funcDecl(t *testing.T, file *ast.File, name string) *ast.FuncDecl {
	t.Helper()
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == name {
			return fn
		}
	}
	t.Fatalf("main.go has no func %s; the harness has been restructured and this invariant needs re-stating against the new shape", name)
	return nil
}

// callee renders a call's target as it is written: "object", "openStore",
// "datasphere.NewStore".
func callee(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		if x, ok := fn.X.(*ast.Ident); ok {
			return x.Name + "." + fn.Sel.Name
		}
		return fn.Sel.Name
	}
	return ""
}

func calls(node ast.Node, name string) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && callee(call) == name {
			found = true
		}
		return !found
	})
	return found
}

// boundTo collects the names of variables assigned from any of the given
// constructors. Only the first result is taken, because that is the value
// position every one of them returns the provider in — and taking the rest
// would name the error and the exit code as providers too.
func boundTo(file *ast.File, constructors map[string]bool) map[string]bool {
	names := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok || !constructors[callee(call)] {
			return true
		}
		if ident, ok := assign.Lhs[0].(*ast.Ident); ok && ident.Name != "_" {
			names[ident.Name] = true
		}
		return true
	})
	return names
}

// caseLiterals returns a switch case's string literals.
func caseLiterals(clause *ast.CaseClause) []string {
	var out []string
	for _, expr := range clause.List {
		lit, ok := expr.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}
		value, err := strconv.Unquote(lit.Value)
		if err != nil {
			continue
		}
		out = append(out, value)
	}
	return out
}

func containsAny(have, want []string) bool {
	for _, w := range want {
		if slices.Contains(have, w) {
			return true
		}
	}
	return false
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, v := range b {
		if !slices.Contains(a, v) {
			return false
		}
	}
	return true
}
