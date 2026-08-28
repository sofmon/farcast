package datasphere

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func mustScope(t *testing.T, name, prefix string) Scope {
	t.Helper()
	s, err := NewScope(name, prefix)
	if err != nil {
		t.Fatalf("NewScope(%q, %q): %v", name, prefix, err)
	}
	return s
}

func TestNewScopeMintsIndependentMaterial(t *testing.T) {
	a := mustScope(t, "app", "app/")
	b := mustScope(t, "other", "other/")

	ak, _ := a.Keyring().ActiveKEK()
	bk, _ := b.Keyring().ActiveKEK()
	if ak.ID == bk.ID {
		t.Error("two scopes minted the same KEK id")
	}
	an, _ := a.Keyring().ActiveNameKey()
	if string(ak.key) == string(an.key) {
		t.Error("a scope's KEK and name key are the same material")
	}
	if a.Derivation != "" {
		t.Errorf("Derivation = %q, want empty: 3.2 mints scopes, it does not derive them", a.Derivation)
	}
}

func TestScopeOwns(t *testing.T) {
	s := mustScope(t, "app", "app/")
	for _, k := range []string{"app/x", "app/a/b"} {
		if !s.Owns(k) {
			t.Errorf("Owns(%q) = false", k)
		}
	}
	// "application/x" must NOT be owned by scope "app/" — this is why the
	// trailing separator is mandatory.
	for _, k := range []string{"application/x", "system/x", "app", "other/app/x"} {
		if s.Owns(k) {
			t.Errorf("Owns(%q) = true; a scope owns a subtree, not a string prefix", k)
		}
	}
}

func TestValidateScopePrefix(t *testing.T) {
	good := []string{"app/", "a/b/", "system/secrets/"}
	for _, p := range good {
		if err := ValidateScopePrefix(p); err != nil {
			t.Errorf("ValidateScopePrefix(%q) = %v, want nil", p, err)
		}
	}
	// ".." is a literal segment, not a traversal: this module deliberately
	// performs no normalization on logical keys, and Owns is a byte-prefix
	// test. A prefix containing it is odd but entirely consistent.
	if err := ValidateScopePrefix("app/../x/"); err != nil {
		t.Errorf("ValidateScopePrefix(%q) = %v; %q is a literal segment here, not traversal", "app/../x/", err, "..")
	}

	bad := []string{"", "app", "/", "//", "app//"}
	for _, p := range bad {
		if err := ValidateScopePrefix(p); err == nil {
			t.Errorf("ValidateScopePrefix(%q) = nil, want an error", p)
		}
	}
}

func TestValidateScopeName(t *testing.T) {
	for _, n := range []string{"app", "app-2", "a"} {
		if err := ValidateScopeName(n); err != nil {
			t.Errorf("ValidateScopeName(%q) = %v", n, err)
		}
	}
	for _, n := range []string{"", "App", "1app", "-app", "app_2", "app/", strings.Repeat("a", 64)} {
		if err := ValidateScopeName(n); err == nil {
			t.Errorf("ValidateScopeName(%q) = nil, want an error", n)
		}
	}
}

// A scope's String must never expose the keys to the data under it.
func TestScopeStringRedacts(t *testing.T) {
	s := mustScope(t, "app", "app/")
	kek, _ := s.Keyring().ActiveKEK()
	rendered := s.String()
	if strings.Contains(rendered, string(kek.key)) {
		t.Fatal("Scope.String leaked key material")
	}
	if !strings.Contains(rendered, "app") {
		t.Errorf("Scope.String should still name the scope: %s", rendered)
	}
}

func TestAddScopeRefusesDuplicatesAndOverlap(t *testing.T) {
	base := testKeyring(t)
	withApp, err := base.AddScope(mustScope(t, "app", "app/"))
	if err != nil {
		t.Fatalf("AddScope: %v", err)
	}

	cases := []struct {
		name  string
		scope Scope
	}{
		{"duplicate name", mustScope(t, "app", "elsewhere/")},
		{"identical prefix", mustScope(t, "other", "app/")},
		{"nested under existing", mustScope(t, "other", "app/inner/")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := withApp.AddScope(tc.scope); !errors.Is(err, ErrKeyringInvalid) {
				t.Fatalf("AddScope accepted %s: err = %v", tc.name, err)
			}
		})
	}

	// The other direction: a parent added over an existing child.
	withInner, err := testKeyring(t).AddScope(mustScope(t, "inner", "app/inner/"))
	if err != nil {
		t.Fatalf("AddScope: %v", err)
	}
	if _, err := withInner.AddScope(mustScope(t, "app", "app/")); !errors.Is(err, ErrKeyringInvalid) {
		t.Fatalf("AddScope accepted a parent over an existing child: %v", err)
	}

	// Sibling prefixes that merely share a leading string are NOT an
	// overlap: no key can be under both, which is exactly what the
	// mandatory trailing separator buys.
	if _, err := withApp.AddScope(mustScope(t, "sibling", "a/")); err != nil {
		t.Errorf("AddScope refused %q alongside %q; they share no key", "a/", "app/")
	}
}

// The compatibility property that makes the schema bump safe: a keyring with
// no scopes must still marshal as version 1, byte-identically to what every
// previous build wrote.
func TestScopelessKeyringStaysVersionOne(t *testing.T) {
	out, err := testKeyring(t).Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(out), "version: 1") {
		t.Fatalf("a scope-less keyring must marshal as version 1:\n%s", out)
	}
	if strings.Contains(string(out), "scopes:") {
		t.Error("a scope-less keyring must not emit a scopes block")
	}
}

func TestKeyringWithScopesRoundTrips(t *testing.T) {
	original, err := testKeyring(t).AddScope(mustScope(t, "app", "app/"))
	if err != nil {
		t.Fatalf("AddScope: %v", err)
	}
	out, err := original.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(out), "version: 2") {
		t.Fatalf("a keyring with scopes must marshal as version 2:\n%s", out)
	}

	back, err := ParseKeyring(out)
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}
	got, ok := back.ScopeNamed("app")
	if !ok {
		t.Fatal("scope did not survive the round trip")
	}
	want, _ := original.ScopeNamed("app")
	if got.Prefix != want.Prefix {
		t.Errorf("prefix = %q, want %q", got.Prefix, want.Prefix)
	}
	gk, _ := got.Keyring().ActiveKEK()
	wk, _ := want.Keyring().ActiveKEK()
	if gk.ID != wk.ID || string(gk.key) != string(wk.key) {
		t.Error("scope key material did not survive the round trip")
	}
}

// An older binary must refuse a file that has grown scopes rather than parse
// it with the scope material silently dropped — which would hand the operator
// a keyring that looks complete and cannot read a whole subtree.
func TestVersionOneFileCarryingScopesIsRefused(t *testing.T) {
	withScope, err := testKeyring(t).AddScope(mustScope(t, "app", "app/"))
	if err != nil {
		t.Fatalf("AddScope: %v", err)
	}
	out, err := withScope.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	downgraded := strings.Replace(string(out), "version: 2", "version: 1", 1)
	if _, err := ParseKeyring([]byte(downgraded)); !errors.Is(err, ErrKeyringInvalid) {
		t.Fatalf("a version 1 file carrying scopes must be refused, got %v", err)
	}
}

func TestMergeScopes(t *testing.T) {
	app := mustScope(t, "app", "app/")

	t.Run("adds an unseen scope", func(t *testing.T) {
		live := testKeyring(t)
		incoming, err := testKeyring(t).AddScope(app)
		if err != nil {
			t.Fatalf("AddScope: %v", err)
		}
		merged, err := live.Merge(incoming)
		if err != nil {
			t.Fatalf("Merge: %v", err)
		}
		if _, ok := merged.ScopeNamed("app"); !ok {
			t.Error("merge dropped the incoming scope")
		}
	})

	t.Run("refuses the same name under two prefixes", func(t *testing.T) {
		a, err := testKeyring(t).AddScope(app)
		if err != nil {
			t.Fatalf("AddScope: %v", err)
		}
		b, err := testKeyring(t).AddScope(mustScope(t, "app", "elsewhere/"))
		if err != nil {
			t.Fatalf("AddScope: %v", err)
		}
		if _, err := a.Merge(b); !errors.Is(err, ErrKeyringInvalid) {
			t.Fatalf("merge accepted one name over two prefixes: %v", err)
		}
	})

	t.Run("refuses an overlapping incoming prefix", func(t *testing.T) {
		a, err := testKeyring(t).AddScope(app)
		if err != nil {
			t.Fatalf("AddScope: %v", err)
		}
		b, err := testKeyring(t).AddScope(mustScope(t, "other", "app/inner/"))
		if err != nil {
			t.Fatalf("AddScope: %v", err)
		}
		if _, err := a.Merge(b); !errors.Is(err, ErrKeyringInvalid) {
			t.Fatalf("merge accepted an overlapping scope: %v", err)
		}
	})
}

// The property the whole scope design rests on: a keyholder given one scope's
// keys is cryptographically incapable of reaching anything else. It cannot
// even compute the stored name of an object outside its scope, because the
// name key differs.
func TestScopedStoreCannotReachMasterObjects(t *testing.T) {
	ctx := context.Background()
	master := testKeyring(t)
	fake := newFakeProvider()

	masterStore, err := NewStore(fake, "farcast-test-bucket", master)
	if err != nil {
		t.Fatalf("NewStore(master): %v", err)
	}
	if err := masterStore.Write(ctx, "system/secret", []byte("operator only")); err != nil {
		t.Fatalf("master Write: %v", err)
	}

	scope := mustScope(t, "app", "app/")
	scopedStore, err := NewStore(fake, "farcast-test-bucket", scope.Keyring())
	if err != nil {
		t.Fatalf("NewStore(scope): %v", err)
	}

	// Same bucket, same logical key, different name key: the scoped store
	// computes a different stored name and finds nothing.
	if _, err := scopedStore.Read(ctx, "system/secret"); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("a scoped store reached a master object: err = %v", err)
	}
	masterName := mustStoredName(t, masterStore, "system/secret")
	scopedName := mustStoredName(t, scopedStore, "system/secret")
	if masterName == scopedName {
		t.Fatal("scope and master tokenized the same logical key identically")
	}

	// And the scope's own round trip works, in the same bucket.
	if err := scopedStore.Write(ctx, "app/data", []byte("app data")); err != nil {
		t.Fatalf("scoped Write: %v", err)
	}
	got, err := scopedStore.Read(ctx, "app/data")
	if err != nil {
		t.Fatalf("scoped Read: %v", err)
	}
	if string(got) != "app data" {
		t.Errorf("scoped round trip = %q", got)
	}
	if _, err := masterStore.Read(ctx, "app/data"); !errors.Is(err, ErrObjectNotFound) {
		t.Errorf("the master store read a scoped object by logical key: %v", err)
	}
}

// Scopes must ride the tested backup path rather than needing a new one.
func TestExportImportCarriesScopes(t *testing.T) {
	original, err := testKeyring(t).AddScope(mustScope(t, "app", "app/"))
	if err != nil {
		t.Fatalf("AddScope: %v", err)
	}
	armored, err := ExportKeyring(original, "a sufficiently long passphrase")
	if err != nil {
		t.Fatalf("ExportKeyring: %v", err)
	}
	back, err := ImportKeyring(armored, "a sufficiently long passphrase")
	if err != nil {
		t.Fatalf("ImportKeyring: %v", err)
	}
	got, ok := back.ScopeNamed("app")
	if !ok {
		t.Fatal("export/import dropped the scope: the operator's backup would not restore app data")
	}
	want, _ := original.ScopeNamed("app")
	gk, _ := got.Keyring().ActiveKEK()
	wk, _ := want.Keyring().ActiveKEK()
	if string(gk.key) != string(wk.key) {
		t.Error("scope key material did not survive export/import")
	}
}

// The wipe Scope.Zero performs, asserted on the bytes themselves. Every other
// package can only observe the consequence, so this is the one place the
// mechanism is proven.
func TestScopeZeroWipesMaterial(t *testing.T) {
	s := mustScope(t, "app", "app/")
	kek, err := s.Keyring().ActiveKEK()
	if err != nil {
		t.Fatalf("ActiveKEK: %v", err)
	}
	nameKey, err := s.Keyring().ActiveNameKey()
	if err != nil {
		t.Fatalf("ActiveNameKey: %v", err)
	}
	if allZero(kek.key) || allZero(nameKey.key) {
		t.Fatal("guard: freshly minted material is already zero")
	}
	s.Zero()
	if !allZero(kek.key) {
		t.Error("Zero left the KEK in the heap")
	}
	if !allZero(nameKey.key) {
		t.Error("Zero left the name key in the heap — the key that can never be rotated")
	}
}
