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

// StoredPrefix must report exactly what a listing queries, and it must differ
// per keyring — that difference is the whole diagnostic value: an empty
// listing under one keyring and a populated one under another is visible only
// if the queried prefix can be shown.
func TestStoredPrefixReportsWhatListingQueries(t *testing.T) {
	master := testKeyring(t)
	scope := mustScope(t, "app", "app/")
	fake := newFakeProvider()

	masterStore, err := NewStore(fake, "farcast-test-bucket", master)
	if err != nil {
		t.Fatal(err)
	}
	scopedStore, err := NewStore(fake, "farcast-test-bucket", scope.Keyring())
	if err != nil {
		t.Fatal(err)
	}

	mp, sp := masterStore.StoredPrefix("app/"), scopedStore.StoredPrefix("app/")
	if mp == "" || sp == "" {
		t.Fatalf("a /-aligned prefix must narrow a listing: master=%q scope=%q", mp, sp)
	}
	if mp == sp {
		t.Fatal("two keyrings tokenized the same prefix identically")
	}

	// It is the prefix the object actually lands under.
	ctx := context.Background()
	if err := scopedStore.Write(ctx, "app/doc", []byte("v")); err != nil {
		t.Fatal(err)
	}
	stored := mustStoredName(t, scopedStore, "app/doc")
	if !strings.HasPrefix(stored, sp) {
		t.Errorf("StoredPrefix(%q) = %q, which does not prefix the stored name %q", "app/", sp, stored)
	}

	// A prefix with nothing to align on narrows nothing, and says so.
	if got := scopedStore.StoredPrefix("app"); got != "" {
		t.Errorf("StoredPrefix(%q) = %q, want empty", "app", got)
	}
}

// IsSecretsKey decides what the keyholder refuses to let an application write,
// so its edges are the rule's edges.
func TestIsSecretsKey(t *testing.T) {
	for _, tc := range []struct {
		key  string
		want bool
	}{
		{"app/secrets/api/DB_PASSWORD", true},
		{"app/secrets/x", true},
		// The subtree's own prefix addresses no object.
		{"app/secrets/", false},
		{"app/secrets", false},
		// A neighbouring name that merely starts with the segment.
		{"app/secretsauce/x", false},
		{"app/reports/q3.csv", false},
		// Outside the scope entirely: not this scope's secrets.
		{"other/secrets/api/x", false},
		{"", false},
	} {
		if got := IsSecretsKey("app/", tc.key); got != tc.want {
			t.Errorf("IsSecretsKey(app/, %q) = %v, want %v", tc.key, got, tc.want)
		}
	}
}

// The writer's rule for a secret name. The same table appears in the SDK's
// own tests, because the two implementations live in modules that cannot
// import each other; when they drift, the writer must be the stricter one.
func TestValidateSecretName(t *testing.T) {
	for _, name := range []string{"A", "DB_PASSWORD", "api.key", "token-2", "x"} {
		if err := ValidateSecretName(name); err != nil {
			t.Errorf("ValidateSecretName(%q) = %v, want nil", name, err)
		}
	}
	for _, name := range []string{
		"", "../../master/key", "a/b", "DB PASSWORD", "sh|ell",
		".hidden", "trailing.", "a..b", strings.Repeat("x", MaxSecretNameLen+1),
	} {
		if err := ValidateSecretName(name); err == nil {
			t.Errorf("ValidateSecretName(%q) = nil, want a refusal", name)
		}
	}
}

// The layout ADR 0018 decision 5 fixes: one scope per application, under a
// root that nothing owns.
func TestAppScopeLayout(t *testing.T) {
	if got := AppScopePrefix("shop", "api"); got != "app/shop/api/" {
		t.Errorf("AppScopePrefix = %q", got)
	}
	if got := AppSecretsPrefix("shop", "api"); got != "app/shop/api/secrets/" {
		t.Errorf("AppSecretsPrefix = %q", got)
	}
	name, err := AppScopeName("shop", "api")
	if err != nil || name != "app-shop-api" {
		t.Errorf("AppScopeName = %q, %v", name, err)
	}

	ns, app, ok := ParseAppScopePrefix("app/shop/api/")
	if !ok || ns != "shop" || app != "api" {
		t.Errorf("ParseAppScopePrefix = %q, %q, %v", ns, app, ok)
	}
	for _, bad := range []string{"app/", "app/shop/", "app/shop/api/extra/", "ops/shop/api/", "", "app/shop//"} {
		if _, _, ok := ParseAppScopePrefix(bad); ok {
			t.Errorf("ParseAppScopePrefix(%q) accepted", bad)
		}
	}

	// A pair too long to name is refused at the mint rather than truncated
	// into a collision with somebody else's scope — and the refusal names
	// both halves and the limit, because the operator's next move is to
	// shorten one of them and the generic rule does not say which.
	_, err = AppScopeName(strings.Repeat("n", 40), strings.Repeat("a", 40))
	if err == nil {
		t.Fatal("AppScopeName composed a name over the limit")
	}
	for _, want := range []string{strings.Repeat("n", 40), strings.Repeat("a", 40), "63"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
	if _, err := NewAppScope("Shop", "api"); err == nil {
		t.Error("NewAppScope accepted a namespace no manifest could carry")
	}
}

// Two applications' scopes coexist; a scope owning the root would not, which
// is why there is no longer one.
func TestAppScopesCoexistButNotWithARootScope(t *testing.T) {
	keys, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	for _, app := range []string{"api", "web"} {
		scope, serr := NewAppScope("shop", app)
		if serr != nil {
			t.Fatal(serr)
		}
		if keys, err = keys.AddScope(scope); err != nil {
			t.Fatalf("AddScope(%s): %v", app, err)
		}
	}
	// The same application in another namespace is another scope: the same
	// manifest deployed twice is two key spaces, not one shared one.
	other, err := NewAppScope("staging", "api")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.AddScope(other); err != nil {
		t.Errorf("a second namespace's scope was refused: %v", err)
	}

	// And a scope owning "app/" is refused against them, which is the
	// constraint that removed the shared scope rather than nesting inside it.
	root, err := NewScope("app", "app/")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.AddScope(root); err == nil {
		t.Error("a scope owning the application root was accepted alongside per-application scopes")
	}
}

// twoAppScopes is a master keyring holding two application scopes, the shape
// every instance has had since ADR 0018 decision 5.
func twoAppScopes(t *testing.T) Keyring {
	t.Helper()
	k := testKeyring(t)
	for _, app := range []string{"alpha", "beta"} {
		s, err := NewAppScope("demo", app)
		if err != nil {
			t.Fatalf("NewAppScope(%s): %v", app, err)
		}
		if k, err = k.AddScope(s); err != nil {
			t.Fatalf("AddScope(%s): %v", app, err)
		}
	}
	return k
}

func TestRotateScopeKEKsPrependsAFreshKEKToEveryScope(t *testing.T) {
	before := twoAppScopes(t)
	after, rotated, err := before.RotateScopeKEKs()
	if err != nil {
		t.Fatalf("RotateScopeKEKs: %v", err)
	}
	if len(rotated) != 2 {
		t.Fatalf("rotated %d scopes, want 2", len(rotated))
	}
	for i, s := range after.Scopes() {
		was := before.Scopes()[i]
		r := rotated[i]
		if r.Scope != s.Name {
			t.Errorf("rotation %d names scope %q, keyring has %q", i, r.Scope, s.Name)
		}
		keks := s.Keyring().KEKs()
		if len(keks) != len(was.Keyring().KEKs())+1 {
			t.Fatalf("scope %q has %d KEKs, want one more than %d", s.Name, len(keks), len(was.Keyring().KEKs()))
		}
		if keks[0].ID != r.Active {
			t.Errorf("scope %q: the active KEK is not the one the rotation reports", s.Name)
		}
		if keks[1].ID != r.Previous || r.Previous != was.Keyring().KEKs()[0].ID {
			t.Errorf("scope %q: the previous KEK was not kept second", s.Name)
		}
		if r.Active == r.Previous {
			t.Errorf("scope %q: rotated to the key it already had", s.Name)
		}
		// Addressing must not move: a new active name key would make every
		// object in the scope unlistable.
		gotNames, wantNames := s.Keyring().NameKeys(), was.Keyring().NameKeys()
		if len(gotNames) != len(wantNames) {
			t.Fatalf("scope %q: name keys went from %d to %d", s.Name, len(wantNames), len(gotNames))
		}
		for j := range gotNames {
			if gotNames[j].ID != wantNames[j].ID {
				t.Errorf("scope %q: name key %d changed", s.Name, j)
			}
		}
		if s.Prefix != was.Prefix || s.Created != was.Created {
			t.Errorf("scope %q: prefix or creation time changed", s.Name)
		}
	}
	// Each scope gets its own key: one shared fresh KEK would let one
	// application's bundle open another's new writes.
	if rotated[0].Active == rotated[1].Active {
		t.Error("two scopes were rotated onto the same KEK")
	}
}

func TestRotateScopeKEKsLeavesTheReceiverAndTheMasterAlone(t *testing.T) {
	before := twoAppScopes(t)
	activeBefore := before.Scopes()[0].Keyring().KEKs()[0].ID
	masterBefore := before.KEKs()[0].ID

	after, _, err := before.RotateScopeKEKs()
	if err != nil {
		t.Fatalf("RotateScopeKEKs: %v", err)
	}
	if got := before.Scopes()[0].Keyring().KEKs()[0].ID; got != activeBefore {
		t.Error("rotating mutated the receiver's scope")
	}
	if after.KEKs()[0].ID != masterBefore || len(after.KEKs()) != len(before.KEKs()) {
		t.Error("rotating scope KEKs touched the master KEKs")
	}
}

func TestRotateScopeKEKsWithNoScopesIsANoOp(t *testing.T) {
	k := testKeyring(t)
	after, rotated, err := k.RotateScopeKEKs()
	if err != nil {
		t.Fatalf("RotateScopeKEKs: %v", err)
	}
	if len(rotated) != 0 || len(after.Scopes()) != 0 {
		t.Errorf("a keyring with no scopes reported %d rotations", len(rotated))
	}
}

// The property `keeper revoke` depends on: material captured before the
// rotation — which is exactly what a lost keeper's bundle is — cannot open
// what the scope writes afterwards, and cannot open what a rekey moved.
func TestRotateScopeKEKsRetiresWhatAnOldBundleCanOpen(t *testing.T) {
	ctx := context.Background()
	fake := newFakeProvider()
	before := twoAppScopes(t)
	alphaBefore := before.Scopes()[0]
	prefix := alphaBefore.Prefix

	oldStore, err := NewStore(fake, "farcast-test-bucket", alphaBefore.Keyring())
	if err != nil {
		t.Fatalf("NewStore(old): %v", err)
	}
	if err := oldStore.Write(ctx, prefix+"before", []byte("written before")); err != nil {
		t.Fatalf("Write(before): %v", err)
	}

	after, rotated, err := before.RotateScopeKEKs()
	if err != nil {
		t.Fatalf("RotateScopeKEKs: %v", err)
	}
	newStore, err := NewStore(fake, "farcast-test-bucket", after.Scopes()[0].Keyring())
	if err != nil {
		t.Fatalf("NewStore(new): %v", err)
	}

	// The rotated scope still reads what was there.
	if got, err := newStore.Read(ctx, prefix+"before"); err != nil || string(got) != "written before" {
		t.Fatalf("the rotated scope lost an older object: %q, %v", got, err)
	}
	// New writes go under the new key, which the old material does not hold.
	if err := newStore.Write(ctx, prefix+"after", []byte("written after")); err != nil {
		t.Fatalf("Write(after): %v", err)
	}
	if KeyID(storedKeyID(t, fake, newStore, prefix+"after")) != rotated[0].Active {
		t.Error("a write after the rotation was not wrapped under the new KEK")
	}
	if _, err := oldStore.Read(ctx, prefix+"after"); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("pre-rotation material opened a post-rotation write: err = %v", err)
	}

	// And a rekey moves the older object out of the old material's reach.
	moved, err := newStore.Rekey(ctx, prefix+"before")
	if err != nil || !moved {
		t.Fatalf("Rekey(before) = %v, %v; want moved", moved, err)
	}
	if _, err := oldStore.Read(ctx, prefix+"before"); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("pre-rotation material still opens a rekeyed object: err = %v", err)
	}
	if got, err := newStore.Read(ctx, prefix+"before"); err != nil || string(got) != "written before" {
		t.Errorf("the rekeyed object no longer reads: %q, %v", got, err)
	}
}

func TestARotatedKeyringRoundTripsActiveFirst(t *testing.T) {
	after, rotated, err := twoAppScopes(t).RotateScopeKEKs()
	if err != nil {
		t.Fatalf("RotateScopeKEKs: %v", err)
	}
	data, err := after.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	back, err := ParseKeyring(data)
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}
	for i, s := range back.Scopes() {
		if s.Keyring().KEKs()[0].ID != rotated[i].Active {
			t.Errorf("scope %q came back with the wrong active KEK", s.Name)
		}
	}
}

// zeroReader mints the same bytes every time, so every key ID collides.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

// A rotation must never hand back a keyring Marshal would refuse — by the time
// the caller marshals, the old keyring may already be gone. With key IDs drawn
// from a reader that repeats, the new KEK collides with the one it replaces.
func TestRotateScopeKEKsRefusesACollidingKeyID(t *testing.T) {
	saved := keyRand
	keyRand = zeroReader{}
	defer func() { keyRand = saved }()

	before := twoAppScopes(t)
	activeBefore := before.Scopes()[0].Keyring().KEKs()[0].ID
	if _, _, err := before.RotateScopeKEKs(); !errors.Is(err, ErrKeyringInvalid) {
		t.Fatalf("RotateScopeKEKs with a colliding key ID = %v; want ErrKeyringInvalid", err)
	}
	if before.Scopes()[0].Keyring().KEKs()[0].ID != activeBefore || len(before.Scopes()[0].Keyring().KEKs()) != 1 {
		t.Error("a refused rotation changed the receiver")
	}
}

// previousKeys is what a rotation's hand-over keeps active while every
// replica takes the new keys.
func previousKeys(rotations []ScopeRotation) map[string]KeyID {
	out := make(map[string]KeyID, len(rotations))
	for _, r := range rotations {
		out[r.Scope] = r.Previous
	}
	return out
}

func TestWithScopeActiveHoldsTheNewKeyWithoutActivatingIt(t *testing.T) {
	before := twoAppScopes(t)
	rotated, rotations, err := before.RotateScopeKEKs()
	if err != nil {
		t.Fatalf("RotateScopeKEKs: %v", err)
	}
	held, err := rotated.WithScopeActive(previousKeys(rotations))
	if err != nil {
		t.Fatalf("WithScopeActive: %v", err)
	}
	for i, s := range held.Scopes() {
		keks := s.Keyring().KEKs()
		r := rotations[i]
		if keks[0].ID != r.Previous {
			t.Errorf("scope %q: active KEK is %s, want the previous key %s — holding a key must not activate it", s.Name, keks[0].ID, r.Previous)
		}
		ids := map[KeyID]bool{}
		for _, e := range keks {
			ids[e.ID] = true
		}
		if !ids[r.Active] {
			t.Errorf("scope %q: the new key is not held", s.Name)
		}
		if len(keks) != len(rotated.Scopes()[i].Keyring().KEKs()) || len(ids) != len(keks) {
			t.Errorf("scope %q: changing the active key changed which keys the scope holds", s.Name)
		}
	}
	// The receiver is untouched: it is what activation pushes.
	for i, s := range rotated.Scopes() {
		if s.Keyring().KEKs()[0].ID != rotations[i].Active {
			t.Errorf("WithScopeActive mutated the rotated keyring's scope %q", s.Name)
		}
	}
	// And the move is reversible: activating the new key again restores the
	// rotated keyring's active key without losing the previous one.
	back, err := held.WithScopeActive(func() map[string]KeyID {
		out := map[string]KeyID{}
		for _, r := range rotations {
			out[r.Scope] = r.Active
		}
		return out
	}())
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range back.Scopes() {
		keks := s.Keyring().KEKs()
		if keks[0].ID != rotations[i].Active || len(keks) != 2 {
			t.Errorf("scope %q after re-activation: %v", s.Name, keks)
		}
	}
}

// Choosing a key from the middle of a scope's list moves that one key and
// keeps every other — the newer ones before it and the older ones after.
func TestWithScopeActiveKeepsEveryKeyAroundTheOneItMoves(t *testing.T) {
	once, first, err := twoAppScopes(t).RotateScopeKEKs()
	if err != nil {
		t.Fatal(err)
	}
	twice, _, err := once.RotateScopeKEKs()
	if err != nil {
		t.Fatal(err)
	}
	middle := map[string]KeyID{}
	for _, r := range first {
		middle[r.Scope] = r.Active
	}
	moved, err := twice.WithScopeActive(middle)
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range moved.Scopes() {
		want := twice.Scopes()[i].Keyring().KEKs()
		got := s.Keyring().KEKs()
		if len(got) != 3 || got[0].ID != middle[s.Name] {
			t.Fatalf("scope %q: %v; want %s active and all three keys", s.Name, got, middle[s.Name])
		}
		if got[1].ID != want[0].ID || got[2].ID != want[2].ID {
			t.Errorf("scope %q: %v; want the newer key, then the older, behind the one moved", s.Name, got)
		}
	}
}

// A key the scope does not hold is refused, not added: WithScopeActive only
// ever chooses among keys a scope already has. That includes asking a keyring
// that never took a rotation to make the rotation's key active.
func TestWithScopeActiveRefusesAKeyTheScopeDoesNotHold(t *testing.T) {
	before := twoAppScopes(t)
	rotated, rotations, err := before.RotateScopeKEKs()
	if err != nil {
		t.Fatal(err)
	}
	activate := map[string]KeyID{rotations[0].Scope: rotations[0].Active}
	if _, err := before.WithScopeActive(activate); !errors.Is(err, ErrKeyringInvalid) {
		t.Errorf("activating a key the scope never held = %v; want ErrKeyringInvalid", err)
	}
	// A key held by ANOTHER scope is not this scope's to use.
	crossed := map[string]KeyID{rotations[0].Scope: rotations[1].Active}
	if _, err := rotated.WithScopeActive(crossed); !errors.Is(err, ErrKeyringInvalid) {
		t.Errorf("activating another scope's key = %v; want ErrKeyringInvalid", err)
	}
	absent := map[string]KeyID{"app-nobody-here": rotations[0].Active}
	if _, err := rotated.WithScopeActive(absent); !errors.Is(err, ErrKeyringInvalid) {
		t.Errorf("naming an absent scope = %v; want ErrKeyringInvalid", err)
	}
}

// Two machines that each deployed the same application before syncing hold two
// scopes with one name and different name keys. A merge used to accept them,
// keep this side's name key active, and so re-address every object the other
// side's keys had named: unlistable and unreadable, here and — once pushed —
// in the keyholder.
func TestMergeRefusesAScopeMintedTwice(t *testing.T) {
	mint := func() Keyring {
		k, err := NewKeyring()
		if err != nil {
			t.Fatal(err)
		}
		s, err := NewAppScope("demo", "alpha")
		if err != nil {
			t.Fatal(err)
		}
		if k, err = k.AddScope(s); err != nil {
			t.Fatal(err)
		}
		return k
	}
	here, there := mint(), mint()
	if _, err := here.Merge(there); !errors.Is(err, ErrKeyringInvalid) || !strings.Contains(err.Error(), "minted twice") {
		t.Fatalf("Merge of a scope minted twice = %v; want a refusal", err)
	}
	// The ordinary case still merges: the same scope, rotated on one side.
	rotated, _, err := here.RotateScopeKEKs()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := here.Merge(rotated); err != nil {
		t.Errorf("Merge of the same scope after a rotation = %v; want it merged", err)
	}
}
