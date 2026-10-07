package keyholder

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/sofmon/farcast/datasphere"
)

func mustBundle(t *testing.T, instance string, generation uint64) *datasphere.Bundle {
	t.Helper()
	// Two applications, each with its own scope — the shape ADR 0018 decision
	// 5 deploys. A fixture with one scope could not tell "reached its own" from
	// "reached the only one there is".
	web, err := datasphere.NewAppScope("apps", "web")
	if err != nil {
		t.Fatalf("NewAppScope: %v", err)
	}
	api, err := datasphere.NewAppScope("apps", "api")
	if err != nil {
		t.Fatalf("NewAppScope: %v", err)
	}
	b, err := datasphere.NewBundle(instance, generation, []datasphere.Scope{web, api})
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	return b
}

// A keyholder always starts sealed. There is no path into this process that
// begins with key material already present.
func TestNewStartsRestartSealed(t *testing.T) {
	v := New("prod")
	st := v.State()
	if st.Phase != PhaseRestartSealed {
		t.Errorf("phase = %q, want %q", st.Phase, PhaseRestartSealed)
	}
	if !st.Sealed() || v.Ready() {
		t.Error("a fresh keyholder must be sealed and not ready")
	}
	if st.Generation != 0 || len(st.Scopes) != 0 {
		t.Errorf("fresh vault carries state: %+v", st)
	}
}

func TestUnsealFromRestartSealed(t *testing.T) {
	v := New("prod")
	if err := v.Unseal(mustBundle(t, "prod", 1), IntentOperator); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	st := v.State()
	if st.Phase != PhaseUnsealed || !v.Ready() {
		t.Fatalf("phase = %q, ready = %v", st.Phase, v.Ready())
	}
	if st.Generation != 1 || len(st.Scopes) != 2 || st.Scopes[0] != "app-apps-web" {
		t.Errorf("state after unseal = %+v", st)
	}
}

// A bundle assembled for one instance must never load into another — the
// mistake an operator makes at 03:00 with two terminals open.
func TestUnsealRefusesForeignInstance(t *testing.T) {
	v := New("prod")
	err := v.Unseal(mustBundle(t, "staging", 1), IntentOperator)
	if !errors.Is(err, ErrInstanceMismatch) {
		t.Fatalf("err = %v, want ErrInstanceMismatch", err)
	}
	if !v.State().Sealed() {
		t.Error("a refused unseal must leave the vault sealed")
	}
	for _, want := range []string{"prod", "staging"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should name both instances, got %v", err)
		}
	}
}

// The keeper rule, enforced in-cluster so it binds a thief, a tenant, and a
// stale honest keeper: an unattended re-seed may never clear a deliberate seal.
func TestKeeperCannotClearAnOperatorHold(t *testing.T) {
	v := New("prod")
	if err := v.Unseal(mustBundle(t, "prod", 1), IntentOperator); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	v.Seal(true, "suspected compromise")

	if err := v.Unseal(mustBundle(t, "prod", 2), IntentReseed); !errors.Is(err, ErrOperatorHold) {
		t.Fatalf("a keeper reseed cleared an operator hold: err = %v", err)
	}
	if v.State().Phase != PhaseOperatorHold {
		t.Error("the hold did not survive the refused reseed")
	}
	if !strings.Contains(v.State().HoldReason, "suspected compromise") {
		t.Errorf("hold reason lost: %+v", v.State())
	}

	// The operator, however, may.
	if err := v.Unseal(mustBundle(t, "prod", 2), IntentOperator); err != nil {
		t.Fatalf("operator unseal into a hold: %v", err)
	}
	if v.State().Phase != PhaseUnsealed {
		t.Error("operator unseal did not clear the hold")
	}
}

// Anti-rollback: a bundle captured before a rotation must not be replayable to
// put retired key material back into service — including across a seal.
func TestGenerationNeverGoesBackwards(t *testing.T) {
	v := New("prod")
	if err := v.Unseal(mustBundle(t, "prod", 7), IntentOperator); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if err := v.Unseal(mustBundle(t, "prod", 6), IntentOperator); !errors.Is(err, ErrGenerationTooOld) {
		t.Fatalf("accepted an older generation: %v", err)
	}

	// A seal must not be usable to rewind the high-water mark.
	v.Seal(false, "")
	if err := v.Unseal(mustBundle(t, "prod", 6), IntentOperator); !errors.Is(err, ErrGenerationTooOld) {
		t.Fatalf("sealing rewound the anti-rollback mark: %v", err)
	}
	if err := v.Unseal(mustBundle(t, "prod", 8), IntentOperator); err != nil {
		t.Fatalf("a newer generation must load: %v", err)
	}
	if v.State().Generation != 8 {
		t.Errorf("generation = %d, want 8", v.State().Generation)
	}
}

// Re-pushing the same generation is what lets the operator fan out across
// replicas and retry freely without tracking who already has it.
func TestUnsealIsIdempotentAtTheSameGeneration(t *testing.T) {
	v := New("prod")
	b := mustBundle(t, "prod", 3)
	if err := v.Unseal(b, IntentOperator); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	first := v.State().Since
	if err := v.Unseal(mustBundle(t, "prod", 3), IntentOperator); err != nil {
		t.Fatalf("second Unseal: %v", err)
	}
	if v.State().Since != first {
		t.Error("an idempotent unseal restarted the clock")
	}
	if v.State().Phase != PhaseUnsealed {
		t.Error("idempotent unseal disturbed the phase")
	}
}

func TestSealPhases(t *testing.T) {
	t.Run("without a hold lands on restart-sealed", func(t *testing.T) {
		v := New("prod")
		if err := v.Unseal(mustBundle(t, "prod", 1), IntentOperator); err != nil {
			t.Fatalf("Unseal: %v", err)
		}
		if got := v.Seal(false, "").Phase; got != PhaseRestartSealed {
			t.Errorf("phase = %q, want %q", got, PhaseRestartSealed)
		}
		// A keeper may act on this one.
		if err := v.Unseal(mustBundle(t, "prod", 2), IntentReseed); err != nil {
			t.Errorf("a keeper must be able to reseed a restart seal: %v", err)
		}
	})

	t.Run("with a hold lands on operator-hold", func(t *testing.T) {
		v := New("prod")
		if got := v.Seal(true, "maintenance").Phase; got != PhaseOperatorHold {
			t.Errorf("phase = %q, want %q", got, PhaseOperatorHold)
		}
	})
}

// Releasing a hold says "automation may act again", not "here are the keys".
func TestReleaseHoldLandsSealedNotUnsealed(t *testing.T) {
	v := New("prod")
	if err := v.Unseal(mustBundle(t, "prod", 1), IntentOperator); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	v.Seal(true, "maintenance")
	st := v.ReleaseHold()
	if st.Phase != PhaseRestartSealed {
		t.Fatalf("phase = %q, want %q — releasing a hold must never hand back key material", st.Phase, PhaseRestartSealed)
	}
	if v.Ready() {
		t.Error("released hold must not be ready")
	}
	if _, err := v.Scope("app/apps/web/x"); !errors.Is(err, ErrSealed) {
		t.Errorf("released hold still served a scope: %v", err)
	}
}

func TestScopeResolution(t *testing.T) {
	v := New("prod")
	if _, err := v.Scope("app/apps/web/x"); !errors.Is(err, ErrSealed) {
		t.Fatalf("sealed Scope = %v, want ErrSealed", err)
	}
	if err := v.Unseal(mustBundle(t, "prod", 1), IntentOperator); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if _, err := v.Scope("app/apps/web/x"); err != nil {
		t.Errorf("in-scope key refused: %v", err)
	}
	// Out-of-scope is permanent; sealed is temporary. An application must be
	// able to tell them apart.
	if _, err := v.Scope("system/secret"); !errors.Is(err, ErrOutOfScope) {
		t.Errorf("out-of-scope key = %v, want ErrOutOfScope", err)
	}
	if errors.Is(ErrOutOfScope, ErrSealed) {
		t.Error("ErrOutOfScope must not classify as ErrSealed")
	}
}

// Sealing must forget the material, not merely stop reporting it. The
// byte-level wipe is proven in the datasphere package, where key material is
// visible; from out here the observable contract is what is asserted — the
// scopes are gone and nothing resolves.
func TestSealDropsScopes(t *testing.T) {
	v := New("prod")
	if err := v.Unseal(mustBundle(t, "prod", 1), IntentOperator); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if len(v.State().Scopes) != 2 {
		t.Fatal("guard: the fixture's two scopes did not load")
	}
	// Observe the material the VAULT owns. This test used to watch it through
	// v.Scope(), which only worked because Scope handed out the vault's own
	// bytes — the aliasing that let a push zero the keys of a request still in
	// flight (see TestAPushDoesNotZeroKeysARequestIsStillUsing). Scope now
	// returns a copy, so the vault's slice is the only honest place to look.
	owned := append([]datasphere.Scope(nil), v.scopes...)
	for _, s := range owned {
		if s.Zeroed() {
			t.Fatal("guard: scope material is already zero before the seal")
		}
	}
	// A request admitted before the seal holds its own copy.
	admitted, err := v.Scope("app/apps/web/x")
	if err != nil {
		t.Fatalf("Scope: %v", err)
	}

	v.Seal(false, "")
	if got := v.State().Scopes; len(got) != 0 {
		t.Errorf("scopes survived the seal: %v", got)
	}
	for _, s := range owned {
		if !s.Zeroed() {
			t.Errorf("Seal dropped scope %q without wiping its material", s.Name)
		}
	}
	// The seal stops new requests and leaves an admitted one to finish with
	// the keys it was admitted with — and to wipe them itself. Zeroing them
	// here instead is the defect, not the safeguard.
	if admitted.Zeroed() {
		t.Error("Seal zeroed a copy belonging to a request it had already admitted")
	}
	admitted.Zero()
	if _, err := v.Scope("app/apps/web/x"); !errors.Is(err, ErrSealed) {
		t.Errorf("a sealed vault still resolved a scope: %v", err)
	}
}

// Vault.String formats counts and phases only — it has no path to key
// material — so this pins that it stays that way and still says enough to
// diagnose with.
func TestStringReportsWithoutMaterial(t *testing.T) {
	v := New("prod")
	if err := v.Unseal(mustBundle(t, "prod", 4), IntentOperator); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	rendered := v.String()
	for _, want := range []string{"prod", string(PhaseUnsealed), "4", "<redacted>"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("Vault.String should contain %q: %s", want, rendered)
		}
	}
}

// The vault is shared mutable state on the one process holding the crown
// jewels, so it is exercised under -race rather than assumed single-threaded.
func TestConcurrentAccess(t *testing.T) {
	v := New("prod")
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := range 50 {
				switch (i + j) % 4 {
				case 0:
					_ = v.Unseal(mustBundle(t, "prod", uint64(j)), IntentOperator)
				case 1:
					v.Seal(j%10 == 0, "churn")
				case 2:
					_, _ = v.Scope("app/apps/web/x")
				default:
					_ = v.State()
					_ = v.Ready()
				}
			}
		}(i)
	}
	wg.Wait()
}

// A bundle's key material is shared, not copied, by Bundle.Scopes(). The vault
// must therefore take OWNERSHIP of what it installs — otherwise the caller
// wiping its bundle (which it should, and the HTTP handler does) zeroes the
// keys the vault is now serving from.
//
// The failure is silent and catastrophic: the keyholder keeps working, because
// it encrypts and decrypts consistently with the zeroed key, so every object it
// writes is protected by a key of all zeros. The operator's own keyring can no
// longer address that data, and anyone holding the ciphertext can read it.
func TestUnsealTakesOwnershipOfKeyMaterial(t *testing.T) {
	v := New("prod")
	b := mustBundle(t, "prod", 1)
	if err := v.Unseal(b, IntentOperator); err != nil {
		t.Fatalf("Unseal: %v", err)
	}

	before, err := v.Scope("app/apps/web/x")
	if err != nil {
		t.Fatalf("Scope: %v", err)
	}
	if before.Zeroed() {
		t.Fatal("guard: the vault's material is already zero before the wipe")
	}

	// The caller wipes its copy, exactly as the unseal handler does on return.
	b.Zero()

	after, err := v.Scope("app/apps/web/x")
	if err != nil {
		t.Fatalf("Scope after the caller wiped its bundle: %v", err)
	}
	if after.Zeroed() {
		t.Fatal("the vault is serving zeroed key material: every object it writes " +
			"would be encrypted under a key of all zeros, and the operator's keyring could not address it")
	}
}

// appKeyring is a master keyring holding one scope per application, so a test
// can rotate it and bundle each version — the shape a real rotation pushes.
func appKeyring(t *testing.T, namespace string, apps ...string) datasphere.Keyring {
	t.Helper()
	k, err := datasphere.NewKeyring()
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	for _, app := range apps {
		s, err := datasphere.NewAppScope(namespace, app)
		if err != nil {
			t.Fatalf("NewAppScope(%s): %v", app, err)
		}
		if k, err = k.AddScope(s); err != nil {
			t.Fatalf("AddScope(%s): %v", app, err)
		}
	}
	return k
}

func bundleOf(t *testing.T, generation uint64, k datasphere.Keyring) *datasphere.Bundle {
	t.Helper()
	b, err := datasphere.NewBundle("prod", generation, k.Scopes())
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	return b
}

// The defect a probe found on 2026-10-06. An unseal at a new generation zeroes
// the scopes it replaces, and Vault.Scope used to hand requests those very
// scopes — so a write admitted before a push, and sealed after it, wrapped its
// data key under an all-zero KEK carrying the real key ID. The object then
// failed integrity under the real keys and opened under a key of zeros. Every
// `farcast run` that handed scopes to a serving keyholder took this path.
func TestAPushDoesNotZeroKeysARequestIsStillUsing(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	k := appKeyring(t, "apps", "web", "api")
	rotated, _, err := k.RotateScopeKEKs()
	if err != nil {
		t.Fatalf("RotateScopeKEKs: %v", err)
	}
	if err := h.vault.Unseal(bundleOf(t, 1, k), IntentOperator); err != nil {
		t.Fatalf("unseal gen 1: %v", err)
	}

	const key = "app/apps/web/in-flight"
	held, err := h.vault.Scope(key) // a request resolves its scope...
	if err != nil {
		t.Fatalf("Scope: %v", err)
	}
	inflight, err := h.srv.cfg.Stores(held)
	if err != nil {
		t.Fatalf("Stores: %v", err)
	}

	// ...the operator pushes a rotated bundle while that request is still
	// reading its body...
	if err := h.vault.Unseal(bundleOf(t, 2, rotated), IntentOperator); err != nil {
		t.Fatalf("unseal gen 2: %v", err)
	}
	if held.Zeroed() {
		t.Fatal("the push zeroed keys an admitted request was still using")
	}

	// ...and only then does the request seal and store its object.
	if err := inflight.Write(ctx, key, []byte("written in flight")); err != nil {
		t.Fatalf("in-flight Write: %v", err)
	}
	held.Zero()

	// The keyholder at generation 2 reads it with the real keys. Under the
	// defect this failed integrity, because the data key had been wrapped
	// under zeros.
	now, err := h.vault.Scope(key)
	if err != nil {
		t.Fatalf("Scope at gen 2: %v", err)
	}
	defer now.Zero()
	store, err := h.srv.cfg.Stores(now)
	if err != nil {
		t.Fatalf("Stores at gen 2: %v", err)
	}
	got, err := store.Read(ctx, key)
	if err != nil {
		t.Fatalf("an object written in flight across a push no longer reads: %v", err)
	}
	if string(got) != "written in flight" {
		t.Errorf("read %q", got)
	}
}

// The other half of the same change: a request wiping its own copy must never
// reach what the vault holds. Were Vault.Scope ever to share bytes again, the
// first request to finish would zero the keyholder for everyone after it.
func TestARequestWipingItsKeysLeavesTheVaultServing(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	if err := h.vault.Unseal(bundleOf(t, 1, appKeyring(t, "apps", "web")), IntentOperator); err != nil {
		t.Fatalf("unseal: %v", err)
	}
	const key = "app/apps/web/x"
	first, err := h.vault.Scope(key)
	if err != nil {
		t.Fatalf("Scope: %v", err)
	}
	first.Zero()

	second, err := h.vault.Scope(key)
	if err != nil {
		t.Fatalf("Scope after a wipe: %v", err)
	}
	defer second.Zero()
	if second.Zeroed() {
		t.Fatal("one request wiping its keys zeroed the vault's")
	}
	store, err := h.srv.cfg.Stores(second)
	if err != nil {
		t.Fatalf("Stores: %v", err)
	}
	if err := store.Write(ctx, key, []byte("still serving")); err != nil {
		t.Fatalf("Write after another request's wipe: %v", err)
	}
	if got, err := store.Read(ctx, key); err != nil || string(got) != "still serving" {
		t.Fatalf("Read after another request's wipe: %q, %v", got, err)
	}
}
