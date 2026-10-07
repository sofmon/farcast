package cli

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/sofmon/farcast/datasphere"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
)

// scopedKeyring mints a keyring holding one scope per application and saves
// it — the shape every instance has had since ADR 0018 decision 5. The
// fixture most of these tests grew up on held no scopes at all, which is why
// a rotate and a rekey that never reached an application's keys passed them.
func scopedKeyring(t *testing.T, dir config.Dir, instance, namespace string, apps ...string) datasphere.Keyring {
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
	saveKeyring(t, dir, instance, k)
	return k
}

func saveKeyring(t *testing.T, dir config.Dir, instance string, k datasphere.Keyring) {
	t.Helper()
	data, err := k.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	replaceKeyring(t, dir, instance, data)
}

// replaceKeyring writes a keyring as a test arranges it, over whatever is
// there — the one writer that may.
func replaceKeyring(t *testing.T, dir config.Dir, instance string, data []byte) {
	t.Helper()
	current, err := dir.LoadInstanceKeyring(instance)
	if err != nil {
		if err := dir.CreateInstanceKeyring(instance, data); err != nil {
			t.Fatalf("CreateInstanceKeyring: %v", err)
		}
		return
	}
	if err := dir.SaveInstanceKeyring(instance, current, data); err != nil {
		t.Fatalf("SaveInstanceKeyring: %v", err)
	}
}

func handOverInstance(t *testing.T, name string) (config.Dir, *config.InstanceMetadata, *Env, *operatorSees) {
	t.Helper()
	dir := config.Dir(t.TempDir())
	meta := runnableInstance(t, dir, name)
	meta.Keyholder = &config.Keyholder{Deployed: true, Replicas: 2}
	if err := dir.SaveInstanceMetadata(name, meta); err != nil {
		t.Fatal(err)
	}
	env, outBuf, errBuf := testEnvBoth(dir, output.ModeHuman)
	return dir, meta, env, &operatorSees{out: outBuf, err: errBuf}
}

// operatorSees is everything a terminal shows: the result on stdout and the
// warnings on stderr. A test that read only one would miss half of it.
type operatorSees struct{ out, err *bytes.Buffer }

func (o *operatorSees) String() string { return o.out.String() + o.err.String() }

func openerFor(kh sealStateClient) keyholderOpener {
	return func(context.Context, *Env, string) (sealStateClient, func(), error) { return kh, func() {}, nil }
}

func TestAHandOverGivesServingReplicasExactlyTheKeysSent(t *testing.T) {
	dir, meta, env, _ := handOverInstance(t, "p60")
	k := scopedKeyring(t, dir, "p60", "demo", "alpha", "beta")
	kh := &fakeStateKeyholder{phase: "unsealed"}

	res := handOverKeys(context.Background(), env, meta, openerFor(kh), liveKeyring(t, dir, meta.Name), handOverOptions{})
	if !res.Complete() {
		t.Fatalf("hand-over not complete: %+v", res)
	}
	for i := range 2 {
		got := kh.replica(i).keys
		if !sameKeys(got, heldKeys(k)) {
			t.Errorf("replica %d holds %v, want %v", i, got, heldKeys(k))
		}
	}
	for _, intent := range kh.intents {
		if intent != keyholder.IntentHandOver {
			t.Errorf("pushed with intent %q, want %q", intent, keyholder.IntentHandOver)
		}
	}
	entries, err := keyholder.ReadLedger(dir.InstanceUnsealLedgerPath("p60"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Intent != keyholder.IntentHandOver || e.Result != "ok" {
			t.Errorf("ledger entry %+v: a hand-over must be recorded as one, so an audit can tell it from an unseal", e)
		}
	}
}

// H2. A hand-over that reached one replica of two used to leave the recorded
// generation behind; the next hand-over reused the number, the replica that
// had taken it treated it as a retry and installed nothing — and answered
// success. Here the second hand-over carries a key the first did not, and the
// serving replica must end up holding it.
func TestASecondHandOverIsNeverSwallowedAsARetry(t *testing.T) {
	dir, meta, env, _ := handOverInstance(t, "p61")
	k := scopedKeyring(t, dir, "p61", "demo", "alpha")
	kh := &fakeStateKeyholder{phase: "unsealed"}
	kh.replica(1).phase = "restart-sealed"

	first := handOverKeys(context.Background(), env, meta, openerFor(kh), liveKeyring(t, dir, meta.Name), handOverOptions{})
	if len(first.Loaded) != 1 || len(first.Waiting) != 1 {
		t.Fatalf("first hand-over: %+v; want replica 0 loaded and replica 1 waiting", first)
	}
	if meta.Keyholder.Generation != first.Generation {
		t.Fatalf("a generation one replica took was not recorded: record %d, took %d", meta.Keyholder.Generation, first.Generation)
	}

	// The keyring changes — a second application — and is handed over again.
	beta, err := datasphere.NewAppScope("demo", "beta")
	if err != nil {
		t.Fatal(err)
	}
	if k, err = k.AddScope(beta); err != nil {
		t.Fatal(err)
	}
	saveKeyring(t, dir, "p61", k)

	second := handOverKeys(context.Background(), env, meta, openerFor(kh), liveKeyring(t, dir, meta.Name), handOverOptions{})
	if second.Generation <= first.Generation {
		t.Fatalf("the second hand-over reused generation %d", second.Generation)
	}
	if !sameKeys(kh.replica(0).keys, heldKeys(k)) {
		t.Errorf("the serving replica kept %v after the second hand-over; want %v", kh.replica(0).keys, heldKeys(k))
	}
}

// The generation must clear what a replica holds, not only what this machine
// remembers — a record can lag (a failed save, another operator's push).
func TestAHandOverClearsAGenerationTheRecordNeverSaw(t *testing.T) {
	dir, meta, env, _ := handOverInstance(t, "p62")
	k := scopedKeyring(t, dir, "p62", "demo", "alpha")
	kh := &fakeStateKeyholder{phase: "unsealed"}
	kh.replica(0).generation = 7 // ahead of the record, which says 0

	res := handOverKeys(context.Background(), env, meta, openerFor(kh), liveKeyring(t, dir, meta.Name), handOverOptions{})
	if res.Generation != 8 {
		t.Fatalf("chose generation %d; want 8, one above the highest a replica reported", res.Generation)
	}
	if !sameKeys(kh.replica(0).keys, heldKeys(k)) {
		t.Error("the replica that was ahead of the record did not take the keys")
	}
}

func TestAHandOverNeverUnsealsASealedKeyholder(t *testing.T) {
	for _, phase := range []string{"restart-sealed", "operator-hold"} {
		t.Run(phase, func(t *testing.T) {
			dir, meta, env, _ := handOverInstance(t, "p63")
			scopedKeyring(t, dir, "p63", "demo", "alpha")
			kh := &fakeStateKeyholder{phase: phase}

			res := handOverKeys(context.Background(), env, meta, openerFor(kh), liveKeyring(t, dir, meta.Name), handOverOptions{})
			if kh.pushes != 0 {
				t.Errorf("pushed %d time(s) to a sealed keyholder", kh.pushes)
			}
			if len(res.Waiting) != 2 || res.Complete() {
				t.Errorf("result %+v; want both replicas waiting", res)
			}
			if meta.Keyholder.Generation != 0 {
				t.Errorf("recorded generation %d though no replica took one", meta.Keyholder.Generation)
			}
		})
	}
}

// A replica that is serving when read and sealed by the time it is pushed is
// refused by the keyholder itself, and counted as waiting — not as a failure,
// and never as success.
func TestAReplicaThatSealsMidHandOverIsWaiting(t *testing.T) {
	dir, meta, env, _ := handOverInstance(t, "p64")
	scopedKeyring(t, dir, "p64", "demo", "alpha")
	kh := &sealsOnPush{fakeStateKeyholder: &fakeStateKeyholder{phase: "unsealed"}}

	res := handOverKeys(context.Background(), env, meta, openerFor(kh), liveKeyring(t, dir, meta.Name), handOverOptions{})
	if len(res.Waiting) != 2 || len(res.Loaded) != 0 || len(res.Refused) != 0 {
		t.Fatalf("result %+v; want both replicas waiting", res)
	}
	if meta.Keyholder.Generation != 0 {
		t.Errorf("recorded generation %d though no replica took one", meta.Keyholder.Generation)
	}
}

// sealsOnPush is a replica that restarts between the state read and the push.
type sealsOnPush struct{ *fakeStateKeyholder }

func (s *sealsOnPush) Unseal(ctx context.Context, i int, payload []byte, intent string) (keyholder.State, error) {
	s.replica(i).phase = "restart-sealed"
	return s.fakeStateKeyholder.Unseal(ctx, i, payload, intent)
}

// A 200 that installed nothing is the failure H2 produced, and must never be
// reported as success.
func TestAHandOverThatInstallsNothingIsNotSuccess(t *testing.T) {
	dir, meta, env, errBuf := handOverInstance(t, "p65")
	scopedKeyring(t, dir, "p65", "demo", "alpha")
	kh := &installsNothing{fakeStateKeyholder: &fakeStateKeyholder{phase: "unsealed"}}

	res := handOverKeys(context.Background(), env, meta, openerFor(kh), liveKeyring(t, dir, meta.Name), handOverOptions{})
	if len(res.Loaded) != 0 || len(res.Refused) != 2 || res.Complete() {
		t.Fatalf("result %+v; a replica that took nothing was counted as loaded", res)
	}
	if meta.Keyholder.Generation != 0 {
		t.Errorf("recorded generation %d that no replica actually took", meta.Keyholder.Generation)
	}
	if !strings.Contains(errBuf.String(), "does not report the keys it was sent") {
		t.Errorf("the mismatch was not reported:\n%s", errBuf.String())
	}
	entries, err := keyholder.ReadLedger(dir.InstanceUnsealLedgerPath("p65"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Result != "not-installed" {
			t.Errorf("ledger entry %+v; want result not-installed", e)
		}
	}
}

// installsNothing answers every push with success and keeps what it had.
type installsNothing struct{ *fakeStateKeyholder }

func (n *installsNothing) Unseal(_ context.Context, i int, _ []byte, intent string) (keyholder.State, error) {
	n.pushes++
	n.intents = append(n.intents, intent)
	r := n.replica(i)
	return keyholder.State{Phase: r.phase, Generation: r.generation, Keys: copyKeys(r.keys), Boot: "b0"}, nil
}

// F5. `storage key rotate` used to rotate the master KEK alone, which reaches
// nothing an application wrote and nothing a keeper's bundle holds.
func TestRotateRotatesEveryScopeAndHandsTheKeysOver(t *testing.T) {
	dir, _, env, errBuf := handOverInstance(t, "p70")
	before := scopedKeyring(t, dir, "p70", "demo", "alpha", "beta")
	kh := &fakeStateKeyholder{phase: "unsealed"}

	cmd := &keyRotateCommand{assumeYes: true, newKeyholder: openerFor(kh)}
	if err := cmd.Run(context.Background(), env, []string{"p70"}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	after := liveKeyring(t, dir, "p70")
	if after.KEKs()[0].ID == before.KEKs()[0].ID {
		t.Error("the instance's own KEK did not rotate")
	}
	for i, s := range after.Scopes() {
		was := before.Scopes()[i]
		keks := s.Keyring().KEKs()
		if keks[0].ID == was.Keyring().KEKs()[0].ID {
			t.Errorf("scope %q did not rotate", s.Name)
		}
		if len(keks) < 2 || keks[1].ID != was.Keyring().KEKs()[0].ID {
			t.Errorf("scope %q lost the KEK its existing objects are wrapped under", s.Name)
		}
	}
	// The keyholder holds the NEW keys, so applications write under them from
	// the next request — the half of retirement that does not wait for rekey.
	for i := range 2 {
		if !sameKeys(kh.replica(i).keys, heldKeys(after)) {
			t.Errorf("replica %d holds %v after the rotation, want %v", i, kh.replica(i).keys, heldKeys(after))
		}
	}
	if !strings.Contains(errBuf.String(), "all 2 replicas hold the new keys") {
		t.Errorf("the hand-over was not reported:\n%s", errBuf.String())
	}
}

func TestRotateLeavesASealedKeyholderSealed(t *testing.T) {
	dir, _, env, errBuf := handOverInstance(t, "p71")
	scopedKeyring(t, dir, "p71", "demo", "alpha")
	kh := &fakeStateKeyholder{phase: "operator-hold"}

	before := heldKeys(liveKeyring(t, dir, "p71"))
	rotateWith(t, env, "p71", kh)
	if kh.pushes != 0 {
		t.Errorf("rotate pushed %d time(s) to a held keyholder", kh.pushes)
	}
	// Review finding 7. With no replica serving, nothing would stop a keeper
	// re-seeding the keys from before — so this machine must not start
	// writing under the new ones either.
	for name, ids := range heldKeys(liveKeyring(t, dir, "p71")) {
		if ids[0] != before[name][0] {
			t.Errorf("this machine now writes %s under %s, which no replica holds", name, ids[0])
		}
	}
	if out := errBuf.String(); !strings.Contains(out, "every replica is sealed") || !strings.Contains(out, "farcast storage unseal p71") {
		t.Errorf("rotate did not say why it stopped, or what to do:\n%s", out)
	}
}

func TestRotateNamesEveryKeeperThatMustBeReenrolled(t *testing.T) {
	dir, meta, env, errBuf := handOverInstance(t, "p72")
	scopedKeyring(t, dir, "p72", "demo", "alpha")
	meta.Keepers = []config.Keeper{{Device: "study-desktop"}, {Device: "lost-laptop", Revoked: true}}
	if err := dir.SaveInstanceMetadata("p72", meta); err != nil {
		t.Fatal(err)
	}
	cmd := &keyRotateCommand{assumeYes: true, newKeyholder: openerFor(&fakeStateKeyholder{phase: "unsealed"})}
	if err := cmd.Run(context.Background(), env, []string{"p72"}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	out := errBuf.String()
	if !strings.Contains(out, "farcast keeper enroll p72 study-desktop") {
		t.Errorf("an active keeper was not named for re-enrolment:\n%s", out)
	}
	if strings.Contains(out, "farcast keeper enroll p72 lost-laptop") {
		t.Errorf("a revoked keeper was offered re-enrolment:\n%s", out)
	}
	if !strings.Contains(out, "name key cannot rotate") {
		t.Errorf("rotate did not say what it cannot retire:\n%s", out)
	}
}

// rekeyInstance is newStorageEnv's instance as ADR 0018 decision 5 deploys it:
// a scope per application, a keyholder, and one object per application written
// through its own scope.
func rekeyInstance(t *testing.T) (*Env, *bytes.Buffer, config.Dir, *fakeObjectStore, datasphere.Keyring) {
	t.Helper()
	env, out, _, dir, f := newStorageEnv(t, output.ModeHuman)
	k := scopedKeyring(t, dir, "prod", "demo", "alpha", "beta")
	meta, err := dir.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatal(err)
	}
	meta.Keyholder = &config.Keyholder{Deployed: true, Replicas: 2}
	if err := dir.SaveInstanceMetadata("prod", meta); err != nil {
		t.Fatal(err)
	}
	for _, s := range k.Scopes() {
		store, err := datasphere.NewStore(f, testBucket, s.Keyring())
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Write(context.Background(), s.Prefix+"data", []byte("written by "+s.Name)); err != nil {
			t.Fatal(err)
		}
	}
	return env, out, dir, f, k
}

// F5, end to end. `keeper revoke` names rotate-then-rekey as the way to retire
// what a lost device holds. On the 2026-10-06 walk that pair rewrote 0 of 4
// objects and changed no key, because both worked on the master alone. Here
// the material a keeper enrolled before the rotation would carry must open
// none of the applications' objects afterwards.
func TestRotateThenRekeyRetiresWhatALostKeeperHolds(t *testing.T) {
	env, out, dir, f, before := rekeyInstance(t)
	ctx := context.Background()
	lost := before.Scopes() // exactly what a keeper's bundle carries
	kh := &fakeStateKeyholder{phase: "unsealed"}

	if err := (&keyRotateCommand{assumeYes: true, newKeyholder: openerFor(kh)}).Run(ctx, env, []string{"prod"}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	// The bare instance — what rotate tells the operator to type next (F4).
	if err := (&keyRekeyCommand{assumeYes: true, newKeyholder: openerFor(kh)}).Run(ctx, env, []string{"prod"}); err != nil {
		t.Fatalf("rekey: %v", err)
	}
	if !strings.Contains(out.String(), "rewritten: 2") {
		t.Errorf("rekey did not rewrite both application objects:\n%s", out.String())
	}

	after := liveKeyring(t, dir, "prod")
	for i, old := range lost {
		key := old.Prefix + "data"
		stale, err := datasphere.NewStore(f, testBucket, old.Keyring())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := stale.Read(ctx, key); !errors.Is(err, datasphere.ErrUnknownKey) {
			t.Errorf("a pre-rotation bundle still opens %s: err = %v", key, err)
		}
		current, err := datasphere.NewStore(f, testBucket, after.Scopes()[i].Keyring())
		if err != nil {
			t.Fatal(err)
		}
		if got, err := current.Read(ctx, key); err != nil || string(got) != "written by "+old.Name {
			t.Errorf("the current keys no longer read %s: %q, %v", key, got, err)
		}
	}
}

// Moving an object onto a KEK a serving replica does not hold makes it
// unreadable through that replica. So rekey moves nothing until every replica
// is serving the current keys.
func TestRekeyMovesNothingUntilEveryReplicaHoldsTheCurrentKeys(t *testing.T) {
	cases := map[string]func(kh *fakeStateKeyholder, old datasphere.Keyring){
		"a replica is sealed": func(kh *fakeStateKeyholder, _ datasphere.Keyring) {
			kh.replica(1).phase = "restart-sealed"
		},
		"a replica serves the old keys": func(kh *fakeStateKeyholder, old datasphere.Keyring) {
			kh.replica(1).phase, kh.replica(1).generation, kh.replica(1).keys = "unsealed", 1, heldKeys(old)
		},
	}
	for name, arrange := range cases {
		t.Run(name, func(t *testing.T) {
			env, _, _, f, before := rekeyInstance(t)
			ctx := context.Background()
			kh := &fakeStateKeyholder{phase: "unsealed"}
			if err := (&keyRotateCommand{assumeYes: true, newKeyholder: openerFor(kh)}).Run(ctx, env, []string{"prod"}); err != nil {
				t.Fatalf("rotate: %v", err)
			}
			arrange(kh, before)

			err := (&keyRekeyCommand{assumeYes: true, newKeyholder: openerFor(kh)}).Run(ctx, env, []string{"prod"})
			if err == nil || !strings.Contains(err.Error(), "farcast storage unseal prod") {
				t.Fatalf("rekey = %v; want a refusal naming 'farcast storage unseal prod'", err)
			}
			// Nothing moved: the old scope keys still open every object.
			for _, old := range before.Scopes() {
				stale, err := datasphere.NewStore(f, testBucket, old.Keyring())
				if err != nil {
					t.Fatal(err)
				}
				if _, err := stale.Read(ctx, old.Prefix+"data"); err != nil {
					t.Errorf("a refused rekey still moved %s: %v", old.Prefix+"data", err)
				}
			}
		})
	}
}

func TestARekeyDryRunSaysWhyARealRunWouldRefuse(t *testing.T) {
	env, out, _, _, _ := rekeyInstance(t)
	ctx := context.Background()
	kh := &fakeStateKeyholder{phase: "unsealed"}
	if err := (&keyRotateCommand{assumeYes: true, newKeyholder: openerFor(kh)}).Run(ctx, env, []string{"prod"}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	kh.replica(0).phase = "operator-hold"
	if err := (&keyRekeyCommand{dryRun: true, newKeyholder: openerFor(kh)}).Run(ctx, env, []string{"prod"}); err != nil {
		t.Fatalf("a dry run must not fail on the gate: %v", err)
	}
	text := out.String()
	if !strings.Contains(text, "would rekey 2 object(s) across 2 application scope(s)") {
		t.Errorf("dry run did not count the application objects:\n%s", text)
	}
	if !strings.Contains(text, "a real run would refuse") || !strings.Contains(text, "replica 0 is operator-hold") {
		t.Errorf("dry run did not say why a real run would refuse:\n%s", text)
	}
}

// flakyKeyholder is a fleet where named replicas fail: one that does not
// answer at all, or one that refuses a particular push.
type flakyKeyholder struct {
	*fakeStateKeyholder
	silent    map[int]bool // State fails
	refuseNth map[int]int  // refuse this replica's Nth push (1-based)
	ignoreNth map[int]int  // answer this replica's Nth push with success, and keep what it had
	seen      map[int]int
}

func (f *flakyKeyholder) State(ctx context.Context, i int) (keyholder.State, error) {
	if f.silent[i] {
		return keyholder.State{}, errors.New("no route to replica")
	}
	return f.fakeStateKeyholder.State(ctx, i)
}

func (f *flakyKeyholder) Unseal(ctx context.Context, i int, payload []byte, intent string) (keyholder.State, error) {
	if f.seen == nil {
		f.seen = map[int]int{}
	}
	f.seen[i]++
	if n, ok := f.refuseNth[i]; ok && f.seen[i] == n {
		return keyholder.State{}, &keyholder.Refusal{Ordinal: i, Code: "", Reason: "tunnel dropped"}
	}
	if n, ok := f.ignoreNth[i]; ok && f.seen[i] == n {
		r := f.replica(i)
		return keyholder.State{Phase: r.phase, Generation: r.generation, Keys: copyKeys(r.keys), Boot: "b0"}, nil
	}
	return f.fakeStateKeyholder.Unseal(ctx, i, payload, intent)
}

// noSplit is the invariant a rotation's hand-over exists to keep: every key
// any serving replica writes under is a key every other serving replica holds.
// Broken, an object written through one replica fails integrity through the
// other.
func noSplit(t *testing.T, kh *fakeStateKeyholder) {
	t.Helper()
	for i, a := range kh.reps {
		for j, b := range kh.reps {
			if i == j || a.phase != "unsealed" || b.phase != "unsealed" {
				continue
			}
			for scope, ids := range a.keys {
				if len(ids) > 0 && !slices.Contains(b.keys[scope], ids[0]) {
					t.Errorf("replica %d writes %s under %s, which replica %d does not hold: reads through %d fail", i, scope, ids[0], j, j)
				}
			}
		}
	}
}

// The defect two reviewers reproduced: rotate made each new key active and
// pushed it one replica at a time, so a replica that did not answer was left
// unable to read what the others wrote from then on.
func TestARotationThatMissesAReplicaActivatesNothing(t *testing.T) {
	dir, meta, env, out := handOverInstance(t, "p80")
	scopedKeyring(t, dir, "p80", "demo", "alpha")
	base := &fakeStateKeyholder{phase: "unsealed"}
	// Both replicas serve the current keys before the rotation.
	if res := handOverKeys(context.Background(), env, meta, openerFor(base), liveKeyring(t, dir, "p80"), handOverOptions{}); !res.Complete() {
		t.Fatalf("guard: setup hand-over incomplete: %+v", res)
	}
	before := slices.Clone(base.replica(0).keys["app-demo-alpha"])
	flaky := &flakyKeyholder{fakeStateKeyholder: base, silent: map[int]bool{1: true}}

	rotateWith(t, env, "p80", flaky)
	noSplit(t, base)
	if got := base.replica(0).keys["app-demo-alpha"]; got[0] != before[0] {
		t.Errorf("replica 0 was made to write under the new key while replica 1 does not hold it: %v", got)
	}
	if !strings.Contains(out.String(), "in use on none") {
		t.Errorf("rotate did not say the new keys are not in use:\n%s", out.String())
	}
}

// If activation itself reaches only some replicas, every replica already
// holds both keys from the first step, so the mix reads everything.
func TestAPartialActivationLeavesEveryReplicaReadingEverything(t *testing.T) {
	dir, meta, env, out := handOverInstance(t, "p81")
	scopedKeyring(t, dir, "p81", "demo", "alpha", "beta")
	base := &fakeStateKeyholder{phase: "unsealed"}
	if res := handOverKeys(context.Background(), env, meta, openerFor(base), liveKeyring(t, dir, "p81"), handOverOptions{}); !res.Complete() {
		t.Fatalf("guard: setup hand-over incomplete: %+v", res)
	}
	// Replica 1 takes the staged keys, then drops the activation push.
	flaky := &flakyKeyholder{fakeStateKeyholder: base, refuseNth: map[int]int{1: 2}}

	rotateWith(t, env, "p81", flaky)
	noSplit(t, base)
	after := liveKeyring(t, dir, "p81")
	for _, sc := range after.Scopes() {
		active := sc.Keyring().KEKs()[0].ID.String()
		if base.replica(0).keys[sc.Name][0] != active {
			t.Errorf("replica 0 is not writing %s under the new key", sc.Name)
		}
		if !slices.Contains(base.replica(1).keys[sc.Name], active) {
			t.Errorf("replica 1 does not hold %s's new key, though it took the staged keys", sc.Name)
		}
	}
	if !strings.Contains(out.String(), "hold them without using them yet") {
		t.Errorf("rotate did not describe the partial activation:\n%s", out.String())
	}
}

// An object the master wrote under a path a scope later claimed — a
// `storage cp` into app/, ahead of the `farcast run` that minted the scope —
// is named only by the master's name key. Rekey used to route each object by
// its key, sent this one to the scope, found nothing, and stopped the sweep.
func TestRekeyRewritesAMasterObjectUnderAScopesPrefix(t *testing.T) {
	env, out, dir, f, before := rekeyInstance(t)
	ctx := context.Background()
	master, err := datasphere.NewStore(f, testBucket, before)
	if err != nil {
		t.Fatal(err)
	}
	const legacy = "app/demo/alpha/legacy"
	if err := master.Write(ctx, legacy, []byte("written by the operator before alpha existed")); err != nil {
		t.Fatal(err)
	}
	kh := &fakeStateKeyholder{phase: "unsealed"}
	if err := (&keyRotateCommand{assumeYes: true, newKeyholder: openerFor(kh)}).Run(ctx, env, []string{"prod"}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if err := (&keyRekeyCommand{assumeYes: true, newKeyholder: openerFor(kh)}).Run(ctx, env, []string{"prod"}); err != nil {
		t.Fatalf("rekey stopped on an object a scope's prefix covers: %v", err)
	}
	if !strings.Contains(out.String(), "rewritten: 3") {
		t.Errorf("rekey did not rewrite the master's object as well as both applications':\n%s", out.String())
	}
	after, err := datasphere.NewStore(f, testBucket, liveKeyring(t, dir, "prod"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := after.Read(ctx, legacy); err != nil || !strings.HasPrefix(string(got), "written by the operator") {
		t.Errorf("the master's object no longer reads after rekey: %q, %v", got, err)
	}
	if _, err := master.Read(ctx, legacy); !errors.Is(err, datasphere.ErrUnknownKey) {
		t.Errorf("the pre-rotation master keyring still opens the rekeyed object: %v", err)
	}
}

// The generation cannot say whether a replica holds the current keys: anything
// holding a bundle can push one at whatever generation it likes. What a lost
// keeper's re-seed leaves behind is a replica serving keys the operator's
// keyring has since rotated past — and 'storage state' is where that shows.
func TestStorageStateFlagsAReplicaServingOtherKeys(t *testing.T) {
	dir, meta, env, out := handOverInstance(t, "p82")
	before := scopedKeyring(t, dir, "p82", "demo", "alpha")
	kh := &fakeStateKeyholder{phase: "unsealed"}
	if res := handOverKeys(context.Background(), env, meta, openerFor(kh), before, handOverOptions{}); !res.Complete() {
		t.Fatalf("guard: %+v", res)
	}
	// Rotated on this machine; replica 1 then re-seeded with the old keys.
	if err := (&keyRotateCommand{assumeYes: true, newKeyholder: openerFor(kh)}).Run(context.Background(), env, []string{"p82"}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	kh.replica(1).keys = heldKeys(before)
	out.out.Reset()
	out.err.Reset()

	if err := (&storageStateCommand{newKeyholder: openerFor(kh)}).Run(context.Background(), env, []string{"p82"}); err != nil {
		t.Fatalf("state: %v", err)
	}
	text := out.String()
	if strings.Count(text, "KEYS DIFFER FROM THIS MACHINE'S KEYRING") != 1 {
		t.Errorf("want exactly replica 1 flagged:\n%s", text)
	}
	if !strings.Contains(text, "lacks app-demo-alpha's current key") {
		t.Errorf("the flag does not say how the replica differs:\n%s", text)
	}
	if !strings.Contains(text, "lost or revoked") || !strings.Contains(text, "farcast storage unseal p82") {
		t.Errorf("the flag does not say what it can mean or what fixes it:\n%s", text)
	}
}

// runWith deploys the two-application manifest against a keyholder fake.
func runWith(t *testing.T, name string, kh sealStateClient, keepers ...config.Keeper) string {
	t.Helper()
	dir := config.Dir(t.TempDir())
	meta := runnableInstance(t, dir, name)
	meta.Keyholder = &config.Keyholder{Deployed: true, Replicas: 2}
	meta.Keepers = keepers
	if err := dir.SaveInstanceMetadata(name, meta); err != nil {
		t.Fatal(err)
	}
	mintKeyring(t, dir, name)
	env, _, errBuf := testEnvBoth(dir, output.ModeHuman)
	c := runCmd(newFakeRun(twoAppManifest))
	c.newKeyholder = func(context.Context, *Env, string) (sealStateClient, func(), error) { return kh, func() {}, nil }
	if err := c.Run(context.Background(), env, []string{name, "github.com/example/my-platform"}); err != nil {
		t.Fatal(err)
	}
	return errBuf.String()
}

// Adding an application switches the keeper fleet off until it is re-enrolled
// — correctly, and it has to say so.
func TestRunNamesTheKeepersANewApplicationDisables(t *testing.T) {
	out := runWith(t, "p83", &fakeStateKeyholder{phase: "unsealed"},
		config.Keeper{Device: "study-desktop"}, config.Keeper{Device: "lost-laptop", Revoked: true})
	if !strings.Contains(out, "farcast keeper enroll p83 study-desktop") {
		t.Errorf("an active keeper was not named:\n%s", out)
	}
	if strings.Contains(out, "lost-laptop") {
		t.Errorf("a revoked keeper was offered re-enrolment:\n%s", out)
	}
	if out := runWith(t, "p84", &fakeStateKeyholder{phase: "unsealed"}); strings.Contains(out, "farcast keeper enroll") {
		t.Errorf("re-enrolment was advised with no keepers enrolled:\n%s", out)
	}
}

// A hand-over that reached one replica of two is not a success, and run must
// not print the line that says it was.
func TestRunReportsAPartialHandOverAsPartial(t *testing.T) {
	kh := &flakyKeyholder{fakeStateKeyholder: &fakeStateKeyholder{phase: "unsealed"}, refuseNth: map[int]int{1: 1}}
	out := runWith(t, "p85", kh)
	if strings.Contains(out, "The keyholder now holds") {
		t.Errorf("a partial hand-over was reported as complete:\n%s", out)
	}
	if !strings.Contains(out, "on 1 of 2 replicas") || !strings.Contains(out, "farcast storage state p85") {
		t.Errorf("the partial hand-over was not described, or not what to do:\n%s", out)
	}
}

// ---------------------------------------------------------------- the second review

// rotateWith runs 'storage key rotate' against a fleet that may not let it
// finish. A rotation whose keys are not in use fails, by design; anything
// else that fails it is a test failure.
func rotateWith(t *testing.T, env *Env, instance string, kh sealStateClient) {
	t.Helper()
	err := (&keyRotateCommand{assumeYes: true, newKeyholder: openerFor(kh)}).Run(context.Background(), env, []string{instance})
	var unfinished rotationUnfinished
	if err != nil && !errors.As(err, &unfinished) {
		t.Fatalf("rotate: %v", err)
	}
}

// mustRotate runs a rotation that has to finish.
func mustRotate(t *testing.T, env *Env, instance string, kh sealStateClient) {
	t.Helper()
	if err := (&keyRotateCommand{assumeYes: true, newKeyholder: openerFor(kh)}).Run(context.Background(), env, []string{instance}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
}

// servingFleet is two replicas serving this machine's keyring.
func servingFleet(t *testing.T, env *Env, meta *config.InstanceMetadata, dir config.Dir) *fakeStateKeyholder {
	t.Helper()
	kh := &fakeStateKeyholder{phase: "unsealed"}
	if res := handOverKeys(context.Background(), env, meta, openerFor(kh), liveKeyring(t, dir, meta.Name), handOverOptions{}); !res.Complete() {
		t.Fatalf("guard: setup hand-over incomplete: %+v", res)
	}
	return kh
}

// writesUnderHeldKeys is the other half of the invariant: this machine writes
// to storage too ('secret set', 'storage cp'), under whatever its keyring makes
// active, so that key must be one every serving replica holds.
func writesUnderHeldKeys(t *testing.T, dir config.Dir, instance string, kh *fakeStateKeyholder) {
	t.Helper()
	for _, sc := range liveKeyring(t, dir, instance).Scopes() {
		if sc.Zeroed() {
			t.Fatalf("this machine's keyring holds wiped key material for %s", sc.Name)
		}
		active := sc.Keyring().KEKs()[0].ID.String()
		for i, r := range kh.reps {
			// A replica without the whole scope refuses that application's
			// requests rather than misreading them — a scope not handed over
			// yet, which is not this invariant.
			ids, serves := r.keys[sc.Name]
			if r.phase == "unsealed" && serves && !slices.Contains(ids, active) {
				t.Errorf("this machine writes %s under %s, which replica %d does not hold: reads through %d fail", sc.Name, active, i, i)
			}
		}
	}
}

// A bundle shares its scopes' key bytes, and wiping it after a push wiped the
// keyring it was built from. A hand-over in two pushes then sent zeroed keys
// the second time, and rotate saved them to disk — destroying every
// application's keys on the operator's own machine. The fake refuses wiped
// material; this pins what is saved.
func TestATwoStepHandOverNeverWipesTheKeysItStillNeeds(t *testing.T) {
	env, _, dir, f, before := rekeyInstance(t)
	rotateWith(t, env, "prod", &fakeStateKeyholder{phase: "unsealed"})
	after := liveKeyring(t, dir, "prod")
	for i, sc := range after.Scopes() {
		if sc.Zeroed() {
			t.Fatalf("rotate saved wiped key material for %s", sc.Name)
		}
		store, err := datasphere.NewStore(f, testBucket, sc.Keyring())
		if err != nil {
			t.Fatal(err)
		}
		if got, err := store.Read(context.Background(), sc.Prefix+"data"); err != nil || string(got) != "written by "+before.Scopes()[i].Name {
			t.Errorf("the saved keyring no longer reads %s: %q, %v", sc.Prefix+"data", got, err)
		}
	}
}

// Finding E. rotate used to save the keyring with each new key active before
// any replica held it, so this machine's own writes used a key a replica that
// missed the hand-over could not read.
func TestAfterAnUnfinishedRotationThisMachineWritesUnderAKeyEveryReplicaHolds(t *testing.T) {
	dir, meta, env, _ := handOverInstance(t, "p90")
	scopedKeyring(t, dir, "p90", "demo", "alpha", "beta")
	base := servingFleet(t, env, meta, dir)

	rotateWith(t, env, "p90", &flakyKeyholder{fakeStateKeyholder: base, silent: map[int]bool{1: true}})
	noSplit(t, base)
	writesUnderHeldKeys(t, dir, "p90", base)
}

// Finding A. A second rotation after an unfinished one used to make the
// FIRST rotation's key active — one a replica had never received — and still
// reported "in use on none".
func TestASecondRotationNeverActivatesAKeyAReplicaMissed(t *testing.T) {
	dir, meta, env, out := handOverInstance(t, "p91")
	scopedKeyring(t, dir, "p91", "demo", "alpha")
	base := servingFleet(t, env, meta, dir)

	rotateWith(t, env, "p91", &flakyKeyholder{fakeStateKeyholder: base, silent: map[int]bool{1: true}})
	// Replica 1 answers this time, and drops the first push it is sent.
	out.out.Reset()
	rotateWith(t, env, "p91", &flakyKeyholder{fakeStateKeyholder: base, refuseNth: map[int]int{1: 1}})
	noSplit(t, base)
	writesUnderHeldKeys(t, dir, "p91", base)
	if !strings.Contains(out.String(), "in use on none") {
		t.Errorf("the second rotation did not say its keys are unused:\n%s", out.String())
	}
	for i := range 2 {
		if got := base.replica(i).keys["app-demo-alpha"][0]; got != base.replica(0).keys["app-demo-alpha"][0] {
			t.Errorf("replica %d writes under %s; the replicas disagree", i, got)
		}
	}

	// And once every replica answers, a rotation finishes: every replica, and
	// this machine, write under one new key.
	rotateWith(t, env, "p91", base)
	noSplit(t, base)
	writesUnderHeldKeys(t, dir, "p91", base)
	want := heldKeys(liveKeyring(t, dir, "p91"))
	for i := range 2 {
		if !sameKeys(base.replica(i).keys, want) {
			t.Errorf("after a finished rotation replica %d holds %v, want %v", i, base.replica(i).keys, want)
		}
	}
}

// Closure item 15, findings B and J. 'storage unseal' is what every message
// tells the operator to run next, and it pushed this machine's keyring in one
// step — so after an unfinished rotation it made the new keys active on the
// replicas it reached first.
func TestUnsealAfterAnUnfinishedRotationNeverSplitsTheReplicas(t *testing.T) {
	dir, meta, env, _ := handOverInstance(t, "p92")
	scopedKeyring(t, dir, "p92", "demo", "alpha")
	base := servingFleet(t, env, meta, dir)
	rotateWith(t, env, "p92", &flakyKeyholder{fakeStateKeyholder: base, silent: map[int]bool{1: true}})

	err := (&storageUnsealCommand{newKeyholder: openerFor(&flakyKeyholder{fakeStateKeyholder: base, refuseNth: map[int]int{1: 1}})}).
		Run(context.Background(), env, []string{"p92"})
	if err == nil {
		t.Fatal("an unseal one replica refused was reported as success")
	}
	if strings.Contains(err.Error(), "no key material") {
		t.Errorf("unseal says the refusing replica holds nothing, but it is serving: %v", err)
	}
	noSplit(t, base)
	writesUnderHeldKeys(t, dir, "p92", base)
}

// The same, from a fleet where one replica was put back on older keys — a
// full restart and a keeper enrolled before the rotation, the limit ADR 0008
// states. Unseal must bring it back without first having the other use a key
// it lacks.
func TestUnsealHoldsANewKeyBackFromAReplicaThatLacksIt(t *testing.T) {
	dir, meta, env, _ := handOverInstance(t, "p93")
	before := scopedKeyring(t, dir, "p93", "demo", "alpha")
	base := servingFleet(t, env, meta, dir)
	rotateWith(t, env, "p93", base)
	base.replica(1).keys = heldKeys(before)

	err := (&storageUnsealCommand{newKeyholder: openerFor(&flakyKeyholder{fakeStateKeyholder: base, refuseNth: map[int]int{1: 1}})}).
		Run(context.Background(), env, []string{"p93"})
	if err == nil {
		t.Fatal("an unseal that could not reach every replica was reported as success")
	}
	noSplit(t, base)

	// And with every replica answering, it finishes.
	if err := (&storageUnsealCommand{newKeyholder: openerFor(base)}).Run(context.Background(), env, []string{"p93"}); err != nil {
		t.Fatalf("unseal: %v", err)
	}
	want := heldKeys(liveKeyring(t, dir, "p93"))
	for i := range 2 {
		if !sameKeys(base.replica(i).keys, want) {
			t.Errorf("replica %d holds %v after unseal, want %v", i, base.replica(i).keys, want)
		}
	}
}

// Finding D. A replica can restart between the two pushes and be re-seeded
// with older keys. Activation used to follow without asking again.
func TestActivationAsksAgainBeforeUsingANewKey(t *testing.T) {
	dir, meta, env, out := handOverInstance(t, "p94")
	before := scopedKeyring(t, dir, "p94", "demo", "alpha")
	base := servingFleet(t, env, meta, dir)

	rotateWith(t, env, "p94", &reseededBetween{fakeStateKeyholder: base, old: heldKeys(before)})
	noSplit(t, base)
	writesUnderHeldKeys(t, dir, "p94", base)
	if !strings.Contains(out.String(), "held and unused everywhere") || !strings.Contains(out.String(), "no longer held") {
		t.Errorf("rotate did not say why it stopped:\n%s", out.String())
	}
}

// reseededBetween is a fleet in which replica 1, once it takes its first push,
// restarts and is re-seeded with older keys.
type reseededBetween struct {
	*fakeStateKeyholder
	old  map[string][]string
	done bool
}

func (r *reseededBetween) Unseal(ctx context.Context, i int, payload []byte, intent string) (keyholder.State, error) {
	st, err := r.fakeStateKeyholder.Unseal(ctx, i, payload, intent)
	if err == nil && i == 1 && !r.done {
		r.done = true
		r.replica(1).keys, r.replica(1).generation = copyKeys(r.old), 1
	}
	return st, err
}

// N10. A replica that answers success and keeps what it had is not holding
// the new key. Comparing only the active key — which a held push leaves where
// it was — counted it as loaded and went on to activate.
func TestAReplicaThatIgnoresTheHeldKeysStopsActivation(t *testing.T) {
	dir, meta, env, out := handOverInstance(t, "p95")
	scopedKeyring(t, dir, "p95", "demo", "alpha")
	base := servingFleet(t, env, meta, dir)

	rotateWith(t, env, "p95", &flakyKeyholder{fakeStateKeyholder: base, ignoreNth: map[int]int{1: 1}})
	noSplit(t, base)
	writesUnderHeldKeys(t, dir, "p95", base)
	if !strings.Contains(out.String(), "in use on none") {
		t.Errorf("rotate activated keys a replica did not hold:\n%s", out.String())
	}
	entries, err := keyholder.ReadLedger(dir.InstanceUnsealLedgerPath("p95"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(entries, func(e keyholder.LedgerEntry) bool { return e.Ordinal == 1 && e.Result == "not-installed" }) {
		t.Errorf("the ignored push is not in the ledger as not-installed: %+v", entries)
	}
}

// Finding H. Unseal used to clear every replica's generation and push this
// machine's keyring whatever it held — so a machine whose keyring predates a
// rotation took the new keys away from every replica.
func TestUnsealRefusesAKeyringBehindTheReplicas(t *testing.T) {
	dir, meta, env, _ := handOverInstance(t, "p96")
	before := scopedKeyring(t, dir, "p96", "demo", "alpha")
	base := servingFleet(t, env, meta, dir)
	rotateWith(t, env, "p96", base)
	serving := copyKeys(base.replica(0).keys)
	saveKeyring(t, dir, "p96", before) // a copy from before the rotation
	pushes := base.pushes

	err := (&storageUnsealCommand{newKeyholder: openerFor(base)}).Run(context.Background(), env, []string{"p96"})
	if err == nil || !strings.Contains(err.Error(), "behind") || !strings.Contains(err.Error(), "farcast storage key import") {
		t.Fatalf("unseal = %v; want a refusal saying this keyring is behind and how to fix it", err)
	}
	if base.pushes != pushes {
		t.Errorf("unseal pushed %d time(s) from a keyring behind the replicas", base.pushes-pushes)
	}
	for i := range 2 {
		if !sameKeys(base.replica(i).keys, serving) {
			t.Errorf("replica %d now holds %v; it served %v", i, base.replica(i).keys, serving)
		}
	}
	// A deploy hands over the same way, and refuses the same way.
	res := handOverKeys(context.Background(), env, meta, openerFor(base), before, handOverOptions{})
	if res.Problem == "" || base.pushes != pushes {
		t.Errorf("a hand-over from a keyring behind the replicas: %+v", res)
	}
}

// An import merges, and a merge keeps this machine's active key: importing an
// export taken after a rotation adds the new key but leaves the old one in
// use. Pushed, that moves every replica back onto a key a lost keeper holds.
func TestUnsealRefusesToMoveReplicasOntoAnOlderKey(t *testing.T) {
	dir, meta, env, _ := handOverInstance(t, "p97")
	before := scopedKeyring(t, dir, "p97", "demo", "alpha")
	base := servingFleet(t, env, meta, dir)
	rotateWith(t, env, "p97", base)
	rotated := liveKeyring(t, dir, "p97")
	serving := copyKeys(base.replica(0).keys)

	merged, err := backdated(t, before, "2020-01-01T00:00:00Z").Merge(rotated)
	if err != nil {
		t.Fatal(err)
	}
	if got := heldKeys(merged)["app-demo-alpha"][0]; got != heldKeys(before)["app-demo-alpha"][0] {
		t.Fatalf("guard: the merged keyring makes %s active; this test needs the pre-rotation key", got)
	}
	saveKeyring(t, dir, "p97", merged)

	err = (&storageUnsealCommand{newKeyholder: openerFor(base)}).Run(context.Background(), env, []string{"p97"})
	if err == nil || !strings.Contains(err.Error(), "older key") || !strings.Contains(err.Error(), "farcast storage key rotate p97") {
		t.Fatalf("unseal = %v; want a refusal naming the rotation that fixes it", err)
	}
	for i := range 2 {
		if !sameKeys(base.replica(i).keys, serving) {
			t.Errorf("replica %d now holds %v; it served %v", i, base.replica(i).keys, serving)
		}
	}
	// And 'storage state' says which keyring is behind.
	if err := (&storageStateCommand{newKeyholder: openerFor(base)}).Run(context.Background(), env, []string{"p97"}); err != nil {
		t.Fatal(err)
	}
}

// backdated is a keyring whose every key was minted at the given time, so a
// test can say which of two keys is older — keys minted in one test share a
// second.
func backdated(t *testing.T, k datasphere.Keyring, when string) datasphere.Keyring {
	t.Helper()
	data, err := k.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?m)^(\s*created:\s*).*$`)
	out, err := datasphere.ParseKeyring(re.ReplaceAll(data, []byte("${1}"+when)))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Finding G. 'storage state' said objects written under the current keys fail
// through a replica that holds every key and only writes under the older one —
// the harmless half-finished activation rotate itself describes as reading
// everything.
func TestStorageStateDescribesAHalfFinishedActivationAsHarmless(t *testing.T) {
	dir, meta, env, out := handOverInstance(t, "p98")
	scopedKeyring(t, dir, "p98", "demo", "alpha")
	base := servingFleet(t, env, meta, dir)
	rotateWith(t, env, "p98", &flakyKeyholder{fakeStateKeyholder: base, refuseNth: map[int]int{1: 2}})
	out.out.Reset()
	out.err.Reset()

	if err := (&storageStateCommand{newKeyholder: openerFor(base)}).Run(context.Background(), env, []string{"p98"}); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if !strings.Contains(text, "writes under an older one") || !strings.Contains(text, "still reads everything") {
		t.Errorf("state did not describe the half-finished activation:\n%s", text)
	}
	if strings.Contains(text, "fail through") {
		t.Errorf("state says reads fail through a replica that holds every key:\n%s", text)
	}
}

// N14. The gate wants every replica holding exactly this machine's keys — the
// same active key AND the same set. A replica writing under the current key but
// missing an older one cannot read what rekey has not moved yet.
func TestRekeyWantsEveryKeyNotOnlyTheActiveOne(t *testing.T) {
	env, _, dir, _, _ := rekeyInstance(t)
	kh := &fakeStateKeyholder{phase: "unsealed"}
	rotateWith(t, env, "prod", kh)
	for name, ids := range heldKeys(liveKeyring(t, dir, "prod")) {
		kh.replica(1).keys[name] = ids[:1] // the current key and nothing else
	}
	err := (&keyRekeyCommand{assumeYes: true, newKeyholder: openerFor(kh)}).Run(context.Background(), env, []string{"prod"})
	if err == nil || !strings.Contains(err.Error(), "replica 1 lacks a key of app-demo") {
		t.Fatalf("rekey = %v; want a refusal: replica 1 lacks the key existing objects are under", err)
	}
}

// Finding I. A prefix inside a scope used to skip the instance's own key
// space, so an object the master wrote there before the scope existed was
// passed over, uncounted, under the retired key.
func TestRekeyOfAScopesPrefixRewritesTheMastersObjectThere(t *testing.T) {
	env, out, dir, f, before := rekeyInstance(t)
	ctx := context.Background()
	master, err := datasphere.NewStore(f, testBucket, before)
	if err != nil {
		t.Fatal(err)
	}
	const legacy = "app/demo/alpha/legacy"
	if err := master.Write(ctx, legacy, []byte("written by the operator before alpha existed")); err != nil {
		t.Fatal(err)
	}
	kh := &fakeStateKeyholder{phase: "unsealed"}
	rotateWith(t, env, "prod", kh)
	if err := (&keyRekeyCommand{assumeYes: true, newKeyholder: openerFor(kh)}).Run(ctx, env, []string{"prod:app/demo/alpha/"}); err != nil {
		t.Fatalf("rekey: %v", err)
	}
	if !strings.Contains(out.String(), "rewritten: 2") {
		t.Errorf("rekey of alpha's prefix did not rewrite alpha's object and the master's:\n%s", out.String())
	}
	if _, err := master.Read(ctx, legacy); !errors.Is(err, datasphere.ErrUnknownKey) {
		t.Errorf("the pre-rotation master keyring still opens the object under alpha's prefix: %v", err)
	}
	current, err := datasphere.NewStore(f, testBucket, liveKeyring(t, dir, "prod"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := current.Read(ctx, legacy); err != nil {
		t.Errorf("the master's object no longer reads: %v", err)
	}
}

// oldImage is a keyholder from before key reporting: it says which scopes it
// holds and nothing about their keys.
type oldImage struct{ *fakeStateKeyholder }

func (o *oldImage) strip(st keyholder.State) keyholder.State {
	if st.Phase == "unsealed" && len(st.Keys) > 0 {
		st.Scopes = slices.Sorted(maps.Keys(st.Keys))
	}
	st.Keys = nil
	return st
}

func (o *oldImage) State(ctx context.Context, i int) (keyholder.State, error) {
	st, err := o.fakeStateKeyholder.State(ctx, i)
	return o.strip(st), err
}

func (o *oldImage) Unseal(ctx context.Context, i int, payload []byte, intent string) (keyholder.State, error) {
	st, err := o.fakeStateKeyholder.Unseal(ctx, i, payload, intent)
	return o.strip(st), err
}

// Closure item 6. A CLI newer than the keyholder it talks to found every
// replica "not installed", said the rest "hold no key material" while they
// served, and never named the command that fixes it.
func TestAKeyholderOlderThanTheCLIIsNamedAsSuch(t *testing.T) {
	t.Run("serving: nothing is pushed", func(t *testing.T) {
		dir, meta, env, _ := handOverInstance(t, "p99")
		scopedKeyring(t, dir, "p99", "demo", "alpha")
		base := servingFleet(t, env, meta, dir)
		pushes := base.pushes
		old := &oldImage{base}

		err := (&storageUnsealCommand{newKeyholder: openerFor(old)}).Run(context.Background(), env, []string{"p99"})
		if err == nil || !strings.Contains(err.Error(), "farcast storage deploy p99") {
			t.Fatalf("unseal = %v; want it to name the deploy that updates the keyholder", err)
		}
		if base.pushes != pushes {
			t.Error("unseal pushed to replicas whose keys it cannot check")
		}
	})
	t.Run("sealed: unsealed but unverified", func(t *testing.T) {
		dir, _, env, out := handOverInstance(t, "p100")
		scopedKeyring(t, dir, "p100", "demo", "alpha")
		old := &oldImage{&fakeStateKeyholder{phase: "restart-sealed"}}

		err := (&storageUnsealCommand{newKeyholder: openerFor(old)}).Run(context.Background(), env, []string{"p100"})
		if err == nil {
			t.Fatal("an unseal whose keys could not be checked was reported as success")
		}
		if strings.Contains(err.Error(), "no key material") {
			t.Errorf("unseal says replicas hold nothing, but they are unsealed: %v", err)
		}
		if !strings.Contains(out.String(), "farcast storage deploy p100") {
			t.Errorf("unseal did not name the deploy that updates the keyholder:\n%s", out.String())
		}
		entries, lerr := keyholder.ReadLedger(dir.InstanceUnsealLedgerPath("p100"))
		if lerr != nil {
			t.Fatal(lerr)
		}
		for _, e := range entries {
			if e.Result != "unverified" {
				t.Errorf("ledger entry %+v; want unverified", e)
			}
		}
	})
	t.Run("state and rekey name it too", func(t *testing.T) {
		env, out, dir, _, _ := rekeyInstance(t)
		kh := &fakeStateKeyholder{phase: "unsealed"}
		meta, _ := dir.LoadInstanceMetadata("prod")
		if res := handOverKeys(context.Background(), env, meta, openerFor(kh), liveKeyring(t, dir, "prod"), handOverOptions{}); !res.Complete() {
			t.Fatalf("guard: %+v", res)
		}
		old := &oldImage{kh}
		if err := (&storageStateCommand{newKeyholder: openerFor(old)}).Run(context.Background(), env, []string{"prod"}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "older than this CLI") || strings.Contains(out.String(), "KEYS DIFFER") {
			t.Errorf("state did not say the keyholder is older than the CLI:\n%s", out.String())
		}
		err := (&keyRekeyCommand{assumeYes: true, newKeyholder: openerFor(old)}).Run(context.Background(), env, []string{"prod"})
		if err == nil || !strings.Contains(err.Error(), "farcast storage deploy prod") {
			t.Errorf("rekey = %v; want it to name the deploy", err)
		}
	})
}

// While a new key is held, the replicas keep writing under a key they already
// use — not merely the next one in this machine's list, which after an import
// is older than the one they use. Rotating from such a keyring is the remedy
// unseal names for it; done naively, its first push would move every replica
// back onto a key a lost keeper may hold, and leave them there if the second
// push failed.
func TestAHeldPushKeepsTheNewestKeyEveryReplicaHolds(t *testing.T) {
	dir, meta, env, _ := handOverInstance(t, "p101")
	before := scopedKeyring(t, dir, "p101", "demo", "alpha")
	base := servingFleet(t, env, meta, dir)
	rotateWith(t, env, "p101", base)
	using := base.replica(0).keys["app-demo-alpha"][0]
	merged, err := backdated(t, before, "2020-01-01T00:00:00Z").Merge(liveKeyring(t, dir, "p101"))
	if err != nil {
		t.Fatal(err)
	}
	saveKeyring(t, dir, "p101", merged)

	// Replica 1 drops the push that would make the newest key active.
	rotateWith(t, env, "p101", &flakyKeyholder{fakeStateKeyholder: base, refuseNth: map[int]int{1: 2}})
	noSplit(t, base)
	if got := base.replica(1).keys["app-demo-alpha"][0]; got != using {
		t.Errorf("replica 1 writes under %s; it used %s, and nothing may move it onto an older key", got, using)
	}
}

// A rotation's new keys go over held first even when no serving replica
// answered: one that did not answer may still be serving, and cannot hold a
// key minted a moment ago. Without that, a fleet of one sealed replica and one
// unreachable one had the new keys activated — on this machine too — beside a
// replica that never saw them.
func TestARotationNeverActivatesBesideAReplicaItCannotSee(t *testing.T) {
	dir, meta, env, out := handOverInstance(t, "p102")
	scopedKeyring(t, dir, "p102", "demo", "alpha")
	base := servingFleet(t, env, meta, dir)
	base.replica(0).phase, base.replica(0).keys = "restart-sealed", nil

	rotateWith(t, env, "p102", &flakyKeyholder{fakeStateKeyholder: base, silent: map[int]bool{1: true}})
	writesUnderHeldKeys(t, dir, "p102", base)
	if !strings.Contains(out.String(), "in use on none") {
		t.Errorf("rotate activated keys beside a replica it could not see:\n%s", out.String())
	}
}

// A replica serving a scope this keyring lacks — an application another
// machine deployed — would lose it to a push from here.
func TestAHandOverRefusesAKeyringMissingAScopeAReplicaServes(t *testing.T) {
	dir, meta, env, _ := handOverInstance(t, "p103")
	alphaOnly := scopedKeyring(t, dir, "p103", "demo", "alpha")
	beta, err := datasphere.NewAppScope("demo", "beta")
	if err != nil {
		t.Fatal(err)
	}
	both, err := alphaOnly.AddScope(beta)
	if err != nil {
		t.Fatal(err)
	}
	saveKeyring(t, dir, "p103", both)
	base := servingFleet(t, env, meta, dir)
	saveKeyring(t, dir, "p103", alphaOnly)
	pushes := base.pushes

	err = (&storageUnsealCommand{newKeyholder: openerFor(base)}).Run(context.Background(), env, []string{"p103"})
	if err == nil || !strings.Contains(err.Error(), "serves scope app-demo-beta") {
		t.Fatalf("unseal = %v; want a refusal naming the scope this keyring lacks", err)
	}
	if base.pushes != pushes {
		t.Error("unseal pushed a keyring that would take an application's scope away")
	}
}

// A replica that refused the held keys and then stops answering may still be
// serving without them. Its refusal alone must stop activation: asking again
// cannot see it.
func TestARefusedHeldPushStopsActivationEvenIfTheReplicaThenGoesQuiet(t *testing.T) {
	dir, meta, env, _ := handOverInstance(t, "p104")
	scopedKeyring(t, dir, "p104", "demo", "alpha")
	base := servingFleet(t, env, meta, dir)

	rotateWith(t, env, "p104", &refusesThenSilent{flakyKeyholder: &flakyKeyholder{fakeStateKeyholder: base, refuseNth: map[int]int{1: 1}}})
	noSplit(t, base)
	writesUnderHeldKeys(t, dir, "p104", base)
}

// refusesThenSilent stops answering State for a replica once it has refused a
// push.
type refusesThenSilent struct{ *flakyKeyholder }

func (r *refusesThenSilent) State(ctx context.Context, i int) (keyholder.State, error) {
	if n, ok := r.refuseNth[i]; ok && r.seen[i] >= n {
		return keyholder.State{}, errors.New("no route to replica")
	}
	return r.flakyKeyholder.State(ctx, i)
}

// An unseal that gave every replica the keys to hold, and then found one no
// longer held them, has not finished — even though every push it made landed.
func TestUnsealThatCouldNotActivateIsNotSuccess(t *testing.T) {
	dir, meta, env, _ := handOverInstance(t, "p105")
	before := scopedKeyring(t, dir, "p105", "demo", "alpha")
	base := servingFleet(t, env, meta, dir)
	rotateWith(t, env, "p105", base)
	base.replica(1).keys = heldKeys(before)

	err := (&storageUnsealCommand{newKeyholder: openerFor(&reseededBetween{fakeStateKeyholder: base, old: heldKeys(before)})}).
		Run(context.Background(), env, []string{"p105"})
	if err == nil || !strings.Contains(err.Error(), "none was told to write under the newest yet") {
		t.Fatalf("unseal = %v; want it to say the replicas do not use this machine's newest keys yet", err)
	}
	noSplit(t, base)
}

// When a hand-over refuses because this keyring is behind the replicas, an
// unseal now would refuse for the same reason, and re-running the deploy once
// it is fixed hands nothing over — the scope exists by then. So run says what
// to fix, that the unseal comes after it, and what applications see meanwhile.
func TestRunSaysWhatHandsTheScopeOverOnceTheKeyringIsFixed(t *testing.T) {
	kh := &fakeStateKeyholder{phase: "unsealed"}
	for i := range 2 {
		kh.replica(i).keys = map[string][]string{"app-elsewhere-other": {"00000000000000aa"}}
	}
	out := runWith(t, "p106", kh)
	if !strings.Contains(out, "behind") || !strings.Contains(out, "farcast storage key import") {
		t.Fatalf("run did not say why the scope was not handed over, or what fixes it:\n%s", out)
	}
	if !strings.Contains(out, "Once that is fixed, 'farcast storage unseal p106' hands it over") {
		t.Errorf("run did not say what hands the scope over after the fix:\n%s", out)
	}
	if !strings.Contains(out, "ErrPermission") {
		t.Errorf("run named the wrong error for a serving replica without the scope:\n%s", out)
	}
}

// ---------------------------------------------------------------- the third review

// backdatedInstance is handOverInstance with a keyring minted long ago, so
// every key a rotation mints in the test is newer than it — as it is on any
// real instance, and as 'which key is newer' needs it to be.
func backdatedInstance(t *testing.T, name string, apps ...string) (config.Dir, *config.InstanceMetadata, *Env, *operatorSees, datasphere.Keyring) {
	t.Helper()
	dir, meta, env, out := handOverInstance(t, name)
	k := backdated(t, scopedKeyring(t, dir, name, "demo", apps...), "2020-01-01T00:00:00Z")
	saveKeyring(t, dir, name, k)
	return dir, meta, env, out, k
}

// Review finding 0. The held push used to keep the NEWEST key every answering
// replica held in use — and after an unfinished rotation that is the key the
// rotation gave to some replicas only. A second rotation with a replica still
// silent put it in use, beside the replica that never received it.
func TestARotationNeverPutsAnUnfinishedRotationsKeyInUse(t *testing.T) {
	dir, meta, env, out, _ := backdatedInstance(t, "p110", "alpha")
	base := servingFleet(t, env, meta, dir)
	using := base.replica(1).keys["app-demo-alpha"][0]

	silent := &flakyKeyholder{fakeStateKeyholder: base, silent: map[int]bool{1: true}}
	rotateWith(t, env, "p110", silent)
	rotateWith(t, env, "p110", silent)
	noSplit(t, base)
	writesUnderHeldKeys(t, dir, "p110", base)
	for i := range 2 {
		if got := base.replica(i).keys["app-demo-alpha"][0]; got != using {
			t.Errorf("replica %d writes under %s; nothing was confirmed on every replica but %s", i, got, using)
		}
	}
	if !strings.Contains(out.String(), "in use on none") {
		t.Errorf("rotate did not say its keys are unused:\n%s", out.String())
	}
	// And once replica 1 answers, a rotation finishes, from the same keyring.
	mustRotate(t, env, "p110", base)
	noSplit(t, base)
	writesUnderHeldKeys(t, dir, "p110", base)
}

// Review finding 6. The keyring rotate saved and the keyring the replicas were
// handed could disagree on which key is in use, leaving this machine "behind"
// its own fleet — and every later unseal from it refused.
func TestThisMachinesKeyringNeverFallsBehindItsOwnFleet(t *testing.T) {
	dir, meta, env, _, _ := backdatedInstance(t, "p111", "alpha")
	base := servingFleet(t, env, meta, dir)
	rotateWith(t, env, "p111", &flakyKeyholder{fakeStateKeyholder: base, silent: map[int]bool{1: true}})
	if err := (&storageUnsealCommand{newKeyholder: openerFor(base)}).Run(context.Background(), env, []string{"p111"}); err != nil {
		t.Fatalf("unseal: %v", err)
	}
	rotateWith(t, env, "p111", &flakyKeyholder{fakeStateKeyholder: base, refuseNth: map[int]int{1: 1}})
	noSplit(t, base)
	disk := heldKeys(liveKeyring(t, dir, "p111"))["app-demo-alpha"][0]
	if got := base.replica(0).keys["app-demo-alpha"][0]; got != disk {
		t.Errorf("replica 0 writes under %s and this machine under %s", got, disk)
	}
	if err := (&storageUnsealCommand{newKeyholder: openerFor(base)}).Run(context.Background(), env, []string{"p111"}); err != nil {
		t.Errorf("unseal from the machine that rotated: %v", err)
	}
}

// Review finding 1. Unseal pushed a replica that did not say what it holds —
// and an operator push replaces everything a replica holds. A replica serving
// a scope this keyring lacks lost it, though the same unseal refuses when the
// replica answers.
func TestUnsealNeverPushesAReplicaThatDidNotAnswer(t *testing.T) {
	dir, meta, env, out := handOverInstance(t, "p112")
	alpha := scopedKeyring(t, dir, "p112", "demo", "alpha")
	// The record is ahead of the replica, so a push would clear its
	// generation: only not pushing it keeps its keys.
	meta.Keyholder.Generation = 5
	if err := dir.SaveInstanceMetadata("p112", meta); err != nil {
		t.Fatal(err)
	}
	kh := &fakeStateKeyholder{phase: "restart-sealed"}
	kh.replica(1).phase, kh.replica(1).generation = "unsealed", 4
	kh.replica(1).keys = heldKeys(alpha)
	kh.replica(1).keys["app-demo-beta"] = []string{"00000000000000bb"}
	serving := copyKeys(kh.replica(1).keys)

	silent := &flakyKeyholder{fakeStateKeyholder: kh, silent: map[int]bool{1: true}}
	err := (&storageUnsealCommand{newKeyholder: openerFor(silent)}).Run(context.Background(), env, []string{"p112"})
	if err == nil || !strings.Contains(err.Error(), "--unchecked") {
		t.Fatalf("unseal = %v; want a refusal naming --unchecked", err)
	}
	if !sameKeys(kh.replica(1).keys, serving) {
		t.Errorf("replica 1, which did not answer, now holds %v; it served %v", kh.replica(1).keys, serving)
	}
	// Review 5, finding 0: and the sealed one is left sealed, since the
	// silent one could be serving keys this keyring lacks.
	if kh.replica(0).phase != "restart-sealed" {
		t.Errorf("replica 0 was unsealed beside a replica nothing could check it against")
	}
	// The operator may say otherwise; the silent replica is still not pushed.
	if err := (&storageUnsealCommand{newKeyholder: openerFor(silent), unchecked: true}).Run(context.Background(), env, []string{"p112"}); err == nil {
		t.Error("an unseal that could not reach every replica was reported as success")
	}
	if !sameKeys(kh.replica(0).keys, heldKeys(alpha)) {
		t.Errorf("replica 0 was not unsealed with --unchecked: %v", kh.replica(0).keys)
	}
	if !sameKeys(kh.replica(1).keys, serving) {
		t.Errorf("--unchecked pushed the replica that did not answer: %v", kh.replica(1).keys)
	}
	// Review 4, finding 10: and why it did not answer is in its row.
	if !strings.Contains(out.String(), "no route to replica") {
		t.Errorf("unseal dropped why replica 1 did not answer:\n%s", out.String())
	}
}

// Review findings 3 and 15. Rotate wrote keys.yaml from the copy it loaded,
// after a network round trip — over a scope 'farcast run' minted meanwhile.
// It now replaces only the file it last read or wrote, and says what stopped
// it.
func TestRotateNeverWritesOverAKeyringAnotherCommandChanged(t *testing.T) {
	dir, meta, env, out := handOverInstance(t, "p113")
	scopedKeyring(t, dir, "p113", "demo", "alpha")
	base := servingFleet(t, env, meta, dir)
	writer := &mintsDuringPush{fakeStateKeyholder: base, t: t, dir: dir, instance: "p113"}

	rotateWith(t, env, "p113", writer)
	if _, ok := liveKeyring(t, dir, "p113").ScopeNamed("app-demo-beta"); !ok {
		t.Fatal("rotate wrote over the scope another command minted while it ran")
	}
	noSplit(t, base)
	writesUnderHeldKeys(t, dir, "p113", base)
	if !strings.Contains(out.String(), "could not save its keyring") || !strings.Contains(out.String(), "keys.yaml can be written") {
		t.Errorf("rotate did not say a local save stopped it:\n%s", out.String())
	}
}

// mintsDuringPush adds a scope to keys.yaml during the first push, as a
// 'farcast run' in another terminal would.
type mintsDuringPush struct {
	*fakeStateKeyholder
	t        *testing.T
	dir      config.Dir
	instance string
	done     bool
}

func (m *mintsDuringPush) Unseal(ctx context.Context, i int, payload []byte, intent string) (keyholder.State, error) {
	if !m.done {
		m.done = true
		beta, err := datasphere.NewAppScope("demo", "beta")
		if err != nil {
			m.t.Fatal(err)
		}
		grown, err := liveKeyring(m.t, m.dir, m.instance).AddScope(beta)
		if err != nil {
			m.t.Fatal(err)
		}
		saveKeyring(m.t, m.dir, m.instance, grown)
	}
	return m.fakeStateKeyholder.Unseal(ctx, i, payload, intent)
}

// Review finding 8. A rotation that reached no scope changes nothing a
// keeper's bundle holds, and must not say every keeper needs re-enrolling.
func TestAMasterOnlyRotationAsksNoKeeperToReenrol(t *testing.T) {
	dir, meta, env, out := handOverInstance(t, "p114")
	k, err := datasphere.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	saveKeyring(t, dir, "p114", k)
	meta.Keepers = []config.Keeper{{Device: "study-desktop"}}
	if err := dir.SaveInstanceMetadata("p114", meta); err != nil {
		t.Fatal(err)
	}
	mustRotate(t, env, "p114", &fakeStateKeyholder{phase: "unsealed"})
	if strings.Contains(out.String(), "keeper enroll") {
		t.Errorf("a master-only rotation asked for keepers to be re-enrolled:\n%s", out.String())
	}
}

// Review finding 9. After a rotation that did not finish, the gate sent the
// operator to unseal and then rekey — which ended in "✓ rekeyed" with every
// application still under the key the rotation was meant to retire.
func TestRekeyRefusesToFinishARotationThatDidNotHappen(t *testing.T) {
	env, _, dir, _, before := rekeyInstance(t)
	saveKeyring(t, dir, "prod", backdated(t, before, "2020-01-01T00:00:00Z"))
	meta, err := dir.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatal(err)
	}
	base := servingFleet(t, env, meta, dir)
	rotateWith(t, env, "prod", &flakyKeyholder{fakeStateKeyholder: base, silent: map[int]bool{1: true}})
	if err := (&storageUnsealCommand{newKeyholder: openerFor(base)}).Run(context.Background(), env, []string{"prod"}); err != nil {
		t.Fatalf("unseal: %v", err)
	}
	err = (&keyRekeyCommand{assumeYes: true, newKeyholder: openerFor(base)}).Run(context.Background(), env, []string{"prod"})
	if err == nil || !strings.Contains(err.Error(), "did not finish") || !strings.Contains(err.Error(), "farcast storage key rotate prod") {
		t.Fatalf("rekey = %v; want a refusal naming the rotation that is unfinished", err)
	}
}

// Review finding 11. The remedy depends on what the keyring lacks: an import
// brings a scope another machine deployed, but not the key another machine
// put in use — an import keeps this machine's active key.
func TestABehindRefusalNamesWhatActuallyFixesIt(t *testing.T) {
	for name, tc := range map[string]struct {
		arrange      func(*fakeStateKeyholder)
		want, unwant string
	}{
		"a scope": {
			arrange: func(kh *fakeStateKeyholder) { kh.replica(0).keys["app-elsewhere-other"] = []string{"00000000000000aa"} },
			want:    "farcast storage key import", unwant: "key rotate",
		},
		"a rotated key": {
			arrange: func(kh *fakeStateKeyholder) {
				kh.replica(0).keys["app-demo-alpha"] = append(kh.replica(0).keys["app-demo-alpha"], "00000000000000bb")
			},
			want: "farcast storage key rotate p115",
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir, meta, env, _ := handOverInstance(t, "p115")
			scopedKeyring(t, dir, "p115", "demo", "alpha")
			kh := servingFleet(t, env, meta, dir)
			tc.arrange(kh)
			err := (&storageUnsealCommand{newKeyholder: openerFor(kh)}).Run(context.Background(), env, []string{"p115"})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("unseal = %v; want it to name %q", err, tc.want)
			}
			if tc.unwant != "" && strings.Contains(err.Error(), tc.unwant) {
				t.Errorf("unseal names %q, which this case does not need: %v", tc.unwant, err)
			}
		})
	}
}

// Review finding 12. A keyring that imported another machine's rotation keeps
// its own older key in use, and holds a rotation's key of its own besides.
// 'storage state' checked what it lacks before whether it is behind, so it
// promised that an unseal would fix replicas an unseal refuses to push.
func TestStorageStateCallsABehindKeyringBehind(t *testing.T) {
	dir, meta, env, out, before := backdatedInstance(t, "p116", "alpha")
	base := servingFleet(t, env, meta, dir)
	mustRotate(t, env, "p116", base) // the other machine's rotation: the fleet uses its key
	theirs := liveKeyring(t, dir, "p116")
	saveKeyring(t, dir, "p116", before) // this machine never saw it
	rotateWith(t, env, "p116", base)    // refused as behind; its own new key stays held
	merged, err := liveKeyring(t, dir, "p116").Merge(theirs)
	if err != nil {
		t.Fatal(err)
	}
	saveKeyring(t, dir, "p116", merged) // and then it imports the other machine's keys
	out.out.Reset()
	out.err.Reset()

	if err := (&storageStateCommand{newKeyholder: openerFor(base)}).Run(context.Background(), env, []string{"p116"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "behind") || strings.Contains(out.String(), "brings them to it") {
		t.Errorf("state did not call this keyring behind, or promised an unseal fixes it:\n%s", out.String())
	}
	if err := (&storageUnsealCommand{newKeyholder: openerFor(base)}).Run(context.Background(), env, []string{"p116"}); err == nil {
		t.Error("guard: unseal from this keyring did not refuse")
	}
}

// Review finding 14. A replica the held push unsealed, which then missed the
// push that would have had it use the newest key, is serving — not "NOT
// UNSEALED".
func TestUnsealReportsAReplicaItUnsealedAsUnsealed(t *testing.T) {
	dir, meta, env, out := handOverInstance(t, "p117")
	before := scopedKeyring(t, dir, "p117", "demo", "alpha")
	base := servingFleet(t, env, meta, dir)
	mustRotate(t, env, "p117", base)
	base.replica(0).keys = heldKeys(before)
	base.replica(1).phase, base.replica(1).keys, base.replica(1).generation = "restart-sealed", nil, 0

	err := (&storageUnsealCommand{newKeyholder: openerFor(&flakyKeyholder{fakeStateKeyholder: base, refuseNth: map[int]int{1: 2}})}).
		Run(context.Background(), env, []string{"p117"})
	if err == nil || !strings.Contains(err.Error(), "hold them without using them yet") {
		t.Fatalf("unseal = %v; want it to say replica 1 holds the keys without using them", err)
	}
	if strings.Contains(out.String(), "replica 1  NOT UNSEALED") {
		t.Errorf("unseal says it did not unseal a replica it unsealed:\n%s", out.String())
	}
	noSplit(t, base)
}

// Review finding 17. The gate said rekeyed objects would be unreadable through
// a replica that holds every key; what is wrong with it is that it keeps
// writing under the old one.
func TestTheRekeyGateSaysWhyAReplicaWritingUnderAnOlderKeyBlocksIt(t *testing.T) {
	env, _, dir, _, _ := rekeyInstance(t)
	meta, err := dir.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatal(err)
	}
	base := servingFleet(t, env, meta, dir)
	rotateWith(t, env, "prod", &flakyKeyholder{fakeStateKeyholder: base, refuseNth: map[int]int{1: 2}})
	err = (&keyRekeyCommand{assumeYes: true, newKeyholder: openerFor(base)}).Run(context.Background(), env, []string{"prod"})
	if err == nil || !strings.Contains(err.Error(), "writes under an older one") {
		t.Fatalf("rekey = %v; want it to say replica 1 writes under an older key", err)
	}
}

// A rotation whose keys are not in use has not done what an operator rotates
// for, and must not read as success — 'rotate && rekey' would rekey onto the
// key being retired.
func TestARotationThatDidNotFinishFails(t *testing.T) {
	dir, meta, env, _ := handOverInstance(t, "p118")
	scopedKeyring(t, dir, "p118", "demo", "alpha")
	base := servingFleet(t, env, meta, dir)
	err := (&keyRotateCommand{assumeYes: true, newKeyholder: openerFor(&flakyKeyholder{fakeStateKeyholder: base, silent: map[int]bool{1: true}})}).
		Run(context.Background(), env, []string{"p118"})
	if err == nil || !strings.Contains(err.Error(), "farcast storage key rotate p118") {
		t.Fatalf("rotate = %v; want a failure naming what finishes it", err)
	}
}

// What this machine writes under while a rotation's keys are held is what the
// replicas can read — the keyring it hands over, not the one it started from.
// Here replica 1 was re-seeded with keys from before this machine's last
// rotation, so the key this machine uses is one it lacks; the hand-over keeps
// an older key in use, and this machine has to follow it.
func TestRotateSavesTheKeyringItHandsOver(t *testing.T) {
	dir, meta, env, _, before := backdatedInstance(t, "p119", "alpha")
	base := servingFleet(t, env, meta, dir)
	mustRotate(t, env, "p119", base)
	base.replica(1).keys = heldKeys(before)

	rotateWith(t, env, "p119", &flakyKeyholder{fakeStateKeyholder: base, refuseNth: map[int]int{1: 1}})
	writesUnderHeldKeys(t, dir, "p119", base)
	noSplit(t, base)
}

// ---------------------------------------------------------------- the fourth review

// restartsAfterFirstPush is a fleet where one replica, once it takes its first
// push, restarts — and, if refuseNext, refuses the push after that.
type restartsAfterFirstPush struct {
	*fakeStateKeyholder
	who        int
	refuseNext bool
	pushes     int
}

func (r *restartsAfterFirstPush) Unseal(ctx context.Context, i int, payload []byte, intent string) (keyholder.State, error) {
	if i == r.who {
		r.pushes++
		if r.pushes == 2 && r.refuseNext {
			return keyholder.State{}, &keyholder.Refusal{Ordinal: i, Reason: "tunnel dropped"}
		}
	}
	st, err := r.fakeStateKeyholder.Unseal(ctx, i, payload, intent)
	if err == nil && i == r.who && r.pushes == 1 {
		rep := r.replica(i)
		rep.phase, rep.keys, rep.generation = "restart-sealed", nil, 0
	}
	return st, err
}

// Review 4, finding 1. The held step had a serving replica take the keys; it
// then restarted before they were to be used, leaving none serving — the very
// state in which a rotation must not put them in use on this machine.
func TestARotationStopsIfNoReplicaIsServingWhenItsKeysAreToBeUsed(t *testing.T) {
	dir, meta, env, out := handOverInstance(t, "p120")
	scopedKeyring(t, dir, "p120", "demo", "alpha")
	base := servingFleet(t, env, meta, dir)
	before := heldKeys(liveKeyring(t, dir, "p120"))["app-demo-alpha"][0]
	base.replica(1).phase, base.replica(1).keys = "restart-sealed", nil

	rotateWith(t, env, "p120", &restartsAfterFirstPush{fakeStateKeyholder: base, who: 0})
	if got := heldKeys(liveKeyring(t, dir, "p120"))["app-demo-alpha"][0]; got != before {
		t.Errorf("this machine now writes under %s, which no serving replica holds", got)
	}
	if !strings.Contains(out.String(), "every replica was sealed") {
		t.Errorf("rotate did not say why it stopped:\n%s", out.String())
	}
}

// Review 4, finding 2. A rotation after a half-finished one, with the replica
// that uses the newer key silent, moved this machine back onto the key the
// first rotation retired — though this machine used the newer one, and every
// replica that answered held it.
func TestARotationNeverMovesThisMachineBackOntoARetiredKey(t *testing.T) {
	dir, meta, env, _, _ := backdatedInstance(t, "p121", "alpha")
	base := servingFleet(t, env, meta, dir)
	rotateWith(t, env, "p121", &flakyKeyholder{fakeStateKeyholder: base, refuseNth: map[int]int{1: 2}})
	using := heldKeys(liveKeyring(t, dir, "p121"))["app-demo-alpha"][0]

	rotateWith(t, env, "p121", &flakyKeyholder{fakeStateKeyholder: base, silent: map[int]bool{0: true}})
	if got := heldKeys(liveKeyring(t, dir, "p121"))["app-demo-alpha"][0]; got != using {
		t.Errorf("this machine now writes under %s; it used %s, which every replica that answered holds", got, using)
	}
	noSplit(t, base)
	writesUnderHeldKeys(t, dir, "p121", base)
	if err := (&storageUnsealCommand{newKeyholder: openerFor(base)}).Run(context.Background(), env, []string{"p121"}); err != nil {
		t.Errorf("unseal from the machine that rotated: %v", err)
	}
}

// Review 4, findings 3 and 11. A replica that took the held keys and then
// restarted holds nothing, and is not "holding the keys without using them".
func TestUnsealDoesNotCallARestartedReplicaServing(t *testing.T) {
	dir, meta, env, out := handOverInstance(t, "p122")
	before := scopedKeyring(t, dir, "p122", "demo", "alpha")
	base := servingFleet(t, env, meta, dir)
	mustRotate(t, env, "p122", base)
	base.replica(0).keys = heldKeys(before) // a hold is needed

	err := (&storageUnsealCommand{newKeyholder: openerFor(&restartsAfterFirstPush{fakeStateKeyholder: base, who: 1, refuseNext: true})}).
		Run(context.Background(), env, []string{"p122"})
	if err == nil {
		t.Fatal("an unseal that left a replica sealed was reported as success")
	}
	if strings.Contains(err.Error(), "hold them without using them") || strings.Contains(out.String(), "replica 1  unsealed") {
		t.Errorf("unseal calls a restarted replica serving: %v\n%s", err, out.String())
	}
}

// Review 4, findings 5 and 7. Every replica took the held keys and then missed
// the push that would have them use the keys: rotate said "✓ now wraps new
// writes under new keys" and exited 0, with no replica writing under them.
func TestARotationWhoseKeysNoReplicaUsesIsNotSuccess(t *testing.T) {
	dir, meta, env, out := handOverInstance(t, "p123")
	scopedKeyring(t, dir, "p123", "demo", "alpha")
	base := servingFleet(t, env, meta, dir)
	before := heldKeys(liveKeyring(t, dir, "p123"))["app-demo-alpha"][0]

	err := (&keyRotateCommand{assumeYes: true, newKeyholder: openerFor(&flakyKeyholder{fakeStateKeyholder: base, refuseNth: map[int]int{0: 2, 1: 2}})}).
		Run(context.Background(), env, []string{"p123"})
	if err == nil {
		t.Fatal("a rotation no replica uses was reported as success")
	}
	if strings.Contains(out.String(), "✓") {
		t.Errorf("rotate printed success:\n%s", out.String())
	}
	if got := heldKeys(liveKeyring(t, dir, "p123"))["app-demo-alpha"][0]; got != before {
		t.Errorf("this machine writes under %s, which no replica uses; want it back on %s", got, before)
	}
	noSplit(t, base)
}

// Review 4, finding 8. A scope two machines each minted shares no key with
// the replicas' copy. It used to be diagnosed as "behind", with an import and
// a rotation as remedies — and both are refused.
func TestAScopeMintedTwiceIsNamedAsSuch(t *testing.T) {
	dir, meta, env, out := handOverInstance(t, "p124")
	scopedKeyring(t, dir, "p124", "demo", "alpha")
	base := servingFleet(t, env, meta, dir)
	for i := range 2 {
		base.replica(i).keys["app-demo-alpha"] = []string{"00000000000000cc"} // the other machine's copy
	}
	err := (&storageUnsealCommand{newKeyholder: openerFor(base)}).Run(context.Background(), env, []string{"p124"})
	if err == nil || !strings.Contains(err.Error(), "minted separately") || strings.Contains(err.Error(), "key import' here") {
		t.Fatalf("unseal = %v; want it named as a scope minted twice, without import as a remedy", err)
	}
	if err := (&storageStateCommand{newKeyholder: openerFor(base)}).Run(context.Background(), env, []string{"p124"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "minted separately") {
		t.Errorf("state did not name the scope minted twice:\n%s", out.String())
	}
}

// Review 4, finding 9. With every replica sealed, the step after the hold is an
// unseal, not another rotation — and the rekey gate must list it first.
func TestAfterARotationStoppedBySealedReplicasUnsealComesFirst(t *testing.T) {
	env, _, dir, _, before := rekeyInstance(t)
	saveKeyring(t, dir, "prod", backdated(t, before, "2020-01-01T00:00:00Z"))
	sealed := &fakeStateKeyholder{phase: "restart-sealed"}
	err := (&keyRotateCommand{assumeYes: true, newKeyholder: openerFor(sealed)}).Run(context.Background(), env, []string{"prod"})
	if err == nil || !strings.Contains(err.Error(), "farcast storage unseal prod', then") {
		t.Fatalf("rotate = %v; want it to name the unseal that comes first", err)
	}
	err = (&keyRekeyCommand{assumeYes: true, newKeyholder: openerFor(sealed)}).Run(context.Background(), env, []string{"prod"})
	if err == nil {
		t.Fatal("guard: rekey did not refuse")
	}
	unseal, rotate := strings.Index(err.Error(), "farcast storage unseal prod"), strings.Index(err.Error(), "farcast storage key rotate prod")
	if unseal < 0 || rotate < 0 || unseal > rotate {
		t.Errorf("the gate's remedies are out of order:\n%v", err)
	}
}

// Review 4, finding 12. A replica that took only the first of two pushes holds
// the new application's scope — the push carried it — and run must count it.
func TestRunCountsAReplicaThatTookOnlyTheHeldPush(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meta := runnableInstance(t, dir, "p125")
	meta.Keyholder = &config.Keyholder{Deployed: true, Replicas: 2}
	if err := dir.SaveInstanceMetadata("p125", meta); err != nil {
		t.Fatal(err)
	}
	mintKeyring(t, dir, "p125")
	// An application deployed before, whose current key replica 0 lacks.
	other, err := datasphere.NewAppScope("elsewhere", "other")
	if err != nil {
		t.Fatal(err)
	}
	k, err := liveKeyring(t, dir, "p125").AddScope(other)
	if err != nil {
		t.Fatal(err)
	}
	k, _, err = k.RotateScopeKEKs()
	if err != nil {
		t.Fatal(err)
	}
	saveKeyring(t, dir, "p125", k)
	kh := &fakeStateKeyholder{phase: "unsealed"}
	for i := range 2 {
		kh.replica(i).generation, kh.replica(i).keys = 1, heldKeys(k)
	}
	ids := kh.replica(0).keys[other.Name]
	kh.replica(0).keys[other.Name] = ids[1:]

	env, _, errBuf := testEnvBoth(dir, output.ModeHuman)
	c := runCmd(newFakeRun(twoAppManifest))
	flaky := &flakyKeyholder{fakeStateKeyholder: kh, refuseNth: map[int]int{1: 2}}
	c.newKeyholder = func(context.Context, *Env, string) (sealStateClient, func(), error) { return flaky, func() {}, nil }
	if err := c.Run(context.Background(), env, []string{"p125", "github.com/example/my-platform"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errBuf.String(), "on 2 of 2 replicas") {
		t.Errorf("run did not count the replica that holds the scope from the first push:\n%s", errBuf.String())
	}
}

// ---------------------------------------------------------------- the fifth review

// Review 5, finding 0. Unseal from a keyring that predates another machine's
// rotation, beside a serving replica that did not answer: nothing could be
// compared, and the sealed replica was unsealed onto the old keys.
func TestUnsealFromAnOlderKeyringNeverSplitsFromASilentServingReplica(t *testing.T) {
	dir, meta, env, _ := handOverInstance(t, "p130")
	stale := scopedKeyring(t, dir, "p130", "demo", "alpha")
	base := servingFleet(t, env, meta, dir)
	mustRotate(t, env, "p130", base) // another machine's rotation, in effect
	saveKeyring(t, dir, "p130", stale)
	base.replica(0).phase, base.replica(0).keys, base.replica(0).generation = "restart-sealed", nil, 0

	err := (&storageUnsealCommand{newKeyholder: openerFor(&flakyKeyholder{fakeStateKeyholder: base, silent: map[int]bool{1: true}})}).
		Run(context.Background(), env, []string{"p130"})
	if err == nil {
		t.Fatal("an unseal beside a silent replica was reported as success")
	}
	if base.replica(0).phase != "restart-sealed" {
		t.Error("replica 0 was unsealed from an older keyring beside a replica serving newer keys")
	}
	noSplit(t, base)
}

// silentAfterPush stops answering State for a replica once it has been
// pushed.
type silentAfterPush struct {
	*fakeStateKeyholder
	pushed map[int]bool
}

func (s *silentAfterPush) State(ctx context.Context, i int) (keyholder.State, error) {
	if s.pushed[i] {
		return keyholder.State{}, errors.New("no route to replica")
	}
	return s.fakeStateKeyholder.State(ctx, i)
}

func (s *silentAfterPush) Unseal(ctx context.Context, i int, payload []byte, intent string) (keyholder.State, error) {
	if s.pushed == nil {
		s.pushed = map[int]bool{}
	}
	s.pushed[i] = true
	return s.fakeStateKeyholder.Unseal(ctx, i, payload, intent)
}

// Review 5, findings 2 and 5. Replicas that only stopped answering are not
// sealed, and the advice for them is not an unseal.
func TestARotationWhoseReplicasStopAnsweringDoesNotCallThemSealed(t *testing.T) {
	dir, meta, env, out := handOverInstance(t, "p131")
	scopedKeyring(t, dir, "p131", "demo", "alpha")
	base := servingFleet(t, env, meta, dir)
	rotateWith(t, env, "p131", &silentAfterPush{fakeStateKeyholder: base})
	if strings.Contains(out.String(), "sealed") || !strings.Contains(out.String(), "no replica answered") {
		t.Errorf("rotate misdescribed replicas that stopped answering:\n%s", out.String())
	}
	writesUnderHeldKeys(t, dir, "p131", base)
}

// reseededWhileSilent is replica 1 sealed at the first read, re-seeded by a
// keeper with older keys while the held push goes to replica 0, and silent
// when asked again.
type reseededWhileSilent struct {
	*fakeStateKeyholder
	old  map[string][]string
	done bool
}

func (r *reseededWhileSilent) State(ctx context.Context, i int) (keyholder.State, error) {
	if i == 1 && r.done {
		return keyholder.State{}, errors.New("no route to replica")
	}
	return r.fakeStateKeyholder.State(ctx, i)
}

func (r *reseededWhileSilent) Unseal(ctx context.Context, i int, payload []byte, intent string) (keyholder.State, error) {
	st, err := r.fakeStateKeyholder.Unseal(ctx, i, payload, intent)
	if i == 0 && !r.done {
		r.done = true
		rep := r.replica(1)
		rep.phase, rep.keys, rep.generation = "unsealed", copyKeys(r.old), 1
	}
	return st, err
}

// Review 5, finding 3. A replica that never took the new keys — sealed at the
// first push — and does not answer when they are to be used may have been
// re-seeded without them meanwhile. Activation used to go ahead.
func TestActivationWaitsForAReplicaThatNeverTookTheKeys(t *testing.T) {
	dir, meta, env, out := handOverInstance(t, "p132")
	before := scopedKeyring(t, dir, "p132", "demo", "alpha")
	base := servingFleet(t, env, meta, dir)
	base.replica(1).phase, base.replica(1).keys, base.replica(1).generation = "restart-sealed", nil, 0

	rotateWith(t, env, "p132", &reseededWhileSilent{fakeStateKeyholder: base, old: heldKeys(before)})
	noSplit(t, base)
	writesUnderHeldKeys(t, dir, "p132", base)
	if !strings.Contains(out.String(), "never took them") {
		t.Errorf("rotate did not say why it stopped:\n%s", out.String())
	}
}

// lossyActivation is the push that would put new keys in use: replica 0
// installs it and its answer is lost; replica 1 refuses it.
type lossyActivation struct {
	*fakeStateKeyholder
	seen map[int]int
}

func (l *lossyActivation) Unseal(ctx context.Context, i int, payload []byte, intent string) (keyholder.State, error) {
	if l.seen == nil {
		l.seen = map[int]int{}
	}
	l.seen[i]++
	if l.seen[i] == 2 {
		if i == 1 {
			return keyholder.State{}, &keyholder.Refusal{Ordinal: i, Reason: "tunnel dropped"}
		}
		if _, err := l.fakeStateKeyholder.Unseal(ctx, i, payload, intent); err != nil {
			return keyholder.State{}, err
		}
		return keyholder.State{}, errors.New("connection reset")
	}
	return l.fakeStateKeyholder.Unseal(ctx, i, payload, intent)
}

// Review 5, finding 4. A push whose answer was lost may have landed. Counted
// as refused, a rotation put this machine back on the keys from before —
// behind a replica already using the new ones.
func TestALostAnswerIsConfirmedBeforeARotationIsUndone(t *testing.T) {
	dir, meta, env, _ := handOverInstance(t, "p133")
	scopedKeyring(t, dir, "p133", "demo", "alpha")
	base := servingFleet(t, env, meta, dir)
	rotateWith(t, env, "p133", &lossyActivation{fakeStateKeyholder: base})
	using := base.replica(0).keys["app-demo-alpha"][0]
	if got := heldKeys(liveKeyring(t, dir, "p133"))["app-demo-alpha"][0]; got != using {
		t.Errorf("this machine writes under %s while replica 0 — whose answer was lost — writes under %s", got, using)
	}
	noSplit(t, base)
	if err := (&storageUnsealCommand{newKeyholder: openerFor(base)}).Run(context.Background(), env, []string{"p133"}); err != nil {
		t.Errorf("unseal from the machine that rotated: %v", err)
	}
}

// Review 5, findings 1 and 6. For a scope another machine minted too, nothing
// on this machine helps — not an unseal, not a rotation.
func TestAForeignCopyIsNeverGivenARemedyThatRefuses(t *testing.T) {
	env, _, dir, _, _ := rekeyInstance(t)
	meta, err := dir.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatal(err)
	}
	base := servingFleet(t, env, meta, dir)
	for i := range 2 {
		base.replica(i).keys["app-demo-alpha"] = []string{"00000000000000cc"}
	}
	err = (&keyRekeyCommand{assumeYes: true, newKeyholder: openerFor(base)}).Run(context.Background(), env, []string{"prod:app/demo/alpha/"})
	if err == nil || strings.Contains(err.Error(), "Run:\n\n  farcast storage unseal prod\n") || !strings.Contains(err.Error(), "machine that deployed it") {
		t.Errorf("rekey = %v; want the machine that deployed it as the remedy, not an unseal", err)
	}
	err = (&keyRotateCommand{assumeYes: true, newKeyholder: openerFor(base)}).Run(context.Background(), env, []string{"prod"})
	if err == nil || strings.Contains(err.Error(), "rotate prod' again") || !strings.Contains(err.Error(), "machine that deployed it") {
		t.Errorf("rotate = %v; want the machine that deployed it, not another rotation here", err)
	}
}

// Review 5, finding 7. Both replicas took the first push and then restarted:
// none holds anything, and run must say storage is sealed for the new
// application, not that it is held.
func TestRunDoesNotCountRestartedReplicasAsHoldingTheScope(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meta := runnableInstance(t, dir, "p134")
	meta.Keyholder = &config.Keyholder{Deployed: true, Replicas: 2}
	if err := dir.SaveInstanceMetadata("p134", meta); err != nil {
		t.Fatal(err)
	}
	mintKeyring(t, dir, "p134")
	other, err := datasphere.NewAppScope("elsewhere", "other")
	if err != nil {
		t.Fatal(err)
	}
	k, err := liveKeyring(t, dir, "p134").AddScope(other)
	if err != nil {
		t.Fatal(err)
	}
	if k, _, err = k.RotateScopeKEKs(); err != nil {
		t.Fatal(err)
	}
	saveKeyring(t, dir, "p134", k)
	kh := &fakeStateKeyholder{phase: "unsealed"}
	for i := range 2 {
		kh.replica(i).generation, kh.replica(i).keys = 1, heldKeys(k)
	}
	ids := kh.replica(0).keys[other.Name]
	kh.replica(0).keys[other.Name] = ids[1:]

	env, _, errBuf := testEnvBoth(dir, output.ModeHuman)
	c := runCmd(newFakeRun(twoAppManifest))
	both := &restartsBothAfterFirstPush{fakeStateKeyholder: kh}
	c.newKeyholder = func(context.Context, *Env, string) (sealStateClient, func(), error) { return both, func() {}, nil }
	if err := c.Run(context.Background(), env, []string{"p134", "github.com/example/my-platform"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(errBuf.String(), "holds api, web's scope on") || !strings.Contains(errBuf.String(), "ErrStorageSealed") {
		t.Errorf("run said restarted replicas hold the new scope:\n%s", errBuf.String())
	}
}

// restartsBothAfterFirstPush restarts every replica once it takes a push.
type restartsBothAfterFirstPush struct{ *fakeStateKeyholder }

func (r *restartsBothAfterFirstPush) Unseal(ctx context.Context, i int, payload []byte, intent string) (keyholder.State, error) {
	st, err := r.fakeStateKeyholder.Unseal(ctx, i, payload, intent)
	if err == nil {
		rep := r.replica(i)
		rep.phase, rep.keys, rep.generation = "restart-sealed", nil, 0
	}
	return st, err
}

// Review 5, finding 8. "Run this again" belongs only to a keyring another
// command changed meanwhile; a linked keys.yaml refuses the same way every
// time.
func TestRunDoesNotAdviseRetryingARefusalThatRepeats(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meta := runnableInstance(t, dir, "p135")
	meta.Keyholder = &config.Keyholder{Deployed: true, Replicas: 2}
	if err := dir.SaveInstanceMetadata("p135", meta); err != nil {
		t.Fatal(err)
	}
	mintKeyring(t, dir, "p135")
	path := dir.InstanceKeyringPath("p135")
	if err := os.Link(path, filepath.Join(t.TempDir(), "backup.yaml")); err != nil {
		t.Fatal(err)
	}
	env, _, _ := testEnvBoth(dir, output.ModeHuman)
	err := runCmd(newFakeRun(twoAppManifest)).Run(context.Background(), env, []string{"p135", "github.com/example/my-platform"})
	if err == nil || strings.Contains(err.Error(), "run this again") || !strings.Contains(err.Error(), "link") {
		t.Errorf("run = %v; want the link refusal, without advice to retry", err)
	}
}

// bothRefuseOneGoesQuiet refuses the push that would put new keys in use on
// both replicas, and replica 0 then stops answering.
type bothRefuseOneGoesQuiet struct {
	*fakeStateKeyholder
	seen map[int]int
}

func (b *bothRefuseOneGoesQuiet) State(ctx context.Context, i int) (keyholder.State, error) {
	if i == 0 && b.seen[0] >= 2 {
		return keyholder.State{}, errors.New("no route to replica")
	}
	return b.fakeStateKeyholder.State(ctx, i)
}

func (b *bothRefuseOneGoesQuiet) Unseal(ctx context.Context, i int, payload []byte, intent string) (keyholder.State, error) {
	if b.seen == nil {
		b.seen = map[int]int{}
	}
	b.seen[i]++
	if b.seen[i] == 2 {
		return keyholder.State{}, &keyholder.Refusal{Ordinal: i, Reason: "tunnel dropped"}
	}
	return b.fakeStateKeyholder.Unseal(ctx, i, payload, intent)
}

// A replica that refused and then would not say what it holds may have taken
// the keys after all. Putting this machine back could leave it behind its own
// fleet; every replica holds the new keys, so staying on them splits nothing.
func TestARotationIsNotUndoneOnAnAnswerItCouldNotConfirm(t *testing.T) {
	dir, meta, env, out := handOverInstance(t, "p136")
	scopedKeyring(t, dir, "p136", "demo", "alpha")
	base := servingFleet(t, env, meta, dir)
	rotateWith(t, env, "p136", &bothRefuseOneGoesQuiet{fakeStateKeyholder: base})
	disk := heldKeys(liveKeyring(t, dir, "p136"))["app-demo-alpha"]
	if !strings.Contains(out.String(), "did not say afterwards") {
		t.Errorf("rotate did not say why this machine stays on the new keys:\n%s", out.String())
	}
	for i := range 2 {
		if !slices.Contains(base.replica(i).keys["app-demo-alpha"], disk[0]) {
			t.Errorf("this machine writes under %s, which replica %d does not hold", disk[0], i)
		}
	}
}
