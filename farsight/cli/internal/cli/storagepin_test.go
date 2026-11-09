package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/sofmon/farcast/datasphere"
	dsdeploy "github.com/sofmon/farcast/datasphere/deploy"
	dskeyholder "github.com/sofmon/farcast/datasphere/keyholder"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/keeper"
	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
)

// Every test that does not bring its own pin store gets one in memory, per
// instance, so no test can shell out to kubectl for the pin.
var testPinStores = struct {
	sync.Mutex
	by map[string]*fakePinStore
}{by: map[string]*fakePinStore{}}

func init() {
	defaultPinStore = func(kubeconfig string) (pinStore, error) {
		testPinStores.Lock()
		defer testPinStores.Unlock()
		ps, ok := testPinStores.by[kubeconfig]
		if !ok {
			ps = &fakePinStore{}
			testPinStores.by[kubeconfig] = ps
		}
		return ps, nil
	}
}

// pinStoreOf is the in-memory pin a test's instance got by default.
func pinStoreOf(dir config.Dir, instance string) *fakePinStore {
	ps, _ := defaultPinStore(dir.InstanceKubeconfigPath(instance))
	return ps.(*fakePinStore)
}

// fakePinStore is the pin ConfigMap with the API server's own rules: create
// fails over an existing one, and replace fails at a stale resourceVersion.
type fakePinStore struct {
	mu      sync.Mutex
	exists  bool
	value   string
	version int
	// failRead and failWrite make the next calls fail as infrastructure does.
	failRead, failWrite error
	// onWrite runs before a write lands, so a test can race another writer.
	onWrite func()
	// loseAnswer lets the next write land and then report failure, as a
	// write whose answer was lost does.
	loseAnswer bool
	// log records every successful write, for ordering against pushes.
	log *[]string
}

func (f *fakePinStore) ConfigMapData(context.Context, string, string) (map[string]string, string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failRead != nil {
		return nil, "", false, f.failRead
	}
	if !f.exists {
		return nil, "", false, nil
	}
	return map[string]string{dsdeploy.PinKey: f.value}, strconv.Itoa(f.version), true, nil
}

func (f *fakePinStore) write(manifest []byte, create bool) error {
	if f.onWrite != nil {
		hook := f.onWrite
		f.onWrite = nil
		hook()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWrite != nil {
		return f.failWrite
	}
	var doc struct {
		Metadata struct {
			Name            string `json:"name"`
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(manifest, &doc); err != nil {
		return err
	}
	if doc.Metadata.Name != dsdeploy.PinConfigMapName("") {
		return fmt.Errorf("wrote %q", doc.Metadata.Name)
	}
	switch {
	case create && f.exists:
		return errors.New("AlreadyExists")
	case !create && (!f.exists || doc.Metadata.ResourceVersion != strconv.Itoa(f.version)):
		return errors.New("Conflict")
	}
	f.exists, f.value = true, doc.Data[dsdeploy.PinKey]
	f.version++
	if f.log != nil {
		*f.log = append(*f.log, "pin "+f.value)
	}
	if f.loseAnswer {
		f.loseAnswer = false
		return errors.New("the connection dropped")
	}
	return nil
}

func (f *fakePinStore) CreateConfigMap(_ context.Context, manifest []byte) error {
	return f.write(manifest, true)
}

func (f *fakePinStore) ReplaceConfigMap(_ context.Context, manifest []byte) error {
	return f.write(manifest, false)
}

// pin is what the store holds, parsed.
func (f *fakePinStore) pin(t *testing.T) dskeyholder.Pin {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	p, _, err := dskeyholder.ParsePin(f.value)
	if err != nil {
		t.Fatalf("the stored pin does not parse: %v", err)
	}
	return p
}

func (f *fakePinStore) set(value string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.exists, f.value = true, value
	f.version++
}

func ids(p []datasphere.KeyID) []string {
	out := make([]string, len(p))
	for i, id := range p {
		out[i] = id.String()
	}
	return out
}

func TestPinForRequiresEverythingAndRetiresOnlyWhatIsOlder(t *testing.T) {
	k := appsKeyring(t, "web", "api")
	rotated, rots, err := k.RotateScopeKEKs()
	if err != nil {
		t.Fatal(err)
	}
	prev := map[string]datasphere.KeyID{}
	for _, r := range rots {
		prev[r.Scope] = r.Previous
	}
	held, err := rotated.WithScopeActive(prev)
	if err != nil {
		t.Fatal(err)
	}

	// Held: the new keys are required and the old ones are what the scopes
	// write under, so nothing is retired.
	p := pinFor(held)
	if len(p.Require) != 4 || len(p.Retired) != 0 {
		t.Errorf("held: require %v, retired %v; want all four keys required, none retired", ids(p.Require), ids(p.Retired))
	}
	// Activated: the old ones are retired, if they are strictly older.
	p = pinFor(rotated)
	if len(p.Require) != 4 {
		t.Errorf("activated: require %v", ids(p.Require))
	}
	for _, r := range rots {
		older := false
		if s, ok := rotated.ScopeNamed(r.Scope); ok {
			keks := s.Keyring().KEKs()
			older = keks[1].Created.Before(keks[0].Created)
		}
		retired := false
		for _, id := range p.Retired {
			retired = retired || id == r.Previous
		}
		if retired != older {
			t.Errorf("%s: previous key retired = %v, created strictly earlier = %v", r.Scope, retired, older)
		}
	}
	if err := p.Admits(heldKeys(rotated)); err != nil {
		t.Errorf("a keyring's own pin refuses it: %v", err)
	}
	if err := pinFor(held).Admits(heldKeys(held)); err != nil {
		t.Errorf("a held keyring's own pin refuses it: %v", err)
	}
}

func TestPinVerdict(t *testing.T) {
	k := appsKeyring(t, "web")
	rotated, rots, err := k.RotateScopeKEKs()
	if err != nil {
		t.Fatal(err)
	}
	if b := pinVerdict(dskeyholder.Pin{}, k); b != nil {
		t.Errorf("an empty pin = %v", b)
	}
	if b := pinVerdict(pinFor(rotated), k); b == nil || len(b.Missing) != 1 || b.Missing[0] != rots[0].Active.String() {
		t.Errorf("a keyring without the rotated key = %+v; want it missing", b)
	}
	retire := dskeyholder.Pin{Retired: []datasphere.KeyID{rots[0].Previous}}
	if b := pinVerdict(retire, k); b == nil || len(b.RetiredActive) != 1 || len(b.Missing) != 0 {
		t.Errorf("a keyring writing under a retired key = %+v", b)
	}
	if b := pinVerdict(retire, rotated); b != nil {
		t.Errorf("the rotated keyring, holding the retired key without writing under it = %+v", b)
	}
}

func TestWritePinCreatesRaisesAndNeverLowers(t *testing.T) {
	ctx := context.Background()
	ps := &fakePinStore{}
	k := appsKeyring(t, "web")
	w, err := writePin(ctx, ps, k, true, false)
	if err != nil || !w.Changed || !ps.exists {
		t.Fatalf("create = %+v, %v", w, err)
	}
	before := ps.version
	if w, err := writePin(ctx, ps, k, true, false); err != nil || w.Changed || ps.version != before {
		t.Errorf("an unchanged pin was rewritten: %+v, %v", w, err)
	}

	rotated, _, err := k.RotateScopeKEKs()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writePin(ctx, ps, rotated, true, false); err != nil {
		t.Fatal(err)
	}
	if got := ps.pin(t); !got.Equal(pinFor(rotated).Union(pinFor(k))) {
		t.Errorf("raised to %s", got.Marshal())
	}
	stored := ps.value
	var behind *pinBehind
	if _, err := writePin(ctx, ps, k, true, false); !errors.As(err, &behind) || ps.value != stored {
		t.Errorf("an older keyring = %v, and the pin is %s; want refused and unchanged", err, ps.value)
	}
	// Replace is the operator lowering it on purpose.
	if w, err := writePin(ctx, ps, k, true, true); err != nil || !w.Pin.Equal(pinFor(k)) {
		t.Errorf("replace = %+v, %v", w, err)
	}
}

// A write is over what was read. Another writer between the read and the write
// is taken into account, not overwritten.
func TestWritePinNeverWritesOverAnotherWriter(t *testing.T) {
	ctx := context.Background()
	ps := &fakePinStore{}
	k := appsKeyring(t, "web")
	if _, err := writePin(ctx, ps, k, true, false); err != nil {
		t.Fatal(err)
	}
	other, err := k.AddScope(mustAppScope(t, "api"))
	if err != nil {
		t.Fatal(err)
	}
	mine, _, err := other.RotateScopeKEKs()
	if err != nil {
		t.Fatal(err)
	}
	// Between this machine's read and its write, another raises the pin with
	// a key this keyring also holds (an import brought it over).
	ps.onWrite = func() { ps.set(pinFor(other).Marshal()) }
	w, err := writePin(ctx, ps, mine, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := ps.pin(t); !got.Equal(w.Pin) || !got.Equal(pinFor(mine).Union(pinFor(other))) {
		t.Errorf("stored %s; want the union of both writers", got.Marshal())
	}
	// Infrastructure failing is an error, not a silent success.
	ps.failWrite = errors.New("credentials expired")
	if _, err := writePin(ctx, ps, appsKeyring(t, "fresh"), true, true); err == nil || !strings.Contains(err.Error(), "credentials expired") {
		t.Errorf("a failing write = %v", err)
	}
}

// Never ahead: whatever keyring a pin is written from, that keyring passes it.
func TestAWrittenPinAlwaysAdmitsTheKeyringItWasWrittenFrom(t *testing.T) {
	ctx := context.Background()
	r := rand.New(rand.NewPCG(1, 2))
	for i := range 40 {
		ps := &fakePinStore{}
		k := appsKeyring(t, "web", "api")
		for range r.IntN(4) {
			rotated, rots, err := k.RotateScopeKEKs()
			if err != nil {
				t.Fatal(err)
			}
			k = rotated
			if r.IntN(2) == 0 {
				prev := map[string]datasphere.KeyID{}
				for _, rot := range rots {
					prev[rot.Scope] = rot.Previous
				}
				if k, err = rotated.WithScopeActive(prev); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := writePin(ctx, ps, k, r.IntN(2) == 0, false); err != nil {
				t.Fatalf("round %d: %v", i, err)
			}
			if err := ps.pin(t).Admits(heldKeys(k)); err != nil {
				t.Fatalf("round %d: the pin refuses the keyring it was written from: %v", i, err)
			}
		}
	}
}

// appsKeyring is a keyring with one scope per application, not saved anywhere.
func appsKeyring(t *testing.T, apps ...string) datasphere.Keyring {
	t.Helper()
	k, err := datasphere.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	for _, app := range apps {
		if k, err = k.AddScope(mustAppScope(t, app)); err != nil {
			t.Fatal(err)
		}
	}
	return k
}

func mustAppScope(t *testing.T, app string) datasphere.Scope {
	t.Helper()
	s, err := datasphere.NewAppScope("apps", app)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestKeyPinCommandRefusesToLowerWithoutReplace(t *testing.T) {
	dir, _, env, _ := handOverInstance(t, "p300")
	keys := scopedKeyring(t, dir, "p300", "apps", "web")
	ps := pinStoreOf(dir, "p300")
	rotated, _, err := keys.RotateScopeKEKs()
	if err != nil {
		t.Fatal(err)
	}
	ps.set(pinFor(rotated).Marshal())
	stored := ps.value

	c := &keyPinCommand{newKeyholder: openerFor(&fakeStateKeyholder{phase: "unsealed"})}
	err = c.Run(context.Background(), env, []string{"p300"})
	if err == nil || !strings.Contains(err.Error(), "behind the instance's key pin") || ps.value != stored {
		t.Fatalf("pin from a keyring behind the pin = %v, stored %s; want refused and unchanged", err, ps.value)
	}

	kh := &fakeStateKeyholder{phase: "unsealed"}
	higher := pinFor(rotated)
	for i := range 2 {
		kh.replica(i).pin = &higher
	}
	c = &keyPinCommand{replace: true, assumeYes: true, newKeyholder: openerFor(kh)}
	if err := c.Run(context.Background(), env, []string{"p300"}); err != nil {
		t.Fatal(err)
	}
	if !ps.pin(t).Equal(pinFor(keys)) {
		t.Errorf("--replace stored %s; want this keyring's own pin", ps.value)
	}
	// And every replica was handed it live, replacing what it had.
	for i := range 2 {
		if p := kh.replica(i).pin; p == nil || !p.Equal(pinFor(keys)) {
			t.Errorf("replica %d enforces %v; want the lowered pin, live", i, p)
		}
	}
}

// loggingFleet records each push in the same log the pin store writes to, so
// a test can see which came first.
type loggingFleet struct {
	*fakeStateKeyholder
	log *[]string
}

func (l *loggingFleet) Unseal(ctx context.Context, i int, payload []byte, intent string) (keyholder.State, error) {
	*l.log = append(*l.log, fmt.Sprintf("push %d %s", i, intent))
	return l.fakeStateKeyholder.Unseal(ctx, i, payload, intent)
}

func (l *loggingFleet) RaisePin(ctx context.Context, i int, pin string, replace bool) (keyholder.State, error) {
	*l.log = append(*l.log, fmt.Sprintf("raise %d", i))
	return l.fakeStateKeyholder.RaisePin(ctx, i, pin, replace)
}

func firstIndex(log []string, prefix string) int {
	for i, l := range log {
		if strings.HasPrefix(l, prefix) {
			return i
		}
	}
	return -1
}

func scopeKEK(k datasphere.Keyring) datasphere.KeyID { return k.Scopes()[0].Keyring().KEKs()[0].ID }

func containsID(ids []datasphere.KeyID, id datasphere.KeyID) bool { return slices.Contains(ids, id) }

// The order the pin is safe in. Required only once every serving replica has
// confirmed — asked twice — that it holds the new keys, so the keyring it is
// written from is behind none of them; handed to every replica live before any
// is told to use the keys, so a sealed one cannot be re-seeded without them in
// between; and retiring the old keys only once the new ones are in use, never
// while they could be put back.
func TestRotateRequiresTheNewKeysBeforeAnyPushAndRetiresOnlyAfter(t *testing.T) {
	dir, meta, env, _, before := backdatedInstance(t, "p301", "alpha")
	base := servingFleet(t, env, meta, dir)
	var log []string
	ps := pinStoreOf(dir, "p301")
	ps.log = &log
	old := scopeKEK(before)

	if err := (&keyRotateCommand{assumeYes: true, newKeyholder: openerFor(&loggingFleet{base, &log})}).
		Run(context.Background(), env, []string{"p301"}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	now := scopeKEK(liveKeyring(t, dir, "p301"))
	firstPin, firstPush := firstIndex(log, "pin "), firstIndex(log, "push ")
	if firstPin < 0 || firstPush < 0 || firstPin < firstPush {
		t.Fatalf("log %v: the held keys go over first, and the pin moves only after", log)
	}
	// After the pin: both replicas raised, then the activating pushes.
	rest := log[firstPin+1:]
	raised, pushedAfter := 0, false
	for _, l := range rest {
		switch {
		case strings.HasPrefix(l, "raise ") && !pushedAfter:
			raised++
		case strings.HasPrefix(l, "push "):
			pushedAfter = true
		}
	}
	if raised != 2 || !pushedAfter {
		t.Fatalf("log %v: every replica must be raised live before any is told to use the new keys", log)
	}
	held, _, err := dskeyholder.ParsePin(strings.TrimPrefix(log[firstPin], "pin "))
	if err != nil {
		t.Fatal(err)
	}
	if !containsID(held.Require, now) || containsID(held.Retired, old) {
		t.Errorf("the pin written before activation = %s; want the new key required and the old one not yet retired", held.Marshal())
	}
	final := ps.pin(t)
	if !containsID(final.Require, now) || !containsID(final.Retired, old) {
		t.Errorf("the final pin = %s; want the new key required and the old one retired", final.Marshal())
	}
	for i := range 2 {
		if p := base.replica(i).pin; p == nil || !p.Equal(final) {
			t.Errorf("replica %d enforces %v; want the final pin, handed over live", i, p)
		}
	}
}

// The high finding of the 2026-10-08 review. A rotation from a keyring the
// fleet refuses as behind must not move the pin: raised from it, the pin would
// refuse the machine whose keys the fleet actually serves.
func TestARotationRefusedAsBehindLeavesThePinAlone(t *testing.T) {
	dir, meta, env, _ := handOverInstance(t, "p310")
	k := scopedKeyring(t, dir, "p310", "demo", "alpha")
	fleet := servingFleet(t, env, meta, dir)
	// Another machine rotated and the fleet serves its keys — but its pin
	// write failed, so the stored pin still says only what this keyring has.
	theirs, _, err := k.RotateScopeKEKs()
	if err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		fleet.replica(i).keys = heldKeys(theirs)
	}
	ps := pinStoreOf(dir, "p310")
	ps.set(pinFor(k).Marshal())
	stored := ps.value

	err = (&keyRotateCommand{assumeYes: true, newKeyholder: openerFor(fleet)}).Run(context.Background(), env, []string{"p310"})
	if err == nil {
		t.Fatal("a rotation from a keyring behind the fleet succeeded")
	}
	if ps.value != stored {
		t.Errorf("the pin moved from a keyring the fleet refused: %s", ps.value)
	}
	for i := range 2 {
		if p := fleet.replica(i).pin; p != nil && p.Admits(heldKeys(theirs)) != nil {
			t.Errorf("replica %d now refuses the keyring it serves: %v", i, p)
		}
	}
}

// What an import of another machine's rotation leaves: every key the pin
// requires, and this machine's own retired key still in use. With every
// replica sealed, neither unseal nor rotate from here gets past the pin; the
// way out the refusal names — key pin --replace, which stops retiring that
// key and keeps every key required — works, and then unseal and rotate do.
func TestAnImportedKeyringOnARetiredKeyHasAWayOut(t *testing.T) {
	dir, meta, env, _, before := backdatedInstance(t, "p311", "alpha")
	base := servingFleet(t, env, meta, dir)
	mustRotate(t, env, "p311", base) // the machine that rotated: the pin now retires the old key
	rotated := liveKeyring(t, dir, "p311")
	merged, err := before.Merge(rotated) // this machine imported it, and kept its own key in use
	if err != nil {
		t.Fatal(err)
	}
	saveKeyring(t, dir, "p311", merged)
	for i := range 2 {
		base.replica(i).phase, base.replica(i).keys = "restart-sealed", nil
	}
	stored := pinStoreOf(dir, "p311").pin(t)

	unseal := func() error {
		return (&storageUnsealCommand{newKeyholder: openerFor(base)}).Run(context.Background(), env, []string{"p311"})
	}
	err = unseal()
	if err == nil || !strings.Contains(err.Error(), "farcast storage key pin p311 --replace") {
		t.Fatalf("unseal from the imported keyring = %v; want it refused, naming the way out", err)
	}
	if err := (&keyPinCommand{replace: true, assumeYes: true, newKeyholder: openerFor(base)}).Run(context.Background(), env, []string{"p311"}); err != nil {
		t.Fatalf("key pin --replace: %v", err)
	}
	after := pinStoreOf(dir, "p311").pin(t)
	for _, id := range stored.Require {
		if !containsID(after.Require, id) {
			t.Errorf("--replace dropped required key %s", id)
		}
	}
	if err := unseal(); err != nil {
		t.Fatalf("unseal after key pin --replace: %v", err)
	}
	mustRotate(t, env, "p311", base)
	noSplit(t, base)
	writesUnderHeldKeys(t, dir, "p311", base)
}

// A rotation whose new keys reached no replica puts this machine back on the
// old ones, so the old ones must not be retired: this machine's own next unseal
// would be refused.
func TestARotationPutBackRetiresNothing(t *testing.T) {
	dir, meta, env, _, before := backdatedInstance(t, "p302", "alpha")
	base := servingFleet(t, env, meta, dir)
	old := scopeKEK(before)
	rotateWith(t, env, "p302", &flakyKeyholder{fakeStateKeyholder: base, refuseNth: map[int]int{0: 2, 1: 2}})
	if scopeKEK(liveKeyring(t, dir, "p302")) != old {
		t.Fatal("guard: this machine was not put back on the old key")
	}
	if p := pinStoreOf(dir, "p302").pin(t); containsID(p.Retired, old) {
		t.Errorf("the pin retired the key this machine was put back on: %s", p.Marshal())
	}
	if err := (&storageUnsealCommand{newKeyholder: openerFor(base)}).Run(context.Background(), env, []string{"p302"}); err != nil {
		t.Errorf("this machine's own unseal after a put-back: %v", err)
	}
}

// The keys move whether or not the pin does; a pin that could not be written
// is a rotation that has not finished what it is for, and says how to finish.
func TestARotationWhosePinCannotBeWrittenFailsAndSaysSo(t *testing.T) {
	dir, meta, env, out := handOverInstance(t, "p303")
	scopedKeyring(t, dir, "p303", "demo", "alpha")
	base := servingFleet(t, env, meta, dir)
	broken := &fakePinStore{failRead: errors.New("the credentials have expired")}
	err := (&keyRotateCommand{assumeYes: true, newKeyholder: openerFor(base),
		newPinStore: func(string) (pinStore, error) { return broken, nil }}).Run(context.Background(), env, []string{"p303"})
	if err == nil || !strings.Contains(err.Error(), "farcast storage key pin p303") {
		t.Fatalf("rotate = %v; want a failure naming 'farcast storage key pin'", err)
	}
	if !strings.Contains(out.String(), "NOT written") || !strings.Contains(out.String(), "credentials have expired") {
		t.Errorf("the result does not say the pin was not written, or why:\n%s", out.String())
	}
	if !sameKeys(base.replica(0).keys, heldKeys(liveKeyring(t, dir, "p303"))) {
		t.Error("guard: the rotation itself did not happen")
	}
}

// A keyring the pin says is behind mints nothing.
func TestARotationFromBehindThePinMintsNothing(t *testing.T) {
	dir, meta, env, _ := handOverInstance(t, "p304")
	k := scopedKeyring(t, dir, "p304", "demo", "alpha")
	servingFleet(t, env, meta, dir)
	elsewhere, _, err := k.RotateScopeKEKs()
	if err != nil {
		t.Fatal(err)
	}
	pinStoreOf(dir, "p304").set(pinFor(elsewhere).Marshal())
	raw, err := dir.LoadInstanceKeyring("p304")
	if err != nil {
		t.Fatal(err)
	}
	err = (&keyRotateCommand{assumeYes: true, newKeyholder: openerFor(&fakeStateKeyholder{phase: "unsealed"})}).
		Run(context.Background(), env, []string{"p304"})
	if err == nil || !strings.Contains(err.Error(), "nothing was rotated") {
		t.Fatalf("rotate = %v; want it refused before minting", err)
	}
	if after, _ := dir.LoadInstanceKeyring("p304"); string(after) != string(raw) {
		t.Error("a refused rotation changed keys.yaml")
	}
}

// run requires a new application's keys before any replica is handed them.
func TestRunRaisesThePinBeforeHandingOverTheScope(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meta := runnableInstance(t, dir, "p305")
	meta.Keyholder = &config.Keyholder{Deployed: true, Replicas: 2}
	if err := dir.SaveInstanceMetadata("p305", meta); err != nil {
		t.Fatal(err)
	}
	mintKeyring(t, dir, "p305")
	var log []string
	ps := pinStoreOf(dir, "p305")
	ps.log = &log
	fleet := &fakeStateKeyholder{phase: "unsealed"}
	env, _, _ := testEnvBoth(dir, output.ModeHuman)
	c := runCmd(newFakeRun(twoAppManifest))
	c.newKeyholder = openerFor(&loggingFleet{fleet, &log})
	if err := c.Run(context.Background(), env, []string{"p305", "github.com/example/my-platform"}); err != nil {
		t.Fatal(err)
	}
	if p, q := firstIndex(log, "pin "), firstIndex(log, "push "); p < 0 || q < 0 || p > q {
		t.Fatalf("log %v: the pin must be raised before the first push", log)
	}
	keys := liveKeyring(t, dir, "p305")
	if err := ps.pin(t).Admits(heldKeys(keys)); err != nil || len(ps.pin(t).Require) == 0 {
		t.Errorf("the pin %s does not require the new scopes' keys: %v", ps.value, err)
	}
	if len(ps.pin(t).Retired) != 0 {
		t.Errorf("run retired a key: %s", ps.value)
	}
	if fleet.replica(0).pin == nil || !fleet.replica(0).pin.Equal(ps.pin(t)) {
		t.Errorf("replica 0 was not handed the pin live: %v", fleet.replica(0).pin)
	}
}

// Nothing about the pin fails a deploy: the workloads are what was asked for.
func TestRunThatCannotRaiseThePinWarnsAndDeploys(t *testing.T) {
	dir := config.Dir(t.TempDir())
	meta := runnableInstance(t, dir, "p306")
	meta.Keyholder = &config.Keyholder{Deployed: true, Replicas: 2}
	if err := dir.SaveInstanceMetadata("p306", meta); err != nil {
		t.Fatal(err)
	}
	mintKeyring(t, dir, "p306")
	env, _, errBuf := testEnvBoth(dir, output.ModeHuman)
	c := runCmd(newFakeRun(twoAppManifest))
	c.newKeyholder = openerFor(&fakeStateKeyholder{phase: "unsealed"})
	c.newPinStore = func(string) (pinStore, error) { return &fakePinStore{failWrite: errors.New("forbidden")}, nil }
	if err := c.Run(context.Background(), env, []string{"p306", "github.com/example/my-platform"}); err != nil {
		t.Fatalf("run failed on the pin: %v", err)
	}
	if !strings.Contains(errBuf.String(), "key pin was not raised") || !strings.Contains(errBuf.String(), "farcast storage key pin p306") {
		t.Errorf("run did not say the pin was not raised, or how to raise it:\n%s", errBuf.String())
	}
}

// storage deploy writes the pin before anything is applied — the kernel may
// create ConfigMaps in that namespace — and a pin it cannot write deploys
// nothing.
func TestStorageDeployWritesThePinBeforeApplying(t *testing.T) {
	dir := config.Dir(t.TempDir())
	deployableInstance(t, dir, "prod")
	fc := &fakeCluster{}
	c := testStorageDeploy(&fakeProvider{}, &fakeBuilder{})
	c.deployer.assumeYes = true
	c.deployer.newCluster = func(string) clusterApplier { return fc }
	env, _ := testEnv(dir, output.ModeHuman)
	if err := c.Run(context.Background(), env, []string{"prod"}); err != nil {
		t.Fatal(err)
	}
	if ps := pinStoreOf(dir, "prod"); !ps.exists {
		t.Error("deploy did not create the pin")
	}

	dir = config.Dir(t.TempDir())
	deployableInstance(t, dir, "prod")
	fc = &fakeCluster{}
	c = testStorageDeploy(&fakeProvider{}, &fakeBuilder{})
	c.deployer.assumeYes = true
	c.deployer.newCluster = func(string) clusterApplier { return fc }
	c.newPinStore = func(string) (pinStore, error) { return &fakePinStore{failWrite: errors.New("forbidden")}, nil }
	env, _ = testEnv(dir, output.ModeHuman)
	if err := c.Run(context.Background(), env, []string{"prod"}); err == nil || !strings.Contains(err.Error(), "nothing was deployed") {
		t.Fatalf("deploy with an unwritable pin = %v", err)
	}
	if len(fc.applied) != 0 {
		t.Error("deploy applied the keyholder without its pin")
	}
}

// A deploy restarts every replica, each into the pin; from a keyring the pin
// refuses, nothing here could unseal them again. Refused before the cost gate.
func TestStorageDeployFromBehindThePinRefusesBeforeSpending(t *testing.T) {
	dir := config.Dir(t.TempDir())
	deployableInstance(t, dir, "prod")
	k := scopedKeyring(t, dir, "prod", "demo", "alpha")
	elsewhere, _, err := k.RotateScopeKEKs()
	if err != nil {
		t.Fatal(err)
	}
	pinStoreOf(dir, "prod").set(pinFor(elsewhere).Marshal())
	fc := &fakeCluster{}
	c := testStorageDeploy(&fakeProvider{}, &fakeBuilder{}) // no --yes: the cost gate would refuse too
	c.deployer.newCluster = func(string) clusterApplier { return fc }
	env, _ := testEnv(dir, output.ModeHuman)
	err = c.Run(context.Background(), env, []string{"prod"})
	if err == nil || !strings.Contains(err.Error(), "behind the instance's key pin") {
		t.Fatalf("deploy = %v; want it refused as behind the pin, before the cost gate", err)
	}
	if len(fc.applied) != 0 {
		t.Error("deploy applied something")
	}
}

// An unseal from a keyring a replica's pin refuses pushes nothing, says what is
// behind and what to do; --below-pin is the operator's way past it.
func TestUnsealBelowThePinRefusesUnlessAsked(t *testing.T) {
	dir, meta, env, _ := handOverInstance(t, "p307")
	k := scopedKeyring(t, dir, "p307", "demo", "alpha")
	fleet := &fakeStateKeyholder{phase: "restart-sealed"}
	elsewhere, _, err := k.RotateScopeKEKs()
	if err != nil {
		t.Fatal(err)
	}
	p := pinFor(elsewhere)
	for i := range 2 {
		fleet.replica(i).pin = &p
	}
	_ = meta

	err = (&storageUnsealCommand{newKeyholder: openerFor(fleet)}).Run(context.Background(), env, []string{"p307"})
	if err == nil || !strings.Contains(err.Error(), "enforces the instance's key pin") || !strings.Contains(err.Error(), "--below-pin") || fleet.pushes != 0 {
		t.Fatalf("unseal below the pin = %v after %d pushes; want refused, naming --below-pin, nothing pushed", err, fleet.pushes)
	}
	if err := (&storageUnsealCommand{newKeyholder: openerFor(fleet), belowPin: true}).Run(context.Background(), env, []string{"p307"}); err != nil {
		t.Fatalf("unseal --below-pin: %v", err)
	}
	for _, intent := range fleet.intents {
		if intent != keyholder.IntentOperatorBelowPin {
			t.Errorf("pushed with intent %q; want the below-pin override", intent)
		}
	}
	for i := range 2 {
		st, _ := fleet.State(context.Background(), i)
		if st.Sealed() || st.Pin == nil || !st.Pin.ServingBelow {
			t.Errorf("replica %d: phase %s, pin %+v; want unsealed and reporting it serves below the pin", i, st.Phase, st.Pin)
		}
	}
}

func TestStorageStateReportsEachReplicasPin(t *testing.T) {
	dir, meta, env, out := handOverInstance(t, "p308")
	scopedKeyring(t, dir, "p308", "demo", "alpha")
	base := servingFleet(t, env, meta, dir)
	mustRotate(t, env, "p308", base)
	base.replica(1).pin = nil
	out.out.Reset()
	if err := (&storageStateCommand{newKeyholder: openerFor(base)}).Run(context.Background(), env, []string{"p308"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.out.String(), "key pin: none loaded") {
		t.Errorf("a replica with no pin loaded is not reported:\n%s", out.out.String())
	}
	if strings.Count(out.out.String(), "key pin:") != 1 {
		t.Errorf("a replica whose pin is current was reported:\n%s", out.out.String())
	}
	// A pin that requires less than this keyring holds is behind it.
	base.replica(1).pin = &dskeyholder.Pin{}
	out.out.Reset()
	if err := (&storageStateCommand{newKeyholder: openerFor(base)}).Run(context.Background(), env, []string{"p308"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.out.String(), "behind this machine's keyring") {
		t.Errorf("a pin behind this keyring is not reported:\n%s", out.out.String())
	}

	// A pin that requires a key this keyring lacks: serving, the replica
	// says it serves below it; sealed, that this keyring is behind.
	extra := keyID(t, "00000000000000aa")
	p := *base.replica(0).pin
	p.Require = append(p.Require, extra)
	base.replica(0).pin = &p
	out.out.Reset()
	if err := (&storageStateCommand{newKeyholder: openerFor(base)}).Run(context.Background(), env, []string{"p308"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.out.String(), "serves keys its own pin refuses") {
		t.Errorf("a replica serving below its pin is not reported:\n%s", out.out.String())
	}
	base.replica(0).phase, base.replica(0).keys = "restart-sealed", nil
	out.out.Reset()
	if err := (&storageStateCommand{newKeyholder: openerFor(base)}).Run(context.Background(), env, []string{"p308"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.out.String(), "refuses this machine's keyring") {
		t.Errorf("a pin ahead of this keyring is not reported:\n%s", out.out.String())
	}
}

func keyID(t *testing.T, s string) datasphere.KeyID {
	t.Helper()
	id, err := datasphere.ParseKeyID(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// A write that does not retire must not un-retire what an earlier one did:
// run writes without retiring, and dropping the retired set there would
// re-admit every bundle the last rotation retired.
func TestWritePinNeverDropsWhatWasRetired(t *testing.T) {
	ctx := context.Background()
	ps := &fakePinStore{}
	k := appsKeyring(t, "web")
	rotated, rots, err := k.RotateScopeKEKs()
	if err != nil {
		t.Fatal(err)
	}
	// Retire the old key by hand: same-second keys are never retired by
	// pinFor, and the property is about what is already in the pin.
	ps.set(dskeyholder.Pin{Require: pinFor(rotated).Require, Retired: []datasphere.KeyID{rots[0].Previous}}.Marshal())
	grown, err := rotated.AddScope(mustAppScope(t, "api"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writePin(ctx, ps, grown, false, false); err != nil {
		t.Fatal(err)
	}
	if p := ps.pin(t); !containsID(p.Retired, rots[0].Previous) {
		t.Errorf("a write that does not retire dropped the retired key: %s", p.Marshal())
	}
}

// A write that landed and lost its answer is success, found by reading back.
func TestWritePinThatLandedButLostItsAnswerSucceeds(t *testing.T) {
	ps := &fakePinStore{loseAnswer: true}
	w, err := writePin(context.Background(), ps, appsKeyring(t, "web"), true, false)
	if err != nil || !w.Changed {
		t.Fatalf("= %+v, %v; want the landed write reported as written", w, err)
	}
	if ps.version != 1 {
		t.Errorf("the pin was written %d times; a lost answer must not cause a second write", ps.version)
	}
}

// The ConfigMap's pin is checked before the hold is saved, not only the
// replicas' copies: a replica that did not take the last raise enforces an
// older pin, and this machine must not be left writing under a retired key.
func TestARotationChecksTheHoldAgainstTheStoredPinToo(t *testing.T) {
	dir, meta, env, _, before := backdatedInstance(t, "p309", "alpha")
	base := servingFleet(t, env, meta, dir)
	mustRotate(t, env, "p309", base)
	base.replica(1).keys = heldKeys(before)
	for i := range 2 {
		base.replica(i).pin = nil // neither took the raise
	}
	using := scopeKEK(liveKeyring(t, dir, "p309"))
	err := (&keyRotateCommand{assumeYes: true, newKeyholder: openerFor(base)}).Run(context.Background(), env, []string{"p309"})
	if err == nil || !strings.Contains(err.Error(), "farcast storage key rotate p309") {
		t.Fatalf("rotate = %v; want it unfinished", err)
	}
	if got := scopeKEK(liveKeyring(t, dir, "p309")); got != using {
		t.Errorf("this machine now writes under %s, a key the stored pin retired; it was on %s", got, using)
	}
}

// A keeper whose read showed nothing wrong, and whose push the keyholder then
// refused on the pin — the pin moved in between — records a stale bundle,
// not an unreachable replica.
func TestAKeeperRefusedOnThePinAtThePushReportsStale(t *testing.T) {
	env, dir, store, cfg := installedKeeper(t)
	meta, err := dir.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatal(err)
	}
	fleet := servingFleet(t, env, meta, dir)
	mustRotate(t, env, "prod", fleet)
	fleet.replica(0).phase, fleet.replica(0).keys, fleet.replica(0).generation = "restart-sealed", nil, 0
	fleet.replica(1).phase, fleet.replica(1).keys, fleet.replica(1).generation = "restart-sealed", nil, 0
	decisions, err := keeperCheckWith(context.Background(), env, store, cfg, &pinHiddenAtRead{fleet}, storeBundle(t, store))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range decisions {
		if d.Action != keeper.ActionStale || !strings.Contains(d.Reason, "re-enrol") {
			t.Errorf("replica %d: %s (%s); want stale, naming re-enrolment", d.Ordinal, d.Action, d.Reason)
		}
	}
}

// pinHiddenAtRead reports no pin when asked, and enforces it on a push: the
// pin was raised between the keeper's read and its push.
type pinHiddenAtRead struct{ *fakeStateKeyholder }

func (p *pinHiddenAtRead) State(ctx context.Context, i int) (keyholder.State, error) {
	st, err := p.fakeStateKeyholder.State(ctx, i)
	st.Pin = nil
	return st, err
}

// --replace lowers what the replicas enforce even once the ConfigMap is no
// longer above this keyring — the case where a lowering missed a replica, or
// the ConfigMap was deleted under a replica that kept a higher pin.
func TestKeyPinReplaceLowersAReplicaAboveTheConfigMap(t *testing.T) {
	dir, _, env, _ := handOverInstance(t, "p312")
	keys := scopedKeyring(t, dir, "p312", "apps", "web")
	rotated, _, err := keys.RotateScopeKEKs()
	if err != nil {
		t.Fatal(err)
	}
	pinStoreOf(dir, "p312").set(pinFor(keys).Marshal()) // already this keyring's
	kh := &fakeStateKeyholder{phase: "unsealed"}
	higher := pinFor(rotated)
	kh.replica(1).pin = &higher

	// Without --replace it is reported, not claimed as enforced.
	out := &bytes.Buffer{}
	env.Out, env.Printer.Out = out, out
	if err := (&keyPinCommand{newKeyholder: openerFor(kh)}).Run(context.Background(), env, []string{"p312"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "still enforces a pin above this keyring's") {
		t.Errorf("a replica above this keyring was reported as enforcing it:\n%s", out.String())
	}
	if err := (&keyPinCommand{replace: true, assumeYes: true, newKeyholder: openerFor(kh)}).Run(context.Background(), env, []string{"p312"}); err != nil {
		t.Fatal(err)
	}
	if p := kh.replica(1).pin; p == nil || p.Admits(heldKeys(keys)) != nil {
		t.Errorf("after --replace replica 1 still refuses this keyring: %v", p)
	}
}

// A pin that grows past what a replica reads is not written; and one already
// stored past it is read as the pin it is, so no keyring can lower it as a
// "repair" of something corrupt.
func TestThePinNeverGrowsPastWhatAReplicaReads(t *testing.T) {
	var many dskeyholder.Pin
	for i := range dskeyholder.MaxPinBytes/19 + 10 {
		id, err := datasphere.ParseKeyID(fmt.Sprintf("%016x", i+1))
		if err != nil {
			t.Fatal(err)
		}
		many.Require = append(many.Require, id)
	}
	raw := many.Marshal()
	if len(raw) <= dskeyholder.MaxPinBytes {
		t.Fatalf("guard: %d bytes is not past the cap", len(raw))
	}
	if _, _, err := dskeyholder.ParsePin(raw); err == nil {
		t.Fatal("guard: a replica read an oversize pin")
	}
	ps := &fakePinStore{}
	ps.set(raw)
	stored := ps.value
	var behind *pinBehind
	if _, err := writePin(context.Background(), ps, appsKeyring(t, "web"), true, false); !errors.As(err, &behind) || ps.value != stored {
		t.Errorf("a keyring behind an oversize pin = %v; want it refused as behind, the pin untouched", err)
	}
}

// A keyring with more keys than one pin can carry is refused before anything
// is written: a pin no replica can read would turn every keeper away.
func TestWritePinRefusesAPinNoReplicaCouldRead(t *testing.T) {
	k := appsKeyring(t, "web")
	for len(pinFor(k).Marshal()) <= dskeyholder.MaxPinBytes {
		for range 500 {
			var err error
			if k, _, err = k.RotateScopeKEKs(); err != nil {
				t.Fatal(err)
			}
		}
	}
	ps := &fakePinStore{}
	if _, err := writePin(context.Background(), ps, k, true, false); err == nil || !strings.Contains(err.Error(), "more than") || ps.exists {
		t.Errorf("an oversize pin = %v, written %v; want it refused and nothing written", err, ps.exists)
	}
}
