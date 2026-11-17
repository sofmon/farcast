package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
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
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	"github.com/sofmon/farcast/planck"
	tkube "github.com/sofmon/farcast/technocore/kube"
)

// Every test that does not bring its own pin store gets one in memory, per
// instance (its config directory and name), so no test reaches a cluster for
// the pin. The pin is the writer's (ADR 0023 M2.5), so a command that opens
// it as anything else is refused here too; a plan reads it through a
// read-only view of the same store, as the reader (testPinPlanReader, ADR
// 0023 M2.6c).
var testPinStores = struct {
	sync.Mutex
	by map[string]*fakePinStore
}{by: map[string]*fakePinStore{}}

// testPinStoreFor is the instance's in-memory pin store, made on first use.
func testPinStoreFor(dir config.Dir, instance string) *fakePinStore {
	key := string(dir) + "/" + instance
	testPinStores.Lock()
	defer testPinStores.Unlock()
	ps, ok := testPinStores.by[key]
	if !ok {
		ps = &fakePinStore{}
		testPinStores.by[key] = ps
	}
	return ps
}

// testDefaultPinStore is the default the tests install in place of
// openPinStore. It records the open as the writer's.
func testDefaultPinStore(r clusterRef) (pinStore, error) {
	if r.Meta == nil || r.Identity != kube.Writer {
		return nil, fmt.Errorf("test pin store: the pin opens as the instance's writer, not %q", r.Identity)
	}
	ps := testPinStoreFor(r.Dir, r.Meta.Name)
	ps.openedAs(r.Identity)
	return ps, nil
}

// testPinPlanReader is a plan's reader of the in-memory pin (A23-20): a
// read-only view of the instance's same store, opened only as the reader,
// and recorded as the reader's open.
func testPinPlanReader(r clusterRef) (pinPlanReader, error) {
	if r.Meta == nil || r.Identity != kube.Reader {
		return nil, fmt.Errorf("test pin reader: a plan reads the pin as the instance's reader, not %q", r.Identity)
	}
	ps := testPinStoreFor(r.Dir, r.Meta.Name)
	ps.openedAs(r.Identity)
	return pinReadView{ps}, nil
}

// pinReadView is a read-only view of a fakePinStore: a pinPlanReader and
// never a pinStore, so a plan holding it cannot write.
type pinReadView struct{ ps *fakePinStore }

func (v pinReadView) ConfigMapData(ctx context.Context, namespace, name string) (map[string]string, string, bool, error) {
	return v.ps.ConfigMapData(ctx, namespace, name)
}

func (v pinReadView) NamespaceUID(ctx context.Context, name string) (string, error) {
	return v.ps.NamespaceUID(ctx, name)
}

// The read-only view reads and cannot write.
var _ pinPlanReader = pinReadView{}

func init() {
	defaultPinStore = testDefaultPinStore
}

// pinStoreOf is the in-memory pin a test's instance got by default.
func pinStoreOf(dir config.Dir, instance string) *fakePinStore {
	return testPinStoreFor(dir, instance)
}

// fakePinStore is the pin ConfigMap with the API server's own rules: create
// fails over an existing one, and replace fails at a stale resourceVersion,
// each as tkube.ErrConflict, as the cluster client returns them (A20-7).
type fakePinStore struct {
	mu      sync.Mutex
	exists  bool
	value   string
	version int
	// failRead and failWrite make the next calls fail as infrastructure does.
	failRead, failWrite error
	// uid and uidErr answer NamespaceUID: farcast-system's uid, "" for none.
	uid    string
	uidErr error
	// opened is the identity each open of the store asked for, in order:
	// the writer's (testDefaultPinStore) or the reader's
	// (testPinPlanReader).
	opened []kube.Identity
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

// openedAs records an open of the store as id.
func (f *fakePinStore) openedAs(id kube.Identity) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opened = append(f.opened, id)
}

// openedBy is the identities the store was opened as, in order.
func (f *fakePinStore) openedBy() []kube.Identity {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.opened)
}

func (f *fakePinStore) NamespaceUID(context.Context, string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.uid, f.uidErr
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
		return fmt.Errorf("AlreadyExists: %w", tkube.ErrConflict)
	case !create && (!f.exists || doc.Metadata.ResourceVersion != strconv.Itoa(f.version)):
		return fmt.Errorf("Conflict: %w", tkube.ErrConflict)
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
	w, err := writePinLoop(ctx, ps, k, true, false)
	if err != nil || !w.Changed || !w.Created || !ps.exists {
		t.Fatalf("create = %+v, %v", w, err)
	}
	before := ps.version
	if w, err := writePinLoop(ctx, ps, k, true, false); err != nil || w.Changed || ps.version != before {
		t.Errorf("an unchanged pin was rewritten: %+v, %v", w, err)
	}

	rotated, _, err := k.RotateScopeKEKs()
	if err != nil {
		t.Fatal(err)
	}
	if w, err := writePinLoop(ctx, ps, rotated, true, false); err != nil || !w.Changed || w.Created {
		t.Fatalf("raise = %+v, %v; want changed, and not created", w, err)
	}
	if got := ps.pin(t); !got.Equal(pinFor(rotated).Union(pinFor(k))) {
		t.Errorf("raised to %s", got.Marshal())
	}
	stored := ps.value
	var behind *pinBehind
	if _, err := writePinLoop(ctx, ps, k, true, false); !errors.As(err, &behind) || ps.value != stored {
		t.Errorf("an older keyring = %v, and the pin is %s; want refused and unchanged", err, ps.value)
	}
	// Replace is the operator lowering it on purpose.
	if w, err := writePinLoop(ctx, ps, k, true, true); err != nil || !w.Pin.Equal(pinFor(k)) {
		t.Errorf("replace = %+v, %v", w, err)
	}
}

// A write is over what was read. Another writer between the read and the write
// is taken into account, not overwritten.
func TestWritePinNeverWritesOverAnotherWriter(t *testing.T) {
	ctx := context.Background()
	ps := &fakePinStore{}
	k := appsKeyring(t, "web")
	if _, err := writePinLoop(ctx, ps, k, true, false); err != nil {
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
	w, err := writePinLoop(ctx, ps, mine, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := ps.pin(t); !got.Equal(w.Pin) || !got.Equal(pinFor(mine).Union(pinFor(other))) {
		t.Errorf("stored %s; want the union of both writers", got.Marshal())
	}
	// Infrastructure failing is an error, not a silent success.
	ps.failWrite = errors.New("credentials expired")
	if _, err := writePinLoop(ctx, ps, appsKeyring(t, "fresh"), true, true); err == nil || !strings.Contains(err.Error(), "credentials expired") {
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
			if _, err := writePinLoop(ctx, ps, k, r.IntN(2) == 0, false); err != nil {
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

// keyPinRefusalNamesThePlan is TestNonInteractiveRefusalsNameThePlan's row
// for storage key pin (ADR 0023 M2.6c): lowering the pin with --replace,
// with no terminal and no --yes, is refused naming the plan's route, and the
// pin is left as it was.
func keyPinRefusalNamesThePlan(t *testing.T) {
	dir, _, env, _ := handOverInstance(t, "p321")
	keys := scopedKeyring(t, dir, "p321", "apps", "web")
	rotated, _, err := keys.RotateScopeKEKs()
	if err != nil {
		t.Fatal(err)
	}
	ps := pinStoreOf(dir, "p321")
	ps.set(pinFor(rotated).Marshal())
	stored := ps.value
	c := withFlags(t, &keyPinCommand{}, "--replace")
	c.newKeyholder = openerFor(&fakeStateKeyholder{phase: "unsealed"})
	err = c.Run(t.Context(), env, []string{"p321"})
	if err == nil || err.Error() != msgKeyPinLowerYes || exitCodeOf(err) != 2 || !strings.HasSuffix(msgKeyPinLowerYes, consentSuffix) {
		t.Errorf("storage key pin --replace with no terminal = %v (exit %d); want %q", err, exitCodeOf(err), msgKeyPinLowerYes)
	}
	if ps.value != stored {
		t.Errorf("a refused lowering wrote the pin %s", ps.value)
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
		newPinStore: func(clusterRef) (pinStore, error) { return broken, nil }}).Run(context.Background(), env, []string{"p303"})
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
	c.newPinStore = func(clusterRef) (pinStore, error) { return &fakePinStore{failWrite: errors.New("forbidden")}, nil }
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
	c.deployer.newCluster = func(clusterRef) (clusterApplier, error) { return fc, nil }
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
	c.deployer.newCluster = func(clusterRef) (clusterApplier, error) { return fc, nil }
	c.newPinStore = func(clusterRef) (pinStore, error) { return &fakePinStore{failWrite: errors.New("forbidden")}, nil }
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
	c.deployer.newCluster = func(clusterRef) (clusterApplier, error) { return fc, nil }
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
	if _, err := writePinLoop(ctx, ps, grown, false, false); err != nil {
		t.Fatal(err)
	}
	if p := ps.pin(t); !containsID(p.Retired, rots[0].Previous) {
		t.Errorf("a write that does not retire dropped the retired key: %s", p.Marshal())
	}
}

// A write that landed and lost its answer is success, found by reading back.
func TestWritePinThatLandedButLostItsAnswerSucceeds(t *testing.T) {
	ps := &fakePinStore{loseAnswer: true}
	w, err := writePinLoop(context.Background(), ps, appsKeyring(t, "web"), true, false)
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
	pass, err := keeperCheckWith(context.Background(), env, store, cfg, &pinHiddenAtRead{fleet}, storeBundle(t, store))
	if err != nil {
		t.Fatal(err)
	}
	decisions := pass.Decisions
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
	if _, err := writePinLoop(context.Background(), ps, appsKeyring(t, "web"), true, false); !errors.As(err, &behind) || ps.value != stored {
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
	if _, err := writePinLoop(context.Background(), ps, k, true, false); err == nil || !strings.Contains(err.Error(), "more than") || ps.exists {
		t.Errorf("an oversize pin = %v, written %v; want it refused and nothing written", err, ps.exists)
	}
}

// A pin written where there was none is reported as written, not raised: the
// 2026-11-10 walk deleted the ConfigMap and was told the pin was "raised".
func TestKeyPinReportsARecreatedPinAsWritten(t *testing.T) {
	dir, _, env, _ := handOverInstance(t, "p320")
	keys := scopedKeyring(t, dir, "p320", "apps", "web", "api")
	out := &bytes.Buffer{}
	env.Out, env.Printer.Out = out, out
	kh := &fakeStateKeyholder{phase: "unsealed"}
	if err := (&keyPinCommand{newKeyholder: openerFor(kh)}).Run(context.Background(), env, []string{"p320"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `wrote the key pin of "p320" from this keyring; there was none`) || strings.Contains(out.String(), "raised") {
		t.Errorf("a pin created over nothing was not reported as written:\n%s", out.String())
	}

	// A pin that requires less than this keyring holds is raised.
	full := pinFor(keys)
	if len(full.Require) < 2 {
		t.Fatalf("the fixture's pin requires %d key(s); a raise needs a smaller one below it", len(full.Require))
	}
	pinStoreOf(dir, "p320").set(dskeyholder.Pin{Require: full.Require[:1]}.Marshal())
	out.Reset()
	if err := (&keyPinCommand{newKeyholder: openerFor(kh)}).Run(context.Background(), env, []string{"p320"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `raised the key pin of "p320"`) || strings.Contains(out.String(), "there was none") {
		t.Errorf("a raise over an existing pin was not reported as a raise:\n%s", out.String())
	}
}

// ADR 0023 M2.6c: storage key pin and storage deploy through --plan and
// --confirm, against fakes. The fixture is writeInstance's, so the instance
// has a reader 'reader grant' verified; the plan reads the in-memory pin as
// the reader, through its read-only view (testPinPlanReader), and the writer
// writes the same pin; nothing reaches the fixture's kubetest server.

// keyPinFixture is writeInstance's instance (its keyring holds one
// application scope), its pin the instance's in-memory one, and its
// keyholder's replicas kh's: the keyring and the pin store.
func keyPinFixture(t *testing.T) (config.Dir, datasphere.Keyring, *fakePinStore) {
	t.Helper()
	dir, _ := writeInstance(t, kubetest.New(t), true)
	keys, err := keyringOf(&Env{ConfigDir: dir}, writeName)
	if err != nil {
		t.Fatal(err)
	}
	return dir, keys, pinStoreOf(dir, writeName)
}

// keyPinPlanCmd is storage key pin with its flags parsed, reading the pin
// as the reader through its read-only view and handing it to kh.
func keyPinPlanCmd(t *testing.T, kh sealStateClient, flags ...string) *keyPinCommand {
	t.Helper()
	c := withFlags(t, &keyPinCommand{}, flags...)
	c.newPlanReader = testPinPlanReader
	c.newKeyholder = noKeyholder
	if kh != nil {
		c.newKeyholder = openerFor(kh)
	}
	return c
}

// runKeyPinPlan runs key pin with --plan and flags, in JSON mode with no
// terminal, and returns its plan.
func runKeyPinPlan(t *testing.T, dir config.Dir, kh sealStateClient, flags ...string) plan.Document {
	t.Helper()
	env, out, errb := testEnvBoth(dir, output.ModeJSON)
	if err := keyPinPlanCmd(t, kh, append(slices.Clone(flags), "--plan")...).Run(t.Context(), env, []string{writeName}); err != nil {
		t.Fatalf("storage key pin --plan: %v\n%s", err, errb)
	}
	return printedDocument(t, out.Bytes())
}

// runKeyPinConfirm runs key pin with --confirm of doc and flags, in JSON
// mode with no terminal: what it printed, and its error.
func runKeyPinConfirm(t *testing.T, dir config.Dir, kh sealStateClient, doc plan.Document, flags ...string) (stdout, stderr string, err error) {
	t.Helper()
	env, out, errb := testEnvBoth(dir, output.ModeJSON)
	err = keyPinPlanCmd(t, kh, append(slices.Clone(flags), "--confirm", doc.Digest)...).Run(t.Context(), env, []string{writeName})
	return out.String(), errb.String(), err
}

// pinFactOf is the one pin fact a plan carries.
func pinFactOf(t *testing.T, b plan.Bound) plan.PinFact {
	t.Helper()
	var found []plan.PinFact
	for _, f := range b.Facts {
		if p, ok := f.(plan.PinFact); ok {
			found = append(found, p)
		}
	}
	if len(found) != 1 {
		t.Fatalf("the plan carries %d pin facts; want one", len(found))
	}
	return found[0]
}

// pinOfFact is a pin fact as a pin.
func pinOfFact(t *testing.T, f plan.PinFact) dskeyholder.Pin {
	t.Helper()
	p, ok := pinFromReport(&dskeyholder.PinReport{Require: f.Require, Retired: f.Retired})
	if !ok {
		t.Fatalf("the pin fact %+v holds an id that is not a key id", f)
	}
	return p
}

// foreignID is foreignKeyID as a key id.
func foreignID(t *testing.T) datasphere.KeyID {
	t.Helper()
	id, err := datasphere.ParseKeyID(foreignKeyID)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// storageRig is storage deploy against writeInstance's fixture, its
// material saved and its record changed by edit, as a release farcast
// carrying the fake components: its provider, builder, writer and storage
// mint fakes, its plan's reader the in-memory pin's read-only view, and its
// writer's pin that same pin. The writer's cluster and the pin answer
// farcast-system's uid u1.
type storageRig struct {
	dir config.Dir
	fp  *fakeProvider
	fb  *fakeBuilder
	fc  *fakeCluster
	ps  *fakePinStore
	// minted counts the storage mints, and mint is what each does (nothing
	// when nil).
	minted int
	mint   func(dir config.Dir) error
	// opened counts the provider's opens.
	opened int
	// writers counts the writer's opens; onWriter runs as it opens, and
	// writerErr refuses it.
	writers   int
	onWriter  func()
	writerErr error
}

func newStorageRig(t *testing.T, edit func(meta *config.InstanceMetadata)) *storageRig {
	t.Helper()
	dir, meta := writeInstance(t, kubetest.New(t), true)
	writeMaterial(t, dir)
	if edit != nil {
		edit(meta)
		if err := dir.SaveInstanceMetadata(writeName, meta); err != nil {
			t.Fatal(err)
		}
	}
	// The registry the ensure answers is the one the record names, when it
	// names one.
	fp := &fakeProvider{}
	if meta.Registry != nil {
		fp.registry = &planck.Registry{Ref: registryRefFor(meta), Prefix: meta.Registry.Prefix}
	}
	r := &storageRig{dir: dir, fp: fp, fb: &fakeBuilder{resolveFn: notFoundForTags}, fc: &fakeCluster{uid: "u1"}, ps: pinStoreOf(dir, writeName)}
	r.ps.uid = "u1"
	return r
}

// mintsBucket is a storage mint that records the bucket the real one would,
// in the instance's region, then changes the record by change.
func (r *storageRig) mintsBucket(change func(m *config.InstanceMetadata)) {
	r.mint = func(dir config.Dir) error {
		_, err := dir.UpdateInstanceMetadata(writeName, func(m *config.InstanceMetadata) error {
			m.Storage = &config.Storage{Bucket: "farcast-atlas-0a1b2c3d", Provider: "gcs", Location: m.Region}
			if change != nil {
				change(m)
			}
			return nil
		})
		return err
	}
}

func (r *storageRig) cmd(t *testing.T, flags ...string) *storageDeployCommand {
	t.Helper()
	c := withFlags(t, &storageDeployCommand{}, flags...)
	asRelease(&c.deployer, nil)
	c.deployer.openProvider = func(*config.InstanceMetadata, *config.InstanceCredentials) (planck.Provider, error) {
		r.opened++
		return r.fp, nil
	}
	c.deployer.newBuilder = func(func(string)) imageBuilder { return r.fb }
	c.deployer.newCluster = func(clusterRef) (clusterApplier, error) {
		r.writers++
		if r.onWriter != nil {
			r.onWriter()
		}
		if r.writerErr != nil {
			return nil, r.writerErr
		}
		return r.fc, nil
	}
	c.newPinStore = testDefaultPinStore
	c.newPlanReader = testPinPlanReader
	c.ensureStorage = func(context.Context, *Env, string) error {
		r.minted++
		if r.mint != nil {
			return r.mint(r.dir)
		}
		return nil
	}
	return c
}

// run runs storage deploy with flags, in JSON mode with no terminal.
func (r *storageRig) run(t *testing.T, flags ...string) (stdout, stderr string, err error) {
	t.Helper()
	env, out, errb := testEnvBoth(r.dir, output.ModeJSON)
	err = r.cmd(t, flags...).Run(t.Context(), env, []string{writeName})
	return out.String(), errb.String(), err
}

// plan is storage deploy's --plan.
func (r *storageRig) plan(t *testing.T) plan.Document {
	t.Helper()
	stdout, stderr, err := r.run(t, "--plan")
	if err != nil {
		t.Fatalf("storage deploy --plan: %v\n%s", err, stderr)
	}
	return printedDocument(t, []byte(stdout))
}

// wroteNothing fails t if the rig minted storage, ensured the registry,
// pushed or built an image, or applied anything.
func (r *storageRig) wroteNothing(t *testing.T) {
	t.Helper()
	if r.minted+len(r.fp.ensured)+len(r.fb.embedded)+len(r.fb.built)+len(r.fc.applied) != 0 {
		t.Errorf("minted storage %d times, ensured %d registries, pushed %d, built %d and applied %d",
			r.minted, len(r.fp.ensured), len(r.fb.embedded), len(r.fb.built), len(r.fc.applied))
	}
}

// ADR 0023 M2.6 (A23-42, A23-23, row 86): under --confirm the pin is
// written once, at the version its plan read, and never as anything the
// plan did not list. Another writer that raises the pin between the
// comparison and the write makes that write a conflict: the command refuses
// plan_changed, with A23-42's text, and leaves the other writer's pin as it
// is, unioned with nothing and written over by nothing. storage deploy then
// records no keyholder and applies nothing. storage key rotate writes two
// pins, and each is that one attempt: the hold, at the version the plan
// read, and the final pin, at the version the hold produced (A23-45).
func TestConfirmNeverWritesAPinThePlanDidNotList(t *testing.T) {
	raise := func(t *testing.T, ps *fakePinStore) string {
		t.Helper()
		other := dskeyholder.Pin{Retired: []datasphere.KeyID{foreignID(t)}}.Marshal()
		ps.onWrite = func() { ps.set(other) }
		return other
	}
	t.Run("storage key pin", func(t *testing.T) {
		dir, _, ps := keyPinFixture(t)
		doc := runKeyPinPlan(t, dir, nil)
		other := raise(t, ps)
		_, _, err := runKeyPinConfirm(t, dir, nil, doc)
		if err == nil || err.Error() != msgPinChanged || kindOf(classified(err)) != kindPlanChanged || exitCodeOf(err) != 1 {
			t.Fatalf("--confirm over another writer's pin = %v (kind %s); want plan_changed, %q", err, kindOf(classified(err)), msgPinChanged)
		}
		if ps.value != other || ps.version != 1 {
			t.Errorf("the pin is %s at version %d; want the other writer's %s, written once", ps.value, ps.version, other)
		}
	})
	t.Run("storage deploy", func(t *testing.T) {
		r := newStorageRig(t, nil)
		doc := r.plan(t)
		other := raise(t, r.ps)
		_, _, err := r.run(t, "--confirm", doc.Digest)
		if err == nil || err.Error() != msgPinChanged || kindOf(classified(err)) != kindPlanChanged {
			t.Fatalf("--confirm over another writer's pin = %v (kind %s); want plan_changed, %q", err, kindOf(classified(err)), msgPinChanged)
		}
		if r.ps.value != other || r.ps.version != 1 {
			t.Errorf("the pin is %s at version %d; want the other writer's %s, written once", r.ps.value, r.ps.version, other)
		}
		if len(r.fc.applied) != 0 {
			t.Errorf("applied %d streams after the pin was refused", len(r.fc.applied))
		}
		if after, err := r.dir.LoadInstanceMetadata(writeName); err != nil || after.Keyholder.Image != "" {
			t.Errorf("recorded the keyholder %+v (%v) after the pin was refused", after.Keyholder, err)
		}
	})
	for _, stage := range []struct {
		name string
		n    int // the pin write the other writer comes before
	}{{"storage key rotate/the hold stage", 1}, {"storage key rotate/the final pin", 2}} {
		t.Run(stage.name, func(t *testing.T) {
			r := newRotateRig(t, backdatedApps)
			doc := r.plan(t)
			other, version := dskeyholder.Pin{Retired: []datasphere.KeyID{foreignID(t)}}.Marshal(), 0
			r.beforeWrite = func(n int) {
				if n == stage.n {
					r.ps.set(other)
					version = r.ps.version
				}
			}
			_, _, err := r.run(t, "--confirm", doc.Digest)
			if err == nil || err.Error() != msgPinChanged || kindOf(classified(err)) != kindPlanChanged || exitCodeOf(err) != 1 {
				t.Fatalf("--confirm over another writer's pin = %v (kind %s); want plan_changed, %q", err, kindOf(classified(err)), msgPinChanged)
			}
			if r.ps.value != other || r.ps.version != version || len(r.writes) != stage.n {
				t.Errorf("the pin is %s at version %d after %d writes; want the other writer's %s at %d, after %d", r.ps.value, r.ps.version, len(r.writes), other, version, stage.n)
			}
		})
	}
}

// ADR 0023 M2.6 (A23-42, mutation 86d): under --confirm a pin write that
// landed and lost its answer is read back, and the planned pin there counts
// as written: the command succeeds, writing once. The pin was opened as the
// reader for the plan and again for its recomputation, and as the writer
// once, after the comparison (A23-20, A21-3 as A23-43 qualifies it).
func TestConfirmPinThatLandedButLostItsAnswerSucceeds(t *testing.T) {
	opens := []kube.Identity{kube.Reader, kube.Reader, kube.Writer}
	t.Run("storage key pin", func(t *testing.T) {
		dir, keys, ps := keyPinFixture(t)
		doc := runKeyPinPlan(t, dir, nil)
		ps.loseAnswer = true
		stdout, stderr, err := runKeyPinConfirm(t, dir, nil, doc)
		if err != nil {
			t.Fatalf("--confirm whose write lost its answer = %v\n%s", err, stderr)
		}
		if !ps.pin(t).Equal(pinFor(keys)) || ps.version != 1 || !strings.Contains(stdout, `"written":true`) {
			t.Errorf("the pin is %s at version %d, and the result %s; want this keyring's, written once", ps.value, ps.version, stdout)
		}
		if got := ps.openedBy(); !slices.Equal(got, opens) {
			t.Errorf("the pin was opened as %v; want %v", got, opens)
		}
	})
	t.Run("storage deploy", func(t *testing.T) {
		r := newStorageRig(t, nil)
		doc := r.plan(t)
		r.ps.loseAnswer = true
		if _, stderr, err := r.run(t, "--confirm", doc.Digest); err != nil {
			t.Fatalf("--confirm whose pin write lost its answer = %v\n%s", err, stderr)
		}
		if r.ps.version != 1 || len(r.fc.applied) != 1 {
			t.Errorf("the pin was written %d times and %d streams applied; want once each", r.ps.version, len(r.fc.applied))
		}
		if got := r.ps.openedBy(); !slices.Equal(got, opens) || r.writers != 1 {
			t.Errorf("the pin was opened as %v and the writer %d times; want %v, and the writer once", got, r.writers, opens)
		}
	})
	t.Run("storage key rotate", func(t *testing.T) {
		r := newRotateRig(t, backdatedApps)
		doc := r.plan(t)
		r.ps.loseAnswer = true
		stdout, stderr, err := r.run(t, "--confirm", doc.Digest)
		if err != nil {
			t.Fatalf("--confirm whose hold lost its answer = %v\n%s", err, stderr)
		}
		if res := rotated(t, stdout); !res.Active || len(r.writes) != 2 || r.ps.version != 2 || !r.ps.pin(t).Equal(r.writes[1].pin) {
			t.Errorf("the pin is %s at version %d after %d writes, and the result %+v; want the hold, then the final pin, each written once",
				r.ps.value, r.ps.version, len(r.writes), res)
		}
		if got := r.ps.openedBy(); !slices.Equal(got, opens) || r.writers != 1 {
			t.Errorf("the pin was opened as %v and the writer %d times; want %v, and the writer once", got, r.writers, opens)
		}
	})
}

// ADR 0023 M2.6 (A23-42): under --confirm a pin write that fails for any
// reason but a conflict keeps its own kind: a 500 is cluster_rejected, not
// plan_changed, and nothing is written.
func TestConfirmPinNon409FailureKeepsItsKind(t *testing.T) {
	failed := &kube.APIError{Method: "POST", Path: configMapsPath,
		Status: kube.Status{Status: tkube.Status{Code: 500, Reason: "InternalError", Message: "etcd is unhappy"}}, KubernetesStatus: true}
	t.Run("storage key pin", func(t *testing.T) {
		dir, _, ps := keyPinFixture(t)
		doc := runKeyPinPlan(t, dir, nil)
		ps.failWrite = failed
		_, _, err := runKeyPinConfirm(t, dir, nil, doc)
		if kind := kindOf(classified(err)); err == nil || kind != kindClusterRejected || !errors.Is(err, failed) {
			t.Fatalf("--confirm whose pin write failed = %v (kind %s); want its own kind, %s", err, kind, kindClusterRejected)
		}
		if ps.exists {
			t.Errorf("a failed write left a pin: %s", ps.value)
		}
	})
	t.Run("storage deploy", func(t *testing.T) {
		r := newStorageRig(t, nil)
		doc := r.plan(t)
		r.ps.failWrite = failed
		_, _, err := r.run(t, "--confirm", doc.Digest)
		if kind := kindOf(classified(err)); err == nil || kind != kindClusterRejected || !strings.Contains(err.Error(), "the key pin could not be written, so nothing was deployed") {
			t.Fatalf("--confirm whose pin write failed = %v (kind %s); want its own kind, %s", err, kind, kindClusterRejected)
		}
		if len(r.fc.applied) != 0 {
			t.Errorf("applied %d streams after the pin failed", len(r.fc.applied))
		}
	})
	// With no keyring here the plan creates the empty pin. A create that
	// failed reads back absent, which is not the empty pin written (row O33
	// of the M2.6c review): the replicas are never deployed with no pin
	// ConfigMap at all.
	t.Run("storage deploy, no keyring here", func(t *testing.T) {
		r := newStorageRig(t, nil)
		if err := os.Remove(r.dir.InstanceKeyringPath(writeName)); err != nil {
			t.Fatal(err)
		}
		doc := r.plan(t)
		if w := planWrites(decodedBound(t, doc)); len(w) == 0 || w[0].(plan.WriteFact).Name != dsdeploy.PinConfigMapName("") || w[0].(plan.WriteFact).Method != plan.WriteCreate {
			t.Fatalf("the plan's first write is %+v; want the empty pin's create", w)
		}
		r.ps.failWrite = failed
		_, _, err := r.run(t, "--confirm", doc.Digest)
		if kind := kindOf(classified(err)); err == nil || kind != kindClusterRejected || !strings.Contains(err.Error(), "the key pin could not be written, so nothing was deployed") {
			t.Fatalf("--confirm whose empty pin's create failed = %v (kind %s); want its own kind, %s", err, kind, kindClusterRejected)
		}
		if r.ps.exists || len(r.fc.applied) != 0 {
			t.Errorf("the pin exists: %v, and %d streams were applied; want neither", r.ps.exists, len(r.fc.applied))
		}
	})
	// rotate's two pins: the hold's failure stops the rotation with the new
	// keys held, and the final pin's leaves them in use; either is the
	// command's error, with its own kind, never an unfinished rotation's
	// internal. The hold's says it is the pin that was not written, the keys
	// held and unused, never a keyring this machine could not save (ADR 0023
	// M2.6c).
	for _, stage := range []struct {
		name   string
		n      int
		active bool
	}{{"storage key rotate/the hold stage", 1, false}, {"storage key rotate/the final pin", 2, true}} {
		t.Run(stage.name, func(t *testing.T) {
			r := newRotateRig(t, backdatedApps)
			doc := r.plan(t)
			r.beforeWrite = func(n int) {
				if n == stage.n {
					r.ps.failWrite = failed
				}
			}
			stdout, _, err := r.run(t, "--confirm", doc.Digest)
			if kind := kindOf(classified(err)); err == nil || kind != kindClusterRejected || !errors.Is(err, failed) {
				t.Fatalf("--confirm whose pin write failed = %v (kind %s); want its own kind, %s", err, kind, kindClusterRejected)
			}
			res := rotated(t, stdout)
			if res.Active != stage.active || len(r.writes) != stage.n {
				t.Errorf("the rotation is in use: %v, after %d pin writes; want %v, after %d", res.Active, len(r.writes), stage.active, stage.n)
			}
			if stage.active {
				return
			}
			if !strings.Contains(res.Keyholder, "every replica took the new keys to hold, but the key pin that would hold them could not be written (write the key pin: ") ||
				!strings.Contains(res.Keyholder, "held and unused") || strings.Contains(res.Keyholder, "could not save its keyring") || res.Status != "held" {
				t.Errorf("the result says %+v; want the new keys held and unused, the pin named as why", res)
			}
		})
	}
	// The same 500, its message hostile, in human mode: no byte the API
	// server sent can act on the terminal, on the keyholder line or any
	// other (ADR 0023 M2.6c, A20-13).
	t.Run("storage key rotate/the hold stage, a hostile message", func(t *testing.T) {
		hostile := &kube.APIError{Method: "PUT", Path: configMapsPath,
			Status: kube.Status{Status: tkube.Status{Code: 500, Reason: "InternalError", Message: "boom \x1b]0;pwned\x07 \x1b[2J"}}, KubernetesStatus: true}
		r := newRotateRig(t, backdatedApps)
		doc := r.plan(t)
		r.beforeWrite = func(n int) {
			if n == 1 {
				r.ps.failWrite = hostile
			}
		}
		env, out, errb := testEnvBoth(r.dir, output.ModeHuman)
		err := r.cmd(t, "--confirm", doc.Digest).Run(t.Context(), env, []string{writeName})
		if kind := kindOf(classified(err)); err == nil || kind != kindClusterRejected {
			t.Fatalf("--confirm whose hold write failed = %v (kind %s); want %s", err, kind, kindClusterRejected)
		}
		for name, text := range map[string]string{"stdout": out.String(), "stderr": errb.String()} {
			for i := 0; i < len(text); i++ {
				if c := text[i]; c < 0x20 && c != '\n' {
					t.Errorf("%s carries the control byte %#x: %q", name, c, text)
					break
				}
			}
		}
		if !strings.Contains(out.String(), "the key pin that would hold them could not be written") {
			t.Errorf("the keyholder line does not name the pin:\n%s", out)
		}
	})
}

// ADR 0023 M2.6 (A23-3, A23-44, mutation 91c): under --confirm, --replace
// lowers what its plan said it lowers without asking: with no terminal and
// no --yes, from a keyring behind the pin, the pin is lowered to this
// keyring's and every replica handed it in place of what it enforced; and
// over a pin it is not behind, a replica found enforcing another pin is
// handed this one in its place. Its plan is the consent; confirmLower is
// never asked.
func TestKeyPinReplaceConfirmLowersReplicasWithoutAsking(t *testing.T) {
	t.Run("from behind the pin", func(t *testing.T) {
		dir, keys, ps := keyPinFixture(t)
		ps.set(dskeyholder.Pin{Require: []datasphere.KeyID{foreignID(t)}}.Marshal())
		kh := &fakeStateKeyholder{phase: "unsealed"}
		above := dskeyholder.Pin{Require: []datasphere.KeyID{foreignID(t)}}
		for i := range 2 {
			kh.replica(i).pin = &above
		}
		doc := runKeyPinPlan(t, dir, kh, "--replace")
		if f := pinFactOf(t, decodedBound(t, doc)); !slices.Equal(f.Lowering, []string{foreignKeyID}) {
			t.Fatalf("the plan lowers %q; want %q", f.Lowering, foreignKeyID)
		}
		stdout, stderr, err := runKeyPinConfirm(t, dir, kh, doc, "--replace")
		if err != nil {
			t.Fatalf("--replace --confirm with no terminal = %v\n%s", err, stderr)
		}
		if strings.Contains(stderr, "Lower the key pin") {
			t.Errorf("--confirm asked: %s", stderr)
		}
		if !ps.pin(t).Equal(pinFor(keys)) || !strings.Contains(stdout, `"lowered":["`+foreignKeyID+`"]`) {
			t.Errorf("the pin is %s, the result %s; want this keyring's own, lowering %s", ps.value, stdout, foreignKeyID)
		}
		for i := range 2 {
			if p := kh.replica(i).pin; p == nil || !p.Equal(pinFor(keys)) {
				t.Errorf("replica %d enforces %v; want this keyring's pin, handed in place of the old", i, p)
			}
		}
	})
	t.Run("a replica above a pin it is not behind", func(t *testing.T) {
		dir, keys, ps := keyPinFixture(t)
		ps.set(pinFor(keys).Marshal())
		kh := &fakeStateKeyholder{phase: "unsealed"}
		above := pinFor(keys).Union(dskeyholder.Pin{Require: []datasphere.KeyID{foreignID(t)}})
		kh.replica(1).pin = &above
		doc := runKeyPinPlan(t, dir, kh, "--replace")
		stdout, stderr, err := runKeyPinConfirm(t, dir, kh, doc, "--replace")
		if err != nil {
			t.Fatalf("--replace --confirm with no terminal = %v\n%s", err, stderr)
		}
		if strings.Contains(stderr, "Lower the key pin") || !strings.Contains(stderr, "replica 1 enforce a pin other than this keyring's") {
			t.Errorf("--confirm asked, or did not say what it lowers: %s", stderr)
		}
		if p := kh.replica(1).pin; p == nil || !p.Equal(pinFor(keys)) || !strings.Contains(stdout, `"lowered":["replica 1"]`) {
			t.Errorf("replica 1 enforces %v, the result %s; want this keyring's pin, handed in place of the higher one", p, stdout)
		}
	})
	// Behind the pin only because this keyring writes under a key the pin
	// retired — a stale or imported keyring after another machine rotated
	// (A23-44: lowering is the missing keys, then the retired active ones;
	// row O17 of the M2.6c review): the plan binds that key as lowered, and
	// --confirm lowers it, without asking.
	t.Run("from behind the pin by a key it retires", func(t *testing.T) {
		dir, keys, ps := keyPinFixture(t)
		active := scopeKEK(keys)
		cur := pinFor(keys)
		cur.Retired = append(cur.Retired, active)
		ps.set(cur.Marshal())
		kh := &fakeStateKeyholder{phase: "unsealed"}
		doc := runKeyPinPlan(t, dir, kh, "--replace")
		b := decodedBound(t, doc)
		if f := pinFactOf(t, b); len(b.Blocked) != 0 || !slices.Equal(f.Lowering, []string{active.String()}) {
			t.Fatalf("the plan blocks %+v and lowers %q; want it unblocked, lowering the retired active key %s", b.Blocked, f.Lowering, active)
		}
		stdout, stderr, err := runKeyPinConfirm(t, dir, kh, doc, "--replace")
		if err != nil {
			t.Fatalf("--replace --confirm with no terminal = %v\n%s", err, stderr)
		}
		if strings.Contains(stderr, "Lower the key pin") || !strings.Contains(stdout, `"lowered":["`+active.String()+`"]`) {
			t.Errorf("--confirm asked, or its result %s does not lower %s: %s", stdout, active, stderr)
		}
	})
}

// ADR 0023 M2.6 (A23-44; row O40 of the M2.6c review): storage key pin's plan
// binds --replace as given, true or false, as its one option.
func TestKeyPinPlanBindsReplace(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(strconv.FormatBool(replace), func(t *testing.T) {
			dir, _, _ := keyPinFixture(t)
			var flags []string
			if replace {
				flags = []string{"--replace"}
			}
			b := decodedBound(t, runKeyPinPlan(t, dir, nil, flags...))
			if want := []plan.Option{{Flag: "replace", Value: strconv.FormatBool(replace)}}; !slices.Equal(b.Options, want) {
				t.Errorf("the plan binds %+v; want %+v", b.Options, want)
			}
		})
	}
}

// ADR 0023 M2.6 (A23-20): the key pin opens only as the writer. A plan
// reads it through its own reader, and pinStoreFor refuses any other
// identity before anything is opened.
func TestPinStoreForOpensOnlyTheWriter(t *testing.T) {
	opened := 0
	seam := func(clusterRef) (pinStore, error) {
		opened++
		return &fakePinStore{}, nil
	}
	for _, id := range []kube.Identity{kube.Reader, ""} {
		ps, err := pinStoreFor(seam, clusterRef{Meta: &config.InstanceMetadata{Name: writeName}, Identity: id}, &fakePinStore{})
		if err == nil || err.Error() != msgPinWriterOnly || ps != nil || kindOf(classified(err)) != kindInternal {
			t.Errorf("pinStoreFor as %q = %v, %v; want %q", id, ps, err, msgPinWriterOnly)
		}
	}
	if opened != 0 {
		t.Errorf("a refused identity opened the pin %d times", opened)
	}
	if _, err := pinStoreFor(seam, clusterRef{Meta: &config.InstanceMetadata{Name: writeName}, Identity: kube.Writer}, nil); err != nil || opened != 1 {
		t.Errorf("pinStoreFor as the writer = %v, opening %d times", err, opened)
	}
}

// ADR 0023 M2.6c (A23-43): with a bucket recorded and no keyring on this
// machine, storage deploy keeps a readable pin as it is, whatever it
// requires, and writes the empty pin only where there is none or none that
// reads: its plan binds the pin there and no pin write, and its --yes run and
// its --confirm leave the pin untouched, at its version.
func TestStorageDeployWithNoKeyringKeepsAReadablePin(t *testing.T) {
	for _, answer := range []string{"--yes", "--confirm"} {
		t.Run(answer, func(t *testing.T) {
			r := newStorageRig(t, nil)
			if err := os.Remove(r.dir.InstanceKeyringPath(writeName)); err != nil {
				t.Fatal(err)
			}
			held := dskeyholder.Pin{Require: []datasphere.KeyID{foreignID(t)}}
			r.ps.set(held.Marshal())
			doc := r.plan(t)
			b := decodedBound(t, doc)
			if f := pinFactOf(t, b); !pinOfFact(t, f).Equal(held) || len(planWrites(b)) == 0 || planWrites(b)[0].(plan.WriteFact).Kind == "ConfigMap" {
				t.Fatalf("the plan binds the pin %+v and the writes %+v; want the readable pin kept, and no pin write", f, planWrites(b))
			}
			flags := []string{"--yes"}
			if answer == "--confirm" {
				flags = []string{"--confirm", doc.Digest}
			}
			if _, stderr, err := r.run(t, flags...); err != nil {
				t.Fatalf("storage deploy %s: %v\n%s", answer, err, stderr)
			}
			if r.ps.value != held.Marshal() || r.ps.version != 1 || len(r.fc.applied) != 1 {
				t.Errorf("the pin is %s at version %d, with %d streams applied; want the readable pin untouched, and the keyholder applied", r.ps.value, r.ps.version, len(r.fc.applied))
			}
		})
	}
}
