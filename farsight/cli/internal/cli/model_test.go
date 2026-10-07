package cli

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/datasphere"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/keeper"
	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
)

// The hand-over, driven at random.
//
// Five review rounds found the keyholder hand-over's defects one interleaving
// at a time — a replica silent at the wrong moment, a push whose answer was
// lost, a restart between two pushes, a keeper re-seeding in the gap, a second
// machine with an older keyring. Each fix got a test for the interleaving that
// found it. These two tests look for the ones nobody thought of: they run
// rotate, unseal, a new application's hand-over, keeper passes, imports and
// replica restarts in random order against a fleet that drops answers,
// refuses pushes, loses acknowledgements and restarts after a push, and check
// after every step that
//
//   - no two serving replicas are split: whatever one writes under, every
//     other serving replica holding that scope holds too;
//   - no operator machine writes under a key a serving replica holding that
//     scope lacks — this machine is a writer too;
//   - no key ever leaves an operator machine's keyring;
//   - no replica holds a key no operator machine has.
//
// Steps are whole commands, so an interleaving inside one — a keeper
// re-seeding a replica between a hand-over's two pushes — is beyond them; the
// tests named for each such case cover those.
//
// They take minutes, so they run only when asked:
//
//	FARCAST_MODEL=1 go test -mod=vendor ./farsight/cli/internal/cli/ -run TestHandOverModel
//
// FARCAST_MODEL_SEEDS, _STEPS and _SEED0 size a run; _SILENT, _REFUSE, _LOST
// and _RESTART set how often each fault strikes. A failure prints the seed and
// every step that led to it, and FARCAST_MODEL_SEED0 with FARCAST_MODEL_SEEDS=1
// replays it.

func modelEnabled(t *testing.T) {
	t.Helper()
	if os.Getenv("FARCAST_MODEL") == "" {
		t.Skip("the randomized hand-over model runs for minutes; set FARCAST_MODEL=1 to run it")
	}
}

func modelInt(t *testing.T, name string, def int) int {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		t.Fatalf("%s=%q: %v", name, v, err)
	}
	return n
}

func modelRate(t *testing.T, name string, def float64) float64 {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f < 0 || f > 1 {
		t.Fatalf("%s=%q: want a probability between 0 and 1", name, v)
	}
	return f
}

// faultyFleet is a fleet whose calls fail the way a tunnel to real replicas
// does: a State call that gets no answer, a push refused on the way, a push
// that lands and whose answer is lost, a replica that restarts right after.
type faultyFleet struct {
	*fakeStateKeyholder
	rng                           *rand.Rand
	silent, refuse, lost, restart float64
	log                           *[]string
}

func (f *faultyFleet) State(ctx context.Context, i int) (keyholder.State, error) {
	if f.rng.Float64() < f.silent {
		*f.log = append(*f.log, fmt.Sprintf("    State(%d): no answer", i))
		return keyholder.State{}, errors.New("no route to replica")
	}
	return f.fakeStateKeyholder.State(ctx, i)
}

func (f *faultyFleet) Unseal(ctx context.Context, i int, payload []byte, intent string) (keyholder.State, error) {
	if f.rng.Float64() < f.refuse {
		*f.log = append(*f.log, fmt.Sprintf("    Unseal(%d, %s): refused on the way", i, intent))
		return keyholder.State{}, &keyholder.Refusal{Ordinal: i, Reason: "tunnel dropped"}
	}
	st, err := f.fakeStateKeyholder.Unseal(ctx, i, payload, intent)
	*f.log = append(*f.log, fmt.Sprintf("    Unseal(%d, %s): err=%v, holds %v", i, intent, err, f.replica(i).keys))
	if err == nil && f.rng.Float64() < f.lost {
		*f.log = append(*f.log, fmt.Sprintf("    Unseal(%d): installed, answer lost", i))
		err = &keyholder.Refusal{Ordinal: i, Reason: "answer lost"}
	}
	if f.rng.Float64() < f.restart {
		*f.log = append(*f.log, fmt.Sprintf("    replica %d restarts", i))
		r := f.replica(i)
		r.phase, r.keys, r.generation = "restart-sealed", nil, 0
	}
	return st, err
}

// minted gives every key a distinct mint time, a minute after the last one.
//
// Keys minted inside one test share a second, and "which of two keys is
// newer" is what the hand-over's behind and hold rules turn on; with every
// key tied, those rules would never be exercised. Real keys are minted
// seconds to months apart.
//
// An id that is all digits is written quoted — the YAML encoder will not let
// it read as a number — and the pattern allows for that. Missing one left
// that key on its real mint time, newer than every re-dated key, and the
// model nondeterministically reported this machine's own keyring as behind.
type minted struct {
	at   map[string]time.Time
	next time.Time
}

var keyEntryRE = regexp.MustCompile(`(?m)^(\s*-?\s*id:\s*"?)([0-9a-f]+)("?)\n(\s*key:.*)\n(\s*created:\s*)(.*)$`)

func newMinted() *minted {
	return &minted{at: map[string]time.Time{}, next: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (m *minted) apply(t *testing.T, dir config.Dir, instance string) {
	t.Helper()
	raw, err := dir.LoadInstanceKeyring(instance)
	if err != nil {
		t.Fatal(err)
	}
	out := keyEntryRE.ReplaceAllFunc(raw, func(entry []byte) []byte {
		sub := keyEntryRE.FindSubmatch(entry)
		id := string(sub[2])
		when, ok := m.at[id]
		if !ok {
			m.next = m.next.Add(time.Minute)
			when = m.next
			m.at[id] = when
		}
		return []byte(string(sub[1]) + id + string(sub[3]) + "\n" + string(sub[4]) + "\n" + string(sub[5]) + when.Format(time.RFC3339))
	})
	if _, err := datasphere.ParseKeyring(out); err != nil {
		t.Fatalf("re-dating the keyring broke it: %v", err)
	}
	if entries, ids := len(keyEntryRE.FindAll(out, -1)), strings.Count(string(out), "id:"); entries != ids {
		t.Fatalf("re-dated %d of %d keys: the pattern no longer matches how the keyring is written", entries, ids)
	}
	if string(out) != string(raw) {
		if err := dir.SaveInstanceKeyring(instance, raw, out); err != nil {
			t.Fatal(err)
		}
	}
}

// operatorMachine is one machine holding the instance's keyring.
type operatorMachine struct {
	dir     config.Dir
	env     *Env
	everHad map[string]map[string]bool
}

// modelViolations checks the invariants above across every machine and the
// fleet, and records what each machine holds now so a later loss shows.
func modelViolations(t *testing.T, instance string, machines []*operatorMachine, kh *fakeStateKeyholder) []string {
	t.Helper()
	var bad []string
	anyMachine := map[string]map[string]bool{}
	for mi, m := range machines {
		mine := heldKeys(liveKeyring(t, m.dir, instance))
		for scope, ids := range m.everHad {
			for id := range ids {
				if !slices.Contains(mine[scope], id) {
					bad = append(bad, fmt.Sprintf("machine %d lost key %s of %s", mi, id, scope))
				}
			}
		}
		for scope, ids := range mine {
			if m.everHad[scope] == nil {
				m.everHad[scope] = map[string]bool{}
			}
			if anyMachine[scope] == nil {
				anyMachine[scope] = map[string]bool{}
			}
			for _, id := range ids {
				m.everHad[scope][id] = true
				anyMachine[scope][id] = true
			}
		}
		for i, r := range kh.reps {
			if r.phase != "unsealed" {
				continue
			}
			for scope, ids := range mine {
				if theirs, ok := r.keys[scope]; ok && !slices.Contains(theirs, ids[0]) {
					bad = append(bad, fmt.Sprintf("machine %d writes %s under %s, which serving replica %d (%v) lacks", mi, scope, ids[0], i, theirs))
				}
			}
		}
	}
	for i, r := range kh.reps {
		if r.phase != "unsealed" {
			continue
		}
		for scope, ids := range r.keys {
			for _, id := range ids {
				if !anyMachine[scope][id] {
					bad = append(bad, fmt.Sprintf("replica %d holds %s of %s, which no machine holds", i, id, scope))
				}
			}
		}
	}
	for i, a := range kh.reps {
		for j, b := range kh.reps {
			if i == j || a.phase != "unsealed" || b.phase != "unsealed" {
				continue
			}
			for scope, ids := range a.keys {
				if theirs, ok := b.keys[scope]; ok && len(ids) > 0 && !slices.Contains(theirs, ids[0]) {
					bad = append(bad, fmt.Sprintf("SPLIT: replica %d writes %s under %s; replica %d holds %v", i, scope, ids[0], j, theirs))
				}
			}
		}
	}
	return bad
}

// covers reports whether keyring a holds every key b does.
func covers(a, b map[string][]string) bool {
	for scope, ids := range b {
		for _, id := range ids {
			if !slices.Contains(a[scope], id) {
				return false
			}
		}
	}
	return true
}

func anyServing(kh *fakeStateKeyholder) bool {
	for _, r := range kh.reps {
		if r.phase == "unsealed" {
			return true
		}
	}
	return false
}

// modelCoverage counts what a run actually did, so a model whose every step
// failed — and so passed — fails instead.
type modelCoverage map[string]int

func (c modelCoverage) require(t *testing.T, what ...string) {
	t.Helper()
	t.Logf("exercised: %v", map[string]int(c))
	for _, w := range what {
		if c[w] == 0 {
			t.Errorf("the model never managed to %s; it checked nothing about it", w)
		}
	}
}

// One operator machine: its own rotations, unseals and new applications, a
// keeper, and replicas restarting under it.
func TestHandOverModelOneMachine(t *testing.T) {
	modelEnabled(t)
	seeds, steps, seed0 := modelInt(t, "FARCAST_MODEL_SEEDS", 200), modelInt(t, "FARCAST_MODEL_STEPS", 60), modelInt(t, "FARCAST_MODEL_SEED0", 0)
	coverage := modelCoverage{}
	for seed := seed0; seed < seed0+seeds; seed++ {
		if !runModel(t, int64(seed), steps, 1, coverage) {
			return
		}
	}
	coverage.require(t, "finish a rotation", "unseal every replica", "re-seed a replica")
}

// Two operator machines with keyrings that drift apart: each rotates, unseals
// and deploys, and each now and then imports the other's keyring.
func TestHandOverModelTwoMachines(t *testing.T) {
	modelEnabled(t)
	seeds, steps, seed0 := modelInt(t, "FARCAST_MODEL_SEEDS", 200), modelInt(t, "FARCAST_MODEL_STEPS", 60), modelInt(t, "FARCAST_MODEL_SEED0", 0)
	coverage := modelCoverage{}
	for seed := seed0; seed < seed0+seeds; seed++ {
		if !runModel(t, int64(seed), steps, 2, coverage) {
			return
		}
	}
	coverage.require(t, "finish a rotation", "unseal every replica", "re-seed a replica", "import another machine's keyring", "refuse a keyring behind the fleet")
}

func runModel(t *testing.T, seed int64, steps, nMachines int, coverage modelCoverage) bool {
	t.Helper()
	ctx := context.Background()
	const instance = "model"
	first, meta, firstEnv, _ := handOverInstance(t, instance)
	scopedKeyring(t, first, instance, "demo", "alpha")
	dates := newMinted()
	dates.apply(t, first, instance)
	machines := []*operatorMachine{{dir: first, env: firstEnv, everHad: map[string]map[string]bool{}}}
	for range nMachines - 1 {
		dir, _, env, _ := handOverInstance(t, instance)
		raw, err := first.LoadInstanceKeyring(instance)
		if err != nil {
			t.Fatal(err)
		}
		replaceKeyring(t, dir, instance, raw)
		machines = append(machines, &operatorMachine{dir: dir, env: env, everHad: map[string]map[string]bool{}})
	}
	base := servingFleet(t, firstEnv, meta, first)
	for _, m := range machines[1:] {
		// As if it had synced the record of the generation once.
		md, err := m.dir.LoadInstanceMetadata(instance)
		if err != nil {
			t.Fatal(err)
		}
		md.Keyholder.Generation = meta.Keyholder.Generation
		if err := m.dir.SaveInstanceMetadata(instance, md); err != nil {
			t.Fatal(err)
		}
	}
	rng := rand.New(rand.NewSource(seed))
	var log []string
	fleet := &faultyFleet{fakeStateKeyholder: base, rng: rng, log: &log,
		silent:  modelRate(t, "FARCAST_MODEL_SILENT", 0.12),
		refuse:  modelRate(t, "FARCAST_MODEL_REFUSE", 0.08),
		lost:    modelRate(t, "FARCAST_MODEL_LOST", 0.05),
		restart: modelRate(t, "FARCAST_MODEL_RESTART", 0.04),
	}
	modelViolations(t, instance, machines, base)

	var keeperBundle []byte
	var keeperGen uint64
	apps := 1
	for step := range steps {
		op := rng.Intn(100)
		mi := rng.Intn(nMachines)
		m := machines[mi]
		switch {
		case op < 20:
			log = append(log, fmt.Sprintf("step %d: machine %d rotates", step, mi))
			err := (&keyRotateCommand{assumeYes: true, newKeyholder: openerFor(fleet)}).Run(ctx, m.env, []string{instance})
			log = append(log, fmt.Sprintf("  -> %v", err))
			switch {
			case err == nil:
				coverage["finish a rotation"]++
			case strings.Contains(err.Error(), "behind the instance's"):
				coverage["refuse a keyring behind the fleet"]++
			}
		case op < 35:
			others := heldKeys(liveKeyring(t, machines[(mi+1)%nMachines].dir, instance))
			if !anyServing(base) && !covers(heldKeys(liveKeyring(t, m.dir, instance)), others) {
				// Stated limit (ADR 0008): with every replica sealed there is
				// nothing to compare a keyring against, so an unseal from one
				// older than another machine's is not caught.
				continue
			}
			log = append(log, fmt.Sprintf("step %d: machine %d unseals", step, mi))
			err := (&storageUnsealCommand{newKeyholder: openerFor(fleet)}).Run(ctx, m.env, []string{instance})
			log = append(log, fmt.Sprintf("  -> %v", err))
			switch {
			case err == nil:
				coverage["unseal every replica"]++
			case strings.Contains(err.Error(), "behind the instance's"):
				coverage["refuse a keyring behind the fleet"]++
			}
		case op < 43:
			apps++
			log = append(log, fmt.Sprintf("step %d: machine %d deploys app%d", step, mi, apps))
			s, err := datasphere.NewAppScope("demo", fmt.Sprintf("app%d", apps))
			if err != nil {
				t.Fatal(err)
			}
			k, err := liveKeyring(t, m.dir, instance).AddScope(s)
			if err != nil {
				t.Fatal(err)
			}
			saveKeyring(t, m.dir, instance, k)
			dates.apply(t, m.dir, instance)
			md, err := m.dir.LoadInstanceMetadata(instance)
			if err != nil {
				t.Fatal(err)
			}
			res := handOverKeys(ctx, m.env, md, openerFor(fleet), liveKeyring(t, m.dir, instance), handOverOptions{})
			log = append(log, fmt.Sprintf("  -> problem=%q activated=%v cause=%q loaded=%v", res.Problem, res.Activated, res.Cause, res.Loaded))
			if res.Unsafe && strings.Contains(res.Problem, "behind the instance's") {
				coverage["refuse a keyring behind the fleet"]++
			}
		case op < 55 && nMachines > 1:
			src := machines[(mi+1)%nMachines]
			log = append(log, fmt.Sprintf("step %d: machine %d imports the other's keyring", step, mi))
			merged, err := liveKeyring(t, m.dir, instance).Merge(liveKeyring(t, src.dir, instance))
			if err != nil {
				log = append(log, fmt.Sprintf("  -> %v", err))
				break
			}
			saveKeyring(t, m.dir, instance, merged)
			coverage["import another machine's keyring"]++
		case op < 73:
			i := rng.Intn(2)
			log = append(log, fmt.Sprintf("step %d: replica %d restarts", step, i))
			r := base.replica(i)
			r.phase, r.keys, r.generation = "restart-sealed", nil, 0
		case op < 78:
			md, err := m.dir.LoadInstanceMetadata(instance)
			if err != nil {
				t.Fatal(err)
			}
			k := liveKeyring(t, m.dir, instance)
			b, err := datasphere.NewBundle(instance, md.Keyholder.Generation, k.Scopes())
			if err != nil {
				t.Fatal(err)
			}
			if keeperBundle, err = b.Marshal(); err != nil {
				t.Fatal(err)
			}
			keeperGen = md.Keyholder.Generation
			log = append(log, fmt.Sprintf("step %d: a keeper is enrolled from machine %d at generation %d with %v", step, mi, keeperGen, heldKeys(k)))
		default:
			if keeperBundle == nil {
				continue
			}
			if !anyServing(base) {
				// Stated limit (ADR 0008): with every replica restarted at
				// once there is nothing to compare a keeper's bundle against.
				continue
			}
			// keeperCheckWith's decision, without the device store it needs:
			// the fleet read once, the verdict, a re-seed where it says so.
			// Its own wiring is pinned by the keeper tests.
			log = append(log, fmt.Sprintf("step %d: keeper pass", step))
			states, errs := make([]keyholder.State, 2), make([]error, 2)
			for i := range 2 {
				states[i], errs[i] = fleet.State(ctx, i)
			}
			parsed, err := datasphere.ParseBundle(keeperBundle)
			if err != nil {
				t.Fatal(err)
			}
			verdict := keeper.FleetOf(parsed, states, errs)
			parsed.Zero()
			for i := range 2 {
				d := keeper.Decide(states[i], errs[i], i, keeperGen, keeper.BudgetState{Allowed: true}, verdict)
				log = append(log, fmt.Sprintf("  replica %d: %s — %s", i, d.Action, d.Reason))
				if d.Action != keeper.ActionReseed {
					continue
				}
				if _, err := fleet.Unseal(ctx, i, keeperBundle, keeper.IntentReseed); err == nil {
					coverage["re-seed a replica"]++
				}
			}
		}
		for _, mm := range machines {
			dates.apply(t, mm.dir, instance)
		}
		for mj, mm := range machines {
			log = append(log, fmt.Sprintf("  machine %d holds %v", mj, heldKeys(liveKeyring(t, mm.dir, instance))))
		}
		for i := range 2 {
			r := base.replica(i)
			log = append(log, fmt.Sprintf("  replica %d %s, generation %d, holds %v", i, r.phase, r.generation, r.keys))
		}
		if bad := modelViolations(t, instance, machines, base); len(bad) > 0 {
			t.Errorf("seed %d, step %d:\n  %s\n\nhow it got there:\n%s\n\nreplay with FARCAST_MODEL=1 FARCAST_MODEL_SEED0=%d FARCAST_MODEL_SEEDS=1",
				seed, step, strings.Join(bad, "\n  "), strings.Join(log, "\n"), seed)
			return false
		}
	}
	return true
}
