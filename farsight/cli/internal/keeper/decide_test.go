package keeper

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/datasphere"
	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
)

func allowed() BudgetState {
	return BudgetState{Used: 1, Limit: 8, Window: DefaultWindow, Allowed: true}
}
func spent() BudgetState {
	return BudgetState{Used: 8, Limit: 8, Window: DefaultWindow, Oldest: time.Now().UTC()}
}

func TestDecide(t *testing.T) {
	sealed := keyholder.State{Phase: "restart-sealed"}

	t.Run("a restarted replica within budget is re-seeded", func(t *testing.T) {
		d := Decide(sealed, nil, 0, 3, allowed(), Fleet{})
		if d.Action != ActionReseed {
			t.Errorf("Action = %q, want %q (%s)", d.Action, ActionReseed, d.Reason)
		}
	})

	t.Run("an unsealed replica is left alone", func(t *testing.T) {
		d := Decide(keyholder.State{Phase: "unsealed", Generation: 3}, nil, 0, 3, allowed(), Fleet{})
		if d.Action != ActionNone {
			t.Errorf("Action = %q, want %q", d.Action, ActionNone)
		}
	})

	// The line the whole design rests on: "sealed because restarted" and
	// "sealed because the operator said so" are different states, and a keeper
	// may only remedy the first.
	t.Run("an operator hold is never a keeper's to clear", func(t *testing.T) {
		d := Decide(keyholder.State{Phase: "operator-hold", HoldReason: "suspected compromise"}, nil, 0, 3, allowed(), Fleet{})
		if d.Action != ActionHold {
			t.Fatalf("Action = %q, want %q", d.Action, ActionHold)
		}
		if !strings.Contains(d.Reason, "suspected compromise") {
			t.Errorf("the operator's own reason was dropped: %q", d.Reason)
		}
	})

	// Even with budget to spare, and even for a keeper that would otherwise
	// have work to do.
	t.Run("a hold outranks an available budget", func(t *testing.T) {
		if d := Decide(keyholder.State{Phase: "operator-hold"}, nil, 0, 3, allowed(), Fleet{}); d.Action == ActionReseed {
			t.Error("a keeper re-seeded through an operator hold")
		}
	})

	t.Run("a spent budget refuses rather than re-seeding", func(t *testing.T) {
		d := Decide(sealed, nil, 0, 3, spent(), Fleet{})
		if d.Action != ActionBudget {
			t.Errorf("Action = %q, want %q", d.Action, ActionBudget)
		}
		if !strings.Contains(d.Reason, "budget is spent") {
			t.Errorf("the refusal does not say the budget is spent: %q", d.Reason)
		}
	})

	// Static bundles degrade visibly rather than corrupting: a device that
	// missed a rekey stops acting instead of pushing retired keys.
	t.Run("a bundle older than the cluster is stale, not pushed", func(t *testing.T) {
		d := Decide(keyholder.State{Phase: "restart-sealed", Generation: 5}, nil, 0, 3, allowed(), Fleet{})
		if d.Action != ActionStale {
			t.Errorf("Action = %q, want %q", d.Action, ActionStale)
		}
		if !strings.Contains(d.Reason, "re-enrol") {
			t.Errorf("the refusal does not say what to do: %q", d.Reason)
		}
	})

	t.Run("an unreachable replica is unknown, not sealed", func(t *testing.T) {
		d := Decide(keyholder.State{}, errors.New("dial failed"), 1, 3, allowed(), Fleet{})
		if d.Action != ActionUnknown {
			t.Errorf("Action = %q, want %q", d.Action, ActionUnknown)
		}
	})
}

// The budget counts key material that actually MOVED. Counting refusals would
// let anything that can make a keeper fail — an unreachable tunnel, a stale
// bundle — spend the budget that bounds how often material moves.
func TestBudgetCountsSuccessfulReseedsInsideTheWindow(t *testing.T) {
	now := time.Now().UTC()
	entries := []keyholder.LedgerEntry{
		{Time: now.Add(-1 * time.Hour), Intent: IntentReseed, Result: "ok"},
		{Time: now.Add(-2 * time.Hour), Intent: IntentReseed, Result: "ok"},
		{Time: now.Add(-3 * time.Hour), Intent: IntentReseed, Result: "refused"},
		{Time: now.Add(-4 * time.Hour), Intent: "operator-unseal", Result: "ok"},
		{Time: now.Add(-40 * 24 * time.Hour), Intent: IntentReseed, Result: "ok"},
	}
	b := Budget(entries, 8, DefaultWindow, now)
	if b.Used != 2 {
		t.Errorf("Used = %d, want 2 (refusals, operator unseals and expired entries do not count)", b.Used)
	}
	if !b.Allowed {
		t.Error("Allowed = false with 2 of 8 used")
	}
	if b.Oldest.IsZero() {
		t.Error("Oldest was not recorded, so a refusal cannot say when the budget recovers")
	}

	full := make([]keyholder.LedgerEntry, 8)
	for i := range full {
		full[i] = keyholder.LedgerEntry{Time: now.Add(-time.Duration(i) * time.Hour), Intent: IntentReseed, Result: "ok"}
	}
	if Budget(full, 8, DefaultWindow, now).Allowed {
		t.Error("Allowed = true at the limit")
	}
}

// instanceKeys is an instance's keyring with one scope per application.
func instanceKeys(t *testing.T, apps ...string) datasphere.Keyring {
	t.Helper()
	k, err := datasphere.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	for _, app := range apps {
		sc, err := datasphere.NewAppScope("demo", app)
		if err != nil {
			t.Fatal(err)
		}
		if k, err = k.AddScope(sc); err != nil {
			t.Fatal(err)
		}
	}
	return k
}

func bundleFrom(t *testing.T, k datasphere.Keyring) *datasphere.Bundle {
	t.Helper()
	b, err := datasphere.NewBundle("prod", 1, k.Scopes())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// serving is a replica holding a keyring, reporting what the control surface
// reports: each scope's active KEK.
func serving(k datasphere.Keyring) keyholder.State {
	keys := map[string][]string{}
	for _, sc := range k.Scopes() {
		for _, e := range sc.Keyring().KEKs() {
			keys[sc.Name] = append(keys[sc.Name], e.ID.String())
		}
	}
	return keyholder.State{Phase: "unsealed", Generation: 4, Keys: keys}
}

func rotated(t *testing.T, k datasphere.Keyring) datasphere.Keyring {
	t.Helper()
	out, _, err := k.RotateScopeKEKs()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// rotatedHeld is a rotation as the fleet first receives it: each scope's new
// key held, the previous one still active.
func rotatedHeld(t *testing.T, k datasphere.Keyring) (held, active datasphere.Keyring) {
	t.Helper()
	out, rotations, err := k.RotateScopeKEKs()
	if err != nil {
		t.Fatal(err)
	}
	previous := map[string]datasphere.KeyID{}
	for _, r := range rotations {
		previous[r.Scope] = r.Previous
	}
	held, err = out.WithScopeActive(previous)
	if err != nil {
		t.Fatal(err)
	}
	return held, out
}

func TestABundleFromBeforeARotationIsAMismatch(t *testing.T) {
	before := instanceKeys(t, "alpha")
	why := Mismatch(bundleFrom(t, before), []keyholder.State{serving(rotated(t, before))})
	if !strings.Contains(why, "rotated after it was enrolled") {
		t.Errorf("Mismatch = %q; want it to say the keys were rotated", why)
	}
}

// Closure item 16. A rotation reaches a replica held-but-unused first, and in
// that window the replica's ACTIVE key is still one the old bundle carries.
// Judging by the active key alone, a keeper enrolled before the rotation
// called itself current and re-seeded a restarted replica without the new
// key — which the serving one was about to write under.
func TestABundleMissingAKeyAReplicaHoldsUnusedIsAMismatch(t *testing.T) {
	before := instanceKeys(t, "alpha")
	held, _ := rotatedHeld(t, before)
	why := Mismatch(bundleFrom(t, before), []keyholder.State{serving(held)})
	if !strings.Contains(why, "rotated after it was enrolled") {
		t.Errorf("Mismatch = %q; a replica holding a key the bundle lacks must stop the re-seed", why)
	}
}

func TestABundleMissingANewApplicationIsAMismatch(t *testing.T) {
	why := Mismatch(bundleFrom(t, instanceKeys(t, "alpha")), []keyholder.State{serving(instanceKeys(t, "beta"))})
	if !strings.Contains(why, "added after it was enrolled") {
		t.Errorf("Mismatch = %q; want it to say an application was added", why)
	}
}

// A bundle AHEAD of a serving replica — enrolled after a rotation that has not
// reached every replica — would have the restarted replica write under a key
// the serving one cannot read. It used to be allowed, on the reasoning that it
// carries the replica's own key too; carrying it is not enough, because the
// bundle writes under the other one.
func TestABundleAheadOfAServingReplicaIsAMismatch(t *testing.T) {
	before := instanceKeys(t, "alpha")
	why := Mismatch(bundleFrom(t, rotated(t, before)), []keyholder.State{serving(before)})
	if !strings.Contains(why, "has not reached every replica") || !strings.Contains(why, "farcast storage unseal") {
		t.Errorf("Mismatch = %q; want it to refuse and name what finishes the hand-over", why)
	}
}

// What a keeper enrolled at each point of a rotation may re-seed beside. Keys
// are only ever added, so a bundle that holds everything a serving replica
// holds, and writes under a key it holds, passes.
func TestABundleThatAgreesWithTheFleetIsNoMismatch(t *testing.T) {
	before := instanceKeys(t, "alpha")
	held, active := rotatedHeld(t, before)
	cases := map[string]struct {
		bundle  datasphere.Keyring
		replica datasphere.Keyring
	}{
		"enrolled after the rotation finished":            {active, active},
		"enrolled mid-rotation, replica not yet using it": {held, held},
		"enrolled mid-rotation, replica already using it": {held, active},
		"enrolled before anything changed":                {before, before},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if why := Mismatch(bundleFrom(t, tc.bundle), []keyholder.State{serving(tc.replica)}); why != "" {
				t.Errorf("Mismatch = %q; this bundle can re-seed beside that replica", why)
			}
		})
	}
}

func TestWithNoServingReplicaThereIsNothingToCompare(t *testing.T) {
	sealed := []keyholder.State{{Phase: "restart-sealed"}, {Phase: "operator-hold"}}
	if why := Mismatch(bundleFrom(t, instanceKeys(t, "alpha")), sealed); why != "" {
		t.Errorf("Mismatch with no serving replica = %q; there is nothing to compare against", why)
	}
}

// The case Mismatch exists for. Replica 0 restarted: it reports generation
// zero and holds nothing, so the generation check passes it. Replica 1 did
// not restart and serves the rotated keys. A keeper enrolled before the
// rotation must not put the old keys back into replica 0.
func TestARestartedReplicaIsNotReseededWithPreRotationKeys(t *testing.T) {
	before := instanceKeys(t, "alpha")
	states := []keyholder.State{{Phase: "restart-sealed"}, serving(rotated(t, before))}
	mismatch := Mismatch(bundleFrom(t, before), states)

	d := Decide(states[0], nil, 0, 1, allowed(), Fleet{Mismatch: mismatch})
	if d.Action != ActionStale {
		t.Fatalf("Decide = %s (%s); want stale — re-seeding would restore the retired keys", d.Action, d.Reason)
	}
	if !strings.Contains(d.Reason, "re-enrol") {
		t.Errorf("the refusal does not say what fixes it: %q", d.Reason)
	}
}

// An operator hold is a person's decision and is reported as one, ahead of
// any staleness.
func TestAnOperatorHoldIsReportedAheadOfStaleness(t *testing.T) {
	d := Decide(keyholder.State{Phase: "operator-hold", HoldReason: "suspected loss"}, nil, 0, 1, allowed(), Fleet{Mismatch: "mismatch"})
	if d.Action != ActionHold {
		t.Errorf("Decide = %s; want hold", d.Action)
	}
}

// backdated is a keyring whose every key was minted at the given time, so a
// test can say which of two keys is older.
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

// Review finding 5. An import merges, and a merge keeps the importing
// keyring's active key; a keeper enrolled from it carries the rotation's new
// key but writes under the old one. Re-seeding with it would move a restarted
// replica back onto a key a lost keeper may hold — the move 'storage unseal'
// refuses.
func TestABundleWritingUnderAnOlderKeyThanTheFleetIsAMismatch(t *testing.T) {
	before := backdated(t, instanceKeys(t, "alpha"), "2020-01-01T00:00:00Z")
	after := rotated(t, before)
	merged, err := before.Merge(after)
	if err != nil {
		t.Fatal(err)
	}
	why := Mismatch(bundleFrom(t, merged), []keyholder.State{serving(after)})
	if !strings.Contains(why, "writes under an older one") {
		t.Errorf("Mismatch = %q; a bundle writing under an older key than a serving replica must not re-seed", why)
	}
	// The bundle the rotation itself produced passes.
	if why := Mismatch(bundleFrom(t, after), []keyholder.State{serving(after)}); why != "" {
		t.Errorf("Mismatch = %q for the rotated bundle itself", why)
	}
}

// Review 4, finding 0. A replica whose answer was lost is unknown, not
// sealed. Read as sealed, a serving replica holding rotated keys was no
// reference at all, and a keeper enrolled before the rotation re-seeded the
// old keys beside it.
func TestAReplicaThatDidNotAnswerStopsAReseed(t *testing.T) {
	before := instanceKeys(t, "alpha")
	states := []keyholder.State{{Phase: "restart-sealed"}, {}}
	errs := []error{nil, errors.New("no route to replica")}
	fleet := FleetOf(bundleFrom(t, before), states, errs)

	d := Decide(states[0], nil, 0, 1, allowed(), fleet)
	if d.Action != ActionUnchecked || !strings.Contains(d.Reason, "replica 1 did not answer") {
		t.Fatalf("Decide = %s (%s); want unchecked — replica 1 may be serving keys this bundle lacks", d.Action, d.Reason)
	}
	// With every replica answering, the same bundle re-seeds.
	if d := Decide(states[0], nil, 0, 1, allowed(), FleetOf(bundleFrom(t, before), states, []error{nil, nil})); d.Action != ActionReseed {
		t.Errorf("Decide = %s (%s) with every replica answering; want reseed", d.Action, d.Reason)
	}
}
