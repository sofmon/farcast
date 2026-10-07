package keeper

import (
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/sofmon/farcast/datasphere"
	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
)

// IntentReseed is what a keeper claims to be doing. The keyholder refuses it
// against an operator hold, which is the in-cluster half of "a keeper never
// clears a deliberate seal".
const IntentReseed = "restart-reseed"

// Action is what a keeper should do about one replica.
type Action string

const (
	// ActionNone: the replica holds key material. Nothing to do.
	ActionNone Action = "none"
	// ActionReseed: the replica restarted and came back sealed. This is the
	// one thing a keeper exists to do.
	ActionReseed Action = "reseed"
	// ActionHold: an operator sealed this deliberately. Never a keeper's to
	// clear, and not even to attempt — the keyholder would refuse, and a
	// keeper that hammered a hold would be a keeper arguing with its operator.
	ActionHold Action = "hold"
	// ActionBudget: it would re-seed, and the budget is spent. The refusal IS
	// the alarm; ADR 0008 asks for a human here rather than a wider budget.
	ActionBudget Action = "budget-exhausted"
	// ActionStale: this device's bundle does not hold what the fleet holds.
	// Either the cluster has held a newer generation, which the keyholder
	// would refuse anyway, or a serving replica's keys and the bundle's
	// disagree (see Mismatch) — the instance's keys were rotated, or an
	// application added, after this keeper was enrolled, or a hand-over has
	// not reached every replica yet. Degradation, never corruption.
	ActionStale Action = "stale-bundle"
	// ActionUnknown: the replica did not answer.
	ActionUnknown Action = "unreachable"
	// ActionUnchecked: it would re-seed, but ANOTHER replica did not answer,
	// so whether that one serves keys this bundle lacks cannot be checked.
	// A replica that does not answer may well be serving; the next pass
	// retries.
	ActionUnchecked Action = "unchecked"
)

// Fleet is what a keeper concluded about every replica together, before
// deciding any one of them.
type Fleet struct {
	// Mismatch is Mismatch's verdict: why this bundle disagrees with what a
	// serving replica holds.
	Mismatch string
	// Unchecked names a replica that did not answer, which leaves the
	// bundle unchecked against it.
	Unchecked string
}

// FleetOf reads the whole fleet's answers once. A replica that did not answer
// is unknown, not sealed: treated as sealed, a serving replica whose answer
// was merely lost was no reference at all, and a keeper enrolled before a
// rotation re-seeded the old keys beside it.
func FleetOf(mine *datasphere.Bundle, states []keyholder.State, errs []error) Fleet {
	f := Fleet{Mismatch: Mismatch(mine, states)}
	for i, err := range errs {
		if err != nil {
			f.Unchecked = fmt.Sprintf("replica %d did not answer, so whether it serves keys this device's bundle lacks cannot be checked; the next pass retries", i)
			break
		}
	}
	return f
}

// Decision is what a keeper concluded about one replica, and why.
type Decision struct {
	Ordinal int
	Action  Action
	Reason  string
}

// Decide chooses what to do about one replica.
//
// Every branch that does NOT re-seed comes first, and that ordering is the
// design: a keeper is an automaton holding key material, so the question it
// answers is "is there any reason not to", and re-seeding is what is left when
// there is not.
//
// fleet is the verdict on the whole fleet, computed once before any replica is
// decided: it is what stops a keeper putting pre-rotation keys back into a
// replica that restarted and holds nothing to compare against.
func Decide(st keyholder.State, err error, ordinal int, mine uint64, budget BudgetState, fleet Fleet) Decision {
	d := Decision{Ordinal: ordinal}
	switch {
	case err != nil:
		d.Action, d.Reason = ActionUnknown, err.Error()
	case !st.Sealed():
		d.Action, d.Reason = ActionNone, "holding key material at generation "+fmt.Sprint(st.Generation)
	case st.Phase == "operator-hold":
		// The reason is carried through verbatim: an operator who sealed with
		// a reason wrote it for whoever looks next, and that is this.
		d.Action = ActionHold
		d.Reason = "sealed by the operator"
		if st.HoldReason != "" {
			d.Reason += ": " + st.HoldReason
		}
	case st.Generation > mine:
		d.Action = ActionStale
		d.Reason = fmt.Sprintf("the cluster has held generation %d and this device carries %d; re-enrol it", st.Generation, mine)
	case fleet.Mismatch != "":
		d.Action, d.Reason = ActionStale, fleet.Mismatch
	case fleet.Unchecked != "":
		d.Action, d.Reason = ActionUnchecked, fleet.Unchecked
	case !budget.Allowed:
		d.Action = ActionBudget
		d.Reason = budget.String()
	default:
		d.Action, d.Reason = ActionReseed, "restart-sealed, and within budget"
	}
	return d
}

// BudgetState is what the ledger says about how much re-seeding this device
// has done lately.
type BudgetState struct {
	Used    int
	Limit   int
	Window  time.Duration
	Allowed bool
	// Oldest is when the earliest counted push happened, so a refusal can say
	// when the budget starts recovering rather than only that it is spent.
	Oldest time.Time
}

func (b BudgetState) String() string {
	if b.Allowed {
		return fmt.Sprintf("%d of %d reseeds used in the last %s", b.Used, b.Limit, humanWindow(b.Window))
	}
	msg := fmt.Sprintf("the reseed budget is spent: %d of %d in the last %s", b.Used, b.Limit, humanWindow(b.Window))
	if !b.Oldest.IsZero() {
		msg += fmt.Sprintf(", and none expires before %s", b.Oldest.Add(b.Window).UTC().Format(time.RFC3339))
	}
	return msg
}

// Budget counts what this device has pushed inside the window.
//
// It counts SUCCESSFUL reseeds only. A refused push moved no key material, and
// counting it would let anything that can make a keeper fail — an unreachable
// tunnel, a stale bundle — spend the budget that exists to bound how often key
// material actually moves.
func Budget(entries []keyholder.LedgerEntry, limit int, window time.Duration, now time.Time) BudgetState {
	b := BudgetState{Limit: limit, Window: window}
	cutoff := now.Add(-window)
	for _, e := range entries {
		if e.Intent != IntentReseed || e.Result != "ok" || e.Time.Before(cutoff) {
			continue
		}
		b.Used++
		if b.Oldest.IsZero() || e.Time.Before(b.Oldest) {
			b.Oldest = e.Time
		}
	}
	b.Allowed = b.Used < limit
	return b
}

func humanWindow(d time.Duration) string {
	if d >= 24*time.Hour {
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
	return d.String()
}

// Mismatch reports why re-seeding a restarted replica with this device's
// bundle would leave it unable to work beside the replicas still serving, or
// "" when no serving replica says so.
//
// The generation cannot tell. It counts pushes, so it moves on every operator
// unseal whether or not a key changed — and a replica that restarted reports
// zero, which is never newer than anything. That is the case that matters: a
// keeper enrolled before a rotation would answer the next restart by putting
// the old keys back, and the replica would then fail every read of an object
// written under the new ones.
//
// What can tell is the key IDs a SERVING replica holds, in two directions:
//
//   - Every key it holds must be in the bundle. A rotation's new key reaches
//     a replica held-but-unused first, so comparing only the key it writes
//     under would miss exactly the window in which some replica is about to
//     use one — and the restarted replica, re-seeded without it, could not
//     read what the others then write.
//   - The key the bundle writes under must be one it holds. A bundle can be
//     AHEAD of a replica — enrolled after a rotation that has not reached
//     every replica — and re-seeding with it would have the restarted one
//     write under a key the other cannot read.
//   - And not an OLDER one than it uses. A bundle enrolled from a keyring
//     that imported a rotation keeps that keyring's old active key, and
//     re-seeding with it would put the restarted replica back to writing
//     under a key a lost keeper may hold — undoing what the rotation was for.
//     (Which of two keys is older comes from when each was minted; two minted
//     in the same second cannot be told apart, and are not refused.)
//
// Keys are only ever added, so a bundle enrolled after everything a serving
// replica holds passes both.
//
// A restarted replica holds nothing to compare, so the verdict leans on the
// replicas that did not restart. With all of them restarted at once there is
// no reference, and a keeper re-seeds what it holds; refusing that is the
// in-cluster key-id pin ADR 0008 specifies and this does not provide.
func Mismatch(mine *datasphere.Bundle, states []keyholder.State) string {
	held := make(map[string]map[string]datasphere.KeyEntry, len(mine.Scopes()))
	active := make(map[string]string, len(mine.Scopes()))
	for _, s := range mine.Scopes() {
		ids := map[string]datasphere.KeyEntry{}
		for i, e := range s.Keyring().KEKs() {
			ids[e.ID.String()] = e
			if i == 0 {
				active[s.Name] = e.ID.String()
			}
		}
		held[s.Name] = ids
	}
	for i, st := range states {
		if st.Sealed() {
			continue
		}
		names := make([]string, 0, len(st.Keys))
		for name := range st.Keys {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			ids, ok := held[name]
			if !ok {
				return fmt.Sprintf("replica %d serves scope %s, which this device's bundle does not carry — an application was added after it was enrolled; re-enrol it", i, name)
			}
			for _, id := range st.Keys[name] {
				if _, ok := ids[id]; !ok {
					return fmt.Sprintf("replica %d holds a key for %s that this device's bundle does not carry — the instance's keys were rotated after it was enrolled; re-enrol it", i, name)
				}
			}
			if !slices.Contains(st.Keys[name], active[name]) {
				return fmt.Sprintf("this device's bundle writes %s under a key replica %d does not hold — a hand-over has not reached every replica yet, "+
					"and a replica re-seeded from this bundle could not be read by that one. The operator's 'farcast storage unseal' finishes it", name, i)
			}
			if theirs := st.Keys[name]; len(theirs) > 0 && theirs[0] != active[name] && ids[theirs[0]].Created.After(ids[active[name]].Created) {
				return fmt.Sprintf("this device's bundle carries the key replica %d writes %s under, but writes under an older one — it was enrolled mid-rotation, "+
					"or from a keyring that imported the rotation; re-enrol it from the machine that rotated, once the rotation has finished", i, name)
			}
		}
	}
	return ""
}
