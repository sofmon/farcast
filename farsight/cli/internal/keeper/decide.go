package keeper

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/sofmon/farcast/datasphere"
	dskeyholder "github.com/sofmon/farcast/datasphere/keyholder"
	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
)

// IntentReseed is what a keeper claims to be doing. The keyholder refuses it
// against an operator hold, which is the in-cluster half of "a keeper never
// clears a deliberate seal".
const IntentReseed = "restart-reseed"

// ResultPending is the Result of the entry a keeper writes BEFORE it pushes.
// The push is recorded on this device's disk first, and is not made when that
// write fails, so no push can happen that the ledger could not record. The
// entry written after the push — "ok", ResultRefusedAfterSend or "refused" —
// settles it; both carry the same Push id, and nothing else settles it. A
// pending entry that nothing settles is a push whose outcome this device did
// not record, and both the budget and the audit count it as one that
// succeeded: the budget so that a ledger that stopped taking writes cannot
// stop it counting, and the audit because it cannot rule out that key
// material moved.
const ResultPending = "pending"

// ResultRefusedAfterSend is a push refused AFTER its sealed bundle was
// written to whatever answered: already serving, a pin it is below, a bundle
// the leaf does not bind, any other refusal or error once the request went
// out. It moved key material as far as the device can tell — the bundle is
// sealed to the challenge's key, and the challenge comes from whatever
// answered, which ADR 0008 finding 1's solicitor can be — so the budget and
// the audit count it as a push. "refused" is left for a push that sent
// nothing: the replica could not be dialled, did not complete the handshake,
// or would not issue a challenge. (A "refused" line written before this
// distinction existed may be either; it is read as the binary that wrote it
// decided, and not counted.)
const ResultRefusedAfterSend = "refused-after-send"

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
	// ActionStale: this device's BUNDLE does not hold what the fleet holds.
	// Either the cluster has held a newer generation, which the keyholder
	// would refuse anyway, or a serving replica's keys and the bundle's
	// disagree (see Mismatch), or the instance's key pin refuses it (see
	// Pinned) — the instance's keys were rotated, or an application added,
	// after this keeper was enrolled, or a hand-over has not reached every
	// replica yet. Degradation, never corruption. It is about the bundle
	// only: a re-enrolment is what changes the answer.
	ActionStale Action = "stale-bundle"
	// ActionPinUnreadable: the replica cannot read its own key pin, so it
	// refuses every re-seed whatever the bundle. That is not about this
	// device: the operator's 'farcast storage key pin' repairs it, and
	// re-enrolling the device changes nothing. The name is the keyholder's
	// own refusal code.
	ActionPinUnreadable Action = "pin-unreadable"
	// ActionUnknown: the replica did not answer.
	ActionUnknown Action = "unreachable"
	// ActionUnchecked: it would re-seed, but ANOTHER replica did not answer,
	// so whether that one serves keys this bundle lacks cannot be checked.
	// A replica that does not answer may well be serving; the next pass
	// retries.
	ActionUnchecked Action = "unchecked"
	// ActionLedgerUnwritable: it would re-seed, and this device's ledger
	// would not take the entry that records the push before it is made, so
	// nothing was pushed. It is a fault on this device, and a person's to
	// repair: an unrecorded push is one the budget never counts.
	ActionLedgerUnwritable Action = "ledger-unwritable"
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
	// Pinned says why the instance's key pin refuses this device's bundle.
	// It is read from every replica that answered, sealed ones included: the
	// pin is the reference that survives a restart, so it is there exactly
	// when no serving replica is.
	Pinned string
}

// Refusal is why this device's bundle would be refused by the fleet, or ""
// when nothing says so — Pinned, else Mismatch, in Decide's precedence. It
// does not depend on any replica being sealed: a keeper whose bundle the
// fleet has moved past learns it at the rotation, rather than at the next
// restart, which is the outage it exists for.
func (f Fleet) Refusal() string {
	if f.Pinned != "" {
		return f.Pinned
	}
	return f.Mismatch
}

// FleetOf reads the whole fleet's answers once. A replica that did not answer
// is unknown, not sealed: treated as sealed, a serving replica whose answer
// was merely lost was no reference at all, and a keeper enrolled before a
// rotation re-seeded the old keys beside it.
func FleetOf(mine *datasphere.Bundle, states []keyholder.State, errs []error) Fleet {
	f := Fleet{Mismatch: Mismatch(mine, states), Pinned: Pinned(mine, states, errs)}
	for i, err := range errs {
		if err != nil {
			f.Unchecked = fmt.Sprintf("replica %d did not answer, so whether it serves keys this device's bundle lacks cannot be checked; the next pass retries", i)
			break
		}
	}
	return f
}

// Pinned reports why the instance's key pin refuses this device's bundle, or
// "" when no replica's does. The keyholder refuses such a bundle itself; deciding it here
// keeps the keeper from spending a push, and a ledger line, on a refusal it
// can see coming — and says why in words.
//
// A replica that cannot read its pin is not named here: that is a fact about
// that replica, which refuses every re-seed whatever the bundle, and it is
// Decide's to say for that replica alone. Here it would stop a re-seed of a
// different replica whose own pin accepts the bundle.
//
// The verdict is the fleet's, not one replica's: a refusing pin on any
// replica stops the re-seed of a replica whose own pin is absent — the
// ConfigMap deleted under it — so the words name the instance's pin rather
// than whichever replica answered first, and a report prints them once.
func Pinned(mine *datasphere.Bundle, states []keyholder.State, errs []error) string {
	keys := dskeyholder.KeysOf(mine)
	for i, st := range states {
		if i < len(errs) && errs[i] != nil || st.Pin == nil {
			continue
		}
		switch st.Pin.Status {
		case dskeyholder.PinValid:
			p, ok := pinOf(st.Pin)
			if !ok {
				return fmt.Sprintf("the instance's key pin, as replica %d reports it, is one this device cannot read", i)
			}
			if err := p.Admits(keys); err != nil {
				return fmt.Sprintf("the instance's key pin refuses this device's bundle (%v) — the instance's keys were rotated, or an application added, "+
					"after it was enrolled; re-enrol it", err)
			}
		}
	}
	return ""
}

// PinUnreadableReason is why a keeper leaves alone a replica that cannot read
// its key pin. Re-enrolling changes nothing: the replica refuses every
// re-seed until the operator repairs the pin. It names no replica, because a
// report already prefixes the one it is about.
func PinUnreadableReason() string {
	return "this replica cannot read its key pin, so it refuses every re-seed whatever this device holds; " +
		"the operator's 'farcast storage key pin' repairs it, and enrolling this device again changes nothing"
}

func pinOf(r *dskeyholder.PinReport) (dskeyholder.Pin, bool) {
	var p dskeyholder.Pin
	for _, s := range r.Require {
		id, err := datasphere.ParseKeyID(s)
		if err != nil {
			return dskeyholder.Pin{}, false
		}
		p.Require = append(p.Require, id)
	}
	for _, s := range r.Retired {
		id, err := datasphere.ParseKeyID(s)
		if err != nil {
			return dskeyholder.Pin{}, false
		}
		p.Retired = append(p.Retired, id)
	}
	return p, true
}

// Decision is what a keeper concluded about one replica, and why.
type Decision struct {
	Ordinal int
	Action  Action
	Reason  string
	// FleetWide says the Reason is the fleet's verdict on this device's
	// bundle (Fleet.Refusal), not a fact about this replica. A report prints
	// it once for the pass rather than under every replica it stops.
	FleetWide bool
}

// Outcome is what a pass amounts to for whoever runs a keeper on a timer.
// The values are ordered: a pass is as bad as its worst replica.
type Outcome int

const (
	// OutcomeKept: every replica serves, was just re-seeded, or is held on
	// purpose by the operator.
	OutcomeKept Outcome = iota
	// OutcomeIncomplete: a replica or the tunnel did not answer, or a re-seed
	// could not be checked. The next pass retries.
	OutcomeIncomplete
	// OutcomeCannotKeep: this device cannot keep the instance until a person
	// acts — a stale bundle, an unreadable pin, a spent budget.
	OutcomeCannotKeep
)

// Outcome classes one replica's action. An action added without a mapping
// is CannotKeep: loud, rather than a silent success.
func (a Action) Outcome() Outcome {
	switch a {
	case ActionNone, ActionReseed, ActionHold:
		return OutcomeKept
	case ActionUnknown, ActionUnchecked:
		return OutcomeIncomplete
	default:
		return OutcomeCannotKeep
	}
}

// PassOutcome is the worst of a pass's decisions — and CannotKeep whenever the
// fleet refuses this device's bundle, though every replica is serving and no
// decision says so.
func PassOutcome(ds []Decision, f Fleet) Outcome {
	worst := OutcomeKept
	if f.Refusal() != "" {
		worst = OutcomeCannotKeep
	}
	for _, d := range ds {
		worst = max(worst, d.Action.Outcome())
	}
	return worst
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
	case st.Pin != nil && st.Pin.Status == dskeyholder.PinInvalid:
		d.Action, d.Reason = ActionPinUnreadable, PinUnreadableReason()
	case fleet.Pinned != "":
		d.Action, d.Reason, d.FleetWide = ActionStale, fleet.Pinned, true
	case fleet.Mismatch != "":
		d.Action, d.Reason, d.FleetWide = ActionStale, fleet.Mismatch, true
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
		return fmt.Sprintf("%d of %d %s used in the last %s", b.Used, b.Limit, reseedNoun(b.Limit), HumanWindow(b.Window))
	}
	msg := fmt.Sprintf("the reseed budget is spent: %d of %d in the last %s", b.Used, b.Limit, HumanWindow(b.Window))
	if !b.Oldest.IsZero() {
		msg += fmt.Sprintf(", and none expires before %s", b.Oldest.Add(b.Window).UTC().Format(time.RFC3339))
	}
	return msg
}

// Budget counts what this device has pushed inside the window.
//
// It counts every push whose sealed bundle left this device: a successful
// reseed, a push refused after the bundle was sent (ResultRefusedAfterSend),
// and a push recorded before it was made and never settled (ResultPending),
// whose outcome is unknown. A refusal after sending is not "no key material
// moved": the bundle went to whatever answered the challenge, and a
// solicitor holding the keyholder's server leaf can read it and answer every
// push with a refusal — a budget that skipped refusals would never trip on
// it. What it does not count is a push that sent nothing ("refused": no
// dial, no handshake, no challenge), so an unreachable tunnel cannot spend
// the budget; a stale bundle is refused before any push is made, and does
// not reach the ledger at all. The price is that a push that loses a race to
// another pusher — the operator, another device — spends a slot, which is
// the direction a tripwire should err in.
func Budget(entries []keyholder.LedgerEntry, limit int, window time.Duration, now time.Time) BudgetState {
	b := BudgetState{Limit: limit, Window: window}
	cutoff := now.Add(-window)
	open := Unsettled(entries)
	for i, e := range entries {
		if e.Intent != IntentReseed || e.Time.Before(cutoff) {
			continue
		}
		if !Delivered(e, open[i]) {
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

// HumanWindow names a budget window the way an operator sets it: in days when
// it is a whole number of them, and otherwise as the duration it is. It never
// rounds: a 36-hour window read as "1 day" would be a budget that recovers a
// half-day later than the operator was told.
func HumanWindow(d time.Duration) string {
	const day = 24 * time.Hour
	if d >= day && d%day == 0 {
		if n := d / day; n != 1 {
			return fmt.Sprintf("%d days", n)
		}
		return "1 day"
	}
	s := d.String()
	// "36h0m0s" reads as "36h", "1h30m0s" as "1h30m": the zero units are noise.
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// reseedNoun agrees with a count: "1 reseed", "8 reseeds".
func reseedNoun(n int) string {
	if n == 1 {
		return "reseed"
	}
	return "reseeds"
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
// no serving reference; the key pin is the one that survives a restart, and
// Pinned reads it — and the keyholder enforces it whatever this decides.
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
