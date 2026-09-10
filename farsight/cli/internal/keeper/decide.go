package keeper

import (
	"fmt"
	"time"

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
	// ActionStale: the cluster holds a NEWER generation than this device's
	// bundle. A rekey happened and this keeper was not re-enrolled, so its
	// bundle would be refused. Degradation, never corruption.
	ActionStale Action = "stale-bundle"
	// ActionUnknown: the replica did not answer.
	ActionUnknown Action = "unreachable"
)

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
func Decide(st keyholder.State, err error, ordinal int, mine uint64, budget BudgetState) Decision {
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
