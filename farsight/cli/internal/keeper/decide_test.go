package keeper

import (
	"errors"
	"strings"
	"testing"
	"time"

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
		d := Decide(sealed, nil, 0, 3, allowed())
		if d.Action != ActionReseed {
			t.Errorf("Action = %q, want %q (%s)", d.Action, ActionReseed, d.Reason)
		}
	})

	t.Run("an unsealed replica is left alone", func(t *testing.T) {
		d := Decide(keyholder.State{Phase: "unsealed", Generation: 3}, nil, 0, 3, allowed())
		if d.Action != ActionNone {
			t.Errorf("Action = %q, want %q", d.Action, ActionNone)
		}
	})

	// The line the whole design rests on: "sealed because restarted" and
	// "sealed because the operator said so" are different states, and a keeper
	// may only remedy the first.
	t.Run("an operator hold is never a keeper's to clear", func(t *testing.T) {
		d := Decide(keyholder.State{Phase: "operator-hold", HoldReason: "suspected compromise"}, nil, 0, 3, allowed())
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
		if d := Decide(keyholder.State{Phase: "operator-hold"}, nil, 0, 3, allowed()); d.Action == ActionReseed {
			t.Error("a keeper re-seeded through an operator hold")
		}
	})

	t.Run("a spent budget refuses rather than re-seeding", func(t *testing.T) {
		d := Decide(sealed, nil, 0, 3, spent())
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
		d := Decide(keyholder.State{Phase: "restart-sealed", Generation: 5}, nil, 0, 3, allowed())
		if d.Action != ActionStale {
			t.Errorf("Action = %q, want %q", d.Action, ActionStale)
		}
		if !strings.Contains(d.Reason, "re-enrol") {
			t.Errorf("the refusal does not say what to do: %q", d.Reason)
		}
	})

	t.Run("an unreachable replica is unknown, not sealed", func(t *testing.T) {
		d := Decide(keyholder.State{}, errors.New("dial failed"), 1, 3, allowed())
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
