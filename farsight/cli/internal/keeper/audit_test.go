package keeper

import (
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
)

func reseed(t time.Time, device, boot, result string) keyholder.LedgerEntry {
	return keyholder.LedgerEntry{
		Time: t, Instance: "prod", Intent: IntentReseed,
		Device: device, Boot: boot, Result: result,
	}
}

// One reseed per keyholder process is a cluster restarting and a keeper doing
// its job.
func TestReconcileCleanFleet(t *testing.T) {
	now := time.Now().UTC()
	a := Reconcile("prod", []keyholder.LedgerEntry{
		reseed(now.Add(-72*time.Hour), "study-desktop", "aaaa1111", "ok"),
		reseed(now.Add(-48*time.Hour), "study-desktop", "bbbb2222", "ok"),
		reseed(now.Add(-24*time.Hour), "home-server", "cccc3333", "ok"),
	})
	if !a.Clean() {
		t.Errorf("a clean fleet was flagged: %+v", a.Divergent)
	}
	if a.Reseeds != 3 || a.Boots != 3 {
		t.Errorf("reseeds=%d boots=%d, want 3 and 3", a.Reseeds, a.Boots)
	}
	if len(a.Devices) != 2 {
		t.Errorf("devices = %v, want both", a.Devices)
	}
}

// Two pushes into the SAME process is the shape of a solicitation: a process is
// sealed once per restart, so the second push had nothing to restore.
func TestReconcileFlagsARepeatedProcess(t *testing.T) {
	now := time.Now().UTC()
	a := Reconcile("prod", []keyholder.LedgerEntry{
		reseed(now.Add(-72*time.Hour), "study-desktop", "aaaa1111", "ok"),
		reseed(now.Add(-71*time.Hour), "study-desktop", "aaaa1111", "ok"),
		reseed(now.Add(-24*time.Hour), "home-server", "cccc3333", "ok"),
	})
	if a.Clean() {
		t.Fatal("a process re-seeded twice was not flagged")
	}
	if len(a.Divergent) != 1 || a.Divergent[0].Boot != "aaaa1111" || a.Divergent[0].Count != 2 {
		t.Errorf("Divergent = %+v, want one entry for aaaa1111 with 2", a.Divergent)
	}
	if a.Reseeds != 3 || a.Boots != 2 {
		t.Errorf("reseeds=%d boots=%d, want 3 into 2 processes", a.Reseeds, a.Boots)
	}
}

// Budgets add across a fleet, and a push aimed at one device is invisible in
// that device's own count. Two devices seeding one process is ordinary — they
// can both wake to the same restart — and is still reported so an operator
// sees it.
func TestReconcileAttributesAFleet(t *testing.T) {
	now := time.Now().UTC()
	a := Reconcile("prod", []keyholder.LedgerEntry{
		reseed(now.Add(-2*time.Hour), "study-desktop", "aaaa1111", "ok"),
		reseed(now.Add(-2*time.Hour), "home-server", "aaaa1111", "ok"),
	})
	if len(a.Divergent) != 1 || a.Divergent[0].Device != "fleet" {
		t.Errorf("Divergent = %+v, want it attributed to the fleet rather than one device", a.Divergent)
	}
}

// A push that names no process cannot be reconciled, and must not silently
// improve the ratio the audit turns on.
func TestReconcileCountsUnlabelledPushesSeparately(t *testing.T) {
	now := time.Now().UTC()
	a := Reconcile("prod", []keyholder.LedgerEntry{
		reseed(now.Add(-2*time.Hour), "study-desktop", "", "ok"),
		reseed(now.Add(-1*time.Hour), "study-desktop", "aaaa1111", "ok"),
	})
	if a.Unlabelled != 1 {
		t.Errorf("Unlabelled = %d, want 1", a.Unlabelled)
	}
	if a.Boots != 1 {
		t.Errorf("Boots = %d, want 1 — an unlabelled push is not a process", a.Boots)
	}
	if !a.Clean() {
		t.Error("an unlabelled push was reported as divergence rather than as unreconcilable")
	}
}

func TestReconcileIgnoresOtherInstancesAndRefusals(t *testing.T) {
	now := time.Now().UTC()
	other := reseed(now, "study-desktop", "dddd4444", "ok")
	other.Instance = "staging"
	a := Reconcile("prod", []keyholder.LedgerEntry{
		other,
		reseed(now.Add(-time.Hour), "study-desktop", "aaaa1111", "refused"),
		reseed(now.Add(-2*time.Hour), "study-desktop", "bbbb2222", "ok"),
	})
	if a.Reseeds != 1 || a.Refused != 1 || a.Boots != 1 {
		t.Errorf("reseeds=%d refused=%d boots=%d, want 1/1/1", a.Reseeds, a.Refused, a.Boots)
	}
}

// pushed is a reseed entry that names its push, as a keeper writes one.
func pushed(t time.Time, device, boot, result, push string) keyholder.LedgerEntry {
	e := reseed(t, device, boot, result)
	e.Push = push
	return e
}

// Review finding RV2-1. A pending entry its outcome settled is read through
// that outcome: neither a second reseed nor a refusal. One nothing settled is
// a push the audit cannot rule out, so it counts as a reseed into the process
// it names, and is reported as unconfirmed — on the process's row too.
func TestReconcileReadsPendingEntriesThroughTheirOutcome(t *testing.T) {
	now := time.Now().UTC()
	a := Reconcile("prod", []keyholder.LedgerEntry{
		pushed(now.Add(-5*time.Hour), "study-desktop", "aaaa1111", ResultPending, "p1"),
		pushed(now.Add(-5*time.Hour), "study-desktop", "aaaa1111", "ok", "p1"),
		pushed(now.Add(-4*time.Hour), "study-desktop", "bbbb2222", ResultPending, "p2"),
		pushed(now.Add(-4*time.Hour), "study-desktop", "bbbb2222", "refused", "p2"),
		pushed(now.Add(-3*time.Hour), "study-desktop", "aaaa1111", ResultPending, "p3"),
	})
	if a.Reseeds != 2 || a.Refused != 1 || a.Unconfirmed != 1 {
		t.Errorf("reseeds=%d refused=%d unconfirmed=%d, want 2/1/1", a.Reseeds, a.Refused, a.Unconfirmed)
	}
	if len(a.Divergent) != 1 || a.Divergent[0].Boot != "aaaa1111" {
		t.Fatalf("Divergent = %+v; the unconfirmed push into aaaa1111 must count as a second one", a.Divergent)
	}
	if d := a.Divergent[0]; d.Unconfirmed != 1 || d.RefusedAfterSend != 0 {
		t.Errorf("Divergent[0] = %+v; want it to say one of its two pushes is unconfirmed", d)
	}
}

// Review finding V3-3. A push refused AFTER its bundle was sent moved key
// material as far as the device can tell — a solicitor holding the
// keyholder's server leaf reads the bundle and answers with a refusal — so
// the audit counts it as a reseed into the process it names, and says which
// rows it is on. A push refused before anything was sent is a refusal.
func TestReconcileCountsARefusalAfterSendingAsAPush(t *testing.T) {
	now := time.Now().UTC()
	a := Reconcile("prod", []keyholder.LedgerEntry{
		pushed(now.Add(-3*time.Hour), "study-desktop", "aaaa1111", ResultPending, "p1"),
		pushed(now.Add(-3*time.Hour), "study-desktop", "aaaa1111", "ok", "p1"),
		pushed(now.Add(-2*time.Hour), "study-desktop", "aaaa1111", ResultPending, "p2"),
		pushed(now.Add(-2*time.Hour), "study-desktop", "aaaa1111", ResultRefusedAfterSend, "p2"),
		pushed(now.Add(-1*time.Hour), "study-desktop", "bbbb2222", ResultPending, "p3"),
		pushed(now.Add(-1*time.Hour), "study-desktop", "bbbb2222", "refused", "p3"),
	})
	if a.Reseeds != 2 || a.RefusedAfterSend != 1 || a.Refused != 1 || a.Boots != 1 {
		t.Errorf("reseeds=%d after-send=%d refused=%d boots=%d, want 2/1/1/1", a.Reseeds, a.RefusedAfterSend, a.Refused, a.Boots)
	}
	if len(a.Divergent) != 1 || a.Divergent[0].Count != 2 || a.Divergent[0].RefusedAfterSend != 1 {
		t.Errorf("Divergent = %+v; want aaaa1111 twice, one of them refused after sending", a.Divergent)
	}
}

// Settling is by push id, and per device and replica: another device's
// outcome, this device's outcome for the other replica, or an outcome for
// another push settles nothing.
func TestUnsettledPairsEachPushWithItsOwnOutcome(t *testing.T) {
	now := time.Now().UTC()
	e := func(device string, ordinal int, result, push string) keyholder.LedgerEntry {
		x := pushed(now, device, "b", result, push)
		x.Ordinal = ordinal
		return x
	}
	entries := []keyholder.LedgerEntry{
		e("a", 0, ResultPending, "p1"), // 0: settled by 3
		e("b", 0, ResultPending, "p1"), // 1: unsettled — a's outcome is not b's
		e("a", 1, "ok", "p1"),          // 2: another replica's outcome
		e("a", 0, "ok", "p1"),          // 3
		e("a", 1, ResultPending, "p4"), // 4: unsettled — its outcome was lost
		e("a", 1, ResultPending, "p5"), // 5: settled by 6
		e("a", 1, "refused", "p5"),     // 6
		e("a", 1, ResultPending, ""),   // 7: no id, so nothing can settle it
		e("a", 1, "ok", ""),            // 8: settles nothing
	}
	op := e("", 0, ResultPending, "p9")
	op.Intent = "operator-unseal"
	entries = append(entries, op) // 9: not a reseed, never counted
	got := Unsettled(entries)
	want := map[int]bool{1: true, 4: true, 7: true}
	if len(got) != len(want) {
		t.Fatalf("Unsettled = %v, want %v", got, want)
	}
	for i := range want {
		if !got[i] {
			t.Errorf("Unsettled = %v, want %v", got, want)
		}
	}
}

// Review finding V3-1. Two keeper processes on one device — a timer's --once
// and a manual one — can both announce a push to the same replica before
// either makes it. Each outcome settles its own announcement: pairing by
// replica left the first one open although its outcome was recorded, and the
// audit then read a process re-seeded twice. Here B's push lands and A's is
// refused before anything was sent, in the order A announced, B announced, B
// landed, A was refused.
func TestUnsettledHoldsAcrossOverlappingPasses(t *testing.T) {
	now := time.Now().UTC()
	entries := []keyholder.LedgerEntry{
		pushed(now, "d", "boot-0", ResultPending, "A"),
		pushed(now, "d", "boot-0", ResultPending, "B"),
		pushed(now, "d", "boot-0", "ok", "B"),
		pushed(now, "d", "boot-0", "refused", "A"),
	}
	if open := Unsettled(entries); len(open) != 0 {
		t.Errorf("Unsettled = %v; both pushes' outcomes are recorded", open)
	}
	a := Reconcile("prod", entries)
	if a.Reseeds != 1 || a.Unconfirmed != 0 || !a.Clean() {
		t.Errorf("reseeds=%d unconfirmed=%d divergent=%+v; want 1, 0 and none", a.Reseeds, a.Unconfirmed, a.Divergent)
	}
	if b := Budget(entries, 8, DefaultWindow, now.Add(time.Minute)); b.Used != 1 {
		t.Errorf("budget used %d; want 1 for one push that landed", b.Used)
	}
}
