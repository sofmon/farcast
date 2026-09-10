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
