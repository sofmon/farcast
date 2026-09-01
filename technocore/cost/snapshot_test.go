package cost

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSnapshotRoundTripsThroughJSON(t *testing.T) {
	l := newLedger(t)
	accrueHours(l, "web", 1, 10)
	accrueHours(l, "worker", 2, 4)
	mustConfirm(t, l, periodStart, periodStart.Add(5*time.Hour), 6)
	before := l.Accrued()

	blob, err := json.Marshal(l.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var s Snapshot
	if err := json.Unmarshal(blob, &s); err != nil {
		t.Fatal(err)
	}
	restored, err := Restore(s)
	if err != nil {
		t.Fatal(err)
	}

	after := restored.Accrued()
	closeTo(t, after.Total, before.Total, "total after restore")
	closeTo(t, after.Confirmed, before.Confirmed, "confirmed after restore")
	closeTo(t, after.Expected, before.Expected, "expected after restore")
	closeTo(t, after.Calibration, before.Calibration, "calibration after restore")
	if after.HasConfirmation != before.HasConfirmation || !after.ConfirmedThrough.Equal(before.ConfirmedThrough) {
		t.Error("confirmation state did not survive the round trip")
	}
	closeTo(t, restored.ByApp()["worker"], l.ByApp()["worker"], "worker attribution")
}

// A restart must not lose the period's accrued spend — that is the entire
// reason the checkpoint exists. A meter that resets to zero on restart never
// trips the limit.
func TestARestoredLedgerRemembersWhatWasSpent(t *testing.T) {
	l := newLedger(t)
	accrueHours(l, "web", 1, 10)
	restored, err := Restore(l.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if got := restored.Accrued().Total; got != 10 {
		t.Fatalf("restored total = %.2f, want 10", got)
	}
}

// An unknown version is refused rather than best-guessed: a cost meter that
// silently misreads its own history under-reports, and always in the
// flattering direction.
func TestRestoreRefusesAnUnknownVersion(t *testing.T) {
	s := newLedger(t).Snapshot()
	s.Version = SnapshotVersion + 1
	if _, err := Restore(s); err == nil {
		t.Fatal("expected a refusal for a newer snapshot version")
	}
	s.Version = 0
	if _, err := Restore(s); err == nil {
		t.Fatal("expected a refusal for a versionless snapshot")
	}
}

// The checkpoint is cloud-resident state. Replaying confirmations through the
// validating path means a tampered one cannot install a calibration the
// running code would have refused.
func TestRestoreReplaysConfirmationsThroughTheClamp(t *testing.T) {
	l := newLedger(t)
	accrueHours(l, "web", 1, 10)
	s := l.Snapshot()
	// Somebody edits the ConfigMap to claim the first five hours were free.
	s.Confirmations = []Confirmation{{Start: periodStart, End: periodStart.Add(5 * time.Hour), USD: 0}}

	restored, err := Restore(s)
	if err != nil {
		t.Fatal(err)
	}
	a := restored.Accrued()
	if a.Total != 10 {
		t.Errorf("total = %.2f, want 10 — a tampered confirmation must not reduce it", a.Total)
	}
	closeTo(t, a.Calibration, 1, "calibration")
	if len(a.Discrepancies) != 1 {
		t.Errorf("the refused confirmation should be recorded as a discrepancy, got %d", len(a.Discrepancies))
	}
}

func TestRestoreRefusesCorruptContent(t *testing.T) {
	base := func(t *testing.T) Snapshot {
		l := newLedger(t)
		accrueHours(l, "web", 1, 4)
		return l.Snapshot()
	}

	bad := base(t)
	bad.Hourly["not-a-number"] = 1
	if _, err := Restore(bad); err == nil {
		t.Error("a non-numeric hour key must be refused")
	}

	neg := base(t)
	for k := range neg.Hourly {
		neg.Hourly[k] = -100
		break
	}
	if _, err := Restore(neg); err == nil {
		t.Error("negative expected spend must be refused")
	}

	negApp := base(t)
	negApp.Apps["web"] = -5
	if _, err := Restore(negApp); err == nil {
		t.Error("negative per-app spend must be refused")
	}

	overlapping := base(t)
	overlapping.Confirmations = []Confirmation{
		{Start: periodStart, End: periodStart.Add(3 * time.Hour), USD: 3},
		{Start: periodStart.Add(time.Hour), End: periodStart.Add(4 * time.Hour), USD: 3},
	}
	if _, err := Restore(overlapping); err == nil {
		t.Error("overlapping confirmations must be refused on restore as on write")
	}
}

// The persisted shape is a decision, not an accident of which fields happen
// to be exported. If this breaks, something changed what gets written.
func TestSnapshotShapeIsStable(t *testing.T) {
	l := newLedger(t)
	l.Accrue(periodStart, "web", 1, time.Hour)
	blob, err := json.Marshal(l.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(blob, &generic); err != nil {
		t.Fatal(err)
	}
	want := []string{"version", "period_start", "period_end", "hourly", "apps", "confirmations"}
	if len(generic) != len(want) {
		t.Errorf("snapshot has %d fields (%v), want exactly %v", len(generic), keysOf(generic), want)
	}
	for _, k := range want {
		if _, ok := generic[k]; !ok {
			t.Errorf("snapshot is missing %q", k)
		}
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
