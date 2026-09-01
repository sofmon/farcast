package cost

import (
	"math"
	"testing"
	"time"
)

var (
	periodStart = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	periodEnd   = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
)

func newLedger(t *testing.T) *Ledger {
	t.Helper()
	l, err := NewLedger(periodStart, periodEnd)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func closeTo(t *testing.T, got, want float64, what string) {
	t.Helper()
	if math.Abs(got-want) > 0.001 {
		t.Errorf("%s = %.4f, want %.4f", what, got, want)
	}
}

// accrue runs one app at a flat hourly rate for n whole hours from the period
// start, one hour per bucket. Each call ends at the hour boundary it fills,
// so hour i's spend lands in hour i's bucket.
func accrueHours(l *Ledger, app string, usdPerHour float64, n int) {
	for i := range n {
		endsAt := periodStart.Add(time.Duration(i+1) * time.Hour)
		l.Accrue(endsAt, app, usdPerHour, time.Hour)
	}
}

func TestExpectedAccruesWithoutAnyConfirmation(t *testing.T) {
	l := newLedger(t)
	accrueHours(l, "web", 1, 10)

	a := l.Accrued()
	closeTo(t, a.Expected, 10, "expected")
	closeTo(t, a.Total, 10, "total")
	closeTo(t, a.Confirmed, 0, "confirmed")
	if a.HasConfirmation {
		t.Error("nothing has been confirmed; HasConfirmation must be false")
	}
	if !a.ConfirmedThrough.IsZero() {
		t.Errorf("ConfirmedThrough = %v, want zero", a.ConfirmedThrough)
	}
	closeTo(t, a.Calibration, 1, "calibration")
}

// The failure this field exists to prevent: an instance whose billing feed has
// never arrived must not read as an instance that has spent nothing.
func TestNoConfirmationIsDistinctFromConfirmedZero(t *testing.T) {
	never := newLedger(t)
	accrueHours(never, "web", 1, 10)

	zero := newLedger(t)
	accrueHours(zero, "web", 1, 10)
	if _, err := zero.Confirm(Confirmation{Start: periodStart, End: periodStart.Add(5 * time.Hour), USD: 0}); err != nil {
		t.Fatal(err)
	}

	if never.Accrued().HasConfirmation {
		t.Error("a ledger with no confirmations reports HasConfirmation")
	}
	if !zero.Accrued().HasConfirmation {
		t.Error("a confirmation of zero is still a confirmation")
	}

	// The case that actually distinguishes the two: a genuinely idle window,
	// where the provider confirms $0 and the model also expected $0. The
	// confirmed total is zero and the flag must still be set — deriving the
	// flag from the amount would report "never confirmed" for an instance
	// whose provider has confirmed, correctly, that it cost nothing.
	idle := newLedger(t)
	for i := 5; i < 10; i++ {
		// Ends at the boundary it fills, so hour i's spend is in hour i's
		// bucket and hours 0-4 are genuinely idle.
		idle.Accrue(periodStart.Add(time.Duration(i+1)*time.Hour), "web", 1, time.Hour)
	}
	if _, err := idle.Confirm(Confirmation{Start: periodStart, End: periodStart.Add(5 * time.Hour), USD: 0}); err != nil {
		t.Fatal(err)
	}
	a := idle.Accrued()
	closeTo(t, a.Confirmed, 0, "confirmed over an idle window")
	if !a.HasConfirmation {
		t.Error("an idle window confirmed at $0 must still count as a confirmation")
	}
	if a.ConfirmedThrough.IsZero() {
		t.Error("ConfirmedThrough must advance even when the confirmed amount is zero")
	}
}

// The provider is trusted inside the clamp: it corrects both the confirmed
// window and, through calibration, the estimate for the rest of the period.
func TestConfirmationCorrectsAndCalibratesWithinTheClamp(t *testing.T) {
	l := newLedger(t)
	accrueHours(l, "web", 1, 10) // $10 modelled, $1/h for 10h

	// The provider says the first 5 hours actually cost $6 — the model was
	// 20% low, which is exactly the staleness calibration exists to fix.
	if d, err := l.Confirm(Confirmation{Start: periodStart, End: periodStart.Add(5 * time.Hour), USD: 6}); err != nil || d != nil {
		t.Fatalf("in-clamp confirmation was refused: d=%v err=%v", d, err)
	}

	a := l.Accrued()
	closeTo(t, a.Confirmed, 6, "confirmed")
	closeTo(t, a.Calibration, 1.2, "calibration")
	// The unconfirmed 5 hours are $5 modelled, raised by the same factor.
	closeTo(t, a.Expected, 6, "calibrated expected")
	closeTo(t, a.Total, 12, "total")
	if a.ConfirmedThrough != periodStart.Add(5*time.Hour) {
		t.Errorf("ConfirmedThrough = %v", a.ConfirmedThrough)
	}
	if len(a.Discrepancies) != 0 {
		t.Errorf("in-clamp confirmation produced a discrepancy: %v", a.Discrepancies)
	}
}

// The security property. A confirmed feed reporting far too little would
// otherwise drive calibration toward zero and switch the guard off — turning
// the late, external, least-trusted signal into a way to disable protection.
func TestAConfirmationCannotLoosenTheGuardBeyondTheClamp(t *testing.T) {
	l := newLedger(t)
	accrueHours(l, "web", 1, 10)

	d, err := l.Confirm(Confirmation{Start: periodStart, End: periodStart.Add(5 * time.Hour), USD: 0})
	if err != nil {
		t.Fatal(err)
	}
	if d == nil {
		t.Fatal("a confirmation of $0 against $5 expected must be refused as a discrepancy")
	}

	a := l.Accrued()
	// The refused window keeps the model's own figure, so the total is
	// unchanged rather than halved.
	closeTo(t, a.Total, 10, "total after a spoofed-zero confirmation")
	closeTo(t, a.Calibration, 1, "calibration must not move on a refused confirmation")
	if len(a.Discrepancies) != 1 {
		t.Fatalf("expected 1 discrepancy, got %d", len(a.Discrepancies))
	}
	if a.Discrepancies[0].Ratio != 0 {
		t.Errorf("discrepancy ratio = %v, want 0", a.Discrepancies[0].Ratio)
	}
}

// The other direction is not symmetric, and must not be: a bill far higher
// than the model is a surprise the operator needs acted on now, so it tightens
// immediately even though it is equally far outside the clamp.
func TestAnUnexpectedlyLargeBillTightensImmediately(t *testing.T) {
	l := newLedger(t)
	accrueHours(l, "web", 1, 10)

	d, err := l.Confirm(Confirmation{Start: periodStart, End: periodStart.Add(5 * time.Hour), USD: 500})
	if err != nil {
		t.Fatal(err)
	}
	if d == nil {
		t.Fatal("$500 against $5 expected is a discrepancy")
	}

	a := l.Accrued()
	// $500 for the confirmed window + $5 uncalibrated for the rest.
	closeTo(t, a.Total, 505, "total")
	closeTo(t, a.Calibration, 1, "a refused confirmation must not calibrate")
}

// Calibration is cumulative across confirmed windows rather than "the last one
// wins", so one noisy window cannot swing the estimate for the whole period.
func TestCalibrationIsCumulativeAcrossWindows(t *testing.T) {
	l := newLedger(t)
	accrueHours(l, "web", 1, 10)

	mustConfirm(t, l, periodStart, periodStart.Add(4*time.Hour), 4)                  // ratio 1.0
	mustConfirm(t, l, periodStart.Add(4*time.Hour), periodStart.Add(8*time.Hour), 6) // ratio 1.5
	// Cumulative: (4+6) / (4+4) = 1.25, not 1.5.
	closeTo(t, l.Accrued().Calibration, 1.25, "cumulative calibration")
}

func TestConfirmationsMustNotOverlapOrEscapeThePeriod(t *testing.T) {
	l := newLedger(t)
	accrueHours(l, "web", 1, 10)
	mustConfirm(t, l, periodStart, periodStart.Add(5*time.Hour), 5)

	cases := map[string]Confirmation{
		"overlapping":   {Start: periodStart.Add(4 * time.Hour), End: periodStart.Add(6 * time.Hour), USD: 2},
		"before period": {Start: periodStart.Add(-time.Hour), End: periodStart, USD: 1},
		"after period":  {Start: periodEnd, End: periodEnd.Add(time.Hour), USD: 1},
		"empty window":  {Start: periodStart.Add(6 * time.Hour), End: periodStart.Add(6 * time.Hour), USD: 1},
		"negative":      {Start: periodStart.Add(6 * time.Hour), End: periodStart.Add(7 * time.Hour), USD: -1},
	}
	for name, c := range cases {
		if _, err := l.Confirm(c); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// A provider figure is instance-level, so it can correct the total but must
// never claim to know which application caused it.
func TestAttributionAlwaysComesFromTheLocalModel(t *testing.T) {
	l := newLedger(t)
	accrueHours(l, "web", 1, 10)
	accrueHours(l, "worker", 2, 10)
	mustConfirm(t, l, periodStart, periodStart.Add(5*time.Hour), 20)

	by := l.ByApp()
	closeTo(t, by["web"], 10, "web")
	closeTo(t, by["worker"], 20, "worker")
	if _, ok := by["confirmed"]; ok {
		t.Error("confirmation must not appear as an attribution key")
	}

	// The returned map is a copy; mutating it must not corrupt the ledger.
	by["web"] = 999
	closeTo(t, l.ByApp()["web"], 10, "web after caller mutation")
}

func TestAccrueIgnoresNonBillableIntervals(t *testing.T) {
	l := newLedger(t)
	l.Accrue(periodStart, "web", 1, 0)
	l.Accrue(periodStart, "web", 1, -time.Hour)
	l.Accrue(periodStart, "web", 0, time.Hour)
	l.Accrue(periodStart, "web", -1, time.Hour)
	closeTo(t, l.Accrued().Total, 0, "total")
}

func TestNewLedgerRejectsAnEmptyPeriod(t *testing.T) {
	if _, err := NewLedger(periodEnd, periodStart); err == nil {
		t.Fatal("expected an error for a period that ends before it starts")
	}
	if _, err := NewLedger(periodStart, periodStart); err == nil {
		t.Fatal("expected an error for a zero-length period")
	}
}

func mustConfirm(t *testing.T, l *Ledger, start, end time.Time, usd float64) {
	t.Helper()
	if _, err := l.Confirm(Confirmation{Start: start, End: end, USD: usd}); err != nil {
		t.Fatal(err)
	}
}

// A restart gap is billed as one multi-hour interval. Lumping it into a single
// bucket would make the model's per-window figures fiction — and those figures
// are exactly what a confirmation is compared against, so the distortion would
// surface as a phantom drift, or as a discrepancy against a provider that was
// right all along.
func TestALongIntervalIsSpreadAcrossTheHoursItSpans(t *testing.T) {
	l := newLedger(t)
	// Six hours at $1/h, billed in one call, as a restarted kernel would.
	l.Accrue(periodStart.Add(6*time.Hour), "web", 1, 6*time.Hour)

	closeTo(t, l.Accrued().Total, 6, "period total")
	// Every hour it spanned carries its own hour's worth.
	for i := range 6 {
		from := periodStart.Add(time.Duration(i) * time.Hour)
		closeTo(t, l.expectedIn(from, from.Add(time.Hour)), 1, "hour "+string(rune('0'+i)))
	}
	// And nothing landed outside the interval.
	closeTo(t, l.expectedIn(periodStart.Add(6*time.Hour), periodEnd), 0, "after the interval")
}

// A confirmation covering part of a restart gap must compare against the model
// for that part alone. Before the accrual was spread this was the case that
// produced a spurious discrepancy.
func TestAConfirmationOverlappingARestartGapComparesFairly(t *testing.T) {
	l := newLedger(t)
	l.Accrue(periodStart.Add(6*time.Hour), "web", 1, 6*time.Hour)

	// The provider confirms the first three hours at exactly what the model
	// says they cost.
	d, err := l.Confirm(Confirmation{Start: periodStart, End: periodStart.Add(3 * time.Hour), USD: 3})
	if err != nil {
		t.Fatal(err)
	}
	if d != nil {
		t.Fatalf("an exactly-correct confirmation was refused: %s", d)
	}
	a := l.Accrued()
	closeTo(t, a.Calibration, 1, "calibration")
	closeTo(t, a.Total, 6, "total")
}

// A partial hour lands proportionally, so a reconcile that straddles a
// boundary does not credit a whole hour to either side.
func TestAPartialHourIsSplitProportionally(t *testing.T) {
	l := newLedger(t)
	// 30 minutes ending 15 minutes into hour 1: 15 min in hour 0, 15 in hour 1.
	l.Accrue(periodStart.Add(75*time.Minute), "web", 4, 30*time.Minute)

	closeTo(t, l.expectedIn(periodStart, periodStart.Add(time.Hour)), 1, "hour 0")
	closeTo(t, l.expectedIn(periodStart.Add(time.Hour), periodStart.Add(2*time.Hour)), 1, "hour 1")
	closeTo(t, l.Accrued().Total, 2, "total")
}
