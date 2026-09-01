package cost

import (
	"testing"
	"time"
)

func TestPeriodForMonthly(t *testing.T) {
	got, end, err := PeriodFor(time.Date(2026, 9, 15, 12, 30, 0, 0, time.UTC), PeriodMonthly)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("start = %v, want the first of the month", got)
	}
	if !end.Equal(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("end = %v, want the first of the next month", end)
	}
}

// AddDate, not a fixed 30 days: months are not all the same length, and a
// window that drifted would eventually apply a monthly limit to a fortnight.
func TestMonthlyPeriodsCoverWholeCalendarMonths(t *testing.T) {
	for _, at := range []time.Time{
		time.Date(2026, 1, 31, 23, 59, 59, 0, time.UTC),
		time.Date(2026, 2, 28, 0, 0, 0, 0, time.UTC),
		time.Date(2028, 2, 29, 12, 0, 0, 0, time.UTC), // leap day
		time.Date(2026, 12, 31, 23, 0, 0, 0, time.UTC),
	} {
		start, end, err := PeriodFor(at, PeriodMonthly)
		if err != nil {
			t.Fatal(err)
		}
		if at.Before(start) || !at.Before(end) {
			t.Errorf("%v is not inside its own period [%v, %v)", at, start, end)
		}
		if start.Day() != 1 || end.Day() != 1 {
			t.Errorf("period [%v, %v) does not span whole months", start, end)
		}
	}
}

// A non-UTC instant lands in the UTC window that contains it — the ledger's
// hour buckets are UTC, so a period in some other zone would misalign with the
// very thing it accounts for.
func TestPeriodsAreComputedInUTC(t *testing.T) {
	zone := time.FixedZone("UTC+13", 13*3600)
	// 2026-10-01 01:00 +13 is 2026-09-30 12:00 UTC: still September.
	start, _, err := PeriodFor(time.Date(2026, 10, 1, 1, 0, 0, 0, zone), PeriodMonthly)
	if err != nil {
		t.Fatal(err)
	}
	if start.Month() != time.September {
		t.Errorf("start = %v, want September — periods follow the ledger's UTC buckets", start)
	}
}

// Silently treating an unknown period as monthly would apply a limit to a
// window nobody chose, invisibly until the bill arrived.
func TestAnUnknownPeriodIsRefused(t *testing.T) {
	for _, p := range []string{"", "weekly", "MONTHLY", "month", "yearly"} {
		if _, _, err := PeriodFor(time.Now(), p); err == nil {
			t.Errorf("period %q was accepted", p)
		}
	}
}
