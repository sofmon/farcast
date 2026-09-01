package cost

import (
	"testing"
	"time"
)

var (
	now = time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	end = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
)

func TestThresholdsFireOnAccruedSpend(t *testing.T) {
	cases := []struct {
		total float64
		want  Level
	}{
		{0, LevelOK}, {49, LevelOK},
		{50, LevelWarn50}, {74.9, LevelWarn50},
		{75, LevelWarn75}, {89.9, LevelWarn75},
		{90, LevelWarn90}, {99.9, LevelWarn90},
		{100, LevelReached}, {250, LevelReached},
	}
	for _, c := range cases {
		got := Assess(c.total, 100, 0, now, end).Level
		if got != c.want {
			t.Errorf("total %.1f of 100: level = %v, want %v", c.total, got, c.want)
		}
	}
}

// Only a limit actually reached authorises stopping anything. A projection is
// a warning — an instance is never stopped on a forecast.
func TestOnlyAReachedLimitAuthorisesAction(t *testing.T) {
	for _, l := range []Level{LevelOK, LevelWarn50, LevelWarn75, LevelWarn90} {
		if l.Acts() {
			t.Errorf("%v must not authorise protective action", l)
		}
	}
	if !LevelReached.Acts() {
		t.Error("a reached limit must authorise protective action")
	}

	// A burn rate that will blow the limit tomorrow still does not act today.
	a := Assess(10, 100, 100, now, end)
	if !a.ProjectedOver {
		t.Fatal("expected a projection warning")
	}
	if a.Level.Acts() {
		t.Error("a projection must never authorise action")
	}
}

func TestProjectionUsesTheRemainingPeriod(t *testing.T) {
	// 12h left, $1/h, $10 accrued of a $100 limit → $22 projected, under.
	shortly := end.Add(-12 * time.Hour)
	a := Assess(10, 100, 1, shortly, end)
	if a.Projected != 22 {
		t.Errorf("projected = %.2f, want 22", a.Projected)
	}
	if a.ProjectedOver {
		t.Error("22 of 100 is not over")
	}

	// Same rate with the whole period left is over.
	b := Assess(10, 100, 1, end.Add(-200*time.Hour), end)
	if !b.ProjectedOver {
		t.Errorf("projected %.2f of 100 should be over", b.Projected)
	}
	// $90 of headroom at $1/h → 90 hours away.
	wantAt := end.Add(-200 * time.Hour).Add(90 * time.Hour)
	if b.ProjectedAt.Sub(wantAt).Abs() > time.Minute {
		t.Errorf("ProjectedAt = %v, want ~%v", b.ProjectedAt, wantAt)
	}
}

// Every FarCast instance must have a cost limit, so an absent one is a bug
// elsewhere. Inventing a shutdown here would turn that bug into an outage.
func TestAnAbsentLimitNeverActs(t *testing.T) {
	for _, limit := range []float64{0, -1} {
		a := Assess(1000, limit, 10, now, end)
		if a.Level != LevelOK || a.Level.Acts() {
			t.Errorf("limit %v: level = %v, want OK", limit, a.Level)
		}
		if a.ProjectedOver {
			t.Errorf("limit %v: must not project over", limit)
		}
	}
}

func TestAPeriodThatHasEndedProjectsNothingFurther(t *testing.T) {
	a := Assess(50, 100, 100, end.Add(time.Hour), end)
	if a.Projected != 50 {
		t.Errorf("projected = %.2f, want the accrued 50 — the period is over", a.Projected)
	}
	if a.ProjectedOver {
		t.Error("a finished period cannot project over")
	}
}

func TestAnIdleInstanceProjectsItsCurrentTotal(t *testing.T) {
	a := Assess(30, 100, 0, now, end)
	if a.Projected != 30 || a.ProjectedOver {
		t.Errorf("idle projection = %.2f over=%v, want 30 and not over", a.Projected, a.ProjectedOver)
	}
}
