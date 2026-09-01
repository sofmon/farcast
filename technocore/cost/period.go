package cost

import (
	"fmt"
	"time"
)

// Supported limit periods. An instance's cost limit is captured at install as
// an amount, a currency and a period; this is the part that decides which
// window the amount applies to.
const (
	PeriodMonthly = "monthly"
	PeriodDaily   = "daily"
)

// PeriodFor returns the half-open accounting window containing now.
//
// An unrecognised period is an error rather than a default. Silently treating
// an unknown period as monthly would apply a limit to a window nobody chose,
// and the failure would be invisible until the bill arrived.
func PeriodFor(now time.Time, period string) (start, end time.Time, err error) {
	n := now.UTC()
	switch period {
	case PeriodMonthly:
		start = time.Date(n.Year(), n.Month(), 1, 0, 0, 0, 0, time.UTC)
		return start, start.AddDate(0, 1, 0), nil
	case PeriodDaily:
		start = time.Date(n.Year(), n.Month(), n.Day(), 0, 0, 0, 0, time.UTC)
		return start, start.AddDate(0, 0, 1), nil
	default:
		return time.Time{}, time.Time{}, fmt.Errorf("cost: unknown limit period %q (want %q or %q)",
			period, PeriodMonthly, PeriodDaily)
	}
}
