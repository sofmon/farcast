package cost

import "time"

// Level is how close an instance is to its cost limit.
type Level int

const (
	LevelOK Level = iota
	LevelWarn50
	LevelWarn75
	LevelWarn90
	// LevelReached is the only level that authorises protective action.
	LevelReached
)

func (l Level) String() string {
	switch l {
	case LevelWarn50:
		return "50%"
	case LevelWarn75:
		return "75%"
	case LevelWarn90:
		return "90%"
	case LevelReached:
		return "limit reached"
	default:
		return "ok"
	}
}

// Acts reports whether this level authorises stopping anything. Only a limit
// actually reached does — [ADR 0009] decision 9: warn on a projection, act on
// an accrual. An instance is never stopped on a forecast.
//
// [ADR 0009]: ../../docs/adr/0009-technocore-kernel-and-cost-metering.md
func (l Level) Acts() bool { return l == LevelReached }

// Assessment is where an instance stands against its limit.
type Assessment struct {
	Total    float64
	Limit    float64
	Fraction float64
	Level    Level

	// Projected is what the period is on course to cost if the current burn
	// rate holds to its end.
	Projected float64
	// ProjectedOver is the early signal: the limit has not been reached, but
	// the current rate says it will be before the period ends. It warns and
	// never acts.
	ProjectedOver bool
	// ProjectedAt is when the limit is projected to be reached, zero if it
	// is not projected to be.
	ProjectedAt time.Time
}

// Assess places an accrued total against a limit, and projects forward at the
// current burn rate.
//
// A limit of zero or less means "no limit configured" and yields LevelOK with
// no projection: every FarCast instance must have a limit, so an absent one is
// a bug elsewhere, and inventing a shutdown here would turn that bug into an
// outage.
func Assess(total, limit, ratePerHour float64, now, periodEnd time.Time) Assessment {
	a := Assessment{Total: total, Limit: limit}
	if limit <= 0 {
		return a
	}
	a.Fraction = total / limit

	switch {
	case a.Fraction >= 1:
		a.Level = LevelReached
	case a.Fraction >= 0.9:
		a.Level = LevelWarn90
	case a.Fraction >= 0.75:
		a.Level = LevelWarn75
	case a.Fraction >= 0.5:
		a.Level = LevelWarn50
	}

	remaining := periodEnd.Sub(now)
	if remaining <= 0 || ratePerHour <= 0 {
		a.Projected = total
		return a
	}
	a.Projected = total + ratePerHour*remaining.Hours()
	if a.Projected > limit && a.Level != LevelReached {
		a.ProjectedOver = true
		hoursToLimit := (limit - total) / ratePerHour
		a.ProjectedAt = now.Add(time.Duration(hoursToLimit * float64(time.Hour)))
	}
	return a
}
