// Package cost keeps an instance's spending against its limit.
//
// It holds the two figures [ADR 0009] decision 4 separates, and the whole
// point of the package is that they are never conflated:
//
//   - expected — metered locally and continuously from Pod requests. Available
//     immediately, needs no credential, and is what protective action fires
//     on.
//   - confirmed — the cloud provider's own number for a window that has
//     closed. Arrives about a day late, never drives an action, and exists to
//     correct expected and calibrate the model behind it.
//
// The asymmetry is deliberate and is a security property, not a convenience.
// `confirmed` reaches the instance from outside; if it drove enforcement, a
// feed that lied, broke or was spoofed could switch the guard off. So it may
// tighten the accounting freely and may only loosen it within a clamp
// (decision 5) — beyond which the window is flagged as a discrepancy for the
// operator and the ledger keeps the more conservative of the two figures.
//
// The Ledger holds no clock. Every entry point takes the time explicitly, so
// the accounting is reproducible and testable rather than dependent on when a
// test happens to run.
//
// [ADR 0009]: ../../docs/adr/0009-technocore-kernel-and-cost-metering.md
package cost

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"time"
)

// The bounds on how far a confirmation may move the local model before it is
// treated as a disagreement rather than a correction.
//
// They are wide on purpose: a rate card that drifted 30% should be calibrated
// away silently, because that is exactly the staleness the confirmed signal
// exists to fix. A factor of two in either direction is not staleness — it is
// a billed quantity the meter does not know about, or a feed that is wrong.
const (
	MinCalibration = 0.5
	MaxCalibration = 2.0
)

var (
	ErrWindowOutsidePeriod = errors.New("cost: confirmation window falls outside the ledger's period")
	ErrWindowEmpty         = errors.New("cost: confirmation window ends at or before it starts")
	ErrWindowOverlaps      = errors.New("cost: confirmation window overlaps one already recorded")
	ErrAmountNegative      = errors.New("cost: confirmed amount is negative")
)

// Confirmation is the provider's figure for one closed window.
type Confirmation struct {
	Start, End time.Time // the window it covers, half-open [Start, End)
	USD        float64
	AsOf       time.Time // when the provider produced it
}

// Discrepancy records a confirmation whose disagreement with the local model
// exceeded the clamp. It is kept rather than discarded: a refused correction
// is the single most interesting thing the cost system can learn, and dropping
// it would leave the operator with a quietly wrong estimate and no signal.
type Discrepancy struct {
	Confirmation Confirmation
	Expected     float64 // what the model said the same window cost
	Ratio        float64 // Confirmation.USD / Expected
}

func (d Discrepancy) String() string {
	return fmt.Sprintf("provider reported $%.2f for %s–%s where the model expected $%.2f (ratio %.2f, outside [%.2f, %.2f])",
		d.Confirmation.USD, d.Confirmation.Start.Format(time.RFC3339), d.Confirmation.End.Format(time.RFC3339),
		d.Expected, d.Ratio, MinCalibration, MaxCalibration)
}

// Accrual is what the ledger currently believes, decomposed so that a caller
// can never accidentally present a modelled number as a billed one.
type Accrual struct {
	// Confirmed is the provider's total for every window it has confirmed.
	Confirmed float64
	// Expected is the calibrated local estimate for the rest of the period —
	// the part no confirmation covers yet.
	Expected float64
	// Total is what enforcement compares against the limit.
	Total float64

	// HasConfirmation distinguishes "the provider has confirmed nothing yet"
	// from "the provider confirmed zero". Reading a missing feed as a period
	// that cost nothing is the failure this field exists to prevent.
	HasConfirmation  bool
	ConfirmedThrough time.Time

	// Calibration is the factor applied to the raw model, 1 when nothing has
	// been confirmed. Surfaced so a report can say how far the model has been
	// corrected rather than silently showing corrected numbers.
	Calibration float64

	// Discrepancies are confirmations the clamp refused.
	Discrepancies []Discrepancy
}

// Ledger accrues one instance's spending for one billing period.
type Ledger struct {
	periodStart, periodEnd time.Time

	// hourly is expected USD bucketed by UTC hour. Buckets exist so a
	// confirmation covering part of the period can be compared against what
	// the model said about that same part; a running total could not be.
	hourly map[int64]float64

	// apps is expected USD per attribution key for the period to date.
	// Attribution comes from here and only from here: a provider's figure is
	// instance-level, so confirmation can correct the total without ever
	// being able to say which application caused it.
	apps map[string]float64

	confirmations []Confirmation
	discrepancies []Discrepancy
}

// NewLedger starts a ledger for the half-open period [start, end).
func NewLedger(start, end time.Time) (*Ledger, error) {
	if !end.After(start) {
		return nil, fmt.Errorf("cost: period ends at or before it starts (%s → %s)", start, end)
	}
	return &Ledger{
		periodStart: start.UTC(),
		periodEnd:   end.UTC(),
		hourly:      map[int64]float64{},
		apps:        map[string]float64{},
	}, nil
}

// Accrue records that app ran for d at usdPerHour, ending at now.
//
// The whole interval is attributed to the bucket containing now rather than
// split across bucket boundaries. At a reconcile interval measured in seconds
// against buckets measured in hours the error is bounded by one interval per
// hour boundary, and it never accumulates — the period total is exact
// regardless of how the interval fell.
func (l *Ledger) Accrue(now time.Time, app string, usdPerHour float64, d time.Duration) {
	if d <= 0 || usdPerHour <= 0 {
		return
	}
	amount := usdPerHour * d.Hours()
	l.hourly[hourKey(now)] += amount
	l.apps[app] += amount
}

// Confirm records the provider's figure for a closed window.
//
// It returns the discrepancy if the clamp refused the correction, so a caller
// can surface it immediately; a refused confirmation is still recorded, and
// still counts toward the accrual in whichever direction is more conservative.
func (l *Ledger) Confirm(c Confirmation) (*Discrepancy, error) {
	switch {
	case c.USD < 0:
		return nil, ErrAmountNegative
	case !c.End.After(c.Start):
		return nil, ErrWindowEmpty
	case c.Start.Before(l.periodStart) || c.End.After(l.periodEnd):
		return nil, ErrWindowOutsidePeriod
	}
	for _, existing := range l.confirmations {
		if c.Start.Before(existing.End) && existing.Start.Before(c.End) {
			return nil, ErrWindowOverlaps
		}
	}

	expected := l.expectedIn(c.Start, c.End)
	l.confirmations = append(l.confirmations, c)
	sort.Slice(l.confirmations, func(i, j int) bool { return l.confirmations[i].Start.Before(l.confirmations[j].Start) })

	// A window the model says cost nothing carries no ratio — there is nothing
	// to divide by and nothing to calibrate from. It is recorded, and its
	// amount still counts.
	if expected <= 0 {
		return nil, nil
	}
	ratio := c.USD / expected
	if ratio < MinCalibration || ratio > MaxCalibration {
		d := Discrepancy{Confirmation: c, Expected: expected, Ratio: ratio}
		l.discrepancies = append(l.discrepancies, d)
		return &d, nil
	}
	return nil, nil
}

// Accrued reports the period to date.
func (l *Ledger) Accrued() Accrual {
	a := Accrual{Calibration: 1}

	var confirmedTotal, expectedInConfirmed float64
	var calibratedFrom, calibratedTo float64
	for _, c := range l.confirmations {
		expected := l.expectedIn(c.Start, c.End)
		amount := c.USD

		// Outside the clamp the provider and the model disagree about kind,
		// not degree. Taking the larger of the two means a surprising bill
		// tightens the guard immediately, while a feed reporting far too
		// little cannot loosen it.
		if expected > 0 {
			if ratio := c.USD / expected; ratio < MinCalibration || ratio > MaxCalibration {
				amount = math.Max(c.USD, expected)
			} else {
				calibratedFrom += expected
				calibratedTo += c.USD
			}
		}

		confirmedTotal += amount
		expectedInConfirmed += expected
		if c.End.After(a.ConfirmedThrough) {
			a.ConfirmedThrough = c.End
		}
	}

	if calibratedFrom > 0 {
		a.Calibration = calibratedTo / calibratedFrom
	}

	rawExpected := l.expectedIn(l.periodStart, l.periodEnd) - expectedInConfirmed
	if rawExpected < 0 {
		rawExpected = 0
	}

	a.HasConfirmation = len(l.confirmations) > 0
	a.Confirmed = confirmedTotal
	a.Expected = rawExpected * a.Calibration
	a.Total = a.Confirmed + a.Expected
	a.Discrepancies = append([]Discrepancy(nil), l.discrepancies...)
	return a
}

// ByApp is the per-application breakdown, always from the local model:
// a provider's figure is instance-level and can never be attributed.
func (l *Ledger) ByApp() map[string]float64 {
	out := make(map[string]float64, len(l.apps))
	for k, v := range l.apps {
		out[k] = v
	}
	return out
}

// expectedIn sums the model's buckets over the half-open window [start, end).
func (l *Ledger) expectedIn(start, end time.Time) float64 {
	var sum float64
	for h, v := range l.hourly {
		t := time.Unix(h*3600, 0).UTC()
		if !t.Before(start) && t.Before(end) {
			sum += v
		}
	}
	return sum
}

func hourKey(t time.Time) int64 { return t.UTC().Unix() / 3600 }
