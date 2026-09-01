package cost

import (
	"fmt"
	"strconv"
	"time"
)

// SnapshotVersion is the on-disk shape of a checkpointed ledger.
//
// It is versioned because this is a *stored* format: a ledger written by one
// build is read by the next one after an upgrade, and a cost meter that
// silently misreads its own history would under-report in the flattering
// direction. An unknown version is refused rather than best-guessed.
const SnapshotVersion = 1

// Snapshot is a Ledger in a form that survives a restart.
//
// The fields are exported and the type is separate from Ledger deliberately:
// what gets persisted is a decision, not an accident of which fields happened
// to be exported. Adding a field to Ledger does not silently change what is
// written.
type Snapshot struct {
	Version     int       `json:"version"`
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`

	// Hourly is expected USD per UTC hour, keyed by the hour's Unix index as
	// a decimal string — JSON object keys must be strings, and a decimal
	// index round-trips exactly where a formatted timestamp would invite a
	// parsing dialect.
	Hourly map[string]float64 `json:"hourly"`

	Apps          map[string]float64 `json:"apps"`
	Confirmations []Confirmation     `json:"confirmations"`
}

// Snapshot captures the ledger for checkpointing.
func (l *Ledger) Snapshot() Snapshot {
	s := Snapshot{
		Version:     SnapshotVersion,
		PeriodStart: l.periodStart,
		PeriodEnd:   l.periodEnd,
		Hourly:      make(map[string]float64, len(l.hourly)),
		Apps:        make(map[string]float64, len(l.apps)),
	}
	for h, v := range l.hourly {
		s.Hourly[strconv.FormatInt(h, 10)] = v
	}
	for k, v := range l.apps {
		s.Apps[k] = v
	}
	s.Confirmations = append([]Confirmation(nil), l.confirmations...)
	return s
}

// Restore rebuilds a Ledger from a checkpoint.
//
// Confirmations are replayed through Confirm rather than assigned, so a
// restored ledger applies the same clamp and the same overlap rules as a live
// one. A checkpoint is cloud-resident state; replaying it through the
// validating path means a tampered or corrupt one cannot install a
// calibration the running code would have refused.
func Restore(s Snapshot) (*Ledger, error) {
	if s.Version != SnapshotVersion {
		return nil, fmt.Errorf("cost: unknown ledger snapshot version %d (this build writes %d)", s.Version, SnapshotVersion)
	}
	l, err := NewLedger(s.PeriodStart, s.PeriodEnd)
	if err != nil {
		return nil, fmt.Errorf("cost: restore: %w", err)
	}
	for k, v := range s.Hourly {
		h, err := strconv.ParseInt(k, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("cost: restore: bad hour key %q: %w", k, err)
		}
		if v < 0 {
			return nil, fmt.Errorf("cost: restore: negative expected spend %.4f in hour %s", v, k)
		}
		l.hourly[h] = v
	}
	for k, v := range s.Apps {
		if v < 0 {
			return nil, fmt.Errorf("cost: restore: negative spend %.4f for %q", v, k)
		}
		l.apps[k] = v
	}
	for _, c := range s.Confirmations {
		if _, err := l.Confirm(c); err != nil {
			return nil, fmt.Errorf("cost: restore: replay confirmation: %w", err)
		}
	}
	return l, nil
}
