// Package shrike is FarCast's security monitor: the policeman to FatLine's wall
// (AGENTS.md, "Module Relationships"). It consumes the egress-decision stream
// FatLine already emits — the fatline/event seam — compares each decision
// against the declared manifest policy, and raises severity-ranked,
// de-duplicated alerts on violations. It never sits in the data path and never
// blocks egress: FatLine enforces deny-by-default inline and fail-closed; Shrike
// watches and intervenes, fail-open.
//
// The same Monitor runs two ways. In-process: pass a *Monitor straight to
// FatLine as its event.Sink. Sidecar: run it in its own container fed over a
// local Unix socket (NewDialSink on the FatLine side, Serve on the Shrike side).
// The two-container Pod that co-schedules them is templated by Planck (4.2);
// this is the phase-2.2 artifact.
package shrike

import (
	"time"

	"github.com/sofmon/farcast/fatline/event"
	"github.com/sofmon/farcast/manifest/parser"
	"github.com/sofmon/farcast/shrike/internal/inspector"
	"github.com/sofmon/farcast/shrike/internal/policy"
)

// Public API re-exported from internal/inspector: the engine stays internal
// while the types callers touch live in package shrike.
type (
	// Severity ranks a violation: info < warning < critical.
	Severity = inspector.Severity
	// Alert is a raised violation — severity-ranked, de-duplicated, counted.
	Alert = inspector.Alert
	// Alerter receives raised alerts. Nil defaults to slog.
	Alerter = inspector.Alerter
	// HostStat is accumulated traffic to one allowed host.
	HostStat = inspector.HostStat
	// Violation is a denied egress class with its running count and severity.
	Violation = inspector.Violation
	// SlogAlerter is the default Alerter: it logs alerts via slog.
	SlogAlerter = inspector.SlogAlerter
)

// Severity levels.
const (
	SeverityInfo     = inspector.Info
	SeverityWarning  = inspector.Warning
	SeverityCritical = inspector.Critical
)

// Config configures a Monitor.
type Config struct {
	// Declared is the egress contract: the manifest's external declarations.
	// Anything an application reaches that is not declared here is, by
	// definition, a violation. (Public-typed so a composition root outside the
	// shrike package can build a Monitor without reaching into internal/.)
	Declared []parser.External

	// Alerter receives raised alerts. Nil logs via slog (denials escalate).
	Alerter Alerter

	// AlertWindow rate-limits repeated alerts of the same violation class: the
	// first is raised immediately, repeats are coalesced into the running count
	// and re-raised at most once per window (and on any severity increase).
	// Zero uses one minute.
	AlertWindow time.Duration
}

// Monitor is Shrike's policy engine: an event.Sink that inspects FatLine's
// egress decisions and alerts on violations. Safe for concurrent Emit.
type Monitor struct {
	policy    policy.Policy
	inspector *inspector.Inspector
	since     time.Time
}

// New constructs a Monitor from the declared policy.
func New(cfg Config) *Monitor {
	return &Monitor{
		policy:    policy.New(cfg.Declared),
		inspector: inspector.New(cfg.Alerter, cfg.AlertWindow),
		since:     time.Now(),
	}
}

// Emit implements event.Sink: it folds one FatLine egress decision into the
// security picture and raises an alert if it is a denial that warrants one.
func (m *Monitor) Emit(e event.Event) { m.inspector.Record(e) }

var _ event.Sink = (*Monitor)(nil)

// Snapshot is the live security picture, served as JSON at StatusPath.
type Snapshot struct {
	Since      time.Time   `json:"since"`
	Events     int64       `json:"events"`
	Declared   []string    `json:"declared"`   // the contract: declared hosts
	Allowed    []HostStat  `json:"allowed"`    // hosts FatLine actually allowed
	Violations []Violation `json:"violations"` // denied classes, most severe first
}

// Snapshot returns the current security picture. Each allowed host is annotated
// with whether it is in the declared policy: a reached-but-undeclared host means
// FatLine and Shrike disagree on policy — a drift worth surfacing.
func (m *Monitor) Snapshot() Snapshot {
	allowed := m.inspector.Allowed()
	for i := range allowed {
		_, allowed[i].Declared = m.policy.Declared(allowed[i].Host)
	}
	return Snapshot{
		Since:      m.since,
		Events:     m.inspector.Events(),
		Declared:   m.policy.Hosts(),
		Allowed:    allowed,
		Violations: m.inspector.Violations(),
	}
}
