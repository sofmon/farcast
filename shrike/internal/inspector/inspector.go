// Package inspector is Shrike's correlation engine: it folds FatLine's
// egress-decision events into a live security picture — per-host traffic stats
// and a violation table — and raises severity-ranked, de-duplicated,
// rate-limited alerts on denials.
//
// It is the "policeman" half of FarCast's deny-by-default boundary: it never
// blocks (FatLine enforces inline, fail-closed) and it is fail-open — a crash
// here must never affect egress. The violation table is the one shared mutable
// state, so it is mutex-guarded and exercised under -race.
package inspector

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sofmon/farcast/fatline/event"
)

// Severity ranks a violation. info < warning < critical.
type Severity string

const (
	Info     Severity = "info"
	Warning  Severity = "warning"
	Critical Severity = "critical"
)

func (s Severity) rank() int {
	switch s {
	case Critical:
		return 3
	case Warning:
		return 2
	case Info:
		return 1
	default:
		return 0
	}
}

// escalate bumps a severity up one level, capped at critical.
func escalate(s Severity) Severity {
	switch s {
	case Info:
		return Warning
	default:
		return Critical
	}
}

// severityForReason maps a FatLine deny reason to its base severity: an SNI
// mismatch is the signature of an active attack (domain-fronting / MITM), a
// cleartext attempt is a policy nudge, and an undeclared host (the default) is a
// warning that escalates on repetition.
func severityForReason(reason string) Severity {
	switch reason {
	case event.ReasonSNIMismatch:
		return Critical
	case event.ReasonCleartext:
		return Info
	default: // ReasonNotInAllowlist and any unknown reason
		return Warning
	}
}

// burstThreshold is the per-class attempt count past which a violation's
// effective severity is escalated one level: one stray deny is noise, a burst
// is an incident.
const burstThreshold = 20

// Alert is a raised violation — more than a log line: severity-ranked,
// de-duplicated by class (reason+host), counted, and time-bounded.
type Alert struct {
	Severity Severity `json:"severity"`
	// App and Namespace are which application did this. Empty only
	// when FatLine could not identify the caller at all, which is its
	// own reason (ADR 0013 decision 6).
	App       string    `json:"app,omitempty"`
	Namespace string    `json:"namespace,omitempty"`
	Host      string    `json:"host"`
	Port      string    `json:"port,omitempty"`
	Proto     string    `json:"proto,omitempty"`
	SNI       string    `json:"sni,omitempty"`
	Reason    string    `json:"reason"`
	Count     int64     `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Message   string    `json:"message"`
}

// Alerter receives raised alerts. The inspector calls Alert off its lock, but
// still on the event-processing path, so implementations must not block long.
type Alerter interface{ Alert(Alert) }

// SlogAlerter is the default Alerter: it logs alerts via slog, mapping severity
// to level (critical->ERROR, warning->WARN, info->INFO).
type SlogAlerter struct{ Logger *slog.Logger }

// Alert logs the alert.
func (a SlogAlerter) Alert(al Alert) {
	l := a.Logger
	if l == nil {
		l = slog.Default()
	}
	lvl := slog.LevelInfo
	switch al.Severity {
	case Critical:
		lvl = slog.LevelError
	case Warning:
		lvl = slog.LevelWarn
	}
	l.LogAttrs(context.Background(), lvl, "shrike: egress policy violation",
		slog.String("severity", string(al.Severity)),
		// Who, before what. The status JSON has carried these since 4.4 while
		// this line did not, so an operator watching the alert stream saw two
		// applications denied the same host as one indistinguishable problem.
		slog.String("namespace", al.Namespace),
		slog.String("app", al.App),
		slog.String("host", al.Host),
		slog.String("port", al.Port),
		slog.String("proto", al.Proto),
		slog.String("sni", al.SNI),
		slog.String("reason", al.Reason),
		slog.Int64("count", al.Count),
	)
}

var _ Alerter = SlogAlerter{}

// HostStat is the accumulated traffic to one host FatLine allowed. Declared is
// filled in by the Monitor from the policy (the engine leaves it false): a
// reached host that is not declared is a policy-drift red flag.
type HostStat struct {
	Host      string    `json:"host"`
	Port      string    `json:"port,omitempty"`
	Declared  bool      `json:"declared"`
	Allows    int64     `json:"allows"`
	BytesUp   int64     `json:"bytes_up"`
	BytesDown int64     `json:"bytes_down"`
	LastSeen  time.Time `json:"last_seen,omitzero"`
}

// Violation is a denied egress class (reason+host) with its running count,
// effective severity, and timing.
type Violation struct {
	Severity Severity `json:"severity"`
	// App and Namespace are which application did this. Empty only
	// when FatLine could not identify the caller at all, which is its
	// own reason (ADR 0013 decision 6).
	App       string    `json:"app,omitempty"`
	Namespace string    `json:"namespace,omitempty"`
	Host      string    `json:"host"`
	Port      string    `json:"port,omitempty"`
	Proto     string    `json:"proto,omitempty"`
	SNI       string    `json:"sni,omitempty"`
	Reason    string    `json:"reason"`
	Count     int64     `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Inspector accumulates egress statistics and a violation table from the event
// stream, raising alerts on denials. Safe for concurrent Record.
type Inspector struct {
	alerter Alerter
	window  time.Duration

	mu         sync.Mutex
	events     int64
	allowed    map[string]*HostStat
	violations map[string]*vrec
}

// vrec is the internal violation record: the public Violation plus the last
// time an alert was raised for it (for rate-limiting).
type vrec struct {
	Violation
	lastAlertAt time.Time
}

// New builds an Inspector. A nil alerter logs via slog; a window <= 0 uses 1m.
func New(alerter Alerter, window time.Duration) *Inspector {
	if alerter == nil {
		alerter = SlogAlerter{}
	}
	if window <= 0 {
		window = time.Minute
	}
	return &Inspector{
		alerter:    alerter,
		window:     window,
		allowed:    make(map[string]*HostStat),
		violations: make(map[string]*vrec),
	}
}

// Record folds one event into the running picture and raises an alert if it is
// a denial that warrants one. It is the event.Sink hot-path body.
func (i *Inspector) Record(e event.Event) {
	now := time.Now()
	i.mu.Lock()
	i.events++
	var alert *Alert
	switch e.Kind {
	case event.Allow:
		i.recordAllow(e, now)
	case event.Close:
		i.recordClose(e, now)
	case event.Deny:
		alert = i.recordDeny(e, now)
	}
	i.mu.Unlock()
	// Raise outside the lock so a slow Alerter cannot stall event processing or
	// deadlock against a Snapshot read.
	if alert != nil {
		i.alerter.Alert(*alert)
	}
}

// statFor returns the host's stat record, creating it on first sight. Caller
// holds the lock.
func (i *Inspector) statFor(host, port string, now time.Time) *HostStat {
	s := i.allowed[host]
	if s == nil {
		s = &HostStat{Host: host}
		i.allowed[host] = s
	}
	if port != "" {
		s.Port = port
	}
	s.LastSeen = now
	return s
}

func (i *Inspector) recordAllow(e event.Event, now time.Time) {
	i.statFor(e.Host, e.Port, now).Allows++
}

func (i *Inspector) recordClose(e event.Event, now time.Time) {
	s := i.statFor(e.Host, e.Port, now)
	s.BytesUp += e.BytesUp
	s.BytesDown += e.BytesDown
}

func (i *Inspector) recordDeny(e event.Event, now time.Time) *Alert {
	// Keyed by application as well as by reason and host. Two applications
	// denied the same host are two different violations with two different
	// remedies — one is reaching somewhere it never declared, the other may
	// simply need the host adding to its manifest — and merging them would
	// report a count nobody can act on (ADR 0013 decision 7).
	key := e.Tenant + "\x00" + e.App + "\x00" + e.Reason + "\x00" + e.Host
	v := i.violations[key]
	if v == nil {
		v = &vrec{Violation: Violation{
			App:       e.App,
			Namespace: e.Tenant,
			Host:      e.Host,
			Port:      e.Port,
			Proto:     e.Proto,
			SNI:       e.SNI,
			Reason:    e.Reason,
			FirstSeen: now,
		}}
		i.violations[key] = v
	}
	v.Count++
	v.LastSeen = now
	if e.SNI != "" {
		v.SNI = e.SNI
	}
	if e.Port != "" {
		v.Port = e.Port
	}

	prev := v.Severity
	base := severityForReason(e.Reason)
	v.Severity = base
	if v.Count >= burstThreshold {
		v.Severity = escalate(base)
	}

	// Raise on first sighting, on any severity increase (e.g. a burst crossing
	// the threshold mid-window), or once per window for an ongoing class.
	if v.Count != 1 && v.Severity.rank() <= prev.rank() && now.Sub(v.lastAlertAt) < i.window {
		return nil
	}
	v.lastAlertAt = now
	a := Alert{
		Severity:  v.Severity,
		App:       v.App,
		Namespace: v.Namespace,
		Host:      v.Host,
		Port:      v.Port,
		Proto:     v.Proto,
		SNI:       v.SNI,
		Reason:    v.Reason,
		Count:     v.Count,
		FirstSeen: v.FirstSeen,
		LastSeen:  v.LastSeen,
		Message:   message(v.Reason, v.Host, v.App, v.Count),
	}
	return &a
}

// message renders the operator-facing alert text for a violation class.
func message(reason, host, app string, count int64) string {
	// Named where it is known. An alert that says "application" when it could
	// say which one leaves an operator to guess, and with per-application
	// policy the guess is the whole question.
	who := "application"
	if app != "" {
		who = fmt.Sprintf("application %q", app)
	}
	switch reason {
	case event.ReasonSNIMismatch:
		return fmt.Sprintf("%s: TLS server_name did not match the allowed CONNECT authority %q (possible domain-fronting or MITM); %d attempt(s)", who, host, count)
	case event.ReasonCleartext:
		return fmt.Sprintf("%s attempted cleartext http:// to %q, denied by default; %d attempt(s)", who, host, count)
	case event.ReasonUnknownApp:
		return fmt.Sprintf("an unidentified caller attempted %q; it presented no credential FatLine recognises, so no declarations could be enforced for it; %d attempt(s)", host, count)
	default:
		return fmt.Sprintf("%s reached undeclared host %q, denied by default; %d attempt(s)", who, host, count)
	}
}

// Events returns the number of events processed.
func (i *Inspector) Events() int64 {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.events
}

// Allowed returns the per-host traffic stats for hosts FatLine allowed, sorted
// by host. The returned slice is a copy.
func (i *Inspector) Allowed() []HostStat {
	i.mu.Lock()
	defer i.mu.Unlock()
	out := make([]HostStat, 0, len(i.allowed))
	for _, s := range i.allowed {
		out = append(out, *s)
	}
	slices.SortFunc(out, func(a, b HostStat) int { return strings.Compare(a.Host, b.Host) })
	return out
}

// Violations returns the violation table, most severe first (then by host and
// reason). The returned slice is a copy.
func (i *Inspector) Violations() []Violation {
	i.mu.Lock()
	defer i.mu.Unlock()
	out := make([]Violation, 0, len(i.violations))
	for _, v := range i.violations {
		out = append(out, v.Violation)
	}
	slices.SortFunc(out, func(a, b Violation) int {
		if r := b.Severity.rank() - a.Severity.rank(); r != 0 {
			return r
		}
		if c := strings.Compare(a.Host, b.Host); c != 0 {
			return c
		}
		return strings.Compare(a.Reason, b.Reason)
	})
	return out
}
