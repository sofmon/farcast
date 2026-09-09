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

// LatencyBounds are the upper edges, in milliseconds, of the bands connection
// times are counted in. There is one more bucket than there are bounds: the
// last holds everything above the last bound.
//
// A ladder rather than a quantile sketch. What an operator asks of a
// connection time is "is this fast, slow, or hanging", and five fixed bands
// answer it in six integers — where a sketch would answer it more precisely in
// a structure nothing here has a reason to carry.
var LatencyBounds = []int64{5, 25, 100, 500, 2000}

// LatencyBands are the human labels for each bucket, including the overflow.
var LatencyBands = []string{"≤5ms", "≤25ms", "≤100ms", "≤500ms", "≤2s", ">2s"}

// Latency is the distribution of upstream connection-establishment times.
//
// Establishment, not request. FatLine tunnels CONNECT opaquely and never
// terminates TLS to the upstream, so what happens inside a connection is
// ciphertext by construction — per-request latency would require breaking the
// one property the boundary exists to keep.
type Latency struct {
	Count       int64   `json:"count"`
	TotalMillis int64   `json:"total_ms"`
	MaxMillis   int64   `json:"max_ms"`
	Buckets     []int64 `json:"buckets,omitempty"`
}

// Observe records one connection time in milliseconds.
func (l *Latency) Observe(ms int64) {
	if ms < 0 {
		ms = 0
	}
	if l.Buckets == nil {
		l.Buckets = make([]int64, len(LatencyBounds)+1)
	}
	l.Count++
	l.TotalMillis += ms
	if ms > l.MaxMillis {
		l.MaxMillis = ms
	}
	for i, bound := range LatencyBounds {
		if ms <= bound {
			l.Buckets[i]++
			return
		}
	}
	l.Buckets[len(LatencyBounds)]++
}

// Add folds another distribution into this one.
func (l *Latency) Add(o Latency) {
	if o.Count == 0 {
		return
	}
	if l.Buckets == nil {
		l.Buckets = make([]int64, len(LatencyBounds)+1)
	}
	l.Count += o.Count
	l.TotalMillis += o.TotalMillis
	if o.MaxMillis > l.MaxMillis {
		l.MaxMillis = o.MaxMillis
	}
	for i := range o.Buckets {
		if i < len(l.Buckets) {
			l.Buckets[i] += o.Buckets[i]
		}
	}
}

// MeanMillis is the arithmetic mean, or zero when nothing was observed.
func (l Latency) MeanMillis() float64 {
	if l.Count == 0 {
		return 0
	}
	return float64(l.TotalMillis) / float64(l.Count)
}

// Band returns the label of the band the q-th connection falls in — the
// bucketed answer to "how slow is the slow end". An empty distribution is "—".
func (l Latency) Band(q float64) string {
	if l.Count == 0 {
		return "—"
	}
	rank := int64(float64(l.Count)*q + 0.5)
	if rank < 1 {
		rank = 1
	}
	var seen int64
	for i, n := range l.Buckets {
		seen += n
		if seen >= rank {
			return LatencyBands[i]
		}
	}
	return LatencyBands[len(LatencyBands)-1]
}

// HostStat is the accumulated traffic to one host FatLine allowed. Declared is
// filled in by the Monitor from the policy (the engine leaves it false): a
// reached host that is not declared is a policy-drift red flag.
type HostStat struct {
	// App and Namespace are which application reached it. Rows are keyed by
	// them as well as by host, because two applications talking to the same
	// host are two facts: merging them reports bytes nobody can attribute,
	// which is the gap ADR 0013 decision 7 closed for denials and left open
	// here.
	//
	// Declared stays trustworthy under that split: a row exists only because
	// FatLine allowed the connection, and FatLine allows against the calling
	// application's own declarations. A false here therefore means Shrike's
	// copy of the policy has drifted from FatLine's, which is what the flag is
	// for.
	App       string `json:"app,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Host      string `json:"host"`
	Port      string `json:"port,omitempty"`
	Declared  bool   `json:"declared"`
	Allows    int64  `json:"allows"`
	// Fails counts allowed connections that could not be established. It is
	// not a violation and never alerts: the policy was satisfied and the
	// network was not.
	Fails     int64     `json:"fails,omitempty"`
	BytesUp   int64     `json:"bytes_up"`
	BytesDown int64     `json:"bytes_down"`
	Latency   Latency   `json:"latency,omitzero"`
	LastSeen  time.Time `json:"last_seen,omitzero"`
}

// AppStat is one application's whole network picture, rolled up across every
// host it reached. It is what a resource report reads: an operator asking
// "what is this application doing on the network" wants one row per
// application, not one per destination.
type AppStat struct {
	App       string    `json:"app,omitempty"`
	Namespace string    `json:"namespace,omitempty"`
	Hosts     int       `json:"hosts"`
	Allows    int64     `json:"allows"`
	Denies    int64     `json:"denies"`
	Fails     int64     `json:"fails"`
	BytesUp   int64     `json:"bytes_up"`
	BytesDown int64     `json:"bytes_down"`
	Latency   Latency   `json:"latency,omitzero"`
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
	case event.Fail:
		i.recordFail(e, now)
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

// statFor returns the stat record for one application's traffic to one host,
// creating it on first sight. Caller holds the lock.
//
// Keyed by application as well as host, for the reason the violation table is:
// two applications reaching the same host are two facts, and a single merged
// row reports bytes nobody can attribute to anyone.
func (i *Inspector) statFor(e event.Event, now time.Time) *HostStat {
	key := e.Tenant + "\x00" + e.App + "\x00" + e.Host + "\x00" + e.Port
	s := i.allowed[key]
	if s == nil {
		s = &HostStat{App: e.App, Namespace: e.Tenant, Host: e.Host}
		i.allowed[key] = s
	}
	if e.Port != "" {
		s.Port = e.Port
	}
	s.LastSeen = now
	return s
}

func (i *Inspector) recordAllow(e event.Event, now time.Time) {
	i.statFor(e, now).Allows++
}

func (i *Inspector) recordClose(e event.Event, now time.Time) {
	s := i.statFor(e, now)
	s.BytesUp += e.BytesUp
	s.BytesDown += e.BytesDown
	if e.DialMillis > 0 {
		s.Latency.Observe(e.DialMillis)
	}
}

// recordFail folds an allowed connection that could not be established.
//
// It raises no alert, deliberately. An unreachable host is not a policy
// violation, and routing it through the violation table would put a network
// outage in front of an operator as something to fix in a manifest.
func (i *Inspector) recordFail(e event.Event, now time.Time) {
	s := i.statFor(e, now)
	s.Fails++
	if e.DialMillis > 0 {
		s.Latency.Observe(e.DialMillis)
	}
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

// Allowed returns the traffic stats for what FatLine allowed, one row per
// application and host, sorted by application then host. The returned slice is
// a copy, and so is each row's latency buckets — a caller must not be handed a
// slice the engine keeps writing to.
func (i *Inspector) Allowed() []HostStat {
	i.mu.Lock()
	defer i.mu.Unlock()
	out := make([]HostStat, 0, len(i.allowed))
	for _, s := range i.allowed {
		row := *s
		row.Latency.Buckets = append([]int64(nil), s.Latency.Buckets...)
		out = append(out, row)
	}
	slices.SortFunc(out, func(a, b HostStat) int {
		if c := strings.Compare(a.App, b.App); c != 0 {
			return c
		}
		if c := strings.Compare(a.Host, b.Host); c != 0 {
			return c
		}
		return strings.Compare(a.Port, b.Port)
	})
	return out
}

// Apps rolls the picture up to one row per application: what it reached, how
// much it moved, how often it could not get there, and how long connecting
// took. Denials are counted here too, from the violation table, so an
// application's network row is complete without a reader joining two tables.
func (i *Inspector) Apps() []AppStat {
	i.mu.Lock()
	defer i.mu.Unlock()

	byApp := map[string]*AppStat{}
	get := func(namespace, app string, now time.Time) *AppStat {
		key := namespace + "\x00" + app
		a := byApp[key]
		if a == nil {
			a = &AppStat{App: app, Namespace: namespace}
			byApp[key] = a
		}
		if now.After(a.LastSeen) {
			a.LastSeen = now
		}
		return a
	}
	for _, s := range i.allowed {
		a := get(s.Namespace, s.App, s.LastSeen)
		a.Hosts++
		a.Allows += s.Allows
		a.Fails += s.Fails
		a.BytesUp += s.BytesUp
		a.BytesDown += s.BytesDown
		a.Latency.Add(s.Latency)
	}
	for _, v := range i.violations {
		get(v.Namespace, v.App, v.LastSeen).Denies += v.Count
	}

	out := make([]AppStat, 0, len(byApp))
	for _, a := range byApp {
		out = append(out, *a)
	}
	slices.SortFunc(out, func(a, b AppStat) int {
		if c := strings.Compare(a.App, b.App); c != 0 {
			return c
		}
		return strings.Compare(a.Namespace, b.Namespace)
	})
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
