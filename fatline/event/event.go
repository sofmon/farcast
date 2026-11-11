// Package event defines FatLine's egress observability seam: the structured
// Event emitted for every egress decision, and the Sink that consumes them.
//
// Shrike (phase 2.2) implements Sink as a sidecar inspector; the default
// SlogSink logs each event. It is a small public leaf package so that both
// FatLine's internal proxy and out-of-tree consumers (Shrike, which lives
// outside fatline/) can depend on it without an import cycle through the
// fatline server package.
package event

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

// Kind is the class of an egress event.
type Kind string

const (
	// Allow is emitted when FatLine permits an outbound connection.
	Allow Kind = "allow"
	// Deny is emitted when FatLine refuses an outbound connection.
	Deny Kind = "deny"
	// Close is emitted when a proxied connection finishes, carrying byte counts.
	Close Kind = "close"
	// Fail is emitted when an ALLOWED connection could not be established.
	//
	// It is not a policy event and it is not a denial: FatLine said yes and
	// the upstream did not answer. Before it existed the dial failure was
	// silent — an application whose declared host was down or unreachable
	// produced an Allow and then nothing at all, so neither the operator's log
	// nor the monitor could tell "reached it" from "never got there".
	Fail Kind = "fail"
)

// Deny reasons. These are stable strings so a consumer (Shrike) can branch on
// them without parsing prose.
const (
	// ReasonNotInAllowlist: the host is not in the app's declared allowlist.
	ReasonNotInAllowlist = "not_in_allowlist"
	// ReasonCleartext: plain http:// egress, denied by default (the cloud and
	// FatLine would see plaintext). Confidentiality is part of deny-by-default.
	ReasonCleartext = "cleartext_not_allowed"
	// ReasonSNIMismatch: the TLS ClientHello server_name did not match the
	// allowlisted CONNECT authority.
	ReasonSNIMismatch = "sni_mismatch"

	// ReasonDialFailed: the connection was allowed and the upstream could not
	// be reached. It rides Fail, never Deny — collapsing the two would report
	// a network outage as a policy violation and send an operator to edit a
	// manifest that was already correct.
	ReasonDialFailed = "dial_failed"

	// ReasonUnknownApp: the caller presented no usable credential, so FatLine
	// cannot tell which application's declarations to enforce.
	//
	// It is deliberately distinct from ReasonNotInAllowlist. "This app may not
	// reach that host" and "I do not know who is asking" have different causes
	// and different fixes, and collapsing them would make a missing credential
	// look like a manifest that forgot a host (ADR 0013 decision 6).
	ReasonUnknownApp = "unknown_app"
)

// Tunnel-stream reasons. A stream event (Proto "stream") is the operator or a
// keeper reaching an in-instance service through the public tunnel, not an
// application's egress, and these are its outcomes. Stable strings, for the
// reason the deny reasons above are.
const (
	// ReasonRelayed: the stream was opened and copied to its end. Rides Allow.
	ReasonRelayed = "relayed"
	// ReasonUnknownRoute: the peer named a route that is not in the table.
	ReasonUnknownRoute = "unknown_route"
	// ReasonRoleRefused: a keeper asked for a route that is the operator's
	// alone.
	ReasonRoleRefused = "role_refused"
	// ReasonBadOrdinal: the replica index named is outside the route's range.
	ReasonBadOrdinal = "bad_ordinal"
)

// ProtoStream marks a tunnel-stream event. It has been set on every stream
// event since the relay existed, so a consumer that separates tunnel streams
// from application egress by it does so for an older FatLine too.
const ProtoStream = "stream"

// Peer roles: which class of tunnel peer a stream event is about. A role names
// a class, never a device, and it is the only peer attribution FatLine's own
// log carries.
const (
	PeerOperator = "operator"
	PeerKeeper   = "keeper"
)

// Event is one structured egress decision. FatLine emits exactly one decision
// Event (Allow or Deny) per egress request, before the caller is answered, so
// Shrike's block-and-alert is satisfiable; a successful connection also emits a
// Close event with byte counts when it finishes.
//
// Tenant and App attribute application egress (filled since phase 4.4); they
// are empty on a tunnel-stream event, which PeerRole and PeerToken attribute
// instead.
//
// The fields carry no JSON tags, and must not gain any: the Shrike wire is
// this struct through encoding/json, so the Go field names ARE the wire keys,
// and a tag would rename a key an older sidecar still reads.
type Event struct {
	Kind   Kind
	Tenant string
	App    string

	// PeerRole is which class of tunnel peer a stream event is about
	// (PeerOperator or PeerKeeper). Empty for application egress.
	PeerRole string
	// PeerToken is the opaque per-leaf token of that peer (identity.LeafToken).
	// It goes to Shrike's in-memory picture, read over the operator's route,
	// and the operator's machine maps it to a device. It is NEVER logged: a
	// stable per-device pseudonym in a provider-visible log would let the
	// provider follow one device for the leaf's life and count the fleet.
	PeerToken string

	Host      string
	Port      string
	Proto     string // "connect" | "http" | "stream"
	SNI       string
	Reason    string
	BytesUp   int64
	BytesDown int64

	// DialMillis is how long establishing the upstream connection took. It
	// rides Close and Fail — on a failure it is how long FatLine waited before
	// giving up, which is what separates a refused connection from a timeout.
	//
	// This is the only latency the boundary can honestly report. FatLine
	// tunnels CONNECT opaquely and never terminates TLS to the upstream, so
	// the requests inside are ciphertext by construction: measuring per-request
	// latency would mean terminating the application's TLS at the proxy, which
	// is the one thing this component exists not to do.
	DialMillis int64
	// DurationMillis is how long the established connection stayed open. It
	// rides Close only.
	DurationMillis int64
}

// Sink receives egress events. Implementations must not block the caller for
// long — the data plane emits on the hot path. Wrap a slow Sink in a
// BufferedSink to decouple it.
type Sink interface{ Emit(Event) }

// SlogSink is the default Sink: it logs each event via slog (denials at WARN,
// everything else at INFO). It never blocks beyond the logger's own write.
type SlogSink struct{ Logger *slog.Logger }

// Emit logs the event.
func (s SlogSink) Emit(e Event) {
	l := s.Logger
	if l == nil {
		l = slog.Default()
	}
	lvl := slog.LevelInfo
	// A failed dial is a warning, not an error: the boundary behaved
	// correctly and something beyond it did not.
	if e.Kind == Deny || e.Kind == Fail {
		lvl = slog.LevelWarn
	}
	attrs := []slog.Attr{
		slog.String("kind", string(e.Kind)),
		// Who, before what. A denial nobody can attribute is telemetry rather
		// than enforcement (ADR 0013), and that is decided here: the proxy
		// fills these in and this is the only place an operator reads them.
		slog.String("tenant", e.Tenant),
		slog.String("app", e.App),
	}
	// A tunnel stream is attributed by its peer's ROLE here and nowhere more
	// finely. PeerToken is deliberately absent: this line lands where the
	// provider can read it, and a token names one leaf for 90 days. The
	// device behind a token is answered from Shrike's picture, on the
	// operator's own machine (ADR 0015).
	if e.PeerRole != "" {
		attrs = append(attrs, slog.String("peer_role", e.PeerRole))
	}
	attrs = append(attrs,
		slog.String("host", e.Host),
		slog.String("port", e.Port),
		slog.String("proto", e.Proto),
		slog.String("sni", e.SNI),
		slog.String("reason", e.Reason),
		slog.Int64("bytes_up", e.BytesUp),
		slog.Int64("bytes_down", e.BytesDown),
		slog.Int64("dial_ms", e.DialMillis),
		slog.Int64("duration_ms", e.DurationMillis),
	)
	l.LogAttrs(context.Background(), lvl, "egress", attrs...)
}

// Tee fans one event out to several sinks, in order. A nil member is skipped.
//
// It exists so streaming decisions to a monitor never REPLACES logging them.
// FatLine is the enforcement point and its own record of what it allowed and
// refused must not depend on anything downstream: Shrike is fail-open by
// design and its wire drops events when the sidecar is unreachable, so wiring
// the sidecar as a substitute would mean a monitor being down quietly erased
// the boundary's audit trail — the one thing that has to survive it.
//
// Each sink is expected to honour the Sink contract and not block; Tee adds no
// buffering of its own, because the caller already wraps the result in a
// BufferedSink.
type Tee []Sink

// Emit passes the event to every sink.
func (t Tee) Emit(e Event) {
	for _, s := range t {
		if s != nil {
			s.Emit(e)
		}
	}
}

// BufferedSink decouples the data-plane hot path from a slow consumer with a
// non-blocking buffered channel. When the buffer is full it drops the event —
// the block/allow decision has already been enforced upstream, so security is
// never sacrificed for observability — and counts the drop. Run drains the
// buffer to the wrapped Sink and periodically reports drops, so a deny flood
// (a misbehaving or hostile app) is never a silent alert blind spot.
type BufferedSink struct {
	out     Sink
	ch      chan Event
	dropped atomic.Int64
	tick    time.Duration
}

// NewBufferedSink wraps out with a buffer of the given size. A size <= 0 uses a
// small default.
func NewBufferedSink(out Sink, buffer int) *BufferedSink {
	if buffer <= 0 {
		buffer = 1024
	}
	return &BufferedSink{
		out:  out,
		ch:   make(chan Event, buffer),
		tick: 30 * time.Second,
	}
}

// Emit is non-blocking: it enqueues the event, or drops and counts it if the
// buffer is full.
func (b *BufferedSink) Emit(e Event) {
	select {
	case b.ch <- e:
	default:
		b.dropped.Add(1)
	}
}

// Dropped returns the number of events dropped because the buffer was full.
func (b *BufferedSink) Dropped() int64 { return b.dropped.Load() }

// Run drains buffered events to the wrapped Sink until ctx is cancelled, then
// flushes what remains. It reports newly dropped events on a periodic tick and
// at shutdown. Run blocks; call it in its own goroutine.
func (b *BufferedSink) Run(ctx context.Context) {
	l := slog.Default()
	t := time.NewTicker(b.tick)
	defer t.Stop()
	var lastReported int64
	report := func() {
		if d := b.dropped.Load(); d > lastReported {
			l.Warn("fatline: egress events dropped (slow event sink)", slog.Int64("dropped", d-lastReported), slog.Int64("dropped_total", d))
			lastReported = d
		}
	}
	for {
		select {
		case <-ctx.Done():
			b.drain()
			report()
			return
		case <-t.C:
			report()
		case e := <-b.ch:
			b.out.Emit(e)
		}
	}
}

// drain flushes any events already buffered (best-effort, non-blocking).
func (b *BufferedSink) drain() {
	for {
		select {
		case e := <-b.ch:
			b.out.Emit(e)
		default:
			return
		}
	}
}
