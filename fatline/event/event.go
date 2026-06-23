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
)

// Event is one structured egress decision. FatLine emits exactly one decision
// Event (Allow or Deny) per egress request, before the caller is answered, so
// Shrike's block-and-alert is satisfiable; a successful connection also emits a
// Close event with byte counts when it finishes.
//
// Tenant and App are the per-app attribution hooks: empty in phase 2.1 (there
// are no running apps yet) and filled by phase 4.4.
type Event struct {
	Kind      Kind
	Tenant    string
	App       string
	Host      string
	Port      string
	Proto     string // "connect" | "http"
	SNI       string
	Reason    string
	BytesUp   int64
	BytesDown int64
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
	if e.Kind == Deny {
		lvl = slog.LevelWarn
	}
	l.LogAttrs(context.Background(), lvl, "egress",
		slog.String("kind", string(e.Kind)),
		slog.String("host", e.Host),
		slog.String("port", e.Port),
		slog.String("proto", e.Proto),
		slog.String("sni", e.SNI),
		slog.String("reason", e.Reason),
		slog.Int64("bytes_up", e.BytesUp),
		slog.Int64("bytes_down", e.BytesDown),
	)
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
