package event

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

type capture struct {
	mu sync.Mutex
	ev []Event
}

func (c *capture) Emit(e Event) {
	c.mu.Lock()
	c.ev = append(c.ev, e)
	c.mu.Unlock()
}

func (c *capture) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.ev)
}

func TestSlogSinkEmitDoesNotPanic(t *testing.T) {
	SlogSink{}.Emit(Event{Kind: Deny, Host: "x", Reason: ReasonNotInAllowlist})
	SlogSink{}.Emit(Event{Kind: Allow, Host: "y"})
}

// TestSlogSinkNamesTheApplication asserts on the RENDERED line rather than on
// the Event, which is the layer where attribution was being lost: the proxy
// filled Tenant and App correctly and this sink dropped them, so every denial
// in a live instance read as anonymous. A test that inspects the Event cannot
// see that; only the bytes an operator reads can.
func TestSlogSinkNamesTheApplication(t *testing.T) {
	for _, k := range []Kind{Deny, Allow, Close} {
		var buf bytes.Buffer
		s := SlogSink{Logger: slog.New(slog.NewTextHandler(&buf, nil))}
		s.Emit(Event{
			Kind: k, Tenant: "egress-demo", App: "reacher",
			Host: "example.com", Port: "443", Proto: "connect",
			Reason: ReasonNotInAllowlist,
		})
		line := buf.String()
		for _, want := range []string{"tenant=egress-demo", "app=reacher"} {
			if !strings.Contains(line, want) {
				t.Errorf("%s event: log line lacks %q\n  got: %s", k, want, line)
			}
		}
	}
}

func TestBufferedSinkDropsAndCounts(t *testing.T) {
	cp := &capture{}
	b := NewBufferedSink(cp, 1) // no drainer yet

	b.Emit(Event{Host: "a"}) // enqueued (buffer has room)
	b.Emit(Event{Host: "b"}) // dropped (full)
	b.Emit(Event{Host: "c"}) // dropped (full)

	if got := b.Dropped(); got != 2 {
		t.Fatalf("Dropped()=%d, want 2", got)
	}

	go b.Run(t.Context())

	deadline := time.Now().Add(2 * time.Second)
	for cp.len() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if cp.len() < 1 {
		t.Fatal("buffered event was not drained to the wrapped sink")
	}
}

func TestBufferedSinkDrainsOnCancel(t *testing.T) {
	cp := &capture{}
	b := NewBufferedSink(cp, 8)
	for range 4 {
		b.Emit(Event{Host: "h"})
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { b.Run(ctx); close(done) }()
	cancel()
	<-done
	if cp.len() != 4 {
		t.Fatalf("after drain on cancel: got %d events, want 4", cp.len())
	}
}

// A monitor must never become the only witness.
//
// Wiring a Shrike sidecar used to REPLACE the slog sink, so enabling it would
// have removed FatLine's own log of every decision — and Shrike's wire is
// fail-open and drops events when the sidecar is unreachable, so a monitor
// being down would have erased the boundary's record rather than just its
// alerting.
func TestTeeReachesEverySink(t *testing.T) {
	var a, b []Event
	tee := Tee{
		sinkFunc(func(e Event) { a = append(a, e) }),
		nil, // a nil member must be skipped, not panic
		sinkFunc(func(e Event) { b = append(b, e) }),
	}
	tee.Emit(Event{Kind: Deny, Tenant: "ns", App: "web", Host: "evil.example.com"})

	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("sinks received %d and %d events, want 1 each", len(a), len(b))
	}
	if a[0].App != "web" || b[0].App != "web" {
		t.Errorf("attribution did not reach both sinks: %+v / %+v", a[0], b[0])
	}
}

type sinkFunc func(Event)

func (f sinkFunc) Emit(e Event) { f(e) }
