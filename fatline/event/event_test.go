package event

import (
	"context"
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
