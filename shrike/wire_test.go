package shrike_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sofmon/farcast/fatline/event"
	"github.com/sofmon/farcast/shrike"
)

type capSink struct {
	mu  sync.Mutex
	got []event.Event
}

func (c *capSink) Emit(e event.Event) {
	c.mu.Lock()
	c.got = append(c.got, e)
	c.mu.Unlock()
}

func (c *capSink) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.got)
}

func (c *capSink) hosts() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.got))
	for i, e := range c.got {
		out[i] = e.Host
	}
	return out
}

// tempSocket returns a short-pathed Unix socket. Socket paths are length-limited
// (~104 bytes in macOS sun_path) and the default macOS TMPDIR is long, so bind
// under /tmp to stay well within the limit on both macOS and Linux.
func tempSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "shrike-test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

func waitReady(t *testing.T, socket string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.Dial("unix", socket); err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("shrike socket never became ready")
}

func waitCount(t *testing.T, sink *capSink, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if sink.len() >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d events; got %d", n, sink.len())
}

func TestWireRoundTrip(t *testing.T) {
	socket := tempSocket(t)
	sink := &capSink{}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- shrike.Serve(ctx, socket, sink) }()
	waitReady(t, socket)

	d := shrike.NewDialSink(socket)
	defer func() { _ = d.Close() }()

	const n = 50
	for i := range n {
		d.Emit(event.Event{Kind: event.Allow, Host: fmt.Sprintf("h%d.example", i), Port: "443"})
	}
	waitCount(t, sink, n)
	if sink.len() != n {
		t.Fatalf("got %d events, want %d", sink.len(), n)
	}
	if d.Dropped() != 0 {
		t.Fatalf("dropped %d events with a live sidecar, want 0", d.Dropped())
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Serve returned %v, want nil on cancel", err)
	}
}

func TestDialSinkDropsWhenAbsent(t *testing.T) {
	// Never bound — every dial fails and the sink must drop-and-count, not block.
	d := shrike.NewDialSink(tempSocket(t))
	for range 5 {
		d.Emit(event.Event{Kind: event.Deny, Host: "evil.com", Reason: event.ReasonNotInAllowlist})
	}
	if d.Dropped() == 0 {
		t.Fatal("expected drops when the sidecar is absent")
	}
}

func TestServeSkipsMalformed(t *testing.T) {
	socket := tempSocket(t)
	sink := &capSink{}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- shrike.Serve(ctx, socket, sink) }()
	waitReady(t, socket)

	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := json.Marshal(event.Event{Kind: event.Allow, Host: "ok.example", Port: "443"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("not json at all\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(append(valid, '\n')); err != nil {
		t.Fatal(err)
	}
	waitCount(t, sink, 1)
	_ = conn.Close()

	if got := sink.hosts(); len(got) != 1 || got[0] != "ok.example" {
		t.Fatalf("delivered hosts=%v, want [ok.example] (garbage line skipped)", got)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Serve: %v", err)
	}
}
