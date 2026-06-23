package shrike

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sofmon/farcast/fatline/event"
)

// The sidecar wire: FatLine ships egress events to a Shrike sidecar over a local
// Unix socket as newline-delimited JSON (NDJSON). FatLine emits, Shrike serves.
// The transport carries decision metadata only (host/port/proto/sni/reason/byte
// counts) — never application payload — so it adds no network hop to the
// proxied traffic and keeps the cloud blind.

// DialSink is the FatLine-side event.Sink that ships events to a Shrike sidecar.
// It is lossy by design: monitoring must never block or fail-close the data
// plane, so if the sidecar is absent or slow the event is dropped and counted,
// and the sink reconnects lazily (throttled). FatLine wraps it in the existing
// BufferedSink, which already decouples it from the egress hot path.
type DialSink struct {
	socketPath string
	dialEvery  time.Duration

	mu        sync.Mutex
	conn      net.Conn
	enc       *json.Encoder
	lastDial  time.Time
	triedDial bool

	dropped atomic.Int64
}

// NewDialSink returns a DialSink targeting the Shrike sidecar's Unix socket.
func NewDialSink(socketPath string) *DialSink {
	return &DialSink{socketPath: socketPath, dialEvery: time.Second}
}

// Emit ships one event to the sidecar, or drops-and-counts it if the sidecar is
// unreachable. It never blocks beyond a bounded dial/write.
func (d *DialSink) Emit(e event.Event) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conn == nil && !d.redial() {
		d.dropped.Add(1)
		return
	}
	if err := d.enc.Encode(e); err != nil {
		// The receiver went away; drop this event and reconnect on the next.
		_ = d.conn.Close()
		d.conn, d.enc = nil, nil
		d.dropped.Add(1)
	}
}

// redial attempts to (re)connect, throttled to at most once per dialEvery so a
// persistently-absent sidecar does not spin. Caller holds the lock.
func (d *DialSink) redial() bool {
	now := time.Now()
	if d.triedDial && now.Sub(d.lastDial) < d.dialEvery {
		return false
	}
	d.lastDial, d.triedDial = now, true
	conn, err := net.DialTimeout("unix", d.socketPath, 2*time.Second)
	if err != nil {
		return false
	}
	d.conn, d.enc = conn, json.NewEncoder(conn)
	return true
}

// Dropped returns the number of events dropped because the sidecar was
// unreachable. (The egress block/allow decision always happened regardless —
// FatLine enforces it before the event is ever emitted.)
func (d *DialSink) Dropped() int64 { return d.dropped.Load() }

// Close releases the connection to the sidecar.
func (d *DialSink) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conn == nil {
		return nil
	}
	err := d.conn.Close()
	d.conn, d.enc = nil, nil
	return err
}

var _ event.Sink = (*DialSink)(nil)

// Serve listens on the Unix socket at socketPath, accepts FatLine connections,
// and replays decoded events into sink (typically a *Monitor) until ctx is
// cancelled. A malformed line is skipped, not fatal. A stale socket file from a
// prior run is removed before binding and on shutdown.
func Serve(ctx context.Context, socketPath string, sink event.Sink) error {
	_ = os.Remove(socketPath)
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "unix", socketPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = ln.Close()
		_ = os.Remove(socketPath)
	}()
	// Unblock Accept when ctx is cancelled; stop() prevents a goroutine leak if
	// Serve returns for another reason first.
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()

	var wg sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			wg.Wait()
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Go(func() {
			// Close this connection on shutdown so its read loop unblocks and
			// Serve can drain; stopConn prevents a leak if the peer closes first.
			stopConn := context.AfterFunc(ctx, func() { _ = conn.Close() })
			defer stopConn()
			handleConn(conn, sink)
		})
	}
}

// handleConn reads NDJSON events off one connection and replays them into sink.
// Malformed lines are skipped so one bad frame never kills the stream.
func handleConn(conn net.Conn, sink event.Sink) {
	defer func() { _ = conn.Close() }()
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e event.Event
		if err := json.Unmarshal(line, &e); err != nil {
			continue
		}
		sink.Emit(e)
	}
}
