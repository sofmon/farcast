package shrike_test

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/sofmon/farcast/fatline/event"
	"github.com/sofmon/farcast/shrike"
)

// serveInto starts a sidecar listener feeding sink and returns its socket.
func serveInto(t *testing.T, sink event.Sink) string {
	t.Helper()
	socket := tempSocket(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- shrike.Serve(ctx, socket, sink) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve returned %v, want nil on cancel", err)
		}
	})
	waitReady(t, socket)
	return socket
}

// The peer crosses the wire intact: FatLine's role and the leaf token reach
// the monitor that keeps the tunnel table.
func TestWireCarriesThePeer(t *testing.T) {
	sink := &capSink{}
	d := shrike.NewDialSink(serveInto(t, sink))
	defer func() { _ = d.Close() }()

	d.Emit(event.Event{Kind: event.Deny, Proto: event.ProtoStream, Host: "shrike", Reason: event.ReasonRoleRefused,
		PeerRole: event.PeerKeeper, PeerToken: "0123456789abcdef"})
	waitCount(t, sink, 1)
	sink.mu.Lock()
	got := sink.got[0]
	sink.mu.Unlock()
	if got.PeerRole != event.PeerKeeper || got.PeerToken != "0123456789abcdef" {
		t.Errorf("the peer did not survive the wire: role=%q token=%q", got.PeerRole, got.PeerToken)
	}
}

// eventV0 is a frozen copy of the Event a sidecar built before peer
// attribution decodes into. It must never be updated: it IS the older sidecar.
type eventV0 struct {
	Kind           string
	Tenant         string
	App            string
	Host           string
	Port           string
	Proto          string
	SNI            string
	Reason         string
	BytesUp        int64
	BytesDown      int64
	DialMillis     int64
	DurationMillis int64
}

// A new FatLine beside an older Shrike sidecar: the line it writes must still
// decode, with every field the older sidecar knows intact. A JSON tag added to
// an existing Event field, or a rename, would blank that field there silently.
func TestAnOlderSidecarStillReadsANewFatLinesLine(t *testing.T) {
	line, err := json.Marshal(event.Event{
		Kind: event.Deny, Tenant: "apps", App: "api", Host: "shrike", Port: "443", Proto: event.ProtoStream,
		SNI: "s", Reason: event.ReasonRoleRefused, BytesUp: 1, BytesDown: 2, DialMillis: 3, DurationMillis: 4,
		PeerRole: event.PeerKeeper, PeerToken: "0123456789abcdef",
	})
	if err != nil {
		t.Fatal(err)
	}
	var old eventV0
	if err := json.Unmarshal(line, &old); err != nil {
		t.Fatalf("an older sidecar cannot decode the new line: %v", err)
	}
	want := eventV0{Kind: "deny", Tenant: "apps", App: "api", Host: "shrike", Port: "443", Proto: "stream",
		SNI: "s", Reason: event.ReasonRoleRefused, BytesUp: 1, BytesDown: 2, DialMillis: 3, DurationMillis: 4}
	if old != want {
		t.Errorf("an older sidecar read %+v, want %+v", old, want)
	}
}

// An older FatLine beside a new Shrike: its stream lines carry no peer, and
// they still land in the tunnel picture rather than in an application's row,
// because they are separated by Proto, which FatLine has always set.
func TestAnOlderFatLinesStreamLineLandsInTheTunnelPicture(t *testing.T) {
	m := shrike.New(shrike.Config{Alerter: nopAlerter{}})
	socket := serveInto(t, m)
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	// Written literally, as the pre-attribution FatLine wrote it.
	if _, err := conn.Write([]byte(`{"Kind":"deny","Tenant":"","App":"","Host":"shrike","Port":"","Proto":"stream","SNI":"","Reason":"role_refused","BytesUp":0,"BytesDown":0,"DialMillis":0,"DurationMillis":0}` + "\n")); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	deadline := time.Now().Add(3 * time.Second)
	for m.Snapshot().Events == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	s := m.Snapshot()
	if len(s.Tunnel) != 1 || s.Tunnel[0].Role != "" || s.Tunnel[0].Route != "shrike" || s.Tunnel[0].Refused != 1 {
		t.Errorf("Tunnel = %+v, want one peerless refusal on shrike", s.Tunnel)
	}
	if len(s.Apps) != 0 || len(s.Allowed) != 0 || len(s.Violations) != 0 {
		t.Errorf("an older FatLine's stream line reached the application tables: apps=%+v allowed=%+v violations=%+v",
			s.Apps, s.Allowed, s.Violations)
	}
}

// The flag the CLI's older-monitor note turns on. Without it, a reader cannot
// tell a monitor whose "(unidentified)" row still absorbs tunnel streams from
// one that saw no tunnel traffic.
func TestSnapshotSaysItSeparatesTheTunnel(t *testing.T) {
	m := shrike.New(shrike.Config{Alerter: nopAlerter{}})
	if !m.Snapshot().TunnelSeparated {
		t.Error("an empty picture does not say it separates the tunnel")
	}
	m.Emit(event.Event{Kind: event.Allow, Proto: event.ProtoStream, Host: "keyholder",
		PeerRole: event.PeerOperator, PeerToken: "op", BytesUp: 5, BytesDown: 7})
	s := m.Snapshot()
	if !s.TunnelSeparated || len(s.Tunnel) != 1 || s.Tunnel[0].Peer != "op" || s.Tunnel[0].BytesDown != 7 {
		t.Errorf("snapshot = separated %v, tunnel %+v", s.TunnelSeparated, s.Tunnel)
	}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back["tunnel_separated"] != true || back["tunnel"] == nil {
		t.Errorf("the served JSON lacks the tunnel fields: %s", raw)
	}
}
