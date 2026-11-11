package fatline_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sofmon/farcast/fatline"
	"github.com/sofmon/farcast/fatline/event"
	"github.com/sofmon/farcast/fatline/identity"
	fcrypto "github.com/sofmon/farcast/fatline/internal/crypto"
	"github.com/sofmon/farcast/fatline/tunnel"
)

// eventLog is a capture Sink: every event FatLine emitted, in order.
type eventLog struct {
	mu sync.Mutex
	ev []event.Event
}

func (l *eventLog) Emit(e event.Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ev = append(l.ev, e)
}

// waitFor returns the first event match accepts, waiting for the buffered
// sink to deliver it.
func (l *eventLog) waitFor(t *testing.T, what string, match func(event.Event) bool) event.Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		l.mu.Lock()
		for _, e := range l.ev {
			if match(e) {
				l.mu.Unlock()
				return e
			}
		}
		l.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	t.Fatalf("no event for %s; saw %+v", what, l.ev)
	return event.Event{}
}

// lockedBuffer is a log destination written from FatLine's sink goroutine and
// read from the test.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func streamOf(route, reason string) func(event.Event) bool {
	return func(e event.Event) bool {
		return e.Proto == event.ProtoStream && e.Host == route && e.Reason == reason
	}
}

// keeperAndOperator starts a FatLine with a keyholder and a shrike route, the
// keeper limited to the first, and connects one keeper and the operator.
func keeperAndOperator(t *testing.T, cfg fatline.Config, device string) (keeper, operator *tunnel.Conn, keeperCert, operatorCert tls.Certificate) {
	t.Helper()
	ca, _ := fcrypto.NewCA("inst")
	addr := freeAddr(t)
	cfg.TunnelListen = addr
	cfg.Instance = "inst"
	cfg.ServerCert = serverCert(t, ca, "127.0.0.1")
	cfg.ClientCA = ca.CertPool()
	cfg.Endpoint = addr
	cfg.StreamRoutes = []fatline.StreamRoute{
		{Name: "keyholder", Addr: startEchoPlain(t)},
		{Name: "shrike", Addr: startEchoPlain(t)},
	}
	cfg.KeeperRoutes = []string{"keyholder"}
	startServer(t, cfg)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	keeperCert = clientCert(t, ca, identity.KeeperURI("inst", device))
	operatorCert = clientCert(t, ca, identity.OperatorURI("inst"))
	var err error
	if keeper, err = tunnel.Connect(ctx, "https://"+addr, tunnel.ClientIdentity{Cert: keeperCert, CA: ca.CertPool(), ServerName: "127.0.0.1"}); err != nil {
		t.Fatalf("connect as a keeper: %v", err)
	}
	t.Cleanup(func() { _ = keeper.Close() })
	if operator, err = tunnel.Connect(ctx, "https://"+addr, tunnel.ClientIdentity{Cert: operatorCert, CA: ca.CertPool(), ServerName: "127.0.0.1"}); err != nil {
		t.Fatalf("connect as the operator: %v", err)
	}
	t.Cleanup(func() { _ = operator.Close() })
	return keeper, operator, keeperCert, operatorCert
}

// relay opens a route, moves a few bytes and closes it, so the relay
// finishes and its event is emitted.
func relay(t *testing.T, conn *tunnel.Conn, route string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	c, err := conn.DialStream(ctx, route, -1)
	if err != nil {
		t.Fatalf("DialStream(%s): %v", route, err)
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := c.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	_ = c.Close()
}

// Every tunnel-stream decision names who it was about: the role FatLine
// decided on and the token of the leaf it verified. Walk finding 1 — a keeper
// refused the operator's route, and nothing said which device.
func TestTunnelStreamsNameTheirPeer(t *testing.T) {
	events := &eventLog{}
	keeper, operator, keeperCert, operatorCert := keeperAndOperator(t, fatline.Config{Events: events}, "laptop")
	keeperToken := identity.LeafToken(keeperCert.Certificate[0])
	operatorToken := identity.LeafToken(operatorCert.Certificate[0])
	if keeperToken == operatorToken {
		t.Fatal("the two leaves share a token; the test would prove nothing")
	}

	relay(t, operator, "shrike")
	relay(t, keeper, "keyholder")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if c, err := keeper.DialStream(ctx, "shrike", -1); err == nil {
		_ = c.Close()
		t.Fatal("a keeper opened the operator's Shrike route")
	}

	for _, tc := range []struct {
		what, route, reason, role, token string
		kind                             event.Kind
	}{
		{"the operator's relay", "shrike", event.ReasonRelayed, event.PeerOperator, operatorToken, event.Allow},
		{"the keeper's relay", "keyholder", event.ReasonRelayed, event.PeerKeeper, keeperToken, event.Allow},
		{"the keeper's refusal", "shrike", event.ReasonRoleRefused, event.PeerKeeper, keeperToken, event.Deny},
	} {
		e := events.waitFor(t, tc.what, streamOf(tc.route, tc.reason))
		if e.Kind != tc.kind || e.PeerRole != tc.role || e.PeerToken != tc.token {
			t.Errorf("%s: kind=%s role=%q token=%q; want %s %q %q", tc.what, e.Kind, e.PeerRole, e.PeerToken, tc.kind, tc.role, tc.token)
		}
	}
	// A relay's byte counts are carried on its event; Shrike counts them.
	if e := events.waitFor(t, "the keeper's relay", streamOf("keyholder", event.ReasonRelayed)); e.BytesUp == 0 || e.BytesDown == 0 {
		t.Errorf("the relay's bytes were not recorded: up=%d down=%d", e.BytesUp, e.BytesDown)
	}
}

// The route was permitted and the service did not answer: a network fact, not
// a policy one. ReasonDialFailed rides Fail, never Deny.
func TestAStreamDialFailureIsAFailNotADenial(t *testing.T) {
	ca, _ := fcrypto.NewCA("inst")
	events := &eventLog{}
	addr := freeAddr(t)
	startServer(t, fatline.Config{
		TunnelListen: addr,
		Instance:     "inst",
		ServerCert:   serverCert(t, ca, "127.0.0.1"),
		ClientCA:     ca.CertPool(),
		Endpoint:     addr,
		StreamRoutes: []fatline.StreamRoute{{Name: "keyholder", Addr: freeAddr(t)}},
		Events:       events,
	})
	conn := operatorConn(t, ca, addr)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if c, err := conn.DialStream(ctx, "keyholder", -1); err == nil {
		_ = c.Close()
		t.Fatal("a stream to a closed port succeeded")
	}
	e := events.waitFor(t, "the dial failure", streamOf("keyholder", event.ReasonDialFailed))
	if e.Kind != event.Fail {
		t.Errorf("a stream dial failure was emitted as %s, want %s", e.Kind, event.Fail)
	}
	if e.PeerRole != event.PeerOperator {
		t.Errorf("the dial failure names role %q, want the operator", e.PeerRole)
	}
}

// FatLine's own log is where the provider can read it. It names a tunnel
// peer's class and nothing finer: not the device name the keeper's leaf
// carries, and not the token Shrike is given.
func TestNoKeeperNameOrTokenReachesFatLinesLog(t *testing.T) {
	const device = "distinctive-device-name"
	logs := &lockedBuffer{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	keeper, _, keeperCert, _ := keeperAndOperator(t, fatline.Config{Logger: logger}, device)

	relay(t, keeper, "keyholder")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if c, err := keeper.DialStream(ctx, "shrike", -1); err == nil {
		_ = c.Close()
		t.Fatal("a keeper opened the operator's Shrike route")
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s := logs.String(); strings.Contains(s, "reason="+event.ReasonRoleRefused) && strings.Contains(s, "reason="+event.ReasonRelayed) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	out := logs.String()
	if !strings.Contains(out, "reason="+event.ReasonRoleRefused) || !strings.Contains(out, "reason="+event.ReasonRelayed) {
		t.Fatalf("the stream decisions were not logged:\n%s", out)
	}
	if !strings.Contains(out, "peer_role=keeper") {
		t.Errorf("the log does not say a keeper was refused:\n%s", out)
	}
	if strings.Contains(out, device) {
		t.Errorf("a keeper's device name reached FatLine's log:\n%s", out)
	}
	if token := identity.LeafToken(keeperCert.Certificate[0]); strings.Contains(out, token) {
		t.Errorf("a keeper's leaf token reached FatLine's log:\n%s", out)
	}
}

// An unknown route's name is whatever the peer sent, percent-decoded, and an
// admitted leaf could otherwise write text of any length into FatLine's log
// once per request. The event carries it cut to a bound and marked, and the
// log line quotes the control bytes in it rather than passing them through.
func TestAnUnknownRouteNameIsRecordedCutAndQuoted(t *testing.T) {
	const (
		bound  = 64         // maxRecordedRoute
		marker = "...(cut)" // routeCutMarker
	)
	events := &eventLog{}
	logs := &lockedBuffer{}
	sinks := event.Tee{events, event.SlogSink{Logger: slog.New(slog.NewTextHandler(logs, nil))}}
	keeper, _, _, _ := keeperAndOperator(t, fatline.Config{Events: sinks}, "laptop")

	name := "\x1b[8m\r" + strings.Repeat("x", 4096)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if c, err := keeper.DialStream(ctx, name, -1); err == nil {
		_ = c.Close()
		t.Fatal("a route that does not exist was opened")
	}

	e := events.waitFor(t, "the unknown route", func(e event.Event) bool {
		return e.Proto == event.ProtoStream && e.Reason == event.ReasonUnknownRoute
	})
	kept, marked := strings.CutSuffix(e.Host, marker)
	if !marked || len(kept) > bound || !strings.HasPrefix(name, kept) {
		t.Errorf("the event records %d bytes %.100q, want at most the first %d of the name, marked as cut", len(e.Host), e.Host, bound)
	}
	if e.Kind != event.Deny || e.PeerRole != event.PeerKeeper {
		t.Errorf("kind=%s role=%q, want a keeper's denial", e.Kind, e.PeerRole)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(logs.String(), "reason="+event.ReasonUnknownRoute) {
		time.Sleep(10 * time.Millisecond)
	}
	out := logs.String()
	if !strings.Contains(out, "reason="+event.ReasonUnknownRoute) {
		t.Fatalf("the refusal was not logged:\n%s", out)
	}
	if strings.ContainsAny(out, "\x1b\r") {
		t.Errorf("a control byte from the route name reached the log unquoted:\n%q", out)
	}
	if strings.Contains(out, strings.Repeat("x", bound+1)) {
		t.Errorf("the log carries more of the name than the bound (%d bytes of log)", len(out))
	}
}
