package inspector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sofmon/farcast/fatline/event"
)

type capAlerter struct {
	mu     sync.Mutex
	alerts []Alert
}

func (c *capAlerter) Alert(a Alert) {
	c.mu.Lock()
	c.alerts = append(c.alerts, a)
	c.mu.Unlock()
}

func (c *capAlerter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.alerts)
}

func (c *capAlerter) last() Alert {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.alerts[len(c.alerts)-1]
}

type nopAlerter struct{}

func (nopAlerter) Alert(Alert) {}

func TestSeverityByReason(t *testing.T) {
	cases := []struct {
		reason string
		want   Severity
	}{
		{event.ReasonSNIMismatch, Critical},
		{event.ReasonNotInAllowlist, Warning},
		{event.ReasonCleartext, Info},
		{"something_unknown", Warning},
	}
	for _, c := range cases {
		if got := severityForReason(c.reason); got != c.want {
			t.Errorf("severityForReason(%q)=%v, want %v", c.reason, got, c.want)
		}
	}
}

func TestAllowAndCloseStats(t *testing.T) {
	ins := New(nopAlerter{}, time.Hour)
	ins.Record(event.Event{Kind: event.Allow, Host: "api.example", Port: "443", Proto: "connect"})
	ins.Record(event.Event{Kind: event.Close, Host: "api.example", Port: "443", Proto: "connect", BytesUp: 100, BytesDown: 900})

	got := ins.Allowed()
	if len(got) != 1 {
		t.Fatalf("Allowed()=%v, want one host", got)
	}
	s := got[0]
	if s.Host != "api.example" || s.Allows != 1 || s.BytesUp != 100 || s.BytesDown != 900 {
		t.Fatalf("stat=%+v, want allows=1 up=100 down=900", s)
	}
	if ins.Events() != 2 {
		t.Fatalf("Events()=%d, want 2", ins.Events())
	}
}

func TestDenyAlertDedupAndCount(t *testing.T) {
	ca := &capAlerter{}
	ins := New(ca, time.Hour) // long window: repeats coalesce, no re-raise
	deny := event.Event{Kind: event.Deny, Host: "evil.com", Port: "443", Proto: "connect", Reason: event.ReasonNotInAllowlist}

	ins.Record(deny)
	if ca.count() != 1 {
		t.Fatalf("first deny should raise exactly one alert, got %d", ca.count())
	}
	if a := ca.last(); a.Severity != Warning || a.Count != 1 || a.Reason != event.ReasonNotInAllowlist {
		t.Fatalf("alert=%+v, want warning/count=1/not_in_allowlist", a)
	}

	for range 5 {
		ins.Record(deny)
	}
	if ca.count() != 1 {
		t.Fatalf("repeats within the window must not re-alert, got %d alerts", ca.count())
	}
	v := ins.Violations()
	if len(v) != 1 || v[0].Count != 6 {
		t.Fatalf("violations=%+v, want one class with count 6", v)
	}
}

func TestSNIMismatchIsCritical(t *testing.T) {
	ca := &capAlerter{}
	ins := New(ca, time.Hour)
	ins.Record(event.Event{Kind: event.Deny, Host: "ok.example", Port: "443", Proto: "connect", SNI: "evil.example", Reason: event.ReasonSNIMismatch})
	if ca.count() != 1 {
		t.Fatalf("expected one alert, got %d", ca.count())
	}
	if a := ca.last(); a.Severity != Critical || a.SNI != "evil.example" {
		t.Fatalf("alert=%+v, want critical with sni recorded", a)
	}
}

func TestBurstEscalates(t *testing.T) {
	ca := &capAlerter{}
	ins := New(ca, time.Hour) // long window so only escalation can re-raise
	deny := event.Event{Kind: event.Deny, Host: "evil.com", Reason: event.ReasonNotInAllowlist}

	for range burstThreshold {
		ins.Record(deny)
	}
	// One initial alert (count 1, warning) + one escalation alert (count crosses
	// the burst threshold, warning -> critical) = 2.
	if ca.count() != 2 {
		t.Fatalf("expected 2 alerts (initial + burst escalation), got %d", ca.count())
	}
	if a := ca.last(); a.Severity != Critical || a.Count != burstThreshold {
		t.Fatalf("escalation alert=%+v, want critical at count %d", a, burstThreshold)
	}
	if v := ins.Violations(); v[0].Severity != Critical {
		t.Fatalf("violation severity=%v, want critical after burst", v[0].Severity)
	}
}

func TestViolationsSortedSeverestFirst(t *testing.T) {
	ins := New(nopAlerter{}, time.Hour)
	ins.Record(event.Event{Kind: event.Deny, Host: "a.example", Reason: event.ReasonCleartext})      // info
	ins.Record(event.Event{Kind: event.Deny, Host: "b.example", Reason: event.ReasonNotInAllowlist}) // warning
	ins.Record(event.Event{Kind: event.Deny, Host: "c.example", Reason: event.ReasonSNIMismatch})    // critical

	v := ins.Violations()
	if len(v) != 3 {
		t.Fatalf("want 3 violation classes, got %d", len(v))
	}
	if v[0].Severity != Critical || v[1].Severity != Warning || v[2].Severity != Info {
		t.Fatalf("order=%v/%v/%v, want critical, warning, info", v[0].Severity, v[1].Severity, v[2].Severity)
	}
}

func TestConcurrentRecord(t *testing.T) {
	ins := New(nopAlerter{}, time.Hour)
	const goroutines, iters = 8, 1000
	var wg sync.WaitGroup
	for range goroutines {
		wg.Go(func() {
			for range iters {
				ins.Record(event.Event{Kind: event.Allow, Host: "api.example", Port: "443"})
				ins.Record(event.Event{Kind: event.Deny, Host: "evil.com", Reason: event.ReasonNotInAllowlist})
				// The tunnel table is shared state of its own.
				ins.Record(event.Event{Kind: event.Allow, Proto: event.ProtoStream, Host: "keyholder",
					PeerRole: event.PeerKeeper, PeerToken: "t1", BytesUp: 1})
				ins.Record(event.Event{Kind: event.Deny, Proto: event.ProtoStream, Host: "shrike",
					PeerRole: event.PeerKeeper, PeerToken: "t1", Reason: event.ReasonRoleRefused})
				_ = ins.Allowed()
				_ = ins.Violations()
				_ = ins.Tunnel()
				_ = ins.Events()
			}
		})
	}
	wg.Wait()
	if want := int64(goroutines * iters * 4); ins.Events() != want {
		t.Fatalf("Events()=%d, want %d", ins.Events(), want)
	}
}

// Two applications denied the same host are two violations, not one.
//
// They have different remedies — one is reaching somewhere it never declared,
// the other may simply need the host adding to its manifest — so a single
// merged count is a number nobody can act on (ADR 0013 decision 7).
func TestTwoApplicationsDeniedTheSameHostAreTwoViolations(t *testing.T) {
	cap := &capAlerter{}
	i := New(cap, time.Minute)

	for _, app := range []string{"alpha", "beta"} {
		i.Record(event.Event{
			Kind: event.Deny, Tenant: "my-platform", App: app,
			Host: "shared.test", Port: "443", Proto: "connect",
			Reason: event.ReasonNotInAllowlist,
		})
	}

	raised := cap.alerts
	if len(raised) != 2 {
		t.Fatalf("raised %d alerts, want one per application: %+v", len(raised), raised)
	}
	seen := map[string]bool{}
	for _, a := range raised {
		seen[a.App] = true
		if a.Namespace != "my-platform" {
			t.Errorf("alert for %q has namespace %q", a.App, a.Namespace)
		}
		if a.Count != 1 {
			t.Errorf("alert for %q counted %d attempts; the two applications were merged", a.App, a.Count)
		}
		if !strings.Contains(a.Message, a.App) {
			t.Errorf("the message does not name the application: %q", a.Message)
		}
	}
	if !seen["alpha"] || !seen["beta"] {
		t.Errorf("alerts did not name both applications: %v", seen)
	}
}

// The same application repeating itself is still one violation, counted.
func TestOneApplicationRepeatingIsOneViolation(t *testing.T) {
	cap := &capAlerter{}
	i := New(cap, time.Minute)
	for range 3 {
		i.Record(event.Event{
			Kind: event.Deny, Tenant: "my-platform", App: "alpha",
			Host: "shared.test", Reason: event.ReasonNotInAllowlist,
		})
	}
	raised := cap.alerts
	if len(raised) != 1 {
		t.Fatalf("raised %d alerts for one application repeating, want 1", len(raised))
	}
}

// An unidentified caller is its own kind of problem and must not read as an
// application that forgot to declare a host.
func TestAnUnidentifiedCallerSaysSo(t *testing.T) {
	cap := &capAlerter{}
	i := New(cap, time.Minute)
	i.Record(event.Event{
		Kind: event.Deny, Host: "somewhere.test", Reason: event.ReasonUnknownApp,
	})
	raised := cap.alerts
	if len(raised) != 1 {
		t.Fatalf("raised %d alerts", len(raised))
	}
	if !strings.Contains(raised[0].Message, "unidentified caller") {
		t.Errorf("message = %q, want it to say the caller could not be identified", raised[0].Message)
	}
	if raised[0].App != "" {
		t.Errorf("an unidentified caller was attributed to %q", raised[0].App)
	}
}

// The status JSON has named the application since 4.4; the alert stream did
// not, so two applications denied the same host read as one problem in the
// logs an operator actually watches. Assert on the rendered line, because
// asserting on the Alert is what let this through.
func TestSlogAlerterNamesTheApplication(t *testing.T) {
	var buf bytes.Buffer
	a := SlogAlerter{Logger: slog.New(slog.NewTextHandler(&buf, nil))}
	a.Alert(Alert{
		Severity: Warning, App: "reacher", Namespace: "egress-demo",
		Host: "evil.example.com", Port: "443", Proto: "connect",
		Reason: event.ReasonNotInAllowlist, Count: 3,
	})
	line := buf.String()
	for _, want := range []string{"app=reacher", "namespace=egress-demo"} {
		if !strings.Contains(line, want) {
			t.Errorf("alert line lacks %q\n  got: %s", want, line)
		}
	}
}

// The mirror of TestTwoApplicationsDeniedTheSameHostAreTwoViolations, for the
// half that was still merged: allowed traffic was keyed by host alone, so two
// applications talking to the same host reported one row of bytes nobody could
// attribute to either of them.
func TestTwoApplicationsReachingTheSameHostAreTwoRows(t *testing.T) {
	i := New(nopAlerter{}, time.Minute)
	i.Record(event.Event{Kind: event.Allow, Tenant: "apps", App: "api", Host: "example.test", Port: "443"})
	i.Record(event.Event{Kind: event.Close, Tenant: "apps", App: "api", Host: "example.test", Port: "443", BytesUp: 100, BytesDown: 200})
	i.Record(event.Event{Kind: event.Allow, Tenant: "apps", App: "web", Host: "example.test", Port: "443"})
	i.Record(event.Event{Kind: event.Close, Tenant: "apps", App: "web", Host: "example.test", Port: "443", BytesUp: 7, BytesDown: 9})

	rows := i.Allowed()
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want one per application: %+v", len(rows), rows)
	}
	if rows[0].App != "api" || rows[0].BytesUp != 100 {
		t.Errorf("first row is %+v, want api's own 100 bytes up", rows[0])
	}
	if rows[1].App != "web" || rows[1].BytesUp != 7 {
		t.Errorf("second row is %+v, want web's own 7 bytes up", rows[1])
	}
}

// An unreachable host is not a policy violation. Routing it through the
// violation table would put a network outage in front of an operator as
// something to fix in a manifest.
func TestAFailedDialIsCountedAndNeverAlerts(t *testing.T) {
	c := &capAlerter{}
	i := New(c, time.Minute)
	i.Record(event.Event{Kind: event.Allow, Tenant: "apps", App: "api", Host: "down.test", Port: "443"})
	i.Record(event.Event{
		Kind: event.Fail, Tenant: "apps", App: "api", Host: "down.test", Port: "443",
		Reason: event.ReasonDialFailed, DialMillis: 30000,
	})

	if c.count() != 0 {
		t.Errorf("an unreachable host raised %d alerts", c.count())
	}
	if len(i.Violations()) != 0 {
		t.Errorf("an unreachable host became a violation: %+v", i.Violations())
	}
	rows := i.Allowed()
	if len(rows) != 1 || rows[0].Fails != 1 {
		t.Fatalf("rows are %+v, want one with a single failure", rows)
	}
	// The time spent waiting is recorded too: it is what separates a refused
	// connection from one that hung until the dialer gave up.
	if got := rows[0].Latency.MaxMillis; got != 30000 {
		t.Errorf("the wait before failing was recorded as %dms, want 30000", got)
	}
}

func TestLatencyLadder(t *testing.T) {
	var l Latency
	for _, ms := range []int64{1, 3, 20, 20, 90, 400, 1500, 9000} {
		l.Observe(ms)
	}
	if l.Count != 8 || l.MaxMillis != 9000 {
		t.Fatalf("count %d, max %d", l.Count, l.MaxMillis)
	}
	if got := l.MeanMillis(); got != 11034.0/8 {
		t.Errorf("mean is %v, want %v", got, 11034.0/8)
	}
	// Half the connections are at or under 25ms.
	if got := l.Band(0.5); got != "≤25ms" {
		t.Errorf("median band is %q, want ≤25ms", got)
	}
	if got := l.Band(1); got != ">2s" {
		t.Errorf("top band is %q, want >2s", got)
	}
	var empty Latency
	if got := empty.Band(0.9); got != "—" {
		t.Errorf("an empty distribution reported the band %q", got)
	}
}

// A reader gets a copy. Handing out the engine's own bucket slice would let a
// snapshot change under a caller while it was being encoded.
func TestAllowedCopiesTheLatencyBuckets(t *testing.T) {
	i := New(nopAlerter{}, time.Minute)
	i.Record(event.Event{Kind: event.Close, Tenant: "apps", App: "api", Host: "a.test", DialMillis: 7})
	rows := i.Allowed()
	rows[0].Latency.Buckets[0] = 9999
	if again := i.Allowed(); again[0].Latency.Buckets[0] == 9999 {
		t.Error("a caller writing to its copy changed the engine's own counters")
	}
}

// An application's network row must be complete on its own: an operator
// reading it should not have to join it against the violation table to learn
// that half its connections were refused.
func TestAppsRollUpTrafficAndDenialsTogether(t *testing.T) {
	i := New(nopAlerter{}, time.Minute)
	i.Record(event.Event{Kind: event.Allow, Tenant: "apps", App: "api", Host: "a.test"})
	i.Record(event.Event{Kind: event.Close, Tenant: "apps", App: "api", Host: "a.test", BytesUp: 10, BytesDown: 20, DialMillis: 15})
	i.Record(event.Event{Kind: event.Allow, Tenant: "apps", App: "api", Host: "b.test"})
	i.Record(event.Event{Kind: event.Close, Tenant: "apps", App: "api", Host: "b.test", BytesUp: 5, BytesDown: 5, DialMillis: 300})
	i.Record(event.Event{Kind: event.Fail, Tenant: "apps", App: "api", Host: "b.test", Reason: event.ReasonDialFailed, DialMillis: 50})
	i.Record(event.Event{Kind: event.Deny, Tenant: "apps", App: "api", Host: "nope.test", Reason: event.ReasonNotInAllowlist})
	i.Record(event.Event{Kind: event.Deny, Tenant: "apps", App: "api", Host: "nope.test", Reason: event.ReasonNotInAllowlist})
	i.Record(event.Event{Kind: event.Allow, Tenant: "apps", App: "web", Host: "a.test"})

	apps := i.Apps()
	if len(apps) != 2 {
		t.Fatalf("got %d applications: %+v", len(apps), apps)
	}
	api := apps[0]
	if api.App != "api" {
		t.Fatalf("first row is %q", api.App)
	}
	if api.Hosts != 2 || api.Allows != 2 || api.Fails != 1 || api.Denies != 2 {
		t.Errorf("api rolled up as %+v, want 2 hosts / 2 allows / 1 fail / 2 denies", api)
	}
	if api.BytesUp != 15 || api.BytesDown != 25 {
		t.Errorf("api moved %d up / %d down, want 15 / 25", api.BytesUp, api.BytesDown)
	}
	if api.Latency.Count != 3 || api.Latency.MaxMillis != 300 {
		t.Errorf("api latency is %+v, want 3 observations peaking at 300ms", api.Latency)
	}
}

// An unidentified caller has no application to roll up to, and must still
// appear: it is the row an operator most needs to see.
func TestAnUnidentifiedCallerStillGetsARow(t *testing.T) {
	i := New(nopAlerter{}, time.Minute)
	i.Record(event.Event{Kind: event.Deny, Host: "x.test", Reason: event.ReasonUnknownApp})
	apps := i.Apps()
	if len(apps) != 1 || apps[0].Denies != 1 || apps[0].App != "" {
		t.Fatalf("apps are %+v, want one unnamed row with a denial", apps)
	}
}

func stream(kind event.Kind, role, token, route, reason string) event.Event {
	return event.Event{Kind: kind, Proto: event.ProtoStream, PeerRole: role, PeerToken: token, Host: route, Reason: reason}
}

// A tunnel stream is the operator or a keeper reaching an in-instance service.
// It is not an application's egress and has no application, and folded into
// the application tables it became the "(unidentified)" row — where walk
// finding 1 lost which device a refusal was about.
func TestTunnelStreamsAreNotApplicationEgress(t *testing.T) {
	ins := New(nopAlerter{}, time.Minute)
	ins.Record(stream(event.Allow, event.PeerKeeper, "k1", "keyholder", event.ReasonRelayed))
	ins.Record(stream(event.Deny, event.PeerKeeper, "k1", "shrike", event.ReasonRoleRefused))
	ins.Record(stream(event.Fail, event.PeerOperator, "op", "keyholder", event.ReasonDialFailed))
	// An older FatLine's stream line: no peer at all. Separated by Proto, so
	// it lands here too.
	ins.Record(event.Event{Kind: event.Deny, Proto: event.ProtoStream, Host: "shrike", Reason: event.ReasonRoleRefused})

	if a := ins.Allowed(); len(a) != 0 {
		t.Errorf("tunnel streams reached the allowed table: %+v", a)
	}
	if v := ins.Violations(); len(v) != 0 {
		t.Errorf("tunnel streams reached the violation table: %+v", v)
	}
	if a := ins.Apps(); len(a) != 0 {
		t.Errorf("tunnel streams reached the application roll-up: %+v", a)
	}
	if n := len(ins.Tunnel()); n != 4 {
		t.Errorf("the tunnel table has %d rows, want 4: %+v", n, ins.Tunnel())
	}
}

// Two keepers on one route are two devices, and two rows.
func TestTwoKeepersOnOneRouteAreTwoRows(t *testing.T) {
	ins := New(nopAlerter{}, time.Minute)
	ins.Record(stream(event.Allow, event.PeerKeeper, "k1", "keyholder", event.ReasonRelayed))
	ins.Record(stream(event.Allow, event.PeerKeeper, "k2", "keyholder", event.ReasonRelayed))
	ins.Record(stream(event.Allow, event.PeerKeeper, "k2", "keyholder", event.ReasonRelayed))
	// The same token in another role is another row: the role is FatLine's
	// decision and the table must not merge two of them.
	ins.Record(stream(event.Allow, event.PeerOperator, "k2", "keyholder", event.ReasonRelayed))
	rows := ins.Tunnel()
	if len(rows) != 3 {
		t.Fatalf("rows = %+v, want three", rows)
	}
	want := []struct {
		role, peer string
		relayed    int64
	}{{event.PeerKeeper, "k1", 1}, {event.PeerKeeper, "k2", 2}, {event.PeerOperator, "k2", 1}}
	for i, w := range want {
		if rows[i].Role != w.role || rows[i].Peer != w.peer || rows[i].Relayed != w.relayed {
			t.Errorf("row %d = %+v, want %s %s relayed %d", i, rows[i], w.role, w.peer, w.relayed)
		}
	}
}

// A relayed stream's bytes ride its Allow event — a stream has no Close — and
// were dropped until the tunnel table counted them.
func TestARelayedStreamCountsItsBytes(t *testing.T) {
	ins := New(nopAlerter{}, time.Minute)
	e := stream(event.Allow, event.PeerOperator, "op", "keyholder", event.ReasonRelayed)
	e.BytesUp, e.BytesDown = 4096, 1<<20
	ins.Record(e)
	ins.Record(e)
	rows := ins.Tunnel()
	if len(rows) != 1 || rows[0].BytesUp != 8192 || rows[0].BytesDown != 2<<20 || rows[0].Relayed != 2 {
		t.Errorf("rows = %+v, want 2 relays moving 8 KiB up and 2 MiB down", rows)
	}
}

// A keeper asking for the operator's route is raised, with its role and
// without its token, and repeats within the window are coalesced.
func TestARoleRefusalAlertsWithTheRoleAndNoToken(t *testing.T) {
	const token = "d1e2v3i4c5e6t7o8"
	alerts := &capAlerter{}
	ins := New(alerts, time.Hour)
	ins.Record(stream(event.Deny, event.PeerKeeper, token, "shrike", event.ReasonRoleRefused))
	if alerts.count() != 1 {
		t.Fatalf("a role refusal raised %d alerts, want 1", alerts.count())
	}
	a := alerts.last()
	if a.PeerRole != event.PeerKeeper || a.Reason != event.ReasonRoleRefused || a.Severity != Warning {
		t.Errorf("alert = %+v", a)
	}
	if !strings.Contains(a.Message, `"shrike"`) || !strings.Contains(a.Message, "keeper") {
		t.Errorf("the message does not name the route and the role: %q", a.Message)
	}
	if strings.Contains(a.Message, token) {
		t.Errorf("the message carries the token: %q", a.Message)
	}

	ins.Record(stream(event.Deny, event.PeerKeeper, token, "shrike", event.ReasonRoleRefused))
	if alerts.count() != 1 {
		t.Errorf("a repeat within the window raised again: %d alerts", alerts.count())
	}
	if rows := ins.Tunnel(); len(rows) != 1 || rows[0].Refused != 2 || rows[0].Reasons[event.ReasonRoleRefused] != 2 {
		t.Errorf("rows = %+v, want two role refusals counted", rows)
	}

	// The log line names the role and never the token.
	var buf bytes.Buffer
	SlogAlerter{Logger: slog.New(slog.NewTextHandler(&buf, nil))}.Alert(a)
	if !strings.Contains(buf.String(), "peer_role=keeper") {
		t.Errorf("the alert line does not name the role:\n  %s", buf.String())
	}
	if strings.Contains(buf.String(), token) {
		t.Errorf("the alert line carries the token:\n  %s", buf.String())
	}
}

// A permitted stream whose service did not answer is a network fact. It is
// counted, and it is not a refusal.
func TestATunnelDialFailureIsNotARefusal(t *testing.T) {
	alerts := &capAlerter{}
	ins := New(alerts, time.Minute)
	ins.Record(stream(event.Fail, event.PeerOperator, "op", "keyholder", event.ReasonDialFailed))
	if alerts.count() != 0 {
		t.Errorf("a dial failure raised %d alerts", alerts.count())
	}
	rows := ins.Tunnel()
	if len(rows) != 1 || rows[0].Failed != 1 || rows[0].Refused != 0 {
		t.Errorf("rows = %+v, want one failure and no refusal", rows)
	}
}

// The reasons map handed out is a copy: a caller must not be given a map the
// engine keeps writing to.
func TestTunnelCopiesTheReasons(t *testing.T) {
	ins := New(nopAlerter{}, time.Minute)
	ins.Record(stream(event.Deny, event.PeerKeeper, "k1", "shrike", event.ReasonRoleRefused))
	rows := ins.Tunnel()
	rows[0].Reasons[event.ReasonRoleRefused] = 99
	if got := ins.Tunnel()[0].Reasons[event.ReasonRoleRefused]; got != 1 {
		t.Errorf("a caller's write reached the engine: %d", got)
	}
}

// preAttributionDialFailed is the line a FatLine older than attribution wrote
// to Shrike's socket when a stream's service did not answer: the event struct
// as it was then, through encoding/json, with the failure riding Deny.
const preAttributionDialFailed = `{"Kind":"deny","Tenant":"","App":"","Host":"keyholder","Port":"","Proto":"stream","SNI":"","Reason":"dial_failed","BytesUp":0,"BytesDown":0,"DialMillis":0,"DurationMillis":0}`

// A newer Shrike beside an older FatLine reads that line as the failure it
// is. Raised as a refusal, it sent an operator hunting for a misused
// credential when a keyholder replica was restarting.
func TestAnOlderFatLinesStreamDialFailureIsNotARefusal(t *testing.T) {
	var e event.Event
	if err := json.Unmarshal([]byte(preAttributionDialFailed), &e); err != nil {
		t.Fatalf("decode the pre-attribution line: %v", err)
	}
	if e.Kind != event.Deny || e.PeerRole != "" {
		t.Fatalf("the fixture is not the pre-attribution shape: %+v", e)
	}
	alerts := &capAlerter{}
	var buf bytes.Buffer
	ins := New(alerterPair{alerts, SlogAlerter{Logger: slog.New(slog.NewTextHandler(&buf, nil))}}, time.Minute)
	ins.Record(e)

	if alerts.count() != 0 || buf.Len() != 0 {
		t.Errorf("an older FatLine's dial failure raised %d alert(s):\n%s", alerts.count(), buf.String())
	}
	rows := ins.Tunnel()
	if len(rows) != 1 || rows[0].Failed != 1 || rows[0].Refused != 0 || len(rows[0].Reasons) != 0 {
		t.Errorf("rows = %+v, want one failure and no refusal", rows)
	}
}

// alerterPair hands each alert to both: the capture, and a real log line.
type alerterPair struct {
	a, b Alerter
}

func (p alerterPair) Alert(al Alert) {
	p.a.Alert(al)
	p.b.Alert(al)
}

// An older FatLine's stream refusal names no peer. It is still a tunnel
// stream, and its line must not read as an application's egress violation.
func TestAnOlderFatLinesStreamRefusalIsLoggedAsATunnelRefusal(t *testing.T) {
	var buf bytes.Buffer
	ins := New(SlogAlerter{Logger: slog.New(slog.NewTextHandler(&buf, nil))}, time.Minute)
	ins.Record(event.Event{Kind: event.Deny, Proto: event.ProtoStream, Host: "shrike", Reason: event.ReasonRoleRefused})
	out := buf.String()
	if !strings.Contains(out, `msg="shrike: tunnel stream refused"`) {
		t.Errorf("a stream refusal without a peer is not logged as a tunnel refusal:\n%s", out)
	}
	if strings.Contains(out, "egress policy violation") {
		t.Errorf("a stream refusal is logged as an egress violation:\n%s", out)
	}
	if strings.Contains(out, "peer_role") {
		t.Errorf("a refusal with no peer carries an empty peer_role:\n%s", out)
	}

	// The control: application egress keeps its own message.
	buf.Reset()
	ins.Record(event.Event{Kind: event.Deny, Tenant: "apps", App: "api", Proto: "connect", Host: "evil.example", Reason: event.ReasonNotInAllowlist})
	if !strings.Contains(buf.String(), `msg="shrike: egress policy violation"`) {
		t.Errorf("an egress denial lost its message:\n%s", buf.String())
	}
}

// Shrike's alert line is read on provider-owned nodes, so it carries nothing
// per leaf: not the token, and not a count or a line pattern that depends on
// one. Two keeper leaves refused the same route in one window are one line,
// and the count that line and the next carry is the role's. The per-leaf
// counts stay in the tunnel table.
func TestTunnelAlertsCarryNothingPerLeaf(t *testing.T) {
	const tokA, tokB = "aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"
	var buf bytes.Buffer
	ins := New(SlogAlerter{Logger: slog.New(slog.NewTextHandler(&buf, nil))}, time.Hour)
	lines := func() []string { return strings.Split(strings.TrimSpace(buf.String()), "\n") }

	ins.Record(stream(event.Deny, event.PeerKeeper, tokA, "shrike", event.ReasonRoleRefused))
	ins.Record(stream(event.Deny, event.PeerKeeper, tokB, "shrike", event.ReasonRoleRefused))
	if got := lines(); len(got) != 1 || !strings.Contains(got[0], "count=1") {
		t.Fatalf("two leaves refused one route in one window gave %d line(s), want one count=1:\n%s", len(got), buf.String())
	}

	// Ten refusals from each leaf: neither alone reaches the burst, the role
	// does, and the escalation says so with the role's count.
	for range 9 {
		ins.Record(stream(event.Deny, event.PeerKeeper, tokA, "shrike", event.ReasonRoleRefused))
		ins.Record(stream(event.Deny, event.PeerKeeper, tokB, "shrike", event.ReasonRoleRefused))
	}
	got := lines()
	if len(got) != 2 {
		t.Fatalf("the role's burst gave %d line(s), want two:\n%s", len(got), buf.String())
	}
	if !strings.Contains(got[1], fmt.Sprintf("count=%d", burstThreshold)) || !strings.Contains(got[1], "severity="+string(Critical)) {
		t.Errorf("the burst line does not carry the role's count, escalated:\n%s", got[1])
	}
	if out := buf.String(); strings.Contains(out, tokA) || strings.Contains(out, tokB) {
		t.Errorf("a token reached the alert line:\n%s", out)
	}

	rows := ins.Tunnel()
	if len(rows) != 2 || rows[0].Peer != tokA || rows[0].Refused != 10 || rows[1].Peer != tokB || rows[1].Refused != 10 {
		t.Errorf("rows = %+v, want each leaf's ten refusals in its own row", rows)
	}
}

// A route name is the peer's own text. Every unknown one is one row per peer
// and one alert key, so an admitted leaf naming routes cannot grow the
// picture, and none of that text reaches the alert line.
func TestUnknownRoutesFoldIntoOneRow(t *testing.T) {
	alerts := &capAlerter{}
	ins := New(alerts, time.Hour)
	for n := range 1000 {
		ins.Record(stream(event.Deny, event.PeerKeeper, "k1", fmt.Sprintf("\x1b[8mroute-%d", n), event.ReasonUnknownRoute))
	}
	ins.Record(stream(event.Deny, event.PeerKeeper, "k2", "another", event.ReasonUnknownRoute))

	rows := ins.Tunnel()
	if len(rows) != 2 {
		t.Fatalf("1001 unknown routes from two leaves gave %d rows, want two: %+v", len(rows), rows)
	}
	for _, r := range rows {
		if r.Route != UnknownRoute {
			t.Errorf("an unknown route kept the peer's name: %q", r.Route)
		}
	}
	if rows[0].Refused != 1000 || rows[0].Reasons[event.ReasonUnknownRoute] != 1000 {
		t.Errorf("row = %+v, want 1000 unknown_route refusals", rows[0])
	}
	ins.mu.Lock()
	nTunnel, nAlerts := len(ins.tunnel), len(ins.tunnelAlerts)
	ins.mu.Unlock()
	if nTunnel != 2 || nAlerts != 1 {
		t.Errorf("state holds %d tunnel rows and %d alert keys, want 2 and 1", nTunnel, nAlerts)
	}

	// One key: the first sighting and the burst escalation, and nothing per
	// name (per name, every one of the 1001 was a first sighting).
	alerts.mu.Lock()
	raised := slices.Clone(alerts.alerts)
	alerts.mu.Unlock()
	if len(raised) != 2 || raised[0].Count != 1 || raised[1].Count != burstThreshold {
		t.Fatalf("raised %+v, want the first sighting and the burst", raised)
	}
	for _, a := range raised {
		if a.Host != UnknownRoute || strings.Contains(a.Message, "route-") || strings.Contains(a.Message, "\x1b") {
			t.Errorf("the alert carries the peer's text: host=%q message=%q", a.Host, a.Message)
		}
		if !strings.Contains(a.Message, "does not exist") {
			t.Errorf("the message does not say the route does not exist: %q", a.Message)
		}
	}

	// A configured route is still its own row.
	ins.Record(stream(event.Allow, event.PeerKeeper, "k1", "keyholder", event.ReasonRelayed))
	if rows := ins.Tunnel(); len(rows) != 3 || rows[1].Peer != "k1" || rows[1].Route != "keyholder" {
		t.Errorf("rows = %+v, want keyholder beside the folded row", rows)
	}
}
