package inspector

import (
	"bytes"
	"log/slog"
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
				_ = ins.Allowed()
				_ = ins.Violations()
				_ = ins.Events()
			}
		})
	}
	wg.Wait()
	if want := int64(goroutines * iters * 2); ins.Events() != want {
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
