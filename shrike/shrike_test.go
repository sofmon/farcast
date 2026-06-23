package shrike_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/sofmon/farcast/fatline/event"
	"github.com/sofmon/farcast/manifest/parser"
	"github.com/sofmon/farcast/shrike"
)

type nopAlerter struct{}

func (nopAlerter) Alert(shrike.Alert) {}

func TestMonitorSnapshot(t *testing.T) {
	m := shrike.New(shrike.Config{
		Declared: []parser.External{{Host: "a.com", Reason: "x"}},
		Alerter:  nopAlerter{},
	})
	m.Emit(event.Event{Kind: event.Allow, Host: "a.com", Port: "443"})
	m.Emit(event.Event{Kind: event.Close, Host: "a.com", Port: "443", BytesUp: 10, BytesDown: 20})
	m.Emit(event.Event{Kind: event.Allow, Host: "drift.com"}) // allowed but not declared
	m.Emit(event.Event{Kind: event.Deny, Host: "evil.com", Reason: event.ReasonNotInAllowlist})

	s := m.Snapshot()
	if !slices.Equal(s.Declared, []string{"a.com"}) {
		t.Fatalf("Declared=%v, want [a.com]", s.Declared)
	}
	if s.Events != 4 {
		t.Fatalf("Events=%d, want 4", s.Events)
	}

	byHost := map[string]shrike.HostStat{}
	for _, h := range s.Allowed {
		byHost[h.Host] = h
	}
	if a := byHost["a.com"]; !a.Declared || a.Allows != 1 || a.BytesDown != 20 {
		t.Fatalf("a.com stat=%+v, want declared with allows=1 down=20", a)
	}
	if d := byHost["drift.com"]; d.Declared {
		t.Fatalf("drift.com reached but not declared — must be flagged undeclared: %+v", d)
	}
	if len(s.Violations) != 1 || s.Violations[0].Host != "evil.com" {
		t.Fatalf("Violations=%+v, want one for evil.com", s.Violations)
	}
}

func TestHandlerServesJSON(t *testing.T) {
	m := shrike.New(shrike.Config{
		Declared: []parser.External{{Host: "a.com"}},
		Alerter:  nopAlerter{},
	})
	m.Emit(event.Event{Kind: event.Deny, Host: "evil.com", Reason: event.ReasonNotInAllowlist})

	srv := httptest.NewServer(m.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + shrike.StatusPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	var s shrike.Snapshot
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	if len(s.Violations) != 1 || s.Violations[0].Severity != shrike.SeverityWarning {
		t.Fatalf("decoded snapshot violations=%+v", s.Violations)
	}
}

func TestConcurrentEmit(t *testing.T) {
	m := shrike.New(shrike.Config{
		Declared:    []parser.External{{Host: "a.com"}},
		Alerter:     nopAlerter{},
		AlertWindow: time.Hour,
	})
	const goroutines, iters = 8, 1000
	var wg sync.WaitGroup
	for range goroutines {
		wg.Go(func() {
			for range iters {
				m.Emit(event.Event{Kind: event.Allow, Host: "a.com"})
				m.Emit(event.Event{Kind: event.Deny, Host: "evil.com", Reason: event.ReasonNotInAllowlist})
				_ = m.Snapshot()
			}
		})
	}
	wg.Wait()
	if want := int64(goroutines * iters * 2); m.Snapshot().Events != want {
		t.Fatalf("Events=%d, want %d", m.Snapshot().Events, want)
	}
}
