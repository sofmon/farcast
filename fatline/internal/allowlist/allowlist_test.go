package allowlist

import (
	"sync"
	"testing"

	"github.com/sofmon/farcast/manifest/parser"
)

func decls(hosts ...string) []parser.External {
	out := make([]parser.External, len(hosts))
	for i, h := range hosts {
		out[i] = parser.External{Host: h, Reason: "reason-" + h}
	}
	return out
}

func TestAllowedExactAndNormalization(t *testing.T) {
	l := New(decls("api.stripe.com"))
	cases := []struct {
		host string
		want bool
	}{
		{"api.stripe.com", true},
		{"API.STRIPE.COM", true},  // DNS is case-insensitive
		{"api.stripe.com.", true}, // trailing FQDN dot stripped
		{"  api.stripe.com  ", true},
		{"evil.com", false},
		{"sub.api.stripe.com", false}, // no subdomain implication
		{"stripe.com", false},         // no parent-domain implication
		{"1.2.3.4", false},            // IP literals are never members
		{"[::1]", false},
		{"", false},
	}
	for _, c := range cases {
		if got := l.Allowed(c.host).Allowed; got != c.want {
			t.Errorf("Allowed(%q)=%v, want %v", c.host, got, c.want)
		}
	}
}

func TestAllowedReasonPassthrough(t *testing.T) {
	l := New([]parser.External{{Host: "api.stripe.com", Reason: "payments"}})
	if d := l.Allowed("api.stripe.com"); !d.Allowed || d.Reason != "payments" {
		t.Errorf("allow decision = %+v, want allowed with reason 'payments'", d)
	}
	if d := l.Allowed("evil.com"); d.Allowed || d.Reason != "not_in_allowlist" {
		t.Errorf("deny decision = %+v, want denied with reason 'not_in_allowlist'", d)
	}
}

func TestEmptyDeniesEverything(t *testing.T) {
	l := New(nil)
	if l.Allowed("anything.com").Allowed {
		t.Fatal("an empty allowlist must deny everything")
	}
}

func TestReloadSwaps(t *testing.T) {
	l := New(decls("a.com"))
	if !l.Allowed("a.com").Allowed {
		t.Fatal("a.com should be allowed before reload")
	}
	l.Reload(decls("b.com"))
	if l.Allowed("a.com").Allowed {
		t.Fatal("a.com should be denied after reload (deny-by-default holds)")
	}
	if !l.Allowed("b.com").Allowed {
		t.Fatal("b.com should be allowed after reload")
	}
}

func TestHostsAndSnapshot(t *testing.T) {
	l := New(decls("a.com", "b.com"))
	hosts := l.Hosts()
	if len(hosts) != 2 || hosts[0] != "a.com" || hosts[1] != "b.com" {
		t.Fatalf("Hosts()=%v", hosts)
	}
	snap := l.Snapshot()
	if len(snap) != 2 || snap[0].Host != "a.com" || snap[0].Reason != "reason-a.com" {
		t.Fatalf("Snapshot()=%+v", snap)
	}
}

func TestTenantSeam(t *testing.T) {
	l := New(decls("a.com"))
	// The default tenant has a.com; an unknown tenant has nothing (deny).
	if !l.Allow("", "a.com").Allowed {
		t.Fatal("default tenant should allow a.com")
	}
	if l.Allow("other-app", "a.com").Allowed {
		t.Fatal("an unknown tenant must deny (per-app isolation seam)")
	}
}

func TestConcurrentReadsAndReload(t *testing.T) {
	l := New(decls("a.com"))
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 2000 {
				_ = l.Allowed("a.com")
				_ = l.Allowed("b.com")
			}
		})
	}
	for i := range 4 {
		wg.Go(func() {
			for range 1000 {
				if i%2 == 0 {
					l.Reload(decls("a.com"))
				} else {
					l.Reload(decls("b.com"))
				}
			}
		})
	}
	wg.Wait()
}
