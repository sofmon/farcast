package policy

import (
	"slices"
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

func TestDeclaredExactAndNormalization(t *testing.T) {
	p := New(decls("api.stripe.com"))
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
		{"", false},
	}
	for _, c := range cases {
		if _, ok := p.Declared(c.host); ok != c.want {
			t.Errorf("Declared(%q)=%v, want %v", c.host, ok, c.want)
		}
	}
}

func TestDeclaredReasonPassthrough(t *testing.T) {
	p := New([]parser.External{{Host: "api.stripe.com", Reason: "payments"}})
	if reason, ok := p.Declared("API.STRIPE.COM"); !ok || reason != "payments" {
		t.Errorf("Declared = (%q,%v), want (payments,true)", reason, ok)
	}
}

func TestIPLiteralsAndEmptySkipped(t *testing.T) {
	p := New([]parser.External{
		{Host: "1.2.3.4", Reason: "ip"},
		{Host: "[::1]", Reason: "ipv6"},
		{Host: "", Reason: "empty"},
		{Host: "ok.example", Reason: "real"},
	})
	if got := p.Hosts(); !slices.Equal(got, []string{"ok.example"}) {
		t.Fatalf("Hosts()=%v, want [ok.example] (IPs and empty skipped, mirroring the allowlist)", got)
	}
}

func TestHostsOrderAndDedup(t *testing.T) {
	p := New(decls("b.com", "a.com", "b.com")) // duplicate b.com keeps first position
	if got := p.Hosts(); !slices.Equal(got, []string{"b.com", "a.com"}) {
		t.Fatalf("Hosts()=%v, want [b.com a.com] in declaration order, de-duplicated", got)
	}
}

func TestZeroPolicyDeniesEverything(t *testing.T) {
	var p Policy // zero value
	if _, ok := p.Declared("anything.com"); ok {
		t.Fatal("the zero Policy must declare nothing")
	}
	if got := p.Hosts(); len(got) != 0 {
		t.Fatalf("Hosts()=%v, want empty", got)
	}
}
