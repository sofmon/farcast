// Package policy is Shrike's read-only view of the declared egress contract:
// the external hosts an application's ./farcast manifest permits it to reach.
//
// It mirrors FatLine's allowlist normalization (lower-case, strip the trailing
// FQDN dot, never treat an IP literal as a member) so Shrike and FatLine agree
// on what "the same host" means — but it does not enforce anything. FatLine is
// the wall; this is the reference the policeman checks decisions against.
package policy

import (
	"net"
	"strings"

	"github.com/sofmon/farcast/manifest/parser"
)

// Policy is an immutable set of declared external hosts keyed by normalized
// host, carrying the operator-facing reason each was declared for. The zero
// value is an empty policy — everything is undeclared — and is safe to use;
// construct a populated one with New.
type Policy struct {
	hosts map[string]string // normalized host -> manifest reason
	order []string          // declared hosts in declaration order, de-duplicated
}

// New builds a Policy from parsed manifest `external` declarations. Empty hosts
// and IP literals are skipped (the manifest forbids both, and an IP can never be
// a member), so the policy mirrors exactly what FatLine's allowlist will admit.
func New(decls []parser.External) Policy {
	p := Policy{hosts: make(map[string]string, len(decls))}
	for _, d := range decls {
		h := normalize(d.Host)
		if h == "" || isIP(h) {
			continue
		}
		if _, seen := p.hosts[h]; !seen {
			p.order = append(p.order, h)
		}
		p.hosts[h] = d.Reason
	}
	return p
}

// Declared reports whether host is in the contract, returning the operator-facing
// reason it was declared for. The reason is surfaced for context (and, in 4.4,
// per-app attribution); 2.2 callers use the bool.
func (p Policy) Declared(host string) (reason string, ok bool) {
	reason, ok = p.hosts[normalize(host)]
	return reason, ok
}

// Hosts returns the declared hosts (normalized) in declaration order.
func (p Policy) Hosts() []string {
	return append([]string(nil), p.order...)
}

// normalize lower-cases the host and strips a single trailing dot, matching
// FatLine's allowlist. There is no suffix, wildcard, or parent-domain matching —
// the manifest is exact hostnames only.
func normalize(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	return strings.TrimSuffix(h, ".")
}

// isIP reports whether host is an IP literal (v4 or v6, with optional brackets).
func isIP(host string) bool {
	h := strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	return net.ParseIP(h) != nil
}
