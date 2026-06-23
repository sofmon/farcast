// Package allowlist is FatLine's deny-by-default egress policy: the set of
// external hosts an application is permitted to reach, built from the parsed
// ./farcast manifest's `external` declarations.
//
// It is one of the two shared-mutable-state paths ADR 0002 singles out for race
// tests (the other is the session table), so it is a first-class package rather
// than buried in the proxy. Reads are lock-free against an immutable snapshot;
// Reload swaps the snapshot atomically, so a concurrent reader never sees a
// torn list and deny-by-default holds during and after a swap.
package allowlist

import (
	"net"
	"strings"
	"sync/atomic"

	"github.com/sofmon/farcast/manifest/parser"
)

// defaultTenant is the single tenant used in phase 2.1, before per-app identity
// exists. The Allow(tenant, host) seam is keyed so phase 4.4 can populate one
// allowlist per app without reshaping callers.
const defaultTenant = ""

// Decision is the outcome of an allowlist check.
type Decision struct {
	Allowed bool
	Host    string // the normalized host that was checked
	Reason  string // allow: the manifest reason; deny: an event.Reason* string
}

// List is a concurrency-safe, deny-by-default egress allowlist. The zero value
// is not usable; construct with New.
type List struct {
	snap atomic.Pointer[snapshot]
}

// snapshot is an immutable view of the policy: tenant -> host -> manifest
// reason. It is never mutated after publication, so readers need no lock.
type snapshot struct {
	tenants map[string]map[string]string
	// hosts is the default tenant's declared hosts in declaration order, for
	// status reporting and event context.
	hosts []parser.External
}

// New builds an allowlist for the default tenant from parsed manifest `external`
// declarations. An empty or nil list denies everything.
func New(decls []parser.External) *List {
	l := &List{}
	l.snap.Store(build(map[string][]parser.External{defaultTenant: decls}))
	return l
}

// build constructs an immutable snapshot from per-tenant declarations.
func build(byTenant map[string][]parser.External) *snapshot {
	s := &snapshot{tenants: make(map[string]map[string]string, len(byTenant))}
	for tenant, decls := range byTenant {
		hosts := make(map[string]string, len(decls))
		for _, d := range decls {
			h := normalize(d.Host)
			if h == "" {
				continue
			}
			hosts[h] = d.Reason
		}
		s.tenants[tenant] = hosts
		if tenant == defaultTenant {
			s.hosts = append([]parser.External(nil), decls...)
		}
	}
	return s
}

// Reload atomically replaces the default tenant's allowlist. Concurrent readers
// see either the old or the new list, never a mix. (Per-tenant reloads for the
// phase-4.4 multi-app model would extend this; 2.1 has only the default tenant.)
func (l *List) Reload(decls []parser.External) {
	l.snap.Store(build(map[string][]parser.External{defaultTenant: decls}))
}

// Allowed checks a host against the default tenant's allowlist.
func (l *List) Allowed(host string) Decision { return l.Allow(defaultTenant, host) }

// Allow checks a host against a specific tenant's allowlist. This is the
// per-app seam (phase 4.4); in 2.1 every caller uses the default tenant.
func (l *List) Allow(tenant, host string) Decision {
	h := normalize(host)
	d := Decision{Host: h}
	if h == "" || isIP(h) {
		// The manifest forbids IP-literal hosts, so an IP can never be a member;
		// deny it explicitly rather than letting a lookup miss it silently.
		d.Reason = "not_in_allowlist"
		return d
	}
	hosts := l.snap.Load().tenants[tenant]
	if reason, ok := hosts[h]; ok {
		d.Allowed = true
		d.Reason = reason
		return d
	}
	d.Reason = "not_in_allowlist"
	return d
}

// Hosts returns the default tenant's declared hosts (normalized), in
// declaration order, for status reporting.
func (l *List) Hosts() []string {
	decls := l.snap.Load().hosts
	out := make([]string, 0, len(decls))
	for _, d := range decls {
		if h := normalize(d.Host); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// Snapshot returns the default tenant's declarations (host + reason), copied.
func (l *List) Snapshot() []parser.External {
	decls := l.snap.Load().hosts
	return append([]parser.External(nil), decls...)
}

// normalize lower-cases the host (DNS is case-insensitive) and strips a single
// trailing dot (the FQDN root). It does not alter anything else: there is no
// suffix, wildcard, or parent-domain matching — the Phase 0.1 manifest is exact
// hostnames only.
func normalize(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimSuffix(h, ".")
	return h
}

// isIP reports whether host is an IP literal (v4 or v6, with optional brackets).
func isIP(host string) bool {
	h := strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	return net.ParseIP(h) != nil
}
