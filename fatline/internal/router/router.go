// Package router tracks FatLine's active ingress tunnel sessions — the second
// of the two shared-mutable-state paths ADR 0002 singles out for race tests
// (the other is the allowlist). It feeds ConnStatus.Active and underpins the
// connection lifecycle (establish, maintain, teardown).
package router

import (
	"net"
	"net/http"
	"sync"
)

// Table is a concurrency-safe registry of active tunnel connections. The zero
// value is not usable; construct with NewTable.
type Table struct {
	mu     sync.Mutex
	active map[net.Conn]struct{}
}

// NewTable returns an empty session table.
func NewTable() *Table {
	return &Table{active: make(map[net.Conn]struct{})}
}

// Add records a newly established connection.
func (t *Table) Add(c net.Conn) {
	t.mu.Lock()
	t.active[c] = struct{}{}
	t.mu.Unlock()
}

// Remove drops a torn-down connection. Removing an absent connection is a no-op.
func (t *Table) Remove(c net.Conn) {
	t.mu.Lock()
	delete(t.active, c)
	t.mu.Unlock()
}

// Active returns the number of live connections.
func (t *Table) Active() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.active)
}

// ConnState is an http.Server.ConnState hook that maintains the table across a
// connection's lifecycle: counted from StateNew until it is hijacked or closed.
func (t *Table) ConnState(c net.Conn, s http.ConnState) {
	switch s {
	case http.StateNew:
		t.Add(c)
	case http.StateHijacked, http.StateClosed:
		t.Remove(c)
	}
}
