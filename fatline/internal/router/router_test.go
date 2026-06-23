package router

import (
	"net"
	"net/http"
	"sync"
	"testing"
)

// pipeConn returns a unique in-memory net.Conn to use as a table key.
func pipeConn() net.Conn {
	c, _ := net.Pipe()
	return c
}

func TestAddRemoveActive(t *testing.T) {
	tbl := NewTable()
	a, b := pipeConn(), pipeConn()
	tbl.Add(a)
	tbl.Add(b)
	if tbl.Active() != 2 {
		t.Fatalf("Active()=%d, want 2", tbl.Active())
	}
	tbl.Remove(a)
	if tbl.Active() != 1 {
		t.Fatalf("Active()=%d, want 1", tbl.Active())
	}
	tbl.Remove(a) // idempotent
	if tbl.Active() != 1 {
		t.Fatalf("Active()=%d after redundant remove, want 1", tbl.Active())
	}
}

func TestConnStateLifecycle(t *testing.T) {
	tbl := NewTable()
	c := pipeConn()
	tbl.ConnState(c, http.StateNew)
	if tbl.Active() != 1 {
		t.Fatalf("after StateNew Active()=%d, want 1", tbl.Active())
	}
	tbl.ConnState(c, http.StateActive) // not counted as a change
	if tbl.Active() != 1 {
		t.Fatalf("after StateActive Active()=%d, want 1", tbl.Active())
	}
	tbl.ConnState(c, http.StateClosed)
	if tbl.Active() != 0 {
		t.Fatalf("after StateClosed Active()=%d, want 0", tbl.Active())
	}
}

func TestConcurrent(t *testing.T) {
	tbl := NewTable()
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			c := pipeConn()
			for range 1000 {
				tbl.Add(c)
				_ = tbl.Active()
				tbl.Remove(c)
			}
		})
	}
	wg.Wait()
	if tbl.Active() != 0 {
		t.Fatalf("Active()=%d after all removed, want 0", tbl.Active())
	}
}
