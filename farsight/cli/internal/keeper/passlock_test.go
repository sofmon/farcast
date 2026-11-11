//go:build darwin || linux || freebsd || openbsd || netbsd || dragonfly

package keeper

import (
	"errors"
	"testing"
)

// Review finding V3-1. One device makes one pass at a time: a second process
// that finds a pass running is told so at once, and does not wait for it.
func TestLockPassAdmitsOnePassAtATime(t *testing.T) {
	s := &Store{dir: t.TempDir()}
	release, err := s.LockPass()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.LockPass(); !errors.Is(err, ErrPassRunning) {
		t.Fatalf("a second pass while one runs: %v; want ErrPassRunning", err)
	}
	release()
	again, err := s.LockPass()
	if err != nil {
		t.Fatalf("after the first pass released it: %v", err)
	}
	again()
}
