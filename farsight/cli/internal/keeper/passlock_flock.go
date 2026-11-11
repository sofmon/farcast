//go:build darwin || linux || freebsd || openbsd || netbsd || dragonfly

package keeper

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// LockPass takes this keeper's pass lock, or returns ErrPassRunning at once
// when another process holds it. The returned function releases it.
//
// One device makes one pass at a time. A timer's --once and a loop, or a
// manual --once over either, would otherwise both read a restarted replica
// as sealed and both push into it: the second push is refused after its
// bundle was sent, which the budget and the audit count — one restart would
// spend two slots and read as a process re-seeded twice. It does not wait: a
// pass that finds another running has nothing to add to it, and a timer that
// queued behind a stuck one would pile up.
//
// The lock is advisory (flock) on a file of its own beside the ledger, so it
// is released by the kernel when the holder exits, however it exits.
func (s *Store) LockPass() (func(), error) {
	f, err := os.OpenFile(filepath.Join(s.dir, passLockFile), os.O_RDWR|os.O_CREATE, fileMode)
	if err != nil {
		return nil, fmt.Errorf("keeper: opening the pass lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrPassRunning
		}
		return nil, fmt.Errorf("keeper: taking the pass lock: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
