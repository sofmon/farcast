//go:build !(darwin || linux || freebsd || openbsd || netbsd || dragonfly)

package keeper

// LockPass has no lock to take on this platform, and does not refuse for
// that: two passes that overlap still record each push under its own id, so
// the ledger reads them correctly. What it cannot prevent is the overlap
// itself — a second push into the same restart, refused after sending, which
// the budget and the audit count.
func (s *Store) LockPass() (func(), error) { return func() {}, nil }
