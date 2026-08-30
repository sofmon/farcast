//go:build linux

package main

import "syscall"

// disableCoreDumps sets RLIMIT_CORE to zero.
//
// A core dump of this process is a copy of the derived bundle written to node
// disk — the one thing the whole design exists to prevent (ADR 0008 decision
// 1). Lowering a soft limit needs no capability and no node access, so the
// process does it for itself rather than trusting the platform to have been
// configured correctly.
func disableCoreDumps() error {
	return syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})
}
