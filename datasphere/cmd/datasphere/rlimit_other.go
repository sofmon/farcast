//go:build !linux

package main

// disableCoreDumps is a no-op away from Linux. The keyholder runs on Linux in
// every deployment; this exists so the package still builds on a developer's
// machine.
func disableCoreDumps() error { return nil }
