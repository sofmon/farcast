//go:build !(darwin || linux || freebsd || openbsd || netbsd || dragonfly)

package config

import (
	"errors"
	"os"
)

// lockFile has no implementation on this platform, and a keyring write
// without one could lose another command's keys — so it refuses.
func lockFile(string) (func(), error) {
	return nil, errors.New("this build cannot lock the keyring against another farcast command, so it does not write it")
}

func linkCount(os.FileInfo) uint64 { return 1 }
