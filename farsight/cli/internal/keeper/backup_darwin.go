package keeper

import (
	"bytes"
	"fmt"

	"golang.org/x/sys/unix"
)

// The macOS backup-exclusion attribute. Time Machine reads it, and it is the
// documented way for a program to say "do not copy this" without asking the
// operator to configure their backup software.
//
// It is set on the DIRECTORY, which excludes what is inside it — so a file
// added later (the ledger, on the first reseed) is covered without anything
// having to remember to mark it.
const (
	backupExcludeAttr  = "com.apple.metadata:com_apple_backup_excludeItem"
	backupExcludeValue = "com.apple.backupd"
)

// ExcludeFromBackup marks dir as excluded from the platform's backup pipeline,
// and then reads it back.
//
// The read-back is the point. ADR 0008 says a platform that cannot guarantee
// the exclusion cannot be a keeper, and a setter whose result nobody checked
// is not a guarantee — it is an intention. Whatever this returns is written
// into the keeper's own record, so an operator can later see what the device
// actually managed rather than what the code hoped for.
//
// What it does NOT cover, stated plainly: a third-party backup agent that
// ignores the attribute, and any copy of the directory made before this ran.
// The attribute binds Time Machine; it does not bind everything.
func ExcludeFromBackup(dir string) error {
	if err := unix.Setxattr(dir, backupExcludeAttr, []byte(backupExcludeValue), 0); err != nil {
		return fmt.Errorf("keeper: this device could not mark %s as excluded from backup: %w", dir, err)
	}
	buf := make([]byte, 256)
	n, err := unix.Getxattr(dir, backupExcludeAttr, buf)
	if err != nil {
		return fmt.Errorf("keeper: this device could not confirm %s is excluded from backup: %w", dir, err)
	}
	if !bytes.Equal(buf[:n], []byte(backupExcludeValue)) {
		return fmt.Errorf("keeper: %s reports a backup-exclusion attribute this build did not set", dir)
	}
	return nil
}
