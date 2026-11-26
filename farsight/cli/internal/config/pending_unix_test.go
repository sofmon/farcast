//go:build unix

package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// ADR 0024 M3b.2: an entry whose pending.yaml could not be written is removed
// again, so its name is not left pending with no record, and a new create of
// it is not refused as ErrPendingExists. The write is made to fail by a umask
// that leaves the new entry unwritable to its owner; pending/ is made before
// that, so the entry can be removed. No test in this package runs in
// parallel, so the process-wide umask reaches no other test.
func TestCreatePendingRemovesAnEntryItCouldNotWrite(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes into a directory its mode closes")
	}
	d := pendingDir(t)
	if err := d.CreatePending("alpha", validPending("alpha")); err != nil {
		t.Fatal(err)
	}
	old := syscall.Umask(0o277)
	restored := false
	restore := func() {
		if !restored {
			syscall.Umask(old)
			restored = true
		}
	}
	t.Cleanup(restore)
	err := d.CreatePending("atlas", validPending("atlas"))
	restore()
	if err == nil || !strings.Contains(err.Error(), `write instance "atlas"'s pending record`) {
		t.Fatalf("CreatePending into an unwritable entry = %v; want its write refused", err)
	}
	if _, err := os.Lstat(filepath.Join(d.PendingDir(), "atlas")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the entry whose record was not written is still there: %v", err)
	}
	if err := d.CreatePending("atlas", validPending("atlas")); err != nil {
		t.Errorf("a create after the failed one = %v; want it made", err)
	}
	if _, err := d.LoadPending("alpha"); err != nil {
		t.Errorf("the other entry: %v", err)
	}
}
