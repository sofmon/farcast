//go:build !darwin

package keeper

import (
	"strings"
	"testing"
)

// The reason is recorded in a keeper's config and printed after "NOT
// verifiably excluded —", so it must read as a reason, not as a log line.
func TestExcludeFromBackupReadsAsAReason(t *testing.T) {
	err := ExcludeFromBackup(t.TempDir())
	if err == nil {
		t.Fatal("a build with no verifiable backup pipeline claimed an exclusion")
	}
	if strings.HasPrefix(err.Error(), "keeper:") {
		t.Errorf("the reason carries a package prefix: %q", err)
	}
}
