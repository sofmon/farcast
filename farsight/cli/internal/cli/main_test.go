package cli

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// TestCertFileVariablesCannotAddARoot's children (harden_test.go) run
	// before anything else, so their first load of the system roots is theirs.
	if mode := os.Getenv(certChildEnv); mode != "" {
		os.Exit(certChildMain(mode))
	}
	// Every stream a fake cluster was asked to apply must pass the
	// in-process client's checks (manifests_test.go).
	os.Exit(finishTests(m.Run(), os.Stderr))
}
