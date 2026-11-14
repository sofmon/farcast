package cli

import (
	"bytes"
	"os"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
)

// ADR 0023 decision 1: farcast turns off the two routes by which vendored
// Google code starts programs nobody asked for, process-wide, before anything
// else runs: client certificates (a certificate provider) and executable
// credential sources.
func TestMainTurnsClientCertificatesAndExecutablesOff(t *testing.T) {
	t.Setenv("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES", "1")
	t.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "true")
	// 'version' reads the config directory: a fresh one, never the operator's.
	t.Setenv(config.EnvConfigHome, t.TempDir())

	var out, errb bytes.Buffer
	if code := Main([]string{"farcast", "version"}, bytes.NewReader(nil), &out, &errb); code != 0 {
		t.Fatalf("farcast version: exit %d, %s", code, errb.String())
	}
	if v, ok := os.LookupEnv("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES"); ok {
		t.Errorf("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES is still set (%q); Main must unset it", v)
	}
	if v := os.Getenv("GOOGLE_API_USE_CLIENT_CERTIFICATE"); v != "false" {
		t.Errorf("GOOGLE_API_USE_CLIENT_CERTIFICATE = %q, want \"false\"", v)
	}
}
