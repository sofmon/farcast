package main

import (
	"os"
	"testing"
)

// ADR 0023 decision 1, for the harness: it turns client certificates and
// executable credential sources off in its own process, as farcast does.
func TestHarnessHardensItsEnvironment(t *testing.T) {
	t.Setenv("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES", "1")
	t.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "true")
	if err := hardenEnvironment(); err != nil {
		t.Fatal(err)
	}
	if v, ok := os.LookupEnv("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES"); ok {
		t.Errorf("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES is still set (%q)", v)
	}
	if v := os.Getenv("GOOGLE_API_USE_CLIENT_CERTIFICATE"); v != "false" {
		t.Errorf("GOOGLE_API_USE_CLIENT_CERTIFICATE = %q, want \"false\"", v)
	}
}
