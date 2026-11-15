package main

import (
	"os"
	"testing"
)

// ADR 0023 decision 1, for the harness: it turns client certificates and
// executable credential sources off in its own process, as farcast does. Since
// ADR 0023 M2.3 it also unsets, as farcast's twin does (design §3.6), the
// Google libraries' logging level and the two variables that replace the
// system roots.
func TestHarnessHardensItsEnvironment(t *testing.T) {
	t.Setenv("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES", "1")
	t.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "true")
	t.Setenv("GOOGLE_SDK_GO_LOGGING_LEVEL", "debug")
	t.Setenv("SSL_CERT_FILE", "/nonexistent/harness-ca.pem")
	t.Setenv("SSL_CERT_DIR", "/nonexistent/harness-certs")
	if err := hardenEnvironment(); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES", "GOOGLE_SDK_GO_LOGGING_LEVEL", "SSL_CERT_FILE", "SSL_CERT_DIR"} {
		if v, ok := os.LookupEnv(k); ok {
			t.Errorf("%s is still set (%q)", k, v)
		}
	}
	if v := os.Getenv("GOOGLE_API_USE_CLIENT_CERTIFICATE"); v != "false" {
		t.Errorf("GOOGLE_API_USE_CLIENT_CERTIFICATE = %q, want \"false\"", v)
	}
}
