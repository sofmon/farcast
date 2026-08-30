package main

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

func runServe(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out, errw bytes.Buffer
	code := run(append([]string{"datasphere", "serve"}, args...), &out, &errw)
	return code, out.String() + errw.String()
}

func TestServeRequiresItsTarget(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"--instance", "prod"},
		{"--bucket", "b"},
	} {
		code, msg := runServe(t, args...)
		if code == 0 {
			t.Errorf("serve %v succeeded without a complete target", args)
		}
		if !strings.Contains(msg, "--instance") || !strings.Contains(msg, "--bucket") {
			t.Errorf("serve %v: message should name what is missing: %q", args, msg)
		}
	}
}

// The keyholder holds only what is pushed to it. Being handed a keyring on
// disk is a misunderstanding of the whole design, so it is named rather than
// silently ignored.
func TestServeRefusesAKeyringOnDisk(t *testing.T) {
	code, msg := runServe(t, "--instance", "prod", "--bucket", "b", "--keys", "keys.yaml")
	if code == 0 {
		t.Fatal("serve accepted --keys")
	}
	if !strings.Contains(msg, "--keys") || !strings.Contains(msg, "memory") {
		t.Errorf("the refusal should explain why: %q", msg)
	}
}

// GOTRACEBACK=crash would print this process's memory neighbourhood on a
// panic. The deployment sets it to none; refusing the dangerous values means
// an injected environment cannot quietly undo that.
func TestServeRefusesDumpingTracebacks(t *testing.T) {
	for _, value := range []string{"crash", "all", "system", "2", "CRASH"} {
		t.Setenv("GOTRACEBACK", value)
		code, msg := runServe(t, "--instance", "prod", "--bucket", "b")
		if code == 0 {
			t.Errorf("serve started with GOTRACEBACK=%s", value)
		}
		if !strings.Contains(msg, "GOTRACEBACK") {
			t.Errorf("GOTRACEBACK=%s: message should name the setting: %q", value, msg)
		}
	}
	// The safe values must not be refused for the wrong reason.
	for _, value := range []string{"", "none", "single"} {
		t.Setenv("GOTRACEBACK", value)
		_, msg := runServe(t, "--instance", "prod", "--bucket", "b")
		if strings.Contains(msg, "GOTRACEBACK") {
			t.Errorf("GOTRACEBACK=%q was refused: %q", value, msg)
		}
	}
}

func TestServeRequiresTransportMaterial(t *testing.T) {
	t.Setenv("GOTRACEBACK", "none")
	t.Setenv(envTLSCA, "")
	t.Setenv(envTLSCert, "")
	t.Setenv(envTLSKey, "")
	code, msg := runServe(t, "--instance", "prod", "--bucket", "b")
	if code == 0 {
		t.Fatal("serve started without transport material")
	}
	for _, want := range []string{envTLSCA, envTLSCert, envTLSKey} {
		if !strings.Contains(msg, want) {
			t.Errorf("message should name %s: %q", want, msg)
		}
	}
}

// A malformed key must never reach a log. The process is handed a private key
// on this path, and an error that echoed it would put it wherever stderr goes.
func TestServeTransportErrorsDoNotEchoMaterial(t *testing.T) {
	const secret = "SUPERSECRETPRIVATEKEYBYTES"
	t.Setenv("GOTRACEBACK", "none")
	t.Setenv(envTLSCA, "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----")
	t.Setenv(envTLSCert, "not a certificate")
	t.Setenv(envTLSKey, "-----BEGIN PRIVATE KEY-----\n"+secret+"\n-----END PRIVATE KEY-----")
	code, msg := runServe(t, "--instance", "prod", "--bucket", "b")
	if code == 0 {
		t.Fatal("serve started with malformed transport material")
	}
	if strings.Contains(msg, secret) {
		t.Fatalf("the failure echoed the private key: %q", msg)
	}
}

// A debug or metrics surface on the one process holding key material is a side
// channel — object sizes, key ids, request timing — and net/http/pprof
// registers itself on the default mux merely by being imported. This asserts
// the whole import graph, so an indirect dependency cannot pull one in either.
func TestNoDebugSurfaceInTheImportGraph(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Skipf("go list unavailable: %v", err)
	}
	forbidden := []string{"net/http/pprof", "expvar", "runtime/pprof", "net/http/httptest"}
	for _, pkg := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		for _, bad := range forbidden {
			if strings.TrimSpace(pkg) == bad {
				t.Errorf("%s is in the keyholder's import graph; it exposes this process's internals", bad)
			}
		}
	}
}

func TestUsageMentionsServe(t *testing.T) {
	var out, errw bytes.Buffer
	run([]string{"datasphere"}, &out, &errw)
	if !strings.Contains(errw.String(), "serve") {
		t.Error("usage does not mention serve")
	}
}
