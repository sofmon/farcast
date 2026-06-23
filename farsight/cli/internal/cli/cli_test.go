package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// runCLI invokes the router with an isolated config home and returns the
// captured streams and exit code.
func runCLI(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	t.Setenv("FARCAST_CONFIG_HOME", t.TempDir())
	var out, errb bytes.Buffer
	full := append([]string{"farcast"}, args...)
	code = run(context.Background(), full, strings.NewReader(""), &out, &errb)
	return out.String(), errb.String(), code
}

func TestVersionHuman(t *testing.T) {
	out, _, code := runCLI(t, "version")
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.HasPrefix(out, "farcast ") {
		t.Errorf("missing version banner:\n%s", out)
	}
	if !strings.Contains(out, "os/arch:") {
		t.Errorf("missing os/arch line:\n%s", out)
	}
}

func TestVersionJSON(t *testing.T) {
	out, _, code := runCLI(t, "-o", "json", "version")
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	for _, k := range []string{"version", "commit", "built", "go", "os", "arch"} {
		if _, ok := m[k]; !ok {
			t.Errorf("JSON missing key %q", k)
		}
	}
}

func TestVersionFlag(t *testing.T) {
	out, _, code := runCLI(t, "--version")
	if code != 0 || !strings.HasPrefix(out, "farcast ") {
		t.Fatalf("--version: code=%d out=%q", code, out)
	}
}

func TestHelpListsCommands(t *testing.T) {
	out, _, code := runCLI(t, "help")
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	for _, want := range []string{"Commands:", "version", "help", "install", "Global flags:"} {
		if !strings.Contains(out, want) {
			t.Errorf("help missing %q:\n%s", want, out)
		}
	}
}

func TestHelpForCommand(t *testing.T) {
	out, _, code := runCLI(t, "help", "install")
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(out, "install") || !strings.Contains(out, "cost-limit") {
		t.Errorf("install help unexpected:\n%s", out)
	}
}

func TestRootHelpFlag(t *testing.T) {
	out, _, code := runCLI(t, "--help")
	if code != 0 || !strings.Contains(out, "Commands:") {
		t.Fatalf("--help: code=%d out=%q", code, out)
	}
}

func TestCommandHelpFlag(t *testing.T) {
	out, _, code := runCLI(t, "install", "--help")
	if code != 0 || !strings.Contains(out, "cost-limit") {
		t.Fatalf("install --help: code=%d out=%q", code, out)
	}
}

func TestNoArgsShowsUsageError(t *testing.T) {
	_, errOut, code := runCLI(t)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errOut, "Commands:") {
		t.Errorf("expected usage on stderr:\n%s", errOut)
	}
}

func TestUnknownCommand(t *testing.T) {
	_, errOut, code := runCLI(t, "frobnicate")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errOut, "unknown command") {
		t.Errorf("expected unknown-command error:\n%s", errOut)
	}
}

func TestBadFlag(t *testing.T) {
	_, errOut, code := runCLI(t, "--nope")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errOut, "farcast:") {
		t.Errorf("expected error on stderr:\n%s", errOut)
	}
}

func TestStubNotImplementedHuman(t *testing.T) {
	_, errOut, code := runCLI(t, "run")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errOut, "not yet implemented") || !strings.Contains(errOut, "4.3") {
		t.Errorf("unexpected stub error:\n%s", errOut)
	}
}

func TestStubNotImplementedJSON(t *testing.T) {
	out, _, code := runCLI(t, "-o", "json", "run")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	var env struct {
		Error struct {
			Message string `json:"message"`
			Code    int    `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if !strings.Contains(env.Error.Message, "not yet implemented") {
		t.Errorf("unexpected message: %q", env.Error.Message)
	}
	if env.Error.Code != 1 {
		t.Errorf("code = %d, want 1", env.Error.Code)
	}
}

func TestFlagsAfterPositional(t *testing.T) {
	// "release <name> --yes" must parse --yes after the positional, so this is a
	// no-such-instance runtime error (exit 1), not a usage error (exit 2).
	_, errOut, code := runCLI(t, "release", "demo", "--yes")
	if code != 1 {
		t.Fatalf("exit = %d, want 1; stderr=%s", code, errOut)
	}
	if !strings.Contains(errOut, "no such instance") {
		t.Errorf("expected no-such-instance, got:\n%s", errOut)
	}
}

func TestInvalidOutputMode(t *testing.T) {
	_, errOut, code := runCLI(t, "-o", "xml", "version")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errOut, "xml") {
		t.Errorf("expected invalid-mode error:\n%s", errOut)
	}
}
