package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/http2"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
)

// http2DebugChild marks the child run of TestEveryCommandRefusesHTTP2Debug,
// and http2DebugWant says whether the child's GODEBUG is to be refused.
const (
	http2DebugChild = "FARCAST_TEST_HTTP2DEBUG_CHILD"
	http2DebugWant  = "FARCAST_TEST_HTTP2DEBUG_WANT"
)

// errorEnvelopeOf decodes the JSON error envelope a refused command prints.
func errorEnvelopeOf(t *testing.T, out []byte) (message string, code int, kind string, ok bool) {
	t.Helper()
	var env struct {
		Error struct {
			Message string `json:"message"`
			Code    int    `json:"code"`
			Kind    string `json:"kind"`
		} `json:"error"`
	}
	if err := json.Unmarshal(out, &env); err != nil {
		return "", 0, "", false
	}
	return env.Error.Message, env.Error.Code, env.Error.Kind, true
}

// TestEveryCommandRefusesHTTP2Debug (ADR 0023 M2.8, step 0): under a GODEBUG
// holding http2debug=1 or http2debug=2, Go's HTTP/2 clients, net/http's and
// the vendored golang.org/x/net/http2 the Google clients use, print every
// request header, the bearer included, to stderr, from the process's start.
// Every command farcast registers refuses it, with the kind
// unsafe_environment and exit 1, before the config store reads anything, so
// no key is loaded and no token minted; so does Main, the binary's entry.
//
// The setting is read at init, so the test runs itself again as a child, once
// for each GODEBUG in the table. In each child, farcast's refusal must agree
// with what the vendored x/net/http2 turned on at its own init (VerboseLogs),
// so a newer x/net that logs under a setting farcast does not refuse fails
// here. net/http's own copy cannot be read; it is held by the toolchain pin
// (kube's http2Verbose names the version).
func TestEveryCommandRefusesHTTP2Debug(t *testing.T) {
	if os.Getenv(http2DebugChild) == "1" {
		everyCommandRefusesHTTP2DebugChild(t)
		return
	}
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GODEBUG=") && !strings.HasPrefix(kv, http2DebugChild+"=") && !strings.HasPrefix(kv, http2DebugWant+"=") {
			env = append(env, kv)
		}
	}
	for _, row := range []struct {
		godebug string
		refused bool
	}{
		{"http2debug=1", true},
		{"http2debug=2", true},
		{"a=1,http2debug=2", true},
		{"http2debug=10", true},
		{"http2debug=0", false},
		{"http2debug=3", false},
		{" http2debug = 1", false},
	} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestEveryCommandRefusesHTTP2Debug$", "-test.count=1", "-test.v")
		cmd.Env = append(slices.Clone(env), "GODEBUG="+row.godebug, http2DebugChild+"=1", fmt.Sprintf("%s=%t", http2DebugWant, row.refused))
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			t.Errorf("GODEBUG=%q: the child run failed: %v\n%s", row.godebug, err, stdout.String())
		}
		if !strings.Contains(stdout.String(), "--- PASS: TestEveryCommandRefusesHTTP2Debug") {
			t.Errorf("GODEBUG=%q: the child did not pass the test:\n%s", row.godebug, stdout.String())
		}
		for _, m := range []string{"Bearer", "authorization", "assertion", "access_token"} {
			if strings.Contains(stderr.String(), m) {
				t.Errorf("GODEBUG=%q: the child's stderr carries %q", row.godebug, m)
			}
		}
	}
}

// everyCommandRefusesHTTP2DebugChild is the child's half. Its GODEBUG is one
// of the parent's rows. Where it is refused, a connected instance's record,
// credential and mTLS material are on disk, so a command that ran would read
// them.
func everyCommandRefusesHTTP2DebugChild(t *testing.T) {
	refusal := kube.UnsafeEnvironment()
	refused := refusal != nil
	if refused != http2.VerboseLogs {
		t.Fatalf("GODEBUG=%q: farcast refuses it: %t; golang.org/x/net/http2 logs every header under it: %t", os.Getenv("GODEBUG"), refused, http2.VerboseLogs)
	}
	if want := os.Getenv(http2DebugWant) == "true"; refused != want {
		t.Fatalf("GODEBUG=%q: refused %t, the parent's table says %t", os.Getenv("GODEBUG"), refused, want)
	}
	if !refused {
		return
	}
	dir := config.Dir(t.TempDir())
	connectedInstance(t, dir, "atlas")
	opened := observeConfigReads(t)
	cmds := defaultRegistry().Commands()
	if len(cmds) == 0 {
		t.Fatal("the registry lists no command")
	}
	for _, c := range cmds {
		var out, errb bytes.Buffer
		code := run(context.Background(), []string{"farcast", "-o", "json", "--config", string(dir), c.Name()}, strings.NewReader(""), &out, &errb)
		msg, envCode, kind, ok := errorEnvelopeOf(t, out.Bytes())
		if code != 1 || !ok || envCode != 1 || kind != kindUnsafeEnvironment || msg != refusal.Error() {
			t.Errorf("%s: exit %d, envelope %q (code %d, kind %q); want exit 1 and the GODEBUG refusal, kind %s", c.Name(), code, msg, envCode, kind, kindUnsafeEnvironment)
		}
		if errb.Len() != 0 {
			t.Errorf("%s: stderr %q, want none in JSON mode", c.Name(), errb.String())
		}
	}
	// Main, the binary's entry, too: its own hardening must not refuse first,
	// which would print the error with no kind and no envelope (A33-9). The
	// environment Main changes is this child's, which is thrown away.
	var out, errb bytes.Buffer
	code := Main([]string{"farcast", "-o", "json", "--config", string(dir), "version"}, strings.NewReader(""), &out, &errb)
	msg, envCode, kind, ok := errorEnvelopeOf(t, out.Bytes())
	if code != 1 || !ok || envCode != 1 || kind != kindUnsafeEnvironment || msg != refusal.Error() || errb.Len() != 0 {
		t.Errorf("Main: exit %d, envelope %q (code %d, kind %q), stderr %q; want exit 1, the GODEBUG refusal of kind %s, and no stderr", code, msg, envCode, kind, errb.String(), kindUnsafeEnvironment)
	}
	if got := opened(); len(got) != 0 {
		t.Errorf("the config store read %v under the refusal, want nothing", got)
	}
}

// TestUnsafeEnvironmentIsRefusedBeforeAnythingIsRead: run asks
// unsafeEnvironment once the printer exists and before the config directory
// is resolved, so a refusal reads no record, no key and no material, in
// either output mode, and comes before an error resolving the config
// directory would. This is the parent-side twin of the child test, with the
// seam answering the refusal.
func TestUnsafeEnvironmentIsRefusedBeforeAnythingIsRead(t *testing.T) {
	refusal := fmt.Errorf("the test's environment refusal: %w", kube.ErrUnsafeEnvironment)
	saved := unsafeEnvironment
	t.Cleanup(func() { unsafeEnvironment = saved })
	unsafeEnvironment = func() error { return refusal }

	dir := config.Dir(t.TempDir())
	connectedInstance(t, dir, "atlas")
	opened := observeConfigReads(t)
	for _, line := range [][]string{
		{"world", "atlas"},
		{"storage", "deploy", "atlas"},
		{"build", "atlas", "."},
	} {
		var out, errb bytes.Buffer
		args := append([]string{"farcast", "-o", "json", "--config", string(dir)}, line...)
		code := run(context.Background(), args, strings.NewReader(""), &out, &errb)
		msg, envCode, kind, ok := errorEnvelopeOf(t, out.Bytes())
		if code != 1 || !ok || envCode != 1 || kind != kindUnsafeEnvironment || msg != refusal.Error() {
			t.Errorf("%v: exit %d, envelope %q (code %d, kind %q); want exit 1 and the refusal, kind %s", line, code, msg, envCode, kind, kindUnsafeEnvironment)
		}

		out.Reset()
		errb.Reset()
		args = append([]string{"farcast", "--config", string(dir)}, line...)
		if code := run(context.Background(), args, strings.NewReader(""), &out, &errb); code != 1 || out.Len() != 0 || errb.String() != "farcast: "+refusal.Error()+"\n" {
			t.Errorf("%v, human: exit %d, stdout %q, stderr %q; want exit 1 and the refusal on stderr", line, code, out.String(), errb.String())
		}
	}
	if got := opened(); len(got) != 0 {
		t.Errorf("the config store read %v under the refusal, want nothing", got)
	}

	// With no config directory that could be resolved, the refusal still
	// comes first: it is not Resolve's error. XDG_CONFIG_HOME is read before
	// HOME on Linux.
	t.Setenv(config.EnvConfigHome, "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")
	var out, errb bytes.Buffer
	code := run(context.Background(), []string{"farcast", "-o", "json", "world", "atlas"}, strings.NewReader(""), &out, &errb)
	msg, envCode, kind, ok := errorEnvelopeOf(t, out.Bytes())
	if code != 1 || !ok || envCode != 1 || kind != kindUnsafeEnvironment || msg != refusal.Error() {
		t.Errorf("no config directory: exit %d, envelope %q (code %d, kind %q); want exit 1 and the refusal, kind %s", code, msg, envCode, kind, kindUnsafeEnvironment)
	}
}
