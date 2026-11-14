package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestMain lets this test binary stand in for kubectl: linked as kubectl
// (selfAsKubectl), it prints its arguments and its whole environment. A Go
// binary rather than a shell script, because macOS strips every DYLD_*
// variable before it starts /bin/sh, so a script could never show one leaking.
func TestMain(m *testing.M) {
	if filepath.Base(os.Args[0]) == "kubectl" {
		args, _ := json.Marshal(os.Args[1:])
		fmt.Printf("args=%s\n", args)
		for _, kv := range os.Environ() {
			fmt.Println(kv)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// raceQuiet stops a race-built binary from sleeping a second when it exits
// 0; the self-kubectl is one. Env passes GORACE through for exactly this.
const raceQuiet = "GORACE=atexit_sleep_ms=0"

// selfAsKubectl links this test binary into a fresh directory as kubectl and
// returns the directory.
func selfAsKubectl(t *testing.T) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(self, filepath.Join(dir, "kubectl")); err != nil {
		t.Fatal(err)
	}
	return dir
}

// kubectlSaw is what the self-kubectl printed: its arguments and its
// environment, one entry per line.
func kubectlSaw(t *testing.T, c *Client) (args, env []string) {
	t.Helper()
	out, err := c.runner.Run(context.Background(), nil, "version")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	first, ok := strings.CutPrefix(lines[0], "args=")
	if !ok {
		t.Fatalf("not the self-kubectl's output: %q", out)
	}
	if err := json.Unmarshal([]byte(first), &args); err != nil {
		t.Fatal(err)
	}
	return args, lines[1:]
}

// shellParent is a developer's shell: everything Env must keep, and
// everything it must drop.
var shellParent = []string{
	"PATH=/usr/bin::bin:/opt/homebrew/bin",
	"HOME=/Users/op", "TMPDIR=/var/folders/xy/T/", "LANG=en_GB.UTF-8", "LC_ALL=en_GB.UTF-8", raceQuiet,
	"KUBECONFIG=/work", "KUBERC=/evil", "KUBECTL_KUBERC=true", "KUBECACHEDIR=/Users/op/.kube/cache",
	"CLOUDSDK_AUTH_ACCESS_TOKEN=planted-token", "CLOUDSDK_CORE_ACCOUNT=someone@work.example",
	"CLOUDSDK_PYTHON=/opt/python/bin/python3", "CLOUDSDK_CONFIG=/g", "CLOUDSDK_ACTIVE_CONFIG_NAME=work",
	"GOOGLE_APPLICATION_CREDENTIALS=/Users/op/key.json", "HTTPS_PROXY=http://127.0.0.1:9", "https_proxy=http://127.0.0.1:9",
	"DYLD_INSERT_LIBRARIES=/tmp/x.dylib", "LD_PRELOAD=/tmp/x.so", "PYTHONPATH=/tmp/py", "BASH_ENV=/tmp/bashenv",
	"SSL_CERT_FILE=/tmp/ca.pem", "FARCAST_CONFIG_HOME=/tmp/farcast", "GOFLAGS=-tags=integration",
}

// ADR 0023 M0: kubectl's environment is an allowlist. Unpinned, it keeps the
// parent's gcloud selection and the parent's KUBECONFIG (the token-cache key
// every command but 'world' has always used), and GORACE.
func TestEnvIsBuiltFromAnAllowlist(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows allowlist is untested until ADR 0023 M4")
	}
	got := Env(shellParent, "/cfg/instances/atlas/kubeconfig.yaml", GCloud{})
	want := []string{
		"CLOUDSDK_ACTIVE_CONFIG_NAME=work",
		"CLOUDSDK_CONFIG=/g",
		"GORACE=atexit_sleep_ms=0",
		"HOME=/Users/op",
		"KUBECONFIG=/work",
		"KUBERC=off",
		"LANG=en_GB.UTF-8",
		"LC_ALL=en_GB.UTF-8",
		"PATH=/usr/bin:/opt/homebrew/bin",
		"TMPDIR=/var/folders/xy/T/",
	}
	if !slices.Equal(got, want) {
		t.Errorf("Env\n got %q\nwant %q", got, want)
	}

	// A relative HOME or TMPDIR is dropped, and a key the parent repeats is
	// passed once, with the value a process would see: the last.
	got = Env([]string{"HOME=home", "TMPDIR=.", "LANG=C", "LANG=en_GB.UTF-8"}, "/kc", GCloud{})
	if want := []string{"KUBERC=off", "LANG=en_GB.UTF-8"}; !slices.Equal(got, want) {
		t.Errorf("Env\n got %q\nwant %q", got, want)
	}
}

// Pinned ('world'), the instance's kubeconfig and the chosen gcloud
// configuration replace the parent's.
func TestEnvPinnedReplacesTheParentsGCloudSelection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows allowlist is untested until ADR 0023 M4")
	}
	got := Env(shellParent, "/cfg/instances/atlas/kubeconfig.yaml", GCloud{Dir: "/Users/op/.config/gcloud", Config: "personal"})
	want := []string{
		"CLOUDSDK_ACTIVE_CONFIG_NAME=personal",
		"CLOUDSDK_CONFIG=/Users/op/.config/gcloud",
		"GORACE=atexit_sleep_ms=0",
		"HOME=/Users/op",
		"KUBECONFIG=/cfg/instances/atlas/kubeconfig.yaml",
		"KUBERC=off",
		"LANG=en_GB.UTF-8",
		"LC_ALL=en_GB.UTF-8",
		"PATH=/usr/bin:/opt/homebrew/bin",
		"TMPDIR=/var/folders/xy/T/",
	}
	if !slices.Equal(got, want) {
		t.Errorf("Env\n got %q\nwant %q", got, want)
	}
}

// Whatever environment a client was built with, kubectl runs with exactly
// one KUBERC, and it is off: no kuberc file can change a call.
func TestEveryKubectlRunsWithKubercOff(t *testing.T) {
	bin := selfAsKubectl(t)
	kuberc := func(env []string) []string {
		var out []string
		for _, kv := range env {
			if strings.HasPrefix(kv, "KUBERC=") {
				out = append(out, kv)
			}
		}
		return out
	}

	t.Setenv("PATH", bin)
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	t.Setenv("KUBERC", "/evil")
	_, env := kubectlSaw(t, New("/kc"))
	if got := kuberc(env); !slices.Equal(got, []string{"KUBERC=off"}) {
		t.Errorf("through New, kubectl saw %q", got)
	}

	_, env = kubectlSaw(t, NewWithEnv("/kc", []string{"PATH=" + bin, raceQuiet, "KUBERC=/x"}))
	if got := kuberc(env); !slices.Equal(got, []string{"KUBERC=off"}) {
		t.Errorf("through NewWithEnv, kubectl saw %q", got)
	}
}

// New no longer hands kubectl this process's environment: what the parent
// exported reaches it only through Env's allowlist.
func TestNewDoesNotInheritTheParentEnvironment(t *testing.T) {
	bin := selfAsKubectl(t)
	t.Setenv("PATH", bin)
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	t.Setenv("CLOUDSDK_AUTH_ACCESS_TOKEN", "planted-token")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	t.Setenv("DYLD_INSERT_LIBRARIES", "/nonexistent/x.dylib")
	_, env := kubectlSaw(t, New("/kc"))
	if len(env) == 0 {
		t.Fatal("kubectl printed no environment")
	}
	for _, kv := range env {
		for _, k := range []string{"CLOUDSDK_AUTH_ACCESS_TOKEN=", "HTTPS_PROXY=", "DYLD_INSERT_LIBRARIES="} {
			if strings.HasPrefix(kv, k) {
				t.Errorf("the parent's %s reached kubectl", strings.TrimSuffix(k, "="))
			}
		}
	}
	if !slices.Contains(env, "PATH="+bin) {
		t.Errorf("kubectl's PATH is not the parent's: %q", env)
	}
}

// The auth plugin keys its one token-cache entry by the current context of
// the file KUBECONFIG names. New keeps the parent's KUBECONFIG, or none,
// and never names the instance's there: that entry belongs to 'world' (ADR
// 0021 decision 9). kubectl itself always gets the instance's with --kubeconfig.
func TestNewKeepsTheParentsTokenCacheKey(t *testing.T) {
	bin := selfAsKubectl(t)
	t.Setenv("PATH", bin)
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	const instanceKC = "/cfg/instances/atlas/kubeconfig.yaml"
	kubeconfigs := func(env []string) []string {
		var out []string
		for _, kv := range env {
			if strings.HasPrefix(kv, "KUBECONFIG=") {
				out = append(out, kv)
			}
		}
		return out
	}

	t.Setenv("KUBECONFIG", "/Users/op/.kube/work")
	args, env := kubectlSaw(t, New(instanceKC))
	if !slices.Equal(args[:2], []string{"--kubeconfig", instanceKC}) {
		t.Errorf("kubectl's arguments: %q", args)
	}
	if got := kubeconfigs(env); !slices.Equal(got, []string{"KUBECONFIG=/Users/op/.kube/work"}) {
		t.Errorf("with the parent's KUBECONFIG set, kubectl saw %q", got)
	}

	if err := os.Unsetenv("KUBECONFIG"); err != nil {
		t.Fatal(err)
	}
	args, env = kubectlSaw(t, New(instanceKC))
	if !slices.Equal(args[:2], []string{"--kubeconfig", instanceKC}) {
		t.Errorf("kubectl's arguments: %q", args)
	}
	if got := kubeconfigs(env); len(got) != 0 {
		t.Errorf("with no KUBECONFIG in the parent, kubectl saw %q", got)
	}
}

// fakeKubectl writes an executable named kubectl into a fresh directory and
// returns that directory. The script is the test's stand-in for kubectl: no
// real binary, no cluster.
func fakeKubectl(t *testing.T, script string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// NewWithEnv gives kubectl exactly the environment it was handed. Nothing the
// parent process exported reaches it unless the caller put it there — which is
// the whole point: the identity kubectl's auth plugin acts as is decided by
// what is in that environment.
func TestNewWithEnvGivesKubectlExactlyTheEnvironmentItWasHanded(t *testing.T) {
	bin := fakeKubectl(t, "/usr/bin/env\n")
	t.Setenv("CLOUDSDK_AUTH_ACCESS_TOKEN", "planted-in-the-parent")
	t.Setenv("KUBECONFIG", "/somewhere/work-config")

	env := []string{"PATH=" + bin, "KUBECONFIG=/instances/atlas/kubeconfig.yaml", "CLOUDSDK_ACTIVE_CONFIG_NAME=personal"}
	out, err := NewWithEnv("/instances/atlas/kubeconfig.yaml", env).runner.Run(context.Background(), nil, "version")
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, want := range env {
		if !slices.Contains(got, want) {
			t.Errorf("kubectl's environment is missing %q:\n%s", want, out)
		}
	}
	for _, line := range got {
		if strings.HasPrefix(line, "CLOUDSDK_AUTH_ACCESS_TOKEN=") || line == "KUBECONFIG=/somewhere/work-config" {
			t.Errorf("the parent's %q reached kubectl", line)
		}
	}
}

// The kubectl that runs is the one the handed environment's PATH finds, not
// the one this process's PATH would — and with none there, the error says
// kubectl is missing, marked so a caller can tell without reading it.
func TestNewWithEnvFindsKubectlOnTheHandedPath(t *testing.T) {
	bin := fakeKubectl(t, "echo from-the-handed-path\n")
	out, err := NewWithEnv("/kc", []string{"PATH=" + bin}).runner.Run(context.Background(), nil, "x")
	if err != nil || strings.TrimSpace(string(out)) != "from-the-handed-path" {
		t.Fatalf("out=%q err=%v", out, err)
	}

	_, err = NewWithEnv("/kc", []string{"PATH=" + t.TempDir()}).runner.Run(context.Background(), nil, "x")
	if !errors.Is(err, ErrKubectlMissing) {
		t.Fatalf("err = %v, want ErrKubectlMissing", err)
	}
	// A relative or empty PATH entry is never searched: a kubectl planted in
	// the working directory must not be the one that runs.
	if _, ok := lookPathIn("kubectl", ":.:relative"); ok {
		t.Error("a relative PATH entry was searched")
	}
	if _, err := NewWithEnv("/kc", nil).runner.Run(context.Background(), nil, "x"); !errors.Is(err, ErrKubectlMissing) {
		t.Errorf("a nil environment found a kubectl: %v", err)
	}
}

// What kubectl's stderr says about authentication becomes a mark a caller can
// test with errors.Is, and the message reads exactly as it did before.
func TestKubectlFailuresAreMarkedWithoutChangingTheirText(t *testing.T) {
	for _, tc := range []struct {
		stderr string
		mark   error
	}{
		{"ERROR: (gcloud.auth.print-access-token) There was a problem refreshing your current auth tokens: Reauthentication failed.", ErrSignedOut},
		{"Unable to connect to the server: getting credentials: exec: executable gke-gcloud-auth-plugin not found", ErrAuthToolMissing},
		{`error: exec: "gcloud": executable file not found in $PATH`, ErrAuthToolMissing},
		{`Error from server (Forbidden): configmaps is forbidden`, nil},
	} {
		bin := fakeKubectl(t, "echo '"+strings.ReplaceAll(tc.stderr, "'", `'\''`)+"' >&2\nexit 1\n")
		_, err := NewWithEnv("/kc", []string{"PATH=" + bin}).runner.Run(context.Background(), nil, "get", "configmap")
		if err == nil {
			t.Fatalf("%q: kubectl failed and the runner did not", tc.stderr)
		}
		if want := "kubectl get configmap: " + tc.stderr; err.Error() != want {
			t.Errorf("text = %q, want %q", err.Error(), want)
		}
		for _, m := range []error{ErrSignedOut, ErrAuthToolMissing, ErrKubectlMissing} {
			if got := errors.Is(err, m); got != (m == tc.mark) {
				t.Errorf("%q: errors.Is(%v) = %v", tc.stderr, m, got)
			}
		}
	}
}

// A kubectl killed by its deadline says only "signal: killed". The runner
// says what happened instead, wrapped so it is found with errors.Is.
func TestAKubectlPastItsDeadlineIsATimeout(t *testing.T) {
	bin := fakeKubectl(t, "exec /bin/sleep 5\n")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := NewWithEnv("/kc", []string{"PATH=" + bin}).runner.Run(ctx, nil, "get", "namespace")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want it to wrap context.DeadlineExceeded", err)
	}
}

func TestNamespacesLabelledReadsJSONAndSorts(t *testing.T) {
	body := `{"items":[{"metadata":{"name":"web"}},{"metadata":{"name":"api"}},{"metadata":{"name":""}}]}`
	fr := &fakeRunner{out: map[string][]byte{"get": []byte(body)}}
	got, err := NewWithRunner(fr).NamespacesLabelled(context.Background(), "app.kubernetes.io/managed-by=farcast")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"api", "web"}) {
		t.Errorf("got %v, want [api web]", got)
	}
	want := []string{"get", "namespace", "-l", "app.kubernetes.io/managed-by=farcast", "-o", "json"}
	if !slices.Equal(fr.calls[0], want) {
		t.Errorf("call = %v, want %v", fr.calls[0], want)
	}

	empty := &fakeRunner{out: map[string][]byte{"get": nil}}
	if got, err := NewWithRunner(empty).NamespacesLabelled(context.Background(), "x=y"); err != nil || got == nil || len(got) != 0 {
		t.Errorf("an empty answer = %v, %v; want an empty list", got, err)
	}
}

// gcloud's other ways of saying the operator must sign in — an account sitting
// in a configuration that was never logged in on this machine or had its grant
// revoked, or no account at all — are signed out too, not an ordinary kubectl
// failure: the map has to be able to say "signed out of gcloud". A missing
// tool stays a missing tool even when gcloud's advice in the same text names a
// sign-in.
func TestEveryGCloudSignInRequestIsSignedOut(t *testing.T) {
	for _, tc := range []struct {
		stderr string
		mark   error
	}{
		{"Unable to connect to the server: getting credentials: exec: executable gke-gcloud-auth-plugin failed with exit code 1: " +
			"ERROR: (gcloud.config.config-helper) Your current active account [operator@example.org] does not have any valid credentials\n" +
			"Please run:\n\n  $ gcloud auth login\n\nto obtain new credentials.", ErrSignedOut},
		{"ERROR: (gcloud.auth.print-access-token) You do not currently have an active account selected.\nPlease run:\n\n  $ gcloud auth login", ErrSignedOut},
		{"To sign in, run: gcloud auth login", ErrSignedOut},
		{`error: exec: "gcloud": executable file not found in $PATH; once installed, run gcloud auth login`, ErrAuthToolMissing},
	} {
		bin := fakeKubectl(t, "printf '%s' '"+strings.ReplaceAll(tc.stderr, "'", `'\''`)+"' >&2\nexit 1\n")
		_, err := NewWithEnv("/kc", []string{"PATH=" + bin}).runner.Run(context.Background(), nil, "get", "configmap")
		if err == nil {
			t.Fatalf("%q: kubectl failed and the runner did not", tc.stderr)
		}
		for _, m := range []error{ErrSignedOut, ErrAuthToolMissing, ErrKubectlMissing} {
			if got := errors.Is(err, m); got != (m == tc.mark) {
				t.Errorf("%q: errors.Is(%v) = %v", tc.stderr, m, got)
			}
		}
	}
}
