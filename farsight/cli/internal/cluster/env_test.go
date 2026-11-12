package cluster

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

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
