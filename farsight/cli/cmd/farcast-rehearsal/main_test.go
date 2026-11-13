package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/rehearsal"
)

// The test binary stands in for two things. Linked as farcast, it is a stub
// that records the argv and environment it was given beside itself, in
// "seen", and prints a version document. Linked as a fake tool, it is that
// tool, as the harness binary is.
func TestMain(m *testing.M) {
	if filepath.Base(os.Args[0]) == "farcast" {
		os.Exit(stubFarcast())
	}
	if code, ok := rehearsal.ToolMain(os.Args[0], os.Args[1:], os.Environ(), os.Stdout, os.Stderr); ok {
		os.Exit(code)
	}
	os.Exit(m.Run())
}

type seen struct {
	Args []string          `json:"args"`
	Env  map[string]string `json:"env"`
}

func stubFarcast() int {
	s := seen{Args: os.Args[1:], Env: map[string]string{}}
	for _, kv := range os.Environ() {
		k, v, _ := strings.Cut(kv, "=")
		s.Env[k] = v
	}
	data, err := json.Marshal(s)
	if err != nil {
		return 1
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(os.Args[0]), "seen"), data, 0o600); err != nil {
		return 1
	}
	fmt.Println(`{"version":"v0.0.0-stub","commit":"0000000"}`)
	return 0
}

// syncBuffer is a bytes.Buffer safe to write from run's goroutine and read
// from the test's.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// running is the start command running in a goroutine, its stdout read line
// by line through a pipe.
type running struct {
	lines  chan string
	done   chan int
	cancel context.CancelFunc
	stderr *syncBuffer
}

func start(t *testing.T, args ...string) *running {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	r := &running{lines: make(chan string, 64), done: make(chan int, 1), cancel: cancel, stderr: &syncBuffer{}}
	go func() {
		code := run(ctx, args, strings.NewReader(""), pw, r.stderr)
		_ = pw.Close()
		r.done <- code
	}()
	go func() {
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			r.lines <- sc.Text()
		}
		close(r.lines)
	}()
	t.Cleanup(cancel)
	return r
}

// until reads lines up to and including the first that starts with prefix.
// It waits only on the rig starting on 127.0.0.1, and at most 30 seconds.
func (r *running) until(t *testing.T, prefix string) []string {
	t.Helper()
	var got []string
	timeout := time.After(30 * time.Second)
	for {
		select {
		case l, ok := <-r.lines:
			if !ok {
				t.Fatalf("the command ended before %q: %v\nstderr: %s", prefix, got, r.stderr.String())
			}
			got = append(got, l)
			if strings.HasPrefix(l, prefix) {
				return got
			}
		case <-timeout:
			t.Fatalf("no %q within 30s: %v\nstderr: %s", prefix, got, r.stderr.String())
		}
	}
}

// stop cancels the command, as Ctrl-C does, and returns its exit code and
// whatever it printed after.
func (r *running) stop(t *testing.T) (int, []string) {
	t.Helper()
	r.cancel()
	var rest []string
	for l := range r.lines {
		rest = append(rest, l)
	}
	select {
	case code := <-r.done:
		return code, rest
	case <-time.After(30 * time.Second):
		t.Fatal("the command did not stop")
	}
	return 0, nil
}

func resolved(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestStartPrintsTheSettingsAndStops(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(resolved(t, parent), "r")
	r := start(t, "--dir", filepath.Join(parent, "r"))
	lines := r.until(t, "Stop with Ctrl-C")
	out := strings.Join(lines, "\n")
	if !strings.HasPrefix(lines[0], "FarCast rehearsal — commit ") || !strings.Contains(lines[0], "listens on 127.0.0.1") {
		t.Errorf("banner: %q", lines[0])
	}
	for _, want := range []string{
		filepath.Join(dir, "kube", "bin", "kubectl"),
		filepath.Join(dir, "sdk", "bin", "gke-gcloud-auth-plugin"),
		filepath.Join(dir, "sdk", "bin", "gcloud"),
		"farcast configuration directory " + filepath.Join(dir, "config"),
		"gcloud configuration directory  " + filepath.Join(dir, "gcloud"),
		"Instance: rehearsal · gcloud account pinned · scenario healthy",
		filepath.Join(dir, "calls.log"),
		"farcast-rehearsal scenario --dir " + dir,
		"rm -rf " + dir,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the settings text lacks %q:\n%s", want, out)
		}
	}
	code, rest := r.stop(t)
	if code != 0 {
		t.Errorf("exit %d, stderr: %s", code, r.stderr.String())
	}
	if !slices.ContainsFunc(rest, func(l string) bool { return strings.HasPrefix(l, "stopped; remove "+dir) }) {
		t.Errorf("after stopping: %v", rest)
	}
	if _, err := os.Stat(filepath.Join(dir, "rehearsal.json")); err != nil {
		t.Errorf("stopping removed the rehearsal: %v", err)
	}
}

func TestScenarioCommandLine(t *testing.T) {
	ctx := t.Context()
	var out, errb bytes.Buffer
	if code := run(ctx, []string{"scenario", "--dir", t.TempDir(), "no-such-scenario"}, nil, &out, &errb); code != 2 {
		t.Errorf("an unknown scenario exited %d, want 2: %s", code, errb.String())
	}
	if code := run(ctx, []string{"scenario", "sealed"}, nil, &out, &errb); code != 2 {
		t.Errorf("a scenario with no --dir exited %d, want 2", code)
	}
	if code := run(ctx, []string{"scenario", "--dir", t.TempDir(), "sealed"}, nil, &out, &errb); code != 1 {
		t.Errorf("a scenario for a directory with no rehearsal exited %d, want 1", code)
	}
	if code := run(ctx, []string{"--scenario", "no-such-scenario"}, nil, &out, &errb); code != 2 {
		t.Errorf("start with an unknown scenario exited %d, want 2", code)
	}
	if code := run(ctx, []string{"--no-such-flag"}, nil, &out, &errb); code != 2 {
		t.Errorf("an unknown flag exited %d, want 2", code)
	}
}

// A scenario name where a command goes is not just "unknown command": it
// says the scenario command that switches to it (phase 7, F7), with the
// directory filled in when --dir was given, and starts nothing.
func TestAScenarioNameAsACommandSaysHowToSwitch(t *testing.T) {
	ctx := t.Context()
	for _, name := range rehearsal.Scenarios() {
		var out, errb bytes.Buffer
		if code := run(ctx, []string{name}, nil, &out, &errb); code != 2 {
			t.Errorf("%s: exit %d, want 2", name, code)
		}
		want := "farcast-rehearsal scenario --dir <dir> " + name + "\n"
		if !strings.Contains(errb.String(), want) || strings.Contains(errb.String(), "unknown command") {
			t.Errorf("%s: stderr %q, want it to hold %q", name, errb.String(), want)
		}
		if out.Len() != 0 {
			t.Errorf("%s: stdout %q", name, out.String())
		}
	}

	dir := filepath.Join(t.TempDir(), "a rehearsal")
	var out, errb bytes.Buffer
	if code := run(ctx, []string{"--dir", dir, rehearsal.ScenarioSealed}, nil, &out, &errb); code != 2 {
		t.Errorf("with --dir: exit %d, want 2", code)
	}
	want := "farcast-rehearsal scenario --dir " + rehearsal.ShellQuote(dir) + " sealed\n"
	if !strings.Contains(errb.String(), want) || strings.Contains(errb.String(), "<dir>") {
		t.Errorf("with --dir: stderr %q, want it to hold %q", errb.String(), want)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("a scenario name as a command made its directory: %v", err)
	}

	// Any other word is still an unknown command.
	errb.Reset()
	if code := run(ctx, []string{"no-such-command"}, nil, &out, &errb); code != 2 ||
		!strings.Contains(errb.String(), `unknown command "no-such-command"`) {
		t.Errorf("an unknown word: exit %d, %q", code, errb.String())
	}
}

func TestSummarizeCommand(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "internal", "cli", "testdata", "world", "healthy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run(t.Context(), []string{"summarize"}, bytes.NewReader(data), &out, &errb); code != 0 {
		t.Fatalf("summarize exited %d: %s", code, errb.String())
	}
	if s := out.String(); !strings.Contains(s, "schema 1") || strings.Contains(s, "atlas") || strings.Contains(s, "stripe") {
		t.Errorf("summary:\n%s", s)
	}
	if code := run(t.Context(), []string{"summarize", "extra"}, nil, &out, &errb); code != 2 {
		t.Errorf("summarize with an argument exited %d, want 2", code)
	}
}

// TestFarcastIsCheckedWithTheAppsVersionArgv: --farcast runs exactly the
// app's version argv, with <config> the rehearsal's own configuration
// directory, and an environment of HOME and PATH alone — so it never reads
// $FARCAST_CONFIG_HOME or the operator's real farcast directory.
func TestFarcastIsCheckedWithTheAppsVersionArgv(t *testing.T) {
	stubDir := filepath.Join(t.TempDir(), "stub")
	if err := os.Mkdir(stubDir, 0o700); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	stub := filepath.Join(stubDir, "farcast")
	if err := os.Symlink(exe, stub); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FARCAST_CONFIG_HOME", filepath.Join(t.TempDir(), "never-read"))
	parent := t.TempDir()
	dir := filepath.Join(resolved(t, parent), "r")

	r := start(t, "--dir", filepath.Join(parent, "r"), "--farcast", stub)
	lines := r.until(t, "Stop with Ctrl-C")
	if code, _ := r.stop(t); code != 0 {
		t.Fatalf("exit %d: %s", code, r.stderr.String())
	}

	data, err := os.ReadFile(filepath.Join(stubDir, "seen"))
	if err != nil {
		t.Fatalf("the stub was never run: %v\nstderr: %s", err, r.stderr.String())
	}
	var got seen
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	argvData, err := os.ReadFile(filepath.Join("..", "..", "internal", "cli", "testdata", "app", "argv.json"))
	if err != nil {
		t.Fatalf("the app's argv vector: %v", err)
	}
	var argv struct {
		Version []string `json:"version"`
	}
	if err := json.Unmarshal(argvData, &argv); err != nil {
		t.Fatal(err)
	}
	want := slices.Clone(argv.Version)
	for i, a := range want {
		if a == "<config>" {
			want[i] = filepath.Join(dir, "config")
		}
	}
	if !slices.Equal(got.Args, want) {
		t.Errorf("farcast was run with %q, want %q", got.Args, want)
	}
	names := make([]string, 0, len(got.Env))
	for k := range got.Env {
		names = append(names, k)
	}
	sort.Strings(names)
	if !slices.Equal(names, []string{"HOME", "PATH"}) || got.Env["HOME"] != dir || got.Env["PATH"] != "/usr/bin:/bin" {
		t.Errorf("farcast's environment: %v", got.Env)
	}
	if !strings.Contains(strings.Join(lines, "\n"), resolved(t, stub)) {
		t.Errorf("the settings text does not name the farcast given:\n%s", strings.Join(lines, "\n"))
	}
	// The stub reports another commit than the harness's: a warning, and
	// the rehearsal still started.
	if !strings.Contains(r.stderr.String(), "warning:") {
		t.Errorf("no warning for a commit that differs: %s", r.stderr.String())
	}
}
