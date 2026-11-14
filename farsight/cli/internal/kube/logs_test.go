package kube_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
)

// buildPod is one Job pod with a log, and a previous instance's log for one
// container.
func buildPod(s *kubetest.Server) {
	s.Put(obj("v1", "Pod", "web", "build-abc", map[string]any{
		"metadata": map[string]any{"annotations": map[string]any{
			kubetest.LogAnnotationPrefix + "build":         "one\ntwo\nthree\n",
			kubetest.LogAnnotationPrefix + "proxy":         "p\n",
			kubetest.PreviousLogAnnotationPrefix + "build": "before the restart\n",
		}},
		"spec": map[string]any{"containers": []any{map[string]any{"name": "build"}, map[string]any{"name": "proxy"}}},
	}))
}

// TestJobLogsAllLinesSendsNoTailLines pins the wire of "every line": TailLines
// < 0 sends no tailLines parameter at all, as the API defines everything and
// as kubectl v0.37.2 omits it for -1; kubetest answers a negative tailLines
// with 400. A count is sent as a decimal integer, 0 included.
func TestJobLogsAllLinesSendsNoTailLines(t *testing.T) {
	s := kubetest.New(t)
	buildPod(s)
	c, _ := connect(t, s, "reader")
	ctx := t.Context()

	var all strings.Builder
	if err := c.StreamLog(ctx, "web", "build-abc", kube.LogOptions{Container: "build", TailLines: -1}, &all); err != nil {
		t.Fatalf("every line: %v", err)
	}
	if all.String() != "one\ntwo\nthree\n" {
		t.Errorf("every line = %q", all.String())
	}
	r := last(t, s)
	q := query(t, r)
	if r.Method != http.MethodGet || r.Path != "/api/v1/namespaces/web/pods/build-abc/log" || q.Has("tailLines") ||
		q.Get("container") != "build" || q.Has("follow") || q.Has("previous") {
		t.Errorf("every line sent %s %s?%s; want no tailLines", r.Method, r.Path, r.RawQuery)
	}

	for _, tc := range []struct {
		tail int
		want string
	}{{2, "two\nthree\n"}, {0, ""}, {10, "one\ntwo\nthree\n"}} {
		var out strings.Builder
		if err := c.StreamLog(ctx, "web", "build-abc", kube.LogOptions{Container: "build", TailLines: tc.tail}, &out); err != nil {
			t.Fatalf("tail %d: %v", tc.tail, err)
		}
		if out.String() != tc.want {
			t.Errorf("tail %d = %q, want %q", tc.tail, out.String(), tc.want)
		}
		if got := query(t, last(t, s)).Get("tailLines"); got != map[int]string{2: "2", 0: "0", 10: "10"}[tc.tail] {
			t.Errorf("tail %d sent tailLines=%q", tc.tail, got)
		}
	}
}

// TestStreamLogPreviousAndFollow: previous reads the previous instance, and
// a container without one is the API server's 400; follow streams until the
// caller's context ends, and returns that context's error.
func TestStreamLogPreviousAndFollow(t *testing.T) {
	s := kubetest.New(t)
	buildPod(s)
	c, _ := connect(t, s, "reader")
	ctx := t.Context()

	var prev strings.Builder
	if err := c.StreamLog(ctx, "web", "build-abc", kube.LogOptions{Container: "build", TailLines: -1, Previous: true}, &prev); err != nil {
		t.Fatal(err)
	}
	if prev.String() != "before the restart\n" || query(t, last(t, s)).Get("previous") != "true" {
		t.Errorf("previous = %q via ?%s", prev.String(), last(t, s).RawQuery)
	}
	err := c.StreamLog(ctx, "web", "build-abc", kube.LogOptions{Container: "proxy", TailLines: -1, Previous: true}, &strings.Builder{})
	var ae *kube.APIError
	if !errors.As(err, &ae) || ae.Status.Code != http.StatusBadRequest {
		t.Errorf("no previous instance: err = %v, want the 400", err)
	}

	fctx, cancel := context.WithCancel(ctx)
	defer cancel()
	w := &signalWriter{want: "one\ntwo\nthree\n", got: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		done <- c.StreamLog(fctx, "web", "build-abc", kube.LogOptions{Container: "build", TailLines: -1, Follow: true}, w)
	}()
	select {
	case <-w.got:
	case <-time.After(10 * time.Second):
		t.Fatal("the followed log never arrived")
	}
	select {
	case err := <-done:
		t.Fatalf("a followed log ended before its context: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("a cancelled follow returned %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a cancelled follow did not return")
	}
	if q := query(t, last(t, s)); q.Get("follow") != "true" {
		t.Errorf("follow sent ?%s", last(t, s).RawQuery)
	}

	failing := errors.New("the writer is full")
	if err := c.StreamLog(ctx, "web", "build-abc", kube.LogOptions{Container: "build", TailLines: -1}, failWriter{failing}); !errors.Is(err, failing) {
		t.Errorf("a failing writer: err = %v, want its own error", err)
	}
}

// signalWriter closes got once it has received want.
type signalWriter struct {
	mu   sync.Mutex
	buf  strings.Builder
	want string
	got  chan struct{}
	once sync.Once
}

func (w *signalWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	if w.buf.String() == w.want {
		w.once.Do(func() { close(w.got) })
	}
	return len(p), nil
}

type failWriter struct{ err error }

func (f failWriter) Write([]byte) (int, error) { return 0, f.err }

// followLog runs a followed StreamLog of build-abc's build container in the
// background, and reports when its lines have arrived and when it returned.
func followLog(t *testing.T, ctx context.Context, c *kube.Client) (got <-chan struct{}, done <-chan error) {
	t.Helper()
	w := &signalWriter{want: "one\ntwo\nthree\n", got: make(chan struct{})}
	d := make(chan error, 1)
	go func() {
		d <- c.StreamLog(ctx, "web", "build-abc", kube.LogOptions{Container: "build", TailLines: -1, Follow: true}, w)
	}()
	return w.got, d
}

// assertFollowRunsUntilCancel: the followed log's lines arrive, it is still
// running a while later, and it returns context.Canceled once cancelled.
func assertFollowRunsUntilCancel(t *testing.T, got <-chan struct{}, done <-chan error, running time.Duration, cancel context.CancelFunc) {
	t.Helper()
	select {
	case <-got:
	case err := <-done:
		t.Fatalf("the followed log ended before its lines arrived: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the followed log never arrived")
	}
	select {
	case err := <-done:
		t.Fatalf("a followed log ended before its context: %v", err)
	case <-time.After(running):
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("a cancelled follow returned %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a cancelled follow did not return")
	}
}

// TestFollowWaitsForAQuietContainer (B-B2-1): the kubelet sends a log's
// headers only with its first line, so a followed log of a container that has
// logged nothing yet has no headers to send. A follow has no
// ResponseHeaderTimeout and is waited for until its caller's context ends; a
// log read that does not follow, and any other request, keeps the bound. The
// bound is shortened here to 100 ms, and kubetest holds each answer 300 ms.
func TestFollowWaitsForAQuietContainer(t *testing.T) {
	s := kubetest.New(t, kubetest.WithDelay(func(r kubetest.Request) time.Duration {
		if r.Path == "/token" {
			return 0
		}
		return 300 * time.Millisecond
	}))
	buildPod(s)
	s.Put(obj("v1", "ConfigMap", "web", "cfg", nil))
	c, _ := connect(t, s, "reader")
	kube.SetResponseHeaderTimeout(c, 100*time.Millisecond)

	fctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	got, done := followLog(t, fctx, c)
	assertFollowRunsUntilCancel(t, got, done, 50*time.Millisecond, cancel)

	err := c.StreamLog(t.Context(), "web", "build-abc", kube.LogOptions{Container: "build", TailLines: -1}, &strings.Builder{})
	if !errors.Is(err, kube.ErrUnreachable) {
		t.Errorf("a log read that does not follow, held past the header bound: err = %v, want ErrUnreachable", err)
	}
	if _, err := c.GetConfigMap(t.Context(), "web", "cfg"); !errors.Is(err, kube.ErrUnreachable) {
		t.Errorf("a GET held past the header bound: err = %v, want ErrUnreachable", err)
	}
}

// TestFollowOutlivesTheRequestDeadline (B-B2-3): a log read is a stream, with
// no per-attempt deadline, so a followed log runs past it until its caller's
// context ends, and one that does not follow is read whole however long its
// answer takes; a GET held as long fails at that deadline. The deadline is
// shortened here to 100 ms, and kubetest holds each answer 300 ms.
func TestFollowOutlivesTheRequestDeadline(t *testing.T) {
	s := kubetest.New(t, kubetest.WithDelay(func(r kubetest.Request) time.Duration {
		if r.Path == "/token" {
			return 0
		}
		return 300 * time.Millisecond
	}))
	buildPod(s)
	s.Put(obj("v1", "ConfigMap", "web", "cfg", nil))
	c, _ := connect(t, s, "reader")
	kube.SetAttemptTimeout(c, 100*time.Millisecond)

	fctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	got, done := followLog(t, fctx, c)
	assertFollowRunsUntilCancel(t, got, done, 300*time.Millisecond, cancel)

	var all strings.Builder
	if err := c.StreamLog(t.Context(), "web", "build-abc", kube.LogOptions{Container: "build", TailLines: -1}, &all); err != nil || all.String() != "one\ntwo\nthree\n" {
		t.Errorf("a log read held past the attempt deadline: %q, %v; want it read whole", all.String(), err)
	}
	if _, err := c.GetConfigMap(t.Context(), "web", "cfg"); !errors.Is(err, kube.ErrUnreachable) || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a GET held past the attempt deadline: err = %v, want ErrUnreachable", err)
	}
}
