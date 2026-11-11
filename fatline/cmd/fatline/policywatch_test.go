package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sofmon/farcast/fatline/policy"
)

// lockedBuffer is a log destination the watcher goroutine and the test both
// touch.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// waitFor polls buf for want, calling nudge (when set) every 20ms meanwhile.
func waitFor(t *testing.T, buf *lockedBuffer, want string, nudge func()) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for i := 0; !strings.Contains(buf.String(), want); i++ {
		if time.Now().After(deadline) {
			t.Fatalf("no %q within 5s:\n%s", want, buf.String())
		}
		if nudge != nil && i%10 == 0 {
			nudge()
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// The reload line carries a timestamp, like the decision lines beside it on the
// same stream: the 2026-11-10 walk could not time a reload's propagation
// across replicas from an untimestamped Fprintf.
func TestPolicyReloadIsTimestamped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	// A fresh one-application document each call: the watcher's first read
	// may land after any one write, so the test writes until it sees a reload.
	write := func() {
		c, err := policy.NewCredential()
		if err != nil {
			t.Fatal(err)
		}
		d := &policy.Document{Version: policy.Version, Apps: []policy.App{{Name: "web", Namespace: "demo", CredentialSHA256: policy.HashCredential(c)}}}
		data, err := d.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	buf := &lockedBuffer{}
	var mu sync.Mutex
	var got *policy.Document
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		watchPolicy(ctx, path, 2*time.Millisecond, func(doc *policy.Document) {
			mu.Lock()
			got = doc
			mu.Unlock()
		}, slog.New(slog.NewTextHandler(buf, nil)))
	}()
	defer func() { cancel(); <-done }()

	waitFor(t, buf, "reloaded", write)
	if !regexp.MustCompile(`(?m)^time=\S+ level=INFO msg="fatline: egress policy reloaded" applications=1$`).MatchString(buf.String()) {
		t.Errorf("the reload line is not a timestamped log record:\n%s", buf.String())
	}
	mu.Lock()
	if got == nil || len(got.Apps) != 1 {
		t.Errorf("the reloaded policy was not handed over: %+v", got)
	}
	mu.Unlock()

	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, buf, "refusing", nil)
	if !regexp.MustCompile(`(?m)^time=\S+ level=WARN msg="fatline: refusing an unreadable egress policy, keeping the previous one" err=`).MatchString(buf.String()) {
		t.Errorf("the refusal line is not a timestamped warning:\n%s", buf.String())
	}
}
