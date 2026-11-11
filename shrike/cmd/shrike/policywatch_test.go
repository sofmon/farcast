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
	"github.com/sofmon/farcast/manifest/parser"
	"github.com/sofmon/farcast/shrike"
)

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

// Shrike's reload line is timestamped like FatLine's, which it mirrors: a
// reload is timed by comparing the two.
func TestDeclaredContractReloadIsTimestamped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	write := func() {
		c, err := policy.NewCredential()
		if err != nil {
			t.Fatal(err)
		}
		d := &policy.Document{Version: policy.Version, Apps: []policy.App{{
			Name: "web", Namespace: "demo", CredentialSHA256: policy.HashCredential(c),
			External: []parser.External{{Host: "api.example.com", Reason: "test"}},
		}}}
		data, err := d.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	buf := &lockedBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		watchPolicy(ctx, path, 2*time.Millisecond, shrike.New(shrike.Config{}), slog.New(slog.NewTextHandler(buf, nil)))
	}()
	defer func() { cancel(); <-done }()

	wait := func(want string, nudge func()) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for i := 0; !strings.Contains(buf.String(), want); i++ {
			if time.Now().After(deadline) {
				t.Fatalf("no %q within 5s:\n%s", want, buf.String())
			}
			// The watcher's first read may land after any one write.
			if nudge != nil && i%10 == 0 {
				nudge()
			}
			time.Sleep(2 * time.Millisecond)
		}
	}
	wait("reloaded", write)
	if !regexp.MustCompile(`(?m)^time=\S+ level=INFO msg="shrike: declared contract reloaded" applications=1 hosts=1$`).MatchString(buf.String()) {
		t.Errorf("the reload line is not a timestamped log record:\n%s", buf.String())
	}
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	wait("refusing", nil)
	if !regexp.MustCompile(`(?m)^time=\S+ level=WARN msg="shrike: refusing an unreadable egress policy, keeping the previous one" err=`).MatchString(buf.String()) {
		t.Errorf("the refusal line is not a timestamped warning:\n%s", buf.String())
	}
}
