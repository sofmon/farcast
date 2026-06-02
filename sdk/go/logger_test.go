package farcast

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

func decodeLast(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	trimmed := bytes.TrimSpace(buf.Bytes())
	if len(trimmed) == 0 {
		t.Fatal("no log output")
	}
	lines := bytes.Split(trimmed, []byte("\n"))
	var m map[string]any
	if err := json.Unmarshal(lines[len(lines)-1], &m); err != nil {
		t.Fatalf("decode log line: %v", err)
	}
	return m
}

func TestRecordShape(t *testing.T) {
	var buf bytes.Buffer
	log := newLogger(&buf, slog.LevelInfo, false, "farcast-one", "api")
	ctx := WithRequestID(context.Background(), "req-abc")

	log.Info(ctx, "service starting", "version", "1.4.2")

	rec := decodeLast(t, &buf)
	want := map[string]any{
		"level":      "info",
		"msg":        "service starting",
		"instance":   "farcast-one",
		"app":        "api",
		"request_id": "req-abc",
		"version":    "1.4.2",
	}
	for k, v := range want {
		if rec[k] != v {
			t.Errorf("record[%q] = %v, want %v", k, rec[k], v)
		}
	}
	ts, ok := rec["time"].(string)
	if !ok {
		t.Fatalf("time missing or not a string: %v", rec["time"])
	}
	if _, err := time.Parse(time.RFC3339Nano, ts); err != nil {
		t.Errorf("time %q is not RFC3339Nano: %v", ts, err)
	}
	if !strings.HasSuffix(ts, "Z") {
		t.Errorf("time %q is not UTC", ts)
	}
}

func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	log := newLogger(&buf, slog.LevelWarn, false, "i", "a")
	ctx := context.Background()

	log.Debug(ctx, "debug-line")
	log.Info(ctx, "info-line")
	log.Warn(ctx, "warn-line")
	log.Error(ctx, "error-line")

	out := buf.String()
	if strings.Contains(out, "debug-line") || strings.Contains(out, "info-line") {
		t.Errorf("below-threshold records leaked:\n%s", out)
	}
	if !strings.Contains(out, "warn-line") || !strings.Contains(out, "error-line") {
		t.Errorf("at/above-threshold records missing:\n%s", out)
	}
}

func TestRequestIDAbsentNotEmitted(t *testing.T) {
	var buf bytes.Buffer
	log := newLogger(&buf, slog.LevelInfo, false, "i", "a")

	log.Info(context.Background(), "no-request-scope")

	rec := decodeLast(t, &buf)
	if _, ok := rec["request_id"]; ok {
		t.Errorf("request_id present without a scoped context: %v", rec["request_id"])
	}
}

func TestWithChild(t *testing.T) {
	var buf bytes.Buffer
	parent := newLogger(&buf, slog.LevelInfo, false, "i", "a")
	child := parent.With("component", "scheduler")

	child.Warn(context.Background(), "queue backpressure", "depth", 42)

	rec := decodeLast(t, &buf)
	if rec["component"] != "scheduler" {
		t.Errorf("component = %v, want scheduler", rec["component"])
	}
	if rec["level"] != "warn" {
		t.Errorf("level = %v, want warn", rec["level"])
	}
	if rec["depth"] != float64(42) {
		t.Errorf("depth = %v, want 42", rec["depth"])
	}
}

func TestSourceEnabled(t *testing.T) {
	var buf bytes.Buffer
	log := newLogger(&buf, slog.LevelInfo, true, "i", "a")

	log.Info(context.Background(), "with-source")

	rec := decodeLast(t, &buf)
	src, ok := rec["source"].(string)
	if !ok {
		t.Fatalf("source missing or not a string: %v", rec["source"])
	}
	if !strings.Contains(src, "logger_test.go:") {
		t.Errorf("source = %q, want it to point at the caller (logger_test.go)", src)
	}
}

func TestSetLogWriterRoutesAndRestores(t *testing.T) {
	var outer bytes.Buffer
	restoreOuter := SetLogWriter(&outer)
	defer restoreOuter()

	var inner bytes.Buffer
	restoreInner := SetLogWriter(&inner)
	Log().Info(context.Background(), "via-inner")
	restoreInner()

	Log().Info(context.Background(), "after-restore")

	if !strings.Contains(inner.String(), "via-inner") {
		t.Errorf("inner writer missing its record:\n%s", inner.String())
	}
	if strings.Contains(inner.String(), "after-restore") {
		t.Errorf("inner writer received a record after restore:\n%s", inner.String())
	}
	if !strings.Contains(outer.String(), "after-restore") {
		t.Errorf("restore did not return to the previous writer:\n%s", outer.String())
	}
}

func TestConcurrentUse(t *testing.T) {
	restore := SetLogWriter(io.Discard)
	defer restore()
	log := Log()

	var wg sync.WaitGroup
	for i := range 64 {
		wg.Go(func() {
			ctx := WithRequestID(context.Background(), NewRequestID())
			log.Info(ctx, "concurrent", "i", i)
		})
	}
	wg.Go(func() {
		for range 16 {
			SetLogWriter(io.Discard)()
		}
	})
	wg.Wait()
}
