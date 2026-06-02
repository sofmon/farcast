package farcast

import (
	"context"
	"encoding/hex"
	"testing"
)

func TestWithRequestIDRoundTrip(t *testing.T) {
	ctx := WithRequestID(context.Background(), "req-123")
	if got := RequestID(ctx); got != "req-123" {
		t.Fatalf("RequestID = %q, want %q", got, "req-123")
	}
}

func TestRequestIDAbsent(t *testing.T) {
	if got := RequestID(context.Background()); got != "" {
		t.Fatalf("RequestID on bare context = %q, want empty", got)
	}
}

func TestNewRequestIDFormat(t *testing.T) {
	id := NewRequestID()
	if len(id) != 32 {
		t.Fatalf("NewRequestID length = %d, want 32", len(id))
	}
	if _, err := hex.DecodeString(id); err != nil {
		t.Fatalf("NewRequestID is not valid hex: %v", err)
	}
}

func TestNewRequestIDUnique(t *testing.T) {
	const n = 1000
	seen := make(map[string]struct{}, n)
	for range n {
		id := NewRequestID()
		if _, dup := seen[id]; dup {
			t.Fatalf("NewRequestID produced a duplicate: %s", id)
		}
		seen[id] = struct{}{}
	}
}
