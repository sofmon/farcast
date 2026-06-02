package farcast

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestStorageStubNotImplemented(t *testing.T) {
	s := Storage()
	ctx := context.Background()
	if _, err := s.Read(ctx, "k"); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("Read err = %v, want ErrNotImplemented", err)
	}
	if err := s.Write(ctx, "k", nil); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("Write err = %v, want ErrNotImplemented", err)
	}
	if _, err := s.List(ctx, ""); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("List err = %v, want ErrNotImplemented", err)
	}
	if err := s.Delete(ctx, "k"); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("Delete err = %v, want ErrNotImplemented", err)
	}
}

func TestNetStubDeniesAndReportsNotImplemented(t *testing.T) {
	n := Net()
	if _, err := n.Status(context.Background()); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("Status err = %v, want ErrNotImplemented", err)
	}
	c := n.HTTPClient()
	if c == nil {
		t.Fatal("HTTPClient returned nil")
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	// The stub transport must refuse rather than reach the network, so that
	// no traffic can bypass the not-yet-present FatLine boundary.
	if _, err := c.Do(req); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("Do err = %v, want it to wrap ErrNotImplemented", err)
	}
}

func TestAIStubNotImplemented(t *testing.T) {
	a := AI()
	if _, err := a.Chat(context.Background(), ChatRequest{}); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("Chat err = %v, want ErrNotImplemented", err)
	}
	if _, err := a.ChatStream(context.Background(), ChatRequest{}); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("ChatStream err = %v, want ErrNotImplemented", err)
	}
}

func TestConfigStub(t *testing.T) {
	c := Config()
	if v, ok := c.Get("x"); ok || v != "" {
		t.Errorf("Get = (%q, %v), want empty/false", v, ok)
	}
	if v := c.GetString("x", "def"); v != "def" {
		t.Errorf("GetString = %q, want def", v)
	}
	if v := c.GetInt("x", 7); v != 7 {
		t.Errorf("GetInt = %d, want 7", v)
	}
	if !c.GetBool("x", true) {
		t.Error("GetBool = false, want true")
	}
	if _, err := c.Require("x"); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("Require err = %v, want ErrNotImplemented", err)
	}
}
