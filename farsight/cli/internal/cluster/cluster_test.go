package cluster

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

type fakeRunner struct {
	calls  [][]string
	stdins [][]byte
	out    map[string][]byte // keyed by args[0]
	err    error
}

func (f *fakeRunner) Run(_ context.Context, stdin []byte, args ...string) ([]byte, error) {
	f.calls = append(f.calls, args)
	f.stdins = append(f.stdins, stdin)
	if f.err != nil {
		return nil, f.err
	}
	if f.out != nil {
		return f.out[args[0]], nil
	}
	return nil, nil
}

func TestApplyPipesManifestToStdin(t *testing.T) {
	fr := &fakeRunner{}
	c := NewWithRunner(fr)
	if err := c.Apply(context.Background(), []byte("MANIFEST")); err != nil {
		t.Fatal(err)
	}
	if len(fr.calls) != 1 || !slices.Equal(fr.calls[0], []string{"apply", "-f", "-"}) {
		t.Fatalf("calls=%v, want one [apply -f -]", fr.calls)
	}
	if string(fr.stdins[0]) != "MANIFEST" {
		t.Fatalf("stdin=%q, want MANIFEST", fr.stdins[0])
	}
}

func TestRolloutStatusArgs(t *testing.T) {
	fr := &fakeRunner{}
	c := NewWithRunner(fr)
	if err := c.RolloutStatus(context.Background(), "farcast-system", "fatline", 90*time.Second); err != nil {
		t.Fatal(err)
	}
	want := []string{"rollout", "status", "deployment/fatline", "-n", "farcast-system", "--timeout", "90s"}
	if len(fr.calls) != 1 || !slices.Equal(fr.calls[0], want) {
		t.Fatalf("calls=%v, want %v", fr.calls, want)
	}
}

func TestWaitExternalIPReturnsIP(t *testing.T) {
	fr := &fakeRunner{out: map[string][]byte{"get": []byte("34.0.0.5\n")}}
	c := NewWithRunner(fr)
	ip, err := c.WaitExternalIP(context.Background(), "farcast-system", "fatline", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if ip != "34.0.0.5" {
		t.Fatalf("ip=%q, want 34.0.0.5 (trimmed)", ip)
	}
}

func TestWaitExternalIPTimesOut(t *testing.T) {
	fr := &fakeRunner{out: map[string][]byte{"get": []byte("")}} // never assigned
	c := NewWithRunner(fr)
	// Zero timeout: the first empty read is already past the deadline.
	if _, err := c.WaitExternalIP(context.Background(), "farcast-system", "fatline", 0); err == nil {
		t.Fatal("expected a timeout error when no external IP is assigned")
	}
}

func TestRunnerErrorPropagates(t *testing.T) {
	fr := &fakeRunner{err: errors.New("boom")}
	c := NewWithRunner(fr)
	if err := c.Apply(context.Background(), []byte("x")); err == nil {
		t.Fatal("expected the runner error to propagate")
	}
}
