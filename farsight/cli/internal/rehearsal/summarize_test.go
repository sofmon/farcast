package rehearsal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// A18-18, mutation O45: errorKinds is a hand copy of the CLI's closed set,
// which rehearsal cannot import. It is the kinds vector's list exactly, in
// its order, so it cannot drift from the CLI's in either direction.
func TestErrorKindsAreTheCLIs(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "cli", "testdata", "kinds", "kinds.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Kinds []string `json:"kinds"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(errorKinds, v.Kinds) {
		t.Errorf("summarize knows %q, the CLI sends %q", errorKinds, v.Kinds)
	}
}
