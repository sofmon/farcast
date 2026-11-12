package cli

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
)

// 'instances' reads each instance's metadata.yaml and nothing else: no
// credential, no kubeconfig, no mTLS material, no keyring.
func TestInstancesReadsOnlyTheRecords(t *testing.T) {
	dir := config.Dir(t.TempDir())
	connectedInstance(t, dir, "atlas") // credentials, kubeconfig and mTLS on disk beside the record
	var mu sync.Mutex
	var opened []string
	stop := config.ObserveReads(func(p string) {
		mu.Lock()
		defer mu.Unlock()
		opened = append(opened, p)
	})
	defer stop()
	env, out := testEnv(dir, output.ModeHuman)
	if err := instancesVectorCommand().Run(context.Background(), env, nil); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(opened, []string{filepath.Join(dir.InstancePath("atlas"), "metadata.yaml")}) {
		t.Errorf("read %v, want the one record", opened)
	}
	if !strings.Contains(out.String(), "atlas") || !strings.Contains(out.String(), "not pinned") {
		t.Errorf("listing:\n%s", out.String())
	}
}

// An instance directory is named by whoever made it, and a name that would
// act on the terminal is quoted in the human listing.
func TestInstancesHumanQuotesNames(t *testing.T) {
	r := instancesResult{Instances: []instanceEntry{
		{Name: "evil\x1b[2J", Error: &sectionProblem{Kind: kindRecordUnreadable, Message: "x\u202ey"}},
	}}
	var b strings.Builder
	if err := r.Human(&b); err != nil {
		t.Fatal(err)
	}
	if !output.Printable(strings.ReplaceAll(b.String(), "\n", "")) {
		t.Errorf("the listing carries a character that acts on the terminal: %q", b.String())
	}
	b.Reset()
	if err := (instancesResult{}).Human(&b); err != nil || !strings.Contains(b.String(), "No instances") {
		t.Errorf("an empty listing: %q", b.String())
	}
}

func TestHelpListsTheConnectedViewCommands(t *testing.T) {
	out, _, code := runCLI(t, "help")
	if code != 0 || !strings.Contains(out, "instances") || !strings.Contains(out, "world") {
		t.Fatalf("help:\n%s", out)
	}
	for _, cmd := range []string{"instances", "world"} {
		out, _, code := runCLI(t, "help", cmd)
		if code != 0 || !strings.Contains(out, "Usage: farcast "+cmd) {
			t.Errorf("help %s:\n%s", cmd, out)
		}
	}
}
