package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/buildinfo"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
)

// Vectors made by running the commands themselves, against a config directory
// written for the test: 'instances', 'version', and the whole-command error
// envelope 'world' prints for an instance this machine does not hold. Every
// path in them is relative, so they are the same bytes on every machine.

func vectorConfigDir(t *testing.T) config.Dir {
	t.Helper()
	dir := config.Dir(filepath.Join(t.TempDir(), "farcast"))
	if err := dir.Ensure(); err != nil {
		t.Fatal(err)
	}
	return dir
}

// writeRecord writes an instance's metadata.yaml and nothing else.
func writeRecord(t *testing.T, dir config.Dir, meta *config.InstanceMetadata) {
	t.Helper()
	if err := dir.CreateInstance(meta.Name); err != nil {
		t.Fatal(err)
	}
	if err := dir.SaveInstanceMetadata(meta.Name, meta); err != nil {
		t.Fatal(err)
	}
}

func instancesVectorCommand() *instancesCommand {
	return &instancesCommand{
		now:   func() time.Time { return vectorNow.Add(123456789) },
		stamp: func() buildStamp { return vectorStamp },
	}
}

func runInstancesJSON(t *testing.T, dir config.Dir) []byte {
	t.Helper()
	env, out := testEnv(dir, output.ModeJSON)
	if err := instancesVectorCommand().Run(context.Background(), env, nil); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestInstancesVectors(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		checkVector(t, "instances", "empty", runInstancesJSON(t, vectorConfigDir(t)))
	})
	t.Run("unreadable", func(t *testing.T) {
		dir := vectorConfigDir(t)
		meta := vectorMeta()
		meta.Keepers = append(meta.Keepers, config.Keeper{Device: "old-laptop", Revoked: true})
		writeRecord(t, dir, meta)
		// atlas's reader is granted, so its key is on this machine; instances
		// tells that by the file's presence, and never reads it.
		if err := dir.SaveReaderKey(meta.Name, []byte("not read"), []byte("not read")); err != nil {
			t.Fatal(err)
		}
		plain := &config.InstanceMetadata{Name: "lab", Provider: "gke", Project: "proj-lab", Region: "us-central1",
			Cluster: "farcast-lab", Status: config.InstanceProvisioning,
			CostLimit: config.CostLimit{Amount: 12.5, Currency: "USD", Period: "monthly"}}
		writeRecord(t, dir, plain)
		if err := dir.CreateInstance("broken"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir.InstancePath("broken"), "metadata.yaml"), []byte("name: [broken\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := dir.CreateInstance("empty"); err != nil { // a directory with no record in it
			t.Fatal(err)
		}
		got := runInstancesJSON(t, dir)
		if bytes.Contains(got, []byte(dir.Path())) {
			t.Fatalf("the listing names the config directory's absolute path:\n%s", got)
		}
		for _, secret := range []string{"proj-atlas", "proj-lab", "farcast-atlas", "203.0.113.7", "gke.goog", meta.Reader.Email, meta.Reader.KeyID} {
			if bytes.Contains(got, []byte(secret)) {
				t.Errorf("the listing carries %q:\n%s", secret, got)
			}
		}
		checkVector(t, "instances", "unreadable", got)
	})
}

func TestVersionVector(t *testing.T) {
	env, out := testEnv(config.Dir(t.TempDir()), output.ModeJSON)
	c := versionCommand{info: func() buildinfo.Info {
		return buildinfo.Info{Version: vectorStamp.Version, Commit: vectorStamp.Commit, Date: "2026-11-12T09:00:00Z"}
	}}
	if err := c.Run(context.Background(), env, nil); err != nil {
		t.Fatal(err)
	}
	// The app decodes {version, commit} and nothing else from 'farcast
	// version': the Go version, the OS and the architecture change with the
	// build, so the vector is those two fields as the command printed them.
	var full map[string]any
	if err := json.Unmarshal(out.Bytes(), &full); err != nil {
		t.Fatal(err)
	}
	if full["version"] != vectorStamp.Version || full["commit"] != vectorStamp.Commit {
		t.Fatalf("version printed %s", out.Bytes())
	}
	checkVector(t, "version", "version", vectorBytes(t, versionStamp{Version: full["version"].(string), Commit: full["commit"].(string)}))
}

// versionStamp is the slice of 'farcast version' the app reads.
type versionStamp struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

func (versionStamp) Human(w io.Writer) error { return nil }

// runRouter runs the whole CLI the way a process does, and returns stdout and
// the exit code.
func runRouter(t *testing.T, args ...string) ([]byte, int) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), append([]string{"farcast"}, args...), strings.NewReader(""), &out, &errb)
	return out.Bytes(), code
}

func TestWorldErrorVectors(t *testing.T) {
	t.Run("not_found", func(t *testing.T) {
		got, code := runRouter(t, "--config", vectorConfigDir(t).Path(), "-o", "json", "world", "nowhere")
		if code != 1 {
			t.Fatalf("exit %d, want 1:\n%s", code, got)
		}
		checkVector(t, "world", "error_not_found", got)
	})
}
