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
// envelope 'world' prints when its guard refuses. Every path in them is
// relative, so they are the same bytes on every machine.

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
		now:     func() time.Time { return vectorNow.Add(123456789) },
		stamp:   func() buildStamp { return vectorStamp },
		environ: func() []string { return nil },
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
		for _, secret := range []string{"proj-atlas", "proj-lab", "farcast-atlas", "203.0.113.7", "gke.goog", "operator@example.org"} {
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

// fakeGCloudDir writes gcloud's configuration files into a fresh directory:
// one configurations/config_<name> per entry, and active_config naming active.
func fakeGCloudDir(t *testing.T, active string, configs ...gcloudConfig) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "gcloud")
	writeGCloudDir(t, dir, active, configs...)
	return dir
}

func writeGCloudDir(t *testing.T, dir, active string, configs ...gcloudConfig) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "configurations"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, c := range configs {
		var b strings.Builder
		b.WriteString("[core]\n")
		if c.Account != "" {
			b.WriteString("account = " + c.Account + "\n")
		}
		if c.Project != "" {
			b.WriteString("project = " + c.Project + "\n")
		}
		b.WriteString("disable_usage_reporting = True\n\n[compute]\nregion = europe-west4\n")
		if c.Override != "" {
			b.WriteString("\n[auth]\n" + c.Override + " = robot@work-prod.iam.gserviceaccount.com\n")
		}
		if err := os.WriteFile(filepath.Join(dir, "configurations", "config_"+c.Name), []byte(b.String()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if active != "" {
		if err := os.WriteFile(filepath.Join(dir, "active_config"), []byte(active), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// runRouter runs the whole CLI the way a process does, and returns stdout and
// the exit code.
func runRouter(t *testing.T, args ...string) ([]byte, int) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), append([]string{"farcast"}, args...), strings.NewReader(""), &out, &errb)
	return out.Bytes(), code
}

func TestWorldErrorVectors(t *testing.T) {
	t.Run("gcloud_mismatch", func(t *testing.T) {
		dir := vectorConfigDir(t)
		writeRecord(t, dir, vectorMeta())
		t.Setenv("CLOUDSDK_CONFIG", fakeGCloudDir(t, "work",
			gcloudConfig{Name: "work", Account: "someone@work.example", Project: "work-prod"},
			gcloudConfig{Name: "personal", Account: "operator@example.org", Project: "proj-old"},
		))
		got, code := runRouter(t, "--config", dir.Path(), "-o", "json", "world", "atlas")
		if code != 1 {
			t.Fatalf("exit %d, want 1:\n%s", code, got)
		}
		for _, leak := range []string{"someone@work.example", "operator@example.org", dir.Path()} {
			if bytes.Contains(got, []byte(leak)) {
				t.Errorf("the refusal carries %q:\n%s", leak, got)
			}
		}
		checkVector(t, "world", "error_gcloud_mismatch", got)
	})
	t.Run("not_found", func(t *testing.T) {
		got, code := runRouter(t, "--config", vectorConfigDir(t).Path(), "-o", "json", "world", "nowhere")
		if code != 1 {
			t.Fatalf("exit %d, want 1:\n%s", code, got)
		}
		checkVector(t, "world", "error_not_found", got)
	})
}
