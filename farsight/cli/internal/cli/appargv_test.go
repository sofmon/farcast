package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// testdata/app/argv.json is every command line the FarCast app runs: the
// three commands, their flags fixed, with <config> and <instance> to fill in
// (ADR 0021 decision 9 and Verification 5). The app's tests decode a copy of
// it and hold its reader to exactly these words; this test holds this CLI to
// them, so the two can only drift apart by failing one side's tests.
//
// The file is written by hand, not by a vector test: it is what the app
// sends, and the CLI is what must accept it.

// appArgv reads argv.json.
func appArgv(t *testing.T) map[string][]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "app", "argv.json"))
	if err != nil {
		t.Fatal(err)
	}
	var argv map[string][]string
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&argv); err != nil {
		t.Fatalf("argv.json: %v", err)
	}
	if len(argv) != 3 || argv["version"] == nil || argv["instances"] == nil || argv["world"] == nil {
		t.Fatalf("argv.json holds %v; the app runs exactly version, instances and world", argv)
	}
	return argv
}

// filled is argv with <config> and <instance> put in.
func filled(argv []string, config, instance string) []string {
	out := make([]string, 0, len(argv))
	for _, word := range argv {
		switch word {
		case "<config>":
			word = config
		case "<instance>":
			word = instance
		}
		out = append(out, word)
	}
	return out
}

func TestTheAppsArgvIsTheCLIs(t *testing.T) {
	argv := appArgv(t)
	dir := vectorConfigDir(t)
	installedInstance(t, dir, "atlas") // no gcloud account pinned
	// Never the operator's own gcloud directory, though nothing here should
	// reach it: an unpinned instance is refused before it is looked for.
	t.Setenv("CLOUDSDK_CONFIG", t.TempDir())

	runApp := func(t *testing.T, args []string) ([]byte, int) {
		t.Helper()
		var out, errb bytes.Buffer
		code := run(context.Background(), append([]string{"farcast"}, args...), nil, &out, &errb)
		if errb.Len() != 0 {
			t.Errorf("farcast %v wrote to stderr:\n%s", args, errb.Bytes())
		}
		return out.Bytes(), code
	}
	envelope := func(t *testing.T, out []byte) (kind string, code int) {
		t.Helper()
		var env struct {
			Error *struct {
				Message string `json:"message"`
				Code    int    `json:"code"`
				Kind    string `json:"kind"`
			} `json:"error"`
		}
		if err := json.Unmarshal(out, &env); err != nil || env.Error == nil {
			t.Fatalf("not an error envelope (%v):\n%s", err, out)
		}
		return env.Error.Kind, env.Error.Code
	}

	t.Run("version", func(t *testing.T) {
		out, code := runApp(t, filled(argv["version"], dir.Path(), ""))
		if code != 0 {
			t.Fatalf("exit %d:\n%s", code, out)
		}
		var v struct {
			Version string `json:"version"`
			Commit  string `json:"commit"`
		}
		if err := json.Unmarshal(out, &v); err != nil {
			t.Fatalf("%v:\n%s", err, out)
		}
		if v.Version == "" || v.Commit == "" {
			t.Fatalf("version printed no version or no commit:\n%s", out)
		}
	})

	t.Run("instances", func(t *testing.T) {
		out, code := runApp(t, filled(argv["instances"], dir.Path(), ""))
		if code != 0 {
			t.Fatalf("exit %d:\n%s", code, out)
		}
		var doc struct {
			Schema    int `json:"schema"`
			Instances []struct {
				Name string `json:"name"`
			} `json:"instances"`
		}
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatalf("%v:\n%s", err, out)
		}
		if doc.Schema != worldSchema || len(doc.Instances) != 1 || doc.Instances[0].Name != "atlas" {
			t.Fatalf("instances printed schema %d and %+v, not schema %d and atlas:\n%s", doc.Schema, doc.Instances, worldSchema, out)
		}
	})

	t.Run("world, refused before any kubectl", func(t *testing.T) {
		out, code := runApp(t, filled(argv["world"], dir.Path(), "atlas"))
		if code != 1 {
			t.Fatalf("exit %d, want 1:\n%s", code, out)
		}
		if kind, ecode := envelope(t, out); kind != kindGCloudMismatch || ecode != 1 {
			t.Fatalf("kind %q (code %d), want %q: an unpinned instance is read as no one", kind, ecode, kindGCloudMismatch)
		}
	})

	t.Run("world, -- ends the flags", func(t *testing.T) {
		// An instance named like a flag is a name, so it is not found,
		// rather than parsed as -o and leaving world with no argument.
		out, code := runApp(t, filled(argv["world"], dir.Path(), "-o"))
		if code != 1 {
			t.Fatalf("exit %d, want 1:\n%s", code, out)
		}
		if kind, _ := envelope(t, out); kind != kindNotFound {
			t.Fatalf("kind %q, want %q", kind, kindNotFound)
		}
	})
}
