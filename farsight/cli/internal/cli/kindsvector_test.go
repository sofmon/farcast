package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// The error kinds as a vector. The FarCast app maps each wire kind to its
// own, and its tests decode this file to prove that every kind the CLI can
// send maps to one the app knows: a kind added here and not there fails the
// app's tests, not an operator's read.
func TestKindsVector(t *testing.T) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(struct {
		Kinds []string `json:"kinds"`
	}{errorKinds}); err != nil {
		t.Fatal(err)
	}
	checkVector(t, "kinds", "kinds", buf.Bytes())
}

// Every file under the vector directories the app copies is one a vector
// test writes. A file left behind by a renamed or removed vector would still
// be copied into the app's tests, which would then hold the app to a
// document this CLI no longer prints.
func TestEveryVectorFileIsProduced(t *testing.T) {
	produced := map[string]bool{
		"instances/empty.json":             true, // TestInstancesVectors
		"instances/unreadable.json":        true,
		"version/version.json":             true, // TestVersionVector
		"kinds/kinds.json":                 true, // TestKindsVector
		"world/error_gcloud_mismatch.json": true, // TestWorldErrorVectors
		"world/error_not_found.json":       true,
	}
	for _, v := range worldVectors() { // TestWorldVectors
		produced["world/"+v.name+".json"] = true
	}
	found := map[string]bool{}
	for _, dir := range []string{"world", "instances", "version", "kinds"} {
		entries, err := os.ReadDir(filepath.Join("testdata", dir))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.Name() == ".DS_Store" { // Finder's, never Go's; check.sh ignores it too
				continue
			}
			name := dir + "/" + e.Name()
			found[name] = true
			if !produced[name] {
				t.Errorf("testdata/%s is not written by any vector test; remove it, or add the test that writes it", name)
			}
		}
	}
	var missing []string
	for name := range produced {
		if !found[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	for _, name := range missing {
		t.Errorf("testdata/%s is missing (run with %s=1 to write it)", name, updateVectorsEnv)
	}
}
