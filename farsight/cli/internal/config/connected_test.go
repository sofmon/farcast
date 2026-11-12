package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// The pinned gcloud account and the per-namespace provenance survive a write
// and a read, and a record written before either loads with both empty.
func TestGCloudAccountAndDeploymentsRoundTrip(t *testing.T) {
	d := testDir(t)
	if err := d.CreateInstance("atlas"); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 12, 9, 30, 0, 0, time.UTC)
	in := &InstanceMetadata{
		Name: "atlas", Provider: "gke", Project: "proj-atlas", Region: "europe-west4",
		Status: InstanceRunning, GCloudAccount: "operator@example.org",
		Deployments: map[string]Deployment{
			"shop": {Repository: "https://github.com/example/shop", Ref: "refs/heads/main",
				Commit: "4f2a9c1e", ManifestDigest: "sha256:ab", DeployedAt: at, StorageWired: true},
		},
	}
	if err := d.SaveInstanceMetadata("atlas", in); err != nil {
		t.Fatal(err)
	}
	got, err := d.LoadInstanceMetadata("atlas")
	if err != nil {
		t.Fatal(err)
	}
	if got.GCloudAccount != in.GCloudAccount {
		t.Errorf("gcloud account = %q", got.GCloudAccount)
	}
	if dep := got.Deployments["shop"]; dep.Repository != "https://github.com/example/shop" || !dep.DeployedAt.Equal(at) || !dep.StorageWired || dep.Commit != "4f2a9c1e" {
		t.Errorf("deployment = %+v", dep)
	}

	raw, err := os.ReadFile(filepath.Join(d.InstancePath("atlas"), "metadata.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "gcloud_account: operator@example.org") || !strings.Contains(string(raw), "deployments:") {
		t.Errorf("the record does not carry the new fields:\n%s", raw)
	}

	old := &InstanceMetadata{Name: "old", Provider: "gke", Region: "us-central1", Status: InstanceRunning}
	if err := d.CreateInstance("old"); err != nil {
		t.Fatal(err)
	}
	if err := d.SaveInstanceMetadata("old", old); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(filepath.Join(d.InstancePath("old"), "metadata.yaml"))
	if strings.Contains(string(raw), "gcloud_account") || strings.Contains(string(raw), "deployments") {
		t.Errorf("an unpinned record with no deployments writes the fields anyway:\n%s", raw)
	}
}

// A record that does not exist is marked as such, and its text and its
// fs.ErrNotExist are what they always were.
func TestAMissingRecordIsMarkedAndReadsAsBefore(t *testing.T) {
	d := testDir(t)
	_, err := d.LoadInstanceMetadata("nowhere")
	if !errors.Is(err, ErrNoInstanceRecord) || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v, want ErrNoInstanceRecord and fs.ErrNotExist", err)
	}
	var pe *fs.PathError
	if !errors.As(err, &pe) || err.Error() != pe.Error() {
		t.Errorf("text = %q, want the path error's own", err.Error())
	}

	// A record that is there and unreadable is not "no record".
	if err := d.CreateInstance("broken"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d.InstancePath("broken"), "metadata.yaml"), []byte("name: [unclosed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := d.LoadInstanceMetadata("broken"); err == nil || errors.Is(err, ErrNoInstanceRecord) {
		t.Errorf("a malformed record: err = %v, want a parse error that is not ErrNoInstanceRecord", err)
	}
}

// The dial identity is three files and never the fourth: it loads with ca.key
// unreadable, and the observer shows ca.key was never opened.
func TestLoadDialIdentityNeverOpensTheCAKey(t *testing.T) {
	d := testDir(t)
	if err := d.CreateInstance("atlas"); err != nil {
		t.Fatal(err)
	}
	m := MTLSMaterial{
		CACertPEM: []byte("ca-cert"), CAKeyPEM: []byte("ca-key"),
		ClientCertPEM: []byte("client-cert"), ClientKeyPEM: []byte("client-key"),
		ServerCertPEM: []byte("server-cert"), ServerKeyPEM: []byte("server-key"),
	}
	if err := d.SaveInstanceMTLS("atlas", m); err != nil {
		t.Fatal(err)
	}
	caKey := filepath.Join(d.InstancePath("atlas"), "fatline", "ca.key")
	if err := os.Chmod(caKey, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(caKey, 0o600) })

	var mu sync.Mutex
	var read []string
	stop := ObserveReads(func(p string) {
		mu.Lock()
		defer mu.Unlock()
		read = append(read, p)
	})
	defer stop()

	id, err := d.LoadDialIdentity("atlas")
	if err != nil {
		t.Fatal(err)
	}
	if string(id.CACertPEM) != "ca-cert" || string(id.ClientCertPEM) != "client-cert" || string(id.ClientKeyPEM) != "client-key" {
		t.Errorf("identity = %q / %q / %q", id.CACertPEM, id.ClientCertPEM, id.ClientKeyPEM)
	}
	mu.Lock()
	defer mu.Unlock()
	if slices.Contains(read, caKey) {
		t.Errorf("the dial identity opened %s", caKey)
	}
	if len(read) != 3 {
		t.Errorf("read %v, want exactly the three dial files", read)
	}
}

// A record that does not parse is described by the kind of fault and its
// line, never in the parser's words: those quote the lines around the fault,
// and some of them quote a value, and a record holds the project, the
// endpoints and the pinned account.
func TestParseFaultNeverQuotesTheRecord(t *testing.T) {
	d := testDir(t)
	if err := d.CreateInstance("atlas"); err != nil {
		t.Fatal(err)
	}
	full := &InstanceMetadata{
		Name: "atlas", Provider: "gke", Project: "proj-secret-7", Region: "europe-west4",
		Endpoint: "gke-9z8y.europe-west4.gke.goog", Status: InstanceRunning, GCloudAccount: "operator@example.org",
		Carrier: &Carrier{Type: "nlb", Endpoint: "203.0.113.9:443", ServerName: "fatline.atlas.farcast"},
	}
	if err := d.SaveInstanceMetadata("atlas", full); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(d.InstancePath("atlas"), "metadata.yaml")
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	secrets := []string{"proj-secret-7", "gke-9z8y", "203.0.113.9", "operator@example.org", "fatline.atlas.farcast"}

	for _, tc := range []struct {
		name   string
		broken string
		says   string
	}{
		// A syntax error right after the account: the parser's own text
		// shows the lines around it, the account and the project among them.
		{"syntax", strings.Replace(string(good), "gcloud_account: operator@example.org\n",
			"gcloud_account: operator@example.org\nbroken: [unclosed\n", 1), "a YAML syntax error at line "},
		// A value of the wrong type: the parser's own text quotes the line
		// that holds it, and the lines before.
		{"wrong type", string(good) + "fatline_deployed: operator@example.org\n", "a value of the wrong type at line "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tc.broken), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := d.LoadInstanceMetadata("atlas")
			if err == nil {
				t.Fatal("a broken record loaded")
			}
			// Guard: the parser's own text does quote the record, or this
			// test would prove nothing.
			if !strings.Contains(err.Error(), "operator@example.org") {
				t.Fatalf("the parser's text no longer quotes the record; the case proves nothing: %v", err)
			}
			fault, ok := ParseFault(err)
			if !ok || !strings.Contains(fault, tc.says) {
				t.Fatalf("ParseFault = %q, %v; want it to say %q (from %v)", fault, ok, tc.says, err)
			}
			for _, s := range secrets {
				if strings.Contains(fault, s) {
					t.Errorf("the fault quotes the record (%q): %s", s, fault)
				}
			}
		})
	}
	if _, ok := ParseFault(errors.New("not a parse failure")); ok {
		t.Error("ParseFault described an error that is not a parse failure")
	}
}
