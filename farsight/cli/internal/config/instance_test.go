package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testDir returns a fresh config dir under a temp dir. It uses a subpath (not
// the 0755 temp dir itself) so Ensure can create it at 0700.
func testDir(t *testing.T) Dir {
	t.Helper()
	return Dir(filepath.Join(t.TempDir(), "cfg"))
}

func assertPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s perm = %#o, want %#o", path, got, want)
	}
}

func TestCreateInstanceReservesDirAndRejectsDuplicate(t *testing.T) {
	d := testDir(t)
	if err := d.CreateInstance("prod"); err != nil {
		t.Fatalf("CreateInstance: %v", err)
	}
	assertPerm(t, d.InstancePath("prod"), 0o700)

	if err := d.CreateInstance("prod"); err == nil {
		t.Fatal("expected CreateInstance to reject an existing instance")
	}
}

func TestInstanceMetadataRoundTrip(t *testing.T) {
	d := testDir(t)
	if err := d.CreateInstance("prod"); err != nil {
		t.Fatalf("CreateInstance: %v", err)
	}
	in := &InstanceMetadata{
		Name:      "prod",
		Provider:  "gke",
		Project:   "proj-1",
		Region:    "us-central1",
		Cluster:   "farcast-prod",
		Endpoint:  "uid.us-central1.gke.goog",
		Status:    InstanceRunning,
		CostLimit: CostLimit{Amount: 50, Currency: "USD", Period: "monthly"},
		CreatedAt: time.Unix(1, 0).UTC(),
		UpdatedAt: time.Unix(2, 0).UTC(),
	}
	if err := d.SaveInstanceMetadata("prod", in); err != nil {
		t.Fatalf("SaveInstanceMetadata: %v", err)
	}
	assertPerm(t, filepath.Join(d.InstancePath("prod"), metadataFile), 0o600)

	out, err := d.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatalf("LoadInstanceMetadata: %v", err)
	}
	if out.Cluster != "farcast-prod" || out.Status != InstanceRunning || out.CostLimit.Amount != 50 {
		t.Errorf("round-trip mismatch: %+v", out)
	}
}

func TestSaveInstanceSecretsAre0600(t *testing.T) {
	d := testDir(t)
	if err := d.CreateInstance("prod"); err != nil {
		t.Fatalf("CreateInstance: %v", err)
	}
	if err := d.SaveInstanceCredentials("prod", &InstanceCredentials{Provider: "gke", ServiceAccountKey: `{"k":"v"}`}); err != nil {
		t.Fatalf("SaveInstanceCredentials: %v", err)
	}
	if err := d.SaveInstanceKubeconfig("prod", []byte("apiVersion: v1\n")); err != nil {
		t.Fatalf("SaveInstanceKubeconfig: %v", err)
	}
	assertPerm(t, filepath.Join(d.InstancePath("prod"), credentialsFile), 0o600)
	assertPerm(t, filepath.Join(d.InstancePath("prod"), kubeconfigFile), 0o600)
}

func TestInstanceExistsAndList(t *testing.T) {
	d := testDir(t)
	if exists, err := d.InstanceExists("nope"); err != nil || exists {
		t.Fatalf("InstanceExists(nope) = %v,%v; want false,nil", exists, err)
	}
	for _, n := range []string{"beta", "alpha"} {
		if err := d.CreateInstance(n); err != nil {
			t.Fatal(err)
		}
	}
	exists, err := d.InstanceExists("alpha")
	if err != nil || !exists {
		t.Fatalf("InstanceExists(alpha) = %v,%v; want true,nil", exists, err)
	}
	names, err := d.ListInstances()
	if err != nil {
		t.Fatalf("ListInstances: %v", err)
	}
	if len(names) != 2 || names[0] != "alpha" || names[1] != "beta" {
		t.Errorf("ListInstances = %v, want [alpha beta] sorted", names)
	}
}

func TestRemoveInstance(t *testing.T) {
	d := testDir(t)
	if err := d.CreateInstance("gone"); err != nil {
		t.Fatal(err)
	}
	if err := d.RemoveInstance("gone"); err != nil {
		t.Fatalf("RemoveInstance: %v", err)
	}
	if exists, _ := d.InstanceExists("gone"); exists {
		t.Error("instance should be gone after RemoveInstance")
	}
}
