package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestInstanceRegistryRoundTrip(t *testing.T) {
	d := testDir(t)
	if err := d.CreateInstance("prod"); err != nil {
		t.Fatalf("CreateInstance: %v", err)
	}
	in := &InstanceMetadata{
		Name:    "prod",
		Cluster: "farcast-prod",
		Status:  InstanceRunning,
		Registry: &Registry{
			Prefix:        "us-central1-docker.pkg.dev/proj-1/farcast-prod",
			Repository:    "farcast-prod",
			Location:      "us-central1",
			Puller:        "serviceAccount:1234-compute@developer.gserviceaccount.com",
			FatLineDigest: "us-central1-docker.pkg.dev/proj-1/farcast-prod/system/fatline@sha256:abc",
		},
	}
	if err := d.SaveInstanceMetadata("prod", in); err != nil {
		t.Fatalf("SaveInstanceMetadata: %v", err)
	}
	out, err := d.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatalf("LoadInstanceMetadata: %v", err)
	}
	if out.Registry == nil {
		t.Fatal("registry lost in the round trip")
	}
	if *out.Registry != *in.Registry {
		t.Errorf("registry round-trip mismatch:\n got %+v\nwant %+v", out.Registry, in.Registry)
	}
}

// Metadata written before instances owned a registry must still load — such an
// instance converges on its next connect rather than becoming unreadable.
func TestLoadInstanceMetadataWithoutRegistry(t *testing.T) {
	d := testDir(t)
	if err := d.CreateInstance("old"); err != nil {
		t.Fatalf("CreateInstance: %v", err)
	}
	legacy := "name: old\nprovider: gke\nregion: us-central1\ncluster: farcast-old\nstatus: running\n"
	if err := d.writeInstanceFile("old", metadataFile, []byte(legacy)); err != nil {
		t.Fatal(err)
	}
	out, err := d.LoadInstanceMetadata("old")
	if err != nil {
		t.Fatalf("LoadInstanceMetadata: %v", err)
	}
	if out.Registry != nil {
		t.Errorf("registry = %+v, want nil for pre-registry metadata", out.Registry)
	}
	if out.Cluster != "farcast-old" {
		t.Errorf("cluster = %q", out.Cluster)
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

	creds, err := d.LoadInstanceCredentials("prod")
	if err != nil {
		t.Fatalf("LoadInstanceCredentials: %v", err)
	}
	if creds.Provider != "gke" || creds.ServiceAccountKey != `{"k":"v"}` {
		t.Errorf("credentials round-trip mismatch: %+v", creds)
	}
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

// The Phase 4.4 walk lost a record exactly this way: one command read the
// metadata, a second command wrote a field, and the first wrote its stale copy
// back over it. The write must be refused and the second command's field must
// survive.
func TestSaveInstanceMetadataRefusesToEraseAConcurrentWrite(t *testing.T) {
	d := testDir(t)
	if err := d.Ensure(); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if err := d.CreateInstance("prod"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := d.SaveInstanceMetadata("prod", &InstanceMetadata{Name: "prod", Provider: "gke"}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// "connect" reads the record.
	connect, err := d.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// "toolchain" records the mirrored images while connect is still working.
	if _, err := d.UpdateInstanceMetadata("prod", func(m *InstanceMetadata) error {
		m.Toolchain = &Toolchain{Builder: "registry/kaniko@sha256:aa", Fetcher: "registry/git@sha256:bb"}
		return nil
	}); err != nil {
		t.Fatalf("toolchain update: %v", err)
	}

	// connect finishes and writes back the copy it read before that. Both
	// changes must survive: they are different fields, so there is nothing to
	// choose between. Refusing here would leave a billable load balancer
	// unrecorded, which is the same class of loss the merge exists to prevent.
	connect.FatLineDeployed = true
	connect.UpdatedAt = time.Now().UTC()
	if err := d.SaveInstanceMetadata("prod", connect); err != nil {
		t.Fatalf("save after a concurrent write: %v", err)
	}

	got, err := d.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got.Toolchain == nil {
		t.Fatal("the toolchain record was erased by a stale write — this is the defect")
	}
	if !got.FatLineDeployed {
		t.Error("connect's own change was dropped by the merge")
	}
}

// Two commands moving the SAME field to different values is the one case the
// merge must not guess at.
func TestSaveInstanceMetadataRefusesARealCollision(t *testing.T) {
	d := testDir(t)
	if err := d.Ensure(); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if err := d.CreateInstance("prod"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := d.SaveInstanceMetadata("prod", &InstanceMetadata{Name: "prod", Status: "running"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	mine, err := d.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := d.UpdateInstanceMetadata("prod", func(m *InstanceMetadata) error {
		m.Status = "removed"
		return nil
	}); err != nil {
		t.Fatalf("other writer: %v", err)
	}

	mine.Status = "stopping"
	err = d.SaveInstanceMetadata("prod", mine)
	if !errors.Is(err, ErrMetadataConflict) {
		t.Fatalf("colliding save error = %v, want ErrMetadataConflict", err)
	}
	got, err := d.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got.Status != "removed" {
		t.Errorf("status = %q, want the other writer's %q left intact", got.Status, "removed")
	}
}

// The bucket is the case that matters most: losing its name loses the only
// local pointer to an instance's data, and it keeps billing regardless.
func TestSaveInstanceMetadataKeepsTheBucketThroughAConcurrentWrite(t *testing.T) {
	d := testDir(t)
	if err := d.Ensure(); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if err := d.CreateInstance("prod"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := d.SaveInstanceMetadata("prod", &InstanceMetadata{Name: "prod"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	stale, err := d.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := d.UpdateInstanceMetadata("prod", func(m *InstanceMetadata) error {
		m.Storage = &Storage{Bucket: "farcast-prod-abc123", Location: "us-central1", Provider: "gcs"}
		return nil
	}); err != nil {
		t.Fatalf("storage deploy: %v", err)
	}

	stale.Status = "running"
	if err := d.SaveInstanceMetadata("prod", stale); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := d.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got.Storage == nil || got.Storage.Bucket != "farcast-prod-abc123" {
		t.Fatalf("the bucket name was lost: %+v", got.Storage)
	}
}

func TestSaveInstanceMetadataRefusesAnUnreadFile(t *testing.T) {
	d := testDir(t)
	if err := d.Ensure(); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if err := d.CreateInstance("prod"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := d.SaveInstanceMetadata("prod", &InstanceMetadata{Name: "prod"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// A fresh struct that never read what is already there.
	err := d.SaveInstanceMetadata("prod", &InstanceMetadata{Name: "prod", Provider: "gke"})
	if !errors.Is(err, ErrMetadataConflict) {
		t.Fatalf("blind overwrite error = %v, want ErrMetadataConflict", err)
	}
}

// A command that saves more than once must not conflict with itself; several
// do (run, kernel meter, kernel confirm all save twice on one path).
func TestSaveInstanceMetadataTwiceInARow(t *testing.T) {
	d := testDir(t)
	if err := d.Ensure(); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if err := d.CreateInstance("prod"); err != nil {
		t.Fatalf("create: %v", err)
	}
	m := &InstanceMetadata{Name: "prod"}
	for i, status := range []string{"running", "stopping", "removed"} {
		m.Status = status
		if err := d.SaveInstanceMetadata("prod", m); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	got, err := d.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got.Status != "removed" {
		t.Errorf("status = %q, want %q", got.Status, "removed")
	}
}

func TestSaveInstanceMetadataIsAtomicAndPrivate(t *testing.T) {
	d := testDir(t)
	if err := d.Ensure(); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if err := d.CreateInstance("prod"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := d.SaveInstanceMetadata("prod", &InstanceMetadata{Name: "prod"}); err != nil {
		t.Fatalf("save: %v", err)
	}
	assertPerm(t, filepath.Join(d.InstancePath("prod"), "metadata.yaml"), 0o600)

	entries, err := os.ReadDir(d.InstancePath("prod"))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("left a temporary file behind: %s", e.Name())
		}
	}
}
