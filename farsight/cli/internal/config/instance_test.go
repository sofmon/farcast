package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
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
	assertPerm(t, filepath.Join(d.InstancePath("prod"), credentialsFile), 0o600)

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

// A keyring write replaces only the file its writer read. Rotate holds its
// keyring across a prompt and a network round trip; a 'farcast run' that minted
// a scope meanwhile — and handed it to the keyholder — would otherwise exist
// only in the replicas' memory.
func TestSaveInstanceKeyringRefusesAFileThatChanged(t *testing.T) {
	d := Dir(t.TempDir())
	if err := d.CreateInstanceKeyring("prod", []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := d.SaveInstanceKeyring("prod", []byte("first"), []byte("second")); err != nil {
		t.Fatalf("a write against the file as read: %v", err)
	}
	err := d.SaveInstanceKeyring("prod", []byte("first"), []byte("third"))
	if !errors.Is(err, ErrKeyringChanged) {
		t.Fatalf("a write against a file that changed = %v; want ErrKeyringChanged", err)
	}
	if got, _ := d.LoadInstanceKeyring("prod"); string(got) != "second" {
		t.Errorf("a refused write changed the file: %q", got)
	}
}

// The write is atomic: one that fails leaves the previous file whole. A
// truncate-then-write that failed half way left keys.yaml unparseable — every
// key this machine holds, gone.
func TestAFailedKeyringSaveLeavesThePreviousFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes through a read-only directory")
	}
	d := Dir(t.TempDir())
	if err := d.CreateInstanceKeyring("prod", []byte("whole")); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(d.InstanceKeyringPath("prod"))
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0o700) }()
	if err := d.SaveInstanceKeyring("prod", []byte("whole"), []byte("replacement")); err == nil {
		t.Fatal("guard: a write into a read-only directory succeeded")
	}
	if got, err := os.ReadFile(d.InstanceKeyringPath("prod")); err != nil || string(got) != "whole" {
		t.Errorf("a failed save left %q (%v); want the previous file whole", got, err)
	}
	info, err := os.Stat(d.InstanceKeyringPath("prod"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("keyring mode %04o; want 0600", info.Mode().Perm())
	}
}

// The compare and the replace are one step. Two writers that read the same
// keyring used to both pass the compare, and the second rename dropped what
// the first wrote — a scope 'farcast run' had already handed to the keyholder.
func TestConcurrentKeyringWritersNeverBothWin(t *testing.T) {
	d := Dir(t.TempDir())
	if err := d.CreateInstanceKeyring("prod", []byte("read by both")); err != nil {
		t.Fatal(err)
	}
	const writers = 16
	errs := make(chan error, writers)
	var start sync.WaitGroup
	start.Add(1)
	for i := range writers {
		go func() {
			start.Wait()
			errs <- d.SaveInstanceKeyring("prod", []byte("read by both"), []byte(fmt.Sprintf("writer %d", i)))
		}()
	}
	start.Done()
	won := 0
	for range writers {
		err := <-errs
		switch {
		case err == nil:
			won++
		case !errors.Is(err, ErrKeyringChanged):
			t.Errorf("a losing writer failed with %v; want ErrKeyringChanged", err)
		}
	}
	if won != 1 {
		t.Errorf("%d writers replaced a keyring they all read; exactly one may", won)
	}
}

// A linked keys.yaml would be replaced by a plain file, leaving the link's
// other end — often the copy being backed up — silently stale.
func TestAKeyringWriteRefusesALinkedFile(t *testing.T) {
	for name, link := range map[string]func(target, path string) error{
		"symlink":   os.Symlink,
		"hard link": os.Link,
	} {
		t.Run(name, func(t *testing.T) {
			d := Dir(t.TempDir())
			if err := d.CreateInstanceKeyring("prod", []byte("original")); err != nil {
				t.Fatal(err)
			}
			path := d.InstanceKeyringPath("prod")
			elsewhere := filepath.Join(t.TempDir(), "backed-up-keys.yaml")
			if name == "symlink" {
				if err := os.Rename(path, elsewhere); err != nil {
					t.Fatal(err)
				}
				if err := link(elsewhere, path); err != nil {
					t.Fatal(err)
				}
			} else if err := link(path, elsewhere); err != nil {
				t.Fatal(err)
			}
			err := d.SaveInstanceKeyring("prod", []byte("original"), []byte("replacement"))
			if err == nil || !strings.Contains(err.Error(), "link") {
				t.Fatalf("a write over a %s = %v; want a refusal naming the link", name, err)
			}
			if got, _ := os.ReadFile(elsewhere); string(got) != "original" {
				t.Errorf("the link's other end holds %q", got)
			}
		})
	}
}

// Review 5, finding 9. The first keyring write never overwrites one that is
// there, and one that fails leaves no keys.yaml at all — not a truncated one
// the next attempt refuses to replace.
func TestCreateInstanceKeyringIsWholeOrAbsent(t *testing.T) {
	d := Dir(t.TempDir())
	if err := d.CreateInstanceKeyring("prod", []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := d.CreateInstanceKeyring("prod", []byte("second")); !errors.Is(err, fs.ErrExist) {
		t.Errorf("a second create = %v; want ErrExist", err)
	}
	if got, _ := d.LoadInstanceKeyring("prod"); string(got) != "first" {
		t.Errorf("a refused create changed the keyring: %q", got)
	}
	if os.Geteuid() == 0 {
		return
	}
	e := Dir(t.TempDir())
	dir := filepath.Dir(e.InstanceKeyringPath("prod"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0o700) }()
	if err := e.CreateInstanceKeyring("prod", []byte("never")); err == nil {
		t.Fatal("guard: a create into a read-only directory succeeded")
	}
	if _, err := os.Lstat(e.InstanceKeyringPath("prod")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a failed create left a keys.yaml behind: %v", err)
	}
}

// The usage report reads the operator's leaf to name the operator's tunnel
// streams. It must not need the CA key to do it: a report has no business
// bringing the instance's crown jewel into memory.
func TestLoadOperatorLeafNeedsNoCAKey(t *testing.T) {
	d := testDir(t)
	if err := d.SaveInstanceMTLS("prod", MTLSMaterial{
		CACertPEM: []byte("ca"), CAKeyPEM: []byte("cakey"), ClientCertPEM: []byte("operator-leaf"),
		ClientKeyPEM: []byte("k"), ServerCertPEM: []byte("s"), ServerKeyPEM: []byte("sk"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(d.fatlineDir("prod"), caKeyFile)); err != nil {
		t.Fatal(err)
	}
	got, err := d.LoadOperatorLeaf("prod")
	if err != nil {
		t.Fatalf("LoadOperatorLeaf without a CA key: %v", err)
	}
	if string(got) != "operator-leaf" {
		t.Errorf("LoadOperatorLeaf = %q, want the operator's client certificate", got)
	}
	// The control: the loader that does read the CA key fails here, so the
	// assertion above is about the key's absence and not a vacuous pass.
	if _, err := d.LoadInstanceMTLS("prod"); err == nil {
		t.Error("LoadInstanceMTLS succeeded without a CA key; the test proves nothing")
	}
}

// ADR 0023 M2.6c (A26-2), mutation A26-2m's base: CheckInstanceMTLS finds
// what LoadInstanceMTLS would refuse for a file that is not there, without
// opening a file. Each missing file gives its own "read <file>: …" error,
// the one LoadInstanceMTLS gives it, and with several missing both name
// the same first one, so the two keep one order; a directory in place of a
// file is refused. It reads nothing: the read observer sees no path, and it
// passes with ca.key, client.key and server.key at mode 000, where
// LoadInstanceMTLS fails.
func TestCheckInstanceMTLSReadsNoKey(t *testing.T) {
	files := []string{caCertFile, caKeyFile, clientCertFile, clientKeyFile, serverCertFile, serverKeyFile}
	material := func(t *testing.T) (Dir, string) {
		t.Helper()
		d := testDir(t)
		if err := d.SaveInstanceMTLS("prod", MTLSMaterial{
			CACertPEM: []byte("ca"), CAKeyPEM: []byte("cakey"), ClientCertPEM: []byte("leaf"),
			ClientKeyPEM: []byte("k"), ServerCertPEM: []byte("s"), ServerKeyPEM: []byte("sk"),
		}); err != nil {
			t.Fatal(err)
		}
		return d, d.fatlineDir("prod")
	}
	// check is CheckInstanceMTLS under the read observer, which must see
	// nothing.
	check := func(t *testing.T, d Dir) error {
		t.Helper()
		reads := observeReads(t)
		err := d.CheckInstanceMTLS("prod")
		if got := reads(); len(got) != 0 {
			t.Errorf("CheckInstanceMTLS read %v", got)
		}
		return err
	}

	t.Run("all six present", func(t *testing.T) {
		d, _ := material(t)
		if err := check(t, d); err != nil {
			t.Fatalf("CheckInstanceMTLS with every file present = %v", err)
		}
	})

	seen := map[string]string{}
	for _, file := range files {
		t.Run("missing "+file, func(t *testing.T) {
			d, dir := material(t)
			if err := os.Remove(filepath.Join(dir, file)); err != nil {
				t.Fatal(err)
			}
			err := check(t, d)
			if err == nil || !strings.HasPrefix(err.Error(), "read "+file+": ") || !errors.Is(err, fs.ErrNotExist) ||
				!strings.Contains(err.Error(), filepath.Join(dir, file)) {
				t.Fatalf("CheckInstanceMTLS without %s = %v; want read %s: …, not exist, naming its path", file, err, file)
			}
			_, loadErr := d.LoadInstanceMTLS("prod")
			if loadErr == nil || !strings.HasPrefix(loadErr.Error(), "read "+file+": ") || !errors.Is(loadErr, fs.ErrNotExist) {
				t.Fatalf("LoadInstanceMTLS without %s = %v; the check's error is not the load's", file, loadErr)
			}
			if other, ok := seen[err.Error()]; ok {
				t.Errorf("a missing %s and a missing %s give one error: %v", file, other, err)
			}
			seen[err.Error()] = file
		})
	}

	// With every file from the i-th on removed, the check and the load both
	// name the i-th: they meet the files in one order.
	for i, first := range files {
		t.Run("missing from "+first, func(t *testing.T) {
			d, dir := material(t)
			for _, file := range files[i:] {
				if err := os.Remove(filepath.Join(dir, file)); err != nil {
					t.Fatal(err)
				}
			}
			err := check(t, d)
			_, loadErr := d.LoadInstanceMTLS("prod")
			want := "read " + first + ": "
			if err == nil || !strings.HasPrefix(err.Error(), want) || loadErr == nil || !strings.HasPrefix(loadErr.Error(), want) {
				t.Errorf("without %v: check = %v, load = %v; want both to name %s", files[i:], err, loadErr, first)
			}
		})
	}

	t.Run("a directory in place of client.key", func(t *testing.T) {
		d, dir := material(t)
		path := filepath.Join(dir, clientKeyFile)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		err := check(t, d)
		if err == nil || !strings.HasPrefix(err.Error(), "read client.key: ") || !errors.Is(err, errNotAFile) || !strings.Contains(err.Error(), path) {
			t.Fatalf("CheckInstanceMTLS with a directory for client.key = %v; want it refused, naming the path", err)
		}
		if _, err := d.LoadInstanceMTLS("prod"); err == nil || !strings.HasPrefix(err.Error(), "read client.key: ") {
			t.Errorf("LoadInstanceMTLS with a directory for client.key = %v; want it refused", err)
		}
	})

	t.Run("keys at mode 000", func(t *testing.T) {
		d, dir := material(t)
		for _, file := range []string{caKeyFile, clientKeyFile, serverKeyFile} {
			path := filepath.Join(dir, file)
			if err := os.Chmod(path, 0o000); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
		}
		if err := check(t, d); err != nil {
			t.Fatalf("CheckInstanceMTLS with the keys unreadable = %v; it must open none of them", err)
		}
		// The control: the loader, which opens them, fails here, so the pass
		// above is about opening nothing and not a vacuous one.
		if _, err := d.LoadInstanceMTLS("prod"); err == nil || !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("LoadInstanceMTLS with ca.key at mode 000 = %v; the test proves nothing (run as root?)", err)
		}
	})
}

// ADR 0023 M2.6d (A28-9): InstanceCAKeyExists is true only for a ca.key that
// is a regular file with something in it, and it opens nothing. A missing
// key, a missing fatline directory, a directory in the key's place and an
// empty key, which SaveInstanceMTLS writes for material with no CA key, are
// all no key; a key at mode 000 is one, and the read observer sees no path,
// where LoadInstanceMTLS fails on it. A stat that fails for another reason
// is an error, never "no key".
func TestInstanceCAKeyExistsReadsNoKey(t *testing.T) {
	material := func(t *testing.T, caKey []byte) (Dir, string) {
		t.Helper()
		d := testDir(t)
		if err := d.SaveInstanceMTLS("prod", MTLSMaterial{
			CACertPEM: []byte("ca"), CAKeyPEM: caKey, ClientCertPEM: []byte("leaf"),
			ClientKeyPEM: []byte("k"), ServerCertPEM: []byte("s"), ServerKeyPEM: []byte("sk"),
		}); err != nil {
			t.Fatal(err)
		}
		return d, filepath.Join(d.fatlineDir("prod"), caKeyFile)
	}
	// exists is InstanceCAKeyExists under the read observer, which must see
	// nothing.
	exists := func(t *testing.T, d Dir) (bool, error) {
		t.Helper()
		reads := observeReads(t)
		ok, err := d.InstanceCAKeyExists("prod")
		if got := reads(); len(got) != 0 {
			t.Errorf("InstanceCAKeyExists read %v", got)
		}
		return ok, err
	}

	for _, row := range []struct {
		name  string
		setup func(t *testing.T) Dir
		want  bool
	}{
		{"a key", func(t *testing.T) Dir {
			d, _ := material(t, []byte("cakey"))
			return d
		}, true},
		{"no ca.key", func(t *testing.T) Dir {
			d, path := material(t, []byte("cakey"))
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			return d
		}, false},
		{"no fatline directory", func(t *testing.T) Dir {
			d := testDir(t)
			if err := d.CreateInstance("prod"); err != nil {
				t.Fatal(err)
			}
			return d
		}, false},
		{"a directory in its place", func(t *testing.T) Dir {
			d, path := material(t, []byte("cakey"))
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			return d
		}, false},
		{"an empty ca.key", func(t *testing.T) Dir {
			d, _ := material(t, nil)
			return d
		}, false},
		{"a key at mode 000", func(t *testing.T) Dir {
			d, path := material(t, []byte("cakey"))
			if err := os.Chmod(path, 0o000); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
			// The control: the loader, which opens it, fails here, so a
			// pass below is about opening nothing and not a vacuous one.
			if _, err := d.LoadInstanceMTLS("prod"); err == nil || !errors.Is(err, fs.ErrPermission) {
				t.Fatalf("LoadInstanceMTLS with ca.key at mode 000 = %v; the test proves nothing (run as root?)", err)
			}
			return d
		}, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			d := row.setup(t)
			ok, err := exists(t, d)
			if err != nil || ok != row.want {
				t.Fatalf("InstanceCAKeyExists = %t, %v; want %t, nil", ok, err, row.want)
			}
		})
	}

	t.Run("a fatline directory it may not search", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root may search a directory at mode 000, so no stat fails here")
		}
		d, path := material(t, []byte("cakey"))
		dir := filepath.Dir(path)
		if err := os.Chmod(dir, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		// The control, as the mode-000 row's: the loader fails here with
		// the permission error, so the stat below fails for the directory's
		// mode and not for a reason of its own. Root may search it, and then
		// the stat succeeds and this row would fail for the wrong reason.
		if _, err := d.LoadInstanceMTLS("prod"); err == nil || !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("LoadInstanceMTLS under an unsearchable fatline directory = %v; the test proves nothing (run as root?)", err)
		}
		ok, err := exists(t, d)
		if ok || !errors.Is(err, fs.ErrPermission) || !strings.Contains(err.Error(), path) {
			t.Fatalf("InstanceCAKeyExists under an unsearchable directory = %t, %v; want the stat's permission error, naming the key's path", ok, err)
		}
	})
}

// TestSystemImagesRoundTrip: every origin, with every field a build records,
// reads back exactly (ADR 0023 decision 4).
func TestSystemImagesRoundTrip(t *testing.T) {
	d := testDir(t)
	if err := d.CreateInstance("prod"); err != nil {
		t.Fatalf("CreateInstance: %v", err)
	}
	const repo = "us-central1-docker.pkg.dev/proj-1/farcast-prod/system/"
	digest := func(c byte) string { return "@sha256:" + strings.Repeat(string(c), 64) }
	built := time.Date(2026, 11, 13, 15, 58, 28, 0, time.UTC)
	in := &InstanceMetadata{
		Name: "prod",
		SystemImages: map[string]SystemImage{
			"fatline":     {Image: repo + "fatline" + digest('e'), Origin: OriginEmbedded, Go: "go1.27.4", Farcast: "v0.1.0"},
			"shrike":      {Image: repo + "shrike" + digest('f'), Origin: OriginOperator, Go: "go1.27.5", Farcast: "v0.1.0", BuiltAt: built, Source: "/Users/op/src/farcast"},
			"technocore":  {Image: repo + "technocore" + digest('d'), Origin: OriginDevelopment, Go: "go1.27.4", Farcast: "dev", BuiltAt: built, Source: "/work/farcast"},
			"datasphered": {Image: "registry.example/ds" + digest('c'), Origin: OriginNamed, Farcast: "v0.1.0"},
		},
	}
	if err := d.SaveInstanceMetadata("prod", in); err != nil {
		t.Fatalf("SaveInstanceMetadata: %v", err)
	}
	out, err := d.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatalf("LoadInstanceMetadata: %v", err)
	}
	if len(out.SystemImages) != 4 {
		t.Fatalf("read back %d system images, want 4: %+v", len(out.SystemImages), out.SystemImages)
	}
	for name, want := range in.SystemImages {
		if got := out.SystemImages[name]; got != want {
			t.Errorf("%s round-tripped to %+v, want %+v", name, got, want)
		}
	}
	// A named or embedded image was never built here: no time is written for it.
	raw, err := os.ReadFile(filepath.Join(d.InstancePath("prod"), metadataFile))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(raw), "built_at"); n != 2 {
		t.Errorf("built_at written %d times, want only for the two builds:\n%s", n, raw)
	}
}

// TestSystemImagesMergePerKey: two commands deploying different components at
// once each keep their own record, and only one key moved on both sides is a
// conflict, named by its key.
func TestSystemImagesMergePerKey(t *testing.T) {
	d := testDir(t)
	if err := d.Ensure(); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if err := d.CreateInstance("prod"); err != nil {
		t.Fatalf("create: %v", err)
	}
	old := SystemImage{Image: "r/system/fatline@sha256:" + strings.Repeat("0", 64), Origin: OriginEmbedded, Go: "go1.27.3", Farcast: "v1"}
	if err := d.SaveInstanceMetadata("prod", &InstanceMetadata{Name: "prod", SystemImages: map[string]SystemImage{"fatline": old}}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// "kernel deploy" reads the record...
	kernel, err := d.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// ...while "redeploy" records a new FatLine.
	fatline := SystemImage{Image: "r/system/fatline@sha256:" + strings.Repeat("e", 64), Origin: OriginEmbedded, Go: "go1.27.4", Farcast: "v2"}
	if _, err := d.UpdateInstanceMetadata("prod", func(m *InstanceMetadata) error {
		m.SystemImages["fatline"] = fatline
		return nil
	}); err != nil {
		t.Fatalf("redeploy's write: %v", err)
	}
	// kernel deploy writes back its stale copy with its own key added.
	technocore := SystemImage{Image: "r/system/technocore@sha256:" + strings.Repeat("e", 64), Origin: OriginEmbedded, Go: "go1.27.4", Farcast: "v2"}
	if kernel.SystemImages == nil {
		kernel.SystemImages = map[string]SystemImage{}
	}
	kernel.SystemImages["technocore"] = technocore
	if err := d.SaveInstanceMetadata("prod", kernel); err != nil {
		t.Fatalf("a write to another component conflicted: %v", err)
	}
	got, err := d.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got.SystemImages["fatline"] != fatline {
		t.Errorf("redeploy's fatline record was lost: %+v", got.SystemImages["fatline"])
	}
	if got.SystemImages["technocore"] != technocore {
		t.Errorf("kernel deploy's technocore record was lost: %+v", got.SystemImages["technocore"])
	}

	// The same key moved differently on both sides is a real conflict.
	mine, err := d.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := d.UpdateInstanceMetadata("prod", func(m *InstanceMetadata) error {
		m.SystemImages["technocore"] = SystemImage{Image: "r/system/technocore@sha256:" + strings.Repeat("a", 64), Origin: OriginNamed}
		return nil
	}); err != nil {
		t.Fatalf("other writer: %v", err)
	}
	mine.SystemImages["technocore"] = SystemImage{Image: "r/system/technocore@sha256:" + strings.Repeat("b", 64), Origin: OriginOperator}
	err = d.SaveInstanceMetadata("prod", mine)
	if !errors.Is(err, ErrMetadataConflict) || !strings.Contains(err.Error(), "SystemImages[technocore]") {
		t.Fatalf("colliding save = %v, want ErrMetadataConflict naming SystemImages[technocore]", err)
	}
}

// ADR 0023 M2.4 (A18-6): server_side_apply round-trips, is absent from a
// record that never moved, and merges onto a newer record as every other
// field does: a change to it and a change elsewhere both survive, and two
// different changes to it are refused.
func TestServerSideApplyRoundTripsAndMerges(t *testing.T) {
	d := testDir(t)
	if err := d.CreateInstance("prod"); err != nil {
		t.Fatal(err)
	}
	if err := d.SaveInstanceMetadata("prod", &InstanceMetadata{Name: "prod", Provider: "gke"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(d.InstancePath("prod"), metadataFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("server_side_apply")) {
		t.Errorf("a record that never moved names server_side_apply:\n%s", raw)
	}
	if m, err := d.LoadInstanceMetadata("prod"); err != nil || m.ServerSideApply != nil {
		t.Fatalf("a record that never moved: %+v, %v", m.ServerSideApply, err)
	}

	// A command holds the record while 'migrate' records the move.
	stale, err := d.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatal(err)
	}
	since := time.Date(2026, 11, 20, 8, 15, 0, 0, time.UTC)
	if _, err := d.UpdateInstanceMetadata("prod", func(m *InstanceMetadata) error {
		m.ServerSideApply = &ServerSideApply{Since: since, Farcast: "v0.2.0"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"server_side_apply:", "since: 2026-11-20T08:15:00Z", "farcast: v0.2.0"} {
		if !bytes.Contains(raw, []byte(want)) {
			t.Errorf("the record does not carry %q:\n%s", want, raw)
		}
	}
	stale.Carrier = &Carrier{Type: "nlb", Endpoint: "203.0.113.5:443", ServerName: "fatline"}
	if err := d.SaveInstanceMetadata("prod", stale); err != nil {
		t.Fatalf("save over a newer server_side_apply: %v", err)
	}
	got, err := d.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatal(err)
	}
	if got.ServerSideApply == nil || !got.ServerSideApply.Since.Equal(since) || got.ServerSideApply.Farcast != "v0.2.0" {
		t.Errorf("server_side_apply after the merge = %+v", got.ServerSideApply)
	}
	if got.Carrier == nil || got.Carrier.Endpoint != "203.0.113.5:443" {
		t.Errorf("the stale command's own change was lost: carrier = %+v", got.Carrier)
	}

	// Two commands recording different moves is refused.
	mine, err := d.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.UpdateInstanceMetadata("prod", func(m *InstanceMetadata) error {
		m.ServerSideApply = &ServerSideApply{Since: since.Add(time.Hour), Farcast: "v0.3.0"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	mine.ServerSideApply = &ServerSideApply{Since: since.Add(2 * time.Hour), Farcast: "v0.4.0"}
	if err := d.SaveInstanceMetadata("prod", mine); !errors.Is(err, ErrMetadataConflict) || !strings.Contains(err.Error(), "ServerSideApply") {
		t.Errorf("colliding save = %v, want ErrMetadataConflict naming ServerSideApply", err)
	}
}

// ADR 0023 M2.7 (A30-14): the files an instance's kubectl left, named by
// config and deleted by farcast migrate. LegacyKubectlFiles names the present
// ones, kubeconfig first, as config-relative slash paths, from os.Lstat alone:
// it opens nothing, and a link is the file it is, wherever it points, a
// dangling one included. RemoveLegacyKubectlFiles deletes what is there,
// treats an absent file as nothing to do, lists exactly what went, and on a
// failure names the file it was deleting and still tries the other one.
func TestLegacyKubectlFilesStatsAndRemoves(t *testing.T) {
	const (
		kubeconfig = "instances/atlas/kubeconfig.yaml"
		cache      = "instances/atlas/gke_gcloud_auth_plugin_cache"
	)
	for _, row := range []struct {
		name  string
		files []string
	}{
		{"none", nil},
		{"the kubeconfig alone", []string{kubeconfig}},
		{"the plugin's cache alone", []string{cache}},
		{"both", []string{kubeconfig, cache}},
	} {
		t.Run(row.name, func(t *testing.T) {
			d := readerDir(t)
			for _, f := range row.files {
				if err := os.WriteFile(filepath.Join(d.Path(), filepath.FromSlash(f)), []byte("planted"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			reads := observeReads(t)
			got, err := d.LegacyKubectlFiles("atlas")
			if err != nil || !slices.Equal(got, row.files) {
				t.Errorf("LegacyKubectlFiles = %q, %v; want %q", got, err, row.files)
			}
			removed, err := d.RemoveLegacyKubectlFiles("atlas")
			if err != nil || !slices.Equal(removed, row.files) {
				t.Errorf("RemoveLegacyKubectlFiles = %q, %v; want %q removed", removed, err, row.files)
			}
			for _, f := range []string{kubeconfig, cache} {
				if _, err := os.Lstat(filepath.Join(d.Path(), filepath.FromSlash(f))); !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("%s after the removal: %v", f, err)
				}
			}
			if got, err := d.LegacyKubectlFiles("atlas"); err != nil || len(got) != 0 {
				t.Errorf("LegacyKubectlFiles after the removal = %q, %v", got, err)
			}
			if again, err := d.RemoveLegacyKubectlFiles("atlas"); err != nil || len(again) != 0 {
				t.Errorf("a second removal = %q, %v; want nothing removed and no error", again, err)
			}
			if r := reads(); len(r) != 0 {
				t.Errorf("the legacy files were read: %q", r)
			}
		})
	}

	t.Run("links", func(t *testing.T) {
		d := readerDir(t)
		elsewhere := filepath.Join(t.TempDir(), "kept")
		if err := os.WriteFile(elsewhere, []byte("not farcast's"), 0o600); err != nil {
			t.Fatal(err)
		}
		inst := d.InstancePath("atlas")
		// A dangling link stats as absent through it, and is there all the same.
		if err := os.Symlink(filepath.Join(t.TempDir(), "gone"), filepath.Join(inst, kubeconfigFile)); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, filepath.Join(inst, pluginCacheFile)); err != nil {
			t.Fatal(err)
		}
		reads := observeReads(t)
		if got, err := d.LegacyKubectlFiles("atlas"); err != nil || !slices.Equal(got, []string{kubeconfig, cache}) {
			t.Errorf("LegacyKubectlFiles over two links = %q, %v", got, err)
		}
		if removed, err := d.RemoveLegacyKubectlFiles("atlas"); err != nil || !slices.Equal(removed, []string{kubeconfig, cache}) {
			t.Errorf("RemoveLegacyKubectlFiles over two links = %q, %v", removed, err)
		}
		if b, err := os.ReadFile(elsewhere); err != nil || string(b) != "not farcast's" {
			t.Errorf("the link's target = %q, %v; a removal deletes the link alone", b, err)
		}
		if r := reads(); len(r) != 0 {
			t.Errorf("the links were read: %q", r)
		}
	})

	t.Run("a failure", func(t *testing.T) {
		d := readerDir(t)
		inst := d.InstancePath("atlas")
		// A directory that holds something is a file os.Remove cannot delete.
		stuck := func(file string) {
			if err := os.MkdirAll(filepath.Join(inst, file, "inside"), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		stuck(kubeconfigFile)
		if err := os.WriteFile(filepath.Join(inst, pluginCacheFile), []byte("planted"), 0o600); err != nil {
			t.Fatal(err)
		}
		removed, err := d.RemoveLegacyKubectlFiles("atlas")
		var pe *fs.PathError
		if !errors.As(err, &pe) || pe.Path != kubeconfig || pe.Op != "delete" || !strings.Contains(err.Error(), kubeconfig) {
			t.Errorf("a kubeconfig that cannot be deleted = %v; want a failure naming %s", err, kubeconfig)
		}
		// Its cause is os.Remove's own error unwrapped, so the text names the
		// config-relative path once and never the absolute one: A30-24's
		// warning prints pe.Err.
		var nested *fs.PathError
		if err != nil && (pe == nil || errors.As(pe.Err, &nested) || strings.Contains(err.Error(), d.Path()) || err.Error() != "delete "+kubeconfig+": "+pe.Err.Error()) {
			t.Errorf("the failure's text holds an absolute path, or more than the operation, %s and the cause: %d bytes, the config directory in it %t",
				kubeconfig, len(err.Error()), strings.Contains(err.Error(), d.Path()))
		}
		if !slices.Equal(removed, []string{cache}) {
			t.Errorf("removed = %q; the cache after the failure is deleted still, and only it is listed", removed)
		}
		if _, err := os.Lstat(filepath.Join(inst, pluginCacheFile)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("the cache after a failed kubeconfig: %v", err)
		}

		// Both failing: the first is the one named, and nothing is listed.
		stuck(pluginCacheFile)
		removed, err = d.RemoveLegacyKubectlFiles("atlas")
		if !errors.As(err, &pe) || pe.Path != kubeconfig || len(removed) != 0 {
			t.Errorf("both stuck = %q, %v; want the kubeconfig's failure and nothing removed", removed, err)
		}
		if got, err := d.LegacyKubectlFiles("atlas"); err != nil || !slices.Equal(got, []string{kubeconfig, cache}) {
			t.Errorf("LegacyKubectlFiles of what could not go = %q, %v", got, err)
		}
	})

	t.Run("an error that is not absence", func(t *testing.T) {
		d := testDir(t)
		if err := os.MkdirAll(filepath.Join(d.Path(), instancesSubdir), 0o700); err != nil {
			t.Fatal(err)
		}
		// An instance path that is a file: nothing can be below it.
		if err := os.WriteFile(d.InstancePath("atlas"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := d.LegacyKubectlFiles("atlas"); err == nil || errors.Is(err, fs.ErrNotExist) {
			t.Errorf("LegacyKubectlFiles below a file = %q, %v; want the stat's own error", got, err)
		}
	})
}
