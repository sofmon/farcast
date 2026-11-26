package config

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/devicekey"
)

// adoptMeta is the record an install hands validPending(name) over to: the
// same project, and an identity holding every ID the entry drew.
func adoptMeta(name string) *InstanceMetadata {
	return &InstanceMetadata{
		Name:      name,
		Provider:  "gke",
		Project:   "proj-test1",
		Region:    "us-central1",
		Cluster:   "farcast-" + name,
		Status:    InstanceProvisioning,
		CostLimit: CostLimit{Amount: 50, Currency: "USD", Period: "monthly"},
		Identity:  validIdentity(),
	}
}

// errInjected is the fault the tests stop a hand-off with.
var errInjected = errors.New("injected stop")

// stopBefore makes the hand-off stop before step, until the test ends or
// the returned function clears it.
func stopBefore(t *testing.T, step string) (clear func()) {
	t.Helper()
	f := func(s string) error {
		if s == step {
			return errInjected
		}
		return nil
	}
	adoptFault.Store(&f)
	clear = func() { adoptFault.Store(nil) }
	t.Cleanup(clear)
	return clear
}

// verifiedEntry is a pending install of name that reached verified, with a
// writer-capable device's keys in its identity/. It returns the anchors'
// DER, reader first.
func verifiedEntry(t *testing.T, d Dir, name string) [][]byte {
	t.Helper()
	p := validPending(name)
	p.State, p.ProjectNumber = PendingVerified, "123456789012"
	if err := d.CreatePending(name, p); err != nil {
		t.Fatal(err)
	}
	dir, err := d.PendingIdentityDir(name)
	if err != nil {
		t.Fatal(err)
	}
	_, ids, err := devicekey.Enrol(rand.Reader, dir, []devicekey.Role{devicekey.Reader, devicekey.Writer}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return [][]byte{ids[0].AnchorDER(), ids[1].AnchorDER()}
}

// editPending is a TestAdoptPendingRefusals setup that rewrites atlas's
// pending record with edit.
func editPending(edit func(*Pending)) func(*testing.T, Dir) {
	return func(t *testing.T, d Dir) {
		t.Helper()
		p, err := d.LoadPending("atlas")
		if err != nil {
			t.Fatal(err)
		}
		edit(p)
		if err := d.SavePending("atlas", p); err != nil {
			t.Fatal(err)
		}
	}
}

// handedOver checks name's hand-off is whole: the record, with the identity
// and the status provisioning; the keys in the instance, readable by
// devicekey and the ones enrolled; and no pending entry.
func handedOver(t *testing.T, d Dir, name string, anchors [][]byte) {
	t.Helper()
	meta, err := d.LoadInstanceMetadata(name)
	if err != nil {
		t.Fatalf("the record: %v", err)
	}
	if meta.Status != InstanceProvisioning || !sameIdentity(meta.Identity, validIdentity()) {
		t.Errorf("the record = status %q, identity %+v", meta.Status, meta.Identity)
	}
	dir, err := d.InstanceIdentityDir(name)
	if err != nil {
		t.Fatal(err)
	}
	store, err := devicekey.Open(dir)
	if err != nil {
		t.Fatalf("the instance's keys do not open: %v", err)
	}
	roles, err := store.Roles()
	if err != nil || !slices.Equal(roles, []devicekey.Role{devicekey.Reader, devicekey.Writer}) {
		t.Errorf("the instance's store holds %v, %v", roles, err)
	}
	for i, r := range []devicekey.Role{devicekey.Reader, devicekey.Writer} {
		c, err := store.CurrentCertificates(r)
		if err != nil || !bytes.Equal(c.AnchorDER(), anchors[i]) {
			t.Errorf("the %s anchor in the instance is not the one enrolled: %v", r, err)
		}
	}
	if ok, err := d.PendingExists(name); ok || err != nil {
		t.Errorf("the pending entry is still there: %v, %v", ok, err)
	}
	if got, err := d.ListInstances(); err != nil || !slices.Contains(got, name) {
		t.Errorf("ListInstances = %v, %v", got, err)
	}
	if got, err := d.ListPending(); err != nil || slices.Contains(got, name) {
		t.Errorf("ListPending = %v, %v", got, err)
	}
}

// ADR 0024 M3b.2 (decision 7, pitfall 10.1): AdoptPending stopped before each
// of its steps leaves a state ResumeAdoption, or AdoptPending again, finishes
// whole: before the instance directory or the record, there is no record to
// resume from, ResumeAdoption refuses and changes nothing, and AdoptPending
// again finishes it, an empty instance directory taken as its first step
// done; once the record is written, ResumeAdoption finishes it. The keys are
// never in two places, and never in none.
func TestAdoptPendingFailingAtEachStepThenResume(t *testing.T) {
	for _, step := range []string{adoptCreate, adoptRecord, adoptIdentity, adoptRemove} {
		t.Run("stopped before "+step, func(t *testing.T) {
			d := pendingDir(t)
			anchors := verifiedEntry(t, d, "atlas")
			clear := stopBefore(t, step)
			if err := d.AdoptPending("atlas", adoptMeta("atlas")); !errors.Is(err, errInjected) {
				t.Fatalf("AdoptPending = %v; want the injected stop", err)
			}
			clear()

			pendingKeys := filepath.Join(d.PendingDir(), "atlas", identitySubdir)
			instanceKeys := filepath.Join(d.InstancePath("atlas"), identitySubdir)
			_, pkErr := os.Lstat(pendingKeys)
			_, ikErr := os.Lstat(instanceKeys)
			_, recErr := os.Lstat(filepath.Join(d.InstancePath("atlas"), metadataFile))
			_, instErr := os.Lstat(d.InstancePath("atlas"))
			wantMoved := step == adoptRemove
			if (pkErr == nil) == wantMoved || (ikErr == nil) != wantMoved {
				t.Fatalf("the keys after a stop before %s: in the entry %v, in the instance %v", step, pkErr, ikErr)
			}
			wantRecord := step == adoptIdentity || step == adoptRemove
			if (recErr == nil) != wantRecord || (instErr == nil) != (step != adoptCreate) {
				t.Fatalf("after a stop before %s: record %v, instance directory %v", step, recErr, instErr)
			}
			if ok, err := d.PendingExists("atlas"); !ok || err != nil {
				t.Fatalf("the pending entry went before the hand-off finished: %v, %v", ok, err)
			}

			if !wantRecord {
				before := tree(t, string(d))
				if err := d.ResumeAdoption("atlas"); !errors.Is(err, ErrNoInstanceRecord) {
					t.Errorf("ResumeAdoption with no record = %v; want ErrNoInstanceRecord", err)
				}
				if after := tree(t, string(d)); !mapsEqual(before, after) {
					t.Error("a refused ResumeAdoption changed the config dir")
				}
				if err := d.PendingOnly("atlas"); err != nil {
					t.Errorf("PendingOnly with no record = %v; the entry must stay abandonable", err)
				}
				if err := d.AdoptPending("atlas", adoptMeta("atlas")); err != nil {
					t.Fatalf("AdoptPending again: %v", err)
				}
			} else {
				if err := d.PendingOnly("atlas"); !errors.Is(err, ErrInstanceRecorded) {
					t.Errorf("PendingOnly with a record = %v; want ErrInstanceRecorded", err)
				}
				if err := d.AdoptPending("atlas", adoptMeta("atlas")); err == nil {
					t.Error("AdoptPending again over a record succeeded")
				}
				if err := d.ResumeAdoption("atlas"); err != nil {
					t.Fatalf("ResumeAdoption: %v", err)
				}
			}
			handedOver(t, d, "atlas", anchors)
			if err := d.ResumeAdoption("atlas"); !errors.Is(err, ErrNoPending) {
				t.Errorf("ResumeAdoption of a finished hand-off = %v; want ErrNoPending", err)
			}
		})
	}
	t.Run("not stopped", func(t *testing.T) {
		d := pendingDir(t)
		anchors := verifiedEntry(t, d, "atlas")
		if err := d.AdoptPending("atlas", adoptMeta("atlas")); err != nil {
			t.Fatal(err)
		}
		handedOver(t, d, "atlas", anchors)
	})

	// The fix round's F3: a process that dies inside step 2, between
	// writeFileAtomic's CreateTemp and its rename, leaves the record's
	// temporary files in the instance directory and no record. AdoptPending
	// again takes that as step 1 done, removes them and finishes.
	t.Run("stopped inside the record's write", func(t *testing.T) {
		d := pendingDir(t)
		anchors := verifiedEntry(t, d, "atlas")
		clear := stopBefore(t, adoptRecord)
		if err := d.AdoptPending("atlas", adoptMeta("atlas")); !errors.Is(err, errInjected) {
			t.Fatal(err)
		}
		clear()
		var temps []string
		for _, n := range []string{"123456", "654321"} {
			p := filepath.Join(d.InstancePath("atlas"), recordTempPrefix+n)
			if err := os.WriteFile(p, []byte("name: atl"), 0o600); err != nil {
				t.Fatal(err)
			}
			temps = append(temps, p)
		}
		before := tree(t, string(d))
		if err := d.ResumeAdoption("atlas"); !errors.Is(err, ErrNoInstanceRecord) || !strings.Contains(err.Error(), "adopting the entry again finishes it") {
			t.Errorf("ResumeAdoption with no record = %v; want ErrNoInstanceRecord", err)
		}
		if after := tree(t, string(d)); !mapsEqual(before, after) {
			t.Error("a refused ResumeAdoption changed the config dir")
		}
		if err := d.AdoptPending("atlas", adoptMeta("atlas")); err != nil {
			t.Fatalf("AdoptPending again over the record's temporary files: %v", err)
		}
		handedOver(t, d, "atlas", anchors)
		for _, p := range temps {
			if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("the record's temporary file %s is still there: %v", filepath.Base(p), err)
			}
		}
	})

	// The fix round's F2: a process that dies inside step 4, after
	// RemovePending's RemoveAll unlinked pending.yaml and before it removed
	// the entry, leaves an entry with no pending.yaml beside the record, the
	// keys in the instance. ResumeAdoption finishes it, and can itself stop
	// there and run again.
	t.Run("stopped inside the entry's removal", func(t *testing.T) {
		d := pendingDir(t)
		anchors := verifiedEntry(t, d, "atlas")
		clear := stopBefore(t, adoptRemove)
		if err := d.AdoptPending("atlas", adoptMeta("atlas")); !errors.Is(err, errInjected) {
			t.Fatal(err)
		}
		clear()
		if err := os.Remove(filepath.Join(d.PendingDir(), "atlas", pendingFile)); err != nil {
			t.Fatal(err)
		}
		if err := d.PendingOnly("atlas"); !errors.Is(err, ErrInstanceRecorded) {
			t.Errorf("PendingOnly beside the record = %v; want ErrInstanceRecorded", err)
		}
		clear = stopBefore(t, adoptRemove)
		before := tree(t, string(d))
		if err := d.ResumeAdoption("atlas"); !errors.Is(err, errInjected) {
			t.Fatalf("ResumeAdoption = %v; want the injected stop", err)
		}
		if after := tree(t, string(d)); !mapsEqual(before, after) {
			t.Error("a stopped ResumeAdoption changed the config dir")
		}
		clear()
		if err := d.ResumeAdoption("atlas"); err != nil {
			t.Fatalf("ResumeAdoption of an entry with no pending.yaml beside the record: %v", err)
		}
		handedOver(t, d, "atlas", anchors)
	})
}

// ADR 0024 M3b.2 (the fix round's F2): an entry with no pending.yaml is
// finished by ResumeAdoption only as the hand-off's step 4 stopped inside
// its removal: beside a record of this instance that CheckedIdentity passes,
// with no identity/ left in it. Anything else is refused with nothing
// changed, and an entry with no record beside it stays abandonable.
func TestResumeAdoptionOfAnEntryWithNoRecord(t *testing.T) {
	gone := func(t *testing.T, d Dir) {
		t.Helper()
		if err := os.Remove(filepath.Join(d.PendingDir(), "atlas", pendingFile)); err != nil {
			t.Fatal(err)
		}
	}
	record := func(t *testing.T, d Dir, m *InstanceMetadata) {
		t.Helper()
		if err := d.CreateInstance("atlas"); err != nil {
			t.Fatal(err)
		}
		if err := d.SaveInstanceMetadata("atlas", m); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, d Dir)
		want  error
		text  string
	}{
		{"no record: a CreatePending that stopped before its write", func(t *testing.T, d Dir) {
			if err := d.CreatePending("atlas", validPending("atlas")); err != nil {
				t.Fatal(err)
			}
			gone(t, d)
		}, fs.ErrNotExist, "abandoned, not handed off"},
		{"keys left in the entry", func(t *testing.T, d Dir) {
			verifiedEntry(t, d, "atlas")
			gone(t, d)
			record(t, d, adoptMeta("atlas"))
		}, fs.ErrNotExist, "still holds an identity/"},
		{"a record naming another instance", func(t *testing.T, d Dir) {
			if err := d.CreatePending("atlas", validPending("atlas")); err != nil {
				t.Fatal(err)
			}
			gone(t, d)
			m := adoptMeta("atlas")
			m.Name = "bravo"
			record(t, d, m)
		}, ErrAdoptionMismatch, "name differs"},
		{"a record with no identity", func(t *testing.T, d Dir) {
			if err := d.CreatePending("atlas", validPending("atlas")); err != nil {
				t.Fatal(err)
			}
			gone(t, d)
			m := adoptMeta("atlas")
			m.Identity = nil
			record(t, d, m)
		}, ErrNoIdentity, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := pendingDir(t)
			tc.setup(t, d)
			before := tree(t, string(d))
			err := d.ResumeAdoption("atlas")
			if !errors.Is(err, tc.want) || errors.Is(err, ErrNoPending) || !strings.Contains(err.Error(), tc.text) {
				t.Errorf("ResumeAdoption = %v; want %v saying %q", err, tc.want, tc.text)
			}
			if after := tree(t, string(d)); !mapsEqual(before, after) {
				t.Error("a refused ResumeAdoption changed the config dir")
			}
		})
	}
	t.Run("no record, then abandoned", func(t *testing.T) {
		d := pendingDir(t)
		if err := d.CreatePending("atlas", validPending("atlas")); err != nil {
			t.Fatal(err)
		}
		gone(t, d)
		if err := d.PendingOnly("atlas"); err != nil {
			t.Fatalf("PendingOnly = %v", err)
		}
		if err := d.RemovePending("atlas"); err != nil {
			t.Fatalf("RemovePending = %v", err)
		}
		if ok, err := d.PendingExists("atlas"); ok || err != nil {
			t.Errorf("the entry is still there: %v, %v", ok, err)
		}
	})
}

// ADR 0024 M3b.2: a recorded instance with no pending entry has no hand-off
// to resume, whatever its record holds, an M2-shape record with no identity
// among them: ResumeAdoption is ErrNoPending, and changes nothing.
func TestResumeAdoptionOfARecordWithNoEntry(t *testing.T) {
	for what, edit := range map[string]func(*InstanceMetadata){
		"a whole hand-off":          func(*InstanceMetadata) {},
		"no identity":               func(m *InstanceMetadata) { m.Identity = nil },
		"another instance's name":   func(m *InstanceMetadata) { m.Name = "bravo" },
		"an identity out of shape":  func(m *InstanceMetadata) { m.Identity.Pool = "../" + longID('0')[3:] },
		"a status of a running one": func(m *InstanceMetadata) { m.Status = InstanceRunning },
	} {
		t.Run(what, func(t *testing.T) {
			d := pendingDir(t)
			m := adoptMeta("atlas")
			edit(m)
			if err := d.CreateInstance("atlas"); err != nil {
				t.Fatal(err)
			}
			if err := d.SaveInstanceMetadata("atlas", m); err != nil {
				t.Fatal(err)
			}
			before := tree(t, string(d))
			if err := d.ResumeAdoption("atlas"); !errors.Is(err, ErrNoPending) {
				t.Errorf("ResumeAdoption with no pending entry = %v; want ErrNoPending", err)
			}
			if after := tree(t, string(d)); !mapsEqual(before, after) {
				t.Error("ResumeAdoption with no pending entry changed the config dir")
			}
		})
	}
}

// ADR 0024 M3b.2 (the fix round's F4): an abandon after an AdoptPending that
// stopped after its first step, which left an instance directory holding no
// record, removes that directory with the entry, so the name is free for a
// new install; and the abandon leaves anything else in instances/ as it is.
func TestAbandonRemovesAnUnrecordedInstanceDirectory(t *testing.T) {
	for _, temp := range []bool{false, true} {
		name := "empty"
		if temp {
			name = "holding a record's temporary file"
		}
		t.Run(name, func(t *testing.T) {
			d := pendingDir(t)
			verifiedEntry(t, d, "atlas")
			clear := stopBefore(t, adoptRecord)
			if err := d.AdoptPending("atlas", adoptMeta("atlas")); !errors.Is(err, errInjected) {
				t.Fatal(err)
			}
			clear()
			if temp {
				if err := os.WriteFile(filepath.Join(d.InstancePath("atlas"), recordTempPrefix+"123456"), []byte("name: atl"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := d.PendingOnly("atlas"); err != nil {
				t.Fatalf("PendingOnly = %v", err)
			}
			if err := d.RemovePending("atlas"); err != nil {
				t.Fatalf("RemovePending = %v", err)
			}
			if ok, err := d.InstanceExists("atlas"); ok || err != nil {
				t.Errorf("the instance directory is still there: %v, %v", ok, err)
			}
			if names, err := d.ListInstances(); err != nil || slices.Contains(names, "atlas") {
				t.Errorf("ListInstances = %v, %v", names, err)
			}
			if err := d.CreatePending("atlas", validPending("atlas")); err != nil {
				t.Errorf("a new pending install of the abandoned name: %v", err)
			}
		})
	}
	t.Run("an instance directory holding something else", func(t *testing.T) {
		d := pendingDir(t)
		if err := d.CreatePending("atlas", validPending("atlas")); err != nil {
			t.Fatal(err)
		}
		if err := d.CreateInstance("atlas"); err != nil {
			t.Fatal(err)
		}
		note := filepath.Join(d.InstancePath("atlas"), "note")
		if err := os.WriteFile(note, []byte("someone's"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := d.RemovePending("atlas"); err != nil {
			t.Fatalf("RemovePending = %v", err)
		}
		if _, err := os.Lstat(note); err != nil {
			t.Errorf("the abandon removed what the instance directory held: %v", err)
		}
	})
	t.Run("a linked instances/", func(t *testing.T) {
		d := pendingDir(t)
		if err := d.CreatePending("atlas", validPending("atlas")); err != nil {
			t.Fatal(err)
		}
		elsewhere := t.TempDir()
		if err := os.Mkdir(filepath.Join(elsewhere, "atlas"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, filepath.Join(string(d), "instances")); err != nil {
			t.Fatal(err)
		}
		before := tree(t, elsewhere)
		if err := d.RemovePending("atlas"); err != nil {
			t.Fatalf("RemovePending = %v", err)
		}
		if after := tree(t, elsewhere); !mapsEqual(before, after) {
			t.Error("the abandon removed something through a linked instances/")
		}
	})
	t.Run("a linked instance directory", func(t *testing.T) {
		d := pendingDir(t)
		if err := d.CreatePending("atlas", validPending("atlas")); err != nil {
			t.Fatal(err)
		}
		elsewhere := t.TempDir()
		if err := os.Mkdir(filepath.Join(string(d), "instances"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, d.InstancePath("atlas")); err != nil {
			t.Fatal(err)
		}
		if err := d.RemovePending("atlas"); err != nil {
			t.Fatalf("RemovePending = %v", err)
		}
		if _, err := os.Lstat(d.InstancePath("atlas")); err != nil {
			t.Errorf("the abandon removed a link in place of the instance directory: %v", err)
		}
		if _, err := os.Stat(elsewhere); err != nil {
			t.Errorf("what the link points at went: %v", err)
		}
	})
}

// ADR 0024 M3b.2 (the fix round's F6): a device add's entry hands its
// record off at running, the instance being there already.
func TestAdoptPendingOfADeviceAdd(t *testing.T) {
	d := pendingDir(t)
	anchors := verifiedEntry(t, d, "atlas")
	p, err := d.LoadPending("atlas")
	if err != nil {
		t.Fatal(err)
	}
	p.Kind = PendingDeviceAdd
	if err := d.SavePending("atlas", p); err != nil {
		t.Fatal(err)
	}
	m := adoptMeta("atlas")
	m.Status = InstanceRunning
	if err := d.AdoptPending("atlas", m); err != nil {
		t.Fatalf("AdoptPending of a device add: %v", err)
	}
	meta, err := d.LoadInstanceMetadata("atlas")
	if err != nil {
		t.Fatal(err)
	}
	if meta.Status != InstanceRunning || !sameIdentity(meta.Identity, validIdentity()) {
		t.Errorf("the device add's record = status %q, identity %+v", meta.Status, meta.Identity)
	}
	if ok, err := d.PendingExists("atlas"); ok || err != nil {
		t.Errorf("the entry is still pending: %v, %v", ok, err)
	}
	dir, err := d.InstanceIdentityDir("atlas")
	if err != nil {
		t.Fatal(err)
	}
	store, err := devicekey.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range []devicekey.Role{devicekey.Reader, devicekey.Writer} {
		if c, err := store.CurrentCertificates(r); err != nil || !bytes.Equal(c.AnchorDER(), anchors[i]) {
			t.Errorf("the %s anchor in the instance is not the one enrolled: %v", r, err)
		}
	}
}

// ADR 0024 M3b.2: ResumeAdoption can itself stop before each of its steps,
// and run again finishes the hand-off.
func TestResumeAdoptionIsResumable(t *testing.T) {
	for _, step := range []string{adoptIdentity, adoptRemove} {
		t.Run("stopped before "+step, func(t *testing.T) {
			d := pendingDir(t)
			anchors := verifiedEntry(t, d, "atlas")
			stopBefore(t, adoptIdentity)
			if err := d.AdoptPending("atlas", adoptMeta("atlas")); !errors.Is(err, errInjected) {
				t.Fatal(err)
			}
			clear := stopBefore(t, step)
			if err := d.ResumeAdoption("atlas"); !errors.Is(err, errInjected) {
				t.Fatalf("ResumeAdoption = %v; want the injected stop", err)
			}
			clear()
			if err := d.ResumeAdoption("atlas"); err != nil {
				t.Fatal(err)
			}
			handedOver(t, d, "atlas", anchors)
		})
	}
}

// ADR 0024 M3b.2: AdoptPending refuses, before its first step and with
// nothing changed, a hand-off that is not this entry's or that would put
// keys where keys or a record already are; ResumeAdoption refuses a record
// that is another install's, and keys in both places.
func TestAdoptPendingRefusals(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, d Dir)
		meta  func() *InstanceMetadata
		want  error  // a sentinel, or nil to match text
		text  string // in the error
	}{
		{"no pending entry", func(*testing.T, Dir) {}, func() *InstanceMetadata { return adoptMeta("bravo") }, ErrNoPending, ""},
		{"no record", nil, func() *InstanceMetadata { return nil }, nil, "no instance record"},
		{"a record naming another instance", nil, func() *InstanceMetadata { return adoptMeta("bravo") }, nil, "names another instance"},
		{"a status other than provisioning", nil, func() *InstanceMetadata {
			m := adoptMeta("atlas")
			m.Status = InstanceRunning
			return m
		}, nil, "pending install: the record's status is not provisioning"},
		{"no identity", nil, func() *InstanceMetadata {
			m := adoptMeta("atlas")
			m.Identity = nil
			return m
		}, ErrNoIdentity, ""},
		{"an identity out of shape", nil, func() *InstanceMetadata {
			m := adoptMeta("atlas")
			m.Identity.Pool = "../" + longID('0')[3:]
			return m
		}, ErrIdentityRecord, "identity.pool"},
		{"another project", nil, func() *InstanceMetadata {
			m := adoptMeta("atlas")
			m.Project = "proj-test2"
			return m
		}, ErrAdoptionMismatch, "project differs"},
		{"another pool", nil, func() *InstanceMetadata {
			m := adoptMeta("atlas")
			m.Identity.Pool = longID('9')
			return m
		}, ErrAdoptionMismatch, "identity.pool differs"},
		{"another reader provider", nil, func() *InstanceMetadata {
			m := adoptMeta("atlas")
			m.Identity.Roles[0].Provider = longID('9')
			return m
		}, ErrAdoptionMismatch, "the reader's provider differs"},
		{"another writer account", nil, func() *InstanceMetadata {
			m := adoptMeta("atlas")
			m.Identity.WriterAccount = shortID('9')
			return m
		}, ErrAdoptionMismatch, "identity.writer_account differs"},
		{"another project number", nil, func() *InstanceMetadata {
			m := adoptMeta("atlas")
			m.Identity.ProjectNumber = "999"
			return m
		}, ErrAdoptionMismatch, "identity.project_number differs"},
		{"another reader account", nil, func() *InstanceMetadata {
			m := adoptMeta("atlas")
			m.Identity.ReaderAccount = shortID('9')
			return m
		}, ErrAdoptionMismatch, "identity.reader_account differs"},
		{"another node account", nil, func() *InstanceMetadata {
			m := adoptMeta("atlas")
			m.Identity.NodeAccount = shortID('9')
			return m
		}, ErrAdoptionMismatch, "identity.node_account differs"},
		{"another condition title", nil, func() *InstanceMetadata {
			m := adoptMeta("atlas")
			m.Identity.ConditionTitle = shortID('9')
			return m
		}, ErrAdoptionMismatch, "identity.condition_title differs"},
		{"another writer provider", nil, func() *InstanceMetadata {
			m := adoptMeta("atlas")
			m.Identity.Roles[1].Provider = longID('9')
			return m
		}, ErrAdoptionMismatch, "the writer's provider differs"},
		// The fix round's S1: an entry is handed off only once its enrolment
		// is recorded as verified, while it holds keys or the record puts a
		// role on the certificate route; else the keys would move with their
		// enrolment windows open, and the instance's writer open with no
		// consent.
		{"an entry at keys_made", editPending(func(p *Pending) { p.State, p.ProjectNumber = PendingKeysMade, "" }),
			func() *InstanceMetadata { return adoptMeta("atlas") }, ErrPendingUnverified, "it is at keys_made"},
		{"an entry at setup_shown", editPending(func(p *Pending) { p.State, p.ProjectNumber = PendingSetupShown, "" }),
			func() *InstanceMetadata { return adoptMeta("atlas") }, ErrPendingUnverified, "it is at setup_shown"},
		{"an entry at coordinates_received", editPending(func(p *Pending) { p.State = PendingCoordinatesReceived }),
			func() *InstanceMetadata { return adoptMeta("atlas") }, ErrPendingUnverified, "it is at coordinates_received"},
		{"an unverified entry holding keys, with no role on the certificate route", editPending(func(p *Pending) {
			p.State, p.Route = PendingCoordinatesReceived, RouteUploadedKey
			p.Draw.ReaderProvider, p.Draw.WriterProvider = "", ""
		}), func() *InstanceMetadata {
			m := adoptMeta("atlas")
			m.Identity.Roles = []DeviceRole{{Role: RoleReader, Route: RouteUploadedKey}, {Role: RoleWriter, Route: RouteGoogleMadeKey}}
			return m
		}, ErrPendingUnverified, "it is at coordinates_received"},
		// The fix round's F6: an install's record is provisioning, a device
		// add's running, its instance being there already.
		{"a device add's record at provisioning", editPending(func(p *Pending) { p.Kind = PendingDeviceAdd }),
			func() *InstanceMetadata { return adoptMeta("atlas") }, nil, "pending device_add: the record's status is not running"},
		{"an instance directory holding another file", func(t *testing.T, d Dir) {
			if err := d.CreateInstance("atlas"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(d.InstancePath("atlas"), ".tmp-"+credentialsFile+"-1"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}, func() *InstanceMetadata { return adoptMeta("atlas") }, ErrInstanceRecorded, "holds something already"},
		{"an instance directory holding a link named as a record's temporary file", func(t *testing.T, d Dir) {
			if err := d.CreateInstance("atlas"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(t.TempDir(), filepath.Join(d.InstancePath("atlas"), recordTempPrefix+"1")); err != nil {
				t.Fatal(err)
			}
		}, func() *InstanceMetadata { return adoptMeta("atlas") }, ErrInstanceRecorded, "holds something already"},
		{"an instance directory holding something", func(t *testing.T, d Dir) {
			if err := os.MkdirAll(filepath.Join(d.InstancePath("atlas"), identitySubdir), 0o700); err != nil {
				t.Fatal(err)
			}
		}, func() *InstanceMetadata { return adoptMeta("atlas") }, ErrInstanceRecorded, "holds something already"},
		{"an instance record", func(t *testing.T, d Dir) {
			if err := d.CreateInstance("atlas"); err != nil {
				t.Fatal(err)
			}
			if err := d.SaveInstanceMetadata("atlas", adoptMeta("atlas")); err != nil {
				t.Fatal(err)
			}
		}, func() *InstanceMetadata { return adoptMeta("atlas") }, ErrInstanceRecorded, ""},
		{"a linked instances/", func(t *testing.T, d Dir) {
			if err := os.Symlink(t.TempDir(), filepath.Join(string(d), "instances")); err != nil {
				t.Fatal(err)
			}
		}, func() *InstanceMetadata { return adoptMeta("atlas") }, ErrUnsafePath, ""},
		{"a widened instance directory", func(t *testing.T, d Dir) {
			if err := os.Mkdir(filepath.Join(string(d), "instances"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(d.InstancePath("atlas"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(d.InstancePath("atlas"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, func() *InstanceMetadata { return adoptMeta("atlas") }, ErrUnsafePath, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := pendingDir(t)
			// The entry first: CreatePending refuses a name with an
			// instance directory, which some setups make.
			verifiedEntry(t, d, "atlas")
			if tc.setup != nil {
				tc.setup(t, d)
			}
			before := tree(t, string(d))
			name := "atlas"
			if tc.name == "no pending entry" {
				name = "bravo"
			}
			err := d.AdoptPending(name, tc.meta())
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) || !strings.Contains(err.Error(), tc.text) {
				t.Fatalf("AdoptPending = %v; want %v saying %q", err, tc.want, tc.text)
			}
			if after := tree(t, string(d)); !mapsEqual(before, after) {
				t.Error("a refused AdoptPending changed the config dir")
			}
		})
	}

	t.Run("a certificate route with no keys", func(t *testing.T) {
		d := pendingDir(t)
		p := validPending("atlas")
		if err := d.CreatePending("atlas", p); err != nil {
			t.Fatal(err)
		}
		before := tree(t, string(d))
		if err := d.AdoptPending("atlas", adoptMeta("atlas")); err == nil || !strings.Contains(err.Error(), "holds no identity/") {
			t.Errorf("AdoptPending with no keys = %v; want a refusal", err)
		}
		if after := tree(t, string(d)); !mapsEqual(before, after) {
			t.Error("the refusal changed the config dir")
		}
		// Recorded as verified, it is refused all the same: the record would
		// name keys that are not there.
		p.State, p.ProjectNumber = PendingVerified, "123456789012"
		if err := d.SavePending("atlas", p); err != nil {
			t.Fatal(err)
		}
		before = tree(t, string(d))
		if err := d.AdoptPending("atlas", adoptMeta("atlas")); err == nil || !strings.Contains(err.Error(), "holds no identity/") {
			t.Errorf("AdoptPending of a verified entry with no keys = %v; want a refusal", err)
		}
		if after := tree(t, string(d)); !mapsEqual(before, after) {
			t.Error("the refusal changed the config dir")
		}
		// A fallback route keeps no keys in identity/, and hands off with none.
		m := adoptMeta("atlas")
		m.Identity = &Identity{Pool: longID('0'), ReaderAccount: shortID('1'), WriterAccount: shortID('2'), NodeAccount: shortID('3'),
			ConditionTitle: shortID('4'), Roles: []DeviceRole{{Role: RoleWriter, Route: RouteGoogleMadeKey}, {Role: RoleReader, Route: RouteNone}}}
		p.Route, p.ProjectNumber = RouteGoogleMadeKey, ""
		p.Draw.ReaderProvider, p.Draw.WriterProvider = "", ""
		if err := d.SavePending("atlas", p); err != nil {
			t.Fatal(err)
		}
		if err := d.AdoptPending("atlas", m); err != nil {
			t.Fatalf("a fallback 3 hand-off: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(d.InstancePath("atlas"), identitySubdir)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("a hand-off with no keys made identity/: %v", err)
		}
		if ok, _ := d.PendingExists("atlas"); ok {
			t.Error("the entry is still pending")
		}
	})

	t.Run("ResumeAdoption with keys in both places", func(t *testing.T) {
		d := pendingDir(t)
		verifiedEntry(t, d, "atlas")
		stopBefore(t, adoptIdentity)
		if err := d.AdoptPending("atlas", adoptMeta("atlas")); !errors.Is(err, errInjected) {
			t.Fatal(err)
		}
		adoptFault.Store(nil)
		if err := os.Mkdir(filepath.Join(d.InstancePath("atlas"), identitySubdir), 0o700); err != nil {
			t.Fatal(err)
		}
		before := tree(t, string(d))
		if err := d.ResumeAdoption("atlas"); err == nil || !strings.Contains(err.Error(), "is there already") {
			t.Errorf("ResumeAdoption with keys in both places = %v; want a refusal", err)
		}
		if after := tree(t, string(d)); !mapsEqual(before, after) {
			t.Error("the refusal moved something")
		}
	})

	t.Run("ResumeAdoption of another install's record", func(t *testing.T) {
		d := pendingDir(t)
		verifiedEntry(t, d, "atlas")
		if err := d.CreateInstance("atlas"); err != nil {
			t.Fatal(err)
		}
		other := adoptMeta("atlas")
		other.Identity.Pool = longID('9')
		if err := d.SaveInstanceMetadata("atlas", other); err != nil {
			t.Fatal(err)
		}
		before := tree(t, string(d))
		if err := d.ResumeAdoption("atlas"); !errors.Is(err, ErrAdoptionMismatch) {
			t.Errorf("ResumeAdoption into another install's record = %v; want ErrAdoptionMismatch", err)
		}
		if after := tree(t, string(d)); !mapsEqual(before, after) {
			t.Error("the refusal moved something")
		}
	})

	t.Run("ResumeAdoption of a record naming another instance", func(t *testing.T) {
		d := pendingDir(t)
		verifiedEntry(t, d, "atlas")
		if err := d.CreateInstance("atlas"); err != nil {
			t.Fatal(err)
		}
		m := adoptMeta("atlas")
		m.Name = "bravo"
		if err := d.SaveInstanceMetadata("atlas", m); err != nil {
			t.Fatal(err)
		}
		before := tree(t, string(d))
		if err := d.ResumeAdoption("atlas"); !errors.Is(err, ErrAdoptionMismatch) || !strings.Contains(err.Error(), "name differs") {
			t.Errorf("ResumeAdoption into a record naming another instance = %v; want ErrAdoptionMismatch", err)
		}
		if after := tree(t, string(d)); !mapsEqual(before, after) {
			t.Error("the refusal moved something")
		}
	})

	// The fix round's S1: ResumeAdoption refuses an entry not recorded as
	// verified as AdoptPending does, by the record's certificate route alone
	// once the keys have moved, and by the keys still in the entry before.
	for _, step := range []string{adoptIdentity, adoptRemove} {
		t.Run("ResumeAdoption of an unverified entry, stopped before "+step, func(t *testing.T) {
			d := pendingDir(t)
			verifiedEntry(t, d, "atlas")
			stopBefore(t, step)
			if err := d.AdoptPending("atlas", adoptMeta("atlas")); !errors.Is(err, errInjected) {
				t.Fatal(err)
			}
			adoptFault.Store(nil)
			editPending(func(p *Pending) { p.State = PendingCoordinatesReceived })(t, d)
			before := tree(t, string(d))
			if err := d.ResumeAdoption("atlas"); !errors.Is(err, ErrPendingUnverified) {
				t.Errorf("ResumeAdoption of an unverified entry = %v; want ErrPendingUnverified", err)
			}
			if after := tree(t, string(d)); !mapsEqual(before, after) {
				t.Error("the refusal moved something")
			}
		})
	}

	// The certificate route of any role, not only the last one's, keeps an
	// unverified entry from being handed off once its keys have moved.
	t.Run("ResumeAdoption of an unverified entry whose certificate role is not its last", func(t *testing.T) {
		d := pendingDir(t)
		verifiedEntry(t, d, "atlas")
		editPending(func(p *Pending) { p.Draw.WriterProvider = "" })(t, d)
		m := adoptMeta("atlas")
		m.Identity.Roles[1] = DeviceRole{Role: RoleWriter, Route: RouteGoogleMadeKey}
		stopBefore(t, adoptRemove)
		if err := d.AdoptPending("atlas", m); !errors.Is(err, errInjected) {
			t.Fatal(err)
		}
		adoptFault.Store(nil)
		editPending(func(p *Pending) { p.State = PendingCoordinatesReceived })(t, d)
		before := tree(t, string(d))
		if err := d.ResumeAdoption("atlas"); !errors.Is(err, ErrPendingUnverified) {
			t.Errorf("ResumeAdoption of an unverified entry = %v; want ErrPendingUnverified", err)
		}
		if after := tree(t, string(d)); !mapsEqual(before, after) {
			t.Error("the refusal moved something")
		}
	})

	t.Run("ResumeAdoption of a record with no identity", func(t *testing.T) {
		d := pendingDir(t)
		verifiedEntry(t, d, "atlas")
		if err := d.CreateInstance("atlas"); err != nil {
			t.Fatal(err)
		}
		m := adoptMeta("atlas")
		m.Identity = nil
		if err := d.SaveInstanceMetadata("atlas", m); err != nil {
			t.Fatal(err)
		}
		if err := d.ResumeAdoption("atlas"); !errors.Is(err, ErrNoIdentity) {
			t.Errorf("ResumeAdoption into a record with no identity = %v; want ErrNoIdentity", err)
		}
	})
}

// mapsEqual compares two trees.
func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}
