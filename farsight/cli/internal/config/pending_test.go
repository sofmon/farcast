package config

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/sofmon/farcast/farsight/cli/internal/devicekey"
)

// validPending is a pending install of name on the certificate route, its
// IDs drawn as validIdentity's are.
func validPending(name string) *Pending {
	return &Pending{
		Kind:      PendingInstall,
		Name:      name,
		Provider:  "gke",
		Project:   "proj-test1",
		Region:    "us-central1",
		CostLimit: CostLimit{Amount: 50, Currency: "USD", Period: "monthly"},
		CreatedAt: time.Date(2026, 11, 26, 8, 0, 0, 0, time.UTC),
		State:     PendingKeysMade,
		Draw: PendingDraw{
			Pool: longID('0'), ReaderProvider: longID('1'), WriterProvider: longID('2'),
			ReaderAccount: shortID('1'), WriterAccount: shortID('2'), NodeAccount: shortID('3'),
			ConditionTitle: shortID('4'),
		},
		Route: RouteCertificate,
	}
}

// pendingDir is a config dir that exists, at 0700.
func pendingDir(t *testing.T) Dir {
	t.Helper()
	d := testDir(t)
	if err := d.Ensure(); err != nil {
		t.Fatal(err)
	}
	return d
}

// samePending compares two records, the creation time by its instant.
func samePending(a, b *Pending) bool {
	x, y := *a, *b
	if !x.CreatedAt.Equal(y.CreatedAt) {
		return false
	}
	x.CreatedAt, y.CreatedAt = time.Time{}, time.Time{}
	return reflect.DeepEqual(x, y)
}

// tree is every path under root, each with its mode, for a test to show a
// refused call changed nothing.
func tree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		v := fi.Mode().String()
		if fi.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			v += " " + string(b)
		}
		out[p] = v
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	return out
}

// ADR 0024 M3b.2: a pending record round-trips through pending.yaml, which is
// 0600 in a 0700 entry in a 0700 pending/, through every state; it is read
// strictly; and the entry holds no identity/ until devicekey makes one.
func TestPendingRoundTrip(t *testing.T) {
	d := pendingDir(t)
	want := validPending("atlas")
	if err := d.CreatePending("atlas", want); err != nil {
		t.Fatal(err)
	}
	assertPerm(t, d.PendingDir(), 0o700)
	assertPerm(t, filepath.Join(d.PendingDir(), "atlas"), 0o700)
	assertPerm(t, filepath.Join(d.PendingDir(), "atlas", pendingFile), 0o600)
	if _, err := os.Lstat(filepath.Join(d.PendingDir(), "atlas", identitySubdir)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("CreatePending made identity/: %v", err)
	}
	got, err := d.LoadPending("atlas")
	if err != nil {
		t.Fatal(err)
	}
	if !samePending(got, want) {
		t.Errorf("round trip = %+v\nwant %+v", got, want)
	}
	for _, state := range []PendingState{PendingSetupShown, PendingCoordinatesReceived, PendingVerified} {
		want.State = state
		if state == PendingCoordinatesReceived {
			want.ProjectNumber = "123456789012"
		}
		if err := d.SavePending("atlas", want); err != nil {
			t.Fatalf("save %s: %v", state, err)
		}
		got, err := d.LoadPending("atlas")
		if err != nil {
			t.Fatal(err)
		}
		if !samePending(got, want) {
			t.Errorf("state %s round-tripped to %+v", state, got)
		}
		assertPerm(t, filepath.Join(d.PendingDir(), "atlas", pendingFile), 0o600)
	}
	// A device add, and each fallback route, round-trip too.
	for i, route := range []Route{RoutePublicKey, RouteUploadedKey, RouteGoogleMadeKey} {
		p := validPending("dev" + string(rune('a'+i)))
		p.Kind, p.Route = PendingDeviceAdd, route
		if err := d.CreatePending(p.Name, p); err != nil {
			t.Fatalf("%s: %v", route, err)
		}
		if got, err := d.LoadPending(p.Name); err != nil || !samePending(got, p) {
			t.Errorf("%s: round trip = %+v, %v", route, got, err)
		}
	}

	// Strict: a field this build does not know, and a key given twice.
	path := filepath.Join(d.PendingDir(), "atlas", pendingFile)
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for what, raw := range map[string]string{
		"an unknown field":  string(good) + "extra: 1\n",
		"a key given twice": string(good) + "state: keys_made\n",
		"not YAML":          "{[",
	} {
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if p, err := d.LoadPending("atlas"); p != nil || err == nil {
			t.Errorf("%s: LoadPending = %+v, %v; want a refusal", what, p, err)
		}
	}
}

// ADR 0024 M3b.2: CreatePending makes its entry with one exclusive mkdir:
// a second create of the name is ErrPendingExists and leaves the first's
// record as it was, and of many at once exactly one wins. A name that already
// has an instance directory is never made pending, and a record naming
// another instance is refused, both before anything is made.
func TestCreatePendingIsExclusive(t *testing.T) {
	d := pendingDir(t)
	if err := d.CreatePending("atlas", validPending("atlas")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(d.PendingDir(), "atlas", pendingFile)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	second := validPending("atlas")
	second.Draw.Pool = longID('9')
	if err := d.CreatePending("atlas", second); !errors.Is(err, ErrPendingExists) {
		t.Errorf("a second create = %v; want ErrPendingExists", err)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Error("a refused create changed the first's record")
	}

	var wg sync.WaitGroup
	errs := make([]error, 16)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := validPending("race")
			p.Draw.Pool = longID(byte('a' + i))
			errs[i] = d.CreatePending("race", p)
		}()
	}
	wg.Wait()
	won := 0
	for _, err := range errs {
		switch {
		case err == nil:
			won++
		case !errors.Is(err, ErrPendingExists):
			t.Errorf("a racing create failed otherwise: %v", err)
		}
	}
	if won != 1 {
		t.Errorf("%d of %d racing creates made the entry; want exactly one", won, len(errs))
	}
	if _, err := d.LoadPending("race"); err != nil {
		t.Errorf("the winner's record does not load: %v", err)
	}

	if err := d.CreateInstance("taken"); err != nil {
		t.Fatal(err)
	}
	if err := d.CreatePending("taken", validPending("taken")); !errors.Is(err, ErrInstanceRecorded) {
		t.Errorf("a recorded name made pending: %v", err)
	}
	if err := d.CreatePending("other", validPending("atlas")); !errors.Is(err, ErrPendingRecord) {
		t.Errorf("a record naming another instance: %v", err)
	}
	// No record at all is no record farcast writes.
	if err := d.CreatePending("none", nil); !errors.Is(err, ErrPendingRecord) {
		t.Errorf("CreatePending of no record = %v; want ErrPendingRecord", err)
	}
	if err := d.SavePending("atlas", nil); !errors.Is(err, ErrPendingRecord) {
		t.Errorf("SavePending of no record = %v; want ErrPendingRecord", err)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Error("a refused save of no record changed the record")
	}
	for _, name := range []string{"taken", "other", "none"} {
		if _, err := os.Lstat(filepath.Join(d.PendingDir(), name)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("a refused create left pending/%s: %v", name, err)
		}
	}
}

// ADR 0024 M3b.2: a pending entry is never an instance. ListInstances lists
// instances/ alone, whatever pending/ holds, and ListPending lists pending/
// alone, passing over a file or a directory whose name install would refuse,
// and refusing a symbolic link.
func TestListInstancesNeverListsAPendingEntry(t *testing.T) {
	d := pendingDir(t)
	for _, n := range []string{"bravo", "alpha"} {
		if err := d.CreatePending(n, validPending(n)); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.CreateInstance("prod"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d.PendingDir(), ".DS_Store"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// A file is no entry, even under a name install would accept.
	if err := os.WriteFile(filepath.Join(d.PendingDir(), "delta"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(d.PendingDir(), "Bad"), 0o700); err != nil {
		t.Fatal(err)
	}
	instances, err := d.ListInstances()
	if err != nil || !slices.Equal(instances, []string{"prod"}) {
		t.Errorf("ListInstances = %v, %v; want only the instance", instances, err)
	}
	pending, err := d.ListPending()
	if err != nil || !slices.Equal(pending, []string{"alpha", "bravo"}) {
		t.Errorf("ListPending = %v, %v; want the two entries, sorted", pending, err)
	}
	if exists, err := d.InstanceExists("alpha"); err != nil || exists {
		t.Errorf("a pending entry is an instance: %v, %v", exists, err)
	}
	if _, err := d.LoadInstanceMetadata("alpha"); !errors.Is(err, ErrNoInstanceRecord) {
		t.Errorf("a pending entry loaded as a record: %v", err)
	}

	if err := os.Symlink(filepath.Join(d.PendingDir(), "alpha"), filepath.Join(d.PendingDir(), "charlie")); err != nil {
		t.Fatal(err)
	}
	if got, err := d.ListPending(); !errors.Is(err, ErrUnsafePath) {
		t.Errorf("a symbolic link in pending/ listed as %v, %v", got, err)
	}
	if got, err := testDir(t).ListPending(); err != nil || got != nil {
		t.Errorf("no pending/ = %v, %v; want no entries", got, err)
	}
}

// ADR 0024 M3b.2: every value of a pending record is held to its shape, as the
// instance record's are, and a kind, a state or a route farcast does not
// write is refused: through CreatePending, which then makes nothing, and
// through LoadPending of a record on disk. The refusal names the field and
// does not quote the value.
func TestPendingRefusesEveryHostileShape(t *testing.T) {
	type field struct {
		name, valid string
		set         func(*Pending, string)
	}
	fields := []field{
		{"draw.pool", longID('0'), func(p *Pending, v string) { p.Draw.Pool = v }},
		{"draw.reader_provider", longID('1'), func(p *Pending, v string) { p.Draw.ReaderProvider = v }},
		{"draw.writer_provider", longID('2'), func(p *Pending, v string) { p.Draw.WriterProvider = v }},
		{"draw.reader_account", shortID('1'), func(p *Pending, v string) { p.Draw.ReaderAccount = v }},
		{"draw.writer_account", shortID('2'), func(p *Pending, v string) { p.Draw.WriterAccount = v }},
		{"draw.node_account", shortID('3'), func(p *Pending, v string) { p.Draw.NodeAccount = v }},
		{"draw.condition_title", shortID('4'), func(p *Pending, v string) { p.Draw.ConditionTitle = v }},
	}
	type row struct {
		what, field, value string
		edit               func(*Pending)
	}
	var rows []row
	for _, f := range fields {
		for what, v := range hostileIDs(f.valid) {
			if v == "" {
				continue // a draw not made yet is absent
			}
			rows = append(rows, row{f.name + " " + what, f.name, v, func(p *Pending) { f.set(p, v) }})
		}
	}
	for what, v := range hostileNumbers {
		if v == "" {
			continue
		}
		rows = append(rows, row{"project_number " + what, "project_number", v, func(p *Pending) { p.ProjectNumber = v }})
	}
	for _, v := range []string{"Proj-test1", "proj_test1", "proj/test1", "../proj", "proj-test1-", "1proj-test",
		"proj-test1\x00", "proj-test1\n", "abcde", strings.Repeat("a", 31)} {
		rows = append(rows, row{"project " + v, "project", v, func(p *Pending) { p.Project = v }})
	}
	// A record naming an instance 'farcast install' would refuse is refused
	// as that, not only as naming another instance than its directory.
	for _, v := range []string{"", "Atlas", "../atlas", "atlas\x1b[2J", "atlas-", strings.Repeat("a", 33)} {
		rows = append(rows, row{"name " + v, "name is not one", v, func(p *Pending) { p.Name = v }})
	}
	rows = append(rows,
		row{"an empty kind", "kind", "", func(p *Pending) { p.Kind = "" }},
		row{"another kind", "kind", "", func(p *Pending) { p.Kind = "release" }},
		row{"an empty state", "state", "", func(p *Pending) { p.State = "" }},
		row{"another state", "state", "", func(p *Pending) { p.State = "installed" }},
		row{"the route none", "route", "", func(p *Pending) { p.Route = RouteNone }},
		row{"an unknown route", "route", "", func(p *Pending) { p.Route = "certificates" }},
		row{"an empty route", "route", "", func(p *Pending) { p.Route = "" }},
		row{"one provider for both roles", "one provider for both roles", "", func(p *Pending) { p.Draw.WriterProvider = p.Draw.ReaderProvider }},
		row{"the reader's account as the writer's", "the reader's account", "", func(p *Pending) { p.Draw.WriterAccount = p.Draw.ReaderAccount }},
		row{"the writer's account as the nodes'", "the writer's account", "", func(p *Pending) { p.Draw.NodeAccount = p.Draw.WriterAccount }},
	)
	for _, r := range rows {
		d := pendingDir(t)
		p := validPending("atlas")
		r.edit(p)
		err := d.CreatePending("atlas", p)
		if !errors.Is(err, ErrPendingRecord) || !strings.Contains(err.Error(), r.field) {
			t.Errorf("%s: CreatePending = %v; want ErrPendingRecord naming %s", r.what, err, r.field)
		}
		if _, serr := os.Lstat(filepath.Join(d.PendingDir(), "atlas")); !errors.Is(serr, fs.ErrNotExist) {
			t.Errorf("%s: a refused create made the entry", r.what)
		}
		// The same record, on disk, is refused when read.
		if err := d.CreatePending("atlas", validPending("atlas")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d.PendingDir(), "atlas", pendingFile), mustMarshal(t, p), 0o600); err != nil {
			t.Fatal(err)
		}
		got, lerr := d.LoadPending("atlas")
		if got != nil || !errors.Is(lerr, ErrPendingRecord) || !strings.Contains(lerr.Error(), r.field) {
			t.Errorf("%s: LoadPending = %+v, %v; want ErrPendingRecord naming %s", r.what, got, lerr, r.field)
		}
		for _, e := range []error{err, lerr} {
			if e != nil && len(r.value) > 3 && strings.Contains(e.Error(), r.value) {
				t.Errorf("%s: the refusal quotes the value: %q", r.what, e)
			}
		}
		// SavePending refuses it too, and leaves the record on disk as it was.
		if err := os.WriteFile(filepath.Join(d.PendingDir(), "atlas", pendingFile), mustMarshal(t, validPending("atlas")), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := d.SavePending("atlas", p); !errors.Is(err, ErrPendingRecord) {
			t.Errorf("%s: SavePending = %v; want ErrPendingRecord", r.what, err)
		}
		if got, err := d.LoadPending("atlas"); err != nil || !samePending(got, validPending("atlas")) {
			t.Errorf("%s: a refused save changed the record: %+v, %v", r.what, got, err)
		}
	}
}

// mustMarshal is p as pending.yaml holds it.
func mustMarshal(t *testing.T, p *Pending) []byte {
	t.Helper()
	b, err := yaml.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// hostileNames are names 'farcast install' refuses, each of which, used as a
// path, would leave pending/ or name something else.
var hostileNames = []string{"", "..", ".", "../instances/victim", "a/b", "/abs", "Atlas", "atlas\x00", "atlas\n",
	"atlas\x1b[2J", "-atlas", "atlas-", "1atlas", "at las", "atlas.", strings.Repeat("a", 33), "atlás"}

// ADR 0024 M3b.2 (decision 4): every function of the pending store, the
// identity paths and the hand-off refuses a name 'farcast install' would
// refuse before it builds a path from it: nothing is read, made, moved or
// removed, a decoy at the path a traversal would reach is untouched, and
// ObserveReads sees no read.
func TestPendingNamesAreCheckedBeforeAnyPath(t *testing.T) {
	d := pendingDir(t)
	victim := filepath.Join(string(d), "instances", "victim")
	if err := os.MkdirAll(filepath.Join(victim, identitySubdir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(victim, pendingFile), mustMarshal(t, validPending("victim")), 0o600); err != nil {
		t.Fatal(err)
	}
	before := tree(t, string(d))
	reads := observeReads(t)
	for _, name := range hostileNames {
		p := validPending("atlas")
		p.Name = name
		calls := map[string]error{
			"CreatePending":  d.CreatePending(name, p),
			"SavePending":    d.SavePending(name, p),
			"RemovePending":  d.RemovePending(name),
			"PendingOnly":    d.PendingOnly(name),
			"AdoptPending":   d.AdoptPending(name, &InstanceMetadata{Name: name, Status: InstanceProvisioning, Identity: validIdentity()}),
			"ResumeAdoption": d.ResumeAdoption(name),
		}
		_, calls["LoadPending"] = d.LoadPending(name)
		_, calls["PendingExists"] = d.PendingExists(name)
		_, calls["PendingIdentityDir"] = d.PendingIdentityDir(name)
		_, calls["InstanceIdentityDir"] = d.InstanceIdentityDir(name)
		for call, err := range calls {
			if err == nil || !strings.Contains(err.Error(), "instance name") {
				t.Errorf("%s(%q) = %v; want the name refused", call, name, err)
			}
		}
	}
	if got := reads(); len(got) != 0 {
		t.Errorf("a refused name read %v", got)
	}
	if after := tree(t, string(d)); !reflect.DeepEqual(before, after) {
		t.Errorf("a refused name changed the config dir:\nbefore %v\nafter  %v", before, after)
	}
}

// ADR 0024 M3b.2 (decision 4): a symbolic link in place of pending/,
// pending/<name>/, pending.yaml or identity/ is refused by every function that
// reaches it, read by Lstat so the link is never followed, and what it points
// at is untouched; a mode other accounts can reach is refused where a key is
// opened or made, and not where an entry is removed.
func TestPendingRefusesSymbolicLinks(t *testing.T) {
	setup := func(t *testing.T) (Dir, string) {
		d := pendingDir(t)
		elsewhere := filepath.Join(t.TempDir(), "elsewhere")
		if err := os.MkdirAll(filepath.Join(elsewhere, "atlas", identitySubdir), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(elsewhere, "atlas", pendingFile), mustMarshal(t, validPending("atlas")), 0o600); err != nil {
			t.Fatal(err)
		}
		return d, elsewhere
	}
	// all is every call refused as ErrUnsafePath; each case names what
	// differs where its link is not on the call's way.
	all := func(differ map[string]error) map[string]error {
		out := map[string]error{}
		for _, c := range []string{"LoadPending", "SavePending", "RemovePending", "PendingIdentityDir", "AdoptPending",
			"ResumeAdoption", "PendingExists", "PendingOnly", "CreatePending", "ListPending"} {
			out[c] = ErrUnsafePath
		}
		for c, e := range differ {
			out[c] = e
		}
		return out
	}
	for _, tc := range []struct {
		name string
		link func(t *testing.T, d Dir, elsewhere string)
		want map[string]error
	}{
		{"pending/", func(t *testing.T, d Dir, elsewhere string) {
			if err := os.Symlink(elsewhere, d.PendingDir()); err != nil {
				t.Fatal(err)
			}
		}, all(nil)},
		{"pending/<name>/", func(t *testing.T, d Dir, elsewhere string) {
			if err := os.Mkdir(d.PendingDir(), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(elsewhere, "atlas"), filepath.Join(d.PendingDir(), "atlas")); err != nil {
				t.Fatal(err)
			}
		}, all(map[string]error{"CreatePending": ErrPendingExists})},
		{"pending.yaml", func(t *testing.T, d Dir, elsewhere string) {
			if err := os.MkdirAll(filepath.Join(d.PendingDir(), "atlas"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(elsewhere, "atlas", pendingFile), filepath.Join(d.PendingDir(), "atlas", pendingFile)); err != nil {
				t.Fatal(err)
			}
		}, all(map[string]error{"PendingIdentityDir": nil, "PendingExists": nil, "PendingOnly": nil, "CreatePending": ErrPendingExists, "ListPending": nil})},
		{"identity/", func(t *testing.T, d Dir, elsewhere string) {
			if err := d.CreatePending("atlas", validPending("atlas")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(elsewhere, "atlas", identitySubdir), filepath.Join(d.PendingDir(), "atlas", identitySubdir)); err != nil {
				t.Fatal(err)
			}
		}, all(map[string]error{"LoadPending": nil, "SavePending": nil, "PendingExists": nil, "PendingOnly": nil, "CreatePending": ErrPendingExists, "ListPending": nil})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, elsewhere := setup(t)
			tc.link(t, d, elsewhere)
			outside := tree(t, elsewhere)
			reads := observeReads(t)
			_, loadErr := d.LoadPending("atlas")
			_, dirErr := d.PendingIdentityDir("atlas")
			_, existsErr := d.PendingExists("atlas")
			_, listErr := d.ListPending()
			got := map[string]error{
				"LoadPending":        loadErr,
				"SavePending":        d.SavePending("atlas", validPending("atlas")),
				"RemovePending":      d.RemovePending("atlas"),
				"PendingIdentityDir": dirErr,
				"AdoptPending":       d.AdoptPending("atlas", adoptMeta("atlas")),
				"ResumeAdoption":     d.ResumeAdoption("atlas"),
				"PendingExists":      existsErr,
				"PendingOnly":        d.PendingOnly("atlas"),
				"CreatePending":      d.CreatePending("atlas", validPending("atlas")),
				"ListPending":        listErr,
			}
			for call, want := range tc.want {
				err := got[call]
				if (want == nil) != (err == nil) || (want != nil && !errors.Is(err, want)) {
					t.Errorf("%s with a link at %s = %v; want %v", call, tc.name, err, want)
				}
				// Refused as the link it is, not as some other unsafe path.
				if errors.Is(want, ErrUnsafePath) && err != nil && !strings.Contains(err.Error(), "symbolic link") {
					t.Errorf("%s with a link at %s = %v; want it named a symbolic link", call, tc.name, err)
				}
			}
			for _, p := range reads() {
				if strings.HasPrefix(p, elsewhere) {
					t.Errorf("read %s through the link", p)
				}
			}
			if after := tree(t, elsewhere); !reflect.DeepEqual(outside, after) {
				t.Errorf("what the link points at changed:\nbefore %v\nafter  %v", outside, after)
			}
			if _, err := os.Lstat(filepath.Join(string(d), "instances", "atlas")); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("a refused hand-off made the instance: %v", err)
			}
		})
	}

	t.Run("a widened mode", func(t *testing.T) {
		d := pendingDir(t)
		if err := d.CreatePending("atlas", validPending("atlas")); err != nil {
			t.Fatal(err)
		}
		entry := filepath.Join(d.PendingDir(), "atlas")
		if err := os.Chmod(entry, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := d.LoadPending("atlas"); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("LoadPending of a widened entry = %v; want ErrUnsafePath", err)
		}
		if _, err := d.PendingIdentityDir("atlas"); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("PendingIdentityDir of a widened entry = %v; want ErrUnsafePath", err)
		}
		if err := d.PendingOnly("atlas"); err != nil {
			t.Errorf("PendingOnly refused a widened entry, which an abandon must still remove: %v", err)
		}
		if err := d.RemovePending("atlas"); err != nil {
			t.Errorf("RemovePending refused a widened entry: %v", err)
		}
		if _, err := os.Lstat(entry); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("the widened entry is still there: %v", err)
		}
	})
}

// ADR 0024 M3b.2 (decision 4): a file in place of pending/, pending/<name>/,
// identity/ or an instance's directory or identity/, and a directory in
// place of pending.yaml, are refused as ErrUnsafePath by every function that
// reaches them, and nothing is changed.
func TestPendingRefusesWhatIsNotADirectoryOrAFile(t *testing.T) {
	file := func(t *testing.T, p string) {
		t.Helper()
		if err := os.WriteFile(p, []byte("not a directory"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, d Dir)
		calls []string
		text  string
	}{
		{"a file in place of pending/", func(t *testing.T, d Dir) { file(t, d.PendingDir()) },
			[]string{"ListPending", "PendingExists", "LoadPending", "SavePending", "PendingIdentityDir", "PendingOnly", "RemovePending", "CreatePending", "AdoptPending", "ResumeAdoption"},
			"is not a directory"},
		{"a file in place of the entry", func(t *testing.T, d Dir) {
			if err := os.Mkdir(d.PendingDir(), 0o700); err != nil {
				t.Fatal(err)
			}
			file(t, filepath.Join(d.PendingDir(), "atlas"))
		}, []string{"PendingExists", "LoadPending", "SavePending", "PendingIdentityDir", "PendingOnly", "RemovePending", "AdoptPending", "ResumeAdoption"},
			"is not a directory"},
		{"a file in place of the entry's identity/", func(t *testing.T, d Dir) {
			if err := d.CreatePending("atlas", validPending("atlas")); err != nil {
				t.Fatal(err)
			}
			file(t, filepath.Join(d.PendingDir(), "atlas", identitySubdir))
		}, []string{"PendingIdentityDir", "RemovePending", "AdoptPending", "ResumeAdoption"}, "is not a directory"},
		{"a directory in place of pending.yaml", func(t *testing.T, d Dir) {
			if err := os.MkdirAll(filepath.Join(d.PendingDir(), "atlas", pendingFile), 0o700); err != nil {
				t.Fatal(err)
			}
		}, []string{"LoadPending", "SavePending", "RemovePending", "AdoptPending", "ResumeAdoption"}, "not a file of its own"},
		{"a file in place of the instance's directory", func(t *testing.T, d Dir) {
			if err := os.Mkdir(filepath.Join(string(d), "instances"), 0o700); err != nil {
				t.Fatal(err)
			}
			file(t, d.InstancePath("atlas"))
		}, []string{"InstanceIdentityDir"}, "is not a directory"},
		{"a file in place of the instance's identity/", func(t *testing.T, d Dir) {
			if err := d.CreateInstance("atlas"); err != nil {
				t.Fatal(err)
			}
			file(t, filepath.Join(d.InstancePath("atlas"), identitySubdir))
		}, []string{"InstanceIdentityDir"}, "is not a directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := pendingDir(t)
			tc.setup(t, d)
			before := tree(t, string(d))
			for _, call := range tc.calls {
				var err error
				switch call {
				case "ListPending":
					_, err = d.ListPending()
				case "PendingExists":
					_, err = d.PendingExists("atlas")
				case "LoadPending":
					_, err = d.LoadPending("atlas")
				case "SavePending":
					err = d.SavePending("atlas", validPending("atlas"))
				case "PendingIdentityDir":
					_, err = d.PendingIdentityDir("atlas")
				case "InstanceIdentityDir":
					_, err = d.InstanceIdentityDir("atlas")
				case "PendingOnly":
					err = d.PendingOnly("atlas")
				case "RemovePending":
					err = d.RemovePending("atlas")
				case "CreatePending":
					err = d.CreatePending("bravo", validPending("bravo"))
				case "AdoptPending":
					err = d.AdoptPending("atlas", adoptMeta("atlas"))
				case "ResumeAdoption":
					err = d.ResumeAdoption("atlas")
				}
				if !errors.Is(err, ErrUnsafePath) || !strings.Contains(err.Error(), tc.text) {
					t.Errorf("%s = %v; want ErrUnsafePath saying %q", call, err, tc.text)
				}
			}
			if after := tree(t, string(d)); !reflect.DeepEqual(before, after) {
				t.Errorf("a refusal changed the config dir:\nbefore %v\nafter  %v", before, after)
			}
		})
	}
}

// ADR 0024 M3b.2 (decision 5): a pending.yaml that names another instance
// than its directory is refused, so a copied or renamed entry is never read
// as the entry it claims to be.
func TestLoadPendingRefusesARecordNamingAnotherInstance(t *testing.T) {
	d := pendingDir(t)
	if err := d.CreatePending("alpha", validPending("alpha")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(d.PendingDir(), "bravo"), 0o700); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(d.PendingDir(), "alpha", pendingFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d.PendingDir(), "bravo", pendingFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if p, err := d.LoadPending("bravo"); p != nil || !errors.Is(err, ErrPendingRecord) || !strings.Contains(err.Error(), "names another instance") {
		t.Errorf("LoadPending of a copied entry = %+v, %v; want ErrPendingRecord", p, err)
	}
	if err := d.SavePending("bravo", validPending("alpha")); !errors.Is(err, ErrPendingRecord) {
		t.Errorf("SavePending of another instance's record = %v; want ErrPendingRecord", err)
	}
}

// ADR 0024 M3b.2: LoadPending reads pending.yaml through readFile, so
// ObserveReads sees it; PendingExists, PendingOnly, ListPending and the
// identity paths read no file at all.
func TestObserveReadsSeesPendingYAML(t *testing.T) {
	d := pendingDir(t)
	if err := d.CreatePending("atlas", validPending("atlas")); err != nil {
		t.Fatal(err)
	}
	reads := observeReads(t)
	if _, err := d.PendingExists("atlas"); err != nil {
		t.Fatal(err)
	}
	if err := d.PendingOnly("atlas"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ListPending(); err != nil {
		t.Fatal(err)
	}
	if _, err := d.PendingIdentityDir("atlas"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.InstanceIdentityDir("atlas"); err != nil {
		t.Fatal(err)
	}
	if got := reads(); len(got) != 0 {
		t.Errorf("the stat-only functions read %v", got)
	}
	if _, err := d.LoadPending("atlas"); err != nil {
		t.Fatal(err)
	}
	if got, want := reads(), []string{filepath.Join(d.PendingDir(), "atlas", pendingFile)}; !slices.Equal(got, want) {
		t.Errorf("LoadPending read %v; want %v", got, want)
	}
}

// ADR 0024 M3b.2 (decision 6): PendingOnly, the abandon precondition, holds
// for a pending entry with no record, an empty instance directory beside it
// included, and refuses a name with no entry and a name with a record.
// PendingExists says whether there is an entry, and RemovePending removes the
// entry with its keys and refuses a name with none.
func TestPendingOnlyAndRemovePending(t *testing.T) {
	d := pendingDir(t)
	if err := d.PendingOnly("atlas"); !errors.Is(err, ErrNoPending) || !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("PendingOnly with no entry = %v; want ErrNoPending", err)
	}
	if ok, err := d.PendingExists("atlas"); ok || err != nil {
		t.Errorf("PendingExists with no entry = %v, %v", ok, err)
	}
	if err := d.CreatePending("atlas", validPending("atlas")); err != nil {
		t.Fatal(err)
	}
	if ok, err := d.PendingExists("atlas"); !ok || err != nil {
		t.Errorf("PendingExists of an entry = %v, %v", ok, err)
	}
	if err := d.PendingOnly("atlas"); err != nil {
		t.Errorf("PendingOnly of an entry alone = %v", err)
	}
	// An AdoptPending that stopped after its first step left an empty
	// instance directory: no record, so an abandon may go on.
	if err := os.MkdirAll(d.InstancePath("atlas"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := d.PendingOnly("atlas"); err != nil {
		t.Errorf("PendingOnly beside an empty instance directory = %v", err)
	}
	if err := d.SaveInstanceMetadata("atlas", adoptMeta("atlas")); err != nil {
		t.Fatal(err)
	}
	if err := d.PendingOnly("atlas"); !errors.Is(err, ErrInstanceRecorded) {
		t.Errorf("PendingOnly beside a record = %v; want ErrInstanceRecorded", err)
	}

	idDir, err := d.PendingIdentityDir("atlas")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := devicekey.Enrol(rand.Reader, idDir, []devicekey.Role{devicekey.Reader, devicekey.Writer}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := d.RemovePending("atlas"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(d.PendingDir(), "atlas")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("RemovePending left the entry or its keys: %v", err)
	}
	if _, err := os.Lstat(d.InstancePath("atlas")); err != nil {
		t.Errorf("RemovePending touched the instance: %v", err)
	}
	if err := d.RemovePending("atlas"); !errors.Is(err, ErrNoPending) {
		t.Errorf("RemovePending of no entry = %v; want ErrNoPending", err)
	}
	// SavePending writes over an entry; it never makes one.
	if err := d.SavePending("atlas", validPending("atlas")); !errors.Is(err, ErrNoPending) {
		t.Errorf("SavePending of no entry = %v; want ErrNoPending", err)
	}
	if ok, err := d.PendingExists("atlas"); ok || err != nil {
		t.Errorf("a refused SavePending made an entry: %v, %v", ok, err)
	}
}

// ADR 0024 M3b.2: the identity paths are exactly where X2 places the store,
// under the 0700 config root, and need nothing to be there yet.
func TestIdentityPaths(t *testing.T) {
	d := testDir(t)
	if got, err := d.InstanceIdentityDir("atlas"); err != nil || got != filepath.Join(string(d), "instances", "atlas", "identity") {
		t.Errorf("InstanceIdentityDir = %q, %v", got, err)
	}
	if got, err := d.PendingIdentityDir("atlas"); err != nil || got != filepath.Join(string(d), "pending", "atlas", "identity") {
		t.Errorf("PendingIdentityDir = %q, %v", got, err)
	}
	if got := d.PendingDir(); got != filepath.Join(string(d), "pending") {
		t.Errorf("PendingDir = %q", got)
	}
	// A link in place of the instance's directory, or its identity/, is
	// refused, as the pending store's are.
	if err := d.Ensure(); err != nil {
		t.Fatal(err)
	}
	elsewhere := t.TempDir()
	if err := os.Mkdir(filepath.Join(string(d), "instances"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, d.InstancePath("atlas")); err != nil {
		t.Fatal(err)
	}
	if _, err := d.InstanceIdentityDir("atlas"); !errors.Is(err, ErrUnsafePath) {
		t.Errorf("InstanceIdentityDir through a link = %v; want ErrUnsafePath", err)
	}
	if err := d.CreateInstance("bravo"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(d.InstancePath("bravo"), identitySubdir)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.InstanceIdentityDir("bravo"); !errors.Is(err, ErrUnsafePath) {
		t.Errorf("InstanceIdentityDir of a linked identity/ = %v; want ErrUnsafePath", err)
	}
}

// ADR 0024 M3b.2 (decision 4): a directory other accounts can reach is
// refused, as ErrUnsafePath, by every function that opens or makes keys or
// reads or writes the pending record through it: a widened pending/, a
// widened entry, a widened identity/ in an entry or in an instance, and a
// widened instances/ or instance directory. PendingOnly and RemovePending,
// the abandon's, refuse none of them, as an abandon removes what a widened
// mode exposes.
//
// Each is widened to the group alone and to others alone: either is another
// account's way in.
func TestPendingRefusesWidenedModes(t *testing.T) {
	for _, m := range []struct {
		name string
		mode fs.FileMode
	}{{"to the group", 0o750}, {"to others", 0o705}} {
		t.Run(m.name, func(t *testing.T) { pendingRefusesWidenedMode(t, m.mode) })
	}
}

// pendingRefusesWidenedMode is TestPendingRefusesWidenedModes with each
// directory widened to mode.
func pendingRefusesWidenedMode(t *testing.T, mode fs.FileMode) {
	refused := func(t *testing.T, what string, err error) {
		t.Helper()
		if !errors.Is(err, ErrUnsafePath) {
			t.Errorf("%s = %v; want ErrUnsafePath", what, err)
		}
	}
	widen := func(t *testing.T, p string) {
		t.Helper()
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	abandons := func(t *testing.T, d Dir) {
		t.Helper()
		if err := d.PendingOnly("atlas"); err != nil {
			t.Errorf("PendingOnly refused a widened entry, which an abandon must still remove: %v", err)
		}
		if err := d.RemovePending("atlas"); err != nil {
			t.Errorf("RemovePending refused a widened entry: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(d.PendingDir(), "atlas")); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("the widened entry is still there: %v", err)
		}
	}
	entry := func(t *testing.T) Dir {
		t.Helper()
		d := pendingDir(t)
		if err := d.CreatePending("atlas", validPending("atlas")); err != nil {
			t.Fatal(err)
		}
		return d
	}

	t.Run("pending/", func(t *testing.T) {
		d := entry(t)
		widen(t, d.PendingDir())
		_, err := d.ListPending()
		refused(t, "ListPending", err)
		_, err = d.PendingIdentityDir("atlas")
		refused(t, "PendingIdentityDir", err)
		_, err = d.LoadPending("atlas")
		refused(t, "LoadPending", err)
		_, err = d.PendingExists("atlas")
		refused(t, "PendingExists", err)
		refused(t, "SavePending", d.SavePending("atlas", validPending("atlas")))
		refused(t, "CreatePending of another name", d.CreatePending("bravo", validPending("bravo")))
		refused(t, "AdoptPending", d.AdoptPending("atlas", adoptMeta("atlas")))
		abandons(t, d)
	})
	t.Run("the entry", func(t *testing.T) {
		d := entry(t)
		widen(t, filepath.Join(d.PendingDir(), "atlas"))
		_, err := d.PendingExists("atlas")
		refused(t, "PendingExists", err)
		refused(t, "SavePending", d.SavePending("atlas", validPending("atlas")))
		_, err = d.LoadPending("atlas")
		refused(t, "LoadPending", err)
		_, err = d.PendingIdentityDir("atlas")
		refused(t, "PendingIdentityDir", err)
		if names, err := d.ListPending(); err != nil || !slices.Equal(names, []string{"atlas"}) {
			t.Errorf("ListPending = %v, %v; it lists names and opens no entry", names, err)
		}
		abandons(t, d)
	})
	t.Run("the entry's identity/", func(t *testing.T) {
		d := entry(t)
		id := filepath.Join(d.PendingDir(), "atlas", identitySubdir)
		if err := os.Mkdir(id, 0o700); err != nil {
			t.Fatal(err)
		}
		widen(t, id)
		_, err := d.PendingIdentityDir("atlas")
		refused(t, "PendingIdentityDir", err)
		refused(t, "AdoptPending", d.AdoptPending("atlas", adoptMeta("atlas")))
		abandons(t, d)
	})
	t.Run("the instance's identity/", func(t *testing.T) {
		d := pendingDir(t)
		if err := d.CreateInstance("atlas"); err != nil {
			t.Fatal(err)
		}
		id := filepath.Join(d.InstancePath("atlas"), identitySubdir)
		if err := os.Mkdir(id, 0o700); err != nil {
			t.Fatal(err)
		}
		widen(t, id)
		_, err := d.InstanceIdentityDir("atlas")
		refused(t, "InstanceIdentityDir", err)
	})
	for _, which := range []string{"instances/", "the instance's directory"} {
		t.Run(which, func(t *testing.T) {
			d := pendingDir(t)
			if err := d.CreateInstance("atlas"); err != nil {
				t.Fatal(err)
			}
			p := d.InstancePath("atlas")
			if which == "instances/" {
				p = filepath.Dir(p)
			}
			widen(t, p)
			_, err := d.InstanceIdentityDir("atlas")
			refused(t, "InstanceIdentityDir", err)
		})
	}
}
