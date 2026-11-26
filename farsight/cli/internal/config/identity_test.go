package config

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/devicekey"
)

// longID and shortID are valid drawn IDs, 32 and 30 characters, each told
// apart by c.
func longID(c byte) string  { return "p" + strings.Repeat(string(c), 31) }
func shortID(c byte) string { return "s" + strings.Repeat(string(c), 29) }

// anchorEnd is a role anchor's NotAfter in the fixtures.
var anchorEnd = time.Date(2027, 12, 21, 10, 0, 0, 0, time.UTC)

// validIdentity is a writer-capable device's identity on the certificate
// route, which knows one other device's reader.
func validIdentity() *Identity {
	return &Identity{
		ProjectNumber:  "123456789012",
		Pool:           longID('0'),
		ReaderAccount:  shortID('1'),
		WriterAccount:  shortID('2'),
		NodeAccount:    shortID('3'),
		ConditionTitle: shortID('4'),
		Roles: []DeviceRole{
			{Role: RoleReader, Route: RouteCertificate, Provider: longID('1'), AnchorNotAfter: anchorEnd},
			{Role: RoleWriter, Route: RouteCertificate, Provider: longID('2'), AnchorNotAfter: anchorEnd},
		},
		Known:      []KnownProvider{{Provider: longID('3'), Role: RoleReader}},
		EnrolledAt: time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC),
	}
}

// sameIdentity compares two identities, every time by its instant. It
// compares each role field by field itself, not through the product's
// sameRole, so a merge that loses one field of a role is seen here.
func sameIdentity(a, b *Identity) bool {
	if a == nil || b == nil {
		return a == b
	}
	x, y := *a, *b
	if !x.EnrolledAt.Equal(y.EnrolledAt) || len(x.Roles) != len(y.Roles) {
		return false
	}
	for i := range x.Roles {
		r, s := x.Roles[i], y.Roles[i]
		if r.Role != s.Role || r.Route != s.Route || r.Provider != s.Provider || !r.AnchorNotAfter.Equal(s.AnchorNotAfter) {
			return false
		}
	}
	x.EnrolledAt, y.EnrolledAt = time.Time{}, time.Time{}
	x.Roles, y.Roles = nil, nil
	return reflect.DeepEqual(x, y)
}

// identityRecord writes a record for name holding id, and loads it back.
func identityRecord(t *testing.T, d Dir, name string, id *Identity) {
	t.Helper()
	if err := d.CreateInstance(name); err != nil {
		t.Fatal(err)
	}
	if err := d.SaveInstanceMetadata(name, &InstanceMetadata{Name: name, Provider: "gke", Project: "proj-test1", Identity: id}); err != nil {
		t.Fatal(err)
	}
}

// ADR 0024 M3b.2: the identity round-trips through metadata.yaml whole, under
// its own key, and passes CheckedIdentity; a record that names none loads a
// nil Identity, writes no identity key, and is ErrNoIdentity.
func TestIdentityRoundTrip(t *testing.T) {
	d := testDir(t)
	identityRecord(t, d, "atlas", validIdentity())
	got, err := d.LoadInstanceMetadata("atlas")
	if err != nil {
		t.Fatal(err)
	}
	if !sameIdentity(got.Identity, validIdentity()) {
		t.Errorf("the identity round-tripped to %+v, want %+v", got.Identity, validIdentity())
	}
	if id, err := CheckedIdentity(got); err != nil || id != got.Identity {
		t.Errorf("CheckedIdentity = %v, %v; want the record's own identity", id, err)
	}
	raw, err := os.ReadFile(filepath.Join(d.InstancePath("atlas"), metadataFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"identity:", "project_number:", "pool:", "reader_account:", "writer_account:", "node_account:",
		"condition_title:", "roles:", "route: certificate", "anchor_not_after:", "known:", "enrolled_at:"} {
		if !bytes.Contains(raw, []byte(key)) {
			t.Errorf("the record does not hold %q:\n%s", key, raw)
		}
	}

	identityRecord(t, d, "plain", nil)
	plain, err := d.LoadInstanceMetadata("plain")
	if err != nil {
		t.Fatal(err)
	}
	if plain.Identity != nil {
		t.Errorf("a record with no identity loaded %+v", plain.Identity)
	}
	if id, err := CheckedIdentity(plain); id != nil || !errors.Is(err, ErrNoIdentity) {
		t.Errorf("CheckedIdentity of no identity = %v, %v; want ErrNoIdentity", id, err)
	}
	if id, err := CheckedIdentity(nil); id != nil || !errors.Is(err, ErrNoIdentity) {
		t.Errorf("CheckedIdentity(nil) = %v, %v; want ErrNoIdentity", id, err)
	}
	raw, err = os.ReadFile(filepath.Join(d.InstancePath("plain"), metadataFile))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("identity")) {
		t.Errorf("a record with no identity wrote one:\n%s", raw)
	}

	// The route-only identity M3b.7 writes for an M2-shape record passes.
	routes := &InstanceMetadata{Identity: &Identity{Roles: []DeviceRole{
		{Role: RoleWriter, Route: RouteGoogleMadeKey}, {Role: RoleReader, Route: RouteUploadedKey},
	}}}
	if _, err := CheckedIdentity(routes); err != nil {
		t.Errorf("a route-only fallback identity was refused: %v", err)
	}
}

// ADR 0024 M3b.2 (the plan's Graft 6): two commands that read the record and
// then each change their own part of the identity both keep their change:
// 'device known' adding a provider while 'device renew' moves a role's
// anchor, two commands adding different known providers, one removing a
// known provider while another adds one, and a scalar moved on one side
// while a role moves on the other. A nil identity on one side reads as an
// empty one. Only one key moved two ways is a conflict, ErrMetadataConflict
// naming that key, and the record on disk is left as the other writer wrote
// it.
func TestIdentityMergesPerKeyUnderTwoWriters(t *testing.T) {
	renewed := anchorEnd.AddDate(1, 0, 0)
	for _, tc := range []struct {
		name         string
		seed         *Identity
		other, mine  func(*Identity) *Identity
		want         func() *Identity
		conflictsKey string
	}{
		{
			name: "device known beside device renew",
			seed: validIdentity(),
			other: func(id *Identity) *Identity {
				id.Known = append(id.Known, KnownProvider{Provider: longID('5'), Role: RoleWriter})
				return id
			},
			mine: func(id *Identity) *Identity {
				id.Roles[0].AnchorNotAfter = renewed
				return id
			},
			want: func() *Identity {
				id := validIdentity()
				id.Roles[0].AnchorNotAfter = renewed
				id.Known = append(id.Known, KnownProvider{Provider: longID('5'), Role: RoleWriter})
				return id
			},
		},
		{
			name: "two known providers added",
			seed: validIdentity(),
			other: func(id *Identity) *Identity {
				id.Known = append(id.Known, KnownProvider{Provider: longID('6'), Role: RoleReader})
				return id
			},
			mine: func(id *Identity) *Identity {
				id.Known = append(id.Known, KnownProvider{Provider: longID('5'), Role: RoleWriter})
				return id
			},
			want: func() *Identity {
				id := validIdentity()
				id.Known = append(id.Known, KnownProvider{Provider: longID('5'), Role: RoleWriter}, KnownProvider{Provider: longID('6'), Role: RoleReader})
				return id
			},
		},
		{
			name: "a known provider removed beside one added",
			seed: validIdentity(),
			other: func(id *Identity) *Identity {
				id.Known = append(id.Known, KnownProvider{Provider: longID('6'), Role: RoleReader})
				return id
			},
			mine: func(id *Identity) *Identity {
				id.Known = nil
				return id
			},
			want: func() *Identity {
				id := validIdentity()
				id.Known = []KnownProvider{{Provider: longID('6'), Role: RoleReader}}
				return id
			},
		},
		{
			name: "the writer role added beside a scalar",
			seed: func() *Identity { id := validIdentity(); id.Roles = id.Roles[:1]; return id }(),
			other: func(id *Identity) *Identity {
				id.EnrolledAt = id.EnrolledAt.Add(time.Hour)
				return id
			},
			mine: func(id *Identity) *Identity {
				id.Roles = append(id.Roles, DeviceRole{Role: RoleWriter, Route: RouteCertificate, Provider: longID('2'), AnchorNotAfter: anchorEnd})
				return id
			},
			want: func() *Identity {
				id := validIdentity()
				id.EnrolledAt = id.EnrolledAt.Add(time.Hour)
				return id
			},
		},
		{
			name: "a role's route moved alone beside a known provider added",
			seed: &Identity{Roles: []DeviceRole{{Role: RoleReader, Route: RouteUploadedKey}, {Role: RoleWriter, Route: RouteGoogleMadeKey}}},
			other: func(id *Identity) *Identity {
				id.Known = append(id.Known, KnownProvider{Provider: longID('5'), Role: RoleWriter})
				return id
			},
			mine: func(id *Identity) *Identity {
				id.Roles[0].Route = RouteNone
				return id
			},
			want: func() *Identity {
				return &Identity{
					Roles: []DeviceRole{{Role: RoleReader, Route: RouteNone}, {Role: RoleWriter, Route: RouteGoogleMadeKey}},
					Known: []KnownProvider{{Provider: longID('5'), Role: RoleWriter}},
				}
			},
		},
		{
			name: "a role's provider moved alone beside a known provider added",
			seed: &Identity{Roles: []DeviceRole{{Role: RoleReader, Route: RoutePublicKey, Provider: longID('1')}}},
			other: func(id *Identity) *Identity {
				id.Known = append(id.Known, KnownProvider{Provider: longID('5'), Role: RoleWriter})
				return id
			},
			mine: func(id *Identity) *Identity {
				id.Roles[0].Provider = longID('7')
				return id
			},
			want: func() *Identity {
				return &Identity{
					Roles: []DeviceRole{{Role: RoleReader, Route: RoutePublicKey, Provider: longID('7')}},
					Known: []KnownProvider{{Provider: longID('5'), Role: RoleWriter}},
				}
			},
		},
		{
			name: "the reader renewed on one side, the writer on the other",
			seed: validIdentity(),
			other: func(id *Identity) *Identity {
				id.Roles[1].AnchorNotAfter = renewed.Add(time.Hour)
				return id
			},
			mine: func(id *Identity) *Identity {
				id.Roles[0].AnchorNotAfter = renewed
				return id
			},
			want: func() *Identity {
				id := validIdentity()
				id.Roles[0].AnchorNotAfter = renewed
				id.Roles[1].AnchorNotAfter = renewed.Add(time.Hour)
				return id
			},
		},
		{
			name: "an identity recorded while another command held a record with none",
			seed: nil,
			other: func(*Identity) *Identity {
				return validIdentity()
			},
			mine: func(id *Identity) *Identity { return id },
			want: validIdentity,
		},
		{
			name: "the same change made on both sides",
			seed: validIdentity(),
			other: func(id *Identity) *Identity {
				id.Roles[1].AnchorNotAfter = renewed
				return id
			},
			mine: func(id *Identity) *Identity {
				id.Roles[1].AnchorNotAfter = renewed
				return id
			},
			want: func() *Identity {
				id := validIdentity()
				id.Roles[1].AnchorNotAfter = renewed
				return id
			},
		},
		{
			name: "one role moved two ways",
			seed: validIdentity(),
			other: func(id *Identity) *Identity {
				id.Roles[0].AnchorNotAfter = renewed
				return id
			},
			mine: func(id *Identity) *Identity {
				id.Roles[0].Route = RouteNone
				id.Roles[0].Provider, id.Roles[0].AnchorNotAfter = "", time.Time{}
				return id
			},
			conflictsKey: `Identity.Roles["reader"]`,
		},
		{
			name: "one known provider moved two ways",
			seed: validIdentity(),
			other: func(id *Identity) *Identity {
				id.Known[0].Role = RoleWriter
				return id
			},
			mine: func(id *Identity) *Identity {
				id.Known = nil
				return id
			},
			conflictsKey: `Identity.Known["` + longID('3') + `"]`,
		},
		{
			name: "one scalar moved two ways",
			seed: validIdentity(),
			other: func(id *Identity) *Identity {
				id.ConditionTitle = shortID('8')
				return id
			},
			mine: func(id *Identity) *Identity {
				id.ConditionTitle = shortID('9')
				return id
			},
			conflictsKey: "Identity.ConditionTitle",
		},
		{
			name: "an identity recorded two ways while none was",
			seed: nil,
			other: func(*Identity) *Identity {
				return validIdentity()
			},
			mine: func(*Identity) *Identity {
				id := validIdentity()
				id.Pool = longID('7')
				return id
			},
			conflictsKey: "Identity.Pool",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := testDir(t)
			identityRecord(t, d, "atlas", tc.seed)
			held, err := d.LoadInstanceMetadata("atlas")
			if err != nil {
				t.Fatal(err)
			}
			var after *Identity
			if _, err := d.UpdateInstanceMetadata("atlas", func(m *InstanceMetadata) error {
				m.Identity = tc.other(m.Identity)
				after = m.Identity
				return nil
			}); err != nil {
				t.Fatalf("the other writer: %v", err)
			}
			held.Identity = tc.mine(held.Identity)
			held.Status = InstanceRunning // a change outside the identity rides along
			err = d.SaveInstanceMetadata("atlas", held)
			got, lerr := d.LoadInstanceMetadata("atlas")
			if lerr != nil {
				t.Fatal(lerr)
			}
			if tc.conflictsKey != "" {
				if !errors.Is(err, ErrMetadataConflict) || !strings.Contains(err.Error(), "field "+tc.conflictsKey+" was changed") {
					t.Fatalf("save = %v; want ErrMetadataConflict naming %s", err, tc.conflictsKey)
				}
				if !sameIdentity(got.Identity, after) || got.Status == InstanceRunning {
					t.Errorf("the refused save changed the record: %+v", got.Identity)
				}
				return
			}
			if err != nil {
				t.Fatalf("save beside the other writer's change: %v", err)
			}
			if !sameIdentity(got.Identity, tc.want()) {
				t.Errorf("merged identity = %+v\nwant %+v", got.Identity, tc.want())
			}
			if got.Status != InstanceRunning {
				t.Error("this command's own change outside the identity was lost")
			}
			if _, err := CheckedIdentity(got); err != nil {
				t.Errorf("the merged identity does not pass its checks: %v", err)
			}
		})
	}
}

// ADR 0024 M3b.2: a list in the identity that names one key twice cannot be
// merged per key, and is refused rather than read as either entry; an
// identity emptied on one side, with the other untouched, is no identity.
func TestIdentityMergeEdges(t *testing.T) {
	twice := validIdentity()
	twice.Roles = append(twice.Roles, twice.Roles[0])
	if _, err := mergeIdentity(validIdentity(), twice, validIdentity()); err == nil || !strings.Contains(err.Error(), `Identity.Roles names "reader" twice`) {
		t.Errorf("a role named twice merged: %v", err)
	}
	knownTwice := validIdentity()
	knownTwice.Known = append(knownTwice.Known, knownTwice.Known[0])
	if _, err := mergeIdentity(knownTwice, validIdentity(), validIdentity()); err == nil || !strings.Contains(err.Error(), "Identity.Known names") {
		t.Errorf("a known provider named twice merged: %v", err)
	}
	if got, err := mergeIdentity(validIdentity(), nil, validIdentity()); err != nil || got != nil {
		t.Errorf("an identity removed on one side merged to %+v, %v; want none", got, err)
	}
	if got, err := mergeIdentity(nil, nil, nil); err != nil || got != nil {
		t.Errorf("no identity anywhere merged to %+v, %v", got, err)
	}
	// A time set in memory and the same instant read from the record are one
	// value: the same renewal made on both sides is no conflict.
	local := validIdentity()
	local.EnrolledAt = local.EnrolledAt.In(time.FixedZone("here", 3600))
	moved := validIdentity()
	moved.EnrolledAt = moved.EnrolledAt.Add(time.Minute)
	movedLocal := validIdentity()
	movedLocal.EnrolledAt = moved.EnrolledAt.In(time.FixedZone("here", 3600))
	if _, err := mergeIdentity(local, movedLocal, moved); err != nil {
		t.Errorf("one instant in two locations conflicted: %v", err)
	}
	// A role's anchor is compared by its instant too: the same NotAfter held
	// in another location is no change on this side, so the other side's
	// renewal stands.
	zoned := validIdentity()
	zoned.Roles[0].AnchorNotAfter = zoned.Roles[0].AnchorNotAfter.In(time.FixedZone("here", 3600))
	renewed := validIdentity()
	renewed.Roles[0].AnchorNotAfter = anchorEnd.AddDate(1, 0, 0)
	if got, err := mergeIdentity(validIdentity(), zoned, renewed); err != nil || got == nil || !got.Roles[0].AnchorNotAfter.Equal(renewed.Roles[0].AnchorNotAfter) {
		t.Errorf("a role's anchor in another location read as a change: %+v, %v", got, err)
	}
}

// ADR 0024 M3b.2: what this command left as it read it stands as the other
// writer left it on disk, to its text: an instant held here in another
// location is no change of this command's, so the record keeps the disk's
// form of it, scalar and role alike, beside the other writer's change.
func TestIdentityMergeKeepsWhatIsOnDisk(t *testing.T) {
	d := testDir(t)
	identityRecord(t, d, "atlas", validIdentity())
	held, err := d.LoadInstanceMetadata("atlas")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.UpdateInstanceMetadata("atlas", func(m *InstanceMetadata) error {
		m.Identity.Known = append(m.Identity.Known, KnownProvider{Provider: longID('5'), Role: RoleWriter})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	here := time.FixedZone("here", 3600)
	held.Identity.EnrolledAt = held.Identity.EnrolledAt.In(here)
	held.Identity.Roles[0].AnchorNotAfter = held.Identity.Roles[0].AnchorNotAfter.In(here)
	if err := d.SaveInstanceMetadata("atlas", held); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(d.InstancePath("atlas"), metadataFile))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("+01:00")) {
		t.Errorf("an instant this command did not change was written in its location:\n%s", raw)
	}
	got, err := d.LoadInstanceMetadata("atlas")
	if err != nil {
		t.Fatal(err)
	}
	want := validIdentity()
	want.Known = append(want.Known, KnownProvider{Provider: longID('5'), Role: RoleWriter})
	if !sameIdentity(got.Identity, want) {
		t.Errorf("merged identity = %+v\nwant %+v", got.Identity, want)
	}
}

// ADR 0024 M3b.2: each shape accepts exactly its alphabet, at the edges of
// each range too. Every byte value, put first, in the middle and last of an
// otherwise valid value, is accepted only where the shape's alphabet holds
// it, in the identity, in a pending record and in an account's email.
func TestShapesAcceptExactlyTheirAlphabets(t *testing.T) {
	lower := func(b byte) bool { return b >= 'a' && b <= 'z' }
	digit := func(b byte) bool { return b >= '0' && b <= '9' }
	alnum := func(b byte) bool { return lower(b) || digit(b) }
	inIdentity := func(set func(*Identity, string)) func(string) error {
		return func(v string) error {
			id := validIdentity()
			set(id, v)
			_, err := CheckedIdentity(&InstanceMetadata{Identity: id})
			return err
		}
	}
	inPending := func(set func(*Pending, string)) func(string) error {
		return func(v string) error {
			p := validPending("atlas")
			set(p, v)
			return checkPending(p)
		}
	}
	for _, s := range []struct {
		name               string
		valid              string
		check              func(string) error
		first, middle, end func(byte) bool
	}{
		{"the pool's ID", longID('0'), inIdentity(func(id *Identity, v string) { id.Pool = v }), lower, alnum, alnum},
		{"a role's provider", longID('1'), inIdentity(func(id *Identity, v string) { id.Roles[0].Provider = v }), lower, alnum, alnum},
		{"a known provider", longID('3'), inIdentity(func(id *Identity, v string) { id.Known[0].Provider = v }), lower, alnum, alnum},
		{"an account's ID", shortID('1'), inIdentity(func(id *Identity, v string) { id.ReaderAccount = v }), lower, alnum, alnum},
		{"the condition's title", shortID('4'), inIdentity(func(id *Identity, v string) { id.ConditionTitle = v }), lower, alnum, alnum},
		{"the project's number", "123456789012", inIdentity(func(id *Identity, v string) { id.ProjectNumber = v }), digit, digit, digit},
		{"a drawn pool", longID('0'), inPending(func(p *Pending, v string) { p.Draw.Pool = v }), lower, alnum, alnum},
		{"a drawn account", shortID('3'), inPending(func(p *Pending, v string) { p.Draw.NodeAccount = v }), lower, alnum, alnum},
		{"a pending project", "proj-test1", inPending(func(p *Pending, v string) { p.Project = v }), lower, func(b byte) bool { return alnum(b) || b == '-' }, alnum},
		{"a pending project number", "123456789012", inPending(func(p *Pending, v string) { p.ProjectNumber = v }), digit, digit, digit},
		{"an account's ID in its email", shortID('1'), func(v string) error { _, err := ServiceAccountEmail(v, "proj-test1"); return err }, lower, alnum, alnum},
		{"a project in an email", "proj-test1", func(v string) error { _, err := ServiceAccountEmail(shortID('1'), v); return err },
			lower, func(b byte) bool { return alnum(b) || b == '-' }, alnum},
	} {
		n := len(s.valid)
		for b := range 256 {
			c := string([]byte{byte(b)})
			for _, at := range []struct {
				where, value string
				ok           bool
			}{
				{"first", c + s.valid[1:], s.first(byte(b))},
				{"in the middle", s.valid[:n/2] + c + s.valid[n/2+1:], s.middle(byte(b))},
				{"last", s.valid[:n-1] + c, s.end(byte(b))},
			} {
				if err := s.check(at.value); (err == nil) != at.ok {
					t.Errorf("%s with %q %s: %v; want it accepted: %v", s.name, c, at.where, err, at.ok)
				}
			}
		}
	}
}

// hostileIDs are values that are not a drawn ID of v's length: each breaks
// one rule, the length kept where it can be.
func hostileIDs(v string) map[string]string {
	n := len(v)
	return map[string]string{
		"empty":                  "",
		"a NUL":                  v[:n-1] + "\x00",
		"an escape":              v[:n-1] + "\x1b",
		"a newline at its end":   v[:n-1] + "\n",
		"a slash":                v[:n/2] + "/" + v[n/2+1:],
		"a dot-dot":              v[:n/2] + ".." + v[n/2+2:],
		"a capital":              v[:n-1] + "A",
		"a capital first":        "P" + v[1:],
		"a hyphen":               v[:n-1] + "-",
		"a digit first":          "1" + v[1:],
		"one character short":    v[:n-1],
		"one character long":     v + "a",
		"a non-ASCII letter":     v[:n-2] + "é",
		"a space":                v[:n-1] + " ",
		"a fullwidth letter":     v[:n-3] + "ａ",
		"twice its length":       v + v,
		"a percent-encoded dot":  v[:n-3] + "%2e",
		"a shell substitution":   v[:n-4] + "$(x)",
		"a single quote":         v[:n-1] + "'",
		"a trailing NUL, longer": v + "\x00",
	}
}

// hostileNumbers are values that are not a project's number.
var hostileNumbers = map[string]string{
	"empty":                "",
	"21 digits":            strings.Repeat("1", 21),
	"a letter":             "12345678901a",
	"a slash":              "123456/89012",
	"a dot-dot":            "1234..789012",
	"a NUL":                "12345678901\x00",
	"a newline at its end": "12345678901\n",
	"a sign":               "-12345678901",
	"a plus":               "+12345678901",
	"a space":              " 12345678901",
	"fullwidth digits":     "１２３",
	"an exponent":          "1e10",
}

// ADR 0024 M3b.2: every value of the identity is held to the one shape it
// may be rendered in. Each hostile value, in each field, is refused as
// ErrIdentityRecord with the field named and the value not quoted.
func TestCheckedIdentityRefusesEveryHostileShape(t *testing.T) {
	type field struct {
		name  string
		valid string
		set   func(*Identity, string)
		// optional fields take "" as absent.
		optional bool
	}
	fields := []field{
		{"identity.pool", longID('0'), func(id *Identity, v string) { id.Pool = v }, false},
		{"identity.reader_account", shortID('1'), func(id *Identity, v string) { id.ReaderAccount = v }, false},
		{"identity.writer_account", shortID('2'), func(id *Identity, v string) { id.WriterAccount = v }, false},
		{"identity.node_account", shortID('3'), func(id *Identity, v string) { id.NodeAccount = v }, false},
		{"identity.condition_title", shortID('4'), func(id *Identity, v string) { id.ConditionTitle = v }, true},
		{"identity.roles[0]", longID('1'), func(id *Identity, v string) { id.Roles[0].Provider = v }, false},
		{"identity.roles[1]", longID('2'), func(id *Identity, v string) { id.Roles[1].Provider = v }, false},
		{"identity.known[0].provider", longID('3'), func(id *Identity, v string) { id.Known[0].Provider = v }, false},
	}
	for _, f := range fields {
		for what, v := range hostileIDs(f.valid) {
			id := validIdentity()
			f.set(id, v)
			_, err := CheckedIdentity(&InstanceMetadata{Identity: id})
			if f.optional && v == "" {
				if err != nil {
					t.Errorf("%s %s: refused an absent optional value: %v", f.name, what, err)
				}
				continue
			}
			if !errors.Is(err, ErrIdentityRecord) || !strings.Contains(err.Error(), f.name) {
				t.Errorf("%s %s: CheckedIdentity = %v; want ErrIdentityRecord naming %s", f.name, what, err, f.name)
				continue
			}
			if v != "" && strings.Contains(err.Error(), v) {
				t.Errorf("%s %s: the refusal quotes the value: %q", f.name, what, err)
			}
		}
	}
	for what, v := range hostileNumbers {
		id := validIdentity()
		id.ProjectNumber = v
		_, err := CheckedIdentity(&InstanceMetadata{Identity: id})
		if !errors.Is(err, ErrIdentityRecord) || !strings.Contains(err.Error(), "identity.project_number") {
			t.Errorf("project number %s: CheckedIdentity = %v; want ErrIdentityRecord naming it", what, err)
		}
		if v != "" && strings.Contains(err.Error(), v) {
			t.Errorf("project number %s: the refusal quotes the value: %q", what, err)
		}
	}
	// The project's number is 1 to 20 digits: both ends pass.
	for _, v := range []string{"1", strings.Repeat("9", 20)} {
		id := validIdentity()
		id.ProjectNumber = v
		if _, err := CheckedIdentity(&InstanceMetadata{Identity: id}); err != nil {
			t.Errorf("the project number of %d digits was refused: %v", len(v), err)
		}
	}
}

// ADR 0024 M3b.2: every route has what it needs and nothing it cannot have;
// a role is named once and is a reader or a writer; and no one ID stands for
// two things.
func TestCheckedIdentityRoutes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		edit   func(*Identity)
		refuse string // "" accepts
	}{
		{"both roles on the certificate route", func(*Identity) {}, ""},
		{"a reader-only device", func(id *Identity) { id.Roles = id.Roles[:1] }, ""},
		{"a reader-only device with no node account", func(id *Identity) { id.Roles, id.NodeAccount = id.Roles[:1], "" }, ""},
		// Each role's certificate route needs its own account and no other
		// role's: a reader holds no writer's account, and a writer beside a
		// reader on none holds no reader's.
		{"a reader-only device with neither the writer's nor the nodes' account", func(id *Identity) {
			id.Roles, id.WriterAccount, id.NodeAccount = id.Roles[:1], "", ""
		}, ""},
		{"a writer on the certificate route beside a reader on none, with no reader account", func(id *Identity) {
			id.Roles[0], id.ReaderAccount = DeviceRole{Role: RoleReader, Route: RouteNone}, ""
		}, ""},
		{"fallback 3's writer with no reader", func(id *Identity) {
			*id = Identity{Roles: []DeviceRole{{Role: RoleWriter, Route: RouteGoogleMadeKey}, {Role: RoleReader, Route: RouteNone}}}
		}, ""},
		{"fallback 1 with a provider", func(id *Identity) {
			id.Roles[0] = DeviceRole{Role: RoleReader, Route: RoutePublicKey, Provider: longID('1')}
		}, ""},
		{"fallback 1 with none", func(id *Identity) { id.Roles[0] = DeviceRole{Role: RoleReader, Route: RoutePublicKey} }, ""},

		{"the certificate route with no provider", func(id *Identity) { id.Roles[0].Provider = "" }, "needs identity.roles[0].provider"},
		{"the certificate route with no anchor", func(id *Identity) { id.Roles[1].AnchorNotAfter = time.Time{} }, "needs identity.roles[1].anchor_not_after"},
		{"the certificate route with no number", func(id *Identity) { id.ProjectNumber = "" }, "needs identity.project_number"},
		{"the certificate route with no pool", func(id *Identity) { id.Pool = "" }, "needs identity.pool"},
		{"the reader's certificate route with no reader account", func(id *Identity) { id.ReaderAccount = "" }, "needs identity.reader_account"},
		{"the writer's certificate route with no writer account", func(id *Identity) { id.WriterAccount = "" }, "needs identity.writer_account"},
		{"the writer's certificate route with no node account", func(id *Identity) { id.NodeAccount = "" }, "needs identity.node_account"},
		{"fallback 2 with a provider", func(id *Identity) {
			id.Roles[0] = DeviceRole{Role: RoleReader, Route: RouteUploadedKey, Provider: longID('1')}
		}, "has none of"},
		{"fallback 3 with a provider", func(id *Identity) {
			id.Roles[1] = DeviceRole{Role: RoleWriter, Route: RouteGoogleMadeKey, Provider: longID('2')}
		}, "has none of"},
		{"none with a provider", func(id *Identity) {
			id.Roles[0] = DeviceRole{Role: RoleReader, Route: RouteNone, Provider: longID('1')}
		}, "has none of"},
		{"fallback 1 with an anchor", func(id *Identity) {
			id.Roles[0] = DeviceRole{Role: RoleReader, Route: RoutePublicKey, Provider: longID('1'), AnchorNotAfter: anchorEnd}
		}, "names an anchor"},
		{"fallback 3 with an anchor", func(id *Identity) {
			id.Roles[1] = DeviceRole{Role: RoleWriter, Route: RouteGoogleMadeKey, AnchorNotAfter: anchorEnd}
		}, "names an anchor"},
		{"a route farcast does not know", func(id *Identity) { id.Roles[0].Route = "certificates" }, "identity.roles[0].route"},
		{"an empty route", func(id *Identity) { id.Roles[0].Route = "" }, "identity.roles[0].route"},
		{"a role that is neither", func(id *Identity) { id.Roles[0].Role = "admin" }, "identity.roles[0].role"},
		{"a role spelt in capitals", func(id *Identity) { id.Roles[0].Role = "Reader" }, "identity.roles[0].role"},
		{"a role named twice", func(id *Identity) { id.Roles[1].Role = RoleReader }, "names the reader role twice"},
		{"one provider for both roles", func(id *Identity) { id.Roles[1].Provider = id.Roles[0].Provider }, "one provider for two roles"},
		{"the reader's account as the writer's", func(id *Identity) { id.WriterAccount = id.ReaderAccount }, "the reader's account for another role's"},
		{"the reader's account as the nodes'", func(id *Identity) { id.NodeAccount = id.ReaderAccount }, "the reader's account for another role's"},
		{"the writer's account as the nodes'", func(id *Identity) { id.NodeAccount = id.WriterAccount }, "the writer's account for the nodes'"},
		{"a known provider named twice", func(id *Identity) {
			id.Known = append(id.Known, KnownProvider{Provider: longID('3'), Role: RoleWriter})
		}, "one provider twice"},
		{"a known provider that is this device's", func(id *Identity) { id.Known[0].Provider = longID('1') }, "one of this device's own"},
		{"a known provider with no role", func(id *Identity) { id.Known[0].Role = "" }, "identity.known[0].role"},
		{"a known provider with another role", func(id *Identity) { id.Known[0].Role = "node" }, "identity.known[0].role"},
	} {
		id := validIdentity()
		tc.edit(id)
		_, err := CheckedIdentity(&InstanceMetadata{Identity: id})
		switch {
		case tc.refuse == "" && err != nil:
			t.Errorf("%s: refused: %v", tc.name, err)
		case tc.refuse != "" && (!errors.Is(err, ErrIdentityRecord) || !strings.Contains(err.Error(), tc.refuse)):
			t.Errorf("%s: CheckedIdentity = %v; want ErrIdentityRecord saying %q", tc.name, err, tc.refuse)
		}
	}

	// An identity that names no role names no route for any, whatever else
	// it holds: it is no identity (ErrNoIdentity), as no identity at all is.
	for what, id := range map[string]*Identity{
		"every ID and no roles": func() *Identity { id := validIdentity(); id.Roles = nil; return id }(),
		"an empty role list":    func() *Identity { id := validIdentity(); id.Roles = []DeviceRole{}; return id }(),
		"nothing at all":        {},
	} {
		if got, err := CheckedIdentity(&InstanceMetadata{Identity: id}); got != nil || !errors.Is(err, ErrNoIdentity) {
			t.Errorf("%s: CheckedIdentity = %v, %v; want ErrNoIdentity", what, got, err)
		}
	}
}

// cycleReader gives every byte value in turn, so a draw from it meets every
// letter and digit of its alphabets, and every byte rejection sampling skips.
type cycleReader struct{ next byte }

func (c *cycleReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = c.next
		c.next++
	}
	return len(p), nil
}

// ADR 0024 M3b.2 (decision 2): config keeps its own shapes and does not
// import devicekey, so every kind devicekey draws is held here to pass
// config's check for the field it is recorded in, from the system's random
// source and from one that walks every byte value.
func TestEveryDrawPassesConfigsShapes(t *testing.T) {
	for _, src := range []struct {
		name string
		rnd  io.Reader
	}{
		{"crypto/rand", rand.Reader},
		{"every byte value", &cycleReader{}},
	} {
		rnd := src.rnd
		draw := func(kind devicekey.ObjectKind) string {
			v, err := devicekey.NewObjectID(kind, rnd)
			if err != nil {
				t.Fatalf("%s: draw kind %d: %v", src.name, kind, err)
			}
			return v
		}
		for i := range 500 {
			id := &Identity{
				ProjectNumber:  "1",
				Pool:           draw(devicekey.PoolID),
				ReaderAccount:  draw(devicekey.ServiceAccountID),
				WriterAccount:  draw(devicekey.ServiceAccountID),
				NodeAccount:    draw(devicekey.ServiceAccountID),
				ConditionTitle: draw(devicekey.ConditionTitle),
				Roles: []DeviceRole{
					{Role: RoleReader, Route: RouteCertificate, Provider: draw(devicekey.ProviderID), AnchorNotAfter: anchorEnd},
					{Role: RoleWriter, Route: RouteCertificate, Provider: draw(devicekey.ProviderID), AnchorNotAfter: anchorEnd},
				},
				Known: []KnownProvider{{Provider: draw(devicekey.ProviderID), Role: RoleReader}},
			}
			if _, err := CheckedIdentity(&InstanceMetadata{Identity: id}); err != nil {
				t.Fatalf("%s, draw %d: a drawn identity was refused: %v (%+v)", src.name, i, err, id)
			}
			p := validPending("atlas")
			p.Draw = PendingDraw{
				Pool: id.Pool, ReaderProvider: id.Roles[0].Provider, WriterProvider: id.Roles[1].Provider,
				ReaderAccount: id.ReaderAccount, WriterAccount: id.WriterAccount, NodeAccount: id.NodeAccount,
				ConditionTitle: id.ConditionTitle,
			}
			if err := checkPending(p); err != nil {
				t.Fatalf("%s, draw %d: a drawn pending record was refused: %v", src.name, i, err)
			}
			for _, sa := range []string{id.ReaderAccount, id.WriterAccount, id.NodeAccount} {
				if _, err := ServiceAccountEmail(sa, "proj-test1"); err != nil {
					t.Fatalf("%s, draw %d: a drawn account has no email: %v", src.name, i, err)
				}
			}
		}
	}
}

// ADR 0024 M3b.2: an account's email is <id>@<project>.iam.gserviceaccount.com,
// and an ID or a project out of its shape is refused, named and not quoted.
func TestServiceAccountEmail(t *testing.T) {
	if got, err := ServiceAccountEmail(shortID('1'), "proj-test1"); err != nil || got != shortID('1')+"@proj-test1.iam.gserviceaccount.com" {
		t.Errorf("ServiceAccountEmail = %q, %v", got, err)
	}
	for _, p := range []string{"abcdef", "a-b-c-1", strings.Repeat("a", 30)} {
		if _, err := ServiceAccountEmail(shortID('1'), p); err != nil {
			t.Errorf("the project %q was refused: %v", p, err)
		}
	}
	for what, v := range hostileIDs(shortID('1')) {
		got, err := ServiceAccountEmail(v, "proj-test1")
		if err == nil || got != "" || !strings.Contains(err.Error(), "service account's ID") {
			t.Errorf("the ID %s: ServiceAccountEmail = %q, %v; want a refusal naming the ID", what, got, err)
		}
		if v != "" && err != nil && strings.Contains(err.Error(), v) {
			t.Errorf("the ID %s: the refusal quotes it: %q", what, err)
		}
	}
	for _, v := range []string{
		"", "Proj-test1", "proj_test1", "proj/test1", "../proj", "proj-test1-", "1proj-test", "proj-test1\x00",
		"proj-test1\n", "abcde", strings.Repeat("a", 31), "proj test1", "proj.test1", "example.com:proj", "proj-tést1",
	} {
		got, err := ServiceAccountEmail(shortID('1'), v)
		if err == nil || got != "" || !strings.Contains(err.Error(), "project's ID") {
			t.Errorf("the project %q: ServiceAccountEmail = %q, %v; want a refusal naming the project", v, got, err)
		}
	}
}

// ADR 0024 M3b.2 (decision 3): a credentials.yaml with a blank key, or one of
// white space alone, is refused as ErrNoServiceAccountKey, naming the file,
// so no caller hands an adapter an empty credential it would read as
// Application Default Credentials. A key is returned as stored.
func TestLoadInstanceCredentialsRefusesABlankKey(t *testing.T) {
	d := testDir(t)
	if err := d.CreateInstance("prod"); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"", " ", "\n", " \t\r\n ", "\u00a0", "\u2003\n"} {
		if err := d.SaveInstanceCredentials("prod", &InstanceCredentials{Provider: "gke", ServiceAccountKey: key}); err != nil {
			t.Fatal(err)
		}
		creds, err := d.LoadInstanceCredentials("prod")
		if creds != nil || !errors.Is(err, ErrNoServiceAccountKey) {
			t.Errorf("key %q: LoadInstanceCredentials = %v, %v; want ErrNoServiceAccountKey", key, creds, err)
			continue
		}
		if !strings.Contains(err.Error(), filepath.Join(d.InstancePath("prod"), credentialsFile)) {
			t.Errorf("key %q: the refusal does not name the file: %v", key, err)
		}
	}
	// A credentials.yaml with no key field at all is the same.
	if err := os.WriteFile(filepath.Join(d.InstancePath("prod"), credentialsFile), []byte("provider: gke\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := d.LoadInstanceCredentials("prod"); !errors.Is(err, ErrNoServiceAccountKey) {
		t.Errorf("no key field: %v; want ErrNoServiceAccountKey", err)
	}
	const key = " {\"type\":\"service_account\"}\n"
	if err := d.SaveInstanceCredentials("prod", &InstanceCredentials{Provider: "gke", ServiceAccountKey: key}); err != nil {
		t.Fatal(err)
	}
	if creds, err := d.LoadInstanceCredentials("prod"); err != nil || creds.ServiceAccountKey != key {
		t.Errorf("a key = %v, %v; want it as stored", creds, err)
	}
}

// ADR 0024 M3b.2 (the fix round's S3): a credentials.yaml that does not
// parse is refused in words that quote none of it, the path and ParseFault's
// fault alone, because the YAML library's own text quotes the lines around
// the fault, and those hold the installer's private key, which every caller
// prints. The library's error is still what it unwraps to, so ParseFault
// reads it.
func TestLoadInstanceCredentialsParseErrorQuotesNothing(t *testing.T) {
	const secret = "MIIEvSECRETSECRET"
	key := `{"private_key": "-----BEGIN PRIVATE KEY-----\n` + secret + `"}`
	d := testDir(t)
	if err := d.CreateInstance("prod"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(d.InstancePath("prod"), credentialsFile)
	for what, body := range map[string]string{
		"a syntax error below the key": "provider: gke\nservice_account_key: |\n  " + key + "\n bad: [\n",
		"a syntax error in the key":    "provider: gke\nservice_account_key: \"" + secret + "\n  [: x\n",
		"a value of the wrong type":    "provider: [gke, " + secret + "]\nservice_account_key: |\n  " + key + "\n",
		"a truncated write":            "provider: gke\nservice_account_key: '{\"private_key\": \"" + secret,
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		creds, err := d.LoadInstanceCredentials("prod")
		if creds != nil || err == nil {
			t.Errorf("%s: LoadInstanceCredentials = %v, %v; want a refusal", what, creds, err)
			continue
		}
		for _, leak := range []string{secret, "PRIVATE", "private_key", "gke"} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("%s: the refusal quotes the file (%q): %v", what, leak, err)
			}
		}
		fault, ok := ParseFault(err)
		if !ok || !strings.HasPrefix(err.Error(), "parse "+path+": ") || !strings.HasSuffix(err.Error(), fault) {
			t.Errorf("%s: the refusal = %v; want the path and ParseFault's %q (%v)", what, err, fault, ok)
		}
	}
	// A fault in none of the types ParseFault reads, an alias to no anchor,
	// whose library text names the alias, is "a YAML error" and nothing more.
	if err := os.WriteFile(path, []byte("provider: gke\nservice_account_key: x\n<<: *"+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	creds, err := d.LoadInstanceCredentials("prod")
	if _, ok := ParseFault(err); ok {
		t.Fatalf("the fixture's fault is one ParseFault reads (%v); it is only worth its name if it is not", err)
	}
	if want := "parse " + path + ": a YAML error"; creds != nil || err == nil || err.Error() != want {
		t.Errorf("an alias to no anchor: LoadInstanceCredentials = %v, %v; want %q", creds, err, want)
	}
}
