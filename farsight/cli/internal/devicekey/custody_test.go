package devicekey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// custodyStates are the store states TestCustodyTable runs each function
// against.
var custodyStates = []string{"fresh", "due", "leaf key mismatch", "anchor replaced", "staged"}

// custodyState builds a writer-capable store in state, and the time to run
// at.
func custodyState(t *testing.T, state string) (*Store, string, time.Time) {
	t.Helper()
	s, dir, ids := enrolBoth(t)
	now := fresh
	switch state {
	case "fresh":
	case "due":
		now = due
	case "leaf key mismatch":
		for _, role := range []string{"reader", "writer"} {
			writeKeyFile(t, filepath.Join(dir, role, "leaf.key"), mustKey(t))
		}
	case "anchor replaced":
		for i, role := range []string{"reader", "writer"} {
			der, key, err := newAnchor(rand.Reader, ids[i].ID(), t0)
			if err != nil {
				t.Fatal(err)
			}
			writeCertFile(t, filepath.Join(dir, role, "anchor.crt"), der)
			writeKeyFile(t, filepath.Join(dir, role, "anchor.key"), key)
		}
	case "staged":
		for _, r := range []Role{Reader, Writer} {
			if _, err := s.RenewAnchor(r, rand.Reader, fresh); err != nil {
				t.Fatal(err)
			}
		}
	default:
		t.Fatalf("no state %q", state)
	}
	return s, dir, now
}

// under is names under dir, as the store's relative paths.
func under(dir string, names ...string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = dir + "/" + n
	}
	return out
}

// TestCustodyTable holds §1.7's table: for each function and each store
// state, the set of relative paths readFile was asked for is exactly the
// row's.
func TestCustodyTable(t *testing.T) {
	consent := GiveConsent(ConsentConfirmed)
	renewing := func(state string) bool {
		return state == "due" || state == "leaf key mismatch" || state == "anchor replaced"
	}
	opening := func(role string) func(string) ([]string, error) {
		return func(state string) ([]string, error) {
			if renewing(state) {
				return under(role, "anchor.crt", "anchor.key", "leaf.crt", "leaf.key"), nil
			}
			return under(role, "anchor.crt", "leaf.crt", "leaf.key"), nil
		}
	}
	always := func(reads []string, err error) func(string) ([]string, error) {
		return func(string) ([]string, error) { return reads, err }
	}
	staging := func(role string) func(string) ([]string, error) {
		return func(state string) ([]string, error) {
			if state == "staged" {
				return nil, ErrRenewalStaged
			}
			return under(role, "anchor.crt"), nil
		}
	}
	staged := func(reads []string) func(string) ([]string, error) {
		return func(state string) ([]string, error) {
			if state == "staged" {
				return reads, nil
			}
			return nil, ErrNothingStaged
		}
	}
	// stagedCerts is StagedCertificates' row: the staged certificates and the
	// current anchor's, whose ID they must carry, only when one is staged;
	// nothing, and no error, otherwise.
	stagedCerts := func(role string) func(string) ([]string, error) {
		return func(state string) ([]string, error) {
			if state == "staged" {
				return append(under(role+".next", "anchor.crt", "leaf.crt"), role+"/anchor.crt"), nil
			}
			return nil, nil
		}
	}
	rows := []struct {
		name string
		prep func(s *Store) error // before reads are recorded
		run  func(s *Store, now time.Time) error
		want func(state string) ([]string, error)
	}{
		{name: "OpenForRead",
			run:  func(s *Store, now time.Time) error { _, err := s.OpenForRead(rand.Reader, now); return err },
			want: opening("reader")},
		{name: "OpenForWrite (consent)",
			run:  func(s *Store, now time.Time) error { _, err := s.OpenForWrite(consent, rand.Reader, now); return err },
			want: opening("writer")},
		{name: "OpenForWrite (no consent)",
			run:  func(s *Store, now time.Time) error { _, err := s.OpenForWrite(Consent{}, rand.Reader, now); return err },
			want: always(nil, ErrNoConsent)},
		{name: "OpenForWrite (--yes)",
			run: func(s *Store, now time.Time) error {
				_, err := s.OpenForWrite(GiveConsent(ConsentYes), rand.Reader, now)
				return err
			},
			want: opening("writer")},
		{name: "OpenForEnrolment(Reader)",
			run: func(s *Store, now time.Time) error {
				_, err := s.OpenForEnrolment(Reader, rand.Reader, now)
				return err
			},
			want: opening("reader")},
		{name: "OpenForEnrolment(Writer)",
			run: func(s *Store, now time.Time) error {
				_, err := s.OpenForEnrolment(Writer, rand.Reader, now)
				return err
			},
			want: opening("writer")},
		{name: "OpenForEnrolment(Writer) once verified",
			prep: func(s *Store) error { return s.EnrolmentVerified(Writer) },
			run: func(s *Store, now time.Time) error {
				_, err := s.OpenForEnrolment(Writer, rand.Reader, now)
				return err
			},
			want: always(nil, ErrNotEnrolling)},
		{name: "OpenForEnrolment(Reader) once verified",
			prep: func(s *Store) error { return s.EnrolmentVerified(Reader) },
			run: func(s *Store, now time.Time) error {
				_, err := s.OpenForEnrolment(Reader, rand.Reader, now)
				return err
			},
			want: always(nil, ErrNotEnrolling)},
		{name: "EnrolmentVerified(Writer)",
			run:  func(s *Store, now time.Time) error { return s.EnrolmentVerified(Writer) },
			want: always(nil, nil)},
		{name: "EnrolmentVerified(Reader)",
			run:  func(s *Store, now time.Time) error { return s.EnrolmentVerified(Reader) },
			want: always(nil, nil)},
		{name: "RenewReaderLeaf",
			run:  func(s *Store, now time.Time) error { _, err := s.RenewReaderLeaf(rand.Reader, now); return err },
			want: always(under("reader", "anchor.crt", "anchor.key"), nil)},
		{name: "RenewWriterLeaf (consent)",
			run: func(s *Store, now time.Time) error {
				_, err := s.RenewWriterLeaf(consent, rand.Reader, now)
				return err
			},
			want: always(under("writer", "anchor.crt", "anchor.key"), nil)},
		{name: "RenewAnchor(Reader)",
			run:  func(s *Store, now time.Time) error { _, err := s.RenewAnchor(Reader, rand.Reader, now); return err },
			want: staging("reader")},
		{name: "RenewAnchor(Writer)",
			run:  func(s *Store, now time.Time) error { _, err := s.RenewAnchor(Writer, rand.Reader, now); return err },
			want: staging("writer")},
		{name: "OpenStaged(Reader)",
			run:  func(s *Store, now time.Time) error { _, err := s.OpenStaged(Reader, Consent{}); return err },
			want: staged(under("reader.next", "anchor.crt", "leaf.crt", "leaf.key"))},
		{name: "OpenStaged(Writer) (consent)",
			run:  func(s *Store, now time.Time) error { _, err := s.OpenStaged(Writer, consent); return err },
			want: staged(under("writer.next", "anchor.crt", "leaf.crt", "leaf.key"))},
		{name: "OpenStaged(Writer) (no consent)",
			run:  func(s *Store, now time.Time) error { _, err := s.OpenStaged(Writer, Consent{}); return err },
			want: always(nil, ErrNoConsent)},
		{name: "CommitAnchor(Reader)",
			run:  func(s *Store, now time.Time) error { return s.CommitAnchor(Reader) },
			want: staged(nil)},
		{name: "CommitAnchor(Writer)",
			run:  func(s *Store, now time.Time) error { return s.CommitAnchor(Writer) },
			want: staged(nil)},
		{name: "DiscardStaged(Reader)",
			run:  func(s *Store, now time.Time) error { return s.DiscardStaged(Reader) },
			want: staged(nil)},
		{name: "DiscardStaged(Writer)",
			run:  func(s *Store, now time.Time) error { return s.DiscardStaged(Writer) },
			want: staged(nil)},
		{name: "Certificates(Reader)",
			run:  func(s *Store, now time.Time) error { _, _, _, err := s.Certificates(Reader); return err },
			want: always(under("reader", "anchor.crt", "leaf.crt"), nil)},
		{name: "Certificates(Writer)",
			run:  func(s *Store, now time.Time) error { _, _, _, err := s.Certificates(Writer); return err },
			want: always(under("writer", "anchor.crt", "leaf.crt"), nil)},
		{name: "CurrentCertificates(Reader)",
			run:  func(s *Store, now time.Time) error { _, err := s.CurrentCertificates(Reader); return err },
			want: always(under("reader", "anchor.crt", "leaf.crt"), nil)},
		{name: "CurrentCertificates(Writer)",
			run:  func(s *Store, now time.Time) error { _, err := s.CurrentCertificates(Writer); return err },
			want: always(under("writer", "anchor.crt", "leaf.crt"), nil)},
		{name: "StagedCertificates(Reader)",
			run:  func(s *Store, now time.Time) error { _, _, err := s.StagedCertificates(Reader); return err },
			want: stagedCerts("reader")},
		{name: "StagedCertificates(Writer)",
			run:  func(s *Store, now time.Time) error { _, _, err := s.StagedCertificates(Writer); return err },
			want: stagedCerts("writer")},
		{name: "RemoveRole(Writer)",
			run:  func(s *Store, now time.Time) error { return s.RemoveRole(Writer) },
			want: always(nil, nil)},
		{name: "RemoveRole(Reader) beside the writer",
			run:  func(s *Store, now time.Time) error { return s.RemoveRole(Reader) },
			want: always(nil, ErrWriterRemains)},
		{name: "AddRole(Writer)",
			prep: func(s *Store) error { return s.RemoveRole(Writer) },
			run:  func(s *Store, now time.Time) error { _, err := s.AddRole(Writer, rand.Reader, now); return err },
			want: always(nil, nil)},
		{name: "Roles",
			run:  func(s *Store, now time.Time) error { _, err := s.Roles(); return err },
			want: always(nil, nil)},
	}
	for _, row := range rows {
		for _, state := range custodyStates {
			t.Run(row.name+"/"+state, func(t *testing.T) {
				s, _, now := custodyState(t, state)
				if row.prep != nil {
					if err := row.prep(s); err != nil {
						t.Fatal(err)
					}
				}
				reads := recordReads(s)
				err := row.run(s, now)
				wantReads, wantErr := row.want(state)
				switch {
				case wantErr == nil && err != nil:
					t.Fatalf("err = %v", err)
				case wantErr != nil && !errors.Is(err, wantErr):
					t.Fatalf("err = %v, want %v", err, wantErr)
				}
				if got, want := sortedSet(*reads), sortedSet(wantReads); !slices.Equal(got, want) {
					t.Errorf("read %v, want exactly %v", got, want)
				}
			})
		}
	}

	t.Run("Enrol", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "identity")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		s := &Store{dir: dir}
		reads := recordReads(s)
		ids, err := s.enrol(rand.Reader, []Role{Reader, Writer}, t0)
		if err != nil {
			t.Fatal(err)
		}
		if len(*reads) != 0 {
			t.Errorf("enrolment read %v; it returns its identities from memory", *reads)
		}
		if len(ids) != 2 {
			t.Fatalf("got %d identities", len(ids))
		}
	})
}

// TestReadNeverOpensAWriterKeyEvenWhenUnreadable: with the writer's files and
// writer.next/ at 0000, and then with writer/ itself at 0000 too, OpenForRead
// succeeds, fresh and due, as it would not if it opened any of them.
func TestReadNeverOpensAWriterKeyEvenWhenUnreadable(t *testing.T) {
	readerOpensWithTheWriterLocked(t, func(s *Store, now time.Time) (Identity, error) {
		return s.OpenForRead(rand.Reader, now)
	})
}

// TestEnrolmentReaderNeverOpensAWriterKeyEvenWhenUnreadable: the same for
// OpenForEnrolment(Reader), a resumed enrolment's reader, which takes no
// consent: with the writer's files and writer.next/ at 0000, and then with
// writer/ itself at 0000 too, it succeeds, fresh and due, and looks at
// nothing under them, the writer's enrolment marker included.
func TestEnrolmentReaderNeverOpensAWriterKeyEvenWhenUnreadable(t *testing.T) {
	readerOpensWithTheWriterLocked(t, func(s *Store, now time.Time) (Identity, error) {
		return s.OpenForEnrolment(Reader, rand.Reader, now)
	})
}

// readerOpensWithTheWriterLocked locks the writer's files and writer.next/ at
// 0000, and checks that open gives the reader, fresh and due, and that the
// store's reader looked at no name under writer/ or writer.next/. It does it
// twice, on a new store each time: the second time writer/ itself is 0000
// too, so a stat of any name under it fails, its enrolment marker included,
// and an opening that looks at one, even only to stat it, fails.
func readerOpensWithTheWriterLocked(t *testing.T, open func(s *Store, now time.Time) (Identity, error)) {
	t.Helper()
	skipIfRoot(t)
	for _, lockDir := range []bool{false, true} {
		name := "the writer's files"
		if lockDir {
			name = "writer/ itself"
		}
		t.Run(name, func(t *testing.T) {
			s, dir, _ := enrolBoth(t)
			if _, err := s.RenewAnchor(Writer, rand.Reader, fresh); err != nil {
				t.Fatal(err)
			}
			var locked []string
			for _, f := range []string{"anchor.key", "anchor.crt", "leaf.key", "leaf.crt"} {
				locked = append(locked, filepath.Join(dir, "writer", f), filepath.Join(dir, "writer.next", f))
			}
			locked = append(locked, filepath.Join(dir, "writer.next"))
			if lockDir {
				locked = append(locked, filepath.Join(dir, "writer"))
			}
			for _, p := range locked {
				if err := os.Chmod(p, 0o000); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() {
				for i := len(locked) - 1; i >= 0; i-- {
					mode := os.FileMode(0o600)
					if b := filepath.Base(locked[i]); b == "writer.next" || b == "writer" {
						mode = 0o700
					}
					_ = os.Chmod(locked[i], mode)
				}
			})
			if _, err := os.ReadFile(filepath.Join(dir, "writer", "leaf.key")); err == nil {
				t.Skip("a mode-0000 file is readable here; the test would prove nothing")
			}
			if lockDir {
				if _, err := os.Lstat(filepath.Join(dir, "writer", "enrolling")); err == nil {
					t.Skip("a name under a mode-0000 directory can be stat-ed here; the test would prove nothing")
				}
			}
			// A read whose failure is swallowed would pass the check below
			// unseen, so every name the store's reader looks at is watched too:
			// its Lstat comes before the open that would fail.
			var looked []string
			s.hooks.afterLstat = func(rel string) { looked = append(looked, rel) }
			for _, now := range []time.Time{fresh, due} {
				id, err := open(s, now)
				if err != nil {
					t.Fatalf("opening the reader at %v with %s unreadable: %v", now, name, err)
				}
				if id.Role() != Reader {
					t.Errorf("opening the reader gave a %s identity", id.Role())
				}
			}
			if len(looked) == 0 {
				t.Fatal("the afterLstat hook saw no read; the watch proves nothing")
			}
			if !slices.Contains(looked, "reader/anchor.key") {
				t.Errorf("the due opening did not renew under the reader's anchor: looked at %v", looked)
			}
			for _, rel := range looked {
				if strings.HasPrefix(rel, "writer/") || strings.HasPrefix(rel, "writer.next/") {
					t.Errorf("opening the reader looked at %s", rel)
				}
			}
		})
	}
}

// TestOpenForWriteRefusesWithoutConsent: no consent opens nothing, for
// OpenForWrite and RenewWriterLeaf alike.
func TestOpenForWriteRefusesWithoutConsent(t *testing.T) {
	s, _, _ := enrolBoth(t)
	reads := recordReads(s)
	lstats := 0
	s.hooks.afterLstat = func(string) { lstats++ }
	for _, c := range []Consent{{}, GiveConsent(0), GiveConsent(4), GiveConsent(-1)} {
		if c.Given() {
			t.Errorf("%+v is given", c)
		}
		if _, err := s.OpenForWrite(c, failingReader{}, fresh); !errors.Is(err, ErrNoConsent) {
			t.Errorf("OpenForWrite(%+v): err = %v, want ErrNoConsent", c, err)
		}
		if _, err := s.RenewWriterLeaf(c, failingReader{}, fresh); !errors.Is(err, ErrNoConsent) {
			t.Errorf("RenewWriterLeaf(%+v): err = %v, want ErrNoConsent", c, err)
		}
	}
	if len(*reads) != 0 || lstats != 0 {
		t.Errorf("a refused call read %v (%d stats)", *reads, lstats)
	}
	for _, k := range []ConsentKind{ConsentConfirmed, ConsentAnswered, ConsentYes} {
		c := GiveConsent(k)
		if !c.Given() {
			t.Errorf("GiveConsent(%d) is not given", k)
		}
		if id, err := s.OpenForWrite(c, rand.Reader, fresh); err != nil || id.Role() != Writer {
			t.Errorf("OpenForWrite with consent %d: %v, %v", k, id, err)
		}
		if id, err := s.RenewWriterLeaf(c, rand.Reader, fresh); err != nil || id.Role() != Writer {
			t.Errorf("RenewWriterLeaf with consent %d: %v, %v", k, id, err)
		}
	}

	// A staged writer renewal opens under each kind of consent, and under
	// none of the refused ones, which read nothing.
	staged, err := s.RenewAnchor(Writer, rand.Reader, fresh)
	if err != nil {
		t.Fatal(err)
	}
	*reads, lstats = nil, 0
	for _, c := range []Consent{{}, GiveConsent(0), GiveConsent(4), GiveConsent(-1)} {
		if _, err := s.OpenStaged(Writer, c); !errors.Is(err, ErrNoConsent) {
			t.Errorf("OpenStaged(Writer) with %+v: err = %v, want ErrNoConsent", c, err)
		}
	}
	if len(*reads) != 0 || lstats != 0 {
		t.Errorf("a refused OpenStaged read %v (%d stats)", *reads, lstats)
	}
	for _, k := range []ConsentKind{ConsentConfirmed, ConsentAnswered, ConsentYes} {
		id, err := s.OpenStaged(Writer, GiveConsent(k))
		if err != nil || id.Role() != Writer || !bytes.Equal(id.LeafDER(), staged.LeafDER()) {
			t.Errorf("OpenStaged(Writer) with consent %d: %v, %v", k, id, err)
		}
	}
}

// TestConsentKinds: GiveConsent gives back each of its three kinds, and the
// zero Consent for anything else; Given is true for the three, and Confirmed
// for --confirm alone, which is what M5's broker admits.
func TestConsentKinds(t *testing.T) {
	if ConsentConfirmed == ConsentAnswered || ConsentConfirmed == ConsentYes || ConsentAnswered == ConsentYes {
		t.Fatal("two consent kinds share a value")
	}
	rows := []struct {
		kind             ConsentKind
		given, confirmed bool
	}{
		{ConsentConfirmed, true, true},
		{ConsentAnswered, true, false},
		{ConsentYes, true, false},
		{0, false, false},
		{4, false, false},
		{-1, false, false},
		{-3, false, false},
	}
	for _, row := range rows {
		c := GiveConsent(row.kind)
		if c.Given() != row.given || c.Confirmed() != row.confirmed {
			t.Errorf("GiveConsent(%d): Given %v, Confirmed %v; want %v, %v", row.kind, c.Given(), c.Confirmed(), row.given, row.confirmed)
		}
		want := row.kind
		if !row.given {
			want = 0
		}
		if c.Kind() != want {
			t.Errorf("GiveConsent(%d).Kind() = %d, want %d", row.kind, c.Kind(), want)
		}
		if !row.given && c != (Consent{}) {
			t.Errorf("GiveConsent(%d) is not the zero Consent", row.kind)
		}
	}
	var zero Consent
	if zero.Given() || zero.Confirmed() || zero.Kind() != 0 {
		t.Error("the zero Consent is a consent")
	}
	// Given and Confirmed name their kinds, not "any kind but 0": a Consent
	// of another kind, which only this package could build, is neither.
	for _, k := range []ConsentKind{4, 5, -1, -3, 100} {
		if c := (Consent{kind: k}); c.Given() || c.Confirmed() {
			t.Errorf("a Consent of kind %d: Given %v, Confirmed %v; want neither", k, c.Given(), c.Confirmed())
		}
	}
	// The three kinds stay distinct as consents, not only as numbers.
	yes, answered, confirmed := GiveConsent(ConsentYes), GiveConsent(ConsentAnswered), GiveConsent(ConsentConfirmed)
	if yes == answered || yes == confirmed || answered == confirmed {
		t.Error("two consent kinds give the same Consent")
	}
}

// TestOpenForEnrolmentRenewsTheWriterUnderItsOwnAnchor: a resumed enrolment
// opens the writer with no consent, renews a due writer leaf under the
// writer's own anchor, writes it, and leaves the reader's files alone.
func TestOpenForEnrolmentRenewsTheWriterUnderItsOwnAnchor(t *testing.T) {
	s, dir, ids := enrolBoth(t)
	readerBefore := snapshot(t, filepath.Join(dir, "reader"))
	reads := recordReads(s)
	id, err := s.OpenForEnrolment(Writer, rand.Reader, due)
	if err != nil {
		t.Fatal(err)
	}
	if id.Role() != Writer || !id.ID().Equal(ids[1].ID()) {
		t.Fatalf("OpenForEnrolment(Writer) gave the %s identity, or another ID", id.Role())
	}
	if bytes.Equal(id.LeafDER(), ids[1].LeafDER()) {
		t.Fatal("the due writer leaf was not renewed")
	}
	if got, want := sortedSet(*reads), sortedSet(under("writer", "anchor.crt", "anchor.key", "leaf.crt", "leaf.key")); !slices.Equal(got, want) {
		t.Errorf("read %v, want exactly %v", got, want)
	}
	leaf, err := x509.ParseCertificate(id.LeafDER())
	if err != nil {
		t.Fatal(err)
	}
	writerAnchor := readCert(t, filepath.Join(dir, "writer", "anchor.crt"))
	readerAnchor := readCert(t, filepath.Join(dir, "reader", "anchor.crt"))
	if err := leaf.CheckSignatureFrom(writerAnchor); err != nil {
		t.Errorf("the new writer leaf does not verify under the writer anchor: %v", err)
	}
	if err := leaf.CheckSignatureFrom(readerAnchor); err == nil {
		t.Error("the new writer leaf verifies under the reader anchor")
	}
	if leaf.Subject.CommonName != ids[1].ID().Hex() {
		t.Error("the new writer leaf's CN is not the writer's role ID")
	}
	if LeafDue(leaf, writerAnchor, due) {
		t.Error("the renewed writer leaf is due at once")
	}
	if onDisk := readCert(t, filepath.Join(dir, "writer", "leaf.crt")); !bytes.Equal(onDisk.Raw, id.LeafDER()) {
		t.Error("the renewed writer leaf was not written")
	}
	if !readKey(t, filepath.Join(dir, "writer", "leaf.key")).PublicKey.Equal(id.Signer().Public()) {
		t.Error("the renewed writer leaf key on disk is not the identity's")
	}
	if !sameFiles(readerBefore, snapshot(t, filepath.Join(dir, "reader"))) {
		t.Error("the reader's files changed")
	}

	// Not due: the same leaf again, and no anchor key opened.
	*reads = nil
	again, err := s.OpenForEnrolment(Writer, rand.Reader, due)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again.LeafDER(), id.LeafDER()) {
		t.Error("a fresh writer leaf was renewed")
	}
	if slices.Contains(*reads, "writer/anchor.key") {
		t.Errorf("a fresh writer leaf opened the anchor key: read %v", *reads)
	}
}

// TestOpenForEnrolmentRefuses: no role, no random source, and a role the
// device does not hold are refused before anything is read.
func TestOpenForEnrolmentRefuses(t *testing.T) {
	s, _, _ := enrolBoth(t)
	reads := recordReads(s)
	lstats := 0
	s.hooks.afterLstat = func(string) { lstats++ }
	for _, r := range []Role{0, 3, -1} {
		if _, err := s.OpenForEnrolment(r, rand.Reader, fresh); !isNoSuchRole(err) {
			t.Errorf("OpenForEnrolment(%v): err = %v, want the role refused as no role", r, err)
		}
	}
	for _, r := range []Role{Reader, Writer} {
		if _, err := s.OpenForEnrolment(r, nil, fresh); err == nil {
			t.Errorf("OpenForEnrolment(%s) with no random source succeeded", r)
		}
	}
	if len(*reads) != 0 || lstats != 0 {
		t.Errorf("a refused call read %v (%d stats)", *reads, lstats)
	}
	dir := filepath.Join(t.TempDir(), "identity")
	ro, _, err := Enrol(rand.Reader, dir, []Role{Reader}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ro.OpenForEnrolment(Writer, rand.Reader, fresh); !errors.Is(err, ErrNoRole) {
		t.Errorf("OpenForEnrolment(Writer) on a reader-only device: err = %v, want ErrNoRole", err)
	}
	if id, err := ro.OpenForEnrolment(Reader, rand.Reader, fresh); err != nil || id.Role() != Reader {
		t.Errorf("OpenForEnrolment(Reader) on a reader-only device: %v, %v", id, err)
	}
}

// TestTheEnrolmentWindow: Enrol and AddRole open a role's enrolment window, a
// 0600 marker in the role's directory, and OpenForEnrolment opens the role
// only while it is open. EnrolmentVerified closes it and reads nothing; from
// then on OpenForEnrolment is ErrNotEnrolling and reads nothing, while
// OpenForRead and a consented OpenForWrite still open. A staged renewal never
// holds a marker, so its commit closes the window too.
func TestTheEnrolmentWindow(t *testing.T) {
	s, dir, _ := enrolBoth(t)
	for _, role := range []string{"reader", "writer"} {
		assertPerm(t, filepath.Join(dir, role, "enrolling"), 0o600)
	}
	for _, r := range []Role{Reader, Writer} {
		if _, err := s.OpenForEnrolment(r, rand.Reader, fresh); err != nil {
			t.Fatalf("OpenForEnrolment(%s) in its window: %v", r, err)
		}
	}

	reads := recordReads(s)
	lstats := 0
	s.hooks.afterLstat = func(string) { lstats++ }
	if err := s.EnrolmentVerified(Writer); err != nil {
		t.Fatal(err)
	}
	if len(*reads) != 0 || lstats != 0 {
		t.Errorf("EnrolmentVerified read %v (%d stats)", *reads, lstats)
	}
	if _, err := os.Lstat(filepath.Join(dir, "writer", "enrolling")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the writer's marker is still there: %v", err)
	}
	for _, now := range []time.Time{fresh, due} {
		if _, err := s.OpenForEnrolment(Writer, rand.Reader, now); !errors.Is(err, ErrNotEnrolling) {
			t.Errorf("OpenForEnrolment(Writer) once verified, at %v: err = %v, want ErrNotEnrolling", now, err)
		}
	}
	if len(*reads) != 0 || lstats != 0 {
		t.Errorf("a refused OpenForEnrolment read %v (%d stats)", *reads, lstats)
	}
	if err := s.EnrolmentVerified(Writer); err != nil {
		t.Errorf("EnrolmentVerified on a closed window: %v", err)
	}
	s.hooks = storeHooks{}

	// The reader's window is its own, and the writer opens after a consent.
	if id, err := s.OpenForEnrolment(Reader, rand.Reader, fresh); err != nil || id.Role() != Reader {
		t.Errorf("OpenForEnrolment(Reader) beside a verified writer: %v, %v", id, err)
	}
	if _, err := s.OpenForWrite(GiveConsent(ConsentYes), rand.Reader, fresh); err != nil {
		t.Errorf("OpenForWrite once the writer's enrolment is verified: %v", err)
	}
	if err := s.EnrolmentVerified(Reader); err != nil {
		t.Fatal(err)
	}
	if _, err := s.OpenForEnrolment(Reader, rand.Reader, fresh); !errors.Is(err, ErrNotEnrolling) {
		t.Errorf("OpenForEnrolment(Reader) once verified: err = %v, want ErrNotEnrolling", err)
	}
	if _, err := s.OpenForRead(rand.Reader, fresh); err != nil {
		t.Errorf("OpenForRead once the reader's enrolment is verified: %v", err)
	}

	// AddRole opens a window for the role it makes.
	if err := s.RemoveRole(Writer); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRole(Writer, rand.Reader, fresh); err != nil {
		t.Fatal(err)
	}
	assertPerm(t, filepath.Join(dir, "writer", "enrolling"), 0o600)
	if _, err := s.OpenForEnrolment(Writer, rand.Reader, fresh); err != nil {
		t.Errorf("OpenForEnrolment(Writer) after AddRole: %v", err)
	}

	// A staged renewal holds no marker, and its commit closes the window.
	if _, err := s.RenewAnchor(Writer, rand.Reader, fresh); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "writer.next", "enrolling")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a staged renewal holds a marker: %v", err)
	}
	if _, err := s.OpenForEnrolment(Writer, rand.Reader, fresh); err != nil {
		t.Errorf("OpenForEnrolment(Writer) beside a staged renewal: %v", err)
	}
	if err := s.CommitAnchor(Writer); err != nil {
		t.Fatal(err)
	}
	if _, err := s.OpenForEnrolment(Writer, rand.Reader, fresh); !errors.Is(err, ErrNotEnrolling) {
		t.Errorf("OpenForEnrolment(Writer) after a committed renewal: err = %v, want ErrNotEnrolling", err)
	}

	// No role, and no such role.
	ro, _, err := Enrol(rand.Reader, filepath.Join(t.TempDir(), "identity"), []Role{Reader}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := ro.EnrolmentVerified(Writer); !errors.Is(err, ErrNoRole) {
		t.Errorf("EnrolmentVerified(Writer) on a reader-only device: err = %v, want ErrNoRole", err)
	}
	for _, r := range []Role{0, 3, -1} {
		if err := s.EnrolmentVerified(r); !isNoSuchRole(err) {
			t.Errorf("EnrolmentVerified(%v): err = %v, want the role refused as no role", r, err)
		}
	}
}

// isNoSuchRole reports whether err is the package's refusal of a Role that
// is neither Reader nor Writer (errNoSuchRole), given before the store is
// looked at: not ErrNoRole, nor an error from a path built from no role.
func isNoSuchRole(err error) bool {
	return err != nil && strings.HasSuffix(err.Error(), " is not a role") && !errors.Is(err, ErrNoRole)
}

// TestAnEnrolmentMarkerMustBeAPlainPrivateFile: a marker that is a symlink,
// a dangling one included, a directory, or a file other accounts can read is
// ErrUnsafeMode, and nothing is read.
func TestAnEnrolmentMarkerMustBeAPlainPrivateFile(t *testing.T) {
	replace := func(t *testing.T, p string, make func() error) {
		t.Helper()
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := make(); err != nil {
			t.Fatal(err)
		}
	}
	for name, plant := range map[string]func(t *testing.T, p string){
		"a symlink to the leaf": func(t *testing.T, p string) {
			replace(t, p, func() error { return os.Symlink("leaf.crt", p) })
		},
		"a dangling symlink": func(t *testing.T, p string) {
			replace(t, p, func() error { return os.Symlink("nowhere", p) })
		},
		"a directory": func(t *testing.T, p string) {
			replace(t, p, func() error { return os.Mkdir(p, 0o700) })
		},
		"a 0644 file": func(t *testing.T, p string) {
			if err := os.Chmod(p, 0o644); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, dir, _ := enrolBoth(t)
			plant(t, filepath.Join(dir, "writer", "enrolling"))
			reads := recordReads(s)
			if _, err := s.OpenForEnrolment(Writer, rand.Reader, fresh); !errors.Is(err, ErrUnsafeMode) {
				t.Errorf("OpenForEnrolment(Writer): err = %v, want ErrUnsafeMode", err)
			}
			if len(*reads) != 0 {
				t.Errorf("a refused OpenForEnrolment read %v", *reads)
			}
		})
	}
}

// TestRemoveRoleKeepsTheReaderWhileAWriterRemains: RemoveRole(Reader) is
// refused with ErrWriterRemains, and removes nothing, while any of the
// writer's three names is there, whatever it is; once the writer is gone it
// removes the reader.
func TestRemoveRoleKeepsTheReaderWhileAWriterRemains(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, s *Store, dir string)
	}{
		{"writer/", func(*testing.T, *Store, string) {}},
		{"writer/ and writer.next/", func(t *testing.T, s *Store, _ string) {
			if _, err := s.RenewAnchor(Writer, rand.Reader, fresh); err != nil {
				t.Fatal(err)
			}
		}},
		{"an interrupted commit: writer.old/ and writer.next/", func(t *testing.T, s *Store, dir string) {
			if _, err := s.RenewAnchor(Writer, rand.Reader, fresh); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(filepath.Join(dir, "writer"), filepath.Join(dir, "writer.old")); err != nil {
				t.Fatal(err)
			}
		}},
		{"writer.old/ alone", func(t *testing.T, _ *Store, dir string) {
			if err := os.Rename(filepath.Join(dir, "writer"), filepath.Join(dir, "writer.old")); err != nil {
				t.Fatal(err)
			}
		}},
		{"writer.next/ alone", func(t *testing.T, _ *Store, dir string) {
			if err := os.Rename(filepath.Join(dir, "writer"), filepath.Join(dir, "writer.next")); err != nil {
				t.Fatal(err)
			}
		}},
		{"writer/ at 0755", func(t *testing.T, _ *Store, dir string) {
			if err := os.Chmod(filepath.Join(dir, "writer"), 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{"writer a plain file", func(t *testing.T, _ *Store, dir string) {
			if err := os.RemoveAll(filepath.Join(dir, "writer")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "writer"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"writer a symlink", func(t *testing.T, _ *Store, dir string) {
			if err := os.RemoveAll(filepath.Join(dir, "writer")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join("reader", "leaf.crt"), filepath.Join(dir, "writer")); err != nil {
				t.Fatal(err)
			}
		}},
		{"writer a dangling symlink", func(t *testing.T, _ *Store, dir string) {
			// A Stat that follows the link finds nothing; only Lstat sees it.
			if err := os.RemoveAll(filepath.Join(dir, "writer")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("nowhere", filepath.Join(dir, "writer")); err != nil {
				t.Fatal(err)
			}
		}},
		{"writer.old a dangling symlink", func(t *testing.T, _ *Store, dir string) {
			if err := os.RemoveAll(filepath.Join(dir, "writer")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("nowhere", filepath.Join(dir, "writer.old")); err != nil {
				t.Fatal(err)
			}
		}},
		{"the store at 0755", func(t *testing.T, _ *Store, dir string) {
			if err := os.Chmod(dir, 0o755); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, dir, _ := enrolBoth(t)
			tc.setup(t, s, dir)
			before := snapshot(t, dir)
			err := s.RemoveRole(Reader)
			if !errors.Is(err, ErrWriterRemains) {
				t.Fatalf("RemoveRole(Reader) beside the writer: err = %v, want ErrWriterRemains", err)
			}
			if !sameFiles(before, snapshot(t, dir)) {
				t.Error("the refused RemoveRole(Reader) changed the store")
			}
			if _, err := os.Lstat(filepath.Join(dir, "reader", "anchor.key")); err != nil {
				t.Errorf("the reader's anchor key is gone: %v", err)
			}
		})
	}

	s, dir, _ := enrolBoth(t)
	if err := s.RemoveRole(Writer); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveRole(Reader); err != nil {
		t.Fatalf("RemoveRole(Reader) once the writer is gone: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "reader")); !errors.Is(err, fs.ErrNotExist) {
		t.Error("reader/ is still there after RemoveRole(Reader)")
	}
}

// TestReaderLeafIsRenewedWithTheReaderAnchorKey: a due reader leaf is renewed
// under the reader anchor, and the writer's files are not touched.
func TestReaderLeafIsRenewedWithTheReaderAnchorKey(t *testing.T) {
	s, dir, ids := enrolBoth(t)
	before := snapshot(t, filepath.Join(dir, "writer"))
	id, err := s.OpenForRead(rand.Reader, due)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(id.LeafDER(), ids[0].LeafDER()) {
		t.Fatal("the due leaf was not renewed")
	}
	leaf, err := x509.ParseCertificate(id.LeafDER())
	if err != nil {
		t.Fatal(err)
	}
	readerAnchor := readCert(t, filepath.Join(dir, "reader", "anchor.crt"))
	writerAnchor := readCert(t, filepath.Join(dir, "writer", "anchor.crt"))
	if err := leaf.CheckSignatureFrom(readerAnchor); err != nil {
		t.Errorf("the new reader leaf does not verify under the reader anchor: %v", err)
	}
	if err := leaf.CheckSignatureFrom(writerAnchor); err == nil {
		t.Error("the new reader leaf verifies under the writer anchor")
	}
	if LeafDue(leaf, readerAnchor, due) {
		t.Error("the renewed leaf is due at once")
	}
	if onDisk := readCert(t, filepath.Join(dir, "reader", "leaf.crt")); !bytes.Equal(onDisk.Raw, id.LeafDER()) {
		t.Error("the renewed leaf was not written")
	}
	if !readKey(t, filepath.Join(dir, "reader", "leaf.key")).PublicKey.Equal(id.Signer().Public()) {
		t.Error("the renewed leaf key on disk is not the identity's")
	}
	if !sameFiles(before, snapshot(t, filepath.Join(dir, "writer"))) {
		t.Error("the writer's files changed")
	}
}

// TestALeafKeyMismatchIsRepairedByRenewal: a leaf.key from one renewal under a
// leaf.crt from another is due, and renewal repairs it; a staged renewal with
// the same mismatch is inconsistent.
func TestALeafKeyMismatchIsRepairedByRenewal(t *testing.T) {
	consent := GiveConsent(ConsentAnswered)
	for _, tc := range []struct {
		role  string
		renew func(s *Store) error
		open  func(s *Store) (Identity, error)
	}{
		{"reader",
			func(s *Store) error { _, err := s.RenewReaderLeaf(rand.Reader, fresh); return err },
			func(s *Store) (Identity, error) { return s.OpenForRead(rand.Reader, fresh) }},
		{"writer",
			func(s *Store) error { _, err := s.RenewWriterLeaf(consent, rand.Reader, fresh); return err },
			func(s *Store) (Identity, error) { return s.OpenForWrite(consent, rand.Reader, fresh) }},
	} {
		t.Run(tc.role, func(t *testing.T) {
			s, dir, _ := enrolBoth(t)
			keyPath := filepath.Join(dir, tc.role, "leaf.key")
			if err := tc.renew(s); err != nil {
				t.Fatal(err)
			}
			first, err := os.ReadFile(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.renew(s); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(keyPath, first, 0o600); err != nil {
				t.Fatal(err)
			}
			reads := recordReads(s)
			id, err := tc.open(s)
			if err != nil {
				t.Fatalf("opening with a mismatched leaf key: %v", err)
			}
			if !slices.Contains(*reads, tc.role+"/anchor.key") {
				t.Errorf("the mismatch was not renewed: read %v", *reads)
			}
			leaf := readCert(t, filepath.Join(dir, tc.role, "leaf.crt"))
			key := readKey(t, keyPath)
			if !key.PublicKey.Equal(leaf.PublicKey) {
				t.Error("after the repair, leaf.key and leaf.crt still do not match")
			}
			if !bytes.Equal(id.LeafDER(), leaf.Raw) || !key.PublicKey.Equal(id.Signer().Public()) {
				t.Error("the identity is not the repaired pair")
			}
		})
	}

	t.Run("staged", func(t *testing.T) {
		s, dir, _ := enrolBoth(t)
		if _, err := s.RenewAnchor(Reader, rand.Reader, fresh); err != nil {
			t.Fatal(err)
		}
		writeKeyFile(t, filepath.Join(dir, "reader.next", "leaf.key"), mustKey(t))
		_, err := s.OpenStaged(Reader, Consent{})
		if !errors.Is(err, ErrInconsistent) {
			t.Fatalf("OpenStaged with a mismatched leaf key: err = %v, want ErrInconsistent", err)
		}
		if !strings.Contains(err.Error(), "reader.next/leaf.key") {
			t.Errorf("the error %q does not name the staged leaf key", err)
		}
	})
}

// TestRenewAnchorStagesAndCommits: a renewal is staged beside the current
// role, opened for its verification, committed with the same ID, discarded,
// and resumed after an interrupted commit.
func TestRenewAnchorStagesAndCommits(t *testing.T) {
	consent := GiveConsent(ConsentConfirmed)
	s, dir, ids := enrolBoth(t)
	writerDir := filepath.Join(dir, "writer")
	readerBefore := snapshot(t, filepath.Join(dir, "reader"))
	writerBefore := snapshot(t, writerDir)
	oldLeaf := readCert(t, filepath.Join(writerDir, "leaf.crt"))
	oldAnchor := readCert(t, filepath.Join(writerDir, "anchor.crt"))

	// 1. RenewAnchor stages writer.next/ and leaves writer/ as it was.
	stagedID, err := s.RenewAnchor(Writer, rand.Reader, fresh)
	if err != nil {
		t.Fatal(err)
	}
	if !sameFiles(writerBefore, snapshot(t, writerDir)) {
		t.Fatal("RenewAnchor changed writer/")
	}
	assertPerm(t, filepath.Join(dir, "writer.next"), 0o700)
	for _, f := range []string{"anchor.key", "anchor.crt", "leaf.key", "leaf.crt"} {
		assertPerm(t, filepath.Join(dir, "writer.next", f), 0o600)
	}
	current, err := s.OpenForWrite(consent, rand.Reader, fresh)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(current.LeafDER(), oldLeaf.Raw) || !bytes.Equal(current.AnchorDER(), oldAnchor.Raw) {
		t.Error("OpenForWrite no longer returns the current identity while a renewal is staged")
	}

	// 2. OpenStaged returns the staged identity: the same ID, a new anchor
	// key, and its leaf under the new anchor.
	opened, err := s.OpenStaged(Writer, GiveConsent(ConsentConfirmed))
	if err != nil {
		t.Fatal(err)
	}
	if !opened.ID().Equal(ids[1].ID()) || !stagedID.ID().Equal(ids[1].ID()) {
		t.Error("the staged renewal has another role ID")
	}
	if !bytes.Equal(opened.LeafDER(), stagedID.LeafDER()) || !bytes.Equal(opened.AnchorDER(), stagedID.AnchorDER()) {
		t.Error("OpenStaged does not return what RenewAnchor staged")
	}
	newAnchorCert, err := x509.ParseCertificate(opened.AnchorDER())
	if err != nil {
		t.Fatal(err)
	}
	if newAnchorCert.PublicKey.(*ecdsa.PublicKey).Equal(oldAnchor.PublicKey) {
		t.Error("the staged anchor reuses the current anchor key")
	}
	if newAnchorCert.Subject.CommonName != ids[1].ID().Hex() {
		t.Error("the staged anchor's CN is not the role ID")
	}
	stagedLeaf, err := x509.ParseCertificate(opened.LeafDER())
	if err != nil {
		t.Fatal(err)
	}
	if err := stagedLeaf.CheckSignatureFrom(newAnchorCert); err != nil {
		t.Errorf("the staged leaf does not verify under the staged anchor: %v", err)
	}

	// 3. A second renewal is refused while one is staged.
	if _, err := s.RenewAnchor(Writer, rand.Reader, fresh); !errors.Is(err, ErrRenewalStaged) {
		t.Errorf("a second RenewAnchor: err = %v, want ErrRenewalStaged", err)
	}

	// 4. CommitAnchor makes it current.
	if err := s.CommitAnchor(Writer); err != nil {
		t.Fatal(err)
	}
	committed := readCert(t, filepath.Join(writerDir, "anchor.crt"))
	if !bytes.Equal(committed.Raw, opened.AnchorDER()) {
		t.Error("writer/anchor.crt is not the staged anchor after the commit")
	}
	if !LeafDue(oldLeaf, committed, fresh) {
		t.Error("the old leaf is not due under the new anchor")
	}
	for _, gone := range []string{"writer.next", "writer.old"} {
		if _, err := os.Lstat(filepath.Join(dir, gone)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s is still there after the commit", gone)
		}
	}
	if !sameFiles(readerBefore, snapshot(t, filepath.Join(dir, "reader"))) {
		t.Error("the commit changed the reader's files")
	}
	if err := s.CommitAnchor(Writer); !errors.Is(err, ErrNothingStaged) {
		t.Errorf("a second commit: err = %v, want ErrNothingStaged", err)
	}

	// 5. DiscardStaged removes a staged renewal and nothing else.
	if _, err := s.RenewAnchor(Reader, rand.Reader, fresh); err != nil {
		t.Fatal(err)
	}
	all := snapshot(t, dir)
	if err := s.DiscardStaged(Reader); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "reader.next")); !errors.Is(err, fs.ErrNotExist) {
		t.Error("reader.next is still there after DiscardStaged")
	}
	for name := range all {
		if strings.HasPrefix(name, "reader.next/") {
			delete(all, name)
		}
	}
	if !sameFiles(all, snapshot(t, dir)) {
		t.Error("DiscardStaged changed something besides reader.next")
	}
	if err := s.DiscardStaged(Reader); !errors.Is(err, ErrNothingStaged) {
		t.Errorf("DiscardStaged with nothing staged: err = %v, want ErrNothingStaged", err)
	}

	// 6. An interrupted commit: only the first rename was made.
	staged2, err := s.RenewAnchor(Writer, rand.Reader, fresh)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(writerDir, filepath.Join(dir, "writer.old")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.OpenForWrite(consent, rand.Reader, fresh); !errors.Is(err, ErrRenewalInterrupted) {
		t.Errorf("OpenForWrite during an interrupted commit: err = %v, want ErrRenewalInterrupted", err)
	}
	if _, _, _, err := s.Certificates(Writer); !errors.Is(err, ErrRenewalInterrupted) {
		t.Errorf("Certificates during an interrupted commit: err = %v, want ErrRenewalInterrupted", err)
	}
	if _, err := s.Roles(); !errors.Is(err, ErrRenewalInterrupted) {
		t.Errorf("Roles during an interrupted commit: err = %v, want ErrRenewalInterrupted", err)
	}
	if err := s.CommitAnchor(Writer); err != nil {
		t.Fatalf("CommitAnchor did not resume the interrupted commit: %v", err)
	}
	resumed, err := s.OpenForWrite(consent, rand.Reader, fresh)
	if err != nil {
		t.Fatalf("OpenForWrite after the resumed commit: %v", err)
	}
	if !bytes.Equal(resumed.AnchorDER(), staged2.AnchorDER()) || !resumed.ID().Equal(ids[1].ID()) {
		t.Error("the resumed commit did not make the staged anchor current")
	}
	for _, gone := range []string{"writer.next", "writer.old"} {
		if _, err := os.Lstat(filepath.Join(dir, gone)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s is still there after the resumed commit", gone)
		}
	}
	if roles, err := s.Roles(); err != nil || !slices.Equal(roles, []Role{Reader, Writer}) {
		t.Errorf("Roles after the resumed commit = %v, %v", roles, err)
	}

	// A commit interrupted after its second rename leaves only the removal.
	if _, err := s.RenewAnchor(Writer, rand.Reader, fresh); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(writerDir, filepath.Join(dir, "writer.old")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "writer.next"), writerDir); err != nil {
		t.Fatal(err)
	}
	if err := s.CommitAnchor(Writer); err != nil {
		t.Fatalf("CommitAnchor after the second rename: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "writer.old")); !errors.Is(err, fs.ErrNotExist) {
		t.Error("writer.old is still there")
	}
}

// TestAnExpiredAnchorRenewsNothing: past its anchor's end a role issues no
// leaf and uses none, and RenewAnchor still stages a renewal.
func TestAnExpiredAnchorRenewsNothing(t *testing.T) {
	consent := GiveConsent(ConsentConfirmed)
	s, dir, ids := enrolBoth(t)
	anchorEnd := NotBefore(t0).Add(AnchorLifetime)
	past := anchorEnd.Add(time.Second)
	calls := map[string]func() error{
		"OpenForRead":     func() error { _, err := s.OpenForRead(rand.Reader, past); return err },
		"OpenForWrite":    func() error { _, err := s.OpenForWrite(consent, rand.Reader, past); return err },
		"RenewReaderLeaf": func() error { _, err := s.RenewReaderLeaf(rand.Reader, past); return err },
		"RenewWriterLeaf": func() error { _, err := s.RenewWriterLeaf(consent, rand.Reader, past); return err },
		"OpenForEnrolment(Reader)": func() error {
			_, err := s.OpenForEnrolment(Reader, rand.Reader, past)
			return err
		},
		"OpenForEnrolment(Writer)": func() error {
			_, err := s.OpenForEnrolment(Writer, rand.Reader, past)
			return err
		},
	}
	before := snapshot(t, dir)
	for name, call := range calls {
		if err := call(); !errors.Is(err, ErrAnchorExpired) {
			t.Errorf("%s under an expired anchor: err = %v, want ErrAnchorExpired", name, err)
		}
	}
	if !sameFiles(before, snapshot(t, dir)) {
		t.Error("a refused call under an expired anchor changed the store")
	}

	// An unexpired leaf under an expired anchor is not used either.
	for i, role := range []string{"reader", "writer"} {
		anchor := readCert(t, filepath.Join(dir, role, "anchor.crt"))
		anchorKey := readKey(t, filepath.Join(dir, role, "anchor.key"))
		leafKey := mustKey(t)
		tmpl := LeafTemplate(ids[i].ID(), bigOne(), anchorEnd.Add(-10*24*time.Hour), anchor)
		tmpl.NotAfter = anchorEnd.Add(80 * 24 * time.Hour)
		der, err := x509.CreateCertificate(rand.Reader, tmpl, anchor, &leafKey.PublicKey, anchorKey)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if LeafDue(leaf, anchor, past) {
			t.Fatal("the fixture's leaf is due; it must be fresh to test this")
		}
		writeCertFile(t, filepath.Join(dir, role, "leaf.crt"), der)
		writeKeyFile(t, filepath.Join(dir, role, "leaf.key"), leafKey)
	}
	if _, err := s.OpenForRead(rand.Reader, past); !errors.Is(err, ErrAnchorExpired) {
		t.Errorf("OpenForRead with a fresh leaf under an expired anchor: err = %v, want ErrAnchorExpired", err)
	}
	if _, err := s.OpenForWrite(consent, rand.Reader, past); !errors.Is(err, ErrAnchorExpired) {
		t.Errorf("OpenForWrite with a fresh leaf under an expired anchor: err = %v, want ErrAnchorExpired", err)
	}

	// RenewAnchor works under the expired anchor, which is what it is for.
	for i, r := range []Role{Reader, Writer} {
		staged, err := s.RenewAnchor(r, rand.Reader, past)
		if err != nil {
			t.Fatalf("RenewAnchor(%s) under an expired anchor: %v", r, err)
		}
		if !staged.ID().Equal(ids[i].ID()) {
			t.Errorf("the %s renewal has another ID", r)
		}
		opened, err := s.OpenStaged(r, GiveConsent(ConsentConfirmed))
		if err != nil {
			t.Fatalf("OpenStaged(%s): %v", r, err)
		}
		if !bytes.Equal(opened.LeafDER(), staged.LeafDER()) {
			t.Errorf("OpenStaged(%s) is not the staged leaf", r)
		}
		if err := s.CommitAnchor(r); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.OpenForRead(rand.Reader, past); err != nil {
		t.Errorf("OpenForRead after the renewal's commit: %v", err)
	}
}

// TestAddRoleAndRemoveRole: a writer is added to a reader-only device, and
// removed with its staged and old directories, leaving the reader alone.
func TestAddRoleAndRemoveRole(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "identity")
	s, ids, err := Enrol(rand.Reader, dir, []Role{Reader}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if roles, err := s.Roles(); err != nil || !slices.Equal(roles, []Role{Reader}) {
		t.Fatalf("Roles = %v, %v", roles, err)
	}
	if _, err := s.OpenForWrite(GiveConsent(ConsentConfirmed), rand.Reader, fresh); !errors.Is(err, ErrNoRole) {
		t.Errorf("OpenForWrite on a reader-only device: err = %v, want ErrNoRole", err)
	}
	readerBefore := snapshot(t, filepath.Join(dir, "reader"))
	w, err := s.AddRole(Writer, rand.Reader, fresh)
	if err != nil {
		t.Fatal(err)
	}
	if w.Role() != Writer || w.ID().Equal(ids[0].ID()) || w.ID().IsZero() {
		t.Error("the added writer is not a writer with an ID of its own")
	}
	assertPerm(t, filepath.Join(dir, "writer"), 0o700)
	for _, f := range []string{"anchor.key", "anchor.crt", "leaf.key", "leaf.crt"} {
		assertPerm(t, filepath.Join(dir, "writer", f), 0o600)
	}
	if roles, err := s.Roles(); err != nil || !slices.Equal(roles, []Role{Reader, Writer}) {
		t.Errorf("Roles after AddRole = %v, %v", roles, err)
	}
	if _, err := s.AddRole(Writer, rand.Reader, fresh); !errors.Is(err, ErrStoreExists) {
		t.Errorf("a second AddRole(Writer): err = %v, want ErrStoreExists", err)
	}
	if _, err := s.AddRole(Reader, rand.Reader, fresh); !errors.Is(err, ErrStoreExists) {
		t.Errorf("AddRole(Reader) on a reader: err = %v, want ErrStoreExists", err)
	}
	if _, err := s.OpenForWrite(GiveConsent(ConsentConfirmed), rand.Reader, fresh); err != nil {
		t.Errorf("OpenForWrite after AddRole: %v", err)
	}
	if _, err := s.RenewAnchor(Writer, rand.Reader, fresh); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "writer.old"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveRole(Writer); err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{"writer", "writer.next", "writer.old"} {
		if _, err := os.Lstat(filepath.Join(dir, gone)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s is still there after RemoveRole", gone)
		}
	}
	if !sameFiles(readerBefore, snapshot(t, filepath.Join(dir, "reader"))) {
		t.Error("adding and removing the writer changed the reader's files")
	}
	if roles, err := s.Roles(); err != nil || !slices.Equal(roles, []Role{Reader}) {
		t.Errorf("Roles after RemoveRole = %v, %v", roles, err)
	}

	// A writer is added only beside a reader.
	if err := s.RemoveRole(Reader); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRole(Writer, rand.Reader, fresh); !errors.Is(err, ErrNoRole) {
		t.Errorf("AddRole(Writer) with no reader: err = %v, want ErrNoRole", err)
	}
	if err := s.Erase(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Error("Erase left the directory")
	}
	if err := s.Erase(); err != nil {
		t.Errorf("Erase of an erased store: %v", err)
	}
}

// TestSignersAreOpaque: every signer the package returns hides its key, is
// its leaf's key, and completes a TLS 1.3 handshake that requires a client
// certificate.
func TestSignersAreOpaque(t *testing.T) {
	consent := GiveConsent(ConsentConfirmed)
	s, _, ids := enrolBoth(t)
	got := map[string]Identity{"Enrol reader": ids[0], "Enrol writer": ids[1]}
	add := func(name string, id Identity, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got[name] = id
	}
	id, err := s.OpenForRead(rand.Reader, fresh)
	add("OpenForRead", id, err)
	id, err = s.OpenForRead(rand.Reader, due)
	add("OpenForRead (due)", id, err)
	id, err = s.OpenForWrite(consent, rand.Reader, fresh)
	add("OpenForWrite", id, err)
	id, err = s.OpenForEnrolment(Reader, rand.Reader, fresh)
	add("OpenForEnrolment(Reader)", id, err)
	id, err = s.OpenForEnrolment(Writer, rand.Reader, due)
	add("OpenForEnrolment(Writer) (due)", id, err)
	id, err = s.RenewReaderLeaf(rand.Reader, fresh)
	add("RenewReaderLeaf", id, err)
	id, err = s.RenewWriterLeaf(consent, rand.Reader, fresh)
	add("RenewWriterLeaf", id, err)
	id, err = s.RenewAnchor(Reader, rand.Reader, fresh)
	add("RenewAnchor", id, err)
	id, err = s.OpenStaged(Reader, Consent{})
	add("OpenStaged", id, err)
	if err := s.RemoveRole(Writer); err != nil {
		t.Fatal(err)
	}
	id, err = s.AddRole(Writer, rand.Reader, fresh)
	add("AddRole", id, err)

	for name, id := range got {
		t.Run(name, func(t *testing.T) {
			signer := id.Signer()
			if _, ok := signer.(*ecdsa.PrivateKey); ok {
				t.Error("the signer is an *ecdsa.PrivateKey")
			}
			if _, ok := signer.(*rsa.PrivateKey); ok {
				t.Error("the signer is an *rsa.PrivateKey")
			}
			if _, ok := signer.(ed25519.PrivateKey); ok {
				t.Error("the signer is an ed25519.PrivateKey")
			}
			if _, ok := signer.(interface{ Bytes() ([]byte, error) }); ok {
				t.Error("the signer exposes Bytes")
			}
			leaf, err := x509.ParseCertificate(id.LeafDER())
			if err != nil {
				t.Fatal(err)
			}
			if !leaf.PublicKey.(*ecdsa.PublicKey).Equal(signer.Public()) {
				t.Error("Public() is not the leaf's key")
			}
			o, ok := signer.(opaque)
			if !ok {
				t.Fatalf("the signer is a %T, not an opaque", signer)
			}
			scalar, err := o.k.(*ecdsa.PrivateKey).Bytes()
			if err != nil {
				t.Fatal(err)
			}
			for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%X", "%d", "%q"} {
				out := fmt.Sprintf(verb, signer)
				if containsBytes(out, scalar) {
					t.Errorf("%s of the signer prints its scalar", verb)
				}
				if out != opaqueText {
					t.Errorf("%s of the signer = %q, want %q", verb, out, opaqueText)
				}
			}
			handshake(t, id)
		})
	}
}

// handshake completes a TLS 1.3 handshake with id's leaf and signer against an
// httptest server that requires and verifies a client certificate under id's
// anchor, on loopback.
func handshake(t *testing.T, id Identity) {
	t.Helper()
	anchor, err := x509.ParseCertificate(id.AnchorDER())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(id.LeafDER())
	if err != nil {
		t.Fatal(err)
	}
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(anchor)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || len(r.TLS.PeerCertificates) == 0 ||
			!bytes.Equal(r.TLS.PeerCertificates[0].Raw, leaf.Raw) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.TLS = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientCAs,
		MinVersion: tls.VersionTLS13,
		Time:       func() time.Time { return leaf.NotBefore.Add(2 * time.Hour) },
	}
	srv.StartTLS()
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	tr := &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:      roots,
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{id.LeafDER()}, PrivateKey: id.Signer()}},
	}}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr, Timeout: 30 * time.Second}).Get(srv.URL)
	if err != nil {
		t.Fatalf("the TLS 1.3 handshake with the %s signer failed: %v", id.Role(), err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("the server saw the wrong client certificate or version: %d", resp.StatusCode)
	}
}

// TestDevicekeyErrorsNameNoID: no error the package returns, made with a
// planted ID, carries that ID in any encoding.
func TestDevicekeyErrorsNameNoID(t *testing.T) {
	consent := GiveConsent(ConsentConfirmed)
	var errs []error
	note := func(err error) {
		t.Helper()
		if err == nil {
			t.Errorf("error %d: a refusal was expected", len(errs))
			return
		}
		errs = append(errs, err)
	}
	s, dir, ids := enrolBoth(t)
	planted := []RoleID{ids[0].ID(), ids[1].ID()}

	_, err := s.OpenForRead(rand.Reader, t0.Add(400*24*time.Hour))
	note(err)
	_, err = s.RenewWriterLeaf(consent, rand.Reader, t0.Add(400*24*time.Hour))
	note(err)
	_, err = s.OpenForWrite(Consent{}, rand.Reader, fresh)
	note(err)
	_, err = s.OpenStaged(Writer, consent)
	note(err)
	_, err = s.OpenStaged(Writer, Consent{})
	note(err)
	note(s.CommitAnchor(Reader))
	note(s.DiscardStaged(Writer))
	_, err = s.RenewAnchor(Writer, rand.Reader, fresh)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.RenewAnchor(Writer, rand.Reader, fresh)
	note(err)
	_, err = s.AddRole(Writer, rand.Reader, fresh)
	note(err)
	_, _, err = Enrol(rand.Reader, dir, []Role{Reader}, t0)
	note(err)
	_, err = s.AddRole(Role(9), rand.Reader, fresh)
	note(err)
	_, _, err = Enrol(rand.Reader, filepath.Join(t.TempDir(), "x"), []Role{Writer}, t0)
	note(err)
	if err := os.Rename(filepath.Join(dir, "writer"), filepath.Join(dir, "writer.old")); err != nil {
		t.Fatal(err)
	}
	_, err = s.OpenForWrite(consent, rand.Reader, fresh)
	note(err)
	_, err = s.Roles()
	note(err)
	if err := s.CommitAnchor(Writer); err != nil {
		t.Fatal(err)
	}
	// Mismatches, each made under the planted reader ID.
	anchorCrt := filepath.Join(dir, "reader", "anchor.crt")
	savedAnchor, err := os.ReadFile(anchorCrt)
	if err != nil {
		t.Fatal(err)
	}
	writeKeyFile(t, filepath.Join(dir, "reader", "leaf.key"), mustKey(t))
	writeKeyFile(t, filepath.Join(dir, "reader", "anchor.key"), mustKey(t))
	_, err = s.OpenForRead(rand.Reader, fresh)
	note(err)
	key := mustKey(t)
	tmpl, err := AnchorTemplate(planted[0], bigOne(), NotBefore(t0), &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.IsCA, tmpl.MaxPathLenZero, tmpl.KeyUsage = false, false, x509.KeyUsageDigitalSignature
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	writeCertFile(t, anchorCrt, der)
	_, _, _, err = s.Certificates(Reader)
	note(err)
	if err := os.WriteFile(anchorCrt, savedAnchor, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "reader", "leaf.crt"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = s.OpenForRead(rand.Reader, fresh)
	note(err)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err = Open(dir)
	note(err)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	// The profile's and Google's text.
	_, err = AnchorTemplate(planted[0], nil, NotBefore(t0), &key.PublicKey)
	note(err)
	_, err = AnchorTemplate(planted[0], bigOne(), NotBefore(t0), nil)
	note(err)
	for _, bad := range []string{strings.ToUpper(planted[0].Hex()), planted[0].Hex() + " ", planted[0].Hex()[:31], " " + planted[0].Hex()} {
		_, err = ParseRoleID(bad)
		note(err)
	}
	_, err = Principal("12345x", "pool1234", planted[0])
	note(err)
	_, err = Principal("123456", "gcp-pool", planted[0])
	note(err)
	_, err = TrustStoreYAML(ids[0].LeafDER())
	note(err)
	for _, row := range providerRows(t, planted[0], ids[0].AnchorDER()) {
		note(CheckProvider(row.answer, ids[0].AnchorDER(), planted[0]))
		note(CheckNamedProvider(row.answer, testNumber, testPool, testProvider, ids[0].AnchorDER(), planted[0]))
	}
	note(CheckNamedProvider(providerAnswer(t, planted[0], ids[0].AnchorDER(), nil), testNumber, testPool, "otherprovider", ids[0].AnchorDER(), planted[0]))
	note(CheckNamedProvider(providerAnswer(t, planted[0], ids[0].AnchorDER(), nil), testNumber, "otherpool", testProvider, ids[0].AnchorDER(), planted[0]))

	// M3b.1's refusals: the reader removed beside the writer, conditions that
	// name the planted IDs in a shape not D3's, lists that carry them, and a
	// staged anchor of another ID.
	note(s.RemoveRole(Reader))
	for _, cond := range hostileConditions(planted[0], planted[1]) {
		_, err = RoleIDFromCondition(cond)
		note(err)
	}
	for _, row := range providerListRows(t, planted[0]) {
		_, _, err = ParseProviders(row.list, testNumber, listPool)
		note(err)
	}
	for _, row := range providerGetRows(t, planted[0]) {
		_, err = ParseProvider(row.list, testNumber, listPool, listProvider)
		note(err)
	}
	if _, err := s.RenewAnchor(Writer, rand.Reader, fresh); err != nil {
		t.Fatal(err)
	}
	restage(t, dir, "writer", planted[0])
	_, _, err = s.StagedCertificates(Writer)
	note(err)

	// The enrolment window: closed, and a marker that is not a plain file.
	if err := s.EnrolmentVerified(Reader); err != nil {
		t.Fatal(err)
	}
	_, err = s.OpenForEnrolment(Reader, rand.Reader, fresh)
	note(err)
	if err := os.Symlink("leaf.crt", filepath.Join(dir, "writer", "enrolling")); err != nil {
		t.Fatal(err)
	}
	_, err = s.OpenForEnrolment(Writer, rand.Reader, fresh)
	note(err)

	if len(errs) < 30 {
		t.Fatalf("only %d errors were made", len(errs))
	}
	for _, err := range errs {
		for _, id := range planted {
			if containsID(err.Error(), id) {
				t.Errorf("the error %q carries a planted role ID", err)
			}
		}
	}
}
