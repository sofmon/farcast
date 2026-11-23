package devicekey

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"time"
)

// Identity is what a TLS handshake needs for one role: its leaf, the leaf's
// key behind an opaque signer, and the public anchor for the chain shapes M3a
// measures. It never carries an anchor key. Its fields sit behind a pointer,
// so it formats as "<role> identity (not printed)" or as an address, as
// RoleID does: two pointers deep, for RoleID's reason. It is returned by
// value: it is a handle around a pointer.
type Identity struct{ p **identity }

type identity struct {
	role     Role
	id       RoleID
	leaf     []byte        // DER
	anchor   []byte        // DER, public
	signer   crypto.Signer // the leaf key, opaque
	notAfter time.Time     // the leaf's
}

// newIdentity is the Identity for a role's leaf, with the leaf key behind an
// opaque signer.
func newIdentity(r Role, id RoleID, leafDER, anchorDER []byte, leafKey *ecdsa.PrivateKey, notAfter time.Time) Identity {
	v := &identity{
		role:     r,
		id:       id,
		leaf:     bytes.Clone(leafDER),
		anchor:   bytes.Clone(anchorDER),
		signer:   opaque{k: leafKey},
		notAfter: notAfter,
	}
	return Identity{p: &v}
}

// get is the identity's fields; nil for the zero Identity.
func (i Identity) get() *identity {
	if i.p == nil {
		return nil
	}
	return *i.p
}

// Role is the identity's role; 0 for the zero Identity.
func (i Identity) Role() Role {
	if v := i.get(); v != nil {
		return v.role
	}
	return 0
}

// ID is the role's ID; the zero RoleID for the zero Identity.
func (i Identity) ID() RoleID {
	if v := i.get(); v != nil {
		return v.id
	}
	return RoleID{}
}

// LeafDER is a copy of the leaf certificate's DER.
func (i Identity) LeafDER() []byte {
	if v := i.get(); v != nil {
		return bytes.Clone(v.leaf)
	}
	return nil
}

// AnchorDER is a copy of the anchor certificate's DER, which is public.
func (i Identity) AnchorDER() []byte {
	if v := i.get(); v != nil {
		return bytes.Clone(v.anchor)
	}
	return nil
}

// Signer is the leaf key, behind an opaque crypto.Signer; nil for the zero
// Identity.
func (i Identity) Signer() crypto.Signer {
	if v := i.get(); v != nil {
		return v.signer
	}
	return nil
}

// NotAfter is the leaf's NotAfter.
func (i Identity) NotAfter() time.Time {
	if v := i.get(); v != nil {
		return v.notAfter
	}
	return time.Time{}
}

// text is the fixed text every formatting of an Identity gives: its role, and
// nothing else.
func (i Identity) text() string {
	if v := i.get(); v != nil {
		return v.role.String() + " identity (not printed)"
	}
	return "identity (not printed)"
}

// String is "<role> identity (not printed)".
func (i Identity) String() string { return i.text() }

// GoString is "<role> identity (not printed)".
func (i Identity) GoString() string { return i.text() }

// Format writes "<role> identity (not printed)" for every verb.
func (i Identity) Format(f fmt.State, verb rune) { _, _ = io.WriteString(f, i.text()) }

// LogValue is slog.StringValue of "<role> identity (not printed)".
func (i Identity) LogValue() slog.Value { return slog.StringValue(i.text()) }

// ConsentKind is how a writing command's consent was given (D2).
type ConsentKind int

const (
	ConsentConfirmed ConsentKind = 1 // --confirm <digest> matched
	ConsentAnswered  ConsentKind = 2 // a terminal's question answered yes
)

// --yes is left out until the operator answers ADR 0024 Choices 24.

// Consent is a writing command's consent. Its zero value is no consent.
// GiveConsent records an intent and checks nothing. What enforces the custody
// rule is the call-site test (TestCustodyCallSitesAreReviewed): every caller
// outside tests is listed and reviewed.
type Consent struct{ kind ConsentKind }

// GiveConsent records a consent of kind k. It gives the zero Consent for any
// k but ConsentConfirmed and ConsentAnswered.
func GiveConsent(k ConsentKind) Consent {
	switch k {
	case ConsentConfirmed, ConsentAnswered:
		return Consent{kind: k}
	}
	return Consent{}
}

// Given reports whether c is a consent at all.
func (c Consent) Given() bool {
	return c.kind == ConsentConfirmed || c.kind == ConsentAnswered
}

// errNoRandom refuses a nil random source.
var errNoRandom = errors.New("devicekey: no random source")

// Enrol is install's and device add's start (purpose: enrolment). dir must not
// exist (it is made 0700), or must be an empty 0700 directory; otherwise
// ErrStoreExists. roles is Reader, or Reader and Writer: no duplicates, and
// Writer alone is refused. For each role it makes a new role ID drawn from
// rnd, a new anchor key and anchor, and a new leaf key and leaf. It returns the
// identities for D4's one verification exchange per role, from memory: it
// opens no file.
//
// A directory that is a symlink, or that other accounts can reach, is
// ErrUnsafeMode. Everything is drawn before anything is written, each role's
// directory appears whole or not at all, and a failed Enrol removes what it
// made.
func Enrol(rnd io.Reader, dir string, roles []Role, now time.Time) (*Store, []Identity, error) {
	if err := checkEnrolRoles(roles); err != nil {
		return nil, nil, err
	}
	if rnd == nil {
		return nil, nil, errNoRandom
	}
	if dir == "" {
		return nil, nil, errors.New("devicekey: no key directory")
	}
	s := &Store{dir: dir}
	created, err := s.prepareDir()
	if err != nil {
		return nil, nil, err
	}
	ids, err := s.enrol(rnd, roles, now)
	if err != nil {
		if created {
			_ = os.RemoveAll(dir)
		}
		return nil, nil, err
	}
	return s, ids, nil
}

// checkEnrolRoles accepts [Reader], or Reader and Writer in either order.
func checkEnrolRoles(roles []Role) error {
	switch {
	case len(roles) == 1 && roles[0] == Reader:
		return nil
	case len(roles) == 2 && roles[0] != roles[1] && roles[0].valid() && roles[1].valid():
		return nil
	}
	return errors.New("devicekey: a device enrols as a reader, or as a reader and a writer, each role once")
}

// prepareDir makes the store's directory 0700, or accepts an existing empty
// one that is safe. created reports whether it made it.
func (s *Store) prepareDir() (created bool, err error) {
	err = os.Mkdir(s.dir, 0o700)
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, fs.ErrExist) {
		return false, fmt.Errorf("devicekey: %w", err)
	}
	fi, err := os.Lstat(s.dir)
	if err != nil {
		return false, fmt.Errorf("devicekey: %w", err)
	}
	if fi.Mode()&fs.ModeSymlink == 0 && !fi.IsDir() {
		return false, fmt.Errorf("devicekey: %s: %w", s.dir, ErrStoreExists)
	}
	root, err := s.openRoot()
	if err != nil {
		return false, err
	}
	defer func() { _ = root.Close() }()
	names, err := readDirNames(root)
	if err != nil {
		return false, fmt.Errorf("devicekey: %w", err)
	}
	if len(names) != 0 {
		return false, fmt.Errorf("devicekey: %s: %w", s.dir, ErrStoreExists)
	}
	return false, nil
}

// enrol draws every role's ID and keys, and then writes each role's
// directory. A failure removes the role directories it wrote.
func (s *Store) enrol(rnd io.Reader, roles []Role, now time.Time) ([]Identity, error) {
	ids := make([]RoleID, len(roles))
	sets := make([]*keySet, len(roles))
	for i := range roles {
		id, err := NewRoleID(rnd)
		if err != nil {
			return nil, err
		}
		set, err := newKeySet(rnd, id, now)
		if err != nil {
			return nil, err
		}
		ids[i], sets[i] = id, set
	}
	root, err := s.openRoot()
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	var written []string
	for i, r := range roles {
		if err := s.writeRoleDir(root, roleDirName(r), sets[i]); err != nil {
			for _, name := range written {
				_ = root.RemoveAll(name)
			}
			return nil, err
		}
		written = append(written, roleDirName(r))
	}
	out := make([]Identity, len(roles))
	for i, r := range roles {
		out[i] = sets[i].identity(r, ids[i])
	}
	return out, nil
}

// AddRole is `device add --role writer` on a reader-only device (purpose:
// enrolment). It refuses a role already present, and opens no existing file.
// A writer is added only beside a reader, as Enrol refuses a writer alone.
func (s *Store) AddRole(r Role, rnd io.Reader, now time.Time) (Identity, error) {
	if !r.valid() {
		return Identity{}, errNoSuchRole(r)
	}
	if rnd == nil {
		return Identity{}, errNoRandom
	}
	root, err := s.openRoot()
	if err != nil {
		return Identity{}, err
	}
	defer func() { _ = root.Close() }()
	st, err := s.roleState(root, r)
	if err != nil {
		return Identity{}, err
	}
	if st.interrupted() {
		return Identity{}, fmt.Errorf("devicekey: the %s role: %w", r, ErrRenewalInterrupted)
	}
	if st.cur {
		return Identity{}, fmt.Errorf("devicekey: this device already holds %s keys: %w", r, ErrStoreExists)
	}
	if r == Writer {
		if err := s.requireRole(root, Reader); err != nil {
			return Identity{}, fmt.Errorf("devicekey: a writer is added beside a reader: %w", err)
		}
	}
	id, err := NewRoleID(rnd)
	if err != nil {
		return Identity{}, err
	}
	set, err := newKeySet(rnd, id, now)
	if err != nil {
		return Identity{}, err
	}
	if err := s.writeRoleDir(root, roleDirName(r), set); err != nil {
		return Identity{}, err
	}
	return set.identity(r, id), nil
}

// RemoveRole is `device rm --role writer`, and M3a's teardown. It removes the
// role's directory, staged and old ones included. It opens no file, and, like
// Erase, refuses only a store directory that is not a real directory: a
// widened mode does not keep the role's keys on disk.
func (s *Store) RemoveRole(r Role) error {
	if !r.valid() {
		return errNoSuchRole(r)
	}
	root, err := s.openRemovalRoot()
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	for _, name := range []string{roleDirName(r), stagedDirName(r), oldDirName(r)} {
		if err := root.RemoveAll(name); err != nil {
			return fmt.Errorf("devicekey: remove %s: %w", s.path(name), err)
		}
	}
	return nil
}

// OpenForRead is every read command's and every plan's (purpose: read). It
// opens the reader's leaf.key, leaf.crt and anchor.crt. When the leaf is due
// (LeafDue, or a key that does not match its certificate), it also opens the
// reader's anchor.key, issues a new leaf with a new leaf key, writes both, and
// returns the new identity. It never opens a file under writer/ or
// reader.next/, whatever they hold.
func (s *Store) OpenForRead(rnd io.Reader, now time.Time) (Identity, error) {
	return s.openRole(Reader, rnd, now)
}

// OpenForWrite is a writing command's, after its consent (purpose: consented
// write). A zero Consent is ErrNoConsent, and nothing is opened. Otherwise it
// works as OpenForRead does, for the writer: it opens writer leaf.key,
// leaf.crt and anchor.crt, and writer anchor.key only when the leaf is due. It
// opens nothing under reader/ or writer.next/.
func (s *Store) OpenForWrite(c Consent, rnd io.Reader, now time.Time) (Identity, error) {
	if !c.Given() {
		return Identity{}, ErrNoConsent
	}
	return s.openRole(Writer, rnd, now)
}

// RenewReaderLeaf renews the reader's leaf now, due or not: M3a's T3, and
// M3b's explicit renew. It opens only the reader's anchor.key and anchor.crt,
// and writes its leaf.
func (s *Store) RenewReaderLeaf(rnd io.Reader, now time.Time) (Identity, error) {
	return s.renewNow(Reader, rnd, now)
}

// RenewWriterLeaf renews the writer's leaf now, due or not, as
// RenewReaderLeaf does for the reader. It needs a given Consent (a zero one is
// ErrNoConsent, and nothing is opened), and opens only the writer's
// anchor.key and anchor.crt.
func (s *Store) RenewWriterLeaf(c Consent, rnd io.Reader, now time.Time) (Identity, error) {
	if !c.Given() {
		return Identity{}, ErrNoConsent
	}
	return s.renewNow(Writer, rnd, now)
}

// openRole is OpenForRead's and OpenForWrite's body for role r: open the
// role's anchor.crt, leaf.crt and leaf.key; refuse an expired anchor; and
// renew the leaf with the role's own anchor.key when it is due or its key does
// not match it.
func (s *Store) openRole(r Role, rnd io.Reader, now time.Time) (Identity, error) {
	if rnd == nil {
		return Identity{}, errNoRandom
	}
	root, err := s.openRoot()
	if err != nil {
		return Identity{}, err
	}
	defer func() { _ = root.Close() }()
	if err := s.requireRole(root, r); err != nil {
		return Identity{}, err
	}
	dir := roleDirName(r)
	anchor, id, err := s.readAnchorCert(dir)
	if err != nil {
		return Identity{}, err
	}
	if err := checkAnchorLive(r, anchor, now); err != nil {
		return Identity{}, err
	}
	leaf, err := s.readLeafCert(dir, anchor)
	if err != nil {
		return Identity{}, err
	}
	leafKey, matches, err := s.readLeafKey(dir, leaf)
	if err != nil {
		return Identity{}, err
	}
	if matches && !LeafDue(leaf, anchor, now) {
		return newIdentity(r, id, leaf.Raw, anchor.Raw, leafKey, leaf.NotAfter), nil
	}
	return s.renewLeaf(root, r, anchor, id, rnd, now)
}

// renewNow is RenewReaderLeaf's and RenewWriterLeaf's body: open the role's
// anchor.crt, refuse an expired anchor, and renew the leaf.
func (s *Store) renewNow(r Role, rnd io.Reader, now time.Time) (Identity, error) {
	if rnd == nil {
		return Identity{}, errNoRandom
	}
	root, err := s.openRoot()
	if err != nil {
		return Identity{}, err
	}
	defer func() { _ = root.Close() }()
	if err := s.requireRole(root, r); err != nil {
		return Identity{}, err
	}
	anchor, id, err := s.readAnchorCert(roleDirName(r))
	if err != nil {
		return Identity{}, err
	}
	if err := checkAnchorLive(r, anchor, now); err != nil {
		return Identity{}, err
	}
	return s.renewLeaf(root, r, anchor, id, rnd, now)
}

// checkAnchorLive is ErrAnchorExpired for an anchor whose validity has ended:
// it renews no leaf, and its unexpired leaves are not used either.
func checkAnchorLive(r Role, anchor *x509.Certificate, now time.Time) error {
	if anchorExpired(anchor, now) {
		return fmt.Errorf("devicekey: the %s role: %w", r, ErrAnchorExpired)
	}
	return nil
}

// renewLeaf opens r's own anchor.key, which must match its anchor, issues a
// new leaf from a new leaf key, and writes leaf.key and then leaf.crt. A crash
// between the two leaves a key that does not match its certificate, which the
// next opening renews.
func (s *Store) renewLeaf(root *os.Root, r Role, anchor *x509.Certificate, id RoleID, rnd io.Reader, now time.Time) (Identity, error) {
	dir := roleDirName(r)
	anchorKey, err := s.readAnchorKey(dir, anchor)
	if err != nil {
		return Identity{}, err
	}
	der, key, err := issueLeaf(rnd, anchor, opaque{k: anchorKey}, now)
	if err != nil {
		return Identity{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return Identity{}, fmt.Errorf("devicekey: read back the new leaf: %w", err)
	}
	keyPEM, err := encodeKey(key)
	if err != nil {
		return Identity{}, err
	}
	if err := s.writeFile(root, dir+"/"+leafKeyName, keyPEM); err != nil {
		return Identity{}, err
	}
	if err := s.writeFile(root, dir+"/"+leafCertName, encodeCert(der)); err != nil {
		return Identity{}, err
	}
	return newIdentity(r, id, der, anchor.Raw, key, leaf.NotAfter), nil
}

// RenewAnchor is `device renew` for one role (purpose: renewal). It reads the
// role's ID from the current anchor.crt, an expired one included, and opens no
// key. It stages a new anchor key and anchor with the SAME role ID, and a
// first leaf under them from a new leaf key, in <role>.next/, made 0700 with
// the four files 0600. The current role directory is not touched, so the
// device keeps working under the anchor Google still trusts until the paste
// applies (D4). It returns the staged identity, for the verification exchange.
// It refuses an absent role with ErrNoRole, and a role with a renewal already
// staged with ErrRenewalStaged.
func (s *Store) RenewAnchor(r Role, rnd io.Reader, now time.Time) (Identity, error) {
	if !r.valid() {
		return Identity{}, errNoSuchRole(r)
	}
	if rnd == nil {
		return Identity{}, errNoRandom
	}
	root, err := s.openRoot()
	if err != nil {
		return Identity{}, err
	}
	defer func() { _ = root.Close() }()
	st, err := s.roleState(root, r)
	if err != nil {
		return Identity{}, err
	}
	switch {
	case st.interrupted():
		return Identity{}, fmt.Errorf("devicekey: the %s role: %w", r, ErrRenewalInterrupted)
	case !st.cur:
		return Identity{}, fmt.Errorf("devicekey: the %s role: %w", r, ErrNoRole)
	case st.next:
		return Identity{}, fmt.Errorf("devicekey: the %s role: %w", r, ErrRenewalStaged)
	}
	_, id, err := s.readAnchorCert(roleDirName(r))
	if err != nil {
		return Identity{}, err
	}
	set, err := newKeySet(rnd, id, now)
	if err != nil {
		return Identity{}, err
	}
	if err := s.writeRoleDir(root, stagedDirName(r), set); err != nil {
		return Identity{}, err
	}
	return set.identity(r, id), nil
}

// OpenStaged opens a staged renewal's leaf.key, leaf.crt and anchor.crt, for
// the verification exchange in a later process (purpose: renewal). It neither
// renews nor opens a staged anchor.key. It returns ErrNothingStaged when there
// is none, and ErrInconsistent when the staged leaf key does not match its
// certificate.
//
// The writer's staged leaf key is a working writer identity once the paste
// has applied, so OpenStaged(Writer) needs a given Consent, as OpenForWrite
// does: a zero one is ErrNoConsent, and nothing is opened. The reader's
// ignores c.
func (s *Store) OpenStaged(r Role, c Consent) (Identity, error) {
	if !r.valid() {
		return Identity{}, errNoSuchRole(r)
	}
	if r == Writer && !c.Given() {
		return Identity{}, ErrNoConsent
	}
	root, err := s.openRoot()
	if err != nil {
		return Identity{}, err
	}
	defer func() { _ = root.Close() }()
	st, err := s.roleState(root, r)
	if err != nil {
		return Identity{}, err
	}
	if st.interrupted() {
		return Identity{}, fmt.Errorf("devicekey: the %s role: %w", r, ErrRenewalInterrupted)
	}
	if !st.next {
		return Identity{}, fmt.Errorf("devicekey: the %s role: %w", r, ErrNothingStaged)
	}
	dir := stagedDirName(r)
	anchor, id, err := s.readAnchorCert(dir)
	if err != nil {
		return Identity{}, err
	}
	leaf, err := s.readLeafCert(dir, anchor)
	if err != nil {
		return Identity{}, err
	}
	key, matches, err := s.readLeafKey(dir, leaf)
	if err != nil {
		return Identity{}, err
	}
	if !matches {
		return Identity{}, inconsistent(dir + "/" + leafKeyName)
	}
	return newIdentity(r, id, leaf.Raw, anchor.Raw, key, leaf.NotAfter), nil
}

// CommitAnchor makes a staged renewal current, once its verification exchange
// has passed. It renames <role> to <role>.old, renames <role>.next to <role>,
// and removes <role>.old. It opens no file, and resumes after a crash at any
// point. With nothing staged and no interrupted commit, it returns
// ErrNothingStaged.
func (s *Store) CommitAnchor(r Role) error {
	if !r.valid() {
		return errNoSuchRole(r)
	}
	root, err := s.openRoot()
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	st, err := s.roleState(root, r)
	if err != nil {
		return err
	}
	cur, next, old := roleDirName(r), stagedDirName(r), oldDirName(r)
	if !st.next {
		if st.cur && st.old {
			// Interrupted after the second rename: only the removal is left.
			return s.removeDir(root, old)
		}
		return fmt.Errorf("devicekey: the %s role: %w", r, ErrNothingStaged)
	}
	if st.cur {
		if st.old {
			// An earlier commit's leftover, from a crash before its removal.
			if err := s.removeDir(root, old); err != nil {
				return err
			}
		}
		if err := root.Rename(cur, old); err != nil {
			return fmt.Errorf("devicekey: commit the %s anchor: %w", r, err)
		}
	}
	if err := root.Rename(next, cur); err != nil {
		return fmt.Errorf("devicekey: commit the %s anchor: %w", r, err)
	}
	return s.removeDir(root, old)
}

// removeDir removes name and everything under it; a missing one is removed.
func (s *Store) removeDir(root *os.Root, name string) error {
	if err := root.RemoveAll(name); err != nil {
		return fmt.Errorf("devicekey: remove %s: %w", s.path(name), err)
	}
	return nil
}

// DiscardStaged removes <role>.next. It opens no file. In an interrupted
// commit it first puts <role>.old back as <role>, so the role keeps its
// current anchor. With nothing staged it returns ErrNothingStaged.
func (s *Store) DiscardStaged(r Role) error {
	if !r.valid() {
		return errNoSuchRole(r)
	}
	root, err := s.openRoot()
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	st, err := s.roleState(root, r)
	if err != nil {
		return err
	}
	if !st.next {
		return fmt.Errorf("devicekey: the %s role: %w", r, ErrNothingStaged)
	}
	if !st.cur && st.old {
		if err := root.Rename(oldDirName(r), roleDirName(r)); err != nil {
			return fmt.Errorf("devicekey: restore the %s anchor: %w", r, err)
		}
	}
	return s.removeDir(root, stagedDirName(r))
}
