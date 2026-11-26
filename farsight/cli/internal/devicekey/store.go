package devicekey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"time"
)

// The package's sentinels. A caller branches on them with errors.Is. Errors
// are fmt.Errorf("devicekey: …: %w", …), naming the role and at most a path,
// never a role ID.
var (
	ErrUnsafeMode         = errors.New("devicekey: a key directory or file is readable by other accounts on this machine, or is not a plain file") // by its mode bits: an ACL is not checked (Store)
	ErrInconsistent       = errors.New("devicekey: a role's keys and certificates do not belong together")
	ErrNoConsent          = errors.New("devicekey: the writer keys open only after the command's consent")
	ErrNoRole             = errors.New("devicekey: this device holds no keys for that role")
	ErrAnchorExpired      = errors.New("devicekey: the role's anchor has expired; a human paste renews it")
	ErrStoreExists        = errors.New("devicekey: the key directory already holds keys")
	ErrRenewalStaged      = errors.New("devicekey: an anchor renewal is already staged for this role; commit it or discard it")
	ErrNothingStaged      = errors.New("devicekey: no anchor renewal is staged for this role")
	ErrRenewalInterrupted = errors.New("devicekey: an anchor renewal's commit was interrupted; commit it again")
	ErrWriterRemains      = errors.New("devicekey: the reader role is removed only after the writer role; a device holds a writer only beside a reader")
	ErrNotEnrolling       = errors.New("devicekey: the role's enrolment is closed (verified, or not begun on this device); its keys open only for a read or after a command's consent")
)

// The store's names. They are unexported: no product code outside devicekey
// builds a path to a key.
const (
	anchorKeyName  = "anchor.key"
	anchorCertName = "anchor.crt"
	leafKeyName    = "leaf.key"
	leafCertName   = "leaf.crt"
	enrollingName  = "enrolling"
	readerDirName  = "reader"
	writerDirName  = "writer"
	stagedSuffix   = ".next"
	oldSuffix      = ".old"
	tmpPrefix      = ".tmp-"
)

// maxStoreFile is the most a read takes: a key or certificate PEM is under
// 2 KiB.
const maxStoreFile = 64 << 10

// The PEM types the store writes.
const (
	pemCertificate = "CERTIFICATE"
	pemPrivateKey  = "PRIVATE KEY"
)

// roleDirName is r's directory; "" for no role.
func roleDirName(r Role) string {
	switch r {
	case Reader:
		return readerDirName
	case Writer:
		return writerDirName
	}
	return ""
}

// stagedDirName is r's staged renewal's directory.
func stagedDirName(r Role) string { return roleDirName(r) + stagedSuffix }

// oldDirName is r's directory during a commit.
func oldDirName(r Role) string { return roleDirName(r) + oldSuffix }

// enrollingRel is r's enrolment marker, as the store's relative path.
func enrollingRel(r Role) string { return roleDirName(r) + "/" + enrollingName }

// enrollingText is what the marker holds. Nothing reads it: the marker is
// there or not.
const enrollingText = "this role's enrolment is not verified yet\n"

// errNoSuchRole refuses a Role that is neither Reader nor Writer.
func errNoSuchRole(r Role) error { return fmt.Errorf("devicekey: %s is not a role", r) }

// Store is one device's keys for one instance. The caller names the
// directory: in M3b <instance dir>/identity, and in the probe a directory
// under its walk directory. The layout:
//
//	<dir>/              0700
//	  reader/           0700
//	    anchor.key      0600  PKCS#8 PEM, "PRIVATE KEY"
//	    anchor.crt      0600  PEM, "CERTIFICATE"
//	    leaf.key        0600
//	    leaf.crt        0600
//	    enrolling       0600  only while the role's enrolment window is open
//	  writer/           0700  (writer-capable devices only)
//	    … the same
//	  <role>.next/      0700  a staged anchor renewal, the same four files
//	  <role>.old/       0700  only for the moment of a commit
//
// The enrolling marker is written with the role's directory by Enrol and
// AddRole, and removed by EnrolmentVerified; a staged renewal never holds
// one. While it is there OpenForEnrolment opens the role with no consent.
// Nothing reads it: it is stat-ed only.
//
// The file names and the role directory names are unexported. No product
// code outside devicekey builds a path to a key.
//
// Every open, stat and rename goes through an os.Root opened on the
// directory, so no path escapes it by a symlink; and every directory and file
// the store uses is checked to be a real one, not a symlink, with
// perm&0o077 == 0. Erase and RemoveRole, which open no file, check the
// store's directory for a real directory only: a widened mode, which is when
// the keys are exposed to other accounts, does not keep them on disk.
//
// The mode bits are all it checks. An access control list is not a mode bit:
// on macOS a directory whose parent carries an inheritable ACL entry gives
// its files that entry, so another account may read a key whose mode is
// 0600, and every check here passes [ran by the build's review, 2026-11-23:
// a 0700 parent with "everyone allow read, file_inherit, directory_inherit"
// gave Enrol's key files that entry]. Reading an ACL
// takes libSystem's acl API, a platform-only call this package does not make
// (it must build for Windows too). So the caller places the store where no
// ACL reaches it, and checks that it holds none: on macOS, `ls -led` on the
// store's directory and its parent shows no "+". The M3a probe's runbook does
// this at P0.2; M3b, wherever it places the store.
type Store struct {
	dir   string
	hooks storeHooks // zero in product code; tests set them
}

// storeHooks are the test seams. readFile is every read. afterCreate runs
// just after a temporary file is created, before it is written. afterLstat
// runs between a read's Lstat and its open.
type storeHooks struct {
	readFile    func(rel string) ([]byte, error)
	afterCreate func(rel string)
	afterLstat  func(rel string)
}

// Open checks that dir, and each role directory present, is a real directory,
// not a symlink, with perm&0o077 == 0. It reads no file.
func Open(dir string) (*Store, error) {
	s := &Store{dir: dir}
	root, err := s.openRoot()
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	for _, r := range []Role{Reader, Writer} {
		if _, err := s.roleState(root, r); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Roles lists the roles whose directory exists, by stat only, reading no file.
// A role whose directory is missing while <role>.next exists is
// ErrRenewalInterrupted.
func (s *Store) Roles() ([]Role, error) {
	root, err := s.openRoot()
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	var roles []Role
	for _, r := range []Role{Reader, Writer} {
		st, err := s.roleState(root, r)
		if err != nil {
			return nil, err
		}
		if st.interrupted() {
			return nil, fmt.Errorf("devicekey: the %s role: %w", r, ErrRenewalInterrupted)
		}
		if st.cur {
			roles = append(roles, r)
		}
	}
	return roles, nil
}

// Certificates reads a role's two certificates, which are public material,
// and the role's ID from the anchor's CN. It opens anchor.crt and leaf.crt
// only, never a .key file, and checks them against each other: the anchor
// parses, is a CA and has a role ID as its CN; the leaf parses, has the
// anchor's CN, and names the anchor's subject DN as its issuer, byte for
// byte. A failure is ErrInconsistent. CurrentCertificates reads the same, and
// also gives the anchor's NotAfter.
func (s *Store) Certificates(r Role) (anchorDER, leafDER []byte, id RoleID, err error) {
	c, err := s.CurrentCertificates(r)
	if err != nil {
		return nil, nil, RoleID{}, err
	}
	return c.AnchorDER(), c.LeafDER(), c.ID(), nil
}

// CurrentCertificates is Certificates' reading as a Certs, which also gives
// the anchor's NotAfter: what M3b's record keeps as the role's
// AnchorNotAfter, for AnchorWarnsAt and AnchorExpiredAt, which hold the
// boundaries AnchorWarns and the openers hold. It opens <role>/anchor.crt and
// <role>/leaf.crt only, never a .key file, with Certificates' checks. An
// absent role is ErrNoRole, and an interrupted commit ErrRenewalInterrupted.
func (s *Store) CurrentCertificates(r Role) (Certs, error) {
	if !r.valid() {
		return Certs{}, errNoSuchRole(r)
	}
	root, err := s.openRoot()
	if err != nil {
		return Certs{}, err
	}
	defer func() { _ = root.Close() }()
	if err := s.requireRole(root, r); err != nil {
		return Certs{}, err
	}
	return s.readCerts(r, roleDirName(r))
}

// StagedCertificates reads a staged anchor renewal's two certificates, so
// `device renew` resumes from what RenewAnchor staged: it shows the staged
// anchor's block again, and records its NotAfter after CommitAnchor. present
// is false, with no error, when the role holds no staged renewal.
//
// It opens <role>.next/anchor.crt and <role>.next/leaf.crt, with
// Certificates' checks, and <role>/anchor.crt, whose role ID the staged
// anchor must carry (a renewal keeps the role ID, D4); one that carries
// another is ErrInconsistent. It never opens a .key file, staged or current.
// An absent role is ErrNoRole.
//
// An interrupted commit is ErrRenewalInterrupted, at either of the points
// CommitAnchor resumes from: the role's directory renamed away and the staged
// one not yet in its place, or both renames done and <role>.old/ not yet
// removed. In both, CommitAnchor finishes the commit, and CurrentCertificates
// then gives the committed anchor's NotAfter for the record. So present is
// false with no error only when nothing is staged and nothing is left to
// commit.
func (s *Store) StagedCertificates(r Role) (c Certs, present bool, err error) {
	if !r.valid() {
		return Certs{}, false, errNoSuchRole(r)
	}
	root, err := s.openRoot()
	if err != nil {
		return Certs{}, false, err
	}
	defer func() { _ = root.Close() }()
	st, err := s.roleState(root, r)
	if err != nil {
		return Certs{}, false, err
	}
	switch {
	case st.interrupted(), st.cur && st.old && !st.next:
		return Certs{}, false, fmt.Errorf("devicekey: the %s role: %w", r, ErrRenewalInterrupted)
	case !st.cur:
		return Certs{}, false, fmt.Errorf("devicekey: the %s role: %w", r, ErrNoRole)
	case !st.next:
		return Certs{}, false, nil
	}
	staged, err := s.readCerts(r, stagedDirName(r))
	if err != nil {
		return Certs{}, false, err
	}
	_, id, err := s.readAnchorCert(roleDirName(r))
	if err != nil {
		return Certs{}, false, err
	}
	if !id.Equal(staged.ID()) {
		return Certs{}, false, inconsistent(stagedDirName(r) + "/" + anchorCertName)
	}
	return staged, true, nil
}

// readCerts reads dir's anchor.crt and leaf.crt for role r, with
// Certificates' checks. It opens no .key file.
func (s *Store) readCerts(r Role, dir string) (Certs, error) {
	anchor, id, err := s.readAnchorCert(dir)
	if err != nil {
		return Certs{}, err
	}
	leaf, err := s.readLeafCert(dir, anchor)
	if err != nil {
		return Certs{}, err
	}
	v := &certs{role: r, id: id, anchor: bytes.Clone(anchor.Raw), leaf: bytes.Clone(leaf.Raw), anchorNotAfter: anchor.NotAfter}
	return Certs{p: &v}, nil
}

// Certs is one role's two certificates, current or staged, read without
// opening a key. Both are public material: the human pastes the anchor, and
// Google sees the leaf at every exchange. Their CN is the role ID, which the
// package never prints, so Certs formats as Identity does: its fields sit two
// pointers deep, for RoleID's reason, and every formatting gives "<role>
// certificates (not printed)" or an address. It is returned by value: it is a
// handle around a pointer.
type Certs struct{ p **certs }

type certs struct {
	role           Role
	id             RoleID
	anchor         []byte // DER
	leaf           []byte // DER
	anchorNotAfter time.Time
}

// get is the fields; nil for the zero Certs.
func (c Certs) get() *certs {
	if c.p == nil {
		return nil
	}
	return *c.p
}

// Role is the certificates' role; 0 for the zero Certs.
func (c Certs) Role() Role {
	if v := c.get(); v != nil {
		return v.role
	}
	return 0
}

// ID is the role ID, the anchor's CN; the zero RoleID for the zero Certs.
func (c Certs) ID() RoleID {
	if v := c.get(); v != nil {
		return v.id
	}
	return RoleID{}
}

// AnchorDER is a copy of the anchor certificate's DER.
func (c Certs) AnchorDER() []byte {
	if v := c.get(); v != nil {
		return bytes.Clone(v.anchor)
	}
	return nil
}

// LeafDER is a copy of the leaf certificate's DER.
func (c Certs) LeafDER() []byte {
	if v := c.get(); v != nil {
		return bytes.Clone(v.leaf)
	}
	return nil
}

// AnchorNotAfter is the anchor's NotAfter; the zero time for the zero Certs.
func (c Certs) AnchorNotAfter() time.Time {
	if v := c.get(); v != nil {
		return v.anchorNotAfter
	}
	return time.Time{}
}

// text is the fixed text every formatting of a Certs gives: its role, and
// nothing else.
func (c Certs) text() string {
	if v := c.get(); v != nil {
		return v.role.String() + " certificates (not printed)"
	}
	return "certificates (not printed)"
}

// String is "<role> certificates (not printed)".
func (c Certs) String() string { return c.text() }

// GoString is "<role> certificates (not printed)".
func (c Certs) GoString() string { return c.text() }

// Format writes "<role> certificates (not printed)" for every verb.
func (c Certs) Format(f fmt.State, verb rune) { _, _ = io.WriteString(f, c.text()) }

// LogValue is slog.StringValue of "<role> certificates (not printed)".
func (c Certs) LogValue() slog.Value { return slog.StringValue(c.text()) }

// Erase removes every role's files and directories, staged ones included, and
// then dir. A directory that does not exist is already erased. It refuses
// only a dir that is not a real directory (a symlink in its place); a dir
// whose mode other accounts can reach is erased like any other, because its
// keys are the ones most exposed (openRemovalRoot).
func (s *Store) Erase() error {
	if s == nil || s.dir == "" {
		return errors.New("devicekey: no key directory")
	}
	if _, err := os.Lstat(s.dir); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	root, err := s.openRemovalRoot()
	if err != nil {
		return err
	}
	entries, err := readDirNames(root)
	if err == nil {
		for _, name := range entries {
			if err = root.RemoveAll(name); err != nil {
				break
			}
		}
	}
	_ = root.Close()
	if err != nil {
		return fmt.Errorf("devicekey: erase %s: %w", s.dir, err)
	}
	if err := os.Remove(s.dir); err != nil {
		return fmt.Errorf("devicekey: erase %s: %w", s.dir, err)
	}
	return nil
}

// readDirNames lists root's own entries.
func readDirNames(root *os.Root) ([]string, error) {
	d, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer func() { _ = d.Close() }()
	return d.Readdirnames(-1)
}

// path is rel's path on disk, for an error.
func (s *Store) path(rel string) string {
	return filepath.Join(s.dir, filepath.FromSlash(rel))
}

// unsafeMode is ErrUnsafeMode for rel.
func (s *Store) unsafeMode(rel string) error {
	return fmt.Errorf("devicekey: %s: %w", s.path(rel), ErrUnsafeMode)
}

// inconsistent is ErrInconsistent for rel, a role directory and a file name;
// it names the role and the file, never the ID.
func inconsistent(rel string) error {
	return fmt.Errorf("devicekey: %s: %w", rel, ErrInconsistent)
}

// safeDir reports whether fi is a real directory, not a symlink, that no
// other account can reach.
func safeDir(fi fs.FileInfo) bool {
	return fi.Mode()&fs.ModeSymlink == 0 && fi.IsDir() && fi.Mode().Perm()&0o077 == 0
}

// realDir reports whether fi is a real directory, not a symlink, whatever
// its mode.
func realDir(fi fs.FileInfo) bool {
	return fi.Mode()&fs.ModeSymlink == 0 && fi.IsDir()
}

// safeFile reports whether fi is a plain file, not a symlink, that no other
// account can reach.
func safeFile(fi fs.FileInfo) bool {
	return fi.Mode().IsRegular() && fi.Mode().Perm()&0o077 == 0
}

// openRoot checks the store's directory and opens it as a root. The
// directory is Lstat-ed first, so a symlink in its place is refused, and the
// opened root must be that same directory. It must be a safeDir.
func (s *Store) openRoot() (*os.Root, error) { return s.openRootIf(safeDir) }

// openRemovalRoot is openRoot for Erase and RemoveRole, which open no file:
// the store's directory must be a real directory, the same one the root
// opened, and may have any mode. A widened mode is what exposes the keys to
// other accounts, so it must not keep them on disk.
func (s *Store) openRemovalRoot() (*os.Root, error) { return s.openRootIf(realDir) }

// openRootIf is openRoot with ok as the directory's check.
func (s *Store) openRootIf(ok func(fs.FileInfo) bool) (*os.Root, error) {
	if s == nil || s.dir == "" {
		return nil, errors.New("devicekey: no key directory")
	}
	fi, err := os.Lstat(s.dir)
	if err != nil {
		return nil, fmt.Errorf("devicekey: %w", err)
	}
	if !ok(fi) {
		return nil, s.unsafeMode(".")
	}
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return nil, fmt.Errorf("devicekey: %w", err)
	}
	opened, err := root.Stat(".")
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("devicekey: %w", err)
	}
	if !os.SameFile(fi, opened) || !ok(opened) {
		_ = root.Close()
		return nil, s.unsafeMode(".")
	}
	return root, nil
}

// dirPresent stats name in root: false when it does not exist, and
// ErrUnsafeMode when it is not a real 0700 directory.
func (s *Store) dirPresent(root *os.Root, name string) (bool, error) {
	fi, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("devicekey: %w", err)
	}
	if !safeDir(fi) {
		return false, s.unsafeMode(name)
	}
	return true, nil
}

// roleState is which of a role's three directories exist, by stat only.
type roleState struct{ cur, next, old bool }

// interrupted is a commit that renamed the role's directory away and did not
// rename the staged one into its place.
func (st roleState) interrupted() bool { return !st.cur && st.next }

// roleState stats r's directory, its staged one and its old one.
func (s *Store) roleState(root *os.Root, r Role) (roleState, error) {
	var st roleState
	var err error
	if st.cur, err = s.dirPresent(root, roleDirName(r)); err != nil {
		return st, err
	}
	if st.next, err = s.dirPresent(root, stagedDirName(r)); err != nil {
		return st, err
	}
	if st.old, err = s.dirPresent(root, oldDirName(r)); err != nil {
		return st, err
	}
	return st, nil
}

// requireRole is nil when r's directory exists; ErrRenewalInterrupted when
// it is missing while a staged one exists; and ErrNoRole otherwise.
func (s *Store) requireRole(root *os.Root, r Role) error {
	st, err := s.roleState(root, r)
	if err != nil {
		return err
	}
	if st.interrupted() {
		return fmt.Errorf("devicekey: the %s role: %w", r, ErrRenewalInterrupted)
	}
	if !st.cur {
		return fmt.Errorf("devicekey: the %s role: %w", r, ErrNoRole)
	}
	return nil
}

// readFile is every read the store makes: the test hook when one is set, and
// readFileDefault otherwise.
func (s *Store) readFile(rel string) ([]byte, error) {
	if s.hooks.readFile != nil {
		return s.hooks.readFile(rel)
	}
	return s.readFileDefault(rel)
}

// readFileDefault reads rel, a role directory and a file name, through a root
// on the store's directory:
//  1. the role directory must be a real 0700 directory;
//  2. Lstat the file: a symlink, a non-regular file or perm&0o077 != 0 is
//     ErrUnsafeMode, before any open;
//  3. hooks.afterLstat;
//  4. open it read-only;
//  5. Stat the open descriptor: unless it is the file step 2 saw
//     (os.SameFile) and still passes the mode check, ErrUnsafeMode. A file
//     swapped between the Lstat and the open is caught here on every
//     platform, without O_NOFOLLOW, which syscall lacks on windows;
//  6. read at most 64 KiB + 1, and refuse more.
func (s *Store) readFileDefault(rel string) ([]byte, error) {
	root, err := s.openRoot()
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	if d := path.Dir(rel); d != "." {
		ok, err := s.dirPresent(root, d)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("devicekey: %s: %w", s.path(d), fs.ErrNotExist)
		}
	}
	before, err := root.Lstat(rel)
	if err != nil {
		return nil, fmt.Errorf("devicekey: %w", err)
	}
	if !safeFile(before) {
		return nil, s.unsafeMode(rel)
	}
	if s.hooks.afterLstat != nil {
		s.hooks.afterLstat(rel)
	}
	f, err := root.Open(rel)
	if err != nil {
		return nil, fmt.Errorf("devicekey: %w", err)
	}
	defer func() { _ = f.Close() }()
	opened, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("devicekey: %w", err)
	}
	if !os.SameFile(before, opened) || !safeFile(opened) {
		return nil, s.unsafeMode(rel)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxStoreFile+1))
	if err != nil {
		return nil, fmt.Errorf("devicekey: read %s: %w", s.path(rel), err)
	}
	if len(data) > maxStoreFile {
		return nil, fmt.Errorf("devicekey: %s is larger than %d bytes; a key or certificate is not", s.path(rel), maxStoreFile)
	}
	return data, nil
}

// randomSuffix is 16 hex characters from crypto/rand, for a temporary name.
// It is not drawn from the caller's rnd, which supplies serials and IDs only.
func randomSuffix() string {
	var b [8]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails (Go 1.24)
	return hex.EncodeToString(b[:])
}

// writeFile writes data to rel through root, never in place:
//  1. create a temporary file in the same directory, O_WRONLY|O_CREATE|O_EXCL
//     at 0600, named .tmp-<base>-<16 hex>;
//  2. hooks.afterCreate;
//  3. write, Sync, Close;
//  4. Rename over the target.
//
// An existing target at a wider mode is replaced by the new 0600 file, never
// chmod-ed in place, so the target's inode changes. It follows the shape of
// config/instance.go's writeFileAtomic, which is unexported.
func (s *Store) writeFile(root *os.Root, rel string, data []byte) error {
	tmp := path.Join(path.Dir(rel), tmpPrefix+path.Base(rel)+"-"+randomSuffix())
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("devicekey: write %s: %w", s.path(rel), err)
	}
	if s.hooks.afterCreate != nil {
		s.hooks.afterCreate(tmp)
	}
	_, err = f.Write(data)
	if err == nil {
		// Durability before visibility: a rename that beats its own contents
		// to disk is how a crash leaves an empty file under a valid name.
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = root.Rename(tmp, rel)
	}
	if err != nil {
		_ = root.Remove(tmp)
		return fmt.Errorf("devicekey: write %s: %w", s.path(rel), err)
	}
	return nil
}

// keySet is one role's four keys and certificates, in memory.
type keySet struct {
	anchorDER []byte
	anchorKey *ecdsa.PrivateKey
	leafDER   []byte
	leafKey   *ecdsa.PrivateKey
	notAfter  time.Time // the leaf's
}

// newKeySet makes a new anchor for id and a first leaf under it, each from a
// new key.
func newKeySet(rnd io.Reader, id RoleID, now time.Time) (*keySet, error) {
	anchorDER, anchorKey, err := newAnchor(rnd, id, now)
	if err != nil {
		return nil, err
	}
	anchor, err := x509.ParseCertificate(anchorDER)
	if err != nil {
		return nil, fmt.Errorf("devicekey: read back the new anchor: %w", err)
	}
	leafDER, leafKey, err := issueLeaf(rnd, anchor, opaque{k: anchorKey}, now)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("devicekey: read back the new leaf: %w", err)
	}
	return &keySet{anchorDER: anchorDER, anchorKey: anchorKey, leafDER: leafDER, leafKey: leafKey, notAfter: leaf.NotAfter}, nil
}

// identity is the set's Identity for role r and id.
func (k *keySet) identity(r Role, id RoleID) Identity {
	return newIdentity(r, id, k.leafDER, k.anchorDER, k.leafKey, k.notAfter)
}

// writeRoleDir writes set's four files into a new temporary directory, with
// the enrolling marker when enrolling, and then renames it to name, so a role
// or a staged renewal appears whole or not at all.
func (s *Store) writeRoleDir(root *os.Root, name string, set *keySet, enrolling bool) error {
	anchorKeyPEM, err := encodeKey(set.anchorKey)
	if err != nil {
		return err
	}
	leafKeyPEM, err := encodeKey(set.leafKey)
	if err != nil {
		return err
	}
	tmp := tmpPrefix + name + "-" + randomSuffix()
	if err := root.Mkdir(tmp, 0o700); err != nil {
		return fmt.Errorf("devicekey: make %s: %w", s.path(name), err)
	}
	done := false
	defer func() {
		if !done {
			_ = root.RemoveAll(tmp)
		}
	}()
	type file struct {
		name string
		data []byte
	}
	files := []file{
		{anchorKeyName, anchorKeyPEM},
		{anchorCertName, encodeCert(set.anchorDER)},
		{leafKeyName, leafKeyPEM},
		{leafCertName, encodeCert(set.leafDER)},
	}
	if enrolling {
		files = append(files, file{enrollingName, []byte(enrollingText)})
	}
	for _, f := range files {
		if err := s.writeFile(root, path.Join(tmp, f.name), f.data); err != nil {
			return err
		}
	}
	if err := root.Rename(tmp, name); err != nil {
		return fmt.Errorf("devicekey: make %s: %w", s.path(name), err)
	}
	done = true
	return nil
}

// encodeKey is key as PKCS#8 PEM, "PRIVATE KEY".
func encodeKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("devicekey: encode a key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemPrivateKey, Bytes: der}), nil
}

// encodeCert is der as PEM, "CERTIFICATE".
func encodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: pemCertificate, Bytes: der})
}

// pemSpace is the whitespace a PEM block may have around it.
const pemSpace = " \t\r\n"

// onlyBlock decodes data's one PEM block of type typ: no headers, and nothing
// around it but pemSpace. pem.Decode alone would skip any text before the
// block.
func onlyBlock(data []byte, typ string) ([]byte, bool) {
	data = bytes.TrimLeft(data, pemSpace)
	if !bytes.HasPrefix(data, []byte("-----BEGIN "+typ+"-----")) {
		return nil, false
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != typ || len(block.Headers) != 0 || len(bytes.Trim(rest, pemSpace)) != 0 {
		return nil, false
	}
	return block.Bytes, true
}

// decodeKey reads a P-256 key from PKCS#8 PEM.
func decodeKey(data []byte) (*ecdsa.PrivateKey, bool) {
	der, ok := onlyBlock(data, pemPrivateKey)
	if !ok {
		return nil, false
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, false
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, false
	}
	return key, true
}

// decodeCert reads a certificate from PEM.
func decodeCert(data []byte) (*x509.Certificate, bool) {
	der, ok := onlyBlock(data, pemCertificate)
	if !ok {
		return nil, false
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, false
	}
	return cert, true
}

// readAnchorCert reads dir's anchor.crt: it must parse, be a CA, and carry a
// role ID as its CN.
func (s *Store) readAnchorCert(dir string) (*x509.Certificate, RoleID, error) {
	rel := path.Join(dir, anchorCertName)
	data, err := s.readFile(rel)
	if err != nil {
		return nil, RoleID{}, err
	}
	cert, ok := decodeCert(data)
	if !ok || !cert.BasicConstraintsValid || !cert.IsCA {
		return nil, RoleID{}, inconsistent(rel)
	}
	id, err := ParseRoleID(cert.Subject.CommonName)
	if err != nil {
		return nil, RoleID{}, inconsistent(rel)
	}
	return cert, id, nil
}

// readLeafCert reads dir's leaf.crt: it must parse, carry the anchor's CN, and
// name the anchor's subject DN as its issuer, byte for byte.
func (s *Store) readLeafCert(dir string, anchor *x509.Certificate) (*x509.Certificate, error) {
	rel := path.Join(dir, leafCertName)
	data, err := s.readFile(rel)
	if err != nil {
		return nil, err
	}
	cert, ok := decodeCert(data)
	if !ok || cert.Subject.CommonName != anchor.Subject.CommonName || !bytes.Equal(cert.RawIssuer, anchor.RawSubject) {
		return nil, inconsistent(rel)
	}
	return cert, nil
}

// readLeafKey reads dir's leaf.key. matches is false when it does not parse
// or is not the leaf certificate's key: two renewals racing, or a crash
// between a renewal's two renames, leave exactly that, and the caller decides
// whether it is due or inconsistent.
func (s *Store) readLeafKey(dir string, leaf *x509.Certificate) (key *ecdsa.PrivateKey, matches bool, err error) {
	data, err := s.readFile(path.Join(dir, leafKeyName))
	if err != nil {
		return nil, false, err
	}
	key, ok := decodeKey(data)
	if !ok || !key.PublicKey.Equal(leaf.PublicKey) {
		return nil, false, nil
	}
	return key, true, nil
}

// readAnchorKey reads dir's anchor.key, which must be the anchor
// certificate's key.
func (s *Store) readAnchorKey(dir string, anchor *x509.Certificate) (*ecdsa.PrivateKey, error) {
	rel := path.Join(dir, anchorKeyName)
	data, err := s.readFile(rel)
	if err != nil {
		return nil, err
	}
	key, ok := decodeKey(data)
	if !ok || !key.PublicKey.Equal(anchor.PublicKey) {
		return nil, inconsistent(rel)
	}
	return key, nil
}
