package devicekey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"
	"time"
)

// t0 is the fixtures' enrolment time. Every test passes its own now, so no
// test depends on the wall clock.
var t0 = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

// fresh is a time at which a leaf issued at t0 is not due; due is one at
// which it is (its half life is 45 days from t0 − 1 h).
var (
	fresh = t0.Add(24 * time.Hour)
	due   = t0.Add(50 * 24 * time.Hour)
)

// detStream is a deterministic byte stream made from a seed: SHA-256 of the
// seed and a counter, block after block. It stands in for rnd where a test
// must know the bytes.
type detStream struct {
	seed string
	n    uint64
	buf  []byte
}

func (d *detStream) Read(p []byte) (int, error) {
	for len(d.buf) < len(p) {
		var c [8]byte
		binary.BigEndian.PutUint64(c[:], d.n)
		d.n++
		sum := sha256.Sum256(append([]byte(d.seed), c[:]...))
		d.buf = append(d.buf, sum[:]...)
	}
	n := copy(p, d.buf)
	d.buf = d.buf[n:]
	return n, nil
}

// failingReader fails every read.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("the random source failed") }

// enrolBoth enrols a writer-capable device at t0 in a new directory.
func enrolBoth(t *testing.T) (*Store, string, []Identity) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "identity")
	s, ids, err := Enrol(rand.Reader, dir, []Role{Reader, Writer}, t0)
	if err != nil {
		t.Fatalf("Enrol: %v", err)
	}
	if len(ids) != 2 || ids[0].Role() != Reader || ids[1].Role() != Writer {
		t.Fatalf("Enrol returned %d identities, roles %v", len(ids), ids)
	}
	return s, dir, ids
}

// recordReads makes s record every relative path its readFile is asked for,
// reading through the default reader.
func recordReads(s *Store) *[]string {
	var reads []string
	s.hooks.readFile = func(rel string) ([]byte, error) {
		reads = append(reads, rel)
		return s.readFileDefault(rel)
	}
	return &reads
}

// sortedSet is the sorted distinct elements of xs.
func sortedSet(xs []string) []string {
	out := slices.Clone(xs)
	sort.Strings(out)
	return slices.Compact(out)
}

// snapshot reads every file under root, by its slash path relative to root.
func snapshot(t *testing.T, root string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = data
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot %s: %v", root, err)
	}
	return files
}

// sameFiles reports whether two snapshots hold the same files, byte for byte.
func sameFiles(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || !bytes.Equal(v, w) {
			return false
		}
	}
	return true
}

// assertPerm checks path's permission bits, as config/instance_test.go does.
func assertPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s perm = %#o, want %#o", path, got, want)
	}
}

// readCert reads a certificate file the store wrote.
func readCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := decodeCert(data)
	if !ok {
		t.Fatalf("%s holds no certificate", path)
	}
	return c
}

// readKey reads a key file the store wrote.
func readKey(t *testing.T, path string) *ecdsa.PrivateKey {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	k, ok := decodeKey(data)
	if !ok {
		t.Fatalf("%s holds no P-256 key", path)
	}
	return k
}

// writeKeyFile replaces path's content with key, keeping the file's 0600.
func writeKeyFile(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	data, err := encodeKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeCertFile replaces path's content with der as PEM, keeping its 0600.
func writeCertFile(t *testing.T, path string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, encodeCert(der), 0o600); err != nil {
		t.Fatal(err)
	}
}

// mustKey makes a P-256 key.
func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := newKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// skipIfRoot skips a test whose point is a permission the superuser ignores.
func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("running as root, which reads any file; the test would prove nothing")
	}
}

// TestStoreModes: every directory is 0700 and every file 0600, from the
// moment it exists; a target at a wider mode is replaced, not chmod-ed; and a
// read refuses a wide, symlinked or swapped file before it opens it.
func TestStoreModes(t *testing.T) {
	s, dir, _ := enrolBoth(t)

	t.Run("enrol", func(t *testing.T) {
		assertPerm(t, dir, 0o700)
		for _, role := range []string{"reader", "writer"} {
			assertPerm(t, filepath.Join(dir, role), 0o700)
			for _, f := range []string{"anchor.key", "anchor.crt", "leaf.key", "leaf.crt"} {
				assertPerm(t, filepath.Join(dir, role, f), 0o600)
			}
		}
	})

	t.Run("every temporary file is 0600 when it is created", func(t *testing.T) {
		var seen []string
		s.hooks.afterCreate = func(rel string) {
			seen = append(seen, rel)
			assertPerm(t, filepath.Join(dir, filepath.FromSlash(rel)), 0o600)
		}
		defer func() { s.hooks.afterCreate = nil }()
		if _, err := s.RenewReaderLeaf(rand.Reader, fresh); err != nil {
			t.Fatal(err)
		}
		if _, err := s.RenewAnchor(Writer, rand.Reader, fresh); err != nil {
			t.Fatal(err)
		}
		if err := s.DiscardStaged(Writer); err != nil {
			t.Fatal(err)
		}
		if len(seen) != 6 {
			t.Fatalf("afterCreate ran for %v; want two leaf files and a staged renewal's four", seen)
		}
	})

	t.Run("a wider target is replaced, not chmod-ed", func(t *testing.T) {
		target := filepath.Join(dir, "reader", "leaf.crt")
		if err := os.Chmod(target, 0o644); err != nil {
			t.Fatal(err)
		}
		before, err := os.Lstat(target)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.RenewReaderLeaf(rand.Reader, fresh); err != nil {
			t.Fatal(err)
		}
		after, err := os.Lstat(target)
		if err != nil {
			t.Fatal(err)
		}
		assertPerm(t, target, 0o600)
		if os.SameFile(before, after) {
			t.Error("the 0644 target is the same file after the write: it was chmod-ed in place, not replaced")
		}
	})

	t.Run("Open refuses a 0755 directory", func(t *testing.T) {
		for _, d := range []string{dir, filepath.Join(dir, "writer")} {
			if err := os.Chmod(d, 0o755); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(dir); !errors.Is(err, ErrUnsafeMode) {
				t.Errorf("Open with %s at 0755: err = %v, want ErrUnsafeMode", d, err)
			}
			if _, err := s.OpenForWrite(GiveConsent(ConsentConfirmed), rand.Reader, fresh); !errors.Is(err, ErrUnsafeMode) {
				t.Errorf("OpenForWrite with %s at 0755: err = %v, want ErrUnsafeMode", d, err)
			}
			if err := os.Chmod(d, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := Open(dir); err != nil {
			t.Fatalf("Open after the modes were restored: %v", err)
		}
	})

	t.Run("a widened store directory is still removed", func(t *testing.T) {
		// Erase and RemoveRole open no file, so a mode other accounts can
		// reach, which is when the keys are most exposed, must not keep
		// them on disk. A symlink in the store's place is still refused.
		for _, mode := range []fs.FileMode{0o755, 0o777, 0o750, 0o705} {
			ws, wdir, _ := enrolBoth(t)
			if err := os.Chmod(wdir, mode); err != nil {
				t.Fatal(err)
			}
			if err := ws.RemoveRole(Writer); err != nil {
				t.Errorf("RemoveRole(Writer) with the store at %o: %v", mode, err)
			}
			if _, err := os.Lstat(filepath.Join(wdir, "writer")); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("writer/ is still there after RemoveRole with the store at %o", mode)
			}
			if _, err := os.Lstat(filepath.Join(wdir, "reader", "leaf.key")); err != nil {
				t.Errorf("RemoveRole(Writer) with the store at %o touched the reader: %v", mode, err)
			}
			if err := ws.Erase(); err != nil {
				t.Errorf("Erase with the store at %o: %v", mode, err)
			}
			if _, err := os.Lstat(wdir); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("Erase with the store at %o left the directory", mode)
			}
		}
		ls, ldir, _ := enrolBoth(t)
		moved := ldir + ".real"
		if err := os.Rename(ldir, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(moved, ldir); err != nil {
			t.Fatal(err)
		}
		if err := ls.Erase(); !errors.Is(err, ErrUnsafeMode) {
			t.Errorf("Erase through a symlink: err = %v, want ErrUnsafeMode", err)
		}
		if err := ls.RemoveRole(Writer); !errors.Is(err, ErrUnsafeMode) {
			t.Errorf("RemoveRole through a symlink: err = %v, want ErrUnsafeMode", err)
		}
		if _, err := os.Lstat(filepath.Join(moved, "writer", "anchor.key")); err != nil {
			t.Errorf("a removal through a symlink reached the real directory: %v", err)
		}
	})

	t.Run("a key file at 0o240 is refused before it is opened", func(t *testing.T) {
		skipIfRoot(t)
		key := filepath.Join(dir, "reader", "leaf.key")
		if err := os.Chmod(key, 0o240); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(key, 0o600) }()
		if _, err := os.ReadFile(key); err == nil {
			t.Skip("the owner can read a 0o240 file here; the row would prove nothing")
		}
		_, err := s.OpenForRead(rand.Reader, fresh)
		if !errors.Is(err, ErrUnsafeMode) {
			t.Errorf("OpenForRead with leaf.key at 0o240: err = %v, want ErrUnsafeMode (a read before the check gives EACCES)", err)
		}
	})

	t.Run("a symlinked key file is refused", func(t *testing.T) {
		key := filepath.Join(dir, "reader", "leaf.key")
		saved, err := os.ReadFile(key)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(key); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("anchor.key", key); err != nil {
			t.Fatal(err)
		}
		_, err = s.OpenForRead(rand.Reader, fresh)
		if !errors.Is(err, ErrUnsafeMode) {
			t.Errorf("OpenForRead with leaf.key a symlink: err = %v, want ErrUnsafeMode", err)
		}
		if err := os.Remove(key); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(key, saved, 0o600); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("a symlinked role directory is refused", func(t *testing.T) {
		role := filepath.Join(dir, "reader")
		real := filepath.Join(dir, "elsewhere")
		if err := os.Rename(role, real); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("elsewhere", role); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(dir); !errors.Is(err, ErrUnsafeMode) {
			t.Errorf("Open with reader/ a symlink: err = %v, want ErrUnsafeMode", err)
		}
		if _, err := s.OpenForRead(rand.Reader, fresh); !errors.Is(err, ErrUnsafeMode) {
			t.Errorf("OpenForRead with reader/ a symlink: err = %v, want ErrUnsafeMode", err)
		}
		if _, err := s.readFileDefault("reader/leaf.crt"); !errors.Is(err, ErrUnsafeMode) {
			t.Errorf("a read under a symlinked reader/: err = %v, want ErrUnsafeMode", err)
		}
		if err := os.Remove(role); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(real, role); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("a file swapped for a symlink after its Lstat is refused", func(t *testing.T) {
		key := filepath.Join(dir, "reader", "leaf.key")
		saved, err := os.ReadFile(key)
		if err != nil {
			t.Fatal(err)
		}
		swapped := false
		s.hooks.afterLstat = func(rel string) {
			if rel != "reader/leaf.key" || swapped {
				return
			}
			swapped = true
			if err := os.Remove(key); err != nil {
				t.Error(err)
			}
			if err := os.Symlink("anchor.key", key); err != nil { // another 0600 file
				t.Error(err)
			}
		}
		defer func() { s.hooks.afterLstat = nil }()
		_, err = s.OpenForRead(rand.Reader, fresh)
		if !swapped {
			t.Fatal("the hook never saw reader/leaf.key")
		}
		if !errors.Is(err, ErrUnsafeMode) {
			t.Errorf("OpenForRead with leaf.key swapped after its Lstat: err = %v, want ErrUnsafeMode", err)
		}
		if err := os.Remove(key); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(key, saved, 0o600); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("a file widened after its Lstat is refused", func(t *testing.T) {
		key := filepath.Join(dir, "reader", "leaf.key")
		widened := false
		s.hooks.afterLstat = func(rel string) {
			if rel != "reader/leaf.key" || widened {
				return
			}
			widened = true
			if err := os.Chmod(key, 0o644); err != nil { // the same file, now readable by others
				t.Error(err)
			}
		}
		defer func() {
			s.hooks.afterLstat = nil
			if err := os.Chmod(key, 0o600); err != nil {
				t.Error(err)
			}
		}()
		_, err := s.OpenForRead(rand.Reader, fresh)
		if !widened {
			t.Fatal("the hook never saw reader/leaf.key")
		}
		if !errors.Is(err, ErrUnsafeMode) {
			t.Errorf("OpenForRead with leaf.key widened to 0644 after its Lstat: err = %v, want ErrUnsafeMode (the open file's mode is checked again)", err)
		}
	})

	t.Run("a file of 64 KiB is read and one byte more is refused", func(t *testing.T) {
		crt := filepath.Join(dir, "reader", "leaf.crt")
		saved, err := os.ReadFile(crt)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.WriteFile(crt, saved, 0o600); err != nil {
				t.Error(err)
			}
		}()
		// The certificate's own PEM padded with newlines, which the PEM reader
		// accepts after a block: only the size can refuse it. The cap is the
		// spec's number (§1.6), written out, so a changed constant fails here.
		const limit = 64 << 10
		padded := func(n int) []byte {
			return append(bytes.Clone(saved), bytes.Repeat([]byte("\n"), n-len(saved))...)
		}
		if err := os.WriteFile(crt, padded(limit), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.OpenForRead(rand.Reader, fresh); err != nil {
			t.Fatalf("OpenForRead with a %d-byte leaf.crt: %v; the cap is %d bytes, not less", limit, err, limit)
		}
		if err := os.WriteFile(crt, padded(limit+1), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.OpenForRead(rand.Reader, fresh); err == nil {
			t.Errorf("OpenForRead with a %d-byte leaf.crt succeeded; a read over %d bytes is refused", limit+1, limit)
		}
	})

	if _, err := s.OpenForRead(rand.Reader, fresh); err != nil {
		t.Fatalf("the store does not open after the rows restored it: %v", err)
	}
}

// TestEnrolMakesFreshKeysPerRole: a writer-capable device has four distinct
// keys and two distinct IDs, two devices share none, and Enrol refuses a
// writer alone, a duplicate and a directory that already holds something.
func TestEnrolMakesFreshKeysPerRole(t *testing.T) {
	keysOf := func(t *testing.T, dir string) []*ecdsa.PrivateKey {
		var keys []*ecdsa.PrivateKey
		for _, role := range []string{"reader", "writer"} {
			for _, f := range []string{"anchor.key", "leaf.key"} {
				keys = append(keys, readKey(t, filepath.Join(dir, role, f)))
			}
		}
		return keys
	}
	_, dirA, idsA := enrolBoth(t)
	_, dirB, idsB := enrolBoth(t)
	keys := append(keysOf(t, dirA), keysOf(t, dirB)...)
	for i := range keys {
		for j := i + 1; j < len(keys); j++ {
			if keys[i].PublicKey.Equal(&keys[j].PublicKey) {
				t.Errorf("keys %d and %d are the same key", i, j)
			}
		}
	}
	ids := []RoleID{idsA[0].ID(), idsA[1].ID(), idsB[0].ID(), idsB[1].ID()}
	for i := range ids {
		if ids[i].IsZero() {
			t.Errorf("ID %d is zero", i)
		}
		for j := i + 1; j < len(ids); j++ {
			if ids[i].Equal(ids[j]) {
				t.Errorf("IDs %d and %d are the same", i, j)
			}
		}
	}
	// Each identity's signer is its own leaf's key, and each anchor its own.
	for _, id := range append(idsA, idsB...) {
		leaf, err := x509.ParseCertificate(id.LeafDER())
		if err != nil {
			t.Fatal(err)
		}
		if !leaf.PublicKey.(*ecdsa.PublicKey).Equal(id.Signer().Public()) {
			t.Errorf("the %s identity's signer is not its leaf's key", id.Role())
		}
	}

	// The role rule itself refuses each of these, before any draw and before
	// any directory: the source counts its reads, so a refusal that came from
	// a failed draw (the rule having let the list through) is told apart.
	const enrolRolesRefusal = "devicekey: a device enrols as a reader, or as a reader and a writer, each role once"
	for _, roles := range [][]Role{{Writer}, {Reader, Reader}, {Writer, Writer}, {}, nil, {Reader, Writer, Reader}, {Reader, Role(3)}, {Role(0)}, {Writer, Role(0)}} {
		dir := filepath.Join(t.TempDir(), "identity")
		cr := &countingReader{}
		_, _, err := Enrol(cr, dir, roles, t0)
		if err == nil || err.Error() != enrolRolesRefusal {
			t.Errorf("Enrol(%v): err = %v, want the role rule's refusal", roles, err)
		}
		if cr.reads != 0 {
			t.Errorf("Enrol(%v) read the random source %d times before refusing its roles", roles, cr.reads)
		}
		if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Enrol(%v) was refused and still made its directory", roles)
		}
	}
	// The control: a role list the rule admits reaches the random source, so a
	// zero count above is the rule's doing.
	for _, roles := range [][]Role{{Reader}, {Reader, Writer}, {Writer, Reader}} {
		cr := &countingReader{}
		dir := filepath.Join(t.TempDir(), "identity")
		if _, _, err := Enrol(cr, dir, roles, t0); err == nil || err.Error() == enrolRolesRefusal || cr.reads == 0 {
			t.Errorf("Enrol(%v) with a failing source: err = %v after %d reads, want a draw's failure", roles, err, cr.reads)
		}
		if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Enrol(%v) failed its draw and left its directory", roles)
		}
	}

	nonEmpty := t.TempDir()
	if err := os.Chmod(nonEmpty, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nonEmpty, "something"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Enrol(rand.Reader, nonEmpty, []Role{Reader}, t0); !errors.Is(err, ErrStoreExists) {
		t.Errorf("Enrol into a non-empty directory: err = %v, want ErrStoreExists", err)
	}
	if _, _, err := Enrol(rand.Reader, dirA, []Role{Reader}, t0); !errors.Is(err, ErrStoreExists) {
		t.Errorf("Enrol into an enrolled directory: err = %v, want ErrStoreExists", err)
	}
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Enrol(rand.Reader, empty, []Role{Reader}, t0); err != nil {
		t.Errorf("Enrol into an empty 0700 directory: %v", err)
	}
	wide := filepath.Join(t.TempDir(), "wide")
	if err := os.Mkdir(wide, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(wide, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Enrol(rand.Reader, wide, []Role{Reader}, t0); !errors.Is(err, ErrUnsafeMode) {
		t.Errorf("Enrol into a 0755 directory: err = %v, want ErrUnsafeMode", err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(empty, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Enrol(rand.Reader, link, []Role{Reader}, t0); !errors.Is(err, ErrUnsafeMode) {
		t.Errorf("Enrol into a symlink: err = %v, want ErrUnsafeMode", err)
	}
	if _, _, err := Enrol(failingReader{}, filepath.Join(t.TempDir(), "failed"), []Role{Reader}, t0); err == nil {
		t.Error("Enrol with a failing random source succeeded")
	}
}

// TestStoreRefusesAMismatchedPair: each row names the function that meets
// the mismatch; each gives ErrInconsistent, naming the role and the file and
// never the ID.
func TestStoreRefusesAMismatchedPair(t *testing.T) {
	type row struct {
		name  string
		file  string // the file the error names
		setup func(t *testing.T, dir string, id RoleID)
		calls map[string]func(s *Store) error
	}
	openDue := func(s *Store) error { _, err := s.OpenForRead(rand.Reader, due); return err }
	openFresh := func(s *Store) error { _, err := s.OpenForRead(rand.Reader, fresh); return err }
	certs := func(s *Store) error { _, _, _, err := s.Certificates(Reader); return err }
	renew := func(s *Store) error { _, err := s.RenewReaderLeaf(rand.Reader, fresh); return err }
	otherAnchor := func(t *testing.T, id RoleID) ([]byte, *ecdsa.PrivateKey) {
		der, key, err := newAnchor(rand.Reader, id, t0)
		if err != nil {
			t.Fatal(err)
		}
		return der, key
	}
	rows := []row{{
		name: "anchor key is not the anchor certificate's",
		file: "reader/anchor.key",
		setup: func(t *testing.T, dir string, id RoleID) {
			writeKeyFile(t, filepath.Join(dir, "reader", "anchor.key"), mustKey(t))
		},
		calls: map[string]func(s *Store) error{"RenewReaderLeaf": renew, "OpenForRead (due)": openDue},
	}, {
		name: "anchor certificate is not a CA",
		file: "reader/anchor.crt",
		setup: func(t *testing.T, dir string, id RoleID) {
			key := mustKey(t)
			tmpl, err := AnchorTemplate(id, bigOne(), NotBefore(t0), &key.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			tmpl.IsCA, tmpl.MaxPathLenZero, tmpl.KeyUsage = false, false, x509.KeyUsageDigitalSignature
			der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			writeCertFile(t, filepath.Join(dir, "reader", "anchor.crt"), der)
		},
		calls: map[string]func(s *Store) error{"OpenForRead": openFresh, "Certificates": certs},
	}, {
		name: "anchor CN is not a role ID",
		file: "reader/anchor.crt",
		setup: func(t *testing.T, dir string, id RoleID) {
			key := mustKey(t)
			tmpl, err := AnchorTemplate(id, bigOne(), NotBefore(t0), &key.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			tmpl.Subject.CommonName = "not-a-role-id"
			der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			writeCertFile(t, filepath.Join(dir, "reader", "anchor.crt"), der)
		},
		calls: map[string]func(s *Store) error{"OpenForRead": openFresh, "Certificates": certs},
	}, {
		name: "leaf CN is not the anchor's",
		file: "reader/leaf.crt",
		setup: func(t *testing.T, dir string, id RoleID) {
			anchor := readCert(t, filepath.Join(dir, "reader", "anchor.crt"))
			anchorKey := readKey(t, filepath.Join(dir, "reader", "anchor.key"))
			other, err := NewRoleID(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			leafKey := mustKey(t)
			der, err := x509.CreateCertificate(rand.Reader, LeafTemplate(other, bigOne(), NotBefore(t0), anchor), anchor, &leafKey.PublicKey, anchorKey)
			if err != nil {
				t.Fatal(err)
			}
			writeCertFile(t, filepath.Join(dir, "reader", "leaf.crt"), der)
			writeKeyFile(t, filepath.Join(dir, "reader", "leaf.key"), leafKey)
		},
		calls: map[string]func(s *Store) error{"OpenForRead": openFresh, "Certificates": certs},
	}, {
		name: "leaf issuer DN is not the anchor's subject DN",
		file: "reader/leaf.crt",
		setup: func(t *testing.T, dir string, id RoleID) {
			other, err := NewRoleID(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			otherDER, otherKey := otherAnchor(t, other)
			otherCert, err := x509.ParseCertificate(otherDER)
			if err != nil {
				t.Fatal(err)
			}
			leafKey := mustKey(t)
			der, err := x509.CreateCertificate(rand.Reader, LeafTemplate(id, bigOne(), NotBefore(t0), otherCert), otherCert, &leafKey.PublicKey, otherKey)
			if err != nil {
				t.Fatal(err)
			}
			writeCertFile(t, filepath.Join(dir, "reader", "leaf.crt"), der)
			writeKeyFile(t, filepath.Join(dir, "reader", "leaf.key"), leafKey)
		},
		calls: map[string]func(s *Store) error{"OpenForRead": openFresh, "Certificates": certs},
	}}
	for _, r := range rows {
		for name, call := range r.calls {
			t.Run(r.name+"/"+name, func(t *testing.T) {
				s, dir, ids := enrolBoth(t)
				id := ids[0].ID()
				r.setup(t, dir, id)
				err := call(s)
				if !errors.Is(err, ErrInconsistent) {
					t.Fatalf("err = %v, want ErrInconsistent", err)
				}
				msg := err.Error()
				if !bytes.Contains([]byte(msg), []byte(r.file)) {
					t.Errorf("the error %q does not name the role and the file %s", msg, r.file)
				}
				if containsID(msg, id) {
					t.Errorf("the error %q names the role ID", msg)
				}
			})
		}
	}
}
