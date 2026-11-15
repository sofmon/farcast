package config

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"
)

func readerDir(t *testing.T) Dir {
	t.Helper()
	d := testDir(t)
	if err := d.CreateInstance("atlas"); err != nil {
		t.Fatal(err)
	}
	return d
}

// observeReads collects every path this package reads until the test ends.
func observeReads(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var read []string
	stop := ObserveReads(func(p string) {
		mu.Lock()
		defer mu.Unlock()
		read = append(read, p)
	})
	t.Cleanup(stop)
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(read)
	}
}

// ADR 0023 M2.3, mutation 43: the reader's key, its certificate and the
// rotated pair are owner-only files, whatever the umask, and a key written
// over one that was readable by others comes out owner-only too.
func TestReaderKeyIsWrittenOwnerOnly(t *testing.T) {
	d := readerDir(t)
	dir := d.InstancePath("atlas")
	// A key someone left readable by others is replaced, not kept.
	if err := os.WriteFile(filepath.Join(dir, readerKeyFile), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := d.SaveReaderKey("atlas", []byte("KEY"), []byte("CERT")); err != nil {
		t.Fatal(err)
	}
	if err := d.SaveNextReaderKey("atlas", []byte("NEXT KEY"), []byte("NEXT CERT")); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{readerKeyFile, readerCertFile, nextReaderKeyFile, nextReaderCertFile} {
		assertPerm(t, filepath.Join(dir, f), 0o600)
	}
	if err := d.PromoteNextReaderKey("atlas"); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{readerKeyFile, readerCertFile} {
		assertPerm(t, filepath.Join(dir, f), 0o600)
	}
	if key, err := d.LoadReaderKey("atlas"); err != nil || string(key) != "NEXT KEY" {
		t.Errorf("reader.key after the promotion = %q, %v", key, err)
	}

	// Nothing is written without both halves.
	if err := d.SaveReaderKey("atlas", nil, []byte("CERT")); err == nil {
		t.Error("SaveReaderKey wrote a certificate with no key")
	}
	if err := d.SaveNextReaderKey("atlas", []byte("KEY"), nil); err == nil {
		t.Error("SaveNextReaderKey wrote a key with no certificate")
	}
	if ok, _ := d.NextReaderKeyExists("atlas"); ok {
		t.Error("a refused SaveNextReaderKey left reader.key.next behind")
	}
}

// The rotated key moves before its certificate, and neither moves unless both
// are there: a missing certificate never leaves a new key beside the old one.
func TestPromoteNextReaderKeyMovesTheKeyFirst(t *testing.T) {
	d := readerDir(t)
	dir := d.InstancePath("atlas")
	if err := d.SaveReaderKey("atlas", []byte("OLD KEY"), []byte("OLD CERT")); err != nil {
		t.Fatal(err)
	}

	// With no rotation waiting, nothing moves.
	if err := d.PromoteNextReaderKey("atlas"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("promote with no rotation: %v, want fs.ErrNotExist", err)
	}
	// With only the key, nothing moves either.
	if err := writeFileAtomic(filepath.Join(dir, nextReaderKeyFile), []byte("NEW KEY")); err != nil {
		t.Fatal(err)
	}
	if err := d.PromoteNextReaderKey("atlas"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("promote with no next certificate: %v, want fs.ErrNotExist", err)
	}
	if key, _ := d.LoadReaderKey("atlas"); string(key) != "OLD KEY" {
		t.Fatalf("a refused promotion moved the key: reader.key = %q", key)
	}

	// The key moves first: with the certificate's rename made to fail (a
	// directory sits where reader.crt goes), the key has moved and the
	// certificate has not.
	if err := writeFileAtomic(filepath.Join(dir, nextReaderCertFile), []byte("NEW CERT")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, readerCertFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, readerCertFile, "blocker"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := d.PromoteNextReaderKey("atlas"); err == nil {
		t.Fatal("the certificate's rename over a directory succeeded; the test proves nothing")
	}
	if key, _ := d.LoadReaderKey("atlas"); string(key) != "NEW KEY" {
		t.Errorf("reader.key = %q after a promotion that stopped at the certificate, want the new key (the key moves first)", key)
	}
	if cert, _ := d.LoadNextReaderCert("atlas"); string(cert) != "NEW CERT" {
		t.Errorf("reader.crt.next = %q, want it left for a retry", cert)
	}

	// A clean promotion.
	if err := os.RemoveAll(filepath.Join(dir, readerCertFile)); err != nil {
		t.Fatal(err)
	}
	if err := d.SaveNextReaderKey("atlas", []byte("NEWER KEY"), []byte("NEWER CERT")); err != nil {
		t.Fatal(err)
	}
	if err := d.PromoteNextReaderKey("atlas"); err != nil {
		t.Fatal(err)
	}
	key, _ := d.LoadReaderKey("atlas")
	cert, _ := d.LoadReaderCert("atlas")
	if string(key) != "NEWER KEY" || string(cert) != "NEWER CERT" {
		t.Errorf("after the promotion reader.key = %q, reader.crt = %q", key, cert)
	}
	if ok, _ := d.NextReaderKeyExists("atlas"); ok {
		t.Error("reader.key.next is still there after the promotion")
	}
	if _, err := os.Stat(filepath.Join(dir, nextReaderCertFile)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("reader.crt.next after the promotion: %v", err)
	}
}

// ADR 0023 M2.4's 'instances' reports a reader's state without opening a
// credential: the Exists helpers stat and never open, even a file nobody may
// read.
func TestReaderKeyExistsNeverOpensTheKey(t *testing.T) {
	d := readerDir(t)
	dir := d.InstancePath("atlas")
	for _, exists := range []func(string) (bool, error){d.ReaderKeyExists, d.NextReaderKeyExists} {
		if ok, err := exists("atlas"); ok || err != nil {
			t.Errorf("before any key: %v, %v", ok, err)
		}
	}
	if err := d.SaveReaderKey("atlas", []byte("KEY"), []byte("CERT")); err != nil {
		t.Fatal(err)
	}
	if err := d.SaveNextReaderKey("atlas", []byte("NEXT KEY"), []byte("NEXT CERT")); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{readerKeyFile, nextReaderKeyFile} {
		p := filepath.Join(dir, f)
		if err := os.Chmod(p, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
	}

	reads := observeReads(t)
	for name, exists := range map[string]func(string) (bool, error){"ReaderKeyExists": d.ReaderKeyExists, "NextReaderKeyExists": d.NextReaderKeyExists} {
		if ok, err := exists("atlas"); !ok || err != nil {
			t.Errorf("%s on an unreadable key = %v, %v; want true from a stat alone", name, ok, err)
		}
	}
	if got := reads(); len(got) != 0 {
		t.Errorf("the Exists helpers read %v", got)
	}

	// The observer does see a read, so its silence above means something.
	if err := os.Chmod(filepath.Join(dir, readerKeyFile), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := d.LoadReaderKey("atlas"); err != nil {
		t.Fatal(err)
	}
	if got := reads(); !slices.Equal(got, []string{filepath.Join(dir, readerKeyFile)}) {
		t.Errorf("LoadReaderKey read %v", got)
	}
}

// Every reader file is read through readFile, so a test can see which
// credential a command opened.
func TestReaderFilesAreReadThroughTheObserver(t *testing.T) {
	d := readerDir(t)
	dir := d.InstancePath("atlas")
	if err := d.SaveReaderKey("atlas", []byte("KEY"), []byte("CERT")); err != nil {
		t.Fatal(err)
	}
	if err := d.SaveNextReaderKey("atlas", []byte("NEXT KEY"), []byte("NEXT CERT")); err != nil {
		t.Fatal(err)
	}
	reads := observeReads(t)
	for _, load := range []struct {
		file string
		fn   func(string) ([]byte, error)
		want string
	}{
		{readerKeyFile, d.LoadReaderKey, "KEY"},
		{readerCertFile, d.LoadReaderCert, "CERT"},
		{nextReaderKeyFile, d.LoadNextReaderKey, "NEXT KEY"},
		{nextReaderCertFile, d.LoadNextReaderCert, "NEXT CERT"},
	} {
		if b, err := load.fn("atlas"); err != nil || string(b) != load.want {
			t.Errorf("load %s = %q, %v", load.file, b, err)
		}
		if got := reads(); len(got) == 0 || got[len(got)-1] != filepath.Join(dir, load.file) {
			t.Errorf("load %s: the observer saw %v", load.file, got)
		}
	}
}

// cluster-ca.crt is optional: absent is ok=false and no error (a Google
// endpoint has none), present is its bytes, and either way it is read
// through the observer.
func TestLoadClusterCA(t *testing.T) {
	d := readerDir(t)
	path := filepath.Join(d.InstancePath("atlas"), clusterCAFile)
	reads := observeReads(t)

	pem, ok, err := d.LoadClusterCA("atlas")
	if pem != nil || ok || err != nil {
		t.Errorf("absent: %q, %v, %v; want nil, false, nil", pem, ok, err)
	}
	if err := os.WriteFile(path, []byte("CA PEM"), 0o600); err != nil {
		t.Fatal(err)
	}
	pem, ok, err = d.LoadClusterCA("atlas")
	if string(pem) != "CA PEM" || !ok || err != nil {
		t.Errorf("present: %q, %v, %v", pem, ok, err)
	}
	// An empty file exists: it is present, and the endpoint rule refuses it.
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if pem, ok, err := d.LoadClusterCA("atlas"); pem == nil || len(pem) != 0 || !ok || err != nil {
		t.Errorf("empty: %q (nil %v), %v, %v; want present and empty", pem, pem == nil, ok, err)
	}
	// Any other failure is an error, never absent.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := d.LoadClusterCA("atlas"); ok || err == nil {
		t.Errorf("a directory named cluster-ca.crt: %v, %v; want an error", ok, err)
	}
	if got := reads(); len(got) != 4 || got[0] != path || got[3] != path {
		t.Errorf("the observer saw %v", got)
	}
}

// The reader block round-trips, and a write merges onto a newer record the
// way every other field does: a change to the reader and a change elsewhere
// both survive, and two different changes to the reader are refused.
func TestReaderRoundTripsAndMerges(t *testing.T) {
	d := readerDir(t)
	granted := time.Date(2026, 11, 14, 9, 30, 0, 0, time.UTC)
	if err := d.SaveInstanceMetadata("atlas", &InstanceMetadata{Name: "atlas", Provider: "gke"}); err != nil {
		t.Fatal(err)
	}
	if m, err := d.LoadInstanceMetadata("atlas"); err != nil || m.Reader != nil {
		t.Fatalf("a record written before readers: reader = %+v, %v", m.Reader, err)
	}

	// 'reader init' records an unverified reader.
	if _, err := d.UpdateInstanceMetadata("atlas", func(m *InstanceMetadata) error {
		m.Reader = &Reader{Email: "farcast-reader-0123abcd@proj-1.iam.gserviceaccount.com"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(d.InstancePath("atlas"), metadataFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"key_id", "scope"} {
		if bytes.Contains(raw, []byte(absent)) {
			t.Errorf("an unrecorded %s was written: %s", absent, raw)
		}
	}

	// A command holds the record across a long operation while 'reader
	// record' and 'reader grant' land. Its own change, and theirs, survive.
	stale, err := d.LoadInstanceMetadata("atlas")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.UpdateInstanceMetadata("atlas", func(m *InstanceMetadata) error {
		m.Reader.KeyID = "c7b74879da78e4cdcbe7e1bf5e129375c0bfa8d0"
		m.Reader.GrantedAt = granted
		m.Reader.Scope = "metered"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	stale.Carrier = &Carrier{Type: "nlb", Endpoint: "34.0.0.5:443", ServerName: "fatline"}
	if err := d.SaveInstanceMetadata("atlas", stale); err != nil {
		t.Fatalf("save over a newer reader: %v", err)
	}
	got, err := d.LoadInstanceMetadata("atlas")
	if err != nil {
		t.Fatal(err)
	}
	want := Reader{
		Email:     "farcast-reader-0123abcd@proj-1.iam.gserviceaccount.com",
		KeyID:     "c7b74879da78e4cdcbe7e1bf5e129375c0bfa8d0",
		GrantedAt: granted,
		Scope:     "metered",
	}
	if got.Reader == nil || got.Reader.Email != want.Email || got.Reader.KeyID != want.KeyID ||
		!got.Reader.GrantedAt.Equal(want.GrantedAt) || got.Reader.Scope != want.Scope {
		t.Errorf("reader after the merge = %+v, want %+v", got.Reader, want)
	}
	if got.Carrier == nil || got.Carrier.Endpoint != "34.0.0.5:443" {
		t.Errorf("the stale command's own change was lost: carrier = %+v", got.Carrier)
	}

	// Two commands moving the reader to different places is refused.
	mine, err := d.LoadInstanceMetadata("atlas")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.UpdateInstanceMetadata("atlas", func(m *InstanceMetadata) error {
		m.Reader.GrantedAt, m.Reader.Scope = time.Time{}, ""
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	mine.Reader = &Reader{Email: want.Email, KeyID: "0000000000000000000000000000000000000000", GrantedAt: granted, Scope: "metered"}
	if err := d.SaveInstanceMetadata("atlas", mine); !errors.Is(err, ErrMetadataConflict) {
		t.Errorf("two different reader changes: %v, want ErrMetadataConflict", err)
	}
	got, err = d.LoadInstanceMetadata("atlas")
	if err != nil {
		t.Fatal(err)
	}
	if got.Reader.KeyID != want.KeyID || !got.Reader.GrantedAt.IsZero() {
		t.Errorf("the refused write changed the reader: %+v", got.Reader)
	}
}
