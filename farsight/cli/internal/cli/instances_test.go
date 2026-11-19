package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
)

// 'instances' reads each instance's metadata.yaml and nothing else: no
// credential, no kubeconfig, no mTLS material, no keyring.
func TestInstancesReadsOnlyTheRecords(t *testing.T) {
	dir := config.Dir(t.TempDir())
	connectedInstance(t, dir, "atlas") // credentials, kubeconfig and mTLS on disk beside the record
	// The premise: the files instances must not open are there to be opened.
	// Nothing writes kubeconfig.yaml since ADR 0023 M2.7, so the fixture
	// writes the one an older install left (installedInstance, A30-34).
	for _, f := range []string{"credentials.yaml", "kubeconfig.yaml"} {
		if _, err := os.Lstat(filepath.Join(dir.InstancePath("atlas"), f)); err != nil {
			t.Fatalf("the fixture holds no %s beside the record: %v", f, err)
		}
	}
	var mu sync.Mutex
	var opened []string
	stop := config.ObserveReads(func(p string) {
		mu.Lock()
		defer mu.Unlock()
		opened = append(opened, p)
	})
	defer stop()
	env, out := testEnv(dir, output.ModeHuman)
	if err := instancesVectorCommand().Run(context.Background(), env, nil); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(opened, []string{filepath.Join(dir.InstancePath("atlas"), "metadata.yaml")}) {
		t.Errorf("read %v, want the one record", opened)
	}
	if !strings.Contains(out.String(), "atlas") || !strings.Contains(out.String(), "READER") || !strings.Contains(out.String(), " none ") {
		t.Errorf("listing:\n%s", out.String())
	}
}

// An instance directory is named by whoever made it, and a name that would
// act on the terminal is quoted in the human listing.
func TestInstancesHumanQuotesNames(t *testing.T) {
	r := instancesResult{Instances: []instanceEntry{
		{Name: "evil\x1b[2J", Error: &sectionProblem{Kind: kindRecordUnreadable, Message: "x\u202ey"}},
	}}
	var b strings.Builder
	if err := r.Human(&b); err != nil {
		t.Fatal(err)
	}
	if !output.Printable(strings.ReplaceAll(b.String(), "\n", "")) {
		t.Errorf("the listing carries a character that acts on the terminal: %q", b.String())
	}
	b.Reset()
	if err := (instancesResult{}).Human(&b); err != nil || !strings.Contains(b.String(), "No instances") {
		t.Errorf("an empty listing: %q", b.String())
	}
}

func TestHelpListsTheConnectedViewCommands(t *testing.T) {
	out, _, code := runCLI(t, "help")
	if code != 0 || !strings.Contains(out, "instances") || !strings.Contains(out, "world") {
		t.Fatalf("help:\n%s", out)
	}
	for _, cmd := range []string{"instances", "world"} {
		out, _, code := runCLI(t, "help", cmd)
		if code != 0 || !strings.Contains(out, "Usage: farcast "+cmd) {
			t.Errorf("help %s:\n%s", cmd, out)
		}
	}
}

// Design §7.4 and A18-12, mutation 67: pin-gcloud is retired. Its documented
// form, the subcommand alone, and --account alone are each a usage error,
// through the router: exit 2, the retirement text on stderr, nothing on
// stdout, in either output mode, and the record byte for byte as it was.
func TestPinGCloudIsRetired(t *testing.T) {
	dir := vectorConfigDir(t)
	writeRecord(t, dir, vectorMeta())
	path := filepath.Join(dir.InstancePath("atlas"), "metadata.yaml")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"instances", "pin-gcloud", "atlas", "--account", "operator@example.org"},
		{"instances", "pin-gcloud", "atlas"},
		{"instances", "pin-gcloud"},
		{"instances", "--account", "operator@example.org"},
		// A18-12 (C-C24-6): the flag given is the retired form, whatever its
		// value; an empty one, from an unset variable, included.
		{"instances", "--account", ""},
		{"instances", "--account="},
	} {
		for _, mode := range []string{"json", "human"} {
			var out, errb bytes.Buffer
			code := run(context.Background(), append([]string{"farcast", "--config", dir.Path(), "-o", mode}, args...), strings.NewReader(""), &out, &errb)
			if code != 2 || out.Len() != 0 {
				t.Errorf("%v -o %s: exit %d, stdout %q; want exit 2 and nothing", args, mode, code, out.String())
			}
			if !strings.Contains(errb.String(), msgPinGCloudRetired) {
				t.Errorf("%v -o %s: stderr %q; want the retirement text", args, mode, errb.String())
			}
		}
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("the record changed:\n%s\nwas\n%s", after, before)
	}
	if !strings.Contains(msgPinGCloudRetired, "pin-gcloud was retired by ADR 0023 M2: farcast reads each instance's cluster as its own read-only service account ('farcast reader init'), so there is no gcloud account to pin.") {
		t.Errorf("the retirement text is %q", msgPinGCloudRetired)
	}
}

// Design §8.2 and A18-13, mutations 65a, 65b (C-C24-2), O24, O25 and O25b:
// every reader state 'instances' reports, through the router, in the order
// its checks run: no reader; reader.key absent, whether or not a key id is
// recorded; no key id; not verified read-only; granted. A reader.key whose
// presence cannot be told (a symlink to itself, so its stat fails with a loop
// rather than with absence) makes the entry unreadable, as an unreadable
// record is: record_unreadable, its message naming the file relative to the
// config directory.
func TestInstancesReportsEachReaderState(t *testing.T) {
	dir := vectorConfigDir(t)
	key := strings.Repeat("ab", 20)
	reader := func(name, keyID string, granted bool) *config.Reader {
		r := &config.Reader{Email: readerName(name) + "@kubetest.invalid", KeyID: keyID}
		if granted {
			r.GrantedAt, r.Scope = readerGrantedAt, "metered"
		}
		return r
	}
	rows := []struct {
		name   string
		reader *config.Reader
		file   string // "", "key" or "loop"
		want   string
	}{
		{"none", nil, "", readerNone},
		{"missing", reader("missing", key, true), "", readerKeyMissing},
		{"missing-noid", reader("missing-noid", "", false), "", readerKeyMissing},
		{"notuploaded", reader("notuploaded", "", false), "key", readerNotUploaded},
		{"notgranted", reader("notgranted", key, false), "key", readerNotGranted},
		{"granted", reader("granted", key, true), "key", readerGranted},
		{"loop", reader("loop", key, true), "loop", ""},
	}
	for _, row := range rows {
		meta := vectorMeta()
		meta.Name, meta.Reader = row.name, row.reader
		writeRecord(t, dir, meta)
		p := filepath.Join(dir.InstancePath(row.name), "reader.key")
		switch row.file {
		case "key":
			if err := os.WriteFile(p, []byte("KEY"), 0o600); err != nil {
				t.Fatal(err)
			}
		case "loop":
			if err := os.Symlink("reader.key", p); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(dir.InstancePath("loop"), "reader.key")); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("guard: a self-referential reader.key must fail its stat other than as absent: %v", err)
	}

	out, code := runRouter(t, "--config", dir.Path(), "-o", "json", "instances")
	if code != 0 {
		t.Fatalf("instances: exit %d\n%s", code, out)
	}
	var doc struct {
		Instances []struct {
			Name   string          `json:"name"`
			Reader *string         `json:"reader"`
			Error  *sectionProblem `json:"error"`
		} `json:"instances"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("%v:\n%s", err, out)
	}
	got := map[string]int{}
	for i, e := range doc.Instances {
		got[e.Name] = i
	}
	for _, row := range rows {
		i, ok := got[row.name]
		if !ok {
			t.Errorf("%s is not listed:\n%s", row.name, out)
			continue
		}
		e := doc.Instances[i]
		if row.want == "" {
			prefix := filepath.Join("instances", row.name, "reader.key") + " could not be checked: "
			if e.Error == nil || e.Error.Kind != kindRecordUnreadable || !strings.HasPrefix(e.Error.Message, prefix) ||
				strings.Contains(e.Error.Message, dir.Path()) || e.Reader != nil {
				t.Errorf("%s = %+v (error %+v); want record_unreadable, %q…, no absolute path and no reader state", row.name, e, e.Error, prefix)
			}
			continue
		}
		if e.Error != nil || e.Reader == nil || *e.Reader != row.want {
			t.Errorf("%s: reader %v (error %+v); want %q", row.name, e.Reader, e.Error, row.want)
		}
	}
}
