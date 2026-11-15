package cli

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sofmon/farcast/datasphere"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/planck"
)

// readerKeyIDOf is the public key in a reader key PEM, and an id of Google's
// shape for it.
func readerKeyIDOf(t *testing.T, keyPEM []byte) (*rsa.PublicKey, string) {
	t.Helper()
	key, ok := readerPrivateKey(keyPEM)
	if !ok {
		t.Fatalf("not a reader key: %d bytes", len(keyPEM))
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(spki)
	return &key.PublicKey, hex.EncodeToString(sum[:20])
}

// ADR 0023 M2.3, mutation 47 (design §7.2): a rotation keeps every read on the
// old key until 'reader record' switches over. Against kubetest, through
// openCluster's reader branch, the /token request carries the old key id
// after --rotate, even once the new key is registered, and the new one only
// after record, which keeps the grant.
func TestRotateKeepsReadsWorkingUntilRecorded(t *testing.T) {
	s := kubetest.New(t)
	s.Put(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "farcast-system"}})
	dir, meta := readerInstance(t, s, "atlas", true)
	oldID := meta.Reader.KeyID
	oldKey := readFileOf(t, dir, "atlas", "reader.key")

	// mint reads once, as openCluster opens the reader from the record as it
	// is now, and returns the /token request that read made.
	mint := func(when string) kubetest.Request {
		t.Helper()
		m, err := dir.LoadInstanceMetadata("atlas")
		if err != nil {
			t.Fatal(err)
		}
		seen := len(s.Requests())
		c, err := openCluster(clusterRef{Dir: dir, Meta: m, Identity: kube.Reader, Warn: io.Discard})
		if err != nil {
			t.Fatalf("%s: openCluster: %v", when, err)
		}
		if names, err := c.NamespacesLabelled(t.Context(), ""); err != nil || !slices.Equal(names, []string{"farcast-system"}) {
			t.Fatalf("%s: the read = %q, %v", when, names, err)
		}
		for _, r := range s.Requests()[seen:] {
			if r.Path == "/token" {
				return r
			}
		}
		t.Fatalf("%s: the read minted no token", when)
		return kubetest.Request{}
	}
	if tok := mint("before the rotation"); tok.As != "reader" || tok.KeyID != oldID {
		t.Fatalf("before the rotation: minted as %q with %q", tok.As, tok.KeyID)
	}

	if _, errOut, code := farcastIn(t, dir, "reader", "init", "atlas", "--rotate"); code != 0 {
		t.Fatalf("reader init --rotate: %s", errOut)
	}
	if !bytes.Equal(readFileOf(t, dir, "atlas", "reader.key"), oldKey) {
		t.Error("--rotate wrote over the key in use")
	}
	if tok := mint("after the rotation"); tok.As != "reader" || tok.KeyID != oldID {
		t.Errorf("after the rotation: minted as %q with %q; want the old key, %q", tok.As, tok.KeyID, oldID)
	}

	// Google now holds the new key too, as the rotate script's upload leaves
	// it. Reads still sign with the old one until it is recorded.
	pub, newID := readerKeyIDOf(t, readFileOf(t, dir, "atlas", "reader.key.next"))
	s.AddKey("reader-next", meta.Reader.Email, pub)
	if tok := mint("after the upload"); tok.As != "reader" || tok.KeyID != oldID {
		t.Errorf("after the upload: minted as %q with %q; want the old key, %q", tok.As, tok.KeyID, oldID)
	}

	out, errOut, code := farcastIn(t, dir, "reader", "record", "atlas", "--key-id", newID)
	if code != 0 {
		t.Fatalf("reader record: exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "The previous key "+oldID+" still works.") {
		t.Errorf("record does not name the previous key:\n%s", out)
	}
	if tok := mint("after the record"); tok.As != "reader-next" || tok.KeyID != newID {
		t.Errorf("after the record: minted as %q with %q; want the new key, %q", tok.As, tok.KeyID, newID)
	}
	after, err := dir.LoadInstanceMetadata("atlas")
	if err != nil {
		t.Fatal(err)
	}
	if want := (config.Reader{Email: meta.Reader.Email, KeyID: newID, GrantedAt: readerGrantedAt, Scope: "metered"}); *after.Reader != want {
		t.Errorf("record left %+v; want %+v", *after.Reader, want)
	}
}

// After an init, record sets the key id and nothing else.
func TestReaderRecordAfterInit(t *testing.T) {
	dir := readerRecordFor(t, "atlas", "proj-test1")
	if _, errOut, code := farcastIn(t, dir, "reader", "init", "atlas"); code != 0 {
		t.Fatal(errOut)
	}
	key := readFileOf(t, dir, "atlas", "reader.key")
	email := readerEmail("atlas", "proj-test1")
	out, errOut, code := farcastIn(t, dir, "reader", "record", "atlas", "--key-id", readerTestKeyID)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if want := fmt.Sprintf("✓ instance \"atlas\"'s reader %s now signs with key %s\n", email, readerTestKeyID); out != want {
		t.Errorf("stdout %q; want %q", out, want)
	}
	meta, err := dir.LoadInstanceMetadata("atlas")
	if err != nil {
		t.Fatal(err)
	}
	if *meta.Reader != (config.Reader{Email: email, KeyID: readerTestKeyID}) {
		t.Errorf("record left %+v", *meta.Reader)
	}
	if !bytes.Equal(readFileOf(t, dir, "atlas", "reader.key"), key) {
		t.Error("record after an init changed reader.key")
	}

	// JSON names the same, with no previous key.
	out, errOut, code = farcastIn(t, dir, "-o", "json", "reader", "record", "atlas", "--key-id", readerTestKeyID)
	if code != 0 {
		t.Fatal(errOut)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if want := map[string]any{"instance": "atlas", "email": email, "key_id": readerTestKeyID}; fmt.Sprint(doc) != fmt.Sprint(want) {
		t.Errorf("JSON %v; want %v", doc, want)
	}
}

// After a rotate, record promotes reader.key.next, sets the new id, keeps the
// grant, and prints the line that deletes the previous key, from checked
// values.
func TestReaderRecordAfterRotate(t *testing.T) {
	dir := readerRecordFor(t, "atlas", "proj-test1")
	if _, errOut, code := farcastIn(t, dir, "reader", "init", "atlas"); code != 0 {
		t.Fatal(errOut)
	}
	if _, errOut, code := farcastIn(t, dir, "reader", "record", "atlas", "--key-id", readerTestKeyID); code != 0 {
		t.Fatal(errOut)
	}
	if _, err := dir.UpdateInstanceMetadata("atlas", func(m *config.InstanceMetadata) error {
		m.Reader.GrantedAt, m.Reader.Scope = readerGrantedAt, "metered"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := farcastIn(t, dir, "reader", "init", "atlas", "--rotate"); code != 0 {
		t.Fatal(errOut)
	}
	nextKey, nextCert := readFileOf(t, dir, "atlas", "reader.key.next"), readFileOf(t, dir, "atlas", "reader.crt.next")
	_, newID := readerKeyIDOf(t, nextKey)
	email := readerEmail("atlas", "proj-test1")

	out, errOut, code := farcastIn(t, dir, "reader", "record", "atlas", "--key-id", newID)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	want := fmt.Sprintf("✓ instance \"atlas\"'s reader %s now signs with key %s\n", email, newID) +
		fmt.Sprintf("The previous key %s still works. Once 'farcast reader grant atlas' has read with the new key, delete it from Cloud Shell: gcloud iam service-accounts keys delete '%s' --iam-account '%s' --project 'proj-test1'\n", readerTestKeyID, readerTestKeyID, email)
	if out != want {
		t.Errorf("stdout\n%q\nwant\n%q", out, want)
	}
	if !bytes.Equal(readFileOf(t, dir, "atlas", "reader.key"), nextKey) || !bytes.Equal(readFileOf(t, dir, "atlas", "reader.crt"), nextCert) {
		t.Error("record did not make the rotated key the one in use")
	}
	if readFileOf(t, dir, "atlas", "reader.key.next") != nil || readFileOf(t, dir, "atlas", "reader.crt.next") != nil {
		t.Error("record left the .next files")
	}
	meta, err := dir.LoadInstanceMetadata("atlas")
	if err != nil {
		t.Fatal(err)
	}
	if *meta.Reader != (config.Reader{Email: email, KeyID: newID, GrantedAt: readerGrantedAt, Scope: "metered"}) {
		t.Errorf("record left %+v", *meta.Reader)
	}
}

// record refuses, changing nothing, a key id not of Google's shape, an
// instance with no reader, a reader email that is not the derived one, a
// record checkedReader refuses, and, after a rotate, the id of the key in use.
func TestReaderRecordRefuses(t *testing.T) {
	email := readerEmail("atlas", "proj-test1")
	for _, id := range []string{"", readerTestKeyID[:39], readerTestKeyID + "0", strings.ToUpper(readerTestKeyID), readerTestKeyID[:39] + ";", "g" + readerTestKeyID[1:]} {
		dir := readerRecordFor(t, "atlas", "proj-test1")
		files := instanceFiles(t, dir, "atlas")
		out, errOut, code := farcastIn(t, dir, "reader", "record", "atlas", "--key-id", id)
		want := fmt.Sprintf("the key id %q is not the 40 hex characters Google prints", id)
		if code != 2 || out != "" || !strings.Contains(errOut, want) {
			t.Errorf("--key-id %q: exit %d, stdout %q, stderr %q; want a usage error %q", id, code, out, errOut, want)
		}
		sameFiles(t, "a refused record", files, instanceFiles(t, dir, "atlas"))
	}

	for _, row := range []struct {
		what   string
		meta   config.InstanceMetadata
		rotate bool
		want   string
	}{
		{"no reader", config.InstanceMetadata{Project: "proj-test1"}, false,
			"farcast: instance \"atlas\" has no reader identity; run 'farcast reader init atlas'\n"},
		{"the installer's email", config.InstanceMetadata{Project: "proj-test1", Reader: &config.Reader{Email: "farcast-installer@proj-test1.iam.gserviceaccount.com"}}, false,
			"farcast: instance \"atlas\" records the reader \"farcast-installer@proj-test1.iam.gserviceaccount.com\", which is not the reader farcast derives for it (" + email + "); nothing was changed\n"},
		{"the loopback form on a Google endpoint", config.InstanceMetadata{Project: "proj-test1", Reader: &config.Reader{Email: readerName("atlas") + "@kubetest.invalid"}}, false,
			"farcast: instance \"atlas\" records the reader \"" + readerName("atlas") + "@kubetest.invalid\", which is not the reader farcast derives for it (" + email + "); nothing was changed\n"},
		{"an unsafe project", config.InstanceMetadata{Project: "proj-$(id)", Reader: &config.Reader{Email: readerEmail("atlas", "proj-$(id)")}}, false,
			"farcast: instance \"atlas\"'s record holds a project ID that is not one Google issues (\"proj-$(id)\"); farcast renders nothing from it\n"},
		{"the key in use, after a rotate", config.InstanceMetadata{Project: "proj-test1", Reader: &config.Reader{Email: email, KeyID: readerTestKeyID}}, true,
			"farcast: that is the key in use; record the id the rotate script printed\n"},
	} {
		dir := config.Dir(filepath.Join(t.TempDir(), "cfg"))
		m := row.meta
		m.Name, m.Provider, m.Region, m.Endpoint = "atlas", "gke", "us-central1", "uid.us-central1.gke.goog"
		writeRecord(t, dir, &m)
		if row.rotate {
			if _, errOut, code := farcastIn(t, dir, "reader", "init", "atlas", "--rotate"); code != 0 {
				t.Fatalf("%s: %s", row.what, errOut)
			}
		}
		files := instanceFiles(t, dir, "atlas")
		out, errOut, code := farcastIn(t, dir, "reader", "record", "atlas", "--key-id", readerTestKeyID)
		if code != 1 || out != "" || errOut != row.want {
			t.Errorf("%s: exit %d, stdout %q, stderr\n%q\nwant\n%q", row.what, code, out, errOut, row.want)
		}
		sameFiles(t, row.what, files, instanceFiles(t, dir, "atlas"))
	}
}

// unsafeReaderRows are the records TestPrintedCloudShellLinesRefuseAnUnsafeRecord
// prints from, each with the marker no printed Cloud Shell line may carry.
var unsafeReaderRows = []struct {
	what    string
	project string
	keyID   string
	email   func(project string) string
	marker  string
	refused bool // checkedReader refuses it
}{
	{"a $( in the project", "proj-$(id)", readerTestKeyID, func(p string) string { return readerEmail("prod", p) }, "$(id)", true},
	{"a ; in the stored key id", "proj-1", readerTestKeyID + ";id", func(p string) string { return readerEmail("prod", p) }, ";id", true},
	{"a $( in the recorded email", "proj-1", readerTestKeyID, func(string) string { return readerName("prod") + "@$(id).iam.gserviceaccount.com" }, "$(id)", false},
}

// ADR 0023 M2.3, mutation 56a: release and reader record print Cloud Shell
// lines from checked values only. Release prints its fallback for a record
// checkedReader refuses, and the derived email when only the recorded email
// is unsafe; reader record refuses before it changes anything, and prints no
// Cloud Shell line at all. On a loopback (test) record, where the derived
// reader is readerName at any name under .invalid, record refuses a domain
// that is not DNS labels, and prints a clean one's delete line from
// checkedReader's values, never from the recorded email.
func TestPrintedCloudShellLinesRefuseAnUnsafeRecord(t *testing.T) {
	carries := func(t *testing.T, what, printed, marker string) {
		t.Helper()
		for _, l := range strings.Split(printed, "\n") {
			if strings.Contains(l, marker) {
				t.Errorf("%s: a printed line carries %q: %q", what, marker, l)
			}
		}
	}
	t.Run("release", func(t *testing.T) {
		for _, row := range unsafeReaderRows {
			for _, mode := range []string{"gate", "human", "json"} {
				env, out, errb, dir := releaseWithReader(t, mode, row.project, &config.Reader{Email: row.email(row.project), KeyID: row.keyID})
				printed := releasePrinted(t, env, dir, mode, out, errb)
				carries(t, row.what+", "+mode, printed, row.marker)
				fallback := fmt.Sprintf(msgReaderUnprintable, "prod", readerName("prod"))
				if mode == "json" {
					quoted, _ := json.Marshal(fallback)
					fallback = strings.Trim(string(quoted), `"`)
				}
				derived := readerEmail("prod", row.project)
				if row.refused {
					if !strings.Contains(printed, fallback) || strings.Contains(printed, "gcloud ") {
						t.Errorf("%s, %s: want the fallback and no gcloud line:\n%s", row.what, mode, printed)
					}
					continue
				}
				if !strings.Contains(printed, derived) || strings.Contains(printed, fallback) {
					t.Errorf("%s, %s: want the derived email %s:\n%s", row.what, mode, derived, printed)
				}
			}
		}
	})
	t.Run("reader record", func(t *testing.T) {
		for _, row := range unsafeReaderRows {
			dir := config.Dir(filepath.Join(t.TempDir(), "cfg"))
			writeRecord(t, dir, &config.InstanceMetadata{
				Name: "prod", Provider: "gke", Project: row.project, Region: "us-central1", Endpoint: "uid.us-central1.gke.goog",
				Reader: &config.Reader{Email: row.email(row.project), KeyID: row.keyID},
			})
			// A rotation waits, so a record that went ahead would print the
			// line that deletes the previous key.
			for _, f := range []string{"reader.key", "reader.crt", "reader.key.next", "reader.crt.next"} {
				if err := os.WriteFile(filepath.Join(dir.InstancePath("prod"), f), []byte(f), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			files := instanceFiles(t, dir, "prod")
			for _, args := range [][]string{
				{"reader", "record", "prod", "--key-id", strings.Repeat("ab", 20)},
				{"-o", "json", "reader", "record", "prod", "--key-id", strings.Repeat("ab", 20)},
			} {
				out, errOut, code := farcastIn(t, dir, args...)
				if code != 1 || strings.Contains(out+errOut, "gcloud") || strings.Contains(out, "previous") {
					t.Errorf("%s: exit %d, stdout %q, stderr %q; want a refusal that prints no Cloud Shell line", row.what, code, out, errOut)
				}
				if args[0] == "reader" && out != "" {
					t.Errorf("%s: stdout %q", row.what, out)
				}
			}
			sameFiles(t, row.what, files, instanceFiles(t, dir, "prod"))
		}
	})
	t.Run("reader record, loopback", func(t *testing.T) {
		// A rotation waits, so a record that went ahead prints the line
		// that deletes the previous key.
		loopback := func(t *testing.T, email string) (config.Dir, *config.InstanceMetadata) {
			t.Helper()
			dir, meta := readerInstance(t, kubetest.New(t), "atlas", true)
			if email != "" {
				if _, err := dir.UpdateInstanceMetadata("atlas", func(m *config.InstanceMetadata) error {
					m.Reader.Email = email
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			for _, f := range []string{"reader.key.next", "reader.crt.next"} {
				if err := os.WriteFile(filepath.Join(dir.InstancePath("atlas"), f), []byte(f), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			return dir, meta
		}
		newID := strings.Repeat("cd", 20)
		for _, domain := range []string{"$(id).invalid", "a'$(id)'.invalid"} {
			dir, _ := loopback(t, readerName("atlas")+"@"+domain)
			files := instanceFiles(t, dir, "atlas")
			out, errOut, code := farcastIn(t, dir, "reader", "record", "atlas", "--key-id", newID)
			if code != 1 || out != "" || strings.Contains(out+errOut, "gcloud") {
				t.Errorf("a domain %q: exit %d, stdout %q, stderr %q; want a refusal that prints no Cloud Shell line", domain, code, out, errOut)
			}
			sameFiles(t, "a loopback domain "+domain, files, instanceFiles(t, dir, "atlas"))
		}
		dir, meta := loopback(t, "")
		out, errOut, code := farcastIn(t, dir, "reader", "record", "atlas", "--key-id", newID)
		if code != 0 {
			t.Fatalf("a clean loopback record: exit %d: %s", code, errOut)
		}
		del := fmt.Sprintf("gcloud iam service-accounts keys delete '%s' --iam-account '%s' --project 'proj-test1'\n", meta.Reader.KeyID, readerEmail("atlas", "proj-test1"))
		if !strings.HasSuffix(out, ": "+del) {
			t.Errorf("the delete line is not built from checkedReader's values (%q):\n%s", del, out)
		}
		carries(t, "a clean loopback record", out, "@"+strings.SplitN(meta.Reader.Email, "@", 2)[1])
	})
}

// releaseProviders numbers the fake providers releaseWithReader registers.
var releaseProviders atomic.Int64

// releaseWithReader is a release of instance "prod", recorded with the given
// project and reader, against a fake provider.
func releaseWithReader(t *testing.T, mode, project string, reader *config.Reader) (*Env, *bytes.Buffer, *bytes.Buffer, config.Dir) {
	t.Helper()
	// One provider per release: a test makes several.
	prov := fmt.Sprintf("fake-release-%d", releaseProviders.Add(1))
	f := &fakeProvider{}
	planck.Register(prov, func(planck.Config) (planck.Provider, error) { return f, nil })
	om := outputModeOf(mode)
	env, out, errb, dir := newInstallEnv(t, om)
	recordInstance(t, dir, "prod", prov)
	if _, err := dir.UpdateInstanceMetadata("prod", func(m *config.InstanceMetadata) error {
		m.Project, m.Reader = project, reader
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return env, out, errb, dir
}

// releasePrinted is everything one release prints: its gate, as the
// interactive confirmation shows it, or its whole run with --yes.
func releasePrinted(t *testing.T, env *Env, dir config.Dir, mode string, out, errb *bytes.Buffer) string {
	t.Helper()
	if mode == "gate" {
		meta, err := dir.LoadInstanceMetadata("prod")
		if err != nil {
			t.Fatal(err)
		}
		var gate bytes.Buffer
		if _, err := (&releaseCommand{}).confirm(true, newPrompter(strings.NewReader("prod\n"), io.Discard), &gate, meta, datasphere.Usage{}, nil, releaseReaderOf("prod", meta)); err != nil {
			t.Fatal(err)
		}
		return gate.String()
	}
	if err := (&releaseCommand{assumeYes: true}).Run(t.Context(), env, []string{"prod"}); err != nil {
		t.Fatalf("release: %v", err)
	}
	return out.String() + errb.String()
}

// ADR 0023 M2.3, mutation 56: release names the reader account it leaves in
// Google, in its gate and its result, with the two Cloud Shell lines that
// delete it, the binding first; and names nothing when no reader is recorded.
func TestReleaseNamesTheReaderAccount(t *testing.T) {
	email := readerEmail("prod", "proj-1")
	gateLine := "  reader:      the reader service account " + email + ", which stays in Google until you delete it\n"
	human := "  reader:      " + email + " stays in Google; delete it from Cloud Shell, the binding first:\n" +
		"                 gcloud projects remove-iam-policy-binding 'proj-1' --condition=None \\\n" +
		"                   --member 'serviceAccount:" + email + "' --role 'roles/container.clusterViewer'\n" +
		"                 gcloud iam service-accounts delete '" + email + "' --project 'proj-1' --quiet\n" +
		"  state:       removed\n"
	commands := []string{
		"gcloud projects remove-iam-policy-binding 'proj-1' --condition=None --member 'serviceAccount:" + email + "' --role 'roles/container.clusterViewer'",
		"gcloud iam service-accounts delete '" + email + "' --project 'proj-1' --quiet",
	}
	reader := &config.Reader{Email: email, KeyID: readerTestKeyID, GrantedAt: readerGrantedAt, Scope: "metered"}

	env, out, errb, dir := releaseWithReader(t, "gate", "proj-1", reader)
	if gate := releasePrinted(t, env, dir, "gate", out, errb); !strings.Contains(gate, gateLine) {
		t.Errorf("the gate lacks\n%q:\n%s", gateLine, gate)
	}
	env, out, errb, dir = releaseWithReader(t, "human", "proj-1", reader)
	if printed := releasePrinted(t, env, dir, "human", out, errb); !strings.HasSuffix(out.String(), human) {
		t.Errorf("the result does not end with\n%s\ngot:\n%s", human, printed)
	}
	env, out, errb, dir = releaseWithReader(t, "json", "proj-1", reader)
	releasePrinted(t, env, dir, "json", out, errb)
	var doc struct {
		Reader map[string]any `json:"reader"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprint(doc.Reader), fmt.Sprint(map[string]any{"email": email, "cloud_shell": []any{commands[0], commands[1]}}); got != want {
		t.Errorf("JSON reader %s; want %s", got, want)
	}
	// The human lines, unwrapped, are the same two commands.
	flat := strings.Join(strings.Fields(strings.ReplaceAll(human, "\\\n", " ")), " ")
	for _, c := range commands {
		if !strings.Contains(flat, c) {
			t.Errorf("the human lines are not the command %q", c)
		}
	}

	// The fallback, in both.
	unsafe := &config.Reader{Email: email, KeyID: "not-a-key-id"}
	fallback := "the reader service account recorded for \"prod\" cannot be printed safely; in Cloud Shell, list the project's service accounts and delete " +
		readerName("prod") + ", after removing its roles/container.clusterViewer binding"
	for _, mode := range []string{"gate", "human"} {
		env, out, errb, dir := releaseWithReader(t, mode, "proj-1", unsafe)
		if printed := releasePrinted(t, env, dir, mode, out, errb); !strings.Contains(printed, "  reader:      "+fallback+"\n") {
			t.Errorf("%s lacks the fallback:\n%s", mode, printed)
		}
	}
	env, out, errb, dir = releaseWithReader(t, "json", "proj-1", unsafe)
	releasePrinted(t, env, dir, "json", out, errb)
	var fallbackDoc struct {
		Reader map[string]any `json:"reader"`
	}
	if err := json.Unmarshal(out.Bytes(), &fallbackDoc); err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprint(fallbackDoc.Reader), fmt.Sprint(map[string]any{"unprintable": fallback}); got != want {
		t.Errorf("JSON reader %s; want %s", got, want)
	}

	// No reader recorded, no reader named.
	for _, mode := range []string{"gate", "human", "json"} {
		env, out, errb, dir := releaseWithReader(t, mode, "proj-1", nil)
		if printed := releasePrinted(t, env, dir, mode, out, errb); strings.Contains(printed, "reader") {
			t.Errorf("%s names a reader none was recorded for:\n%s", mode, printed)
		}
	}
}

// outputModeOf is the printer mode a releaseWithReader mode runs in.
func outputModeOf(mode string) output.Mode {
	if mode == "json" {
		return output.ModeJSON
	}
	return output.ModeHuman
}
