package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
)

// readerTestKeyID is a key id of the shape Google prints (its own sample).
const readerTestKeyID = "c7b74879da78e4cdcbe7e1bf5e129375c0bfa8d0"

// readerRecordFor records a Google-mode instance with no reader, as install
// leaves one.
func readerRecordFor(t *testing.T, name, project string) config.Dir {
	t.Helper()
	dir := config.Dir(filepath.Join(t.TempDir(), "cfg"))
	writeRecord(t, dir, &config.InstanceMetadata{
		Name: name, Provider: "gke", Project: project, Region: "us-central1",
		Cluster: "farcast-" + name, Endpoint: "uid.us-central1.gke.goog", Status: config.InstanceRunning,
	})
	return dir
}

// farcastIn runs one farcast command line, through the router, against dir.
func farcastIn(t *testing.T, dir config.Dir, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var out, errb bytes.Buffer
	full := append([]string{"farcast", "--config", string(dir)}, args...)
	code = run(context.Background(), full, strings.NewReader(""), &out, &errb)
	return out.String(), errb.String(), code
}

// readFileOf reads one file of an instance's directory; nil when absent.
func readFileOf(t *testing.T, dir config.Dir, name, file string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir.InstancePath(name), file))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// instanceFiles is every file in an instance's directory and its bytes, so a
// test can show a refusal changed nothing.
func instanceFiles(t *testing.T, dir config.Dir, name string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir.InstancePath(name))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	for _, e := range entries {
		files[e.Name()] = string(readFileOf(t, dir, name, e.Name()))
	}
	return files
}

func sameFiles(t *testing.T, what string, before, after map[string]string) {
	t.Helper()
	for f, b := range before {
		if a, ok := after[f]; !ok || a != b {
			t.Errorf("%s changed or removed %s", what, f)
		}
	}
	for f := range after {
		if _, ok := before[f]; !ok {
			t.Errorf("%s wrote %s", what, f)
		}
	}
}

// certOf parses the one certificate in a PEM file.
func certOf(t *testing.T, b []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("no certificate in %q", b)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// scriptCert is the certificate between a script's FARCAST_CERT delimiters.
func scriptCert(t *testing.T, script string) []byte {
	t.Helper()
	_, after, ok := strings.Cut(script, "<<'FARCAST_CERT'\n")
	if !ok {
		t.Fatalf("no certificate here-document in:\n%s", script)
	}
	body, _, ok := strings.Cut(after, "FARCAST_CERT\n")
	if !ok {
		t.Fatalf("the certificate here-document does not end:\n%s", script)
	}
	return []byte(body)
}

// initAndRotateScripts renders both scripts through the commands: init for an
// instance with no reader, then, once a key id is recorded, --rotate.
func initAndRotateScripts(t *testing.T) (dir config.Dir, initScript, rotateScript string) {
	t.Helper()
	dir = readerRecordFor(t, "atlas", "proj-test1")
	initScript, stderr, code := farcastIn(t, dir, "reader", "init", "atlas")
	if code != 0 {
		t.Fatalf("reader init: exit %d: %s", code, stderr)
	}
	if _, stderr, code := farcastIn(t, dir, "reader", "record", "atlas", "--key-id", readerTestKeyID); code != 0 {
		t.Fatalf("reader record: exit %d: %s", code, stderr)
	}
	rotateScript, stderr, code = farcastIn(t, dir, "reader", "init", "atlas", "--rotate")
	if code != 0 {
		t.Fatalf("reader init --rotate: exit %d: %s", code, stderr)
	}
	return dir, initScript, rotateScript
}

func scriptLines(script string) []string {
	return strings.Split(strings.TrimSuffix(script, "\n"), "\n")
}

// ADR 0023 M2.3, design §7.2: each rendered script, and the script it runs
// in its child shell, parse as sh.
func TestReaderScriptParses(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skipf("no /bin/sh here: %v", err)
	}
	_, initScript, rotateScript := initAndRotateScripts(t)
	scratch := t.TempDir()
	for kind, script := range map[string]string{"init": initScript, "rotate": rotateScript} {
		lines := scriptLines(script)
		body := strings.Join(lines[1:len(lines)-1], "\n") + "\n"
		for part, text := range map[string]string{"script": script, "body": body} {
			path := filepath.Join(scratch, kind+"-"+part+".sh")
			if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command("/bin/sh", "-n", path).CombinedOutput()
			if err != nil {
				t.Errorf("sh -n on the %s %s: %v\n%s\n%s", kind, part, err, out, text)
			}
		}
	}
}

// ADR 0023 M2.3, mutation 45: each script runs as `sh -s` on a here-document,
// so set -eu and a failure exit only the child, never the Owner's Cloud Shell.
func TestReaderScriptRunsInAChildShell(t *testing.T) {
	_, initScript, rotateScript := initAndRotateScripts(t)
	for kind, script := range map[string]string{"init": initScript, "rotate": rotateScript} {
		if !strings.HasSuffix(script, "FARCAST_READER\n") {
			t.Errorf("%s: the script does not end with its delimiter line:\n%s", kind, script)
		}
		lines := scriptLines(script)
		if lines[0] != "sh -s <<'FARCAST_READER'" {
			t.Errorf("%s: first line %q; want the child shell", kind, lines[0])
		}
		if last := lines[len(lines)-1]; last != "FARCAST_READER" {
			t.Errorf("%s: last line %q; want FARCAST_READER", kind, last)
		}
		for i, l := range lines {
			if l == "FARCAST_READER" && i != len(lines)-1 {
				t.Errorf("%s: line %d ends the child's here-document early", kind, i+1)
			}
			if strings.Contains(l, "set -eu") && (i == 0 || i == len(lines)-1 || l != "set -eu") {
				t.Errorf("%s: line %d, %q, is outside the child shell", kind, i+1, l)
			}
		}
		if n := strings.Count(script, "set -eu"); n != 1 {
			t.Errorf("%s: set -eu appears %d times", kind, n)
		}
	}
}

// ADR 0023 M2.3, mutation 46: the rotate script uploads a key and nothing
// else; only the init script creates the account and grants it a role.
func TestReaderRotateScriptCreatesNothing(t *testing.T) {
	dir, initScript, rotateScript := initAndRotateScripts(t)
	for _, verb := range []string{"service-accounts create", "add-iam-policy-binding"} {
		if strings.Contains(rotateScript, verb) {
			t.Errorf("the rotate script runs %q:\n%s", verb, rotateScript)
		}
		if !strings.Contains(initScript, verb) {
			t.Errorf("the init script lacks %q, so this test proves nothing", verb)
		}
	}
	if !strings.Contains(rotateScript, "gcloud iam service-accounts keys upload") ||
		!strings.Contains(rotateScript, "EMAIL='"+readerEmail("atlas", "proj-test1")+"'") {
		t.Errorf("the rotate script does not upload to the reader:\n%s", rotateScript)
	}
	// It carries reader.crt.next, the key not yet in use.
	if got, want := scriptCert(t, rotateScript), readFileOf(t, dir, "atlas", "reader.crt.next"); !bytes.Equal(got, want) {
		t.Errorf("the rotate script carries\n%s\nwant reader.crt.next\n%s", got, want)
	}
}

// ADR 0023 M2.3, mutation 44: nothing init prints, in either mode, holds
// private key material: no PRIVATE KEY block, and no line of the key's PEM.
func TestReaderScriptHoldsNoPrivateKey(t *testing.T) {
	dir := readerRecordFor(t, "atlas", "proj-test1")
	var printed []string
	for _, args := range [][]string{
		{"reader", "init", "atlas"},
		{"-o", "json", "reader", "init", "atlas"},
	} {
		out, errOut, code := farcastIn(t, dir, args...)
		if code != 0 {
			t.Fatalf("%v: exit %d: %s", args, code, errOut)
		}
		printed = append(printed, out, errOut)
	}
	key := readFileOf(t, dir, "atlas", "reader.key")
	if _, _, code := farcastIn(t, dir, "reader", "record", "atlas", "--key-id", readerTestKeyID); code != 0 {
		t.Fatal("reader record failed")
	}
	keys := [][]byte{key}
	for _, args := range [][]string{
		{"reader", "init", "atlas", "--rotate"},
		{"-o", "json", "reader", "init", "atlas", "--rotate"},
	} {
		out, errOut, code := farcastIn(t, dir, args...)
		if code != 0 {
			t.Fatalf("%v: exit %d: %s", args, code, errOut)
		}
		printed = append(printed, out, errOut)
		// Each --rotate makes its own reader.key.next.
		keys = append(keys, readFileOf(t, dir, "atlas", "reader.key.next"))
	}
	var keyLines []string
	for _, k := range keys {
		if len(k) == 0 {
			t.Fatal("init left no key to look for")
		}
		block, _ := pem.Decode(k)
		keyLines = append(keyLines, base64.StdEncoding.EncodeToString(block.Bytes))
		for _, l := range strings.Split(string(k), "\n") {
			if l != "" && !strings.HasPrefix(l, "-----") {
				keyLines = append(keyLines, l)
			}
		}
	}
	for _, p := range printed {
		if strings.Contains(p, "PRIVATE KEY") {
			t.Errorf("init printed a private key:\n%s", p)
		}
		for _, l := range keyLines {
			if strings.Contains(p, l) {
				t.Errorf("init printed the key's material %q", l)
			}
		}
	}
}

// ADR 0023 M2.3, mutations 48 and 48a: the record is checked before anything
// is rendered from it, and the certificate is rendered only from a parsed one,
// whose subject is exactly CN=unused even when its key is reader.key's own.
func TestReaderScriptRefusesAnUnsafeRecord(t *testing.T) {
	t.Run("record", func(t *testing.T) {
		for _, row := range []struct {
			name, project, field, value string
		}{
			{"atlas", "proj-te'st1", "project ID", "proj-te'st1"},
			{"atlas", "proj-$(id)", "project ID", "proj-$(id)"},
			{"atl'as", "proj-test1", "name", "atl'as"},
			{"a$(id)", "proj-test1", "name", "a$(id)"},
		} {
			dir := readerRecordFor(t, row.name, row.project)
			before := instanceFiles(t, dir, row.name)
			out, errOut, code := farcastIn(t, dir, "reader", "init", row.name)
			want := fmt.Sprintf("farcast: instance %q's record holds a %s that is not one Google issues (%q); farcast renders nothing from it\n", row.name, row.field, row.value)
			if code != 1 || out != "" || errOut != want {
				t.Errorf("%s/%s: exit %d, stdout %q, stderr %q; want exit 1, nothing on stdout, and %q", row.name, row.project, code, out, errOut, want)
			}
			sameFiles(t, "a refused init", before, instanceFiles(t, dir, row.name))
		}
	})

	t.Run("reader.crt", func(t *testing.T) {
		dir := readerRecordFor(t, "atlas", "proj-test1")
		clean, errOut, code := farcastIn(t, dir, "reader", "init", "atlas")
		if code != 0 {
			t.Fatalf("reader init: %s", errOut)
		}
		cert := readFileOf(t, dir, "atlas", "reader.crt")
		key := readFileOf(t, dir, "atlas", "reader.key")
		_, otherCert, err := kube.NewReaderKey(rand.Reader, time.Now().Add(-time.Hour), 1)
		if err != nil {
			t.Fatal(err)
		}
		// A certificate of reader.key's own key, under a subject of the
		// test's choosing: only CN=unused, exactly, may reach Google.
		ownKey, ok := readerPrivateKey(key)
		if !ok {
			t.Fatal("reader init made no RSA reader key")
		}
		ownCert := func(subject pkix.Name) []byte {
			t.Helper()
			tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: subject,
				NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ownKey.PublicKey, ownKey)
			if err != nil {
				t.Fatal(err)
			}
			return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		}
		const refused = "farcast: instances/atlas/reader.crt is not the certificate of this instance's reader key; delete instances/atlas/reader.key and reader.crt, then run 'farcast reader init atlas' again\n"
		for _, row := range []struct {
			what    string
			file    []byte
			renders bool
		}{
			{"a block followed by FARCAST_CERT and $(id)", append(slices.Clone(cert), "FARCAST_CERT\n$(id)\n"...), false},
			{"a block followed by FARCAST_READER", append(slices.Clone(cert), "FARCAST_READER\n"...), false},
			{"a PRIVATE KEY block after the certificate", append(slices.Clone(cert), key...), false},
			{"a PRIVATE KEY block alone", key, false},
			{"the certificate of another key", otherCert, false},
			{"reader.key's own key under a subject naming the account", ownCert(pkix.Name{CommonName: readerName("atlas")}), false},
			{"reader.key's own key under CN=unused and an organization", ownCert(pkix.Name{CommonName: "unused", Organization: []string{"atlas"}}), false},
			{"a valid block preceded by FARCAST_CERT and $(id)", append([]byte("FARCAST_CERT\n$(id)\n"), cert...), true},
			{"a valid block preceded by FARCAST_READER", append([]byte("FARCAST_READER\n"), cert...), true},
		} {
			if err := os.WriteFile(filepath.Join(dir.InstancePath("atlas"), "reader.crt"), row.file, 0o600); err != nil {
				t.Fatal(err)
			}
			out, errOut, code := farcastIn(t, dir, "reader", "init", "atlas")
			if !row.renders {
				if code != 1 || out != "" || errOut != refused {
					t.Errorf("%s: exit %d, stdout %q, stderr %q; want it refused with %q", row.what, code, out, errOut, refused)
				}
				continue
			}
			if code != 0 || out != clean {
				t.Errorf("%s: exit %d (%s); the script is not the clean one:\n%s", row.what, code, errOut, out)
			}
			var delims int
			for _, l := range scriptLines(out) {
				if l == "FARCAST_CERT" {
					delims++
				}
			}
			if delims != 1 {
				t.Errorf("%s: %d FARCAST_CERT lines; want only the delimiter", row.what, delims)
			}
		}
	})

	t.Run("reader.crt.next", func(t *testing.T) {
		dir := readerRecordFor(t, "atlas", "proj-test1")
		if _, errOut, code := farcastIn(t, dir, "reader", "init", "atlas"); code != 0 {
			t.Fatal(errOut)
		}
		keyPEM, _, err := kube.NewReaderKey(rand.Reader, time.Now().Add(-time.Hour), 1)
		if err != nil {
			t.Fatal(err)
		}
		// The next key beside the certificate of the key in use.
		if err := dir.SaveNextReaderKey("atlas", keyPEM, readFileOf(t, dir, "atlas", "reader.crt")); err != nil {
			t.Fatal(err)
		}
		meta, err := dir.LoadInstanceMetadata("atlas")
		if err != nil {
			t.Fatal(err)
		}
		meta.Reader.KeyID = readerTestKeyID
		script, _, err := renderReaderScript(dir, "atlas", meta, readerScriptRotate)
		want := "instances/atlas/reader.crt.next is not the certificate of this instance's next reader key; run 'farcast reader init atlas --rotate' again"
		if script != nil || err == nil || err.Error() != want {
			t.Errorf("renderReaderScript = %q, %v; want %q", script, err, want)
		}
	})
}

// ADR 0023 M2.3, mutation 49: the certificate init makes, and the one its
// script carries, are generic: subject and issuer exactly CN=unused, no
// extension, and nothing in them names the instance, the account or the
// project.
func TestReaderCertificateIsGeneric(t *testing.T) {
	const name, project = "orion-lab", "proj-orion7"
	dir := readerRecordFor(t, name, project)
	script, errOut, code := farcastIn(t, dir, "reader", "init", name)
	if code != 0 {
		t.Fatal(errOut)
	}
	for what, pemBytes := range map[string][]byte{
		"reader.crt": readFileOf(t, dir, name, "reader.crt"),
		"the script": scriptCert(t, script),
	} {
		cert := certOf(t, pemBytes)
		if !bytes.Equal(cert.RawSubject, cnUnused) || !bytes.Equal(cert.RawIssuer, cnUnused) || cert.Subject.String() != "CN=unused" {
			t.Errorf("%s: subject %q, issuer %q; want exactly CN=unused", what, cert.Subject, cert.Issuer)
		}
		if len(cert.Extensions) != 0 || cert.KeyUsage != 0 || len(cert.ExtKeyUsage) != 0 {
			t.Errorf("%s: carries extensions %v, key usage %v, %v", what, cert.Extensions, cert.KeyUsage, cert.ExtKeyUsage)
		}
		for _, s := range []string{name, "orion", readerName(name), readerEmail(name, project), project} {
			if bytes.Contains(cert.Raw, []byte(s)) {
				t.Errorf("%s: the certificate holds %q", what, s)
			}
		}
	}
}

// init's three cases without --rotate (design §7.2 step 1): no reader makes a
// key and records the reader; a reader not yet uploaded prints its script
// again from the stored key, or makes one if reader.key is gone; an uploaded
// one is refused.
func TestReaderInitCases(t *testing.T) {
	dir := readerRecordFor(t, "atlas", "proj-test1")
	email := readerEmail("atlas", "proj-test1")
	before := time.Now()

	// 1. No reader.
	first, errOut, code := farcastIn(t, dir, "reader", "init", "atlas")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	sum := sha256.Sum256([]byte(first))
	if want := "Paste this into Cloud Shell as a project Owner (sha256 " + hex.EncodeToString(sum[:]) + "). It holds only the public certificate.\n"; errOut != want {
		t.Errorf("stderr %q; want %q", errOut, want)
	}
	meta, err := dir.LoadInstanceMetadata("atlas")
	if err != nil {
		t.Fatal(err)
	}
	if meta.Reader == nil || *meta.Reader != (config.Reader{Email: email}) {
		t.Errorf("recorded reader %+v; want only the derived email", meta.Reader)
	}
	for _, f := range []string{"reader.key", "reader.crt"} {
		assertPerm(t, filepath.Join(dir.InstancePath("atlas"), f), 0o600)
	}
	key, crt := readFileOf(t, dir, "atlas", "reader.key"), readFileOf(t, dir, "atlas", "reader.crt")
	if got := scriptCert(t, first); !bytes.Equal(got, crt) {
		t.Errorf("the script carries\n%s\nwant reader.crt\n%s", got, crt)
	}
	for _, want := range []string{"PROJECT='proj-test1'", "SA='" + readerName("atlas") + "'", "--display-name 'FarCast reader for atlas'", "farcast reader record atlas --key-id $KEY_ID"} {
		if !strings.Contains(first, want) {
			t.Errorf("the script lacks %q", want)
		}
	}
	cert := certOf(t, crt)
	// Valid from an hour before now, for the default 365 days.
	if nb := cert.NotBefore; nb.Before(before.Add(-time.Hour-2*time.Second)) || nb.After(time.Now().Add(-time.Hour)) {
		t.Errorf("NotBefore %v; want an hour before %v", nb, before)
	}
	if got := cert.NotAfter.Sub(cert.NotBefore); got != 365*24*time.Hour {
		t.Errorf("lifetime %v; want 365 days", got)
	}

	// 2. Recorded and not uploaded: the same key, the same script, and the
	// record untouched. --days given names that it went unused.
	record := readFileOf(t, dir, "atlas", "metadata.yaml")
	again, errOut, code := farcastIn(t, dir, "reader", "init", "atlas", "--days", "30")
	if code != 0 || again != first {
		t.Errorf("exit %d (%s); the script printed again differs:\n%s", code, errOut, again)
	}
	if !strings.Contains(errOut, "Note: instances/atlas/reader.key exists and no key id is recorded for it, so no key was made and --days was not used.") {
		t.Errorf("stderr %q does not say --days went unused", errOut)
	}
	if !bytes.Equal(readFileOf(t, dir, "atlas", "reader.key"), key) || !bytes.Equal(readFileOf(t, dir, "atlas", "metadata.yaml"), record) {
		t.Error("init printed again, and changed the key or the record")
	}
	// ... and with reader.key gone, a new key, the record kept.
	if err := os.Remove(filepath.Join(dir.InstancePath("atlas"), "reader.key")); err != nil {
		t.Fatal(err)
	}
	remade, errOut, code := farcastIn(t, dir, "reader", "init", "atlas", "--days", "30")
	if code != 0 || remade == first {
		t.Fatalf("exit %d (%s); no new key's script", code, errOut)
	}
	if strings.Contains(errOut, "Note:") {
		t.Errorf("a key was made, yet stderr says none was: %q", errOut)
	}
	newKey := readFileOf(t, dir, "atlas", "reader.key")
	if bytes.Equal(newKey, key) || len(newKey) == 0 {
		t.Error("reader.key was not made again")
	}
	if got := certOf(t, readFileOf(t, dir, "atlas", "reader.crt")); got.NotAfter.Sub(got.NotBefore) != 30*24*time.Hour {
		t.Errorf("--days 30 made a certificate valid for %v", got.NotAfter.Sub(got.NotBefore))
	}
	if !bytes.Equal(readFileOf(t, dir, "atlas", "metadata.yaml"), record) {
		t.Error("making the key again changed the record")
	}

	// 3. Uploaded: refused, nothing changed.
	if _, errOut, code := farcastIn(t, dir, "reader", "record", "atlas", "--key-id", readerTestKeyID); code != 0 {
		t.Fatal(errOut)
	}
	files := instanceFiles(t, dir, "atlas")
	out, errOut, code := farcastIn(t, dir, "reader", "init", "atlas")
	want := fmt.Sprintf("farcast: instance \"atlas\" already has a reader (%s); --rotate makes a new key and prints the script that uploads it\n", email)
	if code != 1 || out != "" || errOut != want {
		t.Errorf("exit %d, stdout %q, stderr %q; want %q", code, out, errOut, want)
	}
	sameFiles(t, "a refused init", files, instanceFiles(t, dir, "atlas"))
}

// --rotate needs an uploaded key; given one, it writes reader.key.next and
// reader.crt.next and changes neither the key in use nor the record.
func TestReaderInitRotate(t *testing.T) {
	dir := readerRecordFor(t, "atlas", "proj-test1")
	files := instanceFiles(t, dir, "atlas")
	out, errOut, code := farcastIn(t, dir, "reader", "init", "atlas", "--rotate")
	if want := "farcast: instance \"atlas\" has no reader identity to rotate; run 'farcast reader init atlas'\n"; code != 1 || out != "" || errOut != want {
		t.Errorf("no reader: exit %d, stdout %q, stderr %q; want %q", code, out, errOut, want)
	}
	sameFiles(t, "a refused rotate", files, instanceFiles(t, dir, "atlas"))

	if _, errOut, code := farcastIn(t, dir, "reader", "init", "atlas"); code != 0 {
		t.Fatal(errOut)
	}
	files = instanceFiles(t, dir, "atlas")
	out, errOut, code = farcastIn(t, dir, "reader", "init", "atlas", "--rotate")
	if want := "farcast: instance \"atlas\"'s reader key is not yet uploaded, so there is nothing to rotate; 'farcast reader init atlas' prints its script again\n"; code != 1 || out != "" || errOut != want {
		t.Errorf("not uploaded: exit %d, stdout %q, stderr %q; want %q", code, out, errOut, want)
	}
	sameFiles(t, "a refused rotate", files, instanceFiles(t, dir, "atlas"))

	if _, errOut, code := farcastIn(t, dir, "reader", "record", "atlas", "--key-id", readerTestKeyID); code != 0 {
		t.Fatal(errOut)
	}
	files = instanceFiles(t, dir, "atlas")
	out, errOut, code = farcastIn(t, dir, "reader", "init", "atlas", "--rotate", "--days", "90")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	sum := sha256.Sum256([]byte(out))
	if want := "Paste this into Cloud Shell as a project Owner (sha256 " + hex.EncodeToString(sum[:]) + "). It holds only the public certificate.\n"; errOut != want {
		t.Errorf("stderr %q; want %q", errOut, want)
	}
	after := instanceFiles(t, dir, "atlas")
	for _, f := range []string{"metadata.yaml", "reader.key", "reader.crt"} {
		if after[f] != files[f] {
			t.Errorf("--rotate changed %s", f)
		}
	}
	for _, f := range []string{"reader.key.next", "reader.crt.next"} {
		if after[f] == "" {
			t.Errorf("--rotate wrote no %s", f)
		}
		assertPerm(t, filepath.Join(dir.InstancePath("atlas"), f), 0o600)
	}
	if got := certOf(t, []byte(after["reader.crt.next"])); got.NotAfter.Sub(got.NotBefore) != 90*24*time.Hour {
		t.Errorf("--days 90 made a certificate valid for %v", got.NotAfter.Sub(got.NotBefore))
	}
	if !strings.HasPrefix(out, "sh -s <<'FARCAST_READER'\n# FarCast: a new key for the read-only identity of instance atlas (ADR 0023 M2).\n") {
		t.Errorf("--rotate printed something other than the rotate script:\n%s", out)
	}
}

// --days is a whole number from 1 to 3650; anything else is a usage error
// that writes nothing.
func TestReaderInitDaysBounds(t *testing.T) {
	for _, days := range []string{"0", "-1", "3651", "100000", "x", "1.5"} {
		dir := readerRecordFor(t, "atlas", "proj-test1")
		files := instanceFiles(t, dir, "atlas")
		out, errOut, code := farcastIn(t, dir, "reader", "init", "atlas", "--days", days)
		if code != 2 || out != "" {
			t.Errorf("--days %s: exit %d, stdout %q, stderr %q; want a usage error", days, code, out, errOut)
		}
		sameFiles(t, "--days "+days, files, instanceFiles(t, dir, "atlas"))
	}
	for _, days := range []int{1, 3650} {
		dir := readerRecordFor(t, "atlas", "proj-test1")
		if _, errOut, code := farcastIn(t, dir, "reader", "init", "atlas", "--days", fmt.Sprint(days)); code != 0 {
			t.Errorf("--days %d: %s", days, errOut)
			continue
		}
		if got := certOf(t, readFileOf(t, dir, "atlas", "reader.crt")); got.NotAfter.Sub(got.NotBefore) != time.Duration(days)*24*time.Hour {
			t.Errorf("--days %d made a certificate valid for %v", days, got.NotAfter.Sub(got.NotBefore))
		}
	}
	if _, errOut, code := farcastIn(t, readerRecordFor(t, "atlas", "proj-test1"), "reader", "init"); code != 2 {
		t.Errorf("no instance: exit %d (%s); want a usage error", code, errOut)
	}
}

// With --output json, init prints exactly {"instance","email","script",
// "script_sha256","script_kind"}, the script byte-equal to what human mode
// prints, and nothing on stderr.
func TestReaderInitJSON(t *testing.T) {
	dir := readerRecordFor(t, "atlas", "proj-test1")
	for _, kind := range []string{"init", "rotate"} {
		args := []string{"-o", "json", "reader", "init", "atlas"}
		if kind == "rotate" {
			if _, errOut, code := farcastIn(t, dir, "reader", "record", "atlas", "--key-id", readerTestKeyID); code != 0 {
				t.Fatal(errOut)
			}
			args = append(args, "--rotate")
		}
		out, errOut, code := farcastIn(t, dir, args...)
		if code != 0 || errOut != "" {
			t.Fatalf("%s: exit %d, stderr %q", kind, code, errOut)
		}
		var doc map[string]string
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("%s: %v\n%s", kind, err, out)
		}
		keys := make([]string, 0, len(doc))
		for k := range doc {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		if want := []string{"email", "instance", "script", "script_kind", "script_sha256"}; !slices.Equal(keys, want) {
			t.Errorf("%s: keys %q; want %q", kind, keys, want)
		}
		sum := sha256.Sum256([]byte(doc["script"]))
		if doc["instance"] != "atlas" || doc["email"] != readerEmail("atlas", "proj-test1") ||
			doc["script_kind"] != kind || doc["script_sha256"] != hex.EncodeToString(sum[:]) {
			t.Errorf("%s: %v", kind, doc)
		}
		if kind == "init" {
			human, _, code := farcastIn(t, dir, "reader", "init", "atlas")
			if code != 0 || human != doc["script"] {
				t.Errorf("the JSON script is not the one human mode prints:\n%s\n%s", doc["script"], human)
			}
		} else if !strings.Contains(doc["script"], "a new key for the read-only identity") {
			t.Errorf("rotate: %s", doc["script"])
		}
	}
}

// reader is a command group of the router, and its help names init, record
// and grant.
func TestReaderCommandIsRegistered(t *testing.T) {
	dir := readerRecordFor(t, "atlas", "proj-test1")
	out, _, code := farcastIn(t, dir, "help")
	if code != 0 || !strings.Contains(out, "  reader ") {
		t.Errorf("help does not list reader:\n%s", out)
	}
	out, _, code = farcastIn(t, dir, "help", "reader")
	if code != 0 || !strings.Contains(out, "Usage: farcast reader <init|record|grant>") {
		t.Errorf("help reader:\n%s", out)
	}
	for _, sub := range []string{"init", "record", "grant"} {
		if !strings.Contains(out, "\n  "+sub+" ") {
			t.Errorf("help reader does not name %s:\n%s", sub, out)
		}
	}
	if _, errOut, code := farcastIn(t, dir, "reader"); code != 2 || !strings.Contains(errOut, "reader requires a subcommand (grant, init, record)") {
		t.Errorf("reader alone: exit %d, %q", code, errOut)
	}
	// Since ADR 0023 M2.4 the read commands' cluster reads run as the reader,
	// and the help says which, and that the writing commands do not yet.
	if flat := strings.Join(strings.Fields(out), " "); !strings.Contains(flat, "The cluster reads of 'world', 'ps', 'costs', 'usage' and 'logs' run as it") ||
		!strings.Contains(flat, "The commands that write still run kubectl as the active gcloud configuration") ||
		strings.Contains(flat, "until then") {
		t.Errorf("help reader does not say which reads run as the reader:\n%s", out)
	}
}
