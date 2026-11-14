package release

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/image"
)

// notices generates THIRD_PARTY_NOTICES for this checkout.
func notices(t *testing.T) (string, string) {
	t.Helper()
	src, err := image.FindSource("")
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := Notices(src, &b); err != nil {
		t.Fatal(err)
	}
	return src, b.String()
}

// block is the text of one module's block, from its heading to the next blank
// line that precedes a heading.
func block(t *testing.T, text, module string) string {
	t.Helper()
	start := strings.Index(text, "\n"+module+" ")
	if start < 0 {
		t.Fatalf("no block for %s", module)
	}
	rest := text[start+1:]
	// Blocks are separated by an empty line followed by a heading; licence
	// texts contain empty lines too, so cut at the next module heading.
	end := len(rest)
	for m := range moduleLicences {
		if m == module {
			continue
		}
		if i := strings.Index(rest, "\n\n"+m+" v"); i >= 0 && i < end {
			end = i
		}
	}
	return rest[:end]
}

func TestNoticesCoverEveryVendoredModule(t *testing.T) {
	src, text := notices(t)
	mods, err := readModules(filepath.Join(src, "vendor", "modules.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) != 31 {
		t.Fatalf("vendor/modules.txt lists %d modules; the header and this test say 31", len(mods))
	}
	for _, m := range mods {
		if !strings.Contains(text, "\n"+m.path+" "+m.version+" ("+moduleLicences[m.path]+")\n") {
			t.Errorf("no heading for %s %s", m.path, m.version)
		}
	}
	if !strings.Contains(text, "Apache-2.0 18, BSD-3-Clause 10, MIT 3") {
		t.Error("the header's licence counts are not Apache-2.0 18, BSD-3-Clause 10, MIT 3")
	}
	pin, err := Pin(src)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "\nGo "+pin+" (BSD-3-Clause)\n--- LICENSE\n") || !strings.Contains(text, "\n--- PATENTS\n") {
		t.Error("the Go block is missing")
	}

	// Every licence-like file under vendor/ is in the file, found here
	// independently of the generator's own prefix list.
	prefixes := []string{"AUTHORS", "CONTRIBUTORS", "COPYLEFT", "COPYING", "COPYRIGHT", "LEGAL", "LICENSE", "LICENCE", "NOTICE", "PATENTS"}
	n := 0
	err = filepath.WalkDir(filepath.Join(src, "vendor"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		upper := strings.ToUpper(d.Name())
		for _, pre := range prefixes {
			if strings.HasPrefix(upper, pre) {
				rel, _ := filepath.Rel(src, p)
				n++
				if !strings.Contains(text, "\n--- "+filepath.ToSlash(rel)+"\n") {
					t.Errorf("%s is not in the notices", rel)
				}
				body, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				if !strings.Contains(text, string(body)) {
					t.Errorf("%s's text is not in the notices verbatim", rel)
				}
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(text, "\n--- vendor/"); got != n {
		t.Fatalf("the notices carry %d vendored files; vendor/ holds %d licence-like files", got, n)
	}
	for _, p := range []string{"golang.org/x/crypto/PATENTS", "google.golang.org/grpc/NOTICE.txt", "google.golang.org/api/AUTHORS"} {
		if !strings.Contains(text, "\n--- vendor/"+p+"\n") {
			t.Errorf("vendor/%s is missing", p)
		}
	}
	if strings.Contains(text, "\r") || !strings.HasSuffix(text, "\n") {
		t.Error("the notices are not LF text ending in a newline")
	}
}

func TestNoticesDoNotClaimNestedModules(t *testing.T) {
	_, text := notices(t)
	for module, nested := range map[string][]string{
		"google.golang.org/genproto": {"googleapis/api", "googleapis/rpc"},
		"cloud.google.com/go/auth":   {"oauth2adapt"},
		"go.opentelemetry.io/otel":   {"otel/metric", "otel/trace"},
	} {
		b := block(t, text, module)
		for _, n := range nested {
			if strings.Contains(b, n+"/") {
				t.Errorf("%s's block claims %s:\n%s", module, n, b[:min(len(b), 400)])
			}
		}
	}
}

func TestNoticesIncludeNestedLicences(t *testing.T) {
	_, text := notices(t)
	b := block(t, text, "google.golang.org/api")
	if !strings.Contains(b, "\n--- vendor/google.golang.org/api/internal/third_party/uritemplates/LICENSE\n") {
		t.Fatal("the uritemplates LICENSE is not in google.golang.org/api's block")
	}
}

func TestNoticesTableMatchesModules(t *testing.T) {
	src, err := image.FindSource("")
	if err != nil {
		t.Fatal(err)
	}
	mods, err := readModules(filepath.Join(src, "vendor", "modules.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := checkLicenceTable(mods); err != nil {
		t.Fatalf("the table does not match vendor/modules.txt: %v", err)
	}
	extra := append(mods[:len(mods):len(mods)], vendoredModule{path: "example.com/unclassified", version: "v1.0.0"})
	if err := checkLicenceTable(extra); err == nil || !strings.Contains(err.Error(), "example.com/unclassified") {
		t.Fatalf("a module missing from the table = %v, want it named", err)
	}
	if err := checkLicenceTable(mods[1:]); err == nil || !strings.Contains(err.Error(), mods[0].path) {
		t.Fatalf("a table entry missing from modules.txt = %v, want it named", err)
	}
}

func TestGoLicenceCopiesAreTheCommittedOnes(t *testing.T) {
	if err := checkGoLicence(); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"GO_LICENSE": goLicenseSHA256, "GO_PATENTS": goPatentsSHA256} {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Fatalf("%s hashes to %s, not the pinned %s", name, got, want)
		}
	}
	if !bytes.HasPrefix(goLicense, []byte("Copyright 2009 The Go Authors.")) || !bytes.Contains(goPatents, []byte("Additional IP Rights Grant (Patents)")) {
		t.Fatal("GO_LICENSE or GO_PATENTS is not the Go project's")
	}
}
