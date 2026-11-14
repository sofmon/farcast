package release

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// GO_LICENSE and GO_PATENTS are the Go project's LICENSE and PATENTS, copied
// from the cached golang.org/toolchain@v0.0.1-go1.27.4.darwin-arm64 (Homebrew's
// GOROOT has no LICENSE). Their hashes are pinned so that an edit to either is a
// deliberate, reviewed change.
var (
	//go:embed GO_LICENSE
	goLicense []byte
	//go:embed GO_PATENTS
	goPatents []byte
)

const (
	goLicenseSHA256 = "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad"
	goPatentsSHA256 = "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc"
)

// licencePrefixes are the upper-cased base-name prefixes of the files a module's
// notice block carries.
var licencePrefixes = []string{"AUTHORS", "CONTRIBUTORS", "COPYLEFT", "COPYING", "COPYRIGHT", "LEGAL", "LICENSE", "LICENCE", "NOTICE", "PATENTS"}

// vendoredModule is one "# <path> <version>" line of vendor/modules.txt.
type vendoredModule struct{ path, version string }

// Notices writes THIRD_PARTY_NOTICES for the checkout at src to w: the Go
// toolchain's licence and every vendored module's licence files, in
// vendor/modules.txt order. It needs no particular Go: it reads go.mod's
// toolchain line for the version it names.
func Notices(src string, w io.Writer) error {
	if err := checkGoLicence(); err != nil {
		return err
	}
	pin, err := Pin(src)
	if err != nil {
		return err
	}
	mods, err := readModules(filepath.Join(src, "vendor", "modules.txt"))
	if err != nil {
		return err
	}
	if err := checkLicenceTable(mods); err != nil {
		return err
	}

	var b bytes.Buffer
	b.WriteString(noticesHeader(mods))
	b.WriteString("\n")
	fmt.Fprintf(&b, "Go %s (BSD-3-Clause)\n", pin)
	b.WriteString("--- LICENSE\n")
	writeLF(&b, goLicense)
	b.WriteString("--- PATENTS\n")
	writeLF(&b, goPatents)

	roots := make([]string, 0, len(mods))
	for _, m := range mods {
		roots = append(roots, m.path)
	}
	for _, m := range mods {
		files, err := licenceFiles(src, m.path, roots)
		if err != nil {
			return err
		}
		if len(files) == 0 {
			return fmt.Errorf("release: vendor/%s holds no licence file", m.path)
		}
		b.WriteString("\n")
		fmt.Fprintf(&b, "%s %s (%s)\n", m.path, m.version, moduleLicences[m.path])
		for _, rel := range files {
			data, err := os.ReadFile(filepath.Join(src, filepath.FromSlash(rel)))
			if err != nil {
				return fmt.Errorf("release: %w", err)
			}
			fmt.Fprintf(&b, "--- %s\n", rel)
			writeLF(&b, data)
		}
	}
	_, err = w.Write(b.Bytes())
	return err
}

// noticesHeader is the file's fixed opening: what it is, how it is made, and the
// licence counts, computed from the table.
func noticesHeader(mods []vendoredModule) string {
	counts := map[string]int{}
	for _, m := range mods {
		counts[moduleLicences[m.path]]++
	}
	ids := make([]string, 0, len(counts))
	for id := range counts {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	var list []string
	for _, id := range ids {
		list = append(list, fmt.Sprintf("%s %d", id, counts[id]))
	}
	return fmt.Sprintf(`THIRD_PARTY_NOTICES for Sofmon FarCast

This file holds the licence and notice texts of the third-party code that
FarCast's executables contain. It ships beside farcast, which carries FarCast's
four components (datasphered, fatline, shrike and technocore); the component
layers themselves carry no notices file.

It is generated, never edited by hand:

    go run ./farsight/cli/cmd/farcast-release notices -o THIRD_PARTY_NOTICES

from vendor/modules.txt and go.mod's toolchain line. ./check.sh fails when the
committed file differs from what they give.

What each executable contains:
- every farcast, and every component, contains the Go runtime and standard
  library, under the Go licence below;
- farcast contains all %d vendored modules below;
- each component contains a subset of them.

The vendored modules, by licence: %s.

Each block below names a module, its version and its licence, followed by every
licence-like file in its vendor/ directory, verbatim.
`, len(mods), strings.Join(list, ", "))
}

// checkGoLicence verifies the embedded Go licence files against their pins.
func checkGoLicence() error {
	for _, f := range []struct {
		name string
		data []byte
		want string
	}{{"GO_LICENSE", goLicense, goLicenseSHA256}, {"GO_PATENTS", goPatents, goPatentsSHA256}} {
		sum := sha256.Sum256(f.data)
		if got := hex.EncodeToString(sum[:]); got != f.want {
			return fmt.Errorf("release: %s hashes to %s, not the pinned %s", f.name, got, f.want)
		}
	}
	return nil
}

// readModules lists vendor/modules.txt's modules, in its order.
func readModules(path string) ([]vendoredModule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("release: %w", err)
	}
	var mods []vendoredModule
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "# ") {
			continue
		}
		f := strings.Fields(strings.TrimPrefix(line, "# "))
		if len(f) != 2 {
			return nil, fmt.Errorf("release: vendor/modules.txt line %q is not \"# <module> <version>\" (a replacement or a local module is not handled)", line)
		}
		mods = append(mods, vendoredModule{path: f[0], version: f[1]})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("release: read vendor/modules.txt: %w", err)
	}
	if len(mods) == 0 {
		return nil, errors.New("release: vendor/modules.txt lists no modules")
	}
	return mods, nil
}

// checkLicenceTable refuses a module with no classified licence, and a
// classification for a module that is not vendored.
func checkLicenceTable(mods []vendoredModule) error {
	listed := map[string]bool{}
	for _, m := range mods {
		listed[m.path] = true
		if moduleLicences[m.path] == "" {
			return fmt.Errorf("release: vendored module %s has no licence in licences.go; classify it there", m.path)
		}
	}
	for p := range moduleLicences {
		if !listed[p] {
			return fmt.Errorf("release: licences.go classifies %s, which vendor/modules.txt does not list", p)
		}
	}
	return nil
}

// licenceFiles lists module's licence-like files, as repository-relative paths
// in byte order. A subtree that is another vendored module's root belongs to
// that module and is skipped.
func licenceFiles(src, module string, roots []string) ([]string, error) {
	root := filepath.Join(src, "vendor", filepath.FromSlash(module))
	var files []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(filepath.Join(src, "vendor"), p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel != module && slices.Contains(roots, rel) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || !isLicenceName(d.Name()) {
			return nil
		}
		files = append(files, path.Join("vendor", rel))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("release: list the licence files of %s: %w", module, err)
	}
	slices.Sort(files)
	return files, nil
}

func isLicenceName(name string) bool {
	upper := strings.ToUpper(name)
	for _, p := range licencePrefixes {
		if strings.HasPrefix(upper, p) {
			return true
		}
	}
	return false
}

// writeLF writes data verbatim, with one LF added if it does not end in one.
func writeLF(b *bytes.Buffer, data []byte) {
	b.Write(data)
	if len(data) == 0 || data[len(data)-1] != '\n' {
		b.WriteByte('\n')
	}
}
