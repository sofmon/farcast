// Package components names FarCast's four in-cluster components and, in a
// release build, carries their image layers and the digests they were released
// with (ADR 0023 decision 4).
//
// Behind the build tag farcast_embedded the package embeds layers/, which only
// farcast-release fills, through go build -overlay; the directory is git-ignored
// and never committed. Without the tag it carries nothing, and a plain
// go build ./... still compiles.
//
// It is a leaf: it imports neither image nor oci.
package components

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
)

// Component is one of FarCast's own in-cluster workloads: where its image lives
// in the instance registry, and what to compile if it is built from source.
type Component struct {
	Name       string // "datasphered", "fatline", "shrike", "technocore"
	ImagePath  string // "system/<Name>"
	Package    string // "./datasphere/cmd/datasphere", "./fatline/cmd/fatline", "./shrike/cmd/shrike", "./technocore/cmd/technocore"
	BinaryPath string // "/datasphere", "/fatline", "/shrike", "/technocore"
}

// The four components.
var (
	Datasphered = Component{Name: "datasphered", ImagePath: "system/datasphered", Package: "./datasphere/cmd/datasphere", BinaryPath: "/datasphere"}
	FatLine     = Component{Name: "fatline", ImagePath: "system/fatline", Package: "./fatline/cmd/fatline", BinaryPath: "/fatline"}
	Shrike      = Component{Name: "shrike", ImagePath: "system/shrike", Package: "./shrike/cmd/shrike", BinaryPath: "/shrike"}
	TechnoCore  = Component{Name: "technocore", ImagePath: "system/technocore", Package: "./technocore/cmd/technocore", BinaryPath: "/technocore"}
)

// All returns the four components, sorted by Name.
func All() []Component {
	all := []Component{Datasphered, FatLine, Shrike, TechnoCore}
	slices.SortFunc(all, func(a, b Component) int { return strings.Compare(a.Name, b.Name) })
	return all
}

// ByName returns the component called name.
func ByName(name string) (Component, bool) {
	for _, c := range All() {
		if c.Name == name {
			return c, true
		}
	}
	return Component{}, false
}

// Artifact is one component as this executable carries it (ADR 0023 decision 4).
type Artifact struct {
	Component
	GoVersion    string // "go1.27.4"
	BinarySHA256 string // 64 hex
	BinarySize   int64
	Layer        string // sha256:… of the gzip'd tar
	LayerSize    int64
	DiffID       string
	Config       string
	Manifest     string // what a deploy pins, and what the registry must echo
}

// ErrNotEmbedded reports that this farcast was built without the components.
var ErrNotEmbedded = errors.New("components: this farcast carries no components (a source build)")

// Table is the digest table's wire shape: shared with the release tool, which
// writes it.
type Table struct {
	Format     int     `json:"format"` // 1
	Go         string  `json:"go"`
	Base       string  `json:"base"`
	Platform   string  `json:"platform"` // "linux/amd64"
	Revision   string  `json:"revision"` // vcs.revision of the tree; "" from the 'layers' subcommand
	Modified   bool    `json:"modified"` // vcs.modified of the tree
	Components []Entry `json:"components"`
}

// Entry is one component's row in the Table.
type Entry struct {
	Name         string `json:"name"`
	Package      string `json:"package"`
	BinaryPath   string `json:"binary_path"`
	Go           string `json:"go"`
	BinarySHA256 string `json:"binary_sha256"`
	BinarySize   int64  `json:"binary_size"`
	Layer        string `json:"layer"`
	LayerSize    int64  `json:"layer_size"`
	DiffID       string `json:"diff_id"`
	Config       string `json:"config"`
	Manifest     string `json:"manifest"`
}

// The table's fixed values and the shapes of its fields.
const (
	tableFormat   = 1
	tablePlatform = "linux/amd64"
)

var (
	digestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	hex64Pattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	revisionPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
)

// ParseTable decodes a digest table strictly: unknown fields, trailing data, and
// any value outside the release tool's shape are refused. It refuses a format
// other than 1, a platform other than linux/amd64, an empty go or base, a
// revision that is neither empty nor 40 or 64 lowercase hex characters, a set of
// names other than exactly the four, a package or binary_path that differs from
// ByName, an entry go that differs from the top-level go, a digest that is not
// sha256:<64 hex>, a binary_sha256 that is not 64 hex characters, and a size
// that is not positive.
func ParseTable(data []byte) (Table, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var t Table
	if err := dec.Decode(&t); err != nil {
		return Table{}, fmt.Errorf("components: decode the digest table: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Table{}, errors.New("components: the digest table has data after its one object")
	}
	switch {
	case t.Format != tableFormat:
		return Table{}, fmt.Errorf("components: the digest table is format %d, not %d", t.Format, tableFormat)
	case t.Platform != tablePlatform:
		return Table{}, fmt.Errorf("components: the digest table is for %q, not %s", t.Platform, tablePlatform)
	case t.Go == "":
		return Table{}, errors.New("components: the digest table names no Go release")
	case t.Base == "":
		return Table{}, errors.New("components: the digest table names no base image")
	case t.Revision != "" && !revisionPattern.MatchString(t.Revision):
		return Table{}, fmt.Errorf("components: the digest table's revision %q is not a full commit hash", t.Revision)
	}

	seen := map[string]bool{}
	for _, e := range t.Components {
		c, ok := ByName(e.Name)
		if !ok {
			return Table{}, fmt.Errorf("components: the digest table lists %q, which is not a FarCast component", e.Name)
		}
		if seen[e.Name] {
			return Table{}, fmt.Errorf("components: the digest table lists %s twice", e.Name)
		}
		seen[e.Name] = true
		switch {
		case e.Package != c.Package:
			return Table{}, fmt.Errorf("components: the digest table builds %s from %q, not %s", e.Name, e.Package, c.Package)
		case e.BinaryPath != c.BinaryPath:
			return Table{}, fmt.Errorf("components: the digest table puts %s at %q, not %s", e.Name, e.BinaryPath, c.BinaryPath)
		case e.Go != t.Go:
			return Table{}, fmt.Errorf("components: the digest table built %s with %q, not the table's %s", e.Name, e.Go, t.Go)
		case !hex64Pattern.MatchString(e.BinarySHA256):
			return Table{}, fmt.Errorf("components: %s's binary_sha256 %q is not 64 hex characters", e.Name, e.BinarySHA256)
		case e.BinarySize <= 0:
			return Table{}, fmt.Errorf("components: %s's binary_size %d is not positive", e.Name, e.BinarySize)
		case e.LayerSize <= 0:
			return Table{}, fmt.Errorf("components: %s's layer_size %d is not positive", e.Name, e.LayerSize)
		}
		for _, f := range [...]struct{ field, digest string }{
			{"layer", e.Layer}, {"diff_id", e.DiffID}, {"config", e.Config}, {"manifest", e.Manifest},
		} {
			if !digestPattern.MatchString(f.digest) {
				return Table{}, fmt.Errorf("components: %s's %s %q is not sha256:<64 hex>", e.Name, f.field, f.digest)
			}
		}
	}
	if len(seen) != len(All()) {
		return Table{}, fmt.Errorf("components: the digest table lists %d components, not the %d", len(seen), len(All()))
	}
	return t, nil
}

// EncodeTable is json.MarshalIndent(t, "", "  ") + "\n", with the components
// sorted by name. The input is not modified.
func EncodeTable(t Table) ([]byte, error) {
	t.Components = slices.Clone(t.Components)
	slices.SortFunc(t.Components, func(a, b Entry) int { return strings.Compare(a.Name, b.Name) })
	out, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("components: encode the digest table: %w", err)
	}
	return append(out, '\n'), nil
}
