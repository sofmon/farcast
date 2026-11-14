//go:build farcast_embedded

package components

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
)

// The layers and their table are never committed: farcast-release supplies them
// with go build -overlay. The names are explicit, so a tagged build with a file
// missing fails to compile.
//
//go:embed layers/digests.json
var digestsJSON []byte

//go:embed layers/datasphered.tar.gz layers/fatline.tar.gz layers/shrike.tar.gz layers/technocore.tar.gz
var layerFS embed.FS

// table is the compiled-in digest table, parsed once at start.
var table Table

func init() {
	t, err := ParseTable(digestsJSON)
	if err != nil {
		panic(fmt.Sprintf("components: the table this farcast was built with is invalid: %v", err))
	}
	table = t
}

// Embedded reports whether this farcast carries the components; a build with
// the farcast_embedded tag always does.
func Embedded() bool { return true }

// Artifacts returns the carried components, sorted by Name.
func Artifacts() []Artifact {
	out := make([]Artifact, 0, len(table.Components))
	for _, e := range table.Components {
		c, ok := ByName(e.Name)
		if !ok {
			continue // ParseTable admits exactly the four names
		}
		out = append(out, Artifact{
			Component:    c,
			GoVersion:    e.Go,
			BinarySHA256: e.BinarySHA256,
			BinarySize:   e.BinarySize,
			Layer:        e.Layer,
			LayerSize:    e.LayerSize,
			DiffID:       e.DiffID,
			Config:       e.Config,
			Manifest:     e.Manifest,
		})
	}
	slices.SortFunc(out, func(a, b Artifact) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// Lookup returns the carried component called name.
func Lookup(name string) (Artifact, bool) {
	for _, a := range Artifacts() {
		if a.Name == name {
			return a, true
		}
	}
	return Artifact{}, false
}

// Layer returns the carried layer of the component called name, verified: its
// sha256 and size against the compiled-in table.
func Layer(name string) ([]byte, error) {
	a, ok := Lookup(name)
	if !ok {
		return nil, fmt.Errorf("components: this farcast carries no component %q", name)
	}
	data, err := layerFS.ReadFile("layers/" + a.Name + ".tar.gz")
	if err != nil {
		return nil, fmt.Errorf("components: read the carried %s layer: %w", a.Name, err)
	}
	sum := sha256.Sum256(data)
	if got := "sha256:" + hex.EncodeToString(sum[:]); got != a.Layer || int64(len(data)) != a.LayerSize {
		return nil, fmt.Errorf("components: the carried %s layer is %s (%d bytes), not the %s (%d bytes) this farcast was built with",
			a.Name, got, len(data), a.Layer, a.LayerSize)
	}
	return data, nil
}

// Base is the base reference the manifests were assembled against.
func Base() string { return table.Base }

// Revision is the source revision the components were built at; "" when
// unrecorded.
func Revision() string { return table.Revision }

// Modified reports whether the components were built from a tree with
// uncommitted changes.
func Modified() bool { return table.Modified }
