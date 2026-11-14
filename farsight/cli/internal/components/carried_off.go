//go:build !farcast_embedded

package components

// Embedded reports whether this farcast carries the components; a build without
// the farcast_embedded tag never does.
func Embedded() bool { return false }

// Artifacts returns the carried components, sorted by Name; nil when !Embedded().
func Artifacts() []Artifact { return nil }

// Lookup returns the carried component called name.
func Lookup(name string) (Artifact, bool) { return Artifact{}, false }

// Layer returns the carried layer of the component called name, verified
// against the compiled-in table.
func Layer(name string) ([]byte, error) { return nil, ErrNotEmbedded }

// Base is the base reference the manifests were assembled against; "" when
// !Embedded().
func Base() string { return "" }

// Revision is the source revision the components were built at; "" when
// unrecorded or !Embedded().
func Revision() string { return "" }

// Modified reports whether the components were built from a tree with
// uncommitted changes.
func Modified() bool { return false }
