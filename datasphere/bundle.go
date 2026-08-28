package datasphere

import (
	"errors"
	"fmt"
	"strings"

	"github.com/goccy/go-yaml"
)

// bundleVersion is the wire schema of an unseal bundle.
const bundleVersion = 1

// ErrBundleInvalid reports a bundle that cannot be trusted.
var ErrBundleInvalid = errors.New("datasphere: invalid unseal bundle")

// Bundle is the key material an operator hands to an in-cluster keyholder.
//
// It carries scope keys and nothing else. The master KEK and the master name
// key are never in a bundle and never enter a cluster: name exposure is the
// one compromise this module's rotation ledger records as permanent, so the
// key that cannot be rotated is the key that must not leave the operator's
// machine.
//
// A bundle is therefore exactly as sensitive as what an unsealed keyholder
// already holds in RAM, and no more — which is the property that lets an
// automated keeper (5.4) push one without widening what a compromised cluster
// can yield. What a bundle does NOT carry is any means of reaching outside its
// own scopes.
//
// Its fields are unexported for the same reason KeyEntry's are: nothing
// outside this package may reach through the struct and print the material.
type Bundle struct {
	instance   string
	generation uint64
	scopes     []Scope
}

// NewBundle assembles the scopes an instance's keyholder should hold.
//
// Generation orders bundles. A keyholder refuses a generation older than the
// one it already holds, so a bundle captured before a rotation cannot be
// replayed to put retired keys back into service.
func NewBundle(instance string, generation uint64, scopes []Scope) (*Bundle, error) {
	if strings.TrimSpace(instance) == "" {
		return nil, fmt.Errorf("%w: bundle must name its instance", ErrBundleInvalid)
	}
	if len(scopes) == 0 {
		return nil, fmt.Errorf("%w: bundle carries no scopes", ErrBundleInvalid)
	}
	out := make([]Scope, 0, len(scopes))
	for _, s := range scopes {
		if err := s.Valid(); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrBundleInvalid, err)
		}
		for _, existing := range out {
			if existing.Name == s.Name {
				return nil, fmt.Errorf("%w: scope %q appears twice", ErrBundleInvalid, s.Name)
			}
			if scopesOverlap(existing.Prefix, s.Prefix) {
				return nil, fmt.Errorf("%w: scope %q prefix %q overlaps scope %q prefix %q",
					ErrBundleInvalid, s.Name, s.Prefix, existing.Name, existing.Prefix)
			}
		}
		out = append(out, s)
	}
	return &Bundle{instance: instance, generation: generation, scopes: out}, nil
}

// Instance is the instance this bundle was assembled for. A keyholder checks
// it, so a bundle meant for one instance cannot be pushed into another.
func (b *Bundle) Instance() string { return b.instance }

// Generation orders this bundle against others for the same instance.
func (b *Bundle) Generation() uint64 { return b.generation }

// Scopes returns the bundle's scopes. The slice is a copy; the key material
// inside it is not.
func (b *Bundle) Scopes() []Scope { return append([]Scope(nil), b.scopes...) }

// String renders the bundle without key material.
func (b *Bundle) String() string {
	names := make([]string, len(b.scopes))
	for i, s := range b.scopes {
		names[i] = s.Name
	}
	return fmt.Sprintf("Bundle{Instance:%s Generation:%d Scopes:[%s] Material:<redacted>}",
		b.instance, b.generation, strings.Join(names, " "))
}

// Zero overwrites the bundle's key material in place.
//
// This is hygiene, not a guarantee: Go's garbage collector may already have
// copied these bytes elsewhere, and on a cloud host the hypervisor can read
// the whole address space anyway. It shortens the window in which a
// no-longer-needed bundle sits in a live heap, which is worth doing on the one
// path that exists to move key material around.
func (b *Bundle) Zero() {
	for _, s := range b.scopes {
		s.Zero()
	}
	b.scopes = nil
}

// bundleFile is the bundle's wire shape. It reuses the keyring's scope
// encoding so that one parser, one validation path and one redaction
// discipline cover both the file at rest and the payload on the wire.
type bundleFile struct {
	Version    int         `yaml:"version"`
	Instance   string      `yaml:"instance"`
	Generation uint64      `yaml:"generation"`
	Scopes     []scopeFile `yaml:"scopes"`
}

// Marshal renders the bundle for the wire. The result is key material in the
// clear: every caller seals it before it leaves the process.
func (b *Bundle) Marshal() ([]byte, error) {
	if len(b.scopes) == 0 {
		return nil, fmt.Errorf("%w: bundle carries no scopes", ErrBundleInvalid)
	}
	out, err := yaml.Marshal(bundleFile{
		Version:    bundleVersion,
		Instance:   b.instance,
		Generation: b.generation,
		Scopes:     marshalScopes(b.scopes),
	})
	if err != nil {
		return nil, fmt.Errorf("datasphere: encode bundle: %w", err)
	}
	return out, nil
}

// ParseBundle reads a bundle. It validates before returning, so no caller ever
// holds a half-usable one.
func ParseBundle(data []byte) (*Bundle, error) {
	var file bundleFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		// The bundle is key material end to end, so the parser's own
		// message — which quotes a window of the source — must never
		// reach a log. Same rule as keys.yaml, and here every line is
		// sensitive rather than merely most of them.
		return nil, fmt.Errorf("%w: not valid YAML (the parser's message is withheld: it quotes the payload, which is key material)", ErrBundleInvalid)
	}
	if file.Version != bundleVersion {
		return nil, fmt.Errorf("%w: unsupported version %d (this build speaks %d)", ErrBundleInvalid, file.Version, bundleVersion)
	}
	scopes, err := parseScopes(file.Scopes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBundleInvalid, err)
	}
	return NewBundle(file.Instance, file.Generation, scopes)
}
