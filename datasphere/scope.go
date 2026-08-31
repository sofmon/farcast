package datasphere

import (
	"fmt"
	"strings"
	"time"

	"github.com/sofmon/farcast/datasphere/internal/crypto"
)

// ScopePrefixSuffix is the separator every scope prefix ends with. A scope
// owns a whole subtree, never a partial segment: without the trailing
// separator a scope named "app" would also claim "application/…".
const ScopePrefixSuffix = "/"

// Scope is a named slice of an instance's storage that carries its own key
// material.
//
// It exists so that key material can reach a cluster without the master keys
// reaching it too. The in-cluster keyholder is given one scope's keys; it can
// read and write that subtree and is cryptographically incapable of touching
// anything else, because objects outside the scope are tokenized under a
// different name key (it cannot even compute their stored names) and wrapped
// under a different KEK (it could not unwrap them if it could).
//
// A scope's keys are minted independently rather than derived from the master.
// That is deliberate for 3.2: [ADR 0008] specifies a stored-prefix derivation
// but freezes it at 4.x, after golden vectors and an independent
// reproduction — and shipping an unreproduced derivation over real data at
// rest is exactly what this module's discipline forbids. Minted keys reach the
// same place (no master in the cluster, scope compromise bounded and
// rotatable) while adding nothing new at rest, so 4.x can introduce derived
// scopes beside these without invalidating a byte. Derivation records which
// shape produced a scope; it is empty for every scope 3.2 mints.
//
// [ADR 0008]: ../docs/adr/0008-in-cluster-key-delivery.md
type Scope struct {
	// Name identifies the scope within the keyring.
	Name string
	// Prefix is the logical key subtree the scope owns, ending in "/".
	Prefix string
	// Created is when the scope was minted.
	Created time.Time
	// Derivation names the scheme that produced this scope's keys. Empty
	// means minted from crypto/rand — every 3.2 scope. 4.x records a KDF
	// label here, so a scope's own record says how to reproduce it.
	Derivation string

	keys Keyring
}

// NewScope mints a scope with its own name key and key-encryption key.
//
// Whatever persists the result carries KeyLossWarning: a scope's keys are as
// unrecoverable as the master's, and the data under its prefix is exactly as
// lost without them.
func NewScope(name, prefix string) (Scope, error) {
	if err := ValidateScopeName(name); err != nil {
		return Scope{}, err
	}
	if err := ValidateScopePrefix(prefix); err != nil {
		return Scope{}, err
	}
	keys, err := NewKeyring()
	if err != nil {
		return Scope{}, err
	}
	return Scope{Name: name, Prefix: prefix, Created: keyNow(), keys: keys}, nil
}

// Keyring returns the scope's own key material.
//
// This is what makes a scope usable without a second encryption path: the
// result goes straight to NewStore, so a scoped Store is an ordinary Store
// that happens to hold different keys. Blob format, name tokenization and
// every byte at rest are untouched.
func (s Scope) Keyring() Keyring { return s.keys }

// Owns reports whether a logical key falls inside the scope.
func (s Scope) Owns(key string) bool { return strings.HasPrefix(key, s.Prefix) }

// Valid reports whether the scope is usable.
func (s Scope) Valid() error {
	if err := ValidateScopeName(s.Name); err != nil {
		return err
	}
	if err := ValidateScopePrefix(s.Prefix); err != nil {
		return err
	}
	return s.keys.Valid()
}

// String renders the scope without key material, so an accidentally logged
// scope cannot expose the keys to the data under it.
func (s Scope) String() string {
	return fmt.Sprintf("Scope{Name:%s Prefix:%s Derivation:%q Keys:%s}",
		s.Name, s.Prefix, s.Derivation, s.keys)
}

// Zero overwrites the scope's key material in place.
//
// This is hygiene rather than a guarantee: the garbage collector may already
// have copied these bytes, and on a cloud host the hypervisor can read the
// whole address space regardless. It shortens the window in which material
// this process no longer needs is still sitting in a live heap, which is worth
// doing wherever key material stops being needed.
func (s Scope) Zero() {
	for _, e := range s.keys.nameKeys {
		clear(e.key)
	}
	for _, e := range s.keys.keys {
		clear(e.key)
	}
}

// Clone returns a scope holding its OWN copy of the key material.
//
// Scope values share their key bytes when copied — a Scope is a struct of
// slices, so assigning one aliases the material rather than duplicating it.
// That is what makes Zero effective across every holder of a scope, and it is
// exactly why anything that intends to OUTLIVE the value it was given must
// clone first. A holder that skipped this keeps serving from bytes its
// provider is entitled to wipe, and the failure is silent: encryption and
// decryption stay self-consistent against the zeroed key, so the data looks
// fine from inside and is readable by anyone from outside.
func (s Scope) Clone() Scope {
	out := s
	out.keys = Keyring{
		nameKeys: cloneEntries(s.keys.nameKeys),
		keys:     cloneEntries(s.keys.keys),
	}
	return out
}

func cloneEntries(entries []KeyEntry) []KeyEntry {
	out := make([]KeyEntry, len(entries))
	for i, e := range entries {
		out[i] = KeyEntry{ID: e.ID, Created: e.Created, key: append([]byte(nil), e.key...)}
	}
	return out
}

// Zeroed reports whether this scope's material has been wiped.
//
// It answers a boolean and never exposes a byte, so it is safe for a
// keyholder to assert its own invariants with — and it is what lets a package
// that cannot see key material still prove that a seal actually forgot it,
// rather than merely stopping to mention it.
func (s Scope) Zeroed() bool {
	for _, e := range s.keys.nameKeys {
		if !allZeroBytes(e.key) {
			return false
		}
	}
	for _, e := range s.keys.keys {
		if !allZeroBytes(e.key) {
			return false
		}
	}
	return true
}

func allZeroBytes(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// ValidateScopeName enforces the scope-name rules: non-empty, at most 63
// bytes, lowercase alphanumerics and dashes, starting with a letter. The
// name reaches Kubernetes object names and DNS labels, so it is bounded by
// the strictest consumer rather than by this package's own needs.
func ValidateScopeName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: scope name must not be empty", ErrKeyringInvalid)
	}
	if len(name) > 63 {
		return fmt.Errorf("%w: scope name must be at most 63 bytes, got %d", ErrKeyringInvalid, len(name))
	}
	if name[0] < 'a' || name[0] > 'z' {
		return fmt.Errorf("%w: scope name must start with a lowercase letter", ErrKeyringInvalid)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
		if !ok {
			return fmt.Errorf("%w: scope name may use only lowercase letters, digits and dashes", ErrKeyringInvalid)
		}
	}
	return nil
}

// ValidateScopePrefix enforces that a prefix is a whole-subtree logical key
// prefix: the logical-key rules apply to the part before the trailing
// separator, and the separator is required.
func ValidateScopePrefix(prefix string) error {
	if !strings.HasSuffix(prefix, ScopePrefixSuffix) {
		return fmt.Errorf("%w: scope prefix must end in %q so it owns a whole subtree", ErrKeyringInvalid, ScopePrefixSuffix)
	}
	base := strings.TrimSuffix(prefix, ScopePrefixSuffix)
	if err := crypto.ValidateLogicalKey(base); err != nil {
		return fmt.Errorf("%w: scope prefix %w", ErrKeyringInvalid, err)
	}
	return nil
}

// scopesOverlap reports whether two prefixes claim any common key. Nesting is
// refused rather than ordered: a key inside both would be addressable under
// two different name keys, so it would exist twice with neither copy visible
// from the other scope.
func scopesOverlap(a, b string) bool {
	return strings.HasPrefix(a, b) || strings.HasPrefix(b, a)
}
