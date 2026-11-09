package keyholder

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/sofmon/farcast/datasphere"
)

// The in-cluster key pin (ADR 0008 finding 4).
//
// A keyholder that restarts holds nothing, so before the pin it had nothing to
// compare a bundle against: a keeper enrolled before a rotation re-seeded the
// old keys into a fleet that had restarted all at once, and only the keeper's
// own check — which needs a serving replica to compare with — stood in the way.
// The pin is the reference that survives a restart. The operator's machine
// writes it into a ConfigMap whenever its keyring gains or retires a key, and
// every replica reads it when it starts and refuses a bundle the pin does not
// admit.
//
// It is two flat sets of key-encryption-key IDs and nothing else. A key ID is a
// random label, not a function of any key (ADR 0008 decision 3), and it already
// sits in plaintext in every object the cloud stores, so resting the set in
// etcd hands the cloud no key-check oracle. Scope NAMES are deliberately not in
// it: a map from scope to IDs would tell a cold reader of the cluster's backups
// which application owns which family of stored objects.
//
// The limit is the label's. An ID names a key; it does not commit to one. A
// bundle carrying a key of its own making under a pinned ID is admitted, so the
// pin binds stale material pushed as it was issued, not a forged bundle. What
// binds a keeper to the exact bundle it was enrolled with is its leaf
// (BundleDigestURI), not this.

// EnvKeyPin is the environment variable datasphered reads its pin from. It is
// filled from the pin ConfigMap through an optional configMapKeyRef, so it is
// read when the container starts; a running replica takes a new pin through
// the control surface instead (Vault.RaisePin).
const EnvKeyPin = "DATASPHERED_KEY_PIN"

// PinVersion is the only pin format this build reads.
const PinVersion = 1

// MaxPinBytes caps a pin. It is set by how the pin arrives: as one
// environment value, which Linux bounds at 128 KiB including its name. At 19
// bytes an ID, about 6,000 IDs fit — every KEK required and most retired, so
// roughly 3,000 key-encryption keys across all scopes, which is scopes times
// rotations. The CLI refuses to write a pin past it rather than leave every
// replica unable to read the one it has.
const MaxPinBytes = 120 << 10

// Pin is the set of key-encryption-key IDs a bundle must hold (Require) and
// the IDs no scope may write under (Retired).
type Pin struct {
	Require []datasphere.KeyID
	Retired []datasphere.KeyID
}

// PinStatus is what a replica made of the pin it was given.
type PinStatus string

const (
	// PinAbsent is no pin at all: a legacy instance, or a ConfigMap someone
	// deleted. Nothing is checked, which is the behaviour before the pin.
	PinAbsent PinStatus = "absent"
	// PinValid is a pin that parsed. Every push is checked against it.
	PinValid PinStatus = "valid"
	// PinInvalid is a pin that did not parse. A keeper's re-seed is refused —
	// the automaton does not act without its guard — and a person's push is
	// admitted and reported, because a human path must never depend on
	// repairing a value that rests in the cloud (ADR 0008 decision 9).
	PinInvalid PinStatus = "invalid"
)

// PinReport is a replica's pin as the control surface reports it.
type PinReport struct {
	Status  PinStatus `json:"status"`
	Require []string  `json:"require,omitempty"`
	Retired []string  `json:"retired,omitempty"`
	Error   string    `json:"error,omitempty"`
	// ServingBelow is a replica serving keys its own pin would refuse: the
	// operator unsealed it past the pin deliberately, or a raise has overtaken
	// what it holds.
	ServingBelow bool `json:"serving_below,omitempty"`
}

// ErrBelowPin reports a bundle the pin refuses: it lacks a key the instance's
// keyring has, or writes under one the keyring retired.
var ErrBelowPin = errors.New("keyholder: bundle predates this instance's key pin")

// ErrPinUnreadable reports a re-seed refused because this replica could not
// parse its pin.
var ErrPinUnreadable = errors.New("keyholder: this replica's key pin is unreadable, so it accepts no re-seed")

type pinWire struct {
	Version int      `json:"version"`
	Require []string `json:"require"`
	Retired []string `json:"retired"`
}

// ParsePin reads a pin. Empty or whitespace-only is absent, not invalid.
// Fields this build does not know are ignored, so a newer CLI can add a
// constraint an older image enforces only as far as it understands.
func ParsePin(raw string) (Pin, bool, error) {
	if len(raw) > MaxPinBytes && strings.TrimSpace(raw) != "" {
		return Pin{}, true, fmt.Errorf("key pin is %d bytes, more than %d", len(raw), MaxPinBytes)
	}
	return ParsePinAnySize(raw)
}

// ParsePinAnySize is ParsePin without the size cap, for the operator's side:
// a well-formed pin that grew past what a replica reads is still the pin, and
// must still be compared with and never lowered as if it were corrupt.
func ParsePinAnySize(raw string) (Pin, bool, error) {
	if strings.TrimSpace(raw) == "" {
		return Pin{}, false, nil
	}
	var w pinWire
	if err := json.Unmarshal([]byte(raw), &w); err != nil {
		return Pin{}, true, fmt.Errorf("key pin is not JSON: %w", err)
	}
	if w.Version != PinVersion {
		return Pin{}, true, fmt.Errorf("key pin is version %d; this build reads %d", w.Version, PinVersion)
	}
	var p Pin
	var err error
	if p.Require, err = parseIDs(w.Require); err != nil {
		return Pin{}, true, fmt.Errorf("key pin require: %w", err)
	}
	if p.Retired, err = parseIDs(w.Retired); err != nil {
		return Pin{}, true, fmt.Errorf("key pin retired: %w", err)
	}
	return p, true, nil
}

func parseIDs(in []string) ([]datasphere.KeyID, error) {
	out := make([]datasphere.KeyID, 0, len(in))
	for _, s := range in {
		id, err := datasphere.ParseKeyID(s)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return canonIDs(out), nil
}

// canonIDs sorts and deduplicates, so two pins that admit the same bundles
// marshal to the same bytes.
func canonIDs(ids []datasphere.KeyID) []datasphere.KeyID {
	out := slices.Clone(ids)
	slices.SortFunc(out, func(a, b datasphere.KeyID) int { return strings.Compare(a.String(), b.String()) })
	return slices.Compact(out)
}

func idStrings(ids []datasphere.KeyID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

// Marshal renders the pin canonically: one line, sorted, both arrays always
// present.
func (p Pin) Marshal() string {
	b, err := json.Marshal(pinWire{
		Version: PinVersion,
		Require: idStrings(canonIDs(p.Require)),
		Retired: idStrings(canonIDs(p.Retired)),
	})
	if err != nil {
		// A struct of strings and an int cannot fail to marshal.
		panic(err)
	}
	return string(b)
}

// Union is a pin that admits only what both admit.
func (p Pin) Union(o Pin) Pin {
	return Pin{
		Require: canonIDs(append(slices.Clone(p.Require), o.Require...)),
		Retired: canonIDs(append(slices.Clone(p.Retired), o.Retired...)),
	}
}

// Equal reports whether two pins admit exactly the same bundles.
func (p Pin) Equal(o Pin) bool {
	return slices.Equal(canonIDs(p.Require), canonIDs(o.Require)) &&
		slices.Equal(canonIDs(p.Retired), canonIDs(o.Retired))
}

// Admits checks a set of held keys against the pin: scope to hex key IDs, the
// active one first — the shape of State.Keys.
//
// It is IDs only by construction, so the vault, the CLI and a keeper all apply
// the same rule to the same data.
func (p Pin) Admits(keys map[string][]string) error {
	held := map[string]bool{}
	for _, ids := range keys {
		for _, id := range ids {
			held[id] = true
		}
	}
	for _, id := range canonIDs(p.Require) {
		if !held[id.String()] {
			return fmt.Errorf("%w: it lacks key %s", ErrBelowPin, id)
		}
	}
	retired := map[string]bool{}
	for _, id := range p.Retired {
		retired[id.String()] = true
	}
	scopes := make([]string, 0, len(keys))
	for name := range keys {
		scopes = append(scopes, name)
	}
	slices.Sort(scopes)
	for _, name := range scopes {
		if ids := keys[name]; len(ids) > 0 && retired[ids[0]] {
			return fmt.Errorf("%w: scope %s writes under retired key %s", ErrBelowPin, name, ids[0])
		}
	}
	return nil
}

// KeysOf is a bundle's keys in the shape Admits reads.
func KeysOf(b *datasphere.Bundle) map[string][]string {
	keys := make(map[string][]string, len(b.Scopes()))
	for _, s := range b.Scopes() {
		keks := s.Keyring().KEKs()
		ids := make([]string, len(keks))
		for i, e := range keks {
			ids[i] = e.ID.String()
		}
		keys[s.Name] = ids
	}
	return keys
}

// ErrPinInvalid reports a pin offered to the raise route that did not parse.
var ErrPinInvalid = errors.New("keyholder: the key pin offered is not valid")
