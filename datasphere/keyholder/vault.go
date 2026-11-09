// Package keyholder is the in-cluster process that holds DataSphere key
// material in memory and serves storage to an instance's applications.
//
// It exists because of one invariant: no entry of the keyring ever rests on
// cloud infrastructure. Key material therefore arrives by a push from the
// operator's own machine and lives only in this process's heap — never in a
// Kubernetes Secret, never on a volume, never on node disk. The consequence is
// stated rather than engineered away: a restarted keyholder comes back
// SEALED, and stays sealed until someone outside the cluster unseals it.
//
// That is not a gap to be closed later. A pod that could recover the key from
// cloud-resident state, by running cloud-supplied code on cloud-controlled
// hardware, would be a pod whose cloud can compute the same function — so a
// keyholder deliberately does not ask a peer, read a Secret, or unwrap
// anything the cloud could unwrap for itself. See ADR 0008.
package keyholder

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/sofmon/farcast/datasphere"
)

// Phase is the keyholder's seal state. The two sealed phases are deliberately
// distinct: one is the platform restarting a pod, the other is a person
// deciding storage should stop. Only the second is beyond an automated
// keeper's authority to clear.
type Phase string

const (
	// PhaseRestartSealed is a process that has never been unsealed, or one
	// whose material was dropped without a deliberate hold. A keeper (5.4)
	// may re-seed this.
	PhaseRestartSealed Phase = "restart-sealed"
	// PhaseUnsealed holds key material and serves storage.
	PhaseUnsealed Phase = "unsealed"
	// PhaseOperatorHold is a deliberate seal. Only an operator clears it.
	PhaseOperatorHold Phase = "operator-hold"
)

// Intent is what the pusher claims to be doing. It is carried on the wire from
// day one so that phase 5.4 adds a keeper driver rather than a new protocol.
//
// It is a claim, and the server no longer takes it on trust: which intents a
// caller may claim follows from the role on its leaf (Identity.MayPush).
type Intent string

const (
	// IntentOperator is a person unsealing. It may clear an operator hold.
	IntentOperator Intent = "operator-unseal"
	// IntentReseed is an unattended keeper restoring material after a
	// restart. It may never clear an operator hold — that is the whole
	// point of the distinction — and it only ever reaches a replica that is
	// sealed: a re-seed into a replica already serving would replace the keys
	// it serves with whatever the pusher holds, which is exactly what a lost
	// keeper's old bundle is.
	IntentReseed Intent = "restart-reseed"
	// IntentHandOver is the operator's machine giving keys to a replica that
	// is ALREADY serving: a new application's scope from `farcast run`, or
	// the rotated KEKs from `farcast storage key rotate`. It never unseals.
	//
	// It exists because pushing a bundle to a sealed replica IS an unseal, and
	// a deploy or a rotation must never perform one as a side effect. The CLI
	// used to enforce that by reading the state and then pushing with
	// operator-unseal — two round trips apart, with an intent the vault accepts
	// even under a hold. A replica that restarted, or was held, in between was
	// unsealed anyway. Refusing here makes the guarantee the keyholder's.
	//
	// Like an operator unseal into a serving replica, a hand-over adds keys or
	// moves which one is in use, and never takes one away (ErrWouldDrop).
	IntentHandOver Intent = "hand-over"
)

// Errors a caller maps onto the wire and, beyond it, onto SDK sentinels.
var (
	// ErrSealed reports that no key material is loaded.
	ErrSealed = errors.New("keyholder: sealed")
	// ErrOperatorHold reports an unseal refused because a person sealed
	// this keyholder deliberately and the pusher is not a person.
	ErrOperatorHold = errors.New("keyholder: sealed by the operator; a keeper may not clear an operator hold")
	// ErrGenerationTooOld reports a bundle older than what this process has
	// already held — the anti-rollback control that refuses a captured
	// pre-rotation bundle.
	ErrGenerationTooOld = errors.New("keyholder: bundle generation is older than the one already held")
	// ErrInstanceMismatch reports a bundle assembled for another instance.
	ErrInstanceMismatch = errors.New("keyholder: bundle names a different instance")
	// ErrNotServing reports a hand-over to a replica that is sealed. A
	// hand-over adds keys to a serving replica and never unseals one.
	ErrNotServing = errors.New("keyholder: a hand-over only reaches a replica that is already serving; this one is sealed")
	// ErrAlreadyServing reports a re-seed aimed at a replica that holds keys.
	// A re-seed restores a replica that restarted; it never replaces the keys
	// of one that is serving.
	ErrAlreadyServing = errors.New("keyholder: a re-seed only reaches a replica that restarted; this one is serving")
	// ErrWouldDrop reports a push to a SERVING replica whose bundle lacks a
	// scope, or a key-encryption key of a scope, that the replica holds. A
	// push adds keys or moves which one is in use; it never takes one away,
	// because whatever was written under it would become unreadable. Seal the
	// replica first to replace its keys deliberately.
	ErrWouldDrop = errors.New("keyholder: this replica serves a key or scope the bundle does not carry, and a push never takes one away — the pusher's keyring is behind the instance's; seal the replica first to replace its keys deliberately")
	// ErrOutOfScope reports a logical key outside every scope held.
	ErrOutOfScope = errors.New("keyholder: key is outside every scope this keyholder holds")
)

// State is a point-in-time view of the keyholder, safe to report to anyone who
// can reach the status endpoint. It carries scope names but never prefixes'
// contents and never key material.
type State struct {
	Phase      Phase
	Since      time.Time
	Generation uint64
	HoldReason string
	Scopes     []string

	// Boot identifies this keyholder PROCESS. See newBootID: it is what lets a
	// keeper fleet's ledgers be reconciled against how many times the cluster
	// actually restarted, and it is disclosed only on the control surface.
	Boot string

	// Keys lists, per scope held, the IDs of every key-encryption key the
	// scope holds, the active one — which wraps new writes — first. Disclosed
	// only on the control surface.
	//
	// It is what lets a pusher answer "does this replica hold the keys I
	// sent" exactly. The generation cannot: it counts pushes, and every
	// operator unseal advances it whether or not a single key changed. Every
	// ID and not only the active one, because a rotation reaches a fleet in
	// two steps — the new key held everywhere, then made active — and the
	// first step changes nothing a single active ID would show. The rekey gate
	// reads this before moving any object onto a rotated KEK, and a keeper
	// reads it to tell that its bundle predates a rotation.
	//
	// A key ID is not secret: it sits in plaintext at bytes 5-12 of every
	// object the cloud stores. It stays off the unauthenticated status surface
	// regardless, because nothing there needs it.
	Keys map[string][]string

	// Pin is the key pin this replica enforces. Disclosed only on the control
	// surface, like Keys.
	Pin PinReport
}

// Sealed reports whether storage is unavailable in this state.
func (s State) Sealed() bool { return s.Phase != PhaseUnsealed }

// Vault holds the process's key material and its seal state.
//
// The zero Vault is unusable; build one with New. Every method is safe for
// concurrent use: this is shared mutable state on the one process that holds
// the crown jewels, so it is guarded rather than merely assumed to be
// single-threaded.
type Vault struct {
	mu       sync.RWMutex
	instance string
	// boot is fixed for the life of the process and needs no lock; it is
	// stored here because this is what owns the process's seal identity.
	boot string

	phase      Phase
	since      time.Time
	holdReason string

	// generation is a high-water mark, not the current bundle's number. It
	// survives a seal so that sealing cannot be used to rewind a keyholder
	// onto retired key material.
	generation uint64
	scopes     []datasphere.Scope

	// pin is what every push is checked against; see pin.go. It is read once
	// at start and raised in place by the operator, never lowered by a push.
	pin       Pin
	pinStatus PinStatus
	pinErr    string

	now func() time.Time
}

// New returns a sealed vault. There is no constructor that returns an unsealed
// one: a keyholder always starts sealed, and the only way out is a push from
// outside the cluster.
func New(instance string) *Vault { return NewWithPin(instance, "") }

// NewWithPin returns a sealed vault that enforces a key pin. An empty pin is
// absent and checks nothing. A pin that does not parse does not stop the
// vault: a replica that refused to start could not be unsealed even by the
// operator, so it starts, refuses keepers, and reports why.
func NewWithPin(instance, rawPin string) *Vault {
	now := func() time.Time { return time.Now().UTC() }
	v := &Vault{
		instance:  instance,
		phase:     PhaseRestartSealed,
		since:     now(),
		now:       now,
		boot:      newBootID(),
		pinStatus: PinAbsent,
	}
	switch p, present, err := ParsePin(rawPin); {
	case err != nil:
		v.pinStatus, v.pinErr = PinInvalid, err.Error()
	case present:
		v.pin, v.pinStatus = p, PinValid
	}
	return v
}

// bootIDLen is the length of a process's boot label, in bytes.
const bootIDLen = 8

// newBootID mints the label that identifies THIS keyholder process.
//
// It is what makes a keeper's ledger reconcilable ([ADR 0008]'s finding 1,
// "detection by audit"). A keeper records the boot it seeded, so an auditor can
// compare reseeds against DISTINCT processes: one reseed per boot is a cluster
// restarting and a keeper doing its job, while two reseeds into the same boot
// means something asked for key material that a live process already held —
// which is what a solicited push looks like from the outside.
//
// It is a random label and nothing more. It is not derived from any key, it
// says nothing about what the process holds, and it changes on every restart
// by construction, because a restarted process is exactly what it exists to
// distinguish. It is served only on the mutually-authenticated control
// surface: the status endpoint is unauthenticated so that a kubelet can probe
// a sealed replica, and a restart counter is not something to hand out there.
//
// A failure to read the system CSPRNG yields an empty label rather than a dead
// keyholder. Reconciliation degrades to "cannot tell", which an auditor sees;
// refusing to start would turn a missing audit label into an outage, and this
// process's job is to hold keys.
func newBootID() string {
	b := make([]byte, bootIDLen)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// State reports the current phase.
func (v *Vault) State() State {
	v.mu.RLock()
	defer v.mu.RUnlock()
	names := make([]string, len(v.scopes))
	var keys map[string][]string
	for i, s := range v.scopes {
		names[i] = s.Name
		keks := s.Keyring().KEKs()
		ids := make([]string, len(keks))
		for j, e := range keks {
			ids[j] = e.ID.String()
		}
		if keys == nil {
			keys = make(map[string][]string, len(v.scopes))
		}
		keys[s.Name] = ids
	}
	return State{
		Phase:      v.phase,
		Since:      v.since,
		Generation: v.generation,
		HoldReason: v.holdReason,
		Scopes:     names,
		Boot:       v.boot,
		Keys:       keys,
		Pin:        v.pinReportLocked(keys),
	}
}

// pinReportLocked reports the pin. ServingBelow is worked out each time rather
// than remembered, so it also shows a replica that a later raise overtook.
func (v *Vault) pinReportLocked(keys map[string][]string) PinReport {
	r := PinReport{Status: v.pinStatus, Error: v.pinErr}
	if v.pinStatus == PinValid {
		r.Require = idStrings(v.pin.Require)
		r.Retired = idStrings(v.pin.Retired)
		r.ServingBelow = v.phase == PhaseUnsealed && v.pin.Admits(keys) != nil
	}
	return r
}

// RaisePin replaces what this replica enforces with the union of its pin and
// p, or with p alone when replace is set. It is how a running replica takes a
// pin the operator wrote after it started: the environment is read only once.
// A pin that was absent or unreadable becomes valid.
func (v *Vault) RaisePin(p Pin, replace bool) State {
	v.mu.Lock()
	if replace || v.pinStatus != PinValid {
		v.pin = Pin{Require: canonIDs(p.Require), Retired: canonIDs(p.Retired)}
	} else {
		v.pin = v.pin.Union(p)
	}
	v.pinStatus, v.pinErr = PinValid, ""
	v.mu.Unlock()
	return v.State()
}

// Ready reports whether the keyholder should receive application traffic. It
// is what the readiness probe answers, so a sealed replica is removed from the
// data Service and traffic goes to a loaded one.
func (v *Vault) Ready() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.phase == PhaseUnsealed
}

// Unseal installs a bundle's scopes.
//
// The checks are ordered so that the cheapest refusals that reveal nothing
// come first. Installation is atomic: the new scope set is built entirely
// before the old one is dropped, so no request ever observes a half-loaded
// vault. It replaces the whole set — but on a serving replica never removes
// anything from it (ErrWouldDrop); seal first to do that.
func (v *Vault) Unseal(b *datasphere.Bundle, intent Intent) error {
	return v.unseal(b, intent, false)
}

// UnsealBelowPin is an operator unseal that the key pin does not check. It is
// the way past a pin no keyring can satisfy any more — the keys it requires
// are gone everywhere — and it needs no cloud access, which is the point
// (ADR 0008 decision 9). Every other check still applies.
func (v *Vault) UnsealBelowPin(b *datasphere.Bundle) error {
	return v.unseal(b, IntentOperator, true)
}

func (v *Vault) unseal(b *datasphere.Bundle, intent Intent, belowPin bool) error {
	if b == nil {
		return fmt.Errorf("keyholder: nil bundle")
	}
	v.mu.Lock()
	defer v.mu.Unlock()

	if b.Instance() != v.instance {
		// Named on both sides: an operator who pushes prod's bundle at
		// staging needs to see which is which, and neither name is secret.
		return fmt.Errorf("%w: bundle is for %q, this keyholder serves %q",
			ErrInstanceMismatch, b.Instance(), v.instance)
	}
	// Before the hold check, so a hand-over's refusal always says the same
	// thing: this replica is not serving, and a hand-over does not change that.
	if intent == IntentHandOver && v.phase != PhaseUnsealed {
		return fmt.Errorf("%w (phase %s)", ErrNotServing, v.phase)
	}
	// The mirror image. Without it a keeper could push its bundle into a
	// replica that is serving — at any generation above the one it holds —
	// and replace that replica's keys wholesale. An honest keeper never
	// tries: it re-seeds only what it finds sealed. A lost one is not honest,
	// and its bundle predates every rotation since it was enrolled.
	if intent == IntentReseed && v.phase == PhaseUnsealed {
		return fmt.Errorf("%w (generation %d)", ErrAlreadyServing, v.generation)
	}
	if v.phase == PhaseOperatorHold && intent != IntentOperator {
		return fmt.Errorf("%w (held since %s: %s)",
			ErrOperatorHold, v.since.Format(time.RFC3339), v.holdReason)
	}
	// After the hold, so a keeper at a hold still hears about the hold; before
	// the generation and the idempotent return, so a retry is checked against
	// the pin as it is now. Every push, sealed or serving: the pin is written
	// only from a keyring that is already saved, so a legitimate bundle always
	// passes it, and checking a serving replica too covers a push from another
	// machine between the pusher's read and its push.
	switch {
	case belowPin:
	case v.pinStatus == PinInvalid && intent == IntentReseed:
		return fmt.Errorf("%w: %s", ErrPinUnreadable, v.pinErr)
	case v.pinStatus == PinValid:
		if err := v.pin.Admits(KeysOf(b)); err != nil {
			return err
		}
	}
	if b.Generation() < v.generation {
		return fmt.Errorf("%w: bundle is generation %d, this keyholder has held %d",
			ErrGenerationTooOld, b.Generation(), v.generation)
	}
	// Under the same lock as the install. The pusher read this replica's
	// keys a moment ago; another machine may have pushed newer ones since,
	// and replacing those would leave everything written under them
	// unreadable. Membership only: which key is in use is the pusher's to
	// move — moving it back to an older held key is how a hand-over keeps a
	// key out of use until every replica holds it.
	if v.phase == PhaseUnsealed {
		if err := v.dropsLocked(b); err != nil {
			return err
		}
	}
	if v.phase == PhaseUnsealed && b.Generation() == v.generation {
		// Idempotent: re-pushing the same generation is what lets an
		// operator fan out across replicas and retry freely.
		return nil
	}

	// Clone: a bundle shares its key bytes with everything it was copied
	// into, and the pusher is entitled to wipe its bundle the moment the push
	// returns. A vault that stored the caller's slices would keep serving from
	// material zeroed out from under it — consistently, and therefore
	// invisibly, under a key of all zeros.
	scopes := make([]datasphere.Scope, 0, len(b.Scopes()))
	for _, s := range b.Scopes() {
		if err := s.Valid(); err != nil {
			// The copies already made are key material too.
			for _, c := range scopes {
				c.Zero()
			}
			return err
		}
		scopes = append(scopes, s.Clone())
	}
	v.dropLocked()
	v.scopes = scopes
	v.generation = b.Generation()
	v.phase = PhaseUnsealed
	v.holdReason = ""
	v.since = v.now()
	return nil
}

// dropsLocked reports a bundle that lacks a scope, or a key-encryption key of
// a scope, that this replica holds. The caller holds v.mu.
func (v *Vault) dropsLocked(b *datasphere.Bundle) error {
	carried := make(map[string]map[datasphere.KeyID]bool, len(b.Scopes()))
	for _, s := range b.Scopes() {
		ids := map[datasphere.KeyID]bool{}
		for _, e := range s.Keyring().KEKs() {
			ids[e.ID] = true
		}
		carried[s.Name] = ids
	}
	for _, s := range v.scopes {
		ids, ok := carried[s.Name]
		if !ok {
			return fmt.Errorf("%w (scope %s)", ErrWouldDrop, s.Name)
		}
		for _, e := range s.Keyring().KEKs() {
			if !ids[e.ID] {
				return fmt.Errorf("%w (key %s of scope %s)", ErrWouldDrop, e.ID, s.Name)
			}
		}
	}
	return nil
}

// Seal drops the key material.
//
// A hold records that a person did this, and survives until that person clears
// it — within this process. It is deliberately NOT durable: a hold that
// outlived the process would have to rest in cloud-resident state, which would
// serve the very adversary a hold is aimed at. A restarted keyholder therefore
// comes back restart-sealed, and every caller that offers a hold says so.
func (v *Vault) Seal(hold bool, reason string) State {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.dropLocked()
	if hold {
		v.phase = PhaseOperatorHold
		v.holdReason = reason
	} else {
		v.phase = PhaseRestartSealed
		v.holdReason = ""
	}
	v.since = v.now()
	return State{Phase: v.phase, Since: v.since, Generation: v.generation, HoldReason: v.holdReason,
		Boot: v.boot, Pin: v.pinReportLocked(nil)}
}

// ReleaseHold converts an operator hold back into an ordinary restart seal,
// making the keyholder eligible for an unattended re-seed again.
//
// It lands on restart-sealed rather than unsealed on purpose: releasing a hold
// says "automation may act again", not "here are the keys". The material is
// gone and only a push brings it back.
func (v *Vault) ReleaseHold() State {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.phase == PhaseOperatorHold {
		v.phase = PhaseRestartSealed
		v.holdReason = ""
		v.since = v.now()
	}
	return State{Phase: v.phase, Since: v.since, Generation: v.generation, Boot: v.boot, Pin: v.pinReportLocked(nil)}
}

// Scope returns the scope owning a logical key.
//
// A sealed vault reports ErrSealed and a key outside every scope reports
// ErrOutOfScope, and the two are distinct all the way to the application: a
// seal is temporary and clears, while out-of-scope never will.
//
// The scope returned is the CALLER's own copy, and the caller must Zero it
// when its request ends. It used to be the vault's, sharing key bytes with
// what the vault holds — so an unseal at a new generation, which zeroes the
// scopes it replaces, zeroed them under every request still in flight. A
// write caught between resolving its scope and sealing its body (the whole of
// its upload) then wrapped its data key under an all-zero KEK that still
// carried the real key ID: unreadable to its owner, and readable by anyone
// who tried a key of zeros. That is the object the cloud ends up storing.
//
// Copying per request is what makes the vault's zeroing safe to do at all. It
// has one consequence worth stating: a request already admitted finishes with
// the material it was admitted with, even across a Seal, and wipes it on the
// way out. A sealed vault holds no key material; a request it admitted earlier
// holds its own until it returns.
func (v *Vault) Scope(logicalKey string) (datasphere.Scope, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.phase != PhaseUnsealed {
		return datasphere.Scope{}, ErrSealed
	}
	for _, s := range v.scopes {
		if s.Owns(logicalKey) {
			return s.Clone(), nil
		}
	}
	return datasphere.Scope{}, ErrOutOfScope
}

// dropLocked forgets the key material. The caller holds the write lock.
func (v *Vault) dropLocked() {
	for _, s := range v.scopes {
		s.Zero()
	}
	v.scopes = nil
}

// String renders the vault without key material.
func (v *Vault) String() string {
	st := v.State()
	return fmt.Sprintf("keyholder.Vault{Instance:%s Phase:%s Generation:%d Scopes:%d Material:<redacted>}",
		v.instance, st.Phase, st.Generation, len(st.Scopes))
}
