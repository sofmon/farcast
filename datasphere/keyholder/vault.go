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

	now func() time.Time
}

// New returns a sealed vault. There is no constructor that returns an unsealed
// one: a keyholder always starts sealed, and the only way out is a push from
// outside the cluster.
func New(instance string) *Vault {
	now := func() time.Time { return time.Now().UTC() }
	return &Vault{
		instance: instance,
		phase:    PhaseRestartSealed,
		since:    now(),
		now:      now,
		boot:     newBootID(),
	}
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
	}
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
// vault.
func (v *Vault) Unseal(b *datasphere.Bundle, intent Intent) error {
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
	if b.Generation() < v.generation {
		return fmt.Errorf("%w: bundle is generation %d, this keyholder has held %d",
			ErrGenerationTooOld, b.Generation(), v.generation)
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
	return State{Phase: v.phase, Since: v.since, Generation: v.generation, HoldReason: v.holdReason}
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
	return State{Phase: v.phase, Since: v.since, Generation: v.generation}
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
