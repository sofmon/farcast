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
type Intent string

const (
	// IntentOperator is a person unsealing. It may clear an operator hold.
	IntentOperator Intent = "operator-unseal"
	// IntentReseed is an unattended keeper restoring material after a
	// restart. It may never clear an operator hold — that is the whole
	// point of the distinction.
	IntentReseed Intent = "restart-reseed"
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
	}
}

// State reports the current phase.
func (v *Vault) State() State {
	v.mu.RLock()
	defer v.mu.RUnlock()
	names := make([]string, len(v.scopes))
	for i, s := range v.scopes {
		names[i] = s.Name
	}
	return State{
		Phase:      v.phase,
		Since:      v.since,
		Generation: v.generation,
		HoldReason: v.holdReason,
		Scopes:     names,
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
func (v *Vault) Scope(logicalKey string) (datasphere.Scope, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.phase != PhaseUnsealed {
		return datasphere.Scope{}, ErrSealed
	}
	for _, s := range v.scopes {
		if s.Owns(logicalKey) {
			return s, nil
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
