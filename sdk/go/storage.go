package farcast

import (
	"context"
	"sync"
	"time"
)

// StorageAPI provides object storage through DataSphere. Reads and writes
// are encrypted transparently — the application handles plaintext while the
// cloud provider sees only encrypted blobs — and the backing object store
// (S3, GCS, …) is hidden behind the key-addressed interface.
//
// The four methods are frozen. Applications implement this interface to fake
// storage in their own tests, so a fifth method would break every one of
// them; capabilities that are not universal arrive as separate optional
// interfaces (see StorageStatusAPI) discovered with a type assertion.
//
// Every method can return ErrStorageSealed: the instance's keyholder holds
// key material in memory only, so any restart leaves storage sealed until an
// operator unseals it. It is a normal, expected state, not a failure —
// see ErrStorageSealed and docs/adr/0008-in-cluster-key-delivery.md.
type StorageAPI interface {
	Read(ctx context.Context, key string) ([]byte, error)
	Write(ctx context.Context, key string, data []byte) error
	List(ctx context.Context, prefix string) ([]string, error)
	Delete(ctx context.Context, key string) error
}

// StorageState is the keyholder's coarse condition.
type StorageState string

const (
	// StorageReady means key material is loaded and calls should succeed.
	StorageReady StorageState = "ready"
	// StorageSealed means the keyholder is running and the data is intact,
	// but no key material is loaded. Calls return ErrStorageSealed.
	StorageSealed StorageState = "sealed"
	// StorageUnreachable means the keyholder could not be reached or its
	// answer was not understood. Calls return ErrStorageUnavailable.
	StorageUnreachable StorageState = "unavailable"
)

// SealReason distinguishes the two ways storage comes to be sealed. They are
// not interchangeable: one is routine and self-inflicted by the platform, the
// other is a deliberate act an operator took and only an operator may undo.
type SealReason string

const (
	// SealNone is the zero value, meaningful only when the state is not
	// StorageSealed.
	SealNone SealReason = ""
	// SealRestart means the keyholder process restarted — a node upgrade,
	// an eviction, a rollout — and came back without key material. This is
	// the common case and the one a keeper device may clear unattended.
	SealRestart SealReason = "restart"
	// SealOperator means an operator sealed storage deliberately. Only an
	// operator can clear it; an automated keeper never may.
	SealOperator SealReason = "operator"
)

// StorageStatus reports the keyholder's condition without attempting an
// operation. It is a struct rather than an interface precisely so that fields
// can be added later without breaking callers, following ConnStatus.
type StorageStatus struct {
	State StorageState
	// Reason is set when State is StorageSealed.
	Reason SealReason
	// Since is when the current state began, if the keyholder reported it.
	Since time.Time
	// Generation counts unseals; it moves when key material is replaced.
	Generation uint64
}

// Sealed reports whether storage is currently sealed.
func (s StorageStatus) Sealed() bool { return s.State == StorageSealed }

// StorageStatusAPI is the optional pre-attempt seam on top of StorageAPI. A
// long-running job can check once rather than discovering a seal on its first
// write, and a health endpoint can report the difference between "sealed" and
// "broken" without touching data.
//
// It is deliberately a separate interface: StorageAPI is what applications
// fake in their own tests, and widening it would break those fakes. Reach it
// with StorageStatusOf rather than asserting by hand.
type StorageStatusAPI interface {
	StorageAPI
	Status(ctx context.Context) (StorageStatus, error)
}

// StorageStatusOf reports s's condition when s implements StorageStatusAPI,
// and ErrNotImplemented when it does not — which is what a hand-written fake
// in an application's tests will normally be.
//
// Checking the status is never required. Every StorageAPI method reports a
// seal on its own with ErrStorageSealed, and a status that says ready can be
// stale by the time the next call runs, so code must still classify the error
// from the operation itself.
func StorageStatusOf(ctx context.Context, s StorageAPI) (StorageStatus, error) {
	if st, ok := s.(StorageStatusAPI); ok {
		return st.Status(ctx)
	}
	return StorageStatus{}, ErrNotImplemented
}

// Storage returns the storage capability.
//
// It is configured from the environment on first use. Outside a FarCast
// instance — or in a build the platform has not wired storage into — the
// methods yield ErrNotImplemented, so an application compiles and runs
// against the full surface before storage exists.
func Storage() StorageAPI {
	storageOnce.Do(func() { storageCapability = newStorageFromEnv() })
	return storageCapability
}

var (
	storageOnce       sync.Once
	storageCapability StorageAPI
)

var _ StorageAPI = storageStub{}

type storageStub struct{}

func (storageStub) Read(context.Context, string) ([]byte, error)   { return nil, ErrNotImplemented }
func (storageStub) Write(context.Context, string, []byte) error    { return ErrNotImplemented }
func (storageStub) List(context.Context, string) ([]string, error) { return nil, ErrNotImplemented }
func (storageStub) Delete(context.Context, string) error           { return ErrNotImplemented }
