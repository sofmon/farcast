// Package datasphere is FarCast's storage abstraction over cloud object
// storage. It exposes a single cloud-agnostic Provider interface for bucket
// and object lifecycle, a small registry so adapters (GCS first; S3 later)
// self-register and are reached through Open, and — above both — the
// encrypting Store, which is the only code in FarCast that holds storage
// plaintext or logical object names together with the ability to reach a
// cloud.
//
// The layering is the security boundary, not a convenience: every Provider
// receives ciphertext under opaque tokenized names, so "the cloud provider
// sees only encrypted blobs" is a structural fact no adapter can violate
// rather than a promise each adapter must keep.
//
// See README.md in this directory for the specification.
package datasphere

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/sofmon/farcast/datasphere/internal/crypto"
)

// Error sentinels callers branch on. The SDK's storage errors (3.2) map onto
// these rather than inventing a parallel vocabulary.
var (
	// ErrObjectNotFound reports that no object is stored under that logical
	// key.
	ErrObjectNotFound = errors.New("datasphere: object not found")

	// ErrIntegrity reports that a stored blob failed authentication — it was
	// modified, corrupted, truncated, or swapped. No plaintext is returned
	// with it, ever.
	ErrIntegrity = crypto.ErrIntegrity

	// ErrUnknownKey reports that a blob names a key ID absent from the
	// keyring. Two causes are indistinguishable from here: the header was
	// tampered with (the key ID is cloud-writable bytes, read before any
	// authentication can run) or the keyring is stale.
	//
	// Because the adversary picks which of the two an operator sees — one bit
	// of the key ID converts either into the other — no message on this path
	// may instruct a destructive recovery. Restoring a keys file is
	// merge-only (see Keyring.Merge): a stale keyring written over the live
	// one destroys every key appended since the backup, which is precisely
	// the key-loss catastrophe a tampering cloud would be steering towards.
	ErrUnknownKey = crypto.ErrUnknownKey

	// ErrTooLarge reports that a plaintext exceeds the object cap. Streaming
	// for large objects arrives with 3.3's `storage cp` as a chunked v2 blob
	// format behind the version byte.
	ErrTooLarge = crypto.ErrTooLarge

	// ErrInvalidKey reports a malformed logical key: empty, over the byte
	// cap, over the segment cap, carrying an empty segment, or ending in "/".
	ErrInvalidKey = crypto.ErrInvalidKey

	// ErrNotOwned reports that a bucket was inspected and the inspection
	// PROVED it is not this instance's — refused for both adoption and
	// deletion.
	//
	// An inspection that merely fails (403, or 429/5xx/timeout after the
	// adapter's retries) is a plain error, never this: conflating "proven
	// foreign" with "could not inspect" is how an ensure orphans its own
	// billable bucket behind a freshly minted name.
	ErrNotOwned = errors.New("datasphere: bucket is not this instance's")

	// ErrBucketNotFound reports that a bucket was inspected and PROVEN absent,
	// as distinct from an inspection that merely failed — the same distinction
	// ErrNotOwned draws, for the same reason.
	//
	// It exists because teardown needs it. DeleteBucket treats an absent bucket
	// as success, but a caller that validates first would never reach that: a
	// free, already-deleted bucket would permanently block the teardown of the
	// billable cluster beside it, and "re-run once it can be reached" would
	// name a condition that never arrives. A proven-absent bucket is nothing to
	// gate on and nothing to delete; an unreachable one is still a reason to
	// stop.
	ErrBucketNotFound = errors.New("datasphere: bucket does not exist")

	// ErrRetentionForced reports that the cloud is holding — and billing for —
	// copies of objects the operator ordered destroyed, because a policy
	// outside FarCast's control forces a soft-delete retention window that the
	// adapter could not reset.
	//
	// It is deliberately delivered as an error accompanying a SUCCESSFUL
	// operation: EnsureBucket returns a usable Bucket with it, and DeleteBucket
	// returns it once the bucket is genuinely gone. A caller that classifies it
	// warns the operator and proceeds; a caller that does not treats it as a
	// failure and retries, which is harmless because every operation it
	// accompanies is idempotent. Both behaviours are safe, and neither reports
	// "nothing left billing" while retained copies bill for days.
	//
	//	if err := p.DeleteBucket(ctx, ref); err != nil {
	//		if !errors.Is(err, datasphere.ErrRetentionForced) {
	//			return err // the bucket may still exist; keep the record
	//		}
	//		warn(err) // deleted, but the cloud is still holding ciphertext
	//	}
	ErrRetentionForced = errors.New("datasphere: the cloud retains deleted objects")
)

// Factory builds a Provider from its configuration.
type Factory func(cfg Config) (Provider, error)

var (
	registryMu sync.RWMutex
	registry   = map[string]Factory{}
)

// Register adds a provider factory under name. Adapters call it from their
// init(). It panics on an empty name, a nil factory, or a duplicate — all
// programmer errors.
func Register(name string, f Factory) {
	if name == "" || f == nil {
		panic("datasphere: Register requires a non-empty name and non-nil factory")
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := registry[name]; dup {
		panic("datasphere: duplicate provider " + name)
	}
	registry[name] = f
}

// Open constructs the registered provider named name with cfg.
func Open(name string, cfg Config) (Provider, error) {
	registryMu.RLock()
	f, ok := registry[name]
	registryMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("datasphere: unknown provider %q (registered: %v); did you blank-import datasphere/providers?", name, Providers())
	}
	return f(cfg)
}

// Providers returns the registered provider names, sorted.
func Providers() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
