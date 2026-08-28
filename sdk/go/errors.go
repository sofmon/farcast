package farcast

import "errors"

// ErrNotImplemented is returned by capability methods whose implementation
// has not yet landed. Application code can compile and run against the full
// SDK surface early; capabilities light up as their build phases complete.
//
// Classify it with errors.Is:
//
//	if _, err := farcast.Storage().Read(ctx, key); errors.Is(err, farcast.ErrNotImplemented) {
//		// capability not available in this build
//	}
var ErrNotImplemented = errors.New("farcast: capability not implemented")

// Storage error sentinels.
//
// These are the classifications an application can actually act on, and the
// set is deliberately small: every sentinel here is inherited by every
// application ever written against this SDK, so one added carelessly can
// never be withdrawn.
//
// DataSphere's own vocabulary is wider (see datasphere/README.md). Sentinels
// that describe an operator's problem rather than an application's — a bucket
// proved to belong to another instance, a cloud retention policy still billing
// for deleted objects — deliberately do not cross into this module: an
// application cannot act on them, and an error it cannot act on is noise it
// may branch on wrongly.
var (
	// ErrStorageSealed reports that the instance's keyholder is running and
	// the data is intact, but no key material is loaded: the process
	// restarted, or an operator sealed it deliberately. Storage will work
	// again once the operator (or, from 5.4, a keeper device) unseals it.
	//
	// It is deliberately distinct from ErrNotImplemented, which means this
	// build never can, and from ErrObjectNotFound, which means there is no
	// such object — an application that read a seal as "no such object" and
	// started over would be silent data loss by a second route.
	//
	// The correct response is to wait and retry, or to fail the request
	// upward. It must never be answered by writing.
	ErrStorageSealed = errors.New("farcast: storage is sealed (no key material loaded)")

	// ErrObjectNotFound reports that no object exists under that logical key.
	// It means absence, and only absence.
	ErrObjectNotFound = errors.New("farcast: no such object")

	// ErrIntegrity reports that a stored object failed authentication —
	// modified, corrupted, truncated or swapped — or that it names key
	// material this instance does not hold. No plaintext was returned.
	//
	// Never treat it as absence and never "recover" by overwriting: the
	// object may be intact and the keyring merely stale, in which case a
	// write destroys recoverable data.
	ErrIntegrity = errors.New("farcast: stored object failed authentication")

	// ErrInvalidKey reports a malformed logical key — empty, over 1024
	// bytes, over 30 segments, an empty segment, or a trailing slash.
	ErrInvalidKey = errors.New("farcast: malformed object key")

	// ErrTooLarge reports that the object exceeds the size limit.
	ErrTooLarge = errors.New("farcast: object exceeds the size limit")

	// ErrPermission reports that the caller may not touch that key. In
	// phase 3.2 this means a key outside the application's own scope.
	ErrPermission = errors.New("farcast: not permitted")

	// ErrStorageUnavailable reports that storage could not be reached, or
	// answered in a way this build does not understand.
	//
	// It exists so the wire mapping is total. Without a catch-all, an
	// unrecognized answer would have to collapse into some other sentinel,
	// and the two nearest — "never will work" and "no such object" — are
	// both wrong in ways that cost data.
	ErrStorageUnavailable = errors.New("farcast: storage is unavailable")
)
