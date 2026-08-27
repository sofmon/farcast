package datasphere

import (
	"context"
	"fmt"
	"io"
	"time"
)

// Provider is one cloud's object storage. Every method honours ctx for
// cancellation and deadlines. All object operations take the bucket name
// recorded in the instance's local metadata; names and data are opaque to the
// adapter — encryption happens above, in Store.
//
// Bucket lifecycle sits in the Provider proper rather than in an optional
// capability the way Planck's registry does: Planck's registry is optional
// because a compute cloud without image hosting is still a complete compute
// provider, whereas no object-storage provider is complete without a bucket.
//
// The concurrency contract, stated here so a second adapter has something to
// conform to rather than inheriting one cloud's accidents:
//
//   - Put on an existing name atomically replaces object and metadata
//     together.
//   - Concurrent Puts to one name yield some single complete write — no torn
//     or merged state. Which writer wins is deliberately unspecified, because
//     GCS and S3 resolve ordering differently and the contract must not
//     promise applications an ordering adapters cannot deliver.
//   - Get concurrent with Put returns a complete prior or new version, never
//     a mix.
//   - A completed Put is visible to subsequent Get and List (strong
//     read-after-write) — the one-call List and the recovery flows rely on it.
//
// GCS and post-2020 S3 provide all four natively. An adapter for a cloud that
// does not cannot satisfy this interface with whole-request operations and
// must say so.
type Provider interface {
	// Name is the provider's stable identifier, e.g. "gcs".
	Name() string

	// Validate confirms the configured credentials are usable. It creates
	// nothing. A zero-value ref is a credentials-only probe; a populated ref
	// additionally verifies the bucket carries FarCast's full ownership
	// labels, including the instance name.
	Validate(ctx context.Context, ref BucketRef) error

	// EnsureBucket idempotently creates the instance's bucket with FarCast's
	// ownership labels and hardened posture. On a name conflict it inspects:
	// a bucket whose labels prove it is this instance's is adopted; a bucket
	// the inspection PROVES is not is refused with ErrNotOwned; an inspection
	// that merely fails (403, timeout, 5xx after retries) is a plain error —
	// never ErrNotOwned, so the caller keeps its record and retries the same
	// name. The adapter never mints a name and never retries under a new one.
	EnsureBucket(ctx context.Context, spec BucketSpec) (*Bucket, error)

	// DeleteBucket verifies full ownership (both labels, including the
	// instance in ref), deletes every object, then deletes the bucket,
	// blocking until removal completes. An absent bucket is success.
	DeleteBucket(ctx context.Context, ref BucketRef) error

	// Put stores an object (ciphertext, opaque name) with its small metadata
	// map, atomically — the metadata must never exist without the data or
	// vice versa. Put on an existing name atomically replaces object and
	// metadata together.
	Put(ctx context.Context, bucket string, obj Object) error

	// Get retrieves an object. A missing object is ErrObjectNotFound.
	Get(ctx context.Context, bucket, name string) (*Object, error)

	// List returns the objects under an opaque name prefix, including each
	// object's metadata map and size, paginating internally.
	List(ctx context.Context, bucket, prefix string) ([]ObjectInfo, error)

	// Delete removes an object. Deleting an absent object is not an error.
	Delete(ctx context.Context, bucket, name string) error

	// PutStream stores an object of unbounded size from a reader, atomically:
	// it becomes visible complete or not at all. An interrupted call must not
	// leave anything an operator would be billed for without being told.
	//
	// Streaming is part of the Provider proper rather than an optional
	// capability because optionality here would be fake — every real object
	// store has it (GCS resumable upload, S3 multipart) — and because
	// GetStream is a correctness requirement of Store.List, not a large-file
	// convenience: the name-recovery fallback would otherwise download a whole
	// object to read its header.
	PutStream(ctx context.Context, bucket string, obj StreamObject) error

	// GetStream returns a reader over a byte range of an object; length -1
	// means "to the end of the object". A missing object is ErrObjectNotFound.
	// The caller closes the reader.
	GetStream(ctx context.Context, bucket, name string, offset, length int64) (io.ReadCloser, error)
}

// BucketSpec describes the bucket to ensure. The caller mints and records the
// bucket name before calling — the bucket's random suffix exists nowhere but
// that record — and the adapter never invents one.
type BucketSpec struct {
	Name     string            // full bucket name, already recorded locally
	Instance string            // instance name; stamped into ownership labels
	Location string            // region; must match the instance's region
	Labels   map[string]string // additional cloud resource labels
}

// BucketRef identifies a bucket for teardown or validation. Instance is
// required for the ownership check: the bucket name is NOT invertible to the
// instance name (the name's instance segment may be truncated to fit the
// cloud's length cap), so the caller supplies it from the local record.
type BucketRef struct {
	Name     string
	Location string
	Instance string
}

// Bucket is an ensured instance bucket.
type Bucket struct {
	Ref BucketRef
}

// Object is a stored blob: ciphertext under an opaque tokenized name, plus a
// small metadata map. The map carries the sealed logical-name mirror, which is
// what lets one list call per page satisfy Store.List without per-object
// fetches. Both GCS custom metadata and S3 user metadata realize the map.
type Object struct {
	Name string
	Data []byte
	Meta map[string]string
}

// StreamObject is an object supplied as a stream. Size is -1 when the length
// is not known up front, which is the normal case for a pipe; an adapter that
// needs a total length is responsible for discovering it.
type StreamObject struct {
	Name string
	Data io.Reader
	Size int64
	Meta map[string]string
}

// ObjectInfo is one listing entry. Size is the stored (ciphertext) size; it
// feeds `storage ls` and usage reporting without new adapter surface.
//
// Created is when the cloud recorded the object. It rides the same listing
// projection at no extra cost and leaks nothing new — creation and access
// timestamps were already among the things the provider observes and this
// module has always said so. It is what makes `storage ls` show an age and
// `storage usage` report a growth rate on its first run rather than its
// second. A provider that does not report one leaves it zero.
type ObjectInfo struct {
	Name    string
	Size    int64
	Created time.Time
	Meta    map[string]string
}

// Config carries credentials and account scoping — the same neutral shape as
// planck.Config, mirrored rather than imported: the storage module must not
// couple to the compute module.
type Config struct {
	Credentials []byte            // raw credential material (e.g. GCP service-account key JSON); empty = ambient/default creds
	Project     string            // GCP project ID / AWS account context
	Location    string            // default region
	Extra       map[string]string // provider-specific options
}

// String renders the config without leaking the credential material, so
// accidental logging (%v/%s) cannot expose the operator's cloud credentials.
func (c Config) String() string {
	cred := "<none>"
	if len(c.Credentials) > 0 {
		cred = fmt.Sprintf("<redacted %d bytes>", len(c.Credentials))
	}
	return fmt.Sprintf("Config{Project:%s Location:%s Credentials:%s Extra:%v}",
		c.Project, c.Location, cred, c.Extra)
}
