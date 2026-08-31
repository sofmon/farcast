# DataSphere

> Storage abstraction — a cloud-agnostic layer over object storage (GCS, S3), where every byte is encrypted before the cloud ever sees it.

DataSphere is the module that turns "a cloud bucket" into "the instance's private disk." It is FarCast's storage substrate: the only module that talks to a cloud's object-storage APIs, hidden behind one interface so the rest of FarCast never names a cloud — and wrapped in one encryption layer so the cloud never sees a name or a byte of what it stores. The cloud provider's role is reduced to holding ciphertext blobs under meaningless names.

This document specifies **Phase 3.1 — the first storage provider adapter**: the `Provider` interface, the encrypting `Store` above it, the operator-held keyring, and one concrete adapter (GCS) that can ensure and destroy the instance's bucket and put, get, list, and delete objects. Wiring into the SDK (3.2) and the operator CLI (3.3) are later phases and are described only in outline here.

> **Status.** Phase 3.1 — **implemented, unit-tested, and validated against a real bucket on 2026-08-27.** Everything specified below exists under `datasphere/`: the blob format is frozen by golden vectors whose HKDF and HMAC values were reproduced independently, the GCS adapter is driven end-to-end over a fake transport, and the whole stack has now been walked against live GCS via [`docs/runbooks/phase-3-validation.md`](../docs/runbooks/phase-3-validation.md) — all nine success criteria passed, with `gcloud` independently confirming that the cloud holds only opaque tokens and `FCDS`-prefixed ciphertext. Both assumptions this module shipped on are settled: **object metadata is returned in the default list projection** (so `List` is one call per page, as claimed), and the recommended **`farcast-*` IAM condition works** and does not block the credentials probe. `X-Goog-Meta-*` turns out not to be sent on media downloads — the one best-effort path, which nothing depends on. **Phase 3.3 is implemented** — the streaming v2 format (golden-vectored against an independent implementation), the `Provider` streaming pair, `BucketUsage`, `Store.Rekey`, the passphrase-armored keyring export, and the hand-rolled GCS resumable-upload path. Validated live against a real bucket on 2026-08-27 — the resumable-upload protocol, ranged reads, and framing overhead exact to the byte (a 64 MiB object stores as 67,110,048, which is 144 of header plus 65 frame tags: 64 full frames plus the zero-length terminator); the operator-facing half lives in [`farsight/cli/README.md`](../farsight/cli/README.md). The frozen upstream contract is [`sdk/go/storage.go`](../sdk/go/README.md)'s `StorageAPI` (`Read`/`Write`/`List(prefix)`/`Delete`, key-addressed, `[]byte` values), which 3.2 wires to the `Store` defined here — the two are deliberately signature-identical. **Out of scope (later phases):** the SDK wiring and the in-cluster key-delivery decision (3.2 — see [Key management](#key-management)), `farcast storage` CLI commands, streaming/large objects, key export and rotation tooling, usage reporting (3.3), per-app isolation (4.x), secrets (5.3), and the second storage provider (8.2).

---

## What DataSphere is — and isn't

**It is** the storage boundary, in both directions. Every read and write crosses one encrypting layer (`Store`) that sits *above* the cloud adapters: plaintext and logical object names exist only on the caller's side of it, and every adapter receives only ciphertext under opaque tokenized names. "The cloud provider sees only encrypted blobs" ([AGENTS.md](../AGENTS.md)) is therefore not a promise each adapter must keep — it is a structural fact no adapter can violate, and the second provider (8.2) inherits the crypto without writing a line of it.

**It is not** a filesystem, a database, or a sync service. DataSphere stores and retrieves whole objects by key. It wraps the cloud's mature object storage exactly as Planck wraps managed Kubernetes ([never reinvent cloud infrastructure](../AGENTS.md)); consistency, durability, and replication are the cloud's job. It is also **not** where keys or credentials live: like Planck, it receives credentials and key material from its caller, uses them, and persists neither. The `farcast` CLI owns the files ([`farsight/cli`](../farsight/cli/README.md)).

**It is honest about what encryption cannot hide.** Encrypting content and names does not make the operator invisible — see [What the cloud still sees](#what-the-cloud-still-sees). A storage spec that implied otherwise would be a privacy overpromise, and this module of all modules does not get to make one.

---

## Architecture & package layout

```
datasphere/
├── README.md                       ← this file (the spec)
├── docs/                           ← deeper notes (blob format vectors, provider notes)
├── datasphere.go (+ types.go)      ← PUBLIC: Provider interface, types, provider registry (Open/Register), error sentinels
├── store.go                        ← PUBLIC: the encrypting Store — the only layer that touches plaintext
├── keyring.go                      ← PUBLIC: Keyring type (in-memory; redacting String); the keys.yaml format contract
├── providers/                      ← PUBLIC: blank-import to register the bundled adapters
│   └── providers.go
├── cmd/
│   └── datasphere/
│       └── main.go                 ← thin manual harness: keygen / ensure / put / get / ls / rm / delete
└── internal/
    ├── crypto/                     ← envelope encryption, name tokenization, blob format v1
    └── providers/
        └── gcs/                    ← GCS adapter (first); S3 later (8.2)
```

The package wiring is Planck's proven [`database/sql`](https://pkg.go.dev/database/sql) pattern ([`planck/README.md`](../planck/README.md)): the root package declares the `Provider` interface and a small registry (`Register`/`Open`/`Providers`); adapters live in `internal/providers/<cloud>` and self-register in `init()`; the public `datasphere/providers` package does nothing but blank-import them; a composition root (the harness now, the CLI in 3.3) imports both. Adding a provider = one new internal package + one blank-import line.

The one structural addition Planck has no analogue for is `Store` — because Planck hands its callers a cloud resource, while DataSphere must hand its callers *plaintext* without ever handing the cloud any. The layering rule is absolute: **`Store` is the only code in FarCast that holds storage plaintext or logical names together with the ability to reach a cloud.** Everything below it operates on ciphertext and tokens.

---

## The Provider interface

Cloud-agnostic, context-first, and ciphertext-only. A `Provider` never sees a logical name or a plaintext byte, so its surface is deliberately boring: bucket lifecycle plus four object operations on opaque names.

```go
// Provider is one cloud's object storage. Every method honours ctx. All object
// operations take the bucket name recorded in the instance's local metadata;
// names and data are opaque to the adapter — encryption happens above, in Store.
type Provider interface {
	// Name is the provider's stable identifier, e.g. "gcs".
	Name() string

	// Validate confirms the configured credentials are usable. It creates
	// nothing, and returns a plain yes or no — a caller may safely treat any
	// error from it as fatal (see Decisions 13). A zero-value ref is a
	// credentials-only probe; a populated ref additionally verifies the bucket
	// carries FarCast's full ownership labels, including the instance name
	// (see The instance bucket).
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
	// the object becomes visible complete or not at all. An interrupted call
	// must leave nothing an operator would be billed for without being told.
	// (3.3)
	PutStream(ctx context.Context, bucket string, obj StreamObject) error

	// GetStream returns a reader over a byte range of an object; length -1
	// means "to the end". A missing object is ErrObjectNotFound. (3.3)
	GetStream(ctx context.Context, bucket, name string, offset, length int64) (io.ReadCloser, error)
}
```

**Why streaming widens the `Provider` rather than riding an optional capability** (3.3). Planck's registry is optional because a compute cloud without image hosting is still a complete compute provider. Streaming is not like that on either count. Every real object store has it — GCS resumable upload, S3 multipart — so optionality would be fake in the same way bucket lifecycle's would be. And `GetStream` is not only for large objects: `Store.List`'s **already-shipped** name-recovery fallback fetches an object whose metadata mirror is unreadable, which for a 5 GiB v2 object means downloading 5 GiB to read 1,168 bytes of header. That fallback is load-bearing for the module's reconstruct-every-name promise, so a ranged read is a correctness requirement of shipped behaviour, not a 3.3 optimization.

Bucket lifecycle sits in the `Provider` proper — a deliberate departure from Planck's optional `RegistryProvider` capability, argued in [Decisions](#decisions) (5).

**The concurrency contract, stated so 8.2 has something to conform to rather than inheriting one cloud's accidents:** `Put` on an existing name atomically replaces object and metadata together; concurrent `Put`s to one name yield some single complete write — no torn or merged state — with which writer wins deliberately unspecified (GCS and S3 resolve ordering differently, and the contract must not promise applications an ordering adapters cannot deliver); `Get` concurrent with `Put` returns a complete prior or new version, never a mix; and a completed `Put` is visible to subsequent `Get` and `List` (strong read-after-write — the one-call `List` and the recovery flows rely on it). GCS and post-2020 S3 both provide all four natively; an adapter for a cloud that does not cannot satisfy this interface with whole-request operations and must say so.

### Supporting types

```go
// BucketSpec describes the bucket to ensure. The caller mints and records the
// bucket name before calling (see The instance bucket); the adapter never
// invents one.
type BucketSpec struct {
	Name     string            // full bucket name, already recorded locally
	Instance string            // instance name; stamped into ownership labels
	Location string            // region; must match the instance's region
	Labels   map[string]string // additional cloud resource labels
}

// BucketRef identifies a bucket for teardown or validation. Instance is
// required for the ownership check: the bucket name is NOT invertible to the
// instance name (the name's instance segment may be truncated), so the caller
// supplies it from the local record.
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
// small metadata map (it carries the sealed logical-name mirror — see Name
// privacy). Both GCS custom metadata and S3 user metadata realize the map.
type Object struct {
	Name string
	Data []byte
	Meta map[string]string
}

// StreamObject is an object supplied as a stream. Size is -1 when unknown,
// which is the normal case for a pipe; an adapter that needs a total length up
// front is responsible for buffering to discover it. (3.3)
type StreamObject struct {
	Name string
	Data io.Reader
	Size int64
	Meta map[string]string
}

// ObjectInfo is one listing entry. Size is the stored (ciphertext) size; it
// feeds `storage ls` and usage reporting in 3.3 without new adapter surface.
type ObjectInfo struct {
	Name string
	Size int64
	Meta map[string]string
}
```

### Provider registry & configuration

```go
// Factory builds a Provider from its configuration.
type Factory func(cfg Config) (Provider, error)

// Config carries credentials and account scoping — the same neutral shape as
// planck.Config (mirrored, not imported: the storage module must not couple
// to the compute module). Credentials is sensitive; String() redacts it.
type Config struct {
	Credentials []byte            // raw credential material (e.g. GCP service-account key JSON)
	Project     string            // GCP project ID / AWS account context
	Location    string            // default region
	Extra       map[string]string // provider-specific options
}

func Register(name string, f Factory)                // called by adapters' init()
func Open(name string, cfg Config) (Provider, error) // construct a registered provider
func Providers() []string                            // registered provider names
```

### Error sentinels

Defined in 3.1 so 3.2 maps errors instead of inventing them (the SDK today has only `ErrNotImplemented`; 3.2 must add the sentinels applications will branch on — a recorded coordination point):

| Sentinel | Meaning |
|---|---|
| `ErrObjectNotFound` | no object under that logical key |
| `ErrIntegrity` | the stored blob failed authentication — modified, corrupted, truncated, or swapped; no plaintext was returned |
| `ErrUnknownKey` | the blob names a key ID absent from the keyring. Two indistinguishable causes: the header was tampered with (the key ID is cloud-writable bytes, read before any authentication can run) or the keyring is stale. Restoring a keys file is therefore **merge-only** — see Key management |
| `ErrTooLarge` | plaintext exceeds the 64 MiB object cap (streaming arrives with 3.3's `storage cp`) |
| `ErrInvalidKey` | the logical key is malformed (empty, over 1024 bytes, over 30 segments, empty segment, or trailing `/`) |
| `ErrNotOwned` | the bucket was inspected and the inspection **proved** it is not this instance's — refused for both adoption and deletion. An inspection that merely *fails* is a plain error, never `ErrNotOwned` |
| `ErrRetentionForced` | the cloud is holding — and billing for — copies of objects the operator ordered destroyed, because a policy outside FarCast's control forces a soft-delete window the adapter could not reset. Added at implementation; see [Decisions](#decisions) (11) |

`ErrUnknownKey` and `ErrIntegrity` are deliberately distinct — "your keyring is missing a key" and "the stored data was tampered with" demand different operator responses — but the adversary controls which one fires (one bit of the key ID converts one into the other), so **no sentinel's message may instruct a destructive recovery**: the remediation text is part of the attack surface. In particular, "restore from backup" advice must never mean overwrite-the-live-file — a stale keyring restored over the live one destroys every KEK appended since the backup, which is exactly the key-loss catastrophe a tampering cloud would be steering the operator into.

---

## The encrypting Store

The public entry point for everything that stores or retrieves data. Its four methods are **byte-for-byte the shape of `sdk/go/storage.go`'s `StorageAPI`**, so the 3.2 SDK wiring is transport, not translation:

```go
// NewStore wraps a Provider and a bucket with the instance's keyring. It is
// the only constructor; there is no unencrypted path, in code or in tooling.
func NewStore(p Provider, bucket string, keys Keyring) (*Store, error)

func (s *Store) Read(ctx context.Context, key string) ([]byte, error)
func (s *Store) Write(ctx context.Context, key string, data []byte) error
func (s *Store) List(ctx context.Context, prefix string) ([]string, error)
func (s *Store) Delete(ctx context.Context, key string) error

// StoredName returns the opaque path a logical key is stored under — the
// module's transparency surface. `datasphere ls --tokens` prints it so an
// operator can hold the stored name next to the logical one and see for
// themselves that the cloud holds neither.
func (s *Store) StoredName(key string) (string, error)
func (s *Store) Bucket() string
```

**Streaming (3.3).** Two methods, and deliberately not four: there is no streaming `List` or `Delete` because neither ever held an object in memory.

```go
// WriteStream stores r under key as a v2 chunked blob, holding one frame in
// memory regardless of size. It is an upsert, like Write.
func (s *Store) WriteStream(ctx context.Context, key string, r io.Reader) error

// ReadStream writes the authenticated plaintext of key to w, one frame at a
// time, and accepts either format — v1 objects stream as a single frame.
func (s *Store) ReadStream(ctx context.Context, key string, w io.Writer) error
```

`ReadStream` carries one caveat the `[]byte` API does not have and callers must be told: authentication is **per frame**, so a truncation or a tampered tail is detected only when the reader reaches it — after earlier frames have already been written to `w`. `Read`'s all-or-nothing guarantee cannot survive streaming, by arithmetic rather than by choice. Every consumer must therefore treat a non-nil error as *the output is incomplete and must not be used*, and `farcast storage cp` writes to a temporary file and renames only on success, so a failed download never leaves a plausible-looking partial file at the destination.

```go
// BucketUsage reports what a bucket physically holds — object count and stored
// bytes — over a Provider, with no keyring and nothing decrypted.
//
// It is a package function rather than a Store method on purpose. Store.List
// reports what the KEYRING can name; a teardown gate or a spend report built on
// that would announce an empty bucket while billable ciphertext sat in it, and
// would stop working entirely for the operator who has lost keys.yaml and most
// needs to see what they are still paying for. A divergence between this count
// and Store.List's is itself worth reporting.
func BucketUsage(ctx context.Context, p Provider, bucket string) (Usage, error)

type Usage struct {
	Objects     int64
	StoredBytes int64
}
```

`Write` is an **upsert**: writing an existing key atomically replaces it (the Provider contract above carries the atomicity). Lost-update protection — generations, preconditions, compare-and-swap — is explicitly out of 3.1's scope; if 3.2's multi-writer reality demands it, it arrives as an interface addition, not a reinterpretation.

Logical keys are opaque byte strings: non-empty UTF-8, at most 1024 bytes and 30 `/`-separated segments, no empty segments, no trailing `/`. **No normalization, ever** — no Unicode folding, no slash collapsing, no trimming. The key's exact bytes participate in authentication (below), so a "helpful" canonicalization applied on write but not read would turn valid data unreadable; a golden test vector with a non-normalized Unicode key pins this.

### Envelope encryption

Every `Write` mints a fresh random 256-bit data-encryption key (DEK) from `crypto/rand`, seals the plaintext with AES-256-GCM under it, and wraps the DEK with AES-256-GCM under the keyring's active key-encryption key (KEK). Both invocations use fresh random 96-bit nonces, stored in the blob.

- **Why envelope, not the KEK directly:** nonce safety first, rotation second. GCM under one long-lived key fails catastrophically on nonce reuse, and a single-use DEK makes data-nonce collision structurally impossible. And rotation becomes a header rewrite, never decrypt-everything-now.
- **The full nonce-budget ledger — three GCM uses, three budgets, none left unstated:** *data seals* — collision impossible (single-use DEKs); *KEK wraps* — one per write, so NIST SP 800-38D's random-nonce bound reads **~4 billion object writes per KEK**, and KEK rotation resets it (the version byte is the escape hatch to derived per-object wrap keys if that ever matters); *name seals* — one per write **under a per-object derived key** (below) whose plaintext and AAD are fixed per stored name, so a nonce collision produces identical ciphertexts and reveals nothing: that budget is unbounded by construction. The per-object derivation exists precisely because the name key cannot rotate — without it, the binding 2³² constraint would sit on the one key with no rotation path.
- **Why random nonces even where fixed ones would be provably safe:** defense in depth. Random nonces mean a future bug that reuses a DEK degrades to a bounded statistical risk instead of an instant catastrophe. 24 bytes per object buys that.
- **AAD binding.** The data seal's AAD is `magic ‖ version ‖ logical-key bytes` — **deliberately excluding the key ID**, so a rekey can rewrite the wrap fields without touching the body; the exclusion costs nothing, because a body transplanted under a foreign header fails GCM regardless (DEKs are single-use) and a cloud-side swap of two blobs fails on the logical-key binding at read time. The wrap's AAD is `magic ‖ version ‖ key ID`. Both AADs carry the version byte (downgrade protection); all AAD layouts are fixed-width fields with one variable field last (unambiguous without length prefixes) and are frozen by golden vectors.
- **What AAD does not defeat, stated plainly:** *rollback* (the cloud re-serving an older, validly-encrypted version of the same key) and *suppression* (omitting objects from listings). Freshness is a deliberate 3.1 non-goal, not an oversight.
- **Key commitment:** AES-GCM is not key-committing; harmless under this threat model (every key is locally minted from `crypto/rand`, no attacker-supplied keys, no multi-key trial decryption) — recorded so 5.3 secrets or any future passphrase-derived key re-opens it before reusing the v1 format.
- **Subkey derivation, pinned:** every derived key in this design is a single-shot `hkdf.Key` (stdlib `crypto/hkdf`), hash **SHA-256**, **nil salt**, output **32 bytes**, with the info strings given where each key is introduced. Two conforming implementations must produce identical bytes; the spec, not the first implementation, defines them.

### Blob format v1

Frozen by golden test vectors (fixed hex literals a refactor cannot regenerate) — this is data at rest, and an unpinned format change is silent data loss for every existing object:

| bytes | field |
|---|---|
| 0–3 | magic `FCDS` |
| 4 | version `0x01` |
| 5–12 | key ID (8 random bytes minted with the KEK — **never** a hash of the key, which would be an offline key-check oracle) |
| 13–24 | wrap nonce (12 B) |
| 25–72 | wrapped DEK (32 B + 16 B tag) |
| 73–74 | sealed-name length (uint16 BE) |
| … | sealed name: 12 B nonce ‖ ciphertext ‖ 16 B tag — the ciphertext's plaintext is `uint16 BE length ‖ logical-key bytes`, zero-padded as a whole to a multiple of 32 bytes |
| … | data nonce (12 B) |
| … | data ciphertext ‖ 16 B tag |

Fixed overhead ≈ 131 bytes plus the sealed name. `Write` rejects plaintext over **64 MiB** (`ErrTooLarge`): honest for a `[]byte` API that holds whole objects in memory, far under GCM's per-invocation limit, and covering what a key-value API is for. Large files arrive with 3.3's `storage cp` as a chunked **v2 format behind the version byte** (per-chunk counter nonces under a fresh per-object DEK — safe only because DEKs are single-use; the v2 design must re-run the wrap-budget arithmetic). No v1 migration will be required.

`Read` returns either the exact authenticated plaintext or an error — never partial output. Bad magic, unknown version, parse failure, or any GCM failure is `ErrIntegrity`; a key ID missing from the keyring is `ErrUnknownKey`.

### Blob format v2 — streaming (Phase 3.3)

v1 holds a whole object in memory, so it caps at 64 MiB. v2 is the chunked format the version byte was reserved for: `Store.WriteStream` and `Store.ReadStream` move objects of arbitrary size without either end ever holding more than one frame.

**v1 is not touched.** `Write`/`Read` keep emitting and accepting v1 byte-for-byte, no golden vector moves, and no stored object is ever rewritten. A reader dispatches on the version byte; a writer chooses by which API was called, not by size.

**The header is v1's, extended after the sealed name — and that ordering is the whole point:**

| bytes | len | field |
|---|---|---|
| 0–3 | 4 | magic `FCDS` |
| 4 | 1 | version `0x02` |
| 5–12 | 8 | key ID of the KEK the DEK is wrapped under |
| 13–24 | 12 | wrap nonce |
| 25–72 | 48 | wrapped DEK (32 B + 16 B tag) |
| 73–74 | 2 | sealed-name length *L* (uint16 BE) |
| 75 … | *L* | sealed name — **identical construction to v1** |
| 75+*L* … | 8 | frame salt (random, once per seal) |
| 83+*L* | 1 | chunk-size exponent *e*; frame plaintext size *P* = 1 ≪ *e* |
| 84+*L* … | var | frame 0, frame 1, … |

Bytes 0 through 74+*L* are the same fields at the same offsets in v1, v2, and every version after. That is not tidiness — it is the mechanism holding up this module's promise that *the bucket plus the keys file alone reconstruct every logical name with no local state*. `ParseHeader`, `HeaderName` and `Rekey` stay **one version-free implementation**; a recovery tool written today reads a name out of a format that does not exist yet. Putting the extension fields *before* the sealed name would have moved it to offset 87 and forced a version branch into the one path that must never need one.

`MaxHeaderLen` = 75 + 1084 + 9 = **1168** bytes (1084 = 12 + 1056 + 16, the longest sealed name), so a reader fetches `Range: bytes=0-1167` and is guaranteed a complete header in one request.

- **Frames.** `frameᵢ = GCM-Seal(DEK, nonceᵢ, plaintextᵢ, frameAAD)`, so a frame is its plaintext plus 16 bytes. Every frame but the last carries exactly *P* bytes; the last carries 0 to *P*. Default *e* = 20 (**1 MiB**), bounded to *e* ∈ [16, 26] (64 KiB – 64 MiB) and range-checked before *P* sizes any allocation — a hostile header must not be able to ask for a 4 GiB buffer. Tag overhead at the default is **15 ppm**.
- **Nonces are `salt ‖ uint32 BE frame index`.** Under one DEK the salt is fixed and the counter strictly increases, so no nonce repeats *by construction* rather than statistically. The salt is fresh per seal and is what preserves v1's defense-in-depth: two seals that erroneously shared a DEK collide only if their salts also collide (2⁻⁶⁴), instead of colliding on frame 0 with certainty. The counter cannot wrap — GCS caps an object at 5 TiB, which at the *smallest* legal frame size is 2²⁶ frames against a 2³² counter, a 51× margin, and the writer refuses index 2³² regardless.
- **AAD.** Frame AAD is `magic ‖ version ‖ e ‖ frame index ‖ final flag ‖ logical-key bytes`; wrap AAD is `magic ‖ version ‖ key ID`. The frame AAD **still excludes the key ID**, so rekey stays a header rewrite for v2 exactly as for v1. The version byte differs from v1's, so a wrapped DEK cannot be replayed across formats.
- **Length is derived, never stored.** The frame count and the plaintext length come from the object's ciphertext length and *e*. A stored length field would be a second cloud-writable source of truth; deriving it means the **final flag** does the work: truncating the object makes a reader treat a `final=0` frame as final, and extending it makes the real final frame parse as non-final. Both are tag failures. Reordering and replay fail on the frame index. A zero-byte object is legal — one frame, zero plaintext.
- **The nonce-budget ledger, re-run as v1 required.** Frame seals: collision structurally impossible (single-use DEK, non-wrapping counter). **KEK wraps: one per `WriteStream`, not one per frame** — this is the number that mattered, and it means a 5 GiB file costs *one* wrap, leaving v1's ~2³² writes per KEK unchanged. Wrapping per frame would have burned that budget 5,120× faster on a single large file and turned rotation from hygiene into an operational requirement. Name seals: unbounded by construction, as before.

**What the cloud additionally sees:** the frame size (a plaintext header byte) and, from the object's length, the frame count. Both were already inferable from the ciphertext size. Padding remains rejected on the cost pillar.

### Name privacy

Object names are metadata the cloud stores and indexes, and names are often the most sensitive metadata there is — `lawsuit-2026/` in plaintext guts the blind-provider pillar in the most legible way possible. But the frozen SDK contract requires `List(prefix)`, so names cannot be fully random without a central index. The design:

**Stored names are path-chained tokens.** The logical key `a/b/c` is stored as `T₁/T₂/T₃`, where `Tᵢ` is the lowercase hex of `HMAC-SHA-256(nameTokenKey, seg₁‖"/"‖…‖segᵢ)` — the HMAC of the exact joined logical *path prefix*, not of the segment alone — truncated to 16 bytes: 32 characters per token, `/` separators preserved. Every `/`-aligned logical prefix is still independently computable client-side, so cloud-side prefix listing works natively — and that is *all* prefix listing needs: equal logical path prefixes yield equal stored prefixes. Chaining deliberately confines equality leakage to shared path prefixes (which any List-compatible scheme must reveal); a per-segment construction would additionally leak segment-equality across unrelated parents — every occurrence of a common leaf name correlated bucket-wide, with the reserved `system/`/`app/` literals as known plaintext — and was rejected for exactly that. `nameTokenKey` is derived from the keyring's stable name key (info `farcast/datasphere/v1/name-token`). Truncation to 16 bytes is load-bearing and frozen by golden vectors: it buys ~31 segments of depth under GCS's 1024-byte object-name limit, against a collision probability (~N²/2¹²⁹ over distinct path prefixes) that is negligible at any realistic scale.

**The logical name travels sealed, twice.** The logical key is sealed once per write — AES-256-GCM under a **per-object seal key** `hkdf.Key(nameKey, info: "farcast/datasphere/v1/name-crypt/" ‖ the tokenized stored path)`, random nonce, AAD = the tokenized stored path bytes (belt-and-braces on top of the per-object key: a mapping cannot be transplanted between objects), plaintext as pinned in the format table (so the ciphertext reveals name length only to the nearest 32-byte bucket) — and the identical sealed block is stored in two places:

1. **In the provider metadata map** (key `farcast-name`, base64) — the fast path: one list call per page returns everything `List` needs, no per-object fetches.
2. **In the blob header** — the authoritative copy: the bucket plus the keys file alone reconstruct every logical name with no local state and no reliance on cloud metadata fidelity (`storage doctor`, future tooling, needs nothing else).

**`List(prefix)` semantics.** Tokenize the longest `/`-aligned portion of the prefix, list cloud-side under that token prefix, unseal logical names from the metadata mirror, filter client-side against the full logical prefix, return sorted logical names. Arbitrary string prefixes (`users/al`) are honoured exactly, at the honest cost of over-listing within one partial segment. A missing or non-authenticating mirror falls back to fetching that object — a plain full-object `Get`, whose header carries the authoritative copy (degraded, never silently wrong); an object whose header also fails is reported in a joined error alongside the successful names — loud, availability-preserving, and never hiding the cloud's misbehaviour.

### What the cloud still sees

Stated here because overpromising privacy is worse than not promising it. With everything above in place, the storage provider still observes: the bucket's existence and name; object **count**; individual ciphertext **sizes** (≈ plaintext + 131 B + sealed name); **logical name length, quantized to 32-byte buckets** (the sealed-name length is a plaintext header field and is visible again as the metadata mirror's size); creation and access **timestamps and patterns**; the tree **shape** — depth via token count, and shared logical path prefixes visible as shared stored prefixes, so directory clustering (including the partition the reserved `system/` and `app/` first segments create) is legible even though the names are not — and everything it can infer from those. Chaining means equal segment names under *different* parents do **not** correlate. Hidden: name content, exact name length within its 32-byte bucket, and every byte of data. Not defended: rollback and suppression (above). **Padding is deliberately rejected for now** — meaningful size-hiding multiplies storage cost (the cost pillar pays real dollars per pad byte, forever) to blunt an adversary who retains timing and access-pattern channels padding cannot touch. The version byte is the door; adopting padding or access-pattern defenses is a threat-model ADR, not a patch.

---

## Key management

**The keys are the operator's, full stop.** PLAN 3.1's "operator-held keys, never stored with the cloud provider" is read literally: the keyring's rest state is the operator's disk, in the instance's local store, beside the mTLS CA key — the repo's one existing precedent for a secret whose loss is existential.

**File:** `<config>/instances/<name>/datasphere/keys.yaml` (directory `0700`, file `0600`), owned and written by the CLI/harness — the `datasphere` package itself never reads or writes it (Planck's "not where credentials live" rule). Format, versioned from day one:

```yaml
version: 1
name_keys:                        # stable name keys; the FIRST entry tokenizes and seals
  - id: 3c9d5f01a2b4e678          #   new writes, later entries stay readable during a
    key: <base64, 32 bytes>       #   future rename sweep
    created: 2026-08-26T00:00:00Z
keys:                             # rotatable KEKs; the FIRST entry wraps new writes,
  - id: 8f3a19c2d4e5b607          #   the rest decrypt old blobs (selected by the
    key: <base64, 32 bytes>       #   header's key ID)
    created: 2026-08-26T00:00:00Z
```

Every id is 8 random bytes (hex) — **never derived from the key**. The **name keys are structurally separate from the rotatable KEKs**, because deterministic name tokens cannot survive a key change without renaming every stored object: KEK rotation must never touch addressing. Both are lists from day one so that a future rename sweep — old and new name keys live simultaneously while objects migrate — is *representable* without a format migration. In memory the file loads into a `Keyring` whose `String()` redacts all material, with a test asserting no key bytes reach any log (the `RegistryToken` discipline) — **including on the parse path**, which is where the invariant was found to be broken at implementation: the YAML library renders a window of the *source* around a parse error, and on a nine-line `keys.yaml` that window contains the base64 key material, so a mis-indented hand edit would print both keys to stderr. Parse failures now report position and diagnosis with the library's rendered message withheld, and a test drives six corruptions to prove it. The Go surface is `NewKeyring`/`NewKey`/`ParseKeyring`/`Marshal`, the accessors `ActiveKEK`/`ActiveNameKey`/`KEKs`/`NameKeys`, `AddKEK` (rotation's whole shape: prepend), and `Merge` — which *is* the merge-only rule, in code, so every restore and import path inherits it rather than re-deriving it. `KeyEntry` keeps its material unexported: nothing outside this package can reach through the struct to print it.

**Restores and imports are merge-only.** Wherever a keys file is restored, imported, or reconciled — 3.3's `key import` is bound to this now — the semantics are *add missing entries, never overwrite or drop entries from the live file*. This is a security control, not a convenience: the blob's key ID is cloud-writable, so a tampering cloud can make any blob demand a key the keyring lacks, and the natural "restore from backup" response, done as an overwrite, would destroy every KEK appended since that backup.

**Rotation shape (permitted now, tooled later):** prepend a new KEK entry; new writes wrap under it; every blob header names its key ID, so old entries keep decrypting; a future `farcast storage rekey` (3.3+) rewrites the header's key ID, wrap nonce, and wrapped DEK (~68 bytes) without touching the body — possible precisely because the data seal's AAD excludes the key ID.

**What rotation does and does not recover — three scopes, stated so the incident response is right:** (a) all data *and all names* already stored under compromised keys are **permanently exposed** to any adversary that captured the ciphertext and headers — the cloud retains what it saw, and no rotation, rewrap, or sweep recovers it; (b) *future data* is protected as soon as a new KEK is active (and the cloud credentials are rotated); (c) *future names* remain exposed until name-key rotation via the rename sweep exists. Rewrap is nonce hygiene and keyring retirement — once nothing references an old KEK it can be deleted from `keys.yaml`, so theft of a stale backup stops decrypting current headers — **not** compromise recovery, and 3.3's `rekey` must say so in its output in mandated words, the way the key-loss warning is mandated below.

**The 3.2 boundary — resolved by [ADR 0008](../docs/adr/0008-in-cluster-key-delivery.md) and shipped.** The next phase gives in-cluster applications storage, and the path of least resistance there is a Kubernetes Secret — which is cloud-resident storage (etcd on the provider's machines). **No entry of the keyring ever rests on cloud infrastructure.** A KEK in a Secret converts encryption-at-rest into encryption-at-rest-except-the-key and guts this module's reason to exist. FatLine's server leaf in a Secret ([`fatline/README.md`](../fatline/README.md)) is not precedent: that is a rotatable *transport* key whose compromise exposes one listener's future sessions; this key *is the data*.

The mechanism chosen is per-scope derived subkeys (the ADR's K5), scoped: one in-cluster component holds **derived per-scope** material in memory only, pushed by the operator over the FatLine tunnel — the master KEK and the unrotatable master **name key** never enter the cluster at all. A restarted component comes back **sealed** and does not ask a peer for key material, because any principal an in-cluster mechanism can authenticate is a principal the cloud can forge. The price is stated rather than engineered away: after a node upgrade with the operator absent, in-cluster storage returns `ErrStorageSealed` until someone unseals it. That is a theorem, not a gap — a pod that could recover the key from cloud-resident state by running cloud-supplied code on cloud-controlled hardware would be a pod whose cloud can compute the same function. The ADR carries the proof, the rejected alternatives, and the honest statement that memory-only means *protected by Google not looking*.

The keyring type is memory-constructable precisely so this shape was reachable.

**What 3.2 actually shipped.** A `Scope` — a named subtree with its own name key and KEK, recorded in `keys.yaml` under a `scopes:` block. The keyholder is given one scope's keys and is *cryptographically* incapable of touching anything else: objects outside the scope are tokenized under a different name key, so it cannot even compute their stored names, and wrapped under a different KEK, so it could not unwrap them if it could. A `Scope` yields an ordinary `Keyring`, so a scoped `Store` is an ordinary `Store` holding different keys — **3.2 changed nothing about data at rest**, which is what let the golden-vector discipline be satisfied by not touching it.

Scope keys are *minted*, not derived. ADR 0008 specifies the stored-prefix derivation and freezes it at 4.x, after golden vectors and an independent reproduction; shipping an unreproduced derivation over real data would be exactly what this module forbids. Minted keys reach the same place — no master in the cluster, scope compromise bounded and rotatable — and 4.x can add derived scopes beside them without invalidating a byte.

The schema bump is conditional: a keyring with no scopes still marshals as version 1, byte-identically to every file previous builds wrote. One that *has* grown scopes is version 2, and an older binary refuses it outright rather than parsing it with the scope material silently dropped — which would hand an operator a keyring that looks complete and cannot read a whole subtree. Because `ExportKeyring` marshals the keyring, scopes ride the existing `key export`/`import` backup path for free; there is no second crown-jewel file to remember.

**Key loss is data loss, permanently.** Every keygen and every relevant error must say, in these words: *loss of `keys.yaml` is permanent, unrecoverable loss of all stored data — FarCast keeps no copy anywhere, by design.* This is strictly worse than CA-key loss (which costs a re-mint, not data). The supported backup is the one the operator already owes the CA key: copy the instance directory offline — both crown jewels in one gesture. A passphrase-armored `farcast storage key export`/`import` (stdlib `crypto/pbkdf2` + AES-256-GCM, versioned format, import merge-only per the rule above) is reserved for 3.3.

---

## The instance bucket

GCS bucket names are **globally unique across all of Google Cloud** — a namespace shared with every stranger on the platform. That makes deterministic names an attack surface: `farcast-<instance>` can be squatted (denial at best; at worst an adoption bug writes the operator's ciphertext into a bucket a stranger can read, delete, and watch), and a probeable name confirms the instance's existence to anyone. Planck's registry needed ownership discipline even in a *per-project* namespace; a global one inverts the presumption — every unrecorded collision is hostile until proven otherwise.

- **Name:** `farcast-<instance>-<8 random lowercase hex>` — 32 bits of entropy, minted by `datasphere.MintBucketName` so the rule lives once in the module that owns the concept rather than in whichever caller needs it first (the harness offers one now; the CLI mints and records one at 3.3) — the instance segment truncated if needed to fit GCS's 63-character cap — uniqueness rides the suffix; legibility rides the prefix (the operator auditing their cloud console must recognise their own resources, the same argument that records `Puller` in the registry design). Because of that truncation clause the name is **not invertible** to the instance: every ownership check receives the instance name from the local record, never derives it from the bucket.
- **Record before create** — the repo's own ordering for billable resources ([`farsight/cli` README](../farsight/cli/README.md) decision 5: local state is written before `CreateCluster`; decision 7 gives the teardown inverse). The bucket needs this discipline *more* than the cluster or the registry did: their names are deterministic and re-derivable, while the bucket's minted suffix exists nowhere but the record — so the name is written to the instance's `metadata.yaml` (a new `storage:` block mirroring the `registry:` block — `bucket`, `location`, `created_at`; pointer-typed so pre-3.1 metadata still loads; the schema change and its writer land with the 3.3 CLI wiring) *before* the create call. A crash between record and create leaves a record pointing at nothing, which the next ensure converges; the reverse order would leave a billable resource with no record, invisible to everyone. Thereafter the recorded name is the sole authority — never re-derived.
- **Ownership is an adapter invariant, verified in both directions** (Planck's hard-learned rule): `EnsureBucket` stamps labels `managed-by: farcast` and `farcast-instance: <name>` at create, and the conflict path is a strict **three-way split**: (1) create returns 409, inspect succeeds, our project and both labels ⇒ adopt (it is our own prior attempt); (2) inspect succeeds and *proves* the bucket is not ours ⇒ `ErrNotOwned`; (3) inspect **fails** — 403, or 429/5xx/timeout after the adapter's standard retries ⇒ a plain error naming the bucket, and the caller's record stays untouched, because on GCS a foreign bucket answers 403 while a bucket *we* created moments ago can too (IAM propagation) — conflating "proven foreign" with "could not inspect" is how an ensure orphans an owned, billable bucket behind a freshly minted name. The mint-new-suffix/update-record/retry loop on `ErrNotOwned` belongs to the **record-owning caller** — the 3.3 CLI ensure path (bounded, 3 attempts) — never to the adapter, which mints nothing; in 3.1 the operator is that caller: the harness passes `--bucket` verbatim and surfaces `ErrNotOwned` for the operator to mint a new name. A *persistent* 403 on the recorded name is overwhelmingly a prior own create or a credential problem — a squatter would have had to guess 32 random bits that never left this machine — so it is surfaced for investigation (inspect the bucket in the console; deliberately clear the storage record to re-mint only once it is confirmed foreign), never auto-minted around. A **fourth outcome, added at implementation**, sits deliberately outside the split: labels ours but *posture* not (uniform access off, public-access prevention not enforced, a different location). A bucket FarCast created always carries the full posture, and a bucket whose metadata a stranger could have made readable could not — so this is a reason to look, not proof of a foreign owner, and it is a plain error that leaves the record alone. What is deliberately **not** checked is project identity: it would require a Cloud Resource Manager permission outside the IAM grant this module asks for, and the residual — an adversary who guessed the recorded random suffix, forged both labels, carried the full posture, and made the bucket readable to a service account they do not know — costs availability, never confidentiality, because everything written is ciphertext. Recorded in [`docs/gcs-provider.md`](docs/gcs-provider.md). `DeleteBucket` runs the same full label check *first* — including the instance match from `BucketRef.Instance` — and refuses a non-matching bucket with `ErrNotOwned`, naming what differs. The enforcement point for the write path: the composition root (harness now; CLI and service later) runs `Validate` with the recorded ref before constructing a `Store`, so even tampered local metadata cannot point writes at a stranger's bucket.
- **Teardown to completion:** verify ownership → **re-read the bucket's soft-delete policy and reset it to zero first** (an org policy may have forced it back on since create; already-soft-deleted objects retain under the policy in force at their deletion time, so the reset must precede the deletes) → delete every object, paging and honouring ctx (GCS has no force-delete; a bucket-delete 409 on a non-empty bucket must never be misread as "already gone") → delete the bucket, blocking until removal completes → only then clear the local record. If the policy reset is refused because an org policy forces retention, the teardown must say so **before** the record is cleared — naming the retention window and that deleted ciphertext remains held and billed until it lapses — and `farcast release`'s confirmation must carry the same statement; anything less reports "nothing left billing" while retained copies bill for days. Any failure keeps the record so a re-run converges. An absent bucket is success. `release`'s confirmation (3.3) must name the bucket, its object count and byte size, and say the data becomes permanently unreadable — unlike registry images, which derive from Git, stored data derives from nothing.
- **Posture, set at create and spec-mandated, not adapter discretion:** single-region in the instance's region; storage class `STANDARD`; uniform bucket-level access **on**; public-access prevention **enforced** (deny-by-default, applied to storage: even a future IAM mistake cannot make the bucket public); versioning **off**; and **soft delete disabled** (`softDeletePolicy.retentionDurationSeconds: 0`) — GCS's 7-day default both *bills* for retained copies of deleted ciphertext and *retains* data the operator ordered destroyed, offending both pillars at once. Consequence stated plainly: deletes are immediate and final. The adapter reads the policy back after create and warns if an org policy forced it back on — and re-checks at teardown, per above. `Validate` reads the same policy on the same call but deliberately does not report it, because a warning delivered at the gate that guards `Store` construction becomes an outage in the hands of a caller that treats validation errors as fatal ([Decisions](#decisions) 13).
- **Cost: surfaced, not gated.** A bucket has no fixed fee — $0.00 until data is written, then storage GiB/month plus operations. ADR 0007 decision 8's argument applies verbatim: gating cents trains the operator to click through the ~$18/month carrier gate that matters. The first ensure prints the price model as a line item; the ownership labels are what TechnoCore's cost attribution (4.1) will key on; usage reporting arrives with 3.3.

**When the bucket is ensured: lazily, at first storage use.** Not at `farcast install` — that flow is shipped and validated, an empty bucket costs nothing and serves nothing, and the registry's defensive-ensure precedent already proves lazy convergence ("an instance created before instances had registries converges on the next reconnect"). Every 3.3 storage command and the future 3.2 service path ensure defensively; `farcast release` deletes unconditionally either way.

---

## First adapter: GCS

Matching the Phase 1 cloud. The adapter is **hand-issued REST over the vendored auth stack** — the exact pattern of the registry capability ([ADR 0007](../docs/adr/0007-instance-owned-image-registry.md) decision 2, [`planck/internal/providers/gke/registry.go`](../planck/internal/providers/gke/registry.go)) — under the same **zero-new-vendored-module budget** (31 before, 31 must remain after).

- **Surface: ~10 JSON-API calls** (8 shipped at 3.1, plus resumable upload and ranged reads at 3.3); all `net/http` + `encoding/json`: `buckets.insert` (labels, PAP, UBLA, versioning, soft-delete-zero in the body), `buckets.get` (ownership inspect; also the soft-delete re-check at Validate and teardown), `buckets.patch` (the teardown-time soft-delete reset), `buckets.delete`, `objects.insert` via **`uploadType=multipart`** (stdlib `mime/multipart`; a JSON metadata part carrying `farcast-name` plus the media part, in one atomic request — `uploadType=media` cannot set metadata, so multipart is load-bearing, not an optimization), `objects.get?alt=media`, `objects.list` (`prefix`, `pageToken`, `prettyPrint=false`, `fields=items(name,size,metadata),nextPageToken`, under its own multi-megabyte response cap — a full page of long names and their sealed-name mirrors is *not* kilobytes, and sharing the error-envelope cap made long-keyed buckets permanently unlistable), `objects.delete` (404 ⇒ success).
- **Auth stays vendored.** Credential resolution, token minting, and refresh live inside `cloud.google.com/go/auth` (`httptransport.NewClient` owns the `Authorization` header) — the half [ADR 0006](../docs/adr/0006-connect-bootstrap-kubectl.md) refused to re-own. A configured key is loaded as a service account *and nothing else*, so an external-account credential file cannot redirect token minting (the guard the registry adapter already applies).
- **Named wire traps, each with a test:** the `/` separators in tokenized object names must be percent-encoded in the URL *path* on object endpoints — a raw `/` changes the route. In the `prefix` *query parameter*, standard percent-encoding as produced by `url.Values` is correct and equivalent to a raw `/` (the server decodes query values; the only real query-side bug is double-encoding). And the metadata-returned-in-default-list-projection assumption behind one-round-trip `List` must be verified against a real bucket in the first integration run, before the List cost claims freeze.
- **Streaming: resumable upload and ranged reads (3.3).** Two more calls, and the revisit trigger this spec set for itself has now fired. `PutStream` buffers up to **8 MiB**; if the stream ends inside that window it goes out as the shipped single `uploadType=multipart` request, so a small streaming write costs exactly one call and nothing changes for the common case. Above it, a resumable session: `POST …?uploadType=resumable` for a session URI, then `PUT`s with `Content-Range`, then completion. `GetStream` is `objects.get?alt=media` with a `Range` header. **Named traps, each owed a test:** Go's `net/http` treats `308 Resume Incomplete` as a redirect, so the client sends `X-GUploader-No-308` *and* sets `CheckRedirect` to `http.ErrUseLastResponse` — belt and braces, because the bare 308 works today only by accident of GCS omitting `Location`. A resend queries the committed offset first (`Content-Range: bytes */*`) and never blindly re-PUTs; a `200`/`201` to that query means the upload finished and the acknowledgement was lost, which is success. A `404` means the session is gone — restart from zero under a **fresh DEK**, never resume an old one over a possibly-different byte stream. A stream ending exactly on a window boundary still needs its zero-length terminator or the object is never finalized. The abort (`DELETE <session>`) runs on `context.WithoutCancel`, because the overwhelmingly common reason to abort is that the context died. And a `200` in answer to a `Range` request is an **error**, not a fallback: it means a proxy stripped the header, and accepting it turns a 1,168-byte header probe into a 5 TiB download at the wrong offset. Whether an abandoned resumable session is billable storage on GCS is **unverified** and goes in the Phase 3 runbook — on S3 the equivalent famously is.
- **The dependency verdict, on the measurement already taken.** Decision 8 named streaming as the trigger to re-open the trade, and it is re-opened here and closed the same way. `cloud.google.com/go/storage` is +18 modules and 18 forced upgrades of modules the shipped Planck provider already depends on; `google.golang.org/api/storage/v1` is +1 (`github.com/google/uuid`) with no version churn and is the only official option that implements resumable upload. Against +1, the counter-argument is the CLI's own precedent: it hand-rolled a **3,097-line** OCI distribution client, chunked blob upload and all, rather than vendor into the binary that holds the operator's cloud credentials and the instance's CA key ([`farsight/cli` decision 11](../farsight/cli/README.md)). Resumable upload is a fraction of that. **Hand-rolled; the budget stays at 31.** The cost lands as code FarCast owns and must test — which is what the named traps above are.
- **Retries are owed, and bounded:** hand-rolling means the adapter carries its own jittered exponential backoff on 429/5xx, ctx-honouring, whole-request only — every operation here is safely retryable (uploads are atomic per stored name, deletes are absent-is-success), and a partial resume of a multipart body must never exist (a truncated ciphertext would fail `ErrIntegrity` only at read time, long after the write).
- **The measurement clause — MEASURED, 2026-08-27** (ADR 0007's inspect-the-diff discipline; intuition has failed in both directions before). Both candidates were run through `go mod tidy && go mod vendor` in throwaway copies, after a control run confirmed the 31-module baseline is stable under `tidy` on its own:

  | candidate | modules | delta | forced upgrades of already-vendored modules | vendor size |
  |---|---|---|---|---|
  | `cloud.google.com/go/storage` v1.65.1 | 31 → **49** | **+18** | **18** | 24 M → 42 M (1164 → 2047 `.go` files) |
  | `google.golang.org/api/storage/v1` (module already vendored) | 31 → **32** | **+1** (`github.com/google/uuid`) | 0 | 24 M → 25 M |

  The spec was exactly right about (b): `go mod why` confirms `storage/v1` → `internal/gensupport` → `github.com/google/uuid`, verbatim. It **materially understated (a)**: `cloud.google.com/go`, `cloud.google.com/go/iam` and transitives are indeed in the set, but the bulk is unguessed — the GCS client's gRPC/DirectPath and built-in client-side metrics drag an entire xDS + SPIFFE + OpenTelemetry-SDK stack (`cel.dev/expr`, `cncf/xds/go`, `envoyproxy/go-control-plane/envoy`, `envoyproxy/protoc-gen-validate`, `spiffe/go-spiffe/v2`, `go-jose/v4`, `planetscale/vtprotobuf`, three `opentelemetry-operations-go` modules, `otel/sdk` + `sdk/metric` + `contrib/detectors/gcp`, `cloud.google.com/go/monitoring`). **A second cost the clause did not ask about and the record should carry:** (a) also force-upgrades 18 modules the shipped Planck provider already depends on — `grpc` 1.80.0 → 1.82.1, the whole `otel` stack, `cloud.google.com/go/auth` 0.18.2 → 0.20.0, `google.golang.org/api` 0.274.0 → 0.287.1, five `golang.org/x` modules — so adopting it is not additive to DataSphere, it moves the dependency floor under Phase 1. (b) forces none. Neither measured zero, so **decision 8 stands on the measurement**, and Phase 3.1's zero-new-module budget is satisfiable only by the hand-rolled path. Numbers are version-specific: re-measure against the resolved version, not the module name. Revisit trigger: if 3.3's streaming `cp` forces the resumable-upload protocol into hand-rolled code, that phase's ADR re-measures — and should start from (b) at +1 with no version churn, which is also the client that actually implements resumable upload.
- **IAM & APIs:** the installer service account needs bucket create/get/patch/delete and object CRUD — `roles/storage.admin`, granted (recommended) with an IAM condition scoping it to `farcast-*` bucket names so the stored credential never holds power over unrelated buckets; exact condition shape (the documented resource-type-guard pattern) verified and recorded in the Phase 3 runbook at implementation, alongside enabling `storage.googleapis.com`.

Crypto is stdlib only — `crypto/aes`, `crypto/cipher`, `crypto/rand`, `crypto/hkdf`, `crypto/hmac`, `crypto/sha256` (Go 1.26; no reach into vendored `golang.org/x/crypto`, which stays an indirect dependency). YAML rides the already-vendored `goccy/go-yaml`. **Expected new modules for all of Phase 3.1: zero.**

---

## The `cmd/datasphere` harness

Long term, `cmd/datasphere` is DataSphere serving inside the instance (a 3.2-era question). For 3.1 it is a thin operator harness, exactly `cmd/planck`'s role: exercising the full stack against real credentials before the CLI wires it in.

```
datasphere keygen        --keys keys.yaml                     # mint a keyring (0600) + the key-loss warning
datasphere validate      --provider gcs --project P --location R [--credentials key.json] [--bucket B --instance NAME]
datasphere ensure-bucket --provider gcs ... --instance NAME --bucket B
datasphere delete-bucket --provider gcs ... --instance NAME --bucket B
datasphere put <key> <file>   --provider gcs ... --bucket B --keys keys.yaml
datasphere get <key> [file]   ...
datasphere ls  [prefix]       ...   [--tokens]                # --tokens prints the stored names — the visible proof the cloud sees only opaque tokens
datasphere rm  <key>          ...
```

The operator mints the bucket name (the harness has no record to write); on `ErrNotOwned` the harness surfaces the refusal and the operator picks a new name — the record-owning retry loop arrives with the 3.3 CLI. Every verb goes through the full `Store`. **There is deliberately no raw/plaintext bypass mode** — a debug flag that ships plaintext to the bucket is a standing footgun aimed at the first pillar, and it does not exist, in the harness or anywhere else.

---

## Testing strategy

Storage costs real money and the blob format is data at rest, so the pyramid is Planck's plus one discipline Planck never needed — **golden vectors**:

- **Unit tests (CI, every commit).**
  - `internal/crypto`: round-trip; **golden known-answer vectors as fixed hex literals** (via an injectable rand seam) freezing the blob format, both AAD layouts (data AAD = `magic ‖ version ‖ logical key`, wrap AAD = `magic ‖ version ‖ key ID`), the sealed-name interior (uint16 BE prefix, 32-byte padding unit), the HKDF parameters, and the chained name tokens — written so a well-meaning refactor cannot regenerate them from the changed code, because an unpinned format change is silent data loss; bit-flip tamper in every header region and the body, each landing where that region is actually authenticated — every region except the sealed name fails `Open` with `ErrIntegrity`, and the sealed name fails `HeaderName`, which is the path that reads it (see [Decisions](#decisions) (12)); a test asserts the region list tiles the whole blob, so no byte escapes the sweep; the swap test (two objects, stored bytes exchanged, both reads fail on AAD); sealed-name transplant ⇒ detected; foreign key ID ⇒ `ErrUnknownKey`; **the rekey property** (rewrite key ID + wrap fields under a new KEK, body untouched ⇒ read still succeeds — pinning that the data AAD excludes the key ID); one-DEK-per-write pinned by test; a non-normalized Unicode logical key round-trips byte-exactly; caps and `ErrInvalidKey` cases; non-segment-aligned prefix filtering and sort order.
  - `Store` over an in-memory fake `Provider` — including the test that matters most: **assert on what the fake received** — no plaintext byte and no logical name ever reaches a Provider.
  - The GCS adapter over a fake `http.RoundTripper`: exact URLs and bodies (percent-encoding of tokenized names in object paths, multipart framing, labels + PAP + UBLA + soft-delete-zero present in the insert body), pagination, 404 ⇒ `ErrObjectNotFound`, delete-absent ⇒ success, retry-then-succeed on 503, and the full 409 three-way split: 409 ⇒ inspect succeeds + our labels ⇒ adopt; 409 ⇒ inspect succeeds + wrong labels ⇒ `ErrNotOwned`; **409 ⇒ inspect 503 ⇒ plain error, no adoption**; **409 ⇒ inspect 403 ⇒ plain error naming the bucket**; `DeleteBucket` with a mismatched `farcast-instance` label ⇒ `ErrNotOwned`; the teardown soft-delete re-check: policy forced on ⇒ the reset is attempted and the refusal surfaced — no listener, no network.
  - Redaction tests: `Config` and `Keyring` `String()` must render no credential and no key material, minted or zero-value — and no *parse* failure of a corrupt `keys.yaml` may echo key bytes either, driven by six real corruptions (mis-indent, tabs, wrong type, key material transposed into an `id` field, unterminated flow, duplicate field), each verified to leak before the fix.
- **Integration tests (gated, never in CI).** `//go:build integration`, `FARCAST_GCS_TEST_*` env vars: a cheap read-only `Validate`; the full ensure → put → list → get → rm → delete-bucket lifecycle behind an additional `FARCAST_GCS_TEST_BUCKET=1`, with teardown registered **before** the first create (a leaked bucket is billable storage nobody is watching), a re-ensure before delete to prove idempotence, and the metadata-in-list-projection verification recorded above.
- **Guardrails.** `go test -race`, `go vet`, `gofmt`, `golangci-lint` — per [AGENTS.md](../AGENTS.md), non-negotiable.

---

## Decisions

1. **Encryption lives above the Provider, in one place** (proposed). Adapters receive only ciphertext under tokenized names, so the blind-cloud pillar is a structural invariant, not a per-adapter promise; the crypto is written and audited once, and 8.2's S3 adapter inherits it untouched. Rejected: crypto per adapter (a per-cloud opportunity to leak plaintext) and crypto in the SDK (3.3's CLI and the harness need it without importing the SDK module).
2. **Envelope encryption with single-use DEKs; random nonces; every GCM key's nonce budget stated** (proposed). Data seals cannot collide (single-use DEKs); KEK wraps are bounded ~2³² writes per KEK with rotation as the reset; name seals ride a per-object derived key whose fixed plaintext/AAD makes collisions information-free — chosen because the name key is the one key that cannot rotate, so it must not carry a budget. The data seal's AAD deliberately excludes the key ID so rekey is a header rewrite; transplants are already defeated by single-use DEKs and the logical-key binding. Key IDs are random bytes, never key hashes (an offline key-check oracle).
3. **Name privacy via path-chained HMAC tokens plus a sealed dual-copy logical name** (proposed). Plaintext names would hand the cloud the semantic map of the data; a central encrypted index is a read-modify-write serialization point whose corruption is total name loss — per-object self-description has no shared mutable cloud state and degrades one object at a time. Chained tokens confine equality leakage to shared path prefixes — the minimum any List-compatible scheme reveals; flat per-segment tokens were rejected for leaking segment equality across unrelated parents, with the reserved `system/`/`app/` literals as known plaintext. The metadata mirror makes `List` one call per page; the header copy makes every blob self-contained. 16-byte token truncation is frozen by golden vectors. Padding is rejected on the cost pillar; the version byte is the door.
4. **The keyring separates stable name keys from rotatable KEKs, both as id-carrying lists, versioned from day one** (proposed). Deterministic tokens cannot survive key change, so addressing and rotation are decoupled structurally; list shape makes a future rename sweep representable without migrating the most dangerous file in the system; and every restore/import is merge-only, because the blob's key ID is cloud-writable and an overwrite-restore is the key-loss catastrophe a tampering cloud would steer the operator into.
5. **Bucket lifecycle sits in the `Provider` proper — a deliberate departure from Planck's optional-capability shape** (proposed). Planck's registry is optional because a compute cloud without image hosting is still a complete compute provider; no object-storage provider is complete without a bucket, so optionality here would be fake. Privilege separation for a future in-cluster consumer is the credential's job (IAM scope), not the Go interface's.
6. **The operator-held-key invariant binds Phase 3.2 now** (proposed). No keyring entry ever rests on cloud infrastructure; a Kubernetes Secret is cloud-resident storage, and the FatLine-leaf precedent does not transfer. Left silent, 3.2 would default to a Secret by inertia and gut the module's reason to exist; fixed now, the 3.2 ADR argues mechanisms, not principles.
7. **Global-namespace bucket discipline: random suffix, record-before-create, ownership verified in both directions with the instance supplied from the record, a three-way conflict split, soft delete off and re-checked at teardown** (proposed). A deterministic name is squattable and probeable; an unrecorded resource is invisible billing; an unverified delete can destroy a stranger's data; an ensure that treats "could not inspect" as "proven foreign" orphans its own billable bucket; and GCS's soft-delete default bills for ciphertext the operator ordered destroyed — including when an org policy forces it back on after create, which is why teardown re-checks. The ordering precedent is [`farsight/cli` README](../farsight/cli/README.md) decisions 5 and 7; the bucket needs the pre-create record more than the cluster or registry did, because its minted suffix is not re-derivable.
8. **Hand-issued REST over the vendored auth stack, measured** (proposed). Same credential-holding binary, same zero-new-module budget, same division as ADR 0007: own the boring wire protocol, never the auth. The official client's actual module delta is measured and recorded at implementation; a resumable-upload need at 3.3 reopens the trade there.
9. **The bucket is ensured lazily, not at install** (proposed). The install flow is shipped and validated; an empty bucket is $0 and serves nothing; defensive ensure on every storage path converges old instances, exactly as the registry does. `release` deletes unconditionally regardless.
10. **Logical-namespace conventions reserved now** (proposed): `system/` for FarCast's own data (5.3 secrets land under it), `app/<deployment>/<app>/` for applications (joining the image-path and future per-app identity shape). One reserved prefix today prevents a rename migration and an app squatting on `system/` tomorrow; enforcement arrives with 3.2's scoping.
11. **A forced retention window is reported as an error accompanying a *successful* operation** (added at implementation). The spec requires teardown to say, before the record is cleared, that an org policy is still holding and billing for ciphertext the operator ordered destroyed — but `DeleteBucket` returns only `error`, and the frozen interface is worth more than the convenience of widening it. So `ErrRetentionForced` is delivered the way `io.EOF` is: a classifiable sentinel wrapped around a result that did succeed. A caller that classifies it warns and proceeds; a caller that does not treats it as failure and retries, which is harmless because every operation it accompanies is idempotent. Both behaviours are safe, and neither reports "nothing left billing" while retained copies bill for days. Rejected: a `Notices` field (two mechanisms for one concern), a logger on `Config` (the shape is deliberately neutral data), and silence (the failure this exists to prevent).
12. **The sealed name in the header is authenticated where it is read, not on every read** (added at implementation, amending the draft). `Read` opens the body and never touches the header's sealed name, so a bit flip there returns the correct plaintext with no error; `HeaderName` — the path `List` falls back to, and the path recovery tooling uses — returns `ErrIntegrity` on the same damaged bytes. This was found by the tamper suite, which now asserts that boundary explicitly rather than papering over it. Verifying it on every read was considered and rejected: the sealed name is a *mirror* of a name the reader already supplied, and the body is bound to that logical key by the data AAD, so a damaged mirror cannot ever produce wrong plaintext — only an unrecoverable name. Refusing an otherwise perfectly authenticated object because a copy of its label was scratched trades data availability for no confidentiality at all, and it would put an HKDF and a GCM open in front of every read to buy it. The damage is still detected, loudly, on the path where it matters: `List` reports it in its joined error.
13. **`Validate` returns a plain yes or no; the forced-retention notice does not ride on it** (added at implementation). The spec has the adapter re-check soft delete at `Validate`, and the first implementation returned `ErrRetentionForced` from there. That is a trap: `Validate` is the enforcement point the composition root runs *before* constructing a `Store`, so a caller that treats a validation error as fatal — the only sane way to treat one — converts an org-policy warning into a total storage outage. The safe-fallback argument that justifies the sentinel on `EnsureBucket` and `DeleteBucket` (an unaware caller retries an idempotent operation) collapses here. Nothing is lost by the removal: every storage path ensures defensively (decision 9), and `EnsureBucket` reports the window from the same read.
14. **v2 is one chunked object per logical key, and its extension fields go *after* the sealed name** (3.3). Rejected: a manifest object plus N chunk objects, which needs no new adapter surface at all and was genuinely tempting on the dependency axis — but it concentrates an arbitrarily large object's only DEK in a 225-byte manifest whose loss orphans every chunk (billing, unlistable, unreadable), it makes a plain concurrent overwrite able to destroy *both* writers' data and the prior value, and its teardown gate would report an empty bucket while gigabytes sat in it. One object per key keeps v1's blast radius — losing an object loses exactly that object. Within that, the extension fields sit after the sealed name rather than before it so bytes 0–74+*L* are identical in every version forever: `ParseHeader`, `HeaderName` and `Rekey` stay one version-free implementation, which is the only thing holding up the promise that the bucket plus the keys file reconstruct every logical name with no local state.
15. **Streaming widens the `Provider`, and resumable upload is hand-rolled** (3.3). Optionality would be fake — every real object store streams — and `GetStream` is a correctness requirement of *shipped* behaviour, not a large-file feature: `Store.List`'s name-recovery fallback would otherwise download 5 GiB to read a 1,168-byte header. On the dependency half, decision 8's revisit trigger fired and closed the same way: +18 modules and 18 forced upgrades for `cloud.google.com/go/storage`, +1 for the generated client, against a CLI precedent of hand-rolling 3,097 lines of OCI distribution client rather than vendoring into the credential-holding binary. The budget stays at 31 and the named wire traps become ours to test.

---

## Roadmap

| Phase | Adds |
|---|---|
| **3.1** | ✅ `Provider` + registry, the encrypting `Store`, blob format v1, keyring format, the GCS adapter, `cmd/datasphere`, the test pyramid. Validated live on 2026-08-27 — see [the runbook](../docs/runbooks/phase-3-validation.md) |
| **3.2** | ✅ Scopes and the unseal bundle in the keyring; the `keyholder` package (seal state machine, HTTP surface, X25519 unseal envelope, TLS policy); `datasphere serve` and the workload renderer; the SDK's frozen storage contract with `ErrStorageSealed` and the status seam; `farcast storage deploy`/`state`/`unseal`/`seal`. Live validation pending — see [the 3.2 runbook](../docs/runbooks/phase-3-2-validation.md) |
| **3.3** | ✅ **Blob format v2** (chunked, streaming) and the `Provider` streaming pair; `BucketUsage`; hand-rolled GCS resumable upload and ranged reads. In the CLI: `farcast storage ls`/`cp`/`rm`/`usage`, the keyring lifecycle (`key export`/`import` (merge-only)/`rotate`/`rekey`), keygen at first use, the `InstanceMetadata` `storage:` block plus the mint/record/retry ensure path, and the bucket teardown wired into `release` behind a refuse-while-data-remains gate |
| 4.x | Per-app namespace scoping and TechnoCore cost attribution keyed on the bucket's labels |
| 5.3 | Secrets riding the same `Store` under `system/` |
| 8.2 | S3 adapter behind the same interface — S3's global namespace and 2 KB metadata cap are already accommodated (tags for labels, the 1024-byte key cap bounding the sealed-name mirror) |

---

## References

- The frozen wire format, as a second implementation would need it — [`docs/blob-format.md`](docs/blob-format.md)
- GCS wire protocol, traps, IAM, and what is still unverified — [`docs/gcs-provider.md`](docs/gcs-provider.md)
- Live validation against a real bucket — [`../docs/runbooks/phase-3-validation.md`](../docs/runbooks/phase-3-validation.md)
- Project overview — [`../README.md`](../README.md)
- Agent/architecture context — [`../AGENTS.md`](../AGENTS.md)
- Execution plan — [`../PLAN.md`](../PLAN.md)
- The exemplar module spec & provider pattern — [`../planck/README.md`](../planck/README.md)
- The frozen SDK storage contract — [`../sdk/go/README.md`](../sdk/go/README.md)
- Operator CLI & the instance's local store — [`../farsight/cli/README.md`](../farsight/cli/README.md)
- The network boundary (tunnel; the CA-key precedent) — [`../fatline/README.md`](../fatline/README.md)
- Backend language strategy (DataSphere stays Go) — [ADR 0002](../docs/adr/0002-backend-language-strategy.md)
- Dependency budget & ownership-label precedents — [ADR 0007](../docs/adr/0007-instance-owned-image-registry.md)
