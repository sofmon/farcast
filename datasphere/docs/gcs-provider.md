# GCS provider notes

Wire-level notes for [`internal/providers/gcs`](../internal/providers/gcs/), the
first `datasphere.Provider`. The module [README](../README.md) carries the
decisions; this page carries the details an implementer or a debugging operator
needs, and is explicit about which of them are **verified by test** and which are
**assumptions awaiting the first integration run**.

The adapter is hand-issued REST over the vendored `cloud.google.com/go/auth`
stack — the same division [ADR 0007](../../docs/adr/0007-instance-owned-image-registry.md)
settled for the instance registry: own the boring protocol, never own auth.
Credential resolution, token minting and refresh all stay inside the auth library;
`httptransport.NewClient` owns the `Authorization` header and nothing here touches
a bearer token by hand.

---

## Endpoints

Eight calls, all `net/http` + `encoding/json`.

| Operation | Method & URL |
|---|---|
| Credentials probe | `GET  /storage/v1/b?project=P&prefix=farcast-&maxResults=1&fields=items(name)` |
| Create bucket | `POST /storage/v1/b?project=P` |
| Inspect bucket | `GET  /storage/v1/b/{bucket}` |
| Reset soft delete | `PATCH /storage/v1/b/{bucket}` |
| Delete bucket | `DELETE /storage/v1/b/{bucket}` |
| Put object | `POST /upload/storage/v1/b/{bucket}/o?uploadType=multipart&fields=name` |
| Get object | `GET  /storage/v1/b/{bucket}/o/{object}?alt=media` |
| List objects | `GET  /storage/v1/b/{bucket}/o?prefix=…&pageToken=…&maxResults=1000&fields=items(name,size,metadata),nextPageToken` |
| Delete object | `DELETE /storage/v1/b/{bucket}/o/{object}` |

Host: `https://storage.googleapis.com`. Scope:
`https://www.googleapis.com/auth/devstorage.full_control` — the narrowest scope
covering bucket create/get/patch/delete plus object CRUD. `cloud-platform` would
also work and would hand the same token every other API in the project.

## Wire traps

**Object names must be percent-encoded in the URL path.** A stored name is a
tokenized path like `c9ce…/f6b2…/11a4…`; a raw `/` in the path changes the route
and addresses a different resource entirely. `url.PathEscape` escapes `/` to
`%2F`, which is exactly why it is used and why a plain path join would be a bug.
*Verified by unit test.*

**The `prefix` query parameter is the opposite case.** Standard percent-encoding as
produced by `url.Values.Encode` is correct there and equivalent to a raw `/` — the
server decodes query values before matching. The only real hazard on the query side
is **double**-encoding, which is why the prefix is set through `url.Values` at the
call site rather than pre-escaped by the caller. *Verified by unit test.*

**`uploadType=multipart` is load-bearing, not an optimization.** `uploadType=media`
cannot set object metadata at all, and a two-call upload-then-patch would leave a
window in which an object exists without the sealed name that identifies it —
precisely the torn state the `Provider` contract forbids. The body is
`multipart/related` with a JSON metadata part (`name`, `metadata`) followed by an
`application/octet-stream` media part. *Verified by unit test.*

**`softDeletePolicy.retentionDurationSeconds` is an int64 the JSON API renders as a
string.** It is typed as a string in the adapter rather than silently collapsing
"zero" and "unset".

**Object metadata in the list projection — VERIFIED 2026-08-27.** The
one-round-trip `List` rests on custom metadata being returned under the
`items(name,size,metadata)` field mask, and it is: confirmed against a real bucket
through the raw JSON API with the adapter's own mask, every entry carrying
`metadata.farcast-name`. `Store.List` costs one call per page as designed, and the
README's cost claims stand. Had it gone the other way, `Store.List` would still have
worked — it falls back to fetching each object and reading the authoritative sealed
name from the blob header — but at one full download per object. The gated
integration test keeps the assertion.

**`X-Goog-Meta-*` on `alt=media` downloads — MEASURED 2026-08-27: not sent.** The
JSON API does not return custom metadata as response headers on a media download, so
`Provider.Get` comes back with an empty metadata map on GCS, every time. That costs
nothing, because nothing depends on it: the encrypting layer reads names from
listings and, failing that, from the object's own authoritative header. The lift
stays in the code because the XML API and other clouds do send them, and an empty map
is the honest answer either way. The integration test *records* this rather than
asserting it — failing a suite over documented best-effort behaviour reports a
problem where there is none.

## Bucket posture

Set at create, spec-mandated, not adapter discretion:

```json
{
  "name": "farcast-<instance>-<8 hex>",
  "location": "<instance region>",
  "storageClass": "STANDARD",
  "labels": { "managed-by": "farcast", "farcast-instance": "<instance>" },
  "iamConfiguration": {
    "uniformBucketLevelAccess": { "enabled": true },
    "publicAccessPrevention": "enforced"
  },
  "versioning": { "enabled": false },
  "softDeletePolicy": { "retentionDurationSeconds": "0" }
}
```

Public-access prevention **enforced** applies deny-by-default to storage: even a
future IAM mistake cannot make the bucket public. Soft delete **off** is a cost and
a privacy decision at once — GCS's 7-day default both bills for retained copies of
deleted ciphertext and retains data the operator ordered destroyed. The consequence
is stated plainly wherever an operator can act on it: **deletes are immediate and
final.**

An org policy can force soft delete back on after create. The adapter re-reads the
policy at create and at teardown and reports it as an error wrapping
`datasphere.ErrRetentionForced` **alongside a successful result**. `Validate`
reads it too and deliberately stays silent: it is the gate the composition root
runs before constructing a `Store`, so a warning returned from there becomes a
storage outage in the hands of any caller that treats a validation failure as
fatal. A caller
that classifies the sentinel warns and proceeds; a caller that does not treats it as
a failure and retries, which is harmless because everything it accompanies is
idempotent. What must never happen is silence — a teardown reporting "nothing left
billing" while retained copies bill for days.

## Ownership: the three-way conflict split

GCS bucket names are globally unique across all of Google Cloud, a namespace shared
with every stranger on the platform. On a `409` from create the adapter inspects,
and the outcome is one of exactly three:

1. **Inspect succeeds, both labels ours, posture ours** → adopt. This is our own
   prior attempt.
2. **Inspect succeeds and PROVES the bucket is not ours** (a label absent or naming
   something else) → `datasphere.ErrNotOwned`, naming what differs.
3. **Inspect merely FAILS** — 403, or 429/5xx/timeout after retries → a plain
   error, **never** `ErrNotOwned`, and the caller's record stays untouched.

The third case is the expensive one to get wrong. On GCS a foreign bucket answers
403, and so can a bucket we created moments ago while IAM propagates; treating
"could not inspect" as "proven foreign" is how an ensure orphans an owned, billable
bucket behind a freshly minted name. The mint-new-suffix/update-record/retry loop
belongs to whoever owns the record — never to the adapter, which mints nothing.

A fourth outcome exists and is deliberately *not* `ErrNotOwned`: labels ours but
**posture** not (uniform access off, public-access prevention not enforced, or a
different location). That is a reason to look, not proof of a foreign owner, so it
is a plain error and the caller keeps its record.

**Residual risk, stated rather than hidden.** Ownership is established by the two
labels read through the operator's own credentials, on a name whose 32 random bits
were minted on the operator's machine and recorded locally. A project-identity check
is deliberately *not* made, because it would require a Cloud Resource Manager
permission outside the IAM grant this module asks for. For an adversary to be
adopted they would have to guess the recorded suffix before the create, stamp both
FarCast labels, carry FarCast's full posture, and make the bucket's metadata
readable by a service account they do not know — and the payoff is availability
damage only, because everything written is ciphertext.

## Teardown ordering

1. Inspect and prove ownership. This is the half that destroys data.
2. **Reset the soft-delete policy** — before any object is deleted. Already
   soft-deleted objects retain under the policy in force at the moment of *their*
   deletion, so a reset afterwards is too late for everything already gone.
3. Delete every object, paging and honouring `ctx`.
4. Delete the bucket. GCS has no force-delete: a `409` here means the bucket is not
   empty and must never be read as "already gone".

An absent bucket is success. Any failure leaves the caller's record in place so a
re-run converges.

## Retries

Hand-rolling the protocol means owning its transient-failure handling. The adapter
retries `429` and `5xx` with jittered exponential backoff, up to 5 attempts,
honouring `ctx`, **whole-request only**. Every operation here is safely retryable:
an upload is atomic per stored name, a delete treats absence as success, and the
reads are reads. What must never exist is a partial resume of an upload body — a
truncated ciphertext would pass silently at write time and surface as an integrity
failure on a read, long afterwards.

`403` and `404` are never retried: they are about the request, not the server.

## Response caps

Two, deliberately. An ordinary JSON response — a bucket resource, an error
envelope — is capped at 1 MiB, so a captive portal or a proxy error page cannot
make the credential-holding CLI allocate without bound. **Object listings get
their own, much larger cap**, because a page is a thousand entries and every
entry carries the object's name plus the metadata map holding its sealed logical
name. Sized from GCS's own per-object limits (1024-byte name, 8 KiB of custom
metadata) a full page can legitimately approach 9.5 MB; measured at what FarCast
itself writes, a page of maximum-length keys is ~2.5 MB.

Sharing the small cap was a real defect, not a theoretical one: an over-cap body
is refused outright on a non-retryable path, so a bucket whose keys were merely
long — well inside what the module advertises as legal — became permanently
unlistable, and `Store.List`'s header-fallback recovery never ran, because the
failure was in the page fetch rather than in any one object's mirror. A unit
test builds a full page at the worst case and asserts both that it exceeds the
ordinary cap and that the listing accepts it.

Listings also send `prettyPrint=false`. Google pretty-prints JSON by default,
which on a thousand-entry page is pure padding between the adapter and its cap.

Downloads are capped separately again, generously above the 64 MiB plaintext
limit. Every cap is enforced by reading one byte past it: hitting a cap is an
explicit error, never a silent truncation, because a clipped ciphertext would
travel back up as an ordinary blob and be reported to the operator as tampering.

## APIs and IAM

Enable the API:

```bash
gcloud services enable storage.googleapis.com --project "$PROJECT_ID"
```

The installer service account needs bucket create/get/patch/delete and object CRUD
— `roles/storage.admin`. Granting it unconditionally hands the stored credential
power over every bucket in the project, including ones FarCast never created, so
the recommended grant carries an IAM condition scoping it to FarCast's own names.
The documented resource-type-guard shape:

```cel
(resource.type != "storage.googleapis.com/Bucket" &&
 resource.type != "storage.googleapis.com/Object") ||
resource.name.startsWith("projects/_/buckets/farcast-")
```

The guard clause matters: a condition that only tested `resource.name` would also
deny permissions checked against resources that are neither a bucket nor an object,
breaking calls that have nothing to do with the scoping intent.

> **Status: VERIFIED 2026-08-27 against a live project.** GCP accepted the
> expression, and every operation the module performs succeeded under it — including
> the project-level `storage.buckets.list` behind the credentials probe, which an
> earlier draft predicted might be denied. The guard clause is exactly why it is not:
> `buckets.list` is authorized against the *project*, which is neither a Bucket nor an
> Object, so the first disjunct is true and the condition allows it. See
> [the Phase 3 runbook](../../docs/runbooks/phase-3-validation.md) for the run.
>
> Still unexercised: this ran on a dedicated `farcast-storage` service account, while
> production puts the grant on the *installer* account that also holds container and
> Artifact Registry roles. That combination lands with 3.3.
