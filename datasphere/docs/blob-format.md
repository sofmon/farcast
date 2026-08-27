# DataSphere blob format v1

> Normative. This is data at rest: an unpinned change here is silent data loss for
> every object already stored. The version byte is the only supported way to change
> anything on this page.

This document is the recipe a second implementation — the S3 adapter (8.2), a
recovery tool, a non-Go reader — follows to produce or consume bytes identical to
the ones `datasphere/internal/crypto` produces today. The module
[README](../README.md) argues *why* the design is shaped this way; this page says
only *what* the bytes are.

The authoritative test vectors live in
[`internal/crypto/blob_test.go`](../internal/crypto/blob_test.go) as fixed hex
literals. They are deliberately not reproduced here, because two copies of a frozen
constant drift.

---

## Primitives

| Role | Algorithm | Parameters |
|---|---|---|
| Content and key wrapping | AES-256-GCM | 96-bit nonce, 128-bit tag |
| Subkey derivation | HKDF-SHA-256 | single-shot `hkdf.Key`, **nil salt**, **32-byte** output |
| Name tokenization | HMAC-SHA-256 | output truncated to 16 bytes, lowercase hex |
| Randomness | CSPRNG | `crypto/rand` |

Every key in the design is 32 bytes. Every nonce is 12 random bytes — including
where a fixed one would be provably safe, so that a future bug reusing a key
degrades to a bounded statistical risk instead of an instant catastrophe.

## Keys

Two structurally separate key kinds, both carried as ordered lists in `keys.yaml`:

- **Name key** (`name_keys[0]`) — stable. Everything about *addressing* derives from
  it. It cannot rotate without renaming every stored object, which is exactly why
  nothing in this design puts a nonce budget on it.
- **Key-encryption key** (`keys[0]`) — rotatable. It wraps per-object data keys, and
  each blob names the one it used by ID.

Every entry carries an 8-byte identifier that is **random material minted alongside
the key, never derived from it**. A key-derived ID would be an offline key-check
oracle for anyone holding a blob.

### Derived keys

| Key | Derivation |
|---|---|
| Name token key | `HKDF-SHA-256(secret = name key, salt = nil, info = "farcast/datasphere/v1/name-token", L = 32)` |
| Per-object name seal key | `HKDF-SHA-256(secret = name key, salt = nil, info = "farcast/datasphere/v1/name-crypt/" ‖ storedPath, L = 32)` |
| Data key (DEK) | 32 fresh CSPRNG bytes per write; never derived, never reused |

The per-object derivation for name sealing is what makes the name key's GCM budget
unbounded: a distinct key per object, over a plaintext and AAD fixed per stored
name, means a nonce collision produces identical ciphertext and reveals nothing.

## Logical keys

A logical key is an opaque byte string: non-empty, valid UTF-8, at most **1024
bytes** and **30** `/`-separated segments, no empty segment, no trailing `/`.

**No normalization, ever** — no Unicode folding, no slash collapsing, no trimming.
The key's exact bytes participate in authentication, so a canonicalization applied
on write but not on read turns valid data permanently unreadable.

## Stored path (name tokenization)

The logical key `seg₁/seg₂/…/segₙ` is stored under `T₁/T₂/…/Tₙ`, where

```
Tᵢ = lowercase_hex( HMAC-SHA-256(nameTokenKey, seg₁‖"/"‖…‖segᵢ)[0:16] )
```

— the HMAC of the exact joined logical path **prefix**, not of the segment alone.
Each token is 32 hex characters; `/` separators are preserved, so 30 segments
tokenize to 989 bytes, inside GCS's 1024-byte object-name limit.

Chaining confines equality leakage to shared path prefixes, which is the minimum
any prefix-listable scheme reveals. A per-segment construction would additionally
correlate every occurrence of a common leaf name bucket-wide.

**Prefix listing.** A cloud-side listing narrows to the longest `/`-aligned portion
of a logical prefix: for prefix `p`, take everything before the final `/`, tokenize
it as a path, and append `/`. A prefix with no `/` yields the empty stored prefix —
list everything and filter client-side. Recovered logical names are always filtered
against the *full* logical prefix afterwards.

## Sealed name

The logical name travels sealed, and the identical block is stored twice: in the
blob header (authoritative) and in the provider's metadata map under
`farcast-name`, base64 (standard encoding, padded) — the fast path that makes a
listing one call per page.

```
sealed name := nonce(12) ‖ AES-256-GCM-Seal(key = per-object name seal key,
                                            nonce,
                                            plaintext = paddedName,
                                            aad = storedPath bytes)
```

`paddedName` is canonical and has exactly one valid encoding per name:

```
paddedName := uint16_be(len(logicalKey)) ‖ logicalKey ‖ 0x00 * pad
len(paddedName) == ceil((2 + len(logicalKey)) / 32) * 32
```

Readers **must** reject a non-minimal length or a non-zero pad byte. Padding the
length prefix together with the name (rather than the name alone) is what makes the
encoding canonical; the 32-byte unit reveals a name's length only to the nearest
32-byte bucket.

The format version is bound into the name seal through the derivation's info
string, not through the AAD.

## Blob layout

| bytes | field |
|---|---|
| 0–3 | magic `FCDS` |
| 4 | version `0x01` |
| 5–12 | key ID of the KEK the DEK is wrapped under |
| 13–24 | wrap nonce (12 B) |
| 25–72 | wrapped DEK (32 B ciphertext + 16 B tag) |
| 73–74 | sealed-name length, `uint16` big-endian |
| 75 … | sealed name (as above) |
| … | data nonce (12 B) |
| … | data ciphertext ‖ 16 B tag |

Fixed overhead is 131 bytes plus the padded name: 75 header + 12 name nonce + 16
name tag + 12 data nonce + 16 data tag.

A zero-byte object is legal — the body is then a nonce and a tag over an empty
plaintext.

`Write` refuses a plaintext over **64 MiB**. Larger objects arrive as a chunked v2
format behind the version byte; no v1 migration will be required.

## Additional authenticated data

```
data AAD := "FCDS" ‖ 0x01 ‖ logicalKey bytes
wrap AAD := "FCDS" ‖ 0x01 ‖ keyID (8 bytes)
name AAD := storedPath bytes
```

Both blob AADs are fixed-width fields with a single variable field last, so they
are unambiguous without length prefixes.

**The data AAD deliberately excludes the key ID.** That exclusion is what makes
rotation a header rewrite — rewrite bytes 5–72 under a new KEK and every body stays
valid — and it costs nothing, because a body transplanted under a foreign header
fails GCM regardless (DEKs are single-use) and a cloud-side swap of two blobs fails
on the logical-key binding at read time.

## Write

1. Validate the logical key; refuse a plaintext over 64 MiB.
2. Draw a 32-byte DEK.
3. Draw a 12-byte wrap nonce; `wrapped = GCM-Seal(KEK, wrapNonce, DEK, wrapAAD)`.
4. Seal the name for the stored path.
5. Draw a 12-byte data nonce; `body = GCM-Seal(DEK, dataNonce, plaintext, dataAAD)`.
6. Assemble the layout above; write the sealed name into the metadata map too.

The draw order is fixed only so the golden vectors are reproducible from a seeded
reader. It is **not** part of the wire format: any writer drawing real randomness
produces a conforming blob.

## Read

1. Length-check and parse the header. Bad magic, an unknown version, a truncated
   blob, and a nonsensical sealed-name length are all the *same* error — a reader
   must not be able to tell "not a DataSphere blob" from "tampered with", and no
   answer here justifies returning plaintext.
2. Resolve the KEK by the header's key ID. A key the keyring does not hold is the
   one distinguishable outcome (`ErrUnknownKey`) — and, because the key ID is
   cloud-writable plaintext read before any authentication can run, an adversary
   chooses when a reader sees it. Nothing on that path may recommend a destructive
   recovery.
3. Unwrap the DEK; open the body with the data AAD built from the logical key the
   caller asked for.
4. Return the exact authenticated plaintext, or an error. Never both, never partial.

## Rekey

Rewrite bytes 5–12 (key ID), 13–24 (wrap nonce) and 25–72 (wrapped DEK) under the
new KEK. Every other byte — the sealed name and the whole body — is untouched.

Rotation is nonce hygiene and keyring retirement: once nothing references an old
KEK it can leave `keys.yaml`, so a stolen stale backup stops decrypting current
headers. It is **not** compromise recovery. Everything a cloud already saw stays
exposed to whoever captured it, and names stay exposed until a name-key rename
sweep exists.

## Nonce budgets

| GCM use | Invocations per key | Bound |
|---|---|---|
| Data seal | 1 (single-use DEK) | collision structurally impossible |
| KEK wrap | 1 per write | ~2³² writes per KEK (NIST SP 800-38D random-nonce bound); rotation resets it |
| Name seal | 1 per write, under a per-object key with fixed plaintext and AAD | unbounded by construction — a collision yields identical ciphertext |

## What this format does not defend

- **Rollback** — a cloud re-serving an older, validly-encrypted version of the same
  logical key.
- **Suppression** — a cloud omitting objects from a listing.

Freshness is a deliberate non-goal at v1, not an oversight.

**Key commitment.** AES-GCM is not key-committing. That is harmless under this
threat model — every key is locally minted from a CSPRNG, there are no
attacker-supplied keys and no multi-key trial decryption — and is recorded here so
that secrets (5.3) or any future passphrase-derived key re-opens the question
before reusing the v1 format.
