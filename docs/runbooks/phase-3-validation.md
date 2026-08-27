# Runbook — Phase 3.1 Validation: Encrypted Storage Against a Real Bucket

**Goal.** Prove, against a real GCP project, that DataSphere creates a hardened
instance bucket, stores and retrieves data through the encrypting `Store`, and
destroys the bucket completely — and that **the cloud holds neither a readable name
nor a readable byte** while it does.

**What this exercises that the unit tests cannot:** real credentials and IAM
(including the recommended `farcast-*` IAM condition, which has never been run
against a live project), the Cloud Storage JSON API, the `409` adopt path against a
real name conflict, whether object metadata really is returned in the default list
projection, and whether soft delete stays off.

**Cost & time.** A bucket has no fixed fee: **$0.00 until data is written**, then
Standard single-region storage per GiB-month plus operations. This runbook writes a
few kilobytes for a few minutes, so the cost is effectively zero — but a *leaked*
bucket is billable storage nobody is watching, which is why step 9 is not optional.
Budget **~15 minutes**.

> **Status.** Executed end-to-end against a real GCP project on **2026-08-27**, in two
> passes: Phase 3.1 (all nine success criteria) and then Phase 3.3's streaming surface.
> The cloud was confirmed to hold only opaque tokens and `FCDS`-prefixed ciphertext,
> and every assumption either phase shipped on is now settled — three of them against
> the prediction written into this runbook. See [Findings](#findings-from-the-2026-08-27-run).

---

## 0. Set shared variables

Run everything below in one shell so these persist:

```bash
export PROJECT_ID="your-gcp-project-id"      # an existing project with BILLING ENABLED
export REGION="us-central1"
export KEY="$HOME/farcast-storage-key.json"  # where the SA key will be written
export INSTANCE="validate"
export WORK="$HOME/.farcast-storage-validation"
mkdir -p "$WORK" && chmod 700 "$WORK"
```

You also need the **gcloud CLI** authenticated as a user with Owner/Editor on the
project. That user auth is for the setup and verification commands below; DataSphere
itself uses the service-account key you create in step 2.

---

## 1. Enable the API

```bash
gcloud services enable storage.googleapis.com --project "$PROJECT_ID"
```

## 2. Create the installer service account + key

```bash
export SA="farcast-storage@${PROJECT_ID}.iam.gserviceaccount.com"
gcloud iam service-accounts create farcast-storage --project "$PROJECT_ID" --display-name "FarCast DataSphere validation"
```

Grant `roles/storage.admin` **with the condition that scopes it to FarCast's own
buckets**. An unconditional grant hands this stored credential power over every
bucket in the project, including ones FarCast never created:

```bash
gcloud projects add-iam-policy-binding "$PROJECT_ID" --member "serviceAccount:${SA}" --role roles/storage.admin --condition='expression=(resource.type != "storage.googleapis.com/Bucket" && resource.type != "storage.googleapis.com/Object") || resource.name.startsWith("projects/_/buckets/farcast-"),title=farcast-buckets-only,description=Scope FarCast storage admin to farcast-* buckets'
```

> **Verified 2026-08-27: this condition works, and it does *not* block
> `storage.buckets.list`.** It was also verified on the **installer** service account —
> the shape production uses, where one account holds container, Artifact Registry and
> conditional storage grants together.
>
> One operational wrinkle: `add-iam-policy-binding` immediately after
> `service-accounts create` can fail with `Service account … does not exist` while IAM
> propagates, even though the account exists enough to mint a key. Retry it.
>
> Original note follows. GCP accepted the expression as written, and every
> operation in this runbook — the project-level credentials probe, bucket create,
> adopt, object CRUD, and teardown — succeeded under it. An earlier draft of this
> runbook warned that the project-level list might 403; that prediction was wrong, and
> the guard clause is why: `buckets.list` is checked against the *project*, which is
> neither a Bucket nor an Object, so the first disjunct is true and the condition
> allows it. Nothing here needs the fallback that warning described.

Download the key — this is the credential DataSphere will use:

```bash
gcloud iam service-accounts keys create "$KEY" --iam-account "$SA" --project "$PROJECT_ID" && chmod 600 "$KEY"
```

## 3. Build the harness and mint a keyring

```bash
go build -o "$WORK/datasphere" ./datasphere/cmd/datasphere && cd "$WORK" && ./datasphere keygen --keys ./keys.yaml
```

The command prints the key-loss warning. Read it. Losing `keys.yaml` is
**permanent, unrecoverable loss of all stored data** — strictly worse than losing
the instance's CA key, which costs only a re-mint. Confirm the file is `0600`:

```bash
ls -l keys.yaml
```

## 4. Pre-flight — validate credentials (free, read-only)

```bash
./datasphere validate --project "$PROJECT_ID" --location "$REGION" --credentials "$KEY"
```

Expect `credentials OK`. See the warning in step 2 if this 403s.

## 5. Mint and record a bucket name

```bash
export BUCKET="$(./datasphere mint-name --instance "$INSTANCE")" && echo "$BUCKET" | tee bucket.txt
```

**Record it before creating anything.** The name's random suffix exists nowhere
else, and an unrecorded bucket is billable storage nobody is watching. This is the
same record-before-create ordering `farcast install` uses for the cluster.

## 6. Ensure the bucket

```bash
./datasphere ensure-bucket --project "$PROJECT_ID" --location "$REGION" --credentials "$KEY" --instance "$INSTANCE" --bucket "$BUCKET"
```

Run it a **second time** — it must succeed identically. That is the `409` adopt path
against a real conflict, and it is the one branch unit tests can only simulate.

Verify the posture independently of FarCast:

```bash
gcloud storage buckets describe "gs://$BUCKET" --project "$PROJECT_ID" --format="yaml(location,default_storage_class,labels,uniform_bucket_level_access,public_access_prevention,soft_delete_policy)"
```

Expect: the region, `STANDARD`, both labels (`managed-by: farcast`,
`farcast-instance: validate`), uniform bucket-level access **enabled**, public
access prevention **enforced**, and a soft-delete retention of **0**. If retention
came back non-zero, an org policy forced it on — the harness will have warned, and
that warning is the point.

## 7. Store and retrieve — the actual claim

```bash
printf 'the quick brown fox' > plain.txt
```

Define a wrapper rather than a `$COMMON` variable. An unquoted `$COMMON` word-splits
in bash but **not** in zsh, where the whole string arrives as a single flag and every
command fails — and zsh is the default shell on macOS. A function is correct in both,
and it relies on the harness accepting operands before flags:

```bash
ds() { ./datasphere "$@" --project "$PROJECT_ID" --location "$REGION" --credentials "$KEY" --instance "$INSTANCE" --bucket "$BUCKET" --keys ./keys.yaml; }
```

```bash
ds put app/blue/web/config.json plain.txt && ds put app/blue/api/config.json plain.txt && ds put system/instance.yaml plain.txt && ds ls && ds ls app/blue/ && ds ls app/blue/w && ds ls --tokens && ds get app/blue/web/config.json -
```

`get` must print `the quick brown fox` exactly. `ls app/blue/` must list both keys, and
`ls app/blue/w` — a prefix that stops mid-segment — must return only the `web` key.

`ls --tokens` is worth reading closely: the two `app/blue/*` keys share their **first
two** tokens and differ from the third onwards, while `system/` shares none. That is
path-chaining doing exactly what it promises — the cloud can see that two objects live
under a common parent, and nothing else.

**Now look at what the cloud actually holds.** This is the whole module in two
commands:

```bash
gcloud storage ls -r "gs://$BUCKET" --project "$PROJECT_ID"
```

```bash
gcloud storage cat "$(gcloud storage ls "gs://$BUCKET/**" --project "$PROJECT_ID" | head -1)" | head -c 64 | xxd | head -4
```

Expect: object paths that are **opaque 32-hex-character tokens**, matching the
stored names `ls --tokens` printed and bearing no resemblance to
`app/blue/web/config.json`; and bytes beginning with the magic `FCDS` followed by
ciphertext. The plaintext string must appear nowhere.

**Verify the list-projection assumption** — the one wire behaviour the adapter
assumes but has never confirmed:

```bash
gcloud storage objects describe "$(gcloud storage ls "gs://$BUCKET/**" --project "$PROJECT_ID" | head -1)" --project "$PROJECT_ID" --format="yaml(metadata)"
```

Expect a `farcast-name` key holding base64. If custom metadata is **absent from
listings**, `Store.List` still works — it falls back to reading each object's
authoritative header — but it costs one full download per object, and the List cost
claims in the module README must be corrected.

> **Verified 2026-08-27: metadata IS returned in the list projection.** Confirmed
> against the raw API with the adapter's exact field mask, not just through `gcloud`:
>
> ```bash
> curl -sS -H "Authorization: Bearer $(gcloud auth print-access-token)" "https://storage.googleapis.com/storage/v1/b/$BUCKET/o?fields=items(name,size,metadata),nextPageToken&maxResults=1000&prettyPrint=false"
> ```
>
> Every entry carried `metadata.farcast-name`. `Store.List` is one call per page as
> designed, and the README's cost claims stand.

## 8. Delete an object

```bash
ds rm app/blue/api/config.json && ds ls
```

Only `app/blue/web/config.json` should remain. Deletes are immediate and final —
soft delete is off by design.

## 9. Prove the ownership guard, then destroy the bucket

This must be **refused**, with nothing deleted:

```bash
./datasphere delete-bucket --project "$PROJECT_ID" --location "$REGION" --credentials "$KEY" --instance "some-other-instance" --bucket "$BUCKET"
```

Then the real teardown — **do not skip this**:

```bash
./datasphere delete-bucket --project "$PROJECT_ID" --location "$REGION" --credentials "$KEY" --instance "$INSTANCE" --bucket "$BUCKET"
```

Verify it is gone, independently:

```bash
gcloud storage buckets describe "gs://$BUCKET" --project "$PROJECT_ID" 2>&1 | tail -2
```

## 10. Clean up

```bash
gcloud iam service-accounts keys list --iam-account "$SA" --project "$PROJECT_ID"
```

```bash
rm -rf "$WORK" "$KEY"
```

Deleting `keys.yaml` here is safe **only because the bucket is gone**. In any real
instance it is the file whose loss ends the data. Remove the service account too if
this project is not being kept for further validation:

```bash
gcloud iam service-accounts delete "$SA" --project "$PROJECT_ID"
```

---

## Optional — the gated integration tests

The same lifecycle runs as Go tests, which also assert the wire details this runbook
only eyeballs. They are gated twice over and never run in CI:

```bash
export FARCAST_GCS_TEST_PROJECT="$PROJECT_ID" FARCAST_GCS_TEST_LOCATION="$REGION" FARCAST_GCS_TEST_CREDENTIALS="$KEY" FARCAST_GCS_TEST_BUCKET=1
```

```bash
go test -tags=integration -v ./datasphere/internal/providers/gcs/
```

That now includes `TestIntegrationStreaming` (Phase 3.3), which is the only
thing that exercises the resumable-upload protocol against the real service —
its 308 handling, its committed-offset query and its zero-length terminator are
edges a fake transport cannot falsify, because the fake is built from the same
understanding as the code. It moves ~20 MiB, spanning three upload windows.

**It also answers a question this project could not settle from documentation.**
The test starts a resumable session and abandons it, then logs what the bucket
reports. On S3 the equivalent — an incomplete multipart upload — famously *is*
billed until aborted and is invisible to an ordinary listing, which is why S3
buckets need a lifecycle rule for it. Whether GCS behaves the same decides
whether `farcast storage usage` owes the operator an "incomplete uploads" line.
Look for the lines the test logs as `FINDING:`, **check the bucket's billed size
in the cloud console before you delete it**, and record the answer below.

---

## Success criteria

1. `validate` succeeds with the condition-scoped credential (or the failure mode is
   recorded above).
2. `ensure-bucket` creates the bucket and a **second run adopts it** without error.
3. `gcloud` independently confirms: correct region, `STANDARD`, both ownership
   labels, uniform bucket-level access on, public access prevention enforced,
   soft-delete retention 0.
4. `put` then `get` returns the exact plaintext.
5. `ls` returns logical names; `ls --tokens` shows the opaque stored paths.
6. **`gcloud storage ls` shows only opaque tokens, and `gcloud storage cat` shows
   only ciphertext behind an `FCDS` magic.** No plaintext name, no plaintext byte.
7. `delete-bucket` with a **wrong** `--instance` is refused and deletes nothing.
8. `delete-bucket` with the right one leaves nothing behind, confirmed by `gcloud`.
9. The list-projection question is answered and recorded.


---

## Findings from the 2026-08-27 run

Recorded because the next person to read this should not have to re-derive them.

**1. The IAM condition works, and the warning this runbook carried was wrong.** GCP
accepted the resource-type-guard expression, and it did *not* block the project-level
`storage.buckets.list` the credentials probe uses. The guard clause is why: that call
is authorized against the project, which is neither a Bucket nor an Object. Step 2's
caution has been corrected in place.

**2. Object metadata IS returned in the default list projection.** Verified against
the raw JSON API with the adapter's own field mask. This was the one wire assumption
the module shipped on without proof, and it holds — `Store.List` costs one call per
page, and nothing in the cost model needs rewriting.

**3. `X-Goog-Meta-*` is NOT returned on `alt=media` downloads.** `Provider.Get`
therefore comes back with an empty metadata map on GCS, every time. Nothing depends on
it — a listing supplies names, and a blob's own header is the authoritative copy — so
this is the answer rather than a fault. The integration test now *records* it instead
of asserting it; asserting documented best-effort behaviour made the suite report a
problem where there is none.

**4. `storage.googleapis.com` was already enabled** on the Phase 1 project, so step 1
was a no-op. It is kept for a fresh project.

**5. The `$COMMON` idiom in step 7 was broken on zsh** — unquoted parameter expansion
does not word-split there, so every command received one long flag. Replaced with a
shell function, which is correct in both shells. This is the kind of thing only a live
walk finds.

**6. The blob format's overhead arithmetic checks out against a real object.** A
19-byte payload under the key `app/blue/web/config.json` stored as **182 bytes**:
75 header + 60 sealed name (12 nonce + 32 padded + 16 tag) + 12 data nonce + 19
ciphertext + 16 tag. Exactly what [the format spec](../../datasphere/docs/blob-format.md)
predicts.

**7. The second `ensure-bucket` adopted through a real 409**, which is the one branch
unit tests can only simulate.

**8. Teardown held through a test failure.** The integration suite failed on finding 3
mid-run, and its `t.Cleanup` teardown still removed the bucket — the project was left
with zero buckets. That ordering discipline is the difference between a failed test and
a billable resource nobody is watching.

**9. Nothing was left billing.** `gcloud storage buckets list` returns empty, and the
bucket 404s.

## 11. Phase 3.3 — streaming, on the same bucket

The harness is 3.1's and has no streaming verbs; the 3.3 surface is the
`farcast` CLI itself. With an installed instance:

```bash
mkfile -n 64m big.bin 2>/dev/null || head -c 67108864 /dev/urandom > big.bin
```

```bash
farcast storage cp ./big.bin validate:app/big.bin && farcast storage ls -l validate: && farcast storage cp validate:app/big.bin ./big.out && cmp big.bin big.out && echo "round trip byte-exact"
```

A 64 MiB file cannot fit the buffered format, so this proves the chunked v2 path
end to end. Then confirm what the cloud holds is still opaque:

```bash
gcloud storage ls -r "gs://$BUCKET" --project "$PROJECT_ID" && gcloud storage cat "$(gcloud storage ls "gs://$BUCKET/**" --project "$PROJECT_ID" | head -1)" | head -c 16 | xxd
```

Expect an opaque token path and an `FCDS` magic followed by version `02`.

Then the teardown gate, which should now refuse:

```bash
farcast release validate
```

Expect a refusal naming the object count and bytes, with nothing destroyed.
`farcast release validate --delete-data` is what proceeds.

---

### Not covered by this run

- **The production credential shape.** This run used a dedicated `farcast-storage`
  service account. The spec puts the storage grant on the *installer* service account,
  which also holds container and Artifact Registry roles — that combination is
  unexercised, and 3.3 is where it lands.
- **A forced retention window.** No org policy on this project forces soft delete back
  on, so the `ErrRetentionForced` path was never triggered live. It is covered by unit
  tests only.
- **Scale.** Three objects, all small. The multi-page listing path and the
  multi-megabyte listing cap were not exercised against real GCS.
- **Everything in Phase 3.3** — the streaming format, the resumable-upload
  protocol, ranged reads, `ObjectInfo.Created` in the list projection, and the
  `farcast storage` commands. Sections 11 and the gated integration run above
  cover them; neither has been executed. Two answers wait on that: whether an
  abandoned resumable session is billable, and whether the service honours
  `Range` the way the adapter assumes.


---

## Findings from the Phase 3.3 pass (2026-08-27)

**1. The streaming path works against the real service.** A 20 MiB resumable upload
spanning three windows, a streamed read-back hashed byte-for-byte, and ranged reads at
offset 0 and at 1 MiB all passed. This is the protocol a fake transport cannot falsify,
because the fake is built from the same understanding as the code.

**2. `ObjectInfo.Created` is populated from a real listing.** The `timeCreated` field was
newly added to the projection and had never run against GCS. `farcast storage usage` now
reports a real write window.

**3. The abandoned-session question is ANSWERED — and better than feared.** A resumable
session holding 8 MiB of never-finalized data is:

- invisible to `objects.list`,
- reported as **0 bytes** by `gcloud storage du`,
- **not enumerable at all** — GCS exposes no equivalent of S3's `ListMultipartUploads`,
- and, decisively, **does not block bucket deletion**: a bucket holding an outstanding
  session deleted cleanly.

So an interrupted `cp` cannot strand a teardown, which is what actually mattered. **The
design consequence is the one that was not obvious:** because they cannot be enumerated,
`farcast storage usage` *cannot* report an "incomplete uploads" line on GCS. That figure
was listed as deferred; it is not deferred, it is unavailable, and the spec now says so.

**4. The v2 framing overhead is exact against real objects.** A 64 MiB upload stored as
67,110,048 bytes — 1,184 bytes of overhead, which is 144 of header plus 65 frame tags:
64 full frames **plus the zero-length terminator**. The self-terminating rule, confirmed
on the wire rather than in a unit test.

**5. A 64 MiB round trip through `farcast storage cp` is byte-exact**, and the object
cannot fit the buffered format, so this exercised the chunked path end to end.

**6. The teardown gate behaves as specified.** `release` refuses while the bucket holds
data, naming the count and bytes; `--yes` does **not** imply `--delete-data`; and the
gate still works with `keys.yaml` removed — an operator who has lost their keyring can
still see what they are paying for and stop paying it.

**7. A cluster-delete failure leaves the data intact and the record in place.** Observed
for real (a credential without `container.clusters.delete`): nothing was destroyed, the
bucket and both objects survived, and the record was kept for a re-run.

**8. The production credential shape works.** The same bucket was reached and torn down
through the **installer** service account carrying container, Artifact Registry and
conditional storage grants together — closing the gap the 3.1 pass explicitly left open.

**9. `farcast storage` needs no cluster and no tunnel.** This pass ran against an
instance record with no cluster behind it at all, which is the claim
[Decisions 13](../../farsight/cli/README.md#decisions) makes.

### Still not covered

- **Scale.** Two objects. The multi-page listing path and the multi-megabyte listing cap
  are still unexercised against real GCS.
- **A forced retention window.** No org policy on this project forces soft delete back
  on, so `ErrRetentionForced` remains unit-tested only.
- **`storage key rekey` against a real bucket.** The keyring verbs were exercised only
  by unit tests in this pass.
