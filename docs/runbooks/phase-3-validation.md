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

> **Status.** Executed end-to-end against a real GCP project on **2026-08-27** — all
> nine success criteria passed, including live confirmation that the cloud holds only
> opaque tokens and `FCDS`-prefixed ciphertext. The two assumptions this run existed to
> settle are both settled, one of them against the prediction written into this runbook.
> See [Findings](#findings-from-the-2026-08-27-run) at the end.

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
> `storage.buckets.list`.** GCP accepted the expression as written, and every
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

### Not covered by this run

- **The production credential shape.** This run used a dedicated `farcast-storage`
  service account. The spec puts the storage grant on the *installer* service account,
  which also holds container and Artifact Registry roles — that combination is
  unexercised, and 3.3 is where it lands.
- **A forced retention window.** No org policy on this project forces soft delete back
  on, so the `ErrRetentionForced` path was never triggered live. It is covered by unit
  tests only.
- **Scale.** Three objects, all small. The multi-page listing path, the 64 MiB object
  cap, and the multi-megabyte listing cap were not exercised against real GCS.
