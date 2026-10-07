# Phase 5.3 — Live Validation

Phase 5.3 gives an application two things it has been compiling against since 0.2: configuration it can read, and secrets an operator provisions. The unit suite proves the refusals bite under mutation — 24 mutations, every one caught — and the cross-module tests prove the CLI writes the key Planck tells the application to read. What none of that proves is that a real application in a real cluster, handed a real ConfigMap, reads a real secret out of a real keyholder.

Designed by [ADR 0017](../adr/0017-application-secrets.md), on the keyholder [ADR 0008](../adr/0008-in-cluster-key-delivery.md) built.

**Walked 2026-09-10** against instance `p53` on GKE Autopilot in `us-central1`, released the same day. About 35 minutes of billing against a ~$77.17/month floor — roughly **$0.06**. Teardown verified independently against the cloud APIs, not from local state: no clusters, buckets, registries, forwarding rules, addresses, target pools, disks or VMs remained.

**All nine functional criteria passed**, including the uncomfortable one. The walk found **two defects no unit test could have found**, and — unlike [the 5.2 walk](phase-5-2-validation.md) — **both fixes were re-verified live on the same instance** before teardown.

The fixture is [`sdk/go/examples/demo`](../../sdk/go/examples/demo/main.go), deployed through [`manifest/examples/sdk-demo`](../../manifest/examples/sdk-demo/farcast) as two applications, `alpha` and `beta`.

---

## Prerequisites

An instance installed, connected, toolchain mirrored, kernel deployed, and a keyholder deployed and unsealed — the state [the 3.2 runbook](phase-3-2-validation.md) leaves behind. The builder's push grant applied **before** the first build ([the 4.2 runbook](phase-4-2-validation.md), and the 5.1b walk that proved what happens otherwise).

The application needs to do one thing this repository's sample applications do not yet do: call `farcast.Config()` and `farcast.Secrets()` and report what it got. Build a small one against `github.com/sofmon/farcast/sdk/go` that exposes an endpoint printing the *presence* — never the value — of each.

---

## 1. Does a secret written here reach an application there?

```bash
printf '%s' 'alpha-db-hunter2' | farcast secret set p53 alpha DB_PASSWORD
printf '%s' 'beta-db-s3cret'   | farcast secret set p53 beta  DB_PASSWORD
echo 'alpha-token-with-newline' | farcast secret set p53 alpha API_TOKEN
farcast secret ls p53
```

**Result: ✅.** `secret ls` listed three secrets by application and name and printed no value. `alpha` reported `state=present bytes=16` and `beta` reported `bytes=14` — each its own, on the first attempt, with no intervention between the write here and the read there.

This is the criterion the whole phase turns on: the operator's key and the application's key are computed in different packages from different inputs, and a divergence stores a secret nothing ever fetches. The rendered ConfigMap carried `FARCAST_SECRETS_PREFIX: app/secrets/alpha/`, and the CLI had written to exactly that.

The newline path worked as designed: `echo` appends a byte, the command stored **24** rather than 25 and said so — *"A trailing newline was removed; pass --raw to keep one."*

## 2. Is the object in the bucket actually opaque?

**Result: ✅.** Three objects, every path segment a hex token, no name containing `secrets`, `alpha`, `beta`, `DB_PASSWORD` or `API_TOKEN`. Every object began `FCDS` and continued as ciphertext; grepping all three for the plaintext values returned zero.

**One thing the walk measured that the ADR only asserts.** The stored sizes were 179, 187 and 177 bytes for secrets of 16, 24 and 14 bytes — a **constant 163 bytes of overhead**. The size is therefore the plaintext length exactly, and a secret drawn from a small set of differing lengths is identified by its stored size alone. That is [ADR 0017](../adr/0017-application-secrets.md)'s *What the cloud still sees*, confirmed to the byte rather than in principle.

## 3. Does the cluster hold the secret anywhere?

**Result: ✅.** The only Secrets in the namespace are `alpha-egress` and `beta-egress` — the egress credentials of [ADR 0013](../adr/0013-per-application-egress-identity.md). A cluster-wide sweep of every Secret and ConfigMap, base64-decoding each value, found **zero occurrences** of any of the three secrets. The phase's stated prohibition — *never in plaintext in K8s* — checked against the cluster rather than against the template.

## 4. Does the keyholder refuse an application that writes a secret?

Run from inside `alpha`'s pod, against the keyholder's data path, with the CA and server name the platform gave it:

```
GET    own secret        -> http=200  (returns the plaintext — an application may read)
PUT    own subtree       -> http=403  code=permission
DELETE own secret        -> http=403  code=permission
PUT    ordinary storage  -> http=204  (the rule is narrow and does not break storage)
LIST   secrets subtree   -> http=200
```

**Result: ✅.** Both mutations refused with the frozen `permission` code, before the body was read; ordinary storage untouched.

And the listing returned **all three keys, `beta`'s included** — which is [ADR 0017](../adr/0017-application-secrets.md) decision 4 behaving as written. Listing is deliberately not refused, because the parent prefix is listable by the same caller and a refusal would imply an enumeration boundary that does not exist.

## 5. Can one application read its neighbour's secret?

`alpha` was given `DEMO_PEER=beta`, derived `beta`'s subtree from its own prefix — exactly what a compromised application would do — and read through plain storage.

**Result: ✅ it succeeded, and that is the point.** `neighbour's secret name=beta/DB_PASSWORD state=present bytes=14`.

[ADR 0017](../adr/0017-application-secrets.md) decision 2 says the boundary is the **instance** and not the application, because every application shares one storage scope and the keyholder's data path authenticates only the server. This walk demonstrates it rather than taking the ADR's word for it, because an operator who assumed otherwise would put a payment credential behind it.

## 6. Does a sealed instance stop secrets, and say so?

```bash
farcast storage seal p53
```

**Result: ✅.** Within one tick the application reported `state=sealed`, `farcast: storage is sealed (no key material loaded)` — **not** `not-found`. An application that read a seal as absence would proceed without the credential.

This exercises the path [ADR 0008](../adr/0008-in-cluster-key-delivery.md) built the contract for: with every replica sealed the data Service has no endpoints, so the SDK's call fails at the dial and only the status endpoint can turn that into the sealed contract. It did.

`farcast storage unseal p53` restored service on the next tick with **zero restarts** — the pod's restart count was 0 before and 0 after.

*(Minor: `farcast storage seal` takes no `-y`, while `secret rm`, `run`, `connect` and `release` all do. An inconsistency, recorded rather than fixed here.)*

## 7. Does `Config()` refuse the platform's namespace in a real pod?

**Result: ✅**, and this is the check that matters more than the unit test, because the credential is genuinely present:

```json
{"key":"FARCAST_FATLINE_PROXY","in_environment":true,"env_bytes":130,
 "via_config":false,"require_err":"ErrConfigReserved"}
```

130 bytes of egress credential sitting in the environment; `Config().Get` reports absent and `Require` classifies it as reserved rather than missing. The application's own keys (`DEMO_GREETING`, `DEMO_WORKERS`, `DEMO_DEBUG`) read back correctly, and `DEMO_TIMEOUT=soon` produced exactly one warning naming the key and never the value.

## 8. Does the redaction hold on the wire?

The fixture deliberately logs a `Secret`, formats it every way `fmt` offers, and marshals it. What reached `farcast logs`:

```json
{"logged_directly":"[redacted]","fmt_v":"[redacted]","fmt_s":"[redacted]",
 "fmt_q":"\"[redacted]\"","fmt_hash_v":"farcast.Secret{[redacted]}","marshalled":"",
 "marshal_err":"json: error calling MarshalJSON for type *farcast.Secret: farcast: a Secret must not be serialized; call Reveal explicitly if that is what you mean"}
```

**Result: ✅.** Every route redacted, marshalling failed loudly, and grepping both applications' entire log streams for the three plaintext values returned **zero**.

## 9. Rotation and removal

**Result: ✅.** `--force` rotated to a 34-byte value and the running application reported `bytes=34` on its next tick — **without a restart**, because the SDK holds no cache. `farcast secret rm` then produced `state=not-found`, `farcast: no such secret` — not the stale value, and not a seal.

---

## What the walk found

### 1. No application FarCast has ever deployed knew its own name

Both applications logged themselves as **`app: demo`** — the executable's base name — and **`instance: local`**, the off-instance fallback, on a real instance. Neither `FARCAST_APP_NAME` nor `FARCAST_INSTANCE_ID` was set in the pod at all: Planck's ConfigMap carried the storage and secrets variables and nothing else.

The SDK has read those variables faithfully since phase 0.3, and the layer that should supply them never did. It went unnoticed for five phases because no fixture had ever logged through the SDK — every previous example application was `alpine` plus `curl`.

Two consequences, and the second is worse than the first. The `instance` and `app` fields the SDK stamps on every record — the ones an operator reads across a whole instance — were wrong on every line. And **two applications built from one image were indistinguishable in the log stream**: `alpha` and `beta` both claimed to be `demo`, while correctly reading their own separate secrets.

It also lands directly on this phase. [ADR 0017](../adr/0017-application-secrets.md) decision 9 justifies `Config()` refusing the `FARCAST_*` namespace on the grounds that *"identity moves to accessors so the refusal leaves nothing an application legitimately needed"* — and in production those accessors answered with a filename and the word `local`. The refusal was sound; the replacement it pointed at was not wired.

**Fixed and re-verified live:** Planck now renders `FARCAST_APP_NAME` per application and `FARCAST_INSTANCE_ID` when the deployment has an instance. After a redeploy the same two pods reported `instance=p53 app=alpha` and `instance=p53 app=beta`, each still reading its own secret. An empty instance renders no variable at all, because the SDK's own `local` fallback is a truer answer than a blank string that looks like an identity.

### 2. The CLI told operators to restart something that does not need restarting

`farcast secret set` ended with *"alpha reads it with farcast.Secrets().Get(ctx, …) **on its next start**."* The walk proved the opposite in section 9: the SDK holds no cache, so a running application picks up a rotation on its **next read**.

The message is wrong in the direction that costs something. It sends an operator to restart a workload needlessly, and — worse — it implies a rotation will *not* take effect until a restart, which is exactly the sort of thing somebody relies on while revoking a credential.

**Fixed and re-verified live:** the line now reads *"picks it up on its next read … — no restart needed."*

### 3. Smaller things, recorded rather than fixed

- **`cgr.dev/chainguard/kaniko:latest` no longer resolves at all** (`oci: not found`). [ADR 0011](../adr/0011-build-toolchain-mirroring.md)'s archived-Kaniko obligation is now overdue rather than theoretical. This walk mirrored `gcr.io/kaniko-project/executor` — Google's archived original — instead, and it built both applications without complaint.
- **There is no manifest field for application configuration.** `Config()` reads the environment, and the only two ways to populate it are `ENV` in the Containerfile or patching the rendered ConfigMap by hand. The walk used both. Patching also needs a pod restart, since `envFrom` resolves at pod creation — confirmed by watching the pre-restart tick still report the old value.
- **The keyholder's first replica crash-looped on a 403** until the bucket IAM grant propagated, exactly as the 3.2 runbook warns. The second unseal attempt then took both replicas to generation 2. Worth keeping the warning where it is.

---

## Re-walk after ADR 0018 decisions 1 and 5 — walked 2026-10-06

**Walked against instance `p54` on GKE Autopilot in `us-central1`, released the same day.** About three hours of billing against a ~$77.17/month floor — roughly **$0.30**, unreconciled against an invoice. Teardown verified independently against the cloud APIs rather than from local state: clusters, buckets, registries, forwarding rules, addresses, target pools, disks and VM instances all zero.

**Four of the five criteria passed. The fifth was not reachable** from a fresh install, and is recorded as unwalked rather than inferred from the other four.

Both toolchain images were re-checked before the walk and still resolved — which means [ADR 0011](../adr/0011-build-toolchain-mirroring.md) risk 4, the *fetcher* being re-tiered the way the builder was, has not happened. The mirrored digests were verified against the upstream `linux/amd64` manifests and matched exactly, so the instance's registry holds images identical to upstream and the command's claim that *"nothing here has to be believed"* is itself checked.

### 11. An unidentified client is refused at the handshake — ✅

From inside `alpha`'s pod, with the CA and server name the platform gave it, and no client certificate:

```
curl: (56) OpenSSL SSL_read: error:0A00045C:SSL routines::tlsv13 alert certificate required
http_code=000
```

**`http_code=000` — no HTTP status at all**, and the server's own alert names the reason. The *listener* refused. A 403 would have meant the listener accepted the connection and the handler refused, which is a strictly weaker property and the one a mutation had to expose in the unit suite because the test could not tell them apart.

### 12. Own objects served, every neighbour object refused — ✅

With the leaf Planck mounted (it arrives in the application's Secret, not its ConfigMap, which is right for a private key):

| Request, as `alpha` | Result |
|---|---|
| GET own secret | 200 |
| PUT own ordinary object | 204 |
| GET own ordinary object | 200 |
| PUT under own `secrets/` | 403 `permission` |
| DELETE own secret | 403 `permission` |
| GET `beta`'s secret, with `alpha`'s scope | 403 `permission` |
| GET `beta`'s secret, **claiming `beta`'s scope** | 403 `permission` |
| GET `beta`'s **ordinary** object, claiming `beta`'s scope | 403 `permission` |

The last two matter most: a compromised `alpha` explicitly asserting `beta`'s scope name is still refused, because identity is checked before the key is decoded. And ordinary objects are refused exactly as secrets are — so **"everything is separated"**, not merely "secrets are separated". This inverts [the original criterion 5](#5-can-one-application-read-its-neighbours-secret), where the neighbour read succeeded and the runbook said that was the point.

Confirmed in the key material too: `keys.yaml` gives each application its own **name key and its own KEK**. A neighbour can neither compute the stored name nor open the object — refused twice over.

### 13. A pre-upgrade application — ⏸ not reachable, not walked

This asks for an application deployed *before* decision 1 existed, then a keyholder upgraded underneath it. On a fresh install with today's binary every application gets a client leaf, so the state cannot occur. Walking it honestly needs a CLI built at `36db52e` deploying first, then today's binary upgrading the keyholder.

`storage deploy` does print the error path preemptively — *"Applications deployed before this keyholder hold no storage identity and will be refused by it. Run 'farcast run' again for each of them"* — so the CLI knows the condition and names the fix. That is not the same as watching it happen, and this criterion stays open.

### 14. `run` mints a scope per application, hands it over, and leaves a sealed keyholder sealed — ✅

**14a, hand-over.** `run` minted `app/sdk-demo/alpha/` and `app/sdk-demo/beta/` with the key-loss warning, then — the keyholder already serving — reported `The keyholder now holds alpha, beta's scope (generation 2)` and wrote **one ledger entry per replica, each with a distinct boot label**. The hand-over happened before the workloads existed.

**14b, sealed.** With the instance sealed, deploying a new namespace minted new scopes, reported them **waiting**, named `farcast storage unseal`, deployed the workloads anyway, and wrote **no ledger entry** — byte-for-byte identical ledger before and after. Repeated against a deliberate `--hold`: same result, hold still in force with its reason intact. A deploy did not clear an operator's decision.

The scopes minted while sealed were not stranded: the next unseal came back holding them.

### 15. An instance with no applications unseals — ✅

Run before anything was deployed, the only moment it is reachable:

```
replica 0  unsealed   generation 1
replica 1  unsealed   generation 1
2 of 2 replicas are unsealed at generation 1, holding no application scopes:
this instance has no applications yet.
```

An empty bundle, and the replicas became ready rather than refusing. Confirmed three ways — the unseal output, both pods going 1/1, and `storage key list` showing a keyring with no application scopes.

Waiting for the bucket IAM grant to propagate before unsealing got this at **generation 1 on a single attempt**, where [the first 5.3 walk](#3-smaller-things-recorded-rather-than-fixed) burned a generation on a premature attempt. The 403 crash-loop reproduced exactly as the 3.2 runbook warns; it is the normal path, not a flake.

### Regressions re-checked in passing

Both defects the first walk found are still fixed: applications logged `instance=p54 app=alpha` and `app=beta` and were distinguishable, and `secret set` says *"picks it up on its next read … no restart needed"*. Rotation without restart was observed directly — `state=not-found` at 14:09:20, `state=present bytes=16` at 14:09:50, pod restart count 0 throughout.

## What the re-walk found

Seven defects, none of them findable by a unit test. **Two were fixed and re-verified on `p54` before teardown**; five were recorded and deliberately not patched against a billing clock. Of those five, findings 4 and 5 were fixed afterwards (2026-10-06, not re-walked), and fixing them turned up two more — see the end of this section.

### 1. `storage unseal` wrote ledger entries with no boot label — fixed, re-verified

`run` and `keeper` both set `Boot` on the entries they write; the operator-unseal path did not, though the state it had just read carried one. Visible directly in `p54`'s ledger: the criterion-15 entries had no `boot`, the criterion-14a entries did.

The boot label is the whole audit primitive — one reseed per distinct boot is a cluster restarting, two into one boot is a live process being handed material it already held. An entry with no boot cannot be placed against a process, and **operator unseal is the most common way material reaches a keyholder**. It is one line, and it quietly weakened the detector that criterion 6 of [the 5.4 runbook](phase-5-4-validation.md) exists to test.

**Fixed and re-verified live:** new operator-unseal entries carry distinct boots where the pre-fix ones read `MISSING`.

### 2. `storage key list` showed a third of the keyring — fixed, re-verified

It read only master-level `NameKeys()` and `KEKs()`. `p54`'s keyring held **14 key ids** — two master, plus a name key and a KEK for each of six application scopes — and the command printed two.

A decision-5 regression: with one shared scope the master keys were nearly the whole story; with a scope per application they are a small minority, and the per-scope **name** keys are the unrotatable ones. An operator deciding whether a rotation covered everything was looking at a fraction of the keyring.

**Fixed and re-verified live:** all six scopes now listed with their prefixes and key ids.

### 3. A hold issued while a replica is down leaves the instance serving

Delete `datasphered-0`, then immediately `storage seal --hold`. The command reports `replica 0 NOT SEALED — 502 Bad Gateway` and holds replica 1. Replica 0 returns `restart-sealed`, carrying no hold; the keeper re-seeds it; the instance reports **"Storage is serving."**

So an operator who deliberately held the instance ends up with storage up, through ordinary restart timing rather than an attack. Nothing is hidden — the unreachable replica is named, and `seal --hold` already warns a hold lives only until the pod restarts. What is missing is follow-through: the command reads as instance-level, reports per-replica, and nothing flags that the instance as a whole is **not** held. No non-zero exit, no "re-run when all replicas are reachable".

### 4. `storage key rekey <instance>` is rejected as "a local path" — fixed, not re-walked

Its own usage says `rekey <instance>[:<prefix>]`, prefix optional. `parseLocator` treats an operand with no colon as a local path, so the documented bare form never reaches the instance branch — while `storage ls <instance>` accepts it. The error tells an operator who typed an instance name that they typed a path. Workaround: a trailing colon.

**Fixed:** rekey now resolves its operand through `instanceLocator`, which `ls` and `usage` had used since phase 3.3 — the fix was a helper written in the same commit as the parser, and never wired to this command.

### 5. `storage key rekey` cannot retire what a keeper device holds — fixed, not re-walked

**The most serious finding of this walk.** `keeper revoke` tells the operator, verbatim: *"If the device was lost, retire what it HOLDS: `farcast storage rekey p54`. Rekey changes the scope keys, so that device's bundle opens nothing written afterwards."*

Measured on `p54`, four objects stored, all under per-application scopes:

```
storage key rekey p54: -y                      -> rewritten: 0, already active: 0
storage key rekey p54:app/sdk-demo/alpha/ -y   -> rewritten: 0
every key id in keys.yaml, master and scope    -> UNCHANGED
storage ls p54:                                -> all 4 objects still readable
```

While walking the key space it emits, once per object, `datasphere: recover name of stored object …: this keyring did not write that object`. Rekey operates at master level only; every object lives under a scope whose name key it cannot use and whose KEK it does not rotate. A revoked device's bundle holds exactly those keys.

**Revoke-plus-rekey currently binds nothing.** The per-object warnings do reach stderr and the result honestly says `rewritten: 0`, so nothing is concealed — but it ends with a green `✓ rekeyed`, never says the scope keys were untouched, and `keeper revoke` makes a promise this command does not keep. Same blind spot as finding 2, with a security consequence instead of a display one.

**Fixed.** The defect was three layers, not one. Rekey listed the master key space alone, though `Session.KeySpaces` already spanned scopes for `storage ls`. Nothing could rotate a scope's KEK at all — no API existed, and `Keyring.Merge` appends, so a merged key never becomes active. And a rotated key has to reach the keyholder **before** any object moves onto it, or every moved object is unreadable to the applications. Now `rotate` prepends a fresh KEK to every scope and hands the new keys to serving replicas at once; `rekey` rewrites each object through its own scope's store and refuses to move any until every replica is serving and reports that scope's current KEK; `revoke` prints rotate, rekey, re-enrol. A unit test reproduces this finding exactly — the scope keys a keeper enrolled beforehand would carry — and proves they open none of the applications' objects afterwards. The two old behaviours, master-only rotate and master-only rekey, each fail it.

### 6. `release` reports a cluster "(deleted)" while the delete is still running

`release` printed `cluster: farcast-p54 (deleted)` and removed the local state. The GKE API reported `STOPPING` with `DELETE_CLUSTER` **RUNNING**; the cluster actually disappeared **200 seconds later**.

It completed, so nothing was stranded. But on the one command whose purpose is to stop billing, "deleted" and "deletion started" are different claims — and the local record is gone either way, so a failed delete would leave a billing cluster, no local trace, and a transcript saying it was deleted. Independent verification after `release` has to stay mandatory, which is why criterion 10 is written the way it is.

### 7. Releasing an instance leaves that machine's keeper state behind

After `release`, `instances/p54` was gone and `keepers/p54` remained — bundle, CA, leaf, key and ledger for an instance that no longer exists. Defensible by design: a keeper is a role, usually on a different machine, and the ledger is deliberately kept. But on a machine holding both, `release` knows the directory is there and says nothing.

### Found while fixing findings 4 and 5 — both fixed, neither walked

**A push to a serving keyholder could destroy, and expose, an in-flight write.** The vault handed each request its own scope by reference, sharing key bytes, and an unseal at a new generation zeroes the scopes it replaces. A write admitted before such a push and sealed after it — the whole of its upload is the window — wrapped its data key under an all-zero KEK carrying the real key ID: unreadable to its owner, and readable by anyone who tried a key of zeros. Reproduced with a probe before it was fixed. **This was criterion 14a's own path**: every `farcast run` that handed a serving keyholder a new scope pushed a new generation. The walk passed 14a honestly — no write was in flight during its push — and could not have shown this. Fixed: each request gets its own copy of its scope's keys and wipes it when it ends.

**A keeper could do anything the operator can to the seal state.** See [the 5.4 runbook's criterion 4](phase-5-4-validation.md): the control surface took its authority from the request, so a keeper's leaf could release a hold, unseal through one by claiming `operator-unseal`, or place one. Fixed: authority now comes from the role on the leaf.

The hand-over itself also changed. It used to read each replica's state and then push with `operator-unseal` — an intent the keyholder honours even under a hold — so a replica that restarted or was held between the two round trips was unsealed by a deploy. It now pushes a `hand-over` intent the keyholder refuses on any sealed replica, chooses a generation above every replica's own report rather than this machine's record alone, and counts a replica as holding the keys only if it reports the ones it was sent. The last two close a defect no walk saw: a hand-over that reached one replica of two left the recorded generation behind, the next reused the number, and the replica that had taken it treated the repeat as a retry — installing nothing, and answering success.

**Verifying those fixes found more, and changed them.** A mutation and adversarial-review pass confirmed fourteen defects in the first version of the fix — the worst one introduced by it. Rotation made a new key active one replica at a time, so a replica that did not answer could no longer read what the others wrote. It now stages the key everywhere before activating it. A keeper could still replace a serving replica's keys with a re-seed, and the keyholder now refuses one. `storage unseal`, the remedy every refusal names, had the same generation defect as the hand-over and now has both of its guards. Every fix carries a test shown to fail with the defect restored. See [ADR 0008](../adr/0008-in-cluster-key-delivery.md#what-the-2026-10-06-walk-found-and-what-changed).

---

## Criteria

| # | Criterion | Result |
|---|---|---|
| 1 | A secret set from the operator's machine is read by the application, by name, first try | ✅ |
| 2 | The bucket object's name and bytes disclose neither the name nor the value | ✅ (size discloses the length exactly — 163-byte constant overhead) |
| 3 | No Kubernetes Secret or ConfigMap anywhere holds the value | ✅ |
| 4 | An application's `PUT` and `DELETE` under `secrets/` are refused with `permission` | ✅ |
| 5 | An application's `GET` of a **neighbour's** secret succeeds, matching ADR 0017 rather than the name | ✅ |
| 6 | A seal reports as a seal, and clears without a restart | ✅ |
| 7 | `Config()` refuses `FARCAST_*` in a pod that genuinely has those variables set | ✅ |
| 8 | A `Secret` reaches no log, no error and no marshalled document in the clear | ✅ |
| 9 | `--force` rotates, `rm` removes, and the application sees both | ✅ (rotation seen with no restart) |
| 10 | Teardown leaves no billable resource — verified independently, not from local state | ✅ |

Criterion 5 was **inverted on purpose** by [ADR 0018](../adr/0018-thin-device-storage.md) decision 5 and is superseded by criterion 12 below. It is left in place rather than rewritten, because the 2026-09-10 walk recorded it passing and a reader comparing the two records needs to see that the behaviour changed under them.

### Re-walk criteria, 2026-10-06

| # | Criterion | Result |
|---|---|---|
| 11 | An unidentified client is refused at the **handshake**, with no HTTP status | ✅ `tlsv13 alert certificate required`, `http_code=000` |
| 12 | An application's own objects are served and **every** neighbour object — secret or ordinary — is refused with `permission` | ✅ including a claim of the neighbour's own scope name |
| 13 | A pre-upgrade application is refused with a message naming the leaf, and recovers on redeploy | ⏸ **not reachable** from a fresh install; needs a CLI built at `36db52e` |
| 14 | `run` mints a scope per application and hands it to a serving keyholder, while leaving a sealed **and** a held one sealed | ✅ ledger byte-identical across both sealed deploys. The hand-over path carried a write-corrupting defect this walk could not exercise; fixed 2026-10-06, not re-walked |
| 15 | An instance with no applications unseals and becomes ready | ✅ generation 1, single attempt |

Both defects the first walk found were fixed **and re-verified on the same live instance** before teardown, which is what [the 5.2 walk](phase-5-2-validation.md) could not do. The re-walk held to the same standard: of the [seven defects it found](#what-the-re-walk-found), the two cheapest were fixed and re-verified on `p54` before it was released.
