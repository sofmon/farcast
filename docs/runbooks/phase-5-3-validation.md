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

## Re-walk after ADR 0018 decision 1 — not yet walked

Identity on the keyholder's data path changes three of the answers above, and each is a claim about a live cluster rather than a unit test.

- **#4 changes shape.** From inside `alpha`'s pod, a `GET` of `alpha`'s own secret succeeds with the leaf the platform mounted; the same `GET` of `beta`'s secret returns `403 permission`; and a `curl` with `--cacert` but **no client certificate** fails the TLS handshake outright — no HTTP status at all. That last one is the listener refusing, and it is the property the whole decision rests on.
- **#5 inverts entirely.** `alpha` reading `beta`'s secret — the demonstration ADR 0017 asked for — now **fails**, and so does `alpha` reading `beta`'s *ordinary* objects: decision 5 gave each application its own scope, so `beta`'s key space is not addressable with `alpha`'s leaf and not openable with `alpha`'s keys. The fixture's `neighbour's secret` line should report `refused`. Confirm both, because "secrets are separated" and "everything is separated" are different claims and only the second is now true.
- **Scopes are minted at deploy, and handed over there.** `farcast run` mints `app/<ns>/<app>/` per application, says so with the key-loss warning, and gives the new scopes to a keyholder that is **already serving** — before the workloads exist, so the application does not start into a keyholder that has never heard of it. Expect `The keyholder now holds …` and a ledger entry per replica.
- **A sealed keyholder is left sealed.** Seal the instance, then deploy a new application: `run` must report that the scopes are waiting, name `farcast storage unseal`, deploy the workloads anyway, and write **no** ledger entry. Pushing a bundle to a sealed keyholder *is* an unseal, and a deploy performing one as a side effect would hide a seal nobody has seen — so walk this deliberately, including with an `--hold` seal, where a deploy that unsealed would be clearing an operator's own decision.
- **An instance with no applications unseals.** Deploy a keyholder and unseal before deploying anything: it must report an empty bundle and become ready, rather than refusing.
- **Deploy order.** Upgrade the keyholder with `storage deploy` while an application from *before* the upgrade is running: it must report `ErrStorageUnavailable` naming the missing leaf, and `farcast run` again must restore it without any change to the application.

Criteria 11–15: an unidentified client is refused at the handshake; an application's own objects are served and every one of a neighbour's is refused with `permission`; a pre-upgrade application is refused with a message that names the leaf and recovers on redeploy; `run` mints a scope per application and hands it to a serving keyholder, while leaving a sealed one sealed; an instance with no applications unseals and becomes ready.

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

Both defects the walk found were fixed **and re-verified on the same live instance** before teardown, which is what [the 5.2 walk](phase-5-2-validation.md) could not do.
