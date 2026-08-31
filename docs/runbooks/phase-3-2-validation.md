# Runbook — Phase 3.2 Validation: The In-Cluster Keyholder

Phase 3.2 puts DataSphere key material inside a cluster for the first time — in memory only, pushed from the operator's machine, and gone again on every restart. This runbook walks that against real GKE.

Everything below was designed against fakes. The claims that matter here are the ones no unit test can make: that a real Autopilot restart really does seal storage, that the sealed state is really reportable when the data Service has no endpoints, and that the operator's keyring and the keyholder's bundle really do agree about names.

**Read [ADR 0008](../adr/0008-in-cluster-key-delivery.md) first.** The behaviour this runbook confirms — storage that stops working after a node upgrade until a human intervenes — is a deliberate, ratified consequence, not a defect to be filed.

## Prerequisites

- An instance that has completed [the Phase 3 runbook](phase-3-validation.md): installed, connected, with a bucket minted and recorded.
- **The installer service account must carry the conditional storage grant** from that runbook's step 2. A project whose service account has only `container.admin` and `artifactregistry.admin` will fail at bucket creation with a `storage.buckets.create` 403 — observed on the 2026-08-31 run, because a previous teardown had removed it.
- `farcast connect <instance>` reports a working tunnel. **Nothing here works without it** — the keyholder is reachable only through FatLine, and an unseal cannot be delivered while the tunnel is down.
- A farcast checkout, so the CLI can compile and push the keyholder image if the instance registry does not have it yet.

## 0. Set shared variables

```bash
INSTANCE=<your-instance-name>
NS=farcast-system

# The CLI keeps instance state under the OS config dir, or FARCAST_CONFIG_HOME
# when that is set. On macOS that is ~/Library/Application Support/farcast.
FARCAST_STATE="${FARCAST_CONFIG_HOME:-$HOME/Library/Application Support/farcast}"
INSTANCE_DIR="$FARCAST_STATE/instances/$INSTANCE"

export KUBECONFIG="$INSTANCE_DIR/kubeconfig.yaml"
kubectl config current-context    # confirm it points at this instance's cluster
```

Every `kubectl` below assumes `KUBECONFIG` points at the file `farcast connect` wrote for this instance.

## 1. Deploy the keyholder

```bash
farcast storage deploy "$INSTANCE"
```

Expect a cost confirmation naming the standing compute, then a build-and-push of `system/datasphered` if the instance registry does not already have it (no container engine involved — the CLI compiles the Go binary and pushes an OCI image directly).

**The command must NOT wait for the pods to become ready.** It should return promptly saying every replica is SEALED and telling you to run `unseal`. If it hangs waiting for a rollout, that is a bug: sealed replicas never become Ready, so the wait could only ever time out.

Confirm what landed:

```bash
kubectl -n "$NS" get statefulset,pdb,svc -l app.kubernetes.io/name=datasphered
kubectl -n "$NS" get pods -l app.kubernetes.io/name=datasphered -o wide
```

Expect two pods on **different nodes** (the hostname topology spread), a PodDisruptionBudget with `minAvailable: 1`, and three Services.

## 1a. Grant the keyholder access to its own bucket

**Found on the 2026-08-31 run: without this the replicas crash-loop on a 403 and nothing else in the runbook can proceed.**

The keyholder reads and writes the bucket under its *own* cloud identity — a dedicated `datasphered` ServiceAccount resolved through Workload Identity, with no token mounted. FarCast does not create the binding: granting it needs permission to change a bucket's IAM, which the operator's credential is not required to carry and which the CLI deliberately never asks for. `storage deploy` prints the exact commands; run them once per instance.

```bash
PROJNUM=$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')
PRINCIPAL="principal://iam.googleapis.com/projects/$PROJNUM/locations/global/workloadIdentityPools/$PROJECT.svc.id.goog/subject/ns/$NS/sa/datasphered"
gcloud storage buckets add-iam-policy-binding "gs://$BUCKET" --member "$PRINCIPAL" --role roles/storage.objectAdmin
gcloud storage buckets add-iam-policy-binding "gs://$BUCKET" --member "$PRINCIPAL" --role roles/storage.legacyBucketReader
```

The grant is on the **bucket**, not the project, and object access is separated from bucket reads so the keyholder cannot delete the bucket it serves. Then restart the pods so they pick it up:

```bash
kubectl -n "$NS" delete pod -l app.kubernetes.io/name=datasphered
```

## 2. Confirm it came up sealed, and that a sealed pod is *not* Ready

```bash
kubectl -n "$NS" get pods -l app.kubernetes.io/name=datasphered
farcast storage state "$INSTANCE"
```

Expect `0/1` READY on both pods, and `restart-sealed` for both replicas. A sealed pod that reported Ready would mean application traffic reaching a replica that can serve nothing.

**Liveness must not be failing.** Check that neither pod is restarting:

```bash
kubectl -n "$NS" get pods -l app.kubernetes.io/name=datasphered \
  -o custom-columns=NAME:.metadata.name,RESTARTS:.status.containerStatuses[0].restartCount
```

A climbing restart count means liveness was wired to the seal — the single most dangerous misconfiguration here, because every restart re-seals and no unseal could ever win the race.

## 3. Confirm the sealed state is reportable with zero data endpoints

This is the flagship claim. The data Service is readiness-gated, so while every replica is sealed it has **no endpoints at all** — and an application must still receive `ErrStorageSealed` rather than an opaque dial error.

```bash
kubectl -n "$NS" get endpoints datasphered          # expect: <none>
kubectl -n "$NS" get endpoints datasphered-status   # expect: TWO addresses
```

The status Service publishes not-ready addresses precisely so the seal stays reportable. Confirm it answers:

```bash
kubectl -n "$NS" run probe --rm -it --restart=Never --image=curlimages/curl:latest -- \
  curl -s http://datasphered-status:8444/v1/state
```

Expect JSON with `"phase":"restart-sealed"` and **no scopes** — a sealed keyholder reports its state and nothing about key material.

## 4. Unseal

```bash
farcast storage unseal "$INSTANCE"
```

The first run mints the `app` scope, records it in `keys.yaml` **before pushing anything**, and prints the key-loss warning. Expect `2 of 2` and a generation number.

```bash
farcast storage state "$INSTANCE"
kubectl -n "$NS" get pods -l app.kubernetes.io/name=datasphered
kubectl -n "$NS" get endpoints datasphered
```

Expect both replicas `unsealed`, both pods `1/1`, and the data Service now carrying two endpoints.

Confirm the push was recorded locally:

```bash
cat "$INSTANCE_DIR/datasphere/unseal-ledger.jsonl"
```

Expect one line per replica, with the generation and `"result":"ok"`. This is the record phase 5.4's keeper audit reads; it must exist from the first push.

## 5. The crux — operator and keyholder agree about names

This is the step that proves the scope actually works. Write through the keyholder, then read the same object from your own machine with the CLI. If these disagree, the scope's key material is wrong and nothing else in this phase matters.

Port-forward the data path and write an object as an application would:

```bash
kubectl -n "$NS" port-forward svc/datasphered 8443:8443 &
CA="$INSTANCE_DIR/fatline/ca.crt"

printf 'hello from inside the cluster' | curl -sS --cacert "$CA" \
  --connect-to "$INSTANCE.datasphered.farcast:8443:127.0.0.1:8443" \
  -X PUT "https://$INSTANCE.datasphered.farcast:8443/v1/object" \
  -H "X-Farcast-Scope: app" \
  -H "X-Farcast-Key: $(printf 'app/hello' | base64)" \
  --data-binary @-
```

Now read it back **from the operator's machine, through the ordinary CLI**:

```bash
farcast storage ls "$INSTANCE:app/"
farcast storage cp "$INSTANCE:app/hello" /tmp/hello.readback
cat /tmp/hello.readback
```

Expect the object to list, and the file to contain `hello from inside the cluster`.

**If the listing is empty, do not guess — ask what it queried:**

```bash
farcast storage ls "$INSTANCE:app/" --explain
```

That reports, per key space, the prefix it owns, the opaque prefix it queried, how many objects the provider holds under it, and how many names were recovered. A key space that queried a prefix with **0 objects under it** does not address the data written there, and its key ids should be compared against the writer's — which is the single fact the 2026-08-31 run could not obtain. That proves the keyring on this laptop and the bundle in the cluster are the same key material, and that the stateless name-recovery promise survives scoping.

## 6. Confirm the cloud sees only opaque names

```bash
gcloud storage ls --recursive "gs://<bucket>" | head
```

Expect tokenized names with no recognisable `app/hello`. Fetch one and confirm it begins with the `FCDS` magic and is otherwise ciphertext.

## 7. Kill one replica — storage keeps serving

```bash
kubectl -n "$NS" delete pod datasphered-0
farcast storage state "$INSTANCE"
```

Expect replica 0 to return `restart-sealed` and replica 1 to stay `unsealed`, and the object from step 5 to remain readable throughout. This is what the second replica and the PDB are for.

Re-unseal to restore full headroom:

```bash
farcast storage unseal "$INSTANCE"
```

## 8. Kill both — the honest cost, observed

```bash
kubectl -n "$NS" delete pod -l app.kubernetes.io/name=datasphered
farcast storage state "$INSTANCE"
```

Expect both `restart-sealed`, the data Service with no endpoints, and the status Service still answering. **This is the 03:00 scenario, and it behaving exactly this way is the phase working as ratified**, not failing. Nothing is lost; `farcast storage unseal` restores service.

## 9. An operator hold is not a keeper's to clear

```bash
farcast storage seal "$INSTANCE" --hold --reason "runbook check"
farcast storage state "$INSTANCE"
```

Expect `operator-hold` with the reason. Now confirm the hold does **not** survive a restart — it is deliberately process-local, because a durable hold would need cloud-resident state, which would serve the very adversary a hold is aimed at:

```bash
kubectl -n "$NS" delete pod datasphered-0
farcast storage state "$INSTANCE"
```

Expect replica 0 back at `restart-sealed`, not `operator-hold`. The CLI said this would happen when you set the hold; confirm it did.

```bash
farcast storage unseal "$INSTANCE"
```

## 10. Anti-rollback

A bundle captured before a rotation must not be replayable. The generation only moves forward, so re-running `unseal` always advances it; confirm the recorded generation in `metadata.yaml` matches what the replicas report:

```bash
farcast storage state "$INSTANCE"
```

Expect every replica's generation to equal the recorded one, and no replica to report a lower number than a previous run.

## 11. Tear down

```bash
kubectl -n "$NS" delete statefulset,svc,pdb,secret -l app.kubernetes.io/name=datasphered
```

Then confirm `farcast release "$INSTANCE"` still tears the instance down cleanly, and that nothing keyholder-shaped is left billing.

## Success criteria

1. `storage deploy` returns without waiting for readiness, and says the replicas are sealed.
2. Two pods land on different nodes, with a PDB; both are `0/1` and neither restarts.
3. With every replica sealed, the data Service has no endpoints and the status Service still reports `restart-sealed`.
4. `storage unseal` reports `2 of 2`, both pods become Ready, and the ledger records both pushes.
5. **An object written through the keyholder reads back byte-exact through `farcast storage cp` on the operator's machine.**
6. `gcloud` shows only tokenized names and `FCDS` ciphertext.
7. Deleting one replica does not interrupt service; deleting both yields a reportable seal and no data loss.
8. An operator hold refuses a keeper-intent reseed, and does not survive a pod restart.
9. Generations never move backwards.
10. Teardown leaves nothing billing.

## Not covered by this run

- **The SDK's own client against a real application.** Applications cannot be deployed until Planck's translator (4.2) and `farcast run` (4.3), so step 5 exercises the data path with `curl` rather than through `farcast.Storage()`. The wire contract is the same, but an application actually classifying `ErrStorageSealed` is untested against a cluster until 4.3.
- **A full node-pool upgrade.** Steps 7 and 8 simulate the seal by deleting pods. A real Autopilot auto-upgrade, with its own PDB handling and one-hour drain budget, is the event the design is really about and it cannot be triggered on demand.
- **NetworkPolicy isolation.** In 3.2 any pod in the cluster can reach the keyholder's data port; access control is network reachability plus the declared scope. The policy that contains this is 4.2's, and per-application identity is 4.x's. This is stated in the SDK README rather than implied.
- **The keeper fleet.** Phases 5.4 and 7.5. The protocol carries the intent and the ledger already, so 5.4 adds a driver rather than a format.
- **The real standing cost.** The cost gate prints an estimate derived from the workload's declared requests. Autopilot raises Pods below its per-Pod minimum, and that minimum differs between clusters with and without bursting support — so **read the actual bill after one cycle** and, if it disagrees materially, amend ADR 0008 decision 6 with the measured figure rather than the estimated one.


---

## Findings from the 2026-08-31 run

Nine of the ten success criteria passed. Criterion 5 — the crux — did not, and its cause is **not yet established**.

**Passed.** `storage deploy` returned in 53 s without waiting for readiness. Two replicas landed on different nodes behind the PDB. Both came up `restart-sealed`, Running, `0/1` Ready, with **zero restarts** — liveness is not seal-gated. With every replica sealed the data Service had no endpoints while the status Service still answered from an in-cluster pod. `unseal` reported `2 of 2`, both pods became Ready, and the ledger recorded both pushes. The **real SDK** worked against the real cluster: the status seam reported `ready`, a write/read round-tripped byte-exact, and an out-of-scope read was refused with `ErrPermission` — which is stronger than this runbook originally planned, and retires the "SDK client never exercised" caveat below.

**Four defects found and fixed.**

1. **Workload Identity was never implemented.** Both replicas crash-looped on a 403: no ServiceAccount, no `serviceAccountName`, no binding. ADR 0008 decision 8 named the shape and nothing built it. The keyholder now has its own ServiceAccount and `storage deploy` prints the exact bucket-scoped grant — see step 1a.
2. **FatLine had no stream route.** Every unseal answered `404`: `Config.StreamRoutes` existed but neither the flag nor the rendered argument did, so the relay was unreachable in any real deployment. Unit tests missed it because they built the config directly. Fixed across the binary, the renderer and `connect`/`redeploy`.
3. **The SDK could not verify an in-cluster keyholder.** The certificate carries the synthetic SAN `<instance>.datasphered.farcast`, but an application dials a Kubernetes Service name, and the client derived the verified identity from the endpoint host. `FARCAST_STORAGE_SERVER_NAME` now separates the two, as FatLine's tunnel already did.
4. **This runbook contained two commands that do not exist** (`farcast instance-path`, and `storage cp … -` for stdout — which would have created a file named `-` and "passed" while proving nothing), and a `curl` step that **cannot work on macOS**: the instance CA is Ed25519 and the system curl is LibreSSL. Use the SDK, or a curl built against OpenSSL.

**Open: criterion 5.** After the SDK wrote `app/sdk-written`, the operator's CLI could not list or read it. The CLI was scope-blind, which is now fixed and tested at every layer — but the fix was *not* confirmed against the cluster, and the live evidence is contradictory:

- The keyholder, re-unsealed at generation 2 from `keys.yaml`, listed both the generation-1 and generation-2 objects — so the scope recorded on disk **is** the scope that wrote them.
- Yet a probe computing `StoredName` from that same `keys.yaml` produced a different stored name than the object's actual path, and `ls app/` returned empty with no name-recovery warnings, meaning nothing matched the tokenized prefix.

Those two cannot both be true, so one of the observations is wrong and the instance was destroyed before it could be settled.

**Follow-up, same day: the sequence was reproduced locally and does not fail.** `TestScopedObjectIsVisibleToTheOperatorCLI` performs the exact live order — operator writes outside any scope with a master-only keyring, `ensureScope` mints the scope and rewrites `keys.yaml` to v2, the bundle round-trips through its wire form into a real vault, the keyholder writes through its scoped `Store`, and the CLI then loads `keys.yaml` **fresh from disk** and lists and reads the object. It passes, and it fails against both forms of the old scope-blind behaviour, so it is a real regression test rather than one that would pass either way.

That makes the scope-blind CLI the whole of the reproducible defect, and it is now fixed and guarded. The unexplained residue is the `StoredName` mismatch observed during the walk, which did not reproduce and is most consistent with a measurement error at the time — the probe was run against a binary that was mid-change, and the stored paths were being paired with objects by eye.

**Criterion 5 nevertheless remains formally unverified**, because a passing local reproduction is not a live confirmation. The next run should test it first. If it fails again, capture in one pass: the scope key ids from `keys.yaml`, the key id in the stored blob's header, and the tokenized prefix the CLI actually queries — the last of which nothing currently prints, and which is why the first run could not be settled.
