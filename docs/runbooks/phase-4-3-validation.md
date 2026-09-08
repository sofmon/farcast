# Runbook — Phase 4.3 Validation: `farcast run`

Phase 4.3 is the command the rest of FarCast exists to make possible: point it at a repository, read what that repository declares, approve it, and have it running.

It is also the first command where the operator's machine **never sees the source**. [ADR 0010](../adr/0010-application-image-builds.md) decision 6 moved the manifest read into the instance, and decision 11 gives that read its own Job. Everything the operator approves is something the cluster told them, and the two values that make the claim checkable — the resolved commit and a digest of the manifest that was parsed — are printed at the gate and recorded in the result.

Everything below was designed against fakes and rendered YAML. The claims that matter here are the ones no unit test can make:

- **The fetcher image has what the read script needs.** A shell at `/bin/sh`, `sha256sum`, `git`, and a user whose group can write the workspace volume. Four assumptions about somebody else's image, in one container.
- **A read-only root filesystem plus an `emptyDir` plus `fsGroup` actually lets git clone.** The builder next door could not have a read-only root; this one is supposed to be able to.
- **The manifest arrives through `kubectl logs` byte-identical.** The whole verification depends on the log carrying exactly what the Pod printed, and the digest travelling by a different channel is what would catch it if not.
- **Kaniko checks out a bare commit SHA.** Documented, and never run by this project — every build so far has used `refs/heads/main`. If it does not work, the approval gate and the build are looking at different trees, which is the one failure 4.3 exists to prevent.
- **The fetch's policy is tighter than the build's and still works.** The build was granted the link-local metadata server because it must mint a push token. The fetch blocks link-local entirely except for DNS. That is a stricter policy than anything that has run in this cluster.
- **`kubectl get configmap --ignore-not-found -o json`** returns empty rather than failing, which is what `farcast costs` relies on to tell "no checkpoint yet" from "no permission".

**Read [ADR 0010](../adr/0010-application-image-builds.md) first**, and note what it does *not* claim: this buys deployment portability, not administration portability. `storage unseal` and the CA operations still need the operator's real machine.

## Prerequisites

- An instance that has completed [the Phase 4.2 runbook](phase-4-2-validation.md): installed, connected, storage deployed and unsealed, kernel deployed, and with the builder's Workload Identity push grant already applied. **`run` does not apply that grant** — it prints it, like `build` does, and a missing grant fails at push after the clone and the build have both succeeded.
- **A valid gcloud user session** — `gcloud auth print-access-token >/dev/null` must succeed.
- The repository is this one, `github.com/sofmon/farcast`, and it is public, so no Git credential is involved. Step 10 covers the private case and is optional.

## 0. Set shared variables

```bash
INSTANCE=<your-instance-name>
NS=farcast-system
APPS=manifest-elsewhere
MANIFEST=manifest/examples/manifest-elsewhere/farcast

FARCAST_STATE="${FARCAST_CONFIG_HOME:-$HOME/Library/Application Support/farcast}"
export KUBECONFIG="$FARCAST_STATE/instances/$INSTANCE/kubeconfig.yaml"
kubectl config current-context
```

## 1. Pin the fetcher, by being refused

Both images `run` puts inside the instance are third party and must be digest-pinned. Pass a tag on purpose:

```bash
farcast run "$INSTANCE" github.com/sofmon/farcast \
  --manifest "$MANIFEST" \
  --fetcher-image cgr.dev/chainguard/git:latest-dev
```

Expected: a refusal that **resolves the tag, reports the digest, and says why it will not simply use it** — the fetcher decides which bytes the approval gate shows, so a tag resolved fresh on every run is a reviewer nobody reviewed. Record it:

```bash
GIT_IMAGE=<the digest-pinned reference from that output>
KANIKO=<the digest-pinned Kaniko reference from the 4.2 walk>
```

If the resolve itself fails, Chainguard has moved the image or dropped it from the free tier. That is a finding about the image, not about FarCast — note that pulling **by digest** stays available across all their tiers, which is why pinning is also what keeps this working.

## 2. Read the manifest, and refuse it

Run it and answer **no** at the prompt.

```bash
farcast run "$INSTANCE" github.com/sofmon/farcast \
  --manifest "$MANIFEST" \
  --fetcher-image "$GIT_IMAGE" --builder-image "$KANIKO"
```

Expected, in order:

1. `Reading https://github.com/sofmon/farcast inside "<instance>" — the instance clones it, not this machine.`
2. A review naming the **commit**, the **manifest digest**, the application `prover`, its Containerfile, and `reaches nothing outside the instance`.
3. A cost block: one build Job at 1000m/2048Mi, and the standing monthly cost of one application on top of the instance floor.
4. `Deploy "manifest-elsewhere"? [y/N]` → answer `n`.
5. `Aborted. Nothing was built and nothing was deployed.`

Then confirm the refusal was real:

```bash
kubectl -n "$NS" get jobs
```

Expected: a `fetch-farcast-<hash>` Job and **no `build-…` Job**. The read costs money; the build does not happen until it is approved.

While it is there, check what the read was allowed to reach:

```bash
kubectl -n "$NS" get networkpolicy -o yaml | grep -A6 "169.254"
```

Expected: `169.254.20.10/32` on port 53 **only**, and `169.254.0.0/16` in the `except` list with **no** carve-out for `169.254.169.254`. That is the line that makes the fetch weaker than the build, and it is deliberate ([ADR 0010](../adr/0010-application-image-builds.md) decision 11).

## 3. Run it

Same command, answer `y`.

```bash
farcast run "$INSTANCE" github.com/sofmon/farcast \
  --manifest "$MANIFEST" \
  --fetcher-image "$GIT_IMAGE" --builder-image "$KANIKO"
```

Expected: the read, the review, `[1/1] Building prover inside "<instance>"…`, then a result naming the deployment, the commit, the manifest digest, and the **digest-pinned** image.

## 4. The build used the commit, not the branch

This is the property the whole design turns on. A branch that moved between the read and the build would mean the operator approved one tree and the instance built another.

```bash
COMMIT=<the commit from step 3's output>
kubectl -n "$NS" get job -l app.kubernetes.io/name=farcast-builder \
  -o jsonpath='{range .items[*]}{.spec.template.spec.containers[0].args}{"\n"}{end}' \
  | tr ' ' '\n' | grep -- --context=
```

Expected: `--context=git://github.com/sofmon/farcast#<the same 40-character commit>` — **not** `#refs/heads/main`.

## 5. What is running

```bash
farcast ps "$INSTANCE"
farcast ps "$INSTANCE" --all
```

Expected: `prover` at `1/1`, tier `app`, in namespace `manifest-elsewhere`. `--all` additionally shows `fatline`, `datasphered` and `technocore` in `farcast-system` — the machinery a cost shutdown never stops.

## 6. The application's own output

```bash
farcast logs "$INSTANCE" prover
```

Expected: `built by farcast, inside the instance` — **the file the `RUN` step created**. The end-to-end proof, now reached by one command rather than by hand.

Then confirm the namespace was found without being given, and that the output is the application's bytes and not this CLI's envelope:

```bash
farcast logs "$INSTANCE" prover --tail 1
farcast logs "$INSTANCE" nosuchapp   # expected: names the namespaces it looked in
```

## 7. What it costs

```bash
farcast costs "$INSTANCE"
```

Expected:

- `expected` — a non-zero figure metered from Pod requests.
- `confirmed` — **`—  the provider has confirmed nothing yet`**, never a confirmed zero. A missing billing feed and a period that genuinely cost nothing look identical as a number and are not the same thing.
- `total`, `limit`, `remaining`, and a percentage.
- `rate USD 0.0xxx/hour across N pods, observed <n>m ago`.
- A per-application breakdown, followed by the sentence saying attribution can only come from `expected` because the provider bills the instance rather than the applications in it.

Cross-check the rate against the cluster, the way the 4.2 walk did:

```bash
kubectl get pods -A -l app.kubernetes.io/managed-by=farcast --no-headers | grep -c Running
```

`pods × 0.0050625` should equal the reported hourly rate for 100m/128Mi pods, and the pod count should match. A mismatch here is the model disagreeing with the cluster, which is the single most important number in the system.

## 8. It is metered

An application the kernel does not count is an application the cost limit does not protect against.

```bash
farcast kernel meter "$INSTANCE"
kubectl -n "$NS" get configmap technocore-namespaces -o yaml | grep -A4 "namespaces"
kubectl -n "$APPS" get rolebinding
```

Expected: `manifest-elsewhere` in the metered list, and a RoleBinding in that namespace granting the kernel the read it needs. `run` applies both, and applies them together — separately, a failure between them leaves the kernel told to meter a namespace it has no permission to read.

## 9. The second run needs no flags

The reviewed digests are recorded against the instance.

```bash
farcast run "$INSTANCE" github.com/sofmon/farcast --manifest "$MANIFEST" -y
grep -A4 toolchain "$FARCAST_STATE/instances/$INSTANCE/metadata.yaml"
```

Expected: it runs without `--fetcher-image` or `--builder-image`, and the metadata records both digests. This is [ADR 0010](../adr/0010-application-image-builds.md) decision 10's "reviewed constant" — reviewed once, written down, not re-derived on every build.

## 10. A private repository (optional)

Skip unless you want the private path covered. It needs a repository-scoped, read-only credential, and it is the case the ADR's consequences section is bluntest about: the cloud provider can read that repository's source for the life of the build, and the credential for as long as it exists.

```bash
kubectl -n "$NS" create secret generic my-repo-git \
  --from-literal=username=<user> --from-literal=token=<read-only PAT>

farcast run "$INSTANCE" github.com/<you>/<private-repo> --git-secret my-repo-git
```

Expected: the same flow. One Secret serves both the read and the build.

## 11. Verify out of band

The point of decision 6's two values. From any machine that can reach the repository — including one that has never seen this instance:

```bash
git ls-remote https://github.com/sofmon/farcast | grep "<commit>"
git show "<commit>:$MANIFEST" | shasum -a 256
```

Expected: the commit exists on the remote, and the manifest's sha256 matches what the gate printed. That is the whole of the audit trail this design gives up prevention for, and it either works or it does not.

## 12. Tear down

```bash
kubectl delete namespace "$APPS"
farcast kernel meter "$INSTANCE" "$APPS" --remove
kubectl -n "$NS" delete jobs -l app.kubernetes.io/name=farcast-fetcher
kubectl -n "$NS" delete jobs -l app.kubernetes.io/name=farcast-builder
```

And, if the instance is not being kept:

```bash
farcast release "$INSTANCE"
```

**Confirm nothing is left billing:** the cluster, the registry repository, the storage bucket and the load-balancer carrier.

---

## Success criteria

Walked live against GKE on **2026-09-08**, instance `p43`, released the same day.

| # | Claim | Result |
|---|-------|--------|
| 1 | An unpinned fetcher is resolved, reported and refused | ✅ after finding 1 |
| 2 | The instance reads the manifest and reports a commit and a digest | ✅ `37c2eb398a87…`, `sha256:02deddf8…` |
| 3 | The gate shows every external declaration before anything is built | ✅ |
| 4 | Answering no builds nothing | ✅ only the fetch Job existed |
| 5 | The fetch reaches DNS and the Git host, and not the metadata server | ✅ `169.254.0.0/16` excluded whole |
| 6 | The build is pinned to the commit that was read, not the branch | ✅ `--context=…#37c2eb39…` |
| 7 | `farcast ps` shows the application, and hides the machinery without `--all` | ✅ after finding 3 |
| 8 | `farcast logs` finds the app without a namespace and prints the `RUN` step's file | ✅ `built by farcast, inside the instance` |
| 9 | `farcast costs` reports both figures, and no confirmed zero | ✅ |
| 10 | The reported rate matches the cluster's pod count exactly | ✅ `0.0304/h` = 6 × $0.0050625 |
| 11 | The new namespace is metered, with its RoleBinding | ✅ |
| 12 | A second run needs neither image flag | ✅ |
| 13 | The commit and manifest digest check out against the remote | ✅ byte-identical |

**The four unknowns about the fetcher image all held.** `/bin/sh`, `git` and `sha256sum` are all present in `cgr.dev/chainguard/git:latest-dev`, and a read-only root filesystem over an `emptyDir` owned by `fsGroup: 65532` clones without complaint. The read took **9 seconds**.

**Kaniko checks out a bare commit SHA.** Documented and never previously exercised here. It works, which is what makes the approval gate mean anything.

---

## Findings

### 1. The OCI client judged a token by its label, not its content — and that blocked the entire toolchain

`farcast run` could not resolve *either* image: `token endpoint cgr.dev answered with "text/plain; charset=utf-8", not JSON`. The body was valid JSON. Chainguard serves it under a sloppy `Content-Type`, and [`oci`](../../farsight/cli/internal/oci/) refused on the header before reading it.

The check looked defensive and was not: `json.Unmarshal` already rejects an HTML error page, so the header gate bought nothing and cost every image on that registry. It now decodes the body and reports the label only when decoding actually fails, with an excerpt of what arrived — because "not JSON" alone tells an operator nothing they can act on.

This would have blocked the 4.2 walk's builder identically. That walk resolved it, so **cgr.dev changed its response between 2026-09-01 and 2026-09-08** — the same week it changed the image's availability.

### 2. The builder image was withdrawn seven days after it was reviewed — and the review had not been written down

`cgr.dev/chainguard/kaniko` returns an empty tag list to an anonymous puller; Docker Hub returns 401; Chainguard's directory now shows the image as `cgr.dev/ORGANIZATION/kaniko`. The maintained fork [ADR 0010](../adr/0010-application-image-builds.md) decision 10 chose is no longer publicly pullable.

Pulling **by digest** survives their tier changes, so the 4.2 walk's reviewed digest would still have worked — except that nothing recorded it. Both runbooks said *"record the digest it prints"* into a shell variable, and no commit, no metadata and no ADR carried it. **The review happened, was never written down, and died with the session.** That half was entirely within this project's control and is the more embarrassing of the two.

[ADR 0011](../adr/0011-build-toolchain-mirroring.md) is the response: reviewed third-party images are **mirrored into the instance's own registry**, so no third party's catalogue policy can stop an instance deploying; the copy preserves the digest of the platform manifest, so a mirror is checkable in two hops without trusting FarCast's code; and the builder is Google's archived Kaniko, pinned — explicitly a stopgap, with the exits named.

Both mirrors were verified against upstream during this walk, and both matched.

### 3. `farcast ps --all` claimed to show FarCast's own components and omitted storage

`ps` listed Deployments. The key holder is a **StatefulSet**, so `datasphered` did not appear at all — on a command whose `--all` flag exists precisely to show the instance's own machinery. `farcast logs` had the same gap from the other side: it built `deployment/<name>`, which names nothing for a StatefulSet.

Both now ask for `deployments,statefulsets` and carry the kind through, and the log target is built from the kind that was found. The regression tests sit at the cluster layer, where the kubectl argument and the JSON decoding actually happen — a first attempt tested through a fake that returned pre-built workloads and caught neither mutation.

### Incidental: an object written before its scope exists becomes unreachable by name

Not a 4.3 defect, and found only because `farcast release` refused to destroy data without consent — a safety gate earning its keep.

A fresh instance has no bucket, `farcast storage deploy` refuses without one, and the only way to mint a bucket is to write an object. The documented place to write is `app/`. But the `app` **scope** does not exist yet, so the object is encrypted under the **master** key space — and `farcast storage unseal` then mints `app`, which owns the `app/` prefix from that moment on.

`ls --explain` names it exactly:

```
master   owns (everything outside every scope)   1 object(s) under it, 1 name(s) recovered
app      owns app/                               1 object(s) under it, 0 name(s) recovered
```

The listing recovers the name through master; the read routes through `app` and reports `object not found`. Nothing is lost — master still holds the key — but the CLI will not reach the object by its own name, and **the documented bring-up order walks you into it.**

The message is the sharper half: `stored data failed integrity check`. Nothing is corrupt; the wrong key was tried. Telling an operator that encrypted storage failed an integrity check, in a system whose whole premise is that the cloud cannot tamper with their data, sends them hunting for corruption that does not exist. "Cannot decrypt because this is not my object" and "decrypted and the tag did not verify" must not share a message.

Filed for a separate session; the smallest real fix may be letting `storage deploy` mint an empty bucket itself, which removes the trap rather than handling it.

### Not a finding: the meter briefly reported five pods for six

`farcast costs` said `across 5 pods` while the cluster had six. The sixth was the application that had just started, and the checkpoint carrying the observation is written every five minutes. The next checkpoint reported six and the rate matched exactly.

This is the documented staleness, and it was diagnosable in seconds **only because the observation carries its own age** — `observed 2m ago`. Without that field it would have looked like a metering bug, which is the most alarming thing this system can appear to have.

---

## What this walk did not cover

- **A repository whose manifest is at its root.** This walk used `--manifest`, because FarCast's own repository has no root `./farcast`. The default path is the same code with a different string — and "the same code with a different string" is the shape of several findings here.
- **A multi-application manifest.** One app was built. The one-at-a-time ordering is unit-tested and was not exercised against a cluster.
- **`--namespace`,** and a build that fails in a real cluster.
- **The private-repository path.** Step 10 was skipped by choice; it needs a read-only credential.
- **Shrike.** Per-application enforcement is 4.4. The manifest is *reviewed* per application and *enforced* per instance, so the gate this walk validated is currently stronger than what backs it.
- **Invoice reconciliation.** Still open from 4.1, and still the largest unverified claim in the project: every figure here is modelled from a published rate card, and `farcast costs` now puts those figures in front of an operator as the answer to "what am I spending".
