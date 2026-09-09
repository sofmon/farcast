# Phase 5.1 — Live Validation

Phase 5.1 asks whether TechnoCore can see what applications actually use, and whether the boundary can say what crossed it. Both halves were written against fixtures. This walk asks the two questions no fixture can answer: **does GKE's managed metrics-server answer FarCast's own client**, and **is the monitor reachable through the tunnel on the Pod's own loopback**.

Designed by [ADR 0014](../adr/0014-observed-usage.md) (compute) and [ADR 0015](../adr/0015-what-the-boundary-can-measure.md) (network).

**Walked 2026-09-09** against instance `p51b` on GKE Autopilot in `us-central1`, released the same day. About 60 minutes of billing against a ~$77.17/month floor — roughly **$0.11**. Teardown verified independently: no clusters, forwarding rules, target pools, registries, buckets or disks remained.

---

## Prerequisites

An instance installed and connected, with the kernel deployed and the build toolchain mirrored — the state [the 4.3 runbook](phase-4-3-validation.md) leaves behind.

---

## 1. Does the cluster serve the metrics API at all?

This is the assumption most likely to be wrong, and it is one command:

```bash
kubectl get --raw /apis/metrics.k8s.io/v1beta1
kubectl top pods -n farcast-system
```

Expected: `PodMetrics`, `namespaced: true`, with `list` among its verbs.

**Result: ✅.** GKE Autopilot serves it with nothing installed. The raw list also confirmed the wire shape the hand-rolled client parses — `timestamp`, `window: "30.323s"`, and per-container `usage` in **nanocores** (`335718n`) and **kibibytes** (`1984Ki`), neither of which the request path ever sees. `labelSelector` works on the aggregated API, so the kernel's `managed-by=farcast` selector narrows it exactly as it does for pods.

## 2. Does the kernel's grant work?

```bash
kubectl logs -n farcast-system deploy/technocore | grep "observed usage"
```

Expected: `sampled=N unrefreshed=0 unavailable=[]`.

**Result: ✅.** Sampling from the first tick, `unavailable=[]` throughout 42 ticks. The `metrics.k8s.io` rule, bound namespace-scoped like every other rule, is sufficient.

## 3. Is the profile document the shape and size it was designed to be?

```bash
kubectl get configmap technocore-profiles -n farcast-system -o jsonpath='{.data.profiles\.json}'
```

**Result: ✅, and one detail earned its keep.** 728 bytes for two applications after one hour; 1007 bytes for three after thirty-five minutes of a busier instance. Nothing was trimmed and no window was shortened, so the byte budget was never approached.

The bucket scheme showed exactly why its bottom is linear rather than logarithmic: `technocore` recorded `{"1": 9, "11": 1}` — a steady 1 millicore with its own start-up spike at 11 in a **separate exact bucket**. A purely logarithmic scheme would have merged the two, and the p95 an eventual resize reads would have been the spike.

## 4. Is Shrike reachable through the tunnel, on loopback?

```bash
kubectl get deploy fatline -n farcast-system -o jsonpath='{.spec.template.spec.containers[0].args}'
farcast usage "$INSTANCE"
```

Expected: `--stream-route=shrike=127.0.0.1:9090` among the args, and a `Network` section in the report.

**Result: ✅.** The route deployed, resolved, and returned Shrike's picture. **No new cluster exposure was needed**: the listener still binds loopback with no Service, and FatLine's relay reaches it because it shares the Pod. An instance with no traffic reported *"No application has made an outbound connection"* rather than a row of zeros or an error.

## 5. Do the new events fire on real traffic?

With an application whose manifest declares one host, from inside its pod:

```bash
curl https://example.com/          # declared      → allow, then close
curl https://example.com:81/       # declared host, closed port → allow, then FAIL
curl https://www.wikipedia.org/    # undeclared    → deny
curl -x http://fatline-egress…     # no credential → deny, unknown_app
```

**Result: ✅, all four.** FatLine's own log:

```
kind=close … app=reacher host=example.com bytes_up=1916 bytes_down=6410 dial_ms=25 duration_ms=70
kind=fail  … app=reacher host=example.com port=81 reason=dial_failed dial_ms=30002
kind=deny  … app=reacher host=www.wikipedia.org reason=not_in_allowlist
kind=deny  … app="" host=example.com reason=unknown_app
```

The `kind=fail` line **did not exist before this phase**: an allowed connection whose upstream could not be reached emitted an `Allow` and then nothing at all. Here it carries the dialer's full 30-second wait, which is what distinguishes a hung dial from a refused one. Connection times across the successful calls ranged 24–105 ms.

## 6. What does the report actually say?

```bash
farcast usage "$INSTANCE"
```

**Result: ✅ for the shape, and it surfaced one defect — see below.** Both halves render together, each naming what it could not measure. The unidentified caller appears as `(unidentified)` rather than an empty cell.

---

## What the walk found

### 1. The network picture is one replica's, and the report presented it as the instance's

**The defect this walk existed to find.** FatLine runs two replicas ([ADR 0005](../adr/0005-fatline-data-plane-ingress.md)); since [ADR 0013](../adr/0013-per-application-egress-identity.md) each carries its own Shrike, and therefore its own picture. A read through the tunnel lands on whichever replica terminated the stream — so four consecutive reports alternated between two different partial counts:

```
reacher{hosts=1 allows=4 fails=0 denies=1 up=7664 down=25663}
reacher{hosts=2 allows=4 fails=1 denies=0 up=5748 down=19276}
reacher{hosts=1 allows=4 fails=0 denies=1 up=7664 down=25663}
reacher{hosts=2 allows=4 fails=1 denies=0 up=5748 down=19276}
```

Neither is the instance's traffic, and both `since` timestamps were identical, so nothing in the output hinted that the picture had changed pods. This is the recurring shape: correct components, wrong at the layer where the number reaches a human.

**Fixed and re-verified live.** The report now reads the replica count from the cluster and says whose picture it is:

```
Seen by one FatLine replica, of 2. Each keeps its own picture, so these
are that replica's share of the instance's traffic, not the total.
```

The warning turns on the **replica count**, not on the monitor naming itself, so a sidecar older than the reader still triggers it — verified live against exactly that combination. Shrike also now reports its own pod name; that half is unit-tested only, because deploying it needed a new image tag and the walk was mid-teardown.

**Aggregating across replicas is not solved here.** The route resolves to `127.0.0.1`, which is by construction whichever pod answered; the keyholder addresses replicas through a headless Service with `{ordinal}`, which a Deployment does not have. Saying the count is a share is the honest floor, not the end state.

### 2. The reading-dedupe never fired, and that is worth knowing

All 42 ticks reported `unrefreshed=0`. metrics-server's window measured **30.323 s** against the kernel's 30 s tick, so a reading had always advanced by the time it was read. The guard against counting one measurement twice is therefore **defensive rather than load-bearing at the default interval** — it is unit-tested, and it was not exercised live. A shorter `--interval` would exercise it.

### 3. The 5.2 case, in three numbers

| workload | CPU peak observed | CPU reserved | memory peak | memory reserved |
|---|---|---|---|---|
| fatline (2 containers) | 2m | 150m | 10Mi | 192Mi |
| technocore | 11m | 100m | 10Mi | 128Mi |
| reacher | 27m | 100m | 10Mi | 128Mi |

Every workload on the instance reserves between roughly **4× and 75×** what it used. That is the whole argument for Phase 5.2, measured rather than asserted.

### 4. The in-cluster build could not push, and it is not FarCast's defect

`farcast run` failed at Kaniko's push check with `DENIED: Permission 'artifactregistry.repositories.uploadArtifacts'`, despite the repository-level grant [the 4.2 runbook](phase-4-2-validation.md) prescribes being present and correct, the cluster's workload pool matching, and a pod running as `farcast-builder` **successfully reading** the same repository through the Artifact Registry API. Reads were honoured and writes were refused on the Docker token endpoint, across four attempts over twelve minutes.

This blocked `farcast run`, so **the walk did not exercise it**. The policy document `run` would have written was constructed by hand instead, through the product's own `fatline/policy` package so the format could not drift, and applied as the same ConfigMap FatLine watches. Everything in section 5 is therefore real traffic through a real boundary under a real per-application credential — but the path that *produces* that policy was not walked here. It was walked on 2026-09-08 for 4.4.

### 5. A false finding, caught before it was recorded

The first round of probes showed an **undeclared host returning 200**, which would have been a catastrophic enforcement failure. It was not one: `FARCAST_FATLINE_PROXY` is FarCast's variable, not curl's, and the hand-made probe pod carried none of the NetworkPolicy Planck renders — so the requests went straight out to the internet without touching FatLine at all. Re-running with `https_proxy` set produced `CONNECT tunnel failed, response 403` from the boundary, as it should.

Worth recording because the mistake is instructive: the NetworkPolicy is what makes the boundary unavoidable, and a pod built by hand does not have it. Every claim about enforcement in section 5 is from the second round.

---

## Criteria

| # | Criterion | Result |
|---|---|---|
| 1 | GKE Autopilot serves `metrics.k8s.io` to FarCast's hand-rolled client | ✅ |
| 2 | The kernel's new RBAC grant suffices, in every metered namespace | ✅ |
| 3 | Usage is collected without affecting metering or cost enforcement | ✅ — rate and ledger unchanged throughout |
| 4 | The profile document persists, restores, and stays small | ✅ — 1007 bytes for three applications |
| 5 | The bucket scheme separates a start-up spike from a steady state | ✅ |
| 6 | Shrike is reachable through the tunnel with no new cluster exposure | ✅ |
| 7 | An allowed connection that cannot be established is recorded | ✅ — `kind=fail`, `dial_ms=30002` |
| 8 | Bytes and connection latency are attributed per application | ✅ |
| 9 | An unidentified caller appears, named as such | ✅ |
| 10 | The report distinguishes "not measured" from "measured as zero" | ✅ — both states seen |
| 11 | The network counts are not presented as more than they are | ✅ **after a fix** — see finding 1 |
| 12 | The reading-dedupe is exercised | ⚠️ **not exercised** — see finding 2 |
| 13 | `farcast run` produces the policy the boundary enforces | ⛔ **not walked here** — see finding 4 |
