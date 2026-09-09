# ADR 0014 — Observed Usage Is a Bounded Distribution, and It Never Enforces

**Status:** Accepted

**Date:** 2026-09-09

**Relates to:** Unblocks Phase 5.1 and constrains 5.2. Extends [ADR 0009](0009-technocore-kernel-and-cost-metering.md) — same reconcile loop, same hand-rolled client, same stateless-reconciler stance — and reuses its `expected`/`confirmed` reasoning about inputs that can lie or vanish. Bounded by [ADR 0003](0003-gke-autopilot.md): Autopilot bills the Pod and permits no node access, so both what is measured and what could measure it are already decided.

---

## Context

The manifest declares no resources. [AGENTS.md](../../AGENTS.md) makes that a promise rather than an omission: *"Manifests never specify resources, ports, or infrastructure details. TechnoCore monitors and adapts resources automatically."* Today only the first half of the sentence has code behind it, and not the half it claims: TechnoCore meters **requests**, which is what Autopilot bills, and has never once looked at what an application actually uses.

That gap is why every FarCast workload runs on a hard-coded number. FatLine asks for 100m/128Mi because someone typed it; the example application takes Planck's default. Nobody knows whether either is right, and the instance floor — $77.17/month as measured on 2026-09-09 — is the sum of those guesses.

Phase 5.2 is supposed to close the gap by adjusting requests. It cannot be built on nothing: an adaptive scaler needs a defensible answer to *what does one pod of this application actually use*, over a window long enough that a startup spike does not become a permanent reservation.

### What can measure it

- **The aggregated `metrics.k8s.io` API.** GKE runs metrics-server as a managed add-on, which is why `kubectl top` works on an Autopilot cluster with nothing installed. It is namespaced, it is reachable from the client [`kube`](../../technocore/kube/) already is, and reading it needs one more RBAC rule bound exactly the way every other rule already is.
- **Cloud Monitoring.** Richer, and retains history so FarCast would not have to. Rejected: it needs a credential *inside the cluster*, which is the thing [ADR 0009](0009-technocore-kernel-and-cost-metering.md) decision 4 refused for billing, and for the same reason — the grant is not scoped to what FarCast runs.
- **The kubelet's cAdvisor endpoint, or an in-pod agent.** Rejected by [ADR 0003](0003-gke-autopilot.md): Autopilot permits neither node access nor the privileges an agent would want.

### What cannot be measured this way

metrics-server reports CPU and memory. It does not report network I/O or request latency, and no amount of RBAC will make it. Those two live at the boundary FarCast already owns — **FatLine sees every byte an application sends and how long each connection took**, because [AGENTS.md](../../AGENTS.md) says nothing else touches the network. Measuring them anywhere else would be measuring them a second time, less well.

---

## Decisions

**1. Usage is read from `metrics.k8s.io`, on the reconcile loop's own tick.** No new client, no new process, no watch. One `list` per metered namespace, alongside the pod list already being taken.

**2. Usage is advisory and can never switch a guard off.** The cost meter continues to read requests and only requests. A namespace whose metrics cannot be read is a named state on the report, not a failure — and unlike metering, *every* namespace failing is still not a fault. The asymmetry is the point: metering that reads nothing would report `$0` for an instance that is spending, so it must fail loudly; a profile that reads nothing means 5.2 declines to resize, which is the safe direction. This is [ADR 0009](0009-technocore-kernel-and-cost-metering.md) decision 5's stance about `confirmed`, applied to a second untrusted input.

**3. A profile describes one pod, not one application.** Summing three replicas and recommending the total as a request would be three times wrong. What the profile exists to size is a pod, so each pod contributes its own sample per tick and the distribution is across pods and time together. Replica counts are recorded separately, because horizontal scaling is a different question with a different answer.

**4. History is a bounded rolling distribution, never a sample log.** Per application, per resource: a ring of twenty-four hourly slots, each an exponential-bucket histogram with exact count, sum and peak. The size is fixed by the window, not by uptime — an instance running for a year stores exactly what one running for a day stores. Trend is *the short window compared against the long one*, not a chart: whether the last hour sits above the day's distribution answers the question 5.2 asks, and a chart would only be a more expensive way to answer it.

Keeping samples was the obvious alternative and is refused twice over. It grows without bound in a ConfigMap capped at 1 MiB, so it would work in testing and start failing writes on a busy instance months later. And a thirty-second series of per-application CPU is a **timeline of when the operator is awake** — the kind of behavioural record this project exists not to leave lying around.

**5. Storing the distribution discloses nothing new, and that is checkable rather than asserted.** [ADR 0009](0009-technocore-kernel-and-cost-metering.md) decision 2's test for cloud-resident state is whether it tells the cloud something it does not already have. These numbers come from Google's own kubelet by way of Google's own metrics-server: the provider measured every one of them before TechnoCore read it. The honest limit is stated rather than glossed — a provider watching every write to the ConfigMap could reconstruct the hourly shape it already served us. What the stored document does not do is *accumulate* that shape into a record any single read discloses.

**6. Profiles live in their own ConfigMap, and are trimmed to fit.** Not in the ledger's: the ledger must always be writable, and an advisory document must never be able to make the cost checkpoint fail. The store is trimmed against a byte budget by first shortening the retained window for every application equally, and only then dropping the least recently seen — degrade uniformly before degrading anybody to nothing. Both are reported.

**7. A sample is taken only when the measurement advances.** metrics-server refreshes on its own cadence and serves the same reading until it does. Polling faster than it refreshes would count one measurement several times and pull every distribution toward whatever the sampler happened to catch. The reading's own timestamp is what makes a sample new.

---

## Consequences

**5.2 gets a defensible input and an explicit refusal.** `p95 over 24h, plus headroom` is a number an adaptive scaler can act on, and `coverage too thin` is a state it can decline on. Both are in the profile rather than invented at the point of use.

**A pod's profile is the pod's, sidecars included.** Application pods are single-container today, so for the workloads 5.2 will resize first this is exact. FatLine's pod is not — since [ADR 0013](0013-per-application-egress-identity.md) it carries Shrike — and its profile is the two containers together. That matches how the meter already reads it, deliberately: Autopilot bills the Pod, so the thing being sized and the thing being billed stay the same thing. Per-container attribution becomes necessary the day a resize needs to move one container's request and not the other's, and not before.

**Network I/O and request latency are not in this slice, and are not dropped.** They are FatLine's measurements, reached by a different path, and folding them in here would have meant inventing a worse source for them.

**The kernel now reads one more API group.** `metrics.k8s.io` `pods` `list`, bound namespace-scoped like every other rule — no `watch`, no `get`, and nothing outside the namespaces FarCast owns.

---

## Phasing

- **5.1a (this decision):** CPU and memory, collected, profiled, persisted, and surfaced to the operator as `farcast usage`.
- **5.1b:** network I/O and latency, measured by FatLine per application and read from there.
- **5.2:** the scaler acts on the profile — and on its refusals.

---

## Revisit triggers

- **metrics-server is absent or unreliable on a target provider.** Decision 2 means this degrades rather than breaks, but a second cloud adapter where it is simply not there would make decision 1 provider-specific rather than general.
- **A resize needs to move one container and not another.** That is the day decision 3's pod-level attribution stops being enough.
- **The trim starts firing on a real instance.** Decision 6's budget is a guess until an instance with many applications proves it either generous or tight.

---

## Sources

- [ADR 0003 — GKE Autopilot](0003-gke-autopilot.md): Pod-level billing, and the node access Autopilot does not permit.
- [ADR 0009 — TechnoCore kernel and cost metering](0009-technocore-kernel-and-cost-metering.md): the reconcile loop, the ConfigMap-as-state test, and the stance on inputs that can lie or vanish.
- [ADR 0013 — Per-application egress identity](0013-per-application-egress-identity.md): why FatLine's pod has two containers.
