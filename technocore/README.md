# TechnoCore

> Kernel — orchestration, instance lifecycle, adaptive resource management.

> **GKE Autopilot constraints ([ADR 0003](../docs/adr/0003-gke-autopilot.md)):** TechnoCore runs as an **in-cluster Kubernetes controller** (least-privilege ServiceAccount + RBAC) operating in app namespaces — never `kube-system`. It scales apps by adjusting Pod replicas/requests (Autopilot provisions compute automatically — no node-pool management, no GKE-API calls to add capacity), and every workload it deploys must be Autopilot-admission-compliant (resource **requests on every container**, no privileged/host-network). Prefer templating the SDK/FatLine sidecar into Deployments over a mutating admission webhook. The control plane it drives is **private** (no public IP), but in-cluster access is over the internal endpoint regardless — TechnoCore needs no public endpoint ([ADR 0004](../docs/adr/0004-private-control-plane.md)).

## Design

[ADR 0009](../docs/adr/0009-technocore-kernel-and-cost-metering.md) settles the three questions Phase 4.1 turns on, and is the specification until this README catches up with the code:

- **TechnoCore is a stateless reconciler and the cluster is its registry.** Declared intent lives as labels and annotations on the workloads themselves, so a restart-sealed instance still has a kernel — the thing that must stay alive to say *why* it is sealed and what it costs while sealed. Its one piece of persisted state is the cost ledger, and that is a ConfigMap because the provider computed every number in it first.
- **It reaches the API server through a hand-rolled, standard-library client, and polls rather than watches.** `client-go` would roughly triple a vendored tree this repository audits as a security property. For a kernel, a loop that cannot silently stop reconciling is worth more than freshness measured in seconds.
- **Spending is two figures, not one.** `expected` is metered locally and continuously — Autopilot bills a Pod's *requests*, so spending is a pure function of numbers FarCast itself writes, computed by [`pricing`](pricing/) from the rate card in [ADR 0003](../docs/adr/0003-gke-autopilot.md). It needs no credential and is what every warning and every protective action fires on. `confirmed` is the provider's own number for a window that has closed; it arrives about a day late, never drives an action, and exists to correct `expected` and calibrate the model behind it. The correction is clamped, and a missing `confirmed` is a named state rather than a zero — so a billing feed that lies, breaks or never arrives can make the estimate wrong but cannot switch the guard off.
- **No billing credential enters the cluster.** `confirmed` is pulled by the operator's machine, which already holds the credential, and pushed in. Reading it in-cluster would mean a grant scoped to a *billing account* — every project the operator owns, not just FarCast's.

### What a cost shutdown may not stop

Workloads carry `farcast.sofmon.com/tier` — `kernel`, `system` or `app`. A cost shutdown scales down `app` workloads only, most expensive first. `datasphered` and FatLine are `system` and are never stopped by one: at ADR 0003's rates the whole system tier is about $15/month against an instance floor near $73, so stopping it saves a fifth of the bill and makes the instance unsealable while the rest keeps billing ([ADR 0008](../docs/adr/0008-in-cluster-key-delivery.md)'s recovery-floor finding). When every application is stopped and spending is still over the limit, TechnoCore reports the floor and names the levers that remain — releasing the load-balancer carrier, or releasing the instance. Both destroy operator-visible capability; a kernel does not take them on its own.

## Packages

| Package | What it is |
|---|---|
| [`pricing`](pricing/) | The Autopilot rate card from [ADR 0003](../docs/adr/0003-gke-autopilot.md), and the arithmetic that turns declared Pod requests into money. No dependencies, no cluster access — the sums only. |
| [`kube`](kube/) | A hand-rolled, standard-library Kubernetes client scoped to what a kernel needs: list pods and deployments, read requests and conditions, patch the scale subresource. Polls; does not watch. |
| [`tier`](tier/) | The `farcast.sofmon.com/tier` classification and the rule that only applications are stoppable by a cost shutdown. |
| [`cost`](cost/) | The `expected`/`confirmed` ledger, the calibration clamp, and threshold assessment against the limit. |
| [`kernel`](kernel/) | The reconcile loop that joins them: observe, meter, assess, act — plus the ConfigMap checkpoint that makes the accounting survive a restart. |

### Two things in here that look like details and are not

**The ServiceAccount token is re-read on every request.** A projected token is rotated by the kubelet while the pod runs, so a client that reads it once works perfectly until it abruptly does not — 401s an hour in, from a process that has been healthy since start-up.

**An unlabelled workload is protected, not stopped.** It could be a mislabelled application, where stopping it saves money, or a system component whose label was lost, where stopping it costs an instance nobody can unseal while it carries on billing. Those two mistakes are not equally bad, so the tie goes to not stopping — and the kernel reports what it could not classify rather than guessing. The cost is real and stated: on an instance whose workloads carry no labels, a cost shutdown does nothing but say so.

**A cost shutdown stops Deployments, not Pods.** Deleting a pod only makes its controller create another one, so the meter reads pods — which is what Autopilot bills — and the shutdown scales deployments, which is what can actually be stopped. The two are attributed to each other through the deployment's own selector.

**Everything the kernel writes is a zero.** There is no code path that scales anything up. Bringing an application back after a shutdown is an operator decision, and a `confirmed` correction that dropped accrued spend below the limit leaves the applications stopped and the operator informed — which is the right way round.

**The floor means "nothing left to stop", not "nothing was stopped".** An instance whose every scale call was refused has a permissions problem and plenty left to stop; reporting that as the floor would tell the operator the kernel had done all it could when it had done nothing.

*Deploy manifest, RBAC and the operator-side commands follow as 4.1 lands.*
