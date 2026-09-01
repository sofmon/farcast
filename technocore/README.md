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
| [`deploy`](deploy/) | The kernel's own Namespace, ServiceAccount, RBAC and Deployment, rendered as a YAML apply stream. |
| [`cmd/technocore`](cmd/technocore/) | The in-cluster entrypoint: `technocore serve`. |

### Two things in here that look like details and are not

**The ServiceAccount token is re-read on every request.** A projected token is rotated by the kubelet while the pod runs, so a client that reads it once works perfectly until it abruptly does not — 401s an hour in, from a process that has been healthy since start-up.

**An unlabelled workload is protected, not stopped.** It could be a mislabelled application, where stopping it saves money, or a system component whose label was lost, where stopping it costs an instance nobody can unseal while it carries on billing. Those two mistakes are not equally bad, so the tie goes to not stopping — and the kernel reports what it could not classify rather than guessing. The cost is real and stated: on an instance whose workloads carry no labels, a cost shutdown does nothing but say so.

**A cost shutdown stops Deployments, not Pods.** Deleting a pod only makes its controller create another one, so the meter reads pods — which is what Autopilot bills — and the shutdown scales deployments, which is what can actually be stopped. The two are attributed to each other through the deployment's own selector.

**Everything the kernel writes is a zero.** There is no code path that scales anything up. Bringing an application back after a shutdown is an operator decision, and a `confirmed` correction that dropped accrued spend below the limit leaves the applications stopped and the operator informed — which is the right way round.

**The floor means "nothing left to stop", not "nothing was stopped".** An instance whose every scale call was refused has a permissions problem and plenty left to stop; reporting that as the floor would tell the operator the kernel had done all it could when it had done nothing.

### What the kernel is allowed to do

The grants are exactly the verbs [`kube`](kube/) calls, and the shape is as important as the list:

| Resource | Verbs | Why |
|---|---|---|
| `pods` | `list` | The meter reads what Autopilot bills. |
| `deployments` | `list` | The shutdown reads what can be stopped. |
| `deployments/scale` | `patch` | The only thing the kernel ever writes to a workload. |
| `configmaps` | `create` | To make its ledger the first time. |
| `configmaps` (named `technocore-ledger`) | `get`, `update`, `patch` | To maintain it, and nothing else in the namespace. |
| `configmaps` (named `technocore-confirmed`) | `get` | To read the provider figures the operator pushes — and never to write one. |

There is no `watch` (the loop polls), no `delete`, and no `get` on anything it does not own. Those absences are each a design decision rather than an oversight, and a test fails if any of them appears.

**The rules are a ClusterRole that is never bound cluster-wide.** A ClusterRole is a rule set, not a grant; binding it with a *RoleBinding* grants it in one namespace only. That is how the kernel reads pods in the namespaces FarCast owns and nowhere else — a `ClusterRoleBinding` would hand it every pod in the cluster, including the managed ones [ADR 0003](../docs/adr/0003-gke-autopilot.md) puts out of bounds.

**Create cannot be restricted by name.** Kubernetes does not know an object's name at authorization time, so `create` is namespace-scoped and every verb afterwards is pinned to the single ledger object. Without that pin the kernel could read and rewrite any ConfigMap in the namespace it shares with FatLine and `datasphered`.

### How `confirmed` arrives

The operator's machine already holds the cloud credential, so it reads the bill and pushes the number: `farcast kernel confirm` writes a `technocore-confirmed` ConfigMap and the kernel picks it up on its next reconcile. Reading billing in-cluster would need a grant scoped to a *billing account*, which spans every project the operator owns and not just FarCast's.

**The kernel is granted `get` on that object and nothing else**, and the asymmetry is the security property: it cannot author a confirmation, so it cannot fabricate the one input that corrects its own estimate. Together with [ADR 0009](../docs/adr/0009-technocore-kernel-and-cost-metering.md) decision 5's clamp, a confirmed figure is untrusted input twice over — the kernel did not write it, and it cannot move the estimate more than a factor of two in either direction.

Confirmations are applied *before* anything is metered on each tick, so the assessment already reflects them. Re-reading the same document every tick is a no-op: a window already in the ledger comes back as an overlap and is skipped, and one belonging to a period that has rolled away is skipped too. Neither is a fault — both happen on every tick once the operator has pushed anything at all.

### One replica, replaced rather than overlapped

The kernel is a meter with a single ledger, so its Deployment is `replicas: 1` with `strategy: Recreate`. A rolling update would run two kernels for a few seconds; both would meter the same instance into their own in-memory ledgers and race to write the same checkpoint, and the period's spending would become whichever wrote last.

It carries **no PodDisruptionBudget**, deliberately: a single-replica workload behind `minAvailable: 1` makes every node drain hang forever, which would block the auto-upgrades ADR 0003 accepts. The checkpoint is what makes the kernel's own reschedule survivable — the successor bills the gap it slept through — so it does not need one.

*The operator-side deploy command follows as 4.1 lands.*
