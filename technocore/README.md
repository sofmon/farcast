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
| [`usage`](usage/) | What workloads actually consume, as a bounded rolling distribution per application. Advisory: nothing in the cost path reads it. |
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
| `pods.metrics.k8s.io` | `list` | The profile reads what a pod actually uses. |
| `deployments` | `list` | The shutdown reads what can be stopped. |
| `deployments/scale` | `patch` | The only thing the kernel ever writes to a workload. |
| `configmaps` | `create` | To make its ledger the first time. |
| `configmaps` (named `technocore-ledger`) | `get`, `update`, `patch` | To maintain it, and nothing else in the namespace. |
| `configmaps` (named `technocore-confirmed`) | `get` | To read the provider figures the operator pushes — and never to write one. |
| `configmaps` (named `technocore-namespaces`) | `get` | To read the namespaces the operator asked to meter — and never to widen or narrow its own scope. |
| `configmaps` (named `technocore-profiles`) | `get`, `update`, `patch` | To maintain the usage profiles, in their own object so they can never make the ledger unwritable. |

There is no `watch` (the loop polls), no `delete`, and no `get` on anything it does not own. Those absences are each a design decision rather than an oversight, and a test fails if any of them appears.

**The rules are a ClusterRole that is never bound cluster-wide.** A ClusterRole is a rule set, not a grant; binding it with a *RoleBinding* grants it in one namespace only. That is how the kernel reads pods in the namespaces FarCast owns and nowhere else — a `ClusterRoleBinding` would hand it every pod in the cluster, including the managed ones [ADR 0003](../docs/adr/0003-gke-autopilot.md) puts out of bounds.

**Create cannot be restricted by name.** Kubernetes does not know an object's name at authorization time, so `create` is namespace-scoped and every verb afterwards is pinned to the single ledger object. Without that pin the kernel could read and rewrite any ConfigMap in the namespace it shares with FatLine and `datasphered`.

### How `confirmed` arrives

The operator's machine already holds the cloud credential, so it reads the bill and pushes the number: `farcast kernel confirm` writes a `technocore-confirmed` ConfigMap and the kernel picks it up on its next reconcile. Reading billing in-cluster would need a grant scoped to a *billing account*, which spans every project the operator owns and not just FarCast's.

**The kernel is granted `get` on that object and nothing else**, and the asymmetry is the security property: it cannot author a confirmation, so it cannot fabricate the one input that corrects its own estimate. Together with [ADR 0009](../docs/adr/0009-technocore-kernel-and-cost-metering.md) decision 5's clamp, a confirmed figure is untrusted input twice over — the kernel did not write it, and it cannot move the estimate more than a factor of two in either direction.

Confirmations are applied *before* anything is metered on each tick, so the assessment already reflects them. Re-reading the same document every tick is a no-op: a window already in the ledger comes back as an overlap and is skipped, and one belonging to a period that has rolled away is skipped too. Neither is a fault — both happen on every tick once the operator has pushed anything at all.

### How a new application namespace becomes metered

Two things have to happen when Planck creates an application namespace, and doing only one is worse than doing neither.

**Permission.** [`deploy.RenderNamespaceBinding`](deploy/) emits a RoleBinding granting the kernel's ClusterRole inside that namespace. It lives in TechnoCore's package rather than the translator that creates the namespace: a translator writing its own version would be a second copy of the kernel's permission model, free to drift from the ClusterRole it references.

**Configuration.** The kernel reads a `technocore-namespaces` ConfigMap on every tick and adds what it names to the configured set. This exists so that deploying an application does not restart the kernel — it is single-replica and `Recreate`, so re-rendering the workload with a longer `--namespaces` argument would tear down the meter at exactly the moment new spending starts. The kernel is granted `get` and never `update`: a kernel that could edit its own metering scope could narrow it, and a narrowed scope looks identical to an instance that is not spending anything.

Discovery only ever **adds**. A document that omitted `farcast-system` would otherwise stop the instance's own components being metered, and under-reporting is the direction this package exists to avoid.

### When the kernel cannot see a namespace

A namespace the operator asked for but the kernel cannot list is almost always a missing RoleBinding — and it means the workloads there are running, billing, and counted nowhere. The response is graded:

- **One namespace refusing is a finding.** It is recorded in `Report.Unreachable`, the tick continues, and the rest of the instance is still metered — a single misconfigured application must not disable cost enforcement everywhere.
- **Every namespace refusing is a fault.** The tick fails. Carrying on would report `$0` for an instance that is still spending, which is the failure this component exists to prevent.
- **An incomplete tick never claims the instance floor.** `Report.Complete()` gates it, in both `Report.AtFloor()` and the shutdown's own result: a namespace the kernel could not read may hold the very workloads it would be saying it has run out of ways to stop.

### The kernel publishes what it saw, so nothing models it twice

`farcast costs` reports spending by reading the kernel's own checkpoint — the rate, the pod count, the level, and the limit **the cluster is actually enforcing**, all written as an `Observation` alongside the ledger.

It would be easy for the CLI to list pods and price them itself. That is the mistake: two implementations of the same arithmetic eventually quote two different numbers, and the one an operator reads would not be the one enforcement acts on. The same reasoning is why the observation carries the kernel's limit rather than the operator's recorded one — when a limit has been changed locally and not redeployed, the cluster is still acting on its own, and a report that quietly showed the local figure would be describing an enforcement that is not happening.

The observation rides the checkpoint's schedule rather than adding a write per tick, so it is as stale as the last checkpoint and carries the timestamp that says so. It also carries `Incomplete` and the unreadable namespaces, because a figure built on a partial picture is a floor and not a total.

### What a pod uses, as opposed to what it reserves

Everything above is about **requests**, because requests are what Autopilot bills. [ADR 0014](../docs/adr/0014-observed-usage.md) adds the other half: what a pod actually consumes, read from the aggregated `metrics.k8s.io` API on the same tick, by the same client, and surfaced as `farcast usage`.

Four things about it are decisions rather than details.

**It never enforces.** The cost meter reads requests and only requests. A namespace whose metrics cannot be read is a named state on the report — and unlike metering, *every* namespace failing is still not a fault. The asymmetry is the point: metering that reads nothing would report `$0` for an instance that is spending, so it must fail loudly; a profile that reads nothing means a future resize declines, which is the safe direction.

**A profile describes one pod, not one application.** Summing three replicas and recommending the total as a request would be wrong by the replica count. Each pod contributes its own sample, so the distribution is across pods and time together, and the replica count is recorded beside it as the separate question it is.

**History is a bounded distribution, never a sample log.** Twenty-four hourly slots per application, each an exponential-bucket histogram with an exact count, sum and peak. The stored size is fixed by the window rather than by uptime, so an instance up for a year holds what one up for a day holds. Keeping samples instead would have grown until a 1 MiB ConfigMap started refusing writes — months after it worked in testing — and a thirty-second series of per-application CPU is a timeline of when the operator is awake. Trend is the last hour compared against the day, not a chart.

**The profiles are their own ConfigMap.** Not a section of the ledger's: the ledger must always be writable, and an advisory document must never be able to make the cost checkpoint fail. It is trimmed to a byte budget by shortening the retained window for everybody first, and only then dropping the least recently seen — degrade uniformly before degrading anybody to nothing. Both are published, because a window that is short because the budget shortened it looks exactly like an instance that has only just started.

Storing these numbers discloses nothing new, by [ADR 0009](../docs/adr/0009-technocore-kernel-and-cost-metering.md) decision 2's own test: they come from the provider's kubelet by way of the provider's metrics-server, so the cloud measured every one of them first.

### One replica, replaced rather than overlapped

The kernel is a meter with a single ledger, so its Deployment is `replicas: 1` with `strategy: Recreate`. A rolling update would run two kernels for a few seconds; both would meter the same instance into their own in-memory ledgers and race to write the same checkpoint, and the period's spending would become whichever wrote last.

It carries **no PodDisruptionBudget**, deliberately: a single-replica workload behind `minAvailable: 1` makes every node drain hang forever, which would block the auto-upgrades ADR 0003 accepts. The checkpoint is what makes the kernel's own reschedule survivable — the successor bills the gap it slept through — so it does not need one.

*The operator-side commands are `farcast kernel deploy|meter|confirm` (4.1), `farcast costs` (4.3) and `farcast usage` (5.1).*
