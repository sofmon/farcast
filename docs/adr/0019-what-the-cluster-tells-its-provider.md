# ADR 0019 — What the Cluster Tells Its Provider

**Status:** Accepted. Not yet walked: whether Autopilot accepts and honours decision 1 is open until the next walk's install (Context, *Logging*).

**Date:** 2026-11-10

**Relates to:** Amends the cluster [ADR 0003](0003-gke-autopilot.md) chose and [ADR 0004](0004-private-control-plane.md) isolated. Extends DataSphere's [What the cloud still sees](../../datasphere/README.md#what-the-cloud-still-sees) beyond the bucket. Uses [ADR 0008](0008-in-cluster-key-delivery.md)'s distinction between what the provider *cannot* see and what it is *trusted not to look at*. Implemented in Planck's GKE adapter ([`../../planck/README.md`](../../planck/README.md#what-the-cloud-still-sees-the-clusters-own-telemetry)) and in `farcast install`, `release` and `logs`.

---

## Context

AGENTS.md says the provider is blind to *content*. Workload logs broke that.

Planck created every cluster with `Name`, `ResourceLabels`, `Autopilot`, `InitialClusterVersion` and `ControlPlaneEndpointsConfig`, and nothing else. It never set `LoggingConfig`, so GKE's default applied: **system logs and workload logs**, both ingested into the project's Cloud Logging. GKE's "system" means its own namespaces (`kube-system` and similar). `farcast-system` is not one of them. So every line FatLine, Shrike, the kernel and the keyholder wrote to stdout, and every line every application wrote, was copied into a service the provider runs and indexes, in plaintext, and kept for the project's retention period.

`farcast logs` never needed any of that. It runs `kubectl logs`, which reads the file on the node through the API server. Nothing in the repository reads Cloud Logging or Cloud Monitoring, and no client for either is vendored. The export was a default nobody asked for, and no FarCast function depended on it.

The finding came from the Phase 5 Session A walk (2026-11-10). The walk record does not carry its evidence yet. The read-back below makes the next walk produce that evidence.

What GKE's public documentation says (Sources). Where it contradicts itself, both sides are given, and the next walk decides.

- **Logging.** SYSTEM is required on every cluster type, and it includes Kubernetes **Events** (*About GKE logs*). `NONE` is not supported on Autopilot, and an empty component list means "disable all logging" (API reference). Whether Autopilot lets WORKLOADS be left out is **not settled by the documentation**:
  - *For.* *About GKE logs* calls WORKLOADS "on by default but optional for all cluster types". The Autopilot create command's own `--logging` example is `--logging=SYSTEM` (*create-auto*).
  - *Against.* The same *About GKE logs* page offers system-only capture to Standard clusters, and only exclusion filters to Autopilot. The Autopilot/Standard comparison lists workload-level logs as *pre-configured* on Autopilot, a term it defines as features you "can't change or disable". The logging troubleshooting page says the cluster's logging setting is "always enabled by default on Autopilot clusters and can't be disabled". The Autopilot overview lists workload logs among what Autopilot collects automatically.

  So Autopilot may reject a SYSTEM-only create. It may accept the create and read back WORKLOADS. Or it may read back SYSTEM_COMPONENTS and collect workload logs anyway. Decision 1 handles the first two. Only the walk's namespace-scoped count (Verification, step 2) can rule out the third. **Until that walk, system-only logging on Autopilot is unverified.**
- **Control-plane logs.** API server, scheduler and controller-manager logs are each optional, and the Autopilot create default is `SYSTEM,WORKLOAD`. There is one documented exception. Since 2024-02-20, observability packages "including control plane logs" are on by default for new managed GKE Enterprise clusters (release notes). A cluster in a project with GKE Enterprise may therefore read back control-plane components that FarCast did not ask for. The documentation does not say whether fleet registration alone does the same.
- **Audit.** Admin Activity audit logs are always on and cannot be disabled. They sit in the `_Required` bucket for **400 days**, which the project can neither shorten nor empty. Data Access audit covers reads, including `kubectl logs`, and status writes (below), and it is off by default. An organization or folder can turn it on for every project beneath it, though, and a project cannot turn off what a parent turned on.
- **The audit policy.** Requests on Secrets, ConfigMaps and TokenReviews are logged at **Metadata** level: verb, object name and namespace, caller, source IP, user agent, time and response code, with no body. Writes on the built-in API groups are, in general, logged at **RequestResponse**, with the full object. The kubelet's updates to `pods/status` are logged at **Request** level: the status it sends, without the response. GKE writes creates, updates and deletes to Admin Activity. It writes gets, lists and status updates to Data Access, and its own example of a Data Access write is updating Pod status.
- **Metrics.** On Autopilot, system metrics cannot be disabled, and they are not billed. They carry the `kubernetes.io/` prefix: per-container CPU, memory and restarts, and per-Pod network bytes, labelled by namespace, Pod and container. Managed Service for Prometheus' managed collection is on by default on Autopilot from 1.25 and cannot be turned off. **Managed collection is not idle without a user `PodMonitoring`.** GKE's own metric packages ride it and are on by default for new clusters:
  - **Kube state metrics**, on Autopilot from 1.27.4-gke.900. They record each Pod's phase, each container's readiness and waiting reason (CrashLoopBackOff, ImagePullBackOff), and Deployment and StatefulSet replica counts, sampled every 30 seconds. The package skips system namespaces. GKE lists those only for logging (`kube-system`, `gke-system` and three others), and FarCast's namespaces are not on that list, so these metrics are expected to cover them (Verification, step 1). Kube state metrics are billed per sample ingested.
  - **cAdvisor/Kubelet**, from 1.29.3-gke.1093000. They record per-container CPU, memory, filesystem and network usage, sampled every 30 seconds.
  - **JobSet**, from 1.32.1-gke.1357001. FarCast renders no JobSet.

  GKE's metrics page describes turning these packages off (`--monitoring=SYSTEM`). It makes Autopilot exceptions only for system metrics and for `NONE`. That is documented, not tried (decision 3).
- **Retention.** `_Default` keeps 30 days unless the project changes it (1–3650). `_Required` keeps 400 days, fixed. Managed Service for Prometheus data, which covers every package above, is kept for **24 months**, and so are most GKE system metrics. The data is downsampled as it ages and ends as one point every 10 minutes. Only deleting the project guarantees that metric data goes sooner.

## Decisions

**1. Every cluster is created with system-only logging, and install fails unless it reads back that way.** `buildCluster` sets `LoggingConfig{ComponentConfig{EnableComponents: [SYSTEM_COMPONENTS]}}` unconditionally. There is no knob, because there is no FarCast cluster that ships its applications' output. Once the cluster reports Running, the adapter reads its logging config back. If the config is not exactly SYSTEM_COMPONENTS, `CreateCluster` returns an error naming this ADR. That covers WORKLOADS, a nil or absent config (the provider default), an empty list, a control-plane stream nobody asked for, and a value the vendored client does not know. `farcast install` already turns that error into an instance recorded as `error`, with a pointer to `farcast release`. **An instance whose cluster reads back with workload logs is never reported as installed.**

The check also applies to a cluster that already existed under the name. `install` refuses an instance it already records, so an existing cluster there is one FarCast lost track of, and it is not adopted as private on trust.

**If Autopilot refuses system-only logging, every install fails.** That is the cost of failing closed, and it is stated here up front. A create that Autopilot rejects makes no cluster: install records `error`, and `farcast release` clears the record. A create that Autopilot accepts but that reads back WORKLOADS leaves a running, billable cluster. Install records it as `error`, and the operator must release it. Either way, nothing installs until the operator chooses a fallback. This ADR takes neither of them:
- *A project-level Log Router exclusion on the instance's container logs.* This is weaker. Exclusion filters are applied after the Logging API has received the entries, so the provider still receives every line before it discards it. The exclusion is also standing project configuration (decision 4).
- *GKE Standard*, which can turn workload logs off, at ADR 0003's cost.

The read-back is the provider's word about its configuration, not about its behaviour. A cluster that reads back SYSTEM_COMPONENTS and still collects workload logs passes it. Verification step 2 checks the behaviour.

**2. No convergence path.** An `UpdateCluster` with `DesiredLoggingConfig` exists in the API, but nothing reaches it. `install` refuses an existing instance, and no live instance predates this ADR: p5a was released, and farcast.one is pending. Whether Autopilot accepts that update is unverified. Adding an unverified mutation to the cloud for a case that cannot occur would be the wrong trade. An instance from before this ADR is reinstalled, not repaired.

**3. Monitoring is read back, not pinned.** FarCast does not set `MonitoringConfig`. Autopilot's system metrics and managed collection cannot be turned off. The adapter reads the monitoring config back alongside logging, and the opt-in integration test logs it, so the walk records what is on. The read-back is expected to list GKE's packages, with components such as POD, DEPLOYMENT, STATEFULSET, DAEMONSET, HPA, STORAGE, CADVISOR, KUBELET and JOBSET. That is recorded, not enforced. Those packages report on FarCast's namespaces, and the provider keeps the data for 24 months (*What the provider still sees*). FarCast renders no `PodMonitoring` or `ClusterPodMonitoring`, so no application's own metrics endpoint is scraped. The translator test that pins the kinds an application deployment renders enforces that, and that is all it keeps out.

*Open decision: pinning the packages off.* GKE's metrics page describes turning the packages off and makes no Autopilot exception for them. By that page, creating every cluster with monitoring pinned to SYSTEM_COMPONENTS would stop the readiness, phase and usage series for FarCast's namespaces, and system metrics would remain. This ADR does not do it. It is untried on a live Autopilot create, and a rejection would fail every install, which would compound decision 1's open question. The operator decides it after the next walk has shown what Autopilot does with logging. Auto-monitoring is opt-in and left unset.

**4. The mandatory remainder is disclosed, not fought.** System logs and Events, Admin Activity audit and system metrics stay, and so, for now, do the metric packages (decision 3). FarCast installs no project-level log exclusion, no sink and no bucket change. Each of those is standing project configuration that outlives the instance, touches every other cluster in the project, and cannot reach `_Required` anyway.

**5. Release names what outlives it, with dates, and deletes nothing there.** `farcast release` gives approximate dates for what the provider keeps:
- the audit log, until about 400 days from now;
- system logs and Events, until about 30 days from now under the default retention;
- metrics about the instance's Pods, until about 24 months from now.

For an instance not recorded as system-only, release also says that the applications' output may be among the logs. The output says the dates are approximate: audit entries expire 400 days after *each* write, a project may have changed `_Default`, and metric points expire 24 months after each sample. Ingested entries cannot be deleted per cluster. The `stdout`/`stderr` log names are project-wide, so deleting them would destroy other clusters' logs. For metric data, only deleting the project guarantees it goes sooner.

**6. `farcast logs` stays on kubectl.** It reads the node's file through the API server. Its usage text now says where logs live and who can see them, rather than claiming nothing collects them.

## What the provider still sees

Stated plainly, because this ADR would be an overpromise without it:

- **System logs and Events, about 30 days.** These carry application names, image references, scheduling, scaling, OOM kills, probe failures and restarts. A keyholder replica passes its readiness probe only when it is unsealed. So a sealed replica's failed probes are Events here, and they date the seal.
- **Admin Activity audit, 400 days, beyond release, undeletable.**
  - *Metadata only* for ConfigMaps and Secrets: FatLine's egress policy, the key pin, TechnoCore's cost ledger (`technocore-ledger`), and the `<app>-egress` Secrets. The provider sees the name, the time and the caller of every write, and never the content. That is enough to read the kernel's write cadence. *(2026-11-12: the ledger's checkpoint also records the kernel's cost stops and the instance floor ([ADR 0009](0009-technocore-kernel-and-cost-metering.md) decision 2's note), and is written at once after a stop, or when the floor is first reached, as well as every five minutes. So its cadence now dates each cost stop too — which the scale-down's own full-body entry, below, very likely already does — and the moment the floor is first reached, which follows from the scale-downs, the limit in the kernel's Deployment arguments and the provider's own bill. The usage profiles' ConfigMap is not written off its schedule.)* It also dates each `run`, key rotation, pin change and keyholder deploy, which are the commands that write the pin. And it tells the operator apart from in-cluster service accounts. `storage unseal` and a keeper's re-seed write no Kubernetes object themselves. When one brings a sealed replica back to serving, its timing reaches the provider through readiness: the Events above, the metrics below and, very likely, the endpoint updates in the next bullet, which last longest.
  - *Full bodies* for every create, update and delete on the built-in API groups, which covers Deployments, StatefulSets, Jobs, Pods, Namespaces, Services and NetworkPolicies. That includes application names, images and resource requests, and very likely TechnoCore's resizes and cost-stop scale-downs. It also includes literal values in two Jobs, and in the Pods created from them:
    - the fetch Job's `FARCAST_REPO`, `FARCAST_REF` and `FARCAST_MANIFEST` environment;
    - the Kaniko build Job's arguments: `--context=git://<repository>#<commit>`, carrying the exact approved commit, then `--context-sub-path`, `--dockerfile` and `--destination`.

    So the provider keeps which repository and commit every build came from. The git token is a `secretKeyRef` and stays at Metadata level.

    Very likely it also dates every readiness transition, per replica: every seal, every keeper re-seed, and every unseal that brings a sealed replica back to serving. An unseal pushed to a replica that is already serving (the remedy when replicas hold the newest keys without using them yet) changes no readiness, so it is not among them. The `datasphered` data Service is the one Service that gates on readiness: it has no `publishNotReadyAddresses`. So each time a keyholder replica turns Ready or NotReady, the control plane's endpoints controllers update that Service's Endpoints and EndpointSlice in `farcast-system`, moving the replica's address, with its Pod named in `targetRef`, between ready and not ready. The audit policy leaves such updates unlogged only in `kube-system`. An update to the core group's Endpoints is an Admin Activity entry with its full body: a 400-day record of each transition, at the moment it happened, finer than the downsampled metrics below. EndpointSlices are in `discovery.k8s.io`, which is not among the policy's listed groups, so their entries would be at Metadata level, which still carries the time. This is inferred from the documented policy and the deploy code. Verification step 8 checks it.
- **Pod status, if Data Access audit is on.** By the audit policy, the kubelet's `pods/status` updates go to Data Access, which is off unless the project or a parent turned it on. Where it is on, they carry:
  - every keyholder replica's readiness transitions and restarts;
  - the termination messages FarCast reads results from: the fetch report's commit and manifest digest (or, when the manifest is missing, the repository, path and commit) and the build's image digest.

  Verification step 6 checks where they land.
- **Metrics, up to 24 months.** System metrics record per-container CPU, memory and restarts and per-Pod network bytes, by namespace, Pod and container. By the documentation, GKE's default packages record the following for FarCast's namespaces (Verification, step 1, shows it):
  - Pod and container names, each Pod's phase, and each container's readiness and waiting reason;
  - Deployment and StatefulSet replica counts;
  - per-container CPU, memory, network and filesystem use.

  They are sampled every 30 seconds, downsampled as they age, and outlive release. A keyholder replica is ready exactly when it is unsealed. So the readiness series is a record of when each replica was sealed, at 30-second resolution for its first week. It dates every seal, every keeper re-seed, and every unseal that brings a sealed replica back to serving; an unseal onto a replica already serving changes no readiness and shows in none of it.
- **Container logs on the node's disk.** Standard kubelet rotation keeps about 10 MiB × 5 files per container. They are removed with the Pod and destroyed with the node. Autopilot nodes are the provider's. In ADR 0008's terms this is *protected by the provider not looking*, not *hidden*.
- **`kubectl logs` passes through the provider-run API server**, which terminates TLS. Nothing records the read unless Data Access audit is enabled.
- **The cluster's etcd** holds every Pod's status too, readiness and termination messages included. It is already named in DataSphere's section, and the control plane itself in ADR 0004.

What the cluster is configured not to send to the provider's logging is the stdout and stderr of FarCast's own components and of every application. Install reads that configuration back. That Autopilot honours it is unverified until the next walk (Context, *Logging*).

## Consequences

- **Log history ends with the Pod.** A deleted, evicted or rescheduled Pod takes its logs with it, and a busy container keeps only about 50 MiB. Shrike and the cost meter never depended on Cloud Logging, so no FarCast function changes. An operator who wants durable logs has to build them (Revisit triggers).
- **If Autopilot refuses system-only logging, nothing installs** until the operator chooses a fallback (decision 1). Failing closed is meant to work this way.
- **The strict read-back can fail an install whose workload logs are off.** A project with GKE Enterprise may get control-plane logs by default. A logging component newer than the vendored client reads back as unknown. Both are refused (Revisit triggers).
- **Cost.** The kernel's `expected` meter never modelled Cloud Logging ingestion, which is billed above a per-project monthly free allotment. The ingestion this removes was a cost the meter did not see. The ingestion that remains (system logs, Events, audit) is still unmodelled, and so are the metric packages' samples, which are billed per sample ingested. Nothing measures how large either is at FarCast's scale.
- **The audit log is a second etcd, and it outlives release.** The DataSphere README's etcd line says rotation frequency is visible. Through the audit log it stays visible for 400 days after the cluster is gone. By the documentation, the metric packages keep each keyholder replica's readiness, and so its sealing and unsealing, for 24 months. Very likely the audit log keeps each of those transitions too, through the data Service's endpoint updates, for 400 days.
- **A known leak class: plain values in a workload spec.** Anything put as a literal in a Job's or Deployment's `env` or `args` is kept by the provider for 400 days, in the workload's body and in each of its Pods'. Two instances are known:
  - the fetch Job's repository, ref and manifest path;
  - the Kaniko build Job's `--context=git://<repository>#<commit>` and the arguments beside it.

  The follow-up, recorded separately and not done here, must cover both. The fetch values move into a Secret. Kaniko's context has to come from a Secret-backed env or file, not from an argument. Until it lands, the repository URL and the full commit stay in every build Job's body for 400 days. Image names carry the application names and a 12-character commit as well.

## Alternatives considered

- **A Cloud Logging exclusion filter on the instance's cluster.** Rejected. It is project configuration that outlives the instance, and it cannot touch `_Required`. Exclusion filters apply only after the Logging API has received the entries, so the provider still receives them. It remains the weaker fallback if Autopilot refuses decision 1.
- **Deleting the sink, or the `stdout`/`stderr` logs, at release.** Rejected. Those names are project-wide, so deleting them destroys other clusters' logs. The `_Required` bucket cannot be emptied.
- **Converging existing clusters with `UpdateCluster`.** Rejected for now (decision 2).
- **Pinning `MonitoringConfig`.** Deferred to an open decision (decision 3).
- **An opt-in for workload logging.** Not offered. If one is ever added, it is a privacy-lowering flag behind its own confirmation, recorded in the instance metadata and named again by `release`.
- **GKE Standard.** It can turn off more, but at ADR 0003's cost and operational price. It stays the home for a later Standard/Spot hybrid, and it is the other fallback if Autopilot refuses decision 1.

## Verification

Unit tests pin:
- the request: `buildCluster` carries system-only logging and keeps the other isolation settings;
- the fail-closed read-back: `systemLogsOnly` rejects nil, empty, WORKLOADS, extra and unknown components;
- the refusal in `CreateCluster`, for fresh and pre-existing clusters;
- install's record: `cloud_logging: system` only on the provider's word;
- release's report;
- the kinds an application deployment renders.

Live verification is deferred to the next walk. Before it spends anything, confirm that the project has no GKE Enterprise enablement and no fleet registration, because a control-plane default would fail install by design. Also record the project's effective Data Access audit configuration, including what it inherits.

After any application has logged:
1. Read back the cluster's logging and monitoring config. Logging must be SYSTEM_COMPONENTS only. Record monitoring as found. It is expected to list GKE's packages (decision 3), and it is not enforced. Also confirm that a kube state series exists for a `datasphered` replica, for example its container readiness. That shows the 24-month disclosure rather than inferring it.
2. Count `k8s_container` entries for the cluster in `farcast-system` and the application namespaces since install. The count must be 0. It has to be namespace-scoped, because `kube-system` entries legitimately remain. This step, not step 1, is the evidence that Autopilot honours system-only logging.
3. `farcast logs <app>` must still return lines.
4. `farcast-system` and the application namespaces must hold no `PodMonitoring`. Record every `ClusterPodMonitoring`, and any `PodMonitoring` elsewhere, rather than requiring none, because the documentation does not say whether GKE's packages create their own.
5. Confirm that an audit entry naming a FatLine or keyholder ConfigMap carries no request or response body.
6. Look for a `pods/status` entry for a `datasphered` replica and one for a fetch Pod, in Admin Activity and, if it is on, in Data Access. The audit policy sends status updates to Data Access, so with Data Access off, Admin Activity should hold neither. If one is there, record what its body carries and add it to *What the provider still sees*.
7. Confirm that one build Job's create entry carries `--context=git://…#<commit>`, so that the follow-up can show it gone.
8. After a seal and an unseal, look in Admin Activity for an `update` entry on the `datasphered` data Service's Endpoints, and one on its EndpointSlice, in `farcast-system`. Record the level of each and what its body carries, such as the replica's Pod name and address. If neither is there, correct *What the provider still sees* and the DataSphere and Planck READMEs.

## Revisit triggers

- A live run shows GKE echoing more than SYSTEM_COMPONENTS, rejecting the create, or ingesting `k8s_container` entries from FarCast's namespaces while it reads back SYSTEM_COMPONENTS. The fallbacks in decision 1 are then the operator's to choose.
- The project has GKE Enterprise (or, undocumented, fleet registration). GKE may then enable control-plane logs by default, and the strict read-back fails an install whose workload logs are off. That failure is closed and correct until someone decides whether control-plane logs are acceptable.
- GKE reads back a logging component that the vendored client does not know. The client's enum stops at `KCP_HPA`, and the API already has `KCP_VPA`, which would read back as unknown and be refused. That also fails closed. The fix is updating the client, not loosening the check.
- The next walk records the monitoring read-back. Then the operator decides whether to pin the metric packages off (decision 3).
- An operator needs log history beyond a Pod's life. The answer is in-instance retention: encrypted, through DataSphere, under the operator's keys. It is never the provider's logging.
- Autopilot allows system metrics or managed collection to be turned off.
- A second cloud provider (8.1). Its defaults get the same read-back before its first install.

## Sources

- About GKE logs — https://docs.cloud.google.com/kubernetes-engine/docs/concepts/about-logs
- gcloud container clusters create-auto (`--logging`, `--monitoring`) — https://docs.cloud.google.com/sdk/gcloud/reference/container/clusters/create-auto
- GKE API reference, `projects.locations.clusters` (`LoggingComponentConfig`) — https://docs.cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters
- Compare features in Autopilot and Standard clusters — https://docs.cloud.google.com/kubernetes-engine/docs/resources/autopilot-standard-feature-comparison
- Troubleshoot missing logs in GKE — https://docs.cloud.google.com/kubernetes-engine/docs/troubleshooting/logging
- GKE Autopilot overview — https://docs.cloud.google.com/kubernetes-engine/docs/concepts/autopilot-overview
- GKE release notes, new features (2024-02-20: GKE Enterprise defaults) — https://docs.cloud.google.com/kubernetes-engine/docs/release-notes-new-features
- Configure metrics collection (the page formerly titled "Configure logging and monitoring for GKE"; metrics only) — https://docs.cloud.google.com/kubernetes-engine/docs/how-to/configure-metrics
- Collect and view kube state metrics — https://docs.cloud.google.com/kubernetes-engine/docs/how-to/kube-state-metrics
- Collect and view cAdvisor/Kubelet metrics — https://docs.cloud.google.com/kubernetes-engine/docs/how-to/cadvisor-kubelet-metrics
- GKE system metrics — https://docs.cloud.google.com/monitoring/api/metrics_kubernetes
- Get started with managed collection — https://docs.cloud.google.com/stackdriver/docs/managed-prometheus/setup-managed
- Google Cloud Managed Service for Prometheus (retention) — https://docs.cloud.google.com/stackdriver/docs/managed-prometheus
- Cloud Monitoring quotas and limits (data retention) — https://docs.cloud.google.com/monitoring/quotas
- Cloud Monitoring, protecting data at rest (deletion) — https://docs.cloud.google.com/monitoring/compliance/data-at-rest
- GKE audit policy — https://docs.cloud.google.com/kubernetes-engine/docs/concepts/audit-policy
- GKE audit logging information — https://docs.cloud.google.com/kubernetes-engine/docs/how-to/audit-logging
- Enable Data Access audit logs (inheritance) — https://docs.cloud.google.com/logging/docs/audit/configure-data-access
- Route log entries (exclusion filters) — https://docs.cloud.google.com/logging/docs/routing/overview
- Cloud Logging quotas and retention — https://docs.cloud.google.com/logging/quotas
- Node system configuration (kubelet log rotation) — https://docs.cloud.google.com/kubernetes-engine/docs/how-to/node-system-config

---

*This ADR is a living record. Revisit it on any trigger above.*
