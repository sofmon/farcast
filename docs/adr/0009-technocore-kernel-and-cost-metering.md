# ADR 0009 — TechnoCore: a Stateless Kernel, Two Cost Signals, and What a Cost Shutdown May Not Stop

**Status:** Accepted (2026-08-31)

One decision changed during ratification, and it is the one that mattered most. The draft metered locally and rejected the provider's billing data outright, on the grounds that a figure a day late cannot enforce anything. The ruling is that **both** figures exist with distinct jobs — `expected` enforces, `confirmed` corrects — which is strictly better, because it turns the compiled-in rate card from an assumption nothing would ever check into a model that is measured against the invoice and calibrated by it.

That change introduced decision 5's clamp, which the draft had no need for: calibration is a path from an external, late, least-trusted signal into the enforcement guard, so it is bounded. A `confirmed` feed that lies, breaks or is spoofed can make the estimate wrong; it cannot switch the guard off.

**Date:** 2026-08-31

**Relates to:** Unblocks Phase 4.1, whose deliverables [`technocore/README.md`](../../technocore/README.md) leaves as *"specification to follow"*. Constrained by [ADR 0003](0003-gke-autopilot.md) (Autopilot bills Pod requests; TechnoCore is an in-cluster controller), [ADR 0004](0004-private-control-plane.md) (private control plane; in-cluster access is internal regardless), [ADR 0005](0005-fatline-data-plane-ingress.md) (the load balancer's standing cost) and [ADR 0008](0008-in-cluster-key-delivery.md) (which assigns 4.1 the last-to-die classification and FatLine's PDB). Answers the aside in [ADR 0006](0006-connect-bootstrap-kubectl.md) decision 1 — *"the in-cluster components that do warrant a typed client (TechnoCore, Phase 4.1+)"* — with the opposite conclusion, and says why. Serves pillar 2 of [AGENTS.md](../../AGENTS.md), and corrects one sentence of it.

---

## Context

Pillar 2 says cost control is mandatory, not optional. Four phases have now shipped while that pillar was enforced by a number in a YAML file and a confirmation prompt. 4.1 is where it becomes machinery, and the machinery raises three questions that are not implementation details.

**What does the kernel know, and where does it keep it?** A kernel that holds a database inherits that database's failure modes. If the registry lives in DataSphere, then a restart-sealed instance has no kernel — precisely inverted, because the kernel is what must stay alive to report *why* the instance is sealed and what it costs while sealed.

**How does it talk to the API server?** ADR 0006 kept `client-go` out of the credential-holding CLI and explicitly reserved a typed client for in-cluster components. But the repository is one Go module with one vendored tree, and that tree — 31 modules — is audited as a security property, not a packaging statistic. `client-go` roughly triples it. The CLI binary would not *link* it; the operator's supply chain would still *contain* it.

**Where does the cost number come from?** This is the sharp one, and the answer is not one number. The provider's billing data is authoritative and arrives about a day late; a locally computed figure is immediate and is a model. Choosing either alone is a mistake in a different direction — enforce on the invoice and a threshold fires a day after the money is gone; enforce on the model and nothing ever checks whether the model is right. So the instance carries **two** figures with different jobs, and the design question becomes how they relate rather than which one wins.

### The decision space

**State.**
- **S1 — a database (PVC, or the instance's own DataSphere).** A PVC is node disk; DataSphere couples the kernel to the seal state and creates the inversion above. Rejected.
- **S2 — the cluster is the registry.** Declared intent lives as labels and annotations on the Kubernetes objects TechnoCore manages; observed state is read live and never cached across reconciles. **Chosen**, with one exception forced by arithmetic (decision 2).

**Kubernetes access.**
- **T1 — vendor `client-go` into the root module.** Typed, informers, the standard path. Takes the audited tree from 31 modules to roughly 80, against a repository whose CLI holds cloud admin credentials out of the same tree. Rejected.
- **T2 — a hand-rolled, standard-library client.** In-cluster access is HTTPS and JSON against `kubernetes.default.svc`, with a projected token and CA at well-known paths. 4.1 needs five verbs over three kinds. Precedent is direct: DataSphere hand-rolled the GCS resumable upload rather than vendor the storage SDK, and both `fatline/deploy` and `datasphere/deploy` render plain YAML rather than construct typed objects. **Chosen.**
- **T3 — make `technocore/` its own Go module, and vendor `client-go` there.** The `sdk/go/` precedent, and it does isolate the tree. Rejected for 4.1 as premature — it splits the build for a verb set that does not need it — but it is the named escape hatch if 5.2's adaptive scaling turns out to want real informer machinery.

**Cost signal.**
- **C1 — the provider's billing data alone.** Authoritative, and it settles over roughly a day. As the *only* signal it cannot enforce anything: a limit breached at 09:00 is reported the following morning, by which time protective shutdown is an obituary. Rejected as the sole signal; **adopted as the confirming one.**
- **C2 — Cloud Monitoring for container usage, priced locally.** Measures the wrong quantity — Autopilot bills *requests*, not usage. Rejected here, and exactly right for 5.1, where the gap between request and usage is the whole signal adaptivity runs on.
- **C3 — meter locally from Pod requests against a pinned regional price table alone.** Under Autopilot the billed compute quantity *is* the sum of Pod requests over time — the number TechnoCore already reads and, from 4.2, itself sets. Real-time and exactly attributable per application. As the *only* signal it is a model nothing ever checks, and a rate card that silently goes stale takes the whole cost pillar with it. Rejected as the sole signal; **adopted as the enforcing one.**
- **C5 — both, with distinct jobs: `expected` enforces, `confirmed` corrects.** The local meter runs continuously and is what protective action fires on; the provider's figure lands for closed windows and calibrates the meter that produced them. Neither is asked to do the other's job. **Chosen.**

Choosing C5 puts the billing credential back on the table, so the *channel* carrying `confirmed` is its own question — and it has answers that do not require billing-account access from inside the cluster:

- **B1 — the operator's machine pulls it and pushes it in.** The CLI already holds the operator's cloud credentials; TechnoCore holds none. **Chosen for 4.1**, because it makes `confirmed` work with no new grant at all. Its honest cost: `confirmed` lands when the operator's machine runs, so a daily cadence is a scheduled local job rather than a property of the instance.
- **B2 — a Cloud Billing budget, scoped to the instance's project, notifying over Pub/Sub.** Automatic, and the in-cluster grant is subscribe-on-one-topic — no billing read whatsoever. The natural upgrade once the two-signal machinery exists, and named here so B1 is understood as a starting channel rather than the design.
- **B3 — BigQuery billing export read in-cluster through an authorized view filtered to this project.** Per-SKU detail, but the export dataset is billing-account-wide and the narrowing lives entirely in getting one view definition right. Not for a first implementation.
- **B4 — the Cloud Billing API called directly from the cluster.** Needs billing-account read, which spans every project the operator owns. **Rejected** — this is the option that would buy pillar 2 with pillar 1.

---

## Decision

**1. TechnoCore is a stateless reconciler, and the cluster is its registry.** Declared intent is labels and annotations on the workloads themselves; observed state is read fresh each reconcile. There is no cache to go stale, no database to restore, and no dependency on DataSphere — so a sealed instance still has a kernel, which is the whole point of having one.

**2. The single exception is the cost ledger, and it lives in a ConfigMap.** Accrued spend must survive a TechnoCore restart or the meter resets to zero and the limit never trips. That ledger is cloud-resident state, which [ADR 0008](0008-in-cluster-key-delivery.md) is otherwise severe about — and it is disclosive of nothing, because *the provider computed every number in it before TechnoCore did*. This is the FatLine-server-leaf distinction, not the keyring one: the test is whether cloud-resident state tells the cloud something it does not already have.

**3. TechnoCore reaches the API server through a hand-rolled, standard-library client (T2).** Scoped deliberately small: list Pods and Deployments in FarCast namespaces, read container requests and Pod conditions, and patch the `scale` subresource. It **polls on a reconcile interval rather than watching** — for a kernel, a loop that cannot silently stop reconciling is worth more than freshness measured in seconds, and none of 4.1's decisions turn on sub-minute latency.

**4. The instance carries two cost figures — `expected` and `confirmed` — and they have different jobs (C5).**

*`expected`* is metered locally and continuously: each application's Pods' requests integrated over their lifetimes at pinned regional Autopilot rates, plus instance overhead (the cluster's own managed workloads, the load balancer, registry storage) attributed to the instance and never smeared across applications. It is available immediately, needs no credential, and is what every warning and every protective action fires on.

*`confirmed`* is the provider's own figure for a window that has closed. It arrives late by construction, carries the date of the window it covers, and **never drives an action** — its job is to correct `expected`, both by replacing it outright for windows it covers and by calibrating the model that will produce the next one.

Accrued spend for a period is therefore `confirmed` for every closed window plus `expected` for the open one. The two are never added into one undifferentiated total, and never presented as one: a report that cannot say which part was measured and which was modelled is worse than either figure alone.

**No billing credential enters the cluster.** `confirmed` reaches TechnoCore over channel B1 — the operator's machine, which already holds the credential, pulls the figure and pushes it in. B2 is the automatic successor; B4 stays rejected.

**5. `confirmed` calibrates `expected`, within a clamp, and its absence is never read as zero.** Comparing the two over the same closed window yields a drift ratio, which is applied to the live estimate — so a rate card that goes stale is *detected and corrected* rather than quietly wrong, which is the failure C3 alone could not have caught.

Two guards, because this is the seam where an external input reaches the enforcement path:

- **The calibration is clamped.** A `confirmed` feed reporting far too little would otherwise drive the ratio toward zero and neuter the guard — turning the late, external, least-trusted signal into a way to switch off protection. The ratio is bounded, a correction beyond the bound is refused and surfaced as a discrepancy for the operator rather than applied, and enforcement continues on the un-calibrated model meanwhile. `expected` enforces precisely so that a `confirmed` channel that lies, breaks or is spoofed can make the estimate wrong but cannot disable the limit.
- **"No confirmation yet" is a distinct state from "confirmed zero".** A missing feed must never read as a period that cost nothing. An instance whose `confirmed` has not arrived is an instance running on `expected` alone, and says so.

**And every cost report states what the meter cannot see** — network egress bytes (until FatLine counts them), storage operations, how stale `confirmed` is, and any drift the clamp refused. A modelled number presented as an invoice is the cost-pillar equivalent of saying "blind" when you mean "blind to content", and this project has already decided which of those two failures is worse.

**6. Workloads carry `farcast.sofmon.com/tier`, one of `kernel`, `system`, `app`.** A cost shutdown scales down `app` workloads only, most expensive first. `system` — `datasphered`, FatLine, Shrike — is never scaled by a cost shutdown. `kernel` never stops itself.

**7. A cost shutdown may not stop `datasphered` or FatLine, and the reason is arithmetic, not sentiment.** At ADR 0003's rates a 100m/128Mi Pod is about $3.70/month, so the entire system tier — two `datasphered` replicas and two FatLine — is about $15/month against a connected instance's floor of roughly $73. Stopping it saves perhaps a fifth of the bill and makes the instance unsealable and unrecoverable *while it keeps billing the rest* — [ADR 0008](0008-in-cluster-key-delivery.md)'s finding, restated as a rule the code enforces.

**8. When every application is stopped and spend is still over the limit, TechnoCore has hit the instance floor. It reports; it does not act.** The levers that remain are releasing the load-balancer carrier (about $18/month, [ADR 0005](0005-fatline-data-plane-ingress.md)) and `farcast release`. Both destroy operator-visible capability or data. A kernel that quietly took either would be a worse failure than the overspend.

**9. Warn on projection, act on accrual.** Thresholds at 50/75/90% fire against accrued spend in the period; a separate warning fires as soon as the burn rate implies the limit will be reached before the period ends — which is the signal that arrives early enough to matter. Protective shutdown fires only on accrued spend reaching the limit: the instance is never stopped on a forecast.

**10. The model is unverified today, and the first `confirmed` window is what verifies it.** ADR 0008's `~$4/month` for the second replica has never been checked against a bill; neither has ADR 0003's `$37/month` empty cluster. Both are modelled figures now load-bearing for an enforcement mechanism. Decision 5 turns that from a one-off reconciliation into a standing property — but the first measurement still has to happen, and 4.1 is not complete until an instance has lived across a billing boundary and the drift between `expected` and `confirmed` has been read and recorded.

**11. FatLine gets the PodDisruptionBudget and second replica `datasphered` already has,** at the same marginal ~$4/month and for the same reason: every unseal and every future keeper reseed rides that tunnel, so a single drained replica is the floor on recovery time.

---

## Consequences

**One sentence of AGENTS.md is wrong and this ADR corrects it.** It reads *"stop high-cost apps first, then the entire instance if needed, keeping only TechnoCore alive"*. Decisions 6–8 say the entire *application set*, never the system tier — the residual floor is an operator decision, not a kernel one. The correction lands with this ADR.

**A `$50/month` limit is below the floor of a connected instance with storage.** Model: about $37 empty ([ADR 0003](0003-gke-autopilot.md)), about $18 for the carrier ([ADR 0005](0005-fatline-data-plane-ingress.md)), about $18 for the system tier and the kernel itself, once FatLine has its second replica — roughly $73 in total. So TechnoCore's first honest act on the runbook's own test instance is to report that the limit cannot be met before a single application runs. This is a real finding, not a bug: 4.1 must check the floor against the limit at deploy time rather than discover it at 90%, and `farcast install`'s prompt should say what the floor is instead of accepting any number.

**Two FatLine replicas split Shrike's view.** Shrike runs in-process or as a per-Pod sidecar, so each replica's policy engine sees half the connections; de-duplication and severity ranking become per-replica. Nothing in 4.1 depends on it, and 4.4 — per-application enforcement — is where it has to be faced.

**`confirmed` at 4.1 is only as regular as the operator's machine.** Channel B1 buys the two-signal model with no new cloud grant, and the price is that a daily correction means a daily local run. An instance whose operator is away drifts on `expected` alone — correctly, and visibly, since decision 5 makes "no confirmation yet" a state the reports name. B2 is what removes the dependency, and it belongs after the machinery it would feed exists.

**A TechnoCore restart leaves an unmetered gap.** The ledger checkpoints on an interval; spend between the last checkpoint and the restart is reconstructed by assuming the observed workload set ran for the whole gap. That over-counts a Pod that died during it and under-counts one that was deleted before TechnoCore came back. The approximation is stated in the report rather than hidden.

**Hand-rolling the client means owning what `client-go` would have given.** Projected-token rotation (the token file is re-read, never cached for the process lifetime), API errors as status objects rather than transport failures, and merge-patch semantics on the scale subresource. Each is small; together they are the thing to test hardest, because a kernel that silently fails to reconcile looks exactly like a kernel with nothing to do.

---

## Phasing

- **4.1** — everything above: the registry, lifecycle, health, the meter, thresholds, protective shutdown, the tier classification, FatLine's PDB and second replica, and the invoice reconciliation of decision 10.
- **4.2** — Planck stamps `farcast.sofmon.com/tier: app` on every workload it renders; TechnoCore's registry gains a declared side to compare observed state against.
- **4.3** — `farcast costs` surfaces both figures side by side — `expected` live, `confirmed` through its window, the drift between them, and the blind spots of each — and is the operator-side command that pulls `confirmed` and pushes it in (channel B1).
- **5.1** — Cloud Monitoring joins as a *usage* source (C2), alongside the request-based meter rather than replacing it; and `confirmed` moves to channel B2, so the correction arrives without the operator's machine being awake.
- **5.2** — adaptive scaling writes requests, which makes the meter's input a variable TechnoCore controls. If informer machinery becomes genuinely necessary there, T3 is the move, not T1.

## Revisit triggers

1. **Drift between `expected` and `confirmed` persistently exceeds the clamp.** Decision 5 corrects a model that is merely stale. A divergence the clamp keeps refusing means the model is wrong in kind rather than in calibration — a billed quantity the meter does not know about — and that is a new mechanism, not a new constant.
2. **A second cloud provider.** The meter's shape assumes Autopilot's request-based billing. A provider that bills nodes rather than Pods makes per-application attribution genuinely hard, and that is a new ADR rather than a parameter.
3. **The hand-rolled client outgrows its verb set.** Watch semantics, server-side apply, or CRDs would each be a signal to take T3 rather than to keep extending T2.

---

## Sources

Written from the repository's own record rather than a design panel: [ADR 0003](0003-gke-autopilot.md)'s rate card and empty-cluster model, [ADR 0005](0005-fatline-data-plane-ingress.md)'s carrier cost, [ADR 0006](0006-connect-bootstrap-kubectl.md)'s minimal-dependency reasoning (whose in-cluster aside this ADR reverses), [ADR 0008](0008-in-cluster-key-delivery.md)'s recovery-floor finding and its cloud-resident-state test, and [`fatline/README.md`](../../fatline/README.md)'s open item on the single-replica tunnel. The `$50`-below-floor consequence falls out of composing the first two, and had not been noticed before.
