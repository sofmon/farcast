# ADR 0003 — Target GKE Autopilot for the First Cloud Provider

**Status:** Accepted

**Date:** 2026-06-02

**Relates to:** Implements the GKE choice in Planck phase 1.2 ([`../../planck/README.md`](../../planck/README.md)). Interacts with [ADR 0002](0002-backend-language-strategy.md): a kernel-level Rust FatLine data plane is gated by this decision to a Standard/hybrid node pool. The control-plane **network-isolation** posture (private control plane via the DNS-based endpoint, no public IP) is decided separately in [ADR 0004](0004-private-control-plane.md).

---

## Context

Phase 1.2 selects GKE as FarCast's first cloud. Within GKE there are two modes:

- **Standard** — you create and manage node pools (VMs); you pay per node regardless of utilization; you control machine types, can use Spot VMs, and can run privileged/host-level workloads.
- **Autopilot** — Google manages the nodes; you pay per running **Pod request**; the platform enforces a hardened admission policy (no privileged pods, no host namespaces, no `NET_ADMIN`), NetworkPolicy is always on, and nodes auto-provision from Pod specs.

For most projects this is an ops-versus-control trade-off. For FarCast it is more, because three defining properties interact with Autopilot's restricted model, and each had to clear before committing:

1. **Cost is a non-negotiable pillar**, and FarCast's baseline is a fixed set of ~7 always-on system components plus a few apps — i.e. many small Pods.
2. **FatLine is the sole egress boundary** (deny-by-default) — historically the kind of thing implemented with kernel-level interception that Autopilot forbids.
3. **TechnoCore deploys and scales apps from inside the cluster** by talking to the Kubernetes control plane, and must stay alive as the last component standing.

### Findings

**1 — Cost at minimum load.** Pricing (us-central1, June 2026): Autopilot general-purpose **$0.0445/vCPU-hr + $0.0049/GiB-hr**; Standard = node VM price (**e2-standard-2 ≈ $48.92/mo**, e2-standard-4 ≈ $97.84/mo); the **$0.10/hr cluster fee is waived** by the free tier for the first zonal/Autopilot cluster. On modern (bursting) Autopilot clusters the per-Pod minimum is **52 MiB / 50m CPU**, billed on actual requests — *not* the 0.5 GiB figure from older docs — so FarCast's many small Pods incur no memory-floor tax. Modeled footprint: **empty ≈ $37/mo, minimum-useful ≈ $45–51/mo** on Autopilot (CPU-dominant), comparable to a single dedicated node (~$49 comfortable, ~$24 fragile). Per unit, Autopilot ≈ 2× the raw VM rate, so a well-packed Standard node wins **above ~70–80% utilization** — but Standard's cheapest lever (**Spot, ~50–70% off**) is unusable for the always-on core (TechnoCore must survive preemption), and every Standard node re-pays ~0.5 vCPU + ~2 GiB of GKE reservation + system-daemonset overhead that Autopilot does not bill. **Net:** at FarCast's baseline, cost is wash-to-favorable for Autopilot; Standard's edge is a high-utilization-plus-Spot optimization, not the install default.

**2 — Egress boundary without privilege.** Autopilot blocks `privileged`, host namespaces, and `NET_ADMIN` (so iptables/kernel transparent interception is out); `NET_RAW` and ordinary capabilities are allowed. FarCast does not need the forbidden path: FatLine is a **userspace L4/L7 proxy** (in/out, TLS/mTLS) — a normal container. The boundary is enforced by **Kubernetes NetworkPolicy**, which on Autopilot (Dataplane V2/eBPF) is **always on and cannot be disabled**. A per-app **default-deny egress** policy allowing only FatLine + DNS means a Pod physically cannot reach the internet except through FatLine — no bypass, cooperative or hostile; a misbehaving app simply gets no internet. Shrike inspects at FatLine as a **sidecar** (no privilege), and Dataplane V2 flow logs are available as managed observability. This is a **stronger** guarantee than Standard, where NetworkPolicy is optional and disable-able — and it matches FarCast's "deny by default is non-negotiable" stance.

**3 — In-cluster control-plane access.** TechnoCore is a standard Kubernetes **controller** (ServiceAccount + RBAC → in-cluster API), the same pattern as Argo CD/Flux/cert-manager — **fully supported on Autopilot**. No GCP CD service (e.g. Cloud Deploy) is needed per change, which would also violate the zero-central-dependency principle. Because Autopilot **auto-provisions compute from Pod requests**, TechnoCore scales by setting replicas/requests via the K8s API and **never manages node pools or calls the GKE API to add capacity** — strictly less code and privilege than Standard. The one boundary: `kube-system` is Google-managed (read-only) and an admission webhook (`warden-validating`) rejects non-compliant workloads — so FarCast operates in its own/app namespaces and emits only compliant specs.

---

## Decision

1. **The GKE adapter provisions Autopilot clusters by default** (regional control plane; Dataplane V2 + NetworkPolicy always on).
2. **FatLine is a userspace L4/L7 proxy.** The deny-by-default egress boundary is enforced by **NetworkPolicy**, not kernel interception. Planck's translator (4.2) generates a per-app default-deny-egress policy allowing only FatLine + DNS.
3. **TechnoCore runs as an in-cluster controller** with a least-privilege ServiceAccount + RBAC, operating in app namespaces, scaling via Pod requests.
4. **Every FarCast-generated workload must be Autopilot-admission-compliant:** resource **requests on every container** (also required for per-Pod billing and TechnoCore's cost attribution), no privileged/`hostNetwork`, allowed capabilities only.
5. **Prefer templating** the SDK/FatLine sidecar into Deployments (Planck) over a mutating admission webhook.
6. **Revisit Standard, or an Autopilot+Standard hybrid** (e.g. a Spot node pool for fault-tolerant batch/heavy apps), as a **Phase 5+** TechnoCore optimization — or if FatLine becomes a kernel/eBPF data plane (ADR 0002's gated Rust option), which needs `NET_ADMIN`/host networking that Autopilot will not grant in-pod and would therefore require a Standard/hybrid node pool.

---

## Consequences

**Positive**

- No node management; the control plane is **regional** (TechnoCore survives a zone failure) at per-Pod price.
- The boundary is enforced at the **platform** level by undisablable NetworkPolicy — the security pillar is structural, not best-effort.
- **Mandatory resource requests** feed both Autopilot scheduling and TechnoCore's per-app cost attribution (Phase 4).
- Scaling is smooth and linear, governed by TechnoCore via Pod requests — exactly the "adapt resources without booting servers" model.

**Negative / constraints**

- Per-unit compute carries a premium (~2× raw VM), so a very large, stable instance may later favor a Standard/hybrid pool with Spot.
- No privileged/host-network workloads in-cluster. This **gates the FatLine Rust-eBPF data-plane option** (ADR 0002) to a Standard/hybrid pool; revisit there if the FatLine benchmark favours a kernel data plane.
- Must operate outside `kube-system`; admission webhooks are constrained (prefer templating).

**Per-module implications**

- **Planck** — provision Autopilot; the translator emits admission-compliant workloads (requests on every container) plus the per-app deny-by-default egress NetworkPolicy.
- **TechnoCore** — in-cluster RBAC controller; scales via Pod requests; templates sidecars; its egress policy must allow the API server + DNS.
- **FatLine** — userspace proxy; boundary via NetworkPolicy, not kernel interception.
- **Shrike** — sidecar inspector; may consume Dataplane V2 flow logs.

---

## Sources

- GKE pricing — https://cloud.google.com/kubernetes-engine/pricing
- Autopilot resource requests / minimums — https://docs.cloud.google.com/kubernetes-engine/docs/concepts/autopilot-resource-requests
- Autopilot security measures — https://docs.cloud.google.com/kubernetes-engine/docs/concepts/autopilot-security
- Network policy (Dataplane V2, always-on) — https://docs.cloud.google.com/kubernetes-engine/docs/how-to/network-policy
- FQDN network policies — https://docs.cloud.google.com/kubernetes-engine/docs/how-to/fqdn-network-policies
- Autopilot overview (auto-provisioning) — https://docs.cloud.google.com/kubernetes-engine/docs/concepts/autopilot-overview
- Service accounts / RBAC in GKE — https://cloud.google.com/kubernetes-engine/docs/how-to/service-accounts

---

*This ADR is a living record. Revisit it after the FatLine benchmark (ADR 0002), when the second cloud provider lands (8.1), or whenever the GKE Autopilot pricing/restriction landscape materially changes.*
