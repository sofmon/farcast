# ADR 0004 — Private GKE Control Plane via the DNS-Based Endpoint

**Status:** Accepted

**Date:** 2026-06-04

**Relates to:** Refines the GKE provisioning posture from [ADR 0003](0003-gke-autopilot.md) (Autopilot) and serves the security pillar of [ADR 0002](0002-backend-language-strategy.md). Implemented by Planck ([`../../planck/README.md`](../../planck/README.md)) and consumed by `farcast install` ([`../../farsight/cli/README.md`](../../farsight/cli/README.md), phase 1.3).

---

## Context

GKE clusters can expose their Kubernetes control plane (the API server) to the internet or keep it private. The classic framing is a binary "public vs private cluster," and the question for FarCast was: since **TechnoCore lives inside the cluster** and talks to the control plane, does a private cluster make sense, and does it fit *security by default*?

The framing turned out to be outdated. GKE has decoupled control-plane access into **three independent, post-creation-mutable knobs**, and one of them — the **DNS-based endpoint** (GA November 2024) — dissolves the usual private-vs-reachable tension.

Two distinctions are essential and were previously conflated:

- **Provisioning ≠ control-plane access.** Planck's `CreateCluster`/`GetCluster`/`DeleteCluster` go to the GKE **management API** (`container.googleapis.com`), which is reachable regardless of how the cluster's *control-plane endpoint* is configured. Endpoint configuration only affects `kubectl`/`client-go`-style access to the API server.
- **In-cluster access ≠ external access.** A workload running *inside* the cluster (TechnoCore) reaches the API server over **internal IPs only**, no matter the endpoint configuration. The thing that needs *external* control-plane access is the **operator CLI** (`farcast install`'s health check now; `farcast run` / the translator later).

So TechnoCore does **not** drive this decision: it works on any configuration. The decision is about how the *operator* reaches the control plane while minimising internet-facing attack surface.

### The three knobs (GKE control-plane access)

1. **DNS-based endpoint** — a per-cluster FQDN (`uid.<region>.gke.goog`) that resolves to a Google-managed frontend, reachable from any network that can reach Google APIs (VPC, on-prem, **or an operator's laptop**), authorised by **IAM** (`container.clusters.connect`) and optionally fenced by VPC Service Controls. No bastion, proxy, or VPN.
2. **IP endpoints** — an external (public) IP endpoint and/or an internal (VPC) IP endpoint, each independently toggleable, optionally restricted by authorized networks (CIDR allowlist).
3. **Private nodes** — whether nodes get external IPs. Independent of the above; governs *node egress*, not control-plane access.

All three are mutable after creation (`gcloud … clusters update`, or `ClusterUpdate.Desired*` on the API) — the public/private choice is **no longer immutable**.

### Findings

**1 — In-cluster access is always internal.** Per GKE, *"the control plane communicates with all nodes through internal IP addresses only,"* regardless of endpoint configuration. TechnoCore (a ServiceAccount + RBAC controller) reaches the API server via the internal path on any configuration, so a private control plane imposes nothing on it. This retires the assumption behind a "start public until TechnoCore exists" plan.

**2 — The DNS-based endpoint gives private *and* reachable.** It is GA, available on every cluster, IAM-authenticated, and reachable from anywhere with Google-API connectivity. Google states it achieves *"the same level of security as a private cluster that can only be accessed from a VPC network,"* while *eliminating bastion hosts and proxies*. This is the key enabler: FarCast can run a control plane with **no public IP** yet keep its zero-bastion, run-from-anywhere operator CLI.

**3 — Configuration is reversible.** Endpoint access can change *"at any time without having to re-create the cluster,"* so the secure default is not a one-way door — a constrained environment can fall back to an authorized-networks public IP without rebuilding.

**4 — The SDK already supports it.** The vendored `cloud.google.com/go/container` (v1.52.0) carries `Cluster.ControlPlaneEndpointsConfig` with `DnsEndpointConfig{AllowExternalTraffic}` and `IpEndpointsConfig{Enabled, EnablePublicEndpoint}` — so Planck can set this posture at create time today; no new dependency.

**5 — Private *nodes* are a separate, later win.** Private nodes (no external IPs) dovetail with FatLine's deny-by-default egress (ADR 0002): a node with no public IP cannot reach the internet except through an explicit path. But that path then needs **Cloud NAT** (small hourly + per-GiB cost — touches the cost pillar) *or* a FatLine-only egress design. That is the FatLine egress question, not the control-plane question, so it is deferred.

---

## Decision

1. **Planck provisions every cluster with a private control plane by default**, via `ControlPlaneEndpointsConfig`:
   - external (public) IP endpoint **off** (`IpEndpointsConfig.EnablePublicEndpoint = false`),
   - internal (VPC) IP endpoint **on** (`IpEndpointsConfig.Enabled = true`) — robust in-cluster and VPC access,
   - **master authorized networks on with an empty CIDR list** (`IpEndpointsConfig.AuthorizedNetworksConfig.Enabled = true`, no `CidrBlocks`) — GKE **rejects** a disabled public endpoint unless authorized networks is enabled (`enable_master_authorized_networks should be enabled if private endpoint is enabled`); the empty allowlist locks the IP endpoint to the cluster's own VPC/node ranges (which stay always-allowed) and does **not** gate the DNS endpoint,
   - DNS-based endpoint **on** for external operator access (`DnsEndpointConfig.AllowExternalTraffic = true`).

   This is a FarCast **invariant**, in the same spirit as "Autopilot always on" — with an escape hatch (see 5) rather than a per-install knob. Authorized networks gate only the IP endpoints; the operator's DNS path stays open via IAM (`container.clusters.connect`) and `AllowExternalTraffic`, and the cluster-level `Cluster.MasterAuthorizedNetworksConfig` is left unset (the SDK forbids setting both it and the nested config).

2. **Operator/CLI access is via the DNS endpoint + IAM** (`container.clusters.connect`). The kubeconfig Planck returns uses the **DNS FQDN** (`server: https://uid.<region>.gke.goog`), not a public IP, with the `gke-gcloud-auth-plugin` exec credential.

3. **In-cluster components (TechnoCore) use the internal endpoint** — unchanged, no special handling.

4. **`farcast install`'s health check does not assume a public IP.** It confirms liveness via the GKE **management API** (`ClusterStatus == RUNNING`, configuration-independent) and/or an IAM-authenticated reach of the DNS endpoint — never a raw public-IP TLS dial.

5. **The posture is relaxable, not rebuilt.** Because endpoint access is mutable, an environment that cannot reach the DNS endpoint can fall back to an authorized-networks-restricted public IP without recreating the cluster. Planck keeps the secure default; the override is deliberate and out of the common path.

6. **Private nodes + controlled egress are deferred to the FatLine phase.** Revisit node privacy (no external IPs) together with the Cloud NAT vs. FatLine-only egress trade-off when FatLine lands; it is independent of this control-plane decision.

---

## Consequences

**Positive**

- **No internet-facing attack surface on the control plane** — the API server has no public IP; access is identity-based (IAM), instantly revocable, audit-logged, and VPC-SC-fenceable. The security pillar becomes structural, not best-effort.
- **Operator UX is preserved** — `farcast install`/`release`/`run` work from a laptop anywhere, with no bastion, proxy, or VPN, using credentials the operator already holds.
- **TechnoCore is unaffected** — in-cluster access is internal regardless; no extra wiring.
- **No new dependency and no recreation risk** — the vendored SDK supports it, and the choice is reversible.

**Negative / constraints**

- Operators need the `container.clusters.connect` IAM permission and connectivity to Google APIs (true for anyone who can run `farcast install`).
- The returned kubeconfig is DNS-based and relies on the `gke-gcloud-auth-plugin` exec credential + an IAM token, not a static client cert — slightly more moving parts than a public-IP kubeconfig.
- This governs only the control plane; **node egress is not yet locked down** (private nodes are deferred), so the full "no Pod reaches the internet except via FatLine" guarantee still depends on the NetworkPolicy boundary (ADR 0003) until the FatLine egress phase.

**Per-module implications**

- **Planck** — set `ControlPlaneEndpointsConfig` at create (public off / internal on / DNS on); build the kubeconfig from the **DNS endpoint**; surface the DNS FQDN as `Cluster.Endpoint`.
- **FarSight CLI (`farcast install`, 1.3)** — health-check via management-API status / DNS-endpoint, not a public-IP dial; show the DNS endpoint in results.
- **TechnoCore** — no change; in-cluster controller over the internal endpoint.
- **FatLine** — owns the deferred private-node / egress decision (Cloud NAT vs. proxy-only).

---

## Sources

- New DNS-based endpoint for the GKE control plane (GA) — https://cloud.google.com/blog/products/containers-kubernetes/new-dns-based-endpoint-for-the-gke-control-plane
- About network isolation in GKE — https://docs.cloud.google.com/kubernetes-engine/docs/concepts/network-isolation
- Customize your network isolation in GKE (how-to) — https://docs.cloud.google.com/kubernetes-engine/docs/how-to/private-clusters
- Simplifying GKE cluster and control-plane networking — https://cloud.google.com/blog/products/containers-kubernetes/simplifying-gke-cluster-and-control-plane-networking/
- Control plane security — https://docs.cloud.google.com/kubernetes-engine/docs/concepts/control-plane-security

---

*This ADR is a living record. Revisit it when private nodes / FatLine egress land, when the second cloud provider arrives (8.1), or whenever GKE's control-plane access model materially changes.*
