# FatLine

> Networking layer — routing, proxy, encryption, all traffic in/out.

> **GKE Autopilot constraint ([ADR 0003](../docs/adr/0003-gke-autopilot.md)):** FatLine runs as a **userspace** L4/L7 proxy (a normal container — no privileged or host-network access). The deny-by-default egress boundary is enforced by always-on Kubernetes NetworkPolicy, not kernel interception. A future kernel/eBPF data plane (the Rust option in [ADR 0002](../docs/adr/0002-backend-language-strategy.md)) would require a GKE Standard/hybrid node pool.

*Specification and implementation details to follow.*
