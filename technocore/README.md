# TechnoCore

> Kernel — orchestration, instance lifecycle, adaptive resource management.

> **GKE Autopilot constraints ([ADR 0003](../docs/adr/0003-gke-autopilot.md)):** TechnoCore runs as an **in-cluster Kubernetes controller** (least-privilege ServiceAccount + RBAC) operating in app namespaces — never `kube-system`. It scales apps by adjusting Pod replicas/requests (Autopilot provisions compute automatically — no node-pool management, no GKE-API calls to add capacity), and every workload it deploys must be Autopilot-admission-compliant (resource **requests on every container**, no privileged/host-network). Prefer templating the SDK/FatLine sidecar into Deployments over a mutating admission webhook.

*Specification and implementation details to follow.*
