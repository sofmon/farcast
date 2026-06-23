# ADR 0006 — Connect-Time FatLine Bootstrap via kubectl, Not a Vendored Kubernetes Client

**Status:** Accepted

**Date:** 2026-06-23

**Relates to:** Implements the `farcast connect` bootstrap that [ADR 0005](0005-fatline-data-plane-ingress.md) assigned to Phase 2.3 — *"bootstrap FatLine into the instance (deploy + mint/inject mTLS material)."* Extends the CLI's minimal-dependency stance ([`../../farsight/cli/README.md`](../../farsight/cli/README.md) design principle 1, decision 6) and the GKE control-plane access model of [ADR 0004](0004-private-control-plane.md). Serves the two pillars of [AGENTS.md](../../AGENTS.md).

---

## Context

`farcast connect` (Phase 2.3) must, on first connect, create Kubernetes objects inside the instance — a Namespace, an mTLS Secret, a Deployment, and a `Service{type: LoadBalancer}` for FatLine — then watch the rollout and read back the load balancer's external IP. That requires talking to the cluster's API server.

The obvious tool is `k8s.io/client-go`. But the FarCast CLI holds the operator's **cloud admin credentials**, and has therefore made minimal dependencies a *security* decision, not a packaging preference: the scaffold is standard-library-only (plus the already-vendored YAML library), and its install-time health check deliberately avoids "a vendored Kubernetes client or a raw public-IP dial" ([CLI README](../../farsight/cli/README.md) decision 6). `client-go` is one of the largest dependency trees in the Go ecosystem (hundreds of transitive modules) — exactly the supply-chain surface that stance exists to avoid.

Two facts make a subprocess approach natural rather than a compromise:

1. **The CLI is already not hermetic.** The kubeconfig Planck generates ([ADR 0004](0004-private-control-plane.md)) authenticates to the private control plane through a `gke-gcloud-auth-plugin` **exec credential** — an external binary the operator must already have installed (alongside `gcloud`). The CLI thus already depends on external Google tooling at runtime; it simply does not depend on it at *compile* time.
2. **The bootstrap is a one-off, not the general translator.** Turning a `./farcast` manifest into per-app workloads is Planck's job at Phase 4.2. Connect needs to apply exactly one, FatLine-authored workload. A general-purpose typed client buys little for a fixed, hand-rendered manifest.

### The decision space

- **K1 — vendor `client-go`.** Typed, well-supported, the standard path. But it contradicts CLI decision 6 head-on, multiplies the supply-chain surface against stored cloud credentials, and is overkill for one fixed workload. The in-cluster components that *do* warrant a typed client (TechnoCore, Phase 4.1+) run **inside** the instance, not in the credential-holding CLI.
- **K2 — kubectl subprocess.** Shell `kubectl apply -f -` (manifest on stdin), `kubectl rollout status`, and `kubectl get -o jsonpath` over the stored kubeconfig. Zero new Go dependencies. Adds a *runtime* requirement (`kubectl`), but on the same external-tooling line the kubeconfig already draws via `gke-gcloud-auth-plugin`.
- **K3 — hand-rolled REST against the API server.** No new Go deps, but re-implements apply semantics, auth-plugin token exec, and (for the deferred control-plane carrier) SPDY/WebSocket port-forward — a large, error-prone surface to own for marginal benefit over K2.

---

## Decision

1. **`farcast connect` deploys FatLine by shelling to `kubectl` (K2), not by vendoring a Kubernetes client.** The CLI renders FatLine's workload as YAML ([`fatline/deploy`](../../fatline/README.md)) and pipes it to `kubectl apply -f -` over the per-instance kubeconfig; it awaits the rollout and reads the Service external IP the same way. This adds an external-tool runtime dependency (`kubectl`, plus the `gke-gcloud-auth-plugin` the kubeconfig already needs) and **no new Go dependency** — keeping the credential-holding binary's supply-chain surface minimal.

2. **The kubectl invocation sits behind an injectable `Runner` seam.** The `farsight/cli/internal/cluster` wrapper exposes apply / rollout / external-IP over a `Runner` interface, so the connect orchestration is unit-tested with a fake and the real cloud path is integration-gated (never in CI — the cost pillar, as for [Planck](../../planck/README.md)).

3. **Secrets cross the boundary via stdin, never argv or temp files.** The mTLS Secret (CA certificate + server leaf+key — never the CA private key) is base64-embedded in the manifest applied on `kubectl` **stdin**. No key material appears on a command line or in a world-readable temp file.

4. **This is the connect-time bootstrap only; it does not pre-empt Phase 4.2.** Planck's general manifest→workload translator (4.2) remains the home for app deployment and may adopt a typed in-cluster client *there* if warranted — that code runs server-side, not in the operator CLI. If a future need makes a typed client unavoidable in the CLI, this ADR is the thing to revisit.

---

## Consequences

**Positive**

- The credential-holding CLI gains **no new Go dependency** for the bootstrap — the security-first minimal-deps posture (CLI decision 6, AGENTS principle 1) holds.
- Consistent with the existing model: the kubeconfig already drives the control plane through an external auth-plugin exec; `kubectl` is the same kind of dependency.
- The `Runner` seam keeps the orchestration fully unit-testable without a cluster, and the real path integration-gated for the cost pillar.

**Negative / constraints**

- **`kubectl` becomes a runtime prerequisite** of `farcast connect` (the CLI errors clearly if it is absent). Acceptable: `gke-gcloud-auth-plugin` is already required, and operators of a GKE instance have kubectl.
- Parsing `kubectl` output (e.g. the jsonpath external IP) is stringly-typed and version-sensitive, versus a typed client — mitigated by using narrow, stable queries and the injectable seam.
- A second, server-side deployment path may later exist (Planck 4.2) using a different mechanism; this is acceptable because the two run in different trust domains (operator laptop vs. in-cluster controller).

**Per-module implications**

- **FarSight CLI** — owns `internal/cluster` (the kubectl wrapper) and the `connect` orchestration; stays Go-stdlib + YAML only.
- **FatLine** — owns `fatline/deploy` (renders its own workload YAML) and `fatline/identity` (operator-side mint), neither of which depends on a Kubernetes client.
- **Planck** — unchanged by 2.3; remains the home of the general translator (4.2), free to choose its own in-cluster mechanism server-side.

---

## Sources

- gke-gcloud-auth-plugin (exec credential for GKE) — https://cloud.google.com/kubernetes-engine/docs/how-to/cluster-access-for-kubectl
- kubectl apply / server-side semantics — https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands#apply
- client-go (dependency surface) — https://github.com/kubernetes/client-go

---

*This ADR is a living record. Revisit it if a typed Kubernetes client becomes unavoidable in the operator CLI, when Planck's translator (4.2) chooses its in-cluster mechanism, or when the control-plane port-forward carrier (ADR 0005's fallback) is bound and needs streaming.*
