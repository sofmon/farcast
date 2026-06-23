# ADR 0005 — FatLine Data-Plane Ingress: an mTLS-Gated Point of Presence, Built Deferred-Hybrid

**Status:** Accepted. The Phase 2.1 artifact shipped deferred-hybrid (the four locked invariants); at **Phase 2.3 the carrier was ratified** — `farcast connect` binds the public mTLS-gated L4 NLB by default and surfaces its standing ~$18/mo against the cost limit (see the 2026-06-23 ratification note below). The CA-key-stays-local mint and the kubectl-not-client-go bootstrap mechanism are recorded in [ADR 0006](0006-connect-bootstrap-kubectl.md).

**Date:** 2026-06-23

**Relates to:** Decides the question [ADR 0004](0004-private-control-plane.md) explicitly deferred "to the FatLine phase" — how the *operator's client* reaches the instance over the **data plane**, as opposed to the control plane. Implemented by FatLine ([`../../fatline/README.md`](../../fatline/README.md), phase 2.1) and consumed by `farcast connect` ([`../../farsight/cli/README.md`](../../farsight/cli/README.md), phase 2.3). Lives within [ADR 0003](0003-gke-autopilot.md) (userspace proxy on Autopilot) and serves the two pillars of [AGENTS.md](../../AGENTS.md).

---

## Context

FatLine is the sole networking layer of a FarCast instance: the operator (CLI now, the FarSight GUI in Phase 7) reaches the instance *inbound*, and applications reach the internet *outbound*, both through FatLine. The root README states the goal plainly — *"the user's point of presence on the internet is the FarCast instance, not their local machine."* That requires the instance to have a reachable inbound entry point.

[ADR 0004](0004-private-control-plane.md) made the **control plane** private (no public IP; an IAM-gated DNS endpoint) and was careful to draw a line: *"In-cluster access ≠ external access… the thing that needs external control-plane access is the operator CLI."* It then deferred the analogous **data-plane** question — the FatLine point of presence, and the private-node / Cloud-NAT-vs-proxy egress trade-off — to the FatLine phase. This ADR takes it up.

Two distinctions matter, and conflating them is the classic error:

- **Control plane ≠ data plane.** The control plane is the Kubernetes API server (`kubectl`/`client-go`), reached over Google IAM. FatLine is the *data plane*: it carries operator/GUI and application traffic, authenticated by FarCast's **own** per-instance CA, not Google IAM. A private control plane (ADR 0004) says nothing about how the data plane is exposed.
- **The artifact ≠ its reachability.** PLAN 2.1 scopes the FatLine *artifact* (the mTLS tunnel, the deny-by-default proxy, the allowlist, the lifecycle). The *operator reaching it* is the `farcast connect` deliverable, which PLAN puts at **2.3**. And there are no applications until **Phase 4**. So in 2.1 there is nothing on either side of an external ingress that can use it yet.

### The decision space (three approaches)

How the operator's client reaches FatLine:

1. **Public mTLS LoadBalancer (A1).** One public entry point — a Kubernetes `Service{type: LoadBalancer}` (a GCP L4 *passthrough* NLB) fronting the FatLine Pod, with FatLine terminating mutual TLS in userspace. The public IP exists, but the TLS layer is the door: only a peer holding a cert signed by the per-instance CA completes the handshake; everyone else is dropped at `ClientHello`/cert-verify before any logic runs. This is the literal "point of presence on the internet" model and the path Phase 7 GUI traffic must take. L4 passthrough means Google forwards raw TCP and never terminates TLS — the cloud carries ciphertext (and SNI) only. Cost: a standing forwarding rule, **~$18/mo** — a real 30–50% bump on the ~$37–51/mo Autopilot baseline ([ADR 0003](0003-gke-autopilot.md)).
2. **Tunnel via the private control plane (A2).** No public data-plane IP: the operator reaches FatLine by tunneling *through* the already-IAM-gated GKE control-plane DNS endpoint (a `kubectl port-forward`-style stream to the Pod via the API server), with FatLine's own mTLS running *inside* it. Zero new public surface, zero LB cost. But it re-merges FarCast's data plane onto Google's control plane (against FatLine's "sole networking layer" charter and ADR 0004's deliberate separation), leaks session metadata to the API server, would drag `client-go`/SPDY into the deliberately minimal-deps CLI, and does not carry Phase-7 GUI traffic.
3. **Deferred point of presence (A3).** In 2.1, stand up no external ingress at all: build and test the mTLS tunnel server + egress proxy as the artifact, reachable in-cluster and loopback for tests; bind the external carrier later (2.3), defaulting to A1.

### Findings

**1 — A public-but-mutually-authenticated port is acceptable under "security by default."** The L4 passthrough LB has no application logic to exploit; the entire boundary is `RequireAndVerifyClientCert` in FatLine. An attacker with the IP gets a TCP connect and a `ClientHello`, then is dropped at certificate verification — no bytes routed, no allowlist reached, no app touched. The default for an unauthenticated peer is *rejection*: deny-by-default at the front door, in the same structural spirit as Autopilot's undisablable egress NetworkPolicy. It is a locked door on a public street, not an open one.

**2 — But the cost is real, and in 2.1 it would buy nothing.** A ~$18/mo forwarding rule fronting a tunnel that *cannot be called* — `farcast connect` is 2.3, and no application exists to proxy until Phase 4 — burns money for months for zero deliverable value. That is a direct hit on the non-negotiable cost pillar, with no offsetting benefit. The PoP earns its cost only once `connect` makes it usable.

**3 — The carrier is a binding, not the boundary.** The security boundary is the mTLS handshake, the per-instance CA, and the allowlist engine. *How bytes arrive* — a public L4 LB, a control-plane port-forward stream, or an in-cluster service — is a thin transport binding on top of that core. As long as 2.1 fixes the wire protocol, the auth policy, the trust root, and a carrier seam, swapping the carrier later touches none of the security-critical code. This is what makes A3 principled sequencing rather than a dodge.

**4 — A2 is a fallback, not the default.** Reusing the control plane is attractive for zero cost and zero public IP, but it sacrifices the data/control-plane separation ADR 0004 worked to establish, can't carry GUI traffic, and would compromise the CLI's minimal-deps posture. It is the right *break-glass / constrained-environment* path, not the everyday one.

**5 — A1 is the correct eventual design.** It is the only approach that satisfies the "instance is your point of presence" model and Phase 7's "all GUI traffic proxied through FatLine" requirement, with the cloud carrying only ciphertext. So the deferral (A3) is *of A1*, not a rejection of it.

---

## Decision

1. **Build FatLine deferred-hybrid: the artifact in 2.1, the paid point of presence at 2.3.** Phase 2.1 ships FatLine as a transport-agnostic artifact with **no public data-plane ingress** — a normal userspace Pod ([ADR 0003](0003-gke-autopilot.md): no privileged/`hostNetwork`/`NET_ADMIN`) behind a ClusterIP Service, plus the stdlib-only client tunnel library — exercised loopback/in-process and optionally in-cluster. It adds **zero** new cloud spend on the ~$37–51/mo baseline. The external carrier is bound at **2.3**, when `farcast connect` makes it usable.

2. **Lock four protocol-shaping invariants in 2.1** (so the deferral is sequencing, not a dodge):
   - a **multiplexed, GUI-sized tunnel framing** — many concurrent proxied streams over one mTLS session with per-stream flow control (default: HTTP/2-over-mTLS), not a thin CLI RPC that Phase 7 would force a rewrite of;
   - **mandatory client-cert verification** (`tls.RequireAndVerifyClientCert`) as a **non-relaxable** invariant;
   - the **per-instance CA** trust root (operator-held; never in the cluster);
   - a **thin, swappable carrier abstraction**, so the external transport is a binding, not a rewrite.

3. **Name the default 2.3 carrier, but defer its ratification (and cost) to 2.3.** The proposed default is a **single mTLS-gated L4 passthrough NLB** per instance — one forwarding rule carrying *all* operator + GUI traffic over the multiplexed tunnel (never multiplying per-app), TLS terminated in FatLine userspace so Google carries only ciphertext + SNI. The documented fallback / break-glass is the **A2 control-plane port-forward** path (FatLine's own mTLS inside the IAM-gated control-plane stream), for an environment that cannot or will not expose a public data-plane IP. **The acceptance of a public data-plane IP as the Phase-7 posture, and the ~$18/mo standing cost, are a 2.3/Phase-7 decision** — 2.1 does not present them as settled, and the cost must be surfaced at `connect` time so the mandatory cost limit accounts for it.

4. **Operator/data-plane access is via FarCast's own per-instance CA + mutual TLS** — never Google IAM. This keeps the sovereign data path off any central authority and preserves the [ADR 0004](0004-private-control-plane.md) control-plane/data-plane separation. The operator's credential is a client cert (SPIFFE-style URI SAN `farcast://<instance>/operator`) stored at `0600` alongside the kubeconfig.

5. **The carrier is relaxable; the authentication is not.** In the spirit of [ADR 0004](0004-private-control-plane.md) decision #5 ("relaxable, not rebuilt"), the carrier is a swappable binding — an environment may move between the public NLB (A1) and the control-plane path (A2) without recreating anything. **But unlike the control plane's IAM-gated public-IP fallback, the data-plane carrier's mTLS client-cert verification may never be relaxed** into an unauthenticated public surface. The escape hatch swaps *how* you arrive, never *whether* you are authenticated.

6. **The egress / private-node story stays deferred.** This ADR decides ingress. The deny-by-default *egress* boundary is enforced by the always-on NetworkPolicy (Planck 4.2), with FatLine doing userspace allowlisting; private nodes and the Cloud-NAT-vs-proxy-only egress trade-off remain the open FatLine-phase design note ADR 0004 flagged (interacting with the DNS-rebinding mitigation — FatLine resolving the name it allowlisted).

---

## Consequences

**Positive**

- **No cost spent before there is value.** 2.1 adds nothing to the cloud bill; the LB cost lands only when `connect` (2.3) makes the PoP callable — the cost pillar honored at the moment it would otherwise be violated.
- **Empty inbound attack surface during 2.1**, while the egress boundary and the mTLS core are fully built and `-race`-tested.
- **The artifact survives contact with the eventual PoP and Phase 7**, because the wire protocol, auth policy, trust root, and carrier seam are fixed up front — the 2.3 carrier is a binding swap, not a redesign.
- **Sovereign, central-dependency-free identity.** FarCast's own per-instance CA authenticates the data plane; no public CA, ACME, or Google IAM in the path.

**Negative / constraints**

- **No end-to-end public-path proof in 2.1** — the artifact is exercised loopback/in-cluster; the paid PoP is validated only at 2.3. This is the deliberate, surfaced tradeoff.
- **The eventual public IP is a real (if mTLS-gated) attack surface** and a standing cost. It absorbs unauthenticated handshake attempts (a DoS/handshake-flood surface, mitigated by the L4 LB and cheap cert-verify rejection), and makes TLS-stack correctness load-bearing — which is exactly why [ADR 0002](0002-backend-language-strategy.md) flags FatLine as the lone Rust candidate and mandates race tests on its shared state.
- **The server leaf key is readable by the managed control plane** (a K8s Secret); the operator-held CA signing key never is. Hardening (CMEK / memory-only delivery) is deferred and sharpens if the threat model adopts process-memory-disclosure / co-tenant attacks (an open ADR 0002 input).

**Per-module implications**

- **FatLine (2.1)** — ship the artifact: mTLS tunnel server + client library, deny-by-default egress proxy + allowlist, per-instance-CA crypto, lifecycle, Shrike event seam; ClusterIP only; the carrier behind a thin abstraction.
- **FarSight CLI (`farcast connect`, 2.3)** — bind the default NLB carrier (control-plane fallback), bootstrap FatLine into the instance (deploy + mint/inject mTLS material), and surface the LB cost against the cost limit.
- **Planck (4.2)** — emit the per-app deny-egress NetworkPolicy and template the FatLine sidecar/env; (provisioning) revisit private nodes + Cloud-NAT-vs-proxy egress per the deferred ADR 0004 note.
- **Shrike (2.2)** — implement the `EventSink` seam FatLine exposes.

---

## Sources

- New DNS-based endpoint for the GKE control plane (GA) — https://cloud.google.com/blog/products/containers-kubernetes/new-dns-based-endpoint-for-the-gke-control-plane
- GKE LoadBalancer Services / external passthrough Network Load Balancer — https://cloud.google.com/kubernetes-engine/docs/concepts/service-load-balancer
- Network Load Balancer pricing (forwarding rules) — https://cloud.google.com/vpc/network-pricing#lb
- TLS 1.3 (RFC 8446) and mutual authentication — https://www.rfc-editor.org/rfc/rfc8446
- SPIFFE / X.509 SVID identity (URI SAN identity model) — https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md

---

## Ratification (2026-06-23, Phase 2.3)

`farcast connect` was implemented and the carrier **ratified as proposed**: the default (and only wired) carrier is the **public mTLS-gated L4 passthrough NLB** (A1). `connect` provisions it on first connect behind a confirmation gate that surfaces the standing **~$18/mo** against the instance's cost limit (`--yes` to skip, required non-interactively), and never relaxes the mTLS client-cert verification (decision #5 holds). The A2 control-plane port-forward fallback remains **documented but unbound** — the carrier seam (`fatline/deploy` Service type + the CLI's `--carrier` flag) reserves it for a later phase. The operator's per-instance CA **private key never leaves the machine**; only the CA certificate and the server leaf+key are injected into the in-cluster Secret. The deploy/inject mechanism (kubectl subprocess, no vendored Kubernetes client) is [ADR 0006](0006-connect-bootstrap-kubectl.md).

---

*This ADR is a living record. Revisit it when the FarSight GUI (Phase 7) exercises the public PoP at scale, when the A2 control-plane fallback is bound, when the threat model hardens (ADR 0002 open input), or when the second cloud provider (8.1) arrives.*
