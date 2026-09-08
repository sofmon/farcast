# ADR 0013 — Per-Application Egress Identity Is a Credential, Not a Position

**Status:** Accepted

**Date:** 2026-09-08

**Relates to:** Unblocks Phase 4.4. Extends [ADR 0005](0005-fatline-data-plane-ingress.md)'s deny-by-default egress from one allowlist per instance to one per application, and keeps its division of labour intact: the network decides *whether an application may reach FatLine at all*, FatLine decides *what it may say*. Constrained by [ADR 0003](0003-gke-autopilot.md) (what Autopilot guarantees, and what other providers do not) and by [ADR 0002](0002-backend-language-strategy.md)'s characterisation of FatLine as the process on attacker-controlled bytes, which is why this decision gives it no new privilege. Borrows [ADR 0010](0010-application-image-builds.md) decision 4's classification of a scoped, rotatable credential.

---

## Context

`farcast run` shows an operator the external hosts **each application** declares, and asks them to approve that. [AGENTS.md](../../AGENTS.md) states the promise plainly: *"All connections — inbound and outbound — are denied unless explicitly declared in an application's `./farcast` manifest."*

Two things are true of the code that is supposed to keep it, and both were found by reading it rather than by a failing test:

1. **The declarations never arrive.** [`fatline/deploy`](../../fatline/README.md) passes no `--manifest`, so a deployed FatLine's allowlist is **empty**. Applications can reach nothing outside the cluster at all. Both the 4.2 and 4.3 walks passed while this was true, because the example application declares no external hosts — the gate was never exercised end to end.

2. **The structure is discarded on the way in.** `flattenExternal` in [`fatline/cmd/fatline/main.go`](../../fatline/cmd/fatline/main.go) concatenates every app's `external` list into one. Even with a manifest loaded, App A would inherit App B's declarations — which is the specific thing PLAN 4.4 says must not happen.

So the operator approves a per-application promise that the enforcement point cannot express and currently does not receive. Closing that is this decision.

### What is available to identify a caller

An application's pod, as [`planck/translate`](../../planck/README.md) renders it today:

- carries **no Kubernetes identity** — `automountServiceAccountToken: false`;
- **shares a namespace** with every other app in the same deployment, so namespace-level separation is unavailable;
- has a NetworkPolicy permitting exactly one outbound destination: FatLine's pods on the egress port;
- reads its proxy address from `FARCAST_FATLINE_PROXY`, injected by the translator.

### The decision space

- **D1 — a listener port per application, with each app's NetworkPolicy permitting only its own.** Identity is the local port a connection arrived on, and the CNI is what stops an app using another's. Attractive because it introduces no secret and reuses the boundary that already exists. **Rejected**, for the reason in the next section.
- **D2 — a per-application credential presented to the proxy.** Identity is checked by FarCast's own code, on any Kubernetes. **Chosen.**
- **D3 — source IP, resolved to a pod through the Kubernetes API.** Nothing app-visible changes and new applications need no reconfiguration. Rejected: it hands cluster API credentials to the one component that lives on attacker-controlled bytes — the direction [ADR 0008](0008-in-cluster-key-delivery.md) decision 4 refused for the keyholder on the same reasoning — and pod IP reuse opens a misattribution window in the component whose output is the audit record.
- **D4 — both a credential and a port.** Defence in depth, and the natural end state if the residue in *Consequences* ever stops being acceptable. Not the starting point: D2 reaches the phase's goal on its own, and D1 layers onto it later without rework.

### Why the port was rejected, having first been chosen

An earlier draft of this ADR chose D1. The argument that displaced it is portability, and it is sharper than a preference.

D1's identity is a *position*; what enforces it is NetworkPolicy. That capability is not uniform across the providers [PLAN.md](../../PLAN.md) 8.1 commits to:

| | NetworkPolicy |
|---|---|
| **GKE Autopilot** | always on, guaranteed ([ADR 0003](0003-gke-autopilot.md)) |
| **EKS** | **off by default**; needs `ENABLE_NETWORK_POLICY=true` on the VPC CNI add-on (v1.14+, Kubernetes 1.25+) |
| **AKS** | engine chosen **at cluster creation and immutable**; an existing cluster must be redeployed to gain one |

**The failure mode is what decides it.** Where policy is not enforced, D1 does not merely weaken — it fails *silently*. App A dials App B's port, FatLine believes it, and every decision, log and alert names App B. No error is raised, the attribution is wrong, and the audit record is confidently false. A control that fails invisibly on two of three targets is the wrong control, and discovering it would require an adversary rather than a test.

D2 fails the other way. If a credential is missing or wrong the request is denied, loudly, in the one place that already refuses things.

The second reason is narrower and was decisive against the last defence of D1 — that it asks less of applications. **It does not.** A credential travels in the proxy URL as userinfo, which is the universal HTTP proxy convention: Go's `net/http` sets `Proxy-Authorization` from `Transport.Proxy`'s userinfo automatically, as do curl, `requests` and Node. An application does exactly what it does today, which is read `FARCAST_FATLINE_PROXY` and use it.

---

## Decisions

**1. An application's egress identity is a per-application credential it presents to FatLine.** Minted by the operator's machine at `farcast run`, delivered to the application in its own Secret, checked by FatLine against the app's declarations. Identity is something the application *holds*, not somewhere it *sits*, so it survives a move to a provider whose network enforces less.

**2. The credential travels as proxy userinfo, so no application changes.** `FARCAST_FATLINE_PROXY` becomes `http://<app>:<credential>@fatline-egress…`, and every standard HTTP client sends `Proxy-Authorization` from it without being asked. An application that ignores the variable still fails closed — the NetworkPolicy denies every other route — so the failure modes an operator already understands are unchanged.

**3. FatLine holds hashes, never credentials.** The policy document carries SHA-256 of each credential and FatLine compares in constant time. Credentials are 256 bits of randomness, which is what makes a fast hash correct here rather than lazy: offline guessing is infeasible against that entropy, so the slow KDF that protects a human-chosen password would buy nothing and would sit on the per-connection path. **The mounted policy therefore contains no secret material at all**, which is what keeps it a ConfigMap and keeps this decision cheap.

**4. The network's job is unchanged, and it is still load-bearing.** NetworkPolicy still forces every outbound byte through FatLine; that is [ADR 0005](0005-fatline-data-plane-ingress.md) and it does not move. What it stops doing is *also* separating applications from each other. The distinction matters on a weaker provider: what is lost there is the guarantee that traffic cannot bypass FatLine — a loud, pre-existing, provider-level concern that 8.1 must face anyway — rather than the silent loss of per-app separation D1 would have suffered.

**5. Policy reaches FatLine as a mounted ConfigMap, not through the Kubernetes API.** `farcast run` writes the per-app document — hosts and credential hashes — and FatLine reads it from a file, reloading through the `ReloadAllowlist` path that already exists. This is what answers D3's objection: FatLine gets no API credential, and the network boundary does not restart when an application deploys, because a ConfigMap update is a file change the kubelet performs.

**6. A caller FatLine cannot identify is denied, and says so as its own reason.** A request with no credential, or one that matches no application, is refused with `unknown_app` rather than falling back to a shared list. There is no shared list to fall back to: `flattenExternal` is deleted, not fixed.

**7. Every egress decision names the application.** `event.Event`'s `App` and `Tenant` fields — reserved in phase 2.1 and empty ever since — are filled from the identified caller, so [Shrike](../../shrike/README.md)'s alerts say which application attempted what. An alert that cannot name the app is telemetry, not enforcement.

**8. A credential is per-application, per-deployment, and rotates by redeploying.** It authorises reaching the hosts an operator already approved *for that application*, so its compromise exposes one app's declared destinations and nothing else. That places it in [ADR 0010](0010-application-image-builds.md) decision 4's class — a scoped, rotatable credential whose blast radius is one thing — not the keyring's, and it is why it lives in a Kubernetes Secret rather than in DataSphere: making egress inherit the storage seal would mean an unsealed instance was also a mute one.

---

## Consequences

**There is now a secret to keep, and D1 would not have had one.** That is the price of this choice and it should not be smoothed over. An application's credential sits in its environment, readable by anything running in that pod — which is the application itself; the boundary being defended is between applications, not within one.

**An application that logs its own proxy URL leaks a usable credential.** Usable only from inside the cluster, because nothing outside can reach FatLine's egress port, and only until the next deploy rotates it. It is a real hazard and the honest mitigation is rotation plus the observation that an application which logs its own configuration has other problems.

**Per-application separation now holds on any Kubernetes**, which is the whole reason for the change. FarCast's promise stops depending on a provider feature that two of three targets leave off.

**"The network stopped it" was easier to verify than "the credential stayed secret".** A reviewer can read a NetworkPolicy; they cannot read discipline. This decision trades a property that can be inspected for one that must be trusted, and accepts that trade because the inspectable property was only inspectable on one provider.

**Nothing here is hidden from the cloud provider.** Secrets, ConfigMaps and policies are all cluster-visible. The provider could already see every packet; per-application separation is about applications, and claiming otherwise would be the overstatement this project treats as worse than not promising at all.

---

## Phasing

- **4.4** — the credential, the per-app policy document, `run` writing it, FatLine identifying callers and attributing decisions, Shrike naming applications in alerts, and `flattenExternal` deleted.
- **Later** — D4's port as a second factor, if the residue above stops being acceptable.

## Revisit triggers

1. **An application leaking its credential in practice**, rather than in principle. That is when D4's second factor stops being optional, and *Consequences* is where to start reading.
2. **Per-application identity being wanted somewhere other than egress.** Storage scopes are the obvious candidate: a credential is something a keyholder can check and a port is not, so this mechanism extends where D1 would have forced a second one. That was an argument for the choice and it is also the trigger to act on it.
3. **A provider whose NetworkPolicy cannot be relied on at all.** The concern then is bypass rather than attribution — applications reaching the internet without passing FatLine — and that is a louder problem than this ADR, belonging to 8.1.

---

## Sources

The two defects in *Context* were read out of the repository on 2026-09-08: [`fatline/deploy/deploy.go`](../../fatline/deploy/deploy.go)'s argument list, which carries no `--manifest`, and `flattenExternal`. The pod's lack of a Kubernetes identity and the shape of the per-app NetworkPolicy are [`planck/translate`](../../planck/README.md)'s rendered output, confirmed live on the [Phase 4.3 walk](../runbooks/phase-4-3-validation.md). The proxy-userinfo behaviour was checked in Go's own `net/http` transport rather than recalled. Provider NetworkPolicy availability was checked against vendor documentation the same day: [Amazon EKS](https://docs.aws.amazon.com/eks/latest/userguide/cni-network-policy.html) and its [VPC CNI announcement](https://aws.amazon.com/about-aws/whats-new/2023/08/amazon-vpc-cni-kubernetes-networkpolicy-enforcement/), and [Azure AKS](https://learn.microsoft.com/en-us/azure/aks/use-network-policies).
