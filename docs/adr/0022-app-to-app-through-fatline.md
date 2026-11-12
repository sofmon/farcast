# ADR 0022 — Application-to-Application Traffic Goes Through FatLine

**Status:** Proposed (2026-11-11). Nothing below is built. The operator made the decision this ADR records. The mechanism is this ADR's proposal and still needs the operator's acceptance.

**Date:** 2026-11-11

**Relates to:**
- **Extends** [ADR 0005](0005-fatline-data-plane-ingress.md)'s deny-by-default boundary from traffic that enters or leaves an instance to traffic between the applications inside it.
- **Uses**:
  - [ADR 0013](0013-per-application-egress-identity.md)'s per-application credential, which says who is calling;
  - [ADR 0018](0018-thin-device-storage.md)'s per-application leaf, which says who is answering;
  - [ADR 0015](0015-what-the-boundary-can-measure.md)'s account of what a proxy that does not read its traffic can measure.
- **Constrained by:**
  - [ADR 0016](0016-adaptive-resources.md) decision 2: the kernel never resizes FatLine;
  - [ADR 0009](0009-technocore-kernel-and-cost-metering.md): FatLine is last-to-die;
  - [ADR 0019](0019-what-the-cluster-tells-its-provider.md): what the provider's audit log keeps, and for how long.
- **Meets** [ADR 0021](0021-farsight-native-client.md) decision 5, whose tile-ingress ADR also routes FatLine to an application's port. Decisions 4 and 7 below are the parts of this ADR that ADR inherits.
- **Independent of** [ADR 0020](0020-instance-pki-ecdsa-p256.md). This ADR uses the instance CA's leaves, whatever algorithm they use.

---

## Context

On 2026-11-11 FarSight's app-first world map was being prototyped. Every application is a placed panel, and the connections between applications, and to the outside, are drawn graded by evidence: observed by FatLine, declared, or denied. Drawing an edge between two applications showed that **such an edge cannot exist today.** The operator decided on the spot that application-to-application traffic goes through FatLine, so that every connection between applications is declared, denied by default, counted, and drawable.

Reading the code to ground that decision turned up three things.

**1. The comment and the behaviour disagree.** Planck gives every application one NetworkPolicy ([`planck/translate/workload.go:217-288`](../../planck/translate/workload.go)). Its ingress rule admits `from: - podSelector: {}`, which is every pod in the same namespace. The comment above it says *"Apps in one manifest are one system and may talk."* The egress rules of the same policy allow DNS, FatLine's egress port (3128) and, when storage is wired, the keyholder. Nothing else. Kubernetes admits a pod-to-pod connection only when the source's egress **and** the destination's ingress both allow it. So a direct call from one application to another is dropped by the **caller's** egress policy before the callee's ingress rule is ever consulted. Apps in one manifest may not talk, whatever the comment says.

**2. The ingress rule therefore admits nothing FarCast renders, and it admits everything FarCast does not.** Every pod FarCast places in an application namespace carries that egress policy. Builds and fetches run in `farcast-system` ([`planck/build/build.go`](../../planck/build/build.go)). So the rule's only effect is on a pod someone else puts in the namespace: a `kubectl run` by hand, or a workload a later change forgets to police. Such a pod reaches every application in the namespace. A rule that only works for pods FarCast did not create is not doing the job its comment describes.

**3. FatLine's egress path can already dial inside the cluster. Its destinations' own ingress policies are what stop it, and this decision would remove one of them.** FatLine dials whatever the cluster resolver returns for an allowed host ([`fatline/internal/proxy/proxy.go:173`](../../fatline/internal/proxy/proxy.go)). The manifest parser accepts any syntactically valid hostname, including a single label (`datasphered`) and a cluster name (`api.shop.svc.cluster.local`), and the resolver's search path completes a single label into `farcast-system`. Today an application's ingress admits its own namespace only, so FatLine, in `farcast-system`, is dropped at the destination. The README already names the general hazard as the "DNS-rebinding split" ([`fatline/README.md:327`](../../fatline/README.md)): FatLine allowlists a name and dials an address. Decision 7 below makes every called application admit FatLine. Without decision 6, any declared `external` host that resolves to a callee would reach it through the egress path, uncounted as a call and without the callee's consent. Closing that is part of this decision, not a follow-up.

### What already exists to build on

- **The caller's identity at FatLine.** Each application presents its own 256-bit credential in `FARCAST_FATLINE_PROXY`, and FatLine names it on every decision ([ADR 0013](0013-per-application-egress-identity.md) decisions 1, 6 and 7).
- **The callee's identity end to end.** `farcast run` already mints a per-application leaf, `farcast://<instance>/app/<namespace>/<name>`, from the operator-held CA, and delivers it in the application's own Secret ([ADR 0018](0018-thin-device-storage.md) decisions 1 and 6; `identity.IssueAppClient`). Today it is a client leaf, and only when storage is wired.
- **One port per application.** Planck assumes every application serves on `DefaultPort` (8080) and publishes a ClusterIP Service on it ([`planck/translate/translate.go:84`](../../planck/translate/translate.go)). The manifest names no port and does not need to.
- **A proxy that copies and does not read.** The CONNECT path tunnels opaquely, peeks the ClientHello for SNI, and emits one event per decision with byte counts and connection timings ([ADR 0015](0015-what-the-boundary-can-measure.md)).
- **A monitor that keys by application.** Shrike's tables are per application, and a separate table already exists for traffic that is not egress, the tunnel streams, split off by `Proto` ([ADR 0015](0015-what-the-boundary-can-measure.md) decision 7).

---

## Decisions

**1. A call is declared by the caller, in its manifest, by application name and reason.** A new per-app list, `calls`, sits beside `external`:

```yaml
name: shop
apps:
  - name: web
    containerfile: ./web/Containerfile
    calls:
      - app: api
        reason: Renders pages from the order API
  - name: api
    containerfile: ./api/Containerfile
    external:
      - host: api.stripe.com
        reason: Payment processing
```

It declares *what*: which application, and why. It names no port, protocol, path or address, for the same reasons `external` does not, and an application has one port anyway. The operator reviews `calls` in the same `farcast run` review as `external`. The parser refuses:
- a call to an application the manifest does not declare;
- a call from an application to itself;
- a duplicate entry;
- an empty reason.

The caller declares rather than the callee because the caller's code is what reaches out, which keeps the rule symmetric with `external`. Within one deployment that is enough: one author wrote both sides, and the operator approved both in the same review.

**2. A call across deployments is allowed only when both sides declare it. Until phase B ships, it is refused.** Deployments are tenants of one instance. That was the existing comment's word, and it is right. A callee's author may have written an internal interface on the assumption that only their own deployment could reach it. One-sided consent would expose that interface without them knowing. So a cross-deployment call needs:
- the caller's `calls` entry, with `deployment:` naming the callee's deployment as deployed (its namespace);
- the callee's `accepts` entry, naming the caller as `deployment` and `app`, with a reason.

Each side lives in its own deployment's record in the policy document (decision 5). Each `run` replaces only its own deployment's record, as it does today ([`farsight/cli/internal/cli/runpolicy.go`](../../farsight/cli/internal/cli/runpolicy.go)). So either author withdraws by redeploying without the declaration, and FatLine allows the call only while both records say so. A call declared by one side alone is *pending*. It is refused and counted, and it does not alert.

Forbidding cross-deployment calls outright was rejected (Alternatives). The parser refuses `deployment:` and `accepts` until phase B, so a manifest cannot declare something the platform would silently not do.

**3. A call is a CONNECT to FatLine that names the callee as an application, never as an address.** The caller uses the proxy it already has: the same `FARCAST_FATLINE_PROXY`, the same credential, the same port. It asks for `CONNECT <app>.<namespace>.app.farcast:443`.
- **The name.** `.app.farcast` is a synthetic suffix, verified against the instance CA and never resolved, in the family of `<instance>.fatline.farcast` and `<instance>.datasphered.farcast` ([`fatline/identity`](../../fatline/identity/identity.go)). FatLine parses exactly two DNS labels before it and treats anything else as unknown.
- **Where FatLine dials.** FatLine identifies the caller first (ADR 0013 decision 6). Then it looks the callee up in the policy document and dials the Service address `farcast run` wrote there (decision 5), `<app>.<namespace>.svc.cluster.local.:8080`. It does not dial anything the caller supplied.
- **The CONNECT port.** It is recorded and selects nothing.
- **The namespace in the name.** Planck renders the application's own namespace into its ConfigMap, so code builds the callee's name without hardcoding a namespace that `farcast run --namespace` may change. The SDK builds the name from the callee's application name.

The listener is shared because a second one would mean a second proxy variable in every application and a second port in every caller's egress policy, and the isolation it would buy is bought by decision 10 instead.

**4. FatLine copies; it never terminates. The caller and the callee run mutual TLS end to end under instance-CA leaves.**
- **Leaves.** The per-application leaf is minted for **every** application on every `run`, whether or not storage is wired. It gains the `serverAuth` usage and a DNS SAN `<app>.<namespace>.app.farcast` beside its existing URI SAN. The keyholder decides from the URI alone, so adding the server half changes nothing it admits.
- **The callee** serves TLS on its one port with that leaf. It requires a client leaf from the instance CA with an `app` URI, and it learns the caller's identity from the leaf. That identity is independent of FatLine. FatLine is the component on hostile bytes, and it holds no application's key, so it cannot forge a caller.
- **The caller** trusts only the instance CA for `.app.farcast` names, pins the callee's URI, and presents its own leaf.
- **The SDK** supplies both halves. An application that does not use the SDK reads the same variables any TLS server or client would.
- **An application that cannot serve TLS cannot be called.** It can still call.
- **What FatLine checks on this path, all stricter than on egress.** It never degrades to authority-only matching here:
  - The first record from the caller must be a ClientHello whose SNI equals the requested name. A missing SNI or a non-TLS first record is refused as `cleartext_not_allowed` or `sni_mismatch`.
  - The first record back from the callee must be a TLS handshake or alert record. Anything else is torn down as a `Fail` with `callee_not_tls`, so a callee's cleartext answer never gets past FatLine to the caller.

  This is a check on framing and an extra layer of protection, not a cryptographic guarantee. The guarantee is that both ends verify each other.

Terminating at FatLine, to read requests or to inject a caller header, is refused for the reason [ADR 0015](0015-what-the-boundary-can-measure.md) decision 1 refused it for egress: it would make the component on attacker-controlled bytes a man-in-the-middle on the operator's own traffic.

**5. Deny by default at FatLine, against a policy document that carries the graph.** The policy document becomes version 2.
- **What each application's record gains:**
  - its `calls`, as namespace, app and reason;
  - its `accepts`, from phase B;
  - its Service address, if anything may call it.
- **Version safety.** A version-1 document stays readable. A FatLine that predates version 2 refuses a version-2 document rather than enforce part of it ([`fatline/policy/policy.go`](../../fatline/policy/policy.go)), and what that refusal does depends on when it happens ([`fatline/cmd/fatline/main.go`](../../fatline/cmd/fatline/main.go)):
  - **While running**, it keeps its previous policy and logs the refusal. The applications just deployed are then unknown to it, and every request they make is refused as `unknown_app`.
  - **At start**, `loadPolicy` returns the error and the process exits. A FatLine replica restarting onto a version-2 document never comes up, so the tunnel goes with it.

  So `farcast run` writes version 2 only to a FatLine that reports it understands it, and tells the operator to `farcast redeploy` otherwise.
- **Order of checks for a call:**
  1. identify the caller (`unknown_app`);
  2. look up the callee;
  3. check the caller's `calls` (`call_not_declared`);
  4. across deployments, check the callee's `accepts` (`call_not_accepted`);
  5. dial.
- **The caller's view.** A caller gets the same 403 and body for a callee that does not exist and for one it may not call. Otherwise a caller could list another tenant's applications by probing names. The event keeps the two cases apart for the operator.
- **What the document holds.** Names and reasons, no secret. It stays a ConfigMap, for ADR 0013 decision 3's reason.

**6. The egress path stops reaching inside the cluster.** For an `external` host, FatLine:
1. resolves the name as an absolute name, so the search path never applies;
2. refuses, as `Deny` with `internal_address`, any answer that is:
   - not globally routable;
   - private (RFC 1918, unique-local IPv6, carrier-grade NAT space);
   - loopback or link-local, which includes the metadata server;
   - inside the cluster's own pod and Service ranges, which FatLine is given at deploy;
3. dials the address it checked, not the name.

That last step is the DNS-rebinding mitigation [`fatline/README.md:327`](../../fatline/README.md) recommended. Its interaction with the deferred Cloud-NAT question in [ADR 0004](0004-private-control-plane.md) does not arise here: the check is on the destination, whatever carries the packet. The build Job already excludes the same ranges with a NetworkPolicy ([`planck/README.md:294`](../../planck/README.md)). FatLine cannot, because it must reach callees and the keyholder, so it checks in code.

The parser also refuses `external` hosts with a single label or under `.local`, `.internal` or `.farcast`. That is a usability guard that tells an author early. The check in FatLine is the one that matters, because a public name can resolve anywhere.

**7. Planck's NetworkPolicy: a called application admits FatLine on its one port, and nothing else. An application nobody calls admits nothing.**
- **Callee ingress.** A callee's ingress rule becomes `from:` the `farcast-system` namespace and the `app.kubernetes.io/name: fatline` pods, TCP on `DefaultPort`. An application is a callee when another application in its manifest calls it, or, from phase B, when it `accepts` a caller. Whether to render the rule therefore depends only on the deployment's own manifest. No other deployment's `run` ever re-renders it.
- **No callers.** An application with no callers keeps `policyTypes: [Ingress, Egress]` with no ingress rules, which Kubernetes reads as deny all.
- **The same-namespace rule is removed, not justified.** It admits nothing FarCast renders (Context, point 2). It admits whatever FarCast does not render. Kept, it would also be the bypass the day anyone widens a caller's egress.
- **Caller egress is unchanged.** Callers already reach FatLine on 3128.
- **What the network enforces, and what FatLine enforces.** The NetworkPolicy cannot tell which caller FatLine is acting for, and it does not try. "Which callers" is FatLine's check. "Only FatLine, and only to an application someone is allowed to call" is the network's. That is the same split ADR 0013 decision 4 made: the network decides whether traffic passes FatLine at all, and FatLine decides what it may do.
- **The policy body names no caller.** Planck's NetworkPolicy bodies go to the provider's Admin Activity log in full for 400 days ([ADR 0019](0019-what-the-cluster-tells-its-provider.md)). The graph itself stays in the policy ConfigMap, whose writes that log records at Metadata level. The policy body does reveal one bit per application: whether anything may call it (*What the provider still sees*).
- **Probes.** Planck renders no probes, so there is no kubelet traffic to admit. If TechnoCore ever adds probes, the node-sourced rule the keyholder needs ([`datasphere/deploy`](../../datasphere/deploy/deploy.go)) is the precedent, and that is that change's work.
- **The comment** at [`workload.go:233-235`](../../planck/translate/workload.go) is replaced by one that says the above (*Sentences this ADR corrects*).

**8. Shrike counts each edge, caller → callee, in its own table.**
- **The event.** A call is an event with `Proto` `call`. It names the caller (from the credential), the callee (from the policy), and the name the caller asked for. An unknown name is cut to 64 bytes, as an unknown route is.
- **The table.** Shrike keeps calls apart from egress and tunnel streams, the way it already separates streams ([ADR 0015](0015-what-the-boundary-can-measure.md) decision 7), in a `Calls` table keyed by `(caller namespace/app, callee namespace/app)`. Each row has:
  - connections allowed and closed;
  - bytes each way;
  - the distributions of dial time and connection duration;
  - refusals by reason;
  - failures by reason: `dial_failed`, `callee_not_tls`, `capacity`;
  - first and last seen;
  - the `declared` cross-check against Shrike's own copy of the policy.

  Names that match no application fold into one `(unknown app)` row per caller. The text is the caller's, and kept per name it would let one application grow the picture without bound.
- **Alerts.**
  - `call_not_declared` is a violation and alerts per caller, reason and callee, as `not_in_allowlist` does.
  - `call_not_accepted` is a pending edge (decision 2). It is counted at info level and raises nothing.
  - `internal_address` on the egress path alerts. The operator approved a name, and it now points inside the instance.
  - A `Fail` never alerts. A callee that is down, or stopped by the cost guard, is an outage, not a violation.
- **Who reads it.** The table is served where the rest of the picture is: `127.0.0.1` inside the Pod, read over the operator's `shrike` route (ADR 0015 decision 4). `farcast usage` gains the edges.

**9. The map draws what the boundary saw, and says how much of it that is.** FarSight builds edges from two sources:
- the declared graph, from the policy document the operator's machine writes;
- the observed graph, from Shrike's `Calls` table.

Each edge is in one of four grades:
- **observed**: FatLine carried a connection;
- **declared**: in the policy, not seen;
- **denied**: attempted and refused;
- **pending**: across deployments, declared by one side.

External edges come from the existing per-application `Allowed` and `Denied` tables, graded the same way. *Declared but not observed* must never be drawn as *unused*. Each FatLine replica keeps its own picture in memory since it started, and a read lands on one replica ([`shrike/README.md:256`](../../shrike/README.md)), so an edge the other replica carried is invisible from this one. The map names the replica it read and says the counts are that replica's share, as `farcast usage` already does.

**10. Calls must not starve the tunnel.** FatLine is now on the path of every application conversation, and it is also the operator's only way in. It is fixed at 100m/128Mi per replica. The kernel never resizes it (ADR 0016 decision 2), and a cost shutdown never stops it (ADR 0009). So:
- **Caps.** The call path gets its own concurrency caps, per caller and in total. They are separate from egress, and the tunnel listener is never subject to them. A call refused at a cap is a `Fail` with `capacity`, never a `Deny`.
- **What the caps do not bound.** They bound connections and memory, not CPU. A few connections at line rate can still compete with the tunnel for FatLine's CPU. The walk measures how much. If it is enough to matter, the levers are a per-caller byte rate and, beyond that, the separate east-west deployment in *Alternatives*.
- **Sizing stays the operator's.** `farcast usage` shows call bytes against FatLine's fixed requests. Resizing FatLine stays the operator's act, through `redeploy`, for ADR 0016's reason: a kernel that could resize the tunnel could remove the means of fixing its own mistake.

---

## What stays unmeasured

Stated so the map does not overclaim:

- **Requests.** The boundary sees no request counts, methods, paths, status codes or per-request latency, because each call is a TLS session FatLine does not hold a key to (ADR 0015 decision 1, applied to this path). One connection may carry thousands of requests over HTTP/2. **Connection counts are not request counts.**
- **Payload.** Nothing inside a call is visible. Exfiltration *to a declared callee* is as invisible as exfiltration to a declared external host. Reviewing declarations is the control.
- **Direct attempts.** An application that dials a callee's ClusterIP directly is dropped by its own egress policy in the dataplane, and FatLine never sees it. GKE can log policy drops, but that log is delivered to the provider's Cloud Logging, and keeping application traffic out of Cloud Logging is why [ADR 0019](0019-what-the-cluster-tells-its-provider.md) exists. Refused here: **a direct attempt is blocked and not counted.**
- **The whole instance at once.** Counts are one replica's share, since that replica started, and a floor rather than a total, because `BufferedSink` drops under flood ([ADR 0015](0015-what-the-boundary-can-measure.md) *Consequences*).
- **Who inside the callee.** The callee learns the caller's identity from the leaf. Neither FatLine nor Shrike learns what the callee did with it.

---

## What the provider still sees

The provider remains **blind to content** on this path, and not to anything more:

- **Content.** Each call is TLS 1.3 between two application leaves, so the provider carries ciphertext between pods, as it does on egress. Every application's leaf key rests in that application's Secret, which a provider that reads etcd or node memory can read. That class of exposure was already conceded, not created here: the provider could impersonate one application to another, or read either endpoint's memory. In [ADR 0008](0008-in-cluster-key-delivery.md)'s terms, call content is *protected by the provider not looking* against an active provider, and protected outright against passive capture, because TLS 1.3's ephemeral key exchange means a key read later does not open traffic recorded earlier. The leaf binds neighbours, tenants and thieves, not the provider ([ADR 0018](0018-thin-device-storage.md) decision 6).
- **The declared graph.** It sits in FatLine's policy ConfigMap in etcd. The audit log records each write at Metadata level only (name, time and caller, no body), so it dates every `run` that changed the graph without carrying the graph.
- **Which applications are callees.** One NetworkPolicy body per application, kept in full in Admin Activity for 400 days, shows whether it admits FatLine. It does not show who calls it.
- **The live graph, by inference.** The provider runs the pod network. The caller's CONNECT line, which carries the callee's name and the caller's credential, crosses it in cleartext, as egress CONNECTs do today (ADR 0013 *Consequences*). The ClientHello's SNI names the callee. Even without either, timing and sizes correlate caller → FatLine with FatLine → callee. GKE's per-Pod network metrics, kept up to 24 months (ADR 0019), now show FatLine carrying the call volume. **FarCast does not claim to hide which applications talk to which, or how much.** It claims the provider cannot read what they say.

Wrapping the CONNECT itself in TLS to FatLine would hide the credential and the name on the wire. It would not hide the graph, for the reason in the last bullet. That is a revisit trigger, not part of this decision.

---

## Cost

- **No new Pod, Service or load balancer.** Calls ride FatLine's two existing replicas and its existing ClusterIP `fatline-egress` Service. Nothing here has a standing cost.
- **FatLine's requests are unchanged, and that has a price.** Calls spend CPU that is already reserved and billed, so they cost nothing extra until they saturate it (decision 10). If the operator raises FatLine's request, each extra 100m is about $3.25 a month per replica, $6.50 for two, at [ADR 0003](0003-gke-autopilot.md)'s Autopilot price of $0.0445 per vCPU-hour.
- **The hop can double inter-zone transfer.** VPC pricing bills traffic between zones in one region at about $0.01/GiB and same-zone internal traffic at nothing (Sources). A direct call crosses at most one zone boundary. A call through FatLine can cross two, caller → FatLine → callee. In the worst case, 1 TiB of calls a month costs about $20 instead of about $10. Two things are open:
  - whether Autopilot bills pod traffic exactly as VPC bills VM traffic. The documentation read for this ADR did not say, so the walk checks;
  - the kernel's `expected` meter, which models Pod requests and **does not model network transfer**. This cost joins the unmodelled list [ADR 0019](0019-what-the-cluster-tells-its-provider.md) *Consequences* started. Shrike's edge bytes are the input a future model would need. Until then the cost guard cannot see this spend.
- **Latency.** Each new connection pays one extra in-cluster hop and the CONNECT exchange. Connection reuse amortises both. FatLine measures dial time per edge, so the walk records the cost rather than this ADR guessing it.

---

## Alternatives considered

**How a call is declared**
- **Implicit within a deployment**, which is what the old comment intended. Rejected. An undeclared edge cannot be reviewed, Shrike cannot call an attempt a violation, and the map has no declared layer to compare against. AGENTS.md's deny-by-default covers *all* connections.
- **Callee-side declaration only.** Rejected within a deployment, because the caller's code is what reaches out. It is the second key across deployments (decision 2).
- **Ports or protocols in the declaration.** Rejected. Manifests describe what, not how, and an application has one port.
- **Cross-deployment wiring by the operator alone**, as a CLI link. Rejected. The callee's author never consents, and their interface may assume it is internal.
- **No cross-deployment calls ever.** Rejected. A service shared across deployments would have to be duplicated, or merged into one manifest. Two-sided consent gives the protection without the prohibition.

**How a call is carried**
- **Direct pod-to-pod, with NetworkPolicy admitting declared pairs.** Rejected. Nothing counts it, so there is no Shrike row and no observed edge. It fails silently where NetworkPolicy is not enforced, which is [ADR 0013](0013-per-application-egress-identity.md)'s portability argument. And it writes the whole graph into NetworkPolicy bodies, which the audit log keeps in full for 400 days.
- **FatLine terminates TLS**, which would give request metrics and a caller header. Refused, for ADR 0015 decision 1's reason (decision 4).
- **Cleartext through FatLine.** Rejected. It puts plaintext on a provider-carried network, against `cleartext_not_allowed` and AGENTS.md's "blind to content".
- **A managed service mesh** (Cloud Service Mesh, or Istio on Autopilot). Rejected. Its control plane and mesh CA would be the provider's: the central dependency AGENTS.md forbids, and a second network boundary beside FatLine. Its sidecars add a billed container to every Pod. Extending FatLine's route table is the smaller change, and it is not inventing infrastructure. FatLine already is the instance's proxy.
- **A separate east-west FatLine Deployment.** Deferred. It would isolate calls from the tunnel completely, at the cost of more always-on Pods (ADR 0003's per-Pod minimum, twice). Decision 10's caps come first. A walk that shows contention is the trigger.
- **A second listener and port on FatLine.** Rejected. It would mean a second proxy variable and a second egress rule in every application, for isolation the caps provide.
- **A TLS-terminating sidecar inside the callee's Pod**, so plain-HTTP applications could be called with plaintext staying inside the Pod. Deferred. It costs a billed container per callee, and the SDK covers the common case. Applications that cannot use the SDK are the trigger.

**The NetworkPolicy**
- **Keep the same-namespace ingress rule.** Rejected (decision 7).
- **Admit FatLine on every application's port.** Rejected for now, because deny by default means an uncalled application is unreachable. The tile-ingress ADR (ADR 0021 decision 5) may widen this to every application with a tile. That is its decision to make, and it would remove the one bit *What the provider still sees* names.

---

## Consequences

- **Calls work, and nothing else changes for an application that makes none.** No application can call another today (Context, point 1), so removing the same-namespace rule breaks nothing FarCast runs.
- **A callee must speak TLS on its port.** This is the price of keeping FatLine copy-only, and it is real. An application that does not use the SDK has to load a certificate. The tile path that ADR 0021 decision 5 leaves to its own ADR reaches the same port, so that ADR inherits the requirement. Its natural shape is the device-side bridge running TLS end to end to the application inside the tunnel stream.
- **Every application gets a leaf, and leaves expire.** A leaf lives 90 days and is reminted on every `run`. An application not redeployed within that window loses its calls on the same day it loses its storage (ADR 0018), and the remedy for one is the remedy for both.
- **FatLine carries more, and stays the same size.** Decision 10 bounds the harm. The walk measures what is left.
- **The egress path refuses destinations it allowed before.** An approved host that resolves to a private address now fails `internal_address`. No known deployment does this. The first operator who needs a VPC-private service is a revisit trigger, not a quiet exception.
- **The policy document's version moves, and an older FatLine fails badly on it.** While running, it keeps its old policy and refuses the new deployment's applications. On restart, it does not start, and the tunnel goes with it (decision 5). `run`'s version check is what stops that being discovered in production. The crash on restart is a property of today's `loadPolicy`, not something this ADR adds. Any future version bump has the same exposure.
- **`run` needs the CA key for every deployment.** It already does once storage is wired (`run.go`'s storage-identity check). Minting a leaf for every application extends that requirement to deployments that use no storage.
- **The map can draw an edge for the first time, and the edge carries a caveat.** The caveat is decision 9's replica share. It is the same caveat `farcast usage` already prints, now in a picture.

---

## Phasing and per-module implications

- **Phase A: calls within one deployment.** Everything in decisions 1, 3–8 and 10, plus decision 9's data:
  - **manifest**: `calls`, its parser rules, and the `external` usability guard;
  - **fatline/policy**: version 2, with calls and Service addresses;
  - **fatline/identity**: the app leaf gains `serverAuth` and its `.app.farcast` DNS SAN, minted for every app;
  - **fatline/internal/proxy**: the call branch, strict SNI and record checks, the egress address check with the pinned dial, and the caps;
  - **fatline/event**: `Proto` `call`, callee fields, and the new reasons;
  - **shrike**: the `Calls` table, the alerts, and the policy copy;
  - **planck/translate**: the callee ingress rule, the same-namespace rule removed, the comment corrected, the namespace rendered into the ConfigMap, the leaf rendered whether or not storage is wired;
  - **farsight/cli**: `run` reviews calls and checks FatLine's version; `usage` shows edges;
  - **sdk/go**: a call client and a TLS listener that exposes the caller.
- **Phase B: across deployments.** Decision 2: `deployment:`, `accepts`, `call_not_accepted`, and the pending grade.
  - *Open for phase B:* how a caller refers to a callee deployed under a namespace other than its manifest name, without writing an instance-specific namespace into a repository.
- **Phase 7: the map draws edges** (decision 9). It is FarSight's consumer, re-sequenced by ADR 0021, and it needs no further boundary work.
- **Untouched:**
  - **TechnoCore.** It neither meters nor resizes the path. The unmodelled transfer is named in *Cost*.
  - **DataSphere.** The keyholder decides from the leaf's URI, and the server half changes nothing it admits.

---

## Sentences this ADR corrects

To be changed when phase A lands, not before. Each still describes the code as built.

- [`AGENTS.md:45`](../../AGENTS.md): *"FatLine is the network boundary. All traffic flows through it. Nothing else touches the network."* This already overstates. An application reaches DNS and the keyholder directly. The keyholder reaches its bucket, and a build its Git host and registry, without FatLine. → *"**FatLine** is the network boundary for applications: every connection an application makes — to the internet or to another application — and every connection into the instance passes through it. The paths that do not are named where they are rendered: DNS and an application's storage, which NetworkPolicy and the keyholder's mutual TLS admit directly, and FarCast's own components' calls to their provider (Planck's README)."*
- [`README.md:280`](../../README.md): *"All traffic — instance-to-instance, instance-to-internet, and client-to-instance — flows through FatLine."* → add application-to-application, and name the same exceptions.
- [`fatline/README.md:7`](../../fatline/README.md): *"Everything that enters or leaves an instance passes through it"* → add the call path. The *Known limitations* entry on the DNS-rebinding split (`:327`) is closed by decision 6. *"Port is not matched"* (`:324`) gains: on the call path, the port selects nothing.
- [`planck/README.md:267`](../../planck/README.md): *"Ingress is its own deployment only."* → *"Ingress is FatLine only, on the application's port, and only for an application something may call; otherwise none."*
- [`planck/translate/workload.go:233-235`](../../planck/translate/workload.go): *"Reachable from its own deployment and nowhere else. Apps in one manifest are one system and may talk…"* → a comment that says calls go through FatLine, that this rule admits FatLine for declared callers only because FatLine checks which caller, and that the caller's egress was never the place this was decided.
- [`manifest/README.md:321`](../../manifest/README.md): *"Inbound / ingress declarations. How applications are exposed to users is handled by FarSight and FatLine, not the manifest."* → exposure to users stays FarSight's and FatLine's. Exposure to another deployment's application is `accepts`.
- [`shrike/README.md:3`](../../shrike/README.md): *"validates live traffic against the manifest's `external` declarations"* → and its `calls`.
- [ADR 0019](0019-what-the-cluster-tells-its-provider.md) *What the provider still sees* gains this ADR's section by reference.

---

## Verification

**Unit tests pin:**
- the parser's `calls` rules and the `external` guard;
- version 2's round trip;
- an older reader refusing version 2;
- the call branch's decisions, for each reason, with one event each;
- the caller's identical answer for an unknown and an undeclared callee;
- strict SNI and the first-record checks;
- the egress address check against an injected resolver, covering each refused range and a name that resolves to both a public and a private address;
- the rendered NetworkPolicy for a callee, a non-callee and a two-app manifest;
- Shrike's `Calls` rows, the unknown-name fold, and that a `Fail` never alerts;
- that the caps never apply to the tunnel listener.

**The walk** deploys a three-app manifest: `web` calls `api`, and `stray` declares nothing.
1. Read back each NetworkPolicy. `api` admits only `farcast-system`/`fatline` on 8080. `web` and `stray` admit nothing.
2. From `web`, dial `api`'s ClusterIP directly. It must time out (dropped), and Shrike must show nothing.
3. From `web`, call `api` through the SDK. It must succeed, and `api` must see `web`'s identity.
4. From `stray`, call `api`. It must get a 403. Shrike shows `call_not_declared` for `stray → api`, and one alert.
5. Declare an `external` host, chosen by the walker, whose public DNS answer is a private address. FatLine must refuse it with `internal_address`. Confirm the parser refuses `api.<ns>.svc.cluster.local` and `datasphered`.
6. Serve plain HTTP from a test callee. The call must fail, and Shrike must record `callee_not_tls` as a failure, not an alert.
7. Run `farcast usage` several times. Record the `web → api` row and each replica's share.
8. Push a measured volume through `web → api`. Record:
   - FatLine's CPU;
   - the tunnel's latency during the transfer;
   - each Pod's zone;
   - whether the billing export shows inter-zone transfer for pod traffic.
9. In Admin Activity, confirm `api`'s NetworkPolicy body names no caller, and the policy ConfigMap's entry has no body.
10. Scale `api` to zero, as the cost guard would. `web`'s calls must `Fail` with `dial_failed`, with no alert.

---

## Revisit triggers

- **The walk shows calls contending with the tunnel.** Add per-caller byte rates, then consider a separate east-west deployment (*Alternatives*).
- **East-west transfer becomes a visible share of the cost limit.** At that point the meter needs to model it, from Shrike's edge bytes and Pod zones.
- **An operator needs an application to reach a VPC-private service.** Decision 6 then needs a declared, reviewed exception, not a removed check.
- **An application that cannot serve TLS needs to be called.** That revisits the callee-side sidecar.
- **The tile-ingress ADR widens callee ingress.** This ADR's NetworkPolicy and disclosure sections are amended with it.
- **The graph becomes something to hide from the provider's network view.** TLS to FatLine for the CONNECT itself is the start, and the inference in *What the provider still sees* is the limit.
- **A second provider (8.1).** Decision 7's NetworkPolicy is again a provider feature ([ADR 0013](0013-per-application-egress-identity.md)'s table). Where NetworkPolicy is not enforced, FatLine's checks still hold for calls that go through it, but nothing then forces calls to go through it. That is the bypass concern ADR 0013's third trigger already gives to 8.1.

---

## Sources

- The code as read on 2026-11-11:
  - [`planck/translate/workload.go`](../../planck/translate/workload.go) and [`translate.go`](../../planck/translate/translate.go): the NetworkPolicy, `DefaultPort`, the egress rules;
  - [`fatline/internal/proxy/proxy.go`](../../fatline/internal/proxy/proxy.go): the CONNECT path and its dial;
  - [`fatline/policy/policy.go`](../../fatline/policy/policy.go): the document and its version rule;
  - [`fatline/identity/identity.go`](../../fatline/identity/identity.go): the leaf names;
  - [`manifest/parser/parser.go`](../../manifest/parser/parser.go): the hostname rules, which accept single labels and cluster names;
  - [`farsight/cli/internal/cli/runpolicy.go`](../../farsight/cli/internal/cli/runpolicy.go): the per-deployment merge;
  - [`datasphere/deploy/deploy.go`](../../datasphere/deploy/deploy.go): the keyholder's ingress, which admits FatLine;
  - [`planck/build/build.go`](../../planck/build/build.go): the excluded ranges.
- Kubernetes, Network Policies: a connection needs both the source's egress and the destination's ingress to allow it — https://kubernetes.io/docs/concepts/services-networking/network-policies/
- Google Cloud, VPC network pricing: same-zone internal traffic free, inter-zone traffic in one region about $0.01/GiB — https://cloud.google.com/vpc/pricing
- IANA IPv4 and IPv6 special-purpose address registries, for the ranges decision 6 refuses — https://www.iana.org/assignments/iana-ipv4-special-registry/ and https://www.iana.org/assignments/iana-ipv6-special-registry/

---

*This ADR is a living record. Revisit it on any trigger above.*
