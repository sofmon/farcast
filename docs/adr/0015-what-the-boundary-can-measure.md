# ADR 0015 — What the Boundary Can Honestly Measure

**Status:** Accepted

**Date:** 2026-09-09

**Relates to:** Completes Phase 5.1, the half [ADR 0014](0014-observed-usage.md) deferred as 5.1b. Extends [ADR 0013](0013-per-application-egress-identity.md)'s per-application attribution from denials to allowed traffic. Bounded by [ADR 0005](0005-fatline-data-plane-ingress.md), whose opaque CONNECT tunnel decides what a proxy is *able* to see.

---

## Context

[ADR 0014](0014-observed-usage.md) settled CPU and memory and named what it could not source: PLAN 5.1 also asks for **network I/O and request latency**, and `metrics.k8s.io` carries neither. The instruction it left was to read them from FatLine, which sees every byte an application sends because [AGENTS.md](../../AGENTS.md) says nothing else touches the network.

Reading the code to do that turned up three things, and only the first was the one being looked for.

**Network I/O was already measured and nothing counted it.** FatLine has emitted a `Close` event carrying `BytesUp` and `BytesDown` since 2.1, attributed to an application since 4.4. Shrike consumes every one of them. The bytes were there the whole time; what was missing was somewhere to add them up.

**Request latency is not measurable here, and no amount of work makes it so.** FatLine tunnels CONNECT opaquely and never terminates TLS to the upstream — that is the property [ADR 0005](0005-fatline-data-plane-ingress.md) exists to keep, and the reason the cloud carries ciphertext. The requests inside a connection are, by construction, bytes FatLine cannot read. Measuring per-request latency would mean terminating the application's TLS at the proxy: a man-in-the-middle on the operator's own traffic, run by the component this project treats as the one on attacker-controlled bytes.

**A failed connection was silent.** An allowed CONNECT whose upstream dial failed produced an `Allow` and then nothing at all — a bare `return`. So "reached its declared host" and "never got there" were indistinguishable in FatLine's log and absent from Shrike's picture, and an application whose declared host was down looked exactly like one that was working.

And one more, found in the same read: **allowed traffic was keyed by host alone.** [ADR 0013](0013-per-application-egress-identity.md) decision 7 made denials per-application because two applications denied the same host are two problems with two different remedies. The allowed side never got the same treatment, so two applications talking to the same host reported one merged row of bytes attributable to neither.

---

## Decisions

**1. The boundary reports CONNECTION latency, and says so where it is named.** How long establishing the upstream connection took, and how long it stayed open. That is a real number an operator can act on — a slow or hanging external dependency is exactly what it shows — and it is the honest ceiling of what a proxy that does not read its traffic can know. Request latency is **not deferred, it is refused**: the only implementation is one that breaks the confidentiality FatLine exists to provide. Anything that needs it must measure it in the application, which is where the plaintext already is.

**2. A failed dial is its own event kind, never a denial.** `Fail` with `dial_failed`, carrying how long FatLine waited before giving up — which is what separates a refused connection from a timeout. Folding it into `Deny` would report a network outage as a policy violation and send an operator to edit a manifest that was already correct; leaving it silent, as it was, left the audit trail unable to distinguish success from never having tried.

**3. Allowed traffic is attributed per application, like denials.** The same reasoning as [ADR 0013](0013-per-application-egress-identity.md) decision 7, applied to the half that was missed: bytes nobody can attribute are telemetry, not observability. The `declared` flag stays meaningful under the split — a row exists only because FatLine allowed the connection, and FatLine allows against the calling application's own declarations, so a `false` there still means Shrike's copy of the policy has drifted from FatLine's.

**4. The monitor's picture is reached over the tunnel, on the Pod's own loopback — no new exposure.** Shrike's status listener stays bound to `127.0.0.1` with no Service and nothing the cluster can dial. FatLine's stream relay runs in that same Pod and therefore shares its loopback, so one more entry in the closed route list reaches it: an operator names a route, never an address, and the mTLS tunnel has already authenticated them.

This is the condition the original comment on that port set — *"until something reaches for it, publishing it would be new attack surface for no reader"* — being met rather than overruled. There is now a reader, and it turned out to need no publishing at all.

**5. The network half does not enter the kernel's profile store.** It is read straight from the monitor by `farcast usage` and joined in the report. Two reasons. Autopilot bills CPU and memory, so network counters are not an input to the resize [ADR 0014](0014-observed-usage.md) exists to feed. And routing them through TechnoCore would mean either giving FatLine cluster credentials — refused for the component on hostile bytes, as [ADR 0013](0013-per-application-egress-identity.md) decision D3 refused it — or giving the kernel a scrape path to a pod, which is new attack surface bought for a number nothing enforces on.

**6. Either half may be missing, and the report says which.** The two come from two places over two paths. A tunnel that is down must not cost the operator the compute half, an unreadable metrics API must not cost them the network half, and neither absence may render as a zero — the same distinction [ADR 0014](0014-observed-usage.md) decision 2 drew between "not measured" and "measured as nothing".

**7. A tunnel stream is attributed by its peer's role in the log, and by an opaque leaf token only in the monitor's picture.** *(Amended 2026-11-10, from walk finding 1 of the Phase 5 Session A walk: a keeper was refused the operator's `shrike` route and nothing could say which device.)* FatLine already holds the verified leaf where it decides on a stream, so every stream event now carries two fields:

- **`PeerRole`** — `operator` or `keeper`, from the same check that makes the `role_refused` decision, so the record and the decision cannot disagree.
- **`PeerToken`** — 16 hex characters: the first 8 bytes of SHA-256 over the label `farcast-leaf-token-v1` and the leaf's DER (`identity.LeafToken`). The label keeps it from equalling the leaf's ordinary fingerprint.

Where each goes is the decision. FatLine's own log line — and Shrike's alert line — gain **`peer_role` only**: it names a class, never a device. The token travels in process memory and over the in-Pod socket to Shrike, which keeps it in a per-peer, per-route **tunnel table** (`Snapshot.Tunnel`), served on `127.0.0.1` and read over the operator's route alone (decision 4). It is **never logged**: a stable per-device pseudonym in a provider-readable log would let the provider follow one device across its network addresses for the leaf's 90-day life, and count the fleet. The provider cannot invert the token either — the tunnel is TLS 1.3 only, so the client certificate crosses the wire encrypted, and a keeper's leaf never rests in the cloud. Only the operator's machine can name the device behind a token: `keeper enroll` records the token of every leaf it issues (`Keeper.LeafTokens`, oldest first, kept across re-enrolment and revocation because an older leaf stays valid in the cluster until its own NotAfter), and `farcast usage` maps tokens to `operator`, `keeper <device>` (marked revoked, expired, or an earlier leaf), or "leaf not enrolled from this machine".

The alert line carries nothing per leaf, its shape included. Shrike de-duplicates tunnel alerts per **role, reason and route**, never per token, so how many lines it writes and the `count` each carries depend on the role alone, not on which leaf, or how many leaves, were refused. Keyed per token, each leaf's first refusal was a new `count=1` line and its running count linked its later ones: no token on the line, and still a weaker form of the same "follow one device, count the fleet" leak. The per-leaf counts stay in the tunnel table. The table also keeps no route name a peer chose: every `unknown_route` refusal is one `(unknown route)` row per peer and one alert key per role, because that name is the peer's own text and, kept per name, let one admitted leaf grow the picture without bound. FatLine's own line records the name quoted, and cut at 64 bytes when longer.

Tunnel streams leave the application tables. They are not egress and have no application; folded in, they became the `(unidentified)` row, which is where the finding lost its device. The monitor separates them by `Proto == "stream"`, which FatLine has always set, so an older FatLine's stream lines land in the tunnel table too, with no peer. Two defects went with them: a relayed stream's bytes ride its `Allow` and were dropped (they are counted now), and a stream `dial_failed` was emitted as `Deny` against decision 2 (it is a `Fail` now).

Rejected: putting the token in the log as well, so FatLine's own record names the device when Shrike is down. That buys a convenience for the operator at the price of a provider-visible device pseudonym, and the question it answers — which device tried — is answered from the picture.

---

## Consequences

**Shrike's picture grew a per-application rollup, and its shape changed.** `Allowed` is now one row per application and host rather than per host. Nothing outside the repository read it — the endpoint had no reader until this decision — so there is no compatibility question, but there is now a published shape where there was an internal one.

**Counts are as lossy as the monitor's wire.** Shrike is fail-open and FatLine's `BufferedSink` drops events rather than block the data plane, so under a flood the byte totals under-report. That is the correct trade — security is never sacrificed for observability — and it means these numbers are a floor, not a total. FatLine logs every drop, which is where an operator sees that the floor is lower than the truth.

**A failed dial now appears in the alert stream's neighbourhood without being an alert.** It is counted per host and per application and it raises nothing. An operator looking for why an application is not working finds it in the same table as everything else, which is the point.

**A keeper enrolled before 2026-11-10 is unnamed from the operator's machine until it is re-enrolled.** The machine never kept the leaf it issued, so its token cannot be backfilled; `farcast usage` shows such a device as "keeper (leaf not enrolled from this machine)" and says that re-enrolling names it. Re-enrolment is the remedy every rotation already requires.

**Mixed versions degrade, and say so.** The event struct carries no JSON tags and the wire decodes without `DisallowUnknownFields`, so an older Shrike sidecar ignores the two new fields and keeps working. A newer Shrike beside an older FatLine still separates tunnel streams, with an empty peer the report names as "FatLine predates attribution", and reads that FatLine's stream `dial_failed`, which rode `Deny`, as the failure it is: counted, never alerted. A picture from a monitor that predates the separation lacks `tunnel_separated`, and the report annotates its `(unidentified)` row as including the operator's and keepers' streams.

**The token is in memory on provider-owned nodes.** It is held the way all of FatLine's and Shrike's in-process state is — FatLine holds the whole leaf already. The claim is that it is never written to a provider-ingested log or disk, not that it is hidden from a provider that reads node memory.

**`farcast usage` needs a tunnel for half its output.** An instance that has never been connected reports compute alone, and says so. `--no-network` skips the tunnel deliberately, so a scripted caller need not pay for it.

---

## Revisit triggers

- **Something genuinely needs request latency.** The answer is instrumentation inside the application, through the SDK, where the plaintext is — not a change here.
- **The monitor's picture gains a reader that is not the operator.** Decision 4 works because the only reader comes through the tunnel. A reader inside the cluster would need the exposure this decision avoided, and the trade would have to be made again.
- **The drop counter starts moving on a real instance.** That is the day the floor-not-a-total caveat stops being theoretical, and the buffer size or the wire becomes a decision rather than a default.

---

## Sources

- [ADR 0005 — FatLine data-plane ingress](0005-fatline-data-plane-ingress.md): the opaque CONNECT tunnel, and why the proxy does not read what it carries.
- [ADR 0013 — Per-application egress identity](0013-per-application-egress-identity.md): attribution as a security property, and why FatLine holds no cluster credential.
- [ADR 0014 — Observed usage](0014-observed-usage.md): the compute half, and the stance on inputs that can vanish.
