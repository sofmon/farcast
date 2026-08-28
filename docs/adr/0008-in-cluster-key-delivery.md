# ADR 0008 — In-Cluster Key Delivery: Sealed by Default, Unsealed by the Operator

**Status:** Proposed (2026-08-27). Unblocks Phase 3.2, which [`datasphere/README.md`](../../datasphere/README.md) explicitly froze pending this decision.

**Date:** 2026-08-27

**Relates to:** Resolves the 3.2 boundary fixed by [`datasphere/README.md`](../../datasphere/README.md) ("Key management") and its decision 6. Constrained by [ADR 0003](0003-gke-autopilot.md) (Autopilot manages and restarts nodes), [ADR 0004](0004-private-control-plane.md) (private control plane), [ADR 0005](0005-fatline-data-plane-ingress.md) (the mTLS tunnel this delivery rides) and [ADR 0007](0007-instance-owned-image-registry.md) (where the in-cluster image comes from). Serves the two pillars of [AGENTS.md](../../AGENTS.md), and is where two of its principles collide.

---

## Context

Phase 3.2 gives in-cluster applications storage through [`sdk/go/storage.go`](../../sdk/go/storage.go)'s `StorageAPI`. DataSphere encrypts above the cloud adapter, so serving that API needs the instance's keyring — and the module already fixed the invariant this decision may not break:

> **No entry of the keyring ever rests on cloud infrastructure.**

A Kubernetes `Secret` is cloud-resident storage: etcd, on the provider's machines, in their backups, reachable through their API and their legal process. A KEK there converts encryption-at-rest into encryption-at-rest-except-the-key. FatLine's server leaf in a Secret is **not** precedent — that is a rotatable *transport* key whose compromise exposes one listener's future sessions; this key **is the data**.

### The collision this ADR has to resolve rather than dodge

[AGENTS.md](../../AGENTS.md) also says *"Every FarCast instance is fully autonomous."* Autopilot manages nodes and restarts pods routinely — auto-upgrades, auto-repair, evictions, rescheduling under bin-packing. So the compliant mechanism means that after a 03:00 node upgrade, in-cluster storage is dead until a human intervenes.

That is not a gap to be engineered away. It is a theorem:

> **If a restarted pod can recover the key from cloud-resident state, by running cloud-supplied code on cloud-controlled hardware, then the cloud can compute the same function.**

Autonomous recovery therefore requires either hardware that will refuse to run that computation *for the cloud*, or an external party supplying an input the cloud does not hold. Everything below follows from which of those is available.

### The decision space

- **K1 — the keyring in a Kubernetes Secret.** The path of least resistance, and the one the invariant exists to forbid. Rejected.
- **K2 — Cloud KMS / CMEK / Cloud EKM wrapping the keyring.** Superficially attractive: with EKM the key material lives outside Google. But **every unwrap is a Google-initiated call** — EKM protects the key at rest from Google and does not stop Google *using* it, on their schedule, for a workload they control. It buys an audit trail, not sovereignty. Rejected.
- **K3 — Confidential Computing with attestation** (SEV-SNP, Confidential Space). The only candidate that could satisfy autonomy. Rejected for now on three findings, with reopening conditions recorded below.
- **K4 — Shamir-split with one share in the cloud.** A share the cloud holds plus a share the cloud can reconstruct on restart is K1 with arithmetic. Rejected.
- **K5 — an in-cluster keyholder, memory-only, unsealed by the operator over the FatLine tunnel.** Autonomy conceded and stated. **Chosen.**
- **K6 — no key in the cluster at all; app storage calls proxied through the operator's machine.** Strongest guarantee, and it makes every application's storage latency and throughput a function of a laptop's uplink. Rejected as a default; noted as the shape of the write-only successor below.

**Why K3 is rejected, precisely, because it is the one a reviewer will want.** First, Confidential Space is a **Compute Engine** product — a hardened image on a Confidential VM, not a GKE one — so adopting it abandons ADR 0003's compute model outright; and its default verifier is Google Cloud Attestation, Google's own (Intel Trust Authority is the alternative, and is available only for TDX). Second, Autopilot hands a workload no attestation device, and Google supplies and auto-upgrades the node image and kubelet **inside** the SEV boundary. Third, and decisively: even given a perfect SEV-SNP report, the launch measurement covers firmware Google supplies and updates, so the cheap defeat is a legitimate-looking firmware bump — whose failure mode is a node upgrade, *the very 03:00 event attestation was invoked to fix*. **Reopen K3 if** a managed Kubernetes offers workload attestation whose root of trust is not the same party that operates the node, or if FarCast moves to Standard node pools where the node image is the operator's to pin.

---

## Decision

**1. One in-cluster component holds key material, and only in memory.** `datasphered` — a serve mode of the existing [`datasphere/cmd/datasphere`](../../datasphere/cmd/datasphere/main.go), built and pushed by the operator's machine to the instance's own registry under the `system/` prefix ADR 0007 reserved, deployed pinned by digest. It is the only in-cluster code holding key material or storage plaintext, which preserves the module's layering rule exactly. Read-only root filesystem, no volumes of any kind (an `emptyDir` is node disk), core dumps disabled.

**2. The master keys never enter the cluster.** The operator's machine loads `keys.yaml`, derives a **per-scope** bundle locally, and pushes only that. The master KEK and — decisively — the master **name key** stay on the operator's disk. That asymmetry is the point: the module's own rotation ledger records name exposure as scope (c), *permanent and unrecoverable*, so the one key that can never be rotated is the one that must never leave.

**3. Derivation is keyed on the STORED prefix, not on a plaintext hint.** For scope `app/<deployment>/<app>` whose stored prefix is `P = T₁/T₂/T₃`, every derived value is `hkdf.Key(SHA-256, <master>, nil, "<info>"+P, 32)` — the module's pinned single-shot shape. Because `P` is visible in the object's own stored path, name recovery stays stateless and the promise that *the bucket plus the keys file reconstruct every logical name with no local state* survives. Scope-key **ids stay random** — 8 random bytes minted with the master, recorded in `keys.yaml` and carried inside the bundle, exactly as every other id in the system. Deriving the id instead would have made it a verifier for the master that anyone can compute, because `P` is public by construction; that is precisely the offline key-check oracle [`datasphere/README.md`](../../datasphere/README.md)'s key-id rule forbids (*every id is 8 random bytes — never derived from the key*). The keys are derived; the labels on them are not. **This derivation is specified here and frozen at 4.x, not at 3.2** — it must be golden-vectored and independently reproduced first, per the module's own discipline for anything that touches data at rest.

**4. Delivery is a push over the existing FatLine tunnel.** `farcast storage unseal <instance>` opens the operator's mTLS session and pushes the derived bundle. The pushing party is authenticated by a client leaf issued from the operator-held CA, which the cloud cannot mint. The bundle terminates inside `datasphered`, not in FatLine's address space — FatLine is the process on attacker-controlled bytes and ADR 0002's standing Rust candidate, and the crown jewels do not belong in it.

**5. There is no peer re-seed, and this is the line.** A replica that restarts comes back **sealed**; it does not ask a living peer for key material. Any principal an in-cluster mechanism can authenticate is a principal the cloud can forge — a projected ServiceAccount token is minted by the API server and signed by the cloud — so a network oracle that dispenses key material is *worse* than K1, because it also looks compliant. Adding seeding later is easy; removing it once applications depend on it is not.

**6. Two replicas and a PodDisruptionBudget, because they cost ~$4/month and concede nothing.** A sealed replica fails readiness, so traffic goes to a loaded one. This survives the common events — a single-pod OOM, one node's auto-repair, a rollout, an eviction under bin-packing — and does not survive a full pool walk or a zonal loss. That is a real improvement over one replica and it is not a solution; both statements belong in the record.

**7. Sealed is a first-class, documented application state — and this is the part that must not be deferred.** The SDK gains `ErrStorageSealed`, deliberately distinct from `ErrNotImplemented` (which means *this build never can*) and from `ErrObjectNotFound` (an app that read a seal as "no such object" and started over would be silent data loss by a second route), plus an optional pre-attempt `Status()` seam and readiness gating at 4.2. The mechanism above can evolve; **every application ever written against the SDK inherits this contract**, so it is fixed now.

**8. The bucket credential is not a keyring entry** and may be cloud-side. Workload Identity is the right shape — metadata-server tokens, no key at rest anywhere.

---

## Consequences

**What this buys, stated without softening.** Memory-only concedes essentially nothing to a determined Google: they run the hypervisor, guest RAM is host-addressable, live migration copies it by design, and on Autopilot they run the node OS and kubelet too. **Memory-only means protected by Google not looking.** The module that wrote *"overpromising privacy is worse than not promising it"* does not get an exemption here.

What it does buy is a different *shape* of exposure, and the shape matters. A demand for stored records reaches etcd, its backups and its snapshots, and yields **ciphertext, forever, retroactively**. Plaintext requires a prospective, targeted, contemporaneous act against a running process — different capability, different logging, different legal posture. The invariant converts a cold target into a warm one. That is worth having and it is not the same as confidentiality.

**What it costs.** In-cluster storage availability is bounded by the operator's response time. At 03:00 with a full-pool upgrade, applications get `ErrStorageSealed` until a human runs `unseal` — hours. Nothing is corrupted and nothing is lost, because a sealed store refuses rather than falls back. An application that cannot tolerate a multi-hour storage outage should not be given a promise this architecture cannot keep.

**Recovery has a floor nobody had noticed: FatLine.** Every unseal path runs through the tunnel, and FatLine today is a single replica with no PDB. The same node-upgrade window that seals storage drains FatLine too, so recovery time is bounded below by FatLine's own reschedule — and if TechnoCore's cost-limit shutdown stops it, storage cannot be unsealed at all while the instance still bills. **FatLine needs the same PDB and second replica, and 4.1 must classify both `datasphered` and FatLine last-to-die.** Fixing one without the other fixes nothing.

**Distribution is already solved and should not be reinvented.** 3.3 shipped `farcast storage key export`/`import` — passphrase-armored, merge-only — which is the tested answer for seeding a second keyring holder, and the armoring pattern the keeper bundle follows.

**The lost-laptop case is worse than it looks, and this ADR does not fix it.** The operator's machine holds *both* `keys.yaml` and `fatline/ca.key`. Losing it means the data is unrecoverable **and** the running instance is unreachable — no new client leaf can be minted to reach a keyholder that is, at that moment, holding the keyring in RAM. Data loss and instance-unreachability arrive together. A 2-of-3 backup across laptop, offline media and a third location belongs in `key export`, not here, and is recorded as follow-up.

### The keeper fleet — planned, and what it must survive

The theorem in *Context* leaves exactly one lawful automation: an external party supplying an input the cloud does not hold. A **keeper** is that party — an operator-owned device (desktop, home server, phone) running the ordinary `farcast` binary, holding a derived bundle and re-seeding a restart-sealed `datasphered` unattended. The human running `unseal` is the degenerate keeper: worst latency, best judgment. The design problem is bolting the judgment onto the automaton, and the product stance is recorded here: **running FarCast as a server requires at least two enrolled keeper devices.** The evaluated posture, as constraints any implementation must satisfy:

1. **The solicitation oracle is the finding everything else answers.** FatLine's server leaf rests in a Secret — the documented transport concession. An automaton that re-seeds whatever presents that leaf converts the concession into a channel for *soliciting* key material: automation removes the human from exactly the point where the human was the control. What keeps it defensible must be priced at this ADR's own standard. The keeper holds and pushes **only the derived bundle — precisely what an unsealed `datasphered` already holds in RAM** — so a solicited push exposes no *class* of material beyond the already-conceded memory dump. But *when* is not nothing: *Consequences* priced plaintext at a contemporaneous act against a running process, and a solicited push is receivable with a Secret read plus a listener, timed to a restart the cloud itself schedules — a materially cheaper act, and one a patient cloud can repeat after every rekey to stay continuously current. Keepers are **outbound-only** — nothing listens on a phone — so every key-material flow originates on operator hardware and leaves a ledger entry the cloud can neither reach nor erase (finding 2's backup exclusion is what makes that literally true). And every keeper carries a **reseed budget**, hard-refused beyond the expected restart cadence — one or two genuine Autopilot restarts a month — without interactive confirmation. The budget is a tripwire, not a barrier: exhaustion is the alarm, and a patient adversary stays under it, so the ledger must actually be read — `keeper status` reconciles the fleet's reseed counts against `datasphered`'s witnessed restarts and flags divergence. That is detection by audit, not a live alert, and it is named as such.
2. **Tiering is mandatory, and it is decision 2's asymmetry again.** The keeper bundle is a distinct artifact from the keyring: derived scope keys and their IDs, nothing else, held in the no-user-presence protection class a background service needs. The master KEK and the unrotatable name key are never on the keeper path — even on a device that also holds the full keyring for its own client use, that copy stays presence-gated behind a separate class. And the at-rest rule has a clause the platforms make load-bearing: **the bundle, the keeper leaf's private key and the ledger are device-bound and excluded from OS cloud backup by construction** — `ThisDeviceOnly`-class, hardware-wrapped, backup-opted-out, and on desktops outside every synced or backed-up path — because a phone's default backup pipeline would otherwise deliver the scope keys to rest on the very cloud this ADR exists to keep them off. A platform that cannot guarantee the exclusion cannot be a keeper. Recovery then splits honestly in two: a stolen device whose bundle was never read is answered *completely* by `keeper revoke` plus `storage rekey` — a header rewrite, names never exposed — while a bundle that *was* read (malware, forensic extraction) exposes content written before the rekey exactly as a cloud solicitation would, and rekey bounds the damage forward, not backward. Bundles reach keepers from the operator's machine, armored in the `key export` pattern — never through the instance, which must not become a distributor of the material it is fed.
3. **A keeper never clears a deliberate seal.** "Sealed because restarted" and "sealed because the operator said so" are distinct states, and only the first is a keeper's to remedy. The hold rests on the keepers themselves — a cloud-resident hold flag serves the adversary the seal targets — and propagates eventually; the race, a keeper that never heard the hold re-seeding, is closed by `rekey`, which changes the pinned key IDs so every stale bundle is refused. That backstop binds whoever honors the pin — a thief, a tenant, a stale honest keeper. Against a cloud that rewrites `datasphered` to ignore it, no hold can bind — and a deliberate seal aimed at the cloud is already moot, because the adversary being sealed out was holding the keys; that case belongs to the write-only successor, not the keeper.
4. **Per-device identity, least privilege.** Each keeper enrolls its own `farcast://<instance>/keeper/<device>` leaf from the operator-held CA, authorized for the reseed and status RPCs and nothing else — a keeper credential must not read storage or touch admin surfaces, and a stolen phone is revoked alone. `datasphered` pins the expected key IDs and a bundle generation (the ids are random labels, not functions of any key — decision 3 — so resting them in-cluster hands the cloud no key-check oracle at all; the online is-this-current check grants a solicitation-capable cloud nothing it lacks): a stolen leaf without a bundle cannot substitute keys, and a pre-rekey bundle is refused. That enforcement is in-cluster code and therefore binds thieves and tenants, not Google — against Google, the budget and the ledger are the controls, and this is stated rather than implied.
5. **Availability, honestly.** A mains-powered desktop keeper turns the sealed window from hours into minutes. A phone is an odds-improver, not an SLO: mobile OSes gate background execution, and a push-woken check rides Apple's or Google's push service — a contentless doorbell, in the availability path but never the key path. The window becomes *time until the first keeper is awake and FatLine is reachable*, which makes FatLine's PDB and second replica a **prerequisite** of the fleet rather than an adjacent fix, and leaves TechnoCore's cost shutdown as the one seal no keeper recovers through. Polling is also metadata: the fleet's cadence sketches which of the operator's devices are awake and from which networks, so keepers poll on coarse, jittered schedules to bound what the carrier's flow logs learn — and the doorbell is contentless but not metadata-free either: its push token ties a named Apple or Google account to keeper duty, and its timing signals seal events to the push provider, so it is a redundant nudge over the jittered poll, never the sole wake path.
6. **Two devices is also the beginning of the lost-laptop answer — and a wider surface, netted here.** A second enrolled device keeps the instance serviceable while the operator rebuilds, and one that additionally holds a presence-gated keyring copy keeps the data recoverable — the catastrophe above stops arriving all at once. The cost is symmetric and stated: each enrolled keeper is one more bundle at rest and one more solicitation endpoint, and budgets add across the fleet while refusals alarm per device — so the reconciliation in finding 1 watches the *fleet's* aggregate count, not any one device's. Minting *new* leaves still needs the CA key; distributing that remains `key export`'s follow-up, not the keeper's.
7. **Scope staleness degrades partially and safely.** Bundles are static. A keeper that missed the newest app scope re-seeds every scope it holds, and the newest app stays sealed until a fresher keeper or the operator acts — visible degradation, never corruption. The alternative, an intermediate derivation key that lets keepers derive future scopes, is rejected: it widens keeper compromise from "current scope keys, rotatable" to "all future scope keys," and it puts derivation capability on the most-stealable hardware. Static bundles keep finding 1's equivalence exact and leave decision 3's derivation tree — and its 4.x freeze — untouched.

None of this reopens decision 5. A peer is an in-cluster principal whose credentials the cloud mints; a keeper is the theorem's external party. The line holds.

### Phasing

- **3.2** — `datasphered`, the unseal push, `ErrStorageSealed` + `Status()` + readiness gating, two replicas + PDB, one scope (the instance's own). Per-scope derivation is *specified*, not frozen. The unseal message is shaped as the keeper protocol from day one — bundle, key IDs, generation, restart-seal distinguished from operator hold — so 5.4 adds a driver, not a protocol.
- **4.1** — last-to-die classification for `datasphered` **and** FatLine; FatLine's PDB and second replica, which the keeper fleet turns from an improvement into a prerequisite.
- **4.x** — per-app scopes go live; the derivation is golden-vectored, independently reproduced, and frozen.
- **5.3** — secrets ride the same keyholder as a per-prefix unwrap oracle with no DEK cache, so a rarely-read secret does not inherit bulk data's 24/7 exposure.
- **5.4** — `farcast keeper` on the desktop: a daemon mode of the same binary (no new machine dependencies), `keeper enroll`/`revoke`/`status`, per-device leaves, the reseed budget and the local ledger — under the keeper-fleet constraints above.
- **7.5** — the mobile keeper: FarSight mobile's first shippable is keeper duty — re-seed within mobile background limits, reseed notifications, an emergency seal — before any GUI ambition. Tiering demotes the keeper device from crown-jewel machine to rotatable-bundle holder, which is exactly what makes a phone eligible.

### Revisit triggers

1. A managed Kubernetes offering workload attestation rooted outside the node operator, or a move to operator-pinned node images — reopens K3 and with it autonomy.
2. A first application that genuinely cannot tolerate a sealed window — pulls the keeper fleet (5.4/7.5) forward, or forces the write-only successor.
3. **The write-only successor**, sketched independently by two designers and worth naming: wrap DEKs to a per-scope *public* key whose private half never leaves the operator, so writes need no secret in the cluster and survive 03:00 entirely. Both found the same blocker — a sealed writer cannot compute a name token — and the honest cost is spooling under random names and re-filing on unseal, during which `List` under-reports. That is a well-formed future ADR, not a change to this one.

---

## Sources

Design panel of four independent mechanisms (sovereignty-absolute, autonomy-first, minimum-shippable, red-team) with two adversarial judgements scored against the pillars and against year two. The impossibility theorem in *Context*, the K2/K3 refutations, the peer-re-seed kill shot, the stored-prefix derivation and the FatLine recovery floor each came from a different member and survived the others' attacks.

- Two pillars and the autonomy principle — [AGENTS.md](../../AGENTS.md)
- The invariant and its rotation ledger — [`datasphere/README.md`](../../datasphere/README.md)
- The tunnel, the mTLS model, the honest boundary — [`fatline/README.md`](../../fatline/README.md)
- Compute platform behaviour — [ADR 0003](0003-gke-autopilot.md)
- Where the in-cluster image comes from — [ADR 0007](0007-instance-owned-image-registry.md)
- The API this must serve — [`sdk/go/storage.go`](../../sdk/go/storage.go)

External, for the claims this ADR rejects vendors on:

- Cloud EKM — *"To use your Cloud EKM keys, Cloud EKM sends requests for cryptographic operations to your EKM"*, the K2 refutation in one sentence — https://cloud.google.com/kms/docs/ekm
- Confidential Space (Compute Engine image on a Confidential VM; Google Cloud Attestation as default verifier) — https://cloud.google.com/confidential-computing/confidential-space/docs/confidential-space-overview
- GKE Autopilot — *"Google manages your infrastructure configuration, including your nodes"*, and applies node security patches automatically — https://cloud.google.com/kubernetes-engine/docs/concepts/autopilot-overview
- Kubernetes Secrets — *"stored unencrypted in the API server's underlying data store (etcd)"* by default — https://kubernetes.io/docs/concepts/configuration/secret/
- ServiceAccount tokens via the `TokenRequest` API and projected volumes — the cluster-minted principal decision 5 refuses to trust — https://kubernetes.io/docs/concepts/security/service-accounts/
- PodDisruptionBudgets and voluntary disruptions (node drain for repair or upgrade) — decision 6's mechanism — https://kubernetes.io/docs/concepts/workloads/pods/disruptions/
- Workload Identity Federation for GKE — decision 8's *"without ... service account key files"* — https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity

---

*This ADR is a living record. Revisit it when a managed Kubernetes offers workload attestation rooted outside the node operator (reopening K3 and with it autonomy), when the first application proves it cannot tolerate a sealed window, when the keeper fleet lands (5.4/7.5) and its reseed budget meets real restart cadences, and when the write-only successor ADR is written.*
