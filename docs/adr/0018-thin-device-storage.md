# ADR 0018 — Thin-Device Storage Through the Keyholder, and Identity on the Data Path

**Status:** Accepted

**Date:** 2026-09-10

**Relates to:** The ADR [PLAN](../../PLAN.md) 5.4 promised. Builds on [ADR 0008](0008-in-cluster-key-delivery.md)'s keyholder and keeper fleet and must not weaken its solicitation-oracle analysis. Closes the revisit trigger [ADR 0017](0017-application-secrets.md) recorded — per-application identity on the keyholder's data path — because the two problems turn out to have one prerequisite. Reuses the credential class [ADR 0010](0010-application-image-builds.md) decision 4 and [ADR 0013](0013-per-application-egress-identity.md) decision 8 established. Extends [ADR 0005](0005-fatline-data-plane-ingress.md)'s closed list of relay routes by one.

---

## Context

[ADR 0010](0010-application-image-builds.md) made *deployment* independent of the operator's machine: the instance clones and builds, and the laptop holds no source. Storage is the capability that did not follow. `farcast storage` encrypts **client-side**, so a machine that wants to read or write an object needs two things the laptop has and nothing else does — the keyring in `keys.yaml`, and a cloud credential for the bucket. A second device is therefore either a full operator, carrying the CA key, the keyring and a service-account key at once, or nothing at all.

That is the lost-laptop catastrophe [ADR 0008](0008-in-cluster-key-delivery.md) named, multiplied by every device the operator wants to use. And one entry of the keyring makes it worse than a mere copy: the master **name key** cannot be rotated. `datasphere/README.md` records name exposure as scope (c), *permanent and unrecoverable* — `rekey` rewrites headers and never names. A phone that holds the master keyring and is lost has not lost a credential; it has lost the one thing nothing can take back.

Meanwhile the instance already contains a component that serves scoped storage to callers that hold no keyring: the keyholder. **Applications read and write through it today** — [the 5.3 walk](../runbooks/phase-5-3-validation.md) did both from inside a pod, and refused only a write under `secrets/` — for as long as the keyholder is unsealed; while it is sealed every call reports `ErrStorageSealed`, which is [ADR 0008](0008-in-cluster-key-delivery.md)'s accepted cost and the keeper's reason to exist. **Nothing in this ADR takes any of that away.** What it changes is who the keyholder believes it is talking to, and it reaches applications with a CA-verified TLS connection and hands them plaintext. Routing a thin device through the same component is the obvious shape, and [PLAN](../../PLAN.md) asked this ADR to settle two things about it: **what the keyholder serves to an operator leaf versus an application one, and what that does to [ADR 0008](0008-in-cluster-key-delivery.md)'s solicitation-oracle analysis.**

### The finding that joins two problems

The keyholder's data path, as shipped in 3.2 and stated plainly in `keyholder.DataTLS`, authenticates **the server only**. Callers are admitted by network position — a NetworkPolicy that limits the data port to pods labelled `tier: app` — and the scope a request names travels in a header every application is given identically. [ADR 0017](0017-application-secrets.md) drew the consequence: applications in one instance can read each other's objects, and any scheme that hands out more scope *names* without identity behind them is a label the caller chooses, not a boundary it is held to.

A thin device cannot be admitted by network position at all. It arrives from the internet, through FatLine's relay, and the only thing it can present is a leaf from the instance CA — which is exactly what an application ought to present too. **Identity on the data path is the prerequisite of thin-device storage, and it is the whole of the fix ADR 0017 asked for.** One change; two problems. That is why this ADR settles both.

### The invariant, restated with one clause added

> No entry of the keyring ever rests on cloud infrastructure — and the master name key rests on no device that does not need it.

Everything below is constrained by the second clause as much as the first.

### What a thin device is

A device that holds an mTLS leaf from the instance CA and, at most, a **keeper-class bundle** — derived scope keys and their ids, the same artifact [ADR 0008](0008-in-cluster-key-delivery.md) finding 2 lets a keeper hold, under the same rest rules. It never holds the keyring, never the CA key, and never a cloud credential. A tablet, a phone, a second laptop, a colleague's machine given narrow access.

---

## Decisions

**1. The keyholder's data path authenticates the caller, and the scope comes from the identity.** The data listener moves from `DataTLS` (server-only) to mutual TLS against the instance CA, the way the control listener already is. A leaf's URI names its role; the keyholder derives what the caller may reach from that URI and never from a header. The `X-Farcast-Scope` header stops being an authorization input — it may remain as a cross-check the keyholder refuses on mismatch, which is what `keyholder.Server.resolve` said 4.x would do: *"a request that omits it must already be a refusal — otherwise that change would be a fail-open one."*

**2. Three roles on the data path, and what each is served. A data leaf never pushes; a keeper leaf never reads.**

| Leaf URI | Control surface (seal state) | Data path | What it is served |
|---|---|---|---|
| `farcast://<i>/operator` | yes | yes | everything the keyholder holds |
| `farcast://<i>/keeper/<device>` | reseed and status only | **refused** | nothing |
| `farcast://<i>/device/<name>` | **refused** | yes | every scope the keyholder holds, including writes under `secrets/` |
| `farcast://<i>/app/<ns>/<name>` | **refused** | yes | **read and write**, its own scope only; the `secrets/` subtree read-only, as today |

The split between `keeper` and `device` is what keeps [ADR 0008](0008-in-cluster-key-delivery.md)'s oracle where it was. A stolen phone that can read storage must not be able to re-seed a sealed instance; a stolen keeper that can re-seed must not be able to read what it re-seeds. Least privilege per principal was finding 4's rule for keepers, and this extends it to the data path rather than letting one leaf accumulate both.

A `device` leaf may write under `secrets/`. The keyholder refuses application writes there today because it cannot tell who is asking ([ADR 0017](0017-application-secrets.md) decision 3); once it can, `farcast secret set` from a thin device is the same act as from the laptop, and the refusal narrows to exactly the callers it was aimed at.

**3. Two tiers for a thin device, chosen per operation and named to the operator.**

- **Tier A — served.** The device sends plaintext and receives plaintext; the keyholder encrypts and decrypts with the scope keys it holds. This is *precisely* application storage: the confidentiality is [ADR 0008](0008-in-cluster-key-delivery.md)'s *"protected by Google not looking"*, and no more. Any device with a `device` leaf can use it. It is cheap, and it is what a phone reading a report needs.

- **Tier B — relayed.** The device holds a keeper-class bundle and encrypts client-side with the scope's own keys, exactly as the laptop does. The keyholder acts as a **ciphertext relay**: it puts and gets stored objects under the scope's tokenized prefix using its Workload Identity, and never sees plaintext or a logical name. The cloud sees what it sees for laptop storage — ciphertext under opaque names — and the device holds no cloud credential. The keyholder holds the scope's name key, so it can compute the scope's stored prefix and refuse a relay that reaches outside it.

The CLI states which tier a command ran at, in the result and never only in a flag. A served read presented as a relayed one is the overpromise this project refuses; an operator choosing Tier A for something that mattered should be able to see that they did.

**4. Master-space objects stay laptop-only, by construction — not by omission.** The keyholder holds no master keys and never will ([ADR 0008](0008-in-cluster-key-delivery.md) decision 2), so objects outside every scope are unreachable from a thin device. That is the invariant working, not a gap. Operator data that should be reachable from a thin device belongs in a **scope minted for it** — an `ops/` scope, say — which places it at scope tier: its name key and KEK in the keyholder's memory, rotatable KEK, name key not. That is a real downgrade from master-space and the operator makes it per subtree, explicitly, with the CLI saying so when the scope is minted.

**5. Per-application scopes, minted rather than derived, one per application.** `farcast run` mints a scope per application at first deploy — `app/<namespace>/<name>/` — records it in `keys.yaml` before anything is deployed, and every bundle carries every scope. This is the shape 3.2 shipped for the shared `app` scope and the shape [ADR 0008](0008-in-cluster-key-delivery.md) decision 3 said derived scopes can later stand beside: minting reaches the same place (no master in the cluster, compromise bounded per scope, KEK rotatable) and adds nothing at rest, so the derivation freeze stays untouched. An application's secrets subtree moves inside its scope — `app/<ns>/<name>/secrets/<secret>`, with no second copy of the application's name, because the scope already is one — which changes only what Planck renders into `FARCAST_SECRETS_PREFIX`, since [ADR 0017](0017-application-secrets.md) decision 5 made the prefix something the platform gives and nothing derives.

**The shared `app` scope is removed rather than retired.** *(Amended 2026-09-11, at implementation.)* This decision first said it would remain, holding what was already there, with migration by `storage cp` under the operator's eye. Two things were wrong with that. A scope owns a whole subtree, so a scope owning `app/` and one owning `app/<ns>/<name>/` both claim the same keys under two different name keys — the object would exist twice with neither copy visible from the other, and `Keyring.AddScope` refuses exactly that pairing, deliberately, with four tests pinning it. The literal layout above and the shared scope could not coexist. And the clause was protecting nothing: FarCast is in development, no instance is deployed, and there is no stored object anywhere to migrate. So the shared scope is gone — a new keyring mints no scopes at all, and there is no shared application prefix for anything to be stranded under.

That leaves the one thing the shared scope existed to do ([ADR 0008](0008-in-cluster-key-delivery.md) decision 9: a prefix must have an owner before the first write). It is done better, per application: an application's scope is minted when the application is deployed, before it can write anything.

**A note on what "an application" is**, because the prefix names it twice over. An application is one entry in a manifest's `apps:` list, and the namespace is the manifest's top-level `name` — overridable with `--namespace`, and *not* derived from the repository. One repository usually owns one namespace holding several applications. So the same manifest deployed under two namespaces is two sets of applications with two sets of scopes, which do not see each other's data; and changing `--namespace` on a redeploy moves an application to a new scope, where its old data is not.

**6. An application's leaf rests in a Kubernetes Secret, and that is the transport class, not the keyring class.** It is minted by the operator's machine at `farcast run`, delivered beside the egress credential, and rotates by redeploying — [ADR 0013](0013-per-application-egress-identity.md) decision 8 and [ADR 0010](0010-application-image-builds.md) decision 4, exactly. A cloud that reads it can impersonate one application to the keyholder and read that application's scope, which the same cloud can already read from the keyholder's memory. The leaf therefore binds **neighbours, tenants and thieves, not Google**, and this ADR says so the way [ADR 0017](0017-application-secrets.md) did rather than implying a boundary against the provider. Putting the leaf in DataSphere instead would make an application's storage identity inherit the seal — an unsealed instance whose applications cannot prove who they are — for no gain in secrecy.

**7. NetworkPolicy stays, and the thin-device path is one more closed route.** The policy still limits the data port to application pods; a thin device reaches the same port through FatLine's relay under a new entry in the closed list [ADR 0005](0005-fatline-data-plane-ingress.md) fixed at deploy — the control port has been relayed this way since 3.2, the data port has not. Two independent admission controls: the network, and the identity. On a provider whose network enforces less ([ADR 0013](0013-per-application-egress-identity.md) decision 4's argument), the identity survives.

---

### Decision 1, as built (2026-09-11)

The data listener is mutual TLS against the instance CA, with no mode that requests a certificate and proceeds without one — a real handshake test refuses an unidentified peer, a keeper leaf and a leaf from a stranger CA *at the listener*, distinguishing that from a handler that merely says no. `farcast run` mints one leaf per application from the CA key and Planck renders it beside the egress credential; the SDK presents it and refuses to build a client without one, naming the missing variables rather than becoming a handshake failure that looks like an outage. The keyholder derives the caller's role from the leaf's URI, checks identity **before** decoding the key or consulting the seal state — an unidentified caller learns nothing, not even that the keyholder is sealed — and keeps the scope header as a cross-check refused on mismatch.

What decision 1 closes on its own: a caller admitted by network position alone, and a keeper leaf on the data path. What it closed for the **secrets subtree** specifically, because that layout already named its owner: an application read its own secrets and nobody else's.

### Decision 5, as built (2026-09-11)

Decision 5 followed immediately, and it makes the rest of that boundary the keys rather than a rule. `farcast run` mints `app/<ns>/<name>/` per application and records it before deploying; Planck renders each application's own scope name and secrets prefix; the SDK sends the scope as a cross-check; the keyholder derives the scope an application may reach from the namespace and name on its leaf, so **nothing an application presents reaches a neighbour's key space at all** — ordinary objects as well as secrets. Every bundle carries every scope, because a keeper re-seeds an instance rather than an application and a partial bundle would leave some applications sealed.

The path-keyed secrets check that decision 1 added is gone with it: the scope is the boundary, and a second check keyed on the path would be a second place for the rule to live and drift. What remains is the rule about the *operation* — no application creates or destroys a secret, whoever it is.

`farcast run` also hands the scopes it mints to a keyholder that is **already serving**, before the workloads exist — otherwise a new application starts, asks for storage, and gets `ErrStorageSealed` until somebody notices. It will not unseal a **sealed** one: pushing a bundle to a sealed keyholder is an unseal, the same call with the same material, and a deploy performing one as a side effect would hide a seal the operator has not seen and would clear an operator hold with a command whose subject is an application. A keyholder that cannot be reached, or that is sealed, leaves the deploy untouched and prints what to run.

Two consequences worth stating. A bundle may now carry **no** scopes, and that is a real state rather than a degenerate one: an instance with no applications has no application keys, and refusing to build that bundle would leave its keyholder permanently sealed and never ready. And a **wiped** bundle is still refused, which is a different thing from an empty one — the distinction is explicit in the type rather than inferred from a length.

ADR 0017 decisions 2, 3 and 4 are now fully superseded.

The `device` role is honoured on the listener and in authorization, so a thin device is a driver away rather than a protocol away; nothing yet issues a device leaf.

**Operational consequence.** An application deployed before its instance's keyholder was upgraded holds no leaf and is refused the moment the new keyholder starts. `farcast storage deploy` says so, and `farcast run` again is what issues the leaf.

## What this does to the solicitation-oracle analysis

[ADR 0008](0008-in-cluster-key-delivery.md) priced the concession exactly: FatLine's and the keyholder's TLS leaves rest in Secrets, so a cloud can impersonate the keyholder to whoever talks to it. It then asked, for every new flow, whether the impersonation yields a *class* of material the memory dump did not already yield. The same question, per tier and per role:

- **Tier A.** A cloud impersonating the data path to a device receives the plaintext that device writes and can feed wrong plaintext on reads. That is content rather than keys, and it is the exposure application data has had since 3.2 — the class does not widen, only its population does, by what the operator chooses to place at Tier A. Wrong plaintext on a read is the one genuinely new failure and it is stated: a served read has no client-side authentication, so Tier A trusts the keyholder for integrity as well as confidentiality. Tier B does not.
- **Tier B.** The impersonated relay receives ciphertext the cloud already holds from the bucket, and can serve wrong ciphertext that the device's AEAD refuses — `ErrIntegrity` or a foreign-object refusal, never silent. No new class in either direction. What Tier B *does* place on a device is a bundle, and the rest rules are the keeper's, verbatim: armored in transit through `Armor`, at rest 0600 under 0700, backup exclusion read back, synced folders refused, a 90-day leaf. A platform that cannot meet them cannot hold a Tier B bundle, which is why Tier B on a phone waits for 7.5's hardware-backed class.
- **The `device` leaf.** Data only. A solicitation-capable cloud gains nothing it lacked: it cannot push a bundle with it, and reading through it yields what memory already yields.
- **The `app` leaf.** Decision 6. No new class against the provider; the neighbour class closes.
- **The `keeper` leaf** is unchanged and is now refused on the data path, which it never needed.

The controls against the provider are what they were — the ledger, the budget, the boot label — and the honest sentence stands: memory-only means protected by Google not looking, at every tier that goes through the keyholder.

---

## Alternatives considered

**The full keyring on every device, via `key export`.** The mechanism exists and works. Rejected because it puts the unrotatable master name key on the most-stealable hardware, and a lost device then costs something no rotation recovers. `key export` remains the answer for a second *operator* machine — a machine that will hold the CA key too — and is not the answer for a tablet.

**Master keys in the keyholder, so it can serve everything.** [ADR 0008](0008-in-cluster-key-delivery.md)'s K1 with a different label. Rejected.

**A cloud credential on the device, direct to the bucket, with a bundle.** Achieves Tier B's confidentiality without the relay. Rejected: a service-account key on a phone is a standing credential to the provider on hardware that leaves the house, and the keeper fleet's stance is that operator devices hold no cloud credential at all. The relay gives the same guarantee with the credential staying in the cluster under Workload Identity.

**A separate storage-proxy service.** One more thing to deploy, bill and seal; the same trust as the keyholder; and the keyholder already *is* a storage proxy for applications. Rejected.

**Identity by shared secret in a header.** [ADR 0013](0013-per-application-egress-identity.md)'s D1 again: a bearer every caller sends, checkable by hash. Rejected because a CA-issued leaf is strictly better — the cloud cannot mint one — and the CA, the issuance code and the mTLS listener all already exist for the control surface. This ADR adds a role table, not a mechanism.

**Serving Tier B without a relay, by handing the device the keyholder's Workload Identity token.** A cluster-minted principal on operator hardware — the peer-re-seed argument of [ADR 0008](0008-in-cluster-key-delivery.md) decision 5 in reverse. Rejected.

---

## Consequences

**[ADR 0017](0017-application-secrets.md) decisions 2, 3 and 4 are superseded** — for the secrets subtree by decision 1, and for everything else by decision 5. An application's storage is confidential from its neighbours as well as from the cloud. With identity on the data path and a scope per application, a secret is confidential from a neighbouring application as well as from the cloud, and the listing refusal that was theatre without identity becomes enforceable with it. That ADR's revisit trigger names this one.

**[ADR 0008](0008-in-cluster-key-delivery.md) finding 4's least privilege now has a data-path half**, and its "what 5.4 shipped" note gains the observation that the keeper leaf was never admitted to the data path only because nothing was — decision 2 makes the refusal deliberate.

**Applications lose nothing.** Once unsealed they read and write their scope exactly as they do now; the change is that the scope is *theirs* rather than shared with every neighbour, and that a caller the keyholder cannot identify is refused instead of trusted by network position.

**The SDK does not change its surface.** `StorageAPI` is frozen; what changes is that the storage client presents a leaf, which is one more environment variable and one more mounted file — the same shape as `FARCAST_STORAGE_CA`. `ErrPermission` gains a case (a scope the identity does not own) and no new sentinel.

**What the cloud still sees** is the same list, per tier: at Tier A, plaintext in flight to a process it can read; at Tier B and from the laptop, ciphertext, opaque names, sizes, counts, tree shape and timing.

**Cost.** Nothing new is deployed and nothing new is billed. One relay route, one listener changing its client-auth mode, one Secret per application beside the one it already has.

---

## Phasing

- **Identity on the data path, per-application leaves, per-application scopes** — **built (2026-09-11)**, ahead of the sequencing proposed here, and it landed alone as expected: [ADR 0017](0017-application-secrets.md)'s gap is closed whether or not a thin device ever exists.
- **Tier A and `device` leaves** — with the first thin client that wants storage, which [PLAN](../../PLAN.md) puts in FarSight mobile (7.x), and equally available to a second CLI machine enrolled with `keeper enroll`'s sibling for devices.
- **Tier B** — on a desktop under the keeper's rest rules as soon as Tier A exists; on a phone with 7.5's hardware-backed bundle class.

---

## Revisit triggers

1. **Name-key rotation** (the rename sweep `datasphere/README.md` reserves) — changes what a Tier B bundle exposes when a device is lost, and would let decision 4's scope-tier downgrade become recoverable.
2. **Derived scopes frozen** ([ADR 0008](0008-in-cluster-key-delivery.md) decision 3's 4.x commitment, still open) — decision 5's minted scopes should then be re-examined, not replaced. Note that a minted scope and a derived one differ in what a lost keyring costs: a derived scope can be recomputed from the master, and a minted one cannot, so every application scope is now material that only `keys.yaml` holds.
3. **The first thin device in production** — Tier A's "wrong plaintext on a read" is priced here in the abstract; the first operator who relies on it will find out what it costs.
4. **A hardware-backed class on the desktop** — reopens the sentence in [ADR 0008](0008-in-cluster-key-delivery.md)'s 5.4 note about what a desktop cannot bind.

---

*This ADR is a living record. It settles a role table on a mechanism that already exists; when the mechanism is extended, the table is the thing to re-read.*
