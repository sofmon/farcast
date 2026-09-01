# ADR 0010 — Application Images Are Built Inside the Instance

**Status:** Proposed

**Date:** 2026-09-01

**Relates to:** Answers the question [ADR 0007](0007-instance-owned-image-registry.md) decision 5 deferred — *"app Containerfiles execute arbitrary `RUN` steps and do need [a builder] — that choice is deferred to its own 4.2-era decision"* — and unblocks Phase 4.2's translator. Inherits [ADR 0007](0007-instance-owned-image-registry.md)'s registry contract, image paths and digest pinning unchanged, and splits from its build anchor deliberately (decision 8). Constrained by [ADR 0003](0003-gke-autopilot.md) (what Autopilot admits), [ADR 0005](0005-fatline-data-plane-ingress.md) (deny-by-default egress) and [ADR 0008](0008-in-cluster-key-delivery.md) (what may never rest in the cloud, and the tiering principle this extends).

---

## Context

Phase 4.2 turns a `./farcast` manifest into running workloads. Every app names a `containerfile`, and something must turn that into an image.

For FarCast's own images [ADR 0007](0007-instance-owned-image-registry.md) decision 5 settled it: compile with the Go toolchain, assemble onto a digest-pinned base with a stdlib OCI client, push. No container engine. That works because a system image needs no Containerfile *execution*.

Applications break the assumption, and not incidentally:

> **Executing a `RUN` step requires a container runtime. There is no library that does it.**

So something has to give among three commitments: no new tool on the operator's machine; no app source in the cloud; any Containerfile works.

### The principle that decides it

The operator's requirement, and the reason this ADR chooses as it does:

> *"I would be able to access it from multiple machines / locations and have the same capabilities. If maintaining the farcast deployed software is connected to specific machine setup, it makes the sovereign idea weak, as I would always be dependent on a well-prepared machine."*

This is not a convenience argument. **Sovereignty means the instance is the anchor, not one laptop.** A design where a dead or unprepared machine strands a running deployment has moved the dependency rather than removed it — and FarCast is already heavily machine-bound (the CA key, the keyring, the credential store all live on one machine), so the pull is toward *more* of that, not less.

It is also the principle [ADR 0008](0008-in-cluster-key-delivery.md) decision 4 already adopted for keepers: a lesser device gets a lesser capability rather than being locked out. This decision extends that tiering from *recovery* to *deployment*.

### The decision space

- **D1 — a local container engine (docker/podman) when present.** Universal support, nothing new in the cluster, no source leaves the machine. Reintroduces the dependency removed on 2026-08-25; on macOS "install podman" is a Linux VM; and `farcast run` then succeeds on one machine and fails on another — the machine-binding the principle above rejects. Rejected.
- **D2 — an ephemeral builder inside the instance.** Any Containerfile works, no operator-machine toolchain, and deployment stops being machine-bound. Costs plaintext source in the cloud and a third-party builder in the path. **Chosen.**
- **D3 — assemble only; refuse `RUN`.** Adds no dependency and no cloud exposure, and is the shape FarCast already uses for its own images. Rejected on two grounds: it refuses multi-stage Containerfiles, which is most Containerfiles in existence — *including FarCast's own [`fatline/Containerfile`](../../fatline/README.md)* — and it breaks 4.3's headline command, since a repository you just fetched is precisely the case where you cannot have pre-built artifacts.
- **D4 — language-aware builders** (`ko`-style, one per language). Engine-free and excellent for Go; makes FarCast a build system with no answer for language *n+1*. Rejected as a general mechanism.

### What Autopilot actually permits — checked, not recalled

An earlier draft asserted that Autopilot's ban on privileged containers is "precisely what these builders want". That is wrong for the builder that matters, and the correction is what moved D2 from *hard* to *viable*:

- **Autopilot allows containers to run as root** — Google's stated reasoning is that 76% of containers do.
- **`SYS_CHROOT` is in the permitted capability set**, with `CHOWN`, `DAC_OVERRIDE`, `SETUID` and `SETGID`.
- **Kaniko never requests privileged mode and needs no seccomp or AppArmor relaxation**, because it creates no nested containers — it extracts layers and executes steps in its own filesystem. That is the reason it exists.
- BuildKit and `img` *do* want seccomp and AppArmor unconfined. Autopilot applies `RuntimeDefault` and permits an override, so this is not categorically blocked either — merely more privilege than the job needs.

The platform is not the obstacle. The real costs are below, argued on their merits.

---

## Decision

**1. Application images are built inside the instance, by an ephemeral Job, using Kaniko.** One Job per build, created for the build and deleted after it. Kaniko because it is the only mature builder that needs neither privileged mode nor a relaxed seccomp profile, which is what makes it admissible under [ADR 0003](0003-gke-autopilot.md) without arguing for an exception.

**2. The build never runs inside TechnoCore.** The kernel is `tier: kernel`, never stopped by a cost shutdown, and single-replica because its ledger has one writer. Running arbitrary operator build steps there would mean an OOM during a build kills the cost meter, a runaway build is executed *by* the component whose job is to catch runaway spending, and the kernel's deliberately tiny RBAC grows the ability to create pods and hold registry credentials. TechnoCore meters the build Job like any other workload and does nothing else with it.

**3. The instance fetches the source, with a per-repository read-only deploy key.** Not the operator's Git credential: a deploy key is repo-scoped, read-only and individually revocable, so what the cloud provider can read is one repository it is about to build anyway. The operator's personal credential never enters the instance.

**4. The deploy key lives in a Kubernetes Secret, not in DataSphere.** This is the FatLine-server-leaf case, not the keyring case — a rotatable, scoped credential whose compromise exposes one repository. Putting it in DataSphere would make **builds inherit the seal**: after a 03:00 node upgrade nothing could be built until a human unsealed storage, spreading [ADR 0008](0008-in-cluster-key-delivery.md)'s accepted cost into a new place for no gain in secrecy.

**5. Egress to the Git host is an explicit, narrow, instance-level allowance.** [ADR 0005](0005-fatline-data-plane-ingress.md) denies egress by default and the build Job is not exempt. The allowance is instance configuration rather than an app's `external:` list, because it belongs to the *build*, not to the application — an app that must not reach the internet at runtime may still have been built from a repository that lives there.

**6. The instance reads the manifest and reports it; the operator device approves. This makes the review stronger and the audit trail weaker, and those are different things.**

An earlier draft called this "weakening the approval gate". That was imprecise, and the distinction matters enough to record:

- **Against a hostile repository** — which is what the gate actually exists for; 4.3 reviews *external service declarations*, a supply-chain control — the instance is the better reviewer, and becomes dramatically better once [Shrike](../../shrike/README.md) can read the source it is about to build: a diff against the running version, dependency changes, declarations that moved. A laptop squinting at a `./farcast` file cannot compete with that. The instance-side review is a **strict improvement**.
- **Against a hostile instance**, the gate was never the control. A compromised instance deploys what it likes regardless of what it reports, so almost nothing is lost by having it do the reporting too.
- **What is genuinely lost is auditability, not prevention**: an operator device that cannot reach the repository can no longer independently establish what is running. The build therefore reports the resolved **commit SHA** and a **digest of the manifest it parsed**, both recorded locally and both checkable out of band by any device that *can* reach the repo. For a device that cannot, it remains a trust assertion — and that residue is a knowledge property, not a safety one.

**7. The registry contract is unchanged.** Images land in `app/<deployment>/<app>` ([ADR 0007](0007-instance-owned-image-registry.md) decision 6), are pushed by the builder under a dedicated ServiceAccount with a repo-scoped Workload Identity grant — the shape [ADR 0008](0008-in-cluster-key-delivery.md) decision 8 uses for the keyholder's bucket — and are deployed pinned by digest.

**8. System images keep the operator-machine anchor; only application images move.** [ADR 0007](0007-instance-owned-image-registry.md) calls the operator's machine "FarCast's sovereign build anchor", and that stays true for FarCast's own code: `fatline`, `datasphered` and `technocore` are still compiled and assembled locally, from Git, with no engine. The split is deliberate — FarCast's own binaries are what the operator must be able to verify independently of the cloud, while an application's image is the operator's own code, which the cloud is about to run in plaintext regardless. A reader who notices the two anchors should find the reason here.

**9. This buys deployment portability, not administration portability, and the difference is not a gap to be closed later.** [ADR 0008](0008-in-cluster-key-delivery.md)'s impossibility theorem is untouched: the keyring and the CA private key can never rest in the cloud, so `storage unseal`, `key rotate` and the CA operations still require the operator's real machine or an exported keyring. What this decision makes machine-independent is *running and updating applications*. Claiming more than that would be the overstatement this project treats as worse than not promising at all.

**10. Kaniko was archived by Google in June 2025 and continues as a Chainguard fork; the instance runs a digest-pinned reference to it.** A project that counts its 31 vendored modules as a security property does not get to adopt an unmaintained builder quietly. The image is pinned by digest like every other third-party base ([ADR 0007](0007-instance-owned-image-registry.md) decision 7), bumps are deliberate reviewed commits, and decision 11 records what replaces it.

---

## Consequences

**A private repository's source is readable by the cloud provider for the life of the build, and its deploy key for as long as it exists.** The deploy key is the sharper of the two: it grants read access to *future* commits, not only the tree being built. Read-only and repo-scoped bounds the damage; it does not eliminate it. An operator for whom this is unacceptable should keep that repository's builds off FarCast, and that sentence belongs in the documentation rather than in a footnote.

**Ephemerality is a smaller protection than it appears.** A build pod's filesystem lives on a node disk the provider can snapshot, and the provider has full access for the duration of the build regardless. What ephemerality buys is a bounded *window*, not bounded *access* — and for an interpreted application the image in Artifact Registry contains the source permanently anyway, so the marginal disclosure is near zero. The honest claim is "shorter exposure", not "no exposure".

**Builds cost money and are metered like anything else.** A build Job is a Pod with requests, so [ADR 0009](0009-technocore-kernel-and-cost-metering.md)'s meter sees it and attributes it. A runaway build is contained by the same limit as a runaway application — which is the correct outcome, and only holds because decision 2 kept the builder out of the kernel.

**It opens a door [Shrike](../../shrike/README.md) cannot otherwise reach, and that door is the point rather than a side effect.** With the source inside the instance, Shrike — using [AllThing](../../allthing/README.md) — can analyse what is about to be deployed and report what changed since the running version, instead of only watching what already talks on the network. An instance that reviews better than the machine connecting to it is the shape this decision is aiming at: capability accumulating in the instance rather than in whichever laptop is to hand. It is recorded as the opportunity that justifies decision 6's trade, and still not as a commitment — code analysis that produces meaningful signal is hard and unproven, and nothing before 4.4 depends on it arriving.

## Phasing

- **4.2** — the build Job, the deploy-key Secret, the egress allowance, the Workload Identity push grant, and the manifest/commit reporting of decision 6.
- **4.3** — `farcast run github.com/user/repo` drives it end to end; the approval gate displays the commit SHA and manifest digest alongside the external declarations.
- **4.4+** — Shrike may consume the fetched source; nothing before then depends on it.

## Revisit triggers

1. **A maintained, first-party in-cluster builder appearing.** Kaniko's archival is this decision's weakest link, and a supported replacement is a straight substitution — decision 1's reasoning is about privilege requirements, not about Kaniko specifically.
2. **An operator who needs a repository the cloud must never read.** The answer is not a smaller build sandbox; it is the machine-anchored path this ADR rejected, offered as an option rather than the default.
3. **Thin-device storage.** This ADR makes deployment machine-independent and leaves `farcast storage` requiring the keyring locally, because it encrypts client-side. Routing it through the keyholder is a planned follow-up ADR (recorded at [PLAN.md](../../PLAN.md) 5.4) and is what completes the same-capability-from-any-device goal without putting the unrotatable name key on a phone.
4. **Unattended deploys** — an instance pulling its own updates on a push. That bypasses decision 6's approval gate entirely and is a separate decision, not an extension of this one.

---

## Sources

[ADR 0007](0007-instance-owned-image-registry.md) decision 5's explicit deferral (which this answers) and decisions 6–7 (which it inherits); [ADR 0003](0003-gke-autopilot.md) and Google's Autopilot security documentation, checked rather than recalled, for what the platform admits; [ADR 0005](0005-fatline-data-plane-ingress.md)'s deny-by-default egress; [ADR 0008](0008-in-cluster-key-delivery.md) decision 4's tiering principle, which this extends from recovery to deployment, and its impossibility theorem, which decision 9 declines to overstate against. The deciding argument is the operator's, recorded verbatim in *Context*.
