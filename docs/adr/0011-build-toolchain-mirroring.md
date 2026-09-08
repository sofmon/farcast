# ADR 0011 — The Instance Mirrors Its Build Toolchain, and Its Builder Is a Stopgap

**Status:** Accepted

**Date:** 2026-09-08

**Relates to:** Supersedes [ADR 0010](0010-application-image-builds.md) decision 10's *choice of image* while keeping every word of its reasoning; extends [ADR 0007](0007-instance-owned-image-registry.md)'s instance-owned registry to third-party images. Triggered by ADR 0010's own revisit trigger 1, firing in the opposite direction to the one anticipated.

---

## Context

[ADR 0010](0010-application-image-builds.md) decision 10 pinned the application builder to `cgr.dev/chainguard/kaniko`, the maintained fork of the Kaniko project Google archived in June 2025. It called that "this decision's weakest link" and wrote a revisit trigger for a maintained replacement appearing.

**Seven days later the link broke, in the direction nobody wrote a trigger for.** The Phase 4.2 walk on 2026-09-01 reviewed a digest for that image and built with it. The Phase 4.3 walk on 2026-09-08 found:

- `cgr.dev/chainguard/kaniko` returns an **empty tag list** to an anonymous puller.
- `chainguard/kaniko` on Docker Hub returns **401**.
- Chainguard's own directory page now shows the image as `cgr.dev/ORGANIZATION/kaniko` — org-scoped and authenticated — under their EmeritOSS programme, which exists *because* upstream is archived.

The fetcher was unaffected: `chainguard/git:latest-dev` is still public on both registries. This was a per-image catalogue decision, not a general withdrawal.

### The second failure, which is ours

Pulling **by digest** survives Chainguard's tier changes. The 4.2 walk had a reviewed digest and could have kept using it — except that nothing recorded it. Both runbooks said *"record the digest it prints"* into a shell variable, and no commit, no metadata file and no ADR carried it. The review happened, was never written down, and died with the session that performed it.

[ADR 0010](0010-application-image-builds.md) decision 10 asked for "a recorded constant". It was not one. That is the more embarrassing of the two findings, because it was entirely within this project's control.

### Two problems, not one

1. **Any third-party registry's availability is somebody else's policy decision.** An instance that cannot deploy because a catalogue was re-tiered is not sovereign in the sense this project means.
2. **Which builder to run**, now that the maintained fork needs an account.

They are separable, and only the first has a clean answer.

---

## Decisions

**1. Reviewed third-party images are mirrored into the instance's own registry.** `farcast toolchain <instance> --builder <ref> --fetcher <ref>` copies a digest-pinned image into `farcast-<instance>/system/<name>`, records it, and from then on the build Job pulls from the registry the cluster already has a grant for. Nothing outside the instance has to stay available. This is [ADR 0007](0007-instance-owned-image-registry.md)'s instance-owned registry doing the job it was built for, extended from FarCast's own images to the two third-party ones an instance runs.

**2. The copy preserves the digest of the manifest it copies — and for a multi-platform source that is the platform manifest, not the index.** The manifest is PUT exactly as fetched rather than re-encoded, so a mirrored image can be checked against its upstream without trusting FarCast's code. But an index is resolved to linux/amd64 first, because a cluster runs one platform and copying an index would drag in architectures nothing will pull. So verification is **two hops** — the reviewed index, its entry for this platform, then the instance — and the tooling reports both rather than implying one number covers it. An earlier draft of this claimed the digest was simply preserved; a test caught that, and the imprecision is recorded here because it is exactly the kind of overstatement this project treats as worse than not promising at all.

**3. The mirror runs on the operator's machine, so a source that needs credentials never puts them in the cluster.** This is not hypothetical tidiness: it is what makes decision 6's exit cheap. Authenticating to a registry becomes a local act, and the cluster keeps pulling from its own registry with the grant it already has — no image pull secret, no new in-cluster credential.

**4. The builder is Google's archived Kaniko, pinned and mirrored. This is a stopgap and is not a position this project is comfortable in.** `gcr.io/kaniko-project/executor:v1.23.2`, mirrored into the instance. [ADR 0010](0010-application-image-builds.md) decision 10 rejected exactly this image, and its reasoning was right: *"a project that counts its 31 vendored modules as a security property does not get to adopt an unmaintained builder quietly."* Nothing about that reasoning has changed. What changed is that the alternative it named stopped being reachable, and the remaining choices were an archived builder, a paid account, or no builder at all. Decision 6 is the obligation this creates.

**5. A reviewed digest is recorded, not remembered.** Instance metadata carries a `toolchain` block holding both images, written when they are mirrored and read by every later `farcast run`. Runbooks must stop instructing an operator to hold a digest in a shell variable — that is what lost the 4.2 review. Where a digest belongs in the repository rather than in local state, it belongs in a committed constant, as [`image.BaseImage`](../../farsight/cli/internal/image/image.go) already does for the distroless base.

**6. Moving off the archived builder is an obligation with named exits, not an aspiration.** Recorded here so that a future reader finds the options already weighed rather than starting over:

- **(a) Authenticate to Chainguard and mirror the maintained fork.** The smallest change by a wide margin, and decision 3 has already removed its architectural cost — it needs an account and a local credential, and nothing else moves. **This is the preferred exit.**
- **(b) A different maintained in-cluster builder.** Any candidate must clear the bar [ADR 0010](0010-application-image-builds.md) decision 1 set, which is not about Kaniko: it must need **neither privileged mode nor a relaxed seccomp profile**, or it is inadmissible on Autopilot ([ADR 0003](0003-gke-autopilot.md)) without arguing for an exception this project should not want. That bar is why the field was small in 2026 and is the first thing to check about any replacement, before its features.
- **(c) FarCast writes its own builder.** Honestly assessed, this is the largest of the three by an order of magnitude and should not be reached for casually. [ADR 0010](0010-application-image-builds.md) states the reason in one line: *"Executing a `RUN` step requires a container runtime. There is no library that does it."* Writing our own means implementing or vendoring a runtime — unpacking layers, namespaces, a filesystem overlay — which collides directly with the minimal-dependency stance that makes the rest of this project auditable. It is not off the table, and it is not a weekend.

---

## Consequences

**FarCast runs an unmaintained builder that holds a credential for the instance's registry.** That is the plain statement of decision 4, and mirroring does not soften it. Kaniko v1.23.2 will accumulate unpatched vulnerabilities for as long as this stands, and the builder is the one FarCast workload that executes code the operator wrote rather than code FarCast compiled.

**Mirroring bounds availability risk, not vulnerability risk.** After decision 1 an instance keeps building when a catalogue changes, a registry goes down, or an image is withdrawn. It does not keep the code inside that image current. Conflating the two would be the overstatement this project avoids, so: the archive going away tomorrow now breaks nothing, and that is *all* it buys.

**The instance registry grows a second kind of content.** It held FarCast's own compiled images; it now also holds copies of third-party ones. Both are pulled by digest and both live under `system/`. Storage is cents ([ADR 0007](0007-instance-owned-image-registry.md) decision 8), and `farcast release` deletes the repository with everything in it, unchanged.

**A mirrored image's digest is not the digest of the upstream index.** Decision 2's two-hop verification is more work for an operator than comparing one string, and any tool or document that shows only one of the two numbers is misleading.

---

## Revisit triggers

1. **A Chainguard account becoming available to this project** — that is exit (a), and it should be taken rather than deferred.
2. **A CVE in Kaniko v1.23.2.** There is no upstream fix coming; the response is to move, not to wait.
3. **A maintained builder clearing ADR 0003's admission bar.** Exit (b), and the bar is the first question, not the last.
4. **Chainguard re-tiering the `git` fetcher too.** The mechanism already handles it — mirror and move on — but it would confirm that decision 1 was the load-bearing half of this ADR rather than decision 4.

---

## Sources

The registry facts were checked live during the Phase 4.3 walk on 2026-09-08, not recalled: an empty tag list from `cgr.dev/v2/chainguard/kaniko/tags/list`, a 401 from Docker Hub, a 200 for `chainguard/git:latest-dev` on both, and Chainguard's own directory page showing the org-scoped path and the EmeritOSS designation. [ADR 0010](0010-application-image-builds.md) decisions 1 and 10 for the admission bar and the pinning rule this inherits; [ADR 0007](0007-instance-owned-image-registry.md) decisions 5–8 for the registry, its credential and its cost.
