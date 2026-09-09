# ADR 0016 — The Kernel May Resize an Application, and Nothing Else

**Status:** Accepted

**Date:** 2026-09-09

**Relates to:** Delivers Phase 5.2, on the profiles [ADR 0014](0014-observed-usage.md) built. Changes one of [ADR 0009](0009-technocore-kernel-and-cost-metering.md)'s stated properties — that everything the kernel writes is a zero — and inherits its cost stance for the one path that can now make an instance cost more. Fires the revisit trigger [ADR 0014](0014-observed-usage.md) named for per-container attribution, and refuses it rather than guessing.

---

## Context

Every FarCast workload runs on a number somebody typed. Planck gives every application 100m/128Mi; FatLine asks for 100m/128Mi because it was written that way. [The 5.1 walk](../runbooks/phase-5-1-validation.md) measured what those numbers are worth: on a live instance every workload reserved between **four and seventy-five times** what it used.

That is what this phase exists to fix, and it is also the first time TechnoCore writes something to a workload that is not a zero. [ADR 0009](0009-technocore-kernel-and-cost-metering.md) states the property plainly — *"There is no code path that scales anything up"* — and it was load-bearing: a component that can only remove capacity cannot cause an outage by miscalculating, and cannot spend money by being wrong. Both of those stop being true here.

### What can go wrong, ranked

1. **A memory reservation set below what the process needs.** Autopilot sets limits from requests, so lowering a memory request lowers the limit and the kernel has arranged for the application to be OOM-killed. This is an outage caused by an inference.
2. **A CPU reservation set too low.** Throttling: a latency regression, recoverable, visible.
3. **A reservation raised.** Autopilot bills requests, so this spends money — the thing [AGENTS.md](../../AGENTS.md) says must never be something a command does on the way to something else.
4. **Churn.** Every resize is a rollout. A controller that re-evaluates on each tick restarts workloads for noise, and the restart's own start-up spike then looks like load.

### The decision space for horizontal scaling

PLAN 5.2 also asks for replica count based on load. The manifest declares `name`, `containerfile`, `context` and `external` — and nothing whatsoever about whether an application may correctly run twice. Scaling one to two replicas on the strength of a CPU measurement is inferring a **correctness** property from a **resource** observation, and getting it wrong corrupts data rather than costing money.

---

## Decisions

**1. CPU is a rate. Memory is a level.** A process sitting at the 95th percentile of its CPU is briefly throttled — a delay, and it recovers. A process sitting at the 95th percentile of its memory is killed one time in twenty. So CPU is sized from the observed **p95** and memory from the observed **peak**, with a larger headroom factor on memory because a day's peak is a lower bound on a week's. The asymmetry is the whole design; a package that used one statistic for both would be tidier and wrong in the direction that kills things.

**2. Only applications, for the reason a cost shutdown stops only applications.** An operator recovers an instance *through* FatLine and the key holder, and a kernel that could resize the tunnel could take away the means of fixing its own mistake. The kernel resizing itself is the same hazard with a shorter loop. `app` tier only, and an unlabelled workload is left alone — the same tie-break [ADR 0009](0009-technocore-kernel-and-cost-metering.md) made.

**3. Acting is off by default; the advice is published always.** Every other guard here is a judgement about numbers, and this one is not: an operator gets to see what the kernel would have done to *their* instance, with their workloads and their savings, before it is allowed to do it. `farcast usage` prints it whether or not it is on, and the workload carries `--adapt` as a visible argument so the answer to "may this kernel change my applications" is in the cluster rather than in whoever ran the command.

This is a weaker default than PLAN's "adjusts automatically", deliberately, for the first release. The revisit trigger is below.

**4. Four bounds, and each one is a refusal rather than an approximation.**
- **Coverage.** Nothing is sized from fewer readings than [ADR 0014](0014-observed-usage.md)'s threshold, and the advice says what it is waiting for.
- **Deadband.** A target within a quarter of the current reservation is not worth a rollout. A workload re-rolled for a 5% correction is a workload restarted for nothing.
- **Step.** One adjustment moves by at most a factor of two. A profile built on a quiet hour cannot collapse a workload in a single move, and one built on a spike cannot multiply the bill. Repeated ticks converge — measured at two to three — and a clamped step says so, because a bounded first move read as a final opinion looks like a wrong answer.
- **Floors.** An idle process still has to start. A reservation small enough to make start-up fail turns an over-provisioned application into a broken one.

**5. Cooldown, and it lives on the workload.** A resized workload is left alone long enough that the next decision rests on readings taken after the last rollout. The stamp is an annotation on the Deployment, not state in the kernel, because [ADR 0009](0009-technocore-kernel-and-cost-metering.md) decision 1 makes the cluster the registry — a restarted kernel that could not see its own last change would have no cooldown at all. A stamp nobody can parse counts as *never resized*: a typo must not freeze a reservation permanently, which is worse than one extra rollout.

**6. An increase may spend up to the limit and not past it.** The operator approved a cost limit, not an open budget. A resize that would put the instance on course to reach that limit is refused and says so. A **decrease is never gated on cost** — it is the thing that helps, and on an instance already over its limit it is the only thing that helps.

**7. Single-container pods only.** This is [ADR 0014](0014-observed-usage.md) decision 3's revisit trigger firing, and the answer is a refusal. The profile is per **pod**, so on a two-container pod nothing in it can say which container's reservation the measurement justifies. Guessing would move the wrong container's request; per-container profiling is the fix, and it is a change to the collection design rather than something to improvise inside a resize.

**8. Horizontal scaling is refused, and it is a manifest gap rather than a hard problem.** Nothing in the manifest says whether an application may run twice. Inferring that from CPU means inferring a correctness property from a resource measurement, and being wrong corrupts data. When the manifest can declare it, this becomes possible; until then a kernel that scaled replicas would be guessing about the one thing it has no evidence for.

**9. "Graceful scaling" is not achievable at one replica, and the honest form of it is decision 8.** A resize is a rollout, and every rollout of a single-replica Deployment is a gap in service. Nothing in this decision closes that. Saying so is better than a `maxSurge` setting that implies otherwise.

---

## Consequences

**The kernel now holds `patch` on deployments, and Kubernetes cannot narrow it to fields.** A grant that lets the kernel change a container's requests also lets it change that container's image. The narrowing that *is* available is applied: the binding is namespaced as it always was, and the code refuses anything that is not application-tier. The grant is asserted by a test so it cannot widen further without somebody deciding to.

**Planck and TechnoCore both write the pod template now.** A `farcast run` re-renders an application at 100m/128Mi and undoes an adaptation; the kernel re-adapts after the cooldown. It converges, at the cost of one cycle and one extra rollout. Making Planck preserve an adapted reservation is the better answer and is not in this decision.

**The advice is honest about what it will not do.** A workload with no profile, too few readings, two containers, a recent resize, or a cost gate says which, in the report. The alternative — omitting what it declined to touch — makes "nothing to do" and "not considered" identical, which is the shape of every observability defect this project has found so far.

**Two of PLAN 5.2's four bullets are refused rather than delivered**, with the reasoning recorded. That is the accurate description of the phase, and it belongs in PLAN rather than in a footnote.

---

## Revisit triggers

- **The default.** Decision 3 is a first-release stance. Once resizes have been watched on a real instance across a few cooldowns without an incident, defaulting `--adapt` on is the intended end state and matches what PLAN describes.
- **A resize needs to move one container and not another.** Decision 7 is refusing on a limitation of the profile, not of the resize. Per-container collection removes it.
- **The manifest learns to declare replication.** That is what decision 8 is waiting for, and it is a manifest-spec change rather than a kernel one.
- **Planck learns to preserve an adapted reservation.** Until then, redeploying an application resets it.

---

## Sources

- [ADR 0009 — TechnoCore kernel and cost metering](0009-technocore-kernel-and-cost-metering.md): the cluster as registry, the tier rules, and the property this decision changes.
- [ADR 0014 — Observed usage](0014-observed-usage.md): the profiles, the coverage threshold, and the per-container revisit trigger.
- [Phase 5.1 validation](../runbooks/phase-5-1-validation.md): the measured 4–75× over-reservation this phase exists to correct.
