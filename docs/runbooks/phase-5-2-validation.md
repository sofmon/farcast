# Phase 5.2 — Live Validation

Phase 5.2 is the first thing TechnoCore writes to a workload that is not a zero. Everything about it was designed from what could go wrong, and the unit suite proves the arithmetic converges and every gate bites under mutation. None of that is the same as watching a kernel restart somebody's application on the strength of its own inference.

Designed by [ADR 0016](../adr/0016-adaptive-resources.md), on the profiles [ADR 0014](../adr/0014-observed-usage.md) built.

**Walked 2026-09-09** against instance `p52` on GKE Autopilot in `us-central1`, released the same day. About 75 minutes of billing against a ~$77.17/month floor — roughly **$0.14**. Teardown verified independently: no clusters, forwarding rules, target pools, registries, buckets, disks or addresses remained.

The walk found **two defects that no unit test could have found**, both about the gap between what the kernel asked the cluster for and what the cluster did.

---

## Prerequisites

An instance installed, connected, toolchain mirrored, kernel deployed, and an application running — the state [the 5.1 runbook](phase-5-1-validation.md) leaves behind. Apply the builder's push grant **before** the first build; [the 4.2 runbook](phase-4-2-validation.md) says so and the 5.1b walk proved what happens otherwise. Mirroring the toolchain is [the 4.3 runbook's step 1a](phase-4-3-validation.md#1a-mirror-the-toolchain). The kernel must be deployed before the application, because `farcast run` refuses an instance without one.

Set `APPS` to the application's namespace before section 1.

Sampling is bounded by metrics-server's ~30-second refresh, not by the kernel's tick, so one pod needs about an hour to reach the threshold. This walk scaled the application to three replicas instead, which reaches it in twenty minutes and exercises the per-pod-not-summed property at the same time.

Before anything billable: `./check.sh --model` passes at the commit being walked; record the commit and the check's summary line with the results.

---

## 1. With adapting off, does it compute and change nothing?

```bash
farcast kernel deploy "$INSTANCE" --adapt=false
farcast usage "$INSTANCE"
kubectl get deploy -n "$APPS" -o custom-columns=\
'NAME:.metadata.name,CPU:.spec.template.spec.containers[0].resources.requests.cpu,ADAPTED:.metadata.annotations.farcast\.sofmon\.com/adapted-at'
```

*(Corrected 2026-10-08: this was `farcast kernel deploy "$INSTANCE"  # no --adapt`. `--adapt`, `--adapt-cooldown` and `--interval` are now recorded in the instance's metadata and carried forward by any deploy that does not name them, so leaving the flag out keeps whatever was deployed last. `--adapt=false` is what turns adapting off. The deploy result's `adapting off` line confirms it.)*

**Result: ✅.** The kernel logged `would resize, but adapting is off app=reacher from=100m/128Mi to=50m/64Mi monthly_delta=-5.5434`, and the report showed the right-sizing table with `Adapting is OFF` and the command to turn it on. **No Deployment carried an annotation and no request changed.**

Three gates were visible in that one output:

- **Tier.** `fatline` and `technocore` appear in the usage table and are **absent from right-sizing entirely** — the kernel does not size the tunnel it would be recovered through, or itself.
- **Coverage.** `hermit`, deployed later, held with *"only 37 readings so far; 120 are needed before sizing anything from them"*.
- **Step.** The target was 25m, and what it offered was 50m — one adjustment moves by at most a factor of two.

## 2. Does turning it on resize a real workload, safely?

```bash
farcast kernel deploy "$INSTANCE" --adapt --adapt-cooldown=2m
```

*(Corrected 2026-10-08: this was `--adapt` alone, with the cooldown patched onto the workload by hand. `2m` is a validation value, below the 6h default and within the 1m–720h bounds. The deploy says so, and the result's `adapting on, cooldown 2m0s` line confirms it took. Restore the default afterwards with `farcast kernel deploy "$INSTANCE" --adapt-cooldown=0`. Like `--adapt` and `--interval`, the cooldown is carried forward until a deploy names it.)*

**Result: ✅.** `reacher` went from 100m/128Mi to 50m/64Mi at 16:22:59Z. In the same patch it gained `farcast.sofmon.com/adapted-at` and `adapted-from: 100m/128Mi`. The rollout completed cleanly, all three pods came back **Running, ready, zero restarts**, and `ephemeral-storage: 1Gi` — which Autopilot injects and FarCast never set — **survived**, because the patch is a strategic merge that merges the requests map rather than replacing it.

Autopilot **admitted 50m/64Mi unchanged**. The kernel restarted and reported `usage_restored=true`: the profile survived, so the readings that justified the resize were not lost to the rollout that applied it.

The cooldown then held, with `resized recently; leaving it alone for another 2m0s`.

*(`--adapt-cooldown` was patched onto the workload by hand for this walk. `farcast kernel deploy` renders `--adapt` but neither `--adapt-cooldown` nor `--interval`, so neither is operator-configurable — a gap, recorded below.)* *(Closed 2026-10-08: `kernel deploy` takes `--adapt-cooldown D` (default 6h, 1m–720h) and `--interval D` (default 30s, 5s–5m) and records both, as it now records `--adapt` (`farsight/cli/internal/cli/kernel.go`). The command above uses the cooldown flag in place of the hand patch.)*

---

## What the walk found

### 1. A resize that restarted three healthy pods and saved nothing

The second adjustment logged:

```
resized an application app=reacher from=50m/64Mi to=25m/64Mi monthly_delta=0.0000
```

**`monthly_delta=0.0000`.** Autopilot bills a Pod for at least `BurstingMinCPUMilli`, which is **50m** — so 50m and 25m cost exactly the same $1.8478/month. The whole justification for resizing a running application is the cost pillar, and this resize had none.

Two things were wrong and both are fixed:

- **`adapt.MinCPUMilli` was 25m, below the billing floor.** A reservation under the floor costs what the floor costs and buys less headroom: it is *strictly worse* than sizing to the floor. The floor is now the billing floor, taken from `pricing` rather than typed as a guess.
- **Nothing checked that a change was worth money.** Every other bound in the package is a *ratio*, and a ratio can be large while the money is nothing. A change that would not change the bill is now refused, with the reason said out loud.

The consequence is stated rather than hidden: a workload somebody set below the floor by hand stays there, with less headroom than it could have for the same money. A rollout needs a reason the cost pillar recognises, and "free headroom" is not one.

### 2. The kernel announced a resize the cluster had already refused — and then did it again

This is the one no fixture could produce. **GKE Autopilot rewrites a below-floor request in the Deployment's own pod template**, not just in the admitted Pod. So:

1. The kernel patched `reacher` to 25m. The API server answered `200`.
2. Autopilot's admission raised it to 50m **in the stored object**.
3. The kernel logged `resized an application … to=25m/64Mi` — a change that had not happened.
4. Next tick it read 50m back, computed "should be 25m", and asked again.
5. Cooldown, repeat. **Four `resized an application` lines for one real resize.**

No outage came of it — after Autopilot's rewrite the stored spec was identical to the running one, so no new ReplicaSet was created and nothing restarted. What it produced was an endless loop of no-op writes and a log that was **not true**.

Both fixes above independently stop this instance of it. But the deeper problem was that the kernel believed itself: it treated `200` as "the workload now carries what I asked for". `SetRequests` now returns **what the cluster stored**, the report carries what was kept rather than what was requested, and a difference between the two is logged as an override naming the likely cause. That makes the whole class visible, rather than relying on having predicted this member of it.

### 3. Two defects found before the walk reached 5.2 at all

**GCP had no capacity in `us-central1`** on the first install. FarCast reported it accurately and said how to clean up — but reaching for another region would have meant every cost figure computed from the wrong rate card, silently: the mandatory limit check, the floor, the ledger, and now the saving a resize is justified by. Nothing said so. `install` now warns where the region is chosen, and `costs` carries the one-line form. The priced region stays silent, because a warning that always fires is one nobody reads.

**`connect` dialled the carrier before it forwarded.** The first connect failed on a completely healthy instance — both FatLine pods Running, the Service's endpoints populated — because `bootstrap` waits for the load balancer to *have* an address, which is all the cloud API will tell it, and the data path is programmed afterwards. It now waits up to two minutes on a bootstrap, and deliberately does not retry on `--status` or a reconnect, where a timeout is real news.

### 4. Smaller things

- **`kernel deploy` renders `--adapt` and nothing else about adapting.** `--adapt-cooldown` and `--interval` exist on the binary and cannot be set from the CLI. This walk hand-patched the workload to observe a second adjustment. *(Fixed 2026-10-08: both are `kernel deploy` flags now, and all three are recorded and carried forward, with `=0` restoring a duration's default and `--adapt=false` turning adapting off. That also fixed a defect this walk did not see: every redeploy that did not repeat `--adapt`, an image bump or a changed limit say, silently turned adapting off.)*
- **A held advice kept its `stepped` flag**, publishing "a bounded step" beside a workload nothing was going to touch. Fixed.

---

## Criteria

| # | Criterion | Result |
|---|---|---|
| 1 | With adapting off, advice is computed, published and acted on by nothing | ✅ |
| 2 | Only application-tier workloads are ever considered | ✅ — FatLine and the kernel absent from right-sizing |
| 3 | Thin coverage holds, and says what it is waiting for | ✅ |
| 4 | A real workload is resized, and the record lands with it | ✅ — annotations in the same patch |
| 5 | The application survives the rollout | ✅ — 3/3 Running, zero restarts |
| 6 | Fields FarCast never set survive the patch | ✅ — Autopilot's `ephemeral-storage` |
| 7 | The profile survives the restart that applies the resize | ✅ — `usage_restored=true` |
| 8 | The cooldown holds afterwards | ✅ |
| 9 | Adjustment converges rather than oscillating | ⚠️ **it did not** — see findings 1 and 2 |
| 10 | A resize is never made for no cost benefit | ⛔ **failed, now fixed** |
| 11 | The kernel reports what actually happened | ⛔ **failed, now fixed** |
| 12 | The fixes are verified live | ❌ **not re-walked** — found near teardown; unit-tested and mutation-tested only |

### How a re-walk checks criteria 10 and 11 — added 2026-10-08

**Neither failure can be triggered any more on a bursting Autopilot cluster.** Both needed the kernel to ask for a reservation below the billing floor. `adapt.MinCPUMilli` is now 50m and `adapt.MinMemMiB` 64Mi (`technocore/adapt/adapt.go`), at or above Autopilot's bursting floor of 50m/52Mi. So the kernel never proposes a change the floor makes free, and admission never has a below-floor request to rewrite. The two guards that would catch either, the refusal of a change that does not move the bill and the override warning when the stored reservation differs from the one asked for, are **unit-tested only**, and a live walk cannot reach them. A re-walk checks for the symptoms instead:

- **Criterion 10, a resize for no cost benefit:** across the whole walk, no `resized an application … monthly_delta=0.0000` line, and no step to 25m or any CPU request below 50m.
- **Criterion 11, the kernel reports what happened:** every `resized an application` line's `to=` equals the stored request, read back with `kubectl -n "$APPS" get deploy <app> -o jsonpath='{.spec.template.spec.containers[0].resources.requests}'`. No application is resized twice while its usage is steady, and no `the cluster stored a different reservation than the one asked for` warning appears.

Record them as symptoms not seen, which is weaker than a guard seen working, and say so.
