# Runbook — Phase 4.1 Validation: The Kernel and the Cost Limit

Phase 4.1 puts a controller inside the cluster whose job is to spend the operator's money more carefully than the operator would. This runbook walks that against real GKE.

Everything below was designed against fakes. The claims that matter here are the ones no unit test can make: that a hand-rolled Kubernetes client really authenticates and really lists what Autopilot is billing for, that the least-privilege RBAC is genuinely *sufficient* as well as minimal, that a real pod restart really does resume the accounting, and that a protective shutdown really stops an application while really leaving the tunnel alone.

**Read [ADR 0009](../adr/0009-technocore-kernel-and-cost-metering.md) first.** Two of its decisions are things a reviewer will otherwise file as bugs: the kernel refuses to act on a projection, and it will not stop `datasphered` or FatLine even when that leaves it unable to get back under the limit.

**One criterion cannot be met in a single sitting.** Decision 10 — reconciling the model against a real bill — needs the provider's figures to settle, which takes about a day. Step 11 is therefore a *second session*, and the instance has to stay up in between. Everything else completes in one walk.

## Prerequisites

- An instance that has completed [the Phase 3.2 runbook](phase-3-2-validation.md): installed, connected, with storage deployed and unsealed. The kernel does not need storage, but an instance carrying it is the one whose floor this phase is about.
- `farcast connect <instance>` reports a working tunnel. The kernel does not use it — it talks to the API server directly — but `kernel deploy` refuses an unconnected instance, because a cost enforcer with nothing to enforce against is a standing charge for nothing.
- A farcast checkout, so the CLI can compile and push the kernel image if the instance registry does not have it yet.
- **A valid gcloud user session**, checked *before* provisioning anything: `gcloud auth print-access-token >/dev/null` must succeed. `install` itself uses the service-account key and works without one, but every later step shells to `kubectl`, whose kubeconfig authenticates through `gke-gcloud-auth-plugin` and the gcloud user session ([ADR 0004](../adr/0004-private-control-plane.md)). Discovering this after `install` means a billable cluster sitting idle while you re-authenticate.
- **The operator credential must be able to create RBAC objects in the cluster.** `roles/container.admin` covers this; a credential that can create Deployments but not ClusterRoles fails at step 2 with a `clusterroles.rbac.authorization.k8s.io is forbidden` error rather than anything about FarCast.

## 0. Set shared variables

```bash
INSTANCE=<your-instance-name>
NS=farcast-system
APPS=farcast-apps

FARCAST_STATE="${FARCAST_CONFIG_HOME:-$HOME/Library/Application Support/farcast}"
INSTANCE_DIR="$FARCAST_STATE/instances/$INSTANCE"

export KUBECONFIG="$INSTANCE_DIR/kubeconfig.yaml"
kubectl config current-context    # confirm it points at this instance's cluster
```

## 1. Create the namespace the kernel will meter

There is no `farcast run` yet (4.3), so the application namespace Planck will create at 4.2 is made by hand here. It must exist **before** the kernel is deployed: `kernel deploy` renders a RoleBinding into every metered namespace, and a RoleBinding for a namespace that does not exist is rejected by the API server.

```bash
kubectl create namespace "$APPS"
kubectl label namespace "$APPS" app.kubernetes.io/managed-by=farcast
```

## 2. See the floor check, then deploy the kernel

```bash
farcast kernel deploy "$INSTANCE" --namespaces "$NS,$APPS"
```

(`farcast-system` is metered whether or not `--namespaces` names it, because every fetch and build Job runs there.)

Expected before the prompt: a breakdown of what the instance costs standing still, and — if the instance's limit is below that total — an explanation that the kernel would reach the limit before a single application ran. **The `USD 50` limit used by the earlier runbooks is below the modelled floor of about `$73`, so this warning firing is the expected result, not a problem with the instance.**

*(Corrected 2026-10-08: the floor is now about **USD 77.42/month**. It is the cluster at ~37, which is modelled and **not** metered by TechnoCore, plus four lines TechnoCore does meter: the load-balancer carrier at ~18.25, FatLine's two Pods at ~11.09 (each carries a Shrike sidecar), the keyholder pair at ~7.39 and the kernel at ~3.70. The metered part totals ~40.42. The Phase 1 runbook now installs at `USD 100`, which clears the whole floor, so **no warning is expected here**. The deploy result still prints a `floor ~USD 77.42/mo fully provisioned (estimated)` line. An instance installed at `USD 50` gets the second form of the warning, not the first: the limit "clears what TechnoCore meters … but not the modelled cluster line".)*

Confirm and let it deploy.

```bash
kubectl -n "$NS" get deploy technocore
kubectl -n "$NS" get pods -l app.kubernetes.io/name=technocore
```

## 3. The RBAC is sufficient — the kernel is actually reconciling

This is the step that catches a least-privilege grant that is minimal but wrong.

```bash
kubectl -n "$NS" logs deploy/technocore --tail=40
```

Expected: a `technocore starting` line naming the instance, the limit and the price-table date, followed by `reconciled` lines every `--interval` (default 30s; the deploy result's `interval` line says which) carrying `pods=`, `rate_per_hour=`, `overhead_per_hour=`, `carrier=`, `total=` and `level=ok`.

**A `forbidden` in these logs is the failure this step exists to find.** Check which verb was refused before changing anything — the fix is a rule in [`technocore/deploy`](../../technocore/deploy/), not a broader binding applied by hand.

**Whether a projection warning appears here depends on the limit.** The instance burns about `$0.025/hour` before any application, which projects to roughly `$18` over a month — under a `USD 100` limit, so nothing is expected yet. Step 9b provokes the warning deliberately.

*(Corrected 2026-10-08: the instance now burns about `$0.0554/hour` before any application. That is `$0.0304` for the five system Pods plus `$0.025` for the load-balancer carrier, which the kernel meters as instance overhead. It projects to roughly `$40` over a month, still under `USD 100`, so nothing is expected yet.)*

## 4. The RBAC is minimal — the grants are not cluster-wide

```bash
kubectl get clusterrolebindings -o name | grep -i technocore || echo "none — correct"
kubectl get rolebindings -A -l app.kubernetes.io/name=technocore
```

Expected: **no** ClusterRoleBinding, and one RoleBinding per metered namespace. A ClusterRoleBinding here would hand the kernel every pod in the cluster including the managed ones ADR 0003 puts out of bounds.

```bash
kubectl auth can-i list pods --as=system:serviceaccount:${NS}:technocore -n kube-system
kubectl auth can-i delete deployments --as=system:serviceaccount:${NS}:technocore -n "$APPS"
kubectl auth can-i update configmaps --as=system:serviceaccount:${NS}:technocore -n "$NS"
```

*(Corrected 2026-11-10: these read `system:serviceaccount:$NS:technocore`. In zsh, the default shell on macOS, `:t` after a bare parameter is the "tail" modifier, so in zsh the name would expand to `farcast-systemechnocore`, an account that does not exist. Every `no` check in this section would then pass whatever the RBAC said, and only the one `yes` could catch it. The recorded walk includes `yes` answers, so its result is not known to have been affected. Found while recording [the consolidated walk](phase-5-session-a.md#results--walked-2026-11-10); the braces are correct in every shell.)*

Expected: `no`, `no`, `no`. The third is the interesting one — the kernel may update its *own* ledger ConfigMap by name, and `can-i` without a resource name asks about all of them.

```bash
kubectl auth can-i update configmaps/technocore-ledger --as=system:serviceaccount:${NS}:technocore -n "$NS"
kubectl auth can-i update configmaps/technocore-confirmed --as=system:serviceaccount:${NS}:technocore -n "$NS"
```

Expected: `yes`, then **`no`**. The kernel reads the confirmations the operator pushes and can never write one — the asymmetry that stops it fabricating the input that corrects its own estimate.

## 5. The metered figures resemble reality

```bash
kubectl -n "$NS" logs deploy/technocore --tail=5 | grep reconciled
```

Cross-check `rate_per_hour` by hand: every FarCast system pod requests 100m/128Mi, which is `$0.0050625/hour` at [ADR 0003](../adr/0003-gke-autopilot.md)'s rates. With FatLine at two replicas, `datasphered` at two and the kernel at one, expect about `$0.0253/hour`.

*(Corrected 2026-10-08: two things changed. A FatLine Pod now requests **150m/192Mi**, which is FatLine's 100m/128Mi plus the Shrike sidecar's 50m/64Mi (`fatline/deploy/deploy.go`), and costs `$0.00759375/hour`. The keyholder and kernel Pods are still 100m/128Mi at `$0.0050625/hour`, so the five Pods come to 2 × 0.00759375 + 3 × 0.0050625 = **`$0.0304/hour`**. The kernel also now meters the load-balancer carrier as instance overhead at `$0.025/hour` (`technocore/pricing` `CarrierHourlyUSD`), and `rate_per_hour` includes it. So expect `rate_per_hour=0.0554` with `overhead_per_hour=0.0250 carrier=load-balancer`, while no fetch or build Job Pod is running. Those Jobs run in `farcast-system` and are metered too. `farcast costs` lists the carrier under "Instance overhead (never attributed to an application)", and it always prints a "Not metered" block: carrier data, bucket storage and operations, registry storage, and the cluster fee.)*

If the figure is a multiple of that, Autopilot is raising the pods to a higher floor than the model assumes — which is exactly the kind of thing decision 10 exists to catch, and worth recording here even though step 11 is where it gets settled.

## 6. The ledger is checkpointed

```bash
kubectl -n "$NS" get configmap technocore-ledger -o jsonpath='{.data.checkpoint\.json}' | head -c 400; echo
```

Expected: a JSON document with `"version":1`, a period covering the current month, and non-zero `hourly` buckets. The checkpoint is written every five minutes, so allow that long after step 2.

## 7. A restart resumes the accounting rather than resetting it

The failure this guards against is invisible in normal operation: a meter that resets to zero on every restart never trips the limit.

```bash
BEFORE=$(kubectl -n "$NS" get configmap technocore-ledger -o jsonpath='{.data.checkpoint\.json}')
echo "$BEFORE" | head -c 200; echo

kubectl -n "$NS" delete pod -l app.kubernetes.io/name=technocore
kubectl -n "$NS" rollout status deploy/technocore --timeout=120s
kubectl -n "$NS" logs deploy/technocore --tail=20 | head -5
```

Expected: the `technocore starting` line reports `restored=true`, and the first `reconciled` line afterwards carries a `billed=` larger than the reconcile interval with `reconstructed=true` — the kernel billing the gap it slept through rather than pretending it did not happen.

## 8. Deploy something the kernel is allowed to stop

Planck will stamp this label at 4.2; here it goes on by hand. The workload is deliberately expensive relative to the system tier so the shutdown ordering is observable.

```bash
kubectl apply -f - <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: costly
  namespace: farcast-apps
  labels:
    app.kubernetes.io/name: costly
    app.kubernetes.io/managed-by: farcast
    farcast.sofmon.com/tier: app
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: costly
  template:
    metadata:
      labels:
        app.kubernetes.io/name: costly
        app.kubernetes.io/managed-by: farcast
        farcast.sofmon.com/tier: app
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: sleep
          image: registry.k8s.io/pause:3.9
          resources:
            requests:
              cpu: 500m
              memory: 512Mi
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: [ALL]
YAML
kubectl -n "$APPS" rollout status deploy/costly --timeout=180s
```

Then watch the kernel notice it:

```bash
kubectl -n "$NS" logs deploy/technocore --tail=3 | grep reconciled
```

Expected: `pods` rises by one and `rate_per_hour` rises by about `$0.0247/hour` (500m/512Mi).

## 9. An unlabelled workload is protected, not stopped

```bash
kubectl -n "$APPS" label deploy/costly farcast.sofmon.com/tier-
kubectl -n "$APPS" label pods -l app.kubernetes.io/name=costly farcast.sofmon.com/tier-
kubectl -n "$NS" logs deploy/technocore --tail=3 | grep reconciled
```

Expected: `unclassified=1`. Put the label back before continuing:

```bash
kubectl -n "$APPS" label deploy/costly farcast.sofmon.com/tier=app
kubectl -n "$APPS" label pods -l app.kubernetes.io/name=costly farcast.sofmon.com/tier=app
```

## 9b. The projection warning fires, and stops nothing

[ADR 0009](../adr/0009-technocore-kernel-and-cost-metering.md) decision 9 says warn on a projection, act only on an accrual. The two are easy to conflate in code and impossible to conflate here: set a limit the current burn rate *will* reach before the period ends, but which almost nothing has yet been spent against.

With the test application running the instance burns about `$0.05/hour`, which projects to roughly `$36` for the month. A limit of `USD 30` is therefore over on the projection and nowhere near it on the accrual.

*(Corrected 2026-10-08: with the carrier now metered and FatLine at 150m/192Mi, the instance burns about `$0.0801/hour` with the test application running: `$0.0554` standing plus `$0.0247`. A full month at that rate is roughly `$58`. The projection is what has accrued plus the rate times the hours left in the period. So `USD 30` is over on the projection only if about 16 days or more of the month remain (30 ÷ 0.0801 ≈ 375 hours). Later in the month, pick a limit below `rate_per_hour × hours left` and still well above `total`.)*

```bash
# Set cost_limit.amount to 30 in metadata.yaml, then redeploy.
"${EDITOR:-vi}" "$INSTANCE_DIR/metadata.yaml"
farcast kernel deploy "$INSTANCE" --namespaces "$NS,$APPS" --yes
kubectl -n "$NS" rollout status deploy/technocore --timeout=120s
sleep 45
kubectl -n "$NS" logs deploy/technocore --tail=20
```

Expected: `on course to exceed the limit before the period ends` with a `projected` figure above 30 and an `at` timestamp — and `level=ok` throughout.

*(Noted 2026-10-08: each redeploy in this runbook (here, in step 10 and when the limit is restored) now keeps the `--adapt`, `--adapt-cooldown` and `--interval` recorded in the instance's metadata unless it names them. The namespaces were already carried forward. This walk never sets them, so the redeploys run the defaults: adapting off, a 6h cooldown, a 30s interval. Before 2026-10-08 a redeploy that did not repeat `--adapt` silently turned adapting off, and the deploy result now prints `interval` and `adapting` lines so a carried value can be seen.)*

```bash
kubectl -n "$APPS" get deploy costly     # replicas 1 — NOT stopped
```

**A kernel that stopped anything here would be the bug this step exists to catch.**

## 10. The protective shutdown — what it stops, and what it will not

Rather than wait for real spending to reach the limit, lower the limit under what has already accrued. The kernel's recorded limit is what it enforces, so this is a redeploy.

```bash
# Read what the kernel says has accrued so far, then set a limit below it.
kubectl -n "$NS" logs deploy/technocore --tail=3 | grep reconciled
```

Edit the instance's cost limit to a value below that `total` — a few cents will do — then redeploy the kernel so it picks the new limit up. This redeploy is also where the **floor warning** appears, since any limit that low is far below the instance's own standing cost:

```bash
# metadata.yaml holds cost_limit.amount; set it to something below the accrued total.
"${EDITOR:-vi}" "$INSTANCE_DIR/metadata.yaml"
farcast kernel deploy "$INSTANCE" --namespaces "$NS,$APPS" --yes
kubectl -n "$NS" rollout status deploy/technocore --timeout=120s
sleep 60
kubectl -n "$NS" logs deploy/technocore --tail=30
```

Expected, and each of these is a separate claim:

```bash
kubectl -n "$APPS" get deploy costly                       # replicas 0 — stopped
kubectl -n "$NS" get deploy fatline                        # replicas 2 — untouched
kubectl -n "$NS" get statefulset datasphered               # replicas 2 — untouched
farcast storage state "$INSTANCE"                          # every replica still UNSEALED
```

The logs must carry `stopped to contain cost` for `costly`, and — once nothing stoppable remains — `at the instance floor` naming what is still burning and the two levers that remain.

*(Corrected 2026-10-08: the floor line's `still_burning_per_hour` now includes the carrier, so expect about `0.0554`, which is the five system Pods' `0.0304` plus `carrier_per_hour=0.0250`, with `remaining_levers` naming the carrier and the instance. The kernel takes neither lever.)*

**`storage state` is the check that matters here, and it has to be that command specifically.** `storage ls` would pass whatever happened: it runs on this machine against the recorded bucket and never touches the cluster. `storage state` reaches each keyholder replica *through the tunnel*, so it fails if the shutdown stopped either FatLine or `datasphered` — which is exactly the outcome the last-to-die classification exists to prevent.

Restore the real limit and redeploy before continuing:

```bash
"${EDITOR:-vi}" "$INSTANCE_DIR/metadata.yaml"
farcast kernel deploy "$INSTANCE" --namespaces "$NS,$APPS" --yes
kubectl -n "$APPS" scale deploy/costly --replicas=1
```

As in 9b, the redeploy carries forward whatever `--adapt`, `--adapt-cooldown` and `--interval` were recorded. Check the result's `interval` and `adapting` lines read what you expect.

## 11. Reconcile against a real bill — a second session, ≥24h later

**This is the criterion the whole cost pillar rests on, and it cannot be rushed.** Every figure in this phase — the `~$77.42` floor, `$3.70` per 100m/128Mi pod, the `~$18.25` carrier, ADR 0003's `$37` empty cluster — is modelled from a published rate card and has never been checked. *(Corrected 2026-10-08: the floor here read `$73`. That was before FatLine's Pods carried the Shrike sidecar, which adds ~$3.70, and before the carrier was priced per hour as `$0.025 × 730`, which adds ~$0.25.)*

Leave the instance running. After at least a full UTC day has passed *and* the provider's figures for that day have settled (allow another day), read the actual cost of the instance's project for that window from the billing console, then:

```bash
# --from defaults to where the last push ended, --to to today's UTC midnight.
farcast kernel confirm "$INSTANCE" --amount <the figure from the bill>
kubectl -n "$NS" logs deploy/technocore --tail=40 | grep -i confirm
```

Expected: `took in confirmed figures from the provider` with `applied=1`, `refused_by_clamp=0` and a `calibration` figure. **Record that calibration number in the findings below** — it is the measured drift between FarCast's model and Google's invoice, and it is the deliverable.

A `refused_by_clamp=1` means the model and the bill disagree by more than a factor of two. That is a finding, not a failure of this step: it means the meter is missing a billed quantity, and it reopens ADR 0009's first revisit trigger.

## 12. Tear down

```bash
kubectl delete namespace "$APPS"
farcast release "$INSTANCE" --delete-data
```

## Success criteria

1. `kernel deploy` prints the instance floor, and flags it when the limit is below it (seen at step 10's redeploy).
2. The kernel reaches the API server and reconciles on a loop — no `forbidden` in its logs.
3. No ClusterRoleBinding exists; one RoleBinding per metered namespace does.
4. The kernel cannot list pods in `kube-system`, cannot delete deployments, and cannot write `technocore-confirmed`.
5. The metered rate matches the rate card by hand to within rounding — or the divergence is recorded.
6. The ledger is checkpointed to a ConfigMap.
7. A restart reports `restored=true` and bills the gap with `reconstructed=true`.
8. A labelled application appears in the meter; removing its label makes it `unclassified` and protected.
9. A limit breach stops the application deployment.
10. The same breach leaves FatLine and `datasphered` at full replicas, and storage still serves.
11. The projection warning fires without anything being stopped (step 9b).
12. A confirmed figure from the real bill is applied, and the calibration is recorded. **Deferred by decision on the 2026-09-01 walk** — see below.

### Criteria results

| # | Criterion | Result |
|---|---|---|
| 1 | Floor printed; flagged when the limit is below it | ✅ printed at every deploy; warning fired at `USD 30` and `USD 0.005` |
| 2 | Kernel reconciles, no `forbidden` | ✅ — but see `pods=0` above: reconciling is not the same as metering |
| 3 | No ClusterRoleBinding; one RoleBinding per metered namespace | ✅ 0 and 2 |
| 4 | Cannot reach `kube-system`, delete deployments, or write confirmations | ✅ `no`, `no`, `no`; `patch deployments --subresource=scale` is `yes` and whole-object `patch deployments` is `no` |
| 5 | Metered rate matches the rate card by hand | ✅ exact: `0.0253`, then `0.0500` |
| 6 | Ledger checkpointed to a ConfigMap | ✅ with per-app attribution |
| 7 | Restart reports `restored=true` and bills the gap | ✅ `restored=true`; a 3-minute outage gave `billed=3m36.8s reconstructed=true` |
| 8 | Removing a tier label makes a workload `unclassified` and protected | ✅ `unclassified=1`, back to `0` when restored |
| 9 | A limit breach stops the application | ✅ `stopped to contain cost name=costly per_hour=0.0247` |
| 10 | FatLine and `datasphered` untouched; storage still serves | ✅ `fatline 2/2`, `datasphered` still 2, `storage state` answers through the tunnel |
| 11 | Projection warns without stopping anything | ✅ `projected=35.41 limit=30.00 at=2026-09-26`, `level=ok`, `costly replicas=1` |
| 12 | Reconcile against a real bill | ⏸️ deferred by decision — see below |

**Also observed, and not a numbered criterion:** restoring the limit to `USD 100` returned the kernel to `level=ok` and left `costly` at zero replicas. The kernel never scales anything up; restarting a stopped application is an operator decision, and nothing in the kernel can make it.

## Not covered by this run

- **Criterion 12, the reconciliation against a real bill.** Deferred deliberately: it needs the instance to stay up for a full UTC day plus about another for the provider's figures to settle, and this walk tears down the same day. Every cost figure in 4.1 — the `$73` floor, `$3.70` per pod, ADR 0003's `$37` empty cluster — therefore remains modelled and unverified, and [ADR 0009](../adr/0009-technocore-kernel-and-cost-metering.md) decision 10 stays open. Step 11 is written and ready for whenever an instance is left running long enough.

- **Per-application cost attribution across more than one app.** One workload is enough to prove the mechanism; the breakdown is `farcast costs` at 4.3.
- **A real cost breach.** Step 10 lowers the limit to meet the spending rather than waiting for spending to meet the limit. The code path is identical; the elapsed time is not.
- **A node upgrade during the walk.** The kernel's own reschedule is exercised by step 7's delete, which is the same mechanism with a shorter fuse.
- **`--enforce=false`.** The observation-only mode is unit-tested and not exercised here.
- **Concurrent kernels.** The manifest renders one replica with `Recreate`, so the ledger's optimistic-concurrency check is not reachable without editing the workload by hand.

## Findings from the 2026-09-01 walk

Instance `p41`, `USD 100 / monthly`, us-central1. Scope agreed up front: steps 1–10, teardown the same day, criterion 12 deferred.

### The floor check never ran on an unattended install

`farcast install --yes` printed no floor breakdown. That was initially read as correct — `USD 100` clears the modelled `$73.48` floor, so `warnIfBelowFloor` is silent by design. It was not correct.

The floor check was called from `printSummary`, and `printSummary` runs only inside `if !c.assumeYes` — the interactive confirmation path. So the check ran **only when a human was already watching**, and never on the unattended path, which is exactly where a limit that cannot be met would sit unnoticed for months. A CI-driven or scripted install would have been silently misconfigured.

The unit tests did not catch it because they tested `warnIfBelowFloor` itself, which was correct, rather than whether anything called it on the path that matters. That is how a correct function ends up somewhere nobody reaches.

**Fixed during the walk:** the check moved out of `printSummary` and onto every install path, before the confirmation gate and regardless of `--yes`. `TestTheFloorCheckRunsOnTheUnattendedInstallPath` asserts the call site by position, which is ugly and is the only thing that would have caught this.

### The kernel metered nothing at all — `pods=0`

The most serious finding, and it was invisible from every angle except this one. The kernel started, authenticated, reconciled on its loop with no `forbidden` anywhere, wrote its checkpoint, and reported:

```
msg=reconciled pods=0 rate_per_hour=0.0000 total=0.0000 level=ok
```

The meter selects pods by `app.kubernetes.io/managed-by=farcast`. Every manifest carried that label on the **workload** — and a controller does not copy its own labels onto the pods it creates, so no pod had it. The selector matched nothing.

The consequence is worse than a wrong number: it is a *plausible* number. The instance would have reported `$0` for its entire life. No threshold would ever cross, no projection would ever warn, no shutdown would ever fire, and every log line would look healthy. The cost pillar would have been decoratively present and functionally absent.

Both sides were individually correct and separately tested — the client sends the selector (asserted), the manifests carry `managed-by` (asserted). Nothing tested the *join*, which is the only place the bug could live. This is the same shape as the floor-check finding above, twice in one walk.

**Fixed during the walk:** `app.kubernetes.io/managed-by: farcast` added to all three system workloads' pod templates, and `TestEverySystemPodCarriesTheLabelTheKernelSelectsOn` in [`technocore/kernel`](../../technocore/kernel/) now renders each manifest, extracts the pod-template labels, and checks them against `kernel.ManagedBy` — parsing the selector rather than hard-coding it, so the two cannot drift apart again. After the fix, `pods=5`.

### The model matched the cluster exactly

With the selector fixed, the kernel reported `rate_per_hour=0.0253` for five system pods, and `0.0500` after the 500m/512Mi test application joined. This runbook predicted `$0.0253` and `+$0.0247` **before the walk**, from [ADR 0003](../adr/0003-gke-autopilot.md)'s rate card. Agreement to four decimal places.

That is not yet a verification of the *bill* — Autopilot could still charge differently from its published rates, which is what criterion 12 exists to settle. It does confirm that the meter reads the requests correctly and prices them by the card it claims to use.

### Two designed behaviours confirmed live

- **FatLine's two replicas landed on the same node.** The soft `ScheduleAnyway` topology constraint behaving as its comment predicts: Autopilot had one node that fit, so the replicas co-located rather than one sitting `Pending` forever. A hard `DoNotSchedule` would have produced the single-replica outage the constraint exists to prevent.
- **A keyholder redeploy parked instead of walking the fleet down.** Adding the `managed-by` label changed `datasphered`'s pod template, so the StatefulSet rolled — and stopped after one replica came back sealed, holding the other loaded. Exactly what [ADR 0008](../adr/0008-in-cluster-key-delivery.md)'s `updateStrategy` note says will happen. Worth knowing before any redeploy: **a pod-template change re-seals storage.**

### The walk stalled on an expired gcloud user credential

`farcast install` completed normally — it authenticates to the GKE API with the service-account key passed as `--credentials`, which is unexpired. But the kubeconfig Planck writes authenticates through `gke-gcloud-auth-plugin` ([ADR 0004](../adr/0004-private-control-plane.md)), which uses gcloud's *user* session, and that had expired:

```
ERROR: There was a problem refreshing your current auth tokens: Reauthentication failed.
```

Every step from `farcast connect` onward shells to `kubectl` and is therefore blocked until the operator runs `gcloud auth login`. This is a property of the design rather than a defect — ADR 0006 accepted an external-tooling runtime dependency deliberately — but it is worth stating in the prerequisites: **a valid gcloud user session is a precondition, and its absence surfaces several minutes and one billable cluster into the walk.**
