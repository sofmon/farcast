# Runbook — Phase 4.2 Validation: Building and Running an Application

Phase 4.2 is where FarCast stops being infrastructure and runs somebody's code. It builds an application's Containerfile **inside the instance**, translates a manifest into workloads, and confines what those workloads may reach.

Everything below was designed against fakes and rendered YAML. The claims that matter here are the ones no unit test can make:

- **Kaniko is admissible on GKE Autopilot** with the capability set [ADR 0010](../adr/0010-application-image-builds.md) grants it. The test checks membership in a documented list; admission is enforced by a webhook, and only a cluster settles it.
- **The Workload Identity push grant works as printed.** The 4.1 walk found the keyholder's equivalent grant was needed and undocumented. This one is printed and has never been run.
- **The digest really arrives through the Pod's termination message.** An elegant mechanism nobody here has seen work.
- **A `RUN` step actually executes.** Every other example assembles; this is the case the whole ADR exists for.

**Read [ADR 0010](../adr/0010-application-image-builds.md) first.** Two of its consequences look like defects and are not: a build is *less* network-confined than the application it produces, and the source of a private repository is readable by the cloud provider for the life of the build.

## Prerequisites

- An instance that has completed [the Phase 4.1 runbook](phase-4-1-validation.md): installed, connected, storage deployed and unsealed, kernel deployed.
- **A valid gcloud user session** — `gcloud auth print-access-token >/dev/null` must succeed. The 4.1 walk lost several minutes and one billable cluster to discovering this after `install`.
- The repository being built must be **reachable from the cluster**. This runbook builds from the public `sofmon/farcast` checkout, so no Git credential is involved; step 8 covers the private case separately and is optional.

## 0. Set shared variables

```bash
INSTANCE=<your-instance-name>
NS=farcast-system
APPS=with-build

FARCAST_STATE="${FARCAST_CONFIG_HOME:-$HOME/Library/Application Support/farcast}"
export KUBECONFIG="$FARCAST_STATE/instances/$INSTANCE/kubeconfig.yaml"
kubectl config current-context
```

## 1. Pin the builder, by being refused

`--builder-image` must be digest-pinned. Pass a tag on purpose and read what happens:

```bash
farcast build "$INSTANCE" --repo https://github.com/sofmon/farcast.git \
  --app prover --builder-image gcr.io/kaniko-project/executor:v1.23.2
```

Expected: a refusal that **resolves the tag, reports the digest, and explains why it will not just use it** — resolving on every build is trust-on-first-use, not pinning.

If the resolve itself fails, the registry is unreachable or the image has moved; that is a finding about the image's location, not about FarCast.

Then mirror the toolchain into the instance's own registry and record it there, rather than holding a digest in a shell variable:

```bash
farcast toolchain "$INSTANCE" --builder gcr.io/kaniko-project/executor:v1.23.2 --fetcher cgr.dev/chainguard/git:latest-dev
```

It refuses both tags and prints the digest each resolves to today. Run it again with the two `…@sha256:…` references it printed. That copy is what lands in `farcast-<instance>/system/…` and in the instance's metadata. `farcast toolchain "$INSTANCE"` with no flags reports what is recorded, and every later `build` and `run` uses it when no image flag is given.

*(Corrected 2026-10-08: this step used `cgr.dev/chainguard/kaniko:latest` and told you to keep the digest in `KANIKO=`. That image no longer resolves for an anonymous puller, and the shell variable is how the 4.2 review was lost: nothing wrote it down ([the 4.3 runbook's finding 2](phase-4-3-validation.md#2-the-builder-image-was-withdrawn-seven-days-after-it-was-reviewed--and-the-review-had-not-been-written-down)). [ADR 0011](../adr/0011-build-toolchain-mirroring.md) decision 4 settles on Google's archived Kaniko, `gcr.io/kaniko-project/executor:v1.23.2`, as a named stopgap, and decision 5 says a reviewed digest is recorded, not remembered. `build` also now refuses, before resolving anything, an instance with no deployed kernel. The build is a billed Job and only the kernel counts it.)*

## 2. Grant the builder its push identity

The build pushes under its own cloud identity, and FarCast does not grant that for you — changing a repository's IAM needs permission this CLI is not required to carry. The command prints the exact grant; run it now rather than discovering a 403 at push:

```bash
PROJNUM=$(gcloud projects describe <project> --format='value(projectNumber)')
PRINCIPAL="principal://iam.googleapis.com/projects/$PROJNUM/locations/global/workloadIdentityPools/<project>.svc.id.goog/subject/ns/farcast-system/sa/farcast-builder"
gcloud artifacts repositories add-iam-policy-binding "farcast-$INSTANCE" \
  --location us-central1 --member "$PRINCIPAL" --role roles/artifactregistry.writer
```

**The grant is on the one repository, not the project.**

## 3. Build — the step that proves the whole decision

```bash
farcast build "$INSTANCE" \
  --repo https://github.com/sofmon/farcast.git \
  --app prover \
  --containerfile manifest/examples/with-build/Containerfile \
  --context manifest/examples/with-build \
  --yes
```

No `--builder-image`: the build uses the mirrored builder step 1 recorded.

While it runs, confirm the two things only a cluster can tell you:

```bash
# Admitted at all — an Autopilot rejection appears here, not in the logs.
kubectl -n "$NS" get pods -l app.kubernetes.io/name=farcast-builder
kubectl -n "$NS" describe job build-with-build-prover | tail -20
```

Expected on success: the command prints a **digest-pinned** image reference. Record it:

```bash
IMAGE=<the image line from that output>
```

Three separate claims are being tested here, and it is worth noting which failed if one does:

| Symptom | What it means |
|---|---|
| Pod never admitted, `violates PodSecurity` or an Autopilot warning | the capability set is wrong — ADR 0010's premise |
| Pod runs, fails at push with 403 | step 2's grant did not take |
| Pod succeeds, CLI reports "instead of a sha256 digest" | the termination-message mechanism does not work |
| Pod fails inside the build | Kaniko or the Containerfile — read the output the CLI printed |

## 4. Confirm the RUN step actually ran

The image is the only evidence, and it is easiest to read once the app is running (step 6). For now, confirm the build was not a no-op:

```bash
kubectl -n "$NS" logs job/build-with-build-prover --tail=30 | grep -iE "RUN|executing|Taking snapshot" | head
```

Expected: Kaniko reporting that it executed the `RUN` command. A build that only assembled would never print it.

## 5. Meter the namespace before deploying into it

*(Superseded 2026-10-08, together with step 6. Both were written before `farcast run` existed. `run` (4.3) creates the namespace, labels it, meters it, renders the workloads and applies them in one command, and it refuses an instance with no kernel before it fetches anything. Hand-rendering is no longer how an application reaches an instance, and `/tmp/render.go` below no longer works: `translate.Render` refuses an application with no egress credential ([ADR 0013](../adr/0013-per-application-egress-identity.md)), and one with no storage identity when storage is wired. `run` mints both. The two steps are kept as the 2026-09-07 walk ran them. To reach the state steps 7 and 9 expect, deploy the same application into this runbook's namespace instead:*

```bash
farcast run "$INSTANCE" github.com/sofmon/farcast \
  --manifest manifest/examples/manifest-elsewhere/farcast --namespace "$APPS"
```

*`manifest-elsewhere` is the same `prover` built from the same Containerfile. Its paths are repository-relative, which `with-build`'s `./Containerfile` is not from the repository root. `--namespace` puts it in `with-build`. Then continue at step 6's checks (`kubectl -n "$APPS" get deploy,svc,networkpolicy` onward). With storage deployed, `run` also mints `prover`'s scope and wires its storage variables, so step 6's note about storage being left unwired no longer applies.)*

Doing this *after* deploying would leave the application running, billing, and counted nowhere — which is the failure the 4.1 walk found in another form.

```bash
kubectl create namespace "$APPS"
kubectl label namespace "$APPS" app.kubernetes.io/managed-by=farcast
farcast kernel meter "$INSTANCE" "$APPS"
```

Expected: the RoleBinding and the metered list applied together, and **no kernel restart**:

```bash
kubectl -n "$NS" get rolebinding technocore -n "$APPS"
kubectl -n "$NS" get pods -l app.kubernetes.io/name=technocore   # same pod, same age
```

## 6. Deploy the translated workloads

*(Superseded 2026-10-08 — see the note at step 5. Skip to the checks after the render block.)*

There is no `farcast run` yet (4.3), so the translator's output is applied by hand — which is also the clearest way to see what it produced.

4.2 ships the translator as a package; `farcast run` is 4.3. Render its output from the checkout — this is exactly the call `run` will make:

```bash
cat > /tmp/render.go <<'GO'
package main

import (
	"fmt"
	"os"

	"github.com/sofmon/farcast/manifest/parser"
	"github.com/sofmon/farcast/planck/translate"
)

func main() {
	raw, err := os.ReadFile("manifest/examples/with-build/farcast")
	if err != nil {
		panic(err)
	}
	m, err := parser.Parse(raw)
	if err != nil {
		panic(err)
	}
	out, err := translate.Render(translate.Config{
		Manifest: *m,
		Images:   map[string]string{"prover": os.Args[1]},
		Instance: os.Args[2],
	})
	if err != nil {
		panic(err)
	}
	fmt.Print(string(out))
}
GO

# From the farcast checkout, with the digest-pinned image from step 3.
go run /tmp/render.go "$IMAGE" "$INSTANCE" > /tmp/with-build.yaml
kubectl apply -f /tmp/with-build.yaml
kubectl -n "$APPS" rollout status deploy/prover --timeout=180s
```

Storage is left unwired here (no scope is passed), so the app gets the egress proxy and no storage variables — which step 7's second probe still exercises through the keyholder's own policy.

```bash
kubectl -n "$APPS" get deploy,svc,networkpolicy
kubectl -n "$APPS" get pods
kubectl -n "$APPS" logs deploy/prover | head -3
```

Expected: `built by farcast, inside the instance` — **the file the `RUN` step created.** That is the end-to-end proof: a Containerfile with an executed build step, built in the cluster, running in the cluster.

## 7. The application is confined, and the build was not

Two policies with deliberately different strictness. Confirm both, because the difference is a stated consequence rather than an oversight.

```bash
# The application cannot reach the internet directly.
kubectl -n "$APPS" exec deploy/prover -- sh -c \
  'wget -q -T5 -O- https://example.com >/dev/null 2>&1 && echo REACHED || echo BLOCKED'
```

Expected: `BLOCKED`. An application that ignores `FARCAST_FATLINE_PROXY` does not reach the internet by another route.

```bash
# The application can reach the keyholder; a pod outside FarCast's namespaces cannot.
kubectl -n "$APPS" exec deploy/prover -- sh -c \
  'wget -q -T5 -O- https://datasphered.farcast-system.svc.cluster.local:8443 2>&1 | head -1; echo rc=$?'
kubectl -n default run probe --rm -i --restart=Never --image=alpine:3.19 -- sh -c \
  'wget -q -T5 -O- https://datasphered.farcast-system.svc.cluster.local:8443 2>&1 | head -1; echo rc=$?'
```

Expected: the app's attempt reaches TLS (a certificate error is a *success* for this test — it got there); the `default`-namespace probe times out. That is the keyholder policy: FarCast applications only.

## 8. Optional — a private repository

Only if you have a repository-scoped, read-only credential to hand. It is the case ADR 0010 accepted a real cost for.

```bash
kubectl -n "$NS" create secret generic demo-git \
  --from-literal=username=<user> --from-literal=token=<repo-scoped read-only token>
farcast build "$INSTANCE" --repo https://github.com/<you>/<private>.git \
  --app demo --git-secret demo-git --yes
```

*(Corrected 2026-10-08: `--builder-image "$KANIKO"` dropped; the mirrored builder from step 1 is used.)*

Expected: the clone succeeds and the credential appears **nowhere in the Job's arguments** — `kubectl -n "$NS" get job build-… -o yaml` should show it only as a `secretKeyRef`.

## 9. The kernel sees the application

```bash
kubectl -n "$NS" logs deploy/technocore --tail=3 | grep reconciled
```

Expected: `pods` includes the application, `unclassified=0`, and `rate_per_hour` risen by the app's requests (100m/128Mi = `$0.0050625/hour`, `$3.70/month`). A `pods` count that did not move means the metering path is broken — the 4.1 failure, recurring per-namespace. *(Corrected 2026-10-08: this read `≈ $0.0037/hour`, which was wrong. The 2026-09-07 walk measured `$0.0050625` per pod, as the results below show. Six Pods now come to 2 × 0.00759375 for FatLine with its Shrike sidecar, plus 4 × 0.0050625, which is `$0.0354/hour`. With the carrier's `$0.025/hour` overhead, expect `rate_per_hour=0.0604`.)*

## 10. Tear down

```bash
kubectl delete namespace "$APPS"
farcast release "$INSTANCE" --delete-data
```

## Success criteria

1. A tagged builder image is refused, with the digest to pin reported.
2. The build Pod is **admitted by Autopilot** with the granted capability set.
3. The build pushes successfully under the Workload Identity grant.
4. The digest arrives through the Pod's termination message and the CLI reports a pinned reference.
5. Kaniko's output shows the `RUN` step executing.
6. `kernel meter` applies the binding and the list together, without restarting the kernel.
7. The translated workloads run, and the application prints the file the `RUN` step created.
8. The application cannot reach the internet directly.
9. A pod outside FarCast's namespaces cannot reach the keyholder's data port; the application can.
10. The kernel meters the application in its new namespace.
11. *(optional)* A private repository builds, with the credential only ever a `secretKeyRef`.

## Not covered by this run

- **`farcast run`.** It is 4.3. Step 6 applies the translator's output by hand, so this walk validates the translated *workloads*, not the command that will generate them.
- **The build's own egress being narrowed.** The policy is CIDR-shaped and permits any public address on 443, which is looser than an application gets. Routing a build through FatLine is not 4.2 and is not tested here.
- **Multi-app manifests.** One application is enough to prove the mechanism; per-app attribution across several is `farcast costs` at 4.3.
- **A build that legitimately needs longer than its deadline.** The 30-minute bound is untested against a genuinely large build.

## Findings from the 2026-09-07 walk

Instance `p42`, `USD 100 / monthly`, us-central1. Scope agreed up front: criteria 1–10, teardown the same day, criterion 11 (private repository) skipped.

**All ten criteria passed — after seven defects were found and fixed.** Every one was invisible to the test suite, and four of them were in code that had been mutation-tested. The build alone took four attempts, each failing for a different reason.

### The build's egress policy blocked DNS — twice, in two packages

The policy excludes link-local so a hostile Containerfile cannot reach the cloud metadata server. **GKE Autopilot runs NodeLocal DNSCache, which listens on a link-local address.** The build died with `lookup github.com: i/o timeout`, which reads like a network outage and is a policy.

The same bug was in [`planck/translate`](../../planck/README.md), for applications, and it made a *different* criterion unreadable: with DNS broken, "blocked from the internet" and "cannot resolve" look identical, so the egress test proved nothing until DNS worked. Both now allow exactly `169.254.20.10/32` on port 53.

### Denying the metadata server and granting the push are the same channel

After DNS was fixed the build cloned, resolved its Containerfile, ran, and failed at push with `Unauthenticated request`. The builder pushes under Workload Identity, and a Workload Identity token is minted by asking the metadata server — the address the policy was blocking to stop a hostile Containerfile stealing credentials.

**These cannot both hold.** The code comment claiming the token "is reached over a path the kubelet provides rather than this one" was simply wrong. `169.254.169.254/32` is now reachable on port 80 and nothing else link-local is, with the concession stated: Workload Identity scopes what that address returns to *this* ServiceAccount, so a hostile Containerfile can mint a token that pushes to one repository — the capability the build already has. On a cluster without Workload Identity this would expose the node's service account and be a much worse trade.

### Kaniko's `--dockerfile` is relative to the context, not the repository

With `--context-sub-path` set, a repository-relative Containerfile path fails with `please provide a valid path to a Dockerfile` — a message that points at the flag rather than at the sub-path that changed its meaning. The manifest expresses both paths repository-relative, so [`planck/build`](../../planck/README.md) now does the translation and refuses a Containerfile outside its own context.

### Applications were pointed at a Service port that did not exist

The most consequential finding. `FARCAST_FATLINE_PROXY` named `fatline.farcast-system:3128`, and FatLine's Service publishes **only** the tunnel port. An application's sole route out resolved and connected to nothing.

The obvious fix is the dangerous one: that Service is a **public LoadBalancer** ([ADR 0005](../adr/0005-fatline-data-plane-ingress.md)), so adding the proxy port to it would put an open forward proxy on the internet. FatLine now renders a separate `fatline-egress` ClusterIP, and a test fails if the proxy port ever appears on the public Service.

This also separated two names that had been conflated: the **Service** an application connects to (`fatline-egress`) and the **pod label** its NetworkPolicy selects (`fatline`). Using one for the other yields a policy that permits nothing.

### The kernel never read the namespace list — and a redeploy erased it

Two defects in sequence, both producing the `$0` failure the 4.1 walk found.

`farcast kernel meter` wrote a correct ConfigMap and **`main.go` never assigned `Reconciler.Discover`**, so the kernel ignored it. Every unit test passed throughout: they exercise the source and the reconciler, and the gap was between `main.go` and both.

With that fixed, `kernel deploy` seeded the list from `--namespaces` alone, **silently discarding everything `kernel meter` had added**. A routine redeploy — an image bump, a changed limit — would have stopped counting every application on the instance. Deploy now seeds the union; narrowing is only ever the explicit `--remove`.

**This is the third wiring gap of the same shape in Phase 4** (the floor check ran only on the interactive path; `RenderNamespaceBinding` had no caller). The pattern is a correct component with no call site, and no unit test of either side can see it. Each now has an assertion on the call site itself.

### Two operational observations, not defects

- **`connect` can fail on a first run and succeed on retry.** It waits for the load balancer's *address*, not for it to serve, so the first dial times out against a healthy instance.
- **`farcast release` can fail on a transient token timeout, and correctly refuses to continue** — it will not delete a cluster while it cannot confirm the bucket is empty, saying so and leaving the instance intact. A re-run completed it. The right behaviour, and worth knowing that a failed teardown leaves a billing instance until you retry.
- **Granting the keyholder's bucket access after `storage deploy` costs a crash loop and a failed first unseal.** Known from 3.2; the grant should precede the deploy. The new keyholder NetworkPolicy did *not* contribute — unseal succeeded through it once the pods settled.

### Criteria results

| # | Criterion | Result |
|---|---|---|
| 1 | Tagged builder refused, digest reported | ✅ |
| 2 | Build Pod admitted by Autopilot with the granted capabilities | ✅ ADR 0010's premise holds |
| 3 | Push succeeds under Workload Identity | ✅ after the metadata-server fix |
| 4 | Digest arrives through the Pod's termination message | ✅ `@sha256:c84d3ef…` |
| 5 | Kaniko executes the `RUN` step | ✅ `Running: [/bin/sh -c mkdir -p /opt && echo …]` |
| 6 | `kernel meter` binds and lists without restarting the kernel | ✅ same pod before and after |
| 7 | The application runs and prints the file its `RUN` created | ✅ `built by farcast, inside the instance` |
| 8 | No direct internet; FatLine's proxy reachable | ✅ after the egress Service and DNS fixes |
| 9 | Keyholder admits FarCast applications, refuses outsiders | ✅ both halves |
| 10 | The kernel meters the application | ✅ `pods=6`, `rate_per_hour=0.0304` — six pods at the rate card, exactly |
| 11 | Private repository | ⏸️ skipped by decision |

**The model matched the cluster again**: 6 pods × `$0.0050625/hour` = `$0.0304`, to four decimal places.
