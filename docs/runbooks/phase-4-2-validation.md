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
  --app prover --builder-image cgr.dev/chainguard/kaniko:latest
```

Expected: a refusal that **resolves the tag, reports the digest, and explains why it will not just use it** — resolving on every build is trust-on-first-use, not pinning. Record the digest it prints:

```bash
KANIKO=<the digest-pinned reference from that output>
```

If the resolve itself fails, the registry is unreachable or the image has moved; that is a finding about the fork's location, not about FarCast.

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
  --builder-image "$KANIKO" --yes
```

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
  --app demo --builder-image "$KANIKO" --git-secret demo-git --yes
```

Expected: the clone succeeds and the credential appears **nowhere in the Job's arguments** — `kubectl -n "$NS" get job build-… -o yaml` should show it only as a `secretKeyRef`.

## 9. The kernel sees the application

```bash
kubectl -n "$NS" logs deploy/technocore --tail=3 | grep reconciled
```

Expected: `pods` includes the application, `unclassified=0`, and `rate_per_hour` risen by the app's requests (100m/128Mi ≈ `$0.0037/hour`). A `pods` count that did not move means the metering path is broken — the 4.1 failure, recurring per-namespace.

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

## Findings

*(to be filled in by the walk)*
