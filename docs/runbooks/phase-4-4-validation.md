# Runbook — Phase 4.4 Validation: Per-Application Egress

Phase 4.4 makes the promise `farcast run` already shows an operator into something the enforcement point can keep. Until now it could not: the declarations never arrived, and the code that would have carried them flattened every application's list into one.

The claims that matter here are the ones no unit test can make:

- **The declarations arrive at all.** `fatline/deploy` passed no manifest before this phase, so a deployed FatLine's allowlist was empty and applications reached nothing outside the cluster. Both earlier walks passed while that was true, because the example application declares no external hosts. **This is the first time FarCast has knowingly let an application out.**
- **An application reaches what it declared.** End to end: a manifest host, through a credential, through a mounted ConfigMap, to a real TLS connection.
- **It cannot reach what another application declared.** The property PLAN 4.4 names, tested from the inside of a running pod rather than in a table.
- **The credential travels with no application change.** `FARCAST_FATLINE_PROXY` is read the same way it always was; whether Go's proxy handling really sends it on a CONNECT to a cluster Service is a claim about somebody else's library.
- **Policy reloads without restarting the boundary.** A ConfigMap change reaching a running FatLine through the kubelet, on its own schedule, with no rollout.
- **Shrike names the application.** An alert that cannot say who did it is telemetry.

**Read [ADR 0013](../adr/0013-per-application-egress-identity.md) first**, particularly *Consequences*: identity is now something an application holds rather than somewhere it sits, and that trades a property a reviewer can inspect for one that must be trusted. The ADR says so plainly and this walk does not pretend otherwise.

## Prerequisites

- An instance that has completed [the Phase 4.3 runbook](phase-4-3-validation.md): installed, connected, storage deployed and unsealed, kernel deployed, toolchain mirrored.
- **A valid gcloud user session** — `gcloud auth print-access-token >/dev/null` must succeed.
- This walk needs an application that actually *makes* an outbound request, which the `with-build` example does not. Step 1 builds one.

## 0. Set shared variables

```bash
INSTANCE=<your-instance-name>
NS=farcast-system
APPS=egress-demo

FARCAST_STATE="${FARCAST_CONFIG_HOME:-$HOME/Library/Application Support/farcast}"
export KUBECONFIG="$FARCAST_STATE/instances/$INSTANCE/kubeconfig.yaml"
kubectl config current-context
```

## 1. A manifest with two applications and different declarations

The fixture is [`manifest/examples/egress-demo`](../../manifest/examples/egress-demo/farcast): two applications, one declaring a host and one declaring none, both built from a Containerfile that sleeps so the pod stays available to `exec` into.

Deploy it:

```bash
farcast run "$INSTANCE" github.com/sofmon/farcast \
  --manifest manifest/examples/egress-demo/farcast --namespace "$APPS" -y
```

Expected: the review names **two** applications with different declarations, and the result ends with a line reading `Egress: 1 declared host across 2 applications, enforced per application.`

## 2. The policy arrived, and carries no credentials

```bash
kubectl -n "$NS" get configmap fatline-egress-policy -o jsonpath='{.data.policy\.json}' | jq .
```

Expected: one entry per application, each with its own `credential_sha256`, and **`reacher` carrying the declared host while `hermit` carries none**.

The document must contain no credential in the clear. Confirm by comparing it against what an application actually holds:

```bash
CRED=$(kubectl -n "$APPS" get secret reacher-egress -o jsonpath='{.data.FARCAST_FATLINE_PROXY}' | base64 -d)
echo "$CRED"          # http://reacher:<credential>@fatline-egress…
kubectl -n "$NS" get configmap fatline-egress-policy -o yaml | grep -c "$(echo "$CRED" | sed 's|.*:||; s|@.*||')"
```

Expected: `0`. The policy holds hashes; only the application's own Secret holds the credential.

## 3. An application reaches what it declared

```bash
kubectl -n "$APPS" exec deploy/reacher -- sh -c \
  'wget -q -T10 -O- https://example.com >/dev/null 2>&1 && echo REACHED || echo BLOCKED'
```

Expected: **`REACHED`**. This is the first outbound request FarCast has ever permitted.

If it is `BLOCKED`, read step 6 before assuming a defect — the policy may not have reached FatLine yet.

## 4. It cannot reach what it did not declare

```bash
kubectl -n "$APPS" exec deploy/reacher -- sh -c \
  'wget -q -T10 -O- https://www.wikipedia.org >/dev/null 2>&1 && echo REACHED || echo BLOCKED'
```

Expected: **`BLOCKED`**.

## 5. One application cannot use another's declarations

This is the property the phase exists for. `hermit` declares nothing, so it must not reach `example.com` even though its neighbour may:

```bash
kubectl -n "$APPS" exec deploy/hermit -- sh -c \
  'wget -q -T10 -O- https://example.com >/dev/null 2>&1 && echo REACHED || echo BLOCKED'
```

Expected: **`BLOCKED`**.

Then the sharper test — `hermit` borrowing `reacher`'s address, credential and all:

```bash
kubectl -n "$APPS" exec deploy/hermit -- sh -c \
  "https_proxy='$CRED' wget -q -T10 -O- https://example.com >/dev/null 2>&1 && echo REACHED || echo BLOCKED"
```

Expected: **`REACHED`** — and that is not a defect. [ADR 0013](../adr/0013-per-application-egress-identity.md) *Consequences* says exactly this: identity is something an application holds, so an application that obtains another's credential can use it. What the design guarantees is that it cannot obtain one by *position*; Kubernetes RBAC is what keeps one application out of another's Secret. Record the result and move on — a walk that quietly skipped its own stated weakness would be worth less than one that names it.

## 6. Policy reloads without restarting the boundary

```bash
kubectl -n "$NS" get pods -l app.kubernetes.io/name=fatline -o jsonpath='{.items[*].metadata.name}{"\n"}'
```

Note the pod names. Now add a host to `hermit` by redeploying with an edited manifest, or patch the policy directly:

```bash
kubectl -n "$NS" get configmap fatline-egress-policy -o json \
  | jq '.data["policy.json"] |= (fromjson | (.apps[] | select(.name=="hermit") | .external) |= [{"host":"example.com","reason":"runbook"}] | tojson)' \
  | kubectl apply -f -
```

Wait for the kubelet to propagate it — up to about a minute — then:

```bash
kubectl -n "$APPS" exec deploy/hermit -- sh -c \
  'wget -q -T10 -O- https://example.com >/dev/null 2>&1 && echo REACHED || echo BLOCKED'
kubectl -n "$NS" get pods -l app.kubernetes.io/name=fatline -o jsonpath='{.items[*].metadata.name}{"\n"}'
kubectl -n "$NS" logs deploy/fatline --tail=5 | grep -i "policy reloaded"
```

Expected: `REACHED`, **the same pod names**, and a log line reporting the reload. The network boundary did not restart.

## 7. Shrike names the application

```bash
kubectl -n "$NS" logs deploy/fatline --tail=50 | grep -iE "deny|violation|alert"
```

Expected: the denials from steps 4 and 5 attributed to `reacher` and `hermit` **by name**, with `not_in_allowlist` as the reason — not a single merged count, and not an anonymous "application".

## 8. An unidentified caller is its own problem

```bash
kubectl -n "$APPS" exec deploy/reacher -- sh -c \
  'https_proxy=http://fatline-egress.farcast-system.svc.cluster.local:3128 wget -q -T10 -O- https://example.com >/dev/null 2>&1 && echo REACHED || echo BLOCKED'
```

Expected: **`BLOCKED`**, and a FatLine log line with reason `unknown_app` — distinct from `not_in_allowlist`, because "I do not know who is asking" and "you may not go there" have different fixes.

## 9. Another deployment's policy survives

```bash
farcast run "$INSTANCE" github.com/sofmon/farcast \
  --manifest manifest/examples/manifest-elsewhere/farcast --namespace other-demo -y
kubectl -n "$NS" get configmap fatline-egress-policy -o jsonpath='{.data.policy\.json}' | jq '.apps[] | .namespace + "/" + .name'
kubectl -n "$APPS" exec deploy/reacher -- sh -c \
  'wget -q -T10 -O- https://example.com >/dev/null 2>&1 && echo REACHED || echo BLOCKED'
```

Expected: **all three applications** in the document, and `reacher` still `REACHED`. One FatLine serves the instance, so a second deployment must not revoke the first's egress — the same shape as the metering a redeploy erased on the 4.2 walk.

## 10. Tear down

```bash
kubectl delete namespace "$APPS" other-demo
farcast kernel meter "$INSTANCE" "$APPS" other-demo --remove
farcast release "$INSTANCE" --delete-data
```

**Confirm nothing is left billing:** the cluster, the registry, the bucket and the load-balancer carrier.

---

## Success criteria

| # | Claim | Result |
|---|-------|--------|
| 1 | `run` reports per-application egress and writes the policy | |
| 2 | The policy carries hashes and no credential in the clear | |
| 3 | An application reaches a host it declared | |
| 4 | It cannot reach a host it did not declare | |
| 5 | Another application cannot reach it by its own identity | |
| 6 | A borrowed credential does work, as the ADR says it would | |
| 7 | Policy reloads with no FatLine restart | |
| 8 | Denials name the application | |
| 9 | An unidentified caller is reported as `unknown_app` | |
| 10 | A second deployment does not revoke the first's egress | |

## Not covered by this run

- **A provider whose NetworkPolicy is weaker than Autopilot's.** The portability argument that chose a credential over a port is about EKS and AKS, and neither is walked here — 8.1 is where that gets tested rather than reasoned about.
- **Credential rotation under load.** Each deploy remints, and an application mid-request when its credential changes is untested.
- **More applications than a manifest has ever had.** The policy document is read whole on every change; nothing here says where that stops being cheap.
- **Invoice reconciliation.** Still open from 4.1, and still the largest unverified claim in the project.
