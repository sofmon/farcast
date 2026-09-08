# Runbook — Phase 4.4 Validation: Per-Application Egress

Phase 4.4 makes the promise `farcast run` already shows an operator into something the enforcement point can keep. Until now it could not: the declarations never arrived, and the code that would have carried them flattened every application's list into one.

The claims that matter here are the ones no unit test can make:

- **The declarations arrive at all.** `fatline/deploy` passed no manifest before this phase, so a deployed FatLine's allowlist was empty and applications reached nothing outside the cluster. Both earlier walks passed while that was true, because the example application declares no external hosts. **This is the first time FarCast has knowingly let an application out.**
- **An application reaches what it declared.** End to end: a manifest host, through a credential, through a mounted ConfigMap, to a real TLS connection.
- **It cannot reach what another application declared.** The property PLAN 4.4 names, tested from the inside of a running pod rather than in a table.
- **The credential travels with no application change.** The application is handed `FARCAST_FATLINE_PROXY` and points its own client at it. Whether that client really opens a CONNECT tunnel to a cluster Service *and* turns the URL's userinfo into a `Proxy-Authorization` header is a claim about somebody else's library — here curl's, since the fixture is `alpine:3.19` plus `curl`. It is **not** busybox's: the first walk found busybox `wget` cannot make an HTTPS request through a CONNECT proxy at all, which is why the fixture carries curl.
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
  'https_proxy="$FARCAST_FATLINE_PROXY" curl -sS --max-time 10 -o /dev/null https://example.com && echo REACHED || echo BLOCKED'
```

Expected: **`REACHED`**. This is the first outbound request FarCast has ever permitted.

**Why the command sets `https_proxy` itself.** FarCast hands an application
`FARCAST_FATLINE_PROXY` and nothing else — [`planck/translate`](../../planck/translate/workload.go)
deliberately does not set `https_proxy`, because an application that ignores the
variable is supposed to fail rather than quietly find another way out. So every
check below points a client at the proxy explicitly. A bare `curl` here would
attempt a direct connection, NetworkPolicy would drop it, and the step would
report `BLOCKED` — the expected answer for entirely the wrong reason.

If it is `BLOCKED`, three different things could be true, and they have
different fixes. Separate them before assuming a defect:

1. **The policy has not reached FatLine yet** — read step 6.
2. **FatLine refused** — step 7's log will say so, with a reason.
3. **the client never asked** — no log line at all, because it either did not
   open a CONNECT tunnel or did not send the credential.

The third is not a FarCast defect, and this probe tells it apart from the other
two by speaking to FatLine with no client in the way:

```bash
kubectl -n "$APPS" exec deploy/reacher -- sh -c '
  CRED=$(echo "$FARCAST_FATLINE_PROXY" | sed "s|^http://||; s|@.*||")
  AUTH=$(printf "%s" "$CRED" | base64 | tr -d "\n")
  printf "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic %s\r\n\r\n" "$AUTH" \
    | nc -w 5 fatline-egress.farcast-system.svc.cluster.local 3128 | head -1'
```

Expected: `HTTP/1.1 200 Connection established`. A `403` means FatLine
identified the caller and refused the host; a `407` means it could not identify
the caller at all. If this returns `200` while the `curl` above says `BLOCKED`,
the boundary works and the client is the problem.

## 4. It cannot reach what it did not declare

```bash
kubectl -n "$APPS" exec deploy/reacher -- sh -c \
  'https_proxy="$FARCAST_FATLINE_PROXY" curl -sS --max-time 10 -o /dev/null https://www.wikipedia.org && echo REACHED || echo BLOCKED'
```

Expected: **`BLOCKED`**.

## 5. One application cannot use another's declarations

This is the property the phase exists for. `hermit` declares nothing, so it must not reach `example.com` even though its neighbour may:

```bash
kubectl -n "$APPS" exec deploy/hermit -- sh -c \
  'https_proxy="$FARCAST_FATLINE_PROXY" curl -sS --max-time 10 -o /dev/null https://example.com && echo REACHED || echo BLOCKED'
```

Expected: **`BLOCKED`** — and check *why* in step 7 before accepting it. `hermit`
uses **its own** credential here, which is the whole point: it is identified
correctly, as an application with no declarations, and refused on that basis.
A denial reason of `unknown_app`, or no log line at all, means the step reported
the expected word without testing per-application enforcement.

Then the sharper test — `hermit` borrowing `reacher`'s address, credential and all:

```bash
kubectl -n "$APPS" exec deploy/hermit -- sh -c \
  "https_proxy='$CRED' curl -sS --max-time 10 -o /dev/null https://example.com && echo REACHED || echo BLOCKED"
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
  'https_proxy="$FARCAST_FATLINE_PROXY" curl -sS --max-time 10 -o /dev/null https://example.com && echo REACHED || echo BLOCKED'
kubectl -n "$NS" get pods -l app.kubernetes.io/name=fatline -o jsonpath='{.items[*].metadata.name}{"\n"}'
kubectl -n "$NS" logs -l app.kubernetes.io/name=fatline --prefix --tail=5 | grep -i "policy reloaded"
```

Expected: `REACHED`, **the same pod names**, and a log line reporting the reload. The network boundary did not restart.

## 7. Shrike names the application

```bash
kubectl -n "$NS" logs -l app.kubernetes.io/name=fatline --prefix --tail=50 | grep -iE "deny|violation|alert"
```

**Read every replica, not one.** FatLine runs two pods by default, a connection
lands on whichever the Service picks, and `logs deploy/fatline` reads only one
of them — so a denial that happened can look like a denial that was never
logged. The label selector above covers both. The same applies to step 6: a
reload has to reach both pods, and a check right after the patch can catch one
reloaded and one not.

Expected: the denials from steps 4 and 5 attributed to `reacher` and `hermit` **by name**, with `not_in_allowlist` as the reason — not a single merged count, and not an anonymous "application".

## 8. An unidentified caller is its own problem

```bash
kubectl -n "$APPS" exec deploy/reacher -- sh -c \
  'https_proxy=http://fatline-egress.farcast-system.svc.cluster.local:3128 curl -sS --max-time 10 -o /dev/null https://example.com && echo REACHED || echo BLOCKED'
```

Expected: **`BLOCKED`**, and a FatLine log line with reason `unknown_app` — distinct from `not_in_allowlist`, because "I do not know who is asking" and "you may not go there" have different fixes.

## 9. Another deployment's policy survives

```bash
farcast run "$INSTANCE" github.com/sofmon/farcast \
  --manifest manifest/examples/manifest-elsewhere/farcast --namespace other-demo -y
kubectl -n "$NS" get configmap fatline-egress-policy -o jsonpath='{.data.policy\.json}' | jq '.apps[] | .namespace + "/" + .name'
kubectl -n "$APPS" exec deploy/reacher -- sh -c \
  'https_proxy="$FARCAST_FATLINE_PROXY" curl -sS --max-time 10 -o /dev/null https://example.com && echo REACHED || echo BLOCKED'
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

Walked 2026-09-08 against instance `p44` on GKE Autopilot, released the same day.

| # | Claim | Result |
|---|-------|--------|
| 1 | `run` reports per-application egress and writes the policy | ✅ `Egress: 1 declared host across 2 applications, enforced per application.` |
| 2 | The policy carries hashes and no credential in the clear | ✅ zero occurrences of either credential; `sha256(credential)` recomputed on the operator's machine and matched |
| 3 | An application reaches a host it declared | ✅ at the boundary — `HTTP/1.1 200 Connection Established`. See finding 4: not via the fixture's own client |
| 4 | It cannot reach a host it did not declare | ✅ `403`, `reason=not_in_allowlist` |
| 5 | Another application cannot reach it by its own identity | ✅ `hermit` with its **own** credential: `403 not_in_allowlist` |
| 6 | A borrowed credential does work, as the ADR says it would | ✅ `hermit` with `reacher`'s credential: `200`, logged as `app=reacher` |
| 7 | Policy reloads with no FatLine restart | ✅ two reloads per replica, pod names unchanged throughout |
| 8 | Denials name the application | ❌ → fixed during the walk (finding 1), re-verified live |
| 9 | An unidentified caller is reported as `unknown_app` | ✅ `407`, `tenant="" app="" reason=unknown_app` |
| 10 | A second deployment does not revoke the first's egress | ❌ blocked by finding 2 → fixed, then ✅ three applications in the document, `reacher` still reaching |

## What walking it found

Five of the ten criteria could not have been honestly ticked from this runbook
as it was first written, and two product defects were invisible to a fully
green unit-test suite.

**1. FatLine's log named no application at all.** `event.SlogSink.Emit` rendered
`kind, host, port, proto, sni, reason, bytes_up, bytes_down` and silently
dropped `Tenant` and `App`. The proxy fills both in correctly — `handlePlain`
even carries the comment *"A denial nobody can attribute is telemetry rather
than enforcement"* — and the sink threw them away one layer below. Every
denial in a live instance read as anonymous, and two different applications
refused for the same host were indistinguishable.

The only test on that sink was `TestSlogSinkEmitDoesNotPanic`, which asserts
nothing. Its replacement asserts on the rendered bytes and fails without the
fix. The same gap left SNI-mismatch denials and `Close` events (which carry the
byte counts) unattributed, though `caller` was in scope at both.

This matters most for the weakness [ADR 0013](../adr/0013-per-application-egress-identity.md)
*accepts*: a stolen credential is meant to be visible in the log as the wrong
application acting. It was not visible at all. Criterion 6 now shows
`app=reacher` on a request `hermit` made.

**2. Two manifests in one repository collided on the fetch Job name.**
`fetch.JobName(repo, ref)` hashed the repository and ref but not the manifest
path — the one thing distinguishing two deployments from one repository. A
Job's `spec.template` is immutable, so the second `run` was refused outright by
the API server, with roughly 8KB of dumped PodSpec naming neither the manifest
nor the collision. Nothing built, nothing deployed.

Wider than this runbook: as shipped, one instance could hold only one
deployment per `(repo, ref)`, and a repository holding several manifests is an
ordinary layout — `manifest/examples/manifest-elsewhere` exists to demonstrate
precisely that.

**3. Five checks in this runbook bypassed the boundary they tested.** Steps 3,
4, 5, 6 and 9 ran a bare client with no proxy configured. Since FarCast sets
only `FARCAST_FATLINE_PROXY`, those requests went direct and NetworkPolicy
dropped them. Step 5's first half expected `BLOCKED` and would therefore have
**passed while proving nothing** — the same blind spot 4.4 exists to close,
reproduced in the runbook written to validate it. Every step now states what
the log must show, so `BLOCKED` alone is never sufficient.

**4. The fixture could not exercise the boundary.** `alpine:3.19`'s busybox
`wget` ignores `https_proxy` and `HTTPS_PROXY` outright, and given `http_proxy`
issues a cleartext proxied GET which FatLine correctly refuses
(`port=80 proto=http cleartext_not_allowed`). It cannot make an HTTPS request
through a CONNECT proxy at all. The walk fell back to a raw CONNECT over `nc`,
which proves FatLine but **not** the "no application change" claim. The fixture
now carries curl; that claim remains unproven until the next walk.

**5. `metadata.yaml` lost concurrent writes.** Running `farcast toolchain`
while `farcast connect` was still finishing left no toolchain record: every
command did an unguarded read-modify-write of the whole file, so `connect`
wrote back a copy loaded before `toolchain` ran. It cost a re-run here. The
same race could drop `storage.bucket`, the only local pointer to the bucket
holding an instance's data — and that bucket keeps billing whether or not
anything remembers its name. There is no second copy of this file.

Fixed after the walk. A save now compares what is on disk against what the
command read, and where they differ it replays the command's own changes onto
the newer record rather than over it — an ordinary three-way merge, which is
the right answer because each command owns a distinct part of this record
(`connect` the carrier, `storage deploy` the bucket, `toolchain` the mirrored
images). Refusing instead would have been the wrong fix: it would leave a load
balancer that already exists unrecorded, which is the same loss wearing a
different hat. Only two commands moving the *same* field somewhere different
is a real conflict, and that is refused rather than guessed. Writes also go
through a temporary file and a rename, so a process that dies mid-write leaves
the previous record whole instead of a truncated one.

**6. Smaller things.** `farcast toolchain` mirrors the builder *before*
validating `--fetcher`, so a rejected command still has an effect;
`farcast kernel deploy` rejects a missing namespace only after compiling and
pushing its image; a failed unseal consumes a keyring generation; and the
keyholder crash-loops on a 403 until the operator applies the grant `storage
deploy` prints *after* deploying it — the second time a printed-not-applied
grant has made a healthy instance look broken.

Confirmed in passing: [ADR 0008](../adr/0008-in-cluster-key-delivery.md) decision
9's fix, live for the first time — the `app` scope was present in the keyring
with `prefix: app/` before any unseal succeeded.

## Not covered by this run

- **A provider whose NetworkPolicy is weaker than Autopilot's.** The portability argument that chose a credential over a port is about EKS and AKS, and neither is walked here — 8.1 is where that gets tested rather than reasoned about.
- **Credential rotation under load.** Each deploy remints, and an application mid-request when its credential changes is untested.
- **More applications than a manifest has ever had.** The policy document is read whole on every change; nothing here says where that stops being cheap.
- **Invoice reconciliation.** Still open from 4.1, and still the largest unverified claim in the project.
