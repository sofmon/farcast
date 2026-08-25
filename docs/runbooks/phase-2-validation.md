# Runbook — Phase 2 Validation: The Networking & Security Boundary

**Goal.** Prove the Phase 2 deliverable: FatLine is the deny-by-default boundary
([2.1](../../fatline/README.md)), Shrike monitors and alerts on it
([2.2](../../shrike/README.md)), and the operator can `farcast connect` to an
instance through the mutually-authenticated tunnel ([2.3](../../farsight/cli/README.md),
[ADR 0005](../adr/0005-fatline-data-plane-ingress.md) / [ADR 0006](../adr/0006-connect-bootstrap-kubectl.md)).

It is in **two tiers**:

- **Part A — Local (free, no cloud).** Validates the FatLine egress proxy + the
  Shrike sidecar wire end-to-end over loopback, plus the tunnel/crypto via the
  test suite. Run this first — it needs nothing but the repo and `curl`.
- **Part B — End-to-end on a real GKE instance (billable).** Validates the
  `farcast connect` bootstrap for real: mint identity → deploy FatLine → provision
  the public mTLS load balancer → dial the tunnel. **This provisions a standing
  ~$18/mo load balancer**; Step B6 tears it all down.

**What Part B exercises that unit tests cannot:** a real FatLine container image,
`kubectl apply` over the IAM-gated kubeconfig, a real `Service{type:LoadBalancer}`
getting a public IP, and the mTLS handshake across the open internet.

**Cost & time.** Part A: free, ~5 min. Part B: the instance itself (empty
Autopilot) is cheap, but the **load balancer bills ~$18/mo while it exists** —
budget the test to a single session and run Step B6 to delete it. Time: ~5 min to
build/push the image, ~3–5 min for `connect`, ~3–5 min for the `release` teardown
to finish (the command itself returns once the deletion is accepted; the cluster
shows `STOPPING` while it completes).

---

# Part A — Local validation (free)

> **Shortcut.** [`phase-2-part-a.sh`](phase-2-part-a.sh) runs everything in Part A
> automatically and stops with a clear message on the first failure (macOS bash):
> `bash docs/runbooks/phase-2-part-a.sh`. The steps below are what it does, for
> when you want to run them by hand.

## A0. Build everything and run the guardrails

From the repo root:

```bash
go test -race ./...        # all unit + race tests (incl. tunnel mTLS e2e, allowlist/inspector races)
go vet ./...
gofmt -l . | grep -v '^vendor/' || echo "gofmt clean"
golangci-lint run ./...    # if installed

# Build into ./bin/ — `go build -o fatline …` at the root would land the binary
# *inside* the fatline/ source dir (Go writes -o <existing-dir> as dir/<name>).
mkdir -p bin
go build -o ./bin/farcast ./farsight/cli/cmd/farcast
go build -o ./bin/fatline ./fatline/cmd/fatline
go build -o ./bin/shrike  ./shrike/cmd/shrike
```

✅ Expect: tests pass, vet/lint clean, three binaries in `./bin/`. The `go test`
run alone already proves the FatLine mTLS tunnel handshake, the per-instance CA
mint/verify, the deny-by-default allowlist (under `-race`), and Shrike's
violation table + wire round-trip.

## A1. FatLine egress + Shrike sidecar, end-to-end over loopback

This is the visible proof of 2.1 (deny-by-default egress) + 2.2 (Shrike monitors
and alerts) wired together — no cloud, no mTLS tunnel, just the egress plane and
the sidecar event wire.

```bash
TMP=$(mktemp -d)
SOCK="$TMP/shrike.sock"
cat > "$TMP/sample-manifest.yaml" <<'EOF'
name: validate
apps:
  - name: web
    containerfile: Containerfile
    external:
      - host: api.stripe.com
        reason: payments
EOF

# Start Shrike (declared policy from the manifest; status on :18132):
./bin/shrike --socket "$SOCK" --manifest "$TMP/sample-manifest.yaml" --status-listen 127.0.0.1:18132 &
SHRIKE_PID=$!

# Start FatLine's egress proxy, shipping decisions to the Shrike socket:
./bin/fatline --egress-listen 127.0.0.1:18131 --manifest "$TMP/sample-manifest.yaml" --shrike-socket "$SOCK" &
FATLINE_PID=$!
sleep 1
```

Drive traffic through the proxy and watch the boundary act:

```bash
# DENIED — undeclared host (deny-by-default), repeated to exercise de-dup:
for i in 1 2 3; do curl -s -o /dev/null -x http://127.0.0.1:18131 https://evil.example.com --max-time 3; done
# DENIED — cleartext http to a declared host (confidentiality is part of deny-by-default):
curl -s -o /dev/null -x http://127.0.0.1:18131 http://api.stripe.com --max-time 3
# ALLOWED — a declared host (the CONNECT is permitted; the upstream dial may or may
# not complete depending on your network, but FatLine emits the allow):
curl -s -o /dev/null -x http://127.0.0.1:18131 https://api.stripe.com --max-time 5
sleep 1

echo "=== Shrike security picture ==="
curl -s http://127.0.0.1:18132/_shrike/status   # | python3 -m json.tool
```

✅ Expect the Shrike status JSON to show:
- `declared: ["api.stripe.com"]`,
- a **`warning`** violation for `evil.example.com` with **`count: 3`** (the three
  denials de-duplicated into one class),
- an **`info`** violation for the cleartext attempt (`cleartext_not_allowed`),
- `api.stripe.com` under `allowed` (it was permitted).

Shrike's stderr should carry matching alert lines (`WARN … policy violation …`).

Clean up:

```bash
kill $FATLINE_PID $SHRIKE_PID 2>/dev/null; rm -rf "$TMP"
```

## A2. The mTLS tunnel & per-instance CA

The tunnel server, the client dialer, and the per-instance-CA crypto are exercised
by the test suite (the tunnel Connect e2e lives in the root `fatline` package,
plus `fatline/internal/crypto` and `fatline/identity`): a good client connects, a
foreign-CA or no-cert peer is rejected at the handshake, and the operator URI-SAN
identity is enforced. Re-run just those if you want to see them in isolation:

```bash
go test ./fatline ./fatline/internal/crypto/... ./fatline/identity/... -v 2>&1 | grep -E '^(=== RUN|--- (PASS|FAIL))' | head -40
```

The *public-path* tunnel (across a real load balancer) is what Part B validates.

## A3. `farcast connect` — the no-cloud surface

```bash
./bin/farcast help connect                 # usage renders; no "not yet implemented"
./bin/farcast connect                      # → usage error, exit 2
echo "exit=$?"
./bin/farcast connect --carrier cp-forward foo   # → unsupported carrier, exit 2
./bin/farcast connect ghost                # → "no such instance" (run install first), exit 1
```

✅ Expect the exit codes above. The full `connect` bootstrap needs a real cluster
— that is Part B.

---

# Part B — End-to-end on a real GKE instance (billable)

> **Cost gate.** Step B2 provisions a **public load balancer (~$18/mo)**. Do the
> whole of Part B in one session and run **Step B6** to delete it. The instance's
> cost limit is only *recorded* until TechnoCore (4.1), so nothing auto-stops it.

## B0. Prerequisites

- **An installed, running instance** — complete the [Phase 1 runbook](phase-1-validation.md)
  (`farcast install`) and keep its `FARCAST_CONFIG_HOME`. Reuse those variables:

  ```bash
  export PROJECT_ID="your-gcp-project-id"
  export REGION="us-central1"
  export INSTANCE="validate"
  export FARCAST_CONFIG_HOME="$HOME/.farcast-validation"
  ```

- **kubectl + the GKE auth plugin** on your PATH (the kubeconfig drives the
  control plane through them — [ADR 0006](../adr/0006-connect-bootstrap-kubectl.md)):

  ```bash
  gcloud components install kubectl gke-gcloud-auth-plugin   # or your distro's packages
  kubectl version --client && gke-gcloud-auth-plugin --version
  ```

## B1. Build & push a FatLine image

`connect` deploys a FatLine container; you must supply its image. There is no
published image yet, so build the one the repo ships: [`fatline/Containerfile`](../../fatline/Containerfile)
(distroless, non-root uid 65532 to match the deploy's security context). **Build
from the repo root** — the context needs the root `go.mod` + `vendor/`.

Push it to Artifact Registry in the **same project** (so the Autopilot node SA can
pull it without extra grants):

```bash
gcloud artifacts repositories create farcast \
  --repository-format=docker --location="$REGION" --project "$PROJECT_ID" 2>/dev/null || true
gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet

export FATLINE_IMAGE="${REGION}-docker.pkg.dev/${PROJECT_ID}/farcast/fatline:0.1.0"
docker build -f fatline/Containerfile -t "$FATLINE_IMAGE" .
docker push "$FATLINE_IMAGE"
```

✅ Expect a pushed image. (If your nodes can't pull it in Step B2, grant the node
SA `roles/artifactregistry.reader` — see Troubleshooting.)

## B2. Connect — bootstrap FatLine + provision the carrier

```bash
./bin/farcast connect "$INSTANCE" --fatline-image "$FATLINE_IMAGE" --yes
```

This mints the per-instance mTLS identity (the **CA key stays local**), applies
the FatLine workload via kubectl, waits for the load balancer's public IP, then
dials the tunnel. It **blocks a few minutes** while the LB is assigned. ✅ Expect:

```
✓ connected to "validate"
  carrier:     public mTLS NLB  34.x.x.x:8443
  identity:    farcast://validate/operator
  active:      0 streams
  allowlist:   0 hosts (deny-by-default)
  cost:        load balancer ~$18/mo (limit: USD 50/monthly)
```

> The allowlist is **empty by design** in 2.3 — `connect` deploys FatLine with no
> manifest, so egress denies by default; per-app allowlists arrive in 4.4. The
> tunnel and status are what 2.3 proves.

## B3. Verify the deployment independently (kubectl)

```bash
export KUBECONFIG="$FARCAST_CONFIG_HOME/instances/$INSTANCE/kubeconfig.yaml"
kubectl get all -n farcast-system
kubectl get secret fatline-mtls -n farcast-system -o jsonpath='{.data}' | tr ',' '\n'
```

✅ Expect: a `fatline` Deployment (1/1 ready), a `fatline` Service of type
**LoadBalancer** with an external IP, and the `fatline-mtls` Secret carrying
**`ca.crt`, `server.crt`, `server.key`** — and crucially **no `ca.key`** (the CA
private key never leaves your machine).

Confirm the CA key is local-only:

```bash
ls -la "$FARCAST_CONFIG_HOME/instances/$INSTANCE/fatline/"   # ca.key present here (0600)…
kubectl get secret fatline-mtls -n farcast-system -o jsonpath='{.data.ca\.key}'; echo "  ← must be EMPTY"
```

## B4. Verify the mTLS boundary — the "locked door"

Read back the carrier endpoint and the pinned server name, then prove the tunnel
admits only a holder of an operator cert signed by the per-instance CA.

```bash
CERTS="$FARCAST_CONFIG_HOME/instances/$INSTANCE/fatline"
# The carrier endpoint (IP:8443) straight from connect's own status JSON:
LB=$(./bin/farcast connect "$INSTANCE" --status --output json | sed -n 's/.*"endpoint":"\([^"]*\)".*/\1/p')
NAME="$INSTANCE.fatline.farcast"
echo "LB=$LB  server-name=$NAME"

# POSITIVE — present the operator client cert, trust only the per-instance CA,
# pin the server name while connecting to the LB IP:
curl -sS --cacert "$CERTS/ca.crt" --cert "$CERTS/client.crt" --key "$CERTS/client.key" \
  --connect-to "$NAME:8443:$LB" "https://$NAME:8443/_fatline/status"; echo

# NEGATIVE — no client certificate → dropped at the handshake:
curl -sS --cacert "$CERTS/ca.crt" \
  --connect-to "$NAME:8443:$LB" "https://$NAME:8443/_fatline/status"; echo "  ← expect a TLS error"
```

✅ Expect: the **positive** call returns the FatLine status JSON
(`{"connected":true,...}`); the **negative** call fails at the TLS layer
(certificate-required / handshake error). That asymmetry is the whole boundary:
an unauthenticated peer with the IP gets nothing.

## B5. Reconnect & scripted status

```bash
./bin/farcast connect "$INSTANCE" --status                 # re-dials the stored carrier; no re-deploy, no cost prompt
./bin/farcast connect "$INSTANCE" --status --output json   # one JSON object for automation
```

✅ Expect: both report `connected: true` against the same endpoint, and `--status`
neither re-deploys nor re-prompts for cost (idempotent reconnect).

## B6. Teardown — delete the load balancer (cost!)

`release` destroys the whole cluster, which deletes the FatLine Service and its
load balancer:

```bash
./bin/farcast release "$INSTANCE" --yes
```

`release` returns once GCP has **accepted** the deletion — the cluster keeps
showing `STOPPING` for a few more minutes while it (and the LB's forwarding rule)
are actually removed. Then **confirm no billable forwarding rule lingers** (re-run
until both checks come back empty):

```bash
gcloud compute forwarding-rules list --project "$PROJECT_ID"   # expect: none from this instance
gcloud container clusters list --project "$PROJECT_ID"          # STOPPING at first, then gone
```

✅ Expect: no cluster, no forwarding rules → no lingering LB charge.

---

## Troubleshooting

| Symptom | Cause & fix |
|---|---|
| `kubectl not found on PATH` | Install `kubectl` + `gke-gcloud-auth-plugin` (B0). The CLI shells to kubectl by design ([ADR 0006](../adr/0006-connect-bootstrap-kubectl.md)). |
| `connect` prompts for cost / refuses non-interactively | The LB is billable. Pass `--yes` (required when not a TTY or in `--output json`). |
| Deployment stuck `ImagePullBackOff` | The node SA can't pull `$FATLINE_IMAGE`. Grant it: `gcloud projects add-iam-policy-binding "$PROJECT_ID" --member "serviceAccount:$(gcloud iam service-accounts list --filter='displayName:Compute Engine default' --format='value(email)' --project "$PROJECT_ID")" --role roles/artifactregistry.reader`, or push to a public registry. |
| `FatLine rollout` times out | `kubectl get pods -n farcast-system` then `kubectl describe`/`logs`. Usually the image (above) or Autopilot scheduling (give it a minute). |
| Load balancer IP never assigned | LB quota/region capacity; `kubectl describe svc fatline -n farcast-system` for events. Re-run `connect` — it is idempotent (won't re-prompt cost once `fatline_deployed` is recorded). |
| Positive curl in B4 fails TLS | Wrong server name (must be `$INSTANCE.fatline.farcast`) or you skipped `--connect-to`. The cert's SAN is the synthetic name, pinned independently of the IP. |
| Interrupted `connect` after the LB was created | The LB is recorded (`fatline_deployed: true`) before the IP wait, so re-running `connect` resumes without re-charging — and `release` always cleans it up. |

## Success criteria

**Part A (local, free):**
- [ ] `go test -race ./...`, `go vet`, lint all clean; three binaries build.
- [ ] Shrike status shows the undeclared host as a `warning` with `count: 3`, the cleartext attempt as `info`, and the declared host under `allowed`.
- [ ] `connect`'s no-cloud surface returns the right exit codes.

**Part B (end-to-end, billable):**
- [ ] `farcast connect` reports `connected` with a public NLB endpoint.
- [ ] kubectl shows the FatLine Deployment/Service/Secret; the Secret has **no `ca.key`**; `ca.key` exists only locally at `0600`.
- [ ] mTLS boundary: the operator cert gets status JSON; no-cert is rejected at the handshake.
- [ ] `connect --status` reconnects idempotently (no re-deploy, no cost prompt).
- [ ] `release` removes the cluster and leaves **no forwarding rule** (no lingering LB charge).

If Part A passes you've validated the security boundary itself; if Part B passes
the operator can reach a real instance through it — the Phase 2 deliverable.
