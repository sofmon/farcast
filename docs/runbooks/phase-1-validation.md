# Runbook — Phase 1 Validation: Create & Destroy a Real FarCast Instance

**Goal.** Prove, against a real GCP project, that `farcast install` provisions a GKE
Autopilot instance and `farcast release` destroys it — the Phase 1 deliverable —
before moving on to Phase 2.

**What this exercises that the unit tests cannot:** real credentials and IAM, the
GKE management API, **actual Autopilot cluster creation with the private control
plane** ([ADR 0004](../adr/0004-private-control-plane.md)), the readiness wait, the
real `DeleteCluster`, and local state round-tripping across two commands.

**Cost & time.** A short create→delete cycle of an *empty* Autopilot cluster is
cheap — the first zonal/Autopilot cluster's management fee is covered by the GKE
free tier, and an empty cluster runs no billable Pods. Budget **~5–10 min** for
create; `release` itself returns in seconds, with GCP finishing the delete over
**~3–5 min** in the background. The mandatory cost limit is only *recorded* in
Phase 1 (TechnoCore enforces it in 4.1), so it will not stop anything — `release`
is what guarantees no lingering charges.

> **Status.** Executed end-to-end against a real GCP project on **2026-08-24** — all six
> success criteria passed, including live confirmation of the private control plane
> (a `*.gke.goog` DNS endpoint, no public control-plane IP). One behavioural note from
> the live run: `release` returns once GCP *accepts* the delete — the cluster stays
> `STOPPING` for a few more minutes (see Steps 8–9).

---

## 0. Set shared variables

Run everything below in one shell so these persist:

```bash
export PROJECT_ID="your-gcp-project-id"      # an existing project with BILLING ENABLED
export REGION="us-central1"                   # any Autopilot-supported region
export KEY="$HOME/farcast-key.json"           # where the SA key will be written
export INSTANCE="validate"                     # instance name → cluster "farcast-validate"
# Isolate validation state in a fresh dir farcast will create at 0700.
# IMPORTANT: do NOT pre-create this directory (see Troubleshooting).
export FARCAST_CONFIG_HOME="$HOME/.farcast-validation"
```

You also need the **gcloud CLI** authenticated as a user with Owner/Editor on the
project (`gcloud auth login`, `gcloud config set project "$PROJECT_ID"`). That user
auth is for the `gcloud` setup/verification commands; FarCast itself uses the
service-account key you create below.

---

## 1. Enable the APIs

GKE for the cluster; Artifact Registry for the instance's own image registry and
Cloud Resource Manager to look up the project number that identifies the node
service account ([ADR 0007](../adr/0007-instance-owned-image-registry.md)).

```bash
gcloud services enable container.googleapis.com artifactregistry.googleapis.com cloudresourcemanager.googleapis.com --project "$PROJECT_ID"
```

## 2. Create the installer service account + key

```bash
gcloud iam service-accounts create farcast-installer \
  --project "$PROJECT_ID" --display-name "FarCast installer"

export SA="farcast-installer@${PROJECT_ID}.iam.gserviceaccount.com"

# Create & delete clusters:
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member "serviceAccount:$SA" --role "roles/container.admin"

# Act as the node service account (Autopilot nodes use the default compute SA):
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member "serviceAccount:$SA" --role "roles/iam.serviceAccountUser"

# Own the instance's image registry (create/delete it, and grant the cluster's
# nodes pull access ON THAT REPOSITORY — never a project-wide role):
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member "serviceAccount:$SA" --role "roles/artifactregistry.admin"

# Download a key (this is the credential FarCast will use and store):
gcloud iam service-accounts keys create "$KEY" --iam-account "$SA"
chmod 600 "$KEY"
```

> `roles/container.admin` + `roles/iam.serviceAccountUser` are the minimal pair for
> cluster create/delete; `roles/artifactregistry.admin` is the narrowest predefined
> role that can create a repository (`repoAdmin` cannot) and it also carries the
> repository-level `setIamPolicy` the node-SA pull grant needs — so the stored
> credential never holds project-IAM power. If your SA is already Owner/Editor you
> can skip the bindings.

## 3. Build the binaries

From the repo root:

```bash
go build -o farcast ./farsight/cli/cmd/farcast
# The low-level Planck harness is invoked with `go run` below (no binary —
# avoids colliding with the planck/ source directory).
```

## 4. Pre-flight — validate credentials (free, read-only)

Before spending any time/money, confirm the key works and the API is reachable.
This lists clusters (read-only) — the cheapest possible check:

```bash
go run ./planck/cmd/planck validate --provider gke --project "$PROJECT_ID" --credentials "$KEY"
```

✅ Expect: `credentials OK`. A permissions or API error here means stop and fix
Step 1/2 before continuing.

## 5. Install — create the instance

```bash
./farcast install \
  --name "$INSTANCE" \
  --project "$PROJECT_ID" \
  --region "$REGION" \
  --credentials "$KEY" \
  --cost-limit 50 \
  --yes
```

This **blocks for several minutes** while Autopilot provisions. ✅ Expect, on
success:

```
✓ instance "validate" installed
  provider:    gke
  region:      us-central1
  cluster:     farcast-validate
  endpoint:    <uid>.us-central1.gke.goog        ← a DNS endpoint, not an IP
  cost limit:  USD 50.00 / monthly
  state:       running
  config:      .../.farcast-validation/instances/validate
```

The `endpoint` being a `*.gke.goog` **DNS** name (no public IP) is the visible
proof the private control plane (ADR 0004) took effect.

## 6. Verify local state

```bash
ls -la "$FARCAST_CONFIG_HOME/instances/$INSTANCE/"
cat    "$FARCAST_CONFIG_HOME/instances/$INSTANCE/metadata.yaml"
```

✅ Expect: directory `0700`; `metadata.yaml`, `credentials.yaml`, `kubeconfig.yaml`
all `0600`; metadata shows `status: running`, the DNS `endpoint`, and the
`cost_limit`.

## 7. Verify the cluster in GCP (independent of FarCast)

```bash
gcloud container clusters list --project "$PROJECT_ID"

gcloud container clusters describe "farcast-$INSTANCE" \
  --location "$REGION" --project "$PROJECT_ID" \
  --format="yaml(name, status, autopilot, controlPlaneEndpointsConfig, privateClusterConfig)"
```

✅ Expect: `status: RUNNING`; `autopilot.enabled: true`; the control plane shows
the **DNS endpoint present** and the **public/external IP endpoint disabled**
(in `controlPlaneEndpointsConfig` / `privateClusterConfig`). If the projected
fields come back empty on your gcloud version, drop the `--format` flag and eyeball
the full description for `autopilot`, `controlPlaneEndpointsConfig`, and
`privateClusterConfig`.

## 8. Release — destroy the instance

`release` reads the provider, project, region, and credentials from the recorded
instance — you only name it:

```bash
./farcast release "$INSTANCE" --yes
```

This returns as soon as GCP **accepts** the delete — the cluster then finishes deleting in
the background, showing as `STOPPING` for another ~3–5 minutes (see Step 9). ✅ Expect:

```
✓ instance "validate" released
  provider:    gke
  cluster:     farcast-validate (deleted)
  state:       removed
```

## 9. Verify teardown & clean up

```bash
gcloud container clusters list --project "$PROJECT_ID"     # STOPPING at first, then gone
ls "$FARCAST_CONFIG_HOME/instances/"                        # 'validate' gone
```

✅ Expect: the local record gone immediately. The cluster may still be listed as `STOPPING`
for a few minutes after `release` returns — re-run the list until `farcast-validate` is gone
(no lingering charges).

Optional final cleanup once you're satisfied:

```bash
rm -rf "$FARCAST_CONFIG_HOME"                               # local validation state
gcloud iam service-accounts keys list --iam-account "$SA"  # then delete keys if desired
# gcloud iam service-accounts delete "$SA" --project "$PROJECT_ID"   # remove the installer SA
```

---

## Troubleshooting (likely first-run snags)

| Symptom | Cause & fix |
|---|---|
| `could not find default credentials` | You omitted `--credentials` and have no ADC. Pass `--credentials "$KEY"`, or run `gcloud auth application-default login`. |
| `PERMISSION_DENIED` on create | The installer SA lacks `roles/container.admin`. Re-check Step 2. |
| `... does not have permission to act as ... compute@developer` | Missing `roles/iam.serviceAccountUser` (Step 2), or the **default compute SA is disabled** on the project (org-policy). Enable it or grant actAs on the node SA. |
| `Kubernetes Engine API has not been used/enabled` | Step 1 not done (or still propagating — wait a minute). |
| `config directory ... is too permissive (0755)` | `FARCAST_CONFIG_HOME` pointed at a dir that already existed at `0755`. Use a path farcast creates itself, or `chmod 700` it. The CLI refuses group/world-accessible state by design. |
| `master_authorized_networks should be enabled if private endpoint is enabled` | A GKE constraint the first live run surfaced — **fixed** in the adapter: it now enables master authorized networks with an empty allowlist alongside the private endpoint ([ADR 0004](../adr/0004-private-control-plane.md)). If you still hit it, you're on an older `farcast` build — rebuild from `main`. |
| Create fails on the **private endpoint / VPC network** for another reason | The private control plane needs usable VPC IP space; on a default project/VPC this normally just works. Capture the exact error — ADR 0004 has a relax-to-public-IP escape hatch if some environment needs it. |
| `quota` / region capacity | Try another `REGION`, or request quota. |
| Provisioning hangs / you Ctrl-C | The local record is kept (`status: provisioning`/`error`); run `./farcast release "$INSTANCE"` to clean up — it is idempotent. |

## Optional — exercise the interactive flows

Run in a real terminal (a TTY) **without** `--yes` and with some flags omitted to
test prompting and the destructive confirmation:

```bash
./farcast install --project "$PROJECT_ID" --credentials "$KEY"   # prompts for name, region, cost limit, confirm
./farcast release "$INSTANCE"                                     # prompts you to RETYPE the instance name
```

## Optional — isolate Planck with the harness

If `install` fails and you want to tell whether the problem is Planck or the CLI,
drive the provider directly (this creates/deletes a real cluster too):

```bash
go run ./planck/cmd/planck create --provider gke --project "$PROJECT_ID" --location "$REGION" --name farcast-probe --credentials "$KEY"
go run ./planck/cmd/planck status --provider gke --project "$PROJECT_ID" --location "$REGION" --name farcast-probe --credentials "$KEY"
go run ./planck/cmd/planck delete --provider gke --project "$PROJECT_ID" --location "$REGION" --name farcast-probe --credentials "$KEY"
```

---

## Success criteria

- [ ] `planck validate` reports `credentials OK`.
- [ ] `farcast install` finishes with `state: running` and a `*.gke.goog` endpoint.
- [ ] `gcloud` shows the cluster `RUNNING`, Autopilot, **no public control-plane IP**.
- [ ] Local state exists with `0700`/`0600` perms and `status: running`.
- [ ] `farcast release` succeeds (delete accepted by GCP) and removes local state.
- [ ] `gcloud` shows the cluster gone — `STOPPING` at first, absent a few minutes later; no lingering billable resources.

If all six pass, Phase 1 is validated end-to-end and you're clear to start Phase 2.
