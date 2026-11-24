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
create and **~3–5 min** for `release`, which waits until GCP reports the cluster gone.
The mandatory cost limit is only *recorded* in
Phase 1 (TechnoCore enforces it in 4.1), so it will not stop anything — `release`
is what guarantees no lingering charges.
*(Corrected 2026-10-08: `release` used to return as soon as GCP accepted the delete;
it now waits, bounded at 15 minutes, until the cluster is gone — see Step 8.)*

> **Status.** Executed end-to-end against a real GCP project on **2026-08-24** — all six
> success criteria passed, including live confirmation of the private control plane
> (a `*.gke.goog` DNS endpoint, no public control-plane IP). One behavioural note from
> the live run: `release` returns once GCP *accepts* the delete — the cluster stays
> `STOPPING` for a few more minutes (see Steps 8–9).
> *(Corrected 2026-10-08: that note describes the CLI of the 2026-08-24 run. `release`
> now waits until GCP reports the cluster gone, so no `STOPPING` cluster remains once it
> returns; Steps 8–9 and the criteria below say what to expect now.)*

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
> can skip the bindings. *(2026-11-22, [ADR 0024](../adr/0024-paste-the-certificate.md): the key this step downloads is a provider-made secret. By the operator's rule of that day, once the certificate route is built (ADR 0024's M3b, proposed), it is used only where that route is closed, named and consented (proposed fallback 3). Until then it is `install`'s only installer credential, and in ADR 0023's M2 walk under [B] it is an exception the operator approves at its G0a, time-boxed and deleted at teardown.)* *(2026-11-24, ADR 0023's M2 walked: the walk used the installer's existing key as that exception, approved at G0a on 2026-11-23. The installer held the three roles above with no condition, and `roles/storage.admin` under its bucket condition. The key was deleted in Google and on the Mac at W6.2, so the installer holds no user-managed key ([its Results](adr-0023-m2-walk.md#results)).)*

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

*(2026-11-13: since [ADR 0023](../adr/0023-one-download-farcast.md) M0 the harness sets `GOOGLE_API_USE_CLIENT_CERTIFICATE=false` and unsets `GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES` in its own process before anything else runs, as `farcast` does, so the Google libraries it links never start a certificate provider or an executable credential source. Nothing to set by hand.)*

*(2026-11-14, ADR 0023 M2.3: it also unsets `GOOGLE_SDK_GO_LOGGING_LEVEL`, `SSL_CERT_FILE` and `SSL_CERT_DIR` first, as `farcast` does, so the environment cannot turn on the Google libraries' default logger, which would print token bodies to stderr, and Google's endpoints are trusted on the system roots alone. A private root added only through those two variables, such as a TLS-inspecting proxy's, is not trusted by the harness either.)*

✅ Expect: `credentials OK`. A permissions or API error here means stop and fix
Step 1/2 before continuing.

## 5. Install — create the instance

```bash
./farcast install \
  --name "$INSTANCE" \
  --project "$PROJECT_ID" \
  --region "$REGION" \
  --credentials "$KEY" \
  --cost-limit 100 \
  --yes
```

*(Corrected 2026-10-08: the limit was `50`. Install checks the limit against what a
fully provisioned instance costs standing still — about USD 77.42/month, of which the
modelled ~USD 37 cluster line is not something TechnoCore meters — and a limit of 50
now draws a warning that it clears what TechnoCore meters but not the cluster line.
100 clears the whole floor, so a clean install prints no warning. The floor itself is
in `farsight/cli/internal/cli/floor.go`.)*

This **blocks for several minutes** while Autopilot provisions. ✅ Expect, on
success:

```
✓ instance "validate" installed
  provider:    gke
  region:      us-central1
  cluster:     farcast-validate
  endpoint:    <uid>.us-central1.gke.goog        ← a DNS endpoint, not an IP
  registry:    us-central1-docker.pkg.dev/<project>/farcast-validate (instance images, ~$0/mo)
  cost limit:  USD 100.00 / monthly
  state:       running
  config:      .../.farcast-validation/instances/validate
```

No "The cost limit is below what a fully provisioned instance costs" block should
appear above it; if it does, the limit or the floor has moved.

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
*(2026-11-18, ADR 0023 M2.7, built, not walked: `install` writes no `kubeconfig.yaml` any
more. Expect `metadata.yaml`, with `server_side_apply` for a cluster this install
created, and `credentials.yaml`.)* *(2026-11-24, ADR 0023's M2 walked: M2.7 is walked; that walk's install ran from a release farcast with no kubectl on its `PATH`, and its record does not list the instance's directory.)*
*(2026-11-20, ADR 0023 M2.9a, built, not walked: `install` records no `server_side_apply`,
since `farcast migrate` and the refusal that read it are removed. Expect `metadata.yaml`
and `credentials.yaml`.)*

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

## 7b. The instance's reader identity — not yet walked

*(Added 2026-11-14 for [ADR 0023](../adr/0023-one-download-farcast.md) M2.3. No part
of this step has been run against Google. It is the once-per-instance privileged setup
of ADR 0023 decision 3: a read-only service account of the instance's own, whose key
this machine makes. None of the success criteria below depends on it. What a reader can
and cannot do is in the
[CLI README](../../farsight/cli/README.md#farcast-reader--the-reader-identity-adr-0023-m23).)*

*(2026-11-15, ADR 0023 M2.4: `farcast world`, `ps`, `costs`, `usage` and `logs` now read
the cluster as this reader, and read nothing until step 4 has verified it. So every later
runbook that runs them against a live instance needs this step first. It is still not
walked. `farcast instances` shows how far it is set up, in its `reader` field, without
opening `reader.key`.)*

*(2026-11-16: ADR 0023's [M2 probe walk](adr-0023-m2-probe-walk.md) ran `reader init` and
the paste, this step's 1 and 2, in a project whose organization enforces
`iam.disableServiceAccountKeyUpload`. `reader init` exited 0. The paste stopped at its
first policy check, printed farcast's own refusal and changed nothing, as step 2 below
says. Run unsilenced, the legacy check's spelling works. The managed one's works once
the Org Policy API, `orgpolicy.googleapis.com`, is on; where it is off, gcloud asks to
enable it, which the silenced script cannot. Steps 3 to 5 were not reached, and the key
id's format is still unverified. The same walk found that GKE's DNS endpoint refuses
farcast's cluster token, scoped to `userinfo.email` alone. So at 2482810 step 4's check,
and every read this reader serves, is refused against GKE. A fix built later that day
mints the reader's token with `cloud-platform` and `userinfo.email`, so a leaked one
works for every Google API the reader's IAM allows, not only the cluster. It is tested
against a local API server only. This step is still not walked.)* *(2026-11-24, ADR 0023's M2 walked: under [B], in the same organization, steps 1 and 2 ran again: `reader init` exited 0, and the paste stopped at its first policy check, the legacy constraint, with nothing changed. `farcast instances` then read the reader as not uploaded, and `reader grant` was refused `credential_missing` with nothing written. This step is still not walked.)*

1. Make the key and the script:

   ```bash
   ./farcast reader init "$INSTANCE"
   ```

   ✅ Expect, on stderr, `Paste this into Cloud Shell as a project Owner (sha256 …)`,
   and on stdout a script whose first line is `sh -s <<'FARCAST_READER'` and whose last
   is `FARCAST_READER`. `instances/$INSTANCE/` gains `reader.key` and `reader.crt`, both
   `0600`, and `metadata.yaml` gains `reader:` with
   `email: farcast-reader-<8 hex>@<project>.iam.gserviceaccount.com`.

   Where the organization enforces `iam.serviceAccountKeyExpiryHours`, run it with a
   `--days` no greater than the constraint's days, and at most 90. At `1h` or `8h` stop
   here: no reader key can be made.

2. Paste the whole script into Cloud Shell, signed in as an Owner of the project.
   ✅ Expect it to end with `farcast reader record validate --key-id <40 hex>`.
   If it says the project blocks service-account key upload, the reader cannot be set
   up in this project, and nothing was changed.

   Record what it printed. The spelling of its two policy checks and the output format
   it reads the key id from are unverified, and this is their first run: note whether
   either check printed an error, and whether the key id is 40 lowercase hex characters.

3. Record the id:

   ```bash
   ./farcast reader record "$INSTANCE" --key-id <id>
   ```

   ✅ Expect `metadata.yaml`'s `reader:` to gain `key_id`.

4. Grant and verify, **once the instance is connected** (Phase 2): the reader's RBAC
   has a RoleBinding in `farcast-system`, which `connect` creates and `install` does
   not. It asks in a terminal (`--yes` is refused), applies with kubectl as your active
   gcloud configuration, then reads as the reader:

   *(2026-11-15, ADR 0023 M2.5: it also needs step 2's installer key in the instance's
   `credentials.yaml`, which step 5's `--credentials` stored. It opens the instance's
   writer with that key, before it asks anything, to run the apply, though it makes no
   in-process call as the writer. Not yet walked.)*

   *(2026-11-18, ADR 0023 M2.7, built, not walked: the apply runs in-process as the
   instance's writer, with that key, and so mints its token. It needs no kubectl and no
   gcloud session.)*

   ```bash
   ./farcast reader grant "$INSTANCE"
   ```

   ✅ Expect a prompt naming the account and what it may read. After `y`, possibly
   `IAM changes typically take 2 minutes, and can take 7 minutes or longer; checking
   again until …`, then `✓ instance "validate"'s reader … reads the cluster, and was
   verified read-only` and `the reader … may now read farcast-system`.
   `metadata.yaml`'s `reader:` gains `granted_at` and `scope: metered`.

   Record how long the first read waited, and whether it was refused with a 401 or a
   403 while it waited. A refusal that says the reader `may` do something means it is
   not read-only, or that it reads beyond its RBAC: record which of the five questions was
   answered yes, and what role the paste granted.

5. At release (step 8), the result gains a `reader:` line naming the account and two
   Cloud Shell commands, the binding's removal first. Run both in Cloud Shell, then:

   ```bash
   gcloud iam service-accounts list --project "$PROJECT_ID" --format 'value(email)' | grep farcast-reader-
   ```

   ✅ Expect this instance's reader absent (another instance in the project may have
   its own). Record whether the binding's removal succeeded, and what
   `gcloud iam service-accounts keys list --iam-account <email>` says after the delete:
   that deleting an account deletes its keys is not verified.

## 8. Release — destroy the instance

`release` reads the provider, project, region, and credentials from the recorded
instance — you only name it:

```bash
./farcast release "$INSTANCE" --yes
```

This **blocks for ~3–5 minutes**: it waits until GCP reports the cluster gone, then deletes
the instance's image registry, and only then removes the local record. ✅ Expect:

```
✓ instance "validate" released
  provider:    gke
  cluster:     farcast-validate (deleted)
  registry:    farcast-validate (deleted)
  state:       removed
```

*(Corrected 2026-10-08: `release` used to return as soon as GCP **accepted** the delete,
leaving the cluster `STOPPING` for minutes afterwards. It now waits, bounded at 15
minutes. If that wait runs out or you interrupt it, the delete carries on in the cloud,
the command fails with "cluster … is still being deleted … re-run 'farcast release
validate'", and the instance record is **kept** so a re-run waits on that same delete.
On an instance that has keepers, `release` also wipes the bundle and leaf key of a keeper
installed on this machine for the instance — keeping its ledger — and names keepers
enrolled on other devices, which it cannot reach. Neither applies to this walk.)*

## 9. Verify teardown & clean up

```bash
gcloud container clusters list --project "$PROJECT_ID"     # farcast-validate absent
gcloud artifacts repositories list --project "$PROJECT_ID" --location "$REGION"   # farcast-validate absent
ls "$FARCAST_CONFIG_HOME/instances/"                        # 'validate' gone
```

✅ Expect: the cluster and the registry are already absent when `release` returns — no
`STOPPING` entry — and the local record is gone (no lingering charges). A cluster still
listed after a *successful* `release` is a finding, not a wait.

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
| `could not find default credentials` | You omitted `--credentials`. Pass `--credentials "$KEY"`. Do not reach for `gcloud auth application-default login`: this project never uses Application Default Credentials — FarCast gets the explicit service-account key, and `gcloud` runs under the operator's own configuration. *(Corrected 2026-10-08: this row used to suggest ADC.)* *(2026-11-15, ADR 0023 M2.5: `farcast install` itself now refuses a missing `--credentials`, with `--credentials is required: …`, before anything is created.)* |
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
drive the provider directly (this creates/deletes a real cluster too). The
harness turns client certificates and executable credential sources off in its
own process, as above (ADR 0023 M0, 2026-11-13):

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
- [ ] `farcast release` succeeds — it returns only once GCP reports the cluster gone — and removes local state.
- [ ] `gcloud` shows the cluster and the registry gone as soon as `release` returns — no `STOPPING` entry; no lingering billable resources. *(Corrected 2026-10-08: this used to expect `STOPPING` at first, absent a few minutes later.)*

If all six pass, Phase 1 is validated end-to-end and you're clear to start Phase 2.
