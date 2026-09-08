# Execution Plan

A phased build order for FarCast. Each phase builds on the previous one and delivers a testable, usable increment. The principle: at the end of every phase, something real works.

---

## Phase 0 — Foundation

*Goal: establish the shared plumbing that every other module depends on.*

### 0.1 Manifest parser

**Status: ✅ Complete** — implemented in `manifest/parser/` with full validation and a comprehensive test suite.

The manifest is the contract between applications and the OS. Every module will need to read it. Build the parser first so all subsequent work has a shared schema to rely on.

- Define the `./farcast` YAML schema: top-level `name` + `apps[]`, where each app has `name`, `containerfile`, optional `context`, and optional `external` (see [`manifest/README.md`](manifest/README.md) for the full specification)
- Implement the Go parser library (`manifest/parser/`)
- Write comprehensive tests — this is the foundation, it must be solid
- Include validation: missing required fields, malformed YAML, unknown keys at any level, empty `apps` list, duplicate app names, DNS-label rules on names, relative-path safety on `containerfile`/`context` (no absolute paths, no `..`), duplicate hosts within a single app's `external` list

### 0.2 SDK — Go (core interfaces)

**Status: ✅ Complete** — interfaces, capability accessors, context helpers, and error sentinels in [`sdk/go/`](sdk/go/README.md).

Define the Go SDK interfaces before any implementation exists. These are the "syscall" signatures that applications will use and that modules will implement behind the scenes.

- `farcast.Log()` — structured logging (first concrete capability)
- `farcast.Config()` — read environment defaults and app configuration
- `farcast.Storage()` — interface for DataSphere (read/write/list/delete)
- `farcast.Net()` — interface for FatLine (outbound HTTP, connection status)
- `farcast.AI()` — interface for AllThing (chat, completion)
- All interfaces only — no implementations yet. These define the contract.

### 0.3 SDK — Logging implementation

**Status: ✅ Complete** — structured `slog`-based JSON logger in [`sdk/go/`](sdk/go/README.md); `go test -race`, `go vet`, and `golangci-lint` all clean.

First real SDK implementation. Logging is the simplest capability and immediately useful for every subsequent phase.

- Structured JSON logging to stdout
- Log levels (debug, info, warn, error)
- Context propagation (instance ID, app name, request ID)
- This is intended to become the standard logging mechanism for FarCast modules too — **not yet adopted**: through Phase 4.4 every module logs via `log/slog` directly and none imports `sdk/go`

**Phase 0 deliverable** ✅ **achieved:** a manifest parser and an SDK with working logging. Every module built after this imports the manifest parser; the SDK is not imported by any of them yet — the root `go.mod` does not depend on `github.com/sofmon/farcast/sdk/go`.

---

## Phase 1 — Install

*Goal: `farcast install` provisions a FarCast instance on a cloud provider from scratch.*

### 1.1 FarSight CLI — scaffold

**Status: ✅ Complete** — command router, `version`/`help`, local config handling, and human/JSON output in [`farsight/cli/`](farsight/cli/README.md); `go test -race`, `go vet` and `golangci-lint` clean — the last against a repository `.golangci.yml`, added on 2026-09-08 so the bar is the same everywhere rather than whatever the operator's installed linter checks this month.

Build the CLI framework. No commands work yet, but the structure is in place.

- CLI argument parsing and subcommand routing
- `farcast version`, `farcast help`
- Configuration file handling (where cloud credentials are stored locally)
- Output formatting (human-readable and JSON modes)

### 1.2 Planck — first cloud provider adapter

**Status: ✅ Complete** — GCP first: a GKE Autopilot adapter behind the provider interface in [`planck/`](planck/README.md) — credential validation, create with readiness wait, status, destroy — provisioning a private control plane per [ADR 0003](docs/adr/0003-gke-autopilot.md) and [ADR 0004](docs/adr/0004-private-control-plane.md). The adapter also realizes the optional registry capability: the instance's own Artifact Registry repository, ensured and torn down alongside the cluster ([ADR 0007](docs/adr/0007-instance-owned-image-registry.md)).

Pick one cloud provider to start (GCP or AWS — whichever you're most comfortable testing against). Implement just enough to create and destroy a managed K8s cluster.

- Cloud credential validation
- Create a managed K8s cluster with sensible defaults
- Wait for cluster readiness
- Destroy/cleanup
- Provider interface so the second provider is easy to add later

### 1.3 FarSight CLI — `farcast install`

**Status: ✅ Complete** — the guided install flow in [`farsight/cli/`](farsight/cli/README.md): provider selection, credential validation, the mandatory cost limit (no default, no "unlimited"), Planck provisioning, the instance's own image registry, a post-create health check, and locally stored credentials, metadata, and cost limit.

Wire the CLI to Planck. The guided install flow:

- `farcast install` starts the interactive process
- Operator selects cloud provider
- Operator provides credentials (access key, project ID, etc.)
- **Operator sets a cost limit (mandatory — install will not proceed without it)**
- Planck provisions the K8s cluster
- Basic health check confirms the instance is alive
- Credentials, instance metadata, and cost limit stored locally

### 1.4 FarSight CLI — `farcast release`

**Status: ✅ Complete** — `farcast release <instance>` with confirmation prompt, image-registry teardown, and local-config cleanup in [`farsight/cli/`](farsight/cli/README.md). Known limitation: release returns once GCP *accepts* the delete — the cluster keeps deleting (`STOPPING`) for several minutes after the command reports "(deleted)".

The counterpart to install — tear everything down.

- `farcast release <instance>` destroys the cloud resources
- Confirmation prompt (this is destructive)
- Clean up local configuration

**Phase 1 deliverable** ✅ **achieved:** `farcast install` creates a real K8s cluster on a cloud provider. `farcast release` destroys it (asynchronously — GCP finishes the delete after the command returns). The operator has a working instance (empty, but alive). Validated live against GCP: all six success criteria in [the Phase 1 runbook](docs/runbooks/phase-1-validation.md) passed.

---

## Phase 2 — Networking & Security Boundary

*Goal: establish the encrypted network boundary before anything runs on the instance.*

### 2.1 FatLine — core proxy

**Status: ✅ Complete** — the mTLS tunnel, deny-by-default egress proxy, and per-instance CA in [`fatline/`](fatline/README.md); the allowlist is built from parsed manifest `external` declarations — a single shared allowlist at this point, replaced by per-application policy in 4.4.

The network boundary must exist before any application traffic flows.

- TLS/mTLS tunnel between client and instance
- Outbound proxy with deny-by-default (drop all traffic not in allowlist)
- Allowlist fed from parsed manifest `external` declarations
- Basic connection lifecycle (establish, maintain, teardown)

### 2.2 Shrike — policy engine (minimal)

**Status: ✅ Complete** — the policy engine in [`shrike/`](shrike/README.md): it consumes FatLine's egress-decision stream and raises severity-ranked, de-duplicated alerts. Blocking stayed inline in FatLine (fail-closed); Shrike never sits in the data path and fails open. It runs in-process or as a Unix-socket sidecar — but the two-container Pod that co-schedules it with FatLine was scoped to Planck (4.2) and **did not ship there** — 4.2 is complete and renders no Shrike container — so `farcast connect` deploys FatLine alone and nothing yet deploys Shrike.

Shrike needs to exist alongside FatLine from the start, even if minimal.

- Read manifest `external` declarations
- Compare live outbound connections against declared endpoints
- Log violations (block + alert, don't just log)
- Shrike as a sidecar/middleware on FatLine — not a separate network hop

### 2.3 FarSight CLI — `farcast connect`

**Status: ✅ Complete** — [`farcast connect`](farsight/cli/README.md) mints the per-instance mTLS identity (the CA key stays local), deploys FatLine into the cluster via the kubeconfig ([ADR 0006](docs/adr/0006-connect-bootstrap-kubectl.md)), binds the public mTLS load-balancer carrier (~$18/month, confirmed against the cost limit — [ADR 0005](docs/adr/0005-fatline-data-plane-ingress.md)), and dials it to report status. The commands that need the tunnel now use it — `farcast storage state`, `unseal` and `seal` reach the in-cluster keyholder through it — while the rest of the CLI talks to the API server directly. The default `--fatline-image` now comes from the instance's own registry (`system/fatline`, tagged with the CLI's version): `connect` re-ensures that registry, preflights the image, offers to compile it from a farcast checkout with the local Go toolchain and push it there when it is missing — no container engine anywhere — and deploys it pinned by digest ([ADR 0007](docs/adr/0007-instance-owned-image-registry.md)). `fatline/Containerfile` is retained as an independently verifiable reference build. [`farcast redeploy`](farsight/cli/README.md) shipped alongside it as the operational counterpart: it re-renders and re-applies FatLine's workload for an instance that is *already* connected, resolving the image through the same shared code, so a fix to the network boundary rolls out without a `release` and a reinstall. It never re-provisions the carrier and never re-mints the CA — those stay `connect`'s, so nothing new becomes billable and the public endpoint and trust root do not move — and it re-applies even when the image digest is unchanged, because the failure that motivated it lived in the workload template rather than in the image.

Wire the client side of FatLine into the CLI.

- `farcast connect <instance>` establishes a FatLine tunnel
- All subsequent CLI commands route through FatLine
- Connection status reporting

**Phase 2 deliverable** ✅ **achieved:** the operator can `farcast connect` to their instance through an encrypted tunnel. All traffic is deny-by-default: FatLine blocks undeclared connections and logs every decision itself; Shrike's monitoring and alerting is proven locally over the sidecar wire (Part A) but is **not yet co-scheduled inside a connected instance**. [The Phase 2 runbook](docs/runbooks/phase-2-validation.md) passes end-to-end — Part A locally, re-run on 2026-09-08 after being rewritten for per-application identity, and **Part B against real GKE on 2026-08-25**: the instance's own registry, an image compiled and pushed with no container engine, a digest-pinned deploy, the public mTLS carrier, the tunnel, an idempotent reconnect, and a teardown that left nothing billing.

---

## Phase 3 — Storage

*Goal: applications can store and retrieve encrypted data.*

### 3.1 DataSphere — provider adapter
Start with one object storage provider (matching the cloud from Phase 1).

- Provider interface (S3 or GCS)
- Encrypt-before-write / decrypt-after-read (AES-256-GCM or similar)
- Key management (operator-held keys, never stored with the cloud provider)
- Basic operations: put, get, list, delete

**Status: ✅ Complete** — the `Provider` interface and registry, the encrypting `Store`, envelope encryption with single-use DEKs, HMAC-tokenized object names, the operator-held keyring, and a GCS adapter in [`datasphere/`](datasphere/README.md), plus the `cmd/datasphere` harness. Blob format v1 is frozen by golden vectors whose HKDF and HMAC values were reproduced from an independent implementation. `go test -race`, `go vet`, `gofmt` and `golangci-lint` all clean; zero new vendored modules (31 before, 31 after — the two official GCS clients measured at +18 and +1). **Validated live against GCP on 2026-08-27:** all nine success criteria in [the Phase 3 runbook](docs/runbooks/phase-3-validation.md) passed, with `gcloud` independently confirming the cloud holds only opaque tokens and ciphertext. Both open wire questions are settled — object metadata *is* returned in the default list projection, and the `farcast-*` IAM condition works and does not block the credentials probe. Scope of that run: it used a dedicated storage service account, while production puts the grant on the installer account. The 3.3 pass exercised that combination against GCP and closed the gap.

### 3.2 SDK — Storage implementation
Wire the `farcast.Storage()` interface to DataSphere.

- SDK calls DataSphere API
- Applications can store/retrieve files without knowing the cloud provider
- Encryption is transparent to the application

**Status: ✅ Complete** — the in-cluster keyholder (`datasphere serve`, a mode of the existing binary), the operator's unseal push, the frozen SDK storage contract, and `farcast storage deploy`/`state`/`unseal`/`seal` in [`farsight/cli/`](farsight/cli/README.md). Key material reaches the cluster only as a *scoped* bundle pushed from the operator's machine over the FatLine tunnel, sealed to one specific replica process answering a single-use challenge; the master KEK and the unrotatable name key never enter the cluster at all. A restarted replica comes back sealed. `go test -race`, `go vet` and `gofmt` clean across both modules; zero new vendored modules (31 before, 31 after) and the SDK module still has none. **Partially validated live:** `storage deploy` and `unseal` have been exercised against real GKE on every Phase 4 walk, since 4.1, 4.2 and 4.3 each require a working keyholder as a prerequisite — a sealed replica that never becomes ready, the challenge-response unseal, and a restart resealing itself have all been observed. [The 3.2 runbook](docs/runbooks/phase-3-2-validation.md) itself was walked live against GKE twice on 2026-08-31, including the deliberate `storage seal --hold` and its non-survival of a restart; what remains unwalked there is the node-upgrade scenario. The 4.3 walk also surfaced a defect in the bring-up order it shares with 3.3 — an object written to `app/` before the `app` scope existed became unreachable by name once `unseal` minted that scope, and the error blamed data integrity when the cause was key-space ownership. **Fixed on 2026-09-08** ([ADR 0008](docs/adr/0008-in-cluster-key-delivery.md) decision 9: a scope is minted with the keyring, not at the first unseal) and confirmed live on the 4.4 walk.

**Unblocked by [ADR 0008](docs/adr/0008-in-cluster-key-delivery.md) (accepted 2026-08-28):** an in-cluster keyholder that holds only *derived per-scope* material, in memory, pushed by the operator over the FatLine tunnel — sealed by default after any restart. The master KEK and the unrotatable name key never enter the cluster. The ADR proves that autonomous recovery is impossible under the invariant, states the availability cost plainly rather than engineering around it, and fixes the one irreversible piece now: the SDK's `ErrStorageSealed` contract, which every application ever written inherits. 3.2 ships the keyholder with two replicas and a PodDisruptionBudget, so the common restarts — a single OOM, one node's auto-repair, a rollout — do not seal storage at all.

### 3.3 FarSight CLI — storage commands
Operator tools for managing storage.

- `farcast storage ls`
- `farcast storage cp <local> <remote>` and vice versa
- Storage usage reporting

**Status: ✅ Complete** — `farcast storage ls`/`cp`/`rm`/`usage` and `storage key list`/`export`/`import`/`rotate`/`rekey` in [`farsight/cli/`](farsight/cli/README.md), on DataSphere's new chunked **blob format v2** (streaming, arbitrary size) with a hand-rolled GCS resumable-upload path and ranged reads. The keyring is minted at first storage use; the bucket is minted, recorded-before-create and ensured lazily; and `farcast release` now refuses while the bucket holds data unless `--delete-data` is given. `go test -race`, `go vet`, `gofmt` and `golangci-lint` clean; zero new vendored modules (31 before, 31 after). v2's golden vectors were reproduced from an independent implementation before being frozen. **Validated live against GCP on 2026-08-27:** a 64 MiB round trip through `farcast storage cp` byte-exact over a real resumable upload, ranged reads, `ObjectInfo.Created` from a real listing, the teardown gate refusing while data remains (and still working with the keyring removed), and the production credential shape — the installer service account carrying container, Artifact Registry and conditional storage grants together. See [the Phase 3 runbook](docs/runbooks/phase-3-validation.md).

**Phase 3 deliverable:** applications and operators can store and retrieve files. Everything is encrypted at rest. The cloud provider sees only encrypted blobs under opaque names — and their sizes, count, tree shape and access times, which [DataSphere](datasphere/README.md#what-the-cloud-still-sees) states rather than hides.

---

## Phase 4 — Run Applications

*Goal: `farcast run` deploys a Git repository as a running application.*

### 4.1 TechnoCore — instance lifecycle & cost monitoring
The kernel comes online. It manages what runs inside the instance and enforces cost limits from day one.

**Status: ✅ Complete** — the in-cluster kernel in [`technocore/`](technocore/README.md) and `farcast kernel deploy`/`meter`/`confirm` in [`farsight/cli/`](farsight/cli/README.md), designed by [ADR 0009](docs/adr/0009-technocore-kernel-and-cost-metering.md): a stateless reconciler over a hand-rolled stdlib Kubernetes client, the two-signal ledger (`expected` enforces, `confirmed` corrects within a clamp), per-app attribution, threshold and projection warnings, the floor check at deploy time, and a protective shutdown that stops applications only and reports the instance floor rather than acting on it. Zero new vendored modules (31 before, 31 after). **Validated live against GKE on 2026-09-01:** criteria 1–11 in [the 4.1 runbook](docs/runbooks/phase-4-1-validation.md) passed after two defects were found and fixed, and criterion 12 was deferred by decision. **Open:** criterion 12, reconciliation against a real invoice — every cost figure in FarCast remains modelled from a published rate card and unverified against a bill.

- Application registry (what's running, what's declared)
- Lifecycle management: **stop only** — a cost shutdown scales an application to zero; deploying is `farcast run` (4.3), and nothing in the kernel starts or restarts a stopped application
- Health checking — **not built in 4.1**; readiness is surfaced by `farcast ps` (4.3), and the kernel renders no probes
- Basic resource monitoring (CPU/memory observation — not yet adaptive)
- **Cost monitoring on two figures ([ADR 0009](docs/adr/0009-technocore-kernel-and-cost-metering.md)) — `expected`, metered locally from Pod requests in real time, and `confirmed`, the provider's own number for a closed window, pulled by the operator's machine and pushed in**
- **`expected` enforces, `confirmed` corrects — the correction is clamped and a missing `confirmed` is never read as zero, so the late external signal cannot disable the guard**
- **Per-application cost attribution — break down spending by app; `confirmed` is instance-level, so attribution always comes from `expected`**
- **Cost threshold warnings — alert operator at 50%, 75%, 90% of limit, plus a projection warning as soon as the burn rate implies the limit will be reached before the period ends**
- **Floor check at deploy time — a limit below the instance's own standing cost is reported when it is set, not discovered at 90%**
- **Protective shutdown — when the limit is reached, stop highest-cost apps first; if spending cannot be contained, stop all apps, keep TechnoCore alive to report status, and report the instance floor with the levers that remain rather than acting on them**
- **Last-to-die classification for `datasphered` and FatLine** ([ADR 0008](docs/adr/0008-in-cluster-key-delivery.md)) — a cost shutdown that stops FatLine makes storage impossible to unseal while the instance still bills
- **FatLine gets the PodDisruptionBudget and second replica `datasphered` already has** — every unseal and every keeper reseed rides that tunnel, so a single drained replica is the floor on recovery

### 4.2 Planck — manifest-to-workload translator
Translate a `./farcast` manifest into K8s resources.

**Status: ✅ Complete** — [`planck/translate`](planck/README.md) renders a namespace plus a ConfigMap, Deployment, Service and NetworkPolicy per app, and [`planck/build`](planck/README.md) is the ephemeral Kaniko Job that turns a Containerfile into an image *inside the instance* ([ADR 0010](docs/adr/0010-application-image-builds.md)), driven by `farcast build`. Zero new vendored modules. **Validated live against GKE on 2026-09-01:** all ten criteria in [the 4.2 runbook](docs/runbooks/phase-4-2-validation.md) passed after **seven** defects were found and fixed — including an application with no route out, and metering a routine redeploy silently erased. Three claims no unit test could make were settled there: Kaniko is admissible on Autopilot, the Workload Identity push grant works as printed, and the digest arrives through the Pod's termination message.

- Parse manifest → create a K8s namespace named after the top-level `name`, then generate Deployment, Service, and ConfigMap resources for each entry in `apps[]` within that namespace
- Sensible defaults for resources (start conservative, TechnoCore will adapt later)
- Each app's container image comes from its `containerfile` path, using the app's `context` directory (or the Containerfile's directory when `context` is omitted), and lands in the instance's own registry under `app/<deployment>/<app>`, deployed by digest — the same registry, path convention, and pull grant `connect` already uses ([ADR 0007](docs/adr/0007-instance-owned-image-registry.md)); report a clear error if a referenced Containerfile is missing
- Unlike FarCast's own system images, app Containerfiles execute arbitrary build steps and so need a builder — settled by [ADR 0010](docs/adr/0010-application-image-builds.md): an ephemeral Kaniko Job **inside the instance**, so that running and updating software is not tied to one prepared machine. `farcast build` drives it; 4.3's `run` reads the manifest and calls the same path for each app
- The SDK contract reaches the container as environment — a per-app ConfigMap plus its egress Secret, consumed with `envFrom`; **no sidecar or init container is injected**

### 4.3 FarSight CLI — `farcast run`
The core command that makes FarCast useful.

**Status: ✅ Complete** — `farcast run`, `ps`, `logs` and `costs` in [`farsight/cli/`](farsight/cli/README.md), with [`planck/fetch`](planck/README.md) reading the manifest inside the instance ([ADR 0010](docs/adr/0010-application-image-builds.md) decision 11) and the kernel publishing its own observation so nothing models spending twice. Zero new vendored modules. **Validated live against GKE on 2026-09-08:** all thirteen criteria in [the 4.3 runbook](docs/runbooks/phase-4-3-validation.md) passed after three defects were found and fixed. The walk also broke a ratified decision: the maintained builder [ADR 0010](docs/adr/0010-application-image-builds.md) decision 10 chose was withdrawn from public access seven days after it was ratified, and [ADR 0011](docs/adr/0011-build-toolchain-mirroring.md) is the answer — reviewed third-party images are mirrored into the instance's own registry, and the builder is Google's archived Kaniko, pinned, **explicitly a stopgap with the exits named**.

- `farcast run <instance> github.com/user/repo` — **the instance fetches the repo, not this machine** ([ADR 0010](docs/adr/0010-application-image-builds.md) decision 6). An ephemeral Job clones at the ref, prints `./farcast`, and reports the resolved commit and a digest of the manifest it parsed; decision 11 gives that read its own workload, with a ServiceAccount that has no registry grant and a policy that blocks the metadata server the builder is allowed
- Reads `./farcast` manifest — `--manifest <path>` for a repository that keeps it elsewhere; paths inside stay repository-relative either way
- **Displays external service declarations for operator review**, alongside the commit and manifest digest, which are what a machine that cannot reach the repository can check out of band later
- Operator approves → **every app is built pinned to the commit that was read**, one build at a time, then Planck deploys → the namespace is added to what TechnoCore meters, with its RoleBinding, in the same apply
- The two third-party images this puts in the instance (Kaniko, and something with git in it) are digest-pinned, reviewed once, and **recorded against the instance** so later runs need no flags
- `farcast ps` lists running applications, hiding the instance's own machinery without `--all`; 0 replicas is reported as stopped rather than broken, because that is what a protective shutdown leaves behind
- `farcast logs <app>` streams application logs, finding the namespace by name across what the kernel meters
- `farcast costs` shows current spending, per-app breakdown, and distance to limit — **read from the kernel's own checkpoint rather than modelled a second time**, so what is reported is what enforcement is acting on, and a missing billing feed is never shown as a confirmed zero

### 4.4 Shrike — manifest enforcement for running apps
Extend Shrike to monitor per-application traffic.

**Status: ✅ Complete** — per-application egress in [`fatline/policy`](fatline/README.md), designed by [ADR 0013](docs/adr/0013-per-application-egress-identity.md): an application's identity is a **credential it holds**, not a position it occupies, so the separation is enforced by FarCast's own code on any Kubernetes rather than by a NetworkPolicy feature that EKS leaves off by default and AKS fixes at cluster creation. Zero new vendored modules. **Validated live 2026-09-08** — see [the 4.4 runbook](docs/runbooks/phase-4-4-validation.md) and the findings from walking it, which fixed two defects a green unit suite could not see: FatLine's log named no application at all, and two manifests in one repository collided on the fetch Job name. The walk's remaining finding — `metadata.yaml` losing concurrent writes — is now fixed too: a save merges its own changes onto a newer record rather than over it, and refuses only a genuine same-field collision. **Re-walked the same day against a second instance, and the last open claim is now proven**: the fixture, rebuilt with a client that can speak CONNECT, reached its declared host by itself — `curl 8.14.1 (x86_64-alpine-linux-musl)` given nothing but `FARCAST_FATLINE_PROXY` returned `200`, while an undeclared host and a neighbour's host both came back `403` naming the application. The second walk also verified both defect fixes from a cold instance rather than a mid-walk redeploy, measured policy propagation in both directions (a grant bites in 28s, a revocation in 41s — the revoking direction had never been walked), and found two commands that report failure after already having had an effect. This section also broke Part A of [the Phase 2 runbook](docs/runbooks/phase-2-validation.md) — FatLine's `--manifest` became `--policy`, and an unidentified caller is refused rather than checked against a shared allowlist — which went unnoticed until PLAN was audited afterwards. **Part A has since been rewritten for per-application identity and passes**: it now runs two applications and shows locally, with no cloud, that one cannot use the other's declaration and that an unidentified caller is `unknown_app`. Fixing it found the same attribution gap in Shrike that the walk found in FatLine: the status JSON named the application and the alert stream did not.

Building it found something bigger than the section described: **the declarations never reached the enforcement point at all.** `fatline/deploy` passed no manifest, so a deployed FatLine's allowlist was empty and applications could reach nothing outside the cluster — invisible through both earlier walks, because the example application declares no external hosts.

- Each app's FatLine allowlist derived from its own entry in the manifest — `farcast run` writes an instance-wide policy document, **merged** with every other deployment's, and FatLine reloads it from a mounted ConfigMap without restarting the network boundary
- App A cannot use App B's external declarations — a caller FatLine cannot identify is refused as `unknown_app` rather than falling back to a shared list, because there is no longer a shared list to fall back to; FatLine's `flattenExternal` is deleted (Shrike's own copy still flattens the manifest for its declared-host contract)
- Violation alerts tied to specific applications — Shrike keys violations by application as well as by reason and host, since two apps denied the same host are two problems with two different remedies

**Phase 4 deliverable** ✅ **achieved:** the full `install → connect → run → release` lifecycle works — a Git repository the operator's machine never clones is read, reviewed, built and run inside the instance, with spending metered against the limit and each application confined to the hosts it declared. All four sections are now validated live, 4.4 on 2026-09-08. The **unmodified-application** claim was proven on a second 4.4 walk the same day. **One claim remains unproven rather than unmet:** invoice reconciliation, open since 4.1 and still the largest unverified claim in the project — it needs a day of real billing, which is calendar time rather than work.

---

## Phase 5 — Intelligent Resource Management

*Goal: TechnoCore becomes adaptive — applications no longer need to think about resources.*

### 5.1 TechnoCore — monitoring & metrics
Deep observability into running applications.

- CPU, memory, network I/O, request latency metrics collection
- Historical data for trend analysis
- Per-application resource profiles

### 5.2 TechnoCore — adaptive scaling
The "intelligent" part of the OS.

- Detect under/over-provisioned applications
- Auto-adjust CPU and memory limits based on observed behaviour
- Horizontal scaling (replica count) based on load patterns
- Graceful scaling (no disruption to running requests)

### 5.3 SDK — Config & Secrets
Complete the SDK's environment capabilities.

- `farcast.Config()` implementation — read environment defaults
- `farcast.Secrets()` — secure secret storage and retrieval
- Secrets encrypted at rest via DataSphere, never in plaintext in K8s

### 5.4 FarSight CLI — `farcast keeper` (desktop)
Unattended recovery on the operator's own hardware, per the keeper fleet planned in [ADR 0008](docs/adr/0008-in-cluster-key-delivery.md): an operator-owned device that re-seeds a restart-sealed `datasphered` without waking anyone. Running FarCast as a server requires at least two enrolled keeper devices — the product stance the ADR records.

- `farcast keeper enroll` / `revoke` / `status` — each device gets its own `farcast://<instance>/keeper/<device>` leaf from the operator-held CA, authorized for reseed and status only
- The keeper daemon is a mode of the same `farcast` binary — no new machine dependencies
- Outbound-only: the keeper dials FatLine, never listens; every reseed lands in a local append-only ledger kept off every cloud-backup path by construction, and `keeper status` reconciles the fleet's ledgers against the cluster's witnessed restarts — detection by audit, flagged on divergence
- The bundle is a distinct artifact from the keyring — derived scope keys and IDs only, provisioned from the operator's machine (armored, in the `key export` pattern), never through the instance; the master KEK and the name key are never on the keeper path. Bundle, leaf key and ledger are device-bound and excluded from OS backup — a platform that cannot guarantee this cannot be a keeper
- Reseed budget: beyond the expected restart cadence the keeper refuses without interactive confirmation
- A deliberate `seal` is an operator hold — a keeper never clears it
- Prerequisite: 4.1's FatLine PDB and second replica — no keeper can re-seed through a drained tunnel
- **Planned ADR — thin-device storage through the keyholder.** [ADR 0010](docs/adr/0010-application-image-builds.md) makes *deployment* machine-independent; storage is the remaining capability that still requires the keyring locally, because `farcast storage` encrypts client-side. Routing it through the in-cluster keyholder — which already holds the scope keys and already serves exactly this to applications — would let a tablet or phone read and write storage with only an mTLS leaf. That keeps the operator's stated goal (same capability from any device) without putting the **unrotatable name key** on every device, which `storage rekey` could never undo. The ADR must settle what the keyholder will serve to an operator leaf versus an application one, and what that does to [ADR 0008](docs/adr/0008-in-cluster-key-delivery.md)'s solicitation-oracle analysis.

**Phase 5 deliverable:** TechnoCore actively manages resources. Applications start with defaults and TechnoCore adjusts automatically. The manifest stays minimal because the OS is smart enough to figure it out. And the first keeper stands watch: a second operator device clears a restart-seal unattended.

---

## Phase 6 — AI Layer

*Goal: AllThing provides AI capabilities to the system and applications.*

### 6.1 AllThing — provider adapter
Abstraction over cloud AI services.

- Provider interface (Gemini, Claude, OpenAI)
- Chat completion API
- Streaming support
- Model selection and fallback

### 6.2 AllThing — chat interface via FarSight
First user-facing AI feature.

- Chat endpoint on FarSight server
- CLI: `farcast chat` for terminal-based AI conversation
- Conversation context management
- Route through FatLine (AI provider traffic must be declared)

### 6.3 SDK — AI implementation
Wire `farcast.AI()` to AllThing.

- Applications can call AI through the SDK
- Provider-agnostic — app doesn't know if it's Gemini or Claude
- Usage tracking and rate limiting

### 6.4 AllThing — system integration
AI as an internal capability for FarCast itself.

- TechnoCore can query AllThing for resource decisions
- Shrike can use AllThing for traffic anomaly analysis
- Foundation for future AI-native features

**Phase 6 deliverable:** AI is available as a platform capability. Users can chat through FarSight, applications can call AI through the SDK, and internal modules can use AI for smarter decisions.

---

## Phase 7 — FarSight GUI

*Goal: the tiling browser interface — FarCast becomes visual.*

### 7.1 FarSight client — Electron shell
The desktop app scaffold.

- Electron app with basic window management
- FatLine integration (all traffic proxied through the instance)
- Two modes: Install wizard and Connected view

### 7.2 FarSight server — UX composition
Server-side component for assembling the interface.

- Application tile registry (which apps are running, their web endpoints)
- Session management
- Layout state persistence

### 7.3 FarSight client — tiling window manager
The core UX.

- Tiling layout engine (split, resize, rearrange)
- Each tile renders an application's web interface
- Tab management
- AllThing chat as a built-in tile

### 7.4 FarSight client — install wizard (GUI)
GUI version of `farcast install`.

- Guided cloud provider setup
- Credential input
- Progress reporting
- Instance management dashboard

### 7.5 FarSight mobile — the keeper in your pocket
The first mobile FarSight is deliberately small: it makes a phone a keeper ([ADR 0008](docs/adr/0008-in-cluster-key-delivery.md)) before it grows any GUI ambition.

- Keeper duty within mobile background-execution limits: outbound-only checks, push-woken where the OS allows (the push is a contentless doorbell — in the availability path, never the key path — and a redundant nudge over the jittered poll, never the sole wake path)
- The bundle held in the no-user-presence protection class, hardware-backed and excluded from iCloud/Google backup by construction — a phone that cannot guarantee the exclusion cannot be a keeper; a presence-gated full keyring copy is a separate, optional decision
- Reseed notifications and an emergency seal action
- Stated honestly: a phone improves the odds of a short sealed window, it is not an SLO — a mains-powered desktop keeper anchors the fleet

**Phase 7 deliverable:** users can download the "farcast" app, install FarCast to a cloud provider via a GUI, and interact with running applications through a tiling browser — all traffic proxied through FatLine. The first mobile FarSight ships alongside it — a keeper before it is a GUI.

---

## Phase 8 — Multi-Provider & Hardening

*Goal: second cloud provider, production hardening, SDK for Node.js and Python.*

### 8.1 Planck — second cloud provider
Add the other major provider (AWS if you started with GCP, or vice versa).

- Implement the provider interface for the second cloud
- Ensure `farcast install` works identically across both
- Cross-provider testing

### 8.2 DataSphere — second storage provider
Match the second compute provider with its storage equivalent.

### 8.3 AllThing — second AI provider
Add a second AI provider to validate the abstraction.

### 8.4 SDK — Node.js and Python
Port the SDK interfaces and implementations.

- Node.js SDK (`sdk/node/`)
- Python SDK (`sdk/python/`)
- Same interface contract as Go, language-idiomatic wrappers

### 8.5 Hardening
Production readiness across all modules.

- Error handling and recovery
- Graceful degradation
- Comprehensive test coverage
- Security audit of encryption implementations
- Documentation completion for all module READMEs

**Phase 8 deliverable:** FarCast runs on two cloud providers, supports three SDK languages, and is hardened for production use.

---

## Dependency Graph

```
Phase 0: Manifest Parser → SDK Interfaces → SDK Logging
              ↓                   ↓
Phase 1: CLI Scaffold → Planck (1st provider) → farcast install/release
              ↓
Phase 2: FatLine (proxy) → Shrike (minimal) → farcast connect
              ↓
Phase 3: DataSphere (1st provider) → SDK Storage → storage CLI
              ↓
Phase 4: TechnoCore → Planck (translator) → farcast run → Shrike (per-app)
              ↓
Phase 5: TechnoCore (adaptive) → SDK Config/Secrets → farcast keeper (desktop)
              ↓
Phase 6: AllThing (1st provider) → Chat → SDK AI → System integration
              ↓
Phase 7: FarSight client (Electron) → FarSight server → Tiling UI → Mobile keeper
              ↓
Phase 8: 2nd cloud provider → 2nd storage → 2nd AI → Node/Python SDK → Hardening
```

---

## Principles for Execution

1. **Each phase is testable.** Don't move to the next phase until the current one works end-to-end.
2. **Start with one cloud provider.** Get everything working on one before abstracting to two. The provider interface exists from day one, but only one adapter is needed initially.
3. **CLI before GUI.** The CLI is faster to build, faster to test, and validates all the backend work before the Electron app adds complexity.
4. **Security from Phase 2, not Phase 8.** FatLine and Shrike come online before any application runs. Security is not a feature — it's the foundation.
5. **SDK drives the API design.** What feels right to an application developer using the SDK should drive how the backend modules expose their capabilities.

---

*This plan is a living document. Update it as phases complete and new insights emerge.*
