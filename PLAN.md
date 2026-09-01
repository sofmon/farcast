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
- This becomes the standard logging mechanism for all FarCast modules too

**Phase 0 deliverable** ✅ **achieved:** a manifest parser and an SDK with working logging. Every module built after this will import both.

---

## Phase 1 — Install

*Goal: `farcast install` provisions a FarCast instance on a cloud provider from scratch.*

### 1.1 FarSight CLI — scaffold

**Status: ✅ Complete** — command router, `version`/`help`, local config handling, and human/JSON output in [`farsight/cli/`](farsight/cli/README.md); `go test -race`, `go vet`, and `golangci-lint` clean.

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

**Status: ✅ Complete** — the mTLS tunnel, deny-by-default egress proxy, and per-instance CA in [`fatline/`](fatline/README.md); the allowlist is built from parsed manifest `external` declarations (a single shared allowlist until per-app identity lands in 4.4).

The network boundary must exist before any application traffic flows.

- TLS/mTLS tunnel between client and instance
- Outbound proxy with deny-by-default (drop all traffic not in allowlist)
- Allowlist fed from parsed manifest `external` declarations
- Basic connection lifecycle (establish, maintain, teardown)

### 2.2 Shrike — policy engine (minimal)

**Status: ✅ Complete** — the policy engine in [`shrike/`](shrike/README.md): it consumes FatLine's egress-decision stream and raises severity-ranked, de-duplicated alerts. Blocking stayed inline in FatLine (fail-closed); Shrike never sits in the data path and fails open. It runs in-process or as a Unix-socket sidecar — but the two-container Pod that co-schedules it with FatLine is Planck work (4.2), so `farcast connect` today deploys FatLine alone.

Shrike needs to exist alongside FatLine from the start, even if minimal.

- Read manifest `external` declarations
- Compare live outbound connections against declared endpoints
- Log violations (block + alert, don't just log)
- Shrike as a sidecar/middleware on FatLine — not a separate network hop

### 2.3 FarSight CLI — `farcast connect`

**Status: ✅ Complete** — [`farcast connect`](farsight/cli/README.md) mints the per-instance mTLS identity (the CA key stays local), deploys FatLine into the cluster via the kubeconfig ([ADR 0006](docs/adr/0006-connect-bootstrap-kubectl.md)), binds the public mTLS load-balancer carrier (~$18/month, confirmed against the cost limit — [ADR 0005](docs/adr/0005-fatline-data-plane-ingress.md)), and dials it to report status. Other CLI commands do not route through the tunnel yet — that arrives with the commands that need it. The default `--fatline-image` now comes from the instance's own registry (`system/fatline`, tagged with the CLI's version): `connect` re-ensures that registry, preflights the image, offers to compile it from a farcast checkout with the local Go toolchain and push it there when it is missing — no container engine anywhere — and deploys it pinned by digest ([ADR 0007](docs/adr/0007-instance-owned-image-registry.md)). `fatline/Containerfile` is retained as an independently verifiable reference build. [`farcast redeploy`](farsight/cli/README.md) shipped alongside it as the operational counterpart: it re-renders and re-applies FatLine's workload for an instance that is *already* connected, resolving the image through the same shared code, so a fix to the network boundary rolls out without a `release` and a reinstall. It never re-provisions the carrier and never re-mints the CA — those stay `connect`'s, so nothing new becomes billable and the public endpoint and trust root do not move — and it re-applies even when the image digest is unchanged, because the failure that motivated it lived in the workload template rather than in the image.

Wire the client side of FatLine into the CLI.

- `farcast connect <instance>` establishes a FatLine tunnel
- All subsequent CLI commands route through FatLine
- Connection status reporting

**Phase 2 deliverable** ✅ **achieved:** the operator can `farcast connect` to their instance through an encrypted tunnel. All traffic is deny-by-default: FatLine blocks undeclared connections, and Shrike monitors and alerts on them. [The Phase 2 runbook](docs/runbooks/phase-2-validation.md) passes end-to-end — Part A locally, and **Part B against real GKE on 2026-08-25**: the instance's own registry, an image compiled and pushed with no container engine, a digest-pinned deploy, the public mTLS carrier, the tunnel, an idempotent reconnect, and a teardown that left nothing billing.

---

## Phase 3 — Storage

*Goal: applications can store and retrieve encrypted data.*

### 3.1 DataSphere — provider adapter
Start with one object storage provider (matching the cloud from Phase 1).

- Provider interface (S3 or GCS)
- Encrypt-before-write / decrypt-after-read (AES-256-GCM or similar)
- Key management (operator-held keys, never stored with the cloud provider)
- Basic operations: put, get, list, delete

**Status: ✅ Complete** — the `Provider` interface and registry, the encrypting `Store`, envelope encryption with single-use DEKs, HMAC-tokenized object names, the operator-held keyring, and a GCS adapter in [`datasphere/`](datasphere/README.md), plus the `cmd/datasphere` harness. Blob format v1 is frozen by golden vectors whose HKDF and HMAC values were reproduced from an independent implementation. `go test -race`, `go vet`, `gofmt` and `golangci-lint` all clean; zero new vendored modules (31 before, 31 after — the two official GCS clients measured at +18 and +1). **Validated live against GCP on 2026-08-27:** all nine success criteria in [the Phase 3 runbook](docs/runbooks/phase-3-validation.md) passed, with `gcloud` independently confirming the cloud holds only opaque tokens and ciphertext. Both open wire questions are settled — object metadata *is* returned in the default list projection, and the `farcast-*` IAM condition works and does not block the credentials probe. Known gap: the run used a dedicated storage service account, while production puts the grant on the installer account; that combination lands with 3.3.

### 3.2 SDK — Storage implementation
Wire the `farcast.Storage()` interface to DataSphere.

- SDK calls DataSphere API
- Applications can store/retrieve files without knowing the cloud provider
- Encryption is transparent to the application

**Status: ✅ Complete** — the in-cluster keyholder (`datasphere serve`, a mode of the existing binary), the operator's unseal push, the frozen SDK storage contract, and `farcast storage deploy`/`state`/`unseal`/`seal` in [`farsight/cli/`](farsight/cli/README.md). Key material reaches the cluster only as a *scoped* bundle pushed from the operator's machine over the FatLine tunnel, sealed to one specific replica process answering a single-use challenge; the master KEK and the unrotatable name key never enter the cluster at all. A restarted replica comes back sealed. `go test -race`, `go vet` and `gofmt` clean across both modules; zero new vendored modules (31 before, 31 after) and the SDK module still has none. Live validation pending — see [the 3.2 runbook](docs/runbooks/phase-3-2-validation.md).

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

- Application registry (what's running, what's declared)
- Lifecycle management: deploy, start, stop, restart
- Health checking
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

- Parse manifest → create a K8s namespace named after the top-level `name`, then generate Deployment, Service, and ConfigMap resources for each entry in `apps[]` within that namespace
- Sensible defaults for resources (start conservative, TechnoCore will adapt later)
- Each app's container image comes from its `containerfile` path, using the app's `context` directory (or the Containerfile's directory when `context` is omitted), and lands in the instance's own registry under `app/<deployment>/<app>`, deployed by digest — the same registry, path convention, and pull grant `connect` already uses ([ADR 0007](docs/adr/0007-instance-owned-image-registry.md)); report a clear error if a referenced Containerfile is missing
- Unlike FarCast's own system images, app Containerfiles execute arbitrary build steps and so need a builder — which builder runs them is deferred to its own 4.2-era ADR
- Inject SDK as sidecar or init container

### 4.3 FarSight CLI — `farcast run`
The core command that makes FarCast useful.

- `farcast run github.com/user/repo` fetches the repo
- Reads `./farcast` manifest
- Displays external service declarations for operator review
- Operator approves → Planck deploys → TechnoCore monitors
- `farcast ps` lists running applications
- `farcast logs <app>` streams application logs
- `farcast costs` shows current spending, per-app breakdown, and distance to limit

### 4.4 Shrike — manifest enforcement for running apps
Extend Shrike to monitor per-application traffic.

- Each app's FatLine allowlist derived from its own entry in the manifest
- App A cannot use App B's external declarations
- Violation alerts tied to specific applications

**Phase 4 deliverable:** the full `install → bind → run → release` lifecycle works. Operators can deploy Git repositories, review their security declarations, and monitor running applications.

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
