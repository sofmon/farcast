# AGENTS.md

Context for AI agents working on this codebase.

## Core Philosophy

FarCast is a cloud operating system where privacy is the foundational principle. Every design decision flows from one question: does the cloud provider, the network, or any third party gain visibility into the user's data or behaviour? If yes, the design is wrong.

## Architectural Principles

**Never reinvent cloud infrastructure.** Cloud providers have mature compute (K8s), storage (S3/GCS), networking, and AI services. FarCast wraps these with a sovereign abstraction layer — it doesn't replace them. Planck abstracts compute, DataSphere abstracts storage, FatLine abstracts networking, AllThing abstracts AI.

**Zero central dependency.** Every FarCast instance is fully autonomous. There is no central registry, no update server, no phone-home mechanism. Instances do not announce their existence to anyone. Discovery between instances happens out-of-band — operators exchange FatLine addresses manually or through their own private channels.

**Deny by default.** All connections — inbound and outbound — are denied unless explicitly declared in an application's `./farcast` manifest. The operator reviews external access declarations before running an app. FatLine enforces the boundary, Shrike monitors compliance at runtime.

**The cloud provider is blind to content.** FatLine encrypts all traffic in transit. DataSphere encrypts all data at rest. The cloud provider carries encrypted packets and stores encrypted blobs — it never sees plaintext or a logical name. It does still see metadata: how many objects there are, how large each one is, the shape of the namespace, and when things are read and written. Say "blind to content" rather than "blind"; the difference is documented in [DataSphere's *What the cloud still sees*](datasphere/README.md#what-the-cloud-still-sees), and overstating it is the one thing this project treats as worse than not promising at all.

**Cost control is mandatory, not optional.** Every instance must have a cost limit set at creation — there is no way to skip it. TechnoCore monitors cloud spending continuously, breaks costs down per application, warns as spending approaches the limit, and takes protective action when the limit is reached: it stops the highest-cost applications first, and then the rest of them. It stops **applications only**. `datasphered` and FatLine are classified last-to-die and a cost shutdown never touches them — stopping the tunnel makes storage impossible to unseal *while the instance keeps billing*, so it trades recovery for about a fifth of the bill ([ADR 0008](docs/adr/0008-in-cluster-key-delivery.md), [ADR 0009](docs/adr/0009-technocore-kernel-and-cost-metering.md)). With every application stopped and spending still over, TechnoCore has reached the instance floor: it reports that, names the levers that remain — drop the load-balancer carrier, or release the instance — and takes neither, because both destroy operator-visible capability or data.

Spending is tracked as **two figures, not one**: `expected` is metered locally from Pod requests in real time and is what protective action fires on; `confirmed` is the provider's own number for a window that has closed, arrives about a day later, and never drives an action — it corrects `expected` and calibrates the model behind it, within a clamp, so a bad billing feed can make the estimate wrong but cannot switch the guard off.

The two non-negotiable pillars of FarCast are: (1) security/privacy, (2) cost control. Everything else is secondary.

**Manifests describe what, not how.** The `./farcast` manifest is intentionally minimal. A single manifest declares one or more applications grouped as a deployment: each application's identity, its Containerfile, and the external services it connects to. Build steps and startup commands live in the Containerfile. Manifests never specify resources, ports, or infrastructure details. TechnoCore monitors and adapts resources automatically.

## Key Design Decisions

**WorldWeb was removed.** The original design included a central hub called WorldWeb for update distribution and instance registry. This was removed because it contradicts the autonomy principle. Updates are the operator's responsibility (pull signed manifests from wherever they trust). There is no instance registry.

**Portal was merged into FarSight.** There were originally separate modules for a browser app (Portal) and monitoring UI (FarSight). These were merged into a single UX layer called FarSight. The downloadable app is branded "farcast".

**CLI was folded into FarSight.** Rather than a separate CLI project, the command line interface lives within FarSight. GUI, CLI and server are all part of FarSight. On macOS one app is to carry the GUI and the CLI, and the other Apple devices a thin client ([ADR 0021](docs/adr/0021-farsight-native-client.md), accepted, not yet built). Even then, on macOS it is not yet one download: the bundled CLI still needs `kubectl`, the GKE auth plugin and `gcloud` beside it, and Go and a farcast checkout. [ADR 0023](docs/adr/0023-one-download-farcast.md), accepted 2026-11-13, removes them in stages: Go and the checkout at its M1, built 2026-11-13 (its walk not yet run), after which a release farcast needs them only for `--source`; `kubectl`, the plugin and `gcloud` at its M2 where service-account keys are allowed, not yet built; and the macOS app becomes one download only at its M5. A release farcast is built by `farcast-release`, and `./check.sh` checks that its builds are byte-identical on the dev Mac, not yet on a second host; a farcast built from source still compiles a missing image from a checkout with Go.

**FarSight's client is native, Apple first; Electron was retired.** Accepted 2026-11-11, not yet built.
- **Why Electron went:**
  - it reaches desktop only;
  - its Chromium patch cadence needs an update server FarCast does not have;
  - its npm toolchain would sit on the machine that holds the cloud credentials.
- **The shape.** FarSight is one product with one wire contract and a native shell per platform family. First comes one Swift/SwiftUI codebase for macOS, iPadOS, iOS and visionOS, using system frameworks only. Android and Windows are decided when they start.
- **Two kinds of UI.** Application UIs are web tiles behind an in-app loopback bridge that does the mutual TLS to FatLine, and each tile reaches only its own application. The operator's own surfaces are native.
- **No unproven traffic claim.** No document says "all traffic goes through FatLine" for a platform until that platform's packet-capture gate passes. On Apple, WebRTC is known to escape a web view's proxy.
- **Sequencing.** FarSight is sequenced ahead of AllThing.
- **What it rests on.** [ADR 0020](docs/adr/0020-instance-pki-ecdsa-p256.md) moves the instance PKI from Ed25519 to ECDSA P-256, because Apple's TLS cannot use Ed25519 and the hardware key stores on every target hold P-256.

Full reasoning: [ADR 0021](docs/adr/0021-farsight-native-client.md).

**One download: `farcast` stands alone.** Accepted 2026-11-13. M0 (hygiene) and M1 (embedded components) were built 2026-11-13, the pinned base's three documents included, and `./check.sh` step 3b checks on the dev Mac that release builds are byte-identical. M1's walk has not run: it is billable and needs the operator's approval. The second-host reproducibility gate has not run either. Every later milestone is not started.
- **No third-party tool is embedded.** `kubectl`, the GKE auth plugin, `gcloud` and Python, Go, the checkout and git each leave the day-to-day flows, replaced in-process. The vendored module count stays 31.
- **An in-process Kubernetes client replaces `kubectl`** (M2). It is built on the kernel's hand-rolled standard-library client and writes with server-side apply. Live objects move over by a one-time migration that cannot be undone, run as its own command behind a plan.
- **FarCast's own components ship pre-built** inside `farcast` (M1, built: the release tool `farcast-release` and the build tag `farcast_embedded`), as reproducible layers checked against digests compiled into the executable. An operator can rebuild the layers and compare them without trusting the release; on macOS the helper that carries the digests is trusted on its signatures unless the operator builds the app. The Go toolchain is not embedded, and `--source` stays the operator's own patch path. A Go security fix reaches the components by a re-release within N days, a window the operator has yet to set, or by `--source`. Nothing phones home, so the operator watches for releases.
- **The cluster token comes from `farcast`, in memory only.** Writes run as an identity bound to the instance, reads as a separate read-only one: reads never mint an admin token. The proposed identity is a per-device, per-instance P-256 key through Workload Identity Federation, gated on a probe (M3a) that creates only free IAM objects and needs the operator's approval. If it passes and the operator takes that route (M3b), service-account keys become a deprecated path and Application Default Credentials go.
- **Consent.** Anything newly automated is a `--plan` fact bound into `--confirm`, never covered by `--yes`. Push access to the instance's registry stays a human step.
- **Platforms.** On macOS one app carries a separate Go helper and brokers tokens from a Secure Enclave key (M5, once the ADR's probes pass); whether Sofmon enrols with Apple to sign and notarize it is still open. Linux and Windows get a standalone CLI (M4). iPhone and iPad stay thin clients first, and an operator iPad needs its own ADRs.
- **What no app can remove.** A Google account; the Cloud sign-up and a billing account; a privileged setup by the human account, once per project and once per instance, pasted into Cloud Shell; and reading the bill for `kernel confirm`.

Full reasoning: [ADR 0023](docs/adr/0023-one-download-farcast.md).

**TimeTomb is deferred.** Snapshot and recovery functionality (TimeTomb) is a future concept documented in the appendix. It is not part of the initial scope.

**Go by default; Rust only on the data plane.** The whole question of "Go or Rust" was settled with a clear principle: **Go for everything that abstracts a cloud or K8s primitive; Rust only where a module is the data plane on hostile bytes.** FarCast is overwhelmingly glue over cloud/K8s SDKs, and that ecosystem is Go-native (`client-go`, first-party AWS/GCP/Azure SDKs, the controller-runtime/kubebuilder corpus) — so the glue majority stays Go even though all code is AI-authored and human readability is a non-concern. The one module with a genuine Rust case is **FatLine** (the universal TLS/mTLS proxy on attacker-controlled bytes, where no-GC tail latency and compile-time data-race elimination matter), and even that is gated on a benchmark — default to Go-first, Rust-on-evidence. **DataSphere stays Go:** it is an abstraction over cloud storage (not a custom filesystem), and its crypto is commodity AES-256-GCM (AES-NI-accelerated, a wash between the languages). Full reasoning and the FatLine benchmark gate: [`docs/adr/0002-backend-language-strategy.md`](docs/adr/0002-backend-language-strategy.md).

**GKE Autopilot is the target compute mode.** The first Planck adapter provisions **GKE Autopilot** clusters: Google manages nodes, FarCast pays per Pod request, and the deny-by-default egress boundary is enforced by **always-on Kubernetes NetworkPolicy** (Dataplane V2) with **FatLine as a userspace proxy** — no privileged containers. **TechnoCore** runs as an in-cluster controller and scales apps by adjusting Pod requests (no node-pool management). Every FarCast-generated workload must carry **resource requests** and avoid privileged/host-network features, and FarCast operates outside the managed `kube-system` namespace. A Standard/Spot hybrid is a later cost optimization — and the home for any future kernel/eBPF FatLine data plane, which Autopilot would not permit. The **control plane is private by default** (no public IP): the operator reaches it through GKE's IAM-gated **DNS-based endpoint**, while in-cluster components use the internal endpoint — see [`docs/adr/0004-private-control-plane.md`](docs/adr/0004-private-control-plane.md). Full cost analysis and reasoning: [`docs/adr/0003-gke-autopilot.md`](docs/adr/0003-gke-autopilot.md).

**The data-plane point of presence is a public, mTLS-gated L4 NLB.** ADR 0004 made the *control* plane private; the *data* plane — how the operator (and later the GUI) reaches FatLine — is a dedicated GCP L4 **passthrough** load balancer that `farcast connect` binds by default. The public IP is not the boundary: FatLine terminates mutual TLS in userspace against the **per-instance CA** (the CA key never leaves the operator's machine), so unauthenticated peers are dropped at certificate verification and the cloud only ever forwards ciphertext. The carrier has a standing cost (~$18/mo), so `connect` surfaces it against the cost limit behind an explicit confirmation gate. The bootstrap deploys FatLine via a **`kubectl` subprocess**, not a vendored `client-go` — the credential-holding CLI keeps its minimal-dependency stance. [ADR 0023](docs/adr/0023-one-download-farcast.md) (accepted 2026-11-13) is to replace the subprocess at its M2 with an in-process client using server-side apply, still without `client-go`, superseding ADR 0006's decisions 1, 2 and 4 then. See [`docs/adr/0005-fatline-data-plane-ingress.md`](docs/adr/0005-fatline-data-plane-ingress.md) and [`docs/adr/0006-connect-bootstrap-kubectl.md`](docs/adr/0006-connect-bootstrap-kubectl.md).

## Module Relationships

- **FatLine** is the instance's network boundary. Application egress and the operator's tunnel pass through it, deny-by-default. It is not the only path:
  - the operator's control-plane calls go to the provider's API server through kubectl ([ADR 0019](docs/adr/0019-what-the-cluster-tells-its-provider.md)). [ADR 0023](docs/adr/0023-one-download-farcast.md)'s M2 is to replace kubectl with an in-process client, and the calls will still go to the API server, not through FatLine;
  - image pulls are node egress it does not see.

  A FarSight client's traffic is claimed to go through it only per platform, once that platform's packet-capture gate passes ([ADR 0021](docs/adr/0021-farsight-native-client.md)).
- **Shrike** monitors FatLine traffic and enforces policy. It does not control the boundary — it watches it and intervenes on violations. Think policeman, not wall.
- **TechnoCore** is the kernel. It manages instance lifecycle, adapts application resources (CPU, memory, replicas) based on observed behaviour, and enforces cost limits. It is the last thing to shut down — if cost limits are breached, TechnoCore stops apps but stays alive to report status.
- **Planck** translates application requirements into cloud-native K8s workloads. It is the compute abstraction.
- **DataSphere** proxies storage and enforces encryption-at-rest. The cloud provider only sees encrypted blobs — under opaque names, but with their sizes, count and tree shape visible.
- **AllThing** abstracts cloud AI services (Gemini, Claude, OpenAI). Starts as a chat interface in FarSight, evolves into the AI backbone for the entire system (TechnoCore resource decisions, Shrike traffic analysis, etc.).
- **FarSight** is the entire UX layer: native clients (application UIs in web tiles, the operator's own surfaces native), the CLI, and an in-instance server that keeps the tile registry, sessions and layout state.
- **SDK** provides syscall-like libraries so applications can interact with the FarCast environment (storage, networking, AI, config, secrets).

## Branding & Domains

**Sofmon** (`sofmon.com`) is the company. It may have multiple projects and products. FarCast is the flagship product but not the only one. Think "Microsoft" — the parent brand that houses many products.

**Sofmon FarCast** is the full product name, following the "Microsoft Windows" pattern. In casual use, people say "FarCast". In official/formal contexts, use "Sofmon FarCast".

**Domain strategy:**
- `sofmon.com` — the company hub. Developer docs, SDK references, marketplace, source code. FarCast lives at `sofmon.com/farcast`, not at the root. Leave room for other Sofmon projects. **Not published yet:** the README links the company root, `www.sofmon.com`, because the `/farcast` subpath does not exist — that is a not-yet, not a change of strategy, and the link moves to the subpath when it is live.
- `farcast.one` — the first living FarCast instance. Not a marketing page — it's an actual FarCast instance running on itself. Proof that the OS works. **Pending:** no instance is deployed there yet, and the README says so rather than linking a promise.

**Go module paths** use `github.com/sofmon/farcast/...` to reflect the company ownership.

## Naming

All component names come from Dan Simmons' *Hyperion Cantos*. The naming is intentional — each component's behaviour mirrors its namesake. Full lore is in `docs/hyperion-reference.md`. Keep the naming consistent but don't over-reference the books in technical documentation.

## Conventions

- The repository is a single Go module rooted at `github.com/sofmon/farcast`, with one `go.mod`, one `go.sum`, and one shared `vendor/` directory at the repo root. Dependencies are vendored — `go mod vendor` is the source of truth, and builds run in vendor mode.
- The one exception is `sdk/go/`, which is its own Go module. The SDK is the public import surface for external applications (analogous to a syscall library), so it must have an independent dependency graph that end users can pull without dragging in the rest of FarCast.
- Each top-level folder (technocore, planck, fatline, …) is a logical module — a package tree under the root module — not a separate Go module. README.md in each folder serves as the specification.
- Deeper specs, architecture notes, and API docs go in each module's `docs/` subfolder.
- Tests sit next to the code they cover (`_test.go` files alongside source).
- Empty directories use `.gitkeep` for Git tracking.
- FarSight's clients are native per platform family. Swift/SwiftUI on Apple comes first, under `farsight/client/apple/` ([ADR 0021](docs/adr/0021-farsight-native-client.md)), and Android and Windows are decided when they start. Everything else is Go (see "Go by default; Rust only on the data plane" above; the sole Rust candidate is a benchmark-gated FatLine data plane).
- **Language guardrails (these make AI-authored code safe without a human reviewer, so they are not optional):**
  - Go modules: `go test -race`, `go vet`, and `golangci-lint` in CI. Go's memory safety is conditional on the absence of data races — `-race` defends that.
  - Swift (the Apple client, [ADR 0021](docs/adr/0021-farsight-native-client.md) decision 4). These join `./check.sh` with the first client code:
    - Swift 6 language mode with complete strict concurrency;
    - `-strict-memory-safety` with its diagnostics as errors;
    - a source gate refusing `@unchecked Sendable`, `nonisolated(unsafe)` and `unsafe` outside a reviewed allowlist;
    - full builds, never `-typecheck` alone;
    - `swift test` and `xcodebuild test`;
    - no third-party packages without an ADR.
  - Any Rust module (currently only a possible FatLine data plane): `#![forbid(unsafe_code)]`, clippy and `cargo-geiger`, plus cancellation-safety integration tests (the one genuinely silent Rust AI hazard — data loss on a future dropped mid-`select!`, non-atomic state across `.await`) and multithreaded/race-style tests for shared session/allowlist state.
