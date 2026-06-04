# AGENTS.md

Context for AI agents working on this codebase.

## Core Philosophy

FarCast is a cloud operating system where privacy is the foundational principle. Every design decision flows from one question: does the cloud provider, the network, or any third party gain visibility into the user's data or behaviour? If yes, the design is wrong.

## Architectural Principles

**Never reinvent cloud infrastructure.** Cloud providers have mature compute (K8s), storage (S3/GCS), networking, and AI services. FarCast wraps these with a sovereign abstraction layer — it doesn't replace them. Planck abstracts compute, DataSphere abstracts storage, FatLine abstracts networking, AllThing abstracts AI.

**Zero central dependency.** Every FarCast instance is fully autonomous. There is no central registry, no update server, no phone-home mechanism. Instances do not announce their existence to anyone. Discovery between instances happens out-of-band — operators exchange FatLine addresses manually or through their own private channels.

**Deny by default.** All connections — inbound and outbound — are denied unless explicitly declared in an application's `./farcast` manifest. The operator reviews external access declarations before running an app. FatLine enforces the boundary, Shrike monitors compliance at runtime.

**The cloud provider is blind.** FatLine encrypts all traffic in transit. DataSphere encrypts all data at rest. The cloud provider carries encrypted packets and stores encrypted blobs — it never sees plaintext.

**Cost control is mandatory, not optional.** Every instance must have a cost limit set at creation — there is no way to skip it. TechnoCore monitors cloud spending continuously, breaks costs down per application, warns as spending approaches the limit, and takes protective action when the limit is reached (stop high-cost apps first, then the entire instance if needed, keeping only TechnoCore alive). The two non-negotiable pillars of FarCast are: (1) security/privacy, (2) cost control. Everything else is secondary.

**Manifests describe what, not how.** The `./farcast` manifest is intentionally minimal. A single manifest declares one or more applications grouped as a deployment: each application's identity, its Containerfile, and the external services it connects to. Build steps and startup commands live in the Containerfile. Manifests never specify resources, ports, or infrastructure details. TechnoCore monitors and adapts resources automatically.

## Key Design Decisions

**WorldWeb was removed.** The original design included a central hub called WorldWeb for update distribution and instance registry. This was removed because it contradicts the autonomy principle. Updates are the operator's responsibility (pull signed manifests from wherever they trust). There is no instance registry.

**Portal was merged into FarSight.** There were originally separate modules for a browser app (Portal) and monitoring UI (FarSight). These were merged into a single UX layer called FarSight. The downloadable app is branded "farcast".

**CLI was folded into FarSight.** Rather than a separate CLI project, the command line interface lives within FarSight. One app, one download — GUI, CLI, and server are all part of FarSight.

**TimeTomb is deferred.** Snapshot and recovery functionality (TimeTomb) is a future concept documented in the appendix. It is not part of the initial scope.

**Go by default; Rust only on the data plane.** The whole question of "Go or Rust" was settled with a clear principle: **Go for everything that abstracts a cloud or K8s primitive; Rust only where a module is the data plane on hostile bytes.** FarCast is overwhelmingly glue over cloud/K8s SDKs, and that ecosystem is Go-native (`client-go`, first-party AWS/GCP/Azure SDKs, the controller-runtime/kubebuilder corpus) — so the glue majority stays Go even though all code is AI-authored and human readability is a non-concern. The one module with a genuine Rust case is **FatLine** (the universal TLS/mTLS proxy on attacker-controlled bytes, where no-GC tail latency and compile-time data-race elimination matter), and even that is gated on a benchmark — default to Go-first, Rust-on-evidence. **DataSphere stays Go:** it is an abstraction over cloud storage (not a custom filesystem), and its crypto is commodity AES-256-GCM (AES-NI-accelerated, a wash between the languages). Full reasoning and the FatLine benchmark gate: [`docs/adr/0002-backend-language-strategy.md`](docs/adr/0002-backend-language-strategy.md).

**GKE Autopilot is the target compute mode.** The first Planck adapter provisions **GKE Autopilot** clusters: Google manages nodes, FarCast pays per Pod request, and the deny-by-default egress boundary is enforced by **always-on Kubernetes NetworkPolicy** (Dataplane V2) with **FatLine as a userspace proxy** — no privileged containers. **TechnoCore** runs as an in-cluster controller and scales apps by adjusting Pod requests (no node-pool management). Every FarCast-generated workload must carry **resource requests** and avoid privileged/host-network features, and FarCast operates outside the managed `kube-system` namespace. A Standard/Spot hybrid is a later cost optimization — and the home for any future kernel/eBPF FatLine data plane, which Autopilot would not permit. The **control plane is private by default** (no public IP): the operator reaches it through GKE's IAM-gated **DNS-based endpoint**, while in-cluster components use the internal endpoint — see [`docs/adr/0004-private-control-plane.md`](docs/adr/0004-private-control-plane.md). Full cost analysis and reasoning: [`docs/adr/0003-gke-autopilot.md`](docs/adr/0003-gke-autopilot.md).

## Module Relationships

- **FatLine** is the network boundary. All traffic flows through it. Nothing else touches the network.
- **Shrike** monitors FatLine traffic and enforces policy. It does not control the boundary — it watches it and intervenes on violations. Think policeman, not wall.
- **TechnoCore** is the kernel. It manages instance lifecycle, adapts application resources (CPU, memory, replicas) based on observed behaviour, and enforces cost limits. It is the last thing to shut down — if cost limits are breached, TechnoCore stops apps but stays alive to report status.
- **Planck** translates application requirements into cloud-native K8s workloads. It is the compute abstraction.
- **DataSphere** proxies storage and enforces encryption-at-rest. The cloud provider only sees encrypted blobs.
- **AllThing** abstracts cloud AI services (Gemini, Claude, OpenAI). Starts as a chat interface in FarSight, evolves into the AI backbone for the entire system (TechnoCore resource decisions, Shrike traffic analysis, etc.).
- **FarSight** is the entire UX layer — GUI (tiling browser), CLI, and a server-side component for UX composition.
- **SDK** provides syscall-like libraries so applications can interact with the FarCast environment (storage, networking, AI, config, secrets).

## Branding & Domains

**Sofmon** (`sofmon.com`) is the company. It may have multiple projects and products. FarCast is the flagship product but not the only one. Think "Microsoft" — the parent brand that houses many products.

**Sofmon FarCast** is the full product name, following the "Microsoft Windows" pattern. In casual use, people say "FarCast". In official/formal contexts, use "Sofmon FarCast".

**Domain strategy:**
- `sofmon.com` — the company hub. Developer docs, SDK references, marketplace, source code. FarCast lives at `sofmon.com/farcast`, not at the root. Leave room for other Sofmon projects.
- `farcast.one` — the first living FarCast instance. Not a marketing page — it's an actual FarCast instance running on itself. Proof that the OS works.

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
- FarSight's client is Electron + TypeScript. Everything else is Go (see "Go by default; Rust only on the data plane" above; the sole Rust candidate is a benchmark-gated FatLine data plane).
- **Language guardrails (these make AI-authored code safe without a human reviewer, so they are not optional):**
  - Go modules: `go test -race`, `go vet`, and `golangci-lint` in CI. Go's memory safety is conditional on the absence of data races — `-race` defends that.
  - Any Rust module (currently only a possible FatLine data plane): `#![forbid(unsafe_code)]`, clippy and `cargo-geiger`, plus cancellation-safety integration tests (the one genuinely silent Rust AI hazard — data loss on a future dropped mid-`select!`, non-atomic state across `.await`) and multithreaded/race-style tests for shared session/allowlist state.
