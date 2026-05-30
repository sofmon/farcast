# ADR 0002 — Backend Language Strategy: Go by Default, Rust Only on the Data Plane

**Status:** Accepted

**Date:** 2026-05-30

**Supersedes / relates to:** Reinforces the existing DataSphere-uses-Go decision recorded in [`AGENTS.md`](../../AGENTS.md) ("Key Design Decisions"). Does not overturn it.

---

## Context

FarCast's backend was specified in Go across every module, with Electron + TypeScript locked in for the FarSight GUI client. The question was raised: since all FarCast code is written by AI agents — meaning human readability, onboarding, and hiring are non-concerns — would switching the backend to Rust yield a better product?

This ADR records the decision and the reasoning, because the obvious framing of the question is misleading and the evidence behind it is easy to get stale.

### The premise, taken as firm

AI agents author all code. Human maintainability is **not** a factor. This deliberately removes the strongest conventional argument *for* Go (it is easy for humans to read and onboard onto) and the strongest conventional argument *against* Rust (the borrow checker taxes human developers). With both removed, the decision turns purely on which language produces the better **artifact**.

### What FarCast actually is

FarCast is **not** custom systems software. It is a sovereign abstraction layer over public cloud. Eight of its nine backend modules derive their value from a cloud or Kubernetes SDK they wrap — they are HTTP/streaming clients, `client-go` calls, billing-API polling, manifest translation, and policy comparison:

- **Planck** — manifest → K8s objects; provision EKS/GKE/AKS; build images. (`client-go`, first-party cloud SDKs, BuildKit)
- **TechnoCore** — control loop reading K8s metrics, adjusting replicas, polling billing APIs. (`client-go`/controller-runtime, billing SDKs)
- **AllThing** — HTTP+SSE client over Gemini/Claude/OpenAI. (provider SDKs)
- **DataSphere** — S3/GCS proxy with AES-256-GCM at rest. (object-storage SDKs)
- **Shrike** — policy comparison + traffic inspection. (reuses manifest types)
- **FarSight server / CLI, SDK, manifest** — UX composition, syscall-like libraries, YAML.

Exactly **one** module is a genuine data plane on hostile bytes:

- **FatLine** — TLS/mTLS tunnel and deny-by-default proxy. All instance traffic flows through it. Its dependency is sockets and a TLS stack, **not** a cloud SDK.

### The deciding factor

For a module whose value is the SDK it wraps, the language that owns the SDK wins. That language is Go: `client-go` is the canonical Kubernetes client, and AWS/GCP/Azure ship mature first-party Go SDKs. Choosing Rust for the glue majority means an AI writes *more* glue against *thinner* libraries — more code, more attack surface, more iteration cycles — which works directly against FarCast's two non-negotiable pillars (security/privacy and cost control). Greenfield makes this worse, not better, because greenfield is when the most glue is written.

This is the same reasoning already recorded for DataSphere. **It generalizes to the whole glue majority.**

### Evidence reviewed (and what was stale)

A multi-angle analysis with an adversarial fact-check pass corrected several pieces of conventional wisdom. Recording them here so this decision does not rest on claims that have already expired:

- **"Rust cloud SDKs are too immature" is largely stale as of mid-2026.** GCP shipped GA Rust libraries (v1.0, Sept 2025, 140+ services), including `google-cloud-container-v1` (core GKE) and `google-cloud-billing-v1` (cost control). The Azure SDK for Rust went GA on 2026-05-14 (core, identity, Key Vault, Storage). AWS has been GA since Nov 2023. The surviving Go-specific SDK advantage is narrow: **Azure AKS-management and Azure cost-management**, which still lack stable Rust crates.
- **`kube-rs` is at functional parity** for workload primitives (Deployments/StatefulSets/Jobs/CRDs) and honors a `client-go`-equivalent version-skew window. The K8s-glue gap is the *weakest* leg of the Go case, not its strongest. The real residual Go edge is the deeper controller-runtime / kubebuilder operator corpus that LLMs reproduce more reliably.
- **Crypto is a verified wash.** AES-256-GCM is AES-NI-accelerated in both languages; Go 1.26's `runtime/secret` erodes Rust's lone key-zeroization edge. DataSphere stays Go — confirmed, not merely inherited.
- **First-pass AI code quality favors Go** (denser corpus, smaller surface, fewer subtly-wrong-but-compiling forks such as async-runtime choice and `Send`/`Sync` across `.await`). The popular "74–93% convergence" counter-evidence is a category error — it measures compiler-loop *repair*, not first-pass generation. Under an agentic compile-test-fix loop the gap narrows but does not invert.

Net effect: the Go case is **real but narrower** than its strongest framing. Surviving Go-specific advantages reduce to Azure AKS/cost-management SDKs, in-process BuildKit Dockerfile embedding, and the operator corpus.

### Where Rust's case is genuinely strong

FatLine is the one module where the Go ecosystem advantage does not apply and Rust's advantages are real:

- It is the data plane; p99/p99.9 tail latency is product-defining, and Go's GC plus per-connection goroutine overhead surface there under connection churn.
- It terminates TLS/mTLS on attacker-controlled bytes with shared mutable state (session tables, dynamic allowlist) — precisely where Go's memory safety is *conditional* (a data race on a slice/interface/map can corrupt memory, not just panic) and where Rust's compile-time data-race elimination converts to fewer exploitable bugs.
- Its dependencies (`rustls`/`tokio` + sockets) are best-in-class in Rust.

The win is **conditional on actual load.** A sovereign single-tenant instance is not a hyperscale load balancer. If FatLine's traffic is I/O-bound and modest, zero-allocation Go (`sync.Pool`, pre-allocation, `splice`) may land within an acceptable band, in which case uniformity and faster AI iteration win.

---

## Decision

1. **Go is the default backend language for every module** — manifest, Planck, TechnoCore, AllThing, DataSphere, Shrike, FarSight server, FarSight CLI, and the Go SDK. (FarSight's GUI client remains Electron + TypeScript; the Node and Python SDKs proceed as planned.)

2. **FatLine is the sole sanctioned Rust candidate, and only its hot data-plane loop.** Its control/config plane stays Go. The choice is **gated on a benchmark** (see below) — default to Go-first, Rust-on-evidence, not speculative Rust.

3. **Shrike follows FatLine.** If FatLine becomes Rust *and* Shrike's inline inspector shares its data path, co-locate the inspector in the Rust process to avoid a cross-language hop on the hot path. Otherwise Shrike stays Go and reuses the Go manifest types.

4. **No other module may adopt Rust without a new ADR** that demonstrates it is a data plane on hostile bytes with a measured tail-latency or footprint win.

### Decision-gating benchmark

Build FatLine in Go first (it is needed early in Phase 2 regardless). Then benchmark a representative workload — TLS/mTLS termination plus per-flow allowlist inspection at target connection counts — across three implementations: **naive Go**, **zero-allocation Go**, and **Rust (`rustls`/`tokio`)**. Measure GC-CPU %, RSS per N connections, and p99/p99.9.

- If zero-allocation Go lands within an acceptable tail-latency/footprint band → stay all-Go (keep uniformity and the faster AI iteration loop).
- If Rust shows a decisive footprint/tail win at realistic load → adopt a Rust FatLine data plane behind a language-neutral (gRPC/HTTP) seam. The multi-language SDK already requires such a seam, so the polyglot cost is near-zero.

### Open inputs to resolve alongside the benchmark

- Does the threat model formally include process-memory disclosure / co-tenant attacks? (Raises FatLine's key-zeroization weight.)
- Is **Azure cost-management specifically** a hard requirement? It is the single surviving decisive pro-Go SDK gap. If cost control can ride AWS Cost Explorer or GCP billing (both stable in Rust), even that gap closes.

---

## Consequences

**Positive**

- The backend stays uniform Go across the glue majority, riding first-party cloud/K8s SDKs and the controller-runtime/kubebuilder corpus that AI agents reproduce most reliably.
- The faster Go compile-test-fix loop compounds across the large glue build-out.
- Rust is reserved for the one place it earns its keep, behind a seam the architecture already needs — so a future FatLine-in-Rust is an isolated, low-cost exception, not a fork in the stack.
- The decision rests on measurement, not language preference.

**Negative / risks**

- **Polyglot seam at the most security-critical boundary** if FatLine goes Rust. The strongest argument against this decision is *compounding correctness*: with no human reviewer, the compiler is the only reviewer, and Rust statically eliminates whole defect classes across every trusting layer — including the Go modules whose output FatLine trusts (TechnoCore's cost numbers, Planck's translation, the SDK). If a single defect anywhere in the trust chain is judged catastrophic, and the residual Go ecosystem edges are judged cheap for an AI to fill, then all-Rust-while-greenfield would dominate and this polyglot answer would be a worst-of-both-worlds middle. We judge the ecosystem tax to be concentrated in the highest-leverage, hardest-to-get-right modules (Planck provisioning, the operator loops) and the compounding-correctness benefit to be real but diffuse — so Go-default wins. This is a catastrophe-tolerance judgment, not a fact dispute, and should be revisited if the threat model hardens.
- Go's memory safety is *conditional* on the absence of data races. This must be actively defended in CI (see below), not assumed.

**Mandated guardrails (make either language safe without a human reviewer)**

- **Go modules:** `go test -race`, `go vet`, and `golangci-lint` in CI.
- **Any Rust module:** `#![forbid(unsafe_code)]`, clippy and `cargo-geiger`, plus **cancellation-safety integration tests** — the one genuinely silent, untooled Rust AI hazard identified in review (data loss when a future is dropped mid-`select!`, non-atomic state across `.await`). Multithreaded / race-style integration tests for the shared session and allowlist state.

---

*This ADR is a living record. Revisit it after the FatLine benchmark and whenever the threat model or the Rust cloud-SDK landscape materially changes.*
