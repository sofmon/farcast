# Planck

> Compute abstraction — a cloud-agnostic layer over managed Kubernetes (GKE, EKS, AKS).

Planck is the module that turns "a cloud account" into "a running Kubernetes cluster," and later "a `./farcast` manifest" into "running workloads." It is FarCast's compute substrate: the only module that talks to a cloud's compute-control APIs, hidden behind one interface so the rest of FarCast never names a cloud.

This document specifies **Phase 1.2 — the first cloud provider adapter**: the `Provider` interface and one concrete implementation that can validate credentials, create a managed Kubernetes cluster with sensible defaults, wait for it to be ready, and destroy it. The manifest-to-workload translator is a later phase and is described only in outline here.

> **Status.** Phase 1.2 — in specification. **Decided:** the first adapter targets **GKE Autopilot** ([ADR 0003](../docs/adr/0003-gke-autopilot.md)). **In scope:** the cloud-agnostic `Provider` interface and registry; the GKE Autopilot adapter implementing credential validation, cluster create / status / delete with readiness waiting; a thin `cmd/planck` harness for driving a real cluster manually. **Out of scope (later phases):** the manifest→K8s **translator** (4.2), wiring into `farcast install` (1.3), cost monitoring/enforcement (TechnoCore, 4.1), and the second/third providers (8.1).

---

## What Planck is — and isn't

**It is** the compute boundary. Planck wraps each cloud's managed-Kubernetes control API (GKE's `container`, EKS, AKS) behind a single `Provider` interface. Give it credentials and a cluster spec; it gives you back a ready cluster and the credentials to reach it. Every cloud-specific quirk — auth, regions, the shape of a "create cluster" call — lives inside an adapter and nowhere else.

**It is not** a Kubernetes reimplementation, an autoscaler, or a cost controller. Planck *provisions and tears down* clusters and (later) *translates* manifests into workloads. Watching resource usage, adapting CPU/memory/replicas, and enforcing the cost limit are **TechnoCore's** job ([`../technocore/README.md`](../technocore/README.md)). Planck provisions a low-cost cluster and then gets out of the way.

**It is not** where credentials live. Planck receives credentials, uses them, and returns cluster-access credentials to its caller. It never persists either. The `farcast` CLI is responsible for storing them locally under strict permissions ([`../farsight/cli/README.md`](../farsight/cli/README.md), phase 1.3).

This single-responsibility framing follows directly from the [backend language strategy](../docs/adr/0002-backend-language-strategy.md): Planck's value *is* the cloud/K8s SDK it wraps, so it stays Go (first-party `client-go` and cloud SDKs), and it stays thin.

---

## Architecture & package layout

```
planck/
├── README.md                       ← this file
├── docs/                           ← deeper provider notes
├── planck.go (+ types.go)          ← PUBLIC: Provider interface, types, registry (Open/Register)
├── providers/                      ← PUBLIC: blank-import to register the bundled adapters
│   └── providers.go
├── cmd/
│   └── planck/
│       └── main.go                 ← thin manual harness: validate / create / delete a cluster
└── internal/
    ├── providers/                  ← cloud adapters (one per cloud)
    │   └── gke/                    ← GKE adapter (first); EKS, AKS later
    └── translator/                 ← manifest → K8s workloads (phase 4.2)
```

The package wiring is the [`database/sql`](https://pkg.go.dev/database/sql) pattern, which is exactly what "make the second provider easy to add" calls for:

- **`planck`** (root, public) declares the `Provider` interface, the shared types, and a small registry: `Register(name, factory)`, `Open(name, cfg)`, `Providers()`. It imports **no** adapter, so it stays a dependency-light leaf that any module (the CLI, TechnoCore) can import for the types.
- **`planck/internal/providers/gke`** implements the adapter and self-registers in its `init()`. It imports `planck` for the interface and types. Keeping adapters `internal` means no other module can construct a cloud client directly — everyone goes through `planck.Open`.
- **`planck/providers`** (public) does nothing but blank-import the bundled adapters so they register:

  ```go
  package providers

  import _ "github.com/sofmon/farcast/planck/internal/providers/gke"
  ```

  A composition root (the `cmd/planck` harness now, the `farcast` CLI in 1.3) imports `planck` for the API and blank-imports `planck/providers` to light up the bundled clouds. Adding a provider = one new `internal/providers/<cloud>` package + one line here.

---

## The Provider interface

The centerpiece. Cloud-agnostic, context-first, and small enough that a second cloud is a focused implementation effort.

```go
// Provider manages the lifecycle of a managed Kubernetes cluster on one
// cloud. Every method honours ctx for cancellation and deadlines; cluster
// operations are minutes-long, so callers pass a ctx with a generous timeout.
type Provider interface {
	// Name is the provider's stable identifier, e.g. "gke".
	Name() string

	// Validate confirms the configured credentials are usable and carry the
	// permissions Planck needs. It creates nothing.
	Validate(ctx context.Context) error

	// CreateCluster provisions a cluster from spec and blocks until it is
	// ready to accept workloads. If a cluster with the same name and location
	// already exists, it returns that cluster rather than failing.
	CreateCluster(ctx context.Context, spec ClusterSpec) (*Cluster, error)

	// ClusterStatus reports the current state of the referenced cluster.
	ClusterStatus(ctx context.Context, ref ClusterRef) (ClusterStatus, error)

	// DeleteCluster tears the cluster down and blocks until removal completes.
	// Deleting an absent cluster is not an error (idempotent cleanup).
	DeleteCluster(ctx context.Context, ref ClusterRef) error
}
```

### Supporting types

```go
// ClusterSpec is a cloud-neutral description of the cluster to create. Most
// fields are optional; Planck fills sensible defaults.
type ClusterSpec struct {
	Name     string            // DNS-label, required
	Location string            // provider-specific (GKE region); default applied if empty
	Version  string            // optional Kubernetes version; provider default if empty
	Labels   map[string]string // optional cloud resource labels
}

// Note: there is no node-count or machine-size field. FarCast provisions GKE
// Autopilot clusters (ADR 0003), where Google manages nodes and compute is
// auto-provisioned from Pod requests. A future Standard or EKS adapter would
// introduce an optional node-pool spec behind the same Factory.

// ClusterRef identifies a cluster for status/delete.
type ClusterRef struct {
	Name     string
	Location string
}

// Cluster is a provisioned cluster and the credentials to reach it.
type Cluster struct {
	Ref        ClusterRef
	Status     ClusterStatus
	Endpoint   string // Kubernetes API server endpoint
	Kubeconfig []byte // credentials to reach the cluster — sensitive; never logged
}

type ClusterStatus string

const (
	StatusProvisioning ClusterStatus = "provisioning"
	StatusRunning      ClusterStatus = "running"
	StatusDeleting     ClusterStatus = "deleting"
	StatusError        ClusterStatus = "error"
	StatusUnknown      ClusterStatus = "unknown"
)
```

### Registry & configuration

```go
// Factory builds a Provider from its configuration.
type Factory func(cfg Config) (Provider, error)

// Config carries credentials and account scoping. Fields are interpreted per
// provider — see each adapter's section.
type Config struct {
	Credentials []byte            // raw credential material (e.g. GCP service-account key JSON); empty = ambient/default creds
	Project     string            // GCP project ID / AWS account context
	Location    string            // default region or zone
	Extra       map[string]string // provider-specific options
}

func Register(name string, f Factory)                // called by adapters' init()
func Open(name string, cfg Config) (Provider, error) // construct a registered provider
func Providers() []string                            // registered provider names
```

`Open` returns a clear error listing the registered providers when `name` is unknown — and a reminder to blank-import `planck/providers` if the list is empty.

---

## Lifecycle

**Validate** — a cheap, side-effect-free permission probe (e.g. list clusters in the project/region). It runs before any create so the operator learns about bad credentials or missing IAM permissions immediately, not three minutes into a provisioning attempt. In the install flow this is what fails fast.

**CreateCluster** — fills defaults, issues the create call for an **Autopilot** cluster, then polls until the control plane reports `RUNNING` (or `ctx` expires); with Autopilot there is no node pool to size or wait for — compute is provisioned later from workload requests. It is effectively idempotent: an existing cluster with the same `Ref` is returned rather than duplicated, so a retried install converges instead of erroring. On success it returns the API endpoint and a kubeconfig.

**ClusterStatus** — maps the cloud's native status enum onto `ClusterStatus`, so callers (and TechnoCore later) reason in FarCast terms.

**DeleteCluster** — issues the delete and blocks until the cloud confirms removal. Deleting an already-absent cluster succeeds silently, so `farcast release` (1.4) and failed-install cleanup are safe to re-run.

All four are long-running and fully `ctx`-governed: a cancelled install or a `farcast` Ctrl-C propagates down and aborts the cloud operation's polling promptly.

---

## First adapter: GKE Autopilot

The first cloud is **Google Kubernetes Engine in Autopilot mode** — decided in [ADR 0003](../docs/adr/0003-gke-autopilot.md) after a cost, egress-security, and in-cluster-control analysis. Google manages the nodes; FarCast pays per running Pod request; and the deny-by-default network boundary is enforced by always-on NetworkPolicy rather than privileged containers. Cluster creation is a single call against one mature first-party Go SDK, with no VPC/IAM/node-group scaffolding to stand up first.

- **Auth.** `Config.Credentials` holds a service-account key JSON; empty means Application Default Credentials (ADC) — the `gcloud` login or `GOOGLE_APPLICATION_CREDENTIALS`. `Config.Project` is the GCP project ID.
- **What Planck creates.** A regional **Autopilot** cluster (`Autopilot{Enabled: true}` on the GKE `Cluster` resource), which comes with GKE Dataplane V2 and Kubernetes NetworkPolicy **always on and undisablable** — the substrate FarCast's egress boundary relies on. No node count, machine type, or node pool is specified; Autopilot provisions compute from Pod requests at deploy time.
- **Defaults.** GKE's default Kubernetes version and a default region; everything else is Autopilot-managed. The cost floor is low by construction (per-Pod billing, ~$37–51/mo at FarCast's baseline — see ADR 0003).
- **Dependency.** This introduces the Google Cloud Go SDK (`cloud.google.com/go/container/apiv1` and auth), vendored via `go mod vendor`. Its `Cluster` type supports Autopilot via the `autopilot` field. It is the first non-stdlib dependency in the root module beyond the YAML parser, and exactly the kind of first-party cloud SDK ADR 0002 says Planck should ride.

---

## Cost & security posture

The two non-negotiable pillars shape even this early module (full analysis in [ADR 0003](../docs/adr/0003-gke-autopilot.md)):

- **Cost.** Autopilot's per-Pod billing gives a low, linear floor (~$37/mo empty, ~$45–51/mo with a few apps) with no idle-node waste and no charge for system overhead. Planck does **not** enforce the cost limit — that is mandatory at `farcast install` (1.3) and continuously monitored by TechnoCore (4.1) — but per-Pod pricing makes spending directly attributable per app, which is exactly what TechnoCore's cost breakdown needs.
- **Egress boundary.** Provisioning Autopilot is what gives FarCast its boundary substrate: **NetworkPolicy is always on and cannot be disabled**. The deny-by-default egress contract — every app Pod may reach only the FatLine proxy and DNS, nothing else — is generated per app by the translator (4.2); FatLine (a userspace proxy) does the manifest allowlisting. A Pod cannot bypass FatLine to reach the internet, by construction.
- **Security / privacy.** The kubeconfig in `Cluster` is secret: never logged, returned to the caller for the CLI to store at `0600`. The honest boundary: the cloud provider runs and can see the *managed control plane* and cluster metadata. FarCast's privacy guarantees (FatLine encrypting traffic, DataSphere encrypting data at rest) operate **above** the cluster. A freshly created cluster is "empty but alive" until later phases deploy onto it.

---

## The `cmd/planck` harness

Long term, `cmd/planck` is the Planck service that runs inside an instance and manages workloads (translator-driven, later phases). For **1.2** it is a thin, operator-facing harness whose only job is to exercise the provider lifecycle against real credentials — because automated tests cannot (cheaply) create real clusters:

```
planck validate  --provider gke --project P --location REGION [--credentials key.json]
planck create    --provider gke --project P --location REGION --name demo
planck status    --provider gke --project P --location REGION --name demo
planck delete    --provider gke --project P --location REGION --name demo
```

It is **not** the user-facing CLI (that is `farcast`); it is a developer/operator tool for validating the adapter before 1.3 wires Planck into `farcast install`. Kept intentionally minimal.

---

## Testing strategy

Cluster creation costs real money and takes minutes, so the test pyramid is split:

- **Unit tests (run in CI, every commit).** The adapter depends on a small interface that wraps the cloud client (e.g. a `gkeClient` seam), so tests inject a fake and exercise the logic that does *not* touch the network: spec→API-request mapping (including the Autopilot flag), default-filling, native-status→`ClusterStatus` mapping, error classification, and idempotent create/delete behaviour. The registry (`Open`/`Register`/unknown-provider error) is unit-tested with a fake provider.
- **Integration tests (gated, never in CI).** Behind a `//go:build integration` tag and requiring real credentials + a project via env, a single test creates a cluster, asserts readiness, and deletes it. Documented in `docs/`, run manually, and explicitly excluded from CI to protect the cost pillar.
- **Guardrails.** `go test -race`, `go vet`, and `golangci-lint`, per [AGENTS.md](../AGENTS.md). The kubeconfig field is covered by a test asserting it is never included in any log/`String()` output.

---

## Decisions

1. **First cloud provider: GKE** (decided). PLAN 1.2 ties this to whichever cloud is easiest to test against. The `Provider` interface and registry are designed so the second provider (8.1) is an additive `internal/providers/<cloud>` package plus one blank-import line; nothing else in FarCast changes.
2. **GKE Autopilot, not Standard** (decided — [ADR 0003](../docs/adr/0003-gke-autopilot.md)). A cost, egress-security, and in-cluster-control analysis found Autopilot competitive at FarCast's baseline (~$37–51/mo), operationally simpler (no node management), more resilient (regional), and a *stronger* boundary (undisablable NetworkPolicy) — while imposing constraints FarCast meets anyway (resource requests on every container, no privileged/host-network workloads, operate outside `kube-system`). A Standard/Spot hybrid is a Phase 5+ optimization, and would also be required if FatLine ever becomes a kernel/eBPF data plane (ADR 0002).
3. **`Config` shape.** A single neutral `Config` (credentials + project + location + `Extra`) keeps `Open` uniform across clouds; provider-specific needs ride in `Extra`. If this gets unwieldy with the second cloud, switch to per-provider config structs behind the same `Factory`.

---

## Roadmap

| Phase | Adds |
|---|---|
| **1.2** (this) | `Provider` interface + registry; first adapter (validate / create / wait / delete); `cmd/planck` harness |
| 1.3 | `farcast install` wires the CLI to `planck.Open` + `CreateCluster`, with the mandatory cost limit |
| 1.4 | `farcast release` → `DeleteCluster` |
| 4.2 | `internal/translator` — `./farcast` manifest → K8s namespace + Deployment/Service/ConfigMap per app, plus the per-app deny-by-default egress NetworkPolicy |
| 5+ | Optional Standard/Spot hybrid node pool as a TechnoCore cost optimization (ADR 0003) |
| 8.1 | Second cloud provider adapter behind the same interface |

---

## References

- Project overview — [`../README.md`](../README.md)
- Agent/architecture context — [`../AGENTS.md`](../AGENTS.md)
- Execution plan — [`../PLAN.md`](../PLAN.md)
- Manifest spec (translator input, 4.2) — [`../manifest/README.md`](../manifest/README.md)
- Kernel & cost enforcement — [`../technocore/README.md`](../technocore/README.md)
- Operator CLI (wires Planck in 1.3) — [`../farsight/cli/README.md`](../farsight/cli/README.md)
- Backend language strategy — [ADR 0002](../docs/adr/0002-backend-language-strategy.md)
- GKE Autopilot decision & cost analysis — [ADR 0003](../docs/adr/0003-gke-autopilot.md)
