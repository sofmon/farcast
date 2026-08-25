# Planck

> Compute abstraction — a cloud-agnostic layer over managed Kubernetes (GKE, EKS, AKS).

Planck is the module that turns "a cloud account" into "a running Kubernetes cluster," and later "a `./farcast` manifest" into "running workloads." It is FarCast's compute substrate: the only module that talks to a cloud's compute-control APIs, hidden behind one interface so the rest of FarCast never names a cloud.

This document specifies **Phase 1.2 — the first cloud provider adapter**: the `Provider` interface and one concrete implementation that can validate credentials, create a managed Kubernetes cluster with sensible defaults, wait for it to be ready, and destroy it. It also specifies the one **optional capability** that has since joined that interface: the instance's own image registry ([ADR 0007](../docs/adr/0007-instance-owned-image-registry.md)). The manifest-to-workload translator is a later phase and is described only in outline here.

> **Status.** Phase 1.2 — **implemented**. The cloud-agnostic `Provider` interface, the provider registry, and the **GKE Autopilot** adapter ([ADR 0003](../docs/adr/0003-gke-autopilot.md)) are built and green (`gofmt`, `go vet`, `go test -race`, `golangci-lint` all clean). The adapter is wired to the real Google Cloud SDK (`cloud.google.com/go/container/apiv1`, vendored): credential validation, cluster create (with readiness waiting) / status / delete (returns on the cloud's acceptance; completion is asynchronous), all driveable through the `cmd/planck` harness. Client construction is lazy — `Open`/`New` is creds-free and credential resolution surfaces through `Validate` — and accepts only a service-account key (`option.WithAuthCredentialsJSON(option.ServiceAccount, …)`). The adapter provisions a **private control plane** (no public IP; IAM-gated DNS-based endpoint — [ADR 0004](../docs/adr/0004-private-control-plane.md)): it sets `ControlPlaneEndpointsConfig` (public off / internal on / DNS on) at create and returns a DNS-endpoint kubeconfig (no embedded CA; it authenticates through a `gke-gcloud-auth-plugin` exec hook, so any `kubectl` use of it requires that plugin installed). Live cluster create/delete is covered by an opt-in integration test (`//go:build integration`, never in CI). The adapter also realizes the optional **`RegistryProvider`** capability ([ADR 0007](../docs/adr/0007-instance-owned-image-registry.md)) — the *instance's own image registry*: `EnsureRegistry` / `DeleteRegistry` / `RegistryToken` on **Artifact Registry**, a `farcast-<instance>` Docker repository in the instance's own project and region, with a repository-scoped `roles/artifactregistry.reader` grant for the cluster's node service account and short-lived push/pull tokens minted in-process. Its six admin calls are issued directly (`net/http` + `encoding/json`) while token minting and refresh stay inside the vendored `cloud.google.com/go/auth`, so the capability added **zero modules** — 31 vendored before and after. It is unit-tested over both of its seams (a fake `registryAPI`, a fake `http.RoundTripper`) plus an opt-in live ensure→grant→delete lifecycle behind the same `integration` tag. **Out of scope (later phases):** the manifest→K8s **translator** (4.2), wiring into `farcast install` (1.3), cost monitoring/enforcement (TechnoCore, 4.1), and the second/third providers (8.1).

---

## What Planck is — and isn't

**It is** the compute boundary. Planck wraps each cloud's managed-Kubernetes control API (GKE's `container`, EKS, AKS) behind a single `Provider` interface. Give it credentials and a cluster spec; it gives you back a ready cluster and the credentials to reach it. Every cloud-specific quirk — auth, regions, the shape of a "create cluster" call — lives inside an adapter and nowhere else. Cloud infrastructure an instance owns *around* its cluster — today the instance's own image registry ([ADR 0007](../docs/adr/0007-instance-owned-image-registry.md)) — arrives on the same boundary as an **optional capability**, so the rest of FarCast still never names a cloud.

**It is not** a Kubernetes reimplementation, an autoscaler, or a cost controller. Planck *provisions and tears down* clusters and (later) *translates* manifests into workloads. Watching resource usage, adapting CPU/memory/replicas, and enforcing the cost limit are **TechnoCore's** job ([`../technocore/README.md`](../technocore/README.md)). Planck provisions a low-cost cluster and then gets out of the way.

**It is not** where credentials live. Planck receives credentials, uses them, and returns cluster-access credentials to its caller. It never persists either. The `farcast` CLI is responsible for storing them locally under strict permissions ([`../farsight/cli/README.md`](../farsight/cli/README.md), phase 1.3). The same holds for the image-registry credential the optional capability mints: short-lived, handed back, used in-process, written down nowhere.

This single-responsibility framing follows directly from the [backend language strategy](../docs/adr/0002-backend-language-strategy.md): Planck's value *is* the cloud/K8s SDK it wraps, so it stays Go (first-party `client-go` and cloud SDKs), and it stays thin.

---

## Architecture & package layout

```
planck/
├── README.md                       ← this file
├── docs/                           ← deeper provider notes
├── planck.go (+ types.go)          ← PUBLIC: Provider interface, types, provider registry (Open/Register)
├── registry.go                     ← PUBLIC: optional RegistryProvider capability — the instance's image registry
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

- **`planck`** (root, public) declares the `Provider` interface, the shared types, the optional `RegistryProvider` capability, and a small provider registry: `Register(name, factory)`, `Open(name, cfg)`, `Providers()`. It imports **no** adapter, so it stays a dependency-light leaf that any module (the CLI, TechnoCore) can import for the types.
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

	// DeleteCluster requests teardown and returns once the cloud accepts the
	// delete operation — removal completes asynchronously.
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

### Provider registry & configuration

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

**CreateCluster** — fills defaults, issues the create call for an **Autopilot** cluster, then polls until the control plane reports `RUNNING` (or `ctx` expires); with Autopilot there is no node pool to size or wait for — compute is provisioned later from workload requests. It is effectively idempotent: an existing cluster with the same `Ref` is returned rather than duplicated, so a retried install converges instead of erroring. On success it returns the control plane's **DNS endpoint** and a kubeconfig that targets it ([ADR 0004](../docs/adr/0004-private-control-plane.md)).

**ClusterStatus** — maps the cloud's native status enum onto `ClusterStatus`, so callers (and TechnoCore later) reason in FarCast terms.

**DeleteCluster** — issues the delete and returns once the cloud *accepts* the operation; removal completes asynchronously (GKE reports the cluster `STOPPING` for a few more minutes). Blocking until removal completes — the counterpart of create's readiness wait — is a known gap. Deleting an already-absent cluster succeeds silently, so `farcast release` (1.4) and failed-install cleanup are safe to re-run.

All four honour `ctx` for cancellation and deadlines (create's readiness polling is minutes-long): a cancelled install or a `farcast` Ctrl-C propagates down and aborts the cloud operation's polling promptly.

---

## The instance image registry — an optional capability

Kubernetes has exactly one native way to get code into a Pod: the kubelet pulls an image from a registry. [ADR 0007](../docs/adr/0007-instance-owned-image-registry.md) settles *which* registry — **the instance's own, in the instance's own cloud project** — so nothing the cluster runs comes from a feed a third party controls. Creating and destroying that registry is cloud-control work, which is exactly Planck's boundary; building the images that go into it is not, and stays in the CLI ([`../farsight/cli/README.md`](../farsight/cli/README.md)).

**A word on the name.** "Registry" is overloaded in this package. `Register`/`Open` above are the **provider registry** — which adapters exist. This section is about the **instance image registry** — where one instance's container images live. The two never meet, and the code and these documents say "instance registry" or "image registry" whenever they mean the second.

It is an **optional capability**, not a fifth `Provider` method: callers type-assert it.

```go
// RegistryProvider is an optional Provider capability: the per-instance
// container image registry the instance owns (ADR 0007).
type RegistryProvider interface {
	// EnsureRegistry idempotently creates the instance's registry and grants
	// the cluster's nodes read access to it. Safe to call repeatedly.
	EnsureRegistry(ctx context.Context, spec RegistrySpec) (*Registry, error)

	// DeleteRegistry removes the registry and everything in it. Deleting an
	// absent registry is not an error (idempotent teardown).
	DeleteRegistry(ctx context.Context, ref RegistryRef) error

	// RegistryToken mints a short-lived credential for pushing to and pulling
	// from the instance's registry.
	RegistryToken(ctx context.Context) (RegistryToken, error)
}

// ErrRegistryUnsupported is what a caller reports when the assertion fails.
var ErrRegistryUnsupported = errors.New("planck: provider does not support an instance registry")
```

And the supporting types:

```go
// RegistrySpec describes the registry to ensure.
type RegistrySpec struct {
	Name     string            // instance name; the registry is named for it
	Location string            // region; the provider default applies if empty
	Cluster  ClusterRef        // the cluster whose nodes must be able to pull
	Labels   map[string]string // optional cloud resource labels
}

// RegistryRef identifies a registry for teardown.
type RegistryRef struct {
	Name     string
	Location string
}

// Registry is an ensured instance registry.
type Registry struct {
	Ref    RegistryRef
	Prefix string // image-path prefix, e.g. us-central1-docker.pkg.dev/proj/farcast-x
	Puller string // principal granted pull access, recorded for transparency
}

// RegistryToken is a short-lived registry credential. Password is sensitive —
// String() renders it redacted.
type RegistryToken struct {
	Username string
	Password string
	Expiry   time.Time
}
```

Why this shape:

- **Optional, so a cloud that cannot host images is still a perfectly good `Provider`.** A caller that needs the registry asserts `p.(RegistryProvider)` and reports `ErrRegistryUnsupported` when the assertion fails; a caller that merely *would have used* one skips it. Making it a fifth `Provider` method instead would have made every future adapter owe an image registry before it could compile a cluster.
- **Three methods, and the contract is a *prefix*.** What `EnsureRegistry` hands back is `Registry.Prefix` — a per-instance image-path prefix — plus, on demand, a credential for it. Deliberately *not* "one Artifact Registry repository object": ECR is repo-per-image with no single container resource, so the second provider (8.1) can realize the same prefix differently and no caller changes a line. Everything *below* the prefix is convention rather than interface (`system/<component>` for FarCast's own images, `app/<deployment>/<app>` for Phase 4 apps), and everything to do with the images themselves — resolving a digest, building, pushing — belongs to the CLI's OCI client, not here.
- **Idempotent at both ends, because the callers repeat.** `farcast install` ensures once, after the cluster; every later `farcast connect` re-ensures defensively, so an instance created before instances had registries converges on the next reconnect instead of failing later as an unexplained `ImagePullBackOff`; `farcast release` deletes the registry before removing local state — the same destroy-the-cloud-resource-before-the-record discipline the cluster gets. An already-present registry is success on ensure; an absent one is success on delete.
- **The token is a credential, not a config value.** It is minted per call, short-lived, and never persisted by Planck; `RegistryToken.String()` renders the password as `<redacted N bytes>`, the same treatment `Cluster.Kubeconfig` gets and for a sharper reason — a push credential for the instance's registry is a foothold on everything the cluster runs.

---

## First adapter: GKE Autopilot

The first cloud is **Google Kubernetes Engine in Autopilot mode** — decided in [ADR 0003](../docs/adr/0003-gke-autopilot.md) after a cost, egress-security, and in-cluster-control analysis. Google manages the nodes; FarCast pays per running Pod request; and the deny-by-default network boundary is enforced by always-on NetworkPolicy rather than privileged containers. Cluster creation is a single call against one mature first-party Go SDK, with no VPC/IAM/node-group scaffolding to stand up first.

- **Auth.** `Config.Credentials` holds a service-account key JSON; empty means Application Default Credentials (ADC) — the `gcloud` login or `GOOGLE_APPLICATION_CREDENTIALS`. `Config.Project` is the GCP project ID.
- **What Planck creates.** A regional **Autopilot** cluster (`Autopilot{Enabled: true}` on the GKE `Cluster` resource), which comes with GKE Dataplane V2 and Kubernetes NetworkPolicy **always on and undisablable** — the substrate FarCast's egress boundary relies on. No node count, machine type, or node pool is specified; Autopilot provisions compute from Pod requests at deploy time.
- **Control-plane network isolation ([ADR 0004](../docs/adr/0004-private-control-plane.md)).** The control plane is **private**: the public IP endpoint is **off**, the internal (VPC) endpoint is **on**, master authorized networks **on with an empty allowlist** (GKE requires it whenever the public endpoint is off, and it does not gate the DNS endpoint), and the IAM-gated **DNS-based endpoint** is **on** for external operator access — set via `Cluster.ControlPlaneEndpointsConfig` (`IpEndpointsConfig{EnablePublicEndpoint:false, Enabled:true, AuthorizedNetworksConfig:{Enabled:true}}`, `DnsEndpointConfig{AllowExternalTraffic:true}`). There is no internet-facing control-plane IP; `farcast` reaches the cluster through the DNS endpoint + IAM (`container.clusters.connect`), and in-cluster components (TechnoCore) use the internal endpoint.
- **Defaults.** GKE's default Kubernetes version and a default region; everything else is Autopilot-managed. The cost floor is low by construction (per-Pod billing, ~$37–51/mo at FarCast's baseline — see ADR 0003).
- **The instance's image registry ([ADR 0007](../docs/adr/0007-instance-owned-image-registry.md)).** The adapter realizes `RegistryProvider` on **Artifact Registry**. `EnsureRegistry` creates `farcast-<instance>` — Docker format, in the instance's region and project, carrying the instance's labels — and waits for the create operation to finish before touching IAM (a `setIamPolicy` on a repository the cloud has accepted but not yet materialised fails with a confusing `NotFound`); a repository that already exists is success, not a conflict. It then grants pull on that repository and returns the image-path prefix `<region>-docker.pkg.dev/<project>/farcast-<instance>` together with the principal it granted. `DeleteRegistry` blocks until the cloud has actually removed the repository — teardown that reports success on a merely *accepted* delete leaves billable storage behind with nobody watching it — and an absent repository is success. `RegistryToken` mints a ~60-minute OAuth2 access token from the same service-account key and returns it under the fixed username `oauth2accesstoken`: no `docker login`, no credential helper, no file on disk.
- **The pull grant is repository-scoped, and finding who to grant it to needs the project number.** The role is `roles/artifactregistry.reader`, bound **on the one repository** and never on the project: today's node identity is the *shared* Compute Engine default service account, so a project-level grant would hand every workload in the project the instance's images. The binding is a read-modify-write of the repository's IAM policy at version 3 that preserves the etag and any conditional bindings, and skips the write entirely when the member is already there — so the defensive ensure on every `connect` causes no policy churn. Nothing leans on that account's automatic project `Editor` grant either: it is org-policy-conditional and Google recommends disabling it, so a pull that depends on it works by accident and breaks on a hardened project. Deriving the account's email needs the project *number* (the cluster object reports its service account as the literal `default`), which the adapter looks up through Cloud Resource Manager (`projects.get`). A dedicated per-instance node service account is recorded follow-up hardening; `RegistrySpec.Cluster` is the field it will key on.
- **Extra IAM and APIs.** Beyond the cluster pair (`roles/container.admin` + `roles/iam.serviceAccountUser`), the installer service account gains exactly one role: **`roles/artifactregistry.admin`** — the narrowest predefined role that can create a repository (`repoAdmin` cannot), and one that also carries the repository-level `setIamPolicy` the pull grant needs, so the stored credential never holds project-IAM power. The project-number lookup needs no new role; `container.admin` already carries project-get. The project must have `artifactregistry.googleapis.com` and `cloudresourcemanager.googleapis.com` enabled alongside `container.googleapis.com` — both are in the [Phase 1 runbook](../docs/runbooks/phase-1-validation.md).
- **Dependency.** This introduces the Google Cloud Go SDK (`cloud.google.com/go/container/apiv1` and auth), vendored via `go mod vendor`. Its `Cluster` type supports Autopilot via the `autopilot` field and the private control-plane posture via `ControlPlaneEndpointsConfig` ([ADR 0004](../docs/adr/0004-private-control-plane.md)). It is the first non-stdlib dependency in the root module beyond the YAML parser, and exactly the kind of first-party cloud SDK ADR 0002 says Planck should ride.
- **The registry's admin calls are hand-issued REST; its auth is vendored.** Six calls carry the whole capability — create the repository, delete it, poll the resulting long-running operation, get and set the repository's IAM policy, and look up the project number — and each is issued with `net/http` + `encoding/json` against the versioned REST endpoint. Riding a client instead was measured, not assumed: the gRPC `apiv1` client adds thirteen modules, and Google's *generated* REST client (`google.golang.org/api/artifactregistry/v1`) — expected to be free, since that module is already vendored — adds one, because every generated client imports `internal/gensupport`, which imports `github.com/google/uuid` in non-test code. The budget for this feature was zero new modules in a binary that holds the operator's cloud credentials, and it held: 31 vendored modules before and after. What is deliberately *not* re-owned is auth. Credential resolution, token minting and refresh all stay inside the vendored `cloud.google.com/go/auth` — `httptransport.NewClient` owns the `Authorization` header, and `RegistryToken` hands out what that stack minted — which is precisely the part [ADR 0006](../docs/adr/0006-connect-bootstrap-kubectl.md) refused to hand-roll. A configured key is loaded as a service account *and nothing else*, so a credential file that is really an external-account configuration cannot redirect token minting at a URL of its author's choosing.

---

- **The repository must prove it is FarCast's, in both directions.** The registry is named after the instance, so the name could collide with a repository FarCast never created — and `farcast release` deletes this repository *and every image in it*. So a create that comes back `ALREADY_EXISTS` is followed by an inspect, and the delete path runs the same check first: the repository is adopted or removed only when its format is `DOCKER` and it carries the identifying labels install stamps on it (`managed-by: farcast`, `farcast-instance: <name>`). Anything else is refused with a message naming what does not match. An absent repository stays a success on the delete path, because teardown has to be idempotent.

## Cost & security posture

The two non-negotiable pillars shape even this early module (full analysis in [ADR 0003](../docs/adr/0003-gke-autopilot.md)):

- **Cost.** Autopilot's per-Pod billing gives a low, linear floor (~$37/mo empty, ~$45–51/mo with a few apps) with no idle-node waste and no charge for system overhead. Planck does **not** enforce the cost limit — that is mandatory at `farcast install` (1.3) and continuously monitored by TechnoCore (4.1) — but per-Pod pricing makes spending directly attributable per app, which is exactly what TechnoCore's cost breakdown needs. The instance's image registry adds a second billable resource and no gate: the capability creates and deletes it, and the CLI names its storage as a line item ([ADR 0007](../docs/adr/0007-instance-owned-image-registry.md) decision 8). Teardown is what keeps that honest — `DeleteRegistry` waits for the removal to actually happen, so `farcast release` cannot leave storage billing behind an instance nobody is watching.
- **Egress boundary.** Provisioning Autopilot is what gives FarCast its boundary substrate: **NetworkPolicy is always on and cannot be disabled**. The deny-by-default egress contract — every app Pod may reach only the FatLine proxy and DNS, nothing else — is generated per app by the translator (4.2); FatLine (a userspace proxy) does the manifest allowlisting. A Pod cannot bypass FatLine to reach the internet, by construction.
- **Security / privacy.** The control plane is **private** — no public IP — reachable only through the IAM-authenticated DNS-based endpoint ([ADR 0004](../docs/adr/0004-private-control-plane.md)), so there is no internet-facing API-server attack surface. The kubeconfig in `Cluster` is secret: never logged, returned to the caller for the CLI to store at `0600`. `RegistryToken.Password` is secret in the same way — minted short-lived, redacted by `String()`, never persisted by Planck — and the pull grant it complements is scoped to the instance's one repository rather than the project. The honest boundary: the cloud provider runs and can see the *managed control plane* and cluster metadata. FarCast's privacy guarantees (FatLine encrypting traffic, DataSphere encrypting data at rest) operate **above** the cluster. A freshly created cluster is "empty but alive" until later phases deploy onto it.

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

- **Unit tests (run in CI, every commit).** The adapter depends on a small interface that wraps the cloud client (e.g. a `gkeClient` seam), so tests inject a fake and exercise the logic that does *not* touch the network: spec→API-request mapping (including the Autopilot flag), default-filling, native-status→`ClusterStatus` mapping, error classification, and idempotent create/delete behaviour. The provider registry (`Open`/`Register`/unknown-provider error) is unit-tested with a fake provider, and a fake `Provider` that does *not* satisfy `RegistryProvider` pins the image-registry capability's optional shape. That capability has two seams of its own: a fake `registryAPI` covers name derivation, defaults, operation waiting, the IAM read-modify-write (including leaving other and conditional bindings untouched) and error classification, while a fake `http.RoundTripper` drives the wire protocol itself — request URLs and bodies, `NOT_FOUND` treated as success, `ALREADY_EXISTS` followed by the ownership check (adopted when the repository is FarCast's, refused when it is not), a hostile operation name refused rather than fetched — with no listener and no network.
- **Integration tests (gated, never in CI).** Behind a `//go:build integration` tag and reading credentials + project from `FARCAST_GKE_TEST_*` env vars: a cheap, read-only test validates credentials against the project, and a second test — further gated behind `FARCAST_GKE_TEST_CREATE=1` — creates a cluster, asserts readiness, and deletes it, with teardown registered up front so a failed run still cleans up. The image-registry capability is gated the same way: minting a token creates nothing and runs with the cheap tests, while the full ensure→grant→delete lifecycle — which mutates IAM on a real resource — needs `FARCAST_GKE_TEST_REGISTRY=1` and re-ensures before deleting to prove idempotence, again with teardown registered up front, because a leaked repository is billable storage nobody is watching. Documented in the test files' headers, run manually, and explicitly excluded from CI to protect the cost pillar.
- **Guardrails.** `go test -race`, `go vet`, and `golangci-lint`, per [AGENTS.md](../AGENTS.md). The kubeconfig field is covered by a test asserting it is never included in any log/`String()` output, and `RegistryToken` by the same discipline — its `String()` must render neither a minted password nor a plausible-looking one for the zero value.

---

## Decisions

1. **First cloud provider: GKE** (decided). PLAN 1.2 ties this to whichever cloud is easiest to test against. The `Provider` interface and the provider registry are designed so the second provider (8.1) is an additive `internal/providers/<cloud>` package plus one blank-import line; nothing else in FarCast changes.
2. **GKE Autopilot, not Standard** (decided — [ADR 0003](../docs/adr/0003-gke-autopilot.md)). A cost, egress-security, and in-cluster-control analysis found Autopilot competitive at FarCast's baseline (~$37–51/mo), operationally simpler (no node management), more resilient (regional), and a *stronger* boundary (undisablable NetworkPolicy) — while imposing constraints FarCast meets anyway (resource requests on every container, no privileged/host-network workloads, operate outside `kube-system`). A Standard/Spot hybrid is a Phase 5+ optimization, and would also be required if FatLine ever becomes a kernel/eBPF data plane (ADR 0002).
3. **`Config` shape.** A single neutral `Config` (credentials + project + location + `Extra`) keeps `Open` uniform across clouds; provider-specific needs ride in `Extra`. If this gets unwieldy with the second cloud, switch to per-provider config structs behind the same `Factory`.
4. **Private control plane by default** (decided — [ADR 0004](../docs/adr/0004-private-control-plane.md)). The adapter provisions clusters with no public control-plane IP — internal IP endpoint on, IAM-gated DNS-based endpoint on for the operator. In-cluster access (TechnoCore) is internal regardless; the operator CLI reaches the API server from anywhere via the DNS endpoint + IAM, with no bastion or VPN. The posture is mutable, so a constrained environment can fall back to an authorized-networks public IP without recreating the cluster.
5. **The instance's image registry is an optional capability, not a core `Provider` method** (decided — [ADR 0007](../docs/adr/0007-instance-owned-image-registry.md)). Callers type-assert `RegistryProvider` and get `ErrRegistryUnsupported` when a provider has none, so a cloud adapter can be complete without hosting images. The surface stays three methods wide and promises a per-instance image-path *prefix* plus a short-lived credential, not "one Artifact Registry repository object" — the shape ECR (repo-per-image) has to be able to realize at 8.1 without any caller changing. Everything image-shaped beyond that — digests, layers, pushes — is the CLI's, not Planck's.
6. **The registry's admin calls are hand-issued REST; its auth is vendored** (decided at implementation — [ADR 0007](../docs/adr/0007-instance-owned-image-registry.md) decision 2). Both client options were measured rather than assumed: gRPC `apiv1` costs thirteen modules and the generated REST client costs one (`internal/gensupport` → `github.com/google/uuid`), against a zero-new-module budget for a binary holding the operator's cloud credentials. So six REST calls ride `net/http` + `encoding/json` — and credential resolution, token minting and refresh stay entirely inside `cloud.google.com/go/auth`, which is the half [ADR 0006](../docs/adr/0006-connect-bootstrap-kubectl.md) refused to re-own. Revisit if a second registry flavour makes the hand-issued half wide enough to matter.

---

## Roadmap

| Phase | Adds |
|---|---|
| **1.2** (this) | `Provider` interface + provider registry; first adapter (validate / create / wait / delete); `cmd/planck` harness |
| 1.3 | `farcast install` wires the CLI to `planck.Open` + `CreateCluster`, with the mandatory cost limit |
| 1.4 | `farcast release` → `DeleteCluster` |
| 2.3 (ADR 0007) | optional `RegistryProvider` — the instance's own image registry (GKE: Artifact Registry), ensured at `install`, re-ensured at `connect`, deleted at `release` |
| 4.2 | `internal/translator` — `./farcast` manifest → K8s namespace + Deployment/Service/ConfigMap per app, plus the per-app deny-by-default egress NetworkPolicy |
| 5+ | Optional Standard/Spot hybrid node pool as a TechnoCore cost optimization (ADR 0003) |
| 8.1 | Second cloud provider adapter behind the same interface — including the image-registry contract on ECR |

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
- Private control plane (DNS-based endpoint) — [ADR 0004](../docs/adr/0004-private-control-plane.md)
- The instance owns its image registry (the optional capability) — [ADR 0007](../docs/adr/0007-instance-owned-image-registry.md)
- Installer service-account roles & API enablement — [Phase 1 runbook](../docs/runbooks/phase-1-validation.md)
