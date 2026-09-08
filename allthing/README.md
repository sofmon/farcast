# AllThing

> Sovereign intelligence — private inference the instance runs itself, scaled to zero; external providers only by declared policy.

AllThing is the module that turns "a request for intelligence" into "an answer the operator's policy admits". It owns the semantics of asking — who may answer, where the content may be, what it cost — and nothing about the machines that answer ([Planck](../planck/README.md), Kubernetes), the bytes that leave ([FatLine](../fatline/README.md)), or the money that stops them ([TechnoCore](../technocore/README.md)). Applications reach it through the [SDK](../sdk/go/README.md); the operator reaches it through `farcast`. A request that says nothing about privacy is served inside the instance or not at all.

This document specifies **Phase 6.0–6.2** — the application contract, the gateway, and the first private backend: an OpenAI-compatible inference runtime on the instance's own accelerator, fetched, verified and scaled to zero by the instance itself — and outlines the phases after it. The decisions it rests on are recorded in [ADR 0011](../docs/adr/0011-allthing-private-inference-first.md).

> **Status.** **Specification only — nothing below is implemented.** `allthing/cmd/allthing/main.go` is an empty `main` and `allthing/internal/{chat,providers}` are placeholders that this specification retires (the packages below replace them). The SDK's `farcast.AI()` is a stub returning `ErrNotImplemented`. Every cost figure is a model of a published rate card dated 2026-09 and has not met an invoice; every item marked *[to confirm live]* names how the Phase 6 runbooks confirm it. **Out of scope (later phases):** external providers (6.3), external spend in the cost ledger (6.4), system callers (6.5), embeddings, vision and reranking, a Gemini dialect (8.3), the FarSight GUI tile (7.3), Node/Python SDKs (8.4).

---

## What AllThing is — and isn't

**It is** a router with a policy and a lifecycle. It holds the backends the operator deployed or enabled, partitioned by whether content stays inside the instance; it decides for each request which of them may answer, in the operator's order; it starts and stops the one backend the instance owns; it emits one event per decision; it never widens what a request permitted.

**It is not** a provider shim. "Provider" in this repository means a cloud adapter opened by name (`planck.Open("gke")`); here the word survives only as the operator-facing name of an *external* backend. It is not a compute manager — it renders its own workloads like every system component and patches one Deployment's scale, and nothing else about Kubernetes. It is not a budget — it participates in the instance's one cost limit and adds no second one. It is not a proxy — content that leaves the instance leaves through FatLine's boundary, attributed, like everything else.

**It is honest about what private inference cannot hide.** Prompts, completions and the KV cache exist in plaintext in memory on the provider's hardware and are protected by the provider not looking — the same standing [ADR 0008](../docs/adr/0008-in-cluster-key-delivery.md) gives the keyholder. [What the cloud still sees](#what-the-cloud-still-sees) states the rest.

---

## Architecture & package layout

```
allthing/
├── README.md                  — this specification
├── backend/                   — Backend and Runtime: somewhere a request can be answered; the one we own
├── policy/                    — Candidates: the pure intersection rule (the privacy invariant lives here)
├── router/                    — partition at construction; try candidates in order; never widen
│   └── serveprivate.go        — the private path; a test parses its imports
├── runtime/                   — the inference runtime's lifecycle: scale 0↔1, phases, the wake rule
├── gateway/                   — the three-mux server: status, control, data; wire codes; SSE
├── catalog/                   — reviewed constants: models, files, hashes, licences, runtime arguments
├── internal/backends/
│   ├── openaicompat/          — the OpenAI dialect: the private runtime, and api.openai.com (6.3)
│   ├── anthropic/             — the Anthropic dialect (6.3)
│   └── fake/                  — test-only: records calls; fails the test when it must not be called
├── backendtest/               — the contract suite every adapter must pass
├── deploy/                    — Render(Config) → the apply stream: gateway, inference, PVC, Job, RBAC, NetworkPolicies
├── docs/
│   └── wire.md                — the normative wire contract and golden fixtures (Node/Python are written against it)
└── cmd/allthing/              — one binary: `allthing serve` (the gateway), `allthing fetch`, `allthing verify`
```

Data flow, private request:

```
 app ── farcast.AI().Chat(ctx, ChatRequest{Messages}) ── https, instance CA ──► allthing :8443 (data)
                                                                                   │ policy.Candidates(Private) = [private]
                                                                                   │ runtime idle → Wake() → "starting" now
                                                                                   │ runtime ready ↓
                                                                        allthing-inference :8000 (vLLM, GPU node)
                                                                                   │ /v1/chat/completions, SSE
                                                                                   ▼
 app ◄── ChatResponse{Content, Served: Private, Usage} ◄── event{Proto:"ai", Reason:"served_private"} → Shrike
```

Deployments: `allthing` (the gateway; tier `system`; one replica) and `allthing-inference` (tier `elective`; 0..1 replicas). Both in `farcast-system`. Image `system/allthing` is compiled by the CLI like every FarCast image; the inference image is a digest-pinned third-party reference ([Decisions](#decisions) 12).

---

## The Backend and Runtime interfaces

Grounded in the two backends that exist: an OpenAI-compatible HTTP+SSE server the instance starts and stops, and external HTTPS APIs with three wire dialects. The OpenAI dialect serves both the private runtime and `api.openai.com`, which is why privacy is a property of the backend, not of the dialect.

```go
package backend

// Privacy is where content goes when a backend serves it. It mirrors the
// SDK's Privacy word for word (mirror-tested) and is fixed at construction:
// the router partitions on it once and never asks a backend to be something
// it is not.
type Privacy string

const (
	Private  Privacy = "private"  // content stays inside the instance
	External Privacy = "external" // content leaves the instance, by declared policy
)

type Message struct{ Role, Content string }

type Request struct {
	App       string    // attribution (X-Farcast-App); never a permission by itself
	Messages  []Message
	MaxTokens int       // 0 = the backend's default
}

// Chunk is one increment of an answer. Done carries the final usage.
type Chunk struct {
	Content string
	Done    bool
	Usage   *Usage
}

type Usage struct{ InputTokens, OutputTokens int }

// Backend answers one request incrementally. A non-streaming answer is a fold
// over Chat; there is no second method to keep in step, so every adapter and
// every fake implements exactly one thing.
type Backend interface {
	Name() string     // operator-facing ("private", "anthropic"); never crosses to an application
	Privacy() Privacy
	Chat(ctx context.Context, req Request, emit func(Chunk) error) error
}

// Runtime is the optional capability of a Backend whose serving process the
// gateway brings up and down. Discovered by type assertion, like
// planck.RegistryProvider; an external backend is a complete Backend without it.
type Runtime interface {
	Backend
	State() State
	Wake(ctx context.Context) error  // ask for it; returns at once; refused with ErrHeld / ErrCostStopped
	Sleep(ctx context.Context) error // scale to zero once drained
}

var (
	ErrStarting    = errors.New("backend: runtime is starting")
	ErrCostStopped = errors.New("backend: runtime is stopped by the cost limit")
	ErrHeld        = errors.New("backend: runtime is held by the operator")
	ErrTooLarge    = errors.New("backend: request exceeds the context the backend can hold")
	ErrUpstream    = errors.New("backend: the serving backend failed")
)
```

Adapters are stdlib `net/http` plus a hand-written SSE reader; no provider SDK enters the module (31 vendored modules before and after, measured on every adapter commit — the [ADR 0007](../docs/adr/0007-instance-owned-image-registry.md) discipline). There is no registry: three compiled-in adapters chosen by a rendered flag are a `switch` in the composition root.

### Supporting types — policy and router

```go
package policy

// Fallback is the operator's policy for an ExternalAllowed request when the
// private runtime is not ready. "never" is the default and the secure one.
type Fallback string

const (
	FallbackNever                  Fallback = "never"
	FallbackWhenPrivateUnavailable Fallback = "when-private-unavailable"
)

type Policy struct {
	Fallback     Fallback
	ExternalApps map[string]bool // apps whose manifest declared ai.external; "" is the operator
}

// Candidates returns the backends permitted for a request, in order. It is
// pure and total: for Private it returns at most the private backend and never
// an external one, whatever the operator configured. Empty means refuse.
func Candidates(privacy backend.Privacy, app string, p Policy,
	private backend.Backend, external []backend.Backend) []backend.Backend
```

| request | private runtime deployed | external enabled | app declared `ai.external` | candidates |
|---|---|---|---|---|
| private, or absent, or unknown | yes | any | any | `[private]` — never anything else |
| private | no | any | any | `[]` → refused |
| external | yes | none | any | `[private]` |
| external | yes | `[a, b]` | yes | `[private]`, then `[a, b]` only under `when-private-unavailable` |
| external | no | `[a, b]` | yes | `[a, b]` |
| external | any | `[a, b]` | no | `[private]` or `[]` |

```go
package router

type Config struct {
	Private  backend.Backend   // the instance's own backend, or nil
	External []backend.Backend // enabled external backends, in the operator's order
	Policy   policy.Policy
	Events   event.Sink        // fatline/event; Proto "ai"
}

// New refuses a Private whose Privacy() != backend.Private and any External
// whose Privacy() != backend.External: the partition is checked once, at
// startup. The private path is a distinct function that cannot range over
// External, and a test parses its imports.
func New(c Config) (*Router, error)

type Decision struct {
	Backend backend.Backend
	Reason  string // served_private | forwarded_external | refused_privacy | refused_app | refused_no_backend | starting | held | cost_stopped
}

func (r *Router) Chat(ctx context.Context, privacy backend.Privacy, req backend.Request,
	emit func(backend.Chunk) error) (Decision, error)
```

`Chat` never widens on error: a `Private` request whose one candidate is `idle` calls `Wake` and returns `ErrStarting` in the same round trip — the request *is* the wake signal; `starting` returns `ErrStarting`; `cost-stopped`, `held` and `failed` return their sentinel. Only under `FallbackWhenPrivateUnavailable`, and only for a request that permitted it, does the loop continue to an external candidate. Every decision emits exactly one `event.Event{Proto: "ai", Tenant: "system", App, Host: <backend name>, Reason}` before the answer starts.

### Supporting types — the runtime lifecycle

```go
package runtime

type Phase string

const (
	PhaseAbsent      Phase = "absent"        // no private inference enabled on this instance
	PhaseUnfetched   Phase = "unfetched"     // enabled; the volume holds no verified weights
	PhaseFetching    Phase = "fetching"      // the fetch Job is running
	PhaseIdle        Phase = "idle"          // replicas 0 by our own choice; a request wakes it
	PhaseStarting    Phase = "starting"      // replicas 1; not yet serving
	PhaseReady       Phase = "ready"
	PhaseDraining    Phase = "draining"      // idle timeout elapsed; in-flight requests finishing
	PhaseCostStopped Phase = "cost-stopped"  // the kernel stopped it, or its status forbids a wake
	PhaseHeld        Phase = "operator-hold" // farcast ai hold; only the operator clears it
	PhaseFailed      Phase = "failed"        // start deadline, attempt budget or verification; Reason says why
)

type State struct {
	Phase       Phase     `json:"phase"`
	Since       time.Time `json:"since"`
	Generation  uint64    `json:"generation"` // bumps on every model or runtime change
	Reason      string    `json:"reason,omitempty"` // unschedulable | quota | image-pull | verify | crash-loop | oom | deadline | kernel-stopped | kernel-status-stale | cost-ceiling
	Model       string    `json:"model"`
	Accelerator string    `json:"accelerator"`
	CostLevel   string    `json:"cost_level"` // from technocore-status; "unknown" when absent
}

// Cluster is the slice of technocore/kube the controller calls. The deploy
// test enumerates exactly these verbs in the gateway's Role.
type Cluster interface {
	GetDeployment(ctx context.Context, ns, name string) (kube.Deployment, error)
	Scale(ctx context.Context, ns, name string, replicas int) error
	ListPods(ctx context.Context, ns, selector string) ([]kube.Pod, error)
	GetConfigMap(ctx context.Context, ns, name string) (*kube.ConfigMap, error)
}

type Controller struct {
	Cluster       Cluster
	Namespace     string        // farcast-system
	Deployment    string        // allthing-inference
	Health        func(ctx context.Context) error // GET /health on the inference Service
	IdleTimeout   time.Duration // default 10m; rendered argument
	StartDeadline time.Duration // default 20m [to confirm live: five measured cold starts]
	MaxAttempts   int           // default 2 per hour; each attempt bills a node
	Ceiling       string        // kernel level at or above which no new cold start; default "90%"
	StatusMaxAge  time.Duration // default four kernel ticks; older reads as reached
}

func (c *Controller) Run(ctx context.Context)          // polls every 15s: pods, health, idle, kernel status
func (c *Controller) State() State
func (c *Controller) Wake(ctx context.Context) error   // the wake rule; replicas clamped to {0, 1} in code
func (c *Controller) Sleep(ctx context.Context) error
func (c *Controller) Hold(reason string)                // not durable across a gateway restart
func (c *Controller) Release()                          // lands on idle, never ready
```

**The wake rule — a scaler that cannot see the meter does not spend.** `Wake` refuses unless `technocore-status` is present, fresh, `level` is below `Ceiling`, and `allthing-inference` is not in the kernel's `stopped` set. Absent, stale or unreadable reads as `reached`. `enforcing: false` is the kernel's choice; the level is honoured regardless. At `reached` the controller sleeps pre-emptively. If a bug wakes the runtime while `reached`, the kernel stops it within a tick and records it; flapping is bounded to one.

```
               farcast ai private enable --model <name>
  ┌────────┐ ─────────────────────────────────────► ┌───────────┐  fetch Job (verified)  ┌──────────┐
  │ absent │                                        │ unfetched │ ─────────────────────► │ fetching │
  └────────┘ ◄──── farcast ai private disable ───── └───────────┘ ◄── fetch failed ───── └────┬─────┘
                                                                                             │ MANIFEST.json
     idle-timeout elapsed, nothing in flight (draining)                                      ▼
  ┌──────────────────────────────────────────────────────────────────────────────►  ┌──────┐
  │                          Wake(): status fresh ∧ level < ceiling ∧ not stopped     │ idle │ ◄────────┐
  │                                                                                   └──┬───┘          │
  │                                                                                      ▼               │ level < reached
  │                                                                              ┌──────────┐           │ (next request)
  │      deadline / attempt budget / verify failed ──► ┌────────┐ ◄─────────────│ starting │           │
  │                                                    │ failed │                └──┬────┬──┘           │
  │      farcast ai private retry ──► idle             └────────┘   /health ok      │    │ crash-loop     │
  │                                                                                 ▼    ▼                │
  │                                                                           ┌───────┐   kernel stopped │
  └───────────────────────────────────────────────────────────────────────────│ ready │─ it, or level ──┤
                                                                              └───────┘   == reached     │
  any phase ── farcast ai hold --reason ──► operator-hold ── farcast ai release ──► idle    ┌──────────────┐
                                                                                            │ cost-stopped │
                                                                                            └──────────────┘
```

---

## The gateway

`allthing serve` composes the keyholder's shape, copied not imported ("modules mirror shapes, they do not import each other"): three muxes on three ports, each for a different audience.

| Mux / port | Route | Auth | Notes |
|---|---|---|---|
| status `:8444`, plain HTTP | `GET /livez` | none | always 200; never fails because inference is starting or held |
| | `GET /readyz` | none | 200 iff the gateway can classify (config loaded, backends constructed); **not** gated on the runtime |
| | `GET /v1/state` | none | exactly what `AIStatus` carries — `{"instance","phase","reason","since","generation","private":{"configured"},"external":{"permitted"}}`; never a model, an accelerator, a provider or the kernel's level, because any Pod with egress to `:8444` can read this mux; no prompts, no keys, no app names |
| data `:8443`, server TLS `<instance>.allthing.farcast` | `POST /v1/chat`, `POST /v1/chat/stream` | `X-Farcast-App` required (403 `permission` without it); `X-Farcast-Privacy` | failures carry `X-Farcast-Code` and `{code, message}` with sentinel text only — never a prompt fragment, never a provider's error body |
| control `:9443`, mTLS | `GET /v1/state` (the full document: model, accelerator, providers, fallback policy, kernel level and `stopped`), `POST /v1/chat[/stream]`, `POST /v1/wake\|sleep\|hold\|release`, `GET /v1/usage`, `GET /v1/metrics` | URI SAN `farcast://<instance>/operator`; later `farcast://<instance>/system/<name>` | the gateway verifies the SAN itself; it does not rely on FatLine, whose deployed tunnel admits any instance-CA leaf |

Services: `allthing` (data; readiness-gated on the **gateway**, which is ready as soon as it can classify and refuse honestly, so a cold runtime never yields a dial failure), `allthing-status` and `allthing-control` (`publishNotReadyAddresses: true`, so a restarting gateway still explains itself). Serve composition copies `datasphere serve`: listeners as flags; TLS material as environment from a Secret (`ALLTHING_TLS_CA/CERT/KEY`); refuse dangerous `GOTRACEBACK`; `RLIMIT_CORE=0`; JSON `slog` to stdout exactly as the keyholder emits it (convergence on the SDK's record shape is a repository-wide change, not this one); `signal.NotifyContext`; bounded shutdown; the import-graph test that forbids `pprof`, `expvar` and `golang.org/x/net/trace` (which registers `/debug/*` on the default mux at init and already sits in the keyholder's graph) on a process that holds prompts and keys, plus a test that every `http.Server` carries its own non-nil `Handler` — the property that actually keeps `/debug/*` off the keyholder today, and which no test there pins.

**Streaming on the wire:** `text/event-stream` with events `state` (heartbeat), `delta` (`{"content"}`), `done` (`{"served","usage"}`) and `error` (`{"code","message"}`); a stream that closes without `done` is a failure, never a shorter answer; the `state` heartbeat interval is pinned there; a client never half-closes its side of a relayed stream after writing the request (FatLine turns a half-close into a FIN and the gateway's HTTP/1.1 server cancels the handler on it). The normative contract — paths, headers, codes, bodies, golden fixtures — lives in [`docs/wire.md`](docs/wire.md); the Node and Python SDKs are written against it, not against Go.

### Error sentinels and wire codes

| Wire code (`X-Farcast-Code`) | HTTP | SDK sentinel | What an application does |
|---|---|---|---|
| `starting` | 503 | `ErrAIStarting` | wait and retry (`Retry-After`); the request woke the runtime |
| `held` | 503 | `ErrAIHeld` | do not retry; an operator acts; `AIStatusOf` says `cost` or `operator` |
| `refused` | 403 | `ErrAIRefused` | do not retry as posed; policy admits no backend for this class |
| `too-large` | 413 | `ErrTooLarge` | shorten the request |
| `permission` | 403 | `ErrPermission` | the app header is missing or refused |
| `bad-request`, `upstream`, `not-configured`, unknown, empty | 400 / 502 / 409 / — | `ErrAIUnavailable` | the total-mapping catch-all; never `ErrNotImplemented`, never `ErrAIRefused` |

The codes live in `sdk/go/aiwire.go` — a new file, because `datasphere/keyholder/wire_test.go` regex-mirrors `sdk/go/wire.go` character for character and must keep doing so — and `gateway/wire_test.go` mirrors them in both directions with a regex that admits the `AICode` prefix. A code may be added, never renamed or reused; the freeze is enforced by the fixtures in `docs/wire.md`, not by the mirror test alone.

---

## The private runtime

### The contract, and what stays outside it

An OpenAI-compatible HTTP server on `:8000` with `GET /health` and `POST /v1/chat/completions` (SSE when `stream: true`), started by one container image, reading weights from a directory, needing one accelerator of a named class. Nothing in `router`, `policy`, `gateway`, the SDK, the wire codes or the state body knows what a GPU, a node, a G2 shape or vLLM is; the adapter is `openaicompat`, not `vllm`. Cloud- and vendor-specific facts live in exactly two places: the placement block of the inference template in `deploy` (filled from `planck.AcceleratorClass`) and the accelerator row of `technocore/pricing`. A second cloud adds an `AcceleratorProvider` realisation and a rate-card row; a second runtime (llama.cpp's server, SGLang) is a different pinned image and catalog arguments behind the same adapter.

```go
// planck/accelerator.go — an optional Planck capability beside registry.go.
type AcceleratorClass struct {
	Name      string            // FarCast's name, e.g. "nvidia-l4"
	MemoryGiB int               // 24 for an L4
	Selector  map[string]string // GKE: {"cloud.google.com/gke-accelerator": "nvidia-l4"}
	Resource  string            // the extended resource key: "nvidia.com/gpu"
	HourlyUSD float64           // the smallest node shape that fits one, all-in; dated by AsOf
	AsOf      string
}

type AcceleratorProvider interface {
	Accelerators(ctx context.Context) ([]AcceleratorClass, error)
}
```

### The workload

`deploy.Render` emits, beside the gateway's objects, all in `farcast-system`, all labelled `app.kubernetes.io/managed-by: farcast` on workload **and** Pod template (a controller does not copy its labels to Pods, and the kernel meters Pods):

| Object | Name | Shape |
|---|---|---|
| Deployment | `allthing-inference` | `replicas: 0` at render; `strategy: Recreate`; labels `app.kubernetes.io/name: allthing-inference`, `farcast.sofmon.com/tier: elective`, `farcast.sofmon.com/accelerator: nvidia-l4`; `automountServiceAccountToken: false`; no ServiceAccount |
| — init container | `verify` | `system/allthing` running `allthing verify --catalog <name> --root /models`: re-hashes every catalog file against reviewed constants; refuses extra, missing or mismatched files; a non-zero exit means the Pod never serves |
| — container | `vllm` | `deploy.InferenceImage`, a digest-pinned reviewed constant (`docker.io/vllm/vllm-openai@sha256:…`; the `-cu129` variant on Autopilot's default R535 driver, or the CUDA-13 image with `gke-gpu-driver-version: latest` *[to confirm live]*); `nodeSelector` from `AcceleratorClass.Selector`; `resources.limits[<Resource>]: 1`; `requests.cpu`/`memory` exported as `InferenceRequestCPUMilli = 2000` / `InferenceRequestMemMiB = 8192`; `ephemeral-storage: 20Gi`; arguments rendered verbatim from the catalog — `--model /models/<name> --served-model-name <name> --max-model-len N --quantization … --api-key $(ALLTHING_INFERENCE_KEY) --ssl-certfile … --ssl-keyfile …` *[to confirm live on the pinned digest with `vllm serve --help`: the listener-after-load behaviour, `--api-key`, `--served-model-name`, `--max-model-len` and the metric names were read from `main`, not the v0.28.0 tag; `--ssl-*` is unsourced]*; request logging left at its default-off — never `--disable-log-requests`, which upstream deprecated for `--enable-log-requests`; **never** `--trust-remote-code` (a test greps the arguments); env `HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1`, `VLLM_NO_USAGE_STATS=1`, `DO_NOT_TRACK=1` (the last two are belt, unverified against the tag; the empty egress list is the control), `VLLM_CACHE_ROOT=/cache`, `HOME=/tmp`; `startupProbe` `GET /health` sized to `StartDeadline`; `readinessProbe` `/health` every 5 s (the listener starts only after the model is loaded, so 200 means loaded) |
| — volumes | | PVC `allthing-models` read-only at `/models`; `emptyDir` at `/tmp` and `/cache`; `emptyDir{medium: Memory, sizeLimit: 2Gi}` at `/dev/shm` |
| Service | `allthing-inference` | ClusterIP `:8000`, readiness-gated on `/health` |
| Secret | `allthing-inference-tls` | server leaf `<instance>.allthing-inference.farcast` + CA certificate (`identity.IssueInferenceServer`) and a random bearer key the gateway presents |
| NetworkPolicy | `allthing-inference` | ingress: only Pods `app.kubernetes.io/name=allthing` on 8000; **egress: an empty list** — not even DNS |
| PVC | `allthing-models` | `ReadWriteOnce`, default StorageClass, `Σ Size × 1.2`; cents, surfaced not gated |
| Job (rendered by `farcast ai model fetch`, deleted on success) | `allthing-fetch` | `system/allthing` running `allthing fetch --catalog <name> --dest /models` through `fatline-egress:3129` under a fetch-scoped `--system-allow` for every host in the entry's `Source.Hosts` (the allowlist is exact-host: the hub and the CDN hosts its redirects land on; a redirect elsewhere is refused, not followed), removed on the Job's completion document rather than on the CLI surviving the fetch; streams each file to a temp name, verifies as it streams, renames on success, deletes on mismatch, writes `MANIFEST.json {catalog, generation}`; NetworkPolicy egress DNS + `:3129` only; labelled `tier: elective` for metering |

**Container posture — the documented exception.** vLLM is third-party code that runs as root by default (a non-root uid 2000/gid 0 exists and is a later hardening). It falls on the *application* side of FarCast's posture line, as Kaniko does in [ADR 0010](../docs/adr/0010-application-image-builds.md): root accepted and stated; `readOnlyRootFilesystem: true` with the three named `emptyDir`s, relaxed only on runbook evidence, recorded as a finding; `allowPrivilegeEscalation: false`; all capabilities dropped; `RuntimeDefault` seccomp; no privileged, no host namespaces, no device mounts. **The compensating control is the empty egress list**: a compromised inference container is a container that can talk to exactly one peer. It is the least-hardened Pod in `farcast-system`, and this sentence is where that is said.

**Autopilot admissibility, checked not recalled** (2026-09-03): a GPU Pod is requested with `nodeSelector cloud.google.com/gke-accelerator: nvidia-l4` and `resources.limits nvidia.com/gpu: 1`; on GKE ≥ 1.29.4 the Accelerator compute class applies automatically; driver installation is automatic; root is permitted; `hostIPC`/`hostPID`/`hostNetwork` and privileged are blocked; `emptyDir` with `medium: Memory` is an allowed volume type; image volumes are **not** — which is why weights ride a PVC; accelerator Pods have no minimum CPU/memory and may request ephemeral storage above the 10 GiB general-purpose cap. These come from Google's autopilot-security and autopilot-resource-requests pages and its vLLM tutorial (re-read 2026-09-04), not from the repository: [ADR 0003](../docs/adr/0003-gke-autopilot.md) asserts only the host-namespace block and the general-purpose floor, and `technocore/pricing` today raises every Pod to that floor, which decision 17 changes. The first runbook step proves a GPU Pod schedules at all and reads back what the admission webhook kept — the requests, the memory `emptyDir` (and whether its size counts against the Pod's memory request), the 20Gi ephemeral request — and that an `image:` volume is rejected.

### Model artifacts

The catalog is reviewed constants (`catalog/catalog.go`):

```go
type File struct{ Path, SHA256 string; Size int64 }

type Model struct {
	Name          string        // operator-facing catalog name
	Source        Source        // Hosts the fetch allowance opens (exact match: the hub and its redirect CDN hosts) and the path template; a redirect elsewhere is refused
	Files         []File        // safetensors + config.json + tokenizer files only; a compile-time test refuses other extensions
	SizeGiB       int
	MinMemoryGiB  int           // refuse enable if the accelerator class has less
	Quantization  string
	MaxModelLen   int
	StartDeadline time.Duration
	RuntimeArgs   []string      // rendered verbatim; a test forbids "trust-remote-code"
	Licence       string
	Reviewed      string        // date and reviewer
}
```

The hub's tree API publishes every LFS file's byte size and SHA-256, which is the integrity manifest an entry records. `.bin`, `.pt` and `.pkl` are refused by constant and by the fetch code: a pickle is remote code execution dressed as a model. Gated repositories are out of the first catalog. The arithmetic every entry must carry: a 14B model in bf16 (~29.5 GB) does not fit an L4's 24 GB; FP8 (~15.3 GB) fits with a 16–32k context; AWQ 4-bit (~10 GB) fits with ample KV budget at a measured cost of one to two benchmark points.

**Verified twice.** The fetch Job verifies as it streams; the `verify` init container re-hashes before vLLM sees a byte, because the disk is provider-writable and a marker file is not a verification. Hubs do not sign; the reviewed hash is the claim. **Updates:** a new catalog entry (a reviewed commit), `farcast ai model fetch` into a sibling directory, `farcast ai private enable --model <new>` with `Generation+1`; the old directory is removed after the first successful `ready`; rollback is the previous entry.

**Rejected homes for weights.** The operator's laptop (10–30 GB per model change against "the instance is the anchor, not one laptop"); the hub at every cold start (a third party learns every wake; the Pod needs an egress rule); DataSphere (public bytes under a seal that exists for data whose exposure is the harm, coupling inference to `restart-sealed`); an OCI artifact in the instance registry (the sovereign end state, deferred until a streaming OCI push and a Workload Identity push grant exist); a bucket with a model streamer (a cloud-specific loader inside the runtime Pod).

### The inference image

A digest-pinned upstream reference recorded as a reviewed constant with its maintenance status — [ADR 0010](../docs/adr/0010-application-image-builds.md) decision 10's shape. Stated plainly: the kubelet's pull is node-level egress FatLine does not see, and the pin makes the third party untrusted *transport*, not an audited *author*. Google lists public Docker Hub beside Artifact Registry as an image-streaming source, so the pinned reference is expected to stream; parity with a same-region mirror is unmeasured (first pulls may not benefit, and every wake on a fresh node is a first pull; Docker Hub rate-limits anonymous pulls; the bytes are off-Google egress) and is a 6.2 runbook measurement. [ADR 0007](../docs/adr/0007-instance-owned-image-registry.md) refused a Docker Hub source in the runtime path for application images; ADR 0011 argues that exception for the inference image alone, bounded by the pin and the NetworkPolicy. The mirror into `<prefix>/system/vllm` becomes mandatory when private nodes land.

### Cold start, measured not recalled

Reported for an L4 Pod on Autopilot (2026-09-03; none measured by this project): node provisioning 60–120 s; image pull 30–90 s with streaming; volume attach seconds; vLLM bootstrap, compile and CUDA-graph capture 1–4 minutes (a persisted compile cache and trimmed capture sizes are the two levers with published effect); weight load 10–30 s. End to end, 3–12 minutes. The 6.2 runbook measures five cold starts and the node-deletion tail; `StartDeadline` and `IdleTimeout` defaults are set from them.

---

## The application contract

`farcast.AI()` follows the storage capability's discipline line for line. The accessor reads `FARCAST_AI_ENDPOINT` (https), `FARCAST_AI_STATUS_ENDPOINT` (**http** — the status listener is plain HTTP), `FARCAST_AI_CA` and `FARCAST_AI_SERVER_NAME` (`<instance>.allthing.farcast`, pinned separately from the dial address) on first use and yields exactly one of stub (`ErrNotImplemented`), broken (present-but-unusable → `ErrAIUnavailable` with the cause) or live: TLS 1.3, instance CA pinned, never system roots. The application's name rides `X-Farcast-App` from the ambient `FARCAST_APP_NAME`.

```go
type Privacy string

const (
	Private         Privacy = "private"  // the zero value "" is read as Private everywhere, and sent explicitly
	ExternalAllowed Privacy = "external" // the repository's own word for outside the boundary
)

type ChatRequest struct {
	Privacy  Privacy
	Messages []Message
	// No model, backend, quality, latency or cost field: those are the operator's.
}

type ChatResponse struct {
	Content string
	Served  Privacy // where the answer actually came from; an application can tell its user the truth
	Usage   Usage   // a count, not a cost
}

// AIAPI's two methods are frozen: applications fake this in their tests.
type AIAPI interface {
	Chat(ctx context.Context, req ChatRequest) (ChatResponse, error)
	ChatStream(ctx context.Context, req ChatRequest) (Stream, error)
}

// Optional, discovered by type assertion (the StorageStatusOf pattern).
type AIStatusAPI interface {
	AIAPI
	Status(ctx context.Context) (AIStatus, error)
}
func AIStatusOf(ctx context.Context, a AIAPI) (AIStatus, error) // ErrNotImplemented for a plain fake

type AIStatus struct {
	State      AIState    // ready | idle | starting | held | unavailable
	Reason     HoldReason // "" | cost | operator
	Since      time.Time
	Generation uint64
	Private    bool // private inference is configured on this instance
	External   bool // the operator permits at least one external provider
}
```

`ChatRequest.Model` is removed: referenced nowhere, it contradicts "the application never names a provider", and it is the field a fallback chain would key on. The effective decision is the intersection of the request, the application's manifest declaration and the instance policy; every absence is a no. The status endpoint is consulted only to explain an already-failed call — `starting` versus `held` versus `unavailable` — never to retry or downgrade; an unknown phase reads as not-ready. "Never an empty result with a nil error", applied to streaming: `Recv` returns `io.EOF` only after `done`.

**Attribution versus authentication.** Until 4.4's per-app leaves, `X-Farcast-App` is attribution, not authentication — the keyholder's `X-Farcast-Scope` position, stated plainly. A declared name may carry a manifest-declared external permission because the harm a spoofed name can do is bounded: an application claiming another's name can send *its own* content to a provider the operator already enabled and reviewed a reason for; it cannot make content leave an instance where no provider is enabled, and it cannot reach a provider host itself, because FatLine's `:3129` is in no application's NetworkPolicy.

---

## The operator surface

A `farcast ai` group like `kernel`; `chat` stays a top-level verb.

| Verb | Effect | Gate |
|---|---|---|
| `farcast ai deploy <instance> [--allthing-image] [--source] [-y]` | requires FatLine and the `allthing` stream route (else "run `farcast redeploy` first"); compiles and pushes `system/allthing` on a preflight miss (the tag is the CLI's version, so a preflight hit redeploys whatever that tag already holds — a gateway change ships only with `--source` or a version bump, FatLine's rule inherited); issues the gateway's leaf; renders the gateway objects; **pre-creates** the usage ConfigMap; records `meta.AI` before apply | standing ~$3.70/month from `deploy.RequestCPUMilli/MemMiB`; joins `floorNow` |
| `farcast ai status <instance>` | state, usage, the kernel document, FatLine's allowances; the derived mode and one explain line; names drift — a running FatLine without the `allthing` route or the recorded allowances (a pre-AI CLI's `redeploy` drops both, fail-closed), or a `system` allowance that is not an enabled provider's host | — |
| `farcast ai private enable <instance> --model <name> [--idle-timeout 10m] [--ceiling 90%] [-y]` | requires `meta.Kernel.Deployed` metering `farcast-system`; refuses a model that does not fit the class; asks Planck for the class facts; renders PVC, Job, the inference objects and the gateway's `--private` arguments; renders the fetch-scoped `--system-allow`, redeploys FatLine, and removes it after `MANIFEST.json` | the while-active gate below |
| `farcast ai private disable [--delete-weights]` / `retry` / `warm` / `hold --reason` / `release` | control intents; `warm` quotes the per-wake minimum | `warm`: consent |
| `farcast ai model fetch <instance> <name>` | the fetch Job for a new entry into a sibling directory | cents |
| `farcast ai external enable <instance> --provider anthropic\|openai --model <m> --reason "…" --key-stdin [--fallback never\|when-private-unavailable]` (6.3) | key from stdin into Secret `allthing-external` (never argv, never a temp file); `--external` on the gateway; `--system-allow <host>` on FatLine; recorded without the key | consent: "content marked external will leave the instance to `<host>`; the meter cannot see token spend" |
| `farcast ai remove <instance> [--keep-weights]` | sleep → inference objects → Job → wait for their Pods to leave (else the `pvc-protection` finalizer holds the billing disk) → PVC → gateway → Secrets → FatLine without allowances or route → `meta.AI` cleared; `cluster.Client.Delete` (`--ignore-not-found --wait --timeout`) on the `clusterApplier` seam and its fake; called by `farcast release` **before** it writes `InstanceDeleting` and before `DeleteCluster`; if the API server is unreachable, `release` proceeds, prints the PVC's disk as a possible orphan and records it | consent |
| `farcast chat <instance> [--external]` | streaming conversation over the tunnel: one relayed stream per turn, TLS inside it pinned to `<instance>.allthing.farcast`, `POST /v1/chat/stream` read until `done`; its own client in the keyholder client's shape, not its code — no 30 s request timeout, no 1 MiB cap, a 120 s inter-chunk idle limit (the HTTP/2 transport sends no liveness pings), never a `CloseWrite` after the request; a stream severed by a FatLine rollout (5 s drain) is `ErrAIUnavailable`, never a shorter answer; the deployed FatLine admits any instance-CA leaf to the route, so the control mux's URI-SAN check is what keeps keeper devices out, and a test proves it | — |

`meta.AI` records what was deployed and from what — image digests, model, accelerator, idle timeout, ceiling, generation, the hourly figure quoted at enable time with its `AsOf`, enabled providers with host, model, reason and the Secret's *name* — and nothing secret. Provider keys live in a Kubernetes Secret consumed as environment: the "FatLine-server-leaf case, not the keyring case" ([ADR 0010](../docs/adr/0010-application-image-builds.md) decision 4), readable by the managed control plane as every Secret is, stated. They move behind `farcast.Secrets()` at 5.3 without changing the contract. Operating modes are **derived**, never stored: `absent`, `private`, `external-only` (with the warning that every `Private` request is refused), `private + external by policy`. "External disabled" is the absence of four verifiable things — no `--external` argument, no `allthing-external` Secret, no provider host in FatLine's `--system-allow`, `external_backends: []` in the state — each printed by `status`.

The manifest changes nothing in the first milestone; with 6.3 it gains one additive, reviewed key — `ai: {external: {reason: "…"}}` — a security contract like `external:` with its `reason`, rendered by `farcast run` into an operator-written, gateway-read `allthing-policy` ConfigMap. Never a model, an accelerator or a resource hint.

---

## What the cloud still sees

Stated here because overpromising privacy is worse than not promising it.

**For a `Private` request on private inference:** prompts, completions and the KV cache exist in plaintext in the inference container's memory, in GPU memory and in the gateway's memory, on the provider's hardware — protected by the provider not looking, exactly as [ADR 0008](../docs/adr/0008-in-cluster-key-delivery.md) says of the keyholder. A node memory snapshot, a live migration or a hypervisor-level read exposes them; not defended. The weights rest on a provider-managed disk the provider can snapshot, and in VRAM; they are public, so what the cloud learns is *which model*. Every wake is a node-provisioning event with a timestamp in the provider's logs and bill: a scale event means "someone asked something private". Request timing and byte sizes cross the VPC between the gateway and the inference Pod (content under TLS once the runtime leaf lands; timing and size not); token counts are approximately derivable from streaming cadence. The kernel's status document, the policy document and the usage document are cloud-resident and carry app names and counts — never prompts. Nodes have external IPs (private nodes deferred); the kubelet pulls the inference image from a third-party registry over node-level egress FatLine does not see; GPU utilisation is visible to the provider through its own metrics whether or not FarCast reads them.

**Hidden from every third party other than the cloud provider:** everything — no model hub after the fetch, no telemetry, no provider. **Hidden from the cloud provider:** nothing that is in memory; the cloud is blind to content on the wire because of TLS, not blind.

**For an `ExternalAllowed` request served externally:** the provider sees the full content, the instance's egress IP and timing, under its own terms; FatLine sees host, port, SNI and bytes; Shrike sees the same plus the `ai` event reason; the application is told (`ChatResponse.Served`). Content that leaves is gone.

---

## Cost & security posture

**Drivers (us-central1, fetched 2026-09-03; modelled, never reconciled against a bill).** The gateway: 1 × 100m/128Mi ≈ $3.70/month. The PVC: ~$0.10/GiB-month, cents. Inference, while a Pod exists: Autopilot bills the **whole G2 node shape** for an accelerator Pod — g2-standard-4 (4 vCPU, 16 GB, 1×L4) on demand $0.7068/h hardware + $0.0846/h premiums ≈ **$0.79/h**, ≈ $0.81/h with a 100 GiB boot disk; Spot ≈ $0.46/h at the live ~40 % discount — all of it holding only while the Pod's requests fit g2-standard-4 (the shape-choice rule is unpublished; the runbook reads the node's `instance-type` label after the first schedule), the boot disk is ~100 GiB, the cluster runs GKE ≥ 1.29.4-gke.1427000 (Planck pins no version) and the Spot quote is today's. Never idle: ~$589/month; 1 h/day ≈ $24/month. **What a $100 limit affords:** $100 − ~$73 floor − $3.70 ≈ $23 ≈ **28 GPU-hours a month**; below roughly $80/month private inference does not fit, and the gate says so. Per wake: cold start plus the idle window ≈ 15–20 minutes of a billed node ≈ $0.20–0.30 *[to confirm live]*. External tokens: "what the meter cannot see" until 6.4.

**The meter changes** (TechnoCore, in the same phase as the gateway, over fakes, before any GPU exists): a dated per-class shape ladder (g2-standard-4/8/12/16/32 for one L4; -24/-48/-96 for two, four and eight) walked to the smallest shape that fits the GPU count, the CPU and the memory — never a flat number, because Autopilot bills the machine type that most closely fits and Google's own example bills 11 vCPU/40 GB as a g2-standard-12; `kube.ResourceList.Extended` for any resource key containing `/`, read from requests and limits; `kube.PodSpec.NodeSelector`, with the class read from `cloud.google.com/gke-accelerator` (what the cloud bills on) and the `farcast.sofmon.com/accelerator` label required to agree, else unknown; an unknown class, or a count, CPU or memory beyond the ladder, priced at the most expensive known shape and counted, never at zero; a fourth tier `elective`, stoppable and sorted first; the `technocore-status` document with `level`, `overhead_hourly_usd` and `stopped[]`. The node's billing tail after scale-to-zero is measured in the runbook and stated as a blind spot until it is a constant.

**The while-active gate**, a new shape — every existing gate quotes a standing monthly figure:

```
Private inference on "p32" adds no standing compute. While a request is being served it
runs one nvidia-l4 pod at ~$0.81/hour (us-central1 rates as of 2026-09; a model of the
published rate card, not a bill). Each wake costs at least ~$0.25 (cold start + 10 min idle).
If it never slept it would cost ~$589/month. Your limit is $100/month; the standing floor is
~$77/month, which leaves ~$23 ≈ 28 GPU-hours this period. TechnoCore stops it first at the
limit; AllThing will not wake it above the 90% level.
Enable it? [y/N]
```

`--yes` passes; non-interactive without it is a usage error naming the hourly figure; below floor + gateway it refuses unless `--yes`; `costgate_test` pins the figure to the class parsed back out of the rendered manifest.

**What AllThing does at each level.**

| Kernel level | Runtime | External backends |
|---|---|---|
| ok, 50 %, 75 % | wakes on `Private` demand; idles down after `IdleTimeout` | serve when policy admits |
| 90 % (default ceiling) | no new cold starts (`ErrAIHeld`, reason `cost-ceiling`); a warm runtime keeps serving until idle | serve when policy admits |
| reached | sleeps pre-emptively → `cost-stopped`; wake refused | refused — nothing new is spent |
| status stale or absent | as reached (`kernel-status-stale`) | serve when policy admits |

Nothing acts on the kernel's projection ([ADR 0009](../docs/adr/0009-technocore-kernel-and-cost-metering.md) decision 9); the ceiling is AllThing's own elective choice about new spend.

**Security, the seven layers that make "private never falls back" true by construction** — each sufficient alone, each with a named test: (L1) the SDK's zero value and explicit header; (L2) the gateway's normalisation and refusal of unknown words; (L3) `policy.Candidates` total, the router partitioned at construction, the private path import-checked; (L4) no external adapter in memory without both the flag and the key, no Secret rendered without a provider; (L5) provider hosts only in FatLine's `system` tenant on `:3129`, empty unless rendered; (L6) NetworkPolicies — the gateway reaches kube-dns, `fatline-egress:3129`, the inference Pod and the API server; the inference Pod reaches nothing; FatLine's own policy admits `:8443` from anywhere, `:3128` from application namespaces and `:3129` only from AllThing's Pods in `farcast-system` (namespace and pod selector both); (L7) one event per decision, correlated by Shrike with FatLine's own CONNECT log, and a forward on an instance with no provider enabled is **critical**.

**Threats, briefly** (the full table is in ADR 0011's context): exfiltration by fallback (L1–L7); egress from the inference Pod (an empty egress list; telemetry variables as belt); model supply chain (reviewed hashes, safetensors only, verified twice, `--trust-remote-code` never rendered); provider keys (Secret via stdin, redaction tests, never in metadata); prompts in logs (the log record type has no content field; a canary test on every path; vLLM request logging at its default-off); container posture (the documented exception, confined by policy); endpoint exposure (ingress from the gateway only; TLS and a bearer key); prompt injection when the model reads logs later (AllThing output never authorises an action); cost as an attack (the wake rule, the idle timeout, the attempt budget, the kernel's backstop; per-app rate limits later); kernel status forgery (a forged "ok" could only allow a wake the kernel re-stops within a tick).

**The gateway's Role** (`deploy` renders it; a test enumerates exactly these and fails on `watch`, `delete`, `create`, `escalate`, `bind`, `impersonate` or an unpinned scale verb): `deployments [get]` and `deployments/scale [patch]` pinned to `allthing-inference`; `pods [list]`; `configmaps [get]` pinned to `technocore-status` and `allthing-policy`; from 6.4, `configmaps [get, update, patch]` pinned to `allthing-usage`, which `farcast ai deploy` pre-creates so the gateway never holds a namespace-wide `create`. Replicas are clamped to `{0, 1}` in code because RBAC cannot bound a count.

---

## Failure modes

| Failure | Detected by | Phase / reason | Application sees | Automatic action; operator does |
|---|---|---|---|---|
| GPU class unavailable in the region | Pod `Unschedulable` past `StartDeadline` | `failed / unschedulable` | `ErrAIStarting` until the deadline, then `ErrAIHeld` | scale to zero, hold; `ai status` shows the scheduler's text; `ai private retry` |
| GPU quota exhausted (`GPUS_ALL_REGIONS` defaults to 0) | same symptom; the event names the quota | `failed / quota` | as above | as above; quota is requested in the Phase 1 runbook before the first Pod |
| Zonal stock-out in the PVC's zone | same symptom | `failed / unschedulable` | as above | stated limitation; a runbook finding is the revisit trigger |
| Model download fails | the Job fails or times out; FatLine `deny` if the host is not allowed | `unfetched` | `ErrAIRefused` (nothing to start) | `ai model fetch` re-runs idempotently; the allowance is removed regardless |
| Model download redirected off the catalog's hosts | the fetch refuses the redirect; FatLine `deny` for the host | `unfetched` | — | add the host to the entry in a reviewed commit; never widen the allowance by hand |
| Model corrupt | the fetch refuses the file, or `verify` exits non-zero | `failed / verify` | `ErrAIHeld` | status names the file; re-fetch; a catalog error is a reviewed fix |
| vLLM crash-loop | restarts exceed `MaxAttempts` in an hour | `failed / crash-loop` | `ErrAIHeld` | scale to zero, hold; bump the pinned image in a reviewed commit |
| Model does not fit | `MinMemoryGiB` vs class memory at enable; OOM termination at runtime | refused at enable; else `failed / oom` | `ErrAIHeld` | the enable error names both numbers |
| Cold start exceeds the deadline | `StartDeadline` | `failed / deadline` | `ErrAIStarting` then `ErrAIHeld` | raise the deadline only on measured evidence |
| Private inference absent | metadata | `absent` | `ErrAIRefused` for `Private`; the external path if permitted and declared | `farcast ai private enable` |
| External provider down (6.3) | adapter error | — | `ExternalAllowed`: served privately if the runtime is ready, else `ErrAIUnavailable` — a failure falls inward, never outward | Shrike drift if FatLine denied a host AllThing thinks is allowed → `farcast redeploy` |
| Policy prevents fallback | `Candidates` | — | `ErrAIStarting` / `ErrAIHeld` / `ErrAIRefused` as the private side dictates | intended |
| Kernel level 90 % | status document | wake refused, `cost-ceiling` | `ErrAIHeld(cost)` | a warm runtime keeps serving until idle |
| Kernel level reached | status document; kernel stop observed | `cost-stopped` | `ErrAIHeld(cost)`; external refused too | pre-emptive sleep; the next request wakes it once the level drops |
| Kernel status stale, missing, unreadable | timestamp / 404 / parse error | `cost-stopped / kernel-status-stale` for cold requests | `ErrAIHeld(cost)` | no wake — ambiguity does not spend; fix the kernel |
| Gateway down | the data Service has no endpoints | — | `ErrAIUnavailable` | the kubelet restarts it |
| FatLine down | not on the private path | private unaffected; external `ErrAIUnavailable` | the operator cannot reach `chat`/`status` | `TestThePrivatePathHasNoFatLineDependency` |
| FatLine rollout or eviction mid-`chat` | the relayed stream closes without `done` after the 5 s drain | — | applications unaffected; `farcast chat` reports `ErrAIUnavailable`, never a truncated answer | the operator repeats the turn |
| Shrike absent | `BufferedSink` drop counter | nothing | dropped-event count in metrics | never blocks the hot path |

---

## The `cmd/allthing` binary

One binary, three verbs, all in the `system/allthing` image compiled by the CLI: `allthing serve` (the gateway; flags for the three listeners, `--instance`, `--private-endpoint`, `--private-model`, `--idle-timeout`, `--ceiling`, `--external <provider>=<host>=<model>` (6.3), `--fallback`, `--shrike-socket`; TLS material and provider keys as environment), `allthing fetch --catalog <name> --dest <dir>` (the Job) and `allthing verify --catalog <name> --root <dir>` (the init container). It is not the user-facing CLI; `farcast` is.

---

## Testing strategy

Per [AGENTS.md](../AGENTS.md) and [ADR 0002](../docs/adr/0002-backend-language-strategy.md): `go test -race`, `go vet`, `gofmt`, `golangci-lint`, tests beside code, fakes not clouds.

- **Unit over fakes at named seams:** `internal/backends/fake` records what it received and fails the test on forbidden contact; `technocore/kernel`'s `fakeCluster` reused; a fake `event.Sink`; fake `http.RoundTripper` per dialect with exact bodies asserted; an `httptest` gateway for the SDK client. `-race` on the router, the controller and the gateway.
- **The privacy invariants, by name:** `TestCandidatesNeverYieldsExternalForPrivate` (a property test over random policies); `TestAPrivateRequestNeverReachesAnExternalBackend` (fuzz over privacy header values including `""`, `"Private"`, `"external "`, garbage); `TestAnUnknownPrivacyIsRefusedNotDowngraded`; `TestExternalAdaptersAreNotConstructedWithoutACredential`; `TestAFailedPrivateRequestIsStartingHeldOrUnavailableNeverExternal`; `TestExternalFailureFallsInwardNeverOutward`; `TestThePrivatePathDoesNotImportExternal`; `TestTheRuntimeHasNoEgressRule`; `TestTheRuntimeIsReachableOnlyFromTheGateway`; `TestTheGatewayEgressRulesAreExact`; `TestNoProviderHostAppearsInAnyRenderedNetworkPolicy`; `TestTheSystemTenantIsEmptyWhenNothingIsEnabled`; `TestPromptsNeverAppearInLogsOrEvents`; `TestTheRuntimeEnvDisablesTelemetry`; `TestRuntimeArgsNeverTrustRemoteCode`; `TestTheCatalogHoldsOnlySafetensors`; `TestVerifyRefuses{AMismatchedFile,AnExtraFile,AMissingFile}`; `TestNoDebugSurfaceInTheImportGraph` (with `golang.org/x/net/trace` on the list); `TestEveryServerHasItsOwnHandler`; `TestAKeeperLeafIsRefusedOnTheControlMux`; `TestTheStatusMuxNamesNoModelProviderOrLevel`; `TestTheFetchRefusesARedirectOffTheCatalogHosts`; `TestExternalConfigStringRedacts`; `TestMetadataNeverCarriesAKey`; `TestChatResponseServedIsNeverEmpty`.
- **The cost invariants:** `TestScaleUpIsRefusedWhenTheKernelSaysReached`, `TestAStaleKernelStatusReadsAsReached`, `TestAMissingKernelStatusReadsAsReached`, `TestReplicasAreClampedToOne`, `TestScaleRBACIsPinnedToTheInferenceDeployment`, the flap test (a kernel fake re-stops every tick while `reached`; the controller never patches 1), `TestAStartDeadlineFailsClosedAndScalesToZero`, `TestCrashLoopIsBounded`, `TestTheWhileActiveGateQuotesTheRenderedClass`, `TestAcceleratorClassFollowsTheNodeSelector` (a label that disagrees prices as unknown), `TestTheShapeLadderNeverPricesBelowTheFittingShape`.
- **Backend contract:** `backendtest.Run(t, b)` for every adapter — a stream ends with `Done` exactly once; an error after the first byte is an error, not a truncated success; cancellation closes the upstream; overflow → `ErrTooLarge`; 5xx → `ErrUpstream`; no content in error text. Against `openaicompat` over a fake server and, behind `//go:build integration` with `FARCAST_AI_TEST_ENDPOINT`, against a real vLLM.
- **Deploy render tests:** parse the YAML back and assert values — labels on both templates, tier literals, the digest pin (this package validates it itself; `fatline/deploy` does not), port distinctness, `publishNotReadyAddresses`, `replicas: 0`, the Role's verbs, NetworkPolicy rule sets, the accelerator label equal to the selector with a count of one; in `fatline/deploy`, `TestTheCarrierServicePublishesOnlyTheTunnelPort` and `TestTheEgressServiceIsClusterIP`; in `fatline/`, an e2e test in the keyholder-client shape asserting deltas arrive before the handler returns and that a half-closed variant fails loudly; join tests in the style of `kernel/selector_test.go` and `tier/classification_test.go`, both of which gain this module.
- **Live:** `//go:build integration` keyed on `FARCAST_AI_TEST_*` with `FARCAST_AI_TEST_GPU=1` for anything that starts an accelerator, teardown registered first, never in CI. Runbooks per sub-phase; the criterion that matters most is the independent witness: FatLine's own event log showing zero `Allow` for tenant `system` across the whole private walk outside the fetch window, and a `kubectl exec` from the inference Pod that cannot resolve a name. The same runbook confirms from outside the cluster that a CONNECT to `:3129` on the carrier's address is refused at the connection level, reads the node's `node.kubernetes.io/instance-type` label after the first schedule, runs `vllm serve --help` on the pinned digest, and establishes whether GKE deletes a dynamically provisioned disk with its cluster.
- **Open, not verified:** twenty-seven load-bearing claims behind this specification were attacked from three lenses each; thirty-nine of the eighty-one attacks ran and their corrections are folded in above. The attacks that did not run are runbook items, not facts: the model-size and safetensors arithmetic; the quota default and the Pending-costs-nothing rule; the node-deletion tail; the zonal-PVC pinning and the Hyperdisk ML alternative; that the seven layers close every code path short of a compromised gateway; that the wake rule bounds flapping to one under a real race with the kernel's tick; that double verification defends a provider-writable disk; that an empty egress list coexists with the kubelet's pull and the gateway's ingress; that tenant-by-socket plus the NetworkPolicies keep an application off the `system` allowance; that a spoofed application name is bounded as decision 7 says; that fail-fast `starting` cannot storm wakes; and that `AccrueAbsolute` can only tighten the guard.

---

## Decisions

All (proposed); the reasoning is in [ADR 0011](../docs/adr/0011-allthing-private-inference-first.md).

1. **AllThing owns the semantics of asking and nothing about compute, egress or money.** The name stays; sub-packages are plain.
2. **Two privacy classes with `Private` as the zero value; no "preferred" class; `Model` removed from the request.** Preference is the operator's `--fallback`, default `never`.
3. **The application contract is frozen at 6.0**: two methods, four sentinels, five wire codes in `sdk/go/aiwire.go`, `Served` on every answer; structs stay extensible; optional capabilities by type assertion.
4. **Effective = intersection; every absence is a no; unknown words are refused, never widened.**
5. **Seven enforcement layers, each sufficient alone, each with a named test.**
6. **Modes are derived; "external disabled" is four verifiable absences.**
7. **`X-Farcast-App` is attribution until 4.4, stated plainly; it may carry a manifest-declared external permission because the harm a spoofed name can do is bounded.**
8. **`Backend` + `Runtime` by type assertion; no registry; the OpenAI dialect serves both the private runtime and OpenAI; no provider SDKs.**
9. **Planck supplies accelerator facts through an optional capability and has no runtime; `deploy` renders AllThing's workloads.**
10. **The inference Deployment is tier `elective`, rendered at zero replicas, with the application-side posture as the documented exception and an empty egress list as the control.**
11. **Weights: a reviewed catalog, an in-instance fetch Job through a fetch-scoped allowance, a PVC, verification before every start; not DataSphere, not the laptop.**
12. **The inference image is a digest-pinned upstream reference; the mirror is triggered by private nodes.**
13. **The gateway scales its own Deployment under a name-pinned Role, clamps replicas to `{0, 1}`, never holds a namespace-wide `create`.**
14. **TechnoCore publishes `technocore-status`, records `stopped[]` (persisted additively on the checkpoint), adds `elective` to `tier.Of()` and sorts it first.**
15. **The wake rule: fresh status, level below the ceiling, not in `stopped`; absent or stale reads as reached; enable requires the kernel.**
16. **Cold start is fail-fast `starting`; the request is the wake signal; the status endpoint explains, never retries.**
17. **Accelerator Pods are metered by the node shape the cloud will bill, walked from a dated per-class ladder with the class read from the node selector; the enable gate quotes what the limit affords; an unknown class never prices at zero.**
18. **External tokens: reported first, accrued as `expected` later, refused at `reached`; never a second budget.**
19. **Configuration is CLI verbs, `meta.AI` and rendered arguments and Secrets; FatLine renders its route and allowances from `meta.AI`; `release` removes AllThing before it marks the instance deleting; the manifest gains one reviewed key with 6.3.**
20. **FatLine's egress ports go on a ClusterIP `fatline-egress`, never on the public carrier Service; FatLine's first NetworkPolicy ships with the `:3129` listener.**
21. **AllThing output never authorises an action.**
22. **The first milestone is a private answer with the guarantee provable from outside, reached through a no-GPU phase first.**

---

## Roadmap

| Phase | Adds |
|---|---|
| **6.0** | This specification; the SDK contract (`Privacy`, sentinels, `aiwire.go`, the three-outcome accessor, `AIStatusOf`); `gateway/wire.go` and its mirror test; `docs/wire.md` with fixtures; the translator's `FARCAST_AI_*` block, egress rule and both status-scheme fixes; the manifest Reserved entry; every document that called AllThing a provider shim corrected. Nothing deployed. |
| **6.1** | The gateway that refuses (no backend), `allthing serve`, `deploy` (gateway objects; the first NetworkPolicy in `farcast-system`), identity leaves, the `allthing` stream route, `farcast ai deploy\|status\|hold\|release`, `farcast chat` replacing the stub; TechnoCore's cost half over fakes: `tier.Elective`, `technocore-status`, `ResourceList.Extended`, the accelerator table, the sort. ~$3.70/month; the flapping conflict closed before the first GPU dollar. |
| **6.2** | (a) FatLine's `:3129` system listener, `fatline-egress`, its NetworkPolicy; (b) the catalog, `allthing fetch`/`verify`, PVC, Job, the inference Deployment, `planck.AcceleratorProvider`, the controller on the real client, `farcast ai private enable\|disable\|retry\|warm`, `model fetch`, `remove`; (c) the runbook with five measured cold starts and the node tail. **First milestone.** |
| **6.3** | Applications (with 4.3's `farcast run`) and external providers by declared policy: `openaicompat` for OpenAI, an `anthropic` dialect, Secret via stdin, `farcast ai external enable\|disable`, `--fallback`, manifest rules 31–34 and `allthing-policy`, Shrike's reason map and CONNECT correlation, token spend reported. |
| **6.4** | `allthing-usage` accrued as `expected`; `farcast costs` lines; the tail constant if material; the deadline-derived wait header; runtime TLS if 6.2 shipped cleartext; Shrike sidecar templating; per-app rate limits. |
| **6.5** | System callers (`farcast://<instance>/system/<name>`) under "output never authorises an action". |
| **8.3** | A Gemini dialect; a second accelerator class or cloud realisation of `AcceleratorProvider`. |

Deferred with named triggers: the image mirror and the OCI weights path (private nodes; a hub rewriting an entry); Planck's quota read (the first quota finding); secondary boot disks (a measured pull dominating cold start); Spot for the elective runtime; embeddings, vision, reranking (each an optional interface and a new route); a chat endpoint on a FarSight server that does not exist; Node/Python SDKs against `docs/wire.md`.

---

## Known limitations

Accepted-and-documented, not oversights:

- **Private inference is protected by the provider not looking.** Memory on provider hardware is not defended; [What the cloud still sees](#what-the-cloud-still-sees) is the whole claim.
- **Below roughly $80/month private inference does not fit**, and the gate says so rather than pretending; under a $100 limit it is about 28 GPU-hours a month.
- **Cold starts are minutes** (3–12 reported, none measured yet); a request during one is answered with `starting`, not held.
- **A zonal volume pins the inference Pod to one zone** of a regional cluster; a stock-out there blocks a wake while other zones may have capacity.
- **The inference image is pulled from a third-party registry over node-level egress** FatLine does not see, and it runs as root with a writable cache; the pin makes the registry untrusted transport, not an audited author; the empty egress list is the control.
- **The node's billing tail after scale-to-zero is unmetered** until the runbook measures it.
- **Application identity is a declared name** until 4.4; what a spoofed name can do is bounded, and stated.
- **Only Deployments in the kernel's metered namespaces are metered and stoppable**; enabling private inference requires a kernel that meters `farcast-system`.
- **Every dollar figure is modelled and unreconciled**, and the accelerator line holds only while Autopilot places the inference Pod on g2-standard-4; the accelerator rate is a second unverified model on top of the first, and the 4.1 runbook's criterion 12 now covers two lines.
- **One private model per instance** in the first implementation; model selection is the operator's, never the application's.
- **No metrics substrate exists**; counters live in the state and usage documents and vLLM's metrics are scraped by the gateway only; a Prometheus endpoint is a later decision.

---

## References

- The decisions and their decision space — [ADR 0011](../docs/adr/0011-allthing-private-inference-first.md)
- The two pillars, deny-by-default, "blind to content" — [AGENTS.md](../AGENTS.md)
- The in-instance service and SDK-client pattern this module mirrors — [DataSphere](../datasphere/README.md), [`sdk/go`](../sdk/go/README.md)
- The kernel, the tier vocabulary and the two cost figures — [TechnoCore](../technocore/README.md), [ADR 0009](../docs/adr/0009-technocore-kernel-and-cost-metering.md)
- The egress boundary, the tunnel and the stream relay — [FatLine](../fatline/README.md), [ADR 0005](../docs/adr/0005-fatline-data-plane-ingress.md)
- The monitor that witnesses AI events — [Shrike](../shrike/README.md)
- Cloud facts and the optional-capability pattern — [Planck](../planck/README.md), [ADR 0003](../docs/adr/0003-gke-autopilot.md)
- Where images and third-party artifacts come from — [ADR 0007](../docs/adr/0007-instance-owned-image-registry.md), [ADR 0010](../docs/adr/0010-application-image-builds.md)
- What may never rest in the cloud, and the frozen-contract discipline — [ADR 0008](../docs/adr/0008-in-cluster-key-delivery.md)
- The operator's surface — [FarSight CLI](../farsight/cli/README.md)
- Execution plan — [`PLAN.md`](../PLAN.md)
