# FarCast SDK — Go

> The syscall surface for applications running on a FarCast instance.

The Go SDK is the library an application imports to talk to the FarCast environment instead of talking to the cloud directly. Where a traditional program calls `open()`, `write()`, or `connect()` and the kernel brokers the hardware, a FarCast application calls `farcast.Storage()`, `farcast.Log()`, or `farcast.Net()` and the FarCast modules broker the cloud. The application never learns which cloud it runs on, never holds a cloud credential, and never reaches the network except through the boundary FarCast controls.

This document is the specification for the Go SDK. It describes the full capability surface, the way each capability reaches its backing module, and — in detail — the logging capability that is implemented first.

> **Status.** [`PLAN.md`](../../PLAN.md) phases **0.2** (core interfaces) and **0.3** (logging implementation) are done: the package, interface types, capability accessors, context helpers, and error sentinels are in place, and logging is a working structured logger (`go test -race`, `go vet`, and `golangci-lint` all clean). **Storage is wired** as of phase 3.2: `farcast.Storage()` talks to the instance's DataSphere keyholder, with `ErrStorageSealed` as a first-class application state. The remaining capabilities (Config, Net, AI, Secrets) return stubs until they are wired to their modules in later phases; see the [roadmap](#roadmap).

---

## What the SDK is — and isn't

**It is** a thin, stable, language-level contract. Applications compile against it the way a Unix program compiles against `unistd.h`. The contract is the same across the Go, Node.js, and Python SDKs (see [`../README.md`](../README.md)); only the idioms differ. The Go SDK is the reference implementation that the others mirror.

**It is not** an infrastructure library. There are no cloud SDKs, no Kubernetes clients, no storage drivers, and no AI provider libraries behind this import. Those live inside the FarCast modules — Planck, DataSphere, FatLine, AllThing — on the other side of the boundary. The application sees only the syscall.

This separation is why `sdk/go/` is its **own Go module** (`github.com/sofmon/farcast/sdk/go`), independent from the repository's root module. An external application pulls the SDK without dragging in the rest of FarCast, and its dependency graph stays small and auditable. See [`../../AGENTS.md`](../../AGENTS.md) ("Conventions") and [`../../README.md`](../../README.md#L114-L125) for the module layout.

---

## Design principles

1. **Zero-ceremony accessors.** A capability is one function call — `farcast.Log()`, `farcast.Storage()` — that returns a ready-to-use value. There is no client to construct, no connection to open, no `Init()` to remember. The SDK configures itself from the environment on first use.
2. **`context.Context` first.** Every method that does I/O or that participates in a request takes a `ctx` as its first argument. This is how cancellation, deadlines, and the per-request identity (the request ID) propagate.
3. **Interface-typed for testability.** Each accessor returns an interface, not a concrete struct. Application tests can substitute a fake without touching the network.
4. **Graceful off-instance behaviour.** The SDK works when run outside a FarCast instance — on a developer's laptop, in CI, in a unit test. Identity degrades to sensible defaults and logging still writes to stdout. Code paths do not branch on "am I in production."
5. **The boundary is deny-by-default.** Outbound access (`farcast.Net()`) only reaches hosts the application declared in its `./farcast` manifest. The SDK surfaces that contract; it never widens it.
6. **Dependency-light.** The logging implementation depends only on the Go standard library. Later capabilities add the minimum needed to speak to their module, never a cloud SDK.

---

## Module & import

```go
import "github.com/sofmon/farcast/sdk/go"
```

The package is named **`farcast`** even though the import path ends in `/go`. Reference it as `farcast.Log()`, `farcast.Storage()`, and so on. If your linter prefers an explicit name for the path-vs-package mismatch, alias it — both are equivalent:

```go
import farcast "github.com/sofmon/farcast/sdk/go"
```

Minimum Go version: **1.26** (matches the repository toolchain; the logger is built on the standard library's `log/slog`).

---

## Quick start

```go
package main

import (
	"context"

	"github.com/sofmon/farcast/sdk/go"
)

func main() {
	// Establish a request scope. The request ID rides on the context and
	// is stamped onto every log record produced with it.
	ctx := farcast.WithRequestID(context.Background(), farcast.NewRequestID())

	log := farcast.Log()
	log.Info(ctx, "service starting", "version", "1.4.2")

	if err := run(ctx); err != nil {
		log.Error(ctx, "startup failed", "err", err)
	}
}
```

Run this anywhere — inside an instance or on a laptop — and it writes structured JSON to stdout. Inside an instance, the platform collects that stdout and the operator sees it in `farcast logs`. On a laptop, it just prints.

---

## The capability surface

Five accessors form the syscall surface. Each returns an interface backed by a FarCast module.

| Capability | Accessor | Backed by | Reaches its backend via |
|---|---|---|---|
| **Logging** | `farcast.Log()` | the platform (TechnoCore/Planck) | **stdout** — no network call |
| **Config** | `farcast.Config()` | environment + app configuration | process environment |
| **Storage** | `farcast.Storage()` | [DataSphere](../../datasphere/README.md) | in-instance module endpoint |
| **Net** | `farcast.Net()` | [FatLine](../../fatline/README.md) | in-instance proxy |
| **AI** | `farcast.AI()` | [AllThing](../../allthing/README.md) | in-instance module endpoint |

### The boundary, and why logging is first

Logging is the only capability that needs **no round-trip to a module**. A FarCast application is a container; its stdout is captured by the node it runs on and shipped by the platform. So "log" means *write one JSON object per line to stdout* — nothing more. That is why logging is the first concrete capability: it has zero dependencies, behaves identically in production and on a laptop, and every later phase can rely on it.

The other capabilities are thin clients to modules running **inside the same instance**. `Storage()` calls DataSphere, which encrypts before writing to object storage. `Net()` hands back an HTTP client whose traffic is forced through FatLine, which permits only declared `external` hosts and lets Shrike watch every connection. `AI()` calls AllThing, which fronts whichever provider the operator chose. In every case the application talks to a local FarCast endpoint — never to the cloud, never holding a credential. The module endpoints are injected into the environment by the platform when the app is deployed (the SDK ships as a sidecar/init container; see [`PLAN.md`](../../PLAN.md) phase 4.2).

---

## Environment & identity

The SDK reads ambient identity and behaviour from environment variables on first use. The platform sets these when it runs the application; off-instance they fall back to safe defaults so nothing has to be configured for local development.

| Variable | Meaning | Default off-instance |
|---|---|---|
| `FARCAST_INSTANCE_ID` | Instance identity; appears as `instance` on every log record. | `local` |
| `FARCAST_APP_NAME` | Application name from the manifest; appears as `app`. | the executable's base name, else `unknown` |
| `FARCAST_LOG_LEVEL` | Minimum level to emit: `debug`, `info`, `warn`, `error`. | `info` |
| `FARCAST_LOG_SOURCE` | When `true`, add caller `source` (file:line) to each record. Has a cost; off by default. | `false` |

Later phases introduce endpoint variables for the remaining capabilities (for example a storage endpoint and the FatLine proxy address). They are documented in those phases, not here, so this table stays accurate to what exists.

`instance` and `app` are **ambient**: read once, attached to every record automatically. The per-request identity — the request ID — is not ambient; it travels on the `context.Context` (see [Context propagation](#context-propagation)).

---

## Logging — `farcast.Log()`

The first real implementation (phase 0.3). Structured JSON to stdout, four levels, automatic identity, and request-scoped context propagation. It is also the **intended standard logging mechanism for FarCast's own modules** — TechnoCore, Planck, FatLine, and the rest are to emit the same record shape, so an operator reads one consistent log stream across the whole instance. (Today the modules that log at all — FatLine, Shrike, and the FarSight CLI — use bare `slog`, and the rest are still scaffolds; they adopt this record shape as they are wired into an instance.)

### The interface

```go
// Log returns the process-wide structured logger. It is always safe to
// call and never returns nil; outside an instance it writes to stdout
// with best-effort identity.
func Log() Logger

// Logger is FarCast's structured logging capability. Each call emits one
// JSON object per line to stdout.
type Logger interface {
	Debug(ctx context.Context, msg string, args ...any)
	Info(ctx context.Context, msg string, args ...any)
	Warn(ctx context.Context, msg string, args ...any)
	Error(ctx context.Context, msg string, args ...any)

	// With returns a child logger that adds the given key/value pairs to
	// every record it emits. Children inherit their parent's fields.
	With(args ...any) Logger
}
```

`args` are alternating key/value pairs following the same convention as the standard library's [`log/slog`](https://pkg.go.dev/log/slog) — `log.Info(ctx, "msg", "key1", value1, "key2", value2)`. The logger is implemented on top of `slog` with a JSON handler writing to stdout, so slog's value handling, grouping, and `slog.Attr` values work as expected.

### Levels

Four levels, ordered `debug < info < warn < error`. The active threshold comes from `FARCAST_LOG_LEVEL` (default `info`), so `Debug` calls are essentially free in production — they are filtered before formatting.

### Record shape

One JSON object per line. Example for `log.Info(ctx, "service starting", "version", "1.4.2")` with a request ID on the context:

```json
{"time":"2026-06-01T09:24:05.123456789Z","level":"info","msg":"service starting","instance":"farcast-one","app":"api","request_id":"7f3a9c1d2e4b6a80f1e2d3c4b5a69788","version":"1.4.2"}
```

| Field | Always present | Source |
|---|---|---|
| `time` | yes | RFC 3339 nanosecond timestamp, UTC, set by the SDK |
| `level` | yes | `debug` / `info` / `warn` / `error` (lowercase) |
| `msg` | yes | the `msg` argument |
| `instance` | yes | `FARCAST_INSTANCE_ID` (or `local`) |
| `app` | yes | `FARCAST_APP_NAME` (or best-effort) |
| `request_id` | when the context carries one | [`WithRequestID`](#context-propagation) |
| `source` | when `FARCAST_LOG_SOURCE=true` | caller file:line |
| *(custom)* | as passed | `args` / `With` key/value pairs |

`time`, `level`, `msg`, `instance`, `app`, `request_id`, and `source` are **reserved keys**. An application should not pass them as custom `args`; the SDK owns them.

### Context propagation

Three identities ride along, by three different mechanisms:

- **`instance` and `app`** are ambient — attached to every record without the caller doing anything.
- **`request_id`** is request-scoped — it travels on the `context.Context`. Set it once where a unit of work begins (an HTTP handler, a queue consumer, a CLI invocation) and every downstream `log.*(ctx, ...)` call carries it, even across package and goroutine boundaries, without threading a logger through every signature.
- **Stable per-component fields** use `With` — a child logger that bakes in fields like a subsystem name.

```go
// WithRequestID returns a copy of ctx that carries id. Every log record
// emitted with that ctx (or a descendant) includes "request_id": id.
func WithRequestID(ctx context.Context, id string) context.Context

// RequestID returns the request ID carried by ctx, or "" if none.
func RequestID(ctx context.Context) string

// NewRequestID returns a new collision-resistant request ID. It uses only
// the standard library — no external dependency.
func NewRequestID() string
```

A typical HTTP middleware adopts an inbound request ID or mints one, then puts it on the context for the rest of the stack:

```go
func RequestScope(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = farcast.NewRequestID()
		}
		ctx := farcast.WithRequestID(r.Context(), id)
		farcast.Log().Info(ctx, "request received",
			"method", r.Method, "path", r.URL.Path)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
```

A subsystem that always wants its own tag uses `With`:

```go
log := farcast.Log().With("component", "scheduler")
log.Warn(ctx, "queue backpressure", "depth", depth)
```

### Logging errors

Log an `error` value under the conventional `err` key so it lands in a predictable field:

```go
if err := store.Write(ctx, key, data); err != nil {
	log.Error(ctx, "write failed", "key", key, "err", err)
}
```

### Privacy

Logs go to stdout, which the operator's **own** TechnoCore collects inside the operator's **own** instance. They are not shipped to any third party. An application that wants logs to reach an external service must route them through `farcast.Net()` to a host it declared in its manifest — at which point FatLine and Shrike govern that traffic like any other outbound connection. The default keeps log data sovereign.

### Testing the logger

The default writer is `os.Stdout`. For tests that need to assert on output, the implementation exposes a seam to redirect it:

```go
// SetLogWriter redirects log output. Intended for tests; the production
// default is os.Stdout. Returns a function that restores the previous
// writer.
func SetLogWriter(w io.Writer) (restore func())
```

This keeps the zero-ceremony singleton usable while still allowing a test to capture and decode the JSON it produces.

---

## Core capability interfaces (the 0.2 contract)

Phase 0.2 defines the following interfaces so applications can compile against the whole surface immediately. Their accessors exist from 0.2 but return stubs whose methods yield [`ErrNotImplemented`](#errors--conventions) until the implementation phase lands (error-less getters, such as `Config().GetString`, fall back to their supplied defaults instead). The shapes below are the contract's starting point; each owning phase refines its own signatures.

Each interface takes an `API` suffix — `Storage()` returns `StorageAPI`, `Config()` returns `ConfigAPI`, and so on — because Go does not permit a function and a type to share a name, and the ergonomic call surface (`farcast.Storage()`) takes priority. Logging is the exception: `Log()` returns the idiomatically named `Logger`.

### Config — `farcast.Config()`

Non-secret configuration: environment defaults and per-app values. Secrets are a separate capability (`farcast.Secrets()`, phase 5.3) and never flow through `Config`.

```go
func Config() ConfigAPI

type ConfigAPI interface {
	Get(key string) (string, bool)
	GetString(key, def string) string
	GetInt(key string, def int) int
	GetBool(key string, def bool) bool
	Require(key string) (string, error) // error if key is absent
}
```

Implementation: phase 5.3.

### Storage — `farcast.Storage()`

Object storage through [DataSphere](../../datasphere/README.md). Reads and writes are encrypted transparently — the application sees plaintext, the cloud sees only encrypted blobs. The application addresses objects by key and never knows whether the backend is S3, GCS, or anything else.

```go
func Storage() StorageAPI

type StorageAPI interface {
	Read(ctx context.Context, key string) ([]byte, error)
	Write(ctx context.Context, key string, data []byte) error
	List(ctx context.Context, prefix string) ([]string, error)
	Delete(ctx context.Context, key string) error
}
```

**These four methods are frozen.** Applications implement `StorageAPI` to fake storage in their own tests, so a fifth method would break every one of them. Capabilities that are not universal arrive as *separate optional interfaces* discovered with a type assertion — which is why the streaming variants once sketched here are not folded into this interface, and why `Status` is not either.

#### Storage can be sealed, and every application must expect it

DataSphere's keys never rest on cloud infrastructure, so the in-cluster keyholder holds them **in memory only**. Any restart — a node upgrade, an eviction, a rollout — leaves storage *sealed* until an operator unseals it ([ADR 0008](../../docs/adr/0008-in-cluster-key-delivery.md)). This is a normal state of a healthy instance, not a failure, and it can last as long as it takes a human to respond.

```go
data, err := farcast.Storage().Read(ctx, key)
switch {
case errors.Is(err, farcast.ErrStorageSealed):
    // Intact but unreadable right now. Wait and retry, or fail upward.
    // Never answer a seal by writing.
case errors.Is(err, farcast.ErrObjectNotFound):
    // There is genuinely no such object.
}
```

`ErrStorageSealed` is deliberately distinct from `ErrNotImplemented` (which means *this build never can*) and from `ErrObjectNotFound` (which means *there is no such object*). An application that read a seal as absence and started over would be silent data loss by a second route; the distinction is fixed now, before any application exists, because every application ever written inherits it.

The optional pre-attempt seam lets a long-running job check once rather than discovering a seal on its first write:

```go
type StorageStatusAPI interface {
	StorageAPI
	Status(ctx context.Context) (StorageStatus, error)
}

// Reports ErrNotImplemented when s has no status seam — e.g. a fake in your tests.
func StorageStatusOf(ctx context.Context, s StorageAPI) (StorageStatus, error)
```

Checking is never *required*: every method reports a seal on its own, and a status that says ready can be stale by the time the next call runs, so code must still classify the error from the operation itself.

#### Configuration

The platform injects these when it runs an application; absent them the capability is the stub and every method reports `ErrNotImplemented`.

| Variable | Meaning |
|---|---|
| `FARCAST_STORAGE_ENDPOINT` | the keyholder's data path (https) |
| `FARCAST_STORAGE_STATUS_ENDPOINT` | its status endpoint, used only to tell a seal from an outage |
| `FARCAST_STORAGE_SCOPE` | the scope this application may address |
| `FARCAST_STORAGE_CA` | the instance CA, in PEM, used to verify the keyholder |

A configuration that is *present but unusable* — an unreadable CA, a plain-`http` endpoint — is neither the stub nor a seal. It reports `ErrStorageUnavailable`, because telling an application "this build never supports storage" would make it stop trying, and telling it "sealed" would make it wait for an operator who has nothing to unseal.

Without a usable CA the SDK refuses to talk to the keyholder at all rather than falling back to the system roots: system roots would accept anything that answers on that address.

Implementation: phase 3.2.

### Net — `farcast.Net()`

Outbound networking through [FatLine](../../fatline/README.md). The returned HTTP client routes every request through FatLine, which permits only the `external` hosts the application declared in its manifest; everything else is denied by default and flagged by Shrike. The application makes ordinary HTTP calls and the boundary is enforced underneath.

```go
func Net() NetAPI

type NetAPI interface {
	// HTTPClient returns an *http.Client whose transport is forced through
	// FatLine. Requests to undeclared hosts are denied.
	HTTPClient() *http.Client

	// Status reports the health of the instance's network boundary.
	Status(ctx context.Context) (ConnStatus, error)
}
```

Implementation: FatLine's core proxy shipped in phase 2, but `Net()` stays a stub until applications get the FatLine data path — the sidecar templating and per-app allowlists of [`PLAN.md`](../../PLAN.md) phases 4.2/4.4.

### AI — `farcast.AI()`

AI through [AllThing](../../allthing/README.md). Provider-agnostic: the application asks for a chat completion and AllThing routes it to whichever provider the operator configured (Gemini, Claude, OpenAI) — the application never names a provider or holds a key.

```go
func AI() AIAPI

type AIAPI interface {
	Chat(ctx context.Context, req ChatRequest) (ChatResponse, error)
	ChatStream(ctx context.Context, req ChatRequest) (Stream, error)
}
```

Implementation: phase 6.3.

---

## Errors & conventions

- **`ErrNotImplemented`.** Until a capability's implementation phase lands, its methods return this sentinel (error-less getters fall back to their supplied defaults instead). Application code can compile and run against the full contract early; capabilities light up as their phases complete.

  ```go
  var ErrNotImplemented = errors.New("farcast: capability not implemented")
  ```

- **Storage sentinels.** `ErrStorageSealed`, `ErrObjectNotFound`, `ErrIntegrity`, `ErrInvalidKey`, `ErrTooLarge`, `ErrPermission`, and `ErrStorageUnavailable`. The set is deliberately small: each is inherited by every application ever written against this SDK, so one added carelessly can never be withdrawn. DataSphere's own vocabulary is wider — sentinels describing an *operator's* problem (a bucket proved to belong to another instance, a retention policy still billing for deleted objects) do not cross into this module, because an application cannot act on them and an error it cannot act on is one it may branch on wrongly. `ErrStorageUnavailable` is the total-mapping catch-all: an answer this build does not understand must never collapse into "no such object" or "never will work", since both are wrong in ways that cost data.
- **Sentinel errors with `errors.Is`.** Following the same pattern as the manifest parser (see [`manifest/parser/parser.go`](../../manifest/parser/parser.go)), the SDK exposes sentinel errors and supports `errors.Is` for classification rather than string matching.
- **`context.Context` is the first argument** of every I/O method. Cancellation and deadlines are honoured; the request ID propagates. `farcast.Log()` and `farcast.Config()` accessors themselves never fail — only their I/O-performing methods (and only Config's `Require`) return errors.
- **Accessors never return nil.** `farcast.Log()` and the others always return a usable value, so call sites need no nil checks.

---

## Versioning & stability

The SDK is pre-1.0 (`v0.x`). The contract may change between minor versions while the capability surface settles. Because the SDK is its own module, an application pins an exact version in its `go.mod` and upgrades deliberately. Once the surface stabilises the module adopts semantic-import versioning for any `v2+` break. The interface set defined in phase 0.2 is the baseline the rest of the project builds against, so changes to it are made cautiously and noted in the module's changelog.

---

## Testing & guardrails

Per [`../../AGENTS.md`](../../AGENTS.md) ("Language guardrails") and [ADR 0002](../../docs/adr/0002-backend-language-strategy.md), the SDK is held to the same Go safety bar as every module:

- `go test -race` — Go's memory safety is conditional on the absence of data races; `-race` defends it. The logger is a process-wide singleton reached from many goroutines, so its concurrency is covered explicitly.
- `go vet` and `golangci-lint` in CI.
- Tests sit beside the code they cover (`farcast_test.go` alongside `farcast.go`).
- The off-instance behaviour (graceful identity defaults, stdout logging, the `SetLogWriter` seam) is what makes the SDK unit-testable without a live instance, and is itself tested.

---

## Roadmap

| Capability | Interface defined | Implementation |
|---|---|---|
| Logging — `Log()` | phase 0.2 | **phase 0.3** |
| Config — `Config()` | phase 0.2 | phase 5.3 |
| Storage — `Storage()` | phase 0.2 | ✅ phase 3.2 |
| Net — `Net()` | phase 0.2 | with the app data path (phase 4.2/4.4; FatLine core shipped in phase 2) |
| AI — `AI()` | phase 0.2 | phase 6.3 |
| Secrets — `Secrets()` | phase 5.3 | phase 5.3 |

Node.js and Python SDKs mirror this contract in phase 8.4.

---

## References

- SDK overview (all languages) — [`../README.md`](../README.md)
- Project overview — [`../../README.md`](../../README.md)
- Agent/architecture context — [`../../AGENTS.md`](../../AGENTS.md)
- Execution plan — [`../../PLAN.md`](../../PLAN.md)
- Manifest specification — [`../../manifest/README.md`](../../manifest/README.md)
- Backing modules — [DataSphere](../../datasphere/README.md), [FatLine](../../fatline/README.md), [AllThing](../../allthing/README.md), [TechnoCore](../../technocore/README.md)
- Backend language strategy — [ADR 0002](../../docs/adr/0002-backend-language-strategy.md)
