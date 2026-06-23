# Shrike

> Security monitor — validates live traffic against the manifest's `external` declarations, raises alerts when an application reaches (or tries to reach) somewhere it never declared.

> **Policeman, not wall ([AGENTS.md](../AGENTS.md#module-relationships)).** Shrike does **not** control the egress boundary — [FatLine](../fatline/README.md) does, inline and deny-by-default ([phase 2.1](../fatline/README.md), already shipped). Shrike *watches* the decisions FatLine has already made and *intervenes* on violations: it is the policeman patrolling behind the wall, not the wall. It adds **no network hop** — an application's bytes never flow through Shrike.

> **GKE Autopilot note ([ADR 0003](../docs/adr/0003-gke-autopilot.md)):** Shrike runs as a **sidecar** inspector alongside FatLine — no privileged or raw-capture access. It consumes the structured egress-decision stream FatLine emits (and, later, may also read GKE Dataplane V2 flow logs). The two-container Pod that actually co-schedules them is **templated by Planck (4.2)**; this phase builds the Shrike artifact and its FatLine seam.

> **Status.** **Phase 2.2 (minimal policy engine) — implemented** (`go test -race`, `go vet`, `golangci-lint` all clean). It delivers: the **inspector** that consumes FatLine's `event.Sink` stream; the **policy** built from parsed manifest `external` declarations; a **violation table** with severity, de-duplication, and rate-limited **alerting** ("block + alert, don't just log"); a queryable **status surface** (the live security picture, served as JSON); and the **sidecar wire** (a local Unix-socket NDJSON transport) so Shrike can run as its own container against FatLine. The violation table — Shrike's one shared-mutable-state path — carries `-race` tests, and the wire is exercised over a real loopback socket; the FatLine→Shrike path is smoke-tested end-to-end (deny → ship → alert). **Out of scope (later phases):** per-application attribution and per-app allowlists (4.4 — `Event.Tenant`/`Event.App` are empty until then); the Pod spec / sidecar templating that co-schedules the two containers (Planck 4.2); Dataplane V2 flow-log ingestion; and any AI-driven anomaly analysis (6.4).

---

## What Shrike is — and isn't (2.2 scope)

| Shrike **is** (2.2) | Shrike **is not** (here) |
|---|---|
| A read-only **observer** of FatLine's egress decisions | An enforcement point. FatLine blocks; Shrike never sits in the data path |
| The thing that turns a raw `deny` event into a **stateful, queryable alert** | A logger. "Don't just log" — an alert is de-duplicated, severity-ranked, counted, and surfaced in status |
| Holder of the **declared policy** (manifest `external`) to give each decision context | The author of policy. The manifest is the policy; Shrike compares against it |
| Runnable as an **in-process sink** *or* a **sidecar process** over a local socket | A separate network hop. It sees event *metadata*, never the proxied bytes |
| Single-tenant in 2.2 (one instance-wide policy) | Per-app aware. `Event.Tenant`/`App` arrive in 4.4 |

The division of labour is the whole point, and it matches the two pillars:

- **FatLine = the wall.** Inline, synchronous, fail-**closed**. It already refuses everything not in the allowlist and emits exactly one decision `event.Event` (`Allow`/`Deny`) per request, plus a `Close` event with byte counts when a tunnel ends.
- **Shrike = the policeman.** Out-of-band, asynchronous, fail-**open** (monitoring must never block or break the boundary). It consumes those events, correlates them against the declared policy over time, and alerts. If Shrike crashes, the wall still stands.

That asymmetry is deliberate: enforcement may never depend on the monitor being healthy, so the monitor is a separate, droppable consumer.

---

## Architecture & package layout

```
shrike/
├── README.md                  — this specification
├── shrike.go                  — package shrike: Monitor (the event.Sink) + Config + Snapshot
├── status.go                  — http.Handler exposing the live security picture as JSON
├── wire.go                    — sidecar transport: DialSink (FatLine→socket) + Serve (socket→Monitor)
├── internal/
│   ├── policy/                — Policy: the declared external endpoints, classification
│   └── inspector/             — Inspector: violation table, severity, de-dup, rate-limited alerts
├── cmd/shrike/                — the sidecar binary: manifest → Policy → Monitor → socket + status
└── docs/                      — deeper notes
```

Data flow (sidecar mode):

```
 app ──► FatLine (proxy, BLOCKS) ──► upstream        ← the bytes; Shrike never sees them
              │
              └─ event.Event (metadata only) ─► BufferedSink ─► DialSink ─┐
                                                                          │ Unix socket, NDJSON
   Shrike sidecar:  Serve ─► Monitor.Emit ─► Inspector ─► Alert + Snapshot ◄┘
```

In-process mode collapses the dashed path: FatLine's composition root passes a `*shrike.Monitor` straight in as `fatline.Config.Events`, no socket. Same `Monitor`, same behaviour — the wire is just how the two run in separate containers.

---

## The seam it consumes

Shrike is built entirely on the contract FatLine already ships — [`fatline/event`](../fatline/event/event.go), a small public leaf package:

- **`event.Sink`** — `interface{ Emit(event.Event) }`. **`shrike.Monitor` implements this.**
- **`event.Event`** — `{ Kind, Tenant, App, Host, Port, Proto, SNI, Reason, BytesUp, BytesDown }`. Metadata only — no payload, no keys.
- **`event.Kind`** — `Allow` | `Deny` | `Close`.
- **`event.Reason*`** — stable deny-reason strings Shrike branches on without parsing prose:
  - `not_in_allowlist` — app reached for an **undeclared** host. The core violation.
  - `sni_mismatch` — `CONNECT` authority was allowed but the TLS `server_name` differed (possible domain-fronting / MITM attempt). **Highest severity.**
  - `cleartext_not_allowed` — app tried plain `http://`. A policy nudge, not an attack.

FatLine emits the decision event **before** answering the caller, so a `Deny` Shrike receives is proof the block already happened. FatLine's `BufferedSink` already decouples emission from the hot path and **drops-and-counts** under load — so a hostile app's deny-flood can never backpressure the data plane, and Shrike never has to worry about being slow enough to matter.

---

## Interfaces (proposed)

```go
package shrike

// Monitor is Shrike's policy engine: an event.Sink that inspects FatLine's
// egress decisions, compares them against the declared policy, and raises
// alerts on violations. It is safe for concurrent Emit.
type Monitor struct { /* … */ }

type Config struct {
    // Policy is the declared egress contract (manifest external). Anything not
    // in it that an app reaches is, by definition, a violation.
    Policy   policy.Policy
    // Alerter receives raised alerts. Nil logs via slog (denials escalate).
    Alerter  Alerter
    // AlertWindow rate-limits repeated alerts for the same violation class
    // (default 1m): the first is raised immediately, repeats are coalesced into
    // the running count and re-raised at most once per window.
    AlertWindow time.Duration
    Logger   *slog.Logger
}

func New(cfg Config) *Monitor
func (m *Monitor) Emit(e event.Event)      // implements event.Sink
func (m *Monitor) Snapshot() Snapshot      // the live security picture
func (m *Monitor) Handler() http.Handler   // serves Snapshot as JSON at StatusPath

// Alert is a raised violation — more than a log line: severity-ranked,
// de-duplicated by class, counted, and time-bounded.
type Alert struct {
    Severity                        Severity   // info | warning | critical
    Host, Port, Proto, SNI, Reason  string
    Count                           int64      // attempts in this class so far
    FirstSeen, LastSeen             time.Time
    Message                         string
}
type Alerter interface{ Alert(Alert) }
type SlogAlerter struct{ Logger *slog.Logger } // default

// Snapshot is the queryable security picture (served at StatusPath).
type Snapshot struct {
    Since      time.Time
    Declared   []string     // policy hosts (the contract)
    Allowed    []HostStat   // hosts actually reached, with counts + bytes
    Violations []Violation  // deny classes, with severity + counts + timing
    Events     int64        // events processed
}

const StatusPath = "/_shrike/status"
```

```go
package policy // internal

// Policy is the declared egress contract: the external hosts the manifest
// permits, with the operator-facing reason each was declared for.
type Policy struct { /* … */ }
func New(decls []parser.External) Policy
func (p Policy) Declared(host string) (parser.External, bool) // is this host in the contract?
func (p Policy) Hosts() []string
```

```go
// wire.go — the sidecar transport (Unix-socket, newline-delimited JSON).

// DialSink is the FatLine-side event.Sink that ships events to a Shrike sidecar.
// It is lossy by design: if the sidecar is absent or slow, events are dropped
// (monitoring must never fail-close the data plane) and counted; it reconnects
// lazily. FatLine's composition root wraps it in the existing BufferedSink.
func NewDialSink(socketPath string) *DialSink
func (d *DialSink) Emit(e event.Event)
func (d *DialSink) Dropped() int64

// Serve accepts the FatLine connection on a Unix socket and replays decoded
// events into sink (a *Monitor) until ctx is cancelled.
func Serve(ctx context.Context, socketPath string, sink event.Sink) error
```

### Severity model

| Reason | Severity | Why |
|---|---|---|
| `sni_mismatch` | **critical** | An allowed `CONNECT` followed by a TLS handshake to a *different* name — the signature of domain-fronting or an active MITM attempt. |
| `not_in_allowlist` | **warning** | An app reached for a host it never declared. Routine misconfiguration *or* the first sign of a compromised dependency exfiltrating data — escalates with repetition. |
| `cleartext_not_allowed` | **info** | The app tried plain `http://`. The manifest carries no scheme, so this is a policy nudge ("declare it / use HTTPS"), not hostile. |

Burst behaviour escalates: N violations of the same class inside the alert window raise the recorded count and, past a threshold, bump the effective severity — a single stray `not_in_allowlist` is noise; a hundred in a minute is an incident.

---

## "Block + alert, don't just log"

The plan's phrasing for 2.2. Mapped to the architecture:

- **Block** — FatLine's, already done (2.1). Shrike *confirms* it: a `Deny` event **is** the proof the connection was refused. Shrike never adds a second, redundant enforcement point (that would be a network hop and a fail-closed dependency on the monitor — both forbidden).
- **Alert** — Shrike's contribution. An alert is distinct from a log line: it is **stateful** (a violation table keyed by `host+reason`), **de-duplicated and rate-limited** (one alert per class per window, not one per packet), **severity-ranked**, **counted with first/last-seen**, and **queryable** via `Snapshot()` / the status endpoint. That is what makes it actionable rather than a line that scrolls past.

A later phase can close the loop the other way — Shrike feeding *dynamic* policy back to FatLine (e.g. quarantine an app after N criticals). That control path is explicitly **out of 2.2 scope**; 2.2 observes and alerts.

---

## Testing & guardrails

Per [AGENTS.md](../AGENTS.md) and [ADR 0002](../docs/adr/0002-backend-language-strategy.md): `go test -race`, `go vet`, `golangci-lint`, all clean. Shrike has its own shared-mutable-state path (the violation table, written from `Emit` on the event stream and read from `Snapshot`/the status handler), so `-race` is load-bearing here too:

- **Policy** — table-driven: declared vs undeclared, case-fold / trailing-dot normalization parity with the allowlist, reason pass-through.
- **Inspector** — an `Allow` updates host stats; each `Deny` reason maps to the right severity; repeated denies coalesce into one rate-limited alert with a rising count; first/last-seen are tracked; a burst escalates severity.
- **Concurrency** — concurrent `Emit` from many goroutines interleaved with `Snapshot()` reads, race-clean (mirrors FatLine's allowlist/session-table race tests).
- **Wire** — round-trip a stream of events through `DialSink` → Unix socket → `Serve` → `Monitor` over a temp socket; a slow/absent receiver drops-and-counts and never blocks the emitter; malformed lines are skipped, not fatal.
- **Status** — the handler serves a well-formed `Snapshot` JSON; it never leaks anything beyond host/port metadata (events carry no secrets by construction, but the test pins it).

---

## Decisions

1. **Shrike monitors; FatLine enforces.** The boundary is FatLine's, inline and fail-closed. Shrike is a read-only, fail-open consumer of the decision stream — policeman, not wall ([AGENTS.md](../AGENTS.md#module-relationships)). Enforcement must never depend on the monitor's health.
2. **Built on the `event.Sink` seam, not a new tap.** 2.1 already emits exactly one structured, payload-free decision event per request through a drop-counting `BufferedSink`. Shrike *is* an `event.Sink`; no new interception, no new data path, no plaintext exposure.
3. **In-process *and* sidecar, same `Monitor`.** The engine is a pure `event.Sink`; a thin Unix-socket NDJSON wire lets the identical `Monitor` run as its own container (ADR 0003 sidecar). The two-container Pod that co-schedules them is **Planck 4.2** — this phase builds the capability and the seam, deferring the deployment, exactly as 2.1 built the mTLS/tunnel core and deferred the paid carrier to 2.3.
4. **An alert is stateful, not a log line.** De-duplicated by violation class, severity-ranked, counted with first/last-seen, rate-limited per window, and queryable in status. "Don't just log" taken literally.
5. **Severity by reason.** `sni_mismatch` → critical (active-attack signature), `not_in_allowlist` → warning (misconfig or exfiltration, escalates on burst), `cleartext_not_allowed` → info (policy nudge).
6. **Single-tenant now, per-app-ready.** 2.2 runs one instance-wide policy; `Event.Tenant`/`Event.App` are empty until 4.4 populates them, at which point the same violation table keys additionally on tenant. No rework — just a wider key.
7. **Stdlib only.** `encoding/json`, `net`, `net/http`, `log/slog`, `sync`, `time` — no third-party dependency, consistent with FatLine and the supply-chain posture.

---

## Roadmap

| Phase | Adds |
|---|---|
| **2.2** (this) | The Shrike artifact: inspector over FatLine's `event.Sink`, policy from manifest `external`, severity-ranked de-duplicated alerting, status surface, sidecar wire |
| 2.3 | (No Shrike change.) [`farcast connect`](../farsight/cli/README.md) binds the carrier; the operator can reach the instance, and the status surface becomes reachable through the tunnel |
| 4.2 | [Planck](../planck/README.md) templates the two-container Pod (FatLine + Shrike sidecar) and wires the socket |
| 4.4 | **Per-app enforcement** — each app's policy derived from its own manifest entry; violation alerts attributed to a specific app via `Event.Tenant`/`App`; "App A can't use App B's declarations" |
| 6.4 | [AllThing](../allthing/README.md) traffic-anomaly analysis feeds Shrike (AI-assisted detection) |

---

## Known limitations

Accepted-and-documented for 2.2, not oversights:

- **Shrike sees metadata, never payload.** By design (no MITM, the cloud stays blind) it knows host/port/proto/SNI/reason/byte-counts, not content. Exfiltration *to a declared host* is invisible to Shrike — that is a manifest-review problem (the operator vetting declarations), not a monitoring one.
- **Inherits FatLine's SNI/ECH blind spots.** Shrike can only alert on what FatLine can distinguish; Encrypted ClientHello, no-SNI, and domain-fronting limits ([FatLine known limitations](../fatline/README.md#known-limitations)) carry through.
- **Single-tenant in 2.2.** All violations attribute to the instance, not an app, until 4.4 — adequate while no apps run yet (Phase 4).
- **Alerts are local.** 2.2 raises alerts to logs and the status surface; routing them to an operator out-of-band (push, the FarSight GUI) is a later UX concern, consistent with zero-central-dependency (no phone-home).
- **No persistence.** The violation table is in-memory; a Shrike restart resets counts. Durable history is deferred (it would lean on DataSphere, Phase 3).

---

## References

- Module roles (policeman-not-wall, deny-by-default) — [`../AGENTS.md`](../AGENTS.md#module-relationships)
- The boundary it watches, and the event seam it consumes — [`../fatline/README.md`](../fatline/README.md), [`../fatline/event/event.go`](../fatline/event/event.go)
- Execution plan (2.2 scope, 4.2/4.4) — [`../PLAN.md`](../PLAN.md)
- Manifest spec (the `external` policy source) — [`../manifest/README.md`](../manifest/README.md)
- GKE Autopilot (sidecar inspector, no privilege) — [ADR 0003](../docs/adr/0003-gke-autopilot.md)
- Backend language strategy + guardrails — [ADR 0002](../docs/adr/0002-backend-language-strategy.md)
