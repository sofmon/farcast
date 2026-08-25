# FatLine

> Networking layer — routing, proxy, encryption, all traffic in/out.

> **GKE Autopilot constraint ([ADR 0003](../docs/adr/0003-gke-autopilot.md)):** FatLine runs as a **userspace** L4/L7 proxy (a normal container — no privileged or host-network access). The deny-by-default egress boundary is enforced by always-on Kubernetes NetworkPolicy, not kernel interception. A future kernel/eBPF data plane (the Rust option in [ADR 0002](../docs/adr/0002-backend-language-strategy.md)) would require a GKE Standard/hybrid node pool. **Private nodes** (no external IPs) plus controlled egress — Cloud NAT vs. proxy-only — is a FatLine-phase decision, deferred in [ADR 0004](../docs/adr/0004-private-control-plane.md).

FatLine is the **sole networking layer** of a FarCast instance. Everything that enters or leaves an instance passes through it: the operator (and later the FarSight GUI) reaches the instance *inbound* over an encrypted tunnel, and applications reach the internet *outbound* through a deny-by-default proxy. It is router, proxy, and encryption boundary in one — and it is the first thing Phase 2 builds, because the security boundary must exist before anything runs on the instance.

This document specifies **Phase 2.1 — the core proxy**: the FatLine *artifact*. The actual point of presence (how an operator's laptop reaches FatLine across the internet) and the `farcast connect` command are wired in **2.3**; Shrike (the inspector) is **2.2**; the per-app NetworkPolicy and sidecar templating that make FatLine unbypassable are **Planck 4.2**. 2.1 builds the proxy and defines clean seams for the rest.

> **Status.** **Phase 2.1 (core proxy) — implemented** (`go test -race`, `go vet`, `golangci-lint` all clean). It delivers the FatLine artifact: the **mTLS tunnel server** (ingress), a stdlib-only **client tunnel library** (the import surface `farcast connect` consumes in 2.3), the **per-instance-CA crypto/identity** package, the **deny-by-default egress proxy** + concurrency-safe **allowlist engine** (fed from parsed manifest `external` declarations), the **connection lifecycle**, and the **Shrike event seam**. The two shared-mutable-state paths ([ADR 0002](../docs/adr/0002-backend-language-strategy.md)) — the allowlist and the session table — carry `-race` tests; mTLS and the egress proxy are exercised over loopback/`httptest` with an in-test ephemeral CA (no cloud, protecting the cost pillar). It ships **no public data-plane ingress** — the carrier (point of presence) is bound at 2.3 ([ADR 0005](../docs/adr/0005-fatline-data-plane-ingress.md), *deferred-hybrid*), so 2.1 adds **zero** new cloud spend. **Out of 2.1 scope, since shipped:** [`farcast connect`](../farsight/cli/README.md) (2.3), [Shrike](../shrike/README.md) (2.2), FatLine in-cluster deploy + mTLS-Secret provisioning (the 2.3 `connect` bootstrap — the `identity`/`deploy` packages below), and FatLine's **image**, which `connect` now compiles and pushes to the instance's own registry with no container engine anywhere in the loop ([ADR 0007](../docs/adr/0007-instance-owned-image-registry.md)). **Still deferred:** the per-app deny-egress NetworkPolicy + sidecar templating (Planck 4.2), and live per-app allowlist population (4.4).

---

## What FatLine is — and isn't (2.1 scope)

**It is** the data-plane networking layer, built as an ordinary userspace Pod:

- the **ingress tunnel** — an mTLS server the operator/SDK dials *into* the instance, multiplexing many concurrent streams over one mutually-authenticated session, sized for the Phase-7 GUI, not a thin CLI RPC;
- the **egress proxy** — a deny-by-default forward proxy that lets an in-instance app reach *only* the external hosts its `./farcast` manifest declares, and nothing else.

**It is not** the control plane. FatLine does **not** proxy `kubectl`/`client-go`; that is the private Kubernetes API server, a separate trust domain reached over Google IAM ([ADR 0004](../docs/adr/0004-private-control-plane.md)). FatLine's tunnel runs on FarCast's *own* per-instance CA, not Google IAM, keeping the sovereign data path free of any central dependency.

**It is not** `farcast connect` (the CLI client is 2.3 — 2.1 ships the library it imports), **not** Shrike (the inspector is 2.2 — 2.1 ships only the event seam it consumes), **not** the thing that makes itself unbypassable (the always-on NetworkPolicy + sidecar are Planck's translator, 4.2), and **not** multi-tenant per-app policy (live per-app allowlist population is 4.4 — 2.1 fixes the tenant-keyed seam).

Throughout, the framing is strict: 2.1 either **delivers** a thing or **defines a seam** for it. The [deferred seams](#deferred-seams) table draws every line.

---

## Architecture & package layout

```
fatline/
├── README.md                       ← this file
├── Containerfile                   ← REFERENCE build of the data-plane image (distroless, non-root, digest-pinned bases); `connect` builds the deployed image itself
├── docs/                           ← deeper protocol/crypto notes
├── fatline.go (+ types.go)         ← PUBLIC: Server, Config, New, Serve, Status, ReloadAllowlist, ConnStatus, Egress, ErrDenied
├── event/                          ← PUBLIC leaf: Event, Kind, Sink, SlogSink, BufferedSink (the Shrike seam)
├── tunnel/                         ← PUBLIC: client tunnel library (the 2.3 `connect` import surface)
│   └── tunnel.go                   ←   Connect(ctx, endpoint, ClientIdentity) → *Conn; Conn; ClientIdentity
├── identity/                       ← PUBLIC: operator-side mTLS mint/load for `connect`  (2.3)
│   └── identity.go                 ←   Mint(instance) → Material; (*Material).DialTLS; OperatorURI/ServerName
├── deploy/                         ← PUBLIC: renders FatLine's own K8s workload YAML      (2.3)
│   └── deploy.go                   ←   Render(Config) → apply stream (Namespace/Secret/Deployment/Service)
├── cmd/
│   └── fatline/
│       └── main.go                 ← thin server entry: load mTLS + allowlist, Serve until SIGINT
└── internal/
    ├── proxy/                      ← egress forward/CONNECT proxy; hot loop behind the Egress seam
    ├── router/                     ← session table + connection lifecycle             (race-tested)
    ├── crypto/                     ← mTLS *tls.Config builders + per-instance CA mint/load helpers
    └── allowlist/                  ← concurrency-safe, manifest-fed allowlist          (race-tested)
```

The wiring mirrors [Planck](../planck/README.md)'s [`database/sql`](https://pkg.go.dev/database/sql) shape — a dependency-light **public root** plus **internal** implementation, with a public surface *only* where another module imports it:

- **`fatline`** (root, public) declares `Server`, `Config`, `New`, `Serve`, `Status`, `ReloadAllowlist`, `ConnStatus`, and the `Egress` seam. TechnoCore and tests import it for the types.
- **`fatline/event`** (public leaf) holds the `Event`/`Sink` Shrike seam. It is a separate leaf because Shrike lives *outside* `fatline/` yet `internal/proxy` also depends on it — a leaf keeps that shared dependency cycle-free.
- **`fatline/tunnel`** (public) is the **client** side — the dialer that presents the operator's certificate and returns an `*http.Client` routed through the instance. It is public, not internal, because it is the one thing `farcast connect` (2.3) and the FarSight client (Phase 7) consume.
- **`fatline/identity`** and **`fatline/deploy`** (public, added 2.3) are the operator-side bootstrap surface `farcast connect` consumes: `identity` mints the per-instance CA + operator/server leaves and assembles the dial credential (wrapping `internal/crypto` so it stays internal); `deploy` renders FatLine's own Autopilot-compliant workload YAML. Neither depends on a Kubernetes client ([ADR 0006](../docs/adr/0006-connect-bootstrap-kubectl.md)).
- **`fatline/internal/allowlist`** and **`fatline/internal/router`** hold the two shared-mutable-state paths [ADR 0002](../docs/adr/0002-backend-language-strategy.md) singles out for race tests — the dynamic allowlist and the session table — so they are first-class packages, not buried in `proxy`.
- **`fatline/internal/proxy`** is the egress hot loop, behind a language-neutral `Egress` interface so the benchmark-gated Rust data plane ([ADR 0002](../docs/adr/0002-backend-language-strategy.md)) can drop in later without caller churn.

**Where the deployed image comes from.** `deploy` renders the workload; it does not build the image — and neither does an operator with a container engine. [`farcast connect`](../farsight/cli/README.md) builds it ([ADR 0007](../docs/adr/0007-instance-owned-image-registry.md)): it compiles `./fatline/cmd/fatline` for `linux/amd64` with the local Go toolchain (`CGO_ENABLED=0`, `-mod=vendor`, `-trimpath` — hermetic, from vendored source), lays the static binary onto a digest-pinned distroless base, and pushes the result to the instance's **own** registry at `<instance-registry>/system/fatline:<version>` through a standard-library OCI client. No docker, no podman, no daemon, and no Sofmon-published feed in the runtime path. What `connect` then hands `deploy.Config.Image` is the digest (`image@sha256:…`), not the tag, so whoever can later write that tag cannot swap FatLine under a running instance — an explicitly passed `--fatline-image` is deployed exactly as the operator named it. `fatline/Containerfile` reproduces the same image independently — both of its bases pinned by digest — as the **reference** build: for verification, or for an operator who does have an engine.

FatLine lives in the **root module** (single `go.mod`, per [AGENTS.md](../AGENTS.md)) and must **not** import `sdk/go` (a separate module). `ConnStatus` is defined here; the SDK keeps its own copy and maps over the wire.

---

## The two planes

### Ingress — the mTLS tunnel

The operator (CLI now, GUI in Phase 7) opens **one** mutually-authenticated TLS session and multiplexes many concurrent proxied streams over it, with per-stream flow control. The default framing is **HTTP/2-over-mTLS** — native multiplexing, stdlib, GUI-sized — kept behind the `fatline/tunnel` package so it is a swappable internal detail, not a wire contract callers depend on.

Both ends authenticate (see [the mTLS model](#the-mtls-model)). The server is configured with `tls.RequireAndVerifyClientCert` against the per-instance CA, so an unauthenticated peer is dropped at the TLS handshake — **deny-by-default at the front door**, before any stream is routed or any allowlist consulted. This is a non-relaxable invariant: a future carrier may change *how* bytes arrive, never *whether* the client cert is verified.

In **2.1 there is no public carrier.** The server listens on a ClusterIP Service and is exercised loopback / in-process (`net.Pipe`, `httptest`) and optionally in-cluster. *How the operator reaches it across the internet* — the point of presence — is bound at **2.3** ([ADR 0005](../docs/adr/0005-fatline-data-plane-ingress.md)): the pre-committed default is a single mTLS-gated L4 passthrough load balancer (TLS terminated in FatLine, so the cloud carries only ciphertext); a control-plane port-forward path is the documented fallback. 2.1 commits to the *tunnel*, not the *carrier*.

### Egress — the deny-by-default forward proxy

An in-instance app's outbound traffic is a standard forward-proxy flow. FatLine is what the SDK's `farcast.Net().HTTPClient()` points at; the proxy URL is discovered from a Pod env var (`FARCAST_FATLINE_PROXY`) that **Planck injects in 4.2** — 2.1 fixes the contract, not the injection.

- **HTTPS (the normal case): `CONNECT host:443`.** FatLine checks the authority host against the app's allowlist, dials the upstream, returns `200`, then does an **opaque** bidirectional `io.Copy`. It **never terminates TLS to the upstream** — end-to-end encryption to e.g. `api.stripe.com` is preserved and FatLine (and the cloud) see ciphertext only. This is what keeps *"the cloud is blind"* true on the egress path.
- **Plain `http://` is denied by default** (reason `cleartext_not_allowed`). FatLine refuses to silently proxy cleartext it would itself see and that would cross cloud-carried network in the clear — confidentiality is part of deny-by-default, not just the hostname. The manifest declares a bare hostname with no scheme, so FarCast cannot infer `https` intent; cleartext is therefore a documented, opt-in-only exception, never the default.
- **SNI defense-in-depth.** On an allowed `CONNECT`, FatLine peeks the TLS ClientHello to read `server_name` *without* terminating, and asserts `SNI == CONNECT authority` (case-folded); a mismatch tears the connection down (`sni_mismatch`). The peek is precise: read and **buffer** the leading record bytes, parse the ClientHello from the buffer, then `io.MultiReader(buffer, conn)` into the upstream copy so consumed bytes are replayed unchanged. The only degraded mode is authority-only matching — it **never fails open** to no check. (This is defense-in-depth, not a cryptographic guarantee — see [Known limitations](#known-limitations).)

**Deny behavior.** A denied request gets a `403` (a policy denial, not a `407` proxy-auth challenge); `CONNECT`-level denials surface a sentinel `ErrDenied` so app code can `errors.Is` it. The denied host is **never dialed** — the cloud sees no connection attempt. Exactly **one** structured `Event` is emitted *before* the caller is answered, so Shrike's *block-and-alert* (2.2) is satisfiable. This mirrors the SDK's existing `deniedTransport` posture in [`sdk/go/net.go`](../sdk/go/net.go).

---

## The interfaces

The public server root:

```go
// Server is the FatLine data plane: the ingress mTLS tunnel and the
// deny-by-default egress proxy. One per instance.
type Server struct { /* … */ }

// Config is everything FatLine needs to run. mTLS material is minted by
// internal/crypto; the allowlist is built from parsed manifest declarations
// (public types only, so the composition root needs no internal packages).
type Config struct {
	TunnelListen        string              // ingress mTLS tunnel address (ClusterIP in 2.1)
	EgressListen        string              // forward-proxy address (FARCAST_FATLINE_PROXY)
	ServerCert          tls.Certificate     // this listener's server leaf + key
	ClientCA            *x509.CertPool      // the per-instance CA — verifies operator clients
	AllowClientIdentity func(uri string) bool // authorize a verified client's URI SAN (nil = any CA-signed cert)
	Allowlist           []parser.External   // egress policy, deny-by-default
	Events              event.Sink          // egress decisions; Shrike implements this in 2.2
	Endpoint            string              // advertised endpoint, reported in status
}

func New(cfg Config) (*Server, error)
func (s *Server) Serve(ctx context.Context) error    // runs both planes until ctx is done; graceful drain
func (s *Server) Status() ConnStatus
func (s *Server) ReloadAllowlist(decls []parser.External) // atomic egress-policy hot-swap

// ConnStatus reports the boundary's health. The SDK (sdk/go/net.go) keeps its
// own ConnStatus and maps onto Connected over the wire.
type ConnStatus struct {
	Connected bool
	Endpoint  string
	Since     time.Time
	Active    int      // live tunnel streams
	Allowlist []string // declared hosts, for `farcast connect` status (2.3)
}
```

The public client tunnel (`fatline/tunnel`) — the 2.3 `connect` import surface:

```go
// ClientIdentity is the operator's data-plane credential: a client leaf + key,
// the per-instance CA to verify the server, and the SAN to pin.
type ClientIdentity struct {
	Cert       tls.Certificate
	CA         *x509.CertPool
	ServerName string
}

// Connect mTLS-dials endpoint and establishes the multiplexed session.
func Connect(ctx context.Context, endpoint string, id ClientIdentity) (*Conn, error)

type Conn struct { /* … */ }
func (c *Conn) HTTPClient() *http.Client            // requests route through the instance
func (c *Conn) Status(ctx context.Context) (ConnStatus, error)
func (c *Conn) Close() error
```

The allowlist (`fatline/internal/allowlist`) — built straight from the manifest parser's type:

```go
// New builds an allowlist from parsed manifest `external` declarations
// (github.com/sofmon/farcast/manifest/parser .External{Host, Reason}).
func New(decls []parser.External) *List

func (l *List) Allowed(host string) Decision         // single-tenant convenience
func (l *List) Allow(tenant, host string) Decision   // tenant-keyed seam (4.4)
func (l *List) Reload(decls []parser.External)        // atomic hot-swap
func (l *List) Snapshot() []parser.External

type Decision struct {
	Allowed bool
	Host    string
	Reason  string // allow → the manifest reason; deny → not_in_allowlist | cleartext_not_allowed | sni_mismatch
}
```

The egress seam (the Rust/benchmark boundary, in the `fatline` package) and the
Shrike seam (the public `fatline/event` leaf — see the note below):

```go
// Egress is the deny-by-default outbound proxy: an http.Handler (CONNECT for
// HTTPS, absolute-URI for HTTP). The hot path sits behind this seam so a future
// Rust data plane (ADR 0002) can replace it.
type Egress interface {
	http.Handler
}

// Sink receives one Event per egress decision, emitted before the caller is
// answered. Shrike (2.2) is a Sink; the 2.1 default is event.SlogSink. A
// BufferedSink decouples a slow consumer from the hot path (it drops + counts
// rather than block, so a decision is never stalled for observability).
type Sink interface{ Emit(Event) }

type Event struct {
	Kind               Kind   // allow | deny | close
	Tenant, App        string // app identity — empty in 2.1; 4.4 fills it
	Host, Port, Proto  string // proto: "connect" | "http"
	SNI                string
	Reason             string // deny reason: not_in_allowlist | cleartext_not_allowed | sni_mismatch
	BytesUp, BytesDown int64
}
```

> **Note (package boundary).** The `Event`/`Sink` seam lives in a small **public
> `fatline/event` leaf**, not the root package. Shrike (which lives *outside*
> `fatline/`) and FatLine's `internal/proxy` both depend on it, so a leaf package
> is what keeps that shared dependency free of an import cycle through the server
> package.

---

## The mTLS model

FatLine's tunnel is mutually authenticated against **one per-instance Root CA** — the instance's sovereign root of trust, with **no public CA, ACME, or cert-manager** in the path (zero central dependency).

- **The CA is the crown jewel and is operator-held — it never enters the cluster.** FatLine is shipped the CA *certificate* (to verify clients) plus its own *server leaf + key*; it is never given the CA private key. So a cloud compromise of the in-cluster Secret can read only the rotatable server leaf (which authenticates *this listener*), never mint new identities.
- **Leg 1 — client verifies server.** The client trusts **only** the instance CA (`RootCAs`, no system-root fallback) and pins the server's `ServerName`/SAN.
- **Leg 2 — server verifies client.** `tls.RequireAndVerifyClientCert` against the instance CA, plus a `VerifyConnection` SAN-identity check, so *"a valid cert from our CA"* is necessary but not sufficient. That SAN hook is the seam the 4.4 per-app identity and multi-operator models build on.
- **Choices.** TLS 1.3 only (a closed FarCast-to-FarCast channel — no 1.2 fallback to misconfigure), **ed25519** leaves/CA (ECDSA P-256 fallback only if a peer rejects ed25519), `crypto/rand` serials, CA validity 1–2 y, leaves 90 d. All stdlib: `crypto/tls`, `crypto/x509`, `crypto/ed25519`, `encoding/pem`.
- **Identity SAN.** Operator identity is a SPIFFE-style URI SAN — `farcast://<instance>/operator` — so it composes with the per-app identities (`farcast://<instance>/app/<name>`) that 4.4 will pin. The server-leaf SAN is a single `serverIdentity` input, so the *same* issuance code serves whichever carrier 2.3 binds (a public DNS/IP, an in-cluster service name, or a URI identity).
- **Storage.** Operator side: `ca.crt`, `ca.key`, `client.crt`, `client.key` (plus the rotatable `server.crt`/`server.key`) at `0600` under the instance's `fatline/` subdirectory in the [CLI instance store](../farsight/cli/README.md#configuration--credential-storage). Server side: the `fatline-mtls` Kubernetes `Secret` (`ca.crt`/`server.crt`/`server.key` — never `ca.key`).
- **Rotation & revocation.** Rotation is re-issuing a leaf from the held CA. There is no CRL/OCSP — revocation is short leaf lifetimes plus a FatLine-side allowed-SAN/serial set, correct for a single sovereign instance (with a documented revocation latency — see [Known limitations](#known-limitations)).

**2.1 ships only the mint/load library** (`internal/crypto`): mint a per-instance CA, issue server/client leaves (`serverIdentity` SAN as one parameter), and build the pinned `*tls.Config` for both legs. Creating the in-cluster `Secret`, and the actual mint-and-persist call from `farcast install`/`connect`, are **2.3/4.2** work — 2.1 does not touch the CLI or provision anything in the cluster.

---

## Cost & security posture

The two non-negotiable pillars ([AGENTS.md](../AGENTS.md)) shape even this early module:

- **Cost.** *Deferred-hybrid* ([ADR 0005](../docs/adr/0005-fatline-data-plane-ingress.md)) adds **zero** new cloud spend in 2.1: a ClusterIP Service and loopback/in-cluster testing, no forwarding rule, on the ~$37–51/mo Autopilot baseline ([ADR 0003](../docs/adr/0003-gke-autopilot.md)). The standing load-balancer cost (~$18/mo — a real 30–50% bump on the floor) lands only at **2.3**, when `farcast connect` makes the carrier *usable*; it must be surfaced at connect time so the mandatory cost limit accounts for it. The instance's image registry — where the deployed image lives ([ADR 0007](../docs/adr/0007-instance-owned-image-registry.md)) — joins that same connect-time cost line as a line item rather than a gate: it rounds to $0 at FatLine's image size, and same-region pulls are free. The test suite uses an in-test ephemeral CA + `httptest`, so CI never touches billable cloud.
- **Security / privacy.** FatLine is a normal userspace Pod — no privileged/`hostNetwork`/`NET_ADMIN` ([ADR 0003](../docs/adr/0003-gke-autopilot.md)); the *enforcement* that an app cannot bypass FatLine is the always-on NetworkPolicy (Planck 4.2), while FatLine does the userspace manifest allowlisting. The SDK's proxy-pinned transport and that NetworkPolicy agree: even a bypass attempt reaches nothing but FatLine + DNS. Deny-by-default is the **only** egress mode (an empty allowlist denies everything); client-cert verification is non-relaxable; and FatLine's own CA — not Google IAM — keeps the data path off any central authority, preserving the [ADR 0004](../docs/adr/0004-private-control-plane.md) control-plane/data-plane separation.

The honest boundary (same as [Planck](../planck/README.md#cost--security-posture)): the cloud runs the managed control plane and the node that terminates TLS, so it can read the in-cluster *server leaf* key — but never the operator-held CA signing key, and never the plaintext of client↔instance traffic. Hardening (CMEK / memory-only key delivery) is a flagged, deferred seam.

---

## Deferred seams

2.1 builds the artifact and exposes a clean attachment point for everything else:

| Deferred | Phase | What 2.1 exposes |
|---|---|---|
| Shrike inspector | 2.2 | `EventSink`/`Event` seam (default slog sink) |
| `farcast connect` command | 2.3 | the `fatline/tunnel` library + `ConnStatus` it consumes |
| Point-of-presence **carrier** (public mTLS NLB; control-plane fallback) | 2.3 | a thin carrier abstraction; the tunnel binds to either without touching crypto/allowlist |
| FatLine in-cluster deploy + mTLS `Secret` + mint material | 2.3 (connect-time bootstrap) | the `internal/crypto` mint/load library |
| Per-app deny-egress **NetworkPolicy** + sidecar templating | Planck 4.2 | a userspace proxy that the policy + SDK env-var (`FARCAST_FATLINE_PROXY`) point at |
| Live per-app identity → allowlist population & attribution | 4.4 (+ 4.2) | the tenant-keyed `Allow(tenant, host)` + empty `Event.App` |
| Optional Rust hot-loop data plane | post-2.1, benchmark-gated | the language-neutral `Egress` interface + `EventSink` |
| Private nodes / Cloud-NAT-vs-proxy egress | FatLine-phase design note | resolve-after-allowlisting hook (see limitations) |

---

## Testing & guardrails

Per [AGENTS.md](../AGENTS.md) and [ADR 0002](../docs/adr/0002-backend-language-strategy.md), FatLine is held to `go test -race`, `go vet`, and `golangci-lint` — and `-race` is **load-bearing here**, because ADR 0002 singles FatLine out for race tests on its shared mutable state:

- **Race tests on the two named paths** — the **allowlist** (concurrent `Allowed()` reads interleaved with `Reload()` atomic swaps, asserting no torn read and deny-by-default *during and after* a swap) and the **session table** (concurrent establish/lookup/teardown under `Serve`), plus race-clean `GetCertificate`/`GetConfigForClient` during cert/SAN-set rotation.
- **mTLS** over `net.Pipe` with an in-test ephemeral CA: a good client connects; a wrong-CA or no-client-cert peer is rejected at the handshake.
- **Egress** against `httptest`: a declared host is proxied; an undeclared host and an empty allowlist are denied; table-driven coverage of case-fold / trailing-dot / IP-literal-deny, `CONNECT` vs absolute-URI, the **fragmented-ClientHello SNI buffer/replay**, the `403`/`ErrDenied` deny behavior, and exactly-one-event-per-decision.
- **Lifecycle** — `ctx`-cancellation drains cleanly (the Go-side analogue of the cancellation-safety tests ADR 0002 mandates for any future Rust data plane).
- **Secret-safety** — TLS keys never appear in any log or `String()` output (the same guard Planck applies to its kubeconfig).
- **Integration** — a real-cluster end-to-end test sits behind `//go:build integration` and is **never in CI** (cost pillar), mirroring [Planck](../planck/README.md#testing-strategy).

---

## Decisions

1. **Deferred-hybrid ingress** ([ADR 0005](../docs/adr/0005-fatline-data-plane-ingress.md)). Build and egress-test the artifact in 2.1 with **no public ingress**; bind the paid point-of-presence carrier at 2.3. Standing up an ~$18/mo load balancer to front a tunnel that cannot yet be called (`connect` is 2.3, no apps until Phase 4) would burn money for zero deliverable value — a cost-pillar violation — and ADR 0004 explicitly deferred this question "to the FatLine phase."
2. **Four protocol-shaping invariants locked now** (so the deferral is sequencing, not a dodge): a multiplexed, GUI-sized tunnel framing; **non-relaxable** `RequireAndVerifyClientCert`; the per-instance CA trust root; and a thin, swappable carrier abstraction. With these fixed, the 2.3 carrier is a binding swap that never touches the tunnel/crypto/allowlist core.
3. **HTTPS/CONNECT preferred; plain `http://` denied by default.** FatLine tunnels TLS opaquely (never sees plaintext, holds no upstream key) and refuses cleartext egress unless explicitly opted in per host — confidentiality is part of deny-by-default.
4. **SNI is defense-in-depth with a precise buffer/replay** (`io.MultiReader`), never failing open. It catches the "CONNECT to an allowed host, then TLS to a different one" lie; it is not a cryptographic guarantee (see limitations).
5. **Tenant-keyed allowlist seam, not a deployment topology.** 2.1 commits to `Allow(tenant, host)` + an empty `Event.App`; whether 4.2 runs a shared multi-tenant FatLine or a per-app sidecar is a Planck/cost decision left to 4.2. The "App A can't use App B's list" guarantee comes from keyed selection, which holds under either topology.
6. **Per-instance, operator-held CA; mutual auth with SAN pinning; TLS 1.3 / ed25519 / stdlib-only.** The CA private key never enters the cluster; identity is a SPIFFE-style URI SAN that composes with the 4.4 per-app model.
7. **Shrike event seam with a drop counter.** One structured event per decision, emitted before the caller is answered; the sink is non-blocking (the *block* always happens even if the event is dropped) but counts drops and emits a periodic summary, so a deny flood under attack is never a silent alert blind spot.
8. **SDK contract fixed, injection deferred.** 2.1 fixes the `http.Transport{Proxy: …}` shape `sdk/go/net.go` will adopt (proxy-pinned, no direct-dial fallback); the `FARCAST_FATLINE_PROXY` env-var injection and the sidecar that sets it are Planck 4.2.
9. **Go for 2.1; Rust gated behind the `Egress` seam** ([ADR 0002](../docs/adr/0002-backend-language-strategy.md)). "Build FatLine in Go first — it is needed early in Phase 2 regardless." The optional Rust hot loop is benchmark-gated and attaches at the language-neutral `Egress`/`EventSink` boundary.

---

## Roadmap

| Phase | Adds |
|---|---|
| **2.1** (this) | FatLine core artifact: mTLS tunnel server + client library, deny-by-default egress proxy + allowlist, per-instance-CA crypto, lifecycle, Shrike event seam |
| 2.2 | [Shrike](../shrike/README.md) sidecar implements `EventSink` — compares live egress against declared endpoints, block + alert on violations |
| 2.3 | [`farcast connect`](../farsight/cli/README.md) binds the carrier (default: public mTLS L4 NLB; control-plane fallback) and bootstraps FatLine into the instance (build + push the image to the instance's own registry — [ADR 0007](../docs/adr/0007-instance-owned-image-registry.md) — deploy it by digest, mint/inject mTLS material) |
| 4.2 | [Planck](../planck/README.md) translator emits the per-app deny-egress NetworkPolicy + templates the FatLine sidecar/env |
| 4.4 | Shrike per-app allowlist population + per-app attribution |
| post-2.1 | Optional benchmark-gated Rust data plane behind the `Egress` seam ([ADR 0002](../docs/adr/0002-backend-language-strategy.md)) |

---

## Known limitations

These are deliberately accepted-and-documented in 2.1, not oversights:

- **SNI allowlisting is defense-in-depth, not a cryptographic guarantee.** It is bypassable under Encrypted ClientHello (ECH hides `server_name`), no-SNI connections, and domain-fronting (the `CONNECT` host and SNI match an allowed name while the HTTP `Host` header *inside* the TLS targets a different origin on a shared frontend — invisible because FatLine never decrypts). IP-literal `CONNECT` authority is hard-denied (the manifest forbids IPs, so no IP can ever be a member).
- **The server leaf key is readable by the GKE managed control plane** (a K8s Secret, Google-managed KMS by default). *"The cloud is blind"* holds for client↔instance traffic confidentiality and for the operator-held CA signing key (never in-cluster), but **not** for the live leaf key on the host that terminates TLS — the cloud already runs that compute. Hardening (CMEK / memory-only delivery) is deferred, and sharpens if the threat model formally adopts process-memory-disclosure / co-tenant attacks (an open [ADR 0002](../docs/adr/0002-backend-language-strategy.md) input).
- **Port is not matched.** The manifest declares host only (ports reserved as not-yet-specified), so any port on an allowed host is permitted; the port is recorded on the event but not enforced.
- **No CRL/OCSP.** Revocation is short leaf lifetimes + a FatLine-side allowed-SAN/serial set + CA rotation; a leaked operator client cert stays valid until its TTL expires or the operator removes its SAN/serial.
- **Plain-HTTP egress cannot be made confidential** — the host-only manifest carries no scheme, so cleartext is a deny-by-default exception (`cleartext_not_allowed`), a limitation of the host-only model rather than a feature.
- **DNS-rebinding split.** FatLine allowlists the *name* but egress dials whatever the resolver returns. The recommended mitigation — FatLine resolves the name it just allowlisted and pins name→IP for the connection — is noted as a design point that interacts with the deferred [ADR 0004](../docs/adr/0004-private-control-plane.md) Cloud-NAT-vs-proxy egress decision.
- **No public-path proof in 2.1.** The artifact is exercised loopback/in-process and optionally in-cluster; the end-to-end paid point of presence is validated only at 2.3 — the deliberate cost-pillar tradeoff.

---

## References

- Project overview ([FatLine](../README.md#fatline), [Sovereignty](../README.md#sovereignty), point of presence) — [`../README.md`](../README.md)
- Agent/architecture context (pillars, Go-vs-Rust, guardrails) — [`../AGENTS.md`](../AGENTS.md)
- Execution plan (2.1/2.2/2.3, 4.2/4.4, Phase 7) — [`../PLAN.md`](../PLAN.md)
- Manifest spec (the `external` allowlist source) — [`../manifest/README.md`](../manifest/README.md)
- SDK networking contract — [`../sdk/go/net.go`](../sdk/go/net.go), [`../sdk/go/README.md`](../sdk/go/README.md)
- Operator CLI (`connect`, instance store) — [`../farsight/cli/README.md`](../farsight/cli/README.md)
- Compute layer (Provider, translator 4.2) — [`../planck/README.md`](../planck/README.md)
- Security monitor (the inspector, 2.2) — [`../shrike/README.md`](../shrike/README.md)
- Backend language strategy + FatLine guardrails — [ADR 0002](../docs/adr/0002-backend-language-strategy.md)
- GKE Autopilot (userspace proxy) — [ADR 0003](../docs/adr/0003-gke-autopilot.md)
- Private control plane (deferred egress/PoP) — [ADR 0004](../docs/adr/0004-private-control-plane.md)
- FatLine data-plane ingress — [ADR 0005](../docs/adr/0005-fatline-data-plane-ingress.md)
- Instance-owned image registry (where FatLine's image is built, pushed, and pulled from) — [ADR 0007](../docs/adr/0007-instance-owned-image-registry.md)
