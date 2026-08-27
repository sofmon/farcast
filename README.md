# Sofmon FarCast

> *"Just farcast it."*

FarCast is a cloud-native operating system by [Sofmon](https://sofmon.com). It treats cloud infrastructure as its hardware — no dedicated machines, no fixed location. A FarCast instance is a **private sovereign space** that lives within the public cloud universe, owned and controlled exclusively by its operator.

**[sofmon.com/farcast](https://sofmon.com/farcast)** · **[farcast.one](https://farcast.one)** *(the first FarCast instance)*

---

## Core Concept

Traditional operating systems run on hardware. FarCast runs on cloud primitives. Rather than reinventing compute, storage, or networking, FarCast provides a sovereign abstraction layer over mature cloud services — managed Kubernetes for compute (Planck), object storage for persistence (DataSphere), and encrypted networking over cloud infrastructure (FatLine). The unit of execution is not a binary — it is a **Git repository**. A repository may contain one or more applications, declared together in a single `./farcast` manifest, and Planck translates them into a namespace of workloads on the underlying cloud provider.

Every instance is private by default. No external party can connect to or control a FarCast instance without explicit permission from the operator. Every instance has a mandatory cost limit — FarCast protects the operator's wallet as fiercely as their data.

---

## Repository Structure

FarCast is organised as a single Go module rooted at `github.com/sofmon/farcast`, with one `go.mod`, one `go.sum`, and one shared `vendor/` directory at the repo root. Each top-level folder is a logical module — its `README.md` serves as the specification, source code lives alongside it, detailed specs and API documentation go in a `docs/` subfolder, and tests sit next to the code they cover. Dependencies are vendored: `go mod vendor` is the source of truth and builds run in vendor mode.

The one exception is `sdk/go/`, which is its own Go module. The SDK is the public import surface for external applications, so it has an independent dependency graph that end users can pull without dragging in the rest of FarCast.

```
farcast/
│
├── README.md                       ← you are here
├── go.mod                          ← single module: github.com/sofmon/farcast
├── go.sum
├── vendor/                         ← shared vendored dependencies
│
├── technocore/                     ← Kernel & core runtime
│   ├── README.md                   ← Module spec & overview
│   ├── docs/                       ← Detailed specs, architecture, API
│   ├── cmd/                        ← Entry point
│   │   └── technocore/
│   │       └── main.go
│   ├── internal/                   ← Private packages
│   │   ├── scheduler/
│   │   ├── monitor/
│   │   └── costs/                  ← Cost tracking & enforcement
│   └── pkg/                        ← Public packages (if any)
│
├── planck/                         ← Compute abstraction over managed K8s
│   ├── README.md
│   ├── docs/
│   ├── cmd/
│   │   └── planck/
│   │       └── main.go
│   ├── planck.go                   ← Package doc & provider registry
│   ├── types.go                    ← Provider interface & lifecycle types
│   ├── registry.go                 ← Optional instance-registry capability
│   ├── providers/                  ← Bundled adapter registration
│   └── internal/
│       ├── providers/              ← Cloud adapters (GKE implemented; EKS, AKS planned)
│       └── translator/             ← Manifest → K8s workload
│
├── fatline/                        ← Networking, routing, proxy & encryption
│   ├── README.md
│   ├── Containerfile               ← Distroless data-plane image
│   ├── docs/
│   ├── cmd/
│   │   └── fatline/
│   │       └── main.go
│   ├── identity/                   ← Per-instance CA & certificate minting
│   ├── tunnel/                     ← mTLS tunnel
│   ├── deploy/                     ← Bootstrap deployment manifests
│   ├── event/                      ← Wire events
│   └── internal/
│       ├── allowlist/
│       ├── proxy/
│       ├── router/
│       └── crypto/
│
├── datasphere/                     ← Storage abstraction & encryption-at-rest
│   ├── README.md
│   ├── docs/
│   ├── cmd/
│   │   └── datasphere/
│   │       └── main.go
│   └── internal/
│       ├── providers/              ← S3, GCS adapters
│       └── crypto/                 ← Encryption-at-rest
│
├── allthing/                       ← AI abstraction layer
│   ├── README.md
│   ├── docs/
│   ├── cmd/
│   │   └── allthing/
│   │       └── main.go
│   └── internal/
│       ├── providers/              ← Gemini, Claude, OpenAI adapters
│       └── chat/                   ← Chat interface
│
├── shrike/                         ← Security monitor & policy enforcement
│   ├── README.md
│   ├── docs/
│   ├── cmd/
│   │   └── shrike/
│   │       └── main.go
│   └── internal/
│       ├── policy/                 ← Manifest-based rule engine
│       └── inspector/              ← Traffic analysis
│
├── farsight/                       ← The "farcast" app (GUI + CLI + server)
│   ├── README.md
│   ├── docs/
│   ├── server/                     ← Go — UX composition & session management
│   │   ├── cmd/
│   │   │   └── farsight-server/
│   │   │       └── main.go
│   │   └── internal/
│   ├── client/                     ← Electron + TypeScript — GUI
│   │   ├── src/
│   │   ├── package.json
│   │   └── tsconfig.json
│   └── cli/                        ← Go — command line interface
│       ├── cmd/
│       │   └── farcast/
│       │       └── main.go
│       └── internal/
│           ├── image/              ← Image build & push, no container engine
│           └── oci/                ← Stdlib OCI distribution client
│
├── sdk/                            ← FarCast libraries (syscall-like APIs)
│   ├── README.md
│   ├── go/                         ← Go SDK — separate Go module
│   │   ├── farcast.go
│   │   ├── go.mod
│   │   └── go.sum
│   ├── node/                       ← Node.js SDK
│   │   ├── src/
│   │   └── package.json
│   └── python/                     ← Python SDK
│       ├── farcast/
│       └── pyproject.toml
│
├── manifest/                       ← ./farcast manifest spec & parser
│   ├── README.md
│   ├── docs/
│   ├── parser/                     ← Go — manifest parser library
│   │   ├── parser.go
│   │   └── parser_test.go
│   └── examples/                   ← Example manifests
│
└── docs/                           ← Project-wide docs
    ├── hyperion-reference.md       ← Naming lore
    ├── adr/                        ← Architecture Decision Records
    └── runbooks/                   ← Live validation runbooks
```

---

## Technology Stack

| Component | Language | Role |
|---|---|---|
| **TechnoCore** | Go | Kernel — orchestration, instance lifecycle, adaptive resource management, cost enforcement |
| **Planck** | Go | Compute abstraction — cloud-agnostic layer over managed Kubernetes (EKS, GKE, AKS) |
| **FatLine** | Go | Networking layer — routing, proxy, encryption, all traffic in/out |
| **DataSphere** | Go | Storage abstraction layer — cloud-agnostic proxy with encryption-at-rest |
| **AllThing** | Go | AI abstraction — cloud-agnostic layer over managed AI services (Gemini, Claude, OpenAI) |
| **Shrike** | Go | Security monitor — validates traffic against manifest declarations, intervenes on violations |
| **FarSight** | Go + Electron + TypeScript | The "farcast" app — GUI (tiling browser), CLI, and server-side composition |

See each module's `README.md` for language specifics, architecture detail, and implementation notes.

---

## The ./farcast Manifest

Any Git repository can run on FarCast by adding a `./farcast` file to its root. The manifest is intentionally minimal — it describes *what* to run, not *how* to run it. There are no resource declarations, no port mappings, no infrastructure details. Build instructions and startup commands live in each application's Containerfile; the manifest only declares identity and the security contract.

TechnoCore monitors every running application and adapts resources automatically — scaling CPU, memory, and replicas based on observed behaviour. The operator never needs to guess at resource requirements or tune infrastructure.

A manifest can describe one or more applications grouped as a single deployment. Planck translates it into a Kubernetes namespace with one workload per application — so a monorepo can deploy its full set of services from a single file.

```yaml
# ./farcast — single application
name: my-application
apps:
  - name: server
    containerfile: ./Containerfile
```

If an application needs to connect to external services, it must declare them explicitly. All outbound connections are denied by default — only declared endpoints are allowed. Declarations are scoped per-application: each app sees only its own allowlist. This ensures the operator knows exactly what each application will access before running it, and gives Shrike a clear contract to enforce at runtime.

```yaml
# ./farcast — with external access
name: my-application
apps:
  - name: server
    containerfile: ./Containerfile
    external:
      - host: api.stripe.com
        reason: Payment processing
      - host: smtp.mailgun.org
        reason: Transactional emails
```

A monorepo with multiple services uses multiple entries under `apps`. Each service points to its own Containerfile and carries its own `external` declarations.

```yaml
# ./farcast — monorepo with multiple services
name: my-platform
apps:
  - name: api
    containerfile: ./services/api/Containerfile
    context: .
    external:
      - host: api.stripe.com
        reason: Payment processing

  - name: worker
    containerfile: ./services/worker/Containerfile
    context: .

  - name: web
    containerfile: ./services/web/Containerfile
```

FarCast provides sensible defaults for everything else. Applications that need to interact with the FarCast environment (storage, networking, configuration, secrets) do so through the **farcast SDK** — a language-level library analogous to syscalls in a traditional OS kernel.

Full manifest specification → [`manifest/README.md`](manifest/README.md)

---

## Key Concepts

### Instances
A FarCast instance is the fundamental unit — analogous to a running OS on a physical machine. Instances are installed from base images, live in cloud infrastructure, and are terminated when no longer needed.

### Sovereignty
Every instance is private by default. All connections — inbound and outbound — are denied unless explicitly declared. Each application must list the external services it needs in its `./farcast` manifest, including a human-readable reason. The operator reviews these declarations before running the app. FatLine enforces the boundary, allowing only declared endpoints. Shrike monitors traffic at runtime and intervenes if an application attempts to reach an undeclared destination. The cloud provider cannot access the contents of an instance.

### Cost Control
Cloud costs are unpredictable by nature. FarCast treats cost control as a mandatory safeguard, not an optional dashboard. When installing an instance, the operator **must** set a cost limit — there is no default, no "unlimited", no way to skip it. TechnoCore continuously monitors cloud spending across compute (Planck), storage (DataSphere), networking (FatLine), and AI (AllThing). It breaks costs down per application, warns the operator as spending approaches the threshold, and takes protective action when the limit is reached — stopping the highest-cost applications first, and if necessary, shutting down the entire instance while keeping only TechnoCore alive to report status and allow the operator to respond.

### Git-Native Execution
Repositories are first-class executables. `farcast run github.com/user/repo` fetches the repository, reads its minimal manifest, and Planck translates it into a namespace containing one or more workloads on the underlying managed Kubernetes. TechnoCore monitors the applications and adapts resources automatically — no build pipeline, no deployment tooling, no capacity planning required.

### DataSphere
DataSphere is the storage abstraction layer. It proxies all file storage and retrieval, hiding the underlying cloud provider (S3, GCS, or any object store) behind a uniform interface. Before any data leaves the instance, DataSphere encrypts it — the cloud provider only ever sees encrypted blobs. Combined with FatLine's encryption in transit, this means the cloud provider is completely blind to both traffic and stored data.

### FatLine
FatLine is the sole networking layer for a FarCast instance. All traffic — instance-to-instance, instance-to-internet, and client-to-instance — flows through FatLine. It acts as router, proxy, and encryption boundary in one. By default, all connections are denied. FatLine only permits outbound traffic to external endpoints that are explicitly declared in an application's `./farcast` manifest. A FatLine connection is established the moment a client connects to a FarCast environment, and nothing enters or leaves the instance without passing through it.

### AllThing
AllThing is the AI abstraction layer. Like Planck abstracts compute and DataSphere abstracts storage, AllThing abstracts cloud AI services — Gemini, Claude, OpenAI, or any provider the operator chooses. Applications interact with AI through AllThing via the SDK, never directly with a provider. Initially, AllThing provides a chat interface accessible through FarSight. Over time, it becomes the AI backbone for the entire system — powering TechnoCore's adaptive resource management, Shrike's traffic analysis, and any application that needs intelligence.

### FarCast SDK
The farcast SDK is a set of language-level libraries that let applications interact with the FarCast environment — analogous to syscalls in a traditional OS. Instead of directly calling cloud APIs or managing infrastructure, applications import the farcast library and get access to storage (DataSphere), networking (FatLine), configuration, secrets, and environment defaults. The SDK abstracts the OS boundary so that applications remain cloud-agnostic and portable across any FarCast instance.

### FarSight
FarSight is how users see and interact with FarCast — the entire UX layer. It consists of a client and a server.

The user downloads a single app called "farcast". It provides three interfaces: a **GUI** (the tiling browser), a **CLI** (for operators and automation), and a **server** that runs inside the FarCast instance.

When opened, the app provides two functions: (1) **Install** — a guided process to deploy FarCast to a cloud environment, where the operator provides admin credentials for their chosen cloud provider, and (2) **Connect** — open a FarSight session towards a running FarCast instance. Both functions are accessible from the GUI and the CLI.

Once connected via the GUI, FarSight presents a browser-like interface using a tiling window manager layout. Each tile is an application running inside the FarCast instance. Every request from the FarSight client is proxied through FatLine — all traffic flows through the FarCast instance, meaning the user's local network cannot observe what they are doing. The user's point of presence on the internet is the FarCast instance, not their local machine.

The **FarSight server** runs inside the FarCast instance and handles UX composition — assembling the tiled layout, managing sessions, and serving the interface back to the client through FatLine.

---

## Naming

All component names are drawn from Dan Simmons' *Hyperion Cantos*. Each name reflects the component's role by design, not decoration. Full reference → [`docs/hyperion-reference.md`](docs/hyperion-reference.md)

---

## Instance Lifecycle

```
install → bind → run → release
```

- **Install** — create a new instance from a base image; operator must set a cost limit
- **Bind** — establish FatLine connections, mount DataSphere volumes
- **Run** — operational state; execute repositories via Planck
- **Release** — terminate the instance

---

## CLI Quick Reference

```bash
# Install an instance (cost limit is mandatory)
farcast install --name my-instance --cost-limit 100

# Run a repository on an instance
farcast run github.com/username/repo

# List running instances
farcast ps

# View cost breakdown
farcast costs my-instance

# Connect to a FarCast instance via FarSight
farcast connect my-instance

# Re-apply FatLine's workload to a connected instance
farcast redeploy my-instance

# Terminate an instance
farcast release my-instance
```

*Implemented today: `install`, `connect`, `redeploy`, `release` (plus `version` and `help`). `run`, `ps`, and `costs` are registered but stubbed until Phase 4.*

Full CLI reference → [`farsight/cli/README.md`](farsight/cli/README.md)

---

## Module READMEs

Each module folder contains its own `README.md` with:

- Purpose and responsibilities
- Architecture and internal design
- API and interfaces exposed to other modules
- Configuration reference
- Implementation notes and language specifics

| Module | README |
|---|---|
| TechnoCore | [`technocore/README.md`](technocore/README.md) |
| Planck | [`planck/README.md`](planck/README.md) |
| FatLine | [`fatline/README.md`](fatline/README.md) |
| DataSphere | [`datasphere/README.md`](datasphere/README.md) |
| Shrike | [`shrike/README.md`](shrike/README.md) |
| AllThing | [`allthing/README.md`](allthing/README.md) |
| FarSight | [`farsight/README.md`](farsight/README.md) |
| SDK | [`sdk/README.md`](sdk/README.md) |
| Manifest Spec | [`manifest/README.md`](manifest/README.md) |

---

## Status

> This project is in early development. Phases 0–2 are implemented, and Phase 3.1 with them. Phase 0 (foundation): the manifest parser and the Go SDK (core interfaces + logging). Phase 1 (provisioning): the FarSight CLI with `install`/`release`, driving Planck's GKE Autopilot provider with a private control plane — and giving every instance its own container image registry, created at install and deleted at release. Phase 2 (connection): FatLine's core proxy (mTLS tunnel, deny-by-default egress), Shrike's policy engine, and `farcast connect`, which builds FatLine's image from a local checkout with the Go toolchain, pushes it to that registry, and deploys it pinned by digest — no container engine anywhere. Phase 3.1 (storage) has landed too: DataSphere's encrypting store, blob format, operator-held keyring and GCS adapter, validated live against GCP — the provider holds only opaque name tokens and ciphertext. The remaining modules are in specification.

| Module | Spec | Implementation |
|---|---|---|
| TechnoCore | 🔲 Draft | 🔲 Not started |
| Planck | 🟡 In progress | 🟡 GKE Autopilot provider (create/destroy), instance image registry |
| FatLine | 🟡 In progress | 🟡 Core proxy: mTLS tunnel, deny-by-default egress |
| DataSphere | 🟡 In progress | 🟡 Encrypting store, blob format v1, keyring, GCS adapter (3.1, validated live) |
| Shrike | 🟡 In progress | 🟡 Policy engine |
| AllThing | 🔲 Draft | 🔲 Not started |
| FarSight | 🟡 In progress | 🟡 CLI: `install`, `release`, `connect`, `redeploy`; engine-less image build |
| SDK | 🟡 In progress | 🟡 Go: logging live, interfaces stubbed |
| Manifest Spec | ✅ Complete | ✅ Parser + tests |

*Legend: ✅ complete · 🟡 in progress · 🔲 draft / not started.*

---

## Future Concepts

The following components are planned for future implementation phases but are not part of the initial scope.

### TimeTomb — Snapshots & Recovery

*Hyperion origin: Sealed artifacts immune to change (the Time Tombs).*

TimeTomb will provide point-in-time snapshots of an entire FarCast instance — state, configuration, and DataSphere volumes — allowing operators to freeze, restore, and clone instances. This would extend the instance lifecycle with a **Snapshot** step between Run and Release, enabling recovery from failures and migration between cloud providers.

---

*Sofmon FarCast — [sofmon.com/farcast](https://sofmon.com/farcast)*