# FarSight CLI — `farcast`

> The operator's command line for FarCast — install instances, run repositories, watch costs.

`farcast` is the command line face of [FarSight](../README.md), the FarCast UX layer. The same downloadable "farcast" app provides a GUI (the tiling browser), a server (UX composition inside an instance), and this CLI. The CLI is what operators and automation use to provision instances, deploy repositories, connect through FatLine, and monitor spending.

This document specifies the CLI phase by phase — the scaffold (1.1) and each command landed since: `install` (1.3), `release` (1.4), and `connect` + `redeploy` (2.3). **Phase 1.1 — the CLI scaffold** (implemented): the command framework, the two commands that work from day one (`version`, `help`), local configuration handling, and the human/JSON output model. **Phase 1.3 — `farcast install`** (implemented): the first command that does real, billable work — interactively provisioning a cloud instance through Planck under a mandatory cost limit. The scaffold is what makes `install` a small, uniform addition.

> **Status.** **Phase 1.1 (scaffold) — implemented** (`go test -race`, `go vet`, and `golangci-lint` all clean): argument parsing and subcommand routing, `farcast version`, `farcast help`, local config file handling, and human + JSON output formatting. **Phase 1.3 (`farcast install`) — implemented** (`go test -race`, `go vet`, `golangci-lint` all clean): interactive provisioning through [Planck](../../planck/README.md), a mandatory cost limit, a management-API + DNS-endpoint health check, the instance's own container image registry ([ADR 0007](../../docs/adr/0007-instance-owned-image-registry.md)), and record-before-create local persistence of instance metadata + credentials + kubeconfig. **Phase 1.4 (`farcast release`) — implemented** (`go test -race`, `go vet`, `golangci-lint` all clean): the destructive counterpart that tears the cluster down through Planck, deletes the instance's registry with it, and removes local state, initiating the cloud delete before removing the record so a failed delete call never strands billable infrastructure (deletion completes asynchronously — see the 1.4 known limitation). **Phase 2.3 (`farcast connect`) — implemented** (`go test -race`, `go vet`, `golangci-lint` all clean): it mints the per-instance mTLS identity (CA key kept local), re-ensures the instance's registry and sources FatLine's image from it — compiling and pushing that image itself, from a farcast checkout, with **no container engine on the operator's machine** ([ADR 0007](../../docs/adr/0007-instance-owned-image-registry.md)) — bootstrap-deploys FatLine via kubectl **pinned to the image's digest** ([ADR 0006](../../docs/adr/0006-connect-bootstrap-kubectl.md)), provisions its public mTLS load-balancer carrier under a cost-confirmation gate ([ADR 0005](../../docs/adr/0005-fatline-data-plane-ingress.md)), dials the tunnel, and reports status. The orchestration is unit-tested against a fake cluster runner, a fake registry provider, a fake image builder and an injected tunnel dial; the real public-NLB path is `//go:build integration`, never in CI (cost pillar), as is the one test that pulls from a real public registry. **`farcast redeploy` — implemented** (same clean bar): the operational counterpart to the bootstrap — it re-renders and re-applies FatLine's workload for an already-connected instance, resolving the image through the *same* code `connect` uses, so a FatLine security fix rolls out without `release` and a reinstall; it never re-provisions the carrier and never re-mints the CA, and it re-applies even when the digest is unchanged (the failure it was built for lived in the workload template, not the image). Every remaining command is **registered but stubbed** — it appears in `help` and routes correctly, but exits non-zero with a "not yet implemented" message naming its [`PLAN.md`](../../PLAN.md) phase (`run`/`ps`/`logs`/`costs` → 4.3, and so on).

---

## What the CLI is — and isn't

**It is** the operator-side client. It runs on a laptop or in CI, holds the operator's cloud credentials locally, and drives instances. It is deliberately small, dependency-light, and secure by construction — it handles cloud admin credentials, so its supply-chain surface is a security concern, not just a packaging one.

**It is not** the [farcast SDK](../../sdk/go/README.md). The SDK is the syscall surface for applications running *inside* an instance; the CLI is the operator tool *outside* it. They do not share code and the CLI does not import the SDK. The two meet only on the wire — the CLI talks to a running instance through FatLine, in later phases.

**It is not** the GUI or the server. Those are separate FarSight components (Electron client, Phase 7; Go server, later). The CLI is a standalone Go binary now; the packaged "farcast" app will ship it alongside the GUI.

---

## Design principles

1. **Minimal dependencies, for security.** The CLI stores cloud admin credentials. Every third-party dependency is attack surface against those credentials, so the scaffold is built on the Go standard library (plus the already-vendored YAML library for config) — and every surface added since has held that line: the container-image path added at 2.3 is standard library end to end and grew the vendored module count by nothing. See [Decisions](#decisions) for the CLI-framework choice this implies.
2. **Results and diagnostics are separate streams.** Command *results* go to **stdout** (human text or JSON, per `--output`). *Diagnostics* go to **stderr** (and only when `--verbose`). A caller can always `farcast … --output json | jq` without log noise on stdout.
3. **Every command is scriptable.** Anything a command prints in human mode it can also emit as JSON, so the CLI is automation-first. Exit codes are meaningful.
4. **Secure local state by construction.** The config directory is `0700`, credential files are `0600`, and the CLI refuses (or repairs, with a warning) state that is more permissive. Credentials never leave the operator's machine except through an explicit, declared channel.
5. **The structure precedes the features.** 1.1 builds the routing, output, and config machinery so that every later command is a small, uniform addition — register a `Command`, return a typed result, done.

---

## Module & build

Per the repository convention ([AGENTS.md](../../AGENTS.md) → "Conventions"), FarCast is a **single Go module** rooted at `github.com/sofmon/farcast`; only `sdk/go/` is separate. The CLI is therefore part of the root module:

- **Binary:** `farcast`
- **Entry point:** `github.com/sofmon/farcast/farsight/cli/cmd/farcast`
- **Packages:** `github.com/sofmon/farcast/farsight/cli/internal/...`

> **Note (cleanup, done).** The stray per-module `go.mod` files — this one plus the seven other unimplemented modules — have been removed, so every package except `sdk/go` now lives in the root module per the single-module convention. Only `go.mod` (root) and `sdk/go/go.mod` remain.

**Build** (from the repository root), stamping version metadata:

```bash
go build -o farcast \
  -ldflags "-X github.com/sofmon/farcast/farsight/cli/internal/buildinfo.Version=0.1.0 \
            -X github.com/sofmon/farcast/farsight/cli/internal/buildinfo.Commit=$(git rev-parse --short HEAD) \
            -X github.com/sofmon/farcast/farsight/cli/internal/buildinfo.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  ./farsight/cli/cmd/farcast
```

When the stamp is absent (e.g. `go run`), `buildinfo` falls back to the VCS data Go embeds via `runtime/debug.ReadBuildInfo`, then to `dev`.

Minimum Go version: **1.26** (matches the repository toolchain). `go.mod` also pins an exact `toolchain` (`go1.27.0`), fetched through the checksum-verified module proxy when the local one is older. That pin reaches past the CLI's own build: the same toolchain is what `connect` shells to when it compiles FatLine's container image ([ADR 0007](../../docs/adr/0007-instance-owned-image-registry.md)).

---

## Command surface

```
farcast [global flags] <command> [command flags] [arguments]
```

| Command | Status | Purpose | Phase |
|---|---|---|---|
| `version` | ✅ works | Print version, commit, build date, Go/OS/arch | 1.1 |
| `help` | ✅ works | Help for `farcast` or a specific command | 1.1 |
| `install` | ✅ works | Provision a new instance on a cloud provider (interactive) | 1.3 |
| `release` | ✅ works | Destroy an instance and clean up local state | 1.4 |
| `connect` | ✅ works | Open a FatLine tunnel to an instance | 2.3 |
| `redeploy` | ✅ works | Re-apply FatLine's workload to a connected instance | 2.3 |
| `run` | ⏳ stub | Deploy a Git repository to an instance | 4.3 |
| `ps` | ⏳ stub | List running applications | 4.3 |
| `logs` | ⏳ stub | Stream an application's logs | 4.3 |
| `costs` | ⏳ stub | Show spending and distance to the cost limit | 4.3 |
| `storage` | ✅ works | The instance's encrypted disk: `ls`, `cp`, `rm`, `usage`, `key …` | 3.3 |
| `chat` | ⏳ stub | Terminal AI chat through AllThing | 6.2 |

*Legend: ✅ works · 📋 specified, not yet implemented · ⏳ stub.* Stubbed commands route correctly and print a clear "not yet implemented (phase N)" message to stderr, exiting non-zero. This mirrors the SDK's `ErrNotImplemented` pattern: the whole surface is visible and navigable before the features land. `install` is the canonical verb for creating an instance — the CLI, the root README, and the [instance lifecycle](../../README.md#instance-lifecycle) (`install → bind → run → release`) all use it.

### Global flags

| Flag | Default | Meaning |
|---|---|---|
| `-o`, `--output {human\|json}` | `human` | Format for command **results** on stdout. |
| `-v`, `--verbose` | off | Emit diagnostic logs on stderr. |
| `--config <dir>` | OS default | Override the config directory (also `FARCAST_CONFIG_HOME`). |
| `-h`, `--help` | — | Show help for `farcast` or the named command. |
| `--version` | — | Shorthand for `farcast version`. |

(The standard library `flag` package treats `-flag` and `--flag` as equivalent, so both spellings work. Bundled short flags like `-vo` are not supported — a deliberate, minor trade-off of staying on the standard library.)

---

## Output model

**Two streams, never mixed:**

- **stdout** — command results. Human text by default; a single JSON value with `--output json`.
- **stderr** — diagnostics (text, only with `--verbose`) and error messages.

**Exit codes:**

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Runtime error (the command ran but failed) |
| `2` | Usage error (unknown command, bad flag, missing argument) |

**Errors** are formatted to match the mode: in human mode a `farcast: <message>` line on stderr; in JSON mode a `{"error":{"message":…,"code":…}}` object on stdout, so automation parses failures the same way it parses results.

### `farcast version`

Human:

```
farcast 0.1.0
  commit:   abc1234
  built:    2026-06-02T10:00:00Z
  go:       go1.26.3
  os/arch:  darwin/arm64
```

JSON (`--output json`):

```json
{"version":"0.1.0","commit":"abc1234","built":"2026-06-02T10:00:00Z","go":"go1.26.3","os":"darwin","arch":"arm64"}
```

### `farcast help`

```
farcast — the operator CLI for FarCast

Usage:
  farcast [global flags] <command> [command flags] [arguments]

Commands:
  version    Print version information
  help       Show help for farcast or a command
  install    Provision a new instance on a cloud provider
  release    Destroy an instance and clean up local state
  connect    Open a FatLine tunnel to an instance
  redeploy   Re-apply FatLine's workload to a connected instance
  run        Deploy a Git repository to an instance   (not yet implemented — phase 4.3)
  …

Global flags:
  -o, --output {human|json}   Result format (default human)
  -v, --verbose               Diagnostic logging on stderr
      --config <dir>          Override the config directory
  -h, --help                  Show this help

Run "farcast help <command>" for details on a command.
```

---

## Configuration & credential storage

FarCast has **zero central dependency** ([AGENTS.md](../../AGENTS.md)): there is no account, no registry, no phone-home. All operator state lives locally.

**Location.** The config directory is resolved as, in order:

1. `--config <dir>` flag, else
2. `FARCAST_CONFIG_HOME` environment variable, else
3. `os.UserConfigDir()/farcast` — i.e. `~/Library/Application Support/farcast` (macOS), `~/.config/farcast` (Linux/XDG), `%AppData%\farcast` (Windows).

**On-disk layout** (schema fleshed out as the commands that own it land):

```
<config-dir>/                         (0700)
├── config.yaml                       (0600)  CLI preferences (default output, etc.)
└── instances/                        (0700)
    └── <instance-name>/              (0700)  one directory per installed instance
        ├── metadata.yaml             (0600)  non-secret: provider, project, region, cluster
        │                                      name + endpoint, status, cost limit, registry,
        │                                      timestamps
        ├── credentials.yaml          (0600)  secret: cloud provider credential (SA key JSON)
        ├── kubeconfig.yaml           (0600)  secret: cluster-access kubeconfig
        └── datasphere/               (0700)  storage keys  (3.3)
            └── keys.yaml             (0600)  secret: the instance's DataSphere keyring —
                                               the one file whose loss is permanent, total
                                               loss of everything in the bucket
```

**Security.** Credentials are secrets the cloud provider would love and an attacker would love more:

- The directory is created `0700` and credential files `0600`. On load, the CLI checks permissions and **refuses to read** (or repairs, with a stderr warning) anything group/world-readable.
- Non-secret metadata is kept separate from secret credentials, so a command that only needs metadata never opens the credential file.
- Plaintext-at-rest with `0600` matches the baseline of `aws`/`gcloud`. Hardening — OS keychain integration, or encrypting credentials with an operator passphrase — is noted for a later phase, consistent with FarCast's security-first posture.

**Format.** YAML, via the already-vendored `github.com/goccy/go-yaml` (the same library the manifest parser uses), keeping the dependency set unchanged and the files operator-readable. See [Decisions](#decisions).

**Phase 1.1 delivered** the `config` package — path resolution, `0700`/`0600` enforcement, and typed load/save of `config.yaml`. **Phase 1.3 adds the instance store** above — typed `metadata.yaml` / `credentials.yaml` / `kubeconfig.yaml` per instance, created and written by [`farcast install`](#farcast-install--provision-an-instance-phase-13) under the same permission rules, with a write-ordering that keeps a cluster from ever existing un-recorded (see that section).

---

## `farcast install` — provision an instance (Phase 1.3)

`farcast install` turns "a cloud account + a cost limit" into "a running FarCast instance." It is the first command that does real, billable work: it provisions a managed Kubernetes cluster through [Planck](../../planck/README.md) ([GKE Autopilot](../../docs/adr/0003-gke-autopilot.md) today), gives the instance the container image registry it owns ([ADR 0007](../../docs/adr/0007-instance-owned-image-registry.md)), confirms the control plane is reachable, and records everything needed to operate and later tear the instance down — all under the strict local-state rules above.

It is **interactive by default** and **fully scriptable**: every prompt has a matching flag, so an operator can run it conversationally while automation runs it unattended.

### Flow

1. **Resolve inputs** from flags, then interactive prompts (human mode + TTY only) for whatever is missing. The mandatory cost limit is never defaulted.
2. **Select the provider** from those Planck has registered (`planck.Providers()`) — today just `gke`.
3. **Validate credentials** — `planck.Open` then `Validate`, before creating anything. Bad credentials fail here, fast and free.
4. **Confirm** — show a summary (provider, region, cluster name, cost limit) and require a yes. `--yes` skips it; it is required when non-interactive. This is the last step before money is spent.
5. **Record intent** — write `metadata.yaml` (status `provisioning`) and `credentials.yaml` *before* provisioning, so a cluster can never exist un-recorded.
6. **Provision** — `CreateCluster` blocks until the cluster is `RUNNING` (several minutes), with progress on stderr.
7. **Record the access path** — write `kubeconfig.yaml` and the cluster's endpoint into metadata.
8. **Ensure the registry** — create the instance's own image repository and grant its cluster pull access on it (see [The instance's registry](#the-instances-registry) below). A failure here is a **warning, not a failed install**: the cluster above is already billable, so aborting would strand it, and the next `farcast connect` re-ensures the registry anyway.
9. **Health check** — confirm the instance is alive via the GKE management API (`ClusterStatus == RUNNING`) plus the IAM-gated DNS endpoint; the control plane is private, so there is no public IP to dial ([ADR 0004](../../docs/adr/0004-private-control-plane.md)).
10. **Finalize** — update metadata to `running` (or `unreachable`), print the result.

### Command surface

```
farcast install [flags]
```

| Flag | Required | Meaning |
|---|---|---|
| `--name <name>` | yes | Instance name — the local-state key and the basis for the cluster name (`farcast-<name>`). DNS-label form. |
| `--provider <id>` | no | Cloud provider (default: the sole registered one, `gke`). |
| `--project <id>` | yes for `gke` | Cloud project (GCP project ID). |
| `--region <region>` | no | Cloud region (default: the provider's, `us-central1`). |
| `--credentials <path>` | no | Path to a credential file (GCP service-account key JSON). Omit to use Application Default Credentials. |
| `--cost-limit <amount>` | **yes** | Monthly spend ceiling, in USD. **No default, no "unlimited" — install will not proceed without it.** Must be > 0. |
| `--yes`, `-y` | no | Skip the confirmation prompt; required when running non-interactively. |

Global flags (`--output`, `--verbose`, `--config`) apply as everywhere; with `--output json` the command prints one JSON result object and never prompts.

**Interactive vs. unattended.** The CLI prompts only when the session is interactive — human output mode *and* stdin is a terminal (detected via `os.ModeCharDevice`; no dependency). Otherwise every required value must come from a flag, `--yes` is required, and a missing value is a usage error (exit 2) rather than a hung prompt. Prompts go to **stderr** and answers are read from **stdin**, so stdout carries only the result and `farcast install … --output json | jq` stays clean.

### The mandatory cost limit

FarCast treats cost control as a safeguard, not a dashboard ([root README](../../README.md#cost-control)). `install` enforces this at the one point where it is structural — the moment the instance is created:

- **No default and no skip.** Omitting `--cost-limit` unattended is a usage error; interactively, the prompt repeats until a valid positive amount is given.
- The limit is persisted in `metadata.yaml`. **Enforcement belongs to TechnoCore** ([phase 4.1](../../technocore/README.md)); 1.3 *captures and persists* the ceiling so the enforcement loop and every cost-aware command have an authoritative value to read. Recording it at install time is what makes "no instance without a limit" a property of the system rather than a habit.

For 1.3 the limit is a monthly USD amount (`{amount, currency: USD, period: monthly}` in metadata, with currency/period fixed); generalizing currency and window is a later refinement.

### Provisioning through Planck

`install` names no cloud. It blank-imports `planck/providers` (so adapters self-register), then drives the neutral interface:

```go
p, err := planck.Open(provider, planck.Config{Project: project, Location: region, Credentials: cred})
if err := p.Validate(ctx); err != nil { /* bad credentials — fail before creating */ }
cluster, err := p.CreateCluster(ctx, planck.ClusterSpec{Name: clusterName, Location: region, Labels: farcastLabels})
// blocks until RUNNING; cluster.Kubeconfig reaches the control plane
```

Cluster shape — Autopilot, node management, networking — is entirely Planck's concern; `install` supplies a name, a region, and FarCast resource labels and gets back a ready `*planck.Cluster`. Planck provisions a **private control plane** (no public IP; IAM-gated DNS-based endpoint — [ADR 0004](../../docs/adr/0004-private-control-plane.md)), so `Cluster.Endpoint` is a DNS FQDN and the kubeconfig targets it. `CreateCluster` is idempotent, so re-running after a partial failure resumes rather than duplicates. The cluster name is derived as `farcast-<instance>` and validated against the provider's rules before anything is created.

### The instance's registry

Kubernetes puts code into a Pod exactly one way — the kubelet pulls an image from a registry — so *some* registry is structural; the only question is whose. FarCast's answer is that the instance owns one ([ADR 0007](../../docs/adr/0007-instance-owned-image-registry.md)). Pulling FarCast's own images out of a feed Sofmon publishes would make every instance's security boundary depend on a third party's artifact server, which is exactly the phone-home shape the zero-central-dependency pillar rejects.

So `install` ensures a Docker-format repository named **`farcast-<instance>`** in the instance's own region and project — instance identity, like the cluster and the CA — and every image the instance ever runs is named from the prefix it yields:

```
prefix:   us-central1-docker.pkg.dev/<project>/farcast-prod
FarCast:  <prefix>/system/fatline:<version>            ← FarCast's own images (2.3)
apps:     <prefix>/app/<deployment>/<app>:<git-sha>    ← application images (phase 4)
```

The `system/` prefix costs one path segment now and prevents both a rename migration later and an operator app named `fatline`. The ensure is **idempotent** — `connect` re-runs it defensively on every connect — and it is Planck's `RegistryProvider`, an *optional* provider capability, so a cloud whose adapter cannot host images is still a perfectly good provider for a cluster ([Planck](../../planck/README.md)).

**Pull access is an explicit, repository-scoped grant.** The ensure binds `roles/artifactregistry.reader` **on that one repository** to the cluster's node service account — today the project's default Compute Engine account, whose email Planck derives from the project *number* (the cluster object reports the account as the literal `default`). It is deliberately not a project-level grant: the node account is shared, so a project-scoped role would hand every workload in the project the instance's images. Nor does it lean on that account's automatic project `Editor` role, which is org-policy-conditional — a pull relying on it works by accident and breaks on a hardened project. The principal that was granted is recorded in metadata, so the grant is auditable from local state without opening a cloud console.

**The installer credential needs one role more than 1.3 asked for:** `roles/artifactregistry.admin` — the narrowest predefined role that can create repositories, covering repository create/delete and repository-level `setIamPolicy`, and nothing at project scope, so the CLI's credential never holds project-IAM power. It is a re-apply for operators who provisioned their service account earlier ([Phase 1 runbook](../../docs/runbooks/phase-1-validation.md)); without it the ensure fails with a permission error naming what is missing, and the install continues with a warning.

**Cost is surfaced, not gated.** Artifact Registry bills storage; FatLine's image is ~20 MB and same-region pulls are free, so the registry is effectively `~$0/mo` beside the ~$18/mo load balancer that *does* earn a confirmation gate ([`connect`](#farcast-connect--open-a-fatline-tunnel-phase-23)). `install` prints it as a line item and asks nothing — gating cents would train the operator to click through the gate that matters.

### Health check

"Basic health check confirms the instance is alive" (PLAN 1.3). `CreateCluster` already waits for `RUNNING`; the health check re-confirms it independently and verifies the operator's own access path. Because FarCast clusters have a **private control plane with no public IP** ([ADR 0004](../../docs/adr/0004-private-control-plane.md)), there is no public endpoint to dial directly — the operator reaches the API server through GKE's IAM-gated **DNS-based endpoint**. So the check is two cheap, dependency-free steps: (1) re-query the GKE **management API** for `ClusterStatus == RUNNING` (configuration-independent, always reachable), and (2) optionally make one IAM-authenticated request to the DNS endpoint to confirm the operator can reach the control plane.

A deeper check — API-server `/healthz`, FarCast components, workloads — needs the in-cluster components and TechnoCore and lands with them. If it fails, the cluster is **kept** (it is billable, and the failure may be transient networking): the instance is recorded `unreachable`, the operator is warned, and the command exits non-zero so automation notices.

### Local state & atomicity

`install` fills in the instance store from [Configuration & credential storage](#configuration--credential-storage). Because an un-recorded cluster is an untracked bill, it writes the local record **before** provisioning:

1. **Reserve** `instances/<name>/`; refuse if it already exists — no silent clobber (release first, or pick another name).
2. **Write** `credentials.yaml` and `metadata.yaml` with `status: provisioning`.
3. **`CreateCluster`.** On error, leave the record (`status: provisioning`/`error`), direct the operator to `farcast release <name>`, exit 1.
4. **On success**, write `kubeconfig.yaml`, ensure the instance's registry (a failure here is a warning, never an abort — the cluster is already billable), run the health check, then update `metadata.yaml` (`status: running` | `unreachable`, plus the endpoint and the registry).

So an interruption at any point — failure, `Ctrl-C` (the root context is cancelled on `SIGINT`), crash — always leaves a local record carrying the deterministic cluster name and the credentials, which `farcast release` (1.4) can act on. The metadata/credentials split means `release`, `costs`, and `ps` read non-secret metadata without ever opening a secret file.

### Output

Human:

```
✓ instance "prod" installed
  provider:    gke
  region:      us-central1
  cluster:     farcast-prod
  endpoint:    a1b2c3d4.us-central1.gke.goog
  registry:    us-central1-docker.pkg.dev/<project>/farcast-prod (instance images, ~$0/mo)
  cost limit:  USD 50.00 / monthly
  state:       running
  config:      ~/Library/Application Support/farcast/instances/prod
```

(The `registry` line is omitted when the provider has no registry capability, or when the ensure failed — in which case the warning naming why is already on stderr.)

JSON (`--output json`) — a single object, the same data:

```json
{"name":"prod","provider":"gke","region":"us-central1","cluster":"farcast-prod","endpoint":"a1b2c3d4.us-central1.gke.goog","registry":"us-central1-docker.pkg.dev/<project>/farcast-prod","status":"running","cost_limit":{"amount":50,"currency":"USD","period":"monthly"},"config_path":"…/farcast/instances/prod"}
```

---

## `farcast release` — tear down an instance (Phase 1.4)

`farcast release <instance>` is the counterpart to [`install`](#farcast-install--provision-an-instance-phase-13): it destroys an instance's cloud resources and removes its local state. It is the one routinely **destructive** command, so it confirms deliberately and orders its steps so a failure never strands billable infrastructure.

### Flow

1. **Resolve the instance** — the positional `<instance>` argument; load its `metadata.yaml` and `credentials.yaml` from local state. An unknown instance is an error.
2. **Open the provider** — `planck.Open` with the *stored* provider, project, region, and credentials (the ones `install` recorded), so release needs no cloud flags beyond the name.
3. **Confirm** — show what will be destroyed and require confirmation (retype the instance name). `--yes` skips it; it is required when non-interactive. This is the point of no return.
4. **Mark deleting** — update `metadata.yaml` to `status: deleting`, so an interrupted release stays visible in local state.
5. **Destroy the cluster** — `DeleteCluster` returns once the cloud accepts the delete; the cluster finishes deleting asynchronously (GKE shows it `STOPPING` for a few more minutes). Deleting an already-absent cluster succeeds (idempotent).
6. **Destroy the registry** — delete the instance's image repository and everything in it ([ADR 0007](../../docs/adr/0007-instance-owned-image-registry.md)), *waiting* for the deletion to actually run (unlike the cluster's, it takes seconds). The cluster goes first because it is the expensive resource. Nothing sovereign is lost — every image in the repository is derivable from Git — while keeping it would leave billable storage nobody is watching. Deleting an absent repository succeeds, and a provider with no registry capability has nothing to delete.
7. **Clean up local state** — remove the instance directory, only after the cloud has accepted both deletes.

### Command surface

```
farcast release <instance> [flags]
```

| Flag | Meaning |
|---|---|
| `<instance>` | The instance name to release (positional, required). |
| `-y`, `--yes` | Skip the destructive confirmation; required when non-interactive. |

Global flags (`--output`, `--verbose`, `--config`) apply. With `--output json` the command prints one JSON result and never prompts. Release takes **no** cloud flags — provider, project, region, and credentials all come from the recorded instance.

### The confirmation

Destruction is irreversible, so the bar is higher than install's. Interactively, release prints a summary (instance, provider, region, cluster, and — when one is recorded — the image registry and every image in it) and asks the operator to **retype the instance name** to confirm; anything else aborts. `--yes` skips the prompt (and is required when stdin is not a terminal). This mirrors the "type the name to delete" pattern operators expect from destructive tooling.

### Order & idempotency

The danger in teardown is the inverse of install's: removing the local record before the cloud resources are gone would strand something **billable and now unfindable**. So release **initiates the cloud deletes first, then removes local state**:

1. Set `status: deleting` in `metadata.yaml`.
2. `DeleteCluster`. On error, **keep** the local record (status stays `deleting`), report the failure, and exit non-zero — the operator can re-run `release`.
3. `DeleteRegistry`, under the same discipline: on error the record is kept — the message says the cluster is destroyed and the registry is not — so a re-run has something to converge on.
4. On success, remove the instance directory.

Both deletes are idempotent (neither an absent cluster nor an absent repository is an error), so a `release` re-run after a partial failure — cluster already deleted, registry or local cleanup interrupted — simply succeeds and removes the lingering record. The registry is identified from the recorded repository name, falling back to the instance name and region, so an instance whose record predates registries still has the (idempotent) delete attempted against the right name. A `release` is therefore always safe to repeat, which is exactly what cleans up the orphaned *record* a failed `install` can leave behind (status `provisioning`/`error`). (Known limitation: `DeleteCluster` currently returns when the cloud *accepts* the delete, not when it completes — release removes the local record while the cluster is still `STOPPING`. A delete that fails after acceptance would strand a cluster with no local record; polling deletion to completion is a planned refinement.)

### Local cleanup & output

On success the instance directory (`metadata.yaml`, `credentials.yaml`, `kubeconfig.yaml`) is removed wholesale. For phase 1.4 there is no persistent storage to consider — the cluster is empty compute; data lifecycle arrives with DataSphere (phase 3).

Human:

```
✓ instance "prod" released
  provider:    gke
  cluster:     farcast-prod (deleted)
  registry:    farcast-prod (deleted)
  state:       removed
```

JSON (`--output json`):

```json
{"name":"prod","provider":"gke","cluster":"farcast-prod","registry":"farcast-prod","status":"released"}
```

The `registry` line and field name only what the instance was recorded as owning: the delete is still attempted for an instance whose record predates registries, but the report claims only what it knows.

---

## `farcast connect` — open a FatLine tunnel (Phase 2.3)

`farcast connect <instance>` is where the operator's machine stops being a point of presence and the *instance* becomes one. It establishes the [FatLine](../../fatline/README.md) mutually-authenticated tunnel into a running instance, reports the boundary's status, and persists the operator's data-plane identity so every later command (`run`, `ps`, `logs`, …, phase 4.3) routes its instance traffic through FatLine rather than the public internet.

Unlike `install`/`release`, which drive the *control plane* (the Kubernetes API, over Google IAM), `connect` drives the *data plane*: FatLine, authenticated by FarCast's **own per-instance CA**, never Google IAM ([ADR 0005](../../docs/adr/0005-fatline-data-plane-ingress.md)). The two planes stay separate by design ([ADR 0004](../../docs/adr/0004-private-control-plane.md)).

The first `connect` to a fresh instance does a one-time **bootstrap**: mint the instance's mTLS identity, put FatLine's image into the registry the instance owns, deploy FatLine into the cluster, and provision its public point of presence. Subsequent connects reuse all of it and simply re-dial. Every step is idempotent, so an interrupted bootstrap is resumed, not duplicated.

### What it carries — the carrier ([ADR 0005](../../docs/adr/0005-fatline-data-plane-ingress.md))

The default carrier is a **single public, mTLS-gated L4 passthrough load balancer** per instance (a GKE `Service{type: LoadBalancer}` fronting the FatLine Pod). Google forwards raw TCP and never terminates TLS, so the cloud carries **ciphertext + SNI only**; the entire boundary is FatLine's `RequireAndVerifyClientCert` — an unauthenticated peer with the IP gets a TCP connect and a `ClientHello`, then is dropped at certificate verification, before any byte is routed. It is a locked door on a public street.

That load balancer is a **standing ~$18/mo cost** (a real 30–50% bump on the ~$37–51/mo Autopilot baseline). Because cost control is a non-negotiable pillar, `connect` surfaces it and **requires confirmation** before provisioning — the same "last step before money is spent" gate as `install`. The carrier sits behind a thin, swappable seam (ADR 0005 invariant #4); the documented control-plane-port-forward fallback (A2) is a later binding against that seam, not a rewrite — `connect`'s mTLS identity and core are carrier-independent.

### Where FatLine's image comes from ([ADR 0007](../../docs/adr/0007-instance-owned-image-registry.md))

A Deployment needs an image, and FarCast's answer to "from where" is **the registry the instance owns** — never one Sofmon publishes. `--fatline-image` therefore defaults to a reference computed from the instance's recorded registry prefix, at the fixed system path, tagged with this CLI's version:

```
<prefix>/system/fatline:<version>
e.g. us-central1-docker.pkg.dev/<project>/farcast-prod/system/fatline:0.1.0
```

There is no central fallback: the `ghcr.io/sofmon/farcast/fatline` default of the earlier 2.3 cut is **deleted, not deprecated**. It made every instance's network boundary depend on an artifact feed a third party controls — a standing central dependency and a supply-chain injection point aimed at FatLine itself.

`connect` preflights that reference against the registry before it deploys anything:

- **Present** → resolve it and deploy `…/system/fatline@sha256:…`, **pinned by digest**. A Deployment that names a *tag* can be redirected by anyone who can write that tag; a digest cannot, so a registry-write compromise cannot swap FatLine under a running instance. The digest is recorded in `metadata.yaml` and shown in the status.
- **Absent** → build it from the farcast checkout on this machine and push it, after a confirmation. Only a literal miss counts as absent: a permission or network failure stops with the registry's own words attached, rather than being buried under a long, doomed push.
- **Named explicitly** with `--fatline-image` → deployed exactly as given, with no preflight and no registry access. The operator vouches for that reference — including whether it is pinned.

**Nothing in that build is a container engine.** FatLine's image is a static Go binary on a digest-pinned distroless base with no `RUN` steps to execute, so the CLI does the whole thing itself: `go build` with the local toolchain (CGO off, `-mod=vendor`, `-trimpath`, `GOOS=linux GOARCH=amd64` — GKE Autopilot nodes are amd64), the binary packed into a deterministic tar layer, that layer appended to the base image pulled anonymously from gcr.io **by digest**, and the result pushed to the instance's registry. No docker, no podman, no daemon, no VM, and no credential left in any tool's store — the push credential is a ~60-minute access token minted in-process from the stored service-account key, used for the one command and dropped. [`fatline/Containerfile`](../../fatline/Containerfile) survives as an independently verifiable **reference** build of the same image, not as the canonical path.

**What the build needs is what a source-built `farcast` already needs:** the Go toolchain on `PATH`, and a farcast checkout. `--source <dir>` names the checkout; without it the CLI walks up from the working directory to the `go.mod` declaring `github.com/sofmon/farcast` (walking *past* `sdk/go`, which is its own module inside this repository). With the image missing and no checkout to build it from, `connect` fails naming exactly what it could not find.

**The image flags apply to the first connect only.** A reconnect re-dials what is
already running; it renders and applies nothing. So `--fatline-image` or
`--source` on an already-connected instance is refused with a usage error rather
than silently ignored — reporting success while the previous image kept serving
is the worst possible answer when the flag is being used to roll out a FatLine
fix. Changing what a connected instance runs is
[`farcast redeploy`](#farcast-redeploy--replace-a-connected-instances-fatline-workload-phase-23)'s
job, and the refusal names it: `connect` opens the tunnel, `redeploy` changes
what runs inside it.

**A registry failure stops only a connect that needs the registry.** `--status` does no registry work whatsoever — a health probe must not depend on it. A reconnect to an instance already running FatLine, or a connect carrying an explicit `--fatline-image`, degrades a failed ensure to a stderr warning and carries on; that is what keeps an instance installed before ADR 0007 — whose stored installer credential predates `roles/artifactregistry.admin` — reconnectable.

### The bootstrap flow

1. **Resolve the instance** — load `metadata.yaml`, `credentials.yaml`, `kubeconfig.yaml`. An instance that was never `install`ed, or is not `running`, is an error directing the operator to `install` first.
2. **Ensure the data-plane identity** — on first connect, mint a fresh **per-instance CA** and from it an **operator client leaf** (URI SAN `farcast://<instance>/operator`) and a **FatLine server leaf** (DNS SAN `<instance>.fatline.farcast`, the pinned server name). Persist all of it under the instance dir at `0600` (see [Local identity store](#local-identity-store)). On later connects, load it. **The CA private key never leaves the operator's machine** — only the CA *certificate* and the server leaf+key are pushed to the cluster, so a compromise of the in-cluster Secret reads a rotatable leaf, never the power to mint identities.
3. **Ensure the instance's registry** — re-run install's idempotent ensure ([above](#the-instances-registry)), so an instance created before it had a registry converges here instead of failing later as an unexplained `ImagePullBackOff` inside the cluster. Skipped entirely under `--status`, and not cost-gated: the registry is cents at most, unlike the load balancer below.
4. **Cost gate** — if FatLine is not yet deployed (or the carrier not yet provisioned), show the standing LB cost (~$18/mo, counted against the instance's cost limit) and require a yes. `--yes` skips it; it is required when non-interactive. *This is the point where money starts.*
5. **Resolve FatLine's image** — preflight the reference in the instance's registry and, when it is missing, compile and push it from the local checkout ([above](#where-fatlines-image-comes-from-adr-0007)). That build is a **second, separate confirmation** — a consent gate, not a cost gate — which `--yes` also covers. What comes out either way is a digest.
6. **Deploy FatLine** — render FatLine's Autopilot-compliant workload ([`fatline/deploy`](#supporting-modules)) — `Namespace`, the mTLS `Secret` (CA cert + server leaf+key; **not** the CA key), `Deployment` (its container image the digest from step 5), and the `Service{type: LoadBalancer}` — and apply it through **kubectl over the stored kubeconfig** (no vendored Kubernetes client — see [Decisions](#decisions)). Idempotent (`kubectl apply`). Requires `kubectl` **and** `gke-gcloud-auth-plugin` on the operator's `PATH` — the stored kubeconfig authenticates through the plugin's exec hook (Decision 8).
7. **Await the point of presence** — record the now-existing (billable) load balancer and the exact image the cluster was told to run *before* waiting, then wait for the Deployment to roll out and the Service to be assigned its external IP (the LB ingress), with progress on stderr.
8. **Dial & verify** — `tunnel.Connect(ctx, "https://<lb-ip>:8443", ClientIdentity{client leaf, per-instance CA, pinned server name})`. `Connect` performs the mTLS handshake and probes FatLine's status endpoint, so a bad cert or unreachable instance fails *here*, not on first use.
9. **Record & report** — persist the carrier (endpoint, server name, type) and `fatline_deployed: true` into `metadata.yaml`; print the connection status.

### Command surface

```
farcast connect <instance> [flags]
```

| Flag | Meaning |
|---|---|
| `<instance>` | The instance to connect to (positional, required). |
| `--carrier <nlb>` | Data-plane carrier (default `nlb`, the public mTLS load balancer). The seam reserves `cp-forward` (control-plane fallback) for a later phase. |
| `--status` | Don't bootstrap or provision anything — just dial the already-bound carrier and report status (re-connect / health probe). Does **no registry work at all**. Fails if the instance was never connected. |
| `--yes`, `-y` | Skip the LB-cost confirmation **and** the build-and-push confirmation; required when non-interactive. |
| `--fatline-image <ref>` | FatLine container image to deploy. Defaults to the **instance's own registry** — `<prefix>/system/fatline:<version>`, which `connect` builds and pushes when it is not there yet. An explicit ref is deployed exactly as given, with no preflight and no registry access. First connect only: refused on a reconnect, which deploys nothing — use `farcast redeploy --fatline-image` to change what a connected instance runs. |
| `--source <dir>` | The farcast checkout to build FatLine's image from (default: auto-detected by walking up from the working directory). Naming it explicitly is a request to *build*: the image is compiled and pushed without a preflight, even if the reference already resolves ([why](#why---source-forces-a-rebuild)). Likewise refused on a reconnect (`farcast redeploy --source` is what rebuilds for a connected instance). |

Global flags (`--output`, `--verbose`, `--config`) apply. With `--output json` the command prints one JSON result and never prompts (so the cost gate must be pre-answered with `--yes`).

### Connection status reporting

`connect` (and `connect --status`) renders FatLine's `ConnStatus` — the boundary's live health, fetched over the tunnel itself:

Human:

```
✓ connected to "prod"
  carrier:     public mTLS NLB  34.120.0.5:8443
  identity:    farcast://prod/operator
  active:      0 streams
  allowlist:   0 hosts (deny-by-default)
  registry:    us-central1-docker.pkg.dev/<project>/farcast-prod
  image:       us-central1-docker.pkg.dev/<project>/farcast-prod/system/fatline@sha256:…
  cost:        load balancer ~$18/mo + registry ~$0/mo (limit: USD 50/monthly)
```

The `image` line is a **digest, not a tag** — it is the reference the cluster was actually told to run. Both it and `registry` are omitted for an instance that has neither recorded.

JSON (`--output json`):

```json
{"name":"prod","connected":true,"carrier":"nlb","endpoint":"34.120.0.5:8443","identity":"farcast://prod/operator","active":0,"registry":"us-central1-docker.pkg.dev/<project>/farcast-prod","image":"…/farcast-prod/system/fatline@sha256:…"}
```

### "All subsequent commands route through FatLine"

The CLI is stateless between invocations — there is no daemon. `connect` makes routing possible by **persisting the operator's identity and the carrier endpoint**; each later command (`run`/`ps`/`logs`/`costs`, phase 4.3) re-loads them and re-dials the tunnel for its duration via the same `fatline/tunnel` library, using `Conn.HTTPClient()` for its instance API calls. So 2.3 delivers the mechanism and the status surface; the commands that consume it land in 4.3. (With the public-NLB carrier the endpoint is a stable IP, so each re-dial is direct and stateless — no port-forward to keep alive.)

### Local identity store

`connect` extends the [instance store](#configuration--credential-storage) with the data-plane mTLS material, under the same `0700`/`0600` rules:

```
instances/<instance-name>/
├── metadata.yaml        (0600)  + carrier {type, endpoint, server_name}, fatline_deployed
│                                + registry {prefix, repository, location, puller,
│                                  fatline_digest} — the instance's own image registry
│                                  and the digest-pinned ref last deployed from it
├── credentials.yaml     (0600)  (unchanged — cloud credential)
├── kubeconfig.yaml      (0600)  (unchanged — control-plane access)
└── fatline/             (0700)  data-plane mTLS identity
    ├── ca.crt           (0600)  per-instance CA certificate
    ├── ca.key           (0600)  per-instance CA private key — the crown jewel, NEVER pushed to the cluster
    ├── client.crt       (0600)  operator client leaf (SAN farcast://<instance>/operator)
    ├── client.key       (0600)
    ├── server.crt       (0600)  FatLine server leaf (SAN <instance>.fatline.farcast) — pushed to the cluster Secret
    └── server.key       (0600)
```

The CA key's locality is the security crux: it is what keeps the data-plane trust root sovereign and off the cloud. The metadata/credentials/identity split means a status-only command never opens the CA key.

### Supporting modules

`connect` is an orchestrator; the reusable capability lives in five small, testable seams:

- **[`fatline/identity`](../../fatline/README.md)** *(new, public)* — the operator-side mint/load surface wrapping FatLine's `internal/crypto` (which stays internal): mint a per-instance CA, issue the operator client + FatLine server leaves, and assemble a `tunnel.ClientIdentity` from stored PEMs. This is what lets the CLI handle mTLS material without importing FatLine internals.
- **[`fatline/deploy`](../../fatline/README.md)** *(new, public)* — renders FatLine's own Kubernetes workload (Namespace, Secret, Deployment, Service) as an Autopilot-compliant apply stream. FatLine owns the shape of how it is deployed; this is the one-off precursor to Planck's general manifest translator (4.2).
- **`farsight/cli/internal/cluster`** *(new)* — a minimal **kubectl-subprocess** wrapper (apply via stdin, await rollout, read the Service external IP) over the stored kubeconfig. The exec boundary is injectable, so the orchestration is unit-tested with a fake runner; the real cloud path is integration-gated.
- **`farsight/cli/internal/oci`** *(new, 2.3 + [ADR 0007](../../docs/adr/0007-instance-owned-image-registry.md))* — a standard-library-only **OCI distribution client**: reference parsing, per-host authentication (anonymous, Basic, and the Bearer-challenge token dance), pull with index platform selection, deterministic tar layer building, layer append, and push. It knows nothing about FarCast — it is pure wire protocol — and it treats registries as untrusted transport: every manifest and every blob is verified against the digest that addressed it, credentials are never logged, never put in a URL, and never sent to a non-loopback host over plaintext HTTP.
- **`farsight/cli/internal/image`** *(new, 2.3 + [ADR 0007](../../docs/adr/0007-instance-owned-image-registry.md))* — the FarCast-shaped decisions above that protocol: which base (`BaseImage`, the digest-pinned distroless), which platform (linux/amd64), which paths. `Builder.Compile` is the injectable subprocess seam over `go build`; `BuildAndPush` compiles, layers, appends and pushes, returning a digest-pinned reference; `Resolve` is the preflight (`ErrNotFound` is the miss that means "offer to build"); `FindSource` locates the checkout.

### Testing

Mirrors `install`/`release` and [Planck's strategy](../../planck/README.md): the orchestration — identity mint/persist, the registry ensure, the image preflight and the build-or-decline decision, manifest rendering, the cost gate, the kubectl call sequence, status rendering, the record-before-provision ordering — is unit-tested against a **fake cluster runner**, a **fake registry provider**, a **fake image builder** and an **in-process mTLS FatLine** (the same `httptest`-over-mTLS harness FatLine's `tunnel` e2e test uses), with `t.TempDir()` state and asserted `0600` perms — **no real cloud, no LB cost, nothing compiled, no registry contacted**. The end-to-end public-NLB path sits behind `//go:build integration` and is **never in CI** (cost pillar), exactly like Planck's create/delete tests.

The two image packages are tested a layer down. `oci` runs against an `httptest` registry: the Bearer and Basic challenge flows, the refusal to offer a credential before being challenged or to fetch a token over plaintext, index platform selection, layer determinism, a cross-registry round trip, and the rejection of a tampered blob or a manifest that breaks its own pin. Wire-protocol correctness is the price of owning this code, so a pull, a tag resolve and a miss are also exercised against the **real gcr.io** behind `//go:build integration` — that one costs nothing, but it is opt-in like every other network-touching test here. `image` drives `BuildAndPush` end to end with an injected compiler, asserting among other things that the target registry's credentials are never offered to the public base's host.

---

## `farcast redeploy` — replace a connected instance's FatLine workload (Phase 2.3)

`farcast redeploy <instance>` re-renders and re-applies FatLine's workload for an instance that is **already connected**. It is how a fix to the network boundary reaches a running instance — a new image, a changed manifest, or both — without touching the carrier, the mTLS identity, or anything else the instance is.

It exists because the alternative was destroying the instance. The first live Phase 2 Part B deploy crash-looped: FatLine's mTLS `Secret` was mounted root-only and the non-root container could not read its own key (fixed in `e4c066e`). Rolling that fix out took hand-editing `fatline_deployed: false` into the instance's `metadata.yaml` to trick `connect` into bootstrapping again, because `connect` skips its bootstrap entirely once the instance is deployed and bound. The only supported alternative was `release` plus a reinstall — destroying an entire instance to patch the thing guarding it. That is the wrong price to attach to a security fix, because it is the price that makes an operator postpone one.

The division of labour is the point: **`connect` opens the tunnel, `redeploy` changes what runs inside it.** Redeploy never provisions a carrier and never mints a CA, so nothing it does is billable-new and the instance's public endpoint and trust root are exactly what they were.

### Flow

1. **Resolve the instance** — load `metadata.yaml` (its `credentials.yaml` and `kubeconfig.yaml` are read by the steps below that need them). An instance being released is refused, as it is by `connect`. An instance that was never connected — no `fatline_deployed`, no carrier — is refused too, directed at `farcast connect <instance>`: redeploy replaces a workload, it does not create one, and inventing a carrier here would duplicate connect's bootstrap (billable half included) behind a verb that promises not to.
2. **Load the data-plane identity** — the per-instance CA certificate and FatLine's server leaf, **loaded, never minted**. FatLine is already running and already trusts a CA; a fresh one would only produce certificates it must reject, and would overwrite the record of what it actually trusts. Missing material is therefore reported as unrecoverable (the same message `connect` gives a deployed instance), never replaced.
3. **Ensure the instance's registry** — the same idempotent ensure `install` and `connect` run ([above](#the-instances-registry)). It comes first because the image may have to be built and pushed into it. A failure stops only a redeploy that needs it: with an explicit `--fatline-image` nothing is looked up or pushed, so the ensure degrades to a stderr warning.
4. **Resolve FatLine's image** — *identical* to connect's resolution, from the same code: default to `<prefix>/system/fatline:<version>` in the instance's own registry, preflight it, offer to compile and push it from a farcast checkout when it is missing, and deploy pinned by digest; an explicit `--fatline-image` is deployed exactly as given ([above](#where-fatlines-image-comes-from-adr-0007)), and an explicit `--source` skips the preflight and rebuilds ([below](#why---source-forces-a-rebuild)). The two commands share one implementation rather than two copies, because that path is the supply chain for the instance's network boundary and a second, subtly different copy of those rules is how an unpinned deploy eventually arrives.
5. **Confirm the change** — show what will change and ask ([below](#the-consent-gate-and-why-there-is-no-cost-gate)). `--yes` skips it; non-interactive without `--yes` is a usage error.
6. **Render & apply** — render the workload for the carrier the instance is **already bound to**, never a default, and apply it through the same kubectl seam `connect` uses. Re-rendering a bound instance with a different Service type would tear down the point of presence the operator reaches it through and, for the load balancer, replace a standing billable resource and its public IP as a side effect of a workload change nobody asked to be one.
7. **Wait, then record** — wait for the rollout, and write the deployed digest into `metadata.yaml` **only once that rollout has succeeded**. This is the one ordering redeploy deliberately inverts from `connect`, which records before waiting because it is racing to record a billable load balancer; nothing here becomes billable. FatLine runs a single replica under the default strategy, so a rollout that never goes ready leaves the *previous* image serving traffic — recording early would name an image that never served a byte, on the exact path this command exists for. A failed rollout leaves the record alone and — when local state records what was there — names the image still serving and the `kubectl describe pod` that explains why the new one is not.
8. **Report** — old digest → new digest, the fact that the digest did not change, or just the image when local state had nothing to compare against.

### Command surface

```
farcast redeploy <instance> [flags]
```

| Flag | Meaning |
|---|---|
| `<instance>` | The instance to redeploy (positional, required). Must already be connected. |
| `--yes`, `-y` | Skip the change confirmation **and** the build-and-push confirmation; required when non-interactive. |
| `--fatline-image <ref>` | FatLine container image to deploy. Defaults to the instance's own registry — `<prefix>/system/fatline:<version>` — which redeploy builds and pushes when it is not there yet. An explicit ref is deployed exactly as given, with no preflight and no registry lookup. |
| `--source <dir>` | The farcast checkout to build FatLine's image from (default: auto-detected by walking up from the working directory). Naming it explicitly **forces** the rebuild-and-push ([below](#why---source-forces-a-rebuild)). |

Global flags (`--output`, `--verbose`, `--config`) apply. With `--output json` the command prints one JSON result and never prompts (so the change gate must be pre-answered with `--yes`). There is deliberately **no `--carrier` flag**: the carrier is whatever the instance is already bound to, and changing it is `connect`'s business, not a workload update's.

### Why `--source` forces a rebuild

With neither image flag, redeploy preflights the instance-registry reference and deploys the digest it finds there, building only if the image is absent — connect's behaviour exactly. `--source <dir>` overrides that: it is read as a request to *build*, so the checkout is compiled and pushed with no preflight at all.

It has to be, because the default tag is derived from the **CLI's** version, and that does not move when FatLine's own code does. Against a connected instance the preflight therefore always hits the image already sitting in the registry. Without the force, an operator who had just patched a FatLine bug would redeploy their own stale image and be told it worked — on precisely the class of fix this command exists to ship.

That makes the two image flags opposed intents — "deploy exactly this" against "build from here and deploy that" — so passing both is a usage error rather than a silent choice between them.

### The consent gate, and why there is no cost gate

Redeploy asks before it applies, and what it asks about is the *change*, not the money:

```
this replaces the image "prod" runs: …/system/fatline@sha256:9f2c… → …/system/fatline@sha256:41ab….
Re-apply FatLine's workload now? [y/N]:
```

There is **no ~$18/mo confirmation** here, and that is a deliberate protection of the gate that matters. The load balancer already exists and a redeploy makes nothing new billable, so re-asking the cost question would attach the cost prompt to an operation whose honest answer is always "nothing changes" — which is how a gate that guards real money ([ADR 0005](../../docs/adr/0005-fatline-data-plane-ingress.md)) gets trained into a reflex. One prompt, one meaning.

Building the image from source keeps its own separate confirmation (the one `connect` uses), and it is asked *first*, because a push changes nothing about what the instance is running. Only the apply does — so the operator is asked about the apply with the resulting digest in hand rather than in the abstract. `--yes` covers both.

**An unchanged digest still re-applies.** The failure this command was built for was a workload-*template* defect with the image byte-identical, so a redeploy that no-opped on a matching digest would be useless for exactly the case it exists for. It says so rather than pretending something moved:

```
"prod" already runs …/system/fatline@sha256:41ab… — image unchanged; re-applying the workload template.
Re-apply FatLine's workload now? [y/N]:
```

### Output

Human:

```
✓ redeployed FatLine to "prod"
  carrier:     public mTLS NLB  34.120.0.5:8443 (unchanged)
  registry:    us-central1-docker.pkg.dev/<project>/farcast-prod
  previous:    us-central1-docker.pkg.dev/<project>/farcast-prod/system/fatline@sha256:9f2c…
  image:       us-central1-docker.pkg.dev/<project>/farcast-prod/system/fatline@sha256:41ab…
  rollout:     complete
```

The image lines report exactly as much as local state supports — three cases, never one dressed as another:

- **The digest moved** → `previous:` then `image:`, as above.
- **Nothing recorded to compare against** → `image:` alone, with no `previous:` line and no "unchanged" claim: local state does not know what the instance was running, so calling it unchanged would be a guess dressed as a fact.
- **The digest did not move** → the two lines collapse into one that says what actually happened:

```
  image:       us-central1-docker.pkg.dev/<project>/farcast-prod/system/fatline@sha256:41ab… (unchanged; the workload template was re-applied)
```

`rollout: complete` is a fact the command waited for, not a hope: it is printed only after the Deployment reports its new Pods ready, so a crash-looping FatLine fails the command instead of being reported as a success — and, because the digest is recorded only after that wait, local state keeps naming the image that is still serving.

JSON (`--output json`):

```json
{"name":"prod","carrier":"nlb","endpoint":"34.120.0.5:8443","registry":"us-central1-docker.pkg.dev/<project>/farcast-prod","previous_image":"…/system/fatline@sha256:9f2c…","image":"…/system/fatline@sha256:41ab…","image_changed":true,"status":"redeployed"}
```

`previous_image` is omitted for an instance whose local state does not record what it was running — the redeploy still proceeds, and says so. `image_changed` is `false` both there and when the digest did not move, so it answers "did the image move?" and never stands in for "did anything happen?" — the workload was re-applied either way.

---

## `farcast storage` — the instance's encrypted disk (Phase 3.3)

`farcast storage` is how an operator puts data into an instance and gets it back out. Everything it writes is encrypted before the cloud sees it and stored under an opaque name, by [DataSphere](../../datasphere/README.md) — the CLI does not get a say in that, because the encrypting `Store` is the only path there is.

Two things make this group unlike the rest of the CLI. It is the first command family that touches **data that derives from nothing** — a cluster is re-provisionable and every registry image rebuilds from Git, but a deleted object is gone, and soft delete is disabled on the bucket by design. And it depends on a local file, `keys.yaml`, whose loss is the permanent loss of everything in the bucket. Both facts shape every decision below.

**It needs no cluster and no tunnel.** Storage runs entirely on the operator's machine: the recorded bucket, the stored cloud credentials, and the local keyring. `farcast storage` therefore works on an instance that has never been `connect`ed, and it is why Phase 3.3 is not blocked on 3.2's in-cluster key-delivery ADR.

### Addressing: `<instance>:<key>`, scp-style

```
prod:app/reports/q3.csv     one object
prod:app/reports/           a /-aligned prefix
prod:                       the whole bucket
./q3.csv    -               a local file; stdin/stdout
```

An operand is **remote** iff its first `:` falls before any `/`, the text before it is a valid instance name, and that instance exists in local state. Everything else is local. If both readings are genuinely available — an instance `prod` exists *and* a local file named `prod:x` exists — it is a **usage error** telling the operator to write `./prod:x`. Guessing here either uploads the wrong bytes or overwrites the wrong file, and neither is recoverable.

### The verb tree

Two levels for the data verbs, as [Decisions](#decisions) 1 reserved; **three only for `key`**.

```
farcast storage ls    <instance>[:prefix]   [-l|--long] [--tokens]
farcast storage cp    <src> <dst>           [-r] [--force|--skip-existing]
farcast storage rm    <instance>:<key>…     [-r] [-y]
farcast storage usage <instance>

farcast storage key list   <instance>
farcast storage key export <instance> --out <path> --passphrase-file <path>
farcast storage key import <instance> <file>       --passphrase-file <path>
farcast storage key rotate <instance>       [-y]
farcast storage key rekey  <instance>       [--dry-run] [-y]
```

`key` earns the third level because **the noun changes**: `ls`/`cp`/`rm`/`usage` address objects in a bucket; `export`/`import`/`rotate`/`rekey` address the file whose loss destroys all of them. Flattening them would put a keyring verb in the same tab-completion neighbourhood as `storage rm`, and `storage rotate` reads as though it rotates data. The cost is one dispatcher instantiated twice.

No command in the group takes cloud flags. Provider, project, region and credentials all come from the recorded instance, exactly as `release`, `connect` and `redeploy` take none, and there is no `--bucket`: the record is the sole authority.

### `cp`, and the two ways it can lose data

`cp` streams in both directions through DataSphere's v2 chunked format, so file size is not a consideration in either direction. Exactly one operand may be remote; two remote or two local operands are a usage error rather than a guess.

- **It never overwrites silently**, in either direction. An existing destination — a local file or a remote key — stops the copy and names what is there; `--force` replaces, `--skip-existing` skips. This is stricter than `cp(1)` on purpose: the remote side has no undelete.
- **A failed download leaves nothing at the destination.** Downloads land in a temporary file alongside the target and are renamed only after the final frame authenticates. This is load-bearing rather than tidy: v2 authenticates per frame, so a truncated or tampered object is detected only when the reader reaches the damage, and a partial file that looks plausible is worse than no file.
- **Local files it creates are `0600`**, matching the credential store's discipline — decrypted plaintext is not something to leave world-readable.
- **A recursive download must not be a path-traversal primitive.** A logical key is any non-normalized UTF-8 byte string and may contain `..`, a leading `/`, or bytes illegal in the local filesystem — and, after 3.2, may have been written by an application inside the instance. `cp -r prod: ./out` refuses any key that does not map to a safe relative path under the destination, names it, and continues with the rest. It never mangles silently and never writes outside the destination root.

### `rm`, and `release`'s new gate

`rm` on an exact key is unceremonious. `rm -r` on a prefix shows what will go and requires confirmation, and says plainly that deletes are immediate and final because soft delete is disabled on the bucket.

`farcast release` gains one flag, `--delete-data`, and one gate:

**`release` refuses while the instance bucket still holds data.** The gate is **data-triggered, not configuration-triggered** — a bucket with zero objects produces no gate, no flag and no extra prompt, so a test instance that installed, connected and released without writing anything behaves exactly as it does today. With data present, `release` names the object count and stored bytes and stops, pointing at `storage cp`; `--delete-data` is what proceeds.

`--delete-data` is a **scope** flag, not a consent flag. `--yes` says "don't ask me" and never implies it: the confirmation an operator clicks through daily must not be able to destroy the one thing that derives from nothing.

The count comes from `datasphere.BucketUsage` over the `Provider` — **never through the `Store`, and with no keyring**. An operator who has lost `keys.yaml` still needs to be able to stop paying, and a gate built on what the keyring can *name* would report an empty bucket while billable ciphertext sat in it.

Ordering inside `release` follows the shipped discipline, with the data last: probe and gate **before anything is destroyed**, then cluster → registry → bucket → local state. A failure part-way leaves the data intact and the record in place, so a re-run converges.

### The keyring, and when it is minted

The keyring lives at `<instance>/datasphere/keys.yaml` (`0700` directory, `0600` file), beside the mTLS CA key — the two crown jewels in one directory, so the backup gesture is one gesture.

It is minted at **first storage use**, not at `install`: the install flow is shipped and validated, and an instance that never stores anything never needs one. The mint is a deliberate step rather than a side effect, and it prints DataSphere's mandated sentence verbatim — *loss of `keys.yaml` is permanent, unrecoverable loss of all stored data — FarCast keeps no copy anywhere, by design* — naming the instance directory as the thing to back up.

- **`key export`** writes a passphrase-armored copy (stdlib `crypto/pbkdf2` + AES-256-GCM, versioned format). The passphrase is read from a terminal, never a flag.
- **`key import` is merge-only** — it adds entries the live keyring lacks and never overwrites or drops one, refusing outright if an id appears on both sides with different material. This is `datasphere.Keyring.Merge`'s semantics surfaced as a command, and it is a security control: a blob's key ID is cloud-writable, so a tampering cloud can make any object demand a key the keyring lacks, and the natural overwrite-restore would destroy every key added since the backup. The output says `removed: nothing — import is merge-only, by design`, in every mode, to teach the invariant to whoever is about to look for a `--force` that does not exist.
- **`key rotate`** prepends a new KEK. Its output must state the scope in DataSphere's mandated terms: everything the cloud already saw **stays exposed** to whoever captured it, future data is protected once the cloud credentials are rotated too, and names stay exposed until name-key rotation exists. Rotation is nonce hygiene and keyring retirement, **not** compromise recovery, and an operator who believes otherwise has been actively misled.
- **`key rekey`** sweeps objects, rewriting each header's key ID and wrap fields under the active KEK without touching a body — possible because the data AAD excludes the key ID. It is resumable, reports a cursor when interrupted, and every object stays readable throughout because old keys remain in `keys.yaml`. It is also the most expensive command in the CLI: a full read and write of every object. `--dry-run` prints the cost first.

### `usage`, and surfacing spend honestly

Object count and stored bytes cannot tell an operator what storage costs, so `usage` reports the object count, the stored bytes the provider actually bills, the window over which they were written, and a monthly estimate. It deliberately takes **no prefix**: scoping to one would mean mapping stored names back to logical ones, which needs the keyring — and the whole point of `usage` is that it still works for the operator who has lost theirs. A silently ignored operand would be worse than an unsupported one, so a prefix is refused with that reason.

Two further figures are specified but **not yet implemented**, and both are worth having: the **envelope overhead** FarCast itself adds (~131 bytes plus a padded sealed name per object — a real, permanent, billed cost of the privacy pillar that no other tool can compute), and the report's own cost in list operations.

A third — **incomplete uploads** left by an interrupted `cp` — was specified and is **not implementable on GCS**, which the [Phase 3 validation run](../../docs/runbooks/phase-3-validation.md) settled. An unfinalized resumable session is invisible to a listing, reports zero bytes, exposes no enumeration endpoint (GCS has no equivalent of S3's `ListMultipartUploads`), and does not block bucket deletion. The failure it was meant to warn about — an interrupted upload stranding a teardown — cannot happen here, so the line has nothing to report and is dropped rather than left as a to-do.

Every figure carries its price basis: estimates are prefixed `~` and the output names the built-in price table's `as_of` date with a pointer to live pricing. A stale price presented as fact is worse than no price. `usage` also states its own cost in list operations, and runs without a keyring, so the operator who lost `keys.yaml` can still see what they are paying.

Cost is **surfaced, never gated**, per [ADR 0007](../../docs/adr/0007-instance-owned-image-registry.md) decision 8: gating cents trains an operator to click through the ~$18/mo carrier gate that guards real money.

### The `storage:` record, and the ensure path

`InstanceMetadata` gains a pointer-typed `storage:` block mirroring `registry:` — `bucket`, `location`, `provider`, `recorded_at`, `created_at` — so pre-3.3 metadata still loads and converges on the next storage command.

The bucket is ensured **lazily, at first storage use**, never at `install`: an empty bucket costs $0.00 and serves nothing, and the registry's defensive-ensure precedent already proves lazy convergence. The record is written **before** the create call, because the name's 32 bits of entropy exist nowhere else and the name is deliberately not re-derivable from the instance (its instance segment may have been truncated to fit GCS's 63-character cap).

The mint/record/retry loop belongs here, in the record-owning caller, never in the adapter — which mints nothing. On `ErrNotOwned` it mints a new suffix, updates the record and retries, bounded at 3 attempts. **With one hard exception:** if `created_at` is set, the bucket was ensured successfully before, and `ErrNotOwned` now means something changed rather than a name collision — auto-minting past it would abandon the operator's data under a name nothing points at any more. That case stops and asks the operator to look. Any other error keeps the record and fails, so a re-run converges.

---

## Diagnostics

Diagnostic logging is for the operator debugging the CLI, not for command output. It is plain text on **stderr**, gated by `--verbose`, built on the standard library's `log/slog` with a text handler. It is intentionally **not** the farcast SDK logger: the SDK is for in-instance applications and emitting JSON to stdout, which is the opposite of what an operator CLI wants. Keeping them separate also keeps the root module free of a dependency on the `sdk/go` module.

---

## Directory layout

```
farsight/cli/
├── README.md                  ← this file
├── cmd/
│   └── farcast/
│       └── main.go            ← thin entry point: os.Exit(cli.Main(os.Args, …))
└── internal/
    ├── cli/                   ← router, root command, global flags, signal handling
    │   ├── cli.go             ← Main/Run, global-flag parsing, dispatch
    │   ├── command.go         ← Command interface + registry
    │   ├── env.go             ← Env passed to commands (printer, config, streams)
    │   ├── print.go           ← fprintf/fprintln helpers for prompts and diagnostics
    │   ├── version.go         ← version command
    │   ├── help.go            ← help command
    │   ├── install.go         ← farcast install: provision via Planck, persist state  (1.3)
    │   ├── prompt.go          ← stdlib interactive prompts + TTY detection  (1.3)
    │   ├── release.go         ← farcast release: tear down via Planck, remove state  (1.4)
    │   ├── connect.go         ← farcast connect: mint identity, bootstrap FatLine, dial tunnel  (2.3)
    │   ├── fatline.go         ← shared by connect + redeploy: image resolution, build gate,
    │   │                        registry ensure, workload render  (2.3)
    │   ├── redeploy.go        ← farcast redeploy: re-render and re-apply FatLine's workload  (2.3)
    │   ├── storage.go         ← farcast storage: ls, cp, rm, usage; the <instance>:<key> locator  (3.3)
    │   └── storagekey.go      ← farcast storage key: export, import, rotate, rekey  (3.3)
    ├── output/                ← human/JSON printer, error formatting, exit codes
    │   └── output.go
    ├── cluster/               ← kubectl-subprocess wrapper: apply, await rollout, read LB IP  (2.3)
    │   └── cluster.go
    ├── image/                 ← FarCast's own container images, no engine  (2.3, ADR 0007)
    │   ├── image.go           ← Builder/Options, BuildAndPush, Resolve, pinned BaseImage
    │   ├── compile.go         ← go build for linux/amd64 — the one subprocess, injectable
    │   └── source.go          ← FindSource: locate the farcast checkout to build from
    ├── oci/                   ← stdlib OCI distribution client  (2.3, ADR 0007)
    │   ├── oci.go             ← reference parsing, media types, manifest/config/layer types
    │   ├── client.go          ← per-host auth: anonymous, Basic, Bearer challenge
    │   ├── pull.go            ← Resolve + Pull, index platform selection, digest verification
    │   ├── layer.go           ← deterministic tar layer building, AppendLayer
    │   └── push.go            ← blob + manifest upload, returns the digest a deploy pins
    ├── config/                ← local config + credential store, permission enforcement
    │   ├── config.go          ← config dir resolution, perms, config.yaml load/save
    │   └── instance.go        ← per-instance metadata / credentials / kubeconfig / mTLS store  (1.3, +2.3)
    └── buildinfo/             ← Version/Commit/Date (ldflags), ReadBuildInfo fallback
        └── buildinfo.go
```

---

## Internal architecture

A command is a small, self-contained unit. The router parses global flags, finds the command, and hands it an `Env`:

```go
// Command is one farcast subcommand.
type Command interface {
	Name() string                 // e.g. "version"
	Synopsis() string             // one line, shown in `help`
	Usage() string                // full usage, shown in `help <command>`
	SetFlags(fs *flag.FlagSet)    // register command-specific flags
	Run(ctx context.Context, env *Env, args []string) error
}

// Env is the ambient context handed to every command.
type Env struct {
	Out, Err io.Writer       // stdout, stderr
	In       io.Reader       // stdin (for interactive commands later)
	Printer  *output.Printer // renders results per the --output mode
	Config   *config.Config  // loaded local configuration
	Verbose  bool
	Log      *slog.Logger    // diagnostics → Err
}
```

- **Routing** (`cli.go`): split global flags from the command and its flags, look the command up in the registry, dispatch. Unknown command or bad usage → exit `2` with a help hint. A root `context.Context` is cancelled on `SIGINT`/`SIGTERM` so long-running commands (logs, run) can shut down cleanly later.
- **Output** (`output.go`): a `Printer` with a `Mode` (human/JSON) and the stdout writer. Commands return a typed result value; in JSON mode the printer marshals it, in human mode it calls the value's `Human(io.Writer)` renderer. One place owns formatting, so every command is automatically scriptable.
- **Config** (`config.go`): path resolution, `0700`/`0600` enforcement, typed load/save.
- **buildinfo** (`buildinfo.go`): `Version`/`Commit`/`Date` set via `-ldflags -X`, with a `runtime/debug.ReadBuildInfo` fallback.

`main.go` stays a thin shell: build the `Env`, call `cli.Main`, `os.Exit` with the returned code.

---

## Testing & guardrails

Per [AGENTS.md](../../AGENTS.md) and [ADR 0002](../../docs/adr/0002-backend-language-strategy.md), the CLI is held to the same bar as every Go module: `go test -race`, `go vet`, and `golangci-lint`, with tests beside the code.

- **Routing** — known command dispatches; unknown command and bad flags exit `2`; `--help`/`-h` at both levels.
- **`version`** — human and JSON output, with `buildinfo` values injected.
- **Output** — human vs JSON rendering; error formatting in both modes; exit codes.
- **Config** — path resolution (flag/env/default precedence) and permission enforcement, using `t.TempDir()`; a too-permissive directory is rejected or repaired.
- **`install`** — flag/prompt precedence; a missing or non-positive `--cost-limit` is rejected (the headline guarantee); unattended mode with a missing required flag exits `2`; the record-before-create ordering and `running`/`unreachable`/`error` state transitions are exercised against a **fake `planck.Provider`** (registered via `planck.Register`), with `t.TempDir()` for state and asserted `0700`/`0600` perms — no real cloud calls.
- **`release`** — loads the recorded instance and tears it down via the fake `planck.Provider`, then removes local state; covers the delete-before-cleanup ordering (a `DeleteCluster` failure keeps the record), idempotent re-release of an already-gone cluster, the destructive confirmation (and `--yes`), and the unknown-instance error.
- **`redeploy`** — shares connect's fakes, and covers what is specific to it: the refusal for an instance that was never connected or is being released, an explicit image deployed as given, the preflight-hit and preflight-miss (build) paths, `--source` forcing a rebuild over a resolvable reference (and preflighting nothing), the two image flags together as a usage error, an unchanged digest that still re-renders and re-applies, the recorded digest being updated on success — and *not* updated when the rollout fails, so the record keeps naming the image still serving — the consent gate as a usage error when non-interactive without `--yes`, one JSON result with no prompt, and, guarding the decision that matters most, that it never mints an mTLS identity and never waits for an external IP, so the trust root and the carrier are provably untouched.
- Commands are tested by calling `Run` with buffers for `Out`/`Err` — no process spawning.

---

## Decisions

The choices made for the scaffold, with rationale:

1. **CLI framework: standard library (not Cobra).** The CLI holds cloud admin credentials, so minimizing the dependency/supply-chain surface is a security decision, consistent with the SDK's stdlib-only stance and FarCast's first pillar. The command tree is shallow enough (mostly `farcast <verb>`, with `storage` as the only two-level case) that Cobra's machinery isn't required. Trade-off: help rendering is hand-written and there is no shell completion yet. If the command tree grows unwieldy, adopting Cobra later is mechanical.
2. **Config format: YAML.** Reuses the already-vendored `goccy/go-yaml` (no new dependency) and keeps config operator-readable and consistent with the manifest.
3. **Single module.** The stray per-module `go.mod` files were removed; the CLI lives in the root module per the repository convention, and only `sdk/go` remains a separate module.
4. **The cost limit is mandatory, enforced at install (1.3).** No default, no "unlimited", no skip — recorded into instance metadata at creation, so "no instance without a limit" is structural. Enforcement is TechnoCore's (4.1); `install` owns capture.
5. **Record before create (1.3).** Local state is written before `CreateCluster`, so an interruption never leaves an untracked, billable cluster — a cost-pillar safety property, at the cost of a possible orphaned *record* (which `release` cleans up).
6. **Dependency-free interaction & health check (1.3).** Prompting and TTY detection use the standard library (`os.ModeCharDevice`), not a prompt library; the health check uses the GKE management API plus the IAM-gated DNS endpoint ([ADR 0004](../../docs/adr/0004-private-control-plane.md)), not a vendored Kubernetes client or a raw public-IP dial — consistent with principle 1, since every dependency is attack surface against stored credentials.
7. **Release initiates the cloud delete before removing local state (1.4).** The inverse of record-before-create: `release` issues the cluster delete first and removes the local record only after the cloud accepts it, so a failed delete call never strands a billable cluster with no way to find it again (deletion itself completes asynchronously — see 1.4's known limitation). `DeleteCluster` is idempotent, so re-running `release` converges. The interactive confirmation requires **retyping the instance name** — stronger than install's y/N, because the operation is destructive; `--yes` skips it.
8. **`connect` deploys via kubectl subprocess, not a vendored Kubernetes client (2.3, [ADR 0006](../../docs/adr/0006-connect-bootstrap-kubectl.md)).** Consistent with principle 1 and decision 6: a vendored `client-go` is a large supply-chain surface against stored cloud credentials. The stored kubeconfig already drives the control plane through an **external auth-plugin exec** (`gke-gcloud-auth-plugin`), so shelling to `kubectl` for the one-off FatLine bootstrap adds an external-tool runtime dependency, not a Go dependency — the same line the kubeconfig already draws. The exec boundary is injectable, so orchestration is unit-tested without a cluster.
9. **`connect` mints the data-plane identity locally; the CA private key never leaves the machine (2.3).** The per-instance CA is the sovereign data-plane trust root ([ADR 0005](../../docs/adr/0005-fatline-data-plane-ingress.md)). `connect` mints it (and the operator client + FatLine server leaves) on first connect and pushes only the CA *certificate* + server leaf+key to the cluster Secret — never the CA key. The default carrier is the public mTLS-gated load balancer; its **standing ~$18/mo cost is confirmed against the cost limit** before provisioning (the carrier was ratified at 2.3 per [ADR 0005](../../docs/adr/0005-fatline-data-plane-ingress.md)).
10. **The instance owns its image registry, and the default image reference moves there (1.3/2.3, [ADR 0007](../../docs/adr/0007-instance-owned-image-registry.md)).** Kubernetes has exactly one way to put code into a Pod — the kubelet pulls from a registry — so the only open question is *whose*. A Sofmon-published default (`ghcr.io/sofmon/farcast/fatline:<version>`, the first 2.3 cut) made every instance's network boundary depend on a third party's artifact feed: a standing central dependency, and a supply-chain injection point aimed at FatLine itself. It is **deleted, not deprecated**. `install` creates `farcast-<instance>` in the instance's own project and region and grants that cluster's nodes a repository-scoped `roles/artifactregistry.reader`; `connect` re-ensures it and defaults `--fatline-image` to `<prefix>/system/fatline:<version>`; `release` deletes it. Deploys **pin the digest**, never the tag, so whoever can write the tag cannot redirect a running Deployment. The capability is an *optional* Planck interface (`RegistryProvider`) promising an image-path prefix plus a credential — not "one repository object" — so a second cloud can realize the same contract without a caller changing.
11. **The CLI builds and pushes FarCast's own images itself — no container engine, and no new dependency (2.3, [ADR 0007](../../docs/adr/0007-instance-owned-image-registry.md)).** FatLine's image is a static Go binary laid onto a digest-pinned distroless base, with no `RUN` steps to execute, so there is nothing an engine would do here that the CLI cannot: the compile shells to the **Go toolchain** (already a prerequisite for having a `farcast` binary at all, behind an injectable seam), and image assembly and push ride an OCI-distribution client the CLI owns, on `net/http` + `encoding/json` + `archive/tar` + `compress/gzip` + `crypto/sha256`. Requiring docker or podman would add an engine — on macOS, a Linux VM — to a tool whose premise is a small trusted base, and would write a push credential for the instance's registry into some other tool's credential store. Vendoring a registry library instead would have dragged seven to nine modules, docker's config and credential-helper packages among them, into the binary that holds the operator's cloud credentials and the instance's CA key. Both were measured and rejected: this feature ships with the vendored module count **unchanged at 31**. The cost lands as code FarCast owns — wire-protocol correctness is now ours to test, which is what the `oci` package's `httptest` suite and its opt-in run against a real registry are for.
12. **Changing a connected instance's FatLine is its own top-level command, and it is consent-gated, not cost-gated (2.3).** Three choices, taken together:
    - **A verb, not a flag.** `farcast redeploy <instance>` rather than `connect --redeploy`. It matches the `farcast <verb>` tree this CLI is built on (decision 1 — `storage` is the only two-level case) and keeps the two concerns legible: `connect` opens the tunnel, `redeploy` changes what runs inside it. A flag would have made the bootstrap-or-not branch inside `connect` a third mode of one command that already has two.
    - **It re-applies even when the image digest is unchanged.** The failure that motivated it was a workload-*template* defect — FatLine's mTLS `Secret` mounted root-only, unreadable by the non-root container — with the image byte-identical, so a redeploy that no-opped on a matching digest would be useless for exactly the case it exists for. When the digest has not moved it says so plainly rather than implying something did.
    - **A consent gate, not a cost gate.** The load balancer already exists and a redeploy makes nothing new billable, so re-prompting the ~$18/mo confirmation ([ADR 0005](../../docs/adr/0005-fatline-data-plane-ingress.md)) would attach the money prompt to an operation whose answer is always "nothing changes" — the way a gate that guards real money gets trained into a reflex. The prompt shows the change instead (old digest → new, or template-only); `--yes` waives it and a non-interactive session without `--yes` is a usage error, exactly as connect's gates behave.

    It never re-provisions the carrier and never re-mints the CA — those stay `connect`'s, because the carrier is the standing cost and the per-instance CA is the sovereign trust root, and neither should move because someone rolled a new image. The reason this is a command at all is that the alternative was `release` plus a reinstall: destroying an entire instance to patch its network boundary is the price that makes an operator postpone a security fix.

13. **Storage is operator-side, addressed scp-style, and its destructive edges are gated on data rather than configuration (3.3).** Four choices that hang together:
    - **It needs no cluster and no tunnel.** `farcast storage` runs against the recorded bucket with the stored cloud credentials and the local keyring, so it works on an instance that was never `connect`ed — and it is why 3.3 is not blocked on 3.2's in-cluster key-delivery ADR. Serving storage to in-cluster applications is a different problem with a different trust model.
    - **`<instance>:<key>`, with ambiguity as a usage error.** One addressing form for the whole group, in the shape operators already have from `scp`. When both readings of an operand are genuinely available it refuses rather than guesses, because a wrong guess either uploads the wrong bytes or overwrites the wrong file, and neither is recoverable.
    - **`key` is the CLI's only third level**, because the noun changes: the data verbs address objects in a bucket, the key verbs address the file whose loss destroys all of them. Flattening would seat a keyring verb next to `storage rm` in tab completion, and `storage rotate` would read as though it rotates data.
    - **`release` refuses while the bucket holds data, and `--delete-data` is a scope flag, not a consent flag.** Stored data is the first thing in FarCast that derives from nothing, and soft delete is off by design. The gate is **data-triggered**, so an empty bucket produces no gate at all and a test instance behaves exactly as it does today; and `--yes` never implies `--delete-data`, so the confirmation an operator clicks through daily cannot destroy the irreplaceable thing. The count comes from `datasphere.BucketUsage` over the `Provider` with **no keyring**, because an operator who has lost `keys.yaml` still needs to be able to stop paying — and a gate built on what the keyring can *name* would announce an empty bucket while billable ciphertext sat in it.

---

## Roadmap

1.1 builds the frame; later phases drop commands into it:

| Phase | Adds |
|---|---|
| **1.1** | Scaffold: routing, `version`, `help`, config handling, output formatting — **done** |
| 1.2 | [Planck](../../planck/README.md) provider adapter (GKE Autopilot) — done |
| **1.3** | `install`: interactive provisioning, mandatory cost limit, health check, instance store, the instance's own image registry ([ADR 0007](../../docs/adr/0007-instance-owned-image-registry.md)) — **done** |
| **1.4** | `release`: confirmed teardown via Planck, cluster *and* registry deleted before local cleanup, local removal — **done** |
| **2.3** | `connect`: mint the per-instance mTLS identity, put FatLine's image in the instance's registry — compiled and pushed by the CLI, no container engine ([ADR 0007](../../docs/adr/0007-instance-owned-image-registry.md)) — bootstrap-deploy FatLine pinned to that digest, provision its public mTLS carrier ([ADR 0005](../../docs/adr/0005-fatline-data-plane-ingress.md)), dial the tunnel, report status — the seam later commands route through — **done** |
| **2.3** | `redeploy`: re-render and re-apply FatLine's workload for a connected instance — a FatLine fix rolls out without destroying the instance; carrier and mTLS identity untouched — **done** |
| **3.3** (next) | `storage ls`/`cp`/`rm`/`usage` and `storage key export`/`import`/`rotate`/`rekey`; the keyring minted at first storage use; the `storage:` record and its mint/record/retry ensure path; bucket teardown wired into `release` behind a refuse-while-data-remains gate — **done**, validated live against GCP |
| 4.3 | `run`, `ps`, `logs`, `costs` |
| 6.2 | `chat` (terminal AI via [AllThing](../../allthing/README.md)) |

---

## References

- FarSight overview — [`../README.md`](../README.md)
- Project overview — [`../../README.md`](../../README.md)
- Agent/architecture context — [`../../AGENTS.md`](../../AGENTS.md)
- Execution plan — [`../../PLAN.md`](../../PLAN.md)
- FarCast SDK (the in-instance counterpart) — [`../../sdk/go/README.md`](../../sdk/go/README.md)
- Compute layer this drives — [`../../planck/README.md`](../../planck/README.md)
- Backend language strategy — [ADR 0002](../../docs/adr/0002-backend-language-strategy.md)
- GKE Autopilot decision — [ADR 0003](../../docs/adr/0003-gke-autopilot.md)
