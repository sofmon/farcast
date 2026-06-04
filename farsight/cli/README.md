# FarSight CLI — `farcast`

> The operator's command line for FarCast — install instances, run repositories, watch costs.

`farcast` is the command line face of [FarSight](../README.md), the FarCast UX layer. The same downloadable "farcast" app provides a GUI (the tiling browser), a server (UX composition inside an instance), and this CLI. The CLI is what operators and automation use to provision instances, deploy repositories, connect through FatLine, and monitor spending.

This document specifies two phases of the CLI. **Phase 1.1 — the CLI scaffold** (implemented): the command framework, the two commands that work from day one (`version`, `help`), local configuration handling, and the human/JSON output model. **Phase 1.3 — `farcast install`** (implemented): the first command that does real, billable work — interactively provisioning a cloud instance through Planck under a mandatory cost limit. The scaffold is what makes `install` a small, uniform addition.

> **Status.** **Phase 1.1 (scaffold) — implemented** (`go test -race`, `go vet`, and `golangci-lint` all clean): argument parsing and subcommand routing, `farcast version`, `farcast help`, local config file handling, and human + JSON output formatting. **Phase 1.3 (`farcast install`) — implemented** (`go test -race`, `go vet`, `golangci-lint` all clean): interactive provisioning through [Planck](../../planck/README.md), a mandatory cost limit, a management-API + DNS-endpoint health check, and record-before-create local persistence of instance metadata + credentials + kubeconfig. **Phase 1.4 (`farcast release`) — implemented** (`go test -race`, `go vet`, `golangci-lint` all clean): the destructive counterpart that tears the cluster down through Planck and removes local state, deleting the cloud resource before the record so a failure never strands billable infrastructure. Every other command is **registered but stubbed** — it appears in `help` and routes correctly, but exits non-zero with a "not yet implemented" message naming its [`PLAN.md`](../../PLAN.md) phase (`connect` → 2.3, `run`/`ps`/`logs`/`costs` → 4.3, and so on).

---

## What the CLI is — and isn't

**It is** the operator-side client. It runs on a laptop or in CI, holds the operator's cloud credentials locally, and drives instances. It is deliberately small, dependency-light, and secure by construction — it handles cloud admin credentials, so its supply-chain surface is a security concern, not just a packaging one.

**It is not** the [farcast SDK](../../sdk/go/README.md). The SDK is the syscall surface for applications running *inside* an instance; the CLI is the operator tool *outside* it. They do not share code and the CLI does not import the SDK. The two meet only on the wire — the CLI talks to a running instance through FatLine, in later phases.

**It is not** the GUI or the server. Those are separate FarSight components (Electron client, Phase 7; Go server, later). The CLI is a standalone Go binary now; the packaged "farcast" app will ship it alongside the GUI.

---

## Design principles

1. **Minimal dependencies, for security.** The CLI stores cloud admin credentials. Every third-party dependency is attack surface against those credentials, so the scaffold is built on the Go standard library (plus the already-vendored YAML library for config). See [Decisions](#decisions) for the CLI-framework choice this implies.
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

Minimum Go version: **1.26** (matches the repository toolchain).

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
| `connect` | ⏳ stub | Open a FatLine tunnel to an instance | 2.3 |
| `run` | ⏳ stub | Deploy a Git repository to an instance | 4.3 |
| `ps` | ⏳ stub | List running applications | 4.3 |
| `logs` | ⏳ stub | Stream an application's logs | 4.3 |
| `costs` | ⏳ stub | Show spending and distance to the cost limit | 4.3 |
| `storage` | ⏳ stub | Manage instance storage (`ls`, `cp`) | 3.3 |
| `chat` | ⏳ stub | Terminal AI chat through AllThing | 6.2 |

Stubbed commands route correctly and print a clear "not yet implemented (phase N)" message to stderr, exiting non-zero. This mirrors the SDK's `ErrNotImplemented` pattern: the whole surface is visible and navigable before the features land. `install` is the canonical verb for creating an instance — the CLI, the root README, and the [instance lifecycle](../../README.md#instance-lifecycle) (`install → bind → run → release`) all use it.

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
  version     Print version information
  help        Show help for farcast or a command
  install     Provision a new instance on a cloud provider   (not yet implemented — phase 1.3)
  connect     Open a FatLine tunnel to an instance           (not yet implemented — phase 2.3)
  run         Deploy a Git repository to an instance         (not yet implemented — phase 4.3)
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
        │                                      name + endpoint, status, cost limit, timestamps
        ├── credentials.yaml          (0600)  secret: cloud provider credential (SA key JSON)
        └── kubeconfig.yaml           (0600)  secret: cluster-access kubeconfig
```

**Security.** Credentials are secrets the cloud provider would love and an attacker would love more:

- The directory is created `0700` and credential files `0600`. On load, the CLI checks permissions and **refuses to read** (or repairs, with a stderr warning) anything group/world-readable.
- Non-secret metadata is kept separate from secret credentials, so a command that only needs metadata never opens the credential file.
- Plaintext-at-rest with `0600` matches the baseline of `aws`/`gcloud`. Hardening — OS keychain integration, or encrypting credentials with an operator passphrase — is noted for a later phase, consistent with FarCast's security-first posture.

**Format.** YAML, via the already-vendored `github.com/goccy/go-yaml` (the same library the manifest parser uses), keeping the dependency set unchanged and the files operator-readable. See [Decisions](#decisions).

**Phase 1.1 delivered** the `config` package — path resolution, `0700`/`0600` enforcement, and typed load/save of `config.yaml`. **Phase 1.3 adds the instance store** above — typed `metadata.yaml` / `credentials.yaml` / `kubeconfig.yaml` per instance, created and written by [`farcast install`](#farcast-install--provision-an-instance-phase-13) under the same permission rules, with a write-ordering that keeps a cluster from ever existing un-recorded (see that section).

---

## `farcast install` — provision an instance (Phase 1.3)

`farcast install` turns "a cloud account + a cost limit" into "a running FarCast instance." It is the first command that does real, billable work: it provisions a managed Kubernetes cluster through [Planck](../../planck/README.md) ([GKE Autopilot](../../docs/adr/0003-gke-autopilot.md) today), confirms the control plane is reachable, and records everything needed to operate and later tear the instance down — all under the strict local-state rules above.

It is **interactive by default** and **fully scriptable**: every prompt has a matching flag, so an operator can run it conversationally while automation runs it unattended.

### Flow

1. **Resolve inputs** from flags, then interactive prompts (human mode + TTY only) for whatever is missing. The mandatory cost limit is never defaulted.
2. **Select the provider** from those Planck has registered (`planck.Providers()`) — today just `gke`.
3. **Validate credentials** — `planck.Open` then `Validate`, before creating anything. Bad credentials fail here, fast and free.
4. **Confirm** — show a summary (provider, region, cluster name, cost limit) and require a yes. `--yes` skips it; it is required when non-interactive. This is the last step before money is spent.
5. **Record intent** — write `metadata.yaml` (status `provisioning`) and `credentials.yaml` *before* provisioning, so a cluster can never exist un-recorded.
6. **Provision** — `CreateCluster` blocks until the cluster is `RUNNING` (several minutes), with progress on stderr.
7. **Health check** — confirm the instance is alive via the GKE management API (`ClusterStatus == RUNNING`) plus the IAM-gated DNS endpoint; the control plane is private, so there is no public IP to dial ([ADR 0004](../../docs/adr/0004-private-control-plane.md)).
8. **Finalize** — update metadata to `running`, write `kubeconfig.yaml`, print the result.

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

### Health check

"Basic health check confirms the instance is alive" (PLAN 1.3). `CreateCluster` already waits for `RUNNING`; the health check re-confirms it independently and verifies the operator's own access path. Because FarCast clusters have a **private control plane with no public IP** ([ADR 0004](../../docs/adr/0004-private-control-plane.md)), there is no public endpoint to dial directly — the operator reaches the API server through GKE's IAM-gated **DNS-based endpoint**. So the check is two cheap, dependency-free steps: (1) re-query the GKE **management API** for `ClusterStatus == RUNNING` (configuration-independent, always reachable), and (2) optionally make one IAM-authenticated request to the DNS endpoint to confirm the operator can reach the control plane.

A deeper check — API-server `/healthz`, FarCast components, workloads — needs the in-cluster components and TechnoCore and lands with them. If it fails, the cluster is **kept** (it is billable, and the failure may be transient networking): the instance is recorded `unreachable`, the operator is warned, and the command exits non-zero so automation notices.

### Local state & atomicity

`install` fills in the instance store from [Configuration & credential storage](#configuration--credential-storage). Because an un-recorded cluster is an untracked bill, it writes the local record **before** provisioning:

1. **Reserve** `instances/<name>/`; refuse if it already exists — no silent clobber (release first, or pick another name).
2. **Write** `credentials.yaml` and `metadata.yaml` with `status: provisioning`.
3. **`CreateCluster`.** On error, leave the record (`status: provisioning`/`error`), direct the operator to `farcast release <name>`, exit 1.
4. **On success**, run the health check, then update `metadata.yaml` (`status: running` | `unreachable`, plus the endpoint) and write `kubeconfig.yaml`.

So an interruption at any point — failure, `Ctrl-C` (the root context is cancelled on `SIGINT`), crash — always leaves a local record carrying the deterministic cluster name and the credentials, which `farcast release` (1.4) can act on. The metadata/credentials split means `release`, `costs`, and `ps` read non-secret metadata without ever opening a secret file.

### Output

Human:

```
✓ instance "prod" installed
  provider:    gke (Autopilot)
  region:      us-central1
  cluster:     farcast-prod
  endpoint:    a1b2c3d4.us-central1.gke.goog
  cost limit:  USD 50 / month
  state:       running
  config:      ~/Library/Application Support/farcast/instances/prod
```

JSON (`--output json`) — a single object, the same data:

```json
{"name":"prod","provider":"gke","region":"us-central1","cluster":"farcast-prod","endpoint":"a1b2c3d4.us-central1.gke.goog","status":"running","cost_limit":{"amount":50,"currency":"USD","period":"monthly"},"config_path":"…/farcast/instances/prod"}
```

---

## `farcast release` — tear down an instance (Phase 1.4)

`farcast release <instance>` is the counterpart to [`install`](#farcast-install--provision-an-instance-phase-13): it destroys an instance's cloud resources and removes its local state. It is the one routinely **destructive** command, so it confirms deliberately and orders its steps so a failure never strands billable infrastructure.

### Flow

1. **Resolve the instance** — the positional `<instance>` argument; load its `metadata.yaml` and `credentials.yaml` from local state. An unknown instance is an error.
2. **Open the provider** — `planck.Open` with the *stored* provider, project, region, and credentials (the ones `install` recorded), so release needs no cloud flags beyond the name.
3. **Confirm** — show what will be destroyed and require confirmation (retype the instance name). `--yes` skips it; it is required when non-interactive. This is the point of no return.
4. **Mark deleting** — update `metadata.yaml` to `status: deleting`, so an interrupted release stays visible in local state.
5. **Destroy** — `DeleteCluster` blocks until the cloud confirms removal. Deleting an already-absent cluster succeeds (idempotent).
6. **Clean up local state** — remove the instance directory, only after the cloud resource is gone.

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

Destruction is irreversible, so the bar is higher than install's. Interactively, release prints a summary (instance, provider, region, cluster) and asks the operator to **retype the instance name** to confirm; anything else aborts. `--yes` skips the prompt (and is required when stdin is not a terminal). This mirrors the "type the name to delete" pattern operators expect from destructive tooling.

### Order & idempotency

The danger in teardown is the inverse of install's: removing the local record before the cloud cluster is gone would strand a **billable, now-unfindable** cluster. So release **deletes the cloud resource first, then removes local state**:

1. Set `status: deleting` in `metadata.yaml`.
2. `DeleteCluster`. On error, **keep** the local record (status stays `deleting`), report the failure, and exit non-zero — the operator can re-run `release`.
3. On success, remove the instance directory.

`DeleteCluster` is idempotent (an absent cluster is not an error), so a `release` re-run after a partial failure — cluster already deleted, local cleanup interrupted — simply succeeds and removes the lingering record. A `release` is therefore always safe to repeat, which is exactly what cleans up the orphaned *record* a failed `install` can leave behind (status `provisioning`/`error`).

### Local cleanup & output

On success the instance directory (`metadata.yaml`, `credentials.yaml`, `kubeconfig.yaml`) is removed wholesale. For phase 1.4 there is no persistent storage to consider — the cluster is empty compute; data lifecycle arrives with DataSphere (phase 3).

Human:

```
✓ instance "prod" released
  provider:    gke
  cluster:     farcast-prod (deleted)
  state:       removed
```

JSON (`--output json`):

```json
{"name":"prod","provider":"gke","cluster":"farcast-prod","status":"released"}
```

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
    │   ├── version.go         ← version command
    │   ├── help.go            ← help command
    │   ├── install.go         ← farcast install: provision via Planck, persist state  (1.3)
    │   ├── prompt.go          ← stdlib interactive prompts + TTY detection  (1.3)
    │   └── release.go         ← farcast release: tear down via Planck, remove state  (1.4)
    ├── output/                ← human/JSON printer, error formatting, exit codes
    │   └── output.go
    ├── config/                ← local config + credential store, permission enforcement
    │   ├── config.go          ← config dir resolution, perms, config.yaml load/save
    │   └── instance.go        ← per-instance metadata / credentials / kubeconfig store  (1.3)
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
7. **Release deletes the cloud resource before local state (1.4).** The inverse of record-before-create: `release` tears the cluster down first and only then removes the local record, so a failure never strands a billable cluster with no way to find it again. `DeleteCluster` is idempotent, so re-running `release` converges. The interactive confirmation requires **retyping the instance name** — stronger than install's y/N, because the operation is destructive; `--yes` skips it.

---

## Roadmap

1.1 builds the frame; later phases drop commands into it:

| Phase | Adds |
|---|---|
| **1.1** | Scaffold: routing, `version`, `help`, config handling, output formatting — **done** |
| 1.2 | [Planck](../../planck/README.md) provider adapter (GKE Autopilot) — done |
| **1.3** | `install`: interactive provisioning, mandatory cost limit, health check, instance store — **done** |
| **1.4** (this) | `release`: confirmed teardown via Planck, delete-before-cleanup, local removal — **done** |
| 2.3 | `connect` (route subsequent commands through [FatLine](../../fatline/README.md)) |
| 3.3 | `storage ls` / `storage cp` |
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
