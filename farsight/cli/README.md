# FarSight CLI — `farcast`

> The operator's command line for FarCast — install instances, run repositories, watch costs.

`farcast` is the command line face of [FarSight](../README.md), the FarCast UX layer. The same downloadable "farcast" app provides a GUI (the tiling browser), a server (UX composition inside an instance), and this CLI. The CLI is what operators and automation use to provision instances, deploy repositories, connect through FatLine, and monitor spending.

This document specifies **Phase 1.1 — the CLI scaffold**: the command framework, the two commands that work from day one (`version`, `help`), local configuration handling, and the human/JSON output model. No instance-touching command does real work yet; the structure is what 1.1 delivers.

> **Status.** Phase 1.1 (scaffold) — **implemented** (`go test -race`, `go vet`, and `golangci-lint` all clean). Delivered: argument parsing and subcommand routing, `farcast version`, `farcast help`, local config file handling, and human + JSON output formatting. Every other command is **registered but stubbed** — it appears in `help` and routes correctly, but exits non-zero with a "not yet implemented" message naming its [`PLAN.md`](../../PLAN.md) phase. The real commands land in later phases (`install` → 1.3, `connect` → 2.3, `run`/`ps`/`logs`/`costs` → 4.3, and so on).

---

## What the CLI is — and isn't

**It is** the operator-side client. It runs on a laptop or in CI, holds the operator's cloud credentials locally, and drives instances. It is deliberately small, dependency-light, and secure by construction — it handles cloud admin credentials, so its supply-chain surface is a security concern, not just a packaging one.

**It is not** the [farcast SDK](../../sdk/go/README.md). The SDK is the syscall surface for applications running *inside* an instance; the CLI is the operator tool *outside* it. They do not share code and the CLI does not import the SDK. The two meet only on the wire — the CLI talks to a running instance through FatLine, in later phases.

**It is not** the GUI or the server. Those are separate FarSight components (Electron client, Phase 7; Go server, later). The CLI is a standalone Go binary now; the packaged "farcast" app will ship it alongside the GUI.

---

## Design principles

1. **Minimal dependencies, for security.** The CLI stores cloud admin credentials. Every third-party dependency is attack surface against those credentials, so the scaffold is built on the Go standard library (plus the already-vendored YAML library for config). See [Open decisions](#open-decisions) for the CLI-framework choice this implies.
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
| `install` | ⏳ stub | Provision a new instance on a cloud provider (interactive) | 1.3 |
| `release` | ⏳ stub | Destroy an instance and clean up local state | 1.4 |
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
    └── <instance-name>/              (0700)
        ├── metadata.yaml             (0600)  cloud provider, region, cost limit, instance IDs
        └── credentials.yaml          (0600)  cloud credentials  ← secret
```

**Security.** Credentials are secrets the cloud provider would love and an attacker would love more:

- The directory is created `0700` and credential files `0600`. On load, the CLI checks permissions and **refuses to read** (or repairs, with a stderr warning) anything group/world-readable.
- Non-secret metadata is kept separate from secret credentials, so a command that only needs metadata never opens the credential file.
- Plaintext-at-rest with `0600` matches the baseline of `aws`/`gcloud`. Hardening — OS keychain integration, or encrypting credentials with an operator passphrase — is noted for a later phase, consistent with FarCast's security-first posture.

**Format.** YAML, via the already-vendored `github.com/goccy/go-yaml` (the same library the manifest parser uses), keeping the dependency set unchanged and the files operator-readable. See [Open decisions](#open-decisions).

**Phase 1.1 scope.** The scaffold delivers the `config` package — path resolution, directory/permission enforcement, and typed load/save of `config.yaml` — plus the placeholder layout above. The credential and instance schemas are filled in by `install` (1.3).

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
    │   └── help.go            ← help command
    ├── output/                ← human/JSON printer, error formatting, exit codes
    │   └── output.go
    ├── config/                ← local config + credential store, permission enforcement
    │   └── config.go
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
- Commands are tested by calling `Run` with buffers for `Out`/`Err` — no process spawning.

---

## Decisions

The choices made for the scaffold, with rationale:

1. **CLI framework: standard library (not Cobra).** The CLI holds cloud admin credentials, so minimizing the dependency/supply-chain surface is a security decision, consistent with the SDK's stdlib-only stance and FarCast's first pillar. The command tree is shallow enough (mostly `farcast <verb>`, with `storage` as the only two-level case) that Cobra's machinery isn't required. Trade-off: help rendering is hand-written and there is no shell completion yet. If the command tree grows unwieldy, adopting Cobra later is mechanical.
2. **Config format: YAML.** Reuses the already-vendored `goccy/go-yaml` (no new dependency) and keeps config operator-readable and consistent with the manifest.
3. **Single module.** The stray per-module `go.mod` files were removed; the CLI lives in the root module per the repository convention, and only `sdk/go` remains a separate module.

---

## Roadmap

1.1 builds the frame; later phases drop commands into it:

| Phase | Adds |
|---|---|
| **1.1** (this) | Scaffold: routing, `version`, `help`, config handling, output formatting |
| 1.2–1.3 | [Planck](../../planck/README.md) provider adapter + `install` (interactive provisioning, mandatory cost limit) |
| 1.4 | `release` |
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
- Backend language strategy — [ADR 0002](../../docs/adr/0002-backend-language-strategy.md)
