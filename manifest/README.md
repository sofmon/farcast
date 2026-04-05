# Manifest Specification (`./farcast`)

> The contract between a Git repository and a FarCast instance.

## Purpose

The `./farcast` manifest declares **what** a repository deploys, not **how** to run it. It is deliberately minimal: a deployment identity and a per-application security contract. Everything else — base images, startup commands, resources, ports, health checks — is either expressed in a Containerfile (build + run concerns) or handled automatically by TechnoCore (resource management).

A single manifest can describe one or more applications grouped as a single deployment. Planck (see [`planck/README.md`](../planck/README.md)) translates the manifest into a Kubernetes namespace containing one workload per application. This lets a monorepo deploy its full set of services with one file.

See the root [README.md](../README.md#L169-L195) for the design intent and [AGENTS.md](../AGENTS.md#L21) for the guiding principle.

---

## File Location & Format

- **Path**: repository root.
- **Filename**: `farcast` (no extension). Referenced as `./farcast` in documentation.
- **Format**: YAML 1.2, UTF-8 encoded, LF line endings.
- **Companion files**: one or more `Containerfile`s, referenced by each app's `containerfile` field. The manifest parser does **not** read or validate Containerfiles — Planck does that at build time.

---

## Schema

### Top-level

| Field  | Type   | Required | Description |
|--------|--------|----------|-------------|
| `name` | string | yes      | Deployment identity. Maps to a Kubernetes namespace. |
| `apps` | list   | yes      | One or more applications. Must contain at least one entry. |

#### `name`

The identifier for the deployment as a whole. Planck uses this as the Kubernetes namespace name when deploying the applications.

**Rules:**

- Non-empty.
- Lowercase letters (`a`–`z`), digits (`0`–`9`), and hyphens (`-`).
- Must start with a letter.
- Must not end with a hyphen.
- Maximum 63 characters (DNS label limit, which K8s namespace names must satisfy).

**Valid:**

```yaml
name: my-app
name: payments-platform
name: team42-services
```

**Invalid:**

```yaml
name: ""                # empty
name: MyApp             # uppercase
name: 1service          # starts with a digit
name: my_app            # underscore
name: my-app-           # trailing hyphen
```

### `apps` entries

Each entry in `apps` is an object describing one application. The parser enforces that `apps` is a non-empty list; a repository with a single deployable expresses it as a list with one element.

| Field           | Type   | Required | Description |
|-----------------|--------|----------|-------------|
| `name`          | string | yes      | Application identity within the manifest. Maps to a Kubernetes workload name. |
| `containerfile` | string | yes      | Relative path to the Containerfile that builds this app's image. |
| `context`       | string | no       | Relative path to the build context directory. Defaults to the directory containing `containerfile`. |
| `external`      | list   | no       | Declared outbound network allowlist. Absent or empty means no external access. |

#### App `name`

Same rules as the top-level `name` (DNS label: lowercase, digits, hyphens, starts with a letter, max 63 chars). Must be unique across all entries in `apps` within a single manifest.

#### `containerfile`

Path to the Containerfile that builds this application, relative to the repository root.

**Rules:**

- Non-empty string.
- Must be a **relative** path (no leading `/`).
- Must not contain `..` segments. This prevents a manifest from referencing files outside the repository.
- The parser does **not** verify the file exists on disk. Planck will report an error at build time if the file is missing.
- Only the filename `Containerfile` is canonical. `Dockerfile` is not accepted as an alternative.

**Valid:**

```yaml
containerfile: ./Containerfile
containerfile: services/api/Containerfile
containerfile: ./apps/worker/Containerfile
```

**Invalid:**

```yaml
containerfile: ""
containerfile: /etc/Containerfile         # absolute
containerfile: ../other-repo/Containerfile # escapes repo
containerfile: ./services/../Containerfile # contains ..
```

#### `context`

The build context directory passed to the container build, relative to the repository root. When omitted, the build context defaults to the directory containing the `containerfile`.

Use `context` when a service's Containerfile needs to include files from a parent directory — the classic monorepo case where multiple services share code. For example, with `containerfile: ./services/api/Containerfile` and `context: .`, the build runs from the repository root and the Containerfile can `COPY ./shared` to pull in shared libraries.

**Rules:** identical to `containerfile` — non-empty when present, relative, no `..`, no absolute paths. Parser does not verify the directory exists.

**Valid:**

```yaml
context: .
context: ./services/api
context: services
```

**Invalid:**

```yaml
context: ""
context: /opt/build
context: ../shared
```

#### `external`

A list of outbound network endpoints this application is permitted to reach. FarCast denies all outbound traffic by default. An application can only connect to hosts declared here, and each declaration must include a human-readable reason that the operator reviews at `farcast run` time. Shrike (see [`shrike/README.md`](../shrike/README.md)) enforces this contract at runtime and treats any undeclared connection as a violation.

`external` is **per-app**. Application A cannot use application B's declarations; each app's allowlist is scoped strictly to itself.

Each entry is an object:

| Field    | Type   | Required | Description |
|----------|--------|----------|-------------|
| `host`   | string | yes      | DNS hostname of the external service. |
| `reason` | string | yes      | Human-readable justification shown to the operator. |

**`host` rules:**

- Non-empty.
- Valid DNS hostname syntax.
- **No** scheme (`https://`), **no** port, **no** path, **no** wildcards (`*.example.com`), **no** IP addresses. These may be added in a future version of the specification.

**`reason` rules:**

- Non-empty string.
- Shown verbatim to the operator. Write it for a human reviewer.

**Example:**

```yaml
external:
  - host: api.stripe.com
    reason: Payment processing
  - host: smtp.mailgun.org
    reason: Transactional email delivery
```

---

## The Containerfile Companion

The manifest does not contain build instructions, base images, language runtimes, or startup commands. All of those live in each app's Containerfile, an OCI-standard build recipe that Docker, Podman, and Buildah all understand.

This keeps responsibilities clean:

- **Manifest** — identity (what to call it) and security contract (what it's allowed to reach).
- **Containerfile** — build recipe (how to assemble the image) and startup command (`CMD`/`ENTRYPOINT`).

The manifest parser's job ends at the YAML file. It does not open, read, or validate any Containerfile. Planck is responsible for resolving the `containerfile` path, applying the `context` directory, and producing a runnable image. A missing Containerfile is a Planck-time error, not a parser-time error.

FarCast canonicalises on the filename `Containerfile`. There is no `Dockerfile` fallback. Modern container tooling reads Containerfiles natively, so this costs developers nothing while eliminating ambiguity when both files might otherwise exist.

---

## Complete Examples

### Single-app repository

Repository layout:

```
my-repo/
├── farcast
├── Containerfile
└── server.js
```

`./farcast`:

```yaml
name: my-app
apps:
  - name: server
    containerfile: ./Containerfile
```

### Single-app with external access

```yaml
name: my-app
apps:
  - name: server
    containerfile: ./Containerfile
    external:
      - host: api.stripe.com
        reason: Payment processing
      - host: smtp.mailgun.org
        reason: Transactional emails
```

### Multi-app monorepo

Repository layout:

```
my-platform/
├── farcast
├── services/
│   ├── api/
│   │   └── Containerfile
│   ├── worker/
│   │   └── Containerfile
│   └── web/
│       └── Containerfile
└── shared/
    └── proto/
```

`./farcast`:

```yaml
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
    external:
      - host: smtp.mailgun.org
        reason: Sending notification emails

  - name: web
    containerfile: ./services/web/Containerfile
```

The `api` and `worker` apps use `context: .` so their Containerfiles can `COPY ./shared/proto` from the repository root. The `web` app omits `context`, so its build context defaults to `./services/web`.

Planck will deploy this manifest as a single Kubernetes namespace called `my-platform` containing three workloads: `api`, `worker`, and `web`. Each workload has its own independent `external` allowlist enforced by Shrike.

---

## Validation Rules

The parser must reject a manifest when any of the following conditions hold. Each rule corresponds to at least one test case in `manifest/parser/parser_test.go`.

### Document-level

1. **Malformed YAML** — any YAML syntax error. The parser wraps the underlying library error and preserves line/column information where available.
2. **Empty document** — a file that is empty or contains only comments/whitespace fails because required fields are missing.
3. **Unknown top-level key** — any key other than `name` and `apps`.

### Top-level `name`

4. `name` is missing.
5. `name` is not a string.
6. `name` is empty.
7. `name` contains characters outside `[a-z0-9-]`.
8. `name` does not start with a lowercase letter.
9. `name` ends with a hyphen.
10. `name` is longer than 63 characters.

### `apps`

11. `apps` is missing.
12. `apps` is not a list.
13. `apps` is an empty list.
14. Two entries in `apps` have the same `name`.

### Per-app fields

15. An app entry is not a mapping/object.
16. An app entry contains an unknown key (anything other than `name`, `containerfile`, `context`, `external`).
17. App `name` is missing, not a string, empty, or violates the DNS-label rules (same rules 6–10 as the top-level `name`).
18. `containerfile` is missing, not a string, or empty.
19. `containerfile` is an absolute path.
20. `containerfile` contains a `..` segment.
21. `context` is present but not a string, or empty.
22. `context` is an absolute path.
23. `context` contains a `..` segment.

### `external` entries

24. `external` is present but not a list.
25. An `external` entry is not a mapping/object.
26. An `external` entry contains an unknown key (anything other than `host`, `reason`).
27. `host` is missing, not a string, or empty.
28. `host` is not a valid DNS hostname.
29. `reason` is missing, not a string, or empty.
30. Two entries in the same app's `external` list have the same `host`. (Duplicates *across* different apps' lists are allowed — each app has its own independent allowlist.)

---

## Reserved / Not Yet Specified

The following are deliberately absent from Phase 0.1. They are listed here so readers know these concerns have been considered and intentionally deferred, not forgotten.

- **Ports, protocols, or schemes on `external` hosts.** `external` declares reachable hostnames only. FatLine enforces the deny-by-default boundary at the DNS level.
- **Inbound / ingress declarations.** How applications are exposed to users is handled by FarSight and FatLine, not the manifest.
- **Resource hints** (CPU, memory, replicas). TechnoCore observes running applications and adapts resources automatically.
- **Environment variables and configuration.** Provided through the SDK via `farcast.Config()` (Phase 5.3).
- **Secrets.** Provided through the SDK via `farcast.Secrets()` (Phase 5.3). Never stored in plaintext, never declared in the manifest.
- **Storage bindings.** Applications access DataSphere through `farcast.Storage()`. There are no manifest-level volume declarations.
- **Base images, build steps, language runtimes.** Expressed in the Containerfile.
- **Startup command.** Expressed in the Containerfile via `CMD` / `ENTRYPOINT`.
- **Health checks and probes.** TechnoCore monitors applications automatically.
- **Wildcard hosts** (e.g. `*.stripe.com`) and **IP address hosts**. A future version of the specification may add these; Phase 0.1 is DNS-hostname-only to keep Shrike's Phase 2 enforcement model simple.
- **Schema version field.** Strict unknown-key rejection leaves room to introduce `schema_version` additively in a future version without ambiguity.

---

## Grammar Reference

A compact summary for implementers. Formal types are for illustration; YAML does not enforce them at the syntax level.

```
Manifest       := { name: Name, apps: [App, ...] }
Name           := string matching /^[a-z][a-z0-9-]{0,61}[a-z0-9]$/  (1..63 chars)
App            := { name: Name,
                    containerfile: RelPath,
                    context?: RelPath,
                    external?: [External, ...] }
External       := { host: Hostname, reason: NonEmptyString }
RelPath        := non-empty relative path; no leading '/'; no '..' segments
Hostname       := valid DNS hostname; no scheme, no port, no path, no wildcards, no IPs
NonEmptyString := string with length >= 1
```

All keys not listed above are rejected. All fields marked as required must be present; a missing required field is an error, not a default.
