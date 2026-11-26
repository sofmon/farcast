# M3b build plan: device certificates (ADR 0023/0024), final

*Kept in the repository 2026-11-26. The operator answered the four questions of §7's "Ask before M3b.1" on 2026-11-26, each with its default: Q24 `--yes` as writer consent on the CLI; Q3 IAM's API host for the reader's token only; X2 the store under the 0700 config root, an ACL check only if M3b.2's spike proves one; Q9 the installer-minted reads as the reader, with resource-scoped grants.*

This plan was judged from two independent plans: Plan A (dependency-first) and Plan B (risk-first). It also draws on four code maps (install-records, credentials, devicekey-federation, cloud-setup). It was checked against:
- `docs/design/adr-0024-design.md` §7 (the scope, :1066-1111);
- D1-D11 (:99-655);
- §9's questions (:1132-1159);
- §11's open items (:1282-1289).

Written 2026-11-24, before M3b's build started. The judge changed no repository file and ran no go command and no test. Beyond the maps, the judge read §7, §9, §11, D2-D7, D10 and D11, and spot-checked these facts:
- `golang.org/x/sys/unix` is already linked on darwin, through `keeper/backup_darwin.go`.
- Its vendored copy defines `SYS_GETATTRLIST` and `ATTR_CMN_EXTENDED_SECURITY`, but has no getattrlist wrapper. `Getxattr` exists.
- `config.Resolve` honours `--config` and `$FARCAST_CONFIG_HOME`.
- `check.sh:397` copies exactly `app instances kinds version world`.

Path shorthand:
- `cli/` is `farsight/cli/internal/cli/`
- `config/` is `farsight/cli/internal/config/`
- `DK/` is `farsight/cli/internal/devicekey/`
- `kube/` is `farsight/cli/internal/kube/`
- `DES` is the design
- `Core/` is `farsight/client/apple/FarSightKit/Sources/FarSightCore/`

M4 (Linux, Windows) is parked. Nothing here is M4-specific. The linux and windows release builds only keep compiling, and the walk's second device is a second config home on the Mac.

---

## 0. The verdict

### The skeleton: Plan A's

The steps run in this order:
1. The foundations, unwired.
2. The consumers, one layer at a time.
3. The documents and `release`'s teardown, before the producer.
4. `install`, the producer.
5. The `device` commands.
6. The fallbacks.
7. The records.

Why this order:
- **No operator-reachable state is ever half-switched.** Until `install` switches (M3b.14), only test fixtures can make a certificate-route record. Every consumer is switched, and tested on such fixtures, before the first real one exists.
- **Pending installs are listed and warned about before they can exist.** `instances` lists them and every command warns at 7 days (M3b.12) before `install` can make the first one (M3b.14). Plan B made pending installs at its .7 and listed them at .10 and warned at .11, so §7's pending bullet and mutation row stood half-delivered for three commits.
- **Everything `install` can make can be released.** `release` prints the teardown (M3b.13) before `install` makes the first certificate-route record, which the cost pillar wants.
- **Each §7 row gets one owner.** Plan A's layering gives each row a natural owner.

### Grafted from Plan B
1. **The paste, line and verify loop, proven early.** `TestSetupPasteThenVerify` runs the real generator under a fake gcloud, feeds the result to the federation fakes, parses the line and verifies (M3b.6). Plan A proved this loop only inside `install`.
2. **An explicit ambient switch in planck and datasphere (`Ambient`).** With neither credential set, the adapters refuse, so "ADC out of the CLI" is enforced in the adapters, not only by a CLI scan (M3b.4).
3. **Adapter-side token sources and the node-account plumbing as their own early step** (M3b.4). It runs in parallel and is reviewed alone.
4. **A goroutine-safe `RoleTokens` with `Invalidate`.** httptransport refreshes in the background (M3b.3).
5. **The pending-to-record hand-off as one config function.** It is `AdoptPending` and `ResumeAdoption` (M3b.2), so its crash windows are tested before `install` uses it.
6. **`Identity.Known` and `Identity.Roles` merged per key,** as `SystemImages` is. A concurrent `device known` or `device renew` then loses no write (M3b.2).
7. **Every record names its routes early.** From M3b.7, M2's `install` writes the writer's route and `reader init` the reader's. The test fixtures move to one helper early. The "no identity means M2's shapes" branch Plan A carried to its M3b.12 is never built, which is no compatibility work.
8. **A fake gcloud written in Go** (the test binary re-executed as `gcloud`, with typed JSON state), not a sh stub. Plan A's stub would have had to model policies, conditional bindings and soft deletes in shell.
9. **Splitting Plan A's large "Google tokens and ADC" step** into planck and registry (M3b.9) and storage, secrets and release (M3b.10).
10. **Review rounds** after M3b.8, M3b.14 and M3b.16, with overlay mutants, as M3a had.
11. **The map corrections.** `kube/federated_test.go:754` inverts when the audience narrows. `walkm3achains_test.go:927` keeps passing.
12. **The walk.** It adds a decoy `GOOGLE_APPLICATION_CREDENTIALS`, the baseline user-managed key count of 0, and the second device as a second config home on the Mac.

### Kept from Plan A over Plan B
- **Per-consumer impersonation scopes** (N9). GCS keeps `devstorage.full_control` instead of widening to `cloud-platform` (gcs/client.go:40-43's own reason).
- **Fallback 3 lands with `install`,** so no commit has an `install` with neither `--credentials` nor fallback 3.
- **`release`'s pre-consent gate falls back to after the retype when no reader can read.** Plan B's default refused `release` there, against the cost pillar.
- **A separate `setupblock` package** with an import rule: no os/exec, no net, no file I/O.
- **Dated records appended in every step** (Q5's default; D10's no-moved-line rule), not only at the end.

The gaps neither plan closed are listed in §11.

---

## 1. Rules every step keeps

- **Each step builds and passes `./check.sh` on the dev Mac.** It keeps these compiling and green:
  - the `-tags walk` probe (check.sh:303 vets it);
  - the linux and windows release builds;
  - every test, offline: loopback fakes and a local fake gcloud only.
- **Each step can be committed alone,** but only when the operator asks, and never staging `.claude/`.
- **Any document, kind or vector change moves Swift in the same step.** `CLIReader` requires the commits to be equal (Core/CLI/CLIReader.swift:72-85). All of M3b's Swift changes land in one step, M3b.12.
- **Mutants are applied as `go test -overlay` copies,** never restored with `git checkout`. After each mutant, grep for residue and run the full suite again.
- **gofmt names packages, never the repository root.**
- **Each step's records are written last,** after `./check.sh` passes (§8).
- **Every new seam that would reach the network or a key** joins `refusingdefaults_test.go`.
- **Every new devicekey importer or watched call site** joins `custodyImporters` or `custodyCallers` (DK/custody_scan_test.go:31, :36).
- **The network guard.** At each review round, the new test binaries run under the M3a `sandbox-exec` profile, which refuses every connection but loopback (DES:1302).

---

## 2. At a glance

| # | Sub-milestone | Needs | Gate | Size [inf] |
|---|---|---|---|---|
| M3b.1 | devicekey: the enrolment reopen, `ConsentYes`, staged-certificate read, condition title, provider-list parser, `RemoveRole` guard | — | **Q24** | S, 1 d |
| M3b.2 | config: `Identity` with per-role routes, pending store, `AdoptPending`, path helpers, shape checks; X2 spike | M3b.1 | **X2** (placement) | S-M, 1.5 d |
| M3b.3 | kube: federated `Credential` and mint, pairing by mode, loopback federation, `RoleTokens` with per-consumer scopes, IAM read client, kubetest links and providers fake | — | **Q3** | M-L, 2.5 d |
| M3b.4 | planck and datasphere: neutral token source, `Ambient`, node-account plumbing, `GOOGLE_API_CERTIFICATE_CONFIG` | — | — | S-M, 1.5 d |
| M3b.5 | `setupblock`: every block, the role table, the console guide, the Go fake gcloud | M3b.1 | Q13 shapes it | L, 2.5 d |
| M3b.6 | The three lines, the settle rule, `verifyEnrolment`, paste-to-verify | M3b.3, M3b.5 | — | M, 1.5 d |
| M3b.7 | The cli role opener; every record names its routes; the reader on the certificate route | M3b.1-M3b.3 | N10 | M, 2 d |
| M3b.8 | Consent, then the writer, for cluster writes; `identity_route` plan fact | M3b.7 | **N1** | L, 2 d |
| M3b.9 | planck and registry through role tokens; registry writes after consent | M3b.4, M3b.8 | N2 | M, 1.5 d |
| M3b.10 | storage, secrets and `release` through role tokens | M3b.9 | N2 | M, 1.5 d |
| M3b.11 | D5: recorded number, the reader's resource grants, every installer-minted read as the reader | M3b.10 | **Q9**, N3, N11 | M, 1.5 d |
| M3b.12 | Documents, warnings, kinds, rehearsal, line vectors; Swift lockstep | M3b.3, M3b.6, M3b.7 | N4-N6, N8, N12 | L, 2.5 d |
| M3b.13 | `release`'s teardown block | M3b.5, M3b.10, M3b.11 | — | S, 1 d |
| M3b.14 | `install` from the paste; fallback 3; pending, resume, abandon; the node account required | M3b.6, M3b.12, M3b.13 | **X2** (enforcement), Q16, N14 | L, 2.5 d |
| M3b.15 | `device coordinates`, `ls`, `known`, `rm` | M3b.14 | — | M, 1.5 d |
| M3b.16 | `device add` (with its own abandon) and `device renew` | M3b.15 | Q8, N7, §9.4 | L, 2 d |
| M3b.17 | Fallback 2 for both roles; `reader init`/`record` reworded | M3b.14 | Q16 | M, 1.5 d |
| M3b.18 | Fallback 1 (OIDC, one single-key JWKS per role); separable | M3b.14 | fallback 1 now or later | M, 1.5 d |
| M3b.19 | Records sweep and the M3b walk runbook | all | Q5 | S, 1 d |

**Effort.** The steps add up to about 32 build days, plus about 3 for the three review rounds [inf]. Taken at face value, that is above §7's 3-4 weeks. Plan A read M2's pace as about 40% of its estimates [inf, not re-checked]; at that pace it is about 3 calendar weeks.

The cheapest cuts:
- M3b.18, fallback 1: about 1.5 d. §7's condition for it is met, so cutting it is the operator's call.
- The Swift line parser in M3b.12: about 0.5 d (N8).

---

## 3. Dependency graph

```
M3b.1 devicekey ──┬──► M3b.5 setupblock ──► M3b.6 lines + verifyEnrolment ───────────────┐
M3b.2 config ◄────┤                              ▲                                        │
M3b.3 kube ───────┼──────────────────────────────┘                                        │
                  └──► M3b.7 opener ─► M3b.8 consent ─► M3b.9 planck/registry ─► M3b.10 storage/secret/release ─► M3b.11 D5
M3b.4 planck+datasphere adapters ─────────────────────────┴──────────────────────────────┘
M3b.3 + M3b.6 + M3b.7 ───────────────────────────────► M3b.12 documents + Swift (after M3b.11 in the line)
M3b.5 + M3b.10 + M3b.11 ─────────────────────────────► M3b.13 release teardown
M3b.6 + M3b.12 + M3b.13 (+ X2) ──────────────────────► M3b.14 install ─► M3b.15 device ls/rm/known/coords ─► M3b.16 device add/renew
                                                                     └─► M3b.17 fallback 2 ─► M3b.18 fallback 1 (separable)
all ─► M3b.19 records + runbook ─► the billable walk (approval at G0)
```

- **The critical path** is M3b.3 → M3b.7 → M3b.8 → M3b.9 → M3b.10 → M3b.11 → M3b.13 → M3b.14 → M3b.15 → M3b.16 → M3b.19.
- **Built beside it:**
  - M3b.1, M3b.2 and M3b.4 beside M3b.3;
  - M3b.5 and M3b.6 beside M3b.7 to M3b.11;
  - M3b.12 beside M3b.9 to M3b.11;
  - M3b.17 and M3b.18 beside M3b.15 and M3b.16.
- **The numbering is the commit order.** No step uses anything a later step adds. The pinned refusals in §4 name a later step only as the text an operator would read.

---

## 4. Transitional states, pinned

These states are fixed. Each refusal has a fixed message and a test, and every one ends "nothing was sent". This follows M2's precedent (adr-0023-m2-design.md §0).

**Two kinds of record.** A certificate-route record exists only in test fixtures until M3b.14. A fallback-route record is what `install` and `reader init` make before M3b.14: the writer on `google_made_key`, the reader on `uploaded_key`.

| After | Certificate-route record | Fallback-route record |
|---|---|---|
| M3b.1-M3b.6 | nothing reads `Identity` | As at 4bbbb5f. From M3b.4, a blank installer key fails closed in planck and datasphere instead of reaching ADC, and an empty node account keeps the default compute account (until M3b.14). |
| M3b.7 | Cluster reads, and plans' cluster reads, run as the federated reader. The writer refuses: "instance %q's writer on the certificate route opens from M3b.8". Google API calls refuse: "… from M3b.9". | Every record names its routes. A record with no `Identity` is refused by every command: "instance %q's record names no identity route; a farcast before M3b wrote it, and that is not supported". The message names no command that would itself refuse (Plan A's "release it" did). The writer (`credentials.yaml`) and the reader (`reader.key`) open through the one opener. |
| M3b.8 | Cluster writes run as the federated writer, after consent. | The cluster writer reads `credentials.yaml` only after consent. Only D5's installer-minted Google reads still mint from it before consent, as at 4bbbb5f, until M3b.11. Interactive plans run as N1 says. |
| M3b.9 | planck and registry writes run as the writer after consent. The installer-minted registry reads in plans refuse: "… as the reader from M3b.11". Storage, secret and `release` refuse: "… from M3b.10". | planck and the registry run through role token sources. The installer-minted registry reads keep the writer route's token, as at 4bbbb5f, until M3b.11. |
| M3b.10 | Storage and secret writes, and all of `release`, run as the writer after consent or the retype. Storage reads refuse: "… as the reader from M3b.11". | The same, through token sources. Storage reads keep the writer route until M3b.11. |
| M3b.11 | Every D5 read runs as the reader. | D5's reads run as the `uploaded_key` reader where it is granted. With no reader route, a read command refuses `credential_missing`. A plan with no recorded number prints the existing `PROJNUM=` line (MS-6). |
| M3b.12 | Documents and warnings carry the identity. | The same. |
| M3b.13 | `release` prints the teardown block. | `release` as at 4bbbb5f, with the reader lines for an `uploaded_key` reader. |
| M3b.14 | `install` makes the first real ones. | `install --google-made-key` records the drawn IDs and the number. M2-shape records are no longer made. |
| M3b.15-M3b.18 | the `device` commands, and fallbacks 2 and 1 | — |

---

## 5. The sub-milestones

### M3b.1: devicekey, the purposes and parsers M3b needs (unwired)

**Goal.** Close M3a's gaps that commands would otherwise work around.

**Changes.**
- `DK/custody.go`:
  - **`(*Store).OpenForEnrolment(r, rnd, now)`.** It is DES:377's "enrolment" purpose. It opens role r's current leaf, renewing it under its own anchor if due, with no consent. Only a resumed `install --coordinates` or `device add` uses it. It is added to the watched list at custody_scan_test.go:46. *(2026-11-26, built: bounded by an enrolment window in the store, and its sites watched per role, as `OpenForEnrolment(Reader)` and `OpenForEnrolment(Writer)` ([the design's §12](adr-0024-design.md#12-amendments-from-m3b1s-build-2026-11-26), departure 1).)*
  - **`ConsentYes`** (Q24's default) and `Consent.Confirmed()`, so M5's broker can admit `--confirm` alone. The kinds stay distinct.
  - **`RemoveRole(Reader)`** refuses while `writer/` exists. That closes the writer-only store pitfall.
- `DK/store.go`:
  - `StagedCertificates(r)`: the staged `anchor.crt` and `leaf.crt`, and whether they are there. It opens no key.
  - `Certificates` also exposes the anchor's `NotAfter`. *(2026-11-26, built as `CurrentCertificates(r)`, a `Certs` with `AnchorNotAfter()`, beside `AnchorWarnsAt` and `AnchorExpiredAt`; `Certificates` keeps its signature.)*
- `DK/ids.go`: a `ConditionTitle` kind. It is `[a-z][a-z0-9]`, 30 characters, and recorded as a D11 trait.
- `DK/google.go`:
  - `CheckProvider` also refuses a present `displayName` or `description` (DES:218), and checks that `name` ends in `/providers/<id>`. *(2026-11-26, built as `CheckNamedProvider(answer, projectNumber, pool, provider, anchorDER, id)`, which compares the whole name; `CheckProvider` stays the walk probe's only.)*
  - New `ParseProviders(listJSON)`, size-bounded, returning `{ID, State, Disabled, RoleID}` and the next page. *(2026-11-26, built as `ParseProviders(listJSON, projectNumber, pool)`, beside `ParseProvider` for one provider; both read strictly, and set `RoleID` only under D3's exact mapping and condition.)*
  - New `RoleIDFromCondition(cond)`. It accepts exactly `AttributeCondition`'s shape, one ID twice, and refuses anything else, two IDs included.

**Delivers.** §7's "D2's custody rules in `devicekey`" (S3b).

**Tests.**
- `OpenForEnrolment(Reader)` never touches `writer/` (mode-000 technique, custody_test.go:223-276).
- The `ConsentYes` kind round trip.
- `RemoveRole` refusal.
- The list parser: paging, `DELETED`, and a two-ID condition refused.
- The custody scan's watched list updated.

**Unwired.** No product importer yet.

**Size.** About 250 product lines and 450 test lines. *(2026-11-26: built at about 900 product lines and 2,300 test lines, with the reviews' fixes.)*

**Risks.**
- `OpenForEnrolment` opens a writer key without consent. The call-site review is its guard, as for `RenewAnchor` and `AddRole`. *(2026-11-26: superseded: an enrolment window in the store's state bounds it, and the scan watches each site by its role.)*
- The list JSON's shape is [inf]; M3a's T4 used `get` only. *(2026-11-26: still [inf]; the parsers fail closed on any other shape.)*

### M3b.2: config, the record, the pending store and the hand-off (unwired)

**Goal.** Every non-secret coordinate has a typed, shape-checked home. The pending store sits outside `instances/`, and the pending-to-record hand-off is one tested function.

**Changes.**
- **New file `config/identity.go`.**
  - `Route`, per role: `certificate`, `public_key` (fallback 1), `uploaded_key` (fallback 2), `google_made_key` (fallback 3), `none`.
  - `Identity{ProjectNumber, Pool, ReaderAccount, WriterAccount, NodeAccount, ConditionTitle, Roles []DeviceRole{Role, Route, Provider, AnchorNotAfter}, Known []KnownProvider{Provider, Role}, EnrolledAt}`.
  - The routes are per role because fallback 3's writer pairs with a fallback 2 reader or none (N13 in Plan A).
  - `CheckedIdentity(meta)` checks each present value against the alphabet it is later rendered into an Owner shell with:
    - the number `^[0-9]{1,20}$`;
    - pool and provider IDs 32 long, SA IDs 30 long, condition titles 30 long, all `[a-z][a-z0-9]*`.
  - It also checks the fields each route requires. The M2-shape fallback routes from M3b.7 carry only the route. M3b.14 tightens fallback 3 to the drawn IDs.
  - `ServiceAccountEmail(id, project)`.
  - config keeps its own regexps and does not import devicekey. `config_test.go` imports devicekey to check that every `NewObjectID` and `ConditionTitle` draw passes.
- **`config/instance.go`.**
  - `InstanceMetadata.Identity` (yaml `identity`).
  - `mergeOntoNewer` merges `Identity.Known` and `Identity.Roles` per key, as `SystemImages` is (:648-655).
  - `InstanceCredentials`' doc loses "empty = ADC", and `LoadInstanceCredentials` refuses a blank key.
  - The path helpers: `InstanceIdentityDir`, `PendingDir` and `PendingIdentityDir`.
- **New file `config/pending.go`.**
  - The store: `<config>/pending/<name>/` at 0700, holding `pending.yaml` (0600) and `identity/`.
  - `Pending{Kind (install | device_add), Name, Provider, Project, Region, CostLimit, CreatedAt, State, Draw{Pool, ReaderProvider, WriterProvider, ReaderAccount, WriterAccount, NodeAccount, ConditionTitle}, Route, ProjectNumber}`.
  - States: `keys_made`, `setup_shown`, `coordinates_received`. *(2026-11-26, M3b.1: and one recording that a role's verification passed, written before `EnrolmentVerified`, which M3b.14's resume reads.)*
  - Functions: `CreatePending` (exclusive `Mkdir`), `Save`/`LoadPending` (atomic; through `readFile`, so `ObserveReads` sees it), `ListPending`, `PendingExists` and `RemovePending` (refuses a symlink). Names are validated before any path is built.
  - **`AdoptPending(name, meta)`** hands off in pitfall 10.1's order:
    1. `CreateInstance`;
    2. `SaveInstanceMetadata`, with `Identity` and status `provisioning`;
    3. rename `identity/` into the instance;
    4. `RemovePending`.

    It refuses an existing destination `identity/`.
  - **`ResumeAdoption(name)`** finishes a hand-off when both the record and the pending entry exist.
- **X2 spike** (no shipped code). It answers whether a cgo-free raw `getattrlist(ATTR_CMN_EXTENDED_SECURITY)` through the already-linked x/sys/unix reports an inherited ACL on the dev Mac. That is [unverified]: x/sys has no wrapper, and Apple does not support raw syscalls. The result feeds X2's enforcement decision before M3b.14.

**Tests.**
- Round trip; the per-key merge under two concurrent writers.
- Every shape refused with hostile values: a control character, `/`, `..`, uppercase, a wrong length.
- `ListInstances` never lists a pending entry.
- Exclusive create.
- `AdoptPending` failing at each of its steps, then `ResumeAdoption`.
- The abandon precondition `PendingOnly(name)` refuses when a record exists.
- `ObserveReads` sees `pending.yaml`.

**Unwired** until M3b.7, where the opener reads the record, and M3b.14, where `install` writes it.

**Size.** About 450 product lines and 700 test lines.

**Risks.** The field set is fixed before its consumers exist, so expect a dated design amendment.

### M3b.3: kube, the federated credential, role tokens and IAM's read host (unwired; Q3)

**Goal.**
- A `kube.Client`, and a per-role token source, minted from a device leaf through STS and IAM Credentials.
- The reader can read providers at IAM's API host, and no other identity can. *(2026-11-26, M3b.1: the list reader requires status 200, caps the pages it follows and refuses a page token it was already given; `ParseProviders` leaves those to it.)*
- All of it testable from package cli.

**Changes.**
- **`kube/credential.go`.** A federated variant, held two pointers deep and built only by `NewFederatedCredential(fed, audience, ClientIdentity, email, role)`. The audience comes only from `Audience`.
- **`kube/token.go`.**
  - `newClient` (:48-76) gets a federated mint:
    - exchange, caching the federated token per credential until `ExpiresIn` minus a margin (D5.1: one exchange per role per process);
    - then `Impersonate`;
    - an IAM 401 re-exchanges once.
  - `tokenCache` is unchanged, so a cluster 401 re-impersonates without re-exchanging.
  - `pair()` (:220-241):
    - the origin comes from the `Federation`'s mode (Google or loopback), never from the email's domain;
    - a loopback federation pairs only with a loopback endpoint;
    - `Config.Identity` must equal the credential's role;
    - `TokenURI` and `UniverseDomain` must be empty.

    This resolves the `.invalid` and `GenerateAccessTokenPath` clash. Loopback credentials keep `*.iam.gserviceaccount.com` emails.
- **`kube/federated.go`.**
  - `checkAudience` narrowed to the number form. This inverts `federated_test.go:754`. `walkm3achains_test.go:927` keeps passing, and the walk-tagged I5 path now refuses locally (a dated amendment).
  - `Federation` gains a mode.
  - Exported `NewLoopbackFederation(sts, iamCredentials, iamAPI, roots)` admits only `127.0.0.1` and `::1` literals. A source scan checks that only `_test` files and `internal/rehearsal` call it.
  - `TestProductExchangesCarryNoKnobs`: no product caller passes a subject chain or scopes (DES:1259).
- **`kube/tokensource.go`** (new).
  - `RoleTokens` with `Token(ctx) (string, time.Time, error)`, the signature planck's and datasphere's neutral interfaces take, and `Invalidate(token)`.
  - It is goroutine-safe, because httptransport refreshes in the background (transport.go:90).
  - It holds one federated token per role per process, and one impersonation per consumer.
  - **N9: each consumer has its scopes from a closed list:**
    - `ScopesCluster` = `TokenScopes`, exactly D5.2's;
    - `ScopesStorage` = `devstorage.full_control`;
    - `ScopesRegistry` = `cloud-platform`.

    `ImpersonationBody` takes one of them; the pinned body and the IAM fake follow. This is a dated amendment to D5.2 for the non-cluster consumers.
  - `TokenSourceFor` wraps a 2LO credential (`reader.key`, `credentials.yaml`) with the same per-consumer scopes, so every route yields a token source.
- **`kube/iamread.go`** (new).
  - `IAMHost = "iam.googleapis.com"`.
  - `IAMReader` accepts only a federated reader's `RoleTokens`.
  - Its client: `Proxy` nil, system roots, TLS 1.2 or later (Q4), no client certificate, no redirects, a size cap, body-free errors typed by step, the bearer only to `IAMHost`, `User-Agent` `kube.UserAgent` (Q14).
  - `GetProvider` and `ListProviders` (paging) take paths built only from shape-checked parts.
- **kubetest.**
  - A `Server` option `WithFederation(f)`: the cluster fake authenticates the IAM fake's SA tokens with id and email. Its own `/token` check stays.
  - The providers keep their PEM, mapping, condition, state and `disabled`.
  - New `RemoveProvider` (to `DELETED`), `DisableProvider`, `Unbind` and `GrantPoolViewer`.
  - An IAM API listener serving get and list, with the bearer checked.
  - An exported non-testing `Start` for the rehearsal.

**Owns rows.**
- R1: a bearer only to IAM Credentials, and the reader's to IAM's API host only; a writer token there fails.
- R2: the client certificate only to STS, through `newClient` and both new clients.
- R3: the environment proxy.
- R4: a URL from input or a file, the loopback constructor given a non-loopback host included.
- R10: a body in an error, in the mint and the IAM client.

**Tests.**
- New:
  - `TestFederatedClientReadsTheCluster`: the username is the SA's email.
  - `TestOneExchangePerRolePerProcess`, counted by `Federation.Requests`.
  - `TestClusterUnauthorizedReimpersonatesOnly`.
  - `TestIAMUnauthorizedReexchangesOnce`.
  - `TestFederatedPairingRefusesEachMismatch`.
  - `TestRoleTokensConcurrentRefresh`, under `-race`.
  - `TestPerConsumerScopes`.
  - `TestIAMReaderRefusesAWriter`.
  - `TestListProvidersPagesAndDeleted`.
- Extended:
  - `TestFederatedFixedValues`;
  - `TestNewFederationURLsAreTheConstants`, now with `IAMHost`;
  - `TestFederationTransportsHaveNoProxy`;
  - `TestIdentityTransportSendsOnlyToItsHost`;
  - `TestBearerOnlyToIAMCredentialsHost`;
  - `TestFederationTypesNeverFormat`;
  - `TestFederatedHasNoInitTimeState`.

**Unwired.** No cli caller.

**Size.** About 800 product lines and 1,500 test lines.

**Risks.**
- The pairing change must keep `TestAuthorizationOnlyToTheEndpointHost` intact.
- The scope change moves a pinned body.
- The walk-tagged probe must still compile.

### M3b.4: planck and datasphere, token sources, `Ambient` and the node-account plumbing (adapters)

**Goal.**
- The adapters take a neutral token source.
- Neither adapter reaches ADC unless told to explicitly.
- planck can name a dedicated node account.

**Changes.**
- **`planck/types.go`.**
  - `Config.Tokens`: a neutral interface `Token(ctx) (string, time.Time, error)`, so planck does not import auth.
  - `Config.Ambient bool`.
  - Setting both credentials is refused, and so is neither without `Ambient`. `String()` redacts both.
- **gke.**
  - `newClient` (client.go:87-101) wraps the token source with `auth.NewCredentials{TokenProvider}` and passes `option.WithAuthCredentials`.
  - `registryCredentials` (registry.go:594-600) feeds `httptransport.Options{Credentials}` and `RegistryToken`.
  - `DetectDefault` runs only under `Ambient`.
- **datasphere.**
  - `types.go` mirrors both fields; mirrored, not imported.
  - `gcs/client.go` `storageCredentials` likewise.
  - `datasphere/cmd/datasphere/main.go` sets `Ambient` when it has no `--credentials`.
- **The planck harness.** `Ambient` when it has no `--credentials`, and a new `--node-service-account`.
- **Both `hardenEnvironment`s** (cli.go:68-78, planck/cmd/planck/main.go:47-57) unset `GOOGLE_API_CERTIFICATE_CONFIG`.
- **The node account.**
  - `ClusterSpec.NodeServiceAccount`, carried in `createInput`.
  - `planCreate` shape-checks a non-empty value: local part 6-30, domain `<project>.iam.gserviceaccount.com`. An empty value keeps the default compute account, pinned until M3b.14.
  - `buildCluster` sets `Autoscaling.AutoprovisioningNodePoolDefaults.ServiceAccount`, and leaves `OauthScopes` unset [unverified].
  - `get()` reads the account back, and `waitReady` refuses a RUNNING cluster whose account differs from the one asked for. That covers adopted clusters.
  - `RegistrySpec.NodeServiceAccount`: when it is given, `grantPull` binds it with no `projects.get`.
  - The integration test passes a node account.
- **CLI scan `TestCLINeverSetsAmbient`.** No CLI file sets `Ambient`. So the CLI's blank-key paths (release.go:112, storage/storage.go:88, fatline.go:552) now fail closed in the adapters.

**Owns.**
- R15: `TestBuildClusterNamesTheNodeAccount`. A mutant that drops the field fails.
- §7's ADC bullet (S11).
- The token-provider clause of D6's wiring (S8b).
- The "`buildCluster` names it, and a test checks the request" clause of the node account (S7a).

**Tests.**
- `TestConfigRefusesBothCredentials` and `TestConfigRefusesNeitherWithoutAmbient`.
- A fake token source drives the cluster, registry and GCS clients, a background refresh included.
- The `waitReady` mismatch refusal.
- `harden_test.go`.

**Size.** About 400 product lines and 700 test lines.

**Risks.**
- Autopilot honouring the account is [inf].
- httptransport replaces the token provider in place.
- A CLI test that relied on a blank key.

### M3b.5: the `setupblock` package, the role table, the console guide and a fake gcloud (unwired)

**Goal.** Every Cloud Shell block and the console guide, produced deterministically from recorded values only, tested offline.

**Changes.**
- **A new package, `farsight/cli/internal/setupblock`.**
  - Its import rule test allows the standard library and devicekey (go-yaml in tests): no os/exec, no net, no file I/O.
  - It is listed in `custodyImporters`. It renders public bytes and opens no key.
- **Inputs:**
  - `Instance{Project, Pool, ReaderAccount, WriterAccount, NodeAccount, ConditionTitle, BucketPrefix}`;
  - `Device{Roles []Anchor{Role, Provider, RoleID, AnchorDER}}`.
- **Renderers**, each returning `Block{Text, SHA256}` with the full hex digest (ADR 0023:219):
  - `Setup`;
  - the shared `InstancePart`: APIs, number, counts, SAs and grants, used by every route;
  - `AddDevice`, `AddWriterRole`;
  - `Renew`: update-x509, one anchor per provider;
  - `DeviceRm`;
  - `Abandon`: reads NUMBER itself, and deletes the pool only if no other non-`DELETED` provider is in it;
  - `AbandonDeviceAdd`: this device's providers and bindings only (§11, gap 7);
  - `Release`: route-aware, the node SA last;
  - `GoogleMadeKey`, fallback 3: `InstancePart`, then console steps that make the writer's key and download it to the Mac. The block never makes a key, so no secret sits in Cloud Shell's home;
  - `ConsoleGuide` (Q7: beside the block).

  Fallbacks 2 and 1 come in M3b.17 and M3b.18.
- **One Go role table,** the single source for the block, the guide and the tests:
  - writer, project: `container.admin` and `artifactregistry.admin`, with `--condition=None`;
  - writer: conditional `storage.admin`, with the random title, no description, and a prefix built from `datasphere.BucketNamePrefix`;
  - writer: `iam.serviceAccountUser` on `NODE_SA` only;
  - reader, project: `container.clusterViewer` and `iam.workloadIdentityPoolViewer`;
  - node, project: `container.defaultNodeServiceAccount`.
- **The shell** (D7:428):
  - `sh -s` with neutral here-document tags and `set -eu`;
  - a y/N on the project from `</dev/tty`;
  - every gcloud line `--quiet </dev/null`;
  - `retry` and `retry_slow`;
  - trust stores from `devicekey.TrustStoreYAML` into `mktemp` files under their own neutral tags;
  - the condition through a here-document file and `--condition-from-file`. `m3aQuote`'s alphabet cannot carry `"()!|`.
- **The setup block,** in order:
  1. enable the APIs;
  2. read NUMBER;
  3. print the two Workload Identity counts, counts only. They use gcloud `--flatten`/`--format` with grep and awk, and cache each role's describe. A custom role the Owner cannot read counts as unknown and asks. A count other than 0 asks y/N, and a no stops before any create;
  4. create the pool if absent; a `DELETED` pool stops with a clear line;
  5. one provider per role;
  6. the three SAs, with no display name;
  7. the grants, marking the block INCOMPLETE on a refusal;
  8. the bindings;
  9. `complete()` prints the setup line only if nothing was refused.

  A refusal names the policy that refused (fallback 4).
- **Ported from `walkm3ablocks_test.go`:** `m3aRetry`, `hereDoc`, `providerExists`, `createX509`, `createSA`, `grantProject`, `bind`, `unbind`, `ungrantProject`, `poolPresent`, `deleteProvider`, `deletePool`, `deleteSA` and `updateTrust`. The probe file stays as walked.
- **The fake gcloud,** in a test-support package `setupblock/gcloudtest`. A scan checks that only `_test` files import it.
  - It is the test binary re-executed as `gcloud` through a wrapper on `PATH` in `t.TempDir()`, with its state in a JSON file.
  - It models:
    - the project number and the APIs;
    - pools and providers, `ACTIVE` or `DELETED`, with 30-day ID reservation;
    - SAs;
    - project and SA policies with conditional bindings;
    - `roles describe` for basic and custom roles;
    - describe of a soft-deleted object, both as `DELETED` and as `NOT_FOUND`;
    - refusal injection per verb.
  - `/dev/tty` is substituted in the harness copy only. A separate test pins the product text to `/dev/tty`.
  - No exec-allowlist line: test-only exec is outside the shipped binaries.

**Owns rows.**
- R12: two anchors in one provider, or two IDs in one condition.
- R13: the trust-store YAML, with one anchor whose `pemCertificate` is the DER byte for byte.
- R14: each member form, basic and custom roles, bindings on an SA or the project, and a no that stops before any create.
- R16: `Abandon`'s, `Release`'s and `DeviceRm`'s blocks against every prefix of the setup, then every prefix of themselves, with `DELETED` left.
- R20: `farcast` outside the condition prefix, or the instance's name.

**Delivers.** §7's generator bullet, the console guide included (S6), and "each role its own provider" (S3a).

**Tests.**
- The writer allowlist:
  - `workloadIdentityPoolAdmin`, `serviceAccountAdmin`, `projectIamAdmin` and `serviceAccountTokenCreator` never appear;
  - `iam.serviceAccountUser` never appears in a `projects add-iam-policy-binding`, and appears exactly once, on `$NODE_SA`, for `$WRITER_SA`.
- M3a's ten offline block tests, ported.
- `BlocksAreReproducibleFromState`: the same digest across processes.
- A cli test that `BucketPrefix` equals `datasphere.BucketNamePrefix`, gcs.go:28 and storagedeploy.go:1349.

**Unwired** until M3b.13 and M3b.14.

**Size.** About 1,000 product lines and 1,800 test lines (the fake about 500).

**Risks.**
- gcloud behaviour that is [unverified]: `--condition-from-file`, removing a conditional binding (`--all`), describe of soft-deleted objects.
- The counts are fragile and slow in large projects.
- The APIs are enabled before the counts, so "nothing created" holds but "nothing changed" does not (stated in the guide).

### M3b.6: the three lines, the settle rule and enrolment verification (unwired)

**Goal.** The paste, line and verify loop, proven end to end against the fakes before any command uses it. *(2026-11-26, M3b.1: the read-back is `CheckNamedProvider`, and once a role's verification has passed and is recorded where a resume reads it, the caller calls `EnrolmentVerified(r)`.)*

**Changes.**
- **`setupblock/lines.go`: three line kinds,** each with a neutral versioned tag, a fixed field count, control characters refused and each field checked against its alphabet:
  - **The setup line** (`install`'s line back). Eight values: project, number, pool, reader provider, writer provider (absent on a reader-only setup), reader SA, writer SA, node SA (DES:1196). The project must equal `--project`, and every ID the drawn one. Plan A's six-field line dropped the provider IDs.
  - **The device-coordinates line** (`device coordinates`, for a new machine). Project, number, pool, the three SA IDs and the region. The region is a dated amendment (N7), so a new machine finds its cluster with no project-wide list.
  - **The device line** (`device add`'s output, for `device known`). Provider IDs and their roles.
- **Go vectors** in `cli/testdata/coordinates/`. The Swift copy follows at M3b.12.
- **`cli/settle.go`** ports `m3aWait`, `m3aNextTry` and `m3aPositive`: a 10-minute bound, waits of 5, 10, 20, 40 and 60 s, and a clock seam.
- **`cli/enrolverify.go`: `verifyEnrolment(ctx, deps, ids, coords, clock)`.**
  - Per role, exchange and impersonate under the settle rule.
  - Then read this device's providers back as the reader: `GetProvider`, then `CheckProvider`.
  - The alerts `handshake_failure` and `decrypt_error` are retried within the bound, then reported.
  - Errors name the field, never a body.
  - The writer's identity is passed in, from `Enrol` or `OpenForEnrolment` at the caller.
  - The file is listed in `custodyImporters`.

**Owns.** R11: a provider accepted by the read-back whose trust store holds other than its one anchor, or whose condition names other than its one ID, shown end to end.

**Tests.** `TestSetupPasteThenVerify` (Plan B):
1. `Enrol` into a temporary directory.
2. Render `Setup` and run it under `sh` with `gcloudtest`.
3. Load the fake's providers and bindings into `kubetest.Federation`.
4. Parse the printed line, and `verifyEnrolment` passes.
5. Mutated setups fail, each naming its field: a second anchor, a wrong condition, the writer bound to the reader SA, and a display name set.

Also: the line vectors, and every line refused for a foreign project, foreign IDs, a bad tag or a control character.

**Size.** About 400 product lines and 900 test lines.

### M3b.7: the cli role opener, every record naming its routes, and the reader on the certificate route

**Goal.**
- One route-aware place opens a role.
- Cluster reads, and plans under `--plan` and `--confirm`, run as the federated reader.
- Every record names its routes.

**Changes.**
- **New file `cli/identity.go`: `openRole(env, ref, role, consent, purpose)`.** It returns the `kube.Credential` and `*kube.RoleTokens`. Its seams:
  - `identityOpener` over devicekey, which records each purpose asked for, because devicekey's reads bypass `ObserveReads`;
  - `newFederation`;
  - both refused in tests.
- **The reader on the certificate route:**
  1. `CheckedIdentity`;
  2. `devicekey.Open(InstanceIdentityDir).OpenForRead`;
  3. `kube.NewClientIdentity([leaf], signer)` (S1);
  4. `NewFederatedCredential(Audience(number, pool, readerProvider), reader email)`.
- **The fallback routes:** `reader.key` and `credentials.yaml`. The writer on the certificate route is the pinned refusal (§4).
- **Every record names its routes from this step.**
  - M2's `install` writes the writer as `google_made_key`.
  - `reader init` and `reader record` write the reader as `uploaded_key`.
  - The rehearsal's layout (rehearsal/layout.go:210-231) does the same.
  - A record with no `Identity` is refused with §4's fixed message.
  - The fixtures move to one helper, `writeTestInstance(t, routes)`.
- **`clusterref.go`.**
  - `openCluster`: step 1 checks per route, and step 4 goes through `openRole`.
  - `readerCredential` keeps `GrantedAt` and `Verifying` on every route.
- **The reader commands.**
  - `readerSubjectShape` (readerrbac.go:79-80) accepts the recorded random reader email.
  - `grantableReader` needs no `KeyID` on the certificate route.
  - `derivedReader` and `checkedReader` become route-aware.
  - `reader init` and `reader record` refuse a certificate-route reader.
- **`instances` `readerStateOf`, on the certificate route,** is stat-only, through `Open` and `Roles`, and never calls `OpenForRead`.
  - `key_missing` means this device holds no reader role.
  - `not_granted` and `granted` come from `GrantedAt`.
  - `ErrUnsafeMode` becomes the entry's error.
  - The words do not change, so Swift does not move here. `readerRemedy` becomes route-aware.
- **`kinds.go` `clusterKind`** maps by `errors.Is` and prints no devicekey text, which carries absolute paths:
  - `ErrNoRole`, `ErrUnsafeMode`, `ErrInconsistent` and `ErrRenewalInterrupted` map to `credential_missing`;
  - `ErrAnchorExpired` maps to `credential_refused`, until M3b.12 gives it its own kind. Only fixtures reach it before then;
  - `ErrNoConsent` maps to `internal`;
  - `ErrTokenRefused` maps to `credential_refused`;
  - `ErrUnreachable` maps to `cluster_unreachable`, naming the step.
- **`worlddoc.go` `scrubMessage`** also scrubs the federated reader email, the number, the pool, and the provider and role IDs.
- **`world`'s Usage (world.go:103-116) and README :1671** state what each refresh now sends (STS, IAM Credentials). They also say the reader leaf may renew in local files (N10).
- **Custody.** `custodyImporters` gains `cli/identity.go`, and `TestNothingShippedImportsDevicekey` changes: farcast now links devicekey.

**Owns.** R5: a read command or a plan that opens a writer key, exchanges the writer leaf, or impersonates the writer.
- `TestWorldNeverOpensAWriterCredential` gains:
  - the purpose log, reader only;
  - `Federation.Requests`, with no writer audience and no writer SA;
  - a mode-000 `writer/`.
- `TestReadCommandsPresentOnlyTheReaderToken` covers `world`, `ps`, `costs`, `usage` and `logs`.
- New `TestPlansOpenOnlyTheReaderKeys`, under `--plan` and `--confirm`, covers kernel deploy, storage deploy, storage pin, storage key, build and run.

**Size.** About 600 product lines and 1,300 test lines, with fixture churn.

**Risks.**
- Concurrent silent reader-leaf renewal across processes. It self-heals (store.go:662-665) and is untested across processes.
- Absolute paths reaching output.

### M3b.8: consent, then the writer (cluster)

**Goal.** In every route and every command, the writer opens only after consent. On the certificate route, cluster writes run as the federated writer.

**Changes.**
- **Consent.**
  - consent.go splits `consentNone` into `consentAsk` and `consentYes`.
  - One helper, `writerConsent(mode, answered)`, is the only `GiveConsent` site. It maps `--confirm` after the comparison to `ConsentConfirmed`, a terminal yes to `ConsentAnswered`, and `--yes` to `ConsentYes` (Q24).
- **The writer.**
  - `clusterRef.Consent`; `openReady`, `openReadyAt` and `openConfirmed` (fatline.go:712-770) take it.
  - `writerCredential`:
    - on the certificate route: `OpenForWrite(consent)`, then the federated writer. A zero consent gives `ErrNoConsent`, and nothing is opened;
    - on fallback 3: the cluster writer reads `credentials.yaml` only after consent. D5's installer-minted reads are the pinned exception until M3b.11 (§4).
- **The twelve sites reorder** to the `openConfirmed` shape: the plan, then the question, then the writer and its uid comparison.
  - connect.go:345, redeploy.go:217, build.go:369/373, run.go:364
  - kernel.go:356/360, storagedeploy.go:407, storagepin.go:770, storagekey.go:565
  - gitcredential.go:587, readergrant.go:305, kernelmeter.go:180, kernelconfirm.go:189
- **The interactive shape (N1's default).**
  - The plan is read as the granted reader.
  - Where this device holds a reader role that is not yet granted, a plan that reads the cluster is refused, naming `reader grant`. connect's, redeploy's, `reader grant`'s and `git-credential`'s plans read no cluster and are unaffected.
  - Where the instance has no reader route at all (fallback 3 without fallback 2), the command shows a summary from the record alone. The summary says its live reads were not made. Then it asks, and the writer reads and acts after the yes.
  - `--yes` opens the writer at the start. `planRead` (clusterref.go:309-314) follows.
- **A new plan fact, `identity_route`,** in every cluster-writing plan, bound into the digest. Fallback 3's line says "Google made this key; it does not expire". The plan vectors are regenerated; they are not Swift-copied.
- **Texts.**
  - `writerRefused` names "the instance's writer service account".
  - `loadInstallerKey`'s text (:193) is reworded for fallback 3.
  - A device that holds no writer role gets `credential_missing` with the remedy `device add <instance> --role writer` (§11, gap 13).
- **Custody.** `custodyCallers` lists the `OpenForWrite` and `GiveConsent` sites.

**Owns.**
- R7: a writer key opened under any purpose but a consented write, a renewal or an enrolment.
- R6: a reader leaf renewed with the writer anchor key, or a writer leaf renewed outside a consented command.

The tests:
- `TestWriterNeverOpensBeforeConsent`: each of the 13 writing commands, interactive with a "no", leaves no writer purpose in the log and no writer exchange.
- `TestYesIsWriterConsent`.
- `TestConfirmOpensTheWriterAfterTheComparison`.
- A writer leaf due for renewal renews only after consent.
- The reader leaf's renewal never opens `writer/`.

**Delivers.**
- "Custody at every command" (S3c).
- The `clusterref.go:159`/`:193` clause (S8c).
- The fallbacks' plan fact (S10d).

**Size.** About 650 product lines and 1,300 test lines, across 12 command files.

**Risks.**
- The interactive UX changes on an instance whose reader is not yet granted.
- Under a Q24 "no", scripts need `--plan` and `--confirm`.

### M3b.9: planck and the registry through role tokens; registry writes after consent

**Changes.**
- **New file `cli/googlecreds.go`: `roleTokens(dir, meta, role, consent, consumer)`,** for every route:
  - federated, on the certificate route;
  - kube's 2LO over `reader.key` or `credentials.yaml`, on the fallbacks.

  The CLI never hands planck an empty credential or SA JSON. A go/ast scan checks that every `planck.Open` in cli passes `Tokens`. planck's SA-JSON loaders stay for the harness only, a small departure from D6's sentence, recorded.
- **`providerOpener` (fatline.go:160)** becomes `(meta, roleSource)`.
  - `defaultProviderOpener` builds `planck.Config{Tokens}`.
  - toolchain's opener (toolchain_cmd.go:75-77) moves to the refusing seam.
  - Commands that plan and then realize open two providers, because of the lazy caches (gke.go:57-60).
- **`registryAccess` splits.**
  - `planRegistry` keeps the writer route's token on the fallback routes until M3b.11, and refuses on the certificate route (§4).
  - `realizeRegistry` runs as the writer, after consent.
- **No Google write before consent.**
  - `registryForPlan` and `deployRegistry` (:642-646, :704-707) stop ensuring before the plan. The plan states `create_repository`, and the ensure runs after consent.
  - connect's reconnect ensure (connect.go:499-510) is skipped. A missing repository is reported, and the next deploy re-ensures it after consent.
  - `toolchain` gains a terminal question and `--yes` (N2).
  - The package-level `ensureRegistry` (fatline.go:551-557) goes.
- **`fatline.go:168` moves.**

**Delivers.** S8d (`fatline.go:168`).

**Tests.**
- `TestNoGoogleWriteBeforeConsent`: a recording planck fake; an interactive "no" makes no `EnsureRegistry`.
- `toolchain` without a terminal or `--yes` is refused.
- The opener fakes in about 31 files: a mechanical change.

**Size.** About 550 product lines and 1,100 test lines.

**Risks.** Test churn.

### M3b.10: storage, secrets and `release` through role tokens

**Changes.**
- **storage.**
  - `storage.Options` gains an explicit role.
  - `storage.Open` (storage.go:83-134) stops reading `credentials.yaml`.
  - `OpenBucketGrants` takes a token source, and `openBucketGrantsDefault` the role.
  - GCS gets `ScopesStorage`.
- **Writes after consent.**
  - `storage cp`'s upload, after a question or `--yes` (N2).
  - `secret set`, after a question read from the controlling terminal, never stdin, or `--yes`, or `--from-file`.
  - `storage rm` and `secret rm` list first (pinned until M3b.11), then open the writer after their question: two sessions.
- **`release`, whole.**
  - `LoadInstanceCredentials` goes.
  - The gate stays pinned until M3b.11.
  - planck and storage open as the writer after the retype (`ConsentAnswered`) or `--yes` (`ConsentYes`).
  - `releaseReaderOf` stays, for an `uploaded_key` reader only.
- **The call sites move:** `release.go:143`, `storage/storage.go:98`, and `storagedeploy.go:140` through `storage.go:238`.
- **A scan:** only `roleTokens`' fallback-3 branch reads `credentials.yaml`.

**Delivers.** S8e.

**Tests.**
- `secret set`'s question never reads stdin.
- The writer in `rm` opens only after the question.
- `release`'s writer opens only after the retype.

**Size.** About 550 product lines and 1,100 test lines.

**Risks.** GCS scope handling in the role token source.

### M3b.11: D5, the reader's resource-scoped reads (Q9)

**Goal.** No plan or read command presents a writer token. The project number comes from the record.

**Changes.**
- **The recorded number.**
  - `readPushGrant` (buildgrant.go:143-195) and `readBucketGrant` (storagedeploy.go:1140-1202) take `Identity.ProjectNumber`, parsed to an `int64` > 0.
  - `GrantReader.ProjectNumber` leaves the plans.
  - Its "never recorded" contract (planck/registry.go:126-128) is amended:
    - on the certificate route, every exchange's audience embeds the number, so a successful exchange proves it [inf];
    - on the fallbacks, `install` reads it once as the writer (M3b.14).
  - A record with no number makes the plan print the existing `PROJNUM=` line.
- **The grant writers.**
  - planck gains `RegistryRoleGranter`, which reuses `getPolicy`, `setPolicy` and `grantRole` (registry.go:452-476). It is never inside `EnsureRegistry`, which runs under `--yes`.
  - gcs gains a member-grant variant, because `checkGrantArgs` (gcs/iam.go:212-231) refuses an empty shared principal.
- **Plan facts,** each never covered by `--yes`:
  - `set_reader_repository_grant`, in `connect`;
  - `set_reader_bucket_grant`, in `storage deploy`, after `mintStorage`, in the same consented run.

  The first plan before its grant states its lookups as "not yet readable by the reader". They are then made after the grant, as the writer, under the same consent (DES:1198's default).
- **Reads as the reader:**
  - `planRegistry`, `RegistryGrant`, and the bucket's `Validate` and `GrantState`;
  - `storage ls`, `storage usage` and `storage cp`'s downloads;
  - `secret ls`;
  - `release`'s gate (N11): as the reader when one is granted; otherwise after the retype, as the writer, before any delete. The "scope shown first" order is lost only there, and the gate line says so.
- **Roles (N3):**
  - `roles/artifactregistry.reader` on the repository;
  - `roles/storage.objectViewer` and `roles/storage.legacyBucketReader` on the bucket.

  Both are [unverified] as the smallest. A policy read the reader cannot make reads `GrantUnknown`, which plans already state.

**Owns.** R9: one of the installer-minted reads presenting a writer token. `TestInstallerMintedReadsPresentTheReader` has one subtest per read in D5's list, and the planck and gcs fakes record the token's role.

**Delivers.** S9.

**Tests.**
- `TestReaderGrantsNeverUnderYes`.
- The first-deploy plan vector.
- `release`'s gate on both paths.

**Size.** About 500 product lines and 1,000 test lines.

**Risks.**
- Role sufficiency, settled at the walk.
- The reader now reaches ciphertext and plaintext images (Q9's trade).

### M3b.12: documents, warnings, kinds, the rehearsal and the line vectors; Swift lockstep

**Changes (Go).**
- **`instances`.**
  - Each entry gains `identity: {routes: {reader, writer}, roles, anchor: ok|expiring|expired}`, from the record's `AnchorNotAfter` and `Roles()`, which only stat. No ID, number, pool, provider or role ID appears in it. *(2026-11-26, M3b.1: `anchor` from `AnchorWarnsAt` and `AnchorExpiredAt` on the record's `AnchorNotAfter`.)*
  - A top-level `pending: [{name, kind, state, since, stale}]`, stale after 7 days by the `now` seam. An errored entry is reduced to its name and error.
  - The human table gains a pending section, and "No instances on this machine" (:203) is fixed.
  - The leak check (cmdvectors_test.go:88-92) covers the new pseudonyms.
- **`world`.**
  - `worldInstance.identity`.
  - A sixth section, `identity` (N6), with its own kind and a deadline under the 60 s ceiling. It lists providers as the reader (`IAMReader`) and reports `{read, known, unknown}`.
  - New alerts: `anchor_expiring` (45 days), `anchor_expired`, `unknown_provider`, and one for the fallback route. Each takes subject `instance` or `operator`. An unknown provider is never a device.
- **The router** (cli.go `run`, after `config.Load` :160-169) warns on stderr only, with a clock seam, about:
  - a pending install older than 7 days;
  - an anchor within 45 days of its end, or past it, from the records alone, never reading `writer/` files.

  A record that fails to load gives no warning.
- **Kinds.** `credential_expired` (N4) replaces M3b.7's interim mapping. It moves `errorKinds` (kinds.go:47-54), the README kinds list and `testdata/kinds/kinds.json`.
- **Schema 3** (N5), in `worldSchema`.
- **The line vectors.** `testdata/coordinates/` joins check.sh:397's list.
- **The rehearsal** moves to the certificate route (N12): `kubetest.Federation.Start`, the IAM API fake, an identity-store fixture and an `Identity` record.
- **README.** "What each read tells the provider" gains `world`'s identity section, and states that `instances` opens no key.

**Changes (Swift, same step).**
- `CLIDocuments.schema` = 3.
- `WireListing.pending`, `CLIListing` and a `PendingInstall` model. `CLIReader`'s allowed set excludes pending names.
- `WireListingEntry.identity` and `InstanceListing`, with word tables.
- `WireInstance.identity`.
- The sixth `Section` case, the `WireSections` field and the mapping list (CLIDocuments.swift:426-438).
- `WorldAlert.Kind`, `alertKind`, and the kind table (:90-114).
- `ProblemText.remedy` rewritten for `device add`, `device renew` and `reader grant`.
- A minimal line parser and its test, over the copied coordinates vectors (N8).
- The vectors, copied byte for byte.

**Owns.**
- R18a: a pending install not listed by `instances`, or listed without its state or age.
- R18b: a warning before 7 days, or none after (tested at 6 d 23 h and at 7 d).

**Delivers.**
- S12;
- S2a (listing) and S2b (warning);
- S4d (`world` marks unknown providers).

**Tests.**
- `TestInstancesOpensNoKey`: the purpose log holds `Open` and `Roles` only, with a FIFO `leaf.key` (nosecrets_test.go:129/:173 technique).
- `TestInstancesReadsOnlyTheRecords` allows `pending.yaml`.
- R5's table gains `world`'s identity section.
- New vectors:
  - `instances/pending.json`, `instances/certificate.json`;
  - `world/certificate_route.json`, `anchor_expiring.json`, `unknown_provider.json`, `fallback_route.json`, `identity_unreadable.json`.

**Size.** About 800 Go lines, 450 Swift lines and 900 test lines.

**Risks.**
- Breaking the lockstep.
- Every Refresh now adds STS, IAM Credentials and IAM API calls, which is new provider visibility.

### M3b.13: `release`'s teardown block

**Changes (release.go).**
- **Before the confirmation:** `setupblock.Release` is rendered from `CheckedIdentity`, and is route-aware. On fallback-3 records made before M3b.14, no IAM teardown is printed, as at 4bbbb5f.
- **The gate line** says the writer keeps its project roles, and its provider stays trusted, until the block is pasted.
- **The block** is printed after `DeleteCluster`, with the node SA after the cluster. JSON gains `teardown {block, sha256}`.
- **The keys:** `identity/` is erased with `Store.Erase` before `RemoveInstance`.
- **Failure:** a failed `DeleteCluster` keeps status `deleting`, so a rerun reprints the block.
- **"No such instance"** (:101-107) names `install --name X --abandon` when a pending entry exists.
- **New: a crashed install** (§11, gap 9). A record in status `provisioning` whose cluster never existed (install crashed after `AdoptPending`) releases cleanly: absent objects are skipped, the block is printed, and the record is removed.

**Delivers.** S5b, `release`'s teardown block.

**Tests.**
- `TestReleaseRendersBeforeRemove`.
- `TestReleaseWriterAfterRetype`.
- `TestReleaseProvisioningWithoutCluster`.
- R16's `Release` shape, wired: the printed block equals the generator's.

**Size.** About 300 product lines and 600 test lines.

**Risks.** The block is the only copy once the record is removed (pitfall 14). JSON carries it, for the app to keep.

### M3b.14: `install` from the paste; fallback 3; pending, resume and abandon; the node account required (X2 decided)

**Changes.**
- **planck (in this commit).**
  - An empty `NodeServiceAccount` is refused in `planCreate` and `planEnsureRegistry`.
  - `nodeServiceAccountFmt` and `nodeServiceAccountMember` are deleted.
  - `grantPull` makes no `projects.get`.
  - The registry tests move: registry_test.go :137-185, :206-227, :490-495, :1161-1196 and :1198-1230; registry_integration_test.go:130-131.
  - The fixtures move: install_test.go:164, writecommands_test.go:3172, config/instance_test.go:89.
  - In cli, `registrySpec` and `recordRegistry` (connect.go:846-884) record `Puller` as the node account.
- **`install`, in D7's order** (pitfall 10.1):
  1. `validateInstanceName`, then refuse a name already recorded (`InstanceExists`) or pending (`PendingExists`, naming `--coordinates` and `--abandon`). Both are local reads, made before any key. :115-121 moves ahead of :100-112.
  2. Draw the pool, the two provider IDs, the three SA IDs and the condition title. Persist `pending.yaml` (kind `install`, state `keys_made`) before showing anything.
  3. `devicekey.Enrol(rand.Reader, PendingIdentityDir, [Reader, Writer], now)`.
  4. Show the anchor PEMs, `setupblock.Setup` and its SHA-256, and the console guide. Mark `setup_shown`. `--setup-only` exits here. In JSON mode it prints `{anchors, block, sha256, guide}`.
  5. Take the setup line at the prompt, or through `--coordinates`, which is the only way in JSON mode. Mark `coordinates_received`.
  6. `verifyEnrolment` for both roles, with the in-memory identities, or `OpenForEnrolment` when resumed. *(2026-11-26, M3b.1: the pending state records "verified" before `EnrolmentVerified`, and a resume that meets `ErrNotEnrolling` has nothing left to verify.)*
  7. `planck.Open` with the reader's tokens, then `Validate`, as the reader [inf: `clusterViewer` carries `container.clusters.list`].
  8. `warnIfBelowFloor`, then consent by y/N (`ConsentAnswered`) or `--yes` (`ConsentYes`).
  9. `AdoptPending`, which puts the record, `Identity` and the keys in place before any cluster call. A resume that finds both a record and a pending entry runs `ResumeAdoption`.
  10. `planck.Open` with the writer's tokens, then `CreateCluster` with `NodeServiceAccount`, the registry with the node account as puller, and the health check.
- **`--abandon`.**
  - It acts on a pending entry of kind `install` only, and refuses when a record exists.
  - It prints `setupblock.Abandon` from `pending.yaml`'s IDs, with its SHA-256, and JSON `teardown`.
  - It erases the pending keys (`Store.Erase`), then the entry.
- **Fallback 3, `--google-made-key <file>`** (Q16's specifics):
  - the `GoogleMadeKey` block and console steps;
  - a terminal question only, "Google made this key; it does not expire". It is never under `--yes`, and refused when not interactive;
  - the key's `client_email` must equal the drawn writer SA (§11, gap 8);
  - the number comes from the line, and is checked by one `projects.get` as the writer after the question (D2's install read);
  - the routes: writer `google_made_key`; reader `none` until `reader init` (N14).
- **Removed:** `--credentials`, `readCredentials`, `msgCredentialsRequired` and `msgCredentialsEmpty`.
- **`installResult`** gains `identity_route` and `roles`.
- **Custody:** `install.go`'s importer, and its `Enrol` and `OpenForEnrolment` sites, are listed.
- **X2:** enforced as decided (§7).

**Owns.**
- R19: an install that makes a key, or shows a block, for a recorded or pending name (an `Enrol` seam proves no key is made); or that calls `CreateCluster` before the record holds the keys and the coordinates. A fake planck checks both crash windows.
- R18c: `--abandon` printing other than exactly the setup's teardown, leaving a pending key, refusing a pending install, or acting on a finished record.

**Delivers.**
- S1;
- S2c (abandon);
- S5a (random IDs, a pool and three SAs per instance);
- S7b (`grantPull` and the metadata name the node account; the default compute account is gone);
- S10a (fallback 3).

**Tests.**
- `TestInstallFromThePaste`:
  1. `gcloudtest` runs the shown block.
  2. Its state feeds the federation fakes.
  3. The line is typed at the prompt.
  4. The planck fake asserts `Validate` with the reader's token, and `CreateCluster` with the writer's token and the node account.
- Resume through `--coordinates` in a new process.
- `TestInstallSetupOnlyIsReproducible`: one digest across processes.
- `TestInstallRefusesAForeignLine`.
- `TestGoogleMadeKeyNeverUnderYes`.
- `TestGoogleMadeKeyMustNameTheDrawnWriter`.
- The R15 regression: an empty node account is refused.

**Size.** About 950 product lines and 1,700 test lines (`install_test.go` rewritten).

**Risks.**
- `Validate` as the reader is [inf].
- Autopilot and the node account are [inf].
- Settle timing.
- The pause and the paste are new to the operator.

### M3b.15: `device coordinates`, `ls`, `known` and `rm`

**Changes (`cli/device.go`).**
- **`coordinates`** prints the device-coordinates line from the record.
- **`ls`** runs `ListProviders` as the reader, then `ParseProviders`. Each provider is labelled own (from the record's `Roles`), known (`Identity.Known`) or unknown, with `DELETED` handled. *(2026-11-26, M3b.1: `ParseProviders(list, number, pool)`; providers are labelled by provider ID only, never by `RoleID`.)*
- **`known <instance> <line>`** runs `ParseDeviceLine`, then `UpdateInstanceMetadata`, merged per key.
- **`rm <instance> <provider>…`, or `--role writer`:**
  - The role ID comes from this machine's anchor for its own providers, or from `RoleIDFromCondition` on a reader read for others. *(2026-11-26, M3b.1: from `ParseProvider`'s `RoleID`, which reads the mapping and the condition, never from `RoleIDFromCondition` alone.)*
  - It prints `setupblock.DeviceRm` with its digest.
  - After a y/N or `--yes`, it erases only this machine's own roles (`RemoveRole`; the reader is refused while the writer stays). *(2026-11-26, M3b.1: `RemoveRole` runs under one per-instance lock, which M3b.16's `AddRole(Writer)` takes too: without it, a `RemoveRole(Reader)` racing another process's `AddRole(Writer)` can leave a writer alone, and M3b.2's config has no such lock.)*
  - It warns before revoking the last writer-capable device this machine knows of.

**Owns.** R17: `device rm` printing, for a provider this machine did not make, a binding removal not taken from that provider's condition, or erasing this machine's keys for a provider it did not make.

**Delivers.** S4a: `coordinates`, `ls`, `known` and `rm`, removing the writer role included.

**Tests.**
- The `ls` labels.
- R16's `DeviceRm` shape, wired.

**Size.** About 450 product lines and 750 test lines.

**Risks.** The reader cannot see another principal's binding on an SA (stated in D4).

### M3b.16: `device add` and `device renew`

**Changes.**
- **`device add <instance> --role reader|writer`** (reader by default, Q8).
  - **On a device holding the reader:** `AddRole(Writer)`, then `AddWriterRole`'s block, then Enter, then `verifyEnrolment` for the writer. That includes the writer provider's read-back. *(2026-11-26, M3b.1: `AddRole(Writer)` runs under `rm`'s per-instance lock (M3b.15), and the verification is followed by `EnrolmentVerified(Writer)`.)*
  - **On a new machine (N7):**
    1. Take the device-coordinates line.
    2. Make a pending entry of kind `device_add`, then `Enrol` into it.
    3. Show `AddDevice`'s block, then wait for Enter, then verify.
    4. Create the record through `AdoptPending`:
       - the region comes from the line;
       - the endpoint from `planck.Open` as the reader;
       - the cost limit from the kernel's in-cluster record, read as the reader, or "unknown";
       - no FatLine PKI and no keyring are transferred, and the command says so.
  - **`device add <instance> --abandon`** prints `AbandonDeviceAdd`, this device's providers only, never the pool or the SAs, and erases the pending keys (§11, gap 7). `install --abandon` refuses a `device_add` entry.
  - It ends by printing the device line.
- **`device renew`.**
  1. Per role: `RenewAnchor`, then `Renew`'s block, then Enter.
  2. `OpenStaged`: the writer's under the command's y/N or `--yes`.
  3. Exchange and impersonate under the settle rule.
  4. The read-back: the provider's trust store must now hold the new anchor alone (§11, gap 6).
  5. `CommitAnchor`, then the record's `AnchorNotAfter`.

  It resumes from `StagedCertificates`. `--discard` is allowed only while the current leaf still exchanges (walkm3a_test.go `stepRenewDiscard`). *(2026-11-26, M3b.1: a resume that meets `ErrRenewalInterrupted` runs `CommitAnchor`, then reads `CurrentCertificates` for the record's `AnchorNotAfter`.)*
- **Custody:** the `AddRole`, `RenewAnchor`, `OpenStaged`, `CommitAnchor`, `Enrol` and `OpenForEnrolment` sites are listed.

**Owns.** R8: a role ID derived from a key, a name or a counter, or changed by an anchor renewal.
- Renewal keeps the role ID and the record's provider.
- devicekey's derivation mutants are re-run.

**Delivers.** S4b (`add` with the writer role, and `renew`). That completes §7's device bullet, and "the read-back in every enrolment" (S4c).

**Tests.**
- Add end to end through `gcloudtest` and the federation fakes: reader-only, then the writer added and removed.
- Commit only after a successful exchange.
- Discard refused when the current leaf no longer exchanges.
- The R6 and R7 regressions for renewal.

**Size.** About 800 product lines and 1,300 test lines.

**Risks.**
- A staged leaf can expire before commit (pitfall 7); the default is to stage again.
- A new machine's record lacks FatLine and the keyring.

### M3b.17: fallback 2 for both roles

**Changes.**
- **`install --uploaded-key`** (Q16):
  - RSA-2048 per role (`kube.NewReaderKey`);
  - `setupblock`'s upload variant: `InstancePart` plus the two uploads, with no pool and no providers;
  - the line back carries the number and the two key IDs;
  - the number is checked by one `projects.get` as the writer, after install's question.
- **`reader init` and `reader record`** become fallback 2:
  - they adopt D3's random names, with no display name;
  - readerinit.go:404 and :409 are reworded to name the policy and the routes still open.
- Fallback 2's `device add` stays out of scope, and is stated.

**Delivers.** S10b: fallback 2, `reader init` and `record`, and the reworded messages.

**Tests.** The R20 and R13 regressions for the variant, and the `identity_route` lines.

**Size.** About 1.5 d.

**Risks.** It cannot be walked in the operator's organization, where upload is blocked.

### M3b.18: fallback 1, OIDC with one single-key JWKS per role (separable)

**Changes.**
- **kube:** an `STSHost` constant (sts.googleapis.com), and an ES256 JWT subject-token exchange through the leaf's `crypto.Signer`. It sends no client certificate.
- **devicekey:** a role key's JWKS. It is ported from `m3aES256JWT` and `m3aJWKS`, with V5's mapping and condition.
- **`setupblock`:** the `createOIDC` variant, with the JWKS in a here-document. The console route takes the JWKS as a file the CLI writes.
- **Routes:** `public_key`.

**Delivers.** S10c.

**Tests.** The R1-R4 and R10 regressions for the plain STS host. The JWT never formats.

**Size.** About 1.5 d. If the operator defers it, a dated note in ADR 0024 says so.

### M3b.19: the records sweep and the walk runbook

- `docs/runbooks/adr-0024-m3b-walk.md`, written and not run.
- The README sweep.
- The design's "Amendments from M3b's build".
- Dated notes (§8).
- About 1 d.

**Review rounds,** as M3a's: security, correctness and tests reviews after M3b.8, after M3b.14 and after M3b.16. Each finding is checked against the code, then overlay mutants run per area, under the sandbox profile.

---

## 6. Coverage

Each item has exactly one owner, the step that delivers it. "Built on" and "kept green by" are prerequisites and regressions, not delivery. §7's multi-part bullets are split into their clauses, and R18 into its three semicolon-separated rows.

### §7 bullets

| §7 bullet (clause) | Owner | Built on | Kept green by |
|---|---|---|---|
| S1 Certificate route for installer, writer and reader; `install --name` with no `--credentials`; keys, show, paste, line back, verify, install; the pending directory makes it resumable | M3b.14 | M3b.1-M3b.13 | — |
| S2a Pending installs listed by `instances` with state and age | M3b.12 | M3b.2 | M3b.14 |
| S2b A warning from every command after 7 days | M3b.12 | M3b.2 | — |
| S2c `install --abandon` | M3b.14 | M3b.5 (block) | — |
| S3a Two roles per device, each with its own provider | M3b.5 | M3b.1 | M3b.14, M3b.16 |
| S3b D2's custody rules in `devicekey` (enrolment purpose, `--yes` kind, `RemoveRole` guard) | M3b.1 | M3a | — |
| S3c Custody kept at every command site | M3b.8 | M3b.7 | M3b.14, M3b.16 |
| S4a `device coordinates`, `ls`, `rm`, `known`; removing the writer role | M3b.15 | M3b.3, M3b.5 | — |
| S4b `device add` (adding the writer role) and `device renew` | M3b.16 | M3b.6 | — |
| S4c The read-back in every enrolment | M3b.16 (the last enrolment path) | M3b.6 (`verifyEnrolment`); M3b.14 (install's) | — |
| S4d `world` marks unknown providers | M3b.12 | M3b.3 | — |
| S5a Random IDs, a pool and three SAs per instance | M3b.14 | M3b.1, M3b.5 | — |
| S5b `release`'s teardown block | M3b.13 | M3b.5 | — |
| S6 The setup-block generator (digest, readerinit-style shell, neutral tags, random condition title, one provider per role, YAML trust stores, node account, two WI counts, writer allowlist with the actAs rule) and the console guide | M3b.5 | M3b.1 | M3b.17, M3b.18 (variants) |
| S7a The node account in planck: `buildCluster` names it, and a test checks the create request | M3b.4 | — | M3b.14 |
| S7b `grantPull` and the instance's metadata name it in place of `nodeServiceAccountFmt` | M3b.14 | M3b.4 | — |
| S8a D6: the federated `kube.Credential` | M3b.3 | — | — |
| S8b D6: token providers for planck and datasphere | M3b.4 | — | — |
| S8c `clusterref.go:159` with its check at `:193` | M3b.8 | M3b.7 | — |
| S8d `fatline.go:168` | M3b.9 | M3b.4 | — |
| S8e `release.go:143`, `storage/storage.go:98`, `storagedeploy.go:140` through `storage.go:238` | M3b.10 | M3b.4 | — |
| S9 The installer-minted reads (D5): reader's resource grants as consented acts; `projects.get` replaced by the recorded number | M3b.11 | M3b.9, M3b.10 | — |
| S10a Fallback 3 behind its flag and question | M3b.14 | M3b.5 | — |
| S10b Fallback 2; `reader init` and `record` as fallback 2; readerinit.go:404 and :409 reworded | M3b.17 | M3b.14 | — |
| S10c Fallback 1, one provider per role | M3b.18 | M3b.14 | — |
| S10d The fallbacks' plan fact `identity_route` | M3b.8 | M3b.2 | — |
| S11 ADC out of the CLI; `GOOGLE_API_CERTIFICATE_CONFIG` unset | M3b.4 | — | M3b.9, M3b.10 |
| S12 `instances` and `world` gain route, roles and pending; Swift in lockstep | M3b.12 | M3b.7 | — |

### §7 mutation rows

| Row (DES line) | Owner | Kept green by |
|---|---|---|
| R1 A bearer to a host other than IAM Credentials' (:1082) | M3b.3 | M3b.18 |
| R2 The client certificate to a host other than STS's (:1083) | M3b.3 | M3b.18 |
| R3 The environment proxy honoured (:1084) | M3b.3 | M3b.18 |
| R4 A URL taken from input or a file (:1085) | M3b.3 | M3b.18 |
| R5 A read command or plan opening a writer key, exchanging the writer leaf, or impersonating the writer (:1086) | M3b.7 | M3b.12 (`world`'s identity section) |
| R6 A reader leaf renewed with the writer anchor key, or a writer leaf renewed outside a consented command or `device renew` (:1087) | M3b.8 | M3b.16 |
| R7 A writer key opened under a purpose other than a consented write, a renewal or an enrolment (:1088) | M3b.8 | M3b.14, M3b.16 |
| R8 A role ID derived from a key, name or counter, or changed by an anchor renewal (:1089) | M3b.16 | — |
| R9 An installer-minted read presenting a writer token (:1090) | M3b.11 | — |
| R10 A response body in an error (:1091) | M3b.3 | M3b.18 |
| R11 A provider accepted by the read-back with another trust anchor or another ID (:1092) | M3b.6 | M3b.14, M3b.16 |
| R12 Two anchors in one provider, or two IDs in one condition (:1093) | M3b.5 | — |
| R13 A trust-store file that is not Google's YAML with exactly one anchor, its `pemCertificate` the anchor's DER (:1094) | M3b.5 | M3b.17 |
| R14 A WI count missing a member form, a basic or custom role, or a binding on an SA or the project; or a nonzero count not stopping before any create (:1095) | M3b.5 | — |
| R15 A cluster create request that does not name the node account (:1096) | M3b.4 | M3b.14 (empty refused) |
| R16 A teardown block (abandon's, release's, `device rm`'s) stopping at an absent object, after every prefix, with `DELETED` left (:1097) | M3b.5 | M3b.13, M3b.14, M3b.15, M3b.16 (wired) |
| R17 `device rm`: a binding removal not taken from the foreign provider's condition, or erasing keys for a provider it did not make (:1098) | M3b.15 | — |
| R18a A pending install not listed, or listed without state or age (:1099) | M3b.12 | M3b.14 |
| R18b A warning before 7 days, or none after (:1099) | M3b.12 | — |
| R18c `install --abandon` printing other than the exact teardown, leaving a pending key, refusing a pending install, or acting on a record (:1099) | M3b.14 | — |
| R19 An `install` that makes a key or shows a block for a recorded or pending name; or calls `CreateCluster` before the record holds the keys and coordinates (:1100) | M3b.14 | — |
| R20 A setup block containing `farcast` outside the condition prefix, or the instance's name (:1101) | M3b.5 | M3b.17, M3b.18 |

§7's walk items are in §9.

---

## 7. Operator questions

### Ask before M3b.1

Each of these has a default this plan would build, but either the default is risky or the answer changes a first step's code.

1. **Q24: `--yes` as writer consent on the CLI.**
   - **Default:** yes, as a distinct `ConsentYes`. It never covers what ADR 0023 keeps from `--yes` (`reader grant`, `--embedded`, `run --yes` at the limit), never selects fallback 3, and never applies on the Mac, whose broker keeps `--confirm` alone.
   - **Why it matters:** it decides whether a scripted run opens the writer's anchor and leaf keys with no human. It shapes devicekey's consent kinds (M3b.1) and every writer site (M3b.8), `release --yes`, `install --yes`, and N2's three commands.
   - **If no:** scripts need `--plan` and `--confirm`. Commands that have no plan, `release`, `install`, `toolchain`, `secret set` and `storage cp`, lose scripting.
2. **Q3: IAM's API host as one more bearer host, for the reader's SA token only.**
   - **Default:** yes, by a dated note on D6.
   - **Why it matters:** it widens D6's bearer-host rule, and it adds a provider-visible IAM read to every enrolment, every `device ls` and every `world` refresh. Without it there is no read-back, which is D4's binding check, no `device ls`, and no unknown-provider mark, so D4 reopens. It blocks M3b.3.
3. **X2: where the identity store lives, and whether the ACL limit is enforced.**
   - **Default placement:** `instances/<name>/identity` and `pending/<name>/identity`, both under the 0700 config root.
   - **Default enforcement:** mode bits only, the limit documented, and `ls -led` checked at the walk. A darwin-only check, with stubs for the linux and windows builds, is added only if M3b.2's spike shows that a cgo-free raw `getattrlist` through the already-linked x/sys/unix reports an ACL. That is [unverified]: x/sys has the constant but no wrapper.
   - **Why it matters:** M3b places real anchor keys there. An inherited ACL can let another account read a 0600 writer anchor key, which mints project-wide writer tokens for up to 390 days.
   - **When:** the placement blocks M3b.2; the enforcement decision is due before M3b.14.
4. **Q9: the installer-minted reads run as the reader, with resource-scoped grants.**
   - **Default:** yes, with `projects.get` replaced by the recorded number.
   - **Why it matters:** it is the riskiest trade in M3b. A leaked reader token then reaches the instance's ciphertext and its plaintext images: FarCast's own components and the operator's applications. The alternative puts writer tokens into plans, which breaks ADR 0023's broker rule. It is built at M3b.11, but it frames the reader's role in every step before it.

### Can stay at their defaults until the named step

| Question | Default | Settle by |
|---|---|---|
| N1 Interactive plans | As the granted reader. A reader role that is present but not granted refuses, naming `reader grant`. With no reader route at all (fallback 3 alone), a record-only summary that says its reads were not made. Alternatives: strict everywhere; summary everywhere (Plan A); fold the reader's RBAC into `connect`. | before M3b.8 |
| N10 `world` may renew the reader leaf | Allowed, and Usage says so | before M3b.7 |
| N9 Per-consumer impersonation scopes (amends D5.2 for non-cluster consumers) | cluster `TokenScopes`; storage `devstorage.full_control`; registry `cloud-platform` | built at M3b.3; reversing it later is local |
| N2 `storage cp` uploads, `secret set` and `toolchain` gain a question | A terminal question, never stdin, plus `--yes` | before M3b.9 |
| Reconnect's registry ensure | Skipped; the next consented deploy repairs it | before M3b.9 |
| N3 The reader's resource roles | `artifactregistry.reader`; `storage.objectViewer` with `legacyBucketReader`; unreadable policies read `GrantUnknown` | before M3b.11; settled at the walk |
| N11 `release`'s gate without a reader | After the retype, as the writer, before any delete | before M3b.11 |
| N4, N5, N6 | A `credential_expired` kind; schema 3; a sixth `identity` section reading providers on each refresh | before M3b.12 |
| N8 Line vectors in Swift | Copied, with a minimal Swift parser and test (DES:1196's "with the Swift vectors"). Alternative: Go only until the GUI install. | before M3b.12 |
| N12 The rehearsal | On the certificate route | before M3b.12 |
| Q16's specifics | `--google-made-key <file>` and `--uploaded-key`; fallback 3 lands with `install` | before M3b.14 |
| N14 A reader under fallback 3 | None unless fallback 2 is open (`reader init`) | before M3b.14 |
| Q13 Neutralising the marks | Opened as its own item; the generator takes the bucket prefix as input. A random bucket prefix would be a planck and datasphere naming step, landed before M3b.14 | before the walk |
| N7 `device add` on a new machine | Records from the line (with the region) and from reader reads; no PKI, no keyring | before M3b.16 |
| §9.4's reading | Renewal means an anchor's paste; leaves renew on the device | before M3b.16 |
| Fallback 1 in M3b | Yes, since §7's condition is met | before M3b.18 |
| Q5 Records | Each step's records written last, after `./check.sh`; no cited line moved (D10). Alternative: one records commit at the end (Plan B) | each step |
| Q4, Q6, Q7, Q8, Q11, Q14 | TLS 1.3 for the exchange and 1.2 elsewhere; 390 days; Cloud Shell first, console beside it; added device is a reader; pending listed and warned, never erased by age; `kube.UserAgent` | stay |
| Q12 / V8 | Per-device subject | at the walk |
| Q1, Q2 | Probe-only; no M3b code | — |
| Small build defaults | `--condition-from-file`; the storage API in the enabled set; condition title 30 characters `[a-z][a-z0-9]`; an eight-value setup line; the release block carried in output only | at the walk |
| The walk's G0 approval | Billable, with a USD 5 cap like M2's | after M3b.19 |

---

## 8. Records each step updates

Each step appends, after `./check.sh` passes, and moves no cited line (D10):
- a dated note in PLAN.md's M3b line;
- a dated note in ADR 0024's Phasing M3b row;
- a dated note in ADR 0023's M3b row;
- "Amendments from M3b.N's build" at the end of the design;
- the sections of `farsight/cli/README.md` it changes:
  - the layout (:226-272, :1732);
  - the documents (:1408-1500);
  - who reads as whom (:1536-1590);
  - the kinds list.

The further records, by step:

| Step | Further records |
|---|---|
| M3b.3 | The design amendments for D5.2's scopes and the audience's narrowing; Q3's dated note on D6 |
| M3b.4 | planck/README.md:354; datasphere's README (`Ambient`) |
| M3b.7 | The README's per-read provider exposure (:1671) |
| M3b.9, M3b.10 | ADR 0007 :32 and :38; the comments at registry.go:588-600; AGENTS.md's ADC and `credentials.yaml` sentences, rewritten in place |
| M3b.11 | ADR 0019 :95; AGENTS.md's "Still minting the installer's" sentence |
| M3b.12 | `client/apple/README.md` (the vectors) |
| M3b.14 | AGENTS.md's "`install` refuses a missing `--credentials`"; ADR 0007:61 closed; dated notes in phase-1-validation.md:95 (now fallback 3) and phase-3-validation.md:71 (the condition now in the block) |
| M3b.19 | The walk runbook and the sweep |

Commit only when the operator asks.

---

## 9. The billable M3b walk

**Before.**
- M3b.1 to M3b.17 built; M3b.18 optional.
- `./check.sh` green on the walked commit.
- A release `farcast` from `farcast-release`.
- The runbook from M3b.19.
- Q13 answered.
- G0 approval:
  - billable, and hard to reverse, since deleted IDs stay reserved for 30 days;
  - a cap like M2's, USD 5;
  - about USD 1-2 by the floor model [inf];
  - a fresh project in the operator's own organization, where key upload is blocked.

**Setup.**
- The Mac has no gcloud, kubectl, Go or service-account key.
- `GOOGLE_APPLICATION_CREDENTIALS` is set to a decoy path, which must never be read.
- Little Snitch rules are set per host for the release binary: sts.mtls, iamcredentials, iam, container, the DNS endpoint, Artifact Registry and Storage. `oauth2.googleapis.com` must never be contacted, which is the evidence that no 2LO mint ran.
- The operator pastes and types every confirmation. The agent offers console changes in the built-in browser, one explicit yes per change.

**Steps.**
1. Baseline counts. The project's user-managed key count is 0, and stays 0.
2. `install` from the paste.
   - The WI counts read 0 and 0.
   - The line goes back, and verification and the read-back record their settle deltas.
   - No `credentials.yaml` exists afterwards.
   - `ls -led` on `identity/` and `pending/` (X2).
3. Read the cluster's node account back. Autopilot taking it is [inf] until here.
4. `connect`, with the reader's repository grant as a plan fact, then `reader grant`.
5. The reader end to end:
   - `world`, `ps`, `costs`, `usage` and `logs`;
   - the `--plan` and `--confirm` of kernel deploy, storage deploy, build and run.

   This closes A22-7's reader evidence, which M2 left open.
6. `storage deploy`, with the reader's bucket grant, then `storage ls`, `usage`, `cp` download and `secret ls` as the reader.
7. One Artifact Registry and one Cloud Storage Admin Activity entry made through the identity, read back for what `serviceAccountDelegationInfo` names. That decides V8 and Q12.
8. A second device, as a second config home on the Mac (`--config` or `$FARCAST_CONFIG_HOME`):
   - `device add --role reader`, then `device ls` and `device known`;
   - revocation timing with `device rm`.
9. `device renew` on the main device.
10. A second pending install, abandoned, with its block run against a partial setup (free IAM objects).
11. `release`, then the teardown block pasted, then the counts back to the baseline.

**Settles:**
- Autopilot and the node account, and its scopes;
- `--condition-from-file`, and removing a conditional binding;
- describe of soft-deleted objects;
- the providers list's shape;
- `Validate` as the reader;
- N3's role sufficiency;
- the WI counts at real scale.

**Not walked.**
- Fallbacks 2 and 3: upload is blocked there, and fallback 3 is a Google-made key.
- Fallback 1 is optional and free.

**After.** The runbook's Results, and dated notes in ADR 0024, ADR 0023, AGENTS.md and PLAN.md.

---

## 10. The standing rules, as this plan keeps them

- **No new vendored module (31 stay).** It uses `auth.NewCredentials`, `option.WithAuthCredentials`, httptransport, go-yaml in tests, and x/sys/unix, which is already linked on darwin.
- **No exec-allowlist line.**
  - devicekey and `setupblock` have no exec.
  - `gcloudtest` is test-only, and a scan checks that no product package imports it.
- **Standard library and hand-rolled code on the identity path.** That covers the exchange, impersonation and the IAM read client.
- **No ADC in the CLI.** planck and datasphere refuse neither-credential without `Ambient`, and a scan checks that the CLI never sets it (M3b.4).
- **No migration or compatibility work.** A record with no `Identity` is refused from M3b.7, as an unsupported older record, with no remedy that loops.
- **Every cluster write keeps `--plan` and `--confirm`.** The new reader grants are plan facts never covered by `--yes`. `--yes` never selects fallback 3.
- **Tests stay offline.** They use loopback fakes and a local fake gcloud, under the sandbox profile at review rounds.
- **M4 parked.** Non-darwin builds only keep compiling; the walk's second device is on the Mac.
- **Swift moves once, at M3b.12,** with its vectors copied byte for byte.
- **Minimal machine dependencies.** The operator's Mac needs no gcloud, kubectl or Go. The blocks run in Cloud Shell.

---

## 11. Gaps fixed, against each plan

1. **Row ownership.**
   - Plan A split R1, R3 and R10 across its two kube steps, and R5, R6, R7, R8 and R11 across several.
   - Plan B split R9 over .6a and .6b, R16 over .2, .7 and .9, R18 over .3, .7, .10 and .11, and R19 over .3 and .7.
   - Here each row has one owner (§6), and R18 is split only along §7's own semicolons.
2. **Plan B left pending installs unlisted and unwarned for three commits after `install` made them.** It also left the documents, and a mislabelled anchor-expired kind, reachable on real records. Here the documents, kinds and warnings land before `install`.
3. **Plan B's release gate refused `release` without a reader bucket grant,** against the cost pillar. Plan A's N11 is used instead.
4. **Plan B's shared token per role widened GCS from `devstorage.full_control` to `cloud-platform`.** Per-consumer scopes are used instead, as a dated amendment to D5.2.
5. **Plan A's refusal of a record with no `Identity` told the operator to "release it",** which refused too. Here the message names the record as unsupported. The "no `Identity` means M2's shapes" branch is never built, because every record names its routes from M3b.7.
6. **Neither plan ran the read-back after `device renew`.** Here renewal checks that the trust store holds the new anchor alone before committing.
7. **Neither plan could abandon a pending `device add` on a new machine.** `install --abandon` would have printed the whole instance's teardown. Pending entries now carry a kind, and `device add --abandon` prints only that device's providers' teardown.
8. **Fallback 3.**
   - Neither plan checked that the Google-made key names the drawn writer SA.
   - Plan A's block variant would have made the key in Cloud Shell, leaving a secret in its home.

   Here the key's `client_email` must equal the drawn writer, and the key is made in the console and downloaded to the Mac.
9. **Neither plan released a record whose `install` crashed after the hand-off,** with no cluster. M3b.13 tests it.
10. **Plan A first proved the paste, line and verify loop inside `install`.** Plan B's integration test now runs at M3b.6.
11. **Plan A relied on a CLI scan for "ADC out",** while the adapters still fell through to ADC. The `Ambient` switch makes them fail closed, and S11 has one owner.
12. **Plan A's setup line had six fields and dropped the provider IDs.** Here the setup line has DES:1196's eight values, plus a device-coordinates line (with the region, for a new machine's record) and a device line.
13. **Neither plan named a remedy for a write on a reader-only device.** It is now `credential_missing`, naming `device add --role writer`.
14. **Neither plan said how `install` works in JSON mode.** It takes no prompts, the line comes through `--coordinates`, and `--setup-only` prints `{anchors, block, sha256, guide}`.
15. **Plan A changed Swift twice,** for a kind at its M3b.6 and the documents at its M3b.10. Here Swift changes once, at M3b.12.
16. **Plan A made fallback 1 wait on fallback 2.** That dependency was false, and is removed.
17. **Plan B put every narrative record at the end.** Here each step appends dated notes (Q5's default, D10's rule), and M3b.19 sweeps.
18. **N1.**
    - Plan A's record-only summary was the default everywhere, so the human consented on less information wherever a reader existed.
    - Plan B refused everywhere, which removed the interactive path for fallback-3-only instances.

    The hybrid here uses the reader wherever one can exist.
19. **X2's facts, read in the tree.** x/sys/unix is already linked on darwin, through keeper/backup_darwin.go. Its vendored copy has `SYS_GETATTRLIST` and `ATTR_CMN_EXTENDED_SECURITY`, but no getattrlist wrapper. So enforcement is [unverified] and stays a decision, with a spike at M3b.2.
20. **Fallbacks have no STS audience to prove the number.** Their number is checked by `install`'s one `projects.get` as the writer, which D2 allows at install, before it is recorded.
