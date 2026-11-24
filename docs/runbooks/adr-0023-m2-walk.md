# ADR 0023 M2 — the billable walk: one fresh instance, written by M2 alone

Since [ADR 0023](../adr/0023-one-download-farcast.md) M2.7, `farcast` starts no `kubectl`, auth plugin or `gcloud`. Every cluster call is in-process. The read commands, and the plans under `--plan` and `--confirm`, read as the instance's reader. Every write, and an interactive or `--yes` run's reads, run as the stored installer account, and each apply is a forced server-side apply named `farcast`. Since M2.8 the bucket grant and the push grant name the ServiceAccount by its uid. None of this is walked. The [probe walk](adr-0023-m2-probe-walk.md) of 2026-11-16 settled only the writer's scope pair. This walk installs one fresh instance with the M2 release farcast, from a shell with no `kubectl`, plugin or `gcloud` on `PATH`. It walks the M2 design's revised §10.7 ([§37](../design/adr-0023-m2-design.md#37-decided-before-m29as-build-2026-11-20), as [§39](../design/adr-0023-m2-design.md#39-decided-before-m29bs-build-2026-11-22) decides it), and releases everything at its end. *(2026-11-24, M2 walked: walked on [B] at 3fd79c4, in the probe walk's project, and released; the reader is still not walked ([Results](#results)).)*

**Status.** *Written 2026-11-22 (ADR 0023 M2.9b), against the code at the commit it lands in. Walked 2026-11-24 at 3fd79c4, under [B], in the probe walk's project in the operator's own organization, and torn down to the baseline; the results are [below](#results).* It needs the operator's own approval in the session that walks it: the choices at G0a, and the yes to spend at G0b. The approval that had ADR 0023 M2.9b write this runbook is not approval to walk it. No earlier walk's approval carries over. *(2026-11-22, [ADR 0024](../adr/0024-paste-the-certificate.md): by the operator's decisions of that day, this walk runs after ADR 0024's M3a, on its own, before M3b, in a project in the operator's own organization, under [B]. A22-2 is answered (G0a). An optional W-FED step, with its own approval, is to be appended to this runbook with M3a's build. Neither M3a nor this walk has run.)* *(2026-11-23, ADR 0024's M3a: built 2026-11-22 to 2026-11-23. W-FED is appended below, after line 733, with its own approval at G0a ([W-FED](#w-fed-the-federated-reader-at-the-cluster-optional-adr-0024)). Neither M3a nor this walk has run.)* *(2026-11-23, ADR 0024's M3a walked: M3a was walked 2026-11-23 and passes in a project in the operator's own organization ([its Results](adr-0024-m3a-probe.md#results)), so W-FED is offered at G0a. This walk has not run.)* *(2026-11-24, M2 walked: approved in the session that walked it: G0a answered 2026-11-23, G0b's yes 2026-11-24. W-FED ran within it, after W5.)*

**It is billable.** One Autopilot instance, installed with `--cost-limit 100` (USD a month), for about 4 to 4.5 hours. G0b asks for under USD 5 [inf]. By the repository's floor model the walk costs about USD 0.7 to 1.5 (G0b has the arithmetic). The walk also creates IAM objects, which cost nothing, and W6 removes them. *(2026-11-24, M2 walked: the instance was up about 3.3 hours, W4.1 to W6.1, W-FED included, and cost about USD 0.6 to 1.0 by the floor model [inf]. The bill was not read.)*

**What is left to choose at G0a:** A22-2's branch first ([U1], [U2] or [B]); the project; whether the Org Policy API may be turned on; and the optional steps: (f), the `git-credential` step, ADR 0019's checklist as W5.3, and W4.17's read of field managers. *(2026-11-22, ADR 0024: the branch is [B], by the operator's decision. [U1] is withdrawn, and [U2] is deferred with a project with no organization. G0a also approves the installer's Google-made key as ADR 0024's exception, chooses the existing key or one made at WP.8, and offers W-FED if M3a passed.)* *(2026-11-23, ADR 0024's M3a walked: it passed, so G0a offers W-FED.)* *(2026-11-24, M2 walked: G0a was answered 2026-11-23: [B]; the probe walk's project; the installer's existing key on the Mac, as ADR 0024's approved exception, deleted in Google and on the Mac at W6.2; the Org Policy API may be turned on at WP.7, and W6.4 turns it off again; W-FED, (f), W4.17's read of field managers and ADR 0019's checklist as W5.3, yes; the `git-credential` step, no; W4 (e) dropped. G0b's yes, "Yes, spend", came 2026-11-24, without the real-API suite.)*

**Its deviations from the M2 design.** Items 1 to 12 are from §37's letter, and the design's A39-25 accepts them. Items 13 to 15 are from §39's letter: 13 and 14 found while this runbook was written, 15 in its review. The code is cited where it decides.
1. W3.1 passes `--adapt=false`. "Without `--adapt`" would keep it: the kernel's settings are recorded and carried forward (`kernel deploy`'s Usage) [read].
2. W3.1 is not "the walk's only live stuck-field check". A container's args are an atomic list in server-side apply [inf], so W3.1 shows that the forced apply took effect, not a field-by-field removal. That stays the real-API suite's `TestForcedApplyRemovesAFieldDroppedFromTheManifest`, which has not run on this tree.
3. The reader's first `world` read follows `connect` (W4.6). `ps`, `logs` and `costs` follow the run (W4.13, W4.14): right after the install `ps` lists nothing, `logs` has no application and `costs` has no kernel. `world`'s refusal before a reader stays right after the install (W4.2).
4. (f) and the `git-credential` step run inside the adaptation's wait, before W3, so the wait bills no idle hour.
5. W3 adds an unchanged `kernel deploy` (W3.2) beside §37's `redeploy`. The second `run` records reset lines, not generations, because it is never unchanged.
6. §37 says that on [B] "every `--plan` step cannot run". The plans that read no cluster still run on [B]: `connect`'s, `redeploy`'s and `git-credential`'s, and `reader grant`'s blocked plan.
7. G0 is split into G0a, before anything names or changes the project, and G0b, right before the first billable step.
8. W4.11, `toolchain`, is added: `run` and `build` need both images pinned by digest.
9. W4 (e) is dropped. W4.15's same-name refusal on one cluster stands for it [inf] (the design's A39-24).
10. [U2] is offered, as a form of A22-2's first option, "allow upload for the project". *(2026-11-22, ADR 0024: superseded. [U2] is deferred until most of FarSight is ready. When it runs, it is a project outside any organization, and ADR 0024 proposes that upload is open there, so that the installer and the reader are both device-made certificates uploaded (its proposed fallback 2), not a form of "allow upload".)*
11. W2's `technocore` half is an optional, free read at W4.17. §37 left it unwalked.
12. WP.7 records the Data Access audit configuration and the installer's roles.
13. `connect` comes before `reader grant`: W4.4 is `connect`, W4.5 `reader grant`, W4.6 the version and the reader's first reads. §39 ordered `reader grant` (W4.4) before `connect` (W4.6). The reader's RBAC holds a Role and RoleBindings in `farcast-system` and no Namespace (`renderReaderRBAC`), and `install` does not create `farcast-system`, which `connect` does (FatLine's workload template) [read]. So on a fresh instance the grant's apply would fail before `connect` [inf], as [phase 1's step 7b](phase-1-validation.md#7b-the-instances-reader-identity--not-yet-walked) says in its step 4.
14. W3.4 on [U] counts the deploy plan's `application_reset` facts in the state `adapted`. A JSON plan carries those facts, not the review's line "adapted by the kernel at …", which only an interactive or `--yes` run prints, on stderr (`resetLine`, `printResets`) [read]. On [B] the `--yes` run's stderr is counted, as §39 says.
15. From the review, recorded in the M2 design's [§40](../design/adr-0023-m2-design.md#40-m29bs-build-and-review-2026-11-22): W4.2 expects `kernel_absent` for `spend`, which `world` reads from the record before any reader is needed (`gatherer.spend`) [read]. A sealed keyholder replica is never Ready (`/readyz`, `datasphere/deploy/deploy.go`) [read], so the keyholder is waited for as started, and after the redeploys of W4.10 [B] and W4.15, which replace `datasphered-1` first and wait there, it is unsealed twice. T4 lists every kind of value a step relays.

**Labels.** The sections keep §10.7's names, so that §37 and A33-39's (a) to (f) read across. W0, W1 and W2 are gone (§37, *Dropped*). W1's other checks are W4's reader steps. W3 runs after W4's run and one adaptation. W4 (b) is not walked, and (e) is dropped. A step that A22-2's choice changes is marked **[U]** (key upload allowed) or **[B]** (blocked). Every other step runs the same on both.

## Throughout

- **T1, the scrub rule,** for every record the walk makes: the Results, the design and every dated note.
  - No address, host name, account name or port. No path under a home directory. No uid, resourceVersion, pid, key id, token byte or plan digest.
  - No project id or number, bucket name, endpoint, registry path or principal string. Dates only, never a time of day.
  - Raw outputs and FAIL lines are never copied. A value withheld is written "withheld".
  - The placeholders are `$INSTANCE` and `$PROJECT`, and `$TOKEN` only in W4.16's silent read. Every other value is described in words: "the walk directory", "the installer's key file", "the private repository chosen at G0a". The shell's own `$HOME`, `$TMPDIR` and `$PWD` are not placeholders.
  - Three texts name a time of day, and are never recorded: `reader grant`'s IAM line, "checking again until …"; the reset line of `run`'s review, "adapted by the kernel at …"; and every plan's `generated_at`.
- **T2, two places.**
  - The walk shell on the operator's Mac runs `farcast`, and the system's own tools from `/usr/bin` and `/bin`, none of which reaches a cloud.
  - Cloud Shell runs every observation: `gcloud`, `kubectl` and the audit.
  - The Mac runs no `gcloud` or `kubectl` in this walk, and reads no kubeconfig. No step needs the keeper VM.
- **T3, credentials.**
  - The install passes `--credentials <the installer's key file>`. No Application Default Credentials, ever.
  - Cloud Shell runs only as the operator's FarCast account, checked by eye, never a work account.
  - Never print a token. Never run `gcloud auth print-access-token`, even with its output redirected: zsh's MULTIOS still sends it to the pipe.
  - The walk shell has no `GODEBUG`, no Google logging or credentials variable, no proxy variable and no `KUBECONFIG`. farcast refuses an `http2debug` setting.
- **T4, who does what.**
  - The agent runs WP.1 to WP.4's setup on the Mac, and farcast's non-interactive lines.
  - The operator does every Cloud Shell step and every typed answer:
    - the paste of `reader init`'s script, `reader record`'s key id, and `reader grant`'s `y`;
    - `storage deploy --grant-bucket`'s questions, and the `--confirm` of a plan that writes the bucket grant;
    - the push grant's add, in Cloud Shell;
    - the toolchain's two digests, read and accepted;
    - `git-credential set` and `rm`, and the token;
    - [B]'s build, answered "no"; *(2026-11-24, M2 walked: answered y; deviation 23.)*
    - [U1]'s org-policy change, and Little Snitch.
  - The agent never types into Cloud Shell and never sees its raw output. The operator relays only what a step records: counts, kinds, states and booleans, and the GKE version, rounded minutes, requests, manager and operation pairs, spec paths, audit levels and methods. *(2026-11-24, M2 walked: the agent typed nothing into Cloud Shell, but wrote its blocks and put them on the clipboard (deviation 16), and raw output reached it through the chat more than once; none of that is recorded (deviation 31).)*
- **T5, output.**
  - The agent never moves its own shell. It makes the walk directory with `mktemp -d`, and uses its path by value. The path is never recorded.
  - For each step the agent writes the step's lines into `step.zsh` in the walk directory, after a first line `source ./walk.zsh`, and runs it in a subshell:
    ```bash
    (cd <the walk directory> && env -i HOME="$HOME" TMPDIR="$TMPDIR" INSTANCE=<name> PROJECT=<the project id> \
      FARCAST_CONFIG_HOME="$PWD/config" PATH="$PWD/bin:/usr/bin:/bin" zsh -f ./step.zsh </dev/null)
    ```
    Stdin is `/dev/null` unless a line pipes into a command. The name and the project id are typed by value and never recorded. farcast counts `/dev/null` as a terminal, since it is a character device (`isTerminal`) [read], so a line that would ask a question reads end of input and stops. Every agent line here passes `--yes` or `--confirm`, or asks nothing.
  - Every farcast line writes its stdout and stderr to the step's own files and echoes its exit: `> <step>.out 2> <step>.err; echo "exit $?"`. Never `2>&1 >/dev/null |`, which zsh's MULTIOS still pipes.
  - The agent prints only exits, kinds, counts and states, through `walk.zsh`'s helpers (WP.2).
  - Every `-o json` document is one line (`output.Printer`) [read]. So a count is `grep -o … | sort | uniq -c` or `grep -o … | wc -l`, never `grep -c` on a JSON document.
  - A plan and its human text name the project, its number, the endpoint, the registry, the bucket, the reader and the uids. They stay in the walk directory. The operator reads a plan's human text in the walk terminal when a step says so.
- **T6, stops.** A **HARD STOP** records what was seen, then goes to W6. Anything else unexpected is a finding: record it, stop, and ask the operator. *(2026-11-22, ADR 0024: on [B], once the installer's key G0a approved exists, any stop that ends the walk, G0b's no included, deletes that key in Google, its file on the Mac and every other copy, as W6.2's note says, and records the count.)*
- **T7, Cloud Shell.** Its session resets when idle, and then WP.6's lines are run again. Every `kubectl` block comes after `kc`. A list that failed, for example with "Reauthentication failed", counts nothing: check that each list ran before recording its count.
- **T8, zsh.** An instance path is written `"${INSTANCE}:walk/…"`, with the braces. zsh reads a bare `$INSTANCE:w…` as a modifier.

---

## G0a. The walk's choices (no spend)

Before any step that names the project or changes it, the agent presents these, and the operator answers in the session that walks. Record the answers and G0a's date.

1. **A22-2's branch, first.** *(2026-11-22, ADR 0024: answered by the operator. The walk takes [B], in a project in the operator's own organization.)*
   - **[U1]:** allow service-account key upload for the walk's project, by the operator's own org-policy change. Its spelling, and who may make it, are [unverified]. W6.4 restores it or keeps it, as decided here. *(2026-11-22, ADR 0024: withdrawn. The walk takes [B], and FarCast is not to ask for a security default to be relaxed (ADR 0024's proposed fallback 4). Today's `reader init` still says an organization administrator must allow upload (`readerinit.go:404`, `:409`), the message W4.3 [B] stops at; ADR 0024's M3b rewords it.)*
   - **[U2]:** a project outside the organization, which has no such policy. This is a form of A22-2's first option, "allow upload for the project", not a fourth option. It brings its own setup (WP.8), its own baseline (WP.7) and W6.8. *(2026-11-22, ADR 0024: deferred with a project with no organization, until most of FarSight is ready; see deviation 10's note.)*
   - **[B]:** upload stays blocked. The walk takes the refusal and terminal path. The reader is not walked, and M2's records keep "reader not walked". *(2026-11-22, ADR 0024: the operator's branch. The installer's Google-made key is an exception to ADR 0024 that the operator approves here, time-boxed to the walk and deleted at teardown: the operator holds it at 0600 on the Mac only for the walk, deletes it in Google and deletes the key file on the Mac after W6.1's release (W6.2's note), and W6.6 deletes the config home's copy. If WP.8 counts 1 key, the installer then holds no user-managed key after the walk. Here the operator also says whether the walk uses the installer's existing key or one made at WP.8.)*
2. **The project.** The probe walk's project, whose baseline is known ([U1] or [B]), or a fresh one ([U2]). For a fresh project, whether W6.8 keeps it or shuts it down. *(2026-11-22, ADR 0024: a project in the operator's own organization: the probe walk's, or a fresh one there. A fresh one is set up at WP.8 as [U2]'s list there says, and W6.8 keeps it or shuts it down, as decided here.)*
3. **The Org Policy API.** WP.7's unsilenced managed check may ask to turn it on (A22-3). W6.4 turns it off again if the walk turned it on.
4. **The optional steps:** *(2026-11-22, ADR 0024: and W-FED, offered only if ADR 0024's M3a passed in the organization project, with its own approval. Its steps are to be appended to this runbook with M3a's build.)* *(2026-11-23, ADR 0024's M3a: W-FED's steps are appended below ([W-FED](#w-fed-the-federated-reader-at-the-cluster-optional-adr-0024)), with its approval, which the agent presents here.)* *(2026-11-23, ADR 0024's M3a walked: it passed in the organization project on 2026-11-23, so W-FED is offered.)*
   - **(f)**, W4.15, with its same-name refusal. Recommended, because it stands for (e). It deletes and creates again `farcast-system/datasphered` from Cloud Shell, and restarts the keyholder twice;
   - **the `git-credential` step**, W4.16. It needs a private repository with a `./farcast` manifest whose name is not `sdk-demo`, which the operator reads here, external declarations included, and approves; and a read-only token scoped to it, typed only by the operator and revoked at W6.7. The Secret's name and the Git username are chosen here, in words, and never recorded. The provider can read the Secret while it exists. Its audit log also keeps, for 400 days, the Secret's name and the private repository's address, ref, manifest path and each built commit, which the fetch and build Jobs carry as literals. W6 cannot remove them ([ADR 0019](../adr/0019-what-the-cluster-tells-its-provider.md#what-the-provider-still-sees));
   - **ADR 0019's checklist** as W5.3: about 20 minutes, no cost beyond instance time, one seal and unseal;
   - **W4.17's read of the resized application's field managers**: free and read-only.
5. **W4 (e) is dropped** (the design's A39-24). To overrule that, the runbook first gains (e)'s steps under a second instance placeholder the operator approves. Those steps are not written.
6. **Optionally, before G0b:** the real-API suite on the keeper VM, by [its own runbook](adr-0023-m2-realapi.md) and its own approval. It costs no cloud. The suite as M2.9a left it, twelve tests, has not run. It is not part of this walk.

The cost is shown here for information (G0b). The yes to spend is G0b's.

---

## WP. Setup on the dev Mac and in Cloud Shell (no cloud spend)

**WP.1, the commit (agent).** In the checkout's root, from a clean tree: `./check.sh`.
- **Record:** the commit and the summary line.
- The commit need not be pushed. `run` clones the public repository's main for `sdk-demo`, not the walked commit (WP.9).

**WP.2, the walk directory and its helpers (agent).**
- `mktemp -d` makes the walk directory, 0700, outside any checkout. Make `bin/` in it, and write `walk.zsh` there:
  ```bash
  # The walk's helpers. Each prints a digest, kinds, counts or states, and never a name, address or principal.
  digest()   { grep -o '"digest":"sha256:[0-9a-f]*"' "$1" | head -1 | cut -d'"' -f4; }
  blocked()  { if grep -q '"blocked":\[\]' "$1"; then echo 'blocked: none'; else grep -o '"blocked":\[{"kind":"[a-z_]*"' "$1" | cut -d'"' -f6; fi; }
  errkind()  { grep -oE '"code":[0-9]+,"kind":"[a-z_]+"\}\}$' "$1" | tr -d '{}"'; }
  grant()    { grep -o "\"type\":\"grant\",\"name\":\"$2\"[^}]*" "$1" | grep -oE '"(state|shared)":"[a-z]*"|"apply":[a-z]*' | tr -d '"'; }
  sections() { grep -o '"sections":{.*' "$1" | grep -oE '"(spend|apps|policy|network|seal)":\{"read":(true|false)(,"skipped":"[a-z_]*")?(,"error":\{"kind":"[a-z_]*")?' | tr -d '{"'; }
  reader()   { grep -o '"reader":"[a-z_]*"' "$1" | tr -d '"'; }
  writes()   { grep -o '"type":"write"' "$1" | wc -l | tr -d ' '; }
  resets()   { grep -oE '"type":"application_reset","namespace":"[a-z0-9-]*","app":"[a-z0-9-]*","state":"[a-z]*"' "$1" | cut -d'"' -f12,16 | tr '"' ' ' | sort | uniq -c; }
  apps()     { grep -oE '"name":"[a-z0-9-]+","image":"[^"]*@sha256:[0-9a-f]{64}"' "$1" | cut -d'"' -f4 | sort | uniq -c; }
  ```
- `digest` reads the document's own digest, which comes before `bound` (`plan.Document`) [read]. `grant` prints the states and `apply`, never a principal or a bucket. `errkind` reads the JSON error envelope's code and kind. `sections` reads `world`'s five sections, each read, skipped or failed with its kind.
- Do not make `config/`. farcast makes it 0700 under `FARCAST_CONFIG_HOME`. A `mkdir -p` under umask 022 makes it 0755, which farcast refuses (`config.Dir.CheckPerms`) [read].
- **Why:** a fresh config home keeps the walk's records, keys, CA keys and keyring away from the operator's own. W6.6 deletes it.

**WP.3, the M2 release farcast (agent).** From the checkout's root, in a subshell, with no `FARCAST_` variable set:
```bash
(cd <the checkout> && GOWORK=off GOTOOLCHAIN=go1.27.4 GOPROXY=off GOFLAGS=-mod=vendor \
  go run ./farsight/cli/cmd/farcast-release build -targets darwin/arm64 -out <the walk directory>/rel)
(cd <the walk directory>/rel && wc -l < SHA256SUMS && shasum -a 256 -c SHA256SUMS | grep -c ': OK$')
shasum -a 256 <the walk directory>/rel/SHA256SUMS
go version -m <the walk directory>/rel/farcast-darwin-arm64 | grep -E -- '-tags=|vcs\.(revision|modified)'
cp <the walk directory>/rel/farcast-darwin-arm64 <the walk directory>/bin/farcast
cmp <the walk directory>/rel/farcast-darwin-arm64 <the walk directory>/bin/farcast && echo same
```
- **Expect:** the `OK` count equal to the line count; `-tags=farcast_embedded`; WP.1's commit as `vcs.revision`; `vcs.modified=false`; `same`.
- **Record:** the `OK` count, the sha256 of `SHA256SUMS`, the revision and `vcs.modified`.
- **Stop:** another revision, or `vcs.modified=true`. A release farcast refuses to push components from another revision or a modified tree. This is one host, not the M1 walk's R0.

**WP.4, the walk shell, which is also the operator's walk terminal.**
- **Agent,** as a step (T5):
  ```bash
  command -v kubectl gke-gcloud-auth-plugin gcloud go gofmt | wc -l
  env | grep -ciE '^(godebug|google_|https?_proxy|all_proxy|no_proxy|kubeconfig|cloudsdk_)='
  farcast -o json version > version.json 2> version.err; echo "exit $?"
  grep -o '"name":"[a-z]*","go":"[^"]*","manifest":"sha256:[0-9a-f]*"' version.json
  ```
  - **HARD STOP** if the first count is not 0. **Stop** if the second is not 0.
  - **Expect:** four components, `datasphered`, `fatline`, `shrike` and `technocore`, each `go1.27.4`.
  - **Record:** that nothing resolved, and the first 12 hex of each manifest, as the M1 walk did.
- **Operator,** in a terminal of their own, from the walk directory:
  ```bash
  env -i HOME="$HOME" TMPDIR="$TMPDIR" INSTANCE=<name> PROJECT=<the project id> \
    FARCAST_CONFIG_HOME="$PWD/config" PATH="$PWD/bin:/usr/bin:/bin" zsh -f
  source ./walk.zsh
  command -v kubectl gke-gcloud-auth-plugin gcloud go gofmt
  ```
  This is the walk terminal. Every step that says "in the walk terminal" runs here. `command -v` prints nothing. *(2026-11-24, M2 walked: the agent opened it, in the desktop app's Terminal panel, with the project and the name read from the walk directory's 0600 files; the operator's `command -v` printed nothing (deviation 17).)*
- **Why:** this is §37's "a shell with no kubectl, plugin or gcloud on `PATH`".

**WP.5, the outbound firewall (operator).** Little Snitch on the walk Mac, rules for `<the walk directory>/bin/farcast`, each for its destination only:
- Google's APIs, as each prompt asks;
- Google's token endpoint and the cluster's DNS endpoint, which [the probe walk's P0.5](adr-0023-m2-probe-walk.md#p0-setup-on-the-dev-mac-no-cloud) names;
- the registry's region host, and the base image's registry, which [the M1 walk's W0.3](adr-0023-m1-walk.md#w0-setup-on-the-dev-mac-no-cloud) names;
- the builder's and the fetcher's upstream registries, which [`phase-5-session-a.md`'s S3](phase-5-session-a.md#bring-up) names (W4.11);
- during W4.4, the carrier's address on FatLine's port, as P0.5 names it: `connect --confirm` dials it before it exits, so allow it when Little Snitch asks, for that destination only.

A held binary shows as an EOF or a timeout, not as a refusal (P0.5's note). No walk probe is built. If a 401 or a 403 needs a diagnosis, build it once, as the probe walk's P0.4 does. *(2026-11-23, ADR 0024's M3a: one exception, under W-FED's own approval: WF.0 builds W-FED's probe, M3a's, before WP.4.)* *(2026-11-24, M2 walked: the operator allowed Little Snitch's prompts as they came. Two of W4.8's three runs ended on a held first dial's EOF (deviations 18, 21).)*

**WP.6, Cloud Shell (operator).** Signed in as an Owner of the project, the FarCast account checked by eye. Typed, never recorded: *(2026-11-24, M2 walked: pasted, not typed, as a clipboard block with the values filled in, twice, since the first copy was lost before pasting; the helpers defined, 11 of 11 (deviation 16).)*
```bash
PROJECT=<the project id>; INSTANCE=<name>
cd "$(mktemp -d)"; export KUBECONFIG="$PWD/kubeconfig"
kc()          { gcloud container clusters get-credentials "farcast-$INSTANCE" --region us-central1 --project "$PROJECT" --dns-endpoint >/dev/null; echo "kc exit $?"; }
bucket()      { gcloud storage buckets list --project "$PROJECT" --filter="labels.farcast-instance=$INSTANCE" --format='value(name)'; }
sauid()       { kubectl -n farcast-system get serviceaccount "$1" -o jsonpath='{.metadata.uid}'; }
bucketroles() { gcloud storage buckets get-iam-policy "gs://$(bucket)" --format=json | jq --arg u "/kubernetes.serviceaccount.uid/$(sauid datasphered)" --arg s "/subject/ns/farcast-system/sa/datasphered" '[.bindings[] | select(.condition == null and (.role == "roles/storage.objectAdmin" or .role == "roles/storage.legacyBucketReader")) | {role, uid: ([.members[] | select(endswith($u))] | length), other_uid: ([.members[] | select(contains("/kubernetes.serviceaccount.uid/") and (endswith($u) | not))] | length), shared: ([.members[] | select(endswith($s))] | length)}]'; }
repomembers() { gcloud artifacts repositories get-iam-policy "farcast-$INSTANCE" --location us-central1 --project "$PROJECT" --format=json | jq --arg u "/kubernetes.serviceaccount.uid/$(sauid farcast-builder)" --arg s "/subject/ns/farcast-system/sa/farcast-builder" '[.bindings[]? | select(.condition == null and .role == "roles/artifactregistry.writer") | {uid: ([.members[] | select(endswith($u))] | length), shared: ([.members[] | select(endswith($s))] | length)}]'; }
keyholder()   { kubectl -n farcast-system get pods -l app.kubernetes.io/name=datasphered -o custom-columns=NAME:.metadata.name,READY:.status.containerStatuses[0].ready,STARTED:.status.containerStatuses[0].started,RESTARTS:.status.containerStatuses[0].restartCount --no-headers; }
gens()        { kubectl get deploy,statefulset -A -l app.kubernetes.io/managed-by=farcast -o custom-columns=NS:.metadata.namespace,KIND:.kind,NAME:.metadata.name,GEN:.metadata.generation --no-headers; }
rsets()       { kubectl get replicasets -A -o json | jq -r '.items[] | .metadata.namespace + "/" + (.metadata.ownerReferences[0].name // "-")' | sort | uniq -c; }
managers()    { kubectl -n "$1" get "$2" --show-managed-fields -o json | jq -r '.metadata.managedFields[] | .manager + "/" + .operation + (if .subresource then "/" + .subresource else "" end)' | sort | uniq -c; }
specpaths()   { kubectl -n "$1" get "$2" -o json | jq -r '.spec | paths(scalars) as $p | [($p | map(tostring) | join(".")), (getpath($p) | tostring)] | @tsv' | sort; }
count()       { local out; out=$("$@" --project "$PROJECT" --format='value(name)') || { echo "FAILED: $*"; return; }; printf '%s\n' "$out" | grep -c .; }
```
- Each helper prints counts, names, generations or manager pairs only. `specpaths`' values stay in Cloud Shell's files: a diff records only its paths column (`cut -f1`).
- The helpers' spellings are [unverified]: `--dns-endpoint`, the label filter, `jq` being installed, and `count`'s `--format` on every list. The label `app.kubernetes.io/name=datasphered` and the bucket label `farcast-instance` are [read] in the keyholder's workload and in `instanceLabels`.

**WP.7, the baseline (operator, Cloud Shell),** in the project G0a chose. Counts only. Record each.
- **Resources,** with `count`: `gcloud container clusters list`; `gcloud artifacts repositories list --location us-central1`; `gcloud storage buckets list`; `gcloud compute forwarding-rules list`, `addresses list`, `target-pools list`, `disks list`, `instances list`, `firewall-rules list`, `health-checks list` and `backend-services list`.
- **Accounts:** `count gcloud iam service-accounts list`; the `farcast-reader-` accounts among them; and the members of `roles/container.clusterViewer` in the project's policy:
  ```bash
  gcloud iam service-accounts list --project "$PROJECT" --format='value(email)' | grep -c '^farcast-reader-'
  gcloud projects get-iam-policy "$PROJECT" --format=json | jq '[.bindings[] | select(.role == "roles/container.clusterViewer") | .members[]] | length'
  ```
- **The installer's roles,** yes or no for each: `roles/container.admin`, `roles/iam.serviceAccountUser` and `roles/artifactregistry.admin` ([phase 1's step 2](phase-1-validation.md#2-create-the-installer-service-account--key)), and `roles/storage.admin` under [phase 3's condition](phase-3-validation.md#2-create-the-installer-service-account--key). The installer's email is typed, never recorded:
  ```bash
  gcloud projects get-iam-policy "$PROJECT" --format=json | jq -r --arg m "serviceAccount:<the installer's email>" '.bindings[] | select(.members | index($m)) | .role + " " + (.condition.title // "-")'
  ```
  The probe walk ran neither `storage deploy` nor `build` in its project. A missing role found at W4.8 would bill an hour first.
- **The APIs:** yes or no, the APIs [phase 1's step 1](phase-1-validation.md#1-enable-the-apis) and [phase 3's step 1](phase-3-validation.md#1-enable-the-api) enable are on, and whether the Org Policy API is on. Read `gcloud services list --enabled --project "$PROJECT"` on screen.
- **The key-upload checks,** unsilenced, as [the probe walk's P3](adr-0023-m2-probe-walk.md#p3-item-3-what-the-init-script-printed) walked them:
  ```bash
  gcloud resource-manager org-policies describe iam.disableServiceAccountKeyUpload \
    --effective --project "$PROJECT" --format 'value(booleanPolicy.enforced)'; echo "exit $?"
  gcloud org-policies describe iam.managed.disableServiceAccountKeyUpload \
    --effective --project "$PROJECT" --format 'value(spec.rules[0].enforce)'; echo "exit $?"
  ```
  If the second asks to turn the Org Policy API on, answer as G0a decided, and record it. *(2026-11-24, M2 walked: it asked; the operator answered y, and the API was turned on (deviation 19). The managed check then read `False`.)*
- **The key expiry policy:** `iam.serviceAccountKeyExpiryHours`' effective value on the project, enforced or not, and its hours. It sets W4.3's `--days`. The spelling is the legacy check's form, [unverified] for this constraint.
- **ADR 0019's precondition** ([its Verification](../adr/0019-what-the-cluster-tells-its-provider.md#verification)):
  - no GKE Enterprise enablement and no fleet membership. The spelling is the operator's, [unverified]. One form is `count gcloud container fleet memberships list`; *(2026-11-24, M2 walked: that list FAILED, its error read as PERMISSION_DENIED, with the GKE Hub API off; the operator accepted the precondition from the API states (deviation 20).)*
  - the project's effective Data Access audit configuration, inherited settings included, as levels or booleans. The project's own: `gcloud projects get-iam-policy "$PROJECT" --format=json | jq -r '.auditConfigs[]? | .service + " " + ([.auditLogConfigs[]?.logType] | join(","))'`. Each folder above it and the organization the same way, where the operator can read them; a level not read is recorded "not read". Never an exempted member. W5.1's "no reader entries" depends on this record.
- **Stop:**
  - **if the cluster count is not 0.** Ask the operator. Every cluster in the project shares the Workload Identity pool, and any of them can present any uid;
  - **if the GKE Enterprise or fleet check fails.** A control-plane logging default would fail the install by design (ADR 0019);
  - **if the installer lacks a role** W4 needs. The operator decides.

**WP.8, A22-2's preparation (operator).** *(2026-11-22, ADR 0024: [B] only.)*
- **[U1]:** the operator's own org-policy change, so that neither key-upload constraint is enforced on the project. Then WP.7's two key-upload checks again: both `False`. *(2026-11-22, ADR 0024: not run; see G0a.)*
- **[U2]:** in the fresh project, in Cloud Shell, the per-project setup: *(2026-11-22, ADR 0024: not run as a branch; see G0a. If G0a chose a fresh project, this list is still its per-project setup, made under [B].)*
  - the APIs, the installer account, its roles and its key, as [phase 1's steps 1 and 2](phase-1-validation.md#1-enable-the-apis) set them up;
  - `roles/storage.admin` under phase 3's condition;
  - billing linked.

  The key goes to the Mac at 0600, never into a checkout or Cloud Shell's home. WP.7 is then taken in that project.
- **[B]:** nothing. *(2026-11-22, ADR 0024: except the installer's key, G0a's approved exception. If G0a chose a new one, it is made here, as [phase 1's step 2](phase-1-validation.md#2-create-the-installer-service-account--key) makes it, but not on the Mac, which runs no `gcloud` (T2): in Cloud Shell, in WP.6's directory, after `umask 077`, `gcloud iam service-accounts keys create <a file name> --iam-account "<the installer's email>" --project "$PROJECT"`, or on the console's Keys tab. It reaches the Mac through the browser's download and is moved at once to a 0600 file outside any checkout. The download folder's copy and Cloud Shell's are deleted at once, not moved to the Trash. It never goes into a checkout or Cloud Shell's home. The operator also records here, in Cloud Shell, how many user-managed keys the installer holds, a count only, once the walk's key exists: `count gcloud iam service-accounts keys list --iam-account "<the installer's email>" --managed-by user`, the email typed, never recorded, the flag's spelling [unverified]. The count expected is 1. Any other count stops the walk to ask the operator, because any other key is G0a's to decide.)*

**WP.9, free checks (operator, or the agent with a web view).**
- The public repository's main holds `manifest/examples/sdk-demo/farcast` and `sdk/go/examples/demo`, and that manifest declares no external host.
- `phase-5-session-a.md`'s S3 still names the builder and the fetcher by tag. Whether the tags still resolve is W4.11's.

---

## G0b. The approval to spend (right before W4.1)

The agent presents, then waits for the operator's explicit yes in the session that walks. With no yes, nothing billable starts. The operator runs W6.4, W6.5 and W6.8, the agent deletes the walk directory (W6.6), the no and its date are recorded, and the walk ends. *(2026-11-22, ADR 0024: on [B], after a no the operator also deletes, in Cloud Shell, the installer's key G0a approved, and the key file on the Mac, as W6.2's note says.)*

- **The cost:** under USD 5 [inf]. By the repository's floor model [read; the totals are inf]:
  - one instance is about USD 0.106 an hour (`floorFull`, `farsight/cli/internal/cli/floor.go`): the modelled cluster line of USD 37 a month (unverified), the carrier at USD 0.025 an hour (`technocore/pricing/pricing.go`), and five system Pods at the Autopilot rates;
  - W4.1 to W6.1 is about 4 to 4.5 hours: about USD 0.45 to 0.5. About an hour of it is the adaptation's wait, which W4.14 to W4.16 fill;
  - four to six builds, each at most about USD 0.027 (1 vCPU and 2 GiB for at most 1,800 s, `planck/build/build.go`): at most about USD 0.16. [B]'s build answered "no" bills nothing;
  - the per-Pod floor on a cluster without bursting: about USD 0.2;
  - the cluster fee of USD 0.10 an hour, if the free tier does not waive it for this cluster ([ADR 0003](../adr/0003-gke-autopilot.md); [unverified] for this billing account): up to about USD 0.45;
  - the fetch Jobs, the registry, image pulls and egress: cents.

  The total is about USD 0.7 to 1.5. The IAM objects, the reader's key, the Org Policy API and the grants bill nothing.
- **What the walk creates:**
  - one Autopilot cluster, with its registry, its bucket and its load balancer;
  - [U] one reader account, with an uploaded key and project-wide `roles/container.clusterViewer`;
  - [U1] the org-policy change, already made at WP.8;
  - the bucket's uid grant, through `--grant-bucket`;
  - the repository's uid push grant, by hand in Cloud Shell;
  - perhaps the Org Policy API, already turned on at WP.7 if G0a allowed it;
  - [U2] the fresh project's setup, already made at WP.8. *(2026-11-22, ADR 0024: and under [B], a fresh project's setup, if G0a chose one, and the installer's key, if made at WP.8.)*
- **The teardown, W6.** It runs `farcast release "$INSTANCE" --delete-data --yes`. That deletes for good, with the instance, the bucket's objects: the walk's secret, `walk/a.bin` and anything the applications wrote. Soft delete is off on the bucket by design. W6 cannot remove what the project keeps of the walk: Admin Activity entries for 400 days, with every workload's spec and the repository and commit of each build; logs for 30 days by default; metrics for 24 months (ADR 0019; `release` prints the dates). *(2026-11-22, ADR 0024: on [B], W6.2 also deletes the installer's key in Google and on the Mac.)* *(2026-11-24, M2 walked: W5 found farcast's own applies absent from Admin Activity, except on ConfigMaps and Secrets. Each build's repository and commit, and every workload's Pod spec, are kept in the controllers' Pod creates instead (W5.3 (7)).)*
- **G0a's choices, restated.**

**Record:** the yes and its date.

---

## W4. The fresh instance (billable from W4.1)

**W4.1, `install` (agent).**
```bash
farcast install --name "$INSTANCE" --cost-limit 100 --region us-central1 --project "$PROJECT" \
  --credentials <the installer's key file> --yes > w4-1.out 2> w4-1.err; echo "exit $?"
grep -c '^endpoint:' "config/instances/$INSTANCE/metadata.yaml"
grep -c '^registry:' "config/instances/$INSTANCE/metadata.yaml"
```
- **Expect:** exit 0 after about 4 to 5 minutes, one endpoint and one registry recorded.
- **Record:** the exit, the minutes, and the two counts.
- **If no registry is recorded,** `install` warned that it could not create it. `connect --plan` then refuses (it needs the registry recorded). Record it as a finding, and run W4.4 as `farcast connect "$INSTANCE" --yes`, which ensures it.
- **Why:** an instance written by M2 alone (§37). `--cost-limit 100` is above the model's floor, as on the M1 and probe walks. The refusal without `--credentials` was walked 2026-11-16 (the probe walk's P1.1), and is not repeated.

**W4.2, `world` before a reader (agent).** This is W1's first check.
```bash
farcast -o json world "$INSTANCE" > w4-2.json 2> w4-2.err; echo "exit $?"; sections w4-2.json
farcast -o json instances > w4-2i.json 2> w4-2i.err; echo "exit $?"; reader w4-2i.json
```
- **Expect:** exit 0. `spend` fails with `kernel_absent`: no kernel is recorded yet, and the record says so before any reader is needed. `apps` and `policy` fail with `credential_missing` ("has no reader identity"), with nothing sent to the cluster. `network` fails with `not_connected`, and `seal` is skipped, `not_deployed`. `instances` says `reader:none`.
- **Record:** each section's state and kind.
- **Stop:** `apps` or `policy` with any kind but `credential_missing`, or `spend` with any kind but `kernel_absent`.

**W4.3, `reader init`, the paste, `reader record`.** This follows [phase 1's step 7b](phase-1-validation.md#7b-the-instances-reader-identity--not-yet-walked), steps 1 to 3, the reader's procedure.
- **Agent:**
  ```bash
  farcast reader init "$INSTANCE" > reader-init.sh 2> reader-init.err; echo "exit $?"
  ```
  Add `--days <the policy's limit in whole days, rounded down, at most 90>` where WP.7 found the expiry policy enforced.
- **Operator,** in the walk terminal: `pbcopy < reader-init.sh`, then paste it into Cloud Shell. Keep what it prints on the screen; do not copy it anywhere. *(2026-11-24, M2 walked: the agent put the script on the clipboard, its sha256 equal to the one farcast printed (deviation 16).)*
  - **[U]:** the paste ends with a `farcast reader record` line. Type `farcast reader record "$INSTANCE" --key-id <the id the paste printed>` in the walk terminal.
  - **[B]:** the paste stops at its first policy check and changes nothing. If it says instead that the key upload was refused, record "managed check silenced" (A22-3): the account and the binding it left are removed at W6.2.
- **Agent:** `farcast -o json instances > w4-3i.json 2> w4-3i.err; echo "exit $?"; reader w4-3i.json`. **Expect** `reader:not_granted` on [U], and `reader:not_uploaded` on [B].
- **Record:**
  - [U]: that the paste passed; for the binding and for the upload, how many errors came before success (the probe walk's P3 form); whether the printed id was 40 lowercase hex, yes or no. Never the id;
  - [B]: which constraint stopped it, legacy or managed.
- **Why:** the probe walk's item 2, never walked.

**W4.4, `connect` (agent, both branches).** Its plan reads no cluster, so the plan route works on [B] too.
```bash
farcast -o json connect "$INSTANCE" --plan > w4-4.plan.json 2> w4-4.plan.err; echo "exit $?"; blocked w4-4.plan.json
farcast connect "$INSTANCE" --confirm "$(digest w4-4.plan.json)" > w4-4.out 2> w4-4.err; echo "exit $?"
farcast -o json connect "$INSTANCE" --status > w4-4s.json 2> w4-4s.err; echo "exit $?"; grep -o '"connected":[a-z]*' w4-4s.json
grep -c '^carrier:' "config/instances/$INSTANCE/metadata.yaml"
```
- **Expect:** exits 0, `blocked: none`, `"connected":true`, one carrier recorded.
- **Record:** the exits, the block, the carrier count, and `connected`.
- **During it:** allow the carrier's address when Little Snitch asks (WP.5); a held dial shows as an EOF or a timeout and fails the confirm.
- **Why:** §10.7's W4. `connect` comes before `reader grant`, because it creates `farcast-system`, where the reader's RBAC binds (deviation 13).

**W4.5, `reader grant`.** This follows phase 1's step 7b, step 4.
- **[U], agent:**
  ```bash
  farcast -o json reader grant "$INSTANCE" --plan > w4-5.plan.json 2> w4-5.plan.err; echo "exit $?"; blocked w4-5.plan.json; writes w4-5.plan.json
  ```
  Its plan reads no cluster (`cluster_identity` is `none`). **Expect** `blocked: none` and 6 writes: 5, and 1 for `farcast-system`, the one namespace bound while no kernel meters any (`readerBoundNamespaces`) [read].
- **[U], operator,** in the walk terminal: `time farcast reader grant "$INSTANCE"`. Answer `y` at once: the elapsed time includes the prompt.
  - **Expect:** `✓ instance "…"'s reader … reads the cluster, and was verified read-only`.
  - **Record:** the elapsed minutes `time` printed, rounded; whether the line "IAM changes typically take 2 minutes" appeared, which says the first read was refused (never the time it names); and which review, if any, answered that the reader `may`.
  - **Stop:** a review that answered `may` stops the reader steps. Record which of the five.
- **[B], agent:**
  ```bash
  farcast -o json reader grant "$INSTANCE" --plan > w4-5b.plan.json 2> w4-5b.plan.err; echo "exit $?"; blocked w4-5b.plan.json
  farcast -o json reader grant "$INSTANCE" > w4-5b.json 2> w4-5b.err; echo "exit $?"; errkind w4-5b.json
  ```
  **Expect:** the plan exits 0, blocked `credential_missing`; the run exits 1, `credential_missing`, and writes nothing.
- **Why:** §37's "`reader grant`, interactive, and its verification, with IAM's lag recorded".

**W4.6, the Kubernetes version, and the reader's first reads.**
- **Operator, Cloud Shell:**
  ```bash
  kc; gcloud container clusters describe "farcast-$INSTANCE" --region us-central1 --project "$PROJECT" --format 'value(currentMasterVersion)'
  ```
  **Record** the version and its minor: the minor §10.6 pins. The probe walk saw 1.36.
- **[U], agent:**
  ```bash
  farcast -o json world "$INSTANCE" > w4-6w.json 2> w4-6w.err; echo "exit $?"; sections w4-6w.json
  farcast -o json instances > w4-6i.json 2> w4-6i.err; echo "exit $?"; reader w4-6i.json
  ```
  - **Expect:** one kind only, `kernel_absent` for `spend`; `seal` skipped; every other section read; `reader:granted`. This is the probe walk's P2.6 expectation.
  - A `credential_refused`, `unauthorized`, `forbidden` or `endpoint_refused` is a finding against farcast's scope pair for the reader (A22-7) or against the RBAC.

**W4.7, `kernel deploy --adapt --adapt-cooldown 1m`.**
- **[U], agent:**
  ```bash
  farcast -o json kernel deploy "$INSTANCE" --adapt --adapt-cooldown 1m --plan > w4-7.plan.json 2> w4-7.plan.err; echo "exit $?"; blocked w4-7.plan.json
  farcast kernel deploy "$INSTANCE" --adapt --adapt-cooldown 1m --confirm "$(digest w4-7.plan.json)" > w4-7.out 2> w4-7.err; echo "exit $?"
  ```
- **[B], agent:**
  ```bash
  farcast -o json kernel deploy "$INSTANCE" --adapt --adapt-cooldown 1m --plan > w4-7b.json 2> w4-7b.err; echo "exit $?"; errkind w4-7b.json
  farcast kernel deploy "$INSTANCE" --adapt --adapt-cooldown 1m --yes > w4-7.out 2> w4-7.err; echo "exit $?"
  ```
  **Expect** the plan refused, exit 1, `credential_missing`, with nothing written; then the `--yes` run exits 0.
- **Operator, Cloud Shell:** `kubectl -n farcast-system get serviceaccount farcast-builder -o name`.
- **Record:** the exits; the kind on [B]; whether `farcast-builder` exists. Never its uid.
- **Why:** §37's kernel flags, so that one adaptation happens within the walk; and A33-20, the builder's account exists before any build.

**W4.8, (a): `storage deploy` with the bucket grant.**
- **[U], agent:**
  ```bash
  farcast -o json storage deploy "$INSTANCE" --grant-bucket --plan > w4-8.plan.json 2> w4-8.plan.err; echo "exit $?"; blocked w4-8.plan.json; grant w4-8.plan.json bucket
  ```
  **Expect** `blocked: none`, then `state:missing`, `shared:missing`, `apply:true`. A first deploy binds placeholders for the bucket and the account.
- **[U], operator,** in the walk terminal: `farcast storage deploy "$INSTANCE" --grant-bucket --plan`. Read it. Then type, with the digest its last line prints:
  ```bash
  farcast -o json storage deploy "$INSTANCE" --grant-bucket --confirm <the digest the plan printed> > w4-8.json 2> w4-8.err; echo "exit $?"
  ```
  **Agent:** `grep -o '"bucket_grant":"[a-z]*"' w4-8.json`. **Expect** `applied`.
- **[B], agent:**
  ```bash
  farcast -o json storage deploy "$INSTANCE" --plan > w4-8b.json 2> w4-8b.err; echo "exit $?"; errkind w4-8b.json
  ```
  **Expect** exit 1, `credential_missing`, nothing written.
- **[B], operator,** in the walk terminal: `farcast storage deploy "$INSTANCE" --grant-bucket`. It asks the cost question, then the grant question, which names "the bucket this deploy creates" and the account "by the uid it has once this deploy creates it". Answer yes to both. This is A33-39's terminal path. **Record** whether it printed any grant commands: none expected, since it applies the grant. *(2026-11-24, M2 walked: it ran three times; the first two ended on an EOF, Little Snitch holding a first dial (deviation 21). The third asked both questions, was answered y to each, and printed no grant commands.)*
- **Both, operator, Cloud Shell:** `kc; bucketroles; keyholder`, then `keyholder` every minute until both replicas are STARTED true and their restart count holds for two reads. READY stays false until the unseal: `/readyz` answers 503 while a replica is sealed (`datasphere/deploy/deploy.go`) [read].
- **Both, agent:** `farcast storage unseal "$INSTANCE" > w4-8u.out 2> w4-8u.err; echo "exit $?"; grep -c 'holding no application scopes' w4-8u.out`.
- **Record:**
  - the result's grant state ([U]) or the commands printed, none or some ([B]);
  - per role, `uid`, `other_uid` and `shared`. **Expect** 1, 0 and 0;
  - the restarts before both ran steadily, and the minutes from the deploy's end to that: IAM's lag; after the unseal, whether `keyholder` shows both READY true;
  - the unseal's exit and its count.
- **Stop:**
  - Google refuses the policy write. Record the kind and its first words only. Skip (c), (d)'s push and (f), and go to W5.
  - Both replicas restart on their start-up bucket check 15 minutes after. That check exits on `provider.Validate` (`datasphere/cmd/datasphere/serve.go`) [read]. Seen by the restarts, and by `kubectl -n farcast-system logs datasphered-0 --previous --tail 50 | grep -c 403`, whose "403" is [inf]. Only then is the uid recorded "not honoured". Skip as above.
  - A replica that does not start for another reason, such as an image pull, is a finding, recorded as its state.
- **Why:** A33-39 (a). It also settles R-R10: the write runs under the installer's conditioned `roles/storage.admin`.

**W4.9, (a): `storage cp` both ways (agent).**
```bash
head -c 1048576 /dev/urandom > w-a.bin
farcast storage cp w-a.bin "${INSTANCE}:walk/a.bin" > w4-9a.out 2> w4-9a.err; echo "exit $?"
farcast storage cp "${INSTANCE}:walk/a.bin" w-a.back > w4-9b.out 2> w4-9b.err; echo "exit $?"
cmp -s w-a.bin w-a.back && echo same
```
- **Record:** the exits, and `same`, yes or no.
- **What it shows:** `storage cp` runs on this Mac with the installer's key and the local keyring (`storage.go`'s group comment) [read]. So it shows the installer's path. The keyholder's path under the uid is W4.13's `present`.

**W4.10, (c): the grant read back.**
- **[U], agent:**
  ```bash
  farcast -o json storage deploy "$INSTANCE" --plan > w4-10.plan.json 2> w4-10.plan.err; echo "exit $?"; grant w4-10.plan.json bucket
  ```
  **Expect** `state:present`, `shared:missing`, `apply:false`. Nothing is written.
- **[B], agent:**
  ```bash
  farcast -o json storage deploy "$INSTANCE" --yes > w4-10b.json 2> w4-10b.err; echo "exit $?"; grep -o '"bucket_grant":"[a-z]*"' w4-10b.json
  ```
  **Expect** `present`. Every `storage deploy` mints a new keyholder leaf, so the StatefulSet rolls. It replaces `datasphered-1` first and waits there, because the new replica comes up sealed and is not Ready until unsealed (`datasphere/deploy/deploy.go`'s `updateStrategy` note) [read]. In Cloud Shell, `keyholder` until `datasphered-1` is STARTED true with a steady restart count. Then `farcast storage unseal "$INSTANCE" > w4-10u.out 2> w4-10u.err; echo "exit $?"`. Then `keyholder` until `datasphered-0` has been replaced: STARTED true, READY false, steady restarts. Then the unseal again, into `w4-10u2.out` and `w4-10u2.err`. `keyholder` then shows both READY true. *(2026-11-24, M2 walked: each unseal followed one `keyholder` read of the replaced replica, STARTED true with 0 restarts, not two (deviation 22).)*
- **Record:** the states, and on [B] the two unseals' exits.
- **Why:** farcast's exact match against what `getIamPolicy` returns (A33-8, OQ-F).

**W4.11, `toolchain`.**
- **Agent:**
  ```bash
  farcast toolchain "$INSTANCE" --builder <the builder image phase-5-session-a.md's S3 names, by its tag> \
    --fetcher <the fetcher image S3 names, by its tag> > w4-11a.out 2> w4-11a.err; echo "exit $?"
  grep -cE '^  [^ ]+@sha256:[0-9a-f]{64}$' w4-11a.err
  ```
  **Expect** exit 2: both tags refused, each with the digest it resolves to today. The count is 2.
- **Operator,** in the walk terminal: `cat w4-11a.err`. Read the two references, and accept them or not.
- **Agent,** once accepted:
  ```bash
  farcast toolchain "$INSTANCE" --builder "$(grep -oE '^  [^ ]+@sha256:[0-9a-f]{64}$' w4-11a.err | sed -n 1p | tr -d ' ')" \
    --fetcher "$(grep -oE '^  [^ ]+@sha256:[0-9a-f]{64}$' w4-11a.err | sed -n 2p | tr -d ' ')" > w4-11b.out 2> w4-11b.err; echo "exit $?"
  ```
  The refusal lists the builder first and the fetcher second (`toolchainCommand.settle`) [read].
- **Record:** refused, then mirrored: yes or no.
- **Stop:** a tag that no longer resolves is a finding, and the operator decides. Nothing is built yet.
- **Why:** `run` and `build` need both images pinned by digest, and §10.7 left this step out.

**W4.12, (d): the push grant.**
- **[U], agent:**
  ```bash
  farcast -o json build "$INSTANCE" --repo <the public repository's https:// address> --app alpha \
    --containerfile sdk/go/examples/demo/Containerfile --context sdk/go --plan > w4-12.plan.json 2> w4-12.plan.err; echo "exit $?"
  blocked w4-12.plan.json; grant w4-12.plan.json push
  ```
  **Expect** `blocked: none`, then `state:missing`, `shared:missing`, `apply:false`.
- **[U], operator:** the same line without `-o json` and the redirections, in the walk terminal. Run the add it prints in Cloud Shell. The plan is not confirmed.
- **[B], agent:** the same `--plan` line. **Expect** exit 1, `credential_missing` (`errkind w4-12.plan.json`).
- **[B], operator,** in the walk terminal:
  ```bash
  farcast build "$INSTANCE" --repo <the public repository's https:// address> --app alpha \
    --containerfile sdk/go/examples/demo/Containerfile --context sdk/go
  ```
  The push grant's notice, with its add, prints before "Build it?". Answer no: nothing is applied or billed. Run the add in Cloud Shell. *(2026-11-24, M2 walked: answered y. One build Job was applied, and failed at kaniko's push check before the grant settled (deviation 23).)*
- **Both:** wait at least 10 minutes: the 5.1 walk measured nine and more. Then, in Cloud Shell: `repomembers`. **Expect** `uid` 1, `shared` 0.
- **Record:** the states, whether the add ran, and the two counts.
- **Why:** A33-39 (d), A33-3 and A35-7. A fresh repository never held the shared principal, so only the add prints.

**W4.13, `run`: the builds push by the uid, and the keyholder serves under it.** The repository is the public one, as [phase 3.2's step 5](phase-3-2-validation.md#5-the-crux--operator-and-keyholder-agree-about-names) writes it.
- **[U], agent:**
  ```bash
  farcast -o json run "$INSTANCE" <the public repository> --manifest manifest/examples/sdk-demo/farcast --plan > w4-13.F.json 2> w4-13.F.err; echo "exit $?"; blocked w4-13.F.json
  farcast -o json run "$INSTANCE" <the public repository> --manifest manifest/examples/sdk-demo/farcast \
    --confirm "$(digest w4-13.F.json)" > w4-13.D.json 2> w4-13.D.err; echo "exit $?"; blocked w4-13.D.json; grant w4-13.D.json push
  farcast -o json run "$INSTANCE" <the public repository> --manifest manifest/examples/sdk-demo/farcast \
    --confirm "$(digest w4-13.D.json)" > w4-13.json 2> w4-13.err; echo "exit $?"; apps w4-13.json
  ```
  Confirm D within 15 minutes of the fetch: a deploy digest is good while the fetch Job it read exists. **Expect** D's push grant `state:present`: Artifact Registry returned the uid member byte-equal.
- **[B], agent:**
  ```bash
  farcast -o json run "$INSTANCE" <the public repository> --manifest manifest/examples/sdk-demo/farcast --plan > w4-13.F.json 2> w4-13.F.err; echo "exit $?"
  farcast -o json run "$INSTANCE" <the public repository> --manifest manifest/examples/sdk-demo/farcast \
    --confirm "$(digest w4-13.F.json)" > w4-13b.json 2> w4-13b.err; echo "exit $?"; errkind w4-13b.json
  farcast -o json run "$INSTANCE" <the public repository> --manifest manifest/examples/sdk-demo/farcast --yes > w4-13.json 2> w4-13.err; echo "exit $?"; apps w4-13.json
  ```
  **Expect** F printed, exit 0; its `--confirm` refused, exit 1, `credential_missing`, with nothing applied; then the `--yes` run. Its review goes to stderr, with no push commands while the grant is present [inf].
- **Then, agent:** `head -c 24 /dev/urandom | base64 | farcast secret set "$INSTANCE" sdk-demo/alpha DB_PASSWORD > w4-13s.out 2> w4-13s.err; echo "exit $?"`. The value is never kept.
- **Alpha's state,** a minute later, counted:
  - [U], agent: `farcast logs "$INSTANCE" alpha --namespace sdk-demo --tail 40 > w4-13.log 2> w4-13l.err; echo "exit $?"; grep -o '"state":"[a-z-]*"' w4-13.log | sort | uniq -c`;
  - [B], operator, Cloud Shell: `kubectl -n sdk-demo logs deploy/alpha --tail=40 | grep -o '"state":"[a-z-]*"' | sort | uniq -c`.
- **Record:** builds pushed, 2 of 2; applications deployed, 2 (`apps`); [U] D's push state; the count of `present`.
- **Stop:** a refused push prints farcast's push-denial text. Wait 10 minutes and run once more. Refused again, record that Artifact Registry did not honour the uid, and skip W3.4.
- **Why:** A33-39 (d). The keyholder reads the bucket under the uid alone.

**W4.14, the reader's reads after the run** (§37's `world`, `ps`, `logs` and `costs`; `logs` is W4.13's). Agent:
```bash
farcast -o json world "$INSTANCE" > w4-14w.json 2> w4-14w.err; echo "exit $?"; sections w4-14w.json; errkind w4-14w.json
farcast -o json ps "$INSTANCE" > w4-14p.json 2> w4-14p.err; echo "exit $?"; grep -oE '"(alpha|beta)"' w4-14p.json | sort | uniq -c; errkind w4-14p.json
farcast -o json costs "$INSTANCE" > w4-14c.json 2> w4-14c.err; echo "exit $?"; errkind w4-14c.json
```
- **Expect:**
  - [U]: every `world` section read; `ps` names `alpha` and `beta`; `costs` reads, with no error kind;
  - [B]: `credential_missing` from each (for `world`, on its cluster sections).
- **Stop:** on [U], an `unauthorized`, `forbidden` or `endpoint_refused` is a finding against A22-7 or the RBAC.

**W4.15, (f): the keyholder's account replaced, and the same-name refusal that stands for (e).** Only if G0a chose it. Every step but 3, 4 and 6 is the operator's, in Cloud Shell.
1. `kc; kubectl -n farcast-system delete serviceaccount datasphered; kubectl -n farcast-system create serviceaccount datasphered`.
2. `kubectl -n farcast-system delete pod datasphered-1`. Then `keyholder` every minute for 10 minutes. Then `kubectl -n farcast-system logs datasphered-1 --previous --tail 50 | grep -c 403` (without `--previous` if it has not restarted).
   - **Expect:** it restarts on its start-up bucket check (`serve.go`'s `provider.Validate`) [read]. Its account has the same namespace and name and another uid, which the policy does not hold. That the refusal's text holds "403" is [inf]; the restart count does not depend on it. *(2026-11-24, M2 walked: it restarted: 3 restarts by minute 1, 6 by minute 10. "403" counted 1 in the previous container's last 50 lines and 1 in the current one's.)*
3. **[U], agent:** `farcast -o json storage deploy "$INSTANCE" --plan > w4-15.plan.json 2> w4-15.plan.err; echo "exit $?"; grant w4-15.plan.json bucket`. **Expect** `state:missing`, `shared:missing`. **[B], operator, Cloud Shell:** `bucketroles`. **Expect** `uid` 0 and `other_uid` 1 per role.
4. **Operator,** in the walk terminal, on both branches: `farcast storage deploy "$INSTANCE" --grant-bucket`, yes to both questions. On [U] this walks the terminal consent.
5. **Cloud Shell:** `keyholder` until `datasphered-1` is STARTED true with a steady restart count: the deploy replaces it first, with a new leaf, and the rollout waits there until it is unsealed. Then `bucketroles`. **Expect** per role `uid` 1, `other_uid` 1 (the stale uid, which farcast leaves, A33-8 OQ-E) and `shared` 0. *(2026-11-24, M2 walked: `bucketroles` was read after both of step 6's unseals (deviation 22).)*
6. **Agent:** `farcast storage unseal "$INSTANCE" > w4-15u.out 2> w4-15u.err; echo "exit $?"`. Then the operator runs `keyholder` until `datasphered-0` is replaced (STARTED true, READY false), and the agent runs the unseal again into `w4-15u2.out` and `w4-15u2.err`. Then alpha's `present` again, read as in W4.13. *(2026-11-24, M2 walked: each unseal followed one `keyholder` read, as at W4.10 (deviation 22).)*
- **Record:** step 2's restarts and its count; steps 3 and 5's states and counts; the minutes to each replaced replica's steady start; the two unseals' exits; the count of `present`.
- **Why:**
  - A33-4 (c): a replaced account reads `missing`, and is granted again.
  - It stands for (e). Another instance's keyholder in the same project is a ServiceAccount of the same namespace and name with another uid, in the same pool. The only difference here is the cluster. Its refusal across two clusters is [inf] from this one (the design's A39-24).

**W4.16, `git-credential` and a private run.** Only if G0a chose it. Both plans read no cluster, so both branches take this route.
- **Agent:**
  ```bash
  farcast -o json git-credential set "$INSTANCE" --name <the Secret's name chosen at G0a> --username <the Git username chosen at G0a> \
    --token-file - --plan > w4-16s.plan.json 2> w4-16s.plan.err; echo "exit $?"; blocked w4-16s.plan.json
  ```
- **Operator,** in the walk terminal, with the digest the plan's human text prints (`farcast git-credential set … --plan` without `-o json`):
  ```bash
  read -rs TOKEN
  printf '%s' "$TOKEN" | farcast git-credential set "$INSTANCE" --name <the Secret's name> --username <the Git username> \
    --token-file - --confirm <the digest the plan printed>; echo "exit $?"
  unset TOKEN
  ```
  A pipe is stdin. A terminal or `/dev/null` is refused there, as a character device.
- **Agent:** `farcast -o json run "$INSTANCE" <the private repository chosen at G0a> --git-secret <the Secret's name> --plan > w4-16.F.json 2> w4-16.F.err; echo "exit $?"`. Then:
  - [U]: `--confirm` with F's digest into `w4-16.D.json`, as in W4.13. Then the **operator,** in the walk terminal: `grep -o '"external":\[[^]]*\]' w4-16.D.json`, and approves the hosts it lists before the agent confirms D. Then, within F's 15 minutes, `--confirm` with D's digest into `w4-16.json`;
  - [B]: `farcast -o json run "$INSTANCE" <the private repository> --git-secret <the Secret's name> --yes > w4-16.json 2> w4-16.err; echo "exit $?"`. The `--yes` run prints its review of the external declarations only to stderr: G0a's approval of the manifest stands for it.

  Then `apps w4-16.json`.
- **Agent:** `farcast -o json git-credential rm "$INSTANCE" --name <the Secret's name> --plan > w4-16r.plan.json 2> w4-16r.plan.err; echo "exit $?"; blocked w4-16r.plan.json`.
- **Operator,** in the walk terminal: `farcast git-credential rm "$INSTANCE" --name <the Secret's name> --confirm <the digest the plan printed>`.
- **Operator, Cloud Shell:** `kubectl -n farcast-system get secret <the Secret's name> -o name`. **Expect** NotFound.
- **Record:** the exits; whether the private run deployed; whether the Secret is gone.
- **Why:** §10.7's W4, and M2.8b.

**W4.17, one adaptation (operator, Cloud Shell).** Every 10 minutes, until the count is 1 or more, and at most 90 minutes after W4.13's run: *(2026-11-24, M2 walked: two reads by hand, then one paste that checked every 10 minutes by itself (deviation 24). The first resize came 60 minutes after W4.13's run.)*
```bash
kubectl -n farcast-system logs deploy/technocore | grep -c 'resized an application'
kubectl -n sdk-demo get deploy -o custom-columns=NAME:.metadata.name,REQ:.spec.template.spec.containers[0].resources.requests --no-headers
```
- **Record:** the minutes to the first resize, and each application's requests before and after.
- **If G0a chose it:** `managers sdk-demo deploy/alpha` once alpha is resized, and record its manager and operation pairs. That is W2's `technocore` half, read-only and free.
- **Why:** W3 needs one adaptation. `MinSamples` is 120 at a 30-second tick, about an hour for one Pod (`technocore/usage/profile.go`) [read]. W4.14 to W4.16 fill the wait. After a pause, Session A saw each application resized once (its S12 note). With no resize by 90 minutes, record that: W3.4 then has no adapted reset to record.

---

## W3. On `$INSTANCE`, after the run and one adaptation

Before and after each step, in Cloud Shell: `gens` and `rsets`. Record the change in each generation, and whether a ReplicaSet was made.

**W3.1, the adapt flag removed.**
- **[U], agent:**
  ```bash
  farcast -o json kernel deploy "$INSTANCE" --adapt=false --plan > w3-1.plan.json 2> w3-1.plan.err; echo "exit $?"; blocked w3-1.plan.json
  farcast kernel deploy "$INSTANCE" --adapt=false --confirm "$(digest w3-1.plan.json)" > w3-1.out 2> w3-1.err; echo "exit $?"
  ```
- **[B], agent:** `farcast kernel deploy "$INSTANCE" --adapt=false --yes > w3-1.out 2> w3-1.err; echo "exit $?"`.
- **Cloud Shell:**
  ```bash
  kubectl -n farcast-system get deploy technocore -o jsonpath='{.spec.template.spec.containers[0].args}' | grep -o -- '--adapt[^"]*' | wc -l
  managers farcast-system deploy/technocore
  ```
- **Expect:** 0 (`--adapt-cooldown` renders only beside `--adapt`) [read]; the generation moved by one and a ReplicaSet was made, since the template changed.
- **Record:** `--adapt` absent, yes or no; the generation's change; whether a ReplicaSet was made; the manager and operation pairs.
- **Stop:** `--adapt` still present is a stuck-field finding. Stop every write, and go to W5.
- **Why `--adapt=false`:** the kernel's settings are recorded and carried forward, so a deploy that does not name `--adapt` keeps it (deviation 1). The args list is atomic in server-side apply [inf], so this shows that the forced apply took effect, and no more (deviation 2).

**W3.2, the same `kernel deploy`, unchanged.**
- **Before it, Cloud Shell:** `specpaths farcast-system deploy/technocore > tc.before`.
- **[U], agent:** `farcast -o json kernel deploy "$INSTANCE" --plan > w3-2.plan.json 2> w3-2.plan.err; echo "exit $?"`, then `farcast kernel deploy "$INSTANCE" --confirm "$(digest w3-2.plan.json)" > w3-2.out 2> w3-2.err; echo "exit $?"`.
- **[B], agent:** `farcast kernel deploy "$INSTANCE" --yes > w3-2.out 2> w3-2.err; echo "exit $?"`.
- **After it, Cloud Shell:** `specpaths farcast-system deploy/technocore > tc.after`. If the generation moved, record only the paths that differ (`diff tc.before tc.after | grep '^[<>]' | cut -f1`), never the values.
- **Record:** whether the generation moved; whether a ReplicaSet was made; the paths.
- **Why:** an unchanged forced re-apply on Autopilot (§37).

**W3.3, `redeploy`, unchanged (agent, both branches).** Its plan reads no cluster. Before the plan, in Cloud Shell: `specpaths farcast-system deploy/fatline > fl.before`; after the confirm, `specpaths farcast-system deploy/fatline > fl.after`.
```bash
farcast -o json redeploy "$INSTANCE" --plan > w3-3.plan.json 2> w3-3.plan.err; echo "exit $?"; blocked w3-3.plan.json
farcast redeploy "$INSTANCE" --confirm "$(digest w3-3.plan.json)" > w3-3.out 2> w3-3.err; echo "exit $?"
```
- **Record:** for FatLine's Deployment, the generation's change, whether a ReplicaSet was made, and, if the generation moved, the paths from `diff fl.before fl.after | grep '^[<>]' | cut -f1`, never the values.
- **Why:** `redeploy` re-applies even when the image is unchanged, and never mints an mTLS identity (its Usage) [read]. So it is FatLine's unchanged forced re-apply.

**W3.4, the second `run`.** As in W4.13, into `w3-4.F.json`, `w3-4.D.json` and `w3-4.json` on [U]; with `--yes` into `w3-4.json` and `w3-4.err` on [B].
- **The resets:**
  - [U]: `resets w3-4.D.json`, the deploy plan's `application_reset` facts by application and state (deviation 14);
  - [B]: `grep -o 'adapted by the kernel at' w3-4.err | wc -l`, the review's reset lines. Never the time they name.
- **Then:** W4.17's requests line in Cloud Shell, and alpha's `present` after its restart, as in W4.13.
- **Record:** the applications reset as `adapted`, and their count; the requests after the run; the count of `present`.
- **Why:** P1's review, live. A second run is never unchanged: it mints the applications' leaves and resets their requests.

---

## W5. The audit (operator, Cloud Shell)

**W5.1, Admin Activity for the cluster.**
- **The read,** into a Cloud Shell file:
  ```bash
  gcloud logging read "<the Admin Activity log's name, as Google's audit-log pages spell it> AND resource.type=\"k8s_cluster\" AND resource.labels.cluster_name=\"farcast-$INSTANCE\"" \
    --project "$PROJECT" --freshness 1d --limit 5000 --format json > audit.json; echo "exit $?"
  jq length audit.json
  ```
  The log's name is a filter on `logName`, which the operator types from Google's pages. If the count equals the limit, raise the limit and read again. *(2026-11-24, M2 walked: the agent typed the log's name, in the block, from Google's documented form (deviation 16). The first read returned 5000, the limit, the newest 95 minutes; it was read again narrowed, not raised, without `system:` principals other than farcast-system's ServiceAccounts: 209 (deviation 25).)*
- **The grouping,** on screen only:
  ```bash
  jq -r '.[] | [.protoPayload.authenticationInfo.principalEmail, (if .protoPayload.requestMetadata.callerSuppliedUserAgent == "farcast" then "farcast" else "other" end), (.protoPayload.methodName | split(".") | .[-2:] | join(".")), (if .protoPayload.request then "body" else "no-body" end)] | @tsv' audit.json | sort | uniq -c
  ```
  The operator classes each principal: the installer, the reader, the kernel's ServiceAccount, the operator's own account (W4.15's hand steps), a GKE system principal, or other. *(2026-11-24, M2 walked: the block classed the principals in `jq`, so no email reached the screen or the chat, and the agent as exactly `farcast`, farcast-prefixed, `kubectl` or other (deviation 16).)*
- **Record:** the counts per class, agent class, method and body. Never an email.
- **Expect:**
  - farcast's applies as patches, by the installer, with the agent exactly `farcast` (`kube.UserAgent`) [read]; *(2026-11-24, M2 walked: not so. farcast's applies left no Admin Activity entry, except on ConfigMaps and Secrets: GKE kept a server-side apply sent as JSON and dropped the same apply sent as YAML, which farcast sends (`kube/apply.go`) (deviation 25). Those entries carry the agent "farcast,gzip(gfe)" (deviation 26).)*
  - the storage pin's create and replace; *(2026-11-24, M2 walked: held: `datasphered-pin` create 1 and update 1, the installer's, with no body.)*
  - `git-credential rm`'s delete, if W4.16 ran; *(2026-11-24, M2 walked: W4.16 was not chosen.)*
  - Secret and ConfigMap entries with no body; *(2026-11-24, M2 walked: held: the installer's configmaps and secrets entries, all with no body.)*
  - the kernel's writes under its own ServiceAccount; *(2026-11-24, M2 walked: held: configmaps.create 2 and update 56, no body; deployments.patch 2, the resizes, with a body.)*
  - no reader reads, which are Data Access, off unless WP.7 found it on [inf]. Whether the reader's five reviews show here is [unverified]. *(2026-11-24, M2 walked: no reader entries: no reader exists on [B], and WP.7 found Data Access none. The reviews stay [unverified].)*
- **Why:** §37, and §10.7's W5. The field names are [unverified].

**W5.2, the cross-check.** Entries with the agent `farcast` by a principal that is neither the installer nor the reader: 0. Installer entries with another agent: 0. *(2026-11-24, M2 walked: the agent reached the audit as "farcast,gzip(gfe)", not `farcast`: the first read counted 9 installer entries with another agent, all farcast-prefixed. Read with farcast-prefixed as farcast's, both counts were 0 (deviation 26).)*

**W5.3, ADR 0019's checklist.** Only if G0a chose it. These are [its Verification](../adr/0019-what-the-cluster-tells-its-provider.md#verification)'s steps 1 to 8, the precondition being WP.7's:
1. the logging and monitoring read-back; *(2026-11-24, M2 walked: the kube-state series were read by the agent in the console, read-only (deviation 28).)*
2. `k8s_container` counts in `farcast-system` and the application namespaces since install;
3. `farcast logs` (W4.13); *(2026-11-24, M2 walked: on [B] it is a reader read, refused: exit 1, "the reader key is not yet uploaded". The lines stand on `kubectl logs` in Cloud Shell, at W4.13, W4.15 and W3.4 (deviation 27).)*
4. `PodMonitoring`;
5. a ConfigMap entry with no body;
6. `pods/status` entries;
7. a build Job's create entry, for presence only, since its arguments name the repository; *(2026-11-24, M2 walked: no Job create entry exists: farcast applies its Jobs as YAML, which Admin Activity drops. The build Pods' creates, by the job controller, carry the template: 4 with `--context=git://…#<commit>`, the two runs' four builds.)*
8. after a seal and an unseal by the agent, `farcast storage seal "$INSTANCE" > w5-3s.out 2> w5-3s.err; echo "exit $?"` and then `farcast storage unseal "$INSTANCE" > w5-3u.out 2> w5-3u.err; echo "exit $?"`, the Endpoints and EndpointSlice entries. *(2026-11-24, M2 walked: 16 entries, each an update with a request and a response body.)*

Record each as ADR 0019 asks, in counts and levels.

---

## W6. Release, and the cloud at zero

1. **Agent:** `farcast release "$INSTANCE" --delete-data --yes > w6-1.out 2> w6-1.err; echo "exit $?"`.
   - **Expect:** exit 0 within 15 minutes. If a wait runs out, run it again: it waits for the same delete.
   - It ends with a reader line naming two Cloud Shell commands, which stays in `w6-1.out`. `--delete-data` is needed: the bucket holds the secret and `walk/a.bin`.
2. **Operator:** read the two reader commands in the walk terminal (`cat w6-1.out`), and run them in Cloud Shell, in order. Then the count of `farcast-reader-` accounts equals the baseline's. *(2026-11-22, ADR 0024: on [B], the operator then deletes, in Cloud Shell, the installer's key G0a approved: `gcloud iam service-accounts keys delete <the walk's key's id> --iam-account "<the installer's email>" --project "$PROJECT"`. The key to delete is the one whose id equals the key file's `private_key_id` field, both read on screen and never recorded. The operator deletes the key file on the Mac, and checks that no copy is left in the download folder or in Cloud Shell. Then WP.8's `count` line again: WP.8's count less one, which is 0 when WP.8 found 1.)* *(2026-11-24, M2 walked: the key's id was compared inside the block, not read on screen, and the Downloads folder was searched by the id, a count only (deviation 33).)*
   - On [B] they answer "not found", which is harmless (the probe walk's P7.3 note), unless W4.3 recorded "managed check silenced". Then they remove a real account.
3. **Operator:** every WP.7 count again, against the cloud, not against `release`'s report. Each equals the baseline. A difference is a finding, removed by hand only with the operator's yes.
4. **Operator:** turn the Org Policy API off, if the walk turned it on, as [the probe walk's P7.6](adr-0023-m2-probe-walk.md#p7-teardown) does. [U1]: the override restored or kept, as G0a decided.
5. **Operator:** delete Cloud Shell's walk directory, with its kubeconfig and `audit.json`.
6. **Agent:** `farcast -o json instances > w6-6.json 2> w6-6.err; echo "exit $?"; grep -o '"instances":\[\]' w6-6.json` prints `"instances":[]`: no instance is recorded. Then delete the walk directory: the release, the config home with the installer key's copy, the CA keys, the keyring and the reader's key, the plans and the outputs.
7. **Operator:** revoke the Git token at the Git host, if W4.16 ran.
8. **[U2]:** the fresh project kept or shut down, as G0a decided. This is the operator's. *(2026-11-22, ADR 0024: and under [B], if G0a chose a fresh project.)*

---

## Results

Walked 2026-11-24, at 3fd79c4, under [B], in the probe walk's project in the operator's own organization, and torn down to the baseline. G0a was answered 2026-11-23, and G0b's yes given 2026-11-24, without the real-API suite. G0a's choices: [B], which WP.7 found the legacy constraint enforces; the probe walk's project; the installer's existing key on the Mac, ADR 0024's approved exception, deleted in Google and on the Mac at W6.2; the Org Policy API allowed on, which WP.7 turned on and W6.4 off; W-FED, (f) as W4.15, W4.17's field managers and ADR 0019's checklist as W5.3, chosen; the `git-credential` step, W4.16, not chosen; W4 (e) dropped. The operator pasted every Cloud Shell block, as their FarCast account; typed every answer in the walk terminal; allowed Little Snitch's prompts; accepted the toolchain's two digests; and deleted the installer's key in Google and on the Mac. The agent ran `./check.sh`, the release build, the probes and every non-interactive farcast line; opened the walk terminal (deviation 17); wrote the Cloud Shell blocks, W5's tested offline first against a synthetic audit file, and put them on the clipboard (deviation 16); read only scrubbed output, but for the raw output relayed through the chat, none of it recorded (deviation 31); and read the kube-state series in the console, read-only (deviation 28). The instance was up about 3.3 hours, W4.1's start to W6.1's end, by the agent's step files (deviation 32): about USD 0.6 to 1.0 by G0b's floor model [inf], inside G0b's under USD 5. The bill was not read. One table follows, `Step | Result | Notes`, as the M1 and probe walks have.
- **Its opening sentence:** the date walked, the commit, G0a's and G0b's dates, the branch and the choices made there, the instance's hours, and its USD by the floor model.
- **A row may hold:** exits, kinds, counts, states (`present`, `missing`, `applied`) and booleans; minutes, rounded, from `time` or by the watch; the four manifests' first 12 hex and the sha256 of `SHA256SUMS`; the commit; the GKE version; requests; manager names; spec paths; principal classes.
- **Never** what T1 bars.

| Step | Result | Notes |
|---|---|---|
| WP.1 commit, `./check.sh` | Passed at 3fd79c4, in 963 s | From a clean tree, on the dev Mac: "check passed: root + sdk/go + Apple client · go1.27.4 · golangci-lint 2.15.0 · 31 vendored modules · Swift 6.4.2 · model: not run (--model)". The tree was still clean after it. |
| WP.3 release: `OK` count, tags, revision, `vcs.modified` | OK 11 of 11; `-tags=farcast_embedded`; revision 3fd79c4; `vcs.modified=false` | `farcast-release build -targets darwin/arm64` exit 0. sha256 of `SHA256SUMS`: 9ba18e14aec972f2a1f1ae4620ab783978b338238bdba8d908f882a59967659c. `bin/farcast` the same bytes. One host, not R0. WP.2: the walk directory made with `mktemp -d`, 0700, outside any checkout, with `bin/` and `walk.zsh`'s nine helpers; `config/` not made. |
| WP.4 the walk shell: nothing resolved; four components, first 12 hex | Nothing resolved; four components, each go1.27.4 | The agent's step: resolved tools 0; proxy, debug, Google or kubeconfig variables 0; `version` exit 0, stderr empty. Manifests' first 12 hex: datasphered f32d80358a9c, fatline 49e984103518, shrike 23b21c4b1d31, technocore 75741aa40fc2, technocore's equal to the build log's. The walk terminal, opened by the agent in the app's Terminal panel (deviation 17): after the operator's `source ./walk.zsh`, `command -v kubectl gke-gcloud-auth-plugin gcloud go gofmt` printed nothing. |
| WP.7 baseline counts | Taken 2026-11-24, by the operator in Cloud Shell, in one paste | Resources: clusters 0; repositories (us-central1) 0; buckets 0; forwarding rules 0; addresses 0; target pools 0; disks 0; instances 0; firewall rules 4; health checks 0; backend services 0. Accounts: service accounts 2; `farcast-reader-` accounts 0; `roles/container.clusterViewer` members 0; `roles/container.viewer` members 0 (W-FED's baseline, for information). WP.6 before it: the helpers defined, 11 of 11, from a clipboard block pasted twice, the first copy lost before pasting (deviation 16). |
| WP.7 the installer's roles; the APIs | All four roles held; the APIs on | `roles/container.admin`, `roles/iam.serviceAccountUser` and `roles/artifactregistry.admin`: yes, each with no condition. `roles/storage.admin`: yes, under the condition `farcast-buckets-only`. Other roles: 0. APIs: container, compute, artifactregistry, cloudresourcemanager and storage on; orgpolicy, gkehub and anthos off. |
| WP.7 key-upload checks; key expiry | Legacy `True`, managed `False`: [B]; no expiry enforced | The legacy check `True` (enforced), exit 0. The managed check found the Org Policy API off; the operator answered y, and it was turned on (deviation 19); then `False`, exit 0. So upload is blocked by the legacy constraint. Key expiry: `iam.serviceAccountKeyExpiryHours`' list policy, allValues ALLOW, exit 0: no expiry enforced, so W4.3 took no `--days`. |
| WP.7 ADR 0019's precondition; Data Access configuration | Held from the API states [inf]; Data Access none | The fleet memberships list FAILED, its error read as PERMISSION_DENIED, with gkehub and anthos off. The operator accepted the precondition from the API states, 2026-11-24 ("Accept it"): with those APIs off and no cluster in the project, there is no fleet membership and no GKE Enterprise enablement [inf]. The GKE Hub API was not turned on (deviation 20). Data Access: the project's own none; one ancestor, the organization, read: none. |
| WP.8 the branch's preparation | [B]: nothing made; the installer's user-managed keys 1, as expected | *(2026-11-22, ADR 0024: on [B], also the installer's user-managed key count, expected 1.)* Read in Cloud Shell, 2026-11-24, for the existing key G0a chose: 1 user-managed key, valid with no expiry date, not disabled. |
| G0a choices; G0b yes | G0a answered 2026-11-23; G0b's yes 2026-11-24 | G0a: [B]; the probe walk's project, its baseline known; the installer's existing key on the Mac, ADR 0024's approved exception, deleted in Google and on the Mac at W6.2, with none left in the walk's config home; the Org Policy API may be turned on at WP.7, and W6.4 turns it off again; W-FED yes, its summary presented (free IAM objects, one project-wide `container.viewer` grant while it runs, about USD 0.1 and up to an hour more, the pool and provider IDs reserved about 30 days); (f) yes; W4.17's field managers yes; ADR 0019's checklist as W5.3 yes; `git-credential`, W4.16, no; W4 (e) dropped; the real-API suite not yet asked. "Start WP now", 2026-11-24. G0b presented the cost (under USD 5 [inf]; by the floor model about USD 0.7 to 1.5, plus about USD 0.1 for W-FED; about 4 to 4.5 hours, plus up to an hour for W-FED and about 20 minutes for W5.3), what the walk creates, W-FED's full list again with its exceptions and the APIs Google may keep on, the teardown and what the project keeps, G0a restated, what a no means on [B], and the real-API suite first. The answer: "Yes, spend", without the real-API suite. |
| W4.1 install: exit, minutes, endpoint, registry | Exit 0 in about 4 minutes; endpoint 1, registry 1 | Stderr one line, no warning. |
| W4.2 `world` and `instances` before a reader | Exit 0; as expected | `spend` `kernel_absent`; `apps` `credential_missing`; `policy` `credential_missing`; `network` `not_connected`; `seal` skipped, `not_deployed`. `instances` exit 0, `reader:none`. |
| W4.3 `reader init`, the paste, `reader record` | [B]: stopped at the legacy constraint, nothing changed; `reader:not_uploaded` | `reader init` exit 0, with no `--days` (WP.7). The script, a `sh -s` here-document, checks the legacy constraint first. The agent put it on the clipboard, its sha256 equal to the one farcast printed (deviation 16). The operator's one paste stopped at its first policy check, the legacy constraint (`iam.disableServiceAccountKeyUpload`): "Nothing was changed". Not "managed check silenced". No `reader record` on [B]. `instances` exit 0, `reader:not_uploaded`. The stop line names the project; it reached the agent whole through the chat and is not recorded (deviation 31). |
| W4.4 `connect`: plan, confirm, status, carrier | Exits 0; blocked: none; `"connected":true`; carrier 1 | `--plan` exit 0, blocked: none. `--confirm` exit 0 in about 5 minutes; the operator allowed Little Snitch's prompt for the carrier (deviation 18). `--status` exit 0. |
| W4.5 `reader grant`: plan, minutes, IAM line, reviews; [B] refusals | [B]: the plan blocked `credential_missing`; the run refused, nothing written | `--plan` exit 0, blocked `credential_missing`. The run exit 1, code 1, `credential_missing`, nothing written. As expected. [U]'s grant, its minutes, IAM line and reviews: not run on [B], where no reader key can be uploaded. |
| W4.6 Kubernetes version; [U] `world` as the reader | 1.36.4-gke.2377000, minor 1.36 | `kc` exit 0. The probe walk saw 1.36. [U]'s `world` as the reader: not run on [B], where no reader exists. |
| W4.7 `kernel deploy --adapt`; `farcast-builder` exists | `--yes` exit 0; `farcast-builder` exists: yes | The `--yes` run exit 0 in about 1 minute; stderr 6 lines, no warning. In Cloud Shell: `serviceaccount/farcast-builder`. |
| W4.7 [B] the plan's refusal | Exit 1, `credential_missing`, nothing written | As expected. |
| W4.8 (a) `--grant-bucket`: state, per-role counts, IAM's lag, unseal | [B]: the terminal path applied the grant and printed no grant commands; per role uid 1, other_uid 0, shared 0; no restart; unseal exit 0 | The operator's `storage deploy --grant-bucket`: the cost question (about USD 7.39 a month modelled, about USD 19.82 at the floor without bursting), y; the grant question, naming `roles/storage.objectAdmin` and `roles/storage.legacyBucketReader` on "the bucket this deploy creates" and `farcast-system/datasphered` "by the uid it has once this deploy creates it", y. It created the keyring (0600) and the bucket, pushed the datasphered image this farcast carries (f32d80358a9c, WP.4's manifest), and deployed 2 sealed replicas. Its output says nothing of the grant itself. It was the third of three runs; the first two ended on an EOF (deviation 21). `bucketroles`: `legacyBucketReader` and `objectAdmin` each uid 1, other_uid 0, shared 0. `keyholder` from minute 0, soon after the deploy, to minute 6: both STARTED true, READY false, 0 restarts, so no restart came before both ran steadily. STARTED does not show that the start-up bucket check passed: it runs before any listener binds (`serve.go`). The unseal exit 0, stderr empty: "2 of 2 replicas are unsealed at generation 1, holding no application scopes", counted 1, one summary line for both. Both control listeners answered, so both start-up checks had passed under the uid grant [inf from `serve.go`]. After it, both READY true, STARTED true, 0 restarts. |
| W4.8 [B] the plan's refusal | Exit 1, code 1, `credential_missing`, nothing written | As expected. |
| W4.9 (a) `storage cp` both ways | Exits 0; same: yes | Up and down, the installer's path. |
| W4.10 (c) the grant read back | [B]: `bucket_grant` `present`; both unseals exit 0 | `storage deploy --yes` exit 0, stderr one line, no warning; the StatefulSet rolled. Minute 0: `datasphered-1`, replaced, STARTED true, READY false, 0 restarts; `datasphered-0` READY true. The unseal after that one read (deviation 22): exit 0, stderr empty, "2 of 2 replicas are unsealed at generation 2". Minute 1: `datasphered-0` replaced, STARTED true, READY false, 0 restarts; `datasphered-1` READY true. The second unseal exit 0, stderr empty, "… at generation 3". So `getIamPolicy` returned the uid member to farcast's exact match. |
| W4.11 `toolchain`: refused, then mirrored | Refused, then mirrored: yes | By the S3 tags: exit 2, both refused, each with the digest it resolves to today; 2 references, the builder first. The operator read and accepted both ("Accept both"), 2026-11-24. By the two digests: exit 0 in about 1 minute; stderr 4 lines, no error. WP.9 before it: S3 still names the builder (the kaniko executor v1.23.2) and the fetcher (the chainguard git latest-dev) by tag. |
| W4.12 (d) the push grant: states, add, counts | [B]: the add printed and run; `repomembers` uid 1, shared 0 | The operator's `build` printed the push grant's notice, one add and no remove, then "Build it?". It was answered y, not n, and the wait stopped with Ctrl-C (deviation 23). The build Job it applied failed in about 3 minutes, Error, exit 1, at kaniko's push check ("error checking push permissions" once and "DENIED" once in its log's last 30 lines), before the grant existed or had settled; it built and pushed nothing. The printed add, in Cloud Shell: "Updated IAM policy". `repomembers`, at least 10 minutes after the add: uid 1, shared 0. |
| W4.12 [B] the plan's refusal | Exit 1, code 1, `credential_missing` | As expected. |
| W4.13 `run`: builds, applications, D's push state, `present` | Builds pushed, 2 of 2; applications 2, alpha 1 and beta 1, each by digest; `present` 10 | [B]: F exit 0, blocked: none; the `--yes` run exit 0 in about 3 minutes. Its review on stderr, 32 lines: the public repository read inside the instance at main's head of the day; the manifest's digest; alpha and beta each "reaches nothing outside the instance"; two build Jobs, one at a time; about USD 7.39 a month for the two applications, the instance about USD 77.42 a month standing; scopes minted for alpha and beta, the keyholder at generation 4. No push commands (the grant present) and no push denial: Artifact Registry honoured the uid member for both pushes. D's push state is [U]'s, not on [B]. `secret set` from 24 random bytes, base64, piped: exit 0, stderr empty, the value never kept. Alpha's last 40 log lines, in Cloud Shell a few minutes after the secret: "state":"present" 10 times, no other state. WP.9 before it: the public repository's main, read anonymously, held the manifest and the demo as at 3fd79c4, and the manifest declares no external host. |
| W4.13 [B] `--confirm` F's refusal | Exit 1, code 1, `credential_missing`, nothing applied | As expected. |
| W4.14 `world`, `ps`, `costs` after the run | [B]: `credential_missing` from each, as expected | `world` exit 0: `spend`, `apps` and `policy` `credential_missing`, the cluster sections; `network` and `seal` read. `ps` exit 1, code 1, `credential_missing`. `costs` exit 1, code 1, `credential_missing`. |
| W4.15 (f) replaced account: restarts, states, counts, `present` | Refused at start-up until granted again; then per role uid 1, other_uid 1, shared 0; `present` 10 | Steps 1 and 2 in one paste: `kc` exit 0; `farcast-system/datasphered` deleted and created again (same namespace and name, another uid); `datasphered-1` deleted. `keyholder` each minute: minute 0, `datasphered-1` STARTED true, READY false, 0 restarts; minute 1, STARTED false, 3 restarts; then 4, 5, 5, 5, 6, 6, 6, 6 and 6 at minutes 2 to 10, the kubelet's back-off; `datasphered-0` READY true, STARTED true, 0 restarts throughout. "403" in the last 50 lines: previous container 1, current container 1. Step 3 [B], `bucketroles`: per role uid 0, other_uid 1, shared 0. Step 4: `storage deploy --grant-bucket`, y to both questions; it finished, no grant commands. Step 5, minute 0: `datasphered-1`, replaced under the new grant, STARTED true, READY false, 0 restarts. Step 6: the unseal after that one read (deviation 22), exit 0, stderr empty, "2 of 2 replicas hold 2 application scope(s) at generation 5": the replaced replica's start-up check had passed under the new uid's grant within about a minute of the deploy, with no restart [inf from `serve.go`]. Minute 1: `datasphered-0` replaced, sealed; the second unseal exit 0, "… at generation 6". Then `bucketroles`: each role uid 1, other_uid 1 (the stale uid, which farcast leaves), shared 0; `keyholder` both READY true, 0 restarts. Each replaced replica started steadily within about a minute. Alpha: "state":"present" 10 times. |
| W4.16 `git-credential` set, private run, rm | Not chosen at G0a | Not run; W6.7 had no token to revoke. |
| W4.17 one adaptation: minutes, requests; field managers | First resize 60 minutes after W4.13's run; each application from cpu 100m and memory 128Mi to 50m and 64Mi; managers farcast/Apply, kube-controller-manager/Update/status, technocore/Update | Soon after the run: resized 0; alpha and beta each cpu 100m, ephemeral-storage 1Gi, memory 128Mi. About 40 minutes after it [inf]: resized 0, requests unchanged. Then one paste checking every 10 minutes (deviation 24): 47 minutes after alpha was created, 0; 58, 0; 68, 2. Each application resized once. After: each cpu 50m, ephemeral-storage 1Gi, memory 64Mi. `managers sdk-demo deploy/alpha` after the resize: farcast/Apply 1, kube-controller-manager/Update/status 1, technocore/Update 1. |
| W3.1 `--adapt=false`: args, generation, ReplicaSet, managers | `--adapt` absent: yes; technocore's generation 1 to 2; one ReplicaSet made; managers farcast/Apply, kube-controller-manager/Update/status | [B] `--yes` exit 0; stderr 4 lines, no warning. Before: generations fatline 1, technocore 1, alpha 2, beta 2, the StatefulSet datasphered 3; ReplicaSets fatline 1, technocore 1, alpha 2, beta 2 (and GKE's own in gke-gmp-system and kube-system). After: technocore's ReplicaSets 1 to 2; every other generation and ReplicaSet unchanged. As expected. |
| W3.2 unchanged `kernel deploy` | Generation stayed 2; no ReplicaSet made; no path differs | [B] `kernel deploy --yes`, by the agent; its exit is not in the walk's record. `specpaths` of technocore, 40 lines before and 40 after. Nothing else moved. An unchanged forced re-apply on Autopilot moved nothing. |
| W3.3 unchanged `redeploy` | Generation stayed 1; no ReplicaSet made; no path differs | `--plan` exit 0, blocked: none; `--confirm` exit 0; stderr 3 lines, no warning. `specpaths` of fatline, 92 lines before and 92 after. Nothing else moved. FatLine's unchanged forced re-apply moved nothing. |
| W3.4 second `run`: resets, requests, `present` | Reset lines 2, alpha and beta; requests back to cpu 100m and memory 128Mi; `present` 2 | [B] `--yes` exit 0 in about 4 minutes; alpha 1, beta 1, each by digest; stderr 32 lines; no push commands. The review's "adapted by the kernel at …" lines: 2, one for each application, the time they name not recorded. Requests after: each cpu 100m, ephemeral-storage 1Gi, memory 128Mi, from 50m and 64Mi. Alpha after its restart: "state":"present" 2 times in its last 40 lines. Generations: alpha and beta each 2 to 3 (the resize had moved each from 1 to 2); the others unchanged. ReplicaSets: alpha and beta each 2 to 3. |
| W5.1 Admin Activity, by class, agent, method and body | farcast's own applies leave no entry, except on ConfigMaps and Secrets: the installer's, with no body | First read: exit 0, 5000 entries, the limit, so truncated, the newest 95 minutes (deviation 25). Second, narrowed to leave out `system:` principals other than farcast-system's ServiceAccounts: exit 0, 209 entries. By class, agent, method and body: a user account, `kubectl`: pods.delete 1, serviceaccounts.create 1 and serviceaccounts.delete 1, each with a body (W4.15's hand steps); the kernel's ServiceAccount, agent other: configmaps.create 2 and update 56, no body, and deployments.patch 2, the resizes, with a body; a Google service agent, other: gatewayclasses.create 4 and update 112, and status.update 4, each with a body; the installer, farcast-prefixed: configmaps.create 1, patch 10 and update 1, and secrets.patch 9, all with no body; other, `kubectl`: rolebindings.create 1 and roles.create 1, with a body; other, agent other: certificatesigningrequests.create 3, with a body (both "other" classes GKE's own [inf]). The storage pin's create and replace: `datasphered-pin` create 1 and update 1, the installer's. No reader entries: no reader on [B], and Data Access none (WP.7). The diagnostic: the installer's 40 Admin Activity entries of the last day held, for the cluster, configmaps and secrets only; by any principal, no create or patch of FarCast's Namespaces, Deployments, StatefulSet, Services, NetworkPolicies, ServiceAccounts, Roles, RoleBindings or Jobs but the kernel's two resizes, the Job controllers' Job patches, each namespace's default ServiceAccount and W4.15's ServiceAccount create and delete by hand. The probe, on the operator's choice: the same server-side apply was kept with a JSON body and dropped with a YAML one; farcast sends YAML (`kube/apply.go`) [read]. |
| W5.2 the cross-check | 0 and 0, with farcast's agent read as "farcast,gzip(gfe)" | First read: the agent exactly `farcast` by a class neither the installer nor the reader: 0; installer entries with another agent: 9, all farcast-prefixed, a finding against W5.1's "exactly `farcast`". Second read: farcast or farcast-prefixed by a class neither the installer nor the reader: 0; installer entries with an agent that is neither: 0. Every farcast-prefixed entry's agent: "farcast,gzip(gfe)", 21; Google's front end appends ",gzip(gfe)" [inf] (deviation 26). |
| W5.3 ADR 0019's checklist | Done; ADR 0019's disclosure holds in substance, through the controllers' entries | (1) Logging SYSTEM_COMPONENTS only. Monitoring as found: SYSTEM_COMPONENTS, STORAGE, HPA, POD, DAEMONSET, DEPLOYMENT, STATEFULSET, CADVISOR, KUBELET, DCGM, JOBSET; managed Prometheus enabled; advanced datapath observability metrics enabled. The kube-state series, read by the agent in Metrics Explorer, read-only (deviation 28): `kube_pod_container_status_ready` for the datasphered container in farcast-system, the last hour, one series for each replica, named by the Pod's uid and name, so the 24-month metrics disclosure is shown, not inferred. (2) `k8s_container` entries since install: farcast-system and sdk-demo 0; kube-system, for contrast, 50 of at most 50 read. (3) [B]: `farcast logs` refused, exit 1, "the reader key is not yet uploaded"; the lines stand on `kubectl logs` at W4.13, W4.15 and W3.4 (deviation 27). (4) PodMonitoring: farcast-system 0, sdk-demo 0, elsewhere none; ClusterPodMonitoring: gke-managed-dcgm-exporter and kube-state-metrics, GKE's own. (5) farcast-system ConfigMaps by any principal: 67 entries, none with a request or a response body: `datasphered-pin` create 1 and update 1, `fatline-egress-policy` patch 2 and `technocore-namespaces` patch 4 (the installer); `technocore-ledger` create 1 and update 28, `technocore-profiles` create 1 and update 28 (the kernel's ServiceAccount); `kube-root-ca.crt` create 1 (a kube-system ServiceAccount). (6) `pods/status` in farcast-system and sdk-demo by any principal: 0, as ADR 0019 expects with Data Access off. (7) No Job create entry. Pod creates there, the last day: 24, each by a kube-system controller, each with a body: in farcast-system `build-$INSTANCE-alpha` 1 (W4.12's extra build), `build-sdk-demo-alpha` 2, `build-sdk-demo-beta` 2 and `fetch-farcast` 2 (the job controller), datasphered 7 (the StatefulSet controller), fatline 2 and technocore 2 (the ReplicaSet controller); in sdk-demo alpha 3 and beta 3 (the ReplicaSet controller). Those carrying `--context=git://…#<commit>`: 4, the two runs' four builds (the extra build named a branch, not a commit [inf]). sdk-demo Pod creates carrying an image by digest: 6. So each build's repository and commit, and every workload's Pod spec, are kept 400 days, in the controllers' Pod creates: a build Job's create entry is a build Pod's. (8) `storage seal` exit 0, both "restart-sealed"; about 45 s later `storage unseal` exit 0, "2 of 2 replicas hold 2 application scope(s) at generation 7". Admin Activity, the last 15 minutes: 16 updates, each with a request and a response body: endpoints datasphered 4; endpointslices datasphered 4, datasphered-status 4 and datasphered-unseal 4. Their bodies carry each replica's address, node name, Pod name, namespace and uid, its ready and serving conditions, hostname and zone; the ports' names, numbers and protocols; and the Service's name and labels. |
| W6.1 `release` | Exit 0 in about 6 minutes; released | Stderr 6 lines, no warning. The cluster, the registry and the bucket deleted: "2 objects are now permanently unreadable". Kept by the provider, as `release` prints: the audit log of the instance's API writes until about 400 days on, system logs and events until about 30 days on, metrics about the Pods until about 24 months on. The reader line names the two Cloud Shell commands. State removed. The audit line overstates how the writes are kept, and `release`'s Usage text more so, "every create, update and delete" on the cluster's API with "the full spec of every workload" (`release.go`) [read]: farcast's own applies leave no entry except on ConfigMaps and Secrets, and the controllers' Pod creates and the Endpoints updates carry the rest (W5). Both texts were changed after the walk (the follow-ups after deviation 34). |
| W6.2 the reader lines; reader accounts at the baseline | Both "not found", harmless on [B]; reader accounts 0; the installer's key deleted, keys 0 | *(2026-11-22, ADR 0024: on [B], also the installer's key deleted, and its count after, expected WP.8's less one: 0 when WP.8 found 1.)* One block: the binding's removal exit 1, "not found"; the account's deletion exit 1, NOT_FOUND, since no reader was made. `farcast-reader-` accounts 0, as WP.7's. The installer's user-managed keys 1, the Mac key file's id among them: yes, compared in the block, no id shown (deviation 33). The operator's y; the key deleted in Google, exit 0; user-managed keys 0, WP.8's count less one. On the Mac the operator deleted the key file; the agent checked it gone, found no file in the Downloads folder holding the key's id (a count: 0), and none in the walk's config home. The key never reached Cloud Shell. |
| W6.3 the cloud at the baseline | Every count at the baseline, but the installer's keys, 1 to 0, as W6.2 intended | Clusters 0; repositories 0; buckets 0; forwarding rules 0; addresses 0; target pools 0; disks 0; instances 0; firewall rules 4; health checks 0; backend services 0; service accounts 2; `farcast-reader-` accounts 0; `roles/container.clusterViewer` members 0; `roles/container.viewer` members 0; the installer's role bindings 4; the project's Data Access configurations 0; the installer's user-managed keys 0. APIs: container, compute, artifactregistry, cloudresourcemanager, storage, IAM and IAM Credentials on; orgpolicy on, from WP.7; gkehub, anthos and STS off. |
| W6.4 to W6.8 the Org Policy API, Cloud Shell, the walk directory, the token, the project | The Org Policy API off; Cloud Shell's directory removed; `"instances":[]`, and the walk directory removed; W6.7 not run; W6.8 not applicable | W6.4: on the operator's y, disabled, exit 0, read back off; the APIs as at WP.7. W6.5, a guarded line: `KUBECONFIG` unset; Cloud Shell's walk directory, with its kubeconfig and the audit files, removed: "removed: yes". W6.6: `instances` exit 0, `"instances":[]`; the walk directory listed first (the release, the config home with the keyring and the CA keys, both probes, the project and instance files, every block, plan and output; about 214 MB), then removed with `rm -rf` on its literal path: gone. W6.7: W4.16 not chosen. W6.8: the probe walk's project kept, as G0a chose. Left to the operator: the walk terminal's tab in the app's Terminal panel, whose shell sat in the removed directory. |

Afterwards each record the walk bears on gets a dated note, and walked text stays as walked. Among them: ADR 0023's status line and its M2 row; [phase 1's step 7b](phase-1-validation.md#7b-the-instances-reader-identity--not-yet-walked), whose procedure W4.3 and W4.5 walk on [U]; ADR 0019's Verification, if W5.3 ran; the records that defer to "the next walk", which the M2 design's A39-7 lists; and the twelve "unverified until the M2 walk" sites in code, which change with these results. *(2026-11-24, M2 walked: these notes were written 2026-11-24, from the walk's record.)*

---

## What this walk settles, and what it does not

Each item holds only if its step passes. A failure is recorded as the answer the other way.

**It settles:**
- whether Autopilot's mutations converge under farcast's forced apply: W3.2's and W3.3's unchanged re-applies move no generation and make no ReplicaSet, or the record names the spec paths that moved. This answers §14's risk 3, as §37 restated it; *(2026-11-24, M2 walked: it held. W3.2's unchanged `kernel deploy` and W3.3's unchanged `redeploy` moved no spec path and no generation, and made no ReplicaSet.)*
- that farcast's forced apply takes effect under Autopilot's admission (W3.1), not field by field; *(2026-11-24, M2 walked: it held. After W3.1 `--adapt` was absent from technocore's args, its generation moved by one, and one ReplicaSet was made.)*
- the audit's caller identity and user agent for M2's writes, and the levels of the Secret and ConfigMap entries (W5.1, W5.2); *(2026-11-24, M2 walked: found otherwise. farcast's own server-side applies leave no Admin Activity entry, except on ConfigMaps and Secrets, which carry the installer as caller, the agent "farcast,gzip(gfe)" and no body. A probe showed GKE keeping a server-side apply sent as JSON and dropping it sent as YAML, which farcast sends (`kube/apply.go`). The content still reaches the provider in the controllers' Pod creates and the Endpoints and EndpointSlices updates (W5.3 (7), (8)).)*
- A33-4 (f) and OQ-F: *(2026-11-24, M2 walked: held on [B], but for Artifact Registry's byte-equal return, which is [U]'s; see each below.)*
  - Cloud Storage accepts a uid member, and the keyholder validates and serves under it alone (W4.8, W4.13); *(2026-11-24, M2 walked: it held. The grant was applied, both replicas unsealed, so their start-up bucket checks had passed under it [inf from `serve.go`], and alpha read `present` 10 times.)*
  - `getIamPolicy` returns it byte-equal to farcast's exact match (W4.10); *(2026-11-24, M2 walked: it held: `bucket_grant` `present` (W4.10 [B]).)*
  - Artifact Registry honours it for a push (W4.12, W4.13) and, on [U], returns it byte-equal; *(2026-11-24, M2 walked: the push held: both runs' builds pushed by digest, and W4.12's extra build, before the grant, was refused at kaniko's push check. The byte-equal return is [U]'s, not walked.)*
  - a replaced ServiceAccount reads `missing`, is refused until granted again, and is granted again (W4.15); *(2026-11-24, M2 walked: it held. On [B] `bucketroles` read uid 0 and other_uid 1 per role; the replaced replica restarted on its start-up check, with "403"; and the account was granted again: uid 1, other_uid 1, shared 0.)*
- R-R10: the installer's conditioned `roles/storage.admin` may read and write the bucket's policy (W4.8). As a by-product, the installer's roles allow the plans' Google reads (A33-1); *(2026-11-24, M2 walked: R-R10 held: the grant was applied under the installer's roles, of which the conditioned `roles/storage.admin` is the one that covers a bucket's policy [inf]. A33-1's plans were refused on [B] for want of a reader, so their reads are not walked as plans.)*
- A33-20: `kernel deploy` creates `farcast-builder` before any build (W4.7); *(2026-11-24, M2 walked: it held: `farcast-builder` existed after W4.7, before any build.)*
- the cluster's version (W4.6), and `run`'s resets live (W3.4), if an adaptation happened by W4.17's limit; *(2026-11-24, M2 walked: both held: 1.36.4-gke.2377000, minor 1.36; one adaptation at 60 minutes, and the second run printed 2 reset lines and reset the requests.)*
- [U] only: *(2026-11-24, M2 walked: none of these, on [B].)*
  - the reader end to end with farcast's scope pair, A22-7's open reader evidence (W4.3, W4.5, W4.6, W4.14); *(2026-11-24, M2 walked: not on [B], where key upload is blocked. A22-7's reader evidence stays open.)*
  - three of the six reader plans with their `--confirm`: `kernel deploy`'s, `storage deploy`'s with `--grant-bucket`, and `run`'s deploy plan; *(2026-11-24, M2 walked: not on [B]; there each was refused `credential_missing`.)*
  - `build`'s plan, printed and not confirmed; *(2026-11-24, M2 walked: not on [B]; there `build --plan` was refused `credential_missing` (W4.12).)*
  - `--grant-bucket`'s terminal consent (W4.15); *(2026-11-24, M2 walked: on [B] the same terminal questions ran at W4.8 and W4.15, without a reader.)*
- [B] only: the reader plans' `credential_missing` refusals live, with nothing written, and `--grant-bucket`'s terminal path where no reader can exist (W4.8, W4.15); *(2026-11-24, M2 walked: it held. Each reader plan the walk tried (`kernel deploy`'s, `storage deploy`'s, `build`'s and `run`'s deploy plan) was refused `credential_missing`, with nothing written, and `reader grant`'s plan was blocked `credential_missing`. Of the reader reads, `world`'s cluster sections, `ps` and `costs` were refused `credential_missing`, and `logs` for want of the reader's key. `--grant-bucket`'s terminal path applied the grant and printed no grant commands.)*
- both: `connect`'s and `redeploy`'s plan and `--confirm`; with W4.16, `git-credential set` and `rm`, and a private repository fetched and built through them. *(2026-11-24, M2 walked: `connect` and `redeploy` held (W4.4, W3.3). W4.16 was not chosen, so `git-credential` and a private repository were not walked.)*

**It does not settle:**
- Cloud Storage's answer to a policy write at a stale etag (A33-13, A35-6). No step writes one, and the old optional (g) is not carried; *(2026-11-24, M2 walked: still open.)*
- separation by uid across two clusters, which was (e) (the design's A39-24). W4.15's same-name refusal on one cluster stands for it [inf]. A compromised cluster in the same pool can present any uid, so one project per instance stays the full separation; *(2026-11-24, M2 walked: still open. W4.15's same-name refusal held on one cluster and stands for it [inf].)*
- W4 (b), the swap of a shared grant on a live keyholder. It is pinned against fixtures only (`TestBucketGrantRemovesTheSharedBinding`); *(2026-11-24, M2 walked: not walked.)*
- the kernel's `/scale` write under Autopilot (A31-12): no step reaches the cost limit. W2's `technocore` half, beyond W4.17's optional read; *(2026-11-24, M2 walked: not walked. W4.17's optional read was taken: alpha's managers are farcast/Apply, kube-controller-manager/Update/status and technocore/Update.)*
- the real-API suite's twelve tests (the design's §38, *What is still not run*), A38-17's preconditions included; *(2026-11-24, M2 walked: not run. Offered at G0b; the yes came without it.)*
- R0, the second host; *(2026-11-24, M2 walked: not run.)*
- `storage key pin` and `storage key rotate` with a keyholder, and their plans; `kernel meter` and `kernel confirm`; `reader grant`'s and `build`'s `--confirm`; *(2026-11-24, M2 walked: not walked.)*
- writes through the keyholder under the uid. Only its start-up check and its reads are observed; that `objectAdmin` covers its writes is [inf]; *(2026-11-24, M2 walked: still [inf].)*
- on [B], the reader end to end and every reader plan under `--confirm`. On [U], the blocked organization's refusals beyond the paste's stop, walked 2026-11-16; *(2026-11-24, M2 walked: on [B], as expected: the reader is not walked.)*
- A22-3, the init script's silenced managed check. It is not fixed, and the walk can meet it; *(2026-11-24, M2 walked: not met: the legacy constraint stopped `reader init`'s paste first (W4.3).)*
- risk 5 (removed applications keep billing) and risk 7 (two runs racing on the egress policy); *(2026-11-24, M2 walked: not walked.)*
- ADR 0019's checklist, unless W5.3 is chosen; *(2026-11-24, M2 walked: W5.3 was chosen and walked.)*
- any instance an older farcast wrote: none exists, and no migration remains (M2.9a); *(2026-11-24, M2 walked: none existed; the walk installed fresh.)*
- M3a and M3b, M4, M5, and every FarSight client claim. *(2026-11-24, M2 walked: not settled by this walk. M3a was walked on its own, 2026-11-23; W-FED answered M3b's largest unknown on S1 ([W-FED's Results](#w-feds-results)); M3b has not started.)*

---

## W-FED. The federated reader at the cluster (optional; ADR 0024)

Written 2026-11-22 with ADR 0024's M3a build, and amended 2026-11-23 by its review. Offered at G0a only if M3a passed in the organization project, with its own approval. It runs after W5 and before W6.1, while the cluster exists. *(2026-11-23, ADR 0024's M3a walked: it passed there on 2026-11-23.)*

It tests M3b's largest unknown on a cluster that exists anyway: whether GKE's DNS endpoint accepts a token made from a device's own certificate. One fresh writer-capable device, made by M3a's probe ([its runbook](adr-0024-m3a-probe.md)), gets the M3a setup in this walk's project; its reader's federated token impersonates its reader SA; and that SA token reads the cluster. Then the federated token itself is tried, unimpersonated. The probe prints statuses, counts and yes/no only, never a token, an email or an ID, and every record here keeps T1.

**Its approval.** At G0a the agent presents these and waits for the operator's yes, which WF.0's row records with its date. G0b's list of what the walk creates does not name W-FED's objects, so when G0a approved W-FED the agent presents them again at G0b.
- **What it creates,** in this walk's project: one pool; two X509 providers, one per role, each holding that role's one anchor; two service accounts with no display name, the writer's with no role; two `roles/iam.workloadIdentityUser` bindings, each role's ID on its own SA; and those of the IAM, IAM Credentials, STS and Resource Manager APIs that are off, recorded in a randomly named file in Cloud Shell's home. *(2026-11-23, ADR 0024's M3a walked: there IAM Credentials, off before, came on with the IAM API [inf], printed `already enabled` and stayed out of the block's record, so the teardown did not try it (M3a's deviation 31). WF.5 and WF.6 should expect the same here whenever WF.2 reads the IAM API off.)*
- **Its one privileged grant:** `roles/container.viewer` on the project, for the reader SA, from WF.3 to WF.5. It is project-wide: while it stands, the device's reader can read every cluster in the project, not only `$INSTANCE`'s.
- **The cost.** The IAM objects bill nothing ([M3a's runbook](adr-0024-m3a-probe.md)). W-FED keeps the instance up longer, by up to about an hour: three pastes, the settle waits of up to 10 minutes from `wfed-setup` and from `wfed-viewer`, `wfed`'s 20-minute bound and `wfed-gone`'s 15-minute bound. At G0b's floor of about USD 0.106 an hour that is about USD 0.1 more [inf], outside G0b's "W4.1 to W6.1 is about 4 to 4.5 hours".
- **Hard to reverse:** a deleted pool's or provider's ID stays reserved for about 30 days ([Google](https://docs.cloud.google.com/iam/docs/manage-workload-identity-pools-providers)), which W-FED's random IDs absorb.
- **The teardown,** WF.5, and that Google may leave on the APIs W-FED enabled: without `--force` it refuses to disable a service used in the last 30 days (M3a's deviation 21). *(2026-11-23, ADR 0024's M3a walked: there it held for Resource Manager only; STS and IAM, enabled the same day, were disabled without `--force` (M3a's deviation 32).)* *(2026-11-24, M2 walked: here only STS was enabled, and it was disabled without `--force`.)*
- **Its exceptions to this runbook's rules,** named here: T2's (the Mac also runs a probe binary); WP.5's ("No walk probe is built": WF.0 builds one); and T5's (the agent reads the probe's own `.out` files, which the probe has scrubbed, not only exits, kinds, counts and states through `walk.zsh`). The firewall stays the operator's (T4).

- **WF.0, before WP.4 (only if G0a approved W-FED).**
  - The agent builds the probe once, from the walked commit, outside the walk shell, which has no `go` (WP.4):
    ```bash
    mkdir -m 700 <the walk directory>/probe
    env GOWORK=off GOTOOLCHAIN=go1.27.4 GOPROXY=off GOFLAGS=-mod=vendor \
      go test -C <the checkout> -tags walk -c -o <the walk directory>/probe/walkprobe.test ./farsight/cli/internal/cli/
    ```
    `probe/` is not on the walk shell's `PATH`; the steps below name the binary by its path.
  - The operator adds Little Snitch rules for that path (T4), and nothing else: STS's mTLS endpoint `sts.mtls.googleapis.com:443`, IAM Credentials' endpoint `iamcredentials.googleapis.com:443`, and the cluster's DNS endpoint, each named as WP.5 names its rules. *(2026-11-24, M2 walked: the operator allowed Little Snitch's prompts for the probe as they came (deviation 18).)*
- **WF.1 (agent).**
  - `mkdir -m 700 wfed` in the walk directory, then `ls -led . wfed | cut -c1-11`. *Expect* exactly two `drwx------` lines, with no `+` after either and no further line. A `+`, or any further line, is an access control list, which can let another account read the device's 0600 keys: `devicekey` and the probe check mode bits only (`devicekey.Store`'s comment). Then stop, remove `wfed`, and make it again where no ACL is inherited.
  - Run `wfed-init`, then `wfed-blocks`, as `step.zsh` lines (T5), each in the form:
    ```bash
    env FARCAST_WALK=1 FARCAST_WALK_CWD="$PWD" FARCAST_WALK_M3A_DIR="$PWD/wfed" FARCAST_WALK_PROJECT="$PROJECT" FARCAST_WALK_M3A_STEP=wfed-init \
      ./probe/walkprobe.test -test.run '^TestWalkM3a$' -test.v -test.count=1 -test.timeout 0 > wf-1a.out 2> wf-1a.err; echo "exit $?"
    ```
    Every later step is the same line with its own `FARCAST_WALK_M3A_STEP`, its own inputs, and its own output files. `mark <name>` below means `FARCAST_WALK_M3A_STEP=mark FARCAST_WALK_M3A_MARK=<name>`. A mark is taken only after the block printed its change; on `refused` or `absent`, record the line and paste again (M3a's P5 rule).
  - Record the counts `wfed-init` printed, and that `wfed-blocks` wrote its three blocks.
- **WF.2 (operator).**
  - First, W-FED's own baseline, in Cloud Shell, counts and yes/no only: the pools, DELETED excluded (`count gcloud iam workload-identity-pools list --location=global`); the service accounts (`count gcloud iam service-accounts list`); the members of `roles/container.viewer` in the project's policy (`gcloud projects get-iam-policy "$PROJECT" --format=json | jq '[.bindings[] | select(.role == "roles/container.viewer") | .members[]] | length'`); and, yes or no each, whether the IAM, IAM Credentials, STS and Resource Manager APIs are on, read from `gcloud services list --enabled --project "$PROJECT"` on screen. WP.7 counts none of these but the service accounts. *(2026-11-24, M2 walked: the baseline and `wfed-setup.sh` went as one paste (deviation 29).)*
  - Paste `wfed-setup.sh` (`pbcopy < wfed/blocks/wfed-setup.sh`, by the agent). It asks y/N for the project, then creates:
    - the pool and the device's two providers, each holding its role's one anchor, with D3's mapping and that role's condition;
    - the two SAs, with no display name, the writer SA with no role;
    - the two bindings: the device's reader ID on the reader SA, its writer ID on the writer SA.

    It records the APIs it enabled in a randomly named file in Cloud Shell's home. After a failure part way it can be pasted again: what exists prints `exists`. Each binding is retried for up to 210 s, since a new service account may take 60 s or more before it can be used, and the block prints its last line, the coordinates, only when both bindings printed `added`; otherwise it prints `setup not complete` and exits 1 (M3a's deviation 23). Paste it again then, unless a policy refused a binding: then W-FED stops, and WF.5's teardown follows.
  - Relay its labelled lines, and copy its last line as soon as it prints. *(2026-11-24, M2 walked: the operator relayed the whole output through the chat, the coordinates line included; it is not recorded (deviation 31).)*
  - The agent runs `pbpaste > wfed/line`, then `coordinates` with `FARCAST_WALK_M3A_LINE="$PWD/wfed/line"`, then `rm wfed/line`, then `mark wfed-setup`. None of these prints the line. *(2026-11-24, M2 walked: the line was taken from the clipboard by its prefix into a 0600 file, read by `coordinates`, and removed (deviation 29).)*
- **WF.3 (operator).**
  - Paste `wfed-viewer.sh`. It grants the reader SA `roles/container.viewer` on the project, for this step only. That it is the smallest role whose IAM grant authorises the three reads is [unverified] (ADR 0023:121's 2026-11-16 note).
  - When it printed `added`, the agent runs `mark wfed-viewer`.
- **WF.4 (agent).** Run `wfed` with `FARCAST_WALK_INSTANCE="$INSTANCE"` and `FARCAST_WALK_M3A_SHAPE=<M3a's simplest passing shape>`. It reads the instance's record and endpoint as farcast does, under `FARCAST_CONFIG_HOME`. Record: *(2026-11-23, ADR 0024's M3a walked: its simplest passing shape is S1, for both roles.)* *(2026-11-24, M2 walked: S1. The walked probe took the review's 201 for a refusal, so WF.4 ran again with a patched probe (deviation 30).)*
  - the reader's exchange and impersonation lines;
  - the impersonated token's three reads' statuses, `GET /version`, the namespace list (the writing commands' preflight read) and a `SelfSubjectReview`, each under the settle rule from `wfed-viewer`;
  - "email matches: yes/no", from the review; *(2026-11-24, M2 walked: printed only by the patched probe: yes.)*
  - the federated token's three statuses: 401 (the endpoint refuses the token) or 403 (authenticated, then refused), or another status.
- **WF.5 (operator, then agent).**
  - Paste `wfed-teardown.sh`. It removes the viewer grant first, then the bindings, then the providers, the pool, the SAs, and the APIs it enabled, each tried once without `--force`. Each line skips an absent object. An API Google will not disable prints `kept enabled` and stays in the block's record, which the block then keeps (`API record: kept`); the operator decides whether to disable it with `--force`, which also disables the services that depend on it, after reading `gcloud services list --enabled --project "$PROJECT"` for dependents. *(2026-11-24, M2 walked: nothing was kept: STS was disabled without `--force`, and the block printed `API record: removed`.)*
  - Once the block printed its deletions, the agent runs `mark wfed-teardown`, then `wfed-gone` with the same `FARCAST_WALK_M3A_SHAPE` as WF.4's (it has no default), and only after `wfed-gone` has exited, `rm -rf wfed`, which removes the device's keys. Record `wfed-gone`'s lines: each role's exchange, both polled until refused in one loop from the mark, so each delta is its own. No positive control exists once everything is deleted, so each refusal is read alone. No impersonation is polled: the teardown deletes the SAs too, so its refusal would say nothing about the federation.
  - Then W-FED's baseline again, as WF.2 took it, and compare.
- **WF.6.** W-FED is torn down when WF.5's counts equal WF.2's: the pools, the service accounts and the members of `roles/container.viewer` back at the baseline, and each API back as it was, or kept on and named with the operator's `--force` decision. Once that decision is made, if `wfed-teardown.sh` printed `API record: kept`, the operator removes the record from Cloud Shell's home: it is the file named on the block's `RECORD=` line, which they read in their own viewer, as M3a's P10 (e) does. W6.5 removes Cloud Shell's walk directory, not that file. W6.3 repeats WP.7's counts, which see W-FED only through the service accounts.

**What it settles:** that GKE's DNS endpoint accepts an impersonated token carrying the scope pair; what username Kubernetes sees, as "email matches"; and how the endpoint answers a direct federated token. *(2026-11-24, M2 walked: all three, on S1: the impersonated token was accepted for `GET /version`, the namespace list and a SelfSubjectReview; Kubernetes sees the reader SA's email; the federated token itself is authenticated, then refused, 403.)*

**What it does not settle:** the reader's RBAC with farcast's own RoleBindings, since the grant here is IAM's `container.viewer`; and the delegation entries of Artifact Registry and Cloud Storage, which are M3b's walk's.

### W-FED's Results

Walked 2026-11-24, during M2's walk, after W5 and before W6.1, at 3fd79c4 under [B], in the same project, on S1. Its approval: G0a's yes, 2026-11-23, with its summary presented, and its full list presented again at G0b, 2026-11-24, before "Yes, spend". The operator allowed the probe's Little Snitch prompts, pasted the three blocks and answered each y; the agent built and ran the probe and read its scrubbed `.out` files. W5.3 (1)'s kube-state read ran during its waits. It was torn down to its baseline. One row per step; statuses, counts and yes/no only, never a token, email or ID (T1).

| Step | Result | Notes |
|---|---|---|
| WF.0 the approval's yes and its date; the probe built; its firewall rules | Approved at G0a, 2026-11-23, its list again at G0b, 2026-11-24; the probe built | Built once, before WP.4, with `go test -tags walk -c` from 3fd79c4 in a clean tree, with no tree entry before or after, into `probe/` (0700), off the walk shell's PATH. A test binary carries no vcs stamp; its tags line reads `-tags=walk`. Firewall: the operator allowed Little Snitch's prompts for the probe as they came (deviation 18). A second, patched probe was built at WF.4 (deviation 30). |
| WF.1 the directory's ACL check; `wfed-init`'s counts; `wfed-blocks` | Two `drwx------` lines, no `+`; `wfed-init` exit 0; `wfed-blocks` exit 0, three blocks | `wfed` made 0700. "devices enrolled: 1 (writer-capable); providers drawn: 2; service accounts drawn: 2; keys made: 4". The blocks' sha256, first 12 hex: `wfed-setup.sh` 9203a42207e7, `wfed-viewer.sh` 92df37d98be0, `wfed-teardown.sh` adb03ac584c9. |
| WF.2 W-FED's baseline; `wfed-setup.sh`'s lines; coordinates; `mark wfed-setup` | Baseline taken; setup complete; "coordinates recorded: yes; the project matches: yes"; `mark wfed-setup` | One paste, the baseline first (deviation 29). Baseline: pools (DELETED excluded) 1; service accounts 2; `roles/container.viewer` members 0; IAM on, IAM Credentials on, STS off, Resource Manager on. `wfed-setup.sh`, on the operator's y: IAM, IAM Credentials and Resource Manager "already enabled", STS enabled; the project number read; the pool, the federated reader and writer providers and the reader and writer SAs created; both bindings added, each at its first try; the coordinates line printed. The whole output reached the agent through the chat; not recorded (deviation 31). The agent took the line from the clipboard by its prefix into a 0600 file; `coordinates` exit 0; the file removed; then the mark. |
| WF.3 the viewer grant; `mark wfed-viewer` | "reader SA viewer grant: added"; `mark wfed-viewer` | On the operator's y. |
| WF.4 the exchange; the three reads with the SA token; email matches; the federated token's three statuses | S1: the exchange and impersonation accepted; with the SA token, `GET /version` 200, the namespace list 200, a SelfSubjectReview 201; email matches: yes; the federated token 403, 403 and 403 | First run, the walked probe, exit 0, stderr empty: the reader's exchange accepted at its first try, `access_token`, lifetime 3599 s, TLS 1.3 yes; the impersonation accepted at its first try, a token for about 60 minutes; `GET /version` 200, first tried 9 s after `wfed-viewer`'s mark and accepted 88 s after it; the namespace list 200 at its first try, 88 s after the mark; the SelfSubjectReview answered 201 Created, `application/json`, which the probe took for a refusal until its 20-minute bound, so "email matches" was not printed (deviation 30); the federated token itself, 403 for each of the three, authenticated, then refused. Second run, the patched probe, on the operator's choice: exit 0, stderr empty, about 22 minutes after the mark, so no line is a settle time; the exchange and the impersonation accepted; 200, 200 and 201, each at its first try; "email matches: yes", the username Kubernetes sees being the reader SA's email; the federated token 403 for each, authenticated, then refused. |
| WF.5 `wfed-teardown.sh`'s lines; `wfed-gone`; the baseline again | Torn down; `wfed-gone`: both refused 0 s after the mark; the baseline equal to WF.2's | `wfed-teardown.sh`, on the operator's y: the viewer grant removed; both bindings removed; both providers and the pool deleted; both SAs deleted; STS disabled, without `--force`; "API record: removed". No Org Policy question: W-FED did not enable it. The agent: `mark wfed-teardown`; `wfed-gone` (S1) exit 0, stderr empty, "no positive control exists after the teardown; each refusal below is read alone": the reader's exchange refused 0 s after the mark, the writer's 0 s after it, each at its first try. `wfed` listed (the blocks, `state.json`, the device's reader and writer keys) and removed with `rm -rf` on its literal path: the device's keys are gone. The baseline again: pools 1; service accounts 2; `roles/container.viewer` members 0; IAM on, IAM Credentials on, STS off, Resource Manager on. |
| WF.6 W-FED's counts against its baseline; any API kept enabled, and the `--force` decision; the API record removed | Torn down: every count and API at WF.2's | No API was kept, so there was no `--force` decision. The block removed its own API record, so nothing is left in Cloud Shell's home. |

## Deviations found while walking (2026-11-24)

Numbered on from *Its deviations from the M2 design* (1 to 15), at the top of this runbook.

16. **Cloud Shell's steps went as clipboard blocks, not typed lines.** The agent wrote each Cloud Shell step as a block with the values filled in and put it on the clipboard, and the operator pasted it. WP.6's helpers went as one block, pasted twice because the first copy was lost before pasting. WP.7's and WP.8's reads ran in one here-document (`bash -s`), each `gcloud` call with `--quiet` and stdin from `/dev/null`, and the Org Policy API's turn-on behind a y/N read from `/dev/tty`, as M3a's blocks do. That block added, for information: the members of `roles/container.viewer` (W-FED's baseline), the compute, gkehub and anthos APIs' states, the Data Access configuration above the project through `get-ancestors`, and the installer key's expiry date. `reader init`'s script went to the clipboard from the agent, its sha256 equal to the one farcast printed, where W4.3 gives the `pbcopy` to the operator. W4.15's steps 1 and 2 went as one paste, and W4.17's later checks as one (deviation 24). W5.1, W5.2 and W5.3's steps 1, 2 and 4 to 7 went as one block, tested offline first against a synthetic audit file with `gcloud` and `kubectl` stubbed. It classes each principal in `jq`, so no email reached the screen or the chat: the installer by its email; `farcast-reader-` accounts; farcast-system's ServiceAccounts by name; other ServiceAccounts by namespace; `system:` principals as GKE's; Google service agents; other service accounts; a user account. It classes the agent as exactly `farcast`, farcast-prefixed, `kubectl` or other. The Admin Activity log's name in it was typed by the agent from Google's documented form, not by the operator (W5.1).
17. **The walk terminal was opened by the agent,** in the desktop app's Terminal panel, from the walk directory, with `env -i`, and with the project and the instance's name read from the walk directory's 0600 files rather than typed. The operator ran `source ./walk.zsh` and `command -v` there, and the agent read from the panel that `command -v` printed nothing. Closing the tab, whose shell sat in the removed walk directory, was left to the operator after W6.6.
18. **Little Snitch's prompts were allowed as they came** (WP.5, WF.0): the carrier's at W4.4 and the probe's at WF.4, by the operator. A held first dial shows as an EOF, as it did twice at W4.8 (deviation 21).
19. **The Org Policy API was turned on at WP.7, and off at W6.4.** WP.7's managed check found it off; the operator answered y, as G0a allowed, and it was turned on. Its enable printed an operation name that carries the project's number, which is not recorded. W6.3 read it on; W6.4 disabled it on the operator's y, exit 0, and read it back off, so the APIs were then as at WP.7.
20. **The fleet list was not read** (WP.7, ADR 0019's precondition). The fleet memberships list FAILED, its error read as PERMISSION_DENIED, with the GKE Hub and anthos APIs off. The finding was put to the operator: the list could not be read with the GKE Hub API off [inf]; with that API and anthos off and no cluster in the project, there is no fleet membership and no GKE Enterprise enablement [inf]. The operator's answer, 2026-11-24, "Accept it": the precondition was taken as held from the API states, without the list, and the GKE Hub API was not turned on.
21. **W4.8's `storage deploy --grant-bucket` ran three times.** The agent found the first two later, in the walk terminal. The first ended while reading the key pin, the token endpoint not reached (an EOF), with nothing deployed. The second ended on the datasphered image's lookup in the instance's registry, with an EOF. Both are Little Snitch holding a first dial (WP.5's note). The third is the run recorded. It created the keyring and the bucket itself, so the first two created neither [inf].
22. **Each replaced keyholder replica was unsealed after one read** (W4.10, W4.15 step 6), not after its restart count held for two. The agent unsealed on the first `keyholder` read that showed the replaced replica STARTED true with 0 restarts, since an unseal that reaches no listener fails harmlessly and is repeated. Every unseal exited 0. At W4.15, step 5's `bucketroles` was read after both of step 6's unseals.
23. **W4.12's "Build it?" was answered y, not n.** The operator stopped the wait with Ctrl-C after "Building … inside" ("wait for the build: context canceled"). So one build Job, `build-$INSTANCE-alpha` in `farcast-system`, with 1 vCPU and 2 GiB, a 30-minute deadline and backoffLimit 0, removed an hour after it ends, was applied and ran without its wait: at most about USD 0.03. Its name differs from `run`'s build Jobs (`build-sdk-demo-alpha` and `-beta`), so it did not collide with W4.13 (planck/build's JobName) [read]. It failed in about 3 minutes, Error, exit 1, 0 of 1 completions. Its log's last 30 lines hold "error checking push permissions" once and "DENIED" once: kaniko's check before building, refused while the push grant did not yet exist or had not settled. It built and pushed nothing. Its Pod's create is in W5.3 (7)'s count.
24. **W4.17's wait was one self-timed paste.** After two reads by hand, soon after W4.13's run and about 40 minutes after it [inf], one paste checked every 10 minutes by itself: 47 minutes after alpha was created, 0 resizes; 58, 0; 68, 2. The first resize came 60 minutes after W4.13's run. W4.15 ran inside the wait.
25. **W5.1 was read twice, then diagnosed and probed.** The first read returned 5000 entries, equal to the limit, so it was truncated: `gcloud` returns the newest first, and those spanned 95 minutes. It held no Job create and few of farcast's applies. The second read was narrowed rather than raised: it left out `system:` principals other than farcast-system's ServiceAccounts, and returned 209 entries. In it the installer's entries for the cluster were ConfigMaps and Secrets only, and no Job create showed. A read-only diagnostic followed. D1, the installer in Admin Activity over every resource type for the last day: 40 entries. On `audited_resource`: ArtifactRegistry.CreateRepository 11, ArtifactRegistry.SetIamPolicy 1 and serviceAccounts.actAs 1. On `gcs_bucket`: buckets.create 3 and storage.setIamPermissions 2. On `gke_cluster`: ClusterManager.CreateCluster 1. On `k8s_cluster`: configmaps.create 1, patch 10 and update 1, and secrets.patch 9, so for the cluster configmaps and secrets only. D2, the workload kinds written on the cluster by any principal: 680 entries, almost all GKE's own. In FarCast's namespaces only the kernel's deployments.patch 2 (the resizes), the Job controllers' jobs.patch 4 and jobs.delete 4, each namespace's default ServiceAccount's create, and the operator's serviceaccounts.create and delete at W4.15: no entry by the installer, so none of farcast's own creates or patches of FarCast's Namespaces, Deployments, StatefulSet, Services, NetworkPolicies, ServiceAccounts, Roles, RoleBindings or Jobs. D3, the second read's "other" principals: GKE's own [inf]. The finding was put to the operator, who chose "Run the probe" (2026-11-24): two throwaway ServiceAccounts in `farcast-system`, applied server-side through `kubectl proxy` in Cloud Shell, one with a YAML body and one with a JSON body, both as `application/apply-patch+yaml`. Both answered HTTP 201. Admin Activity, read each minute for 6 minutes, held the JSON one's patch, with a body, from minute 1, and the YAML one's never. Both were deleted. So GKE's Admin Activity drops a server-side apply whose body is YAML and keeps the same apply sent as JSON (GKE 1.36.4; why is Google's, not read). farcast sends each apply as its document's own YAML (`kube/apply.go`) [read]. W5.3 (7) was then read again, for the controllers' Pod creates. `release`'s printed "audit log of this instance's API writes" (W6.1) overstates how the writes are kept, and its Usage text more so (`release.go`); both were changed after the walk (below).
26. **W5.2 read farcast's agent as "farcast,gzip(gfe)", not `farcast`.** The first read counted 9 installer entries with another agent, all farcast-prefixed: a finding against W5.1's "exactly `farcast`". In the second read the agent of every farcast-prefixed entry, 21 of them, was "farcast,gzip(gfe)": Google's front end appends ",gzip(gfe)" to farcast's exact "farcast" [inf]. Read with farcast-prefixed as farcast's, both of W5.2's counts were 0.
27. **W5.3 (3) on [B].** `farcast logs` is a reader read, and was refused: exit 1, no lines, "the reader key is not yet uploaded", as W4.14's reads were. ADR 0019's "logs still return lines" stands on `kubectl logs` in Cloud Shell instead: alpha's lines read at W4.13, W4.15 and W3.4.
28. **W5.3 (1)'s kube-state series were read by the agent,** in the desktop app's built-in browser, read-only, during W-FED's waits, after the operator signed in again on the console's password challenge. W5.3 gives every read to the operator. The agent read Metrics Explorer's PromQL `kube_pod_container_status_ready{namespace="farcast-system",container="datasphered"}` over the last hour: a series for `datasphered-0` and one for `datasphered-1`, each named by the Pod's uid and name. The editor's Duplicate button was clicked once by mistake, which made an unsaved second query in the page. Nothing was saved.
29. **W-FED's baseline and `wfed-setup.sh` went as one paste,** the baseline first, as a `bash -s` block, then the setup. The agent took the coordinates line from the clipboard by its prefix into a 0600 file, not with `pbpaste > wfed/line`; `coordinates` read it, and the file was removed before `mark wfed-setup`.
30. **W-FED's probe refused a 201, and was patched** (WF.4). The walked probe accepted only 200 as success (`walkm3a_test.go`, `stepWFED`: `code == http.StatusOK`) [read]. The SelfSubjectReview's create answered 201 Created, the API's success for a create, so the probe retried to its 20-minute bound, printed "still refused at the bound", and never printed "email matches". A probe bug; the review itself was answered. The operator chose "Patch and re-run" (2026-11-24). The agent built a second probe from the walked commit through `go test -overlay`, the repository untouched and no tree entry made: `stepWFED` accepts 200 or 201, and its accepted line names the status; nothing else differs. It ran about 22 minutes after `wfed-viewer`'s mark, so none of its lines is a settle time. After the walk the same two lines were written into `farsight/cli/internal/cli/walkm3a_test.go`, byte-equal to the overlay: `gofmt` is clean, `go vet` with the integration, walk and realapi tags exits 0, and the walk-tagged tests pass under the network guard.
31. **Raw output reached the agent through the chat,** more than once, against T4, under which the agent never sees Cloud Shell's raw output and the operator relays only what a step records. The operator relayed whole outputs, not only what a step records: WP.7's, whose Org Policy API enable printed an operation name that carries the project's number; W4.3's stop line, which names the project; W4.8's `storage deploy --grant-bucket` output from the walk terminal, which names the project, the bucket, the registry path and the walk directory; and `wfed-setup.sh`'s whole output, the coordinates line included, which names the project and its number. None of it is recorded.
32. **The instance's hours came from the agent's step files.** W4.1's start to W6.1's end was taken from the modification times of the agent's step files: about 197 minutes, about 3.3 hours. By G0b's floor model [inf]: the instance about USD 0.35; five builds, four by the runs and one extra at W4.12, at most about USD 0.14; the per-Pod floor about USD 0.2; the cluster fee up to about USD 0.33 if the free tier does not waive it; the rest cents: about USD 0.6 to 1.0 in all, inside G0b's under USD 5. The bill itself was not read.
33. **W6.2's key comparison was computed in the block, and the Downloads check went by the key's id.** W6.2's note has the key file's `private_key_id` and the key's id read on screen. Instead the block compared them, and printed only whether the Mac key file's id was among the installer's user-managed keys: yes, with no id shown. After the operator deleted the key file on the Mac, the agent checked it gone, and searched the Downloads folder for a file holding the key's id, a count only: 0. None was in the walk's config home either.
34. **A question during the adaptation's wait.** The operator asked whether a `gcloud auth login` into another account, for other work, would compromise the walk. The answer: on the Mac it would not, in another configuration and never as Application Default Credentials; it was not to be done in the walk's Cloud Shell; and the account is checked by eye before each paste.

**Follow-ups, made after the walk.** On 2026-11-24, after these records were written, the texts the walk answered were changed, each with the tests that pin it. `release`'s printed "audit log of this instance's API writes" (W6.1), and its Usage text, which said the audit log keeps "every create, update and delete" on the cluster's API with "the full spec of every workload" (`release.go`), overstated how the writes are kept (deviation 25): both now name the audit log of writes to the cluster's API, with every Pod's spec, which the controllers' Pod creates carry, and the Usage text also each Service-backed Pod's address and readiness, which the Endpoints updates carry. `install`'s printed "that it is honoured is unwalked" (`install.go`, pinned by `install_test.go`) and `logs`' Usage, "which the next walk checks" (`logs.go`, pinned by `logs_test.go`), were answered by W5.3 (1) and (2), the logging configuration read back `SYSTEM_COMPONENTS` only and the provider holding no container log entry from `farcast-system` or `sdk-demo`; both now say a walk on 2026-11-24 found it honoured, still as the provider's read-back. Comments that said the same now say what the walk found: that the logging configuration is honoured on Autopilot (`planck/types.go`'s `SystemLogsOnly`, `config/instance.go`'s `CloudLogging`, `install.go`'s `CloudLogging` and the comment above its printed line, and `release.go`'s `WorkloadLogs`); that under Autopilot the kernel's and FatLine's Deployments, re-applied unchanged, moved no spec path or generation and made no ReplicaSet (`cluster/cluster.go`; W3.2 and W3.3); and that the email in the identity GKE derives from a cluster token was shown for a token impersonated from a federated one (W-FED), and for farcast's own reader key is still inferred (`kube/client.go`).
