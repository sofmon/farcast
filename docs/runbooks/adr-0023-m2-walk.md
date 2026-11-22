# ADR 0023 M2 — the billable walk: one fresh instance, written by M2 alone

Since [ADR 0023](../adr/0023-one-download-farcast.md) M2.7, `farcast` starts no `kubectl`, auth plugin or `gcloud`. Every cluster call is in-process. The read commands, and the plans under `--plan` and `--confirm`, read as the instance's reader. Every write, and an interactive or `--yes` run's reads, run as the stored installer account, and each apply is a forced server-side apply named `farcast`. Since M2.8 the bucket grant and the push grant name the ServiceAccount by its uid. None of this is walked. The [probe walk](adr-0023-m2-probe-walk.md) of 2026-11-16 settled only the writer's scope pair. This walk installs one fresh instance with the M2 release farcast, from a shell with no `kubectl`, plugin or `gcloud` on `PATH`. It walks the M2 design's revised §10.7 ([§37](../design/adr-0023-m2-design.md#37-decided-before-m29as-build-2026-11-20), as [§39](../design/adr-0023-m2-design.md#39-decided-before-m29bs-build-2026-11-22) decides it), and releases everything at its end.

**Status.** *Written 2026-11-22 (ADR 0023 M2.9b), against the code at the commit it lands in. Not run.* It needs the operator's own approval in the session that walks it: the choices at G0a, and the yes to spend at G0b. The approval that had ADR 0023 M2.9b write this runbook is not approval to walk it. No earlier walk's approval carries over. *(2026-11-22, [ADR 0024](../adr/0024-paste-the-certificate.md): by the operator's decisions of that day, this walk runs after ADR 0024's M3a, on its own, before M3b, in a project in the operator's own organization, under [B]. A22-2 is answered (G0a). An optional W-FED step, with its own approval, is to be appended to this runbook with M3a's build. Neither M3a nor this walk has run.)*

**It is billable.** One Autopilot instance, installed with `--cost-limit 100` (USD a month), for about 4 to 4.5 hours. G0b asks for under USD 5 [inf]. By the repository's floor model the walk costs about USD 0.7 to 1.5 (G0b has the arithmetic). The walk also creates IAM objects, which cost nothing, and W6 removes them.

**What is left to choose at G0a:** A22-2's branch first ([U1], [U2] or [B]); the project; whether the Org Policy API may be turned on; and the optional steps: (f), the `git-credential` step, ADR 0019's checklist as W5.3, and W4.17's read of field managers. *(2026-11-22, ADR 0024: the branch is [B], by the operator's decision. [U1] is withdrawn, and [U2] is deferred with a project with no organization. G0a also approves the installer's Google-made key as ADR 0024's exception, chooses the existing key or one made at WP.8, and offers W-FED if M3a passed.)*

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
    - [B]'s build, answered "no";
    - [U1]'s org-policy change, and Little Snitch.
  - The agent never types into Cloud Shell and never sees its raw output. The operator relays only what a step records: counts, kinds, states and booleans, and the GKE version, rounded minutes, requests, manager and operation pairs, spec paths, audit levels and methods.
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
4. **The optional steps:** *(2026-11-22, ADR 0024: and W-FED, offered only if ADR 0024's M3a passed in the organization project, with its own approval. Its steps are to be appended to this runbook with M3a's build.)*
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
  This is the walk terminal. Every step that says "in the walk terminal" runs here. `command -v` prints nothing.
- **Why:** this is §37's "a shell with no kubectl, plugin or gcloud on `PATH`".

**WP.5, the outbound firewall (operator).** Little Snitch on the walk Mac, rules for `<the walk directory>/bin/farcast`, each for its destination only:
- Google's APIs, as each prompt asks;
- Google's token endpoint and the cluster's DNS endpoint, which [the probe walk's P0.5](adr-0023-m2-probe-walk.md#p0-setup-on-the-dev-mac-no-cloud) names;
- the registry's region host, and the base image's registry, which [the M1 walk's W0.3](adr-0023-m1-walk.md#w0-setup-on-the-dev-mac-no-cloud) names;
- the builder's and the fetcher's upstream registries, which [`phase-5-session-a.md`'s S3](phase-5-session-a.md#bring-up) names (W4.11);
- during W4.4, the carrier's address on FatLine's port, as P0.5 names it: `connect --confirm` dials it before it exits, so allow it when Little Snitch asks, for that destination only.

A held binary shows as an EOF or a timeout, not as a refusal (P0.5's note). No walk probe is built. If a 401 or a 403 needs a diagnosis, build it once, as the probe walk's P0.4 does.

**WP.6, Cloud Shell (operator).** Signed in as an Owner of the project, the FarCast account checked by eye. Typed, never recorded:
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
  If the second asks to turn the Org Policy API on, answer as G0a decided, and record it.
- **The key expiry policy:** `iam.serviceAccountKeyExpiryHours`' effective value on the project, enforced or not, and its hours. It sets W4.3's `--days`. The spelling is the legacy check's form, [unverified] for this constraint.
- **ADR 0019's precondition** ([its Verification](../adr/0019-what-the-cluster-tells-its-provider.md#verification)):
  - no GKE Enterprise enablement and no fleet membership. The spelling is the operator's, [unverified]. One form is `count gcloud container fleet memberships list`;
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
- **The teardown, W6.** It runs `farcast release "$INSTANCE" --delete-data --yes`. That deletes for good, with the instance, the bucket's objects: the walk's secret, `walk/a.bin` and anything the applications wrote. Soft delete is off on the bucket by design. W6 cannot remove what the project keeps of the walk: Admin Activity entries for 400 days, with every workload's spec and the repository and commit of each build; logs for 30 days by default; metrics for 24 months (ADR 0019; `release` prints the dates). *(2026-11-22, ADR 0024: on [B], W6.2 also deletes the installer's key in Google and on the Mac.)*
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
- **Operator,** in the walk terminal: `pbcopy < reader-init.sh`, then paste it into Cloud Shell. Keep what it prints on the screen; do not copy it anywhere.
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
- **[B], operator,** in the walk terminal: `farcast storage deploy "$INSTANCE" --grant-bucket`. It asks the cost question, then the grant question, which names "the bucket this deploy creates" and the account "by the uid it has once this deploy creates it". Answer yes to both. This is A33-39's terminal path. **Record** whether it printed any grant commands: none expected, since it applies the grant.
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
  **Expect** `present`. Every `storage deploy` mints a new keyholder leaf, so the StatefulSet rolls. It replaces `datasphered-1` first and waits there, because the new replica comes up sealed and is not Ready until unsealed (`datasphere/deploy/deploy.go`'s `updateStrategy` note) [read]. In Cloud Shell, `keyholder` until `datasphered-1` is STARTED true with a steady restart count. Then `farcast storage unseal "$INSTANCE" > w4-10u.out 2> w4-10u.err; echo "exit $?"`. Then `keyholder` until `datasphered-0` has been replaced: STARTED true, READY false, steady restarts. Then the unseal again, into `w4-10u2.out` and `w4-10u2.err`. `keyholder` then shows both READY true.
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
  The push grant's notice, with its add, prints before "Build it?". Answer no: nothing is applied or billed. Run the add in Cloud Shell.
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
   - **Expect:** it restarts on its start-up bucket check (`serve.go`'s `provider.Validate`) [read]. Its account has the same namespace and name and another uid, which the policy does not hold. That the refusal's text holds "403" is [inf]; the restart count does not depend on it.
3. **[U], agent:** `farcast -o json storage deploy "$INSTANCE" --plan > w4-15.plan.json 2> w4-15.plan.err; echo "exit $?"; grant w4-15.plan.json bucket`. **Expect** `state:missing`, `shared:missing`. **[B], operator, Cloud Shell:** `bucketroles`. **Expect** `uid` 0 and `other_uid` 1 per role.
4. **Operator,** in the walk terminal, on both branches: `farcast storage deploy "$INSTANCE" --grant-bucket`, yes to both questions. On [U] this walks the terminal consent.
5. **Cloud Shell:** `keyholder` until `datasphered-1` is STARTED true with a steady restart count: the deploy replaces it first, with a new leaf, and the rollout waits there until it is unsealed. Then `bucketroles`. **Expect** per role `uid` 1, `other_uid` 1 (the stale uid, which farcast leaves, A33-8 OQ-E) and `shared` 0.
6. **Agent:** `farcast storage unseal "$INSTANCE" > w4-15u.out 2> w4-15u.err; echo "exit $?"`. Then the operator runs `keyholder` until `datasphered-0` is replaced (STARTED true, READY false), and the agent runs the unseal again into `w4-15u2.out` and `w4-15u2.err`. Then alpha's `present` again, read as in W4.13.
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

**W4.17, one adaptation (operator, Cloud Shell).** Every 10 minutes, until the count is 1 or more, and at most 90 minutes after W4.13's run:
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
  The log's name is a filter on `logName`, which the operator types from Google's pages. If the count equals the limit, raise the limit and read again.
- **The grouping,** on screen only:
  ```bash
  jq -r '.[] | [.protoPayload.authenticationInfo.principalEmail, (if .protoPayload.requestMetadata.callerSuppliedUserAgent == "farcast" then "farcast" else "other" end), (.protoPayload.methodName | split(".") | .[-2:] | join(".")), (if .protoPayload.request then "body" else "no-body" end)] | @tsv' audit.json | sort | uniq -c
  ```
  The operator classes each principal: the installer, the reader, the kernel's ServiceAccount, the operator's own account (W4.15's hand steps), a GKE system principal, or other.
- **Record:** the counts per class, agent class, method and body. Never an email.
- **Expect:**
  - farcast's applies as patches, by the installer, with the agent exactly `farcast` (`kube.UserAgent`) [read];
  - the storage pin's create and replace;
  - `git-credential rm`'s delete, if W4.16 ran;
  - Secret and ConfigMap entries with no body;
  - the kernel's writes under its own ServiceAccount;
  - no reader reads, which are Data Access, off unless WP.7 found it on [inf]. Whether the reader's five reviews show here is [unverified].
- **Why:** §37, and §10.7's W5. The field names are [unverified].

**W5.2, the cross-check.** Entries with the agent `farcast` by a principal that is neither the installer nor the reader: 0. Installer entries with another agent: 0.

**W5.3, ADR 0019's checklist.** Only if G0a chose it. These are [its Verification](../adr/0019-what-the-cluster-tells-its-provider.md#verification)'s steps 1 to 8, the precondition being WP.7's:
1. the logging and monitoring read-back;
2. `k8s_container` counts in `farcast-system` and the application namespaces since install;
3. `farcast logs` (W4.13);
4. `PodMonitoring`;
5. a ConfigMap entry with no body;
6. `pods/status` entries;
7. a build Job's create entry, for presence only, since its arguments name the repository;
8. after a seal and an unseal by the agent, `farcast storage seal "$INSTANCE" > w5-3s.out 2> w5-3s.err; echo "exit $?"` and then `farcast storage unseal "$INSTANCE" > w5-3u.out 2> w5-3u.err; echo "exit $?"`, the Endpoints and EndpointSlice entries.

Record each as ADR 0019 asks, in counts and levels.

---

## W6. Release, and the cloud at zero

1. **Agent:** `farcast release "$INSTANCE" --delete-data --yes > w6-1.out 2> w6-1.err; echo "exit $?"`.
   - **Expect:** exit 0 within 15 minutes. If a wait runs out, run it again: it waits for the same delete.
   - It ends with a reader line naming two Cloud Shell commands, which stays in `w6-1.out`. `--delete-data` is needed: the bucket holds the secret and `walk/a.bin`.
2. **Operator:** read the two reader commands in the walk terminal (`cat w6-1.out`), and run them in Cloud Shell, in order. Then the count of `farcast-reader-` accounts equals the baseline's. *(2026-11-22, ADR 0024: on [B], the operator then deletes, in Cloud Shell, the installer's key G0a approved: `gcloud iam service-accounts keys delete <the walk's key's id> --iam-account "<the installer's email>" --project "$PROJECT"`. The key to delete is the one whose id equals the key file's `private_key_id` field, both read on screen and never recorded. The operator deletes the key file on the Mac, and checks that no copy is left in the download folder or in Cloud Shell. Then WP.8's `count` line again: WP.8's count less one, which is 0 when WP.8 found 1.)*
   - On [B] they answer "not found", which is harmless (the probe walk's P7.3 note), unless W4.3 recorded "managed check silenced". Then they remove a real account.
3. **Operator:** every WP.7 count again, against the cloud, not against `release`'s report. Each equals the baseline. A difference is a finding, removed by hand only with the operator's yes.
4. **Operator:** turn the Org Policy API off, if the walk turned it on, as [the probe walk's P7.6](adr-0023-m2-probe-walk.md#p7-teardown) does. [U1]: the override restored or kept, as G0a decided.
5. **Operator:** delete Cloud Shell's walk directory, with its kubeconfig and `audit.json`.
6. **Agent:** `farcast -o json instances > w6-6.json 2> w6-6.err; echo "exit $?"; grep -o '"instances":\[\]' w6-6.json` prints `"instances":[]`: no instance is recorded. Then delete the walk directory: the release, the config home with the installer key's copy, the CA keys, the keyring and the reader's key, the plans and the outputs.
7. **Operator:** revoke the Git token at the Git host, if W4.16 ran.
8. **[U2]:** the fresh project kept or shut down, as G0a decided. This is the operator's. *(2026-11-22, ADR 0024: and under [B], if G0a chose a fresh project.)*

---

## Results

Not run. When it runs, one table, `Step | Result | Notes`, as the M1 and probe walks have.
- **Its opening sentence:** the date walked, the commit, G0a's and G0b's dates, the branch and the choices made there, the instance's hours, and its USD by the floor model.
- **A row may hold:** exits, kinds, counts, states (`present`, `missing`, `applied`) and booleans; minutes, rounded, from `time` or by the watch; the four manifests' first 12 hex and the sha256 of `SHA256SUMS`; the commit; the GKE version; requests; manager names; spec paths; principal classes.
- **Never** what T1 bars.

| Step | Result | Notes |
|---|---|---|
| WP.1 commit, `./check.sh` | Not run | |
| WP.3 release: `OK` count, tags, revision, `vcs.modified` | Not run | |
| WP.4 the walk shell: nothing resolved; four components, first 12 hex | Not run | |
| WP.7 baseline counts | Not run | |
| WP.7 the installer's roles; the APIs | Not run | |
| WP.7 key-upload checks; key expiry | Not run | |
| WP.7 ADR 0019's precondition; Data Access configuration | Not run | |
| WP.8 the branch's preparation | Not run | *(2026-11-22, ADR 0024: on [B], also the installer's user-managed key count, expected 1.)* |
| G0a choices; G0b yes | Not run | |
| W4.1 install: exit, minutes, endpoint, registry | Not run | |
| W4.2 `world` and `instances` before a reader | Not run | |
| W4.3 `reader init`, the paste, `reader record` | Not run | |
| W4.4 `connect`: plan, confirm, status, carrier | Not run | |
| W4.5 `reader grant`: plan, minutes, IAM line, reviews; [B] refusals | Not run | |
| W4.6 Kubernetes version; [U] `world` as the reader | Not run | |
| W4.7 `kernel deploy --adapt`; `farcast-builder` exists | Not run | |
| W4.7 [B] the plan's refusal | Not run | |
| W4.8 (a) `--grant-bucket`: state, per-role counts, IAM's lag, unseal | Not run | |
| W4.8 [B] the plan's refusal | Not run | |
| W4.9 (a) `storage cp` both ways | Not run | |
| W4.10 (c) the grant read back | Not run | |
| W4.11 `toolchain`: refused, then mirrored | Not run | |
| W4.12 (d) the push grant: states, add, counts | Not run | |
| W4.12 [B] the plan's refusal | Not run | |
| W4.13 `run`: builds, applications, D's push state, `present` | Not run | |
| W4.13 [B] `--confirm` F's refusal | Not run | |
| W4.14 `world`, `ps`, `costs` after the run | Not run | |
| W4.15 (f) replaced account: restarts, states, counts, `present` | Not run | |
| W4.16 `git-credential` set, private run, rm | Not run | |
| W4.17 one adaptation: minutes, requests; field managers | Not run | |
| W3.1 `--adapt=false`: args, generation, ReplicaSet, managers | Not run | |
| W3.2 unchanged `kernel deploy` | Not run | |
| W3.3 unchanged `redeploy` | Not run | |
| W3.4 second `run`: resets, requests, `present` | Not run | |
| W5.1 Admin Activity, by class, agent, method and body | Not run | |
| W5.2 the cross-check | Not run | |
| W5.3 ADR 0019's checklist | Not run | |
| W6.1 `release` | Not run | |
| W6.2 the reader lines; reader accounts at the baseline | Not run | *(2026-11-22, ADR 0024: on [B], also the installer's key deleted, and its count after, expected WP.8's less one: 0 when WP.8 found 1.)* |
| W6.3 the cloud at the baseline | Not run | |
| W6.4 to W6.8 the Org Policy API, Cloud Shell, the walk directory, the token, the project | Not run | |

Afterwards each record the walk bears on gets a dated note, and walked text stays as walked. Among them: ADR 0023's status line and its M2 row; [phase 1's step 7b](phase-1-validation.md#7b-the-instances-reader-identity--not-yet-walked), whose procedure W4.3 and W4.5 walk on [U]; ADR 0019's Verification, if W5.3 ran; the records that defer to "the next walk", which the M2 design's A39-7 lists; and the twelve "unverified until the M2 walk" sites in code, which change with these results.

---

## What this walk settles, and what it does not

Each item holds only if its step passes. A failure is recorded as the answer the other way.

**It settles:**
- whether Autopilot's mutations converge under farcast's forced apply: W3.2's and W3.3's unchanged re-applies move no generation and make no ReplicaSet, or the record names the spec paths that moved. This answers §14's risk 3, as §37 restated it;
- that farcast's forced apply takes effect under Autopilot's admission (W3.1), not field by field;
- the audit's caller identity and user agent for M2's writes, and the levels of the Secret and ConfigMap entries (W5.1, W5.2);
- A33-4 (f) and OQ-F:
  - Cloud Storage accepts a uid member, and the keyholder validates and serves under it alone (W4.8, W4.13);
  - `getIamPolicy` returns it byte-equal to farcast's exact match (W4.10);
  - Artifact Registry honours it for a push (W4.12, W4.13) and, on [U], returns it byte-equal;
  - a replaced ServiceAccount reads `missing`, is refused until granted again, and is granted again (W4.15);
- R-R10: the installer's conditioned `roles/storage.admin` may read and write the bucket's policy (W4.8). As a by-product, the installer's roles allow the plans' Google reads (A33-1);
- A33-20: `kernel deploy` creates `farcast-builder` before any build (W4.7);
- the cluster's version (W4.6), and `run`'s resets live (W3.4), if an adaptation happened by W4.17's limit;
- [U] only:
  - the reader end to end with farcast's scope pair, A22-7's open reader evidence (W4.3, W4.5, W4.6, W4.14);
  - three of the six reader plans with their `--confirm`: `kernel deploy`'s, `storage deploy`'s with `--grant-bucket`, and `run`'s deploy plan;
  - `build`'s plan, printed and not confirmed;
  - `--grant-bucket`'s terminal consent (W4.15);
- [B] only: the reader plans' `credential_missing` refusals live, with nothing written, and `--grant-bucket`'s terminal path where no reader can exist (W4.8, W4.15);
- both: `connect`'s and `redeploy`'s plan and `--confirm`; with W4.16, `git-credential set` and `rm`, and a private repository fetched and built through them.

**It does not settle:**
- Cloud Storage's answer to a policy write at a stale etag (A33-13, A35-6). No step writes one, and the old optional (g) is not carried;
- separation by uid across two clusters, which was (e) (the design's A39-24). W4.15's same-name refusal on one cluster stands for it [inf]. A compromised cluster in the same pool can present any uid, so one project per instance stays the full separation;
- W4 (b), the swap of a shared grant on a live keyholder. It is pinned against fixtures only (`TestBucketGrantRemovesTheSharedBinding`);
- the kernel's `/scale` write under Autopilot (A31-12): no step reaches the cost limit. W2's `technocore` half, beyond W4.17's optional read;
- the real-API suite's twelve tests (the design's §38, *What is still not run*), A38-17's preconditions included;
- R0, the second host;
- `storage key pin` and `storage key rotate` with a keyholder, and their plans; `kernel meter` and `kernel confirm`; `reader grant`'s and `build`'s `--confirm`;
- writes through the keyholder under the uid. Only its start-up check and its reads are observed; that `objectAdmin` covers its writes is [inf];
- on [B], the reader end to end and every reader plan under `--confirm`. On [U], the blocked organization's refusals beyond the paste's stop, walked 2026-11-16;
- A22-3, the init script's silenced managed check. It is not fixed, and the walk can meet it;
- risk 5 (removed applications keep billing) and risk 7 (two runs racing on the egress policy);
- ADR 0019's checklist, unless W5.3 is chosen;
- any instance an older farcast wrote: none exists, and no migration remains (M2.9a);
- M3a and M3b, M4, M5, and every FarSight client claim.
