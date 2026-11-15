# Phase 7 — the Connected view: the no-cost rehearsal, then the first live read

The macOS FarCast app reads the operator's instances by running the operator's own `farcast` ([ADR 0021](../adr/0021-farsight-native-client.md) decision 9, amended 2026-11-12). This runbook walks it twice: first from Finder against an instance that lives on this Mac, then against a live one. It is the ADR's "Walked before it is relied on", and the rehearsal step of its Verification 5.

**Part R costs nothing and touches no cloud.** Everything in it listens on 127.0.0.1: a local Kubernetes API server and token endpoint, a real FatLine and Shrike, and two keyholder replicas (`farsight/cli/README.md`, "The no-cost rehearsal"). *(2026-11-15: until [ADR 0023](../adr/0023-one-download-farcast.md) M2.4 the cluster was three fake tools, `kubectl`, `gke-gcloud-auth-plugin` and `gcloud`.)*

**Part L reads a live instance.** A read adds no standing cost, but it needs an instance up, and an instance up is billable. Ask before standing one up (L0).

**Gate G1 (2026-11-12): Q1 and Q2 accepted.** The app's child `PATH` ends with the system's own directories, and its `CLOUDSDK_CONFIG` is the gcloud directory confirmed in Settings. Without the second, a `farcast` started from Finder would read the operator's real `~/.config/gcloud`. So R4 to R9 are not blocked. *(2026-11-15: since ADR 0023 M2.4 the child's `PATH` is the system's own directories alone, and it has no `CLOUDSDK_CONFIG`: `farcast` runs no tool for the app's three commands, so neither question arises.)*

**Commit walked:** `5bb19ac` (2026-11-12). **Status:** Part R walked 2026-11-12. R2, R5 and R8.3–R8.5 were not reported, and Part L is not walked. Eight findings, listed under Results.

*(2026-11-15: R1, R3–R9 and Part L were rewritten for ADR 0023 M2.4. The rehearsal's cluster is now a local API server, and every read runs as the instance's reader. **The rewritten Part R is not yet walked:** the Results below are the 2026-11-12 walk of the old rig. Part L is still not walked.)*

Throughout:
- Run every command from the checkout root, and keep that checkout outside `~/Documents`, `~/Desktop` and `~/Downloads`, which TCC prompts for.
- Never paste raw output of a live read anywhere. [The scrub rule](#the-scrub-rule) says what may be recorded.
- `DIR` below is the rehearsal's state directory, which R1 prints. Set it once in the terminal you drive the walk from: `DIR=<the directory R1 printed>`.

---

## Part R: the rehearsal, from Finder

### R0. Build from one clean commit

```bash
test -z "$(git status --porcelain)" || echo "commit first: the check compares HEAD, not the working tree"
./check.sh
COMMIT=$(git rev-parse HEAD | cut -c1-7)
go build -o ./bin/farcast ./farsight/cli/cmd/farcast
go build -o ./bin/farcast-rehearsal ./farsight/cli/cmd/farcast-rehearsal
(cd farsight/client/apple && xcodebuild -project FarSight.xcodeproj -scheme FarCast \
  -destination 'platform=macOS' -derivedDataPath .build/DerivedData build FARCAST_COMMIT="$COMMIT")
./bin/farcast version          # commit: $COMMIT
plutil -extract FarCastCommit raw farsight/client/apple/.build/DerivedData/Build/Products/Debug/FarCast.app/Contents/Info.plist   # $COMMIT
```

- `./check.sh` passes at this commit. Record its summary line.
- `./bin/farcast version` and the `plutil` line both name `$COMMIT`, and R1's banner names it for the harness. `./bin/` is git-ignored, so the builds leave the tree clean.

### R1. Start the harness

```bash
./bin/farcast-rehearsal --farcast "$PWD/bin/farcast"
```

- Its banner reads `FarCast rehearsal — commit $COMMIT`. A line starting `warning:` means the `farcast` given was built from another commit: stop, and go back to R0.
- Keep the printed block. It is the two paths for Settings (`farcast` and `farcast configuration directory`), the instance's reader as Check shows it, the state directory, and the commands to change the scenario and to stop.
- Leave it running in this terminal. Drive the rest from a second one, with `DIR` set.

### R2. Open it once from Finder, with nothing planted

Double-click `FarCast.app` in `farsight/client/apple/.build/DerivedData/Build/Products/Debug/`. It gets launchd's environment and its minimal `PATH`. Do not use Xcode's Run button: that build carries no commit (R8).

- Expect the setup view: "Read your instances with your own farcast", and the line naming this build's commit.
- Quit it (⌘Q).

### R3. Open it the way Finder does, with the variables the app must not pass on

`open -n --env` has LaunchServices launch the app as Finder does, with launchd's environment rather than the shell's, plus only these variables. Nothing changes the login session's environment.

```bash
open -n \
  --env CLOUDSDK_AUTH_ACCESS_TOKEN=planted \
  --env CLOUDSDK_CORE_ACCOUNT=someone@work.invalid \
  --env CLOUDSDK_ACTIVE_CONFIG_NAME=work \
  --env CLOUDSDK_CONFIG=/nonexistent \
  --env KUBECONFIG=/nonexistent \
  --env FARCAST_CONFIG_HOME=/nonexistent \
  --env HTTPS_PROXY=http://127.0.0.1:9 \
  farsight/client/apple/.build/DerivedData/Build/Products/Debug/FarCast.app
```

This is Verification 5's second bullet, end to end. R4 to R9 run in this instance of the app; reopen it with this same command whenever a step says to reopen.

- Expect the setup view and the commit line.
- `cat "$DIR/calls.log"` prints nothing.
- `pgrep -fl 'json (version|instances|world)'` prints nothing. The pattern matches the app's `farcast` (`… -o json world -- …`), and not the harness, whose own command line holds `bin/farcast`.
- The planted variables cannot show in `calls.log` since M2.4: `farcast` reads none of them for these three commands, and a line carries no variable. That the child drops them is held by FarSightKit's `ChildEnvironmentTests` and cli's `TestWorldPresentsOnlyTheReaderToken`; this step shows the reads still work with them planted.

### R4. Settings

Open Settings (⌘,), enter the two paths R1 printed, press Check, then Confirm.

- Check shows `farcast <version> · commit $COMMIT — matches this build`, and `rehearsal` with "reader granted".
- Settings refuses a mistyped path, and a relative one, before Check can run.

### R5. The launch listing, and nothing else

- The map shows `rehearsal`, not read yet.
- Quit, and reopen with R3's command. `cat "$DIR/calls.log"` still prints nothing: `version` and `instances` read files on this Mac only, and send no request.

### R6. Refresh (⌘R)

Every fact in the `healthy` row of the table in R7, and also:
- the spending is split, confirmed and expected, and never shown as one total;
- the boundary's panel says `counted by fatline-rehearsal-0 since … · 1 of 1 FatLine replica · every count is a floor`;
- nothing illustrative appears: no fixture group, app or planned line;
- every figure on TechnoCore's panel is whole, none cut at the top or the side, and "more" under its notes opens every word of them, the not-metered list whole among them (F2). At a smaller zoom the figures take a tighter arrangement; they are never cut.

Then the log:

```bash
grep -v ' as reader | ok$' "$DIR/calls.log"                           # prints nothing
awk '{print $2, $3}' "$DIR/calls.log" | sort -u
#   cluster GET
#   token POST
grep ' token ' "$DIR/calls.log" | awk '{print $4}' | sort -u           # /token
```

Every line ends `as reader | ok`: no request was the writer's, carried no token, or was refused. Every `cluster` line is a `GET` of one of `world`'s reads (workload lists, the labelled namespaces, and the ConfigMaps in `farcast-system`), and every `token` line is a `POST /token`. A 404 for a ConfigMap the rehearsal does not hold is an answer, and reads `ok`.

### R7. Each scenario

Switch with `./bin/farcast-rehearsal scenario --dir "$DIR" <name>`, then Refresh once. The switch takes effect on that very read; nothing restarts.

| Scenario | What the map should show |
|---|---|
| `healthy` | Every section read. Spending split, confirmed and expected. `≥n ok` on `api → api.payments.invalid`, and `telemetry.invalid` declared and unused. The keeper healthy, with its line into storage. The tunnel and watch lines. Storage lines "wired, not counted". Replica `fatline-rehearsal-0`, 1 of 1. |
| `sealed` | The `sealed` alert on DataSphere. |
| `stale-checkpoint` | The `checkpoint_stale` alert, and "checkpoint stale" on the chip. |
| `cost-reached` | The critical `cost` alert, and spending over the $50 limit: the total reads more than 100% beside "limit reached", never a few percent (F6). `web` stopped, with no reason given: this kernel recorded no stop. |
| `at-floor` *(added 2026-11-12, after this walk)* | The critical `cost` alert, and beside it the critical `at_floor` alert on TechnoCore, its title naming the levers: drop the load-balancer carrier, or release the instance. Spending over the limit, as in `cost-reached`. `api` and `web` each "stopped by the cost guard". TechnoCore's panel says what still burns a month and names the same levers; the spending line says "at the floor". |
| `token-refused` *(since ADR 0023 M2.4)* | Spend, apps and policy each `credential_refused`. Network and seal still read. Shrike's panel shows what it watched, "1 line watched" and "0 refusals seen", never "not watching" or "not read" (F1). Each panel says each of its own failed sections in one sentence, and no API server text: TechnoCore "spending not read · credential refused — check this machine's clock; then the key id (farcast reader record); a reader key expires with its certificate: farcast reader init <instance> --rotate" and "apps not read · …", FatLine "egress policy not read · …", DataSphere "apps not read · …" (F3). Its figures stay whole. The chip reads "3 sections not read · credential refused" and stays on screen; narrowed, it drops the spending before that, then says "3 sections not read" (F4). farcast's own message appears once, behind the chip's info button. The lines `calls.log` gains are `token` lines ending `refused: token-refused refuses every assertion`, and none is a `cluster` line. |
| `unauthorized` *(since ADR 0023 M2.4)* | Spend, apps and policy each `unauthorized`, network and seal read, as in `token-refused`. The sentence's remedy: "the cluster refused the reader's token: check that the Cloud Shell step granted roles/container.clusterViewer; farcast instances shows the reader's state". The chip reads "3 sections not read · unauthorized". `calls.log`'s `cluster` lines end `refused: unauthorized answers every read`. |
| `forbidden` *(since ADR 0023 M2.4)* | Spend and policy each `forbidden`; apps, network and seal read. TechnoCore "spending not read · forbidden — the reader may not read this: farcast reader grant <instance>; if the reader was just set up, IAM changes can take 7 minutes or longer", and FatLine "egress policy not read · …". The chip reads "2 sections not read · forbidden". Only the checkpoint's and the egress policy's `calls.log` lines end `refused: forbidden answers this read`. |
| `reader-missing` *(since ADR 0023 M2.4)* | Spend, apps and policy each `credential_missing`, network and seal read, and nothing sent to the cluster: `wc -l < "$DIR/calls.log"` is the same before and after the Refresh. The chip reads "3 sections not read · credential missing". Settings › Check shows `rehearsal` with "reader key missing, not on this Mac" and the `farcast reader init … --rotate` line, never the reader's email. |
| `denied` | The `denied` alert on `shop/web`, and a refused line to `tracker.invalid`, on the first read after the switch. |
| `slow-cluster` | R9's. |

- A failed read keeps the last good snapshot, faded, with its read time.
- Walk `denied` last. Its refusals stay in Shrike's picture, and its alert stays within the hour, until the harness restarts, as a real Shrike's do. R8's restart clears them.
- Return to `healthy` at the end.
- `signed-out` and `identity-mismatch` were retired with the gcloud identity (ADR 0023 M2.4): the harness refuses them and names `token-refused` and `forbidden`. Their rows in the 2026-11-12 Results are the old rig's.

### R8. Failure paths

1. **The tunnel goes away.** `./bin/farcast-rehearsal scenario --dir "$DIR" tunnel-down`, wait a moment for FatLine to stop listening, then Refresh. Network and seal read `tunnel_unreachable`. Apps, spend and policy still read, because the cluster stays up. The declared line to `telemetry.invalid` reads "declared · use not read", and its card "declared by shop/api, use not read", never "unused" (F8). TechnoCore still counts "0 apps stopped": Shrike's state not read is no application's. DataSphere's keepers needing attention read "not read", never 0.
2. **The harness comes back.** `./bin/farcast-rehearsal scenario --dir "$DIR" healthy`, then Ctrl-C the harness, and restart it on **the same directory**: `./bin/farcast-rehearsal --dir "$DIR" --farcast "$PWD/bin/farcast"`. It rebinds the same tunnel and cluster ports, reuses its own leaves and writes a new `cluster-ca.crt`, so Settings stay as they are. Refresh: healthy again, the keeper included, and no `denied` alert. If it says the port is in use, stop whatever holds it, or start a new rehearsal in a new directory and enter Settings again. *(Since 2026-11-13: a rehearsal directory made before [ADR 0020](../adr/0020-instance-pki-ecdsa-p256.md) moved the instance PKI to P-256 holds an Ed25519 CA, and a restart refuses it with "start a new one in a new directory"; do that, and enter Settings again.)* *(Since 2026-11-15: a directory made before ADR 0023 M2.4 holds the fake tools and no `cluster-ca.crt`, and a restart refuses it the same way.)*
3. **farcast goes missing.** `mv ./bin/farcast ./bin/farcast.away`, then Refresh. Refresh lists first, and the listing's preflight finds nothing at the path before it runs anything: "Settings need attention: farcast: nothing is at this path". Restore it with `mv ./bin/farcast.away ./bin/farcast`.
4. *Optionally,* `chmod -x ./bin/farcast`, then Refresh: "Settings need attention: farcast: is not executable by you". Restore it with `chmod 755 ./bin/farcast`. ("could not be started" comes only from a file that passes these checks and still will not exec.)
5. **A build without its commit.** Run the app from Xcode's Run button: "built without its commit", and nothing runs (`calls.log` gains nothing). Quit it, and reopen with R3's command.

### R9. Quit mid-read

Switch to `slow-cluster`, Refresh, then ⌘Q within 5 seconds. Two seconds later, `pgrep -fl 'json (version|instances|world)'` prints nothing and exits 1, which is `pgrep`'s "no match". That means quitting stopped the read; since ADR 0023 M2.4 it starts no other process. Exit 0 with lines printed would be a finding. `calls.log` may end with lines `refused: the caller left while the answer was held`, which are not. Switch back to `healthy`.

### R10. Teardown

- Settings › Forget, then quit the app.
- Ctrl-C the harness, then `rm -rf "$DIR"`.
- Optionally, `defaults delete com.sofmon.farcast farsight.arrangement.live.v1`. Before any live read it holds only the rehearsal's places.

### Firewall notes

- Every rehearsal connection is to 127.0.0.1. The app itself makes **no** connection: it runs `farcast`, and `farcast` connects.
- An outbound-firewall prompt for `FarCast` itself, or for any destination other than 127.0.0.1, during the rehearsal is a **finding**. Deny it and record it.
- A prompt for `farcast` or `farcast-rehearsal` to 127.0.0.1 may be allowed, for loopback only.
- Local Network privacy does not apply to loopback.

---

## Part L: the first live read

It comes after Part R passes, and after `farcast world` has been walked from a terminal (PLAN principle 3).

### L0. Ask before spending

- Reading costs nothing beyond the instance's standing floor (about $0.106/hour), which is already being paid if an instance is up.
- Standing one up is billable. Present the cost, the duration and the teardown, and wait for a yes. Approval does not carry over from another walk.
- Every instance `farcast instances` lists is read on Refresh. Make sure that list is what you mean to read.

### L1. The reader

Since [ADR 0023](../adr/0023-one-download-farcast.md) M2.4, `world` reads the cluster as the instance's own read-only service account, its reader, and reads no cluster section without one. Set it up with [phase 1's step 7b](phase-1-validation.md#7b-the-instances-reader-identity--not-yet-walked), which is not yet walked: `farcast reader init`, the printed script pasted into Cloud Shell by an Owner of the project, `farcast reader record`, and `farcast reader grant` once the instance is connected.
- **The operator runs these**, in their own terminal and Cloud Shell, never through an agent's shell: the script names the project and the account.
- `reader grant` still applies its RBAC through kubectl as the active gcloud configuration, until M2.7. Use only the FarCast gcloud configuration for it, never a work one. Check that gcloud is signed in without printing a secret. Never run `gcloud auth print-access-token`, even with its output redirected: zsh's MULTIOS still sends it to the pipe.
- Where the organization forbids service-account key upload, there can be no reader, and this walk stops here. Record that, and nothing else.
- The walk records only that `farcast instances -o json` shows `"reader":"granted"` for `$INSTANCE`. It never prints the email or the key id.

### L1b. The real paths in Settings

R10's Forget left the `farcast` field empty. The operator enters:
- the real `farcast`: R0's `./bin/farcast`, by its absolute path;
- the real farcast configuration directory.

Then Check, then Confirm. Check must show the commit match, and `$INSTANCE` with "reader granted". The paths are never recorded: they hold the home directory.

### L2. A terminal walk under the app's own environment

- Settings › Check, then "Copy terminal command" for `$INSTANCE`.
- Run it at once, so the clipboard holds that command and its text never appears:
  ```bash
  sh -c "$(pbpaste)" 2>/dev/null | ./bin/farcast-rehearsal summarize
  ```
  The command holds home-directory paths and the instance's name. farcast's stderr is dropped; a refusal arrives as the envelope on stdout, whose kind `summarize` prints.
- Record only that summary.
- This is the same argv and environment the app will use. It proves that `farcast` reads a live cluster as the reader under the app's environment, with only the system's own directories on `PATH` and no `CLOUDSDK_*` variable, and that GKE's DNS endpoint accepts the reader's token. The rehearsal cannot prove either: its cluster and token endpoint are on loopback.

### L3. The app

One Refresh. Expect these outbound-firewall prompts, all for `farcast`, and allow each for this destination only:
- the carrier's address and port;
- the control plane's `*.gke.goog:443`;
- `oauth2.googleapis.com:443`, where it mints the reader's token.

Deny anything else, and record it. Nothing else should start: since M2.4 the app's `farcast` runs no kubectl and no gcloud.

### L4. Record, and tear down

- Record with the scrub rule, below.
- A read leaves nothing to tear down. The reader L1 set up does: its Google account, its uploaded keys and its project binding outlive the instance.
- If an instance was stood up for this walk, release it. Its result prints a `reader:` line naming the account, and two Cloud Shell lines that delete it, the binding's removal first. **The operator** runs both in Cloud Shell, as an Owner of the project. Record only that they ran, and whether each succeeded.
- Then verify independently that nothing is left billing: clusters, registries, buckets, forwarding rules and addresses.

---

## The scrub rule

- Never paste these into the transcript, an issue or the repository:
  - raw `world` or `instances` output from a live instance;
  - a live screenshot;
  - a live `calls.log` (there is none: the cluster is real);
  - a copied terminal command.
- Record only `farcast-rehearsal summarize` output, and placeholders: `$INSTANCE`, `<namespace>`, `<host>`, `<repository>`.
- Never record instance, namespace, app or host names, repository URLs, deployed commits, replica Pod names, the carrier's address, the project, account emails, home-directory paths, or times of day.
- Rehearsal output may be recorded as it is, because every name in it is a `.invalid` placeholder. Write home paths as `~`, and paths under `$TMPDIR` (`/var/folders/<per-user id>/T/…`, or its `/private/var` form) as `$TMPDIR/…`.

---

## Results

### Part R: walked 2026-11-12 at `5bb19ac`, by the operator

| Step | Result | Notes |
|---|---|---|
| Commit | `5bb19ac` | The Connected view's own commit. |
| R0 build, `./check.sh` | pass | `./check.sh` passed on this exact tree immediately before it was committed. It was not re-run at the commit itself. `./bin/farcast version` and the app's `FarCastCommit` both read `5bb19ac`. |
| R1 harness | pass | Started on a temporary directory under `$TMPDIR`. |
| R2 Finder, nothing planted | not reported | |
| R3 Finder, planted | pass | Opened with R3's `open -n --env …` command, all seven variables planted. Every read that followed reached the fake tools, which refuse the moment a planted variable reaches them, so none did. Before the commit, `farcast` run from a terminal under the app's exact child environment showed the same. |
| R4 Settings | pass | Inferred from the reads that followed. |
| R5 launch listing | not reported | |
| R6 Refresh | pass, one finding | Spending split as `$1.45 confirmed through Nov 10 + $2.77 expected of $50.00`. `counted by fatline-rehearsal-0 … 1 of 1 FatLine replica · every count is a floor` appears on FatLine and Shrike. Nothing illustrative. The group is labelled `git.rehearsal.invalid/shop · main at ef4c4ac`. TechnoCore's notes are clipped (F2). The `calls.log` checks were not reported. |
| R7 scenarios | pass, five findings | `sealed`: the alert, and DataSphere red. `stale-checkpoint`: "checkpoint stale" on the chip and the panel. `cost-reached`: the alert and `web` stopped, but "total 8%" beside "limit reached" (F6). `signed-out`: spend, apps and policy read "signed out of gcloud" while network and seal read, but Shrike says "not watching" (F1), raw errors fill the panels (F3), and the chip runs off screen (F4). `identity-mismatch`: refused, the last snapshot kept and faded, the tunnel no longer claimed, but "read not read" (F5). `denied`: ✕ at the OUT gate, `tracker.invalid` "≥1 refused", the alert on `shop/web`. |
| R8 failure paths | pass, one finding | R8.1: network and seal read `tunnel_unreachable`, Shrike "state not read", the IN gate no longer "your tunnel", the keeper "not read". But declared lines read "declared · unused" (F8). R8.2: a restart on the same directory came back healthy with Settings untouched, the keeper healthy and the `denied` alert gone. R8.3–R8.5 were not reported. |
| R9 quit mid-read | pass | `pgrep` printed nothing (exit 1). |
| R10 teardown | pass | Settings forgotten, the app quit, the harness stopped and its temporary directory removed. |
| L0–L4 | not walked | |

### Findings

- **F1. Shrike says "not watching" after a read whose `apps` section failed, though Shrike answered.**
  - The CLI marks the monitor `unknown` when the workloads read fails. The design says it is `running` whenever Shrike answered through the tunnel.
  - The panel then requires `running` before it trusts the observed watch line.
- **F2. Long notes are clipped.** TechnoCore's not-metered list ends mid-sentence, so what the meter does not see is not fully readable (ADR 0009).
- **F3. Raw errors fill the panels.** A failed section's whole kubectl and gcloud message is repeated in several panels. It overflows them, clipping their first row and running under lines.
- **F4. The chip runs off screen** with one entry per failed section.
- **F5. "read not read (gcloud identity does not match)"** should say the read was refused. **"1 apps stopped"** should be singular.
- **F6. The harness's `cost-reached` scenario contradicts itself.** It shows "limit reached" beside "total 8%", because it flips the kernel's level without putting spending over the limit.
- **F7. A scenario name passed to the start form gets only "unknown command".** It should point to `farcast-rehearsal scenario --dir <dir> <name>`.
- **F8. A declared line reads "declared · unused" when the network section was not read.** That claims an absence of traffic nobody read.

**Seen, and not counted as findings:**
- Lines cross panel content: the keeper line over FatLine's figures, and an egress line through `web`.
- The Connections legend covers part of a device card.
