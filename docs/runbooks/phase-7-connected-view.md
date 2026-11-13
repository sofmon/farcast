# Phase 7 — the Connected view: the no-cost rehearsal, then the first live read

The macOS FarCast app reads the operator's instances by running the operator's own `farcast` ([ADR 0021](../adr/0021-farsight-native-client.md) decision 9, amended 2026-11-12). This runbook walks it twice: first from Finder against an instance that lives on this Mac, then against a live one. It is the ADR's "Walked before it is relied on", and the rehearsal step of its Verification 5.

**Part R costs nothing and touches no cloud.** Everything in it listens on 127.0.0.1: a real FatLine and Shrike, two keyholder replicas, and fake `kubectl`, `gke-gcloud-auth-plugin` and `gcloud` (`farsight/cli/README.md`, "The no-cost rehearsal").

**Part L reads a live instance.** A read adds no standing cost, but it needs an instance up, and an instance up is billable. Ask before standing one up (L0).

**Gate G1 (2026-11-12): Q1 and Q2 accepted.** The app's child `PATH` ends with the system's own directories, and its `CLOUDSDK_CONFIG` is the gcloud directory confirmed in Settings. Without the second, a `farcast` started from Finder would read the operator's real `~/.config/gcloud`. So R4 to R9 are not blocked.

**Commit walked:** `5bb19ac` (2026-11-12). **Status:** Part R walked 2026-11-12. R2, R5 and R8.3–R8.5 were not reported, and Part L is not walked. Eight findings, listed under Results.

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
- Keep the printed block. It is the six paths for Settings, the state directory, and the commands to change the scenario and to stop.
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
- `pgrep -fl 'json (version|instances|world)|/kube/bin/kubectl '` prints nothing. The pattern matches the app's `farcast` (`… -o json world -- …`) and the fake `kubectl`, and not the harness, whose own command line holds `bin/farcast`.

### R4. Settings

Open Settings (⌘,), enter the six paths R1 printed, press Check, then Confirm.

- Check shows `farcast <version> · commit $COMMIT — matches this build`, and `rehearsal` with "gcloud account pinned".
- Settings refuses a mistyped path, and a relative one, before Check can run.

### R5. The launch listing, and nothing else

- The map shows `rehearsal`, not read yet.
- Quit, and reopen with R3's command. `cat "$DIR/calls.log"` still prints nothing: `version` and `instances` read files on this Mac only, and call no tool.

### R6. Refresh (⌘R)

Every fact in the `healthy` row of the table in R7, and also:
- the spending is split, confirmed and expected, and never shown as one total;
- the boundary's panel says `counted by fatline-rehearsal-0 since … · 1 of 1 FatLine replica · every count is a floor`;
- nothing illustrative appears: no fixture group, app or planned line;
- every figure on TechnoCore's panel is whole, none cut at the top or the side, and "more" under its notes opens every word of them, the not-metered list whole among them (F2). At a smaller zoom the figures take a tighter arrangement; they are never cut.

Then the log:

```bash
grep -v ' | ok$' "$DIR/calls.log"                                     # prints nothing
grep ' kubectl ' "$DIR/calls.log" | awk '{print $5}' | sort -u         # get
grep -E ' (gke-gcloud-auth-plugin|gcloud) ' "$DIR/calls.log" | cut -d' ' -f2- | sort -u
#   gcloud config config-helper --format=json | ok
#   gke-gcloud-auth-plugin | ok
grep -E 'planted|work\.invalid|CLOUDSDK_AUTH|CLOUDSDK_CORE|GOOGLE_APPLICATION|nonexistent|PROXY' "$DIR/calls.log"   # prints nothing
```

Every line ends `| ok`. Every `kubectl` line's first argument after `--kubeconfig <path>` is `get`. The other lines are `gke-gcloud-auth-plugin`, with no arguments, and `gcloud config config-helper --format=json`. No line names a planted variable: the fake `kubectl` would have refused it, and said which.

### R7. Each scenario

Switch with `./bin/farcast-rehearsal scenario --dir "$DIR" <name>`, then Refresh once. The switch takes effect on that very read; nothing restarts.

| Scenario | What the map should show |
|---|---|
| `healthy` | Every section read. Spending split, confirmed and expected. `≥n ok` on `api → api.payments.invalid`, and `telemetry.invalid` declared and unused. The keeper healthy, with its line into storage. The tunnel and watch lines. Storage lines "wired, not counted". Replica `fatline-rehearsal-0`, 1 of 1. |
| `sealed` | The `sealed` alert on DataSphere. |
| `stale-checkpoint` | The `checkpoint_stale` alert, and "checkpoint stale" on the chip. |
| `cost-reached` | The critical `cost` alert, and spending over the $50 limit: the total reads more than 100% beside "limit reached", never a few percent (F6). `web` stopped, with no reason given: this kernel recorded no stop. |
| `at-floor` *(added 2026-11-12, after this walk)* | The critical `cost` alert, and beside it the critical `at_floor` alert on TechnoCore, its title naming the levers: drop the load-balancer carrier, or release the instance. Spending over the limit, as in `cost-reached`. `api` and `web` each "stopped by the cost guard". TechnoCore's panel says what still burns a month and names the same levers; the spending line says "at the floor". |
| `signed-out` | Spend, apps and policy each `gcloud_signed_out`. Network and seal still read. Shrike's panel shows what it watched, "1 line watched" and "0 refusals seen", never "not watching" or "not read" (F1). Each panel says each of its own failed sections in one sentence, and no kubectl or gcloud text: TechnoCore "spending not read · signed out of gcloud — run gcloud auth login" and "apps not read · …", FatLine "egress policy not read · …", DataSphere "apps not read · …" (F3). Its figures stay whole. The chip reads "3 sections not read · signed out of gcloud" and stays on screen; narrowed, it drops the spending before that, then says "3 sections not read" (F4). gcloud's own message appears once, behind the chip's info button. |
| `identity-mismatch` | The read is refused with `gcloud_mismatch` before any `kubectl` runs: `grep -c ' kubectl ' "$DIR/calls.log"` is the same before and after the Refresh. Every panel says "the read was refused · gcloud identity does not match — farcast instances pin-gcloud", and the chip "read refused · gcloud identity does not match", never "read not read" (F5). |
| `denied` | The `denied` alert on `shop/web`, and a refused line to `tracker.invalid`, on the first read after the switch. |
| `slow-cluster` | R9's. |

- A failed read keeps the last good snapshot, faded, with its read time.
- Walk `denied` last. Its refusals stay in Shrike's picture, and its alert stays within the hour, until the harness restarts, as a real Shrike's do. R8's restart clears them.
- Return to `healthy` at the end.

### R8. Failure paths

1. **The tunnel goes away.** Ctrl-C the harness, then Refresh. Network and seal read `tunnel_unreachable`. Apps, spend and policy still read, because the fake tools are files. The declared line to `telemetry.invalid` reads "declared · use not read", and its card "declared by shop/api, use not read", never "unused" (F8). TechnoCore still counts "0 apps stopped": Shrike's state not read is no application's. DataSphere's keepers needing attention read "not read", never 0.
2. **The harness comes back.** Restart it on **the same directory**: `./bin/farcast-rehearsal --dir "$DIR" --farcast "$PWD/bin/farcast"`. It rebinds the same tunnel port and reuses its own leaves, so Settings stay as they are. Refresh: healthy again, the keeper included, and no `denied` alert. If it says the port is in use, stop whatever holds it, or start a new rehearsal in a new directory and enter Settings again. *(Since 2026-11-13: a rehearsal directory made before [ADR 0020](../adr/0020-instance-pki-ecdsa-p256.md) moved the instance PKI to P-256 holds an Ed25519 CA, and a restart refuses it with "start a new one in a new directory"; do that, and enter Settings again.)*
3. **farcast goes missing.** `mv ./bin/farcast ./bin/farcast.away`, then Refresh. Refresh lists first, and the listing's preflight finds nothing at the path before it runs anything: "Settings need attention: farcast: nothing is at this path". Restore it with `mv ./bin/farcast.away ./bin/farcast`.
4. *Optionally,* `chmod -x ./bin/farcast`, then Refresh: "Settings need attention: farcast: is not executable by you". Restore it with `chmod 755 ./bin/farcast`. ("could not be started" comes only from a file that passes these checks and still will not exec.)
5. **A build without its commit.** Run the app from Xcode's Run button: "built without its commit", and nothing runs (`calls.log` gains nothing). Quit it, and reopen with R3's command.

### R9. Quit mid-read

Switch to `slow-cluster`, Refresh, then ⌘Q within 5 seconds. Two seconds later, `pgrep -fl 'json (version|instances|world)|/kube/bin/kubectl '` prints nothing and exits 1, which is `pgrep`'s "no match". That means quitting stopped the read and every process it started. Exit 0 with lines printed would be a finding. Switch back to `healthy`.

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

### L1. Identity

- **The operator types this in their own terminal**, never through an agent's shell, because it names the account: `farcast instances pin-gcloud $INSTANCE --account <the FarCast account>`. Use only the FarCast gcloud configuration, never a work one.
- The walk records only that `farcast instances -o json` shows `"gcloud_pinned": true`. It never prints the email.
- Check that gcloud is signed in without printing a secret. Never run `gcloud auth print-access-token`, even with its output redirected: zsh's MULTIOS still sends it to the pipe.

### L1b. The real paths in Settings

R10's Forget left the tool fields empty. The operator enters:
- the real `farcast`: R0's `./bin/farcast`, by its absolute path;
- the real `kubectl`, `gke-gcloud-auth-plugin` and `gcloud`;
- the two real configuration directories.

Then Check, then Confirm. Check must show the commit match, and `$INSTANCE` with "gcloud account pinned". The paths are never recorded: they hold the home directory.

### L2. A terminal walk under the app's own environment

- Settings › Check, then "Copy terminal command" for `$INSTANCE`.
- Run it at once, so the clipboard holds that command and its text never appears:
  ```bash
  sh -c "$(pbpaste)" 2>/dev/null | ./bin/farcast-rehearsal summarize
  ```
  The command holds home and gcloud paths and the instance's name. farcast's stderr is dropped; a refusal arrives as the envelope on stdout, whose kind `summarize` prints.
- Record only that summary.
- This is the same argv and environment the app will use. It proves that the real `gcloud`, a shell script that needs the system's utilities and finds its Python on `PATH`, runs on the app's `PATH` (Q1). The rehearsal cannot prove this: its tools are fakes.

### L3. The app

One Refresh. Expect these outbound-firewall prompts, and allow each for this destination only:
- `farcast` → the carrier's address and port;
- `kubectl` → the control plane's `*.gke.goog:443` (on this Mac, Docker's binary behind `/usr/local/bin/kubectl`);
- the Python that `gcloud` runs → `oauth2.googleapis.com:443`.

Deny gcloud's update check, and anything else, and record it.

### L4. Record

- Record with the scrub rule, below.
- There is nothing to tear down for a read.
- If an instance was stood up for this walk, release it, and verify independently that nothing is left billing: clusters, registries, buckets, forwarding rules and addresses.

---

## The scrub rule

- Never paste these into the transcript, an issue or the repository:
  - raw `world` or `instances` output from a live instance;
  - a live screenshot;
  - a live `calls.log` (there is none: the tools are real);
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
