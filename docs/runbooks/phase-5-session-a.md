# Phase 5 — Session A: the consolidated walk that closes it

One instance, one session, every Phase 5 criterion still open, and every check the 2026-10-08 work added. It replaces running the 5.2, 5.3 and 5.4 runbooks separately; each step names the criterion it answers, and the per-phase runbooks keep the reasoning behind each one.

**It is billable.** Expect about six hours and roughly $1 — the standing floor is about $0.106/hour — the five system Pods and the carrier at $0.0554/hour, plus the modelled cluster line — plus about six application Pods and four builds. Do not start it until the spend is approved.

**Keepers stay in `--once` mode for the whole session — never as a running daemon.** A running keeper re-seeds every restart-sealed replica, and most of the checks below need a replica to *stay* sealed until the step says otherwise.

Throughout: the operator's own gcloud configuration only, and `--credentials <service-account-key.json>` on every `farcast` command that takes it. No Application Default Credentials. Never paste a project id, bucket name, address or key into the results — `$INSTANCE` and placeholders only.

*Checked against the code on 2026-11-09, before the walk, in two passes: twenty-two places where following this runbook as written would have gone wrong — one of them a rotation left unfinished in 7d that broke 7g and 7h — are corrected below, and the one that was the code's (`keeper status` read no fleet budget total, 5.4 c9) is fixed.*

---

## The walk probe, and where scratch files live

Several checks need a client the CLI refuses to be — a keeper claiming to be the operator, a lost device pushing an old bundle, an application's leaf at the public tunnel. They use the build-tagged probe, which is Go in this repository and adds no tool to the operator's machine.

Set these once, in the shell you walk from, at the root of the checkout:

```bash
INSTANCE=<name>              # first: KEYS below expands it once, and S1 installs under this name
REPO=$PWD                    # the checkout: every farcast command runs from here
WALK=$(mktemp -d)            # 0700 and OUTSIDE the checkout: keyring copies, packets, the passphrase, leaves
probe() { env FARCAST_WALK=1 FARCAST_WALK_INSTANCE="$INSTANCE" FARCAST_WALK_CWD="$WALK" "$@" \
  go test -C "$REPO" -mod=vendor -tags walk -count=1 -run TestWalkProbe -v ./farsight/cli/internal/cli/; }
# device A as itself — its own leaf AND its own bundle; any other bundle is refused as keeper-bundle first
asA() { probe FARCAST_WALK_LEAF=packet:a.packet FARCAST_WALK_BUNDLE=packet:a.packet FARCAST_WALK_PASSPHRASE_FILE=pass "$@"; }
KEYS="${FARCAST_CONFIG_HOME:-$HOME/Library/Application Support/farcast}/instances/$INSTANCE/datasphere"
# the directory holding this machine's keys.yaml — the macOS default; on Linux, ${XDG_CONFIG_HOME:-$HOME/.config}/farcast/…
```

Every relative path the probe is given resolves against `$WALK`, and every scratch file below is created there — never in the checkout. A file there is untracked key material one `git add -A` away from a pushed repository, and it makes any rebuild report `vcs.modified=true`. The passphrase file is `$WALK/pass`, 0600, written once by hand.

Its header ([`walkprobe_test.go`](../../farsight/cli/internal/cli/walkprobe_test.go)) lists the probes and inputs: `FARCAST_WALK_LEAF` (`operator`, the default; `store:<dir>`; `packet:<file>`), `FARCAST_WALK_BUNDLE` (`store:`, `packet:`, `keys:<file>`, `keys:@live` — this machine's current keyring), `FARCAST_WALK_INTENT`, `FARCAST_WALK_ORDINAL` (default 0), `FARCAST_WALK_GENERATION`, `FARCAST_WALK_HOLD=1` to make `seal` a hold, `FARCAST_WALK_PASSPHRASE_FILE`, `FARCAST_WALK_CERT`/`_KEY` for `tunnel` (or, without them, the leaf `FARCAST_WALK_LEAF` names), `FARCAST_WALK_PACKET` and `FARCAST_WALK_OBJECT` for `packet` and `open`. Every `push` needs a `FARCAST_WALK_BUNDLE`. It prints key IDs and never key material. The probe runs only on the operator's machine: device A has the keeper binary and nothing else, so A's leaf is presented from its packet, which stays in `$WALK` after enrolment.

---

## S0. Before the session

1. `./check.sh --model` passes at the commit being walked. Record the commit and the check's summary line.
2. The commit is pushed. `farcast run` clones the repository from GitHub, so a fixture or Containerfile change reaches the walk only once pushed (or with `--ref <pushed sha>`).
3. Build the binary from that clean checkout, check it is that commit, and make it the `farcast` every later step runs:
   ```bash
   go build -o ./bin/farcast ./farsight/cli/cmd/farcast
   ./bin/farcast version
   go version -m ./bin/farcast | grep -E 'vcs.revision|vcs.modified'   # vcs.modified=false
   export PATH="$PWD/bin:$PATH"; hash -r
   command -v farcast    # must be <this checkout>/bin/farcast
   ```
   Do not set `Version` with ldflags: it becomes the tag of every system image. A different `farcast` earlier on `PATH` would tag the images with *its* version, and they would not be built from the commit being walked. Run every command from this checkout — the system images are compiled from it.
4. The second machine: the keeper binary only, cross-compiled from the same commit **into `$WALK`, not `./bin`** (a Linux build there would replace the operator's own binary): `GOOS=linux GOARCH=amd64 go build -o "$WALK/device/farcast" ./farsight/cli/cmd/farcast`, or for a Mac, a copy of `./bin/farcast`. Copy it with `scp` and put it on A's `PATH` as `farcast` — the steps below type `farcast keeper …` on A. No `~/.kube`, no gcloud, no key file, no farcast config directory.
5. Every keeper enrolled before 2026-10-08 is dead to the new image: keeper leaves now bind their bundle, and one that binds none is refused. Nothing to do — this session enrols fresh ones.

## Bring-up

**S1.** `farcast install --name "$INSTANCE" --cost-limit 100 --region us-central1` — the name from the setup block, so `$KEYS` points at this instance's keyring. *Expect* no below-floor warning (the floor is about USD 77.42, and the limit clears it — install prints the floor only when it does not) and no region warning.

**S2.** `farcast connect`. *Tunnel admission, part 1:* `farcast connect "$INSTANCE" --status` connects; a request with no client certificate is refused at the handshake (the phase-2 B4 check).

**S3.** Mirror the toolchain and apply the builder's push grant **before** any build:
```bash
farcast toolchain "$INSTANCE" --builder gcr.io/kaniko-project/executor:v1.23.2 --fetcher cgr.dev/chainguard/git:latest-dev
# it refuses the tags and prints the digests; run it again with the @sha256: references
```
Then the push grant ([the 4.2 runbook](phase-4-2-validation.md), step 2). Nothing in this walk prints it before a build fails — `run` names it only after a refused push, when the clone and the build are already paid for:
```bash
PROJNUM=$(gcloud projects describe <project> --format='value(projectNumber)')
PRINCIPAL="principal://iam.googleapis.com/projects/$PROJNUM/locations/global/workloadIdentityPools/<project>.svc.id.goog/subject/ns/farcast-system/sa/farcast-builder"
gcloud artifacts repositories add-iam-policy-binding "farcast-$INSTANCE" --location us-central1 --member "$PRINCIPAL" --role roles/artifactregistry.writer
```
The grant is on the one repository, not the project. Apply it now: the registry can take several minutes to honour it (the 5.1 walk measured nine and more), and S4–S6 give it that time before S7's first build.

**S4.** `farcast storage deploy`, and the bucket grant it prints; wait for the grant to propagate.
- *Key pin created before the replicas:* `kubectl -n farcast-system get configmap datasphered-pin -o json` exists, its `pin` is `{"version":1,"require":[],"retired":[]}`, and it carries no scope name.
- 3.2 c2/c3: no data endpoints while sealed; the status endpoint answers.
- `farcast storage unseal` on the empty instance — *expect* "holding no application scopes: this instance has no applications yet" (5.3 c15).

**S5. New: `run` refuses without a kernel.** `farcast run "$INSTANCE" <repo> --manifest manifest/examples/sdk-demo/farcast` refuses, naming `farcast kernel deploy`. *Then:* no `fetch-*` Job in `farcast-system`, no `sdk-demo` namespace, and `farcast storage key list` unchanged.

**S6.** `farcast kernel deploy` with defaults. **New: carrier metering.**
- The kernel's log, while no fetch or build Job runs: `carrier state=load-balancer per_hour=0.0250`, then `reconciled … rate_per_hour=0.0554 overhead_per_hour=0.0250 carrier=load-balancer` (five system Pods 0.0304 plus the carrier).
- **About six minutes after the first `reconciled` line**, `farcast costs` shows `carrier` under *Instance overhead (never attributed to an application)*, and ends with the *Not metered* block. Not sooner: the first tick bills nothing (there is no earlier observation to bill from) and writes the first checkpoint, `costs` reads only checkpoints, and the next is written five minutes later (`--checkpoint-interval`). Before then the rate line already ends "and the carrier" and the overhead block is absent — expected, not a failure. The carrier's figure is a fraction of a cent and may print as 0.00; the line being there is the check.

## Applications, sealing, and the kernel

**S7.** `farcast run` sdk-demo.
- 5.3 c14a: the unseal ledger shows distinct boots.
- *Key pin raised before the hand-over:* the pin now requires the two new scopes' key IDs and retires nothing. `farcast storage state "$INSTANCE" -o json` shows `"pin_status":"current"` for every replica; the human view prints a `key pin:` line **only** when a pin is not current, so there the pass is that no replica has one.
- Set the secrets: `farcast secret set "$INSTANCE" sdk-demo/alpha DB_PASSWORD` (and the rest from the 5.3 runbook). Quick regression of 5.3 c11/c12.
- The 3.2 crux, from inside alpha with its own leaf — the corrected step 5 of [the 3.2 runbook](phase-3-2-validation.md).
- Scale **beta** to 3 for 5.2 (`kubectl -n sdk-demo scale deploy/beta --replicas=3`), so alpha — the subject of S10 and S14 — is never rolled.
- **The status endpoint (fixed 2026-10-08):** `farcast storage seal "$INSTANCE"` (both replicas), wait at least 20 s with `kubectl -n farcast-system get endpoints datasphered` showing none, and alpha reports `sealed`, not unavailable. Then `farcast storage unseal`.

**S8.** `farcast kernel deploy "$INSTANCE" --interval=10s` (5.1 c12). Over ten minutes and more, `observed usage … unrefreshed=N` appears with N>0; `farcast usage -o json` sample counts grow about two a minute per Pod, not six.

**S9.** Enrol device A for 5.4 c1 and c2, on the operator's machine:
```bash
farcast keeper enroll "$INSTANCE" <A> --budget 8 --out "$WALK/a.packet" --passphrase-file "$WALK/pass"
```
Copy `a.packet` and `pass` to A. On A: `farcast keeper install a.packet --passphrase-file pass` — on Linux, refused first without `--accept-backup-risk`, then accepted with it. **Then `rm a.packet pass` on A:** `install` leaves both where they were, outside the 0700, backup-excluded keeper directory, and the packet is A's leaf key and bundle with its passphrase beside it. The operator's copies in `$WALK` stay; the probe presents A from them.
- `probe FARCAST_WALK_PROBE=packet FARCAST_WALK_PACKET=a.packet FARCAST_WALK_PASSPHRASE_FILE=pass` — two leaf URIs (the device, then `urn:farcast:keeper-bundle:sha256:…`), "the leaf binds the bundle it carries", no master key ID.
- Inventory the device (5.4 c2): the keeper binary and the keeper directory, and no credentials, packet, passphrase or other state.

**S10.** 5.4 c3: `kubectl -n farcast-system delete pod datasphered-0`, then `farcast storage state "$INSTANCE"` until replica 0 reads `restart-sealed` — not unreachable. On A, `farcast keeper run "$INSTANCE" --once` re-seeds it (`replica 0: re-seeded …`). Alpha's restart count stays 0. A `replica 0: unreachable` means the Pod was not back yet: run it again — an unreachable pass writes no ledger line and spends no budget.

## Keepers, egress, and adapting

**S11. Keepers refuse after a `run` that mints a scope.**
1. `install -m 0600 "$KEYS/keys.yaml" "$WALK/keys.pre-S11.yaml"` — the keyring before the new scopes.
2. `farcast run` egress-demo. This also covers 4.4 steps 2–8 and 5.1 c13; `farcast usage` names Shrike's Pod.
3. `run` printed the re-enrol list.
4. `kubectl -n farcast-system delete pod datasphered-0`, then `farcast storage state` until replica 0 reads `restart-sealed`.
5. On A, `keeper run --once` reports `stale-bundle`, naming the key pin; the ledger line count is unchanged and replica 0 stays restart-sealed.
6. `farcast storage unseal` recovers it.
7. Re-enrol A at the same path — `enroll` never overwrites, and every later step reads `a.packet` as A's *current* packet: `rm "$WALK/a.packet"`, then `farcast keeper enroll "$INSTANCE" <A> --budget 8 --out "$WALK/a.packet" --passphrase-file "$WALK/pass"` (same device name). Copy `a.packet` and `pass` to A, `farcast keeper install a.packet --passphrase-file pass` (with `--accept-backup-risk` on Linux), and `rm a.packet pass` on A again. The ledger is kept: A's `keeper status` still counts the S10 re-seed.

**S12.** 5.2 c9–c12, about 25 minutes after S7, once beta has 120 readings.
- `farcast kernel deploy "$INSTANCE" --adapt --adapt-cooldown=2m`. The 10 s interval from S8 is carried forward — visible in the Pod's arguments without being named again.
- Exactly one beta resize, 100m/128Mi to 50m/64Mi, with `monthly_delta=-5.5434` (three Pods at -1.8478 each).
- At least three cooldowns (six minutes and more) with no second `resized` line, no `0.0000`, and the stored requests equal to `to=`. Beta has two ReplicaSets.
- Then `farcast kernel deploy "$INSTANCE" --adapt=false`, before alpha reaches coverage (about 60 minutes after S7).
- Reboot device A now (5.4 c8).

**S13. Holds, solicitation, budget, and the drop refusal.** Every probe push here sets `FARCAST_WALK_ORDINAL` explicitly: what a replica answers depends on whether it is serving, sealed or held, and the default of 0 is not always the replica the check is about.
- **5.4 c4:** `farcast storage seal "$INSTANCE" --hold --reason walk`. A's `keeper run --once` reports the hold. Then, as A:
  - `asA FARCAST_WALK_PROBE=push FARCAST_WALK_INTENT=restart-reseed FARCAST_WALK_ORDINAL=0` → `409 operator-hold`;
  - `asA FARCAST_WALK_PROBE=release-hold FARCAST_WALK_ORDINAL=0`, `asA FARCAST_WALK_PROBE=seal FARCAST_WALK_HOLD=1 FARCAST_WALK_ORDINAL=1` and `asA FARCAST_WALK_PROBE=push FARCAST_WALK_INTENT=operator-unseal FARCAST_WALK_ORDINAL=0` → each `403 permission`;
  - `farcast storage state`: both replicas still held, with the reason `walk`.
- **5.4 c6:** `farcast storage unseal` releases the hold — an operator push, which also moves every replica one generation past A's bundle, so from here A can re-seed only a replica that restarted (a restart resets the generation to 0).
  - `asA FARCAST_WALK_PROBE=push FARCAST_WALK_INTENT=restart-reseed FARCAST_WALK_ORDINAL=1` → `409 already-serving`.
  - The double re-seed: `kubectl -n farcast-system delete pod datasphered-0`; `farcast storage state` until replica 0 reads `restart-sealed`; A's `keeper run --once` re-seeds it. Seal that replica alone, with no hold and no restart — `probe FARCAST_WALK_PROBE=seal FARCAST_WALK_ORDINAL=0` (the operator's leaf) — and A's `keeper run --once` re-seeds it again. A's `keeper status` shows `1 PROCESS(ES) RE-SEEDED MORE THAN ONCE`. Replica 1 serves throughout.
- **The leaf binds the bundle:** `probe FARCAST_WALK_PROBE=seal FARCAST_WALK_ORDINAL=0` again, and do not run A's keeper until this check is done. `probe FARCAST_WALK_PROBE=push FARCAST_WALK_LEAF=packet:a.packet FARCAST_WALK_PASSPHRASE_FILE=pass FARCAST_WALK_BUNDLE=keys:@live FARCAST_WALK_INTENT=restart-reseed FARCAST_WALK_ORDINAL=0` — A's leaf with the current keyring, a different bundle from A's — → `403 keeper-bundle`, and replica 0 stays sealed.
- **5.4 c5 and c9, the fleet:** enrol device B on the operator's machine with `--budget 1` (`--out "$WALK/b.packet" --passphrase-file "$WALK/pass"`) and `farcast keeper install "$WALK/b.packet" --passphrase-file "$WALK/pass"` there. `farcast keeper status` on the operator's machine lists A and B under *Enrolled from this machine*, each with `until <date>` and its budget, and `fleet budget: up to 9 reseeds per 30 days across 2 device(s)` — the two budgets read as one total.
- **The drop refusal, and the pin in front of it** — both pushes to replica 1, which is serving. A hand-over to a sealed replica answers `409 not-serving` before the pin is consulted, and `operator-unseal+below-pin` to a sealed replica is not refused at all: it would unseal it with the pre-S11 keyring.
  - `probe FARCAST_WALK_PROBE=push FARCAST_WALK_INTENT=hand-over FARCAST_WALK_BUNDLE=keys:keys.pre-S11.yaml FARCAST_WALK_ORDINAL=1` → `409 below-pin`: the pin requires the egress-demo scopes and is checked first.
  - The same push with `FARCAST_WALK_INTENT=operator-unseal+below-pin` — which skips the pin and nothing else — → `409 would-drop`.
  - `farcast storage state` still shows the egress-demo scopes on replica 1. (`farcast storage seal` then `farcast storage unseal` is the deliberate way past both refusals; nothing here takes it.)
- `farcast storage unseal` brings back replica 0, left sealed by the keeper-bundle check; `farcast storage state` shows both replicas serving before S14 begins.
- After the reboot (5.4 c8): A's `keeper status` shows its ledger and budget intact, 0600 files in a 0700 directory, and on macOS `tmutil isexcluded` holds.

**S14. 5.3 c14b, a write in flight across a rotation.**
1. Record `farcast storage key list`, and keep the keyring from before this rotation: `install -m 0600 "$KEYS/keys.yaml" "$WALK/keys.pre-rotate.yaml"`.
2. In alpha: `head -c 16777216 /dev/urandom >/tmp/b; sha256sum /tmp/b`, then the S7 PUT with `--limit-rate 64k --data-binary @/tmp/b` to `app/sdk-demo/alpha/inflight.bin`, in the background (about 256 s). Keep it at 16 MiB or less: the keyholder reads the body whole and requests only 128Mi.
3. While it runs: `farcast storage key rotate "$INSTANCE" -y`.
4. *Expect* 204; a GET from the Pod and `farcast storage cp "$INSTANCE:app/sdk-demo/alpha/inflight.bin" …` both match the sha256.
5. The object header's key ID equals alpha's pre-rotation KEK ID.

## Rotation, the pin, and teardown

**S15.** 5.4 c7, reordered.
- **7a.** `farcast keeper revoke "$INSTANCE" <A> -y`. Until a rotation, the revoked device still re-seeds while its bundle is current — and S16 shows what changes after one.
- **7b.** `kubectl -n farcast-system scale statefulset datasphered --replicas=1`. `storage state` shows `502` for replica 1; `rotate` exits non-zero ("the new keys are held by 1 of 2 replicas and in use on none, because 1 replica(s) did not take them"); `storage unseal` activates nothing. In `key list`, no **scope's** active (`*`) key changes and each scope gains one new unstarred key; the instance key space's own `*` does move to its new key, because that key space never enters the keyholder and is in use at once (rotate says so: "the instance key space's new key is in use here already").
- **7c.** Scale back to 2, so replica 1 is restart-sealed — `farcast storage state` shows it so, with replica 0 serving. `rotate` finishes and exits 0; it counts rather than names: `1 of 2 replicas write under the new keys (generation N); 1 sealed, and receive them on the next 'farcast storage unseal …'`, and its pin line ends `2 of 2 replicas enforce it now` (a sealed replica takes the pin live). `storage unseal`; `rotate` again — all replicas hold and write; `state` flags nothing, and `farcast storage state "$INSTANCE" -o json` shows `"pin_status":"current"` for every replica.
- **7d.** `farcast storage seal` without a hold. `rotate` stops at the held step ("every replica is sealed, so none holds them"), exits non-zero, and no scope's active key changes — each scope's new key is held, unstarred. Then `storage unseal`, **and `farcast storage key rotate "$INSTANCE" -y` again**: both replicas serve, so it finishes. Skip that second rotate and every scope keeps an unused key newer than the one it writes under: 7g's rekey refuses ("a rotation that did not finish") and 7h reads `hello`.
- **7e.** Scale to 1 and delete `datasphered-0`. `unseal` leaves replica 0 sealed and names `--unchecked`; `unseal --unchecked` unseals replica 0 and pushes nothing to replica 1. Scale to 2; `unseal`.
- **7f.** Save the live keyring and its hash first — `install -m 0600 "$KEYS/keys.yaml" "$WALK/keys.current.yaml"; shasum -a 256 "$KEYS/keys.yaml"` — then `cp "$WALK/keys.pre-rotate.yaml" "$KEYS/keys.yaml"`. With both replicas serving, `unseal` refuses before pushing anything: replica 0 holds keys this keyring lacks (the serving-replica comparison answers before the pin is consulted), and the ledger is unchanged. Restore with `cp "$WALK/keys.current.yaml" "$KEYS/keys.yaml"` and check the hash matches **before running any other farcast command** — a keyring replaced without that copy loses the post-rotation keys for good.
- **7g.** `farcast storage key rekey "$INSTANCE" -y` reports `rewritten > 0`. Nothing in 7a–7g trips the drop refusal.
- **7h.** `probe FARCAST_WALK_PROBE=open FARCAST_WALK_PACKET=a.packet FARCAST_WALK_PASSPHRASE_FILE=pass FARCAST_WALK_OBJECT=app/sdk-demo/alpha/hello` — `ErrUnknownKey`.

**S16. New: the key pin.**
1. `kubectl -n farcast-system get configmap datasphered-pin -o json`: the pin requires the post-rotation key IDs and retires the pre-rotation ones; no scope name appears anywhere in it. The StatefulSet did not roll when it changed (`kubectl -n farcast-system rollout history statefulset datasphered`).
2. `kubectl -n farcast-system delete pod -l app.kubernetes.io/name=datasphered` — nothing is left serving to compare against. `farcast storage state` until both read `restart-sealed`.
3. With the revoked packet: `asA FARCAST_WALK_PROBE=push FARCAST_WALK_INTENT=restart-reseed FARCAST_WALK_ORDINAL=0` → `409 below-pin`; the replica stays restart-sealed. (Before 2026-10-08 this re-seeded the old keys.)
4. The same packet's leaf with the current keyring as the bundle — `probe FARCAST_WALK_PROBE=push FARCAST_WALK_LEAF=packet:a.packet FARCAST_WALK_PASSPHRASE_FILE=pass FARCAST_WALK_BUNDLE=keys:@live FARCAST_WALK_INTENT=restart-reseed FARCAST_WALK_ORDINAL=0` → `403 keeper-bundle`. The two layers together: a stolen leaf can push only its own bundle, and the pin refuses that one now.
5. Re-enrol B — the device `rotate` listed; a revoked device is never listed — with the default budget: `farcast keeper enroll "$INSTANCE" <B> --out "$WALK/b2.packet" --passphrase-file "$WALK/pass"`, then `farcast keeper install "$WALK/b2.packet" --passphrase-file "$WALK/pass"`. B's `keeper run --once` re-seeds both replicas.
6. *Live raise:* seal replica 1 (`probe FARCAST_WALK_PROBE=seal FARCAST_WALK_ORDINAL=1`), rotate again; `probe FARCAST_WALK_PROBE=state` shows replica 1's pin raised to the new keys without a restart. Unseal.
7. *Re-arm:* delete the ConfigMap, then delete both Pods: `storage state` reports "none loaded"; `farcast storage key pin "$INSTANCE"` re-creates it and raises it live; `farcast storage state "$INSTANCE" -o json` shows `"pin_status":"current"` (and the human view no `key pin:` line). Then `farcast storage unseal`, so both replicas serve going into 8.
8. *Unreadable:* `kubectl -n farcast-system patch configmap datasphered-pin --type merge -p '{"data":{"pin":"{"}}'`, then delete **`datasphered-0`** — only a restarted Pod reads the pin again, so only replica 0 has the unreadable one; `storage state` until it reads `restart-sealed`.
   - `storage state` reports replica 0's pin unreadable.
   - B's `keeper run --once` refuses replica 0 locally, naming the unreadable pin.
   - `probe FARCAST_WALK_PROBE=push FARCAST_WALK_LEAF=packet:b2.packet FARCAST_WALK_BUNDLE=packet:b2.packet FARCAST_WALK_PASSPHRASE_FILE=pass FARCAST_WALK_INTENT=restart-reseed FARCAST_WALK_ORDINAL=0` → `409 pin-unreadable`. Leaf and bundle must be the same keeper's, or `keeper-bundle` answers first; and the ordinal must be the Pod deleted, because replica 1 still has a valid pin.
   - `farcast storage unseal` still unseals it; `farcast storage key pin` repairs it, live.
9. *Below the pin, deliberately:* `farcast storage seal "$INSTANCE"` first — `--below-pin` skips the pin and nothing else, so against serving replicas holding newer keys it is refused as behind them. Then the 7f save-and-swap to `$WALK/keys.pre-rotate.yaml`: plain `unseal` refuses as below the pin, naming `--below-pin`, with nothing pushed; `farcast storage unseal --below-pin` unseals, and `state` reports the replicas serving below their pin. Restore `$WALK/keys.current.yaml` and check its hash, then `farcast storage seal` and `farcast storage unseal` to put the replicas back on the current keys.

**S17.** 5.4 c9, after revocation: `keeper status` on the operator's machine lists A as `REVOKED` (no date, no budget — 7a) and B with `until <date>` and `budget 8 per 30 days`, and the fleet budget is B's alone: `fleet budget: up to 8 reseeds per 30 days across 1 device(s)`.
- **New: tunnel admission, part 2.** Write alpha's storage leaf from the `alpha-egress` Secret (`FARCAST_STORAGE_CLIENT_CERT` / `_KEY`) to 0600 files in `$WALK`; `probe FARCAST_WALK_PROBE=tunnel FARCAST_WALK_CERT=alpha.crt FARCAST_WALK_KEY=alpha.key` — refused at the handshake. Delete the files.
- A's keeper leaf (`probe FARCAST_WALK_PROBE=tunnel FARCAST_WALK_LEAF=packet:a.packet FARCAST_WALK_PASSPHRASE_FILE=pass`, A's packet from S11): the `datasphered` route opens; the `shrike` route answers `403` (`route shrike: REFUSED: … 403 Forbidden`). Exactly one of the two FatLine replicas carried the connection and logs it, so read both: `kubectl -n farcast-system logs -l app.kubernetes.io/name=fatline -c fatline --prefix --since=10m --tail=-1 | grep 'reason=role_refused'` shows one `kind=deny … host=shrike reason=role_refused`. `--tail=-1` matters: a selector read otherwise stops at ten lines a Pod.

**S18. The carrier, second half.** Lower the limit below the accrued total — edit `cost_limit.amount` in the instance's `metadata.yaml`, then `farcast kernel deploy "$INSTANCE" -y`. *Expect* applications stopped, `at the instance floor … still_burning_per_hour=0.0554 carrier_per_hour=0.0250` (Pods and carrier), and Service `fatline` still `LoadBalancer` with its forwarding rule in place.

**S19. New: release waits.** `time farcast release "$INSTANCE" --delete-data --yes`.
- It returns only after GKE reports the cluster gone; no `(deleted)` line before then, and the local record lasts until then.
- B, the keeper installed on this machine for this instance, is reported wiped (ledger kept); device A is named with `farcast keeper uninstall "$INSTANCE"` to run there — run it, and its `keeper status` shows the material wiped.
- Verify independently that clusters, buckets, registries, forwarding rules, addresses, target pools, disks and VMs are all zero.
- `rm -rf "$WALK"` — it holds keyring copies, packets and the passphrase.

---

## Recording the results

Per step: the command, what was expected, what was seen, and pass or fail. A failure is recorded as found — with the defect, its fix, and whether the fix was re-walked — exactly as the per-phase runbooks do. Phase 5 is closed when every row passes or carries a recorded reason it cannot, and PLAN.md says so.
