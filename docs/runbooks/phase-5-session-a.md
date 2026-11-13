# Phase 5 — Session A: the consolidated walk that closes it

One instance, one session, every Phase 5 criterion still open, and every check the 2026-10-08 work added. It replaces running the 5.2, 5.3 and 5.4 runbooks separately; each step names the criterion it answers, and the per-phase runbooks keep the reasoning behind each one.

**It is billable.** Expect about six hours and roughly $1 — the standing floor is about $0.106/hour — the five system Pods and the carrier at $0.0554/hour, plus the modelled cluster line — plus about six application Pods and four builds. Do not start it until the spend is approved.

**Keepers stay in `--once` mode for the whole session — never as a running daemon.** A running keeper re-seeds every restart-sealed replica, and most of the checks below need a replica to *stay* sealed until the step says otherwise.

Throughout: the operator's own gcloud configuration only, and `--credentials <service-account-key.json>` on every `farcast` command that takes it. No Application Default Credentials. Never paste a project id, bucket name, address or key into the results — `$INSTANCE` and placeholders only.

*Checked against the code on 2026-11-09, before the walk, in two passes: twenty-two places where following this runbook as written would have gone wrong — one of them a rotation left unfinished in 7d that broke 7g and 7h — are corrected below, and the one that was the code's (`keeper status` read no fleet budget total, 5.4 c9) is fixed.*

***Walked 2026-11-10** against instance `p5a`, with an Ubuntu VM as device A: every step from S0 to S19 ran, and every criterion passed or carries a recorded reason. **Phase 5 is closed.** The [results](#results--walked-2026-11-10) are at the end. The walk found eleven more places where this runbook was wrong: four in the setup notes, and one each in S0.4, S4, S12, S13, S14, S14.5 and S19. Each is corrected in place and marked 2026-11-10. None was a defect in the product, but two of them, S4's bucket grant and S19's `keeper uninstall`, concern commands that the CLI prints.*

*Rewritten 2026-11-13 for [ADR 0020](../adr/0020-instance-pki-ecdsa-p256.md) (enrolment by request), not yet walked. A keeper's key is now made on the device, and no request, packet or command carries it off the device (on a desktop it is still a 0600 file, not bound to hardware), so the packet carries a certificate and no key, and the probe can no longer present device A from its packet. Every dishonest-keeper check presents **walk keeper W** instead: a keeper enrolled by request into a scratch store on the operator's machine. W has `--budget 1` and never runs `keeper run`, so the fleet counts three devices and 10 reseeds in S13. The [results](#results--walked-2026-11-10) below stay the record of the 2026-11-10 walk, against the runbook as it was then.*

---

## The walk probe, and where scratch files live

Several checks need a client the CLI refuses to be — a keeper claiming to be the operator, a lost device pushing an old bundle, an application's leaf at the public tunnel. They use the build-tagged probe, which is Go in this repository and adds no tool to the operator's machine.

Set these once, in the shell you walk from, at the root of the checkout:

```bash
INSTANCE=<name>              # first: KEYS below expands it once, and S1 installs under this name
REPO=$PWD                    # the checkout: every farcast command runs from here
WALK=$(mktemp -d)            # 0700 and OUTSIDE the checkout: keyring copies, packets, the passphrase, leaves
STATE="${FARCAST_CONFIG_HOME:-$HOME/Library/Application Support/farcast}"   # the macOS default; on Linux, ${XDG_CONFIG_HOME:-$HOME/.config}/farcast
export KUBECONFIG="$STATE/instances/$INSTANCE/kubeconfig.yaml"             # S1 writes it; never the default kubeconfig
# the probe, built ONCE at a fixed path — see the note below
go test -C "$REPO" -mod=vendor -tags walk -c -o "$WALK/walkprobe.test" ./farsight/cli/internal/cli/
probe() { (cd "$WALK" && env FARCAST_WALK=1 FARCAST_WALK_INSTANCE="$INSTANCE" FARCAST_WALK_CWD="$WALK" "$@" \
  "$WALK/walkprobe.test" -test.run '^TestWalkProbe$' -test.v -test.count=1); }
# walk keeper W: a keeper enrolled by request into a scratch config directory on THIS machine (S9)
WKEEP="$WALK/walk-keeper"                      # W's FARCAST_CONFIG_HOME
W_STORE="$WKEEP/keepers/$INSTANCE"            # W's keeper directory: its key, leaf and bundle
# W as itself — its own leaf AND its own bundle; any other bundle is refused as keeper-bundle first
asW() { probe FARCAST_WALK_LEAF=store:"$W_STORE" FARCAST_WALK_BUNDLE=store:"$W_STORE" "$@"; }
KEYS="$STATE/instances/$INSTANCE/datasphere"   # the directory holding this machine's keys.yaml
```

Every relative path the probe is given resolves against `$WALK`, and every scratch file below is created there — never in the checkout. A file there is untracked key material one `git add -A` away from a pushed repository, and it makes any rebuild report `vcs.modified=true`. The passphrase file is `$WALK/pass`, 0600, written once by hand. W's store is in `$WALK` too, so S19's `rm -rf "$WALK"` takes W's key with it.

*(Corrected 2026-11-10. Four things about the operator's own machine, none of them FarCast's, each of which cost the walk time:)*
- **Build the probe once.** `go test` links a new binary at a new temporary path on every run. An outbound firewall that makes its rules per binary holds each new binary's connections while it waits for someone to answer. The walk's was Little Snitch, and others such as LuLu make their rules the same way. On the walk, every probe that dialled the tunnel waited inside the dial until its own five-minute deadline ran out. That happened with the operator's leaf as well as a keeper's, while `farcast` opened the same tunnel in half a second. With a fixed path, one rule is enough: `walkprobe.test` to the carrier's address on port 8443. S19's `rm -rf "$WALK"` deletes the binary.
- **`KUBECONFIG` is the instance's own.** The operator's default kubeconfig can hold other clusters, and every `kubectl` step here must reach this cluster and no other. The instance kubeconfig authenticates through `gke-gcloud-auth-plugin`, so it holds no secret and acts as whatever gcloud configuration is in force.
- **In zsh, brace every parameter that a colon follows: `"${INSTANCE}:app/…"`, never `"$INSTANCE:app/…"`.** zsh reads a colon and a letter after a bare parameter as a modifier. `:a` means "make absolute", `:t` means "tail", `:h` means "head", and so on. So `farcast storage ls "$INSTANCE:app/sdk-demo/alpha/"` receives a local path and refuses it. In [the 4.1 runbook](phase-4-1-validation.md), `system:serviceaccount:$NS:technocore` became a service account that does not exist, and every `can-i … no` check passed whatever the RBAC said. zsh is the default shell on macOS.
- **Reaching device A over SSH from a Mac.** macOS's Local Network privacy blocks an app's connections to the local network until that app is allowed. The walk saw `No route to host` from `nc` and `ssh -v`, and `Undefined error: 0` from `ssh-copy-id`, all while ARP already listed the device. Allow the terminal you walk from. A shell that another app starts may run as its own app bundle, and then that bundle needs its own switch.

Its header ([`walkprobe_test.go`](../../farsight/cli/internal/cli/walkprobe_test.go)) lists the probes and inputs: `FARCAST_WALK_LEAF` (`operator`, the default, or `store:<dir>`; `packet:<file>` was retired by ADR 0020, because a packet carries no private key), `FARCAST_WALK_BUNDLE` (`store:`, `packet:`, `keys:<file>`, `keys:@live` — this machine's current keyring), `FARCAST_WALK_INTENT`, `FARCAST_WALK_ORDINAL` (default 0), `FARCAST_WALK_GENERATION`, `FARCAST_WALK_HOLD=1` to make `seal` a hold, `FARCAST_WALK_PASSPHRASE_FILE`, `FARCAST_WALK_CERT`/`_KEY` for `tunnel` (or, without them, the leaf `FARCAST_WALK_LEAF` names), `FARCAST_WALK_PACKET` and `FARCAST_WALK_OBJECT` for `packet` and `open`, and `FARCAST_WALK_KEY_SHA256` and `FARCAST_WALK_SCAN` for `keyscan`. Every `push` needs a `FARCAST_WALK_BUNDLE`. It prints key IDs and fingerprints, and never key material. The probe runs only on the operator's machine. FarCast never carries device A's key off A — that is ADR 0020's point — so A runs only its own `keeper run --once`, and every check that needs a dishonest keeper presents **walk keeper W** (`asW`, or `store:"$W_STORE"`), a keeper enrolled by request into a scratch store on the operator's machine (S9).

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
4. The second machine: the keeper binary only, cross-compiled from the same commit **into `$WALK`, not `./bin`** (a Linux build there would replace the operator's own binary): `GOOS=linux GOARCH=<arch> go build -o "$WALK/device/farcast" ./farsight/cli/cmd/farcast`. For a Mac, copy `./bin/farcast`. *(2026-11-10: this was fixed at `amd64`. Pick `<arch>` from `uname -m` on the device: `x86_64` means `amd64`, and `aarch64` or `arm64` means `arm64`. A virtual machine on Apple silicon is `aarch64`. Check `farcast version` and the sha256 on the device against the build.)* Copy it with `scp` and put it on A's `PATH` as `farcast` — the steps below type `farcast keeper …` on A. No `~/.kube`, no gcloud, no key file, no farcast config directory.
5. Every keeper enrolled before 2026-10-08 is dead to the new image: keeper leaves now bind their bundle, and one that binds none is refused. Nothing to do — this session enrols fresh ones.

## Bring-up

**S1.** `farcast install --name "$INSTANCE" --cost-limit 100 --region us-central1` — the name from the setup block, so `$KEYS` points at this instance's keyring. *Expect* no below-floor warning (the floor is about USD 77.42, and the limit clears it — install prints the floor only when it does not) and no region warning.

**S2.** `farcast connect`. *Tunnel admission, part 1:* `farcast connect "$INSTANCE" --status` connects; a request with no client certificate is refused at the handshake (the phase-2 B4 check).
- **New (ADR 0020): the system curl with the operator's P-256 leaf.** Attempted and recorded either way — macOS's `/usr/bin/curl` (LibreSSL) could not load the Ed25519 leaf this used to be. Set `LB` to the address and port `connect --status` prints, then:
  ```bash
  F="$STATE/instances/$INSTANCE/fatline"
  /usr/bin/curl --cert "$F/client.crt" --key "$F/client.key" --cacert "$F/ca.crt" \
    --connect-to "$INSTANCE.fatline.farcast:8443:$LB" "https://$INSTANCE.fatline.farcast:8443/_fatline/status"
  ```
  Record what it answers. FatLine's status, or a TLS error naming the client certificate, are both results. The second answers ADR 0020's Consequences ("curl may work again", to be confirmed on the next walk, not assumed) in the negative; it is not a failure of this step, and `/usr/bin/curl`'s LibreSSL is not macOS's platform TLS stack, which FarSightKit's regression tests.

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

*(2026-11-10: until the grant lands, the replicas crash-loop on a 403 for the bucket, and they start sealed within seconds of it. The printed grant uses `gcloud storage buckets add-iam-policy-binding`. A gcloud whose bundled Python cannot load the `storage` command group crashes before it changes anything; the walk's did, with `ssl.PROTOCOL_TLSv1` under Python 3.14. In that case, apply the same two bucket-level bindings through the Storage JSON API: GET `storage/v1/b/<bucket>/iam`, add `roles/storage.objectAdmin` and `roles/storage.legacyBucketReader` for the printed principal, and PUT the policy back with its `etag`.)*
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

**S9.** Enrol device A for 5.4 c1 and c2, by request ([ADR 0020](../adr/0020-instance-pki-ecdsa-p256.md) decision 3). *(Rewritten 2026-11-13.)*
1. **On A:** `farcast keeper request "$INSTANCE" --out a.csr` — on Linux, refused first without `--accept-backup-risk` (the key is never made there), then accepted with it. Record the fingerprint it prints, two lines of eight groups, from A's screen. Carry `a.csr` to `$WALK/a.csr`.
2. **On the operator's machine,** first with a wrong fingerprint — any other 64 hex characters: `farcast keeper enroll "$INSTANCE" <A> --request "$WALK/a.csr" --key-sha256 <not A's> --budget 8 --out "$WALK/a.packet" --passphrase-file "$WALK/pass"` → refused, "the request's key is not the one --key-sha256 names; nothing was issued", no `a.packet`, and nothing of A's fingerprint on the screen. Then with A's:
   ```bash
   farcast keeper enroll "$INSTANCE" <A> --request "$WALK/a.csr" --key-sha256 <A's fingerprint> --budget 8 --out "$WALK/a.packet" --passphrase-file "$WALK/pass"
   ```
   It prints the fingerprint, "confirmed against <A>".
3. Copy `a.packet` and `pass` to A. On A: `farcast keeper install a.packet --passphrase-file pass` (with `--accept-backup-risk` on Linux). **Then `rm a.packet pass a.csr` on A:** `install` leaves them where they were, outside the 0700, backup-excluded keeper directory, and the packet is A's bundle with its passphrase beside it. The operator's copies in `$WALK` stay.
4. **Walk keeper W, on the operator's machine** — the keeper every dishonest-keeper check below presents:
   ```bash
   FARCAST_CONFIG_HOME="$WKEEP" farcast keeper request "$INSTANCE" --out "$WALK/w.csr"
   farcast keeper enroll "$INSTANCE" walk --request "$WALK/w.csr" --key-sha256 <W's fingerprint> --budget 1 --out "$WALK/w.packet" --passphrase-file "$WALK/pass"
   FARCAST_CONFIG_HOME="$WKEEP" farcast keeper install "$WALK/w.packet" --passphrase-file "$WALK/pass"
   ```
   W never runs `keeper run`.

New checks (ADR 0020):
- **(a) A key is certified once.** `farcast keeper enroll "$INSTANCE" <A> --request "$WALK/w.csr" --key-sha256 <W's fingerprint> --out "$WALK/x.packet" --passphrase-file "$WALK/pass"` → refused, "this key is already certified for $INSTANCE/walk", and no `x.packet`.
- **(b) The packet carries no key.** `probe FARCAST_WALK_PROBE=packet FARCAST_WALK_PACKET=a.packet FARCAST_WALK_PASSPHRASE_FILE=pass` → `packet version 2`, "the packet carries no private key", `leaf certifies key <…>` equal to the fingerprint A printed, two leaf URIs (the device, then `urn:farcast:keeper-bundle:sha256:…`), "the leaf binds the bundle it carries", no master key ID.
- **(c) No PEM file under `$HOME` or `$TMPDIR` holds A's key.** `probe FARCAST_WALK_PROBE=keyscan FARCAST_WALK_KEY_SHA256=<A's fingerprint> FARCAST_WALK_SCAN="$HOME:$TMPDIR"` → `scanned N files (skipped M: …), found K private keys, none certifies <A's last four groups>`. Record N, M and K with the result. Among the K are this instance's `ca.key`, `client.key` and `server.key` under `$STATE`, and W's `leaf.key` under `$WALK` (which `mktemp -d` made under `$TMPDIR`); none matches A's. The scan's limits are part of the result: it reads PEM text in readable regular files of 1 MiB or less (so `walkprobe.test` itself is among the skipped), follows no symlink, and does not see a key embedded as escaped text in JSON or YAML (the checkout's PKI vectors are such), archived or encrypted. It can take some minutes. macOS may ask whether `walkprobe.test` may read Desktop, Documents, Downloads and other protected folders; allow it for this check, or deny and record that those folders were skipped (the line counts what it skipped).
- **(d) A certificate for another key is a security event.** Copy `$WALK/w.packet` and `pass` to A. On A: `farcast keeper install w.packet --passphrase-file pass` → refused: "security event: the certificate in this packet certifies key …, which this device does not hold", naming A's own key and `farcast keeper revoke`. A's keeper directory is unchanged (`ls -l` and `sha256sum` of its files, before and after). Then `rm w.packet pass` on A.
- Inventory the device (5.4 c2): the keeper binary and the keeper directory, and no credentials, packet, passphrase, request or other state. Inside the keeper directory, no `request.key` or `request.yaml` after install: the key moved to `leaf.key`.

**S10.** 5.4 c3: `kubectl -n farcast-system delete pod datasphered-0`, then `farcast storage state "$INSTANCE"` until replica 0 reads `restart-sealed` — not unreachable. On A, `farcast keeper run "$INSTANCE" --once` re-seeds it (`replica 0: re-seeded …`). Alpha's restart count stays 0. A `replica 0: unreachable` means the Pod was not back yet: run it again — an unreachable pass writes no ledger line and spends no budget.

## Keepers, egress, and adapting

**S11. Keepers refuse after a `run` that mints a scope.**
1. `install -m 0600 "$KEYS/keys.yaml" "$WALK/keys.pre-S11.yaml"` — the keyring before the new scopes.
2. `farcast run` egress-demo. This also covers 4.4 steps 2–8 and 5.1 c13; `farcast usage` names Shrike's Pod.
3. `run` printed the re-enrol list.
4. `kubectl -n farcast-system delete pod datasphered-0`, then `farcast storage state` until replica 0 reads `restart-sealed`.
5. On A, `keeper run --once` reports `stale-bundle`, naming the key pin; the ledger line count is unchanged and replica 0 stays restart-sealed.
6. `farcast storage unseal` recovers it.
7. Re-enrol A and W by request, at the same packet paths — `enroll` never overwrites, and every later step reads `a.packet` and W's store as current: `rm "$WALK/a.packet" "$WALK/w.packet"` first. *(Rewritten 2026-11-13: a re-enrolment is a new key, from a new request.)*
   - On A: `farcast keeper request "$INSTANCE" --out a2.csr` (with `--accept-backup-risk` on Linux) — a renewal beside the installed key; record its fingerprint and carry `a2.csr` to `$WALK/a2.csr`. Then `farcast keeper enroll "$INSTANCE" <A> --request "$WALK/a2.csr" --key-sha256 <A's new fingerprint> --budget 8 --out "$WALK/a.packet" --passphrase-file "$WALK/pass"` (same device name). Copy `a.packet` and `pass` to A, `farcast keeper install a.packet --passphrase-file pass` (with `--accept-backup-risk` on Linux), and `rm a.packet pass a2.csr` on A again.
   - W: `FARCAST_CONFIG_HOME="$WKEEP" farcast keeper request "$INSTANCE" --out "$WALK/w2.csr"`, `farcast keeper enroll "$INSTANCE" walk --request "$WALK/w2.csr" --key-sha256 <W's new fingerprint> --budget 1 --out "$WALK/w.packet" --passphrase-file "$WALK/pass"`, and `FARCAST_CONFIG_HOME="$WKEEP" farcast keeper install "$WALK/w.packet" --passphrase-file "$WALK/pass"`.
   - The ledger is kept: A's `keeper status` still counts the S10 re-seed.

**S12.** 5.2 c9–c12, about 25 minutes after S7, once beta has 120 readings.
- `farcast kernel deploy "$INSTANCE" --adapt --adapt-cooldown=2m`. The 10 s interval from S8 is carried forward — visible in the Pod's arguments without being named again.
- Exactly one beta resize, 100m/128Mi to 50m/64Mi, with `monthly_delta=-5.5434` (three Pods at -1.8478 each).
- At least three cooldowns (six minutes and more) with no second `resized` line, no `0.0000`, and the stored requests equal to `to=`. Beta has two ReplicaSets.
- Then `farcast kernel deploy "$INSTANCE" --adapt=false`, before alpha reaches coverage (about 60 minutes after S7).
- *(2026-11-10: that window is real. The walk reached S12 about 105 minutes after S7, after a pause, and alpha had qualified as well. It was resized beside beta (`monthly_delta=-1.8478`), and neither application was resized a second time. If S12 starts more than about an hour after S7, expect one resize per application and check each for the single resize. Apps deployed in S11 reach coverage about an hour after S11, which is the deadline for `--adapt=false`.)*
- Reboot device A now (5.4 c8).

**S13. Holds, solicitation, budget, and the drop refusal.** Every probe push here sets `FARCAST_WALK_ORDINAL` explicitly: what a replica answers depends on whether it is serving, sealed or held, and the default of 0 is not always the replica the check is about.
- **5.4 c4:** `farcast storage seal "$INSTANCE" --hold --reason walk`. A's `keeper run --once` reports the hold. Then, as walk keeper W — a keeper's leaf, presented by a client that does not refuse first:
  - `asW FARCAST_WALK_PROBE=push FARCAST_WALK_INTENT=restart-reseed FARCAST_WALK_ORDINAL=0` → `409 operator-hold`;
  - `asW FARCAST_WALK_PROBE=release-hold FARCAST_WALK_ORDINAL=0`, `asW FARCAST_WALK_PROBE=seal FARCAST_WALK_HOLD=1 FARCAST_WALK_ORDINAL=1` and `asW FARCAST_WALK_PROBE=push FARCAST_WALK_INTENT=operator-unseal FARCAST_WALK_ORDINAL=0` → each `403 permission`;
  - `farcast storage state`: both replicas still held, with the reason `walk`.
- **5.4 c6:** `farcast storage unseal` releases the hold — an operator push, which also moves every replica one generation past the keepers' bundles, so from here a keeper can re-seed only a replica that restarted (a restart resets the generation to 0).
  - `asW FARCAST_WALK_PROBE=push FARCAST_WALK_INTENT=restart-reseed FARCAST_WALK_ORDINAL=1` → `409 already-serving`.
  - The double re-seed: `kubectl -n farcast-system delete pod datasphered-0`; `farcast storage state` until replica 0 reads `restart-sealed`; A's `keeper run --once` re-seeds it. Seal that replica alone, with no hold and no restart — `probe FARCAST_WALK_PROBE=seal FARCAST_WALK_ORDINAL=0` (the operator's leaf) — and A's `keeper run --once` re-seeds it again. A's `keeper status` shows `1 PROCESS(ES) RE-SEEDED MORE THAN ONCE`. Replica 1 serves throughout.
- **The leaf binds the bundle:** `probe FARCAST_WALK_PROBE=seal FARCAST_WALK_ORDINAL=0` again, and do not run A's keeper until this check is done. `probe FARCAST_WALK_PROBE=push FARCAST_WALK_LEAF=store:"$W_STORE" FARCAST_WALK_BUNDLE=keys:@live FARCAST_WALK_INTENT=restart-reseed FARCAST_WALK_ORDINAL=0` — W's leaf with the current keyring, a different bundle from W's — → `403 keeper-bundle`, and replica 0 stays sealed.
- **5.4 c9, the fleet:** *(2026-11-10: this was labelled "c5 and c9". 5.4's c5 is the exhausted budget, which passed on 2026-10-06. Nothing here exhausts one: B's `--budget 1` only makes the total, and S16.5 re-enrols B before it ever pushes.)* Enrol device B, the operator's machine itself, by request: `farcast keeper request "$INSTANCE" --out "$WALK/b.csr"`, then `farcast keeper enroll "$INSTANCE" <B> --request "$WALK/b.csr" --key-sha256 <B's fingerprint> --budget 1 --out "$WALK/b.packet" --passphrase-file "$WALK/pass"`, and `farcast keeper install "$WALK/b.packet" --passphrase-file "$WALK/pass"` there. `farcast keeper status` on the operator's machine lists A, `walk` and B under *Enrolled from this machine*, each with `until <date>` and its budget, and `fleet budget: up to 10 reseeds per 30 days across 3 device(s)` — A's 8, W's 1 and B's 1 read as one total.
- **The drop refusal, and the pin in front of it** — both pushes to replica 1, which is serving. A hand-over to a sealed replica answers `409 not-serving` before the pin is consulted, and `operator-unseal+below-pin` to a sealed replica is not refused at all: it would unseal it with the pre-S11 keyring.
  - `probe FARCAST_WALK_PROBE=push FARCAST_WALK_INTENT=hand-over FARCAST_WALK_BUNDLE=keys:keys.pre-S11.yaml FARCAST_WALK_ORDINAL=1` → `409 below-pin`: the pin requires the egress-demo scopes and is checked first.
  - The same push with `FARCAST_WALK_INTENT=operator-unseal+below-pin` — which skips the pin and nothing else — → `409 would-drop`.
  - `farcast storage state` still shows the egress-demo scopes on replica 1. (`farcast storage seal` then `farcast storage unseal` is the deliberate way past both refusals; nothing here takes it.)
- `farcast storage unseal` brings back replica 0, left sealed by the keeper-bundle check; `farcast storage state` shows both replicas serving before S14 begins.
- After the reboot (5.4 c8): A's `keeper status` shows its ledger and budget intact, 0600 files in a 0700 directory, and on macOS `tmutil isexcluded` holds.

**S14. 5.3 c14, a write in flight across a rotation.** *(2026-11-10: this was labelled "c14b". In the 5.3 runbook, 14b is the sealed deploy, a different check.)*
1. Record `farcast storage key list`, and keep the keyring from before this rotation: `install -m 0600 "$KEYS/keys.yaml" "$WALK/keys.pre-rotate.yaml"`.
2. In alpha: `head -c 16777216 /dev/urandom >/tmp/b; sha256sum /tmp/b`, then the S7 PUT with `--limit-rate 64k --data-binary @/tmp/b` to `app/sdk-demo/alpha/inflight.bin`, in the background (about 256 s). Keep it at 16 MiB or less: the keyholder reads the body whole and requests only 128Mi.
3. While it runs: `farcast storage key rotate "$INSTANCE" -y`.
4. *Expect* 204; a GET from the Pod and `farcast storage cp "${INSTANCE}:app/sdk-demo/alpha/inflight.bin" …` both match the sha256. Use the braces, which zsh needs (see the setup notes).
5. The object header's key ID equals alpha's pre-rotation KEK ID. *(2026-11-10: read it from the bucket. In every format version, bytes 5–12 of a blob are the KEK ID ([blob layout](../../datasphere/docs/blob-format.md#blob-layout)). List the bucket and pick the one object of about 16 MiB by its size: its opaque name comes from the listing and is never derived from the logical key. Then read its first 13 bytes (`?alt=media` with `Range: bytes=0-12` on the Storage JSON API). They show `FCDS`, the version byte and the key ID. That needs no decryption, and it is the cloud's own view of the object.)*

## Rotation, the pin, and teardown

**S15.** 5.4 c7, reordered.
- **7a.** `farcast keeper revoke "$INSTANCE" <A> -y`, and `farcast keeper revoke "$INSTANCE" walk -y`. Until a rotation, a revoked device still re-seeds while its bundle is current — and S16 shows what changes after one. Every key each was certified for is now recorded as revoked, and stays refused.
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
3. With revoked W: `asW FARCAST_WALK_PROBE=push FARCAST_WALK_INTENT=restart-reseed FARCAST_WALK_ORDINAL=0` → `409 below-pin`; the replica stays restart-sealed. (Before 2026-10-08 this re-seeded the old keys.)
4. W's leaf with the current keyring as the bundle — `probe FARCAST_WALK_PROBE=push FARCAST_WALK_LEAF=store:"$W_STORE" FARCAST_WALK_BUNDLE=keys:@live FARCAST_WALK_INTENT=restart-reseed FARCAST_WALK_ORDINAL=0` → `403 keeper-bundle`. The two layers together: a stolen leaf can push only its own bundle, and the pin refuses that one now.
5. Re-enrol B — the device `rotate` listed; a revoked device is never listed — by request, with the default budget: `farcast keeper request "$INSTANCE" --out "$WALK/b2.csr"`, `farcast keeper enroll "$INSTANCE" <B> --request "$WALK/b2.csr" --key-sha256 <B's new fingerprint> --out "$WALK/b2.packet" --passphrase-file "$WALK/pass"`, then `farcast keeper install "$WALK/b2.packet" --passphrase-file "$WALK/pass"`. B's `keeper run --once` re-seeds both replicas.
6. *Live raise:* seal replica 1 (`probe FARCAST_WALK_PROBE=seal FARCAST_WALK_ORDINAL=1`), rotate again; `probe FARCAST_WALK_PROBE=state` shows replica 1's pin raised to the new keys without a restart. Unseal.
7. *Re-arm:* delete the ConfigMap, then delete both Pods: `storage state` reports "none loaded"; `farcast storage key pin "$INSTANCE"` re-creates it and raises it live; `farcast storage state "$INSTANCE" -o json` shows `"pin_status":"current"` (and the human view no `key pin:` line). Then `farcast storage unseal`, so both replicas serve going into 8.
8. *Unreadable:* `kubectl -n farcast-system patch configmap datasphered-pin --type merge -p '{"data":{"pin":"{"}}'`, then delete **`datasphered-0`** — only a restarted Pod reads the pin again, so only replica 0 has the unreadable one; `storage state` until it reads `restart-sealed`.
   - `storage state` reports replica 0's pin unreadable.
   - B's `keeper run --once` refuses replica 0 locally, naming the unreadable pin.
   - `probe FARCAST_WALK_PROBE=push FARCAST_WALK_LEAF=store:"$STATE/keepers/$INSTANCE" FARCAST_WALK_BUNDLE=store:"$STATE/keepers/$INSTANCE" FARCAST_WALK_INTENT=restart-reseed FARCAST_WALK_ORDINAL=0` — B's own store on this machine → `409 pin-unreadable`. Leaf and bundle must be the same keeper's, or `keeper-bundle` answers first; and the ordinal must be the Pod deleted, because replica 1 still has a valid pin.
   - `farcast storage unseal` still unseals it; `farcast storage key pin` repairs it, live.
9. *Below the pin, deliberately:* `farcast storage seal "$INSTANCE"` first — `--below-pin` skips the pin and nothing else, so against serving replicas holding newer keys it is refused as behind them. Then the 7f save-and-swap to `$WALK/keys.pre-rotate.yaml`: plain `unseal` refuses as below the pin, naming `--below-pin`, with nothing pushed; `farcast storage unseal --below-pin` unseals, and `state` reports the replicas serving below their pin. Restore `$WALK/keys.current.yaml` and check its hash, then `farcast storage seal` and `farcast storage unseal` to put the replicas back on the current keys.

**S17.** 5.4 c9, after revocation: `keeper status` on the operator's machine lists A and `walk` as `REVOKED` (no date, no budget — 7a) and B with `until <date>` and `budget 8 per 30 days`, and the fleet budget is B's alone: `fleet budget: up to 8 reseeds per 30 days across 1 device(s)`.
- **New: tunnel admission, part 2.** Write alpha's storage leaf from the `alpha-egress` Secret (`FARCAST_STORAGE_CLIENT_CERT` / `_KEY`) to 0600 files in `$WALK`; `probe FARCAST_WALK_PROBE=tunnel FARCAST_WALK_CERT=alpha.crt FARCAST_WALK_KEY=alpha.key` — refused at the handshake. Delete the files.
- W's keeper leaf (`probe FARCAST_WALK_PROBE=tunnel FARCAST_WALK_LEAF=store:"$W_STORE"`, W's store from S11.7; revoked, and revoke does not reach the cluster): the `datasphered` route opens; the `shrike` route answers `403` (`route shrike: REFUSED: … 403 Forbidden`). Exactly one of the two FatLine replicas carried the connection and logs it, so read both: `kubectl -n farcast-system logs -l app.kubernetes.io/name=fatline -c fatline --prefix --since=10m --tail=-1 | grep 'reason=role_refused'` shows one `kind=deny … host=shrike reason=role_refused`. `--tail=-1` matters: a selector read otherwise stops at ten lines a Pod.

**S18. The carrier, second half.** Lower the limit below the accrued total — edit `cost_limit.amount` in the instance's `metadata.yaml`, then `farcast kernel deploy "$INSTANCE" -y`. *Expect* applications stopped, `at the instance floor … still_burning_per_hour=0.0554 carrier_per_hour=0.0250` (Pods and carrier), and Service `fatline` still `LoadBalancer` with its forwarding rule in place.

**S19. New: release waits.** `time farcast release "$INSTANCE" --delete-data --yes`.
- It returns only after GKE reports the cluster gone; no `(deleted)` line before then, and the local record lasts until then.
- B, the keeper installed on this machine for this instance, is reported wiped (ledger kept); devices A and `walk` are named with `farcast keeper uninstall "$INSTANCE"` to run there — run it on A, and its `keeper status` shows the material wiped. *(2026-11-10: over SSH without a terminal, add `--yes`. The command asks for confirmation, and refuses when nothing can answer.)* For W: `FARCAST_CONFIG_HOME="$WKEEP" farcast keeper uninstall "$INSTANCE" --yes`.
- Verify independently that clusters, buckets, registries, forwarding rules, addresses, target pools, disks and VMs are all zero.
- `rm -rf "$WALK"` — it holds keyring copies, packets, requests, the passphrase and W's store.

---

## Recording the results

Per step: the command, what was expected, what was seen, and pass or fail. A failure is recorded as found — with the defect, its fix, and whether the fix was re-walked — exactly as the per-phase runbooks do. Phase 5 is closed when every row passes or carries a recorded reason it cannot, and PLAN.md says so.

---

## Results — walked 2026-11-10

**Walked against instance `p5a` on GKE Autopilot in `us-central1`, at commit `554d4df`, and released the same day.** Device A was an Ubuntu 26.04 LTS arm64 virtual machine. It held the keeper binary and nothing else, and was driven over SSH. Device B was the operator's own machine, as the runbook says. Install was at 11:18Z and release finished at 14:40Z: 3 h 22 m in all, of which about 80 minutes was a pause between S9 and S10 and about 25 went to the probe firewall described in the setup notes.

**Spending:** the kernel's `expected` read USD 0.23 at S18's floor, covering the Pods and the carrier. The cluster line that the kernel cannot meter adds a modelled USD 0.17 or so, for about USD 0.40 in total. `confirmed` never arrived before release.

**Teardown** was verified against the cloud APIs rather than local state. Clusters, buckets, registries, forwarding rules, addresses, target pools, backend services, health checks, instances, disks and routers were all zero, and the project's firewall rules and service accounts were exactly what they had been before S1.

**Every step ran, and every criterion passed or carries a recorded reason.** Four things departed from the runbook. Each is recorded under *Deviations* rather than smoothed over, and none turned a pass into a fail. S15 7b's message is the one expected output that was not seen. Several branches that this runbook never asks for are listed as unwalked under *Not walked*, so that "closed" does not quietly claim them.

| Step | What it answers | Result |
|---|---|---|
| S0 | check, push, binary, device | ✅ `./check.sh --model` passed at the walked commit (31 vendored modules, model passed). Device A was checked by version and sha256, and held no gcloud, kubectl, kubeconfig or farcast state |
| S1 | install | ✅ About four minutes, with no below-floor warning and no region warning |
| S2 | tunnel admission, part 1 | ✅ `connect --status` connects. curl with the CA and no client certificate fails with `sslv3 alert handshake failure` |
| S3 | toolchain and push grant | ✅ Tags refused with their digests; mirrored by digest and recorded. The grant is on the repository only, and the registry honoured it by the first build, about 11 minutes later |
| S4 | pin before the replicas; 3.2 c2/c3; 5.3 c15 | ✅ The pin is `{"version":1,"require":[],"retired":[]}`, with no scope name. No data endpoints while sealed, and the status endpoint answers. Unsealing the empty instance says "holding no application scopes" |
| S5 | `run` refuses without a kernel | ✅ It names `farcast kernel deploy`. No Job, no namespace, and `storage key list` is byte-identical |
| S6 | carrier metering | ✅ The kernel logs `carrier state=load-balancer per_hour=0.0250` and `rate_per_hour=0.0554 overhead_per_hour=0.0250`. At 6.5 minutes `costs` lists `carrier` under instance overhead and ends with *Not metered* |
| S7 | 5.3 c14a; pin raised before the hand-over; secrets; 3.2 crux; 5.3 c11/c12; status endpoint | ✅ One hand-over ledger entry per replica, with distinct boots, written before the application Pods started. The pin requires both new scopes' KEKs, and both replicas report `pin_status: current`. Secrets are picked up on the next read, with no restart. The crux object written in alpha reads back on the operator's machine. c11: `certificate required`, `http_code=000`. c12: alpha's PUT and GET of its own object and GET of its own secret are served. Its PUT under its own `secrets/` and DELETE of its own secret are refused `403 permission`. Every request for beta's objects is refused `403 permission`, including one that claims beta's scope. With both replicas sealed and no endpoints for 20 s, alpha reports `sealed` |
| S8 | 5.1 c12 | ✅ `unrefreshed=7` and `unrefreshed=9` between sampled ticks; about 2.0 samples per minute per Pod over 10 minutes, not 6 |
| S9 | 5.4 c1, c2 | ✅ The packet has two leaf URIs, "the leaf binds the bundle it carries", and no master key. The Linux install is refused without `--accept-backup-risk` and accepted with it. After `rm a.packet pass`, the device holds the keeper directory (0700, five 0600 files) and nothing else |
| S10 | 5.4 c3 | ✅ A re-seeded the restarted replica. Alpha had 0 restarts, and A's ledger counted 1 of 8 |
| S11 | refusal after a scope-minting `run`; 4.4 steps 2–8; 5.1 c13 | ✅ The re-enrol list was printed. A reported `stale-bundle` naming the pin, wrote no ledger line, and the replica stayed sealed. The unseal recovered it, and re-enrolling at the same path kept the ledger. 4.4: the policy holds hashes only (after correcting step 2's check, under *Deviations*). reacher reaches its host. The undeclared host and hermit get `403`, each logged by name with `not_in_allowlist`. A borrowed credential reaches the host, which is ADR 0013's stated consequence. No credential gets `407` and `unknown_app`. A grant took effect in 34 s and a revocation in 58 s, with the same FatLine Pods throughout. `farcast usage` names the FatLine replica whose Shrike it read |
| S12 | 5.2 c9–c12 | ✅ With deviation 1. Beta went from 100m/128Mi to 50m/64Mi with `monthly_delta=-5.5434`. Across four cooldowns and more there was no second resize and no `0.0000`; the stored requests equal `to=`, and there are two ReplicaSets. The interval carried forward without being named again. **This walks both of 5.2's live-found fixes** |
| S13 | 5.4 c4, c6, c8, c9; keeper-bundle; the drop refusal | ✅ A's keeper reported the hold. A's push got `409 operator-hold`, and its release, seal and operator-unseal each got `403 permission`. The operator's unseal released the hold, and A's re-seed of a serving replica got `409 already-serving`. The double re-seed was flagged `1 PROCESS(ES) RE-SEEDED MORE THAN ONCE`. A's leaf with another bundle got `403 keeper-bundle`. Fleet: "up to 9 reseeds per 30 days across 2 device(s)". The pre-S11 keyring got `409 below-pin`, then `409 would-drop` with the pin skipped. After a reboot, A's ledger, budget and 0600/0700 modes were intact |
| S14 | 5.3 c14, a write in flight | ✅ A 16 MiB write, throttled to 256 s, returned `204` across a rotation that finished mid-write. Both read paths match its sha256, and its blob header names alpha's pre-rotation KEK. After S15's rekey, the same header names alpha's current KEK |
| S15 | 5.4 c7, 7a–7h | ✅ With deviation 2 (the 7b message). 7c counts rather than names and ends "2 of 2 replicas enforce it now". 7d stops at the held step, and the second rotate finishes. 7e: `--unchecked` pushes nothing to the absent replica. 7f refuses before pushing, and the keyring was restored by hash. 7g: `rewritten: 5`. 7h: `ErrUnknownKey` |
| S16 | the key pin, 1–9 | ✅ The pin requires the active KEKs beyond the ones it retires, names no scope, and never rolled the StatefulSet. Revoked A got `409 below-pin`; A's leaf with the current keyring got `403 keeper-bundle`; B re-seeded both replicas. A sealed replica's pin was raised live without a restart. With the ConfigMap gone: "none loaded", re-armed live, then `current`. With the pin unreadable: `state` flags it, B refuses locally, the probe gets `409 pin-unreadable`, unseal still works, and `key pin` repairs it live. Below the pin: plain unseal refuses and names `--below-pin`; `--below-pin` unseals and `state` flags it; then restored |
| S17 | 5.4 c9 after revocation; tunnel admission, part 2 | ✅ A shows `REVOKED`; B shows `until` and `budget 8 per 30 days`; the fleet total is "up to 8 … across 1 device(s)". Alpha's storage leaf is refused at the handshake (`bad certificate`). A's keeper leaf opens `datasphered`, `shrike` answers `403`, and there is one `role_refused` line across both FatLine replicas |
| S18 | carrier, second half | ✅ Every application was stopped, highest cost first, then `at the instance floor … still_burning_per_hour=0.0554 carrier_per_hour=0.0250`. The Service is still `LoadBalancer`, with its forwarding rule in place |
| S19 | release waits | ✅ 6 m 07 s. The cluster read `RUNNING`, then `STOPPING` from about 20 s in until it was gone. The local record stayed until GKE reported the cluster gone, and "(deleted)" printed only after that. B was wiped with its ledger kept; A was named, and `keeper uninstall` wiped it. The cloud was verified empty and `$WALK` was removed |

### Deviations

1. **S12 resized alpha as well as beta.** The pause put S12 about 105 minutes after S7, by which time alpha had reached coverage too. Each application was resized once and neither twice, which is the property c9–c12 is about. The runbook now says what to expect in that case.
2. **S15 7b's rotate message was not captured.** The walker's own output filter used `\|`, which BSD `sed` does not support, and re-running `rotate` mints fresh keys, so it was not repeated. What was observed: exit status 1; a key list in which no scope's active key moved, each scope gained one unstarred key, and the instance key space's active key moved; and an unseal afterwards that activated nothing, leaving `storage key list` byte-identical.
3. **4.4 step 2's credential check could not fail.** Its `sed 's|.*:||; s|@.*||'` is greedy. It returns the proxy's *port*, `3128`, from `http://reacher:<credential>@fatline-egress…:3128`, so "0 occurrences" held whatever the ConfigMap contained, and the step also printed the credential. The corrected check found each application's 64-character credential 0 times in the policy, and each one's sha256 equal to its own `credential_sha256`. It is fixed in [the 4.4 runbook](phase-4-4-validation.md#2-the-policy-arrived-and-carries-no-credentials).
4. **The probe was rebuilt once at a fixed path** after it hung behind the operator's firewall. That is a property of the operator's machine (see the setup notes), not of the probe or the product.

### What the walk found

Nothing here failed a criterion. They are listed in rough order of weight. Each carries a dated note on what changed after the walk, and **none of those changes has been walked**: they are built and unit-tested only, and the next paid session walks them.

1. **FatLine's tunnel-stream decisions carry no peer identity.** In `farcast usage`, the operator's and keepers' mTLS streams to `datasphered` and `shrike` are counted as `(unidentified)`, the same bucket the report uses for anonymous in-cluster callers. S17's `role_refused` line for a keeper on the operator's route reads `tenant="" app=""`, so the log cannot say which device tried. FatLine has the leaf at that point, since a role refusal is decided from the role on it, but it does not record it. Until it does, Shrike cannot attribute a tunnel violation to a device.
   *Fixed 2026-11-10, not yet walked:* every stream event now carries the peer's role and an opaque per-leaf token. Logs name only the role. The token stays in Shrike's in-memory picture, which is read over the operator's route, and `farcast usage` maps it to a device in a new *Tunnel* section. The keyholder's refusal line no longer names the device. See [ADR 0015](../adr/0015-what-the-boundary-can-measure.md) decision 7. Keepers enrolled before the change read as "leaf not enrolled from this machine" until they are enrolled again.
2. **An Autopilot eviction put both keyholder replicas on the node that also held both FatLine replicas, and nothing moves them apart again.** FatLine's two replicas had shared a node since their first deploy, when the cluster had only one. About a minute after S7's hand-over, Autopilot evicted alpha and `datasphered-1` together and recreated both on the node that already ran `datasphered-0`. Replica 1 came back restart-sealed, and for the 55 s before the walk's own seal in S7 nothing reported that. Afterwards it shows only as a new boot label in the next unseal's ledger entry. The spread is `ScheduleAnyway` on purpose: a hard constraint can leave a replica Pending forever on Autopilot (the reasoning is in `datasphere/deploy`). But a soft constraint never rebalances. When placement was checked, at about 11:56Z, one node repair would have sealed storage and dropped the tunnel together. Placement was not checked again after the keyholder Pods were recreated in later steps. This is a gap against [ADR 0008](../adr/0008-in-cluster-key-delivery.md)'s case for a second replica, not a defect in the code as written.
   *Reported 2026-11-10, not yet walked, and not fixed:* each replica now reports its node on the mutual-TLS surface only. `farcast storage state` names replicas that share a node, and `connect --status` names the node of the FatLine replica that answered. Nothing moves replicas apart. That decision is left to a later ADR, which also holds the deferred hard spread for FatLine.
3. **The keeper's report misleads in three places.**
   - An unreadable pin is filed under `stale-bundle`, which sends the operator to re-enrol, the one remedy that changes nothing.
   - The fleet-wide pin verdict (`keeper.Pinned` in `farsight/cli/internal/keeper/decide.go`) is printed under each replica, so replica 1's line reads "replica 0's key pin refuses…".
   - `keeper run --once` exits 0 when it refused, so cron or systemd cannot tell "kept" from "can no longer keep".

   *Fixed 2026-11-10, not yet walked:*
   - An unreadable pin has its own label, `pin-unreadable`, which names `farcast storage key pin`.
   - The pin's verdict prints once per pass, as `this device: stale-bundle — …`. It prints even while every replica serves, so a keeper learns it is stale at the rotation rather than at the next restart.
   - `keeper run --once` exits 0 when it kept, 3 when a person must act, 4 when the pass did not finish and the next one retries (including when another keeper pass on the same device was running), and 1 on a fault on the device itself, including a ledger that will not take the entry a re-seed is recorded in before it is pushed (the re-seed is then not made). The running mode never exits on any of these. The exit codes are in the [CLI README](../../farsight/cli/README.md#what-a-pass-exits-with).
4. **`keeper revoke` overstates what remains.** It says the device can still re-seed a restarted replica with its old keys until its certificate expires. Since the pin, a rotation retires those keys, and S16.3 shows the refusal.
   *Fixed 2026-11-10, not yet walked:* `revoke` now says the device can re-seed only until `rotate` writes the instance's key pin. After that every replica refuses its bundle (`below-pin`), and a replica that starts without the pin checks nothing, which `storage state` reports as "none loaded".
5. **`farcast run -y` prints no declared host.** Its result reads "1 declared host across 2 applications", so an operator approving with `-y` never sees `example.com` in this output.
   *Fixed 2026-11-10, not yet walked:* `-y` now skips the question, not the review. The review goes to stderr with every host and its reason, and the result lists each application's hosts under the summary line. In `-o json`, `apps[].external` is now `[{host, reason}]` and is always present. Reasons and paths that carry terminal-control or bidirectional characters print quoted.
6. **Smaller, recorded:**
   - Durations print as `720h0m0s` beside `30 days`, and counts as "1 reseeds".
   - The key-loss warning is appended mid-paragraph, starting with a lowercase word.
   - `storage state` prints `scopes ` when there are none.
   - Re-creating a missing pin is reported as "raised".
   - A refused unseal reports "0 of 2 replicas … at generation 20".
   - `release` prints "device-a (revoked) still hold", and is silent through its six-minute wait.
   - FatLine's "egress policy reloaded" line has no timestamp, so per-replica propagation cannot be timed from the log.
   - An operator seal without a hold reports `restart-sealed`, although nothing restarted.
   - The egress fixture's `sh -c "… && sleep 86400"` ignores SIGTERM, so a stopped Pod bills through its 30-second grace period. That shows as three ticks at `pods=7` after S18's stop.
   - On a desktop Linux device, GNOME's file indexer indexes `~` without descending into it. So the packet's and passphrase's *file names* were indexable for as long as S9 left them there. The keeper directory, under `~/.config`, is not indexed.

   *Fixed 2026-11-10, not yet walked*, all ten:
   - Budgets read "1 reseed per 30 days". The JSON window stays a Go duration.
   - Counts agree with their nouns.
   - The key-loss warning always prints on its own `WARNING:` line.
   - `storage state` says "holding no application scopes".
   - A re-created pin reports that there was none.
   - A refused unseal prints no generation summary.
   - `release` reads "still holds" and prints a line about once a minute while it waits.
   - FatLine's and Shrike's reload lines are timestamped log records.
   - An operator seal without a hold says a keeper re-seeds that state.
   - Both idling fixtures stop on SIGTERM.
   - The GNOME indexer is answered with advice, not code: the keeper documentation says to write the packet and passphrase outside indexed directories.

### Found after the walk

7. **Every container's output reached the provider's logging, the applications' included.** After release, the project's Cloud Logging still held `k8s_container` entries from the walk, counted read-only and by number alone:
   - in `farcast-system`: FatLine 375, the kernel 493, `datasphered` 122 and Shrike 10;
   - in the application namespaces: alpha 250, beta 750, and the egress fixture 2.

   Planck created clusters with no logging configuration, so GKE's default applied, and that default sends every container's stdout and stderr to the provider. There the entries outlive the instance, for 30 days under the default retention. They included:
   - FatLine's per-application egress decisions;
   - the keyholder's refusals, which then named the keeper device;
   - anything an application writes with `farcast.Log()`.

   No criterion asked about this, which is why every row above still passes. It contradicts "blind to content" all the same, and it is the heaviest thing this walk turned up.

   *Fixed 2026-11-10, not yet walked:* [ADR 0019](../adr/0019-what-the-cluster-tells-its-provider.md).
   - Every cluster is created with system-only logging.
   - `install` fails unless the cluster reads back that way.
   - `release` names what the provider keeps after the instance is gone.

   Google's documentation disagrees with itself on whether Autopilot accepts system-only logging, so the next install is the test. If Autopilot refuses, install fails rather than running with workload logs on. The ADR also names what no setting turns off: system logs, Events, system metrics, and the Admin Activity audit log, kept 400 days. GKE's default metric packages are on too; turning them off is documented but untried, and an open decision (ADR 0019 decision 3). The audit log carries each workload's spec, and with it the repository and commit every build came from. And for 24 months by the metrics, and very likely 400 days by the audit log's endpoint updates, the provider can date when each keyholder replica was sealed and brought back to serving. The walk's own entries were not deleted. Under the default retention they expire around 2026-12-10.

### Not walked

These were built and unit-tested, and this walk did not exercise them. They are not counted as walked anywhere:
- The keeper's long-running mode (`keeper run` without `--once`, the same pass every 15 minutes). This runbook keeps keepers to `--once`, so every re-seed here was a single pass the walker started, not an unattended one.
- `farcast build`'s refusal without a kernel. S5 tried only `run`.
- `run` refusing a keyring from before per-application scopes.
- `release` when its wait runs out or is interrupted.
- `storage key pin --replace`.
- The hand-over's own refusal of a sealed replica, and the repeated-generation "retry" case it closes.
- 5.3 criterion 14b's sealed and held deploys under the hand-over as it now is.
- From the 2026-10-06 hardening:
  - keyring writes under their lock against a concurrent `run` or a second operator machine;
  - a merge refusing a scope minted twice;
  - the keeper refusing to re-seed beside a silent replica;
  - a lost answer being confirmed before a rotation is undone;
  - the keeper's comparison against a serving replica's keys. In every refusal on this walk the key pin answered first.
- 5.2's no-saving refusal and override warning. This walk saw only their absence: no `0.0000`, and no resize that was overridden.

**Closed elsewhere by this walk:**
- 5.1 c12, the reading-dedupe, exercised, and c13, `run` writing the policy the boundary enforces.
- 5.2's two live-found fixes.
- 5.3 c14, a hand-over with a write in flight.
- 5.4's second-machine criteria and its 2026-10-06 fixes.
- Phase 1.4's "release returns before the cluster is gone".

**Still open, and not inferred:** 4.1 c12, invoice reconciliation, because `confirmed` never arrived before release.

**Retired rather than walked:** 5.3 c13, a pre-upgrade application. Since 2026-10-08, `run` refuses the keyring that state needs, so no install can reach it.

### What the next walk owes this record

Each fix above carries "not yet walked" until a paid session walks it. Most of the fixes change the FatLine, Shrike and `datasphered` images, so they go out as one rollout with the operator present. Rolling the keyholder restarts both replicas sealed, and the operator has to unseal them. Before that session spends anything, it should check:
- **Logging (finding 7):**
  - `install` succeeds, and the cluster reads back system-only logging. If it fails instead, Autopilot has refused, and that is a decision for the operator before anything else runs.
  - Counted from install onwards, `farcast-system` and the application namespaces have no `k8s_container` entries.
  - `farcast logs` still works.
  - Work through all eight steps of [ADR 0019's Verification](../adr/0019-what-the-cluster-tells-its-provider.md#verification) and record each result. Steps 2 and 3 are the two bullets above. The rest:
    - Step 1: the logging and monitoring read-back, and that a kube state series (container readiness) exists for a `datasphered` replica;
    - Step 4: `farcast-system` and the application namespaces hold no `PodMonitoring`, and every `ClusterPodMonitoring` is recorded;
    - Step 5: an audit entry naming a FatLine or keyholder ConfigMap carries no request or response body;
    - Step 6: a `pods/status` entry for a `datasphered` replica and one for a fetch Pod, looked for in Admin Activity and, if it is on, Data Access;
    - Step 7: one build Job's create entry carries `--context=git://…#<commit>`;
    - Step 8: after a seal and the unseal that brings the replica back to serving, an Admin Activity `update` on the `datasphered` data Service's Endpoints and one on its EndpointSlice in `farcast-system`, with the level of each and what its body carries.
  - Before install, read-only: confirm that the project has no GKE Enterprise enablement or fleet registration (either could turn control-plane logs on and fail the strict read-back), and record its effective Data Access audit configuration, inherited settings included.
- **Peer identity (finding 1):**
  - Enrol the keeper devices again, so their tokens are recorded.
  - `farcast usage` names each keeper in its *Tunnel* section, including on the `role_refused` row.
  - FatLine's and `datasphered`'s logs hold no device name and no token, and the refusal line carries `peer_role=keeper`.
- **The keeper (findings 3 and 4):**
  - A replica the keeper cannot reach exits 4.
  - S11.5's stale bundle prints `this device: stale-bundle` once and exits 3.
  - S13's hold still exits 0.
  - S16.8's unreadable pin reads `pin-unreadable` and exits 3.
  - `revoke` shows the new text.
  - Any step run under `set -e` that expects a refusal must now tolerate exit 3.
  - After S10's re-seed, A's ledger gains two lines for that push: a `pending` line and an `ok` line carrying the same `push` id. `keeper status` on A, whose ledger mixes the walk's old single-line entries with the new two-line ones, shows no `unconfirmed` and no `after send` line.
  - A keeper push into a replica that is already serving (for example `keeper run --once` started just after `storage unseal` reached the restarted replica) is recorded as `refused-after-send`, spends one budget slot, and appears in `keeper status` as `after send 1`.
  - A second `keeper run --once` started while another pass on the same device runs exits 4 with `another keeper pass on this device is running` and adds no ledger line. Check this only if it can be timed; the unit tests cover it.
- **Placement (finding 2):** `storage state` shows a `node` on each replica and says whether replicas share one, and `connect --status` shows `relayed by`. Check the names once against the Pods' nodes.
- **`run -y` (finding 5):** 4.4 step 1 with `-y` shows the review and its hosts on stderr, and the result lists `reacher → example.com` and hermit reaching nothing.
- **The smaller items (finding 6):**
  - The reload lines carry timestamps.
  - Both fixtures leave at once on stop, with no ticks at the old Pod count.
  - `release -y` prints a line about once a minute.
- **[ADR 0020](../adr/0020-instance-pki-ecdsa-p256.md), enrolment by request (rewritten 2026-11-13, its Verification 3):**
  - S2's system curl with the operator's P-256 leaf: what it answered.
  - The key-absence checks: S9 (b), the packet carries no private key and certifies the key A printed; S9 (c), no PEM file under `$HOME` or `$TMPDIR` holds A's key, with the scan's counts (files, skipped, private keys).
  - The security-event install: S9 (d), W's packet refused on A with nothing changed.
  - The fingerprint refusals: S9.2's wrong `--key-sha256` issues nothing, and S9 (a) refuses W's key for A.
