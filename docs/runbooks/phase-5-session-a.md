# Phase 5 — Session A: the consolidated walk that closes it

One instance, one session, every Phase 5 criterion still open, and every check the 2026-10-08 work added. It replaces running the 5.2, 5.3 and 5.4 runbooks separately; each step names the criterion it answers, and the per-phase runbooks keep the reasoning behind each one.

**It is billable.** Expect about six hours and roughly $1 — the standing floor is about $0.106/hour — the five system Pods and the carrier at $0.0554/hour, plus the modelled cluster line — plus about six application Pods and four builds. Do not start it until the spend is approved.

**Keepers stay in `--once` mode for the whole session — never as a running daemon.** A running keeper re-seeds every restart-sealed replica, and most of the checks below need a replica to *stay* sealed until the step says otherwise.

Throughout: the operator's own gcloud configuration only, and `--credentials <service-account-key.json>` on every `farcast` command that takes it. No Application Default Credentials. Never paste a project id, bucket name, address or key into the results — `$INSTANCE` and placeholders only.

---

## The walk probe

Several checks need a client the CLI refuses to be — a keeper claiming to be the operator, a lost device pushing an old bundle, an application's leaf at the public tunnel. They use the build-tagged probe, which is Go in this repository and adds no tool to the operator's machine:

```bash
probe() { env FARCAST_WALK=1 FARCAST_WALK_INSTANCE="$INSTANCE" FARCAST_WALK_CWD="$PWD" "$@" \
  go test -mod=vendor -tags walk -count=1 -run TestWalkProbe -v ./farsight/cli/internal/cli/; }
# e.g. probe FARCAST_WALK_PROBE=state
KEYS="${FARCAST_CONFIG_HOME:-$HOME/Library/Application Support/farcast}/instances/$INSTANCE/datasphere"
# the directory holding this machine's keys.yaml — the macOS default; on Linux, ${XDG_CONFIG_HOME:-$HOME/.config}/farcast/…
```

`go test` runs the probe in the package's directory, so `probe` passes `FARCAST_WALK_CWD="$PWD"` and every relative path below is resolved against the directory you run from. `FARCAST_WALK_BUNDLE=keys:@live` is this machine's current keyring.

Its header ([`walkprobe_test.go`](../../farsight/cli/internal/cli/walkprobe_test.go)) lists the probes and inputs: `FARCAST_WALK_LEAF` (`operator`, `store:<dir>`, `packet:<file>`), `FARCAST_WALK_BUNDLE` (`store:`, `packet:`, `keys:<file>`, `keys:@live`), `FARCAST_WALK_INTENT`, `FARCAST_WALK_ORDINAL`, `FARCAST_WALK_GENERATION`, `FARCAST_WALK_PASSPHRASE_FILE`, `FARCAST_WALK_CERT`/`_KEY` for `tunnel` (or, without them, the leaf `FARCAST_WALK_LEAF` names), `FARCAST_WALK_PACKET` and `FARCAST_WALK_OBJECT` for `packet` and `open`. It prints key IDs and never key material.

---

## S0. Before the session

1. `./check.sh --model` passes at the commit being walked. Record the commit and the check's summary line.
2. The commit is pushed. `farcast run` clones the repository from GitHub, so a fixture or Containerfile change reaches the walk only once pushed (or with `--ref <pushed sha>`).
3. Build the binary from that clean checkout, and check it is that commit:
   ```bash
   go build -o ./bin/farcast ./farsight/cli/cmd/farcast
   ./bin/farcast version
   go version -m ./bin/farcast | grep -E 'vcs.revision|vcs.modified'   # vcs.modified=false
   ```
   Do not set `Version` with ldflags: it becomes the tag of every system image. Run every command from this checkout — the system images are compiled from it.
4. The second machine: the keeper binary only, cross-compiled from the same commit (`GOOS=linux GOARCH=amd64 go build -o bin/farcast-keeper ./farsight/cli/cmd/farcast`, or the native build for macOS, copied with `scp`). No `~/.kube`, no gcloud, no key file, no farcast config directory.
5. Every keeper enrolled before 2026-10-08 is dead to the new image: keeper leaves now bind their bundle, and one that binds none is refused. Nothing to do — this session enrols fresh ones.

## Bring-up

**S1.** `farcast install` with `--cost-limit 100` in `us-central1`. *Expect* no below-floor warning (the floor is about USD 77.42, and the limit clears it — install prints the floor only when it does not) and no region warning.

**S2.** `farcast connect`. *Tunnel admission, part 1:* `farcast connect "$INSTANCE" --status` connects; a request with no client certificate is refused at the handshake (the phase-2 B4 check).

**S3.** Mirror the toolchain and apply the builder's push grant **before** any build:
```bash
farcast toolchain "$INSTANCE" --builder gcr.io/kaniko-project/executor:v1.23.2 --fetcher cgr.dev/chainguard/git:latest-dev
# it refuses the tags and prints the digests; run it again with the @sha256: references
```

**S4.** `farcast storage deploy`, and the bucket grant it prints; wait for the grant to propagate.
- *Key pin created before the replicas:* `kubectl -n farcast-system get configmap datasphered-pin -o json` exists, its `pin` is `{"version":1,"require":[],"retired":[]}`, and it carries no scope name.
- 3.2 c2/c3: no data endpoints while sealed; the status endpoint answers.
- `farcast storage unseal` on the empty instance — *expect* "holding no application scopes: this instance has no applications yet" (5.3 c15).

**S5. New: `run` refuses without a kernel.** `farcast run "$INSTANCE" <repo> --manifest manifest/examples/sdk-demo/farcast` refuses, naming `farcast kernel deploy`. *Then:* no `fetch-*` Job in `farcast-system`, no `sdk-demo` namespace, and `farcast storage key list` unchanged.

**S6.** `farcast kernel deploy` with defaults. **New: carrier metering.**
- The kernel's log, while no fetch or build Job runs: `carrier state=load-balancer per_hour=0.0250`, then `reconciled … rate_per_hour=0.0554 overhead_per_hour=0.0250 carrier=load-balancer` (five system Pods 0.0304 plus the carrier).
- `farcast costs` shows `carrier` under *Instance overhead (never attributed to an application)*, and ends with the *Not metered* block.

## Applications, sealing, and the kernel

**S7.** `farcast run` sdk-demo.
- 5.3 c14a: the unseal ledger shows distinct boots.
- *Key pin raised before the hand-over:* the pin now requires the two new scopes' key IDs and retires nothing; `farcast storage state` reports each replica's pin `current`.
- Set the secrets: `farcast secret set "$INSTANCE" sdk-demo/alpha DB_PASSWORD` (and the rest from the 5.3 runbook). Quick regression of 5.3 c11/c12.
- The 3.2 crux, from inside alpha with its own leaf — the corrected step 5 of [the 3.2 runbook](phase-3-2-validation.md).
- Scale **beta** to 3 for 5.2 (`kubectl -n sdk-demo scale deploy/beta --replicas=3`), so alpha — the subject of S10 and S14 — is never rolled.
- **The status endpoint (fixed 2026-10-08):** `farcast storage seal "$INSTANCE"` (both replicas), wait at least 20 s with `kubectl -n farcast-system get endpoints datasphered` showing none, and alpha reports `sealed`, not unavailable. Then `farcast storage unseal`.

**S8.** `farcast kernel deploy "$INSTANCE" --interval=10s` (5.1 c12). Over ten minutes and more, `observed usage … unrefreshed=N` appears with N>0; `farcast usage -o json` sample counts grow about two a minute per Pod, not six.

**S9.** Enrol device A on the second machine with `--budget 8`; walk 5.4 c1 and c2.
- `probe FARCAST_WALK_PROBE=packet FARCAST_WALK_PACKET=a.packet FARCAST_WALK_PASSPHRASE_FILE=pass` — two leaf URIs (the device, then `urn:farcast:keeper-bundle:sha256:…`), "the leaf binds the bundle it carries", no master key ID.
- On Linux: `keeper install` without `--accept-backup-risk` is refused first, then succeeds with it. Inventory the device: no credentials and no other state.

**S10.** 5.4 c3: `kubectl -n farcast-system delete pod datasphered-0`; on A, `farcast keeper run "$INSTANCE" --once` re-seeds it. Alpha's restart count stays 0.

## Keepers, egress, and adapting

**S11. Keepers refuse after a `run` that mints a scope.**
1. `install -m 0600 "$KEYS/keys.yaml" ./keys.pre-S11.yaml` — a copy of the keyring before the new scopes, in the directory you run the probe from.
2. `farcast run` egress-demo. This also covers 4.4 steps 2–8 and 5.1 c13; `farcast usage` names Shrike's Pod.
3. `run` printed the re-enrol list.
4. `kubectl -n farcast-system delete pod datasphered-0`.
5. On A, `keeper run --once` reports `stale-bundle`, naming the key pin; the ledger line count is unchanged and replica 0 stays restart-sealed.
6. `farcast storage unseal` recovers it.
7. Re-enrol A (`keeper enroll` with the same device name, then `keeper install`); the ledger is kept.

**S12.** 5.2 c9–c12, about 25 minutes after S7, once beta has 120 readings.
- `farcast kernel deploy "$INSTANCE" --adapt --adapt-cooldown=2m`. The 10 s interval from S8 is carried forward — visible in the Pod's arguments without being named again.
- Exactly one beta resize, 100m/128Mi to 50m/64Mi, with `monthly_delta=-5.5434` (three Pods at -1.8478 each).
- At least three cooldowns (six minutes and more) with no second `resized` line, no `0.0000`, and the stored requests equal to `to=`. Beta has two ReplicaSets.
- Then `farcast kernel deploy "$INSTANCE" --adapt=false`, before alpha reaches coverage (about 60 minutes after S7).
- Reboot device A now (5.4 c8).

**S13. Holds, solicitation, budget, and the drop refusal.**
- **5.4 c4:** `farcast storage seal "$INSTANCE" --hold --reason walk`. A's `keeper run --once` reports the hold. With A's leaf (`FARCAST_WALK_LEAF=store:<A's keeper dir>` on A, or `packet:` on the operator's machine): `push` with `restart-reseed` is refused by the hold (`operator-hold`); `release-hold`, `seal`, and `push` with `operator-unseal` all answer `403 permission`; the hold is untouched.
- **5.4 c6:** release the hold and unseal; then `push` with A's leaf and `restart-reseed` to a serving replica answers `409 already-serving`. Then the plain-seal double re-seed shows `RE-SEEDED MORE THAN ONCE` in `keeper status`.
- **The leaf binds the bundle:** `push` with A's leaf, `FARCAST_WALK_BUNDLE=keys:@live` (the current keyring — a different bundle from A's) and `restart-reseed`, to a sealed replica: `403 keeper-bundle`, and the replica stays sealed.
- **5.4 c5:** enrol device B on the operator's machine with `--budget 1`.
- **The drop refusal, and the pin in front of it:** `push` with the operator's leaf, `hand-over`, `FARCAST_WALK_BUNDLE=keys:keys.pre-S11.yaml` → `409 below-pin`: the pin requires the egress-demo scopes and is checked first. The same push with intent `operator-unseal+below-pin` — which skips the pin and nothing else — to a serving replica → `409 would-drop`. Either way `storage state` still shows the egress-demo scopes; `farcast storage seal` then `farcast storage unseal` is the deliberate way past.
- After the reboot (5.4 c8): A's `keeper status` shows its ledger and budget intact, 0600 files in a 0700 directory, and on macOS `tmutil isexcluded` holds.

**S14. 5.3 c14b, a write in flight across a rotation.**
1. Record `farcast storage key list`, and keep the keyring from before this rotation: `install -m 0600 "$KEYS/keys.yaml" ./keys.pre-rotate.yaml`.
2. In alpha: `head -c 16777216 /dev/urandom >/tmp/b; sha256sum /tmp/b`, then the S7 PUT with `--limit-rate 64k --data-binary @/tmp/b` to `app/sdk-demo/alpha/inflight.bin`, in the background (about 256 s). Keep it at 16 MiB or less: the keyholder reads the body whole and requests only 128Mi.
3. While it runs: `farcast storage key rotate "$INSTANCE" -y`.
4. *Expect* 204; a GET from the Pod and `farcast storage cp "$INSTANCE:app/sdk-demo/alpha/inflight.bin" …` both match the sha256.
5. The object header's key ID equals alpha's pre-rotation KEK ID.

## Rotation, the pin, and teardown

**S15.** 5.4 c7, reordered.
- **7a.** `farcast keeper revoke "$INSTANCE" <A> -y`. Until a rotation, the revoked device still re-seeds while its bundle is current — and S16 shows what changes after one.
- **7b.** `kubectl -n farcast-system scale statefulset datasphered --replicas=1`. `storage state` shows `502` for replica 1; `rotate` exits non-zero ("held on some, in use on none"); `key list`'s active keys are unchanged; `storage unseal` activates nothing.
- **7c.** Scale back to 2, so replica 1 is restart-sealed. `rotate` finishes and names replica 1 sealed; `storage unseal`; `rotate` again — all replicas hold and write; `state` flags nothing, and every replica's pin is `current`.
- **7d.** `farcast storage seal` without a hold. `rotate` stops at the hold, exits non-zero, keys unchanged. `storage unseal`.
- **7e.** Scale to 1 and delete `datasphered-0`. `unseal` leaves replica 0 sealed and names `--unchecked`; `unseal --unchecked` unseals replica 0 and pushes nothing to replica 1. Scale to 2; `unseal`.
- **7f.** Save the live keyring and its hash first — `install -m 0600 "$KEYS/keys.yaml" ./keys.current.yaml; shasum -a 256 "$KEYS/keys.yaml"` — then `cp ./keys.pre-rotate.yaml "$KEYS/keys.yaml"`. With both replicas serving, `unseal` refuses before pushing anything: replica 0 holds keys this keyring lacks (the serving-replica comparison answers before the pin is consulted), and the ledger is unchanged. Restore with `cp ./keys.current.yaml "$KEYS/keys.yaml"` and check the hash matches **before running any other farcast command** — a keyring replaced without that copy loses the post-rotation keys for good.
- **7g.** `farcast storage key rekey "$INSTANCE" -y` reports `rewritten > 0`. Nothing in 7a–7g trips the drop refusal.
- **7h.** `probe FARCAST_WALK_PROBE=open FARCAST_WALK_PACKET=a.packet FARCAST_WALK_PASSPHRASE_FILE=pass FARCAST_WALK_OBJECT=app/sdk-demo/alpha/hello` — `ErrUnknownKey`.

**S16. New: the key pin.**
1. `kubectl -n farcast-system get configmap datasphered-pin -o json`: the pin requires the post-rotation key IDs and retires the pre-rotation ones; no scope name appears anywhere in it. The StatefulSet did not roll when it changed (`kubectl -n farcast-system rollout history statefulset datasphered`).
2. `kubectl -n farcast-system delete pod -l app.kubernetes.io/name=datasphered` — nothing is left serving to compare against.
3. With the revoked packet: `push`, `FARCAST_WALK_LEAF=packet:a.packet FARCAST_WALK_BUNDLE=packet:a.packet`, `restart-reseed`, ordinal 0 → `409 below-pin`; the replica stays restart-sealed. (Before 2026-10-08 this re-seeded the old keys.)
4. The same packet's leaf with the current keyring as the bundle → `403 keeper-bundle`. The two layers together: a stolen leaf can push only its own bundle, and the pin refuses that one now.
5. A freshly re-enrolled keeper's `keeper run --once`, or `farcast storage unseal`, succeeds.
6. *Live raise:* seal replica 1 (`probe FARCAST_WALK_PROBE=seal FARCAST_WALK_ORDINAL=1`), rotate again; `probe FARCAST_WALK_PROBE=state` shows replica 1's pin raised to the new keys without a restart. Unseal.
7. *Re-arm:* delete the ConfigMap, then delete both Pods: `storage state` reports "none loaded"; `farcast storage key pin "$INSTANCE"` re-creates it and raises it live; `state` reports `current`.
8. *Unreadable:* replace the ConfigMap's value with `{` and delete one Pod: `storage state` reports that replica's pin unreadable; a keeper's `keeper run --once` refuses it locally, and the probe's `push` with a keeper leaf and `restart-reseed` → `409 pin-unreadable`; `farcast storage unseal` still unseals it; `farcast storage key pin` repairs it, live.
9. *Below the pin, deliberately:* `farcast storage seal "$INSTANCE"` first — `--below-pin` skips the pin and nothing else, so against serving replicas holding newer keys it is refused as behind them. Then the 7f save-and-swap to `keys.pre-rotate.yaml`: plain `unseal` refuses as below the pin, naming `--below-pin`, with nothing pushed; `farcast storage unseal --below-pin` unseals, and `state` reports the replicas serving below their pin. Restore `keys.current.yaml` and check its hash, then `farcast storage seal` and `farcast storage unseal` to put the replicas back on the current keys.

**S17.** 5.4 c9: `keeper status` on the operator's machine lists A and B with expiries and a fleet budget total.
- **New: tunnel admission, part 2.** Write alpha's storage leaf from the `alpha-egress` Secret (`FARCAST_STORAGE_CLIENT_CERT` / `_KEY`) to 0600 scratch files; `probe FARCAST_WALK_PROBE=tunnel FARCAST_WALK_CERT=alpha.crt FARCAST_WALK_KEY=alpha.key` — refused at the handshake. Delete the files.
- A's keeper leaf (`probe FARCAST_WALK_PROBE=tunnel FARCAST_WALK_LEAF=packet:a.packet FARCAST_WALK_PASSPHRASE_FILE=pass`, with A's packet re-enrolled in S11): the `datasphered` route opens; the `shrike` route answers `403`, and FatLine logs `role_refused`.

**S18. The carrier, second half.** Lower the limit below the accrued total (edit `metadata.yaml`, then `farcast kernel deploy -y`). *Expect* applications stopped, `at the instance floor … still_burning_per_hour=0.0554 carrier_per_hour=0.0250` (Pods and carrier), and Service `fatline` still `LoadBalancer` with its forwarding rule in place.

**S19. New: release waits.** `time farcast release "$INSTANCE" --delete-data --yes`.
- It returns only after GKE reports the cluster gone; no `(deleted)` line before then, and the local record lasts until then.
- A keeper installed on this machine for this instance is reported wiped (ledger kept); device A is named with `farcast keeper uninstall "$INSTANCE"` to run there — run it, and its `keeper status` shows the material wiped.
- Verify independently that clusters, buckets, registries, forwarding rules, addresses, target pools, disks and VMs are all zero.

---

## Recording the results

Per step: the command, what was expected, what was seen, and pass or fail. A failure is recorded as found — with the defect, its fix, and whether the fix was re-walked — exactly as the per-phase runbooks do. Phase 5 is closed when every row passes or carries a recorded reason it cannot, and PLAN.md says so.
