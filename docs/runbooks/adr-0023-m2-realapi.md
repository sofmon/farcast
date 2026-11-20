# ADR 0023 M2 — the real-API suite: what kubetest cannot settle

From [ADR 0023](../adr/0023-one-download-farcast.md) M2.7b, which is not built at the commit this runbook is written against, farcast is to write to a cluster with its own server-side apply, not kubectl. An instance an older farcast wrote is then migrated once: each object's client-side apply entry is renamed to farcast's, and kubectl's last-applied annotation is removed. farcast's tests run against `kubetest`, a local emulation of the API server. kubetest does not track ownership field by field, does not default, and follows no generation rule of a real server. So it cannot show whether a migrated object keeps a field farcast later drops, whether the first apply after a migration rolls a workload, or what the server records for a patch. This runbook runs farcast's real-API suite against a real `kube-apiserver` and `etcd`, from envtest v1.36.2. They run on the keeper VM, listen only on that VM's loopback, and are reached from the Mac through `ssh -L`. The run sits between M2.7a and M2.7b: the migration is built only after it.

**Status.** *Written 2026-11-18 against M2.7a. Run on 2026-11-18, from 2728e5f, and again on 2026-11-19, on M2.7b's tree before its commit (the M2 design's §31, "The re-run"); the Results of both are below.*

*(2026-11-19: the re-run builds from M2.7b's tree, built and not committed. There farcast writes with server-side apply and `farcast migrate` is built, so the opening paragraph's "is to" and "the run sits between M2.7a and M2.7b" describe Run 1 only. The re-run also records item 7 for the egress policy as `run` renders it, at a stale resourceVersion and at the stored one. In item 9 it also records a `/scale` write of 2, and whether a `/scale` write of 0 moves the time of farcast's Apply entry.)*

*(2026-11-20, [ADR 0023](../adr/0023-one-download-farcast.md) M2.9a, built 2026-11-20, not walked: `farcast migrate` is removed, and with it the migration's tests, row 104's mutant and the two kubectl seeds. Run 1 and the re-run stand as run, on the trees they were built from. Items 2 to 5 and 11 below have nothing left to record, and item 1 now asks its question of farcast's forced apply alone, with no row 104. Item 8 now asks only of metadata-only lists and gets, since no patch is left to check. A later run follows R6's M2.9a note, which names its tests.)*

**It records:**
1. whether a field that a migrated object's manifest later drops is removed by farcast's next apply, for §6.8's seven cases; and whether mutation row 104's mutant is killed there;
2. whether removing the annotation in the migration's own patch leaves a `farcast`/Update entry;
3. what the server does with a managed-fields rewrite it cannot decode;
4. that a stale migration patch is a 409 that changes nothing, and that a fresh read then migrates the object;
5. how `metadata.generation` moves: on the migration, and on the first apply after it;
6. whether re-applying an unchanged Job is a no-op, and what the server defaults in it;
7. whether an apply carrying a stale `metadata.resourceVersion` is refused with 409, and what one answers for a Secret deleted since it was read: 404, 409, or a 2xx that recreates it;
8. the wire facts: metadata-only lists, gets and patches carry no Secret value; the conflict cause's key; the kinds of typed and partial list items;
9. what the kernel's writes are recorded as, whether its `/scale` write is tracked, and whether farcast's forced apply takes `replicas` back;
10. whether every stream farcast renders applies twice, with no error and no generation move on the second apply;
11. once: whether kubectl's own client-side seed matches the suite's emulated one.

**It costs nothing.** Nothing runs in a cloud. It downloads one 45.1 MB archive from GitHub to the keeper VM, and it takes about 45 minutes. Teardown deletes everything it made.

**What this exposes.** The binaries run as the keeper VM's existing account, the one `$VM` names (the operator's decision O2, 2026-11-18). So the three downloaded binaries, `kube-apiserver`, `etcd` and `kubectl`, can read that account's files, keeper material included. These limit it:
- the archive's sha512 is checked against two published values before anything is extracted (R2);
- everything lives in one fresh directory, `~/realapi-<YYYYMMDD>`, which teardown deletes; etcd's data directory is inside it;
- every listener binds 127.0.0.1;
- no `sudo`, no systemd unit, and no change outside that directory;
- the agent never types the VM's sudo password.

**Do not start R2 until the operator has approved this run in this session (R0).**

Throughout:
- **The scrub rule** holds for every record: this runbook's Results, and the M2 design's §31. No address, host name or account name, loopback and the VM's own included, and no port. No path under the operator's home, on the Mac or the VM. No uid, resourceVersion, pid, key id or token byte. No time of day; dates only. Raw outputs and logs are never copied into a record.
- **The ssh destination** is `$VM` and nothing else, here and in every record.
- **Never print the token.** It is made on the VM, copied to `$RUN` with mode 0600, and read only by the test binaries, which use it as a bearer and print it nowhere. Never `cat` it, and never put it on a command line.
- **The tree is never edited.** Row 104's mutant is an overlay under `$RUN` (R1 step 6).
- **The Mac's farcast config directory and `~/.kube` are never read.** No step sets `KUBECONFIG` on the Mac.

**Variables.**
- On the Mac, from the repository root:
  ```bash
  VM='<account>@<host>'                # the keeper VM's ssh destination: O2's existing account; never recorded
  RUN=$(mktemp -d); chmod 700 "$RUN"   # every file of this run on the Mac
  ```
  Every go command runs with `GOWORK=off GOTOOLCHAIN=go1.27.4 GOPROXY=off GOFLAGS=-mod=vendor`.
  - `echo "$RUN"` once, on the terminal only: a shell that does not keep variables needs it again.
  - An agent's tool shells keep no variable from one command to the next. So each Mac code block below begins with `: "${VM:?}" "${RUN:?}"`, which stops it when either is unset. In a new shell, set both again by value, `RUN=<the directory echoed above>`, never by a second `mktemp`: that would make a new, empty directory, which R9 would then delete in place of the run's. R6's `FARCAST_REALAPI_*` variables are set again the same way, as R7 does.
- On the VM, each step is one fresh shell, run as one command, with the run's date written out in place of `<YYYYMMDD>`. The step's lines go where `…` is:
  ```bash
  ssh "$VM" bash -s <<'REMOTE'
  set -eu; umask 077; D=$HOME/realapi-<YYYYMMDD>; B=$D/controller-tools/envtest; K="env KUBERC=off $B/kubectl --kubeconfig $D/kubeconfig --cache-dir $D/kube-cache"
  cd "$D"
  …
  REMOTE
  ```
  - The script reaches the VM on stdin, under a quoted delimiter, so nothing in it is expanded on the Mac, and the steps' own quotes need no escaping.
  - From R3 on, each step starts with `cd "$D"`, as above. R2 makes `$D`, and R9's checks run after it is deleted, so those two leave the `cd` out.
  - `$K` is kubectl as this run uses it: its own kubeconfig, and its discovery and HTTP caches under `$D`, so nothing lands in the account's `~/.kube/cache`. `--cache-dir` is *confirmed on the VM, 2026-11-18*: no discovery cache landed outside `$D`. Every `$K` call ran with `KUBERC=off` and succeeded; what it suppresses was not observed.

A flag below taken from documentation, and not yet run, was marked *to be confirmed on the VM*. A flag that has to change is recorded in §31, and this runbook is corrected in place with a dated note. *2026-11-18: every mark ran without error, and none had to change. Each now reads "confirmed on the VM", except `KUBERC=off`, whose effect was not observed.*

---

## R0. Approval

On 2026-11-18 the operator decided to run the suite on the keeper VM before M2.7b (O1), as the VM's existing account (O2). The orchestrator chose the envtest v1.36.2 archive, and the one kubectl variant (A30-3).

Before R2, the agent presents:
- the URL: `https://github.com/kubernetes-sigs/controller-tools/releases/download/envtest-v1.36.2/envtest-v1.36.2-linux-arm64.tar.gz`;
- its size, 45.1 MB;
- its sha512's first and last 16 hex characters, `2d72ee985a8e262a` and `c6d824dd9c6649ac`;
- the account: the VM's existing one, which `$VM` names;
- the loopback ports: 2379, 2380 and 6443 on the VM, and 16443 on the Mac;
- about 45 minutes, and USD 0;
- what this exposes (above);
- for a re-run, the tree it builds from: M2.7b's uncommitted tree, and the HEAD it sits on (R1 step 7's dated note; the M2 design's A30-1).

Then it waits for the operator's yes in this session. Approval does not carry over from another run or walk, as in [adr-0023-m2-probe-walk.md](adr-0023-m2-probe-walk.md).

## R1. Preflight, on the Mac

1. The operator starts the keeper VM.
2. `ssh "$VM" true`. If this fails with "No route to host" or "Undefined error: 0", the operator grants Local Network to the Claude Code bundle, then retries.
3. `ssh "$VM" 'uname -m; . /etc/os-release; echo "$VERSION_ID"; command -v curl sha512sum tar openssl ss pgrep'`. *Expect* `aarch64`, `26.04`, and a path for every tool.
4. The ports are free. `ssh "$VM" "ss -ltnH '( sport = :2379 or sport = :2380 or sport = :6443 )'"` prints nothing, and on the Mac `lsof -nP -iTCP:16443 -sTCP:LISTEN` prints nothing. If a port is taken, choose another, and record that a port moved, not which.
5. The account's `~/.kube`, its names only:
   ```bash
   : "${VM:?}" "${RUN:?}"
   ssh "$VM" 'if test -e ~/.kube; then ls -A ~/.kube; else echo absent; fi' >"$RUN/kube-before.txt"
   ```
   It stays in `$RUN` and is never recorded. R9 compares against it.
6. **Row 104's mutant**, written under `$RUN` only:
   ```bash
   : "${VM:?}" "${RUN:?}"
   mkdir -m 700 "$RUN/row104"
   cp farsight/cli/internal/kube/migrate.go "$RUN/row104/migrate.go"
   perl -0pi -e 's/(\t\tmf\[target\]\.Manager = ssa\n)/$1\t\tif f, err := RemoveField(mf[target].FieldsV1, "f:metadata", "f:labels"); err == nil { mf[target].FieldsV1 = f }\n/' "$RUN/row104/migrate.go"
   diff farsight/cli/internal/kube/migrate.go "$RUN/row104/migrate.go"
   printf '{"Replace":{"%s":"%s"}}\n' "$PWD/farsight/cli/internal/kube/migrate.go" "$RUN/row104/migrate.go" >"$RUN/row104/overlay.json"
   ```
   - The one edit is in `upgradeOne`, right after the conversion inside `if target < 0`: the converted entry loses `f:metadata`'s `f:labels`, so it owns no label, and keeps every other field it owned, so it is not empty. That is mutation row 104 as the M2 design's §30 re-points it, amended 2026-11-18: a converted entry left with `fieldsV1` `{}` may be pruned by the server *(inferred: not in the saved sources)*, and the end-state check would then refuse before the stuck-field assertion.
   - Under it, the label `farcast.sofmon.com/instance`, which the subtest `a label leaves` drops in its v2, is owned by no manager after the migration. So v2's forced apply should leave it *(inferred from server-side apply's removal rule, which removes only a field the applier owned)*, and that subtest fails at `stuck field: `. *Confirmed by the run, 2026-11-18: the mutant failed there and nowhere else.*
   - `diff` must print exactly that one added line. Anything else stops the run before R2.
7. **The test binaries**, built once, at the M2.7a commit, from a clean tree. A re-run builds from the tree the M2 design's A30-1 names, and records its tree hash. One binary per suite means one firewall rule each, should loopback dials ever need one *(inferred: they do not)*.
   ```bash
   : "${VM:?}" "${RUN:?}"
   if test -n "$(git status --porcelain)"; then echo 'STOP: the tree is not clean'; else git rev-parse HEAD; fi
   ```
   A `STOP` line ends the run here. Otherwise the commit printed is recorded (R8), and:
   ```bash
   env GOWORK=off GOTOOLCHAIN=go1.27.4 GOPROXY=off GOFLAGS=-mod=vendor \
     go test -c -tags realapi -o "$RUN/kube-realapi.test" ./farsight/cli/internal/kube/
   env GOWORK=off GOTOOLCHAIN=go1.27.4 GOPROXY=off GOFLAGS=-mod=vendor \
     go test -c -tags realapi -o "$RUN/cli-realapi.test" ./farsight/cli/internal/cli/
   env GOWORK=off GOTOOLCHAIN=go1.27.4 GOPROXY=off GOFLAGS=-mod=vendor \
     go test -c -tags realapi -overlay "$RUN/row104/overlay.json" -o "$RUN/kube-realapi-row104.test" ./farsight/cli/internal/kube/
   ```
   - *Corrected 2026-11-18, for a re-run on an uncommitted tree.* The M2 design's A30-1 names M2.7b's tree before its commit, and R0 names it to the operator. In place of the check above, the agent hashes the working tree through a throwaway index under `$RUN`, never the real index or the stash. `.claude/` is gitignored, so `git add -A` leaves it out:
     ```bash
     : "${VM:?}" "${RUN:?}"
     git rev-parse HEAD
     GIT_INDEX_FILE="$RUN/tree.index" git read-tree HEAD && GIT_INDEX_FILE="$RUN/tree.index" git add -A && GIT_INDEX_FILE="$RUN/tree.index" git write-tree >"$RUN/tree-before.txt" && cat "$RUN/tree-before.txt"
     ```
     This runs before the builds above: three, or two when row 104's mutant is not run (no `-overlay` build). After them, the same hash is taken again, and the run stops unless it is equal:
     ```bash
     : "${VM:?}" "${RUN:?}"
     GIT_INDEX_FILE="$RUN/tree.index" git add -A && GIT_INDEX_FILE="$RUN/tree.index" git write-tree | diff "$RUN/tree-before.txt" - && echo 'the tree did not change' || echo 'STOP: the tree changed during the builds'
     ```
     R8 records the tree hash and the HEAD it sits on.

## R2. Download, on the VM

In one VM shell, without the `cd "$D"`: this step makes `$D`.
```bash
umask 077; mkdir -m 700 "$D"; cd "$D"
curl -fL --proto '=https' --tlsv1.2 -O https://github.com/kubernetes-sigs/controller-tools/releases/download/envtest-v1.36.2/envtest-v1.36.2-linux-arm64.tar.gz
stat -c %s envtest-v1.36.2-linux-arm64.tar.gz
sha512sum envtest-v1.36.2-linux-arm64.tar.gz
curl -fL --proto '=https' --tlsv1.2 -O https://github.com/kubernetes-sigs/controller-tools/releases/download/envtest-v1.36.2/envtest-v1.36.2-linux-arm64.tar.gz.sha512
cat envtest-v1.36.2-linux-arm64.tar.gz.sha512
```
- `mkdir` and `cd` are two commands, so under `set -e` an existing `$D` ends the step before anything is downloaded. **If `$D` already exists, stop.** It is left from an earlier run: finish that run's R9 first.
- The sidecar's name, `….tar.gz.sha512`, is *confirmed on the VM, 2026-11-18*. Its line names the archive with a leading `/`, so `sha512sum -c` would not read it as is; this step compares by eye and does not use `-c`. If its download fails, the step ends there, with the computed size and sha512 already printed. Nothing is extracted: the operator decides, from the other two values, whether the run goes on, and §31 records that the sidecar was not read.
- **The operator compares three values** before anything is extracted:
  - the computed sha512;
  - the sidecar's;
  - the full value for v1.36.2 linux/arm64 in controller-tools' `envtest-releases.yaml`, read in their own browser.

  All three must be equal, beginning `2d72ee985a8e262a` and ending `c6d824dd9c6649ac`.
- **The size is a sanity check only; the sha512 binds.** `stat` prints bytes. GitHub's 45.1 MB is binary: the run measured 47,304,572 bytes, 45.11 MiB (2026-11-18). A byte count far from that is a mismatch.
- **On any mismatch:** stop, `rm -rf "$D"`, and record it.

## R3. Extract

1. `tar -tvzf envtest-v1.36.2-linux-arm64.tar.gz` must list only the regular files `controller-tools/envtest/kube-apiserver`, `etcd` and `kubectl`, and their directories. The prefix is *confirmed on the VM, 2026-11-18*: one directory and the three regular files. Any absolute path, any `..`, any link, or any other entry stops the run.
2. Then:
   ```bash
   tar -xzf envtest-v1.36.2-linux-arm64.tar.gz --no-same-owner --no-same-permissions -C "$D"
   ```
   `B=$D/controller-tools/envtest` from here on, as the Variables set it.
3. Record `"$B/kube-apiserver" --version`, `"$B/etcd" --version` and `"$B/kubectl" version --client`.

## R4. Material

With `umask 077`. Nothing here is echoed, and the token is never on a command line.
```bash
mkdir -p "$D/certs" "$D/etcd-data" "$D/logs"
openssl genrsa -out "$D/sa.key" 2048 2>/dev/null
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$D/token"
{ cat "$D/token"; printf ',realapi,realapi,system:masters\n'; } > "$D/tokens.csv"
wc -c < "$D/token"
cat > "$D/kubeconfig" <<EOF
apiVersion: v1
kind: Config
clusters:
- name: realapi
  cluster:
    server: https://127.0.0.1:6443
    certificate-authority: $D/certs/apiserver.crt
users:
- name: realapi
  user:
    tokenFile: $D/token
contexts:
- name: realapi
  context:
    cluster: realapi
    user: realapi
current-context: realapi
EOF
```
- `wc` prints `64`, the byte count only.
- The kubeconfig names the server `https://127.0.0.1:6443`, the certificate R5 makes, and a user whose `tokenFile` is `$D/token`. So it holds no token. `tokenFile` is *confirmed on the VM, 2026-11-18*.
- The static-token file's format (`token,user,uid,group`) and `system:masters` bypassing RBAC under `--authorization-mode RBAC` are from documentation, *confirmed on the VM, 2026-11-18*.

## R5. etcd, then kube-apiserver, on 127.0.0.1

As envtest starts them, with its client certificates replaced by a static token. Every flag here is *confirmed on the VM, 2026-11-18*.
```bash
nohup "$B/etcd" --name realapi --data-dir "$D/etcd-data" \
  --listen-client-urls http://127.0.0.1:2379 --advertise-client-urls http://127.0.0.1:2379 \
  --listen-peer-urls http://127.0.0.1:2380 --initial-advertise-peer-urls http://127.0.0.1:2380 \
  --initial-cluster realapi=http://127.0.0.1:2380 --unsafe-no-fsync \
  </dev/null >"$D/logs/etcd.log" 2>&1 & echo $! >"$D/etcd.pid"

nohup "$B/kube-apiserver" --etcd-servers http://127.0.0.1:2379 \
  --bind-address 127.0.0.1 --advertise-address 127.0.0.1 --secure-port 6443 \
  --cert-dir "$D/certs" --service-cluster-ip-range 10.0.0.0/24 \
  --service-account-issuer https://127.0.0.1:6443 \
  --service-account-key-file "$D/sa.key" --service-account-signing-key-file "$D/sa.key" \
  --token-auth-file "$D/tokens.csv" --anonymous-auth=false \
  --authorization-mode RBAC --disable-admission-plugins ServiceAccount --profiling=false \
  </dev/null >"$D/logs/apiserver.log" 2>&1 & echo $! >"$D/apiserver.pid"
```
**What differs from envtest's own start** (from documentation: controller-runtime's `apiserver.go`):
- `--allow-privileged` is not passed, so privileged pods are refused, as Autopilot refuses them;
- `--token-auth-file` replaces envtest's client-certificate authentication, and `--anonymous-auth=false` is added;
- `--profiling=false` is added;
- `--advertise-address 127.0.0.1` is added; it is not among envtest's flags;
- `--bind-address`, which envtest passes too, is 127.0.0.1 here, because its default is `0.0.0.0` (documentation);
- etcd's client and peer URLs are 127.0.0.1, where envtest's peer URL names `localhost`.

**The serving certificate** is self-signed into `$D/certs/apiserver.crt`, with the bind address as an IP SAN (documentation). Confirm on the VM:
- `grep -c 'BEGIN CERTIFICATE' "$D/certs/apiserver.crt"` prints `2`: the leaf and its CA;
- `openssl x509 -in "$D/certs/apiserver.crt" -noout -ext subjectAltName` names `IP Address:127.0.0.1`.

**Checks**, in the next VM shell:
- `$K get --raw /readyz` prints `ok`. While the server starts, try for at most 60 s:
  ```bash
  for i in $(seq 60); do $K get --raw /readyz 2>/dev/null && break; sleep 1; done
  ```
- `ss -ltnpH` shows etcd and kube-apiserver listening on 127.0.0.1 only.

## R6. The forward, and the run, on the Mac

```bash
: "${VM:?}" "${RUN:?}"
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:16443:127.0.0.1:6443 "$VM" </dev/null >"$RUN/ssh.log" 2>&1 & echo $! >"$RUN/ssh.pid"
for i in $(seq 10); do lsof -nP -iTCP:16443 -sTCP:LISTEN >/dev/null && break; sleep 1; done
if lsof -nP -iTCP:16443 -sTCP:LISTEN >/dev/null; then echo 'the forward listens'; else echo 'STOP: the forward did not start (ssh.log in the run directory says why)'; fi
scp "$VM":realapi-<YYYYMMDD>/certs/apiserver.crt "$RUN/apiserver.crt"
scp "$VM":realapi-<YYYYMMDD>/token "$RUN/token"; chmod 600 "$RUN/token" "$RUN/apiserver.crt"
export FARCAST_REALAPI_ENDPOINT=127.0.0.1:16443 FARCAST_REALAPI_CA_FILE="$RUN/apiserver.crt" FARCAST_REALAPI_TOKEN_FILE="$RUN/token"
REALAPI='^(TestMigrationRemovesAFieldLaterDroppedFromTheManifest|TestAnnotationRemovalInTheSamePatchLeavesNoUpdateEntry|TestRealAPIKeepsTheLiveListOnAnUndecodableRewrite|TestMigrationIsResumable|TestFirstApplyAfterMigrationChangesNoGeneration|TestReapplyingAnUnchangedJobIsANoOp|TestApplyRefusesAStaleResourceVersion|TestMetadataOnlyListsCarryNoSecretData|TestStatusCauseWireName|TestTypedListItemsCarryNoKind|TestMigrationLeavesAnotherManagersFieldAlone|TestKernelWritesAreTrackedAsTechnocore)$'
(cd farsight/cli/internal/kube && "$RUN/kube-realapi.test" -test.run "$REALAPI" -test.v -test.count=1 -test.timeout=30m >"$RUN/kube.out" 2>&1); echo "exit $?"
(cd farsight/cli/internal/cli && "$RUN/cli-realapi.test" -test.run '^TestEveryRenderedStreamAppliesOnARealServer$' -test.v -test.count=1 -test.timeout=15m >"$RUN/cli.out" 2>&1); echo "exit $?"
(cd farsight/cli/internal/kube && "$RUN/kube-realapi-row104.test" -test.run '^TestMigrationRemovesAFieldLaterDroppedFromTheManifest$' -test.v -test.count=1 >"$RUN/row104.out" 2>&1); echo "exit $?"
grep -E '^(=== RUN|--- (PASS|FAIL|SKIP)|PASS$|FAIL$)' "$RUN/kube.out" "$RUN/cli.out"
grep -cE '^--- (PASS|FAIL)' "$RUN/kube.out"     # must print 12
grep -cE '^--- (PASS|FAIL)' "$RUN/cli.out"      # must print 1
grep -E '^ +--- (PASS|FAIL): TestApplyRefusesAStaleResourceVersion/' "$RUN/kube.out"
grep -E '^ *--- (PASS|FAIL)|stuck field: ' "$RUN/row104.out"
```
- **The kube run names its tests.** `REALAPI` is every top-level test in `kube/realapi_test.go` but `TestEmulatedSeedMatchesKubectl` (R7), anchored at both ends, so the unit test `TestStatusCauseWireNameIsReason` is not matched. `kube.out` must hold exactly 12 unindented `--- PASS` or `--- FAIL` lines, and `cli.out` exactly 1: the two counts above. Any other count stops the run, because a test was missed.
  - *(2026-11-20, [ADR 0023](../adr/0023-one-download-farcast.md) M2.8, built 2026-11-19 to 2026-11-20, not walked.)* `kube/realapi_test.go` now also holds `TestServiceAccountUIDSurvivesForcedApplyAndMigration` and `TestDeleteSecretHonoursItsUIDPrecondition`. `cli/realapi_test.go` now also holds `TestReaderReadsTheNamedServiceAccounts`. `REALAPI` names none of the three, so "every top-level test" and the counts above hold only for the tree the two runs were built from. The three are written and vetted, and have not run against a real server.
  - *(2026-11-20, [ADR 0023](../adr/0023-one-download-farcast.md) M2.9a, built 2026-11-20, not walked.)* The migration is removed, and the real-API suite changes with it:
    - five tests are removed: `TestAnnotationRemovalInTheSamePatchLeavesNoUpdateEntry`, `TestRealAPIKeepsTheLiveListOnAnUndecodableRewrite`, `TestMigrationIsResumable`, `TestFirstApplyAfterMigrationChangesNoGeneration` and R7's `TestEmulatedSeedMatchesKubectl`;
    - three are renamed, each now starting from a forced apply: `TestMigrationRemovesAFieldLaterDroppedFromTheManifest` is `TestForcedApplyRemovesAFieldDroppedFromTheManifest`, `TestMigrationLeavesAnotherManagersFieldAlone` is `TestForcedApplyTakesAnotherManagersField`, and M2.8's `TestServiceAccountUIDSurvivesForcedApplyAndMigration` is `TestServiceAccountUIDSurvivesAForcedApply`;
      - the stuck-field test applies each case's v1 and then its v2, both forced. Its Secret case starts from the `data:` form, because `SplitStream` refuses `stringData`, so the subtest is `a Secret data key leaves`;
      - the other-manager test's first step is farcast's forced apply of the Deployment. The merge PATCH's `realapi-other/Update` entry and its `replicas` of 3 are checked before the forced apply of 1 takes the field back;
      - the uid test keeps its builder half, and its keyholder half applies the ServiceAccount forced, then again with a label added, and checks that the uid did not move;
    - `TestMetadataOnlyListsCarryNoSecretData` is seeded by a forced apply, reads `ListObjects`, a raw partial list and `GetObject`, and expects no kubectl annotation;
    - R1 step 6 (row 104's mutant), its `-overlay` build in R1 step 7, R6's row-104 run, and R7 with its two kubectl seeds are retired: the code they exercised is gone.

    A later run names its tests anew: `REALAPI` below in place of R6's, `CLIREALAPI` below as the cli run's `-test.run` pattern in place of its one name, and the counts 10 for `kube.out` and 2 for `cli.out` in place of 12 and 1:
    ```bash
    REALAPI='^(TestForcedApplyRemovesAFieldDroppedFromTheManifest|TestReapplyingAnUnchangedJobIsANoOp|TestApplyRefusesAStaleResourceVersion|TestMetadataOnlyListsCarryNoSecretData|TestStatusCauseWireName|TestTypedListItemsCarryNoKind|TestKernelWritesAreTrackedAsTechnocore|TestForcedApplyTakesAnotherManagersField|TestServiceAccountUIDSurvivesAForcedApply|TestDeleteSecretHonoursItsUIDPrecondition)$'
    CLIREALAPI='^(TestEveryRenderedStreamAppliesOnARealServer|TestReaderReadsTheNamedServiceAccounts)$'
    ```
    The three renamed tests, the reseeded `TestMetadataOnlyListsCarryNoSecretData`, and M2.8's other two, `TestDeleteSecretHonoursItsUIDPrecondition` and `TestReaderReadsTheNamedServiceAccounts`, are written and have not run against a real server. `./check.sh` vets and lints them with the `realapi` tag and never runs them. `TestKernelWritesAreTrackedAsTechnocore` keeps its body, but it reads managed fields through the rewritten `owns` helper, which has not run against a real server either; `owns` itself is now pinned by the untagged `TestOwnsWalksTheFieldsV1Trie` in `kube/owns_test.go`, which `./check.sh` runs. R8's grep then reads `kube.out` and `cli.out` only.
- **The stale-rv subtests.** A subtest's result is indented, so the first grep does not show it; the fourth does. `a_stale_resourceVersion` decides step 3 (What the run decides). `a_Secret_deleted_since_it_was_read` only records.
  - *(2026-11-19, the re-run on M2.7b's tree.)* The test has a third subtest, `the_egress_policy_at_a_stale_resourceVersion` (the M2 design's A31-2). It runs step 3's own path: the policy as `RenderPolicyConfigMap` renders it, split with `AllowResourceVersion`, is refused by `Apply` with a 409 that unwraps to `ErrConflict` and nothing written, then applied at the stored resourceVersion. The fourth grep prints three lines. Step 3 is built, so `a_stale_resourceVersion` no longer decides it alone: it and the new subtest must both pass, the new one on both halves (What the run decides).
- **Row 104 counts as killed only when both hold:**
  - `TestMigrationRemovesAFieldLaterDroppedFromTheManifest` passed in the unmutated `kube.out`;
  - the mutant's failure is the stuck-field assertion, a line with `stuck field: `, in the subtest `a_label_leaves`, recorded by its subtest's name. The mutant's other six subtests are expected to pass.

  Any other failure (a missing variable, a setup error, the end-state check) is recorded by its assertion and does not count: row 104 is then not verified.
- Each binary runs in its package's directory, as `go test` would, so `testdata/` resolves.
- Outputs go only to `$RUN`. Nothing else is printed but the lines above. What a test records is on its log lines that carry `fact: `, after the `realapi_test.go:<line>: ` every test log line begins with. They are already scrubbed of uids, resourceVersions, addresses and the token; R8 copies from those. A FAIL line's text is not scrubbed: it can quote the server's own message, so it is read, never copied.

## R7. The kubectl variant, once

```bash
: "${VM:?}" "${RUN:?}"
scp farsight/cli/internal/kube/testdata/realapi/kubectl-seed-v1.yaml farsight/cli/internal/kube/testdata/realapi/kubectl-seed-v1b.yaml "$VM":realapi-<YYYYMMDD>/
```
Then on the VM, in one shell, with `K` as the Variables define it (`--cache-dir "$D/kube-cache"` included):
```bash
$K create namespace realapi-kubectl
$K apply -n realapi-kubectl -f "$D/kubectl-seed-v1.yaml"
$K apply -n realapi-kubectl -f "$D/kubectl-seed-v1b.yaml"
```
Then on the Mac, in R6's shell or with its variables set again by value (Variables):
```bash
: "${VM:?}" "${RUN:?}"
export FARCAST_REALAPI_ENDPOINT=127.0.0.1:16443 FARCAST_REALAPI_CA_FILE="$RUN/apiserver.crt" FARCAST_REALAPI_TOKEN_FILE="$RUN/token"
lsof -nP -iTCP:16443 -sTCP:LISTEN >/dev/null || echo 'STOP: the forward is gone; start it again as R6 does'
(cd farsight/cli/internal/kube && FARCAST_REALAPI_KUBECTL_NAMESPACE=realapi-kubectl "$RUN/kube-realapi.test" -test.run '^TestEmulatedSeedMatchesKubectl$' -test.v -test.count=1 >"$RUN/kubectl.out" 2>&1); echo "exit $?"
```
- kubectl's apply is client-side by default at 1.36, so each object should show `kubectl-client-side-apply`/Update. That is *confirmed on the VM, 2026-11-18*.
- If the two seeds differ, the test's `fact:` lines say how. The emulated seed is then corrected, and the stuck-field cases run again under the re-run rule (What the run decides).

## R8. Results, scrubbed

This runbook's Results and the M2 design's §31 hold only:
- the commit the binaries were built from, and its tree hash (R1 step 7); for a re-run from an uncommitted tree, the tree hash and the HEAD it sits on;
- the versions, the archive's byte count, and that its sha512 matched both published values;
- each test's PASS or FAIL, `TestApplyRefusesAStaleResourceVersion`'s subtests' included (two in Run 1, three from the re-run), and whether row 104's mutant was killed;
- the facts each test records: managers, operations, subresources, field paths, HTTP codes, kinds and generation moves;
- *(2026-11-19)* for the re-run, these fact lines as well: `Scale to 0: …; farcast/Apply's time moved: …` and `Scale to 2: …; a technocore/Update/scale entry appears: …; it owns spec.replicas: …` (the M2 design's A31-5); `after realapi-other's merge PATCH …` and `after the migration: …; realapi-other/Update unchanged: …`; and the two `the egress policy rendered at …` lines (A31-2). `SetRequests`' entries line now follows a Scale to 2, so it is not compared with Run 1's;
- each refusal of a rendered stream, from its fact line: the stream, the document, the code, the reason and the causes' field paths.

The fact lines are pulled out on the terminal only, with nothing written:
```bash
: "${RUN:?}"
grep -h ': fact: ' "$RUN/kube.out" "$RUN/cli.out" "$RUN/row104.out" "$RUN/kubectl.out" | sed -E 's/^ *[a-z_]+\.go:[0-9]+: //'
```
Each record follows the scrub rule (Throughout).

## R9. Teardown

1. On the VM, in one shell. `kube-apiserver` is stopped first, and `etcd` only once it has exited.
   ```bash
   stop() {  # $1: the pid file's name; fails when that process outlives 30 s
     p=$(cat "$D/$1.pid" 2>/dev/null) || { echo "$1: no pid file"; return 0; }
     kill "$p" 2>/dev/null || { echo "$1: not running"; return 0; }
     for i in $(seq 30); do kill -0 "$p" 2>/dev/null || return 0; sleep 1; done
     return 1
   }
   stop apiserver || { echo 'STOP: kube-apiserver still runs 30 s after SIGTERM; etcd is left running, nothing deleted'; exit 1; }
   stop etcd || { echo 'STOP: etcd still runs 30 s after SIGTERM; nothing deleted'; exit 1; }
   for i in $(seq 30); do pgrep -u "$(id -u)" -x 'etcd|kube-apiserver|kubectl' >/dev/null || break; sleep 1; done
   if pgrep -u "$(id -u)" -x 'etcd|kube-apiserver|kubectl' >/dev/null; then echo 'STOP: still running; nothing deleted'; exit 1; fi
   cd ~ && rm -rf "$D" && echo 'the run directory is deleted'
   ```
   - Each `stop` that finds its process gone says so and goes on, so a server that already exited (as when it would not start) still leaves the other to be stopped and `$D` to be deleted.
   - A `kube-apiserver` that outlives its 30 s leaves `etcd` running, so it can still shut down cleanly.
   - `$D` is deleted only when none of the three runs any more. On a `STOP` line, the operator decides what is stopped, and this step runs again.
   - *Corrected 2026-11-18.* The first run sent SIGTERM to both servers at once. `kube-apiserver`, with its etcd gone, kept retrying it for over 90 s, so the step stopped at `STOP` with nothing deleted. The operator then approved a SIGKILL, and the step ran again and passed. If that recurs, the remedy for the operator to approve is this, which sends nothing unless the pid file still names the run's own binary:
     ```bash
     p=$(cat "$D/apiserver.pid"); if [ "$(readlink "/proc/$p/exe" 2>/dev/null)" = "$B/kube-apiserver" ]; then kill -9 "$p" && echo 'apiserver: SIGKILL sent'; else echo 'apiserver.pid does not name the run'"'"'s kube-apiserver; nothing sent'; fi
     ```
2. Check on the VM, in a VM shell without the `cd "$D"`. Each line prints its own verdict:
   ```bash
   if ss -ltnH '( sport = :2379 or sport = :2380 or sport = :6443 )' | grep -q .; then echo 'STOP: a port still listens'; else echo 'ports: free'; fi
   if pgrep -u "$(id -u)" -x 'etcd|kube-apiserver|kubectl' >/dev/null; then echo 'STOP: a server still runs'; else echo 'processes: none'; fi
   if test -e "$D"; then echo 'STOP: the run directory is still there'; else echo 'directory: gone'; fi
   if test -e ~/.kube/cache/discovery/127.0.0.1_6443; then echo 'STOP: a discovery cache outside the run directory'; else echo 'discovery cache: none'; fi
   ```
   Then, on the Mac, `~/.kube`'s state, taken as in R1 step 5, equals what R1 kept:
   ```bash
   : "${VM:?}" "${RUN:?}"
   ssh "$VM" 'if test -e ~/.kube; then ls -A ~/.kube; else echo absent; fi' | diff "$RUN/kube-before.txt" - && echo same
   ```
   A difference, or a `STOP` line, is recorded as a change outside `$D`, and the operator decides what is removed.
3. On the Mac:
   ```bash
   : "${VM:?}" "${RUN:?}"
   kill "$(cat "$RUN/ssh.pid")" 2>/dev/null || echo 'ssh: not running'
   for i in $(seq 5); do lsof -nP -iTCP:16443 -sTCP:LISTEN >/dev/null || break; sleep 1; done
   if lsof -nP -iTCP:16443 -sTCP:LISTEN >/dev/null; then echo 'STOP: the forward still listens'; else echo 'the forward is closed'; fi
   unset FARCAST_REALAPI_ENDPOINT FARCAST_REALAPI_CA_FILE FARCAST_REALAPI_TOKEN_FILE FARCAST_REALAPI_KUBECTL_NAMESPACE
   rm -rf "$RUN"; test ! -e "$RUN" && echo 'the run directory is deleted'   # the binaries, the token, the CA copy and the outputs
   ```
4. The operator may stop the VM.

## What the run decides

The run's scrubbed outcome is written into Results below and into the M2 design as §31. Each part decides one thing before M2.7b is built:
- **The same-patch annotation removal** (`TestAnnotationRemovalInTheSamePatchLeavesNoUpdateEntry`).
  - No `farcast`/Update entry: §6.3's single patch stands.
  - One: §31 pins a revision of §6.3, and the operator approves it before M2.7b. A second request is not built in advance. Once built, it runs again under the re-run rule.
- **The stale resourceVersion**, decided by the subtest `TestApplyRefusesAStaleResourceVersion/a_stale_resourceVersion` alone: its result line (R6's fourth grep) and its fact line.
  - 409 (the subtest passes): M2.7b builds step 3, the egress policy's resourceVersion precondition.
  - Any other answer (200 when the server ignores the body's resourceVersion): step 3 is not built, and risk 7 stays.
  - The other subtest, `a_Secret_deleted_since_it_was_read`, never gates step 3, so a top-level FAIL of the test is read through its subtests. Its answer, 404, 409, or a 2xx with whether the Secret was recreated, is recorded beside the decision. A 2xx means the precondition cannot tell a deleted policy from one never written: step 3's handling of a deleted object (the M2 design's A30-40) then has nothing to catch, and §31 says so.
  - *(2026-11-19, the re-run.)* Step 3 is built. If `a_stale_resourceVersion` or `the_egress_policy_at_a_stale_resourceVersion` does not pass, the latter on either half, its 409 or its apply at the stored resourceVersion, step 3 does not hold on this server: M2.7b is not committed, and the operator decides.
- **Row 104's mutant.**
  - Killed, by R6's rule (a `stuck field: ` line in `a_label_leaves`): row 104 is verified.
  - Survived, or failed anywhere but the stuck-field assertion: stop. The operator decides before M2.7b.
- **Every rendered stream applied twice.** Each refusal is recorded from its fact line (the stream, the document, the code, the reason and the causes' field paths), never from the FAIL line's server message. M2.7b fixes that renderer and regenerates its vectors, and the stream runs again under the re-run rule.
- **The generation moves.** The migration's own move, and the first apply's. A first apply that moves one confirms risk 3, and the billable walk's W3 watches it.
- **The Job re-apply:** a no-op, or a conflict.
- **The kernel's entries:** manager, operation and subresource per write; whether `/scale`'s `replicas` is tracked; and whether farcast's forced apply takes it back.
  - *(2026-11-19, the re-run.)* Whether a `technocore`/Update entry with subresource `scale` owns `spec.replicas` after the Scale to 2 settles §31's `/scale` inference. Whether farcast's Apply entry's time moved decides whether the kernel's stop can change P1 (c)'s adapted fact, which compares the kernel's adapted-at stamp with that time (the M2 design's A31-5). §31 records both beside Run 1, and ADR 0009's decision 3 note and the CLI README's `run` review follow them.
- **The wire facts:** metadata-only lists, gets and patches; the conflict cause's key; the kinds of typed and partial list items.
- **The kubectl variant:** equal, or how the seeds differ.
- **Any flag** that had to change from this runbook.
- *(2026-11-19, the re-run.)* **A FAIL among R6's counted tests stops the commit.** A FAIL among the twelve kube tests of `REALAPI` or in the cli test, `TestEveryRenderedStreamAppliesOnARealServer`, stops M2.7b's commit, and the operator decides. Its cause is recorded from fact lines only; a FAIL line is read, never copied. That includes:
  - a build or fetch policy whose generation still moves on the second apply;
  - `TestKernelWritesAreTrackedAsTechnocore/Scale` finding an entry that owns `spec.replicas` after the Scale to 0;
  - `TestMigrationLeavesAnotherManagersFieldAlone` finding realapi-other's entry not kept by the migration;
  - a failure in either reframed test's own code.

  A fix to any of them runs again under the re-run rule. Each part above that "decides one thing before M2.7b is built" describes Run 1.

**The re-run rule.** An outcome that changes code the suite exercises runs again by this runbook, with the operator's approval, before M2.7b is committed. That code is a renderer, §6.3's request shape, the suite's `migrateOne`, the emulated seed, or either reframed test's own code.
- The re-run's binaries are built from a named tree: an "M2.7a fix" commit on the branch, or M2.7b's tree before it is committed, recorded by its tree hash.
- Results and §31 record the second run beside the first.
- If no re-run happens, the records name each such path as not run against a real server.

**If the run cannot happen** (the VM is unavailable, the checksum does not match, or the server will not start), M2.7b is not built, and the question goes back to the operator.

---

## Results

### Run 1, 2026-11-18

**The run.**
- Built on the Mac from 2728e5f (M2.7a), on a clean tree whose hash is 8bde46e9807fbe09518e95bd04ff1fc1fdbc8c23. The servers ran as the VM's existing account.
- Versions: `kube-apiserver` v1.36.2, `etcd` 3.6.8, `kubectl` v1.36.2.
- The archive: 47,304,572 bytes. Its sha512 equalled the `.sha512` asset and, by the operator's comparison, `envtest-releases.yaml`.
- Every flag marked *to be confirmed on the VM* ran without error, and none had to change. `KUBERC=off`'s effect was not observed.
- **Teardown:** R9 first stopped at `STOP`, because `kube-apiserver` kept retrying its stopped etcd. A SIGKILL, which the operator approved, ended it; R9 then ran again and every check passed. R9 is corrected (dated note).
- **Agent-side variations, none changing what was tested:**
  - the forward ran as a background job of the agent's shell, by `exec`, with `-o ServerAliveInterval=30`;
  - `curl -s` and `scp -q`;
  - R1 also recorded the tree hash.

**Each test.** The kube suite counted 12 results, and the cli suite 1.

| Test | Result |
|---|---|
| `TestMigrationRemovesAFieldLaterDroppedFromTheManifest` | PASS, all seven cases; each object's only entry afterwards is `farcast/Apply` |
| `TestAnnotationRemovalInTheSamePatchLeavesNoUpdateEntry` | PASS: no `farcast`/Update entry, in the answer or the read-back, for a Deployment, a Secret or a ConfigMap |
| `TestRealAPIKeepsTheLiveListOnAnUndecodableRewrite` | PASS: 200, the live list kept; the same patch's annotation removal took effect |
| `TestMigrationIsResumable` | PASS: 409 at a moved resourceVersion; afterwards `farcast/Apply` and `realapi-other/Apply` |
| `TestFirstApplyAfterMigrationChangesNoGeneration` | PASS: the migration moved a Deployment's generation by one (the annotation); the first apply moved none and added no entry |
| `TestReapplyingAnUnchangedJobIsANoOp` | PASS: 200, forced and unforced, with nothing moved |
| `TestApplyRefusesAStaleResourceVersion` | PASS: a stale rv is answered 409 and nothing is written; a deleted Secret's rv is answered 201, recreating it |
| `TestMetadataOnlyListsCarryNoSecretData` | PASS: every metadata-only answer carries `apiVersion`, `kind` and `metadata` only |
| `TestStatusCauseWireName` | PASS: 409, cause type `FieldManagerConflict` |
| `TestTypedListItemsCarryNoKind` | PASS: typed items carry no kind; partial items are `PartialObjectMetadata` |
| `TestKernelWritesAreTrackedAsTechnocore` | FAIL in `Scale` only: the `/scale` write of 0 left no `technocore` entry. `SetRequests` and `SaveConfigMap` are `technocore/Update` |
| `TestMigrationLeavesAnotherManagersFieldAlone` | FAIL at its premise only: the kernel's `/scale` write of 0 left no entry to keep. The migration and the forced reset of `replicas` passed |
| `TestEveryRenderedStreamAppliesOnARealServer` | FAIL: all 23 streams applied twice with no refusal, but the build and fetch NetworkPolicies moved their generation on the second apply |
| Row 104's mutant | killed, in `a_label_leaves` only |
| `TestEmulatedSeedMatchesKubectl` | PASS, all four kinds equal |

**Two checks beyond this runbook**, made against the same server with the run's own kubectl:
- **`ingress: []`.** A NetworkPolicy carrying it moves its generation on every unchanged server-side apply; without it, it does not. The stored object has no `ingress` field either way. Only the build and fetch renderers emit it.
- **`/scale`.** Every write tried set 0; a non-zero count was not tried.
  - A `/scale` write of 0 records no entry for its writer, and it removes `spec.replicas` from every existing entry, the Apply entry included. Why *(inferred, not run)*: a Scale of 0 carries no `replicas` field, because autoscaling/v1 omits an empty one, so its writer owns nothing. *(2026-11-19: Run 2 does not bear this out. A write of 2, which carries the field, recorded no entry either.)*
  - The same merge PATCH on the Deployment itself is recorded as its manager's Update.
  - After a `/scale` write of 0, an unforced apply of `replicas` takes the field back with no conflict.
- **`kubectl get`** leaves out managed fields unless `--show-managed-fields` is given.

**What it decided** (the M2 design's §31):
- the migration's single patch stands;
- the egress policy's resourceVersion precondition is built in M2.7b, catching a concurrent change but not a deletion, which a 201 recreates;
- row 104 is verified;
- the build and fetch policies drop `ingress: []` in M2.7b;
- the kernel's `/scale` write, always of 0, is untracked. That changes two of this suite's tests in M2.7b, and `run`'s stopped fact not at all. Whether it moves the time `run`'s adapted fact reads was not recorded.

**Due: a re-run** on M2.7b's tree before its commit, because two renderers change and the egress policy's precondition changes `SplitStream`, `Apply` and the policy's renderer. *(2026-11-19: it ran as Run 2, below.)*
- It runs R0–R6, R8 and R9, with R1 step 7's uncommitted-tree path.
- Row 104's mutant (R1 step 6, R1 step 7's `-overlay` build, and R6's row-104 run and its grep) runs again only if M2.7b changes `upgradeOne`, and R7 only if the emulated seed changes. R8's grep then leaves out the outputs that were not made.
- Until it runs, these are not run against a real server: the build and fetch renderers' fix, the precondition's rv-carrying policy apply, and the two reframed tests. *(2026-11-19: all three ran in Run 2 and passed.)*

### Run 2, 2026-11-19

**The run.**
- Built on the Mac from M2.7b's tree before its commit, on HEAD 0397826. Its tree hash, taken through a throwaway index, is babeda086cf07d429a43e5c815684507cc49396f, and it was the same after the builds. The servers ran as the VM's existing account.
- Versions: `kube-apiserver` v1.36.2, `etcd` 3.6.8, `kubectl` v1.36.2.
- The archive: 47,304,572 bytes. Its sha512 equalled the `.sha512` asset and, by the operator's comparison, `envtest-releases.yaml`.
- Row 104's mutant and R7 were not run: M2.7b changes neither `upgradeOne` nor the emulated seed. `kube/migrate.go`, the seed files and the suite's seed functions are byte-identical to 2728e5f's.
- **Teardown:** R9, in its corrected order, passed at the first try. `kube-apiserver` exited on SIGTERM, then `etcd`. Every check passed.
- **Agent-side variations, none changing what was tested:**
  - `ssh -o BatchMode=yes`, `curl -sS` and `scp -q`;
  - the forward ran as a background job of the agent's shell;
  - R3's listing and R5's `ss` were printed as entry types, names and addresses only.

**Each test.** The kube suite counted 12 results, and the cli suite 1. All 13 passed.

| Test | Result |
|---|---|
| `TestMigrationRemovesAFieldLaterDroppedFromTheManifest` | PASS, all seven cases; each object's only entry afterwards is `farcast/Apply` |
| `TestAnnotationRemovalInTheSamePatchLeavesNoUpdateEntry` | PASS: no `farcast`/Update entry, in the answer or the read-back, for a Deployment, a Secret or a ConfigMap |
| `TestRealAPIKeepsTheLiveListOnAnUndecodableRewrite` | PASS: 200, the live list kept; the same patch's annotation removal took effect |
| `TestMigrationIsResumable` | PASS: 409 at a moved resourceVersion; afterwards `farcast/Apply` and `realapi-other/Apply` |
| `TestFirstApplyAfterMigrationChangesNoGeneration` | PASS: the migration moved a Deployment's generation by one; the first apply moved none and added no entry |
| `TestReapplyingAnUnchangedJobIsANoOp` | PASS: 200, forced and unforced, with nothing moved |
| `TestApplyRefusesAStaleResourceVersion` | PASS, all three subtests. A stale rv is answered 409 and nothing is written; a deleted Secret's rv is answered 201, recreating it. The egress policy as `run` renders it, split with `AllowResourceVersion`, is answered 409 at a stale rv with nothing written, then 200 and written at the stored one |
| `TestMetadataOnlyListsCarryNoSecretData` | PASS: every metadata-only answer carries `apiVersion`, `kind` and `metadata` only |
| `TestStatusCauseWireName` | PASS: 409, cause type `FieldManagerConflict` |
| `TestTypedListItemsCarryNoKind` | PASS: typed items carry no kind; partial items are `PartialObjectMetadata` |
| `TestKernelWritesAreTrackedAsTechnocore` | PASS: `Scale` to 0 left `farcast/Apply` the only entry, with no entry owning `spec.replicas`, and did not move that entry's time. `Scale` to 2 added no entry (no `technocore/Update` with subresource `scale`), and `replicas` read 2. `SetRequests` and `SaveConfigMap` are `technocore/Update` |
| `TestMigrationLeavesAnotherManagersFieldAlone` | PASS: `realapi-other`'s merge PATCH was recorded as `realapi-other/Update` owning `spec.replicas`; the migration left that entry unchanged; a forced `farcast` apply of `replicas` took the field back |
| `TestEveryRenderedStreamAppliesOnARealServer` | PASS: all 23 streams applied twice, with nothing moved on the second apply, the build and fetch policies included |

**What it decided** (the M2 design's §31):
- step 3's precondition holds on this server: the egress policy as `run` renders and splits it is refused at a stale resourceVersion, writing nothing, and applies at the stored one. `cluster.ApplyAt` itself, and `run`'s path through it, ran against kubetest only;
- the build and fetch policies no longer move on an unchanged apply;
- a `/scale` write of 2 is recorded under no manager, as one of 0 is, so Run 1's inferred cause does not explain it, and the cause is not known;
- on this server, a `/scale` write of 0 leaves the time of farcast's Apply entry as it was, so the kernel's stop does not change what `run`'s adapted fact reads;
- nothing in M2.7b has to change, and its commit is the operator's to make.
