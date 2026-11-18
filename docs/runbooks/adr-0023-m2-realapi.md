# ADR 0023 M2 — the real-API suite: what kubetest cannot settle

From [ADR 0023](../adr/0023-one-download-farcast.md) M2.7b, which is not built at the commit this runbook is written against, farcast is to write to a cluster with its own server-side apply, not kubectl. An instance an older farcast wrote is then migrated once: each object's client-side apply entry is renamed to farcast's, and kubectl's last-applied annotation is removed. farcast's tests run against `kubetest`, a local emulation of the API server. kubetest does not track ownership field by field, does not default, and follows no generation rule of a real server. So it cannot show whether a migrated object keeps a field farcast later drops, whether the first apply after a migration rolls a workload, or what the server records for a patch. This runbook runs farcast's real-API suite against a real `kube-apiserver` and `etcd`, from envtest v1.36.2. They run on the keeper VM, listen only on that VM's loopback, and are reached from the Mac through `ssh -L`. The run sits between M2.7a and M2.7b: the migration is built only after it.

**Status.** *Written 2026-11-18 against M2.7a; not run.*

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
  - `$K` is kubectl as this run uses it: its own kubeconfig, and its discovery and HTTP caches under `$D`, so nothing lands in the account's `~/.kube/cache`. `KUBERC=off` and `--cache-dir` are *to be confirmed on the VM*.

A flag below taken from documentation, and not yet run, is marked *to be confirmed on the VM*. A flag that has to change is recorded in §31, and this runbook is corrected in place with a dated note.

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
- what this exposes (above).

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
   - Under it, the label `farcast.sofmon.com/instance`, which the subtest `a label leaves` drops in its v2, is owned by no manager after the migration. So v2's forced apply should leave it *(inferred from server-side apply's removal rule, which removes only a field the applier owned)*, and that subtest fails at `stuck field: `.
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
- The sidecar's name, `….tar.gz.sha512`, is *to be confirmed on the VM*. If its download fails, the step ends there, with the computed size and sha512 already printed. Nothing is extracted: the operator decides, from the other two values, whether the run goes on, and §31 records that the sidecar was not read.
- **The operator compares three values** before anything is extracted:
  - the computed sha512;
  - the sidecar's;
  - the full value for v1.36.2 linux/arm64 in controller-tools' `envtest-releases.yaml`, read in their own browser.

  All three must be equal, beginning `2d72ee985a8e262a` and ending `c6d824dd9c6649ac`.
- **The size is a sanity check only; the sha512 binds.** `stat` prints bytes. GitHub's 45.1 MB is about 45.1 million bytes if its MB is decimal, and about 47.3 million if it is binary, as GitHub's asset sizes are believed to be *(inferred)*. A byte count far outside that range is a mismatch.
- **On any mismatch:** stop, `rm -rf "$D"`, and record it.

## R3. Extract

1. `tar -tvzf envtest-v1.36.2-linux-arm64.tar.gz` must list only the regular files `controller-tools/envtest/kube-apiserver`, `etcd` and `kubectl`, and their directories. The prefix is *to be confirmed on the VM*. Any absolute path, any `..`, any link, or any other entry stops the run.
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
- The kubeconfig names the server `https://127.0.0.1:6443`, the certificate R5 makes, and a user whose `tokenFile` is `$D/token`. So it holds no token. `tokenFile` is *to be confirmed on the VM*.
- The static-token file's format (`token,user,uid,group`) and `system:masters` bypassing RBAC under `--authorization-mode RBAC` are from documentation, *to be confirmed on the VM*.

## R5. etcd, then kube-apiserver, on 127.0.0.1

As envtest starts them, with its client certificates replaced by a static token. Every flag here is *to be confirmed on the VM*.
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
- **The stale-rv subtests.** A subtest's result is indented, so the first grep does not show it; the fourth does. `a_stale_resourceVersion` decides step 3 (What the run decides). `a_Secret_deleted_since_it_was_read` only records.
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
- kubectl's apply is client-side by default at 1.36, so each object should show `kubectl-client-side-apply`/Update. That is *to be confirmed on the VM*.
- If the two seeds differ, the test's `fact:` lines say how. The emulated seed is then corrected, and the stuck-field cases run again under the re-run rule (What the run decides).

## R8. Results, scrubbed

This runbook's Results and the M2 design's §31 hold only:
- the commit the binaries were built from (R1 step 7);
- the versions, the archive's byte count, and that its sha512 matched both published values;
- each test's PASS or FAIL, `TestApplyRefusesAStaleResourceVersion`'s two subtests' included, and whether row 104's mutant was killed;
- the facts each test records: managers, operations, subresources, field paths, HTTP codes, kinds and generation moves;
- each refusal of a rendered stream, from its fact line: the stream, the document, the code, the reason and the causes' field paths.

The fact lines are pulled out on the terminal only, with nothing written:
```bash
: "${RUN:?}"
grep -h ': fact: ' "$RUN/kube.out" "$RUN/cli.out" "$RUN/row104.out" "$RUN/kubectl.out" | sed -E 's/^ *[a-z_]+\.go:[0-9]+: //'
```
Each record follows the scrub rule (Throughout).

## R9. Teardown

1. On the VM, in one shell:
   ```bash
   for p in apiserver etcd; do kill "$(cat "$D/$p.pid")" 2>/dev/null || echo "$p: not running"; done
   for i in $(seq 30); do pgrep -u "$(id -u)" -x 'etcd|kube-apiserver|kubectl' >/dev/null || break; sleep 1; done
   if pgrep -u "$(id -u)" -x 'etcd|kube-apiserver|kubectl'; then echo 'STOP: still running; nothing deleted'; exit 1; fi
   cd ~ && rm -rf "$D" && echo 'the run directory is deleted'
   ```
   - Each `kill` that finds its process gone says so and goes on, so a server that already exited (as when it would not start) still leaves the other to be stopped and `$D` to be deleted.
   - `$D` is deleted only when none of the three runs any more. On a `STOP` line, the operator decides what is stopped, and this step runs again.
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
- **Row 104's mutant.**
  - Killed, by R6's rule (a `stuck field: ` line in `a_label_leaves`): row 104 is verified.
  - Survived, or failed anywhere but the stuck-field assertion: stop. The operator decides before M2.7b.
- **Every rendered stream applied twice.** Each refusal is recorded from its fact line (the stream, the document, the code, the reason and the causes' field paths), never from the FAIL line's server message. M2.7b fixes that renderer and regenerates its vectors, and the stream runs again under the re-run rule.
- **The generation moves.** The migration's own move, and the first apply's. A first apply that moves one confirms risk 3, and the billable walk's W3 watches it.
- **The Job re-apply:** a no-op, or a conflict.
- **The kernel's entries:** manager, operation and subresource per write; whether `/scale`'s `replicas` is tracked; and whether farcast's forced apply takes it back.
- **The wire facts:** metadata-only lists, gets and patches; the conflict cause's key; the kinds of typed and partial list items.
- **The kubectl variant:** equal, or how the seeds differ.
- **Any flag** that had to change from this runbook.

**The re-run rule.** An outcome that changes code the suite exercises runs again by this runbook, with the operator's approval, before M2.7b is committed. That code is a renderer, §6.3's request shape, the suite's `migrateOne`, or the emulated seed.
- The re-run's binaries are built from a named tree: an "M2.7a fix" commit on the branch, or M2.7b's tree before it is committed, recorded by its tree hash.
- Results and §31 record the second run beside the first.
- If no re-run happens, the records name each such path as not run against a real server.

**If the run cannot happen** (the VM is unavailable, the checksum does not match, or the server will not start), M2.7b is not built, and the question goes back to the operator.

---

## Results

Not run.
