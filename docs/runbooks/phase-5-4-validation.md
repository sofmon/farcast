# Phase 5.4 — Live Validation

**Status: ✅ complete, walked twice.** On 2026-10-06, from the operator's machine only, criterion 7 failed, and a defect found while fixing it meant criterion 4 had passed for the wrong reason. Three criteria genuinely needed a second machine and were recorded as unwalked. On 2026-11-10 [the consolidated Phase 5 walk](phase-5-session-a.md#results--walked-2026-11-10) walked every criterion except criterion 5, and criterion 7 only in part, with a second machine that held the keeper binary and nothing else. Every criterion has now passed. Twelve were walked on 2026-11-10. Criterion 5, the exhausted budget, rests on 2026-10-06 alone, and so does criterion 7's "still works until rekey" half. That walk closed Phase 5. Its record for 5.4 is [at the end](#walked-2026-11-10--session-a).

The 2026-10-06 walk shared instance `p54` with [the 5.3 re-walk](phase-5-3-validation.md), which is where the full record and all seven defects live — 5.4 criterion 3 needs an application recovering from `ErrStorageSealed`, so the applications had to be deployed anyway, and deploying them is most of the 5.3 re-walk. One cluster, both phases, about three hours and roughly $0.30.

**On 2026-10-06 the keeper was installed on the operator's own machine, by decision.** That proves the mechanics and says nothing about the property — the bundle sat beside the keyring it is supposed to be independent of. Criterion 2 was therefore left open, not passed, and criteria 8 and 9 with it, until 2026-11-10.

Phase 5.4 is the first time FarCast lets something other than a person hand a cluster its key material. Everything about it was designed from what could go wrong, and the unit suite proves each refusal bites under mutation — 18 mutations, every one caught, three of which exposed a test that was passing for the wrong reason. None of that was the same as watching a device re-seed a real keyholder that a real restart sealed — which the 2026-10-06 walk did, and which is also where it found that the documented remedy for a lost device rotates nothing.

Designed by [ADR 0008](../adr/0008-in-cluster-key-delivery.md)'s keeper fleet, on the unseal protocol 3.2 shaped for exactly this.

---

## Prerequisites

An instance installed, connected, keyholder deployed and unsealed at least once — the state [the 3.2 runbook](phase-3-2-validation.md) leaves behind. FatLine's PDB and second replica matter here rather than being a nicety: [ADR 0008](../adr/0008-in-cluster-key-delivery.md) makes them a **prerequisite** of the fleet, because no keeper re-seeds through a drained tunnel.

A second machine is genuinely needed for the parts that matter. A keeper installed on the operator's own laptop proves the mechanics and proves nothing about the property — the whole point is a device that holds a bundle and does not hold the keyring. The 2026-10-06 walk did exactly that, deliberately, and the three criteria it could not answer are the measure of what the shortcut costs.

Before anything billable: `./check.sh --model` passes at the commit being walked; record the commit and the check's summary line with the results.

**Every keeper enrolled before 2026-10-08 must be re-enrolled; none of them works against the current keyholder.** Two things changed, both described in [ADR 0008's *The in-cluster key pin, and a keeper bound to its bundle*](../adr/0008-in-cluster-key-delivery.md#the-in-cluster-key-pin-and-a-keeper-bound-to-its-bundle):

- **A keeper's leaf now binds its bundle.** `keeper enroll` issues the leaf with a second URI SAN, `urn:farcast:keeper-bundle:sha256:…`, a digest over the exact bundle the device is given. The keyholder refuses, with code `keeper-bundle`, a keeper push whose leaf binds no bundle or a different one. A leaf from before the change binds none, so every push it makes is refused.
- **The keyholder enforces an in-cluster key pin.** A ConfigMap, `datasphered-pin` in `farcast-system`, holds two flat sets of KEK ids: the keys a bundle must hold, and the keys no scope may write under any more. It holds no scope names. Every replica reads the pin at start and refuses, with code `below-pin`, a bundle that falls short of it, whether the replica is sealed or serving. `rotate` and `run` raise it.

FatLine's public tunnel also admits only the operator's leaf and keeper leaves now, and a keeper may open only the keyholder's stream route. An application's leaf is refused at the handshake.

### The walk probe

Several checks below need a client the CLI refuses to be: a keeper claiming the operator's authority, a device pushing a bundle that is not its own, a hand-made request with an intent of your choosing. Until 2026-10-08 there was no tooling for that, and "a hand-made request" was left to the walker. There is now a build-tagged probe, which is Go in this repository and adds no tool to the operator's machine. It runs from the checkout being walked:

```bash
# go test runs in the package's directory, so relative paths are resolved
# against FARCAST_WALK_CWD — the directory you run from.
probe() { FARCAST_WALK=1 FARCAST_WALK_INSTANCE="$INSTANCE" FARCAST_WALK_CWD="$PWD" "$@" \
  go test -mod=vendor -tags walk -count=1 -run TestWalkProbe -v ./farsight/cli/internal/cli/; }
# e.g. probe env FARCAST_WALK_PROBE=state

# As the enrolled device, with its own leaf and bundle from its newest packet.
# It is a function rather than one long variable, so it works in zsh too.
PACKET=./study.packet
asdevice() { probe env FARCAST_WALK_LEAF=packet:"$PACKET" FARCAST_WALK_BUNDLE=packet:"$PACKET" \
  FARCAST_WALK_PASSPHRASE_FILE=./pass "$@"; }
```

`FARCAST_WALK_PROBE` is one of `packet`, `state`, `push`, `seal`, `release-hold`, `tunnel` or `open`. The inputs are listed in the header of [`walkprobe_test.go`](../../farsight/cli/internal/cli/walkprobe_test.go): `FARCAST_WALK_LEAF` (`operator` | `store:<dir>` | `packet:<file>`), `FARCAST_WALK_BUNDLE` (`store:<dir>` | `packet:<file>` | `keys:<file>` | `keys:@live`, this machine's keyring), `FARCAST_WALK_PASSPHRASE_FILE`, `FARCAST_WALK_ORDINAL`, `FARCAST_WALK_INTENT`, `FARCAST_WALK_GENERATION`, `FARCAST_WALK_CERT` and `FARCAST_WALK_KEY` for `tunnel`, `FARCAST_WALK_PACKET` and `FARCAST_WALK_OBJECT` for `packet` and `open`, and `FARCAST_WALK_HOLD=1` to make `seal` a hold. It prints key ids and never key material. The packet and its passphrase file stay on the operator's machine after enrolment, so `packet:"$PACKET"` is the device's leaf and bundle there. `keeper enroll` refuses to overwrite its `--out` file. So each time the device is re-enrolled (section 5's `--budget 1`, section 6a), write the new packet to a new path, install it on the device, and set `PACKET` to it. [The consolidated walk runbook](phase-5-session-a.md) runs every check below in one session.

---

## 1. Does enrolment produce something only that device can use?

```bash
farcast keeper enroll "$INSTANCE" study-desktop --out ./study.packet --passphrase-file ./pass
```

**Expect:** a 0600 packet, a reported expiry about 90 days out, and — with one device enrolled — the line saying two are wanted.

Then check what is *not* in it. The packet is armored, so open it with the passphrase and confirm the CA key and the keyring are absent, and that the leaf's URI is `farcast://<instance>/keeper/study-desktop`. The unit suite asserts this; the walk should confirm it against a real instance's own material, because the assertion is only as good as the fixture behind it.

```bash
probe env FARCAST_WALK_PROBE=packet FARCAST_WALK_PACKET=./study.packet FARCAST_WALK_PASSPHRASE_FILE=./pass
```

**Expect:** two leaf URIs, `farcast://<instance>/keeper/study-desktop` and `urn:farcast:keeper-bundle:sha256:…`, a clientAuth-only extended key usage and an expiry about 90 days out. Then `the leaf binds the bundle it carries`, the bundle's scopes with their KEK ids, and `checked against this machine's keyring: no master key in the bundle`. The probe prints `FAIL` and fails if the packet carries a master key id or any private key besides the leaf's. *(Corrected 2026-10-08: this step said "open it" with nothing to open it with. The probe is that tool, and the second URI is new.)*

## 2. Does a device with no FarCast state become a keeper?

On the second machine, with no instance installed and no keyring:

```bash
farcast keeper install ./study.packet --passphrase-file ./pass
farcast keeper status
```

**Expect:** the install reports the backup exclusion was read back (on macOS), and `status` shows the device keeping the instance with a budget and an empty ledger.

This is the criterion that says a keeper is a *role*, not a second operator machine: nothing was installed, no cloud credential is present, and no kubeconfig exists.

## 3. Does it re-seed a genuinely restarted keyholder?

Seal the instance the way a node upgrade would — a restart, not an operator hold:

```bash
kubectl -n farcast-system delete pod datasphered-0
farcast storage state "$INSTANCE"        # replica 0 restart-sealed
```

On the keeper:

```bash
farcast keeper run "$INSTANCE" --once
```

**Expect:** `replica 0: re-seeded … (process <boot>)`, storage serving again, and a ledger entry naming the device and the boot.

Then the part worth watching: replica 0 rejoins the data Service's endpoints and the application keeps serving **without a restart**, exactly as after a manual unseal. *(Corrected 2026-10-08: with only `datasphered-0` deleted, replica 1 is still serving and the Service routes to it, so the application never sees `ErrStorageSealed` here. To watch an application recover from a seal, delete both Pods — and since the status-endpoint fix of 2026-10-08, an application with every replica sealed reports `sealed` rather than unavailable.)*

## 4. Does it refuse an operator hold?

```bash
farcast storage seal "$INSTANCE" --hold --reason "runbook"
farcast keeper run "$INSTANCE" --once
```

**Expect:** `hold — sealed by the operator: runbook`, no push attempted, and no ledger entry. Then confirm the second line of defence by pushing anyway with a hand-made request: the keyholder must refuse `restart-reseed` against a hold on its own, without relying on the device's good behaviour.

```bash
asdevice FARCAST_WALK_PROBE=push FARCAST_WALK_INTENT=restart-reseed FARCAST_WALK_ORDINAL=0
```

**Expect** `replica 0 REFUSED` with code `operator-hold`, and the hold still in place in `farcast storage state "$INSTANCE"`.

And then push the way a **modified** keeper would, because the honest request is not the threat. With the device's own leaf: `POST /v1/release-hold`, `POST /v1/seal?hold=true`, and an unseal claiming `intent=operator-unseal`. **Expect `403 permission` for all three, and the hold untouched.** Until 2026-10-06 all three succeeded: the control surface took its authority from the request, and the walk's own probe passed only because it declared its intent honestly.

```bash
asdevice FARCAST_WALK_PROBE=release-hold FARCAST_WALK_ORDINAL=0
asdevice FARCAST_WALK_PROBE=seal FARCAST_WALK_HOLD=1 FARCAST_WALK_ORDINAL=1
asdevice FARCAST_WALK_PROBE=push FARCAST_WALK_INTENT=operator-unseal FARCAST_WALK_ORDINAL=0
```

*(Added 2026-10-08: until now this step named no tool for the hand-made requests. The probe is that tool.)*

## 5. Does the budget refuse, and is the refusal legible?

Set a deliberately small budget at enrolment (`--budget 1`), re-seed once, then force a second restart.

**Expect:** the second cycle reports `budget-exhausted` with the count, the window and when the budget starts recovering — and **does not** re-seed. Confirm storage stays sealed, because a budget that quietly re-seeded anyway would be worse than none.

## 6. Does the audit see a solicitation?

This is the criterion the boot label exists for, and it needs a push that a restart did not justify.

The 2026-10-06 walk produced one by pushing a second time into a replica that was **serving** — and that push is now refused outright (`409 already-serving`): a re-seed only reaches a replica that restarted. That is the better outcome, a solicitation into a live process stopped rather than detected afterwards, and it is worth confirming first. With the device's own leaf, push `restart-reseed` at a serving replica: **expect `already-serving`, and the replica's keys untouched** (`farcast storage state` shows no replica flagged).

```bash
asdevice FARCAST_WALK_PROBE=push FARCAST_WALK_INTENT=restart-reseed FARCAST_WALK_ORDINAL=0   # replica 0 serving
```

The audit can still be walked, because a plain seal is indistinguishable from a restart by design. Re-seed a restarted replica; seal it with `farcast storage seal` — no `--hold`, and **no restart**; then let the keeper re-seed it again. Same process, two re-seeds.

```bash
farcast keeper status "$INSTANCE"
```

**Expect:** `PROCESS(ES) RE-SEEDED MORE THAN ONCE`, naming the boot and the count. A clean fleet must report *nothing to explain*; the walk should see both states, because a detector that only ever says "fine" has not been tested. A refused push is counted and reported separately, and never trips the flag.

## 6a. Does a keeper stand down once the instance holds keys it lacks?

*(Added 2026-10-08.)* A keeper's bundle carries the scopes that existed when it was enrolled. A keyholder replaces its whole set on a push, so a keeper re-seeding a restarted replica after a new application was deployed would leave that replica serving without the new application's keys, and refusing every request for it. The key pin is what lets a restarted replica, which holds nothing to compare against, know that.

Deploy a fresh set of applications, so `run` mints new scopes. `--namespace` mints them without editing the manifest:

```bash
farcast run "$INSTANCE" github.com/sofmon/farcast --manifest manifest/examples/sdk-demo/farcast --namespace sdk-demo-2
```

**Expect:** the new scopes minted with the key-loss warning, then handed to the serving replicas. The key pin is raised silently. A `warning: the instance's key pin was not raised` line means it was not, and the rest of this step cannot pass. `kubectl -n farcast-system get configmap datasphered-pin -o yaml` shows more `require` key ids than before, and no scope name. The output ends with a re-enrol list. It starts *"Every keeper's bundle predates …"* and gives one `farcast keeper enroll "$INSTANCE" study-desktop --out <path> --passphrase-file <path>` line per enrolled device.

Then, before re-enrolling anything, restart a replica and let the keeper look:

```bash
wc -l < "<the device's config dir>/keepers/$INSTANCE/ledger.jsonl"    # on the device: note the count
kubectl -n farcast-system delete pod datasphered-0
farcast storage state "$INSTANCE"                                      # replica 0 restart-sealed
farcast keeper run "$INSTANCE" --once                                  # on the device
```

**Expect** `this device: stale-bundle`, naming the key pin: the instance's pin refuses this device's bundle because an application was added. Then `replica 0: stale-bundle — restart-sealed, and not re-seeded`, pointing to that line, and exit status `3` (`echo $?` on the device). *(Updated 2026-11-10: the pin's verdict is printed once per pass, and `--once` exits by outcome.)* Expect also no push, the device's ledger line count unchanged, and replica 0 still `restart-sealed`. Then recover it from the operator's machine with `farcast storage unseal "$INSTANCE"`. Re-enrol and reinstall the device from the list `run` printed before going on. Its next packet binds the new bundle. `enroll` refuses to overwrite an existing file, so give it a new `--out`, such as `./study-2.packet`, and set `PACKET` to it so `asdevice` presents the device as it now is.

## 7. Does revocation say what it does not do?

```bash
farcast keeper revoke "$INSTANCE" study-desktop -y
```

**Expect:** the report says it did not reach the cluster, names the sequence that retires the bundle — `farcast storage key rotate`, `farcast storage key rekey`, then re-enrolling every keeper kept — and says what that does not undo: anything already read, the names, and a restarted replica re-seeded by the device until the rotation writes the key pin — after which every replica refuses its bundle (`below-pin`), for as long as a replica has the pin loaded (`none loaded` in `storage state`, restored by `storage key pin`). *(Updated 2026-11-10: the text predated the pin.)* Then confirm the uncomfortable half: before the rotation, the revoked device can **still** re-seed, because its certificate is still valid. That is what the ADR says, and the walk should demonstrate it rather than assume the message is enough.

Then retire what the device holds, and prove it from the bundle's side rather than the command's:

```bash
farcast storage key rotate "$INSTANCE" -y      # every scope; serving replicas take the new keys
farcast storage key rekey "$INSTANCE" -y       # moves stored objects onto them
```

**Expect:** rotate reports a new KEK for **every application scope**, not only the instance's own, and that all replicas hold them and write under them; rekey reports a non-zero `rewritten` count. Then the half that matters for a fleet: with one replica made unreachable — its State call must fail; a replica caught mid-restart answers restart-sealed, which is a different case (below) — rotate must report the new keys **held on some and in use on none, this machine included**, and exit non-zero: it hands a rotation over in two steps, and activates only once every serving replica holds the new key and still holds it when asked again. `farcast storage key list` must show each application scope's active key unchanged from before that rotate. `farcast storage unseal` run now must **not** make the new keys active (it hands over this machine's keyring, in which they are held). Then, with every replica answering, run rotate once more: it must report all replicas holding and writing under the newest keys, and `farcast storage state` must flag no replica. Finally, copy a `keys.yaml` from before the rotation over this machine's and run `farcast storage unseal`: it must **refuse** (this keyring is behind the instance's) and push nothing — restore the current file afterwards. The sealed cases: with one replica restart-sealed and the other serving, rotate finishes and reports one replica sealed, to receive the keys on the next unseal; with **every** replica sealed it must stop at the hold, say so, and leave each scope's active key unchanged — with none serving, nothing would stop a keeper re-seeding the keys from before. And with one replica sealed and the other unreachable, `farcast storage unseal` must leave the sealed one sealed and name `--unchecked`; with `--unchecked` it unseals it, and still does not push the unreachable one. Then open an object with the material the revoked device's packet carries: it must fail (`blob is sealed under a key the keyring does not hold`). The 2026-10-06 walk ran this as written then — `storage rekey` — and found the command did not exist and the real pair rewrote 0 of 4 objects; this is the re-walk of that.

*(Added 2026-10-08: how to do the two hand-made parts of this step.)*

**Making one replica unreachable.** Scale the keyholder down by one:

```bash
kubectl -n farcast-system scale statefulset datasphered --replicas=1
farcast storage state "$INSTANCE"      # replica 1: an error, not a phase
```

The CLI keeps asking for ordinal 1, because it reads the replica count recorded in the instance's metadata and not the cluster's. FatLine's relay then cannot dial `datasphered-1`. It logs `dial_failed` and the CLI sees a `502`, which is the failed State call the step needs. When the unreachable-replica checks are done:

```bash
kubectl -n farcast-system scale statefulset datasphered --replicas=2
```

That recreates replica 1, restart-sealed, which is the starting point of the sealed cases above. **Caveat:** scaling down destroys replica 1's process and its keys. It is not just silent. So this tests the CLI's handling of a replica that does not answer. It does not test a replica that is silent to the operator while still serving applications, and nothing here can produce that case by hand.

**Opening an object with the revoked device's keys,** after `rekey` has rewritten it:

```bash
probe env FARCAST_WALK_PROBE=open FARCAST_WALK_PACKET="$PACKET" FARCAST_WALK_PASSPHRASE_FILE=./pass \
  FARCAST_WALK_OBJECT='<an application object rekey rewrote, e.g. app/sdk-demo/alpha/hello>'
```

**Expect** `ErrUnknownKey — the object is under a key this device never held`. The device can still compute the object's stored name, since names are not rotated, but it cannot open the object. `READ … this device's keys still open it` is the failure this step exists to catch.

### 7a. The key pin, with no serving replica left, and the bundle a keeper leaf is bound to

*(Added 2026-10-08.)* Run this after the rotation has finished with every replica answering, and before the device is re-enrolled, so that `$PACKET` still holds its pre-rotation bundle. Before the pin existed, a replica that had restarted held nothing to compare a bundle against. With the whole fleet restarted at once, a keeper enrolled before a rotation re-seeded the retired keys and nothing refused it. Seal the fleet that way:

```bash
kubectl -n farcast-system delete pod -l app.kubernetes.io/name=datasphered
farcast storage state "$INSTANCE"                       # both restart-sealed; none serving
farcast keeper run "$INSTANCE" --once                   # on the device
asdevice FARCAST_WALK_PROBE=push FARCAST_WALK_INTENT=restart-reseed FARCAST_WALK_ORDINAL=0
```

**Expect** the keeper to report `this device: stale-bundle`, naming the key pin, once; each replica's `stale-bundle` line to point to it; exit status `3`; and no push. That is the device behaving. The probe then pushes anyway, as a device that does not behave would. Expect `replica 0 REFUSED` with code `below-pin`. That is the keyholder refusing on its own, with no serving replica to compare against. Both replicas stay `restart-sealed`.

Then, still with both sealed, present the device's leaf with a bundle that is current and satisfies the pin but is not the one the leaf was issued for. The operator's own keyring will do:

```bash
probe env FARCAST_WALK_PROBE=push FARCAST_WALK_LEAF=packet:"$PACKET" FARCAST_WALK_PASSPHRASE_FILE=./pass \
  FARCAST_WALK_BUNDLE=keys:@live \
  FARCAST_WALK_INTENT=restart-reseed FARCAST_WALK_ORDINAL=0
```

**Expect** `replica 0 REFUSED` with code `keeper-bundle`. The leaf's `urn:farcast:keeper-bundle:sha256:…` names one bundle, and a stolen keeper leaf can push only that bundle, which the pin refuses after a rotation. Then `farcast storage unseal "$INSTANCE"` brings both replicas back on the operator's keys. Re-enrol any keeper being kept.

## 8. Does the device survive its own restart, and the platform's?

Reboot the keeper. **Expect** `keeper run` to resume with its ledger and budget intact, and the material still at 0600 inside a 0700 directory with the exclusion still set.

## 9. What the fleet costs

Two keepers double the bundles at rest and double the solicitation endpoints. Confirm `keeper status` on the operator's machine lists both devices and their expiries, and that budgets are read as a **fleet** total rather than per device — ADR 0008 finding 6 says the reconciliation watches the aggregate.

---

## Criteria

| # | Criterion | Result |
|---|---|---|
| 1 | An enrolment packet carries a bundle and a device leaf, and neither the keyring nor the CA key | ✅ master key ids absent from the bundle; leaf `farcast://p54/keeper/study-vm`, clientAuth only. **Re-confirmed 2026-11-10** (S9): `farcast://p5a/keeper/device-a` and the `urn:farcast:keeper-bundle:sha256:…` URI, clientAuth, "the leaf binds the bundle it carries", and no master key |
| 2 | A machine with no FarCast state becomes a keeper from the packet alone | ✅ **walked 2026-11-10** (S9), on device A, an Ubuntu VM with the keeper binary and no gcloud, kubectl, kubeconfig or FarCast state. Install was refused without `--accept-backup-risk` and accepted with it. After `rm a.packet pass` the device held the 0700 keeper directory, five 0600 files, and nothing else. *(2026-10-06: not walked — installed on the operator's machine, which holds the keyring.)* |
| 3 | A restart-sealed replica is re-seeded unattended, and an application recovers without restarting | ✅ `re-seeded … (process bbf993a8)`; `alpha` kept reading at restart count 0. **Re-confirmed 2026-11-10** (S10), on device A: `replica 0: re-seeded …`, alpha at 0 restarts, A's ledger at 1 of 8 and the operator's unchanged. Replica 1 served throughout, the case section 3's note describes. Each re-seed was a `keeper run --once` pass that the walker started; the long-running mode (the same pass every 15 minutes) was not walked |
| 4 | An operator hold is refused by the device **and** by the keyholder independently | ✅ **walked 2026-11-10** (S13), now for the right reason. A's keeper reported the hold on both replicas, pushed nothing and wrote no ledger line. Pushed anyway as A: `restart-reseed` got `409 operator-hold`, and `release-hold`, `seal --hold` and an `operator-unseal` claim each got `403 permission`, with the hold still in place. Authority comes from the role on the leaf, not from the request. *(2026-10-06: passed for the wrong reason — the keyholder refused a push that declared `restart-reseed`, but took that intent from the request, so a keeper claiming `operator-unseal`, or calling `release-hold`, was obeyed. Fixed 2026-10-06.)* |
| 5 | An exhausted budget refuses, legibly, and leaves storage sealed | ✅ `budget-exhausted — 2 of 2 in the last 30 days, none expires before 2026-11-05`; replica stayed sealed. Walked 2026-10-06 and **not re-walked on 2026-11-10**: device B's `--budget 1` there only made up the fleet total, and B was re-enrolled before it ever pushed |
| 6 | `keeper status` reports a clean fleet as clean, and flags a process re-seeded twice | ✅ both states seen — `nothing to explain`, then `1 PROCESS(ES) RE-SEEDED MORE THAN ONCE: process 4b94f94a re-seeded 2 times`. **Re-confirmed 2026-11-10** (S10, S13): `nothing to explain`, then the double re-seed flagged `1 PROCESS(ES) RE-SEEDED MORE THAN ONCE`; a re-seed pushed at a serving replica got `409 already-serving` |
| 7 | `revoke` states its limits, and a revoked device demonstrably still works until rekey | ✅ **walked 2026-11-10** (S15). 7a: `revoke` said it did not reach the cluster or invalidate the certificate, and named rotate, rekey and re-enrolment. 7b–7f as written, except that 7b's message was not captured (Session A's deviation 2). 7g: `rewritten: 5`. 7h: A's revoked packet got `ErrUnknownKey` on an object rekey rewrote. The "still works" half was not repeated as a re-seed: A's revoked leaf still opened the keyholder's route (S17), and after the rotation its re-seed got `409 below-pin` (S16.3). *(2026-10-06: first half ✅; the **rekey half failed** — see below. Fixed 2026-10-06.)* |
| 8 | A rebooted keeper resumes with its ledger, budget and file modes intact | ✅ **walked 2026-11-10** (S13). After device A was rebooted, its `keeper status` showed the ledger and the budget (1 of 8) intact, all six files 0600 in 0700 directories (the five from S9 plus the ledger that S10 created), and A went on to re-seed in S13. Linux has no exclusion to check (`tmutil` is macOS); device B, on macOS, read its exclusion back at install, and B was not rebooted. *(2026-10-06: partly — modes only, no reboot.)* |
| 9 | Two devices are visible as a fleet, with expiries, and their budgets read as a total | ✅ **walked 2026-11-10** (S13, S17). `keeper status` listed device-a and device-b, each with `until <date>` and its budget, and `fleet budget: up to 9 reseeds per 30 days across 2 device(s)`. Straight after A's revocation (S15 7a): A `REVOKED`, and `up to 1 … across 1 device(s)`, because B still had budget 1. After B was re-enrolled at the default budget (S16.5): `up to 8 … across 1 device(s)` (S17). The total itself was added on 2026-11-09, before the walk. *(2026-10-06: not walked — needed a second device.)* |
| 10 | Teardown leaves no billable resource — verified independently, not from local state | ✅ all eight resource classes zero against the cloud APIs. **Re-confirmed 2026-11-10** (S19): eleven resource classes zero against the cloud APIs, and the project's firewall rules and service accounts exactly as before install |
| 11 | A restarted replica refuses a pre-rotation bundle with no serving replica left (the key pin, `below-pin`) | ✅ **walked 2026-11-10** (S16.2–3; section 7a). With both replicas restart-sealed and none serving, revoked A's push of its own pre-rotation bundle got `409 below-pin`, and the replica stayed sealed. A's own keeper reported `stale-bundle`, naming the pin, and pushed nothing. *(Added 2026-10-08.)* |
| 12 | A keeper leaf pushing a bundle other than its own is refused (`keeper-bundle`) | ✅ **walked 2026-11-10** (S13, S16.4; section 7a). A's leaf with the operator's keyring as its bundle got `403 keeper-bundle`, with one replica sealed in S13 and with both in S16.4. *(Added 2026-10-08.)* |
| 13 | After a `run` that mints a scope, a keeper refuses to re-seed a restarted replica (`stale-bundle`, naming the pin), writes no ledger entry, and `storage unseal` recovers the replica | ✅ **walked 2026-11-10** (S11.3–6; section 6a). `run` printed the re-enrol list. After replica 0 restarted, A's keeper reported `stale-bundle` naming the key pin, its ledger stayed at one line, and replica 0 stayed `restart-sealed` until `storage unseal` recovered it. *(Added 2026-10-08.)* |

### Criterion 7 is the one that failed

Both documented halves behaved: `revoke` said plainly that it *"did not reach the cluster, and it did not invalidate the device's certificate"*, named `storage rekey`, and warned that rekey *"does not reach backwards"*. A device revoked seconds earlier then re-seeded a live replica, exactly as the ADR says it would.

The remedy is what failed. `storage key rekey` rotated **no key at all** and re-encrypted **0 of 4 objects**, because every object lives under a per-application scope it cannot address. The bundle a lost device holds is untouched by the command an operator is told to run. Full measurements in [the 5.3 re-walk's finding 5](phase-5-3-validation.md#5-storage-key-rekey-cannot-retire-what-a-keeper-device-holds--fixed-walked-2026-11-10).

Until that is fixed, **revocation has no teeth**: the only bound on a lost keeper is its certificate's own 90-day expiry.

**Fixed 2026-10-06, re-walked 2026-11-10.** `rotate` now gives every scope a new KEK and hands it to serving replicas; `rekey` rewrites each object under its own scope's key and refuses to move any until every replica holds it; `revoke` prints that sequence. A unit test drives exactly the walk's failure — the material a keeper enrolled before the rotation would carry — and proves it opens none of the applications' objects afterwards. The re-walk is the procedure in section 7 above. What it still cannot do is stated in the command and in [ADR 0008](../adr/0008-in-cluster-key-delivery.md#what-the-2026-10-06-walk-found-and-what-changed): names stay computable, and a restarted replica can still be re-seeded with old keys by a device that is not honest, until the in-cluster key-id pin exists. *(Updated 2026-10-08: the pin exists now, together with the keeper-bundle binding. Section 7a and criteria 11–12 are its walk. Names stay computable.)* *(Re-walked 2026-11-10: `rekey` rewrote 5 objects, and the revoked device's packet could not open the one it was tried on (`ErrUnknownKey`). See [below](#walked-2026-11-10--session-a).)*

### What a second machine owed — paid 2026-11-10

Criteria 2, 8 and 9. On Linux, `keeper install` refuses without `--accept-backup-risk` — there is no single backup pipeline it can verifiably exclude from, so it will not promise what nobody checked. Walking that refusal, and then the no-cloud-credential inventory on a device that holds nothing else, is what criterion 2 actually asks for. The macOS exclusion path was confirmed here (`backup excluded, and the exclusion was read back`), so the remaining gap was the device property, not the mechanism.

*(Paid 2026-11-10, on an Ubuntu VM: the refusal without `--accept-backup-risk`, the inventory, the reboot, and a two-device fleet. See below.)*

### Walked 2026-11-10 — Session A

Every check above except section 5's, and criterion 7's re-seed half, was run in [the consolidated Phase 5 walk](phase-5-session-a.md#results--walked-2026-11-10), against instance `p5a` at commit `554d4df`, released the same day. The S-numbers in the table are that runbook's steps. Device A was an Ubuntu 26.04 LTS arm64 virtual machine, driven over SSH, holding the keeper binary and nothing else. Device B was the operator's own machine. It was enrolled to make a fleet of two, and later re-seeded the keyholder after A was revoked.

- **Criteria 4 and 7 were walked on their 2026-10-06 fixes.** A keeper's leaf can no longer release a hold, place one, or claim its way through one. Rotate and then rekey retired what A held: its packet could not open an object that rekey rewrote.
- **Criteria 2, 8 and 9 had their second machine.** What the walk could not show is a backup exclusion on the device that was rebooted. Linux has none to verify, so A holds its bundle under `--accept-backup-risk`, and its record says so. B confirmed the macOS exclusion at install, but B was not rebooted.
- **Criteria 11–13, the key pin and the bundle-bound leaf, were walked for the first time.** With nothing serving, the pin refused a pre-rotation bundle. The leaf refused a bundle not its own, with one replica sealed and with both.
- **Two things were not repeated.** Criterion 5, because nothing in Session A exhausts a budget; the 2026-10-06 result stands. And criterion 7's first half as a re-seed: A was revoked and the rotation followed it, so the walk showed the refusal after a rotation rather than a revoked device still re-seeding before one.

Nothing failed a criterion. The keeper's own output misleads in three places, and `revoke`'s text in a fourth. Each is recorded in [Session A's findings](phase-5-session-a.md#results--walked-2026-11-10), and none is fixed yet:

- **An unreadable pin is filed under `stale-bundle`** (S16.8). The bundle is not stale, and re-enrolling, the remedy that label points to, changes nothing.
- **The fleet-wide pin verdict is printed under each replica**, so replica 1's line reads "replica 0's key pin refuses…" (S16).
- **`keeper run --once` exits 0 when it refused** (S11.5), so cron or systemd cannot tell a device that kept the instance from one that no longer can.
- **`keeper revoke`'s text predates the pin** (S15 7a). It says the device can still re-seed a restarted replica with its old keys until its certificate expires. Since the pin, that holds only until a rotation retires those keys, and S16.3 shows the refusal.

*(Fixed 2026-11-10, not yet walked.)* An unreadable pin is reported as `pin-unreadable`, naming `farcast storage key pin`. The pin's verdict is printed once per pass, as `this device: stale-bundle — …`, naming no replica — and also when every replica is still serving. `keeper run --once` exits `0` kept (a hold included), `3` when a person must act, `4` when the pass did not finish; the long-running mode never exits on these. `revoke`'s text says the device can re-seed only until the rotation writes the pin, and that the pin protects only while a replica has it loaded. The next walk re-checks S11.5, S16 and S16.8 against the steps above.
