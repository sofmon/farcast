# Phase 5.4 — Live Validation

**Status: walked 2026-10-06, from the operator's machine only.** Criterion 7 failed, and a defect found while fixing it means criterion 4 passed for the wrong reason; both are fixed and **not re-walked**. Three criteria genuinely need a second machine and are recorded as unwalked.

The walk shared instance `p54` with [the 5.3 re-walk](phase-5-3-validation.md), which is where the full record and all seven defects live — 5.4 criterion 3 needs an application recovering from `ErrStorageSealed`, so the applications had to be deployed anyway, and deploying them is most of the 5.3 re-walk. One cluster, both phases, about three hours and roughly $0.30.

**The keeper was installed on the operator's own machine, by decision.** That proves the mechanics and says nothing about the property — the bundle sat beside the keyring it is supposed to be independent of. Criterion 2 is therefore open, not passed, and criteria 8 and 9 with it.

Phase 5.4 is the first time FarCast lets something other than a person hand a cluster its key material. Everything about it was designed from what could go wrong, and the unit suite proves each refusal bites under mutation — 18 mutations, every one caught, three of which exposed a test that was passing for the wrong reason. None of that was the same as watching a device re-seed a real keyholder that a real restart sealed — which the 2026-10-06 walk did, and which is also where it found that the documented remedy for a lost device rotates nothing.

Designed by [ADR 0008](../adr/0008-in-cluster-key-delivery.md)'s keeper fleet, on the unseal protocol 3.2 shaped for exactly this.

---

## Prerequisites

An instance installed, connected, keyholder deployed and unsealed at least once — the state [the 3.2 runbook](phase-3-2-validation.md) leaves behind. FatLine's PDB and second replica matter here rather than being a nicety: [ADR 0008](../adr/0008-in-cluster-key-delivery.md) makes them a **prerequisite** of the fleet, because no keeper re-seeds through a drained tunnel.

A second machine is genuinely needed for the parts that matter. A keeper installed on the operator's own laptop proves the mechanics and proves nothing about the property — the whole point is a device that holds a bundle and does not hold the keyring. The 2026-10-06 walk did exactly that, deliberately, and the three criteria it could not answer are the measure of what the shortcut costs.

---

## 1. Does enrolment produce something only that device can use?

```bash
farcast keeper enroll "$INSTANCE" study-desktop --out ./study.packet --passphrase-file ./pass
```

**Expect:** a 0600 packet, a reported expiry about 90 days out, and — with one device enrolled — the line saying two are wanted.

Then check what is *not* in it. The packet is armored, so open it with the passphrase and confirm the CA key and the keyring are absent, and that the leaf's URI is `farcast://<instance>/keeper/study-desktop`. The unit suite asserts this; the walk should confirm it against a real instance's own material, because the assertion is only as good as the fixture behind it.

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

Then the part worth watching: an application that was receiving `ErrStorageSealed` recovers **without a restart**, exactly as it does after a manual unseal.

## 4. Does it refuse an operator hold?

```bash
farcast storage seal "$INSTANCE" --hold --reason "runbook"
farcast keeper run "$INSTANCE" --once
```

**Expect:** `hold — sealed by the operator: runbook`, no push attempted, and no ledger entry. Then confirm the second line of defence by pushing anyway with a hand-made request: the keyholder must refuse `restart-reseed` against a hold on its own, without relying on the device's good behaviour.

And then push the way a **modified** keeper would, because the honest request is not the threat. With the device's own leaf: `POST /v1/release-hold`, `POST /v1/seal?hold=true`, and an unseal claiming `intent=operator-unseal`. **Expect `403 permission` for all three, and the hold untouched.** Until 2026-10-06 all three succeeded: the control surface took its authority from the request, and the walk's own probe passed only because it declared its intent honestly.

## 5. Does the budget refuse, and is the refusal legible?

Set a deliberately small budget at enrolment (`--budget 1`), re-seed once, then force a second restart.

**Expect:** the second cycle reports `budget-exhausted` with the count, the window and when the budget starts recovering — and **does not** re-seed. Confirm storage stays sealed, because a budget that quietly re-seeded anyway would be worse than none.

## 6. Does the audit see a solicitation?

This is the criterion the boot label exists for, and it needs a push that a restart did not justify.

The 2026-10-06 walk produced one by pushing a second time into a replica that was **serving** — and that push is now refused outright (`409 already-serving`): a re-seed only reaches a replica that restarted. That is the better outcome, a solicitation into a live process stopped rather than detected afterwards, and it is worth confirming first. With the device's own leaf, push `restart-reseed` at a serving replica: **expect `already-serving`, and the replica's keys untouched** (`farcast storage state` shows no replica flagged).

The audit can still be walked, because a plain seal is indistinguishable from a restart by design. Re-seed a restarted replica; seal it with `farcast storage seal` — no `--hold`, and **no restart**; then let the keeper re-seed it again. Same process, two re-seeds.

```bash
farcast keeper status "$INSTANCE"
```

**Expect:** `PROCESS(ES) RE-SEEDED MORE THAN ONCE`, naming the boot and the count. A clean fleet must report *nothing to explain*; the walk should see both states, because a detector that only ever says "fine" has not been tested. A refused push is counted and reported separately, and never trips the flag.

## 7. Does revocation say what it does not do?

```bash
farcast keeper revoke "$INSTANCE" study-desktop -y
```

**Expect:** the report says it did not reach the cluster, names the sequence that retires the bundle — `farcast storage key rotate`, `farcast storage key rekey`, then re-enrolling every keeper kept — and says what that does not undo: anything already read, the names, and a restarted replica re-seeded by the device before its certificate expires. Then confirm the uncomfortable half: the revoked device can **still** re-seed, because its certificate is still valid. That is what the ADR says, and the walk should demonstrate it rather than assume the message is enough.

Then retire what the device holds, and prove it from the bundle's side rather than the command's:

```bash
farcast storage key rotate "$INSTANCE" -y      # every scope; serving replicas take the new keys
farcast storage key rekey "$INSTANCE" -y       # moves stored objects onto them
```

**Expect:** rotate reports a new KEK for **every application scope**, not only the instance's own, and that all replicas hold them and write under them; rekey reports a non-zero `rewritten` count. Then the half that matters for a fleet: with one replica made unreachable — its State call must fail; a replica caught mid-restart answers restart-sealed, which is a different case (below) — rotate must report the new keys **held on some and in use on none, this machine included**, and exit non-zero: it hands a rotation over in two steps, and activates only once every serving replica holds the new key and still holds it when asked again. `farcast storage key list` must show each application scope's active key unchanged from before that rotate. `farcast storage unseal` run now must **not** make the new keys active (it hands over this machine's keyring, in which they are held). Then, with every replica answering, run rotate once more: it must report all replicas holding and writing under the newest keys, and `farcast storage state` must flag no replica. Finally, copy a `keys.yaml` from before the rotation over this machine's and run `farcast storage unseal`: it must **refuse** (this keyring is behind the instance's) and push nothing — restore the current file afterwards. The sealed cases: with one replica restart-sealed and the other serving, rotate finishes and reports one replica sealed, to receive the keys on the next unseal; with **every** replica sealed it must stop at the hold, say so, and leave each scope's active key unchanged — with none serving, nothing would stop a keeper re-seeding the keys from before. And with one replica sealed and the other unreachable, `farcast storage unseal` must leave the sealed one sealed and name `--unchecked`; with `--unchecked` it unseals it, and still does not push the unreachable one. Then open an object with the material the revoked device's packet carries: it must fail (`blob is sealed under a key the keyring does not hold`). The 2026-10-06 walk ran this as written then — `storage rekey` — and found the command did not exist and the real pair rewrote 0 of 4 objects; this is the re-walk of that.

## 8. Does the device survive its own restart, and the platform's?

Reboot the keeper. **Expect** `keeper run` to resume with its ledger and budget intact, and the material still at 0600 inside a 0700 directory with the exclusion still set.

## 9. What the fleet costs

Two keepers double the bundles at rest and double the solicitation endpoints. Confirm `keeper status` on the operator's machine lists both devices and their expiries, and that budgets are read as a **fleet** total rather than per device — ADR 0008 finding 6 says the reconciliation watches the aggregate.

---

## Criteria

| # | Criterion | Result |
|---|---|---|
| 1 | An enrolment packet carries a bundle and a device leaf, and neither the keyring nor the CA key | ✅ master key ids absent from the bundle; leaf `farcast://p54/keeper/study-vm`, clientAuth only |
| 2 | A machine with no FarCast state becomes a keeper from the packet alone | ⏸ **not walked** — installed on the operator's machine, which holds the keyring |
| 3 | A restart-sealed replica is re-seeded unattended, and an application recovers without restarting | ✅ `re-seeded … (process bbf993a8)`; `alpha` kept reading at restart count 0 |
| 4 | An operator hold is refused by the device **and** by the keyholder independently | ⚠️ passed **for the wrong reason**: the keyholder refused a push that declared `restart-reseed`, but took that intent from the request — a keeper claiming `operator-unseal`, or calling `release-hold`, was obeyed. Fixed 2026-10-06, not re-walked |
| 5 | An exhausted budget refuses, legibly, and leaves storage sealed | ✅ `budget-exhausted — 2 of 2 in the last 30 days, none expires before 2026-11-05`; replica stayed sealed |
| 6 | `keeper status` reports a clean fleet as clean, and flags a process re-seeded twice | ✅ both states seen — `nothing to explain`, then `1 PROCESS(ES) RE-SEEDED MORE THAN ONCE: process 4b94f94a re-seeded 2 times` |
| 7 | `revoke` states its limits, and a revoked device demonstrably still works until rekey | ⚠️ first half ✅; the **rekey half failed** — see below. Fixed 2026-10-06, not re-walked |
| 8 | A rebooted keeper resumes with its ledger, budget and file modes intact | ⏸ **partly** — modes confirmed 0600 inside 0700; the reboot was not performed and the backup exclusion has no Linux equivalent to check |
| 9 | Two devices are visible as a fleet, with expiries, and their budgets read as a total | ⏸ **not walked** — needs a second device |
| 10 | Teardown leaves no billable resource — verified independently, not from local state | ✅ all eight resource classes zero against the cloud APIs |

### Criterion 7 is the one that failed

Both documented halves behaved: `revoke` said plainly that it *"did not reach the cluster, and it did not invalidate the device's certificate"*, named `storage rekey`, and warned that rekey *"does not reach backwards"*. A device revoked seconds earlier then re-seeded a live replica, exactly as the ADR says it would.

The remedy is what failed. `storage key rekey` rotated **no key at all** and re-encrypted **0 of 4 objects**, because every object lives under a per-application scope it cannot address. The bundle a lost device holds is untouched by the command an operator is told to run. Full measurements in [the 5.3 re-walk's finding 5](phase-5-3-validation.md#5-storage-key-rekey-cannot-retire-what-a-keeper-device-holds).

Until that is fixed, **revocation has no teeth**: the only bound on a lost keeper is its certificate's own 90-day expiry.

**Fixed 2026-10-06, not re-walked.** `rotate` now gives every scope a new KEK and hands it to serving replicas; `rekey` rewrites each object under its own scope's key and refuses to move any until every replica holds it; `revoke` prints that sequence. A unit test drives exactly the walk's failure — the material a keeper enrolled before the rotation would carry — and proves it opens none of the applications' objects afterwards. The re-walk is the procedure in section 7 above. What it still cannot do is stated in the command and in [ADR 0008](../adr/0008-in-cluster-key-delivery.md#what-the-2026-10-06-walk-found-and-what-changed): names stay computable, and a restarted replica can still be re-seeded with old keys by a device that is not honest, until the in-cluster key-id pin exists.

### What a second machine still owes

Criteria 2, 8 and 9. On Linux, `keeper install` refuses without `--accept-backup-risk` — there is no single backup pipeline it can verifiably exclude from, so it will not promise what nobody checked. Walking that refusal, and then the no-cloud-credential inventory on a device that holds nothing else, is what criterion 2 actually asks for. The macOS exclusion path was confirmed here (`backup excluded, and the exclusion was read back`), so the remaining gap is the device property, not the mechanism.
