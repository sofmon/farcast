# ADR 0023 M2 — the probe walk: what Google's pages do not settle

Since [ADR 0023](../adr/0023-one-download-farcast.md) M2.4, `world`, `ps`, `costs`, `usage` and `logs` read the cluster in-process as the instance's reader. Since M2.5, every writing command that reads the cluster reads it in-process as the installer service account, the writer, and the storage key pin is written the same way; `kernel meter`, `kernel confirm` and `reader grant` make no call as the writer. Both mint their own token, in memory, from a key, with the one scope `userinfo.email` *(2026-11-16: at 2482810, the code this walk ran; since the fix later that day, `cloud-platform` and `userinfo.email`, as the Status says)*. Google documents that GKE's DNS endpoint accepts a token minted from a service-account key by `gke-gcloud-auth-plugin` ([GKE auth](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/api-server-authentication)). It does not document farcast's own token with `userinfo.email` alone, nor a reader holding `roles/container.clusterViewer` plus RBAC. This walk tests those first, on one short-lived instance, before ADR 0023 M2.9's billable walk depends on them. *(2026-11-22: "M2.9's billable walk", here and in the approval paragraph below, is M2's billable walk. [ADR 0023](../adr/0023-one-download-farcast.md) M2.9b wrote its runbook, [adr-0023-m2-walk.md](adr-0023-m2-walk.md), and did not run it; it needs its own approval.)*

**Status.** *Written 2026-11-15 against the code as built. Walked 2026-11-16 at 2482810 (M2.5). The scope fix was built after it, the same day, and is not walked.* The probe was rebuilt during the walk with two options, now in the tree and in [`walkprobe_test.go`](../../farsight/cli/internal/cli/walkprobe_test.go)'s header: `FARCAST_WALK_SCOPE`, and `mint-empty-kid`'s `FARCAST_WALK_IDENTITY`. The [Results](#results) hold what it recorded.
- **Answered:** items 1, 3, 4, 5, 6 and 7. Item 3 only in part: the script stopped at its first policy check, before its retries, its upload and its key id. Item 5 only for a key Google created, not an uploaded one.
- **Item 1's answer is a hard stop.** GKE's DNS endpoint refuses a token scoped to `userinfo.email` alone (401, an HTML page). It accepts the same key's token with `cloud-platform` (200). At 2482810 farcast minted every in-process cluster token with `userinfo.email` alone. So there the endpoint refuses its in-process cluster calls: the five read commands and `reader grant`'s check since M2.4, and the writing commands' reads and the storage key pin since M2.5. The fix is to restore `cloud-platform` ([ADR 0023](../adr/0023-one-download-farcast.md) decision 3's dated notes).
- **The fix, built later on 2026-11-16, not walked.** farcast now mints every cluster token with `cloud-platform` and `userinfo.email`, in that order, the order this walk's probe sent them in. `cloud-platform` is what the endpoint's IAM check needs. `userinfo.email` keeps the account's email in the identity GKE derives from the token, which the reader's RoleBindings name; that is inferred, not walked. The trade-off: a leaked cluster token works for every Google API the account's IAM allows, not only the cluster: `roles/container.clusterViewer` for the reader, everything the installer holds for the writer. The fix is built and tested against a local API server (`kube/kubetest`) only. For the writer, this walk's 200 to exactly this pair, sent by the probe in P1.4 and not by farcast, is the evidence. For the reader there is none: item 2 was not walked, and where key upload is blocked no reader can be set up. From now on the probe's default is farcast's pair; `FARCAST_WALK_SCOPE=userinfo.email` reproduces this walk's 401.
- **Not answered:** item 2. The project's organization enforces `iam.disableServiceAccountKeyUpload`, so P2.2 created no reader. P1.5 was not run, after P1.4's hard stop. P2.3 to P2.6 were not run, because there was no reader.
- **Teardown:** the instance is released, the throwaway account is deleted, the Org Policy API the walk enabled is off again, and the project is back to P0.8's counts.

**It records seven things:**
1. whether the DNS endpoint accepts the **writer's** token scoped to `userinfo.email` alone, which every writing command's reads need since M2.5. If it refuses, `cloud-platform` comes back, with a dated note in ADR 0023;
2. the same for the **reader**, end to end: `reader init`, the Cloud Shell paste, `reader record`, `reader grant` and `world`;
3. what the reader's init script printed: the spelling and output of its two policy checks, the retry against a fresh account, and whether the upload needs a key usage on the certificate;
4. whether GKE's SelfSubjectAccessReviews consult IAM. A throwaway account with `roles/container.developer` and no RBAC asks whether it may create Deployments;
5. whether Google's token endpoint accepts an assertion whose key id is empty, `"kid":""`;
6. the body of a 403 from the endpoint's IAM check, compared with a Kubernetes Status;
7. the recorded endpoint's form, and whether its location label is the region or a zone; and the cluster's Kubernetes version.

The steps take them in this order, except items 6 and 7. Item 6 needs the throwaway account before it has a role, so it is measured inside P4, before item 4's grant. Item 7's endpoint form costs nothing and is read right after the install (P1.3), because a zone label there would stop every in-process step after it. The walk ends with `release` and the reader lines it prints.

**It is billable.** One Autopilot instance, installed with `--cost-limit 100` (USD a month), for about 2 hours. By the repository's floor model the standing cost is about USD 0.11 an hour ([phase-5-session-a.md](phase-5-session-a.md)): the modelled cluster line, the five system Pods and the carrier. That is about USD 0.25 for the walk, plus cents for the registry's storage and the carrier's traffic: under USD 1 in all. The walk also creates, in the instance's project, the reader's service account with one uploaded key, and a throwaway service account with one downloaded key. IAM objects cost nothing, and P7 deletes them all.

**Do not start P1 until the operator has approved this walk for this session.** Approval does not carry over from another walk, the M1 walk and M2.9's included. Present the cost, the duration, the two service accounts, the walk's one privileged grant and the teardown (P7), and wait for a yes. The grant is `roles/container.developer` on the project for the throwaway account (P4.4), from P4.4 until P7.1, at least 10 minutes: it can write workloads in every cluster in the project, not only this instance's, and its key sits on this Mac in `$WALK/probe/` all that time.

Throughout:
- **The operator's own gcloud configuration only,** never a work one. `--credentials <service-account-key.json>` on every `farcast` command that takes it, which is `install`. No Application Default Credentials: since M2.5 `install` refuses a missing `--credentials`, and P1 checks that.
- **Never paste raw output** of a live command anywhere: not into the transcript, an issue or the repository, and no screenshots. Record only what each step says to record, with `$INSTANCE` and placeholders such as `$PROJECT`. Never record a project id, a project number, an account email, a key id, an address, a home-directory path or a time of day.
- **Never print a token.** Never run `gcloud auth print-access-token`, even with its output redirected: zsh's MULTIOS still sends it to the pipe. The walk probe prints no token, key, assertion, email, project id or address, and scrubs what the cluster or Google sent before it prints it. Read a scrubbed message before recording it all the same. If anything identifying survived the scrubber, record "withheld", and note it as a finding against the probe.
- **`KUBECONFIG` is the instance's own kubeconfig** in every shell that runs `kubectl` or `farcast`. The operator's default kubeconfig can hold other clusters.
- **No `GODEBUG` and no `GOOGLE_SDK_GO_LOGGING_LEVEL`** in any shell that runs `farcast` or the probe. farcast and the probe both refuse an `http2debug` setting, which would print the bearer; the walk shell below starts with neither.
- **The throwaway account's key** lives only in `$WALK/probe/`: never in the checkout, `~/Downloads` or Cloud Shell's home. P7 deletes it with the account.
- **Cloud Shell steps are the operator's.** An agent never types into Cloud Shell. `reader grant` needs a terminal and a typed `y`, so it is the operator's too.

---

## P0. Setup on the dev Mac (no cloud)

1. `./check.sh` passes at the commit being walked, from a clean tree. Record the commit and the check's summary line. Nothing in this walk clones from GitHub, so the commit need not be pushed.
2. **The walk directory**, outside any checkout:
   ```bash
   INSTANCE=<name>
   REPO=<the checkout, at that commit>
   WALK=$(mktemp -d)                  # 0700; every scratch file of this walk lives here, never in the checkout
   mkdir -p "$WALK/bin" "$WALK/tools"
   ```
3. **The farcast**, a release build for this Mac, so that `connect` pushes the FatLine and Shrike images it carries and builds nothing:
   ```bash
   (cd "$REPO" && GOTOOLCHAIN=go1.27.4 go run ./farsight/cli/cmd/farcast-release build -targets darwin/arm64 -out "$WALK/rel")
   (cd "$WALK/rel" && shasum -a 256 -c SHA256SUMS)
   go version -m "$WALK/rel/farcast-darwin-arm64" | grep -E -- '-tags=|vcs\.(revision|modified)'
   cp "$WALK/rel/farcast-darwin-arm64" "$WALK/bin/farcast"
   ```
   *Expect* every line `OK`, `-tags=farcast_embedded`, step 1's commit as `vcs.revision`, and `vcs.modified=false`.
4. **The walk probe, built once** at a fixed path, from the same checkout. `go test` would link a new binary at a new temporary path on every run, and an outbound firewall that makes its rules per binary would hold each one ([phase-5-session-a.md](phase-5-session-a.md), "Build the probe once"):
   ```bash
   (cd "$REPO" && go test -mod=vendor -tags walk -c -o "$WALK/walkprobe.test" ./farsight/cli/internal/cli/)
   ```
   Its cluster modes are `forbidden-body`, `review` and `mint-empty-kid`, and the header of [`walkprobe_test.go`](../../farsight/cli/internal/cli/walkprobe_test.go) lists their inputs. They read the instance's record and keys from farcast's own config directory, by farcast's own rules. `forbidden-body` and `review` each mint one token and send one request; `mint-empty-kid` only mints.
5. **The outbound firewall** (Little Snitch, on the walk Mac). Make these rules before P1, each for its destination only:
   - `$WALK/bin/farcast`: Google's APIs, the registry's `<region>-docker.pkg.dev`, and `gcr.io` for the base image, as on the M1 walk. New since M2.4 and M2.5: the cluster's `*.gke.goog:443` and `oauth2.googleapis.com:443`, for its in-process reads and the tokens it mints. Add the carrier's address on port 8443 after P1.
   - `$WALK/walkprobe.test`: `*.gke.goog:443` and `oauth2.googleapis.com:443`, and nothing else.
   - `kubectl`, the GKE auth plugin and gcloud keep the rules they had. Until M2.7 every apply still runs kubectl as the active gcloud configuration. *(2026-11-18, ADR 0023 M2.7, built, not walked: farcast starts none of the three, so a re-walk gives `farcast` no rules or tools for them; they serve only observation, which a re-walk runs from Cloud Shell.)*
   - *(2026-11-16: a firewall that has not yet allowed `walkprobe.test` does not show as a refusal. The probe prints `NOT ANSWERED: EOF` from the token endpoint, after about 16 s. Allow it for its two destinations, and run the probe again.)*
6. **Three tools for the applies.** Link `kubectl`, the GKE auth plugin and `gcloud` one by one into `$WALK/tools`, never a whole tool directory. *(2026-11-18, ADR 0023 M2.7, built, not walked: farcast starts none of the three, so a re-walk gives `farcast` no rules or tools for them; they serve only observation, which a re-walk runs from Cloud Shell.)* For this walk:
   ```bash
   for t in kubectl gke-gcloud-auth-plugin gcloud; do ln -s "$(command -v "$t")" "$WALK/tools/$t"; done
   ```
7. **The walk shell**, with nothing inherited but what is named:
   ```bash
   env -i HOME="$HOME" TMPDIR="$TMPDIR" WALK="$WALK" INSTANCE="$INSTANCE" \
     CLOUDSDK_ACTIVE_CONFIG_NAME=<your FarCast gcloud configuration> \
     PATH="$WALK/bin:$WALK/tools:/usr/bin:/bin" zsh -f
   ```
   Then, inside it:
   ```bash
   STATE="$HOME/Library/Application Support/farcast"
   export KUBECONFIG="$STATE/instances/$INSTANCE/kubeconfig.yaml"   # P1 writes it
   # (2026-11-18, ADR 0023 M2.7, built, not walked) Neither install nor connect writes kubeconfig.yaml any more. (2026-11-20, M2.9a, built, not walked: farcast migrate, which deleted one an older farcast left, is removed; only release deletes it now, with the instance's directory.) A re-walk observes with kubectl from Cloud Shell (ADR 0023 Phasing), not over a file farcast wrote; an exported KUBECONFIG naming the absent file fails rather than falling back to ~/.kube/config [inf].
   cd "$WALK"
   env | grep -E '^(GODEBUG|GOOGLE_SDK_GO_LOGGING_LEVEL|HTTPS?_PROXY|ALL_PROXY)=' && echo "STOP: unset these"
   probe() { (cd "$WALK" && env FARCAST_WALK=1 FARCAST_WALK_INSTANCE="$INSTANCE" FARCAST_WALK_CWD="$WALK" "$@" \
     "$WALK/walkprobe.test" -test.run '^TestWalkProbe$' -test.v -test.count=1); }
   farcast version
   ```
   *Expect* the `grep` to print nothing, and `farcast version` to list four components.
8. **The observing shell.** A second, ordinary terminal, with gcloud on the FarCast configuration:
   ```bash
   INSTANCE=<name>; WALK=<the same directory>
   STATE="$HOME/Library/Application Support/farcast"
   export KUBECONFIG="$STATE/instances/$INSTANCE/kubeconfig.yaml"
   # (2026-11-18, ADR 0023 M2.7, built, not walked) Neither install nor connect writes kubeconfig.yaml any more. (2026-11-20, M2.9a, built, not walked: farcast migrate, which deleted one an older farcast left, is removed; only release deletes it now, with the instance's directory.) A re-walk observes with kubectl from Cloud Shell (ADR 0023 Phasing), not over a file farcast wrote; an exported KUBECONFIG naming the absent file fails rather than falling back to ~/.kube/config [inf].
   export CLOUDSDK_ACTIVE_CONFIG_NAME=<your FarCast gcloud configuration>
   ```
   Record the counts of clusters, registries, buckets, forwarding rules, addresses, target pools, disks and VMs in the project now, for P7 to compare with. Record counts only.

   *(2026-11-16: count the buckets in Cloud Shell, with P0.9's `PROJECT`. `gcloud storage` still crashes on the operator's Mac, so this walk counted them there. An expired gcloud session fails every list, with "Reauthentication failed", so a list that failed counts nothing. Check that each list ran before recording its count, and sign in again if it did not.)*
9. **Cloud Shell**, signed in as an Owner of the instance's project. Set the project and the instance there, typed and never recorded: `PROJECT=<the project id>` and `INSTANCE=<name>`. P6 and P7 use both.

---

## P1. Install, and item 1: a writing command's reads run as the writer (billable from here)

1. **No cost: `install` refuses Application Default Credentials.** In the walk shell, twice: with no `--credentials`, and with `--credentials /dev/null`, an empty file. `install` refuses both before it opens the provider or records anything. Nothing could be created even if it did not: with no `--yes` and no terminal on stdin it stops before its confirmation. The project is a made-up one, and `GOOGLE_APPLICATION_CREDENTIALS` names a file that does not exist, so not even a regression could validate the machine's Application Default Credentials against the instance's project. Each refusal is a usage error: exit status 2, its prose on stderr, nothing on stdout and no JSON envelope (there is no `usage` kind). Each run writes to files, never through a `2>&1 >/dev/null` pipe, which zsh's MULTIOS would break:
   ```bash
   GOOGLE_APPLICATION_CREDENTIALS="$WALK/none.json" farcast -o json install --name "$INSTANCE" --cost-limit 100 \
     --region us-central1 --project farcast-walk-unused </dev/null >"$WALK/p1-1.out" 2>"$WALK/p1-1.err"; echo "exit $?"
   wc -c < "$WALK/p1-1.out"; grep -c 'credentials is required' "$WALK/p1-1.err"
   GOOGLE_APPLICATION_CREDENTIALS="$WALK/none.json" farcast -o json install --name "$INSTANCE" --cost-limit 100 \
     --region us-central1 --project farcast-walk-unused --credentials /dev/null </dev/null >"$WALK/p1-1b.out" 2>"$WALK/p1-1b.err"; echo "exit $?"
   wc -c < "$WALK/p1-1b.out"; grep -c 'credentials names an empty file' "$WALK/p1-1b.err"
   ```
   *Expect*, for each, `exit 2`, a count of `0` bytes on stdout, and `1`. Record them. Anything else is a finding: stop, and do not go on to step 2.
2. **The install.** In the walk shell:
   ```bash
   farcast install --name "$INSTANCE" --cost-limit 100 --region us-central1 --project <the project id> --credentials <service-account-key.json>
   ```
   Answer its confirmation. *Expect* it to finish as on the M1 walk. `credentials.yaml` now holds the installer's key.
3. **No cost: the endpoint's form (item 7).** In the observing shell, from `metadata.yaml`, which step 2 wrote. It prints each label's shape, never the endpoint itself:
   ```bash
   M="$STATE/instances/$INSTANCE/metadata.yaml"
   REGION=$(awk '/^region:/{print $2}' "$M")
   awk '/^endpoint:/{print $2}' "$M" | awk -F. -v r="$REGION" '{
     for (i = 1; i <= NF; i++) { l = $i
       if (l == r) s = "<the region>"; else if (index(l, r "-") == 1) s = "<a zone of the region: " l ">"
       else if (l == "gke" || l == "goog") s = l; else s = "<" length(l) " characters>"
       printf "%s%s", s, (i < NF ? "." : "\n") } }'
   ```
   Record the line it printed. farcast's endpoint rule (`kube.ParseEndpoint`) accepts a `gke.goog` name only when one of its labels after the first is the recorded region. A zone label in its place, as in Google's one published example, fails closed before anything is sent: every in-process call after this step, farcast's and the probe's, would stop at that rule, and `connect` and `world` would fail with `endpoint_refused`. **So a zone label is a stop.** Record it as item 7's answer and as a finding against the rule. Skip every step that reaches the cluster in-process (steps 4 and 5, P2.4 to P2.6, P4 and P5), and go on with P2.1 to P2.3, P3, P6 and P7.
4. **Before `connect`: one read as the writer.** The probe sends the writing commands' preflight read, the list of `farcast-system`, once, as the installer's key:
   ```bash
   probe FARCAST_WALK_PROBE=forbidden-body FARCAST_WALK_IDENTITY=writer
   ```
   *Expect* `status 200 OK` and `not a refusal`: the DNS endpoint accepts the writer's token with `userinfo.email` alone *(2026-11-16: since the fix, with farcast's pair, `cloud-platform` and `userinfo.email`; P1.4's notes below)*. Record the status line. For anything else, also record the lines it printed: the Content-Type, whether the body is a Kubernetes Status, the reason and code, and the scrubbed message.

   **Hard stop on a 401 or a 403.** Then every writing command would refuse at its own preflight read, so `connect` would refuse before it creates the load balancer, and nothing about it is learned by running it. Skip step 5, and P2's grant and `world`. Go on with P2's init, paste and record, then P2.4, which needs no connected instance and is then item 2's answer: a 403 whose body is a Kubernetes Status means the endpoint accepted the reader's token and RBAC refused it, as it should before a grant; a 401 means the endpoint refused the token; the endpoint's IAM refusal is no answer yet, so run it again after a few minutes, as P2.4 says. Then go on with P3 to P6, which do not need a connected instance either. Adding `cloud-platform` back is a code change with its own dated note in ADR 0023, not a walk step.

   *(2026-11-16: the probe now takes `FARCAST_WALK_SCOPE`, added during the walk. It sets the scope every cluster mode mints with: `userinfo.email`, farcast's own and the default then; `cloud-platform`; or `cloud-platform+userinfo.email`, what gcloud asks for. On this walk the writer's read answered 401 Unauthorized, `text/html`, not a Kubernetes Status, with `userinfo.email`. It answered 200 OK with each of the other two. So the hard stop held, and the cause is farcast's scope, not the writer: the same key reads with `cloud-platform`. Running this step with each scope tells the two apart. A firewall that has not yet allowed `walkprobe.test` shows here as `NOT ANSWERED: EOF` after about 16 s, not as a refusal (P0.5).)* *(2026-11-16, after the fix: the probe's default is now farcast's own pair, `cloud-platform` and `userinfo.email`, the same as `FARCAST_WALK_SCOPE=cloud-platform+userinfo.email`. So *expect* 200 with the default. `FARCAST_WALK_SCOPE=userinfo.email` reproduces this walk's 401, and `cloud-platform` alone stays an option.)* *(2026-11-16, after the fix: "what gcloud asks for" above is not right, and the walk did not observe gcloud's request. gcloud's own scope list, as its installed source on the dev Mac sets it, puts `userinfo.email` before `cloud-platform` and asks for more scopes besides. `cloud-platform+userinfo.email` is the probe's own pair, in the probe's order.)*
5. **`connect`.** In the walk shell:
   ```bash
   farcast -o json connect "$INSTANCE" --yes > "$WALK/connect.json"; echo "exit $?"
   grep -o '"kind":"[a-z_]*"}}' "$WALK/connect.json"
   grep -c '^carrier:' "$STATE/instances/$INSTANCE/metadata.yaml"
   ```
   `--yes` answers the load balancer's cost confirmation, and only that. Since M2.5, `connect` reads `farcast-system` as the writer before that question, before it mints the instance's CA and before any push or apply. After its applies it reads the rollout and the carrier's IP as the writer too.

   *Expect* exit 0, no kind, and one `carrier:` line. Then `farcast connect "$INSTANCE" --status` connects. Record:
   - the exit status, and the error's kind if there was one;
   - whether `metadata.yaml` records a carrier. A refusal with no carrier recorded came before the load balancer, so at the preflight read;
   - from the firewall's log, whether `$WALK/bin/farcast` itself reached the cluster's `*.gke.goog` host and `oauth2.googleapis.com` (its in-process reads, as the writer), and whether kubectl reached the cluster (the applies);
   - whether `connect --status` connected.

## P2. Item 2: the reader, end to end

1. **The key and the script.** In the walk shell:
   ```bash
   farcast reader init "$INSTANCE" > "$WALK/reader-init.sh"
   pbcopy < "$WALK/reader-init.sh"
   ```
   Where the organization enforces `iam.serviceAccountKeyExpiryHours`, pass a `--days` no greater than its days, and at most 90 ([phase-1-validation.md](phase-1-validation.md) step 7b). *Expect* `Paste this into Cloud Shell as a project Owner (sha256 …)` on stderr, and `reader.key` and `reader.crt` in the instance's directory.
2. **The paste.** Paste the script into Cloud Shell. Keep what it prints on the screen for P3; do not copy it anywhere. *Expect* it to end with `farcast reader record $INSTANCE --key-id <40 hex>`.

   *(2026-11-16: where the organization enforces `iam.disableServiceAccountKeyUpload`, as this walk's did, the script stops at its first policy check. It prints farcast's own refusal and changes nothing. There is then no reader in the project, and item 2 cannot be walked there. Skip P2.3 to P2.6 and P4.6's reader review, go on with P3, and run P5 with another key (P5's note).)*
3. **The record.** In the walk shell: `farcast reader record "$INSTANCE" --key-id <the id>`. *Expect* `metadata.yaml`'s `reader:` to gain `key_id`.
4. **Optional, no extra cost: an RBAC refusal from the real API server.** Before `reader grant`, the reader has its IAM role and no RBAC yet:
   ```bash
   probe FARCAST_WALK_PROBE=forbidden-body FARCAST_WALK_IDENTITY=reader
   ```
   Record the lines it printed, as in P1.4. A 403 whose body is a Kubernetes Status is an RBAC refusal, the shape farcast's `forbidden` sentence for the reader assumes. While `clusterViewer` is still propagating, the answer may be the endpoint's IAM refusal, or a 401, instead: record which, and how many minutes after the paste.
5. **The grant.** In the walk shell, which is a terminal, timed by zsh's `time`, which prints the elapsed time when the command ends:
   ```bash
   time farcast reader grant "$INSTANCE"
   ```
   Answer `y` at once: the elapsed time includes the prompt. It applies through kubectl, then reads as the reader, waiting up to 8 minutes for IAM, then asks five access reviews. If its first read is refused it prints `IAM changes typically take 2 minutes, and can take 7 minutes or longer; checking again until <a time of day>` once; the retries after it print nothing. *Expect* `✓ instance "$INSTANCE"'s reader … reads the cluster, and was verified read-only`. Record:
   - the elapsed minutes `time` printed, rounded, never a time of day;
   - whether the `IAM changes typically take 2 minutes` line appeared, which says the first read was refused. Never record the time it names;
   - if a review answered that the reader `may` do something, which of the five.

   Whether a refusal while it waited was a 401 or a 403 is not printed unless the 8 minutes run out. If that matters, run P2.4's probe just before the grant: its status line is the answer at that moment.
6. **`world`, as the reader.** In the walk shell:
   ```bash
   farcast -o json world "$INSTANCE" > "$WALK/world.json"; echo "exit $?"
   grep -o '"error":{"kind":"[a-z_]*"' "$WALK/world.json" | sort | uniq -c
   grep -o '"read":[a-z]*\(,"skipped":"[a-z_]*"\)\{0,1\}' "$WALK/world.json" | sort | uniq -c
   ```
   This walk deploys no kernel and no keyholder. So *expect* one error kind only, `kernel_absent`, for the spend section, which reads nothing from the cluster without a kernel; and the seal section `"read":false` with `"skipped"`. Every other section reads. Record the exit status and the two counts. This is item 2's answer: the DNS endpoint accepts the reader's token with `userinfo.email` alone *(2026-11-16: since the fix, with farcast's pair, `cloud-platform` and `userinfo.email`)*, and `clusterViewer` plus farcast's RBAC reads what `world` reads. A `credential_refused`, `unauthorized`, `forbidden` or `endpoint_refused` is the answer the other way.

## P3. Item 3: what the init script printed

From what the paste printed in P2.2, record:
- whether either policy check printed anything. The script silences both (`2>/dev/null`), so nothing is expected;
- whether the script stopped at a policy check;
- the retry against a fresh account. Each failed try prints gcloud's own error, then the script waits 8, 16, 24, 32 and 40 seconds. Record, for the binding and for the upload, how many errors came before the command succeeded, or `FarCast: gave up after 6 tries`. Record each error's command group and its first words only, never a line that names the project or an account;
- whether `keys upload` accepted the certificate. The certificate carries no key usage and no other extension. An error naming key usage, an extension or the certificate's form means the upload needs one;
- whether the printed key id is 40 lowercase hex characters, which says `--format 'value(name.basename())'` printed the id alone.

Then run the two checks unsilenced in Cloud Shell, to record their spelling and output:
```bash
gcloud resource-manager org-policies describe iam.disableServiceAccountKeyUpload \
  --effective --project "$PROJECT" --format 'value(booleanPolicy.enforced)'; echo "exit $?"
gcloud org-policies describe iam.managed.disableServiceAccountKeyUpload \
  --effective --project "$PROJECT" --format 'value(spec.rules[0].enforce)'; echo "exit $?"
```
For each, record the exit status, and whether it printed nothing, `True`, `False`, or an error. For an error, record its command group and first words only, such as an unknown command, an unrecognized argument or `NOT_FOUND`.

*(2026-11-16: the managed check needs the Org Policy API, `orgpolicy.googleapis.com`, on the project. Where it is off, gcloud asks whether to enable it. If the walk enables it, record that, and P7.6 turns it off again. In the script the check is silenced and has no terminal, so gcloud cannot ask: with the API off it prints nothing, which the script reads as "not enforced". On this walk the legacy check printed `True`, and the managed one, once the API was on, `False`, each with exit 0.)*

## P4. Items 6 and 4: a throwaway account

The account has no role at first, so the endpoint's IAM check refuses it (item 6). Then it gets `roles/container.developer` and no RBAC, and asks for a review (item 4).

1. **The account**, in Cloud Shell:
   ```bash
   PROBE_SA=farcast-walk-probe
   gcloud iam service-accounts describe "$PROBE_SA@$PROJECT.iam.gserviceaccount.com" --project "$PROJECT" >/dev/null 2>&1 \
     && echo "STOP: $PROBE_SA already exists"
   gcloud iam service-accounts create "$PROBE_SA" --project "$PROJECT" --display-name 'FarCast probe walk; delete at teardown'
   ```
   No role is granted yet.
2. **Its key, into the walk's scratch directory only.** In the observing shell, as the operator's own configuration:
   ```bash
   PROJECT=$(awk '/^project:/{print $2}' "$STATE/instances/$INSTANCE/metadata.yaml")   # never print it
   mkdir -m 700 "$WALK/probe"
   gcloud iam service-accounts keys create "$WALK/probe/key.json" \
     --iam-account "farcast-walk-probe@$PROJECT.iam.gserviceaccount.com" --project "$PROJECT"; echo "exit $?"
   chmod 600 "$WALK/probe/key.json"
   ```
   gcloud names the account and the file on stderr: do not record that line. If the project forbids key creation (`iam.disableServiceAccountKeyCreation` or its managed form), record that, delete the account (P7.1), and skip the rest of P4: items 4 and 6 are then not walked.

   **From here, if the walk stops for any reason, run P7.1 before anything else.** The account has a key on this Mac, and from step 4 a role on the whole project.
3. **Item 6: the endpoint's IAM refusal.** In the walk shell:
   ```bash
   probe FARCAST_WALK_PROBE=forbidden-body FARCAST_WALK_IDENTITY=key FARCAST_WALK_KEY_JSON=probe/key.json
   ```
   A new key can take a short while to work. If the probe says `the token endpoint minted no token`, wait a minute and run it again, and record how many tries it took. *Expect* a refusal. Record every line it printed after the first, all of them scrubbed:
   - the status and the Content-Type;
   - the body's keys;
   - whether the body is a Kubernetes Status, with its reason and code; or Google's JSON error, with its status, its code, and each detail's `@type` and reason;
   - the scrubbed message.

   farcast tells an RBAC refusal from the endpoint's IAM refusal by whether the body is a Kubernetes Status, so these lines settle that rule.

   *(2026-11-16: while the probe's default scope is `userinfo.email` alone, farcast's own as built, run this step twice: as written, and again with `FARCAST_WALK_SCOPE=cloud-platform`. On this walk the default scope got the endpoint's 401 for an account with a role and for one with none: the writer in P1.4, and this account here, before its role. With `cloud-platform` this step got the endpoint's IAM refusal, the 403 it looks for. So run step 5's review and step 6's controls with `FARCAST_WALK_SCOPE=cloud-platform`, as this walk did. With the default scope step 5 would get only 401s, and item 4 no answer (inferred). Run P2.4 both ways too, for the same reason. This walk did not run P2.4.)* *(2026-11-16, after the fix: the probe's default is now farcast's own pair, so the condition above no longer holds. Run this step, step 5 and step 6 with the default, which carries `cloud-platform`; that the pair gets the same 403 as `cloud-platform` alone did is inferred. `FARCAST_WALK_SCOPE=userinfo.email` still reproduces the 401.)*
4. **The role**, in Cloud Shell. The command prints the project's whole IAM policy, so it is discarded:
   ```bash
   gcloud projects add-iam-policy-binding "$PROJECT" --condition=None \
     --member "serviceAccount:$PROBE_SA@$PROJECT.iam.gserviceaccount.com" --role roles/container.developer >/dev/null; echo "exit $?"
   ```
5. **Item 4: the review.** In the walk shell, every one or two minutes:
   ```bash
   probe FARCAST_WALK_PROBE=review FARCAST_WALK_IDENTITY=key FARCAST_WALK_KEY_JSON=probe/key.json \
     FARCAST_WALK_VERB=create FARCAST_WALK_RESOURCE=deployments FARCAST_WALK_GROUP=apps FARCAST_WALK_NAMESPACE=farcast-system
   ```
   IAM changes typically take 2 minutes, and can take 7 minutes or longer ([Google](https://docs.cloud.google.com/iam/docs/access-change-propagation)). Until the role is in force, the review itself may be refused at the endpoint: the probe then prints `the review itself was refused` and the refusal's lines, which are a second sample for item 6. Keep asking until two answers at least five minutes apart agree, the later one at least 10 minutes after step 4. Record:
   - the verdict, `ALLOWED`, `DENIED` or `NO OPINION`, and the scrubbed reason;
   - how many minutes after step 4 the answer settled;
   - whether the review itself was refused before that, and how.

   `ALLOWED` means GKE's reviews consult IAM: an account with an IAM role and no RBAC is allowed. `reader grant`'s five reviews then also see an IAM role stronger than `clusterViewer` edited into the paste, as the CLI README assumes. `DENIED` or `NO OPINION`, settled, means they consult RBAC alone. Record that as a finding against the [CLI README's `reader grant` section](../../farsight/cli/README.md#farcast-reader-grant--the-rbac-and-the-check), which states the inference.
6. **Controls, optional and at no extra cost.** The same review as the writer (`FARCAST_WALK_IDENTITY=writer`; *expect* `ALLOWED`: the installer holds `roles/container.admin`) and as the reader (`FARCAST_WALK_IDENTITY=reader`; *expect* anything but `ALLOWED`: `reader grant` asked exactly this). Then `forbidden-body` as the key once more, now holding its role. Record the three verdicts or statuses.

## P5. Item 5: an empty key id

In the walk shell:
```bash
probe FARCAST_WALK_PROBE=mint-empty-kid
```
It mints once with the reader's key, sending `"kid":""` in place of the recorded key id, and requests nothing from the cluster. Record its one result line: `ACCEPTED`, `REFUSED: OAuth error …` with the code, `NOT ANSWERED: …`, `ANSWERED without a token`, or `the token endpoint's answer could not be read`. The last two are findings against the probe or the token source: record them as such. P2's `world` is the control: the same key, under its recorded id, minted there.

A refusal changes nothing today, because every key farcast mints with carries its id: the reader's is recorded by `reader record`, and the installer's key file names its own. It is still a finding for the token source, which sends whatever id is recorded.

*(2026-11-16: where the reader cannot be uploaded, `mint-empty-kid` takes `FARCAST_WALK_IDENTITY` in place of its default, the reader, as `review` and `forbidden-body` do. With `FARCAST_WALK_IDENTITY=key` and `FARCAST_WALK_KEY_JSON=probe/key.json` it mints with the throwaway account's key, so it runs before P7.1 deletes that key. This walk used that key. It was created by Google, not uploaded. The control is then the same key under its own id, which minted in P4.3.)*

## P6. Item 7: the cluster's version

The endpoint's form was read in P1.3. The cluster's version, in Cloud Shell:
```bash
gcloud container clusters describe "farcast-$INSTANCE" --region us-central1 --project "$PROJECT" \
  --format 'value(currentMasterVersion,location)'
```
Record the version and the location. Its minor version is the one ADR 0023 M2.7's no-cost test against a real API server pins.

## P7. Teardown

1. **The throwaway account**, in Cloud Shell, the binding first:
   ```bash
   gcloud projects remove-iam-policy-binding "$PROJECT" --condition=None \
     --member "serviceAccount:$PROBE_SA@$PROJECT.iam.gserviceaccount.com" --role roles/container.developer >/dev/null; echo "exit $?"
   gcloud iam service-accounts delete "$PROBE_SA@$PROJECT.iam.gserviceaccount.com" --project "$PROJECT" --quiet; echo "exit $?"
   gcloud iam service-accounts keys list --iam-account "$PROBE_SA@$PROJECT.iam.gserviceaccount.com" --project "$PROJECT" >/dev/null 2>&1; echo "keys list exit $?"
   ```
   Record the three exit statuses. The last is expected to fail, because the account and its keys are gone. Then, in the observing shell: `rm -f "$WALK/probe/key.json"`.
2. **`release`**, in the walk shell: `farcast release "$INSTANCE" --yes`. No `storage deploy` ran, so there is no bucket with objects, and `--delete-data` is not needed. *Expect* its result to end with a `reader:` line naming the reader and two Cloud Shell commands, the binding's removal first. Do not record them.
3. **The reader's account**, in Cloud Shell: run the two printed commands, in order. Then, with P0.9's `INSTANCE`:
   ```bash
   READER_SA="farcast-reader-$(printf %s "$INSTANCE" | sha256sum | cut -c1-8)"
   gcloud iam service-accounts list --project "$PROJECT" --format 'value(email)' | grep -c -e "^$READER_SA@" -e '^farcast-walk-probe@'
   ```
   *Expect* `0`. Record whether each printed command succeeded, and the count.

   *(2026-11-16, steps 2 and 3: `release` can print the reader's two lines for an account that was never created. On this walk P2.2 created no account, and `release` printed them all the same: the record held the reader's email from `reader init`, with no key id. Run then, they are expected to fail with `not found`, which is harmless. The count is still the check.)*
4. **The cloud**, in the observing shell: verify against the cloud, not local state, that clusters, registries, buckets, forwarding rules, addresses, target pools, disks and VMs are back to P0.8's counts. *(2026-11-16: count the buckets in Cloud Shell, as P0.8's note says.)*
5. `rm -rf "$WALK"`. It holds the release, the probe, the reader's script and the JSON results.
6. *(Added 2026-11-16.)* **The Org Policy API**, only if P3's managed check enabled it, in Cloud Shell:
   ```bash
   gcloud services disable orgpolicy.googleapis.com --project "$PROJECT"; echo "exit $?"
   ```
   Record the exit status. It can run any time after P3; the 2026-11-16 walk ran it after step 3.

---

## Results

Walked 2026-11-16 at 2482810, in us-central1. Every value is scrubbed. The agent ran farcast and the probe in P0.7's walk shell, and the operator ran every Cloud Shell step. The operator approved the full gate first: the cost, the duration, the two service accounts, the project-wide `container.developer` grant and the teardown. The instance lived 83 minutes: about USD 0.15 by the floor model, plus cents. The throwaway account held its project-wide grant for about 15 minutes.

| Step | Result | Notes |
|---|---|---|
| Commit, `./check.sh` | 2482810 (M2.5). `./check.sh` passed on the same tree content, run just before the commit. | The probe was built from 2482810 first. It was rebuilt twice during the walk, from 2482810 plus walk-time changes to `walkcluster_test.go` and `walkprobe_test.go`, uncommitted then: `FARCAST_WALK_SCOPE`, and `mint-empty-kid`'s `FARCAST_WALK_IDENTITY`. |
| P0 release build: `OK`, tags, revision, `vcs.modified=false` | 11 checksums `OK`, `-tags=farcast_embedded`, `vcs.revision` 2482810, `vcs.modified=false`. | `farcast-release build -targets darwin/arm64`. P0.7: `farcast version` listed four components, and the walk shell carried no `GODEBUG`, proxy or `GOOGLE_APPLICATION_CREDENTIALS`. |
| P0.5 the firewall (added) | The probe's first run printed `NOT ANSWERED: EOF` from the token endpoint, after about 16 s. Once Little Snitch allowed `walkprobe.test`, the same run was answered. | A firewall that holds or denies the probe shows as this EOF (P0.5's note). |
| P0.8 the baseline (added) | 0 clusters, 0 registries (us-central1), 0 buckets, 0 forwarding rules, 0 addresses, 0 target pools, 0 disks, 0 VMs, 2 service accounts. | The gcloud session had expired: every call failed with "Reauthentication failed", and the first attempt counted nothing. The operator signed in again and the counts were retaken. Buckets were counted in Cloud Shell, because `gcloud storage` crashes on the operator's Mac. |
| P1.1 install without `--credentials`, and with `/dev/null`: exit 2 each, no envelope, nothing created | Each exited 2, with 0 bytes on stdout and the refusal on stderr. | Nothing was recorded. |
| P1.2 install | Exit 0 after about 4 minutes. Status `running`, cloud logging `system`. | |
| Item 7, P1.3: the endpoint's form | `<51 characters>.<the region>.gke.goog` | The region label, not a zone, so farcast's endpoint rule accepts it. |
| Item 1, P1.4: the writer's preflight read before `connect` | **401 Unauthorized**, `text/html`, not a Kubernetes Status (1452 bytes), with farcast's own scope, `userinfo.email` alone. **Hard stop.** | GKE's DNS endpoint refuses farcast's own token, as it was at 2482810. Every writing command's preflight read, and every read command, would refuse the same way. The fix, `cloud-platform` back, was built later that day, with its trade-off, and is not walked (Status). |
| Item 1, P1.4 with `FARCAST_WALK_SCOPE` (added) | `cloud-platform`: **200 OK**, `application/json`. `cloud-platform+userinfo.email`, what gcloud asks for: **200 OK**. | The same request with the same installer key. So the refusal is the scope's, not the writer's. `cloud-platform+userinfo.email` is exactly the pair farcast mints with since the fix: the writer's evidence for it, sent by the probe, not by farcast (Status). *(2026-11-16, after the fix: "what gcloud asks for" is not right; the walk did not observe gcloud's request, and gcloud's own list puts `userinfo.email` first and asks for more. The pair is the probe's, P1.4's notes.)* |
| Item 1, P1.5: `connect`: exit, kind, carrier recorded, firewall log, `--status` | Not run, after P1.4's hard stop. | |
| P2.1 `reader init` (added) | Exit 0. The script was 66 lines and held no private key. `reader.key` was 0600. | |
| P2.2 the paste (added) | Stopped at its first policy check: the project's organization enforces `iam.disableServiceAccountKeyUpload`. It printed farcast's own refusal: the reader cannot be set up until an organization administrator allows upload, and nothing was changed. | No reader account was created. In an organization that blocks key upload (Google enforces it by default in newer organizations), `world`, `ps`, `costs`, `usage` and `logs` cannot read the cluster at all. |
| Item 2, P2.3: `reader record` (added) | Not run: P2.2 printed no key id. | Item 2 is not walkable in this project. |
| Item 2, P2.4 (optional): the reader before its RBAC | Not run: no reader. | |
| Item 2, P2.5: `reader grant`: elapsed minutes, the IAM line, reviews | Not run: no reader. | |
| Item 2, P2.6: `world` as the reader: error kinds, sections read | Not run: no reader. | Not walked for the reader. Its token at 2482810 carried `userinfo.email` alone, which item 1's answer says the endpoint refuses. So there the reader's reads are refused too (inferred). The fix, built later that day, gives it `cloud-platform` and `userinfo.email`; there is no evidence yet for the reader with them (Status). |
| Item 3: the paste: policy checks, retries, upload, key id shape | No policy check printed anything; both are silenced. The script stopped at the legacy check, with its clean message. | The retries, the upload and the key id's shape were not reached. |
| Item 3: the two policy checks unsilenced | Legacy (`resource-manager org-policies describe … --effective`, `value(booleanPolicy.enforced)`): `True`, exit 0. The spelling works. Managed (`org-policies describe … --effective`, `value(spec.rules[0].enforce)`): the Org Policy API was off, and gcloud asked whether to enable it. The operator enabled it, and the check printed `False`, exit 0. The spelling works once that API is on. | **Finding.** In the script the managed check is silenced and has no terminal, so gcloud cannot ask. With the API off it prints nothing, which the script reads as "not enforced". An enforced managed policy in such a project would then fail at the upload with gcloud's own error, not farcast's message. P7.6 turned the API off again. |
| P4.1, P4.2 the throwaway account and its key (added) | Account created, exit 0. Key created, exit 0, mode 0600, in the walk directory only. | Key creation is allowed in this project (`iam.disableServiceAccountKeyCreation` is not enforced), though key upload is not. An earlier attempt failed locally, before any key was created, because a helper file of the agent's sat at `$WALK/probe`. That is not a runbook defect: the runbook's `probe` is a shell function. |
| Item 6, P4.3: the endpoint's IAM refusal, every printed line | `userinfo.email`: 401 Unauthorized, `text/html`, not a Status (1452 bytes). `cloud-platform`: **403 Forbidden, `text/html`, not a Kubernetes Status** (1449 bytes). | **Settles farcast's rule:** a 403 whose body is not a Status is the endpoint's IAM, not RBAC (`forbiddenByRBAC`). The probe printed the byte count only, not the HTML's first line. How many tries the new key took was not recorded. |
| P4.4 the role (added) | `roles/container.developer` granted on the project, exit 0. | Held about 15 minutes, until P7.1. |
| Item 4, P4.5: the review: verdict, reason, minutes to settle | At about +0 min the review itself was refused: 403, `text/html`, not a Status (1449 bytes), a second sample for item 6. From about +1.5 min to +15 min, 10 answers: **ALLOWED**, reason "access granted by IAM permissions." | As the throwaway key with `cloud-platform`, asked every 90 s. **Settled: GKE's SelfSubjectAccessReviews consult IAM.** So `reader grant`'s five reviews see an IAM role stronger than `clusterViewer`, as the CLI README infers. |
| P4.6 controls (optional): writer, reader, key with its role | The writer's review (`cloud-platform`): ALLOWED, "access granted by IAM permissions." The reader's review: not run, no reader. `forbidden-body` as the throwaway key holding its role (`cloud-platform`): 200 OK. | The installer has no RBAC binding, so the writer's ALLOWED is IAM too. |
| Item 5, P5: `"kid":""` | **ACCEPTED**, with scope `userinfo.email`. Google minted a token, which was not printed. | With the throwaway account's Google-created key (`FARCAST_WALK_IDENTITY=key`), not an uploaded one: the reader could not be uploaded here. The control was the same key under its own id, which minted in P4.3. |
| Item 7, P6: the cluster's version and location | `1.36.4-gke.2377000`, location `us-central1`. | A regional cluster. The minor version is 1.36. |
| P7 throwaway account, key and binding deleted | The binding was removed (exit 0) and the account deleted (exit 0). `keys list` then exited 1, as expected. The key file was deleted. | |
| P7 `release`, the reader lines run, accounts absent | `release` exited 0 after about 5 minutes. The cluster and the registry were deleted, and the local record removed. The count of reader and probe accounts was 0. | `release` printed the reader's two Cloud Shell lines, though the reader's account was never created: the record held the reader's email from `reader init`, with no key id. Running them was not reported. With no account they are expected to fail with `not found` (P7.3's note). |
| P7.6 the Org Policy API (added) | Disabled, exit 0. | The walk had enabled it in P3. |
| P7 the cloud back to P0's counts | Every count matches P0.8 exactly, buckets included (0). The walk directory was deleted. | |
