# ADR 0024 M3a — the X.509 probe: whether Google's certificate route exists

[ADR 0024](../adr/0024-paste-the-certificate.md) decision 6 proposes that the operator's cloud credential on Google is X.509 Workload Identity Federation: for each role, reader and writer, the device makes an anchor and a leaf, and a human pastes the anchor into a provider of its own. No Google page read settles that route for the profile the [design](../design/adr-0024-design.md)'s D2 gives it: a self-signed anchor whose only subject field is a random role ID, and a leaf whose DN equals its issuer's. Design §6 defines M3a, the probe that walks it in a project in the operator's own organization. It tests first whether V1, a writer-capable device, exchanges its reader leaf at its reader provider and its writer leaf at its writer provider at all, in four chain shapes (T1). Then come the other positives, the negatives with their positive controls, the variants, the information items, renewal, revocation, the audit and the organization's policies. The probe is [`walkm3a_test.go`](../../farsight/cli/internal/cli/walkm3a_test.go) (`//go:build walk`), whose header lists its steps, its inputs and the hosts it dials. It calls `kube.Federation` and `devicekey`, the code M3b ships, so what it walks is what M3b ships.

**Status.** *Written 2026-11-22 to 2026-11-23 with M3a's build, against the code at the commit it lands in. Not run.* It needs the operator's own approval in the session that runs it (below). The approval that built it is not approval to walk it, and no earlier walk's approval carries over.

**It records fifteen things:**
1. whether Google takes D2's anchor shape, and a leaf whose DN equals its issuer's (T1, and V1x and V1y if T1 refuses every shape);
2. the per-role providers, and whether a trust store takes a second anchor (I7);
3. whether STS binds `subject_token` to the handshake, and whether it needs a client certificate (N5, N6, I6);
4. the TLS version STS's mTLS host negotiates (T1);
5. whether Google enforces the anchor's path length and builds chains through intermediates the client sends (N7, information);
6. the per-provider condition, across devices and across roles (N2, N3, N9);
7. silent leaf renewal (T3), and anchor replacement, by the paste and in the console (P6);
8. the revocation window, and IAM's settle times (P7, and every positive's delta, read with its timing note: P3);
9. the 390-day rule's reach (I4, V6, V7);
10. whether the audience takes the project's ID in place of its number (I5);
11. the organization's policies, as the project sees them (P9);
12. which IAM Credentials endpoint is needed (I1);
13. what the audit logs carry (P8);
14. the console form's fields (P2);
15. V5's and V8's viability.

**It is free.** IAM is offered at no charge ([Google](https://docs.cloud.google.com/iam/docs/billing-questions)); STS and impersonation are unpriced, and a session's Data Access entries fit inside Cloud Logging's free ingestion (both inferred). **It is hard to reverse:** a deleted pool's or provider's ID stays reserved for about 30 days ([Google](https://docs.cloud.google.com/iam/docs/manage-workload-identity-pools-providers)), which the run's random IDs absorb. If enabling STS or IAM Credentials needs a billing link, the walk stops and asks; whether it does is unverified.

**Do not start P0, its P0.0 project included, until the operator has approved this walk for this session.** Approval does not carry over from another walk, nor from the approval that built M3a. The agent presents, and waits for a yes:
- the project (G0): by default a fresh scratch project the operator creates at P0.0 in their own organization, with no billing account linked, and shuts down at P10 (e);
- the object list (G0);
- the cost: USD 0, and a billing link stops the walk (above);
- that a deleted pool's and provider's IDs stay reserved for about 30 days (above);
- the temporary Data Access change: Admin Read, Data Read and Data Write for STS and IAM Credentials, and Admin Read on the IAM API; and the Org Policy API if P9 needs it;
- the teardown (P10), and that Google may leave on the APIs the walk enabled (P10 (b));
- the deviations G0 accepts ([Deviations](#deviations)), with what 4 and 8 change in the project;
- the session's length: 3 to 4 hours if Google refuses a revoked token within minutes, and up to about 6 if P7 lets each held token run to its end (deviation 12).

Throughout:
- **Scrubbing.** The design's scrub rule applies to every record this walk makes. IDs, numbers, emails and host names are given in words, and a service endpoint is named by what it is ("STS's mTLS token endpoint", "IAM Credentials"), never by its host, as the M2 walk's T1 also says. This runbook's own steps name Google's public hosts where a firewall rule needs them; a record does not. Dates only, never a time of day. "Withheld" stands for anything that survives the scrub, with a finding against the probe.
- **Machines.** The Mac runs the probe and the tools in `/usr/bin` and `/bin` only, and no `gcloud`. Cloud Shell runs every `gcloud`, as the operator's FarCast account, checked by eye, never a work account.
- **The agent and Cloud Shell.** The agent never types into Cloud Shell and never sees its raw output. The operator relays only each block's labelled lines: states, yes/no and counts. Every block asks y/N for the project before its first `gcloud`.
- **Secrets.** Never print a token. Every key lives only under `$WALK/m3a`. The agent never `cat`s a block or the state: it names a block by its path, and `pbcopy` reads it. Record dates only.
- **The walk shell** has no `GODEBUG`, `GOOGLE_*`, proxy, `SSL_CERT_*` or `KUBECONFIG` variable. The probe also refuses them itself, naming each variable and never its value.
- **From P1 on, any stop runs P10 first.**

---

## G0. Approval and choices (no spend)

- **The project:** one fresh scratch project in the operator's organization (the default), which the operator creates at P0.0 with no billing account linked and shuts down at P10 (e); or another project there. Whether it is kept or shut down after P10.
- **The object list** (design §6):
  - the project itself, when it is the fresh one (P0.0 to P10 (e));
  - the APIs: IAM, IAM Credentials, STS and Resource Manager, each enabled only if it is off, and recorded in a randomly named file in Cloud Shell's home, so P10 tries to disable exactly those and keeps the record of any Google leaves on (deviation 21);
  - one pool, with a random ID;
  - up to fourteen providers, by variant: V1's two, V1b's, V1c's two (through the console), V2, V3, V4, V5, V6, V7, V8, and V1x and V1y only if T1 refuses every shape for a role;
  - two service accounts, with no display name;
  - one project grant: the reader SA's `roles/iam.workloadIdentityPoolViewer`, IAM Workload Identity Pool Viewer, the role [Google names](https://docs.cloud.google.com/iam/docs/manage-workload-identity-pools-providers) for viewing pools and providers (read 2026-11-23), for T4's read-back;
  - the `roles/iam.workloadIdentityUser` bindings, one per principal, on the reader SA but V1's writer, which is on the writer SA;
  - Data Access audit logs, in this project only, until P10 (c): Admin Read, Data Read and Data Write for the Security Token Service API and the IAM Service Account Credentials API, and Admin Read for the IAM API. [Google's audit-logging examples for workload identity federation](https://docs.cloud.google.com/iam/docs/audit-logging/examples-workload-identity) (read 2026-11-23) ask for Admin Read on both the IAM API and the Security Token Service API "to receive audit logs for all steps of the token-exchange process", and show STS's exchange entry as Admin Read, so Data Read and Data Write alone would record none. The page does not say which step the IAM API logs, so `audit.sh` reads its entries too (P8). Which sub-type `generateAccessToken` uses is unverified, so IAM Credentials gets all three;
  - the Org Policy API, if P9 needs it, asked for in P9 and again before P10 disables it.
- **The deviations G0 accepts:** every one but 2, 6, 22 and 23, which are the probe's own mechanics and change nothing in the project ([Deviations](#deviations)): 1, 3, 4 (V1's two providers are deleted while their bindings stand; P10 (b) removes the bindings after), 5, 7, 8 (P7 (b) re-enables V1's writer provider, an IAM change the design does not make; if the re-enable fails, P7 (c) holds the reader alone and the writer provider's deletion is not measured), 9 (I6 gates as N6), 10 (TLS 1.3 on the exchange), 11 (positive controls; only a decision is a refusal; `INCONCLUSIVE` gates), 12 (P7's information timings run to the token's end), 13 (staged anchor renewal), 14 (I4 run twice), the build's 15 to 19, 20 (P3 straight after P1; Data Access and P2 after P3) and 21 (the teardown leaves on an API Google will not disable without `--force`).
- **The yes,** with its date.

## P0. Setup on the dev Mac (no cloud)

0. **The project** (operator, only if G0 chose a fresh one), after G0's yes: create it in the operator's own organization, in the console or Cloud Shell, with no billing account linked. Its ID, which P0.5 and `init` take, is never recorded. This is the walk's only step before P1 that changes anything in the cloud, and it bills nothing.
1. `./check.sh` passes at the commit being walked, from a clean tree. Record the commit and the summary line.
2. **The walk directory**, outside any checkout:
   ```bash
   REPO=<the checkout, at that commit>
   WALK=$(mktemp -d)        # 0700
   mkdir -m 700 "$WALK/m3a"
   ls -led "$WALK" "$WALK/m3a" | cut -c1-11
   ```
   *Expect* exactly two lines, each `drwx------` with no `+` after it. A `+`, or any further line, is an access control list, which can let another account read a 0600 key: `devicekey` and the probe check mode bits only (`devicekey.Store`'s comment). Then stop, remove the directory, and make it again where no ACL is inherited.
3. **The probe, built once** at a fixed path. No `FARCAST_*` variable is set, and the agent's shell does not move:
   ```bash
   env GOWORK=off GOTOOLCHAIN=go1.27.4 GOPROXY=off GOFLAGS=-mod=vendor \
     go test -C "$REPO" -tags walk -c -o "$WALK/walkprobe.test" ./farsight/cli/internal/cli/
   ```
4. **The outbound firewall** (Little Snitch). Rules for `$WALK/walkprobe.test`, one per destination, and nothing else. Each rule is named by what it is and the page that gives it:
   - `sts.mtls.googleapis.com:443`, STS's mTLS token endpoint ([X.509 federation](https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-x509-certificates));
   - `iamcredentials.googleapis.com:443`, IAM Credentials ([generateAccessToken](https://docs.cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken));
   - `sts.googleapis.com:443`, STS's plain endpoint, for V5 and I6 ([STS](https://docs.cloud.google.com/iam/docs/reference/sts/rest/v1/TopLevel/token));
   - `iamcredentials.mtls.googleapis.com:443`, for I1 alone: no page read names it, and it follows the `*.mtls.googleapis.com` convention (inferred);
   - `iam.googleapis.com:443`, for T4's read-back of V1's providers ([providers.get](https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.locations.workloadIdentityPools.providers/get));
   - `oauth2.googleapis.com:443`, for T2's token info ([token types](https://docs.cloud.google.com/docs/authentication/token-types)).

   A binary the firewall holds shows as `NOT ANSWERED: EOF` after about 16 s, not as a refusal ([the probe walk's P0.5](adr-0023-m2-probe-walk.md#p0-setup-on-the-dev-mac-no-cloud)). Allow it for that destination only, and run the step again.
5. **The walk shell**, with nothing inherited but what is named:
   ```bash
   env -i HOME="$HOME" TMPDIR="$TMPDIR" WALK="$WALK" PROJECT=<the project id> PATH="/usr/bin:/bin" zsh -f
   ```
   Then, inside it:
   ```bash
   cd "$WALK"
   env | grep -iE '^(GODEBUG|GOOGLE_|HTTPS?_PROXY|ALL_PROXY|NO_PROXY|SSL_CERT_|KUBECONFIG)' && echo "STOP: unset these"
   probe() { (cd "$WALK" && env FARCAST_WALK=1 FARCAST_WALK_CWD="$WALK" FARCAST_WALK_M3A_DIR="$WALK/m3a" \
     FARCAST_WALK_PROJECT="$PROJECT" "$@" "$WALK/walkprobe.test" -test.run '^TestWalkM3a$' -test.v -test.count=1 -test.timeout 0); }
   ```
   *Expect* the `grep` to print nothing. The walk shell works in `$WALK`, so nothing it writes lands in the checkout. Every step below is a call of the form, its output files named by their full path:
   ```bash
   probe FARCAST_WALK_M3A_STEP=<step> [FARCAST_WALK_M3A_MARK=<name>] [FARCAST_WALK_M3A_SINCE=<name>] > "$WALK/<step>.out" 2> "$WALK/<step>.err"; echo "exit $?"
   ```
   `mark <name>` below means `probe FARCAST_WALK_M3A_STEP=mark FARCAST_WALK_M3A_MARK=<name>`. The agent reads the `.out` files, which the probe has scrubbed, and records what each step says to record. A step that refuses its environment, its directory or its state fails before it sends anything.
6. `init`, then `blocks`. Record the counts `init` printed, "directory mode 0700: yes", and each block's 12-hex digest from `blocks.out`'s `wrote blocks/<block> (sha256 <digest>)` lines (a digest names nothing). Keep `$WALK/blocks.out`: P2.0 compares the second `blocks` against it. Each block is pasted the same way: `pbcopy < "$WALK/m3a/blocks/<block>"`, then the operator's paste, its `y`, and its labelled lines.
7. **Cloud Shell**, by the operator. Sign in as an Owner of the project; type `PROJECT=<the project id>`, never recorded; then take the baseline, counts and yes/no only, with these lines, each of which reads nothing from stdin, so no `gcloud` offer to enable an API can be taken:
   ```bash
   count() { local out; out=$("$@" --project "$PROJECT" --format='value(name)' --quiet </dev/null 2>/dev/null) || { echo "not read"; return; }; printf '%s\n' "$out" | grep -c .; }
   gcloud services list --enabled --project "$PROJECT" --format='value(config.name)' --quiet </dev/null | grep -xE '(iam|iamcredentials|sts|cloudresourcemanager|orgpolicy)\.googleapis\.com'
   count gcloud iam workload-identity-pools list --location=global
   count gcloud iam service-accounts list
   gcloud projects get-iam-policy "$PROJECT" --format=json --quiet </dev/null | jq '[.bindings[]?.members[]?] | length'
   gcloud projects get-iam-policy "$PROJECT" --format=json --quiet </dev/null | jq -r '[.auditConfigs[]? | select(.service == "sts.googleapis.com" or .service == "iamcredentials.googleapis.com" or .service == "iam.googleapis.com" or .service == "allServices") | .service + ": " + ([.auditLogConfigs[]?.logType] | join(", "))] | if length == 0 then "no Data Access configuration" else .[] end'
   ```
   - Record, in words: which of the IAM, IAM Credentials, STS, Resource Manager and Org Policy APIs are on, yes or no each (the `services list` line shows them by their public names on screen; the record names them in words); the pools, DELETED excluded; the service accounts; the project's IAM members; and, yes or no per sub-type, the project's own Data Access configuration for STS, IAM Credentials, IAM and all services, so P10 (c) puts back exactly that.
   - In the default fresh project the IAM API is off: it is not among the services a new project has enabled ([Google](https://docs.cloud.google.com/service-usage/docs/enabled-service), read 2026-11-23). Then the pool and service-account lines print `not read`: record them as "API off: 0". Answer N to any offer to enable an API, so that only `setup.sh` enables one and records it, and P10 (b) and (d) know of it.

## P1. The setup paste

1. The agent runs `pbcopy < "$WALK/m3a/blocks/setup.sh"`. The operator pastes it, answers `y`, and relays each labelled line: the APIs enabled or already enabled, the pool, each provider `created`, `exists` or `refused` with its yes/no words, the two service accounts, the project grant, and each binding `added` or `refused`. A grant or binding right after the service accounts are created is retried for up to 210 s: Google says a new service account may take 60 s or more before it can be used ([Google](https://docs.cloud.google.com/iam/docs/service-accounts-create), read 2026-11-23). The block prints its last line, the coordinates, only when the grant and every binding printed `added` (deviation 23).
2. **At once, as soon as the block prints its last line,** which names the project and its number, the operator copies it, and the agent runs, in turn, printing nothing of the line:
   - `pbpaste > "$WALK/m3a/line"`;
   - `coordinates`, with `FARCAST_WALK_M3A_LINE="$WALK/m3a/line"`. *Expect* `coordinates recorded: yes; the project matches: yes`;
   - `rm "$WALK/m3a/line"`;
   - `mark setup`;
   - then straight to P3's `t1` (deviation 20). T1's settle deltas and each role's first binding's, which set M3b's enrolment retry bound (design §6), measure from this mark, so nothing comes between the mark and `t1`: Data Access, the second `blocks` and P2 wait until P3 is done.
3. If a named policy refuses V1's providers, the project grant or a binding, the block stops there: after V1's providers' refusal at once, and after a grant's or binding's at its end, with `setup not complete` and no coordinates line. Record it, run P9, then P10 from (b).
4. After any other failure (a refusal that names no policy, `setup not complete`, an `exit 1` part way, a Cloud Shell reset), paste `setup.sh` again: the pool, every provider and both service accounts print `exists` when they are there, an API already on prints `already enabled`, and the grant and the bindings are added again. Record both pastes' lines. The mark is taken after the paste that printed the last line. Paste it at most three times in all; then record the line that kept failing, run P9, then P10 from (b).

## P2. The console form (V1c), after P3

0. Once P3 is done (deviation 20):
   - **Data Access**, in the console: IAM & Admin, then Audit Logs. For the Security Token Service API and the IAM Service Account Credentials API, Admin Read, Data Read and Data Write; for the Identity and Access Management (IAM) API, Admin Read. Record which sub-types were turned on. The exchanges P3 made come before it and are not in the Data Access logs; P4's and later ones are.
   - `blocks` again, its output to `"$WALK/blocks-2.out"` in place of `blocks.out`. `console-v1c.txt` gains V1c's two principals, which name the project's number; every other block is written byte-identical, with the same digest (deviation 15). Check it: `diff <(grep '^wrote blocks/' "$WALK/blocks.out") <(grep '^wrote blocks/' "$WALK/blocks-2.out")` shows `console-v1c.txt`'s two lines and nothing else. Record "byte-identical but console-v1c.txt: yes/no"; on "no", stop: a block P10 pastes differs from P0's.
1. The operator opens `$WALK/m3a/blocks/console-v1c.txt` on the Mac in their own viewer, never in the agent's shell.
2. They create V1c's two providers through the console's X.509 provider form, from its fields: the provider ID, the trust anchor's PEM, the mapping and the condition. Then V1c's two principals on the reader SA's permissions page, with `roles/iam.workloadIdentityUser`; or, as the fallback, by pasting `bind-v1c.sh`.
3. Record, in words, whether the form offers Trust anchors, Intermediate certificates, the attribute mapping and the attribute condition, and which route made the bindings.
4. The agent runs `mark console`, then `console`. It tries S1 to S4 for each of V1c's roles, so V1c's result does not depend on T1. Record each role's passing shapes and each impersonation line. V1c is information.

## P3. The positives (gating)

- Run `t1` straight after P1's `mark setup`, then `t2`, `t3` and `t4`, in that order. `t1` sends V1's two roles' and V1b's twelve (role, shape) entries in one round-robin from the setup mark, and, from the round in which a role's first shape is accepted, that role's first impersonation: V1's reader at the reader SA, V1's writer at the writer SA, V1b at the reader SA. So each exchange's settle time and each binding's first settle time is measured from the mark under the settle rule, and none waits for another entry's tries to reach the bound (deviation 22). V1's two impersonations there are information; V1b's is V1b's T2, and gates. `v1b` runs V1b alone again, for a rerun. `t2` polls both roles' exchanges and impersonations in one round-robin; `console` and `contingent` do the same for V1c's and for V1x's and V1y's.
- **Timing notes.** Each positive's line says how far its delta is a settle time: "first tried N s after the mark, past the bound: not a settle time" (a step that started past the bound, or a rerun: one try, and its delta is the time since the mark); "accepted at its first try, N s after the mark: the settle time is at most that" (an upper bound); "first tried N s after the mark" (the settle time lies between that and the delta); no note: tried from the mark under the settle rule. Record each note with its delta. Item 8 counts as a settle time only a delta with no note; a delta with an "at most" or a "first tried" note is a bound, and one with "not a settle time" is none.
- **A gating positive's verdict** (T1 to T4, V1b): `holds` when accepted; `FAILS` when its last answer was a decision against it; `INCONCLUSIVE` when its last answer was no decision (a 3xx, a 429, a 5xx, an alert that is not a certificate's, or none). An `INCONCLUSIVE` positive gates until its step is run again, as a negative's does (deviation 11). A rerun past the bound from its mark makes one try per entry, and its delta is the time since the mark, not a settle time: record it as a rerun.
- **T4's read-back.** `t4` polls each of V1's two providers' read-back from the setup mark under the settle rule until it answers 200, because the reader SA's pool viewer grant it needs is an IAM change of the same paste, and Google gives a policy change as typically 2 minutes, potentially 7 or longer ([Google](https://docs.cloud.google.com/iam/docs/access-change-propagation), read 2026-11-23). A 200 holds when the provider matches and `FAILS` when a field differs. At the bound, a 400, 401, 403 or 404 reads `FAILS`; a 3xx, a 429, a 5xx or no answer reads `INCONCLUSIVE`.
- **T2's reading rule.** T2 holds for a role only if its impersonation line is an acceptance and, when token info answered 200, its line lists both `cloud-platform` and `userinfo.email`. If token info answers with any other status, it is "not answered by POST", and T2 holds on the impersonation's 200 alone. If token info is not answered at all, or its 200 is not readable, T2 reads `INCONCLUSIVE`: run `t2` again. "Email matches" is information. The probe prints each role's `T2 <role> token info:` verdict line and folds it into `T2:`.
- Record:
  - from `t1`, each role's verdict line, its passing shapes and the simplest, each acceptance's delta with its timing note, `issued_token_type`, lifetime and `TLS 1.3: yes/no`; each first-binding impersonation line with its delta and note; and V1b's passing shapes and its two verdicts (or, after a rerun, `v1b`'s);
  - from `t2`, each role's impersonation line, its token info line (email matches, the scope set and the expiry in minutes; or "token info not answered by POST" with its status) and its token info verdict line;
  - from `t3`, each role's verdict;
  - from `t4`, each provider's status with its delta and note, and "trust store, mapping, condition and state match: yes", or the field that differs.
- If `t1` meets `tls: protocol version not supported`, stop: lowering the exchange's TLS floor is a code change and a rebuild, and the operator decides (deviation 10).
- If T1 refuses every shape for a role, the walk takes the contingent branch. V1x and V1y are their own providers, so they record no shape for V1: `negatives` refuses to start without a passing shape for V1's reader, V1's writer and V1b, and P7 and P10 (a) need them too. So P4, P6 and P7 cannot run on V1: record the pass rule as not met as written. Design §6 makes a passing V1x, V1y, V2 or V3 the route then, so the branch still records the audit and the console form:
  1. P2.0: Data Access and the second `blocks`; then P2, if the operator wants V1c's console form (item 14), which needs no T1 shape.
  2. P5's `contingent-blocks`, its paste, `mark contingent`, and `contingent`.
  3. P5's `variants`, always (V2 to V8 fall back to S1 to S4 when T1 recorded no reader shape); and `i1` to `i7-removed` only when T1 recorded a shape for V1's reader, since each sends in it.
  4. P8, P9, then P10 from (b).

## P4. The negatives

- Run `negatives`. It refuses to start until `t1` (or a `v1b` rerun, for V1b) has recorded a passing shape for V1's reader, V1's writer and V1b, and until `t3` has saved the old reader leaf.
- It sends each negative in the simplest shape T1 recorded for the role whose provider it targets, beside its positive control through the same `kube.Federation`. It checks every negative at once, then again at the later of the latest mark plus 10 minutes and 60 s after its last first check (the settle rule, from the latest mark: deviation 5).
- N4's control is the same token at its own SA. N10's is two calls, the reader's token at the reader SA and the writer's at the writer SA, both accepted; so a reader token IAM Credentials does not authenticate is no control, and N10 cannot hold on a refusal that tested nothing about the writer SA.
- Only a decision is a refusal: a 400, 401 or 403; or, ending the exchange before an answer, one of the certificate's TLS alerts, which Go words as `bad certificate`, `unsupported certificate`, `revoked certificate`, `expired certificate`, `unknown certificate`, `unknown certificate authority`, `access denied` and `certificate required`. Any other alert (`internal error`, `handshake failure`, `error decrypting message`, `error decoding message`, `protocol version not supported` among them), any alert while an answer is read, a 3xx, a 429, a 5xx, or no answer, tested nothing: its check reads as its control refused, its line says "no decision" with the alert's words, and the row reads `INCONCLUSIVE`. Any 200, a usable token or not, is an acceptance. If a row stays `INCONCLUSIVE` on `handshake failure` or `error decrypting message` after a rerun, those alerts name no certificate, so whether the row holds is the operator's decision, recorded with the row.
- Record every row's two checks, each with its control's result, and its verdict: `holds`, `FAILS` or `INCONCLUSIVE`. N4 and N10 note a status that is not 403.
- An `INCONCLUSIVE` row gates as a failure until `negatives` is run again and the row reads `holds` or `FAILS`. Record each rerun.

## P5. Information

1. `variants`: V2 to V8, each in T1's reader shape (S1 to S4 if T1 recorded none), and V5's JWT at STS's plain endpoint. Record each exchange line and each impersonation line. A provider refused at creation for a limit is recorded from P1's lines.
2. `contingent-blocks`. If it wrote `contingent.sh`: its paste, the operator's lines, `mark contingent`, then `contingent`. Otherwise record "not needed: T1 passed".
3. `i1` to `i6`, in order, after `variants`. Record each line. I1's client with V1's reader leaf takes TLS 1.3 at least, so the leaf never crosses the network in clear (deviation 10); a refusal at 1.3 is I1's answer. I4 (a)'s leaf predates its issuer, and its line says so.
   - **I6 gates as N6, and is read as a negative** (deviations 9 and 11). `i6` sends the mTLS token type to STS's plain endpoint with no client certificate, beside a positive control at the same endpoint in the same form encoding: V5's JWT exchange, as `jwt`, else as `id_token`. It checks both at once and again at the later of the latest mark plus 10 minutes and 60 s after the first. Record both checks with their controls, and the verdict. Any 200 at either check, a usable token or not, is `FAILS`. A control refused or not answered, or an I6 answer that is no decision (a 3xx, a 429, a 5xx, or none), is `INCONCLUSIVE`. Both gate until `i6` is run again.
   - I6's control is V5. If V5's provider was refused at P1, or V5 was never accepted in `variants`, no exchange at the plain endpoint can show that it answers this form, so I6 stays `INCONCLUSIVE` and the pass rule is not met as G0 accepted it. Record it; the operator decides.
4. The `i7-add.sh` paste, its line, `mark i7-add`, then `i7-added`.
5. The `i7-remove.sh` paste, its line, `mark i7-remove`, then `i7-removed`.

A mark, here and in P6, P7 and P10, is taken only after the block printed its change: `updated`, `removed`, `added`, `disabled`, `enabled` or `deleted`. For `teardown-v1.sh` that is `deleted` for each of V1's two providers, across the pastes since `hold-delete` started: a provider an earlier paste deleted prints `absent` on the next, and counts as deleted. On any other `absent`, or `refused`, or a policy line the operator cannot read, take no mark: record the line, and paste again, at most twice. If the change still did not print, record the step as not measured and follow its own branch: P6.4 for a renewal; P7 (a), (b) or (c) as each says; I7 is information. A gating row not measured means the pass rule is not met as written, which the operator decides. A held step that waits for its mark times out after 30 minutes; start it again only while what it holds still exists. After a partial `teardown-v1.sh` whose `hold-delete` has ended, it cannot hold the reader again, because the reader provider may be gone: go to P10 (b), and record P7 (c)'s deletion as not measured.

## P6. Renewal (not gating)

1. `renew`; paste `renew-paste.sh`; when it printed `updated`, `mark renew-paste`; `renewal` with `FARCAST_WALK_M3A_SINCE=renew-paste`. It commits the staged renewal only if the new leaf exchanged (deviation 13).
2. `renew-console`. The operator replaces the writer provider's trust anchor through the console's edit form, from `console-renew.txt`, opened in their own viewer. Once the console has saved the change, `mark renew-console`, and `renewal` with `FARCAST_WALK_M3A_SINCE=renew-console`.
3. Record each `renewal`'s four measurement lines: the renewed leaf's exchange; the renewed writer impersonating the writer SA, which is the check that the grants are unchanged (design §6, P6); the current leaf polled until refused; and V1's reader. Then "committed: yes/no" and its information line.
4. If a `renewal` did not commit, the staged renewal is still in place, and the writer still holds its current material:
   - Run `renewal` again, with the same `FARCAST_WALK_M3A_SINCE`. If Google applied the change but it settled after the bound, the staged leaf gets one more try, and on an acceptance the renewal commits.
   - If it still did not commit, run `renew-discard`, whatever the paste's block (or the console's form) printed. That covers a paste refused twice, after which no mark exists and `renewal` cannot run, and a paste that printed `updated` but whose staged leaf never exchanged. It exchanges the current writer leaf at V1's writer provider, and only if that is accepted does it discard the staged renewal (`discarded: yes`), so it is safe in every case. Then `renew-console` (P6.2) can stage a renewal again, and P7 goes on.
   - If the current writer leaf is refused, `renew-discard` keeps the staged renewal (`discarded: no`), because Google may now trust the staged anchor alone. Record "writer stopped at P6", and skip the writer's parts of P7. A skipped P7 (b) means the pass rule is not met: design §6 requires that the exchange after P7's disable be refused. The operator decides.

## P7. Revocation

A held step makes its tokens, impersonates once with each held token and with its control's, and only then prints `holding a federated token; paste <block>, then mark; waiting for mark <name>`, and polls the state for that mark for up to 30 minutes. So a held token's "refused after N s" always follows an acceptance before the paste, and a binding already gone, or not yet settled, stops the step before the paste instead of reading as a revocation's window. The agent starts it in the background with its output in its own files, `(probe FARCAST_WALK_M3A_STEP=<step> > "$WALK/<step>.out" 2> "$WALK/<step>.err"; echo "exit $?" > "$WALK/<step>.exit") &`, and waits for that line. Only then does the operator paste, and only once the block printed its change does the agent run `mark` (P5's rule); then the agent waits for the held step to end. A held step that ends before it prints `holding…` made no token to hold: its line says why. Paste nothing; record the line, and run the step again.

From the mark, a held step polls everything it measures in one loop, each on its own schedule: each gating new exchange at the settle rule's times until it is refused with its control accepted or the 10-minute bound passes, and each held token's impersonation every 60 s until it is refused with its control accepted or it expires. So every delta is measured from the mark, and no held token waits for a gating poll to end. A held token's line reads "refused after N s", "accepted until it expired after N min" only when a poll whose control was accepted saw it accepted, or "no conclusive poll before it expired".
- **(a)** Start `hold-binding`. Paste `revoke-binding.sh`; when it printed `removed`, `mark revoke-binding`; wait, up to about an hour. Then paste `readd-binding.sh`; when it printed `added`, `mark readd-binding`; `writer-back` with `FARCAST_WALK_M3A_SINCE=readd-binding`. Record "refused after N s" or "accepted until it expired after N min", and `writer-back`'s two lines. If `writer-back`'s impersonation is not accepted, the binding is not back, or not settled: paste `readd-binding.sh` again, mark, and run `writer-back` again, at most twice, before P7 (b). If it is still refused, `hold-disable` stops before its paste (its writer token does not impersonate): record P7 (b) as not measured, and go to (c), where `hold-delete` does not time the writer's held token but still polls the writer's new exchange.
- **(b)** Start `hold-disable`. Paste `disable-writer.sh`; when it printed `disabled`, `mark disable-writer`; wait. The new writer exchange polled until refused is gating; the held token's timing is information (deviation 12). Then paste `enable-writer.sh`; when it printed `enabled`, `mark enable-writer`; `writer-back` with `FARCAST_WALK_M3A_SINCE=enable-writer` (deviation 8). `--no-disabled` is the flag [Google's page](https://docs.cloud.google.com/iam/docs/manage-workload-identity-pools-providers) names for enabling a provider (read 2026-11-23); what is measured is the re-enable's outcome, so record its line. Google also documents that after a disable "existing tokens still grant access" ([update-x509](https://docs.cloud.google.com/sdk/gcloud/reference/iam/workload-identity-pools/providers/update-x509), read 2026-11-23), so the held token is expected to read "accepted until it expired". If the re-enable is refused, or `writer-back` stays refused, V1's writer provider is still disabled: P7 (c) then holds the reader alone and prints "writer not re-enabled", and the writer provider's deletion is not measured. The design's pass rule asks for the exchange after the deletion to be refused for each of V1's providers, so whether it is met is then the operator's decision, recorded with the verdict.
- **(c)** is P10 (a). `hold-delete` holds the reader alone only when its writer exchange was refused with a decision, as it is while the writer provider stays disabled; any other failure to make a writer token stops it before the paste, as above.

## P8. The audit reads

- `audit-block`, then paste `audit.sh`. It reads the last day's Admin Activity entries for the pool and providers and for `SetIamPolicy` on the service accounts; the Data Access entries for STS and IAM Credentials; and the IAM API's Data Access entries, which Google's page asks Admin Read for to log every step of the exchange without saying which step they hold. Of the IAM API's it counts all, checks all for keyInfo, a role ID and a fingerprint, and reads the rest only of those with a principalSubject or a method that is not a Get or a List, which leaves out the operator's own describe and list calls [inf]. It prints counts, scrubbed key paths and yes/no lines; each yes names, in words, the services whose entries carry it.
- It looks for each leaf's serial and fingerprint, and for each CA's fingerprint: every anchor, I7's, N1's, the negatives' intermediates and each staged anchor. Google's X.509 keyInfo carries the trust anchor's or the intermediate CA's SHA-256 fingerprint, not the leaf's ([Google](https://docs.cloud.google.com/iam/docs/audit-logging/examples-workload-identity), read 2026-11-23), and an anchor's fingerprint names one device's role for 390 days, across its leaves' renewals.
- Record which Data Access sub-types were on (P2.0), and that P3's exchanges came before them. A "no" with Admin Read off for STS or for the IAM API would record less than Google logs; with both on, the "no" is Google's.
- The operator relays the counts, the key paths and the yes/no lines, among them which encoding of a leaf's serial or fingerprint, or of a CA's fingerprint, matched, if any, and in which service's entries. Record field names, encodings and services in words only.
- Session control (ADR 0023:176) is an operator observation, recorded in words.

## P9. The organization's policies

- Paste `policies.sh`. It asks y/N before enabling the Org Policy API, and records it if it does, for P10.
- The operator relays each constraint's line: enforced yes/no; for a list constraint, allow all, deny all, or its counts of values; for `iam.workloadIdentityPoolProviders` and its managed twin, the allowed values' kinds as counts; and the custom constraints on WIF providers as a count, or "not readable".
- Record each constraint's state as the block prints it, and whether the organization carries the whole secure-by-default set: yes only when all seven of the baseline's constraints read `enforced: yes`, or carry a list policy, as the block prints them. The [secure-by-default page](https://docs.cloud.google.com/resource-manager/docs/secure-by-default-organizations) (read 2026-11-23) lists them: `iam.managed.disableServiceAccountKeyCreation`, `iam.disableServiceAccountKeyUpload`, `iam.automaticIamGrantsForDefaultServiceAccounts`, `iam.allowedPolicyMemberDomains`, `essentialcontacts.managed.allowedContactDomains`, `compute.managed.restrictProtocolForwardingCreationForTypes` and `storage.uniformBucketLevelAccess`; and it says that `compute.restrictProtocolForwardingCreationForTypes` may already be applied to some organizations created after 15 August 2024, so the block reads it too. Record also whether P1's bindings were admitted, from P1's lines. Every name the block reads is on [Google's constraint list](https://docs.cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints) (read 2026-11-23; deviation 17); a name Google no longer knows prints "not readable".

## P10. Teardown

- **(a)** Run it only once `t1` (or a `v1b` rerun) has recorded a passing shape for V1's reader, V1's writer and V1b, and V1's two providers exist. Otherwise, after an early stop (P1.3) or T1's contingent branch (P3), skip it and start at (b). Start `hold-delete` in the background. Paste `teardown-v1.sh`, which deletes V1's two providers and nothing else, so the measurement isolates the deletion (deviation 4); when it printed `deleted` for each of the two, across its pastes (P5's rule), `mark teardown-v1`; wait. Each role's new exchange polled until refused, with V1b's exchange as its control, is gating. This is P7 (c).
- **(b)** Paste `teardown.sh`. It removes every binding and the project grant first, before any service account is deleted; then every provider still present, the pool, and the two service accounts; then the APIs `setup.sh` recorded as enabled, asking y/N before the Org Policy API. Each line skips an absent object. Each API is tried once, without `--force`: Google refuses to disable a service used in the last 30 days, or enabled in the last 3, without it (deviation 21), so the walk's APIs are expected to print `kept enabled`. An API disabled leaves the block's record in Cloud Shell's home; one kept stays in it, and the block prints `API record: kept`, so it can be pasted again. In the default fresh project, (e)'s shutdown covers them. In a kept project, the operator decides whether to disable them with `--force`, which also disables the services that depend on them, after reading `gcloud services list --enabled --project "$PROJECT"` for dependents; until then (d) expects them on.
- **(c)** Put Data Access back as P0.7 recorded it: turn off, in the console, the sub-types P2.0 turned on for STS, IAM Credentials and IAM, and read P0.7's last line again to check.
- **(d)** Take P0.7's baseline again, with its lines, and compare it with P0's. The APIs (b) kept enabled are expected on; record them as kept, by name, with the operator's `--force` decision.
- **(e)** Shut the project down, unless G0 kept it. If (b) kept the API record, remove it from Cloud Shell's home once the APIs are settled: it is the file named on the `RECORD=` line of `teardown.sh`, which the operator reads in their own viewer.
- **(f)** `rm -rf "$WALK"`, which removes every key, the state, the blocks and every step's `.out`, `.err` and `.exit` file.

The IDs stay reserved for about 30 days, which random IDs absorb.

---

## Results

Not walked. When it runs, this section holds an opening sentence, one table and the pass rule's verdict.
- **The opening sentence:** the date, the commit, the project's kind (in words), who ran what, and the approval's date.
- **The table**, one row per P-step and one per item below. A row holds statuses, codes, alert words, TLS versions, shapes, deltas in whole seconds, counts and yes/no; and, where the step says so, field names and scrubbed key paths (P8), each constraint's name and state (P9), the console form's fields and the binding route in words (P2), and the Data Access sub-types (P2.0, P8). Never an ID, a number, an email or a host name.

| Step | Result | Notes |
|---|---|---|
| G0 approval and choices | Not run | |
| P0 the project (P0.0); `./check.sh`; the directory's ACL check (P0.2); the build, the firewall, the walk shell; `init`'s counts; `blocks`' digests | Not run | |
| P0.7 the baseline: the five APIs yes/no, the pools and service accounts (or "API off: 0"), the project's IAM members, and the Data Access sub-types for STS, IAM Credentials, IAM and all services | Not run | |
| P1 the setup paste: APIs, pool, providers, accounts, grant, bindings | Not run | |
| P2 Data Access turned on (P2.0), by sub-type; the second `blocks`, byte-identical but `console-v1c.txt`: yes/no; the console form: its fields; V1c's shapes and impersonations | Not run | |
| T1 V1's reader and writer: shapes passing, the simplest, TLS version, each delta with its timing note; each role's first binding's impersonation (information) | Not run | |
| T2 impersonation; token info's two scopes (T2's reading rule) | Not run | |
| T3 silent leaf renewal | Not run | |
| T4 the read-back of V1's two providers, polled from the setup mark | Not run | |
| V1b T1 and T2 (in `t1`, or a `v1b` rerun) | Not run | |
| V1c (P2) | Not run | |
| N1 a foreign anchor | Not run | |
| N2 (a) another device's ID as the leaf's CN | Not run | |
| N2 (b) an intermediate carrying another device's ID | Not run | |
| N3 another device's leaf | Not run | |
| N4 another device's token at the writer SA | Not run | |
| N5 (i) and (ii) a `subject_token` that is not the handshake's leaf | Not run | |
| N6 no client certificate | Not run | |
| N7 (i) a reader-ID intermediate (information) | Not run | |
| N7 (ii) a writer-ID intermediate at the reader provider (gating as N9) | Not run | |
| N7 (iii) the same chain at the writer provider (gating as N1) | Not run | |
| N8 expired and not yet valid (information) | Not run | |
| N9 (a), (b) and (c) across roles on one device | Not run | |
| N10 the reader's token at the writer SA | Not run | |
| V1x, V1y (if needed) | Not run | |
| V2 to V8 | Not run | |
| I1 IAM Credentials' mTLS endpoint | Not run | the leaf's client at TLS 1.3 at least |
| I2 `userinfo.email` at STS | Not run | |
| I3 a leaf 20 minutes from its end | Not run | |
| I4 (a) under V1's reader anchor; (b) under V6's | Not run | I4 (a)'s leaf predates its issuer |
| I5 the project's ID in the audience | Not run | |
| I6 the mTLS token type at the plain endpoint (gating as N6), beside V5's exchange as its control | Not run | |
| I7 a second anchor added, then removed | Not run | |
| P6 renewal by the paste, and in the console: the renewed leaf, its impersonation of the writer SA (the grants unchanged), the current leaf refused, the reader | Not run | |
| P7 (a) the binding removed | Not run | |
| P7 (b) the writer provider disabled | Not run | |
| P7 (c) V1's providers deleted | Not run | |
| P8 the audit reads, IAM's Data Access entries included; leaf and CA fingerprints; the Data Access sub-types on | Not run | |
| P9 the organization's policies; the secure-by-default set whole: yes/no | Not run | |
| P10 teardown, and the baseline again; the APIs kept enabled | Not run | |
| The no-organization project | not run; deferred until most of FarSight is ready | (ADR 0024 decision 3) |

- **The pass rule's verdict,** as design §6 states it, with the deviations G0 accepted that change it: 9 (I6 gates as N6) and 11 (an `INCONCLUSIVE` row or positive gates). T2 holds by P3's reading rule: both scopes when token info answers 200. Where P7 (c) held the reader alone (P7 (b)), the verdict records the operator's decision on the writer provider's deletion.

## Deviations

From the design, accepted at G0 or recorded here, and any found while walking:
1. **T4's read-back sends the reader's SA token to IAM's API host, from the probe.** D6's rule, the bearer only to IAM Credentials' host, binds `federated.go` and holds there. T4 must read the providers through the reader's own token, and providers are read at `iam.googleapis.com`. The comparison itself is product code (`devicekey.CheckProvider`).
2. **I1, I6 and V5's exchange are probe-only paths.** They share the product's body builders. Product code presents its certificate to STS's mTLS host alone, and never sends to STS's plain endpoint.
3. **The firewall has six destinations, not four.** V5 and I6 also need STS's plain endpoint, and T4 needs IAM's API host.
4. **P7 (c) runs before P10's bindings first.** V1's two providers are deleted while their bindings stand, so the measurement isolates the deletion. P10 (b) removes the bindings afterwards. Accepted at G0, because it changes the order of the project's teardown from the design's "bindings first".
5. **The settle bound runs from a named mark.** The agent records the mark after the operator ends a paste. Each positive measures from the mark of the change it tests, and a negative's second check from the latest mark. The probe cannot see the IAM change itself, so each delta is a lower bound on Google's settle time.
6. **P7's held tokens are coordinated through `mark`,** read by a background probe, not through stdin: the agent cannot answer a prompt.
7. **W-FED runs a probe binary in the M2 walk** ([its section](adr-0023-m2-walk.md#w-fed-the-federated-reader-at-the-cluster-optional-adr-0024)), under its own approval and its own firewall rules.
8. **P7 (b) re-enables V1's writer provider after its measurement,** so that P7 (c) can hold a writer token when the providers are deleted. It is an IAM change the design does not make, with the flag (`--no-disabled`) Google's page on managing providers names; what is measured is whether the re-enable took. If it fails, P7 (c) holds the reader alone and the writer provider's deletion is not measured (P7 (b)). Accepted at G0.
9. **I6 gates, as N6 does.** An acceptance at I6 means STS's plain endpoint exchanges a leaf with no proof of possession, which is what N6 gates. It is read as a negative, checked twice beside V5's exchange at the same endpoint as its control (deviation 11), so a V5 that never passes leaves I6 `INCONCLUSIVE`.
10. **The exchange transport's TLS floor is 1.3.** In TLS 1.2 the client's Certificate message, the leaf with its role ID, crosses the network in clear. The impersonation transport keeps the 1.2 floor. T1 records the negotiated version.
11. **Every gating negative, I6 included, and every gating poll for a refusal, carries a positive control,** in the simplest shape T1 recorded for its target provider's role; I6's is V5's exchange at the same plain endpoint, and N10's both other cells (P4). A check whose control was refused reads `INCONCLUSIVE`, and gates as a failure until it is run again. Only a 400, 401 or 403, or one of the certificate's TLS alerts ending the exchange before an answer (P4), counts as a refusal; any other alert, an alert while an answer is read, a 3xx, a 429, a 5xx or no answer tested nothing, and reads `INCONCLUSIVE` too. A gating positive whose last answer was no decision reads `INCONCLUSIVE` the same way (P3). So a refusal for an unrelated reason cannot pass M3a, and a server's failure cannot fail it.
12. **P7's information timings run until the held token is refused or expires,** not to the 10-minute bound. The gating rows keep the bound. Every timing and gating poll of a held step runs from its mark in one loop. Each of the three held steps (`hold-binding`, `hold-disable`, `hold-delete`) may run to its token's end, about 60 minutes, where the design's bound is 10, so it lengthens the session by up to about 2.5 hours, which the session's length at G0 includes.
13. **An anchor renewal is staged, and committed only after its verification exchange,** so the role keeps working until Google applies the paste, and the old anchor key survives a failed paste. A renewal Google did not take is discarded by `renew-discard`, only while the current writer leaf still exchanges.
14. **I4 runs twice:** (a) as the design has it, whose leaf predates its issuer, so a refusal there cannot be read as the 390-day rule alone; and (b), the same length nested inside V6's backdated anchor, read beside V6's own result.
15. **`blocks` runs twice.** `console-v1c.txt`'s principals name the project's number, which only `coordinates` records. The second run writes every other block byte-identical.
16. **Steps that make a leaf record it in the state,** so `audit.sh` can look for each leaf's serial and fingerprint: `init`, `t3`, `negatives`, `i3`, `i4`, `renew` and `renew-console` write the state for that. The negatives', I3's and I4's leaf keys live in memory for their one step.
17. **P9 reads more than the baseline.** Its list holds the secure-by-default baseline's seven, the legacy protocol-forwarding constraint the baseline's page names, and the non-managed and managed twins of the IAM, key and contact constraints; every name was checked against Google's constraint list and the secure-by-default page, both read 2026-11-23. G0 may check them again.
18. **`audit.sh`'s key-path scrub also replaces any field name of 20 or more characters,** such as the user agent's, as the scrub rule's run of 20 token characters does. `principalSubject`, `keyInfo` and the user agent have yes/no lines of their own.
19. **`wfed-gone` has no positive control:** after the teardown nothing remains to accept. Its refusals are read alone, and W-FED does not gate. It polls the two exchanges only, both in one loop from the teardown's mark, so the writer's delta does not wait for the reader's poll to end: a federated token it made would come after the teardown's mark, and the teardown deletes the service accounts too, so an impersonation's refusal there would say nothing about the federation's revocation, which P7 measures.
20. **P3 runs straight after P1's mark, before Data Access and P2.** With P2's console forms and Data Access between the setup mark and `t1`, T1's round-robin would start past its 10-minute bound, each entry would get one try, and its deltas would measure the operator's console work, not IAM's settle time, from which M3b's enrolment retry takes its bound. So `t1` runs first, then `t2` to `t4`; Data Access, the second `blocks` and P2 follow. P3's exchanges are then not in the Data Access logs (P8).
21. **The teardown leaves on an API Google will not disable.** gcloud's `services disable` refuses, without `--force`, a service used in the last 30 days or enabled in the last 3, and `--force` also disables the services that depend on it. The blocks try each API once without it, and keep the record of what is still on; P10 (b) and W-FED's WF.5 leave the choice of `--force` to the operator.
22. **`t1` also polls V1b and each role's first impersonation, in its one round-robin.** Run after `t1`, `v1b` and `t2` would start when `t1` ended, past the bound whenever a shape is refused for good, and their deltas would be the time since the mark, not a settle time. So `t1` sends V1b's shapes beside V1's, and polls each role's first impersonation from the round its first shape is accepted in; `v1b` is a rerun alone. Every positive's line carries its timing note (P3), and a held step impersonates with each held token before its paste (P7), so no delta is recorded as a settle time or a revocation window that is not one.
23. **`setup.sh` and `wfed-setup.sh` print their coordinates line only when every grant and binding was added,** retrying each that follows the service accounts' creation for up to 210 s. Otherwise they print `setup not complete` and exit 1, so P1.2's "at once" never marks a partial setup.

## The record

Once walked: dated notes in ADR 0024 (decision 3, Phasing's M3a row, Verification 1) and in ADR 0023's Verification 4, never rewriting walked or accepted text.
