# ADR 0024 and ADR 0023's M3a: paste the certificate the installer shows (design, v3)

*(2026-11-22: kept in the repository from here on, with ADR 0024's records. It was drafted outside it, so the sizing prototypes it cites (`proto/`, `variantb/` and `twoanchor/`, with `twoanchor/perrole_test.go`), the critique of v1 and the earlier versions were working files in a scratch directory, and are not kept. A [ran] result is reproduced only by repeating it. Code citations are file:line at 5ef5ee8, and paths are relative to the repository root. A bare file name is in `farsight/cli/internal/cli/`, or is cited with its directory earlier in this design; `kube/` is `farsight/cli/internal/kube/`.)*

This is the design behind [ADR 0024](../adr/0024-paste-the-certificate.md), the operator's cloud credential, and behind [ADR 0023](../adr/0023-one-download-farcast.md)'s milestone M3a, the identity probe. It was written 2026-11-22 against the repository at 5ef5ee8 (ADR 0023 M2.9b). Nothing in it is built or walked, M3a has not run, and no cloud call was made. *(2026-11-23: M3a's part of it was built 2026-11-22 to 2026-11-23: `devicekey`, `kube/federated.go`, the probe, its runbook and W-FED's steps, offline and wired into no command (§11). M3a has not run.)* *(2026-11-23, M3a walked: it ran 2026-11-23 at bb51a6d and passes in a project in the operator's own organization (§6; [the runbook's Results](../runbooks/adr-0024-m3a-probe.md#results)). The run in a project with no organization stays deferred, and the DNS endpoint with an impersonated token stays unverified.)* *(2026-11-24, ADR 0023's M2 walked: W-FED ran in M2's walk on 2026-11-24, in a project in the operator's own organization. GKE's DNS endpoint accepted a token impersonated with the scope pair from the device's federated reader token, and the username Kubernetes saw was the reader SA's email ("email matches: yes"); the federated token itself got 403, authenticated, then refused.)* *(2026-11-26, M3b.1: M3b's build began; its first step, M3b.1, was built that day in `devicekey`, offline and wired into no command (§12). Nothing of M3b is walked.)* *(2026-11-26, M3b.2: M3b's second step, M3b.2, was built that day in `config`, offline and wired into no command but for the installer key's load, which now refuses a blank key and quotes nothing of a file that does not parse (§13).)*

This is v3. All three versions are of 2026-11-22.
- **v1** merged three designs written from three priorities: privacy, the operator's procedure, and uniformity across providers. Where they disagreed, privacy and cost control won, then the operator's procedure, then uniformity. Each decision says which answer it took, and why the others lost where that is still true.
- **A critique of v1** found three blocking defects, twelve major and fourteen minor. Among them: one principal per device held both the reader's and the writer's power, so every read carried writer-capable material; a role ID that was its own key's hash marked every FarCast anchor; defaults were recorded as accepted; and the M2 walk's Google-made key was covered by no decision.
- **v2** resolved each finding. From it come the two roles per device (D2), the random role IDs (D2, D3), the accepted and proposed marks, the gating negatives N5 and N6 and the settle rule (§6), and the pending installs (D7).
- **v3** records the operator's answers of the same day. It also makes one provider per role the default, in place of v2's two anchors in one provider. With two anchors in one provider, keeping the reader's key from the writer would rest on Google enforcing the anchor's path length, which none of the Google pages read says it does (D2).

**What the operator decided on 2026-11-22.** These are accepted.
1. **The procedure.** The operator's cloud credential is the same on every provider: **paste the certificate the installer shows**. The installer (the `farcast` CLI today, the FarSight app later) makes its own keys on the device and shows public certificates. The human creates the identity once, in the provider's console or its cloud shell, and pastes them in. Nothing secret leaves the device.
2. **The fallback rule.** A provider-made secret is used only where the certificate route is closed. It is named and consented.
3. **M3a first.** ADR 0023's M3a, the identity probe, is brought forward, before M2's billable walk.
4. **The order.** M2's billable walk runs on its own after M3a, then M3b. That is D9's branch S, the separate walks. There is no merged walk.
5. **The projects.** M3a and M2's walk use a project in the operator's own organization. A project with no organization comes later, when most of FarSight is ready. So M2's walk takes branch [B]: key upload is blocked there, the installer's Google-made key is an exception to ADR 0024 that the operator approves at the walk's G0a, time-boxed and deleted at teardown, and the reader is not walked in M2. *(2026-11-24, ADR 0023's M2 walked: the walk ran 2026-11-24 under [B]. The exception was the installer's existing key, deleted in Google and on the Mac at W6.2, after which the installer held no user-managed key; the reader was not walked.)*
6. **Who enrols (ADR 0023 Choices 5): human only.** Every device addition, renewal and revocation is a human's paste. No FarCast identity can enrol devices.

Everything else here is proposed, with a default, until the operator answers it (§9).

**Marks.**
- **[read]**: read in the repository at 5ef5ee8, or in its vendored source.
- **[ran]**: run locally and offline on the dev Mac, in the scratch directory the opening note names, with go1.27.4 under `GOWORK=off GOTOOLCHAIN=go1.27.4 GOPROXY=off GOFLAGS=-mod=vendor`, no `FARCAST_*` set, against loopback fakes only. The prototypes are not kept.
- **[doc]**: a web page, with its key below.
- **[inf]**: an inference.
- **[unverified]**: not settled by any source read.

**Web sources** (all fetched 2026-11-22):
- [X509] https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-x509-certificates. Fetched a second time that day, for v2, for the trust-store limits, the 390-day wording, the attribute list, the `subject_token` rule and the console's Trust anchors field.
- [TS] https://docs.cloud.google.com/iam/docs/reference/rest/v1/TrustStore. Fetched a second time that day, for v2.
- [PROV] https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.locations.workloadIdentityPools.providers
- [MGMT] https://docs.cloud.google.com/iam/docs/manage-workload-identity-pools-providers
- [STS] https://docs.cloud.google.com/iam/docs/reference/sts/rest/v1/TopLevel/token
- [AUD] https://docs.cloud.google.com/iam/docs/audit-logging/examples-workload-identity
- [OIDC] https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-other-providers
- [CUS] https://docs.cloud.google.com/iam/docs/workload-identity-federation-custom-constraints
- [DRS] https://docs.cloud.google.com/organization-policy/domain-restricted-sharing
- [SBD] https://docs.cloud.google.com/resource-manager/docs/secure-by-default-organizations
- [QUOTA] https://docs.cloud.google.com/iam/quotas
- [PRICE] https://docs.cloud.google.com/iam/docs/billing-questions
- [GKEAUTH] https://docs.cloud.google.com/kubernetes-engine/docs/how-to/api-server-authentication
- [GKERBAC] https://docs.cloud.google.com/kubernetes-engine/docs/how-to/role-based-access-control
- [GKESA] https://docs.cloud.google.com/kubernetes-engine/docs/how-to/service-accounts (for the node account's minimum role)
- [RN] https://docs.cloud.google.com/iam/docs/release-notes (X.509 federation GA 2025-05-07; WIF custom constraints 2026-04-07)
- [POLHIST] https://docs.cloud.google.com/iam/docs/review-iam-policy-history (from the critique)
- [AUDLOG] https://docs.cloud.google.com/logging/docs/audit/understanding-audit-logs (from the critique)
- [WV-2020] https://developers.googleblog.com/2020/08/guidance-for-our-effort-to-block-less-secure-browser-and-apps.html (from the critique)
- [WV-2021] https://developers.googleblog.com/en/upcoming-security-changes-to-googles-oauth-20-authorization-endpoint-in-embedded-webviews/ (from the critique; fetched a second time that day, for v2: it names WKWebView)
- [WV-HELP] https://support.google.com/accounts/answer/7675428 (from the critique)
- [RA-TRUST] https://docs.aws.amazon.com/rolesanywhere/latest/userguide/trust-model.html
- [RA-START] https://docs.aws.amazon.com/rolesanywhere/latest/userguide/getting-started.html
- [RA-SIGN] https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-sign-process.html
- [RA-QUOTA] https://docs.aws.amazon.com/general/latest/gr/rolesanywhere.html
- [AWS-SCP] https://docs.aws.amazon.com/accounts/latest/reference/scps-and-rcps-for-projects.html
- [AWS-ADV] https://docs.aws.amazon.com/accounts/latest/reference/activate-advanced-features.html
- [ENTRA-CERT] https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials
- [ENTRA-RSA] https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-self-signed-certificate
- [ENTRA-FIC] https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-create-trust
- [ENTRA-POL] https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-app-management-policies
- [ENTRA-LOG] https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs (the fields)
- [ENTRA-RET] https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-reports-data-retention (the retention)

**The scrub rule for this design and everything it records.** Dates only, never a time of day. No host name, address, port, account or project name, home path, uid, resourceVersion, key id or token byte. The only placeholders are `$INSTANCE` and `$PROJECT`; every other value is in words ("the role ID", "the project's number"). Service endpoints are named by what they are ("STS's mTLS token endpoint"), and their exact URLs are given by reference to the page that states them.

---

## 0. Where things stand, and what this design settles

- **M2 is built and not walked** beyond the 2026-11-16 probe walk. M2's billable walk is written (`docs/runbooks/adr-0023-m2-walk.md`) and has not run (ADR 0023:3, AGENTS.md:48, PLAN.md:454-457) [read]. *(2026-11-24, ADR 0023's M2 walked: M2's billable walk ran 2026-11-24 at 3fd79c4 under [B], W-FED included; the reader was not walked.)*
- **Today's writer** is a Google-made installer key that the operator downloads (`docs/runbooks/phase-1-validation.md:85-86`; `install.go:58`) [read].
- **Today's reader is already a certificate paste,** in its service-account-key-upload form. `farcast reader init` makes an RSA-2048 key on the device, with a `CN=unused` certificate (`farsight/cli/internal/kube/readerkey.go:16-72`), and the human uploads only that certificate from Cloud Shell (`farsight/cli/internal/cli/readerinit.go:395-432`) [read]. The operator's organization blocks key upload, so the reader could not be set up there (ADR 0023:119's 2026-11-16 note), and M2's walk, which runs there, does not walk it.
- **Reads never mint an admin token** (ADR 0023:115-117). Today the reader's key cannot write, and `world` never opens `credentials.yaml` [read]. This design keeps that rule by key separation (D2).
- **ADR 0023 decision 5** (ADR 0023:153-176) proposed an ES256 JWT signed by the device, an uploaded JWKS and a `.invalid` issuer. This design proposes X.509 federation in its place on Google, where the pasted thing is a certificate [doc: X509].

This design settles D1 to D11 (§1, §2); the outline of a new ADR 0024 (§3); the dated notes to ADR 0023 and the other records (§4, §5); M3a in full (§6); M3b's revised scope (§7); the Phasing changes (§8); the questions for the operator (§9); and the risks (§10). The operator's answers of 2026-11-22 are recorded as accepted where they apply: the procedure and the fallback rule (D7), M3a's place and its project's organization (D8), human-only enrolment (D4), and the order with its branch (D9). Everything else is proposed, with its default.

---

## 1. Decisions at a glance

| # | Question | Decision | Status |
|---|---|---|---|
| D1 | Google's route | X.509 Workload Identity Federation: each role's certificate is the trust anchor of its own X509 provider, exchanged over mutual TLS, then `generateAccessToken`. OIDC with an uploaded JWKS is the measured fallback, not the route. | proposed; gated on M3a |
| D2 | The artifact | Per device, per instance, per role: a self-signed P-256 anchor (the pasted certificate) and a leaf the device issues under it. A reader-only device has two keys; a writer-capable device four. Anchor 390 days, leaf 90 days. The CN is the role ID only. One provider per role: a reader-only device has one provider, a writer-capable device two, each trust store holding one anchor. | proposed |
| D3 | Mapping, condition, grants, names | `google.subject` from the issuer CN; per provider, a condition that the issuer CN equals the subject CN and equals that provider's one role ID; each role ID bound to its own SA only; role IDs of 128 random bits; random object IDs; no names in any certificate or object | proposed |
| D4 | Enrol, revoke, renew | Human only: every device addition, renewal and revocation is a human's paste, and no FarCast identity can enrol devices. The mechanics: enrol by one paste and an automatic read-back; add the writer role by one paste that creates its provider; revoke by removing bindings, then deleting the providers; leaves renew silently, each within its role's rule; anchors by one paste that replaces each provider's anchor | **accepted** (human only, ADR 0023 Choices 5, 2026-11-22); the mechanics proposed |
| D5 | Token path | Each role impersonates its own per-instance SA, with `[cloud-platform, userinfo.email]`, never direct grants. The reads that use the installer today move to the reader with resource-scoped read grants | proposed; reads decided per read in M3b |
| D6 | Code | Hand-rolled on the standard library: `farsight/cli/internal/devicekey` and `kube/federated.go`. No module, no vendor change, no exec site | proposed |
| D7 | The procedure | The same four steps on every provider: show, paste, one non-secret line back, verify. Fallbacks ordered from "still public material" down to "a provider-made secret", each named and consented. Pending installs are listed and can be abandoned | **accepted** (the procedure and the fallback rule); specifics proposed |
| D8 | M3a | An X.509 probe in a project in the operator's own organization (proposed: one fresh scratch project there), free IAM objects only, before M2's walk (§6). The run in a project with no organization is deferred until most of FarSight is ready | **accepted** (its place, and its project's organization); the project and the content proposed |
| D9 | Order | M3a, then M2's walk on its own under [B] in the operator's organization, then M3b. Proposed, as a revisit trigger: if M2's walk has not run when M3b's build is done, the operator decides again | **accepted** (branch S, with [B]); specifics proposed *(2026-11-24, ADR 0023's M2 walked: M2's walk ran 2026-11-24, before M3b's build started, so the trigger cannot arise)* |
| D10 | Records | A new ADR 0024; dated notes in ADR 0023, 0007, 0019 and 0020 and in three runbooks; AGENTS.md, PLAN.md and the README rewritten in place where they summarise; this design in `docs/design/`; the M2 design gains §41. M3a's runbook and W-FED's steps come with M3a's build | proposed |
| D11 | Privacy accounting | Removes, wherever the certificate route or a device-made fallback is open, every Google-made secret, and, on the certificate route, the reader's named display name; fallback 3 keeps a Google-made key where every other route is closed, and M2's walk keeps one as its time-boxed exception; adds opaque per-device, per-role pseudonyms, which are stated, not hidden; lists the marks that remain | proposed *(2026-11-24, ADR 0023's M2 walked: the walk kept the installer's existing key, deleted at its W6.2)* |

---

## 2. The decisions

### D1. Google's route: X.509 federation *(proposed, gated on M3a)*

**Decision.** On Google, the operator's identity is Workload Identity Federation with X509 providers.
- Each role's anchor certificate is the one trust anchor of that role's provider, pasted by the human (D2).
- The device exchanges a role's leaf at STS's mTLS token endpoint, naming that role's provider in the audience, with `subject_token_type` `urn:ietf:params:oauth:token-type:mtls`. The `subject_token` is a JSON list of base64 DER certificates that "must at least include `CLIENT_CERT` as the first item", the handshake's leaf [doc: X509, STS].
- The federated token then impersonates that role's service account through `generateAccessToken` (D5).

OIDC with an uploaded JWKS, ADR 0023 decision 5's proposal, is **not** the route. M3a measures it once, as variant V5, so that it is a measured fallback for three cases only: Google's route, if M3a refuses every X.509 shape, not by a policy, and V5 passes; D7's fallback 1, in an organization that closes X.509 and admits OIDC, built in M3b if V5 passed; and the Mac app's route alone, if M5 finds that the Mac's Secure Enclave key cannot form a TLS client identity. *(2026-11-23, M3a walked: STS accepted every X.509 shape M3a tried, and M3a recorded V5 passing, in a project in the operator's own organization, so the first case did not arise and the other two stand.)*

**Why.**
- **It is literally the procedure.** The console's X509 form has a **Trust anchors** field: "enter your trusted CA certificates in PEM format" [doc: X509, fetched again]. The OIDC form takes the JWKS only as a file upload [doc: OIDC].
- **There is no issuer URI.** That removes ADR 0023:164's `.invalid` workaround. It does not remove the organization-policy question. `iam.workloadIdentityPoolProviders`'s documented values are issuer URIs [doc: MGMT], so whether a restricted list admits an X.509 provider, and under which value, is [unverified]. M3a's P9 records it. *(2026-11-23, M3a walked: P9 read it not enforced, allow all, and its managed twin not enforced with no allowed values, in the operator's own organization, so a restricted list's value for an X.509 provider stays [unverified].)*
- **Possession is proved on every exchange,** by the TLS handshake, if STS binds `subject_token`'s first item to the handshake's certificate. The page says the handshake's leaf "must be specified as the first item" [doc: X509]; that STS enforces it is [unverified], and M3a's N5 and N6 are gating for it. An ES256 subject JWT is a bearer credential that can be replayed until its `exp` [doc: OIDC]. *(2026-11-23, M3a walked: N5 and N6 held, and I6 with them.)*
- **Leaves renew without a human.** The device re-issues a role's leaf under that role's pasted anchor (D2). A JWKS upload "replaces any existing uploaded keys", so every JWKS rotation is a human step [doc: PROV].
- **It is the artifact AWS takes.** A Roles Anywhere trust anchor is a pasted CA certificate [doc: RA-START], so Google and AWS share one artifact and one verb.
- X.509 federation has been GA since 2025-05-07 [doc: RN], and takes P-256 and P-384, and RSA from 2048 to 4096 bits [doc: X509]. Neither `iam.workloadIdentityPoolProviders` nor its managed twin is in Google's secure-by-default set [doc: SBD], so the route is open by default where no one restricted it [inf]. M3a runs in the operator's own organization, and P9 records which of that set the organization carries; it is recorded, not assumed. *(2026-11-23, M3a walked: P9 read both not enforced. Of the set's seven, the organization carries key upload, automatic grants, uniform bucket access and allowed policy member domains, and not managed key creation, managed contact domains or managed protocol forwarding, so not the whole set.)*

**Why the other answers lost.** The three designs agreed on the route. They differed only on V5: the operator's design left OIDC out of M3a and would probe it in a second round only after a failure. It lost because V5 costs one free provider and a few minutes, and it saves a second approval round in each case that needs it.

**Costs.**
- The proof is mutual TLS, so on the Mac at M5 each Secure Enclave leaf key must become a TLS client identity, not only a signer (§7, §10).
- The vendored X.509 credential source cannot be used (D6).
- Google stores every field of every anchor and sees every leaf, so every field must say as little as possible (D2, D11).
- There is no CRL or OCSP: the page mentions neither [doc: X509, fetched again]. Its limits table gives a "Maximum leaf certificate lifetime" of 390 days, and "Certificates with a validity period that's more than 390 days will stop working" [doc: X509]. Whether Google holds anchors to it is [unverified] (V6, V7). *(2026-11-23, M3a walked: V6 and V7 were admitted and exchanged, while a 430-day leaf was refused (I4), so the rule binds leaves and not anchors [inf].)*

### D2. The artifact: per role, an anchor and a leaf the device issues, in a provider of its own *(proposed)*

**Decision.** For each instance it serves, an operator device holds one or two **roles**, reader and writer. For each role it makes two P-256 keys: an **anchor key** and a **leaf key**. *(2026-11-23: built offline in M3a's `devicekey`, wired into no command. Where the build departs, and what its reviews changed, are in §11.)* *(2026-11-23, M3a walked: N7 (i) was accepted: Google built a chain through an intermediate the client sent, under an anchor of path length 0, so it does not enforce path length [inf]. D3's one anchor per provider does not rely on it, and N7 (ii) and (iii) held.)*
- A **reader-only device** makes a reader anchor key and a reader leaf key: two keys.
- A **writer-capable device** also makes a writer anchor key and a writer leaf key: four keys.
- No key is ever an instance-PKI key (ADR 0020), and none is reused across instances, across roles or across a revoke.

| | An anchor (pasted; one per role) | A leaf (never pasted; one per role) |
|---|---|---|
| Key | the role's anchor key | the role's leaf key, new at every renewal |
| Subject | CN = the role ID, and nothing else | CN = the same role ID, and nothing else |
| Issuer | itself (self-signed) | the role's anchor |
| Serial | 128 random bits | 128 random bits |
| basicConstraints | critical, CA:TRUE, path length 0 | critical, CA:FALSE |
| keyUsage | critical, keyCertSign | critical, digitalSignature |
| extendedKeyUsage | clientAuth, as Google's example CA carries [doc: X509] | clientAuth |
| Validity | NotBefore one hour back, truncated to the second; NotAfter = NotBefore + 390 days exactly | NotBefore one hour back, truncated; NotAfter = NotBefore + 90 days, or the anchor's NotAfter if that is sooner; renewed at half its life |
| Key identifiers | the subject key identifier Go adds: the first 20 bytes of SHA-256 of the subjectPublicKey [ran] | an authority key identifier set explicitly to the anchor's; no subject key identifier [ran] |
| Anything else | no O, OU, SAN, policy, AIA or CRL distribution point | the same |

- **NotAfter** is NotBefore plus the lifetime, as `kube/readerkey.go:54-59` does for the reader certificate [read]. So the total is exactly 390 or 90 days, never an hour over.
- **The authority key identifier** is set on purpose. The leaf's DN equals its issuer's, and Go's `crypto/x509` then leaves the field out [ran]. Setting it lets a chain builder match the leaf to its anchor by key as well as by name. Whether Google accepts a leaf whose DN equals its issuer's is [unverified]; M3a's T1 tests exactly this shape, and V1y one whose DN differs (§6). *(2026-11-23, M3a walked: T1 accepted it in all four shapes for both roles, so V1y was not made.)*
- **keyEncipherment is left out of the leaf,** though Google's RSA example carries it [doc: X509], because it has no meaning for an EC key [unverified whether Google requires it]. If M3a refuses V1 in all four chain shapes, it tries V1x, Google's example extensions verbatim, before reading any other variant as the route (§6). *(2026-11-23, M3a walked: T1 passed without it, so V1x was not made.)*

**The role IDs.**
- Each is 128 random bits, written as 32 lowercase hex characters.
- It is drawn once per device, per instance, per role, and kept in the device's record of that instance.
- It is never derived from a key, the instance name or a counter.
- It is kept across anchor renewals (D4), so the principal and its grant do not change.
- It fits `google.subject`'s 127 bytes [doc: QUOTA].
- No human compares it by eye. A block printed elsewhere could print any ID, so a shown value binds nothing. The binding checks are D4's read-back and `device ls`.

**Where the anchors go, on Google: one provider per role.** Each role of each device has an X509 provider of its own, in one pool per instance (D3).
- A reader-only device has one provider, holding its reader anchor.
- A writer-capable device has two providers, a reader's and a writer's. Each trust store holds that role's one anchor, and each condition pins that role's own ID (D3).
- The X.509 page's limits table gives 3 trust anchors and 10 intermediate certificates [doc: X509, fetched again]. The REST reference states no maximum, and says each trust anchor's PEM "Must only contain one ca certificate" [doc: TS, fetched again]. One anchor per trust store is inside both.
- The Cloud Shell block still creates both of a writer-capable device's providers in one paste. The console route takes two provider forms for such a device (D7).

**The key-custody rules.** They keep ADR 0023:115-117's "reads never mint an admin token" by key separation, not only by code.
- Read commands, and every plan under `--plan` and `--confirm`, open only the reader keys. The reader leaf renews silently at half its life inside any command, with the reader anchor key.
- The writer leaf key opens only in a command after its consent (`--confirm`, or a terminal's question), or at enrolment: for D4's one verification exchange and, in `install`, its one read of the project's number (D7). It never opens in a read command or a plan. *Proposed, for the operator to confirm:* on the CLI, `--yes` also counts as that consent wherever a command accepts it today, so a scripted run can still write. On the Mac, the broker keeps ADR 0023:116's `--confirm` alone. *(2026-11-26, M3b.1: confirmed by the operator with §9's question 24's default; built as `ConsentYes` (§12), wired at M3b.8.)*
- The writer anchor key opens only to renew the writer leaf inside such a command, or in `device renew`. It also opens at enrolment, in `install` and `device add --role writer`, and when `device renew` makes a new anchor, to issue the first writer leaf under that anchor, which is exchanged once for verification (D4). So a writer leaf may lapse while unused; the next consented command renews it before its exchange.
- On the Mac at M5, the broker holds all four keys in the Secure Enclave and issues reader tokens by default, and a writer token only to a child started with `--confirm` (ADR 0023:116, :195).

**AWS** and **Azure:** D7.

**Why.**
- **Two roles, two anchors.** With one principal per device, every read on the CLI, a terminal `farcast`, Linux and Windows would open a key that mints writer power, and the anchor key could mint any number of such leaves. ADR 0023:115 names the outcome: "the read path would become the most privileged path". Two anchors with their own principals and grants make Google refuse a reader key's attempt to act as the writer (M3a's N7 chain carrying the writer ID, N9 and N10), so the split holds outside the Mac's broker too.
- **One provider per role.** With two anchors in one provider, keeping the reader's key from reaching the writer would depend on Google enforcing the anchor's path length. The reader anchor's key can make an intermediate CA whose CN is the writer ID, and the condition, which reads the leaf's immediate issuer, would then admit a writer principal. None of the Google pages read for this design says that X.509 federation enforces path length, so it is [unverified]. A provider per role needs no such assumption: the reader's provider admits only the reader ID, and the writer's provider trusts only the writer's anchor, so a chain the reader anchor's key made is refused at both, whatever the verifier does with path length [ran: `twoanchor/perrole_test.go`, against fakes]. Path length then bounds nothing across roles or devices, and M3a's N7 records it for information. N7's chain carrying the writer ID still gates: accepted at either provider, it fails M3a as N9 or N1 does (§6).
- **It is the documented common shape.** AWS requires the anchor to be CA:true with Certificate Sign and the end entity to be CA:false with Digital Signature [doc: RA-TRUST]. One pair per role serves both providers.
- **Two keys per role,** because neither provider documents a CA and a leaf sharing one key [unverified]. M3a measures the shared key (V2), so that a later dated note may halve the key count. *(2026-11-23, M3a walked: V2 was accepted in S1, and its token impersonated the reader's account (information); the key count stays as it is until a decision.)*
- **Random role IDs.** A CN that is the lowercase hex SHA-256 of its own key would let Google find every FarCast anchor it holds with one hash, with no false positives. After the first anchor renewal it would also stop being true. A random ID marks nothing; it is a pseudonym (D11).
- **Privacy.** The certificate carries a random ID, a public key, a random serial and dates. Nothing in it says FarCast or names the instance. The profile's shape is still a set of traits shared by every FarCast anchor, listed in D11.
- **Human-only enrolment** holds by construction [inf] (ADR 0023 Choices 5, :229, answered 2026-11-22). An anchor reaches Google only by a human's paste, and an anchor can only ever renew its own role on its own device, because its provider trusts it alone and its condition names only its own ID (D3). It holds only while no account the writer can act as holds pool-admin rights, by actAs or through GKE's Workload Identity (D4's *How it holds*).
- **390 days for the anchor.** It meets the 390-day rule whether Google applies it to anchors or only to leaves [unverified], and a device that is forgotten, or stolen unnoticed, stops on its own within about a year. *(2026-11-23, M3a walked: V6, an anchor backdated 400 days and valid two years, and V7, valid five years, were admitted and exchanged, while a 430-day leaf was refused (I4), so the rule binds leaves and not anchors [inf].)*
- **The offline mechanics pass** [ran]: `twoanchor/`, a prototype in the scratch directory, not kept; `go -C twoanchor test -race ./...` and `go vet`, against loopback fakes of STS's exchange and IAM Credentials. It builds this profile exactly: random IDs, the issuer-equals-subject condition, 390-day anchors with clientAuth and path length 0, 90-day leaves, NotAfter = NotBefore + lifetime, every key behind an opaque `crypto.Signer`.
  - Each anchor PEM is 644 or 648 bytes, twelve lines, so each trust store is one such PEM. A leaf PEM is 635 or 639 bytes. The sizes vary with the signature's and the serial's encoding (twenty runs).
  - `perrole_test.go`, written for v3, walks the default: a writer-capable device with a reader provider and a writer provider, and a reader-only device with one. Against the fakes: each role's leaf exchanges at its own provider and impersonates its own SA only; the reader's federated token gets 403 at the writer SA, and the writer's at the reader SA; a reader-anchor leaf carrying the writer ID is refused at the reader provider by the condition and at the writer provider by the trust store; each role's leaf is refused at the other role's provider; a `subject_token` that is not the handshake's leaf, a missing client certificate, a foreign CA, another device's leaf or ID, an expired and a not-yet-valid leaf, and an intermediate under a path-length-0 anchor are refused; a replaced writer anchor with the same ID works and the old one's leaf does not; a deleted writer provider stops the writer and leaves the reader working.
  - It also stands in for a verifier that ignores path length: an intermediate the reader anchor's key made, naming the writer ID, is refused at both per-role providers, and one naming the reader ID reaches the reader SA only. `twoanchor_test.go`, v2's, shows the same chain reaching the writer SA when both anchors share one provider. That is why the default changed.
  - `twoanchor_test.go` also sends T1's four chain shapes, and its `TestProfile` checks the templates.
  - This is a fake, not Google. It shows the client mechanics and the logic of the trust store and the condition only. v1's `variantb/` used another profile (a key-derived ID, a five-year anchor with no EKU, a subject-only pin), and its 615-byte figure does not apply here.

**Rejected.**
- **ADR 0020's instance CA as the anchor.** Its CN is `FarCast Instance CA: ` and the instance (`fatline/internal/crypto/crypto.go:245`). It lives two years (`crypto.go:44`). It is minted only at `connect`, after `install` needs a cloud identity (`farsight/cli/internal/cli/connect.go:643`). Whoever holds `ca.key` could enrol Google identities with no human step. And presenting its leaves to Google would let Google compute `LeafToken`, which `fatline/identity/identity.go:111-121` keeps unknown to the cloud [read].
- **A per-instance federation CA.** Its holder enrols any device with no paste, which breaks Choices 5, and its theft compromises every device until each is re-pasted.
- **One self-signed certificate as both anchor and leaf** (the first prototype's shape). It is undocumented on Google and forbidden on AWS. M3a measures it as V3. *(2026-11-23, M3a walked: V3 was accepted in S1, and its token impersonated the reader's account (information).)*
- **One principal per device for both roles** (v1). It made every read hold writer-capable material.
- **A role ID that is its own key's fingerprint** (v1). It marked every FarCast anchor.

**Why the other answers lost.**
- **Two anchors in one provider** (v2's default). It kept one console form, one provider in `device ls` and one delete per device. It lost because the reader/writer split would then rest on Google enforcing the anchor's path length, which none of the Google pages read says it does (above).
- **Two leaves under one anchor** (the critique's first suggestion), with distinct subject CNs. It lost to two anchors: the one anchor key is opened to renew the reader leaf silently, and it can also mint the writer leaf, so the read path would still hold writer-capable material.
- **Anchor life.** The operator's five years and uniformity's two years lost to privacy's 390 days: a shorter-lived trusted key is the security pillar's side of the trade. The operator may lengthen it if M3a shows the rule binds leaves only (§9, question 6). *(2026-11-23, M3a walked: V6 and V7, anchors valid two and five years, were admitted and exchanged, and a 430-day leaf was refused (I4), so the rule binds leaves alone [inf]. The choice stays the operator's.)*
- **Leaf life.** Privacy's seven-day leaves lost to 90 days, which matches `leafValidity` (`crypto.go:45`). Within a role both keys share one custody (one 0600 directory, or one Secure Enclave), so a shorter leaf protects nothing the anchor key does not also expose [inf].
- **NotBefore.** Privacy's NotBefore truncated to the UTC day lost: a midnight NotBefore would be a profile marker of its own [inf], and the creation date is already in Admin Activity. One hour back is the reader certificate's precedent (`readerinit.go:209`) [read].

**Costs.**
- Four keys on a writer-capable device: two Secure Enclave pairs on the Mac at M5, four 0600 files elsewhere. V2, an anchor and its leaf on one key, would halve it if M3a shows Google accepts it. *(2026-11-23, M3a walked: V2 was accepted in S1, and its token impersonated the reader's account (information).)*
- Two providers per writer-capable device: two console forms, two providers in `device ls`, two deletes at revocation, and twice the providers per pool, whose limit is undocumented [doc: QUOTA].
- Each anchor key is a long-lived signing secret Google trusts. The writer anchor's power is the installer's project-wide roles, with actAs on the node account alone and revocable per device. It is confined to one instance only where the project holds one instance.
- A paste per device per instance each year (D4), covering all its providers.
- At M5 the Swift app must build the leaf's to-be-signed bytes with no ASN.1 library: a fixed template and Go conformance vectors, as ADR 0020's request is built (ADR 0020:159-164; ADR 0021 decision 7).

### D3. Mapping, condition, grants and names *(proposed)*

**Decision.**
- **Mapping:** `google.subject = assertion.issuer.dn.cn`. That is the role ID, fixed by the role's anchor and stable across leaf renewals. The page lists `issuer.dn.cn` among the mapping attributes, and its examples use the `assertion.` prefix [doc: X509, fetched again]. Nothing else is mapped: no `attribute.*` key, no `google.groups`.
- **Condition, per provider:** the issuer CN equals the subject CN, and equals that provider's one role ID, quoted:
  `assertion.issuer.dn.cn == '<the role ID>' && assertion.subject.dn.cn == '<the role ID>'`.
  A writer-capable device's reader provider names its reader ID, and its writer provider its writer ID. No condition names two IDs.
- **Principal:** the documented `principal://` form for a pool subject, ending in `/subject/` and the role ID [doc: X509]. Hex keeps `/`, `+` and `=` out of the path.
- **Grants:** the reader ID's principal gets `roles/iam.workloadIdentityUser` on the instance's reader SA only. The writer ID's principal gets it on the writer SA only. Neither gets a project or cluster role (D5).
- **Names:** the pool and the three SAs, the reader's, the writer's and the nodes', get random IDs drawn per instance, and each provider a random ID drawn per device and role, each from the alphabet its ID allows, starting with a letter, with no fixed prefix. None says `farcast`, names the instance or names the role, and none is derived from the instance name. No display name and no description is set. The IDs are kept as non-secret coordinates in the instance's record.
- **The privacy alternative,** a constant subject per role in place of the role ID, is measured in M3a as V8 and revisited at M3b's walk (below). *(2026-11-23, M3a walked: V8 was accepted in S1, and its token impersonated the reader's account (information).)*

**Why.**
- **Pool scope.** Principals are scoped to the pool, not the provider [inf, from the documented principal form]. The mapping takes the leaf's issuer's CN, so a leaf whose own CN names another ID still maps to its anchor's ID. But without the condition, a device's anchor key could make an intermediate CA named with another device's ID, issue a leaf under it, and act as that device, unless Google enforces the anchor's path length 0 [unverified]. That is the X.509 form of ADR 0023:161's caveat. The condition's issuer clause names only this provider's ID, so any other ID is refused here. Its subject clause refuses a leaf whose own CN names another ID. *(2026-11-23, M3a walked: N7 (i) was accepted, so Google builds chains through intermediates the client sends and does not enforce the anchor's path length 0 [inf]. N2 (b), an intermediate carrying another device's ID, was refused 400 unauthorized_client at both checks, so by the condition's issuer clause [inf].)*
- **Issuer equals subject.** It ties the principal to the leaf's issuer. The issuer CN is the leaf's immediate issuer's, and a holder of the provider's one anchor key can make an intermediate CA with any CN. In a provider per role that gains nothing: the condition refuses every CN but the provider's own ID, so such an intermediate can only name the role its maker already holds [ran: `perrole_test.go`, against fakes]. Whether Google enforces path length 0, or builds chains through intermediates the client sends, is recorded in M3a's N7 for information. *(2026-11-23, M3a walked: N7 (i) was accepted, so Google builds chains through intermediates the client sends and does not enforce path length 0 [inf]. N7 (ii) and (iii), a writer-ID intermediate under the reader anchor, were refused at both providers, so such an intermediate gained nothing.)*
- **The leaf's `sha256Fingerprint`** changes with every leaf [doc: X509], so it cannot be the subject.
- **One grant per role** keeps least privilege, and enforces in Google what D2's key custody enforces on the device: a reader key reaches only the reader SA.
- **Random object IDs.** The reader's name today is `farcast-reader-` and eight hex characters of the instance name's hash (`farsight/cli/internal/cli/reader.go:20-27`), with the display name `FarCast reader for` and the instance name (`readerinit.go:412-414`) [read]. That names the product and the instance to Google IAM, and the hash is guessable and repeats in every project. A deleted pool's or provider's ID stays reserved for about 30 days [doc: MGMT, PROV], so IDs derived from the instance name would also collide on a reinstall.

**V8, the alternative kept open.** A provider could map `google.subject` to a constant per role, drawn at random per instance, so that every device's reader shares one principal and every writer another.
- **What it gains.** The bindings name the two constants once, at install, so enrolling a device adds no `SetIamPolicy` entry with its IDs. Delegation entries of services that log delegation carry the constant. `fatline/identity/identity.go:111-121` names a stable per-device pseudonym in a provider-ingested log as a harm for FatLine's leaves [read].
- **What it does not gain.** Each provider's condition still names its role ID, and each provider's creation is in Admin Activity. The device count stays visible, one or two providers per device. So the gain is smaller than v1 stated.
- **What it costs.** It goes against Google's advice of a unique, unchanging subject [doc: X509]. Revocation could no longer cut one device's live federated token by removing its binding. Google's own logs could no longer tell devices apart.
- **The rule.** If M3b's walk finds Artifact Registry or Cloud Storage delegation entries carry the role ID, and V8 passed, the operator decides between the two (§9, question 12).

**Why the other answers lost.**
- **Default mapping.** Privacy's default mapping (`assertion.subject.dn.cn`) lost to the issuer's CN, because the leaf's subject is the device's choice and the issuer is chain-verified. The condition pins both, so the difference is only which field names the principal.
- **Pool-wide grant.** Uniformity's grant to the whole pool (`principalSet` and `*`) lost: it makes every enrolled device a writer, and any provider added to the pool, rogue or phished, a writer at once.
- **Fixed prefixes.** The operator's prefixes (a letter and a hyphen per object kind) lost to random IDs, because a fixed pattern across every FarCast pool is itself a mark [inf].
- **A two-clause condition over a device's two IDs** (v2's, with two anchors in one provider). It lost with that shape (D2).
- **Mapping from the subject CN with a role suffix** (the critique's two-leaves shape). It lost with that shape (D2).

**Costs.**
- The console route has one more field per provider, the condition, which the guide shows with a copy button. D4's read-back catches a mistake.
- Random IDs are unreadable in Google's console; the app labels them.
- The marks that exist today stay until a separate decision (§9, question 13):
  - cluster names `farcast-` and the instance (ADR 0023:256);
  - the repository prefix and its labels (`planck/internal/providers/gke/registry.go:44-48`, `:705`), which `registry.go:44-47` chose for recognisability on purpose;
  - the `farcast-` bucket prefix (`datasphere/internal/providers/gcs/gcs.go:28`), which the writer's storage condition names in the project's IAM policy (`docs/runbooks/phase-3-validation.md:60-65`);
  - the installer account's name (`docs/runbooks/phase-1-validation.md:67`);
  - the user agent and field manager `farcast` (`farsight/cli/internal/kube/client.go:13-18`) [read].

### D4. Enrolment, revocation and renewal *(human only: accepted 2026-11-22; the mechanics proposed)*

**Decision, accepted 2026-11-22 (ADR 0023 Choices 5).** Only a human enrols a device. Every device addition, renewal and revocation is a human's paste, and no FarCast identity can enrol devices. *Proposed reading, for the operator to confirm:* the renewal in those words is a device's anchor renewal (`device renew`), which is a human's paste. A leaf's renewal on the device, under an anchor a human pasted, is neither an enrolment nor such a renewal: it adds nothing Google trusts.

**How it holds (proposed).** No FarCast identity holds pool-admin rights or any right over a project's or a service account's IAM policy. The writer SA's role list is an allowlist, tested in the setup generator, that excludes `roles/iam.workloadIdentityPoolAdmin`, `roles/iam.serviceAccountAdmin`, `roles/resourcemanager.projectIamAdmin` and `roles/iam.serviceAccountTokenCreator`. **The actAs rule:** the writer's `roles/iam.serviceAccountUser` is granted on the node service account alone, never at the project level, and the allowlist test checks that. Phase 1 grants it project-wide today (`docs/runbooks/phase-1-validation.md:76-78`), and with `roles/container.admin` that lets the installer run a node as any service account in the project and take its token [inf], so any such account holding pool-admin rights would let it enrol a device with no paste.
- **The node account** is to be a dedicated per-instance one (ADR 0007 decision 3's recorded follow-up), because the default compute account keeps its automatic project Editor grant wherever that grant is not disabled (ADR 0007:34); whether Editor covers pool admin is [unverified]. The actAs rule is built so that it does not rest on that grant. M3a's P9 records the organization's effective `iam.automaticIamGrantsForDefaultServiceAccounts`, which decides whether a new project's default compute account gets it [inf]. The setup block makes the node account, with a random ID and no display name (D3). It holds `roles/container.defaultNodeServiceAccount` on the project, the minimum GKE documents for a node account [doc: GKESA], and the pull grant on the instance's repository, which the writer applies when it ensures the repository (ADR 0007 decision 3). It holds no other role. *(2026-11-23, M3a walked: P9 read `iam.automaticIamGrantsForDefaultServiceAccounts` enforced in the operator's own organization.)*
- **What planck must change for it.** `buildCluster` sets no node account today, so Autopilot nodes run as the default compute account (`planck/internal/providers/gke/client.go:160-174`), and `grantPull` binds the pull role to that account (`planck/internal/providers/gke/registry.go:63-68`, `:384-399`) [read]. M3b has `buildCluster` name the dedicated account through the cluster's autoprovisioning defaults (the vendored API's `AutoprovisioningNodePoolDefaults.ServiceAccount` [read]; that Autopilot takes it at creation is [inf]), has `grantPull` and the instance's metadata name it in place of the default account, and tests that the create request names it (§7). Until then the writer needs actAs on the default compute account, and with it whatever that account holds.
- **A second route, through GKE's Workload Identity.** `roles/container.admin` alone lets the writer make a cluster in the project, and a namespace and a Kubernetes ServiceAccount of any name in it. Such a ServiceAccount is a principal of the project's one pool, `$PROJECT.svc.id.goog`, named by namespace and name (`farsight/cli/internal/cli/grants.go:41`). So the writer can act as any such principal, and as any Google account that grants one `workloadIdentityUser`, with no actAs [inf]. The property therefore also needs that no principal of that pool holds pool-admin, project-IAM or service-account-IAM rights, directly or through an account it can impersonate. FarCast's own grants to such principals are the bucket grant and the push grant, and neither carries those rights (`storagedeploy.go:1340`; `buildgrant.go:43`) [read]; another workload in a shared project may hold more.
- **The two Workload Identity counts.** The setup block prints them, counts only, before it creates anything (D7). Each is expected to be 0. If either is not, the block asks y/N to go on, and a no stops it with nothing created. The counts are not pasted back, so `install` never sees them.
  - *Those rights* are the permissions `iam.workloadIdentityPoolProviders.create`, `iam.workloadIdentityPoolProviders.update`, `resourcemanager.projects.setIamPolicy` and `iam.serviceAccounts.setIamPolicy`. A role carries them if its permission list holds any of them, a basic or custom role included.
  - *A member of that pool* is written in either form: `principal://` or `principalSet://` on the pool `$PROJECT.svc.id.goog`, as `grants.go:39-41` writes it, or `serviceAccount:$PROJECT.svc.id.goog[…]`, the form GKE's Workload Identity pages use to link a Kubernetes ServiceAccount to an account [unverified: not among the pages read].
  - The first count is the bindings, on the project and on each of its accounts, of a role carrying those rights to a member of that pool. The second is the project's accounts that hold such a role and let such a member act as them: a binding, on the account or on the project, to such a member, of a role whose permission list holds `iam.serviceAccounts.getAccessToken` or `iam.serviceAccounts.actAs`, `roles/iam.workloadIdentityUser` and `roles/iam.serviceAccountTokenCreator` included.
  - Not counted: bindings inherited from a folder or the organization, which the block does not read, and chains through more than one account.
- Until M3b's build settles both routes, "by construction" is [inf]. It holds by construction only in a project that holds one instance and nothing else.

**The first device** is enrolled inside `install` (D7). It is writer-capable: two providers, two anchors, two leaves, two grants.

**Adding a device.**
1. On an enrolled device, `farcast device coordinates $INSTANCE` shows the instance's non-secret coordinates line (D7).
2. On the new device, `farcast device add $INSTANCE --role reader|writer` takes that line, typed or pasted. The role defaults to reader. The command makes the role keys and a first leaf per role, and shows the anchor PEMs, a Cloud Shell block with its digest, and the console steps.
3. The block, or the console steps, create the device's one or two providers, one per role, each with its anchor and D3's mapping and condition, and the device's one or two bindings.
4. When the human says the paste is done (Enter at the prompt, or the app's Done), the device exchanges and verifies. It retries with backoff within a bound, under M3a's settle rule (§6), because IAM changes take time to apply. Nothing is pasted back. *(2026-11-23, M3a walked: the settle rule's deltas (§6's note): provider changes applied by the first try, within 3 s of their marks; a new binding's first impersonation took up to 78 to 79 s from its mark (V1c's console grant), a lower bound on the settle from the change; a removed binding took effect within 62 s of its mark.)*
5. It ends by printing the device's provider IDs and their roles, one non-secret line. *Proposed:* the human may give that line to `farcast device known $INSTANCE` on each other enrolled device, so its `device ls` labels them, and a revocation run there can name them.

**Adding the writer role to a reader-only device.** On that device, `farcast device add $INSTANCE --role writer` makes the writer anchor and leaf, and prints one block. The block creates the writer's own provider (the writer anchor, D3's mapping, the writer's condition) and binds the writer ID's principal on the writer SA. That is one paste, and the reader's provider is not touched. Run on that device, `device rm $INSTANCE --role writer` does the reverse: it prints the lines that remove the writer binding and delete the writer's provider, and erases the writer keys.

**Verifying every enrolment, install's included.**
- For each role: an exchange at that role's provider, and `generateAccessToken` for that role's SA.
- **The read-back.** The reader reads the device's providers back, holding `roles/iam.workloadIdentityPoolViewer` [unverified role name]. The device refuses unless each trust store holds exactly that role's one anchor, and the mapping and the condition are exactly what it made. *(2026-11-23, M3a walked: `setup.sh` added this role, by this name, as the reader's account's one project grant, and T4's read-back on that account's token answered 200 with every field matching. So the name holds and the role suffices for the read-back; whether it is the smallest such role was not measured.)*
- **No decoy exchange.** v1 sent a decoy leaf at every enrolment. If M3a passes, its gating negatives show that Google enforces such a condition (§6), and the read-back checks each provider's condition text.
- A failure names the field to fix, and nothing billable has started.
- **The block's digest** is shown beside it, as ADR 0023:219 asks. Like any value a block prints, it binds nothing about a block that came from elsewhere. The binding checks are the read-back and `device ls`.

**Listing devices.** `farcast device ls $INSTANCE` reads the pool's providers through the reader. It shows each provider, names the role of those this machine made or was told of by `device known` (proposed), and marks every other provider as unknown, another enrolled device's included. `world` carries the same mark. On a machine told of every device, a rogue or phished provider in the instance's own pool is the one unknown. Otherwise the human must account for each unknown provider, and a rogue one shows only as one more. A binding of another principal on the writer SA does not show: the reader cannot read the SAs' IAM policies. Nor can `device ls` pair the providers of a device this machine was not told of, because nothing in Google links a device's two provider IDs.

**Revoking a device.** `farcast device rm $INSTANCE <provider>…`, where each `<provider>` is a provider's ID as `device ls` shows it, or FarSight, prints the lines that:
1. remove the device's principals' bindings on both SAs, whatever each principal's role, which stops new SA tokens once IAM applies it;
2. delete its providers, one or two, which stops new exchanges.

Each line skips an object that is absent (D7's *Pending installs*). The human runs them. A principal ends in its role ID, not its provider's ID, so for a provider this machine did not make `device rm` first reads that provider's condition through the reader, as the read-back does, and takes the role ID from it. The console route works from any browser, so a lost device is revoked from anywhere: on each operator SA's permissions page, remove the device's principals' grants; then the pool, each provider, Delete. `device rm` erases this machine's keys only for a role whose provider it names and this machine made. From another machine, a lost writer-capable device's revocation must name both its providers. That machine knows them only if it was told of them (`device known`); otherwise nothing there says which unknown providers are the lost device's.

What is left after a revocation [inf; M3a measures it]:
- an SA token already issued, for up to one hour;
- if Google lets a federated token issued before the deletion still impersonate, up to about two hours. Removing the bindings first narrows it. *(2026-11-23, M3a walked: P7 measured it. Removing a binding stopped an issued federated token's impersonation within 62 s. After a provider's disable or deletion, new exchanges were refused within 2 s, but tokens already issued impersonated until they expired, about an hour later. Removing the bindings first holds.)*

FarSight warns before revoking an instance's last writer-capable device. The instance keeps running and billing, and an Owner can always enrol again.

**Renewing.**
- **The reader leaf** renews silently at half its life, with a new leaf key, inside any command, with no network and no human.
- **The writer leaf** renews the same way, but only inside a consented command or `device renew` (D2's custody rules).
- **The anchors.** From 45 days before an anchor's end, every command and FarSight warn. `farcast device renew $INSTANCE` makes a new anchor key and a new anchor for each of the device's roles, each with the **same role ID as its CN**, and a block, or console steps, that **replace each provider's trust store with its new anchor alone**. That is one paste for all the device's providers. The principals, mapping, conditions and grants do not change, and the old anchor keys stop once the trust-store update applies, within the settle bound M3a measures (P6). The device then exchanges, under the settle rule. If M3a shows a trust store cannot be replaced (P6), renewal becomes new providers and new bindings plus the old providers' revocation, in one block. *(2026-11-23, M3a walked: P6 replaced the trust store by the paste and in the console's edit form, and both committed.)*
- **A missed renewal** stops that device. The instance keeps running and TechnoCore keeps enforcing the cost limit in the cluster. The same block, pasted late, recovers it.

**Releasing.** `release` prints one block that deletes the providers, the pool, the three SAs and their bindings, bindings first and the node SA after the cluster, each line skipping an object that is absent. That extends the reader lines it prints today (ADR 0023:238's 2026-11-14 note).

**Why the other answers lost.**
- **An enrolled device that may add providers** (ADR 0023 Choices 5's other answer). The operator chose human only on 2026-11-22. A device that can add providers holds pool-admin rights, so one stolen device could enrol keys that outlive its own revocation (ADR 0023:229).
- **Renewal as add-plus-revoke.** Privacy's and uniformity's renewal (a new key, a new ID, new bindings, then the old revoked) lost to replacing the anchors in place. It is fewer console steps, and the privacy gain is nil: Google sees the old provider go and the new one come in the same pool on the same day [inf].
- **Keeping old and new anchors.** The operator's `[old, new]` trust store lost to the new anchor alone, so the old key stops once the update applies. With one anchor per provider it would fit the page's limit of three [doc: X509]; v2's second reason, four anchors in one trust store, is gone with v2's shape.
- **Writer by default.** The operator's "every added device gets both roles" lost to privacy's reader by default.
- **No bindings at enrolment.** Uniformity's binding-free enrolment came from its pool-wide grant (D3).
- **Polling STS** every 5 seconds for 15 minutes after the paste (v1) lost to an exchange when the human says done. Polling leaves the same run of refused exchanges in STS's Data Access log at every enrolment, where that log is on.

**Costs.**
- Every add, role change, renewal and revocation needs a human with IAM admin rights on the project. That is the price of human-only enrolment.
- Revocation is not instant.
- The reader's pool-viewer role exposes the pool's configuration, which is public material, to reader tokens.
- A lost Mac's Secure Enclave keys cannot be backed up (ADR 0021:358), so recovery is a new enrolment.

### D5. The token path: impersonation *(proposed; the installer-minted reads are decided per read in M3b's build)*

**Decision.**
1. For each role it needs, the device runs the mTLS exchange with that role's leaf, at that role's provider's audience, with scope `cloud-platform`, and keeps the federated token in memory, one per role per instance.
2. It calls `generateAccessToken` on that role's SA only, with `[cloud-platform, userinfo.email]` in `kube.TokenScopes`'s order (`farsight/cli/internal/kube/client.go:34-46`) and a lifetime of 3600 seconds.
3. The SA token goes only to the endpoint's host, as today (`TestAuthorizationOnlyToTheEndpointHost`, `kube/transport_test.go:179`).

The rules that keep:
- Read commands, and every plan under `--plan` and `--confirm`, exchange only the reader leaf and impersonate only the reader. A command that writes exchanges the writer leaf only after its consent, and on the Mac only through the broker for `--confirm` (ADR 0023:116, :195). `TestWorldNeverOpensAWriterCredential` (`nosecrets_test.go:59`) gains "never opens a writer key".
- RBAC subjects stay the SAs' emails (`farsight/cli/internal/cli/readerrbac.go:188-191`). SA tokens stay in FarCast's `tokenCache`, with its re-mint after a 401 (`farsight/cli/internal/kube/token.go:153-199`) [read].
- **The writer SA** holds phase 1's installer roles: `roles/container.admin`, `roles/iam.serviceAccountUser` and `roles/artifactregistry.admin` (`docs/runbooks/phase-1-validation.md:72-83`), with `roles/iam.serviceAccountUser` on the node service account alone, not project-wide (D4's actAs rule). It also holds phase 3's `roles/storage.admin` under its condition, which names `farcast-` buckets (`docs/runbooks/phase-3-validation.md:60-65`). The setup block gives that condition a title drawn at random per instance and no description (D7).
- **The reader SA** holds `roles/container.clusterViewer` and the pool viewer of D4, and from M3b the resource-scoped read grants below.

**The reads that mint the installer's token today.** None of them is covered by the reader's roles [read]:
- the registry image lookups in plans: `planRegistry` mints a registry token from the installer's key (`farsight/cli/internal/cli/fatline.go:608-625`);
- `projects.get` and the repository's `getIamPolicy` in the deploy plans of `build` and `run` (`buildgrant.go:155-180`);
- `projects.get`, the bucket's `GET` (its labels) and its `getIamPolicy` in `storage deploy`'s plan (`storagedeploy.go:1140-1202`; ADR 0023:258-259);
- `storage ls`, `storage usage` and `storage cp`'s downloads, which open storage with the installer's key (`farsight/cli/internal/storage/storage.go:82-100`; ADR 0023:118);
- `secret ls`. It reads the bucket's metadata (`provider.Validate`, its labels; `datasphere/internal/providers/gcs/bucket.go:41-66`), lists the objects under each application's secrets prefix (`farsight/cli/internal/cli/secret.go:354-418`; `datasphere/store.go:179-199`), and fetches an object's header only where a listing entry's name mirror is missing or does not open (`datasphere/store.go:304-321`). It decrypts names on the device and never reads a value [read].

**The proposed default, decided per read in M3b's build:**
- From M3b these reads run as the reader.
- The reader gains read-only grants scoped to the instance's own repository and bucket, never project-wide and never the writer's. On the repository: reading images and its IAM policy. On the bucket: reading its metadata and its IAM policy, listing its objects and reading them. Which predefined or custom role is the smallest that covers each is [unverified], and is chosen in M3b's build.
- The repository is created by `install` and re-ensured by every deploying command (`install.go:204-269`; `fatline.go:496-520`), and the bucket by `storage deploy`. Neither exists when the setup block runs, and `install` has no `--plan` [read]. So the writer applies the reader's grant on the repository in `connect`'s plan, and on the bucket in `storage deploy`'s, each as a plan fact never covered by `--yes` (ADR 0023 decision 8) [inf]. The first such plan runs before its grant exists: its own lookups are stated in the plan as not yet readable by the reader, and made after the grant, under the same consent. The exact shape is M3b's build's to decide.
- `projects.get` goes from plans: the record holds the project's number, from the coordinates line or, where the line was not asked for, from `install`'s one read after verification (D7), so plans read it from the record.
- What the reader then reaches: ciphertext under opaque names, image layers, and the two resources' policies. A leaked reader token could copy the ciphertext out, and pull the instance's images, which are not encrypted: FarCast's own components and the operator's application images, in plaintext. The keyring stays on the device, so it cannot decrypt the storage ciphertext. That is more than today's reader reaches, and it is the operator's call (§9, question 9). *(2026-11-26, M3b.1: answered with this default before M3b.1; built at M3b.11.)*

**Why.**
- GKE does not log the delegating identity, so cluster entries name only the SA [doc: AUD]. Direct `principal://` grants would put the role ID into the always-on Admin Activity entries of GKE writes [inf].
- The reader/writer split is enforced by Google (one provider and one grant per role) and by the device (one key pair per role).
- GKE's authentication page describes federation as credentials that impersonate SAs and requires `userinfo.email` [doc: GKEAUTH]. GKE's RBAC page lists no pool principal among its subject kinds [doc: GKERBAC]. STS's documented scope is `cloud-platform` [doc: X509].
- A leaked reader federated token reaches only the reader SA, and a leaked writer federated token only the writer SA [inf].

**Unproven until a cluster exists.**
- That GKE's DNS endpoint accepts an impersonated token carrying the scope pair (ADR 0023:121). An impersonated token is an ordinary SA access token [inf]. *(2026-11-24, ADR 0023's M2 walked: settled by W-FED in an organization project. The impersonated reader token read `GET /version` 200, the namespace list 200 and a SelfSubjectReview 201 (shape S1). In the first run `GET /version` was first tried 9 s after the viewer grant's mark and accepted 88 s after it.)*
- That Kubernetes then sees the SA's email as the username [inf]. *(2026-11-24, ADR 0023's M2 walked: shown by W-FED: the review's username was the reader SA's email ("email matches: yes").)*
- What Artifact Registry and Cloud Storage writes record under `serviceAccountDelegationInfo`. *(2026-11-24, ADR 0023's M2 walked: not settled: W-FED made no Artifact Registry or Cloud Storage write, so this stays M3b's walk's.)*

M2's walk can settle the first two in its optional W-FED step (D9), if M3a passed in the organization project and W-FED is approved at the walk's G0a. Otherwise M3b's walk does. M3b's walk settles the third. *(2026-11-24, ADR 0023's M2 walked: W-FED settled the first two on 2026-11-24.)*

**Why the other answers lost.**
- All three designs chose impersonation. Google's own recommendation, direct grants, lost for the privacy reason above.
- **The writer for the installer-minted reads** (the critique's other option) lost: plans would then hold a writer token, which breaks ADR 0023:116's broker rule, and every `storage ls` would open the writer's keys.

**Costs.**
- Two operator SAs per instance, beside its node SA (D4), and two calls per fresh SA token.
- The writer's roles are project-wide, so one project per instance stays the full separation (ADR 0023:113, AGENTS.md:48).
- The writer's federated token can impersonate the writer, so on the Mac the broker keeps it inside the Swift app and hands the helper SA tokens only.
- The reader reaches the instance's ciphertext, and its images, which are not encrypted.

### D6. The code: hand-rolled on the standard library *(proposed)*

**Decision.** FarCast's own code, on `crypto/x509`, `crypto/tls`, `net/http` and `encoding/json`. No vendored external-account code is used. `vendor/` does not change, `VENDORED_MODULES` stays 31 (`check.sh:66`), and `exec-allowlist.txt` gains no line. *(2026-11-23: built in part in M3a's `devicekey` and `kube/federated.go`, offline and wired into no command. Where the build departs from the list below is in §11: among other things, the exchange's TLS floor is 1.3, and kubetest's fakes came with M3a.)*

- **`farsight/cli/internal/devicekey`** (new, built in M3a, wired into no command until M3b):
  - per instance and per role, the anchor key and the leaf key as PKCS#8 files at 0600, with their certificates, in a new `identity/` directory at 0700 in the instance's config directory; the role IDs and the provider IDs in the instance's record;
  - D2's two templates, with the explicit authority key identifier, the random role IDs, and leaf and anchor renewal;
  - one opening function per role and purpose (read, consented write, renewal, enrolment), so that D2's custody rules are tested in one place;
  - every key behind `crypto.Signer`, so M5's broker signer and a Secure Enclave signer fit later;
  - it needs no `fatline/identity` helper, because no ID is a key fingerprint.
- **`farsight/cli/internal/kube/federated.go`** (new, built in M3a):
  - the exchange and `generateAccessToken`, their URLs Go constants with the values the X.509 page and the IAM Credentials reference give, never read from a file or the environment;
  - an mTLS token transport: `Proxy` nil, the system roots, TLS 1.2 or later, no redirects;
  - `GetClientCertificate` returns the role's leaf with its `crypto.Signer`. The client certificate is presented only to STS's host, and to IAM Credentials' mTLS host only if M3a's I1 shows that endpoint is needed; *(2026-11-23, M3a walked: it is not needed: I1's mTLS endpoint answered 200 with no client certificate, and T2's impersonations at IAM Credentials were accepted.)*
  - no `Authorization` header to STS, and the bearer only to IAM Credentials' host;
  - no `x-goog-api-client` header, and the user agent of `kube.UserAgent`;
  - response bodies size-limited and never put into an error. Errors are typed by step, status and OAuth error code. That goes beyond `tokenError` (`token.go:125-146`), which names a refusal by its status alone and never carries the body.
- **M3a's probe:** `farsight/cli/internal/cli/walkm3a_test.go`, `//go:build walk`. It calls the product code above, so what M3a walks is what M3b ships. Three pieces are probe-only:
  - V5's ES256 JWT signer;
  - a token-info check, which POSTs the SA token in the request body, never in a query string, to Google's token-info endpoint, with a firewall rule of its own;
  - a W-FED mode, which M2's walk uses (D9): three reads at a cluster's DNS endpoint with the impersonated reader token (the API server's version, the namespace list and a SelfSubjectReview), and the same reads once more with a direct federated token. *(2026-11-24, ADR 0023's M2 walked: the mode accepted a read only at 200, so the SelfSubjectReview, a create the API answers 201 Created, was retried to its 20-minute bound and "email matches" never printed. The walk ran the reads again with a probe patched by `go test -overlay`, with the operator's approval, to accept 200 or 201 and print the status; the same two lines are now in `walkm3a_test.go`.)*
  - It is built once with `go test -c` to a fixed path, so the firewall's per-binary rules hold.
  - It prints only status, OAuth error code, `issued_token_type`, lifetimes and settle times as deltas, the scope set, counts, and "email matches: yes or no". It never prints a token, key, email, project number or ID (`walkprobe_test.go:1-110`'s rule).
- **M3b's wiring** (§7):
  - `kube.Credential` (`kube/credential.go:13-20`) gains a federated variant: coordinates, the role's leaf and its signer. `newClient` mints from it beside `twoLegged` (`token.go:48-123`), and `pair` and `credentialOrigin` (`token.go:220-282`) learn its origin. `kubetest` gains a loopback STS that requires and verifies a client certificate, and an IAM Credentials fake.
  - `planck.Config` (`planck/types.go:98`) and `datasphere.Config` (`datasphere/types.go:162`) gain a token-provider field for the CLI, given the reader's or the writer's provider as D5 says. It goes through the vendored `auth.NewCredentials` (`vendor/cloud.google.com/go/auth/auth.go:217-243`), with `option.WithAuthCredentials` (`vendor/google.golang.org/api/option/option.go:504`) for the cluster client (`planck/internal/providers/gke/client.go:87-100`), and `httptransport.Options{Credentials}` for Artifact Registry (`registry.go:568-600`) and Cloud Storage (`datasphere/internal/providers/gcs/client.go:96-119`).
  - The SA-JSON loaders and their service-account-only guard (`registry.go:588-600`) stay, for fallbacks 2 and 3.
  - `DetectDefault` stays only in the in-cluster `datasphered`, which opens storage with no credential unless given `--credentials` (`datasphere/cmd/datasphere/main.go:315-324`) and so falls back to it (`datasphere/internal/providers/gcs/client.go:113-119`).
  - `GOOGLE_API_CERTIFICATE_CONFIG` joins the variables `hardenEnvironment` unsets (`farsight/cli/internal/cli/cli.go:66-78`) and the planck harness unsets (`planck/cmd/planck/main.go:47-57`). This is defence in depth [inf]: `GOOGLE_API_USE_CLIENT_CERTIFICATE=false` already keeps the library's certificate-based access off.

**Why.**
- **The vendored X.509 source cannot be used.** It reads the certificate and key paths from a config file (`vendor/cloud.google.com/go/auth/credentials/internal/externalaccount/x509_provider.go:58-70`). It loads an unencrypted PEM key on every handshake, so it can never take a `crypto.Signer` or a Secure Enclave key (`x509_provider.go:200-219`; `vendor/cloud.google.com/go/auth/internal/transport/cert/workload_cert.go:94-102`). It clones the default transport, with its environment proxy. And it reads its URLs from a file, against ADR 0023:168 [read].
- **The public `credentials/externalaccount` package** is not vendored; it would keep the module count at 31 [inf]. But the vendored internal code it wraps sends `x-goog-api-client` with the Go version (`vendor/cloud.google.com/go/auth/credentials/internal/externalaccount/externalaccount.go:303`, `:424-431`). Its layered caches defeat `tokenCache`'s re-mint. And its errors carry response bodies (`vendor/cloud.google.com/go/auth/credentials/internal/stsexchange/sts_exchange.go:106-108`, `vendor/cloud.google.com/go/auth/credentials/internal/impersonate/impersonate.go:134-136`) [read].
- **Size** [ran]: `proto/wif.go`, a prototype not kept, is 224 non-blank lines, and `go test -race` passes offline against a loopback server that requires a client certificate. Product code is about 350 lines plus about 600 of tests, with the second role [inf].

**Why the other answers lost.**
- **A cross-provider interface.** Uniformity's `cloudid` package lost, because no AWS or Azure adapter is scheduled. The sameness is a product rule, recorded in ADR 0024, and an interface is written when a second adapter starts.
- **A sub-package.** Privacy's `kube/wif` sub-package lost to the operator's split, which keeps the keys apart from the wire code: the keys also serve AWS, Azure and M5's signer later.
- **A neutral user agent.** Privacy's neutral user agent for the identity path lost, for three reasons. Go's default would mark Go instead. The identity calls appear only in Data Access logs, which are off by default, while the same project's cluster writes already carry `farcast` in the always-on log. And two rules would double the work of the marks decision (§9, question 14). *(2026-11-24, ADR 0023's M2 walked: on GKE 1.36.4 the always-on log carried farcast's own cluster writes only on ConfigMaps and Secrets, 21 entries, with the agent "farcast,gzip(gfe)" (Google's front end appends the suffix [inf]); its other applies, sent as YAML, left no entry (W5).)*

**Costs.**
- It departs from ADR 0007 decision 2's "no hand-rolled JWT, signing, or token refresh" (`docs/adr/0007-instance-owned-image-registry.md:32`) and from ADR 0023:168's "the exchange and refresh stay in the vendored library". The departure is smaller than the JWT route's: the standard library signs, there is no JWT, and the refresh has been FarCast's own `tokenCache` since M2.1.
- FarCast must track changes to Google's endpoints itself.

### D7. The procedure on every provider *(accepted: the procedure and the fallback rule; the rest proposed)*

**Decision.** The same four steps everywhere:
1. the installer shows the certificates and a guide;
2. the human creates the identity in the provider's console, or by one paste of public material into its cloud shell, pasting those certificates in;
3. the human pastes back one non-secret line, where the installer cannot learn it;
4. `farcast` verifies, by minting and making one harmless read.

The app shows these on three surfaces: the provider's console, the guide, and the paste-and-drop surface, which shows the certificates with Copy buttons and takes the line back. The app never scripts the console page.
- **The console surface may not be an embedded view.** Google blocks Google Account sign-in from embedded browser frameworks [doc: WV-2020, WV-HELP], and its OAuth policy names WKWebView among the web views that do not comply [doc: WV-2021]. Whether the Cloud console's own sign-in fails inside a macOS WKWebView is [unverified]. If it does, the console surface is the system browser beside the app, with the guide and the paste surface in the app. A no-cost check settles it before the GUI install flow is built. It is not an M3a item (§9, question 10).

**Google, now (the CLI).**
1. `farcast install --name $INSTANCE --project $PROJECT --region … --cost-limit …`, with no `--credentials`. `install` takes the instance as `--name` and refuses a positional argument (`install.go:65-79`); every later command takes it as its first argument, as `reader init <instance>` does, and so do the `device` commands. `install` first refuses a name already recorded, a local read, before it makes any key. That is `install.go:114-121`'s refusal, moved ahead of `planck.Open` and `Validate` (`:105-112`), which then need the credential the paste makes. It refuses a name with a pending install too, naming `--coordinates` to resume it and `--abandon`. Then it makes the device's four keys in a pending directory at 0700, outside any instance record, and shows the anchor PEMs, the setup block with its SHA-256, and the console steps. It makes no cloud call yet. For scripts, `--setup-only` prints and exits, and `--coordinates` takes the line back later.
2. **The setup block** holds only public material. It names neither FarCast nor the instance, with one exception: the writer's storage condition names `farcast-` buckets (D5), an existing mark (D11). The block sets that condition's title to a value drawn at random per instance, from the alphabet a condition title allows, as D3 does for object IDs, so no fixed word repeats in every FarCast project's IAM policy; it gives it no description.
   - **Its shape follows readerinit's** (`readerinit.go:378-432`): `sh -s` reading a here-document, `set -eu`, single-quoted values checked to a narrow alphabet, and a bounded retry for IAM calls, like `readerRetry`. It changes two things. Its here-document tag is neutral, where readerinit's names FarCast. It asks y/N to confirm the project it names, reading the answer from `</dev/tty`, because the here-document is the script's standard input. Each provider's trust store is written from a here-document of its own, also with a neutral tag, into a `mktemp` file that the block removes. The file is the YAML trust-store document Google's X509 provider reads, `trustStore` with one `trustAnchors` entry whose `pemCertificate` is that role's anchor, and no `intermediateCas`. The PEM is in Google's one-line form, each newline written `\n` inside a double-quoted scalar [doc: X509], because a plain multi-line PEM in a double-quoted scalar is folded, its newlines read as spaces [inf]. A generator test parses the file as that YAML, finds exactly one anchor, and decodes its `pemCertificate` to the anchor's DER, byte for byte. The material is public, and everything in it also goes into the project's IAM objects: the project's ID, the role IDs and the `farcast-` condition. So the block does not try to keep itself out of Cloud Shell's history, which persists in the operator's Cloud Shell home [inf].
   - **It does, in order:**
     - enables the IAM, IAM Credentials, STS and Resource Manager APIs, and the APIs `install` needs (phase 1's step 1);
     - prints the two Workload Identity counts of D4's *How it holds*, counts only, and if either is not 0 asks y/N to go on, from `</dev/tty`, so a no stops it before it creates anything;
     - creates the pool if absent; then the device's reader provider, its trust store holding the reader anchor alone, with D3's mapping and the reader's condition; then the device's writer provider, its trust store holding the writer anchor alone, with the mapping and the writer's condition;
     - creates the writer, reader and node SAs, with no display name, and grants their roles (D5): the storage grant under phase 3's condition with the random title, the writer's `roles/iam.serviceAccountUser` on the node SA alone (D4's actAs rule), and the node SA's `roles/container.defaultNodeServiceAccount` (D4);
     - binds `roles/iam.workloadIdentityUser` on the reader SA to the reader ID's principal, and on the writer SA to the writer ID's principal;
     - prints one line: the coordinates. In words, those are the project's ID and number, the pool's ID, the device's provider IDs, one per role, and the three SAs' IDs.
   - Folding the once-per-project part into this once-per-instance block makes it idempotent. With one project per instance, the recommended layout, that is one paste per instance.
   - A skeleton, with every command elided:

     ```sh
     sh -s <<'END_OF_SETUP'
     set -eu
     PROJECT='$PROJECT'
     printf 'Set up project %s? [y/N] ' "$PROJECT" >/dev/tty
     read -r ANSWER </dev/tty
     [ "$ANSWER" = y ] || { echo 'Nothing was changed.' >&2; exit 1; }
     # … enable the APIs; print the two Workload Identity counts, and ask y/N if either is not 0; create the pool if absent …
     TRUST="$(mktemp)"
     cat > "$TRUST" <<'END_OF_ANCHOR'
     … the YAML trust store: one trustAnchors entry, its pemCertificate the reader anchor's PEM, and no intermediateCas …
     END_OF_ANCHOR
     # … create the reader's X509 provider from "$TRUST", with the mapping and the reader's condition …
     cat > "$TRUST" <<'END_OF_ANCHOR'
     … the same YAML, its one pemCertificate the writer anchor's PEM …
     END_OF_ANCHOR
     # … create the writer's X509 provider from "$TRUST", with the mapping and the writer's condition …
     rm -f "$TRUST"
     # … create the three SAs; grant their roles; bind each role ID's principal …
     # … print the coordinates line …
     END_OF_SETUP
     ```

3. **The console alternative,** about 40 actions for a writer-capable device [inf]:
   - enable the APIs;
   - Workload Identity Federation, Create pool; then one provider form per role, type X509: paste that role's anchor into Trust anchors, and set the mapping and that role's condition from copy buttons. A reader-only device fills one provider form, a writer-capable device two;
   - create the three SAs and grant their roles, the writer's `roles/iam.serviceAccountUser` on the node SA alone;
   - on each operator SA's permissions page, grant `workloadIdentityUser` to that role's principal (a copy button);
   - copy the project's number back.

   This route makes no Workload Identity check (D4); the guide says so.
4. **The line back,** at the prompt, through `--coordinates`, or on the app's drop surface. STS's audience needs the project's number, and the installer holds no credential that could read it. If M3a shows the audience accepts the project's ID (I5), the line becomes optional whenever `--project` was given; the installer then asks only for "done". Plans still need the number, for the uid principals (`buildgrant.go:167-178`; `storagedeploy.go:1152`), so `install` then reads it once, as the writer, after verification and under its own consent, and stores it in the record (D5) [inf]. *(2026-11-23, M3a walked: I5 refused the project's ID in the audience, 400 invalid_target, still refused at the settle bound, so the line stays needed.)*
5. **Verification** (D4). Then `install` goes on as today: `planck.Open` and `Validate` (`install.go:105-112`), the floor check and the consent. It creates the instance's record and moves the keys and the coordinates into it, before `CreateCluster`, as `install.go:149-175` records intent before provisioning today. Then the cluster.
6. After `connect`, `reader grant` writes the reader's RBAC as today, and `reader init` and `reader record` become fallback 2.

**Pending installs.** Until `install` creates the instance's record, after verification, the keys live in the pending directory, outside any record.
- `farcast instances` lists each pending install with its state (keys made; setup shown; coordinates received) and its age. *(2026-11-26, M3b.2: and a fourth, `verified`, which the hand-off requires of an entry holding keys (§13, departure 1).)*
- Every command warns about a pending install older than 7 days.
- `farcast install --name $INSTANCE --abandon` prints the teardown block for what the setup created (the bindings first, then the providers, the pool if it holds no other provider, and the three SAs), and erases the pending keys. It acts on a pending install's entry alone, so a pending install can always be abandoned, and never on a finished record; that is `release`'s. The device cannot know how far the setup ran, so each line of the block skips an object that is absent, as `readerinit.go:412`'s `describe ||` does in reverse; `release`'s and `device rm`'s blocks do the same. For the pool and a provider, absent means not found, or found in the state `DELETED`, which Google keeps for about 30 days after a delete [doc: PROV]; a provider's line is also skipped once the pool is absent. Whether a describe returns a soft-deleted object is [unverified].
- Nothing erases pending keys by age alone.

**The guided default** for a non-technical person is the Cloud Shell block, with the console form beside it (§9, question 7). The guide says to paste only what your own installer shows. `device ls` shows a provider in the instance's pool that this machine does not know, and the read-back a condition the device did not make. Neither shows a binding of another principal on an SA (D4).

**Google's fallbacks, per organization.** The rule is accepted: a provider-made secret only where the certificate route is closed, named and consented. The order below is proposed. Each applies only where the one before is closed. Each is named in a plan fact, `identity_route`, and shown in the `instances` and `world` documents.
1. **OIDC with an uploaded single-key JWKS of a device key** ("paste the public key"). It applies only if M3a recorded V5 passing and the organization admits it. *(2026-11-23, M3a walked: M3a recorded V5 passing, in a project in the operator's own organization, which admitted its provider, so both conditions are met there.)*
   - It is a paste only in Cloud Shell, where the block writes the JWKS from a here-document. The console form takes the JWKS only as a file upload [doc: OIDC], so the app offers the file on its drop surface, reversed.
   - As on the X.509 route, one provider per role, each with a single-key JWKS: a claim is not bound to a key, so either key in a shared JWKS could sign the other role's subject (ADR 0023:161).
   - An organization that blocks X.509 by a custom constraint on trust anchors [doc: CUS] may still admit it.
2. **SA-key upload of a device-made RSA-2048 certificate:** today's reader mechanism (`readerinit.go:395-432`), for the reader, and the same way for the writer, where upload is allowed. It is still a certificate paste, and nothing secret leaves the device. The RSA key cannot live in the Secure Enclave, which holds P-256 keys only. On the Mac it is a 0600 PKCS#8 file in the instance's config directory, as `reader.key` is today, in the CLI and in the app at M5 alike; the broker cannot protect it [inf].
3. **A Google-made key download:** today's `--credentials` (`docs/runbooks/phase-1-validation.md:85-86`), where key creation is allowed. It is a provider-made secret. It needs its own flag, and a plan fact or a terminal question stating that Google made it and that it does not expire. `--yes` never selects it.
4. **None open:** `farcast` names the policy that closed each route. It never asks the operator to relax a security default.

If M3a refuses every X.509 shape, not by a policy, and V5 passes, fallback 1 becomes Google's route, by a dated note in ADR 0024.

M2's walk under [B] uses a Google-made installer key before any of this is built. That is not fallback 3: it is an exception to ADR 0024 that the operator approves at the walk's G0a, time-boxed and deleted at teardown (D9). *(2026-11-24, ADR 0023's M2 walked: G0a chose the installer's existing key; it was deleted in Google and on the Mac at W6.2, and the installer's user-managed keys then counted 0.)*

**AWS,** when its adapter starts (not scheduled).
- **The artifact** is the same pair per role, each anchor pasted as a Roles Anywhere trust anchor, "External certificate bundle" [doc: RA-START]: one or two per device per instance, out of a quota of 50 per account, adjustable [doc: RA-QUOTA].
- **Per instance:** a writer role and a reader role trusting the Roles Anywhere service, and one profile. Each role's trust names, per device, `ArnEquals aws:SourceArn` equal to that role's anchor and `StringEquals aws:PrincipalTag/x509Subject/CN` equal to that role ID [doc: RA-TRUST]. A reader anchor is trusted by the reader role only, and a writer anchor by the writer role only.
- **The exchange** is `CreateSession`, signed `AWS4-X509-ECDSA-SHA256` with the leaf key, which is a data signature, so the Secure Enclave fits with no TLS identity. Then HMAC SigV4 and the EKS token, all hand-rolled [doc: RA-SIGN].
- **The departures:**
  - an enrolment edits one or two trust policies;
  - P-256 acceptance is [unverified], and is an AWS probe;
  - the end-entity expiry notices are turned off per anchor, because leaves renew themselves [inf].
- **Accounts from "Sign up for AWS (new)"** have Roles Anywhere closed by AWS-managed SCPs [doc: AWS-SCP] until "Activate advanced AWS features", which is irreversible and removes the account's spend limit [doc: AWS-ADV]. FarCast never asks for that activation, under the cost pillar. There, the fallback is an IAM user access key, a provider-made secret, consented like Google's fallback 3.
- **No CRL URL,** because it would be a central dependency. Revocation deletes the anchor.

**Azure,** when its adapter starts (not scheduled).
- **The artifact** is a self-signed RSA-2048 certificate per role, made by a software key (0600, never the Secure Enclave), because Entra takes RSA only and offers no CA-level trust [doc: ENTRA-RSA, ENTRA-CERT].
- **Setup:** each is uploaded under "Certificates & secrets" to its role's app registration, reader or writer, with neutral names. The portal takes a file, so the app offers the file on its drop surface, reversed; Azure Cloud Shell is the alternative [unverified syntax]. Role assignments are made at the resource group.
- **The exchange** is a PS256 client assertion carrying `x5t#S256` [doc: ENTRA-CERT], hand-rolled.
- **The departures:**
  - no P-256 and no Secure Enclave;
  - every new certificate is a human paste, up to the tenant's maximum lifetime [doc: ENTRA-POL];
  - federated identity credentials are rejected, because they need a public HTTPS issuer, which is a central dependency, and take RS256 only [doc: ENTRA-FIC].
- **Fallback:** a client secret, where tenant policy blocks certificates, consented like Google's fallback 3.

**ADR 0023 Choices 1 (b),** an OAuth client the operator registers, keeps a refresh token at rest, which is a provider-made secret. It is proposed as not planned (§9, question 17).

**Why the other answers lost.**
- **Fallback order.** Privacy's order (SA-key upload before JWKS, and JWKS only as a route-level outcome) lost to the operator's: JWKS is device-made public material, so it ranks above the SA-key upload [inf].
- **Sameness.** Uniformity's "keep the line back even where the project's ID works" lost to the operator's procedure: a line that need not be pasted is not asked for.
- **The console split.** Uniformity's split (Cloud Shell for the instance, the console form for each further device) is offered as question 7's alternative.

**Costs.**
- `install` gains a pause for the human, and a line back.
- The setup still runs in an Owner-level shell, or across many console pages, two provider forms for a writer-capable device.
- AWS and Azure each break one part of the sameness. Some AWS accounts and some Azure tenants land on a provider-made secret.

### D8. M3a, redefined *(accepted 2026-11-22: its place before M2's billable walk, and its project's organization; the project and its content proposed)*

**Decision.** M3a is the X.509 probe of §6. It creates free IAM objects only, makes no cluster, and runs before M2's billable walk. The operator decided on 2026-11-22 that it runs in a project in the operator's own organization. *Proposed:* one fresh scratch project there, approved with M3a (§9, question 1). The run in a project with no organization is deferred until most of FarSight is ready. Its probe calls D6's product code. M3a also lands `devicekey` and `kube/federated.go`, tested offline and wired into no command, and the W-FED mode M2's walk can use (D9).

**Why the other answers lost.** The three variant lists were merged. v2 added the two-role shape and the negatives the critique asked for, and v3 makes V1 the per-role pair. Each kept variant answers a question one of the decisions depends on, and the gating set is the smallest that proves the route. v2's second project, one with no organization, waits for the operator's later run.

### D9. The order *(accepted 2026-11-22: branch S, under [B]; the specifics proposed)*

**Decision, accepted 2026-11-22.** M3a first. Then M2's billable walk on its own, on M2's code, in a project in the operator's own organization, taking G0a's branch [B]. Then M3b. There is no merged walk. *Proposed,* as a revisit trigger: if M2's walk has not run when M3b's build is done, the operator decides again. *(2026-11-24, ADR 0023's M2 walked: M2's walk ran 2026-11-24 at 3fd79c4, before M3b's build started, so the trigger cannot arise.)*

**The steps.**
1. **Now, with no cloud:** the records of §4 and §5, in one commit made when the operator asks (D10).
2. **M3a's build, with no cloud:** D6's two packages and the M3a walk file, its W-FED mode included, with `./check.sh` green; M3a's runbook; and W-FED's steps, appended to M2's walk runbook.
3. **M3a,** in an approved session, in a project in the operator's own organization (proposed: one fresh scratch project there). It is free.
4. **M2's billable walk, on M2's code, after M3a,** in a project in the operator's own organization, under [B]. That organization blocks key upload and allows key creation (`docs/runbooks/adr-0023-m2-probe-walk.md:337`). The walked commit may carry M3a's packages, which no command uses, so the walked `farcast` is M2's [inf]. *(2026-11-24, ADR 0023's M2 walked: walked 2026-11-24 at 3fd79c4, which carries M3a's packages, in the probe walk's project under [B].)*
   - **The installer's key.** The installer's Google-made key is an exception to ADR 0024, which the operator approves at the walk's G0a. It is time-boxed to the walk and deleted at teardown. *Proposed specifics* (§9, question 23): the walk uses the installer's existing key if the operator holds one, or one made at WP.8 as phase 1's step 2 makes it (`docs/runbooks/phase-1-validation.md:85-86`), in Cloud Shell or on the console's Keys tab, because the Mac runs no `gcloud` in the walk, then downloaded through the browser and moved at once to 0600 on the Mac, every other copy deleted; WP.8 counts the installer's user-managed keys, a count only, once the walk's key exists, and the count expected is 1: any other count stops the walk to ask the operator, because any other key is G0a's to decide; after W6.1's release the operator deletes the key in Google from Cloud Shell, and the key file on the Mac, and checks the count is WP.8's less one, which is 0 when WP.8 found 1, and then the installer holds no user-managed key; W6.6 deletes the config home's copy; a no at G0b, or any stop that ends the walk once the key exists, deletes them too. *(2026-11-24, ADR 0023's M2 walked: G0a chose the existing key; WP.8 counted 1; after W6.1 it was deleted in Google and on the Mac, and the count was then 0. No copy was found in the download folder or in the walk's config home, the key never reached Cloud Shell, and W6.6 removed the walk directory, the config home with it.)*
   - **The reader is not walked** in M2, as [B] says today: `reader init` stops at its first policy check (`readerinit.go:402-411`), and M2's records keep "reader not walked". *(2026-11-24, ADR 0023's M2 walked: so it was: W4.3's paste stopped at its first policy check, the legacy upload constraint, with nothing changed.)*
   - **[U1] is withdrawn:** the walk takes [B], and FarCast is not to ask for a security default to be relaxed (D7, fallback 4, proposed). Today's `reader init` still says an organization administrator must allow upload (`readerinit.go:404`, `:409`); M3b rewords it (§7).
   - **[U2] is deferred** with the project that has no organization, until most of FarSight is ready. When it runs, it is a project outside any organization, and this design proposes (not decided) that key upload is open there, so that the installer and the reader are both fallback 2, device-made RSA certificates uploaded in Cloud Shell, and no Google-made key exists. The reader would be set up by `reader init` and `reader record`, as today. The installer would be set up by a walk-tagged helper, `farsight/cli/internal/cli/walkm2key_test.go` (`//go:build walk`), which makes the key with `kube.NewReaderKey` (`kube/readerkey.go:38-72`), prints the Cloud Shell lines that create the installer SA, grant its roles and upload the certificate, and, given the key ID the upload printed, assembles at 0600 the service-account JSON M2's code reads. That JSON passes `install`'s check (`install.go:384-405`, `kube/credential.go:47-98`) and the registry's service-account-only loader (`registry.go:588-600`), whose vendored 2LO source fills in the default `token_uri` (`vendor/cloud.google.com/go/auth/credentials/filetypes.go:132-155`) [read; not run]. The helper is not built now.
   - **W-FED,** an optional step with its own approval at G0a, offered only if M3a passed in the organization project. Its steps are appended to M2's walk runbook with M3a's build, because they use M3a's probe, and they run after W5 and before W6.1, while the cluster exists. *(2026-11-24, ADR 0023's M2 walked: approved at G0a on 2026-11-23, and run 2026-11-24, after W5 and before W6.1.)*
     1. In the walk's project, in Cloud Shell, M3a's setup paste for one fresh writer-capable device, made by the probe: it creates the pool, the device's two providers and the two SAs, with their bindings. The writer SA gets no role.
     2. The reader SA gets `roles/container.viewer` on the walk's project, for this step only. IAM then authorises its reads with no RBAC and no reader record: GKE's access reviews consult IAM (ADR 0023:121's 2026-11-16 note). That it is the smallest role that does so is [unverified]. *(2026-11-24, ADR 0023's M2 walked: with that role alone and no RBAC, the SA token's three reads were answered 200, 200 and 201. That it is the smallest such role stays [unverified].)*
     3. The probe, with the impersonated reader token at the cluster's DNS endpoint: it reads the API server's version, lists namespaces, and posts a SelfSubjectReview to record the username the cluster sees as "email matches: yes or no", scrubbed. That the cluster serves SelfSubjectReview is [inf]. *(2026-11-24, ADR 0023's M2 walked: it serves it: the review was answered 201 Created, and "email matches: yes". The probe accepted only 200 at first, and was patched to accept 201 too (D6's note).)*
     4. Once more with a direct federated token, recording 401 against 403. 401 means the endpoint refuses that kind of token; 403, that it authenticated it and IAM or RBAC refused it. *(2026-11-24, ADR 0023's M2 walked: 403 for each of the three, authenticated, then refused.)*
     5. Then the grant, the bindings, the providers, the pool and the SAs are deleted, under the settle rule, and the device's keys go with the walk directory. *(2026-11-24, ADR 0023's M2 walked: all were deleted. STS, which W-FED enabled, was disabled without `--force`, and no API was kept; `wfed-gone` saw both roles' exchanges refused at its first try; W-FED's counts returned to its baseline; the device's keys were removed.)*

     It records statuses, counts and "yes or no" only, never a token, email or ID.
5. **M3b,** built after M3a passes. Its build may overlap step 4.
6. **M3b's billable walk,** after M2's walk. Proposed, as a revisit trigger: if M2's walk has not run when M3b's build is done, the operator decides again. *(2026-11-24, ADR 0023's M2 walked: M2's walk ran 2026-11-24, before M3b's build started, so the trigger cannot arise.)*

**Why this order.**
- M2's walk tests what still ships under M3b: the service-account token path that fallbacks 2 and 3 share (the same loaders, `kube/credential.go:47-98` and `registry.go:588-600`) [inf], and every part of M2 that M3b does not change. That is the in-process client, server-side apply, the plans and the uid grants (M2.8's uid member is [unverified] until that walk). It tests them with the only credential shown to work at the DNS endpoint, a 2LO SA token (the probe walk's 200). *(2026-11-24, ADR 0023's M2 walked: it did, at 3fd79c4 under [B], with the installer's 2LO token throughout. The uid member is settled: Cloud Storage accepted and honoured it, and Artifact Registry honoured it for a push.)*
- W-FED moves M3b's largest unknown onto a cluster that exists anyway, at a few minutes' cost, before weeks of M3b are built on it. *(2026-11-24, ADR 0023's M2 walked: it did: GKE's DNS endpoint accepted the impersonated token, and Kubernetes saw the SA's email.)*
- It runs where the operator's own projects are: an organization where key upload is blocked, as in newer organizations by default (ADR 0023:119).

**Why the other answers lost.**
- **One merged walk** (v2's branch M) would have saved a billable session: G0b's floor model puts M2's walk at about USD 0.7 to 1.5, with USD 5 the approval cap (`adr-0023-m2-walk.md:7`, `:235-243`). It would also have made no service-account key. Against it: one session with two sets of unknowns, M3b built on an unproven premise, and M2.1 to M2.9b unwalked for weeks longer. The operator chose the separate walk.
- **A project with no organization now** ([U2]) would have made no Google-made key. The operator deferred it until most of FarSight is ready.

**Costs.**
- Two billable walks.
- One Google-made installer key, an approved exception, for the walk's duration.
- The reader is not walked in M2: A22-7's reader evidence stays open, except the federated reader's cluster reads if W-FED runs. *(2026-11-24, ADR 0023's M2 walked: W-FED ran: the federated reader's impersonated token read the cluster under IAM's `container.viewer`, and Kubernetes saw the SA's email. The evidence for a reader under farcast's own RBAC stays open.)*
- Fallback 2's reader and installer stay unwalked until the deferred project with no organization.

### D10. How it is recorded *(proposed)*

**Decision.** One records commit, made only when the operator asks. It holds:
- **a new ADR,** `docs/adr/0024-paste-the-certificate.md` (§3);
- **dated notes, never rewrites,** in ADR 0023 (§4) and in ADR 0007, 0019 and 0020 (§5). Accepted ADR text is never rewritten;
- **dated notes in two runbooks:** phase 1's key download and phase 3's storage condition (§5);
- **the summaries, rewritten in place:** AGENTS.md, PLAN.md and the README (§5);
- **this design,** as `docs/design/adr-0024-design.md`;
- **the M2 design's §41,** which answers A22-2 and supersedes its open lines (§5). §40 already exists;
- **the M2 walk runbook's dated notes:** its Status line (the header), what is left to choose at G0a (`:9`), deviation 10 (`:21`), T6's stops (`:70`), G0a's branch, project and optional steps, WP.8, and those that carry G0a's key and its deletion and a fresh project's teardown: G0b's no, G0b's list of what the walk creates and its teardown (`:251`, `:252`), W6.2, W6.8, and the Results rows of WP.8 and W6.2 (`:656`, `:687`) (§5).

**Not in that commit:** M3a's runbook, `docs/runbooks/adr-0024-m3a-probe.md`, and W-FED's steps, appended to M2's walk runbook. Both are written with M3a's build, because they use its probe.

**No cited line moves.** Other files cite lines by number (for example AGENTS.md:33, :48, :70 and :78; README.md:280 and :300; PLAN.md:430-435 and :457; many ADR 0023 lines) [read]. So every note is appended at the end of an existing line or, in a table row, at the end of the cell it amends, every summary sentence is rewritten in place within its line, §41 goes after the M2 design's last line, and the two new files are new. AGENTS.md gains no paragraph: one placed before "TimeTomb is deferred" would move :70 and :78, and :78 is cited by ADR 0021:8 and :30, accepted text that cannot be rewritten [read].

**Why the other answers lost.** All three designs agreed on a new ADR. Uniformity numbered the design's amendment §40, which is taken. v2 placed a new AGENTS.md paragraph and a new runbook header line, each of which moved cited lines.

### D11. Privacy accounting *(proposed)*

**Decision.** ADR 0024 records this as *What each provider sees*.

**Google, today:**
- **The writer,** a Google-made key. Google made the private key, and it travelled as a download. One installer serves the whole project, so its token writes every cluster in it. It does not expire. Entries name the SA [read: ADR 0023:113, :290].
- **The reader,** an uploaded device-made RSA key. Google holds a `CN=unused` certificate valid up to 3650 days (`farsight/cli/internal/kube/readerkey.go:14-21`). The SA's name and display name name the product and the instance (D3).

**Google, under this design:**
- **What it holds:** the pool; one provider per role per device per instance, each holding one anchor certificate (a random role ID, a public key, its dates and its serial) and a condition naming that ID; three SAs, the reader's, the writer's and the nodes', and their bindings, all under random IDs.
- **On each exchange,** about hourly while a role is in use: the reader's on reads, the writer's only in consented commands. Google sees the leaf, in the handshake and in `subject_token`, with the source address and the time, then a `generateAccessToken` call.
- **Admin Activity** (always on, 400 days, undeletable; ADR 0019:29) records:
  - the creation and deletion of the pool, the providers and the SAs. Whether a provider's entry keeps its request in full, the anchor PEM and the condition with the role ID, is [unverified]; M3a's P8 settles it; *(2026-11-23, M3a walked: P8 read 42 entries for the pool and providers; the condition, with its role ID, is present in them, and no PEM is.)*
  - **every enrolment's `SetIamPolicy` on the SAs.** Its entry carries the binding delta with its member: the principal, with its role ID [doc: POLHIST, AUDLOG, as the critique read them]. So each role ID is in the always-on log for 400 days, whatever delegation logging does. P8 reads these entries too; *(2026-11-23, M3a walked: P8 read 13 entries; the binding delta's member names the role ID.)*
  - cluster writes, naming the SA; *(2026-11-24, ADR 0023's M2 walked: on GKE 1.36.4, with today's installer, the log kept farcast's own cluster writes only on ConfigMaps and Secrets, at the metadata level; its other server-side applies, sent as YAML, left no entry. The controllers' Pod creates, which carry each Pod's template, name GKE's controllers, not the writer (W5).)*
  - the role ID under `serviceAccountDelegationInfo`, only in services that log delegation, which GKE does not [doc: AUD]. Artifact Registry and Cloud Storage are recorded at M3b's walk.

  With random IDs these are pseudonyms, not marks: an ID says nothing but itself.
- **Data Access** (off by default; a parent can force it on, ADR 0019:29) records STS's `principalSubject`, the mapped principal and the anchor's `keyInfo` fingerprint (a Preview feature), and IAM Credentials' federated principal [doc: AUD]. *(2026-11-23, M3a walked: P8 found that every STS and IAM Credentials entry of the exchange and impersonation carries the user agent `farcast`, the caller's address and the role ID as the mapped principal, and a `principalSubject` is present in both services' entries; STS's carry the anchor's or intermediate's SHA-256 fingerprint in `keyInfo`; none of those entries carries a leaf's serial or fingerprint. The user agent is one more FarCast mark the provider logs, beside the anchor profile's traits, for M3b to decide.)*

**New to Google:**
- how many operator devices an instance has, which of them are writer-capable (a provider whose principal is bound on the writer SA is a writer's, and a device's two providers are created in one paste on the same day [inf]), and when each was enrolled, changed and revoked;
- which device and role made which call, where delegation or Data Access is logged.

That is a stable pseudonym per device and role, the kind `fatline/identity/identity.go:111-121` keeps out of provider logs for FatLine's leaves. It is stated here rather than hidden. V8 (D3) is the measured way to narrow it, and it narrows less than v1 said.

**Removed,** from M3b on, wherever the certificate route or a device-made fallback is open:
- every Google-made private key, and the download. Fallback 3 keeps one, named and consented, where every other route is closed; M2's walk keeps one, as the approved, time-boxed exception (D9);
- the shared, non-expiring installer key, on the same condition;
- the product and instance names in the reader's display name, on the certificate route. Fallback 2's `reader init` keeps them, unless it adopts D3's random names;
- linkage across instances by key or by ID, since each instance has its own anchor keys and random IDs.

**Linkability that remains:**
- the operator's source address calling several projects. That holds on every route, because control-plane calls do not pass through FatLine (ADR 0019);
- the profile traits below.

**Marks of FarCast that this design does not remove** (§9, question 13):
- **existing marks:**
  - cluster names;
  - the repository prefix and its labels;
  - the `farcast-` bucket prefix, which the writer's storage condition names in the project's IAM policy (`docs/runbooks/phase-3-validation.md:60-65`), so it sits in an always-on Admin Activity entry from the setup on; *(2026-11-26, M3b.1: M3b.1 added the kind the condition's title is drawn as, 30 characters of `[a-z][a-z0-9]*`; the setup block is to draw it per instance (M3b.5), with no description, so that no fixed word repeats. Its fixed length and alphabet are one more trait of a FarCast project, as the object IDs' are (§12).)*
  - the installer account's name until M3b, and the reader's until M3b;
  - the user agent and field manager `farcast`; *(2026-11-23, M3a walked: P8 found the user agent in every STS and IAM Credentials Data Access entry of the exchange and impersonation too.)* *(2026-11-24, ADR 0023's M2 walked: in GKE's Admin Activity log too, on farcast's ConfigMap and Secret writes, as "farcast,gzip(gfe)" (Google's front end appends the suffix [inf]).)*
  - the same embedded component digests pushed into every instance's registry since M1 [inf];
- **the anchor profile's traits,** shared by every FarCast anchor. Each is common alone; together they let Google cluster FarCast's anchors [inf]:
  - a self-signed CA with path length 0 and the clientAuth extended key usage;
  - a subject that is a CN alone, of 32 lowercase hex characters, and a leaf whose DN equals its issuer's;
  - the key identifiers Go adds: the anchor's subject key identifier is the first 20 bytes of SHA-256 of its subjectPublicKey [ran], which tools that use SHA-1 do not produce [inf]; the leaf has an explicit authority key identifier and no subject key identifier [ran];
  - providers made in pairs in one paste, each trust store holding one such anchor and each condition of the same shape;
  - the lifetimes, 390 and 90 days to the second;
  - the one-hour backdating to a whole second;
  - 128-bit serials.

**AWS** [doc: RA-TRUST; the CloudTrail claims are [unverified], their pages not listed]:
- CloudTrail records `CreateSession` as a management event [unverified];
- every later event carries `sourceIdentity` (the leaf's CN, the role ID) and the session name (the leaf's serial in hex) [unverified];
- the Subject resource keeps recent leaf certificates, for a retention that is [unverified];
- expiry notices are on by default [unverified].

**Azure:**
- `keyCredentials` stores the certificate;
- service-principal sign-in logs keep its thumbprint, key ID, address, ASN and user agent [doc: ENTRA-LOG], for 7 days on Free and 30 on P1 or P2 [doc: ENTRA-RET].

**Why the other answers lost.** The three accountings agreed. This one adds the explicit tension with `identity.go:111-121`, V8, the `SetIamPolicy` entries and the profile traits.

---

## 3. ADR 0024's outline

**File:** `docs/adr/0024-paste-the-certificate.md`.

**Title:** "ADR 0024 — The Operator's Cloud Credential: Paste the Certificate the Installer Shows".

**Status:** Accepted 2026-11-22 by the operator, in part:
- the procedure: paste the certificate the installer shows, the same on every provider;
- the fallback rule: a provider-made secret only where the certificate route is closed, named and consented;
- M3a's advancement, before M2's billable walk;
- the order: M2's billable walk runs on its own after M3a, then M3b, with no merged walk;
- the projects: M3a and M2's walk use a project in the operator's own organization, and a project with no organization comes later, when most of FarSight is ready. So M2's walk takes [B]: the installer's Google-made key is an exception to this ADR that the operator approves at the walk's G0a, time-boxed and deleted at teardown, and the reader is not walked in M2;
- ADR 0023 *Choices* 5: human-only enrolment. Every device addition, renewal and revocation is a human's paste, and no FarCast identity can enrol devices.

Every other decision is proposed, with its default in *Choices*, and is dated when the operator answers it.
- Google's X.509 mechanism is gated on M3a, which has not run. *(2026-11-23, M3a walked: M3a ran 2026-11-23 and passes in an organization project.)*
- The AWS and Azure mappings are gated on their own probes, which are defined and not run.
- Nothing is built.

**Date:** 2026-11-22.

**Relates to:**
- **Answers** ADR 0023 *Choices* 1 in its procedure, *Choices* 5, and its 2026-11-16 note at :119 (A22-2).
- **Amends,** by the operator's decisions of 2026-11-22, ADR 0023's milestone order (M3a before M2's walk, M2's walk on its own, then M3b), the organization of M3a's and M2's walk's project, and M2's walk's branch [B]; and **proposes to amend** ADR 0023 decisions 5 and 7, M3a's content, W-FED in M2's walk, its Phasing rows for M3b and M5, and its revisit trigger on M3a.
- **Keeps** ADR 0023:115-117's "reads never mint an admin token", by key separation.
- **Departs from** ADR 0007 decision 2, if decision 8 below is accepted.
- **Uses** ADR 0020's P-256, and **keeps** ADR 0020's instance PKI apart from cloud identity.
- **Constrained by** ADR 0019 (what the provider logs), ADR 0018:33 (thin devices hold no cloud credential), and ADR 0021 decision 7 (conformance vectors for the Swift template).

**Context.**
- What `farcast` does today (§0).
- The research of 2026-11-22, with URLs and dates:
  - Google: key creation and upload blocked by default in organizations created on or after 2024-05-03; X.509 federation GA since 2025-05-07, with its limits; OIDC with an uploaded JWKS; embedded web views refused for Google sign-in.
  - AWS: Roles Anywhere, and the "Sign up for AWS (new)" accounts' SCPs.
  - Azure: RSA-only certificate credentials; RS256-only federated credentials with a public issuer.
- The operator's install vision (three surfaces), and the operator's decisions of 2026-11-22.

**Decisions,** each marked:
1. **The procedure,** provider-neutral: D7's four steps. *Accepted 2026-11-22.*
2. **The fallback rule:** a provider-made secret only where the certificate route is closed, named and consented. *Accepted 2026-11-22.* The order of fallbacks and their per-provider forms (D7) are *proposed*.
3. **M3a before M2's billable walk, in a project in the operator's own organization.** *Accepted 2026-11-22.* The run in a project with no organization is deferred until most of FarSight is ready. One fresh scratch project there, and M3a's content (D8, §6), are *proposed*.
4. **The artifact:** two roles, an anchor and a leaf per role, one provider per role, random role IDs (D2). *Proposed.*
5. **Mapping, condition, grants and names:** D3. *Proposed.*
6. **Google's route and token path:** D1 and D5. *Proposed,* gated on M3a.
7. **The installer-minted reads:** D5. *Proposed,* decided per read in M3b's build.
8. **The code:** D6, including the departure from ADR 0007 decision 2. *Proposed.*
9. **Enrolment, revocation, renewal and pending installs:** human-only enrolment, ADR 0023 *Choices* 5, *accepted 2026-11-22*. The mechanics (D4) and pending installs (D7) are *proposed*.
10. **AWS and Azure:** D7, each departure named. *Proposed,* gated on their probes.
11. **The order and the projects:** M3a; then M2's billable walk on its own, under [B] in the operator's own organization, with the installer's Google-made key as an approved, time-boxed exception; then M3b (D9). *Accepted 2026-11-22.* W-FED and the exception's specifics are *proposed*.

**What each provider sees:** D11.

**Cost:**
- No new standing cost. IAM is offered at no additional charge [doc: PRICE], STS and impersonation are unpriced [inf], and Roles Anywhere with a self-made CA, and Entra certificate credentials, carry no charge [inf from the readers' sources].
- M3a is USD 0.
- A missed anchor renewal leaves the instance billing under TechnoCore's in-cluster limit, recoverable by one paste.
- AWS's activation path is refused because it removes the spend limit.

**Consequences:**
- *Positive:*
  - no provider-made secret on any route where the certificate route is open, from M3b on;
  - reads hold no key that can write, on every platform;
  - per-device, per-role revocation;
  - the reader/writer split rests on each provider's trust store and condition, not on Google enforcing path length;
  - works where Google blocks SA keys, if M3a passes;
  - one procedure for a non-technical operator;
  - leaves renew themselves.
- *Negative:*
  - up to four keys and two providers per device per instance;
  - a yearly paste per device per instance;
  - stable per-device, per-role pseudonyms in Admin Activity and in some other logs;
  - the reader reaches the instance's ciphertext, and its images, which are not encrypted, from M3b;
  - FarCast owns its token-exchange code;
  - Azure's key is not in the Secure Enclave;
  - some organizations and AWS accounts land on a secret;
  - an Owner-level paste is a phishing pattern;
  - M2's walk keeps one Google-made key, as an approved, time-boxed exception;
  - the route is proven, if M3a passes, in an organization project only, until the deferred run in a project with no organization.

**Alternatives considered:**
- OIDC with an uploaded JWKS as the route;
- the instance CA as anchor;
- a per-instance federation CA;
- one certificate as anchor and leaf;
- one principal per device for both roles;
- two leaves under one anchor;
- two anchors in one provider per device, with a two-clause condition;
- a role ID derived from the key;
- direct principal grants;
- a pool-wide grant;
- the writer for the installer-minted reads;
- vendoring the public external-account package;
- a cross-provider adapter interface now;
- an operator-registered OAuth client (ADR 0023 Choices 1 (b));
- an enrolled device that may add providers (ADR 0023 Choices 5's other answer);
- one merged billable walk for M2 and M3b;
- Azure federated credentials;
- AWS's CRL fetching;
- AWS's advanced-features activation.

**Choices left to the operator:** §9, each with its default.

**Verification:**
1. M3a's Results table (§6);
2. the unit and mutation rows of §7;
3. M2's walk W-FED, or M3b's walk, for the DNS endpoint; *(2026-11-24, ADR 0023's M2 walked: W-FED settled it on 2026-11-24.)*
4. M5's Secure Enclave TLS identity;
5. AWS and Azure probes when their adapters start;
6. the no-cost embedded-sign-in check, before the GUI install flow;
7. M3a's deferred run in a project with no organization.

**Revisit triggers:**
- M3a fails, which brings in D7's order and the operator re-decides;
- M3a is refused by a policy Google sets by default in new organizations, which fails the operator's rule (no route a provider closes by default), and the operator re-decides;
- an organization the operator uses blocks X.509 providers;
- the deferred run in a project with no organization differs from the organization run;
- Google documents that X.509 federation enforces a CA's path length, which would reopen two anchors in one provider (fewer console forms);
- GKE refuses impersonated tokens; *(2026-11-24, ADR 0023's M2 walked: W-FED found that it accepts them.)*
- Artifact Registry or Cloud Storage delegation entries carry the role ID, which reopens V8;
- Google adds CRL support, or certificate-bound tokens leave Preview;
- Google prices STS or impersonation;
- AWS documents P-256 for Roles Anywhere or changes the new accounts' SCPs;
- Entra accepts EC certificates;
- a Secure Enclave TLS identity fails at M5;
- Google admits or refuses Cloud console sign-in in an embedded web view;
- M2's walk has not run when M3b's build is done, and the operator decides again. *(2026-11-24, ADR 0023's M2 walked: M2's walk ran 2026-11-24, before M3b's build started, so the trigger cannot arise.)*

**Sources:** the [doc] list above, and the repository at 5ef5ee8.

---

## 4. ADR 0023's dated notes

Each note is appended at the end of the anchor's line or, in a Phasing table row, at the end of the cell it amends, as ADR 0023's earlier Phasing notes are, in the ADR's own form: `*(2026-11-22, [ADR 0024](0024-paste-the-certificate.md): …)*`. No accepted text is rewritten, and no line is added. Where a line carries two anchors, the two notes are one. Line numbers are at 5ef5ee8. The texts below are where the applied notes started; the applied texts were revised from them, and ADR 0023 itself is the record.

| Line | Anchor text | The note to append |
|---|---|---|
| :3 | "The other choices stay open until the milestone that needs them: 1 and 5 by M3b" and "What remains of M2 is that walk; M3a and every later milestone are not started." | The operator decided on 2026-11-22 that the operator's cloud credential is the certificate the installer shows, pasted in the provider's console or cloud shell, the same on every provider, with a provider-made secret only where that route is closed. That answers Choice 1's procedure; on Google, ADR 0024 proposes X.509 federation, gated on M3a. Choice 5 was answered the same day: human only. M3a was brought forward and comes before M2's walk, which then runs on its own, in a project in the operator's own organization under its branch [B], before M3b. Neither has started. |
| :16 | "This ADR adds the Mac case, a Secure Enclave key kept by a Developer ID app without a sandbox, as an M5 probe." | Google's X.509 exchange proves possession by mutual TLS, so the M5 probe also covers a TLS client identity formed from such a key, for each role's leaf. The AWS route needs only a signature. |
| :74 | "M3a identity probe · M3b device keys" | M3a probes X.509 federation and runs before M2's billable walk. |
| :79 | "Workload Identity Federation adds one package, `credentials/externalaccount`, from an already-vendored module [ran]." | That was measured for the JWT route. The vendored X.509 source is file-based (`credentials/internal/externalaccount/x509_provider.go:58-70`, `:200-219`), against decision 5's "never read from a file" and the Mac broker, so ADR 0024 proposes to hand-roll the exchange on the standard library: +0 modules and +0 packages vendored. |
| :81 | "The cost: an organization that enforces certificate-based access would refuse this CLI." | farcast would present its device certificates only through its own transport, in STS's mTLS exchange, never through the library's certificate-based access. The variable stays false, so the stated cost stands. |
| :113 | "From M3b it is a per-instance SA that the device key impersonates." | Under ADR 0024, a writer-capable device impersonates it with its writer key alone, never a reader key. "Bound to the instance" still does not hold in a shared project: the writer SA's roles are project-wide, so one project per instance stays the full separation. |
| :116 | "From decision 5 on, the device key impersonates it through its own grant." | Under ADR 0024 each device holds a reader anchor and leaf, and a writer-capable device also a writer anchor and leaf. Each role has its own provider, principal and grant. Read commands and plans open only the reader keys. |
| :117 | "**reads never mint an admin token**" | ADR 0024 keeps the rule by key separation, on every platform: no read opens a key whose principal is bound to the writer, with a test. Google refusing a reader key's attempt to act as the writer is gated in M3a. |
| :118 | "and plans' Google reads are to move to a scoped identity at M3b." | ADR 0024 proposes that identity: from M3b the reader, with read-only grants on the instance's own repository and bucket, applied by the writer, as consented acts, when it creates or re-ensures them. `storage ls`, `storage usage`, `storage cp`'s downloads and `secret ls` move to it too. `projects.get` goes, because the coordinates hold the project's number. It is decided per read in M3b's build. |
| :119 | "*Where SA keys are made:* `farcast` generates each SA's RSA key pair on the device" | This holds for the reader only. The installer's key is a Google-made download (`docs/runbooks/phase-1-validation.md:85-86`). The 2026-11-16 options are answered by the operator's decisions of 2026-11-22: the third, no service-account key, is the route; the second's Google-made key is kept only where the certificate route is closed, and for M2's walk, which runs under [B] in the operator's own organization, as an exception the operator approves at its G0a, time-boxed and deleted at teardown; the first, relaxing a security default, is not proposed. |
| :121 | "An impersonated token is still open, for M3b." | M3a makes no cluster. M2's walk can settle it in an optional W-FED step, with its own approval, if M3a passed in the organization project; otherwise M3b's walk does (ADR 0024, D9). |
| :153 | "**5. Identity, proposed: a per-device, per-instance P-256 key, through Workload Identity Federation" | On 2026-11-22 the operator decided the procedure: paste the certificate the installer shows. ADR 0024 proposes X.509 federation as its mechanism on Google: each role's certificate is the trust anchor of its own X509 provider, exchanged over mutual TLS, then `generateAccessToken`. It is gated on M3a. The JWT, uploaded JWKS and `.invalid` issuer of :154-166 are the proposed fallback, measured in M3a as V5. |
| :160 | "*The shape this implies [inf]:*" | Under X.509 the proposed shape is ADR 0024's decisions 4 and 5: per device per instance, one provider per role, each holding that role's anchor, so a reader-only device has one and a writer-capable device two; a CN that is a random role ID and nothing else; and a condition that the issuer CN equals the subject CN and equals that provider's role ID, because principals are pool-scoped (the X.509 form of :161's caveat). X.509 has no issuer URI, so :164's analogue is a certificate that names nothing, though its profile's traits together may mark it as FarCast's [inf] (ADR 0024, *What each provider sees*). |
| :161 | "A token already issued stays valid until it expires, up to one hour." | Possibly about two hours, if a federated token issued before the deletion can still impersonate [inf]. M3a measures it, and ADR 0024 removes the bindings first. |
| :163 | "**An opaque subject:** the key's thumbprint" | ADR 0024 proposes a random 128-bit ID per device per instance per role, never derived from a key. A CN that is its own key's hash would let Google find every FarCast anchor with one hash. |
| :165 | "that pools work in a project with no organization is an inference." | It stays an inference: the operator deferred M3a's run in a project with no organization until most of FarSight is ready. |
| :166 | "*The gate:* real STS accepting a self-signed ES256 JWT" | The gate is now ADR 0024's M3a: STS accepting a device-made P-256 anchor and its leaf over mutual TLS, and refusing every gating negative. It runs in a project in the operator's own organization, by the operator's decision (one fresh scratch project there is proposed); the run in a project with no organization is deferred until most of FarSight is ready. The JWT client's offline pass is evidence for the fallback only. |
| :168 | "The exchange and refresh stay in the vendored library." | Under X.509 no subject JWT is signed. ADR 0024 proposes the exchange and `generateAccessToken` hand-rolled on the standard library, which departs from ADR 0007 decision 2 instead; the refresh has been FarCast's own `tokenCache` since M2.1. The guard now sits at `planck/internal/providers/gke/registry.go:588-600`. |
| :170 | "*SA keys stay as a deprecated legacy path,*" | There are two kinds. An uploaded key with a device-made RSA certificate is still a certificate paste (ADR 0024's fallback 2). A Google-made download is a provider-made secret (fallback 3): its own flag, a plan fact, never `--yes`. |
| :171 | "*What stays at rest:* a 0600 device-key file" | Under ADR 0024, up to four 0600 key files per instance: a reader anchor and leaf, and on a writer-capable device a writer anchor and leaf. The writer's two open only after consent. |
| :172 | "*What Google can see:* the pool, one provider and one public key per enrolled device per instance" | Under X.509, one provider per role per device per instance, each holding one anchor certificate with all its fields, and the leaf on every exchange. Each role ID is also in the always-on `SetIamPolicy` entries of its binding (ADR 0024, *What each provider sees*). |
| :195 | "**The Swift app holds the key and brokers tokens.**" | Under ADR 0024 it holds two pairs on a writer-capable Mac. The exchange needs a TLS client identity from each leaf key, not only a signature. The federated tokens stay inside the app, and the helper receives SA tokens only. |
| :196 | "**A terminal `farcast`** cannot use the app's key. It enrols its own 0600 P-256 key" | Under ADR 0024 it enrols its own reader pair, and a writer pair if writer-capable, by one paste per instance. |
| :198 | "So the no-cost M5 probe tests both creating the key and restoring it from the file." | It also tests a TLS client identity: `SecIdentityCreate` on that key, which worked in ADR 0020's foreground probe and which Apple DTS advised against (ADR 0020:57), or a keychain-formed identity, which brings back the keychain item and access-group entitlement this bullet avoids. If neither holds, the Mac app takes ADR 0024's fallback. |
| :201 | "and a 0600 software P-256 key, as keeper keys are today." | Under ADR 0024, up to four per instance, and a paste per device per instance. |
| :219 | "it shows its digest, because the operator pastes it into an Owner-level shell [inf]." | Like any value a block prints, the digest binds nothing about a block that came from elsewhere. ADR 0024's binding checks are the read-back of the providers and `device ls`. |
| :225 | "*Recommended:* (a), if M3a passes." | The operator decided the procedure on 2026-11-22. (a) is proposed with X.509 certificates. (c) splits into an uploaded device certificate (fallback 2) and a Google-made download (fallback 3). (b) keeps a refresh token at rest, a provider-made secret, and is proposed as not planned. |
| :229 | "*Recommended:* human only." | Answered 2026-11-22 by the operator: human only. Every device addition, renewal and revocation is a human's paste, and no FarCast identity can enrol devices. Under ADR 0024 it holds by construction [inf]: a device's anchors reach Google only by a human's paste, and neither a FarCast identity nor an account the writer can act as is to hold pool-admin rights (ADR 0024 decision 9). |
| :238 | "the devices' providers, which hold public keys only. A Cloud Shell paste does it" | In the console or Cloud Shell, pasting the certificates the installer shows. Per instance there are a pool and three SAs (the reader's, the writer's and the nodes'), and the per-project part folds into one idempotent block per instance. Providers hold certificates, one provider per role per device. |
| :239 | "Enrolling or revoking a device: one Cloud Shell line, creating or deleting one provider." | Enrolling pastes one or two certificates, creating one provider per role and its binding. Revoking removes the bindings, then deletes the device's providers. There is no CRL or OCSP. The window is :161's note. |
| :254 | "each device's public key and provider, per instance, and each token exchange." | Under X.509, each device's one or two providers, each with one anchor certificate and all its fields, and its leaf on every exchange. |
| :258 | "every `storage deploy`, in every mode, calls as the installer: `projects.get`" | ADR 0024 proposes that from M3b these reads, and `build`'s and `run`'s, run as the reader with resource-scoped read grants, and that `projects.get` goes, the number being in the coordinates. Decided per read in M3b's build. |
| :279 | "M3a creates free IAM objects in scratch projects and needs approval too." | In a project in the operator's own organization, by the operator's decision of 2026-11-22 (one fresh scratch project there is proposed); the run in a project with no organization waits until most of FarSight is ready. |
| :289 | "It is kept as an optional mode (*Choices*, 1)." | ADR 0024 proposes it is not planned: it keeps a refresh token at rest, a provider-made secret. Answered when the operator confirms it. |
| :299 | "The probes: STS accepts a self-signed JWT (M3a)" | Now: STS accepts a device-made P-256 certificate over mutual TLS and refuses the gating negatives (M3a), and the Secure Enclave key forms a TLS client identity (M5). |
| :308 | "The operator pastes a script into an Owner-level shell once per project and once per instance." | Or fills the console's forms, pasting the certificates, one provider form per role. Each further device takes one more paste, and each anchor renewal one more. |
| :319 | "**Billable walk:** install a fresh instance; the DNS endpoint accepts the SA token" | It runs after M3a, on its own, then M3b (accepted 2026-11-22, ADR 0024, D9), in a project in the operator's own organization. G0a's A22-2 is answered: the walk takes [B], the installer's Google-made key is an exception the operator approves there, time-boxed and deleted at teardown, and the reader is not walked. [U1] is withdrawn, and [U2] is deferred with a project with no organization. An optional W-FED step, with its own approval, if M3a passed in the organization project. |
| :320 | "WIF probe: a pool, one single-key ES256 provider with a `.invalid` issuer" | Redefined by ADR 0024 as the X.509 probe, before M2's walk: free IAM objects in a project in the operator's own organization (one fresh scratch project there is proposed); the run in a project with no organization is deferred until most of FarSight is ready. At the end of the row's Effort cell: 3 to 4 days, plus one session [inf]. |
| :321 | "the Cloud Shell generator, per-instance SAs and software keys, the reader by impersonation" | Its scope is ADR 0024's, and covers the installer and writer as well as the reader, two roles per writer-capable device with a provider each, and the reader's resource-scoped grants. At the end of the row's Effort cell: 3 to 4 weeks [inf]. |
| :323 | "Secure Enclave broker, `dataRepresentation` probe" | Plus a Secure Enclave TLS client identity for STS. |
| :334 | "decision 2's \"no hand-rolled JWT, signing, or token refresh\"" | Under X.509 there is no JWT. The proposed departure is the hand-rolled exchange (ADR 0024). |
| :358 | "`registry.go:512-517` (the ADC fallback and the service-account-only guard), `client.go:88-92` and `datasphere/README.md:483`" | At 5ef5ee8 these are `registry.go:588-600`, `client.go:87-100` and `datasphere/README.md:485`. |
| :378 | "4. **M3a**, recorded with what STS returned and which audit entries carry the subject." | ADR 0024's M3a, and its Results table. |
| :383 | "**M3a fails,** or `allowedPolicyMemberDomains` blocks the pool." | ADR 0024's fallback order replaces (b) or (c). A refusal by a policy Google sets by default in new organizations fails the operator's rule, no route a provider closes by default, and the operator re-decides. |

---

## 5. The other records

Every edit below appends to the end of an existing line, or rewrites a sentence in place within its line. None adds a line before a line cited elsewhere (D10). A link inside a quoted note or sentence is relative to the file it goes into, not to this design. The texts below are where the applied edits started; the applied texts were revised from them, and the edited files are the record.

**ADR 0007** (dated notes):
- `:32`. Anchor: "departs from \"no hand-rolled JWT, signing, or token refresh\" at its M3b". Note: "*(2026-11-22: [ADR 0024](0024-paste-the-certificate.md) proposes X.509 federation in place of that JWT. No subject JWT would be signed. The departure would instead be the token exchange and `generateAccessToken`, hand-rolled on the standard library; the refresh has been FarCast's own cache since ADR 0023's M2.1. Until M3b lands, tokens are minted as described here.)*"
- `:38`. Anchor: "M3b mints the push token through a device key instead of the stored SA key." Note: "*(2026-11-22, [ADR 0024](0024-paste-the-certificate.md): through the instance's writer SA, impersonated by a writer-capable device's writer key, only in a consented command.)*"

**ADR 0019** (dated note):
- `:95`. Anchor: "**Each operator read mints a token at Google**". Note: "*(2026-11-22, [ADR 0024](0024-paste-the-certificate.md): from its M3b, as proposed, each read mints at Google's STS over mutual TLS with the reader leaf, and then at IAM Credentials, as the reader account. Data Access entries there, where on, name the reader's opaque role ID.)*"

**ADR 0020** (dated note):
- `:266`. Anchor: "the probe both creates the key and restores it from that file." Note: "*(2026-11-22, [ADR 0024](0024-paste-the-certificate.md): the same M5 probe also forms a TLS client identity from such a key, for Google's mutual-TLS exchange: `SecIdentityCreate` or a keychain-formed identity, as this ADR's Context weighs them. It changes nothing this ADR decided, and keeps the instance PKI apart from cloud identity.)*"

**AGENTS.md** (it summarises, so its sentences are rewritten in place; it gains no paragraph, because :70 and :78 are cited, D10):
- `:48`, the sentence "What remains of M2 is that walk; M3a and every later milestone are not started." becomes: "What remains of M2 is that walk. Since 2026-11-22 M3a comes before it, and the walk then runs on its own, in a project in the operator's own organization where key upload is blocked, before M3b ([ADR 0024](docs/adr/0024-paste-the-certificate.md)). Neither has started."
- `:52`, the sentences "The proposed identity is … Application Default Credentials go." become: "What is to replace both stored keys was decided on 2026-11-22 ([ADR 0024](docs/adr/0024-paste-the-certificate.md), accepted in part, not built; M3a has not run): the operator's cloud credential is *paste the certificate the installer shows*, the same on every provider. The installer (the `farcast` CLI first, the FarSight app later) makes its own keys on the device and shows public certificates, a human creates the identity once in the provider's console or its cloud shell and pastes them in, and nothing secret leaves the device. A provider-made secret is used only where the certificate route is closed, and then it is named and consented. Only a human enrols a device: every device addition, renewal and revocation is a human's paste, and no FarCast identity can enrol devices (ADR 0023 *Choices* 5). M3a and M2's walk use a project in the operator's own organization, and a project with no organization comes later, when most of FarSight is ready. Key upload is blocked in that organization, so in M2's walk the installer's Google-made key is an exception to ADR 0024 that the operator approves at the walk's G0a, time-boxed and deleted at teardown, and the reader is not walked. Everything else is proposed, with a default: on Google, X.509 Workload Identity Federation, gated on a probe (M3a) that creates only free IAM objects, needs the operator's approval and runs before M2's walk; per device and per instance, a reader anchor and the leaf it issues and, on a writer-capable device, a writer anchor and leaf too, two keys per role, each anchor the trust anchor of its own provider and each role with a random ID as its subject; each role impersonating its own per-instance service account, so a read never opens a key that can write; and the order of the fallbacks. From M3b service-account keys would be fallbacks only, and Application Default Credentials would go from the CLI. The provider still sees a stable opaque ID per device and role; each enrolment; each exchange's leaf, with the source address and the time; and the anchor profile's traits, which together may mark an anchor as FarCast's [inf]. Existing marks, the `farcast-` bucket prefix in the writer's storage condition among them, stay until a separate decision."
- `:55` becomes: "**What no app can remove.** A Google account; the Cloud sign-up and a billing account; a privileged setup by the human account, once per project and once per instance (ADR 0024 proposes folding the per-project part into the per-instance one), and again for each device added, renewed or revoked, in the provider's console or its cloud shell, pasting what the installer shows: the certificates to add or renew a device, and the delete lines to revoke one (ADR 0024's procedure, accepted 2026-11-22, its specifics proposed, not built); and reading the bill for `kernel confirm`."

**PLAN.md** (in place):
- `:454`. After "no milestone after M2 is started", add: "Since 2026-11-22 M3a comes before M2's billable walk, which then runs on its own, before M3b ([ADR 0024](docs/adr/0024-paste-the-certificate.md))."
- `:457`. The tail "M3a and every later milestone are not started." becomes "M3a, now ahead of this walk, and every later milestone are not started." The **Billable walk** clause gains "after M3a, on its own, in a project in the operator's own organization where key upload is blocked ([B]): the installer's Google-made key is an approved exception, deleted at teardown, and the reader is not walked; A22-2 answered by ADR 0024; an optional federated step, W-FED, with its own approval".
- `:458` becomes: "**M3a, identity probe: before M2's billable walk (brought forward 2026-11-22).** Not started. It creates free IAM objects in a project in the operator's own organization (one fresh scratch project there is proposed) and needs approval; its run in a project with no organization waits until most of FarSight is ready. The procedure is chosen: paste the certificate the installer shows ([ADR 0024](docs/adr/0024-paste-the-certificate.md), accepted in part 2026-11-22). Its content, an X.509 probe, is proposed: it confirms Google's mechanism, or brings in ADR 0024's fallback order."
- `:459` becomes: "**M3b, device certificates: built after M3a passes, walked after M2's walk.** Not started. Its proposed scope is the certificate route for the installer, the writer and the reader, two roles per writer-capable device, each with its own provider, and `install` with no service-account key. If M2's walk has not run when M3b's build is done, the operator decides again (proposed). **Billable walk, needing approval.**"
- `:461`. After "a Secure Enclave token broker", add: "with a TLS client identity from each role's leaf key for Google's mutual-TLS exchange ([ADR 0024](docs/adr/0024-paste-the-certificate.md))".
- `:491` becomes: "GUI version of `farcast install`, on macOS only, because among the GUI clients only the Mac app holds the keys of the operator's cloud identity. The app makes its keys on the device and shows their certificates, and the operator pastes them into the provider's console beside it; if Google refuses sign-in in an embedded view, the console opens in the system browser (proposed). Where the certificate route is open, no cloud credential is typed into the app. A provider-made secret is used only where that route is closed, and it is named and consented ([ADR 0024](docs/adr/0024-paste-the-certificate.md), accepted in part 2026-11-22, not built)."
- `:494`, "Credential input", becomes: "The certificates shown, the provider's console beside them, and the one non-secret line pasted back"

**README.md** (in place):
- `:300`. After "has not run, and needs the operator's approval." add: "Since 2026-11-22 its M3a, the identity probe, comes before that walk, which then runs on its own, before M3b ([ADR 0024](docs/adr/0024-paste-the-certificate.md))." The last sentence's "once per project and once per instance" becomes "once per project and once per instance (ADR 0024 proposes folding the two) and, under ADR 0024, for each device added, renewed or revoked,".
- `:302`. "where the operator provides admin credentials for their chosen cloud provider" becomes "where the app shows certificates it made on the device, and the operator pastes them into their cloud provider's console; nothing secret leaves the device, and a provider-made secret is used only where the certificate route is closed, and then it is named and consented ([ADR 0024](docs/adr/0024-paste-the-certificate.md), accepted in part 2026-11-22, not built)". "because it needs the cloud admin credential" becomes "because among the GUI clients only the Mac app holds the keys of the operator's cloud identity; thin clients hold no cloud credential ([ADR 0018](docs/adr/0018-thin-device-storage.md))".

**docs/design/adr-0023-m2-design.md:**
- **A new §41, appended after its last line,** "Decided by the operator on 2026-11-22: A22-2 and the walk's branch". It says:
  - the operator's decisions of 2026-11-22 ([ADR 0024](../adr/0024-paste-the-certificate.md)) answer A22-2 with its third option, no service-account key. Its second, a command that imports a Google-made reader key, is not built: by the fallback rule a Google-made key is used only where the certificate route is closed, which ADR 0024 proposes as its fallback 3. M2's walk, in the operator's own organization where upload is blocked, keeps one Google-made key, the installer's, as an exception the operator approves at G0a, time-boxed and deleted at teardown, and imports no reader key. Its first, relaxing a security default, is not proposed;
  - M2's walk runs after ADR 0024's M3a, on its own, before M3b, in a project in the operator's own organization. It takes [B]: the reader is not walked, and M2's records keep "reader not walked". [U1] is withdrawn. [U2] is deferred with a project with no organization, until most of FarSight is ready; how it runs is ADR 0024's proposal, not decided: a project outside any organization where the installer and the reader are both its fallback 2, not a form of "allow upload". A fresh project in the organization is set up at WP.8 as [U2]'s list says, and W6.8 applies to it;
  - the exception's specifics, proposed, as D9 gives them;
  - an optional W-FED step, with its own approval at G0a, if M3a passed in the organization project; its steps are appended to the runbook with M3a's build;
  - the runbook's dated notes, line by line.
- §41 **supersedes**: `:3436-3441` (A22-2's options), `:3498` ("decided separately, before the billable M2 walk"), `:8349` ("A22-2's choice still comes before the walk"), `:8958-8961` (A39-19's branches), `:9088` (question 3's [U2] as a form of "allow upload") and `:9215` (A40-15's question 3, which the decisions answer). Each gets a dated note at the end of its line: A22-2's options one, at `:3438`, and A39-19's branches one per line. §41 also supersedes, with no note, `:8962`, `:8985` and `:9041`, which offer [U2] or tie a fresh project to it.

**docs/runbooks/adr-0023-m2-walk.md** (dated notes, each at the end of its line; the scrub rule of its T1 applies):
- `:5`, the Status line (the header): "*(2026-11-22, [ADR 0024](../adr/0024-paste-the-certificate.md): by the operator's decisions of that day, this walk runs after ADR 0024's M3a, on its own, before M3b, in a project in the operator's own organization, under [B]. A22-2 is answered (G0a). An optional W-FED step, with its own approval, is to be appended to this runbook with M3a's build. Neither M3a nor this walk has run.)*"
- `:9`, "A22-2's branch first ([U1], [U2] or [B])": "*(2026-11-22, ADR 0024: the branch is [B], by the operator's decision. [U1] is withdrawn, and [U2] is deferred with a project with no organization. G0a also approves the installer's Google-made key as ADR 0024's exception, chooses the existing key or one made at WP.8, and offers W-FED if M3a passed.)*"
- `:21`, deviation 10: "*(2026-11-22, ADR 0024: superseded. [U2] is deferred until most of FarSight is ready. When it runs, it is a project outside any organization, and ADR 0024 proposes that upload is open there, so that the installer and the reader are both device-made certificates uploaded (its proposed fallback 2), not a form of "allow upload".)*"
- `:70`, T6's stops: "*(2026-11-22, ADR 0024: on [B], once the installer's key G0a approved exists, any stop that ends the walk, G0b's no included, deletes that key in Google, its file on the Mac and every other copy, as W6.2's note says, and records the count.)*" T6 sent only a HARD STOP to W6, so a plain stop that ended the walk after WP.8 would not have reached the key's deletion.
- `:80`, "**A22-2's branch, first.**": "*(2026-11-22, ADR 0024: answered by the operator. The walk takes [B], in a project in the operator's own organization.)*"
- `:81`, [U1]: "*(2026-11-22, ADR 0024: withdrawn. The walk takes [B], and FarCast is not to ask for a security default to be relaxed (ADR 0024's proposed fallback 4). Today's `reader init` still says an organization administrator must allow upload (`readerinit.go:404`, `:409`), the message W4.3 [B] stops at; ADR 0024's M3b rewords it.)*"
- `:82`, [U2]: "*(2026-11-22, ADR 0024: deferred with a project with no organization, until most of FarSight is ready; see deviation 10's note.)*"
- `:83`, [B]: "*(2026-11-22, ADR 0024: the operator's branch. The installer's Google-made key is an exception to ADR 0024 that the operator approves here, time-boxed to the walk and deleted at teardown: the operator holds it at 0600 on the Mac only for the walk, deletes it in Google and deletes the key file on the Mac after W6.1's release (W6.2's note), and W6.6 deletes the config home's copy. If WP.8 counts 1 key, the installer then holds no user-managed key after the walk. Here the operator also says whether the walk uses the installer's existing key or one made at WP.8.)*"
- `:84`, "**The project.**": "*(2026-11-22, ADR 0024: a project in the operator's own organization: the probe walk's, or a fresh one there. A fresh one is set up at WP.8 as [U2]'s list there says, and W6.8 keeps it or shuts it down, as decided here.)*" Without its second sentence, a fresh project under [B] would have no setup step: WP.8's [B] is "nothing".
- `:86`, "**The optional steps:**": "*(2026-11-22, ADR 0024: and W-FED, offered only if ADR 0024's M3a passed in the organization project, with its own approval. Its steps are to be appended to this runbook with M3a's build.)*"
- `:215`, "**WP.8, A22-2's preparation (operator).**": "*(2026-11-22, ADR 0024: [B] only.)*"
- `:216`, [U1]: "*(2026-11-22, ADR 0024: not run; see G0a.)*"
- `:217`, [U2]: "*(2026-11-22, ADR 0024: not run as a branch; see G0a. If G0a chose a fresh project, this list is still its per-project setup, made under [B].)*"
- `:223`, "**[B]:** nothing.": "*(2026-11-22, ADR 0024: except the installer's key, G0a's approved exception. If G0a chose a new one, it is made here, as [phase 1's step 2](phase-1-validation.md#2-create-the-installer-service-account--key) makes it, but not on the Mac, which runs no `gcloud` (T2): in Cloud Shell, in WP.6's directory, after `umask 077`, `gcloud iam service-accounts keys create <a file name> --iam-account "<the installer's email>" --project "$PROJECT"`, or on the console's Keys tab. It reaches the Mac through the browser's download and is moved at once to a 0600 file outside any checkout. The download folder's copy and Cloud Shell's are deleted at once, not moved to the Trash. It never goes into a checkout or Cloud Shell's home. The operator also records here, in Cloud Shell, how many user-managed keys the installer holds, a count only, once the walk's key exists: `count gcloud iam service-accounts keys list --iam-account "<the installer's email>" --managed-by user`, the email typed, never recorded, the flag's spelling [unverified]. The count expected is 1. Any other count stops the walk to ask the operator, because any other key is G0a's to decide.)*"
- `:233`, G0b's no: "*(2026-11-22, ADR 0024: on [B], after a no the operator also deletes, in Cloud Shell, the installer's key G0a approved, and the key file on the Mac, as W6.2's note says.)*" A no at G0b runs W6.4, W6.5, W6.6 and W6.8, and not W6.2, so without this note a key made at WP.8 would outlive a walk that never started.
- `:251`, G0b's list, "[U2] the fresh project's setup, already made at WP.8.": "*(2026-11-22, ADR 0024: and under [B], a fresh project's setup, if G0a chose one, and the installer's key, if made at WP.8.)*"
- `:252`, "**The teardown, W6.**": "*(2026-11-22, ADR 0024: on [B], W6.2 also deletes the installer's key in Google and on the Mac.)*"
- `:629`, W6.2 ("**Operator:** read the two reader commands …"): "*(2026-11-22, ADR 0024: on [B], the operator then deletes, in Cloud Shell, the installer's key G0a approved: `gcloud iam service-accounts keys delete <the walk's key's id> --iam-account "<the installer's email>" --project "$PROJECT"`. The key to delete is the one whose id equals the key file's `private_key_id` field, both read on screen and never recorded. The operator deletes the key file on the Mac, and checks that no copy is left in the download folder or in Cloud Shell. Then WP.8's `count` line again: WP.8's count less one, which is 0 when WP.8 found 1.)*" W6 has no step that deletes the installer's key in Google, so without it "deleted at teardown" would rest on G0a's note alone.
- `:636`, W6.8: "*(2026-11-22, ADR 0024: and under [B], if G0a chose a fresh project.)*"
- `:656`, the Results row of WP.8: "*(2026-11-22, ADR 0024: on [B], also the installer's user-managed key count, expected 1.)*"
- `:687`, the Results row of W6.2: "*(2026-11-22, ADR 0024: on [B], also the installer's key deleted, and its count after, expected WP.8's less one: 0 when WP.8 found 1.)*"
- `:282-296` (W4.3) and `:309-325` (W4.5) are unchanged: [B]'s paths there already hold.
- **W-FED's steps** are not in this commit. They are appended at the end of the runbook with M3a's build, run after W5 and before W6.1, so no cited line moves.

**docs/runbooks/phase-1-validation.md:**
- `:95`, the end of the note below step 2's commands ("can skip the bindings."): "*(2026-11-22, [ADR 0024](../adr/0024-paste-the-certificate.md): the key this step downloads is a provider-made secret. By the operator's rule of that day, once the certificate route is built (ADR 0024's M3b, proposed), it is used only where that route is closed, named and consented (proposed fallback 3). Until then it is `install`'s only installer credential, and in ADR 0023's M2 walk under [B] it is an exception the operator approves at its G0a, time-boxed and deleted at teardown.)*" Line 85, the comment above the download, sits inside a code block, so the note goes on the prose line after it.

**docs/runbooks/phase-3-validation.md:**
- `:71`, the end of the sentence on "the shape production uses" ("conditional storage grants together."): "*(2026-11-22, [ADR 0024](../adr/0024-paste-the-certificate.md): from its M3b, as proposed, this grant goes to the writer SA, with a condition title drawn at random per instance and no description. The `farcast-` prefix stays a mark of FarCast in the project's IAM policy until the marks decision, ADR 0024's marks question.)*" The condition itself, `:60-65`, ends in a code block.

**Not changed now,** by ADR 0023:331's convention that a sentence describing built code keeps until the code changes:
- `farsight/cli/README.md`, `planck/README.md:354` and the code comments at `registry.go:588-600`. These change at M3b.

---

## 6. M3a in full

**Objects created.** All are free [doc: PRICE].
- **The APIs:** IAM, IAM Credentials, STS and Resource Manager are enabled. The Org Policy API is enabled for the session only if reading effective policies needs it (A22-3's lesson), and turned off at teardown.
- **One pool,** with a random ID.
- **Providers in it.** Each anchor is made on the operator's Mac, with a random role ID. Each provider holds one anchor, has D3's mapping, and a condition naming its own ID unless the variant says otherwise.

| Variant | What it is | Gating |
|---|---|---|
| V1 | Device A, writer-capable: a reader provider and a writer provider, each trust store holding that role's one anchor, each condition pinning that role's ID; each anchor with its leaf. Created by the setup paste | yes |
| V1b | Device B, reader-only: one provider, its reader anchor alone. The other device in the negatives | yes |
| V1c | Device C, writer-capable, created through the console's form: two provider forms. Both its IDs are bound to the reader SA only | no; checks the console path |
| V1x | Google's example extensions verbatim. Created only if V1 is refused in all four chain shapes | no |
| V1y | D2's extensions, with a leaf whose DN differs from its issuer's (the role ID plus a fixed suffix, the condition naming both). Created only if V1 is refused in all four chain shapes | no; is a leaf with its issuer's DN refused? |
| V2 | Reader-only: anchor and leaf on one key | no; halves the key count |
| V3 | Reader-only: one self-signed CA:TRUE certificate (keyCertSign, digitalSignature, clientAuth) as anchor and leaf | no |
| V4 | Reader-only: RSA-2048 anchor and leaf | no; Windows Hello, Azure and fallback 2's key type |
| V5 | OIDC: an uploaded single-key ES256 JWKS, a random `.invalid` issuer, a 10-minute JWT. By the paste only | no; the fallback |
| V6 | Reader-only: an anchor backdated 400 days, valid two years in all | no; does the 390-day rule bind anchors? |
| V7 | Reader-only: a fresh anchor valid five years | no; is it refused at creation? |
| V8 | Reader-only: D2's profile, with the mapping setting `google.subject` to a random per-instance constant, the condition still naming its ID | no; D3's privacy alternative |

- **Two SAs** with no role but the reader's pool viewer. `workloadIdentityUser` is bound on the reader SA for V1's reader ID, and on the writer SA for V1's writer ID. Every other variant's principal is bound on the reader SA alone.
- **Data Access audit logs** for STS and IAM Credentials, in the probe project only, turned off at teardown. *(2026-11-23: M3a's runbook turns on Admin Read, Data Read and Data Write for STS and IAM Credentials, and Admin Read for the IAM API; §11.)* *(2026-11-23, M3a walked: the console's Audit Logs page has no IAM Credentials row, so the IAM API's row took Admin Read, Data Read and Data Write, and P8 still read IAM Credentials' Data Access entries (the runbook's deviation 26).)*

**Projects.**
- **The organization project:** a project in the operator's own organization, by the operator's decision of 2026-11-22. *Proposed:* one fresh scratch project there, approved with M3a (§9, question 1). That organization blocks key upload and not key creation (`docs/runbooks/adr-0023-m2-probe-walk.md:337`). Whether enabling STS or IAM Credentials needs a billing link is [unverified]. If it does, the runbook stops and asks. *(2026-11-23, M3a walked: one fresh scratch project there, approved at G0. With billing disabled, enabling IAM, STS and Resource Manager needed no billing link. P9 read key upload blocked and key creation not.)*
- **The no-organization project:** not run; deferred until most of FarSight is ready. Its row in the Results reads so.
- **No new organization** is created. The operator's organization's effective policies are recorded instead (P9).

**The settle rule.** IAM changes take time to apply, and M3a must not read an early refusal as a failure, or a stale allow as a hole.
- It applies after any IAM change: a provider's creation, update, disable or deletion, and a binding's addition or removal.
- A gating positive is polled with backoff (5, 10, 20, 40 and 60 seconds, then every 60 seconds) for up to 10 minutes from the change [inf: Google's propagation time is not measured here]. The first success ends the wait. A positive still refused at the bound fails.
- A negative is checked at once and again when the same bound has passed since the last IAM change. Accepted at either check, it fails.
- A refusal that a removal should bring (P7) is polled the same way, up to the same bound.
- Each wait is recorded as a delta, never a time. M3b's enrolment retry (D4) takes its bound from these deltas. *(2026-11-23, M3a walked: from their marks, V1's and V1b's providers (the setup), V1c's (the console), I7's two trust-store updates, P6's two renewals and the re-enable each applied by the first try, within 3 s, and a disable or deletion refused new exchanges within 2 s. V2 to V8 give no settle time: six were first tried past the bound, and V5's try is not timed. A new binding's first impersonation was accepted at its first try, at most 3 s and 4 s after the setup mark, for V1's reader and V1b; and after 39 s, 75 s and 78 to 79 s, with no note, for V1's writer, the re-added writer binding and V1c's console grant. A binding's removal applied within 62 s of its mark. A first-try figure bounds the settle time from above, from its mark only. Each mark was taken after its change ended (the runbook's deviations 5 and 29), so the later acceptances, 39 s, 75 s and 78 to 79 s, are lower bounds on the settle time from the change. Every figure is inside the 10-minute bound; M3b's enrolment retry takes its bound from these.)*

**The runbook,** `docs/runbooks/adr-0024-m3a-probe.md`, shaped like `adr-0023-m2-probe-walk.md`. It is written with M3a's build, not in the records commit (D10). *(2026-11-23: written 2026-11-22 to 2026-11-23 with M3a's build, not run. Its Deviations list numbers this design's departures as §11 gives them.)* *(2026-11-23, M3a walked: walked 2026-11-23. Its Results, its verdict and nine deviations found while walking, 24 to 32, are filled in.)*
- **G0, approval and choices (no spend).** The exact object list above, the project, the temporary Data Access change, and the Org Policy API if needed. A billing link stops the walk. Whether the scratch project is kept after teardown is chosen here.
- **P0, setup on the dev Mac (no cloud).**
  - Build the probe once with `go test -c` to a fixed path, with `GOWORK=off GOTOOLCHAIN=go1.27.4 GOPROXY=off GOFLAGS=-mod=vendor` and no `FARCAST_*`.
  - Add firewall rules for that binary: STS's mTLS endpoint, IAM Credentials' two endpoints, and the token-info endpoint, each named by reference to the page that gives it.
  - Make every key in a 0700 scratch directory, deleted at the end.
  - Print the setup blocks and their digests.
- **P1, the setup paste** in Cloud Shell. It prints the project's number.
- **P2, the console form:** V1c, through two provider forms, each with Trust anchors, mapping and condition. Record whether the form offers each field.
- **P3, the positives (gating),** each under the settle rule.
  - T1: V1's reader leaf at the reader provider and its writer leaf at the writer provider each exchange: 200. It is run four ways, before any V1x or V1y: `subject_token` [leaf] or [leaf, anchor], times a TLS chain of [leaf] or [leaf, anchor]. Record which pairs pass, with `issued_token_type` and the lifetime. T1 holds if at least one pair passes for each role; the product sends the simplest pair that passed. V1x and V1y are created only if all four are refused.
  - T2: `generateAccessToken` returns 200 for the reader's federated token on the reader SA, and for the writer's on the writer SA, with both scopes. Token info, by POST: email matches, yes or no; both scopes present.
  - T3: a renewed fresh-key leaf under each V1 anchor returns 200 with no console step.
  - T4: V1's two providers read back through the reader's SA token. Each trust store, mapping and condition equals what the device made.
  - V1b's T1 and T2, for the reader only.
- **P4, the negatives,** each under the settle rule.
  - N1 (gating): a leaf from a CA in no provider, to V1's reader provider: refused.
  - N2 (gating): another device's ID, at V1's reader provider, both refused. (a) A leaf under V1's reader anchor with V1b's ID as its CN: refused by the condition's subject clause; under the issuer mapping it would map to V1's own ID. (b) An intermediate CA under V1's reader anchor with V1b's reader ID as its CN, sent in the TLS chain and in `subject_token`, and a leaf under it with the same CN: refused by the issuer clause, or by path length. Accepted, (b) would let one device act as another.
  - N3 (gating): V1b's leaf to V1's reader provider: refused.
  - N4 (gating): V1b's federated token impersonating the writer SA: 403.
  - N5 (gating): a `subject_token` that is not the handshake's leaf. At V1's reader provider, a handshake with V1's reader leaf and a `subject_token` naming another valid reader leaf under the same anchor, as T3 makes; and at V1's writer provider, a handshake with V1's reader leaf and a `subject_token` naming V1's writer leaf. Both refused.
  - N6 (gating): no client certificate, with V1's writer leaf as the `subject_token`, at V1's writer provider: refused.
  - N7 (information): path length and client-sent intermediates. Two chains under V1's reader anchor, each through an intermediate CA it made, the intermediate sent both in the TLS chain and in `subject_token`: one whose intermediate and leaf carry the reader ID, at the reader provider; and one whose intermediate and leaf carry the writer ID (v2's N11), at the reader provider and at the writer provider. Does Google enforce the anchor's path length 0, and does it build chains through intermediates the client sends? With a provider per role, neither answer lets a reader key act as the writer [ran, against fakes]. If the writer-ID chain is accepted at the reader provider, the condition did not hold, which is N9's failure; at the writer provider, the trust store did not hold, which is N1's. Either gates as that negative does.
  - N8 (information): an expired leaf, and one not yet valid.
  - N9 (gating): across roles on one device. A leaf under V1's reader anchor carrying V1's writer ID as its CN, at the reader provider (the condition's subject clause; under the issuer mapping it would map to the reader's ID) and at the writer provider (the trust store); and each role's own leaf at the other role's provider. All refused. The chain that would let a reader key act as the writer, through an intermediate carrying the writer ID, is N7's gating part.
  - N10 (gating): V1's reader federated token impersonating the writer SA: 403.
- **P5, information.**
  - V1x and V1y if needed; V2, V3, V4, V5, V6, V7 and V8: accepted at creation? An exchange?
  - I1: `generateAccessToken` at IAM Credentials' mTLS endpoint.
  - I2: STS asked for `userinfo.email`.
  - I3: the lifetime for a leaf 20 minutes from its end.
  - I4: the 390-day rule. A leaf under V1's reader anchor valid 430 days in all, backdated 400; and V6.
  - I5: an audience naming the project's ID instead of its number.
  - I6: the mTLS token type sent to STS's plain endpoint.
  - I7: a second anchor added to V1's reader provider's trust store, then removed: accepted? (The page's limit is three; only an overlap renewal would use it.)
  - Any limit hit on providers per pool.
- **P6, renewal.** V1's writer provider's trust store is replaced by a new anchor with a new key and the same writer ID, by the paste, and through the console's edit form. The new writer leaf returns 200, the old writer leaf is refused, the reader, in its own provider, still works, and the grants are unchanged. Not gating: if it fails, D4 falls back.
- **P7, revocation,** under the settle rule.
  - (a) Remove V1's writer binding, then time how long until a live writer federated token's `generateAccessToken` is refused. Re-add it.
  - (b) Disable V1's writer provider. A new exchange must be refused (gating). Time a pre-issued federated token's `generateAccessToken` until it is refused or expires.
  - (c) At teardown, delete V1's providers and repeat (b) for each.
- **P8, the audit reads** in Cloud Shell. Record field names only, with values scrubbed:
  - the Admin Activity entries for the pool's and providers' creation: is the PEM in the request? Is the condition?
  - the Admin Activity `SetIamPolicy` entries for the bindings: is the member, with its role ID, present?
  - STS's and IAM Credentials' Data Access entries: `principalSubject`, the mapped principal, `keyInfo`, whether the leaf's serial, fingerprint or CN appears, and the caller's user agent;
  - whether session control shows any effect (ADR 0023:176).
- **P9, the organization's policies,** as the project sees them:
  - effective `iam.allowedPolicyMemberDomains`;
  - `iam.workloadIdentityPoolProviders` and its managed twin, and, where either is restricted, which value, if any, admits an X.509 provider;
  - any WIF custom constraint [doc: CUS];
  - the two key constraints;
  - whether the organization carries Google's whole secure-by-default set [doc: SBD], each constraint in it recorded as enforced or not. It is recorded, not assumed;
  - the effective `iam.automaticIamGrantsForDefaultServiceAccounts`, which decides whether a new project's default compute account gets the project Editor grant [inf]. M3a enables no Compute Engine API, so there is no default compute account to read. The pre-M3b installer's project-wide actAs reaches that account; D4's actAs rule is built not to rest on it;
  - whether P1's principal bindings were admitted.
- **P10, teardown:**
  - delete the providers, the pool and the SAs, bindings first;
  - turn off Data Access and the Org Policy API;
  - disable the APIs the probe enabled;
  - shut down the scratch project unless G0 kept it;
  - delete the key directory.

  IDs stay reserved for about 30 days, which random IDs absorb.
- **Then:** a Results table, with the no-organization row reading "not run; deferred until most of FarSight is ready", Deviations, and the record: dated notes in ADR 0024 and in ADR 0023's Verification 4.

**The pass rule.** M3a runs in an organization project, so its pass is a pass there.
- **The route passes in an organization project** if the organization admits it (P1's paste and P9) and, in that project: T1 to T4 hold for V1, and T1 and T2 for V1b; every gating negative (N1 to N6, N9, N10, and N7's chain carrying the writer ID) is refused after the settle rule's bound; and the exchange after P7's disable and delete is refused. *(2026-11-23, M3a walked: it passes, in a project in the operator's own organization. The organization admitted every object; T1 to T4 held for V1, and T1 and T2 for V1b; every gating negative and I6 were refused at both checks, the second after the bound, each beside an accepted control; and the writer's new exchange after P7's disable, and each role's after P7's deletion, was refused. No row was INCONCLUSIVE ([the runbook's Results](../runbooks/adr-0024-m3a-probe.md#results)).)*
- **A refusal by a named policy** is not a pass, whatever else held.
- Everything else is recorded and does not gate.

**The outcomes:**
- **Pass, in an organization project:** M3b proceeds on D1 to D7. P9 records the effective policies, and whether that organization carries Google's whole secure-by-default set. The no-organization row reads "not run; deferred until most of FarSight is ready", and the route there stays an inference (ADR 0023:165) until that run. *(2026-11-23, M3a walked: this was the outcome. P9 recorded the policies, and that the organization does not carry the whole secure-by-default set.)*
- **Refused by a named policy:** not a pass, and M3b does not start on it. If the policy is one Google sets by default in new organizations [doc: SBD], the route fails the operator's own rule, no route a provider closes by default, and the operator re-decides. If it is the organization's own, the record names it and what would admit it; FarCast does not ask for it to be relaxed, and the operator decides what comes next.
- **V1 refused in all four shapes, and V1x, V1y, V2 or V3 passes:** that shape becomes the route by a dated note on D2. V3 is Google-only, so AWS keeps the pair.
- **Every X.509 shape refused, not by a policy, and V5 passes:** Google's route becomes V5, "paste the public key" in Cloud Shell, by a dated note in ADR 0024.
- **Any gating negative accepted,** and no shape closes it: **fail**, whatever else passed.
- **Everything refused:** D7's fallback order, and the operator re-decides (ADR 0023's revisit trigger).

**What M3a settles:**
- the anchor shape on Google, and the leaf whose DN equals its issuer's;
- the per-role providers, and whether a trust store takes a second anchor (I7);
- whether STS binds `subject_token` to the handshake, and needs a client certificate;
- whether Google enforces path length and builds chains through client-sent intermediates, for information (N7);
- the per-provider condition, across devices and across roles;
- silent leaf renewal, and anchor replacement;
- the revocation window, and IAM's settle times;
- the 390-day rule's reach;
- whether the audience takes a project's ID, which decides the line back;
- what the operator's organization's policies admit, `iam.workloadIdentityPoolProviders` included, and which of Google's secure-by-default set it carries;
- which IAM Credentials endpoint is needed;
- what the logs carry, the `SetIamPolicy` entries included;
- the console form's fields;
- V5's and V8's viability.

**What it does not settle:**
- the route in a project with no organization (deferred until most of FarSight is ready);
- the DNS endpoint and an impersonated token, and the Kubernetes username (W-FED or M3b's walk); *(2026-11-24, ADR 0023's M2 walked: W-FED settled both on 2026-11-24.)*
- the delegation entries of Artifact Registry and Cloud Storage (M3b's walk);
- the reader's resource-scoped read grants (M3b's build and walk);
- the Secure Enclave TLS identity (M5);
- Cloud console sign-in in an embedded web view (its own no-cost check);
- AWS and Azure (their adapters' probes);
- limits beyond what P5 meets.

**Cost:** USD 0. IAM is offered at no charge [doc: PRICE]. STS and impersonation are unpriced [inf]. A session's Data Access entries fit inside Cloud Logging's free ingestion [inf].

**Approval:** needed before anything is created (ADR 0023:279), in the session that walks it. Deleted IDs stay reserved for 30 days, so it is a hard-to-reverse step under the ask-first rule.

**Effort:** 3 to 4 days to build `devicekey`, `kube/federated.go`, the walk file with V5's signer and the W-FED mode, the runbook and W-FED's steps, all offline with `./check.sh` green. Then one 3 to 4 hour session, the settle waits included.

---

## 7. M3b's revised scope

**Built** after M3a passes. The build may overlap M2's walk.
- **The certificate route on Google for the installer and writer as well as the reader.** `install --name $INSTANCE` takes no `--credentials` (D7): keys, show, paste, line back, verify, install. The pending directory makes `install` resumable at the paste, with no compatibility work, since no instance persists.
- **Pending installs:** listed by `instances` with state and age, a warning from every command after 7 days, and `install --abandon` (D7).
- **Two roles per device:** the reader pair, and the writer pair on a writer-capable device, each role with its own provider, with D2's custody rules in `devicekey`.
- **`farcast device add`, `ls`, `rm`, `renew` and `coordinates`, and the proposed `device known`** (D4), including adding and removing the writer role and its provider. The read-back in every enrolment. `world` marks unknown providers.
- **Random IDs,** a pool and three SAs per instance, and `release`'s teardown block.
- **The setup-block generator,** with its digest, its readerinit-style shell, its neutral tags, its random condition title, one provider per role, each trust store in Google's YAML form, the dedicated node account, the two Workload Identity counts, and the writer's tested role allowlist, `roles/iam.serviceAccountUser` never at the project level among its checks (D4's actAs rule); and the console guide's text.
- **The dedicated node account in planck** (D4): `buildCluster` names it as the nodes' account, `grantPull` and the instance's metadata name it in place of the default compute account (`nodeServiceAccountFmt`, `registry.go:63-68`), and a test checks that the create request names it.
- **D6's wiring:** the federated `kube.Credential`, and the token providers for `planck` and `datasphere`. The `creds.ServiceAccountKey` callers move: `fatline.go:168`, `release.go:143`, `storage/storage.go:98`, and `storagedeploy.go:140`, through `storage.OpenBucketGrants` (`storage/storage.go:238`); and `clusterref.go:159`, with its check at `:193`, the writer's cluster credential, which the federated `kube.Credential` replaces.
- **The installer-minted reads** (D5), each decided in this build: the reader's resource-scoped read grants, applied by the writer as consented acts when it creates or re-ensures the repository and the bucket; `projects.get` replaced by the recorded project number.
- **Fallbacks 2 and 3** behind their flags and plan facts. `reader init` and `reader record` become fallback 2, and `reader init`'s policy message (`readerinit.go:404`, `:409`), which says an organization administrator must allow upload, is reworded to name the policy and the routes still open. Fallback 1, with one provider per role, if M3a recorded V5 passing. *(2026-11-23, M3a walked: M3a recorded V5 passing, in a project in the operator's own organization, so this condition is met.)*
- **ADC out of the CLI.** `GOOGLE_API_CERTIFICATE_CONFIG` is unset.
- **The `instances` and `world` documents** gain the identity route, the roles and pending installs, and the Swift app's documents follow in lockstep.
- **Tests against fakes.** Mutation rows, each shown to fail with its defect restored:
  - a bearer sent to a host other than IAM Credentials';
  - the client certificate presented to a host other than STS's (and IAM Credentials' mTLS host, only if M3a's I1 required it);
  - the environment proxy honoured;
  - a URL taken from input or a file;
  - a read command or a plan that opens a writer key, exchanges the writer leaf, or impersonates the writer;
  - a reader leaf renewed with the writer anchor key, or a writer leaf renewed outside a consented command or `device renew`;
  - a writer key opened under any purpose but a consented write, a renewal or an enrolment;
  - a role ID derived from a key, a name or a counter, or changed by an anchor renewal;
  - one of the installer-minted reads presenting a writer token;
  - a response body in an error;
  - a provider accepted by the read-back whose trust store holds other than its role's one anchor, or whose condition names other than its role's one ID;
  - a setup block that puts two anchors in one provider, or names two IDs in one condition;
  - a trust-store file that does not parse as Google's YAML trust store with exactly one anchor and no intermediate, or whose parsed `pemCertificate` does not decode to the anchor's DER, byte for byte;
  - a Workload Identity count that misses either member form, a basic or custom role carrying a counted permission, or a binding on one of the project's accounts or on the project; or a count other than 0 that does not stop the block, at a no, before it creates anything;
  - a cluster create request that does not name the dedicated node account;
  - a teardown block, `install --abandon`'s, `release`'s or `device rm`'s, that stops at an absent object, run against a fake with each prefix of the setup applied, then again after each prefix of itself, with the pool and providers it deleted left in the state `DELETED`;
  - `device rm` printing, for a provider this machine did not make, a binding removal not taken from that provider's condition, or erasing this machine's keys for a provider it did not make;
  - a pending install not listed by `instances`, or listed without its state or age; a warning before 7 days, or none after; `install --abandon` printing other than the teardown of exactly what the setup creates, leaving a pending key, refusing a pending install, or acting on a finished record;
  - an `install` that makes a key, or shows a block, for a name already recorded or already pending; or that calls `CreateCluster` before the record holds the keys and the coordinates;
  - a setup block containing `farcast` outside the storage condition's prefix, or the instance's name.

**M3b's walk,** after M2's walk:
- a fresh install from the paste, with no service-account key on the machine, in a project in the operator's own organization, which M3a's pass covers;
- the reader end to end, which M2's walk under [B] does not walk;
- the DNS endpoint, unless W-FED settled it; *(2026-11-24, ADR 0023's M2 walked: W-FED settled it on 2026-11-24.)*
- the reader's resource-scoped reads, and the writer's consented acts that grant them;
- revocation timing on a live instance;
- one Artifact Registry and one Cloud Storage Admin Activity entry made through the identity, read back, recording what they name. That decides V8 (D3).

**Effort:** 3 to 4 weeks [inf], up from ADR 0023's 2 to 3, because the writer, the second role, the reader's grants and the planck and datasphere plumbing join it.

---

## 8. The Phasing changes

ADR 0023's table keeps its rows. Each changed cell gets §4's dated note. ADR 0024 restates the order as a table of its own:

| # | Milestone | Cloud | Effort |
|---|---|---|---|
| **M3a** | The X.509 probe (§6) and the offline `devicekey` and `kube/federated.go`. Brought forward 2026-11-22, before M2's walk. A project in the operator's own organization (accepted 2026-11-22); one fresh scratch project there (proposed); the run in a project with no organization is deferred until most of FarSight is ready. Its runbook, `docs/runbooks/adr-0024-m3a-probe.md`, and W-FED's steps, appended to M2's walk runbook, are written with its build, not in the records commit *(2026-11-23: built 2026-11-22 to 2026-11-23, not walked; §11)* *(2026-11-23, M3a walked: walked 2026-11-23 at bb51a6d; it passes in an organization project)* | Free IAM objects; approval needed | 3–4 days, plus one session |
| **M2's walk** | On its own, after M3a, before M3b (accepted 2026-11-22). G0a: [B], in a project in the operator's own organization; the installer's Google-made key is an exception the operator approves, time-boxed and deleted at teardown; the reader is not walked. [U1] withdrawn; [U2] deferred with a project with no organization. Optional W-FED, with its own approval, if M3a passed in the organization project *(2026-11-24, ADR 0023's M2 walked: walked 2026-11-24 at 3fd79c4 under [B], W-FED included; the installer's key deleted at teardown; the reader not walked)* | Billable; approval needed | as its runbook |
| **M3b** | §7. Built after M3a passes, walked after M2's walk. If M2's walk has not run when M3b's build is done, the operator decides again (proposed) *(2026-11-24, ADR 0023's M2 walked: M2's walk ran 2026-11-24, before M3b's build started, so the trigger cannot arise)* | Billable walk; approval needed | 3–4 weeks [inf] |
| **M5** | As ADR 0023, plus a Secure Enclave TLS client identity for each role's leaf, for STS. On failure, the Mac app takes V5 on Google if M3a recorded it passing, or else 0600 keys, as the operator decides then *(2026-11-23, M3a walked: M3a recorded V5 passing, in an organization project)* | Billable walk | unchanged |
| **GUI install** | Before it is built: a no-cost check of Cloud console sign-in in an embedded web view. On refusal, the console surface is the system browser beside the app | None | under an hour [inf] |
| **M3a, no organization** | Deferred until most of FarSight is ready: M3a's run in a project with no organization, and with it M2's [U2] if the operator wants it then | Free IAM objects; approval needed | one session |
| **AWS adapter** | Not scheduled. ADR 0024's AWS probes: P-256 `CreateSession` under a pasted anchor; a Secure Enclave signature; one key or two per role; the CloudTrail fields; a new-sign-up account's refusal | Free objects; approval | — |
| **Azure adapter** | Not scheduled. ADR 0024's Azure probes: PS256 versus RS256; an EC certificate refused; the sign-in log fields; an AKS token | Free objects; approval | — |

---

## 9. Questions for the operator

Each answered question says so, with the answer. Each open one has the default this design follows until it is answered.

1. **Approve M3a** as §6 lists it: the objects, the project, Data Access for STS and IAM Credentials in the probe project for the session only, and the Org Policy API if needed. Its project's organization is answered (question 3); which project there is approved here. *Default:* approve exactly that list, in the session that walks it, with one fresh scratch project in the operator's own organization. *(2026-11-23: M3a's runbook asks G0 for more than this list: Admin Read on the IAM API besides Data Access for STS and IAM Credentials, and the deviations G0 accepts, among them I6 gating as N6 under Q1's default, proposed (its deviation 9; §11).)* *(2026-11-23, M3a walked: approved at G0 on 2026-11-23 with that default, and walked that day.)*
2. **D9, the order.** *Answered 2026-11-22:* M2's walk runs on its own after M3a, then M3b (branch S). There is no merged walk. *Default,* as a revisit trigger: if M2's walk has not run when M3b's build is done, the operator decides again. *(2026-11-24, ADR 0023's M2 walked: M2's walk ran 2026-11-24, before M3b's build started, so the trigger cannot arise.)*
3. **A project with no organization.** *Answered 2026-11-22:* M3a and M2's walk use a project in the operator's own organization. A project with no organization comes later, when most of FarSight is ready. So M2's walk takes [B]: key upload is blocked there, the installer's Google-made key is an exception to ADR 0024 that the operator approves at the walk's G0a, time-boxed and deleted at teardown, and the reader is not walked in M2.
4. **ADR 0023 Choices 5,** human-only enrolment. *Answered 2026-11-22:* human only. Every device addition, renewal and revocation is a human's paste, and no FarCast identity can enrol devices. *Still proposed, for you to confirm:* that the renewal here is a device's anchor renewal, so a leaf renews on the device with no paste (D4).
5. **Two roles per writer-capable device,** at the cost of four keys (two Secure Enclave pairs at M5) and two providers. *Default:* yes, with one provider per role, so that reads never hold a key that can write and the split does not rest on Google enforcing path length. V2 is measured; if Google accepts it, a dated note may halve the key count.
6. **The anchor's life.** *Default:* 390 days, warned from 45 days ahead, and renewed by one paste that keeps the role IDs and grants. Up to two years only if M3a shows the rule binds leaves alone, and you choose it.
7. **The guided default** for a non-technical person. *Default:* the Cloud Shell block, with the console form beside it. *Alternative:* the block for the instance and the console form for each further device.
8. **A newly added device's role.** *Default:* reader only, unless writer is chosen in its paste.
9. **The installer-minted reads at M3b** (plans' registry and IAM-policy reads, `projects.get`, `storage ls`, `storage usage`, `storage cp`'s downloads, `secret ls`). *Default:* the reader, with read-only grants on the instance's own repository and bucket applied by the writer as consented acts, and `projects.get` replaced by the recorded number. The reader then reaches ciphertext, and the instance's images, which are not encrypted: FarCast's own components and the operator's application images. *Alternative:* the writer, after consent, which puts writer tokens into plans. *(2026-11-26, M3b.1: answered with its default, before M3b.1; built at M3b.11 ([the M3b plan](adr-0024-m3b-plan.md)).)*
10. **The console surface,** if Google refuses sign-in in an embedded web view. *Default:* the system browser beside the app, checked at no cost before the GUI install flow is built.
11. **Pending installs.** *Default:* listed by `instances` with state and age; every command warns after 7 days; `install --abandon` prints the teardown block and erases the keys; nothing is erased by age alone.
12. **A per-device subject, or V8's constant per role,** if M3b's walk finds the role ID in Artifact Registry or Cloud Storage delegation entries and V8 passed. *Default:* per-device, revisited at that walk.
13. **Neutralise the marks** as a separate item: cluster names; the repository prefix and labels; the `farcast-` bucket prefix that the writer's storage condition names, where a random per-instance bucket prefix is the candidate (a planck and datasphere naming change); the installer's and reader's names; the user agent and field manager; the identical digests; and the anchor profile's traits (D11). `registry.go:44-47` chose recognisability on purpose. *Default:* open the item and decide it before M3b's walk. Nothing persists yet, so now is the cheapest time.
14. **The user agent on the identity path.** *Default:* `kube.UserAgent`, revisited with question 13. *Alternative:* no product name there.
15. **Hand-roll the exchange,** departing from ADR 0007 decision 2, or vendor the public external-account package, with its Go-version header, its caches and its body-bearing errors? *Default:* hand-roll, with the departure recorded in ADR 0024.
16. **The installer and writer on the certificate route.** *Answered 2026-11-22 by the procedure and the fallback rule:* the installer and writer use the certificate route, and a Google-made key is only fallback 3, where the certificate route is closed. Still proposed: that this lands at M3b, and fallback 3's flag and plan fact. *Default:* at M3b.
17. **ADR 0023 Choices 1 (b),** the operator-registered OAuth client with a refresh token at rest. *Default:* not planned, recorded as considered. Revisit only if the app is ever to create projects or link billing.
18. **AWS accounts from "Sign up for AWS (new)".** *Default:* never ask for the irreversible activation that removes the spend limit; use the consented IAM user access key fallback there.
19. **Azure.** *Default:* a software RSA-2048 certificate per role (0600, never the Secure Enclave), re-pasted at each renewal; a client secret only where tenant policy blocks certificates; federated credentials rejected.
20. **AWS and Azure probes.** *Default:* deferred to their adapters, with no accounts or tenants made now.
21. **M5, if a Secure Enclave key cannot form a TLS identity** without a keychain item and access-group entitlement. *Default:* decide at M5, leaning to a keychain-formed identity as ADR 0020's keeper does. ADR 0023:198's no-keychain premise is reopened now. V5 for the Mac on Google only if M3a recorded it passing. *(2026-11-23, M3a walked: M3a recorded V5 passing, in a project in the operator's own organization.)*
22. **The records:** ADR 0024, the dated notes, the summaries rewritten in place, this design as `docs/design/adr-0024-design.md`, the M2 design's §41, and the M2 walk runbook's notes on its Status line, what is left to choose at G0a, deviation 10, T6's stops, G0a's branch, project and optional steps, WP.8, G0b's no, G0b's list and teardown, W6.2, W6.8, and the Results rows of WP.8 and W6.2, in one commit made only when you ask. M3a's runbook and W-FED's steps come with M3a's build. *Default:* yes.
23. **M2's walk under [B]: the key and W-FED.** The exception itself is answered (question 3): the walk's key is time-boxed to the walk and deleted at teardown. If WP.8 counts 1 key, the installer holds no user-managed key after W6.2. Which key, the deletion's steps, and W-FED are asked at the walk's G0a. *Default:* the walk uses the installer's existing key if you hold one, or one made at WP.8; you delete it in Google and on the Mac after W6.1's release, at W6.2. W-FED is offered if M3a passed in the organization project, with its own approval and `roles/container.viewer` for the reader SA for that step only. *(2026-11-24, ADR 0023's M2 walked: answered at G0a on 2026-11-23, as the default: the existing key, deleted in Google and on the Mac at W6.2; W-FED approved, with `roles/container.viewer` for the reader SA for that step only.)*
24. **`--yes` and the writer keys on the CLI.** *Default:* on the CLI, `--yes` counts as consent to open the writer keys wherever a command accepts `--yes` today, so a scripted run can still write. It never covers what ADR 0023 already keeps from `--yes`, and never selects fallback 3 (D7). On the Mac, the broker keeps ADR 0023:116's `--confirm` alone. *(2026-11-26, M3b.1: answered with its default, before M3b.1: `ConsentYes`, a consent kind of its own, built in `devicekey` (§12) and wired at M3b.8.)*

---

## 10. Risks

- **Google may refuse a detail of the profile,** such as a leaf without keyEncipherment, a device-made CA with path length 0, or a leaf whose DN equals its issuer's. M3a's four chain shapes, V1x, V1y and V2 or V3 catch it before any product use. *(2026-11-23, M3a walked: it refused none: T1 accepted D2's profile in all four shapes for both roles, so V1x and V1y were not made, and V2 and V3 were accepted too.)*
- **STS may not bind `subject_token` to the handshake.** Then anyone who has seen a leaf, which is sent on every exchange and may be logged, could exchange it. N5 and N6 are gating. *(2026-11-23, M3a walked: it does: N5 (i) and (ii) were refused 400 invalid_grant at both checks, and N6 and I6 held.)*
- **GKE's DNS endpoint may refuse an impersonated token,** or map it to a username the reader's RoleBindings do not name. Only a cluster settles it. W-FED is the earliest place to learn it. The fallback would be direct grants, which change RBAC subjects and the logs. *(2026-11-24, ADR 0023's M2 walked: W-FED found neither: the endpoint accepted the impersonated token, and the username was the SA's email.)*
- **The route is proven, if M3a passes, in an organization project only.** In a project with no organization it stays an inference (ADR 0023:165) until the deferred run, and a FarCast operator without an organization meets it first. *(2026-11-23, M3a walked: M3a passed in an organization project on 2026-11-23; the run in a project with no organization stays deferred.)*
- **A Google default may close the route.** If the operator's organization refuses it by a policy Google sets by default in new organizations, the route fails the operator's own rule, and the operator re-decides. P9 records which defaults the organization carries, so a pass there is read against them.
- **The Mac.** Go's `crypto/tls` asks a signer to sign a digest, and Apple DTS advised against `SecIdentityCreate`. A Secure Enclave TLS identity may need the keychain and an entitlement (ADR 0023:198 reopened). Letting the Go helper drive the handshake through a remote signer would break the broker's rule, because the broker could not tell what it signs [inf], so it is not a candidate.
- **Google may refuse Google Account sign-in in an embedded web view** [doc: WV-2020, WV-2021, WV-HELP]. If the Cloud console's sign-in fails in a macOS WKWebView, the install vision's first surface cannot host Google's console or Cloud Shell, and the system browser takes its place.
- **Revocation may leave about two hours,** not one. The binding is removed first, and M3a measures the window. *(2026-11-23, M3a walked: P7 measured it: federated tokens issued before a provider's disable or deletion impersonated until they expired, 59 and 58 min after the mark, and removing the binding stopped one within 62 s.)*
- **IAM's settle time may exceed the rule's bound,** making M3a inconclusive. The deltas are recorded, and a bound that is too short shows as late successes, not as a pass or a hole.
- **Organizations can close the route,** by custom constraints on trust anchors (since 2026-04-07), by `iam.workloadIdentityPoolProviders` (which value admits X.509 is [unverified]), or by `allowedPolicyMemberDomains` [doc: DRS]. Their operators land on fallbacks, some of which are secrets.
- **Phishing.** The procedure teaches pasting blocks into an Owner shell, and an attacker's block would trust the attacker's CA. The read-back and `device ls` reduce this and do not remove it; a digest or an ID a block prints proves nothing.
- **A stolen 0600 writer anchor key** (CLI, terminal, Linux, Windows) mints writer tokens for that instance until a human deletes the writer's provider, or for up to 390 days. A stolen reader key reaches the reader's reads, which from M3b include the instance's ciphertext.
- **Four keys and two providers per writer-capable device** add files, Secure Enclave keys, console forms and renewals.
- **Limits on providers per pool and pools per project** are undocumented [doc: QUOTA]. One provider per role per device per instance meets such a limit up to twice as soon as one provider per device would.
- **M2's walk keeps one Google-made key** for its duration, an approved exception. Its deletion at teardown is a human step (W6.2's note, G0b's for a no, and T6's for any other stop that ends the walk); a walk that stops early must still reach it. *(2026-11-24, ADR 0023's M2 walked: the walk reached it: the key was deleted in Google and on the Mac at W6.2, and the count was then 0.)*
- **The reader is not walked in M2.** A22-7's reader evidence stays open until M3b's walk, except the federated reader's cluster reads if W-FED runs. *(2026-11-24, ADR 0023's M2 walked: W-FED ran, and its cluster reads passed; A22-7's evidence for farcast's own reader stays open until M3b's walk.)*
- **The per-device, per-role pseudonyms** in Admin Activity, Data Access and delegation entries are new metadata (D11).
- **Hand-rolled exchange code** on the credential path may drift from Google's protocol, and only a FarCast release fixes it.
- **Yearly anchor pastes** per device per instance are friction. A missed one locks the device out while the instance bills under its in-cluster limit.
- **Google's console changes without notice,** which breaks the guided console steps. The Cloud Shell block is more stable.
- **M3b grows to 3 to 4 weeks,** which delays FarSight, sequenced ahead of AllThing.
- **The evidence offline is the client mechanics only** (`proto/`, `variantb/`, `twoanchor/`, against loopback fakes, none kept) [ran]. Every Google, AWS and Azure behaviour here is documented or inferred, not observed. *(2026-11-23, M3a walked: M3a observed STS's, IAM Credentials' and IAM's behaviours on 2026-11-23, in an organization project, as the runbook's Results record them; the DNS endpoint's, AWS's and Azure's stay documented or inferred.)* *(2026-11-24, ADR 0023's M2 walked: the DNS endpoint's answers to an impersonated token and to a federated one were observed in W-FED on 2026-11-24.)*

---

## Not settled here

- Whether a Google trust store can be replaced in place (M3a, P6), or renewal becomes add-plus-revoke. *(2026-11-23, M3a walked: it can be: P6 replaced it by the paste and in the console, and both committed.)*
- Whether a trust store takes a second anchor (M3a, I7), which only an overlap renewal would use. *(2026-11-23, M3a walked: it does: I7's second anchor's leaf was accepted beside V1's reader leaf.)*
- Whether Google enforces a CA's path length in X.509 federation, and builds chains through client-sent intermediates (M3a, N7). With a provider per role it is information only. *(2026-11-23, M3a walked: N7 (i) was accepted, so Google builds chains through client-sent intermediates and does not enforce path length [inf].)*
- The exact console wording of each field, which M3a's P2 records once and the guide follows. *(2026-11-23, M3a walked: P2 recorded the form's fields and their labels, in the runbook's Results.)*
- The coordinates line's encoding. It holds up to eight non-secret values: the project's ID and number, the pool's ID, the device's one or two provider IDs, and the three SAs' IDs. Its format and its documents' schema are decided in M3b's build, with the Swift vectors.
- The smallest role for each of the reader's resource-scoped reads (M3b's build).
- How the first plan that grants the reader a resource read makes its own lookups (M3b's build, D5).
- The enrolment retry's bound, taken from M3a's settle deltas. *(2026-11-23, M3a walked: the deltas are recorded: §6's settle rule and the runbook's Results.)*
- Where ADR 0024's AWS and Azure probes run, decided when their adapters start.
- Whether Data Access in the operator's organization is forced on by a parent, recorded at M3a's P9.
- The route in a project with no organization: M3a's run there, and M2's [U2], deferred until most of FarSight is ready.
- W-FED's exact steps, and whether `roles/container.viewer` is the smallest role for its three reads, written with M3a's build. *(2026-11-23: W-FED's steps are written, appended to M2's walk runbook with M3a's build, and have not run. That `roles/container.viewer` is the smallest role for the three reads stays [unverified], as its WF.3 says: W-FED's run would show whether the role is enough, not whether it is the smallest.)* *(2026-11-24, ADR 0023's M2 walked: W-FED ran 2026-11-24. The role was enough for the three reads; that it is the smallest stays [unverified].)*
- M2's walk's key under [B]: the existing key or one made at WP.8 (§9, question 23, at the walk's G0a). Its deletion at teardown is the operator's decision, not open. *(2026-11-24, ADR 0023's M2 walked: G0a chose the existing key, and it was deleted at W6.2.)*

---

## 11. M3a's build (2026-11-22 to 2026-11-23)

M3a was built 2026-11-22 to 2026-11-23, on 2b7f461, from a build spec that took this design's D2 to D7, D9's W-FED and §6. The spec, its critique and the review rounds' reports were working files in a scratch directory, and are not kept. Nothing had been committed when this section was written. Nothing has run against Google, and the probe has never run. Deviation numbers here are the M3a runbook's. *(2026-11-23, M3a walked: the probe ran against Google on 2026-11-23, at bb51a6d, and M3a passes in a project in the operator's own organization ([the runbook's Results](../runbooks/adr-0024-m3a-probe.md#results)). Still not settled: the DNS endpoint with an impersonated token, and the run in a project with no organization, which stays deferred.)* *(2026-11-24, ADR 0023's M2 walked: W-FED settled the DNS endpoint with an impersonated token on 2026-11-24, in an organization project.)*

### What landed

- **`farsight/cli/internal/devicekey/`**, new, with its tests and two conformance vectors in `testdata/`: random role IDs and object IDs, D2's profile, the signers, the store (0600 files in 0700 directories), one opening function per role and purpose, and Google's text (the mapping, the condition, the principal, the trust store's YAML and the read-back's check).
- **`farsight/cli/internal/kube/federated.go`**, new, with `federated_test.go` and `federated_wire_test.go`: STS's mTLS exchange and `generateAccessToken`. `kube/export_test.go` gains test hooks, and `kube/doc.go` one sentence.
- **`farsight/cli/internal/kube/kubetest/federation.go`**, new, with `federation_test.go`: a loopback STS that requires and verifies a client certificate, and an IAM Credentials fake.
- **The probe,** `farsight/cli/internal/cli/walkm3a_test.go` (`//go:build walk`), which compiles and has never run, and its two untagged companions, `walkm3ablocks_test.go` and `walkm3achains_test.go`, whose tests run offline. *(2026-11-23, M3a walked: it ran 2026-11-23.)*
- **The runbooks:** `docs/runbooks/adr-0024-m3a-probe.md`, new, and W-FED, appended after line 733 of `docs/runbooks/adr-0023-m2-walk.md`. Neither has run. *(2026-11-23, M3a walked: M3a's runbook was walked 2026-11-23; W-FED has not run.)* *(2026-11-24, ADR 0023's M2 walked: W-FED ran 2026-11-24.)*
- **Wired into nothing.** No command calls the new code. Only tests and the probe import `devicekey`, and `farcast` does not link it (`go list -deps`). `vendor/` stays at 31 modules. `exec-allowlist.txt`, `errorKinds` and `hardenEnvironment` are unchanged, and no new file names an exec function.

### The five open questions, each at its default

The operator has not answered them. The build took each default, which stays proposed until the operator answers. *(2026-11-23, M3a walked: G0 accepted deviation 9, Q1's default, for the walk on 2026-11-23, which ran under it. No answer to Q2 to Q5 is recorded; they stay at their defaults.)* *(2026-11-26, M3b.1: the operator answered Q3 with its default before M3b.1; Q2, Q4 and Q5 stay at theirs.)*
- **Q1, I6 accepted:** I6 gates as N6 does, so an acceptance at I6 fails M3a (deviation 9).
- **Q2, token info:** by POST only, with the token in the body. Any status but 200 reads "not answered by POST", and T2 then holds on `generateAccessToken`'s 200 alone.
- **Q3, the read-back's host:** T4's read-back at IAM's API host is the probe's own (deviation 1). Default: IAM's API host becomes the read-back's one further bearer host, for the reader's SA token only, by a dated note on D6 when M3b builds it. *(2026-11-26, M3b.1: answered with its default before M3b.1; D6's note comes with M3b.3 ([the M3b plan](adr-0024-m3b-plan.md)).)*
- **Q4, the TLS floor:** 1.3 wherever a client certificate is carried, that is the exchange and the probe's I1 client; 1.2 for impersonation (deviation 10). If T1 meets a protocol-version alert, the walk stops and the operator decides.
- **Q5, the records:** in this build, made last, as dated notes and in-place rewrites only. They were made before `./check.sh` ran as a whole, where the default puts them after it passes; it then passed on the tree they describe, and no check reads a record.

### Departures from this design

By the number the M3a runbook's Deviations list gives each:
1. T4's read-back sends the reader's SA token to IAM's API host, from the probe; D6's bearer rule holds in `federated.go`.
2. I1, I6 and V5's exchange are probe-only paths, built with the product's body builders.
3. The firewall has six destinations, not four: STS's plain endpoint (V5, I6) and IAM's API host (T4) join.
4. P7 (c) deletes V1's providers while their bindings stand; P10 (b) removes the bindings after.
5. Each settle delta runs from a named mark taken after a paste, so it is a lower bound on Google's settle time.
6. P7's held tokens wait for a mark, read by a background probe, not for stdin.
7. W-FED runs a probe binary in M2's walk, under its own approval and firewall rules.
8. P7 (b) re-enables V1's writer provider, so that P7 (c) can hold a writer token.
9. I6 gates as N6 does (Q1), checked twice beside V5's exchange as its control.
10. The exchange's TLS floor is 1.3 (Q4); impersonation keeps 1.2.
11. Every gating negative, and every gating poll for a refusal, carries a positive control; only a decision is a refusal, and `INCONCLUSIVE` gates.
12. P7's information timings run to the held token's end, not to the 10-minute bound: up to about 2.5 hours more.
13. An anchor renewal is staged, and committed only after its verification exchange; `renew-discard` drops one Google did not take.
14. I4 runs twice: as designed, and nested inside V6's backdated anchor.
15. `blocks` runs twice, because `console-v1c.txt`'s principals name the project's number.
16. The steps that make a leaf record it in the probe's state, for `audit.sh`.
17. P9 reads the secure-by-default baseline's seven constraints, the legacy protocol-forwarding one, and the managed and non-managed twins of the IAM, key and contact constraints.
18. `audit.sh`'s key-path scrub also replaces any field name of 20 or more characters.
19. `wfed-gone` has no positive control, and polls the two exchanges only, in one loop.
20. P3 runs straight after P1's mark, before Data Access and P2.
21. The teardown leaves on an API Google will not disable without `--force`, and keeps its record for the operator.
22. `t1` also polls V1b and each role's first impersonation, in one round-robin from the setup mark.
23. `setup.sh` and `wfed-setup.sh` print the coordinates only when every grant and binding was added.

The code's own departures, which the runbook does not number:
- the anchor's subject key identifier is set explicitly, to the bytes Go adds by default, so no `GODEBUG` setting can change it (D2: "the subject key identifier Go adds");
- `kube.ExchangeRequest` carries M3a's knobs in product code: a separate subject chain, no certificate, and other scopes. M3b may narrow it;
- the exchange is HTTP/1.1, on a fresh transport per call, with no session resumed. That STS takes HTTP/1.1 is [inf]; *(2026-11-23, M3a walked: the runbook's Results do not state the HTTP version, so this stays [inf], though STS's mTLS endpoint accepted every exchange the walk expected to pass.)*
- kubetest's STS and IAM Credentials fakes came with M3a; D6 placed them in M3b's wiring;
- `devicekey` takes a directory, and reads the role ID from the anchor's CN. The `identity/` directory and the instance's record are M3b's wiring;
- object IDs have fixed lengths, 32 for pools and providers and 30 for accounts: one more trait of a FarCast project, for D11;
- Data Access is changed in the console, not by a block, which would rewrite the project's whole IAM policy.

### What the review rounds changed in D2, D6 and §6

- **A staged writer leaf needs consent.** `OpenStaged(Writer)` takes a consent, as D2's custody rule asks of the current writer leaf.
- **Secrets two pointers deep.** `kube.ClientIdentity`, `ExchangeRequest` and `ExchangeAnswer` hold their contents two pointers deep, as `devicekey.RoleID` and `Identity` do, so they format as fixed text even inside another struct's unexported field.
- **Erase and RemoveRole** refuse a symlink or a non-directory, but not a widened mode, so a widened store can still be removed.
- **FederationError's alert words.** It carries a TLS alert's words when they are in shape, and nothing else of the server's.
- **An alert while an answer is read** is no refusal. It reads as unreachable, with no status.
- **A 3xx with an unparsable Location** is the answer itself: the header is dropped, so no server text reaches the error.
- **An answer Go cannot parse** names nothing. kube keeps words only from a short list of Go's own network errors, and otherwise reads "no readable answer".
- **The probe's refusal rule.** Only a 400, 401 or 403, or a certificate alert that ends the exchange's handshake, is a refusal. Anything else, `handshake_failure` and `decrypt_error` included, is no decision and reads `INCONCLUSIVE`.
- **INCONCLUSIVE positives.** A gating positive whose last answer was no decision reads `INCONCLUSIVE`, and gates until it is rerun.
- **T2's token info.** When token info answers 200, it must list both scopes, or T2 fails.
- **The P1 to P3 order.** `t1` runs straight after the setup mark, in one round-robin with V1b and the first impersonations (deviations 20 and 22). Every positive's line says whether its delta can be read as a settle time.
- **Data Access sub-types.** Admin Read, Data Read and Data Write for STS and IAM Credentials, and Admin Read for the IAM API, which Google's audit-logging page for workload identity federation asks for. P0.7 records the baseline, and P10 (c) restores it. *(2026-11-23, M3a walked: the console's Audit Logs page has no IAM Credentials row, so the IAM API's row took Admin Read, Data Read and Data Write, and P8 still read IAM Credentials' Data Access entries (the runbook's deviation 26); P10 (c) turned all six off.)*
- **The teardown keeps what Google will not disable.** Each API is tried once without `--force`. What stays on stays in the record, and the operator decides.

### What stays open

- **The macOS ACL limit** (round 2's X2). `devicekey` and the probe check mode bits only, and an inherited ACL can let another account read a 0600 key. Reading an ACL needs libSystem's ACL API, against `devicekey`'s rule of no platform-only call. The limit is documented in the package and on `Store`, and both runbooks check for an ACL with `ls -led` (P0.2, WF.1). Where M3b places the store needs the same check, or a decision to enforce it. *(2026-11-26, M3b.1: answered with its default, the M3b plan's X2: the store under the 0700 config root, mode bits only, `ls -led` checked at the walk, and a darwin-only check added only if M3b.2's spike shows that a raw `getattrlist` reports an ACL.)* *(2026-11-26, M3b.2: it does, on the dev Mac (§13). A shipped check would cost a raw system call Apple does not support [inf] and FarCast's first `unsafe` import outside a test; X2's enforcement is decided before M3b.14.)*
- **The read-back's host** (Q3), at M3b. *(2026-11-26, M3b.1: answered with its default before M3b.1; built at M3b.3.)*
- **Q1, Q2, Q4 and Q5,** until the operator answers.
- **`handshake_failure` and `decrypt_error`.** A row they leave `INCONCLUSIVE` is the operator's call (P4).
- **`--yes` as writer consent** (ADR 0024 *Choices* 24). `devicekey` has no consent kind for it until that is answered. *(2026-11-26, M3b.1: answered with its default before M3b.1; M3b.1 built `ConsentYes` (§12), and M3b.8 wires it.)*
- Round 3 deferred nothing.

### How it was checked

- **The spec.** A critique of its first version found 1 blocker, 13 major and 22 minor findings. Each was checked against the repository, go1.27.4's source or a public page, then applied, applied in part or refuted.
- **Round 1:** three reviews (security, correctness, tests) reported 11 findings, 4 major and 7 minor, two of them the same defect. Each held when checked against the code and go1.27.4's source, and each was fixed.
- **Mutation testing,** after round 1, one record per area. Each mutation was applied to a copy only, and compiled in with `-overlay`:
  - `devicekey`: 55 rows, 74 mutants. 52 rows were killed at once, 2 after a test was strengthened, and 1 is equivalent;
  - `kube` and kubetest: 46 rows, 58 mutants. 44 were killed at once and 2 after a test was strengthened; none is equivalent;
  - the probe's companions: 36 rows, 37 mutants. 30 mutants (29 rows) were killed at once and 5 after a test was strengthened. 2 reached only the walk-tagged file; round 2 moved that code into a companion, whose new test kills both.
- **Round 2:** three reviews (an attacker's lens, the walk's operability, the runbooks) reported 26 findings, 7 major and 19 minor; two pairs named the same defect. Each held when checked. All were fixed but X2, fixed in part (above).
- **Round 3:** three reviews (the product code, a dry run of the walk, Google's pages) reported 19 findings, 4 major and 15 minor. Each held against the code, go1.27.4's source or Google's pages, and each was fixed.
- **The fixers' mutants.** Rounds 2 and 3 proved 11 and 15 more mutants by overlay, each failing its named test. Two of round 2's are the companions' two walk-only mutants, run again against the new test.
- **The network guard.** The test binaries of `devicekey`, `kube`, kubetest and the cli package, the mutants' included, ran under macOS's `sandbox-exec`, with a profile that refuses every outbound connection but loopback and local sockets, and refuses the system resolver's socket.
- **The last gates,** 2026-11-23: `gofmt -l` prints nothing; `go vet` passes untagged and with the integration, walk and realapi tags; `golangci-lint` with those tags reports 0 issues on the three trees; `go test -race` passes for `devicekey`, `kube` and kubetest, for the probe's 36 companion tests, and once for the whole cli package. `./check.sh` passes on this tree, on the dev Mac, 2026-11-23.
- **Google's pages** were read with WebFetch on 2026-11-22 and 2026-11-23, from Google's documentation site only. No cloud call was made. *(2026-11-23, M3a walked: the walk itself made cloud calls on 2026-11-23, recorded in its runbook.)*

### What is not verified

- **Every Google behaviour:** whether STS takes D2's profile and a leaf whose DN equals its issuer's; whether it binds the subject token to the handshake; path length; the 390-day rule's reach; HTTP/1.1 and TLS 1.3 at STS's mTLS endpoint; settle times and the revocation window; what the audit logs carry, and which sub-type `generateAccessToken` logs under; and whether enabling STS or IAM Credentials needs a billing link. *(2026-11-23, M3a walked: settled in an organization project, as the runbook's Results give them: D2's profile and that leaf accepted; the subject token bound to the handshake; path length not enforced [inf]; a 430-day leaf refused; TLS 1.3 at STS's mTLS endpoint; the settle times and the revocation window measured; the audit fields read; and, with billing disabled, enabling the APIs needed no billing link. Still unsettled: HTTP/1.1 at STS's mTLS endpoint, which stays [inf] because the Results do not state the version; and which sub-type `generateAccessToken` logs under, because IAM's row had all three on.)*
- **Every Cloud Shell line** beyond what a fetched page settles. The 17 generated scripts pass `sh -n`, and `setup.sh` ran against a fake `gcloud` only. No `gcloud` ran. *(2026-11-23, M3a walked: the blocks the walk used ran in Cloud Shell on 2026-11-23; `contingent.sh` and `bind-v1c.sh` were not needed, and W-FED's blocks have not run.)* *(2026-11-24, ADR 0023's M2 walked: W-FED's three blocks ran in Cloud Shell on 2026-11-24.)*
- **The walk itself,** and W-FED. The probe compiles and has never run. *(2026-11-23, M3a walked: the walk ran 2026-11-23, and M3a passes in an organization project. W-FED has not run, and the DNS endpoint with an impersonated token stays unverified.)* *(2026-11-24, ADR 0023's M2 walked: W-FED ran 2026-11-24 in M2's walk, and the DNS endpoint accepted the impersonated token. Its probe accepted only status 200 at first; a SelfSubjectReview's 201 needed the fix now in `walkm3a_test.go` (D6's note).)*

---

## 12. Amendments from M3b.1's build (2026-11-26)

M3b.1, the first of the nineteen steps of [the M3b plan](adr-0024-m3b-plan.md), was built 2026-11-26 on 4bbbb5f, after the operator answered, that day, the four questions the plan asks before M3b.1, each with its default: ADR 0024 *Choices* 9 and 24, and the plan's Q3 and X2. It changes `farsight/cli/internal/devicekey/` only. Nothing outside the package calls what it adds: it is tested offline and wired into no command, and nothing has run against Google for it. The reviews' and the mutants' reports were working files in a scratch directory, and are not kept.

### What landed

- **The enrolment purpose's opener.** `(*Store).OpenForEnrolment(r, rnd, now)` opens role r's current leaf as `OpenForRead` opens the reader's, renewing a due leaf under r's own anchor, with no consent. It serves D4's verification exchange and `install`'s one read of the project's number when an enrolment resumes in a later process (D2, D6).
- **`ConsentYes`, `Consent.Confirmed()` and `Consent.Kind()`.** `--yes` is a consent kind of its own (ADR 0024 *Choices* 24). `Given` counts it and `Confirmed` does not, so M5's broker can admit `--confirm` alone.
- **`RemoveRole(Reader)`** refuses with `ErrWriterRemains` while any of the writer's three directories is there, by `Lstat` alone, so this call never leaves a store with a writer and no reader (a concurrent `AddRole(Writer)` aside: below).
- **The certificates, read without a key.** `CurrentCertificates(r)` and `StagedCertificates(r)` return a `Certs`, which formats as fixed text, as `Identity` does, and gives the anchor's `NotAfter`. `AnchorWarnsAt` and `AnchorExpiredAt` hold `AnchorWarns`' and the openers' boundaries for a `NotAfter` read from the record. `Certificates` keeps its signature.
- **`ConditionTitle`,** a fourth kind of drawn ID: 30 characters of `[a-z][a-z0-9]*`, for the title of the writer's storage condition (D5, D7).
- **Google's text.** `CheckNamedProvider`, `ParseProviders`, `ParseProvider` and `RoleIDFromCondition`, each strict. `ParseProviders` and `ParseProvider` refuse an answer of more than `MaxProvidersList` bytes; `CheckNamedProvider` leaves the bound to the read that fetched its answer (M3b.3).

### Where it departs from the plan

1. **An enrolment window bounds `OpenForEnrolment`,** where the plan left it to the call-site review (its M3b.1 risk).
   - `Enrol` and `AddRole` write a 0600 `enrolling` marker into each new role's directory, inside the same atomic rename.
   - `EnrolmentVerified(r)`, which opens no file, removes it.
   - `OpenForEnrolment` refuses with `ErrNotEnrolling` when the marker is absent, before it reads anything, and with `ErrUnsafeMode` when the marker is not a plain private file.
   - A staged anchor renewal never holds one, so a committed renewal closes the window too, and `RemoveRole` and `Erase` remove the marker with the role's directory.

   So once an enrolment is verified, the writer's keys open only after a consent. The marker is local to the device, and adds nothing Google sees. The custody scan watches each site by its role, as `OpenForEnrolment(Reader)` or `OpenForEnrolment(Writer)`: a site whose first argument the scan cannot read as `devicekey.Reader` counts as the writer's.
2. **The read-back compares the whole name.** `CheckNamedProvider(answer, projectNumber, pool, provider, anchorDER, id)` builds `projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>` and compares it whole, where the plan asked only that the name end in `/providers/<id>`. M3a's `CheckProvider` keeps its signature for the walk probe, and a new test refuses it in any shipped file.
3. **The parsers know the instance's pool.** `ParseProviders(listJSON, projectNumber, pool)` refuses an entry outside the instance's pool, where the plan's took the list alone. A new `ParseProvider(getJSON, projectNumber, pool, provider)` reads one provider, for `device rm`, and refuses an answer about any other.
4. **JSON is read strictly.** The read-back and both parsers refuse a key given twice, also when one is spelled with a JSON escape, and trailing data. A list's answer holding any top-level key but the providers and the page token is refused whole, so an error body is never read as an empty pool.
5. **`RoleID` only under D3's exact mapping and condition.** A provider with no mapping, or any other mapping of strings, lists with a zero `RoleID`; a mapping that is not an object of strings is refused, and the whole list with it. Providers are labelled by provider ID only, because a copied mapping and condition can make two providers name one role ID.
6. **An interrupted commit is named.** `StagedCertificates` gives `ErrRenewalInterrupted` at either point `CommitAnchor` resumes from, never "nothing staged".
7. **Size.** About 900 product lines and 2,300 test lines, against the plan's 250 and 450: the reviews' fixes above, and a test that classifies every exported function as watched by the custody scan or unwatched, with a reason.

### What later steps take from it

- **M3b.3:** the providers-list reader requires status 200, caps the pages it follows, and refuses a page token it was already given; `ParseProviders` leaves those to it. Its read of one provider caps the answer's size, which `CheckNamedProvider` leaves to it.
- **M3b.6:** the read-back is `CheckNamedProvider`. Once a role's verification has passed and is recorded where a resumed command reads it, the caller calls `EnrolmentVerified(r)`.
- **M3b.12:** `anchor: ok|expiring|expired` comes from `AnchorWarnsAt` and `AnchorExpiredAt` on the record's `AnchorNotAfter`.
- **M3b.14:** a resumed verification opens through `OpenForEnrolment`; the pending state records "verified" before `EnrolmentVerified`, one more state for M3b.2's list; and a resume that meets `ErrNotEnrolling` has nothing left to verify.
- **M3b.15:** `ls` labels providers by ID only. `rm` takes another device's role ID from the `RoleID` of `ParseProvider` or `ParseProviders`, never from `RoleIDFromCondition` alone. Its `RemoveRole` runs under one per-instance lock, which M3b.16's `AddRole(Writer)` takes too.
- **M3b.16:** `device add --role writer` is `AddRole` under that lock, then the verification, then `EnrolmentVerified(Writer)`. `device renew`'s resume after `ErrRenewalInterrupted` is `CommitAnchor`, then `CurrentCertificates` for the record's `AnchorNotAfter`.
- **D11:** the condition title's fixed length and alphabet are one more trait of a FarCast project, as the object IDs' are.

### How it was checked

- **Three reviews,** read-only: custody, correctness against the plan and this design, and the tests' strength. They reported 22 findings, 4 of them major: 7 on custody, 7 on correctness and 8 on the tests, three pairs of them the same defect. A refute-first fixer checked each against the code, the plan and this design. Each held, two in part, and each was fixed.
- **Mutation testing.** 170 mutants, each a copy compiled in with `go test -overlay`, and one more on a scratch copy of the package on disk, for the test that reads source from disk. Against the tests the fix round left, 14 survived. The tests were strengthened, and 13 of the 14 were then killed, each by a failing test. In the final run 168 of the 170 failed a test, one failed to compile against a test file, as it had in the first, and one survived; the one on disk failed its test. The survivor, `refuseWhileWriter` going on after an `Lstat` fails, is equivalent: the error that causes it makes the removal fail too.
- **The network guard.** Every test binary the fix round and the mutation proof ran, the mutants' included, ran with `-race` under macOS's `sandbox-exec`, with M3a's profile, which refuses every outbound connection but loopback. `./check.sh`'s own run of the package is outside the guard.
- **The gates,** 2026-11-26: `gofmt -l` prints nothing; `go vet` and `golangci-lint` are clean for the package; its 65 tests pass under the guard; and `./check.sh` passes on the dev Mac.

### What is not verified

- **The list's shape** is [inf]: M3a read one provider with `get`, and never a list. The parsers refuse any other shape, so a different one fails closed, and M3b's walk reads the real one.
- **The name's project segment.** The three name checks take the project's number. If Google names a provider by the project's ID instead, they refuse it [inf], and M3b's walk settles it.
- **Concurrent removal.** A `RemoveRole(Reader)` racing an `AddRole(Writer)` in another process could still leave a writer alone. No lock guards that yet: config's only lock is the keyring's, and M3b.2 plans none. The M3b plan's notes have `device rm` (M3b.15) and `device add` (M3b.16) take one per-instance lock around those calls.

---

## 13. Amendments from M3b.2's build (2026-11-26)

M3b.2, the second of the nineteen steps of [the M3b plan](adr-0024-m3b-plan.md), was built 2026-11-26 on b0a0237. It changes `farsight/cli/internal/config/`. In `cli` it changes `loadInstallerKey`, which maps config's new refusal, the error classifier `classified`, which gives that refusal its kind, and a doc comment in `fatline.go`. Its tests are in `config`, `cli` and `storage`. Outside `config`, no product code but those two `cli` functions uses what it adds, and they use only the new `ErrNoServiceAccountKey`. It is tested offline, and nothing has run against Google for it.

Two changes reach commands, both where the installer key is loaded: a blank key is refused (below), and a `credentials.yaml` that does not parse is refused in words that quote none of it (departure 5). The reviews', the mutants' and the spike's reports were working files in a scratch directory, and are not kept.

### What landed

- **The record.** `InstanceMetadata.Identity`, with `Identity`, `DeviceRole` and `KnownProvider` as the plan names them, and the five routes, recorded per role.
  - `CheckedIdentity(meta)` checks each value that is present against the alphabet it is later rendered in: the project's number, 1 to 20 digits; the pool's and each provider's ID, 32 characters; each service account's ID and the condition's title, 30; each ID `[a-z][a-z0-9]*`. It also checks what each route needs (D7). Its errors name the field and the shape, never the value.
  - `ServiceAccountEmail(id, project)` refuses an ID or a project out of shape.
- **The merge.** `mergeOntoNewer` merges `Identity` field by field, `Roles` per role and `Known` per provider, with the three-way rule `SystemImages` keeps. A time compares by its instant, and a list that names a key twice is refused, not merged.
- **The pending store.** `<config>/pending/<name>/` (0700), holding `pending.yaml` (0600) and `identity/` (0700), beside `instances/`, never in it.
  - `Pending`, as the plan names it, with its draw as `PendingDraw`. It has two kinds, `install` and `device_add`, and four states: `keys_made`, `setup_shown`, `coordinates_received` and `verified`, the one §12 asked for.
  - `CreatePending`, one exclusive `mkdir`; `SavePending` and `LoadPending`, atomic, strict and read through `readFile`; `ListPending`; `PendingExists`; `PendingOnly`, the abandon's precondition; and `RemovePending`.
  - Every function that takes a name checks it with `ValidateInstanceName` before it builds a path. That is config's own copy of `install`'s rule, and a `cli` test holds the two equal for every byte value and every length.
  - Where the store keeps something, it refuses a symbolic link, a directory other accounts can reach, and anything else that is not a directory or a regular file (`ErrUnsafePath`). An abandon still removes a widened directory rather than refusing it.
- **The paths.** `InstanceIdentityDir`, `PendingDir` and `PendingIdentityDir`.
- **The hand-off.** `AdoptPending(name, meta)` in D7's order: `CreateInstance`, then `SaveInstanceMetadata`, then the rename of `identity/` into the instance, then `RemovePending`.
  - `ResumeAdoption(name)` finishes one that stopped after its record; `AdoptPending` again finishes one that stopped before it.
  - A test seam can stop either function before each of its steps.
- **A blank key.** `LoadInstanceCredentials` refuses a key that is empty or white space, `ErrNoServiceAccountKey`.
  - `loadInstallerKey` maps it to the refusal it gave before, with the same text and kind, `credential_missing`.
  - Three callers load the key without `loadInstallerKey`: `release`; the commands that open storage (`storage ls`, `cp`, `rm`, `usage` and `key rekey`, and the `secret` commands); and `toolchain`'s registry ensure. They now refuse such a record at that load, `load credentials for "<name>": …`, as `credential_missing` too: `classified` gives that kind to an error that names no kind of its own and holds `ErrNoServiceAccountKey` anywhere in its chain, as these three do. `storage deploy` opens the writer first and keeps `loadInstallerKey`'s refusal.
  - With an empty key, each of those three would otherwise have opened its provider as the machine's Application Default Credentials. So no farcast command now hands planck or datasphere a blank key. The adapters' own fallback to ADC stays until M3b.4.

### Where it departs from the plan

1. **The hand-off requires `verified`.** `AdoptPending` and `ResumeAdoption` refuse an entry that is not at `verified` while it holds an `identity/` or its record puts a role on the certificate route (`ErrPendingUnverified`).
   - Without it, an entry at `keys_made` could be handed off. The instance's writer would then open through `OpenForEnrolment` with no consent, because devicekey's enrolment markers move with the keys (§12, departure 1).
   - config cannot see those markers, so the state is the only evidence of verification it has, and closing the markers stays the caller's.
   - M3b.14 keeps the order: `SavePending` at `verified`, then `EnrolmentVerified` for each role, then `AdoptPending`. A resume that finds `verified` calls `EnrolmentVerified` again first, which is no error on a closed window.
2. **A device add's record is `running`.** `AdoptPending` requires `provisioning` of an install's entry and `running` of a device add's, whose instance is there already (M3b.16). The plan named `provisioning` alone.
3. **Stops inside a step, and an abandon after step 1.** The plan tested stops between steps. Three more cases are now handled:
   - a stop inside step 2's write, which leaves the record's temporary files in the instance's directory: `AdoptPending` again takes a directory holding nothing else as step 1 done, removes them and goes on;
   - a stop inside step 4's removal, which unlinks `pending.yaml` before the entry's directory: `ResumeAdoption` removes an entry with no `pending.yaml` and no `identity/` beside a record of this instance that `CheckedIdentity` passes;
   - a stop after step 1, then an abandon: `RemovePending` removes the instance's directory too when it holds no record and nothing but those temporary files, so the name can be installed again.
4. **No roles is no identity.** `CheckedIdentity` refuses an identity that names no role as `ErrNoIdentity`. A role a machine cannot act as is named with the route `none`.
5. **No caller quotes a credentials file that does not parse.** The YAML library's error quotes the lines around the fault, which can hold the installer's private key. `release`, the commands that open storage and `toolchain`'s registry ensure printed it. `LoadInstanceCredentials`' error is now the path and `ParseFault`'s fault and position alone, and it still unwraps to the library's error. The leak predates M3b.2.
6. **Where the draws are checked.** The test that every drawn ID passes config's shapes is in `identity_test.go`, not `config_test.go`.
7. **Size.** About 1,550 product lines and 3,200 test lines, against the plan's 450 and 700: the departures above, and the documentation of each function's refusals.

### The X2 spike

X2 asks whether a raw `getattrlist(ATTR_CMN_EXTENDED_SECURITY)`, with no cgo, reports an inherited ACL (§11). It ran 2026-11-26 as scratch code, twice and independently: once as a standalone program over the standard library's `syscall`, built with `CGO_ENABLED=0`, and once as a test built in with `-overlay` and `-race` over `x/sys/unix`. Neither is shipped.

**Answer: yes, on the dev Mac** (macOS 27.2.1, arm64, go1.27.4). Each case agreed with `ls -le`:
- a file or a directory with no ACL returns no extended security;
- an explicit entry on a file, and an inheritable one on a directory, each return a `kauth_filesec` with one entry;
- so does each object made in that directory, which inherits the entry: a file, a subdirectory, and a key written through a temporary file and a rename, as devicekey writes keys;
- a symbolic link read with `FSOPT_NOFOLLOW` returns its own, which is none.

The filesec came back in the host's byte order.

**What it costs,** for X2's enforcement decision, due before M3b.14:
- Go's `syscall.Syscall6` on darwin/arm64 is a raw trap, not a call into libSystem, and `x/sys/unix` reaches the same trap. Apple supports neither the trap nor the filesec's layout as an interface [inf].
- A shipped check would be the first FarCast Go file outside a test to import `unsafe`.
- amd64 Macs and a sandboxed app (M5) were not tried.
- It needs no new dependency and no cgo.

### What later steps take from it

- **M3b.7:** `loadInstallerKey`'s blank-key text still tells the operator to release the instance, and since M3b.2 `release` refuses such an instance when it loads the key. So the advice leads to a refusal until M3b.7's message replaces it (the plan's §4). No instance with a blank key exists.
- **M3b.14:**
  - the order in departure 1;
  - whether fallback 3's check records `verified`: the hand-off does not require it where there are no keys and no certificate route;
  - X2's enforcement, from the spike above;
  - `install --abandon` is `PendingOnly`, then the keys' erasure, then `RemovePending`;
  - concurrency in the store. M3b.2 adds no lock, and no step of the plan names one for the store: M3b.15's per-instance lock is for devicekey's `RemoveRole`, which M3b.16's `AddRole(Writer)` takes too. Once M3b.14 wires `install`, its resume and `--abandon`, two processes can race in the store. For example, an abandon could remove the new, empty instance directory of another `install` of the same name. Each check of a path and its use are inside the 0700 config root, so only the same account can race them.
- **M3b.16:** a device add's hand-off records `running`, with the endpoint read through `planck.Open` as the reader. Like an install's, it needs the entry at `verified`, then `EnrolmentVerified`, first (departure 1).

### How it was checked

- **Three reviews,** read-only: security and custody, correctness against the plan and this design, and the tests' strength. They reported 18 findings, 2 of them major: 4 on security, 8 on correctness and 6 on the tests, five pairs of them the same defect. A refute-first fixer checked each against the code, the plan and this design, and each held. Of the 13 defects they name:
  - 11 were fixed in code and tests;
  - the X2 spike, which two findings asked for, was run (above);
  - the blank-key text, two more, M3b.2 keeps by design (M3b.7, above).
- **The records' review.** Two read-only reviews of these records were made, one for accuracy and one for the record rules. The second found that the three callers' refusals of a blank key printed the kind `internal`. That is fixed in `classified`, with a test that fails without the fix: `release`'s and `ensureRegistry`'s kind, and the JSON error of `storage ls` and `secret ls` run through the CLI's router.
- **Mutation testing.** 301 mutants, each a copy compiled in with `go test -overlay`. 22 survived their first run. The tests were strengthened, and 16 of those 22 were then killed. In the final run 295 failed a test, and the 6 that still survive are equivalent:
  - a sort of a list `os.ReadDir` had already sorted;
  - two checks of a name that the next call checks first;
  - a comparison of a key the caller had already matched;
  - a path recomputed to the same string;
  - `RemoveAll` in place of `Remove`, of a directory already emptied.
- **The network guard.** Every test binary run in the build, the reviews, the fix round, the mutation proof and the final runs ran with `-race` under macOS's `sandbox-exec`, with M3a's profile, which refuses every outbound connection but loopback and local sockets, and refuses the system resolver's socket. That includes the mutants' and the X2 spike's test. The exceptions are listings of a binary's tests, which run none (the build's and the mutation proof's among them), and `./check.sh`'s own run.
- **The gates,** 2026-11-26:
  - `gofmt -l` prints nothing;
  - `go vet`, with and without the `walk`, `integration` and `realapi` tags, is clean for `config`, `cli` and `storage`, and so is `golangci-lint` with those tags, as `./check.sh` runs it;
  - under the guard, `config`'s 74 tests, `storage`'s 18 and `devicekey`'s 65 pass, and `cli`'s 979, with its two `TestHandOverModel*` skipped, as they are without `FARCAST_MODEL=1`;
  - `./check.sh` passes on the dev Mac;
  - the vendored modules stay 31, and the exec allowlist gains no entry.

### What is not verified

- **The field set** is fixed before its consumers exist, the plan's M3b.2 risk. M3b.7 is its first reader and M3b.14 its first writer, and either may amend it.
- **The X2 check** held on one OS build, on arm64, as above.
- **Concurrency** in the store: no step yet names a lock for it, as above.
