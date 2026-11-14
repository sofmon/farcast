# ADR 0023 — One Download: farcast Stands Alone

**Status:** Accepted (2026-11-13), proposed the same day. M0 and M1 were built 2026-11-13, the pinned base's three documents included, and `./check.sh` step 3b checks on the dev Mac that release builds are byte-identical. M1's billable walk has not run: it needs the operator's approval, and its runbook is [adr-0023-m1-walk.md](../runbooks/adr-0023-m1-walk.md). The second-host reproducibility gate has not run either. Nothing below has been walked, and every later milestone is not started. The operator made the decision to pursue one download: `farcast` alone is to be enough to install and run FarCast. Accepting decision 4 answers *Choices* 2: FarCast ships its components pre-built. That choice's re-release window N (decision 6) and where the signing key's fingerprint is published stay open. The other choices stay open until the milestone that needs them: 6 and 7 by M2, 1 and 5 by M3b, 3 by M5, and 4 not before M3. The evidence is a feasibility study at commit 6b62d3f: repository reads, local builds and offline probes on the dev Mac (macOS 27, Go 1.27.3, Xcode 27.2), and fetched documentation. No cloud call was made. Tags: **[ran]** built, measured or probed locally; **[read]** read in the repository; **[inf]** inference. External facts carry their URL.

**Date:** 2026-11-13

**Relates to:**
- **Answers** [ADR 0021](0021-farsight-native-client.md) decision 6, which says "one app, one download" is "not yet true on macOS" and that prebuilt, signed system images need "its own ADR", and that ADR's revisit trigger on prebuilt images.
- **Supersedes, when M2 lands,** [ADR 0006](0006-connect-bootstrap-kubectl.md) decisions 1, 2 and 4. Its decision 3, secrets never on argv or in temp files, is kept.
- **Amends, as each milestone lands** (each record carries a dated note naming its milestone):
  - [ADR 0004](0004-private-control-plane.md) decision 2's exec credential;
  - [ADR 0007](0007-instance-owned-image-registry.md) decisions 2, 4, 5 and 7;
  - [ADR 0010](0010-application-image-builds.md) decision 8;
  - [ADR 0019](0019-what-the-cluster-tells-its-provider.md) decision 6;
  - [ADR 0021](0021-farsight-native-client.md) decisions 6 and 9, and Verification 4 and 5.
- **Uses** [ADR 0020](0020-instance-pki-ecdsa-p256.md)'s P-256 keys. ADR 0020:57 and its Verification 4 leave a permanent Secure Enclave key in the data-protection keychain untested, for an iPhone keeper. This ADR adds the Mac case, a Secure Enclave key kept by a Developer ID app without a sandbox, as an M5 probe.
- **Constrained by:**
  - [ADR 0009](0009-technocore-kernel-and-cost-metering.md): spending the meter cannot see, and decision 3's small scope for the kernel's client;
  - [ADR 0016](0016-adaptive-resources.md): who owns a pod template's fields;
  - [ADR 0018](0018-thin-device-storage.md):33: a thin device "never holds … a cloud credential";
  - [ADR 0019](0019-what-the-cluster-tells-its-provider.md): what the provider's audit log keeps.

---

## Context

The operator's request, 2026-11-13 (condensed): *"In my vision you download only one application, farcast, on your laptop or tablet, and it is sufficient to install FarCast on the cloud. Today it needs third-party programs: go, gcloud, kubectl, etc. Can we bypass them or embed their libraries? The end vision is that farcast is a standalone app. If that means embedding pre-compiled binaries in the app, so be it."*

### What the operator's machine needs today

`farcast` starts exactly two programs [read]: `kubectl` ([`cluster/cluster.go:116,122`](../../farsight/cli/internal/cluster/cluster.go)) and `go build` ([`image/compile.go:42`](../../farsight/cli/internal/image/compile.go)). Everything else hangs off those two, or off the identity they need.

- **kubectl, every day from `connect` on.**
  - `cluster.Client` has 15 methods (`cluster.go:234-613`) behind about 17 commands: `apply -f -`, `create`/`replace -f -`, `get … -o json|jsonpath`, `rollout status` and `logs [--follow]`.
  - `apply` sends 13 kinds in 6 API groups, all rendered by FarCast. No call uses exec, port-forward, attach, `delete`, a CRD or a watch outside `rollout status` [read].
  - Every command but `world` hands kubectl the operator's whole environment (`cluster.go:99-105`), and nothing sets `KUBERC=off`. kuberc is beta and on by default since kubectl 1.34 ([kuberc](https://kubernetes.io/docs/reference/kubectl/kuberc/)).
- **The GKE auth plugin, gcloud and Python, for the token.**
  - The kubeconfig names `gke-gcloud-auth-plugin` by bare name, with no arguments ([`kubeconfig.go`](../../planck/internal/providers/gke/kubeconfig.go)). The plugin runs `gcloud config config-helper` ([plugin source](https://github.com/kubernetes/cloud-provider-gcp/blob/master/cmd/gke-gcloud-auth-plugin/gcloud_token_provider.go)), and gcloud needs Python 3.10–3.15 ([gcloud install](https://docs.cloud.google.com/sdk/docs/install-sdk)).
  - So cluster calls run as whichever gcloud configuration is active. Only `world` runs as a pinned account (ADR 0021 decision 9).
  - gcloud keeps refresh tokens for the human's whole account in a local credentials database under `~/.config/gcloud`, a directory Google says malware targets, and writes ADC there as a plaintext file ([Google](https://docs.cloud.google.com/architecture/bps-for-mitigating-gcloud-oauth-tokens)).
- **Go, a farcast checkout and git, for FarCast's own images.**
  - Four components (fatline, shrike, technocore, datasphered) are compiled whenever `<registry>/system/<c>:<CLI version>` is missing. That is every fresh instance and every new CLI build, because the tag is the CLI version.
  - `go.mod`'s `toolchain go1.27.0` is a floor, not a pin: go1.27.3 compiled here [ran]. `goCompile` passes `os.Environ()` through (`compile.go:46`), and `go build`'s VCS stamping runs git when it is present [ran: `go build -x`].
  - `farcast` itself is distributed as source. The macOS app is ad-hoc signed (`project.pbxproj`) and records six paths in Settings: farcast, kubectl, the plugin, gcloud and two configuration directories ([`CLISettings.swift:36-68`](../../farsight/client/apple/FarSightKit/Sources/FarSightCore/CLI/CLISettings.swift)).
- **A second cloud identity.** Every Google API call uses an SA key held verbatim in a 0600 `credentials.yaml`, or ADC when the key path is left blank ([`install.go:305`](../../farsight/cli/internal/cli/install.go)). The runbook says the project "never uses Application Default Credentials" ([`phase-1-validation.md:242`](../runbooks/phase-1-validation.md)). The installer SA holds `container.admin`, `iam.serviceAccountUser` and `artifactregistry.admin` (`phase-1-validation.md:64-85`), and a conditioned `storage.admin` ([`phase-3-validation.md:60-65`](../runbooks/phase-3-validation.md)).
- **gcloud by hand.**
  - The project setup: APIs, the SA, its roles and its key.
  - Two grants the CLI prints and deliberately does not apply: the builder's push grant ([`buildgrant.go:52-73`](../../farsight/cli/internal/cli/buildgrant.go)) and the keyholder's bucket grant ([`storagedeploy.go:328-355`](../../farsight/cli/internal/cli/storagedeploy.go)).
  - A hand-made `kubectl create secret` for private repositories ([`phase-4-2-validation.md:224`](../runbooks/phase-4-2-validation.md), [`phase-4-3-validation.md:208`](../runbooks/phase-4-3-validation.md)), and a `kubectl create namespace` hint ([`kernel.go:237`](../../farsight/cli/internal/cli/kernel.go)).
- **A browser**, for gcloud's sign-in, the Cloud sign-up and billing, and reading the bill for `kernel confirm`.
- **Vendored code that can start programs nobody asked for.** Seven `exec.Command` sites sit in vendored packages linked into `farcast` [ran: `go list -deps` and grep]:
  - the enterprise-certificate-proxy signer and the auth library's SecureConnect command. Both are reachable because `cloud.google.com/go/auth` turns client certificates on by default ([`cba.go:291-298`](../../vendor/cloud.google.com/go/auth/internal/transport/cba.go));
  - SecureConnect in `google.golang.org/api`, on only when `GOOGLE_API_USE_CLIENT_CERTIFICATE` is `"true"` (`internal/cba.go:146`);
  - two executable external-account providers, gated on `GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1` and an external_account file reached through ADC;
  - two Windows-only `powershell` GCE probes, reached only through DirectPath or ALTS, which nothing enables [read].

### Three findings on the way

- **Client-side apply copies Secret keys into annotations.** `Apply` pipes YAML to `kubectl apply -f -` (`cluster.go:234-235`), and client-side apply keeps the whole applied object in `kubectl.kubernetes.io/last-applied-configuration` ([Kubernetes](https://kubernetes.io/docs/tasks/manage-kubernetes-objects/declarative-config/)). So FatLine's `server.key` ([`fatline/deploy/deploy.go:318-330`](../../fatline/deploy/deploy.go)), each application's egress Secret and the keyholder's listener key ([`datasphere/deploy/deploy.go:365`](../../datasphere/deploy/deploy.go)) each sit a second time in their own Secret's metadata [read]. Decision 2 ends this.
- **A Windows build compiles but cannot install.** Go reports every Windows directory as mode 0777 (go1.27.3 `src/os/types_windows.go`), and `Dir.CheckPerms` refuses any directory with group or world bits ([`config/config.go:56-66`](../../farsight/cli/internal/config/config.go)). So `install` fails at `CreateInstance` before it creates anything, and every later config write fails too. The keyring lock refuses outright on that platform ([`keyring_lock_other.go`](../../farsight/cli/internal/config/keyring_lock_other.go)) [read].
- **ADR 0009:114 is ahead of the code.** It says `farcast costs` pulls `confirmed`, but the code takes a typed `kernel confirm --amount` ([`kernelconfirm.go:73`](../../farsight/cli/internal/cli/kernelconfirm.go)) [read]. It is unrelated to this ADR, and accepting this ADR does not change it.

### What no app can remove

- A Google account.
- The Google Cloud sign-up, and a billing account with a payment method. The API "creates billing subaccounts" only ([billingAccounts.create](https://docs.cloud.google.com/billing/docs/reference/rest/v1/billingAccounts/create)).
- A privileged setup by the human account, once per project and once per instance. Service accounts can create projects only inside an organization ([projects](https://docs.cloud.google.com/resource-manager/docs/creating-managing-projects)).
- Reading the bill for `kernel confirm`, which takes a typed `--amount`.

---

## Decisions

*Milestones, defined under Phasing:* M0 hygiene · M1 embedded layers · M2 in-process client · M3a identity probe · M3b device keys · M4 Linux and Windows · M5 macOS app · M6 thin client · M7 operator iPad.

**1. farcast embeds no third-party tool. Each one is replaced in-process, and the vendored module count stays 31.**
- *What goes:* kubectl, the auth plugin, gcloud, Python, Go, the checkout and git, from every day-to-day flow (decisions 2–4).
- *The only pre-built binaries farcast carries* are FarCast's own four Linux components (decision 4). Third-party images are still pulled at run time, in-process and digest-pinned: the distroless base from gcr.io, and the toolchain mirror's `gcr.io/kaniko-project` and `cgr.dev` images ([`toolchain.go:20,25`](../../farsight/cli/internal/cli/toolchain.go)).
- *Module count:* `vendor/modules.txt` lists 31 modules, before and after. The Kubernetes client is standard library. Workload Identity Federation adds one package, `credentials/externalaccount`, from an already-vendored module [ran]. Windows ACLs use the already-vendored `golang.org/x/sys/windows`. `embed` is standard library.
- *The one route that would break 31, and why it is not taken:* the Go CLI cannot reach the macOS Keychain or the Secure Enclave without cgo, a new module (+1, purego-style), hand-written trampolines (unsafe code) or `/usr/bin/security` (a subprocess with the secret on argv, against ADR 0006 decision 3). So that work moves to the Swift app (decision 7), and the Go binary does not do it.
- *No program starts unasked.* In-process, `farcast` sets `GOOGLE_API_USE_CLIENT_CERTIFICATE=false` and unsets `GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES`. ADC goes in decision 5. A `check.sh` gate fails if a newly linked vendored package contains an `exec` call. The cost: an organization that enforces certificate-based access would refuse this CLI.

**2. An in-process Kubernetes client replaces kubectl.** It reuses [`technocore/kube`](../../technocore/kube/), the hand-rolled, standard-library client ADR 0009 chose for the kernel: 840 non-test lines, already linked into `farcast` [ran: `go list -deps`].
- *Its own package:* the CLI's code lives in `farsight/cli/internal/kube` and reuses `technocore/kube`'s types and quantity parsing. `technocore/kube` keeps its in-cluster scope (ADR 0009 decision 3), so the kernel links no Secret or apply code.
- *Transport:* an out-of-cluster constructor that takes the DNS endpoint and a token provider. It validates against the system roots with no client certificate, as the kubeconfig does today (ADR 0004).
- *Writes:* server-side apply. That is `PATCH … Content-Type: application/apply-patch+yaml` with `fieldManager=farcast`, `fieldValidation=Strict` and, for FarCast's own components, `force=true` ([server-side apply](https://kubernetes.io/docs/reference/using-api/server-side-apply/)). Applications follow the operator's choice (*Choices*, 6).
  - A fixed table of the 13 kinds: Namespace, ServiceAccount, Secret, ConfigMap, Service; Deployment, StatefulSet; Job; PodDisruptionBudget; NetworkPolicy; Role, RoleBinding, ClusterRole. Anything else is refused, and there is no discovery.
  - The storage pin keeps create and replace with `resourceVersion`, so 409 stays a conflict.
- *Secrets are rendered with base64 `data:` only.* The egress Secret uses `stringData:` today ([`planck/translate/workload.go:50`](../../planck/translate/workload.go)), and Kubernetes says "The `stringData` field for a Secret does not work well with server-side apply" ([Kubernetes](https://kubernetes.io/docs/tasks/configmap-secret/managing-secret-using-config-file/)). A test refuses `stringData` in any rendered manifest.
- *Rollout:* the Deployment is polled and judged by kubectl's six rules ([`rollout_status.go`](https://raw.githubusercontent.com/kubernetes/kubectl/master/pkg/polymorphichelpers/rollout_status.go)).
- *Logs:* the pod `log` subresource, which is plain chunked HTTP. kubectl's pod choice and per-container follow are ported ([`logsforobject.go`](https://raw.githubusercontent.com/kubernetes/kubectl/master/pkg/polymorphichelpers/logsforobject.go)).
- *A one-time migration from client-side apply, as its own command.* Live objects carry a `kubectl-client-side-apply` manager and the annotation. `farcast migrate <instance>` renames each object's manager entry and drops the annotation, guarded by `resourceVersion`, the egress Secret included. Its plan lists every object it rewrites (decision 8), and every other writing command refuses an instance not yet migrated. Without this, a field later removed from a manifest stays co-owned and is never removed.
  - *It cannot be undone.* `csaupgrade`, kubectl's routine for the same rename on its own manager, says "This operation is not reversible" ([csaupgrade](https://pkg.go.dev/k8s.io/client-go/util/csaupgrade)).
  - *Stuck fields:* migrating from client-side apply is known to leave them ([kubernetes#99003](https://github.com/kubernetes/kubernetes/issues/99003), open since 2021). So the k3s test removes a field after migrating.
- *Out of scope:* exec, port-forward, attach and watch. Needing one is a revisit trigger.
- *The seams:* `cluster.Client`'s methods keep their signatures, so call sites stay. The test seam moves from `Runner` to an HTTP round-tripper.
- *The error kinds:* `kubectl_missing`, `kubectl_failed`, `auth_tool_missing`, `gcloud_signed_out` and `gcloud_mismatch` are retired. New kinds take their place: credential-missing, unauthorized (401) and forbidden (403). A shipped kind keeps its meaning ([`kinds.go:15-16`](../../farsight/cli/internal/cli/kinds.go)), so no name is reused. The `instances` document loses `gcloud_pinned`, and both it and the `world` document change version.
- *The rehearsal seam must be redesigned, not lost.* The rig fakes kubectl, the plugin and gcloud, and its rule is that a fake "must never be in the product binary" ([`rehearsal.go:1-21`](../../farsight/cli/internal/rehearsal/rehearsal.go)). An in-process client needs another way in, so a test path enters the product binary under one rule:
  - a cluster token minted from Google's endpoints goes only to a host under `gke.goog`, validated against the system roots;
  - only a token minted from a loopback endpoint may go to a loopback IP literal, never the name `localhost`, with `certificate-authority-data`;
  - no field in an instance record turns either on alone.

  The alternative is to run ADR 0021 Verification 5 before this lands.
- *Size:* about 800–1,000 lines plus as many test lines, and +0 modules [inf].
- *When M2 lands:* this supersedes ADR 0006 decisions 1, 2 and 4. Its premises have expired: "already not hermetic" (line 19), and a "one-off" bootstrap (line 20) that is now 15 methods. Its objections to the hand-rolled client it rejected (line 26) no longer hold: server-side apply moves apply semantics to the server, the token is minted in-process (decision 3), and no path uses port-forward. Decision 3 is kept, and becomes trivially true.

**3. The cluster token comes from farcast, in memory only. Writes run as an instance identity; reads run as a separate read-only identity.**
- *The token:* minted with the vendored `cloud.google.com/go/auth`, as Artifact Registry tokens already are. It carries `cloud-platform` and `userinfo.email`, which GKE requires ([GKE auth](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/api-server-authentication)) and which the registry token source does not request today ([`registry.go:80`](../../planck/internal/providers/gke/registry.go)). It is never cached in a file, and nothing is written to `~/.kube`.
- *Who writes:* an identity bound to the instance, never "whichever gcloud configuration is active". In SA-key mode (M2) it is the stored installer SA, one per project as today. From M3b it is a per-instance SA that the device key impersonates. That ends ADR 0021 decisions 6 and 9's work-identity hazard for cluster calls, and retires `instances pin-gcloud` and the gcloud identity guard on the cluster path.
- *Who reads:* a per-instance reader SA with read-only GKE roles. The exact role set is not yet verified.
  - *Why:* today `world`, the Connected view's Refresh, reads as a pinned human account. It opens neither the CA key nor the keyring ([`world.go:108-120`](../../farsight/cli/internal/cli/world.go), ADR 0021:305), and it never loads `credentials.yaml` [read]. A naive in-process client would mint every read from the installer SA, and the read path would become the most privileged path.
  - *How:* in SA-key mode the reader SA has its own key, stored apart from `credentials.yaml`. From decision 5 on, the device key impersonates it through its own grant. On the Mac, the broker issues reader tokens by default, and a writer token only to a child started with `--confirm <digest>` (decision 7). So every command that writes to a cluster needs a plan (decision 8).
  - *The rule:* ADR 0021 decision 9's "reads never open the CA key" is extended to **reads never mint an admin token**, with a test that `world` never opens a writer credential.
- *Where SA keys are made:* `farcast` generates each SA's RSA key pair on the device, and the setup uploads only its X.509 certificate (`gcloud iam service-accounts keys upload`, [key upload](https://docs.cloud.google.com/iam/docs/keys-upload)). No private key is made in Cloud Shell or crosses the browser. Organizations created on or after 2024-05-03 block key upload as well as key creation ([secure by default](https://docs.cloud.google.com/resource-manager/docs/secure-by-default-organizations)).
- *What the audit shows:* cluster-call entries name a service account instead of a human email (ADR 0019). The user agent recorded in the 400-day Admin Activity log changes from kubectl's (ADR 0019:29-30). It is chosen deliberately: neither "kubectl" nor a needless fingerprint.
- *Open until walked:* that the GKE DNS endpoint accepts an SA token, and later an impersonated one, carrying `userinfo.email`. It is documented, and only a live cluster settles it.

**4. FarCast's own components ship pre-built inside farcast, as reproducible layers checked against digests compiled into the executable. The Go toolchain is not embedded.**
- *What ships:* the four linux/amd64 components as finished, stripped (`-s -w`) gzip layers, 15,480,150 bytes in all [ran]. Pushing them uses the existing OCI client. arm64 is not needed, because FarCast pushes amd64-only manifests today.
- *The expected digests are compiled into the signed executable* (`-X` or a small `go:embed`), never stored beside the layers. A digest list in the same file would validate whatever the file was changed to [inf]. They are checked:
  - before every push: the registry's digest must equal the expected one;
  - before every reuse: today's preflight reuses any image found at the version tag ([`fatline.go:282-294`](../../farsight/cli/internal/cli/fatline.go));
  - against `dev` and `+dirty` versions, which are refused. Today a build without VCS information is versioned `dev` ([`buildinfo.go:43-49`](../../farsight/cli/internal/buildinfo/buildinfo.go)), and `imageTag` folds `+dirty` into a valid tag (`fatline.go:371-395`).
- *The release step* builds the components, writes the layers and digests into a git-ignored folder, then builds `farcast`. `go:embed` cannot reach outside its package, and a plain source build without the layers must still compile.
- *Reproducibility becomes a gate* on the stripped layers, on the Linux `farcast` with its layers embedded, and on a second host OS. At 6b62d3f it was shown only for the unstripped components on one darwin host: all eight binaries had identical SHA-256 across three builds (warm cache, empty `GOCACHE`, another worktree path) [ran]. A Go patch release or a VCS-stamp change alters the digest [ran]. So the recipe pins the exact Go release, the VCS-stamp policy, `GOAMD64=v1` and a clean environment. `fatline/Containerfile` could not match, because `.dockerignore` excluded `.git`; it is retired at M1 (below).
- *How an operator checks a release without trusting it:* extract the layers from a documented container format with standard tools, hash them, rebuild with the pinned recipe and compare. A binary's own `farcast version` output proves nothing, because a swapped binary prints whatever it likes.
- *Where that check stops:* on macOS the helper that carries the digests is Developer ID-signed, like the Swift app, so neither matches a self-build byte for byte. There the layers are checkable, and the helper and its digests are trusted on Sofmon's and Apple's signatures unless the operator builds the app. A comparison with signatures stripped is an M5 probe, not a claim.
- *`--source` stays* as the operator's own patch path (decision 6). It builds, pushes and deploys, so it is not the comparison above.
  - A `--source` image is recorded in the instance's metadata as operator-built, with its digest and Go version.
  - Reuse accepts the compiled digest or that recorded one, and nothing else.
  - Replacing an operator-built image with the embedded one names both Go versions, and is a plan fact (decision 8).
- *The distroless base stays pulled by digest*, not embedded. Embedding it would need a licence review of its tzdata and ca-certificates ([distroless](https://github.com/GoogleContainerTools/distroless/blob/main/base/README.md)). A third-party notices file ships for the 31 vendored modules.
- *This is not ADR 0007's rejected default registry.* Nothing is fetched at run time and there is no feed. The instance registry stays the only runtime source.
- *ADR 0021 decision 6's version-skew guard stays.* Embedding binds components to the CLI that carries them, but two CLIs of different versions on one Mac still redeploy each other's components.
- *M1 as built (2026-11-13; its walk has not run):*
  - *The release step* is a Go command, `farcast-release`, run as `GOTOOLCHAIN=<pin> go run ./farsight/cli/cmd/farcast-release build -out <dir>`. It writes the layers and the digest table into that output directory, never into the source tree, and builds `farcast` with them overlaid (`go build -overlay`) onto `farsight/cli/internal/components/layers/`, which is git-ignored, under the build tag `farcast_embedded`. Untagged, the package carries nothing, so a plain `go build ./...` still compiles.
  - *The layers* total 15,778,258 bytes as `oci.BuildLayer` writes them, under go1.27.4 with the components' source unchanged since 006e479 [ran]. The 15,480,150 above is `gzip -9` of the raw binaries.
  - *The expected digests* are a table embedded with the layers. Each component's manifest digest is the checked identity. The table also records the source revision: a farcast whose own `vcs.revision` differs, whose version is `dev` or carries `+dirty`, or that was built from a modified tree refuses to push its components, before anything is asked or called.
  - *The pinned base's three documents* are in the tree under `farsight/cli/internal/image/base/`, so the manifest digests are computed offline. They were fetched 2026-11-13 anonymously from gcr.io and checked against the pin's digest chain; a base bump is `farcast-release base -write`, reviewed and committed. The distroless layers are still pulled by digest at run time.
  - *`fatline/Containerfile` and `.dockerignore` are retired.* The Containerfile could reproduce at best the binary. The release tool reproduces the binaries, layers, manifest digests and `farcast` with Go alone, checked on the dev Mac by `./check.sh` step 3b; the second-host gate has not run.
  - *The skew guard* is built for FarCast's own components: a farcast that carries them replaces an image another farcast version deployed only with an explicit `--embedded`, which `--yes` never implies. A farcast built from source carries none, and the guard does not apply to it: it compiles from a checkout after its build confirmation, which `--yes` answers. In M1 `--embedded` stands where this ADR says "plan fact"; it becomes a plan fact with M2's `--plan` and `--confirm`.
- *M1 amends (dated notes added 2026-11-13):*
  - ADR 0007 decision 4 ("the only build anchor"; "without a Git checkout, fails");
  - ADR 0007 decision 5 (the compile shells out to Go);
  - ADR 0007 decision 7 (reproducibility moves from "a goal, not a gate" to a gate);
  - ADR 0010 decision 8, whose anchor becomes "the released, reproducible layers, verifiable by rebuild without trusting the release".

**5. Identity, proposed: a per-device, per-instance P-256 key, through Workload Identity Federation, impersonating a per-instance service account. It is gated on the M3a probe.**
- *How it works:* the device key signs a 10-minute ES256 JWT. Google's Security Token Service (STS) exchanges it, and `generateAccessToken` returns a one-hour token for the instance's SA ([WIF](https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-other-providers); [generateAccessToken](https://docs.cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken)).
- *What the documentation confirms:*
  - pools are created in a project;
  - an OIDC provider takes an uploaded JWKS (the JSON list of public keys it trusts) of at most 8 keys, and "This operation replaces any existing uploaded keys";
  - tokens are RS256 or ES256, with `exp − iat` at most 24 hours;
  - mappings "can use the claims embedded in the ID token".
- *The shape this implies [inf]:*
  - **One provider per device per instance, each with a single-key JWKS.** A claim is not bound to a key, so any key in a shared JWKS could sign another device's subject. Enrolling a device never re-uploads the others, and revoking one deletes its provider. Deleting a provider stops new exchanges. A token already issued stays valid until it expires, up to one hour.
  - **A distinct key per instance.** One public key enrolled in several projects would let Google link them, which today's separate SA keys do not.
  - **An opaque subject:** the key's thumbprint, never a host or user name, because Google's always-on audit log can keep it (below).
  - **A non-resolvable issuer:** a reserved `https://….invalid` name, never a Sofmon domain. A resolvable name would make Sofmon's DNS look like a dependency and mark every pool as Sofmon's. `.invalid` is reserved, so no one can ever serve keys under it.
  - **No organization needed:** that pools work in a project with no organization is an inference.
- *The gate:* real STS accepting a self-signed ES256 JWT, with an uploaded JWKS and a `.invalid` issuer, is not walked. The client side passes offline against fakes [ran]. M3a runs in a project with no organization and in one with an organization.
  - *Domain-restricted sharing:* `iam.allowedPolicyMemberDomains` limits who can be granted roles. Organizations created on or after 2024-05-03 enforce it "with your domain listed as the only allowed value". Both forms of that value admit "All workload identity pools in any project in your organization" ([domain-restricted sharing](https://docs.cloud.google.com/organization-policy/domain-restricted-sharing)). M3a confirms this in the organization project.
- *The guard against external-account files keeps its purpose.* Today a configured key is loaded "as a service account *and nothing else*", so a file cannot redirect token minting ([`registry.go:512-517`](../../planck/internal/providers/gke/registry.go)). The WIF credential is built in-process, with the STS and IAM Credentials URLs fixed in code and never read from a file. The subject JWT is signed by FarCast, which departs from ADR 0007 decision 2's "no hand-rolled JWT, signing, or token refresh". The exchange and refresh stay in the vendored library.
- *Why now:* organizations created on or after 2024-05-03 block SA key creation by default ([restricting service accounts](https://docs.cloud.google.com/resource-manager/docs/organization-policy/restricting-service-accounts)), so SA keys already fail for some operators.
- *SA keys stay as a deprecated legacy path,* in their 0600 file. *ADC is removed.* That also removes ADC's metadata-server probe ([`detect.go:168`](../../vendor/cloud.google.com/go/auth/credentials/detect.go)) and the contradiction between `install`'s "blank = ADC" and the runbook.
- *What stays at rest:* a 0600 device-key file, wherever a `farcast` runs outside the Mac app's broker: the CLI until M5, a terminal `farcast` on a Mac after it, and every Linux and Windows CLI. It is a long-lived secret that Google trusts, scoped to one instance's SA and revocable per device. It is not "no key at rest".
- *What Google can see:* the pool, one provider and one public key per enrolled device per instance; each STS exchange and `generateAccessToken` call it serves, with source address and time; and Admin Activity entries for cluster writes, naming the SA.
  - *Where the device subject is logged:* in STS's and IAM Credentials' Data Access logs, which are off by default (ADR 0019:29). It is also logged in the always-on, 400-day Admin Activity log of services that record delegation, under `serviceAccountDelegationInfo`. Google's example is a Pub/Sub write ([WIF audit examples](https://docs.cloud.google.com/iam/docs/audit-logging/examples-workload-identity)).
  - *GKE does not log it,* so cluster-call entries name only the SA. Google names GKE and App Engine as services that do not.
  - *FarCast's other writes* go to Artifact Registry (`registry.go:217`, `:666`) and Cloud Storage. M3b records which of them carry the subject. Hence the opaque subject above.
- *That session control does not apply to WIF* is an inference, and M3a records what it sees. Session control is an organization's forced re-sign-in (*What stays outside the app*, 7).

**6. Release, signing and Go security releases.**
- *What embedding freezes:* the Go standard library inside FatLine (mutual TLS on a public load balancer), Shrike, TechnoCore and datasphered, at the release's patch level. 9 of the 11 go1.26 minor releases carried security fixes. go1.27.2 and go1.27.3 fixed crypto/tls, net/http and crypto/x509, and go1.27.4 (2026-11-10) fixed net/http and already supersedes the go1.27.3 the digests above were measured with ([Go releases](https://go.dev/doc/devel/release)).
- *Today is not better by default:* the tag is the CLI version, so components rebuild only on a new CLI or an explicit `--source` (`fatline.go:276-283`). What changes is that Sofmon's release cadence becomes the only route that needs no Go.
- *So FarCast states a policy:*
  - a re-release within N days of any Go security release that touches a linked package (N is the operator's to set);
  - each component's Go version printed by `farcast version` and carried in the `world` document;
  - `--source` with an operator-chosen toolchain as the operator's own patch path, which brings Go back for that operator;
  - plain words that FarCast never phones home, so the operator watches for releases. There is no updater, appcast or in-app check.
- *Signing:* a key-pinned detached signature, plus a signed git tag that carries `SHA256SUMS`. Keyless Sigstore is avoided, because it leans on central services [inf]. `ssh-keygen -Y verify` ships with macOS and most Linux distributions and can be the verifier [inf].
- *Still open:* where the key's fingerprint is published (sofmon.com is not live, per AGENTS.md), and how the key rotates or is revoked with no update server. Whatever host serves the downloads sees who downloads, and the module path points at GitHub today.

**7. Platforms.**
- **macOS: one download.** FarCast.app is Developer ID-signed, notarized and stapled, with the hardened runtime and no App Sandbox (ADR 0021 decision 6 stands).
  - `Contents/Helpers/farcast` is a universal, stripped Go CLI: 43.3 MB, 15.5 MB gzipped. It runs under the hardened runtime with no exception entitlements [ran: signed ad hoc with `-o runtime`, run natively and under Rosetta].
  - `Contents/Resources/` holds one file of amd64 layers, about 15.5 MB, placed once rather than embedded in each architecture slice, which would double it. The expected digests live in the helper (decision 4).
  - About 59 MB on disk, plus the Swift executable, which nobody has measured.
  - **The helper stays a separate process.** Linking Go into the app removes no tool, and it loses crash containment, memory separation from the tile bridge, and signal ownership: `cli.Main` installs SIGINT and SIGTERM handlers ([`cli.go:23`](../../farsight/cli/internal/cli/cli.go)) [inf].
  - **The Swift app holds the key and brokers tokens.** It holds a Secure Enclave P-256 key and hands one-hour tokens to the helper over an inherited pipe: reader tokens by default, writer tokens only for `--confirm`. A command-line tool can carry keychain-access-group entitlements once wrapped in an app-like bundle with a provisioning profile ([TN3137](https://developer.apple.com/tutorials/data/documentation/technotes/tn3137-on-mac-keychains.md)), but the cgo-free Go binary would still lack the Security binding (decision 1).
  - **A terminal `farcast`** cannot use the app's key. It enrols its own 0600 P-256 key, revocable on its own. "One CLI, one state" stays: the helper and a terminal `farcast` share the config directory, and the skew guard stays required.
  - **The broker rule is a rule in the code, not a boundary.** A helper started with a broker pipe never opens a device-key file, with a test. But anything running as the operator can read the terminal's 0600 key. So on a Mac that also uses a terminal `farcast`, such an attacker can mint a writer token from that file, whatever the Secure Enclave holds.
  - **CryptoKit's `dataRepresentation`** is "an encrypted block that only the same Secure Enclave can later use to restore the key" ([CryptoKit](https://developer.apple.com/tutorials/data/documentation/cryptokit/storing-cryptokit-keys-in-the-keychain.md)). The candidate route is a non-permanent Secure Enclave key whose blob is kept in a 0600 file, so no keychain item or access-group entitlement is needed. Apple's sample keeps the blob in the data-protection keychain instead, and its macOS target sets the keychain-access-groups entitlement. So the no-cost M5 probe tests both creating the key and restoring it from the file.
  - **The bare CLI on macOS** ships in a stapled `.pkg` or `.dmg`. A standalone binary cannot be stapled, so Gatekeeper looks its ticket up online at first launch ([Apple](https://developer.apple.com/tutorials/data/documentation/security/customizing-the-notarization-workflow.md)). An unsigned download opens only through Open Anyway ([Apple](https://support.apple.com/en-us/102445)).
  - Settings drops the six recorded paths and the built PATH ([`ChildEnvironment.swift`](../../farsight/client/apple/FarSightKit/Sources/FarSightCore/CLI/ChildEnvironment.swift)).
- **Linux:** one static binary per architecture, with the layers embedded (+about 15.5 MB) and a 0600 software P-256 key, as keeper keys are today.
- **Windows:** windows/amd64 first. windows/arm64 is not a first-class Go port ([PortingPolicy](https://go.dev/wiki/PortingPolicy)). It needs owner-only DACL checks through `x/sys/windows` in place of mode bits, for the config directory, the keyring and the credential files, and a `LockFileEx` keyring lock. Where Smart App Control is on, an unsigned `farcast.exe` may be blocked (*What … still see*, Microsoft).
- **iPad and iPhone: a thin client first,** as ADR 0021 step 7 plans. An "operator iPad" that installs is deferred to its own ADRs. It would reverse ADR 0018:33 and ADR 0021 decisions 6 and 7, and the rejected "Go core in every client". What the study found it would need:
  - Go as a `c-archive` behind a file-descriptor boundary, which compiled under Swift 6 strict memory safety with zero `unsafe` [ran]. That result is Swift-side only: all 31 modules would ship inside the Apple app, outside decision 4's source gate.
  - Build tags to compile out `os/exec`, because the archive still references `fork` and `execve` [ran]. iOS apps "are not allowed to spawn child processes" ([DTS](https://developer.apple.com/forums/thread/747499)).
  - A resumable `install`. Today it refuses an existing record ([`install.go:112-118`](../../farsight/cli/internal/cli/install.go)), though `CreateCluster` already resumes ([`gke.go:92-112`](../../planck/internal/providers/gke/gke.go)).
  - `BGContinuedProcessingTask`, which is iOS 26 only, user-initiated and cancellable ([BGCPT](https://developer.apple.com/tutorials/data/documentation/backgroundtasks/bgcontinuedprocessingtask.md)). It has a locked-device bug last reported in December 2025 as persisting on iOS 26.2 beta 3 (FB21233240), after DTS said it should have been fixed in 26.1 ([forum](https://developer.apple.com/forums/thread/796138)).
  - A custody ADR, because deleting the app probably wipes its container, with the CA key, the keyring and the record of a cluster that is still billing. No Apple page confirmed this.
- **visionOS:** a viewer and thin client only. It has no continued-processing API, the Go build for it only compiles [ran], and gomobile has no target for it ([golang/go#65251](https://github.com/golang/go/issues/65251)).
- **Android:** not researched.

**8. Anything newly automated is consented to through the plan, never by `--yes`.**
- Each new automated act becomes a `--plan` fact, bound into the `--confirm` digest (ADR 0021 decision 6), and is never covered by `--yes`. Today `--yes` skips every gate (ADR 0021:105).
- *Every command that writes to a cluster gains `--plan` and `--confirm`,* because the broker issues writer tokens only for `--confirm` (decision 3). ADR 0021 decision 6 gives the plan step only to "every command with an operator gate". Two commands write to a cluster with no gate today: `kernel confirm` and `kernel meter` ([`kernelconfirm.go:156`](../../farsight/cli/internal/cli/kernelconfirm.go), [`kernelmeter.go:119`](../../farsight/cli/internal/cli/kernelmeter.go)) [read].
- The two printed grants are the first case. The SA that writes could apply both: `artifactregistry.admin` covers the repository's `setIamPolicy` (ADR 0007 decision 3), and the conditioned `storage.admin` covers the bucket. The code withholds them on purpose:
  - push access "means code FarCast did not write can put images into the one registry this instance runs from … a decision for a human, once, deliberately" (`buildgrant.go:52-61`). **Push access stays a human step.** A scripted `run --yes` never arranges it.
  - the bucket grant needs a permission "which this CLI deliberately never asks for" (`storagedeploy.go:328-334`). It may be offered through the plan, and the printed command stays for credentials that lack bucket `setIamPolicy`.
- The one-time apply migration (decision 2) is its own command, and its plan lists every object it rewrites, because it cannot be undone. The new private-repository Secret and namespace subcommands go through the plan.
- The Cloud Shell setup script the app generates contains only public material. It is short and readable, and it shows its digest, because the operator pastes it into an Owner-level shell [inf].

---

## Choices left to the operator

1. **The identity route.** (a) Device key and WIF (decision 5). (b) A Desktop OAuth client the operator registers in their own project, with sign-in in the system browser. (c) SA keys. *Recommended:* (a), if M3a passes. (b) stays an optional mode for operators who want the app to create projects and link billing. (c) stays deprecated legacy. The setup runs as a Cloud Shell paste ([free](https://cloud.google.com/shell/pricing)).
2. **Shipping pre-built components, and the release policy.** Ship them (decision 4), or keep source-only. *Recommended:* ship them, with the verification recipe, the N-day re-release policy, and a decision on where the signing key's fingerprint is published. *(Answered on acceptance, 2026-11-13: ship them. N and where the fingerprint is published stay open.)*
3. **Apple Developer Program enrolment.** Enrol (USD 99 a year, [Apple](https://developer.apple.com/programs/whats-included/)), notarizing and stapling every release, or leave builds ad hoc, so each operator self-builds or uses Open Anyway. *Recommended:* enrol. Apple then sees each published build and keeps a revocation switch over it. It does not see instances.
4. **The operator iPad.** *Recommended:* thin client first. Decide the operator iPad only after M3, with a custody ADR and a third-party-code ADR.
5. **Who may enrol devices.** A human, through Cloud Shell, or an enrolled device that may add providers. *Recommended:* human only. A device that can add providers holds pool-admin rights, so one stolen device could enrol keys that outlive its own revocation.
6. **Forced or non-forced apply for applications.** Forced matches today's client-side apply: manifest fields overwrite TechnoCore's adaptations, as ADR 0016:62 already records. Non-forced surfaces conflicts with TechnoCore's manager instead. *Recommended:* forced for FarCast's own components; decide for applications under ADR 0016.
7. **The bucket grant.** Keep printing it, or offer it through the plan (decision 8). *Recommended:* offer it through the plan. Push access stays human either way.

---

## What stays outside the app

1. A Google account, the Cloud sign-up and a billing account. Whether `projects.create` works by API before the Cloud terms are accepted in the console is unconfirmed.
2. A privileged setup by the human account. Once per project: enable the APIs, and create the pool or, in SA-key mode, the installer SA. Once per instance: create its SAs and their roles, and the devices' providers, which hold public keys only. A Cloud Shell paste does it in the browser with nothing installed locally.
3. Enrolling or revoking a device: one Cloud Shell line, creating or deleting one provider. A token already issued outlives the revocation by up to one hour.
4. Reading the bill for `kernel confirm`.
5. Network reach: Google's APIs, the cluster's DNS endpoint, `<region>-docker.pkg.dev`, gcr.io, cgr.dev (before `run` can build); on a Mac, Apple for Gatekeeper's online checks; on Windows with Smart App Control on, Microsoft's cloud service.
6. Obtaining and updating the app: from any source the operator trusts on a Mac; the App Store and an Apple ID, or a self-build, on an iPad.
7. Only under option (b): the unverified-app click-through on each consent ([Google](https://support.google.com/cloud/answer/13464323)), and for organization-managed accounts re-sign-in under session control.
   - Admins can set 1 to 24 hours for any app that uses Google Cloud scopes ([Workspace](https://knowledge.workspace.google.com/admin/security/set-session-length-for-google-cloud-services)).
   - Google documents a 16-hour default for the console and the SDK, and for a subset of organizations since June 2026 ([session controls](https://docs.cloud.google.com/access-context-manager/docs/session-controls-for-reauthentication)). Whether it covers an operator-registered client is not stated.
8. An optional scheduler (launchd, systemd or cron), for `keeper run --once` and a daily `kernel confirm`.

## What Google, Apple and Microsoft still see

**Google.** This ADR does not change what the provider sees of an instance. It stays blind to content and sees metadata, as AGENTS.md says. What changes is what Google sees of the operator:
- cluster-call audit entries name a service account, not a human email;
- the device subject, an opaque thumbprint, sits in Data Access logs where they are on, and in the always-on Admin Activity log of services that record delegation (decision 5);
- the user agent in Admin Activity changes (decision 3);
- each device's public key and provider, per instance, and each token exchange. A key reused across instances would link them, hence decision 5's distinct keys;
- Cloud Shell sessions are Google sessions [inf];
- no Sofmon OAuth `client_id` is added. Resource names (`farcast-<instance>`) already say FarCast.

**Apple.**
- Notarization scans each published build, and FarCast's builds are public anyway.
- Gatekeeper is a run-time contact. It "performs online checks to verify if an app contains known malware" and "whether the developer's signing certificate is revoked", and Apple says it does not log IP addresses for Developer ID certificate checks ([Apple](https://support.apple.com/en-us/102445), 2026-05-27). Stapling lets Gatekeeper find the ticket offline, but neither page exempts a stapled app from the revocation check.
- So Apple can revoke the Developer ID or a ticket, and macOS then refuses the app on every operator's Mac. The escape is a self-built, non-quarantined app.
- On the iPad, App Store distribution ties installs to Apple IDs. Every route goes through an Apple developer team (ADR 0021:343).
- If an iPad app ever carries the Go core (M7), it ships its own TLS and AES-GCM, and App Store Connect asks export questions on each submission ([Apple](https://developer.apple.com/tutorials/data/documentation/security/complying-with-encryption-export-regulations.md)). The Developer ID Mac app is not submitted through App Store Connect.

**Microsoft.**
- On Windows 11 with Smart App Control on, each launch is first checked with Microsoft's "cloud-powered security service". When that service has no confident verdict, an unsigned app is considered untrusted and blocked ([Microsoft](https://support.microsoft.com/en-us/topic/what-is-smart-app-control-285ea03d-fa88-4d56-882e-6698afdb7003)).
- M4 ships `farcast.exe` with a signed tag and `SHA256SUMS`, not an Authenticode signature. Where Smart App Control is on, it may not run, and its launches reach Microsoft. Authenticode signing is not decided.

## Cost

- **No new standing cloud cost.** IAM is "offered at no additional charge" ([Google](https://docs.cloud.google.com/iam/docs/billing-questions)). No page found prices STS or impersonation, so that they are free is [inf]. Cloud Shell is free. The embedded layers push the same images as today, cents a month in Artifact Registry (ADR 0007 decision 8).
- **Sofmon pays USD 99 a year to Apple,** if enrolled. That is not an instance cost.
- **Verification costs cluster-hours** in M1, M2, M3b and M5. Each billable walk is a separate session the operator approves before anything is created. M3a creates free IAM objects in scratch projects and needs approval too.
- **The operator iPad (M7) only:** a stalled install is a billing cluster, so the app must list incomplete operations, with their standing cost, at launch. A free self-built app stops launching after 7 days ([Apple](https://developer.apple.com/support/compare-memberships/)), and an app holding the record of a billing cluster that silently stops launching is a cost-control hazard.

## Alternatives considered

- **`client-go`.** Measured on a copy of the repository: typed plus dynamic clients add 39 modules and 34.4 MB (+113 %) to `farcast`; the dynamic client alone adds 19. Both force a pre-release protobuf pseudo-version and five `golang.org/x` upgrades [ran]. Rollout rules and log pod choice live in `k8s.io/kubectl`, not `client-go`, so it does not buy the hard parts. Rejected.
- **Bundling kubectl.** 57.9–63.5 MB per platform for v1.37.2 (HEAD requests to `dl.k8s.io`), about 123 MB universal [ran]. It is supported only within one minor version of the API server ([skew policy](https://kubernetes.io/releases/version-skew-policy/)), GKE moves on its own channel, and there is no update server. It still needs a token source, and it cannot run on iOS. Rejected.
- **A Sofmon-owned OAuth client.** It breaks zero central dependency: one action on Sofmon's project disables every operator's sign-in, and its `client_id` tells Google "this account runs FarCast" [inf]. Google's terms say credentials "may not be embedded in open source projects" ([§4(b)(1)](https://developers.google.com/terms)). Rejected.
- **Reusing gcloud's OAuth client.** It would "misrepresent or mask" the client's identity ([§2(c)](https://developers.google.com/terms)). Rejected.
- **The OAuth device grant.** It allows no Cloud scopes ([Google](https://developers.google.com/identity/protocols/oauth2/limited-input-device)). Rejected.
- **An operator-registered OAuth client as the default.** It is registered in the Console only, and no API for standard clients was found [inf]. It brings a consent screen, an unverified-app warning and refresh tokens at rest. It is kept as an optional mode (*Choices*, 1). The study's loopback PKCE probe passes offline with no new package [ran].
- **SA keys as the default.** Keys "don't expire automatically" ([Google](https://docs.cloud.google.com/architecture/bps-for-mitigating-gcloud-oauth-tokens)), and new organizations ban them. Kept as deprecated legacy.
- **Embedding the Go toolchain.** The compiler cannot be linked as a library, because of Go's internal-package rule ([cmd/go](https://pkg.go.dev/cmd/go#hdr-Internal_Directories)). As binaries, a minimal darwin/arm64 subset is 32.6 MB gzipped plus 5.3 MB of source, and a cold `GOCACHE` reached 408 MB [ran]. It is as pre-built as the components, so it adds no trust. Rejected.
- **Building the components in the cloud.** In-cluster, TechnoCore must exist before `farcast build` runs, yet it is one of the images. FatLine would be produced by an archived Kaniko holding a push credential (ADR 0011). Fetching source from a Git host would announce each instance to that host. Cloud Build adds an API, roles and a bucket, and its spend is not a Pod request, so TechnoCore's `expected` cannot see it. ADR 0010 decision 8 reserves system images for verification independent of the cloud. Rejected.
- **A Go core linked into the Apple app.** On macOS it removes no tool and loses the process boundary (decision 7). On the iPad it is the M7 question, deferred.
- **`farcast` as its own exec credential plugin for kubectl** (about 60 lines). It drops gcloud quickly, but only while kubectl stays, and is then thrown away. Skipped unless M2 slips.

## Consequences

**Positive**
- On a Mac, after M0–M5 and once three probes pass, one notarized download installs and runs FarCast, with a Google account, billing and a Cloud Shell paste in a browser. The probes: STS accepts a self-signed JWT (M3a), the DNS endpoint accepts SA and impersonated tokens (M2, M3b), and a Secure Enclave key persists under Developer ID (M5).
- The credential-holding binary stops running about 60 MB of opaque kubectl, the plugin, gcloud and whatever `python3` sits first on PATH. The module count stays 31.
- Secret keys stop being copied into annotations. Cluster calls stop running as whatever identity is active, and reads stop being able to write.
- It works where SA keys are banned, after M3. Windows becomes installable after M4.

**Negative**
- FarCast owns about a thousand lines of Kubernetes wire code, and a migration on live objects that cannot be undone.
- Components are frozen at a release's Go patch level, and no channel tells the operator when that matters.
- Apple holds a run-time switch over the Mac app, and Microsoft's Smart App Control may block an unsigned Windows binary. A 0600 device key remains for a terminal `farcast`, and on Linux and Windows.
- The operator pastes a script into an Owner-level shell once per project and once per instance.
- The Swift app and the bundled Go helper are Developer ID-signed Mach-Os, so neither matches a self-build byte for byte. On a Mac, the helper and the digests it carries are trusted on Sofmon's and Apple's signatures unless the operator builds the app.

## Phasing

Every milestone is useful if the plan stops after it. Effort is rough [inf]. A clean machine has no gcloud, kubectl or Go, so the walks observe from Cloud Shell or a second machine, with the walk probe built elsewhere (`walkprobe_test.go` needs `go test -c`).

| # | Milestone | What it removes | Verified by | Cloud | Effort |
|---|---|---|---|---|---|
| **M0** | Hygiene: an exact Go pin tied to decision 6; a VCS-stamp policy and `-s -w` in both the release recipe and `goCompile`; a sanitized `goCompile` environment; the client-certificate and executable-provider variables (decision 1); the `check.sh` exec gate; a built environment and `KUBERC=off` for every kubectl call until M2; the README's Go version corrected | Unrequested subprocesses beyond kubectl and go | Unit tests; three builds with identical SHA-256, stripped and unstripped; `go build -x` shows no git | None | 2–3 days |
| **M1** | Embedded layers (decision 4): release step, compiled digests, `PushEmbedded`, digest-checked reuse, `dev` and dirty refused, Go version in `version`, notices file, second-host gate | Go, the checkout, git | httptest registry; digest determinism | **Billable walk:** install → connect → kernel deploy → storage deploy with no `go` on PATH | 1–1.5 weeks |
| **M2** | In-process client (decision 2) with the stored SA key; `data:` Secrets; the migration command; the reader SA (decision 3); the rehearsal seam; new error kinds; a plan for every writing command and the grants (decision 8); `pin-gcloud` retired | kubectl, plugin, gcloud and Python, where SA keys are allowed | httptest API server; the migration on local k3s (no cost) | **Billable walk:** migrate a live instance, install a fresh one; the DNS endpoint accepts the SA token | 3–4 weeks |
| **M3a** | WIF probe: a pool, one single-key ES256 provider with a `.invalid` issuer, an SA with no roles, STS and `generateAccessToken`, in a project with no organization and in an organization project, where `allowedPolicyMemberDomains` is checked | Decides the identity route | The probe's result, with which audit entries carry the subject | Free IAM objects; approval needed | 1–2 days |
| **M3b** | Device-key identity (decision 5): the Cloud Shell generator, per-instance SAs and software keys, the reader by impersonation, ADC removed, SA key deprecated | The SA key, where M3a passed | Unit tests against fakes | **Billable walk:** the DNS endpoint accepts an impersonated token; one Artifact Registry Admin Activity entry made through it is read back, and what it names recorded | 2–3 weeks |
| **M4** | Linux and Windows release: DACL checks, `LockFileEx`, signed tag and `SHA256SUMS`, windows/amd64 first | Nothing new; Windows can install | Cross-builds; a Windows install against a fake cloud; a keyring-lock race test; a run with Smart App Control on | None | 1–2 weeks |
| **M5** | macOS one download (decision 7): helper and layers bundled, Secure Enclave broker, `dataRepresentation` probe, a signature-stripped comparison probe, Developer ID, notarization and stapling, bare CLI in a `.pkg`/`.dmg`, Settings paths removed | Xcode; every tool on a Mac | **Billable walk** on a clean macOS user or VM: download → install → connect → release | Billable | 2–4 weeks, plus enrolment |
| **M6** | iPad and iPhone thin client (ADR 0021 step 7) | — | As ADR 0021 | As ADR 0021 | Per ADR 0021 |
| **M7** | Operator iPad, optional: custody and third-party-code ADRs, ADR 0018 and 0021 amended, c-archive, journaled install, App Review | Installing from a tablet | Simulator, then a device | **Billable walk:** an install interrupted and resumed | 6–10+ weeks |

M1 and M2 together give a standalone CLI where SA keys are allowed, in about 4–5 weeks [inf].

## Records this changes on acceptance

Listed here, with line numbers as at 6b62d3f. On acceptance (2026-11-13), ADRs 0004, 0006, 0007, 0010, 0019, 0020 and 0021 gained dated notes naming the milestone that changes them. ADR 0009 gained none, because only a revisit trigger is touched and the kernel's client keeps its scope, and neither did ADR 0018, which changes only under M7's own ADRs. AGENTS.md and README.md gained pointers, and PLAN.md placed the milestones. Nothing else was edited: a sentence that describes code as built keeps describing it until that code changes.
- **ADR 0004:** decision 2's `gke-gcloud-auth-plugin` exec credential (:56), and the matching Negative consequence (:80).
- **ADR 0006:** superseded, except decision 3.
- **ADR 0007:** decisions 4, 5 and 7; decision 2's "no hand-rolled JWT, signing, or token refresh" and decision 5's "minted in-process from the stored SA key", once M3b lands.
- **ADR 0009:** revisit trigger 3 (server-side apply as a signal to take client-go, T3). The kernel's client keeps its scope, and the CLI's own package carries server-side apply as a content type on PATCH (decision 2; *Alternatives*, client-go).
- **ADR 0010:** decision 8.
- **ADR 0019:** decision 6 (`farcast logs` stays on kubectl) becomes the log subresource. Caller identity, the reader SA, the user agent and where the device subject is logged are restated.
- **ADR 0020:** :57 and Verification 4 gain the Mac case as an M5 dependency, with the `dataRepresentation` option.
- **ADR 0021:**
  - decision 6: the plan step's scope ("every command with an operator gate"), the explicit-environment block, the "not yet true on macOS" line and the skew rule's scope;
  - decision 9: the pinned-gcloud rules, the `auth_tool_missing`, `gcloud_signed_out` and `gcloud_mismatch` kinds, and "reads never mint an admin token";
  - Verification 4 and 5; the Negative consequences at :392 (not one download) and :398-401 (who signs is open, which *Choices* 3 answers); *What Apple still sees*;
  - for M7 only: the thin-client paragraph, decision 7 and the rejected Go core.
- **ADR 0018:33:** for M7 only.
- **AGENTS.md:** line 33 ("Even then, on macOS it is not yet one download"); line 59 (control-plane calls "through kubectl"); the data-plane paragraph's "`kubectl` subprocess".
- **README.md:** :281 (control-plane calls "through kubectl"); :301 (the not-one-download sentence); :303 ("Install runs on macOS only") from M4, when Linux and Windows CLIs ship. For M7 only, :299 ("thin client that never holds cloud credentials").
- **`farsight/cli/README.md`:**
  - :55 (Go version and toolchain pin); :83-84 and :1019-1030 (`pin-gcloud`, `gcloud_pinned`); :249 (ADC when `--credentials` is omitted);
  - "Where FatLine's image comes from" (:434-466), bootstrap step 5 (:473), :474 (requires kubectl and the plugin) and redeploy step 4 (:582);
  - :557 (the kubectl-subprocess wrapper); :1040-1042 (the `world` sections read through kubectl);
  - decisions 8 and 11; the error-kind table (~1105); the `world` identity guard (~1117); the rehearsal (~1145); the directory layout (:1211-1237).
- **Other READMEs:** `planck/README.md:350` (ADC as the empty-credentials fallback, M3b); `fatline/README.md:64` (the local Go toolchain, and a Containerfile that "reproduces the same image").
- **PLAN.md:** :443, :447 and :457 (the pinned gcloud account, the checkout and the tool paths as the explicit environment), and the order.
- **Code comments that carry decisions:**
  - `buildgrant.go:52-61` and `storagedeploy.go:328-334` if decision 8 changes them; `workload.go:50`;
  - `image/compile.go:25-33` (Go as "the only external tool", and an exact pin) for M0 and M1;
  - `kubeconfig.go:5-12` (the exec credential), `cluster.go`'s missing-tool messages (:131, :225, :372) and `rehearsal.go:1-21` for M2;
  - `registry.go:512-517` (the ADC fallback and the service-account-only guard), `client.go:88-92` and `datasphere/README.md:483` for M3b;
  - the permission checks in `config/config.go` and `config/instance.go`.
- **Runbooks:** phase-1 (SA, key, line 242, the reader SA); phase-2 B0 and B1; phase-3 (storage grant); the 4.x prerequisites; 4.2 and 4.3 (`kubectl create secret`); phase-7-connected-view (Part R's fake tools and scenarios, `pin-gcloud`, the firewall rules for kubectl and gcloud); every walk's observation steps.
- **Apple client:** `farsight/client/apple/README.md`, `CLISettings.swift` and `ChildEnvironment.swift`; `CLIDocuments.swift`, `WireDocuments.swift`, `WorldReader.swift` and `ProblemText.swift` (`gcloud_pinned` and the gcloud kinds).

## Verification

1. **Unit and mutation tests,** each shown to fail with its defect restored:
   - an unknown kind is refused, and a rendered `stringData` fails the build;
   - the migration renames the manager, drops the annotation and refuses on a `resourceVersion` conflict;
   - the rollout port matches kubectl's six rules;
   - `world` never opens a writer credential, and the broker never hands a writer token to a child without `--confirm`;
   - with a terminal key present, neither an app-launched `world` nor an app-launched command without `--confirm` presents a writer token;
   - a pushed or reused image whose digest is neither the compiled one nor a recorded operator-built one is refused, and so are `dev` and dirty versions; a `--source` push is accepted and recorded;
   - a `--confirm` whose digest does not cover a newly automated act is refused, and `--yes` never covers one;
   - a Google-minted cluster token never reaches a loopback or non-`gke.goog` host, and a loopback-minted token never reaches anything else;
   - on Windows, a directory or file readable by another principal is refused.
2. **The reproducibility gate:** three builds with identical SHA-256 for the stripped layers and for the Linux `farcast` with them embedded, on two host operating systems.
3. **The exec gate:** a vendored package with a new `exec` call fails `./check.sh`.
4. **M3a**, recorded with what STS returned and which audit entries carry the subject.
5. **The walks** in the phasing table, each approved first. M5's walk runs on a machine with no Xcode, Homebrew, gcloud, kubectl or Go, and observes from Cloud Shell or a second machine.

## Revisit triggers

- **M3a fails,** or `allowedPolicyMemberDomains` blocks the pool. The identity route falls back to *Choices* 1 (b) or (c).
- **A flow needs exec, port-forward, attach or watch.** That reopens the client's scope, and ADR 0005's control-plane carrier.
- **Go ships a security release touching a linked package.** The decision 6 clock starts.
- **Apple revokes, or changes notarization or Gatekeeper.**
- **Google prices STS or impersonation, or documents session control for WIF.**
- **The operator asks for the operator iPad.** That starts the M7 ADRs.
- **Android work starts.** Nothing here was researched for it.

## Sources

- The repository at 6b62d3f, as cited inline. Builds, digests, sizes, module counts and the offline probes ran on the dev Mac with Go 1.27.3, 2026-11-13, in session scratch space outside the repository. The probes are not kept in the repository, so a [ran] result is reproduced only by repeating it.
- Kubernetes — server-side apply: https://kubernetes.io/docs/reference/using-api/server-side-apply/ · client-side apply and the annotation: https://kubernetes.io/docs/tasks/manage-kubernetes-objects/declarative-config/ · `stringData` and server-side apply: https://kubernetes.io/docs/tasks/configmap-secret/managing-secret-using-config-file/ · version skew: https://kubernetes.io/releases/version-skew-policy/ · kuberc: https://kubernetes.io/docs/reference/kubectl/kuberc/ · kubectl `rollout_status.go` and `logsforobject.go`: https://github.com/kubernetes/kubectl/tree/master/pkg/polymorphichelpers · `csaupgrade`: https://pkg.go.dev/k8s.io/client-go/util/csaupgrade · stuck fields: https://github.com/kubernetes/kubernetes/issues/99003
- GKE and gcloud — API server authentication: https://docs.cloud.google.com/kubernetes-engine/docs/how-to/api-server-authentication · kubectl access: https://docs.cloud.google.com/kubernetes-engine/docs/how-to/cluster-access-for-kubectl · auth plugin: https://github.com/kubernetes/cloud-provider-gcp/blob/master/cmd/gke-gcloud-auth-plugin/gcloud_token_provider.go · gcloud install: https://docs.cloud.google.com/sdk/docs/install-sdk · gcloud tokens: https://docs.cloud.google.com/architecture/bps-for-mitigating-gcloud-oauth-tokens
- Google IAM and policy — WIF with other providers: https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-other-providers · `generateAccessToken`: https://docs.cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken · IAM Credentials audit: https://docs.cloud.google.com/iam/docs/audit-logging/audit-logging-iamcreds · WIF audit examples: https://docs.cloud.google.com/iam/docs/audit-logging/examples-workload-identity · key upload: https://docs.cloud.google.com/iam/docs/keys-upload · restricting service accounts: https://docs.cloud.google.com/resource-manager/docs/organization-policy/restricting-service-accounts · secure-by-default organizations: https://docs.cloud.google.com/resource-manager/docs/secure-by-default-organizations · domain-restricted sharing: https://docs.cloud.google.com/organization-policy/domain-restricted-sharing · IAM billing: https://docs.cloud.google.com/iam/docs/billing-questions
- Google accounts and OAuth — billing accounts: https://docs.cloud.google.com/billing/docs/reference/rest/v1/billingAccounts/create · projects: https://docs.cloud.google.com/resource-manager/docs/creating-managing-projects · Cloud Shell pricing: https://cloud.google.com/shell/pricing · APIs terms (2021): https://developers.google.com/terms · device grant: https://developers.google.com/identity/protocols/oauth2/limited-input-device · native apps: https://developers.google.com/identity/protocols/oauth2/native-app · verification exceptions: https://support.google.com/cloud/answer/13464323 · session length: https://knowledge.workspace.google.com/admin/security/set-session-length-for-google-cloud-services · session controls: https://docs.cloud.google.com/access-context-manager/docs/session-controls-for-reauthentication
- Go — releases: https://go.dev/doc/devel/release · reproducible builds (2023): https://go.dev/blog/rebuild · internal directories: https://pkg.go.dev/cmd/go#hdr-Internal_Directories · porting policy: https://go.dev/wiki/PortingPolicy · gomobile and visionOS: https://github.com/golang/go/issues/65251
- Apple — notarization workflow: https://developer.apple.com/tutorials/data/documentation/security/customizing-the-notarization-workflow.md · Gatekeeper and Open Anyway (2026-05-27): https://support.apple.com/en-us/102445 · TN3137: https://developer.apple.com/tutorials/data/documentation/technotes/tn3137-on-mac-keychains.md · CryptoKit keys: https://developer.apple.com/tutorials/data/documentation/cryptokit/storing-cryptokit-keys-in-the-keychain.md · Developer Program: https://developer.apple.com/programs/whats-included/ · memberships: https://developer.apple.com/support/compare-memberships/ · child processes on iOS (2024): https://developer.apple.com/forums/thread/747499 · `BGContinuedProcessingTask`: https://developer.apple.com/tutorials/data/documentation/backgroundtasks/bgcontinuedprocessingtask.md · locked-device bug: https://developer.apple.com/forums/thread/796138 · export compliance: https://developer.apple.com/tutorials/data/documentation/security/complying-with-encryption-export-regulations.md
- Microsoft — Smart App Control: https://support.microsoft.com/en-us/topic/what-is-smart-app-control-285ea03d-fa88-4d56-882e-6698afdb7003
- Distroless base: https://github.com/GoogleContainerTools/distroless/blob/main/base/README.md

---

*This ADR is a living record. Revisit it on any trigger above.*
