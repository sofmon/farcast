# ADR 0023 M1 — farcast with no Go: the second host, then the billable walk

[ADR 0023](../adr/0023-one-download-farcast.md) M1 puts FarCast's four components inside `farcast`. This runbook proves it twice. R0 rebuilds a release on a second host OS and compares it byte for byte. W0–W7 install a live instance with a farcast built by `farcast-release`, from a shell with **no `go` on `PATH` and no checkout reachable**, and check that every system image deployed is the carried digest.

**Status.** Written 2026-11-13 against the code as built. ***W0–W7 walked 2026-11-14** at 44890cb against instance `$INSTANCE`: every system image deployed was the carried digest, recorded `origin: embedded`, from a shell with no Go and no checkout, and the instance is released. **R0 has not run.** The [Results](#results) are at the end. The walk corrected W1, W4 and W6 in place, each marked 2026-11-14: none of them is a defect in the product.*

**The pinned base's three documents are in the tree,** under `farsight/cli/internal/image/base/`: fetched 2026-11-13 anonymously from gcr.io and checked against `image.BaseImage`'s digest chain. `farcast-release build` builds a release on them, and `./check.sh` step 3b checks on the dev Mac that its builds are byte-identical. That is one host: R0 is the second, and has not run. A base bump is `farcast-release base -write`, reviewed and committed.

**What it proves.** A farcast built by `farcast-release` installs an instance and brings up FatLine, Shrike, TechnoCore and the keyholder. It needs no Go and no checkout to do it. It does not show that farcast starts no git: macOS keeps `git` at `/usr/bin/git`, which the walk shell keeps on `PATH`, so the walk shows only that no step failed for want of Go or a checkout. What farcast can start is the reviewed `exec-allowlist.txt`, which `./check.sh` step 1b compares with the code. Every system image the cluster is told to run is the digest compiled into that farcast, and `metadata.yaml` records each as `origin: embedded`. ADR 0023 Verification 2 (the reproducibility gate on two host operating systems) is met when R0 and `./check.sh` step 3b both pass.

**R0 costs nothing and touches no cloud.** Its only network reads are the clone and a one-time fetch of the pinned Go toolchain.

**W0–W7 are billable.** Expect about 2–3 hours of one Autopilot instance. The standing floor is about USD 0.106/hour ([phase-5-session-a.md](phase-5-session-a.md)), plus cents for the carrier's traffic, the registry and the bucket: under USD 1 in all. **Do not start W1 until the operator has approved this spend for this session.** Approval does not carry over from another walk. Present the cost, the duration and the teardown (W7), and wait for a yes.

Throughout:
- The operator's own gcloud configuration only, never a work one. `--credentials <service-account-key.json>` on every `farcast` command that takes it. No Application Default Credentials.
- Never paste raw output of a live command anywhere: not into the transcript, an issue or the repository, and no screenshots. Record only what each step says to record, with `$INSTANCE` and placeholders: never a project id, bucket name, address, account email, home-directory path or time of day.
- Never print a token. Never run `gcloud auth print-access-token`, even with its output redirected: zsh's MULTIOS still sends it to the pipe.
- `KUBECONFIG` is the instance's own kubeconfig in every shell that runs `kubectl` or `farcast`. The operator's default kubeconfig can hold other clusters.
- `farcast instances pin-gcloud` names an account, so **the operator types it**, in their own terminal, never through an agent's shell (W4). It is typed with the walked farcast's full path, `"$WALK/bin/farcast"`: a farcast from before M1 rewrites `metadata.yaml` without its `system_images`.

---

## R0. The second host (no cloud)

The release must be byte-identical on two host operating systems ([ADR 0023](../adr/0023-one-download-farcast.md) decision 4). The second host is the Ubuntu keeper VM used for the Phase 5 walks. This is an operator step: the operator runs it on the VM, and never types the VM's sudo password through an agent.

1. **The same commit and the same tags on both hosts.** Go stamps farcast's version from the local repository: the tag at the commit, or else a pseudo-version built on a tag among the commit's ancestors. So two clones with different tag sets, or a shallow clone, build different `farcast-*` bytes; the components and layers do not depend on tags. On both hosts use a full clone, not a shallow one, at the commit being released, from a clean tree:
   ```bash
   git fetch --tags
   test -z "$(git status --porcelain)" || echo "STOP: the tree is not clean"
   test "$(git rev-parse --is-shallow-repository)" = false || echo "STOP: a shallow clone"
   git rev-parse HEAD
   git tag --merged HEAD | sort
   ```
   Both hosts must print the same revision and the same tag list (empty, today) before anything is compared.
2. **The pinned Go, once per host.** go.mod's `toolchain` line names it (`go1.27.4`). Any installed Go that understands `GOTOOLCHAIN` bootstraps the fetch, which is checked against sum.golang.org whatever the host's go env file says:
   ```bash
   env GOENV=off GOMODCACHE="$(GOTOOLCHAIN=local go env GOMODCACHE)" GOFLAGS= GOPROXY=https://proxy.golang.org \
     GOSUMDB=sum.golang.org GONOSUMDB= GOPRIVATE= GOINSECURE= GOTOOLCHAIN=go1.27.4 go version
   ```
   About 74 MB from proxy.golang.org. On the dev Mac it is already in the module cache.
3. **Three builds on each host**, run from the checkout's root with the output outside it, the first with the host's build cache and the other two each with a new, empty one:
   ```bash
   cd <the checkout>
   R=$(mktemp -d)
   GOTOOLCHAIN=go1.27.4 go run ./farsight/cli/cmd/farcast-release build -out "$R/a"
   GOCACHE="$R/cache-b" GOTOOLCHAIN=go1.27.4 go run ./farsight/cli/cmd/farcast-release build -out "$R/b"
   GOCACHE="$R/cache-c" GOTOOLCHAIN=go1.27.4 go run ./farsight/cli/cmd/farcast-release build -out "$R/c"
   diff "$R/a/SHA256SUMS" "$R/b/SHA256SUMS" && diff "$R/a/SHA256SUMS" "$R/c/SHA256SUMS" && echo "same on this host"
   shasum -a 256 "$R/a/SHA256SUMS"        # on Linux: sha256sum
   ```
   The default targets are `darwin/arm64`, `darwin/amd64`, `linux/amd64` and `linux/arm64`, so both hosts build the same eight files plus the layers and the table.
4. **The criterion.** All three `SHA256SUMS` files are byte-identical on each host, and the VM's are byte-identical to the Mac's from the same commit: copy one of them across and `diff` prints nothing. A difference is a finding: record which lines differ (`components/…`, `layers/…`, `farcast-…`), never the files themselves.
5. **Record**, on both hosts: the sha256 of `SHA256SUMS`, the revision and tag list from step 1, `uname -srm` (the release and architecture, never the host name), and from `go version -m "$R/a/farcast-<goos>-<goarch>"` only the Go version and the `-tags`, `vcs.revision` and `vcs.modified` lines, for each `farcast-*`.

Keep the Mac's `$R/a` from this step: W0 uses it as `$REL`, and W7 deletes it. Delete the rest of `$R` on both hosts afterwards, with its two build caches (step 3b's single-target caches measured about 720 MB each on 2026-11-13; four targets take more, not yet measured).

---

## W0. Setup on the dev Mac (no cloud)

1. `./check.sh` passes at the commit being walked, from a clean tree, and the commit is pushed. Record the commit and the check's summary line.
2. **The release.** Use R0's Mac build, or make it now from the checkout's root, with the output outside it:
   ```bash
   REL=<R0's $R/a>      # or, in the checkout's root: REL=$(mktemp -d)/rel; GOTOOLCHAIN=go1.27.4 go run ./farsight/cli/cmd/farcast-release build -out "$REL"
   (cd "$REL" && shasum -a 256 -c SHA256SUMS)
   go version -m "$REL/farcast-darwin-arm64" | grep -E -- '-tags=|vcs\.(revision|modified)'
   ```
   *Expect* every line `OK`, `-tags=farcast_embedded`, the commit from step 1 as `vcs.revision`, and `vcs.modified=false`. A release farcast refuses to push its components when its own revision is not the one they were built at, or when either was built from a modified tree.
3. **The walk directory and the binary**, outside any checkout:
   ```bash
   INSTANCE=<name>
   WALK=$(mktemp -d)                  # 0700; this walk's scratch files live here, never in the checkout
   mkdir -p "$WALK/bin" && cp "$REL/farcast-darwin-arm64" "$WALK/bin/farcast"
   ```
   An outbound firewall that makes its rules per binary (Little Snitch, on the walk Mac) asks about `$WALK/bin/farcast` the first time it reaches each host. Allow it, for that destination only: Google's APIs, the registry's `<region>-docker.pkg.dev`, `gcr.io` for the base image, and the carrier's address on port 8443 after W2.
4. **Exactly three tools.** Link `kubectl`, the GKE auth plugin and `gcloud` one by one into a directory of their own. Never put a whole tool directory on the walk shell's `PATH`: on the walk Mac, Homebrew's `/opt/homebrew/bin` holds the plugin and `gcloud`, and also `go` and `gofmt`.
   ```bash
   mkdir -p "$WALK/tools"
   for t in kubectl gke-gcloud-auth-plugin gcloud; do ln -s "$(command -v "$t")" "$WALK/tools/$t"; done
   ```
5. **The walk shell.** Open it with nothing inherited but what is named. `/usr/bin:/bin` stay for the system utilities and the `python3` that gcloud runs:
   ```bash
   env -i HOME="$HOME" TMPDIR="$TMPDIR" WALK="$WALK" INSTANCE="$INSTANCE" \
     CLOUDSDK_ACTIVE_CONFIG_NAME=<your FarCast gcloud configuration> \
     PATH="$WALK/bin:$WALK/tools:/usr/bin:/bin" zsh -f
   ```
   Then, inside it:
   ```bash
   command -v go gofmt                # HARD STOP if this prints anything
   STATE="$HOME/Library/Application Support/farcast"
   export KUBECONFIG="$STATE/instances/$INSTANCE/kubeconfig.yaml"   # W1 writes it
   cd "$WALK"                         # outside any checkout
   farcast version
   ```
   **Hard stop:** if `command -v go gofmt` prints anything, stop, fix `PATH`, and do not go on to W1. *Expect* `farcast version` to list four components (`datasphered`, `fatline`, `shrike`, `technocore`), each `go1.27.4`, on `linux/amd64`. Record that it did, and the four manifest digests' first 12 hex characters.

   The plugin's gcloud finds its Python on this `PATH`. Since M0, `CLOUDSDK_PYTHON` no longer reaches it through kubectl. If gcloud fails for want of a Python, stop and record it as a finding; do not widen `PATH`.
6. **The observing shell.** A second, ordinary terminal, with gcloud and kubectl. Go on its `PATH` does not matter: nothing here proves anything about Go, and W6 needs it. Every check of the registry or the cluster below runs here, never in the walk shell. Set it up once:
   ```bash
   INSTANCE=<name>; WALK=<the same directory>
   STATE="$HOME/Library/Application Support/farcast"
   export KUBECONFIG="$STATE/instances/$INSTANCE/kubeconfig.yaml"
   export CLOUDSDK_ACTIVE_CONFIG_NAME=<your FarCast gcloud configuration>
   # the carried manifests, by component, from the release farcast itself
   carried() { "$WALK/bin/farcast" -o json version | grep -o '"name":"[a-z]*","go":"[^"]*","manifest":"sha256:[0-9a-f]*"'; }
   # the digests a workload runs, without the registry's project path
   running() { kubectl -n farcast-system get "$1" -o jsonpath='{.spec.template.spec.containers[*].image}' | tr ' ' '\n' | sed -n 's/.*@\(sha256:[0-9a-f]*\)$/\1/p'; }
   # the origins this machine recorded, without the image paths
   origins() { awk '/^system_images:/{f=1;next} f&&/^[^ ]/{f=0} f&&/^  [a-z]+:$|origin:|go:|farcast:/' "$STATE/instances/$INSTANCE/metadata.yaml"; }
   ```
   `running`'s and `carried`'s digests are the release's own and name no instance, so they may be compared by eye. The image paths they drop hold the project.

---

## W1. `farcast install` (billable from here)

In the walk shell:
```bash
farcast install --name "$INSTANCE" --cost-limit 100 --region us-central1 --credentials <service-account-key.json>
```
*Expect* the install to finish as on the Phase 5 walk. Nothing here touches FarCast's own images.

*(2026-11-14: without a terminal, as an agent runs it, the command as written stops twice: first at a prompt for the GCP project ID, then at install's own confirmation. Add `--project <the project id>`, taken from the FarCast gcloud configuration and not printed, and `--yes`, which answers only the spend the operator approved before W1.)*

## W2. `farcast connect`

In the walk shell: `farcast connect "$INSTANCE" --yes`.
- *Expect* a progress line pushing `fatline` and `shrike` as the images this farcast carries, with their Go and digests, and **no build prompt**. The cost confirmation is the only question, and `--yes` answers it.
- In the observing shell: `running deployment/fatline` prints two digests, equal to `carried`'s `fatline` and `shrike` manifests.
- `gcloud artifacts docker tags list <prefix>/system/fatline` lists the farcast version tag at that same digest, and no `source-…` tag. Record only "version tag at the carried digest: yes/no".
- `origins` shows `fatline` and `shrike`, each `origin: embedded`, `go: go1.27.4`, and the walk farcast's version.

## W3. `farcast kernel deploy`

In the walk shell: `farcast kernel deploy "$INSTANCE" --yes`.
- *Expect* the same: the carried `technocore` pushed, no build prompt.
- `running deployment/technocore` is `carried`'s `technocore` manifest; the version tag under `system/technocore` holds it; `origins` shows `technocore` as `embedded`.

## W4. `farcast storage deploy`

In the walk shell: `farcast storage deploy "$INSTANCE" --yes`.
- It prints the bucket grant **before** it applies anything. Apply it from the observing shell, as in [the phase-3 runbook](phase-3-validation.md) and Session A's S4, and wait for it to propagate.

  *(2026-11-14: the printed `gcloud storage` commands still crash on the walk Mac's gcloud under Python 3.14 (`ssl.PROTOCOL_TLSv1`), and that gcloud refuses the system's Python 3.9. `gsutil` loads. The walk applied the same two bucket-level bindings with `gsutil iam get gs://<bucket>`, adding `roles/storage.objectAdmin` and `roles/storage.legacyBucketReader` for the printed principal to that JSON, and `gsutil iam set`. That way no token is printed. The replicas crash-looped until the grant landed, and ran sealed about a minute after it.)*
- `running statefulset/datasphered` is `carried`'s `datasphered` manifest; `origins` shows `datasphered` as `embedded`.
- `farcast storage unseal "$INSTANCE"` in the walk shell, as on every walk: the replicas come up sealed.
- **`world` shows the Go of all four.** `world` reads as a pinned account. The operator types, in their own terminal, which is neither the walk shell nor the observing shell, so it sets both names first:
  ```bash
  WALK=<the walk directory>; INSTANCE=<name>
  "$WALK/bin/farcast" instances pin-gcloud "$INSTANCE" --account <the FarCast account>
  ```
  Then `origins` in the observing shell must still show all four components as `embedded`. If `system_images` is gone, a farcast from before M1 rewrote the record: that is a setup error, not a W4 result. Stop, and record it as such. Then in the walk shell: `farcast -o json world "$INSTANCE" | grep -o '"name":"[a-z]*","state":"[a-z_]*","ready":[0-9a-z]*,"desired":[0-9a-z]*,"version":[^,]*,"go":[^}]*'`. *Expect* `"go":"go1.27.4"` for `fatline`, `technocore`, `shrike` and `datasphered`. Record only those four `go` values.

## W5. `farcast redeploy`

In the walk shell: `farcast redeploy "$INSTANCE" --yes`.
- *Expect* "already holds the image this farcast carries" for both `fatline` and `shrike`, and no push.
- The registry shows no new tag and no new upload under `system/fatline` or `system/shrike`. The deployed digests are unchanged.

## W6 (optional). An operator build

From the observing shell, which has Go (at or above go1.27.4) and a checkout of the walked commit:
```bash
"$WALK/bin/farcast" redeploy "$INSTANCE" --source <the checkout> --yes
```
- *Expect* both images built, pushed under `source-<12 hex>`, and `origins` showing `origin: operator` with the Go on that shell's `PATH` (`metadata.yaml` also records the checkout path; never record it).
- Back in the walk shell, `farcast redeploy "$INSTANCE" --yes` **keeps** the operator build, and its note names both Go versions and `--embedded`.
- Then `farcast redeploy "$INSTANCE" --embedded --yes` replaces it with the carried images, and says so. `running deployment/fatline` is `carried`'s again; `origins` shows `embedded`.

*(2026-11-14: with exactly go1.27.4 on the observing shell's `PATH`, the operator build of the walked commit is byte-identical to the carried images, with the same manifest digests. So the deployed digests never change. `--embedded` then changes only the record, from `operator` to `embedded`, and prints no replacement note, because the note is printed only when the deployed digest changes. To see "and says so", build with a Go other than the pinned one.)*

## W6b (optional, no extra cost). The skew guard

Only if a second release farcast of another version is at hand, copied to `$WALK/bin/farcast-other`, whose carried `fatline` and `shrike` manifests both differ from the walked one's. Two releases whose components' source and Go did not change carry the same images, and the same image from another version is no skew. Check it in the observing shell:
```bash
carried_other() { "$WALK/bin/farcast-other" -o json version | grep -o '"name":"[a-z]*","go":"[^"]*","manifest":"sha256:[0-9a-f]*"'; }
diff <(carried | grep -E '"name":"(fatline|shrike)"') <(carried_other | grep -E '"name":"(fatline|shrike)"')
```
Both lines must differ. Otherwise skip W6b and record why: "the other release carries the same fatline or shrike image". In the walk shell:
```bash
farcast-other -o json redeploy "$INSTANCE" --yes | grep -o '"kind":"[a-z_]*"'
```
*Expect* `"kind":"version_skew"`, and nothing changed. The kind is printed only in JSON mode. The message itself names image paths, so do not record it: it names both farcast versions and both Go versions and says `Pass --embedded to replace it.`, followed, when `farcast-other` carries an older Go than the deployed image's, by a sentence saying it would put back that older Go. Then `farcast-other redeploy "$INSTANCE" --embedded --yes` replaces the images and says so. Then put the walked farcast's images back: `farcast redeploy "$INSTANCE" --embedded --yes`.

Then the break-glass pair, in the walk shell. On `redeploy`, `--fatline-image` names FatLine's image alone, and `--embedded` beside it governs Shrike's:
```bash
FL=$(awk '$1=="fatline_digest:"{print $2}' "$STATE/instances/$INSTANCE/metadata.yaml")   # the image FatLine runs now; never print it
farcast-other -o json redeploy "$INSTANCE" --fatline-image "$FL" --yes | grep -o '"kind":"[a-z_]*"'
farcast-other redeploy "$INSTANCE" --fatline-image "$FL" --embedded --yes
```
*Expect* `"kind":"version_skew"` from the first, now Shrike's refusal alone, and nothing changed. The second is accepted, and deploys FatLine's image as given: in the observing shell, `running deployment/fatline` prints FatLine's digest unchanged and then `farcast-other`'s carried `shrike` manifest; `origins` shows `fatline` as `origin: named` and `shrike` as `origin: embedded` with `farcast-other`'s version; and the only replacement note names `shrike`. Then put the walked farcast's images back once more: `farcast redeploy "$INSTANCE" --embedded --yes`.

## W7. `farcast release`

In the walk shell: `farcast release "$INSTANCE" --delete-data --yes`.
- In the observing shell, verify against the cloud, not local state, that clusters, registries, buckets, forwarding rules, addresses, target pools, disks and VMs are all zero. The registry repository goes with the instance.
- `rm -rf "$WALK"`.
- Once the Results table is filled in, delete the release this walk used: R0's kept `$R` (which holds `$REL`), or the directory W0 step 2 made for it.

---

## Results

W0–W7 walked 2026-11-14 on the dev Mac, against instance `$INSTANCE`, with placeholders only. R0 has not run: it is the operator's step on the Ubuntu keeper VM.

| Step | Result | Notes |
|---|---|---|
| Commit | ✅ | `44890cb` (`44890cb555fdb26636da222b8a61da92cd44a569`), on `origin/main` before the walk; walked from a clean tree |
| R0 revision and tags match on both hosts | Not run | R0 is an operator step on the keeper VM |
| R0 three builds identical, Mac | Not run | sha256 of `SHA256SUMS`: not run as R0. W0's single build is in the W0 row below |
| R0 three builds identical, VM | Not run | sha256 of `SHA256SUMS`: ; `uname -srm`: |
| R0 Mac and VM identical | Not run | |
| R0 `go version -m` lines | Not run | |
| W0 `./check.sh` | ✅ | `check passed: root + sdk/go + Apple client · go1.27.4 · golangci-lint 2.15.0 · 31 vendored modules · Swift 6.4.2 · model: not run (--model)` |
| W0 `shasum -c`, `go version -m` | ✅ | W0 step 2's own build, not R0's: 14 of 14 `OK`. `-tags=farcast_embedded`, `vcs.revision=44890cb555fdb26636da222b8a61da92cd44a569`, `vcs.modified=false`, go1.27.4. sha256 of its `SHA256SUMS`: `9a845ac6924b03dce66752deb0d998c7951a39eaa0d3bddcc693809c5c89a822` |
| W0 `command -v go gofmt` printed nothing | ✅ | The walk shell's `PATH` was `$WALK/bin:$WALK/tools:/usr/bin:/bin`, its working directory `$WALK`, and no checkout was reachable from it. gcloud ran there without a finding |
| W0 `farcast version`, four components | ✅ | Four components, each go1.27.4, on linux/amd64. First 12 hex of each manifest: datasphered `af98339c72cb`, fatline `6022502be77f`, shrike `62bff3f232f4`, technocore `1cc8e8e6522b` |
| W1 install | ✅ | Finished as on Phase 5. Run without a terminal, it needed `--project` and `--yes` (W1's note) |
| W2 connect: no build prompt, carried digests deployed, `embedded` recorded | ✅ | fatline and shrike were pushed as "the image this farcast carries" (go1.27.4, the carried digests), with no build prompt. `running deployment/fatline` printed `carried`'s fatline and shrike manifests. Version tag at the carried digest: yes, for both, and no `source-…` tag. `origins`: fatline and shrike `embedded`, go1.27.4, the walk farcast's version |
| W3 kernel deploy | ✅ | The carried technocore was pushed, with no build prompt. `running deployment/technocore` is `carried`'s technocore manifest, the version tag under `system/technocore` holds it, and `origins` shows `embedded` |
| W4 storage deploy, unseal, `world` `go` ×4 | ✅ | The grant was printed before the keyholder was applied, and applied with gsutil (W4's note). `running statefulset/datasphered` is `carried`'s datasphered manifest, recorded `embedded`. Unseal: 2 of 2 replicas at generation 1. After the operator typed `pin-gcloud` with `"$WALK/bin/farcast"`, `origins` still showed all four `embedded`. `world` `go`: fatline `go1.27.4`, technocore `go1.27.4`, shrike `go1.27.4`, datasphered `go1.27.4` |
| W5 redeploy reuses, no upload | ✅ | "already holds the image this farcast carries" for fatline and shrike, and no push. The tags, versions and update times under `system/fatline` and `system/shrike` were unchanged, and so were the deployed digests |
| W6 operator build kept, then replaced | ✅, except "says so" | Built on the observing shell's go1.27.4 from a clean checkout of 44890cb. Both images were pushed under `source-<12 hex>` and are byte-identical to the carried ones. `origins`: `operator`, go1.27.4. The walk shell's `redeploy` kept them, and its note named both Go versions and `--embedded`. `--embedded` put `origins` back to `embedded` with `carried`'s digests running, but printed no replacement note, because no digest changed (W6's note) |
| W6b skew guard; `--fatline-image` with `--embedded` replaces Shrike alone | Skipped | No second release farcast of another version is at hand. 44890cb is the first commit with `farcast-release`, so no other release carries different fatline and shrike images |
| W7 release, nothing left billing | ✅ | `release` reported the cluster, registry and bucket deleted after 5–6 minutes. Checked against the cloud afterwards: clusters, registries, buckets, forwarding rules, addresses, target pools, disks and VMs all 0 (also 0 before W1). The local record was removed, `$WALK` was deleted, and the release was deleted once this table was filled in |
