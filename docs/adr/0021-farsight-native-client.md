# ADR 0021 — FarSight's Client: Native Shells, Apple First

**Status:** Accepted (2026-11-11). Decision 2 amended the same day: the app world map replaces tiling as the base layout. Decision 9's first step has begun — `farsight/client/apple/` holds FarSightKit and the FarCast app target, drawing the map against an illustrative fixture. Decision 9's Connected view is built on macOS (2026-11-12) and awaits its no-cost rehearsal and first live read; nothing else below is built. Decisions 2 and 9 amended, and decision 6 corrected, 2026-11-12: a group is a namespace labelled with its repository; a read-only Connected view on macOS comes before 7.1; tile ingress and device leaves are decided together; cluster calls also need `gcloud`, and every one runs under a pinned gcloud account. This ADR depends on [ADR 0020](0020-instance-pki-ecdsa-p256.md): without it, no Apple client can reach FatLine on stock APIs. The tile-path evidence below comes from a probe on macOS 27 and the iOS 26.0 simulator, with no packet capture and no physical device. visionOS was not probed.

**Date:** 2026-11-11

**Relates to:**
- **Supersedes** the client half of [ADR 0002](0002-backend-language-strategy.md) decision 1 (*"FarSight's GUI client remains Electron + TypeScript"*) and [`AGENTS.md:78`](../../AGENTS.md).
- **Re-sequences** [PLAN](../../PLAN.md) Phase 7 ahead of Phase 6.
- **Consumes** ADR 0020's P-256 identities and its enrolment by request.
- **Constrained by:**
  - [ADR 0005](0005-fatline-data-plane-ingress.md): the tunnel is the only way in;
  - [ADR 0006](0006-connect-bootstrap-kubectl.md): kubectl;
  - [ADR 0007](0007-instance-owned-image-registry.md): images derived from Git on the operator's machine;
  - [ADR 0008](0008-in-cluster-key-delivery.md): the keeper;
  - [ADR 0009](0009-technocore-kernel-and-cost-metering.md): tiers, the floor, what survives a cost shutdown;
  - [ADR 0018](0018-thin-device-storage.md): the thin device;
  - [ADR 0019](0019-what-the-cluster-tells-its-provider.md): what the provider logs.
- **Names three follow-up ADRs it does not decide:**
  - tile ingress through FatLine;
  - a read route for instance state;
  - device leaves (ADR 0018 decision 2).

---

## Context

The operator's brief, 2026-11-11: build FarSight before AllThing *"so that FarCast will get a face"*, and reconsider Electron. *"Farcast could have one client app for Mac OS, iOS, VisionOS, Android and Windows … I may want to consider using the native languages for those platforms giving me the best integration with the host platforms. I would start with the Apple ecosystem so maybe Swift?"*

Electron exists only on paper. [`farsight/client/`](../../farsight/client/) is a `package.json`, a `tsconfig.json` and an empty `src/`. The choice is written into `AGENTS.md:78`, `README.md:147,198`, `farsight/README.md:7,11`, `farsight/cli/README.md:19`, ADR 0002 (lines 13 and 67) and `PLAN.md:430-435,526,537`. Changing it costs edits, not code.

### Nothing in Phase 7 needs AllThing

The only Phase 7 line that names AllThing is 7.3's *"AllThing chat as a built-in tile"* (`PLAN.md:450`). [`allthing/README.md:9`](../../allthing/README.md) lists the FarSight GUI tile as out of scope. [ADR 0012](0012-allthing-private-inference-first.md) defers *"a chat endpoint on a FarSight server that does not yet exist"* (line 164). So the reorder is feasible, and the one dependency runs the other way: AllThing's chat waits for 7.2. Phases 1–5 are closed and walked (PLAN, 2026-11-10).

### Electron, re-assessed (2026-11-11)

**Against:**
- **It can't reach the targets.** v45.3.0 (Chromium 156) ships for macOS, Windows and Linux only, with no iOS, iPadOS, visionOS or Android build.
- **Its patch cadence clashes with having no update server.** Six v45 releases came out between 2026-10-27 and 2026-11-10. Four of them backported Chromium and V8 fixes, and the other two updated Chromium. Chrome has been on a two-week stable cycle since M153. FarCast has no update server to deliver any of them.
- **Its toolchain is a large npm surface on the credential machine.**
  - *Size:* resolving the lockfile, Electron Forge with TypeScript and Vite lists 279 packages, of which about 234 install on an Apple-silicon Mac. electron-builder with electron-updater lists 351 (about 307).
  - *Outside the lockfile:* Electron's own binary is then fetched from GitHub, outside the lockfile's integrity hashes.
  - *Why it matters:* all of that would sit on the machine holding cloud admin credentials and the CA key, while self-propagating npm worms that harvest cloud credentials have been active since 2025. FarCast counts its 31 vendored Go modules ([`check.sh`](../../check.sh)) because that surface is a security property (ADR 0006).
- **Its native access is thin.** `safeStorage` keeps a key in the Keychain and offers no Secure Enclave or access-control option. WidgetKit and App Intents need separate Swift targets anyway.

**What Electron does better, stated rather than buried:**
- `protocol.handle` can capture `https`.
- `setWebRTCIPHandlingPolicy('disable_non_proxied_udp')` keeps WebRTC inside a proxy.
- Its browser process returns no Safe Browsing service, component updater, variations or metrics service. Its one default call home is the spellchecker's Hunspell download from a Google CDN on Windows and Linux, which can be disabled or redirected.

**Tauri 2** (2.12.5) adds iOS and Android but not visionOS. On mobile it has no multi-webview, proxy configuration or TLS hooks.

### What reaches the five targets

- **No cross-platform toolkit has a native visionOS target.**
  - Flutter runs there only as an iPad-compatible app.
  - Kotlin/Native and Compose Multiplatform have no visionOS target.
  - .NET MAUI, Avalonia 12 and Tauri do not list it.
  - React Native's visionOS fork stalled at 0.79 in September 2025.
- **SwiftUI covers the Apple platforms.** It targets macOS, iOS, iPadOS and visionOS, and from OS 26 WebKit ships a SwiftUI `WebView`/`WebPage` on all four.
- **Swift beyond Apple:**
  - *Android:* an official Swift SDK since Swift 6.3 (2026-03-24), with no UI layer. Skip has been free and Apache-2.0 since 2026-01-21 and renders SwiftUI as Jetpack Compose, but its WebView module is immature.
  - *Windows:* the toolchain is supported, but no mature UI path exists.
    - `swift-winui` was archived in October 2025.
    - Arc for Windows, a shipped Swift/WinUI app, stops working on 2026-12-22.
    - SwiftCrossUI has a work-in-progress WinUI backend with no WebView.
- **Every option needs per-platform native code to force a web view's traffic through the tunnel:** `WKWebsiteDataStore.proxyConfigurations` on Apple, androidx `ProxyController` on Android, `WebResourceRequested` or proxy arguments in WebView2. A cross-platform UI framework therefore removes less native code than it appears to.

### The tile path on Apple — probed

**Setup:**
- *Platforms:* macOS 27 and the iOS 26.0 simulator.
- *Proxy:* each page's data store had `proxyConfigurations` pointing at an HTTP CONNECT listener on 127.0.0.1 that required credentials, with failover off.

**Findings:**
- **Everything HTTP-shaped went through the listener as CONNECT.** That covered `fetch`, images, `<video>` and WebSocket, to any hostname, plain `http://` included. Basic proxy credentials arrived after a 407.
- **`http://<app>.localhost` gets a per-app secure context without TLS.** It was sent to the proxy, and the page saw `isSecureContext`, `serviceWorker` and `crypto.subtle`. WebKit treats `*.localhost` as potentially trustworthy. `http://app.internal.test` was proxied but was not a secure context.
- **`127.0.0.1` origins bypassed the proxy.** Cookies are not isolated by port either, so loopback-IP origins are out.
- **WebRTC leaked.** STUN binding requests left directly over UDP, 18 packets from the simulator, and no public `WKPreferences` or `WKWebpagePreferences` switch stops it.

**What the documentation and source add:**
- **WKWebView cannot do FatLine's mutual TLS through a proxy.** It never runs the TLS verify or challenge blocks for the proxy hop (WebKit bug 293611, open, last changed 2026-03-04; Apple DTS forum thread 751750). So an in-app bridge must do the mutual TLS.
- **Set a store's proxy before its first load and never change it.** Changing it on a live store was unreliable until a WebKit trunk fix on 2026-10-19 (bug 316948), and which OS ships that fix is unknown.
- **`WKURLSchemeHandler` cannot carry tiles.** It refuses `http`, `https`, `ws` and `wss`, and WebSocket cannot run over a custom scheme.
- **Safe Browsing is on by default and must be turned off.** `WKPreferences.isFraudulentWebsiteWarningEnabled` defaults to true, and WebKit passes the full URL to Apple's Safe Browsing framework with no scheme filter.
- **`<link rel=dns-prefetch>` probably reaches the device resolver despite a per-store proxy.** That conclusion comes from source only. A content-rule block suppresses it.

### What a face needs from the backend, whatever the language

1. **Most dashboard data does not travel through FatLine today.**
   - *Reached through kubectl:* `costs`, `usage`, `ps` and `logs` read ConfigMaps and workloads through a `kubectl` subprocess authenticated by `gke-gcloud-auth-plugin` ([`costs.go:82`](../../farsight/cli/internal/cli/costs.go), [`usage.go:116`](../../farsight/cli/internal/cli/usage.go), [`ps.go:79`](../../farsight/cli/internal/cli/ps.go), [`logs.go:91`](../../farsight/cli/internal/cli/logs.go)). Each read is an IAM-authenticated request to the provider-run API server, which the provider can log (ADR 0019).
   - *Reached through the tunnel:* only storage state, FatLine status and Shrike's network picture.
   - *Missing entirely:* TechnoCore serves no HTTP, and keeper-fleet state lives only on each device.
2. **No inbound route reaches an application.**
   - FatLine mounts its status probe and one stream handler ([`fatline.go:218-225`](../../fatline/fatline.go)).
   - Behind that handler is a closed, deploy-time list of routes, today `datasphered` and `shrike` ([`fatline/stream.go:28-73`](../../fatline/stream.go)).
   - Application Services are ClusterIP on an assumed port 8080, and their NetworkPolicy admits only same-namespace pods ([`planck/translate/workload.go:204-237`](../../planck/translate/workload.go)).
3. **No second device can connect.**
   - The public tunnel admits only the operator leaf and keeper leaves ([`fatline/admit.go`](../../fatline/admit.go)).
   - A keeper may open only the routes in `KeeperRoutes`, today the keyholder's ([`fatline.go:59-61`](../../fatline/fatline.go), enforced at [`stream.go:136-141`](../../fatline/stream.go)).
   - `DeviceURI` exists, but nothing issues a device leaf (ADR 0018, line 96).
4. **The CLI is not a GUI back end yet.**
   - *Flows need more than the binary.* `connect`, `kernel deploy`, `storage deploy` and `redeploy` build FarCast's system images from a farcast checkout with the local Go toolchain whenever the instance's registry lacks them ([`fatline.go:262-310`](../../farsight/cli/internal/cli/fatline.go), [`image/compile.go`](../../farsight/cli/internal/image/compile.go); ADR 0007), unless `--fatline-image` names a prebuilt image. Every cluster call also execs `kubectl` and, through it, `gke-gcloud-auth-plugin` from PATH ([`cluster/cluster.go:30-43`](../../farsight/cli/internal/cluster/cluster.go)).
   - *Gates need a terminal.* Under `-o json`, or with stdin not a terminal, every operator gate refuses unless `--yes` is passed, and `--yes` skips it. That covers connect's carrier cost, run's external-access review, release's scope summary and secret deletion ([`connect.go:413-420`](../../farsight/cli/internal/cli/connect.go), [`run.go:713-732`](../../farsight/cli/internal/cli/run.go), [`release.go:416-433`](../../farsight/cli/internal/cli/release.go)). With `--yes`, release returns before it prints what becomes unreadable. Install prints progress only to an interactive or verbose terminal, as prose.

## Decisions

**1. FarSight is one product with one wire contract and a native shell per platform family. Electron is retired as the planned client.**
- *The contract:*
  - FatLine's tunnel: HTTP/2 over mutual TLS 1.3 with ADR 0020's P-256 identities;
  - its stream routes;
  - the read route (follow-up ADR);
  - ADR 0020's enrolment request;
  - the keeper protocol;
  - on macOS, the bundled CLI's JSON (decision 6).
- *The reference implementation:* Go, for every part.
- *The clients:* implementations of the contract, held to it by conformance vectors (decision 7), not by a shared runtime.

**2. Apple first: one Swift/SwiftUI codebase for macOS, iPadOS, iOS and visionOS.**
- *Location:* the code lives in `farsight/client/apple/`, and the Electron scaffold is removed.
- *Package:* logic sits in a local SwiftPM package that builds and tests headlessly.
- *Project:* app targets live in an Xcode project that uses folder-synchronized groups (Xcode 16 and later), so adding a file does not churn the project file. No project generator such as XcodeGen or Tuist is used; a generator would be a tool dependency.
- *Platform-specific code stays in scenes and windows:*
  - The app world map inside one window is the common base (amended below).
  - Where a platform supports several windows (macOS, iPadOS, visionOS), detaching a tile into its own window uses `WindowGroup` and `openWindow`.
  - The iPhone shows one app at a time, and swipes to the neighbour the map places beside it.
  - macOS adds `MenuBarExtra` and `Settings`, and visionOS adds ornaments. Those are confined to their platforms because their availability is (`Window` is macOS 13 and visionOS 26, not iOS; `defaultWindowPlacement` is not available on iPadOS).

*Amended 2026-11-11: the app world map.* The operator chose the base layout from the prototype canvas, over tiling:
- **Nothing is hidden.** Every app, FarCast's own components included, is a panel on one freeform two-dimensional map. The operator never switches apps; the camera flies to where an app is, and a stopped app keeps its place.
- **Repos are places.** One Git repository is one namespace and one group, which the operator moves as a unit (amended 2026-11-12, below: a group is a namespace, labelled with its repository). Each instance is its own walled territory, with nothing drawn between instances because nothing runs between them.
- **Connections are drawn and graded by evidence:** counted by FatLine, declared only, refused at the wall, or decided but not built. Lines that cross a wall pass through its gate, so no line suggests a path FatLine does not see.
- **A few panels are live.** Only panels drawn large enough to use are live, a handful at a time; the rest show a last frame, marked as such.
- **FarCast's own components are panels like any app.** Their surfaces are decision 6's native operator surfaces, not web tiles.
- **The HUD is Liquid Glass, the map is not.** Instances, alerts, the connection legend, the minimap, the app strip and the jump palette float over the map in glass; the map is content. visionOS has no `glassEffect`, so the HUD falls back to `glassBackgroundEffect` there.
- **App-to-app traffic goes through FatLine** (operator decision, 2026-11-11, to be recorded in its own ADR). Until it is built, the map draws such lines only on an illustrative group, labelled "decided, not built".

*Amended 2026-11-12: a group is a namespace, labelled with its repository.* "One Git repository is one namespace and one group" is not what `run` does.
- **Why the old sentence fails.**
  - A namespace is the manifest's name, or `--namespace` ([`run.go:202-205`](../../farsight/cli/internal/cli/run.go)). A repository with several manifests is therefore several namespaces.
  - Two repositories whose manifests share a name land in one namespace. The second run then replaces the first one's egress entries ([`runpolicy.go:35-43`](../../farsight/cli/internal/cli/runpolicy.go)). An application of the same name also reuses the first one's storage scope, and so reads that application's data ([`run.go:449-456`](../../farsight/cli/internal/cli/run.go)).
- **One group per namespace.** The map draws a group for each namespace and labels it with the repository `run` recorded for it.
  - This departs from "repos are places": a repository with several manifests becomes several groups, which the map does not yet move as one unit.
  - Whether groups that share a repository move together is the operator's call.
- **The record stays on the operator's machine.** `run` records the repository, ref, commit and manifest digest on the operator's machine, never in the cluster.
  - The provider already keeps the repository and commit for 400 days, through the fetch and build Job bodies (ADR 0019). A Namespace annotation would add a standing copy, plus another full-body entry in that log.
- **`run` refuses a namespace recorded under another repository.** It refuses unless the operator explicitly says to replace it, and it names both repositories.
- **What this does not catch.** The record belongs to the machine that made it.
  - A deploy from another machine is not caught, and this Mac's map may then label the group with a repository that no longer runs there.
  - A namespace with no record here is accepted by the first `run` from any repository. That covers every namespace deployed before this change, and any whose record was lost with the config directory. Such a group is drawn with its namespace and "repository not recorded on this Mac".
  - The iPhone, iPad and Vision Pro clients never hold the record, so they label groups by namespace only.

**3. System frameworks only.**
- *Allowed:* SwiftUI, WebKit, Network, Security, CryptoKit, BackgroundTasks, UserNotifications, and WidgetKit or App Intents where used. ADR 0020's enrolment request is a template built with these.
- *Third-party Swift packages:* none. The first one needs an ADR, as the vendored-module count does for Go. That rule covers an update framework such as Sparkle too.
- *Offline check:* with nothing to resolve, the Swift build stays offline, as `check.sh` is today (`GOPROXY=off`).
- *Telemetry:* the app ships no crash reporter and does not use MetricKit.

**4. The guardrails are part of `./check.sh`.**
- *Language settings:*
  - Swift 6 language mode with complete strict concurrency.
  - `-strict-memory-safety`, with its diagnostics promoted to errors.
- *Source gate:* refuses `@unchecked Sendable`, `nonisolated(unsafe)` and `unsafe` outside a reviewed allowlist. Strict memory safety did not flag `@unchecked Sendable` in a test on 2026-11-11, so the gate does that part.
- *Full builds, never `-typecheck`:* Swift reports region-isolation races during SIL, which `-typecheck` never reaches.
- *Tests:* Swift Testing under `swift test` for the package, and `xcodebuild test` for the app on a macOS destination and an iOS simulator.
- *A missing toolchain fails the check,* as a missing `golangci-lint` already does. `./check.sh` therefore requires a Mac with Xcode.

**5. Tiles are WebKit behind an in-app loopback bridge** (the probed path), and each tile reaches only its own application.

- **One store per application.**
  - Each application gets its own `WKWebsiteDataStore`. Its proxy is set before the first load and never changed on a live store.
  - On iPhone, iPad and Vision Pro the store is non-persistent, one per application per launch, unless the operator opts that application in.
  - A persistent store (`forIdentifier:`, macOS 14, iOS 17, visionOS 1) has its directory excluded from backup on every platform, with the exclusion read back. Otherwise application plaintext in cookies, storage and caches would reach a backup.
  - `farcast release` and device removal call `removeDataStore(forIdentifier:)` for every store of that instance.
- **The bridge.**
  - `proxyConfigurations` points at a Network.framework HTTP CONNECT listener on 127.0.0.1, with failover off.
  - Each store gets its own proxy credential (random, at least 128 bits, compared in constant time).
  - The bridge binds that credential to exactly one authority, `<app>.localhost`, and refuses any other CONNECT on it with 403.
- **Where authorities come from.**
  - They come from the tile registry, never from page input.
  - No authority maps to a system route (`datasphered`, `shrike`, the planned `allthing`, the keyholder), and an application name that collides with a system route name is refused.
- **Origins.** An application's origin is `http://<app>.localhost`, never `127.0.0.1`.
- **The hop to FatLine.**
  - The bridge carries each CONNECT over one mutual-TLS session, using URLSession or Network.framework with a P-256 identity (ADR 0020).
  - The application's name rides inside the tunnel as the CONNECT authority, never as SNI. Per-app SNI would show the network and the provider which applications exist and which tile is in use.
  - The bridge never presents the operator leaf or a keeper leaf. It presents a leaf that FatLine admits to tile routes only, which the device-leaf ADR defines. Until that leaf exists, the bridge reaches only local test servers (decision 9).
- **Hardening.**
  - `isFraudulentWebsiteWarningEnabled = false`.
  - Each store's content rule list blocks every load except to its own `<app>.localhost`, which also stops DNS prefetch.
  - WebRTC is removed at document start in every frame by a user script. That is best effort: a page can try to reach a fresh realm, which the tile gate attacks (Verification). It stays only until WebKit gains a public switch.
  - No `WKURLSchemeHandler` for application content.
- **Navigation and UI delegates deny by default.**
  - No popup web views are created.
  - Nothing is handed to the system browser or `openURL`.
  - A navigation to anything but the tile's own `<app>.localhost` is cancelled. That also keeps app and universal links from opening.
  - Non-http schemes are refused.
  - Downloads are refused.
  - Camera, microphone, location and file-picker requests need an explicit operator grant per application.
- **No "all traffic goes through FatLine" claim** until each platform family's packet capture shows zero direct egress (Verification). Until then, FarSight's documentation lists which channels are proven.
- **FatLine's half,** how a route reaches an application, is the tile-ingress ADR. That ADR must:
  - carry the tile's application identity to FatLine, so admission does not rest on the client's whole authority;
  - keep FatLine copy-only on hostile bytes ([`fatline/stream.go:97-103`](../../fatline/stream.go));
  - amend ADR 0005's closed route list and Planck's NetworkPolicy.

**6. Operator surfaces are native SwiftUI; application UIs are web tiles.**

The dashboard, the install wizard, connect and release, keeper custody, and seal/unseal are SwiftUI views over JSON. The dashboard covers expected, confirmed and limit cost, applications, seal state and the keeper fleet. Native views are also what can feed a menu-bar status, a widget or a cost notification, which is the host integration the brief asks for. Native operator surfaces meet VoiceOver and Dynamic Type from the first build. Localisation is deferred.

**On macOS, the app bundles the Go `farcast` binary and drives it.**
- *What goes through it:* every flow that holds cloud credentials, the CA key or the keyring. That covers install, connect, release, run, redeploy, storage deploy and key operations, secrets, keeper enrolment and kernel deploy. Those flows keep one implementation, the one already walked, once the CLI has the three things below.
- **The CLI gains a consent protocol.**
  - *The plan step:* every command with an operator gate gains a `--plan` step. It emits, as JSON, the same facts the interactive prompt prints, and changes nothing. The facts are: cost and carrier figures, declared egress, release scope with what becomes unreadable, and the keepers it cannot reach.
  - *The digest:* the plan carries a digest, and the executing call accepts only `--confirm <digest>`. The CLI refuses if the facts changed, so what the operator saw is what runs. Run's plan binds the commit and manifest digest the in-instance fetch read.
  - *No bare `--yes`:* the shell renders the plan natively and never passes `--yes` on the operator's behalf.
  - *Progress:* long-running commands emit progress as newline-delimited JSON events on a separate stream.
  - *Vectors:* plan, progress and error shapes get golden vectors (Verification).
- **The CLI's environment is explicit.**
  - *What the flows need:* image builds need a farcast checkout and the Go toolchain (Context, item 4), and cluster calls need `kubectl` and `gke-gcloud-auth-plugin`, which authenticates through `gcloud`'s user session as whichever gcloud configuration is active (corrected 2026-11-12). A Finder- or Dock-launched app inherits launchd's minimal PATH.
  - *How the shell provides it:* it records the operator's checkout and each tool's absolute path once, confirmed in Settings, and passes `--source` and an explicit PATH to every invocation. Any PATH it guessed would be a binary-planting surface in a credential-holding process. *(Amended 2026-11-12:* every invocation, writes included, runs `kubectl` as the instance's pinned gcloud account, under the identity rules of the Connected-view amendment in decision 9. A work identity does more harm in a write than in a read.)
  - *What remains untrue:* "one app, one download" (AGENTS.md:33) is not yet true on macOS. Shipping prebuilt, signed system images instead would amend ADR 0007 and needs its own ADR.
- **One CLI, one state.**
  - *Sandbox and distribution:* the app is not App Sandboxed. It is distributed with Developer ID, outside the Mac App Store.
  - *Shared state:* its bundled CLI resolves the same config directory and keyring lock as a terminal `farcast`, and the app offers to put that binary on PATH so there is one.
  - *Version skew:*
    - System images are tagged with the deploying CLI's version ([`fatline.go:155`](../../farsight/cli/internal/cli/fatline.go)), so a bundled CLI and a terminal CLI would redeploy each other's components.
    - A system-component deploy therefore records the deploying CLI version in instance metadata.
    - The CLI refuses to redeploy over a different version without an explicit flag, and names both versions.
- **Background surfaces wait for the read route.** The menu bar, widgets and notifications read only the read route through FatLine, and do not exist until it does. They never poll through the bundled CLI. CLI-backed reads happen on operator action only, because each one is a provider-loggable API-server request (Context, item 1). (`farcast instances`, which reads only files on the Mac, also runs at launch: decision 9, amended 2026-11-12.)

**iPhone, iPad and Vision Pro are thin clients.**
- They never hold cloud credentials, the CA key or the keyring (ADR 0018's thin device), so the install wizard is macOS-only.
- They reach the instance through FatLine with a device leaf and read the read route. Until both exist, they run against fixtures.

**The read route must survive a cost shutdown.** It must be served from a tier a cost shutdown spares: kernel or system, ADR 0009 decision 6. The follow-up ADR chooses and justifies which, weighing that ADR 0009 decision 3 keeps the kernel deliberately small. Otherwise the dashboard vanishes exactly when the operator needs it. The follow-up ADRs also:
- name the tier of the 7.2 server and of the read route;
- add each standing Pod as a line in the instance floor ([`floor.go`](../../farsight/cli/internal/cli/floor.go)) and in the kernel's meter;
- state the change to the floor before anything is deployed.

**7. There is no shared runtime core; there is a shared contract with conformance vectors.**
- *What the Go tests emit:* golden vectors. That covers ADR 0020's P-256 PKI fixture and enrolment requests, the wire JSON of every read surface, the CLI's plan, progress, result and error shapes, and keeper ledger and budget cases.
- *Who consumes them:* each client's tests. That is how independent implementations stay in step without a Go runtime in every app.
- *Two questions are left open for 7.5.*
  - **How the iOS keeper's device side is built.**
    - *Preferred:* Swift against the vectors. That keeps one language under Swift 6's checks, signing directly with the Secure Enclave.
    - *Fallback:* the Go keeper as a c-archive. Probed on 2026-11-11, it builds and links for iOS. For visionOS it links only unofficially, with the `xros` clang as the C compiler, and was never run.
    - *gomobile is not an option:* it has no visionOS target.
  - **Whether the keeper and the viewer are one app or two.** If they are one, the tile bridge shares a process with the keeper leaf, and decision 5's rule that the bridge never presents a keeper leaf is enforced in code and tested.

**8. Android and Windows are decided when they start, from evidence already recorded.**
- **Android:** Kotlin/Compose, or Skip Fuse to reuse the SwiftUI code. Either way, the WebView is configured to opt out of Safe Browsing and metrics.
  - *Google's developer-verification rule:* since 2026-09-30 it is enforced for installs from seven listed stores in Brazil, Indonesia, Singapore and Thailand, and sideloads and ADB are not affected.
  - *2027:* Google plans to extend it to all apps on certified devices. After that, an unregistered app cannot be updated without the advanced flow or ADB.
- **Windows:** WinUI 3 with WebView2, or a bundled-Chromium shell. Privacy argues both ways:
  - *Against WebView2:* it collects "required" diagnostic data regardless of the Windows setting, and its Evergreen runtime updates itself from Microsoft unless the app ships a Fixed Version runtime.
  - *For Electron:* its browser process returns no Safe Browsing service, component updater, variations or metrics service. Its Hunspell download must be disabled or redirected.

  Swift on Windows is not a UI option today.
- **Either way,** whatever is chosen implements the same contract and passes the same vectors.

**9. FarSight moves ahead of AllThing.** The order:
1. **The Apple shell prototype, against fixtures.** Fixtures come from `farcast … -o json`. It covers the app world map, the dashboard and the wizard, with no backend change. *Begun 2026-11-11:* the map, its HUD and the core apps' first surfaces run on macOS and the iPad simulator. Their fixture is the prototype canvas's illustrative world, because no CLI command yet reports apps by namespace with the repository `run` recorded, or graded connections; fixtures move to CLI output as commands gain those fields. The wizard is not started. A read-only Connected view on macOS follows it (amended below).
2. **ADR 0020 implemented,** and Phase 5 Session A walked again.
3. **The CLI's consent protocol and explicit environment** (decision 6), walked from a terminal.
4. **7.1, the macOS shell** driving the bundled CLI, with the tile bridge tested against local servers.
5. **The tile-ingress ADR, with the device-leaf ADR or after it** (amended below), then 7.3: tiles reach real applications, behind the packet-capture gate. Device-leaf enrolment first gains a CLI consumer that is walked end to end before a GUI depends on it, per PLAN principle 3.
6. **The read-route ADR** (amended below), then 7.2. The read route first gains a CLI consumer that is walked end to end before a GUI depends on it, per PLAN principle 3. The FarSight server keeps the tile registry, sessions and layout state.
7. **The iPadOS, iOS and visionOS thin clients,** then the 7.5 keeper.
8. **Phase 6, AllThing.** Its chat endpoint lands on the 7.2 server, and its chat is an ordinary web tile.

*Amended 2026-11-12: a read-only Connected view on macOS comes before 7.1.* The operator brought it forward, after a review of what the map needs against what an instance holds.
- **What it is.** When the operator presses Refresh, the macOS app runs the operator's own `farcast` and draws what comes back. Anything that changes an instance still waits for step 3 and 7.1. On iPhone, iPad and Vision Pro the app keeps the fixture until those devices have a device leaf and the read route (decision 6).
- **Two new read-only commands.** `farcast instances` and `farcast world <instance>` were added on 2026-11-12, with their golden vectors, before the app used them. They are the one CLI change ahead of step 3.
- **Reads only. Nothing the provider can see happens except on the operator's action.**
  - The app runs exactly three commands: `farcast version`, `farcast instances` and `farcast world <instance>`.
  - Their flags are fixed in code. The one argument, an instance name, must be a name `instances` returned, and a test proves nothing else can be run.
  - `version` and `instances` read only files on the Mac and run at launch. `world` runs only when the operator asks.
  - Nothing runs on a timer. The menu bar, widgets and notifications still wait for the read route (decision 6).
- **The installed CLI, until 7.1.** This is a temporary departure from decision 6's bundled `farcast`, and it ends with 7.1.
  - Until the app bundles `farcast`, it runs the copy at an absolute path the operator confirms in Settings.
  - It refuses to read when `farcast version` names a different commit from the app's own build.
  - The app's own commit is written into its Info.plist at build time (`FARCAST_COMMIT`). A build without it, such as one from Xcode's Run button, reads nothing.
  - *What it gives up.* The bundled binary is covered by the app's signature. The installed one is whatever sits at that path, and a binary reports its own commit, so the check catches version skew, not a replaced binary. The installed copy is trusted exactly as a terminal `farcast` is: that adds no exposure the terminal does not already have, and removes none.
- **An explicit environment.**
  - The app records the absolute paths of `farcast`, `kubectl`, `gke-gcloud-auth-plugin` and `gcloud`, and the farcast and gcloud configuration directories, confirmed once in Settings.
  - The child process gets an environment built from an allowlist:
    - `HOME`, `TMPDIR` and the locale (`LANG`, `LC_*`) from the app;
    - `PATH`, made of the recorded tools' directories followed by the system's own read-only directories (`/usr/bin:/bin:/usr/sbin:/sbin`, on the sealed system volume). The CLI runs `kubectl` by bare name; the instance kubeconfig names the plugin by bare name; the plugin runs `gcloud` by bare name; and `gcloud` is a shell script that needs the system's utilities and finds its Python on `PATH`;
    - `CLOUDSDK_CONFIG`, set to the confirmed gcloud directory: the directory the CLI's identity guard reads and hands to `kubectl`.

    `--config` names the config directory, and stdin is closed.
  - It inherits nothing else from the app: not its `PATH`, and none of its `CLOUDSDK_*` variables, `KUBECONFIG`, `FARCAST_CONFIG_HOME`, proxy settings or `GOOGLE_APPLICATION_CREDENTIALS`.
- **The cloud identity is pinned.**
  - *How the plugin chooses an identity.* The auth plugin authenticates as whichever gcloud configuration is active (*Sentences corrected*, below). Before it asks gcloud, it returns `CLOUDSDK_AUTH_ACCESS_TOKEN` if that is set, or an unexpired token from its cache. That cache is keyed by the current context of the kubeconfig in `KUBECONFIG` (or `~/.kube/config`), not by account. It is not keyed by the `--kubeconfig` that kubectl was given either.
  - *What the instance records.* Each instance records the gcloud account it is read as.
    - The operator pins it once from a terminal, with `farcast instances pin-gcloud`, which refuses an account that no gcloud configuration pairs with the instance's project. The app shows only whether an account is pinned. The account itself stays in the instance's record and the terminal, so it never reaches the app's output or a captured listing.
    - It is never taken from whatever happens to be active.
  - *How every read runs.*
    - The CLI chooses a gcloud configuration whose account is the recorded one and whose project is the instance's. It never consults the active configuration. It reads gcloud's configuration files to choose, without running gcloud (ADR 0007).
    - `kubectl` runs with `KUBECONFIG` naming the instance's own kubeconfig, so the plugin's cache is keyed by the instance's own context.
    - It runs with `CLOUDSDK_ACTIVE_CONFIG_NAME` naming the chosen configuration, and with `CLOUDSDK_CONFIG` naming the directory the CLI read.
  - *Variables that never reach it:* `CLOUDSDK_AUTH_ACCESS_TOKEN`, `CLOUDSDK_CORE_ACCOUNT`, every other `CLOUDSDK_*` variable except the two the CLI sets, and `GOOGLE_APPLICATION_CREDENTIALS`.
  - *Refusal.* A read is refused before `kubectl` runs in three cases: the instance has no recorded account, no configuration matches, or the project is unrecorded. A Refresh never reads as a work identity that happens to be active.
  - *What remains.* A token the plugin cached within the hour for this instance's own context is reused, whichever account minted it. That needs `kubectl` to have run against this instance's kubeconfig under another account.
- **Reads never open the CA key or the storage keyring.** `instances` and `world` open neither. A test runs them against a config directory where both are unreadable.
  - Today `storage state` and the tunnel reads open the CA key, and `storage state` also opens the keyring. Those commands keep their behaviour.
  - `world` therefore cannot use today's tunnel opener (`usagenet.go:36-45`), which loads every mTLS file, `ca.key` included, through `LoadInstanceMTLS` (`config/instance.go:862-880`).
  - It gets an opener that reads only the CA certificate and the operator's client certificate and key, which is all `clientIdentity` uses (`connect.go:514-526`).
- **The contract has vectors.**
  - Every JSON shape the app decodes has a golden vector, errors included (decision 7, Verification 4). `go test` checks the vector against the CLI, and FarSightKit's tests decode it.
  - Errors carry a stable kind, so the map can tell "no tunnel", "no kernel", "version skew" and "signed out of gcloud" apart without parsing prose.
- **Walked before it is relied on.**
  - `farcast world` is walked end to end from a terminal before the app depends on it (PLAN principle 3).
  - The app's first read of a live instance follows a rehearsal that costs nothing, against a local FatLine and Shrike and a fake `kubectl`.
- **No standing cost.** A Refresh adds no standing cost and never runs `connect`. Its tunnel reads ride the carrier the instance already pays for. Without one, the counted lines are drawn as "no tunnel".
- **Honest drawing.**
  - A live map never shows the fixture's illustrative groups, apps or planned lines.
  - Spending is drawn as the kernel reports it, and is never recomputed in the app.
    - The accrued figure that enforcement compares against the kernel's own limit, at the kernel's level, is shown split. `confirmed` covers each closed window, with its date, or says "no confirmation yet". `expected` covers the open window.
    - The two are never shown as one undifferentiated total (ADR 0009 decision 4).
    - Beside them is what the meter does not see.
  - A counted line is labelled as a floor (ADR 0015), counted by one FatLine replica since it started, and the map names that replica (ADR 0022 decision 9).
  - Each instance shows when it was read. A section that could not be read says so instead of disappearing.
- **What a Refresh tells the provider and the network.**
  - Before `kubectl` runs, gcloud may refresh the account's access token at Google's OAuth endpoint. That tells Google the account, the time and the source address. gcloud may also run its own daily update check.
  - The `kubectl` reads go to the provider's API server, which terminates TLS. Data Access audit is off by default, but any parent folder or organisation can force it on. Where it is on, it records each get and list: caller, object, namespace, source address, user agent and time (ADR 0019). The objects read are in the provider's etcd already.
  - The Mac's resolver sees the control plane's `*.gke.goog` name (ADR 0004).
  - The tunnel reads show the provider the source address, the timing, the sizes and the SNI that names the instance, and nothing of their content.
  - That is why a read happens only when the operator asks for one.

*Amended 2026-11-12: tile ingress and device leaves are decided together.*
- **The conflict.** Decision 5's bridge presents "a leaf that FatLine admits to tile routes only, which the device-leaf ADR defines", and takes its authorities from the tile registry that 7.2 keeps. Step 5 put tiles before both.
- **Leaves move to step 5.** The device-leaf half of step 6 moves into step 5. It is written with the tile-ingress ADR, or before it, ahead of 7.3.
- **The registry, until 7.2.** The tile-ingress ADR decides where the macOS shell's tile registry comes from until 7.2's server exists. One candidate is the instance's `world` read, which takes nothing from page input.
- **What stays in step 6.** The read route and 7.2.

## What Apple still sees

Stated because *"blind to content"* is FarCast's standard, and installing a client on Apple hardware is not covered by it.

- **Installing.**
  - *macOS:* a published build is Developer ID-signed and notarized by Apple, so Apple sees each published build, and Gatekeeper may check online. A build the operator makes from source on their own Mac needs neither.
  - *iPhone, iPad and Vision Pro:* every route goes through Apple: the App Store, TestFlight, or ad hoc and development builds under a developer team. App Store downloads are logged against the Apple Account with hardware ID and IP, and kept at least as long as the account exists.
  - *So:* "zero central dependency" describes instances, not putting the client on an Apple device.
- **Running.**
  - The shell calls no Apple service itself, and WebKit's Safe Browsing is switched off.
  - If the user enabled OS diagnostics sharing, crash logs go to Apple. On App Store and TestFlight builds they also go to the publisher.
  - What else WebKit or the OS sends is not assumed. The capture gate proves or disproves it.
- **Waking a keeper.**
  - *What a push reveals:* an APNs push, even an empty one, shows Apple the device token, the app's bundle ID and the timing.
  - *What sending one requires:* the app publisher's credential. That means a copy on every instance or a central relay, and AGENTS.md rules out both.
  - *So:* the keeper never depends on push. Background refresh on iOS is heuristic, and a force-quit stops it. A keeper also cannot run after a reboot until the device has been unlocked once. PLAN 7.5 already calls a phone an odds-improver, not an SLO, and that stands.
- **Backing up.**
  - *Keychain items:* `…ThisDeviceOnly` items are backed up wrapped to the device's UID, not excluded. The exception is `WhenPasscodeSetThisDeviceOnly`, which needs an unlocked device and so cannot serve a background keeper.
  - *Keys and files:* a Secure Enclave key is device-bound. Files need `isExcludedFromBackup`.
  - *So:* 7.5's "excluded from backup by construction" means a Secure Enclave key plus excluded files, and nothing else.
- **Tile data.** A persistent tile store that is not excluded from backup would carry application plaintext into iCloud Backup, unless Advanced Data Protection is on. Decision 5 excludes them.

## Alternatives considered

- **Electron + TypeScript (the status quo).** Rejected for the reasons in Context: two of five targets, the npm surface on the credential machine, a patch cadence with no update server, and thin native access. It is kept as a candidate Windows shell (decision 8).
- **Tauri 2.** It has no visionOS target, its mobile builds lack multi-webview, proxy and TLS hooks, and its core is Rust, which ADR 0002 confines to the data plane.
- **Flutter, Compose Multiplatform, React Native, .NET MAUI, Avalonia.** None has a native visionOS target. Flutter's desktop platform views are weak, and web-view interception would still be per-platform native code.
- **Skip for everything.** It reaches only Android beyond Apple, and its WebView module is immature. Reconsider for Android (decision 8).
- **A server-composed web dashboard in a tile, with thin native shells.** It would be written once for every platform and would reuse the tile bridge. Rejected for Apple:
  - it cannot feed a menu bar, a widget or a notification;
  - it exists only while an in-cluster server runs, which a cost shutdown may stop;
  - the wizard and the keeper must be native regardless.

  The data API is shared either way. Reconsider if three native dashboards prove costly once Android and Windows start.
- **A Go core in every client, as a c-archive or c-shared library.** It would give one implementation of the protocol. Rejected as the default:
  - it puts a Go runtime and a second TLS stack in every app, outside Swift's checks;
  - gomobile has no visionOS target;
  - after ADR 0020, stock APIs suffice.

  It stays the 7.5 fallback (decision 7).
- **swift-nio-ssl to keep Ed25519.** A third-party package, made unnecessary by ADR 0020.

## Consequences

**Positive**
- One Swift codebase reaches every Apple device, visionOS included, with no third-party code and with compile-time data-race checks.
- The credential-holding Mac gains no package manager surface.
- Tiles use the platform's own engine with per-application isolation. WebKit's security fixes arrive with OS updates, so the tile engine does not depend on FarCast shipping anything. That is the direct answer to Electron's patch cadence.
- The operator's surfaces integrate with the host (menu bar, widgets, notifications, the Secure Enclave), which is the point of going native.
- The CLI's consent protocol makes the walked gates usable by any front end, not just a terminal.
- FarCast gets a face before AllThing, and AllThing's chat gets a home when it arrives.

**Negative**
- **Separate codebases.** Each platform family is its own codebase, so Android and Windows are new code when they come. The cost is verification more than typing, which is what the conformance vectors are for.
- **The CLI must change before the macOS shell can drive it:** the consent protocol, the explicit environment and the version record (decision 6). Until then the shell drives only read commands and fixtures.
- **"One app, one download" is not yet true on macOS.** The operator still installs `kubectl`, `gke-gcloud-auth-plugin`, `gcloud` and Go, and keeps a checkout.
- **The gate needs a Mac.** Since the first Swift code landed (2026-11-11), `./check.sh` requires a Mac with Xcode.
- **A Chromium-only web app can misbehave in a tile.** Tiles inherit Safari's web platform, not Chromium's.
- **The dev Mac is missing runtimes.** It has no visionOS simulator runtime and no iOS 27 runtime (installed: iOS 17.5, 18.1 and 26.0). visionOS work needs the runtime installed first, which is the operator's download to make.
- **Who signs and publishes the app is open, on every Apple platform.**
  - *macOS:* a Sofmon-published build needs Developer ID and notarization, and one an operator builds from source on their own Mac needs neither.
  - *iPhone, iPad and Vision Pro:* shipping needs a paid Apple Developer team. Ad hoc profiles last a year and free development profiles last 7 days.
  - *Why it matters:* the choice changes what Apple learns and who could ever send a push. It must be decided before the first build leaves the dev Mac.
- **No in-app updater.**
  - *How the operator updates:* by re-downloading or rebuilding a tagged release.
  - *Pinning the CLI:* the bundled `farcast` is built from the same commit, shown in About, and checked against `farcast version`.

**Sentences this ADR corrected on acceptance (2026-11-11).** Where a document describes something not yet built, the correction says "accepted, not yet built" rather than describing it as done.
- AGENTS.md:
  - `:78`;
  - `:79-81` gains a Swift guardrails bullet (decision 4);
  - `:33` says that on macOS one app is to carry the GUI and the CLI and the other Apple devices a thin client, and that on macOS this is not yet one download (decision 6);
  - the Key Design Decisions section gains a paragraph on this ADR.
- README:
  - `README.md:147,198`, and the Phase 7 row at `:21`;
  - `README.md:295`: "all traffic" becomes a goal, gated on the tile capture, with the proven channels listed;
  - `README.md:297`: the FarSight server keeps the tile registry, sessions and layout, and operator surfaces are native.
- `farsight/README.md:7,11`.
- `farsight/cli/README.md:19`.
- ADR 0002: a dated note at lines 13 and 67 (superseded for the client by this ADR), and at line 105 (Swift guardrails, decision 4).
- The `check.sh` header (lines 3–5): the Apple client's Swift guardrails join the gate with the first client code.
- **Found by the acceptance review and corrected the same day.** These sentences contradicted this ADR's rule on traffic claims, or the server's narrowed role:
  - *Traffic claims:*
    - AGENTS.md's FatLine and FarSight module bullets;
    - the README's FatLine section and module-table rows;
    - `docs/hyperion-reference.md:39`;
    - `fatline/README.md:3`;
    - the README's FarSight section (what each device runs; install is macOS-only; no channel proven yet).
  - *The server's role:* the "UX composition" wording in the README tree, `farsight/README.md` and `farsight/cli/README.md:5`.
  - *The tunnel:* `fatline/README.md:59,76` (the tunnel is a wire contract native clients implement).
  - *PLAN:* `PLAN.md:3` (phase order); 7.5's push and backup-exclusion bullets.
- PLAN:
  - 7.1 becomes the Apple shell (`PLAN.md:430-435`);
  - the Phase 7 deliverable's "all traffic proxied through FatLine" (`:468`) gains the same gate;
  - the dependency graph (`:526`);
  - principle 3's *"before the Electron app adds complexity"* (`:537`);
  - the Phase 6 and Phase 7 order, per decision 9.
- `farsight/client/package.json` and `tsconfig.json` are removed.

**Sentences corrected by the 2026-11-12 amendments.**
- **gcloud.** Decision 6's list of what cluster calls need, the "one download" consequence, `AGENTS.md:33` and `README.md:301` gain `gcloud`.
  - The auth plugin runs through gcloud's user session ([`phase-4-1-validation.md`](../runbooks/phase-4-1-validation.md), *The walk stalled on an expired gcloud user credential*; ADR 0006 already named gcloud beside it). So gcloud is a third tool, and the account it acts as is part of the environment.
  - Decision 6's environment now records that account for every invocation.
- **Repositories as groups.** Decision 2's "Repos are places" and the sentences that group the map by repository: `README.md:305`, PLAN 7.3, `farsight/client/apple/README.md:3`, and step 1 here and in PLAN. A group is a namespace labelled with its repository. `AppGroup`'s doc comment (`World.swift:65`) changes with the Connected view's code.
- **PLAN Phase 7:**
  - the status line said "not started" while step 1 had begun;
  - the order gains the Connected view and the moved device-leaf ADR;
  - the Connected view's read-only half comes before 7.1;
  - step 3's environment gains the pinned gcloud account.
- **The "no network" sentences** change when the Connected view's code lands, not before. These are the sentences that say the client reaches no network (`farsight/client/apple/README.md:5`), or that the map draws fixtures until the read route exists (`World.swift:7-8`, `FarCastApp.swift:6-7`) (changed 2026-11-12, with the Connected view's code).

**Sentences the decision 2 amendment corrected (2026-11-11).** "Tiling browser" and "tiling window manager" become the app world map in `README.md:196,297,305`, `PLAN.md:430,438,464-468,490,546`, `docs/hyperion-reference.md:63`, `farsight/README.md:3,7` and `farsight/cli/README.md:5`, and the `check.sh` header describes the Swift steps it now runs.

## Verification

1. **The ADR 0020 regression lives in this package.** Mutual TLS from URLSession and `NWConnection` to a Go test server built from the vectors, plus the negative test against Ed25519.
2. **The tile gate, per platform family,** recorded in a runbook.
   - *When:* it is passed on each platform family (Mac, iPhone, iPad, Vision Pro) before that family's client renders tiles.
   - *Setup:* a physical device and a packet capture on the uplink.
   - *The test page exercises:* `fetch`, images, video, WebSocket, a service worker, `dns-prefetch`, a popup, an external link, a custom scheme, a universal link and a download.
   - *WebRTC:* the page actively tries to obtain an `RTCPeerConnection` from a fresh `about:blank`, `srcdoc` or `javascript:` iframe and after `document.open`.
   - *Cross-tile:* a second tile on the same device names another application's authority and must get 403 from the bridge.
   - *Pass:* zero packets to any destination other than the FatLine carrier.
   - *Until it passes:* the "all traffic" sentence is not written for that family.
3. **The guardrails, shown by mutation.** A data race, an `@unchecked Sendable`, an unsafe pointer and a third-party package dependency must each fail `./check.sh`.
4. **The bundled-CLI contract.**
   - Each JSON shape the macOS shell parses has a golden vector: result, plan, progress and error. A CLI change that breaks the GUI then fails `go test`.
   - A plan whose facts change before `--confirm` is refused.
   - A run with no checkout and launchd's PATH fails with the CLI's named error, and never hangs or misreports.
5. **The Connected view** (decision 9, amended 2026-11-12). Each of these is a test that needs no cloud:
   - nothing but `version`, `instances` and `world` can be run, and `world` takes only a name `instances` returned;
   - the child environment drops what the parent set: `PATH`, `FARCAST_CONFIG_HOME`, `KUBECONFIG`, proxy variables, every `CLOUDSDK_*` variable and `GOOGLE_APPLICATION_CREDENTIALS` among it; the one `CLOUDSDK_*` variable the child has, `CLOUDSDK_CONFIG`, is the gcloud directory confirmed in Settings, never the parent's;
   - the `kubectl` that `world` runs gets `KUBECONFIG` naming the instance's own kubeconfig;
   - `instances` and `world` succeed with the CA key and the keyring unreadable;
   - a read under a gcloud account or project other than the instance's record is refused before `kubectl` runs;
   - with a token planted in the auth plugin's cache under another context, and `CLOUDSDK_AUTH_ACCESS_TOKEN` set in the parent, the bearer token a local fake API server receives is never either of them;
   - a live map refuses illustrative groups and planned lines.

   Then a rehearsal, from Finder, against a local FatLine and Shrike and a fake `kubectl`, before the first read of a live instance.

## Revisit triggers

- **WebKit fixes bug 293611,** or gains a public switch for WebRTC proxying. WKWebView might then do mutual TLS to FatLine itself, and the bridge could shrink.
- **A cross-platform toolkit gains a native visionOS target.**
- **Android or Windows work starts** (decision 8).
- **Three native dashboards prove costly.** That reopens the server-composed alternative.
- **Prebuilt, signed system images are proposed** (amending ADR 0007). The macOS app could then be one download.
- **Apple's distribution rules change,** in the EU or in notarization, or **Android's developer verification goes global** (2027).

## Sources

- Local probes on macOS 27 / SDK 27.2, Swift 6.4.2, Go 1.27.3 and the iOS 26.0 simulator, 2026-11-11: the TLS results in ADR 0020; the WKWebView loopback-CONNECT tile path; the Go c-archive for iOS and visionOS; the Swift 6 strict-memory-safety test. Verification step 1 and the tile-gate runbook replace them.
- WebKit — bug 293611 (proxy client auth): https://bugs.webkit.org/show_bug.cgi?id=293611 · bug 316948 (proxy change on a live store): https://bugs.webkit.org/show_bug.cgi?id=316948 · Apple DTS, forum thread 751750: https://developer.apple.com/forums/thread/751750 · `SecurityOrigin.cpp`, `NetworkRTCUDPSocketCocoa.mm`, `SafeBrowsingUtilities.mm`, main branch.
- Apple — `WKPreferences.isFraudulentWebsiteWarningEnabled`: https://developer.apple.com/documentation/webkit/wkpreferences/isfraudulentwebsitewarningenabled · SwiftUI `WebView`: https://developer.apple.com/documentation/webkit/webview-swift.struct · App Store & Privacy: https://www.apple.com/legal/privacy/data/en/app-store/ · APNs token-based connection: https://developer.apple.com/documentation/usernotifications/establishing-a-token-based-connection-to-apns · Keychain data protection: https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web · SE-0458, strict memory safety: https://github.com/swiftlang/swift-evolution/blob/main/proposals/0458-strict-memory-safety.md
- Electron — releases: https://github.com/electron/electron/releases · timelines: https://github.com/electron/electron/blob/main/docs/tutorial/electron-timelines.md · `safeStorage`: https://github.com/electron/electron/blob/main/docs/api/safe-storage.md · `browser_process_impl.cc`: https://github.com/electron/electron/blob/main/shell/browser/browser_process_impl.cc · spellchecker: https://www.electronjs.org/docs/latest/tutorial/spellchecker · Chrome's two-week cycle: https://developer.chrome.com/blog/chrome-two-week-release
- Tauri — https://github.com/tauri-apps/tauri (README, issue 9969) · wry proxy: https://github.com/tauri-apps/wry/blob/dev/src/wkwebview/proxy.rs
- Cross-platform coverage — Kotlin/Native targets: https://kotlinlang.org/docs/native-target-support.html · .NET MAUI platforms: https://learn.microsoft.com/en-us/dotnet/maui/supported-platforms · Flutter visionOS issue 128313: https://github.com/flutter/flutter/issues/128313 · react-native-visionos releases: https://github.com/callstack/react-native-visionos/releases · Avalonia 12: https://avaloniaui.net/blog/avalonia-12
- Swift beyond Apple — Swift 6.3: https://swift.org/blog/swift-6.3-released/ · Skip is free: https://skip.dev/blog/skip-is-free/ · Windows workgroup: https://www.swift.org/blog/announcing-windows-workgroup/ · swift-winui (archived): https://github.com/thebrowsercompany/swift-winui
- Android and Windows web views — WebView privacy: https://developer.android.com/develop/ui/views/layout/webapps/webview-privacy · androidx `ProxyController`: https://developer.android.com/reference/androidx/webkit/ProxyController · developer verification: https://developer.android.com/developer-verification · WebView2 data privacy: https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/data-privacy · Windows App SDK 2.0: https://learn.microsoft.com/en-us/windows/apps/windows-app-sdk/release-notes/windows-app-sdk-2-0

---

*This ADR is a living record. Revisit it on any trigger above, and when the first non-Apple shell starts.*
