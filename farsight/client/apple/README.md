# FarSight for Apple devices

One Swift/SwiftUI codebase for macOS, iPadOS, iOS and visionOS ([ADR 0021](../../../docs/adr/0021-farsight-native-client.md)). It draws the **app world map**: every app on one freeform map, FarCast's own components included, grouped by namespace and labelled with the repository it came from, with its connections drawn and graded by evidence. Nothing is hidden; the camera flies to an app instead of switching to it. The HUD over the map is Liquid Glass, and under everything lies a backdrop the glass picks its colour up from.

**State:** the prototype step (ADR 0021 decision 9, step 1). On macOS this includes the read-only Connected view (decision 9, amended 2026-11-12).
- On iPhone, iPad and Vision Pro the map runs against an illustrative fixture, and the app reaches nothing.
- On macOS the app itself opens no network connection and holds no key. It runs the operator's own `farcast`, at a path the operator confirmed in Settings, and only as three commands:
  - `farcast version` and `farcast instances`, at launch, which read only files on the Mac;
  - `farcast world <instance>`, only when the operator presses Refresh.
- That `farcast` reaches an instance as a terminal `farcast` does:
  - through `kubectl`, whose reads the provider's API server sees and may log;
  - through the instance's FatLine tunnel, which shows the provider its source address, timing, sizes and server name and none of its content.
- No tile shows a real app yet. Tiles wait for the bridge (decision 5) and the tile-ingress ADR.

## Layout

- `FarSightKit/` — a SwiftPM package that builds and tests headlessly.
  - `FarSightCore` — values only: the world snapshot and its validation, the standard arrangement, where everything is drawn, how connections are routed through the gates, the camera and its flights, the live-panel budget. Also the Connected view's contract: the `WorldReader` protocol a reader of instances implements; `Display`, which makes text from an instance safe to draw; the Connected view's adapter (`CLIDocuments`), which turns `farcast`'s JSON into a world; and its reader (`CLIReader`), which runs `farcast` through an executor the app supplies. It runs no process itself.
  - `FarSightUI` — the map and its HUD: panels at three levels of detail (marker, glance, full), the connection layers, the minimap, the app strip, the ⌘K jump palette, and the backdrop under them (`Backdrop/backdrop.heic`). Also `WorldFeed`, which holds what was read from each instance, and `ConnectedWorldScreen`, a window's map of it.
  - `FarSightFixtures` — `world.json`, two illustrative instances, and `FixtureReader`, which reads them as a reader of instances would.
  - `Tests/FarSightCoreTests/Vectors/` — the CLI's golden vectors, copied byte for byte from `farsight/cli/internal/cli/testdata/`; `./check.sh` refuses a copy that differs. They are test data and never ship in the app.
  - `Tests/FarSightTLSTests/` — ADR 0020's Apple regression ([ADR 0021](../../../docs/adr/0021-farsight-native-client.md) Verification 1), a test target with no dependency that no product links: mutual TLS from URLSession and `NWConnection` to Go servers on 127.0.0.1, the Ed25519 negative, and the enrolment request template against Go's request vectors (below). Its `Vectors/pki/` is a copy of FatLine's PKI vectors, `fatline/internal/crypto/testdata/pki/`, byte for byte; `./check.sh` refuses a copy that differs. Test data, never shipped: the keys in it are trusted nowhere else.
- `FarSight.xcodeproj` — the `FarCast` app target, one target for every platform, with folder-synchronized sources in `FarCast/`. No project generator.
  - `FarCast/FarCastApp.swift` — the app's scenes, on every platform.
  - `FarCast/ConnectedApp.swift`, `ProcessExecutor.swift`, `SettingsView.swift`, `SetupView.swift` — macOS only: the confirmed paths and the feed, the executor that starts `farcast` (Foundation `Process`, no shell), Settings, and the window shown before any paths are confirmed.
- `FarCast-Info.plist` — the build's commit only (`FarCastCommit = $(FARCAST_COMMIT)`); Xcode merges it with the keys it generates. It sits outside `FarCast/`, so it is never copied into the app as a resource.
- `unsafe-allowlist.txt` — the lines the source gate in `./check.sh` lets through. Empty.

## Run it

On macOS, build `farcast` and the app from one commit. Run this from the checkout's root, with a clean tree:

```bash
test -z "$(git status --porcelain)" || echo "commit first: the check compares HEAD, not the working tree"
COMMIT=$(git rev-parse HEAD | cut -c1-7)
go build -o ./bin/farcast ./farsight/cli/cmd/farcast
(cd farsight/client/apple && xcodebuild -project FarSight.xcodeproj -scheme FarCast \
  -destination 'platform=macOS' -derivedDataPath .build/DerivedData build FARCAST_COMMIT="$COMMIT")
./bin/farcast version          # commit: $COMMIT
plutil -extract FarCastCommit raw farsight/client/apple/.build/DerivedData/Build/Products/Debug/FarCast.app/Contents/Info.plist   # $COMMIT
open farsight/client/apple/.build/DerivedData/Build/Products/Debug/FarCast.app
```

A build without `FARCAST_COMMIT` (Xcode's Run button) draws the setup and the illustrative world, but reads no instance. `./check.sh` builds this same `FarCast.app` again, in the same `.build/DerivedData`, without the commit, so run it before this build, never after. On an iPad simulator, run the `FarCast` scheme from Xcode; it draws the illustrative fixture.

On the map:
- **Move around.** Drag anywhere that is not a handle to pan. Pinch or ⌘-scroll to zoom; a trackpad scroll pans.
- **Rearrange.** Drag a repo by its title, or an app by its title bar. A drop that would put two panels, two repos or two instances' rows on top of each other is refused, and the item goes back.
- **Jump.** Tap an app to fly to it. ⌘K jumps by name, Esc backs out to the instance, 0 shows the whole world, and Space goes to the next alert.

Arrangements are kept on the device until the FarSight server exists to keep them. The fixture and live instances keep theirs under separate keys, so a real instance named like a fixture instance never inherits the fixture's places.

## The world it draws

A world says where it came from: the fixture, or live. A live world is read from the operator's instances by the Connected view (ADR 0021 decision 9, amended 2026-11-12), and validation refuses anything illustrative in it: no sketch groups or apps, no planned lines, no app-to-app lines. On macOS, `CLIReader` lists and reads instances by running the confirmed `farcast` with fixed arguments. It refuses to read when that `farcast` names a different commit from this build. A counted line is labelled as a floor, and the boundary's panel names the one FatLine replica that counted it, and since when (ADR 0022 decision 9).

- **A group is a namespace,** labelled with the repository `run` recorded for it on this Mac.
- **What could not be read says so.** An instance carries its status as its record holds it, when it was read, and every section of the read that failed. Apps, FarCast's own components among them, can be `starting`, `not deployed` or `unknown` as well as running or stopped; only a running app is drawn in the running colour, and an unknown one is drawn with a dashed outline. An instance listed but never read is drawn with its four components in an unknown state, and its chip says "not read yet". A component's panel says "not read" for every figure whose section was not read, never 0. An app or a keeper built without a state or a health has none: unknown, never running or healthy. A record whose cost limit is missing or not one is drawn with that said, as a problem with the record, and keeps no other instance off the map.
- **Spending is the kernel's, in two parts.** `confirmed`, with the UTC day it runs to, as the CLI prints it, and `expected`, against the kernel's own limit and coloured by the kernel's level. The two are never drawn as one total: the bar has a solid part and a lighter part, and the text names both; the HUD's chip labels its share "total". Not read, it says so, and shows the recorded limit as the recorded one.
- **Why an app is stopped, and the floor, only as the kernel records them** (2026-11-12). An app is "stopped by the cost guard" when the CLI says `stopped_by: cost_guard` — the kernel recorded stopping it, and it is still at zero — and plainly "stopped" otherwise. When the kernel records the instance floor, TechnoCore's panel says what still burns a month and names the levers it leaves to the operator (dropping the load-balancer carrier, releasing the instance), the spending line says "at the floor", and the `at_floor` alert is drawn critical on TechnoCore. Where the kernel keeps no such record, the panel says "not recorded", never "no".
- **A failed section is one plain sentence, never farcast's message** (after the Phase 7 rehearsal, 2026-11-12). Each panel says, for each section of its own that failed, what was not read, why, and the remedy where there is one, made from the CLI's stable error kinds (`ProblemText`): "spending not read · signed out of gcloud — run gcloud auth login", "the read was refused · gcloud identity does not match — farcast instances pin-gcloud", "network not read · tunnel unreachable". The instance's chip says it in brief — "3 sections not read · signed out of gcloud", "read refused · gcloud identity does not match", "read timed out" — counted, never listed one by one. A spending figure a read section gave and the map cannot draw (out of the range it draws a sum in) is no section not read: it says "spending figure not drawn · out of range" in TechnoCore's panel, and is counted apart on the chip. farcast's own message, which can run to a whole kubectl or gcloud error, is shown once per instance, behind the chip's info button, whole, through `Display.message`; a message several sections share is shown once under their sentences.
- **The chip never runs past its band, nor off the screen.** Where all of it does not fit, it says less: the spending's share for both parts, then what failed without when, then what failed without the share, then what failed at its shortest ("read refused", "3 sections not read"), then the name alone, cut short to the band. What failed outlives the spending, because a share from a snapshot the latest read could not renew would pass for current; and a share at the floor or from a stale checkpoint says so ("total 145% · at the floor", "· stale"), here and on the HUD's chip. The one exception is an instance drawn smaller than the chip's least — its padding, an ellipsis and the info button, about 40 points at the smallest type — where that least stands wider than the band.
- **A component's panel is a fixed layout, never a scroll view,** because a drag on it pans the map. Its figures stand at the top, whole, at their own height; a smaller panel takes a tighter arrangement of them (closer, then three columns, then smaller type) before it would cut one, and `PanelWordingTests` holds the tightest to fit, with room for the notes, on the smallest panel drawn whole: a phone on its side, 280 points wide. No screen draws a panel whole narrower than that (`WorldModel.leastFullPanelWidth`); smaller, it is a glance, which draws no figure to cut. A Mac window is never smaller than `WorldScreen.minimumWindow` (667 × 460), where a focused app is still drawn whole. What the read could not say stands whole under the figures where an arrangement leaves room, and otherwise heads the notes. The notes take the space left, and when they do not fit, "more" opens all of it, every figure and every word — TechnoCore's list of what the meter does not see among them (ADR 0009). VoiceOver hears the same: a panel is one element, and its value is every figure and every word under them. A count of one is singular ("1 app stopped"), every other plural, by one rule (`Plural`).
- **Shrike's watch is read from its evidence.** A current watch on FatLine that the read observed means Shrike watches, whatever the apps section could say of its state. Without one, Shrike is "not watching" only where its state was read, and "not read" where it was not.
- **A declared line is "unused" only where the network was read.** Where it was not, the line says "declared · use not read" and its host "declared by …, use not read": nobody saw either way. FatLine's figure is labelled the same way, whether or not the policy was read.
- **A figure is a claim only where it was read.** TechnoCore's "apps stopped" counts applications, never FarCast's own components — TechnoCore stops applications only, and Shrike's state is what the tunnel read says — and says "not read" where any application's state was not read. DataSphere's "keepers needing attention" says "not read" where no keeper's health was read, and is "of those read" where only some were.
- **Tolerant where a newer CLI may add a word.** An unknown state, level, health, status, problem or alert kind decodes as `unknown`. A connection's kind or evidence, a role, an endpoint or an alert's subject does not: the read fails, and the instance keeps its last good snapshot.
- **Alerts are about an app, an instance or a device.** Opening one focuses the app, or frames the instance or device. Space walks them by id.
- **Text from an instance is escaped where it is drawn,** by the CLI's own rule: anything Go's `unicode.IsPrint` refuses is written as its Go escape. Ids are never escaped.

`WorldFeed` lists the instances at launch, from files on the Mac, and reads them only when the operator presses Refresh, one at a time, each with a deadline that holds even against a reader that ignores cancellation. A failed read keeps the instance's last good snapshot, faded, with its read time and the failure, and what the newer listing says of the record (a release started since, say) is drawn over it. A live feed never shows the fixture.

## The Connected view on macOS

The app reads the operator's instances with the operator's own `farcast` (ADR 0021 decision 9, amended 2026-11-12). Before it reads a live instance, it is walked with [the Phase 7 runbook](../../../docs/runbooks/phase-7-connected-view.md): a rehearsal from Finder that costs nothing, then the first live read.

**Settings (⌘,) records six absolute paths, confirmed once:** `farcast`, `kubectl`, `gke-gcloud-auth-plugin` and `gcloud`, the farcast configuration directory (`--config`) and the gcloud configuration directory (`CLOUDSDK_CONFIG`). The tool fields start empty, because a guessed tool path is a place to plant one (decision 6). The two directories start at their standard places, and are still used only once confirmed. Each path is refused unless:
- it is absolute, with no `~`, `.`, `..`, empty part or trailing `/`, and holds nothing `PATH` cannot carry (a `:`, or a character that is not printable);
- it is not inside FarCast.app, with symlinks resolved;
- a tool is a file you can execute, named as it is run (`kubectl`, `gke-gcloud-auth-plugin`, `gcloud`; `farcast` may have any name), which is not writable by everyone on the Mac, in a directory that is not either, both where the path is typed and, for a link, where it leads;
- a directory is a directory that is not writable by everyone on the Mac.

Group-writable is allowed, since Homebrew's own directories are. A tool may not be shadowed either: for each of `kubectl`, `gke-gcloud-auth-plugin` and `gcloud`, the first directory on the child's `PATH` that holds one must be that tool's own.

Check runs `farcast version` and `farcast instances` with exactly the form's paths, and shows the CLI's version and commit, which must be this build's, and whether each instance has a gcloud account pinned. Confirm keeps the form only after a Check of that same form succeeded, and Forget clears it, after which nothing is read until paths are confirmed again. After a Check, "Copy terminal command" copies the exact command a Refresh runs for one instance, environment included. It is for this Mac's terminal only, since it holds home-directory paths.

**The child's environment is built, never inherited.** It holds exactly these keys:

| Key | Value |
|---|---|
| `HOME` | the app's; without an absolute one, nothing runs |
| `TMPDIR` | the app's, when it is absolute |
| `LANG`, and each `LC_` variable | the app's, when set |
| `PATH` | the recorded tools' directories (kubectl's, the plugin's, gcloud's, without repeats), then `/usr/bin:/bin:/usr/sbin:/sbin` |
| `CLOUDSDK_CONFIG` | the confirmed gcloud configuration directory |

Everything else the app was started with is dropped: its `PATH`, `FARCAST_CONFIG_HOME`, `KUBECONFIG`, the proxy variables, every `CLOUDSDK_*` variable (its own `CLOUDSDK_CONFIG` among them), `GOOGLE_APPLICATION_CREDENTIALS`, `DYLD_*` and the rest. `farcast`'s own directory is not on `PATH`: it is run by its absolute path, and nothing looks it up by name. The system directories are there because `gcloud` is a shell script that needs the system's utilities and finds its Python on `PATH`. They sit on the sealed system volume, so nothing can be planted in them. The Python that `gcloud` runs is the first one on that `PATH`, so the recorded tools' directories decide it too.

**Why `CLOUDSDK_CONFIG` is set.** The child inherits none of the app's `CLOUDSDK_*` variables. This one is the directory the operator confirmed, as `--config` is. `farcast`'s identity guard reads that directory and hands the same one to `kubectl`, so the directory it checks is the one confirmed in Settings, never one derived from whatever `HOME` the app was launched with. That is also why a rehearsal started from Finder never reads the real `~/.config/gcloud`.

**The pinned gcloud account.** Every `world` runs `kubectl` as the gcloud account the instance records, pinned once from a terminal with `farcast instances pin-gcloud <instance> --account <account>` ([`farsight/cli/README.md`](../../cli/README.md#farcast-instances-and-farcast-world--the-connected-views-reads-adr-0021-decision-9-amended-2026-11-12)). The app shows only whether an account is pinned, never which one.

**When it runs.**
- At launch the app lists the instances, with `version` and `instances`. It runs `world` for each listed instance only on Refresh (⌘R), one at a time. Nothing runs on a timer.
- Each command has its own timeout (5, 10 and 75 seconds), each under the feed's deadline. One that prints more than 8 MiB is stopped, and nothing it printed is read.
- Every document's commit is checked, not only `version`'s, so a `farcast` of another commit swapped in between a listing and a read is refused too. A binary reports its own commit, so a replacement that reports this build's commit is not caught (ADR 0021 decision 9, *What it gives up*). A build without its own commit runs nothing.
- A command that times out, or whose read is cancelled, gets SIGTERM, which makes `farcast` cancel its own `kubectl`, and SIGKILL 3 seconds later. Quitting the app stops a running read the same way, waiting at most half a second before SIGKILL. Closing a window stops nothing.

## The backdrop

One seamless 4096-pixel tile, 10-bit Display P3, repeated across a plane that lies behind the map. Far out, it pans and zooms almost with the map; over an app shown at full size it moves a fifth as fast, and a ninth at the closest zoom. No single scale serves the map's whole zoom range: pinned to the map, the backdrop would shrink to a busy pattern over the whole world and swell to a blur over one panel. Inside an instance's wall the app draws a blurred form of it, so the wall reads as a frosted pane, and the surfaces on top are tinted over it. The image is read once per process, whatever the number of windows.

Readability rests on one number. No backdrop pixel may be brighter than relative luminance 0.07 (`Backdrop.luminanceCap`). `BackdropTests` checks the surfaces in `Theme` over every colour under that cap, not only today's backdrop, in each way a renderer might blend a surface over it. It holds these to WCAG contrast, 4.5:1 for text and 3:1 for lines:
- connection lines at full strength, on the open backdrop and inside walls;
- their labels, and the gates' and instances' labels, on chips over the backdrop;
- a group's text;
- the app strip's repo names, on chips over anything the map shows;
- a host's or device's card border against its card, by health and by alert, and an app's state colour on its card;
- every spending level's colour on an instance's chip;
- the text on a FarCast component's panel, opaque, and in what its "more" and the instance chip's info button open.

It also checks the shipped file against the cap.

Some things are not held to that contrast, and the test names them:
- outlines (an instance's wall, a group's frame, an app card's plain border);
- faded lines and labels (stale, or dimmed by another app's focus);
- a stopped app's faded marker and glance card;
- the decorative dot grid;
- the map's lines and label chips where they cross a panel's light page;
- the expected part of the spending bar, lighter than the confirmed part on purpose, whose figure is also written out;
- the HUD's Liquid Glass, which adapts to what is under it and was checked by eye on the iPad simulator.

The plain border, the stopped marker and the glance card were below these ratios on the old plain ground too.

A backdrop chosen later, and a palette taken from it, would first have to be brought under the cap.

The tile is painted by `BackdropPainter` in the UI tests, not drawn by hand. It uses warped periodic noise, so it repeats with no seam, coloured in OKLCh and held under the cap with headroom. The file carries 64 pixels of wrap on every side (4224 pixels in all), and the app crops them away. Without the margin, HEVC's colour subsampling would flatten the tile's last columns into a seam. To paint it again:

```
cd FarSightKit
FARSIGHT_PAINT_BACKDROP="$PWD/Sources/FarSightUI/Backdrop/backdrop.heic" swift test --filter BackdropTests
```

That run checks the file it just wrote: it matches the painter, it is seamless as decoded, and it is under the cap in both forms. Without the variable, the same test checks the bundled copy.

## Check it

`./check.sh` at the repository root runs the guardrails ADR 0021 decision 4 requires:
- Swift 6 with strict concurrency, strict memory safety and warnings as errors;
- the source gate;
- `swift test`;
- the app built for macOS, the iOS simulator and the visionOS simulator;
- `xcodebuild test` on macOS and an iOS simulator;
- in each of the three test runs, ADR 0020's Apple regression against its Go servers, every live test passed by name (below).

The source gate holds the client to allowlists, not denylists:
- file types (Swift, the manifests and project, JSON and text), the one backdrop image by its path, and no links;
- the CLI's golden vectors: each of `app`, `instances`, `kinds`, `version` and `world` under `Tests/FarSightCoreTests/Vectors/` is byte for byte the directory Go's tests hold to the CLI, with nothing added or missing (Finder's `.DS_Store` aside);
- FatLine's PKI vectors: `pki` under `Tests/FarSightTLSTests/Vectors/` is byte for byte `fatline/internal/crypto/testdata/pki/`, which Go's tests hold to what `crypto.go` issues, with nothing added or missing;
- Swift attributes, with `unsafe` and `unsafeFlags` refused outside `unsafe-allowlist.txt`;
- a static package manifest, with each target's settings drawn from a fixed set, and its resources, by exact path and rule, from another;
- the project's exact objects and fields, its build-setting keys, one Info.plist file holding only the build's commit, and one scheme with no actions;
- the guardrails as `xcodebuild` resolves them, for every configuration and SDK.

Adding any of these — a new attribute, setting, resource, file type or project object — is a reviewed change to `check.sh`. The gate was mutation-tested against each bypass that review found. It is a regex and allowlist gate, not a Swift parser.

### ADR 0020's Apple regression

ADR 0020 moved the instance PKI to ECDSA P-256 because Apple's TLS can neither present nor accept Ed25519. `FarSightTLSTests` holds that to the code (ADR 0021 Verification 1). Its seven live tests, each named `ADR 0020 live: …`, run against three Go servers from `fatline/internal/crypto/applefixture_test.go`. Each runs FatLine's own `ServerTLSConfig`, admitting only the fixture's operator leaf, and presents a different certificate: the P-256 fixture's server leaf, a leaf from another CA with the same subject, and an Ed25519 leaf. The tests check:
- URLSession completes TLS 1.3 mutual authentication over HTTP/2, with an identity formed in memory (no keychain item, no prompt) and trust pinned to the fixture CA and server name;
- `NWConnection` does the same over HTTP/1.1, pinning the server's key;
- neither reaches an Ed25519 server: the handshake fails before any trust callback runs, and a pass there would mean Apple's TLS changed, so ADR 0020 is revisited;
- the pinned trust refuses another name and another CA, and FatLine refuses a client with no certificate.

The offline tests need no server: the copied vectors decode, the identity forms in memory, Swift fingerprints a key as Go does, and the enrolment request template (ADR 0021 decision 3) rebuilds each of Go's six request vectors byte for byte, with CryptoKit verifying each signature.

`./check.sh` starts the servers after `swift build` and stops them after `xcodebuild test`. It names their addresses to the tests as `FARSIGHT_TLS_P256`, `FARSIGHT_TLS_FOREIGN` and `FARSIGHT_TLS_ED25519`, and to `xcodebuild test` with a `TEST_RUNNER_` prefix, which xcodebuild strips on the way to the runner. Without them, as in a plain `swift test` or Xcode's Test button, the live tests are skipped with a reason. A skipped test still counts in "Test run with N tests", so the check also requires all seven to report passed, by name, in each of its three runs. The scheme stays free of actions and variables, which its shape check requires, so Xcode's Test button always skips them.

To run the regression by hand, start the servers in one terminal, from the repository root:

```bash
go test -mod=vendor -c -o /tmp/applefixture.test ./fatline/internal/crypto/ \
  && (cd fatline/internal/crypto && FARCAST_APPLE_FIXTURE=/tmp/a.json /tmp/applefixture.test -test.run '^TestServeAppleFixture$')
```

They serve until their stdin closes: here stdin is the terminal, so Ctrl-D stops them. Two things make it this form rather than a plain `go test -run TestServeAppleFixture`:
- `go test` hands a test binary an empty stdin, so the servers would stop at once, and it applies a 10-minute timeout. A binary run directly has neither.
- The binary reads its vectors from `testdata/` relative to the directory it runs in, so it runs from `fatline/internal/crypto`.

Then, in a second terminal, from `FarSightKit/`:

```bash
export FARSIGHT_TLS_P256=$(plutil -extract p256 raw -o - /tmp/a.json) \
  FARSIGHT_TLS_FOREIGN=$(plutil -extract foreign raw -o - /tmp/a.json) \
  FARSIGHT_TLS_ED25519=$(plutil -extract ed25519 raw -o - /tmp/a.json)
swift test --filter FarSightTLSTests
```

When Go's PKI vectors change (`FARCAST_UPDATE_VECTORS=1 go test -mod=vendor ./fatline/internal/crypto/ -run Vector`, then reviewed), copy them again, from the repository root:

```bash
rm -rf farsight/client/apple/FarSightKit/Tests/FarSightTLSTests/Vectors/pki \
  && cp -R fatline/internal/crypto/testdata/pki farsight/client/apple/FarSightKit/Tests/FarSightTLSTests/Vectors/
```

### Snapshots and renders

`FARSIGHT_SNAPSHOTS=<dir> swift test` in `FarSightKit/` also writes the snapshot test's frames as PNGs. They are drawn offscreen, so they show layout, not the glass.

`FARSIGHT_RENDERS=<dir> swift test --filter RenderHarness` draws FarCast's own panels, the instances' chips, what their disclosures open and a host card, from the CLI's vectors through the real adapter and feed, healthy, signed out, refused, at the floor and with the tunnel down, and writes them to `<dir>` as PNGs. `FARSIGHT_RENDER_DOCS=<dir>` may name world documents a rehearsal printed (`signed-out.json`), read in place of the nearest vector. Keep `<dir>` outside the repository: nothing under `farsight/` may hold an image.
