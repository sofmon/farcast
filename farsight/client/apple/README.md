# FarSight for Apple devices

One Swift/SwiftUI codebase for macOS, iPadOS, iOS and visionOS ([ADR 0021](../../../docs/adr/0021-farsight-native-client.md)). It draws the **app world map**: every app on one freeform map, FarCast's own components included, grouped by repository, with its connections drawn and graded by evidence. Nothing is hidden; the camera flies to an app instead of switching to it. The HUD over the map is Liquid Glass.

**State:** the prototype step (ADR 0021 decision 9, step 1). The map runs against an illustrative fixture. No tile shows a real app yet: tiles wait for the bridge (decision 5) and the tile-ingress ADR. Nothing here talks to an instance, holds a key, or reaches the network.

## Layout

- `FarSightKit/` — a SwiftPM package that builds and tests headlessly.
  - `FarSightCore` — values only: the world snapshot and its validation, the standard arrangement, where everything is drawn, how connections are routed through the gates, the camera and its flights, the live-panel budget.
  - `FarSightUI` — the map and its HUD: panels at three levels of detail (marker, glance, full), the connection layers, the minimap, the app strip, the ⌘K jump palette.
  - `FarSightFixtures` — `world.json`, two illustrative instances.
- `FarSight.xcodeproj` — the `FarCast` app target, one target for every platform, with folder-synchronized sources in `FarCast/`. No project generator.
- `unsafe-allowlist.txt` — the lines the source gate in `./check.sh` lets through. Empty.

## Run it

Open `FarSight.xcodeproj` in Xcode and run the `FarCast` scheme on My Mac or an iPad simulator, or from a terminal:

```
xcodebuild -project FarSight.xcodeproj -scheme FarCast -destination 'platform=macOS' -derivedDataPath .build/DerivedData build
open .build/DerivedData/Build/Products/Debug/FarCast.app
```

On the map:
- **Move around.** Drag anywhere that is not a handle to pan. Pinch or ⌘-scroll to zoom; a trackpad scroll pans.
- **Rearrange.** Drag a repo by its title, or an app by its title bar. A drop that would put two panels, two repos or two instances' rows on top of each other is refused, and the item goes back.
- **Jump.** Tap an app to fly to it. ⌘K jumps by name, Esc backs out to the instance, 0 shows the whole world, and Space goes to the next alert.

Arrangements are kept on the device until the FarSight server exists to keep them.

## Check it

`./check.sh` at the repository root runs the guardrails ADR 0021 decision 4 requires:
- Swift 6 with strict concurrency, strict memory safety and warnings as errors;
- the source gate;
- `swift test`;
- the app built for macOS, the iOS simulator and the visionOS simulator;
- `xcodebuild test` on macOS and an iOS simulator.

The source gate holds the client to allowlists, not denylists:
- file types, and no links;
- Swift attributes, with `unsafe` and `unsafeFlags` refused outside `unsafe-allowlist.txt`;
- a static package manifest, with each target's settings drawn from a fixed set;
- the project's exact objects and fields, its build-setting keys, and one scheme with no actions;
- the guardrails as `xcodebuild` resolves them, for every configuration and SDK.

Adding any of these — a new attribute, setting, file type or project object — is a reviewed change to `check.sh`. The gate was mutation-tested against each bypass that review found. It is a regex and allowlist gate, not a Swift parser.

`FARSIGHT_SNAPSHOTS=<dir> swift test` in `FarSightKit/` also writes the snapshot test's frames as PNGs. They are drawn offscreen, so they show layout, not the glass.
