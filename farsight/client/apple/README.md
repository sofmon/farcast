# FarSight for Apple devices

One Swift/SwiftUI codebase for macOS, iPadOS, iOS and visionOS ([ADR 0021](../../../docs/adr/0021-farsight-native-client.md)). It draws the **app world map**: every app on one freeform map, FarCast's own components included, grouped by repository, with its connections drawn and graded by evidence. Nothing is hidden; the camera flies to an app instead of switching to it. The HUD over the map is Liquid Glass, and under everything lies a backdrop the glass picks its colour up from.

**State:** the prototype step (ADR 0021 decision 9, step 1). The map runs against an illustrative fixture. No tile shows a real app yet: tiles wait for the bridge (decision 5) and the tile-ingress ADR. Nothing here talks to an instance, holds a key, or reaches the network.

## Layout

- `FarSightKit/` — a SwiftPM package that builds and tests headlessly.
  - `FarSightCore` — values only: the world snapshot and its validation, the standard arrangement, where everything is drawn, how connections are routed through the gates, the camera and its flights, the live-panel budget.
  - `FarSightUI` — the map and its HUD: panels at three levels of detail (marker, glance, full), the connection layers, the minimap, the app strip, the ⌘K jump palette, and the backdrop under them (`Backdrop/backdrop.heic`).
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

## The backdrop

One seamless 4096-pixel tile, 10-bit Display P3, repeated across a plane that lies behind the map. Far out, it pans and zooms almost with the map; over an app shown at full size it moves a fifth as fast, and a ninth at the closest zoom. No single scale serves the map's whole zoom range: pinned to the map, the backdrop would shrink to a busy pattern over the whole world and swell to a blur over one panel. Inside an instance's wall the app draws a blurred form of it, so the wall reads as a frosted pane, and the surfaces on top are tinted over it. The image is read once per process, whatever the number of windows.

Readability rests on one number. No backdrop pixel may be brighter than relative luminance 0.07 (`Backdrop.luminanceCap`). `BackdropTests` checks the surfaces in `Theme` over every colour under that cap, not only today's backdrop, in each way a renderer might blend a surface over it. It holds these to WCAG contrast, 4.5:1 for text and 3:1 for lines:
- connection lines at full strength, on the open backdrop and inside walls;
- their labels, and the gates' and instances' labels, on chips over the backdrop;
- a group's text;
- the app strip's repo names, on chips over anything the map shows;
- a host's or device's card border against its card.

It also checks the shipped file against the cap.

Some things are not held to that contrast, and the test names them:
- outlines (an instance's wall, a group's frame, an app card's plain border);
- faded lines and labels (stale, or dimmed by another app's focus);
- a stopped app's faded marker and glance card;
- the decorative dot grid;
- the map's lines and label chips where they cross a panel's light page;
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
- `xcodebuild test` on macOS and an iOS simulator.

The source gate holds the client to allowlists, not denylists:
- file types (Swift, the manifests and project, JSON and text), the one backdrop image by its path, and no links;
- Swift attributes, with `unsafe` and `unsafeFlags` refused outside `unsafe-allowlist.txt`;
- a static package manifest, with each target's settings drawn from a fixed set;
- the project's exact objects and fields, its build-setting keys, and one scheme with no actions;
- the guardrails as `xcodebuild` resolves them, for every configuration and SDK.

Adding any of these — a new attribute, setting, file type or project object — is a reviewed change to `check.sh`. The gate was mutation-tested against each bypass that review found. It is a regex and allowlist gate, not a Swift parser.

`FARSIGHT_SNAPSHOTS=<dir> swift test` in `FarSightKit/` also writes the snapshot test's frames as PNGs. They are drawn offscreen, so they show layout, not the glass.
