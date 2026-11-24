# FarSight

> The "farcast" app — native GUI (the app world map), CLI, and an in-instance server for tiles, sessions and layout.

FarSight is the UX layer of FarCast. It is one product called "farcast" with three components. On macOS one app is to carry the GUI and the CLI, and on iPhone, iPad and Vision Pro the app is to be a thin client ([ADR 0021](../docs/adr/0021-farsight-native-client.md), accepted; neither is built yet, only its prototype step, the app world map and on macOS the read-only Connected view: [`client/apple/README.md`](client/apple/README.md)). The server runs inside the instance.

- **client/** — native GUI shells drawing the app world map. `client/apple/` is one Swift/SwiftUI codebase for macOS, iPadOS, iOS and visionOS ([ADR 0021](../docs/adr/0021-farsight-native-client.md)), and Android and Windows follow.
- **cli/** — Go command line interface for operators and automation
- **server/** — Go server running inside the FarCast instance that keeps the tile registry, sessions and layout state

The CLI is specified and implemented as [`cli/README.md`](cli/README.md) records. The client (native, Phase 7, [ADR 0021](../docs/adr/0021-farsight-native-client.md)) is at its prototype step, specified in [`client/apple/README.md`](client/apple/README.md); the server is scaffold-only, and its specification will follow.
