# FarSight

> The "farcast" app — native GUI (tiling browser), CLI, and an in-instance server for tiles, sessions and layout.

FarSight is the UX layer of FarCast. It is one product called "farcast" with three components. On macOS one app is to carry the GUI and the CLI, and on iPhone, iPad and Vision Pro the app is to be a thin client ([ADR 0021](../docs/adr/0021-farsight-native-client.md), accepted, not yet built). The server runs inside the instance.

- **client/** — native GUI shells with a tiling interface. `client/apple/` is one Swift/SwiftUI codebase for macOS, iPadOS, iOS and visionOS ([ADR 0021](../docs/adr/0021-farsight-native-client.md)), and Android and Windows follow.
- **cli/** — Go command line interface for operators and automation
- **server/** — Go server running inside the FarCast instance that keeps the tile registry, sessions and layout state

The CLI is specified and implemented through Phase 2.3 (`install`, `release`, `connect`, `redeploy`) — see [`cli/README.md`](cli/README.md). The client (native, Phase 7, [ADR 0021](../docs/adr/0021-farsight-native-client.md)) and server components are scaffold-only. Their specifications will follow.
