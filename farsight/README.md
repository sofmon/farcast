# FarSight

> The "farcast" app — GUI (tiling browser), CLI, and server-side composition.

FarSight is the UX layer of FarCast. It ships as a single downloadable app called "farcast" with three components:

- **client/** — Electron + TypeScript GUI with a tiling window manager interface
- **cli/** — Go command line interface for operators and automation
- **server/** — Go server running inside the FarCast instance for UX composition

The CLI is specified and implemented through Phase 2.3 (`install`, `release`, `connect`, `redeploy`) — see [`cli/README.md`](cli/README.md). The client (Electron GUI, Phase 7) and server components are scaffold-only; their specifications will follow.
