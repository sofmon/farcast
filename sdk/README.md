# FarCast SDK

> Language-level libraries for interacting with the FarCast environment — analogous to syscalls in a traditional OS.

The SDK gives applications access to logging, configuration, storage (DataSphere), networking (FatLine), and AI (AllThing) — and secrets, since phase 5.3 — through a simple, cloud-agnostic API. Applications import the SDK instead of talking to the cloud directly.

## Language SDKs

The Go SDK is the reference implementation; the Node.js and Python SDKs mirror its contract (planned for phase 8.4).

| SDK | Spec | Implementation |
|---|---|---|
| **[go/](go/README.md)** | ✅ Complete | 🟡 Logging, config, storage and secrets implemented; `Net()` and `AI()` stubs |
| **node/** | 🔲 Not started | 🔲 Not started |
| **python/** | 🔲 Not started | 🔲 Not started |

See [`go/README.md`](go/README.md) for the full capability contract, the logging design, and current status.
