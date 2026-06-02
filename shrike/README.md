# Shrike

> Security monitor — validates traffic against manifest declarations, intervenes on violations.

> **GKE Autopilot note ([ADR 0003](../docs/adr/0003-gke-autopilot.md)):** Shrike runs as a **sidecar** inspector on FatLine — no privileged or raw-capture access needed; it sees the traffic FatLine proxies and may also consume GKE Dataplane V2 flow logs.

*Specification and implementation details to follow.*
