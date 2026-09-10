# ADR 0017 — Application Secrets, and What an Instance Can Actually Isolate

**Status:** Accepted

**Date:** 2026-09-09

**Relates to:** Delivers Phase 5.3's secrets half. Builds on [ADR 0008](0008-in-cluster-key-delivery.md)'s keyholder and inherits its seal contract. Records that [ADR 0008](0008-in-cluster-key-delivery.md)'s 4.x commitment to per-application scopes did not ship, and states what that costs. Applies [ADR 0013](0013-per-application-egress-identity.md)'s finding — that a control nobody can attribute is telemetry rather than enforcement — to storage, where it has not been fixed.

---

## Context

[PLAN](../../PLAN.md) 5.3 asks for `farcast.Secrets()`, with one line of specification that is really a prohibition: *"Secrets encrypted at rest via DataSphere, never in plaintext in K8s."*

The prohibition is right, and it is worth being precise about what it rules out. A Kubernetes Secret is base64 in etcd. On GKE it is encrypted at rest, by a key **Google holds**, and it is readable by anything with `get secrets` in the namespace — including a workload with a projected service-account token, which is why applications get none ([`planck/translate/workload.go`](../../planck/translate/workload.go)). "The cloud cannot read the operator's data" is the property this project exists to hold, and a Kubernetes Secret is precisely the shape that gives it away.

So a secret becomes an object in the instance's own storage: encrypted client-side under keys the cloud never sees, stored under a tokenized name, in the subtree `<scope>/secrets/<app>/<name>`.

That is the easy half. The hard half is what an instance can isolate.

### What the instance actually has today

- **One scope.** `datasphere.DefaultScopeName` is `app`, prefix `app/`, and every application in an instance is given it. [ADR 0008](0008-in-cluster-key-delivery.md) says *"4.x — per-app scopes go live"*. Phase 4 shipped without them.
- **No caller identity on the storage data path.** `keyholder.DataTLS` authenticates the **server** only, and says so: *"In phase 3.2 there are no application identities to verify."* The scope a request declares travels in a header, and every application is handed the same string.
- **Per-application identity does exist — for egress.** [ADR 0013](0013-per-application-egress-identity.md) gives each application a credential FatLine verifies, and the keyholder does not use it. Sharing it would let the keyholder impersonate the application to FatLine, which is a worse trade than the one it would fix.

Put together: **two applications in one instance can read each other's storage objects**, and giving each a different scope *name* would not change that, because the name is declared by the caller and proven by nothing. Minting per-application scopes without per-application identity produces a system that looks isolated in a diagram and is not isolated in the cluster — the exact failure [ADR 0013](0013-per-application-egress-identity.md) named for egress and fixed there.

This ADR does not fix it. It states it, bounds it, and takes the enforcement that *is* available.

---

## Decisions

**1. A secret is a DataSphere object, never a Kubernetes Secret.** It is written from the operator's machine with the instance's own keys and read by the application through the keyholder, over the storage path that already exists. Nothing new is deployed, nothing new is billed, and the cloud provider holds ciphertext under an opaque name.

**2. The boundary is the instance, not the application — and this is written where a reader will hit it.** A secret is confidential from the cloud provider, from anyone with the bucket, and from anything outside the instance. It is **not** confidential from another application inside the same instance. That sentence appears in the SDK's `SecretsAPI` documentation, in the `farcast secret` help text, in the ConfigMap Planck renders, and here. A capability called Secrets that quietly promised less than its name is worse than no capability, because an operator would put a payment credential behind it.

**3. The keyholder enforces the one rule it honestly can: no application creates or destroys a secret.** `PUT` and `DELETE` under a scope's `secrets/` subtree are refused on the application data path (`keyholder.ErrSecretsReadOnly`, reported as the frozen `permission` code). The path cannot tell **whose** secret this is, so it does not pretend to; it can tell that a *write* is happening, and it refuses. What that buys is real and small: a compromised application can read the instance's secrets, and cannot plant a credential for a neighbour to pick up, or delete one to force a fallback to something weaker.

**4. Listing is deliberately not refused.** The parent prefix is listable by the same caller, so refusing `list` on `secrets/` would prevent nothing while implying an enumeration boundary that does not exist. A test asserts the listing succeeds, so that "hardening" it later is a deliberate act with this ADR reopened rather than a quiet one.

**5. The prefix is given to the application, never derived by it.** Planck renders `FARCAST_SECRETS_PREFIX` from the recorded scope prefix; the SDK refuses any prefix that does not name the reserved segment. A prefix guessed from the scope name would land one segment away from the subtree the keyholder protects — and the capability would still call itself Secrets while writing into ordinary storage. The CLI resolves the same prefix from the keyring and refuses to write when it diverges from what the deploy recorded, because applications are handed the recorded one.

**6. Provisioning is an operator act, and there is no `get`.** `farcast secret set` reads the value from stdin or a file and there is no `--value` flag: a value on the command line is world-readable in `/proc` while the command runs and lands in shell history. `farcast secret ls` prints names and never values. There is no read-back verb, because a secret printed to a terminal is in scrollback, in a screen share, and in whatever recorded the session. This is a guard rail rather than a lock — the keyring belongs to the operator, so `farcast storage cp` can always recover the bytes deliberately, with the key in hand.

**7. A trailing newline is removed by default, and the removal is reported.** `echo x |` appends a byte that is the shell's, not the operator's, and a credential silently one byte longer than the one in the provider's console is a long afternoon. `--raw` keeps it. Acting and saying so beats both silent choices.

**8. The SDK returns a `Secret`, not a string.** It redacts through every route `fmt`, `slog` and `encoding/json` take to a value, and marshalling **fails** rather than emitting a placeholder — a well-formed document containing `[redacted]` where a working value was meant is discovered at the far end of whatever consumed it. `Reveal()` is the one way out: a verb an author has to type and a reviewer can grep for.

**9. `Config()` refuses the platform's namespace.** `FARCAST_FATLINE_PROXY` carries the application's egress credential ([ADR 0013](0013-per-application-egress-identity.md)) and is injected from a Kubernetes Secret precisely because it is one. A capability documented as *non-secret configuration* that returns it is a capability that will eventually log it. Identity moves to accessors (`farcast.AppName`, `farcast.InstanceID`) so the refusal leaves nothing an application legitimately needed. It is a guard rail on the SDK's surface, not a sandbox: `os.Getenv` still works, and claiming otherwise would be the kind of theatre that makes a reader trust the wrong thing.

**10. The writer's name rule must never be more permissive than the reader's.** `datasphere.ValidateSecretName` and the SDK's `validSecretName` live in modules that cannot import each other, so they are mirrored the way the wire codes are, with a cross-module test on the shared bound. The direction is the point: a writer stricter than the reader refuses a name somebody could have used; a writer *looser* than the reader stores a secret no application can fetch, and nothing says so until production asks for it.

---

## What the cloud still sees

The same list as ordinary storage ([`datasphere/README.md`](../../datasphere/README.md)), and one entry of it matters more here: **a stored object's size is visible to within a constant.** A secret drawn from a small set of differing lengths is identified by its size alone. If that matters — a flag, a short enum, a token from a known issuer — pad it to a fixed slot deterministically before storing it, exactly as the SDK's storage documentation describes. Names are tokenized, but the *number* of secrets an application holds and *when* each is read are visible.

---

## Alternatives considered

**A Kubernetes Secret, mounted or injected.** Rejected by the phase's own specification, and correctly: it is cloud-resident plaintext-yielding storage, and the projected-token path makes it readable by more than the application it belongs to.

**A separate DataSphere scope for secrets.** Tempting, and it would bound key compromise per scope. Rejected for now because the keyholder holds every scope it is given and the data path cannot tell callers apart, so the isolation it *appears* to add is not there — while the moving parts (minting, bundle, deploy, rekey) are. It becomes worthwhile the moment decision 11's revisit lands, and not before.

**Per-application scopes without per-application identity.** This is the one that looks like the answer. It is not: the scope is declared by the caller in a header, so a second scope name is a label an application chooses, not a boundary it is held to.

**A dedicated secrets service.** More code, one more thing to deploy, one more thing to bill, and — without caller identity — exactly the same isolation as the keyholder has.

---

## Revisit trigger

**Per-application identity on the keyholder's data path.** The shape is already written down in the code that anticipates it: `keyholder.Server.resolve` says *"When 4.x derives it from the caller's own certificate, a request that omits it must already be a refusal."* Concretely it needs a per-application leaf from the instance CA, mounted into the workload; `ClientCAs` on `DataTLS`; the scope derived from the verified certificate rather than read from a header; and per-application scopes minted with the derivation [ADR 0008](0008-in-cluster-key-delivery.md) requires to be golden-vectored and independently reproduced before it is frozen.

That is a phase of work, not a section, and most of it is machinery Phase 5.4's planned ADR on thin-device storage through the keyholder needs anyway — that ADR has to settle what the keyholder serves an **operator** leaf versus an **application** one, which is the same question asked from the other side. When it lands, decisions 2 and 4 change and this ADR is reopened.

Until then the honest statement is the one in decision 2, and it is the reason `farcast secret` talks about applications sharing an instance rather than about applications being isolated from each other.
