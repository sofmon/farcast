# ADR 0020 — The Instance PKI Moves to ECDSA P-256

**Status:** Accepted (2026-11-11). Implemented 2026-11-13: the instance PKI issues and accepts ECDSA P-256 only, keepers enrol by request, LeafToken is v2, and FarSightKit's regression runs in `./check.sh` on macOS and the iOS simulator. Verification 3 (the re-walk) and 4 (the 7.5 gates) are owed. The re-walk is billable, about USD 0.40, and a separate session the operator approves before anything is created. The rest of this record keeps its 2026-11-11 wording. The evidence is a probe on the dev Mac (macOS 27, SDK 27.2) and the iOS 26.0 simulator. The findings below say which ran where. Nothing ran on a physical iPhone, an iPad or a Vision Pro.

**Date:** 2026-11-11

**Relates to:**
- **Takes the exit** that [ADR 0005](0005-fatline-data-plane-ingress.md)'s mTLS model left open. [`fatline/README.md:238`](../../fatline/README.md) records it as *"ECDSA P-256 fallback only if a peer rejects ed25519"*.
- **A prerequisite** of [ADR 0021](0021-farsight-native-client.md) (the native client).
- **Changes** how [ADR 0008](0008-in-cluster-key-delivery.md)'s keeper leaves are enrolled, and fixes how [ADR 0018](0018-thin-device-storage.md)'s device leaves will be.
- **Leaves alone** the keyholder's X25519 unseal envelope ([`datasphere/keyholder/envelope.go`](../../datasphere/keyholder/envelope.go)). That is key agreement, not TLS identity.
- **Takes a reserved number.** ADR 0008 (line 62) reserved "0020" for the replica-placement ADR. This ADR takes the number, and placement takes the next free one (corrected on acceptance, below).

---

## Context

Every certificate the instance PKI issues is Ed25519. That covers the per-instance CA, FatLine's and the keyholder's server leaves, the operator leaf, each application's leaf and each keeper's leaf. The choice lives in one file, [`fatline/internal/crypto/crypto.go`](../../fatline/internal/crypto/crypto.go): the header comment (lines 12–13), the import (17), and lines 41, 57, 104, 140 and 268–282. FatLine's README states the choice with its own exit: Ed25519, with a P-256 fallback "only if a peer rejects ed25519".

Peers have been rejecting it since Phase 2, without anyone calling it that condition. macOS's system curl is built on LibreSSL and cannot load the operator's Ed25519 leaf ([`phase-2-validation.md:416`](../runbooks/phase-2-validation.md)). The 3.2 runbook had to move its curl step into an Alpine pod for the same reason ([`phase-3-2-validation.md:158`](../runbooks/phase-3-2-validation.md), finding 4). Each time it was recorded as a client limitation and worked around, because every client that mattered was Go.

The FarSight GUI ends that. [ADR 0021](0021-farsight-native-client.md) proposes a native Swift client on Apple platforms. The keeper fleet also asks for hardware:
- **ADR 0008 finding 2** (line 106) requires the keeper leaf's private key, the bundle and the ledger to be device-bound and "hardware-wrapped". It defers hardware binding to 7.5 (line 123).
- **[PLAN](../../PLAN.md) 7.5** (line 464) asks for the bundle to be hardware-backed.

Both questions were tested on 2026-11-11.

### What Apple's TLS does with Ed25519 — probed, not recalled

**Setup:**
- *Client:* macOS 27 (SDK 27.2, Swift 6.4.2) and the iOS 26.0 simulator.
- *Server:* Go 1.27.3 TLS 1.3 servers on 127.0.0.1 that required client certificates.
- *Keys:* an Ed25519 PKI and a P-256 PKI side by side.
- *Control:* OpenSSL 3.5.9 `s_client` completed mutual TLS against every server, which shows both PKIs are valid.

**Findings:**
- **Apple does not offer Ed25519.** URLSession, Network.framework and WKWebView send `signature_algorithms` 0x0403 0x0804 0x0401 0x0503 0x0805 0x0501 0x0806 0x0601 0x0201, with no 0x0807.
  - *What happens:* a server whose leaf is Ed25519 aborts the handshake, and Go logs *"tls: peer doesn't support any of the certificate's signature algorithms"*. The client gets `errSSLPeerHandshakeFail` (-9824), which URLSession reports as `NSURLErrorDomain` -1200.
  - *Why app code can't fix it:* the handshake dies before any trust or client-certificate callback runs, and no public API adds an algorithm.
  - *It isn't new:* the same list appears in a 2021 trace on iOS 14.2 (Apple forum thread 674462).
- **Apple cannot present an Ed25519 key.**
  - The public SDK has no Ed25519 `SecKey` type.
  - `SecPKCS12Import` rejects an Ed25519 `.p12` with `errSecDecode` (-26275) in all three encodings tried.
  - An Ed25519 `SecIdentity` built through a private constant (`kSecAttrKeyTypeEd25519`, exported in `Security.tbd` with no header) still aborted the handshake locally with -9858, against a server that offered 0x0807.

  There is no shippable route, and the unshippable one fails too.
- **Apple's SSL server trust policy rejects any chain that contains an Ed25519 key,** leaf or CA. That is `SecPolicyCreateSSL` with a server name, and the error is `errSecUnsupportedKeySize` (-67735, *"Key size is not permitted for this use"*). The SSL client policy and `SecPolicyCreateBasicX509` accept the same chain, which matters for the hybrid under *Alternatives*.
- **P-256 works on stock APIs.**
  - *Setup:* a P-256 CA as the only anchor (`SecTrustSetAnchorCertificatesOnly`), and the server name pinned through `SecPolicyCreateSSL`.
  - *Clients that completed TLS 1.3 mutual authentication:* URLSession over HTTP/2, `NWConnection` over HTTP/1.1, and WKWebView.
  - *Server view:* Go logged an ECDSA client certificate. A wrong server name was refused (-67602).
  - *Where the client identity came from:*
    - an in-memory PKCS#12 import (`kSecImportToMemoryOnly`, macOS 15 / iOS 18);
    - `SecIdentityCreate`;
    - a Secure Enclave P-256 key wrapped by `SecIdentityCreate`, with no keychain item written.

    That Secure Enclave key was non-permanent and used in the foreground. A keeper needs a permanent key, held in the data-protection keychain and used from a background task while the device is locked, and that was not tested. Apple DTS advised against `SecIdentityCreate` in January 2025, so the keeper forms its identity from the keychain instead (Verification).

**Which findings ran where:**
- *On both macOS 27 and the iOS 26.0 simulator:* URLSession's missing 0x0807 and its Ed25519 failure, the server-policy rejection of an Ed25519 CA, and URLSession P-256 mutual TLS.
- *On macOS 27 only:*
  - WKWebView mutual TLS;
  - the PKCS#12 and private-SPI failures;
  - the Secure Enclave identity (the simulator has no Secure Enclave).

  iOS, iPadOS and visionOS behaviour on these is inferred from the shared stack.

Apple support article 126655 (2026-06-16) is consistent with this, but it is not the cause. From OS 27, App Transport Security flags a server certificate whose signature algorithm the ClientHello did not advertise, and sets key-size minimums of RSA 2048 and ECDSA 256. It does not mention Ed25519. Security.framework already parses Ed25519 internally, so public support may come later. Nothing public showed it on 2026-11-11.

### What the hardware on each target will hold

- **Apple Secure Enclave.** For signing in the public API, P-256 only (iOS 13 and later). From OS 26, CryptoKit adds ML-DSA-65/87 and ML-KEM-768/1024. Keys are generated inside the enclave and cannot be imported (`SecItem.h` and the CryptoKit interface, SDK 27.2).
- **Android.**
  - KeyMint 2 (Android 13) added Curve25519 to the TEE, but StrongBox, itself optional hardware, refuses it.
  - Conscrypt, the platform TLS stack, accepts only RSA and EC Keystore keys for TLS and advertises no Ed25519 for verification.
  - P-256 works in both the TEE and StrongBox.
- **Windows.** CNG lists ECDSA P-256/384/521, RSA and ML-DSA, and no EdDSA. Chromium's TPM-backed keys map only ECDSA P-256 and RSA.
- **Chromium,** and so Electron, WebView2 and Android WebView, has no Ed25519 in its verify preferences either.

So Ed25519 is not an Apple quirk:
- **No platform TLS stack accepts it.** Apple and Chromium were probed or read, Conscrypt was read, and Schannel's absence is inferred from CNG.
- **No hardware key store can use an Ed25519 key for platform TLS.** The Android TEE can hold one from Android 13, but Conscrypt cannot present it.
- **Platforms are moving to ML-DSA next,** not to Ed25519.

### Where FarCast stands

- **Only `crypto.go` knows the algorithm.** Every consumer loads keys through `tls.X509KeyPair` or `tls.LoadX509KeyPair`, and neither cares which algorithm the key uses:
  - [`sdk/go/storageclient.go:138`](../../sdk/go/storageclient.go)
  - [`datasphere/keyholder/tls.go:114`](../../datasphere/keyholder/tls.go)
  - [`farsight/cli/internal/cli/keeper.go:46`](../../farsight/cli/internal/cli/keeper.go)
  - [`farsight/cli/internal/keyholder/client.go:209`](../../farsight/cli/internal/keyholder/client.go)
  - [`fatline/identity/identity.go:291`](../../fatline/identity/identity.go)
  - [`fatline/cmd/fatline/main.go:89`](../../fatline/cmd/fatline/main.go)

  Elsewhere, Ed25519 appears only in a test fixture ([`datasphere/keyholder/tls_test.go:161-188`](../../datasphere/keyholder/tls_test.go)) and a comment ([`walkprobe_test.go:10`](../../farsight/cli/internal/cli/walkprobe_test.go)).
- **The keeper's bundle binding is unaffected; LeafToken is not.**
  - *The binding:* a URI SAN inside the signed certificate body, so the signature change does not touch it.
  - *LeafToken is the exception:* it hashes the leaf's whole DER ([`identity.go:110-115`](../../fatline/identity/identity.go), over the bytes the peer presented at [`admit.go:73`](../../fatline/admit.go)). An Ed25519 signature has one valid encoding. An ECDSA signature does not: (r, n−s) verifies as well as (r, s), and Go does not insist on low s.
  - *The consequence:* under a P-256 CA, a leaf holder could present a second valid DER of the same certificate and get a second token. The operator's records would then show that leaf as "not enrolled from this machine" instead of by its device name. Decision 4 handles it.
- **No instance exists.** Every walk instance was released the day it was walked. For the last one, see [`phase-5-session-a.md:212`](../runbooks/phase-5-session-a.md). farcast.one is still pending.
- **There is no CA rotation.** `farcast connect` refuses to re-mint a CA for a deployed instance ([`connect.go:305-314`](../../farsight/cli/internal/cli/connect.go)). Once clients ship, changing the algorithm means reinstalling every instance or building a rotation feature. Today it costs one re-walk, about USD 0.40.
- **Keeper leaf keys are minted on the operator's machine** ([`identity.go:214`](../../fatline/identity/identity.go), through `crypto.go:140`) and travel inside the keeper packet ([`keeper.go:228`](../../farsight/cli/internal/cli/keeper.go)). Importing such a key into a device-only keychain item would meet ADR 0008's "hardware-wrapped". A key *generated* in hardware cannot be made this way under any algorithm, because a Secure Enclave cannot import a key.

## Decisions

**1. Every key the instance PKI issues is ECDSA P-256.**
- *What it covers:* the CA, every server leaf, and the operator, application, keeper and (once ADR 0018 decision 2 is built) device leaves.
- *One algorithm, no mix:* ECDSA over P-256 with SHA-256, which is the TLS 1.3 scheme `ecdsa_secp256r1_sha256` (0x0403).
- *What stays the same:* TLS 1.3 only, `RequireAndVerifyClientCert`, the URI-SAN identities, the admission rule ([`fatline/admit.go`](../../fatline/admit.go)), CA validity of about 2 years and leaves of 90 days.
- *Implementation:* `crypto/ecdsa` with `elliptic.P256()`. FarCast implements no ECDSA itself. Go's package is constant-time on P-256 and mixes the private key and message with its entropy, so a failing random source does not leak the key through nonce reuse (package doc, Go 1.27.3).
- *Out of scope: where the CA key lives.* It stays a PKCS#8 file at 0600 on the operator's machine. P-256 is the first algorithm under which it *could* live in a Secure Enclave or a TPM. But such a key cannot be exported, so it could not join ADR 0008's backup follow-up, and with no CA rotation a lost machine would then lose the instance for good. That needs its own ADR, after rotation exists.

**2. Ed25519 is refused, not tolerated.**
- *Issuance:* `LoadCA` and key parsing accept an `*ecdsa.PrivateKey` on P-256 and nothing else. An Ed25519 CA fails with a message that names this ADR and says *release and reinstall*. So an instance store from before this ADR can no longer `run`, enrol or `connect`. Other commands are not separately guarded, because the set of such stores is empty today.
- *Verification, as defence in depth:* `ServerTLSConfig` and the keyholder's TLS configs refuse a peer leaf whose key is not P-256.
- *No dual-serving and no hybrid chain* (see *Alternatives*).

**3. A device-held leaf's key is generated where it will live, and never travels.** This applies to keeper leaves now and to device leaves when they are built.

**Where the key is born.** The device generates a fresh P-256 key:
- the Secure Enclave on Apple;
- StrongBox where present, otherwise the TEE, on Android;
- a TPM 2.0 key through the Platform Crypto Provider on Windows where present;
- otherwise, and on a desktop keeper, a 0600 file under today's rest rules.

The request records which. `keeper request` creates the keeper directory under `keeper install`'s rules before it generates anything: synced folders refused, backup exclusion read back, 0700/0600. So the key never rests unprotected.

**The request.** A PKCS#10 certificate request, sent out of band as the packet travels today. It travels unauthenticated. So:
- the device shows the SHA-256 fingerprint of the request's SubjectPublicKeyInfo;
- `keeper enroll` shows the same fingerprint and issues only once the operator confirms it against the device's screen, or passes `--key-sha256 <hex>`;
- the fingerprint covers the SubjectPublicKeyInfo, not the request bytes, because an ECDSA request's signature has more than one valid encoding.

*(Note, 2026-11-13, as built: `keeper enroll` meets "shows the same fingerprint" by showing it once it matches, never before. Shown first and then asked for, the request's fingerprint — which is the sender's value until confirmed — can be copied back from the line above, or from the scrollback of a failed attempt, and that confirms nothing; the habituation that rules out a bare "yes" rules that out too. So at a terminal the operator types the fingerprint as the device shows it, all 16 groups or at least the last 8 (128 bits, P-256's security level); the full fingerprint is printed after a match, as confirmed, and no refusal prints any of it. `--key-sha256` takes all 64 characters, for scripts and the runbooks. This is a stricter reading of the sentence above, not a change to it.)*

**What the operator's machine checks.** It parses the request and requires all of the following, explicitly:
- `PublicKeyAlgorithm` ECDSA;
- the curve P-256;
- `SignatureAlgorithm` ECDSA-with-SHA256;
- a valid self-signature (`CheckSignature`), which proves the device holds the key.

The checks are explicit because `CheckSignature` alone accepts SHA-1 and parses Ed25519, RSA, other curves and ML-DSA keys. Without them, decision 1's single algorithm would not hold.

**What it honours.** Nothing in the request but the public key. The identity URI, the keeper's bundle-digest binding, the EKU and the validity period stay the operator's to choose, as now.

**One key, one device, one instance.**
- A device generates a new key for each instance and for each `keeper request`. A key is never reused across instances, where it would become a cross-instance pseudonym of the kind [`identity.go:99-109`](../../fatline/identity/identity.go) avoids, and never across a revoke.
- Each keeper record stores the SPKI fingerprints it certified.
- `enroll` refuses a fingerprint already recorded under another device or on a revoked device.

**The return packet stays passphrase-armored.** It carries the certificate and the bundle, and no private key. The bundle is still the secret.

**Install checks the match.** `keeper install` refuses a certificate whose key is not its own, and says so as a security event: the leaf was issued to someone else's key. The operator revokes and rotates, as for a disclosed packet.

**The proposed command shape:**
1. `farcast keeper request <instance>` on the device writes the key and the request, and prints the fingerprint.
2. `farcast keeper enroll <instance> <device> --request <file>` on the operator's machine writes the packet.
3. `farcast keeper install <packet>` on the device installs the certificate and bundle beside its own key.

**Building the request without an ASN.1 library.** The device side is a template. The only parts that vary are:
- the uncompressed P-256 point (65 bytes, 0x04‖X‖Y, which is what `SecKeyCopyExternalRepresentation` returns);
- the ecdsa-with-SHA256 signature;
- the length octets that the signature's DER encoding changes.

The conformance vectors include signatures whose r or s needs a 0x00 pad, and ones with a short encoding. An Apple client builds the request with system frameworks and no ASN.1 library ([ADR 0021](0021-farsight-native-client.md) decision 3), and the Go parser checks it against the vectors.

**Leaves that stay operator-minted.** Operator, application and server leaves stay as they are:
- **the operator leaf** lives on the machine that holds the CA;
- **application and server leaves** rest in Secrets (ADR 0008's concession, unchanged).

**4. LeafToken hashes the signed certificate body, not the whole DER.**
- *What it hashes:* `LeafToken` and `LeafTokenPEM` hash `RawTBSCertificate`, the part the CA signs, under a new domain label (`farcast-leaf-token-v2`).
- *Why it is still unique:* the leaf's random serial and key keep the body unique per leaf. Re-encoding the signature no longer changes the token.
- *What else holds:* the token stays unknown to the cloud, because TLS 1.3 keeps the client certificate encrypted, and it is still recorded at enrolment.

**5. Migration: none.** No instance exists. After the change lands, the Phase 5 Session A runbook is walked again, with the rewrites under Verification.

**6. ML-DSA is the next algorithm, not Ed25519.** The Secure Enclave already holds ML-DSA keys from OS 26, and Go 1.27.3's CertificateRequest already advertises ML-DSA. Apple's TLS stack does not advertise it yet. When it does, the instance PKI is reconsidered (Revisit triggers).

## Alternatives considered

- **Keep Ed25519 and bundle a TLS stack in every client.**
  - *Go c-archive:* probed. Ed25519 mutual TLS over HTTP/2 completed in the iOS 26 simulator.
  - *swift-nio-ssl:* its API offers Ed25519; it was not run.

  Rejected:
  - it puts a second TLS stack in every client, either Go code that Swift's concurrency checks do not see or a third-party package;
  - the leaf key could be hardware-*wrapped* but never generated in hardware;
  - a WKWebView tile cannot use the bundled stack directly anyway, and needs the loopback bridge ADR 0021 describes either way.
- **Hybrid: an Ed25519 CA with P-256 leaves.** `NWConnection` completed the handshake only with a `SecPolicyCreateBasicX509` trust handler. That policy checks neither the server name nor the certificate's purpose, so every client would have to carry hand-written name and EKU checks. Without them, an application leaf from the same CA would pass as the server. Rejected: that is security-critical code on hostile input, written by an AI, which nobody reviews.
- **Serve both leaf types from the Go servers.** Probed: Go picks the leaf per ClientHello. Rejected, because it only helps live instances and there are none.
- **P-384.** The Secure Enclave does not hold it, StrongBox mandates only P-256, and it buys nothing at this threat model.
- **RSA.** Windows Hello's `KeyCredential` keys are RSA-2048, so a Hello-gated Windows key is the one place P-256 is worse. A TPM key through the Platform Crypto Provider is P-256, and Hello gating is not a requirement. Revisit if it becomes one.
- **Apple's private Ed25519 SPI.** It is not shippable, and it failed the handshake anyway.

## Consequences

**Positive**
- **Platform TLS everywhere.** Every platform's own TLS stack can open FatLine's tunnel directly, so ADR 0021's clients need no TLS library of their own for that. The keeper's second, inner TLS session to the keyholder runs over a FatLine stream, and URLSession and `NWConnection` cannot take a stream as their transport. That path is a 7.5 gate (Verification).
- **Hardware keys where the hardware exists.** Keeper and device leaf keys can be non-exportable hardware keys wherever the device has a Secure Enclave, an Android TEE or StrongBox, or a TPM 2.0. That goes beyond ADR 0008's "wrapped" for the leaf-key half of finding 2.
- **What this does not deliver: the bundle's half.** Wrapping the bundle at rest under a hardware key, which PLAN 7.5 asks for, is still owed by 7.5. That wrapping key is separate from the leaf key, which signs only TLS handshakes and its own request.
- **A packet in transit no longer carries a leaf.** A keeper's leaf key never exists on the operator's machine or in a packet. A packet intercepted in transit yields the bundle, as it does today, but no longer a usable leaf, provided the request's fingerprint was confirmed. Packet plus passphrase therefore no longer lets anyone re-seed through the tunnel.
- **curl may work again.** The runbooks' LibreSSL curl workaround should become unnecessary. That is to be confirmed on the next walk, not assumed.

**Negative**
- **Enrolment gains a round trip.** The keeper CLI gains a verb, and the operator a fingerprint to compare.
- **ECDSA is less forgiving to implement than Ed25519** when the nonce is wrong, and its signatures have more than one valid encoding. FarCast implements neither: signing is Go's, the Secure Enclave's, StrongBox's or the TPM's. The one place the encoding mattered (LeafToken) is decision 4.
- **Neither choice is post-quantum for signatures.** Key exchange is separate and was not tested here.

**Per-module implications.**
- *FatLine:*
  - `crypto.go` gets P-256 in `NewCA` and `issue`, a P-256-only key parser (`parseEd25519Key` goes), and `IssueClientFromRequest`, which takes request DER plus the operator's identity, EKU and bindings and applies decision 3's checks.
  - Peer-key refusal in `ServerTLSConfig`.
  - Its header comment is updated.
- *Identity:*
  - `IssueKeeperClient` takes a request instead of minting a key. `IssueDeviceClient` follows later, on the same path.
  - `LeafToken` and `LeafTokenPEM` move to `RawTBSCertificate` under the v2 label.
- *DataSphere keyholder:* peer-key refusal in its TLS configs. The `tls_test.go` fixture moves to P-256.
- *FarSight CLI:*
  - `keeper request`, `keeper enroll --request` with the fingerprint confirmation, and the certificate-matches-key refusal in `keeper install`.
  - Keeper records gain SPKI fingerprints.
  - `warnPacketDisclosure` ([`keeper.go:299-305`](../../farsight/cli/internal/cli/keeper.go)) now says the packet exposes the bundle but no longer re-seeds.
  - `connect` refuses an Ed25519 store and names this ADR.
- *Keeper package* ([`farsight/cli/internal/keeper`](../../farsight/cli/internal/keeper/)):
  - Packet version 2 drops `leaf_key_pem`.
  - `Validate` refuses a v2 packet that carries a key, and names this ADR for a v1 packet.
  - `keeper request` applies `Install`'s directory rules before generating the key.
  - `Install` writes only the certificate and bundle.
  - `keeper_test.go`'s "no key" case becomes "a key present is refused".
- *Walk probe* ([`walkprobe_test.go`](../../farsight/cli/internal/cli/walkprobe_test.go)):
  - `FARCAST_WALK_LEAF=packet:` is retired.
  - The `packet` probe FAILs if a packet carries any private key.
  - Dishonest-keeper checks present a walk keeper enrolled by request into a scratch store on the operator's machine, through the existing `store:<dir>` inputs.
- *Tests.* Each of these is shown to fail with the defect restored, as the repository's mutation practice requires:
  - every issuer emits P-256;
  - `LoadCA` refuses an Ed25519 key with this ADR named;
  - a request carrying an Ed25519, RSA, P-384 or ML-DSA key, or signed with ECDSA-SHA1, is refused;
  - SANs, EKU and validity carried in a request are ignored;
  - a request whose signature does not verify is refused;
  - a fingerprint mismatch is refused;
  - a fingerprint already recorded under another device or a revoked one is refused;
  - a leaf re-signed with s′ = n − s keeps its token;
  - a non-P-256 peer leaf is refused by FatLine and the keyholder.
- *Conformance vectors* (ADR 0021 decision 7): the Go tests emit a P-256 PKI fixture and request vectors, padded and short signatures included, that every client's tests consume.

**Sentences this ADR corrected on acceptance (2026-11-11).** A document that describes the code as built keeps describing it and gains a pointer here. It is rewritten when the code changes.
- [`fatline/README.md:238`](../../fatline/README.md) and `:295`: the fallback is recorded as taken, and Ed25519 stays named as what the code issues.
- [`farsight/cli/README.md`](../../farsight/cli/README.md): the `keeper` row, a note under the keeper synopsis, and the packet paragraph now say that enrolment becomes a request and the packet stops carrying the leaf key.
- [ADR 0008 line 62](0008-in-cluster-key-delivery.md): the placement ADR takes the next free number.
- [PLAN](../../PLAN.md) 7.5 gains a bullet: the leaf key is generated in the Secure Enclave and enrolled by request, and wrapping the bundle at rest is still owed there.
- A dated note beside [`phase-2-validation.md:416`](../runbooks/phase-2-validation.md) and [`phase-3-2-validation.md:158,299`](../runbooks/phase-3-2-validation.md). Those are walk records, and they keep what they found.

**Changed with the code, not before it:** `crypto.go:12-13`, `walkprobe_test.go:10`, and the CLI README's keeper synopsis and packet paragraph themselves. They are rewritten when `keeper request` exists.

## Verification

1. **Unit and mutation tests,** as listed under *Per-module implications*.
2. **The client regression.** ADR 0021's Apple package tests mutual TLS against a Go test server built from the P-256 fixture, over URLSession and `NWConnection`, plus a negative test against an Ed25519 server. If an OS update ever changes Apple's behaviour in either direction, a test says so.
3. **The re-walk.** The Phase 5 Session A runbook against a fresh instance:
   - steps S9, S11, S16, S17 and 7h, and `phase-5-4-validation.md`'s device steps, are rewritten to present the walk keeper enrolled by request;
   - device A is enrolled by request, and its private key is shown to be absent from the packet and from every file on the operator's machine;
   - the LibreSSL curl step is attempted and its result recorded.
4. **7.5 gates, not this ADR's, recorded here because this ADR makes them possible:**
   - on a physical iPhone, a permanent Secure Enclave key (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, keychain-formed identity) signs a TLS handshake from a background task with the device locked;
   - the keeper's inner mutual TLS to a Go keyholder test server, carried over a FatLine stream, presents that key, through a Swift loopback relay or ADR 0021 decision 7's Go fallback.

   *(2026-11-13: [ADR 0023](0023-one-download-farcast.md), accepted that day, adds a Mac case beside the permanent key the Context leaves untested, as a probe in its M5: a Secure Enclave P-256 key kept by a Developer ID app without App Sandbox. The candidate is a non-permanent key whose `dataRepresentation` blob sits in a 0600 file, and the probe both creates the key and restores it from that file. It is ADR 0023's M5 dependency, not a 7.5 gate, and it changes nothing this ADR decided.)*

## Revisit triggers

- Apple's TLS stack advertises ML-DSA (0x0904–0x0906) in its ClientHello. That would make a post-quantum, Secure Enclave-held identity possible on Apple.
- Apple makes Ed25519 public in Security.framework and Network.framework. That would not reverse this ADR by itself, since hardware stores on the other targets still require P-256.
- A CA rotation feature is built. The algorithm then becomes changeable for live instances, and a hardware-held CA key becomes discussable.
- A requirement for Windows Hello-gated keys (RSA-2048).

## Sources

- Local probe on macOS 27 / SDK 27.2, Swift 6.4.2, Go 1.27.3, OpenSSL 3.5.9 and the iOS 26.0 simulator, 2026-11-11. The results are recorded above with error codes and the platform each ran on. The probe code was a scratch artifact. Verification step 2's regression replaces it.
- Apple — *Prepare your network environment for stricter security requirements* (support article 126655, 2026-06-16): https://support.apple.com/126655 · *Requirements for trusted certificates in iOS 13 and macOS 10.15*: https://support.apple.com/103769 · Developer forum thread 674462 (Apple's ClientHello signature algorithms, iOS 14.2): https://developer.apple.com/forums/thread/674462
- Apple SDK 27.2 headers: `Security.framework/Headers/SecItem.h` (key types; the Secure Enclave is 256-bit EC only, with no import), `SecImportExport.h` (`kSecImportToMemoryOnly`), and the CryptoKit `.swiftinterface` (the `SecureEnclave` namespace).
- Android — Keystore: https://developer.android.com/privacy-and-security/keystore · KeyMint features: https://source.android.com/docs/security/features/keystore · `IKeyMintDevice.aidl` (StrongBox curves): https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/security/keymint/aidl/android/hardware/security/keymint/IKeyMintDevice.aidl
- Microsoft — CNG algorithm identifiers: https://learn.microsoft.com/en-us/windows/win32/SecCNG/cng-algorithm-identifiers
- Chromium — `net/socket/ssl_client_socket_impl.cc` (verify preferences) and `crypto/unexportable_key_win.cc` (TPM key algorithms), main branch, fetched 2026-11-11.
- Go 1.27.3 — `crypto/ecdsa` package documentation (nonce entropy, constant time), and `crypto/x509` `CertificateRequest.CheckSignature` (`x509.go:2414-2415`, which allows SHA-1).

---

*This ADR is a living record. Revisit it on any trigger above.*
