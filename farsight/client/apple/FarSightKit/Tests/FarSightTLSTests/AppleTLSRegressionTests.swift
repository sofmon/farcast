import Foundation
import Network
import Security
import Testing

/// What a fixture server answers: the client as Go's server saw it.
struct Echo: Decodable, Equatable {
    let client: String
    let key: String
    let tls: String
    let proto: String
}

/// ADR 0020's Apple regression (ADR 0021 Verification 1), live: URLSession
/// and NWConnection against Go servers that run FatLine's own server config
/// over the PKI vectors. `./check.sh` starts the servers and requires each of
/// these to pass by name in all three of its runs (swift test, and xcodebuild
/// test on macOS and the iOS simulator). With no server, they are skipped.
@Suite("ADR 0020's Apple regression, live against FatLine's server config", .serialized)
struct AppleTLSRegressionTests {
    /// errSSLPeerHandshakeFail: what Apple's TLS reports when the server's
    /// certificate is Ed25519, before any trust evaluation.
    static let handshakeFailure: OSStatus = -9824

    static let revisit = "Apple's TLS now reaches trust evaluation against an Ed25519 server: revisit ADR 0020 (Revisit triggers)"

    /// How many connections CFNetwork tries for one GET whose connection is
    /// reset after the handshake: the first, and two retries (probed
    /// 2026-11-13, with a server that resets every attempt).
    static let getAttempts = 3

    static func fixture() throws -> PKIFixture { try PKIVectors.fixture("p256") }

    /// The HTTP/1.1 status line and body of a raw response.
    static func http(_ text: String) throws -> (status: String, body: Data) {
        let parts = text.components(separatedBy: "\r\n\r\n")
        guard parts.count >= 2, let status = parts[0].components(separatedBy: "\r\n").first else {
            throw VectorError("not an HTTP response")
        }
        return (status, Data(parts.dropFirst().joined(separator: "\r\n\r\n").utf8))
    }

    @Test(
        "ADR 0020 live: URLSession completes TLS 1.3 mutual authentication against FatLine's server config",
        .enabled(if: FixtureServers.configured, "the Go fixture server is not running: ./check.sh starts it"),
        .timeLimit(.minutes(1))
    )
    func urlSessionMutualTLS() async throws {
        let fixture = try Self.fixture()
        let client = try #require(fixture.client)
        let delegate = PinnedSessionDelegate(fixture: fixture)
        let (data, response) = try await delegate.get(try FixtureServers.address(.p256).url)
        #expect(response.statusCode == 200)
        let echo = try JSONDecoder().decode(Echo.self, from: data)
        #expect(echo == Echo(client: try #require(client.identity), key: "ECDSA P-256", tls: "1.3", proto: "HTTP/2.0"))
        #expect(delegate.trustCalls == 1)
        #expect(delegate.identityCalls == 1)
    }

    @Test(
        "ADR 0020 live: NWConnection completes TLS 1.3 mutual authentication against FatLine's server config",
        .enabled(if: FixtureServers.configured, "the Go fixture server is not running: ./check.sh starts it"),
        .timeLimit(.minutes(1))
    )
    func nwConnectionMutualTLS() async throws {
        let fixture = try Self.fixture()
        let client = try #require(fixture.client)
        let identity = try ClientIdentity.operatorIdentity(fixture)
        let response = try await NWFetch.get(
            try FixtureServers.address(.p256), identity: identity, pinnedKeySHA256: try fixture.server.fingerprint)
        let (status, body) = try Self.http(response.text)
        #expect(status.hasPrefix("HTTP/1.1 200 "))
        let echo = try JSONDecoder().decode(Echo.self, from: body)
        #expect(echo == Echo(client: try #require(client.identity), key: "ECDSA P-256", tls: "1.3", proto: "HTTP/1.1"))
        #expect(response.verifyCalls == 1)
    }

    @Test(
        "ADR 0020 live: URLSession cannot reach an Ed25519 server, and no trust callback runs",
        .enabled(if: FixtureServers.configured, "the Go fixture server is not running: ./check.sh starts it"),
        .timeLimit(.minutes(1))
    )
    func urlSessionRefusesEd25519() async throws {
        let delegate = PinnedSessionDelegate(fixture: try Self.fixture())
        do {
            _ = try await delegate.get(try FixtureServers.address(.ed25519).url)
            Issue.record(Comment(rawValue: Self.revisit))
        } catch let error as URLError {
            #expect(error.code == .secureConnectionFailed)
            if let stream = error.errorUserInfo["_kCFStreamErrorCodeKey"] as? Int {
                #expect(stream == Int(Self.handshakeFailure))
            }
        }
        if delegate.trustCalls != 0 {
            Issue.record(Comment(rawValue: Self.revisit))
        }
    }

    @Test(
        "ADR 0020 live: NWConnection cannot reach an Ed25519 server, and its verify block never runs",
        .enabled(if: FixtureServers.configured, "the Go fixture server is not running: ./check.sh starts it"),
        .timeLimit(.minutes(1))
    )
    func nwConnectionRefusesEd25519() async throws {
        let fixture = try Self.fixture()
        let identity = try ClientIdentity.operatorIdentity(fixture)
        do {
            _ = try await NWFetch.get(
                try FixtureServers.address(.ed25519), identity: identity, pinnedKeySHA256: try fixture.server.fingerprint)
            Issue.record(Comment(rawValue: Self.revisit))
        } catch let failure as NWFetchFailure {
            #expect(failure.verifyCalls == 0)
            let tlsStatus: OSStatus? =
                if let error = failure.error as? NWError, case .tls(let status) = error { status } else { nil }
            #expect(tlsStatus == Self.handshakeFailure, "\(failure.error)")
        }
    }

    @Test(
        "ADR 0020 live: the pinned trust refuses the server under another name",
        .enabled(if: FixtureServers.configured, "the Go fixture server is not running: ./check.sh starts it"),
        .timeLimit(.minutes(1))
    )
    func pinnedTrustRefusesAnotherName() async throws {
        let delegate = PinnedSessionDelegate(fixture: try Self.fixture(), pinnedName: "other.fatline.farcast")
        do {
            _ = try await delegate.get(try FixtureServers.address(.p256).url)
            Issue.record("the pinned trust accepted the server under another name")
        } catch let error as URLError {
            #expect(error.code == .cancelled)
        }
        #expect(delegate.trustCalls == 1)
    }

    @Test(
        "ADR 0020 live: the pinned trust refuses a server from another CA",
        .enabled(if: FixtureServers.configured, "the Go fixture server is not running: ./check.sh starts it"),
        .timeLimit(.minutes(1))
    )
    func pinnedTrustRefusesAnotherCA() async throws {
        let delegate = PinnedSessionDelegate(fixture: try Self.fixture())
        do {
            _ = try await delegate.get(try FixtureServers.address(.foreign).url)
            Issue.record("the pinned trust accepted a server from another CA with the same subject")
        } catch let error as URLError {
            #expect(error.code == .cancelled)
        }
        #expect(delegate.trustCalls == 1)
        #expect(delegate.identityCalls == 0)
    }

    @Test(
        "ADR 0020 live: FatLine's server config refuses a client with no identity",
        .enabled(if: FixtureServers.configured, "the Go fixture server is not running: ./check.sh starts it"),
        .timeLimit(.minutes(1))
    )
    func serverRefusesAClientWithNoIdentity() async throws {
        let delegate = PinnedSessionDelegate(fixture: try Self.fixture(), presentIdentity: false)
        do {
            _ = try await delegate.get(try FixtureServers.address(.p256).url)
            Issue.record("FatLine's server config admitted a client with no identity")
        } catch let error as URLError {
            if error.code == .networkConnectionLost {
                // Every attempt lost the alert to the reset, so the last
                // error is the reset's own.
                #expect(delegate.trustCalls == Self.getAttempts)
            } else {
                #expect(error.code == .clientCertificateRequired)
            }
        }
        // Go's certificate_required alert comes after Apple's side of the
        // TLS 1.3 handshake has finished, and Go closes the connection right
        // after it, onto the request the client has already sent. When the
        // reset reaches the client before it has read the alert, CFNetwork
        // retries the GET on a new connection, up to getAttempts attempts in
        // all, and each attempt asks once for trust and once for an identity.
        #expect((1...Self.getAttempts).contains(delegate.trustCalls))
        #expect(delegate.identityCalls == delegate.trustCalls)
    }
}
