import Foundation
import Network

/// The Go servers of `fatline/internal/crypto/applefixture_test.go`, which
/// `./check.sh` starts on 127.0.0.1 and names to these tests: as
/// `FARSIGHT_TLS_*` to `swift test`, and as `TEST_RUNNER_FARSIGHT_TLS_*` to
/// `xcodebuild test`, which strips the prefix on the way to the runner.
enum FixtureServer: String, CaseIterable, Sendable {
    /// FatLine's server config, presenting the P-256 fixture's server leaf.
    case p256 = "FARSIGHT_TLS_P256"
    /// The same config, presenting a leaf from another CA with the same subject.
    case foreign = "FARSIGHT_TLS_FOREIGN"
    /// The same config, presenting a leaf of the retired Ed25519 PKI.
    case ed25519 = "FARSIGHT_TLS_ED25519"
}

struct FixtureAddress: Sendable {
    let host: String
    let port: NWEndpoint.Port
    let url: URL
}

enum FixtureServers {
    /// True only when all three addresses are set. The live tests are
    /// skipped otherwise, and `./check.sh` counts their passes by name, so a
    /// skip there fails the check.
    static var configured: Bool {
        FixtureServer.allCases.allSatisfy { ProcessInfo.processInfo.environment[$0.rawValue] != nil }
    }

    /// The server's address. A value that is set but malformed fails the test
    /// that reads it: it is never a reason to skip.
    static func address(_ server: FixtureServer) throws -> FixtureAddress {
        guard let value = ProcessInfo.processInfo.environment[server.rawValue] else {
            throw VectorError("\(server.rawValue) is not set")
        }
        return try parse(value, variable: server.rawValue)
    }

    /// `127.0.0.1:<1-65535>`, and nothing else: the fixture listens on
    /// loopback only.
    static func parse(_ value: String, variable: String) throws -> FixtureAddress {
        let prefix = "127.0.0.1:"
        let digits = value.hasPrefix(prefix) ? value.dropFirst(prefix.count) : ""
        guard !digits.isEmpty, digits.count <= 5, digits.allSatisfy({ $0.isASCII && $0.isWholeNumber }),
              let number = UInt16(digits), number > 0, let port = NWEndpoint.Port(rawValue: number),
              let url = URL(string: "https://127.0.0.1:\(number)/")
        else {
            throw VectorError("\(variable) is '\(value)', not 127.0.0.1:<port>")
        }
        return FixtureAddress(host: "127.0.0.1", port: port, url: url)
    }
}
