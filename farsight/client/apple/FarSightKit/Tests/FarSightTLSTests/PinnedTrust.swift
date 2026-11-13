import Foundation
import Security
import Synchronization

/// How a FarSight client trusts its instance: the instance's own CA as the
/// only anchor, the SSL policy for the server name it pins, at a given time.
enum PinnedTrust {
    static func evaluate(_ trust: SecTrust, anchorDER: Data, serverName: String, at verifyAt: Date) -> Bool {
        guard let anchor = SecCertificateCreateWithData(nil, anchorDER as CFData),
              SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, serverName as CFString)) == errSecSuccess,
              SecTrustSetAnchorCertificates(trust, [anchor] as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
              SecTrustSetVerifyDate(trust, verifyAt as CFDate) == errSecSuccess
        else {
            return false
        }
        return SecTrustEvaluateWithError(trust, nil)
    }
}

/// A URLSession delegate that trusts only the fixture's CA under a pinned
/// name, and answers a client-certificate challenge with the fixture's
/// operator identity, formed in memory. It counts both challenges, so a test
/// can tell a refusal at trust evaluation from one before it.
final class PinnedSessionDelegate: NSObject, URLSessionTaskDelegate, Sendable {
    let fixture: PKIFixture
    let pinnedName: String
    /// False answers the client-certificate challenge with default handling,
    /// which presents no certificate.
    let presentIdentity: Bool
    let trustAsked = Mutex(0)
    let identityAsked = Mutex(0)

    init(fixture: PKIFixture, pinnedName: String? = nil, presentIdentity: Bool = true) {
        self.fixture = fixture
        self.pinnedName = pinnedName ?? fixture.serverName
        self.presentIdentity = presentIdentity
    }

    var trustCalls: Int { trustAsked.withLock { $0 } }
    var identityCalls: Int { identityAsked.withLock { $0 } }

    func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge) async
        -> (URLSession.AuthChallengeDisposition, URLCredential?)
    {
        switch challenge.protectionSpace.authenticationMethod {
        case NSURLAuthenticationMethodServerTrust:
            trustAsked.withLock { $0 += 1 }
            guard let trust = challenge.protectionSpace.serverTrust,
                  let anchor = try? fixture.ca.certificateDER,
                  PinnedTrust.evaluate(trust, anchorDER: anchor, serverName: pinnedName, at: fixture.verifyAt)
            else {
                return (.cancelAuthenticationChallenge, nil)
            }
            return (.useCredential, URLCredential(trust: trust))
        case NSURLAuthenticationMethodClientCertificate:
            identityAsked.withLock { $0 += 1 }
            guard presentIdentity else { return (.performDefaultHandling, nil) }
            guard let identity = try? ClientIdentity.operatorIdentity(fixture) else {
                return (.cancelAuthenticationChallenge, nil)
            }
            return (.useCredential, URLCredential(identity: identity, certificates: nil, persistence: .forSession))
        default:
            return (.performDefaultHandling, nil)
        }
    }

    /// GET `url` in an ephemeral session of its own, so no TLS session is
    /// resumed from another test and every challenge reaches this delegate.
    func get(_ url: URL) async throws -> (Data, HTTPURLResponse) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 10
        let session = URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        let (data, response) = try await session.data(from: url)
        guard let http = response as? HTTPURLResponse else { throw VectorError("not an HTTP response") }
        return (data, http)
    }
}
