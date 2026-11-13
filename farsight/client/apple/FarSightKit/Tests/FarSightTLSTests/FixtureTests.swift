import CryptoKit
import Foundation
import Security
import Testing

/// What the live regression rests on, checked with no server: the copied
/// vectors decode, the client identity forms in memory, Swift fingerprints a
/// key as Go does, and the addresses `./check.sh` passes are read strictly.
@Suite("ADR 0020's PKI vectors, as Swift reads them")
struct FixtureTests {
    @Test("every PKI fixture decodes, with what the regression reads from it")
    func everyFixtureDecodes() throws {
        let p256 = try PKIVectors.fixture("p256")
        let foreign = try PKIVectors.fixture("foreign")
        let ed25519 = try PKIVectors.fixture("ed25519")
        let verifyAt = Date(timeIntervalSince1970: 1_794_614_400)  // 2026-11-14T00:00:00Z
        for fixture in [p256, foreign, ed25519] {
            #expect(fixture.schema == 1)
            #expect(fixture.serverName == "fixture.fatline.farcast")
            #expect(fixture.verifyAt == verifyAt)
            #expect(fixture.server.identity == "fixture.fatline.farcast")
            #expect(fixture.server.keyPEM != nil)
        }
        #expect(p256.client?.identity == "farcast://fixture/operator")
        #expect(p256.client?.keySHA256 != nil)
        #expect(foreign.client == nil)
        #expect(ed25519.client == nil)
        #expect(ed25519.server.keySHA256 == nil)
        #expect(p256.server.keySHA256 != foreign.server.keySHA256)
    }

    @Test("the foreign CA has the fixture CA's subject, and another key")
    func foreignCAHasTheSameSubject() throws {
        let p256 = try #require(try ClientIdentity.certificate(pem: try PKIVectors.fixture("p256").ca.certPEM))
        let foreign = try #require(try ClientIdentity.certificate(pem: try PKIVectors.fixture("foreign").ca.certPEM))
        let p256Subject = SecCertificateCopySubjectSummary(p256) as String?
        let foreignSubject = SecCertificateCopySubjectSummary(foreign) as String?
        #expect(p256Subject == "FarCast Instance CA: fixture")
        #expect(foreignSubject == p256Subject)
        #expect(ClientIdentity.publicKey(of: p256) != ClientIdentity.publicKey(of: foreign))
    }

    @Test("the fixture's client identity forms in memory")
    func clientIdentityFormsInMemory() throws {
        let fixture = try PKIVectors.fixture("p256")
        let client = try #require(fixture.client)
        let certificate = try #require(try ClientIdentity.certificate(pem: client.certPEM))
        let key = try #require(try ClientIdentity.key(pkcs8PEM: try client.key))
        #expect(SecIdentityCreate(nil, certificate, key) != nil)
        // SecIdentityCreate pairs a certificate only with its own key.
        let serverKey = try #require(try ClientIdentity.key(pkcs8PEM: try fixture.server.key))
        #expect(SecIdentityCreate(nil, certificate, serverKey) == nil)
    }

    @Test("Swift computes the fixture's key fingerprints as Go does")
    func fingerprintsMatchGo() throws {
        let fixture = try PKIVectors.fixture("p256")
        for part in [try #require(fixture.client), fixture.server] {
            let key = try P256.Signing.PrivateKey(pemRepresentation: try part.key)
            #expect(fingerprint(spki: key.publicKey.derRepresentation) == (try part.fingerprint))
            // The certificate certifies that key: the pin NWConnection checks
            // is the key the server presents.
            let certificate = try #require(try ClientIdentity.certificate(pem: part.certPEM))
            let point = try #require(ClientIdentity.publicKey(of: certificate))
            #expect(fingerprint(spki: RequestTemplate.spkiPrefix + point) == (try part.fingerprint))
        }
        let ca = try #require(try ClientIdentity.certificate(pem: fixture.ca.certPEM))
        let caPoint = try #require(ClientIdentity.publicKey(of: ca))
        #expect(fingerprint(spki: RequestTemplate.spkiPrefix + caPoint) == (try fixture.ca.fingerprint))
    }

    @Test(
        "a fixture address is 127.0.0.1 and a port, and nothing else",
        arguments: [
            ("127.0.0.1:1", true), ("127.0.0.1:443", true), ("127.0.0.1:65535", true),
            ("127.0.0.1:0", false), ("127.0.0.1:65536", false), ("127.0.0.1:", false), ("127.0.0.1", false),
            ("127.0.0.1:+80", false), ("127.0.0.1:80 ", false), ("127.0.0.1:080000", false), ("127.0.0.10:80", false),
            ("localhost:80", false), ("10.0.0.1:80", false), ("[::1]:80", false), ("", false),
        ])
    func addressesAreReadStrictly(value: String, valid: Bool) {
        let address = try? FixtureServers.parse(value, variable: "FARSIGHT_TLS_P256")
        #expect((address != nil) == valid)
        if let address {
            #expect(address.host == "127.0.0.1")
            #expect(address.url.absoluteString == "https://\(value)/")
        }
    }
}
