import CryptoKit
import Foundation
import Security

/// A client identity formed in memory from the fixture's PEM: no keychain
/// item and no prompt, on macOS or the simulator. Not `SecPKCS12Import`,
/// whose result comes back through an out-pointer that strict memory safety
/// flags.
///
/// The Security calls that take an out-pointer are made here and nowhere
/// else, each with `nil`, and their results bound to a value before any test
/// macro sees them: written as the top-level expression of `#expect` or
/// `#require`, such a call hands the macro its `nil` as a raw pointer value,
/// which strict memory safety flags too.
enum ClientIdentity {
    /// An ECDSA P-256 private key, from its PKCS#8 PEM, as Security holds it.
    static func key(pkcs8PEM: String) throws -> SecKey? {
        let key = try P256.Signing.PrivateKey(pemRepresentation: pkcs8PEM)
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
        ]
        return SecKeyCreateWithData(key.x963Representation as CFData, attributes as CFDictionary, nil)
    }

    static func certificate(pem: String) throws -> SecCertificate? {
        SecCertificateCreateWithData(nil, try PEM.der(pem, type: "CERTIFICATE") as CFData)
    }

    /// The identity of `part`, its certificate and its key: nil when either
    /// does not form, or the key is not the certificate's.
    static func identity(_ part: PKIPart) throws -> SecIdentity? {
        guard let certificate = try certificate(pem: part.certPEM), let key = try key(pkcs8PEM: try part.key) else {
            return nil
        }
        return SecIdentityCreate(nil, certificate, key)
    }

    /// The X9.63 point of a certificate's public key.
    static func publicKey(of certificate: SecCertificate) -> Data? {
        guard let key = SecCertificateCopyKey(certificate), let point = SecKeyCopyExternalRepresentation(key, nil) else {
            return nil
        }
        return point as Data
    }

    /// The fixture's operator identity, which every live test presents.
    static func operatorIdentity(_ fixture: PKIFixture) throws -> SecIdentity {
        guard let client = fixture.client, let identity = try identity(client) else {
            throw VectorError("the fixture's client identity did not form")
        }
        return identity
    }
}
