import Foundation

/// ADR 0021 decision 3's enrolment request, as a template: a PKCS#10 request
/// with an empty subject and no attributes, ECDSA P-256 signed with SHA-256.
/// Only the public point, the signature and the lengths the signature
/// changes vary, so a client can build one byte by byte around a key it
/// cannot export, and sign the body with it. Test code until step 7.5 needs
/// it in a product target.
enum RequestTemplate {
    /// A P-256 SubjectPublicKeyInfo up to its point: SEQUENCE, the
    /// id-ecPublicKey and prime256v1 identifiers, and the BIT STRING header.
    static let spkiPrefix = Data([
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ])

    /// AlgorithmIdentifier ecdsa-with-SHA256, with no parameters.
    static let signatureAlgorithm = Data([0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02])

    /// A DER length: one byte under 128, otherwise 0x80 plus the count of
    /// the big-endian bytes that follow.
    static func length(_ count: Int) -> Data {
        precondition(count >= 0)
        if count < 0x80 { return Data([UInt8(count)]) }
        var bytes: [UInt8] = []
        var rest = count
        while rest > 0 {
            bytes.insert(UInt8(rest & 0xff), at: 0)
            rest >>= 8
        }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }

    /// The signed body, CertificationRequestInfo: version 0, an empty
    /// subject, the key, and an empty attribute set.
    static func tbs(point: Data) -> Data {
        let body = Data([0x02, 0x01, 0x00, 0x30, 0x00]) + spkiPrefix + point + Data([0xa0, 0x00])
        return Data([0x30]) + length(body.count) + body
    }

    /// The whole request, given the body's ECDSA signature in DER.
    static func der(point: Data, signature: Data) -> Data {
        let bits = Data([0x00]) + signature
        let body = tbs(point: point) + signatureAlgorithm + Data([0x03]) + length(bits.count) + bits
        return Data([0x30]) + length(body.count) + body
    }
}
