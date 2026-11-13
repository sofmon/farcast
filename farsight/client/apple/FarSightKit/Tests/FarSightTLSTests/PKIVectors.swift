import CryptoKit
import Foundation
import Testing

/// FatLine's PKI vectors, `Vectors/pki/`: a copy of
/// `fatline/internal/crypto/testdata/pki/`, byte for byte (`./check.sh` 7a
/// refuses a copy that differs). Go issues them through FatLine's own
/// issuers and serves them through its own server config, so what these
/// tests hold Apple's TLS to is what an instance presents.
enum PKIVectors {
    static func data(_ name: String) throws -> Data {
        let root = try #require(Bundle.module.url(forResource: "Vectors", withExtension: nil), "the Vectors resource is missing")
        return try Data(contentsOf: root.appending(path: "pki/\(name).json"))
    }

    static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }

    /// `p256`, `foreign` or `ed25519`.
    static func fixture(_ name: String) throws -> PKIFixture {
        try decoder().decode(PKIFixture.self, from: data(name))
    }

    /// The six requests built from the minimal template. `key_only` and
    /// `invalid` are for Go's checks, and are not read here.
    static func requests() throws -> [RequestVector] {
        try decoder().decode(RequestVectors.self, from: data("requests")).valid
    }
}

/// One of `p256.json`, `foreign.json` and `ed25519.json`. Every key is named
/// in `CodingKeys`: a snake-case conversion would read `key_sha256` as
/// `keySha256`.
struct PKIFixture: Decodable, Sendable {
    let schema: Int
    let serverName: String
    let verifyAt: Date
    let ca: PKIPart
    let server: PKIPart
    /// The operator's leaf; only `p256.json` has one.
    let client: PKIPart?

    enum CodingKeys: String, CodingKey {
        case schema
        case serverName = "server_name"
        case verifyAt = "verify_at"
        case ca
        case server
        case client
    }
}

/// A certificate in a fixture, with its key where the file carries one.
struct PKIPart: Decodable, Sendable {
    let identity: String?
    let certPEM: String
    let keyPEM: String?
    /// The SHA-256 of the key's SubjectPublicKeyInfo, lowercase hex. The
    /// retired Ed25519 fixture has none.
    let keySHA256: String?

    enum CodingKeys: String, CodingKey {
        case identity
        case certPEM = "cert_pem"
        case keyPEM = "key_pem"
        case keySHA256 = "key_sha256"
    }

    var certificateDER: Data {
        get throws { try PEM.der(certPEM, type: "CERTIFICATE") }
    }

    var key: String {
        get throws {
            guard let keyPEM else { throw VectorError("this part of the fixture carries no key") }
            return keyPEM
        }
    }

    var fingerprint: String {
        get throws {
            guard let keySHA256 else { throw VectorError("this part of the fixture carries no key fingerprint") }
            return keySHA256
        }
    }
}

struct RequestVectors: Decodable, Sendable {
    let schema: Int
    let valid: [RequestVector]

    enum CodingKeys: String, CodingKey {
        case schema
        case valid
    }
}

/// An enrolment request Go made from the minimal template (empty subject, no
/// attributes), with its parts in hex.
struct RequestVector: Decodable, Sendable, CustomTestStringConvertible {
    let name: String
    let requestPEM: String
    let keySHA256: String
    let pointHex: String
    let tbsHex: String
    let signatureHex: String
    /// The DER INTEGER content lengths of r and s: 33 is padded, 31 or less short.
    let rBytes: Int
    let sBytes: Int
    let highS: Bool

    enum CodingKeys: String, CodingKey {
        case name
        case requestPEM = "request_pem"
        case keySHA256 = "key_sha256"
        case pointHex = "point_hex"
        case tbsHex = "tbs_hex"
        case signatureHex = "signature_hex"
        case rBytes = "r_bytes"
        case sBytes = "s_bytes"
        case highS = "high_s"
    }

    var testDescription: String { name }
}

struct VectorError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

enum PEM {
    /// The DER inside `pem`, which must be exactly one block of `type`: the
    /// armour stripped and the base64 decoded.
    static func der(_ pem: String, type: String) throws -> Data {
        let lines = pem.split(separator: "\n").map(String.init)
        guard lines.count > 2, lines.first == "-----BEGIN \(type)-----", lines.last == "-----END \(type)-----" else {
            throw VectorError("not one PEM block of type \(type)")
        }
        guard let der = Data(base64Encoded: lines.dropFirst().dropLast().joined()) else {
            throw VectorError("the \(type) block is not base64")
        }
        return der
    }
}

enum Hex {
    static func data(_ hex: String) throws -> Data {
        let digits = Array(hex.utf8)
        guard digits.count.isMultiple(of: 2) else { throw VectorError("odd-length hex") }
        var out = Data(capacity: digits.count / 2)
        for i in stride(from: 0, to: digits.count, by: 2) {
            guard let high = value(digits[i]), let low = value(digits[i + 1]) else { throw VectorError("not hex") }
            out.append(high << 4 | low)
        }
        return out
    }

    static func string(_ data: Data) -> String {
        let alphabet = Array("0123456789abcdef")
        var out = ""
        out.reserveCapacity(data.count * 2)
        for byte in data {
            out.append(alphabet[Int(byte >> 4)])
            out.append(alphabet[Int(byte & 0x0f)])
        }
        return out
    }

    private static func value(_ digit: UInt8) -> UInt8? {
        switch digit {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): digit - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"): digit - UInt8(ascii: "a") + 10
        default: nil
        }
    }
}

/// A key's fingerprint as FatLine computes it (`KeyFingerprint`): SHA-256
/// over its DER SubjectPublicKeyInfo, lowercase hex.
func fingerprint(spki: Data) -> String {
    Hex.string(Data(SHA256.hash(data: spki)))
}
