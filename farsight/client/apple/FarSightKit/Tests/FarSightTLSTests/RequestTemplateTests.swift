import CryptoKit
import Foundation
import Testing

/// ADR 0021 decision 3's enrolment request against Go's vectors: the
/// template rebuilds every request Go made from it, byte for byte, and
/// CryptoKit verifies each signature, so a client that builds the request
/// around a key held in hardware produces what FatLine checks (ADR 0020
/// decision 3).
@Suite("The enrolment request template, against Go's vectors")
struct RequestTemplateTests {
    @Test("requests.json holds the six template requests, in Go's order, high and low s among them")
    func sixVectorsInOrder() throws {
        let vectors = try PKIVectors.requests()
        #expect(vectors.map(\.name) == ["plain", "r_padded", "s_padded", "both_padded", "r_short", "s_short"])
        #expect(vectors.contains { $0.highS })
        #expect(vectors.contains { !$0.highS })
    }

    @Test("the enrolment request template rebuilds every valid Go vector", arguments: try PKIVectors.requests())
    func templateRebuildsGo(_ vector: RequestVector) throws {
        let point = try Hex.data(vector.pointHex)
        let signature = try Hex.data(vector.signatureHex)
        let request = try PEM.der(vector.requestPEM, type: "CERTIFICATE REQUEST")
        #expect(RequestTemplate.tbs(point: point) == (try Hex.data(vector.tbsHex)))
        #expect(RequestTemplate.der(point: point, signature: signature) == request)

        // The signature is the shape the vector's name says: r and s as DER
        // INTEGERs of rBytes and sBytes.
        let bytes = [UInt8](signature)
        try #require(bytes.count > 4 && bytes[0] == 0x30 && Int(bytes[1]) == bytes.count - 2 && bytes[2] == 0x02)
        let rLength = Int(bytes[3])
        try #require(bytes.count > 5 + rLength && bytes[4 + rLength] == 0x02)
        #expect(rLength == vector.rBytes)
        #expect(Int(bytes[5 + rLength]) == vector.sBytes)

        let key = try P256.Signing.PublicKey(x963Representation: point)
        let ecdsa = try P256.Signing.ECDSASignature(derRepresentation: signature)
        #expect(key.isValidSignature(ecdsa, for: try Hex.data(vector.tbsHex)))
        #expect(RequestTemplate.spkiPrefix + point == key.derRepresentation)
        #expect(fingerprint(spki: RequestTemplate.spkiPrefix + point) == vector.keySHA256)
    }

    @Test("DER lengths take one byte under 128, and the fewest bytes after 0x80 above it")
    func derLengths() {
        #expect(RequestTemplate.length(0) == Data([0x00]))
        #expect(RequestTemplate.length(127) == Data([0x7f]))
        #expect(RequestTemplate.length(128) == Data([0x81, 0x80]))
        #expect(RequestTemplate.length(255) == Data([0x81, 0xff]))
        #expect(RequestTemplate.length(256) == Data([0x82, 0x01, 0x00]))
        #expect(RequestTemplate.length(65_536) == Data([0x83, 0x01, 0x00, 0x00]))
    }
}
