import Foundation
import Network
import Security
import Synchronization

/// What an NWConnection fetch read, and how often its verify block ran.
struct NWFetchResponse: Sendable {
    let text: String
    let verifyCalls: Int
}

/// An NWConnection fetch that failed, with how often its verify block ran.
struct NWFetchFailure: Error {
    let error: any Error
    let verifyCalls: Int
}

/// The state an NWConnection's callbacks share.
final class NWFetchState: Sendable {
    let verifyCalls = Mutex(0)
    let finished = Mutex(false)
    let received = Mutex(Data())
}

/// One HTTP/1.1 GET over TLS 1.3 with NWConnection, presenting an identity
/// and pinning the server by the SHA-256 of its key's SubjectPublicKeyInfo,
/// which is what `sec_protocol_metadata_copy_peer_public_key` returns.
///
/// It pins the key rather than evaluating the chain: a `SecTrust` taken from
/// the verify block's `sec_trust_t` comes through an unmanaged reference,
/// which would be the first entry in the source gate's allowlist, so that is
/// decided where production code first needs it (step 7.1). URLSession's
/// tests carry the chain evaluation. It sets no ALPN and no server name,
/// because both setters take a C string, so the server answers in HTTP/1.1.
enum NWFetch {
    static func get(_ address: FixtureAddress, identity: SecIdentity, pinnedKeySHA256: String) async throws -> NWFetchResponse {
        let tls = NWProtocolTLS.Options()
        let options = tls.securityProtocolOptions
        sec_protocol_options_set_min_tls_protocol_version(options, .TLSv13)
        guard let local = sec_identity_create(identity) else { throw VectorError("sec_identity_create returned nil") }
        sec_protocol_options_set_local_identity(options, local)
        let state = NWFetchState()
        let queue = DispatchQueue(label: "FarSightTLSTests.NWFetch")
        sec_protocol_options_set_verify_block(options, { metadata, _, complete in
            state.verifyCalls.withLock { $0 += 1 }
            guard let key = sec_protocol_metadata_copy_peer_public_key(metadata) else {
                complete(false)
                return
            }
            complete(fingerprint(spki: Data(key as DispatchData)) == pinnedKeySHA256)
        }, queue)
        let tcp = NWProtocolTCP.Options()
        tcp.connectionTimeout = 10
        let connection = NWConnection(host: NWEndpoint.Host(address.host), port: address.port, using: NWParameters(tls: tls, tcp: tcp))
        defer { connection.cancel() }
        let request = "GET / HTTP/1.1\r\nHost: fixture.fatline.farcast\r\nConnection: close\r\n\r\n"
        do {
            let data = try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, any Error>) in
                    let finish: @Sendable (Result<Data, any Error>) -> Void = { result in
                        let first = state.finished.withLock { done in
                            defer { done = true }
                            return !done
                        }
                        if first { continuation.resume(with: result) }
                    }
                    connection.stateUpdateHandler = { newState in
                        switch newState {
                        case .ready:
                            connection.send(content: Data(request.utf8), completion: .contentProcessed { error in
                                if let error { finish(.failure(error)) }
                            })
                            receive(connection, state: state, finish: finish)
                        case .failed(let error), .waiting(let error):
                            finish(.failure(error))
                        case .cancelled:
                            finish(.failure(VectorError("the connection was cancelled")))
                        default:
                            break
                        }
                    }
                    connection.start(queue: queue)
                }
            } onCancel: {
                connection.cancel()
            }
            return NWFetchResponse(text: String(decoding: data, as: UTF8.self), verifyCalls: state.verifyCalls.withLock { $0 })
        } catch {
            throw NWFetchFailure(error: error, verifyCalls: state.verifyCalls.withLock { $0 })
        }
    }

    /// Reads until the server closes the connection, as `Connection: close` asks.
    private static func receive(
        _ connection: NWConnection, state: NWFetchState, finish: @escaping @Sendable (Result<Data, any Error>) -> Void
    ) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { content, _, isComplete, error in
            if let content { state.received.withLock { $0.append(content) } }
            if let error {
                finish(.failure(error))
            } else if isComplete {
                finish(.success(state.received.withLock { $0 }))
            } else {
                receive(connection, state: state, finish: finish)
            }
        }
    }
}
