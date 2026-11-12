import Foundation

/// Runs one `farcast` invocation to completion. Never throws: a launch failure is
/// an outcome. Honours cancellation: on cancel it asks the child to stop
/// (SIGTERM), kills it after a grace period, and returns `.cancelled` once the
/// child has exited.
///
/// The macOS app supplies the one that starts a process; this package runs
/// none.
public protocol Executor: Sendable {
    func run(_ invocation: Invocation) async -> ExecutionResult
}

/// One invocation. Only this module can make one (`CLICommand`), so nothing the
/// app holds can ask an executor to run anything else (ADR 0021 Verification 5).
public struct Invocation: Sendable, Equatable {
    /// The confirmed absolute path to farcast.
    public let executable: String
    /// argv[1...].
    public let arguments: [String]
    /// The whole environment; nothing is inherited.
    public let environment: [String: String]
    public let timeout: Duration
    /// Stdout bytes kept; more is `.outputTooLarge`.
    public let outputLimit: Int
    /// Stderr bytes kept; more is dropped.
    public let errorLimit: Int

    init(
        executable: String,
        arguments: [String],
        environment: [String: String],
        timeout: Duration,
        outputLimit: Int,
        errorLimit: Int
    ) {
        self.executable = executable
        self.arguments = arguments
        self.environment = environment
        self.timeout = timeout
        self.outputLimit = outputLimit
        self.errorLimit = errorLimit
    }
}

/// How an invocation ended, and what it printed.
public struct ExecutionResult: Sendable, Equatable {
    public enum Outcome: Sendable, Equatable {
        case exited(Int32)
        case signalled(Int32)
        case timedOut
        /// Stdout passed `Invocation.outputLimit`; nothing it printed is read.
        case outputTooLarge
        case cancelled
        case launchFailed(String)
    }

    public var outcome: Outcome
    public var stdout: Data
    public var stderr: Data

    public init(outcome: Outcome, stdout: Data = Data(), stderr: Data = Data()) {
        self.outcome = outcome
        self.stdout = stdout
        self.stderr = stderr
    }
}

/// Bytes kept up to a limit. `append` returns false once the total would pass it,
/// keeping only the first `limit` bytes.
public struct CappedBuffer: Sendable, Equatable {
    public let limit: Int
    public private(set) var data: Data
    public private(set) var overflowed: Bool

    public init(limit: Int) {
        self.limit = max(limit, 0)
        data = Data()
        overflowed = false
    }

    public mutating func append(_ chunk: Data) -> Bool {
        let room = limit - data.count
        guard chunk.count <= room else {
            data.append(chunk.prefix(max(room, 0)))
            overflowed = true
            return false
        }
        data.append(chunk)
        return !overflowed
    }
}

/// How much of `farcast`'s output is kept.
public enum CLILimits {
    /// 8 MiB of stdout: the 200-host vector is 68 KB.
    public static let output = 8 << 20
    /// 64 KiB of stderr.
    public static let error = 64 << 10
}
