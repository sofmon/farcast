#if os(macOS)
import Foundation
import Synchronization
import FarSightCore

/// Runs the operator's `farcast` for the Connected view (ADR 0021 decision 9,
/// amended 2026-11-12): one Foundation `Process` per invocation, with no shell.
///
/// - The child gets exactly the invocation's executable, arguments and
///   environment, `/` as its working directory (what a Finder launch has),
///   and a closed stdin.
/// - Its stdout and stderr are read as they arrive, each up to its limit.
///   Stdout past its limit stops the child and is `.outputTooLarge`; stderr
///   past its limit is cut, which is not a failure.
/// - A child that outlives its timeout, or whose read is cancelled, is asked
///   to stop with SIGTERM — farcast then cancels its own kubectl — and is
///   killed `grace` later if it has not exited.
/// - `run` returns only once the child has exited, its output has ended (or a
///   second has passed since it exited), and it has left the registry of
///   live children that `terminateAll` stops when the app quits.
nonisolated final class ProcessExecutor: Executor {
    /// How long a child asked to stop may take before it is killed.
    ///
    /// `grace + drain` is the most a run takes past its timeout. FarSightKit's
    /// `ReaderDeadlineTests` holds the reader's timeouts plus 4 s under the
    /// feed's deadlines: change that test with these.
    static let grace: Duration = .seconds(3)
    /// How long `run` waits for the output to end once the child has exited:
    /// a grandchild that kept a pipe open does not hold the read up.
    static let drain: Duration = .seconds(1)

    /// The pids of children that have not exited yet. A pid is signalled
    /// only while it is here, so a pid the system has since given to another
    /// process is never signalled.
    private let live = Mutex<Set<Int32>>([])

    func run(_ invocation: Invocation) async -> ExecutionResult {
        let run = ProcessRun(invocation, executor: self)
        return await withTaskCancellationHandler {
            await run.start()
        } onCancel: {
            run.cancel()
        }
    }

    /// For the app's will-terminate, which returns straight into exit:
    /// SIGTERM every live child, wait up to 500 ms for them to exit, and
    /// SIGKILL the rest.
    func terminateAll() {
        for pid in live.withLock({ $0 }) { send(SIGTERM, to: pid) }
        let deadline = ContinuousClock.now.advanced(by: .milliseconds(500))
        while ContinuousClock.now < deadline, !live.withLock({ $0.isEmpty }) {
            Thread.sleep(forTimeInterval: 0.01)
        }
        for pid in live.withLock({ $0 }) { send(SIGKILL, to: pid) }
    }

    fileprivate func register(_ pid: Int32) {
        live.withLock { _ = $0.insert(pid) }
    }

    fileprivate func unregister(_ pid: Int32) {
        live.withLock { _ = $0.remove(pid) }
    }

    /// Sends `signal` to `pid` only while it is a live child of this
    /// executor. Darwin's kill takes no pointer.
    fileprivate func send(_ signal: Int32, to pid: Int32) {
        live.withLock { pids in
            if pids.contains(pid) { _ = Darwin.kill(pid, signal) }
        }
    }
}

/// One invocation, from launch to its result. Every callback — each pipe's
/// reads, the child's exit, the timeout, cancellation — goes through one
/// lock, and the first time everything has ended it resumes `start`.
private nonisolated final class ProcessRun: Sendable {
    private let invocation: Invocation
    private let executor: ProcessExecutor
    private let state: Mutex<State>

    private struct State {
        var stdout: CappedBuffer
        var stderr: CappedBuffer
        var pid: Int32?
        var exit: ExecutionResult.Outcome?
        var stdoutEnded = false
        var stderrEnded = false
        var drained = false
        var outputTooLarge = false
        var timedOut = false
        var cancelled = false
        var stopping = false
        var finished = false
        var continuation: CheckedContinuation<ExecutionResult, Never>?
        var timer: Task<Void, Never>?
        var handles: [FileHandle] = []
    }

    /// What `finish` hands back once, outside the lock.
    private struct Ending {
        let continuation: CheckedContinuation<ExecutionResult, Never>
        let result: ExecutionResult
        let timer: Task<Void, Never>?
        let handles: [FileHandle]
    }

    init(_ invocation: Invocation, executor: ProcessExecutor) {
        self.invocation = invocation
        self.executor = executor
        state = Mutex(State(
            stdout: CappedBuffer(limit: invocation.outputLimit),
            stderr: CappedBuffer(limit: invocation.errorLimit)
        ))
    }

    func start() async -> ExecutionResult {
        await withCheckedContinuation { continuation in
            launch(continuation)
        }
    }

    func cancel() {
        state.withLock { $0.cancelled = true }
        stop()
    }

    private func launch(_ continuation: CheckedContinuation<ExecutionResult, Never>) {
        let cancelledEarly = state.withLock { state in
            state.continuation = continuation
            return state.cancelled
        }
        if cancelledEarly {
            // Cancelled before anything ran: there is no child to wait for.
            finish { _ in ExecutionResult(outcome: .cancelled) }
            return
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: invocation.executable)
        process.arguments = invocation.arguments
        process.environment = invocation.environment
        process.currentDirectoryURL = URL(fileURLWithPath: "/")
        process.standardInput = FileHandle.nullDevice
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        let readers = [stdout.fileHandleForReading, stderr.fileHandleForReading]
        state.withLock { $0.handles = readers }

        // At the end of its output a handle is called again and again with
        // nothing, until its handler is removed.
        stdout.fileHandleForReading.readabilityHandler = { [self] handle in
            let chunk = handle.availableData
            if chunk.isEmpty { handle.readabilityHandler = nil }
            read(chunk, isStdout: true)
        }
        stderr.fileHandleForReading.readabilityHandler = { [self] handle in
            let chunk = handle.availableData
            if chunk.isEmpty { handle.readabilityHandler = nil }
            read(chunk, isStdout: false)
        }
        process.terminationHandler = { [self] child in
            let outcome: ExecutionResult.Outcome = child.terminationReason == .uncaughtSignal
                ? .signalled(child.terminationStatus)
                : .exited(child.terminationStatus)
            exited(child.processIdentifier, outcome)
        }

        do {
            try process.run()
        } catch {
            let why = error.localizedDescription
            finish { _ in ExecutionResult(outcome: .launchFailed(why)) }
            return
        }

        // The child may have exited already; then it is never registered,
        // and nothing signals its pid.
        let pid = process.processIdentifier
        let stopNow = state.withLock { state in
            state.pid = pid
            if state.exit == nil { executor.register(pid) }
            return state.cancelled || state.outputTooLarge
        }
        if stopNow { stop() }

        let timeout = invocation.timeout
        let timer = Task { [self] in
            do {
                try await Task.sleep(for: timeout, clock: ContinuousClock())
            } catch {
                return
            }
            let fire = state.withLock { state in
                guard !state.finished, state.exit == nil else { return false }
                state.timedOut = true
                return true
            }
            if fire { stop() }
        }
        let alreadyFinished = state.withLock { state in
            state.timer = timer
            return state.finished
        }
        if alreadyFinished { timer.cancel() }
    }

    /// SIGTERM now, and SIGKILL after the grace period if the child has not
    /// exited by then. Once per run, and only once it has a pid.
    private func stop() {
        let pid: Int32? = state.withLock { state in
            guard let pid = state.pid, state.exit == nil, !state.stopping else { return nil }
            state.stopping = true
            return pid
        }
        guard let pid else { return }
        executor.send(SIGTERM, to: pid)
        let executor = self.executor
        Task {
            try? await Task.sleep(for: ProcessExecutor.grace, clock: ContinuousClock())
            executor.send(SIGKILL, to: pid)
        }
    }

    private func read(_ chunk: Data, isStdout: Bool) {
        let overflow = state.withLock { state -> Bool in
            if chunk.isEmpty {
                if isStdout { state.stdoutEnded = true } else { state.stderrEnded = true }
                return false
            }
            if isStdout {
                guard !state.stdout.append(chunk), !state.outputTooLarge else { return false }
                state.outputTooLarge = true
                return true
            }
            _ = state.stderr.append(chunk)
            return false
        }
        if overflow { stop() }
        if chunk.isEmpty { finishIfDone() }
    }

    private func exited(_ pid: Int32, _ outcome: ExecutionResult.Outcome) {
        state.withLock { state in
            state.exit = outcome
            executor.unregister(pid)
        }
        finishIfDone()
        // Output still open a second after the exit is not waited for.
        Task { [self] in
            try? await Task.sleep(for: ProcessExecutor.drain, clock: ContinuousClock())
            state.withLock { $0.drained = true }
            finishIfDone()
        }
    }

    /// Once the child has exited and its output has ended, or a second has
    /// passed since: precedence is output too large, then timed out, then
    /// cancelled, then how the child ended.
    private func finishIfDone() {
        finish { state in
            guard let exit = state.exit, state.drained || (state.stdoutEnded && state.stderrEnded) else { return nil }
            if state.outputTooLarge { return ExecutionResult(outcome: .outputTooLarge, stderr: state.stderr.data) }
            if state.timedOut { return ExecutionResult(outcome: .timedOut, stderr: state.stderr.data) }
            if state.cancelled { return ExecutionResult(outcome: .cancelled, stderr: state.stderr.data) }
            return ExecutionResult(outcome: exit, stdout: state.stdout.data, stderr: state.stderr.data)
        }
    }

    /// Resumes `start` the first time `answer` has a result, and lets go of
    /// the pipes and the timer.
    private func finish(_ answer: (State) -> ExecutionResult?) {
        let ending: Ending? = state.withLock { state in
            guard !state.finished, let continuation = state.continuation, let result = answer(state) else { return nil }
            state.finished = true
            state.continuation = nil
            let handles = state.handles
            state.handles = []
            return Ending(continuation: continuation, result: result, timer: state.timer, handles: handles)
        }
        guard let ending else { return }
        ending.timer?.cancel()
        for handle in ending.handles { handle.readabilityHandler = nil }
        ending.continuation.resume(returning: ending.result)
    }
}
#endif
