import Foundation
import Synchronization
import Testing
@testable import FarSightCore

/// The CLI's golden vectors, copied byte for byte from
/// farsight/cli/internal/cli/testdata into this target's `Vectors` resource
/// (check.sh holds the copy to Go's).
enum Vectors {
    static func url(_ path: String) throws -> URL {
        let root = try #require(Bundle.module.url(forResource: "Vectors", withExtension: nil), "the Vectors resource is missing")
        return root.appending(path: path)
    }

    static func data(_ path: String) throws -> Data {
        try Data(contentsOf: url(path))
    }

    /// The `.json` files in one of the vector directories, sorted. Anything
    /// else (a Finder `.DS_Store`) is not Go's and is not listed.
    static func names(_ directory: String) throws -> [String] {
        try FileManager.default.contentsOfDirectory(atPath: url(directory).path)
            .filter { $0.hasSuffix(".json") }
            .sorted()
    }

    /// `app/argv.json`: every command line the app runs, `<config>` and
    /// `<instance>` to fill in.
    static func argv() throws -> [String: [String]] {
        try JSONDecoder().decode([String: [String]].self, from: data("app/argv.json"))
    }

    /// One of argv.json's command lines, filled in.
    static func argv(_ command: String, config: String, instance: String = "") throws -> [String] {
        let words = try #require(argv()[command], "argv.json has no \(command)")
        return words.map { word in
            switch word {
            case "<config>": config
            case "<instance>": instance
            default: word
            }
        }
    }

    /// A vector with every `from` replaced by `to`, for a stamp that names
    /// another commit.
    static func data(_ path: String, replacing from: String, with to: String) throws -> Data {
        let text = String(decoding: try data(path), as: UTF8.self)
        #expect(text.contains(from), "\(path) has no \(from) to replace")
        return Data(text.replacingOccurrences(of: from, with: to).utf8)
    }
}

/// An executor that runs nothing: it records every invocation and answers
/// from a script keyed by the arguments.
final class ScriptedExecutor: Executor {
    enum Step: Sendable {
        case result(ExecutionResult)
        /// Waits until the task running it is cancelled, then answers
        /// `.cancelled`, as an executor that stopped its child does.
        case hangUntilCancelled
    }

    private struct State {
        var script: [[String]: Step]
        var invocations: [Invocation] = []
        var hanging: CheckedContinuation<Void, Never>?
        var hangStarted = false
        var hangWaiters: [CheckedContinuation<Void, Never>] = []
        var cancelled = false
    }

    private let state: Mutex<State>

    init(_ script: [[String]: Step] = [:]) {
        state = Mutex(State(script: script))
    }

    /// Answers `arguments` with `step` from now on.
    func answer(_ arguments: [String], with step: Step) {
        state.withLock { $0.script[arguments] = step }
    }

    var invocations: [Invocation] {
        state.withLock { $0.invocations }
    }

    /// Whether a hanging step saw its task cancelled.
    var sawCancellation: Bool {
        state.withLock { $0.cancelled }
    }

    /// Returns once a hanging step has begun.
    func hanging() async {
        await withCheckedContinuation { (waiter: CheckedContinuation<Void, Never>) in
            let started = state.withLock { state in
                if !state.hangStarted { state.hangWaiters.append(waiter) }
                return state.hangStarted
            }
            if started { waiter.resume() }
        }
    }

    func run(_ invocation: Invocation) async -> ExecutionResult {
        let step = state.withLock { state in
            state.invocations.append(invocation)
            return state.script[invocation.arguments]
        }
        switch step {
        case .result(let result)?:
            return result
        case .hangUntilCancelled?:
            await withTaskCancellationHandler {
                await withCheckedContinuation { (hang: CheckedContinuation<Void, Never>) in
                    let (cancelled, waiters) = state.withLock { state in
                        state.hangStarted = true
                        let waiters = state.hangWaiters
                        state.hangWaiters = []
                        if !state.cancelled { state.hanging = hang }
                        return (state.cancelled, waiters)
                    }
                    for waiter in waiters { waiter.resume() }
                    if cancelled { hang.resume() }
                }
            } onCancel: {
                let hang = state.withLock { state in
                    state.cancelled = true
                    let hang = state.hanging
                    state.hanging = nil
                    return hang
                }
                hang?.resume()
            }
            return ExecutionResult(outcome: .cancelled)
        case nil:
            return ExecutionResult(outcome: .launchFailed("the test scripted no answer to \(invocation.arguments)"))
        }
    }
}

/// The file system as a table: a path's entry, after following `links`.
struct FakeProbe: FileProbe {
    var entries: [String: FileEntry] = [:]
    /// A path and the path it resolves to.
    var links: [String: String] = [:]

    func entry(at path: String) -> FileEntry {
        entries[links[path] ?? path] ?? .missing
    }

    func resolved(_ path: String) -> String? {
        let target = links[path] ?? path
        return entries[target] == nil ? nil : target
    }
}

/// A Mac set up as Settings expects, as a table.
enum Fixture {
    static let appCommit = "0e54eb1"
    static let bundlePath = "/Applications/FarCast.app"
    static let home = "/Users/op"

    static let settings = CLISettings(
        farcast: "/Users/op/src/farcast/bin/farcast",
        kubectl: "/usr/local/bin/kubectl",
        authPlugin: "/opt/homebrew/bin/gke-gcloud-auth-plugin",
        gcloud: "/opt/homebrew/bin/gcloud",
        configDirectory: "/Users/op/Library/Application Support/farcast",
        gcloudDirectory: "/Users/op/.config/gcloud"
    )

    static let executable = FileEntry.file(executable: true, worldWritable: false)
    static let directory = FileEntry.directory(worldWritable: false)

    /// Every path in `settings` as it should be, and the tools' directories.
    static func probe(for settings: CLISettings = settings) -> FakeProbe {
        var entries: [String: FileEntry] = [:]
        for tool in [settings.farcast, settings.kubectl, settings.authPlugin, settings.gcloud] where !tool.isEmpty {
            entries[tool] = executable
            if let parent = ChildEnvironment.directory(of: tool) { entries[parent] = directory }
        }
        for directory in [settings.configDirectory, settings.gcloudDirectory] where !directory.isEmpty {
            entries[directory] = Self.directory
        }
        return FakeProbe(entries: entries)
    }

    /// The app's own environment, with what must never reach farcast in it.
    static let parent: [String: String] = [
        "HOME": home,
        "PATH": "/usr/bin:/bin",
        "TMPDIR": "/var/folders/xy/T/",
        "LANG": "en_US.UTF-8",
        "KUBECONFIG": "/Users/op/.kube/config",
        "CLOUDSDK_CONFIG": "/elsewhere",
    ]

    static func reader(
        _ executor: ScriptedExecutor,
        settings: CLISettings = settings,
        appCommit: String? = appCommit,
        parent: [String: String] = parent,
        probe: FakeProbe? = nil
    ) -> CLIReader {
        CLIReader(
            settings: settings,
            appCommit: appCommit,
            parentEnvironment: parent,
            executor: executor,
            probe: probe ?? Self.probe(for: settings),
            bundlePath: bundlePath
        )
    }

    /// An executor that answers `version` with the version vector,
    /// `instances` with `instances`, and `world` for each name in `worlds`.
    static func executor(
        settings: CLISettings = settings,
        instances: String = "instances/unreadable.json",
        worlds: [String: Step] = [:]
    ) throws -> ScriptedExecutor {
        let config = settings.configDirectory
        var script: [[String]: Step] = [
            try Vectors.argv("version", config: config): .result(exited(0, try Vectors.data("version/version.json"))),
            try Vectors.argv("instances", config: config): .result(exited(0, try Vectors.data(instances))),
        ]
        for (name, step) in worlds {
            script[try Vectors.argv("world", config: config, instance: name)] = step
        }
        return ScriptedExecutor(script)
    }

    typealias Step = ScriptedExecutor.Step

    static func exited(_ code: Int32, _ stdout: Data = Data(), stderr: String = "") -> ExecutionResult {
        ExecutionResult(outcome: .exited(code), stdout: stdout, stderr: Data(stderr.utf8))
    }
}

/// The failure `body` throws, or nil when it throws none. Anything thrown
/// that is not a `ReadFailure` is an issue: the CLI's documents and the
/// reader throw nothing else.
func failure(_ body: () throws -> Void) -> ReadFailure? {
    do {
        try body()
        return nil
    } catch let failure as ReadFailure {
        return failure
    } catch {
        Issue.record("threw \(error), not a ReadFailure")
        return nil
    }
}

/// The failure `body` throws, or nil when it throws none.
func awaitFailure(_ body: () async throws -> Void) async -> ReadFailure? {
    do {
        try await body()
        return nil
    } catch let failure as ReadFailure {
        return failure
    } catch {
        Issue.record("threw \(error), not a ReadFailure")
        return nil
    }
}
