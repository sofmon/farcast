import Foundation

/// The Connected view's reader on macOS: it lists and reads the operator's
/// instances by running their own `farcast`, at the path they confirmed in
/// Settings, through an executor the app supplies (ADR 0021 decision 9,
/// amended 2026-11-12, and Verification 5).
///
/// - It runs three commands and no other, with flags fixed in code
///   (`CLICommand`): `version` and `instances`, which read only files on the
///   Mac, and `world <name>`, only for a name the latest successful listing
///   returned and `farcast install` could have created.
/// - Each runs with an environment built from an allowlist
///   (`ChildEnvironment`), never the app's own.
/// - It reads nothing from a farcast built from another commit than this
///   app, and nothing at all when the app does not know its own commit. Every
///   document's stamp is checked, not only `version`'s, so a farcast of
///   another commit swapped in between a listing and a read is refused too.
///   A binary reports its own commit: one that reports this build's is not
///   caught (ADR 0021 decision 9, *What it gives up*).
/// - It never sleeps and never retries. Time belongs to the executor,
///   through each invocation's timeout, and to the feed, through its
///   deadline. Each timeout here, with the time the app's executor takes to
///   stop a child, is below the feed's matching deadline, so a hung farcast
///   comes back as this reader's own `.timeout`.
public actor CLIReader: WorldReader {
    public struct Timeouts: Sendable, Equatable {
        public var version: Duration = .seconds(5)
        /// version + instances, with the 4 s the app's executor may take to
        /// stop a timed-out child, < WorldFeed's 20 s listing deadline.
        public var instances: Duration = .seconds(10)
        /// The CLI's 60 s ceiling + start-up; with the same 4 s, < WorldFeed's
        /// 90 s read deadline.
        public var world: Duration = .seconds(75)

        public init() {}
    }

    public nonisolated let source: World.Source = .live

    private let settings: CLISettings
    private let appCommit: String?
    private let parentEnvironment: [String: String]
    private let executor: any Executor
    private let probe: any FileProbe
    private let bundlePath: String
    private let timeouts: Timeouts
    /// The readable names from the latest successful listing; empty before
    /// one, and after any listing that failed: the reader fails closed.
    private var allowed: Set<String> = []

    public init(
        settings: CLISettings,
        appCommit: String?,
        parentEnvironment: [String: String],
        executor: any Executor,
        probe: any FileProbe,
        bundlePath: String,
        timeouts: Timeouts = Timeouts()
    ) {
        self.settings = settings
        self.appCommit = appCommit
        self.parentEnvironment = parentEnvironment
        self.executor = executor
        self.probe = probe
        self.bundlePath = bundlePath
        self.timeouts = timeouts
    }

    /// The listing with the stamp of the CLI that wrote it, for Settings' Check. It is the
    /// listing `listInstances()` makes, and it sets the names `readWorld` and
    /// `terminalCommand` accept, exactly as that does.
    public func listing() async throws(ReadFailure) -> CLIListing {
        do throws(ReadFailure) {
            let (environment, commit) = try preflight()
            let stamp = try CLIDocuments.version(try await run(.version, environment, timeouts.version))
            try check(stamp, against: commit)
            let listing = try CLIDocuments.instances(try await run(.instances, environment, timeouts.instances))
            try check(listing.stamp, against: commit)
            allowed = Set(listing.instances.map(\.name).filter(InstanceName.isReadable))
            return listing
        } catch {
            allowed = []
            throw error
        }
    }

    /// `try await listing().instances`: the feed's view of the same call.
    public func listInstances() async throws(ReadFailure) -> [InstanceListing] {
        try await listing().instances
    }

    public func readWorld(_ instance: String) async throws(ReadFailure) -> World {
        try refuseUnlisted(instance)
        let (environment, commit) = try preflight()
        let document = try CLIDocuments.world(
            try await run(.world(instance), environment, timeouts.world),
            asReadOf: instance
        )
        try check(document.stamp, against: commit)
        return document.world
    }

    /// The exact command a read of `instance` runs, for a terminal: `env -i 'K=V' … '<farcast>' '--config' … '--' '<instance>'`,
    /// each word single-quoted (' as '\''). Refuses, as readWorld does, a name the last listing did not return.
    public func terminalCommand(for instance: String) throws(ReadFailure) -> String {
        try refuseUnlisted(instance)
        let (environment, _) = try preflight()
        let words = environment.keys.sorted().map { "\($0)=\(environment[$0] ?? "")" }
            + [settings.farcast]
            + CLICommand.world(instance).arguments(configDirectory: settings.configDirectory)
        return (["env", "-i"] + words.map(Self.quoted)).joined(separator: " ")
    }

    // MARK: - The steps

    private func refuseUnlisted(_ instance: String) throws(ReadFailure) {
        guard allowed.contains(instance), InstanceName.isReadable(instance) else {
            throw ReadFailure(
                kind: .notFound,
                message: "\(instance) was not in the last listing of this Mac's instances, so it is not read"
            )
        }
    }

    /// Runs nothing: the settings are checked, the environment built, and
    /// the app's own commit known, or the read stops here.
    private func preflight() throws(ReadFailure) -> (environment: [String: String], commit: String) {
        if let problem = settings.problems(probe: probe, bundlePath: bundlePath).first {
            throw ReadFailure(kind: .internal, message: "Settings need attention: \(problem.field.title): \(problem.message)")
        }
        let environment = try ChildEnvironment.build(parent: parentEnvironment, settings: settings)
        guard let appCommit else {
            throw ReadFailure(
                kind: .versionSkew,
                message: "This FarCast was built without its commit (a build from Xcode's Run button), so it cannot check "
                    + "that the farcast at \(settings.farcast) is the same commit, and reads nothing. "
                    + "Build it as the README says: FARCAST_COMMIT=<commit> on the xcodebuild line."
            )
        }
        return (environment, appCommit)
    }

    private func check(_ stamp: CLIStamp, against commit: String) throws(ReadFailure) {
        guard let theirs = BuildCommit.parse(stamp.commit) else {
            throw ReadFailure(
                kind: .versionSkew,
                message: "farcast at \(settings.farcast) reports no commit ('\(stamp.commit)') and this FarCast is "
                    + "commit \(commit); build both from the same commit"
            )
        }
        guard theirs == commit else {
            throw ReadFailure(
                kind: .versionSkew,
                message: "farcast at \(settings.farcast) is commit \(theirs) (\(stamp.version)) and this FarCast is "
                    + "commit \(commit); build both from the same commit"
            )
        }
    }

    /// Runs one command and returns what it printed on stdout when it exited
    /// 0; every other ending is a failure with a kind.
    private func run(_ command: CLICommand, _ environment: [String: String], _ timeout: Duration) async throws(ReadFailure) -> Data {
        let invocation = Invocation(
            executable: settings.farcast,
            arguments: command.arguments(configDirectory: settings.configDirectory),
            environment: environment,
            timeout: timeout,
            outputLimit: CLILimits.output,
            errorLimit: CLILimits.error
        )
        let result = await executor.run(invocation)
        let label = command.label
        switch result.outcome {
        case .exited(0):
            return result.stdout
        case .exited(let code):
            if let failure = CLIDocuments.failure(result.stdout) { throw failure }
            let stderr = Self.text(result.stderr)
            if code == 2 {
                throw ReadFailure(
                    kind: .internal,
                    message: "farcast refused the command line FarCast gave it (exit 2)" + (stderr.isEmpty ? "" : ": \(stderr)")
                )
            }
            throw ReadFailure(
                kind: .internal,
                message: "farcast \(label) exited \(code)" + (stderr.isEmpty ? " and printed nothing" : ": \(stderr)")
            )
        case .signalled(let signal):
            throw ReadFailure(kind: .internal, message: "farcast \(label) was stopped by signal \(signal)")
        case .timedOut:
            throw ReadFailure(
                kind: .timeout,
                message: "farcast \(label) did not finish within \(timeout.components.seconds) seconds and was stopped"
            )
        case .outputTooLarge:
            throw ReadFailure(
                kind: .internal,
                message: "farcast \(label) printed more than \(CLILimits.output >> 20) MiB, so nothing it printed was read"
            )
        case .cancelled:
            throw ReadFailure(kind: .timeout, message: "farcast \(label) was stopped before it finished")
        case .launchFailed(let why):
            throw ReadFailure(kind: .internal, message: "farcast at \(settings.farcast) could not be started: \(why)")
        }
    }

    /// What farcast wrote on stderr, as text: trimmed, and cut to 1000
    /// characters. Drawn through `Display.message` where it is shown.
    static func text(_ stderr: Data) -> String {
        String(String(decoding: stderr, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines).prefix(1000))
    }

    /// One word for a POSIX shell: single-quoted, each ' written '\''.
    static func quoted(_ word: String) -> String {
        "'" + word.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
