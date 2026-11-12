import Foundation
import Testing
@testable import FarSightCore

/// The reader that runs the operator's farcast, against an executor that
/// runs nothing (ADR 0021 decision 9 and Verification 5): only three
/// commands, only listed names, only a farcast of this build's commit, and
/// nothing at all while Settings need attention.
@Suite("The reader that runs farcast")
struct CLIReaderTests {
    typealias Step = ScriptedExecutor.Step
    static let config = Fixture.settings.configDirectory

    static func argv(_ command: String, _ instance: String = "") throws -> [String] {
        try Vectors.argv(command, config: config, instance: instance)
    }

    /// A world read that answers with an error envelope, as farcast does.
    static let notFound = Step.result(Fixture.exited(1, (try? Vectors.data("world/error_not_found.json")) ?? Data()))

    @Test("it runs version, instances and world for each listed name, and nothing else")
    func runsOnlyTheThreeCommands() async throws {
        let executor = try Fixture.executor(worlds: [
            "atlas": .result(Fixture.exited(0, try Vectors.data("world/healthy.json"))),
            "broken": Self.notFound, "empty": Self.notFound, "lab": Self.notFound,
        ])
        let reader = Fixture.reader(executor)
        let listed = try await reader.listInstances()
        #expect(listed.map(\.name) == ["atlas", "broken", "empty", "lab"])
        var read: [String: World] = [:]
        for name in listed.map(\.name) {
            read[name] = try? await reader.readWorld(name)
        }
        #expect(read["atlas"]?.instances.map(\.id) == ["atlas"])
        #expect(read.count == 1)

        let invocations = executor.invocations
        #expect(invocations.map(\.arguments) == [
            try Self.argv("version"), try Self.argv("instances"),
            try Self.argv("world", "atlas"), try Self.argv("world", "broken"),
            try Self.argv("world", "empty"), try Self.argv("world", "lab"),
        ])
        let environment = try ChildEnvironment.build(parent: Fixture.parent, settings: Fixture.settings)
        for invocation in invocations {
            #expect(invocation.executable == Fixture.settings.farcast)
            #expect(invocation.environment == environment)
            #expect(invocation.outputLimit == CLILimits.output && invocation.errorLimit == CLILimits.error)
        }
        #expect(invocations.map(\.timeout) == [.seconds(5), .seconds(10)] + Array(repeating: .seconds(75), count: 4))
    }

    @Test("a name the last listing did not return is not read, and nothing runs")
    func refusesNamesNotListed() async throws {
        let names = ["atlas", "../atlas", "-o", "", "atlas\n", "Atlas", "a/b"]
        let executor = try Fixture.executor(worlds: ["atlas": .result(Fixture.exited(0, try Vectors.data("world/healthy.json")))])
        let reader = Fixture.reader(executor)
        func refusesAll(_ when: String) async {
            let before = executor.invocations.count
            for name in names {
                let refusal = await awaitFailure { _ = try await reader.readWorld(name) }
                #expect(refusal?.kind == .notFound, "\(when): \(name.debugDescription)")
            }
            #expect(executor.invocations.count == before, "\(when): something ran")
        }
        await refusesAll("before any listing")

        executor.answer(try Self.argv("version"), with: .result(Fixture.exited(1, try Vectors.data("world/error_gcloud_mismatch.json"))))
        #expect(await awaitFailure { _ = try await reader.listInstances() }?.kind == .gcloudMismatch)
        await refusesAll("after a failed listing")

        executor.answer(try Self.argv("version"), with: .result(Fixture.exited(0, try Vectors.data("version/version.json"))))
        _ = try await reader.listInstances()
        #expect(try await reader.readWorld("atlas").instances.count == 1)
        executor.answer(try Self.argv("instances"), with: .result(Fixture.exited(0, try Vectors.data("instances/empty.json"))))
        #expect(try await reader.listInstances().isEmpty)
        await refusesAll("after a listing that dropped the name")
    }

    @Test("a build without its commit reads nothing, and runs nothing")
    func noCommitRunsNothing() async throws {
        let executor = try Fixture.executor()
        let reader = Fixture.reader(executor, appCommit: nil)
        let refusal = await awaitFailure { _ = try await reader.listInstances() }
        #expect(refusal?.kind == .versionSkew)
        #expect(refusal?.message.hasPrefix("This FarCast was built without its commit") == true)
        #expect(refusal?.message.contains(Fixture.settings.farcast) == true)
        #expect(executor.invocations.isEmpty)
    }

    @Test("a farcast of another commit, or of none, is not read from")
    func commitMismatchRefuses() async throws {
        for commit in ["1111111", "none"] {
            let executor = try Fixture.executor()
            executor.answer(try Self.argv("version"), with: .result(Fixture.exited(
                0, try Vectors.data("version/version.json", replacing: "0e54eb1", with: commit)
            )))
            let refusal = await awaitFailure { _ = try await Fixture.reader(executor).listInstances() }
            #expect(refusal?.kind == .versionSkew, "\(commit)")
            #expect(executor.invocations.map(\.arguments) == [try Self.argv("version")], "\(commit)")
            let said = commit == "none" ? "reports no commit ('none')" : "is commit 1111111 (v0.0.0-vector)"
            #expect(refusal?.message.contains(said) == true, "\(refusal?.message ?? "")")
        }

        let instances = try Fixture.executor()
        instances.answer(try Self.argv("instances"), with: .result(Fixture.exited(
            0, try Vectors.data("instances/unreadable.json", replacing: "0e54eb1", with: "1111111")
        )))
        let reader = Fixture.reader(instances)
        #expect(await awaitFailure { _ = try await reader.listInstances() }?.kind == .versionSkew)
        #expect(await awaitFailure { _ = try await reader.readWorld("atlas") }?.kind == .notFound)

        let world = try Fixture.executor(worlds: ["atlas": .result(Fixture.exited(
            0, try Vectors.data("world/healthy.json", replacing: "0e54eb1", with: "1111111")
        ))])
        let worldReader = Fixture.reader(world)
        _ = try await worldReader.listInstances()
        #expect(await awaitFailure { _ = try await worldReader.readWorld("atlas") }?.kind == .versionSkew)
    }

    @Test("every way a run can end maps to a kind", arguments: [
        (ExecutionResult(outcome: .exited(0), stdout: Data("not json".utf8)), SectionProblem.Kind.internal, "farcast's world output is not a JSON object"),
        (ExecutionResult(outcome: .exited(0), stdout: Data(#"{"schema":2}"#.utf8)), .versionSkew, "farcast wrote schema 2"),
        (ExecutionResult(outcome: .exited(2), stderr: Data("flag provided but not defined: -x\n".utf8)), .internal,
         "farcast refused the command line FarCast gave it (exit 2): flag provided but not defined: -x"),
        (ExecutionResult(outcome: .exited(3)), .internal, "farcast world atlas exited 3 and printed nothing"),
        (ExecutionResult(outcome: .exited(4), stderr: Data("  panic: boom  \n".utf8)), .internal, "farcast world atlas exited 4: panic: boom"),
        (ExecutionResult(outcome: .signalled(9)), .internal, "farcast world atlas was stopped by signal 9"),
        (ExecutionResult(outcome: .timedOut), .timeout, "farcast world atlas did not finish within 75 seconds and was stopped"),
        (ExecutionResult(outcome: .outputTooLarge), .internal, "farcast world atlas printed more than 8 MiB, so nothing it printed was read"),
        (ExecutionResult(outcome: .cancelled), .timeout, "farcast world atlas was stopped before it finished"),
        (ExecutionResult(outcome: .launchFailed("no such file")), .internal,
         "farcast at /Users/op/src/farcast/bin/farcast could not be started: no such file"),
    ] as [(ExecutionResult, SectionProblem.Kind, String)])
    func outcomesMapToKinds(result: ExecutionResult, kind: SectionProblem.Kind, message: String) async throws {
        let reader = Fixture.reader(try Fixture.executor(worlds: ["atlas": .result(result)]))
        _ = try await reader.listInstances()
        let refusal = await awaitFailure { _ = try await reader.readWorld("atlas") }
        #expect(refusal?.kind == kind)
        #expect(refusal?.message.hasPrefix(message) == true, "\(refusal?.message ?? "nil")")
    }

    @Test("an envelope on a failed run is the failure, with its kind")
    func envelopesMapToKinds() async throws {
        for (vector, kind) in [("error_gcloud_mismatch", SectionProblem.Kind.gcloudMismatch), ("error_not_found", .notFound)] {
            let data = try Vectors.data("world/\(vector).json")
            let reader = Fixture.reader(try Fixture.executor(worlds: ["atlas": .result(Fixture.exited(1, data))]))
            _ = try await reader.listInstances()
            let refusal = await awaitFailure { _ = try await reader.readWorld("atlas") }
            #expect(refusal == CLIDocuments.failure(data))
            #expect(refusal?.kind == kind)
        }
    }

    @Test("Settings that need attention, or no home directory, run nothing")
    func settingsProblemsRunNothing() async throws {
        var relative = Fixture.settings
        relative.kubectl = "bin/kubectl"
        let executor = try Fixture.executor()
        let refusal = await awaitFailure {
            _ = try await Fixture.reader(executor, settings: relative, probe: Fixture.probe()).listInstances()
        }
        #expect(refusal?.kind == .internal)
        #expect(refusal?.message.hasPrefix("Settings need attention: kubectl: must be an absolute path") == true)

        var homeless = Fixture.parent
        homeless["HOME"] = nil
        let noHome = await awaitFailure { _ = try await Fixture.reader(executor, parent: homeless).listInstances() }
        #expect(noHome == ReadFailure(kind: .internal, message: "FarCast has no home directory to give farcast"))
        #expect(executor.invocations.isEmpty)
    }

    @Test("cancelling a read reaches the executor, and the reader says it was stopped")
    func cancellationReachesTheExecutor() async throws {
        let executor = try Fixture.executor(worlds: ["atlas": .hangUntilCancelled])
        let reader = Fixture.reader(executor)
        _ = try await reader.listInstances()
        let read = Task { try await reader.readWorld("atlas") }
        await executor.hanging()
        read.cancel()
        let result = await read.result
        #expect(executor.sawCancellation)
        switch result {
        case .success: Issue.record("a cancelled read returned a world")
        case .failure(let error):
            #expect((error as? ReadFailure)?.kind == .timeout)
            #expect((error as? ReadFailure)?.message == "farcast world atlas was stopped before it finished")
        }
    }

    @Test("a listing that fails clears the names a read may use")
    func listingFailureClearsTheAllowedNames() async throws {
        let executor = try Fixture.executor(worlds: ["atlas": .result(Fixture.exited(0, try Vectors.data("world/healthy.json")))])
        let reader = Fixture.reader(executor)
        _ = try await reader.listInstances()
        #expect(try await reader.readWorld("atlas").instances.count == 1)
        executor.answer(try Self.argv("instances"), with: .result(ExecutionResult(outcome: .timedOut)))
        #expect(await awaitFailure { _ = try await reader.listInstances() }?.kind == .timeout)
        let before = executor.invocations.count
        #expect(await awaitFailure { _ = try await reader.readWorld("atlas") }?.kind == .notFound)
        #expect(executor.invocations.count == before)
    }

    @Test("the terminal command is the read's own, each word quoted, for listed names only")
    func terminalCommandIsTheReadsOwn() async throws {
        var settings = Fixture.settings
        settings.configDirectory = "/Users/op/it's/farcast"
        let executor = try Fixture.executor(settings: settings)
        let reader = Fixture.reader(executor, settings: settings)
        #expect(await awaitFailure { _ = try await reader.terminalCommand(for: "atlas") }?.kind == .notFound)
        _ = try await reader.listInstances()
        let command = try await reader.terminalCommand(for: "atlas")
        #expect(command.hasPrefix("env -i 'CLOUDSDK_CONFIG=/Users/op/.config/gcloud' 'HOME=/Users/op' "))
        let environment = try ChildEnvironment.build(parent: Fixture.parent, settings: settings)
        for (key, value) in environment {
            #expect(command.contains("'\(key)=\(value)'"), "\(key)")
        }
        #expect(!command.contains("KUBECONFIG") && !command.contains("/elsewhere"))
        #expect(command.hasSuffix(
            "'/Users/op/src/farcast/bin/farcast' '--config' '/Users/op/it'\\''s/farcast' '-o' 'json' 'world' '--' 'atlas'"
        ))
        #expect(await awaitFailure { _ = try await reader.terminalCommand(for: "lab2") }?.kind == .notFound)
        #expect(executor.invocations.count == 2)
    }

    @Test("listing() carries the stamp, sets the names, and a failed one unsets them")
    func listingCarriesTheStamp() async throws {
        let executor = try Fixture.executor()
        let reader = Fixture.reader(executor)
        let listing = try await reader.listing()
        #expect(listing.stamp == CLIStamp(version: "v0.0.0-vector", commit: "0e54eb1"))
        #expect(listing.instances.map(\.name) == ["atlas", "broken", "empty", "lab"])
        #expect(try await reader.listInstances() == listing.instances)
        _ = try await reader.terminalCommand(for: "atlas")
        executor.answer(try Self.argv("instances"), with: .result(Fixture.exited(1, try Vectors.data("world/error_not_found.json"))))
        #expect(await awaitFailure { _ = try await reader.listing() }?.kind == .notFound)
        #expect(await awaitFailure { _ = try await reader.terminalCommand(for: "atlas") }?.kind == .notFound)
    }

    @Test("a Settings problem names its row")
    func settingsProblemNamesTheRow() async throws {
        let executor = try Fixture.executor()
        var missing = Fixture.probe()
        missing.entries[Fixture.settings.farcast] = nil
        let refusal = await awaitFailure { _ = try await Fixture.reader(executor, probe: missing).listInstances() }
        #expect(refusal == ReadFailure(kind: .internal, message: "Settings need attention: farcast: nothing is at this path"))

        var open = Fixture.probe()
        open.entries[Fixture.settings.gcloudDirectory] = .directory(worldWritable: true)
        let gcloud = await awaitFailure { _ = try await Fixture.reader(executor, probe: open).listInstances() }
        #expect(gcloud == ReadFailure(
            kind: .internal,
            message: "Settings need attention: gcloud configuration directory: is writable by anyone on this Mac"
        ))
        #expect(executor.invocations.isEmpty)
    }

    @Test("the reader's deadlines sit under the feed's")
    func timeouts() {
        let timeouts = CLIReader.Timeouts()
        #expect(timeouts.version == .seconds(5) && timeouts.instances == .seconds(10) && timeouts.world == .seconds(75))
        // 20 and 90 s are WorldFeed's defaults, written out here as a reminder;
        // FarSightUITests' ReaderDeadlineTests checks against the feed's own,
        // with the time the app's executor takes to stop a child.
        #expect(timeouts.version + timeouts.instances < .seconds(20))
        #expect(timeouts.world < .seconds(90))
        #expect(CLILimits.output == 8 << 20 && CLILimits.error == 64 << 10)
    }
}
