import Foundation
import Synchronization
import Testing
@testable import FarSightUI
import FarSightCore
import FarSightFixtures

/// What a FarCast component's panel says, by label.
enum PanelFacts {
    static func of(_ model: WorldModel, _ appID: String) throws -> [String: String] {
        let app = try #require(model.index.apps[appID])
        return Dictionary(
            SystemSummary(app: app, model: model).facts.map { ($0.label, $0.value) },
            uniquingKeysWith: { first, _ in first }
        )
    }

    /// The panel's note, the lines under its facts.
    static func note(_ model: WorldModel, _ appID: String) throws -> String {
        let app = try #require(model.index.apps[appID])
        return SystemSummary(app: app, model: model).note ?? ""
    }
}

/// A clock that moves only when a test moves it, so a timeout is tested
/// without waiting for one.
nonisolated final class ManualClock: Clock {
    struct Instant: InstantProtocol {
        var offset: Duration

        func advanced(by duration: Duration) -> Instant { Instant(offset: offset + duration) }
        func duration(to other: Instant) -> Duration { other.offset - offset }
        static func < (a: Instant, b: Instant) -> Bool { a.offset < b.offset }
    }

    private struct Sleeper {
        let deadline: Instant
        let continuation: CheckedContinuation<Void, any Error>
    }

    private struct Waiter {
        let deadline: Instant
        let continuation: CheckedContinuation<Void, Never>
    }

    private struct State {
        var now = Instant(offset: .zero)
        var next = 0
        var sleepers: [Int: Sleeper] = [:]
        var cancelled: Set<Int> = []
        var waiters: [Waiter] = []
    }

    private let state = Mutex(State())

    var now: Instant { state.withLock { $0.now } }
    var minimumResolution: Duration { .zero }

    /// The moment `duration` after this clock's start.
    static func at(_ duration: Duration) -> Instant { Instant(offset: duration) }

    func sleep(until deadline: Instant, tolerance: Duration?) async throws {
        let id = state.withLock { state -> Int in
            state.next += 1
            return state.next
        }
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                enum Then { case wait, wake, cancel }
                let (then, ready) = state.withLock { state -> (Then, [CheckedContinuation<Void, Never>]) in
                    if state.cancelled.contains(id) { return (.cancel, []) }
                    if deadline <= state.now { return (.wake, []) }
                    state.sleepers[id] = Sleeper(deadline: deadline, continuation: continuation)
                    let ready = state.waiters.filter { $0.deadline == deadline }.map(\.continuation)
                    state.waiters.removeAll { $0.deadline == deadline }
                    return (.wait, ready)
                }
                for waiter in ready { waiter.resume() }
                switch then {
                case .wait: break
                case .wake: continuation.resume()
                case .cancel: continuation.resume(throwing: CancellationError())
                }
            }
        } onCancel: {
            let sleeper = state.withLock { state -> Sleeper? in
                state.cancelled.insert(id)
                return state.sleepers.removeValue(forKey: id)
            }
            sleeper?.continuation.resume(throwing: CancellationError())
        }
    }

    /// Returns once something is asleep until `deadline`.
    func sleeper(until deadline: Instant) async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            let present = state.withLock { state -> Bool in
                if state.sleepers.values.contains(where: { $0.deadline == deadline }) { return true }
                state.waiters.append(Waiter(deadline: deadline, continuation: continuation))
                return false
            }
            if present { continuation.resume() }
        }
    }

    /// Moves time on, and wakes every sleeper whose deadline has come.
    func advance(by duration: Duration) {
        let due = state.withLock { state -> [CheckedContinuation<Void, any Error>] in
            state.now = state.now.advanced(by: duration)
            let now = state.now
            let due = state.sleepers.filter { $0.value.deadline <= now }
            for id in due.keys { state.sleepers[id] = nil }
            return due.values.map(\.continuation)
        }
        for continuation in due { continuation.resume() }
    }
}

/// Something a fake reader waits on until the test opens it.
nonisolated final class Latch: Sendable {
    private struct State {
        var isOpen = false
        var next = 0
        var waiters: [Int: CheckedContinuation<Void, Never>] = [:]
        var cancelled: Set<Int> = []
        var arrived = 0
        var watchers: [CheckedContinuation<Void, Never>] = []
    }

    private let state = Mutex(State())

    /// How many waits were cancelled.
    var cancellations: Int { state.withLock { $0.cancelled.count } }

    /// Returns once something has come to wait here.
    func arrival() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            let arrived = state.withLock { state -> Bool in
                if state.arrived > 0 { return true }
                state.watchers.append(continuation)
                return false
            }
            if arrived { continuation.resume() }
        }
    }

    private func arrive() {
        let watchers = state.withLock { state -> [CheckedContinuation<Void, Never>] in
            state.arrived += 1
            let watchers = state.watchers
            state.watchers = []
            return watchers
        }
        for watcher in watchers { watcher.resume() }
    }

    /// Waits until opened, cancelled or not: a reader that ignores
    /// cancellation.
    func wait() async {
        arrive()
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            let open = state.withLock { state -> Bool in
                if state.isOpen { return true }
                state.next += 1
                state.waiters[state.next] = continuation
                return false
            }
            if open { continuation.resume() }
        }
    }

    /// Waits until opened or cancelled. Returns whether it was opened.
    func waitUnlessCancelled() async -> Bool {
        arrive()
        let id = state.withLock { state -> Int in
            state.next += 1
            return state.next
        }
        await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                let resume = state.withLock { state -> Bool in
                    if state.isOpen || state.cancelled.contains(id) { return true }
                    state.waiters[id] = continuation
                    return false
                }
                if resume { continuation.resume() }
            }
        } onCancel: {
            let waiter = state.withLock { state -> CheckedContinuation<Void, Never>? in
                state.cancelled.insert(id)
                return state.waiters.removeValue(forKey: id)
            }
            waiter?.resume()
        }
        return state.withLock { $0.isOpen }
    }

    func open() {
        let waiters = state.withLock { state -> [CheckedContinuation<Void, Never>] in
            state.isOpen = true
            let waiters = Array(state.waiters.values)
            state.waiters = [:]
            return waiters
        }
        for waiter in waiters { waiter.resume() }
    }
}

/// A reader that answers as a test tells it to, and records what it was
/// asked.
nonisolated final class FakeReader: WorldReader {
    indirect enum Answer: Sendable {
        case world(World)
        case failure(ReadFailure)
        /// Waits for the latch whatever happens, then answers.
        case after(Latch, Answer)
        /// Waits for the latch, and gives up if cancelled.
        case unlessCancelled(Latch, Answer)
    }

    enum Listing: Sendable {
        case instances([InstanceListing])
        case failure(ReadFailure)
    }

    private struct State {
        var listing: Listing
        var worlds: [String: Answer] = [:]
        var calls: [String] = []
    }

    let source: World.Source
    private let state: Mutex<State>

    init(source: World.Source = .live, listing: [InstanceListing] = [], worlds: [String: Answer] = [:]) {
        self.source = source
        state = Mutex(State(listing: .instances(listing), worlds: worlds))
    }

    var calls: [String] { state.withLock { $0.calls } }

    func set(listing: Listing) { state.withLock { $0.listing = listing } }
    func set(_ name: String, _ answer: Answer) { state.withLock { $0.worlds[name] = answer } }

    func listInstances() async throws(ReadFailure) -> [InstanceListing] {
        let listing = state.withLock { state -> Listing in
            state.calls.append("list")
            return state.listing
        }
        switch listing {
        case .instances(let listing): return listing
        case .failure(let failure): throw failure
        }
    }

    func readWorld(_ name: String) async throws(ReadFailure) -> World {
        let answer = state.withLock { state -> Answer? in
            state.calls.append("read \(name)")
            return state.worlds[name]
        }
        guard let answer else { throw ReadFailure(kind: .notFound, message: "no answer for \(name)") }
        return try await Self.give(answer)
    }

    private static func give(_ answer: Answer) async throws(ReadFailure) -> World {
        switch answer {
        case .world(let world):
            return world
        case .failure(let failure):
            throw failure
        case .after(let latch, let then):
            await latch.wait()
            return try await give(then)
        case .unlessCancelled(let latch, let then):
            guard await latch.waitUnlessCancelled() else {
                throw ReadFailure(kind: .internal, message: "cancelled")
            }
            return try await give(then)
        }
    }
}

/// Worlds for the tests.
nonisolated enum Worlds {
    /// One instance as a live reader returns it: its ids under its prefix,
    /// the operator's device as `operator`, a keeper of its own, a host and
    /// an alert whose names any other instance may share.
    static func slice(_ name: String, host: String = "api.example.test", readAt: Date? = nil) -> World {
        var instance = Instance.notYetRead(InstanceListing(
            name: name, status: .running, cloudLogging: .unverified, recordedLimitCents: 5000,
            components: [.kernel: true, .monitor: true, .boundary: true, .storage: true]
        ))
        for i in instance.groups[0].apps.indices {
            instance.groups[0].apps[i].state = .running
            instance.groups[0].apps[i].ready = 1
            instance.groups[0].apps[i].desired = 1
        }
        instance.groups.append(AppGroup(
            id: "\(name)/web", namespace: "web", source: "github.com/example/web",
            apps: [Application(id: "\(name)/web/site", name: "site", role: "the site", state: .running, ready: 1, desired: 1)]
        ))
        instance.spending = Spending(
            expectedCents: 1000, confirmedCents: 500, totalCents: 1500, limitCents: 5000, recordedLimitCents: 5000,
            hasConfirmation: true, confirmedThrough: Date(timeIntervalSince1970: 1_794_355_200), level: .ok
        )
        instance.readAt = readAt
        let system = "\(name)/farcast-system"
        return World(
            instances: [instance],
            devices: [
                Device(id: World.operatorDeviceID, name: "This Mac", role: .operator, note: "operator"),
                Device(id: "\(name)/phone", name: "phone", role: .keeper, note: "keeper", health: .healthy),
            ],
            hosts: [Host(id: "\(name)/\(host)", name: host, instanceID: name, note: "used by site")],
            connections: [
                Connection(
                    id: "\(name)/egress", from: .app("\(name)/web/site"), to: .host("\(name)/\(host)"),
                    kind: .egress, evidence: .observed, label: "at least 5", count: 5
                ),
                Connection(
                    id: "\(name)/tunnel", from: .device(World.operatorDeviceID), to: .app("\(system)/fatline"),
                    kind: .tunnel, evidence: .observed, label: "read now"
                ),
                Connection(
                    id: "\(name)/watch", from: .app("\(system)/shrike"), to: .app("\(system)/fatline"),
                    kind: .watch, evidence: .observed, label: "watches"
                ),
                Connection(
                    id: "\(name)/keeper", from: .device("\(name)/phone"), to: .app("\(system)/datasphere"),
                    kind: .keeper, evidence: .observed, label: "keeper"
                ),
            ],
            alerts: [WorldAlert(
                id: "\(name)/logging_unverified", kind: .loggingUnverified, severity: .warning,
                title: "\(name): cloud logging unverified", subject: .instance(name)
            )],
            source: .live
        )
    }

    static func listing(_ name: String) -> InstanceListing {
        InstanceListing(
            name: name, status: .running, cloudLogging: .unverified, recordedLimitCents: 5000,
            components: [.kernel: true, .monitor: true, .boundary: true, .storage: true]
        )
    }

    /// The fixture as a live world could hold it: the same ids, no sketch,
    /// no planned line, no app to app.
    static func liveFixture() throws -> World {
        var world = try Fixtures.world()
        world.source = .live
        let sketches = Set(world.instances.flatMap(\.groups).filter(\.isIllustrative).flatMap(\.apps).map(\.id))
        for i in world.instances.indices { world.instances[i].groups.removeAll(where: \.isIllustrative) }
        world.connections.removeAll { line in
            line.evidence == .planned || line.kind == .appToApp
                || [line.from, line.to].contains { $0.appID.map(sketches.contains) ?? false }
        }
        world.hosts.removeAll { host in !world.connections.contains { $0.to == .host(host.id) } }
        return world
    }
}
