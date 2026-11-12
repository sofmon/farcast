import Foundation
import Observation
import FarSightCore

/// The world read from the operator's instances, for every window of the
/// app: one feed per app, passed down with `.environment(feed)` and read
/// with `@Environment(WorldFeed.self)`. Each window keeps its own
/// `WorldModel` and updates it from `world`; closing a window drops only its
/// model.
///
/// What it reads, and when (ADR 0021 decision 9, amended 2026-11-12):
/// - At launch it lists the instances, which reads only files on this Mac,
///   and draws each as not read yet. That listing is the one read it starts
///   by itself. Nothing runs on a timer.
/// - On `refresh()` — the operator's Refresh — it lists again, then reads
///   each instance in the listing's order, one at a time, and each lands on
///   the map as it arrives. A refresh asked for while one runs is ignored.
/// - Each listing and each read has a deadline on the injected clock, and
///   control comes back by it even from a reader that ignores cancellation.
/// - A read that fails, or that returns a world that cannot be drawn, keeps
///   that instance's last good snapshot: its lines fade, since nothing
///   vouches for them now, its read time stays, and the failure is shown.
///   What the newer listing says of the record — its status, its limit,
///   its logging — is drawn over the kept snapshot. An instance never read
///   is drawn from its listing. Neither ever falls back to the fixture.
/// - A listing that fails changes nothing on the map and is shown as
///   `listingProblem`. One entry whose record cannot be drawn is drawn with
///   that said, and never keeps the other instances off the map. An
///   instance a successful listing no longer has is removed, with its
///   snapshot.
@Observable
public final class WorldFeed {
    /// Every instance, composed from the latest listing and each one's last
    /// good read. Always valid: a window may hand it to `update(world:)` as
    /// it is.
    public private(set) var world: World
    /// Why the last listing failed, until one succeeds.
    public private(set) var listingProblem: ReadFailure?
    /// Whether a listing has succeeded: until then, an empty world says
    /// nothing about whether there are instances.
    public private(set) var hasListed = false
    /// Whether a listing or a refresh is running.
    public private(set) var isRefreshing = false

    /// How long a listing and each read may take.
    public struct Timeouts: Sendable, Equatable {
        public var listing: Duration
        public var read: Duration

        /// A read is the CLI's whole `world` command, which holds itself to
        /// about a minute.
        public init(listing: Duration = .seconds(20), read: Duration = .seconds(90)) {
            self.listing = listing
            self.read = read
        }
    }

    @ObservationIgnored private let reader: any WorldReader
    @ObservationIgnored private let clock: any Clock<Duration>
    @ObservationIgnored private let timeouts: Timeouts
    @ObservationIgnored private let now: @Sendable () -> Date
    /// The instances, in the listing's order.
    @ObservationIgnored private var order: [String] = []
    @ObservationIgnored private var slots: [String: Slot] = [:]
    @ObservationIgnored private var task: Task<Void, Never>?
    @ObservationIgnored private var started = false

    /// One instance: what the listing says of it, its last good read, and
    /// why its latest read failed, if it did.
    private struct Slot {
        var listing: InstanceListing
        var good: World?
        var failure: ReadFailure?
        /// The listing came after the last good read: every refresh lists
        /// first, so until this refresh's read lands, or when it fails, what
        /// the record says now is newer than the snapshot kept.
        var listingIsNewer = false
    }

    public init(
        reader: any WorldReader,
        clock: any Clock<Duration> = ContinuousClock(),
        timeouts: Timeouts = Timeouts(),
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.reader = reader
        self.clock = clock
        self.timeouts = timeouts
        self.now = now
        // Empty, from the reader's source: a live feed never holds the
        // fixture, not even before its first listing.
        world = World(instances: [], source: reader.source)
    }

    /// Where this feed's worlds come from.
    public var source: World.Source { reader.source }

    /// The launch listing, once. Returns its task, or nil if it already ran
    /// or something else is running.
    @discardableResult
    public func start() -> Task<Void, Never>? {
        guard !started else { return nil }
        started = true
        return begin(reading: false)
    }

    /// The operator's Refresh: list, then read every instance. Returns its
    /// task, or nil when one is already running and this one is ignored.
    @discardableResult
    public func refresh() -> Task<Void, Never>? {
        begin(reading: true)
    }

    /// Stops whatever is running, as the app quits. A read cut short is not
    /// recorded as a failure. Closing a window never calls this.
    public func cancel() {
        task?.cancel()
    }

    private func begin(reading: Bool) -> Task<Void, Never>? {
        guard task == nil else { return nil }
        isRefreshing = true
        let task = Task { await run(reading: reading) }
        self.task = task
        return task
    }

    private func run(reading: Bool) async {
        defer {
            task = nil
            isRefreshing = false
        }
        let reader = self.reader
        let listed = await withDeadline(timeouts.listing, on: clock) { () async throws(ReadFailure) -> [InstanceListing] in
            try await reader.listInstances()
        }
        switch listed {
        case nil:
            return
        case .failure(let failure):
            listingProblem = failure
            return
        case .success(let listing):
            // A listing that cannot be drawn is a failed listing: it changes
            // nothing, and nothing is read on it.
            guard apply(listing) else { return }
        }
        guard reading else { return }
        for name in order {
            guard !Task.isCancelled else { return }
            let read = await withDeadline(timeouts.read, on: clock) { () async throws(ReadFailure) -> World in
                try await reader.readWorld(name)
            }
            guard let read else { return }
            land(name, read)
        }
    }

    /// Takes a listing in: the instances it names, in its order, each drawn
    /// from its last good read or as not read yet. One entry's bad record
    /// never keeps the others off the map — `Instance.notYetRead` turns what
    /// cannot be drawn into a problem with that record. Returns whether the
    /// listing was taken; if the whole could still not be drawn, the map
    /// stays as it was and the listing is reported as failed.
    private func apply(_ listing: [InstanceListing]) -> Bool {
        var seen = Set<String>()
        let unique = listing.filter { seen.insert($0.name).inserted }
        var next: [String: Slot] = [:]
        for entry in unique {
            var slot = slots[entry.name] ?? Slot(listing: entry)
            slot.listing = entry
            slot.listingIsNewer = slot.good != nil
            next[entry.name] = slot
        }
        let previous = (order, slots)
        order = unique.map(\.name)
        slots = next
        do throws(WorldError) {
            try commit()
        } catch {
            (order, slots) = previous
            listingProblem = ReadFailure(kind: .internal, message: "the instances listed cannot be drawn together: \(error.description)")
            return false
        }
        listingProblem = nil
        hasListed = true
        return true
    }

    private func land(_ name: String, _ result: Result<World, ReadFailure>) {
        guard let previous = slots[name] else { return }
        var slot = previous
        switch result {
        case .success(var read):
            // A world read from an instance carries the record's limit only
            // inside its spending section. When that section failed, the
            // listing — read from the same record, moments before — still
            // says what the record holds, labelled as recorded.
            if read.instances.count == 1, read.instances[0].spending.recordedLimitCents == nil {
                read.instances[0].spending.recordedLimitCents = slot.listing.drawableLimitCents
            }
            do throws(WorldError) {
                try read.validate(asReadOf: name, source: reader.source)
                if read.instances[0].readAt == nil { read.instances[0].readAt = now() }
                slot.good = read
                slot.failure = nil
                slot.listingIsNewer = false
            } catch {
                slot.failure = ReadFailure(kind: .internal, message: "the read of \(name) cannot be drawn: \(error.description)")
            }
        case .failure(let failure):
            slot.failure = failure
        }
        slots[name] = slot
        do throws(WorldError) {
            try commit()
        } catch {
            // The slot as it was composed before, with the read's failure:
            // that only adds a problem and fades lines, so it composes.
            var kept = previous
            kept.failure = ReadFailure(kind: .internal, message: "the read of \(name) does not compose with the other instances: \(error.description)")
            slots[name] = kept
            try? commit()
        }
    }

    /// Composes and validates the world, and shows it if it is valid.
    private func commit() throws(WorldError) {
        let composed = compose()
        try composed.validate()
        if composed != world { world = composed }
    }

    /// Instances in the listing's order, the operator's device once, and
    /// everything else each instance's read holds. Ids do not collide,
    /// because each read's carry its instance's prefix
    /// (`World.validate(asReadOf:source:)`).
    private func compose() -> World {
        var composite = World(instances: [], source: reader.source)
        var devices = Set<String>()
        for name in order {
            guard let slot = slots[name] else { continue }
            var part = slot.good ?? World(instances: [.notYetRead(slot.listing)], source: reader.source)
            if slot.good != nil, slot.listingIsNewer {
                // The snapshot kept is older than the listing: what the
                // record says now — a release started from a terminal, say
                // — is drawn over it, and what is wrong with the record is
                // said.
                let listing = slot.listing
                part.instances[0].status = listing.status
                part.instances[0].cloudLogging = listing.cloudLogging
                part.instances[0].spending.recordedLimitCents = listing.drawableLimitCents
                for problem in listing.recordProblems where !part.instances[0].problems.contains(problem) {
                    part.instances[0].problems.append(problem)
                }
            }
            if let failure = slot.failure {
                // Kept, but nothing vouches for it now: every line fades, the
                // tunnel's among them, so the map no longer claims one.
                part.instances[0].problems.append(SectionProblem(section: .read, kind: failure.kind, message: failure.message))
                for i in part.connections.indices { part.connections[i].isStale = true }
            }
            composite.instances += part.instances
            for device in part.devices where devices.insert(device.id).inserted {
                composite.devices.append(device)
            }
            composite.hosts += part.hosts
            composite.connections += part.connections
            composite.alerts += part.alerts
        }
        return composite
    }
}
