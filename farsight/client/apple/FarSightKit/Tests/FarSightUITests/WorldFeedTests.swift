import Foundation
import Testing
@testable import FarSightUI
import FarSightCore
import FarSightFixtures

/// The feed: what it reads, when, and what it keeps when a read fails. Every
/// timeout here runs on a `ManualClock`; nothing waits in real time.
@Suite("The world feed")
struct WorldFeedTests {
    nonisolated static let readTime = Date(timeIntervalSince1970: 1_794_477_600)

    func feed(_ reader: FakeReader, clock: ManualClock = ManualClock()) -> WorldFeed {
        WorldFeed(
            reader: reader,
            clock: clock,
            timeouts: WorldFeed.Timeouts(listing: .seconds(5), read: .seconds(10)),
            now: { Self.readTime }
        )
    }

    @Test("at launch it lists the instances, reads none, and draws each as not read yet")
    func launchListsOnly() async throws {
        let reader = FakeReader(listing: [Worlds.listing("a"), Worlds.listing("b")], worlds: ["a": .world(Worlds.slice("a"))])
        let feed = feed(reader)
        #expect(feed.world.instances.isEmpty && feed.world.source == .live && !feed.hasListed)
        await feed.start()?.value
        #expect(feed.start() == nil)
        #expect(reader.calls == ["list"])
        #expect(feed.hasListed)
        #expect(feed.world.instances.map(\.id) == ["a", "b"])
        #expect(feed.world.instances.allSatisfy { $0.readAt == nil && $0.groups.count == 1 })
        #expect(feed.world.instances.flatMap(\.groups).flatMap(\.apps).allSatisfy { $0.state == .unknown })
        try feed.world.validate()
    }

    @Test("a refresh asked for while one runs is ignored")
    func oneRefreshAtATime() async throws {
        let latch = Latch()
        let reader = FakeReader(listing: [Worlds.listing("a")], worlds: ["a": .after(latch, .world(Worlds.slice("a")))])
        let feed = feed(reader)
        let running = try #require(feed.refresh())
        #expect(feed.isRefreshing)
        #expect(feed.refresh() == nil)
        #expect(feed.start() == nil)
        latch.open()
        await running.value
        #expect(!feed.isRefreshing)
        #expect(reader.calls == ["list", "read a"])
        #expect(feed.world.instances.map(\.groups.count) == [2])
        #expect(feed.world.instances[0].readAt == Self.readTime)
        let again = try #require(feed.refresh())
        await again.value
        #expect(reader.calls == ["list", "read a", "list", "read a"])
    }

    @Test("a failed read keeps the last good snapshot, faded, with its time and its problem, and no tunnel")
    func failedReadKeepsLastGood() async throws {
        let first = Date(timeIntervalSince1970: 1_794_470_000)
        let reader = FakeReader(listing: [Worlds.listing("a")], worlds: ["a": .world(Worlds.slice("a", readAt: first))])
        let feed = feed(reader)
        await feed.refresh()?.value
        let model = WorldModel(world: feed.world)
        #expect(model.tunnelled == ["a"])

        reader.set("a", .failure(ReadFailure(kind: .tunnelUnreachable, message: "dial tcp: i/o timeout")))
        await feed.refresh()?.value
        let instance = try #require(feed.world.instances.first)
        #expect(instance.groups.map(\.id) == ["a/farcast-system", "a/web"])
        #expect(instance.readAt == first)
        #expect(instance.problems == [SectionProblem(section: .read, kind: .tunnelUnreachable, message: "dial tcp: i/o timeout")])
        #expect(feed.world.connections.count == 4 && feed.world.connections.allSatisfy(\.isStale))
        model.update(world: feed.world)
        #expect(model.tunnelled.isEmpty)
        #expect(Format.readState(instance)?.contains("tunnel unreachable") == true)

        // A read that works again clears it.
        reader.set("a", .world(Worlds.slice("a")))
        await feed.refresh()?.value
        #expect(feed.world.instances[0].problems.isEmpty)
        #expect(feed.world.connections.allSatisfy { !$0.isStale })
    }

    @Test("a live feed never falls back to the fixture: not before a listing, not after a failed one, not for a failed read")
    func neverFallsBackToTheFixture() async throws {
        let fixtureGroups = Set(try Fixtures.world().instances.flatMap(\.groups).map(\.id))
        let reader = FakeReader()
        reader.set(listing: .failure(ReadFailure(kind: .internal, message: "config directory unreadable")))
        let feed = feed(reader)
        await feed.refresh()?.value
        #expect(feed.world.instances.isEmpty && feed.world.source == .live)
        #expect(feed.listingProblem?.message == "config directory unreadable")
        #expect(!feed.hasListed)

        reader.set(listing: .instances([Worlds.listing("atlas")]))
        reader.set("atlas", .failure(ReadFailure(kind: .gcloudMismatch, message: "no configuration matches")))
        await feed.refresh()?.value
        #expect(feed.listingProblem == nil)
        let atlas = try #require(feed.world.instances.first)
        #expect(atlas.groups.map(\.id) == ["atlas/farcast-system"])
        #expect(Set(feed.world.instances.flatMap(\.groups).map(\.id)).isDisjoint(with: fixtureGroups.subtracting(["atlas/farcast-system"])))
        #expect(atlas.problems.map(\.kind) == [.gcloudMismatch])
        #expect(feed.world.hosts.isEmpty && feed.world.connections.isEmpty && feed.world.alerts.isEmpty)
        try feed.world.validate()
    }

    @Test("a read that runs out of time gives control back, even from a reader that ignores cancellation")
    func timeoutFromAStalledReader() async throws {
        let clock = ManualClock()
        let latch = Latch()
        defer { latch.open() }
        let reader = FakeReader(
            listing: [Worlds.listing("a"), Worlds.listing("b")],
            worlds: ["a": .after(latch, .world(Worlds.slice("a"))), "b": .world(Worlds.slice("b"))]
        )
        let feed = feed(reader, clock: clock)
        let running = try #require(feed.refresh())
        await clock.sleeper(until: ManualClock.at(.seconds(10)))
        clock.advance(by: .seconds(10))
        await running.value
        #expect(!feed.isRefreshing)
        #expect(reader.calls == ["list", "read a", "read b"])
        #expect(feed.world.instances.map(\.id) == ["a", "b"])
        #expect(feed.world.instances[0].problems.map(\.kind) == [.timeout])
        #expect(feed.world.instances[1].problems.isEmpty && feed.world.instances[1].readAt == Self.readTime)
    }

    @Test("a listing that runs out of time changes nothing and says so")
    func listingTimeout() async throws {
        let clock = ManualClock()
        let reader = StallingLister()
        defer { reader.latch.open() }
        let feed = WorldFeed(reader: reader, clock: clock, timeouts: WorldFeed.Timeouts(listing: .seconds(5), read: .seconds(10)))
        let running = try #require(feed.refresh())
        await clock.sleeper(until: ManualClock.at(.seconds(5)))
        clock.advance(by: .seconds(5))
        await running.value
        #expect(feed.listingProblem?.kind == .timeout)
        #expect(feed.world.instances.isEmpty && !feed.hasListed)
    }

    @Test("cancel ends a refresh at once, and a read cut short is not recorded as a failure")
    func cancelling() async throws {
        let clock = ManualClock()
        let latch = Latch()
        defer { latch.open() }
        let reader = FakeReader(listing: [Worlds.listing("a")], worlds: ["a": .after(latch, .world(Worlds.slice("a")))])
        let feed = feed(reader, clock: clock)
        let running = try #require(feed.refresh())
        await clock.sleeper(until: ManualClock.at(.seconds(10)))
        feed.cancel()
        await running.value
        #expect(!feed.isRefreshing)
        #expect(feed.world.instances.map(\.problems) == [[]])
        #expect(feed.world.instances[0].readAt == nil)
    }

    @Test("a reader that honours cancellation is cancelled when its read runs out of time")
    func timedOutReadIsCancelled() async throws {
        let clock = ManualClock()
        let latch = Latch()
        defer { latch.open() }
        let reader = FakeReader(listing: [Worlds.listing("a")], worlds: ["a": .unlessCancelled(latch, .world(Worlds.slice("a")))])
        let feed = feed(reader, clock: clock)
        let running = try #require(feed.refresh())
        await latch.arrival()
        await clock.sleeper(until: ManualClock.at(.seconds(10)))
        clock.advance(by: .seconds(10))
        await running.value
        #expect(feed.world.instances[0].problems.map(\.kind) == [.timeout])
        #expect(latch.cancellations == 1)
    }

    @Test("the listing decides the instances: one it no longer has goes, and a failed listing changes nothing")
    func listingDecides() async throws {
        let reader = FakeReader(
            listing: [Worlds.listing("a"), Worlds.listing("b")],
            worlds: ["a": .world(Worlds.slice("a")), "b": .world(Worlds.slice("b"))]
        )
        let feed = feed(reader)
        await feed.refresh()?.value
        #expect(feed.world.instances.map(\.id) == ["a", "b"])

        reader.set(listing: .instances([Worlds.listing("b")]))
        await feed.refresh()?.value
        #expect(feed.world.instances.map(\.id) == ["b"])
        #expect(feed.world.hosts.map(\.id) == ["b/api.example.test"])
        let kept = feed.world

        reader.set(listing: .failure(ReadFailure(kind: .internal, message: "unreadable")))
        await feed.refresh()?.value
        #expect(feed.world == kept)
        #expect(feed.listingProblem?.kind == .internal)

        reader.set(listing: .instances([]))
        await feed.refresh()?.value
        #expect(feed.world.instances.isEmpty && feed.hasListed && feed.listingProblem == nil)
    }

    @Test("two instances with the same host and the same kind of alert compose, and the operator's device is drawn once")
    func instancesCompose() async throws {
        let reader = FakeReader(
            listing: [Worlds.listing("a"), Worlds.listing("b")],
            worlds: ["a": .world(Worlds.slice("a")), "b": .world(Worlds.slice("b"))]
        )
        let feed = feed(reader)
        await feed.refresh()?.value
        try feed.world.validate()
        #expect(feed.world.hosts.map(\.name) == ["api.example.test", "api.example.test"])
        #expect(feed.world.devices.map(\.id) == ["operator", "a/phone", "b/phone"])
        #expect(feed.world.alerts.map(\.kind) == [.loggingUnverified, .loggingUnverified])
        #expect(WorldModel(world: feed.world).tunnelled == ["a", "b"])
    }

    @Test("an instance whose read cannot be drawn leaves the others drawn")
    func invalidInstanceIsolated() async throws {
        var sketchy = Worlds.slice("b")
        sketchy.instances[0].groups[1].isIllustrative = true
        sketchy.instances[0].groups[1].apps[0].isIllustrative = true
        var stray = Worlds.slice("c")
        stray.hosts[0].id = "api.example.test"
        stray.connections[0].to = .host("api.example.test")
        let reader = FakeReader(
            listing: [Worlds.listing("a"), Worlds.listing("b"), Worlds.listing("c")],
            worlds: ["a": .world(Worlds.slice("a")), "b": .world(sketchy), "c": .world(stray)]
        )
        let feed = feed(reader)
        await feed.refresh()?.value
        try feed.world.validate()
        let instances = feed.world.instances
        #expect(instances.map(\.id) == ["a", "b", "c"])
        #expect(instances[0].groups.count == 2 && instances[0].problems.isEmpty)
        for unreadable in instances[1...] {
            #expect(unreadable.groups.count == 1)
            #expect(unreadable.problems.map(\.kind) == [.internal])
        }
        #expect(instances[1].problems[0].message.contains("live world has illustrative group b/web"))
        #expect(instances[2].problems[0].message.contains("host api.example.test is not under c/"))
    }

    @Test("one listed record that cannot be drawn is drawn with that said, and the others are listed and read")
    func badListingEntryIsolated() async throws {
        let reader = FakeReader(
            listing: [
                Worlds.listing("atlas"),
                InstanceListing(name: "legacy", status: .running, cloudLogging: .systemOnly, recordedLimitCents: nil),
                InstanceListing(name: "zero", status: .running, cloudLogging: .systemOnly, recordedLimitCents: 0),
            ],
            worlds: ["atlas": .world(Worlds.slice("atlas"))]
        )
        let feed = feed(reader)
        await feed.start()?.value
        #expect(feed.hasListed && feed.listingProblem == nil)
        try #require(feed.world.instances.map(\.id) == ["atlas", "legacy", "zero"])
        // What ConnectedWorldScreen's "No instances on this Mac" waits for.
        #expect(!(feed.hasListed && feed.listingProblem == nil && feed.world.instances.isEmpty))

        await feed.refresh()?.value
        #expect(reader.calls == ["list", "list", "read atlas", "read legacy", "read zero"])
        try feed.world.validate()
        let instances = feed.world.instances
        try #require(instances.count == 3)
        #expect(instances[0].groups.count == 2 && instances[0].problems.isEmpty)
        for listed in instances[1...] {
            #expect(listed.spending.recordedLimitCents == nil)
            #expect(listed.problem(in: .record)?.kind == .internal)
        }
        #expect(instances[1].problem(in: .record)?.message == "the record holds no cost limit")
        #expect(instances[2].problem(in: .record)?.message.contains("0 cents") == true)
    }

    @Test("a read whose spending section failed lands, for a running instance and a deleting one, with the recorded limit from the listing")
    func spendNotReadLands() async throws {
        func unspent(_ name: String, _ status: Instance.Status) -> World {
            var world = Worlds.slice(name)
            world.instances[0].status = status
            world.instances[0].spending = Spending()
            world.instances[0].problems = [SectionProblem(section: .spend, kind: .kernelAbsent, message: "no technocore")]
            return world
        }
        let reader = FakeReader(
            listing: [Worlds.listing("a"), Worlds.listing("b")],
            worlds: ["a": .world(unspent("a", .running)), "b": .world(unspent("b", .deleting))]
        )
        let feed = feed(reader)
        await feed.refresh()?.value
        try feed.world.validate()
        for instance in feed.world.instances {
            #expect(instance.groups.count == 2, "\(instance.id) landed")
            #expect(instance.readAt == Self.readTime)
            #expect(instance.problems.map(\.section) == [.spend])
            #expect(instance.spending.limitCents == nil && instance.spending.recordedLimitCents == 5000)
            #expect(Format.spending(instance.spending) == "spending not read · recorded limit $50.00")
        }
        #expect(feed.world.instances.map(\.status) == [.running, .deleting])
    }

    @Test("what a newer listing says of the record is drawn over a kept snapshot, until a read lands")
    func listingOverKeptSnapshot() async throws {
        let reader = FakeReader(listing: [Worlds.listing("a")], worlds: ["a": .world(Worlds.slice("a"))])
        let feed = feed(reader)
        await feed.refresh()?.value
        try #require(feed.world.instances.count == 1)
        #expect(feed.world.instances[0].status == .running)

        // A release started from a terminal; the read then fails.
        var released = Worlds.listing("a")
        released.status = .deleting
        released.cloudLogging = .systemOnly
        released.recordedLimitCents = 7000
        reader.set(listing: .instances([released]))
        reader.set("a", .failure(ReadFailure(kind: .tunnelUnreachable, message: "dial tcp: i/o timeout")))
        await feed.refresh()?.value
        let kept = try #require(feed.world.instances.first)
        #expect(kept.groups.count == 2)
        #expect(kept.status == .deleting && kept.cloudLogging == .systemOnly)
        #expect(kept.spending.recordedLimitCents == 7000 && kept.spending.limitCents == 5000)
        #expect(Format.readState(kept)?.contains("release incomplete, may still be billing") == true)

        // While the next read is out, the listing is still the newer; once
        // it lands, the read is.
        let latch = Latch()
        reader.set("a", .after(latch, .world(Worlds.slice("a"))))
        let running = try #require(feed.refresh())
        await latch.arrival()
        #expect(feed.world.instances[0].status == .deleting)
        latch.open()
        await running.value
        #expect(feed.world.instances[0].status == .running && feed.world.instances[0].problems.isEmpty)
        #expect(feed.world.instances[0].spending.recordedLimitCents == 5000)
    }

    @Test("a failed read leaves no healthy keeper needing attention, and the present says not read")
    func failedReadKeepsKeepersHealthy() async throws {
        let reader = FakeReader(listing: [Worlds.listing("a")], worlds: ["a": .world(Worlds.slice("a"))])
        let feed = feed(reader)
        await feed.refresh()?.value
        let model = WorldModel(world: feed.world)
        func facts(_ app: String) throws -> [String: String] {
            try PanelFacts.of(model, "a/farcast-system/\(app)")
        }
        #expect(try facts("datasphere")["keepers needing attention"] == "0")
        #expect(try facts("datasphere")["keepers"] == "1")
        #expect(try facts("fatline")["devices coming in"] == "2")

        reader.set("a", .failure(ReadFailure(kind: .tunnelUnreachable, message: "dial tcp: i/o timeout")))
        await feed.refresh()?.value
        model.update(world: feed.world)
        #expect(try facts("datasphere")["keepers needing attention"] == "0")
        #expect(try facts("datasphere")["keepers"] == "1")
        #expect(try facts("datasphere")["seal not read"] == "unknown")
        #expect(try facts("fatline")["devices coming in"] == "not read")
        #expect(try facts("shrike")["Shrike's watch on FatLine"] == "not read")
        // What the kept snapshot counted stays, as of its read.
        #expect(try facts("fatline")["lines out, counted"] == "1")
    }

    @Test("over the fixture reader, the feed composes the fixture's instances, with their ids")
    func fixtureFeed() async throws {
        let fixture = try Fixtures.world()
        let feed = WorldFeed(reader: try FixtureReader(), clock: ManualClock())
        await feed.refresh()?.value
        try feed.world.validate()
        #expect(feed.world.source == .fixture)
        #expect(feed.world.instances.map(\.id) == fixture.instances.map(\.id))
        #expect(feed.world.instances.map(\.groups) == fixture.instances.map(\.groups))
        #expect(feed.world.connections.count == fixture.connections.count)
        #expect(feed.world.devices.map(\.id) == ["operator", "atlas/ubuntu-vm", "borealis/pixel-phone"])
    }

    @Test("a deadline answers with the operation when it finishes first")
    func deadlineAnswers() async throws {
        let answer = await withDeadline(.seconds(1), on: ManualClock()) { () async throws(ReadFailure) -> Int in 42 }
        #expect(try answer?.get() == 42)
        let failure = await withDeadline(.seconds(1), on: ManualClock()) { () async throws(ReadFailure) -> Int in
            throw ReadFailure(kind: .kubectlMissing, message: "no kubectl")
        }
        #expect(throws: ReadFailure(kind: .kubectlMissing, message: "no kubectl")) { try failure?.get() }
    }
}

/// A reader whose listing never answers, cancelled or not.
nonisolated final class StallingLister: WorldReader {
    let source: World.Source = .live
    let latch = Latch()

    func listInstances() async throws(ReadFailure) -> [InstanceListing] {
        await latch.wait()
        return []
    }

    func readWorld(_ instance: String) async throws(ReadFailure) -> World {
        throw ReadFailure(kind: .notFound, message: instance)
    }
}
