import Foundation
import SwiftUI
import Testing
@testable import FarSightUI
import FarSightCore
import FarSightFixtures

/// A world that changes under the map, and what the map says of what it
/// could not read.
@Suite("A world that changes")
struct LiveModelTests {
    let viewport = CGSize(width: 1440, height: 900)

    func model(_ world: World, store: ArrangementStore? = nil) -> WorldModel {
        let model = WorldModel(world: world, store: store)
        model.viewportChanged(to: viewport)
        return model
    }

    /// Drags `group` by its header `dx` world units to the right.
    func drag(_ model: WorldModel, _ group: String, by dx: CGFloat) {
        let grab = model.camera.screen(model.geometry.groups[group]!.header.origin, in: viewport)
        let point = CGPoint(x: grab.x + 10, y: grab.y + 5)
        #expect(model.beginMove(.group(group), at: point))
        model.move(.group(group), to: CGPoint(x: point.x + dx * model.camera.scale, y: point.y))
        model.endMove(.group(group))
    }

    func defaults() throws -> (UserDefaults, String) {
        let suite = "farsight.tests.\(UUID().uuidString)"
        return (try #require(UserDefaults(suiteName: suite)), suite)
    }

    // MARK: - update(world:)

    @Test("an update keeps a dragged group where the operator put it, and places what is new")
    func updateKeepsDraggedGroup() throws {
        let world = try Fixtures.world()
        let model = model(world)
        drag(model, "atlas/home", by: 300)
        let moved = try #require(model.arrangement.groupOrigins["atlas/home"])
        #expect(moved != Arrangement.standard(for: world).groupOrigins["atlas/home"])

        var next = world
        next.instances[0].groups[2].apps.append(Application(id: "atlas/dev/ci", name: "ci", role: "builds", state: .running))
        next.connections[0].label = "6 ok"
        model.update(world: next)
        #expect(model.arrangement.groupOrigins["atlas/home"] == moved)
        #expect(model.geometry.apps["atlas/dev/ci"] != nil)
        #expect(model.world == next)
        #expect(!model.arrangement.hasConflicts(for: next))
        #expect(model.flight == nil)
    }

    @Test("focus on an app that is gone is dropped; focus on one still there stays")
    func focusOnRemovedAppClears() throws {
        let world = try Fixtures.world()
        let model = model(world)
        model.focus(on: "atlas/home/photos")
        var next = world
        next.instances[0].groups[1].apps.removeAll { $0.id == "atlas/home/photos" }
        next.connections.removeAll { $0.from == .app("atlas/home/photos") }
        try next.validate()
        model.update(world: next)
        #expect(model.focus == nil)
        #expect(model.index.apps["atlas/home/photos"] == nil)

        model.focus(on: "atlas/home/notes")
        model.update(world: next)
        #expect(model.focus == "atlas/home/notes")
    }

    @Test("Space goes on from the alert last opened, by its id, after the alerts are reordered")
    func alertCursorSurvivesReordering() throws {
        let world = try Fixtures.world()
        let model = model(world)
        #expect(model.alerts.map(\.id) == ["sealed-borealis", "cost-borealis", "denied-forge"])
        model.open(model.alerts[2])
        #expect(model.focus == "atlas/dev/forge")
        var next = world
        next.alerts.reverse()
        model.update(world: next)
        // Critical first, then the snapshot's order: denied-forge now comes
        // before cost-borealis. By position, Space would wrap round to
        // sealed-borealis and focus DataSphere; by id it goes on to the
        // alert after denied-forge, the one about borealis itself.
        #expect(model.alerts.map(\.id) == ["sealed-borealis", "denied-forge", "cost-borealis"])
        model.openNextAlert()
        #expect(model.focus == nil)
        #expect(model.camera == model.fitted(.instance("borealis")))

        // The one last opened is gone: Space starts again at the most urgent.
        next.alerts.removeAll { $0.id == "cost-borealis" }
        model.update(world: next)
        model.openNextAlert()
        #expect(model.focus == "borealis/farcast-system/datasphere")
    }

    @Test("a drag on something that is gone is put back, unsaved")
    func vanishedMoveIsCancelled() throws {
        let (defaults, suite) = try defaults()
        defer { defaults.removePersistentDomain(forName: suite) }
        let world = try Fixtures.world()
        let model = model(world, store: ArrangementStore(defaults: defaults))
        let before = try #require(model.arrangement.groupOrigins["atlas/dev"])
        let grab = model.camera.screen(model.geometry.groups["atlas/dev"]!.header.origin, in: viewport)
        #expect(model.beginMove(.group("atlas/dev"), at: grab))
        model.move(.group("atlas/dev"), to: CGPoint(x: grab.x + 50, y: grab.y))
        var next = world
        next.instances[0].groups.removeAll { $0.id == "atlas/dev" }
        next.connections.removeAll { $0.from == .app("atlas/dev/forge") }
        next.alerts.removeAll { $0.subject == .app("atlas/dev/forge") }
        next.hosts.removeAll { ["git", "tracker"].contains($0.id) }
        try next.validate()
        model.update(world: next)
        model.endMove(.group("atlas/dev"))
        #expect(model.arrangement.groupOrigins["atlas/dev"] == before)
        #expect(defaults.data(forKey: ArrangementStore.key(for: .fixture)) == nil)
    }

    @Test("the first world with anything in it is framed at once; a change of source flies to the whole world")
    func framing() throws {
        let model = model(World(instances: [], source: .live))
        let empty = model.camera
        let live = try Worlds.liveFixture()
        model.update(world: live)
        #expect(model.camera != empty)
        #expect(model.camera == model.fitted(.world))
        #expect(model.flight == nil)

        model.focus(on: "atlas/home/photos")
        model.update(world: live)
        #expect(model.camera == model.fitted(.app("atlas/home/photos")))

        model.update(world: try Fixtures.world())
        #expect(model.flight != nil)
        #expect(model.camera == model.fitted(.world))
    }

    // MARK: - Arrangements per source

    @Test("each source keeps its arrangement under its own key, and a live world never inherits the fixture's places")
    func arrangementPerSource() throws {
        let (defaults, suite) = try defaults()
        defer { defaults.removePersistentDomain(forName: suite) }
        #expect(ArrangementStore.key(for: .fixture) == "farsight.arrangement.v2")
        #expect(ArrangementStore.key(for: .live) != ArrangementStore.key(for: .fixture))

        let fixture = try Fixtures.world()
        let model = model(fixture, store: ArrangementStore(defaults: defaults))
        drag(model, "atlas/home", by: 300)
        let saved = try #require(defaults.data(forKey: ArrangementStore.key(for: .fixture)))
        let dragged = model.arrangement.groupOrigins["atlas/home"]

        let live = try Worlds.liveFixture()
        model.update(world: live)
        #expect(defaults.data(forKey: ArrangementStore.key(for: .live)) == nil)
        #expect(model.arrangement.groupOrigins["atlas/home"] == Arrangement.standard(for: live).groupOrigins["atlas/home"])
        #expect(model.arrangement.groupOrigins["atlas/home"] != dragged)

        model.show(.world)
        drag(model, "atlas/dev", by: 300)
        #expect(defaults.data(forKey: ArrangementStore.key(for: .live)) != nil)
        #expect(defaults.data(forKey: ArrangementStore.key(for: .fixture)) == saved)

        // A store made for the fixture, handed a live world, uses the live key.
        let reopened = WorldModel(world: live, store: ArrangementStore(defaults: defaults))
        #expect(reopened.arrangement.groupOrigins["atlas/dev"] == model.arrangement.groupOrigins["atlas/dev"])
        #expect(reopened.arrangement.groupOrigins["atlas/home"] != dragged)
    }

    // MARK: - Alerts about instances and devices

    @Test("an alert about an instance or a device frames it, and leaves nothing focused")
    func alertSubjects() throws {
        var world = try Worlds.liveFixture()
        world.alerts.append(WorldAlert(id: "log", kind: .loggingUnverified, severity: .warning, title: "atlas: logging unverified", subject: .instance("atlas")))
        world.alerts.append(WorldAlert(id: "key", kind: .keeper, severity: .warning, title: "pixel-phone: leaf expired", subject: .device("pixel-phone")))
        try world.validate()
        let model = model(world)
        #expect(model.alertByInstance["atlas"]?.id == "log")
        #expect(model.alertByInstance["borealis"]?.id == "cost-borealis")
        #expect(model.alertByDevice["pixel-phone"]?.id == "key")
        #expect(model.alertByApp["borealis/farcast-system/datasphere"]?.id == "sealed-borealis")

        model.focus(on: "borealis/lab/wiki")
        model.open(try #require(model.alerts.first { $0.id == "log" }))
        #expect(model.focus == nil)
        #expect(model.camera == model.fitted(.instance("atlas")))
        model.focus(on: "atlas/home/notes")
        model.open(try #require(model.alerts.first { $0.id == "key" }))
        #expect(model.focus == nil)
        #expect(model.camera == model.fitted(.device("pixel-phone")))
        #expect(model.frame(of: .device("pixel-phone")) == model.geometry.devices["pixel-phone"])
    }

    // MARK: - What is drawn

    @Test("an instance that could not be read is drawn: a territory whose chip says what failed")
    func unreadableInstanceDraws() throws {
        let broken = Instance.notYetRead(InstanceListing(
            name: "broken",
            problem: SectionProblem(section: .record, kind: .recordUnreadable, message: "metadata.yaml: bad indent")
        ))
        var deleting = Instance.notYetRead(Worlds.listing("atlas"))
        deleting.status = .deleting
        deleting.problems = [SectionProblem(section: .read, kind: .timeout, message: "no answer within 90 seconds")]
        let world = World(instances: [broken, deleting], source: .live)
        try world.validate()
        let model = model(world)
        #expect(model.geometry.territories.keys.sorted() == ["atlas", "broken"])
        #expect(Format.readState(broken) == "not read yet · record unreadable")
        #expect(Format.readState(deleting) == "release incomplete, may still be billing · not read yet · timed out")
        #expect(Format.spending(deleting.spending) == "spending not read · recorded limit $50.00")

        let renderer = ImageRenderer(content: WorldScreen(model: model, backdrop: nil).frame(width: viewport.width, height: viewport.height))
        renderer.proposedSize = ProposedViewSize(viewport)
        #expect(renderer.cgImage != nil)
    }

    @Test("spending is said in two parts against the kernel's limit, never as one total, and VoiceOver names the total")
    func spendingInTwoParts() throws {
        let fixture = try Fixtures.world()
        let atlas = fixture.instances[0].spending
        let through = try #require(atlas.confirmedThrough)
        #expect(Format.spending(atlas) == "$29.00 confirmed through \(Format.day(through)) + $12.80 expected of $150.00 · total 28%")
        let spoken = Format.spendingSpoken(atlas)
        #expect(spoken.contains("$29.00 confirmed through") && spoken.contains("$12.80 expected"))
        #expect(spoken.contains("total 28% of its $150.00 limit, the figure enforcement compares"))

        let unconfirmed = Spending(expectedCents: 1280, totalCents: 1280, limitCents: 15000, level: .ok)
        #expect(Format.spending(unconfirmed) == "$12.80 expected of $150.00 · no confirmation yet · total 9%")
        #expect(Format.spendingSpoken(unconfirmed).contains("no confirmation yet"))
        var stale = unconfirmed
        stale.isCheckpointStale = true
        stale.limitCents = nil
        #expect(Format.spending(stale) == "$12.80 expected · no kernel limit · no confirmation yet · checkpoint stale")
        #expect(Theme.level(.unknown) == Theme.secondaryText)
        #expect(Theme.level(.warn90) == Theme.warning && Theme.level(.reached) == Theme.critical && Theme.level(.ok) == Theme.running)
    }

    @Test("the day confirmed runs to is the UTC day, in any time zone")
    func confirmedDayIsUTC() {
        // 2026-11-10T00:00:00Z, its last second, and the next day's first.
        let start = Date(timeIntervalSince1970: 1_794_268_800)
        let end = start.addingTimeInterval(86_399)
        let next = start.addingTimeInterval(86_400)
        // West of UTC the first would be the 9th; east, the second the 11th.
        #expect(Format.day(start) == Format.day(end))
        #expect(Format.day(start) != Format.day(next))
        #expect(Format.day(start).contains("10") && Format.day(next).contains("11"))
    }

    @Test("the HUD's chip labels its share as the total, or says why there is none")
    func chipShare() throws {
        let atlas = try Fixtures.world().instances[0].spending
        #expect(Format.share(atlas) == "total 28%")
        var noKernelLimit = atlas
        noKernelLimit.limitCents = nil
        #expect(Format.share(noKernelLimit) == "no kernel limit")
        #expect(Format.share(Spending(recordedLimitCents: 5000)) == "not read")
    }

    @Test("search says an instance's spending as its label does: both parts, or why not")
    func searchSaysSpending() throws {
        var world = try Worlds.liveFixture()
        world.instances[1].spending.limitCents = nil
        let model = model(world)
        let instances = model.search("instance").filter { if case .instance = $0.target { true } else { false } }
        let details = Dictionary(uniqueKeysWithValues: instances.map { ($0.title, $0.detail) })
        let atlas = try #require(details["atlas"])
        #expect(atlas == "instance · \(Format.spending(world.instances[0].spending))")
        #expect(atlas.contains("$29.00 confirmed through") && atlas.contains("$12.80 expected"))
        // Read, with no limit from the kernel: not "not read".
        let borealis = try #require(details["borealis"])
        #expect(borealis.contains("no kernel limit") && !borealis.contains("not read"))
    }

    @Test("a panel says not read for every section that was not read, never 0")
    func panelsSayNotRead() throws {
        let listed = Instance.notYetRead(Worlds.listing("a"))
        let model = model(World(instances: [listed], source: .live))
        for app in listed.groups[0].apps {
            let facts = try PanelFacts.of(model, app.id)
            #expect(!facts.isEmpty, "\(app.name)")
            // No count, and no state that was never seen.
            #expect(!facts.values.contains { Int($0) != nil || $0 == "not watching" || $0 == "none yet" || $0 == "not sealed" }, "\(app.name): \(facts)")
            #expect(try PanelFacts.note(model, app.id).contains("Not read yet."), "\(app.name)")
        }
        let kernel = try PanelFacts.of(model, "a/farcast-system/technocore")
        #expect(kernel["confirmed"] == "not read" && kernel["no confirmation yet"] == nil)
        #expect(kernel["apps stopped"] == "not read")
        #expect(kernel["recorded limit; the kernel's not read"] == "$50.00")

        // Read, but the network, the policy and the apps failed.
        var world = Worlds.slice("a", readAt: Date(timeIntervalSince1970: 1_794_477_600))
        world.instances[0].problems = [
            SectionProblem(section: .network, kind: .tunnelUnreachable, message: "dial tcp: i/o timeout"),
            SectionProblem(section: .policy, kind: .kubectlFailed, message: "forbidden"),
            SectionProblem(section: .apps, kind: .kubectlFailed, message: "forbidden"),
        ]
        model.update(world: world)
        let boundary = try PanelFacts.of(model, "a/farcast-system/fatline")
        #expect(["lines out, counted", "refused at the wall", "declared, never used", "devices coming in"].map { boundary[$0] }
            == Array(repeating: "not read", count: 4))
        #expect(try PanelFacts.of(model, "a/farcast-system/shrike") == ["Shrike's watch on FatLine": "not read"])
        #expect(try PanelFacts.of(model, "a/farcast-system/datasphere")["apps storing here"] == "not read")
        #expect(try PanelFacts.of(model, "a/farcast-system/technocore")["apps stopped"] == "not read")
        #expect(try PanelFacts.note(model, "a/farcast-system/fatline").contains("network not read (tunnel unreachable)"))

        // All read: figures, the confirmed one with its day.
        world.instances[0].problems = []
        model.update(world: world)
        let read = try PanelFacts.of(model, "a/farcast-system/technocore")
        #expect(read["apps stopped"] == "0")
        #expect(read["confirmed through \(Format.day(Date(timeIntervalSince1970: 1_794_355_200)))"] == "$5.00")
        #expect(try PanelFacts.of(model, "a/farcast-system/fatline")["lines out, counted"] == "1")
        #expect(try PanelFacts.of(model, "a/farcast-system/shrike")["lines watched"] == "1")
        #expect(try PanelFacts.of(model, "a/farcast-system/datasphere")["storage"] == "not sealed")
    }

    @Test("a keeper with no line is still the instance's keeper: unseen needs attention, unknown is not read")
    func keepersWithoutLines() throws {
        var world = Worlds.slice("a", readAt: Date(timeIntervalSince1970: 1_794_477_600))
        world.connections.removeAll { $0.kind == .keeper }
        world.devices[1].health = .unseen
        try world.validate()
        let model = model(world)
        var storage = try PanelFacts.of(model, "a/farcast-system/datasphere")
        #expect(storage["keepers"] == "1" && storage["keepers needing attention"] == "1")
        #expect(storage["keeper not read"] == nil)

        world.devices[1].health = .unknown
        model.update(world: world)
        storage = try PanelFacts.of(model, "a/farcast-system/datasphere")
        #expect(storage["keepers"] == "1" && storage["keepers needing attention"] == "0")
        #expect(storage["keeper not read"] == "1")
    }

    @Test("a keeper the CLI grades healthy needs no attention, though its line faded")
    func healthyKeeperWithStaleLine() throws {
        var world = Worlds.slice("a", readAt: Date(timeIntervalSince1970: 1_794_477_600))
        for i in world.connections.indices where world.connections[i].kind == .keeper {
            world.connections[i].isStale = true
        }
        let storage = try PanelFacts.of(model(world), "a/farcast-system/datasphere")
        #expect(storage["keepers"] == "1" && storage["keepers needing attention"] == "0")
    }

    @Test("the fixture's panels draw its figures whole: it is illustrative, not unread")
    func fixturePanels() throws {
        let model = model(try Fixtures.world())
        #expect(try PanelFacts.of(model, "borealis/farcast-system/technocore")["apps stopped"] == "1")
        #expect(try PanelFacts.of(model, "borealis/farcast-system/datasphere")["storage"] == "sealed")
        #expect(try PanelFacts.of(model, "borealis/farcast-system/datasphere")["keepers needing attention"] == "1")
        #expect(try PanelFacts.of(model, "atlas/farcast-system/datasphere")["apps storing here"] == "3")
        #expect(try PanelFacts.of(model, "atlas/farcast-system/fatline")["lines out, counted"] == "3")
        #expect(try !PanelFacts.note(model, "atlas/farcast-system/technocore").contains("Not read yet."))
    }

    @Test("states have labels, and only a running app is drawn in the running colour")
    func stateLabels() {
        #expect(AppState.allCases.map(\.label) == ["running", "stopped", "starting", "not deployed", "unknown"])
        #expect(AppState.allCases.filter { Theme.state($0) == Theme.running } == [.running])
        #expect(AppState.allCases.filter { !Theme.stateDash($0).isEmpty } == [.unknown])
        #expect(AppState.allCases.filter(\.isDormant) == [.stopped, .notDeployed])
    }

    @Test("a refused line has a dash of its own, so it reads without its colour")
    func deniedDash() {
        for kind in Connection.Kind.allCases {
            for evidence in Connection.Evidence.allCases {
                let style = EdgeStyle(Connection(id: "c", from: .app("a"), to: .app("b"), kind: kind, evidence: evidence, label: ""))
                #expect((style.dash == [2, 3]) == (evidence == .denied), "\(kind) \(evidence)")
            }
        }
        #expect(EdgeStyle.deniedDash == [2, 3])
    }

    @Test("a keeper not read is drawn as not read, not as unhealthy")
    func keeperNotRead() {
        let keeper = Connection(id: "k", from: .device("k"), to: .app("s"), kind: .keeper, evidence: .observed, label: "")
        #expect(EdgeStyle(keeper, health: .unknown).color == Theme.secondaryText)
        #expect(EdgeStyle(keeper, health: .expired).color == Theme.warning)
        #expect(EdgeStyle(keeper, health: .healthy).color == Theme.keeper)
        #expect(Theme.device(Device(id: "k", name: "k", role: .keeper, note: "", health: .unknown)) == Theme.secondaryText)
        #expect(Theme.device(Device(id: "m", name: "m", role: .operator, note: "")) == Theme.focus)
    }

    @Test("what an instance names is escaped where it is drawn, and its ids are not")
    func namesAreEscaped() throws {
        var world = try Worlds.liveFixture()
        world.instances[0].groups[1].apps[0].name = "notes\u{202E}txt"
        world.instances[0].groups[1].source = "github.com/example\u{1B}[2J/home"
        let model = model(world)
        let titles = model.search("").map(\.title)
        #expect(titles.contains("notes\\u202etxt"))
        #expect(model.search("home").contains { $0.detail.contains("github.com/example\\x1b[2J/home") })
        #expect(model.index.apps["atlas/home/notes"] != nil)
    }
}
