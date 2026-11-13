import Foundation
import SwiftUI
import Testing
@testable import FarSightUI
import FarSightCore

/// What FarCast's own panels and an instance's chip say after a read that
/// failed in part, as the Phase 7 rehearsal found them wanting (F1–F5, F8):
/// Shrike's watch from its evidence, one sentence a failed section and never
/// the CLI's message, the chip in brief, counts in the singular for one, and
/// the figures whole at the smallest panel drawn whole.
@Suite("Panel wording")
struct PanelWordingTests {
    static let readAt = Date(timeIntervalSince1970: 1_794_477_600)
    static let raw = "kubectl get deployments -n farcast-system -o json: ERROR: (gcloud.auth) RAW-CLI-MESSAGE"
    let system = "a/farcast-system"

    func model(_ world: World) -> WorldModel {
        let model = WorldModel(world: world, store: nil)
        model.viewportChanged(to: CGSize(width: 1440, height: 900))
        return model
    }

    func read(_ problems: [SectionProblem] = [], _ edit: (inout World) -> Void = { _ in }) -> World {
        var world = Worlds.slice("a", readAt: Self.readAt)
        world.instances[0].problems = problems
        edit(&world)
        return world
    }

    func signedOut(_ section: SectionProblem.Section) -> SectionProblem {
        SectionProblem(section: section, kind: .gcloudSignedOut, message: Self.raw)
    }

    func setShrike(_ state: AppState, in world: inout World) {
        let i = world.instances[0].groups[0].apps.firstIndex { $0.system == .monitor }!
        world.instances[0].groups[0].apps[i].state = state
    }

    // MARK: - F1: Shrike's watch, from its evidence

    @Test("a current watch the read observed is the evidence: Shrike watches, though the apps section failed")
    func watchIsEvidence() throws {
        let world = read([signedOut(.apps)]) { setShrike(.unknown, in: &$0) }
        let facts = try PanelFacts.of(model(world), "\(system)/shrike")
        #expect(facts["line watched"] == "1" && facts["refusals seen"] == "0")
        #expect(!facts.values.contains("not watching") && !facts.values.contains("not read"))
    }

    @Test("with no watch and its state not read, Shrike is not read, never not watching")
    func noEvidenceIsNotRead() throws {
        let world = read([signedOut(.apps)]) { world in
            setShrike(.unknown, in: &world)
            world.connections.removeAll { $0.kind == .watch }
        }
        let model = model(world)
        #expect(try PanelFacts.of(model, "\(system)/shrike") == ["Shrike's watch on FatLine": "not read"])
        #expect(try PanelFacts.note(model, "\(system)/shrike").contains("apps not read · signed out of gcloud — run gcloud auth login"))

        // A watch that faded is no evidence either.
        var stale = world
        stale.connections.append(Connection(
            id: "a/watch", from: .app("\(system)/shrike"), to: .app("\(system)/fatline"),
            kind: .watch, evidence: .observed, label: "watches", isStale: true
        ))
        #expect(try PanelFacts.of(self.model(stale), "\(system)/shrike") == ["Shrike's watch on FatLine": "not read"])
    }

    @Test("the CLI's own vector, apps failed and network read, says Shrike watches, through the real adapter")
    func watchFromTheVector() throws {
        let world = try RenderHarness.vector("account_in_message")
        let model = model(world)
        let shrike = try #require(model.index.apps["atlas/farcast-system/shrike"])
        #expect(shrike.state == .running)
        let facts = try PanelFacts.of(model, "atlas/farcast-system/shrike")
        #expect(facts["line watched"] == "1" && facts["refusals seen"] == "0")
        #expect(!facts.values.contains("not watching") && !facts.values.contains("not read"))
    }

    @Test("with its state read and no watch, Shrike is not watching")
    func readStateWithoutWatch() throws {
        let world = read { $0.connections.removeAll { $0.kind == .watch } }
        #expect(try PanelFacts.of(model(world), "\(system)/shrike")["no current watch on FatLine in the snapshot"] == "not watching")
    }

    // MARK: - F3, F5: one sentence a section, never the CLI's message

    @Test("each panel says its own failed sections in one sentence each, and none repeats the CLI's message")
    func sentencesNotMessages() throws {
        let model = model(read([signedOut(.spend), signedOut(.apps), signedOut(.policy)]))
        let notes = try ["technocore", "fatline", "datasphere", "shrike"].map { try PanelFacts.note(model, "\(system)/\($0)") }
        #expect(!notes.contains { $0.contains("RAW-CLI-MESSAGE") || $0.contains("kubectl get") })
        let kernel = try #require(model.index.apps["\(system)/technocore"])
        #expect(SystemSummary(app: kernel, model: model).problems == [
            "spending not read · signed out of gcloud — run gcloud auth login",
            "apps not read · signed out of gcloud — run gcloud auth login",
        ])
        #expect(notes[1].hasPrefix("egress policy not read · signed out of gcloud — run gcloud auth login\n"))
        #expect(!notes[1].contains("spending not read"))
        #expect(notes[2].hasPrefix("apps not read · signed out of gcloud"))
        // Shrike's watch was read: nothing failed that is its.
        let shrike = try #require(model.index.apps["\(system)/shrike"])
        #expect(SystemSummary(app: shrike, model: model).problems.isEmpty)
    }

    @Test("a refused read says it was refused, in every panel, and never 'read not read'")
    func refusedRead() throws {
        let refused = SectionProblem(section: .read, kind: .gcloudMismatch, message: Self.raw)
        let model = model(read([refused]))
        for component in ["technocore", "fatline", "datasphere", "shrike"] {
            let note = try PanelFacts.note(model, "\(system)/\(component)")
            #expect(note.components(separatedBy: "the read was refused · gcloud identity does not match — farcast instances pin-gcloud").count == 2, "\(component)")
            #expect(!note.contains("read not read") && !note.contains("RAW-CLI-MESSAGE"), "\(component)")
        }
    }

    @Test("a section that failed twice the same way is said once")
    func saidOnce() throws {
        let model = model(read([
            SectionProblem(section: .spend, kind: .internal, message: "expected spending is not one: -1 cents"),
            SectionProblem(section: .spend, kind: .internal, message: "total spending is not one: -1 cents"),
        ]))
        let kernel = try #require(model.index.apps["\(system)/technocore"])
        #expect(SystemSummary(app: kernel, model: model).problems == ["spending not read · internal error"])
    }

    @Test("a spending figure the map cannot draw says so, never that spending was not read")
    func figureNotDrawn() throws {
        let model = model(read([
            SectionProblem(section: .figures, kind: .internal, message: "expected spending is not one: -1 cents"),
            SectionProblem(section: .figures, kind: .internal, message: "total spending is not one: -1 cents"),
        ]))
        let kernel = try #require(model.index.apps["\(system)/technocore"])
        #expect(SystemSummary(app: kernel, model: model).problems == ["spending figure not drawn · out of range"])
        #expect(!(try PanelFacts.note(model, "\(system)/technocore")).contains("spending not read"))
        let fatline = try #require(model.index.apps["\(system)/fatline"])
        #expect(SystemSummary(app: fatline, model: model).problems.isEmpty)
    }

    // MARK: - F5: counts

    @Test("a count of one is singular on every panel; any other count is plural")
    func counts() throws {
        let one = model(read { world in
            world.instances[0].groups[1].apps[0].state = .stopped
            world.connections.append(Connection(
                id: "a/refused", from: .app("a/web/site"), to: .host("a/api.example.test"),
                kind: .egress, evidence: .denied, label: "≥2 refused", count: 2
            ))
        })
        let kernel = try PanelFacts.of(one, "\(system)/technocore")
        #expect(kernel["app stopped"] == "1" && kernel["apps stopped"] == nil)
        let boundary = try PanelFacts.of(one, "\(system)/fatline")
        #expect(boundary["line out, counted"] == "1" && boundary["refused at the wall"] == "1")
        #expect(try PanelFacts.of(one, "\(system)/shrike")["refusal seen"] == "1")
        let storage = try PanelFacts.of(one, "\(system)/datasphere")
        #expect(storage["keeper"] == "1" && storage["keepers needing attention"] == "0")

        let two = model(read { world in
            world.instances[0].groups[1].apps[0].state = .stopped
            world.instances[0].groups[1].apps.append(Application(id: "a/web/worker", name: "worker", role: "", state: .stopped))
            world.devices.append(Device(id: "a/tablet", name: "tablet", role: .keeper, note: "keeper", health: .unseen))
        })
        #expect(try PanelFacts.of(two, "\(system)/technocore")["apps stopped"] == "2")
        #expect(try PanelFacts.of(two, "\(system)/shrike")["refusals seen"] == "0")
        let both = try PanelFacts.of(two, "\(system)/datasphere")
        #expect(both["keepers"] == "2" && both["keeper needing attention"] == "1")
    }

    @Test("TechnoCore counts applications stopped, never FarCast's own components, and Shrike's unread state leaves the count")
    func stoppedCountsApplicationsOnly() throws {
        // The tunnel down: Shrike's state is not read, the apps section is.
        let down = model(read([
            SectionProblem(section: .network, kind: .tunnelUnreachable, message: "x"),
            SectionProblem(section: .seal, kind: .tunnelUnreachable, message: "x"),
        ]) { setShrike(.unknown, in: &$0) })
        #expect(try PanelFacts.of(down, "\(system)/technocore")["apps stopped"] == "0")
        #expect(SystemSummary(app: try #require(down.index.apps["\(system)/technocore"]), model: down).problems.isEmpty)
        // FatLine scaled to zero is no application stopped.
        let fatlineStopped = read { world in
            let i = world.instances[0].groups[0].apps.firstIndex { $0.system == .boundary }!
            world.instances[0].groups[0].apps[i].state = .stopped
        }
        #expect(try PanelFacts.of(model(fatlineStopped), "\(system)/technocore")["apps stopped"] == "0")
        // An application whose state was not read still leaves the count unread.
        let unknownApp = read { $0.instances[0].groups[1].apps[0].state = .unknown }
        #expect(try PanelFacts.of(model(unknownApp), "\(system)/technocore")["apps stopped"] == "not read")
    }

    @Test("keepers needing attention: not read where no keeper's health was read, and of those read where some were")
    func keepersNeedingAttention() throws {
        let none = read { world in
            for i in world.devices.indices where world.devices[i].role == .keeper { world.devices[i].health = .unknown }
        }
        let unread = try PanelFacts.of(model(none), "\(system)/datasphere")
        #expect(unread["keepers needing attention"] == "not read" && unread["keeper not read"] == "1")
        let some = read { world in
            world.devices.append(Device(id: "a/tablet", name: "tablet", role: .keeper, note: "keeper", health: .unknown))
        }
        let part = try PanelFacts.of(model(some), "\(system)/datasphere")
        #expect(part["keepers needing attention, of those read"] == "0" && part["keepers needing attention"] == nil)
        #expect(part["keeper not read"] == "1" && part["keepers"] == "2")
    }

    // MARK: - F8: a declaration's use

    @Test("a declared line is never used only where the network was read; unread, its use was not read")
    func declaredUse() throws {
        func world(_ problems: [SectionProblem]) -> World {
            read(problems) { world in
                world.connections.append(Connection(
                    id: "a/declared", from: .app("a/web/site"), to: .host("a/api.example.test"),
                    kind: .egress, evidence: .declared, label: "declared · unused"
                ))
            }
        }
        #expect(try PanelFacts.of(model(world([])), "\(system)/fatline")["declared, never used"] == "1")
        let unread = try PanelFacts.of(model(world([SectionProblem(section: .network, kind: .tunnelUnreachable, message: "x")])), "\(system)/fatline")
        #expect(unread["declared, use not read"] == "1" && unread["declared, never used"] == nil)
        let noPolicy = try PanelFacts.of(model(world([SectionProblem(section: .policy, kind: .kubectlFailed, message: "x")])), "\(system)/fatline")
        #expect(noPolicy["declared, never used"] == "not read")
    }

    @Test("with neither the policy nor the network read, the declared figure claims no use either way")
    func declaredUseNothingRead() throws {
        let world = read([
            SectionProblem(section: .policy, kind: .gcloudSignedOut, message: "x"),
            SectionProblem(section: .network, kind: .tunnelUnreachable, message: "x"),
        ])
        let facts = try PanelFacts.of(model(world), "\(system)/fatline")
        #expect(facts["declared, use not read"] == "not read" && facts["declared, never used"] == nil)
    }

    // MARK: - F4: the chip

    @Test("the chip summarises what failed: counted, with why, never one entry a section")
    func chipSummary() {
        let time = "read \(Format.time(Self.readAt))"
        let signed = read([signedOut(.spend), signedOut(.apps), signedOut(.policy)]).instances[0]
        #expect(Format.readState(signed) == "\(time) · 3 sections not read · signed out of gcloud")
        #expect(Format.readState(signed, brief: true) == "3 sections not read · signed out of gcloud")
        let refused = read([SectionProblem(section: .read, kind: .gcloudMismatch, message: Self.raw)]).instances[0]
        #expect(Format.readState(refused) == "\(time) · read refused · gcloud identity does not match")
        let healthy = read().instances[0]
        #expect(Format.readState(healthy) == time)
        #expect(Format.readState(healthy, brief: true) == nil)
        var released = healthy
        released.status = .deleting
        #expect(Format.readState(released, brief: true) == "release incomplete, may still be billing")
    }

    @Test("what failed outlives the spending on a narrow chip, and is said at its shortest before the name stands alone")
    func chipVariants() throws {
        let refused = read([SectionProblem(section: .read, kind: .gcloudMismatch, message: Self.raw)]).instances[0]
        let variants = TerritoryLabel.variants(refused, showsReadState: true)
        let time = "read \(Format.time(Self.readAt))"
        #expect(variants.map(\.readState) == [
            "\(time) · read refused · gcloud identity does not match",
            "\(time) · read refused · gcloud identity does not match",
            "read refused · gcloud identity does not match",
            "read refused · gcloud identity does not match",
            "read refused",
            nil,
        ])
        #expect(variants.map { $0.spending == nil } == [false, false, false, true, true, true])
        #expect(variants.map(\.truncates) == [false, false, false, false, false, true])
        // Nothing failed: the share goes last, before the name.
        let healthy = TerritoryLabel.variants(read().instances[0], showsReadState: true)
        #expect(healthy.map(\.readState) == [time, time, nil, nil])
        #expect(healthy.map { $0.spending == nil } == [false, false, false, true])
        // The fixture says no read state at all.
        #expect(TerritoryLabel.variants(read().instances[0], showsReadState: false).map(\.readState) == [nil, nil, nil])
        #expect(Format.readHeadline(read([signedOut(.spend), signedOut(.apps)]).instances[0]) == "2 sections not read")
        #expect(Format.readHeadline(read().instances[0]) == nil)
    }

    @Test("in a 540-point band the refused chip still says the read was refused, and the name alone never runs past its band")
    func chipFitsItsBand() throws {
        var world = Worlds.slice("rehearsal", readAt: Self.readAt)
        world.instances[0].problems = [SectionProblem(section: .read, kind: .gcloudMismatch, message: Self.raw)]
        let model = model(world)
        let instance = model.world.instances[0]
        let scale = try #require(model.fitted(.group("rehearsal/farcast-system"))).scale
        let label = TerritoryLabel(instance: instance, rect: CGRect(x: 0, y: 0, width: 620, height: 56), scale: scale, showsReadState: true) {}
        let size = TerritoryLabel.size(at: scale)
        func width(_ variant: TerritoryLabel.Variant, proposed: CGFloat? = nil) throws -> CGFloat {
            let renderer = ImageRenderer(content: label.chip(size: size, variant))
            renderer.scale = 1
            renderer.proposedSize = ProposedViewSize(width: proposed, height: nil)
            return CGFloat(try #require(renderer.cgImage).width)
        }
        // What ViewThatFits picks: the first variant at its own width that fits.
        var chosen: TerritoryLabel.Variant?
        for variant in TerritoryLabel.variants(instance, showsReadState: true) {
            if try width(variant) <= 540 {
                chosen = variant
                break
            }
        }
        #expect(chosen?.readState?.contains("read refused") == true, "\(String(describing: chosen))")
        // The last, proposed less than its name needs, cuts the name and
        // stays within what it was given.
        let last = try #require(TerritoryLabel.variants(instance, showsReadState: true).last)
        let whole = try width(last), cut = try width(last, proposed: 120)
        #expect(whole > 120)
        // A whole pixel at most for the image's rounding up.
        #expect(cut <= 121, "\(cut) of \(whole)")
    }

    @Test("a share at the floor, or from a stale checkpoint, says so")
    func shareSaysStaleAndFloor() {
        var spending = read().instances[0].spending
        #expect(Format.share(spending) == "total 30%")
        spending.isCheckpointStale = true
        #expect(Format.share(spending) == "total 30% · stale")
        spending.floor = SpendingFloor(since: Self.readAt, stillBurningMonthCents: 5703, levers: [])
        #expect(Format.share(spending) == "total 30% · at the floor · stale")
    }

    @Test("the chip stands in the part of its band that is on screen")
    func chipBand() {
        let visible = CGRect(x: 8, y: 0, width: 1424, height: 900)
        // Running off the right edge, and off the left.
        #expect(TerritoryLabel.band(CGRect(x: 600, y: 40, width: 2000, height: 50), within: visible)
            == CGRect(x: 600, y: 40, width: 832, height: 50))
        #expect(TerritoryLabel.band(CGRect(x: -900, y: 40, width: 1200, height: 50), within: visible)
            == CGRect(x: 8, y: 40, width: 292, height: 50))
        // Only its width is cut: a band above the screen keeps its place.
        #expect(TerritoryLabel.band(CGRect(x: 100, y: -80, width: 300, height: 50), within: visible)
            == CGRect(x: 100, y: -80, width: 300, height: 50))
        // None of it on screen: the band as it is.
        let away = CGRect(x: 2000, y: 40, width: 300, height: 50)
        #expect(TerritoryLabel.band(away, within: visible) == away)
    }

    @Test("the chip's disclosure says each message once, under every sentence it explains")
    func disclosureGroups() {
        let problems = [signedOut(.spend), signedOut(.apps), SectionProblem(section: .network, kind: .tunnelUnreachable, message: "dial tcp: i/o timeout"), signedOut(.policy)]
        let groups = ReadDetailsContent.groups(problems)
        #expect(groups.map(\.message) == [Self.raw, "dial tcp: i/o timeout"])
        #expect(groups[0].sentences.count == 3 && groups[1].sentences == ["network not read · tunnel unreachable"])
        let image = ImageRenderer(content: ReadDetailsContent(instance: read(problems).instances[0]).frame(width: 460)).cgImage
        #expect(image != nil)
    }

    // MARK: - F2: the figures whole

    @Test("no screen draws a panel whole narrower than the least width, and a Mac window no smaller than its minimum draws a focused app whole")
    func leastWholeWidth() throws {
        // As figuresFit's: TechnoCore with every figure it can have.
        var world = read([signedOut(.policy)])
        world.instances[0].spending = Spending(
            expectedCents: 1805, confirmedCents: 464, totalCents: 2269, limitCents: 2000, recordedLimitCents: 2000,
            hasConfirmation: true, confirmedThrough: Self.readAt, level: .reached,
            notMetered: ["data through the carrier", "bucket storage and operations"], atFloor: true,
            floor: SpendingFloor(since: Self.readAt, stillBurningMonthCents: 5703, levers: ["drop the load-balancer carrier", "release the instance"])
        )
        world.devices.append(Device(id: "a/tablet", name: "tablet", role: .keeper, note: "keeper", health: .unknown))
        // A Mac window at its minimum, with the HUD's regular insets: a
        // focused app is drawn wider than the least, so whole.
        let mac = WorldModel(world: world, store: nil)
        mac.viewportChanged(to: WorldScreen.minimumWindow)
        #expect(mac.focusedPanelWidth * 0.95 >= WorldModel.leastFullPanelWidth)
        #expect(mac.fullPanelWidth <= mac.focusedPanelWidth)
        // A window smaller than any phone: never whole below the least.
        let tiny = WorldModel(world: world, store: nil)
        tiny.layoutChanged(compact: true)
        tiny.viewportChanged(to: CGSize(width: 320, height: 300))
        #expect(tiny.fullPanelWidth == WorldModel.leastFullPanelWidth)
        // At the least width itself, every figure stays whole.
        let unit = WorldModel.leastFullPanelWidth / Metrics.panel.width
        let surface = CGSize(width: Metrics.panel.width * unit, height: Metrics.panel.height * unit - AppPanel.titleBarHeight)
        let style = SurfaceStyle(unit: unit)
        let inner = CGSize(width: surface.width - 2 * style.padding, height: surface.height - 2 * style.padding)
        let model = model(world)
        for component in ["technocore", "fatline", "datasphere", "shrike"] {
            let app = try #require(model.index.apps["\(system)/\(component)"])
            let renderer = ImageRenderer(content: SurfaceTop(title: app.role, summary: SystemSummary(app: app, model: model), style: style.tight, columns: 3))
            renderer.proposedSize = ProposedViewSize(width: inner.width, height: nil)
            let top = CGFloat(try #require(renderer.cgImage).height)
            #expect(top + style.tight.gap + SurfaceNote.least(style.tight) <= inner.height, "\(component): \(top) of \(inner.height)")
        }
    }

    @Test("VoiceOver hears every figure and every word of a FarCast panel, what its 'more' opens included")
    func spokenSurface() throws {
        var world = read([signedOut(.apps)])
        world.instances[0].spending.notMetered = ["data through the carrier", "bucket storage and operations"]
        let model = model(world)
        let kernel = try #require(model.index.apps["\(system)/technocore"])
        let summary = SystemSummary(app: kernel, model: model)
        let spoken = summary.spoken
        for fact in summary.facts {
            #expect(spoken.contains("\(fact.value) \(fact.label)"), "\(fact.label)")
        }
        #expect(spoken.contains("apps not read · signed out of gcloud — run gcloud auth login"))
        #expect(spoken.contains("Not metered: data through the carrier; bucket storage and operations."))
        #expect(spoken.hasSuffix(summary.text))
    }

    @Test("at the smallest a panel is drawn whole, a phone on its side, the tightest arrangement leaves every figure whole and room for the notes")
    func figuresFit() throws {
        var world = read([signedOut(.policy)])
        world.instances[0].spending = Spending(
            expectedCents: 1805, confirmedCents: 464, totalCents: 2269, limitCents: 2000, recordedLimitCents: 2000,
            hasConfirmation: true, confirmedThrough: Self.readAt, level: .reached,
            notMetered: ["data through the carrier", "bucket storage and operations"], atFloor: true,
            floor: SpendingFloor(since: Self.readAt, stillBurningMonthCents: 5703, levers: ["drop the load-balancer carrier", "release the instance"])
        )
        world.devices.append(Device(id: "a/tablet", name: "tablet", role: .keeper, note: "keeper", health: .unknown))
        let model = WorldModel(world: world, store: nil)
        model.layoutChanged(compact: true, short: true)
        model.viewportChanged(to: CGSize(width: 667, height: 375))
        let unit = model.fullPanelWidth / Metrics.panel.width
        #expect(unit > 0.2 && unit < 0.3)
        let surface = CGSize(width: Metrics.panel.width * unit, height: Metrics.panel.height * unit - AppPanel.titleBarHeight)
        let style = SurfaceStyle(unit: unit)
        let inner = CGSize(width: surface.width - 2 * style.padding, height: surface.height - 2 * style.padding)

        for component in ["technocore", "fatline", "datasphere", "shrike"] {
            let app = try #require(model.index.apps["\(system)/\(component)"])
            let summary = SystemSummary(app: app, model: model)
            let renderer = ImageRenderer(content: SurfaceTop(title: app.role, summary: summary, style: style.tight, columns: 3))
            renderer.proposedSize = ProposedViewSize(width: inner.width, height: nil)
            let top = CGFloat(try #require(renderer.cgImage).height)
            #expect(top + style.tight.gap + SurfaceNote.least(style.tight) <= inner.height, "\(component): \(top) of \(inner.height)")
            // And the whole surface draws there.
            let whole = ImageRenderer(content: SystemSurface(app: app, model: model, unit: unit).frame(width: surface.width, height: surface.height))
            #expect(whole.cgImage != nil)
        }
    }
}
