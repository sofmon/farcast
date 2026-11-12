import Foundation
import SwiftUI
import Testing
@testable import FarSightUI
import FarSightCore
import FarSightFixtures

@Suite("The world on screen")
struct WorldModelTests {
    let viewport = CGSize(width: 1440, height: 900)

    func model(store: ArrangementStore? = nil) throws -> WorldModel {
        let model = WorldModel(world: try Fixtures.world(), store: store)
        model.viewportChanged(to: viewport)
        return model
    }

    @Test("the first frame shows the whole world")
    func firstFrame() throws {
        let model = try model()
        let visible = model.camera.visibleWorld(in: viewport)
        #expect(visible.contains(model.geometry.bounds))
    }

    @Test("focusing an app flies to it and lifts it")
    func focusing() throws {
        let model = try model()
        model.focus(on: "atlas/home/photos")
        #expect(model.focus == "atlas/home/photos")
        #expect(model.flight != nil)
        let panel = model.camera.screen(model.geometry.apps["atlas/home/photos"]!, in: viewport)
        #expect(CGRect(origin: .zero, size: viewport).contains(panel))
        #expect(model.liveApps(at: model.camera).contains("atlas/home/photos"))
        #expect(model.currentInstanceID == "atlas")
    }

    @Test("Esc backs out from an app to its instance, then closes nothing more")
    func escaping() throws {
        let model = try model()
        model.focus(on: "borealis/lab/wiki")
        model.escape()
        #expect(model.focus == nil)
        #expect(model.camera == model.fitted(.instance("borealis")))
        model.isPalettePresented = true
        model.escape()
        #expect(!model.isPalettePresented)
    }

    @Test("alerts come critical first, and Space walks through them")
    func alerts() throws {
        let model = try model()
        #expect(model.alerts.map(\.severity) == [.critical, .critical, .warning])
        model.openNextAlert()
        #expect(model.focus == model.alerts[0].appID)
        model.openNextAlert()
        model.openNextAlert()
        model.openNextAlert()
        #expect(model.focus == model.alerts[0].appID)
    }

    @Test("dragging a group moves its apps, and the arrangement is kept")
    func dragging() throws {
        let suite = "farsight.tests.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let world = try Fixtures.world()
        let store = ArrangementStore(defaults: defaults)

        let model = WorldModel(world: world, store: store)
        model.viewportChanged(to: viewport)
        let before = model.geometry.apps["atlas/home/notes"]!
        let scale = model.camera.scale
        // Take home by its header and drag it 300 world units right.
        let grab = model.camera.screen(model.geometry.groups["atlas/home"]!.header.origin, in: viewport)
        let point = CGPoint(x: grab.x + 10, y: grab.y + 5)
        #expect(model.beginMove(.group("atlas/home"), at: point))
        model.move(.group("atlas/home"), to: CGPoint(x: point.x + 100 * scale, y: point.y))
        model.move(.group("atlas/home"), to: CGPoint(x: point.x + 300 * scale, y: point.y))
        model.endMove(.group("atlas/home"))
        let after = model.geometry.apps["atlas/home/notes"]!
        #expect(abs(after.minX - before.minX - 300) <= Metrics.snap)
        #expect(after.minY == before.minY)

        let reopened = WorldModel(world: world, store: store)
        #expect(reopened.geometry.apps["atlas/home/notes"] == after)
        reopened.resetArrangement()
        #expect(reopened.geometry.apps["atlas/home/notes"] == before)
        #expect(WorldModel(world: world, store: store).geometry.apps["atlas/home/notes"] == before)
    }

    @Test("a pinch zooms about where it started, even as the map moves under it")
    func pinching() throws {
        let model = try model()
        let anchor = CGPoint(x: 400, y: 300)
        let pinned = model.camera.world(anchor, in: viewport)
        model.magnifyChanged(1.5, at: anchor)
        model.magnifyChanged(3, at: CGPoint(x: 999, y: 999))
        model.magnifyEnded()
        let after = model.camera.screen(pinned, in: viewport)
        #expect(abs(after.x - anchor.x) < 0.001 && abs(after.y - anchor.y) < 0.001)
    }

    @Test("a fling coasts; a placed drag does not")
    func panning() throws {
        let model = try model()
        model.panChanged(CGSize(width: 50, height: 0))
        model.panEnded(CGSize(width: 50, height: 0), predicted: CGSize(width: 52, height: 0))
        #expect(model.flight == nil)
        model.panChanged(CGSize(width: 50, height: 0))
        model.panEnded(CGSize(width: 50, height: 0), predicted: CGSize(width: 400, height: 0))
        #expect(model.flight?.path.style == .glide)
    }

    @Test("the palette finds apps, repos and instances by any word")
    func searching() throws {
        let model = try model()
        #expect(model.search("pho").map(\.title) == ["photos"])
        #expect(model.search("borealis wiki").map(\.title) == ["wiki"])
        #expect(model.search("forge").contains { $0.target == .group("atlas/dev") })
        #expect(model.search("").allSatisfy { if case .app = $0.target { true } else { false } })
        #expect(model.search("nothing-is-called-this").isEmpty)
    }

    @Test("hosts are toned by what reached them")
    func hostTones() throws {
        let model = try model()
        #expect(model.hostTones["maps"] == .used)
        #expect(model.hostTones["cdn"] == .declared)
        #expect(model.hostTones["tracker"] == .refused)
        #expect(model.hostTones["pay"] == .planned)
    }

    @Test("money reads the way the HUD says it")
    func money() {
        #expect(Format.dollars(4180) == "$41.80")
        #expect(Format.dollars(5) == "$0.05")
        #expect(Format.dollars(-1250) == "-$12.50")
        #expect(Format.dollars(Int.min) == "-$92233720368547758.08")
        #expect(Format.percent(0.92) == "92%")
        #expect(Format.percent(1e300) == "99999%")
        #expect(Format.percent(.nan) == "–")
    }

    @Test("a drop that would put one instance in another's rows is refused")
    func refusedDrop() throws {
        let model = try model()
        let before = model.arrangement
        let point = CGPoint(x: 700, y: 300)
        #expect(model.beginMove(.group("atlas/home"), at: point))
        // Far down, into borealis.
        model.move(.group("atlas/home"), to: CGPoint(x: point.x, y: point.y + 4800 * model.camera.scale))
        #expect(model.arrangement.hasConflicts(for: model.world))
        model.endMove(.group("atlas/home"))
        #expect(model.arrangement == before)
    }

    @Test("a dragged item stays under the pointer while the camera zooms")
    func moveUnderZoom() throws {
        let model = try model()
        let point = CGPoint(x: 700, y: 300)
        #expect(model.beginMove(.group("atlas/home"), at: point))
        let held = model.camera.world(point, in: viewport)
        let origin = model.position(of: .group("atlas/home"))
        _ = model.scrolled(by: CGSize(width: 0, height: 20), at: CGPoint(x: 100, y: 100), precise: false, zoom: true)
        model.move(.group("atlas/home"), to: point)
        let now = model.camera.world(point, in: viewport)
        let moved = model.position(of: .group("atlas/home"))
        #expect(abs((moved.x - origin.x) - (now.x - held.x)) <= Metrics.snap)
        #expect(abs((moved.y - origin.y) - (now.y - held.y)) <= Metrics.snap)
        model.endMove(.group("atlas/home"))
    }

    @Test("a pinch is not a drag: a move it catches goes back, and none starts during one")
    func pinchCancelsMove() throws {
        let model = try model()
        let before = model.arrangement
        let point = CGPoint(x: 700, y: 300)
        #expect(model.beginMove(.group("atlas/home"), at: point))
        model.move(.group("atlas/home"), to: CGPoint(x: point.x + 200, y: point.y))
        model.magnifyChanged(1.4, at: point)
        #expect(model.arrangement == before)
        #expect(!model.beginMove(.group("atlas/dev"), at: point))
        model.magnifyEnded()
        model.endMove(.group("atlas/home"))
        #expect(model.arrangement == before)
    }

    @Test("a fresh pan moves from its first event")
    func freshPan() throws {
        let model = try model()
        let start = model.camera
        model.panChanged(CGSize(width: 12, height: 0))
        #expect(abs(model.camera.center.x - (start.center.x - 12 / start.scale)) < 0.001)
    }

    @Test("a flight started mid-pan wins, and the pan resumes without a jump")
    func flightDuringPan() throws {
        let model = try model()
        model.panChanged(CGSize(width: 10, height: 0))
        model.focus(on: "atlas/home/photos")
        let goal = model.camera
        model.panChanged(CGSize(width: 40, height: 0))
        #expect(model.camera == goal)
    }

    @Test("a pan that resumes after a pinch does not jump")
    func panAfterPinch() throws {
        let model = try model()
        model.panChanged(CGSize(width: 20, height: 0))
        model.magnifyChanged(1.5, at: CGPoint(x: 700, y: 450))
        model.panChanged(CGSize(width: 140, height: 60))  // the fingers' centroid moved during the pinch
        model.magnifyEnded()
        let afterPinch = model.camera
        // One finger lifted; the other drags on. The first event re-anchors
        // where the camera is, the next moves it by just the 10 points between.
        model.panChanged(CGSize(width: 150, height: 60))
        #expect(model.camera == afterPinch)
        model.panChanged(CGSize(width: 160, height: 60))
        #expect(abs(model.camera.center.x - (afterPinch.center.x - 10 / afterPinch.scale)) < 0.001)
        #expect(abs(model.camera.center.y - afterPinch.center.y) < 0.001)
    }

    @Test("a cancelled pan or pinch leaves nothing anchored")
    func cancelling() throws {
        let model = try model()
        model.magnifyChanged(2, at: .zero)
        model.magnifyEnded()  // what a cancelled pinch's reset calls
        model.panChanged(CGSize(width: 30, height: 0))
        let moved = model.camera
        model.panCancelled()
        // A new pan anchors afresh where the camera is, not at the old pan's start.
        model.panChanged(CGSize(width: 5, height: 0))
        #expect(model.camera == moved.panned(by: CGSize(width: 5, height: 0)))
    }

    @Test("a scroll over the HUD is the HUD's")
    func scrollingOverTheHUD() throws {
        let model = try model()
        model.viewportFrame = CGRect(x: 0, y: 0, width: 1440, height: 900)
        model.hudRegions["app strip"] = CGRect(x: 400, y: 820, width: 600, height: 60)
        let camera = model.camera
        #expect(!model.scrolled(by: CGSize(width: 0, height: 10), at: CGPoint(x: 500, y: 850), precise: true, zoom: false))
        #expect(model.camera == camera)
        #expect(model.scrolled(by: CGSize(width: 0, height: 10), at: CGPoint(x: 500, y: 400), precise: true, zoom: false))
        #expect(model.camera != camera)
    }

    @Test("Space goes to the alert after the one last opened, however it was opened")
    func alertCursor() throws {
        let model = try model()
        model.open(model.alerts[1])
        model.openNextAlert()
        #expect(model.focus == model.alerts[2].appID)
    }

    @Test("on a phone, a focused app is drawn full and can be live")
    func narrowViewport() throws {
        let model = WorldModel(world: try Fixtures.world())
        model.layoutChanged(compact: true)
        let phone = CGSize(width: 390, height: 844)
        model.viewportChanged(to: phone)
        model.show(.app("atlas/home/photos"))
        model.focus = "atlas/home/photos"
        let drawn = model.camera.screen(model.geometry.apps["atlas/home/photos"]!, in: phone)
        #expect(drawn.width >= model.fullPanelWidth)
        #expect(model.liveApps(at: model.camera).contains("atlas/home/photos"))
    }

    @Test("a scroll mid-pan stands: the pan resumes from it without undoing it")
    func scrollDuringPan() throws {
        let model = try model()
        model.viewportFrame = CGRect(origin: .zero, size: viewport)
        model.panChanged(CGSize(width: 10, height: 0))
        #expect(model.scrolled(by: CGSize(width: 0, height: 10), at: CGPoint(x: 700, y: 450), precise: false, zoom: true))
        let zoomed = model.camera
        model.panChanged(CGSize(width: 20, height: 0))
        #expect(model.camera.scale == zoomed.scale)
        #expect(model.camera.center == zoomed.center)
        model.panChanged(CGSize(width: 30, height: 0))
        #expect(abs(model.camera.center.x - (zoomed.center.x - 10 / zoomed.scale)) < 0.001)
    }

    @Test("the coasting tail of a fling does not stop a flight")
    func momentumDuringFlight() throws {
        let model = try model()
        model.viewportFrame = CGRect(origin: .zero, size: viewport)
        model.focus(on: "atlas/home/photos")
        let goal = model.camera
        #expect(model.scrolled(by: CGSize(width: 30, height: 0), at: CGPoint(x: 700, y: 450), precise: true, zoom: false, momentum: true))
        #expect(model.flight != nil)
        #expect(model.camera == goal)
    }

    @Test("only web tiles are budgeted: FarCast's surfaces and sketches never take a live slot")
    func budgetIsForTiles() throws {
        let model = try model()
        model.show(.instance("atlas"))
        model.show(.group("atlas/farcast-system"))
        let live = model.liveApps(at: model.camera)
        #expect(live.allSatisfy { !$0.contains("farcast-system") && !$0.contains("/shop/") })
        model.show(.app("atlas/home/notes"))
        #expect(model.liveApps(at: model.camera).contains("atlas/home/notes"))
    }

    @Test("a saved layout full of conflicts loads without any")
    func conflictingSaveLoadsClean() throws {
        let suite = "farsight.tests.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let world = try Fixtures.world()
        var bad = Arrangement.standard(for: world)
        bad.appOffsets["atlas/home/photos"] = bad.appOffsets["atlas/home/notes"]
        bad.groupOrigins["atlas/dev"] = bad.groupOrigins["atlas/home"]
        for group in world.instances[1].groups { bad.groupOrigins[group.id]?.y -= 3000 }
        #expect(bad.hasConflicts(for: world))
        let store = ArrangementStore(defaults: defaults)
        store.save(bad)
        let model = WorldModel(world: world, store: store)
        #expect(!model.arrangement.hasConflicts(for: world))
    }

    @Test("two windows' moves both survive: each save adds its own item to what is stored")
    func twoWindows() throws {
        let suite = "farsight.tests.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let world = try Fixtures.world()
        let store = ArrangementStore(defaults: defaults)
        let a = WorldModel(world: world, store: store), b = WorldModel(world: world, store: store)
        a.viewportChanged(to: viewport)
        b.viewportChanged(to: viewport)
        let point = CGPoint(x: 700, y: 300)
        #expect(a.beginMove(.app("atlas/home/photos"), at: point))
        a.move(.app("atlas/home/photos"), to: CGPoint(x: point.x + 40, y: point.y))
        a.endMove(.app("atlas/home/photos"))
        #expect(b.beginMove(.app("borealis/lab/wiki"), at: point))
        b.move(.app("borealis/lab/wiki"), to: CGPoint(x: point.x, y: point.y + 40))
        b.endMove(.app("borealis/lab/wiki"))
        let fresh = WorldModel(world: world, store: store)
        #expect(fresh.arrangement.appOffsets["atlas/home/photos"] == a.arrangement.appOffsets["atlas/home/photos"])
        #expect(fresh.arrangement.appOffsets["borealis/lab/wiki"] == b.arrangement.appOffsets["borealis/lab/wiki"])
    }

    @Test("a flight ends a drag where it stands")
    func flightEndsDrag() throws {
        let model = try model()
        let point = CGPoint(x: 700, y: 300)
        #expect(model.beginMove(.group("atlas/home"), at: point))
        model.move(.group("atlas/home"), to: CGPoint(x: point.x + 30, y: point.y))
        let dropped = model.position(of: .group("atlas/home"))
        model.fly(to: .world)
        model.move(.group("atlas/home"), to: CGPoint(x: point.x + 400, y: point.y + 400))
        #expect(model.position(of: .group("atlas/home")) == dropped)
    }
}
