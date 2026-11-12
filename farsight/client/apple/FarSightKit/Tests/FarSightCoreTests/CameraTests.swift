import CoreGraphics
import Foundation
import Testing
@testable import FarSightCore

@Suite("The camera")
struct CameraTests {
    let viewport = CGSize(width: 1440, height: 900)

    func close(_ a: CGPoint, _ b: CGPoint, within tolerance: CGFloat = 1e-6) -> Bool {
        abs(a.x - b.x) <= tolerance && abs(a.y - b.y) <= tolerance
    }

    @Test("screen and world are inverses")
    func roundTrip() {
        let camera = Camera(center: CGPoint(x: 3000, y: -1200), scale: 0.37)
        let point = CGPoint(x: 123, y: 456)
        #expect(close(camera.screen(camera.world(point, in: viewport), in: viewport), point))
        #expect(camera.screen(camera.center, in: viewport) == CGPoint(x: 720, y: 450))
    }

    @Test("zooming keeps the point under the pointer where it is")
    func zoomAnchor() {
        let camera = Camera(center: CGPoint(x: 500, y: 500), scale: 0.5)
        let anchor = CGPoint(x: 200, y: 700)
        let pinned = camera.world(anchor, in: viewport)
        let zoomed = camera.zoomed(by: 2.5, keeping: anchor, in: viewport)
        #expect(abs(zoomed.scale - 1.25) < 1e-9)
        #expect(close(zoomed.screen(pinned, in: viewport), anchor))
    }

    @Test("scale is clamped, even when asked for nonsense")
    func clamping() {
        #expect(Camera(center: .zero, scale: 100).scale == Camera.scales.upperBound)
        #expect(Camera(center: .zero, scale: 0).scale == Camera.scales.lowerBound)
        #expect(Camera(center: .zero, scale: .nan).scale == Camera.scales.lowerBound)
        #expect(Camera(center: .zero, scale: 1).zoomed(by: 1000, keeping: .zero, in: viewport).scale == Camera.scales.upperBound)
    }

    @Test("panning moves the world with the finger")
    func panning() {
        let camera = Camera(center: CGPoint(x: 100, y: 100), scale: 0.5)
        let world = CGPoint(x: 140, y: 80)
        let before = camera.screen(world, in: viewport)
        let after = camera.panned(by: CGSize(width: 30, height: -10)).screen(world, in: viewport)
        #expect(close(after, CGPoint(x: before.x + 30, y: before.y - 10)))
    }

    @Test("fitting shows the whole rectangle in the part the HUD leaves free")
    func fitting() {
        let rect = CGRect(x: 1000, y: 2000, width: 8000, height: 3000)
        let insets = ViewportInsets(top: 80, leading: 20, bottom: 140, trailing: 20)
        let camera = Camera.fitting(rect, in: viewport, insets: insets, margin: 0, maxScale: 1)
        let shown = camera.screen(rect, in: viewport)
        let free = CGRect(x: 20, y: 80, width: viewport.width - 40, height: viewport.height - 220)
        #expect(shown.minX >= free.minX - 1e-6 && shown.maxX <= free.maxX + 1e-6)
        #expect(shown.minY >= free.minY - 1e-6 && shown.maxY <= free.maxY + 1e-6)
        #expect(abs(shown.width - free.width) < 1e-6 || abs(shown.height - free.height) < 1e-6)
        #expect(Camera.fitting(CGRect(x: 0, y: 0, width: 10, height: 10), in: viewport, maxScale: 0.9).scale == 0.9)
    }

    @Test("a flight starts and ends exactly where it should")
    func flightEnds() {
        let from = Camera(center: CGPoint(x: 0, y: 0), scale: 0.05)
        let to = Camera(center: CGPoint(x: 6000, y: 4000), scale: 0.9)
        for style in [CameraFlight.Style.arc, .glide] {
            let flight = CameraFlight(from: from, to: to, viewport: viewport, style: style)
            #expect(flight.camera(at: 0) == from)
            #expect(flight.camera(at: 1) == to)
            #expect(flight.duration > 0 && flight.duration <= 1.1)
        }
    }

    @Test("an arc is continuous and lands without a jump")
    func flightIsSmooth() {
        let from = Camera(center: CGPoint(x: 0, y: 0), scale: 0.9)
        let to = Camera(center: CGPoint(x: 20000, y: 9000), scale: 0.9)
        let flight = CameraFlight(from: from, to: to, viewport: viewport)
        var previous = flight.camera(at: 0)
        var widest = previous.scale
        for step in 1...200 {
            let camera = flight.camera(at: Double(step) / 200)
            let moved = hypot(camera.center.x - previous.center.x, camera.center.y - previous.center.y)
            #expect(moved < 1200)
            widest = min(widest, camera.scale)
            previous = camera
        }
        // Between two close-up views far apart, the arc zooms out on the way.
        #expect(widest < 0.2)
        let almost = flight.camera(at: 0.999)
        #expect(abs(almost.center.x - to.center.x) < 5 && abs(almost.scale - to.scale) < 0.01)
    }

    @Test("a zoom on the spot does not wander")
    func zoomInPlace() {
        let from = Camera(center: CGPoint(x: 300, y: 300), scale: 0.1)
        let to = Camera(center: CGPoint(x: 300, y: 300), scale: 1)
        let flight = CameraFlight(from: from, to: to, viewport: viewport)
        let middle = flight.camera(at: 0.5)
        #expect(middle.center == from.center)
        #expect(middle.scale > from.scale && middle.scale < to.scale)
    }

    @Test("a still flight takes no time")
    func stillFlight() {
        let camera = Camera(center: .zero, scale: 0.5)
        #expect(CameraFlight(from: camera, to: camera, viewport: viewport).duration == 0)
    }
}

@Suite("Which panels are live")
struct LiveBudgetTests {
    let viewport = CGSize(width: 1440, height: 900)

    func panels(_ count: Int) -> [String: CGRect] {
        Dictionary(uniqueKeysWithValues: (0..<count).map { i in
            ("app\(i)", CGRect(x: CGFloat(i % 4) * 1280, y: CGFloat(i / 4) * 900, width: 1120, height: 740))
        })
    }

    @Test("zoomed out, nothing is live")
    func zoomedOut() {
        let camera = Camera(center: CGPoint(x: 2500, y: 1000), scale: 0.1)
        #expect(LiveBudget.live(panels(8), camera: camera, viewport: viewport).isEmpty)
    }

    @Test("close up, at most the budget, nearest the middle first")
    func closeUp() {
        let camera = Camera(center: CGPoint(x: 1840, y: 820), scale: 0.5)
        let live = LiveBudget.live(panels(16), camera: camera, viewport: viewport, budget: 2)
        #expect(live.count == 2)
        #expect(live.contains("app1") || live.contains("app5"))
    }

    @Test("the focused app is live before any other")
    func focusFirst() {
        let camera = Camera(center: CGPoint(x: 1840, y: 820), scale: 0.5)
        let live = LiveBudget.live(panels(16), camera: camera, viewport: viewport, focus: "app0", budget: 1)
        #expect(live == ["app0"])
    }

    @Test("off screen is never live")
    func offScreen() {
        let camera = Camera(center: CGPoint(x: -50000, y: 0), scale: 1)
        #expect(LiveBudget.live(panels(4), camera: camera, viewport: viewport).isEmpty)
    }
}
