import CoreGraphics
import Foundation
import Testing
@testable import FarSightCore

@Suite("Where the backdrop is drawn")
struct BackdropLayoutTests {
    let layout = BackdropLayout.standard

    static let viewports = [
        CGSize(width: 1440, height: 900),
        CGSize(width: 1366.5, height: 1024.25),
        CGSize(width: 390, height: 844),
        CGSize(width: 3008, height: 1692),
    ]

    static let cameras: [Camera] = [
        Camera(center: .zero, scale: 1),
        Camera(center: CGPoint(x: 4_321.7, y: -987.3), scale: 0.37),
        Camera(center: CGPoint(x: -61_000.25, y: 12_500), scale: Camera.scales.lowerBound),
        Camera(center: CGPoint(x: 24_999.9, y: 25_000.1), scale: Camera.scales.upperBound),
        Camera(center: CGPoint(x: 7_777, y: 3_333), scale: 0.074),
    ]

    @Test("the tiles cover the whole viewport, meet on whole device pixels, and none lies wholly outside", arguments: viewports)
    func covers(_ viewport: CGSize) {
        for (camera, pixel) in Self.cameras.flatMap({ c in [1, 2, 3].map { (c, CGFloat($0)) } }) {
            let tiles = layout.tiles(for: camera, in: viewport, pixelsPerPoint: pixel)
            // A third of a point is not exact in binary; within a billionth.
            let onPixel = { (v: CGFloat) in abs(v * pixel - (v * pixel).rounded()) < 1e-9 }
            #expect(!tiles.isEmpty)
            let screen = CGRect(origin: .zero, size: viewport)
            // A full grid, no tile missing or repeated: then the outer edges
            // and every neighbour meeting its neighbour cover the screen.
            let columns = tiles.map(\.id.column), rows = tiles.map(\.id.row)
            let first = (columns.min() ?? 0, rows.min() ?? 0), last = (columns.max() ?? -1, rows.max() ?? -1)
            #expect(tiles.count == (last.0 - first.0 + 1) * (last.1 - first.1 + 1))
            #expect(Set(tiles.map(\.id)).count == tiles.count)
            let union = tiles.reduce(CGRect.null) { $0.union($1.rect) }
            #expect(union.contains(screen), "uncovered at scale \(camera.scale), \(pixel)x")
            let byID = Dictionary(uniqueKeysWithValues: tiles.map { ($0.id, $0.rect) })
            for tile in tiles {
                let r = tile.rect
                #expect(onPixel(r.minX) && onPixel(r.maxX) && onPixel(r.minY) && onPixel(r.maxY))
                #expect(r.width > 0 && r.height > 0)
                #expect(r.intersects(screen), "tile \(tile.id) lies outside")
                if tile.id.column < last.0 {
                    let right = byID[.init(column: tile.id.column + 1, row: tile.id.row)]
                    #expect(right.map { abs($0.minX - r.maxX) < 1e-9 && $0.minY == r.minY && $0.maxY == r.maxY } == true)
                }
                if tile.id.row < last.1 {
                    let below = byID[.init(column: tile.id.column, row: tile.id.row + 1)]
                    #expect(below.map { abs($0.minY - r.maxY) < 1e-9 && $0.minX == r.minX && $0.maxX == r.maxX } == true)
                }
            }
        }
    }

    @Test("the backdrop moves with the map far out and lags it close in, never faster")
    func parallax() {
        var previous = CGFloat.infinity
        for scale in stride(from: Camera.scales.lowerBound, through: Camera.scales.upperBound, by: 0.01) {
            let camera = Camera(center: .zero, scale: scale)
            let ratio = layout.scale(for: camera) / camera.scale
            #expect(ratio > 0 && ratio <= 1)
            #expect(ratio < previous)
            previous = ratio
        }
        let far = Camera(center: .zero, scale: Camera.scales.lowerBound)
        #expect(layout.scale(for: far) / far.scale > 0.9)
        let near = Camera(center: .zero, scale: 1)
        #expect(abs(layout.scale(for: near) - 0.2) < 1e-9)
        // At depth 0 the plane is the map.
        let pinned = BackdropLayout(tile: 1000, depth: 0)
        #expect(pinned.scale(for: near) == near.scale)
    }

    @Test("panning the camera slides every tile by the plane's share of the pan")
    func pans() throws {
        let viewport = CGSize(width: 1440, height: 900)
        let camera = Camera(center: CGPoint(x: 1000, y: 2000), scale: 0.5)
        let moved = Camera(center: CGPoint(x: 1300, y: 1800), scale: 0.5)
        let s = layout.scale(for: camera)
        let before = Dictionary(uniqueKeysWithValues: layout.tiles(for: camera, in: viewport).map { ($0.id, $0.rect) })
        let after = layout.tiles(for: moved, in: viewport)
        var compared = 0
        for tile in after {
            guard let old = before[tile.id] else { continue }
            #expect(abs((tile.rect.minX - old.minX) - (-300 * s)) <= 1)
            #expect(abs((tile.rect.minY - old.minY) - (200 * s)) <= 1)
            compared += 1
        }
        #expect(compared > 0)
    }

    @Test("zooming about the middle keeps the plane's middle where it is")
    func zoomsAboutTheMiddle() throws {
        let viewport = CGSize(width: 1440, height: 900)
        let middle = CGPoint(x: 720, y: 450)
        for scale in [0.02, 0.1, 0.5, 1, 2] as [CGFloat] {
            let camera = Camera(center: CGPoint(x: 12_345, y: 6_789), scale: scale)
            let tiles = layout.tiles(for: camera, in: viewport)
            let tile = try #require(tiles.first { $0.rect.contains(middle) })
            // Where in its tile the middle falls, from the plane's own geometry.
            let fx = (12_345 / layout.tile).truncatingRemainder(dividingBy: 1)
            let drawn = (middle.x - tile.rect.minX) / tile.rect.width
            #expect(abs(drawn - fx) < 2 / tile.rect.width + 1e-9)
        }
    }

    @Test("nothing is drawn for an empty viewport or a lost camera, and a runaway layout draws nothing rather than stall")
    func degenerate() {
        let camera = Camera(center: .zero, scale: 1)
        #expect(layout.tiles(for: camera, in: .zero).isEmpty)
        #expect(layout.tiles(for: camera, in: CGSize(width: -10, height: 100)).isEmpty)
        #expect(layout.tiles(for: Camera(center: CGPoint(x: CGFloat.nan, y: 0), scale: 1), in: CGSize(width: 100, height: 100)).isEmpty)
        #expect(layout.tiles(for: Camera(center: CGPoint(x: CGFloat.infinity, y: 0), scale: 1), in: CGSize(width: 100, height: 100)).isEmpty)
        let tiny = BackdropLayout(tile: 2, depth: 0)
        #expect(tiny.tiles(for: Camera(center: .zero, scale: 1), in: CGSize(width: 2000, height: 2000)).isEmpty)
    }

    @Test("the standard layout stays well inside its limit on a large display, however far out")
    func bounded() {
        let large = CGSize(width: 3008, height: 1692)
        let far = Camera(center: CGPoint(x: 123, y: 456), scale: Camera.scales.lowerBound)
        let count = layout.tiles(for: far, in: large).count
        #expect(count > 0 && count <= layout.limit / 4)
    }
}
