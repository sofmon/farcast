import CoreGraphics

/// Where the backdrop's tiles are drawn for a camera.
///
/// The backdrop is one seamless image repeated across a plane that lies
/// behind the map. Far out, the plane pans and zooms almost with the map; over
/// an app shown at full size it moves a fifth as fast, and a ninth at the
/// closest zoom, the way distant ground lags what is near. It is not pinned to the screen, so motion over
/// empty space still reads, and not pinned to the map, because no one image
/// serves the map's whole zoom range at one scale: pinned, it would shrink to
/// a busy pattern over the whole world and swell to a blur over one panel.
public struct BackdropLayout: Sendable, Equatable {
    /// One repeat of the image across the plane, in world units.
    public var tile: CGFloat
    /// How far behind the map the plane lies, in units of 1/scale. At 0 the
    /// plane is the map itself; the larger it is, the less the backdrop moves
    /// and grows as the camera comes close.
    public var depth: CGFloat
    /// The most tiles a layout draws. A layout that would need more draws
    /// none, rather than stall a frame; the standard one needs far fewer.
    public var limit: Int

    public init(tile: CGFloat, depth: CGFloat, limit: Int = 400) {
        self.tile = tile
        self.depth = depth
        self.limit = limit
    }

    /// One repeat is about 1,600 points wide where the illustrative world
    /// fits the app's default 1440×900 window (scale 0.086); over an app at
    /// full size (scale 1) the backdrop moves a fifth as fast as the map.
    public static let standard = BackdropLayout(tile: 25_000, depth: 4)

    /// Screen points per world unit on the plane: the camera's scale,
    /// diminished by the plane's distance. Never more than the camera's own,
    /// so the plane never moves faster than the map; what is drawn follows it
    /// to the nearest device pixel.
    public func scale(for camera: Camera) -> CGFloat {
        camera.scale / (1 + camera.scale * max(depth, 0))
    }

    public struct Tile: Sendable, Equatable, Identifiable {
        public struct ID: Hashable, Sendable {
            public var column: Int
            public var row: Int
        }

        public var id: ID
        /// Where it is drawn, in viewport points. Edges sit on whole device
        /// pixels and neighbours share them, so no seam opens between tiles.
        public var rect: CGRect
    }

    /// The tiles that cover the viewport: every point of it, and no tile
    /// wholly outside it. `pixelsPerPoint` is the display's scale; edges are
    /// rounded to its pixels.
    public func tiles(for camera: Camera, in viewport: CGSize, pixelsPerPoint: CGFloat = 1) -> [Tile] {
        guard viewport.width > 0, viewport.height > 0,
              camera.center.x.isFinite, camera.center.y.isFinite,
              tile.isFinite, tile > 0 else { return [] }
        let step = tile * scale(for: camera)
        let pixel = pixelsPerPoint.isFinite ? max(pixelsPerPoint, 1) : 1
        guard step.isFinite, step >= 1 else { return [] }

        // A plane point q is drawn at (q - centre) * scale + viewport / 2.
        func edge(_ i: Int, _ centre: CGFloat, _ half: CGFloat) -> CGFloat {
            (((CGFloat(i) * tile - centre) / tile * step + half) * pixel).rounded() / pixel
        }
        func span(_ centre: CGFloat, _ length: CGFloat) -> ClosedRange<Int>? {
            let half = length / 2
            let low = ((centre - half / step * tile) / tile).rounded(.down)
            let high = ((centre + half / step * tile) / tile).rounded(.down)
            guard low.isFinite, high.isFinite, abs(low) < 1e15, abs(high) < 1e15 else { return nil }
            var first = Int(low), last = Int(high)
            // Rounding the edges can leave a sliver uncovered at either end,
            // or a tile that ends exactly where the viewport begins.
            while edge(first, centre, half) > 0 { first -= 1 }
            while edge(first + 1, centre, half) <= 0 { first += 1 }
            while edge(last + 1, centre, half) < length { last += 1 }
            while edge(last, centre, half) >= length { last -= 1 }
            return first...last
        }
        guard let columns = span(camera.center.x, viewport.width),
              let rows = span(camera.center.y, viewport.height),
              columns.count * rows.count <= limit else { return [] }

        var tiles: [Tile] = []
        tiles.reserveCapacity(columns.count * rows.count)
        for row in rows {
            let top = edge(row, camera.center.y, viewport.height / 2)
            let bottom = edge(row + 1, camera.center.y, viewport.height / 2)
            for column in columns {
                let left = edge(column, camera.center.x, viewport.width / 2)
                let right = edge(column + 1, camera.center.x, viewport.width / 2)
                tiles.append(Tile(
                    id: Tile.ID(column: column, row: row),
                    rect: CGRect(x: left, y: top, width: right - left, height: bottom - top)
                ))
            }
        }
        return tiles
    }
}
