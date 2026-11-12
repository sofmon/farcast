import SwiftUI
import FarSightCore

extension Backdrop {
    /// The backdrop that ships with FarSight.
    @MainActor static var bundledURL: URL? {
        Bundle.module.url(forResource: "backdrop", withExtension: "heic")
    }

    @MainActor private static var shared: Task<Backdrop?, Never>?

    /// The bundled backdrop, read once for the whole process: every window
    /// awaits the same read and draws the same two images.
    @MainActor static func bundled() async -> Backdrop? {
        if let shared { return await shared.value }
        guard let url = bundledURL else { return nil }
        let read = Task.detached(priority: .userInitiated) { prepare(url) }
        shared = read
        return await read.value
    }
}

/// The backdrop under the map: open ground drawn as it is, and inside every
/// instance's wall the frosted form, so a wall reads as a pane laid over the
/// backdrop. The surfaces above both are tinted in TerritoryLayer.
struct BackdropLayers: View {
    let backdrop: Backdrop
    let camera: Camera
    let viewport: CGSize
    /// The instances' walls, in viewport points.
    let walls: [CGRect]
    @Environment(\.displayScale) private var displayScale

    var body: some View {
        let tiles = BackdropLayout.standard.tiles(for: camera, in: viewport, pixelsPerPoint: displayScale)
        ZStack(alignment: .topLeading) {
            BackdropTiles(image: backdrop.image, tiles: tiles)
            BackdropTiles(image: backdrop.frosted, tiles: tiles)
                .clipShape(WallsShape(walls: walls, scale: camera.scale))
        }
        .frame(width: viewport.width, height: viewport.height, alignment: .topLeading)
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }
}

/// One image, drawn once per tile. Each tile is a plain image view, so moving
/// the camera moves layers the GPU already holds rather than redrawing them.
private struct BackdropTiles: View {
    let image: CGImage
    let tiles: [BackdropLayout.Tile]

    var body: some View {
        ZStack(alignment: .topLeading) {
            ForEach(tiles) { tile in
                Image(decorative: image, scale: 1)
                    .resizable()
                    .interpolation(.high)
                    .frame(width: tile.rect.width, height: tile.rect.height)
                    .position(x: tile.rect.midX, y: tile.rect.midY)
            }
        }
    }
}

/// The insides of the instances' walls, the same shapes TerritoryLayer draws.
nonisolated struct WallsShape: Shape {
    let walls: [CGRect]
    let scale: CGFloat

    func path(in rect: CGRect) -> Path {
        var path = Path()
        for wall in walls {
            path.addPath(TerritoryLayer.wall(wall, at: scale))
        }
        return path
    }
}
