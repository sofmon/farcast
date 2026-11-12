import Foundation
import ImageIO
import SwiftUI
import Testing
import UniformTypeIdentifiers
@testable import FarSightUI
import FarSightCore
import FarSightFixtures

/// Renders the screen at a few camera positions. Always a smoke test: the
/// whole view tree builds and draws. With FARSIGHT_SNAPSHOTS set to a
/// directory, the frames are also written there as PNGs to look at.
///
/// ImageRenderer draws offscreen, so Liquid Glass is not composited the way a
/// window shows it; these frames are for layout, not for the glass.
@Suite("Snapshots")
struct SnapshotTests {
    static let viewport = CGSize(width: 1440, height: 900)

    enum Shot: String, CaseIterable {
        case world, atlas, photos, borealis
    }

    @Test("the screen draws", arguments: Shot.allCases)
    func draws(_ shot: Shot) throws {
        let model = WorldModel(world: try Fixtures.world())
        model.viewportChanged(to: Self.viewport)
        switch shot {
        case .world: model.show(.world)
        case .atlas: model.show(.instance("atlas"))
        case .photos:
            model.focus = "atlas/home/photos"
            model.show(.app("atlas/home/photos"))
        case .borealis:
            model.focus = "borealis/farcast-system/technocore"
            model.show(.group("borealis/farcast-system"))
        }

        let renderer = ImageRenderer(content: WorldScreen(model: model).frame(width: Self.viewport.width, height: Self.viewport.height))
        renderer.proposedSize = ProposedViewSize(Self.viewport)
        renderer.scale = 2
        let image = try #require(renderer.cgImage)
        #expect(image.width == Int(Self.viewport.width * 2))

        if let directory = ProcessInfo.processInfo.environment["FARSIGHT_SNAPSHOTS"] {
            let url = URL(fileURLWithPath: directory).appendingPathComponent("\(shot.rawValue).png")
            let destination = try #require(CGImageDestinationCreateWithURL(url as CFURL, UTType.png.identifier as CFString, 1, nil))
            CGImageDestinationAddImage(destination, image, nil)
            #expect(CGImageDestinationFinalize(destination))
        }
    }
}
