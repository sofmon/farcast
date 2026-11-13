import Foundation
import ImageIO
import SwiftUI
import Testing
import UniformTypeIdentifiers
@testable import FarSightUI
import FarSightCore

/// Draws FarCast's own panels, the instances' chips, what their disclosures
/// open, and a host card, at 2x, and writes them as PNGs to look at: the
/// visual check behind the Connected view's panel layout. Each world is read
/// from the CLI's own vectors through the real adapter and the real feed.
///
/// It runs only with FARSIGHT_RENDERS set to a directory outside the
/// repository, which it writes into; nothing under `farsight/` may hold an
/// image. FARSIGHT_RENDER_DOCS may name a directory of world documents a
/// rehearsal printed (`signed-out.json`), read in place of the vector
/// nearest to it. Offscreen drawing composites no Liquid Glass; these are
/// for layout and wording.
@Suite("Renders")
struct RenderHarness {
    nonisolated static let directory = ProcessInfo.processInfo.environment["FARSIGHT_RENDERS"]
    nonisolated static let documents = ProcessInfo.processInfo.environment["FARSIGHT_RENDER_DOCS"]
    static let viewport = CGSize(width: 1440, height: 900)

    @Test("panels, chips, disclosures and a host card, drawn to PNGs", .enabled(if: RenderHarness.directory != nil))
    func render() async throws {
        let out = URL(fileURLWithPath: try #require(Self.directory))
        try FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)

        // (1) Healthy, then (3) the same instance refused on its next read,
        // its snapshot kept: the feed does what the app does.
        let healthy = try await Self.feedWorld("atlas", read: .world(Self.vector("healthy")))
        let refusal = try #require(CLIDocuments.failure(Self.vectorData("error_gcloud_mismatch")))
        let refused = try await Self.feedWorld("atlas", read: .world(Self.vector("healthy")), then: .failure(refusal))
        // (2) Signed out: spend, apps and policy failed, network read.
        let signedOut: World
        if let documents = Self.documents {
            let data = try Data(contentsOf: URL(fileURLWithPath: documents).appending(path: "signed-out.json"))
            signedOut = try await Self.feedWorld("rehearsal", read: .world(CLIDocuments.world(data, asReadOf: "rehearsal").world))
        } else {
            signedOut = try await Self.feedWorld("atlas", read: .world(Self.vector("account_in_message")))
        }
        let floor = try await Self.feedWorld("atlas", read: .world(Self.vector("at_floor")))
        let tunnelDown = try await Self.feedWorld("atlas", read: .world(Self.vector("tunnel_down")))

        let components = ["technocore", "fatline", "datasphere", "shrike"]
        for (name, world) in [("healthy", healthy), ("signed-out", signedOut), ("refused", refused), ("floor", floor), ("tunnel-down", tunnelDown)] {
            let model = Self.model(world)
            let instance = try #require(world.instances.first).id
            // The system group framed, as the operator sees all four; and the
            // smallest a panel is drawn whole on this screen.
            let group = try #require(model.fitted(.group("\(instance)/farcast-system"))).scale
            let smallest = model.fullPanelWidth / Metrics.panel.width
            for component in components {
                let id = "\(instance)/farcast-system/\(component)"
                try Self.write(Self.panel(model, id, scale: group), to: out, "\(name)-\(component).png")
                try Self.write(Self.panel(model, id, scale: smallest), to: out, "\(name)-\(component)-smallest.png")
            }
            for (suffix, scale) in [("", group), ("-smallest", smallest)] {
                let ids = components.map { "\(instance)/farcast-system/\($0)" }
                try Self.write(
                    VStack(spacing: 0) {
                        HStack(spacing: 0) { Self.panel(model, ids[0], scale: scale); Self.panel(model, ids[1], scale: scale) }
                        HStack(spacing: 0) { Self.panel(model, ids[2], scale: scale); Self.panel(model, ids[3], scale: scale) }
                    },
                    to: out, "\(name)-panels\(suffix).png"
                )
            }
            try Self.write(Self.chip(model, width: Self.viewport.width), to: out, "\(name)-chip.png")
            try Self.write(Self.chip(model, width: 620), to: out, "\(name)-chip-narrow.png")
            if let instance = world.instances.first, !instance.problems.isEmpty || !instance.caveats.isEmpty {
                try Self.write(ReadDetailsContent(instance: instance).frame(width: 460), to: out, "\(name)-chip-details.png")
            }
        }

        // The kernel focused, at the size a window shows one app, and its
        // "more": every word of what the meter does not see.
        let model = Self.model(healthy)
        let kernel = "atlas/farcast-system/technocore"
        let focused = try #require(model.fitted(.app(kernel))).scale
        try Self.write(Self.panel(model, kernel, scale: focused), to: out, "healthy-technocore-focused.png")
        let app = try #require(model.index.apps[kernel])
        try Self.write(
            SurfaceDetailContent(title: "TechnoCore", summary: SystemSummary(app: app, model: model)).frame(width: 420),
            to: out, "healthy-technocore-more.png"
        )

        // (5) A declared host whose use was not read, and the boundary's
        // gate and line beside it.
        let down = Self.model(tunnelDown)
        let host = try #require(tunnelDown.hosts.first { $0.name == "sentry.io" })
        let card = try #require(down.geometry.hosts[host.id])
        let size = CGSize(width: 640, height: 200)
        let camera = Camera.fitting(card, in: size, margin: 20)
        try Self.write(
            OutsideLayer(model: down, camera: camera, viewport: size).frame(width: size.width, height: size.height).background(Theme.ground),
            to: out, "tunnel-down-host-card.png"
        )
        // The smallest a panel is drawn whole anywhere: a phone on its side.
        for (name, world) in [("signed-out", signedOut), ("floor", floor)] {
            let phone = WorldModel(world: world, store: nil)
            phone.layoutChanged(compact: true, short: true)
            phone.viewportChanged(to: CGSize(width: 667, height: 375))
            let instance = try #require(world.instances.first).id
            let ids = components.map { "\(instance)/farcast-system/\($0)" }
            let scale = phone.fullPanelWidth / Metrics.panel.width
            try Self.write(
                VStack(spacing: 0) {
                    HStack(spacing: 0) { Self.panel(phone, ids[0], scale: scale); Self.panel(phone, ids[1], scale: scale) }
                    HStack(spacing: 0) { Self.panel(phone, ids[2], scale: scale); Self.panel(phone, ids[3], scale: scale) }
                },
                to: out, "\(name)-panels-phone.png"
            )
        }
    }

    // MARK: - Worlds

    static func vectorURL(_ name: String) -> URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .appending(path: "FarSightCoreTests/Vectors/world/\(name).json")
    }

    static func vectorData(_ name: String) throws -> Data {
        try Data(contentsOf: vectorURL(name))
    }

    static func vector(_ name: String) throws -> World {
        try CLIDocuments.world(vectorData(name), asReadOf: "atlas").world
    }

    /// What the feed holds after a listing and one read, or two.
    static func feedWorld(_ name: String, read: FakeReader.Answer, then next: FakeReader.Answer? = nil) async throws -> World {
        let listing = InstanceListing(
            name: name, status: .running, cloudLogging: .systemOnly, recordedLimitCents: 5000,
            components: [.kernel: true, .monitor: true, .boundary: true, .storage: true], gcloudPinned: true
        )
        let reader = FakeReader(listing: [listing], worlds: [name: read])
        let feed = WorldFeed(reader: reader)
        await feed.refresh()?.value
        if let next {
            reader.set(name, next)
            await feed.refresh()?.value
        }
        try #require(feed.world.instances.first?.readAt != nil)
        return feed.world
    }

    static func model(_ world: World) -> WorldModel {
        let model = WorldModel(world: world, store: nil)
        model.viewportChanged(to: viewport)
        return model
    }

    // MARK: - Views

    static func panel(_ model: WorldModel, _ id: String, scale: CGFloat) -> some View {
        let app = model.index.apps[id]
        let group = model.index.groupOfApp[id].flatMap { model.index.groups[$0] }
        let size = CGSize(width: Metrics.panel.width * scale, height: Metrics.panel.height * scale)
        return ZStack {
            if let app, let group {
                AppPanel(
                    app: app, group: group, rect: CGRect(origin: .zero, size: size), scale: scale,
                    isFocused: false, isLive: false, alert: model.alert(for: id),
                    fullWidth: model.fullPanelWidth, model: model
                )
            }
        }
        .frame(width: size.width, height: size.height)
        .padding(12)
        .background(Theme.ground)
    }

    /// An instance's chip in a band `width` wide, at the scale the system
    /// group is framed at.
    static func chip(_ model: WorldModel, width: CGFloat) -> some View {
        let instance = model.world.instances[0]
        let scale = model.fitted(.group("\(instance.id)/farcast-system"))?.scale ?? 0.3
        let band = CGRect(x: 0, y: 0, width: width, height: 56)
        return TerritoryLabel(
            instance: instance, rect: band, scale: scale, alert: model.alertByInstance[instance.id],
            showsReadState: true, visible: band.insetBy(dx: 8, dy: 0)
        ) {}
            .frame(width: width, height: band.height)
            .background(Theme.territorySurface)
            .background(Theme.ground)
    }

    @MainActor
    static func write(_ view: some View, to directory: URL, _ name: String) throws {
        let renderer = ImageRenderer(content: view)
        renderer.scale = 2
        let image = try #require(renderer.cgImage, "\(name) did not draw")
        let url = directory.appending(path: name)
        let destination = try #require(CGImageDestinationCreateWithURL(url as CFURL, UTType.png.identifier as CFString, 1, nil))
        CGImageDestinationAddImage(destination, image, nil)
        #expect(CGImageDestinationFinalize(destination))
    }
}
