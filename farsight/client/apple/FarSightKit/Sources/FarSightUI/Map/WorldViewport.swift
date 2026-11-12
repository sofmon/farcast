import SwiftUI
import FarSightCore

/// The map, drawn for the camera. Everything is placed in screen space from
/// world coordinates each frame, so lines stay crisp and text stays legible at
/// any zoom, and a panel always knows how large it is drawn.
struct WorldViewport: View {
    let model: WorldModel
    /// Drawn under everything once it is ready; until then, the plain ground.
    let backdrop: Backdrop?

    var body: some View {
        GeometryReader { proxy in
            TimelineView(.animation(minimumInterval: nil, paused: model.flight == nil)) { timeline in
                MapContent(model: model, backdrop: backdrop, camera: model.camera(at: timeline.date), viewport: proxy.size)
            }
            .onAppear { model.viewportChanged(to: proxy.size) }
            .onChange(of: proxy.size) { _, size in model.viewportChanged(to: size) }
        }
        .coordinateSpace(.named(MapSpace.name))
        .modifier(CameraGestures(model: model))
        .onGeometryChange(for: CGRect.self) { $0.frame(in: .global) } action: { model.viewportFrame = $0 }
        #if os(macOS)
        .background(
            ScrollWheelReader(isEnabled: !model.isPalettePresented) { delta, point, precise, zoom, momentum in
                model.scrolled(by: delta, at: point, precise: precise, zoom: zoom, momentum: momentum)
            }
        )
        #endif
    }
}

private struct MapContent: View {
    let model: WorldModel
    let backdrop: Backdrop?
    let camera: Camera
    let viewport: CGSize

    var body: some View {
        let geometry = model.geometry
        let index = model.index
        let screen = CGRect(origin: .zero, size: viewport).insetBy(dx: -60, dy: -60)
        let live = model.liveApps(at: camera)

        let walls = geometry.territories.values.map { camera.screen($0.frame, in: viewport) }

        ZStack(alignment: .topLeading) {
            if let backdrop {
                BackdropLayers(backdrop: backdrop, camera: camera, viewport: viewport, walls: walls)
                    .transition(OpacityTransition())
            }

            Ground(camera: camera, viewport: viewport, walls: walls)
                .onTapGesture(count: 2) { point in model.zoomStep(2, at: point) }
                .onTapGesture { model.clearFocus() }

            TerritoryLayer(geometry: geometry, index: index, tunnelled: model.tunnelled, camera: camera, viewport: viewport)
                .allowsHitTesting(false)

            ConnectionLayer(model: model, camera: camera, viewport: viewport, tier: .under)
                .allowsHitTesting(false)

            OutsideLayer(model: model, camera: camera, viewport: viewport)
                .allowsHitTesting(false)

            ForEach(model.groupOrder) { group in
                if let frame = geometry.groups[group.id] {
                    let rect = camera.screen(frame.header, in: viewport)
                    if rect.intersects(screen) {
                        GroupHeader(group: group, rect: rect, frame: camera.screen(frame.frame, in: viewport), scale: camera.scale, model: model)
                    }
                }
            }

            ForEach(model.appOrder) { app in
                if let world = geometry.apps[app.id], let groupID = index.groupOfApp[app.id],
                   let group = index.groups[groupID] {
                    let rect = camera.screen(world, in: viewport)
                    if rect.intersects(screen) {
                        AppPanel(
                            app: app,
                            group: group,
                            rect: rect,
                            scale: camera.scale,
                            isFocused: model.focus == app.id,
                            isLive: live.contains(app.id),
                            alert: model.alert(for: app.id),
                            fullWidth: model.fullPanelWidth,
                            model: model
                        )
                    }
                }
            }

            // After the group headers and the panels, so an instance's
            // label always wins its own taps however small the map is drawn.
            ForEach(model.world.instances) { instance in
                if let territory = geometry.territories[instance.id] {
                    let rect = camera.screen(territory.header, in: viewport)
                    if rect.intersects(screen) {
                        TerritoryLabel(instance: instance, rect: rect, scale: camera.scale) {
                            model.fly(to: .instance(instance.id))
                        }
                    }
                }
            }

            ConnectionLayer(model: model, camera: camera, viewport: viewport, tier: .over)
                .allowsHitTesting(false)
        }
        .frame(width: viewport.width, height: viewport.height, alignment: .topLeading)
        .clipped()
    }
}

/// The ground over the backdrop: a dot grid that pans and zooms with the map,
/// so motion reads even over empty space, at the map's own pace where the
/// backdrop lags it. The dots stay outside the walls, as they did when the
/// walls were opaque. It is also what a drag on empty space grabs.
private struct Ground: View {
    let camera: Camera
    let viewport: CGSize
    /// The instances' walls, in viewport points.
    let walls: [CGRect]

    var body: some View {
        Canvas { context, size in
            // Everything outside every wall, overlapping walls included: the
            // same nonzero inside that the frosted form is cut to, inverted.
            var inside = Path()
            for wall in walls { inside.addPath(TerritoryLayer.wall(wall, at: camera.scale)) }
            context.clip(to: inside, options: .inverse)
            var spacing: CGFloat = 200
            while spacing * camera.scale < 24 { spacing *= 5 }
            let visible = camera.visibleWorld(in: viewport)
            var dots = Path()
            var x = (visible.minX / spacing).rounded(.down) * spacing
            while x <= visible.maxX {
                var y = (visible.minY / spacing).rounded(.down) * spacing
                while y <= visible.maxY {
                    let p = camera.screen(CGPoint(x: x, y: y), in: viewport)
                    dots.addRect(CGRect(x: p.x - 0.75, y: p.y - 0.75, width: 1.5, height: 1.5))
                    y += spacing
                }
                x += spacing
            }
            context.fill(dots, with: .color(Theme.gridDot))
        }
        .contentShape(Rectangle())
    }
}
