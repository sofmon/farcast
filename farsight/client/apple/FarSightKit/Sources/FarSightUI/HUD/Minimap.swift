import SwiftUI
import FarSightCore

/// The whole world, small, with the viewport drawn on it. Tap to go there;
/// drag to sweep the camera across.
struct Minimap: View {
    let model: WorldModel
    let size: CGSize

    var body: some View {
        TimelineView(.animation(minimumInterval: nil, paused: model.flight == nil)) { timeline in
            let camera = model.camera(at: timeline.date)
            let fit = MinimapFit(bounds: model.geometry.bounds, size: size)
            Canvas { context, _ in
                for territory in model.geometry.territories.values {
                    let rect = fit.map(territory.frame)
                    let wall = RoundedRectangle(cornerRadius: 3, style: .continuous).path(in: rect)
                    context.fill(wall, with: .color(Theme.territory))
                    context.stroke(wall, with: .color(Theme.wall), lineWidth: 1)
                }
                for (id, rect) in model.geometry.apps {
                    let app = model.index.apps[id]
                    let color: Color =
                        if model.focus == id { Theme.focus }
                        else if let alert = model.alert(for: id) { Theme.severity(alert.severity) }
                        else if app?.state == .stopped { Theme.stopped }
                        else if app?.isIllustrative ?? false { Theme.illustrative }
                        else { Theme.secondaryText }
                    context.fill(Path(fit.map(rect)), with: .color(color.opacity(0.85)))
                }
                for rect in model.geometry.hosts.values {
                    context.fill(Path(fit.map(rect)), with: .color(Theme.observed.opacity(0.35)))
                }
                for rect in model.geometry.devices.values {
                    context.fill(Path(fit.map(rect)), with: .color(Theme.focus.opacity(0.35)))
                }
                let view = fit.map(camera.visibleWorld(in: model.viewport)).intersection(CGRect(origin: .zero, size: size).insetBy(dx: -1, dy: -1))
                if !view.isNull {
                    context.stroke(Path(roundedRect: view, cornerRadius: 2), with: .color(.white.opacity(0.9)), lineWidth: 1.5)
                }
            }
            .frame(width: size.width, height: size.height)
            .contentShape(Rectangle())
            .gesture(
                // The touch-down glides there; the sweep after it follows the
                // finger. Nothing is kept between gestures, so none can stick.
                DragGesture(minimumDistance: 0)
                    .onChanged { value in
                        model.look(at: fit.unmap(value.location), animated: value.translation == .zero)
                    }
            )
        }
        .padding(10)
        .hudGlass(in: RoundedRectangle(cornerRadius: 20, style: .continuous))
        .hudRegion(model, "minimap")
        .accessibilityLabel("Minimap")
        .accessibilityHint("Tap a place to move the camera there")
    }
}

/// The world's bounds fitted into the minimap, keeping proportions.
private struct MinimapFit {
    let origin: CGPoint
    let scale: CGFloat
    let offset: CGPoint

    init(bounds: CGRect, size: CGSize) {
        let world = bounds.isNull ? CGRect(x: 0, y: 0, width: 1, height: 1) : bounds.insetBy(dx: -200, dy: -200)
        scale = min(size.width / world.width, size.height / world.height)
        origin = world.origin
        offset = CGPoint(x: (size.width - world.width * scale) / 2, y: (size.height - world.height * scale) / 2)
    }

    func map(_ rect: CGRect) -> CGRect {
        CGRect(
            x: (rect.minX - origin.x) * scale + offset.x,
            y: (rect.minY - origin.y) * scale + offset.y,
            width: max(rect.width * scale, 1),
            height: max(rect.height * scale, 1)
        )
    }

    func unmap(_ point: CGPoint) -> CGPoint {
        CGPoint(x: (point.x - offset.x) / scale + origin.x, y: (point.y - offset.y) / scale + origin.y)
    }
}
