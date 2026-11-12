import SwiftUI
import FarSightCore

/// Instances' walls with their two gates, and the frames of the groups
/// inside them.
struct TerritoryLayer: View {
    let geometry: WorldGeometry
    let index: WorldIndex
    /// Instances the operator has a tunnel into; only their IN gate says so.
    let tunnelled: Set<String>
    let camera: Camera
    let viewport: CGSize

    var body: some View {
        Canvas { context, size in
            let screen = CGRect(origin: .zero, size: size)
            let scale = camera.scale

            for (instanceID, territory) in geometry.territories {
                let rect = camera.screen(territory.frame, in: viewport)
                guard rect.intersects(screen) else { continue }
                let wall = RoundedRectangle(cornerRadius: max(4, 90 * scale), style: .continuous).path(in: rect)
                context.fill(wall, with: .color(Theme.territory))
                context.stroke(wall, with: .color(Theme.wall), lineWidth: min(max(10 * scale, 1.5), 4))

                for (gate, label, anchor) in [
                    (territory.inGate, tunnelled.contains(instanceID) ? "IN · your tunnel" : "IN", UnitPoint.trailing),
                    (territory.outGate, "OUT · FatLine egress", UnitPoint.leading),
                ] {
                    let p = camera.screen(gate, in: viewport)
                    let height = max(16, 150 * scale), width = min(max(36 * scale, 7), 14)
                    let notch = Capsule().path(in: CGRect(x: p.x - width / 2, y: p.y - height / 2, width: width, height: height))
                    context.fill(notch, with: .color(Theme.ground))
                    context.stroke(notch, with: .color(Theme.observed), lineWidth: 1.5)
                    if scale > 0.025 {
                        let text = Text(label)
                            .font(.system(size: 11, weight: .semibold))
                            .foregroundStyle(Theme.observed)
                        let offset: CGFloat = anchor == .trailing ? -(width + 6) : width + 6
                        context.draw(text, at: CGPoint(x: p.x + offset, y: p.y - height / 2 - 8), anchor: anchor)
                    }
                }
            }

            for (id, group) in geometry.groups {
                let rect = camera.screen(group.frame, in: viewport)
                guard rect.intersects(screen) else { continue }
                let info = index.groups[id]
                let frame = RoundedRectangle(cornerRadius: max(3, 44 * scale), style: .continuous).path(in: rect)
                context.fill(frame, with: .color(Theme.groupFill))
                let illustrative = info?.isIllustrative ?? false
                let stroke = illustrative ? Theme.illustrative.opacity(0.7)
                    : (info?.isSystem ?? false) ? Theme.systemGroupStroke : Theme.groupStroke
                context.stroke(frame, with: .color(stroke), style: StrokeStyle(lineWidth: 1.5, dash: illustrative ? [7, 5] : []))
            }
        }
    }
}

/// The hosts outside the walls and the operator's devices.
struct OutsideLayer: View {
    let model: WorldModel
    let camera: Camera
    let viewport: CGSize

    var body: some View {
        Canvas { context, size in
            let screen = CGRect(origin: .zero, size: size)
            for host in model.world.hosts {
                guard let world = model.geometry.hosts[host.id] else { continue }
                let rect = camera.screen(world, in: viewport)
                guard rect.intersects(screen) else { continue }
                let tone = model.hostTones[host.id] ?? .unconnected
                let (color, dash): (Color, [CGFloat]) = switch tone {
                case .used: (Theme.observed, [])
                case .refused: (Theme.denied, [])
                case .planned: (Theme.planned, [6, 4])
                case .declared: (Theme.declared, [2, 4])
                case .unconnected: (Theme.tertiaryText, [1, 5])
                }
                Self.card(context, rect, title: host.name, note: host.note, color: color, dash: dash, scale: camera.scale)
            }
            for device in model.world.devices {
                guard let world = model.geometry.devices[device.id] else { continue }
                let rect = camera.screen(world, in: viewport)
                guard rect.intersects(screen) else { continue }
                let color = !device.isHealthy ? Theme.warning : device.role == .operator ? Theme.focus : Theme.keeper
                Self.card(context, rect, title: device.name, note: device.note, color: color, dash: [], scale: camera.scale)
            }
        }
    }

    private static func card(
        _ context: GraphicsContext,
        _ rect: CGRect,
        title: String,
        note: String,
        color: Color,
        dash: [CGFloat],
        scale: CGFloat
    ) {
        let shape = RoundedRectangle(cornerRadius: max(3, 30 * scale), style: .continuous).path(in: rect)
        context.fill(shape, with: .color(Theme.panel))
        context.stroke(shape, with: .color(color), style: StrokeStyle(lineWidth: 1.5, dash: dash))
        guard rect.width > 70 else { return }
        var context = context
        context.clip(to: shape)
        let size = min(max(44 * scale, 9), 16)
        let inset = min(max(30 * scale, 6), 16)
        context.draw(
            Text(title).font(.system(size: size, weight: .semibold)).foregroundStyle(Theme.text),
            at: CGPoint(x: rect.minX + inset, y: rect.minY + rect.height * 0.36),
            anchor: .leading
        )
        if rect.height > 34 {
            context.draw(
                Text(note).font(.system(size: size * 0.78)).foregroundStyle(color.opacity(0.9)),
                at: CGPoint(x: rect.minX + inset, y: rect.minY + rect.height * 0.7),
                anchor: .leading
            )
        }
    }
}

/// An instance's name and spending, above its wall. Tap to frame it.
struct TerritoryLabel: View {
    let instance: Instance
    let rect: CGRect
    let scale: CGFloat
    let action: () -> Void

    var body: some View {
        let size = min(max(96 * scale, 13), 28)
        let inset = min(max(160 * scale, 10), 40)
        let height = max(rect.height, size + 12)
        let spending = instance.spending
        Button(action: action) {
            HStack(alignment: .firstTextBaseline, spacing: size * 0.5) {
                Text(instance.id)
                    .font(.system(size: size, weight: .bold))
                    .foregroundStyle(Theme.text)
                Text("\(Format.dollars(spending.expectedCents)) expected of \(Format.dollars(spending.limitCents)) · \(Format.percent(spending.fraction))")
                    .font(.system(size: size * 0.62, weight: .medium, design: .monospaced))
                    .foregroundStyle(Theme.spending(spending.fraction))
            }
            .lineLimit(1)
            .fixedSize()
        }
        .buttonStyle(.plain)
        .accessibilityLabel("\(instance.id), expected spending at \(Format.percent(spending.fraction)) of its cost limit")
        .frame(width: max(rect.width - 2 * inset, 1), height: height, alignment: .leading)
        .position(x: rect.midX, y: rect.maxY - height / 2)
    }
}

/// A group's name on its top band. Drag it to move the whole group; tap it to
/// frame the group.
struct GroupHeader: View {
    let group: AppGroup
    /// The header band, on screen.
    let rect: CGRect
    /// The whole group, on screen: the header never reaches outside it.
    let frame: CGRect
    let scale: CGFloat
    let model: WorldModel

    var body: some View {
        let size = min(max(54 * scale, 11), 22)
        let height = min(max(rect.height, size + 10), frame.height)
        HStack(spacing: size * 0.6) {
            Image(systemName: group.isSystem ? "gearshape.2.fill" : "shippingbox")
                .font(.system(size: size * 0.8))
                .foregroundStyle(Theme.secondaryText)
            Text(group.isSystem ? "FarCast" : group.namespace)
                .font(.system(size: size, weight: .semibold))
                .foregroundStyle(Theme.text)
            if rect.width > 300 {
                Text(group.isSystem ? "the OS itself, shown as apps" : group.source)
                    .font(.system(size: size * 0.72))
                    .foregroundStyle(Theme.secondaryText)
            }
            if group.isIllustrative, rect.width > 200 {
                Text("illustrative")
                    .font(.system(size: size * 0.66, weight: .semibold))
                    .foregroundStyle(Theme.illustrative)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .overlay(Capsule().strokeBorder(Theme.illustrative.opacity(0.7)))
            }
            Spacer(minLength: 0)
        }
        .lineLimit(1)
        .padding(.horizontal, min(max(60 * scale, 6), 24))
        .frame(width: max(rect.width, 1), height: height, alignment: .leading)
        .contentShape(Rectangle())
        .moveHandle(model, .group(group.id))
        .onTapGesture { model.fly(to: .group(group.id)) }
        // Grown to stay legible when small, it grows down over its own
        // panels (which sit above it and keep their taps), never up over the
        // instance's label.
        .position(x: rect.midX, y: rect.minY + height / 2)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isButton)
        .accessibilityHint("Drag to move the group")
    }
}
