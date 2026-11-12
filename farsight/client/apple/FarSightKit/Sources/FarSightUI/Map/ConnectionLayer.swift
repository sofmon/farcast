import SwiftUI
import FarSightCore

/// The connections, drawn twice: once under the panels, for lines that stay
/// inside an instance, and once over them, for lines that cross a wall and
/// for everything the focused app touches. Labels are always on top, except
/// for lines dimmed by another app's focus, which have none.
struct ConnectionLayer: View {
    enum Tier {
        case under
        case over
    }

    let model: WorldModel
    let camera: Camera
    let viewport: CGSize
    let tier: Tier

    var body: some View {
        let connections = model.world.connections
        let routes = model.routes
        let focus = model.focus
        let filter = model.filter
        let devices = model.index.devices

        Canvas { context, size in
            let screen = CGRect(origin: .zero, size: size).insetBy(dx: -20, dy: -20)
            var labels: [(Route, Connection, EdgeStyle)] = []

            for connection in connections {
                guard filter.shows(connection, focus: focus), let route = routes[connection.id] else { continue }
                let emphasis = Emphasis(connection, focus: focus)
                // With an app focused, only its own lines rise above the
                // panels; the rest dim and sink under them, so none crosses
                // the app the operator is looking at.
                let over = emphasis == .lifted || (emphasis == .normal && connection.crossesWall)
                let health: Device.Health = if case .device(let id) = connection.from { devices[id]?.health ?? .healthy } else { .healthy }
                let style = EdgeStyle(connection, health: health)

                if over == (tier == .over) {
                    var path = Path()
                    for (i, segment) in route.segments.enumerated() {
                        let start = camera.screen(segment.start, in: viewport)
                        if i == 0 { path.move(to: start) }
                        path.addCurve(
                            to: camera.screen(segment.end, in: viewport),
                            control1: camera.screen(segment.control1, in: viewport),
                            control2: camera.screen(segment.control2, in: viewport)
                        )
                    }
                    guard path.boundingRect.intersects(screen) else { continue }

                    var line = context
                    line.opacity = (emphasis == .dimmed ? 0.16 : 1) * (connection.isStale ? 0.45 : 1)
                    let width = style.width * (emphasis == .lifted ? 1.4 : 1)
                    line.stroke(
                        path,
                        with: .color(style.color),
                        style: StrokeStyle(lineWidth: width, lineCap: style.cap, lineJoin: .round, dash: style.dash)
                    )
                    if let last = route.segments.last {
                        Self.drawEnd(
                            route.end, line,
                            tip: camera.screen(last.end, in: viewport),
                            from: camera.screen(last.control2, in: viewport),
                            color: style.color, width: width
                        )
                    }
                }
                // Labels are fixed-size chips; below this scale they would
                // crowd each other at the hosts, so the lines speak alone.
                if tier == .over, emphasis != .dimmed, camera.scale > 0.1 {
                    labels.append((route, connection, style))
                }
            }

            // Stacks are counted from the labels actually drawn — a dimmed
            // or filtered line leaves its stack. A stack may take only its
            // host's own rows; one that would not fit says how many lines
            // there are.
            let room = (Metrics.host.height + Metrics.hostGap) * camera.scale
            var stacks: [String: [Int]] = [:]
            for (i, label) in labels.enumerated() {
                stacks["\(label.0.labelPoint.x),\(label.0.labelPoint.y)", default: []].append(i)
            }
            for members in stacks.values {
                let ordered = members.sorted { labels[$0].1.id < labels[$1].1.id }
                if ordered.count > 1, CGFloat(ordered.count) * 23 > room {
                    var single = labels[ordered[0]].0
                    single.labelStack = (0, 1)
                    Self.drawLabel("\(ordered.count) lines", single, context, camera: camera, viewport: viewport, color: Theme.secondaryText, stale: false)
                    continue
                }
                for (position, i) in ordered.enumerated() {
                    var (route, connection, style) = labels[i]
                    route.labelStack = (position, ordered.count)
                    Self.drawLabel(Display.name(connection.label), route, context, camera: camera, viewport: viewport, color: style.color, stale: connection.isStale)
                }
            }
        }
    }

    private static func drawEnd(_ end: Route.End, _ context: GraphicsContext, tip: CGPoint, from: CGPoint, color: Color, width: CGFloat) {
        var dx = tip.x - from.x, dy = tip.y - from.y
        let length = max(hypot(dx, dy), 0.001)
        dx /= length
        dy /= length
        switch end {
        case .arrow:
            let size = 6 + width * 1.5
            var head = Path()
            head.move(to: tip)
            head.addLine(to: CGPoint(x: tip.x - dx * size - dy * size * 0.5, y: tip.y - dy * size + dx * size * 0.5))
            head.addLine(to: CGPoint(x: tip.x - dx * size + dy * size * 0.5, y: tip.y - dy * size - dx * size * 0.5))
            head.closeSubpath()
            context.fill(head, with: .color(color))
        case .wall:
            // Refused here: a cross on the wall, and nothing beyond it.
            let size: CGFloat = 7
            var cross = Path()
            cross.move(to: CGPoint(x: tip.x - size, y: tip.y - size))
            cross.addLine(to: CGPoint(x: tip.x + size, y: tip.y + size))
            cross.move(to: CGPoint(x: tip.x - size, y: tip.y + size))
            cross.addLine(to: CGPoint(x: tip.x + size, y: tip.y - size))
            context.stroke(cross, with: .color(color), style: StrokeStyle(lineWidth: 2.5, lineCap: .round))
        }
    }

    private static func drawLabel(
        _ label: String,
        _ route: Route,
        _ context: GraphicsContext,
        camera: Camera,
        viewport: CGSize,
        color: Color,
        stale: Bool
    ) {
        guard !label.isEmpty else { return }
        let point = camera.screen(route.labelPoint, in: viewport)
        let text = context.resolve(
            Text(label)
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(color.opacity(stale ? 0.6 : 1))
        )
        let size = text.measure(in: CGSize(width: 320, height: 40))
        let box = CGSize(width: size.width + 12, height: size.height + 6)
        let origin = switch route.labelPlacement {
        case .leading: CGPoint(x: point.x, y: point.y - box.height / 2)
        case .centered: CGPoint(x: point.x - box.width / 2, y: point.y - box.height / 2)
        }
        // Labels sharing a point stack in screen points, so they stay apart
        // at every zoom.
        let lift = (CGFloat(route.labelStack.index) - CGFloat(route.labelStack.count - 1) / 2) * (box.height + 4)
        let rect = CGRect(origin: CGPoint(x: origin.x, y: origin.y + lift), size: box)
        let chip = Capsule().path(in: rect)
        context.fill(chip, with: .color(Theme.chip))
        context.stroke(chip, with: .color(color.opacity(0.35)), lineWidth: 1)
        context.draw(text, at: CGPoint(x: rect.midX, y: rect.midY), anchor: .center)
    }
}

/// How a connection looks, from what kind it is and what is known about it.
/// Solid means FatLine counted it; dots mean only declared; red with short
/// dashes means refused, so a refusal reads without its colour too; violet
/// dashes mean decided but not built. No two grades share a dash.
struct EdgeStyle {
    let color: Color
    let width: CGFloat
    let dash: [CGFloat]
    /// Round, except on the refused line: round caps would close its short
    /// gaps.
    var cap: CGLineCap { dash == Self.deniedDash ? .butt : .round }

    /// The refused line's dash, which no other line uses.
    static let deniedDash: [CGFloat] = [2, 3]

    /// `health` is the health of the device a line starts at, if it does.
    init(_ connection: Connection, health: Device.Health = .healthy) {
        switch (connection.kind, connection.evidence) {
        case (_, .denied):
            (color, width, dash) = (Theme.denied, 2, Self.deniedDash)
        case (_, .planned):
            (color, width, dash) = (Theme.planned, 2, [8, 6])
        case (_, .declared):
            (color, width, dash) = (Theme.declared, 1.8, [0.5, 6])
        case (.egress, .observed):
            (color, width, dash) = (Theme.observed, 2, [])
        case (.tunnel, .observed):
            (color, width, dash) = (Theme.observed, 2.6, [])
        case (.keeper, .observed):
            let color: Color = switch health {
            case .healthy: Theme.keeper
            case .expired, .revoked, .unseen: Theme.warning
            case .unknown: Theme.secondaryText
            }
            (self.color, width, dash) = (color, 2, [7, 6])
        case (.storage, .observed):
            (color, width, dash) = (Theme.storage, 2, [6, 5])
        case (.appToApp, .observed):
            (color, width, dash) = (Theme.planned, 2, [])
        case (.watch, .observed):
            (color, width, dash) = (Theme.watch, 1.5, [3, 5])
        }
    }
}
