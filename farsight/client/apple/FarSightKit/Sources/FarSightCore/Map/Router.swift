import CoreGraphics

/// How one connection is drawn: a chain of cubic Bézier segments in world
/// units, what it ends in, and where its label goes.
public struct Route: Sendable, Equatable {
    public struct Segment: Sendable, Equatable {
        public var start: CGPoint
        public var control1: CGPoint
        public var control2: CGPoint
        public var end: CGPoint

        public func point(at t: CGFloat) -> CGPoint {
            let u = 1 - t
            let a = u * u * u, b = 3 * u * u * t, c = 3 * u * t * t, d = t * t * t
            return CGPoint(
                x: a * start.x + b * control1.x + c * control2.x + d * end.x,
                y: a * start.y + b * control1.y + c * control2.y + d * end.y
            )
        }
    }

    public enum End: Sendable, Equatable {
        /// It arrives.
        case arrow
        /// It was refused at the wall and never crossed.
        case wall
    }

    public enum LabelPlacement: Sendable, Equatable {
        /// The label starts at `labelPoint`, beside a host or a device.
        case leading
        /// The label is centred on `labelPoint`, on the line.
        case centered
    }

    public var segments: [Segment]
    public var end: End
    public var labelPoint: CGPoint
    public var labelPlacement: LabelPlacement
    /// This label's place among the labels that share its point, and how
    /// many share it. Labels are drawn at a fixed size, so the drawing
    /// spreads them in screen points, not here in world units.
    public var labelStack: (index: Int, count: Int) = (0, 1)

    public static func == (a: Route, b: Route) -> Bool {
        a.segments == b.segments && a.end == b.end && a.labelPoint == b.labelPoint
            && a.labelPlacement == b.labelPlacement && a.labelStack == b.labelStack
    }
}

/// Routes every connection the way the map's honesty needs: anything that
/// crosses an instance's wall goes through that wall's gate, so no line ever
/// suggests a path FatLine does not see.
public enum Router {
    public static func routes(world: World, index: WorldIndex, geometry: WorldGeometry) -> [String: Route] {
        var routes: [String: Route] = [:]
        let spread = egressSpread(world, geometry)
        for connection in world.connections {
            if let route = route(connection, index, geometry, spread[connection.id] ?? 0) {
                routes[connection.id] = route
            }
        }
        // Labels that would stand on one point — lines to one host, a device's
        // lines to one gate — are stacked, in a stable order.
        var byPoint: [String: [String]] = [:]
        for (id, route) in routes {
            byPoint["\(route.labelPoint.x),\(route.labelPoint.y)", default: []].append(id)
        }
        for ids in byPoint.values where ids.count > 1 {
            for (i, id) in ids.sorted().enumerated() {
                routes[id]?.labelStack = (i, ids.count)
            }
        }
        return routes
    }

    private static func route(
        _ connection: Connection,
        _ index: WorldIndex,
        _ geometry: WorldGeometry,
        _ offset: CGFloat
    ) -> Route? {
        switch connection.kind {
        case .egress:
            guard let app = connection.from.appID, let panel = geometry.apps[app],
                  case .host(let hostID) = connection.to, let host = geometry.hosts[hostID],
                  let instance = index.instanceID(ofApp: app),
                  let gate = geometry.territories[instance]?.outGate else { return nil }
            let leave = Self.horizontal(CGPoint(x: panel.maxX, y: panel.midY + offset), gate)
            let label = CGPoint(x: host.maxX + 40, y: host.midY)
            if connection.evidence == .denied {
                return Route(segments: [leave], end: .wall, labelPoint: label, labelPlacement: .leading)
            }
            let arrive = Self.horizontal(gate, CGPoint(x: host.minX, y: host.midY))
            return Route(segments: [leave, arrive], end: .arrow, labelPoint: label, labelPlacement: .leading)

        case .tunnel, .keeper:
            guard case .device(let deviceID) = connection.from, let device = geometry.devices[deviceID],
                  let app = connection.to.appID, let panel = geometry.apps[app],
                  let instance = index.instanceID(ofApp: app),
                  let gate = geometry.territories[instance]?.inGate else { return nil }
            // Devices stand in one column left of every wall, level with the
            // average of their gates, which can be another instance's rows.
            // So a device's line first finds its gate's height in the
            // corridor between the devices and the walls, where no instance
            // stands, then runs straight in.
            let corridor = CGPoint(x: geometry.corridorX, y: gate.y)
            let climb = Self.horizontal(CGPoint(x: device.maxX, y: device.midY), corridor)
            let approach = Self.straight(corridor, gate)
            if connection.evidence == .denied {
                // Refused at the IN gate: the line stops at the wall.
                return Route(segments: [climb, approach], end: .wall, labelPoint: climb.point(at: 0.5), labelPlacement: .centered)
            }
            let arrive = Self.horizontal(gate, CGPoint(x: panel.minX, y: panel.midY))
            return Route(
                segments: [climb, approach, arrive],
                end: .arrow,
                labelPoint: climb.point(at: 0.5),
                labelPlacement: .centered
            )

        case .storage, .appToApp, .watch:
            guard let from = connection.from.appID.flatMap({ geometry.apps[$0] }),
                  let to = connection.to.appID.flatMap({ geometry.apps[$0] }) else { return nil }
            let segment = Self.between(from, to)
            return Route(
                segments: [segment],
                end: .arrow,
                labelPoint: segment.point(at: 0.5),
                labelPlacement: .centered
            )
        }
    }

    /// Lines leaving one panel for several hosts leave it apart, in the order
    /// their hosts stand, so they do not cross at the panel's edge.
    private static func egressSpread(_ world: World, _ geometry: WorldGeometry) -> [String: CGFloat] {
        var byApp: [String: [Connection]] = [:]
        for connection in world.connections where connection.kind == .egress {
            if let app = connection.from.appID { byApp[app, default: []].append(connection) }
        }
        var spread: [String: CGFloat] = [:]
        for (_, connections) in byApp {
            func hostY(_ c: Connection) -> CGFloat {
                if case .host(let id) = c.to, let rect = geometry.hosts[id] { return rect.midY }
                return .infinity
            }
            let sorted = connections.sorted { (hostY($0), $0.id) < (hostY($1), $1.id) }
            // Never wider than the panel's edge, however many lines leave it.
            let room = Metrics.panel.height - 2 * Metrics.lineSpread
            let step = sorted.count > 1 ? min(Metrics.lineSpread, room / CGFloat(sorted.count - 1)) : 0
            for (i, connection) in sorted.enumerated() {
                spread[connection.id] = (CGFloat(i) - CGFloat(sorted.count - 1) / 2) * step
            }
        }
        return spread
    }


    /// A straight segment.
    static func straight(_ a: CGPoint, _ b: CGPoint) -> Route.Segment {
        Route.Segment(
            start: a,
            control1: CGPoint(x: a.x + (b.x - a.x) / 3, y: a.y + (b.y - a.y) / 3),
            control2: CGPoint(x: a.x + 2 * (b.x - a.x) / 3, y: a.y + 2 * (b.y - a.y) / 3),
            end: b
        )
    }

    /// A segment that leaves and arrives horizontally.
    static func horizontal(_ a: CGPoint, _ b: CGPoint) -> Route.Segment {
        let reach = max(abs(b.x - a.x) * 0.5, 120)
        let direction: CGFloat = b.x >= a.x ? 1 : -1
        return Route.Segment(
            start: a,
            control1: CGPoint(x: a.x + reach * direction, y: a.y),
            control2: CGPoint(x: b.x - reach * direction, y: b.y),
            end: b
        )
    }

    /// A segment that leaves and arrives vertically.
    static func vertical(_ a: CGPoint, _ b: CGPoint) -> Route.Segment {
        let reach = max(abs(b.y - a.y) * 0.5, 120)
        let direction: CGFloat = b.y >= a.y ? 1 : -1
        return Route.Segment(
            start: a,
            control1: CGPoint(x: a.x, y: a.y + reach * direction),
            control2: CGPoint(x: b.x, y: b.y - reach * direction),
            end: b
        )
    }

    /// Between two panels, from the facing edges.
    static func between(_ a: CGRect, _ b: CGRect) -> Route.Segment {
        let dx = b.midX - a.midX, dy = b.midY - a.midY
        if abs(dx) >= abs(dy) {
            return horizontal(
                CGPoint(x: dx >= 0 ? a.maxX : a.minX, y: a.midY),
                CGPoint(x: dx >= 0 ? b.minX : b.maxX, y: b.midY)
            )
        }
        return vertical(
            CGPoint(x: a.midX, y: dy >= 0 ? a.maxY : a.minY),
            CGPoint(x: b.midX, y: dy >= 0 ? b.minY : b.maxY)
        )
    }
}
