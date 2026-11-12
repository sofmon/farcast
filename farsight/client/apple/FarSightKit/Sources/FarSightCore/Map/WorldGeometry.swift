import CoreGraphics

/// Where everything is drawn, in world units, for one world and one
/// arrangement.
public struct WorldGeometry: Sendable, Equatable {
    public struct GroupFrame: Sendable, Equatable {
        public var frame: CGRect
        /// The top band, where the group's name sits and where it is dragged.
        public var header: CGRect
    }

    public struct Territory: Sendable, Equatable {
        /// The instance's wall.
        public var frame: CGRect
        public var header: CGRect
        /// Where the operator's tunnel comes through the left wall, level
        /// with FatLine, because FatLine is where the wall opens.
        public var inGate: CGPoint
        /// Where egress leaves through the right wall, level with FatLine.
        public var outGate: CGPoint
    }

    public private(set) var apps: [String: CGRect] = [:]
    public private(set) var groups: [String: GroupFrame] = [:]
    public private(set) var territories: [String: Territory] = [:]
    public private(set) var hosts: [String: CGRect] = [:]
    public private(set) var devices: [String: CGRect] = [:]
    /// Everything above; the "whole world" view fits this.
    public private(set) var bounds: CGRect = .null
    /// The vertical corridor between the devices and every wall, where a
    /// device's line climbs to its gate's height without crossing anyone.
    public private(set) var corridorX: CGFloat = 0

    public init(world: World, index: WorldIndex, arrangement: Arrangement) {
        let groupInset = Metrics.groupInset, territoryInset = Metrics.territoryInset

        for instance in world.instances {
            var content = CGRect.null
            for group in instance.groups {
                let origin = arrangement.groupOrigins[group.id] ?? .zero
                var panels = CGRect.null
                for app in group.apps {
                    let offset = arrangement.appOffsets[app.id] ?? .zero
                    let rect = CGRect(
                        origin: CGPoint(x: origin.x + offset.x, y: origin.y + offset.y),
                        size: Metrics.panel
                    )
                    apps[app.id] = rect
                    panels = panels.union(rect)
                }
                if panels.isNull {
                    // A group with no apps still keeps its place.
                    panels = CGRect(origin: origin, size: Metrics.panel)
                }
                let frame = CGRect(
                    x: panels.minX - groupInset.side,
                    y: panels.minY - groupInset.top,
                    width: panels.width + 2 * groupInset.side,
                    height: panels.height + groupInset.top + groupInset.bottom
                )
                groups[group.id] = GroupFrame(
                    frame: frame,
                    header: CGRect(x: frame.minX, y: frame.minY, width: frame.width, height: groupInset.top)
                )
                content = content.union(frame)
            }
            guard !content.isNull else { continue }

            let frame = CGRect(
                x: content.minX - territoryInset.side,
                y: content.minY - territoryInset.top,
                width: content.width + 2 * territoryInset.side,
                height: content.height + territoryInset.top + territoryInset.bottom
            )
            let boundary = index.systemApp(.boundary, in: instance.id).flatMap { apps[$0.id] }
            let gateY = min(
                max(boundary?.midY ?? frame.midY, frame.minY + territoryInset.top),
                frame.maxY - territoryInset.bottom
            )
            territories[instance.id] = Territory(
                frame: frame,
                header: CGRect(x: frame.minX, y: frame.minY, width: frame.width, height: territoryInset.top),
                inGate: CGPoint(x: frame.minX, y: gateY),
                outGate: CGPoint(x: frame.maxX, y: gateY)
            )
        }

        placeHosts(world)
        placeDevices(world, index)

        for rect in Array(apps.values) + groups.values.map(\.frame) + territories.values.map(\.frame)
            + Array(hosts.values) + Array(devices.values) {
            bounds = bounds.union(rect)
        }
    }

    /// Hosts stand outside their instance's right wall, each level with the
    /// apps that reach it, stacked so none overlap.
    private mutating func placeHosts(_ world: World) {
        var sourceY: [String: CGFloat] = [:]
        for connection in world.connections where connection.kind == .egress {
            guard case .host(let host) = connection.to,
                  let app = connection.from.appID, let rect = apps[app] else { continue }
            sourceY[host] = min(sourceY[host] ?? .infinity, rect.midY)
        }
        for (instanceID, territory) in territories {
            let mine = world.hosts.filter { $0.instanceID == instanceID }
            let sorted = mine.sorted {
                (sourceY[$0.id] ?? .infinity, $0.name) < (sourceY[$1.id] ?? .infinity, $1.name)
            }
            // Nothing stands above its territory's wall.
            var bottom = territory.frame.minY - Metrics.hostGap
            for host in sorted {
                let wanted = (sourceY[host.id] ?? bottom + Metrics.host.height) - Metrics.host.height / 2
                let y = max(wanted, bottom + Metrics.hostGap)
                hosts[host.id] = CGRect(
                    origin: CGPoint(x: territory.frame.maxX + Metrics.hostOffset, y: y),
                    size: Metrics.host
                )
                bottom = y + Metrics.host.height
            }
        }
    }

    /// The operator's devices stand left of every territory, each level with
    /// the gates it comes in through.
    private mutating func placeDevices(_ world: World, _ index: WorldIndex) {
        guard let left = territories.values.map(\.frame.minX).min(),
              let top = territories.values.map(\.frame.minY).min() else { return }
        corridorX = left - Metrics.deviceOffset / 2
        var gates: [String: [CGFloat]] = [:]
        for connection in world.connections where connection.kind == .tunnel || connection.kind == .keeper {
            guard case .device(let device) = connection.from,
                  let instance = index.instanceID(of: connection),
                  let territory = territories[instance] else { continue }
            gates[device, default: []].append(territory.inGate.y)
        }
        func target(_ device: Device) -> CGFloat? {
            guard let ys = gates[device.id], !ys.isEmpty else { return nil }
            return ys.reduce(0, +) / CGFloat(ys.count)
        }
        let sorted = world.devices.sorted {
            (target($0) ?? .infinity, $0.name) < (target($1) ?? .infinity, $1.name)
        }
        var bottom = top - Metrics.deviceGap
        for device in sorted {
            let wanted = (target(device) ?? bottom + Metrics.device.height) - Metrics.device.height / 2
            let y = max(wanted, bottom + Metrics.deviceGap)
            devices[device.id] = CGRect(
                origin: CGPoint(x: left - Metrics.deviceOffset - Metrics.device.width, y: y),
                size: Metrics.device
            )
            bottom = y + Metrics.device.height
        }
    }

    /// The instance whose territory holds `point`, or failing that the one
    /// whose territory is nearest to it.
    public func instance(nearest point: CGPoint) -> String? {
        territories.min { a, b in
            let da = a.value.frame.distance(to: point), db = b.value.frame.distance(to: point)
            return (da, a.key) < (db, b.key)
        }?.key
    }
}

extension CGRect {
    /// 0 inside the rectangle, otherwise the distance to its nearest edge.
    public func distance(to point: CGPoint) -> CGFloat {
        let dx = max(minX - point.x, 0, point.x - maxX)
        let dy = max(minY - point.y, 0, point.y - maxY)
        return (dx * dx + dy * dy).squareRoot()
    }
}
