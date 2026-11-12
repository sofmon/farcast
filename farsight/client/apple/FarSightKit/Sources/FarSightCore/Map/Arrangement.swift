import CoreGraphics

/// Where things sit on the map: each group's origin and each app's place
/// inside its group. Only groups and apps are arranged — territories, gates,
/// hosts and devices follow from them.
///
/// The operator moves groups and apps. FarSight moves one only to keep two
/// things from overlapping when it loads a layout (`completed`, `separated`)
/// — because the world changed, or because a saved layout overlaps, as two
/// windows' drops can make it. A drag itself is never second-guessed, only
/// refused. A client
/// keeps the arrangement on its device for now. ADR 0021 gives layout state
/// to the FarSight server, so it is to move there once that server exists.
public struct Arrangement: Codable, Sendable, Equatable {
    /// Group id → the world point its apps are placed from.
    public var groupOrigins: [String: CGPoint]
    /// App id → offset from its group's origin.
    public var appOffsets: [String: CGPoint]

    public init(groupOrigins: [String: CGPoint] = [:], appOffsets: [String: CGPoint] = [:]) {
        self.groupOrigins = groupOrigins
        self.appOffsets = appOffsets
    }

    /// The arrangement a first look gets, already separated (`separated`), so
    /// no instance's hosts reach into the next one's rows. Instances stack top
    /// to bottom. In
    /// each, the system group comes first and the other groups pack into
    /// `Metrics.columns` columns, each into the column that is shortest so
    /// far, a wide group spanning as many as it needs. A group's apps sit in a
    /// grid: two across for the system group, up to three for the rest.
    public static func standard(for world: World) -> Arrangement {
        let panel = Metrics.panel, gap = Metrics.panelGap
        let inset = Metrics.groupInset, territory = Metrics.territoryInset
        let columnWidth = 2 * panel.width + gap.width + 2 * inset.side
        var result = Arrangement()
        var top: CGFloat = 0

        for instance in world.instances {
            var bottoms = Array(repeating: top + territory.top, count: Metrics.columns)
            let ordered = instance.groups.filter(\.isSystem) + instance.groups.filter { !$0.isSystem }
            for group in ordered {
                let across = group.isSystem ? 2 : max(1, min(group.apps.count, 3))
                let rows = max(1, (group.apps.count + across - 1) / across)
                for (i, app) in group.apps.enumerated() {
                    result.appOffsets[app.id] = CGPoint(
                        x: CGFloat(i % across) * (panel.width + gap.width),
                        y: CGFloat(i / across) * (panel.height + gap.height)
                    )
                }
                let outer = CGSize(
                    width: CGFloat(across) * panel.width + CGFloat(across - 1) * gap.width + 2 * inset.side,
                    height: CGFloat(rows) * panel.height + CGFloat(rows - 1) * gap.height + inset.top + inset.bottom
                )
                var span = 1
                while span < Metrics.columns,
                      CGFloat(span) * columnWidth + CGFloat(span - 1) * Metrics.groupGap.width < outer.width {
                    span += 1
                }
                var column = 0
                var y = CGFloat.infinity
                for start in 0...(Metrics.columns - span) {
                    let lowest = bottoms[start..<(start + span)].max() ?? top
                    if lowest < y { column = start; y = lowest }
                }
                let x = territory.side + CGFloat(column) * (columnWidth + Metrics.groupGap.width)
                result.groupOrigins[group.id] = CGPoint(x: x + inset.side, y: y + inset.top)
                for c in column..<(column + span) {
                    bottoms[c] = y + outer.height + Metrics.groupGap.height
                }
            }
            let contentBottom = (bottoms.max() ?? top) - Metrics.groupGap.height
            top = contentBottom + territory.bottom + Metrics.instanceGap
        }
        return result.separated(for: world)
    }

    /// This arrangement for `world`.
    ///
    /// What it already places keeps its place. What it lacks goes where
    /// nothing is: a new app to the right of its group's apps, a new group
    /// below its instance's groups, a new instance below every instance
    /// already placed. An app on top of a sibling moves to the right of its
    /// group's apps; a group that grew onto a sibling moves below its
    /// instance's groups; an instance that would share rows with another
    /// moves down, whole. Where a group or app that comes back finds its
    /// place taken, the world's order decides which one moves: the one later
    /// in it. Entries for groups and apps the world no longer has are kept,
    /// so a layout survives an instance being away.
    public func completed(for world: World, from fallback: Arrangement) -> Arrangement {
        let panel = Metrics.panel, gap = Metrics.panelGap, inset = Metrics.groupInset
        var result = self
        var newInstances = Set<String>()
        for instance in world.instances {
            if !instance.groups.contains(where: { result.groupOrigins[$0.id] != nil }) {
                newInstances.insert(instance.id)
            }
            var changed = Set<String>()
            var placed = instance.groups.compactMap { group in
                result.groupOrigins[group.id].map { result.frame(of: group, origin: $0) }
            }.reduce(CGRect.null) { $0.union($1) }

            for group in instance.groups {
                if result.groupOrigins[group.id] == nil {
                    changed.insert(group.id)
                    if placed.isNull {
                        result.groupOrigins[group.id] = fallback.groupOrigins[group.id] ?? .zero
                    } else {
                        result.groupOrigins[group.id] = CGPoint(
                            x: placed.minX + inset.side,
                            y: placed.maxY + Metrics.groupGap.height + inset.top
                        )
                    }
                }
                let known = group.apps.compactMap { result.appOffsets[$0.id] }
                var nextX = (known.map(\.x).max() ?? -(panel.width + gap.width)) + panel.width + gap.width
                let row = known.map(\.y).min() ?? 0
                for app in group.apps where result.appOffsets[app.id] == nil {
                    changed.insert(group.id)
                    if known.isEmpty {
                        result.appOffsets[app.id] = fallback.appOffsets[app.id] ?? CGPoint(x: nextX, y: row)
                    } else {
                        result.appOffsets[app.id] = CGPoint(x: nextX, y: row)
                        nextX += panel.width + gap.width
                    }
                }
                if result.unstackApps(of: group) { changed.insert(group.id) }
                if let origin = result.groupOrigins[group.id] {
                    placed = placed.union(result.frame(of: group, origin: origin))
                }
            }
            result.unstack(instance, moving: changed)
        }
        return result.separated(for: world, placingLast: newInstances)
    }

    /// Moves apps of `group` off each other: each app whose panel overlaps
    /// one placed before it goes to the right of the group's apps, on the top
    /// row. Returns whether any moved.
    mutating func unstackApps(of group: AppGroup) -> Bool {
        let step = Metrics.panel.width + Metrics.panelGap.width
        let all = group.apps.compactMap { appOffsets[$0.id].map { CGRect(origin: $0, size: Metrics.panel) } }
        // Movers go right of every app of the group, not only those placed
        // so far, so none lands on a sibling that was never in the way.
        var right = all.map(\.maxX).max() ?? 0
        let top = all.map(\.minY).min() ?? 0
        var panels: [CGRect] = []
        var moved = false
        for app in group.apps {
            guard let offset = appOffsets[app.id] else { continue }
            var panel = CGRect(origin: offset, size: Metrics.panel)
            if panels.contains(where: { $0.intersects(panel) }) {
                panel.origin = CGPoint(x: right - Metrics.panel.width + step, y: top)
                appOffsets[app.id] = panel.origin
                right = panel.maxX
                moved = true
            }
            panels.append(panel)
        }
        return moved
    }

    /// Moves groups of `instance` off each other: each group that overlaps
    /// one placed before it goes below all of them. Groups in `moving` are
    /// placed last, so they are the ones that move.
    mutating func unstack(_ instance: Instance, moving: Set<String>) {
        let order = instance.groups.filter { !moving.contains($0.id) } + instance.groups.filter { moving.contains($0.id) }
        // Movers go below every group of the instance, not only those placed
        // so far, so none lands on a group that was never in the way.
        var all = instance.groups.compactMap { group in groupOrigins[group.id].map { frame(of: group, origin: $0) } }
            .reduce(CGRect.null) { $0.union($1) }
        var frames: [CGRect] = []
        for group in order {
            guard let origin = groupOrigins[group.id] else { continue }
            var frame = frame(of: group, origin: origin)
            if frames.contains(where: { $0.intersects(frame) }) {
                let dx = all.minX - frame.minX, dy = all.maxY + Metrics.groupGap.height - frame.minY
                groupOrigins[group.id] = CGPoint(x: origin.x + dx, y: origin.y + dy)
                frame = frame.offsetBy(dx: dx, dy: dy)
                all = all.union(frame)
            }
            frames.append(frame)
        }
    }

    /// This arrangement with no two instances sharing rows. Instances are
    /// bands across the map — devices stand left of them, hosts right, and
    /// lines run sideways between them — so an instance beside another would
    /// have lines drawn through it. Each instance whose band (its wall and
    /// its hosts) comes near an earlier one's moves down, whole, below it.
    /// Instances in `late` give way to every other.
    public func separated(for world: World, placingLast late: Set<String> = []) -> Arrangement {
        var result = self
        let bands = self.bands(for: world)
        let order = world.instances.filter { !late.contains($0.id) } + world.instances.filter { late.contains($0.id) }
        var settled: [ClosedRange<CGFloat>] = []
        for instance in order {
            guard let band = bands[instance.id] else { continue }
            var shift: CGFloat = 0
            while let blocking = settled.first(where: { Self.near($0, band.shifted(by: shift)) }) {
                shift = blocking.upperBound + Metrics.instanceGap - band.lowerBound
            }
            if shift > 0 {
                for group in instance.groups {
                    result.groupOrigins[group.id]?.y += shift
                }
            }
            settled.append(band.shifted(by: shift))
        }
        return result
    }

    /// Whether this arrangement has anything a drop must not cause: two
    /// panels overlapping, two groups of an instance overlapping, or two
    /// instances sharing rows.
    public func hasConflicts(for world: World) -> Bool {
        let index = WorldIndex(world)
        let geometry = WorldGeometry(world: world, index: index, arrangement: self)
        let panels = Array(geometry.apps.values)
        for (i, a) in panels.enumerated() {
            for b in panels[(i + 1)...] where a.intersects(b) { return true }
        }
        for instance in world.instances {
            let frames = instance.groups.compactMap { geometry.groups[$0.id]?.frame }
            for (i, a) in frames.enumerated() {
                for b in frames[(i + 1)...] where a.intersects(b) { return true }
            }
        }
        let bands = Array(bands(for: world).values)
        for (i, a) in bands.enumerated() {
            for b in bands[(i + 1)...] where Self.near(a, b) { return true }
        }
        return false
    }

    /// Each instance's rows: its wall and the hosts stacked beside it.
    func bands(for world: World) -> [String: ClosedRange<CGFloat>] {
        let geometry = WorldGeometry(world: world, index: WorldIndex(world), arrangement: self)
        var bands: [String: ClosedRange<CGFloat>] = [:]
        for (id, territory) in geometry.territories {
            var extent = territory.frame
            for host in world.hosts where host.instanceID == id {
                if let rect = geometry.hosts[host.id] { extent = extent.union(rect) }
            }
            bands[id] = extent.minY...extent.maxY
        }
        return bands
    }

    /// Bands closer than half the instance gap are too close.
    static func near(_ a: ClosedRange<CGFloat>, _ b: ClosedRange<CGFloat>) -> Bool {
        let margin = Metrics.instanceGap / 2
        return a.lowerBound - margin < b.upperBound && b.lowerBound - margin < a.upperBound
    }

    /// A group's frame, header band included, with its apps where this
    /// arrangement puts them.
    func frame(of group: AppGroup, origin: CGPoint) -> CGRect {
        let inset = Metrics.groupInset
        var panels = group.apps.reduce(CGRect.null) { rect, app in
            let offset = appOffsets[app.id] ?? .zero
            return rect.union(CGRect(origin: CGPoint(x: origin.x + offset.x, y: origin.y + offset.y), size: Metrics.panel))
        }
        if panels.isNull { panels = CGRect(origin: origin, size: Metrics.panel) }
        return CGRect(
            x: panels.minX - inset.side,
            y: panels.minY - inset.top,
            width: panels.width + 2 * inset.side,
            height: panels.height + inset.top + inset.bottom
        )
    }
}

extension ClosedRange where Bound == CGFloat {
    func shifted(by offset: CGFloat) -> ClosedRange<CGFloat> {
        (lowerBound + offset)...(upperBound + offset)
    }
}
