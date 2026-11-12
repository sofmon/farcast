import CoreGraphics
import Foundation
import Testing
@testable import FarSightCore
import FarSightFixtures

@Suite("Where things sit on the map")
struct MapTests {
    let world: World
    let index: WorldIndex
    let geometry: WorldGeometry

    init() throws {
        world = try Fixtures.world()
        index = WorldIndex(world)
        geometry = WorldGeometry(world: world, index: index, arrangement: .standard(for: world))
    }

    @Test("every app, group, host and device has a place")
    func everythingIsPlaced() {
        #expect(Set(geometry.apps.keys) == Set(index.apps.keys))
        #expect(Set(geometry.groups.keys) == Set(index.groups.keys))
        #expect(Set(geometry.territories.keys) == Set(index.instances.keys))
        #expect(Set(geometry.hosts.keys) == Set(index.hosts.keys))
        #expect(Set(geometry.devices.keys) == Set(index.devices.keys))
        for rect in geometry.apps.values { #expect(geometry.bounds.contains(rect)) }
    }

    @Test("in the standard arrangement nothing overlaps")
    func nothingOverlaps() {
        func disjoint(_ rects: [CGRect]) -> Bool {
            for (i, a) in rects.enumerated() {
                for b in rects[(i + 1)...] where a.intersects(b) { return false }
            }
            return true
        }
        #expect(disjoint(Array(geometry.apps.values)))
        #expect(disjoint(geometry.groups.values.map(\.frame)))
        #expect(disjoint(geometry.territories.values.map(\.frame)))
        #expect(disjoint(Array(geometry.hosts.values)))
        #expect(disjoint(Array(geometry.devices.values)))
    }

    @Test("every app sits inside its group, and every group inside its instance")
    func nesting() {
        for (appID, rect) in geometry.apps {
            let group = index.groupOfApp[appID]!
            #expect(geometry.groups[group]!.frame.contains(rect))
        }
        for (groupID, frame) in geometry.groups {
            let instance = index.instanceOfGroup[groupID]!
            #expect(geometry.territories[instance]!.frame.contains(frame.frame))
        }
    }

    @Test("hosts stand outside the right wall, devices left of every wall")
    func outsiders() {
        for host in world.hosts {
            #expect(geometry.hosts[host.id]!.minX > geometry.territories[host.instanceID]!.frame.maxX)
        }
        let left = geometry.territories.values.map(\.frame.minX).min()!
        for rect in geometry.devices.values { #expect(rect.maxX < left) }
    }

    @Test("the gates are level with FatLine")
    func gates() {
        for instance in world.instances {
            let fatline = geometry.apps[index.systemApp(.boundary, in: instance.id)!.id]!
            let territory = geometry.territories[instance.id]!
            #expect(territory.inGate == CGPoint(x: territory.frame.minX, y: fatline.midY))
            #expect(territory.outGate == CGPoint(x: territory.frame.maxX, y: fatline.midY))
        }
    }

    @Test("the arrangement moves a group's apps with it, and survives coding")
    func moving() throws {
        var arrangement = Arrangement.standard(for: world)
        let before = geometry.apps["atlas/home/photos"]!
        arrangement.groupOrigins["atlas/home", default: .zero].x += 400
        let moved = WorldGeometry(world: world, index: index, arrangement: arrangement)
        #expect(moved.apps["atlas/home/photos"]! == before.offsetBy(dx: 400, dy: 0))
        #expect(moved.apps["atlas/home/notes"]! == geometry.apps["atlas/home/notes"]!.offsetBy(dx: 400, dy: 0))

        let decoded = try JSONDecoder().decode(Arrangement.self, from: JSONEncoder().encode(arrangement))
        #expect(decoded == arrangement)
    }

    func disjoint(_ rects: [CGRect]) -> Bool {
        for (i, a) in rects.enumerated() {
            for b in rects[(i + 1)...] where a.intersects(b) { return false }
        }
        return true
    }

    @Test("a saved arrangement keeps its places, puts what is new in free space, and keeps what is gone")
    func completing() {
        let standard = Arrangement.standard(for: world)
        var saved = standard
        // Since the save: a new group, a new app in an old group, and a group
        // the world no longer has.
        saved.groupOrigins["atlas/dev"] = nil
        saved.appOffsets["atlas/dev/forge"] = nil
        saved.appOffsets["atlas/home/photos"] = nil
        saved.groupOrigins["gone/group"] = CGPoint(x: 1, y: 1)

        let completed = saved.completed(for: world, from: standard)
        #expect(completed.groupOrigins["atlas/home"] == standard.groupOrigins["atlas/home"])
        #expect(completed.groupOrigins["gone/group"] == CGPoint(x: 1, y: 1))
        #expect(index.apps.keys.allSatisfy { completed.appOffsets[$0] != nil })

        let placed = WorldGeometry(world: world, index: index, arrangement: completed)
        #expect(disjoint(Array(placed.apps.values)))
        #expect(disjoint(placed.groups.values.map(\.frame)))
        #expect(disjoint(placed.territories.values.map(\.frame)))
        #expect(placed.apps["atlas/home/photos"]!.minX > placed.apps["atlas/home/notes"]!.maxX)
        #expect(!completed.hasConflicts(for: world))
    }

    @Test("the standard arrangement has no conflicts")
    func standardIsClean() {
        #expect(!Arrangement.standard(for: world).hasConflicts(for: world))
    }

    @Test("an instance that would share rows with another moves down, whole")
    func separating() {
        var arrangement = Arrangement.standard(for: world)
        for group in world.instances[1].groups {
            arrangement.groupOrigins[group.id]?.y -= 3000
        }
        #expect(arrangement.hasConflicts(for: world))
        let separated = arrangement.separated(for: world)
        #expect(!separated.hasConflicts(for: world))
        let before = arrangement.groupOrigins["borealis/lab"]!, after = separated.groupOrigins["borealis/lab"]!
        let system = arrangement.groupOrigins["borealis/farcast-system"]!, systemAfter = separated.groupOrigins["borealis/farcast-system"]!
        #expect(after.x == before.x && after.y > before.y)
        #expect(after.y - before.y == systemAfter.y - system.y)
        #expect(separated.groupOrigins["atlas/home"] == arrangement.groupOrigins["atlas/home"])
    }

    @Test("snapping lands on the grid")
    func snapping() {
        #expect(CGPoint(x: 29, y: -31).snapped == CGPoint(x: 20, y: -40))
    }
}

@Suite("How connections are drawn")
struct RouteTests {
    let world: World
    let geometry: WorldGeometry
    let routes: [String: Route]

    init() throws {
        world = try Fixtures.world()
        let index = WorldIndex(world)
        geometry = WorldGeometry(world: world, index: index, arrangement: .standard(for: world))
        routes = Router.routes(world: world, index: index, geometry: geometry)
    }

    @Test("every connection has a route")
    func complete() {
        #expect(Set(routes.keys) == Set(world.connections.map(\.id)))
    }

    @Test("egress leaves through the OUT gate and arrives at its host")
    func egress() {
        let route = routes["e2"]!  // photos → maps
        let gate = geometry.territories["atlas"]!.outGate
        #expect(route.segments.count == 2)
        #expect(route.segments[0].end == gate)
        #expect(route.segments[1].start == gate)
        #expect(route.segments[1].end.x == geometry.hosts["maps"]!.minX)
        #expect(route.end == .arrow)
    }

    @Test("a denied connection stops at the wall")
    func denied() {
        let route = routes["e5"]!  // forge → tracker, refused
        #expect(route.segments.count == 1)
        #expect(route.segments[0].end == geometry.territories["atlas"]!.outGate)
        #expect(route.end == .wall)
    }

    @Test("the tunnel climbs in the corridor, then comes in through the IN gate to FatLine")
    func tunnel() {
        let route = routes["e10"]!
        let gate = geometry.territories["atlas"]!.inGate
        #expect(route.segments.count == 3)
        #expect(route.segments[0].start.x == geometry.devices["mac"]!.maxX)
        #expect(route.segments[0].end == CGPoint(x: geometry.corridorX, y: gate.y))
        #expect(route.segments[1].end == gate)
        #expect(route.segments[2].end.x == geometry.apps["atlas/farcast-system/fatline"]!.minX)
        let left = geometry.territories.values.map(\.frame.minX).min()!
        #expect(geometry.devices["mac"]!.maxX < geometry.corridorX && geometry.corridorX < left)
    }

    @Test("no device line crosses an instance it is not going into")
    func deviceLinesStayOut() {
        for connection in world.connections where connection.kind == .tunnel || connection.kind == .keeper {
            let target = WorldIndex(world).instanceID(of: connection)!
            let route = routes[connection.id]!
            for segment in route.segments.dropLast() {
                for step in 0...40 {
                    let point = segment.point(at: CGFloat(step) / 40)
                    for (id, territory) in geometry.territories where id != target {
                        #expect(!territory.frame.insetBy(dx: 1, dy: 1).contains(point))
                    }
                }
            }
        }
    }

    @Test("lines leaving one panel leave it apart")
    func spread() {
        let maps = routes["e2"]!.segments[0].start, cdn = routes["e3"]!.segments[0].start
        #expect(abs(maps.y - cdn.y) == Metrics.lineSpread)
    }

    @Test("a segment's ends are its first and last points")
    func bezier() {
        let segment = routes["e6"]!.segments[0]
        #expect(segment.point(at: 0) == segment.start)
        #expect(segment.point(at: 1) == segment.end)
    }

    @Test("the filter keeps boundary and inside apart, and storage to the focused app")
    func filter() {
        let byID = Dictionary(uniqueKeysWithValues: world.connections.map { ($0.id, $0) })
        let egress = byID["e1"]!, link = byID["e6"]!, storage = byID["e12"]!
        #expect(ConnectionFilter.boundary.shows(egress, focus: nil))
        #expect(!ConnectionFilter.boundary.shows(link, focus: nil))
        #expect(ConnectionFilter.inside.shows(link, focus: nil))
        #expect(!ConnectionFilter.all.shows(storage, focus: nil))
        #expect(!ConnectionFilter.all.shows(storage, focus: "atlas/home/photos"))
        #expect(ConnectionFilter.all.shows(storage, focus: "atlas/home/notes"))
        #expect(!ConnectionFilter.boundary.shows(storage, focus: "atlas/home/notes"))
        #expect(!ConnectionFilter.off.shows(egress, focus: nil))
        #expect(Emphasis(egress, focus: "atlas/home/notes") == .lifted)
        #expect(Emphasis(egress, focus: "atlas/home/photos") == .dimmed)
        #expect(Emphasis(egress, focus: nil) == .normal)
    }

    @Test("a refused tunnel stops at the IN gate")
    func refusedTunnel() throws {
        var world = self.world
        let i = try #require(world.connections.firstIndex { $0.id == "e10" })
        world.connections[i].evidence = .denied
        let index = WorldIndex(world)
        let geometry = WorldGeometry(world: world, index: index, arrangement: .standard(for: world))
        let route = try #require(Router.routes(world: world, index: index, geometry: geometry)["e10"])
        #expect(route.segments.count == 2)
        #expect(route.segments.last!.end == geometry.territories["atlas"]!.inGate)
        #expect(route.end == .wall)
    }

    @Test("labels of lines reaching one host stand apart")
    func stackedLabels() throws {
        var world = self.world
        world.connections.append(Connection(
            id: "x", from: .app("atlas/home/notes"), to: .host("maps"), kind: .egress, evidence: .observed, label: "3 ok"
        ))
        let index = WorldIndex(world)
        let geometry = WorldGeometry(world: world, index: index, arrangement: .standard(for: world))
        let routes = Router.routes(world: world, index: index, geometry: geometry)
        // One point, two places in the stack; the drawing spreads them in
        // screen points.
        #expect(routes["e2"]!.labelPoint == routes["x"]!.labelPoint)
        #expect(Set([routes["e2"]!.labelStack.index, routes["x"]!.labelStack.index]) == [0, 1])
        #expect(routes["e2"]!.labelStack.count == 2)
        #expect(routes["e1"]!.labelStack.count == 1)
    }

    @Test("however many lines leave a panel, they leave it within its edge")
    func spreadStaysOnThePanel() throws {
        var world = self.world
        for n in 0..<24 {
            world.connections.append(Connection(
                id: "s\(n)", from: .app("atlas/home/notes"), to: .host("sync"), kind: .egress, evidence: .observed, label: ""
            ))
        }
        let index = WorldIndex(world)
        let geometry = WorldGeometry(world: world, index: index, arrangement: .standard(for: world))
        let panel = geometry.apps["atlas/home/notes"]!
        let routes = Router.routes(world: world, index: index, geometry: geometry)
        let leaving = world.connections.filter { $0.from == .app("atlas/home/notes") && $0.kind == .egress }
        #expect(leaving.count == 25)
        for connection in leaving {
            let y = routes[connection.id]!.segments[0].start.y
            #expect(panel.minY < y && y < panel.maxY)
        }
    }

    @Test("side by side is a conflict: instances are rows, lines run sideways between them")
    func sideBySide() {
        let index = WorldIndex(world)
        var arrangement = Arrangement.standard(for: world)
        let atlas = WorldGeometry(world: world, index: index, arrangement: arrangement).territories["atlas"]!.frame
        let borealis = WorldGeometry(world: world, index: index, arrangement: arrangement).territories["borealis"]!.frame
        for group in world.instances[1].groups {
            arrangement.groupOrigins[group.id]?.x += atlas.maxX + 3000 - borealis.minX
            arrangement.groupOrigins[group.id]?.y += atlas.minY - borealis.minY
        }
        let moved = WorldGeometry(world: world, index: index, arrangement: arrangement)
        #expect(!moved.territories["atlas"]!.frame.intersects(moved.territories["borealis"]!.frame))
        #expect(arrangement.hasConflicts(for: world))
    }

    @Test("a group that grew onto a sibling moves below its instance's groups; the others stay")
    func grownGroup() {
        let standard = Arrangement.standard(for: world)
        var saved = standard
        // dev sits below home in column 1. Give home's row a third app, as if
        // photos had been added after home's other apps were placed at the
        // far right: it lands where dev would collide.
        saved.appOffsets["atlas/home/photos"] = nil
        saved.appOffsets["atlas/home/notes"] = CGPoint(x: 0, y: 900)
        let completed = saved.completed(for: world, from: standard)
        #expect(!completed.hasConflicts(for: world))
        #expect(completed.groupOrigins["atlas/dev"] == standard.groupOrigins["atlas/dev"])
        #expect(completed.groupOrigins["atlas/farcast-system"] == standard.groupOrigins["atlas/farcast-system"])
    }

    @Test("a new instance takes no one's place: it goes below the instances already placed")
    func newInstanceGoesLast() {
        var world = self.world
        world.instances.insert(Instance(
            id: "andromeda",
            spending: Spending(expectedCents: 0, limitCents: 1000),
            groups: [AppGroup(
                id: "andromeda/farcast-system", namespace: "farcast-system", source: "FarCast", isSystem: true,
                apps: [Application(id: "andromeda/farcast-system/fatline", name: "FatLine", role: "network boundary", state: .running, system: .boundary)]
            )]
        ), at: 0)
        let saved = Arrangement.standard(for: self.world)
        let completed = saved.completed(for: world, from: Arrangement.standard(for: world))
        #expect(completed.groupOrigins["atlas/home"] == saved.groupOrigins["atlas/home"])
        #expect(completed.groupOrigins["borealis/lab"] == saved.groupOrigins["borealis/lab"])
        let placed = WorldGeometry(world: world, index: WorldIndex(world), arrangement: completed)
        #expect(placed.territories["andromeda"]!.frame.minY > placed.territories["borealis"]!.frame.maxY)
        #expect(!completed.hasConflicts(for: world))
    }

    @Test("the standard arrangement keeps a tall stack of hosts out of the next instance's rows")
    func standardSeparatesHosts() {
        var world = self.world
        for n in 0..<8 {
            world.hosts.append(Host(id: "x\(n)", name: "x\(n).example.test", instanceID: "atlas", note: "illustrative"))
            world.connections.append(Connection(
                id: "xe\(n)", from: .app("atlas/shop/worker"), to: .host("x\(n)"), kind: .egress, evidence: .planned, label: ""
            ))
        }
        #expect(!Arrangement.standard(for: world).hasConflicts(for: world))
    }

    @Test("an app that comes back onto a sibling moves to the right of its group")
    func returningApp() {
        let standard = Arrangement.standard(for: world)
        var saved = standard
        saved.appOffsets["atlas/home/photos"] = saved.appOffsets["atlas/home/notes"]
        let completed = saved.completed(for: world, from: standard)
        #expect(!completed.hasConflicts(for: world))
        #expect(completed.appOffsets["atlas/home/notes"] == standard.appOffsets["atlas/home/notes"])
        #expect(completed.appOffsets["atlas/home/photos"]!.x > completed.appOffsets["atlas/home/notes"]!.x)
    }
}
