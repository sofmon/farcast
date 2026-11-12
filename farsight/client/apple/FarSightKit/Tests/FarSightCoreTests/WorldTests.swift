import Foundation
import Testing
@testable import FarSightCore
import FarSightFixtures

@Suite("The world snapshot")
struct WorldTests {
    @Test("the fixture decodes and validates")
    func fixtureIsValid() throws {
        let world = try Fixtures.world()
        #expect(world.instances.map(\.id) == ["atlas", "borealis"])
        #expect(world.instances.allSatisfy { $0.groups.contains(where: \.isSystem) })
    }

    @Test("endpoints round-trip through their text form")
    func endpointCoding() throws {
        let endpoints: [Endpoint] = [.app("atlas/home/notes"), .host("sync"), .device("mac")]
        let data = try JSONEncoder().encode(endpoints)
        #expect(String(decoding: data, as: UTF8.self) == #"["app:atlas\/home\/notes","host:sync","device:mac"]"#)
        #expect(try JSONDecoder().decode([Endpoint].self, from: data) == endpoints)
    }

    @Test("malformed endpoints are refused", arguments: [#""notes""#, #""app:""#, #""route:x""#, #"":x""#])
    func endpointRefusal(text: String) {
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(Endpoint.self, from: Data(text.utf8))
        }
    }

    @Test("validation names every problem it finds")
    func validationCatchesBrokenSnapshots() throws {
        var world = try Fixtures.world()
        world.connections.append(Connection(
            id: "x1", from: .app("atlas/home/notes"), to: .app("borealis/lab/wiki"),
            kind: .appToApp, evidence: .planned, label: "across"
        ))
        world.connections.append(Connection(
            id: "x2", from: .app("atlas/home/notes"), to: .host("nowhere"),
            kind: .egress, evidence: .observed, label: "?"
        ))
        world.connections.append(Connection(
            id: "x3", from: .device("mac"), to: .app("atlas/home/notes"),
            kind: .tunnel, evidence: .observed, label: "?"
        ))
        world.alerts.append(WorldAlert(id: "x4", kind: .cost, severity: .warning, title: "?", subject: .app("atlas/ghost")))
        world.instances[0].spending.limitCents = 0

        #expect {
            try world.validate()
        } throws: { error in
            guard let error = error as? WorldError else { return false }
            let text = error.description
            return text.contains("x1 joins two instances")
                && text.contains("x2 ends at unknown host:nowhere")
                && text.contains("x3 does not end at the instance's boundary")
                && text.contains("x4 points at unknown app")
                && text.contains("atlas has no cost limit")
        }
    }

    @Test("an instance without FatLine has no gate to draw, so it is refused")
    func boundaryIsRequired() throws {
        var world = try Fixtures.world()
        world.instances[1].groups[0].apps.removeAll { $0.system == .boundary }
        world.connections.removeAll { $0.to == .app("borealis/farcast-system/fatline") || $0.from == .app("borealis/farcast-system/shrike") }
        #expect(throws: WorldError.self) { try world.validate() }
    }

    @Test("crossing the wall is a property of the kind")
    func wallCrossing() {
        let crossing = Connection.Kind.allCases.filter {
            Connection(id: "c", from: .app("a"), to: .app("b"), kind: $0, evidence: .observed, label: "").crossesWall
        }
        #expect(Set(crossing) == [.egress, .tunnel, .keeper])
    }

    func problems(_ change: (inout World) -> Void) throws -> String {
        var world = try Fixtures.world()
        change(&world)
        do {
            try world.validate()
            return ""
        } catch {
            return error.description
        }
    }

    @Test("app to app is only ever planned, and only between illustrative apps")
    func appToAppIsNotBuilt() throws {
        let observed = try problems { world in
            world.connections[world.connections.firstIndex { $0.id == "e6" }!].evidence = .observed
        }
        #expect(observed.contains("e6 must be planned and between illustrative apps"))
        let real = try problems { world in
            world.connections.append(Connection(
                id: "x", from: .app("atlas/home/notes"), to: .app("atlas/home/photos"), kind: .appToApp, evidence: .planned, label: ""
            ))
        }
        #expect(real.contains("x must be planned and between illustrative apps"))
    }

    @Test("only a wall refuses")
    func onlyWallsRefuse() throws {
        let text = try problems { world in
            world.connections[world.connections.firstIndex { $0.id == "e12" }!].evidence = .denied
        }
        #expect(text.contains("e12 is marked denied, but only a wall refuses"))
        #expect(try problems { world in
            world.connections[world.connections.firstIndex { $0.id == "e10" }!].evidence = .denied
        }.isEmpty)
    }

    @Test("one system group, one app per role, Shrike watching FatLine, no loops")
    func systemShape() throws {
        let twoRoles = try problems { world in
            world.instances[0].groups[0].apps[1].system = .kernel
        }
        #expect(twoRoles.contains("two apps in the kernel role"))
        let twoGroups = try problems { world in
            world.instances[0].groups[1].isSystem = true
            for i in world.instances[0].groups[1].apps.indices { world.instances[0].groups[1].apps[i].system = .monitor }
        }
        #expect(twoGroups.contains("2 system groups"))
        let watch = try problems { world in
            world.connections[world.connections.firstIndex { $0.id == "e9" }!].from = .app("atlas/home/notes")
        }
        #expect(watch.contains("e9 is not Shrike watching FatLine"))
        let loop = try problems { world in
            world.connections.append(Connection(id: "x", from: .host("sync"), to: .host("sync"), kind: .egress, evidence: .observed, label: ""))
        }
        #expect(loop.contains("x starts and ends at host:sync"))
    }

    @Test("money out of range is refused")
    func moneyRange() throws {
        let text = try problems { world in
            world.instances[0].spending.expectedCents = Int.min
            world.instances[1].spending.limitCents = Int.max
            world.instances[0].groups[1].apps[0].monthCents = -1
        }
        #expect(text.contains("atlas's expected spending is out of range"))
        #expect(text.contains("borealis's cost limit is out of range"))
        #expect(text.contains("atlas/home/notes's spending is out of range"))
    }

    @Test("an illustrative app is not a deployment: only planned lines, no spending")
    func illustrativeStaysIllustrative() throws {
        let observed = try problems { world in
            world.connections[world.connections.firstIndex { $0.id == "e8" }!].evidence = .observed
        }
        #expect(observed.contains("e8 touches an illustrative app, so it can only be planned"))
        let spending = try problems { world in
            world.instances[0].groups[3].apps[0].monthCents = 100
        }
        #expect(spending.contains("illustrative app atlas/shop/web has spending"))
        let mixed = try problems { world in
            world.instances[0].groups[3].apps[0].isIllustrative = false
        }
        #expect(mixed.contains("atlas/shop/web and its group disagree"))
    }

    @Test("the tunnel comes from the operator's device, a keeper's line from a keeper")
    func deviceRoles() throws {
        let text = try problems { world in
            world.connections[world.connections.firstIndex { $0.id == "e10" }!].from = .device("ubuntu-vm")
            world.connections[world.connections.firstIndex { $0.id == "e11" }!].from = .device("mac")
        }
        #expect(text.contains("tunnel e10 does not start at an operator's device"))
        #expect(text.contains("keeper e11 does not start at a keeper device"))
    }

    @Test("nothing happens to a sketch: no alert, no stop, and FarCast itself is never one")
    func sketchesAreQuiet() throws {
        let alert = try problems { world in
            world.alerts.append(WorldAlert(id: "x", kind: .denied, severity: .warning, title: "api: 3 denied", subject: .app("atlas/shop/api")))
        }
        #expect(alert.contains("alert x is about illustrative app atlas/shop/api"))
        let stopped = try problems { world in
            world.instances[0].groups[3].apps[0].state = .stopped
        }
        #expect(stopped.contains("illustrative app atlas/shop/web is stopped"))
        let system = try problems { world in
            world.instances[0].groups[0].isIllustrative = true
        }
        #expect(system.contains("atlas's system group is illustrative"))
    }
}
