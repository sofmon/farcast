import Foundation
import FarSightCore

/// The world FarSight draws where it reads no instance: on iPhone, iPad and
/// Vision Pro until they have a device leaf and the read route, and wherever
/// the Connected view is not in use (ADR 0021 decision 9). Two instances
/// with their apps, devices, hosts and connections, as the prototype canvas
/// drew them. Every name and figure in it is illustrative; nothing is read
/// from a live instance, and its `source` says so.
public enum Fixtures {
    public enum Failure: Error, Equatable {
        case missing
    }

    /// The fixture world, decoded and validated.
    public static func world() throws -> World {
        guard let url = Bundle.module.url(forResource: "world", withExtension: "json") else {
            throw Failure.missing
        }
        let world = try World.decoder().decode(World.self, from: Data(contentsOf: url))
        try world.validate()
        return world
    }
}

/// A `WorldReader` over the fixture: it lists the fixture's instances and
/// reads each one as a slice of it, with ids made the way a reader makes
/// them (`WorldReader`). It reads nothing and reaches nothing; what it
/// returns is as illustrative as the fixture, and says so in `source`.
public struct FixtureReader: WorldReader {
    public let source: World.Source = .fixture
    private let world: World

    public init() throws {
        world = try Fixtures.world()
    }

    /// Over another fixture-shaped world, as tests use it.
    public init(world: World) {
        self.world = world
    }

    public func listInstances() async throws(ReadFailure) -> [InstanceListing] {
        world.instances.map { instance in
            InstanceListing(
                name: instance.id,
                status: instance.status,
                cloudLogging: instance.cloudLogging,
                recordedLimitCents: instance.spending.recordedLimitCents ?? instance.spending.limitCents,
                components: Dictionary(uniqueKeysWithValues: SystemRole.allCases.map { role in
                    (role, instance.groups.contains { $0.isSystem && $0.apps.contains { $0.system == role } })
                })
            )
        }
    }

    public func readWorld(_ name: String) async throws(ReadFailure) -> World {
        guard let instance = world.instances.first(where: { $0.id == name }) else {
            throw ReadFailure(kind: .notFound, message: "no instance \(name) in the fixture")
        }
        return Self.slice(world, instance)
    }

    /// One instance of `world`, with what belongs to it, its ids prefixed.
    static func slice(_ world: World, _ instance: Instance) -> World {
        let index = WorldIndex(world)
        let name = instance.id
        let connections = world.connections.filter { index.instanceID(of: $0) == name }
        var deviceIDs = Set<String>()
        for connection in connections {
            for end in [connection.from, connection.to] {
                if case .device(let id) = end { deviceIDs.insert(id) }
            }
        }
        func device(_ id: String) -> String {
            index.devices[id]?.role == .operator ? World.operatorDeviceID : "\(name)/\(id)"
        }
        func host(_ id: String) -> String { "\(name)/\(id)" }
        func end(_ endpoint: Endpoint) -> Endpoint {
            switch endpoint {
            case .app: endpoint
            case .host(let id): .host(host(id))
            case .device(let id): .device(device(id))
            }
        }
        let apps = Set(instance.groups.flatMap(\.apps).map(\.id))
        let alerts = world.alerts.filter { alert in
            switch alert.subject {
            case .app(let id): apps.contains(id)
            case .instance(let id): id == name
            case .device(let id): deviceIDs.contains(id)
            }
        }
        return World(
            instances: [instance],
            devices: world.devices.filter { deviceIDs.contains($0.id) }.map { original in
                var copy = original
                copy.id = device(original.id)
                return copy
            },
            hosts: world.hosts.filter { $0.instanceID == name }.map { original in
                var copy = original
                copy.id = host(original.id)
                return copy
            },
            connections: connections.map { original in
                var copy = original
                copy.id = "\(name)/\(original.id)"
                copy.from = end(original.from)
                copy.to = end(original.to)
                return copy
            },
            alerts: alerts.map { original in
                var copy = original
                copy.id = "\(name)/\(original.id)"
                if case .device(let id) = original.subject { copy.subject = .device(device(id)) }
                return copy
            },
            source: world.source
        )
    }
}
