import Foundation
import FarSightCore

/// The world FarSight draws until the read route exists (ADR 0021 decision 9,
/// step 1): two instances with their apps, devices, hosts and connections, as
/// the prototype canvas drew them. Every name and figure in it is
/// illustrative; nothing is read from a live instance.
public enum Fixtures {
    public enum Failure: Error, Equatable {
        case missing
    }

    /// The fixture world, decoded and validated.
    public static func world() throws -> World {
        guard let url = Bundle.module.url(forResource: "world", withExtension: "json") else {
            throw Failure.missing
        }
        let world = try JSONDecoder().decode(World.self, from: Data(contentsOf: url))
        try world.validate()
        return world
    }
}
