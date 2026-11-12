import Foundation

/// Where a world comes from, one instance at a time (ADR 0021 decision 9,
/// amended 2026-11-12). The feed lists the instances, then reads each one,
/// only when the operator asks; nothing reads on a timer.
///
/// `readWorld(_:)` returns a world holding that one instance. Every host,
/// connection and alert id in it is prefixed `<instance>/`, a keeper's device
/// id is `<instance>/<keeper>`, and the operator's device is `operator`, so
/// worlds read from several instances compose without colliding
/// (`World.validate(asReadOf:source:)`).
///
/// A reader honours cancellation: the feed cancels a read that ran out of
/// time, or that was running when the app quit, and a reader that runs a
/// process ends it. The feed does not rely on that to get control back.
public protocol WorldReader: Sendable {
    var source: World.Source { get }
    func listInstances() async throws(ReadFailure) -> [InstanceListing]
    func readWorld(_ instance: String) async throws(ReadFailure) -> World
}

/// Why a listing or a read failed, as a stable kind and the CLI's message.
public struct ReadFailure: Error, Sendable, Equatable {
    public var kind: SectionProblem.Kind
    public var message: String

    public init(kind: SectionProblem.Kind, message: String) {
        self.kind = kind
        self.message = message
    }
}

/// One instance as this Mac's records list it, before anything is read
/// from it: what the instance list command reads from local files alone.
public struct InstanceListing: Sendable, Equatable, Identifiable {
    public var name: String
    public var status: Instance.Status
    public var cloudLogging: Instance.CloudLogging
    /// The local record's cost limit; nil when the record is unreadable.
    public var recordedLimitCents: Int?
    /// Which of FarCast's components the local record says were deployed.
    /// A role missing here is not known either way.
    public var components: [SystemRole: Bool]
    /// Set when the record itself could not be read.
    public var problem: SectionProblem?
    /// Whether the record pins the gcloud account the instance is read as;
    /// nil when the record could not be read. `farcast world` reads nothing
    /// without a pin.
    public var gcloudPinned: Bool?

    public var id: String { name }

    /// The record's cost limit, when it is one the map can state: nil when
    /// the record holds none, or one that is not a positive sum in range.
    public var drawableLimitCents: Int? {
        recordedLimitCents.flatMap { (1...World.maxCents).contains($0) ? $0 : nil }
    }

    /// What is wrong with the record, said where the map shows the instance
    /// rather than refusing it: the listing's own problem; a limit that is
    /// not one (`drawableLimitCents`); and a record that was read, with a
    /// status, but holds no limit, when every instance has one set at
    /// creation (AGENTS.md). Each is a problem with the record, so one bad
    /// record never keeps the instance, or any other, off the map.
    public var recordProblems: [SectionProblem] {
        var problems = problem.map { [$0] } ?? []
        if let cents = recordedLimitCents, drawableLimitCents == nil {
            problems.append(SectionProblem(
                section: .record, kind: .internal,
                message: "the record's cost limit is not one: \(cents) cents"
            ))
        } else if recordedLimitCents == nil, status != .unknown, !problems.contains(where: { $0.section == .record }) {
            problems.append(SectionProblem(section: .record, kind: .internal, message: "the record holds no cost limit"))
        }
        return problems
    }

    public init(
        name: String,
        status: Instance.Status = .unknown,
        cloudLogging: Instance.CloudLogging = .unknown,
        recordedLimitCents: Int? = nil,
        components: [SystemRole: Bool] = [:],
        problem: SectionProblem? = nil,
        gcloudPinned: Bool? = nil
    ) {
        self.name = name
        self.status = status
        self.cloudLogging = cloudLogging
        self.recordedLimitCents = recordedLimitCents
        self.components = components
        self.problem = problem
        self.gcloudPinned = gcloudPinned
    }
}

extension Instance {
    /// The namespace FarCast's own components run in.
    public static let systemNamespace = "farcast-system"

    /// An instance listed but not read yet, or whose read never succeeded:
    /// its territory, its system group with FarCast's four components in an
    /// unknown state — or not deployed, where the record says so — and no
    /// figure that was not read. The apps' ids are the canonical ones a full
    /// read uses, so their places carry over when it lands.
    ///
    /// It always validates: a record limit that is not one is left out and
    /// said as a problem with the record (`InstanceListing.recordProblems`).
    public static func notYetRead(_ listing: InstanceListing) -> Instance {
        let name = listing.name
        return Instance(
            id: name,
            spending: Spending(recordedLimitCents: listing.drawableLimitCents),
            groups: [AppGroup(
                id: "\(name)/\(systemNamespace)",
                namespace: systemNamespace,
                source: "FarCast",
                isSystem: true,
                apps: SystemComponent.all.map { component in
                    Application(
                        id: SystemComponent.appID(component.role, in: name),
                        name: component.name,
                        role: component.summary,
                        state: listing.components[component.role] == false ? .notDeployed : .unknown,
                        system: component.role
                    )
                }
            )],
            status: listing.status,
            readAt: nil,
            problems: listing.recordProblems,
            cloudLogging: listing.cloudLogging
        )
    }
}

/// FarCast's own four components, as the map draws them in every
/// instance's system group: one table, so an instance listed and not read
/// and one read from `farcast world` name the same apps the same way, and
/// their places on the map carry over from one to the other.
public struct SystemComponent: Sendable, Equatable {
    public let role: SystemRole
    /// The last part of the app's id: technocore, shrike, fatline, datasphere.
    public let slug: String
    /// TechnoCore, Shrike, FatLine, DataSphere.
    public let name: String
    /// The glance line under the name.
    public let summary: String

    /// In the order the system group lists them.
    public static let all: [SystemComponent] = [
        SystemComponent(role: .kernel, slug: "technocore", name: "TechnoCore", summary: "kernel · cost and resources"),
        SystemComponent(role: .monitor, slug: "shrike", name: "Shrike", summary: "traffic monitor"),
        SystemComponent(role: .boundary, slug: "fatline", name: "FatLine", summary: "network boundary"),
        SystemComponent(role: .storage, slug: "datasphere", name: "DataSphere", summary: "storage and keys"),
    ]

    /// The id of the app that plays `role` in `instance`:
    /// `<instance>/farcast-system/<slug>`.
    public static func appID(_ role: SystemRole, in instance: String) -> String {
        let slug = all.first { $0.role == role }?.slug ?? role.rawValue
        return "\(instance)/\(Instance.systemNamespace)/\(slug)"
    }
}

extension World {
    /// The device id of the operator's own Mac in a world read from an
    /// instance.
    public static let operatorDeviceID = "operator"

    /// Checks a world a reader returned for `name`: it validates on its own,
    /// it came from `expected`, it holds that one instance and nothing else,
    /// and its ids carry the instance's prefix, so it composes with the
    /// worlds read from other instances without a collision.
    public func validate(asReadOf name: String, source expected: Source) throws(WorldError) {
        var problems: [String] = []
        do throws(WorldError) {
            try validate()
        } catch {
            problems = error.problems
        }
        let prefix = "\(name)/"
        if source != expected {
            problems.append("the read of \(name) is \(source.rawValue), not \(expected.rawValue)")
        }
        if instances.map(\.id) != [name] {
            problems.append("the read of \(name) holds \(instances.map(\.id)), not that one instance")
        }
        for host in hosts where !host.id.hasPrefix(prefix) {
            problems.append("host \(host.id) is not under \(prefix)")
        }
        for connection in connections where !connection.id.hasPrefix(prefix) {
            problems.append("connection \(connection.id) is not under \(prefix)")
        }
        for alert in alerts where !alert.id.hasPrefix(prefix) {
            problems.append("alert \(alert.id) is not under \(prefix)")
        }
        for device in devices {
            switch device.role {
            case .operator where device.id != Self.operatorDeviceID:
                problems.append("the operator's device is \(device.id), not \(Self.operatorDeviceID)")
            case .keeper where !device.id.hasPrefix(prefix):
                problems.append("keeper \(device.id) is not under \(prefix)")
            case .operator, .keeper:
                break
            }
        }
        if !problems.isEmpty { throw WorldError(problems: problems) }
    }
}

/// Runs `operation`, and gives up on it once `limit` has passed on `clock`,
/// whichever comes first. The loser is cancelled.
///
/// Control comes back by the deadline even when `operation` ignores
/// cancellation: the two race as separate tasks and the first to finish
/// answers, which a task group or `async let` would not do — each waits for
/// every child to finish. Returns nil when the calling task is cancelled.
public func withDeadline<T: Sendable>(
    _ limit: Duration,
    on clock: any Clock<Duration>,
    _ operation: @escaping @Sendable () async throws(ReadFailure) -> T
) async -> Result<T, ReadFailure>? {
    let (stream, continuation) = AsyncStream.makeStream(of: Result<T, ReadFailure>.self)
    let work = Task {
        do throws(ReadFailure) {
            continuation.yield(.success(try await operation()))
        } catch {
            continuation.yield(.failure(error))
        }
    }
    let timer = Task {
        do {
            try await clock.sleep(for: limit)
        } catch {
            return  // cancelled: the operation answered first
        }
        continuation.yield(.failure(ReadFailure(
            kind: .timeout,
            message: "no answer within \(limit.components.seconds) seconds"
        )))
    }
    defer {
        work.cancel()
        timer.cancel()
        continuation.finish()
    }
    var first = stream.makeAsyncIterator()
    return await first.next()
}
