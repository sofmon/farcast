import Foundation

/// Everything the map draws: the operator's instances and the apps running in
/// them, the operator's own devices, the hosts outside, and the connections
/// between them.
///
/// It is a snapshot, and it says where it came from (`source`). A fixture
/// world is illustrative. A live world arrives from the Connected view's
/// reader, one instance at a time, when the operator asks for a read (ADR
/// 0021 decision 9, amended 2026-11-12); the read route is to deliver it
/// later, through FatLine. Nothing in it is hidden by the map: every app has
/// a place, a stopped one included.
public struct World: Codable, Sendable, Equatable {
    public var instances: [Instance]
    public var devices: [Device]
    public var hosts: [Host]
    public var connections: [Connection]
    public var alerts: [WorldAlert]
    /// Illustrative, or read from instances. A live world never holds the
    /// fixture's illustrative groups, apps or planned lines (`validate()`).
    public var source: Source

    public init(
        instances: [Instance],
        devices: [Device] = [],
        hosts: [Host] = [],
        connections: [Connection] = [],
        alerts: [WorldAlert] = [],
        source: Source = .live
    ) {
        self.instances = instances
        self.devices = devices
        self.hosts = hosts
        self.connections = connections
        self.alerts = alerts
        self.source = source
    }

    /// A snapshot that does not say where it came from is held to the live
    /// rules, the stricter ones.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        instances = try container.decode([Instance].self, forKey: .instances)
        devices = try container.decode([Device].self, forKey: .devices)
        hosts = try container.decode([Host].self, forKey: .hosts)
        connections = try container.decode([Connection].self, forKey: .connections)
        alerts = try container.decode([WorldAlert].self, forKey: .alerts)
        source = try container.decodeIfPresent(Source.self, forKey: .source) ?? .live
    }

    public enum Source: String, Codable, Sendable, Equatable, CaseIterable {
        /// Illustrative: drawn from `world.json`, read from nothing.
        case fixture
        /// Read from the operator's instances.
        case live

        /// A source this build does not know is held to the live rules.
        public init(from decoder: any Decoder) throws {
            let raw = try decoder.singleValueContainer().decode(String.self)
            self = Source(rawValue: raw) ?? .live
        }
    }

    /// A decoder for a world as `world.json` writes it: times are RFC 3339,
    /// to the second.
    public static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }

    /// An encoder that writes what `decoder()` reads.
    public static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }
}

/// One FarCast instance: its own territory on the map, with nothing drawn
/// between it and any other instance, because nothing runs between them.
public struct Instance: Codable, Sendable, Equatable, Identifiable {
    public var id: String
    public var spending: Spending
    public var groups: [AppGroup]
    /// What the local record says, verbatim.
    public var status: Status
    /// When the instance was read; nil for the fixture and for an instance
    /// listed but not read yet.
    public var readAt: Date?
    /// Every part of the read that failed. A section that could not be read
    /// says so here instead of disappearing.
    public var problems: [SectionProblem]
    public var cloudLogging: CloudLogging
    /// Which FatLine replica counted the instance's lines, and since when;
    /// nil when the network was not read.
    public var network: NetworkReading?
    /// What the read saw and could not draw, in the CLI's words: rows that
    /// name no app on the map, an app the monitor names that is not
    /// running. Shown through `Display.message`.
    public var caveats: [String]

    public init(
        id: String,
        spending: Spending,
        groups: [AppGroup],
        status: Status = .unknown,
        readAt: Date? = nil,
        problems: [SectionProblem] = [],
        cloudLogging: CloudLogging = .unknown,
        network: NetworkReading? = nil,
        caveats: [String] = []
    ) {
        self.id = id
        self.spending = spending
        self.groups = groups
        self.status = status
        self.readAt = readAt
        self.problems = problems
        self.cloudLogging = cloudLogging
        self.network = network
        self.caveats = caveats
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        spending = try container.decode(Spending.self, forKey: .spending)
        groups = try container.decode([AppGroup].self, forKey: .groups)
        status = try container.decodeIfPresent(Status.self, forKey: .status) ?? .unknown
        readAt = try container.decodeIfPresent(Date.self, forKey: .readAt)
        problems = try container.decodeIfPresent([SectionProblem].self, forKey: .problems) ?? []
        cloudLogging = try container.decodeIfPresent(CloudLogging.self, forKey: .cloudLogging) ?? .unknown
        network = try container.decodeIfPresent(NetworkReading.self, forKey: .network)
        caveats = try container.decodeIfPresent([String].self, forKey: .caveats) ?? []
    }

    /// The instance's status as its local record holds it.
    public enum Status: String, Codable, Sendable, Equatable, CaseIterable, UnknownDecodable {
        case provisioning
        case running
        case unreachable
        /// A release that did not finish: the instance may still be billing.
        case deleting
        case error
        case unknown

        public var label: String {
            switch self {
            case .provisioning: "provisioning"
            case .running: "running"
            case .unreachable: "unreachable"
            case .deleting: "release incomplete, may still be billing"
            case .error: "error"
            case .unknown: "status unknown"
            }
        }
    }

    /// Whether the cluster sends only system logs to the provider's logging.
    public enum CloudLogging: String, Codable, Sendable, Equatable, CaseIterable, UnknownDecodable {
        case systemOnly
        /// The record says nothing: the setting was never confirmed.
        case unverified
        case unknown
    }

    /// The problem the read had with `section`, if any.
    public func problem(in section: SectionProblem.Section) -> SectionProblem? {
        problems.first { $0.section == section }
    }
}

/// What counted every line of an instance: one FatLine replica's monitor,
/// since it started (ADR 0022 decision 9). Counts are floors.
public struct NetworkReading: Codable, Sendable, Equatable {
    /// The Pod; nil when the monitor did not say.
    public var replica: String?
    public var since: Date?
    /// How many FatLine replicas run; nil when not read.
    public var fatlineReplicas: Int?

    public init(replica: String? = nil, since: Date? = nil, fatlineReplicas: Int? = nil) {
        self.replica = replica
        self.since = since
        self.fatlineReplicas = fatlineReplicas
    }
}

/// One part of an instance's read that failed, and why.
public struct SectionProblem: Codable, Sendable, Equatable, Hashable {
    public var section: Section
    public var kind: Kind
    /// Written by the CLI; shown through `Display.message`.
    public var message: String

    public init(section: Section, kind: Kind, message: String) {
        self.section = section
        self.kind = kind
        self.message = message
    }

    /// Which part failed: one of the world document's sections, the local
    /// record, or the read as a whole (a timeout, a refused identity) — or,
    /// as `figures`, a spending figure a section that was read gave and the
    /// map cannot draw. That one is the map's own, never the CLI's: its
    /// section was read, and says so.
    public enum Section: String, Codable, Sendable, Equatable, Hashable, CaseIterable, UnknownDecodable {
        case record
        case read
        case spend
        case apps
        case policy
        case network
        case seal
        case figures
        case unknown
    }

    /// The CLI's stable error kinds, so the map tells "no tunnel", "no
    /// kernel", "version skew" and "signed out of gcloud" apart without
    /// reading prose.
    public enum Kind: String, Codable, Sendable, Equatable, Hashable, CaseIterable, UnknownDecodable {
        case recordUnreadable
        case notFound
        /// No FatLine recorded, so no tunnel.
        case notConnected
        case tunnelUnreachable
        case kernelAbsent
        case notCheckpointed
        case versionSkew
        case kubectlMissing
        case kubectlFailed
        case gcloudMismatch
        case gcloudSignedOut
        case authToolMissing
        case timeout
        case `internal`
        case unknown

        public var label: String {
            switch self {
            case .recordUnreadable: "record unreadable"
            case .notFound: "not found"
            case .notConnected: "no tunnel"
            case .tunnelUnreachable: "tunnel unreachable"
            case .kernelAbsent: "no kernel"
            case .notCheckpointed: "not checkpointed yet"
            case .versionSkew: "version skew"
            case .kubectlMissing: "kubectl missing"
            case .kubectlFailed: "kubectl failed"
            case .gcloudMismatch: "gcloud identity does not match"
            case .gcloudSignedOut: "signed out of gcloud"
            case .authToolMissing: "auth plugin missing"
            case .timeout: "timed out"
            case .internal: "internal error"
            case .unknown: "unknown error"
            }
        }
    }
}

/// Spending as TechnoCore reports it, never recomputed here (ADR 0009).
///
/// Two figures, not one: `confirmed` is the provider's own number for each
/// window that has closed, through `confirmedThrough`; `expected` is metered
/// locally for the open window, and is what protective action fires on. They
/// are never shown as one undifferentiated total (ADR 0009 decision 4):
/// `totalCents` is their sum as the kernel compares it, and only sets the
/// length of the bar.
public struct Spending: Codable, Sendable, Equatable {
    public var expectedCents: Int?
    public var confirmedCents: Int?
    /// What enforcement compares against the kernel's limit. Drawn as the
    /// bar's length, never printed as one figure.
    public var totalCents: Int?
    /// The kernel's own limit; nil unless spending was read, or when the
    /// kernel published none.
    public var limitCents: Int?
    /// The local record's limit; nil when the record could not be read.
    public var recordedLimitCents: Int?
    public var hasConfirmation: Bool
    public var confirmedThrough: Date?
    /// The kernel's level, as it last reconciled.
    public var level: Level
    public var currency: String
    /// Discrepancies and gaps the kernel or the CLI reported.
    public var caveats: [String]
    /// What the meter cannot see from inside the cluster.
    public var notMetered: [String]
    /// The kernel's checkpoint is older than three checkpoint intervals.
    public var isCheckpointStale: Bool
    /// Whether the kernel records that it is at the instance floor: every
    /// application stopped, and spending still over its limit (ADR 0009
    /// decision 8). Nil when not read, or when the kernel that wrote the
    /// checkpoint records no such thing — never read as "not at the floor".
    public var atFloor: Bool?
    /// The kernel's floor record, while it is at the floor.
    public var floor: SpendingFloor?

    public init(
        expectedCents: Int? = nil,
        confirmedCents: Int? = nil,
        totalCents: Int? = nil,
        limitCents: Int? = nil,
        recordedLimitCents: Int? = nil,
        hasConfirmation: Bool = false,
        confirmedThrough: Date? = nil,
        level: Level = .unknown,
        currency: String = "USD",
        caveats: [String] = [],
        notMetered: [String] = [],
        isCheckpointStale: Bool = false,
        atFloor: Bool? = nil,
        floor: SpendingFloor? = nil
    ) {
        self.expectedCents = expectedCents
        self.confirmedCents = confirmedCents
        self.totalCents = totalCents
        self.limitCents = limitCents
        self.recordedLimitCents = recordedLimitCents
        self.hasConfirmation = hasConfirmation
        self.confirmedThrough = confirmedThrough
        self.level = level
        self.currency = currency
        self.caveats = caveats
        self.notMetered = notMetered
        self.isCheckpointStale = isCheckpointStale
        self.atFloor = atFloor
        self.floor = floor
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        expectedCents = try container.decodeIfPresent(Int.self, forKey: .expectedCents)
        confirmedCents = try container.decodeIfPresent(Int.self, forKey: .confirmedCents)
        totalCents = try container.decodeIfPresent(Int.self, forKey: .totalCents)
        limitCents = try container.decodeIfPresent(Int.self, forKey: .limitCents)
        recordedLimitCents = try container.decodeIfPresent(Int.self, forKey: .recordedLimitCents)
        hasConfirmation = try container.decodeIfPresent(Bool.self, forKey: .hasConfirmation) ?? false
        confirmedThrough = try container.decodeIfPresent(Date.self, forKey: .confirmedThrough)
        level = try container.decodeIfPresent(Level.self, forKey: .level) ?? .unknown
        currency = try container.decodeIfPresent(String.self, forKey: .currency) ?? "USD"
        caveats = try container.decodeIfPresent([String].self, forKey: .caveats) ?? []
        notMetered = try container.decodeIfPresent([String].self, forKey: .notMetered) ?? []
        isCheckpointStale = try container.decodeIfPresent(Bool.self, forKey: .isCheckpointStale) ?? false
        atFloor = try container.decodeIfPresent(Bool.self, forKey: .atFloor)
        floor = try container.decodeIfPresent(SpendingFloor.self, forKey: .floor)
    }

    /// The kernel's level: where spending stands against its limit, as the
    /// kernel last judged it. Never recomputed from the figures.
    public enum Level: String, Codable, Sendable, Equatable, CaseIterable, UnknownDecodable {
        case ok
        case warn50
        case warn75
        case warn90
        case reached
        case unknown

        /// As the kernel says it.
        public var label: String {
            switch self {
            case .ok: "ok"
            case .warn50: "50%"
            case .warn75: "75%"
            case .warn90: "90%"
            case .reached: "limit reached"
            case .unknown: "not read"
            }
        }
    }

    /// Whether any figure was read: an instance listed but not read, or
    /// whose spending section failed, has none.
    public var isRead: Bool {
        expectedCents != nil || confirmedCents != nil || totalCents != nil
    }

    /// The total as a share of the kernel's limit: what enforcement compares.
    /// Nil when either was not read.
    public var fraction: Double? {
        guard let total = totalCents, let limit = limitCents, limit > 0 else { return nil }
        return Double(total) / Double(limit)
    }

    /// The bar's two parts as shares of the kernel's limit, each clamped to
    /// the bar: confirmed first, then expected up to the total. Nil when the
    /// total or the limit was not read.
    public var bar: (confirmed: Double, expected: Double)? {
        guard let total = totalCents, let limit = limitCents, limit > 0 else { return nil }
        let length = min(max(Double(total) / Double(limit), 0), 1)
        let confirmed = hasConfirmation ? min(max(Double(confirmedCents ?? 0) / Double(limit), 0), length) : 0
        return (confirmed, length - confirmed)
    }
}

/// The instance floor as TechnoCore records it (ADR 0009 decision 8): every
/// application stopped and spending still over. What remains is the
/// instance's own standing cost, and the levers that would reduce it destroy
/// operator-visible capability or data, so the kernel names them and takes
/// neither.
public struct SpendingFloor: Codable, Sendable, Equatable {
    /// When the kernel first found nothing left to stop.
    public var since: Date?
    /// What still burns, a month at that rate; nil when the figure could
    /// not be drawn.
    public var stillBurningMonthCents: Int?
    /// The levers left, as the map says them: "drop the load-balancer
    /// carrier", "release the instance". Shown through `Display.message`.
    public var levers: [String]

    public init(since: Date? = nil, stillBurningMonthCents: Int? = nil, levers: [String] = []) {
        self.since = since
        self.stillBurningMonthCents = stillBurningMonthCents
        self.levers = levers
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        since = try container.decodeIfPresent(Date.self, forKey: .since)
        stillBurningMonthCents = try container.decodeIfPresent(Int.self, forKey: .stillBurningMonthCents)
        levers = try container.decodeIfPresent([String].self, forKey: .levers) ?? []
    }
}

/// One namespace's apps, labelled with the repository `run` recorded for it
/// on this Mac: one Kubernetes namespace, one group that moves on the map as
/// a unit. A repository with several manifests deploys several namespaces,
/// so several groups (ADR 0021 decision 2, amended 2026-11-12). The system
/// group is FarCast itself — TechnoCore, Shrike, FatLine and DataSphere,
/// shown as apps like any other.
public struct AppGroup: Codable, Sendable, Equatable, Identifiable {
    /// `<instance>/<namespace>`.
    public var id: String
    public var namespace: String
    /// The repository `run` recorded for the namespace on this Mac, or a
    /// note that none is recorded here, or "FarCast" for the system group.
    public var source: String
    public var isSystem: Bool
    /// Drawn to show behaviour that is decided but not built. Never a real
    /// deployment; the map marks it so, and a live world never has one.
    public var isIllustrative: Bool
    public var apps: [Application]

    public init(
        id: String,
        namespace: String,
        source: String,
        isSystem: Bool = false,
        isIllustrative: Bool = false,
        apps: [Application]
    ) {
        self.id = id
        self.namespace = namespace
        self.source = source
        self.isSystem = isSystem
        self.isIllustrative = isIllustrative
        self.apps = apps
    }
}

/// One application: a panel on the map that shows its own UI.
public struct Application: Codable, Sendable, Equatable, Identifiable {
    /// `<instance>/<namespace>/<name>`.
    public var id: String
    public var name: String
    /// One line saying what the app is, for the glance shown when zoomed out.
    public var role: String
    public var state: AppState
    /// Why it is stopped, when it is.
    public var stopReason: String?
    /// The part of FarCast this app is, for apps in the system group.
    public var system: SystemRole?
    /// Expected spending this month; nil when it is counted elsewhere or
    /// could not be told apart.
    public var monthCents: Int?
    /// Where the spending is counted when `monthCents` is nil.
    public var costNote: String?
    public var isIllustrative: Bool
    /// Ready replicas, and the replicas wanted, when the apps were read.
    public var ready: Int?
    public var desired: Int?

    /// `state` defaults to `unknown`: an app built without one has nothing
    /// behind it saying it runs, and is never drawn as running.
    public init(
        id: String,
        name: String,
        role: String,
        state: AppState = .unknown,
        stopReason: String? = nil,
        system: SystemRole? = nil,
        monthCents: Int? = nil,
        costNote: String? = nil,
        isIllustrative: Bool = false,
        ready: Int? = nil,
        desired: Int? = nil
    ) {
        self.id = id
        self.name = name
        self.role = role
        self.state = state
        self.stopReason = stopReason
        self.system = system
        self.monthCents = monthCents
        self.costNote = costNote
        self.isIllustrative = isIllustrative
        self.ready = ready
        self.desired = desired
    }
}

/// What an app, or one of FarCast's own components, is doing.
public enum AppState: String, Codable, Sendable, Equatable, CaseIterable, UnknownDecodable {
    case running
    case stopped
    /// Fewer replicas ready than wanted.
    case starting
    /// Never deployed, or the cluster has no workload for it.
    case notDeployed
    /// Not read: the section that would say failed, or was never read.
    case unknown

    /// What the map says, and VoiceOver reads.
    public var label: String {
        switch self {
        case .running: "running"
        case .stopped: "stopped"
        case .starting: "starting"
        case .notDeployed: "not deployed"
        case .unknown: "unknown"
        }
    }

    /// Nothing runs: drawn faded, as a stopped app always was.
    public var isDormant: Bool {
        switch self {
        case .stopped, .notDeployed: true
        case .running, .starting, .unknown: false
        }
    }
}

/// The FarCast component a system app is. The map anchors the instance's
/// gates to the boundary: FatLine is where the wall opens.
public enum SystemRole: String, Codable, Sendable, Equatable, CaseIterable {
    case kernel     // TechnoCore
    case monitor    // Shrike
    case boundary   // FatLine
    case storage    // DataSphere
}

/// An address outside every instance, reached only through FatLine's egress.
public struct Host: Codable, Sendable, Equatable, Identifiable {
    public var id: String
    public var name: String
    /// The instance whose wall the host is drawn beside.
    public var instanceID: String
    public var note: String

    public init(id: String, name: String, instanceID: String, note: String) {
        self.id = id
        self.name = name
        self.instanceID = instanceID
        self.note = note
    }
}

/// A device of the operator's: the Mac that holds the keys, or a keeper.
public struct Device: Codable, Sendable, Equatable, Identifiable {
    public var id: String
    public var name: String
    public var role: DeviceRole
    public var note: String
    public var health: Health

    /// A device given no `health` has the one its role implies
    /// (`unstatedHealth(_:)`), never one read from nothing.
    public init(id: String, name: String, role: DeviceRole, note: String, health: Health? = nil) {
        self.id = id
        self.name = name
        self.role = role
        self.note = note
        self.health = health ?? Self.unstatedHealth(role)
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        role = try container.decode(DeviceRole.self, forKey: .role)
        note = try container.decode(String.self, forKey: .note)
        health = try container.decodeIfPresent(Health.self, forKey: .health) ?? Self.unstatedHealth(role)
    }

    /// The health of a device that states none. The operator's own Mac is
    /// not graded — it is the one reading — so it is healthy, as a world
    /// read from an instance names it (`{"id": "operator", "role":
    /// "operator"}`). A keeper's health is graded from what was read, so
    /// without one it was not read.
    public static func unstatedHealth(_ role: DeviceRole) -> Health {
        switch role {
        case .operator: .healthy
        case .keeper: .unknown
        }
    }

    /// Whether the device is drawn as needing nothing. Kept for the callers
    /// that only ask that; a device not read (`unknown`) is not claimed to be
    /// unhealthy, so it counts here, and the map says "not read" for it by
    /// switching on `health`.
    public var isHealthy: Bool {
        health == .healthy || health == .unknown
    }

    public enum Health: String, Codable, Sendable, Equatable, CaseIterable, UnknownDecodable {
        case healthy
        /// Its leaf is past its expiry.
        case expired
        case revoked
        /// No tunnel from it within a day, where the read can tell.
        case unseen
        /// Not read: the network section failed or could not tell.
        case unknown
    }
}

public enum DeviceRole: String, Codable, Sendable, Equatable, CaseIterable {
    case `operator`
    case keeper
}

/// One line on the map, graded by the evidence behind it. The grade is the
/// point: a line FatLine counted, a line a manifest only declares, and a line
/// that was refused at the wall must never look alike.
public struct Connection: Codable, Sendable, Equatable, Identifiable {
    public var id: String
    public var from: Endpoint
    public var to: Endpoint
    public var kind: Kind
    public var evidence: Evidence
    public var label: String
    /// The last observation is old, or the read that gave it failed since:
    /// the line is drawn faded.
    public var isStale: Bool
    /// A floor, counted by one FatLine replica since `since`; never a total.
    public var count: Int?
    public var since: Date?
    public var lastSeen: Date?

    public init(
        id: String,
        from: Endpoint,
        to: Endpoint,
        kind: Kind,
        evidence: Evidence,
        label: String,
        isStale: Bool = false,
        count: Int? = nil,
        since: Date? = nil,
        lastSeen: Date? = nil
    ) {
        self.id = id
        self.from = from
        self.to = to
        self.kind = kind
        self.evidence = evidence
        self.label = label
        self.isStale = isStale
        self.count = count
        self.since = since
        self.lastSeen = lastSeen
    }

    public enum Kind: String, Codable, Sendable, Equatable, CaseIterable {
        /// An app to a host outside, through FatLine's egress.
        case egress
        /// The operator's device to FatLine: the mutual-TLS tunnel.
        case tunnel
        /// A keeper device to the keyholder route, and nothing else.
        case keeper
        /// An app to DataSphere, served by the keyholder.
        case storage
        /// One app to another, through FatLine.
        case appToApp
        /// Shrike watching FatLine.
        case watch
    }

    public enum Evidence: String, Codable, Sendable, Equatable, CaseIterable {
        /// FatLine counted it.
        case observed
        /// A manifest declares it; nothing has used it.
        case declared
        /// Attempted, and refused at the wall.
        case denied
        /// Decided, not built.
        case planned
    }

    /// Whether the line crosses the instance's wall.
    public var crossesWall: Bool {
        switch kind {
        case .egress, .tunnel, .keeper: true
        case .storage, .appToApp, .watch: false
        }
    }
}

/// Something a connection starts or ends at. Encoded as `app:<id>`,
/// `host:<id>` or `device:<id>`, so a snapshot reads the way the map does.
public enum Endpoint: Hashable, Sendable, CustomStringConvertible {
    case app(String)
    case host(String)
    case device(String)

    public var description: String {
        switch self {
        case .app(let id): "app:\(id)"
        case .host(let id): "host:\(id)"
        case .device(let id): "device:\(id)"
        }
    }

    public var appID: String? {
        if case .app(let id) = self { id } else { nil }
    }
}

extension Endpoint: Codable {
    public init(from decoder: any Decoder) throws {
        let text = try decoder.singleValueContainer().decode(String.self)
        guard let colon = text.firstIndex(of: ":") else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "endpoint \(text.debugDescription) is not app:, host: or device:"
            ))
        }
        let id = String(text[text.index(after: colon)...])
        switch text[..<colon] {
        case "app" where !id.isEmpty: self = .app(id)
        case "host" where !id.isEmpty: self = .host(id)
        case "device" where !id.isEmpty: self = .device(id)
        default:
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "endpoint \(text.debugDescription) is not app:, host: or device:"
            ))
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
}

/// What an alert is about. Encoded as `app:<id>`, `instance:<id>` or
/// `device:<id>`, as an `Endpoint` is. A FarCast component is its system
/// app: the reader maps a component subject to `.app` of the app in that
/// role.
public enum AlertSubject: Hashable, Sendable, CustomStringConvertible {
    case app(String)
    case instance(String)
    case device(String)

    public var description: String {
        switch self {
        case .app(let id): "app:\(id)"
        case .instance(let id): "instance:\(id)"
        case .device(let id): "device:\(id)"
        }
    }

    public var appID: String? {
        if case .app(let id) = self { id } else { nil }
    }
}

extension AlertSubject: Codable {
    public init(from decoder: any Decoder) throws {
        let text = try decoder.singleValueContainer().decode(String.self)
        let refused = DecodingError.dataCorrupted(.init(
            codingPath: decoder.codingPath,
            debugDescription: "alert subject \(text.debugDescription) is not app:, instance: or device:"
        ))
        guard let colon = text.firstIndex(of: ":") else { throw refused }
        let id = String(text[text.index(after: colon)...])
        switch text[..<colon] {
        case "app" where !id.isEmpty: self = .app(id)
        case "instance" where !id.isEmpty: self = .instance(id)
        case "device" where !id.isEmpty: self = .device(id)
        default: throw refused
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
}

/// Something the operator should look at, pinned to what it is about.
public struct WorldAlert: Codable, Sendable, Equatable, Identifiable {
    public var id: String
    public var kind: Kind
    public var severity: Severity
    /// Short plain English, written by the CLI; shown through
    /// `Display.message`.
    public var title: String
    public var subject: AlertSubject

    public init(id: String, kind: Kind, severity: Severity, title: String, subject: AlertSubject) {
        self.id = id
        self.kind = kind
        self.severity = severity
        self.title = title
        self.subject = subject
    }

    public enum Kind: String, Codable, Sendable, Equatable, CaseIterable, UnknownDecodable {
        case cost
        case checkpointStale
        /// Every application stopped and spending still over: the kernel
        /// has reached the instance floor, and names what is left.
        case atFloor
        case sealed
        case denied
        case unattributedDenials
        case notReady
        case keeper
        case unmeteredNamespace
        case loggingUnverified
        case releaseIncomplete
        case hostsOmitted
        case drift
        case unknown
    }

    public enum Severity: String, Codable, Sendable, Equatable, Comparable, CaseIterable {
        case warning
        case critical

        /// A severity this build does not know sorts and draws as a warning.
        public init(from decoder: any Decoder) throws {
            let raw = try decoder.singleValueContainer().decode(String.self)
            self = Severity(rawValue: raw) ?? .warning
        }

        public static func < (a: Severity, b: Severity) -> Bool {
            a == .warning && b == .critical
        }
    }
}
