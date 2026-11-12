import Foundation

/// Everything the map draws: the operator's instances and the apps running in
/// them, the operator's own devices, the hosts outside, and the connections
/// between them.
///
/// It is a snapshot. Fixtures provide it today; the read route ADR 0021 names
/// is to deliver it later, through FatLine. Nothing in it is hidden by the
/// map: every app has a place, a stopped one included.
public struct World: Codable, Sendable, Equatable {
    public var instances: [Instance]
    public var devices: [Device]
    public var hosts: [Host]
    public var connections: [Connection]
    public var alerts: [WorldAlert]

    public init(
        instances: [Instance],
        devices: [Device] = [],
        hosts: [Host] = [],
        connections: [Connection] = [],
        alerts: [WorldAlert] = []
    ) {
        self.instances = instances
        self.devices = devices
        self.hosts = hosts
        self.connections = connections
        self.alerts = alerts
    }
}

/// One FarCast instance: its own territory on the map, with nothing drawn
/// between it and any other instance, because nothing runs between them.
public struct Instance: Codable, Sendable, Equatable, Identifiable {
    public var id: String
    public var spending: Spending
    public var groups: [AppGroup]

    public init(id: String, spending: Spending, groups: [AppGroup]) {
        self.id = id
        self.spending = spending
        self.groups = groups
    }
}

/// TechnoCore's figure that protective action fires on, `expected`, against
/// the limit set at creation (AGENTS.md, cost control). The provider's
/// `confirmed` figure arrives a day later and is not drawn yet.
public struct Spending: Codable, Sendable, Equatable {
    public var expectedCents: Int
    public var limitCents: Int

    public init(expectedCents: Int, limitCents: Int) {
        self.expectedCents = expectedCents
        self.limitCents = limitCents
    }

    /// Expected spending as a share of the limit; 0 when there is no limit to
    /// share, which an instance never has but a malformed snapshot could.
    public var fraction: Double {
        limitCents > 0 ? Double(expectedCents) / Double(limitCents) : 0
    }
}

/// One Git repository's apps: one deployment, one Kubernetes namespace, one
/// group that moves on the map as a unit. The system group is FarCast itself —
/// TechnoCore, Shrike, FatLine and DataSphere, shown as apps like any other.
public struct AppGroup: Codable, Sendable, Equatable, Identifiable {
    /// `<instance>/<namespace>`.
    public var id: String
    public var namespace: String
    /// Where the apps come from: a repository, or "FarCast" for the system group.
    public var source: String
    public var isSystem: Bool
    /// Drawn to show behaviour that is decided but not built. Never a real
    /// deployment; the map marks it so.
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
    /// Expected spending this month; nil when it is counted elsewhere.
    public var monthCents: Int?
    /// Where the spending is counted when `monthCents` is nil.
    public var costNote: String?
    public var isIllustrative: Bool

    public init(
        id: String,
        name: String,
        role: String,
        state: AppState = .running,
        stopReason: String? = nil,
        system: SystemRole? = nil,
        monthCents: Int? = nil,
        costNote: String? = nil,
        isIllustrative: Bool = false
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
    }
}

public enum AppState: String, Codable, Sendable, Equatable {
    case running
    case stopped
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
    public var isHealthy: Bool

    public init(id: String, name: String, role: DeviceRole, note: String, isHealthy: Bool = true) {
        self.id = id
        self.name = name
        self.role = role
        self.note = note
        self.isHealthy = isHealthy
    }
}

public enum DeviceRole: String, Codable, Sendable, Equatable {
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
    /// The last observation is old: the line is drawn faded.
    public var isStale: Bool

    public init(
        id: String,
        from: Endpoint,
        to: Endpoint,
        kind: Kind,
        evidence: Evidence,
        label: String,
        isStale: Bool = false
    ) {
        self.id = id
        self.from = from
        self.to = to
        self.kind = kind
        self.evidence = evidence
        self.label = label
        self.isStale = isStale
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

    public enum Evidence: String, Codable, Sendable, Equatable {
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

/// Something the operator should look at, pinned to the app it is about.
public struct WorldAlert: Codable, Sendable, Equatable, Identifiable {
    public var id: String
    public var kind: Kind
    public var severity: Severity
    public var title: String
    public var appID: String

    public init(id: String, kind: Kind, severity: Severity, title: String, appID: String) {
        self.id = id
        self.kind = kind
        self.severity = severity
        self.title = title
        self.appID = appID
    }

    public enum Kind: String, Codable, Sendable, Equatable {
        case cost
        case sealed
        case denied
    }

    public enum Severity: String, Codable, Sendable, Equatable, Comparable {
        case warning
        case critical

        public static func < (a: Severity, b: Severity) -> Bool {
            a == .warning && b == .critical
        }
    }
}
