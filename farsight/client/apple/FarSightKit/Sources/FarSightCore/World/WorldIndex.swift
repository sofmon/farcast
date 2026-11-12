import Foundation

/// Lookups over one `World`, built once per snapshot.
public struct WorldIndex: Sendable {
    public let apps: [String: Application]
    public let groups: [String: AppGroup]
    public let instances: [String: Instance]
    public let hosts: [String: Host]
    public let devices: [String: Device]
    /// App id → group id.
    public let groupOfApp: [String: String]
    /// Group id → instance id.
    public let instanceOfGroup: [String: String]

    public init(_ world: World) {
        var apps: [String: Application] = [:]
        var groups: [String: AppGroup] = [:]
        var instances: [String: Instance] = [:]
        var groupOfApp: [String: String] = [:]
        var instanceOfGroup: [String: String] = [:]
        for instance in world.instances {
            instances[instance.id] = instance
            for group in instance.groups {
                groups[group.id] = group
                instanceOfGroup[group.id] = instance.id
                for app in group.apps {
                    apps[app.id] = app
                    groupOfApp[app.id] = group.id
                }
            }
        }
        self.apps = apps
        self.groups = groups
        self.instances = instances
        self.groupOfApp = groupOfApp
        self.instanceOfGroup = instanceOfGroup
        self.hosts = Dictionary(world.hosts.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        self.devices = Dictionary(world.devices.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
    }

    public func instanceID(ofApp id: String) -> String? {
        groupOfApp[id].flatMap { instanceOfGroup[$0] }
    }

    /// The app that plays `role` in an instance's system group.
    public func systemApp(_ role: SystemRole, in instanceID: String) -> Application? {
        instances[instanceID]?.groups
            .first(where: \.isSystem)?
            .apps.first(where: { $0.system == role })
    }

    /// The instance a connection belongs to: the instance of whichever end is
    /// an app. Every connection the map draws has one.
    public func instanceID(of connection: Connection) -> String? {
        connection.from.appID.flatMap(instanceID(ofApp:))
            ?? connection.to.appID.flatMap(instanceID(ofApp:))
    }
}

/// Why a snapshot cannot be drawn. A snapshot is input, so a client checks it
/// before trusting a single id in it.
public struct WorldError: Error, Equatable, CustomStringConvertible {
    public let problems: [String]
    public var description: String { problems.joined(separator: "; ") }
}

extension World {
    /// The largest amount of money a snapshot may state, in cents: a billion
    /// dollars. Anything larger is malformed input, not spending, and would
    /// overflow the arithmetic that formats it.
    public static let maxCents = 100_000_000_000

    /// Checks the snapshot is drawable and says nothing the map would draw
    /// as more than it is:
    /// - ids are unique and nest the way the map nests them;
    /// - each instance has a cost limit, one system group, and in it at most
    ///   one app per FarCast role, FatLine among them;
    /// - every connection's ends exist and suit its kind, and a refusal is
    ///   only ever recorded where a wall can refuse it;
    /// - app-to-app lines are only drawn where they are illustrative,
    ///   because app-to-app through FatLine is decided but not built, and an
    ///   illustrative app has nothing observed, declared or refused, and no
    ///   spending — it is not a deployment;
    /// - the tunnel comes from the operator's device, a keeper's line from a
    ///   keeper;
    /// - every alert points at an app, and every sum of money is in range.
    public func validate() throws(WorldError) {
        var problems: [String] = []
        var seen = Set<String>()
        func unique(_ kind: String, _ id: String) {
            if !seen.insert("\(kind):\(id)").inserted { problems.append("duplicate \(kind) id \(id)") }
        }
        func money(_ cents: Int, _ what: String, allowZero: Bool = true) {
            if cents < (allowZero ? 0 : 1) || cents > Self.maxCents {
                problems.append("\(what) is out of range")
            }
        }

        for instance in instances {
            unique("instance", instance.id)
            if instance.spending.limitCents <= 0 {
                problems.append("instance \(instance.id) has no cost limit")
            } else {
                money(instance.spending.limitCents, "instance \(instance.id)'s cost limit", allowZero: false)
            }
            money(instance.spending.expectedCents, "instance \(instance.id)'s expected spending")
            let systemGroups = instance.groups.filter(\.isSystem)
            if systemGroups.count != 1 {
                problems.append("instance \(instance.id) has \(systemGroups.count) system groups, not one")
            }
            if systemGroups.contains(where: \.isIllustrative) {
                problems.append("instance \(instance.id)'s system group is illustrative; FarCast itself is never a sketch")
            }
            for group in instance.groups {
                unique("group", group.id)
                if group.id != "\(instance.id)/\(group.namespace)" {
                    problems.append("group \(group.id) is not \(instance.id)/\(group.namespace)")
                }
                var roles = Set<SystemRole>()
                for app in group.apps {
                    unique("app", app.id)
                    if !app.id.hasPrefix("\(group.id)/") || app.id.count == group.id.count + 1 {
                        problems.append("app \(app.id) is not under its group \(group.id)")
                    }
                    if (app.system != nil) != group.isSystem {
                        problems.append("app \(app.id) has a system role outside the system group, or none inside it")
                    }
                    if let role = app.system, !roles.insert(role).inserted {
                        problems.append("group \(group.id) has two apps in the \(role.rawValue) role")
                    }
                    if let cents = app.monthCents { money(cents, "app \(app.id)'s spending") }
                    if app.isIllustrative != group.isIllustrative {
                        problems.append("app \(app.id) and its group disagree on being illustrative")
                    }
                    if app.isIllustrative, app.monthCents != nil {
                        problems.append("illustrative app \(app.id) has spending; it is not a deployment")
                    }
                    if app.isIllustrative, app.state != .running || app.stopReason != nil {
                        problems.append("illustrative app \(app.id) is stopped; only a deployment can be")
                    }
                }
            }
        }
        for device in devices { unique("device", device.id) }
        for host in hosts { unique("host", host.id) }
        for connection in connections { unique("connection", connection.id) }
        for alert in alerts { unique("alert", alert.id) }

        let index = WorldIndex(self)
        for instance in instances where index.systemApp(.boundary, in: instance.id) == nil {
            problems.append("instance \(instance.id) has no boundary app")
        }
        for host in hosts where index.instances[host.instanceID] == nil {
            problems.append("host \(host.id) is drawn beside unknown instance \(host.instanceID)")
        }
        for connection in connections {
            problems += Self.problems(with: connection, index)
        }
        for alert in alerts {
            if index.apps[alert.appID] == nil {
                problems.append("alert \(alert.id) points at unknown app \(alert.appID)")
            } else if index.apps[alert.appID]?.isIllustrative == true {
                problems.append("alert \(alert.id) is about illustrative app \(alert.appID); nothing happens to a sketch")
            }
        }

        if !problems.isEmpty { throw WorldError(problems: problems) }
    }

    private static func problems(with connection: Connection, _ index: WorldIndex) -> [String] {
        let id = connection.id
        func exists(_ endpoint: Endpoint) -> Bool {
            switch endpoint {
            case .app(let app): index.apps[app] != nil
            case .host(let host): index.hosts[host] != nil
            case .device(let device): index.devices[device] != nil
            }
        }
        var problems: [String] = []
        for end in [connection.from, connection.to] where !exists(end) {
            problems.append("connection \(id) ends at unknown \(end)")
        }
        guard problems.isEmpty else { return problems }
        if connection.from == connection.to {
            return ["connection \(id) starts and ends at \(connection.from)"]
        }

        let from = connection.from, to = connection.to
        let fromInstance = from.appID.flatMap(index.instanceID(ofApp:))
        let toInstance = to.appID.flatMap(index.instanceID(ofApp:))
        func role(_ endpoint: Endpoint) -> SystemRole? {
            endpoint.appID.flatMap { index.apps[$0]?.system }
        }
        func illustrative(_ endpoint: Endpoint) -> Bool {
            guard let app = endpoint.appID, let group = index.groupOfApp[app] else { return false }
            return index.groups[group]?.isIllustrative ?? false
        }

        switch connection.kind {
        case .egress:
            if from.appID == nil { problems.append("egress \(id) does not start at an app") }
            if case .host(let host) = to {
                if index.hosts[host]?.instanceID != fromInstance {
                    problems.append("egress \(id) reaches a host drawn beside another instance")
                }
            } else {
                problems.append("egress \(id) does not end at a host")
            }
        case .tunnel, .keeper:
            guard case .device(let device) = from else {
                problems.append("\(connection.kind.rawValue) \(id) does not start at a device")
                break
            }
            let wanted: SystemRole = connection.kind == .tunnel ? .boundary : .storage
            if role(to) != wanted {
                problems.append("\(connection.kind.rawValue) \(id) does not end at the instance's \(wanted.rawValue)")
            }
            let deviceRole: DeviceRole = connection.kind == .tunnel ? .operator : .keeper
            if index.devices[device]?.role != deviceRole {
                problems.append("\(connection.kind.rawValue) \(id) does not start at a\(deviceRole == .operator ? "n operator's" : " keeper") device")
            }
        case .storage:
            if from.appID == nil || role(to) != .storage {
                problems.append("storage \(id) is not an app to its DataSphere")
            }
        case .appToApp:
            if from.appID == nil || to.appID == nil {
                problems.append("appToApp \(id) is not between two apps")
            }
            // App to app through FatLine is decided, not built (ADR 0021,
            // amended): nothing can have observed, declared or refused it.
            if connection.evidence != .planned || !illustrative(from) || !illustrative(to) {
                problems.append("appToApp \(id) must be planned and between illustrative apps until it is built")
            }
        case .watch:
            if role(from) != .monitor || role(to) != .boundary {
                problems.append("watch \(id) is not Shrike watching FatLine")
            }
        }
        // An illustrative app is not a deployment: nothing about it was
        // observed, declared or refused.
        if (illustrative(from) || illustrative(to)), connection.evidence != .planned {
            problems.append("\(connection.kind.rawValue) \(id) touches an illustrative app, so it can only be planned")
        }
        // Only a wall refuses: egress at the OUT gate, a device at the IN gate.
        if connection.evidence == .denied, !connection.crossesWall {
            problems.append("\(connection.kind.rawValue) \(id) is marked denied, but only a wall refuses")
        }
        if let fromInstance, let toInstance, fromInstance != toInstance {
            problems.append("connection \(id) joins two instances; nothing runs between instances")
        }
        return problems
    }
}
