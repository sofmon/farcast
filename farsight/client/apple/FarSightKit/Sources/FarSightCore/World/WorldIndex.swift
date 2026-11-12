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
    /// - each instance has one system group, and in it at most one app per
    ///   FarCast role, FatLine among them; an instance whose record and
    ///   spending were read has a cost limit, and nothing requires a figure
    ///   that was not read;
    /// - every connection's ends exist and suit its kind, and a refusal is
    ///   only ever recorded where a wall can refuse it;
    /// - app-to-app lines are only drawn where they are illustrative,
    ///   because app-to-app through FatLine is decided but not built, and an
    ///   illustrative app has nothing observed, declared or refused, and no
    ///   spending — it is not a deployment;
    /// - a live world has no illustrative group or app, no planned line and
    ///   no app-to-app line (ADR 0021 decision 9, amended 2026-11-12);
    /// - the tunnel comes from the operator's device, a keeper's line from a
    ///   keeper;
    /// - every alert points at an app, instance or device the world holds,
    ///   and every sum of money is in range.
    ///
    /// Unknown states, levels, statuses and healths are accepted: they are
    /// what an instance that could not be read is drawn with.
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
            let spending = instance.spending
            // A limit is checked where it was read. An instance whose record
            // and spending were read must have one: every instance has a cost
            // limit set at creation (AGENTS.md). One whose record failed, or
            // whose status is unknown, is drawn without; so is one whose
            // spending section failed, because a world read from an instance
            // carries both limits only inside that section.
            if let limit = spending.limitCents {
                if limit <= 0 {
                    problems.append("instance \(instance.id) has no cost limit")
                } else {
                    money(limit, "instance \(instance.id)'s cost limit", allowZero: false)
                }
            }
            if let recorded = spending.recordedLimitCents {
                if recorded <= 0 {
                    problems.append("instance \(instance.id) has no recorded cost limit")
                } else {
                    money(recorded, "instance \(instance.id)'s recorded cost limit", allowZero: false)
                }
            }
            if instance.status != .unknown, instance.problem(in: .record) == nil, instance.problem(in: .spend) == nil,
               spending.limitCents == nil, spending.recordedLimitCents == nil {
                problems.append("instance \(instance.id) has no cost limit")
            }
            if let cents = spending.expectedCents { money(cents, "instance \(instance.id)'s expected spending") }
            if let cents = spending.confirmedCents { money(cents, "instance \(instance.id)'s confirmed spending") }
            if let cents = spending.totalCents { money(cents, "instance \(instance.id)'s total spending") }
            if spending.hasConfirmation, spending.confirmedCents == nil {
                problems.append("instance \(instance.id) says spending is confirmed, with no confirmed figure")
            }
            let systemGroups = instance.groups.filter(\.isSystem)
            if systemGroups.count != 1 {
                problems.append("instance \(instance.id) has \(systemGroups.count) system groups, not one")
            }
            if systemGroups.contains(where: \.isIllustrative) {
                problems.append("instance \(instance.id)'s system group is illustrative; FarCast itself is never a sketch")
            }
            for group in instance.groups {
                unique("group", group.id)
                if source == .live, group.isIllustrative {
                    problems.append("live world has illustrative group \(group.id); a live map never shows the fixture's sketches")
                }
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
                    if source == .live, app.isIllustrative {
                        problems.append("live world has illustrative app \(app.id)")
                    }
                    if let ready = app.ready, ready < 0 { problems.append("app \(app.id) has a negative ready count") }
                    if let desired = app.desired, desired < 0 { problems.append("app \(app.id) has a negative desired count") }
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
            if source == .live, connection.evidence == .planned {
                problems.append("live world has planned line \(connection.id); nothing decided-but-not-built is read")
            }
            if source == .live, connection.kind == .appToApp {
                problems.append("live world has app-to-app line \(connection.id); app to app is not built")
            }
            if let count = connection.count, count < 0 {
                problems.append("connection \(connection.id) has a negative count")
            }
        }
        for alert in alerts {
            switch alert.subject {
            case .app(let app):
                if index.apps[app] == nil {
                    problems.append("alert \(alert.id) points at unknown app \(app)")
                } else if index.apps[app]?.isIllustrative == true {
                    problems.append("alert \(alert.id) is about illustrative app \(app); nothing happens to a sketch")
                }
            case .instance(let instance):
                if index.instances[instance] == nil {
                    problems.append("alert \(alert.id) points at unknown instance \(instance)")
                }
            case .device(let device):
                if index.devices[device] == nil {
                    problems.append("alert \(alert.id) points at unknown device \(device)")
                }
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
