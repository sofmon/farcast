import Foundation

/// The CLI that wrote a document: `farcast.version` and `farcast.commit`.
public struct CLIStamp: Sendable, Equatable {
    public var version: String
    public var commit: String

    public init(version: String, commit: String) {
        self.version = version
        self.commit = commit
    }

    init(_ wire: WireStamp) {
        self.init(version: wire.version, commit: wire.commit)
    }
}

/// `farcast instances`, as the map lists it, with the CLI that wrote it.
public struct CLIListing: Sendable, Equatable {
    /// The instances document's `farcast.version` and `farcast.commit`.
    public var stamp: CLIStamp
    public var instances: [InstanceListing]
}

/// `farcast world <name>`, as the map draws it, with the CLI that wrote it.
public struct CLIWorld: Sendable, Equatable {
    public var stamp: CLIStamp
    /// One instance, `source == .live`, ids prefixed `<instance>/`.
    public var world: World
}

/// The Connected view's adapter: the CLI's three documents into the model
/// (ADR 0021 decision 9, amended 2026-11-12). It decodes and maps, and
/// nothing else: it never draws, never escapes — the model holds raw text,
/// and every draw site applies `Display` — and never validates a world,
/// which the feed does.
///
/// An enum the map's structure rests on — a line's kind or evidence, a
/// component's role, a device's role — that this build does not know fails
/// the read, so the instance keeps its last good snapshot. A word in a
/// tolerant enum — a state, a level, a health, a status, a kind of problem
/// or alert — reads as unknown. A figure the map cannot draw becomes a
/// problem with that figure, never a refusal of the instance.
public enum CLIDocuments {
    /// The one schema this build reads (Go: `worldSchema`).
    public static let schema = 1

    /// `farcast version -o json`: only `version` and `commit` are read; every
    /// other field is ignored.
    public static func version(_ stdout: Data) throws(ReadFailure) -> CLIStamp {
        let what = "version"
        if try head(stdout, what).hasError { throw envelope(stdout, what) }
        return CLIStamp(try decode(WireStamp.self, stdout, what))
    }

    /// `farcast instances -o json`.
    public static func instances(_ stdout: Data) throws(ReadFailure) -> CLIListing {
        let wire = try document(WireListing.self, stdout, "instances")
        return CLIListing(stamp: CLIStamp(wire.farcast), instances: wire.instances.map(listing))
    }

    /// `farcast world <name> -o json`. Refuses a document about any other
    /// instance.
    public static func world(_ stdout: Data, asReadOf name: String) throws(ReadFailure) -> CLIWorld {
        let wire = try document(WireWorld.self, stdout, "world")
        guard InstanceName.isReadable(name) else {
            throw refusal("FarCast reads only the names 'farcast install' creates, and \(name) is not one")
        }
        guard wire.instance.name == name else {
            throw refusal("asked for \(name); farcast answered about \(wire.instance.name)")
        }
        var mapping = WorldMapping(name: name, wire: wire)
        return CLIWorld(stamp: CLIStamp(wire.farcast), world: try mapping.world())
    }

    /// The CLI's JSON error envelope `{"error":{"message","code","kind"}}`,
    /// when stdout is one; else nil.
    public static func failure(_ stdout: Data) -> ReadFailure? {
        guard let envelope = try? World.decoder().decode(WireEnvelope.self, from: stdout) else { return nil }
        return ReadFailure(kind: kind(envelope.error.kind ?? ""), message: envelope.error.message)
    }

    /// A wire error kind (`record_unreadable`, …) as the map's kind;
    /// anything unknown is `.unknown`.
    public static func kind(_ wire: String) -> SectionProblem.Kind {
        switch wire {
        case "record_unreadable": .recordUnreadable
        case "not_found": .notFound
        case "not_connected": .notConnected
        case "tunnel_unreachable": .tunnelUnreachable
        case "kernel_absent": .kernelAbsent
        case "not_checkpointed": .notCheckpointed
        case "version_skew": .versionSkew
        case "kubectl_missing": .kubectlMissing
        case "kubectl_failed": .kubectlFailed
        case "gcloud_mismatch": .gcloudMismatch
        case "gcloud_signed_out": .gcloudSignedOut
        case "auth_tool_missing": .authToolMissing
        case "timeout": .timeout
        case "internal": .internal
        default: .unknown
        }
    }

    // MARK: - Reading a document

    /// What is read of a document before the rest: whether it is an error
    /// envelope, and its schema number, nil when absent or not an integer.
    private struct Head: Decodable {
        let hasError: Bool
        let schema: Int?

        private enum Key: String, CodingKey { case error, schema }

        init(from decoder: any Decoder) throws {
            let container = try decoder.container(keyedBy: Key.self)
            hasError = container.contains(.error)
            schema = try? container.decode(Int.self, forKey: .schema)
        }
    }

    private static func head(_ data: Data, _ what: String) throws(ReadFailure) -> Head {
        do {
            return try World.decoder().decode(Head.self, from: data)
        } catch {
            throw refusal("farcast's \(what) output is not a JSON object")
        }
    }

    /// A schema-1 document, checked in this order: a JSON object; not an
    /// error envelope; a schema number; schema 1, before the rest is
    /// decoded, so a schema-2 document of another shape reads as skew rather
    /// than as a document that could not be read; then the whole of it.
    private static func document<T: Decodable>(_ type: T.Type, _ data: Data, _ what: String) throws(ReadFailure) -> T {
        let top = try head(data, what)
        if top.hasError { throw envelope(data, what) }
        guard let number = top.schema else {
            throw refusal("farcast's \(what) output carries no schema number, so it is not a document this FarCast reads")
        }
        guard number == schema else {
            throw ReadFailure(
                kind: .versionSkew,
                message: "farcast wrote schema \(number) and this FarCast reads schema \(schema); build both from the same commit"
            )
        }
        return try decode(type, data, what)
    }

    private static func decode<T: Decodable>(_ type: T.Type, _ data: Data, _ what: String) throws(ReadFailure) -> T {
        do {
            return try World.decoder().decode(type, from: data)
        } catch {
            throw refusal(String("farcast's \(what) output could not be read: \(describe(error))".prefix(500)))
        }
    }

    /// The envelope a document turned out to be.
    private static func envelope(_ data: Data, _ what: String) -> ReadFailure {
        failure(data) ?? refusal("farcast's \(what) output is an error this FarCast cannot read")
    }

    /// Where a decode failed, and why: the coding path joined with ".".
    static func describe(_ error: any Error) -> String {
        guard let error = error as? DecodingError else { return String(describing: error) }
        let path: [any CodingKey]
        let context: DecodingError.Context
        switch error {
        case .keyNotFound(let key, let found):
            path = found.codingPath + [key]
            context = found
        case .typeMismatch(_, let found), .valueNotFound(_, let found):
            path = found.codingPath
            context = found
        case .dataCorrupted(let found):
            path = found.codingPath
            context = found
        default:
            return String(describing: error)
        }
        let at = path.map { $0.intValue.map(String.init) ?? $0.stringValue }.joined(separator: ".")
        return "\(at): \(context.debugDescription)"
    }

    static func refusal(_ message: String) -> ReadFailure {
        ReadFailure(kind: .internal, message: message)
    }

    // MARK: - The listing

    private static func listing(_ entry: WireListingEntry) -> InstanceListing {
        if let error = entry.error {
            return InstanceListing(
                name: entry.name,
                problem: SectionProblem(section: .record, kind: kind(error.kind), message: error.message)
            )
        }
        var components: [SystemRole: Bool] = [:]
        if let recorded = entry.components {
            components = [.boundary: recorded.fatline, .kernel: recorded.kernel, .storage: recorded.keyholder]
            // Shrike rides FatLine's Pod: without FatLine there is no Shrike.
            // With it, whether Shrike runs is not known from the record.
            if !recorded.fatline { components[.monitor] = false }
        }
        let problem: SectionProblem? = InstanceName.isReadable(entry.name) ? nil : SectionProblem(
            section: .record, kind: .internal,
            message: "this is not a name 'farcast install' creates, so FarCast does not read it"
        )
        return InstanceListing(
            name: entry.name,
            status: entry.status.map(status) ?? .unknown,
            cloudLogging: entry.cloudLogging.map(cloudLogging) ?? .unknown,
            recordedLimitCents: entry.costLimit?.cents,
            components: components,
            problem: problem,
            gcloudPinned: entry.gcloudPinned
        )
    }

    // MARK: - Tables (explicit; never a raw value on a snake_case word)

    static func status(_ wire: String) -> Instance.Status {
        switch wire {
        case "provisioning": .provisioning
        case "running": .running
        case "unreachable": .unreachable
        case "deleting": .deleting
        case "error": .error
        default: .unknown
        }
    }

    static func cloudLogging(_ wire: String) -> Instance.CloudLogging {
        switch wire {
        case "system_only": .systemOnly
        case "unverified": .unverified
        default: .unknown
        }
    }

    static func level(_ wire: String) -> Spending.Level {
        switch wire {
        case "ok": .ok
        case "warn50": .warn50
        case "warn75": .warn75
        case "warn90": .warn90
        case "reached": .reached
        default: .unknown
        }
    }

    static func appState(_ wire: String) -> AppState {
        switch wire {
        case "running": .running
        case "starting": .starting
        case "stopped": .stopped
        case "not_deployed": .notDeployed
        default: .unknown
        }
    }

    static func health(_ wire: String) -> Device.Health {
        switch wire {
        case "healthy": .healthy
        case "expired": .expired
        case "revoked": .revoked
        case "unseen": .unseen
        default: .unknown
        }
    }

    static func alertKind(_ wire: String) -> WorldAlert.Kind {
        switch wire {
        case "cost": .cost
        case "checkpoint_stale": .checkpointStale
        case "sealed": .sealed
        case "denied": .denied
        case "unattributed_denials": .unattributedDenials
        case "not_ready": .notReady
        case "keeper": .keeper
        case "unmetered_namespace": .unmeteredNamespace
        case "logging_unverified": .loggingUnverified
        case "release_incomplete": .releaseIncomplete
        case "hosts_omitted": .hostsOmitted
        case "drift": .drift
        default: .unknown
        }
    }

    static func severity(_ wire: String) -> WorldAlert.Severity {
        wire == "critical" ? .critical : .warning
    }

    /// Strict: nil fails the read.
    static func systemRole(_ wire: String) -> SystemRole? {
        switch wire {
        case "boundary": .boundary
        case "monitor": .monitor
        case "kernel": .kernel
        case "storage": .storage
        default: nil
        }
    }

    /// Strict: nil fails the read. Nothing on the wire is app to app.
    static func lineKind(_ wire: String) -> Connection.Kind? {
        switch wire {
        case "egress": .egress
        case "tunnel": .tunnel
        case "keeper": .keeper
        case "watch": .watch
        case "storage": .storage
        default: nil
        }
    }

    /// Strict: nil fails the read. `planned` is never sent; it maps, and a
    /// live world's validation then refuses it.
    static func evidence(_ wire: String) -> Connection.Evidence? {
        switch wire {
        case "observed": .observed
        case "denied": .denied
        case "declared": .declared
        case "planned": .planned
        default: nil
        }
    }

    /// Strict: nil fails the read.
    static func deviceRole(_ wire: String) -> DeviceRole? {
        switch wire {
        case "operator": .operator
        case "keeper": .keeper
        default: nil
        }
    }
}

/// The names `farcast install` creates (`validateInstanceName`, install.go):
/// 1–32 bytes of [a-z0-9-], starting with [a-z], not ending with "-".
/// The only names the app ever passes to `world`, and the only ones used as
/// an id prefix it trusts.
public enum InstanceName {
    public static func isReadable(_ name: String) -> Bool {
        let bytes = Array(name.utf8)
        guard (1...32).contains(bytes.count), let first = bytes.first, let last = bytes.last else { return false }
        func lower(_ byte: UInt8) -> Bool { byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "z") }
        func digit(_ byte: UInt8) -> Bool { byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9") }
        guard lower(first), last != UInt8(ascii: "-") else { return false }
        return bytes.allSatisfy { lower($0) || digit($0) || $0 == UInt8(ascii: "-") }
    }
}

/// One world document into a world of one instance, every id under
/// `<name>/`.
private struct WorldMapping {
    let name: String
    let wire: WireWorld
    /// The figures the map cannot draw, said as problems with the spend
    /// section: one bad figure never blanks an instance.
    var figureProblems: [SectionProblem] = []

    init(name: String, wire: WireWorld) {
        self.name = name
        self.wire = wire
    }

    mutating func world() throws(ReadFailure) -> World {
        let instance = wire.instance
        let spending = mapSpending(instance.spend)
        var groups = [try systemGroup()]
        for group in wire.groups {
            groups.append(try appGroup(group))
        }
        var connections: [Connection] = []
        for line in wire.lines {
            connections.append(try connection(line))
        }
        let devices = try mapDevices()
        let alerts = try mapAlerts()

        var problems: [SectionProblem] = []
        let sections: [(SectionProblem.Section, WireSectionStatus)] = [
            (.spend, wire.sections.spend), (.apps, wire.sections.apps), (.policy, wire.sections.policy),
            (.network, wire.sections.network), (.seal, wire.sections.seal),
        ]
        for (section, status) in sections {
            if let error = status.error {
                problems.append(SectionProblem(section: section, kind: CLIDocuments.kind(error.kind), message: error.message))
            } else if status.skipped != nil {
                continue  // not deployed, so there is nothing to read
            } else if !status.read {
                problems.append(SectionProblem(section: section, kind: .unknown, message: "not read"))
            }
        }
        problems += figureProblems
        // As `InstanceListing.recordProblems` says it, so validation never
        // refuses the whole read for it.
        if let spend = instance.spend, spend.recordedLimitCents == nil {
            problems.append(SectionProblem(section: .record, kind: .internal, message: "the record holds no cost limit"))
        }

        let read = Instance(
            id: name,
            spending: spending,
            groups: groups,
            status: CLIDocuments.status(instance.status),
            readAt: wire.generatedAt,
            problems: problems,
            cloudLogging: CLIDocuments.cloudLogging(instance.cloudLogging),
            network: instance.network.map {
                NetworkReading(replica: $0.replica, since: $0.since, fatlineReplicas: Self.count($0.fatlineReplicas))
            },
            caveats: instance.caveats
        )
        return World(
            instances: [read],
            devices: devices,
            hosts: mapHosts(),
            connections: connections,
            alerts: alerts,
            source: .live
        )
    }

    // MARK: Figures

    /// A sum of money the map can state, or nil and a problem.
    private mutating func money(_ cents: Int?, _ what: String) -> Int? {
        guard let cents else { return nil }
        guard (0...World.maxCents).contains(cents) else {
            figureProblems.append(SectionProblem(section: .spend, kind: .internal, message: "\(what) is not one: \(cents) cents"))
            return nil
        }
        return cents
    }

    /// A cost limit the map can state: a positive sum in range.
    private mutating func limit(_ cents: Int?, _ what: String) -> Int? {
        guard let cents else { return nil }
        guard (1...World.maxCents).contains(cents) else {
            figureProblems.append(SectionProblem(section: .spend, kind: .internal, message: "\(what) is not one: \(cents) cents"))
            return nil
        }
        return cents
    }

    /// A count, or nil when it is negative: no problem is raised, the count
    /// is simply not drawn.
    static func count(_ value: Int?) -> Int? {
        value.flatMap { $0 < 0 ? nil : $0 }
    }

    /// A sum that never traps: a count is a floor, and one that would pass
    /// `Int.max` is drawn as `Int.max`.
    static func sum(_ values: [Int]) -> Int {
        values.reduce(0) { total, value in
            let (sum, overflow) = total.addingReportingOverflow(value)
            return overflow ? Int.max : sum
        }
    }

    // MARK: Spending

    private mutating func mapSpending(_ spend: WireSpend?) -> Spending {
        guard let spend else { return Spending() }
        let confirmed = money(spend.confirmedCents, "confirmed spending")
        return Spending(
            expectedCents: money(spend.expectedCents, "expected spending"),
            confirmedCents: confirmed,
            totalCents: money(spend.totalCents, "total spending"),
            limitCents: limit(spend.limitCents, "the kernel's cost limit"),
            recordedLimitCents: limit(spend.recordedLimitCents, "the recorded cost limit"),
            hasConfirmation: spend.hasConfirmation && confirmed != nil,
            confirmedThrough: spend.confirmedThrough,
            level: CLIDocuments.level(spend.level),
            currency: spend.currency,
            caveats: spend.caveats,
            notMetered: spend.notMetered,
            isCheckpointStale: spend.checkpointStale
        )
    }

    // MARK: Groups

    private func systemGroup() throws(ReadFailure) -> AppGroup {
        var byRole: [SystemRole: WireComponent] = [:]
        for component in wire.instance.components {
            guard let role = CLIDocuments.systemRole(component.role) else {
                throw CLIDocuments.refusal("farcast named a component in the role '\(component.role)', which this FarCast does not know")
            }
            guard byRole[role] == nil else {
                throw CLIDocuments.refusal("farcast named two components in the \(component.role) role")
            }
            byRole[role] = component
        }
        let apps = SystemComponent.all.map { component in
            let read = byRole[component.role]
            return Application(
                id: SystemComponent.appID(component.role, in: name),
                name: component.name,
                role: component.summary,
                state: read.map { CLIDocuments.appState($0.state) } ?? .unknown,
                system: component.role,
                ready: Self.count(read?.ready),
                desired: Self.count(read?.desired)
            )
        }
        return AppGroup(
            id: "\(name)/\(Instance.systemNamespace)",
            namespace: Instance.systemNamespace,
            source: "FarCast",
            isSystem: true,
            apps: apps
        )
    }

    private mutating func appGroup(_ group: WireGroup) throws(ReadFailure) -> AppGroup {
        let namespace = group.namespace
        guard !namespace.isEmpty, namespace != Instance.systemNamespace, !namespace.contains("/") else {
            throw CLIDocuments.refusal("farcast named a group '\(namespace)' that cannot be drawn")
        }
        let id = "\(name)/\(namespace)"
        let spendRead = wire.instance.spend != nil
        var apps: [Application] = []
        for app in group.apps {
            guard !app.name.isEmpty, !app.name.contains("/") else {
                throw CLIDocuments.refusal("farcast named an app '\(app.name)' in \(namespace) that cannot be drawn")
            }
            let ready = Self.count(app.ready), desired = Self.count(app.desired)
            let month = money(app.monthCents, "\(namespace)/\(app.name)'s spending this month")
            let costNote: String? = if month != nil {
                nil
            } else if app.monthCents != nil {
                "not a figure the map can draw"  // the figure was refused, and a problem says why
            } else if !spendRead {
                "spending not read"
            } else if group.metered == false {
                "not metered"
            } else if group.metered == nil {
                "metering not read"
            } else {
                "not told apart from an app of the same name"
            }
            let role = if let ready, let desired { "\(ready) of \(desired) ready" } else { "running" }
            apps.append(Application(
                id: "\(id)/\(app.name)",
                name: app.name,
                role: role,
                state: CLIDocuments.appState(app.state),
                stopReason: app.stoppedBy.map { $0 == "cost_guard" ? "stopped by the cost guard" : "stopped by \($0)" },
                monthCents: month,
                costNote: costNote,
                isIllustrative: false,
                ready: ready,
                desired: desired
            ))
        }
        return AppGroup(id: id, namespace: namespace, source: Self.source(group), apps: apps)
    }

    /// The group's label: the repository `run` recorded on this Mac, its ref
    /// and commit, or that none is recorded; and whether it is metered.
    static func source(_ group: WireGroup) -> String {
        var label = "repository not recorded on this Mac"
        if let provenance = group.provenance {
            var repository = provenance.repository
            for scheme in ["https://", "http://", "ssh://", "git://"] where repository.hasPrefix(scheme) {
                repository.removeFirst(scheme.count)
                break
            }
            if repository.hasSuffix("/") { repository.removeLast() }
            if repository.hasSuffix(".git") { repository.removeLast(4) }
            var ref = provenance.ref
            for prefix in ["refs/heads/", "refs/tags/"] where ref.hasPrefix(prefix) {
                ref.removeFirst(prefix.count)
                break
            }
            label = repository
                + (provenance.ref.isEmpty ? "" : " · " + ref)
                + (provenance.commit.isEmpty ? "" : " at " + String(provenance.commit.prefix(7)))
        }
        if group.metered == false { label += " · not metered" }
        return label
    }

    // MARK: Hosts and lines

    private func mapHosts() -> [Host] {
        var linesTo: [String: [WireLine]] = [:]
        for line in wire.lines where line.kind == "egress" {
            if let host = line.to.host { linesTo[host, default: []].append(line) }
        }
        return wire.hosts.map { host in
            var reached: [String] = [], refused: [String] = [], unused: [String] = []
            for line in linesTo[host.name] ?? [] {
                guard let app = line.from.app else { continue }
                let evidence = line.ports.map(\.evidence)
                if evidence.contains("observed") { reached.append(app) }
                if evidence.contains("denied") { refused.append(app) }
                if !evidence.isEmpty, evidence.allSatisfy({ $0 == "declared" }) { unused.append(app) }
            }
            var parts: [String] = []
            if !reached.isEmpty { parts.append("reached by \(reached.joined(separator: ", "))") }
            if !refused.isEmpty { parts.append("refused for \(refused.joined(separator: ", "))") }
            if !unused.isEmpty { parts.append("declared by \(unused.joined(separator: ", ")), never used") }
            if !host.seenAs.isEmpty { parts.append("also written \(host.seenAs.joined(separator: ", "))") }
            return Host(id: "\(name)/\(host.name)", name: host.name, instanceID: name, note: parts.joined(separator: " · "))
        }
    }

    private func connection(_ line: WireLine) throws(ReadFailure) -> Connection {
        guard let kind = CLIDocuments.lineKind(line.kind) else {
            throw CLIDocuments.refusal("farcast drew a line of the kind '\(line.kind)', which this FarCast does not know")
        }
        guard let evidence = CLIDocuments.evidence(line.evidence) else {
            throw CLIDocuments.refusal("farcast drew a line with the evidence '\(line.evidence)', which this FarCast does not know")
        }
        let from = try end(line.from)
        let to = try end(line.to)
        var count: Int?
        let label: String
        switch kind {
        case .egress:
            (label, count) = Self.egress(line)
        case .tunnel:
            label = line.labelHint == "read_now" ? "you · this read" : "you · mTLS tunnel"
        case .keeper:
            label = "keeper · keyholder only"
        case .watch:
            label = "watches"
        case .storage:
            label = line.labelHint == "wired_not_counted" ? "storage · wired, not counted" : "storage"
        case .appToApp:
            throw CLIDocuments.refusal("farcast drew an app-to-app line, which is not built")
        }
        return Connection(
            id: "\(name)/\(line.kind):\(from.key)>\(to.key)",
            from: from.endpoint,
            to: to.endpoint,
            kind: kind,
            evidence: evidence,
            label: label,
            isStale: line.stale ?? false,
            count: count,
            since: line.since,
            lastSeen: line.lastSeen
        )
    }

    /// An egress line's label and count, from its ports. Every count is a
    /// floor (ADR 0015), so it is written with ≥, and integers plainly, the
    /// same on every platform.
    static func egress(_ line: WireLine) -> (label: String, count: Int?) {
        let observed = line.ports.filter { $0.evidence == "observed" }
        let denied = line.ports.filter { $0.evidence == "denied" }
        let allows = sum(observed.map { count($0.count) ?? 0 })
        let fails = sum(observed.map { count($0.fails) ?? 0 })
        let refused = sum(denied.map { count($0.count) ?? 0 })
        var parts: [String] = []
        if !observed.isEmpty { parts.append("≥\(allows) ok") }
        if fails > 0 { parts.append("≥\(fails) failed") }
        if !denied.isEmpty { parts.append("≥\(refused) refused") }
        if !line.ports.isEmpty, line.ports.allSatisfy({ $0.evidence == "declared" }) { parts.append("declared · unused") }
        if line.drift == true { parts.append("not declared") }
        if observed.contains(where: \.noLongerDeclared) { parts.append("no longer declared") }
        let counted: Int? = if !observed.isEmpty { allows } else if !denied.isEmpty { refused } else { nil }
        return (parts.joined(separator: " · "), counted)
    }

    /// A line's end: exactly one of app, host, device or component, as the
    /// key the line's id is made of and the endpoint the map draws.
    private func end(_ end: WireEnd) throws(ReadFailure) -> (key: String, endpoint: Endpoint) {
        let named = [end.app, end.host, end.device, end.component].compactMap { $0 }
        guard named.count == 1 else {
            throw CLIDocuments.refusal("farcast drew a line end that names \(named.count) things, not one")
        }
        if let app = end.app, !app.isEmpty {
            return ("app:\(app)", .app("\(name)/\(app)"))
        }
        if let host = end.host, !host.isEmpty {
            return ("host:\(host)", .host("\(name)/\(host)"))
        }
        if let device = end.device, device == World.operatorDeviceID || isKeeperID(device) {
            return ("device:\(device)", .device(device))
        }
        if let component = end.component, let role = CLIDocuments.systemRole(component) {
            return ("component:\(component)", .app(SystemComponent.appID(role, in: name)))
        }
        throw CLIDocuments.refusal("farcast drew a line end the map cannot place: \(named[0])")
    }

    /// `<name>/<keeper>`.
    private func isKeeperID(_ id: String) -> Bool {
        let prefix = "\(name)/"
        return id.hasPrefix(prefix) && id.count > prefix.count
    }

    // MARK: Devices and alerts

    private func mapDevices() throws(ReadFailure) -> [Device] {
        var devices: [Device] = []
        for device in wire.devices {
            guard let role = CLIDocuments.deviceRole(device.role) else {
                throw CLIDocuments.refusal("farcast named a device in the role '\(device.role)', which this FarCast does not know")
            }
            switch role {
            case .operator:
                guard device.id == World.operatorDeviceID else {
                    throw CLIDocuments.refusal("farcast named the operator's device '\(device.id)', not '\(World.operatorDeviceID)'")
                }
                devices.append(Device(
                    id: World.operatorDeviceID, name: "This Mac", role: .operator,
                    note: "operator · holds the keys", health: .healthy
                ))
            case .keeper:
                guard isKeeperID(device.id) else {
                    throw CLIDocuments.refusal("farcast named a keeper '\(device.id)' that is not under \(name)/")
                }
                let health = device.health.map(CLIDocuments.health) ?? .unknown
                let suffix = switch health {
                case .expired: " · leaf expired"
                case .revoked: " · revoked"
                case .unseen: " · not seen for a day"
                case .healthy, .unknown: ""
                }
                let shortName = String(device.id.dropFirst(name.count + 1))
                devices.append(Device(
                    id: device.id,
                    name: device.name.flatMap { $0.isEmpty ? nil : $0 } ?? shortName,
                    role: .keeper,
                    note: "keeper for \(name)\(suffix)",
                    health: health
                ))
            }
        }
        return devices
    }

    private func mapAlerts() throws(ReadFailure) -> [WorldAlert] {
        var alerts: [WorldAlert] = []
        for alert in wire.alerts {
            let subject = alert.subject
            var about: [AlertSubject] = []
            if let app = subject.app { about.append(.app("\(name)/\(app)")) }
            if let component = subject.component {
                guard let role = CLIDocuments.systemRole(component) else {
                    throw CLIDocuments.refusal("farcast raised an alert about a component in the role '\(component)', which this FarCast does not know")
                }
                about.append(.app(SystemComponent.appID(role, in: name)))
            }
            if let device = subject.device { about.append(.device(device)) }
            if subject.instance { about.append(.instance(name)) }
            guard about.count == 1 else {
                throw CLIDocuments.refusal("farcast raised an alert \(alert.id) about \(about.count) things, not one")
            }
            alerts.append(WorldAlert(
                id: "\(name)/\(alert.id)",
                kind: CLIDocuments.alertKind(alert.kind),
                severity: CLIDocuments.severity(alert.severity),
                title: alert.title,
                subject: about[0]
            ))
        }
        return alerts
    }
}
