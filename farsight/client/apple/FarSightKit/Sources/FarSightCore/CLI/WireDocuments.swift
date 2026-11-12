import Foundation

// The CLI's JSON documents as the wire carries them, schema 1: mirrors of
// the Go types in farsight/cli/internal/cli (worlddoc.go, instances.go,
// version.go), decoded as they are and mapped into the model by
// `CLIDocuments`, never used by anything else.
//
// Which fields are required comes from the Go types, never from the
// vectors: a field Go marks omitempty, or a pointer, may be absent or null,
// and every array may be absent or null (Go writes a nil slice as null), so
// one record that omits a field never fails a whole listing. Every string
// from a closed set a newer CLI may extend is decoded as a String and mapped
// by an explicit table in `CLIDocuments`, never through a raw value.

/// `farcast.version` and `farcast.commit`, and `farcast version`'s own two.
struct WireStamp: Decodable {
    let version: String
    let commit: String
}

/// A kind and the message that explains it: a section's error, a listing
/// entry's.
struct WireProblem: Decodable {
    let kind: String
    let message: String
}

// MARK: - farcast instances

struct WireListing: Decodable {
    let schema: Int
    let generatedAt: Date
    let farcast: WireStamp
    let instances: [WireListingEntry]

    enum CodingKeys: String, CodingKey {
        case schema
        case generatedAt = "generated_at"
        case farcast
        case instances
    }

    init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        schema = try c.decode(Int.self, forKey: .schema)
        generatedAt = try c.decode(Date.self, forKey: .generatedAt)
        farcast = try c.decode(WireStamp.self, forKey: .farcast)
        // Required, but null reads as none, as every array does.
        instances = try c.decode([WireListingEntry]?.self, forKey: .instances) ?? []
    }
}

/// `instanceEntry`: only the name is required. An entry with an error
/// carries its name and its error and nothing else.
struct WireListingEntry: Decodable {
    let name: String
    let status: String?
    let costLimit: WireCostLimit?
    let cloudLogging: String?
    let components: WireRecordedComponents?
    let gcloudPinned: Bool?
    let error: WireProblem?

    enum CodingKeys: String, CodingKey {
        case name, status
        case costLimit = "cost_limit"
        case cloudLogging = "cloud_logging"
        case components
        case gcloudPinned = "gcloud_pinned"
        case error
    }
}

struct WireCostLimit: Decodable {
    let cents: Int
    let currency: String
    let period: String
}

/// What the record says was deployed.
struct WireRecordedComponents: Decodable {
    let fatline: Bool
    let kernel: Bool
    let keyholder: Bool
}

// MARK: - farcast world

struct WireWorld: Decodable {
    let schema: Int
    let generatedAt: Date
    let farcast: WireStamp
    let instance: WireInstance
    let groups: [WireGroup]
    let hosts: [WireHost]
    let lines: [WireLine]
    let devices: [WireDevice]
    let alerts: [WireAlert]
    let sections: WireSections

    enum CodingKeys: String, CodingKey {
        case schema
        case generatedAt = "generated_at"
        case farcast, instance, groups, hosts, lines, devices, alerts, sections
    }

    init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        schema = try c.decode(Int.self, forKey: .schema)
        generatedAt = try c.decode(Date.self, forKey: .generatedAt)
        farcast = try c.decode(WireStamp.self, forKey: .farcast)
        instance = try c.decode(WireInstance.self, forKey: .instance)
        groups = try c.decodeIfPresent([WireGroup].self, forKey: .groups) ?? []
        hosts = try c.decodeIfPresent([WireHost].self, forKey: .hosts) ?? []
        lines = try c.decodeIfPresent([WireLine].self, forKey: .lines) ?? []
        devices = try c.decodeIfPresent([WireDevice].self, forKey: .devices) ?? []
        alerts = try c.decodeIfPresent([WireAlert].self, forKey: .alerts) ?? []
        sections = try c.decode(WireSections.self, forKey: .sections)
    }
}

struct WireInstance: Decodable {
    let name: String
    let status: String
    let cloudLogging: String
    /// Nil when not read: `{"read": false}`.
    let spend: WireSpend?
    /// Nil when not read: `{"read": false}`.
    let network: WireNetwork?
    let components: [WireComponent]
    let caveats: [String]

    enum CodingKeys: String, CodingKey {
        case name, status
        case cloudLogging = "cloud_logging"
        case spend, network, components, caveats
    }

    init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        name = try c.decode(String.self, forKey: .name)
        status = try c.decode(String.self, forKey: .status)
        cloudLogging = try c.decode(String.self, forKey: .cloudLogging)
        spend = try c.decodeIfPresent(WireReadable<WireSpend>.self, forKey: .spend)?.value
        network = try c.decodeIfPresent(WireReadable<WireNetwork>.self, forKey: .network)?.value
        components = try c.decodeIfPresent([WireComponent].self, forKey: .components) ?? []
        caveats = try c.decodeIfPresent([String].self, forKey: .caveats) ?? []
    }
}

/// A part of the document that is `{"read": false}` when it was not read,
/// and the whole of `T` when it was. Decoded in two steps, so `read` is the
/// only field required of the short form, and the full form's own required
/// fields are required only when it says it was read.
struct WireReadable<T: Decodable>: Decodable {
    let value: T?

    private enum CodingKeys: String, CodingKey { case read }

    init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        if try c.decode(Bool.self, forKey: .read) {
            value = try T(from: decoder)
        } else {
            value = nil
        }
    }
}

/// `worldSpend`, when read.
struct WireSpend: Decodable {
    let currency: String
    let period: String
    let totalCents: Int
    let expectedCents: Int
    let confirmedCents: Int?
    let hasConfirmation: Bool
    let confirmedThrough: Date?
    let limitCents: Int?
    let recordedLimitCents: Int?
    let level: String
    let checkpointStale: Bool
    let notMetered: [String]
    let caveats: [String]

    enum CodingKeys: String, CodingKey {
        case currency, period
        case totalCents = "total_cents"
        case expectedCents = "expected_cents"
        case confirmedCents = "confirmed_cents"
        case hasConfirmation = "has_confirmation"
        case confirmedThrough = "confirmed_through"
        case limitCents = "limit_cents"
        case recordedLimitCents = "recorded_limit_cents"
        case level
        case checkpointStale = "checkpoint_stale"
        case notMetered = "not_metered"
        case caveats
    }

    init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        currency = try c.decode(String.self, forKey: .currency)
        period = try c.decode(String.self, forKey: .period)
        totalCents = try c.decode(Int.self, forKey: .totalCents)
        expectedCents = try c.decode(Int.self, forKey: .expectedCents)
        confirmedCents = try c.decodeIfPresent(Int.self, forKey: .confirmedCents)
        hasConfirmation = try c.decode(Bool.self, forKey: .hasConfirmation)
        confirmedThrough = try c.decodeIfPresent(Date.self, forKey: .confirmedThrough)
        limitCents = try c.decodeIfPresent(Int.self, forKey: .limitCents)
        recordedLimitCents = try c.decodeIfPresent(Int.self, forKey: .recordedLimitCents)
        level = try c.decode(String.self, forKey: .level)
        checkpointStale = try c.decode(Bool.self, forKey: .checkpointStale)
        notMetered = try c.decodeIfPresent([String].self, forKey: .notMetered) ?? []
        caveats = try c.decodeIfPresent([String].self, forKey: .caveats) ?? []
    }
}

/// `worldNetwork`, when read: every field a pointer.
struct WireNetwork: Decodable {
    let replica: String?
    let since: Date?
    let fatlineReplicas: Int?

    enum CodingKeys: String, CodingKey {
        case replica, since
        case fatlineReplicas = "fatline_replicas"
    }
}

/// One of FarCast's own components, by role.
struct WireComponent: Decodable {
    let role: String
    let name: String
    let state: String
    let ready: Int?
    let desired: Int?
}

struct WireGroup: Decodable {
    let namespace: String
    let metered: Bool?
    let provenance: WireProvenance?
    let apps: [WireApp]

    enum CodingKeys: String, CodingKey { case namespace, metered, provenance, apps }

    init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        namespace = try c.decode(String.self, forKey: .namespace)
        metered = try c.decodeIfPresent(Bool.self, forKey: .metered)
        provenance = try c.decodeIfPresent(WireProvenance.self, forKey: .provenance)
        apps = try c.decodeIfPresent([WireApp].self, forKey: .apps) ?? []
    }
}

/// What `run` recorded on this Mac for a namespace. Only what the group's
/// label uses is read.
struct WireProvenance: Decodable {
    let repository: String
    let ref: String
    let commit: String
}

struct WireApp: Decodable {
    let name: String
    let state: String
    let ready: Int?
    let desired: Int?
    let stoppedBy: String?
    let monthCents: Int?

    enum CodingKeys: String, CodingKey {
        case name, state, ready, desired
        case stoppedBy = "stopped_by"
        case monthCents = "month_cents"
    }
}

struct WireHost: Decodable {
    let name: String
    let seenAs: [String]

    enum CodingKeys: String, CodingKey {
        case name
        case seenAs = "seen_as"
    }

    init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        name = try c.decode(String.self, forKey: .name)
        seenAs = try c.decodeIfPresent([String].self, forKey: .seenAs) ?? []
    }
}

/// Where a line starts or ends: one key of four. Every key is omitempty;
/// which combinations are legal is the mapping's call.
struct WireEnd: Decodable {
    let app: String?
    let host: String?
    let device: String?
    let component: String?
}

/// Any of the five line kinds. Each kind carries only its own fields, so
/// only the four every line has are required.
struct WireLine: Decodable {
    let kind: String
    let from: WireEnd
    let to: WireEnd
    let evidence: String
    let ports: [WirePort]
    let stale: Bool?
    let drift: Bool?
    let lastSeen: Date?
    let since: Date?
    let labelHint: String?

    enum CodingKeys: String, CodingKey {
        case kind, from, to, evidence, ports, stale, drift, since
        case lastSeen = "last_seen"
        case labelHint = "label_hint"
    }

    init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        kind = try c.decode(String.self, forKey: .kind)
        from = try c.decode(WireEnd.self, forKey: .from)
        to = try c.decode(WireEnd.self, forKey: .to)
        evidence = try c.decode(String.self, forKey: .evidence)
        ports = try c.decodeIfPresent([WirePort].self, forKey: .ports) ?? []
        stale = try c.decodeIfPresent(Bool.self, forKey: .stale)
        drift = try c.decodeIfPresent(Bool.self, forKey: .drift)
        lastSeen = try c.decodeIfPresent(Date.self, forKey: .lastSeen)
        since = try c.decodeIfPresent(Date.self, forKey: .since)
        labelHint = try c.decodeIfPresent(String.self, forKey: .labelHint)
    }
}

/// One port of an egress line, graded on its own.
struct WirePort: Decodable {
    let evidence: String
    let count: Int?
    let fails: Int?
    let noLongerDeclared: Bool

    enum CodingKeys: String, CodingKey {
        case evidence, count, fails
        case noLongerDeclared = "no_longer_declared"
    }

    init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        evidence = try c.decode(String.self, forKey: .evidence)
        count = try c.decodeIfPresent(Int.self, forKey: .count)
        fails = try c.decodeIfPresent(Int.self, forKey: .fails)
        noLongerDeclared = try c.decodeIfPresent(Bool.self, forKey: .noLongerDeclared) ?? false
    }
}

struct WireDevice: Decodable {
    let id: String
    let role: String
    let name: String?
    let health: String?
}

/// What an alert is about: one key of four, `instance` false when absent.
struct WireSubject: Decodable {
    let app: String?
    let component: String?
    let device: String?
    let instance: Bool

    enum CodingKeys: String, CodingKey { case app, component, device, instance }

    init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        app = try c.decodeIfPresent(String.self, forKey: .app)
        component = try c.decodeIfPresent(String.self, forKey: .component)
        device = try c.decodeIfPresent(String.self, forKey: .device)
        instance = try c.decodeIfPresent(Bool.self, forKey: .instance) ?? false
    }
}

struct WireAlert: Decodable {
    let id: String
    let kind: String
    let severity: String
    let subject: WireSubject
    let title: String
}

struct WireSections: Decodable {
    let spend: WireSectionStatus
    let apps: WireSectionStatus
    let policy: WireSectionStatus
    let network: WireSectionStatus
    let seal: WireSectionStatus
}

struct WireSectionStatus: Decodable {
    let read: Bool
    let skipped: String?
    let error: WireProblem?
}

// MARK: - The error envelope

/// `{"error":{"message","code","kind"}}`: what every command prints on
/// stdout in JSON mode when it fails, exit code 1.
struct WireEnvelope: Decodable {
    struct Body: Decodable {
        let message: String
        let code: Int
        let kind: String?
    }

    let error: Body
}
