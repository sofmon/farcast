import Foundation
import Testing
@testable import FarSightCore

/// The adapter against the CLI's own golden vectors: the documents
/// `farcast` prints, byte for byte, decoded as the Connected view decodes
/// them (ADR 0021 decision 7 and Verification 4).
@Suite("The CLI's vectors")
struct VectorTests {
    /// Every world vector present today. A new one in Go fails here until it
    /// gains an expectation.
    static let worldVectors = [
        "account_in_message.json", "checkpoint_version_skew.json", "cost_reached_stopped_apps.json", "drift.json",
        "error_gcloud_mismatch.json", "error_not_found.json", "healthy.json", "host_cap_exceeded.json",
        "hostile_host_name.json", "keepers.json", "mixed_evidence.json", "never_connected.json", "no_kernel.json",
        "nothing_read.json", "release_incomplete.json", "removed_app_violation.json", "sealed_replica.json",
        "shared_app_name.json", "stale_checkpoint.json", "system_namespace_rows.json", "tunnel_down.json",
        "unattributed_denial.json", "unmetered_namespace.json",
    ]

    /// A world vector, read as the app reads `atlas`, and checked as the
    /// feed checks it.
    static func world(_ name: String) throws -> World {
        let world = try CLIDocuments.world(try Vectors.data("world/\(name).json"), asReadOf: "atlas").world
        try world.validate(asReadOf: "atlas", source: .live)
        return world
    }

    static func instance(_ world: World) throws -> Instance {
        try #require(world.instances.first)
    }

    static func line(_ world: World, to host: String) throws -> Connection {
        try #require(world.connections.first { $0.kind == .egress && $0.to == .host("atlas/\(host)") })
    }

    static let technocore = "atlas/farcast-system/technocore"
    static let fatline = "atlas/farcast-system/fatline"
    static let datasphere = "atlas/farcast-system/datasphere"

    @Test("every world vector is decoded and validates, or is refused with its kind")
    func everyWorldVectorIsDecodedOrRefused() throws {
        let names = try Vectors.names("world")
        #expect(names == Self.worldVectors)
        let refusals: [String: SectionProblem.Kind] = [
            "error_gcloud_mismatch.json": .gcloudMismatch,
            "error_not_found.json": .notFound,
        ]
        for name in names {
            let data = try Vectors.data("world/\(name)")
            if let kind = refusals[name] {
                #expect(CLIDocuments.failure(data)?.kind == kind, "\(name)")
                #expect(failure { _ = try CLIDocuments.world(data, asReadOf: "atlas") }?.kind == kind, "\(name)")
                continue
            }
            let world = try CLIDocuments.world(data, asReadOf: "atlas").world
            #expect(world.source == .live, "\(name)")
            #expect(throws: Never.self, "\(name)") { try world.validate(asReadOf: "atlas", source: .live) }
        }
    }

    @Test("healthy: every section read, the replica named, spending split, every id prefixed")
    func healthy() throws {
        let document = try CLIDocuments.world(try Vectors.data("world/healthy.json"), asReadOf: "atlas")
        #expect(document.stamp == CLIStamp(version: "v0.0.0-vector", commit: "0e54eb1"))
        let world = try Self.world("healthy")
        let instance = try Self.instance(world)
        #expect(instance.problems.isEmpty)
        #expect(instance.status == .running)
        #expect(instance.cloudLogging == .systemOnly)
        #expect(instance.readAt == Date(timeIntervalSince1970: 1_794_477_600))
        #expect(instance.network?.replica == "fatline-5d8c7b9f4-x2k7q")
        #expect(instance.network?.fatlineReplicas == 2)
        #expect(instance.network?.since == Date(timeIntervalSince1970: 1_794_384_000))
        #expect(instance.caveats.isEmpty)

        let spending = instance.spending
        #expect(spending.confirmedCents == 464)
        #expect(spending.expectedCents == 1805)
        #expect(spending.totalCents == 2269)
        #expect(spending.limitCents == 5000)
        #expect(spending.recordedLimitCents == 5000)
        #expect(spending.hasConfirmation)
        #expect(spending.level == .ok)
        #expect(spending.notMetered.count == 5)

        let groups = instance.groups
        #expect(groups.map(\.id) == ["atlas/farcast-system", "atlas/shop"])
        #expect(groups[0].isSystem && groups[0].source == "FarCast")
        #expect(groups[0].apps.map(\.id) == SystemComponent.all.map { SystemComponent.appID($0.role, in: "atlas") })
        #expect(groups[0].apps.allSatisfy { $0.state == .running })
        #expect(groups[1].source == "github.com/example/shop · main at 4f2a9c1")
        let api = try #require(groups[1].apps.first { $0.name == "api" })
        #expect(api.id == "atlas/shop/api")
        #expect(api.monthCents == 825 && api.costNote == nil)
        #expect(api.role == "2 of 2 ready")

        let tunnel = try #require(world.connections.first { $0.kind == .tunnel })
        #expect(tunnel.from == .device("operator"))
        #expect(tunnel.to == .app(Self.fatline))
        #expect(tunnel.label == "you · this read")

        let stripe = try Self.line(world, to: "api.stripe.com")
        #expect(stripe.id == "atlas/egress:app:shop/api>host:api.stripe.com")
        #expect(stripe.from == .app("atlas/shop/api"))
        #expect(stripe.evidence == .observed)
        #expect(stripe.count == 120)
        #expect(stripe.label == "≥120 ok · ≥2 failed")
        #expect(try Self.line(world, to: "sentry.io").label == "declared · unused")

        let host = try #require(world.hosts.first { $0.name == "api.stripe.com" })
        #expect(host.id == "atlas/api.stripe.com" && host.instanceID == "atlas")
        #expect(host.note == "reached by shop/api")
        #expect(world.hosts.first { $0.name == "sentry.io" }?.note == "declared by shop/api, never used")

        let keeper = try #require(world.devices.first { $0.id == "atlas/phone" })
        #expect(keeper.health == .healthy)
        #expect(keeper.name == "phone" && keeper.note == "keeper for atlas")
        #expect(world.devices.first { $0.role == .operator }?.name == "This Mac")
        #expect(world.connections.contains { $0.kind == .keeper && $0.from == .device("atlas/phone") && $0.to == .app(Self.datasphere) })
        #expect(world.connections.contains { $0.kind == .watch && $0.label == "watches" })
        #expect(world.connections.filter { $0.kind == .storage }.allSatisfy { $0.label == "storage · wired, not counted" })

        let apps = instance.groups.flatMap(\.apps)
        #expect(apps.allSatisfy { $0.id.hasPrefix("atlas/") })
        #expect(world.connections.allSatisfy { $0.id.hasPrefix("atlas/") })
        #expect(world.alerts.isEmpty)
    }

    @Test("never_connected: no tunnel recorded, the seal skipped, nothing drawn between")
    func neverConnected() throws {
        let instance = try Self.instance(Self.world("never_connected"))
        let world = try Self.world("never_connected")
        #expect(instance.problem(in: .network)?.kind == .notConnected)
        #expect(instance.problem(in: .seal) == nil)
        #expect(instance.network == nil)
        #expect(world.connections.isEmpty)
        #expect(instance.groups.count == 1)
    }

    @Test("nothing_read: five problems, with the vector's kinds; spending not read")
    func nothingRead() throws {
        let instance = try Self.instance(Self.world("nothing_read"))
        #expect(instance.problems.map(\.section) == [.spend, .apps, .policy, .network, .seal])
        #expect(instance.problems.map(\.kind) == [.gcloudSignedOut, .gcloudSignedOut, .gcloudSignedOut, .tunnelUnreachable, .tunnelUnreachable])
        #expect(!instance.spending.isRead)
        #expect(instance.spending.level == .unknown)
        #expect(instance.groups.flatMap(\.apps).filter { $0.system != nil }.allSatisfy { $0.state == .unknown })
    }

    @Test("release_incomplete: the instance may still be billing, and the alert is about it")
    func releaseIncomplete() throws {
        let world = try Self.world("release_incomplete")
        #expect(try Self.instance(world).status == .deleting)
        let alert = try #require(world.alerts.first { $0.kind == .releaseIncomplete })
        #expect(alert.subject == .instance("atlas"))
        #expect(alert.severity == .critical)
        #expect(alert.id == "atlas/release_incomplete:instance")
    }

    @Test("sealed_replica: the sealed alert is on DataSphere")
    func sealedReplica() throws {
        let alert = try #require(try Self.world("sealed_replica").alerts.first { $0.kind == .sealed })
        #expect(alert.subject == .app(Self.datasphere))
    }

    @Test("stale_checkpoint: the checkpoint is stale, and the alert is on TechnoCore")
    func staleCheckpoint() throws {
        let world = try Self.world("stale_checkpoint")
        #expect(try Self.instance(world).spending.isCheckpointStale)
        let alert = try #require(world.alerts.first { $0.kind == .checkpointStale })
        #expect(alert.subject == .app(Self.technocore))
    }

    @Test("unmetered_namespace: the alert names the namespace and sits on TechnoCore; the group says it is not metered")
    func unmeteredNamespace() throws {
        let world = try Self.world("unmetered_namespace")
        let alert = try #require(world.alerts.first { $0.kind == .unmeteredNamespace })
        #expect(alert.id == "atlas/unmetered_namespace:component:kernel:lab")
        #expect(alert.subject == .app(Self.technocore))
        let lab = try #require(try Self.instance(world).groups.first { $0.namespace == "lab" })
        #expect(lab.source.hasSuffix("· not metered"))
        #expect(lab.source == "repository not recorded on this Mac · not metered")
        #expect(lab.apps.first?.costNote == "not metered")
        #expect(try Self.instance(world).caveats == ["storage wiring unknown for lab"])
    }

    @Test("checkpoint_version_skew: the spend section's problem is version skew")
    func checkpointVersionSkew() throws {
        #expect(try Self.instance(Self.world("checkpoint_version_skew")).problem(in: .spend)?.kind == .versionSkew)
    }

    @Test("shared_app_name: two apps of one name have no figure, and say why")
    func sharedAppName() throws {
        let webs = try Self.instance(Self.world("shared_app_name")).groups.flatMap(\.apps).filter { $0.name == "web" }
        #expect(webs.map(\.id) == ["atlas/blog/web", "atlas/shop/web"])
        for web in webs {
            #expect(web.monthCents == nil)
            #expect(web.costNote == "not told apart from an app of the same name")
        }
    }

    @Test("mixed_evidence: one line, counted and refused")
    func mixedEvidence() throws {
        let label = try Self.line(Self.world("mixed_evidence"), to: "api.stripe.com").label
        #expect(label.contains("ok") && label.contains("refused"))
        let host = try #require(try Self.world("mixed_evidence").hosts.first { $0.name == "api.stripe.com" })
        #expect(host.note.contains("also written API.Stripe.com."))
    }

    @Test("drift: a host the policy does not declare is said so, and alerted")
    func drift() throws {
        let world = try Self.world("drift")
        #expect(try Self.line(world, to: "tracker.example").label.contains("not declared"))
        #expect(try Self.line(world, to: "old-cdn.example").label.contains("no longer declared"))
        #expect(try Self.line(world, to: "old-cdn.example").isStale)
        #expect(world.alerts.contains { $0.kind == .drift && $0.subject == .app("atlas/shop/api") })
    }

    @Test("unattributed_denial and system_namespace_rows: the alert is on FatLine")
    func unattributedDenials() throws {
        for name in ["unattributed_denial", "system_namespace_rows"] {
            let world = try Self.world(name)
            let alert = try #require(world.alerts.first { $0.kind == .unattributedDenials }, "\(name)")
            #expect(alert.subject == .app(Self.fatline), "\(name)")
        }
        #expect(try Self.instance(Self.world("system_namespace_rows")).caveats.count == 1)
    }

    @Test("hostile_host_name: the adapter keeps the bytes, and Display escapes them as Go does")
    func hostileHostName() throws {
        let world = try Self.world("hostile_host_name")
        let host = try #require(world.hosts.first { $0.name.unicodeScalars.contains("\u{202E}") })
        #expect(host.name == "pay\u{202E}pal\u{9B}.example")
        #expect(Display.name(host.name) == "pay\\u202epal\\u009b.example")
        let line = try #require(world.connections.first { $0.to == .host(host.id) })
        #expect(line.evidence == .denied)
        for drawn in [Display.name(line.label), Display.name(host.note), Display.name(host.name)] {
            #expect(!drawn.unicodeScalars.contains { $0 == "\u{202E}" || (0x80...0x9F).contains($0.value) }, "\(drawn)")
        }
    }

    @Test("host_cap_exceeded: 200 hosts, and an alert for the rest")
    func hostCapExceeded() throws {
        let world = try Self.world("host_cap_exceeded")
        #expect(world.hosts.count == 200)
        let alert = try #require(world.alerts.first { $0.kind == .hostsOmitted })
        #expect(alert.subject == .app(Self.fatline))
    }

    @Test("keepers: each keeper's health, and alerts on the devices that need attention")
    func keepers() throws {
        let world = try Self.world("keepers")
        let health = Dictionary(uniqueKeysWithValues: world.devices.map { ($0.id, $0.health) })
        #expect(health == ["atlas/laptop": .expired, "atlas/nas": .unseen, "atlas/phone": .healthy, "operator": .healthy])
        #expect(world.devices.first { $0.id == "atlas/laptop" }?.note == "keeper for atlas · leaf expired")
        #expect(world.devices.first { $0.id == "atlas/nas" }?.note == "keeper for atlas · not seen for a day")
        let subjects = Set(world.alerts.filter { $0.kind == .keeper }.map(\.subject))
        #expect(subjects == [.device("atlas/laptop"), .device("atlas/nas")])
        #expect(try Self.instance(world).network?.fatlineReplicas == 1)
    }

    @Test("removed_app_violation: an app the monitor names but the cluster does not run")
    func removedAppViolation() throws {
        let world = try Self.world("removed_app_violation")
        let worker = try #require(try Self.instance(world).groups.flatMap(\.apps).first { $0.name == "worker" })
        #expect(worker.state == .notDeployed)
        #expect(try Self.instance(world).caveats.count == 1)
        #expect(try Self.line(world, to: "queue.example").label == "≥3 refused")
        #expect(try Self.line(world, to: "queue.example").count == 3)
    }

    @Test("account_in_message: the CLI's messages are carried as they are; the adapter escapes nothing")
    func accountInMessage() throws {
        struct Sections: Decodable {
            struct Status: Decodable {
                struct Problem: Decodable { let message: String }
                let error: Problem?
            }

            let spend: Status, apps: Status, policy: Status
        }
        struct Document: Decodable { let sections: Sections }
        let wire = try JSONDecoder().decode(Document.self, from: try Vectors.data("world/account_in_message.json")).sections
        let instance = try Self.instance(Self.world("account_in_message"))
        #expect(instance.problem(in: .spend)?.message == wire.spend.error?.message)
        #expect(instance.problem(in: .apps)?.message == wire.apps.error?.message)
        #expect(instance.problem(in: .policy)?.message == wire.policy.error?.message)
        #expect(instance.problem(in: .policy)?.message.contains("\n") == true)
        #expect(instance.problem(in: .policy)?.kind == .gcloudSignedOut)
        #expect(instance.network?.fatlineReplicas == nil)
    }

    @Test("tunnel_down: nothing through the tunnel was read, and no tunnel is drawn")
    func tunnelDown() throws {
        let world = try Self.world("tunnel_down")
        let instance = try Self.instance(world)
        #expect(instance.network == nil)
        #expect(instance.problem(in: .network)?.kind == .tunnelUnreachable)
        #expect(instance.problem(in: .seal)?.kind == .tunnelUnreachable)
        #expect(!world.connections.contains { $0.kind == .tunnel })
    }

    @Test("cost_reached_stopped_apps: a critical cost alert, and the stopped apps as the vector has them")
    func costReachedStoppedApps() throws {
        let world = try Self.world("cost_reached_stopped_apps")
        let alert = try #require(world.alerts.first { $0.kind == .cost })
        #expect(alert.severity == .critical)
        #expect(alert.subject == .instance("atlas"))
        let shop = try #require(try Self.instance(world).groups.first { $0.namespace == "shop" })
        #expect(shop.apps.allSatisfy { $0.state == .stopped && $0.stopReason == nil })
        #expect(try Self.instance(world).spending.level == .reached)
        #expect(try Self.instance(world).spending.caveats.count == 1)
    }

    @Test("no_kernel: spending not read, so no app has a figure, and says why")
    func noKernel() throws {
        let instance = try Self.instance(Self.world("no_kernel"))
        #expect(instance.problem(in: .spend)?.kind == .kernelAbsent)
        let shop = try #require(instance.groups.first { $0.namespace == "shop" })
        #expect(shop.apps.allSatisfy { $0.monthCents == nil && $0.costNote == "spending not read" })
        #expect(shop.source.hasSuffix(" · not metered"))
        #expect(instance.groups[0].apps.first { $0.system == .kernel }?.state == .notDeployed)
    }

    @Test("the instances vectors: an empty listing, and one with unreadable records")
    func instancesVectors() throws {
        let empty = try CLIDocuments.instances(try Vectors.data("instances/empty.json"))
        #expect(empty.instances.isEmpty)
        #expect(empty.stamp == CLIStamp(version: "v0.0.0-vector", commit: "0e54eb1"))

        let listing = try CLIDocuments.instances(try Vectors.data("instances/unreadable.json"))
        #expect(listing.stamp == CLIStamp(version: "v0.0.0-vector", commit: "0e54eb1"))
        #expect(listing.instances.map(\.name) == ["atlas", "broken", "empty", "lab"])
        let atlas = listing.instances[0], broken = listing.instances[1], blank = listing.instances[2], lab = listing.instances[3]
        #expect(atlas.gcloudPinned == true)
        #expect(atlas.status == .running && atlas.cloudLogging == .systemOnly)
        #expect(atlas.components == [.boundary: true, .kernel: true, .storage: true])
        #expect(atlas.components[.monitor] == nil)
        #expect(atlas.recordedLimitCents == 5000 && atlas.problem == nil)
        for unreadable in [broken, blank] {
            #expect(unreadable.problem?.section == .record)
            #expect(unreadable.problem?.kind == .recordUnreadable)
            #expect(unreadable.status == .unknown && unreadable.components.isEmpty && unreadable.gcloudPinned == nil)
        }
        #expect(lab.status == .provisioning && lab.cloudLogging == .unverified)
        #expect(lab.gcloudPinned == false)
        #expect(lab.components == [.boundary: false, .monitor: false, .kernel: false, .storage: false])
        #expect(lab.recordedLimitCents == 1250)
    }

    @Test("the version vector: the stamp the app checks its own commit against")
    func versionVector() throws {
        #expect(try CLIDocuments.version(try Vectors.data("version/version.json")) == CLIStamp(version: "v0.0.0-vector", commit: "0e54eb1"))
    }

    @Test("every error kind the CLI can send maps to one the map knows, and every kind the map knows is sent")
    func everyErrorKindMaps() throws {
        struct Kinds: Decodable { let kinds: [String] }
        let wire = try JSONDecoder().decode(Kinds.self, from: try Vectors.data("kinds/kinds.json")).kinds
        #expect(wire.count == 14)
        let mapped = wire.map(CLIDocuments.kind)
        #expect(!mapped.contains(.unknown))
        #expect(Set(mapped) == Set(SectionProblem.Kind.allCases).subtracting([.unknown]))
        #expect(Set(mapped).count == wire.count)
    }

    @Test("the app's argv: three commands, flags first, -- before the instance")
    func appArgv() throws {
        let argv = try Vectors.argv()
        #expect(Set(argv.keys) == ["version", "instances", "world"])
        for command in [CLICommand.version, .instances, .world("atlas")] {
            let name = switch command {
            case .version: "version"
            case .instances: "instances"
            case .world: "world"
            }
            #expect(command.arguments(configDirectory: "/c") == (try Vectors.argv(name, config: "/c", instance: "atlas")))
        }
    }
}
