import Foundation
import Testing
@testable import FarSightCore
@testable import FarSightFixtures

/// The world as the Connected view reads it: tolerant where a newer CLI may
/// add a word, strict where the map's structure rests on one, and honest
/// about what was not read.
@Suite("A live world")
struct LiveWorldTests {
    /// The fixture as a live world could hold it: no sketch, no planned line,
    /// no app to app.
    static func liveFixture() throws -> World {
        var world = try Fixtures.world()
        world.source = .live
        let sketches = Set(world.instances.flatMap(\.groups).filter(\.isIllustrative).flatMap(\.apps).map(\.id))
        for i in world.instances.indices { world.instances[i].groups.removeAll(where: \.isIllustrative) }
        world.connections.removeAll { line in
            line.evidence == .planned || line.kind == .appToApp
                || [line.from, line.to].contains { $0.appID.map(sketches.contains) ?? false }
        }
        world.hosts.removeAll { host in !world.connections.contains { $0.to == .host(host.id) } }
        return world
    }

    func decode<T: Decodable>(_ type: T.Type, _ json: String) throws -> T {
        try World.decoder().decode(type, from: Data(json.utf8))
    }

    // MARK: - Tolerant and strict decoding

    @Test("a value this build does not know decodes as unknown, in every tolerant enum")
    func unknownValuesDecode() throws {
        #expect(try decode([AppState].self, #"["running", "hibernating"]"#) == [.running, .unknown])
        #expect(try decode([AppState].self, #"["starting", "notDeployed"]"#) == [.starting, .notDeployed])
        #expect(try decode([Spending.Level].self, #"["warn90", "warn99"]"#) == [.warn90, .unknown])
        #expect(try decode([Device.Health].self, #"["revoked", "quarantined"]"#) == [.revoked, .unknown])
        #expect(try decode([Instance.Status].self, #"["deleting", "migrating"]"#) == [.deleting, .unknown])
        #expect(try decode([Instance.CloudLogging].self, #"["systemOnly", "everything"]"#) == [.systemOnly, .unknown])
        #expect(try decode([SectionProblem.Kind].self, #"["timeout", "quota_exceeded"]"#) == [.timeout, .unknown])
        #expect(try decode([SectionProblem.Section].self, #"["seal", "billing"]"#) == [.seal, .unknown])
        #expect(try decode([WorldAlert.Kind].self, #"["drift", "solar_flare"]"#) == [.drift, .unknown])
        // Not `unknown`, but as defined: a severity sorts and draws as a
        // warning, and a source is held to the live rules.
        #expect(try decode([WorldAlert.Severity].self, #"["critical", "catastrophic"]"#) == [.critical, .warning])
        #expect(try decode([World.Source].self, #"["fixture", "replay"]"#) == [.fixture, .live])
    }

    @Test("a whole instance with new words in it still decodes, with what it does not know as unknown")
    func toleratedInstance() throws {
        let instance = try decode(Instance.self, #"""
        {
          "id": "atlas", "status": "hibernating", "cloudLogging": "verbose", "readAt": "2026-11-12T10:00:00Z",
          "problems": [{ "section": "billing", "kind": "quota_exceeded", "message": "later" }],
          "spending": { "level": "warn99", "expectedCents": 100, "totalCents": 100, "limitCents": 1000 },
          "groups": []
        }
        """#)
        #expect(instance.status == .unknown)
        #expect(instance.cloudLogging == .unknown)
        #expect(instance.problems == [SectionProblem(section: .unknown, kind: .unknown, message: "later")])
        #expect(instance.spending.level == .unknown)
        #expect(instance.readAt == Date(timeIntervalSince1970: 1_794_477_600))
    }

    @Test(
        "a value the map's structure rests on is refused, so the read fails and keeps its last good snapshot",
        arguments: [
            #"{"kind": "teleport", "evidence": "observed"}"#,
            #"{"kind": "egress", "evidence": "rumoured"}"#,
            #"{"role": "scheduler"}"#,
            #"{"device": "tablet"}"#,
            #"{"subject": "component:boundary"}"#,
            #"{"subject": "app:"}"#,
            #"{"endpoint": "route:x"}"#,
        ]
    )
    func strictEnumsRefuse(json: String) {
        struct Probe: Decodable {
            var kind: Connection.Kind?
            var evidence: Connection.Evidence?
            var role: SystemRole?
            var device: DeviceRole?
            var subject: AlertSubject?
            var endpoint: Endpoint?
        }
        #expect(throws: DecodingError.self) { try decode(Probe.self, json) }
    }

    @Test("alert subjects read the way endpoints do")
    func alertSubjectCoding() throws {
        let subjects: [AlertSubject] = [.app("atlas/home/notes"), .instance("atlas"), .device("atlas/ubuntu-vm")]
        let data = try JSONEncoder().encode(subjects)
        #expect(String(decoding: data, as: UTF8.self) == #"["app:atlas\/home\/notes","instance:atlas","device:atlas\/ubuntu-vm"]"#)
        #expect(try JSONDecoder().decode([AlertSubject].self, from: data) == subjects)
    }

    @Test("the fixture round-trips through the world's own coding")
    func roundTrip() throws {
        let world = try Fixtures.world()
        let data = try World.encoder().encode(world)
        #expect(try World.decoder().decode(World.self, from: data) == world)
        #expect(world.source == .fixture)
        #expect(world.instances.allSatisfy { $0.status == .running && $0.spending.hasConfirmation })
    }

    // MARK: - Live validation

    @Test("a live map refuses illustrative groups and apps, planned lines and app-to-app lines")
    func liveRefusesIllustrative() throws {
        var world = try Fixtures.world()
        world.source = .live
        #expect {
            try world.validate()
        } throws: { error in
            let text = (error as? WorldError)?.description ?? ""
            return text.contains("live world has illustrative group atlas/shop")
                && text.contains("live world has illustrative app atlas/shop/web")
                && text.contains("live world has planned line e6")
                && text.contains("live world has app-to-app line e7")
        }
        try Self.liveFixture().validate()
    }

    @Test("the fixture's cost alert follows the CLI's rule: about the instance, a warning short of the limit, critical at it")
    func fixtureCostAlert() throws {
        let world = try Fixtures.world()
        let costs = world.alerts.filter { $0.kind == .cost }
        #expect(!costs.isEmpty)
        for alert in costs {
            guard case .instance(let id) = alert.subject else {
                Issue.record("cost alert \(alert.id) is about \(alert.subject), not an instance")
                continue
            }
            let level = try #require(world.instances.first { $0.id == id }?.spending.level)
            #expect(alert.severity == (level == .reached ? .critical : .warning), "\(alert.id) at \(level)")
        }
    }

    @Test("a snapshot that does not say where it came from is held to the live rules")
    func missingSourceIsLive() throws {
        let world = try decode(World.self, #"{"instances": [], "devices": [], "hosts": [], "connections": [], "alerts": []}"#)
        #expect(world.source == .live)
    }

    @Test("an instance that could not be read validates: its system group, unknown states, its problem, no figure")
    func unreadableInstanceValidates() throws {
        let unreadable = Instance.notYetRead(InstanceListing(
            name: "broken",
            problem: SectionProblem(section: .record, kind: .recordUnreadable, message: "metadata.yaml: bad indent")
        ))
        let unread = Instance.notYetRead(InstanceListing(
            name: "atlas", status: .running, cloudLogging: .systemOnly, recordedLimitCents: 15000,
            components: [.kernel: true, .boundary: true, .storage: false]
        ))
        let world = World(instances: [unreadable, unread], source: .live)
        try world.validate()

        #expect(unreadable.groups.map(\.id) == ["broken/farcast-system"])
        #expect(unreadable.groups[0].apps.map(\.id) == [
            "broken/farcast-system/technocore", "broken/farcast-system/shrike",
            "broken/farcast-system/fatline", "broken/farcast-system/datasphere",
        ])
        #expect(unreadable.groups[0].apps.allSatisfy { $0.state == .unknown })
        #expect(unreadable.problems.map(\.kind) == [.recordUnreadable])
        #expect(!unreadable.spending.isRead && unreadable.spending.limitCents == nil && unreadable.spending.fraction == nil)
        // The record says DataSphere's keyholder was never deployed; what it
        // does not mention is not known either way.
        let states = Dictionary(uniqueKeysWithValues: unread.groups[0].apps.map { ($0.system!, $0.state) })
        #expect(states == [.kernel: .unknown, .monitor: .unknown, .boundary: .unknown, .storage: .notDeployed])
        #expect(unread.spending.recordedLimitCents == 15000 && unread.spending.limitCents == nil)
    }

    @Test("an instance whose record and spending were read still needs a cost limit; one whose record or spending failed does not")
    func limitOnlyWhereRead() throws {
        // As a reader might build it, with nothing said about the record.
        var listed = Instance.notYetRead(InstanceListing(name: "atlas", status: .running))
        listed.problems = []
        let missing = World(instances: [listed], source: .live)
        #expect(throws: WorldError(problems: ["instance atlas has no cost limit"])) { try missing.validate() }
        listed.problems = [SectionProblem(section: .record, kind: .recordUnreadable, message: "")]
        try World(instances: [listed], source: .live).validate()
        // A world read from an instance carries both limits only inside its
        // spending section: with that section failed, neither is required.
        listed.problems = [SectionProblem(section: .spend, kind: .notCheckpointed, message: "the ledger is empty")]
        try World(instances: [listed], source: .live).validate()
        listed.problems = []
        listed.spending.recordedLimitCents = 0
        #expect(throws: WorldError(problems: ["instance atlas has no recorded cost limit"])) {
            try World(instances: [listed], source: .live).validate()
        }
    }

    @Test(
        "a listing whose record holds no limit, or one that is not a limit, is drawn with that said, never refused",
        arguments: [nil, 0, -5, World.maxCents + 1] as [Int?]
    )
    func badRecordLimitIsAProblem(limit: Int?) throws {
        let listing = InstanceListing(name: "legacy", status: .running, cloudLogging: .systemOnly, recordedLimitCents: limit)
        let instance = Instance.notYetRead(listing)
        try World(instances: [instance], source: .live).validate()
        #expect(instance.spending.recordedLimitCents == nil && instance.spending.limitCents == nil)
        #expect(instance.status == .running)
        let problem = try #require(instance.problem(in: .record))
        #expect(problem.kind == .internal)
        #expect(problem.message.contains(limit == nil ? "holds no cost limit" : "\(limit ?? 0) cents"))
        // A good one is kept as it is, with nothing said.
        let good = InstanceListing(name: "atlas", status: .running, recordedLimitCents: 5000)
        #expect(good.drawableLimitCents == 5000 && good.recordProblems.isEmpty)
        #expect(Instance.notYetRead(good).spending.recordedLimitCents == 5000)
        // An unreadable record already says so, and a limit it lacks adds
        // nothing to that.
        let unreadable = InstanceListing(
            name: "broken", status: .deleting,
            problem: SectionProblem(section: .record, kind: .recordUnreadable, message: "bad indent")
        )
        #expect(unreadable.recordProblems.map(\.kind) == [.recordUnreadable])
    }

    @Test("what states no health or state was not read: a keeper's health is unknown and an app's state unknown; the operator's Mac is healthy")
    func unstatedIsNotRead() throws {
        let devices = try decode([Device].self, #"""
        [{ "id": "operator", "name": "This Mac", "role": "operator", "note": "" },
         { "id": "atlas/phone", "name": "phone", "role": "keeper", "note": "" }]
        """#)
        #expect(devices.map(\.health) == [.healthy, .unknown])
        #expect(Device(id: "operator", name: "This Mac", role: .operator, note: "").health == .healthy)
        #expect(Device(id: "atlas/phone", name: "phone", role: .keeper, note: "").health == .unknown)
        #expect(Device(id: "atlas/phone", name: "phone", role: .keeper, note: "", health: .revoked).health == .revoked)
        #expect(Application(id: "atlas/web/site", name: "site", role: "").state == .unknown)
    }

    @Test("an alert must be about an app, instance or device the world holds")
    func alertSubjectsExist() throws {
        var world = try Self.liveFixture()
        world.alerts.append(WorldAlert(id: "i", kind: .loggingUnverified, severity: .warning, title: "", subject: .instance("atlas")))
        world.alerts.append(WorldAlert(id: "d", kind: .keeper, severity: .warning, title: "", subject: .device("pixel-phone")))
        try world.validate()
        world.alerts.append(WorldAlert(id: "x", kind: .loggingUnverified, severity: .warning, title: "", subject: .instance("ghost")))
        world.alerts.append(WorldAlert(id: "y", kind: .keeper, severity: .warning, title: "", subject: .device("ghost")))
        #expect {
            try world.validate()
        } throws: { error in
            let text = (error as? WorldError)?.description ?? ""
            return text.contains("alert x points at unknown instance ghost") && text.contains("alert y points at unknown device ghost")
        }
    }

    @Test("a reader's world is one instance, from its source, with every id under the instance's prefix")
    func readSlices() throws {
        let fixture = try Fixtures.world()
        var slice = FixtureReader.slice(fixture, fixture.instances[0])
        try slice.validate(asReadOf: "atlas", source: .fixture)
        #expect(slice.devices.map(\.id).sorted() == ["atlas/ubuntu-vm", "operator"])
        #expect(slice.hosts.allSatisfy { $0.id.hasPrefix("atlas/") })
        #expect(throws: WorldError.self) { try slice.validate(asReadOf: "atlas", source: .live) }
        #expect(throws: WorldError.self) { try slice.validate(asReadOf: "borealis", source: .fixture) }
        slice.hosts[0].id = "maps"
        slice.connections = slice.connections.map { line in
            var line = line
            if line.to == .host("atlas/maps") { line.to = .host("maps") }
            return line
        }
        #expect {
            try slice.validate(asReadOf: "atlas", source: .fixture)
        } throws: { error in
            (error as? WorldError)?.description.contains("host maps is not under atlas/") ?? false
        }
    }

    @Test("the fixture reader lists the fixture's instances and reads each as a slice")
    func fixtureReader() async throws {
        let reader = try FixtureReader()
        let listing = try await reader.listInstances()
        #expect(listing.map(\.name) == ["atlas", "borealis"])
        #expect(listing.allSatisfy { $0.components.values.allSatisfy { $0 } && $0.components.count == 4 })
        #expect(listing.map(\.recordedLimitCents) == [15000, 6000])
        for entry in listing {
            let world = try await reader.readWorld(entry.name)
            try world.validate(asReadOf: entry.name, source: .fixture)
        }
        await #expect(throws: ReadFailure(kind: .notFound, message: "no instance ghost in the fixture")) {
            try await reader.readWorld("ghost")
        }
    }

    // MARK: - Spending, devices

    @Test("the bar is confirmed then expected, against the kernel's limit, and nothing when either was not read")
    func spendingBar() throws {
        let read = Spending(expectedCents: 1280, confirmedCents: 2900, totalCents: 4180, limitCents: 15000, hasConfirmation: true)
        let bar = try #require(read.bar)
        #expect(abs(bar.confirmed - 2900.0 / 15000) < 1e-12)
        #expect(abs(bar.expected - 1280.0 / 15000) < 1e-12)
        #expect(read.fraction == 4180.0 / 15000)
        let over = Spending(expectedCents: 900, confirmedCents: 1500, totalCents: 2400, limitCents: 1000, hasConfirmation: true)
        #expect(over.bar.map { $0.confirmed + $0.expected } == 1)
        let unconfirmed = Spending(expectedCents: 100, confirmedCents: 0, totalCents: 100, limitCents: 1000)
        #expect(unconfirmed.bar?.confirmed == 0)
        // The kernel published no limit: no share is made up from the
        // recorded one.
        let noKernelLimit = Spending(expectedCents: 100, totalCents: 100, recordedLimitCents: 1000)
        #expect(noKernelLimit.bar == nil && noKernelLimit.fraction == nil)
        #expect(!Spending(recordedLimitCents: 1000).isRead)
    }

    @Test("a device not read is not called unhealthy; one expired, revoked or unseen is")
    func deviceHealth() {
        func healthy(_ health: Device.Health) -> Bool {
            Device(id: "k", name: "k", role: .keeper, note: "", health: health).isHealthy
        }
        #expect(healthy(.healthy) && healthy(.unknown))
        #expect(!healthy(.expired) && !healthy(.revoked) && !healthy(.unseen))
    }

    // MARK: - Display

    @Test("display text escapes what is not printable, as the CLI's errorText does")
    func displaySanitising() {
        let both: [(String, String)] = [
            ("plain.example.test", "plain.example.test"),
            ("evil\u{202E}txt.exe", "evil\\u202etxt.exe"),        // bidi override
            ("a\u{85}b", "a\\u0085b"),                             // C1 control
            ("\u{1B}[31mred", "\\x1b[31mred"),                     // escape
            ("line\rover", "line\\rover"),
            ("del\u{7F}", "del\\x7f"),
            ("bell\u{07}\u{08}\u{0C}\u{0B}", "bell\\a\\b\\f\\v"),
            ("nul\u{0}", "nul\\x00"),
            ("zero\u{200D}width", "zero\\u200dwidth"),
            ("nb\u{A0}sp", "nb\\u00a0sp"),
            ("soft\u{AD}hyphen", "soft\\u00adhyphen"),
            ("sep\u{2028}", "sep\\u2028"),
            ("tag\u{E0001}", "tag\\U000e0001"),
            ("é 日本 😀 e\u{301} \u{FFFD} → ·", "é 日本 😀 e\u{301} \u{FFFD} → ·"),
            ("👨\u{200D}👩", "👨\\u200d👩"),
        ]
        for (input, output) in both {
            #expect(Display.name(input) == output)
            #expect(Display.message(input) == output)
        }
        #expect(Display.name("two\nlines\tand a tab") == "two\\nlines\\tand a tab")
        #expect(Display.message("two\nlines\tand a tab") == "two\nlines\tand a tab")
    }

    @Test("a document with a byte that is not UTF-8 is refused whole, so no such byte reaches the screen")
    func invalidUTF8() {
        let bad = Data([0x7B, 0x22, 0x6E, 0x22, 0x3A, 0x22, 0x61, 0xFF, 0x62, 0x22, 0x7D])  // {"n":"a?b"}
        #expect(throws: DecodingError.self) { try JSONDecoder().decode([String: String].self, from: bad) }
    }
}
