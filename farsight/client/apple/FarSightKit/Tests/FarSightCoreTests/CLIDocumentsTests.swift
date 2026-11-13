import Foundation
import Testing
@testable import FarSightCore

/// The adapter on documents made by hand: what a vector cannot show — a
/// schema this build does not read, a word it does not know, a figure the
/// map cannot draw, a field Go omits.
@Suite("Reading farcast's documents")
struct CLIDocumentsTests {
    /// A world document, schema 1, about `atlas`, each part replaceable.
    struct Doc {
        var schema: String? = "1"
        var name = "atlas"
        var status = "running"
        var level = "ok"
        var limit = "5000"
        var recorded = "5000"
        var expected = "1805"
        var total = "2269"
        var spend: String?
        var components = #"[{"role":"boundary","name":"fatline","state":"running","ready":2,"desired":2,"version":null},{"role":"kernel","name":"technocore","state":"running","ready":1,"desired":1,"version":null}]"#
        var groups = #"[{"namespace":"shop","metered":true,"provenance":null,"apps":[{"name":"api","state":"running","ready":1,"desired":1,"stopped_by":null,"month_cents":100}]}]"#
        var hosts = #"[{"name":"api.example","seen_as":[]}]"#
        var lines = #"[{"kind":"egress","from":{"app":"shop/api"},"to":{"host":"api.example"},"evidence":"observed","ports":[{"port":443,"evidence":"observed","count":3,"fails":0,"reason":null,"last_seen":null,"no_longer_declared":false}],"stale":false,"drift":false,"last_seen":null,"since":null},{"kind":"tunnel","from":{"device":"operator"},"to":{"component":"boundary"},"evidence":"observed","label_hint":"read_now"}]"#
        var devices = #"[{"id":"operator","role":"operator"},{"id":"atlas/phone","role":"keeper","name":"phone","health":"healthy"}]"#
        var alerts = "[]"
        var sections = #"{"spend":{"read":true},"apps":{"read":true},"policy":{"read":true},"network":{"read":true},"seal":{"read":true}}"#

        var json: String {
            let spend = self.spend ?? #"{"read":true,"currency":"USD","period":"monthly","total_cents":\#(total),"expected_cents":\#(expected),"confirmed_cents":464,"has_confirmation":true,"confirmed_through":"2026-11-08T00:00:00Z","limit_cents":\#(limit),"recorded_limit_cents":\#(recorded),"level":"\#(level)","checkpoint_stale":false,"not_metered":null,"caveats":null}"#
            let schema = self.schema.map { #""schema":\#($0),"# } ?? ""
            return #"{\#(schema)"generated_at":"2026-11-12T10:00:00Z","farcast":{"version":"v0","commit":"0e54eb1"},"instance":{"name":"\#(name)","status":"\#(status)","cloud_logging":"system_only","spend":\#(spend),"network":{"read":true,"replica":"fatline-0","since":null,"fatline_replicas":2},"components":\#(components),"hosts_omitted":0,"caveats":null},"groups":\#(groups),"hosts":\#(hosts),"lines":\#(lines),"devices":\#(devices),"alerts":\#(alerts),"sections":\#(sections)}"#
        }

        var data: Data { Data(json.utf8) }

        /// The world it reads as, checked as the feed checks it.
        func world() throws -> World {
            let world = try CLIDocuments.world(data, asReadOf: "atlas").world
            try world.validate(asReadOf: "atlas", source: .live)
            return world
        }

        /// Why it is refused.
        var refusal: ReadFailure? {
            failure { _ = try CLIDocuments.world(data, asReadOf: "atlas") }
        }
    }

    @Test("the hand-made document reads, and validates")
    func baseline() throws {
        let world = try Doc().world()
        let instance = try #require(world.instances.first)
        #expect(instance.problems.isEmpty)
        #expect(instance.groups.first?.apps.count == 4)
        #expect(instance.groups.first?.apps.filter { $0.state == .unknown }.map(\.system) == [.monitor, .storage])
        #expect(instance.groups.last?.source == "repository not recorded on this Mac")
        #expect(instance.spending.notMetered.isEmpty && instance.caveats.isEmpty)
    }

    @Test("a schema this build does not read is skew; no schema number is refused", arguments: [
        ("2", SectionProblem.Kind.versionSkew), (nil, .internal), (#""1""#, .internal), ("1.5", .internal), ("null", .internal),
    ] as [(String?, SectionProblem.Kind)])
    func schema(number: String?, kind: SectionProblem.Kind) {
        var doc = Doc()
        doc.schema = number
        #expect(doc.refusal?.kind == kind)
        let head = number.map { "\"schema\":\($0)," } ?? ""
        let listing = Data(#"{\#(head)"generated_at":"2026-11-12T10:00:00Z","farcast":{"version":"v0","commit":"0e54eb1"},"instances":[]}"#.utf8)
        #expect(failure { _ = try CLIDocuments.instances(listing) }?.kind == kind)
    }

    @Test("a schema-2 document of another shape reads as skew, not as one that could not be read")
    func skewBeforeShape() {
        let data = Data(#"{"schema":2,"instances":"a string now"}"#.utf8)
        let refusal = failure { _ = try CLIDocuments.instances(data) }
        #expect(refusal?.kind == .versionSkew)
        #expect(refusal?.message == "farcast wrote schema 2 and this FarCast reads schema 1; build both from the same commit")
    }

    @Test("what is not a JSON object is refused", arguments: ["not json", "[1,2]", "", "\"atlas\""])
    func notJSON(text: String) {
        let data = Data(text.utf8)
        #expect(failure { _ = try CLIDocuments.world(data, asReadOf: "atlas") }?.kind == .internal)
        #expect(failure { _ = try CLIDocuments.instances(data) }?.message == "farcast's instances output is not a JSON object")
        #expect(failure { _ = try CLIDocuments.version(data) }?.kind == .internal)
        #expect(CLIDocuments.failure(data) == nil)
    }

    @Test("a byte that is not UTF-8 is refused, never read past")
    func badUTF8() {
        var bytes = Array(Doc().data)
        let inKey = bytes.firstIndex(of: UInt8(ascii: "a"))!  // inside the first key, a string
        bytes.insert(0xFF, at: inKey)
        #expect(failure { _ = try CLIDocuments.world(Data(bytes), asReadOf: "atlas") }?.kind == .internal)
    }

    @Test("the error envelope: its kind and message, an unknown kind as unknown")
    func envelope() {
        let unknown = Data(#"{"error":{"message":"the sun flared","code":1,"kind":"solar_flare"}}"#.utf8)
        #expect(CLIDocuments.failure(unknown) == ReadFailure(kind: .unknown, message: "the sun flared"))
        #expect(failure { _ = try CLIDocuments.world(unknown, asReadOf: "atlas") }?.kind == .unknown)
        let none = Data(#"{"error":{"message":"no kind","code":1}}"#.utf8)
        #expect(CLIDocuments.failure(none)?.kind == .unknown)
        #expect(CLIDocuments.failure(Data(#"{"error":"a string"}"#.utf8)) == nil)
    }

    @Test("an envelope in a document gives the envelope's kind")
    func envelopeInDocument() {
        let data = Data(#"{"schema":1,"error":{"message":"took too long","code":1,"kind":"timeout"}}"#.utf8)
        #expect(failure { _ = try CLIDocuments.world(data, asReadOf: "atlas") } == ReadFailure(kind: .timeout, message: "took too long"))
        #expect(failure { _ = try CLIDocuments.version(data) }?.kind == .timeout)
    }

    @Test("a document about another instance is refused, as is a name install never creates")
    func otherInstance() {
        var doc = Doc()
        doc.name = "lab"
        #expect(doc.refusal == ReadFailure(kind: .internal, message: "asked for atlas; farcast answered about lab"))
        let data = Doc().data
        #expect(failure { _ = try CLIDocuments.world(data, asReadOf: "Atlas") }?.kind == .internal)
    }

    @Test("a word the map's structure rests on, unknown, fails the read")
    func strictWords() {
        var kind = Doc()
        kind.lines = #"[{"kind":"teleport","from":{"app":"shop/api"},"to":{"host":"api.example"},"evidence":"observed"}]"#
        var evidence = Doc()
        evidence.lines = #"[{"kind":"egress","from":{"app":"shop/api"},"to":{"host":"api.example"},"evidence":"rumoured"}]"#
        var role = Doc()
        role.components = #"[{"role":"scheduler","name":"x","state":"running"}]"#
        var deviceRole = Doc()
        deviceRole.devices = #"[{"id":"atlas/tablet","role":"tablet"}]"#
        var duplicateRole = Doc()
        duplicateRole.components = #"[{"role":"boundary","name":"a","state":"running"},{"role":"boundary","name":"b","state":"running"}]"#
        var twoKeys = Doc()
        twoKeys.lines = #"[{"kind":"watch","from":{"component":"monitor","app":"shop/api"},"to":{"component":"boundary"},"evidence":"observed"}]"#
        var noKey = Doc()
        noKey.lines = #"[{"kind":"watch","from":{},"to":{"component":"boundary"},"evidence":"observed"}]"#
        var strangeDevice = Doc()
        strangeDevice.lines = #"[{"kind":"keeper","from":{"device":"lab/phone"},"to":{"component":"storage"},"evidence":"observed"}]"#
        var subject = Doc()
        subject.alerts = #"[{"id":"x","kind":"cost","severity":"warning","subject":{},"title":"about nothing"}]"#
        var operatorID = Doc()
        operatorID.devices = #"[{"id":"mac","role":"operator"}]"#
        for doc in [kind, evidence, role, deviceRole, duplicateRole, twoKeys, noKey, strangeDevice, subject, operatorID] {
            #expect(doc.refusal?.kind == .internal, "\(doc.json)")
        }
    }

    @Test("a word in a tolerant enum, unknown, reads as unknown, and the world validates")
    func tolerantWords() throws {
        var doc = Doc()
        doc.status = "migrating"
        doc.level = "warn99"
        doc.components = #"[{"role":"boundary","name":"fatline","state":"hibernating","ready":1,"desired":1}]"#
        doc.devices = #"[{"id":"operator","role":"operator"},{"id":"atlas/phone","role":"keeper","health":"quarantined"},{"id":"atlas/nas","role":"keeper"}]"#
        doc.alerts = #"[{"id":"solar:instance","kind":"solar_flare","severity":"catastrophic","subject":{"instance":true},"title":"the sun"}]"#
        let world = try doc.world()
        let instance = try #require(world.instances.first)
        #expect(instance.status == .unknown)
        #expect(instance.spending.level == .unknown)
        #expect(instance.groups[0].apps.first { $0.system == .boundary }?.state == .unknown)
        #expect(world.devices.first { $0.id == "atlas/phone" }?.health == .unknown)
        #expect(world.devices.first { $0.id == "atlas/nas" }?.health == .unknown)
        #expect(world.devices.first { $0.id == "atlas/nas" }?.name == "nas")
        #expect(world.alerts.first?.kind == .unknown)
        #expect(world.alerts.first?.severity == .warning)
        #expect(world.alerts.first?.id == "atlas/solar:instance")
    }

    @Test("a group or app or keeper the map cannot draw fails the read")
    func illegalNames() {
        var system = Doc()
        system.groups = #"[{"namespace":"farcast-system","metered":true,"provenance":null,"apps":[]}]"#
        var empty = Doc()
        empty.groups = #"[{"namespace":"","metered":true,"provenance":null,"apps":[]}]"#
        var slash = Doc()
        slash.groups = #"[{"namespace":"shop","metered":true,"provenance":null,"apps":[{"name":"a/b","state":"running"}]}]"#
        var keeper = Doc()
        keeper.devices = #"[{"id":"operator","role":"operator"},{"id":"phone","role":"keeper"}]"#
        for doc in [system, empty, slash, keeper] {
            #expect(doc.refusal?.kind == .internal, "\(doc.json)")
        }
    }

    @Test("a figure the map cannot draw becomes a problem, never a refusal", arguments: [
        ("expected", "-5", "expected spending is not one: -5 cents"),
        ("total", "100000000001", "total spending is not one: 100000000001 cents"),
        ("limit", "0", "the kernel's cost limit is not one: 0 cents"),
        ("recorded", "-1", "the recorded cost limit is not one: -1 cents"),
    ])
    func figures(field: String, value: String, message: String) throws {
        var doc = Doc()
        switch field {
        case "expected": doc.expected = value
        case "total": doc.total = value
        case "limit": doc.limit = value
        default: doc.recorded = value
        }
        let instance = try #require(try doc.world().instances.first)
        #expect(instance.problems == [SectionProblem(section: .figures, kind: .internal, message: message)])
        let spending = instance.spending
        switch field {
        case "expected": #expect(spending.expectedCents == nil)
        case "total": #expect(spending.totalCents == nil)
        case "limit": #expect(spending.limitCents == nil)
        default: #expect(spending.recordedLimitCents == nil)
        }
    }

    @Test("with both cost limits figures the map cannot draw, the read still lands: the figures are said, the section was read")
    func bothLimitsNotDrawn() throws {
        var doc = Doc()
        doc.limit = "0"
        doc.recorded = "-1"
        let instance = try #require(try doc.world().instances.first)
        #expect(instance.problems.map(\.section) == [.figures, .figures])
        #expect(instance.problem(in: .spend) == nil)
        #expect(instance.problems.map(\.sentence) == ["spending figure not drawn · out of range", "spending figure not drawn · out of range"])
    }

    @Test("an app's figure the map cannot draw becomes a problem, and the app says it has none")
    func appFigure() throws {
        var doc = Doc()
        doc.groups = #"[{"namespace":"shop","metered":true,"provenance":null,"apps":[{"name":"api","state":"running","ready":-1,"desired":2,"stopped_by":"cost_guard","month_cents":-3},{"name":"web","state":"stopped","stopped_by":"operator","month_cents":null}]}]"#
        let instance = try #require(try doc.world().instances.first)
        #expect(instance.problems == [SectionProblem(section: .figures, kind: .internal, message: "shop/api's spending this month is not one: -3 cents")])
        let api = try #require(instance.groups.last?.apps.first)
        #expect(api.monthCents == nil && api.costNote == "not a figure the map can draw")
        #expect(api.ready == nil && api.desired == 2 && api.role == "running")
        #expect(api.stopReason == "stopped by the cost guard")
        // The kernel's one reason is the only one said; any other word on
        // the wire leaves the app plainly "stopped".
        #expect(instance.groups.last?.apps.last?.stopReason == nil)
        #expect(instance.groups.last?.apps.last?.costNote == "not told apart from an app of the same name")
    }

    @Test("the floor: levers in the map's words, an unknown one as written, and a figure it cannot draw a problem")
    func floor() throws {
        var doc = Doc()
        doc.spend = #"{"read":true,"currency":"USD","period":"monthly","total_cents":2269,"expected_cents":1805,"confirmed_cents":464,"has_confirmation":true,"confirmed_through":"2026-11-08T00:00:00Z","limit_cents":5000,"recorded_limit_cents":5000,"level":"reached","checkpoint_stale":false,"at_floor":true,"floor":{"since":"2026-11-12T08:30:00Z","still_burning_month_cents":-1,"levers":["drop_carrier","sell_the_house","release_instance"]},"not_metered":null,"caveats":null}"#
        doc.alerts = #"[{"id":"at_floor:component:kernel","kind":"at_floor","severity":"critical","subject":{"component":"kernel"},"title":"t"},{"id":"x:instance","kind":"something_new","severity":"loud","subject":{"instance":true},"title":"t"}]"#
        let world = try doc.world()
        let instance = try #require(world.instances.first)
        let floor = try #require(instance.spending.floor)
        #expect(floor.levers == ["drop the load-balancer carrier", "sell_the_house", "release the instance"])
        #expect(floor.stillBurningMonthCents == nil)
        #expect(instance.problems == [SectionProblem(section: .figures, kind: .internal, message: "what still burns at the floor is not one: -1 cents")])
        #expect(instance.spending.atFloor == true)
        #expect(world.alerts.map(\.kind) == [.atFloor, .unknown])
        #expect(world.alerts.map(\.severity) == [.critical, .warning])
    }

    @Test("at_floor: null from a kernel that records no floor, false from one that does, absent from an older CLI")
    func atFloorStates() throws {
        func spend(_ atFloor: String) -> String {
            #"{"read":true,"currency":"USD","period":"monthly","total_cents":10,"expected_cents":10,"confirmed_cents":null,"has_confirmation":false,"confirmed_through":null,"limit_cents":5000,"recorded_limit_cents":5000,"level":"ok","checkpoint_stale":false,\#(atFloor)"not_metered":null,"caveats":null}"#
        }
        for (field, want) in [(#""at_floor":null,"floor":null,"#, Bool?.none), (#""at_floor":false,"floor":null,"#, false), ("", nil)] {
            var doc = Doc()
            doc.spend = spend(field)
            let spending = try #require(try doc.world().instances.first).spending
            #expect(spending.atFloor == want, "\(field)")
            #expect(spending.floor == nil)
        }
    }

    @Test("spending read with no recorded limit is a problem with the record, and the world validates")
    func noRecordedLimit() throws {
        var doc = Doc()
        doc.recorded = "null"
        doc.limit = "null"
        let instance = try #require(try doc.world().instances.first)
        #expect(instance.problems == [SectionProblem(section: .record, kind: .internal, message: "the record holds no cost limit")])
    }

    @Test("a section not read says so; one skipped says nothing; spending not read is no figure")
    func sections() throws {
        var doc = Doc()
        doc.spend = #"{"read":false}"#
        doc.groups = #"[{"namespace":"shop","metered":true,"provenance":null,"apps":[{"name":"api","state":"running","month_cents":null}]}]"#
        doc.sections = #"{"spend":{"read":false},"apps":{"read":true},"policy":{"read":true},"network":{"read":false,"error":{"kind":"tunnel_unreachable","message":"no tunnel"}},"seal":{"read":false,"skipped":"not_deployed"}}"#
        let instance = try #require(try doc.world().instances.first)
        #expect(instance.problems == [
            SectionProblem(section: .spend, kind: .unknown, message: "not read"),
            SectionProblem(section: .network, kind: .tunnelUnreachable, message: "no tunnel"),
        ])
        #expect(instance.spending == Spending())
        #expect(instance.groups.last?.apps.first?.costNote == "spending not read")
    }

    @Test("counts are floors that never overflow, and every label part is said")
    func egressLabels() throws {
        var doc = Doc()
        doc.lines = #"[{"kind":"egress","from":{"app":"shop/api"},"to":{"host":"api.example"},"evidence":"observed","ports":[{"evidence":"observed","count":9223372036854775807,"fails":1,"no_longer_declared":true},{"evidence":"observed","count":9223372036854775807},{"evidence":"denied","count":4}],"drift":true}]"#
        let line = try #require(try doc.world().connections.first)
        #expect(line.count == Int.max)
        #expect(line.label == "≥\(Int.max) ok · ≥1 failed · ≥4 refused · not declared · no longer declared")
        #expect(line.isStale == false)
    }

    @Test("a listing entry carries only what it has: one omitted field never fails the listing")
    func sparseListing() throws {
        let data = Data(#"{"schema":1,"generated_at":"2026-11-12T10:00:00Z","farcast":{"version":"v0","commit":"0e54eb1"},"instances":[{"name":"atlas"},{"name":"Bad_Name","status":"running","components":{"fatline":true,"kernel":false,"keyholder":false}},{"name":"x","error":{"kind":"record_unreadable","message":"m"}}]}"#.utf8)
        let listing = try CLIDocuments.instances(data)
        #expect(listing.instances[0] == InstanceListing(name: "atlas"))
        #expect(listing.instances[1].problem == SectionProblem(
            section: .record, kind: .internal,
            message: "this is not a name 'farcast install' creates, so FarCast does not read it"
        ))
        #expect(listing.instances[1].components == [.boundary: true, .kernel: false, .storage: false])
        #expect(listing.instances[2].problem?.kind == .recordUnreadable)
        let nullList = Data(#"{"schema":1,"generated_at":"2026-11-12T10:00:00Z","farcast":{"version":"v0","commit":"0e54eb1"},"instances":null}"#.utf8)
        #expect(try CLIDocuments.instances(nullList).instances.isEmpty)
        let noList = Data(#"{"schema":1,"generated_at":"2026-11-12T10:00:00Z","farcast":{"version":"v0","commit":"0e54eb1"}}"#.utf8)
        #expect(failure { _ = try CLIDocuments.instances(noList) }?.message.hasPrefix("farcast's instances output could not be read: instances") == true)
    }

    @Test("the group label: the repository without its scheme, the short ref, seven digits, never an at sign")
    func groupLabel() throws {
        var doc = Doc()
        doc.groups = #"[{"namespace":"shop","metered":false,"provenance":{"repository":"ssh://git.example/shop.git/","ref":"refs/tags/v1","commit":"abcdef0123","manifest_digest":"x","storage_wired":false},"apps":[]}]"#
        doc.lines = "[]"
        #expect(try doc.world().instances.first?.groups.last?.source == "git.example/shop · v1 at abcdef0 · not metered")
    }

    @Test("the names install creates are the only ones read", arguments: [
        ("atlas", true), ("a", true), ("a-1", true), (String(repeating: "a", count: 32), true),
        ("", false), ("-a", false), ("a-", false), ("A", false), ("a_b", false), ("a/b", false), ("..", false),
        (String(repeating: "a", count: 33), false), ("atlas\n", false), ("1a", false), ("atlás", false),
    ])
    func instanceNames(name: String, readable: Bool) {
        #expect(InstanceName.isReadable(name) == readable)
    }
}
