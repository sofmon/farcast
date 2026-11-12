import Foundation
import Testing
@testable import FarSightUI
import FarSightCore

/// What the boundary's panel says first: which one FatLine replica counted
/// the lines, since when, and that every count is a floor (ADR 0022 decision
/// 9).
@Suite("Counted by")
struct CountedByTests {
    static let since = Date(timeIntervalSince1970: 1_794_384_000)  // 2026-11-11T08:00:00Z

    @Test("every field set")
    func everyField() {
        let text = Format.countedBy(NetworkReading(replica: "fatline-5d8c7b9f4-x2k7q", since: Self.since, fatlineReplicas: 2))
        #expect(text == "counted by fatline-5d8c7b9f4-x2k7q since \(Format.day(Self.since)) \(Format.time(Self.since))"
            + " · 1 of 2 FatLine replicas · every count is a floor")
    }

    @Test("no replica named, no time, no count")
    func nothingNamed() {
        #expect(Format.countedBy(NetworkReading()) == "counted by one FatLine replica · every count is a floor")
    }

    @Test("one replica is not plural")
    func oneReplica() {
        let text = Format.countedBy(NetworkReading(replica: "fatline-rehearsal-0", fatlineReplicas: 1))
        #expect(text == "counted by fatline-rehearsal-0 · 1 of 1 FatLine replica · every count is a floor")
    }

    @Test("a replica's name is drawn through Display")
    func escaped() {
        let text = Format.countedBy(NetworkReading(replica: "fatline\u{202E}-0\n"))
        #expect(text == "counted by fatline\\u202e-0\\n · every count is a floor")
        #expect(!text.unicodeScalars.contains("\u{202E}"))
    }

    @Test("the boundary's and the monitor's notes say it first; the boundary's names the caveats")
    func panels() throws {
        let world = try CLIDocuments.world(Data(Self.document.utf8), asReadOf: "atlas").world
        try world.validate(asReadOf: "atlas", source: .live)
        let model = WorldModel(world: world)
        let counted = "counted by fatline-0 · 1 of 2 FatLine replicas · every count is a floor"
        let boundary = try PanelFacts.note(model, "atlas/farcast-system/fatline")
        #expect(boundary.hasPrefix(counted + "\nWhat this read could not draw: shop/worker is named\\u202e; a second\n"))
        #expect(try PanelFacts.note(model, "atlas/farcast-system/shrike").hasPrefix(counted + "\n"))

        var unread = world
        unread.instances[0].network = nil
        unread.instances[0].caveats = []
        let quiet = WorldModel(world: unread)
        #expect(try PanelFacts.note(quiet, "atlas/farcast-system/fatline").hasPrefix("network not read\nApplication egress"))
    }

    static let document = #"""
    {"schema":1,"generated_at":"2026-11-12T10:00:00Z","farcast":{"version":"v0","commit":"0e54eb1"},
     "instance":{"name":"atlas","status":"running","cloud_logging":"system_only",
      "spend":{"read":true,"currency":"USD","period":"monthly","total_cents":10,"expected_cents":10,"has_confirmation":false,
               "limit_cents":5000,"recorded_limit_cents":5000,"level":"ok","checkpoint_stale":false},
      "network":{"read":true,"replica":"fatline-0","fatline_replicas":2},
      "components":[{"role":"boundary","name":"fatline","state":"running","ready":2,"desired":2},
                    {"role":"monitor","name":"shrike","state":"running","ready":2,"desired":2}],
      "caveats":["shop/worker is named‮","a second\nline"]},
     "groups":[],"hosts":[],"devices":[{"id":"operator","role":"operator"}],"alerts":[],
     "lines":[{"kind":"watch","from":{"component":"monitor"},"to":{"component":"boundary"},"evidence":"observed"}],
     "sections":{"spend":{"read":true},"apps":{"read":true},"policy":{"read":true},"network":{"read":true},"seal":{"read":true}}}
    """#
}

/// The reader's per-command timeouts against the feed's deadlines, so a hung
/// farcast comes back as the reader's own `.timeout`, which names the
/// command, and the feed's deadline stays the backstop. It is here because
/// this target sees both FarSightCore and FarSightUI.
@Suite("The reader's deadlines under the feed's")
struct ReaderDeadlineTests {
    /// The most the macOS app's executor takes to end a run once its timeout
    /// has passed: `ProcessExecutor.grace` (3 s from SIGTERM to SIGKILL) and
    /// `ProcessExecutor.drain` (up to 1 s for the output to end after the
    /// exit). ProcessExecutor names this test, so the two change together.
    static let stopping: Duration = .seconds(4)

    @Test("each command's timeout, and the time to stop it, ends before the feed gives up")
    func underTheFeeds() {
        let reader = CLIReader.Timeouts()
        let feed = WorldFeed.Timeouts()
        // A listing runs version, then instances. version may succeed just
        // before its timeout (it starts no process, so nothing holds its
        // output open once it exits); instances may then time out, and take
        // `stopping` to end.
        #expect(reader.version + reader.instances + Self.stopping < feed.listing)
        // A read is one world, which may time out and take `stopping` to end.
        #expect(reader.world + Self.stopping < feed.read)
    }
}
