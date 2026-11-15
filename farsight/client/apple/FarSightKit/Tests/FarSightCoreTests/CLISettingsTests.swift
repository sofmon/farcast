import Foundation
import Testing
@testable import FarSightCore

/// Settings' checks: what the app will run, refused before it runs.
@Suite("Settings")
struct CLISettingsTests {
    static let bundle = Fixture.bundlePath

    /// The problems with `settings` on a Mac set up as `probe` says.
    static func problems(_ settings: CLISettings, _ probe: FakeProbe? = nil) -> [SettingsProblem] {
        settings.problems(probe: probe ?? Fixture.probe(for: settings), bundlePath: bundle)
    }

    /// The one problem with `field`, or nil.
    static func problem(_ field: CLISettings.Field, _ settings: CLISettings, _ probe: FakeProbe? = nil) -> String? {
        let found = problems(settings, probe).filter { $0.field == field }
        #expect(found.count <= 1)
        return found.first?.message
    }

    @Test("a Mac set up as Settings expects has no problem")
    func valid() {
        #expect(Self.problems(Fixture.settings).isEmpty)
    }

    @Test("an empty field is not set")
    func empty() {
        let problems = Self.problems(CLISettings(), FakeProbe())
        #expect(problems.map(\.field) == CLISettings.Field.allCases)
        #expect(problems.allSatisfy { $0.message == "not set" })
    }

    @Test("a path that is not canonical and absolute is refused", arguments: [
        "~/bin/farcast", "bin/farcast", "/usr//local/bin/farcast", "/usr/local/bin/farcast/", "/usr/./local/bin/farcast",
        "/usr/../local/bin/farcast", "./farcast",
    ])
    func notCanonical(path: String) {
        var settings = Fixture.settings
        settings.farcast = path
        settings.configDirectory = path
        let message = "must be an absolute path, with no \"~\", \".\", \"..\", empty part or trailing \"/\""
        #expect(Self.problem(.farcast, settings) == message)
        #expect(Self.problem(.configDirectory, settings) == message)
    }

    @Test("a ':' or a character that does not print is refused, in either path", arguments: [
        "/usr/local/b:in/farcast", "/usr/local/b\u{202E}in/farcast", "/usr/local/b\nin/farcast", "/usr/local/b\u{9B}in/farcast",
    ])
    func unprintable(path: String) {
        var settings = Fixture.settings
        settings.farcast = path
        settings.configDirectory = path
        #expect(Self.problem(.farcast, settings) == "holds a \":\" or a character that does not print")
        #expect(Self.problem(.configDirectory, settings) == "holds a \":\" or a character that does not print")
    }

    @Test("a space is no such character")
    func space() {
        var settings = Fixture.settings
        settings.farcast = "/Users/op/my tools/farcast"
        settings.configDirectory = "/Users/op/Library/Application Support/farcast"
        #expect(Self.problems(settings).isEmpty)
    }

    @Test("a path inside FarCast.app is refused, and so is one that resolves into it")
    func insideTheBundle() {
        var settings = Fixture.settings
        settings.farcast = "/Applications/FarCast.app/Contents/MacOS/farcast"
        #expect(Self.problem(.farcast, settings) == "is inside FarCast.app")
        settings.configDirectory = Self.bundle
        #expect(Self.problem(.configDirectory, settings) == "is inside FarCast.app")

        var probe = Fixture.probe()
        probe.links[Fixture.settings.farcast] = "/Applications/FarCast.app/Contents/Resources/farcast"
        probe.entries["/Applications/FarCast.app/Contents/Resources/farcast"] = Fixture.executable
        #expect(Self.problem(.farcast, Fixture.settings, probe) == "is inside FarCast.app")

        settings = Fixture.settings
        settings.farcast = "/Applications/FarCast.application/farcast"
        #expect(Self.problem(.farcast, settings) == nil)
    }

    @Test("farcast may have any name: it is run by its path")
    func anyName() {
        var settings = Fixture.settings
        settings.farcast = "/Users/op/src/farcast/bin/farcast-dev"
        #expect(Self.problems(settings).isEmpty)
    }

    @Test("a link into a directory anyone can write is refused; one into a closed directory is not")
    func linkIntoAnOpenDirectory() {
        var probe = Fixture.probe()
        probe.links[Fixture.settings.farcast] = "/shared/farcast"
        probe.entries["/shared/farcast"] = Fixture.executable
        probe.entries["/shared"] = .directory(worldWritable: true)
        #expect(Self.problem(.farcast, Fixture.settings, probe) == "it links to a file in a directory anyone on this Mac can write")

        probe.entries["/shared"] = Fixture.directory
        #expect(Self.problem(.farcast, Fixture.settings, probe) == nil)

        // A link into an open directory is said as the directory it is typed in, when that is open too.
        probe.entries["/shared"] = .directory(worldWritable: true)
        probe.entries["/Users/op/src/farcast/bin"] = .directory(worldWritable: true)
        #expect(Self.problem(.farcast, Fixture.settings, probe) == "its directory is writable by anyone on this Mac")
    }

    @Test("a path into the bundle is refused whichever form either is given in")
    func bundleInEitherForm() {
        // macOS gives a translocated or /private/tmp bundle under /private;
        // URL's symlink resolution drops that prefix.
        let given = "/private/var/folders/xy/T/AppTranslocation/0A/d/FarCast.app"
        let resolved = "/var/folders/xy/T/AppTranslocation/0A/d/FarCast.app"
        var settings = Fixture.settings
        settings.farcast = "\(resolved)/Contents/MacOS/farcast"
        var probe = Fixture.probe(for: settings)
        probe.links[given] = resolved
        probe.entries[resolved] = Fixture.directory
        let problems = settings.problems(probe: probe, bundlePath: given)
        #expect(problems == [SettingsProblem(field: .farcast, message: "is inside FarCast.app")])
    }

    @Test("the bundle itself is inside it, though its path ends with a slash")
    func theBundleItself() {
        var settings = Fixture.settings
        settings.configDirectory = "/Applications/FarCast.app"
        var probe = Fixture.probe(for: settings)
        probe.entries["/Applications/FarCast.app"] = Fixture.directory
        // As a bundle URL's path gives it.
        let problems = settings.problems(probe: probe, bundlePath: "/Applications/FarCast.app/")
        #expect(problems == [SettingsProblem(field: .configDirectory, message: "is inside FarCast.app")])
        #expect(settings.problems(probe: probe, bundlePath: "/Applications/FarCast.application/").isEmpty)
    }

    @Test("farcast is an executable file only its owner can replace", arguments: [
        (FileEntry.missing, "nothing is at this path"),
        (.directory(worldWritable: false), "is not a file"),
        (.other, "is not a file"),
        (.file(executable: false, worldWritable: false), "is not executable by you"),
        (.file(executable: true, worldWritable: true), "anyone on this Mac can replace it"),
    ])
    func toolEntry(entry: FileEntry, message: String) {
        var probe = Fixture.probe()
        probe.entries[Fixture.settings.farcast] = entry
        #expect(Self.problem(.farcast, Fixture.settings, probe) == message)
    }

    @Test("farcast in a directory anyone can write is refused; group-writable is not")
    func toolDirectory() {
        var probe = Fixture.probe()
        probe.entries["/Users/op/src/farcast/bin"] = .directory(worldWritable: true)
        #expect(Self.problem(.farcast, Fixture.settings, probe) == "its directory is writable by anyone on this Mac")
        #expect(Self.problem(.configDirectory, Fixture.settings, probe) == nil)
    }

    @Test("the configuration directory is a directory only its owner can write", arguments: [
        (FileEntry.missing, "is not a directory"),
        (.file(executable: false, worldWritable: false), "is not a directory"),
        (.other, "is not a directory"),
        (.directory(worldWritable: true), "is writable by anyone on this Mac"),
    ])
    func directories(entry: FileEntry, message: String) {
        var probe = Fixture.probe()
        probe.entries[Fixture.settings.configDirectory] = entry
        #expect(Self.problem(.configDirectory, Fixture.settings, probe) == message)
        #expect(Self.problem(.farcast, Fixture.settings, probe) == nil)
    }

    @Test("a blank form suggests the configuration directory and no farcast")
    func suggested() {
        let suggested = CLISettings.suggested(home: "/Users/op")
        #expect(suggested == CLISettings(configDirectory: "/Users/op/Library/Application Support/farcast"))
        #expect(CLISettings.suggested(home: "/Users/op/") == suggested)
        #expect(suggested.farcast.isEmpty)
    }

    @Test("each row's title: two rows")
    func titles() {
        #expect(CLISettings.Field.allCases.map(\.title) == ["farcast", "farcast configuration directory"])
    }

    @Test("the store keeps confirmed settings, forgets them, and reads nothing from garbage")
    func store() throws {
        let suite = "farsight.tests.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let store = CLISettingsStore(defaults: defaults)
        #expect(CLISettingsStore.key == "farsight.connected.settings.v1")
        #expect(store.load() == nil)

        let confirmed = ConfirmedCLISettings(settings: Fixture.settings, confirmedAt: Date(timeIntervalSince1970: 1_794_477_600.5))
        store.save(confirmed)
        #expect(store.load() == confirmed)
        #expect(CLISettingsStore(defaults: defaults).load() == confirmed)

        store.clear()
        #expect(store.load() == nil)

        defaults.set(Data("not settings".utf8), forKey: CLISettingsStore.key)
        #expect(store.load() == nil)
        defaults.set("a string", forKey: CLISettingsStore.key)
        #expect(store.load() == nil)
    }

    @Test("settings saved with six paths load as the two, and the next save keeps only those")
    func storeSixKeys() throws {
        let suite = "farsight.tests.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        // As a build before ADR 0023 M2.4 saved them, under the same key.
        let saved = """
            {"confirmedAt":1794477600.5,"settings":{"authPlugin":"/opt/homebrew/bin/gke-gcloud-auth-plugin",\
            "configDirectory":"/Users/op/Library/Application Support/farcast","farcast":"/Users/op/src/farcast/bin/farcast",\
            "gcloud":"/opt/homebrew/bin/gcloud","gcloudDirectory":"/Users/op/.config/gcloud","kubectl":"/usr/local/bin/kubectl"}}
            """
        defaults.set(Data(saved.utf8), forKey: CLISettingsStore.key)
        let store = CLISettingsStore(defaults: defaults)
        let loaded = try #require(store.load())
        #expect(loaded == ConfirmedCLISettings(settings: Fixture.settings, confirmedAt: Date(timeIntervalSince1970: 1_794_477_600.5)))

        store.save(loaded)
        let written = try #require(defaults.data(forKey: CLISettingsStore.key))
        let object = try #require(try JSONSerialization.jsonObject(with: written) as? [String: Any])
        let settings = try #require(object["settings"] as? [String: Any])
        #expect(Set(settings.keys) == ["farcast", "configDirectory"])
        #expect(Set(object.keys) == ["settings", "confirmedAt"])
        #expect(store.load() == loaded)
    }
}
