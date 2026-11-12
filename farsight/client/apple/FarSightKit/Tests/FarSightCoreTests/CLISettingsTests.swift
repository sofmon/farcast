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
        "~/bin/kubectl", "bin/kubectl", "/usr//local/bin/kubectl", "/usr/local/bin/kubectl/", "/usr/./local/bin/kubectl",
        "/usr/../local/bin/kubectl", "./kubectl",
    ])
    func notCanonical(path: String) {
        var settings = Fixture.settings
        settings.kubectl = path
        #expect(Self.problem(.kubectl, settings) == "must be an absolute path, with no \"~\", \".\", \"..\", empty part or trailing \"/\"")
    }

    @Test("a character PATH cannot carry is refused; a space is not", arguments: [
        "/usr/local/b:in/kubectl", "/usr/local/b\u{202E}in/kubectl", "/usr/local/b\nin/kubectl", "/usr/local/b\u{9B}in/kubectl",
    ])
    func unprintable(path: String) {
        var settings = Fixture.settings
        settings.kubectl = path
        #expect(Self.problem(.kubectl, settings) == "holds a character PATH cannot carry")
    }

    @Test("a space is a character PATH carries")
    func space() {
        var settings = Fixture.settings
        settings.kubectl = "/Users/op/my tools/kubectl"
        #expect(Self.problem(.kubectl, settings) == nil)
    }

    @Test("a path inside FarCast.app is refused, and so is one that resolves into it")
    func insideTheBundle() {
        var settings = Fixture.settings
        settings.kubectl = "/Applications/FarCast.app/Contents/MacOS/kubectl"
        #expect(Self.problem(.kubectl, settings) == "is inside FarCast.app")
        settings.configDirectory = Self.bundle
        #expect(Self.problem(.configDirectory, settings) == "is inside FarCast.app")

        var probe = Fixture.probe()
        probe.links[Fixture.settings.kubectl] = "/Applications/FarCast.app/Contents/Resources/kubectl"
        probe.entries["/Applications/FarCast.app/Contents/Resources/kubectl"] = Fixture.executable
        #expect(Self.problem(.kubectl, Fixture.settings, probe) == "is inside FarCast.app")

        settings = Fixture.settings
        settings.farcast = "/Applications/FarCast.application/farcast"
        #expect(Self.problem(.farcast, settings) == nil)
    }

    @Test("a tool must have the name it is run by; farcast may have any")
    func basename() {
        var settings = Fixture.settings
        settings.kubectl = "/usr/local/bin/kubectl-1.33"
        settings.authPlugin = "/opt/homebrew/bin/auth-plugin"
        settings.gcloud = "/opt/homebrew/bin/gcloud.sh"
        settings.farcast = "/Users/op/src/farcast/bin/farcast-dev"
        let problems = Self.problems(settings)
        #expect(problems.map(\.field) == [.kubectl, .authPlugin, .gcloud])
        #expect(Self.problem(.kubectl, settings) == "farcast runs it by the name \"kubectl\", so the file must be called that")
        #expect(Self.problem(.authPlugin, settings)?.contains("\"gke-gcloud-auth-plugin\"") == true)
        #expect(Self.problem(.gcloud, settings)?.contains("\"gcloud\"") == true)
    }

    @Test("a tool's name is said with what runs it by that name")
    func basenameNamesTheRunner() {
        var settings = Fixture.settings
        settings.kubectl = "/usr/local/bin/kubectl-1.33"
        settings.authPlugin = "/opt/homebrew/bin/auth-plugin"
        settings.gcloud = "/opt/homebrew/bin/gcloud.sh"
        // farcast runs only kubectl; kubectl runs the plugin the instance's
        // kubeconfig names; the plugin runs gcloud.
        #expect(Self.problem(.kubectl, settings) == "farcast runs it by the name \"kubectl\", so the file must be called that")
        #expect(Self.problem(.authPlugin, settings) == "kubectl runs it by the name \"gke-gcloud-auth-plugin\", so the file must be called that")
        #expect(Self.problem(.gcloud, settings) == "gke-gcloud-auth-plugin runs it by the name \"gcloud\", so the file must be called that")
    }

    @Test("a link into a directory anyone can write is refused; one into a closed directory is not")
    func linkIntoAnOpenDirectory() {
        var probe = Fixture.probe()
        probe.links[Fixture.settings.kubectl] = "/shared/kubectl"
        probe.entries["/shared/kubectl"] = Fixture.executable
        probe.entries["/shared"] = .directory(worldWritable: true)
        #expect(Self.problem(.kubectl, Fixture.settings, probe) == "it links to a file in a directory anyone on this Mac can write")

        probe.entries["/shared"] = Fixture.directory
        #expect(Self.problem(.kubectl, Fixture.settings, probe) == nil)

        // A link into an open directory is said as the directory it is typed in, when that is open too.
        probe.entries["/shared"] = .directory(worldWritable: true)
        probe.entries["/usr/local/bin"] = .directory(worldWritable: true)
        #expect(Self.problem(.kubectl, Fixture.settings, probe) == "its directory is writable by anyone on this Mac")
    }

    @Test("a path into the bundle is refused whichever form either is given in")
    func bundleInEitherForm() {
        // macOS gives a translocated or /private/tmp bundle under /private;
        // URL's symlink resolution drops that prefix.
        let given = "/private/var/folders/xy/T/AppTranslocation/0A/d/FarCast.app"
        let resolved = "/var/folders/xy/T/AppTranslocation/0A/d/FarCast.app"
        var settings = Fixture.settings
        settings.kubectl = "\(resolved)/Contents/MacOS/kubectl"
        var probe = Fixture.probe(for: settings)
        probe.links[given] = resolved
        probe.entries[resolved] = Fixture.directory
        let problems = settings.problems(probe: probe, bundlePath: given)
        #expect(problems == [SettingsProblem(field: .kubectl, message: "is inside FarCast.app")])
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

    @Test("a tool is an executable file only its owner can replace", arguments: [
        (FileEntry.missing, "nothing is at this path"),
        (.directory(worldWritable: false), "is not a file"),
        (.other, "is not a file"),
        (.file(executable: false, worldWritable: false), "is not executable by you"),
        (.file(executable: true, worldWritable: true), "anyone on this Mac can replace it"),
    ])
    func toolEntry(entry: FileEntry, message: String) {
        var probe = Fixture.probe()
        probe.entries[Fixture.settings.gcloud] = entry
        #expect(Self.problem(.gcloud, Fixture.settings, probe) == message)
    }

    @Test("a tool in a directory anyone can write is refused; group-writable is not")
    func toolDirectory() {
        var probe = Fixture.probe()
        probe.entries["/opt/homebrew/bin"] = .directory(worldWritable: true)
        #expect(Self.problem(.gcloud, Fixture.settings, probe) == "its directory is writable by anyone on this Mac")
        #expect(Self.problem(.authPlugin, Fixture.settings, probe) == "its directory is writable by anyone on this Mac")
        #expect(Self.problem(.kubectl, Fixture.settings, probe) == nil)
    }

    @Test("a configuration directory is a directory only its owner can write", arguments: [
        (FileEntry.missing, "is not a directory"),
        (.file(executable: false, worldWritable: false), "is not a directory"),
        (.other, "is not a directory"),
        (.directory(worldWritable: true), "is writable by anyone on this Mac"),
    ])
    func directories(entry: FileEntry, message: String) {
        var probe = Fixture.probe()
        probe.entries[Fixture.settings.configDirectory] = entry
        probe.entries[Fixture.settings.gcloudDirectory] = entry
        #expect(Self.problem(.configDirectory, Fixture.settings, probe) == message)
        #expect(Self.problem(.gcloudDirectory, Fixture.settings, probe) == message)
    }

    @Test("a tool shadowed on farcast's PATH is refused, on that tool's row")
    func shadowing() {
        var probe = Fixture.probe()
        probe.entries["/usr/local/bin/gcloud"] = Fixture.executable  // in kubectl's directory, which comes first
        let problems = Self.problems(Fixture.settings, probe)
        #expect(problems == [SettingsProblem(
            field: .gcloud,
            message: "/usr/local/bin/gcloud comes first on the PATH farcast gets, so it would run instead of this one"
        )])

        // A system directory comes last, so one there shadows nothing.
        var system = Fixture.probe()
        system.entries["/usr/bin/kubectl"] = Fixture.executable
        #expect(Self.problems(Fixture.settings, system).isEmpty)

        // One that is not executable shadows nothing either.
        var inert = Fixture.probe()
        inert.entries["/usr/local/bin/gcloud"] = .file(executable: false, worldWritable: false)
        #expect(Self.problems(Fixture.settings, inert).isEmpty)

        // And shadowing is not checked while a tool has a problem of its own.
        probe.entries[Fixture.settings.kubectl] = .missing
        #expect(Self.problems(Fixture.settings, probe).map(\.field) == [.kubectl])
    }

    @Test("a blank form suggests the two directories and no tool")
    func suggested() {
        let suggested = CLISettings.suggested(home: "/Users/op")
        #expect(suggested == CLISettings(
            configDirectory: "/Users/op/Library/Application Support/farcast",
            gcloudDirectory: "/Users/op/.config/gcloud"
        ))
        #expect(CLISettings.suggested(home: "/Users/op/") == suggested)
        #expect(suggested.farcast.isEmpty && suggested.kubectl.isEmpty && suggested.authPlugin.isEmpty && suggested.gcloud.isEmpty)
    }

    @Test("each row's title")
    func titles() {
        #expect(CLISettings.Field.allCases.map(\.title) == [
            "farcast", "kubectl", "gke-gcloud-auth-plugin", "gcloud",
            "farcast configuration directory", "gcloud configuration directory",
        ])
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
}
