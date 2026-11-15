import Foundation
import Testing
@testable import FarSightCore

/// The environment farcast runs with: built from an allowlist, never the
/// app's own (ADR 0021 decision 9 and Verification 5).
@Suite("The child's environment")
struct ChildEnvironmentTests {
    @Test("only the allowlist reaches farcast; no CLOUDSDK_ variable, the app's CLOUDSDK_CONFIG among them")
    func buildsOnlyTheAllowlist() throws {
        let parent = [
            "PATH": "/Users/op/bin:/usr/bin:/bin",
            "HOME": "/Users/op",
            "TMPDIR": "/tmp/x",
            "LANG": "en_US.UTF-8",
            "LC_ALL": "en_US.UTF-8",
            "FARCAST_CONFIG_HOME": "/Users/op/other-farcast",
            "KUBECONFIG": "/Users/op/.kube/config",
            "HTTP_PROXY": "http://127.0.0.1:9",
            "https_proxy": "http://127.0.0.1:9",
            "ALL_PROXY": "socks5://127.0.0.1:9",
            "NO_PROXY": "*",
            "CLOUDSDK_CONFIG": "/elsewhere",
            "CLOUDSDK_AUTH_ACCESS_TOKEN": "planted",
            "CLOUDSDK_CORE_ACCOUNT": "someone-at-work",
            "CLOUDSDK_ACTIVE_CONFIG_NAME": "work",
            "CLOUDSDK_PYTHON": "/usr/bin/python3",
            "GOOGLE_APPLICATION_CREDENTIALS": "/Users/op/key.json",
            "GODEBUG": "http2debug=2",
            "DYLD_INSERT_LIBRARIES": "/tmp/x.dylib",
            "GOFLAGS": "-mod=mod",
            "PYTHONPATH": "/tmp",
            "SSH_AUTH_SOCK": "/tmp/agent",
            "LC_bad": "x",
        ]
        let child = try ChildEnvironment.build(parent: parent)
        #expect(Set(child.keys) == ["HOME", "TMPDIR", "LANG", "LC_ALL", "PATH"])
        #expect(child["HOME"] == "/Users/op")
        #expect(child["TMPDIR"] == "/tmp/x")
        #expect(child["LANG"] == "en_US.UTF-8" && child["LC_ALL"] == "en_US.UTF-8")
        #expect(child["PATH"] == "/usr/bin:/bin:/usr/sbin:/sbin")
        #expect(child["CLOUDSDK_CONFIG"] == nil)
        #expect(!child.keys.contains { $0.hasPrefix("CLOUDSDK") || $0.hasPrefix("GO") })
    }

    @Test("PATH is the system's own directories and nothing else, whatever Settings hold; never farcast's")
    func pathIsTheSystemDirectories() async throws {
        #expect(ChildEnvironment.systemDirectories == ["/usr/bin", "/bin", "/usr/sbin", "/sbin"])
        #expect(ChildEnvironment.path == "/usr/bin:/bin:/usr/sbin:/sbin")
        // Settings are no input to it: what a reader runs farcast with
        // carries the same PATH whichever paths were confirmed.
        for settings in [Fixture.settings, CLISettings(farcast: "/opt/homebrew/bin/farcast", configDirectory: "/Users/op/c")] {
            let executor = try Fixture.executor(settings: settings)
            _ = try await Fixture.reader(executor, settings: settings).listing()
            #expect(executor.invocations.count == 2)
            for invocation in executor.invocations {
                #expect(invocation.environment["PATH"] == "/usr/bin:/bin:/usr/sbin:/sbin")
                #expect(!(invocation.environment["PATH"] ?? "").contains("/opt/homebrew/bin"))
                #expect(!(invocation.environment["PATH"] ?? "").contains("/Users/op/src/farcast/bin"))
            }
        }
    }

    @Test("a TMPDIR that is not absolute is dropped")
    func relativeTmpdirIsDropped() throws {
        let child = try ChildEnvironment.build(parent: ["HOME": "/Users/op", "TMPDIR": "tmp"])
        #expect(child["TMPDIR"] == nil)
        #expect(Set(child.keys) == ["HOME", "PATH"])
    }

    @Test("without an absolute home directory, nothing is built", arguments: [[:], ["HOME": ""], ["HOME": "Users/op"]])
    func missingHomeThrows(parent: [String: String]) {
        let refusal = failure { _ = try ChildEnvironment.build(parent: parent) }
        #expect(refusal == ReadFailure(kind: .internal, message: "FarCast has no home directory to give farcast"))
    }

    @Test("a locale variable is LC_ and capitals")
    func locale() {
        for key in ["LC_ALL", "LC_CTYPE", "LC_MESSAGES", "LC__"] { #expect(ChildEnvironment.isLocale(key), "\(key)") }
        for key in ["LC_", "LC_bad", "LC_ALL1", "XLC_ALL", "lc_all", "LANG"] { #expect(!ChildEnvironment.isLocale(key), "\(key)") }
    }
}
