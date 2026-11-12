import Foundation
import Testing
@testable import FarSightCore

/// The environment farcast runs with: built from an allowlist, never the
/// app's own (ADR 0021 decision 9 and Verification 5).
@Suite("The child's environment")
struct ChildEnvironmentTests {
    @Test("only the allowlist reaches farcast; CLOUDSDK_CONFIG is the confirmed directory, never the app's")
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
            "DYLD_INSERT_LIBRARIES": "/tmp/x.dylib",
            "GOFLAGS": "-mod=mod",
            "PYTHONPATH": "/tmp",
            "SSH_AUTH_SOCK": "/tmp/agent",
            "LC_bad": "x",
        ]
        let settings = Fixture.settings
        let child = try ChildEnvironment.build(parent: parent, settings: settings)
        #expect(Set(child.keys) == ["HOME", "TMPDIR", "LANG", "LC_ALL", "PATH", "CLOUDSDK_CONFIG"])
        #expect(child["HOME"] == "/Users/op")
        #expect(child["TMPDIR"] == "/tmp/x")
        #expect(child["LANG"] == "en_US.UTF-8" && child["LC_ALL"] == "en_US.UTF-8")
        #expect(child["PATH"] == ChildEnvironment.path(for: settings))
        #expect(child["CLOUDSDK_CONFIG"] == settings.gcloudDirectory)
        #expect(child["CLOUDSDK_CONFIG"] != parent["CLOUDSDK_CONFIG"])
    }

    @Test("PATH is the tools' directories in order, once each, then the system's; never farcast's")
    func pathOrder() {
        #expect(ChildEnvironment.systemDirectories == ["/usr/bin", "/bin", "/usr/sbin", "/sbin"])
        let settings = Fixture.settings
        #expect(ChildEnvironment.path(for: settings) == "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin")
        #expect(!ChildEnvironment.path(for: settings).contains("/Users/op/src/farcast/bin"))

        var system = settings
        system.kubectl = "/usr/bin/kubectl"
        #expect(ChildEnvironment.path(for: system) == "/usr/bin:/opt/homebrew/bin:/bin:/usr/sbin:/sbin")

        var spread = settings
        spread.authPlugin = "/opt/google/bin/gke-gcloud-auth-plugin"
        spread.gcloud = "/opt/google/sdk/bin/gcloud"
        #expect(ChildEnvironment.path(for: spread) == "/usr/local/bin:/opt/google/bin:/opt/google/sdk/bin:/usr/bin:/bin:/usr/sbin:/sbin")

        #expect(ChildEnvironment.path(for: CLISettings()) == "/usr/bin:/bin:/usr/sbin:/sbin")
    }

    @Test("a TMPDIR that is not absolute is dropped")
    func relativeTmpdirIsDropped() throws {
        let child = try ChildEnvironment.build(parent: ["HOME": "/Users/op", "TMPDIR": "tmp"], settings: Fixture.settings)
        #expect(child["TMPDIR"] == nil)
        #expect(Set(child.keys) == ["HOME", "PATH", "CLOUDSDK_CONFIG"])
    }

    @Test("without an absolute home directory, nothing is built", arguments: [[:], ["HOME": ""], ["HOME": "Users/op"]])
    func missingHomeThrows(parent: [String: String]) {
        let refusal = failure { _ = try ChildEnvironment.build(parent: parent, settings: Fixture.settings) }
        #expect(refusal == ReadFailure(kind: .internal, message: "FarCast has no home directory to give farcast"))
    }

    @Test("a locale variable is LC_ and capitals")
    func locale() {
        for key in ["LC_ALL", "LC_CTYPE", "LC_MESSAGES", "LC__"] { #expect(ChildEnvironment.isLocale(key), "\(key)") }
        for key in ["LC_", "LC_bad", "LC_ALL1", "XLC_ALL", "lc_all", "LANG"] { #expect(!ChildEnvironment.isLocale(key), "\(key)") }
    }
}
