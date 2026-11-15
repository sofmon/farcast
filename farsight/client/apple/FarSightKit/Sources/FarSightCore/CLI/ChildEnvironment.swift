/// The environment `farcast` runs with: built from an allowlist, never
/// inherited (ADR 0021 decision 9, "An explicit environment", and
/// Verification 5).
///
/// | Key | Value |
/// |---|---|
/// | `HOME` | the app's; required, absolute |
/// | `TMPDIR` | the app's, when absolute |
/// | `LANG`, `LC_*` | the app's, when present |
/// | `PATH` | the system's own directories |
///
/// Everything else the app was started with is dropped: its `PATH`,
/// `FARCAST_CONFIG_HOME`, `KUBECONFIG`, every proxy variable, every
/// `CLOUDSDK_*`, `GOOGLE_APPLICATION_CREDENTIALS`, `GODEBUG` and every
/// other `GO*`, `DYLD_*`, `PYTHON*`, `SSH_AUTH_SOCK` and the rest.
///
/// Since ADR 0023 M2.4, of the three commands the app runs, only `world`
/// reads a cluster, in-process, as each instance's own reader, and none runs
/// another tool: no kubectl, no auth plugin, no gcloud. So nothing of
/// gcloud's is set, and `PATH` names no directory Settings records.
///
/// farcast's own directory is not on `PATH`: farcast is run by its absolute
/// path, and nothing looks it up by name.
public enum ChildEnvironment {
    /// The sealed system volume's own directories, and all of `PATH`. They
    /// are not writable, so they are no place to plant a tool.
    public static let systemDirectories = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]

    /// `PATH`: `systemDirectories`, joined.
    public static let path = systemDirectories.joined(separator: ":")

    /// The whole environment farcast runs with. Built, never inherited.
    public static func build(parent: [String: String]) throws(ReadFailure) -> [String: String] {
        guard let home = parent["HOME"], home.hasPrefix("/") else {
            throw ReadFailure(kind: .internal, message: "FarCast has no home directory to give farcast")
        }
        var environment = [
            "HOME": home,
            "PATH": path,
        ]
        if let tmpdir = parent["TMPDIR"], tmpdir.hasPrefix("/") {
            environment["TMPDIR"] = tmpdir
        }
        for (key, value) in parent where key == "LANG" || isLocale(key) {
            environment[key] = value
        }
        return environment
    }

    /// The directory an absolute path is in: `/usr/local/bin` for
    /// `/usr/local/bin/farcast`, `/` for `/farcast`; nil for a path that is
    /// not absolute, or names no file.
    static func directory(of path: String) -> String? {
        guard path.hasPrefix("/"), !path.hasSuffix("/"), let slash = path.lastIndex(of: "/") else { return nil }
        return slash == path.startIndex ? "/" : String(path[..<slash])
    }

    /// `LC_` followed by one or more of [A-Z_].
    static func isLocale(_ key: String) -> Bool {
        let scalars = Array(key.unicodeScalars)
        guard scalars.count > 3, scalars[0] == "L", scalars[1] == "C", scalars[2] == "_" else { return false }
        return scalars.dropFirst(3).allSatisfy { ("A"..."Z").contains($0) || $0 == "_" }
    }
}
