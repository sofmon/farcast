/// The environment `farcast` runs with: built from an allowlist, never
/// inherited (ADR 0021 decision 9, "An explicit environment", and
/// Verification 5).
///
/// | Key | Value |
/// |---|---|
/// | `HOME` | the app's; required, absolute |
/// | `TMPDIR` | the app's, when absolute |
/// | `LANG`, `LC_*` | the app's, when present |
/// | `PATH` | the recorded tools' directories, then the system's own |
/// | `CLOUDSDK_CONFIG` | the gcloud directory confirmed in Settings |
///
/// Everything else the app was started with is dropped: its `PATH`,
/// `FARCAST_CONFIG_HOME`, `KUBECONFIG`, every proxy variable, every
/// `CLOUDSDK_*` (its `CLOUDSDK_CONFIG` among them),
/// `GOOGLE_APPLICATION_CREDENTIALS`, `DYLD_*`, `GO*`, `PYTHON*`,
/// `SSH_AUTH_SOCK` and the rest.
///
/// `CLOUDSDK_CONFIG` is set, not inherited: it is the operator-confirmed
/// Settings value, as `--config` is, and it is the directory the CLI's
/// identity guard reads and hands to kubectl. It is always set, even when it
/// is the default, so a read never depends on the `HOME` the app was
/// launched with.
///
/// farcast's own directory is not on `PATH`: farcast is run by its absolute
/// path, and nothing looks it up by name.
public enum ChildEnvironment {
    /// The sealed system volume's own directories, last on PATH. The CLI runs
    /// `kubectl` by bare name, the kubeconfig names the auth plugin by bare
    /// name, the plugin runs `gcloud` by bare name, and `gcloud` is a shell
    /// script that needs the system's utilities and finds its Python on
    /// `PATH`. These directories are not writable, so they are no place to
    /// plant a tool.
    public static let systemDirectories = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]

    /// The whole environment farcast runs with. Built, never inherited.
    public static func build(parent: [String: String], settings: CLISettings) throws(ReadFailure) -> [String: String] {
        guard let home = parent["HOME"], home.hasPrefix("/") else {
            throw ReadFailure(kind: .internal, message: "FarCast has no home directory to give farcast")
        }
        var environment = [
            "HOME": home,
            "PATH": path(for: settings),
            "CLOUDSDK_CONFIG": settings.gcloudDirectory,
        ]
        if let tmpdir = parent["TMPDIR"], tmpdir.hasPrefix("/") {
            environment["TMPDIR"] = tmpdir
        }
        for (key, value) in parent where key == "LANG" || isLocale(key) {
            environment[key] = value
        }
        return environment
    }

    /// The recorded tools' directories, in the order kubectl, gke-gcloud-auth-plugin, gcloud,
    /// without repeats, then systemDirectories not already present.
    public static func path(for settings: CLISettings) -> String {
        var directories: [String] = []
        for tool in [settings.kubectl, settings.authPlugin, settings.gcloud] {
            if let directory = directory(of: tool), !directories.contains(directory) {
                directories.append(directory)
            }
        }
        for directory in systemDirectories where !directories.contains(directory) {
            directories.append(directory)
        }
        return directories.joined(separator: ":")
    }

    /// The directory an absolute path is in: `/usr/local/bin` for
    /// `/usr/local/bin/kubectl`, `/` for `/kubectl`; nil for a path that is
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
