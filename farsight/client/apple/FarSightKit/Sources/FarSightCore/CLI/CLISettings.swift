import Foundation

/// The paths the app runs `farcast` with, as the operator confirmed them once
/// in Settings (ADR 0021 decision 9, amended 2026-11-12). Nothing here is
/// guessed: a guessed tool path is a place to plant a tool (decision 6).
public struct CLISettings: Codable, Sendable, Equatable {
    public var farcast: String
    public var kubectl: String
    /// gke-gcloud-auth-plugin.
    public var authPlugin: String
    public var gcloud: String
    /// farcast's `--config`.
    public var configDirectory: String
    /// `CLOUDSDK_CONFIG`.
    public var gcloudDirectory: String

    public init(
        farcast: String = "",
        kubectl: String = "",
        authPlugin: String = "",
        gcloud: String = "",
        configDirectory: String = "",
        gcloudDirectory: String = ""
    ) {
        self.farcast = farcast
        self.kubectl = kubectl
        self.authPlugin = authPlugin
        self.gcloud = gcloud
        self.configDirectory = configDirectory
        self.gcloudDirectory = gcloudDirectory
    }

    public enum Field: String, Sendable, CaseIterable {
        case farcast, kubectl, authPlugin, gcloud, configDirectory, gcloudDirectory

        /// The Settings row's name, and the field's name in messages: "farcast", "kubectl",
        /// "gke-gcloud-auth-plugin", "gcloud", "farcast configuration directory",
        /// "gcloud configuration directory".
        public var title: String {
            switch self {
            case .farcast: "farcast"
            case .kubectl: "kubectl"
            case .authPlugin: "gke-gcloud-auth-plugin"
            case .gcloud: "gcloud"
            case .configDirectory: "farcast configuration directory"
            case .gcloudDirectory: "gcloud configuration directory"
            }
        }

        /// The name a tool is run by, which its file must have; nil for
        /// farcast, which is run by its path, and for the directories.
        var runName: String? {
            switch self {
            case .kubectl: "kubectl"
            case .authPlugin: "gke-gcloud-auth-plugin"
            case .gcloud: "gcloud"
            case .farcast, .configDirectory, .gcloudDirectory: nil
            }
        }

        /// What runs the tool by `runName`: farcast runs kubectl (it runs
        /// no other tool), the instance's kubeconfig has kubectl run the
        /// plugin, and the plugin runs gcloud.
        var runBy: String? {
            switch self {
            case .kubectl: "farcast"
            case .authPlugin: "kubectl"
            case .gcloud: "gke-gcloud-auth-plugin"
            case .farcast, .configDirectory, .gcloudDirectory: nil
            }
        }

        var isTool: Bool {
            switch self {
            case .farcast, .kubectl, .authPlugin, .gcloud: true
            case .configDirectory, .gcloudDirectory: false
            }
        }
    }

    subscript(field: Field) -> String {
        switch field {
        case .farcast: farcast
        case .kubectl: kubectl
        case .authPlugin: authPlugin
        case .gcloud: gcloud
        case .configDirectory: configDirectory
        case .gcloudDirectory: gcloudDirectory
        }
    }

    /// A blank form's suggestions, shown and never used until confirmed: the tools empty
    /// (never guessed — a guessed path is a planting surface, ADR 0021 decision 6), the
    /// directories at their defaults.
    public static func suggested(home: String) -> CLISettings {
        var base = home
        while base.hasSuffix("/") { base.removeLast() }
        return CLISettings(
            configDirectory: "\(base)/Library/Application Support/farcast",
            gcloudDirectory: "\(base)/.config/gcloud"
        )
    }

    /// What is wrong with each field, at most one problem per field, the
    /// first failing rule winning; empty when every path may be run.
    ///
    /// Every field: set; canonical-absolute; carries only what PATH can;
    /// not inside FarCast.app, as typed or resolved, against the bundle as
    /// given or resolved. Tools: the name it is run by; an executable file
    /// that only its owner can replace, in a directory only its owner can
    /// write, both where it is typed and where its links lead. Directories:
    /// a directory only its owner can write. Then, when kubectl, the plugin
    /// and gcloud are each fine, none of them is shadowed on the PATH
    /// farcast gets. Group-writable is not refused: Homebrew's own
    /// directories are.
    public func problems(probe: any FileProbe, bundlePath: String) -> [SettingsProblem] {
        // Both forms of the bundle, so a path in either form is caught:
        // URL's symlink resolution drops a leading /private, and the
        // caller's bundlePath may not have been resolved the same way.
        let bundles = bundlePath.isEmpty ? [] : [bundlePath, probe.resolved(bundlePath)].compactMap { $0 }
        var problems: [SettingsProblem] = []
        for field in Field.allCases {
            if let message = problem(field, probe: probe, bundles: bundles) {
                problems.append(SettingsProblem(field: field, message: message))
            }
        }
        let tools: [Field] = [.kubectl, .authPlugin, .gcloud]
        guard !problems.contains(where: { tools.contains($0.field) }) else { return problems }
        let path = ChildEnvironment.path(for: self).split(separator: ":").map(String.init)
        for field in tools {
            guard let name = field.runName, let own = ChildEnvironment.directory(of: self[field]) else { continue }
            let first = path.first { directory in
                if case .file(executable: true, worldWritable: _) = probe.entry(at: Self.join(directory, name)) { return true }
                return false
            }
            if let first, first != own {
                problems.append(SettingsProblem(
                    field: field,
                    message: "\(Self.join(first, name)) comes first on the PATH farcast gets, so it would run instead of this one"
                ))
            }
        }
        return problems.sorted { a, b in
            Field.allCases.firstIndex(of: a.field) ?? 0 < Field.allCases.firstIndex(of: b.field) ?? 0
        }
    }

    private func problem(_ field: Field, probe: any FileProbe, bundles: [String]) -> String? {
        let path = self[field]
        if path.isEmpty { return "not set" }
        if !Self.isCanonicalAbsolute(path) {
            return "must be an absolute path, with no \"~\", \".\", \"..\", empty part or trailing \"/\""
        }
        if path.unicodeScalars.contains(where: { $0 == ":" || ($0 != " " && !Display.isPrintable($0)) }) {
            return "holds a character PATH cannot carry"
        }
        let resolved = probe.resolved(path)
        let forms = [path, resolved].compactMap { $0 }
        if forms.contains(where: { form in bundles.contains { Self.isInside(form, $0) } }) {
            return "is inside FarCast.app"
        }
        let entry = probe.entry(at: path)
        guard field.isTool else {
            switch entry {
            case .directory(worldWritable: false): return nil
            case .directory(worldWritable: true): return "is writable by anyone on this Mac"
            case .missing, .other, .file: return "is not a directory"
            }
        }
        if let name = field.runName, let runner = field.runBy, Self.basename(path) != name {
            return "\(runner) runs it by the name \"\(name)\", so the file must be called that"
        }
        switch entry {
        case .missing: return "nothing is at this path"
        case .other, .directory: return "is not a file"
        case .file(executable: false, worldWritable: _): return "is not executable by you"
        case .file(executable: true, worldWritable: true): return "anyone on this Mac can replace it"
        case .file(executable: true, worldWritable: false): break
        }
        if Self.inWorldWritableDirectory(path, probe) {
            return "its directory is writable by anyone on this Mac"
        }
        // A link is checked where it leads too: the file that runs is the
        // target, and anyone who can write the target's directory can
        // replace it.
        if let resolved, resolved != path, Self.inWorldWritableDirectory(resolved, probe) {
            return "it links to a file in a directory anyone on this Mac can write"
        }
        return nil
    }

    static func inWorldWritableDirectory(_ path: String, _ probe: any FileProbe) -> Bool {
        guard let directory = ChildEnvironment.directory(of: path) else { return false }
        return probe.entry(at: directory) == .directory(worldWritable: true)
    }

    /// Starts with "/", holds no "//", ends without "/" unless it is "/", and
    /// has no "." or ".." part.
    static func isCanonicalAbsolute(_ path: String) -> Bool {
        guard path.hasPrefix("/"), !path.contains("//") else { return false }
        if path == "/" { return true }
        guard !path.hasSuffix("/") else { return false }
        return !path.split(separator: "/").contains { $0 == "." || $0 == ".." }
    }

    /// Whether `path` is `bundle` or under it. A bundle URL's path ends with
    /// "/", so that is dropped first: the bundle itself is inside it too.
    static func isInside(_ path: String, _ bundle: String) -> Bool {
        var base = bundle
        while base.count > 1, base.hasSuffix("/") { base.removeLast() }
        if base == "/" { return path.hasPrefix("/") }
        return path == base || path.hasPrefix(base + "/")
    }

    static func basename(_ path: String) -> String {
        path.split(separator: "/", omittingEmptySubsequences: true).last.map(String.init) ?? path
    }

    static func join(_ directory: String, _ name: String) -> String {
        directory == "/" ? "/\(name)" : "\(directory)/\(name)"
    }
}

/// One field's problem, said in Settings beside its row.
public struct SettingsProblem: Sendable, Equatable {
    public var field: CLISettings.Field
    public var message: String
}

/// Settings as the operator confirmed them, and when.
public struct ConfirmedCLISettings: Codable, Sendable, Equatable {
    public var settings: CLISettings
    public var confirmedAt: Date

    public init(settings: CLISettings, confirmedAt: Date) {
        self.settings = settings
        self.confirmedAt = confirmedAt
    }
}

/// Kept in UserDefaults directly; SwiftUI's AppStorage wrapper is outside the source gate's attribute set.
public struct CLISettingsStore {
    public static let key = "farsight.connected.settings.v1"

    private let defaults: UserDefaults

    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    /// Nil when absent or undecodable.
    public func load() -> ConfirmedCLISettings? {
        guard let data = defaults.data(forKey: Self.key) else { return nil }
        return try? Self.decoder().decode(ConfirmedCLISettings.self, from: data)
    }

    public func save(_ confirmed: ConfirmedCLISettings) {
        guard let data = try? Self.encoder().encode(confirmed) else { return }
        defaults.set(data, forKey: Self.key)
    }

    public func clear() {
        defaults.removeObject(forKey: Self.key)
    }

    private static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return decoder
    }

    private static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }
}
