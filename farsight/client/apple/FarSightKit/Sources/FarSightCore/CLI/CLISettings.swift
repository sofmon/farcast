import Foundation

/// The paths the app runs `farcast` with, as the operator confirmed them once
/// in Settings (ADR 0021 decision 9, amended 2026-11-12). Nothing here is
/// guessed: a guessed tool path is a place to plant a tool (decision 6).
///
/// Two paths since ADR 0023 M2.4: farcast reads each instance's cluster
/// in-process, so it runs no kubectl, auth plugin or gcloud for the three
/// commands the app runs. Settings saved with the four other paths load as
/// these two, and the next save drops the rest.
public struct CLISettings: Codable, Sendable, Equatable {
    public var farcast: String
    /// farcast's `--config`.
    public var configDirectory: String

    public init(farcast: String = "", configDirectory: String = "") {
        self.farcast = farcast
        self.configDirectory = configDirectory
    }

    public enum Field: String, Sendable, CaseIterable {
        case farcast, configDirectory

        /// The Settings row's name, and the field's name in messages:
        /// "farcast", "farcast configuration directory".
        public var title: String {
            switch self {
            case .farcast: "farcast"
            case .configDirectory: "farcast configuration directory"
            }
        }

        var isTool: Bool {
            switch self {
            case .farcast: true
            case .configDirectory: false
            }
        }
    }

    subscript(field: Field) -> String {
        switch field {
        case .farcast: farcast
        case .configDirectory: configDirectory
        }
    }

    /// A blank form's suggestions, shown and never used until confirmed:
    /// farcast empty (never guessed — a guessed path is a planting surface,
    /// ADR 0021 decision 6), the directory at its default.
    public static func suggested(home: String) -> CLISettings {
        var base = home
        while base.hasSuffix("/") { base.removeLast() }
        return CLISettings(configDirectory: "\(base)/Library/Application Support/farcast")
    }

    /// What is wrong with each field, at most one problem per field, the
    /// first failing rule winning; empty when every path may be run.
    ///
    /// Both fields: set; canonical-absolute; no ":" and nothing that does
    /// not print, so what Settings shows and a terminal command carries is
    /// the path itself; not inside FarCast.app, as typed or resolved,
    /// against the bundle as given or resolved. farcast: an executable file
    /// that only its owner can replace, in a directory only its owner can
    /// write, both where it is typed and where its links lead; it may have
    /// any name, since it is run by its path. The directory: a directory
    /// only its owner can write. Group-writable is not refused: Homebrew's
    /// own directories are.
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
        return problems
    }

    private func problem(_ field: Field, probe: any FileProbe, bundles: [String]) -> String? {
        let path = self[field]
        if path.isEmpty { return "not set" }
        if !Self.isCanonicalAbsolute(path) {
            return "must be an absolute path, with no \"~\", \".\", \"..\", empty part or trailing \"/\""
        }
        if path.unicodeScalars.contains(where: { $0 == ":" || ($0 != " " && !Display.isPrintable($0)) }) {
            return "holds a \":\" or a character that does not print"
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
