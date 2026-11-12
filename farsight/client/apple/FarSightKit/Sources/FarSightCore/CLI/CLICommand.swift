/// The three commands the app runs, and the only argv it ever builds (ADR
/// 0021 decision 9 and Verification 5). The words are exactly
/// `testdata/app/argv.json`'s, which the CLI's own tests run, with
/// `<config>` and `<instance>` filled in:
/// - the flags go before the command name, `--config <dir> -o json`, where
///   Go's root flag set takes them;
/// - `--` ends flag parsing before the instance name, so a name is never
///   read as a flag.
///
/// No other flag exists in code: not `-v`, not `--help`, not `pin-gcloud`.
enum CLICommand: Sendable, Equatable {
    case version
    case instances
    case world(String)

    func arguments(configDirectory: String) -> [String] {
        let flags = ["--config", configDirectory, "-o", "json"]
        return switch self {
        case .version: flags + ["version"]
        case .instances: flags + ["instances"]
        case .world(let instance): flags + ["world", "--", instance]
        }
    }

    /// For messages: "version", "instances", "world <name>".
    var label: String {
        switch self {
        case .version: "version"
        case .instances: "instances"
        case .world(let instance): "world \(instance)"
        }
    }
}
