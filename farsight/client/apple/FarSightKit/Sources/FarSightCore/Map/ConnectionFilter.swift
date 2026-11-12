/// Which connections the map draws.
public enum ConnectionFilter: String, CaseIterable, Sendable, Codable {
    case all
    /// Only what crosses an instance's wall: egress, the tunnel, keepers.
    case boundary
    /// Only what stays inside: app to app, storage, Shrike watching.
    case inside
    case off

    /// Whether `connection` is drawn with `focus` the focused app. Storage is
    /// drawn only for the focused app: every app has it, so drawn for all of
    /// them it would say nothing.
    public func shows(_ connection: Connection, focus: String?) -> Bool {
        switch self {
        case .off:
            return false
        case .boundary where !connection.crossesWall, .inside where connection.crossesWall:
            return false
        case .all, .boundary, .inside:
            if connection.kind == .storage {
                return focus != nil && (connection.from.appID == focus || connection.to.appID == focus)
            }
            return true
        }
    }
}

/// How strongly a drawn connection stands out.
public enum Emphasis: Sendable, Equatable {
    case normal
    /// It touches the focused app: drawn above everything.
    case lifted
    /// Something else is focused.
    case dimmed

    public init(_ connection: Connection, focus: String?) {
        guard let focus else { self = .normal; return }
        self = connection.from.appID == focus || connection.to.appID == focus ? .lifted : .dimmed
    }
}
