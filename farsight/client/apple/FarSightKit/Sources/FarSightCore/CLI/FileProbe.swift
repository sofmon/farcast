import Foundation

/// What is at a path, as far as Settings' checks need to know.
public enum FileEntry: Sendable, Equatable {
    case missing
    /// Something that is neither a regular file nor a directory.
    case other
    case directory(worldWritable: Bool)
    case file(executable: Bool, worldWritable: Bool)
}

/// The file system as Settings' checks see it, so the checks are tested
/// against a table rather than this Mac's disk.
public protocol FileProbe: Sendable {
    /// Follows symlinks.
    func entry(at path: String) -> FileEntry
    /// Symlinks resolved; nil when missing.
    func resolved(_ path: String) -> String?
}

/// FileManager: `isExecutableFile(atPath:)`, `attributesOfItem` permissions (o+w), `URL.resolvingSymlinksInPath()`.
public struct LocalFileProbe: FileProbe {
    public init() {}

    public func entry(at path: String) -> FileEntry {
        guard let target = resolved(path),
              let attributes = try? FileManager.default.attributesOfItem(atPath: target)
        else { return .missing }
        let mode = (attributes[.posixPermissions] as? NSNumber)?.intValue ?? 0
        let worldWritable = mode & 0o002 != 0
        switch attributes[.type] as? FileAttributeType {
        case .typeDirectory?:
            return .directory(worldWritable: worldWritable)
        case .typeRegular?:
            return .file(executable: FileManager.default.isExecutableFile(atPath: target), worldWritable: worldWritable)
        default:
            return .other
        }
    }

    public func resolved(_ path: String) -> String? {
        guard path.hasPrefix("/") else { return nil }
        let target = URL(fileURLWithPath: path).resolvingSymlinksInPath().path
        // A link that resolves to nothing is left as the link itself: it is
        // missing, as following it finds.
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: target),
              attributes[.type] as? FileAttributeType != .typeSymbolicLink
        else { return nil }
        return target
    }
}
