import Foundation

/// An enum read from a snapshot that a newer CLI may extend. A raw value this
/// build does not know decodes as `unknown`, so one new word costs one field
/// its meaning, not the whole instance its read.
///
/// Only enums whose `unknown` has a meaning the map can draw adopt it: a
/// state, a level, a health, a status, a kind of problem or alert. Enums the
/// map's structure rests on — a connection's kind and evidence, a system or
/// device role, an endpoint, an alert's subject — stay strict: an unknown
/// value there throws, the read fails, and the instance keeps its last good
/// snapshot.
///
/// A protocol extension rather than a property wrapper: the source gate in
/// `check.sh` refuses attributes outside its allowlist.
public protocol UnknownDecodable: RawRepresentable, Codable where RawValue == String {
    static var unknown: Self { get }
}

extension UnknownDecodable {
    public init(from decoder: any Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self = Self(rawValue: raw) ?? .unknown
    }
}
