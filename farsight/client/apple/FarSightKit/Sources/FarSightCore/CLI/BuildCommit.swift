/// The commit a build was made from, as both sides state it: the app in its
/// Info.plist (`FarCastCommit`, written at build time from `FARCAST_COMMIT`),
/// farcast in `version` and in every document's `farcast.commit`. The app
/// reads nothing from a farcast built from another commit (ADR 0021 decision
/// 9), and nothing at all when it does not know its own.
///
/// Both sides use seven digits: Go's build stamp shortens the commit to 7,
/// and the app is built with `FARCAST_COMMIT=$(git rev-parse HEAD | cut -c1-7)`.
/// Neither records whether the tree was modified.
public enum BuildCommit {
    public static let infoKey = "FarCastCommit"

    /// The first seven hex digits, lower-cased, of a commit; nil for anything else
    /// ("", "none", "dev", "$(FARCAST_COMMIT)", fewer than seven hex digits).
    public static func parse(_ raw: String?) -> String? {
        guard let raw else { return nil }
        let scalars = Array(raw.unicodeScalars)
        guard (7...64).contains(scalars.count), scalars.allSatisfy(isHex) else { return nil }
        return String(String.UnicodeScalarView(scalars.prefix(7))).lowercased()
    }

    private static func isHex(_ scalar: Unicode.Scalar) -> Bool {
        ("0"..."9").contains(scalar) || ("a"..."f").contains(scalar) || ("A"..."F").contains(scalar)
    }
}
