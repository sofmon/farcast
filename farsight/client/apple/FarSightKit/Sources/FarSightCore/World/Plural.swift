/// Counts, said in words: the singular for exactly one, the plural for any
/// other count, none included — "1 app stopped", "0 apps stopped", "2 lines
/// out". The map's one rule for it, so no label says "1 apps".
public enum Plural {
    /// The word or phrase for `count` of something.
    public static func of(_ count: Int, _ singular: String, _ plural: String) -> String {
        count == 1 ? singular : plural
    }

    /// The count, then its word: "1 section", "3 sections".
    public static func count(_ count: Int, _ singular: String, _ plural: String) -> String {
        "\(count) \(of(count, singular, plural))"
    }
}
