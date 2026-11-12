/// Text that came from an instance, made safe to draw.
///
/// An instance names its apps, hosts and devices, and the CLI passes on what
/// a monitor, a keyholder or a keeper said. Any of it can carry a bidi
/// override that reorders what is drawn around it, a control character, or
/// an invisible one. So every such string is drawn, and read to VoiceOver,
/// through one of these — the CLI's own rule, ported (`output.Printable` and
/// `errorText` in `farsight/cli/internal/output`):
///
/// - a scalar is printable when its general category is a letter, a mark, a
///   number, a punctuation mark or a symbol, or it is U+0020: Go's
///   `unicode.IsPrint`;
/// - every other scalar is written as Go's `strconv.QuoteRuneToASCII` writes
///   it, without the quotes: `\a \b \f \n \r \t \v`, `\xNN` below U+0080,
///   `\uNNNN`, then `\UNNNNNNNN`, in lowercase hex.
///
/// Go also writes each byte that is not UTF-8 as `\xNN`. No such byte reaches
/// a Swift `String`: decoding refuses it or replaces it with U+FFFD first.
///
/// Only what is drawn is escaped, never an id: ids key the arrangement, the
/// alerts and the lines, and are compared, not shown.
public enum Display {
    /// For a name, a host, a label: one line, so newlines and tabs are
    /// escaped too.
    public static func name(_ text: String) -> String {
        escape(text, keepingLines: false)
    }

    /// For a message, a caveat, an alert's title: prose that may run over
    /// several lines, so newlines and tabs stay, as `errorText` keeps them.
    public static func message(_ text: String) -> String {
        escape(text, keepingLines: true)
    }

    /// Go's `unicode.IsPrint`, by general category.
    public static func isPrintable(_ scalar: Unicode.Scalar) -> Bool {
        if scalar == " " { return true }
        switch scalar.properties.generalCategory {
        case .uppercaseLetter, .lowercaseLetter, .titlecaseLetter, .modifierLetter, .otherLetter,
             .nonspacingMark, .spacingMark, .enclosingMark,
             .decimalNumber, .letterNumber, .otherNumber,
             .connectorPunctuation, .dashPunctuation, .openPunctuation, .closePunctuation,
             .initialPunctuation, .finalPunctuation, .otherPunctuation,
             .mathSymbol, .currencySymbol, .modifierSymbol, .otherSymbol:
            return true
        default:
            return false
        }
    }

    private static func escape(_ text: String, keepingLines: Bool) -> String {
        guard text.unicodeScalars.contains(where: { !kept($0, keepingLines) }) else { return text }
        var out = String.UnicodeScalarView()
        for scalar in text.unicodeScalars {
            if kept(scalar, keepingLines) {
                out.append(scalar)
            } else {
                out.append(contentsOf: escaped(scalar).unicodeScalars)
            }
        }
        return String(out)
    }

    private static func kept(_ scalar: Unicode.Scalar, _ keepingLines: Bool) -> Bool {
        isPrintable(scalar) || (keepingLines && (scalar == "\n" || scalar == "\t"))
    }

    /// One scalar as Go's `strconv.QuoteRuneToASCII` writes it, unquoted.
    static func escaped(_ scalar: Unicode.Scalar) -> String {
        switch scalar {
        case "\u{07}": return "\\a"
        case "\u{08}": return "\\b"
        case "\u{0C}": return "\\f"
        case "\n": return "\\n"
        case "\r": return "\\r"
        case "\t": return "\\t"
        case "\u{0B}": return "\\v"
        default:
            let value = scalar.value
            if value < 0x20 || value == 0x7F { return "\\x" + hex(value, digits: 2) }
            if value < 0x1_0000 { return "\\u" + hex(value, digits: 4) }
            return "\\U" + hex(value, digits: 8)
        }
    }

    private static func hex(_ value: UInt32, digits: Int) -> String {
        let text = String(value, radix: 16, uppercase: false)
        return String(repeating: "0", count: max(digits - text.count, 0)) + text
    }
}
