/// What a part of a read that failed says on the map, in the map's own
/// words: one plain sentence per section, made from the CLI's stable kinds,
/// never from its prose. A section's sentence names what was not read, why,
/// and the remedy where there is one:
///
///     spending not read · signed out of gcloud — run gcloud auth login
///     the read was refused · gcloud identity does not match — farcast instances pin-gcloud
///     network not read · tunnel unreachable
///
/// The CLI's own message, which can run to a whole kubectl or gcloud error,
/// is shown once per instance, behind the instance chip's disclosure, and
/// never repeated in the panels.
public enum ProblemText {
    /// What was not read, or what happened to the read as a whole.
    public static func what(_ section: SectionProblem.Section, _ kind: SectionProblem.Kind) -> String {
        switch section {
        case .read:
            switch kind {
            case .gcloudMismatch, .versionSkew: "the read was refused"
            case .timeout: "the read timed out"
            default: "the read failed"
            }
        case .record:
            switch kind {
            case .recordUnreadable: "the record on this Mac is unreadable"
            case .notFound: "no record of it on this Mac"
            default: "the record on this Mac could not be drawn whole"
            }
        case .unknown:
            "part of the read failed"
        case .figures:
            // Its section was read: only this figure is not drawn.
            "spending figure not drawn"
        case .spend, .apps, .policy, .network, .seal:
            "\(name(section)) not read"
        }
    }

    /// Why, in a few words; nil where `what` already says it.
    public static func why(_ section: SectionProblem.Section, _ kind: SectionProblem.Kind) -> String? {
        switch (section, kind) {
        case (.read, .timeout), (.record, .recordUnreadable), (.record, .notFound), (.record, .internal):
            nil
        case (.figures, _):
            // Outside the range the map draws a sum of money in.
            "out of range"
        case (_, .unknown):
            // No kind, or one this build does not know: the CLI gave no
            // reason the map can say.
            "no reason given"
        default:
            kind.label
        }
    }

    /// The one thing the operator can do about it, where there is one.
    public static func remedy(_ section: SectionProblem.Section, _ kind: SectionProblem.Kind) -> String? {
        guard section != .figures else { return nil }
        return switch kind {
        case .gcloudSignedOut: "run gcloud auth login"
        case .gcloudMismatch: "farcast instances pin-gcloud"
        case .notConnected: "farcast connect opens one"
        case .kernelAbsent: "farcast kernel deploy starts one"
        case .notCheckpointed: "the kernel writes one within minutes of starting"
        case .kubectlMissing: "set kubectl in Settings"
        case .authToolMissing: "set gke-gcloud-auth-plugin in Settings"
        // Only the read as a whole is refused for skew between this app and
        // its farcast; a section's skew is the cluster's, with no one fix.
        case .versionSkew: section == .read ? "build farcast and FarCast from one commit" : nil
        case .recordUnreadable, .notFound, .tunnelUnreachable, .kubectlFailed, .timeout, .internal, .unknown: nil
        }
    }

    /// The sentence: what, then why after " · ", then the remedy after " — ".
    public static func sentence(_ section: SectionProblem.Section, _ kind: SectionProblem.Kind) -> String {
        what(section, kind)
            + (why(section, kind).map { " · \($0)" } ?? "")
            + (remedy(section, kind).map { " — \($0)" } ?? "")
    }

    /// A section as a sentence names it.
    public static func name(_ section: SectionProblem.Section) -> String {
        switch section {
        case .spend: "spending"
        case .apps: "apps"
        case .policy: "egress policy"
        case .network: "network"
        case .seal: "seal"
        case .figures: "figures"
        case .record: "record"
        case .read: "read"
        case .unknown: "part of the read"
        }
    }

    /// What an instance's chip says of its problems, briefly: the read as a
    /// whole, the record, then the sections that were not read, counted and
    /// never listed one by one, with why, then the figures not drawn. Empty
    /// when nothing failed.
    ///
    ///     read refused · gcloud identity does not match
    ///     3 sections not read · signed out of gcloud
    ///     network not read · tunnel unreachable
    ///     1 spending figure not drawn
    public static func summary(_ problems: [SectionProblem]) -> [String] {
        var parts: [String] = []
        if let read = problems.first(where: { $0.section == .read }) {
            switch read.kind {
            case .gcloudMismatch, .versionSkew: parts.append("read refused · \(read.kind.label)")
            // The read that timed out is the latest; the time the chip
            // shows beside it is the kept snapshot's.
            case .timeout: parts.append("read timed out")
            default: parts.append("read failed · \(why(.read, read.kind) ?? read.kind.label)")
            }
        }
        if let record = problems.first(where: { $0.section == .record }) {
            switch record.kind {
            case .recordUnreadable: parts.append("record unreadable")
            case .notFound: parts.append("no record")
            default: parts.append("record incomplete")
            }
        }
        // A section is counted once, however many problems name it. A
        // figure not drawn is no section that was not read: it is counted
        // apart, after them.
        var sections: [SectionProblem.Section] = []
        var reasons: [String] = []
        for problem in problems where ![.read, .record, .figures].contains(problem.section) {
            if !sections.contains(problem.section) { sections.append(problem.section) }
            let reason = why(problem.section, problem.kind) ?? problem.kind.label
            if !reasons.contains(reason) { reasons.append(reason) }
        }
        if let first = sections.first {
            let because = switch reasons.count {
            case 0: ""
            case 1, 2: " · " + reasons.joined(separator: ", ")
            default: " · \(reasons[0]), \(reasons[1]) and more"
            }
            let what = sections.count == 1 ? Self.what(first, .unknown) : "\(Plural.count(sections.count, "section", "sections")) not read"
            parts.append(what + because)
        }
        let figures = problems.filter { $0.section == .figures }.count
        if figures > 0 {
            parts.append("\(Plural.count(figures, "spending figure", "spending figures")) not drawn")
        }
        return parts
    }
}

extension SectionProblem {
    /// This problem as the map says it (`ProblemText.sentence`).
    public var sentence: String {
        ProblemText.sentence(section, kind)
    }
}
