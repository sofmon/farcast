/// What a part of a read that failed says on the map, in the map's own
/// words: one plain sentence per section, made from the CLI's stable kinds,
/// never from its prose. A section's sentence names what was not read, why,
/// and the remedy where there is one:
///
///     spending not read · cluster unreachable — check the network
///     the read was refused · version skew — build farcast and FarCast from one commit
///     network not read · tunnel unreachable
///
/// The CLI's own message, which can run to a whole API server error, is
/// shown once per instance, behind the instance chip's disclosure, and never
/// repeated in the panels.
public enum ProblemText {
    /// What was not read, or what happened to the read as a whole.
    public static func what(_ section: SectionProblem.Section, _ kind: SectionProblem.Kind) -> String {
        switch section {
        case .read:
            switch kind {
            case .versionSkew: "the read was refused"
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
        case .notConnected: "farcast connect opens one"
        case .kernelAbsent: "farcast kernel deploy starts one"
        case .notCheckpointed: "the kernel writes one within minutes of starting"
        // Only the read as a whole is refused for skew between this app and
        // its farcast; a section's skew is the cluster's, with no one fix.
        case .versionSkew: section == .read ? "build farcast and FarCast from one commit" : nil
        // Every step, since the kind also covers a reader uploaded and not
        // yet granted, for which reader init refuses.
        case .credentialMissing:
            "set up the instance's reader in a terminal: farcast reader init <instance>, the printed Cloud Shell script, "
                + "reader record and reader grant; farcast instances shows the reader's state"
        // Rotation is the last remedy, not the first.
        case .credentialRefused:
            "check this machine's clock; then the key id (farcast reader record); "
                + "a reader key expires with its certificate: farcast reader init <instance> --rotate"
        // An authentication failure, which reader grant, an RBAC fix, cannot fix.
        case .unauthorized:
            "the cluster refused the reader's token: check that the Cloud Shell step granted "
                + "roles/container.clusterViewer; farcast instances shows the reader's state"
        case .forbidden:
            "the reader may not read this: farcast reader grant <instance>; "
                + "if the reader was just set up, IAM changes can take 7 minutes or longer"
        case .clusterUnreachable: "check the network"
        // The app's child environment never carries what unsafe_environment
        // refuses, and in a terminal the CLI's message says what to unset.
        case .unsafeEnvironment, .endpointRefused, .clusterRejected, .documentUnreadable,
             .rolloutStalled, .notMigrated, .planChanged: nil
        case .recordUnreadable, .notFound, .tunnelUnreachable, .timeout, .internal, .unknown: nil
        }
    }

    /// The sentence: what, then why after " · ", then the remedy after " — ".
    public static func sentence(_ section: SectionProblem.Section, _ kind: SectionProblem.Kind) -> String {
        what(section, kind)
            + (why(section, kind).map { " · \($0)" } ?? "")
            + (remedy(section, kind).map { " — \($0)" } ?? "")
    }

    /// What a group whose applications were not read says on the map,
    /// while the rest of the apps section was (`AppGroup.appsProblem`): that
    /// they were not read, and why, as the kind's label.
    ///
    ///     applications not read · forbidden
    public static func groupNotRead(_ problem: SectionProblem) -> String {
        "applications not read · \(why(.apps, problem.kind) ?? problem.kind.label)"
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
    ///     read refused · version skew
    ///     3 sections not read · credential missing
    ///     network not read · tunnel unreachable
    ///     1 spending figure not drawn
    public static func summary(_ problems: [SectionProblem]) -> [String] {
        var parts: [String] = []
        if let read = problems.first(where: { $0.section == .read }) {
            switch read.kind {
            case .versionSkew: parts.append("read refused · \(read.kind.label)")
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
