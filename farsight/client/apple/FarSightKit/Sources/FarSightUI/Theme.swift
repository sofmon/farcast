import SwiftUI
import FarSightCore

/// The map's colours. A first pass, to be tuned once the scaffold runs.
enum Theme {
    // The ground and what is built on it.
    static let ground = Color(rgb: 0x0B0F14)
    static let gridDot = Color.white.opacity(0.06)
    static let territory = Color(rgb: 0x111821)
    static let wall = Color(rgb: 0x3E5A78)
    static let groupFill = Color(rgb: 0x0F151C)
    static let groupStroke = Color(rgb: 0x2A3949)
    static let systemGroupStroke = Color(rgb: 0x3B5068)

    // Surfaces over the backdrop. Each lets some of the backdrop through and
    // covers the rest with its own colour, enough that the connection lines,
    // labels and text BackdropTests lists keep WCAG contrast on it over any
    // backdrop no brighter than Backdrop.luminanceCap. Outlines and faded
    // lines are not held to that; BackdropTests names them.
    /// The inside of an instance's wall, over the backdrop's frosted form.
    static let territorySurface = territory.opacity(0.55)
    /// A group's frame, over its instance's surface.
    static let groupSurface = groupFill.opacity(0.6)
    /// Behind a label: a connection's, a gate's, an instance's, and a repo's
    /// name in the app strip. Nearly opaque, because a label may stand on the
    /// open backdrop or, in the strip, on an app's light page.
    static let chip = ground.opacity(0.94)

    // Panels.
    static let panel = Color(rgb: 0x141B23)
    static let panelStroke = Color(rgb: 0x2F4052)
    static let panelBar = Color(rgb: 0x1A232D)
    static let page = Color(rgb: 0xF3F1EC)
    static let pageInk = Color(rgb: 0xD9D4CA)
    static let pageInkStrong = Color(rgb: 0xBEB6A8)

    // Text.
    static let text = Color(rgb: 0xE6EDF3)
    static let secondaryText = Color(rgb: 0x8FA3B6)
    static let tertiaryText = Color(rgb: 0x5F7387)

    // States.
    static let running = Color(rgb: 0x4FD1B5)
    static let stopped = Color(rgb: 0x7E8E9E)
    static let focus = Color(rgb: 0x6FB6FF)
    static let warning = Color(rgb: 0xF2B24C)
    static let critical = Color(rgb: 0xFF6B57)
    static let illustrative = Color(rgb: 0xB48CFF)
    static let money = Color(rgb: 0xF2B24C)

    // Connections, by what is known about them.
    static let observed = Color(rgb: 0x6FB6FF)
    static let declared = Color(rgb: 0x8FA3B6)
    static let denied = Color(rgb: 0xFF6B57)
    static let storage = Color(rgb: 0x4FD1B5)
    static let keeper = Color(rgb: 0xA9B7C4)
    static let planned = Color(rgb: 0xB48CFF)
    static let watch = Color(rgb: 0x6E8296)

    /// Spending by the kernel's own level, never by a share worked out here:
    /// calm, then a warning, then critical where TechnoCore acts. A level not
    /// read is said in plain text, never in the calm colour.
    static func level(_ level: Spending.Level) -> Color {
        switch level {
        case .ok, .warn50: running
        case .warn75, .warn90: warning
        case .reached: critical
        case .unknown: secondaryText
        }
    }

    /// The part of the spending bar that is `expected`, lighter than the
    /// confirmed part beside it.
    static let expectedShare = 0.45

    /// An app's state. Only a running app is drawn in the running colour; one
    /// not read is drawn in the secondary text colour, with a dashed outline
    /// (`stateDash`), so it never passes for running.
    static func state(_ state: AppState) -> Color {
        switch state {
        case .running: running
        case .starting: warning
        case .stopped, .notDeployed: stopped
        case .unknown: secondaryText
        }
    }

    /// The outline an app's state adds to its panel, if any.
    static func stateDash(_ state: AppState) -> [CGFloat] {
        switch state {
        case .unknown: [2, 4]
        case .running, .starting, .stopped, .notDeployed: []
        }
    }

    /// A device by its health. One not read is not called unhealthy.
    static func device(_ device: Device) -> Color {
        switch device.health {
        case .healthy: device.role == .operator ? focus : keeper
        case .expired, .revoked, .unseen: warning
        case .unknown: secondaryText
        }
    }

    static func severity(_ severity: WorldAlert.Severity) -> Color {
        severity == .critical ? critical : warning
    }
}

extension Color {
    init(rgb: UInt32) {
        self.init(
            red: Double((rgb >> 16) & 0xFF) / 255,
            green: Double((rgb >> 8) & 0xFF) / 255,
            blue: Double(rgb & 0xFF) / 255
        )
    }
}

/// Money and shares, the way the HUD says them.
enum Format {
    /// Any Int, Int.min included: the magnitude is taken unsigned.
    static func dollars(_ cents: Int) -> String {
        let sign = cents < 0 ? "-" : ""
        let value = cents.magnitude
        let rest = value % 100
        return "\(sign)$\(value / 100).\(rest < 10 ? "0" : "")\(rest)"
    }

    /// Clamped, so a malformed share never traps on conversion.
    static func percent(_ fraction: Double) -> String {
        guard fraction.isFinite else { return "–" }
        let percent = min(max(fraction * 100, -99_999), 99_999)
        return "\(Int(percent.rounded()))%"
    }

    static func cost(of app: Application) -> String {
        if let cents = app.monthCents { return dollars(cents) }
        return Display.name(app.costNote ?? "")
    }

    /// A share, or a dash when it was not read.
    static func percent(_ fraction: Double?) -> String {
        fraction.map { percent($0) } ?? "–"
    }

    /// A day, as the confirmed figure is dated. The date a confirmed window
    /// runs to is a UTC day boundary, and the CLI prints it in UTC, so it is
    /// said in UTC here too: in the Mac's own zone, west of UTC, it would be
    /// the day before.
    static func day(_ date: Date) -> String {
        var style = Date.FormatStyle.dateTime.day().month(.abbreviated)
        style.timeZone = .gmt
        return date.formatted(style)
    }

    /// A time of day, as a read is stamped.
    static func time(_ date: Date) -> String {
        date.formatted(date: .omitted, time: .shortened)
    }

    /// Spending in a line: confirmed, with the day it runs to, and expected
    /// apart, against the kernel's limit, never one undifferentiated total
    /// (ADR 0009 decision 4). Not read, it says so, and names the recorded
    /// limit as recorded.
    static func spending(_ spending: Spending) -> String {
        guard spending.isRead else {
            let recorded = spending.recordedLimitCents.map { " · recorded limit \(dollars($0))" } ?? ""
            return "spending not read\(recorded)"
        }
        let limit = spending.limitCents.map { " of \(dollars($0))" } ?? " · no kernel limit"
        let expected = spending.expectedCents.map { "\(dollars($0)) expected" } ?? "expected not read"
        var text: String
        if spending.hasConfirmation, let confirmed = spending.confirmedCents {
            let through = spending.confirmedThrough.map { " through \(day($0))" } ?? ""
            text = "\(dollars(confirmed)) confirmed\(through) + \(expected)\(limit)"
        } else {
            text = "\(expected)\(limit) · no confirmation yet"
        }
        // The share is of the total, the sum enforcement compares; it is
        // labelled so, and never printed as a figure of its own.
        if let fraction = spending.fraction { text += " · total \(percent(fraction))" }
        if spending.isCheckpointStale { text += " · checkpoint stale" }
        return text
    }

    /// Spending at its briefest, for the HUD's chip: the total's share of the
    /// kernel's limit, labelled as the total — the sum enforcement compares
    /// — and never a bare percent; or why there is no share.
    static func share(_ spending: Spending) -> String {
        guard spending.isRead else { return "not read" }
        return spending.fraction.map { "total \(percent($0))" } ?? "no kernel limit"
    }

    /// What VoiceOver says for an instance's spending: both parts, and the
    /// total by name, as the figure enforcement compares.
    static func spendingSpoken(_ spending: Spending) -> String {
        guard spending.isRead else {
            let recorded = spending.recordedLimitCents.map { ", its recorded limit \(dollars($0))" } ?? ""
            return "spending not read\(recorded)"
        }
        var parts: [String] = []
        if spending.hasConfirmation, let confirmed = spending.confirmedCents {
            let through = spending.confirmedThrough.map { " through \(day($0))" } ?? ""
            parts.append("\(dollars(confirmed)) confirmed\(through)")
        } else {
            parts.append("no confirmation yet")
        }
        parts.append(spending.expectedCents.map { "\(dollars($0)) expected" } ?? "expected not read")
        if let fraction = spending.fraction, let limit = spending.limitCents {
            parts.append("total \(percent(fraction)) of its \(dollars(limit)) limit, the figure enforcement compares")
        } else {
            parts.append("total not compared, no kernel limit read")
        }
        parts.append("level \(spending.level.label)")
        if spending.isCheckpointStale { parts.append("checkpoint stale") }
        return parts.joined(separator: ", ")
    }

    /// Which FatLine replica counted an instance's lines, and since when:
    /// the counts on the map are that one replica's share, since it
    /// started, and each is a floor (ADR 0022 decision 9, ADR 0015).
    static func countedBy(_ network: NetworkReading) -> String {
        "counted by \(network.replica.map(Display.name) ?? "one FatLine replica")"
            + (network.since.map { " since \(day($0)) \(time($0))" } ?? "")
            + (network.fatlineReplicas.map { " · 1 of \($0) FatLine replica\($0 == 1 ? "" : "s")" } ?? "")
            + " · every count is a floor"
    }

    /// When an instance was read, and what in the read failed: what its
    /// territory's chip says under its name. Nil for an instance the map has
    /// nothing to say about (the fixture's).
    static func readState(_ instance: Instance) -> String? {
        var parts: [String] = []
        switch instance.status {
        case .running, .unknown: break
        case .provisioning, .unreachable, .deleting, .error: parts.append(instance.status.label)
        }
        parts.append(instance.readAt.map { "read \(time($0))" } ?? "not read yet")
        for problem in instance.problems {
            parts.append(problem.section == .read || problem.section == .record
                ? problem.kind.label
                : "\(problem.section.rawValue) not read: \(problem.kind.label)")
        }
        return parts.joined(separator: " · ")
    }
}
