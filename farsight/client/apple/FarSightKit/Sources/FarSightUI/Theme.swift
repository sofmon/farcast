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

    /// Spending against the limit: calm, then a warning, then critical at the
    /// point TechnoCore starts acting.
    static func spending(_ fraction: Double) -> Color {
        fraction >= 0.9 ? critical : fraction >= 0.75 ? warning : running
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
        return app.costNote ?? ""
    }
}
