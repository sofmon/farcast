import SwiftUI
import FarSightCore

/// One app's place on the map. How much it shows depends on how large it is
/// drawn: far away, a marker; nearer, a glance — name, status, cost; close,
/// the app itself, live or showing its last frame.
struct AppPanel: View {
    let app: Application
    let group: AppGroup
    /// Where the panel is drawn, in viewport points.
    let rect: CGRect
    let scale: CGFloat
    let isFocused: Bool
    let isLive: Bool
    let alert: WorldAlert?
    /// Narrower than this on screen, the panel shows a glance, not its app.
    let fullWidth: CGFloat
    let model: WorldModel

    static let titleBarHeight: CGFloat = 32

    private enum Level {
        case marker
        case glance
        case full
    }

    private var level: Level {
        rect.width < min(120, fullWidth * 0.5) ? .marker : rect.width < fullWidth ? .glance : .full
    }

    var body: some View {
        Group {
            switch level {
            case .marker: marker
            case .glance: glance
            case .full: full
            }
        }
        .frame(width: rect.width, height: rect.height)
        .position(x: rect.midX, y: rect.midY)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(accessibilityText)
        .accessibilityAddTraits(.isButton)
        .accessibilityAction { model.focus(on: app.id) }
    }

    // MARK: - Levels

    private var marker: some View {
        RoundedRectangle(cornerRadius: 3, style: .continuous)
            .fill(stateColor.opacity(app.state.isDormant ? 0.35 : 0.8))
            .overlay(
                RoundedRectangle(cornerRadius: 3, style: .continuous)
                    .strokeBorder(borderColor, style: StrokeStyle(lineWidth: isFocused || alert != nil ? 2 : 0.5, dash: dash))
            )
            .overlay(alignment: .bottom) {
                if rect.width >= 30 {
                    Text(Display.name(app.name))
                        .font(.system(size: 10, weight: .medium))
                        .foregroundStyle(Theme.text)
                        .fixedSize()
                        .offset(y: 14)
                }
            }
            .contentShape(Rectangle())
            .onTapGesture { model.focus(on: app.id) }
    }

    private var glance: some View {
        VStack(alignment: .leading, spacing: 4) {
            // The name band is the handle that moves the app; the rest of the
            // card pans the map like empty space does.
            HStack(spacing: 6) {
                Circle().fill(stateColor).frame(width: 7, height: 7)
                Text(Display.name(app.name))
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(Theme.text)
                Spacer(minLength: 0)
            }
            .frame(height: 20)
            .contentShape(Rectangle())
            .moveHandle(model, .app(app.id))
            Text(statusLine)
                .font(.system(size: 11))
                .foregroundStyle(statusColor)
                .lineLimit(2)
            Spacer(minLength: 0)
            Text(Format.cost(of: app))
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(Theme.money)
        }
        .lineLimit(1)
        .padding(10)
        .frame(width: rect.width, height: rect.height, alignment: .topLeading)
        .background(Theme.panel, in: shape)
        .overlay(shape.strokeBorder(borderColor, style: StrokeStyle(lineWidth: borderWidth, dash: dash)))
        .opacity(app.state.isDormant ? 0.75 : 1)
        .contentShape(shape)
        .onTapGesture { model.focus(on: app.id) }
    }

    private var full: some View {
        VStack(spacing: 0) {
            titleBar
            surface
        }
        .background(Theme.panel)
        .clipShape(shape)
        .overlay(shape.strokeBorder(borderColor, style: StrokeStyle(lineWidth: borderWidth, dash: dash)))
        .shadow(color: .black.opacity(isFocused ? 0.5 : 0.3), radius: isFocused ? 24 : 10, y: 6)
    }

    // MARK: - Full panel parts

    private var titleBar: some View {
        HStack(spacing: 8) {
            Circle().fill(stateColor).frame(width: 8, height: 8)
            Text(Display.name(app.name))
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(Theme.text)
            Text(group.isSystem ? "FarCast" : Display.name(group.namespace))
                .font(.system(size: 11))
                .foregroundStyle(Theme.secondaryText)
            Spacer(minLength: 4)
            badge
            Text(Format.cost(of: app))
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(Theme.money)
        }
        .lineLimit(1)
        .padding(.horizontal, 12)
        .frame(height: Self.titleBarHeight)
        .background(Theme.panelBar)
        .contentShape(Rectangle())
        .moveHandle(model, .app(app.id))
        .onTapGesture { model.focus(on: app.id) }
    }

    /// The app's state, when it is anything but running; otherwise what the
    /// live budget would do with this panel. Tiles are not built, so nothing
    /// is live yet and there is no last frame: the pill says "would".
    /// FarCast's own surfaces are native and not budgeted, so they have none.
    @ViewBuilder
    private var badge: some View {
        if app.state != .running {
            Pill(text: app.state.label, color: Theme.state(app.state))
        } else if group.isSystem {
            EmptyView()
        } else if app.isIllustrative {
            // A sketch of decided behaviour: no deployment, no UI, nothing
            // to budget.
            Pill(text: "illustrative", color: Theme.illustrative)
        } else if isLive {
            Pill(text: "would be live", color: Theme.focus)
                .help("Tiles are not built yet. Close up like this, the app's own UI would run here.")
        } else {
            Pill(text: "would be frozen", color: Theme.secondaryText)
                .help("Tiles are not built yet. Outside the live budget, this would show the app's last frame.")
        }
    }

    private var surface: some View {
        let size = CGSize(width: rect.width, height: max(rect.height - Self.titleBarHeight, 0))
        return ZStack {
            if group.isSystem {
                SystemSurface(app: app, model: model, unit: scale)
            } else {
                PageSketch(seed: app.id, illustrative: app.isIllustrative)
            }
            switch app.state {
            case .stopped, .notDeployed:
                Theme.ground.opacity(0.55)
                Label(statusLine, systemImage: app.state == .stopped ? "pause.circle" : "circle.dashed")
                    .font(.system(size: min(max(30 * scale, 12), 20), weight: .semibold))
                    .foregroundStyle(Theme.text)
            case .running, .starting, .unknown:
                EmptyView()
            }
        }
        .frame(width: size.width, height: size.height)
        .saturation(isLive || group.isSystem || app.isIllustrative ? 1 : 0.3)
        .overlay(alignment: .bottomLeading) {
            if !group.isSystem, size.height > 120 {
                Text(app.isIllustrative
                    ? "illustrative · not a deployment, and it has no UI"
                    : "placeholder · \(Display.name(app.name))'s own web UI is drawn here once tiles exist")
                    .font(.system(size: 10))
                    .foregroundStyle(Theme.tertiaryText)
                    .padding(8)
            }
        }
        .clipped()
        .contentShape(Rectangle())
        .onTapGesture { model.focus(on: app.id) }
    }

    // MARK: - Appearance

    private var shape: RoundedRectangle {
        RoundedRectangle(cornerRadius: min(max(40 * scale, 4), 18), style: .continuous)
    }

    private var stateColor: Color {
        app.isIllustrative ? Theme.illustrative : Theme.state(app.state)
    }

    private var borderColor: Color {
        if isFocused { return Theme.focus }
        if let alert { return Theme.severity(alert.severity) }
        if app.isIllustrative { return Theme.illustrative }
        return Theme.panelStroke
    }

    private var borderWidth: CGFloat {
        isFocused ? 3 : alert != nil ? 2.5 : 1
    }

    private var dash: [CGFloat] {
        if isFocused { return [] }
        return app.isIllustrative ? [7, 5] : Theme.stateDash(app.state)
    }

    /// What the glance says under the name: the state when it is not
    /// running, else the alert, else what the app is.
    private var statusLine: String {
        switch app.state {
        case .stopped: return Display.name(app.stopReason ?? "stopped")
        case .notDeployed: return "not deployed"
        case .starting:
            if let ready = app.ready, let desired = app.desired { return "starting · \(ready) of \(desired) ready" }
            return "starting"
        case .unknown: return "state not read"
        case .running: break
        }
        if let alert { return Display.message(alert.title) }
        return Display.name(app.role)
    }

    private var statusColor: Color {
        if let alert { return Theme.severity(alert.severity).opacity(0.9) }
        switch app.state {
        case .stopped: return Theme.critical.opacity(0.9)
        case .starting: return Theme.warning
        case .notDeployed, .unknown: return Theme.secondaryText
        case .running: break
        }
        if app.isIllustrative { return Theme.illustrative }
        return Theme.secondaryText
    }

    private var accessibilityText: String {
        var parts = [
            Display.name(app.name),
            group.isSystem ? "FarCast" : Display.name(group.namespace),
            app.isIllustrative ? "illustrative" : app.state.label,
        ]
        if let alert { parts.append(Display.message(alert.title)) }
        if app.isIllustrative { parts.append("not a deployment") }
        return parts.joined(separator: ", ")
    }
}

/// A small outlined label.
struct Pill: View {
    let text: String
    let color: Color

    var body: some View {
        Text(text)
            .font(.system(size: 10, weight: .semibold))
            .foregroundStyle(color)
            .padding(.horizontal, 7)
            .padding(.vertical, 2)
            .background(color.opacity(0.14), in: Capsule())
    }
}
