import SwiftUI
import FarSightCore

/// Everything that floats over the map, all of it Liquid Glass: instances and
/// jump along the top, alerts under them, the connection legend bottom left,
/// the app strip bottom centre, the minimap bottom right.
struct HUD: View {
    let model: WorldModel

    #if os(iOS)
    @Environment(\.horizontalSizeClass) private var sizeClass
    @Environment(\.verticalSizeClass) private var verticalSizeClass
    private var compact: Bool { sizeClass == .compact }
    /// A phone on its side: the HUD keeps only the top bar and the app
    /// strip, and the map gets the rest (WorldModel.shortInsets).
    private var short: Bool { verticalSizeClass == .compact }
    #else
    private let compact = false
    private let short = false
    #endif

    var body: some View {
        ZStack {
            VStack(spacing: 10) {
                TopBar(model: model, compact: compact, alertsInline: short)
                if !short {
                    // On a phone on its side the alerts move into the top
                    // bar as icons, so they cover nothing the camera frames.
                    AlertBar(model: model, compact: compact)
                }
                Spacer(minLength: 0)
                if short {
                    AppStrip(model: model)
                        .hudRegion(model, "app strip")
                } else if compact {
                    HStack(alignment: .bottom, spacing: 8) {
                        ConnectionLegend(model: model, startsExpanded: false, compact: true)
                            .hudRegion(model, "legend")
                            .layoutPriority(-1)
                        Minimap(model: model, size: CGSize(width: 110, height: 80))
                    }
                    AppStrip(model: model)
                        .hudRegion(model, "app strip")
                } else {
                    HStack(alignment: .bottom, spacing: 16) {
                        ConnectionLegend(model: model, startsExpanded: true)
                            .hudRegion(model, "legend")
                        Spacer(minLength: 0)
                        AppStrip(model: model)
                            .hudRegion(model, "app strip")
                        Spacer(minLength: 0)
                        Minimap(model: model, size: CGSize(width: 230, height: 160))
                    }
                }
            }
            .padding(compact ? 10 : 16)
            // The keyboard covers the HUD rather than shoving it up: nothing
            // moves that the operator did not move.
            .ignoresSafeArea(.keyboard)

            if model.isPalettePresented {
                JumpPalette(model: model)
                    .transition(OpacityTransition().combined(with: ScaleTransition(0.97)))
            }
        }
        .animation(.smooth(duration: 0.2), value: model.isPalettePresented)
        .background(KeyboardShortcuts(model: model))
    }
}

/// The instances, each with its spending against its limit, and the jumps
/// that do not depend on where anything is.
private struct TopBar: View {
    let model: WorldModel
    let compact: Bool
    /// The alerts, as icons in the bar, when there is no room for their row.
    let alertsInline: Bool

    var body: some View {
        HUDGlassGroup(spacing: 8) {
            HStack(spacing: 8) {
                // Each cluster reports its own region, so the gap between
                // them stays the map's for scrolling.
                HStack(spacing: 8) {
                    ForEach(model.world.instances) { instance in
                        Button {
                            model.fly(to: .instance(instance.id))
                        } label: {
                            InstanceChip(instance: instance, compact: compact)
                        }
                        .hudButton(prominent: model.currentInstanceID == instance.id)
                    }
                }
                .hudRegion(model, "instances")
                if alertsInline, !model.alerts.isEmpty {
                    HStack(spacing: 6) {
                        ForEach(model.alerts) { alert in
                            Button {
                                model.open(alert)
                            } label: {
                                Image(systemName: AlertBar.symbol(alert.kind))
                                    .padding(8)
                            }
                            .buttonStyle(.plain)
                            .hudGlass(tint: Theme.severity(alert.severity).opacity(0.4), interactive: true)
                            .accessibilityLabel(alert.title)
                        }
                    }
                    .hudRegion(model, "alerts")
                }
                Spacer(minLength: 8)
                HStack(spacing: 8) {
                Button {
                    model.focus = nil
                    model.fly(to: .world)
                } label: {
                    Label("World", systemImage: "globe")
                        .labelStyle(.iconOnly)
                }
                .hudButton()
                .help("Show the whole world (0)")
                Button {
                    model.isPalettePresented = true
                } label: {
                    if compact {
                        Label("Jump", systemImage: "magnifyingglass").labelStyle(.iconOnly)
                    } else {
                        Label("Jump to…", systemImage: "magnifyingglass")
                    }
                }
                .hudButton()
                .help("Jump to an app, repo or instance (⌘K)")
                }
                .hudRegion(model, "top buttons")
            }
        }
        #if os(macOS)
        .padding(.leading, 70)  // the window's traffic lights
        #endif
    }
}

private struct InstanceChip: View {
    let instance: Instance
    let compact: Bool

    var body: some View {
        let fraction = instance.spending.fraction
        HStack(spacing: 7) {
            Text(instance.id).fontWeight(.semibold)
            if !compact {
                Capsule()
                    .fill(.white.opacity(0.18))
                    .frame(width: 36, height: 5)
                    .overlay(alignment: .leading) {
                        Capsule()
                            .fill(Theme.spending(fraction))
                            .frame(width: 36 * min(max(fraction, 0), 1), height: 5)
                    }
            }
            Text(Format.percent(fraction))
                .monospacedDigit()
                .foregroundStyle(Theme.spending(fraction))
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(instance.id), expected spending at \(Format.percent(fraction)) of its cost limit")
    }
}

/// What needs looking at, most urgent first. Each flies to the app it is about.
struct AlertBar: View {
    let model: WorldModel
    let compact: Bool

    var body: some View {
        let alerts = model.alerts
        if !alerts.isEmpty {
            ViewThatFits(in: .horizontal) {
                row(alerts, titles: true)
                row(alerts, titles: false)
            }
            .frame(maxWidth: .infinity)
        }
    }

    private func row(_ alerts: [WorldAlert], titles: Bool) -> some View {
        HUDGlassGroup(spacing: 8) {
            HStack(spacing: 8) {
                ForEach(alerts) { alert in
                    Button {
                        model.open(alert)
                    } label: {
                        Label(alert.title, systemImage: Self.symbol(alert.kind))
                            .labelStyle(AlertLabelStyle(showsTitle: titles))
                            .font(.callout.weight(.medium))
                            .padding(.horizontal, 12)
                            .padding(.vertical, 7)
                    }
                    .buttonStyle(.plain)
                    .hudGlass(tint: Theme.severity(alert.severity).opacity(0.4), interactive: true)
                    .help(alert.title)
                }
            }
            .fixedSize()
            .hudRegion(model, "alerts")
        }
    }

    static func symbol(_ kind: WorldAlert.Kind) -> String {
        switch kind {
        case .cost: "dollarsign.circle.fill"
        case .sealed: "lock.fill"
        case .denied: "xmark.octagon.fill"
        }
    }
}

private struct AlertLabelStyle: LabelStyle {
    let showsTitle: Bool

    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 6) {
            configuration.icon
            if showsTitle { configuration.title }
        }
    }
}

/// The keyboard: ⌘K jumps, Esc backs out, 0 shows the world, Space goes to
/// the next alert.
private struct KeyboardShortcuts: View {
    let model: WorldModel

    var body: some View {
        ZStack {
            Button("Jump to…") { model.isPalettePresented = true }
                .keyboardShortcut("k", modifiers: .command)
            Button("Back out") { model.escape() }
                .keyboardShortcut(.escape, modifiers: [])
            Button("Whole world") {
                model.focus = nil
                model.fly(to: .world)
            }
            .keyboardShortcut("0", modifiers: [])
            .disabled(model.isPalettePresented)
            Button("Next alert") { model.openNextAlert() }
                .keyboardShortcut(.space, modifiers: [])
                .disabled(model.isPalettePresented)
        }
        .frame(width: 0, height: 0)
        .opacity(0)
        .accessibilityHidden(true)
    }
}
