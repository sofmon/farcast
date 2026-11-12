import SwiftUI
import FarSightCore

/// Every app of the instance in view, by repo, in one row. A position-free way
/// to any app: tap one and the camera flies there.
struct AppStrip: View {
    let model: WorldModel
    @Namespace private var glass

    var body: some View {
        let instanceID = model.currentInstanceID
        let groups = model.world.instances.first { $0.id == instanceID }?.groups ?? []
        // The scroll view takes whatever width the bottom row leaves it; the
        // glass container goes inside it, around the chips themselves.
        ScrollView(.horizontal) {
            HUDGlassGroup(spacing: 6) {
                HStack(spacing: 6) {
                    ForEach(groups) { group in
                        // The repo's name has no glass of its own and floats
                        // over whatever the map shows under the strip — the
                        // backdrop, or an app's light page — so it carries a
                        // chip, as the map's labels do.
                        Text(group.isSystem ? "FarCast" : Display.name(group.namespace))
                            .font(.caption2.weight(.semibold))
                            .foregroundStyle(Theme.text)
                            .padding(.horizontal, 7)
                            .padding(.vertical, 3)
                            .background(Theme.chip, in: Capsule())
                            .padding(.leading, group.id == groups.first?.id ? 0 : 4)
                        ForEach(group.apps) { app in
                            chip(app)
                        }
                    }
                }
                .padding(6)
            }
        }
        .scrollIndicators(.hidden)
        .frame(minWidth: 0, maxWidth: 780)
        .fixedSize(horizontal: false, vertical: true)
        .layoutPriority(-1)
    }

    private func chip(_ app: Application) -> some View {
        let focused = model.focus == app.id
        let alert = model.alert(for: app.id)
        let dot: Color = alert.map { Theme.severity($0.severity) }
            ?? (app.isIllustrative ? Theme.illustrative : Theme.state(app.state))
        return Button {
            model.focus(on: app.id)
        } label: {
            HStack(spacing: 6) {
                Circle().fill(dot).frame(width: 6, height: 6)
                Text(Display.name(app.name))
            }
            .font(.callout.weight(focused ? .semibold : .regular))
            .padding(.horizontal, 11)
            .padding(.vertical, 6)
        }
        .buttonStyle(.plain)
        .hudGlass(tint: focused ? Theme.focus.opacity(0.55) : nil, interactive: true)
        .hudGlassID(app.id, in: glass)
        .accessibilityLabel("\(Display.name(app.name)), \(app.isIllustrative ? "illustrative" : app.state.label)\(alert.map { ", \(Display.message($0.title))" } ?? "")")
    }
}
