import SwiftUI

// Liquid Glass is the HUD's material: everything that floats over the map —
// the top bar, the alerts, the legend, the minimap, the app strip and the
// jump palette. Nothing on the map itself is glass; the map is content, and
// glass is for the layer that navigates it.
//
// visionOS has no `glassEffect`, `GlassEffectContainer` or glass button
// styles: there every window is glass already. The helpers below fall back to
// `glassBackgroundEffect` and the bordered styles, so the HUD is written once.

extension View {
    /// The HUD's glass in a capsule.
    func hudGlass(tint: Color? = nil, interactive: Bool = false) -> some View {
        hudGlass(tint: tint, interactive: interactive, in: Capsule())
    }

    /// The HUD's glass in `shape`, optionally tinted, optionally reacting to
    /// touch and pointer the way a control does.
    @ViewBuilder
    func hudGlass<S: InsettableShape>(tint: Color? = nil, interactive: Bool = false, in shape: S) -> some View {
        #if os(visionOS)
        glassBackgroundEffect(in: shape)
        #else
        glassEffect(Glass.regular.tint(tint).interactive(interactive), in: shape)
        #endif
    }

    /// Lets glass morph between places that share `id` inside one
    /// `HUDGlassGroup`, the way the focused chip slides along the app strip.
    @ViewBuilder
    func hudGlassID<ID: Hashable & Sendable>(_ id: ID, in namespace: Namespace.ID) -> some View {
        #if os(visionOS)
        self
        #else
        glassEffectID(id, in: namespace)
        #endif
    }

    /// A glass button, or a prominent one for the current choice.
    func hudButton(prominent: Bool = false) -> some View {
        modifier(HUDButtonStyle(prominent: prominent))
    }
}

/// Glass shapes inside one group render together, and blend and morph when
/// they come within `spacing` of each other.
struct HUDGlassGroup<Content: View>: View {
    var spacing: CGFloat = 10
    @ViewBuilder var content: Content

    var body: some View {
        #if os(visionOS)
        content
        #else
        GlassEffectContainer(spacing: spacing) { content }
        #endif
    }
}

private struct HUDButtonStyle: ViewModifier {
    let prominent: Bool

    func body(content: Content) -> some View {
        #if os(visionOS)
        if prominent {
            content.buttonStyle(.borderedProminent)
        } else {
            content.buttonStyle(.bordered)
        }
        #else
        if prominent {
            content.buttonStyle(.glassProminent)
        } else {
            content.buttonStyle(.glass)
        }
        #endif
    }
}
