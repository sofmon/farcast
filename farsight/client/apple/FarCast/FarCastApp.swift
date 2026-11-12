import SwiftUI
import FarSightCore
import FarSightFixtures
import FarSightUI

/// The "farcast" app. On macOS one window draws the Connected view: what the
/// operator's own `farcast` reads from their instances when they press
/// Refresh (ADR 0021 decision 9, amended 2026-11-12). Settings records and
/// confirms the tools it runs, and a second window shows the illustrative
/// world. On iPhone, iPad and Vision Pro it draws the illustrative fixture,
/// until those devices have a device leaf and the read route.
@main
struct FarCastApp: App {
    #if os(macOS)
    @State private var connected = ConnectedApp()
    #endif

    var body: some Scene {
        WindowGroup("FarCast") {
            #if os(macOS)
            ConnectedRoot(app: connected)
            #else
            FixtureRoot()
            #endif
        }
        #if os(macOS)
        .windowStyle(.hiddenTitleBar)
        .defaultSize(width: 1440, height: 900)
        #endif
        #if os(macOS)
        Window("Illustrative world", id: "illustrative") {
            FixtureRoot(marked: true)
        }
        .windowStyle(.hiddenTitleBar)
        .defaultSize(width: 1440, height: 900)
        Settings {
            CLISettingsView(app: connected)
        }
        #endif
    }
}

/// The illustrative fixture's world, kept under the fixture's own
/// arrangement key, apart from any live instance's. When `marked`, it says
/// so over the map: on macOS it shares the app with the Connected view.
private struct FixtureRoot: View {
    var marked = false
    @State private var loaded = Result { try Fixtures.world() }

    var body: some View {
        switch loaded {
        case .success(let world):
            WorldScreen(world: world, store: ArrangementStore())
                .overlay(alignment: .topLeading) {
                    if marked {
                        IllustrativeLabel()
                    }
                }
        case .failure(let error):
            ContentUnavailableView(
                "The world could not be drawn",
                systemImage: "exclamationmark.triangle",
                description: Text(String(describing: error))
            )
        }
    }
}

/// Says that nothing on this map was read from an instance.
private struct IllustrativeLabel: View {
    var body: some View {
        Label("Illustrative — nothing here is read from an instance", systemImage: "paintpalette")
            .font(.callout.weight(.medium))
            .padding(.horizontal, 14)
            .padding(.vertical, 8)
            #if os(visionOS)
            .glassBackgroundEffect(in: Capsule())
            #else
            .glassEffect(.regular, in: Capsule())
            #endif
            .padding(.top, 70)
            .padding(.leading, 16)
            .allowsHitTesting(false)
    }
}
