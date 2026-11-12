import SwiftUI
import FarSightCore
import FarSightFixtures
import FarSightUI

/// The "farcast" app: one window, and in it the app world map. It draws the
/// fixture world until the read route exists (ADR 0021 decision 9, step 1).
@main
struct FarCastApp: App {
    var body: some Scene {
        WindowGroup("FarCast") {
            Root()
        }
        #if os(macOS)
        .windowStyle(.hiddenTitleBar)
        .defaultSize(width: 1440, height: 900)
        #endif
    }
}

private struct Root: View {
    @State private var loaded = Result { try Fixtures.world() }

    var body: some View {
        switch loaded {
        case .success(let world):
            WorldScreen(world: world, store: ArrangementStore())
        case .failure(let error):
            ContentUnavailableView(
                "The world could not be drawn",
                systemImage: "exclamationmark.triangle",
                description: Text(String(describing: error))
            )
        }
    }
}
