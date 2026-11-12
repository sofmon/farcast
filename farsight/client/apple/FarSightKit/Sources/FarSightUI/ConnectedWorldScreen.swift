import SwiftUI
import FarSightCore

/// One window's map of what a `WorldFeed` has read: the Connected view (ADR
/// 0021 decision 9, amended 2026-11-12).
///
/// The window owns its `WorldModel`, made once and kept for as long as the
/// window is open, and hands it each new world the feed composes. The feed
/// is the app's, shared by every window. Over the map: a Refresh button,
/// which is the only way a read starts; what went wrong with the listing,
/// if it did; and, when the listing succeeded with nothing in it, that
/// there are no instances on this Mac.
public struct ConnectedWorldScreen: View {
    private let feed: WorldFeed
    private let store: ArrangementStore
    @State private var model: WorldModel?

    /// `store` gives the defaults arrangements are kept in; the feed's
    /// source picks the key.
    public init(feed: WorldFeed, store: ArrangementStore = ArrangementStore()) {
        self.feed = feed
        self.store = store
    }

    public var body: some View {
        ZStack {
            if let model {
                WorldScreen(model: model)
                    .overlay(alignment: .topTrailing) {
                        FeedControls(feed: feed, model: model)
                    }
                    .overlay {
                        if feed.hasListed, feed.listingProblem == nil, feed.world.instances.isEmpty {
                            ContentUnavailableView(
                                "No instances on this Mac",
                                systemImage: "square.dashed",
                                description: Text("This Mac holds no FarCast instance's record.")
                            )
                        }
                    }
            } else {
                Theme.ground.ignoresSafeArea()
            }
        }
        .onChange(of: feed.world, initial: true) {
            if let model {
                model.update(world: feed.world)
            } else {
                model = WorldModel(world: feed.world, store: store)
            }
        }
        .task { feed.start() }
    }
}

/// Refresh, and what the listing could not do.
private struct FeedControls: View {
    let feed: WorldFeed
    let model: WorldModel

    var body: some View {
        VStack(alignment: .trailing, spacing: 8) {
            Button {
                feed.refresh()
            } label: {
                if feed.isRefreshing {
                    Label("Reading…", systemImage: "arrow.clockwise")
                } else {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
            }
            .hudButton()
            .disabled(feed.isRefreshing)
            .keyboardShortcut("r", modifiers: .command)
            .help("Read every instance now (⌘R). Nothing is read until you ask.")
            .hudRegion(model, "refresh")
            if let problem = feed.listingProblem {
                Label(
                    Display.message("Instances could not be listed: \(problem.kind.label). \(problem.message)"),
                    systemImage: "exclamationmark.triangle.fill"
                )
                .font(.callout)
                .lineLimit(3)
                .padding(.horizontal, 12)
                .padding(.vertical, 7)
                .frame(maxWidth: 420, alignment: .trailing)
                .hudGlass(tint: Theme.warning.opacity(0.4), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                .hudRegion(model, "listing problem")
            }
        }
        .padding(.top, 70)
        .padding(.trailing, 16)
    }
}
