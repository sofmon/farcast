#if os(macOS)
import AppKit
import Observation
import SwiftUI
import FarSightCore
import FarSightUI

/// The Connected view's state for the whole app on macOS (ADR 0021 decision
/// 9, amended 2026-11-12): the paths the operator confirmed in Settings, and
/// the one feed every window draws.
///
/// There is a feed only while there are confirmed paths. It lists the
/// instances at launch, which reads only files on this Mac, and reads them
/// only when the operator presses Refresh. Quitting stops a read that is
/// running, and the `farcast` it started; closing a window never does.
@Observable
@MainActor
final class ConnectedApp {
    private(set) var confirmed: ConfirmedCLISettings?
    private(set) var feed: WorldFeed?
    /// This build's own commit, written into its Info.plist at build time
    /// (`FARCAST_COMMIT`); nil in a build without it, which reads nothing.
    let appCommit: String?
    /// Where this app is, symlinks resolved: no confirmed path may point
    /// inside it.
    let bundlePath: String

    @ObservationIgnored let executor = ProcessExecutor()
    @ObservationIgnored private let store = CLISettingsStore()
    @ObservationIgnored private var quitObserver: (any NSObjectProtocol)?

    init() {
        appCommit = BuildCommit.parse(Bundle.main.object(forInfoDictionaryKey: BuildCommit.infoKey) as? String)
        bundlePath = Bundle.main.bundleURL.resolvingSymlinksInPath().path(percentEncoded: false)
        confirmed = store.load()
        if let confirmed {
            feed = WorldFeed(reader: reader(for: confirmed.settings))
        }
        // Will-terminate returns straight into exit, so the read is stopped
        // here, synchronously, and with it every farcast still running.
        quitObserver = NotificationCenter.default.addObserver(
            forName: NSApplication.willTerminateNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                self?.feed?.cancel()
                self?.executor.terminateAll()
            }
        }
    }

    /// A reader of `settings`, with this app's commit, environment and
    /// executor. Settings' Check uses one before the paths are confirmed.
    func reader(for settings: CLISettings) -> CLIReader {
        CLIReader(
            settings: settings,
            appCommit: appCommit,
            parentEnvironment: ProcessInfo.processInfo.environment,
            executor: executor,
            probe: LocalFileProbe(),
            bundlePath: bundlePath
        )
    }

    /// Keeps `settings` as confirmed, and starts a new feed on them.
    func confirm(_ settings: CLISettings) {
        let next = ConfirmedCLISettings(settings: settings, confirmedAt: Date())
        store.save(next)
        confirmed = next
        feed?.cancel()
        feed = WorldFeed(reader: reader(for: settings))
    }

    /// Forgets the confirmed paths: nothing is read until paths are
    /// confirmed again.
    func forget() {
        store.clear()
        confirmed = nil
        feed?.cancel()
        feed = nil
    }
}

/// A window of the Connected view: the map of what the feed has read, or,
/// before any paths are confirmed, how to get there.
struct ConnectedRoot: View {
    let app: ConnectedApp

    var body: some View {
        if let feed = app.feed {
            // A new feed (Confirm) is a new screen, and so a new launch
            // listing.
            ConnectedWorldScreen(feed: feed)
                .id(ObjectIdentifier(feed))
        } else {
            SetupView(app: app)
        }
    }
}

/// Whether this build knows its own commit, and how to build one that does.
struct BuildCommitStatus: View {
    let appCommit: String?

    /// The documented build (the README's "Run it").
    static let command = """
        # From the checkout's root, with everything committed: the check compares HEAD.
        # Run ./check.sh before this, never after: it rebuilds this FarCast.app without the commit.
        COMMIT=$(git rev-parse HEAD | cut -c1-7)
        go build -o ./bin/farcast ./farsight/cli/cmd/farcast
        (cd farsight/client/apple && xcodebuild -project FarSight.xcodeproj -scheme FarCast \\
          -destination 'platform=macOS' -derivedDataPath .build/DerivedData build FARCAST_COMMIT="$COMMIT")
        """

    var body: some View {
        if let appCommit {
            Label {
                Text(verbatim: "This FarCast is commit \(Display.name(appCommit))")
            } icon: {
                Image(systemName: "checkmark.seal")
            }
        } else {
            VStack(alignment: .leading, spacing: 8) {
                Label {
                    Text("This FarCast was built without its commit and reads nothing. Build it with:")
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                }
                Text(verbatim: Self.command)
                    .font(.callout.monospaced())
                    .textSelection(.enabled)
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(.quaternary, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            }
        }
    }
}
#endif
