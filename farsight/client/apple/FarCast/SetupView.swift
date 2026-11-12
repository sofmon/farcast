#if os(macOS)
import SwiftUI
import FarSightCore

/// What a window of the Connected view shows before any paths are
/// confirmed: how to read your instances with your own `farcast`, and a way
/// to the illustrative world meanwhile. Nothing is run from here.
struct SetupView: View {
    let app: ConnectedApp
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                Text("Read your instances with your own farcast")
                    .font(.largeTitle.weight(.semibold))
                Text("FarCast draws what your own `farcast` reads, when you press Refresh. It opens no network connection itself and holds no key.")
                    .foregroundStyle(.secondary)
                VStack(alignment: .leading, spacing: 12) {
                    step(1, "Build `farcast` and this app from one commit.")
                    step(2, "Pin each instance's gcloud account from a terminal: `farcast instances pin-gcloud <instance> --account <account>`.")
                    step(3, "Confirm the paths in Settings (⌘,).")
                }
                BuildCommitStatus(appCommit: app.appCommit)
                HStack(spacing: 12) {
                    SettingsLink {
                        Text("Open Settings…")
                    }
                    .buttonStyle(.borderedProminent)
                    Button("Show the illustrative world") {
                        openWindow(id: "illustrative")
                    }
                }
            }
            .padding(48)
            .frame(maxWidth: 760, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func step(_ number: Int, _ text: LocalizedStringKey) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(verbatim: "\(number).")
                .font(.body.monospacedDigit().weight(.semibold))
                .foregroundStyle(.secondary)
            Text(text)
        }
    }
}
#endif
