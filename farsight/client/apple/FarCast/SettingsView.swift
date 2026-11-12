#if os(macOS)
import AppKit
import SwiftUI
import UniformTypeIdentifiers
import FarSightCore

/// Settings: the paths the Connected view runs `farcast` with, confirmed
/// once (ADR 0021 decision 9, amended 2026-11-12).
///
/// The form starts from the confirmed paths, or from blank tools and the
/// two directories at their standard places: a tool path is never guessed.
/// Check runs `farcast version` and `farcast instances` on exactly this form,
/// with a reader of it; Confirm keeps the form only once that Check has
/// succeeded, and any edit after it takes Confirm away again.
struct CLISettingsView: View {
    let app: ConnectedApp

    @State private var draft: CLISettings
    @State private var checked: Checked?
    @State private var checking = false
    @State private var picking: CLISettings.Field?
    @State private var forgetting = false
    @State private var copyName = ""
    @State private var copyNote: String?

    /// The last Check: the form it ran on, and what came back. On success
    /// it keeps the reader it used, whose listing allowed the names the
    /// terminal command may be copied for.
    private struct Checked {
        var draft: CLISettings
        var outcome: Outcome

        enum Outcome {
            case listed(CLIReader, CLIListing)
            case failed(ReadFailure)
        }
    }

    init(app: ConnectedApp) {
        self.app = app
        _draft = State(initialValue: app.confirmed?.settings ?? CLISettings.suggested(home: NSHomeDirectory()))
    }

    var body: some View {
        let problems = draft.problems(probe: LocalFileProbe(), bundlePath: app.bundlePath)
        Form {
            Section {
                Text("FarCast runs only `farcast version`, `farcast instances` and `farcast world <instance>`, with flags fixed in code.")
                Text("The first two read only files on this Mac and run at launch and on Check. `world` runs only when you press Refresh.")
                Text("Each `world` reaches your instance's API server through kubectl, as the gcloud account pinned for that instance, and its FatLine tunnel, which the provider sees as traffic and none of its content.")
                Text("Nothing runs on a timer.")
            }
            .foregroundStyle(.secondary)

            Section {
                ForEach(CLISettings.Field.allCases, id: \.self) { field in
                    row(field, problem: problems.first { $0.field == field })
                }
            } header: {
                Text("Paths")
            } footer: {
                Text("Absolute paths only. The file chooser hides dotfiles: ⌘⇧. shows hidden folders, or type the path.")
            }

            Section("This build") {
                BuildCommitStatus(appCommit: app.appCommit)
            }

            Section("Check") {
                HStack {
                    Button("Check") { check() }
                        .disabled(!problems.isEmpty || checking)
                    Button("Confirm") { app.confirm(draft) }
                        .buttonStyle(.borderedProminent)
                        .disabled(!canConfirm)
                    if checking { ProgressView().controlSize(.small) }
                    Spacer()
                    Button("Forget…", role: .destructive) { forgetting = true }
                        .disabled(app.confirmed == nil)
                }
                if !problems.isEmpty {
                    Text("Check runs once every path above is fine.")
                        .foregroundStyle(.secondary)
                }
                if let checked {
                    result(checked)
                }
                if app.confirmed != nil, app.confirmed?.settings == draft {
                    Label("These are the confirmed paths.", systemImage: "checkmark.circle")
                        .foregroundStyle(.secondary)
                }
            }
        }
        .formStyle(.grouped)
        .frame(minWidth: 680, idealWidth: 720, minHeight: 560, idealHeight: 760)
        .fileImporter(
            isPresented: Binding(get: { picking != nil }, set: { if !$0 { picking = nil } }),
            allowedContentTypes: picking.map(Self.isDirectory) == true ? [.folder] : [.item]
        ) { result in
            if let field = picking, case .success(let url) = result {
                draft[keyPath: Self.path(field)] = url.path(percentEncoded: false)
            }
            picking = nil
        }
        .confirmationDialog("Forget the confirmed paths?", isPresented: $forgetting) {
            Button("Forget", role: .destructive) {
                app.forget()
                draft = CLISettings.suggested(home: NSHomeDirectory())
                checked = nil
                copyNote = nil
            }
        } message: {
            Text("FarCast will read nothing until you confirm paths again.")
        }
    }

    // MARK: - Rows

    private func row(_ field: CLISettings.Field, problem: SettingsProblem?) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(verbatim: field.title)
                    .fontWeight(.medium)
                Spacer()
                Button("Choose…") { picking = field }
            }
            TextField(field.title, text: $draft[dynamicMember: Self.path(field)], prompt: Text(verbatim: Self.isDirectory(field) ? "/absolute/path/to/directory" : "/absolute/path/to/\(field.title)"))
                .labelsHidden()
                .font(.body.monospaced())
                .textFieldStyle(.roundedBorder)
                .autocorrectionDisabled()
            if let problem {
                Label {
                    Text(verbatim: Display.message(problem.message))
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                }
                .font(.callout)
            } else {
                Label("Fine", systemImage: "checkmark.circle")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 2)
    }

    private static func path(_ field: CLISettings.Field) -> WritableKeyPath<CLISettings, String> {
        switch field {
        case .farcast: \.farcast
        case .kubectl: \.kubectl
        case .authPlugin: \.authPlugin
        case .gcloud: \.gcloud
        case .configDirectory: \.configDirectory
        case .gcloudDirectory: \.gcloudDirectory
        }
    }

    private static func isDirectory(_ field: CLISettings.Field) -> Bool {
        switch field {
        case .configDirectory, .gcloudDirectory: true
        case .farcast, .kubectl, .authPlugin, .gcloud: false
        }
    }

    // MARK: - Check

    /// Confirm needs a Check that succeeded on exactly this form.
    private var canConfirm: Bool {
        guard let checked, checked.draft == draft, case .listed = checked.outcome else { return false }
        return true
    }

    private func check() {
        let form = draft
        let reader = app.reader(for: form)
        checking = true
        copyNote = nil
        Task {
            let outcome: Checked.Outcome
            do throws(ReadFailure) {
                let listing = try await reader.listing()
                outcome = .listed(reader, listing)
                copyName = listing.instances.first { InstanceName.isReadable($0.name) }?.name ?? ""
            } catch {
                outcome = .failed(error)
            }
            checked = Checked(draft: form, outcome: outcome)
            checking = false
        }
    }

    @ViewBuilder
    private func result(_ checked: Checked) -> some View {
        switch checked.outcome {
        case .failed(let failure):
            Label {
                Text(verbatim: "\(failure.kind.label): \(Display.message(failure.message))")
            } icon: {
                Image(systemName: "xmark.octagon.fill")
                    .foregroundStyle(.red)
            }
        case .listed(let reader, let listing):
            VStack(alignment: .leading, spacing: 10) {
                Label {
                    Text(verbatim: "farcast \(Display.name(listing.stamp.version)) · commit \(Display.name(listing.stamp.commit)) — matches this build")
                } icon: {
                    Image(systemName: "checkmark.seal.fill")
                        .foregroundStyle(.green)
                }
                if checked.draft != draft {
                    Text("The paths have changed since this Check; check again to confirm them.")
                        .foregroundStyle(.secondary)
                }
                if listing.instances.isEmpty {
                    Text("This Mac holds no FarCast instance's record.")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(listing.instances) { instance in
                        HStack(alignment: .firstTextBaseline) {
                            Text(verbatim: Display.name(instance.name))
                                .font(.body.monospaced())
                            Text(verbatim: "—").foregroundStyle(.secondary)
                            pinState(instance)
                        }
                    }
                }
                copyCommand(reader, listing)
            }
        }
    }

    @ViewBuilder
    private func pinState(_ instance: InstanceListing) -> some View {
        if let problem = instance.problem {
            Text(verbatim: "\(problem.kind.label): \(Display.message(problem.message))")
                .foregroundStyle(.orange)
        } else {
            switch instance.gcloudPinned {
            case true?:
                Text("gcloud account pinned")
            case false?:
                VStack(alignment: .leading, spacing: 2) {
                    Text("no gcloud account pinned — in a terminal:")
                        .foregroundStyle(.orange)
                    Text(verbatim: "farcast instances pin-gcloud \(Display.name(instance.name)) --account <email>")
                        .font(.callout.monospaced())
                        .textSelection(.enabled)
                }
            case nil:
                Text("farcast did not say whether a gcloud account is pinned")
                    .foregroundStyle(.secondary)
            }
        }
    }

    /// The exact command a Refresh runs for one instance, for this Mac's
    /// terminal, from the reader this Check used: its listing allowed the
    /// name, where a new reader would refuse it.
    @ViewBuilder
    private func copyCommand(_ reader: CLIReader, _ listing: CLIListing) -> some View {
        let names = listing.instances.map(\.name).filter(InstanceName.isReadable)
        if !names.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Picker("Instance", selection: $copyName) {
                        ForEach(names, id: \.self) { name in
                            Text(verbatim: Display.name(name)).tag(name)
                        }
                    }
                    .fixedSize()
                    Button("Copy terminal command") { copy(reader, copyName) }
                        .disabled(!names.contains(copyName))
                }
                Text("For this Mac's terminal only: it holds home-directory paths, so never paste it anywhere shared.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                if let copyNote {
                    Text(verbatim: copyNote)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private func copy(_ reader: CLIReader, _ name: String) {
        Task {
            do throws(ReadFailure) {
                let command = try await reader.terminalCommand(for: name)
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(command, forType: .string)
                copyNote = "Copied the command that reads \(Display.name(name))."
            } catch {
                copyNote = "\(error.kind.label): \(Display.message(error.message))"
            }
        }
    }
}
#endif
