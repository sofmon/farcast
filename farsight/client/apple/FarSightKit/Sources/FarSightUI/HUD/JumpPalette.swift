import SwiftUI
import FarSightCore

/// ⌘K: type part of a name, press Return, and the camera flies there. The way
/// to an app that does not depend on remembering where it is.
struct JumpPalette: View {
    let model: WorldModel
    @State private var query = ""
    @State private var selection = 0
    @FocusState private var fieldFocused: Bool

    var body: some View {
        let results = Array(model.search(query).prefix(8))
        ZStack(alignment: .top) {
            Color.black.opacity(0.2)
                .ignoresSafeArea()
                .contentShape(Rectangle())
                .onTapGesture { model.isPalettePresented = false }

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 10) {
                    Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                    TextField("Jump to an app, repo or instance", text: $query)
                        .textFieldStyle(.plain)
                        .focused($fieldFocused)
                        .onSubmit {
                            if results.indices.contains(selection) { model.go(to: results[selection]) }
                        }
                        .onChange(of: query) { selection = 0 }
                    #if !os(visionOS)
                        .onKeyPress(.downArrow) {
                            selection = min(selection + 1, max(results.count - 1, 0))
                            return .handled
                        }
                        .onKeyPress(.upArrow) {
                            selection = max(selection - 1, 0)
                            return .handled
                        }
                    #endif
                }
                .font(.title3)
                .padding(.horizontal, 16)
                .padding(.vertical, 13)

                if !results.isEmpty {
                    Divider().padding(.horizontal, 12)
                }
                ForEach(Array(results.enumerated()), id: \.element.id) { offset, result in
                    Button {
                        model.go(to: result)
                    } label: {
                        HStack(spacing: 12) {
                            Image(systemName: result.symbol)
                                .frame(width: 20)
                                .foregroundStyle(.secondary)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(result.title).font(.body.weight(.medium))
                                Text(result.detail).font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer(minLength: 0)
                        }
                        .lineLimit(1)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 7)
                        .background(
                            offset == selection ? Color.white.opacity(0.1) : .clear,
                            in: RoundedRectangle(cornerRadius: 12, style: .continuous)
                        )
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .padding(.horizontal, 6)
                }
            }
            .padding(.bottom, 8)
            .frame(maxWidth: 540)
            .hudGlass(in: RoundedRectangle(cornerRadius: 26, style: .continuous))
            .padding(.horizontal, 16)
            .padding(.top, 96)
        }
        .onAppear { fieldFocused = true }
        #if os(macOS)
        .onExitCommand { model.isPalettePresented = false }
        #endif
    }
}
