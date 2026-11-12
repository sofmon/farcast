import SwiftUI
import FarSightCore

/// Which lines are drawn, and what each kind of line means.
struct ConnectionLegend: View {
    @Bindable var model: WorldModel
    @State private var expanded: Bool
    /// Narrow: the filter's segments get short titles.
    let compact: Bool

    init(model: WorldModel, startsExpanded: Bool, compact: Bool = false) {
        self.model = model
        self.compact = compact
        _expanded = State(initialValue: startsExpanded)
    }

    private static let entries: [(String, Connection.Kind, Connection.Evidence)] = [
        ("counted by FatLine", .egress, .observed),
        ("declared, never used", .egress, .declared),
        ("refused at the wall", .egress, .denied),
        ("your tunnel, mutual TLS", .tunnel, .observed),
        ("keeper, keyholder route only", .keeper, .observed),
        ("storage, for the focused app", .storage, .observed),
        ("decided, not built (illustrative), e.g. app to app via FatLine", .appToApp, .planned),
    ]

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Button {
                withAnimation(.smooth(duration: 0.25)) { expanded.toggle() }
            } label: {
                HStack {
                    Text("Connections").font(.headline)
                    Spacer()
                    Image(systemName: "chevron.down")
                        .rotationEffect(.degrees(expanded ? 0 : 180))
                        .foregroundStyle(.secondary)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            Picker("Connections", selection: $model.filter) {
                Text("All").tag(ConnectionFilter.all)
                Text(compact ? "Wall" : "Boundary").tag(ConnectionFilter.boundary)
                    .accessibilityLabel("Boundary")
                Text("Inside").tag(ConnectionFilter.inside)
                Text("Off").tag(ConnectionFilter.off)
            }
            .pickerStyle(.segmented)
            .labelsHidden()

            if expanded {
                VStack(alignment: .leading, spacing: 7) {
                    ForEach(Self.entries, id: \.0) { title, kind, evidence in
                        HStack(spacing: 10) {
                            LineSwatch(style: EdgeStyle(Connection(
                                id: title, from: .app(""), to: .app(""), kind: kind, evidence: evidence, label: ""
                            )), refused: evidence == .denied)
                            .frame(width: 34, height: 12)
                            Text(title)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                .transition(OpacityTransition())
            }
        }
        .padding(14)
        // Up to 290 wide; narrower when the row beside it needs the room.
        .frame(minWidth: 0, maxWidth: 290, alignment: .leading)
        .hudGlass(in: RoundedRectangle(cornerRadius: 22, style: .continuous))
    }
}

/// A short sample of a line style.
private struct LineSwatch: View {
    let style: EdgeStyle
    let refused: Bool

    var body: some View {
        Canvas { context, size in
            var path = Path()
            path.move(to: CGPoint(x: 1, y: size.height / 2))
            path.addLine(to: CGPoint(x: size.width - (refused ? 6 : 1), y: size.height / 2))
            context.stroke(
                path,
                with: .color(style.color),
                style: StrokeStyle(lineWidth: style.width, lineCap: .round, dash: style.dash)
            )
            if refused {
                var cross = Path()
                let x = size.width - 4, y = size.height / 2
                cross.move(to: CGPoint(x: x - 3.5, y: y - 3.5))
                cross.addLine(to: CGPoint(x: x + 3.5, y: y + 3.5))
                cross.move(to: CGPoint(x: x - 3.5, y: y + 3.5))
                cross.addLine(to: CGPoint(x: x + 3.5, y: y - 3.5))
                context.stroke(cross, with: .color(style.color), style: StrokeStyle(lineWidth: 2, lineCap: .round))
            }
        }
        .accessibilityHidden(true)
    }
}
