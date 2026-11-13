import SwiftUI
import FarSightCore

/// Sizes for a FarCast component's surface. They scale with the panel, but
/// never below what can be read: a small panel takes a tighter arrangement
/// (`compact`, then `tight`) rather than shrinking its text to dust.
struct SurfaceStyle {
    /// Points per world unit.
    var unit: CGFloat
    var title: CGFloat
    var value: CGFloat
    var label: CGFloat
    var note: CGFloat
    /// Between the title, the bar, the figures and the notes.
    var gap: CGFloat
    var rowGap: CGFloat
    var columnGap: CGFloat
    /// Between a figure and its label.
    var factGap: CGFloat
    var padding: CGFloat
    var bar: CGFloat

    init(unit: CGFloat) {
        self.unit = unit
        title = max(20 * unit, 9)
        value = max(56 * unit, 15)
        label = max(21 * unit, 9)
        note = max(21 * unit, 9)
        gap = 30 * unit
        rowGap = 30 * unit
        columnGap = 56 * unit
        factGap = 6 * unit
        padding = 52 * unit
        bar = max(10 * unit, 4)
    }

    /// The same text, closer together.
    var compact: SurfaceStyle {
        var style = self
        style.gap = 16 * unit
        style.rowGap = 14 * unit
        style.columnGap = 32 * unit
        style.factGap = 2 * unit
        return style
    }

    /// The smallest a figure is drawn, for the smallest panel drawn whole.
    var tight: SurfaceStyle {
        var style = compact
        style.title = max(20 * unit, 8)
        style.value = max(56 * unit, 12)
        style.label = max(21 * unit, 8)
        style.gap = 10 * unit
        style.rowGap = 8 * unit
        style.columnGap = 24 * unit
        return style
    }

    func font(_ size: CGFloat, _ weight: Font.Weight = .regular, design: Font.Design = .default) -> Font {
        .system(size: size, weight: weight, design: design)
    }
}

/// The figures first, at their own height, and the notes under them in the
/// space left. The figures are offered the height that leaves the notes
/// their least — one line and the "more" button — so an arrangement is
/// chosen that keeps both; they are never squeezed by the notes, and never
/// centred, so nothing is cut at the top.
struct SurfaceStack: Layout {
    var gap: CGFloat

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        if let width = proposal.width, let height = proposal.height {
            return CGSize(width: width, height: height)
        }
        // Asked for its ideal: everything stacked, whole.
        let sizes = subviews.map { $0.sizeThatFits(ProposedViewSize(width: proposal.width, height: nil)) }
        let width = proposal.width ?? sizes.map(\.width).max() ?? 0
        let height = sizes.map(\.height).reduce(0, +) + gap * CGFloat(max(sizes.count - 1, 0))
        return CGSize(width: width, height: proposal.height ?? height)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        guard let top = subviews.first else { return }
        let width = bounds.width
        let rest = subviews.count > 1 ? subviews[1] : nil
        // The least the notes draw in, given no height at all.
        let reserve = rest.map { gap + $0.sizeThatFits(ProposedViewSize(width: width, height: 0)).height } ?? 0
        let offer = ProposedViewSize(width: width, height: max(bounds.height - reserve, 0))
        let topHeight = top.sizeThatFits(offer).height
        top.place(at: bounds.origin, anchor: .topLeading, proposal: offer)
        if let rest {
            let y = topHeight + gap
            rest.place(
                at: CGPoint(x: bounds.minX, y: bounds.minY + y),
                anchor: .topLeading,
                proposal: ProposedViewSize(width: width, height: max(bounds.height - y, 0))
            )
        }
    }
}

/// The component's name, its spending bar if it has one, and its figures,
/// always at their own height.
struct SurfaceTop: View {
    let title: String
    let summary: SystemSummary
    let style: SurfaceStyle
    let columns: Int
    /// What the read could not say, whole, under the figures; empty when
    /// it heads the notes instead.
    var problems: [String] = []

    var body: some View {
        VStack(alignment: .leading, spacing: style.gap) {
            Text(title.uppercased())
                .font(style.font(style.title, .semibold))
                .tracking(1.5 * style.unit)
                .foregroundStyle(Theme.secondaryText)
                .lineLimit(1)
            if let spending = summary.spending {
                SpendingBar(spending: spending)
                    .frame(height: style.bar)
            }
            FactGrid(facts: summary.facts, style: style, columns: columns)
            if !problems.isEmpty {
                Text(problems.joined(separator: "\n"))
                    .font(style.font(style.note))
                    .foregroundStyle(Theme.warning)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .fixedSize(horizontal: false, vertical: true)
    }
}

/// Figures in equal columns. A figure is never cut: one wider than its
/// column is drawn smaller, and a label wraps.
struct FactGrid: View {
    let facts: [SystemSummary.Fact]
    let style: SurfaceStyle
    let columns: Int

    var body: some View {
        VStack(alignment: .leading, spacing: style.rowGap) {
            ForEach(Array(stride(from: 0, to: facts.count, by: columns)), id: \.self) { start in
                HStack(alignment: .top, spacing: style.columnGap) {
                    ForEach(start..<(start + columns), id: \.self) { i in
                        if i < facts.count {
                            cell(facts[i])
                        } else {
                            Color.clear
                                .frame(maxWidth: .infinity, maxHeight: 0)
                        }
                    }
                }
            }
        }
    }

    private func cell(_ fact: SystemSummary.Fact) -> some View {
        VStack(alignment: .leading, spacing: style.factGap) {
            Text(fact.value)
                .font(style.font(style.value, .semibold, design: .rounded))
                .foregroundStyle(fact.tone)
                .lineLimit(1)
                .minimumScaleFactor(0.5)
            Text(fact.label)
                .font(style.font(style.label))
                .foregroundStyle(Theme.secondaryText)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// The notes under the figures: whole when they fit, else as much as fits,
/// and a "more" button that opens all of it. Problems not already shown
/// whole above come first, in the warning colour.
struct SurfaceNote: View {
    let title: String
    let summary: SystemSummary
    /// Whether the problems stand whole under the figures already.
    let problemsShown: Bool
    let style: SurfaceStyle
    @State private var showsAll = false

    /// The least the notes take: a line, and the "more" button under it.
    static func least(_ style: SurfaceStyle) -> CGFloat {
        2 * line(style) + spacing(style)
    }

    /// A line of the notes' text, with room to spare.
    static func line(_ style: SurfaceStyle) -> CGFloat {
        (style.note * 1.25).rounded(.up)
    }

    static func spacing(_ style: SurfaceStyle) -> CGFloat {
        max(6 * style.unit, 3)
    }

    var body: some View {
        ViewThatFits(in: .vertical) {
            text
            VStack(alignment: .leading, spacing: Self.spacing(style)) {
                text
                    .frame(maxHeight: .infinity, alignment: .topLeading)
                more
            }
        }
    }

    private var text: some View {
        Text(Self.styled(summary, problems: !problemsShown))
            .font(style.font(style.note))
            .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var more: some View {
        Button {
            showsAll = true
        } label: {
            Label("more", systemImage: "ellipsis.circle")
                .font(style.font(style.note, .semibold))
                .foregroundStyle(Theme.focus)
                .lineLimit(1)
        }
        .buttonStyle(.plain)
        .accessibilityLabel("Read all of \(title)'s notes")
        .popover(isPresented: $showsAll, arrowEdge: .bottom) {
            SurfaceDetail(title: title, summary: summary)
        }
    }

    /// The problems in the warning colour, then the notes in the secondary.
    static func styled(_ summary: SystemSummary, problems: Bool = true) -> AttributedString {
        var text = AttributedString()
        let parts = (problems ? summary.problems.map { ($0, Theme.warning) } : [])
            + (summary.note.map { [($0, Theme.secondaryText)] } ?? [])
        for (i, (line, color)) in parts.enumerated() {
            var run = AttributedString(i == 0 ? line : "\n" + line)
            run.swiftUI.foregroundColor = color
            text += run
        }
        return text
    }
}

/// Everything a component's surface says, at a size made for reading, apart
/// from the map: its figures, what the read could not say, and its notes,
/// every word of them. It scrolls, being off the map.
struct SurfaceDetail: View {
    let title: String
    let summary: SystemSummary

    var body: some View {
        ScrollView {
            SurfaceDetailContent(title: title, summary: summary)
        }
        .frame(idealWidth: 420, maxWidth: 420)
        .frame(minHeight: 120, idealHeight: 420, maxHeight: 560)
        .background(Theme.panel)
        .presentationBackground(Theme.panel)
        .environment(\.colorScheme, .dark)
    }
}

struct SurfaceDetailContent: View {
    let title: String
    let summary: SystemSummary

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(title)
                .font(.headline)
                .foregroundStyle(Theme.text)
            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 6) {
                ForEach(summary.facts.indices, id: \.self) { i in
                    GridRow {
                        Text(summary.facts[i].value)
                            .font(.body.weight(.semibold))
                            .foregroundStyle(summary.facts[i].tone)
                        Text(summary.facts[i].label)
                            .foregroundStyle(Theme.secondaryText)
                    }
                }
            }
            ForEach(summary.problems.indices, id: \.self) { i in
                Label {
                    Text(summary.problems[i])
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill")
                }
                .foregroundStyle(Theme.warning)
            }
            ForEach(Array((summary.note ?? "").split(separator: "\n").enumerated()), id: \.offset) { _, line in
                Text(line)
                    .foregroundStyle(Theme.text)
            }
        }
        .font(.callout)
        .fixedSize(horizontal: false, vertical: true)
        .textSelection(.enabled)
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.panel)
    }
}
