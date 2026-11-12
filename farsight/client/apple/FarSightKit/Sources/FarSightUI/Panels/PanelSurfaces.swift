import SwiftUI
import FarSightCore

/// Stands in for an app's own web UI until tiles exist (ADR 0021 decision 5):
/// the outline of a page, different per app but the same every launch.
struct PageSketch: View {
    let seed: String
    let illustrative: Bool

    var body: some View {
        let layout = Self.stableHash(seed) % 3
        Canvas { context, size in
            let unit = size.width / Metrics.panel.width
            context.fill(Path(CGRect(origin: .zero, size: size)), with: .color(Theme.page))
            let ink = GraphicsContext.Shading.color(illustrative ? Theme.illustrative.opacity(0.25) : Theme.pageInk)
            let strong = GraphicsContext.Shading.color(illustrative ? Theme.illustrative.opacity(0.4) : Theme.pageInkStrong)
            let pad = 40 * unit
            context.fill(Path(CGRect(x: 0, y: 0, width: size.width, height: 64 * unit)), with: ink)
            context.fill(
                Path(roundedRect: CGRect(x: pad, y: 20 * unit, width: 180 * unit, height: 24 * unit), cornerRadius: 6 * unit),
                with: strong
            )
            let top = 64 * unit + pad
            let height = size.height - top - pad

            switch layout {
            case 0:  // a grid of tiles
                let columns = 4, rows = 3, gap = 24 * unit
                let w = (size.width - 2 * pad - CGFloat(columns - 1) * gap) / CGFloat(columns)
                let h = (height - CGFloat(rows - 1) * gap) / CGFloat(rows)
                for r in 0..<rows {
                    for c in 0..<columns {
                        let rect = CGRect(x: pad + CGFloat(c) * (w + gap), y: top + CGFloat(r) * (h + gap), width: w, height: h)
                        context.fill(Path(roundedRect: rect, cornerRadius: 10 * unit), with: (r + c).isMultiple(of: 2) ? ink : strong)
                    }
                }
            case 1:  // a sidebar and a list
                let side = 260 * unit
                context.fill(Path(roundedRect: CGRect(x: pad, y: top, width: side, height: height), cornerRadius: 10 * unit), with: ink)
                let rowHeight = 64 * unit, gap = 18 * unit
                var y = top
                var i = 0
                while y + rowHeight <= top + height {
                    let width = (size.width - side - 3 * pad) * (i.isMultiple(of: 3) ? 0.8 : 1)
                    context.fill(
                        Path(roundedRect: CGRect(x: side + 2 * pad, y: y, width: width, height: rowHeight), cornerRadius: 8 * unit),
                        with: i.isMultiple(of: 2) ? ink : strong
                    )
                    y += rowHeight + gap
                    i += 1
                }
            default:  // a dashboard
                let gap = 24 * unit
                let cardWidth = (size.width - 2 * pad - 2 * gap) / 3
                let cardHeight = height * 0.32
                for c in 0..<3 {
                    let rect = CGRect(x: pad + CGFloat(c) * (cardWidth + gap), y: top, width: cardWidth, height: cardHeight)
                    context.fill(Path(roundedRect: rect, cornerRadius: 12 * unit), with: ink)
                }
                let chart = CGRect(x: pad, y: top + cardHeight + gap, width: size.width - 2 * pad, height: height - cardHeight - gap)
                context.fill(Path(roundedRect: chart, cornerRadius: 12 * unit), with: ink)
                var line = Path()
                for i in 0...12 {
                    let x = chart.minX + chart.width * CGFloat(i) / 12
                    let wave = sin(Double(i) * 0.9 + Double(Self.stableHash(seed) % 7))
                    let y = chart.midY - chart.height * 0.3 * CGFloat(wave)
                    if i == 0 { line.move(to: CGPoint(x: x, y: y)) } else { line.addLine(to: CGPoint(x: x, y: y)) }
                }
                context.stroke(line, with: strong, lineWidth: max(2, 6 * unit))
            }
        }
    }

    /// FNV-1a: the same layout for the same app on every launch, which
    /// `hashValue` does not promise.
    static func stableHash(_ text: String) -> Int {
        var hash: UInt64 = 0xcbf2_9ce4_8422_2325
        for byte in text.utf8 {
            hash ^= UInt64(byte)
            hash = hash &* 0x0000_0100_0000_01b3
        }
        return Int(hash % 1_000_003)
    }
}

/// A FarCast component's own surface, native rather than a web tile (ADR 0021
/// decision 6): the few facts it would lead with, drawn from the snapshot.
struct SystemSurface: View {
    let app: Application
    let model: WorldModel
    /// Points per world unit, so the surface scales with its panel.
    let unit: CGFloat

    var body: some View {
        let summary = SystemSummary(app: app, model: model)
        VStack(alignment: .leading, spacing: 30 * unit) {
            Text(app.role.uppercased())
                .font(font(20, .semibold))
                .tracking(1.5 * unit)
                .foregroundStyle(Theme.secondaryText)
            if let progress = summary.progress {
                ProgressView(value: min(progress, 1))
                    .tint(Theme.spending(progress))
            }
            Grid(alignment: .leading, horizontalSpacing: 56 * unit, verticalSpacing: 30 * unit) {
                ForEach(Array(stride(from: 0, to: summary.facts.count, by: 2)), id: \.self) { i in
                    GridRow {
                        fact(summary.facts[i])
                        if i + 1 < summary.facts.count { fact(summary.facts[i + 1]) }
                    }
                }
            }
            if let note = summary.note {
                Text(note)
                    .font(font(21))
                    .foregroundStyle(Theme.tertiaryText)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(52 * unit)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Theme.panel)
    }

    private func fact(_ fact: SystemSummary.Fact) -> some View {
        VStack(alignment: .leading, spacing: 6 * unit) {
            Text(fact.value)
                .font(font(56, .semibold, design: .rounded))
                .foregroundStyle(fact.tone)
            Text(fact.label)
                .font(font(21))
                .foregroundStyle(Theme.secondaryText)
        }
    }

    /// Sizes scale with the panel, but never below what can be read: a
    /// small panel crops its surface rather than shrinking it to dust.
    private func font(_ size: CGFloat, _ weight: Font.Weight = .regular, design: Font.Design = .default) -> Font {
        .system(size: max(size * unit, size >= 40 ? 15 : 9), weight: weight, design: design)
    }
}

/// What each FarCast component leads with, from the snapshot alone.
struct SystemSummary {
    struct Fact {
        let value: String
        let label: String
        let tone: Color
    }

    var facts: [Fact] = []
    var note: String?
    var progress: Double?

    init(app: Application, model: WorldModel) {
        let index = model.index
        guard let instanceID = index.instanceID(ofApp: app.id), let instance = index.instances[instanceID] else { return }
        let lines = model.world.connections.filter { index.instanceID(of: $0) == instanceID }
        let apps = instance.groups.flatMap(\.apps)

        // Every figure counts what the snapshot holds and no more: observed
        // lines only where a figure says "counted", distinct devices and apps
        // rather than lines, refusals only where a wall refuses.
        let observed = lines.filter { $0.evidence == .observed }
        let current = observed.filter { !$0.isStale }
        let refused = lines.filter { $0.evidence == .denied && $0.crossesWall }
        func distinctDevices(_ kinds: Set<Connection.Kind>) -> [Device] {
            let ids = Set(current.filter { kinds.contains($0.kind) }.compactMap { line -> String? in
                if case .device(let id) = line.from { return id }
                return nil
            })
            return ids.sorted().compactMap { index.devices[$0] }
        }
        switch app.system {
        case .kernel:
            let spending = instance.spending
            progress = spending.fraction
            facts = [
                Fact(value: Format.dollars(spending.expectedCents), label: "expected this month", tone: Theme.spending(spending.fraction)),
                Fact(value: Format.dollars(spending.limitCents), label: "cost limit", tone: Theme.text),
                Fact(value: Format.percent(spending.fraction), label: "of the limit", tone: Theme.spending(spending.fraction)),
                Fact(value: "\(apps.filter { $0.state == .stopped }.count)", label: "apps stopped", tone: Theme.text),
            ]
            note = "At the limit, TechnoCore stops your applications, highest cost first. It stops applications only, never FarCast's own components."
        case .boundary:
            facts = [
                Fact(value: "\(observed.filter { $0.kind == .egress }.count)", label: "lines out, counted", tone: Theme.observed),
                Fact(value: "\(refused.count)", label: "refused at the wall", tone: refused.isEmpty ? Theme.text : Theme.denied),
                Fact(value: "\(lines.filter { $0.kind == .egress && $0.evidence == .declared }.count)", label: "declared, never used", tone: Theme.declared),
                Fact(value: "\(distinctDevices([.tunnel, .keeper]).count)", label: "devices coming in", tone: Theme.text),
            ]
            note = "Application egress and your tunnel pass here. Image pulls and calls to the provider's API do not."
        case .monitor:
            // Shrike's figures are what it saw, so they stand only while it
            // runs and its watch on FatLine is observed and current.
            let watching = app.state == .running && observed.contains {
                $0.kind == .watch && $0.from == .app(app.id) && !$0.isStale
            }
            guard watching else {
                facts = [Fact(value: "not watching", label: "no current watch on FatLine in the snapshot", tone: Theme.secondaryText)]
                note = nil
                break
            }
            facts = [
                Fact(value: "\(observed.filter { $0.kind == .egress }.count)", label: "lines watched", tone: Theme.observed),
                Fact(value: "\(refused.count)", label: "refusals seen", tone: refused.isEmpty ? Theme.text : Theme.denied),
            ]
            note = refused.isEmpty ? "Nothing refused." : refused.map { line in
                let from: String = switch line.from {
                case .app(let id): index.apps[id]?.name ?? id
                case .device(let id): index.devices[id]?.name ?? id
                case .host(let id): index.hosts[id]?.name ?? id
                }
                let to: String = switch line.to {
                case .app(let id): index.apps[id]?.name ?? id
                case .device(let id): index.devices[id]?.name ?? id
                case .host(let id): index.hosts[id]?.name ?? id
                }
                return "\(from) → \(to): \(line.label)"
            }.joined(separator: "\n")
        case .storage:
            // Every keeper with a line here counts, a stale or refused one
            // included: an absent keeper is the one that needs attention.
            let keeperIDs = Set(lines.filter { $0.kind == .keeper && $0.evidence != .planned }.compactMap { line -> String? in
                if case .device(let id) = line.from { return id }
                return nil
            })
            let keepers = keeperIDs.sorted().compactMap { index.devices[$0] }
            let present = Set(distinctDevices([.keeper]).map(\.id))
            let storing = Set(observed.filter { $0.kind == .storage }.compactMap(\.from.appID))
            // Seal state is not in the snapshot; only an alert says "sealed".
            let sealed = model.world.alerts.contains { $0.appID == app.id && $0.kind == .sealed }
            facts = [
                Fact(value: "\(storing.count)", label: "apps storing here", tone: Theme.storage),
                Fact(value: "\(keepers.count)", label: "keepers", tone: Theme.text),
                Fact(
                    value: "\(keepers.filter { !$0.isHealthy || !present.contains($0.id) }.count)",
                    label: "keepers needing attention",
                    tone: keepers.contains { !$0.isHealthy || !present.contains($0.id) } ? Theme.warning : Theme.text
                ),
                sealed
                    ? Fact(value: "sealed", label: "storage", tone: Theme.critical)
                    : Fact(value: "unknown", label: "seal state, not in the snapshot", tone: Theme.secondaryText),
            ]
            note = "The provider holds encrypted blobs under opaque names. It still sees how many there are, how large each one is, the shape of the tree, and when each is read and written. DataSphere's README lists the rest."
        case nil:
            break
        }
    }
}
