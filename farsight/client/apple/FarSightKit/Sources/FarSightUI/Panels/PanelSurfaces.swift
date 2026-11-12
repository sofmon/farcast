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
            Text(Display.name(app.role).uppercased())
                .font(font(20, .semibold))
                .tracking(1.5 * unit)
                .foregroundStyle(Theme.secondaryText)
            if let spending = summary.spending {
                SpendingBar(spending: spending)
                    .frame(height: max(10 * unit, 4))
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
    /// For the kernel: spending, drawn as its two-part bar.
    var spending: Spending?

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
        // What was read. The fixture is illustrative and drawn whole; a live
        // instance was read when it has a read time — one listed and never
        // read has none — and each section of it only where that section
        // did not fail. A figure whose section was not read says "not read",
        // never 0 or a state, because 0 is a claim (ADR 0021 decision 9: a
        // section that could not be read says so).
        let wasRead = model.world.source == .fixture || instance.readAt != nil
        func notRead(_ section: SectionProblem.Section) -> Bool {
            !wasRead || instance.problem(in: section) != nil
        }
        // What says how things stand now — a device coming in, Shrike
        // watching, the seal — is not read either once the latest read
        // failed: the snapshot kept is older than that.
        func notReadNow(_ section: SectionProblem.Section) -> Bool {
            notRead(section) || instance.problem(in: .read) != nil
        }
        func unreadFact(_ label: String) -> Fact {
            Fact(value: "not read", label: label, tone: Theme.secondaryText)
        }
        // What the read could not say about this component's part, said
        // instead of left out.
        func unread(_ sections: [SectionProblem.Section]) -> [String] {
            (wasRead ? [] : ["Not read yet."])
                + instance.problems.filter { sections.contains($0.section) }.map { problem in
                    Display.message("\(problem.section.rawValue) not read (\(problem.kind.label)): \(problem.message)")
                }
        }
        // Every count on the boundary and the monitor is one FatLine
        // replica's, since it started, and a floor (ADR 0022 decision 9): it
        // says so first, so no count is read as the instance's total. A live
        // instance whose network reading is missing with no problem saying
        // why says that too, rather than nothing.
        let countedBy: [String] = if let network = instance.network {
            [Format.countedBy(network)]
        } else if model.world.source == .live, instance.problem(in: .network) == nil {
            ["network not read"]
        } else {
            []
        }
        switch app.system {
        case .kernel:
            // Two figures, never one total (ADR 0009 decision 4): confirmed
            // with its date, expected for the open window, against the
            // kernel's own limit, at the kernel's level; then what the meter
            // does not see.
            let spending = instance.spending
            self.spending = spending
            let limit: Fact = if let cents = spending.limitCents {
                Fact(value: Format.dollars(cents), label: "the kernel's cost limit", tone: Theme.text)
            } else if let cents = spending.recordedLimitCents {
                Fact(value: Format.dollars(cents), label: "recorded limit; the kernel's not read", tone: Theme.secondaryText)
            } else {
                unreadFact("cost limit")
            }
            let confirmed: Fact = if spending.hasConfirmation, let cents = spending.confirmedCents {
                Fact(
                    value: Format.dollars(cents),
                    label: "confirmed\(spending.confirmedThrough.map { " through \(Format.day($0))" } ?? "")",
                    tone: Theme.text
                )
            } else if spending.isRead {
                Fact(value: "none yet", label: "no confirmation yet", tone: Theme.secondaryText)
            } else {
                unreadFact("confirmed")
            }
            // A stopped app is counted only where every app's state was
            // read: one unknown could be stopped.
            let stopped: Fact = notRead(.apps) || apps.contains(where: { $0.state == .unknown })
                ? unreadFact("apps stopped")
                : Fact(value: "\(apps.filter { $0.state == .stopped }.count)", label: "apps stopped", tone: Theme.text)
            facts = [
                confirmed,
                Fact(
                    value: spending.expectedCents.map(Format.dollars) ?? "not read",
                    label: "expected, the open window",
                    tone: Theme.level(spending.level)
                ),
                limit,
                Fact(
                    value: spending.level.label,
                    label: spending.fraction.map { "level · total \(Format.percent($0)), what enforcement compares" } ?? "level",
                    tone: Theme.level(spending.level)
                ),
                stopped,
            ]
            var lines = ["At the limit, TechnoCore stops your applications, highest cost first. It stops applications only, never FarCast's own components."]
            if spending.isCheckpointStale {
                lines.append("The kernel's checkpoint is stale: these figures are older than they look.")
            }
            lines += spending.caveats.map(Display.message)
            if !spending.notMetered.isEmpty {
                lines.append("Not metered: \(spending.notMetered.map(Display.message).joined(separator: "; ")).")
            }
            lines += unread([.record, .read, .spend, .apps])
            note = lines.joined(separator: "\n")
        case .boundary:
            // Counted lines and refusals come from the network section, a
            // declaration from the policy; devices coming in are the ones
            // whose line the latest read saw.
            facts = [
                notRead(.network)
                    ? unreadFact("lines out, counted")
                    : Fact(value: "\(observed.filter { $0.kind == .egress }.count)", label: "lines out, counted", tone: Theme.observed),
                notRead(.network)
                    ? unreadFact("refused at the wall")
                    : Fact(value: "\(refused.count)", label: "refused at the wall", tone: refused.isEmpty ? Theme.text : Theme.denied),
                notRead(.policy)
                    ? unreadFact("declared, never used")
                    : Fact(value: "\(lines.filter { $0.kind == .egress && $0.evidence == .declared }.count)", label: "declared, never used", tone: Theme.declared),
                notReadNow(.network)
                    ? unreadFact("devices coming in")
                    : Fact(value: "\(distinctDevices([.tunnel, .keeper]).count)", label: "devices coming in", tone: Theme.text),
            ]
            // What the read saw and could not draw, after the reading it
            // belongs to.
            let caveats = instance.caveats.isEmpty
                ? []
                : ["What this read could not draw: " + instance.caveats.map(Display.message).joined(separator: "; ")]
            note = (countedBy + caveats
                + ["Application egress and your tunnel pass here. Image pulls and calls to the provider's API do not."]
                + unread([.network, .policy, .read])).joined(separator: "\n")
        case .monitor:
            // Shrike's figures are what it saw, so they stand only while it
            // runs and its watch on FatLine is observed and current. Where
            // the network was not read, whether it watches was not read
            // either.
            guard !notReadNow(.network) else {
                facts = [unreadFact("Shrike's watch on FatLine")]
                note = (countedBy + unread([.network, .read])).joined(separator: "\n")
                break
            }
            let watching = app.state == .running && observed.contains {
                $0.kind == .watch && $0.from == .app(app.id) && !$0.isStale
            }
            guard watching else {
                facts = [Fact(value: "not watching", label: "no current watch on FatLine in the snapshot", tone: Theme.secondaryText)]
                note = countedBy.isEmpty ? nil : countedBy.joined(separator: "\n")
                break
            }
            facts = [
                Fact(value: "\(observed.filter { $0.kind == .egress }.count)", label: "lines watched", tone: Theme.observed),
                Fact(value: "\(refused.count)", label: "refusals seen", tone: refused.isEmpty ? Theme.text : Theme.denied),
            ]
            note = (countedBy + [refused.isEmpty ? "Nothing refused." : refused.map { line in
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
                return "\(Display.name(from)) → \(Display.name(to)): \(Display.name(line.label))"
            }.joined(separator: "\n")]).joined(separator: "\n")
        case .storage:
            // The instance's keepers: every keeper device that is its own —
            // a live world names each `<instance>/<keeper>`, with a line or
            // without one, since an unseen keeper, or one whose health was
            // not read, has none — and every keeper with a line here, a
            // stale or refused one included, which is how the fixture's
            // unprefixed keepers are found.
            let lineKeepers = lines.filter { $0.kind == .keeper && $0.evidence != .planned }.compactMap { line -> String? in
                if case .device(let id) = line.from { return id }
                return nil
            }
            let ownKeepers = model.world.devices.filter { $0.role == .keeper && $0.id.hasPrefix("\(instanceID)/") }.map(\.id)
            let keepers = Set(lineKeepers + ownKeepers).sorted().compactMap { index.devices[$0] }
            // Health alone says whether a keeper needs attention: the CLI
            // grades it from the tunnel's rows, a day at a time. A line that
            // faded, or a read that failed since, does not make a healthy
            // keeper need attention; one whose health was not read is
            // counted as not read, never as needing attention.
            let needing = keepers.filter { [.expired, .revoked, .unseen].contains($0.health) }.count
            let unreadKeepers = keepers.filter { $0.health == .unknown }.count
            // A storage line is counted only where the keyholder counted it;
            // otherwise it says an app is wired to storage, not that it
            // stores anything.
            let storageLines = lines.filter { $0.kind == .storage && $0.evidence != .planned }
            let wired = Set(storageLines.compactMap(\.from.appID))
            let storing = Set(storageLines.filter { $0.evidence == .observed }.compactMap(\.from.appID))
            // A sealed replica raises an alert. Without one, storage is "not
            // sealed" only where the seal was read, by the latest read.
            let sealed = model.world.alerts.contains { $0.subject == .app(app.id) && $0.kind == .sealed }
            facts = [
                notRead(.apps)
                    ? unreadFact("apps storing here")
                    : wired == storing
                        ? Fact(value: "\(storing.count)", label: "apps storing here", tone: Theme.storage)
                        : Fact(value: "\(wired.count)", label: "apps wired to storage, not counted", tone: Theme.storage),
                wasRead
                    ? Fact(value: "\(keepers.count)", label: "keepers", tone: Theme.text)
                    : unreadFact("keepers"),
                wasRead
                    ? Fact(value: "\(needing)", label: "keepers needing attention", tone: needing > 0 ? Theme.warning : Theme.text)
                    : unreadFact("keepers needing attention"),
                sealed
                    ? Fact(value: "sealed", label: "storage", tone: Theme.critical)
                    : notReadNow(.seal)
                        ? Fact(value: "unknown", label: "seal not read", tone: Theme.secondaryText)
                        : Fact(value: "not sealed", label: "storage", tone: Theme.text),
            ]
            if unreadKeepers > 0 {
                facts.append(Fact(value: "\(unreadKeepers)", label: unreadKeepers == 1 ? "keeper not read" : "keepers not read", tone: Theme.secondaryText))
            }
            note = (["The provider holds encrypted blobs under opaque names. It still sees how many there are, how large each one is, the shape of the tree, and when each is read and written. DataSphere's README lists the rest."]
                + unread([.seal, .apps])).joined(separator: "\n")
        case nil:
            break
        }
    }
}
