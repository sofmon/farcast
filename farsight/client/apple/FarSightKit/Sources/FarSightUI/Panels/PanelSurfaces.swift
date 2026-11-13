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
///
/// A fixed layout, never a scroll view, because the panel lies on the map
/// and every drag on it pans the map. The figures stand at the top at their
/// own height, whole, however much the notes under them say; a smaller
/// panel takes a tighter arrangement of them before it would cut one. The
/// notes — what the read could not say, then the component's own — take
/// the space left, and when they do not fit, a "more" button opens all of
/// it.
struct SystemSurface: View {
    let app: Application
    let model: WorldModel
    /// Points per world unit, so the surface scales with its panel.
    let unit: CGFloat

    var body: some View {
        let summary = SystemSummary(app: app, model: model)
        let style = SurfaceStyle(unit: unit)
        let arrangements = [(style, 2), (style.compact, 2), (style.compact, 3), (style.tight, 3)]
        // The first arrangement whose figures fit whole, with the least the
        // notes need under them: first with what the read could not say
        // whole beside the figures, then with it at the head of the notes.
        // The last is drawn whatever happens, top first.
        ViewThatFits(in: .vertical) {
            if !summary.problems.isEmpty {
                ForEach(arrangements.indices, id: \.self) { i in
                    arrangement(summary, arrangements[i].0, columns: arrangements[i].1, problemsOnTop: true)
                }
            }
            // Ids apart from the first set's: ViewThatFits needs each child's
            // to be its own.
            ForEach(arrangements.indices.map { $0 + arrangements.count }, id: \.self) { i in
                let (style, columns) = arrangements[i - arrangements.count]
                arrangement(summary, style, columns: columns, problemsOnTop: false)
            }
        }
        .padding(style.padding)
        .frame(minWidth: 0, maxWidth: .infinity, minHeight: 0, maxHeight: .infinity, alignment: .topLeading)
        .background(Theme.panel)
    }

    private func arrangement(_ summary: SystemSummary, _ style: SurfaceStyle, columns: Int, problemsOnTop: Bool) -> some View {
        let title = Display.name(app.role)
        let rest = problemsOnTop ? summary.note.map { [$0] } ?? [] : summary.lines
        return SurfaceStack(gap: style.gap) {
            SurfaceTop(title: title, summary: summary, style: style, columns: columns, problems: problemsOnTop ? summary.problems : [])
            if !rest.isEmpty {
                SurfaceNote(title: Display.name(app.name), summary: summary, problemsShown: problemsOnTop, style: style)
                    // Asked for its ideal, the notes ask only for their
                    // least, so an arrangement is chosen by its figures.
                    .frame(minHeight: 0, idealHeight: SurfaceNote.least(style), maxHeight: .infinity, alignment: .topLeading)
            }
        }
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
    /// What the read could not say about this component's part: one plain
    /// sentence per section that failed (`ProblemText`), never the CLI's
    /// message, which the instance's chip discloses once.
    var problems: [String] = []
    /// The component's own notes, under the problems.
    var note: String?
    /// For the kernel: spending, drawn as its two-part bar.
    var spending: Spending?

    /// Everything under the figures, as "more" shows it: the problems, then
    /// the notes.
    var text: String {
        lines.joined(separator: "\n")
    }

    var lines: [String] {
        problems + (note.map { [$0] } ?? [])
    }

    /// Every figure, then everything under them, as VoiceOver says the
    /// surface: what the "more" button opens, in full.
    var spoken: String {
        (facts.map { "\($0.value) \($0.label)" } + lines).joined(separator: "\n")
    }

    init(app: Application, model: WorldModel) {
        let index = model.index
        guard let instanceID = index.instanceID(ofApp: app.id), let instance = index.instances[instanceID] else { return }
        let lines = model.world.connections.filter { index.instanceID(of: $0) == instanceID }
        // The applications, without FarCast's own components: TechnoCore
        // stops applications only, and a component's state says nothing of
        // whether the apps section was read — Shrike's is what the tunnel
        // read says.
        let applications = instance.groups.filter { !$0.isSystem }.flatMap(\.apps)

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
        // instead of left out: one sentence a section, in the order the
        // sections are listed, each said once however many problems name it.
        func unread(_ sections: [SectionProblem.Section]) -> [String] {
            var said: [String] = wasRead ? [] : ["Not read yet."]
            for problem in instance.problems where sections.contains(problem.section) {
                let sentence = problem.sentence
                if !said.contains(sentence) { said.append(sentence) }
            }
            return said
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
            // A stopped app is counted only where every application's state
            // was read: one unknown could be stopped.
            let stoppedCount = applications.filter { $0.state == .stopped }.count
            let stopped: Fact = notRead(.apps) || applications.contains(where: { $0.state == .unknown })
                ? unreadFact("apps stopped")
                : Fact(value: "\(stoppedCount)", label: Plural.of(stoppedCount, "app stopped", "apps stopped"), tone: Theme.text)
            facts = [
                confirmed,
                Fact(
                    value: spending.expectedCents.map(Format.dollars) ?? "not read",
                    label: "expected, the open window",
                    tone: Theme.level(spending.level)
                ),
                limit,
                // The total's share is what enforcement compares; the
                // spending line and VoiceOver say so in full.
                Fact(
                    value: spending.level.label,
                    label: spending.fraction.map { "level · total \(Format.percent($0)) of the limit" } ?? "level",
                    tone: Theme.level(spending.level)
                ),
                stopped,
            ]
            // The floor, as the kernel records it (ADR 0009 decision 8):
            // said only where the kernel says it, and "not recorded" where
            // the kernel keeps no such record — never "no" for a silence.
            if let floor = spending.floor {
                facts.append(Fact(
                    value: floor.stillBurningMonthCents.map { "\(Format.dollars($0))/mo" } ?? "at the floor",
                    label: "still burning, every app stopped",
                    tone: Theme.critical
                ))
            } else if spending.isRead {
                facts.append(spending.atFloor == false
                    ? Fact(value: "no", label: "at the instance floor", tone: Theme.text)
                    : Fact(value: "not recorded", label: "at the instance floor", tone: Theme.secondaryText))
            }
            // What the kernel says now first, then what the meter does not
            // see (ADR 0009), then what TechnoCore does at the limit.
            var notes: [String] = []
            if let floor = spending.floor {
                let since = floor.since.map { " since \(Format.day($0)) \(Format.time($0))" } ?? ""
                let levers = floor.levers.map(Display.message).joined(separator: ", or ")
                notes.append("At the instance floor\(since): every application is stopped and spending is still over the limit."
                    + (levers.isEmpty ? "" : " What is left is to \(levers).")
                    + " TechnoCore names it and leaves it to you.")
            }
            if spending.isCheckpointStale {
                notes.append("The kernel's checkpoint is stale: these figures are older than they look.")
            }
            notes += spending.caveats.map(Display.message)
            if !spending.notMetered.isEmpty {
                notes.append("Not metered: \(spending.notMetered.map(Display.message).joined(separator: "; ")).")
            }
            notes.append("At the limit, TechnoCore stops your applications, highest cost first. It stops applications only, never FarCast's own components.")
            problems = unread([.record, .read, .spend, .figures, .apps])
            note = notes.joined(separator: "\n")
        case .boundary:
            // Counted lines and refusals come from the network section, a
            // declaration from the policy; devices coming in are the ones
            // whose line the latest read saw. A declared line is "never
            // used" only where the network was read and counted nothing on
            // it, whether or not the policy was read.
            let counted = observed.filter { $0.kind == .egress }.count
            let declared = lines.filter { $0.kind == .egress && $0.evidence == .declared }.count
            let declaredLabel = notRead(.network) ? "declared, use not read" : "declared, never used"
            let coming = distinctDevices([.tunnel, .keeper]).count
            facts = [
                notRead(.network)
                    ? unreadFact("lines out, counted")
                    : Fact(value: "\(counted)", label: Plural.of(counted, "line out, counted", "lines out, counted"), tone: Theme.observed),
                notRead(.network)
                    ? unreadFact("refused at the wall")
                    : Fact(value: "\(refused.count)", label: "refused at the wall", tone: refused.isEmpty ? Theme.text : Theme.denied),
                notRead(.policy)
                    ? unreadFact(declaredLabel)
                    : Fact(value: "\(declared)", label: declaredLabel, tone: Theme.declared),
                notReadNow(.network)
                    ? unreadFact("devices coming in")
                    : Fact(value: "\(coming)", label: Plural.of(coming, "device coming in", "devices coming in"), tone: Theme.text),
            ]
            // What the read saw and could not draw, after the reading it
            // belongs to.
            let caveats = instance.caveats.isEmpty
                ? []
                : ["What this read could not draw: " + instance.caveats.map(Display.message).joined(separator: "; ")]
            problems = unread([.network, .policy, .read])
            note = (countedBy + caveats
                + ["Application egress and your tunnel pass here. Image pulls and calls to the provider's API do not."])
                .joined(separator: "\n")
        case .monitor:
            // Shrike's figures are what it saw. Where the network was not
            // read, whether it watches was not read either. Where it was, a
            // current watch on FatLine that the read observed is itself the
            // evidence that Shrike runs and watches, whatever the apps
            // section could say of its state; without one, Shrike is "not
            // watching" only where its state was read, and "not read" where
            // it was not — never a claim from a silence.
            guard !notReadNow(.network) else {
                facts = [unreadFact("Shrike's watch on FatLine")]
                problems = unread([.network, .read])
                note = countedBy.isEmpty ? nil : countedBy.joined(separator: "\n")
                break
            }
            let watching = current.contains { $0.kind == .watch && $0.from == .app(app.id) }
            guard watching else {
                if app.state == .unknown {
                    facts = [unreadFact("Shrike's watch on FatLine")]
                    problems = unread([.apps])
                } else {
                    facts = [Fact(value: "not watching", label: "no current watch on FatLine in the snapshot", tone: Theme.secondaryText)]
                }
                note = countedBy.isEmpty ? nil : countedBy.joined(separator: "\n")
                break
            }
            let watched = observed.filter { $0.kind == .egress }.count
            facts = [
                Fact(value: "\(watched)", label: Plural.of(watched, "line watched", "lines watched"), tone: Theme.observed),
                Fact(value: "\(refused.count)", label: Plural.of(refused.count, "refusal seen", "refusals seen"), tone: refused.isEmpty ? Theme.text : Theme.denied),
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
            // counted as not read, never as needing attention — nor as not
            // needing it. With none read, how many need attention was not
            // read; with some, the count is of those read.
            let needing = keepers.filter { [.expired, .revoked, .unseen].contains($0.health) }.count
            let unreadKeepers = keepers.filter { $0.health == .unknown }.count
            let needingFact: Fact = if !wasRead || (!keepers.isEmpty && unreadKeepers == keepers.count) {
                unreadFact("keepers needing attention")
            } else {
                Fact(
                    value: "\(needing)",
                    label: Plural.of(needing, "keeper needing attention", "keepers needing attention")
                        + (unreadKeepers > 0 ? ", of those read" : ""),
                    tone: needing > 0 ? Theme.warning : Theme.text
                )
            }
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
                        ? Fact(value: "\(storing.count)", label: Plural.of(storing.count, "app storing here", "apps storing here"), tone: Theme.storage)
                        : Fact(
                            value: "\(wired.count)",
                            label: Plural.of(wired.count, "app wired to storage, not counted", "apps wired to storage, not counted"),
                            tone: Theme.storage
                        ),
                wasRead
                    ? Fact(value: "\(keepers.count)", label: Plural.of(keepers.count, "keeper", "keepers"), tone: Theme.text)
                    : unreadFact("keepers"),
                needingFact,
                sealed
                    ? Fact(value: "sealed", label: "storage", tone: Theme.critical)
                    : notReadNow(.seal)
                        ? Fact(value: "unknown", label: "seal not read", tone: Theme.secondaryText)
                        : Fact(value: "not sealed", label: "storage", tone: Theme.text),
            ]
            if unreadKeepers > 0 {
                facts.append(Fact(value: "\(unreadKeepers)", label: Plural.of(unreadKeepers, "keeper not read", "keepers not read"), tone: Theme.secondaryText))
            }
            problems = unread([.seal, .apps, .read])
            note = "The provider holds encrypted blobs under opaque names. It still sees how many there are, how large each one is, the shape of the tree, and when each is read and written. DataSphere's README lists the rest."
        case nil:
            break
        }
    }
}
