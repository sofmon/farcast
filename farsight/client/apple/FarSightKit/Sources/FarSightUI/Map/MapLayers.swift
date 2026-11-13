import SwiftUI
import FarSightCore

/// Instances' walls with their two gates, and the frames of the groups
/// inside them.
struct TerritoryLayer: View {
    let geometry: WorldGeometry
    let index: WorldIndex
    /// Instances the operator has a tunnel into; only their IN gate says so.
    let tunnelled: Set<String>
    let camera: Camera
    let viewport: CGSize

    var body: some View {
        Canvas { context, size in
            let screen = CGRect(origin: .zero, size: size)
            let scale = camera.scale

            for (instanceID, territory) in geometry.territories {
                let rect = camera.screen(territory.frame, in: viewport)
                guard rect.intersects(screen) else { continue }
                let wall = Self.wall(rect, at: scale)
                context.fill(wall, with: .color(Theme.territorySurface))
                context.stroke(wall, with: .color(Theme.wall), lineWidth: min(max(10 * scale, 1.5), 4))

                for (gate, label, anchor) in [
                    (territory.inGate, tunnelled.contains(instanceID) ? "IN · your tunnel" : "IN", UnitPoint.trailing),
                    (territory.outGate, "OUT · FatLine egress", UnitPoint.leading),
                ] {
                    let p = camera.screen(gate, in: viewport)
                    let height = max(16, 150 * scale), width = min(max(36 * scale, 7), 14)
                    let notch = Capsule().path(in: CGRect(x: p.x - width / 2, y: p.y - height / 2, width: width, height: height))
                    context.fill(notch, with: .color(Theme.ground))
                    context.stroke(notch, with: .color(Theme.observed), lineWidth: 1.5)
                    if scale > 0.025 {
                        let text = context.resolve(
                            Text(label)
                                .font(.system(size: 11, weight: .semibold))
                                .foregroundStyle(Theme.observed)
                        )
                        let offset: CGFloat = anchor == .trailing ? -(width + 6) : width + 6
                        let at = CGPoint(x: p.x + offset, y: p.y - height / 2 - 8)
                        // The label stands outside the wall, on the open
                        // backdrop, so it gets a chip of its own.
                        let size = text.measure(in: CGSize(width: 400, height: 40))
                        let left = anchor == .trailing ? at.x - size.width : at.x
                        let chip = CGRect(x: left - 7, y: at.y - size.height / 2 - 3, width: size.width + 14, height: size.height + 6)
                        context.fill(Capsule().path(in: chip), with: .color(Theme.chip))
                        context.draw(text, at: at, anchor: anchor)
                    }
                }
            }

            for (id, group) in geometry.groups {
                let rect = camera.screen(group.frame, in: viewport)
                guard rect.intersects(screen) else { continue }
                let info = index.groups[id]
                let frame = RoundedRectangle(cornerRadius: max(3, 44 * scale), style: .continuous).path(in: rect)
                context.fill(frame, with: .color(Theme.groupSurface))
                let illustrative = info?.isIllustrative ?? false
                let stroke = illustrative ? Theme.illustrative.opacity(0.7)
                    : (info?.isSystem ?? false) ? Theme.systemGroupStroke : Theme.groupStroke
                context.stroke(frame, with: .color(stroke), style: StrokeStyle(lineWidth: 1.5, dash: illustrative ? [7, 5] : []))
            }
        }
    }

    /// An instance's wall drawn at `rect`. The backdrop's frosted form is cut
    /// to the same shape, and the ground's dots kept out of it.
    nonisolated static func wall(_ rect: CGRect, at scale: CGFloat) -> Path {
        RoundedRectangle(cornerRadius: max(4, 90 * scale), style: .continuous).path(in: rect)
    }
}

/// The hosts outside the walls and the operator's devices.
struct OutsideLayer: View {
    let model: WorldModel
    let camera: Camera
    let viewport: CGSize

    var body: some View {
        Canvas { context, size in
            let screen = CGRect(origin: .zero, size: size)
            for host in model.world.hosts {
                guard let world = model.geometry.hosts[host.id] else { continue }
                let rect = camera.screen(world, in: viewport)
                guard rect.intersects(screen) else { continue }
                let tone = model.hostTones[host.id] ?? .unconnected
                let (color, dash): (Color, [CGFloat]) = switch tone {
                case .used: (Theme.observed, [])
                case .refused: (Theme.denied, [])
                case .planned: (Theme.planned, [6, 4])
                case .declared: (Theme.declared, [2, 4])
                case .unconnected: (Theme.tertiaryText, [1, 5])
                }
                Self.card(context, rect, title: Display.name(host.name), note: Display.name(host.note), color: color, dash: dash, scale: camera.scale)
            }
            for device in model.world.devices {
                guard let world = model.geometry.devices[device.id] else { continue }
                let rect = camera.screen(world, in: viewport)
                guard rect.intersects(screen) else { continue }
                // A device an alert is about takes the alert's colour, as a
                // panel does; otherwise its health's. One whose health was not
                // read says so rather than passing for healthy or not.
                let alert = model.alertByDevice[device.id]
                let color = alert.map { Theme.severity($0.severity) } ?? Theme.device(device)
                let note = device.health == .unknown && device.role == .keeper
                    ? "\(Display.name(device.note)) · not read" : Display.name(device.note)
                Self.card(context, rect, title: Display.name(device.name), note: note, color: color, dash: [], scale: camera.scale)
            }
        }
    }

    private static func card(
        _ context: GraphicsContext,
        _ rect: CGRect,
        title: String,
        note: String,
        color: Color,
        dash: [CGFloat],
        scale: CGFloat
    ) {
        let shape = RoundedRectangle(cornerRadius: max(3, 30 * scale), style: .continuous).path(in: rect)
        context.fill(shape, with: .color(Theme.panel))
        context.stroke(shape, with: .color(color), style: StrokeStyle(lineWidth: 1.5, dash: dash))
        guard rect.width > 70 else { return }
        var context = context
        context.clip(to: shape)
        let size = min(max(44 * scale, 9), 16)
        let inset = min(max(30 * scale, 6), 16)
        context.draw(
            Text(title).font(.system(size: size, weight: .semibold)).foregroundStyle(Theme.text),
            at: CGPoint(x: rect.minX + inset, y: rect.minY + rect.height * 0.36),
            anchor: .leading
        )
        if rect.height > 34 {
            context.draw(
                Text(note).font(.system(size: size * 0.78)).foregroundStyle(color.opacity(0.9)),
                at: CGPoint(x: rect.minX + inset, y: rect.minY + rect.height * 0.7),
                anchor: .leading
            )
        }
    }
}

/// An instance's name and spending, above its wall, and — for an instance
/// read from a live world — when it was read and, in brief, what of the read
/// failed. Tap to frame it.
///
/// The chip never runs past its band, nor off the screen: where the whole
/// of it does not fit, it says less (`variants`). What failed outlives the
/// spending: a share from a snapshot the latest read could not renew would
/// pass for current, so the spending goes before what failed does, and what
/// failed is said at its shortest before the chip is the name alone, which
/// it keeps however small the instance is drawn — cut short, never past its
/// band. What failed is counted, never listed; the CLI's own words for it
/// are behind the chip's info button, once for the instance.
struct TerritoryLabel: View {
    let instance: Instance
    let rect: CGRect
    let scale: CGFloat
    /// The instance's most urgent alert: the chip takes its colour.
    var alert: WorldAlert? = nil
    /// Whether to say when the instance was read: only a live world is read.
    var showsReadState = false
    /// The part of the viewport the chip may stand in.
    var visible: CGRect = .infinite
    let action: () -> Void

    /// One way of saying the chip: its spending and read state, either nil
    /// when left out, and whether its name is cut short to fit.
    struct Variant: Equatable {
        var spending: String?
        var readState: String?
        var truncates = false
    }

    /// What the chip says, roomiest first. With problems: both spending
    /// parts and the read time, then the share, then what failed without
    /// the read time beside the share, then without the share, then at its
    /// shortest, then the name alone. Without problems, the spending goes
    /// last, before the name.
    static func variants(_ instance: Instance, showsReadState: Bool) -> [Variant] {
        let spending = instance.spending
        let full = Format.spending(spending), share = Format.share(spending)
        let readState = showsReadState ? Format.readState(instance) : nil
        var variants = [Variant(spending: full, readState: readState), Variant(spending: share, readState: readState)]
        if showsReadState, let brief = Format.readState(instance, brief: true) {
            variants += [Variant(spending: share, readState: brief), Variant(spending: nil, readState: brief)]
            if let headline = Format.readHeadline(instance), headline != brief {
                variants.append(Variant(spending: nil, readState: headline))
            }
        } else if readState != nil {
            variants.append(Variant(spending: share, readState: nil))
        }
        variants.append(Variant(spending: nil, readState: nil, truncates: true))
        return variants
    }

    /// The chip's type size at a scale.
    static func size(at scale: CGFloat) -> CGFloat {
        min(max(96 * scale, 13), 28)
    }

    var body: some View {
        let size = Self.size(at: scale)
        let inset = min(max(160 * scale, 10), 40)
        let height = max(rect.height, size + 12)
        let band = Self.band(rect.insetBy(dx: inset, dy: 0), within: visible)
        let variants = Self.variants(instance, showsReadState: showsReadState)
        ViewThatFits(in: .horizontal) {
            ForEach(variants.indices, id: \.self) { i in
                chip(size: size, variants[i])
            }
        }
        .accessibilityElement(children: .contain)
        .frame(width: max(band.width, 1), height: height, alignment: .leading)
        .position(x: band.midX, y: rect.maxY - height / 2)
    }

    /// Where the chip may stand: its band, cut across to what is on screen,
    /// or the band itself when none of it is. Only its width is cut; it
    /// keeps its place above the wall.
    static func band(_ band: CGRect, within visible: CGRect) -> CGRect {
        let left = max(band.minX, visible.minX), right = min(band.maxX, visible.maxX)
        return right - left < 1 ? band : CGRect(x: left, y: band.minY, width: right - left, height: band.height)
    }

    func chip(size: CGFloat, _ variant: Variant) -> some View {
        let spending = instance.spending
        let hasProblems = !instance.problems.isEmpty || instance.status == .deleting
        return HStack(alignment: .center, spacing: size * 0.45) {
            Button(action: action) {
                HStack(alignment: .firstTextBaseline, spacing: size * 0.5) {
                    Text(Display.name(instance.id))
                        .font(.system(size: size, weight: .bold))
                        .foregroundStyle(Theme.text)
                        .truncationMode(.tail)
                    if let text = variant.spending {
                        Text(text)
                            .font(.system(size: size * 0.62, weight: .medium, design: .monospaced))
                            .foregroundStyle(Theme.level(spending.level))
                    }
                    if let readState = variant.readState {
                        Text(readState)
                            .font(.system(size: size * 0.55, weight: .medium))
                            .foregroundStyle(hasProblems ? Theme.warning : Theme.secondaryText)
                    }
                }
            }
            .buttonStyle(.plain)
            .accessibilityLabel(([Display.name(instance.id), Format.spendingSpoken(spending)]
                + (showsReadState ? Format.readState(instance).map { [$0] } ?? [] : [])
                + (alert.map { [Display.message($0.title)] } ?? [])).joined(separator: ", "))
            if showsReadState, !instance.problems.isEmpty || !instance.caveats.isEmpty {
                ReadDetailsButton(instance: instance, size: size * 0.6)
                    .layoutPriority(1)
            }
        }
        .lineLimit(1)
        // Every variant but the last stands at its own width, for the
        // container to choose by; the last takes the band and cuts its name.
        .fixedSize(horizontal: !variant.truncates, vertical: true)
        // Drawn small, the chip may stand partly on the open backdrop, so it
        // carries its own ground.
        .padding(.horizontal, size * 0.45)
        .padding(.vertical, size * 0.16)
        .background(Theme.chip, in: Capsule())
        .overlay {
            if let alert {
                Capsule().strokeBorder(Theme.severity(alert.severity), lineWidth: 2)
            }
        }
    }
}

/// The info button on an instance's chip, and what it opens: each part of
/// the last read that failed, in the map's sentence and then in the CLI's
/// own words, whole; and what the read saw and could not draw. This is the
/// one place the CLI's message is shown, for the whole instance.
struct ReadDetailsButton: View {
    let instance: Instance
    let size: CGFloat
    @State private var isPresented = false

    var body: some View {
        Button {
            isPresented = true
        } label: {
            Image(systemName: "info.circle")
                .font(.system(size: size, weight: .semibold))
                .foregroundStyle(instance.problems.isEmpty ? Theme.secondaryText : Theme.warning)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help("What the last read could not do, in farcast's own words")
        .accessibilityLabel("Details of \(Display.name(instance.id))'s last read")
        .popover(isPresented: $isPresented, arrowEdge: .bottom) {
            ReadDetails(instance: instance)
        }
    }
}

/// An instance's read problems, each as the map says it and as farcast
/// said it, and its caveats. Every message is drawn through
/// `Display.message`, which escapes what could reorder or hide text. It
/// scrolls, being off the map.
struct ReadDetails: View {
    let instance: Instance

    var body: some View {
        ScrollView {
            ReadDetailsContent(instance: instance)
        }
        .frame(idealWidth: 460, maxWidth: 460)
        .frame(minHeight: 120, idealHeight: 380, maxHeight: 560)
        .background(Theme.panel)
        .presentationBackground(Theme.panel)
        .environment(\.colorScheme, .dark)
    }
}

struct ReadDetailsContent: View {
    let instance: Instance

    /// The problems by what farcast said, in the order it first said it:
    /// sections that failed for one reason — a sign-out stops every read
    /// after it — share one message, said once under their sentences.
    static func groups(_ problems: [SectionProblem]) -> [(sentences: [String], message: String)] {
        var groups: [(sentences: [String], message: String)] = []
        for problem in problems {
            if let i = groups.firstIndex(where: { $0.message == problem.message }) {
                if !groups[i].sentences.contains(problem.sentence) { groups[i].sentences.append(problem.sentence) }
            } else {
                groups.append(([problem.sentence], problem.message))
            }
        }
        return groups
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(verbatim: "\(Display.name(instance.id)): \(Format.readState(instance) ?? "")")
                .font(.headline)
                .foregroundStyle(Theme.text)
            let groups = Self.groups(instance.problems)
            ForEach(groups.indices, id: \.self) { i in
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(groups[i].sentences.indices, id: \.self) { j in
                        Text(groups[i].sentences[j])
                            .font(.callout.weight(.semibold))
                            .foregroundStyle(Theme.warning)
                    }
                    Text(verbatim: Display.message(groups[i].message))
                        .font(.caption.monospaced())
                        .foregroundStyle(Theme.secondaryText)
                        .padding(.top, 2)
                }
            }
            if !instance.caveats.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text("What this read could not draw")
                        .font(.callout.weight(.semibold))
                        .foregroundStyle(Theme.text)
                    ForEach(instance.caveats.indices, id: \.self) { i in
                        Text(verbatim: Display.message(instance.caveats[i]))
                            .font(.callout)
                            .foregroundStyle(Theme.secondaryText)
                    }
                }
            }
        }
        .fixedSize(horizontal: false, vertical: true)
        .textSelection(.enabled)
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.panel)
    }
}

/// A group's name on its top band. Drag it to move the whole group; tap it to
/// frame the group.
struct GroupHeader: View {
    let group: AppGroup
    /// The header band, on screen.
    let rect: CGRect
    /// The whole group, on screen: the header never reaches outside it.
    let frame: CGRect
    let scale: CGFloat
    let model: WorldModel

    var body: some View {
        let size = min(max(54 * scale, 11), 22)
        let height = min(max(rect.height, size + 10), frame.height)
        HStack(spacing: size * 0.6) {
            Image(systemName: group.isSystem ? "gearshape.2.fill" : "shippingbox")
                .font(.system(size: size * 0.8))
                .foregroundStyle(Theme.secondaryText)
            Text(group.isSystem ? "FarCast" : Display.name(group.namespace))
                .font(.system(size: size, weight: .semibold))
                .foregroundStyle(Theme.text)
            if rect.width > 300 {
                Text(group.isSystem ? "the OS itself, shown as apps" : Display.name(group.source))
                    .font(.system(size: size * 0.72))
                    .foregroundStyle(Theme.secondaryText)
            }
            if group.isIllustrative, rect.width > 200 {
                Text("illustrative")
                    .font(.system(size: size * 0.66, weight: .semibold))
                    .foregroundStyle(Theme.illustrative)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .overlay(Capsule().strokeBorder(Theme.illustrative.opacity(0.7)))
            }
            Spacer(minLength: 0)
        }
        .lineLimit(1)
        .padding(.horizontal, min(max(60 * scale, 6), 24))
        .frame(width: max(rect.width, 1), height: height, alignment: .leading)
        .contentShape(Rectangle())
        .moveHandle(model, .group(group.id))
        .onTapGesture { model.fly(to: .group(group.id)) }
        // Grown to stay legible when small, it grows down over its own
        // panels (which sit above it and keep their taps), never up over the
        // instance's label.
        .position(x: rect.midX, y: rect.minY + height / 2)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isButton)
        .accessibilityHint("Drag to move the group")
    }
}
