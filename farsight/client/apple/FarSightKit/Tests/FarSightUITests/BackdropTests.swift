import CoreGraphics
import CoreImage
import Foundation
import SwiftUI
import Testing
@testable import FarSightUI

/// The backdrop and what it asks of everything drawn over it.
///
/// Readability is held to one contract. A backdrop may be any colour, but no
/// brighter than Backdrop.luminanceCap; over every such colour, however a
/// surface is blended over it, the surfaces in Theme must keep WCAG contrast —
/// 4.5:1 for text, 3:1 for lines — for what `readable()` lists: connection
/// lines at full strength on the open backdrop and inside walls, their labels
/// and the gates' and instances' on chips over the backdrop, a group's text,
/// the app strip's repo names on chips over anything the map shows, and a
/// host's or device's card border against its card. So the contract is checked against every colour
/// under the cap, not only the colours of today's backdrop, and the backdrop
/// is checked against the cap on its own.
///
/// Not held to it, on purpose or as before the backdrop:
/// - outlines — an instance's wall and a group's frame, whose surface's own
///   edge, frosted and tinted against the open backdrop, also marks them, and
///   an app card's plain border (1.6:1, as on the plain ground);
/// - faded lines and labels: stale ones (0.45 and 0.6), lines dimmed by
///   another app's focus (0.16);
/// - a stopped app's faded marker (0.35) and glance card (0.75), which were
///   below these ratios on the plain ground too;
/// - the dot grid, which is decorative and kept outside the walls;
/// - the map's lines and label chips where they cross a panel's light page;
/// - the HUD's Liquid Glass, which adapts to what is under it and was
///   checked by eye on the iPad simulator, not here.
@Suite("The backdrop")
struct BackdropTests {
    // MARK: - The painter

    @Test("the painted field is seamless: each edge continues into the opposite one")
    func seamless() {
        let painter = BackdropPainter()
        for i in 0..<64 {
            let t = Double(i) / 64 + 0.003
            for (a, b) in [(painter.sample(0, t), painter.sample(1, t)), (painter.sample(t, 0), painter.sample(t, 1))] {
                #expect(abs(a.field - b.field) < 1e-9)
                #expect(abs(a.q.0 - b.q.0) < 1e-9 && abs(a.q.1 - b.q.1) < 1e-9)
                #expect(abs(a.r.0 - b.r.0) < 1e-9 && abs(a.r.1 - b.r.1) < 1e-9)
            }
        }
    }

    @Test("the painter stays under its own cap, and its cap leaves room under the backdrop's")
    func paintedUnderCap() async {
        let painter = BackdropPainter()
        #expect(painter.cap < Backdrop.luminanceCap)
        let bytes = await painter.pixels(side: 96)
        #expect(bytes.count == 96 * 96 * 8)
        var brightest = 0.0
        for i in stride(from: 0, to: bytes.count, by: 8) {
            let channel = { (k: Int) in Double(UInt16(bytes[i + k]) | UInt16(bytes[i + k + 1]) << 8) / 65535 }
            brightest = max(brightest, Light.luminanceP3(Light.linear(channel(0)), Light.linear(channel(2)), Light.linear(channel(4))))
        }
        #expect(brightest <= painter.cap + 1e-6)
        #expect(brightest > painter.cap * 0.5, "a backdrop this dark has lost its colour")
    }

    // MARK: - The shipped backdrop

    /// One test, so a repaint and every check of the file run in order on the
    /// file just written. Without FARSIGHT_PAINT_BACKDROP it checks the copy
    /// SwiftPM bundled at build time, which is the one the app reads.
    @Test("the shipped backdrop is the painter's tile, seamless across its edges, and under the cap in both forms")
    func shipped() async throws {
        let url: URL
        if let path = ProcessInfo.processInfo.environment["FARSIGHT_PAINT_BACKDROP"] {
            url = URL(fileURLWithPath: path)
            try await BackdropPainter().write(side: 4096, to: url)
        } else {
            url = try #require(Backdrop.bundledURL)
        }
        let backdrop = try #require(await Backdrop.load(from: url))
        let image = backdrop.image
        #expect(image.width == 4096 && image.height == 4096)
        #expect(backdrop.frosted.width == 1024 && backdrop.frosted.height == 1024)

        // Pixels of the file against the painter at the same points: equal
        // but for the file's compression and the dither.
        let pixels = try #require(Pixels(image))
        let painter = BackdropPainter()
        let side = 4096
        let step = 1 / Double(side)
        var total = 0.0, worst = 0.0, count = 0
        for i in 0..<200 {
            // Every fifth point on the tile's edge, where the file is most
            // likely to differ.
            let x = i % 5 == 0 ? (i % 2 == 0 ? 0 : side - 1) : (i * 1_237 + 311) % side
            let y = (i * 2_801 + 97) % side
            let at = { (dx: Int, dy: Int) in painter.sample((Double(x + dx) + 0.5) * step, (Double(y + dy) + 0.5) * step) }
            let gx = (at(1, 0).field - at(-1, 0).field) / (2 * step)
            let gy = (at(0, 1).field - at(0, -1).field) / (2 * step)
            let want = painter.color(at(0, 0), slope: gx, gy)
            let have = pixels.rgb(x, y)
            for (w, h) in [(want.0, have.0), (want.1, have.1), (want.2, have.2)] {
                let difference = abs(w * 255 - h * 255)
                total += difference
                worst = max(worst, difference)
                count += 1
            }
        }
        #expect(total / Double(count) < 1.5, "mean difference \(total / Double(count)) levels")
        #expect(worst < 6, "worst difference \(worst) levels")

        // Seamless as decoded, not only as painted. Read without the dither.
        let space = try #require(CGColorSpace(name: CGColorSpace.displayP3))
        let tile = try #require(Backdrop.tile(from: url))
        let undithered = try #require(Backdrop.render(tile, tile.extent, CIContext(), space, dither: false))
        let plain = try #require(Pixels(undithered))
        // On macOS this caught the seam the file had before its margin (a
        // step of 8 levels against 5 inside); the iOS simulator's decoder
        // hides that seam in its own texture, so there it only checks the
        // wrap is no worse than the rest.
        for across in [true, false] {
            let seam = Self.seam(plain, side: side, painter: painter, across: across)
            let direction = across ? "across" : "down"
            #expect(seam.edgeStep <= seam.insideStep + 1, "\(direction) the edge: steps \(seam.edgeStep) levels rough, inside \(seam.insideStep)")
            #expect(seam.edgeDrift <= seam.insideDrift + 1, "\(direction) the edge: \(seam.edgeDrift) levels off the painter, inside \(seam.insideDrift)")
        }

        // No pixel brighter than the cap, open or frosted.
        for (name, form) in [("open", backdrop.image), ("frosted", backdrop.frosted)] {
            let pixels = try #require(Pixels(form))
            var brightest = 0.0
            for y in 0..<form.height {
                for x in 0..<form.width {
                    let (r, g, b) = pixels.linear(x, y)
                    brightest = max(brightest, Light.luminanceP3(r, g, b))
                }
            }
            #expect(brightest <= Backdrop.luminanceCap, "\(name): brightest pixel \(brightest)")
        }
    }

    /// How the tile's wrap compares with lines inside it, as decoded.
    ///
    /// Each measure sets the edge against the roughest interior lines of the
    /// same parity in the same decode, because what a decoder does to steep
    /// gradients is not a seam. Some decoders, the iOS simulator's among them,
    /// repeat subsampled colour in pixel pairs, so a steep fold steps every
    /// other column wherever it lies. The wrap crosses one of the steepest
    /// folds, and only the inside's own steepest lines are a fair comparison.
    /// - `edgeStep`: how much rougher the step across the wrap is than the
    ///   steps on either side of it.
    /// - `edgeDrift`: how far the pixels either side of the wrap are from the
    ///   painter's.
    struct Seam {
        var edgeStep = 0.0, insideStep = 0.0, edgeDrift = 0.0, insideDrift = 0.0
    }

    static func seam(_ pixels: Pixels, side: Int, painter: BackdropPainter, across: Bool) -> Seam {
        let step = 1 / Double(side)
        // (along, at): along the line, and which column (or row) across it.
        func level(_ along: Int, _ at: Int, _ c: Int) -> Double {
            let a = (at % side + side) % side
            return across ? pixels.level(a, along, c) : pixels.level(along, a, c)
        }
        func painted(_ along: Int, _ at: Int) -> [Double] {
            let (x, y) = across ? (at, along) : (along, at)
            let s = { (dx: Int, dy: Int) in painter.sample((Double(x + dx) + 0.5) * step, (Double(y + dy) + 0.5) * step) }
            let color = painter.color(s(0, 0), slope: (s(1, 0).field - s(-1, 0).field) / (2 * step), (s(0, 1).field - s(0, -1).field) / (2 * step))
            return [color.0 * 255, color.1 * 255, color.2 * 255]
        }
        // A line falls between `at - 1` and `at`; the wrap is at 0. Inside:
        // every 16th column for the steps, every 128th for the drift, which
        // asks the painter for each pixel. All even, as the wrap is.
        var seam = Seam()
        for at in stride(from: 0, to: side, by: 16) {
            var rough = 0.0
            for along in 0..<side {
                for c in 0..<3 {
                    let wrap = level(along, at, c) - level(along, at - 1, c)
                    let before = level(along, at - 1, c) - level(along, at - 2, c)
                    let after = level(along, at + 1, c) - level(along, at, c)
                    rough = max(rough, abs(wrap - (before + after) / 2))
                }
            }
            if at == 0 { seam.edgeStep = rough } else { seam.insideStep = max(seam.insideStep, rough) }
            guard at % 128 == 0 else { continue }
            var drift = 0.0
            for along in stride(from: 3, to: side, by: 8) {
                for at in [at - 1, at] {
                    let want = painted(along, at)
                    for c in 0..<3 { drift = max(drift, abs(level(along, at, c) - want[c])) }
                }
            }
            if at == 0 { seam.edgeDrift = drift } else { seam.insideDrift = max(seam.insideDrift, drift) }
        }
        return seam
    }

    // MARK: - Readability over any backdrop under the cap

    @Test("the listed text and lines keep their contrast on every surface over any backdrop under the cap")
    func readable() {
        let backdrops = Light.colorsUnderCap(Backdrop.luminanceCap)
        #expect(backdrops.count > 500)

        // The brightest each surface can get, over every backdrop colour,
        // blended each way a renderer might blend it.
        let territory = Paint(Theme.territorySurface)
        let group = Paint(Theme.groupSurface)
        let chip = Paint(Theme.chip)
        var open = 0.0, inside = 0.0, groups = 0.0, chipped = 0.0
        for backdrop in backdrops {
            for blend in Light.Blend.allCases {
                open = max(open, Light.luminance(backdrop))
                let wall = territory.over(backdrop, in: blend)
                inside = max(inside, Light.luminance(wall))
                groups = max(groups, Light.luminance(group.over(wall, in: blend)))
                chipped = max(chipped, Light.luminance(chip.over(backdrop, in: blend)))
            }
        }
        // The app strip floats over whatever the map shows, a panel's light
        // page included, so its chips are taken over that too.
        var stripChip = chipped
        for page in [Theme.page, Theme.pageInk, Theme.pageInkStrong, Theme.panel] {
            for blend in Light.Blend.allCases {
                stripChip = max(stripChip, Light.luminance(chip.over(Paint(page).rgb, in: blend)))
            }
        }
        let card = Light.luminance(Paint(Theme.panel).rgb)

        let lines: [(String, Color)] = [
            ("observed", Theme.observed), ("declared", Theme.declared), ("denied", Theme.denied),
            ("planned", Theme.planned), ("keeper", Theme.keeper), ("unhealthy keeper", Theme.warning),
        ]
        let insideLines = lines + [("storage", Theme.storage), ("watch", Theme.watch)]
        let labels = insideLines + [
            ("text", Theme.text), ("secondary text", Theme.secondaryText),
            ("running", Theme.running), ("warning", Theme.warning), ("critical", Theme.critical),
        ]
        let groupText: [(String, Color)] = [
            ("text", Theme.text), ("secondary text", Theme.secondaryText), ("illustrative", Theme.illustrative),
        ]

        let cardBorders: [(String, Color)] = [
            ("used", Theme.observed), ("refused", Theme.denied), ("planned", Theme.planned),
            ("declared", Theme.declared), ("unconnected", Theme.tertiaryText),
            ("operator device", Theme.focus), ("keeper device", Theme.keeper), ("unhealthy device", Theme.warning),
        ]

        // Lines crossing the open backdrop: egress to hosts, tunnels and
        // keepers from devices. Lines inside a wall: all kinds. Labels on
        // chips: every line's colour, the gates', the instances' spending.
        // Text on a group: its name, source and badge. A host's or device's
        // border against its own opaque card, which is what shapes it.
        for (surface, brightest, foreground, ratio) in [
            ("open backdrop", open, lines, 3.0),
            ("an instance's surface", inside, insideLines, 3.0),
            ("a chip", chipped, labels, 4.5),
            ("a chip in the app strip", stripChip, [("repo name", Theme.text)], 4.5),
            ("a group's surface", groups, groupText, 4.5),
            ("a card", card, cardBorders, 3.0),
        ] as [(String, Double, [(String, Color)], Double)] {
            for (name, color) in foreground {
                let y = Light.luminance(Paint(color).rgb)
                let contrast = (y + 0.05) / (brightest + 0.05)
                #expect(contrast >= ratio, "\(name) on \(surface): \(contrast) against \(ratio)")
            }
        }
    }
}

// MARK: - Colour arithmetic

/// Relative luminance and blending, by the book: sRGB and Display P3 share a
/// transfer curve and a white point and differ in primaries.
enum Light {
    /// Where a surface's colour is mixed with the backdrop under it.
    enum Blend: CaseIterable {
        /// Gamma-encoded Display P3, as a P3 display composites.
        case p3
        /// Gamma-encoded extended sRGB, as wide-colour UIKit composites.
        case sRGB
        /// Linear light: the most generous to a bright backdrop.
        case linear
    }

    static func linear(_ v: Double) -> Double {
        let m = abs(v)
        let l = m <= 0.040_45 ? m / 12.92 : pow((m + 0.055) / 1.055, 2.4)
        return v < 0 ? -l : l
    }

    static func gamma(_ v: Double) -> Double {
        let m = abs(v)
        let g = m <= 0.003_130_8 ? 12.92 * m : 1.055 * pow(m, 1 / 2.4) - 0.055
        return v < 0 ? -g : g
    }

    static func luminanceP3(_ r: Double, _ g: Double, _ b: Double) -> Double {
        0.228_974_6 * r + 0.691_738_5 * g + 0.079_286_9 * b
    }

    static func p3(fromLinearSRGB c: (Double, Double, Double)) -> (Double, Double, Double) {
        (
            0.822_462_1 * c.0 + 0.177_538_0 * c.1,
            0.033_194_1 * c.0 + 0.966_805_8 * c.1,
            0.017_082_7 * c.0 + 0.072_397_4 * c.1 + 0.910_519_9 * c.2
        )
    }

    static func sRGB(fromLinearP3 c: (Double, Double, Double)) -> (Double, Double, Double) {
        (
            1.224_940_1 * c.0 - 0.224_940_4 * c.1,
            -0.042_056_9 * c.0 + 1.042_057_1 * c.1,
            -0.019_637_6 * c.0 - 0.078_636_1 * c.1 + 1.098_273_5 * c.2
        )
    }

    /// Luminance of a colour held as linear Display P3, the form every
    /// colour here is kept in whatever blend produced it.
    static func luminance(_ c: (Double, Double, Double)) -> Double {
        luminanceP3(c.0, c.1, c.2)
    }

    /// Every gamma-encoded Display P3 colour on a 1/20 grid no brighter than
    /// `cap`, as linear Display P3.
    static func colorsUnderCap(_ cap: Double) -> [(Double, Double, Double)] {
        var colors: [(Double, Double, Double)] = []
        for r in 0...20 {
            for g in 0...20 {
                for b in 0...20 {
                    let c = (linear(Double(r) / 20), linear(Double(g) / 20), linear(Double(b) / 20))
                    if luminanceP3(c.0, c.1, c.2) <= cap { colors.append(c) }
                }
            }
        }
        return colors
    }
}

/// A Theme colour, resolved, as linear Display P3 with its opacity.
struct Paint {
    let rgb: (Double, Double, Double)
    let opacity: Double

    init(_ color: Color) {
        let resolved = color.resolve(in: EnvironmentValues())
        rgb = Light.p3(fromLinearSRGB: (
            Light.linear(Double(resolved.red)),
            Light.linear(Double(resolved.green)),
            Light.linear(Double(resolved.blue))
        ))
        opacity = Double(resolved.opacity)
    }

    /// This paint laid over `under`, both linear Display P3, mixed in `blend`.
    func over(_ under: (Double, Double, Double), in blend: Light.Blend) -> (Double, Double, Double) {
        let a = opacity
        switch blend {
        case .linear:
            return (a * rgb.0 + (1 - a) * under.0, a * rgb.1 + (1 - a) * under.1, a * rgb.2 + (1 - a) * under.2)
        case .p3:
            let mix = { (top: Double, bottom: Double) in Light.linear(a * Light.gamma(top) + (1 - a) * Light.gamma(bottom)) }
            return (mix(rgb.0, under.0), mix(rgb.1, under.1), mix(rgb.2, under.2))
        case .sRGB:
            let top = Light.sRGB(fromLinearP3: rgb), bottom = Light.sRGB(fromLinearP3: under)
            let mix = { (t: Double, b: Double) in Light.linear(a * Light.gamma(t) + (1 - a) * Light.gamma(b)) }
            return Light.p3(fromLinearSRGB: (mix(top.0, bottom.0), mix(top.1, bottom.1), mix(top.2, bottom.2)))
        }
    }
}

/// An 8-bit RGBA image's pixels, read without touching memory directly.
struct Pixels {
    let bytes: [UInt8]
    let bytesPerRow: Int

    init?(_ image: CGImage) {
        guard image.bitsPerPixel == 32, image.bitsPerComponent == 8,
              image.alphaInfo == .premultipliedLast || image.alphaInfo == .last || image.alphaInfo == .noneSkipLast,
              image.colorSpace?.name == CGColorSpace.displayP3,
              let data = image.dataProvider?.data else { return nil }
        bytes = [UInt8](data as Data)
        bytesPerRow = image.bytesPerRow
    }

    /// One channel's 8-bit level, 0 to 255.
    func level(_ x: Int, _ y: Int, _ channel: Int) -> Double {
        Double(bytes[y * bytesPerRow + x * 4 + channel])
    }

    /// Gamma-encoded Display P3, each channel in [0, 1].
    func rgb(_ x: Int, _ y: Int) -> (Double, Double, Double) {
        let i = y * bytesPerRow + x * 4
        return (Double(bytes[i]) / 255, Double(bytes[i + 1]) / 255, Double(bytes[i + 2]) / 255)
    }

    /// Linear Display P3.
    func linear(_ x: Int, _ y: Int) -> (Double, Double, Double) {
        let i = y * bytesPerRow + x * 4
        return (Self.table[Int(bytes[i])], Self.table[Int(bytes[i + 1])], Self.table[Int(bytes[i + 2])])
    }

    private static let table: [Double] = (0...255).map { Light.linear(Double($0) / 255) }
}
