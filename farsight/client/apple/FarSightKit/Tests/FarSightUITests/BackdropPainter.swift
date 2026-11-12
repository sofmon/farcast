import CoreGraphics
import CoreImage
import Foundation
import ImageIO
@testable import FarSightUI

/// Paints FarSight's backdrop, the file FarSightUI ships as backdrop.heic:
/// flowing bands of deep colour, folded like silk, that repeat seamlessly in
/// both directions so the map can tile them as far as it reaches.
///
/// It lives with the tests rather than in the app, which only reads the file.
/// To paint the file again:
///
///     FARSIGHT_PAINT_BACKDROP="$PWD/Sources/FarSightUI/Backdrop/backdrop.heic" \
///       swift test --filter BackdropTests
///
/// Seamless by construction, not by blending edges: every noise lattice wraps
/// at the tile's edge, and the warps that fold the field are themselves made
/// of wrapping noise, so the field at x = 1 is the field at x = 0.
///
/// No pixel is brighter than `cap` (relative luminance, linear Display P3).
/// The map's surfaces keep their contrast over any backdrop under
/// Backdrop.luminanceCap, so the painter holds its colours below it, with
/// headroom for the file's compression and the dither the app adds, rather
/// than trusting a palette to.
nonisolated struct BackdropPainter: Sendable {
    var seed: UInt32 = 0x0F5C_A57
    /// Lattice cells across the tile at the coarsest octave.
    var frequency = 2
    var octaves = 4
    /// Each octave's weight against the one before.
    var gain = 0.45
    /// The warps are smoother than the field they fold.
    var warpOctaves = 3
    /// How far the two warps fold the field, in tiles.
    var firstWarp = 0.9
    var secondWarp = 0.7
    /// The ceiling on relative luminance, linear Display P3: under
    /// Backdrop.luminanceCap (0.07), less what compression and dither add.
    var cap = 0.062

    // MARK: - The field

    struct Sample {
        var field: Double
        var q: (Double, Double)
        var r: (Double, Double)
    }

    /// The folded field at tile coordinates (x, y); period 1 in both.
    func sample(_ x: Double, _ y: Double) -> Sample {
        let q = (fbm(x + 0.13, y + 0.71, salt: 1, octaves: warpOctaves), fbm(x + 0.52, y + 0.29, salt: 2, octaves: warpOctaves))
        let qx = x + firstWarp * q.0, qy = y + firstWarp * q.1
        let r = (fbm(qx + 0.37, qy + 0.91, salt: 3, octaves: warpOctaves), fbm(qx + 0.83, qy + 0.17, salt: 4, octaves: warpOctaves))
        let f = fbm(x + secondWarp * r.0, y + secondWarp * r.1, salt: 5, octaves: octaves)
        return Sample(field: f, q: q, r: r)
    }

    /// Fractal noise in roughly [-1, 1], periodic with period 1.
    func fbm(_ x: Double, _ y: Double, salt: UInt32, octaves: Int) -> Double {
        var sum = 0.0, amplitude = 1.0, norm = 0.0
        var period = frequency
        for octave in 0..<octaves {
            let p = Double(period)
            sum += amplitude * noise(x * p, y * p, period: period, salt: salt &* 7919 &+ UInt32(octave))
            norm += amplitude
            amplitude *= gain
            period *= 2
        }
        return sum / norm
    }

    /// Gradient noise on a lattice that wraps every `period` cells.
    func noise(_ x: Double, _ y: Double, period: Int, salt: UInt32) -> Double {
        let fx = x.rounded(.down), fy = y.rounded(.down)
        let dx = x - fx, dy = y - fy
        let ix = Self.wrap(Int(fx), period), iy = Self.wrap(Int(fy), period)
        let jx = Self.wrap(ix + 1, period), jy = Self.wrap(iy + 1, period)
        let n00 = gradient(ix, iy, salt, dx, dy)
        let n10 = gradient(jx, iy, salt, dx - 1, dy)
        let n01 = gradient(ix, jy, salt, dx, dy - 1)
        let n11 = gradient(jx, jy, salt, dx - 1, dy - 1)
        let u = Self.fade(dx), v = Self.fade(dy)
        let a = n00 + (n10 - n00) * u
        let b = n01 + (n11 - n01) * u
        return (a + (b - a) * v) * 1.41
    }

    private func gradient(_ ix: Int, _ iy: Int, _ salt: UInt32, _ dx: Double, _ dy: Double) -> Double {
        var h = UInt32(truncatingIfNeeded: ix) &* 0x8DA6_B343
        h ^= UInt32(truncatingIfNeeded: iy) &* 0xD816_3841
        h ^= (seed ^ salt) &* 0xCB1A_B31F
        h ^= h >> 15
        h &*= 0x2C1B_3C6D
        h ^= h >> 12
        h &*= 0x297A_2D39
        h ^= h >> 15
        let g = Self.gradients[Int(h & 63)]
        return g.0 * dx + g.1 * dy
    }

    private static let gradients: [(Double, Double)] = (0..<64).map {
        let angle = Double($0) / 64 * 2 * Double.pi
        return (cos(angle), sin(angle))
    }

    private static func wrap(_ i: Int, _ period: Int) -> Int {
        let m = i % period
        return m < 0 ? m + period : m
    }

    private static func fade(_ t: Double) -> Double { t * t * t * (t * (t * 6 - 15) + 10) }

    // MARK: - Colour

    /// Gamma-encoded Display P3, each channel in [0, 1], for a sample whose
    /// field slopes by (gx, gy) per tile.
    func color(_ s: Sample, slope gx: Double, _ gy: Double) -> (Double, Double, Double) {
        // Light from the upper left catches the folds, softly.
        let light = Self.clamp((-gx * 0.6 - gy * 0.8) * 0.012, -1, 1)
        let lift = Self.smoothstep(-0.6, 0.7, s.field)
        // Sheen along the folds: thin bright bands where the field crosses
        // a contour, the way light runs along creases in silk.
        let crease = 0.5 + 0.5 * cos(2 * Double.pi * (s.field * 2.4 + 0.35 * s.r.0))
        let sheen = pow(crease, 7)
        let lightness = 0.23 + 0.16 * lift + 0.10 * sheen * (0.4 + 0.6 * lift) + 0.03 * light
        // Teal through blue and violet to magenta and crimson.
        let hue = 300 + 88 * tanh(1.3 * s.r.0 + 0.9 * s.q.1 - 0.4 * s.q.0)
        let chroma = 0.08 + 0.12 * Self.smoothstep(-0.1, 0.55, hypot(s.q.0, s.q.1) + 0.25 * lift)
        return encode(Self.capped(Self.p3(lightness: lightness, chroma: chroma, hue: hue), cap: cap))
    }

    /// Linear Display P3 for an OKLCh colour, its chroma reduced until it
    /// fits the gamut.
    static func p3(lightness: Double, chroma: Double, hue: Double) -> (Double, Double, Double) {
        let angle = hue * Double.pi / 180
        var low = 0.0, high = 1.0
        var best = linearP3(lightness, 0, 0)
        for _ in 0..<14 {
            let k = (low + high) / 2
            let c = linearP3(lightness, chroma * k * cos(angle), chroma * k * sin(angle))
            if inGamut(c) { best = c; low = k } else { high = k }
        }
        let full = linearP3(lightness, chroma * cos(angle), chroma * sin(angle))
        return inGamut(full) ? full : best
    }

    /// OKLab to linear Display P3 (Björn Ottosson's OKLab, then sRGB to P3).
    static func linearP3(_ L: Double, _ a: Double, _ b: Double) -> (Double, Double, Double) {
        let l = pow(L + 0.396_337_777_4 * a + 0.215_803_757_3 * b, 3)
        let m = pow(L - 0.105_561_345_8 * a - 0.063_854_172_8 * b, 3)
        let s = pow(L - 0.089_484_177_5 * a - 1.291_485_548_0 * b, 3)
        let r = 4.076_741_662_1 * l - 3.307_711_591_3 * m + 0.230_969_929_2 * s
        let g = -1.268_438_004_6 * l + 2.609_757_401_1 * m - 0.341_319_396_5 * s
        let bl = -0.004_196_086_3 * l - 0.703_418_614_7 * m + 1.707_614_701_0 * s
        return (
            0.822_462_1 * r + 0.177_538_0 * g,
            0.033_194_1 * r + 0.966_805_8 * g,
            0.017_082_7 * r + 0.072_397_4 * g + 0.910_519_9 * bl
        )
    }

    static func inGamut(_ c: (Double, Double, Double)) -> Bool {
        let e = 1e-9
        return c.0 >= -e && c.0 <= 1 + e && c.1 >= -e && c.1 <= 1 + e && c.2 >= -e && c.2 <= 1 + e
    }

    /// Relative luminance of linear Display P3.
    static func luminance(_ c: (Double, Double, Double)) -> Double {
        0.228_974_6 * c.0 + 0.691_738_5 * c.1 + 0.079_286_9 * c.2
    }

    /// Scaled down, hue and saturation kept, to below `cap`. Above a knee
    /// at 70% of the cap, luminance is compressed rather than clipped, so the
    /// brightest folds keep their gradation instead of flattening at the cap.
    static func capped(_ c: (Double, Double, Double), cap: Double) -> (Double, Double, Double) {
        let y = luminance(c)
        let knee = 0.7 * cap
        guard y > knee else { return c }
        let room = cap - knee
        let target = knee + room * (1 - exp(-(y - knee) / room))
        let k = target / y
        return (c.0 * k, c.1 * k, c.2 * k)
    }

    func encode(_ c: (Double, Double, Double)) -> (Double, Double, Double) {
        (Self.gamma(c.0), Self.gamma(c.1), Self.gamma(c.2))
    }

    static func gamma(_ v: Double) -> Double {
        let c = clamp(v, 0, 1)
        return c <= 0.003_130_8 ? 12.92 * c : 1.055 * pow(c, 1 / 2.4) - 0.055
    }

    static func clamp(_ v: Double, _ low: Double, _ high: Double) -> Double { min(max(v, low), high) }

    static func smoothstep(_ a: Double, _ b: Double, _ x: Double) -> Double {
        let t = clamp((x - a) / (b - a), 0, 1)
        return t * t * (3 - 2 * t)
    }

    // MARK: - Painting

    /// The tile at `side` × `side` pixels, with `margin` more on every side
    /// continuing the field past the edge: RGBA, 16 bits a channel,
    /// little-endian, gamma-encoded Display P3. Rows are painted in bands
    /// across the cores; each band reads one row and one column beyond itself
    /// on each side for the slope.
    func pixels(side: Int, margin: Int = 0) async -> [UInt8] {
        let total = side + 2 * margin
        let bandHeight = max(1, total / 64)
        let bands = (total + bandHeight - 1) / bandHeight
        let painter = self
        return await withTaskGroup(of: (Int, [UInt8]).self) { group in
            for band in 0..<bands {
                group.addTask {
                    let first = band * bandHeight - margin
                    let rows = min(bandHeight, total - band * bandHeight)
                    return (band, painter.band(rows: first..<(first + rows), side: side, margin: margin))
                }
            }
            var parts = [[UInt8]](repeating: [], count: bands)
            for await (band, bytes) in group { parts[band] = bytes }
            return parts.flatMap { $0 }
        }
    }

    /// Rows `rows` (tile pixel rows; negative and past the side lie in the
    /// margin), each from column -margin to side + margin.
    func band(rows: Range<Int>, side: Int, margin: Int) -> [UInt8] {
        let step = 1 / Double(side)
        let columns = (-margin - 1)...(side + margin)
        var fields: [[Sample]] = []
        fields.reserveCapacity(rows.count + 2)
        for row in (rows.lowerBound - 1)...rows.upperBound {
            let y = (Double(row) + 0.5) * step
            fields.append(columns.map { sample((Double($0) + 0.5) * step, y) })
        }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(rows.count * (side + 2 * margin) * 8)
        for i in 0..<rows.count {
            let above = fields[i], here = fields[i + 1], below = fields[i + 2]
            for x in 1..<(here.count - 1) {
                let gx = (here[x + 1].field - here[x - 1].field) / (2 * step)
                let gy = (below[x].field - above[x].field) / (2 * step)
                let (r, g, b) = color(here[x], slope: gx, gy)
                for v in [r, g, b, 1.0] {
                    let q = UInt16((Self.clamp(v, 0, 1) * 65535).rounded())
                    bytes.append(UInt8(q & 0xFF))
                    bytes.append(UInt8(q >> 8))
                }
            }
        }
        return bytes
    }

    /// Writes the tile as FarSight ships it: 10-bit HEIC, Display P3, so the
    /// long dark gradients keep their steps finer than 8 bits would, with
    /// Backdrop.margin of wrap on every side for the app to crop away.
    func write(side: Int, to url: URL) async throws {
        let margin = Int(Backdrop.margin)
        guard let image = await image(side: side, margin: margin),
              let space = CGColorSpace(name: CGColorSpace.displayP3) else { throw PaintError.unpainted }
        let quality = CIImageRepresentationOption(rawValue: kCGImageDestinationLossyCompressionQuality as String)
        try CIContext().writeHEIF10Representation(of: image, to: url, colorSpace: space, options: [quality: 0.9])
    }

    enum PaintError: Error {
        case unpainted
    }

    /// The tile and its margin as an image, ready to write.
    func image(side: Int, margin: Int = 0) async -> CIImage? {
        guard let space = CGColorSpace(name: CGColorSpace.displayP3) else { return nil }
        let total = side + 2 * margin
        let bytes = await pixels(side: side, margin: margin)
        return CIImage(
            bitmapData: Data(bytes),
            bytesPerRow: total * 8,
            size: CGSize(width: total, height: total),
            format: .RGBA16,
            colorSpace: space
        )
    }
}
