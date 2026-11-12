import Foundation
import CoreGraphics

/// A camera move from one view to another.
///
/// A jump across the map flies an arc (van Wijk and Nuij, "Smooth and
/// efficient zooming and panning", 2003): it zooms out, travels, and zooms
/// back in, so the operator sees where they went instead of being cut to a
/// new place. A glide is the short coast at the end of a fling.
public struct CameraFlight: Sendable, Equatable {
    public enum Style: Sendable, Equatable {
        case arc
        case glide
    }

    public let from: Camera
    public let to: Camera
    public let style: Style
    /// Seconds.
    public let duration: TimeInterval

    private let path: Path

    private enum Path: Sendable, Equatable {
        case still
        /// Zoom on the spot: `w(t) = w0 · e^(ρ·S·t)`.
        case zoom(w0: Double, s: Double)
        /// The general arc.
        case arc(w0: Double, d: Double, r0: Double, s: Double)
        case glide
    }

    private static let rho = 2.0.squareRoot()

    public init(from: Camera, to: Camera, viewport: CGSize, style: Style = .arc) {
        self.from = from
        self.to = to
        self.style = style

        let width = Double(max(viewport.width, 1))
        let w0 = width / Double(from.scale), w1 = width / Double(to.scale)
        let dx = Double(to.center.x - from.center.x), dy = Double(to.center.y - from.center.y)
        let d2 = dx * dx + dy * dy

        if from == to {
            path = .still
            duration = 0
            return
        }
        if style == .glide {
            path = .glide
            duration = 0.45
            return
        }

        let rho = Self.rho, rho2 = rho * rho, rho4 = rho2 * rho2
        let length: Double
        if d2 < 1e-6 {
            let s = log(w1 / w0) / rho
            path = .zoom(w0: w0, s: s)
            length = abs(s)
        } else {
            let d = d2.squareRoot()
            let b0 = (w1 * w1 - w0 * w0 + rho4 * d2) / (2 * w0 * rho2 * d)
            let b1 = (w1 * w1 - w0 * w0 - rho4 * d2) / (2 * w1 * rho2 * d)
            let r0 = log((b0 * b0 + 1).squareRoot() - b0)
            let r1 = log((b1 * b1 + 1).squareRoot() - b1)
            let s = (r1 - r0) / rho
            path = .arc(w0: w0, d: d, r0: r0, s: s)
            length = abs(s)
        }
        // About a second for a long jump, never so short it reads as a cut.
        duration = min(max(0.25 * length, 0.45), 1.1)
    }

    /// The camera `progress` of the way through, 0 to 1. Time is eased here,
    /// so pass elapsed / duration.
    public func camera(at progress: Double) -> Camera {
        if progress <= 0 { return from }
        if progress >= 1 { return to }

        switch path {
        case .still:
            return to
        case .glide:
            let t = 1 - pow(1 - progress, 3)
            return interpolated(t)
        case .zoom(let w0, let s):
            let t = Self.easeInOut(progress)
            let w = w0 * exp(Self.rho * s * t)
            return Camera(center: lerp(from.center, to.center, t), scale: from.scale * CGFloat(w0 / w))
        case .arc(let w0, let d, let r0, let s):
            let t = Self.easeInOut(progress)
            let rho = Self.rho, rho2 = rho * rho
            let at = t * s
            let u = w0 / (rho2 * d) * (cosh(r0) * tanh(rho * at + r0) - sinh(r0))
            let w = w0 * cosh(r0) / cosh(rho * at + r0)
            // u is already the fraction of the way travelled (d3's
            // interpolateZoom divides by d where the paper does not).
            let fraction = CGFloat(u)
            return Camera(
                center: CGPoint(
                    x: from.center.x + (to.center.x - from.center.x) * fraction,
                    y: from.center.y + (to.center.y - from.center.y) * fraction
                ),
                scale: from.scale * CGFloat(w0 / w)
            )
        }
    }

    /// Straight interpolation, linear in the logarithm of scale so a zoom
    /// feels even all the way.
    private func interpolated(_ t: Double) -> Camera {
        let scale = exp(log(Double(from.scale)) * (1 - t) + log(Double(to.scale)) * t)
        return Camera(center: lerp(from.center, to.center, t), scale: CGFloat(scale))
    }

    private func lerp(_ a: CGPoint, _ b: CGPoint, _ t: Double) -> CGPoint {
        CGPoint(x: a.x + (b.x - a.x) * CGFloat(t), y: a.y + (b.y - a.y) * CGFloat(t))
    }

    private static func easeInOut(_ t: Double) -> Double {
        t < 0.5 ? 4 * t * t * t : 1 - pow(-2 * t + 2, 3) / 2
    }
}
