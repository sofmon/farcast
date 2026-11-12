import CoreGraphics

/// What the viewport looks at: the world point at its centre and how many
/// screen points one world unit takes. Apps never switch; the camera moves.
public struct Camera: Sendable, Equatable {
    public var center: CGPoint
    public private(set) var scale: CGFloat

    /// From the whole of a large world down to a panel shown at twice its size.
    public static let scales: ClosedRange<CGFloat> = 0.012...2

    public init(center: CGPoint, scale: CGFloat) {
        self.center = center
        self.scale = Self.clamped(scale)
    }

    static func clamped(_ scale: CGFloat) -> CGFloat {
        guard scale.isFinite else { return scales.lowerBound }
        return min(max(scale, scales.lowerBound), scales.upperBound)
    }

    public func screen(_ point: CGPoint, in viewport: CGSize) -> CGPoint {
        CGPoint(
            x: (point.x - center.x) * scale + viewport.width / 2,
            y: (point.y - center.y) * scale + viewport.height / 2
        )
    }

    public func screen(_ rect: CGRect, in viewport: CGSize) -> CGRect {
        CGRect(origin: screen(rect.origin, in: viewport), size: CGSize(width: rect.width * scale, height: rect.height * scale))
    }

    public func world(_ point: CGPoint, in viewport: CGSize) -> CGPoint {
        CGPoint(
            x: (point.x - viewport.width / 2) / scale + center.x,
            y: (point.y - viewport.height / 2) / scale + center.y
        )
    }

    /// The part of the world the viewport shows.
    public func visibleWorld(in viewport: CGSize) -> CGRect {
        CGRect(
            x: center.x - viewport.width / 2 / scale,
            y: center.y - viewport.height / 2 / scale,
            width: viewport.width / scale,
            height: viewport.height / scale
        )
    }

    /// The camera after the content moved by `delta` screen points: the
    /// world follows the finger.
    public func panned(by delta: CGSize) -> Camera {
        Camera(center: CGPoint(x: center.x - delta.width / scale, y: center.y - delta.height / scale), scale: scale)
    }

    /// The camera after zooming by `factor`, keeping the world point under
    /// `anchor` where it is on screen.
    public func zoomed(by factor: CGFloat, keeping anchor: CGPoint, in viewport: CGSize) -> Camera {
        let pinned = world(anchor, in: viewport)
        let scale = Self.clamped(scale * factor)
        return Camera(
            center: CGPoint(
                x: pinned.x - (anchor.x - viewport.width / 2) / scale,
                y: pinned.y - (anchor.y - viewport.height / 2) / scale
            ),
            scale: scale
        )
    }

    /// The camera that shows all of `rect` in the part of the viewport the
    /// HUD leaves free, no larger than `maxScale`.
    public static func fitting(
        _ rect: CGRect,
        in viewport: CGSize,
        insets: ViewportInsets = .zero,
        margin: CGFloat = 24,
        maxScale: CGFloat = 1
    ) -> Camera {
        let width = max(viewport.width - insets.leading - insets.trailing - 2 * margin, 1)
        let height = max(viewport.height - insets.top - insets.bottom - 2 * margin, 1)
        let scale = clamped(min(width / max(rect.width, 1), height / max(rect.height, 1), maxScale))
        let free = CGPoint(x: insets.leading + margin + width / 2, y: insets.top + margin + height / 2)
        return Camera(
            center: CGPoint(
                x: rect.midX - (free.x - viewport.width / 2) / scale,
                y: rect.midY - (free.y - viewport.height / 2) / scale
            ),
            scale: scale
        )
    }
}

/// The parts of the viewport the HUD covers, in screen points.
public struct ViewportInsets: Sendable, Equatable {
    public var top: CGFloat
    public var leading: CGFloat
    public var bottom: CGFloat
    public var trailing: CGFloat

    public init(top: CGFloat, leading: CGFloat, bottom: CGFloat, trailing: CGFloat) {
        self.top = top
        self.leading = leading
        self.bottom = bottom
        self.trailing = trailing
    }

    public static let zero = ViewportInsets(top: 0, leading: 0, bottom: 0, trailing: 0)
}
