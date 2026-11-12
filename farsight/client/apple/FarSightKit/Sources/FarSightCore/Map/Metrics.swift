import CoreGraphics

/// Sizes on the map, in world units. At camera scale 1 a world unit is one
/// point, so a panel is drawn at the size its web UI would be laid out for.
public enum Metrics {
    /// One app's panel.
    public static let panel = CGSize(width: 1120, height: 740)
    /// Between panels inside a group.
    public static let panelGap = CGSize(width: 160, height: 160)

    /// Around a group's panels; the top band carries the group's header.
    public static let groupInset = Inset(top: 140, side: 60, bottom: 60)
    /// Between groups in an instance's standard arrangement.
    public static let groupGap = CGSize(width: 280, height: 200)
    /// Columns per instance in the standard arrangement.
    public static let columns = 2

    /// Around an instance's groups; the line drawn there is its wall.
    public static let territoryInset = Inset(top: 260, side: 160, bottom: 160)
    /// Between one instance's territory and the next.
    public static let instanceGap: CGFloat = 900

    /// Hosts stand outside an instance's right wall, where egress leaves.
    public static let host = CGSize(width: 820, height: 150)
    public static let hostOffset: CGFloat = 420
    public static let hostGap: CGFloat = 70

    /// The operator's devices stand left of every territory, where the tunnel
    /// comes in.
    public static let device = CGSize(width: 1000, height: 220)
    public static let deviceOffset: CGFloat = 640
    public static let deviceGap: CGFloat = 120

    /// How far apart two lines leave the same panel edge.
    public static let lineSpread: CGFloat = 70

    /// Dragged groups and apps land on this grid.
    public static let snap: CGFloat = 20

    public struct Inset: Sendable, Equatable {
        public var top: CGFloat
        public var side: CGFloat
        public var bottom: CGFloat
    }
}

extension CGPoint {
    /// The point on the `Metrics.snap` grid nearest to this one.
    public var snapped: CGPoint {
        CGPoint(
            x: (x / Metrics.snap).rounded() * Metrics.snap,
            y: (y / Metrics.snap).rounded() * Metrics.snap
        )
    }
}
