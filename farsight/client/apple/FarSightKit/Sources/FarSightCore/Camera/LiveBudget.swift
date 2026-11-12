import CoreGraphics

/// Which panels show their app live. Every other panel shows its last frame,
/// marked as such, because a frame that looks live but is not would lie.
///
/// Live costs: each live panel is a web view with its own process and its
/// own traffic through FatLine. So only panels drawn large enough to use are
/// live, nearest the middle of the viewport first, a few at most, and the
/// focused app before any other.
public enum LiveBudget {
    public static let standardBudget = 4
    /// Narrower than this on screen, a live page would be unreadable anyway.
    public static let minimumWidth: CGFloat = 480

    public static func live(
        _ candidates: [String: CGRect],
        camera: Camera,
        viewport: CGSize,
        focus: String? = nil,
        budget: Int = standardBudget,
        minimumWidth: CGFloat = minimumWidth
    ) -> Set<String> {
        guard budget > 0 else { return [] }
        let screen = CGRect(origin: .zero, size: viewport)
        let middle = CGPoint(x: viewport.width / 2, y: viewport.height / 2)
        let ranked = candidates.compactMap { id, rect -> (id: String, rank: CGFloat)? in
            let drawn = camera.screen(rect, in: viewport)
            guard drawn.width >= minimumWidth, drawn.intersects(screen) else { return nil }
            let shown = drawn.intersection(screen)
            let distance = hypot(shown.midX - middle.x, shown.midY - middle.y)
            return (id, id == focus ? -1 : distance)
        }
        .sorted { ($0.rank, $0.id) < ($1.rank, $1.id) }
        return Set(ranked.prefix(budget).map(\.id))
    }
}
