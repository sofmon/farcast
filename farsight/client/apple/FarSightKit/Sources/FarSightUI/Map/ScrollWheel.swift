#if os(macOS)
import AppKit
import SwiftUI

/// Trackpad scrolling and the mouse wheel, which SwiftUI does not hand to a
/// view that is not a scroll view. A local event monitor offers scroll events
/// to the map while the pointer is over it; the map declines those over the
/// HUD, which then scroll as usual. The view never takes clicks.
///
/// It reads neither its own nor the event's `window`: AppKit declares both as
/// unowned references without a safety check, which strict memory safety
/// refuses (ADR 0021 decision 4). A tracking area says when the pointer is
/// over the map, and the window list says which window this view is in, so a
/// second window's scrolls are left alone.
struct ScrollWheelReader: NSViewRepresentable {
    var isEnabled: Bool
    /// The delta in points, where it happened in the view, whether it came
    /// from a trackpad (precise), whether ⌘ was held, and whether it is the
    /// coasting tail of a fling. Returns whether the map took it.
    var onScroll: (CGSize, CGPoint, Bool, Bool, Bool) -> Bool

    func makeNSView(context: Context) -> MonitorView {
        let view = MonitorView()
        view.isEnabled = isEnabled
        view.onScroll = onScroll
        return view
    }

    func updateNSView(_ view: MonitorView, context: Context) {
        view.isEnabled = isEnabled
        view.onScroll = onScroll
    }

    static func dismantleNSView(_ view: MonitorView, coordinator: ()) {
        view.stop()
    }

    final class MonitorView: NSView {
        var isEnabled = true
        var onScroll: ((CGSize, CGPoint, Bool, Bool, Bool) -> Bool)?
        private var monitor: Any?
        private var tracking: NSTrackingArea?
        /// Assumed inside until the tracking area says otherwise: the map
        /// fills the window it opens in.
        private var pointerInside = true
        /// The window this view is in, once known.
        private var windowNumber: Int?

        override var isFlipped: Bool { true }

        override func hitTest(_ point: NSPoint) -> NSView? { nil }

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            // Which window this view is in, found from the window list rather
            // than from `window`, which strict memory safety refuses.
            windowNumber = NSApp.windows.first { window in
                window.contentView.map { isDescendant(of: $0) } ?? false
            }?.windowNumber
            guard monitor == nil else { return }
            monitor = NSEvent.addLocalMonitorForEvents(matching: .scrollWheel) { [weak self] event in
                guard let self, self.take(event) else { return event }
                return nil
            }
        }

        override func updateTrackingAreas() {
            super.updateTrackingAreas()
            if let tracking { removeTrackingArea(tracking) }
            let area = NSTrackingArea(
                rect: .zero,
                options: [.mouseEnteredAndExited, .activeAlways, .inVisibleRect, .assumeInside],
                owner: self,
                userInfo: nil
            )
            addTrackingArea(area)
            tracking = area
        }

        override func mouseEntered(with event: NSEvent) {
            pointerInside = true
        }

        override func mouseExited(with event: NSEvent) {
            pointerInside = false
        }

        func stop() {
            if let monitor { NSEvent.removeMonitor(monitor) }
            monitor = nil
        }

        private func take(_ event: NSEvent) -> Bool {
            // Fails closed: a scroll is taken only in a window known to be
            // this view's.
            guard isEnabled, pointerInside, let windowNumber, event.windowNumber == windowNumber else { return false }
            let point = convert(event.locationInWindow, from: nil)
            guard bounds.contains(point) else { return false }
            return onScroll?(
                CGSize(width: event.scrollingDeltaX, height: event.scrollingDeltaY),
                point,
                event.hasPreciseScrollingDeltas,
                event.modifierFlags.contains(.command),
                !event.momentumPhase.isEmpty
            ) ?? false
        }
    }
}
#endif
