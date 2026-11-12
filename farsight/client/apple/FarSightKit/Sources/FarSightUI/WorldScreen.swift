import SwiftUI
import FarSightCore

/// FarSight's one screen: the app world map, with the HUD floating over it.
/// There is no other place an app can be; to use one, the camera goes there.
public struct WorldScreen: View {
    @State private var model: WorldModel
    @State private var backdrop: Backdrop?
    #if os(iOS)
    @Environment(\.horizontalSizeClass) private var sizeClass
    @Environment(\.verticalSizeClass) private var verticalSizeClass
    #endif

    public init(model: WorldModel) {
        _model = State(initialValue: model)
    }

    /// With the backdrop already read, as the snapshot tests draw it.
    init(model: WorldModel, backdrop: Backdrop?) {
        _model = State(initialValue: model)
        _backdrop = State(initialValue: backdrop)
    }

    public init(world: World, store: ArrangementStore? = nil) {
        self.init(model: WorldModel(world: world, store: store))
    }

    public var body: some View {
        ZStack {
            WorldViewport(model: model, backdrop: backdrop)
                .ignoresSafeArea()
            HUD(model: model)
        }
        .task {
            guard backdrop == nil else { return }
            let loaded = await Backdrop.bundled()
            withAnimation(.easeOut(duration: 0.6)) { backdrop = loaded }
        }
        #if os(iOS)
        .onChange(of: [sizeClass, verticalSizeClass], initial: true) {
            model.layoutChanged(compact: sizeClass == .compact, short: verticalSizeClass == .compact)
        }
        #endif
        // Until the backdrop is read, and wherever it is not drawn.
        .background(Theme.ground)
        .preferredColorScheme(.dark)
    }
}

/// The coordinate space of the map's viewport. Drags measure in it, so a
/// panel that moves under the pointer does not move the drag with it.
enum MapSpace {
    static let name = "farsight.map"
}

/// Drag to pan, pinch to zoom, attached once to the whole viewport so it
/// never lives on a view that can vanish mid-gesture (a panel changes level
/// as the camera zooms). A child's own drag — a title bar, a group's header —
/// takes precedence over the pan; the pinch runs alongside everything.
/// `@GestureState` resets when a gesture is cancelled as well as when it
/// ends, so a cancelled gesture can never leave the camera anchored.
struct CameraGestures: ViewModifier {
    let model: WorldModel
    @GestureState private var panning = false
    @GestureState private var pinching = false

    func body(content: Content) -> some View {
        content
            .gesture(
                DragGesture(minimumDistance: 3, coordinateSpace: .named(MapSpace.name))
                    .updating($panning) { _, state, _ in state = true }
                    .onChanged { model.panChanged($0.translation) }
                    .onEnded { model.panEnded($0.translation, predicted: $0.predictedEndTranslation) }
            )
            .simultaneousGesture(
                MagnifyGesture()
                    .updating($pinching) { _, state, _ in state = true }
                    .onChanged { model.magnifyChanged($0.magnification, at: $0.startLocation) }
                    .onEnded { _ in model.magnifyEnded() }
            )
            .onChange(of: panning) { _, active in
                if !active { model.panCancelled() }
            }
            .onChange(of: pinching) { _, active in
                if !active { model.magnifyEnded() }
            }
    }
}

/// Makes a view the handle that drags a group or an app. The model holds the
/// move; the handle starts it, feeds it the pointer, and ends it however the
/// drag stops — ended, cancelled, or the handle itself gone (scrolled out of
/// view, or swapped for another level of detail).
struct MoveHandle: ViewModifier {
    let model: WorldModel
    let item: WorldModel.Movable
    /// Whether this drag asked to move yet, and whether it was let. A drag
    /// asks once: one that began during a pinch stays a drag that moves
    /// nothing, rather than starting late from a stale touch-down.
    @State private var asked = false
    @State private var started = false
    @GestureState private var moving = false

    func body(content: Content) -> some View {
        content
            .gesture(
                DragGesture(minimumDistance: 3, coordinateSpace: .named(MapSpace.name))
                    .updating($moving) { _, state, _ in state = true }
                    .onChanged { value in
                        if !asked {
                            asked = true
                            started = model.beginMove(item, at: value.startLocation)
                        }
                        if started { model.move(item, to: value.location) }
                    }
                    .onEnded { _ in finish() }
            )
            .onChange(of: moving) { _, active in
                if !active { finish() }
            }
            .onDisappear { finish() }
    }

    private func finish() {
        asked = false
        guard started else { return }
        started = false
        model.endMove(item)
    }
}

/// Reports where a piece of the HUD is, so the map leaves scrolls over it
/// alone.
struct HUDRegion: ViewModifier {
    let model: WorldModel
    let name: String

    func body(content: Content) -> some View {
        content
            .onGeometryChange(for: CGRect.self) { $0.frame(in: .global) } action: { model.hudRegions[name] = $0 }
            .onDisappear { model.hudRegions[name] = nil }
    }
}

extension View {
    func moveHandle(_ model: WorldModel, _ item: WorldModel.Movable) -> some View {
        modifier(MoveHandle(model: model, item: item))
    }

    func hudRegion(_ model: WorldModel, _ name: String) -> some View {
        modifier(HUDRegion(model: model, name: name))
    }
}
