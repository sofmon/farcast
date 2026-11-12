import Foundation
import Observation
import SwiftUI
import FarSightCore

/// One world on screen: the snapshot, where the operator has put things, and
/// where the camera looks. Views read it; gestures and the HUD change it.
///
/// Each window owns one. A live world changes under it as reads land
/// (`update(world:)`); the model's identity never changes for one screen.
@Observable
public final class WorldModel {
    public private(set) var world: World
    public private(set) var index: WorldIndex
    public private(set) var arrangement: Arrangement
    public private(set) var geometry: WorldGeometry
    public private(set) var routes: [String: Route]

    // Derived once per snapshot, so no frame recomputes them.
    private(set) var hostTones: [String: HostTone] = [:]
    /// Apps and groups in a stable order, for drawing.
    private(set) var appOrder: [Application] = []
    private(set) var groupOrder: [AppGroup] = []
    /// Most urgent first, then in the snapshot's order.
    private(set) var alerts: [WorldAlert] = []
    /// The alert each app shows: its most urgent.
    private(set) var alertByApp: [String: WorldAlert] = [:]
    /// The alert each instance's label shows: its most urgent.
    private(set) var alertByInstance: [String: WorldAlert] = [:]
    /// The alert each device's card shows: its most urgent.
    private(set) var alertByDevice: [String: WorldAlert] = [:]
    /// Instances the operator has a tunnel into.
    private(set) var tunnelled: Set<String> = []

    /// Where the camera rests — or will rest, once a flight lands. Only
    /// `place(_:)` sets it.
    public private(set) var camera = Camera(center: .zero, scale: 0.05)
    /// The instance the camera is over, or nearest to. Stored, and changed
    /// only when that changes, so the HUD does not redraw on every frame of a
    /// pan.
    private(set) var currentInstanceID: String?
    private(set) var flight: Flight?
    public private(set) var viewport: CGSize = .zero
    /// What the HUD covers, so fitting a view keeps clear of it.
    private(set) var hudInsets = WorldModel.regularInsets

    /// The app the operator is looking at: its connections are lifted, every
    /// other line dims.
    public var focus: String?
    public var filter: ConnectionFilter = .all
    var isPalettePresented = false

    /// Where the HUD's pieces are, in global coordinates, so a scroll over one
    /// is left to it. Not observed: nothing redraws when they move.
    @ObservationIgnored var hudRegions: [String: CGRect] = [:]
    /// Where the map's viewport is, in global coordinates.
    @ObservationIgnored var viewportFrame: CGRect = .zero

    /// Where this world's source keeps its arrangement: one store per
    /// source, so a live instance named like a fixture instance never
    /// inherits the fixture's places.
    @ObservationIgnored private var store: ArrangementStore?
    /// Counts every change to the camera. A gesture's anchor records the
    /// count after its own change; finding it moved on means something else
    /// moved the camera meanwhile — a flight, a scroll, the minimap — and the
    /// anchor is stale.
    @ObservationIgnored private var cameraEpoch = 0
    /// A pan's starting camera and the drag's translation when it started.
    @ObservationIgnored private var panAnchor: (camera: Camera, base: CGSize, epoch: Int)?
    @ObservationIgnored private var zoomAnchor: (camera: Camera, point: CGPoint, epoch: Int)?
    /// A pan that a pinch or a flight cut into: until it ends, its events wait
    /// for the flight to land, then re-anchor where the camera is, without a
    /// jump.
    @ObservationIgnored private var panInterrupted = false
    /// A pinch that a flight cut into: its events are ignored until it ends.
    @ObservationIgnored private var pinchInterrupted = false
    /// The drag that is moving a group or an app: what, from where, where on
    /// it the pointer took hold (in world units), and whether the world had a
    /// conflict before it began, so a drop is refused only for one it causes.
    @ObservationIgnored private var activeMove: (item: Movable, start: CGPoint, grab: CGSize, hadConflicts: Bool)?
    @ObservationIgnored private var flights = 0
    @ObservationIgnored private var hasFramed = false
    /// The alert last opened, by id, so a reordering does not move Space
    /// on to the wrong one.
    @ObservationIgnored private var alertCursor: String?

    static let regularInsets = ViewportInsets(top: 84, leading: 24, bottom: 150, trailing: 24)
    static let compactInsets = ViewportInsets(top: 64, leading: 8, bottom: 190, trailing: 8)

    struct Flight: Equatable {
        let id: Int
        let path: CameraFlight
        let start: Date
    }

    public enum Target: Hashable, Sendable {
        case world
        case instance(String)
        case group(String)
        case app(String)
        case device(String)
    }

    /// What the operator can drag on the map.
    enum Movable: Hashable, Sendable {
        case group(String)
        case app(String)
    }

    /// `store` gives the defaults the arrangement is kept in; the key is
    /// the world's source's, whatever source the store was made for.
    public init(world: World, store: ArrangementStore? = nil) {
        let store = store?.for(world.source)
        let index = WorldIndex(world)
        let standard = Arrangement.standard(for: world)
        let arrangement = store?.load()?.completed(for: world, from: standard) ?? standard
        let geometry = WorldGeometry(world: world, index: index, arrangement: arrangement)
        self.world = world
        self.index = index
        self.arrangement = arrangement
        self.geometry = geometry
        self.routes = Router.routes(world: world, index: index, geometry: geometry)
        self.store = store
        derive()
    }

    /// A new snapshot of the world, validated by whoever read it: a live
    /// world changes as each instance's read lands.
    ///
    /// What the operator arranged stays where it is, and what is new is
    /// placed around it. When the source changes, the arrangement is the new
    /// source's own, never the old one's completed into it. Focus on an app
    /// that is gone is dropped, and a drag on something that is gone is put
    /// back. The camera stays, except that the first world with anything in
    /// it is framed, and a change of source flies to the whole world.
    public func update(world new: World) {
        let sourceChanged = new.source != world.source
        let newIndex = WorldIndex(new)
        if let active = activeMove {
            let gone = switch active.item {
            case .group(let id): newIndex.groups[id] == nil
            case .app(let id): newIndex.apps[id] == nil
            }
            // Back where it started, unsaved: on a change of source its
            // start belongs to the other source's layout.
            if gone || sourceChanged {
                activeMove = nil
                if !sourceChanged { set(active.item, active.start) }
            }
        }
        let standard = Arrangement.standard(for: new)
        if sourceChanged {
            store = store?.for(new.source)
            arrangement = store?.load()?.completed(for: new, from: standard) ?? standard
        } else {
            arrangement = arrangement.completed(for: new, from: standard)
        }
        world = new
        index = newIndex
        if let focus, index.apps[focus] == nil { self.focus = nil }
        rebuild()
        derive()
        if !hasFramed, fitted(.world) != nil {
            hasFramed = true
            show(.world)
        } else if sourceChanged {
            fly(to: .world)
        }
    }

    private func derive() {
        appOrder = index.apps.values.sorted { $0.id < $1.id }
        groupOrder = index.groups.values.sorted { $0.id < $1.id }
        alerts = world.alerts.enumerated()
            .sorted { ($1.element.severity, $0.offset) < ($0.element.severity, $1.offset) }
            .map(\.element)
        alertByApp = [:]
        alertByInstance = [:]
        alertByDevice = [:]
        for alert in alerts {
            switch alert.subject {
            case .app(let id): if alertByApp[id] == nil { alertByApp[id] = alert }
            case .instance(let id): if alertByInstance[id] == nil { alertByInstance[id] = alert }
            case .device(let id): if alertByDevice[id] == nil { alertByDevice[id] = alert }
            }
        }
        tunnelled = Set(world.connections.filter { line in
            guard line.kind == .tunnel, line.evidence == .observed, !line.isStale,
                  case .device(let id) = line.from, index.devices[id]?.role == .operator else { return false }
            return true
        }.compactMap { index.instanceID(of: $0) })
        hostTones = [:]
        for host in world.hosts {
            let lines = world.connections.filter { $0.to == .host(host.id) }
            hostTones[host.id] =
                if lines.isEmpty { .unconnected }
                else if lines.contains(where: { $0.evidence == .observed }) { .used }
                else if lines.contains(where: { $0.evidence == .denied }) { .refused }
                else if lines.allSatisfy({ $0.evidence == .planned }) { .planned }
                else { .declared }
        }
    }

    // MARK: - The camera

    /// Sets where the camera rests.
    private func place(_ camera: Camera) {
        self.camera = camera
        cameraEpoch += 1
        let current = geometry.instance(nearest: camera.center)
        if current != currentInstanceID { currentInstanceID = current }
    }

    /// The camera at `date`: during a flight, wherever the flight has got to.
    func camera(at date: Date) -> Camera {
        guard let flight else { return camera }
        guard flight.path.duration > 0 else { return flight.path.to }
        return flight.path.camera(at: date.timeIntervalSince(flight.start) / flight.path.duration)
    }

    /// The viewport's size, whenever it changes. The first time, the camera
    /// frames the whole world.
    public func viewportChanged(to size: CGSize) {
        guard size.width > 0, size.height > 0, size != viewport else { return }
        viewport = size
        if !hasFramed, let whole = fitted(.world) {
            hasFramed = true
            place(whole)
        }
    }

    /// The HUD takes more of a narrow screen, and less of a short one.
    func layoutChanged(compact: Bool, short: Bool = false) {
        hudInsets = short ? Self.shortInsets : compact ? Self.compactInsets : Self.regularInsets
    }

    static let shortInsets = ViewportInsets(top: 52, leading: 16, bottom: 104, trailing: 16)

    /// How wide a focused app is drawn on this screen.
    var focusedPanelWidth: CGFloat {
        guard viewport.width > 0, viewport.height > 0 else { return 0 }
        let panel = CGRect(origin: .zero, size: Metrics.panel)
        return Camera.fitting(panel, in: viewport, insets: hudInsets, margin: 12, maxScale: 1).scale * Metrics.panel.width
    }

    /// Narrower than this on screen, a panel shows a glance, not its app. A
    /// focused app is always drawn at least this wide, on any screen.
    var fullPanelWidth: CGFloat { min(320, focusedPanelWidth * 0.95) }

    func frame(of target: Target) -> CGRect? {
        switch target {
        case .world: geometry.bounds.isNull ? nil : geometry.bounds
        case .instance(let id): geometry.territories[id]?.frame
        case .group(let id): geometry.groups[id]?.frame
        case .app(let id): geometry.apps[id]
        case .device(let id): geometry.devices[id]
        }
    }

    func fitted(_ target: Target) -> Camera? {
        guard let rect = frame(of: target), viewport.width > 0, viewport.height > 0 else { return nil }
        let isApp = if case .app = target { true } else { false }
        return Camera.fitting(
            rect,
            in: viewport,
            insets: hudInsets,
            margin: isApp ? 12 : 40,
            maxScale: isApp ? 1 : 0.6
        )
    }

    /// Flies the camera to `target`.
    public func fly(to target: Target) {
        guard let goal = fitted(target) else { return }
        fly(to: goal, style: .arc)
    }

    /// Puts the camera on `target` at once, without flying.
    public func show(_ target: Target) {
        guard let goal = fitted(target) else { return }
        flight = nil
        place(goal)
    }

    private func fly(to goal: Camera, style: CameraFlight.Style) {
        // A flight ends a drag where it stands: the map is about to move out
        // from under a pointer that is holding still.
        if let active = activeMove { endMove(active.item) }
        let now = Date()
        let path = CameraFlight(from: camera(at: now), to: goal, viewport: viewport, style: style)
        place(goal)
        guard path.duration > 0 else {
            flight = nil
            return
        }
        flights += 1
        let id = flights
        flight = Flight(id: id, path: path, start: now)
        Task { [weak self] in
            try? await Task.sleep(for: .seconds(path.duration))
            if self?.flight?.id == id { self?.flight = nil }
        }
    }

    /// Stops a flight where it is, so a gesture starts from what is on screen.
    private func land() {
        guard flight != nil else { return }
        place(camera(at: Date()))
        flight = nil
    }

    func panChanged(_ translation: CGSize) {
        // A pinch owns the camera while it lasts.
        guard zoomAnchor == nil, !pinchInterrupted else {
            panInterrupted = true
            panAnchor = nil
            return
        }
        // Something else moved the camera since this pan's last event — a
        // flight, a scroll, the minimap. That move stands: the pan lets a
        // flight land, then resumes from where the camera is.
        if let anchor = panAnchor, anchor.epoch != cameraEpoch {
            panAnchor = nil
            panInterrupted = true
        }
        if panAnchor == nil {
            if panInterrupted, flight != nil { return }
            land()
            // A fresh pan moves from its first event; one resuming after an
            // interruption starts where the fingers are now.
            panAnchor = (camera, panInterrupted ? translation : .zero, cameraEpoch)
            panInterrupted = false
        }
        if let anchor = panAnchor {
            place(anchor.camera.panned(by: translation - anchor.base))
            panAnchor?.epoch = cameraEpoch
        }
    }

    func panEnded(_ translation: CGSize, predicted: CGSize) {
        panInterrupted = false
        guard let anchor = panAnchor else { return }
        panAnchor = nil
        // A fling coasts on; a placed drag stays put; a pan something else
        // overtook does not coast over it.
        guard anchor.epoch == cameraEpoch else { return }
        let coast = hypot(predicted.width - translation.width, predicted.height - translation.height)
        if coast > 30 { fly(to: anchor.camera.panned(by: predicted - anchor.base), style: .glide) }
    }

    /// The pan gesture went away without ending, as a cancelled one does.
    func panCancelled() {
        panAnchor = nil
        panInterrupted = false
    }

    func magnifyChanged(_ magnification: CGFloat, at point: CGPoint) {
        guard !pinchInterrupted else { return }
        // Something else moved the camera mid-pinch; that move stands, and
        // the rest of this pinch is ignored.
        if let anchor = zoomAnchor, anchor.epoch != cameraEpoch {
            zoomAnchor = nil
            pinchInterrupted = true
            return
        }
        if zoomAnchor == nil {
            land()
            if panAnchor != nil { panInterrupted = true }
            panAnchor = nil
            // A pinch is not a drag: a move it caught goes back where it was.
            cancelMove()
            zoomAnchor = (camera, point, cameraEpoch)
        }
        if let anchor = zoomAnchor {
            place(anchor.camera.zoomed(by: magnification, keeping: anchor.point, in: viewport))
            zoomAnchor?.epoch = cameraEpoch
        }
    }

    /// Called when a pinch ends and when it is cancelled.
    func magnifyEnded() {
        zoomAnchor = nil
        pinchInterrupted = false
    }

    /// A trackpad scroll pans; a mouse wheel, or a scroll with ⌘ held, zooms.
    /// Returns whether the map took it: a scroll over the HUD is the HUD's.
    /// The coasting tail of a fling (`momentum`) never stops a flight; only a
    /// scroll the fingers are making does.
    func scrolled(by delta: CGSize, at point: CGPoint, precise: Bool, zoom: Bool, momentum: Bool = false) -> Bool {
        let global = CGPoint(x: viewportFrame.minX + point.x, y: viewportFrame.minY + point.y)
        if hudRegions.values.contains(where: { $0.contains(global) }) { return false }
        if momentum, flight != nil { return true }
        land()
        if zoom || !precise {
            place(camera.zoomed(by: pow(precise ? 1.006 : 1.1, delta.height), keeping: point, in: viewport))
        } else {
            place(camera.panned(by: delta))
        }
        return true
    }

    /// One step in or out, animated, about `point`.
    func zoomStep(_ factor: CGFloat, at point: CGPoint) {
        fly(to: camera(at: Date()).zoomed(by: factor, keeping: point, in: viewport), style: .glide)
    }

    /// Centres the camera on a world point: what the minimap does.
    func look(at point: CGPoint, animated: Bool) {
        let goal = Camera(center: point, scale: camera(at: Date()).scale)
        if animated {
            fly(to: goal, style: .glide)
        } else {
            land()
            place(goal)
        }
    }

    /// The running apps that would show live at `camera`. Only web tiles
    /// are budgeted: FarCast's own surfaces are native, and an illustrative
    /// app has no UI to run.
    func liveApps(at camera: Camera) -> Set<String> {
        let running = geometry.apps.filter { id, _ in
            guard let app = index.apps[id], app.state == .running, !app.isIllustrative,
                  let group = index.groupOfApp[id], index.groups[group]?.isSystem == false else { return false }
            return true
        }
        return LiveBudget.live(
            running,
            camera: camera,
            viewport: viewport,
            focus: focus,
            minimumWidth: min(LiveBudget.minimumWidth, focusedPanelWidth * 0.95)
        )
    }

    // MARK: - Focus and alerts

    public func focus(on appID: String) {
        focus = appID
        fly(to: .app(appID))
    }

    func clearFocus() {
        focus = nil
    }

    /// Esc: closes the palette, or backs out from an app to its instance.
    func escape() {
        if isPalettePresented {
            isPalettePresented = false
            return
        }
        let instance = focus.flatMap(index.instanceID(ofApp:)) ?? currentInstanceID
        focus = nil
        fly(to: instance.map(Target.instance) ?? .world)
    }

    /// Opens what an alert is about: an app is focused; an instance or a
    /// device is framed, and nothing stays focused.
    func open(_ alert: WorldAlert) {
        alertCursor = alert.id
        switch alert.subject {
        case .app(let id):
            focus(on: id)
        case .instance(let id):
            focus = nil
            fly(to: .instance(id))
        case .device(let id):
            focus = nil
            fly(to: .device(id))
        }
    }

    /// Space: the alert after the one last opened, round and round. If that
    /// one is gone, the most urgent.
    func openNextAlert() {
        guard !alerts.isEmpty else { return }
        let last = alertCursor.flatMap { id in alerts.firstIndex { $0.id == id } }
        open(alerts[last.map { ($0 + 1) % alerts.count } ?? 0])
    }

    func alert(for appID: String) -> WorldAlert? {
        alertByApp[appID]
    }

    // MARK: - Arranging

    func position(of item: Movable) -> CGPoint {
        switch item {
        case .group(let id): arrangement.groupOrigins[id] ?? .zero
        case .app(let id): arrangement.appOffsets[id] ?? .zero
        }
    }

    /// A drag on `item`'s handle began at `point`, in viewport coordinates.
    /// Returns whether the move starts: not during a pinch.
    @discardableResult
    func beginMove(_ item: Movable, at point: CGPoint) -> Bool {
        if let active = activeMove, active.item != item { endMove(active.item) }
        guard zoomAnchor == nil, !pinchInterrupted else { return false }
        // Taking hold of something stops the map, as grabbing the map does.
        land()
        let start = position(of: item)
        let held = camera(at: Date()).world(point, in: viewport)
        let origin = worldOrigin(of: item, at: start)
        activeMove = (item, start, CGSize(width: held.x - origin.x, height: held.y - origin.y), arrangement.hasConflicts(for: world))
        return true
    }

    /// The pointer moved to `point`: the item follows it, keeping the place
    /// it was taken by under the pointer — as the camera is drawn, mid-flight
    /// included — whatever the camera does meanwhile.
    func move(_ item: Movable, to point: CGPoint) {
        guard let active = activeMove, active.item == item else { return }
        let held = camera(at: Date()).world(point, in: viewport)
        let origin = CGPoint(x: held.x - active.grab.width, y: held.y - active.grab.height)
        set(item, position(for: item, worldOrigin: origin).snapped)
        rebuild()
    }

    /// The drag ended, was cancelled, or lost its handle. A drop that would
    /// put two panels, two groups or two instances' rows on top of each other
    /// is refused: the item goes back where it was. A conflict that was there
    /// before the drag does not refuse it.
    func endMove(_ item: Movable) {
        guard let active = activeMove, active.item == item else { return }
        activeMove = nil
        if !active.hadConflicts, arrangement.hasConflicts(for: world) {
            set(item, active.start)
            rebuild()
        }
        // Saved on top of what the store holds, so another window's moves
        // since are kept: whatever this window placed that the store lacks,
        // and the whole instance the drop happened in, as this window shows
        // it. If that would make the stored layout overlap — another window
        // dropped something on the same spot — this window's layout, the
        // one the operator just looked at, is saved whole.
        if let store {
            var saved = store.load() ?? arrangement
            for (id, origin) in arrangement.groupOrigins where saved.groupOrigins[id] == nil { saved.groupOrigins[id] = origin }
            for (id, offset) in arrangement.appOffsets where saved.appOffsets[id] == nil { saved.appOffsets[id] = offset }
            let appID: String? = if case .app(let id) = item { id } else { nil }
            let groupID: String? = switch item {
            case .group(let id): id
            case .app(let id): index.groupOfApp[id]
            }
            if let instanceID = groupID.flatMap({ index.instanceOfGroup[$0] }), let instance = index.instances[instanceID] {
                for group in instance.groups {
                    saved.groupOrigins[group.id] = arrangement.groupOrigins[group.id]
                    for app in group.apps { saved.appOffsets[app.id] = arrangement.appOffsets[app.id] }
                }
            } else if let appID {
                saved.appOffsets[appID] = arrangement.appOffsets[appID]
            }
            store.save(saved.hasConflicts(for: world) ? arrangement : saved)
        }
    }

    /// Puts a move back where it started, without saving.
    private func cancelMove() {
        guard let active = activeMove else { return }
        activeMove = nil
        set(active.item, active.start)
        rebuild()
    }

    /// Where `item`'s arranged position puts it in the world: a group's origin
    /// is already a world point, an app's offset is relative to its group.
    private func worldOrigin(of item: Movable, at position: CGPoint) -> CGPoint {
        guard case .app(let id) = item, let group = index.groupOfApp[id],
              let origin = arrangement.groupOrigins[group] else { return position }
        return CGPoint(x: origin.x + position.x, y: origin.y + position.y)
    }

    private func position(for item: Movable, worldOrigin: CGPoint) -> CGPoint {
        guard case .app(let id) = item, let group = index.groupOfApp[id],
              let origin = arrangement.groupOrigins[group] else { return worldOrigin }
        return CGPoint(x: worldOrigin.x - origin.x, y: worldOrigin.y - origin.y)
    }

    public func resetArrangement() {
        arrangement = .standard(for: world)
        rebuild()
        store?.clear()
    }

    private func set(_ item: Movable, _ point: CGPoint) {
        switch item {
        case .group(let id): arrangement.groupOrigins[id] = point
        case .app(let id): arrangement.appOffsets[id] = point
        }
    }

    private func rebuild() {
        geometry = WorldGeometry(world: world, index: index, arrangement: arrangement)
        routes = Router.routes(world: world, index: index, geometry: geometry)
        let current = geometry.instance(nearest: camera.center)
        if current != currentInstanceID { currentInstanceID = current }
    }

    // MARK: - Search

    struct SearchResult: Identifiable, Hashable {
        let id: String
        let title: String
        let detail: String
        let symbol: String
        let target: Target
    }

    func search(_ query: String) -> [SearchResult] {
        var results: [SearchResult] = []
        for instance in world.instances {
            let name = Display.name(instance.id)
            results.append(SearchResult(
                id: "instance:\(instance.id)", title: name,
                // The same words as the instance's label: both parts, or
                // what was not read, never a share made into a whole.
                detail: "instance · \(Format.spending(instance.spending))",
                symbol: "square.dashed", target: .instance(instance.id)
            ))
            for group in instance.groups {
                let groupName = group.isSystem ? "FarCast" : Display.name(group.namespace)
                results.append(SearchResult(
                    id: "group:\(group.id)", title: groupName,
                    detail: "\(name) · \(Display.name(group.source))", symbol: "folder", target: .group(group.id)
                ))
                for app in group.apps {
                    results.append(SearchResult(
                        id: "app:\(app.id)", title: Display.name(app.name),
                        detail: "\(name) · \(groupName) · \(Display.name(app.role))",
                        symbol: app.system == nil ? "app" : "gearshape", target: .app(app.id)
                    ))
                }
            }
        }
        let words = query.lowercased().split(separator: " ").map(String.init)
        guard !words.isEmpty else { return results.filter { if case .app = $0.target { true } else { false } } }
        return results.filter { result in
            let text = "\(result.title) \(result.detail)".lowercased()
            return words.allSatisfy(text.contains)
        }
    }

    func go(to result: SearchResult) {
        isPalettePresented = false
        if case .app(let id) = result.target {
            focus(on: id)
        } else {
            fly(to: result.target)
        }
    }

    // MARK: - Hosts

    /// What a host's lines say about it, strongest evidence first.
    enum HostTone {
        /// FatLine counted traffic to it.
        case used
        /// Refused at the wall; nothing ever crossed.
        case refused
        /// Only decided-but-not-built lines reach it.
        case planned
        /// Declared, never used.
        case declared
        /// No line reaches it at all.
        case unconnected
    }
}

private extension CGSize {
    static func - (a: CGSize, b: CGSize) -> CGSize {
        CGSize(width: a.width - b.width, height: a.height - b.height)
    }
}

/// Keeps the operator's arrangement on this device. ADR 0021 gives layout
/// state to the FarSight server; this is the stand-in until that server
/// exists. One arrangement for every instance of a source: it keeps the
/// places of groups the world no longer shows, so an instance that comes
/// back finds its layout.
///
/// Each source has its own key, and the fixture keeps the key it always
/// had, so a real instance named like a fixture instance never inherits the
/// fixture's places.
public struct ArrangementStore {
    private let defaults: UserDefaults
    public let source: World.Source

    public init(defaults: UserDefaults = .standard, source: World.Source = .fixture) {
        self.defaults = defaults
        self.source = source
    }

    /// The key each source's arrangement is kept under.
    public static func key(for source: World.Source) -> String {
        switch source {
        case .fixture: "farsight.arrangement.v2"
        case .live: "farsight.arrangement.live.v1"
        }
    }

    /// The store for `source`, in the same defaults.
    func `for`(_ source: World.Source) -> ArrangementStore {
        ArrangementStore(defaults: defaults, source: source)
    }

    func load() -> Arrangement? {
        defaults.data(forKey: Self.key(for: source)).flatMap { try? JSONDecoder().decode(Arrangement.self, from: $0) }
    }

    func save(_ arrangement: Arrangement) {
        if let data = try? JSONEncoder().encode(arrangement) { defaults.set(data, forKey: Self.key(for: source)) }
    }

    func clear() {
        defaults.removeObject(forKey: Self.key(for: source))
    }
}
