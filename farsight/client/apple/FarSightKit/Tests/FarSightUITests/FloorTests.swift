import Foundation
import SwiftUI
import Testing
@testable import FarSightUI
import FarSightCore

/// What TechnoCore's panel says about the instance floor (ADR 0009 decision
/// 8): only what the kernel records, and its silence said as silence.
@Suite("The instance floor")
struct FloorTests {
    let viewport = CGSize(width: 1440, height: 900)
    let kernel = "a/farcast-system/technocore"

    func model(_ spending: Spending) -> WorldModel {
        var world = Worlds.slice("a", readAt: Date(timeIntervalSince1970: 1_794_477_600))
        world.instances[0].spending = spending
        let model = WorldModel(world: world, store: nil)
        model.viewportChanged(to: viewport)
        return model
    }

    var read: Spending {
        Spending(
            expectedCents: 2000, totalCents: 2000, limitCents: 1000, recordedLimitCents: 1000, level: .reached
        )
    }

    @Test("at the floor, the kernel's panel says what still burns and names the levers")
    func atTheFloor() throws {
        var spending = read
        spending.atFloor = true
        spending.floor = SpendingFloor(
            since: Date(timeIntervalSince1970: 1_794_472_200), stillBurningMonthCents: 5703,
            levers: ["drop the load-balancer carrier", "release the instance"]
        )
        let model = model(spending)
        let facts = try PanelFacts.of(model, kernel)
        #expect(facts["still burning, every app stopped"] == "$57.03/mo")
        let note = try PanelFacts.note(model, kernel)
        #expect(note.contains("At the instance floor since"))
        #expect(note.contains("What is left is to drop the load-balancer carrier, or release the instance."))
        #expect(note.contains("leaves it to you"))
        #expect(Format.spending(spending).hasSuffix(" · at the floor"))
        #expect(Format.spendingSpoken(spending).contains("at the instance floor"))
    }

    @Test("not at the floor, it says no only where the kernel says so")
    func notAtTheFloor() throws {
        var recorded = read
        recorded.atFloor = false
        #expect(try PanelFacts.of(model(recorded), kernel)["at the instance floor"] == "no")
        // A kernel that records no floor is not a kernel that is not at it.
        #expect(try PanelFacts.of(model(read), kernel)["at the instance floor"] == "not recorded")
        #expect(!(try PanelFacts.note(model(read), kernel)).contains("At the instance floor"))
        #expect(!Format.spending(read).contains("floor"))
    }

    @Test("the floor's alert has its own symbol")
    func symbol() {
        #expect(AlertBar.symbol(.atFloor) == "arrow.down.to.line")
        #expect(AlertBar.symbol(.atFloor) != AlertBar.symbol(.cost))
    }
}
