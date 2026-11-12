import Foundation
import Testing
@testable import FarSightCore

/// The executor's seam: output kept up to a limit, and the commit a build
/// states.
@Suite("Running farcast")
struct ExecutionTests {
    @Test("a capped buffer keeps up to its limit, and says when more came")
    func cappedBuffer() {
        var buffer = CappedBuffer(limit: 4)
        let under = buffer.append(Data([1, 2]))
        #expect(under && buffer.data == Data([1, 2]) && !buffer.overflowed)
        let at = buffer.append(Data([3, 4]))
        #expect(at && buffer.data == Data([1, 2, 3, 4]) && !buffer.overflowed)
        let past = buffer.append(Data([5]))
        #expect(!past && buffer.data == Data([1, 2, 3, 4]) && buffer.overflowed)
        let after = buffer.append(Data())
        #expect(!after, "once over, it stays over")

        var over = CappedBuffer(limit: 4)
        let whole = over.append(Data([1, 2, 3, 4, 5, 6]))
        #expect(!whole && over.data == Data([1, 2, 3, 4]) && over.overflowed)

        var sliced = CappedBuffer(limit: 3)
        let chunk = Data([9, 8, 7, 6, 5]).dropFirst(1)  // a slice whose indices do not start at 0
        let cut = sliced.append(chunk)
        #expect(!cut && sliced.data == Data([8, 7, 6]))

        var none = CappedBuffer(limit: 0)
        let nothing = none.append(Data())
        let something = none.append(Data([1]))
        #expect(nothing && !something && none.data.isEmpty)
    }

    @Test("a build's commit is seven hex digits, lower-cased; anything else is none", arguments: [
        ("0E54EB1", "0e54eb1"),
        ("4f2a9c1e8b7d6a5f4e3c2b1a0f9e8d7c6b5a4938", "4f2a9c1"),
        ("0e54eb1", "0e54eb1"),
        ("", nil), ("none", nil), ("dev", nil), ("$(FARCAST_COMMIT)", nil), ("abc12", nil), ("abc123", nil),
        ("0e54eb1-dirty", nil), (" 0e54eb1", nil), ("0e54eg1", nil),
    ] as [(String, String?)])
    func buildCommit(raw: String, parsed: String?) {
        #expect(BuildCommit.parse(raw) == parsed)
    }

    @Test("no commit at all is none, and the Info.plist key is the one the build writes")
    func noCommit() {
        #expect(BuildCommit.parse(nil) == nil)
        #expect(BuildCommit.infoKey == "FarCastCommit")
    }
}
