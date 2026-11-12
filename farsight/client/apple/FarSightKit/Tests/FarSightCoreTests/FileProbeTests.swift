import Foundation
import Testing
@testable import FarSightCore

/// The probe Settings' checks run against on a real Mac, on real files in a
/// temporary directory (which the iOS simulator has too).
@Suite("Probing files")
struct FileProbeTests {
    /// A new directory of its own, removed after `body`.
    static func inTemporaryDirectory(_ body: (String) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory.appending(path: "farsight-probe-\(UUID().uuidString)").path
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(atPath: directory) }
        try body(directory)
    }

    static func file(_ path: String, mode: Int) throws {
        #expect(FileManager.default.createFile(atPath: path, contents: Data("#!/bin/sh\n".utf8)))
        try chmod(path, mode)
    }

    static func chmod(_ path: String, _ mode: Int) throws {
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: path)
    }

    @Test("a file, executable or not, a directory, and nothing at all")
    func entries() throws {
        try Self.inTemporaryDirectory { root in
            let probe = LocalFileProbe()
            try Self.file("\(root)/tool", mode: 0o755)
            try Self.file("\(root)/notes", mode: 0o644)
            try FileManager.default.createDirectory(atPath: "\(root)/bin", withIntermediateDirectories: false)
            try Self.chmod("\(root)/bin", 0o755)
            try Self.chmod(root, 0o700)

            #expect(probe.entry(at: "\(root)/tool") == .file(executable: true, worldWritable: false))
            #expect(probe.entry(at: "\(root)/notes") == .file(executable: false, worldWritable: false))
            #expect(probe.entry(at: "\(root)/bin") == .directory(worldWritable: false))
            #expect(probe.entry(at: root) == .directory(worldWritable: false))
            #expect(probe.entry(at: "\(root)/nothing") == .missing)
            #expect(probe.resolved("\(root)/nothing") == nil)
            #expect(probe.resolved("relative/tool") == nil)
        }
    }

    @Test("a link is followed to what it points at")
    func symlinks() throws {
        try Self.inTemporaryDirectory { root in
            let probe = LocalFileProbe()
            try Self.file("\(root)/tool", mode: 0o755)
            try FileManager.default.createSymbolicLink(atPath: "\(root)/link", withDestinationPath: "\(root)/tool")
            try FileManager.default.createSymbolicLink(atPath: "\(root)/dangling", withDestinationPath: "\(root)/gone")

            #expect(probe.entry(at: "\(root)/link") == .file(executable: true, worldWritable: false))
            let target = URL(fileURLWithPath: "\(root)/tool").resolvingSymlinksInPath().path
            #expect(probe.resolved("\(root)/link") == target)
            #expect(probe.resolved("\(root)/tool") == target)
            #expect(probe.resolved("\(root)/link") != "\(root)/link")
            #expect(probe.entry(at: "\(root)/dangling") == .missing)
            #expect(probe.resolved("\(root)/dangling") == nil)
        }
    }

    @Test("what anyone on this Mac can write is said so")
    func worldWritable() throws {
        try Self.inTemporaryDirectory { root in
            let probe = LocalFileProbe()
            try FileManager.default.createDirectory(atPath: "\(root)/open", withIntermediateDirectories: false)
            try Self.chmod("\(root)/open", 0o777)
            try Self.file("\(root)/shared", mode: 0o666)
            try Self.file("\(root)/shared-tool", mode: 0o777)
            try Self.file("\(root)/group", mode: 0o775)

            #expect(probe.entry(at: "\(root)/open") == .directory(worldWritable: true))
            #expect(probe.entry(at: "\(root)/shared") == .file(executable: false, worldWritable: true))
            #expect(probe.entry(at: "\(root)/shared-tool") == .file(executable: true, worldWritable: true))
            #expect(probe.entry(at: "\(root)/group") == .file(executable: true, worldWritable: false))
        }
    }

    @Test("Settings refuse a tool that links into a directory anyone can write, on real files")
    func linkIntoAnOpenDirectory() throws {
        try Self.inTemporaryDirectory { root in
            let probe = LocalFileProbe()
            try FileManager.default.createDirectory(atPath: "\(root)/open", withIntermediateDirectories: false)
            try Self.chmod("\(root)/open", 0o777)
            try FileManager.default.createDirectory(atPath: "\(root)/bin", withIntermediateDirectories: false)
            try Self.chmod("\(root)/bin", 0o755)
            try Self.file("\(root)/open/kubectl", mode: 0o755)
            try FileManager.default.createSymbolicLink(atPath: "\(root)/bin/kubectl", withDestinationPath: "\(root)/open/kubectl")

            let settings = CLISettings(kubectl: "\(root)/bin/kubectl")
            let kubectl = settings.problems(probe: probe, bundlePath: "").first { $0.field == .kubectl }
            #expect(kubectl?.message == "it links to a file in a directory anyone on this Mac can write")

            try Self.chmod("\(root)/open", 0o755)
            #expect(settings.problems(probe: probe, bundlePath: "").first { $0.field == .kubectl } == nil)
        }
    }

    @Test("Settings refuse a tool inside the bundle, with either one reached through a link, on real files")
    func bundleThroughALink() throws {
        try Self.inTemporaryDirectory { root in
            let probe = LocalFileProbe()
            try FileManager.default.createDirectory(atPath: "\(root)/real/FarCast.app/Contents/MacOS", withIntermediateDirectories: true)
            try Self.file("\(root)/real/FarCast.app/Contents/MacOS/kubectl", mode: 0o755)
            try FileManager.default.createSymbolicLink(atPath: "\(root)/alias", withDestinationPath: "\(root)/real")

            // The bundle given through the link, as a bundle URL's path, and the tool typed where it is.
            let direct = CLISettings(kubectl: "\(root)/real/FarCast.app/Contents/MacOS/kubectl")
            let given = direct.problems(probe: probe, bundlePath: "\(root)/alias/FarCast.app/").first { $0.field == .kubectl }
            #expect(given?.message == "is inside FarCast.app")

            // The tool typed through the link, and the bundle given where it is.
            let linked = CLISettings(kubectl: "\(root)/alias/FarCast.app/Contents/MacOS/kubectl")
            let typed = linked.problems(probe: probe, bundlePath: "\(root)/real/FarCast.app/").first { $0.field == .kubectl }
            #expect(typed?.message == "is inside FarCast.app")
        }
    }
}
