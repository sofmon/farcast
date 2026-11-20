import Foundation
import Testing
@testable import FarSightCore

/// What a failed part of a read says on the map: one plain sentence a
/// section, from the CLI's kinds, never its prose; and the chip's summary.
@Suite("Problem sentences")
struct ProblemTextTests {
    @Test("the operator's three sentences, word for word")
    func examples() {
        #expect(SectionProblem(section: .spend, kind: .clusterUnreachable, message: "x").sentence
            == "spending not read · cluster unreachable — check the network")
        #expect(SectionProblem(section: .read, kind: .versionSkew, message: "x").sentence
            == "the read was refused · version skew — build farcast and FarCast from one commit")
        #expect(SectionProblem(section: .network, kind: .tunnelUnreachable, message: "x").sentence
            == "network not read · tunnel unreachable")
    }

    /// Every kind, in a section of the world document.
    static let sectionSentences: [SectionProblem.Kind: String] = [
        .recordUnreadable: "network not read · record unreadable",
        .notFound: "network not read · not found",
        .notConnected: "network not read · no tunnel — farcast connect opens one",
        .tunnelUnreachable: "network not read · tunnel unreachable",
        .kernelAbsent: "network not read · no kernel — farcast kernel deploy starts one",
        .notCheckpointed: "network not read · not checkpointed yet — the kernel writes one within minutes of starting",
        .versionSkew: "network not read · version skew",
        .credentialMissing: "network not read · credential missing — set up the instance's reader in a terminal: "
            + "farcast reader init <instance>, the printed Cloud Shell script, reader record and reader grant; "
            + "farcast instances shows the reader's state",
        .credentialRefused: "network not read · credential refused — check this machine's clock; then the key id "
            + "(farcast reader record); a reader key expires with its certificate: farcast reader init <instance> --rotate",
        .unsafeEnvironment: "network not read · environment refused",
        .endpointRefused: "network not read · endpoint refused",
        .clusterUnreachable: "network not read · cluster unreachable — check the network",
        .unauthorized: "network not read · unauthorized — the cluster refused the reader's token: check that the "
            + "Cloud Shell step granted roles/container.clusterViewer; farcast instances shows the reader's state",
        .forbidden: "network not read · forbidden — the reader may not read this: farcast reader grant <instance>; "
            + "if the reader was just set up, IAM changes can take 7 minutes or longer",
        .clusterRejected: "network not read · cluster rejected",
        .documentUnreadable: "network not read · document unreadable",
        .rolloutStalled: "network not read · rollout stalled",
        .planChanged: "network not read · plan changed",
        .timeout: "network not read · timed out",
        .internal: "network not read · internal error",
        .unknown: "network not read · no reason given",
    ]

    @Test("every kind, in a section, says what was not read, why, and the remedy where there is one")
    func everyKindInASection() {
        #expect(Set(Self.sectionSentences.keys) == Set(SectionProblem.Kind.allCases))
        #expect(SectionProblem.Kind.allCases.count == 21)
        for kind in SectionProblem.Kind.allCases {
            #expect(ProblemText.sentence(.network, kind) == Self.sectionSentences[kind], "\(kind)")
        }
    }

    @Test("each remedy has one ' — ' and no quoted command, as the app's remedies are written")
    func remediesHaveOneSeparator() {
        for kind in SectionProblem.Kind.allCases {
            let sentence = ProblemText.sentence(.spend, kind)
            #expect(sentence.components(separatedBy: " — ").count <= 2, "\(kind)")
            #expect(!sentence.contains("'farcast"), "\(kind)")
        }
    }

    @Test("every kind, for the read as a whole: only version skew is refused; timed out, or failed")
    func everyKindForTheRead() {
        for kind in SectionProblem.Kind.allCases {
            let sentence = ProblemText.sentence(.read, kind)
            switch kind {
            case .versionSkew:
                #expect(sentence.hasPrefix("the read was refused · \(kind.label) — "), "\(kind)")
            case .timeout:
                #expect(sentence == "the read timed out")
            default:
                #expect(sentence.hasPrefix("the read failed · "), "\(kind)")
            }
            #expect(!sentence.contains("read not read"))
        }
        #expect(ProblemText.sentence(.read, .versionSkew)
            == "the read was refused · version skew — build farcast and FarCast from one commit")
        #expect(ProblemText.sentence(.read, .tunnelUnreachable) == "the read failed · tunnel unreachable")
        #expect(ProblemText.sentence(.read, .credentialMissing).hasPrefix("the read failed · credential missing — "))
    }

    @Test("the record says what is wrong with it, and nothing it cannot know")
    func theRecord() {
        #expect(ProblemText.sentence(.record, .recordUnreadable) == "the record on this Mac is unreadable")
        #expect(ProblemText.sentence(.record, .notFound) == "no record of it on this Mac")
        #expect(ProblemText.sentence(.record, .internal) == "the record on this Mac could not be drawn whole")
    }

    @Test("every section by its name, and each sentence is one line of plain words")
    func everySection() {
        let names: [SectionProblem.Section: String] = [
            .spend: "spending not read", .apps: "apps not read", .policy: "egress policy not read",
            .network: "network not read", .seal: "seal not read", .unknown: "part of the read failed",
        ]
        for (section, what) in names {
            #expect(ProblemText.what(section, .clusterRejected) == what)
        }
        for section in SectionProblem.Section.allCases {
            for kind in SectionProblem.Kind.allCases {
                let sentence = ProblemText.sentence(section, kind)
                #expect(!sentence.isEmpty && !sentence.contains("\n") && !sentence.contains("_"), "\(section) \(kind)")
                #expect(sentence == SectionProblem(section: section, kind: kind, message: "anything").sentence)
            }
        }
    }

    @Test("a spending figure the map cannot draw has its own sentence, never its section not read, and is counted apart on the chip")
    func figures() {
        let figure = SectionProblem(section: .figures, kind: .internal, message: "expected spending is not one: -5 cents")
        #expect(figure.sentence == "spending figure not drawn · out of range")
        for kind in SectionProblem.Kind.allCases {
            #expect(ProblemText.sentence(.figures, kind) == "spending figure not drawn · out of range", "\(kind)")
        }
        #expect(ProblemText.summary([figure]) == ["1 spending figure not drawn"])
        #expect(ProblemText.summary([figure, figure, SectionProblem(section: .network, kind: .tunnelUnreachable, message: "x")])
            == ["network not read · tunnel unreachable", "2 spending figures not drawn"])
    }

    @Test("the chip counts the sections not read and says why, never listing them")
    func summary() {
        func problem(_ section: SectionProblem.Section, _ kind: SectionProblem.Kind) -> SectionProblem {
            SectionProblem(section: section, kind: kind, message: "a long message from the API server")
        }
        #expect(ProblemText.summary([]).isEmpty)
        #expect(ProblemText.summary([problem(.spend, .credentialMissing), problem(.apps, .credentialMissing), problem(.policy, .credentialMissing)])
            == ["3 sections not read · credential missing"])
        #expect(ProblemText.summary([problem(.read, .versionSkew)]) == ["read refused · version skew"])
        #expect(ProblemText.summary([problem(.read, .credentialRefused)]) == ["read failed · credential refused"])
        #expect(ProblemText.summary([problem(.network, .tunnelUnreachable)]) == ["network not read · tunnel unreachable"])
        #expect(ProblemText.summary([problem(.network, .tunnelUnreachable), problem(.seal, .tunnelUnreachable)])
            == ["2 sections not read · tunnel unreachable"])
        // A section is counted once, however many problems name it.
        #expect(ProblemText.summary([problem(.spend, .forbidden), problem(.spend, .internal)])
            == ["spending not read · forbidden, internal error"])
        #expect(ProblemText.summary([problem(.spend, .forbidden), problem(.apps, .unauthorized), problem(.network, .tunnelUnreachable)])
            == ["3 sections not read · forbidden, unauthorized and more"])
        // The read, then the record, then the sections.
        #expect(ProblemText.summary([problem(.network, .tunnelUnreachable), problem(.record, .internal), problem(.read, .timeout)])
            == ["read timed out", "record incomplete", "network not read · tunnel unreachable"])
        #expect(ProblemText.summary([problem(.read, .internal)]) == ["read failed · internal error"])
        #expect(ProblemText.summary([problem(.record, .recordUnreadable)]) == ["record unreadable"])
    }

    @Test("the chip's summary of the vectors that failed in part")
    func summaryOfVectors() throws {
        func summary(_ name: String) throws -> [String] {
            let world = try CLIDocuments.world(try Vectors.data("world/\(name).json"), asReadOf: "atlas").world
            return ProblemText.summary(try #require(world.instances.first).problems)
        }
        #expect(try summary("account_in_message") == ["3 sections not read · cluster rejected, forbidden and more"])
        #expect(try summary("nothing_read") == ["5 sections not read · credential refused, tunnel unreachable"])
        #expect(try summary("reader_missing") == ["3 sections not read · credential missing"])
        #expect(try summary("release_incomplete") == ["5 sections not read · cluster unreachable, timed out"])
        #expect(try summary("tunnel_down") == ["2 sections not read · tunnel unreachable"])
        #expect(try summary("healthy").isEmpty)
        // A group the reader may not read is no section not read: the chip says nothing of it.
        #expect(try summary("namespace_unread").isEmpty)
        // The read refused as a whole: version skew, the only kind that refuses it.
        let refused = ReadFailure(kind: .versionSkew, message: "farcast wrote schema 3 and this FarCast reads schema 2; build both from the same commit")
        #expect(ProblemText.summary([SectionProblem(section: .read, kind: refused.kind, message: refused.message)])
            == ["read refused · version skew"])
    }

    @Test("a group whose applications were not read says so with the kind's label, and no remedy")
    func groupNotRead() {
        #expect(ProblemText.groupNotRead(SectionProblem(section: .apps, kind: .forbidden, message: "x")) == "applications not read · forbidden")
        #expect(ProblemText.groupNotRead(SectionProblem(section: .apps, kind: .unknown, message: "x")) == "applications not read · no reason given")
        for kind in SectionProblem.Kind.allCases {
            let text = ProblemText.groupNotRead(SectionProblem(section: .apps, kind: kind, message: "x"))
            #expect(text.hasPrefix("applications not read · ") && !text.contains(" — "), "\(kind)")
        }
    }
}

@Suite("Counts in words")
struct PluralTests {
    @Test("one is singular; none, many and anything else are plural")
    func plural() {
        #expect(Plural.of(1, "app stopped", "apps stopped") == "app stopped")
        #expect(Plural.of(0, "app stopped", "apps stopped") == "apps stopped")
        #expect(Plural.of(2, "app stopped", "apps stopped") == "apps stopped")
        #expect(Plural.of(-1, "app", "apps") == "apps")
        #expect(Plural.count(1, "section", "sections") == "1 section")
        #expect(Plural.count(3, "section", "sections") == "3 sections")
        #expect(Plural.count(0, "line", "lines") == "0 lines")
    }
}
