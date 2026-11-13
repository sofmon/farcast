import Foundation
import Testing
@testable import FarSightCore

/// What a failed part of a read says on the map: one plain sentence a
/// section, from the CLI's kinds, never its prose; and the chip's summary.
@Suite("Problem sentences")
struct ProblemTextTests {
    @Test("the operator's three sentences, word for word")
    func examples() {
        #expect(SectionProblem(section: .spend, kind: .gcloudSignedOut, message: "x").sentence
            == "spending not read · signed out of gcloud — run gcloud auth login")
        #expect(SectionProblem(section: .read, kind: .gcloudMismatch, message: "x").sentence
            == "the read was refused · gcloud identity does not match — farcast instances pin-gcloud")
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
        .kubectlMissing: "network not read · kubectl missing — set kubectl in Settings",
        .kubectlFailed: "network not read · kubectl failed",
        .gcloudMismatch: "network not read · gcloud identity does not match — farcast instances pin-gcloud",
        .gcloudSignedOut: "network not read · signed out of gcloud — run gcloud auth login",
        .authToolMissing: "network not read · auth plugin missing — set gke-gcloud-auth-plugin in Settings",
        .timeout: "network not read · timed out",
        .internal: "network not read · internal error",
        .unknown: "network not read · no reason given",
    ]

    @Test("every kind, in a section, says what was not read, why, and the remedy where there is one")
    func everyKindInASection() {
        #expect(Set(Self.sectionSentences.keys) == Set(SectionProblem.Kind.allCases))
        for kind in SectionProblem.Kind.allCases {
            #expect(ProblemText.sentence(.network, kind) == Self.sectionSentences[kind], "\(kind)")
        }
    }

    @Test("every kind, for the read as a whole: refused, timed out, or failed")
    func everyKindForTheRead() {
        for kind in SectionProblem.Kind.allCases {
            let sentence = ProblemText.sentence(.read, kind)
            switch kind {
            case .gcloudMismatch, .versionSkew:
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
            #expect(ProblemText.what(section, .kubectlFailed) == what)
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
            SectionProblem(section: section, kind: kind, message: "a long message from kubectl")
        }
        #expect(ProblemText.summary([]).isEmpty)
        #expect(ProblemText.summary([problem(.spend, .gcloudSignedOut), problem(.apps, .gcloudSignedOut), problem(.policy, .gcloudSignedOut)])
            == ["3 sections not read · signed out of gcloud"])
        #expect(ProblemText.summary([problem(.read, .gcloudMismatch)]) == ["read refused · gcloud identity does not match"])
        #expect(ProblemText.summary([problem(.network, .tunnelUnreachable)]) == ["network not read · tunnel unreachable"])
        #expect(ProblemText.summary([problem(.network, .tunnelUnreachable), problem(.seal, .tunnelUnreachable)])
            == ["2 sections not read · tunnel unreachable"])
        // A section is counted once, however many problems name it.
        #expect(ProblemText.summary([problem(.spend, .kubectlFailed), problem(.spend, .internal)])
            == ["spending not read · kubectl failed, internal error"])
        #expect(ProblemText.summary([problem(.spend, .kubectlFailed), problem(.apps, .gcloudSignedOut), problem(.network, .tunnelUnreachable)])
            == ["3 sections not read · kubectl failed, signed out of gcloud and more"])
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
        #expect(try summary("account_in_message") == ["3 sections not read · kubectl failed, signed out of gcloud"])
        #expect(try summary("nothing_read") == ["5 sections not read · signed out of gcloud, tunnel unreachable"])
        #expect(try summary("tunnel_down") == ["2 sections not read · tunnel unreachable"])
        #expect(try summary("healthy").isEmpty)
        let refused = try #require(CLIDocuments.failure(try Vectors.data("world/error_gcloud_mismatch.json")))
        #expect(ProblemText.summary([SectionProblem(section: .read, kind: refused.kind, message: refused.message)])
            == ["read refused · gcloud identity does not match"])
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
