package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/manifest/parser"
	pbuild "github.com/sofmon/farcast/planck/build"
	pfetch "github.com/sofmon/farcast/planck/fetch"
	"github.com/sofmon/farcast/planck/translate"
)

// review is what an operator is shown before anything is built.
//
// [AGENTS.md] states the gate plainly: all connections are denied unless
// declared in the manifest, and the operator reviews the declarations before
// running an app. This is that review — and because [ADR 0010] moved the
// reading into the instance, it also carries the two facts that make the
// reading checkable afterwards.
//
// [ADR 0010]: ../../../../docs/adr/0010-application-image-builds.md
type review struct {
	Instance  string
	Repo      string
	Namespace string
	Manifest  parser.Manifest
	Report    pfetch.Report

	FatLineDeployed bool
	Limit           config.CostLimit
	Floor           instanceFloor

	// Live is what run read of the instance: the kernel's ledger and each
	// application's live Deployment (A23-48, A28-1).
	Live runLive
	// Notices are the deploy plan's lines that print once, before the
	// question (A23-26): the reader's warning.
	Notices []string
}

func (r review) print(w io.Writer) {
	fprintf(w, "\n%s, read inside %q:\n\n", r.Repo, r.Instance)
	fprintf(w, "  commit    %s\n", r.Report.Commit)
	fprintf(w, "  manifest  %s\n", r.Report.ManifestDigest)
	fprintf(w, "\nThis machine did not clone the repository. Those two values are what any\n")
	fprintf(w, "machine that can reach it may check independently.\n")

	fprintf(w, "\n%s in %q", plural(len(r.Manifest.Apps), "application", "applications"), r.Manifest.Name)
	if r.Namespace != r.Manifest.Name {
		// Worth saying out loud: the manifest names one thing and this is
		// going somewhere else, which is the whole point of --namespace and
		// also the way to deploy over the wrong deployment by accident.
		fprintf(w, ", deploying into namespace %q instead", r.Namespace)
	}
	fprintln(w, ":")

	for _, app := range r.Manifest.Apps {
		fprintf(w, "\n  %s\n", app.Name)
		// Paths are the repository's text too, and the parser rules out only
		// absolute ones and "..", so they go through terminalText as well.
		fprintf(w, "    build   %s", terminalText(app.Containerfile))
		// A context of "." is the repository root, which is the default.
		// Printing it adds a word and no information.
		if c := strings.Trim(app.Context, "./"); c != "" {
			fprintf(w, "  (context %s)", terminalText(app.Context))
		}
		fprintln(w)
		printDeclared(w, app.External)
	}

	fprintf(w, "\nThose hosts are the whole of what these applications may reach. FatLine denies\n")
	fprintf(w, "every other outbound address, and Shrike reports anything that tries.\n")

	if line := noWayOutWarning(r.Instance, r.Manifest, r.FatLineDeployed); line != "" {
		fprintf(w, "\n%s\n", line)
	}

	r.printCost(w)
	r.printResets(w)
	for _, line := range r.Notices {
		fprintf(w, "\n%s\n", line)
	}
}

// noWayOutWarning is the warning that the hosts a manifest declares are
// unreachable while the instance has no FatLine, or "" when it has one or
// they declare none. The review prints it in its place, and a deploy plan
// carries it as a notice (A28-8).
func noWayOutWarning(instance string, m parser.Manifest, fatlineDeployed bool) string {
	declared := 0
	for _, app := range m.Apps {
		declared += len(app.External)
	}
	if declared == 0 || fatlineDeployed {
		return ""
	}
	return fmt.Sprintf("WARNING: FatLine is not deployed in %q, and it is the only way out.\n"+
		"The hosts above will be unreachable until 'farcast connect %s' has run.", instance, instance)
}

// printResets says, after the cost, what this deploy resets of what runs
// now, one line per application (A23-48), and, while the instance's
// spending reads as at its limit, that this deploy adds to it (A28-1).
func (r review) printResets(w io.Writer) {
	first := true
	for _, a := range r.Live.Apps {
		line := a.resetLine()
		if line == "" {
			continue
		}
		if first {
			fprintf(w, "\nResets:\n")
			first = false
		}
		fprintf(w, "  %s\n", line)
	}
	if r.Live.Limit.Reached {
		fprintf(w, "\n%s\n", limitLine(r.Live.Limit.Reason))
	}
}

// printDeclared prints what one application may reach, one host per line with
// the reason the manifest gives for it, in the order the manifest declares them.
//
// The review and the run's result both print through this, so what the
// operator approved and what the result says was allowed are the same lines,
// byte for byte. Both are the operator's record; two formats would be two
// things to compare.
//
// The reason is the repository's free text and goes through terminalText; the
// host is validated by the parser and goes through it anyway, because the
// printer should not have to know that.
func printDeclared(w io.Writer, ext []parser.External) {
	if len(ext) == 0 {
		fprintf(w, "    reaches nothing outside the instance\n")
		return
	}
	for _, e := range ext {
		fprintf(w, "    → %-34s %s\n", terminalText(e.Host), terminalText(e.Reason))
	}
}

// printCost says what approving this will cost, in the two ways it costs:
// once for the builds, and every month for what is left running.
func (r review) printCost(w io.Writer) {
	n := len(r.Manifest.Apps)
	currency := r.Limit.Currency
	if currency == "" {
		currency = "USD"
	}

	standing := applicationsMonthlyUSD(n)
	fprintf(w, "\nCost:\n")
	fprintf(w, "  building   %s, one at a time, each asking %dm CPU and %dMi with a %d-minute deadline\n",
		plural(n, "Job", "Jobs"), pbuild.RequestCPUMilli, pbuild.RequestMemMiB, pbuild.DeadlineSeconds/60)
	fprintf(w, "  running    ~%s %.2f/mo for %s at %dm/%dMi\n",
		currency, standing, plural(n, "application", "applications"),
		translate.RequestCPUMilli, translate.RequestMemMiB)
	fprintf(w, "  instance   ~%s %.2f/mo standing, before these\n", currency, r.Floor.Total)

	// The floor check the operator already met at install time, asked again
	// with the applications in it. This is the first moment the answer can
	// change, because it is the first moment an instance has applications.
	warnIfBelowFloor(w, r.Limit, withApplications(r.Floor, n), "this instance with these applications")
}

// withApplications is floor with n translated applications in it, standing:
// the floor run's review and its deploy plan state.
func withApplications(floor instanceFloor, n int) instanceFloor {
	floor.add("applications", applicationsMonthlyUSD(n), fmt.Sprintf("%s (TechnoCore adapts these at 5.2)",
		plural(n, "translated workload", "translated workloads")))
	return floor
}

// plural is "1 application" or "3 applications"; noun is just the word.
func plural(n int, one, many string) string {
	return fmt.Sprintf("%d %s", n, noun(n, one, many))
}

func noun(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
