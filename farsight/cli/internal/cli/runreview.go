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

	var declared int
	for _, app := range r.Manifest.Apps {
		fprintf(w, "\n  %s\n", app.Name)
		fprintf(w, "    build   %s", app.Containerfile)
		// A context of "." is the repository root, which is the default.
		// Printing it adds a word and no information.
		if c := strings.Trim(app.Context, "./"); c != "" {
			fprintf(w, "  (context %s)", app.Context)
		}
		fprintln(w)
		if len(app.External) == 0 {
			fprintf(w, "    reaches nothing outside the instance\n")
			continue
		}
		declared += len(app.External)
		for _, e := range app.External {
			fprintf(w, "    → %-34s %s\n", e.Host, e.Reason)
		}
	}

	fprintf(w, "\nThose hosts are the whole of what these applications may reach. FatLine denies\n")
	fprintf(w, "every other outbound address, and Shrike reports anything that tries.\n")

	if declared > 0 && !r.FatLineDeployed {
		fprintf(w, "\nWARNING: FatLine is not deployed in %q, and it is the only way out.\n", r.Instance)
		fprintf(w, "The hosts above will be unreachable until 'farcast connect %s' has run.\n", r.Instance)
	}

	r.printCost(w)
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
	with := r.Floor
	with.add("applications", standing, fmt.Sprintf("%s (TechnoCore adapts these at 5.2)",
		plural(n, "translated workload", "translated workloads")))
	warnIfBelowFloor(w, r.Limit, with, "this instance with these applications")
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
