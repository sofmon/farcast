package cli

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// Human is the brief, terminal reading of a world document. The map is the
// full one; this says what was read, what was not, and what needs attention.
//
// Every string in it that came from the instance — a namespace, an
// application, a host, a keeper's name, a section's message — goes through
// terminalText, because a manifest, a monitor or a kubectl error chose it.
func (d worldDoc) Human(w io.Writer) error {
	in := d.Instance
	fprintf(w, "%s — %s, read %s\n", terminalText(in.Name), terminalText(orUnknown(in.Status)),
		time.Time(d.GeneratedAt).UTC().Format("2006-01-02 15:04 UTC"))

	switch s := in.Spend.(type) {
	case worldSpend:
		fprintf(w, "  spend      %s\n", spendLine(s))
	default:
		fprintf(w, "  spend      not read\n")
	}
	parts := make([]string, 0, len(in.Components))
	for _, c := range in.Components {
		p := c.Role + " " + strings.ReplaceAll(c.State, "_", " ")
		if c.Ready != nil && c.Desired != nil {
			p += fmt.Sprintf(" %d/%d", *c.Ready, *c.Desired)
		}
		parts = append(parts, p)
	}
	fprintf(w, "  system     %s\n", strings.Join(parts, " · "))

	apps, notReady, guarded := 0, 0, 0
	for _, g := range d.Groups {
		apps += len(g.Apps)
		for _, a := range g.Apps {
			if a.State == stateStarting {
				notReady++
			}
			if a.StoppedBy != nil {
				guarded++
			}
		}
	}
	if !hasWorkloads(in.Components) {
		// The workloads were not read: a count would read as "none".
		fprintf(w, "  apps       not read, in %s known from elsewhere\n", plural(len(d.Groups), "namespace", "namespaces"))
	} else {
		fprintf(w, "  apps       %s in %s", plural(apps, "application", "applications"), plural(len(d.Groups), "namespace", "namespaces"))
		if notReady > 0 {
			fprintf(w, ", %d not ready", notReady)
		}
		if guarded > 0 {
			fprintf(w, ", %d stopped by the cost guard", guarded)
		}
		fprintln(w)
	}
	for _, g := range d.Groups {
		label := "repository not recorded on this machine"
		if g.Provenance != nil {
			label = g.Provenance.Repository
		}
		fprintf(w, "    %-20s %s\n", terminalText(g.Namespace), terminalText(label))
	}

	counts := map[string]int{}
	for _, l := range d.Lines {
		if e, ok := l.(egressLine); ok {
			counts[e.Evidence]++
		}
	}
	fprintf(w, "  egress     %d observed, %d denied, %d declared only, to %s",
		counts[evidenceObserved], counts[evidenceDenied], counts[evidenceDeclared], plural(len(d.Hosts), "host", "hosts"))
	if in.HostsOmitted > 0 {
		fprintf(w, " (%d more not drawn)", in.HostsOmitted)
	}
	fprintln(w)
	if n, ok := in.Network.(worldNetwork); ok {
		fprintf(w, "             counts are floors, counted by one FatLine replica")
		if n.Replica != nil {
			fprintf(w, " (%s)", terminalText(*n.Replica))
		}
		if n.Since != nil {
			fprintf(w, " since %s", time.Time(*n.Since).UTC().Format("2006-01-02 15:04"))
		}
		fprintln(w)
	}

	if len(d.Alerts) > 0 {
		fprintln(w, "\nNeeds attention:")
		for _, a := range d.Alerts {
			fprintf(w, "  %-8s %s\n", a.Severity, terminalText(a.Title))
		}
	}

	var unread []string
	for _, s := range []struct {
		name string
		st   sectionStatus
	}{{"spend", d.Sections.Spend}, {"apps", d.Sections.Apps}, {"policy", d.Sections.Policy}, {"network", d.Sections.Network}, {"seal", d.Sections.Seal}} {
		if s.st.Error != nil {
			unread = append(unread, fmt.Sprintf("  %-8s %s — %s", s.name, s.st.Error.Kind, terminalText(s.st.Error.Message)))
		}
	}
	if len(unread) > 0 {
		fprintln(w, "\nNot read — unknown, which is not the same as absent:")
		for _, u := range unread {
			fprintln(w, u)
		}
	}
	caveats := append([]string{}, in.Caveats...)
	if s, ok := in.Spend.(worldSpend); ok {
		caveats = append(caveats, s.Caveats...)
	}
	if len(caveats) > 0 {
		fprintln(w, "\nCaveats:")
		for _, c := range caveats {
			fprintf(w, "  %s\n", terminalText(c))
		}
	}
	fprintln(w, "\n'farcast world <instance> -o json' is the whole document.")
	return nil
}

// spendLine says spending the way ADR 0009 decision 4 requires: confirmed and
// expected apart, never as one undifferentiated figure.
func spendLine(s worldSpend) string {
	money := func(c int64) string { return fmt.Sprintf("%s %.2f", s.Currency, float64(c)/100) }
	var b strings.Builder
	if s.HasConfirmation && s.ConfirmedCents != nil {
		fmt.Fprintf(&b, "%s confirmed", money(*s.ConfirmedCents))
		if s.ConfirmedThrough != nil {
			fmt.Fprintf(&b, " through %s", time.Time(*s.ConfirmedThrough).UTC().Format("2006-01-02"))
		}
		fmt.Fprintf(&b, " + %s expected", money(s.ExpectedCents))
	} else {
		fmt.Fprintf(&b, "%s expected · no confirmation yet", money(s.ExpectedCents))
	}
	if s.LimitCents != nil {
		fmt.Fprintf(&b, ", of the kernel's limit %s", money(*s.LimitCents))
	} else {
		b.WriteString(", the kernel published no limit")
	}
	fmt.Fprintf(&b, " (level %s)", s.Level)
	if s.Floor != nil {
		b.WriteString(", at the instance floor")
	}
	if s.CheckpointStale {
		b.WriteString(", checkpoint stale")
	}
	return b.String()
}

// hasWorkloads reports whether FarCast's own workloads were read: whether any
// component whose state is its workload's has a state. The monitor's is not
// its workload's — it is running whenever Shrike answered through the tunnel,
// whatever else was read — so it never stands for the workloads. The apps
// section's own status does not say it either: the section also fails when
// only the kernel's metered list could not be read, with every workload read.
func hasWorkloads(cs []worldComponent) bool {
	for _, c := range cs {
		if c.Role != roleMonitor && c.State != stateUnknown {
			return true
		}
	}
	return false
}

func orUnknown(s string) string {
	if s == "" {
		return stateUnknown
	}
	return s
}
