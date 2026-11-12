package rehearsal

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"
)

// Summarize reads a world document, or the CLI's error envelope, and writes
// only its shape: the walk's scrub tool, so a live read can be recorded
// without recording what it read (D9).
//
// It prints the schema, the date the document was made, the instance's
// status, each section's outcome, counts — of groups, apps, hosts, and lines
// by kind and evidence — the alert kinds with their counts, the number of
// caveats, and whether spend and network were read. Every word it prints is
// either a number or a value from a closed set the CLI's README fixes; any
// other value is printed as "other". So it never prints a name, a host, a
// repository, a commit, a replica, a message, a title or a time of day,
// whatever the document holds.
func Summarize(r io.Reader, w io.Writer) error {
	data, err := io.ReadAll(io.LimitReader(r, 64<<20))
	if err != nil {
		return err
	}
	var head map[string]json.RawMessage
	if err := json.Unmarshal(data, &head); err != nil {
		return errors.New("not a JSON object: neither a world document nor farcast's error envelope")
	}
	if raw, ok := head["error"]; ok {
		var env struct {
			Kind string `json:"kind"`
			Code int    `json:"code"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			return errors.New("an error envelope that does not parse")
		}
		_, err := fmt.Fprintf(w, "error: kind %s, exit %d\n", closed(env.Kind, errorKinds), env.Code)
		return err
	}

	var doc struct {
		Schema      *int   `json:"schema"`
		GeneratedAt string `json:"generated_at"`
		Instance    struct {
			Status       string `json:"status"`
			CloudLogging string `json:"cloud_logging"`
			Spend        struct {
				Read            bool   `json:"read"`
				Level           string `json:"level"`
				HasConfirmation bool   `json:"has_confirmation"`
				CheckpointStale bool   `json:"checkpoint_stale"`
			} `json:"spend"`
			Network struct {
				Read            bool `json:"read"`
				FatLineReplicas *int `json:"fatline_replicas"`
			} `json:"network"`
			Components []struct {
				Role  string `json:"role"`
				State string `json:"state"`
			} `json:"components"`
			HostsOmitted int               `json:"hosts_omitted"`
			Caveats      []json.RawMessage `json:"caveats"`
		} `json:"instance"`
		Groups []struct {
			Apps []struct {
				State string `json:"state"`
			} `json:"apps"`
		} `json:"groups"`
		Hosts []json.RawMessage `json:"hosts"`
		Lines []struct {
			Kind     string `json:"kind"`
			Evidence string `json:"evidence"`
		} `json:"lines"`
		Devices []struct {
			Role   string `json:"role"`
			Health string `json:"health"`
		} `json:"devices"`
		Alerts []struct {
			Kind     string `json:"kind"`
			Severity string `json:"severity"`
		} `json:"alerts"`
		Sections map[string]struct {
			Read    bool   `json:"read"`
			Skipped string `json:"skipped"`
			Error   *struct {
				Kind string `json:"kind"`
			} `json:"error"`
		} `json:"sections"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return errors.New("a document that does not parse as a world document")
	}

	var b strings.Builder
	schema := "none"
	if doc.Schema != nil {
		schema = fmt.Sprint(*doc.Schema)
	}
	day := "unreadable"
	if t, err := time.Parse(time.RFC3339, doc.GeneratedAt); err == nil {
		day = t.UTC().Format("2006-01-02")
	}
	fmt.Fprintf(&b, "schema %s · generated %s · status %s · cloud logging %s\n",
		schema, day, closed(doc.Instance.Status, statuses), closed(doc.Instance.CloudLogging, cloudLoggings))

	parts := []string{}
	for _, name := range sectionNames {
		s, ok := doc.Sections[name]
		switch {
		case !ok:
			parts = append(parts, name+" absent")
		case s.Error != nil:
			parts = append(parts, name+" "+closed(s.Error.Kind, errorKinds))
		case s.Skipped != "":
			parts = append(parts, name+" skipped ("+closed(s.Skipped, skips)+")")
		case s.Read:
			parts = append(parts, name+" read")
		default:
			parts = append(parts, name+" not read")
		}
	}
	fmt.Fprintf(&b, "sections: %s\n", strings.Join(parts, " · "))

	sp := doc.Instance.Spend
	if sp.Read {
		fmt.Fprintf(&b, "spend: read · level %s · confirmation %s · checkpoint %s\n",
			closed(sp.Level, levels), yesNo(sp.HasConfirmation, "yes", "none yet"), yesNo(sp.CheckpointStale, "stale", "fresh"))
	} else {
		b.WriteString("spend: not read\n")
	}
	if nw := doc.Instance.Network; nw.Read {
		replicas := "unknown"
		if nw.FatLineReplicas != nil {
			replicas = fmt.Sprint(*nw.FatLineReplicas)
		}
		fmt.Fprintf(&b, "network: read · FatLine replicas %s\n", replicas)
	} else {
		b.WriteString("network: not read\n")
	}

	comps := []string{}
	for _, c := range doc.Instance.Components {
		comps = append(comps, closed(c.Role, roles)+" "+closed(c.State, states))
	}
	fmt.Fprintf(&b, "components: %s\n", orNone(comps))

	apps := map[string]int{}
	nApps := 0
	for _, g := range doc.Groups {
		for _, a := range g.Apps {
			apps[closed(a.State, states)]++
			nApps++
		}
	}
	fmt.Fprintf(&b, "groups %d · apps %d (%s) · hosts %d · hosts omitted %d\n",
		len(doc.Groups), nApps, orNone(counted(apps)), len(doc.Hosts), doc.Instance.HostsOmitted)

	lines := map[string]int{}
	for _, l := range doc.Lines {
		lines[closed(l.Kind, lineKinds)+" "+closed(l.Evidence, evidences)]++
	}
	fmt.Fprintf(&b, "lines %d: %s\n", len(doc.Lines), orNone(counted(lines)))

	devices := map[string]int{}
	for _, d := range doc.Devices {
		k := closed(d.Role, deviceRoles)
		if d.Health != "" {
			k += " " + closed(d.Health, healths)
		}
		devices[k]++
	}
	fmt.Fprintf(&b, "devices %d: %s\n", len(doc.Devices), orNone(counted(devices)))

	alerts := map[string]int{}
	for _, a := range doc.Alerts {
		alerts[closed(a.Kind, alertKinds)+" ("+closed(a.Severity, severities)+")"]++
	}
	fmt.Fprintf(&b, "alerts %d: %s\n", len(doc.Alerts), orNone(counted(alerts)))
	fmt.Fprintf(&b, "caveats %d\n", len(doc.Instance.Caveats))
	_, err = io.WriteString(w, b.String())
	return err
}

// The closed sets, as farsight/cli/README.md fixes them.
var (
	sectionNames = []string{"spend", "apps", "policy", "network", "seal"}
	errorKinds   = []string{
		"record_unreadable", "not_found", "not_connected", "tunnel_unreachable", "kernel_absent", "not_checkpointed",
		"version_skew", "kubectl_missing", "kubectl_failed", "gcloud_mismatch", "gcloud_signed_out", "auth_tool_missing",
		"timeout", "internal",
	}
	statuses      = []string{"provisioning", "running", "unreachable", "deleting", "error"}
	cloudLoggings = []string{"system_only", "unverified", "unknown"}
	levels        = []string{"ok", "warn50", "warn75", "warn90", "reached", "unknown"}
	states        = []string{"running", "starting", "stopped", "not_deployed", "unknown"}
	skips         = []string{"not_deployed"}
	roles         = []string{"boundary", "monitor", "kernel", "storage"}
	lineKinds     = []string{"egress", "tunnel", "keeper", "watch", "storage"}
	evidences     = []string{"observed", "denied", "declared", "planned"}
	deviceRoles   = []string{"operator", "keeper"}
	healths       = []string{"healthy", "expired", "revoked", "unseen", "unknown"}
	alertKinds    = []string{
		"cost", "checkpoint_stale", "sealed", "denied", "unattributed_denials", "not_ready", "keeper",
		"unmetered_namespace", "logging_unverified", "release_incomplete", "hosts_omitted", "drift",
	}
	severities = []string{"critical", "warning"}
)

// closed is v when it is one of set, and "other" otherwise.
func closed(v string, set []string) string {
	if slices.Contains(set, v) {
		return v
	}
	return "other"
}

func yesNo(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}

func orNone(parts []string) string {
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, " · ")
}

// counted is "key n" for each key, sorted.
func counted(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k, n := range m {
		out = append(out, fmt.Sprintf("%s %d", k, n))
	}
	sort.Strings(out)
	return out
}
