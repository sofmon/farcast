package cli

import (
	"cmp"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/fatline/event"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
)

// The second half of the world builder: hosts and the lines to them, the
// operator's and keepers' devices, alerts, and the document's final order.

// hostsAndEgress draws each host once, the strongest evidence first and then
// by name, up to the cap — and an egress line from each application to each
// host it reached, was refused, or declares. Hosts past the cap are not drawn,
// and neither are their lines: both are counted, never silently lost.
func (b *worldBuilder) hostsAndEgress() {
	strength := map[string]int{}
	for _, e := range b.egress {
		r := strongestRank(e.ports)
		if cur, ok := strength[e.host]; !ok || r < cur {
			strength[e.host] = r
		}
	}
	names := keysSorted(strength)
	sort.SliceStable(names, func(i, j int) bool {
		if strength[names[i]] != strength[names[j]] {
			return strength[names[i]] < strength[names[j]]
		}
		return names[i] < names[j]
	})
	kept := map[string]bool{}
	b.doc.Hosts = make([]worldHost, 0, min(len(names), hostCap))
	for i, n := range names {
		if i >= hostCap {
			b.doc.Instance.HostsOmitted++
			continue
		}
		kept[n] = true
		seen := []string{}
		for raw := range b.hostSeen[n] {
			if raw != n {
				seen = append(seen, raw)
			}
		}
		sort.Strings(seen)
		b.doc.Hosts = append(b.doc.Hosts, worldHost{Name: n, SeenAs: seen})
	}

	since := optTime(b.in.Network.Snapshot.Since)
	for _, key := range keysSorted(b.egress) {
		e := b.egress[key]
		if !kept[e.host] {
			continue
		}
		slices.SortStableFunc(e.ports, comparePorts)
		var last time.Time
		counted := false
		for _, p := range e.ports {
			if p.Evidence == evidenceDeclared {
				continue
			}
			counted = true
			if p.LastSeen != nil && time.Time(*p.LastSeen).After(last) {
				last = time.Time(*p.LastSeen)
			}
		}
		line := egressLine{
			Kind: "egress", From: lineEnd{App: e.tenant}, To: lineEnd{Host: e.host},
			Evidence: e.ports[0].Evidence, Ports: e.ports, LastSeen: optTime(last),
			Stale: counted && !b.recent(last),
		}
		if counted && b.networkRead() {
			line.Since = since
		}
		if b.policyRead() {
			line.Drift = ptr(e.drift)
		}
		b.lines = append(b.lines, lineEntry{key: lineKey("egress", e.tenant, e.host), body: line})
	}
}

func strongestRank(ports []linePort) int {
	best := evidenceRank(evidenceDeclared)
	for _, p := range ports {
		best = min(best, evidenceRank(p.Evidence))
	}
	return best
}

// comparePorts orders a line's port entries: strongest evidence first, then
// by port (unknown last), then by reason.
func comparePorts(a, b linePort) int {
	if c := cmp.Compare(evidenceRank(a.Evidence), evidenceRank(b.Evidence)); c != 0 {
		return c
	}
	switch {
	case a.Port == nil && b.Port != nil:
		return 1
	case a.Port != nil && b.Port == nil:
		return -1
	case a.Port != nil && b.Port != nil && *a.Port != *b.Port:
		return cmp.Compare(*a.Port, *b.Port)
	}
	ar, br := "", ""
	if a.Reason != nil {
		ar = *a.Reason
	}
	if b.Reason != nil {
		br = *b.Reason
	}
	return cmp.Compare(ar, br)
}

// keeperID is a keeper device's id: the instance and the device's name.
func keeperID(instance, device string) string { return instance + "/" + device }

// devicesAndKeepers draws the operator, every keeper this machine enrolled,
// and the lines the tunnel read can vouch for: the read itself, the monitor
// watching the boundary, and each keeper's streams into storage.
func (b *worldBuilder) devicesAndKeepers() {
	b.doc.Devices = []worldDevice{{ID: "operator", Role: "operator"}}
	net := b.in.Network
	snap := net.Snapshot

	if net.Tunnel {
		b.lines = append(b.lines, lineEntry{
			key: lineKey("tunnel", "device:operator", "component:"+roleBoundary),
			body: tunnelLine{Kind: "tunnel", From: lineEnd{Device: "operator"}, To: lineEnd{Component: roleBoundary},
				Evidence: evidenceObserved, LabelHint: "read_now"},
		})
	}
	if b.networkRead() {
		b.lines = append(b.lines, lineEntry{
			key: lineKey("watch", "component:"+roleMonitor, "component:"+roleBoundary),
			body: watchLine{Kind: "watch", From: lineEnd{Component: roleMonitor}, To: lineEnd{Component: roleBoundary},
				Evidence: evidenceObserved, Since: optTime(snap.Since)},
		})
	}

	// Which keeper each tunnel row belongs to, by the leaf token this machine
	// recorded when it enrolled the device. A row no device here issued is
	// counted, and drawn as nothing.
	lastByDevice := map[string]time.Time{}
	unnamed := map[string]bool{}
	if b.networkRead() {
		for _, row := range snap.Tunnel {
			switch row.Role {
			case event.PeerOperator:
				if net.OperatorToken != "" && row.Peer != net.OperatorToken {
					unnamed[row.Role+"\x00"+row.Peer] = true
				}
				continue
			case event.PeerKeeper:
				if k := keeperByToken(b.meta.Keepers, row.Peer); k != nil {
					id := keeperID(b.in.Name, k.Device)
					if prev, ok := lastByDevice[id]; !ok || row.LastSeen.After(prev) {
						lastByDevice[id] = row.LastSeen
					}
					continue
				}
			}
			unnamed[row.Role+"\x00"+row.Peer] = true
		}
	}
	if n := len(unnamed); n > 0 {
		b.caveats = append(b.caveats, fmt.Sprintf("%s not enrolled from this machine",
			plural(n, "tunnel peer is", "tunnel peers are")))
	}

	seen := map[string]bool{}
	for _, k := range b.meta.Keepers {
		id := keeperID(b.in.Name, k.Device)
		if k.Device == "" || seen[id] {
			continue
		}
		seen[id] = true
		last, hasRow := lastByDevice[id]
		b.doc.Devices = append(b.doc.Devices, worldDevice{
			ID: id, Role: "keeper", Name: k.Device, Health: b.keeperHealth(k, last, hasRow),
		})
		if hasRow {
			b.lines = append(b.lines, lineEntry{
				key: lineKey("keeper", "device:"+id, "component:"+roleStorage),
				// Stale by the window health uses, not the egress hour:
				// a keeper streams only when it re-seeds, and a line that
				// called a healthy keeper stale would contradict its own
				// device.
				body: keeperLine{Kind: "keeper", From: lineEnd{Device: id}, To: lineEnd{Component: roleStorage},
					Evidence: evidenceObserved, LastSeen: optTime(last), Stale: !b.within(last, keeperSeenWithin)},
			})
		}
	}
}

// keeperByToken is the keeper this machine issued a leaf with this token to.
func keeperByToken(keepers []config.Keeper, token string) *config.Keeper {
	if token == "" {
		return nil
	}
	for i := range keepers {
		if slices.Contains(keepers[i].LeafTokens, token) {
			return &keepers[i]
		}
	}
	return nil
}

// keeperHealth is what can honestly be said of a keeper.
//
// Revoked and expired come from this machine's record. Healthy is a tunnel
// row of its own within the last day. Unseen — no row in a day — is claimed
// only when the absence means something: the picture covers a whole day, the
// device has a leaf this machine can recognise, and there is one FatLine
// replica, so the row could not be sitting in another replica's picture.
// Anything else is unknown.
func (b *worldBuilder) keeperHealth(k config.Keeper, last time.Time, hasRow bool) string {
	switch {
	case k.Revoked:
		return "revoked"
	case !k.Expires.IsZero() && !b.now.Before(k.Expires.UTC().Truncate(time.Second)):
		return "expired"
	case !b.networkRead():
		return stateUnknown
	case hasRow && b.within(last, keeperSeenWithin):
		return "healthy"
	}
	since := b.in.Network.Snapshot.Since
	if !since.IsZero() && !since.UTC().Truncate(time.Second).After(b.now.Add(-keeperSeenWithin)) &&
		len(k.LeafTokens) > 0 && b.fatlineDesired != nil && *b.fatlineDesired == 1 {
		return "unseen"
	}
	return stateUnknown
}

func (b *worldBuilder) alert(kind, severity string, subject alertSubject, discriminator, title string) {
	id := kind + ":" + subject.key()
	if discriminator != "" {
		id += ":" + discriminator
	}
	b.alerts = append(b.alerts, worldAlert{ID: id, Kind: kind, Severity: severity, Subject: subject, Title: title})
}

func (b *worldBuilder) raiseAlerts() {
	instance := alertSubject{Instance: true}

	if s := b.spendBody; s != nil {
		switch s.Level {
		case "warn75":
			b.alert("cost", severityWarning, instance, "", "Spending has passed 75% of the kernel's limit")
		case "warn90":
			b.alert("cost", severityWarning, instance, "", "Spending has passed 90% of the kernel's limit")
		case "reached":
			b.alert("cost", severityCritical, instance, "", "Spending has reached the kernel's limit")
		}
		if s.CheckpointStale {
			b.alert("checkpoint_stale", severityCritical, alertSubject{Component: roleKernel}, "",
				"The kernel has not checkpointed for more than 15 minutes")
		}
	}

	b.sealedAlert()

	if b.networkRead() {
		perApp := map[string]int64{}
		var unattributed int64
		for _, v := range b.in.Network.Snapshot.Violations {
			if !b.recent(v.LastSeen) {
				continue
			}
			// A refusal is the app's when the app is on this map. One that
			// names no application, or one the map holds no group for —
			// farcast-system's — is the boundary's: an alert never names
			// an app the document does not draw.
			if v.App == "" || v.Namespace == "" || b.app(v.Namespace, v.App) == nil {
				unattributed += v.Count
				continue
			}
			perApp[tenantOf(v.Namespace, v.App)] += v.Count
		}
		for _, tenant := range keysSorted(perApp) {
			if perApp[tenant] > 0 {
				b.alert("denied", severityWarning, alertSubject{App: tenant}, "",
					fmt.Sprintf("FatLine refused %s's egress in the last hour (%s, at least)", tenant,
						plural(int(perApp[tenant]), "attempt", "attempts")))
			}
		}
		if unattributed > 0 {
			b.alert("unattributed_denials", severityWarning, alertSubject{Component: roleBoundary}, "",
				fmt.Sprintf("FatLine refused %s in the last hour that it could not tie to an application on this map (at least)",
					plural(int(unattributed), "connection", "connections")))
		}
	}

	for _, ns := range keysSorted(b.groups) {
		g := b.groups[ns]
		for _, a := range g.Apps {
			if a.State == stateStarting {
				b.alert("not_ready", severityWarning, alertSubject{App: tenantOf(ns, a.Name)}, "",
					fmt.Sprintf("%s has %d of %d replicas ready", tenantOf(ns, a.Name), *a.Ready, *a.Desired))
			}
		}
		if g.Metered != nil && !*g.Metered {
			b.alert("unmetered_namespace", severityWarning, alertSubject{Component: roleKernel}, ns,
				fmt.Sprintf("%s is not metered: its spending is not counted against the limit", ns))
		}
	}

	for _, d := range b.doc.Devices {
		title := ""
		switch d.Health {
		case "expired":
			title = fmt.Sprintf("Keeper %s's leaf has expired: it can no longer re-seed storage", d.Name)
		case "revoked":
			title = fmt.Sprintf("Keeper %s is revoked; its leaf stays valid in the cluster until it expires", d.Name)
		case "unseen":
			title = fmt.Sprintf("Keeper %s has not been seen through the tunnel for a day", d.Name)
		}
		if title != "" {
			b.alert("keeper", severityWarning, alertSubject{Device: d.ID}, "", title)
		}
	}

	if b.doc.Instance.CloudLogging == "unverified" {
		b.alert("logging_unverified", severityWarning, instance, "",
			"The provider's logging of this cluster was never verified to be system logs only")
	}
	if b.meta.Status == config.InstanceDeleting {
		b.alert("release_incomplete", severityCritical, instance, "",
			"A release did not finish: this instance may still be billing")
	}
	if n := b.doc.Instance.HostsOmitted; n > 0 {
		b.alert("hosts_omitted", severityWarning, alertSubject{Component: roleBoundary}, "",
			fmt.Sprintf("%s past the first %d are not drawn", plural(n, "host", "hosts"), hostCap))
	}
	drifted := map[string]bool{}
	for _, e := range b.egress {
		if e.drift {
			drifted[e.tenant] = true
		}
	}
	for _, tenant := range keysSorted(drifted) {
		b.alert("drift", severityWarning, alertSubject{App: tenant}, "",
			fmt.Sprintf("%s reached a host its egress policy does not declare", tenant))
	}
}

// sealedAlert is raised when any replica that answered holds no key material.
func (b *worldBuilder) sealedAlert() {
	if b.in.Seal.Skipped || b.in.Seal.Problem != nil {
		return
	}
	sealed, held := 0, 0
	for _, r := range b.in.Seal.Replicas {
		if r.State == nil || !r.State.Sealed() {
			continue
		}
		sealed++
		if r.State.Phase == "operator-hold" {
			held++
		}
	}
	if sealed == 0 {
		return
	}
	total := len(b.in.Seal.Replicas)
	title := fmt.Sprintf("Storage is sealed on %d of %d replicas", sealed, total)
	if held > 0 {
		title += fmt.Sprintf(", %d under an operator hold", held)
	}
	b.alert("sealed", severityCritical, alertSubject{Component: roleStorage}, "", title)
}

func (b *worldBuilder) sections() {
	s := &b.doc.Sections
	if p := b.in.Apps.Problem; p != nil {
		s.Apps = sectionStatus{Error: b.problem(p)}
	} else if p := b.in.Apps.Meter.Problem; p != nil {
		s.Apps = sectionStatus{Error: b.problem(p)}
	} else {
		s.Apps = sectionStatus{Read: true}
	}
	if p := b.in.Policy.Problem; p != nil {
		s.Policy = sectionStatus{Error: b.problem(p)}
	} else {
		s.Policy = sectionStatus{Read: true}
	}
	if p := b.in.Network.Problem; p != nil {
		s.Network = sectionStatus{Error: b.problem(p)}
	} else {
		s.Network = sectionStatus{Read: true}
	}
	switch seal := b.in.Seal; {
	case seal.Skipped:
		s.Seal = sectionStatus{Skipped: stateNotDeployed}
	case seal.Problem != nil:
		s.Seal = sectionStatus{Error: b.problem(seal.Problem)}
	default:
		s.Seal = sectionStatus{Read: true}
		for _, r := range seal.Replicas {
			if r.Problem != nil {
				s.Seal = sectionStatus{Error: b.problem(&sectionProblem{
					Kind: r.Problem.Kind, Message: fmt.Sprintf("replica %d: %s", r.Ordinal, r.Problem.Message)})}
				break
			}
		}
	}
}

func (b *worldBuilder) finish() {
	d := &b.doc
	d.Groups = make([]worldGroup, 0, len(b.groups))
	for _, ns := range keysSorted(b.groups) {
		g := *b.groups[ns]
		sort.Slice(g.Apps, func(i, j int) bool { return g.Apps[i].Name < g.Apps[j].Name })
		d.Groups = append(d.Groups, g)
	}
	sort.Slice(b.lines, func(i, j int) bool { return b.lines[i].key < b.lines[j].key })
	d.Lines = make([]any, 0, len(b.lines))
	for _, l := range b.lines {
		d.Lines = append(d.Lines, l.body)
	}
	sort.Slice(d.Devices, func(i, j int) bool { return d.Devices[i].ID < d.Devices[j].ID })
	sort.Slice(b.alerts, func(i, j int) bool {
		ri, rj := severityRank(b.alerts[i].Severity), severityRank(b.alerts[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return b.alerts[i].ID < b.alerts[j].ID
	})
	d.Alerts = append([]worldAlert{}, b.alerts...)
	for _, ns := range keysSorted(b.undrawn) {
		where := "no namespace, and are not drawn"
		switch ns {
		case "":
		case tcdeploy.DefaultNamespace:
			where = ns + ", which holds FarCast's own components and is never drawn as a group"
		default:
			where = ns + " with no application named, and are not drawn"
		}
		b.caveats = append(b.caveats, fmt.Sprintf("%s name %s",
			plural(b.undrawn[ns], "policy or monitor row", "policy or monitor rows"), where))
	}
	d.Instance.Caveats = sortedUnique(b.caveats)
	if b.spendBody != nil {
		b.spendBody.Caveats = sortedUnique(b.spendCaveats)
		d.Instance.Spend = *b.spendBody
	}
	if b.networkRead() {
		snap := b.in.Network.Snapshot
		n := worldNetwork{Read: true, Since: optTime(snap.Since), FatLineReplicas: b.fatlineDesired}
		if snap.Replica != "" {
			n.Replica = ptr(snap.Replica)
		}
		d.Instance.Network = n
	}
	if d.Hosts == nil {
		d.Hosts = []worldHost{}
	}
}

func severityRank(s string) int {
	if s == severityCritical {
		return 0
	}
	return 1
}

// sortedUnique is ss sorted with repeats removed, and never nil.
func sortedUnique(ss []string) []string {
	out := append([]string{}, ss...)
	sort.Strings(out)
	return slices.Compact(out)
}
