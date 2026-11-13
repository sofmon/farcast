package cli

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// Properties every world vector must hold, whatever its case: what the map's
// validation will check, and what the wire rules promise.

// arrayKeys are the keys whose value is always a JSON array — empty, never
// null.
var arrayKeys = map[string]bool{
	"groups": true, "hosts": true, "lines": true, "devices": true, "alerts": true, "apps": true,
	"ports": true, "components": true, "seen_as": true, "not_metered": true, "caveats": true, "instances": true,
	"levers": true,
}

func walkJSON(t *testing.T, path string, v any, visit func(path, key string, v any)) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			visit(path, k, child)
			walkJSON(t, path+"."+k, child, visit)
		}
	case []any:
		for _, child := range x {
			walkJSON(t, path+"[]", child, visit)
		}
	}
}

var rfc3339Seconds = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)

func TestEveryVectorKeepsTheWireRules(t *testing.T) {
	for _, v := range worldVectors() {
		t.Run(v.name, func(t *testing.T) {
			raw := vectorBytes(t, buildWorld(v.inputs(t)))
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			walkJSON(t, "", doc, func(path, key string, val any) {
				if arrayKeys[key] && path != ".sections" {
					if _, ok := val.([]any); !ok {
						t.Errorf("%s.%s is %v, not an array", path, key, val)
					}
				}
				// Times are absolute, UTC, whole seconds.
				if s, ok := val.(string); ok && (strings.HasSuffix(key, "_at") || key == "since" || key == "last_seen" ||
					key == "confirmed_through" || key == "period_start" || key == "period_end") {
					if !rfc3339Seconds.MatchString(s) {
						t.Errorf("%s.%s = %q is not RFC 3339 UTC to the second", path, key, s)
					}
				}
				// Money is integer cents.
				if strings.HasSuffix(key, "_cents") && val != nil {
					if f, ok := val.(float64); !ok || f != float64(int64(f)) {
						t.Errorf("%s.%s = %v is not integer cents", path, key, val)
					}
				}
				// What the document never carries.
				if key == "credential_sha256" || key == "endpoint" || key == "project" || key == "cluster" || key == "bucket" {
					t.Errorf("%s carries %q", path, key)
				}
			})
			for _, never := range []string{"proj-atlas", "203.0.113.7", "gke-1a2b3c", "farcast-atlas-5f3a9c21", "operator@example.org", "planned"} {
				if strings.Contains(string(raw), never) {
					t.Errorf("the document carries %q", never)
				}
			}
		})
	}
}

// Every app, host, device and component a line or an alert names is in the
// document: the map validates exactly this, and refuses an instance whose
// world points at nothing.
func TestEveryVectorIsClosed(t *testing.T) {
	for _, v := range worldVectors() {
		t.Run(v.name, func(t *testing.T) {
			doc := buildWorld(v.inputs(t))
			apps, hosts, devices, roles := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
			for _, g := range doc.Groups {
				if g.Namespace == "farcast-system" {
					t.Error("the system namespace is a group")
				}
				for _, a := range g.Apps {
					apps[tenantOf(g.Namespace, a.Name)] = true
				}
			}
			for _, h := range doc.Hosts {
				hosts[h.Name] = true
			}
			for _, d := range doc.Devices {
				devices[d.ID] = true
			}
			for _, c := range doc.Instance.Components {
				roles[c.Role] = true
			}
			if !devices["operator"] || len(roles) != 4 {
				t.Errorf("devices %v, roles %v", devices, roles)
			}
			check := func(what string, e lineEnd) {
				switch {
				case e.App != "" && !apps[e.App]:
					t.Errorf("%s names app %q, not in any group", what, e.App)
				case e.Host != "" && !hosts[e.Host]:
					t.Errorf("%s names host %q, not in hosts", what, e.Host)
				case e.Device != "" && !devices[e.Device]:
					t.Errorf("%s names device %q, not in devices", what, e.Device)
				case e.Component != "" && !roles[e.Component]:
					t.Errorf("%s names component %q", what, e.Component)
				}
			}
			seen := map[string]bool{}
			for _, l := range doc.Lines {
				raw, _ := json.Marshal(l)
				var line struct {
					Kind     string     `json:"kind"`
					From     lineEnd    `json:"from"`
					To       lineEnd    `json:"to"`
					Evidence string     `json:"evidence"`
					Ports    []linePort `json:"ports"`
				}
				if err := json.Unmarshal(raw, &line); err != nil {
					t.Fatal(err)
				}
				id := lineKey(line.Kind, line.From.App+line.From.Device+line.From.Component, line.To.Host+line.To.Component)
				if seen[id] {
					t.Errorf("two %s lines from %+v to %+v", line.Kind, line.From, line.To)
				}
				seen[id] = true
				check(line.Kind+" line", line.From)
				check(line.Kind+" line", line.To)
				if !slices.Contains([]string{evidenceObserved, evidenceDenied, evidenceDeclared}, line.Evidence) {
					t.Errorf("a line with evidence %q", line.Evidence)
				}
				if line.Kind == "egress" && (len(line.Ports) == 0 || line.Ports[0].Evidence != line.Evidence) {
					t.Errorf("an egress line's evidence is not its strongest port's: %s", raw)
				}
			}
			ids := map[string]bool{}
			for _, a := range doc.Alerts {
				if ids[a.ID] {
					t.Errorf("two alerts share id %q", a.ID)
				}
				ids[a.ID] = true
				check("alert "+a.ID, lineEnd{App: a.Subject.App, Device: a.Subject.Device, Component: a.Subject.Component})
			}
		})
	}
}

// One vector's source times carry nanoseconds; on the wire there are none.
func TestTimesAreTruncatedToTheSecond(t *testing.T) {
	in := healthyInputs(t)
	if in.Network.Snapshot.Since.Nanosecond() == 0 || in.Now.Nanosecond() == 0 {
		t.Fatal("guard: the healthy vector must carry nanoseconds to prove anything")
	}
	raw, err := os.ReadFile("testdata/world/healthy.json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"since":"2026-11-11T08:00:00Z"`) || strings.Contains(string(raw), ".123") {
		t.Errorf("the healthy vector's times are not whole seconds")
	}
	b, _ := json.Marshal(optTime(time.Date(2026, 1, 2, 3, 4, 5, 999999999, time.FixedZone("x", 3600))))
	if string(b) != `"2026-01-02T02:04:05Z"` {
		t.Errorf("a time on the wire: %s", b)
	}
}

// No vector carries anything shaped like an account, in any case: the pinned
// one, a work identity's, or a service account's. kubectl's errors name them,
// and the builder replaces every one.
func TestNoVectorCarriesAnAccount(t *testing.T) {
	for _, v := range worldVectors() {
		t.Run(v.name, func(t *testing.T) {
			raw := vectorBytes(t, buildWorld(v.inputs(t)))
			if m := emailLike.Find(raw); m != nil {
				t.Errorf("the document carries %q", m)
			}
			var b strings.Builder
			if err := buildWorld(v.inputs(t)).Human(&b); err != nil {
				t.Fatal(err)
			}
			if m := emailLike.FindString(b.String()); m != "" {
				t.Errorf("the human reading carries %q", m)
			}
		})
	}
}

// A keeper line is stale by the window its keeper's health is judged by — a
// day — not the egress hour: a keeper streams only when it re-seeds, and a
// healthy keeper drawn with a stale line would contradict itself.
func TestAKeeperLineAgreesWithItsKeepersHealth(t *testing.T) {
	keeperLines := 0
	for _, v := range worldVectors() {
		t.Run(v.name, func(t *testing.T) {
			in := v.inputs(t)
			doc := buildWorld(in)
			health := map[string]string{}
			for _, d := range doc.Devices {
				health[d.ID] = d.Health
			}
			now := in.Now.UTC().Truncate(time.Second)
			for _, l := range doc.Lines {
				k, ok := l.(keeperLine)
				if !ok {
					continue
				}
				keeperLines++
				old := k.LastSeen == nil || time.Time(*k.LastSeen).Before(now.Add(-keeperSeenWithin))
				if k.Stale != old {
					t.Errorf("%s: stale %v, last seen %v", k.From.Device, k.Stale, k.LastSeen)
				}
				if health[k.From.Device] == "healthy" && k.Stale {
					t.Errorf("%s is healthy and its line is stale", k.From.Device)
				}
			}
		})
	}
	if keeperLines == 0 {
		t.Fatal("guard: no vector draws a keeper line, so this proves nothing")
	}
}
