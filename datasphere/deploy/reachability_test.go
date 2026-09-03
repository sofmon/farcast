package deploy_test

import (
	"strings"
	"testing"

	"github.com/goccy/go-yaml"

	dsdeploy "github.com/sofmon/farcast/datasphere/deploy"
	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/manifest/parser"
	"github.com/sofmon/farcast/planck/translate"
)

// The keyholder's ingress policy names labels that three other packages
// render: FatLine's pod label, and the namespace and pod labels Planck stamps
// on a translated application. A selector that does not match what those
// packages actually emit is a policy that silently admits nobody — and the
// symptom is not an error, it is storage that times out for every application
// while the keyholder looks perfectly healthy.
//
// The 4.1 validation walk found this exact shape once already: a selector and
// a label that were each correct and did not meet. Nothing on either side can
// catch it; only a test that renders both can.
func TestThePolicyAdmitsWhatTheOtherModulesActuallyRender(t *testing.T) {
	policy := ingressRules(t, renderKeyholder(t))

	// The unseal port must admit FatLine's pods as FatLine actually labels
	// them.
	fatlinePod := podTemplateLabels(t, renderFatLine(t))
	unseal := selectorOf(t, policy[dsdeploy.DefaultUnsealPort])
	for k, v := range matchLabels(t, unseal, "podSelector") {
		if fatlinePod[k] != v {
			t.Errorf("the unseal rule requires pod label %s=%q; FatLine renders %q — the operator's push would be denied",
				k, v, fatlinePod[k])
		}
	}

	// The data port must admit a translated application as Planck actually
	// labels it, in a namespace Planck actually labels.
	appNS, appPod := translatedAppLabels(t)
	data := selectorOf(t, policy[dsdeploy.DefaultDataPort])
	for k, v := range matchLabels(t, data, "podSelector") {
		if appPod[k] != v {
			t.Errorf("the data rule requires pod label %s=%q; Planck renders %q — every application's storage would be denied",
				k, v, appPod[k])
		}
	}
	for k, v := range matchLabels(t, data, "namespaceSelector") {
		if appNS[k] != v {
			t.Errorf("the data rule requires namespace label %s=%q; Planck renders %q", k, v, appNS[k])
		}
	}
}

func ingressRules(t *testing.T, manifest []byte) map[int]map[string]any {
	t.Helper()
	out := map[int]map[string]any{}
	for _, doc := range strings.Split(string(manifest), "\n---\n") {
		var m map[string]any
		if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
			t.Fatalf("invalid YAML: %v", err)
		}
		if kind, _ := m["kind"].(string); kind != "NetworkPolicy" {
			continue
		}
		spec := m["spec"].(map[string]any)
		for _, r := range spec["ingress"].([]any) {
			rule := r.(map[string]any)
			ports := rule["ports"].([]any)
			p := ports[0].(map[string]any)["port"]
			out[toInt(t, p)] = rule
		}
		return out
	}
	t.Fatal("no NetworkPolicy in the keyholder's manifest")
	return nil
}

func toInt(t *testing.T, v any) int {
	t.Helper()
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case uint64:
		return int(n)
	case float64:
		return int(n)
	}
	t.Fatalf("port is not a number: %T", v)
	return 0
}

func selectorOf(t *testing.T, rule map[string]any) map[string]any {
	t.Helper()
	if rule == nil {
		t.Fatal("no rule for that port")
	}
	from, ok := rule["from"].([]any)
	if !ok || len(from) != 1 {
		t.Fatalf("rule has %v sources, want exactly one so the selectors AND", rule["from"])
	}
	return from[0].(map[string]any)
}

func matchLabels(t *testing.T, sel map[string]any, which string) map[string]string {
	t.Helper()
	s, ok := sel[which].(map[string]any)
	if !ok {
		t.Fatalf("rule has no %s", which)
	}
	raw, ok := s["matchLabels"].(map[string]any)
	if !ok {
		t.Fatalf("%s has no matchLabels", which)
	}
	out := map[string]string{}
	for k, v := range raw {
		out[k] = v.(string)
	}
	return out
}

func podTemplateLabels(t *testing.T, manifest []byte) map[string]string {
	t.Helper()
	for _, doc := range strings.Split(string(manifest), "\n---\n") {
		var m map[string]any
		if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
			t.Fatal(err)
		}
		switch kind, _ := m["kind"].(string); kind {
		case "Deployment", "StatefulSet":
		default:
			continue
		}
		return stringMap(dig(m, "spec", "template", "metadata", "labels"))
	}
	t.Fatal("no workload in the manifest")
	return nil
}

// translatedAppLabels renders a minimal application through Planck and returns
// its namespace labels and its pod labels.
func translatedAppLabels(t *testing.T) (ns, pod map[string]string) {
	t.Helper()
	out, err := translate.Render(translate.Config{
		Manifest: parser.Manifest{Name: "demo", Apps: []parser.App{{Name: "server"}}},
		Images:   map[string]string{"server": "reg/app/demo/server@sha256:" + strings.Repeat("a", 64)},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, doc := range strings.Split(string(out), "\n---\n") {
		var m map[string]any
		if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
			t.Fatal(err)
		}
		if kind, _ := m["kind"].(string); kind == "Namespace" {
			ns = stringMap(dig(m, "metadata", "labels"))
		}
	}
	return ns, podTemplateLabels(t, out)
}

func dig(v any, path ...string) any {
	for _, k := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

func stringMap(v any) map[string]string {
	raw, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := map[string]string{}
	for k, val := range raw {
		if s, ok := val.(string); ok {
			out[k] = s
		}
	}
	return out
}

func renderKeyholder(t *testing.T) []byte {
	t.Helper()
	out, err := dsdeploy.Render(dsdeploy.Config{
		Image:    "example/datasphered@sha256:" + strings.Repeat("a", 64),
		Instance: "p42", Bucket: "b", Provider: "gcs", Project: "proj-1", Location: "us-central1",
		CACertPEM: []byte("CA"), ServerCertPEM: []byte("CRT"), ServerKeyPEM: []byte("KEY"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func renderFatLine(t *testing.T) []byte {
	t.Helper()
	out, err := fldeploy.Render(fldeploy.Config{
		Image: "example/fatline:test", CACertPEM: []byte("CA"),
		ServerCertPEM: []byte("CRT"), ServerKeyPEM: []byte("KEY"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
