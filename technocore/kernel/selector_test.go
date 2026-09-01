package kernel_test

import (
	"strings"
	"testing"

	"github.com/goccy/go-yaml"

	dsdeploy "github.com/sofmon/farcast/datasphere/deploy"
	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
	"github.com/sofmon/farcast/technocore/kernel"
)

// Found by the 2026-09-01 runbook walk, on a live cluster, with everything
// else working: the kernel reconciled cleanly and reported `pods=0`.
//
// It selects pods by app.kubernetes.io/managed-by=farcast. Every manifest
// carried that label on the WORKLOAD — and a controller does not copy its own
// labels onto the pods it creates, so no pod had it. The meter matched nothing
// and would have reported $0 for the life of the instance: no threshold, no
// projection, no shutdown, no sign that anything was wrong.
//
// Both sides were individually correct and separately tested. Nothing tested
// the join, which is the only place the bug could live. That is what this
// file is: the one assertion that spans the selector and the manifests.
func TestEverySystemPodCarriesTheLabelTheKernelSelectsOn(t *testing.T) {
	key, value, ok := strings.Cut(kernel.ManagedBy, "=")
	if !ok {
		t.Fatalf("kernel.ManagedBy = %q, which is not a key=value selector", kernel.ManagedBy)
	}

	for name, manifest := range map[string][]byte{
		"fatline":     renderFatLine(t),
		"datasphered": renderDatasphered(t),
		"technocore":  renderTechnoCore(t),
	} {
		labels := podTemplateLabels(t, manifest)
		if labels == nil {
			t.Errorf("%s: no pod template found", name)
			continue
		}
		if labels[key] != value {
			t.Errorf("%s: pod template has %s=%q, want %q — the kernel would not meter these pods at all",
				name, key, labels[key], value)
		}
	}
}

// podTemplateLabels returns spec.template.metadata.labels from whichever
// workload document the stream carries.
func podTemplateLabels(t *testing.T, manifest []byte) map[string]string {
	t.Helper()
	for _, doc := range strings.Split(string(manifest), "\n---\n") {
		var m map[string]any
		if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
			t.Fatalf("rendered document is not valid YAML: %v", err)
		}
		switch kind, _ := m["kind"].(string); kind {
		case "Deployment", "StatefulSet", "DaemonSet":
		default:
			continue
		}
		cur := any(m)
		for _, k := range []string{"spec", "template", "metadata", "labels"} {
			mm, ok := cur.(map[string]any)
			if !ok {
				return nil
			}
			cur = mm[k]
		}
		raw, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		out := map[string]string{}
		for k, v := range raw {
			if s, ok := v.(string); ok {
				out[k] = s
			}
		}
		return out
	}
	return nil
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

func renderDatasphered(t *testing.T) []byte {
	t.Helper()
	out, err := dsdeploy.Render(dsdeploy.Config{
		Image:    "example/datasphered@sha256:" + strings.Repeat("a", 64),
		Instance: "p41", Bucket: "b", Provider: "gcs", Project: "proj-1", Location: "us-central1",
		CACertPEM: []byte("CA"), ServerCertPEM: []byte("CRT"), ServerKeyPEM: []byte("KEY"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func renderTechnoCore(t *testing.T) []byte {
	t.Helper()
	out, err := tcdeploy.Render(tcdeploy.Config{
		Image:    "example/technocore@sha256:" + strings.Repeat("a", 64),
		Instance: "p41", CostLimit: 50,
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
