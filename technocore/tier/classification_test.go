package tier_test

import (
	"strings"
	"testing"

	"github.com/goccy/go-yaml"

	dsdeploy "github.com/sofmon/farcast/datasphere/deploy"
	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/technocore/tier"
)

// The classification is only real if the manifests carry it, and this is the
// only direction the dependency may run: TechnoCore reads what the deploy
// packages render, and the deploy packages know nothing about TechnoCore. A
// shared constant would have inverted the layering — FatLine importing the
// kernel — so the label is a literal in each template and this test is what
// keeps the two spellings identical.
//
// It closes [ADR 0008]'s 4.1 deliverable: "last-to-die classification for
// datasphered AND FatLine; fixing either alone fixes nothing."
func TestSystemWorkloadsAreClassifiedLastToDie(t *testing.T) {
	for name, manifest := range map[string][]byte{
		"fatline":     renderFatLine(t),
		"datasphered": renderDatasphered(t),
	} {
		workload, pod := tiersIn(t, manifest)
		if workload != tier.System {
			t.Errorf("%s: workload tier = %q, want %q — a cost shutdown could stop it", name, workload, tier.System)
		}
		if pod != tier.System {
			t.Errorf("%s: pod-template tier = %q, want %q — the meter reads pods, not workloads", name, pod, tier.System)
		}
		if workload.Stoppable() || pod.Stoppable() {
			t.Errorf("%s is stoppable by a cost shutdown; ADR 0008 says it must not be", name)
		}
	}
}

// tiersIn returns the tier label on the workload object and on its pod
// template. Both must carry it: TechnoCore reads pods to meter and workloads
// to scale.
func tiersIn(t *testing.T, manifest []byte) (workload, pod tier.Tier) {
	t.Helper()
	for _, doc := range strings.Split(string(manifest), "\n---\n") {
		var m map[string]any
		if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
			t.Fatalf("rendered document is not valid YAML: %v", err)
		}
		kind, _ := m["kind"].(string)
		if kind != "Deployment" && kind != "StatefulSet" {
			continue
		}
		workload = tier.Of(labelsAt(m, "metadata", "labels"))
		pod = tier.Of(labelsAt(m, "spec", "template", "metadata", "labels"))
		return workload, pod
	}
	t.Fatal("no Deployment or StatefulSet in the rendered manifest")
	return
}

func labelsAt(m map[string]any, path ...string) map[string]string {
	var cur any = m
	for _, k := range path {
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

func renderFatLine(t *testing.T) []byte {
	t.Helper()
	out, err := fldeploy.Render(fldeploy.Config{
		Image:         "example/fatline:test",
		CACertPEM:     []byte("CA"),
		ServerCertPEM: []byte("CRT"),
		ServerKeyPEM:  []byte("KEY"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func renderDatasphered(t *testing.T) []byte {
	t.Helper()
	out, err := dsdeploy.Render(dsdeploy.Config{
		Image:         "example/datasphered@sha256:" + strings.Repeat("a", 64),
		Instance:      "p41",
		Bucket:        "b",
		Provider:      "gcs",
		Project:       "proj-1",
		Location:      "us-central1",
		CACertPEM:     []byte("CA"),
		ServerCertPEM: []byte("CRT"),
		ServerKeyPEM:  []byte("KEY"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
