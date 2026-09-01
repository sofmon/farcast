package deploy_test

import (
	"strings"
	"testing"

	dsdeploy "github.com/sofmon/farcast/datasphere/deploy"
	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
)

// Three modules render the Namespace they deploy into, each owns its own
// deployment shape, and any of the three streams may be applied first. So the
// document has to be *identical* rather than merely compatible: two managers
// writing the same value is a no-op, two writing different labels is a
// tug-of-war on every redeploy.
//
// Each package asserts properties of its own Namespace document, which is not
// the same thing — three separate property checks can all pass while the three
// documents differ. This is the one place that can compare them, because
// technocore is downstream of both others and neither is downstream of it.
func TestTheThreeSystemWorkloadsRenderTheSameNamespace(t *testing.T) {
	rendered := map[string]string{
		"fatline":     namespaceDoc(t, renderFatLine(t)),
		"datasphered": namespaceDoc(t, renderDatasphered(t)),
		"technocore":  namespaceDoc(t, renderTechnoCore(t)),
	}
	want := rendered["fatline"]
	if strings.TrimSpace(want) == "" {
		t.Fatal("fatline rendered no Namespace document")
	}
	for name, got := range rendered {
		if got != want {
			t.Errorf("%s renders a different Namespace document:\n--- %s ---\n%s\n--- fatline ---\n%s",
				name, name, got, want)
		}
	}
}

// namespaceDoc returns the Namespace document from a rendered apply stream,
// compared as text rather than as parsed YAML: the failure this guards is two
// managers fighting over a field, and a parse would normalise away exactly the
// formatting differences that make one apply overwrite another.
func namespaceDoc(t *testing.T, manifest []byte) string {
	t.Helper()
	for _, doc := range strings.Split(string(manifest), "\n---\n") {
		if strings.Contains(doc, "kind: Namespace") {
			return strings.TrimSpace(doc)
		}
	}
	t.Fatal("no Namespace document in the rendered stream")
	return ""
}

func renderTechnoCore(t *testing.T) []byte {
	t.Helper()
	out, err := tcdeploy.Render(tcdeploy.Config{
		Image:     "example/technocore@sha256:" + strings.Repeat("a", 64),
		Instance:  "p41",
		CostLimit: 50,
	})
	if err != nil {
		t.Fatal(err)
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
