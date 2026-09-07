package kernel

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"

	"github.com/sofmon/farcast/technocore/kube"
)

func namespacesCM(t *testing.T, meter ...string) *fakeConfigMaps {
	t.Helper()
	blob, err := MarshalNamespaces(meter)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeConfigMaps{cm: &kube.ConfigMap{
		Metadata: kube.ObjectMeta{Name: DefaultNamespacesName},
		Data:     map[string]string{NamespacesKey(): string(blob)},
	}}
}

// The reason this exists: deploying an application must not restart the
// kernel. The kernel is single-replica and Recreate, so a restart is a real
// gap in cost enforcement at exactly the moment new spending starts.
func TestADiscoveredNamespaceIsMeteredWithoutARestart(t *testing.T) {
	f := runningApp()
	f.byNS["demo"] = f.byNS["farcast-apps"]
	r := reconciler(t, f, "farcast-system")
	r.Discover = &ConfigMapNamespaces{Client: namespacesCM(t, "demo")}

	rep, err := r.Reconcile(context.Background(), start)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(rep.Metered, ",") != "demo,farcast-system" {
		t.Errorf("metered %v, want the configured namespace plus the discovered one", rep.Metered)
	}
	if len(rep.Workloads) == 0 {
		t.Error("the discovered namespace was not metered")
	}
}

// The configured list is never dropped. A document that omitted
// farcast-system would otherwise stop the instance's own components being
// metered, and under-reporting is the direction this package exists to avoid.
func TestDiscoveryAddsAndNeverRemoves(t *testing.T) {
	r := reconciler(t, runningApp(), "farcast-apps", "farcast-system")
	r.Discover = &ConfigMapNamespaces{Client: namespacesCM(t, "demo")}

	got, err := r.meteredNamespaces(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "demo,farcast-apps,farcast-system" {
		t.Errorf("metered %v, want all three, sorted", got)
	}

	// A document that names nothing must not shrink the set.
	r.Discover = &ConfigMapNamespaces{Client: namespacesCM(t)}
	got, err = r.meteredNamespaces(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "farcast-apps,farcast-system" {
		t.Errorf("an empty document shrank the metered set to %v", got)
	}
}

func TestDiscoveryDeduplicatesAndIgnoresBlanks(t *testing.T) {
	r := reconciler(t, runningApp(), "farcast-apps")
	r.Discover = &ConfigMapNamespaces{Client: namespacesCM(t, "farcast-apps", "  ", "demo", "demo")}
	got, err := r.meteredNamespaces(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "demo,farcast-apps" {
		t.Errorf("metered %v, want a deduplicated, sorted set", got)
	}
}

// A fresh instance has no applications; that is not a failure.
func TestAnAbsentNamespaceDocumentIsNotAFailure(t *testing.T) {
	r := reconciler(t, runningApp(), "farcast-apps")
	r.Discover = &ConfigMapNamespaces{Client: &fakeConfigMaps{}}
	if _, err := r.Reconcile(context.Background(), start); err != nil {
		t.Fatalf("a missing document must not fail the tick: %v", err)
	}
}

// A document that is present but unreadable is different: the operator wrote
// something and the kernel cannot use it, so the metered scope is not what
// they think it is.
func TestAnUnreadableNamespaceDocumentFailsTheTick(t *testing.T) {
	for name, body := range map[string]string{
		"not json":      "{{{",
		"wrong version": `{"version":99,"meter":["demo"]}`,
	} {
		r := reconciler(t, runningApp(), "farcast-apps")
		r.Discover = &ConfigMapNamespaces{Client: &fakeConfigMaps{cm: &kube.ConfigMap{
			Data: map[string]string{NamespacesKey(): body},
		}}}
		if _, err := r.Reconcile(context.Background(), start); err == nil {
			t.Errorf("%s: expected the tick to fail", name)
		}
	}
}

func TestAReadFailureOnTheNamespaceDocumentFailsTheTick(t *testing.T) {
	r := reconciler(t, runningApp(), "farcast-apps")
	r.Discover = &ConfigMapNamespaces{Client: &fakeConfigMaps{getErr: errors.New("unreachable")}}
	if _, err := r.Reconcile(context.Background(), start); err == nil {
		t.Fatal("an unreachable API server must not read as no namespaces")
	}
}

// The operator writes this document and the kernel reads it; a disagreement
// about the key or the shape is invisible on either side alone.
func TestTheNamespaceDocumentRoundTripsBetweenWriterAndReader(t *testing.T) {
	manifest, err := RenderNamespacesConfigMap("farcast-system", DefaultNamespacesName, []string{"demo", "other"})
	if err != nil {
		t.Fatal(err)
	}
	var cm struct {
		Metadata struct{ Name, Namespace string }
		Data     map[string]string
	}
	if err := yaml.Unmarshal(manifest, &cm); err != nil {
		t.Fatalf("the rendered ConfigMap is not valid YAML: %v\n%s", err, manifest)
	}
	if cm.Metadata.Name != DefaultNamespacesName {
		t.Errorf("rendered %q", cm.Metadata.Name)
	}
	src := &ConfigMapNamespaces{Client: &fakeConfigMaps{cm: &kube.ConfigMap{Data: cm.Data}}}
	got, err := src.Load(context.Background())
	if err != nil {
		t.Fatalf("the kernel cannot read what the operator wrote: %v", err)
	}
	if strings.Join(got, ",") != "demo,other" {
		t.Errorf("read %v, wrote [demo other]", got)
	}
}
