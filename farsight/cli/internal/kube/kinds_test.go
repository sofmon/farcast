package kube

import (
	"slices"
	"testing"
)

// TestKindsFollowTheTable pins §5.1's table, row for row and in order.
func TestKindsFollowTheTable(t *testing.T) {
	want := []Kind{
		{"Namespace", "v1", "namespaces", false, nil},
		{"ServiceAccount", "v1", "serviceaccounts", true, nil},
		{"Secret", "v1", "secrets", true, nil},
		{"ConfigMap", "v1", "configmaps", true, nil},
		{"Service", "v1", "services", true, nil},
		{"Deployment", "apps/v1", "deployments", true, nil},
		{"StatefulSet", "apps/v1", "statefulsets", true, nil},
		{"Job", "batch/v1", "jobs", true, nil},
		{"PodDisruptionBudget", "policy/v1", "poddisruptionbudgets", true, nil},
		{"NetworkPolicy", "networking.k8s.io/v1", "networkpolicies", true, nil},
		{"Role", "rbac.authorization.k8s.io/v1", "roles", true, nil},
		{"RoleBinding", "rbac.authorization.k8s.io/v1", "rolebindings", true, nil},
		{"ClusterRole", "rbac.authorization.k8s.io/v1", "clusterroles", false, nil},
		{"ClusterRoleBinding", "rbac.authorization.k8s.io/v1", "clusterrolebindings", false, []string{"farcast-reader-namespaces"}},
	}
	if len(Kinds) != len(want) {
		t.Fatalf("Kinds has %d rows, want %d", len(Kinds), len(want))
	}
	for i, w := range want {
		k := Kinds[i]
		if k.Kind != w.Kind || k.APIVersion != w.APIVersion || k.Resource != w.Resource || k.Namespaced != w.Namespaced || !slices.Equal(k.Names, w.Names) {
			t.Errorf("row %d = %+v, want %+v", i+1, k, w)
		}
		if (k.Names == nil) != (w.Names == nil) {
			t.Errorf("row %d: Names nil-ness differs from the table", i+1)
		}
	}
}

// TestKindOfMatchesExactlyAndCopiesNames: the pair is matched exactly, and a
// caller editing the Kind it gets cannot edit the table.
func TestKindOfMatchesExactlyAndCopiesNames(t *testing.T) {
	for _, k := range Kinds {
		got, ok := KindOf(k.APIVersion, k.Kind)
		if !ok || got.Kind != k.Kind || got.APIVersion != k.APIVersion {
			t.Errorf("KindOf(%q, %q) = %+v, %v", k.APIVersion, k.Kind, got, ok)
		}
	}
	for _, pair := range [][2]string{
		{"v1", "Pod"},
		{"extensions/v1beta1", "Deployment"},
		{"apps/v1", "deployment"},
		{"V1", "Secret"},
		{"rbac.authorization.k8s.io/v1beta1", "ClusterRoleBinding"},
		{"", ""},
	} {
		if got, ok := KindOf(pair[0], pair[1]); ok {
			t.Errorf("KindOf(%q, %q) = %+v, want no match", pair[0], pair[1], got)
		}
	}
	crb, _ := KindOf("rbac.authorization.k8s.io/v1", "ClusterRoleBinding")
	crb.Names[0] = "cluster-admin"
	if Kinds[13].Names[0] != "farcast-reader-namespaces" {
		t.Errorf("editing KindOf's answer edited the table: %v", Kinds[13].Names)
	}
}

// TestKindPathAndListPath: /api/v1 for the core group, /apis/<apiVersion> for
// the rest, a namespace segment for a namespaced kind, every segment escaped.
func TestKindPathAndListPath(t *testing.T) {
	byKind := func(kind string) Kind {
		for _, k := range Kinds {
			if k.Kind == kind {
				return k
			}
		}
		t.Fatalf("no kind %s", kind)
		return Kind{}
	}
	cases := []struct {
		kind, namespace, name string
		path, list            string
	}{
		{"Secret", "web", "egress", "/api/v1/namespaces/web/secrets/egress", "/api/v1/namespaces/web/secrets"},
		{"Namespace", "", "web", "/api/v1/namespaces/web", "/api/v1/namespaces"},
		{"Namespace", "ignored", "web", "/api/v1/namespaces/web", "/api/v1/namespaces"},
		{"Deployment", "farcast-system", "fatline", "/apis/apps/v1/namespaces/farcast-system/deployments/fatline", "/apis/apps/v1/namespaces/farcast-system/deployments"},
		{"Job", "web", "build-1", "/apis/batch/v1/namespaces/web/jobs/build-1", "/apis/batch/v1/namespaces/web/jobs"},
		{"NetworkPolicy", "web", "egress", "/apis/networking.k8s.io/v1/namespaces/web/networkpolicies/egress", "/apis/networking.k8s.io/v1/namespaces/web/networkpolicies"},
		{"RoleBinding", "", "x", "/apis/rbac.authorization.k8s.io/v1/rolebindings/x", "/apis/rbac.authorization.k8s.io/v1/rolebindings"},
		{"ClusterRole", "web", "farcast-reader", "/apis/rbac.authorization.k8s.io/v1/clusterroles/farcast-reader", "/apis/rbac.authorization.k8s.io/v1/clusterroles"},
		{"ClusterRoleBinding", "", "farcast-reader-namespaces", "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/farcast-reader-namespaces", "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"},
		{"ConfigMap", "a/b", "c d?", "/api/v1/namespaces/a%2Fb/configmaps/c%20d%3F", "/api/v1/namespaces/a%2Fb/configmaps"},
	}
	for _, c := range cases {
		k := byKind(c.kind)
		if got := k.Path(c.namespace, c.name); got != c.path {
			t.Errorf("%s.Path(%q, %q) = %q, want %q", c.kind, c.namespace, c.name, got, c.path)
		}
		if got := k.ListPath(c.namespace); got != c.list {
			t.Errorf("%s.ListPath(%q) = %q, want %q", c.kind, c.namespace, got, c.list)
		}
	}
}
