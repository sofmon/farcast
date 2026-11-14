package kube

import (
	"net/url"
	"slices"
)

// Kind is one kind farcast applies, and how its REST path is built. There is
// no discovery: the table below is the whole set.
type Kind struct {
	Kind       string // "Deployment"
	APIVersion string // "apps/v1"
	Resource   string // "deployments"
	Namespaced bool
	Names      []string // non-nil: the only names allowed (ClusterRoleBinding)
}

// Kinds is ADR 0023 decision 2's table of the kinds farcast applies (§5.1), in
// that order: the 13 the ADR names, and ClusterRoleBinding restricted to the
// one name the reader's cluster-wide namespaces grant uses (P3, decided).
var Kinds = [...]Kind{
	{Kind: "Namespace", APIVersion: "v1", Resource: "namespaces"},
	{Kind: "ServiceAccount", APIVersion: "v1", Resource: "serviceaccounts", Namespaced: true},
	{Kind: "Secret", APIVersion: "v1", Resource: "secrets", Namespaced: true},
	{Kind: "ConfigMap", APIVersion: "v1", Resource: "configmaps", Namespaced: true},
	{Kind: "Service", APIVersion: "v1", Resource: "services", Namespaced: true},
	{Kind: "Deployment", APIVersion: "apps/v1", Resource: "deployments", Namespaced: true},
	{Kind: "StatefulSet", APIVersion: "apps/v1", Resource: "statefulsets", Namespaced: true},
	{Kind: "Job", APIVersion: "batch/v1", Resource: "jobs", Namespaced: true},
	{Kind: "PodDisruptionBudget", APIVersion: "policy/v1", Resource: "poddisruptionbudgets", Namespaced: true},
	{Kind: "NetworkPolicy", APIVersion: "networking.k8s.io/v1", Resource: "networkpolicies", Namespaced: true},
	{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1", Resource: "roles", Namespaced: true},
	{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1", Resource: "rolebindings", Namespaced: true},
	{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1", Resource: "clusterroles"},
	{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1", Resource: "clusterrolebindings", Names: []string{"farcast-reader-namespaces"}},
}

// KindOf finds the pair apiVersion/kind in Kinds, matched exactly. The Kind
// returned carries its own copy of Names, so a caller cannot edit the table.
func KindOf(apiVersion, kind string) (Kind, bool) {
	for _, k := range Kinds {
		if k.APIVersion == apiVersion && k.Kind == kind {
			k.Names = slices.Clone(k.Names)
			return k, true
		}
	}
	return Kind{}, false
}

// group is the path prefix of the kind's API group: /api/v1 for the core
// group, /apis/<apiVersion> for every other.
func (k Kind) group() string {
	if k.APIVersion == "v1" {
		return "/api/v1"
	}
	return "/apis/" + k.APIVersion
}

// Path is one object's path: "/api/v1/namespaces/<ns>/secrets/<name>", with
// the namespace and the name url.PathEscape'd. A cluster-scoped kind ignores
// namespace; a namespaced one needs it, and without one the path names no
// object a server serves (SplitStream never yields such a document).
func (k Kind) Path(namespace, name string) string {
	return k.ListPath(namespace) + "/" + url.PathEscape(name)
}

// ListPath is the collection path. For a namespaced kind an empty namespace
// is every namespace ("/apis/rbac.authorization.k8s.io/v1/rolebindings").
// A cluster-scoped kind ignores namespace.
func (k Kind) ListPath(namespace string) string {
	if k.Namespaced && namespace != "" {
		return k.group() + "/namespaces/" + url.PathEscape(namespace) + "/" + k.Resource
	}
	return k.group() + "/" + k.Resource
}
