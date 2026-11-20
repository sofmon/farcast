package kube_test

import (
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
)

// farcastApplied is an object farcast applied: farcast's label, and one
// farcast Apply entry on the object itself.
func farcastApplied(apiVersion, kind, namespace, name string, extra map[string]any) map[string]any {
	o := obj(apiVersion, kind, namespace, name, extra)
	md := o["metadata"].(map[string]any)
	md["labels"] = map[string]any{"app.kubernetes.io/managed-by": "farcast"}
	md["managedFields"] = []any{map[string]any{
		"manager": "farcast", "operation": "Apply", "apiVersion": apiVersion,
		"time": "2026-11-01T09:00:00Z", "fieldsType": "FieldsV1",
		"fieldsV1": map[string]any{"f:metadata": map[string]any{
			"f:labels": map[string]any{"f:app.kubernetes.io/managed-by": map[string]any{}},
		}},
	}}
	return o
}

// TestObjectDecodesAnAnswerThatCarriesKind: a single-object answer carries
// kind and apiVersion, as a real server's does, and Object.Kind is never
// decoded from it (json:"-"): GetObject's metadata-only answer and a server
// that ignores Accept and sends a whole Secret both decode, each Kind set
// from the request.
func TestObjectDecodesAnAnswerThatCarriesKind(t *testing.T) {
	deployments := mustKind(t, "apps/v1", "Deployment")
	secrets := mustKind(t, "v1", "Secret")
	s := kubetest.New(t)
	s.Put(farcastApplied("apps/v1", "Deployment", "web", "api", nil))
	c, _ := connect(t, s, "writer")
	ctx := t.Context()

	o, err := c.GetObject(ctx, deployments, "web", "api")
	if err != nil {
		t.Fatalf("GetObject of an answer that carries kind: %v", err)
	}
	if o.Kind.Kind != "Deployment" || o.Kind.Resource != "deployments" || o.Metadata.Name != "api" || len(o.Metadata.ManagedFields) != 1 ||
		!kube.IsOwnApply(o.Metadata.ManagedFields[0]) {
		t.Errorf("GetObject = %+v", o)
	}
	r := last(t, s)
	if r.Path != "/apis/apps/v1/namespaces/web/deployments/api" || r.Accept != "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1" {
		t.Errorf("GetObject sent %s, Accept %q", r.Path, r.Accept)
	}

	whole := kubetest.New(t, kubetest.WithHandler(func(r kubetest.Request) (int, []byte, bool) {
		if r.Path == "/api/v1/namespaces/web/secrets/git" {
			return 0, []byte(`{"kind":"Secret","apiVersion":"v1","metadata":{"name":"git","namespace":"web","uid":"u"},"data":{"token":"U0VDUkVU"}}`), true
		}
		return 0, nil, false
	}))
	wc, _ := connect(t, whole, "writer")
	so, err := wc.GetObject(ctx, secrets, "web", "git")
	if err != nil {
		t.Fatalf("a whole Secret, kind and all: %v", err)
	}
	if so.Kind.Kind != "Secret" || so.Metadata.UID != "u" {
		t.Errorf("GetObject of a whole Secret = %+v", so)
	}
}

// TestListObjectsAsksForMetadataOnly: a list is one per kind, across every
// namespace when it names none, by label, paged, asking for a
// PartialObjectMetadataList; each Object's Kind is the request's.
func TestListObjectsAsksForMetadataOnly(t *testing.T) {
	rolebindings := mustKind(t, "rbac.authorization.k8s.io/v1", "RoleBinding")
	s := kubetest.New(t)
	s.Put(farcastApplied("rbac.authorization.k8s.io/v1", "RoleBinding", "unlabelled-ns", "technocore-meter", map[string]any{
		"roleRef": map[string]any{"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "technocore-meter"},
	}))
	s.Put(farcastApplied("rbac.authorization.k8s.io/v1", "RoleBinding", "web", "technocore-meter", nil))
	s.Put(obj("rbac.authorization.k8s.io/v1", "RoleBinding", "web", "someone-elses", nil))
	c, _ := connect(t, s, "writer")

	objs, err := c.ListObjects(t.Context(), rolebindings, "", "app.kubernetes.io/managed-by=farcast")
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != 2 || objs[0].Metadata.Namespace != "unlabelled-ns" || objs[1].Metadata.Namespace != "web" {
		t.Fatalf("ListObjects = %+v", objs)
	}
	for _, o := range objs {
		if o.Kind.Kind != "RoleBinding" || o.Kind.APIVersion != "rbac.authorization.k8s.io/v1" {
			t.Errorf("%s/%s Kind = %+v", o.Metadata.Namespace, o.Metadata.Name, o.Kind)
		}
	}
	r := last(t, s)
	q := query(t, r)
	if r.Path != "/apis/rbac.authorization.k8s.io/v1/rolebindings" || q.Get("labelSelector") != "app.kubernetes.io/managed-by=farcast" ||
		q.Get("limit") != "500" || r.Accept != "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1" {
		t.Errorf("ListObjects sent %s?%s, Accept %q", r.Path, r.RawQuery, r.Accept)
	}

	before := len(s.Requests())
	hand := kube.Kind{Kind: "Pod", APIVersion: "v1", Resource: "pods", Namespaced: true}
	if _, err := c.ListObjects(t.Context(), hand, "", ""); err == nil {
		t.Error("ListObjects of a kind outside the table was sent")
	}
	if _, err := c.GetObject(t.Context(), rolebindings, "", "x"); err == nil {
		t.Error("GetObject of a namespaced kind without a namespace was sent")
	}
	if _, err := c.GetObject(t.Context(), rolebindings, "web", ".."); err == nil {
		t.Error("GetObject of a name that walks the path was sent")
	}
	if n := len(s.Requests()) - before; n != 0 {
		t.Errorf("%d requests for refused addresses", n)
	}
}
