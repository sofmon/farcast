package kube_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
)

const lastApplied = "kubectl.kubernetes.io/last-applied-configuration"

// clientSideApplied is an object an older farcast applied with kubectl's
// client-side apply: one kubectl-client-side-apply Update entry that owns the
// last-applied annotation, and the annotation.
func clientSideApplied(apiVersion, kind, namespace, name string, extra map[string]any) map[string]any {
	o := obj(apiVersion, kind, namespace, name, extra)
	md := o["metadata"].(map[string]any)
	md["labels"] = map[string]any{"app.kubernetes.io/managed-by": "farcast"}
	md["annotations"] = map[string]any{lastApplied: `{"kind":"` + kind + `","marker":"LAST-APPLIED-MARKER"}`}
	md["managedFields"] = []any{map[string]any{
		"manager": "kubectl-client-side-apply", "operation": "Update", "apiVersion": apiVersion,
		"time": "2026-11-01T09:00:00Z", "fieldsType": "FieldsV1",
		"fieldsV1": map[string]any{"f:metadata": map[string]any{
			"f:annotations": map[string]any{".": map[string]any{}, "f:" + lastApplied: map[string]any{}},
			"f:labels":      map[string]any{".": map[string]any{}, "f:app.kubernetes.io/managed-by": map[string]any{}},
		}},
	}}
	return o
}

// TestObjectDecodesAnAnswerThatCarriesKind: a single-object answer carries
// kind and apiVersion, as a real server's does, and Object.Kind is never
// decoded from it (json:"-"): GetObject's metadata-only answer, PatchJSON's
// full one, and a server that ignores Accept and sends a whole Secret all
// decode, each Kind set from the request.
func TestObjectDecodesAnAnswerThatCarriesKind(t *testing.T) {
	deployments := mustKind(t, "apps/v1", "Deployment")
	secrets := mustKind(t, "v1", "Secret")
	s := kubetest.New(t)
	s.Put(clientSideApplied("apps/v1", "Deployment", "web", "api", nil))
	c, _ := connect(t, s, "writer")
	ctx := t.Context()

	o, err := c.GetObject(ctx, deployments, "web", "api")
	if err != nil {
		t.Fatalf("GetObject of an answer that carries kind: %v", err)
	}
	if o.Kind.Kind != "Deployment" || o.Kind.Resource != "deployments" || o.Metadata.Name != "api" || len(o.Metadata.ManagedFields) != 1 {
		t.Errorf("GetObject = %+v", o)
	}
	r := last(t, s)
	if r.Path != "/apis/apps/v1/namespaces/web/deployments/api" || r.Accept != "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1" {
		t.Errorf("GetObject sent %s, Accept %q", r.Path, r.Accept)
	}

	csa, err := kube.ClientSideManagers(o.Metadata.ManagedFields)
	if err != nil {
		t.Fatal(err)
	}
	patch, err := kube.MigrationPatch(o, csa, kube.FieldManager)
	if err != nil || patch == nil {
		t.Fatalf("MigrationPatch = %s, %v", patch, err)
	}
	p, err := c.PatchJSON(ctx, deployments, "web", "api", patch)
	if err != nil {
		t.Fatalf("PatchJSON, whose answer carries kind Deployment: %v", err)
	}
	if p.Kind.Kind != "Deployment" {
		t.Errorf("PatchJSON's Kind = %+v", p.Kind)
	}
	if err := kube.MigratedEndState(p, csa, kube.FieldManager); err != nil {
		t.Errorf("the patch's answer is not migrated: %v", err)
	}
	r = last(t, s)
	if r.Method != http.MethodPatch || r.RawQuery != "fieldManager=farcast&fieldValidation=Strict" ||
		r.ContentType != "application/json-patch+json" || string(r.Body) != string(patch) {
		t.Errorf("PatchJSON sent %s ?%s (%s)", r.Method, r.RawQuery, r.ContentType)
	}
	back, err := c.GetObject(ctx, deployments, "web", "api")
	if err != nil || kube.MigratedEndState(back, csa, kube.FieldManager) != nil {
		t.Errorf("read back: %+v, %v", back.Metadata.ManagedFields, err)
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

// TestListObjectsAsksForMetadataOnly: discovery is one list per kind, across
// every namespace when it names none, by label, paged, asking for a
// PartialObjectMetadataList; each Object's Kind is the request's.
func TestListObjectsAsksForMetadataOnly(t *testing.T) {
	rolebindings := mustKind(t, "rbac.authorization.k8s.io/v1", "RoleBinding")
	s := kubetest.New(t)
	s.Put(clientSideApplied("rbac.authorization.k8s.io/v1", "RoleBinding", "unlabelled-ns", "technocore-meter", map[string]any{
		"roleRef": map[string]any{"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "technocore-meter"},
	}))
	s.Put(clientSideApplied("rbac.authorization.k8s.io/v1", "RoleBinding", "web", "technocore-meter", nil))
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
		if _, ok := o.Metadata.Annotations[lastApplied]; !ok {
			t.Errorf("%s/%s lost its annotation's presence", o.Metadata.Namespace, o.Metadata.Name)
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
	if _, err := c.PatchJSON(t.Context(), rolebindings, "web", "..", []byte(`[]`)); err == nil {
		t.Error("PatchJSON of a name that walks the path was sent")
	}
	if n := len(s.Requests()) - before; n != 0 {
		t.Errorf("%d requests for refused addresses", n)
	}
}

// TestPatchJSONConflictIsTheCallers: a JSON patch at a stale resourceVersion
// is a 409 the migration's own loop handles, and the patch is never retried
// by the transport, on 409 or 503.
func TestPatchJSONConflictIsTheCallers(t *testing.T) {
	configmaps := mustKind(t, "v1", "ConfigMap")
	s := kubetest.New(t)
	s.Put(clientSideApplied("v1", "ConfigMap", "web", "settings", nil))
	c, _ := connect(t, s, "writer")
	o, err := c.GetObject(t.Context(), configmaps, "web", "settings")
	if err != nil {
		t.Fatal(err)
	}
	stale := o
	stale.Metadata.ResourceVersion = o.Metadata.ResourceVersion + "0" // not the current one
	patch, err := kube.MigrationPatch(stale, []string{"kubectl-client-side-apply"}, kube.FieldManager)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.PatchJSON(t.Context(), configmaps, "web", "settings", patch)
	var ae *kube.APIError
	if !errors.As(err, &ae) || ae.Status.Code != http.StatusConflict || ae.Status.Reason != "Conflict" {
		t.Errorf("a stale patch: err = %v, want 409 Conflict", err)
	}
	if err != nil && strings.Contains(err.Error(), "LAST-APPLIED-MARKER") {
		t.Error("the conflict carries the annotation's value")
	}
	if n := len(requestsTo(s, http.MethodPatch, "/api/v1/namespaces/web/configmaps/settings")); n != 1 {
		t.Errorf("%d PATCHes, want 1", n)
	}
}

// TestMigratedEndStateRefusesAKeptListWhoseOwnerLostTheAnnotation (F-F2): an
// object already carries a farcast/Apply entry (§6.6: written again by
// kubectl after its migration) and a kubectl-edit Update entry that owns the
// annotation and other fields. A rewrite the server cannot decode is kept
// silently, the annotation still goes, and the server strips its path from
// kubectl-edit's entry. The read-back then shows no annotation, one
// farcast/Apply entry, and no entry that owns the annotation, so only the set
// the patch was computed for shows kubectl-edit was never converted.
func TestMigratedEndStateRefusesAKeptListWhoseOwnerLostTheAnnotation(t *testing.T) {
	deployments := mustKind(t, "apps/v1", "Deployment")
	s := kubetest.New(t)
	o := obj("apps/v1", "Deployment", "web", "api", nil)
	md := o["metadata"].(map[string]any)
	md["annotations"] = map[string]any{lastApplied: `{"marker":"LAST-APPLIED-MARKER"}`}
	md["managedFields"] = []any{
		map[string]any{"manager": "farcast", "operation": "Apply", "apiVersion": "apps/v1", "time": "2026-11-02T09:00:00Z", "fieldsType": "FieldsV1",
			"fieldsV1": map[string]any{"f:spec": map[string]any{"f:replicas": map[string]any{}}}},
		map[string]any{"manager": "kubectl-edit", "operation": "Update", "apiVersion": "apps/v1", "time": "2026-11-03T09:00:00Z", "fieldsType": "FieldsV1",
			"fieldsV1": map[string]any{
				"f:metadata": map[string]any{"f:annotations": map[string]any{".": map[string]any{}, "f:" + lastApplied: map[string]any{}}},
				"f:spec":     map[string]any{"f:template": map[string]any{"f:spec": map[string]any{}}},
			}},
	}
	s.Put(o)
	c, _ := connect(t, s, "writer")
	ctx := t.Context()

	before, err := c.GetObject(ctx, deployments, "web", "api")
	if err != nil {
		t.Fatal(err)
	}
	csa, err := kube.ClientSideManagers(before.Metadata.ManagedFields)
	if err != nil || len(csa) != 1 || csa[0] != "kubectl-edit" {
		t.Fatalf("ClientSideManagers = %q, %v; want kubectl-edit", csa, err)
	}
	patch, err := kube.MigrationPatch(before, csa, kube.FieldManager)
	if err != nil {
		t.Fatal(err)
	}
	// The same patch with a list the server cannot decode: every operation
	// Update, which no entry may carry without an apiVersion.
	undecodable := strings.Replace(string(patch), `"apiVersion":"apps/v1"`, `"apiVersion":""`, 1)
	if undecodable == string(patch) {
		t.Fatalf("the patch carries no apiVersion to break: %s", patch)
	}
	answer, err := c.PatchJSON(ctx, deployments, "web", "api", []byte(undecodable))
	if err != nil {
		t.Fatalf("PatchJSON of a list the server keeps silently: %v", err)
	}
	back, err := c.GetObject(ctx, deployments, "web", "api")
	if err != nil {
		t.Fatal(err)
	}
	for _, got := range []kube.Object{answer, back} {
		if _, ok := got.Metadata.Annotations[lastApplied]; ok {
			t.Fatal("the annotation's removal did not apply")
		}
		left, err := kube.ClientSideManagers(got.Metadata.ManagedFields)
		if err != nil || len(left) != 0 {
			t.Fatalf("the read-back still shows client-side managers %q (%v); the server strips the annotation's path from every entry", left, err)
		}
		err = kube.MigratedEndState(got, csa, kube.FieldManager)
		if !errors.Is(err, kube.ErrNotMigrated) || err.Error() != "kubectl-edit/Update still present" {
			t.Errorf("MigratedEndState = %v, want kubectl-edit/Update still present", err)
		}
		if err != nil && strings.Contains(err.Error(), "LAST-APPLIED-MARKER") {
			t.Error("the refusal carries the annotation's value")
		}
	}
}
