package kube_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
)

// TestSelfSubjectAccessReview asks the API server about one thing as the
// client's own identity, and reads status.allowed; an answer without a status
// is unreadable, never "not allowed".
func TestSelfSubjectAccessReview(t *testing.T) {
	s := kubetest.New(t, kubetest.WithAccess(func(id string, a kube.ResourceAttributes) bool {
		return id == "reader" && a.Verb == "list" && a.Resource == "pods" && a.Namespace == "web"
	}))
	c, _ := connect(t, s, "reader")
	ctx := t.Context()

	allowed, err := c.SelfSubjectAccessReview(ctx, kube.ResourceAttributes{Namespace: "web", Verb: "list", Resource: "pods"})
	if err != nil || !allowed {
		t.Errorf("list pods in web: %v, %v; want allowed", allowed, err)
	}
	r := last(t, s)
	apiVersion, kind, attrs := reviewOf(t, r.Body)
	if r.Method != http.MethodPost || r.Path != "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" || r.ContentType != "application/json" ||
		apiVersion != "authorization.k8s.io/v1" || kind != "SelfSubjectAccessReview" ||
		len(attrs) != 3 || attrs["verb"] != "list" || attrs["resource"] != "pods" || attrs["namespace"] != "web" {
		t.Errorf("review sent %s %s (%s) %s", r.Method, r.Path, r.ContentType, r.Body)
	}

	allowed, err = c.SelfSubjectAccessReview(ctx, kube.ResourceAttributes{Namespace: "web", Verb: "get", Resource: "secrets", Name: "fatline-mtls"})
	if err != nil || allowed {
		t.Errorf("get a Secret: %v, %v; want not allowed", allowed, err)
	}
	if _, _, attrs := reviewOf(t, last(t, s).Body); attrs["name"] != "fatline-mtls" || attrs["resource"] != "secrets" {
		t.Errorf("the second review's attributes = %v", attrs)
	}

	statusless := kubetest.New(t, kubetest.WithHandler(func(r kubetest.Request) (int, []byte, bool) {
		return http.StatusCreated, []byte(`{"kind":"SelfSubjectAccessReview","apiVersion":"authorization.k8s.io/v1"}`), true
	}))
	sc, _ := connect(t, statusless, "reader")
	if _, err := sc.SelfSubjectAccessReview(ctx, kube.ResourceAttributes{Verb: "get", Resource: "pods"}); !errors.Is(err, kube.ErrUnreadable) {
		t.Errorf("a review answered without a status: err = %v, want ErrUnreadable", err)
	}

	// B-B2-2: a "no" that reports an evaluationError is the authorizer
	// failing, not the identity being refused; it is unreadable, whether or
	// not it is also denied, and the server's words are not quoted. An
	// allowed answer stays allowed, which reader grant refuses.
	for _, row := range []struct {
		name, status string
		allowed      bool
		unreadable   bool
	}{
		{"no opinion, with an evaluation error", `{"allowed":false,"evaluationError":"webhook: timeout"}`, false, true},
		{"denied, with an evaluation error", `{"allowed":false,"denied":true,"evaluationError":"webhook: timeout"}`, false, true},
		{"allowed, with an evaluation error", `{"allowed":true,"evaluationError":"webhook: timeout"}`, true, false},
		{"denied", `{"allowed":false,"denied":true}`, false, false},
		{"no opinion", `{"allowed":false}`, false, false},
	} {
		srv := kubetest.New(t, kubetest.WithHandler(func(r kubetest.Request) (int, []byte, bool) {
			return http.StatusCreated, []byte(`{"kind":"SelfSubjectAccessReview","apiVersion":"authorization.k8s.io/v1","status":` + row.status + `}`), true
		}))
		rc, _ := connect(t, srv, "reader")
		allowed, err := rc.SelfSubjectAccessReview(ctx, kube.ResourceAttributes{Namespace: "farcast-system", Verb: "create", Group: "apps", Resource: "deployments"})
		switch {
		case row.unreadable && (!errors.Is(err, kube.ErrUnreadable) || allowed):
			t.Errorf("%s: %v, %v; want ErrUnreadable, never a no", row.name, allowed, err)
		case row.unreadable && err.Error() != "the API server could not fully evaluate the review of create deployments; its answer proves nothing":
			t.Errorf("%s: err = %q", row.name, err)
		case !row.unreadable && (err != nil || allowed != row.allowed):
			t.Errorf("%s: %v, %v; want %v", row.name, allowed, err, row.allowed)
		}
	}
}

// reviewOf decodes a SelfSubjectAccessReview request body by its exact keys,
// as the API server reads it, never into a struct, which encoding/json would
// match in any case. A body with any other key fails the test.
func reviewOf(t *testing.T, body []byte) (apiVersion, kind string, attrs map[string]string) {
	t.Helper()
	var review map[string]json.RawMessage
	if err := json.Unmarshal(body, &review); err != nil {
		t.Fatal(err)
	}
	var spec map[string]map[string]string
	for k, v := range review {
		var err error
		switch k {
		case "apiVersion":
			err = json.Unmarshal(v, &apiVersion)
		case "kind":
			err = json.Unmarshal(v, &kind)
		case "spec":
			err = json.Unmarshal(v, &spec)
		default:
			t.Fatalf("the review carries the key %q: %s", k, body)
		}
		if err != nil {
			t.Fatalf("the review's %s: %v", k, err)
		}
	}
	if len(spec) != 1 || spec["resourceAttributes"] == nil {
		t.Fatalf("the review's spec is not resourceAttributes alone: %s", body)
	}
	return apiVersion, kind, spec["resourceAttributes"]
}
