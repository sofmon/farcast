package kube

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

type capture struct {
	method, path, query, contentType, auth, body string
}

// server records what the client sent and replies with what the test names.
func server(t *testing.T, status int, reply string, seen *capture) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		if r.ContentLength > 0 {
			_, _ = r.Body.Read(b)
		}
		if seen != nil {
			*seen = capture{
				method: r.Method, path: r.URL.Path, query: r.URL.RawQuery,
				contentType: r.Header.Get("Content-Type"),
				auth:        r.Header.Get("Authorization"),
				body:        string(b),
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(s.Close)
	return s
}

func tokenFileWith(t *testing.T, value string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func client(t *testing.T, endpoint, tokenPath string) *Client {
	t.Helper()
	c, err := New(endpoint, tokenPath, "farcast-system", nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

const twoPods = `{"items":[
 {"metadata":{"name":"web-1","namespace":"farcast-apps","labels":{"app":"web"}},
  "spec":{"containers":[{"name":"web","resources":{"requests":{"cpu":"100m","memory":"128Mi"}}}]},
  "status":{"phase":"Running","conditions":[{"type":"Ready","status":"True"}]}},
 {"metadata":{"name":"web-2","namespace":"farcast-apps"},
  "spec":{"containers":[{"name":"web","resources":{"requests":{"cpu":"250m","memory":"512Mi"}}}]},
  "status":{"phase":"Succeeded","conditions":[{"type":"Ready","status":"False"}]}}]}`

func TestListPodsDecodesWhatTheKernelReads(t *testing.T) {
	var seen capture
	s := server(t, 200, twoPods, &seen)
	pods, err := client(t, s.URL, tokenFileWith(t, "tkn")).ListPods(context.Background(), "farcast-apps", "app=web")
	if err != nil {
		t.Fatal(err)
	}
	if len(pods) != 2 {
		t.Fatalf("got %d pods, want 2", len(pods))
	}
	if seen.path != "/api/v1/namespaces/farcast-apps/pods" {
		t.Errorf("path = %q", seen.path)
	}
	if seen.query != "labelSelector=app%3Dweb" {
		t.Errorf("query = %q, want the label selector", seen.query)
	}
	if seen.auth != "Bearer tkn" {
		t.Errorf("Authorization = %q", seen.auth)
	}

	cpu, mem, err := pods[0].Requests()
	if err != nil {
		t.Fatal(err)
	}
	if cpu != 100 || mem != 128 {
		t.Errorf("requests = %dm/%dMi, want 100m/128Mi", cpu, mem)
	}
	if !pods[0].Ready() || pods[1].Ready() {
		t.Error("Ready() disagrees with the pods' conditions")
	}
	if !pods[0].Billable() || pods[1].Billable() {
		t.Error("a Running pod bills and a Succeeded pod does not")
	}
}

// Autopilot reserves capacity at admission, so a pod bills before it Runs.
// Excluding Pending would under-report exactly the workload most likely to be
// misbehaving — one wedged pulling an image, or unschedulable and retrying —
// which is the case a cost guard most needs to see.
func TestPendingPodsBillAndTerminalOnesDoNot(t *testing.T) {
	billable := map[string]bool{
		PodPending: true, PodRunning: true,
		PodSucceeded: false, PodFailed: false,
		"Unknown": false,
	}
	for phase, want := range billable {
		if got := (Pod{Status: PodStatus{Phase: phase}}).Billable(); got != want {
			t.Errorf("phase %s: Billable() = %v, want %v", phase, got, want)
		}
	}
}

// Autopilot bills the larger of the init and main request sets, not the sum.
// Summing them would over-report every pod with an init container; ignoring
// them would under-report a pod whose init step is the expensive one.
func TestRequestsFloorAtTheLargestInitContainer(t *testing.T) {
	p := Pod{Spec: PodSpec{
		Containers: []Container{
			{Resources: ResourceRequirements{Requests: ResourceList{CPU: "100m", Memory: "128Mi"}}},
			{Resources: ResourceRequirements{Requests: ResourceList{CPU: "150m", Memory: "128Mi"}}},
		},
		InitContainers: []Container{
			{Resources: ResourceRequirements{Requests: ResourceList{CPU: "2", Memory: "64Mi"}}},
		},
	}}
	cpu, mem, err := p.Requests()
	if err != nil {
		t.Fatal(err)
	}
	// CPU: init wants 2000m, mains sum to 250m → 2000m.
	// Memory: mains sum to 256Mi, init wants 64Mi → 256Mi.
	if cpu != 2000 {
		t.Errorf("cpu = %dm, want 2000m (the init container floors it)", cpu)
	}
	if mem != 256 {
		t.Errorf("mem = %dMi, want 256Mi (the main containers exceed the init floor)", mem)
	}
}

func TestRequestsRejectsAQuantityItCannotParse(t *testing.T) {
	p := Pod{Spec: PodSpec{Containers: []Container{
		{Resources: ResourceRequirements{Requests: ResourceList{CPU: "100 potatoes"}}},
	}}}
	if _, _, err := p.Requests(); err == nil {
		t.Fatal("an unparseable request must be an error, not a zero")
	}
}

// A pod with no declared requests is not free — but this client must report
// what the manifest says and leave the floors to the pricing package, which
// is the one place that knows what Autopilot charges for a tiny pod.
func TestRequestsOfAnUnspecifiedPodAreZeroNotAssumed(t *testing.T) {
	p := Pod{Spec: PodSpec{Containers: []Container{{Name: "c"}}}}
	cpu, mem, err := p.Requests()
	if err != nil || cpu != 0 || mem != 0 {
		t.Fatalf("got %dm/%dMi err=%v, want 0/0", cpu, mem, err)
	}
}

func TestScalePatchesTheScaleSubresource(t *testing.T) {
	var seen capture
	s := server(t, 200, `{}`, &seen)
	if err := client(t, s.URL, tokenFileWith(t, "tkn")).Scale(context.Background(), "farcast-apps", "web", 0); err != nil {
		t.Fatal(err)
	}
	if seen.method != http.MethodPatch {
		t.Errorf("method = %s, want PATCH", seen.method)
	}
	if seen.path != "/apis/apps/v1/namespaces/farcast-apps/deployments/web/scale" {
		t.Errorf("path = %q, want the scale subresource", seen.path)
	}
	// A full update would race with every other writer; a merge patch names
	// the one field it changes.
	if seen.contentType != "application/merge-patch+json" {
		t.Errorf("Content-Type = %q, want a merge patch", seen.contentType)
	}
	if !strings.Contains(seen.body, `"replicas":0`) {
		t.Errorf("body = %q, want replicas 0", seen.body)
	}
}

func TestScaleRejectsANegativeReplicaCount(t *testing.T) {
	s := server(t, 200, `{}`, nil)
	if err := client(t, s.URL, tokenFileWith(t, "t")).Scale(context.Background(), "ns", "web", -1); err == nil {
		t.Fatal("expected an error for a negative replica count")
	}
}

// Branching on what went wrong is the whole reason for the taxonomy: a
// forbidden scale is a missing RBAC rule the operator must fix, while a
// not-found one is a workload that has already gone.
func TestAPIErrorsCarryTheServersOwnStatus(t *testing.T) {
	cases := map[int]error{
		http.StatusNotFound:     ErrNotFound,
		http.StatusForbidden:    ErrForbidden,
		http.StatusUnauthorized: ErrUnauthorized,
		http.StatusConflict:     ErrConflict,
	}
	for code, want := range cases {
		body := `{"kind":"Status","status":"Failure","message":"nope","reason":"Testing","code":` +
			strconv.Itoa(code) + `}`
		s := server(t, code, body, nil)
		err := client(t, s.URL, tokenFileWith(t, "t")).Scale(context.Background(), "ns", "web", 1)
		if !errors.Is(err, want) {
			t.Errorf("code %d: err = %v, want %v", code, err, want)
		}
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.Status.Message != "nope" {
			t.Errorf("code %d: the server's own message was lost: %v", code, err)
		}
	}
}

// Something in front of the API server — a proxy, a mesh sidecar — returns
// HTML or plain text. Losing that to a JSON decode failure would report the
// wrong problem.
func TestANonJSONErrorBodyStillReportsTheCode(t *testing.T) {
	s := server(t, http.StatusBadGateway, "<html>upstream is down</html>", nil)
	err := client(t, s.URL, tokenFileWith(t, "t")).Scale(context.Background(), "ns", "web", 1)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want an APIError", err)
	}
	if apiErr.Status.Code != http.StatusBadGateway || !strings.Contains(apiErr.Status.Message, "upstream") {
		t.Errorf("lost the upstream body: %+v", apiErr.Status)
	}
}

// A projected ServiceAccount token is rotated by the kubelet while the pod
// runs. A client that reads it once works perfectly until it abruptly does
// not — 401s an hour in, from a process healthy since start-up.
func TestTheTokenIsRereadOnEveryRequest(t *testing.T) {
	var seen capture
	var count atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		seen.auth = r.Header.Get("Authorization")
		w.Write([]byte(`{"items":[]}`))
	}))
	t.Cleanup(s.Close)

	path := tokenFileWith(t, "first")
	c := client(t, s.URL, path)
	if _, err := c.ListPods(context.Background(), "ns", ""); err != nil {
		t.Fatal(err)
	}
	if seen.auth != "Bearer first" {
		t.Fatalf("Authorization = %q, want the first token", seen.auth)
	}

	if err := os.WriteFile(path, []byte("rotated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ListPods(context.Background(), "ns", ""); err != nil {
		t.Fatal(err)
	}
	if seen.auth != "Bearer rotated" {
		t.Errorf("Authorization = %q after rotation; the token was cached for the process lifetime", seen.auth)
	}
	if count.Load() != 2 {
		t.Errorf("server saw %d requests, want 2", count.Load())
	}
}

func TestAMissingTokenFileIsAnError(t *testing.T) {
	s := server(t, 200, `{"items":[]}`, nil)
	c := client(t, s.URL, filepath.Join(t.TempDir(), "absent"))
	if _, err := c.ListPods(context.Background(), "ns", ""); err == nil {
		t.Fatal("expected an error when the token file is missing")
	}
}

func TestInClusterRefusesOutsideACluster(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	if _, err := InCluster(); err == nil {
		t.Fatal("InCluster must refuse when the environment says otherwise")
	}
}
