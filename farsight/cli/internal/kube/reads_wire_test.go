package kube_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
	tkube "github.com/sofmon/farcast/technocore/kube"
)

func workload(kind, namespace, name string, replicas int, image string) map[string]any {
	return obj("apps/v1", kind, namespace, name, map[string]any{
		"metadata": map[string]any{"labels": map[string]any{"app": name}},
		"spec": map[string]any{
			"replicas": replicas,
			"selector": map[string]any{"matchLabels": map[string]any{"app": name}},
			"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": name, "image": image}}}},
		},
		"status": map[string]any{"readyReplicas": replicas},
	})
}

// TestWorkloadsStampsKindPerListNeverFromTheItem: a list's items carry no
// kind, as a typed list's items do, and kubetest omits it; each Deployment
// and StatefulSet a list returns is stamped from the list it came from. An
// item that names another kind is still its list's. This is the Phase 4.3
// regression (cluster.go:427-432), where a guessed kind hid the key holder.
func TestWorkloadsStampsKindPerListNeverFromTheItem(t *testing.T) {
	s := kubetest.New(t)
	s.Put(workload("Deployment", "web", "api", 2, "r/api"))
	s.Put(workload("StatefulSet", "web", "keyholder", 1, "r/kh"))
	c, _ := connect(t, s, "reader")
	ctx := t.Context()

	ds, err := c.ListDeployments(ctx, "web")
	if err != nil {
		t.Fatal(err)
	}
	ss, err := c.ListStatefulSets(ctx, "web")
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) != 1 || ds[0].Metadata.Name != "api" || ds[0].Kind.Kind != "Deployment" || ds[0].Kind.APIVersion != "apps/v1" {
		t.Errorf("deployments = %+v; want api, stamped Deployment", ds)
	}
	if len(ss) != 1 || ss[0].Metadata.Name != "keyholder" || ss[0].Kind.Kind != "StatefulSet" || ss[0].Kind.Resource != "statefulsets" {
		t.Errorf("statefulsets = %+v; want keyholder, stamped StatefulSet", ss)
	}
	if ds[0].Spec.Replicas == nil || *ds[0].Spec.Replicas != 2 || ds[0].Spec.Template.Spec.Containers[0].Image != "r/api" {
		t.Errorf("the deployment did not decode: %+v", ds[0].Spec)
	}
	paths := []string{}
	for _, r := range apiRequests(s) {
		paths = append(paths, r.Method+" "+r.Path)
	}
	if want := []string{"GET /apis/apps/v1/namespaces/web/deployments", "GET /apis/apps/v1/namespaces/web/statefulsets"}; !slices.Equal(paths, want) {
		t.Errorf("requests = %v, want %v", paths, want)
	}

	lying := kubetest.New(t, kubetest.WithHandler(func(r kubetest.Request) (int, []byte, bool) {
		if r.Method == http.MethodGet && r.Path == "/apis/apps/v1/namespaces/web/deployments" {
			return http.StatusOK, []byte(`{"kind":"DeploymentList","apiVersion":"apps/v1","metadata":{},"items":[{"kind":"StatefulSet","apiVersion":"apps/v1","metadata":{"name":"lying","namespace":"web"}}]}`), true
		}
		return 0, nil, false
	}))
	lc, _ := connect(t, lying, "reader")
	ld, err := lc.ListDeployments(ctx, "web")
	if err != nil {
		t.Fatal(err)
	}
	if len(ld) != 1 || ld[0].Kind.Kind != "Deployment" {
		t.Errorf("an item that names StatefulSet in a Deployment list = %+v; its kind is the list's", ld)
	}

	d, err := c.GetDeployment(ctx, "web", "api")
	if err != nil || d.Kind.Kind != "Deployment" || d.Metadata.Name != "api" {
		t.Errorf("GetDeployment = %+v, %v", d, err)
	}
	st, err := c.GetStatefulSet(ctx, "web", "keyholder")
	if err != nil || st.Kind.Kind != "StatefulSet" || st.Status.ReadyReplicas != 1 {
		t.Errorf("GetStatefulSet = %+v, %v", st, err)
	}
}

// TestListsPageWithLimitAndContinue: lists send limit=500 and follow
// metadata.continue until it is empty, against kubetest's own paging.
func TestListsPageWithLimitAndContinue(t *testing.T) {
	s := kubetest.New(t)
	const n = 501
	for i := range n {
		s.Put(obj("v1", "Namespace", "", fmt.Sprintf("ns-%03d", n-1-i), map[string]any{
			"metadata": map[string]any{"labels": map[string]any{"tier": map[bool]string{true: "app", false: "system"}[i%2 == 0]}},
		}))
	}
	c, _ := connect(t, s, "reader")
	names, err := c.ListNamespaces(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != n || !slices.IsSorted(names) || names[0] != "ns-000" {
		t.Fatalf("%d names, sorted %v, first %q", len(names), slices.IsSorted(names), names[0])
	}
	reqs := apiRequests(s)
	if len(reqs) != 2 {
		t.Fatalf("%d requests, want 2 pages", len(reqs))
	}
	if q := query(t, reqs[0]); q.Get("limit") != "500" || q.Has("continue") {
		t.Errorf("first page query %q", reqs[0].RawQuery)
	}
	if q := query(t, reqs[1]); q.Get("limit") != "500" || q.Get("continue") == "" {
		t.Errorf("second page query %q", reqs[1].RawQuery)
	}

	app, err := c.ListNamespaces(t.Context(), "tier=app")
	if err != nil {
		t.Fatal(err)
	}
	if len(app) != 251 {
		t.Errorf("tier=app selects %d namespaces, want 251", len(app))
	}
	if q := query(t, last(t, s)); q.Get("labelSelector") != "tier=app" {
		t.Errorf("selector query %q", last(t, s).RawQuery)
	}
}

// TestListsRestartOnceOnGone: a 410 Gone while following a continue token
// restarts the list once from its first page; a second is the error; a
// server that hands back its token is not followed forever.
func TestListsRestartOnceOnGone(t *testing.T) {
	page := func(cont string, names ...string) []byte {
		items := []string{}
		for _, n := range names {
			items = append(items, `{"metadata":{"name":"`+n+`"}}`)
		}
		return []byte(`{"kind":"NamespaceList","apiVersion":"v1","metadata":{"continue":"` + cont + `"},"items":[` + strings.Join(items, ",") + `]}`)
	}
	gone := []byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Expired","message":"The provided continue parameter is too old","code":410}`)

	var gones, cycles atomic.Int32
	var maxGones int32 = 1
	s := kubetest.New(t, kubetest.WithHandler(func(r kubetest.Request) (int, []byte, bool) {
		if r.Path != "/api/v1/namespaces" {
			return 0, nil, false
		}
		switch {
		case strings.Contains(r.RawQuery, "continue=c1"):
			if gones.Load() < maxGones {
				gones.Add(1)
				return http.StatusGone, gone, true
			}
			return 0, page("", "c"), true
		case strings.Contains(r.RawQuery, "continue=loop"):
			return 0, page("loop", "x"), true
		case strings.Contains(r.RawQuery, "labelSelector=cycle") && cycles.Add(1) > 10:
			// A client that follows the cycle gets an end after ten pages,
			// so the test fails rather than hangs.
			return 0, page("", "end"), true
		case strings.Contains(r.RawQuery, "continue=cycleA"):
			return 0, page("cycleB", "y"), true
		case strings.Contains(r.RawQuery, "continue=cycleB"):
			return 0, page("cycleA", "z"), true
		case strings.Contains(r.RawQuery, "labelSelector=cycle"):
			return 0, page("cycleA", "x"), true
		case strings.Contains(r.RawQuery, "labelSelector=loop"):
			return 0, page("loop", "x"), true
		}
		return 0, page("c1", "a", "b"), true
	}))
	c, _ := connect(t, s, "reader")

	names, err := c.ListNamespaces(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(names, []string{"a", "b", "c"}) {
		t.Errorf("names = %v; a restart keeps no item twice", names)
	}
	if n := len(apiRequests(s)); n != 4 {
		t.Errorf("%d requests, want 4: page 1, 410, page 1 again, page 2", n)
	}

	gones.Store(0)
	maxGones = 2
	_, err = c.ListNamespaces(t.Context(), "")
	var ae *kube.APIError
	if !errors.As(err, &ae) || ae.Status.Code != http.StatusGone {
		t.Errorf("a second 410: err = %v, want the 410", err)
	}

	_, err = c.ListNamespaces(t.Context(), "loop")
	if !errors.Is(err, kube.ErrUnreadable) {
		t.Errorf("a repeated continue token: err = %v, want ErrUnreadable", err)
	}

	// A server that alternates its tokens, A, B, A, is not followed forever
	// either: a token already sent in this pass is refused (F-F5).
	before := len(apiRequests(s))
	_, err = c.ListNamespaces(t.Context(), "cycle")
	if !errors.Is(err, kube.ErrUnreadable) {
		t.Errorf("an A, B, A cycle of continue tokens: err = %v, want ErrUnreadable", err)
	}
	if n := len(apiRequests(s)) - before; n != 3 {
		t.Errorf("an A, B, A cycle sent %d pages, want 3: the first, A and B", n)
	}
}

// TestRetryWaitIsCutShortByTheCallersContext (F-F4): with the product's own
// wait between retries (no SetSleep), a 503 that names no Retry-After waits
// 1 s before its retry, and the caller's context ending during that wait ends
// the call at once, with the context's error and no second attempt.
func TestRetryWaitIsCutShortByTheCallersContext(t *testing.T) {
	const path = "/api/v1/namespaces/web/configmaps/x"
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var once sync.Once
	cancelledAt := make(chan time.Time, 1)
	s := kubetest.New(t, kubetest.WithDelay(func(r kubetest.Request) time.Duration {
		if r.Path == path {
			// The first GET's answer is the injected 503; the caller's
			// context ends 100 ms later, inside the 1 s wait.
			once.Do(func() {
				time.AfterFunc(100*time.Millisecond, func() {
					cancelledAt <- time.Now()
					cancel()
				})
			})
		}
		return 0
	}))
	s.Put(obj("v1", "ConfigMap", "web", "x", map[string]any{"data": map[string]any{"k": "v"}}))
	ep, err := kube.ParseEndpoint(s.Endpoint(), "", s.CAPEM())
	if err != nil {
		t.Fatal(err)
	}
	c, err := kube.New(kube.Config{Endpoint: ep, Credential: s.Credential("writer"), Identity: kube.Writer})
	if err != nil {
		t.Fatal(err)
	}

	s.Fail(http.MethodGet, path, http.StatusServiceUnavailable, kube.Status{})
	_, err = c.GetConfigMap(ctx, "web", "x")
	returned := time.Now()
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if n := len(requestsTo(s, http.MethodGet, path)); n != 1 {
		t.Errorf("%d GETs, want 1: no retry after the context ended", n)
	}
	select {
	case at := <-cancelledAt:
		if d := returned.Sub(at); d > 500*time.Millisecond {
			t.Errorf("the call returned %s after its context ended; the wait did not end with it", d)
		}
	default:
		t.Error("the call returned before its context ended: it never waited")
	}

	// Left alone, the same 503 waits its 1 s, and the retry is served.
	s.Fail(http.MethodGet, path, http.StatusServiceUnavailable, kube.Status{})
	start := time.Now()
	if _, err := c.GetConfigMap(t.Context(), "web", "x"); err != nil {
		t.Fatalf("after the wait: %v", err)
	}
	if d := time.Since(start); d < time.Second {
		t.Errorf("the retry came %s after the first attempt began, before the 1 s wait", d)
	}
	if n := len(requestsTo(s, http.MethodGet, path)); n != 3 {
		t.Errorf("%d GETs in all, want 3", n)
	}
}

// TestReadsAddressAndDecodeEachKind: each read's path, its Accept, and what
// it decodes.
func TestReadsAddressAndDecodeEachKind(t *testing.T) {
	s := kubetest.New(t)
	s.Put(obj("v1", "Service", "web", "edge", map[string]any{
		"status": map[string]any{"loadBalancer": map[string]any{"ingress": []any{map[string]any{"ip": "203.0.113.7"}}}},
	}))
	s.Put(obj("batch/v1", "Job", "web", "build", map[string]any{
		"spec": map[string]any{
			"selector": map[string]any{"matchLabels": map[string]any{"job-name": "build"}},
			"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "build"}}}},
		},
		"status": map[string]any{"succeeded": 1},
	}))
	for i, labels := range []map[string]any{{"job-name": "build"}, {"job-name": "build"}, {"job-name": "other"}} {
		s.Put(obj("v1", "Pod", "web", fmt.Sprintf("build-%d", i), map[string]any{
			"metadata": map[string]any{"labels": labels},
			"spec":     map[string]any{"nodeName": "n", "containers": []any{map[string]any{"name": "build"}}},
			"status":   map[string]any{"phase": "Succeeded"},
		}))
	}
	s.Put(obj("v1", "ConfigMap", "farcast-system", "technocore-ledger", map[string]any{"data": map[string]any{"ledger.json": "{}"}}))
	c, _ := connect(t, s, "reader")
	ctx := t.Context()

	svc, err := c.GetService(ctx, "web", "edge")
	if err != nil || len(svc.Status.LoadBalancer.Ingress) != 1 || svc.Status.LoadBalancer.Ingress[0].IP != "203.0.113.7" {
		t.Errorf("GetService = %+v, %v", svc, err)
	}
	if r := last(t, s); r.Path != "/api/v1/namespaces/web/services/edge" || r.Accept != "application/json" {
		t.Errorf("GetService sent %s (Accept %q)", r.Path, r.Accept)
	}
	job, err := c.GetJob(ctx, "web", "build")
	if err != nil || job.Status.Succeeded != 1 || job.Spec.Template.Spec.Containers[0].Name != "build" {
		t.Errorf("GetJob = %+v, %v", job, err)
	}
	if r := last(t, s); r.Path != "/apis/batch/v1/namespaces/web/jobs/build" {
		t.Errorf("GetJob sent %s", r.Path)
	}
	sel, err := kube.SelectorString(job.Spec.Selector)
	if err != nil {
		t.Fatal(err)
	}
	pods, err := c.ListPods(ctx, "web", sel)
	if err != nil || len(pods) != 2 || pods[0].Metadata.Name != "build-0" || pods[0].Status.Phase != "Succeeded" {
		t.Errorf("ListPods = %+v, %v", pods, err)
	}
	if r := last(t, s); r.Path != "/api/v1/namespaces/web/pods" || query(t, r).Get("labelSelector") != "job-name=build" {
		t.Errorf("ListPods sent %s?%s", r.Path, r.RawQuery)
	}
	cm, err := c.GetConfigMap(ctx, "farcast-system", "technocore-ledger")
	if err != nil || cm.Data["ledger.json"] != "{}" || cm.Metadata.ResourceVersion == "" {
		t.Errorf("GetConfigMap = %+v, %v", cm, err)
	}

	_, err = c.GetConfigMap(ctx, "farcast-system", "absent")
	if !errors.Is(err, tkube.ErrNotFound) {
		t.Errorf("an absent ConfigMap: err = %v, want tkube.ErrNotFound", err)
	}
	s.Fail(http.MethodGet, "/api/v1/namespaces/farcast-system/configmaps/technocore-ledger", http.StatusForbidden, kube.Status{})
	_, err = c.GetConfigMap(ctx, "farcast-system", "technocore-ledger")
	if !errors.Is(err, tkube.ErrForbidden) || errors.Is(err, tkube.ErrNotFound) {
		t.Errorf("a forbidden ConfigMap: err = %v, want tkube.ErrForbidden and never not-found", err)
	}

	before := len(s.Requests())
	for _, bad := range []func() error{
		func() error { _, err := c.GetConfigMap(ctx, "farcast-system", ".."); return err },
		func() error { _, err := c.GetDeployment(ctx, "..", "x"); return err },
		func() error { _, err := c.GetJob(ctx, "web", "a/b"); return err },
		func() error { _, err := c.ListPods(ctx, ".", ""); return err },
		func() error { _, err := c.NamespaceUID(ctx, "Upper"); return err },
	} {
		if bad() == nil {
			t.Error("a name that walks the path was sent")
		}
	}
	if n := len(s.Requests()) - before; n != 0 {
		t.Errorf("%d requests for names the rule refuses", n)
	}
}

// TestNamespaceUID reads one namespace's uid with the list verb.
func TestNamespaceUID(t *testing.T) {
	s := kubetest.New(t)
	s.Put(obj("v1", "Namespace", "", "farcast-system", map[string]any{"metadata": map[string]any{"uid": "uid-system"}}))
	s.Put(obj("v1", "Namespace", "", "web", nil))
	c, _ := connect(t, s, "reader")
	uid, err := c.NamespaceUID(t.Context(), "farcast-system")
	if err != nil || uid != "uid-system" {
		t.Errorf("NamespaceUID = %q, %v", uid, err)
	}
	r := last(t, s)
	if r.Method != http.MethodGet || r.Path != "/api/v1/namespaces" || query(t, r).Get("fieldSelector") != "metadata.name=farcast-system" ||
		!strings.Contains(r.RawQuery, "fieldSelector=metadata.name%3Dfarcast-system") {
		t.Errorf("NamespaceUID sent %s %s?%s", r.Method, r.Path, r.RawQuery)
	}
	if uid, err := c.NamespaceUID(t.Context(), "absent"); err != nil || uid != "" {
		t.Errorf("an absent namespace: %q, %v; want \"\"", uid, err)
	}

	ignoring := kubetest.New(t, kubetest.WithHandler(func(r kubetest.Request) (int, []byte, bool) {
		if r.Path == "/api/v1/namespaces" {
			if strings.Contains(r.RawQuery, "one") {
				return 0, []byte(`{"metadata":{},"items":[{"metadata":{"name":"other","uid":"u"}}]}`), true
			}
			return 0, []byte(`{"metadata":{},"items":[{"metadata":{"name":"a","uid":"1"}},{"metadata":{"name":"b","uid":"2"}}]}`), true
		}
		return 0, nil, false
	}))
	ic, _ := connect(t, ignoring, "reader")
	if _, err := ic.NamespaceUID(t.Context(), "a"); !errors.Is(err, kube.ErrUnreadable) {
		t.Errorf("two items: err = %v, want ErrUnreadable", err)
	}
	if _, err := ic.NamespaceUID(t.Context(), "one"); !errors.Is(err, kube.ErrUnreadable) {
		t.Errorf("an item by another name: err = %v, want ErrUnreadable", err)
	}
}

// TestConfigMapWritesCreateAndReplace: the pin's two writes are a POST and a
// PUT, never an apply, each naming farcast and strict validation; a create
// that exists is AlreadyExists, a replace at a stale resourceVersion is a
// Conflict, and a replace without one is refused before anything is sent.
func TestConfigMapWritesCreateAndReplace(t *testing.T) {
	s := kubetest.New(t)
	c, _ := connect(t, s, "writer")
	ctx := t.Context()
	pin := func(rv, value string) []byte {
		md := map[string]any{"name": "keyholder-pin", "namespace": "farcast-system"}
		if rv != "" {
			md["resourceVersion"] = rv
		}
		b, _ := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": md, "data": map[string]string{"pin": value}})
		return b
	}

	if err := c.CreateConfigMap(ctx, pin("", "one")); err != nil {
		t.Fatal(err)
	}
	r := last(t, s)
	if r.Method != http.MethodPost || r.Path != "/api/v1/namespaces/farcast-system/configmaps" ||
		r.RawQuery != "fieldManager=farcast&fieldValidation=Strict" || r.ContentType != "application/json" || string(r.Body) != string(pin("", "one")) {
		t.Errorf("create sent %s %s?%s (%s) %s", r.Method, r.Path, r.RawQuery, r.ContentType, r.Body)
	}
	err := c.CreateConfigMap(ctx, pin("", "two"))
	var ae *kube.APIError
	if !errors.Is(err, tkube.ErrConflict) || !errors.As(err, &ae) || ae.Status.Reason != "AlreadyExists" {
		t.Errorf("a second create: err = %v, want 409 AlreadyExists", err)
	}

	cm, err := c.GetConfigMap(ctx, "farcast-system", "keyholder-pin")
	if err != nil {
		t.Fatal(err)
	}
	before := len(s.Requests())
	if err := c.ReplaceConfigMap(ctx, pin("", "two")); !errors.Is(err, kube.ErrRefusedDocument) {
		t.Errorf("a replace without a resourceVersion: err = %v, want ErrRefusedDocument", err)
	}
	if n := len(s.Requests()) - before; n != 0 {
		t.Errorf("a refused replace sent %d requests", n)
	}
	if err := c.ReplaceConfigMap(ctx, pin(cm.Metadata.ResourceVersion, "two")); err != nil {
		t.Fatal(err)
	}
	r = last(t, s)
	if r.Method != http.MethodPut || r.Path != "/api/v1/namespaces/farcast-system/configmaps/keyholder-pin" || r.RawQuery != "fieldManager=farcast&fieldValidation=Strict" {
		t.Errorf("replace sent %s %s?%s", r.Method, r.Path, r.RawQuery)
	}
	if err := c.ReplaceConfigMap(ctx, pin(cm.Metadata.ResourceVersion, "three")); !errors.Is(err, tkube.ErrConflict) {
		t.Errorf("a replace at a stale resourceVersion: err = %v, want tkube.ErrConflict", err)
	}
	got, _ := c.GetConfigMap(ctx, "farcast-system", "keyholder-pin")
	if got.Data["pin"] != "two" {
		t.Errorf("pin = %q, want two", got.Data["pin"])
	}

	before = len(s.Requests())
	for _, body := range [][]byte{
		[]byte(`not json`),
		[]byte(`{"apiVersion":"v1","kind":"Secret","metadata":{"name":"s","namespace":"web"}}`),
		[]byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"..","namespace":"web"}}`),
		[]byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"x"}}`),
	} {
		if err := c.CreateConfigMap(ctx, body); !errors.Is(err, kube.ErrRefusedDocument) {
			t.Errorf("create %s: err = %v, want ErrRefusedDocument", body, err)
		}
	}
	if n := len(s.Requests()) - before; n != 0 {
		t.Errorf("refused bodies sent %d requests", n)
	}
}

// TestRetryPolicy is D12: a GET and a server-side apply are sent again on 429
// and 503, up to 3 attempts in all, waiting each answer's Retry-After (1 s
// when it names none); nothing else is retried, and no other code is.
func TestRetryPolicy(t *testing.T) {
	ctx := t.Context()
	cmPath := "/api/v1/namespaces/web/configmaps/x"
	applyDoc := func(t *testing.T) kube.Document {
		docs, err := kube.SplitStream([]byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n  namespace: web\ndata:\n  k: v\n"))
		if err != nil {
			t.Fatal(err)
		}
		return docs[0]
	}
	cases := []struct {
		name     string
		method   string
		path     string
		codes    []int
		run      func(t *testing.T, c *kube.Client) error
		requests int
		waits    []time.Duration
		ok       bool
	}{
		{"GET 503, 503, then served", http.MethodGet, cmPath, []int{503, 503},
			func(t *testing.T, c *kube.Client) error { _, err := c.GetConfigMap(ctx, "web", "x"); return err },
			3, []time.Duration{time.Second, time.Second}, true},
		{"GET 429 three times", http.MethodGet, cmPath, []int{429, 429, 429},
			func(t *testing.T, c *kube.Client) error { _, err := c.GetConfigMap(ctx, "web", "x"); return err },
			3, []time.Duration{time.Second, time.Second}, false},
		{"GET 500", http.MethodGet, cmPath, []int{500},
			func(t *testing.T, c *kube.Client) error { _, err := c.GetConfigMap(ctx, "web", "x"); return err },
			1, nil, false},
		{"GET 403", http.MethodGet, cmPath, []int{403},
			func(t *testing.T, c *kube.Client) error { _, err := c.GetConfigMap(ctx, "web", "x"); return err },
			1, nil, false},
		{"a list GET 503", http.MethodGet, "/api/v1/namespaces", []int{503},
			func(t *testing.T, c *kube.Client) error { _, err := c.ListNamespaces(ctx, ""); return err },
			2, []time.Duration{time.Second}, true},
		{"a log GET 429", http.MethodGet, "/api/v1/namespaces/web/pods/p/log", []int{429},
			func(t *testing.T, c *kube.Client) error {
				return c.StreamLog(ctx, "web", "p", kube.LogOptions{Container: "c", TailLines: -1}, &strings.Builder{})
			},
			2, []time.Duration{time.Second}, true},
		{"apply 429", http.MethodPatch, cmPath, []int{429},
			func(t *testing.T, c *kube.Client) error { _, err := c.Apply(ctx, applyDoc(t), true); return err },
			2, []time.Duration{time.Second}, true},
		{"apply 503 three times", http.MethodPatch, cmPath, []int{503, 503, 503},
			func(t *testing.T, c *kube.Client) error { _, err := c.Apply(ctx, applyDoc(t), true); return err },
			3, []time.Duration{time.Second, time.Second}, false},
		{"POST 503", http.MethodPost, "/api/v1/namespaces/web/configmaps", []int{503},
			func(t *testing.T, c *kube.Client) error {
				return c.CreateConfigMap(ctx, []byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"y","namespace":"web"}}`))
			},
			1, nil, false},
		{"PUT 429", http.MethodPut, cmPath, []int{429},
			func(t *testing.T, c *kube.Client) error {
				return c.ReplaceConfigMap(ctx, []byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"x","namespace":"web","resourceVersion":"1"}}`))
			},
			1, nil, false},
		{"DELETE 503", http.MethodDelete, "/api/v1/namespaces/web/secrets/s", []int{503},
			func(t *testing.T, c *kube.Client) error { return c.DeleteSecret(ctx, "web", "s", "uid-s") },
			1, nil, false},
		{"JSON patch 503", http.MethodPatch, cmPath, []int{503},
			func(t *testing.T, c *kube.Client) error {
				_, err := c.PatchJSON(ctx, mustKind(t, "v1", "ConfigMap"), "web", "x", []byte(`[]`))
				return err
			},
			1, nil, false},
		{"review POST 429", http.MethodPost, "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", []int{429},
			func(t *testing.T, c *kube.Client) error {
				_, err := c.SelfSubjectAccessReview(ctx, kube.ResourceAttributes{Verb: "get", Resource: "pods"})
				return err
			},
			1, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := kubetest.New(t)
			s.Put(obj("v1", "ConfigMap", "web", "x", map[string]any{"data": map[string]any{"k": "v"}}))
			s.Put(obj("v1", "Secret", "web", "s", map[string]any{"metadata": map[string]any{"uid": "uid-s"}}))
			s.Put(obj("v1", "Pod", "web", "p", map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "c"}}}}))
			for _, code := range tc.codes {
				s.Fail(tc.method, tc.path, code, kube.Status{})
			}
			c, w := connect(t, s, "writer")
			err := tc.run(t, c)
			if tc.ok && err != nil {
				t.Fatalf("err = %v, want served after the retries", err)
			}
			if !tc.ok {
				var ae *kube.APIError
				if !errors.As(err, &ae) || ae.Status.Code != tc.codes[len(tc.codes)-1] && ae.Status.Code != tc.codes[0] {
					t.Fatalf("err = %v, want the injected %d", err, tc.codes[0])
				}
			}
			if n := len(requestsTo(s, tc.method, tc.path)); n != tc.requests {
				t.Errorf("%d requests, want %d", n, tc.requests)
			}
			if got := w.all(); !slices.Equal(got, tc.waits) {
				t.Errorf("waits = %v, want %v", got, tc.waits)
			}
		})
	}
}

// TestWarningsAreDistinctAndInOrder: Warnings() keeps each distinct Warning
// text any answer carried, errors included, in the order first seen, and
// hands back a copy.
func TestWarningsAreDistinctAndInOrder(t *testing.T) {
	s := kubetest.New(t, kubetest.WithWarnings(func(r kubetest.Request) []string {
		switch r.Path {
		case "/api/v1/namespaces":
			return []string{"b", `say "hi"`}
		case "/api/v1/namespaces/web/configmaps/absent":
			return []string{"a", "b", `back\slash`}
		}
		return nil
	}))
	c, _ := connect(t, s, "reader")
	if got := c.Warnings(); len(got) != 0 {
		t.Errorf("a new client's warnings = %q", got)
	}
	if _, err := c.ListNamespaces(t.Context(), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetConfigMap(t.Context(), "web", "absent"); !errors.Is(err, tkube.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if _, err := c.ListNamespaces(t.Context(), ""); err != nil {
		t.Fatal(err)
	}
	want := []string{"b", `say "hi"`, "a", `back\slash`}
	got := c.Warnings()
	if !slices.Equal(got, want) {
		t.Errorf("Warnings() = %q, want %q", got, want)
	}
	got[0] = "changed"
	if c.Warnings()[0] != "b" {
		t.Error("Warnings() handed out its own slice")
	}
}

// TestAPIErrorTellsANonStatus403FromRBAC: a 403 whose body is not a Status
// (the DNS endpoint's IAM check answers Google's JSON error) is an APIError
// with KubernetesStatus false; an RBAC refusal is a Status. Both unwrap to
// tkube.ErrForbidden, and neither is retried or re-minted.
func TestAPIErrorTellsANonStatus403FromRBAC(t *testing.T) {
	s := kubetest.New(t)
	c, _ := connect(t, s, "reader")
	path := "/api/v1/namespaces/web/configmaps/x"

	s.Fail(http.MethodGet, path, http.StatusForbidden, kube.Status{Status: tkube.Status{Kind: "Error"}})
	_, err := c.GetConfigMap(t.Context(), "web", "x")
	var ae *kube.APIError
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v, want an APIError", err)
	}
	if ae.KubernetesStatus || ae.Status.Code != http.StatusForbidden || !errors.Is(err, tkube.ErrForbidden) {
		t.Errorf("IAM 403 = %+v; want KubernetesStatus false, code 403, tkube.ErrForbidden", ae)
	}
	if want := "kube: GET " + path + ": 403 Forbidden: The caller does not have permission"; err.Error() != want {
		t.Errorf("err = %q, want %q", err, want)
	}

	s.Fail(http.MethodGet, path, http.StatusForbidden, kube.Status{})
	_, err = c.GetConfigMap(t.Context(), "web", "x")
	if !errors.As(err, &ae) || !ae.KubernetesStatus || ae.Status.Reason != "Forbidden" || !strings.Contains(ae.Status.Message, "reader@kubetest.invalid") {
		t.Errorf("RBAC 403 = %+v; want a Status naming the caller", ae)
	}
	if n := len(requestsTo(s, http.MethodGet, path)); n != 2 {
		t.Errorf("%d requests for two 403s, want 2", n)
	}
	if n := len(tokenRequests(s)); n != 1 {
		t.Errorf("%d mints; a 403 re-mints nothing", n)
	}
}
