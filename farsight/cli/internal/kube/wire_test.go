package kube_test

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
)

// waits records the waits a client would have slept between retries.
type waits struct {
	mu sync.Mutex
	d  []time.Duration
}

func (w *waits) sleep(_ context.Context, d time.Duration) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.d = append(w.d, d)
	return nil
}

func (w *waits) all() []time.Duration {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]time.Duration(nil), w.d...)
}

// connect is a client of s as farcast builds one: s's recorded endpoint and
// cluster CA through ParseEndpoint, and a fresh credential registered on s
// under id, through New. Its retry waits are recorded, not slept.
func connect(t *testing.T, s *kubetest.Server, id string) (*kube.Client, *waits) {
	t.Helper()
	ep, err := kube.ParseEndpoint(s.Endpoint(), "", s.CAPEM())
	if err != nil {
		t.Fatal(err)
	}
	c, err := kube.New(kube.Config{Endpoint: ep, Credential: s.Credential(id), Identity: kube.Writer})
	if err != nil {
		t.Fatal(err)
	}
	w := &waits{}
	kube.SetSleep(c, w.sleep)
	return c, w
}

// apiRequests are the requests s saw, but its token requests.
func apiRequests(s *kubetest.Server) []kubetest.Request {
	var out []kubetest.Request
	for _, r := range s.Requests() {
		if r.Path != "/token" {
			out = append(out, r)
		}
	}
	return out
}

// tokenRequests are s's token requests.
func tokenRequests(s *kubetest.Server) []kubetest.Request {
	var out []kubetest.Request
	for _, r := range s.Requests() {
		if r.Path == "/token" {
			out = append(out, r)
		}
	}
	return out
}

// requestsTo are the requests s saw for one method and path.
func requestsTo(s *kubetest.Server, method, path string) []kubetest.Request {
	var out []kubetest.Request
	for _, r := range s.Requests() {
		if r.Method == method && r.Path == path {
			out = append(out, r)
		}
	}
	return out
}

func last(t *testing.T, s *kubetest.Server) kubetest.Request {
	t.Helper()
	reqs := apiRequests(s)
	if len(reqs) == 0 {
		t.Fatal("the server saw no API request")
	}
	return reqs[len(reqs)-1]
}

func query(t *testing.T, r kubetest.Request) url.Values {
	t.Helper()
	q, err := url.ParseQuery(r.RawQuery)
	if err != nil {
		t.Fatalf("query %q: %v", r.RawQuery, err)
	}
	return q
}

func mustKind(t *testing.T, apiVersion, kind string) kube.Kind {
	t.Helper()
	k, ok := kube.KindOf(apiVersion, kind)
	if !ok {
		t.Fatalf("%s %s is not in kube.Kinds", apiVersion, kind)
	}
	return k
}

// obj builds a JSON object for kubetest.Put.
func obj(apiVersion, kind, namespace, name string, extra map[string]any) map[string]any {
	md := map[string]any{"name": name}
	if namespace != "" {
		md["namespace"] = namespace
	}
	o := map[string]any{"apiVersion": apiVersion, "kind": kind, "metadata": md}
	for k, v := range extra {
		if k == "metadata" {
			for mk, mv := range v.(map[string]any) {
				md[mk] = mv
			}
			continue
		}
		o[k] = v
	}
	return o
}

func containsAny(s string, markers ...string) string {
	for _, m := range markers {
		if m != "" && strings.Contains(s, m) {
			return m
		}
	}
	return ""
}
