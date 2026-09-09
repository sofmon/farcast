package kube

import (
	"context"
	"errors"
	"testing"
)

const podMetricsReply = `{
  "kind": "PodMetricsList",
  "apiVersion": "metrics.k8s.io/v1beta1",
  "items": [
    {
      "metadata": {"name": "api-7d9", "namespace": "farcast-apps"},
      "timestamp": "2026-09-09T10:00:00Z",
      "window": "20.058s",
      "containers": [
        {"name": "api", "usage": {"cpu": "2431721n", "memory": "38884Ki"}}
      ]
    }
  ]
}`

func TestListPodMetricsReadsTheAggregatedAPI(t *testing.T) {
	var seen capture
	s := server(t, 200, podMetricsReply, &seen)
	c := client(t, s.URL, tokenFileWith(t, "tok"))

	items, err := c.ListPodMetrics(context.Background(), "farcast-apps", "app.kubernetes.io/managed-by=farcast")
	if err != nil {
		t.Fatal(err)
	}
	if seen.path != "/apis/metrics.k8s.io/v1beta1/namespaces/farcast-apps/pods" {
		t.Errorf("asked for %q", seen.path)
	}
	if seen.query != "labelSelector=app.kubernetes.io%2Fmanaged-by%3Dfarcast" {
		t.Errorf("selector went as %q", seen.query)
	}
	if len(items) != 1 {
		t.Fatalf("got %d readings, want 1", len(items))
	}
	if items[0].Timestamp.IsZero() {
		t.Error("the reading carries no timestamp, so nothing can tell it from the previous one")
	}
	if items[0].Window != "20.058s" {
		t.Errorf("window is %q", items[0].Window)
	}
}

// Nanocores and kibibytes are what metrics-server actually sends, and both
// are units the request path never sees.
func TestUsageConvertsWhatTheMetricsAPISends(t *testing.T) {
	s := server(t, 200, podMetricsReply, nil)
	c := client(t, s.URL, tokenFileWith(t, "tok"))
	items, err := c.ListPodMetrics(context.Background(), "farcast-apps", "")
	if err != nil {
		t.Fatal(err)
	}
	cpu, mem, err := items[0].Usage()
	if err != nil {
		t.Fatal(err)
	}
	if cpu != 3 { // 2431721n = 2.43 millicores, rounded up
		t.Errorf("cpu is %dm, want 3m", cpu)
	}
	if mem != 38 { // 38884Ki = 37.97 MiB, rounded up
		t.Errorf("memory is %dMi, want 38Mi", mem)
	}
}

// Rounded once at the end, not per container: two containers each idling
// below a millicore are a pod using less than one, not two.
func TestUsageRoundsThePodOnceNotEachContainer(t *testing.T) {
	m := PodMetrics{Containers: []ContainerMetrics{
		{Name: "app", Usage: ResourceList{CPU: "400000n", Memory: "100Ki"}},
		{Name: "shrike", Usage: ResourceList{CPU: "300000n", Memory: "100Ki"}},
	}}
	cpu, mem, err := m.Usage()
	if err != nil {
		t.Fatal(err)
	}
	if cpu != 1 {
		t.Errorf("cpu is %dm, want 1m — 0.7 millicores rounded once", cpu)
	}
	if mem != 1 {
		t.Errorf("memory is %dMi, want 1Mi", mem)
	}
}

func TestUsageRefusesAQuantityItCannotRead(t *testing.T) {
	m := PodMetrics{Containers: []ContainerMetrics{{Name: "app", Usage: ResourceList{CPU: "12X"}}}}
	if _, _, err := m.Usage(); err == nil {
		t.Fatal("an unreadable quantity was accepted")
	}
}

// A cluster with no metrics API is a state to name, not a failure to hide:
// the caller has to be able to tell it apart from a real error.
func TestAMissingMetricsAPIIsNotFound(t *testing.T) {
	s := server(t, 404, `{"kind":"Status","code":404,"reason":"NotFound","message":"the server could not find the requested resource"}`, nil)
	c := client(t, s.URL, tokenFileWith(t, "tok"))
	_, err := c.ListPodMetrics(context.Background(), "farcast-apps", "")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("error is %v, want ErrNotFound", err)
	}
}
