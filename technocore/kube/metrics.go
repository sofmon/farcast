package kube

import (
	"context"
	"fmt"
	"net/url"
	"time"
)

// The aggregated metrics API — what `kubectl top` reads. On GKE it is served
// by a managed metrics-server, so nothing has to be installed for this to
// work; on a cluster without one, every request 404s and [ADR 0014]
// decision 2 is what makes that a named state rather than a failure.
//
// [ADR 0014]: ../../docs/adr/0014-observed-usage.md
const metricsAPI = "/apis/metrics.k8s.io/v1beta1"

// ContainerMetrics is one container's current consumption.
type ContainerMetrics struct {
	Name string `json:"name"`
	// Usage reuses ResourceList because the wire shape is the same map of
	// quantities. It is consumption, not a reservation.
	Usage ResourceList `json:"usage"`
}

// PodMetrics is one pod's reading.
type PodMetrics struct {
	Metadata ObjectMeta `json:"metadata"`
	// Timestamp is when the reading was taken, by the server. It is what
	// makes a sample new: metrics-server refreshes on its own cadence and
	// serves the same reading until it does, so a poller that ignored this
	// would count one measurement many times.
	Timestamp time.Time `json:"timestamp"`
	// Window is the interval the reading averages over, as a duration string.
	// It is carried so a report can say how smoothed the number is.
	Window     string             `json:"window"`
	Containers []ContainerMetrics `json:"containers"`
}

// Usage returns the pod's consumption: every container summed.
//
// The sum happens in base units and is rounded once at the end, unlike
// [Pod.Requests], which rounds per container. A request is a declared integer
// so rounding it per container changes nothing; usage is a measurement, and
// rounding each of two idling containers up to a millicore would report twice
// what the pod is doing.
func (m PodMetrics) Usage() (cpuMilli, memMiB int, err error) {
	var cores, bytes float64
	for _, c := range m.Containers {
		if s := c.Usage.CPU; s != "" {
			v, err := ParseQuantity(s)
			if err != nil {
				return 0, 0, fmt.Errorf("kube: container %q cpu: %w", c.Name, err)
			}
			cores += v
		}
		if s := c.Usage.Memory; s != "" {
			v, err := ParseQuantity(s)
			if err != nil {
				return 0, 0, fmt.Errorf("kube: container %q memory: %w", c.Name, err)
			}
			bytes += v
		}
	}
	if cpuMilli, err = ceilInt(cores * 1000); err != nil {
		return 0, 0, err
	}
	if memMiB, err = ceilInt(bytes / (1 << 20)); err != nil {
		return 0, 0, err
	}
	return cpuMilli, memMiB, nil
}

// PodMetricsList is the aggregated API's list response.
type PodMetricsList struct {
	Items []PodMetrics `json:"items"`
}

// ListPodMetrics returns current readings for the pods in a namespace.
//
// A cluster with no metrics API returns ErrNotFound, and a namespace the
// kernel may list pods in but not metrics returns ErrForbidden. Both are for
// the caller to name rather than to fail on: usage is advisory, and the cost
// meter reads requests.
func (c *Client) ListPodMetrics(ctx context.Context, namespace, selector string) ([]PodMetrics, error) {
	var out PodMetricsList
	path := fmt.Sprintf("%s/namespaces/%s/pods", metricsAPI, url.PathEscape(namespace))
	if err := c.get(ctx, path, selector, &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}
