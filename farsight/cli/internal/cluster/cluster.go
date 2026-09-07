// Package cluster is a minimal kubectl-subprocess wrapper for the connect-time
// FatLine bootstrap: apply a manifest stream, await a rollout, and read a
// Service's external IP. It deliberately shells to kubectl rather than vendoring
// a Kubernetes client — the CLI holds cloud credentials, so its dependency
// surface is a security concern (ADR 0006), and the stored kubeconfig already
// drives the control plane through the gke-gcloud-auth-plugin exec credential.
//
// The exec boundary is the Runner interface, so the connect orchestration is
// unit-tested with a fake; the real cloud path is integration-gated.
package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

// Runner executes one kubectl invocation (with optional stdin) and returns its
// stdout. It is injectable so orchestration can be tested without a cluster.
type Runner interface {
	Run(ctx context.Context, stdin []byte, args ...string) (stdout []byte, err error)
}

// execRunner runs the real kubectl binary found on PATH, against a kubeconfig.
type execRunner struct{ kubeconfig string }

func (r execRunner) Run(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	full := append([]string{"--kubeconfig", r.kubeconfig}, args...)
	cmd := exec.CommandContext(ctx, "kubectl", full...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, errors.New("kubectl not found on PATH — deploying into an instance needs kubectl and the gke-gcloud-auth-plugin")
		}
		if msg := strings.TrimSpace(errb.String()); msg != "" {
			return nil, fmt.Errorf("kubectl %s: %s", strings.Join(args, " "), msg)
		}
		return nil, fmt.Errorf("kubectl %s: %w", strings.Join(args, " "), err)
	}
	return out.Bytes(), nil
}

// Client applies workloads to a cluster over a kubeconfig.
type Client struct {
	runner Runner
}

// New returns a Client that shells to kubectl using the kubeconfig at the given
// path (the per-instance kubeconfig.yaml the CLI stored at install time).
func New(kubeconfigPath string) *Client {
	return &Client{runner: execRunner{kubeconfig: kubeconfigPath}}
}

// NewWithRunner returns a Client backed by a custom Runner (for tests).
func NewWithRunner(r Runner) *Client { return &Client{runner: r} }

// Apply pipes a multi-document manifest to `kubectl apply -f -`. It is
// idempotent: re-applying an unchanged workload is a no-op.
func (c *Client) Apply(ctx context.Context, manifests []byte) error {
	_, err := c.runner.Run(ctx, manifests, "apply", "-f", "-")
	return err
}

// RolloutStatus blocks until the named Deployment is rolled out or the timeout
// elapses.
func (c *Client) RolloutStatus(ctx context.Context, namespace, name string, timeout time.Duration) error {
	_, err := c.runner.Run(ctx, nil, "rollout", "status",
		"deployment/"+name, "-n", namespace, "--timeout", durArg(timeout))
	return err
}

// WaitExternalIP polls the named Service until its load-balancer ingress IP is
// assigned or the timeout elapses.
func (c *Client) WaitExternalIP(ctx context.Context, namespace, name string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for {
		ip, err := c.serviceExternalIP(ctx, namespace, name)
		if err != nil {
			return "", err
		}
		if ip != "" {
			return ip, nil
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("cluster: service %s/%s had no external IP after %s", namespace, name, timeout)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

func (c *Client) serviceExternalIP(ctx context.Context, namespace, name string) (string, error) {
	out, err := c.runner.Run(ctx, nil, "get", "service", name, "-n", namespace,
		"-o", "jsonpath={.status.loadBalancer.ingress[0].ip}")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// durArg formats a timeout for kubectl's --timeout flag (e.g. "180s").
func durArg(d time.Duration) string {
	return fmt.Sprintf("%ds", int(d.Seconds()))
}

// JobResult is how a build Job ended.
type JobResult struct {
	Succeeded bool
	// Message is the container's termination message, which is where the
	// build reports the digest it pushed. Kubernetes surfaces it in the Pod's
	// status, so reading it needs no log parsing and no shared volume.
	Message string
}

// WaitJob blocks until a Job succeeds or fails.
//
// It polls both conditions rather than using `kubectl wait --for=condition=complete`,
// because that call cannot express "or failed": a build that fails would sit
// there until the timeout and be reported as a timeout, which is the wrong
// diagnosis for a Containerfile that does not compile.
func (c *Client) WaitJob(ctx context.Context, namespace, name string, timeout time.Duration) (JobResult, error) {
	deadline := time.Now().Add(timeout)
	for {
		out, err := c.runner.Run(ctx, nil, "get", "job", name, "-n", namespace,
			"-o", "jsonpath={.status.succeeded}/{.status.failed}")
		if err != nil {
			return JobResult{}, err
		}
		succeeded, failed, _ := strings.Cut(strings.TrimSpace(string(out)), "/")
		switch {
		case succeeded != "" && succeeded != "0":
			msg, _ := c.jobMessage(ctx, namespace, name)
			return JobResult{Succeeded: true, Message: msg}, nil
		case failed != "" && failed != "0":
			msg, _ := c.jobMessage(ctx, namespace, name)
			return JobResult{Succeeded: false, Message: msg}, nil
		}
		if time.Now().After(deadline) {
			return JobResult{}, fmt.Errorf("cluster: job %s/%s neither succeeded nor failed after %s", namespace, name, timeout)
		}
		select {
		case <-ctx.Done():
			return JobResult{}, ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

// jobMessage reads the terminated container's message from the Job's Pod.
//
// A missing message is not an error: a Pod that was evicted, or a container
// that died before writing, leaves nothing there, and the caller's own
// "no digest" failure is a better diagnosis than one about jsonpath.
func (c *Client) jobMessage(ctx context.Context, namespace, job string) (string, error) {
	out, err := c.runner.Run(ctx, nil, "get", "pods", "-n", namespace,
		"-l", "job-name="+job,
		"-o", "jsonpath={.items[0].status.containerStatuses[0].state.terminated.message}")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// JobLogs returns a Job's output: a build failure the operator has to read, or
// a manifest read whose whole point is what it printed.
//
// A non-positive lines asks for everything. That is not a convenience — a
// fetch's stdout IS the manifest, and a tail of it is a manifest that parses
// and is missing its first applications.
func (c *Client) JobLogs(ctx context.Context, namespace, job string, lines int) (string, error) {
	tail := "-1"
	if lines > 0 {
		tail = fmt.Sprintf("%d", lines)
	}
	out, err := c.runner.Run(ctx, nil, "logs", "-n", namespace,
		"job/"+job, "--tail="+tail)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// Streamer is a Runner that can also write a command's output as it arrives.
//
// It is a second interface rather than a second method on Runner because
// almost nothing needs it: following logs is the only place where waiting for
// a subprocess to exit before showing anything would be wrong. A Runner that
// does not implement it simply cannot follow.
type Streamer interface {
	Stream(ctx context.Context, out io.Writer, args ...string) error
}

func (r execRunner) Stream(ctx context.Context, out io.Writer, args ...string) error {
	full := append([]string{"--kubeconfig", r.kubeconfig}, args...)
	cmd := exec.CommandContext(ctx, "kubectl", full...)
	var errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = out, &errb
	if err := cmd.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return errors.New("kubectl not found on PATH — reading an instance's logs needs kubectl and the gke-gcloud-auth-plugin")
		}
		// A follow the operator interrupted is not a failure, and reporting it
		// as one would end every 'farcast logs --follow' with an error.
		if ctx.Err() != nil {
			return nil
		}
		if msg := strings.TrimSpace(errb.String()); msg != "" {
			return fmt.Errorf("kubectl %s: %s", strings.Join(args, " "), msg)
		}
		return fmt.Errorf("kubectl %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

// Workload is one Deployment, as much of it as a listing needs.
type Workload struct {
	Namespace string
	Name      string
	Desired   int
	Ready     int
	Images    []string
	Labels    map[string]string
	CreatedAt time.Time
}

// Deployments lists the Deployments in a namespace.
//
// It reads JSON rather than a jsonpath or custom columns. Both of those are
// output formats meant for a human to eyeball, and both would parse a
// cluster's answer by position — a column that moves becomes silently wrong
// data rather than an error.
func (c *Client) Deployments(ctx context.Context, namespace string) ([]Workload, error) {
	out, err := c.runner.Run(ctx, nil, "get", "deployments", "-n", namespace, "-o", "json")
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return nil, nil
	}
	var list struct {
		Items []struct {
			Metadata struct {
				Name              string            `json:"name"`
				Namespace         string            `json:"namespace"`
				Labels            map[string]string `json:"labels"`
				CreationTimestamp time.Time         `json:"creationTimestamp"`
			} `json:"metadata"`
			Spec struct {
				Replicas *int `json:"replicas"`
				Template struct {
					Spec struct {
						Containers []struct {
							Image string `json:"image"`
						} `json:"containers"`
					} `json:"spec"`
				} `json:"template"`
			} `json:"spec"`
			Status struct {
				ReadyReplicas int `json:"readyReplicas"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, fmt.Errorf("cluster: read the deployments in %s: %w", namespace, err)
	}
	workloads := make([]Workload, 0, len(list.Items))
	for _, it := range list.Items {
		w := Workload{
			Namespace: it.Metadata.Namespace,
			Name:      it.Metadata.Name,
			Ready:     it.Status.ReadyReplicas,
			Labels:    it.Metadata.Labels,
			CreatedAt: it.Metadata.CreationTimestamp,
		}
		if w.Namespace == "" {
			w.Namespace = namespace
		}
		// A Deployment with no explicit replicas runs one. Reading that as
		// zero would show every healthy application as stopped — and stopped
		// is exactly what a protective cost shutdown leaves behind, so the two
		// must never be confused.
		w.Desired = 1
		if it.Spec.Replicas != nil {
			w.Desired = *it.Spec.Replicas
		}
		for _, ct := range it.Spec.Template.Spec.Containers {
			w.Images = append(w.Images, ct.Image)
		}
		workloads = append(workloads, w)
	}
	return workloads, nil
}

// ConfigMapValue returns one key from a ConfigMap, and reports whether the
// ConfigMap exists at all.
//
// JSON again, and for a sharper reason here: the keys FarCast stores contain
// dots, and jsonpath reads a dot as a path separator. `{.data.checkpoint.json}`
// asks for something that does not exist and returns empty rather than
// failing, and empty reads as "the kernel has never checkpointed".
func (c *Client) ConfigMapValue(ctx context.Context, namespace, name, key string) (string, bool, error) {
	out, err := c.runner.Run(ctx, nil, "get", "configmap", name, "-n", namespace,
		"--ignore-not-found", "-o", "json")
	if err != nil {
		return "", false, err
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return "", false, nil
	}
	var cm struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(out, &cm); err != nil {
		return "", false, fmt.Errorf("cluster: read %s/%s: %w", namespace, name, err)
	}
	value, ok := cm.Data[key]
	if !ok {
		return "", true, fmt.Errorf("cluster: %s/%s has no %q", namespace, name, key)
	}
	return value, true, nil
}

// Logs writes a workload's logs to w, optionally following them.
func (c *Client) Logs(ctx context.Context, out io.Writer, namespace, target string, lines int, follow, previous bool) error {
	args := []string{"logs", "-n", namespace, target, fmt.Sprintf("--tail=%d", lines), "--all-containers=true"}
	if follow {
		args = append(args, "--follow")
	}
	if previous {
		args = append(args, "--previous")
	}
	if follow {
		s, ok := c.runner.(Streamer)
		if !ok {
			return errors.New("cluster: this client cannot follow logs")
		}
		return s.Stream(ctx, out, args...)
	}
	body, err := c.runner.Run(ctx, nil, args...)
	if err != nil {
		return err
	}
	_, err = out.Write(body)
	return err
}
