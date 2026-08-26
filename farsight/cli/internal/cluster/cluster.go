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
	"errors"
	"fmt"
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
