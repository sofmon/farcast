// Package cluster is a minimal kubectl-subprocess wrapper: apply a manifest
// stream, await a rollout, read a Service's external IP, read the kernel's
// checkpoint, and create or compare-and-replace the keyholder's key pin. It deliberately shells to kubectl rather than vendoring
// a Kubernetes client — the CLI holds cloud credentials, so its dependency
// surface is a security concern (ADR 0006), and the stored kubeconfig already
// drives the control plane through the gke-gcloud-auth-plugin exec credential.
//
// kubectl never inherits this process's environment. Every call runs with one
// built from an allowlist (Env, ADR 0023 M0), with KUBERC=off, and finds
// kubectl on that environment's own PATH.
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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Runner executes one kubectl invocation (with optional stdin) and returns its
// stdout. It is injectable so orchestration can be tested without a cluster.
type Runner interface {
	Run(ctx context.Context, stdin []byte, args ...string) (stdout []byte, err error)
}

// ErrKubectlMissing marks a kubectl that could not be found. Every error a
// missing kubectl produces wraps it, so a caller tells it from a kubectl that
// ran and failed with errors.Is, never by its words.
var ErrKubectlMissing = errors.New("kubectl not found")

// ErrAuthToolMissing marks a kubectl that ran but could not authenticate
// because the tool its kubeconfig names — the gke-gcloud-auth-plugin, or the
// gcloud it runs — is not installed where it looks.
var ErrAuthToolMissing = errors.New("the cluster's auth plugin or gcloud is missing")

// ErrSignedOut marks a kubectl that ran but whose credential plugin could not
// get a token because gcloud's user session has expired. Signing in again is
// the operator's act; nothing here can do it for them.
var ErrSignedOut = errors.New("gcloud is signed out")

// subprocessError is a kubectl failure as it always read, marked with what it
// means. The text is the same text it carried before it was marked: the mark
// is for a caller deciding what to do, not for the operator reading it.
type subprocessError struct {
	msg  string
	mark error
	err  error
}

func (e *subprocessError) Error() string { return e.msg }

func (e *subprocessError) Unwrap() []error {
	out := make([]error, 0, 2)
	if e.mark != nil {
		out = append(out, e.mark)
	}
	if e.err != nil {
		out = append(out, e.err)
	}
	return out
}

// markOf reads what kubectl's stderr says about authentication. The phrases
// are the ones the auth plugin and gcloud print; a kubectl failure that says
// none of them is an ordinary failure, and unmarked.
//
// Signed out covers a session that expired, an account that sits in a
// configuration but was never logged in on this machine or had its grant
// revoked, and a configuration with no account at all: every one of them is
// fixed by the operator signing in, and gcloud ends each with the command
// that does it.
func markOf(stderr string) error {
	switch {
	// A missing tool first: it is the more exact diagnosis, and gcloud's own
	// advice in the same text may name a sign-in that would not help.
	case strings.Contains(stderr, "executable gke-gcloud-auth-plugin not found"),
		strings.Contains(stderr, "gke-gcloud-auth-plugin: executable file not found"),
		strings.Contains(stderr, `"gke-gcloud-auth-plugin": executable file not found`),
		strings.Contains(stderr, `"gcloud": executable file not found`),
		strings.Contains(stderr, "gcloud: executable file not found"):
		return ErrAuthToolMissing
	case strings.Contains(stderr, "Reauthentication failed"),
		strings.Contains(stderr, "problem refreshing your current auth tokens"),
		strings.Contains(stderr, "does not have any valid credentials"),
		strings.Contains(stderr, "You do not currently have an active account selected"),
		strings.Contains(stderr, "gcloud auth login"):
		return ErrSignedOut
	}
	return nil
}

// execRunner runs the real kubectl binary, against a kubeconfig.
//
// The subprocess gets exactly env, with KUBERC=off enforced, and nothing else
// from this process; kubectl is looked up on env's own PATH, so the binary
// that runs is the one the environment it runs in would find. New builds env
// with Env, unpinned; 'world' hands NewWithEnv one pinned to its identity.
type execRunner struct {
	kubeconfig string
	env        []string
	// missing is what a missing kubectl means to the command that wanted it.
	missing string
}

func (r execRunner) command(ctx context.Context, args []string) (*exec.Cmd, error) {
	full := append([]string{"--kubeconfig", r.kubeconfig}, args...)
	path, ok := lookPathIn("kubectl", envValue(r.env, "PATH"))
	if !ok {
		return nil, &subprocessError{msg: r.missingText(), mark: ErrKubectlMissing}
	}
	cmd := exec.CommandContext(ctx, path, full...)
	cmd.Env = withKubercOff(r.env)
	return cmd, nil
}

func (r execRunner) missingText() string {
	if r.missing != "" {
		return r.missing
	}
	return "kubectl not found on PATH — deploying into an instance needs kubectl and the gke-gcloud-auth-plugin"
}

// failure turns a kubectl that did not succeed into an error.
//
// A context that ended is wrapped as itself, so a caller can tell a timeout
// from a refusal: kubectl killed by its deadline says only "signal: killed",
// which reads like a crash.
func (r execRunner) failure(ctx context.Context, args []string, stderr string, err error) error {
	if errors.Is(err, exec.ErrNotFound) {
		return &subprocessError{msg: r.missingText(), mark: ErrKubectlMissing, err: err}
	}
	if cerr := ctx.Err(); cerr != nil {
		return fmt.Errorf("kubectl %s: %w", strings.Join(args, " "), cerr)
	}
	if msg := strings.TrimSpace(stderr); msg != "" {
		return &subprocessError{msg: fmt.Sprintf("kubectl %s: %s", strings.Join(args, " "), msg), mark: markOf(msg)}
	}
	return fmt.Errorf("kubectl %s: %w", strings.Join(args, " "), err)
}

func (r execRunner) Run(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	cmd, err := r.command(ctx, args)
	if err != nil {
		return nil, err
	}
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, r.failure(ctx, args, errb.String(), err)
	}
	return out.Bytes(), nil
}

// envValue is the last value env gives key, the one a process reading its
// environment sees.
func envValue(env []string, key string) string {
	v := ""
	for _, kv := range env {
		if k, val, ok := strings.Cut(kv, "="); ok && k == key {
			v = val
		}
	}
	return v
}

// lookPathIn finds an executable named name on a PATH value, as a shell
// would: the first directory that holds an executable regular file by that
// name. An empty entry is not the current directory here — a binary planted
// in whatever directory the CLI happens to run from must never be the kubectl
// that holds the operator's cluster credential.
//
// On Windows the file is name.exe, and Windows keeps no execute bit to check.
// That branch is untested until ADR 0023 M4.
func lookPathIn(name, pathValue string) (string, bool) {
	windows := runtime.GOOS == "windows"
	if windows {
		name += ".exe"
	}
	for _, dir := range filepath.SplitList(pathValue) {
		if dir == "" || !filepath.IsAbs(dir) {
			continue
		}
		p := filepath.Join(dir, name)
		info, err := os.Stat(p)
		if err != nil || !info.Mode().IsRegular() || (!windows && info.Mode().Perm()&0o111 == 0) {
			continue
		}
		return p, true
	}
	return "", false
}

// Client applies workloads to a cluster over a kubeconfig.
type Client struct {
	runner Runner
}

// New returns a Client that shells to kubectl using the kubeconfig at the given
// path (the per-instance kubeconfig.yaml the CLI stored at install time).
//
// kubectl runs with Env(os.Environ(), kubeconfigPath, GCloud{}): an
// environment built from an allowlist, unpinned, so it acts as whichever gcloud
// configuration the parent selects (ADR 0023 M0 changes what reaches kubectl,
// not who it acts as) and keeps the parent's KUBECONFIG, never the instance's.
// It is NewWithEnv with that environment, keeping its own words for a missing
// kubectl.
func New(kubeconfigPath string) *Client {
	return &Client{runner: execRunner{
		kubeconfig: kubeconfigPath,
		env:        Env(os.Environ(), kubeconfigPath, GCloud{}),
	}}
}

// NewWithEnv is New with kubectl's whole environment given: the subprocess
// sees env, with KUBERC=off enforced, and nothing else, and kubectl is found on
// env's PATH. A nil or empty env is an environment with nothing in it, which
// finds no kubectl.
//
// It exists for 'farcast world', which pins the identity kubectl's auth plugin
// acts as (ADR 0021 decision 9, amended 2026-11-12): what reaches the plugin
// is decided by the caller, not by whatever the operator's shell exported.
func NewWithEnv(kubeconfigPath string, env []string) *Client {
	if env == nil {
		env = []string{}
	}
	return &Client{runner: execRunner{
		kubeconfig: kubeconfigPath, env: env,
		missing: "kubectl not found on the PATH this read runs with — reading an instance needs kubectl, the gke-gcloud-auth-plugin and gcloud",
	}}
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
	r.missing = "kubectl not found on PATH — reading an instance's logs needs kubectl and the gke-gcloud-auth-plugin"
	cmd, err := r.command(ctx, args)
	if err != nil {
		return err
	}
	var errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = out, &errb
	if err := cmd.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return &subprocessError{msg: r.missingText(), mark: ErrKubectlMissing, err: err}
		}
		// A follow the operator interrupted is not a failure, and reporting it
		// as one would end every 'farcast logs --follow' with an error.
		if ctx.Err() != nil {
			return nil
		}
		return r.failure(ctx, args, errb.String(), err)
	}
	return nil
}

// Workload is one Deployment or StatefulSet, as much of it as a listing needs.
type Workload struct {
	// Kind is "Deployment" or "StatefulSet". It is carried because reading a
	// workload's logs needs the kind in the target, and guessing "deployment/"
	// is how the Phase 4.3 walk found the key holder invisible to `farcast ps`.
	Kind      string
	Namespace string
	Name      string
	Desired   int
	Ready     int
	Images    []string
	Labels    map[string]string
	CreatedAt time.Time
}

// Workloads lists the Deployments and StatefulSets in a namespace.
//
// Both kinds, because FarCast runs both: the key holder is a StatefulSet, and
// a listing that asked only for Deployments showed an instance with no storage
// in it at all. The Phase 4.3 walk found that — `farcast ps --all` claimed to
// show FarCast's own components and silently omitted one of them.
//
// It reads JSON rather than a jsonpath or custom columns. Both of those are
// output formats meant for a human to eyeball, and both would parse a
// cluster's answer by position — a column that moves becomes silently wrong
// data rather than an error.
func (c *Client) Workloads(ctx context.Context, namespace string) ([]Workload, error) {
	out, err := c.runner.Run(ctx, nil, "get", "deployments,statefulsets", "-n", namespace, "-o", "json")
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return nil, nil
	}
	var list struct {
		Items []struct {
			Kind     string `json:"kind"`
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
			Kind:      it.Kind,
			Namespace: it.Metadata.Namespace,
			Name:      it.Metadata.Name,
			Ready:     it.Status.ReadyReplicas,
			Labels:    it.Metadata.Labels,
			CreatedAt: it.Metadata.CreationTimestamp,
		}
		if w.Namespace == "" {
			w.Namespace = namespace
		}
		if w.Kind == "" {
			w.Kind = "Deployment"
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

// ConfigMapData returns a ConfigMap's data and its resourceVersion, and
// reports whether it exists. The resourceVersion is what ReplaceConfigMap
// compares against: a write only over what was read.
func (c *Client) ConfigMapData(ctx context.Context, namespace, name string) (map[string]string, string, bool, error) {
	out, err := c.runner.Run(ctx, nil, "get", "configmap", name, "-n", namespace,
		"--ignore-not-found", "-o", "json")
	if err != nil {
		return nil, "", false, err
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return nil, "", false, nil
	}
	var cm struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(out, &cm); err != nil {
		return nil, "", false, fmt.Errorf("cluster: read %s/%s: %w", namespace, name, err)
	}
	if cm.Metadata.ResourceVersion == "" {
		return nil, "", false, fmt.Errorf("cluster: %s/%s carries no resourceVersion", namespace, name)
	}
	return cm.Data, cm.Metadata.ResourceVersion, true, nil
}

// CreateConfigMap creates a ConfigMap and fails if it already exists. Unlike
// Apply it never overwrites: the caller read "absent" and writes only over
// that.
func (c *Client) CreateConfigMap(ctx context.Context, manifest []byte) error {
	_, err := c.runner.Run(ctx, manifest, "create", "-f", "-")
	return err
}

// ReplaceConfigMap replaces a ConfigMap whose manifest names the
// resourceVersion it was read at; the API server refuses it with a conflict
// if anything has written since.
func (c *Client) ReplaceConfigMap(ctx context.Context, manifest []byte) error {
	_, err := c.runner.Run(ctx, manifest, "replace", "-f", "-")
	return err
}

// Namespaces lists every namespace in the cluster.
//
// The whole list rather than a membership test per name: callers use it to
// refuse before doing expensive work, and an operator who mistyped two names
// should be told about both in one go.
func (c *Client) Namespaces(ctx context.Context) ([]string, error) {
	out, err := c.runner.Run(ctx, nil, "get", "namespace", "-o", "name")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		names = append(names, strings.TrimPrefix(line, "namespace/"))
	}
	return names, nil
}

// NamespacesLabelled lists the namespaces that carry a label selector, by name,
// sorted.
//
// JSON, for the reason Workloads reads JSON: a namespace listing parsed by
// position is one column move away from silently wrong data.
func (c *Client) NamespacesLabelled(ctx context.Context, selector string) ([]string, error) {
	out, err := c.runner.Run(ctx, nil, "get", "namespace", "-l", selector, "-o", "json")
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return []string{}, nil
	}
	var list struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, fmt.Errorf("cluster: read the namespaces labelled %s: %w", selector, err)
	}
	names := make([]string, 0, len(list.Items))
	for _, it := range list.Items {
		if it.Metadata.Name != "" {
			names = append(names, it.Metadata.Name)
		}
	}
	sort.Strings(names)
	return names, nil
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
