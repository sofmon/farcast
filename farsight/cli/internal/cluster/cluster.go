// Package cluster is FarCast's operations on an instance's cluster: apply a
// manifest stream, await a rollout, read a Service's external IP, read the
// kernel's checkpoint, and create or compare-and-replace the keyholder's key
// pin. Since ADR 0023 M2.6 it also reads an application Deployment's state,
// for run's review and plan (DeploymentState), and whether a Job is there
// (JobState).
//
// It is moving from kubectl to the in-process client in internal/kube (ADR
// 0023 decision 2), in the stages of ADR 0023 M2. Every Client farcast builds
// is built by Open, as one of the instance's two identities, in-process. The
// reader: since ADR 0023 M2.4 every cluster read of 'world', 'ps', 'costs',
// 'usage' and 'logs', and the verifying read and reviews of 'reader grant',
// run through one; it answers every read, CanI and NamespaceUID, starts no
// program, and refuses every write before anything is sent. The writer: since
// ADR 0023 M2.5 every writing command's reads run through one, and so do the
// storage key pin's create and replace, in-process as the instance's stored
// installer key. Only the writer's Apply still runs kubectl, as the active
// gcloud configuration, until ADR 0023 M2.7 — the CLI holds cloud
// credentials, so its dependency surface is a security concern (ADR 0006),
// and the stored kubeconfig drives the control plane through the
// gke-gcloud-auth-plugin exec credential.
//
// A Client with no in-process client is built only by this package's tests
// (newWithEnv and newWithRunner), until kubectl goes in ADR 0023 M2.7. It runs
// kubectl for Apply alone, and refuses every other method, running nothing
// (inProcessOnly).
//
// kubectl never inherits this process's environment. Every call runs with one
// built from an allowlist (Env, ADR 0023 M0), with KUBERC=off, and finds
// kubectl on that environment's own PATH.
//
// The exec boundary is the Runner interface, so this package's tests drive
// Apply with a fake one; the real cloud path is integration-gated.
package cluster

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/kube"
)

// Runner executes one kubectl invocation (with optional stdin) and returns its
// stdout. It is injectable so orchestration can be tested without a cluster.
type Runner interface {
	Run(ctx context.Context, stdin []byte, args ...string) (stdout []byte, err error)
}

// errKubectlMissing marks a kubectl that could not be found. Every error a
// missing kubectl produces wraps it. Since ADR 0023 M2.4 nothing outside this
// package reads it, or the two marks below: they keep a kubectl failure's
// text as it always read, until kubectl goes in ADR 0023 M2.7.
var errKubectlMissing = errors.New("kubectl not found")

// errAuthToolMissing marks a kubectl that ran but could not authenticate
// because the tool its kubeconfig names — the gke-gcloud-auth-plugin, or the
// gcloud it runs — is not installed where it looks.
var errAuthToolMissing = errors.New("the cluster's auth plugin or gcloud is missing")

// errSignedOut marks a kubectl that ran but whose credential plugin could not
// get a token because gcloud's user session has expired. Signing in again is
// the operator's act; nothing here can do it for them.
var errSignedOut = errors.New("gcloud is signed out")

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
		return errAuthToolMissing
	case strings.Contains(stderr, "Reauthentication failed"),
		strings.Contains(stderr, "problem refreshing your current auth tokens"),
		strings.Contains(stderr, "does not have any valid credentials"),
		strings.Contains(stderr, "You do not currently have an active account selected"),
		strings.Contains(stderr, "gcloud auth login"):
		return errSignedOut
	}
	return nil
}

// execRunner runs the real kubectl binary, against a kubeconfig.
//
// The subprocess gets exactly env, with KUBERC=off enforced, and nothing else
// from this process; kubectl is looked up on env's own PATH, so the binary
// that runs is the one the environment it runs in would find. An Open'd
// writer builds it with Env(os.Environ()) as env (Open), and newWithEnv with
// the env a test hands it.
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
		return nil, &subprocessError{msg: r.missingText(), mark: errKubectlMissing}
	}
	cmd := exec.CommandContext(ctx, path, full...)
	cmd.Env = withKubercOff(r.env)
	return cmd, nil
}

// ready is what command and kubectl itself would refuse before anything
// runs, found without running anything: no kubectl on env's PATH (command's
// own error, its text unchanged), or a kubeconfig that is not there, which
// kubectl refuses for an explicit --kubeconfig before it reads anything else.
func (r execRunner) ready() error {
	if _, ok := lookPathIn("kubectl", envValue(r.env, "PATH")); !ok {
		return &subprocessError{msg: r.missingText(), mark: errKubectlMissing}
	}
	if _, err := os.Stat(r.kubeconfig); err != nil {
		return fmt.Errorf("this machine has no kubeconfig for the instance, which kubectl applies through until ADR 0023 M2.7 (%w)", err)
	}
	return nil
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
		return &subprocessError{msg: r.missingText(), mark: errKubectlMissing, err: err}
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

// Client applies workloads to a cluster and reads them back, in-process as
// the instance's reader or writer (Open), a writer's Apply through kubectl
// until ADR 0023 M2.7.
type Client struct {
	// runner is kubectl, for Apply alone: an Open'd writer's, over the
	// kubeconfig it was opened with, and nil when it was opened without one.
	// An Open'd reader has none. A test-built Client (newWithEnv,
	// newWithRunner) has a runner and nothing else.
	runner Runner

	// kube is the in-process client of an Open'd Client, and nil only for a
	// test-built one. Every exported method but Apply begins by checking it,
	// and refuses without it (inProcessOnly); Apply never touches it, so a
	// Client reaches its runner, if it has one, only to apply.
	kube *kube.Client
	// warnings receives the kube client's Warning texts and Logs' notes
	// (Open); warned is how many Warning texts have been written. Both are
	// written under warnMu.
	warnings io.Writer
	warnMu   sync.Mutex
	warned   int

	// poll is the wait between the reads of RolloutStatus, WaitExternalIP and
	// WaitJob; zero is each one's own (2 s, 3 s and 5 s). cluster's tests set
	// it so that several reads take no time.
	poll time.Duration
}

// newWithEnv is a test-built Client whose one program is kubectl over
// kubeconfigPath, with kubectl's whole environment given: the subprocess sees
// env, with KUBERC=off enforced, and nothing else, and kubectl is found on
// env's PATH. A nil or empty env is an environment with nothing in it, which
// finds no kubectl. It has no in-process client, so every method but Apply
// refuses on it (inProcessOnly). It is for this package's environment tests,
// until kubectl goes in ADR 0023 M2.7.
func newWithEnv(kubeconfigPath string, env []string) *Client {
	if env == nil {
		env = []string{}
	}
	return &Client{runner: execRunner{
		kubeconfig: kubeconfigPath, env: env,
		missing: "kubectl not found on the PATH this client runs with — deploying into an instance needs kubectl and the gke-gcloud-auth-plugin",
	}}
}

// newWithRunner returns a test-built Client backed by a custom Runner, for
// this package's Apply tests, until ADR 0023 M2.7. Like a newWithEnv client,
// it refuses every method but Apply.
func newWithRunner(r Runner) *Client { return &Client{runner: r} }

// Apply pipes a multi-document manifest to `kubectl apply -f -`. It is
// idempotent: re-applying an unchanged workload is a no-op. A reader client
// refuses it before anything is sent. A writer runs kubectl over the
// kubeconfig it was opened with, and refuses it, running nothing, when it was
// opened without one: Apply is the one method that runs kubectl until ADR
// 0023 M2.7, and never sends anything in-process.
func (c *Client) Apply(ctx context.Context, manifests []byte) error {
	if err := c.neverWrites(); err != nil {
		return err
	}
	if c.runner == nil {
		return errNoKubeconfig
	}
	_, err := c.runner.Run(ctx, manifests, "apply", "-f", "-")
	return err
}

// ApplyReady reports, running nothing and sending nothing, whether Apply
// could start: a reader never applies (errNeverWrites), a writer opened
// without a kubeconfig cannot (errNoKubeconfig), and an Open'd writer's
// kubectl must be on the PATH its environment gives and its kubeconfig must
// be there. Each refusal is the one Apply would return, earlier. A writing
// command asks it right after it opens its writer, before it reads, asks,
// mints, pushes, writes or records anything (ADR 0023 M2.5): until Apply runs
// in-process in ADR 0023 M2.7 a machine without kubectl cannot finish any
// command that applies, and since M2.5 that command's first reads no longer
// run kubectl to find out. It cannot tell whether the auth plugin is
// installed or gcloud is signed in; only kubectl's run finds those. A
// test-built runner that is not kubectl is ready.
func (c *Client) ApplyReady() error {
	if err := c.neverWrites(); err != nil {
		return err
	}
	if c.runner == nil {
		return errNoKubeconfig
	}
	if r, ok := c.runner.(execRunner); ok {
		return r.ready()
	}
	return nil
}

// RolloutStatus blocks until the named Deployment is rolled out or the timeout
// elapses. It judges the Deployment itself, read every 2 s, by
// kube.RolloutState.
func (c *Client) RolloutStatus(ctx context.Context, namespace, name string, timeout time.Duration) error {
	if c.kube == nil {
		return inProcessOnly("RolloutStatus")
	}
	return c.rolloutInProcess(ctx, namespace, name, timeout)
}

// WaitExternalIP reads the named Service every 3 s until its load-balancer
// ingress IP is assigned or the timeout elapses.
func (c *Client) WaitExternalIP(ctx context.Context, namespace, name string, timeout time.Duration) (string, error) {
	if c.kube == nil {
		return "", inProcessOnly("WaitExternalIP")
	}
	return c.externalIPInProcess(ctx, namespace, name, timeout)
}

// JobResult is how a build Job ended.
type JobResult struct {
	Succeeded bool
	// Message is the container's termination message, which is where the
	// build reports the digest it pushed. Kubernetes surfaces it in the Pod's
	// status, so reading it needs no log parsing and no shared volume.
	Message string
	// UID is the Job's metadata.uid, as the GET that ended WaitJob's wait, or
	// JobState's one GET, read it: which Job this result is of, since a Job's
	// name is deterministic and a Job of the same name may be another one.
	UID string
}

// WaitJob blocks until a Job succeeds or fails, reading it every 5 s.
//
// It watches for both, rather than for completion alone as `kubectl wait
// --for=condition=complete` would: a build that fails would sit there until
// the timeout and be reported as a timeout, which is the wrong diagnosis for a
// Containerfile that does not compile.
func (c *Client) WaitJob(ctx context.Context, namespace, name string, timeout time.Duration) (JobResult, error) {
	if c.kube == nil {
		return JobResult{}, inProcessOnly("WaitJob")
	}
	return c.waitJobInProcess(ctx, namespace, name, timeout)
}

// JobState reads a Job once, and reports whether it is there: its uid, and
// whether it has succeeded as WaitJob judges it. It reads no pod, so Message
// is always "", and a Job that has not succeeded may be running or may have
// failed: a caller uses JobState for a Job's presence and uid, and WaitJob for
// its outcome.
//
// The Job is absent only when the API server says so: a 404 whose body is a
// Kubernetes Status. A 403, or a 404 from anything else, is an error with
// found false, and never absent.
func (c *Client) JobState(ctx context.Context, namespace, name string) (JobResult, bool, error) {
	if c.kube == nil {
		return JobResult{}, false, inProcessOnly("JobState")
	}
	return c.jobStateInProcess(ctx, namespace, name)
}

// JobLogs returns a Job's output: a build failure the operator has to read, or
// a manifest read whose whole point is what it printed.
//
// A non-positive lines asks for everything. That is not a convenience — a
// fetch's stdout IS the manifest, and a tail of it is a manifest that parses
// and is missing its first applications.
func (c *Client) JobLogs(ctx context.Context, namespace, job string, lines int) (string, error) {
	if c.kube == nil {
		return "", inProcessOnly("JobLogs")
	}
	return c.jobLogsInProcess(ctx, namespace, job, lines)
}

// Streamer is a Runner that can also write a command's output as it arrives.
//
// It is a second interface rather than a second method on Runner because
// almost nothing needed it: following logs was the only place where waiting
// for a subprocess to exit before showing anything would be wrong. Since ADR
// 0023 M2.4 Logs is in-process only, so nothing streams through kubectl; the
// interface and execRunner's Stream go with kubectl in M2.7.
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
			return &subprocessError{msg: r.missingText(), mark: errKubectlMissing, err: err}
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
// It lists each kind on its own, paged, and stamps the kind from the list it
// came from.
func (c *Client) Workloads(ctx context.Context, namespace string) ([]Workload, error) {
	if c.kube == nil {
		return nil, inProcessOnly("Workloads")
	}
	return c.workloadsInProcess(ctx, namespace)
}

// DeploymentState is what run's review and plan need of one live application
// Deployment (ADR 0023 §5.4 and A23-46): whether it is there, the replicas
// and requests it runs with, and whether the kernel resized it after farcast
// last applied it. The zero value is an absent Deployment.
type DeploymentState struct {
	Present bool
	// Replicas is spec.replicas, nil when the answer carried none.
	Replicas *int32
	// Requests is each container's requests, by container name; a request
	// that is not set is 0. It is nil only when the Deployment is absent.
	Requests map[string]Requests
	// AdaptedAt is the kernel's stamp on the Deployment, the
	// farcast.sofmon.com/adapted-at annotation (kernel.AdaptedAtLabel), as
	// the kernel itself reads it (kernel.Target.AdaptedAt), in UTC. It is
	// zero when the annotation is absent or does not parse: never adapted.
	AdaptedAt time.Time
	// LastAppliedAt is the newest time among the Deployment's own
	// managed-fields entries that record an apply by farcast
	// (kube.IsLastApply: farcast's Apply, or kubectl's client-side apply
	// Update), in UTC, zero when there is none. The kernel's scale and resize
	// writes never move it. Kubernetes moves an entry's time only when that
	// manager changes a value, so an apply that changed nothing leaves it
	// where it was.
	LastAppliedAt time.Time
	// ResourceVersion is metadata.resourceVersion.
	ResourceVersion string
}

// Requests is one container's requests: milli-CPU and MiB, each rounded up as
// tkube parses a quantity.
type Requests struct{ CPUMilli, MemMiB int64 }

// DeploymentState reads one Deployment, once, as run's review, its plan and
// its re-read need it.
//
// The Deployment is absent only when the API server says so: a 404 whose
// body is a Kubernetes Status, which is Present false and no error. A 403, or
// a 404 from anything else, is an error and never absent: an application
// read as absent would read as one this deploy creates, never as one it
// restarts. A set request that does not parse is an error wrapping
// kube.ErrUnreadable.
func (c *Client) DeploymentState(ctx context.Context, namespace, name string) (DeploymentState, error) {
	if c.kube == nil {
		return DeploymentState{}, inProcessOnly("DeploymentState")
	}
	return c.deploymentStateInProcess(ctx, namespace, name)
}

// ConfigMapValue returns one key from a ConfigMap, and reports whether the
// ConfigMap exists at all.
//
// The key is looked up as it is in the ConfigMap's decoded data. The keys
// FarCast stores contain dots, and a jsonpath read, as kubectl's was, takes a
// dot for a path separator: `{.data.checkpoint.json}` asks for something that
// does not exist and returns empty rather than failing, and empty reads as
// "the kernel has never checkpointed".
//
// The ConfigMap is absent only when the API server says so: a 404 whose body
// is a Kubernetes Status. A 403, or a 404 from anything else, is an error and
// never absent.
func (c *Client) ConfigMapValue(ctx context.Context, namespace, name, key string) (string, bool, error) {
	if c.kube == nil {
		return "", false, inProcessOnly("ConfigMapValue")
	}
	return c.configMapValueInProcess(ctx, namespace, name, key)
}

// ConfigMapData returns a ConfigMap's data and its resourceVersion, and
// reports whether it exists. The resourceVersion is what ReplaceConfigMap
// compares against: a write only over what was read.
func (c *Client) ConfigMapData(ctx context.Context, namespace, name string) (map[string]string, string, bool, error) {
	if c.kube == nil {
		return nil, "", false, inProcessOnly("ConfigMapData")
	}
	return c.configMapDataInProcess(ctx, namespace, name)
}

// CreateConfigMap creates a ConfigMap and fails if it already exists. Unlike
// Apply it never overwrites: the caller read "absent" and writes only over
// that. A reader client refuses it before anything is sent. A writer creates
// it in-process (kube.Client.CreateConfigMap, a POST of manifest as it is,
// never an apply), and an AlreadyExists unwraps to tkube.ErrConflict.
func (c *Client) CreateConfigMap(ctx context.Context, manifest []byte) error {
	if c.kube == nil {
		return inProcessOnly("CreateConfigMap")
	}
	if err := c.neverWrites(); err != nil {
		return err
	}
	err := c.kube.CreateConfigMap(ctx, manifest)
	c.flushWarnings()
	return err
}

// ReplaceConfigMap replaces a ConfigMap whose manifest names the
// resourceVersion it was read at; the API server refuses it with a conflict
// if anything has written since. A reader client refuses it before anything
// is sent. A writer replaces it in-process (kube.Client.ReplaceConfigMap, a
// PUT of manifest as it is): a conflict unwraps to tkube.ErrConflict, and a
// manifest that names no resourceVersion is kube.ErrRefusedDocument, with
// nothing sent.
func (c *Client) ReplaceConfigMap(ctx context.Context, manifest []byte) error {
	if c.kube == nil {
		return inProcessOnly("ReplaceConfigMap")
	}
	if err := c.neverWrites(); err != nil {
		return err
	}
	err := c.kube.ReplaceConfigMap(ctx, manifest)
	c.flushWarnings()
	return err
}

// Namespaces lists every namespace in the cluster, paged, the names sorted.
//
// The whole list rather than a membership test per name: callers use it to
// refuse before doing expensive work, and an operator who mistyped two names
// should be told about both in one go.
func (c *Client) Namespaces(ctx context.Context) ([]string, error) {
	if c.kube == nil {
		return nil, inProcessOnly("Namespaces")
	}
	return c.namespacesInProcess(ctx, "")
}

// NamespacesLabelled lists the namespaces that carry a label selector, by name,
// sorted, in-process and paged.
func (c *Client) NamespacesLabelled(ctx context.Context, selector string) ([]string, error) {
	if c.kube == nil {
		return nil, inProcessOnly("NamespacesLabelled")
	}
	return c.namespacesInProcess(ctx, selector)
}

// Logs writes a workload's logs to out, optionally following them. target is
// deployment/<name> or statefulset/<name>, and lines is the tail of each
// container's log, a negative lines all of it.
//
// It reads the pod kubectl logs would choose (kube.PickPod, by the
// workload's own selector), and every container of it: init, then main, then
// ephemeral. Without follow they are read one after another; with follow at
// once, at most five, each written to out a whole line at a time, and a
// cancelled ctx is the operator ending the follow, not a failure. With
// previous, a container that has no previous instance is a note on the
// warnings writer, never on out, which carries the application's own bytes.
func (c *Client) Logs(ctx context.Context, out io.Writer, namespace, target string, lines int, follow, previous bool) error {
	if c.kube == nil {
		return inProcessOnly("Logs")
	}
	return c.logsInProcess(ctx, out, namespace, target, lines, follow, previous)
}
