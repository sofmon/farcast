// Package cluster is FarCast's operations on an instance's cluster: apply a
// manifest stream, await a rollout, read a Service's external IP, read the
// kernel's checkpoint and an application Deployment's state, create or
// compare-and-replace the keyholder's key pin, (ADR 0023 M2.7) the
// migration's metadata reads and managed-fields patch, and (M2.8)
// git-credential rm's delete of a Secret. Every Client is built by Open, as
// one of the instance's two identities, and works in-process through
// internal/kube: the reader for the read commands and the plans, and the
// writer for a writing command's reads and every write. Every write is a
// server-side apply as farcast, except the pin's create and replace, the
// migration's patch, and git-credential rm's uid-preconditioned Secret
// delete, which takes no field manager. It starts no program: kubectl, its
// allowlisted environment and the Runner seam went in ADR 0023 M2.7.
package cluster

import (
	"context"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/kube"
)

// Client applies workloads to a cluster and reads them back, in-process as
// the instance's reader or writer (Open).
type Client struct {
	// kube is the in-process client Open built, as the instance's reader or
	// writer. It is never nil: every Client is built by Open.
	kube *kube.Client
	// warnings receives the kube client's Warning texts and Logs' notes
	// (Open); warned is how many Warning texts have been written. Both are
	// written under warnMu.
	warnings io.Writer
	warnMu   sync.Mutex
	warned   int

	// traces is every object an Apply's answer showed still carrying a trace
	// of kubectl's client-side apply (kube.ClientSideTrace), named by
	// traceName, once each, in apply order (ADR 0023 §6.6). Traces returns a
	// copy. Both are under traceMu.
	traceMu sync.Mutex
	traces  []string

	// poll is the wait between the reads of RolloutStatus, WaitExternalIP and
	// WaitJob; zero is each one's own (2 s, 3 s and 5 s). cluster's tests set
	// it so that several reads take no time.
	poll time.Duration
}

// Apply applies a rendered multi-document stream in-process (ADR 0023 M2.7,
// design §5.3): the stream is split and checked by kube.SplitStream, and each
// document is sent as its own forced server-side apply (kube.Client.Apply,
// force=true, as fieldManager farcast), in stream order, the warnings each
// answer carried written after it. It is idempotent: re-applying an
// unchanged document changes nothing.
//
// A reader client refuses it before anything is sent, and so does a stream
// SplitStream refuses or one that holds no document. Apply stops at the first
// document that fails, and its error says how many documents before it were
// applied and names the one that failed; nothing after it is sent. No apply
// is atomic: the documents before the failure stay applied.
//
// Each answer that still carries a trace of kubectl's client-side apply
// (kube.ClientSideTrace) is noted for Traces, the documents applied before a
// failure included.
func (c *Client) Apply(ctx context.Context, manifests []byte) error {
	if err := c.neverWrites(); err != nil {
		return err
	}
	docs, err := kube.SplitStream(manifests)
	if err != nil {
		return err
	}
	if len(docs) == 0 {
		return fmt.Errorf("cluster: the stream holds no document, so nothing was sent: %w", kube.ErrRefusedDocument)
	}
	return c.applyDocuments(ctx, docs)
}

// ApplyAt applies a manifest of exactly one document, as Apply applies each
// of a stream's, and lets that document carry metadata.resourceVersion when
// resourceVersion is not "" (kube.AllowResourceVersion; ADR 0023 M2.7,
// design A30-40 as §31's A31-2 amends it). The API server holds the apply to
// it: one that is no longer the stored object's is a 409 that unwraps to
// tkube.ErrConflict, and nothing is written. An object deleted since it was
// read is created again, which no resourceVersion can tell from one never
// there. With resourceVersion "" it is Apply of one document, with no
// precondition.
//
// A reader client refuses it before anything is sent, and so does a manifest
// SplitStream refuses, or one that holds no document or more than one.
func (c *Client) ApplyAt(ctx context.Context, manifest []byte, resourceVersion string) error {
	if err := c.neverWrites(); err != nil {
		return err
	}
	docs, err := kube.SplitStream(manifest, kube.AllowResourceVersion(resourceVersion))
	if err != nil {
		return err
	}
	if len(docs) != 1 {
		return fmt.Errorf("cluster: ApplyAt applies exactly one document, and the manifest holds %d, so nothing was sent: %w", len(docs), kube.ErrRefusedDocument)
	}
	return c.applyDocuments(ctx, docs)
}

// applyDocuments sends each of docs as its own forced server-side apply, in
// order, writing the warnings each answer carried after it and noting its
// traces, and stops at the first that fails (Apply's rules).
func (c *Client) applyDocuments(ctx context.Context, docs []kube.Document) error {
	for i, d := range docs {
		md, err := c.kube.Apply(ctx, d, true)
		c.flushWarnings()
		if err != nil {
			return fmt.Errorf("cluster: %d of %d documents were applied before %s failed: %w", i, len(docs), traceName(d), err)
		}
		c.noteTrace(d, md)
	}
	return nil
}

// traceName names an applied document as Traces lists it and Apply's error
// names it: "<Kind> <namespace>/<name>", or "<Kind> <name>" for a
// cluster-scoped one. It is built from the Document, whose kind, namespace
// and name SplitStream checked, never from the server's answer.
func traceName(d kube.Document) string {
	if d.Namespace == "" {
		return d.Kind.Kind + " " + d.Name
	}
	return d.Kind.Kind + " " + d.Namespace + "/" + d.Name
}

// noteTrace notes d's object, once, when the answer md to its apply still
// carries a trace of kubectl's client-side apply (kube.ClientSideTrace): the
// last-applied annotation's key, or a client-side manager's entry. Only d's
// name is kept, never anything of md, so no annotation value is held.
func (c *Client) noteTrace(d kube.Document, md kube.ObjectMeta) {
	if !kube.ClientSideTrace(md) {
		return
	}
	name := traceName(d)
	c.traceMu.Lock()
	defer c.traceMu.Unlock()
	if !slices.Contains(c.traces, name) {
		c.traces = append(c.traces, name)
	}
}

// Traces lists every object an Apply of this client answered with that still
// carries kubectl's client-side apply's annotation or entry (ADR 0023 §6.6):
// a farcast older than M2.7, or kubectl, wrote it since the instance was
// migrated. Each is named as traceName names it, once, in apply order, and
// the list is a copy; it is empty when there is none. farcast's own Apply
// entry, which every answer carries, is no trace.
func (c *Client) Traces() []string {
	c.traceMu.Lock()
	defer c.traceMu.Unlock()
	return slices.Clone(c.traces)
}

// RolloutStatus blocks until the named Deployment is rolled out or the timeout
// elapses. It judges the Deployment itself, read every 2 s, by
// kube.RolloutState.
func (c *Client) RolloutStatus(ctx context.Context, namespace, name string, timeout time.Duration) error {
	return c.rolloutInProcess(ctx, namespace, name, timeout)
}

// WaitExternalIP reads the named Service every 3 s until its load-balancer
// ingress IP is assigned or the timeout elapses.
func (c *Client) WaitExternalIP(ctx context.Context, namespace, name string, timeout time.Duration) (string, error) {
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
	return c.jobStateInProcess(ctx, namespace, name)
}

// JobLogs returns a Job's output: a build failure the operator has to read, or
// a manifest read whose whole point is what it printed.
//
// A non-positive lines asks for everything. That is not a convenience — a
// fetch's stdout IS the manifest, and a tail of it is a manifest that parses
// and is missing its first applications.
func (c *Client) JobLogs(ctx context.Context, namespace, job string, lines int) (string, error) {
	return c.jobLogsInProcess(ctx, namespace, job, lines)
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
	return c.configMapValueInProcess(ctx, namespace, name, key)
}

// ConfigMapData returns a ConfigMap's data and its resourceVersion, and
// reports whether it exists. The resourceVersion is what ReplaceConfigMap
// compares against: a write only over what was read.
func (c *Client) ConfigMapData(ctx context.Context, namespace, name string) (map[string]string, string, bool, error) {
	return c.configMapDataInProcess(ctx, namespace, name)
}

// CreateConfigMap creates a ConfigMap and fails if it already exists. Unlike
// Apply it never overwrites: the caller read "absent" and writes only over
// that. A reader client refuses it before anything is sent. A writer creates
// it in-process (kube.Client.CreateConfigMap, a POST of manifest as it is,
// never an apply), and an AlreadyExists unwraps to tkube.ErrConflict.
func (c *Client) CreateConfigMap(ctx context.Context, manifest []byte) error {
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
	return c.namespacesInProcess(ctx, "")
}

// NamespacesLabelled lists the namespaces that carry a label selector, by name,
// sorted, in-process and paged.
func (c *Client) NamespacesLabelled(ctx context.Context, selector string) ([]string, error) {
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
	return c.logsInProcess(ctx, out, namespace, target, lines, follow, previous)
}
