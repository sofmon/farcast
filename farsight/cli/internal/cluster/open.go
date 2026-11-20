package cluster

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/technocore/kernel"
	tkube "github.com/sofmon/farcast/technocore/kube"
)

// errNeverWrites is every write of a reader client: refused before anything
// is sent.
var errNeverWrites = errors.New("cluster: a reader client never writes")

// Open builds a Client that reaches the cluster in-process, through
// internal/kube (ADR 0023 decision 2), as one of the instance's two
// identities: kube.Reader or kube.Writer. It starts no program, dials nothing
// and mints nothing until a method is called. Any other identity is refused
// before the client is built, with nothing sent.
//
// Either identity answers every read, CanI and NamespaceUID in-process. A
// reader refuses Apply, ApplyAt, CreateConfigMap, ReplaceConfigMap and
// DeleteSecret before anything is sent; since ADR 0023 M2.4 it is how
// 'world', 'ps', 'costs', 'usage' and 'logs' read the cluster. A writer
// applies, creates and replaces a ConfigMap (the storage key pin), and
// deletes a Secret on its uid (git-credential rm, M2.8), all of it as cfg's
// credential, the instance's stored installer key.
//
// warnings receives each distinct API Warning header text, once, as
// "Warning (cluster): <text>\n", after the call whose answer carried it, and
// the notes Logs writes. A text that would not print as it is (a control
// character, a bidi override, invalid UTF-8) is written Go-quoted instead,
// because it comes from the server. A nil warnings discards them.
func Open(cfg kube.Config, warnings io.Writer) (*Client, error) {
	switch cfg.Identity {
	case kube.Reader, kube.Writer:
	default:
		return nil, fmt.Errorf("cluster: Open builds an instance's reader or writer, and %q is neither", cfg.Identity)
	}
	kc, err := kube.New(cfg)
	if err != nil {
		return nil, err
	}
	return &Client{kube: kc, warnings: warnings}, nil
}

// CanI asks the API server whether this client's identity may do one thing:
// kube.Client.SelfSubjectAccessReview, for the proof 'farcast reader grant'
// makes that the reader cannot write (ADR 0023 §7.2).
func (c *Client) CanI(ctx context.Context, a kube.ResourceAttributes) (bool, error) {
	allowed, err := c.kube.SelfSubjectAccessReview(ctx, a)
	c.flushWarnings()
	if err != nil {
		return false, err
	}
	return allowed, nil
}

// NamespaceUID is one namespace's uid, "" when there is no such namespace:
// kube.Client.NamespaceUID, read with the list verb, which the reader holds
// too (a plan binds farcast-system's uid, ADR 0023 M2.6). A refused read is an
// error and never "". In ADR 0023 M2.5 its one caller is the writing
// commands' preflight read.
func (c *Client) NamespaceUID(ctx context.Context, name string) (string, error) {
	uid, err := c.kube.NamespaceUID(ctx, name)
	c.flushWarnings()
	if err != nil {
		return "", err
	}
	return uid, nil
}

// lastAppliedAnnotation is kubectl's client-side apply's annotation: on an
// object anyone applied with kubectl, a copy of every field it applied, a
// Secret's values included.
const lastAppliedAnnotation = "kubectl.kubernetes.io/last-applied-configuration"

// blankLastApplied keeps the last-applied annotation's key on o and empties
// its value (ADR 0023 §6.4). No caller reads the annotation. A Secret anyone
// applied with kubectl carries its data in that value, and the blank keeps
// it out of what a caller prints or binds.
func blankLastApplied(o *kube.Object) {
	if _, ok := o.Metadata.Annotations[lastAppliedAnnotation]; ok {
		o.Metadata.Annotations[lastAppliedAnnotation] = ""
	}
}

// GetMeta reads one object's metadata: kube.Client.GetObject (ADR 0023
// §2.3), for the plans' and the grants' reads of the two ServiceAccounts'
// uids (design §33, A33-18) and git-credential's Secret read (§9.8). A
// Secret's data and stringData are never decoded. Its last-applied
// annotation, which on a Secret kubectl applied holds a copy of them, is
// decoded into memory with the metadata, and returned with its key and an
// empty value (blankLastApplied).
func (c *Client) GetMeta(ctx context.Context, k kube.Kind, namespace, name string) (kube.Object, error) {
	o, err := c.kube.GetObject(ctx, k, namespace, name)
	c.flushWarnings()
	if err != nil {
		return kube.Object{}, err
	}
	blankLastApplied(&o)
	return o, nil
}

// DeleteSecret deletes the Secret namespace/name, preconditioned on its uid:
// kube.Client.DeleteSecret, with the warnings its answer carried written
// after it (ADR 0023 M2.8, design §33, A33-31). It is git-credential rm's
// only, the one delete farcast makes, of a Git credential it wrote, by the
// uid it read. A reader client refuses it before anything is sent, a token
// included. A uid that is no longer the stored one is a 409 that unwraps to
// tkube.ErrConflict, and nothing is deleted; an absent Secret is a 404 that
// unwraps to tkube.ErrNotFound. It is not an apply: a DELETE takes no field
// manager. It is never retried on 429 or 503. A 401 is sent once more with a
// fresh token, as every call is (§3.4): the server refuses a 401 before
// processing the call [inf], and the second DELETE is preconditioned on the
// same uid.
func (c *Client) DeleteSecret(ctx context.Context, namespace, name, uid string) error {
	if err := c.neverWrites(); err != nil {
		return err
	}
	err := c.kube.DeleteSecret(ctx, namespace, name, uid)
	c.flushWarnings()
	return err
}

// neverWrites refuses a write on a reader client before anything is sent. It
// keys on the identity the client was opened as: a writer writes.
func (c *Client) neverWrites() error {
	if c.kube.Identity() != kube.Writer {
		return errNeverWrites
	}
	return nil
}

// namespacesInProcess is NamespacesLabelled and Namespaces on an Open'd
// client: kube's ListNamespaces with the selector ("" is every namespace),
// paged, the names sorted.
func (c *Client) namespacesInProcess(ctx context.Context, selector string) ([]string, error) {
	names, err := c.kube.ListNamespaces(ctx, selector)
	c.flushWarnings()
	if err != nil {
		return nil, err
	}
	return names, nil
}

// The waits between the reads of RolloutStatus, WaitExternalIP and WaitJob
// (design §4).
const (
	rolloutPoll = 2 * time.Second
	servicePoll = 3 * time.Second
	jobPoll     = 5 * time.Second
)

// every is the wait between two reads: the client's poll when a test set
// one, else d.
func (c *Client) every(d time.Duration) time.Duration {
	if c.poll > 0 {
		return c.poll
	}
	return d
}

// sleep waits d, or returns ctx's error when it ends first.
func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// deadline is a wait that ran out: its text is the message the wait has
// always given, and it unwraps to kube.ErrTimedOut, so a caller tells a
// timeout from a refusal with errors.Is.
type deadline struct{ msg string }

func (e *deadline) Error() string { return e.msg }
func (e *deadline) Unwrap() error { return kube.ErrTimedOut }

// rolloutInProcess is RolloutStatus on an Open'd client: GET the Deployment
// every 2 s until kube.RolloutState says it is done, refuses it (a stalled
// rollout, ErrRolloutStalled), or timeout passes. A 404 is an error.
func (c *Client) rolloutInProcess(ctx context.Context, namespace, name string, timeout time.Duration) error {
	end := time.Now().Add(timeout)
	for {
		d, err := c.kube.GetDeployment(ctx, namespace, name)
		c.flushWarnings()
		if err != nil {
			return err
		}
		done, waiting, err := kube.RolloutState(d)
		if err != nil || done {
			return err
		}
		if time.Now().After(end) {
			return fmt.Errorf("deployment %s/%s did not finish rolling out within %s: %w (last: %s)", namespace, name, timeout, kube.ErrTimedOut, waiting)
		}
		if err := sleep(ctx, c.every(rolloutPoll)); err != nil {
			return err
		}
	}
}

// externalIPInProcess is WaitExternalIP on an Open'd client: GET the Service
// every 3 s until its first load-balancer ingress names an IP. An IP that does
// not parse as one, or carries a zone, is an error rather than an endpoint.
func (c *Client) externalIPInProcess(ctx context.Context, namespace, name string, timeout time.Duration) (string, error) {
	end := time.Now().Add(timeout)
	for {
		svc, err := c.kube.GetService(ctx, namespace, name)
		c.flushWarnings()
		if err != nil {
			return "", err
		}
		if ing := svc.Status.LoadBalancer.Ingress; len(ing) > 0 && ing[0].IP != "" {
			ip := ing[0].IP
			if a, err := netip.ParseAddr(ip); err != nil || a.Zone() != "" {
				return "", fmt.Errorf("cluster: service %s/%s reports a load-balancer IP that is not one: %q", namespace, name, ip)
			}
			return ip, nil
		}
		if time.Now().After(end) {
			return "", &deadline{msg: fmt.Sprintf("cluster: service %s/%s had no external IP after %s", namespace, name, timeout)}
		}
		if err := sleep(ctx, c.every(servicePoll)); err != nil {
			return "", err
		}
	}
}

// waitJobInProcess is WaitJob on an Open'd client: GET the Job every 5 s.
// status.succeeded above zero, or a Complete condition that is True, is
// success; status.failed above zero, or a Failed condition that is True, is
// failure. Either way the uid is the one that GET read, and the message is
// jobMessageInProcess's, whose error is discarded: a missing message is the
// caller's own "no digest" to report.
func (c *Client) waitJobInProcess(ctx context.Context, namespace, name string, timeout time.Duration) (JobResult, error) {
	end := time.Now().Add(timeout)
	for {
		j, err := c.kube.GetJob(ctx, namespace, name)
		c.flushWarnings()
		if err != nil {
			return JobResult{}, err
		}
		switch {
		case jobSucceeded(j):
			msg, _ := c.jobMessageInProcess(ctx, namespace, name)
			return JobResult{Succeeded: true, Message: msg, UID: j.Metadata.UID}, nil
		case j.Status.Failed > 0 || jobCondition(j, "Failed"):
			msg, _ := c.jobMessageInProcess(ctx, namespace, name)
			return JobResult{Succeeded: false, Message: msg, UID: j.Metadata.UID}, nil
		}
		if time.Now().After(end) {
			return JobResult{}, &deadline{msg: fmt.Sprintf("cluster: job %s/%s neither succeeded nor failed after %s", namespace, name, timeout)}
		}
		if err := sleep(ctx, c.every(jobPoll)); err != nil {
			return JobResult{}, err
		}
	}
}

// jobSucceeded is WaitJob's success: status.succeeded above zero, or a
// Complete condition that is True.
func jobSucceeded(j kube.Job) bool {
	return j.Status.Succeeded > 0 || jobCondition(j, "Complete")
}

// jobStateInProcess is JobState on an Open'd client: one GET of the Job. It
// is absent only when the API server says so (statusNotFound); any other
// failure is an error with found false, never absent.
func (c *Client) jobStateInProcess(ctx context.Context, namespace, name string) (JobResult, bool, error) {
	j, err := c.kube.GetJob(ctx, namespace, name)
	c.flushWarnings()
	if err != nil {
		if statusNotFound(err) {
			return JobResult{}, false, nil
		}
		return JobResult{}, false, err
	}
	return JobResult{Succeeded: jobSucceeded(j), UID: j.Metadata.UID}, true, nil
}

// jobCondition reports whether a Job carries the condition of this type with
// status True.
func jobCondition(j kube.Job, condType string) bool {
	for _, c := range j.Status.Conditions {
		if c.Type == condType && c.Status == "True" {
			return true
		}
	}
	return false
}

// jobMessageInProcess is a finished Job's termination message: GET the Job,
// list its pods by its own selector, take the newest pod by creationTimestamp
// (FarCast's choice; kubectl's jsonpath read the first listed), and return the
// trimmed message of its first container status that has terminated.
func (c *Client) jobMessageInProcess(ctx context.Context, namespace, job string) (string, error) {
	j, err := c.kube.GetJob(ctx, namespace, job)
	c.flushWarnings()
	if err != nil {
		return "", err
	}
	pods, err := c.jobPods(ctx, namespace, job, j)
	if err != nil {
		return "", err
	}
	var newest *kube.Pod
	for i := range pods {
		if newest == nil || pods[i].Metadata.CreationTimestamp.After(newest.Metadata.CreationTimestamp) {
			newest = &pods[i]
		}
	}
	if newest == nil {
		return "", nil
	}
	for _, cs := range newest.Status.ContainerStatuses {
		if cs.State.Terminated != nil {
			return strings.TrimSpace(cs.State.Terminated.Message), nil
		}
	}
	return "", nil
}

// jobPods lists a Job's pods by the Job's own selector, refusing one that
// farcast cannot read as a plain label selector.
func (c *Client) jobPods(ctx context.Context, namespace, job string, j kube.Job) ([]kube.Pod, error) {
	sel, err := kube.SelectorString(j.Spec.Selector)
	if err != nil {
		return nil, fmt.Errorf("the Job %s/%s %w", namespace, job, err)
	}
	pods, err := c.kube.ListPods(ctx, namespace, sel)
	c.flushWarnings()
	return pods, err
}

// jobLogsInProcess is JobLogs on an Open'd client: the log of the Job
// template's one container, in the pod kube.PickPod chooses, all of it unless
// lines is positive. A template of any other number of containers is refused
// before the pods are listed: farcast's Jobs run one, and which of several to
// read would be a guess.
func (c *Client) jobLogsInProcess(ctx context.Context, namespace, job string, lines int) (string, error) {
	j, err := c.kube.GetJob(ctx, namespace, job)
	c.flushWarnings()
	if err != nil {
		return "", err
	}
	containers := j.Spec.Template.Spec.Containers
	if len(containers) != 1 {
		return "", fmt.Errorf("job %s/%s has %d containers; farcast reads only one", namespace, job, len(containers))
	}
	pods, err := c.jobPods(ctx, namespace, job, j)
	if err != nil {
		return "", err
	}
	pod, ok := kube.PickPod(pods)
	if !ok {
		return "", fmt.Errorf("job %s/%s has no pod to read", namespace, job)
	}
	tail := -1
	if lines > 0 {
		tail = lines
	}
	var buf bytes.Buffer
	err = c.kube.StreamLog(ctx, namespace, pod.Metadata.Name, kube.LogOptions{Container: containers[0].Name, TailLines: tail}, &buf)
	c.flushWarnings()
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

// workloadsInProcess is Workloads on an Open'd client: the Deployments, then
// the StatefulSets, each paged and in the server's order, each one's kind
// stamped from the list it came from. An empty namespace is refused before
// anything is sent, because kube reads it as every namespace.
func (c *Client) workloadsInProcess(ctx context.Context, namespace string) ([]Workload, error) {
	if namespace == "" {
		return nil, errors.New("cluster: Workloads was given no namespace, which would list every namespace's; nothing was sent")
	}
	deployments, err := c.kube.ListDeployments(ctx, namespace)
	c.flushWarnings()
	if err != nil {
		return nil, err
	}
	sets, err := c.kube.ListStatefulSets(ctx, namespace)
	c.flushWarnings()
	if err != nil {
		return nil, err
	}
	out := make([]Workload, 0, len(deployments)+len(sets))
	for _, d := range deployments {
		out = append(out, workloadOf(d.Kind, d.Metadata, d.Spec, d.Status.ReadyReplicas, namespace))
	}
	for _, s := range sets {
		out = append(out, workloadOf(s.Kind, s.Metadata, s.Spec, s.Status.ReadyReplicas, namespace))
	}
	return out, nil
}

// workloadOf is one listed workload as a Workload.
func workloadOf(k kube.Kind, md kube.ObjectMeta, spec kube.WorkloadSpec, ready int32, namespace string) Workload {
	w := Workload{
		Kind:      k.Kind,
		Namespace: md.Namespace,
		Name:      md.Name,
		Ready:     int(ready),
		Labels:    md.Labels,
		CreatedAt: md.CreationTimestamp,
	}
	if w.Namespace == "" {
		w.Namespace = namespace
	}
	// A Deployment with no explicit replicas runs one. Reading that as zero
	// would show every healthy application as stopped — and stopped is
	// exactly what a protective cost shutdown leaves behind, so the two must
	// never be confused.
	w.Desired = 1
	if spec.Replicas != nil {
		w.Desired = int(*spec.Replicas)
	}
	for _, ct := range spec.Template.Spec.Containers {
		w.Images = append(w.Images, ct.Image)
	}
	return w
}

// deploymentStateInProcess is DeploymentState on an Open'd client: one GET of
// the Deployment (A23-46, A28-7). It is absent only when the API server says
// so (statusNotFound), which is Present false and no error; any other failure
// is an error, never absent. A container's request that is set and does not
// parse is an error too, wrapping kube.ErrUnreadable: a caller then knows
// nothing of the application, rather than a request it misread.
func (c *Client) deploymentStateInProcess(ctx context.Context, namespace, name string) (DeploymentState, error) {
	d, err := c.kube.GetDeployment(ctx, namespace, name)
	c.flushWarnings()
	if err != nil {
		if statusNotFound(err) {
			return DeploymentState{}, nil
		}
		return DeploymentState{}, err
	}
	containers := d.Spec.Template.Spec.Containers
	st := DeploymentState{
		Present:         true,
		Replicas:        d.Spec.Replicas,
		Requests:        make(map[string]Requests, len(containers)),
		ResourceVersion: d.Metadata.ResourceVersion,
		LastAppliedAt:   lastAppliedAt(d.Metadata.ManagedFields),
	}
	for _, ct := range containers {
		r, err := requestsOf(namespace, name, ct)
		if err != nil {
			return DeploymentState{}, err
		}
		st.Requests[ct.Name] = r
	}
	// The kernel's own reading of its stamp: absent or unparseable is never
	// adapted, so AdaptedAt stays zero.
	if at, ok := (kernel.Target{Annotations: d.Metadata.Annotations}).AdaptedAt(); ok {
		st.AdaptedAt = at.UTC()
	}
	return st, nil
}

// requestsOf is one container's requests in milli-CPU and MiB, each rounded
// up as tkube parses it. A request that is not set is 0; one that is set and
// does not parse is an error naming the Deployment, the container and the
// value, each server-supplied text quoted.
func requestsOf(namespace, name string, ct kube.Container) (Requests, error) {
	cpu, ok := quantity(ct.Resources.Requests.CPU, tkube.ParseCPUMilli)
	if !ok {
		return Requests{}, unreadableRequest(namespace, name, ct.Name, "cpu", ct.Resources.Requests.CPU)
	}
	mem, ok := quantity(ct.Resources.Requests.Memory, tkube.ParseMemMiB)
	if !ok {
		return Requests{}, unreadableRequest(namespace, name, ct.Name, "memory", ct.Resources.Requests.Memory)
	}
	return Requests{CPUMilli: cpu, MemMiB: mem}, nil
}

// quantity is q through parse, "" as 0: tkube refuses an empty quantity, and
// a container that requests nothing reserves nothing. ok is false when q is
// set and parse refuses it.
func quantity(q string, parse func(string) (int, error)) (int64, bool) {
	if q == "" {
		return 0, true
	}
	v, err := parse(q)
	if err != nil {
		return 0, false
	}
	return int64(v), true
}

// unreadable is an answer farcast could not read: its text is exactly msg,
// and it unwraps to kube.ErrUnreadable.
type unreadable struct{ msg string }

func (e *unreadable) Error() string { return e.msg }
func (e *unreadable) Unwrap() error { return kube.ErrUnreadable }

// unreadableRequest is a container's set request that does not parse. The
// container's name and the value came from the server, so both are quoted.
func unreadableRequest(namespace, name, container, resource, value string) error {
	return &unreadable{msg: fmt.Sprintf("cluster: the Deployment %s/%s's container %q requests %s %q, which farcast cannot read as a quantity", namespace, name, container, resource, value)}
}

// lastAppliedAt is the newest time among the entries that record farcast's
// own Apply of the object (kube.IsOwnApply), zero when there is none. An
// entry whose time does not parse is passed over: it can only make the last
// apply read older, and an older apply never gates anything.
func lastAppliedAt(entries []kube.ManagedFieldsEntry) time.Time {
	var newest time.Time
	for _, e := range entries {
		if !kube.IsOwnApply(e) {
			continue
		}
		at, err := time.Parse(time.RFC3339, e.Time)
		if err != nil {
			continue
		}
		if at.After(newest) {
			newest = at
		}
	}
	return newest.UTC()
}

// statusNotFound reports whether err is the API server saying that an object
// is not there: a 404 whose body is a Kubernetes Status (A18-4's rule). It is
// the one absence test of every read that tells an absent object from a
// failed read (configMapInProcess, deploymentStateInProcess and
// jobStateInProcess). errors.Is(err, tkube.ErrNotFound) is never that test: a
// 404 from something in front of the API server unwraps to it too, and proves
// nothing about the object.
func statusNotFound(err error) bool {
	var ae *kube.APIError
	return errors.As(err, &ae) && ae.KubernetesStatus && ae.Status.Code == http.StatusNotFound
}

// configMapInProcess reads one ConfigMap on an Open'd client. It is absent
// only when the API server says so (statusNotFound). Any other failure is
// returned with found false and never read as absent: a 403 read as absent
// would show a refused read as "never checkpointed", and a 404 from something
// in front of the API server proves nothing about the ConfigMap.
func (c *Client) configMapInProcess(ctx context.Context, namespace, name string) (kube.ConfigMap, bool, error) {
	cm, err := c.kube.GetConfigMap(ctx, namespace, name)
	c.flushWarnings()
	if err != nil {
		if statusNotFound(err) {
			return kube.ConfigMap{}, false, nil
		}
		return kube.ConfigMap{}, false, err
	}
	return cm, true, nil
}

func (c *Client) configMapValueInProcess(ctx context.Context, namespace, name, key string) (string, bool, error) {
	cm, found, err := c.configMapInProcess(ctx, namespace, name)
	if err != nil || !found {
		return "", false, err
	}
	value, ok := cm.Data[key]
	if !ok {
		return "", true, fmt.Errorf("cluster: %s/%s has no %q", namespace, name, key)
	}
	return value, true, nil
}

func (c *Client) configMapDataInProcess(ctx context.Context, namespace, name string) (map[string]string, string, bool, error) {
	cm, found, err := c.configMapInProcess(ctx, namespace, name)
	if err != nil || !found {
		return nil, "", false, err
	}
	if cm.Metadata.ResourceVersion == "" {
		return nil, "", false, fmt.Errorf("cluster: %s/%s carries no resourceVersion", namespace, name)
	}
	return cm.Data, cm.Metadata.ResourceVersion, true, nil
}

// maxFollowed is how many containers Logs follows at once: kubectl's own
// default (MaxFollowConcurrency, pkg/cmd/logs/logs.go, kubectl v0.37.2).
const maxFollowed = 5

// logPiece is the most of one unfinished line a followed container holds
// back: once that much is held, it is written as a piece.
const logPiece = 32 << 10

// logsInProcess is Logs on an Open'd client (design §4 and A18-4).
func (c *Client) logsInProcess(ctx context.Context, out io.Writer, namespace, target string, lines int, follow, previous bool) error {
	pod, containers, err := c.logPod(ctx, namespace, target)
	if err != nil {
		return err
	}
	if follow && len(containers) > maxFollowed {
		return fmt.Errorf("following %d containers at once is more than farcast follows (%d)", len(containers), maxFollowed)
	}
	opts := func(container string) kube.LogOptions {
		return kube.LogOptions{Container: container, TailLines: lines, Follow: follow, Previous: previous}
	}
	if follow {
		return c.followLogs(ctx, out, namespace, pod, containers, opts, previous)
	}
	for _, container := range containers {
		err := c.kube.StreamLog(ctx, namespace, pod, opts(container), out)
		c.flushWarnings()
		if noPrevious(err, previous) {
			c.noteNoPrevious(pod, container)
			continue
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// logPod is the pod Logs reads and its containers, init, then main, then
// ephemeral: the workload's own selector, then the pod kubectl logs would
// choose (kube.PickPod). The warnings of these reads are written before any
// log is.
func (c *Client) logPod(ctx context.Context, namespace, target string) (string, []string, error) {
	resource, name, _ := strings.Cut(target, "/")
	var (
		kind     string
		selector *kube.LabelSelector
	)
	switch resource {
	case "deployment":
		d, err := c.kube.GetDeployment(ctx, namespace, name)
		c.flushWarnings()
		if err != nil {
			return "", nil, err
		}
		kind, selector = d.Kind.Kind, d.Spec.Selector
	case "statefulset":
		s, err := c.kube.GetStatefulSet(ctx, namespace, name)
		c.flushWarnings()
		if err != nil {
			return "", nil, err
		}
		kind, selector = s.Kind.Kind, s.Spec.Selector
	default:
		return "", nil, fmt.Errorf("cluster: the log target %q is neither deployment/<name> nor statefulset/<name>", target)
	}
	sel, err := kube.SelectorString(selector)
	if err != nil {
		return "", nil, fmt.Errorf("the %s %s/%s %w", kind, namespace, name, err)
	}
	pods, err := c.kube.ListPods(ctx, namespace, sel)
	c.flushWarnings()
	if err != nil {
		return "", nil, err
	}
	pod, ok := kube.PickPod(pods)
	if !ok {
		return "", nil, fmt.Errorf("no pod of %s/%s is running yet", namespace, name)
	}
	var containers []string
	for _, ct := range pod.Spec.InitContainers {
		containers = append(containers, ct.Name)
	}
	for _, ct := range pod.Spec.Containers {
		containers = append(containers, ct.Name)
	}
	for _, ct := range pod.Spec.EphemeralContainers {
		containers = append(containers, ct.Name)
	}
	return pod.Metadata.Name, containers, nil
}

// followLogs follows every container at once, each through its own
// lineWriter onto out. The first failure that is not the context's ends the
// others and is returned; a context that ends, the operator stopping the
// follow, is not a failure.
func (c *Client) followLogs(ctx context.Context, out io.Writer, namespace, pod string, containers []string, opts func(string) kube.LogOptions, previous bool) error {
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		outMu sync.Mutex
		once  sync.Once
		first error
		wg    sync.WaitGroup
	)
	for _, container := range containers {
		wg.Go(func() {
			lw := &lineWriter{mu: &outMu, out: out}
			err := c.kube.StreamLog(sctx, namespace, pod, opts(container), lw)
			if ferr := lw.flush(); err == nil {
				err = ferr
			}
			switch {
			case err == nil, sctx.Err() != nil:
				return
			case noPrevious(err, previous):
				c.noteNoPrevious(pod, container)
				return
			}
			once.Do(func() {
				first = err
				cancel()
			})
		})
	}
	wg.Wait()
	c.flushWarnings()
	return first
}

// lineWriter is one followed container's way onto out, which every container
// followed at once shares under mu. It writes only whole lines, so two
// containers' lines never mix within a line, except that once logPiece bytes
// of one line are held without its end, they are written as a piece, so a
// long line holds back at most 32 KiB and another container's lines may come
// between its pieces. flush writes what is held when the stream ends.
type lineWriter struct {
	mu   *sync.Mutex
	out  io.Writer
	held []byte
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.held = append(w.held, p...)
	n := bytes.LastIndexByte(w.held, '\n') + 1
	for len(w.held)-n >= logPiece {
		n += logPiece
	}
	if n == 0 {
		return len(p), nil
	}
	if err := w.emit(w.held[:n]); err != nil {
		return 0, err
	}
	w.held = append(w.held[:0], w.held[n:]...)
	return len(p), nil
}

// flush writes whatever the stream left unfinished.
func (w *lineWriter) flush() error {
	if len(w.held) == 0 {
		return nil
	}
	err := w.emit(w.held)
	w.held = nil
	return err
}

func (w *lineWriter) emit(b []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, err := w.out.Write(b)
	return err
}

// noPrevious reports whether err is the API server saying that a container
// has no previous instance: a 400 whose body is a Kubernetes Status, to a
// request for the previous instance. Every other error stops Logs.
func noPrevious(err error, previous bool) bool {
	var ae *kube.APIError
	return previous && errors.As(err, &ae) && ae.KubernetesStatus && ae.Status.Code == http.StatusBadRequest
}

// noteNoPrevious writes "<pod>/<container>: no previous instance" to the
// warnings writer, under the warnings' mutex, each name quoted when it would
// not print as it is; a nil writer discards it. The note never goes to the
// log's own writer, which carries the application's bytes (design §4, D11).
func (c *Client) noteNoPrevious(pod, container string) {
	c.warnMu.Lock()
	defer c.warnMu.Unlock()
	if c.warnings == nil {
		return
	}
	_, _ = fmt.Fprintf(c.warnings, "%s/%s: no previous instance\n", printable(pod), printable(container))
}

// printable is s, or s Go-quoted when it would not print as it is: a server's
// text never reaches the operator's terminal raw.
func printable(s string) string {
	if output.Printable(s) {
		return s
	}
	return strconv.QuoteToGraphic(s)
}

// flushWarnings writes every Warning text the kube client has seen and this
// client has not yet written. kube keeps each distinct text once, in the
// order first seen, so what is new is the tail after the last count written.
func (c *Client) flushWarnings() {
	texts := c.kube.Warnings()
	c.warnMu.Lock()
	defer c.warnMu.Unlock()
	if len(texts) <= c.warned {
		return
	}
	fresh := texts[c.warned:]
	c.warned = len(texts)
	if c.warnings == nil {
		return
	}
	for _, t := range fresh {
		_, _ = fmt.Fprintf(c.warnings, "Warning (cluster): %s\n", printable(t))
	}
}
