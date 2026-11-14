package kube

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	tkube "github.com/sofmon/farcast/technocore/kube"
)

// The types below carry only the fields farcast reads (§2.1). encoding/json
// ignores every other field, so a server newer than these structs is a
// non-event, as in technocore/kube.

// ObjectMeta is tkube's ObjectMeta with the two fields the migration and the
// rollout rules need.
type ObjectMeta struct {
	tkube.ObjectMeta
	Generation    int64                `json:"generation"`
	ManagedFields []ManagedFieldsEntry `json:"managedFields"`
}

// ManagedFieldsEntry is meta/v1's ManagedFieldsEntry, kept as the server
// wrote it: its time is a string, and its fieldsV1 raw JSON.
type ManagedFieldsEntry struct {
	Manager     string          `json:"manager,omitempty"`
	Operation   string          `json:"operation,omitempty"`
	APIVersion  string          `json:"apiVersion,omitempty"`
	Time        string          `json:"time,omitempty"` // kept as the server wrote it
	FieldsType  string          `json:"fieldsType,omitempty"`
	FieldsV1    json.RawMessage `json:"fieldsV1,omitempty"`
	Subresource string          `json:"subresource,omitempty"`
}

// LabelSelector is a workload's claim on pods, with both halves of the wire type.
type LabelSelector struct {
	MatchLabels      map[string]string          `json:"matchLabels,omitempty"`
	MatchExpressions []LabelSelectorRequirement `json:"matchExpressions,omitempty"`
}

// LabelSelectorRequirement is one matchExpressions term. farcast decodes it
// only so that SelectorString can refuse it: a selector decoded without it
// would read as a broader one.
type LabelSelectorRequirement struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values,omitempty"`
}

// Container is a workload template's container: its name, its image and its
// requests.
type Container struct {
	Name      string                     `json:"name"`
	Image     string                     `json:"image"`
	Resources tkube.ResourceRequirements `json:"resources"`
}

// TemplatePodSpec is the pod spec of a Deployment's or a StatefulSet's template.
type TemplatePodSpec struct {
	Containers          []Container `json:"containers"`
	InitContainers      []Container `json:"initContainers"`
	EphemeralContainers []Container `json:"ephemeralContainers"`
}

// PodTemplate is a workload's pod template, as far as farcast reads it.
type PodTemplate struct {
	Spec TemplatePodSpec `json:"spec"`
}

// WorkloadSpec is the spec a Deployment and a StatefulSet share here.
type WorkloadSpec struct {
	Replicas *int32         `json:"replicas"`
	Selector *LabelSelector `json:"selector"`
	Template PodTemplate    `json:"template"`
}

// Deployment is an apps/v1 Deployment.
type Deployment struct {
	// Kind is the Deployment row of Kinds, set by ListDeployments and
	// GetDeployment from the request, never read from the body: a list's
	// items carry no kind, and an item that did could name another.
	Kind     Kind             `json:"-"`
	Metadata ObjectMeta       `json:"metadata"`
	Spec     WorkloadSpec     `json:"spec"`
	Status   DeploymentStatus `json:"status"`
}

// DeploymentStatus is what the rollout rules read (§4).
type DeploymentStatus struct {
	ObservedGeneration int64                 `json:"observedGeneration"`
	Replicas           int32                 `json:"replicas"`
	UpdatedReplicas    int32                 `json:"updatedReplicas"`
	ReadyReplicas      int32                 `json:"readyReplicas"`
	AvailableReplicas  int32                 `json:"availableReplicas"`
	Conditions         []DeploymentCondition `json:"conditions"`
}

// DeploymentCondition is one of a Deployment's status conditions.
type DeploymentCondition struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

// StatefulSet is an apps/v1 StatefulSet.
type StatefulSet struct {
	// Kind is the StatefulSet row of Kinds, set as Deployment's is.
	Kind     Kind              `json:"-"`
	Metadata ObjectMeta        `json:"metadata"`
	Spec     WorkloadSpec      `json:"spec"`
	Status   StatefulSetStatus `json:"status"`
}

// StatefulSetStatus is a StatefulSet's status, as far as farcast reads it.
type StatefulSetStatus struct {
	ObservedGeneration int64 `json:"observedGeneration"`
	Replicas           int32 `json:"replicas"`
	ReadyReplicas      int32 `json:"readyReplicas"`
}

// Pod is a core/v1 Pod, as far as the choice of a pod for logs and a Job's
// message read it.
type Pod struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     PodSpec    `json:"spec"`
	Status   PodStatus  `json:"status"`
}

// PodSpec is a pod's spec, as far as farcast reads it.
type PodSpec struct {
	NodeName            string          `json:"nodeName"`
	Containers          []PodContainer  `json:"containers"`
	InitContainers      []InitContainer `json:"initContainers"`
	EphemeralContainers []PodContainer  `json:"ephemeralContainers"`
}

// PodContainer is a pod's container, by name.
type PodContainer struct {
	Name string `json:"name"`
}

// InitContainer is a pod's init container. A restartPolicy of Always makes it
// a sidecar, whose restarts the choice of a pod counts.
type InitContainer struct {
	Name          string `json:"name"`
	RestartPolicy string `json:"restartPolicy,omitempty"`
}

// PodStatus is a pod's status, as far as farcast reads it.
type PodStatus struct {
	Phase                 string                `json:"phase"`
	Conditions            []PodCondition        `json:"conditions"`
	ContainerStatuses     []ContainerStatus     `json:"containerStatuses"`
	InitContainerStatuses []InitContainerStatus `json:"initContainerStatuses"`
}

// PodCondition is one of a pod's status conditions.
type PodCondition struct {
	Type               string    `json:"type"`
	Status             string    `json:"status"`
	LastTransitionTime time.Time `json:"lastTransitionTime"`
}

// ContainerStatus is a regular container's status.
type ContainerStatus struct {
	Name         string         `json:"name"`
	RestartCount int32          `json:"restartCount"`
	State        ContainerState `json:"state"`
}

// ContainerState is a container's current state; only termination is read.
type ContainerState struct {
	Terminated *ContainerStateTerminated `json:"terminated,omitempty"`
}

// ContainerStateTerminated is a terminated container's message.
type ContainerStateTerminated struct {
	Message string `json:"message"`
}

// InitContainerStatus is an init container's status.
type InitContainerStatus struct {
	Name         string `json:"name"`
	RestartCount int32  `json:"restartCount"`
}

// Job is a batch/v1 Job, as far as WaitJob and JobLogs read it.
type Job struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     JobSpec    `json:"spec"`
	Status   JobStatus  `json:"status"`
}

// JobSpec is a Job's selector and its template's containers.
type JobSpec struct {
	Selector *LabelSelector `json:"selector"`
	Template JobTemplate    `json:"template"`
}

// JobTemplate is a Job's pod template.
type JobTemplate struct {
	Spec JobPodSpec `json:"spec"`
}

// JobPodSpec is a Job template's pod spec, by container name.
type JobPodSpec struct {
	Containers []PodContainer `json:"containers"`
}

// JobStatus is a Job's outcome.
type JobStatus struct {
	Succeeded  int32          `json:"succeeded"`
	Failed     int32          `json:"failed"`
	Conditions []JobCondition `json:"conditions"`
}

// JobCondition is one of a Job's status conditions.
type JobCondition struct {
	Type   string `json:"type"`
	Status string `json:"status"`
}

// Service is a core/v1 Service, as far as WaitExternalIP reads it.
type Service struct {
	Status ServiceStatus `json:"status"`
}

// ServiceStatus is a Service's load-balancer status.
type ServiceStatus struct {
	LoadBalancer LoadBalancerStatus `json:"loadBalancer"`
}

// LoadBalancerStatus lists a load balancer's ingress points.
type LoadBalancerStatus struct {
	Ingress []LoadBalancerIngress `json:"ingress"`
}

// LoadBalancerIngress is one ingress point.
type LoadBalancerIngress struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

// ConfigMap is a core/v1 ConfigMap.
type ConfigMap struct {
	Metadata ObjectMeta        `json:"metadata"`
	Data     map[string]string `json:"data"`
}

// LogOptions are one log request's parameters (§4).
type LogOptions struct {
	Container string
	TailLines int // < 0: everything, sent as no tailLines parameter at all (§4)
	Follow    bool
	Previous  bool
}

// PickPod is a port of kubectl v0.37.2's podutils.ByLogging
// (k8s.io/kubectl/pkg/util/podutils/podutils.go, kubectl v0.37.2), the order
// `kubectl logs` uses to choose a workload's pod: it sorts a copy of pods by
// that order and returns the first. The sort is stable, farcast's choice, so
// pods the order cannot tell apart keep the server's order. An empty list
// returns false; kubectl would wait for a pod, and the caller reports none.
func PickPod(pods []Pod) (Pod, bool) {
	if len(pods) == 0 {
		return Pod{}, false
	}
	sorted := slices.Clone(pods)
	sort.SliceStable(sorted, func(i, j int) bool { return byLoggingLess(&sorted[i], &sorted[j]) })
	return sorted[0], true
}

// logPhaseOrder is ByLogging's rule 2: Running < Unknown < Pending. A phase
// the map does not name, Succeeded and Failed included, reads as 0 and so
// ties with Running, exactly as kubectl's map lookup does.
var logPhaseOrder = map[string]int{"Running": 0, "Unknown": 1, "Pending": 2}

// byLoggingLess is ByLogging.Less (kubectl v0.37.2, podutils.go), rule for rule.
func byLoggingLess(a, b *Pod) bool {
	// 1. assigned < unassigned
	if a.Spec.NodeName != b.Spec.NodeName && (a.Spec.NodeName == "" || b.Spec.NodeName == "") {
		return a.Spec.NodeName != ""
	}
	// 2. PodRunning < PodUnknown < PodPending
	if logPhaseOrder[a.Status.Phase] != logPhaseOrder[b.Status.Phase] {
		return logPhaseOrder[a.Status.Phase] < logPhaseOrder[b.Status.Phase]
	}
	// 3. ready < not ready
	readyA, readyB := podReady(a), podReady(b)
	if readyA != readyB {
		return readyA
	}
	// 4. Been ready for more time < less time < empty time
	if readyA && readyB {
		if ta, tb := podReadyTime(a), podReadyTime(b); !ta.Equal(tb) {
			return afterOrZero(tb, ta)
		}
	}
	// 5. Pods with containers with higher restart counts < lower restart counts
	if res, decided := compareMaxContainerRestarts(a, b); decided {
		return res
	}
	// 6. older pods < newer pods < empty timestamp pods
	if ca, cb := a.Metadata.CreationTimestamp, b.Metadata.CreationTimestamp; !ca.Equal(cb) {
		return afterOrZero(cb, ca)
	}
	return false
}

// podReady is podutils.IsPodReady: the first Ready condition is True.
func podReady(p *Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == "Ready" {
			return c.Status == "True"
		}
	}
	return false
}

// podReadyTime is podutils.podReadyTime: the transition time of the first
// Ready condition that is True, or the zero time.
func podReadyTime(p *Pod) time.Time {
	for _, c := range p.Status.Conditions {
		if c.Type == "Ready" && c.Status == "True" {
			return c.LastTransitionTime
		}
	}
	return time.Time{}
}

// afterOrZero is podutils.afterOrZero: whether t1 is after t2, with a zero
// time seen as after any other.
func afterOrZero(t1, t2 time.Time) bool {
	if t1.IsZero() || t2.IsZero() {
		return t1.IsZero()
	}
	return t1.After(t2)
}

// maxContainerRestarts is podutils.maxContainerRestarts: the highest restart
// count among the regular containers, and among the sidecars (init containers
// whose restartPolicy is Always).
func maxContainerRestarts(p *Pod) (regular, sidecar int32) {
	for _, c := range p.Status.ContainerStatuses {
		regular = max(regular, c.RestartCount)
	}
	sidecars := map[string]bool{}
	for _, c := range p.Spec.InitContainers {
		if c.RestartPolicy == "Always" {
			sidecars[c.Name] = true
		}
	}
	for _, c := range p.Status.InitContainerStatuses {
		if sidecars[c.Name] {
			sidecar = max(sidecar, c.RestartCount)
		}
	}
	return regular, sidecar
}

// compareMaxContainerRestarts is podutils.compareMaxContainerRestarts, with
// kubectl's *bool as (result, decided): the pod with more restarts sorts
// first, regular containers before sidecars.
func compareMaxContainerRestarts(a, b *Pod) (aFirst, decided bool) {
	regularA, sidecarA := maxContainerRestarts(a)
	regularB, sidecarB := maxContainerRestarts(b)
	if regularA != regularB {
		return regularA > regularB, true
	}
	if sidecarA != sidecarB {
		return sidecarA > sidecarB, true
	}
	return false, false
}

// The characters a selector term may carry, so that no key or value can add a
// term or an operator to the string: a label key (an optional DNS prefix and
// a name) and a label value.
var (
	selectorKey   = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
	selectorValue = regexp.MustCompile(`^[A-Za-z0-9._-]*$`)
)

// SelectorString renders a workload's selector as an equality-only label
// selector, k=v,k=v sorted by key. It refuses nil, empty, or any matchExpressions:
// a selector with expressions would otherwise read as a broader one, and logs
// could come from another workload's pod. It also refuses a key or value with
// a character a label cannot hold, which could otherwise smuggle a term in.
//
// Its error is the end of a sentence, wrapping ErrUnreadable, so a caller
// writes fmt.Errorf("the %s %s/%s %w", kind, namespace, name, err) and gets
// "the Deployment web/api selects its pods with matchExpressions, which
// farcast does not read".
func SelectorString(s *LabelSelector) (string, error) {
	if s == nil || (len(s.MatchLabels) == 0 && len(s.MatchExpressions) == 0) {
		return "", refuse(ErrUnreadable, "selects its pods with an empty selector, which farcast does not read")
	}
	if len(s.MatchExpressions) > 0 {
		return "", refuse(ErrUnreadable, "selects its pods with matchExpressions, which farcast does not read")
	}
	keys := make([]string, 0, len(s.MatchLabels))
	for k, v := range s.MatchLabels {
		if !selectorKey.MatchString(k) || !selectorValue.MatchString(v) {
			return "", refuse(ErrUnreadable, "selects its pods with a label a selector cannot carry, which farcast does not read")
		}
		keys = append(keys, k)
	}
	slices.Sort(keys)
	terms := make([]string, len(keys))
	for i, k := range keys {
		terms[i] = k + "=" + s.MatchLabels[k]
	}
	return strings.Join(terms, ","), nil
}

// The rows of Kinds the reads and writes address, and the one kind farcast
// reads and never applies.
var (
	kindNamespace   = mustKind("v1", "Namespace")
	kindSecret      = mustKind("v1", "Secret")
	kindConfigMap   = mustKind("v1", "ConfigMap")
	kindService     = mustKind("v1", "Service")
	kindDeployment  = mustKind("apps/v1", "Deployment")
	kindStatefulSet = mustKind("apps/v1", "StatefulSet")
	kindJob         = mustKind("batch/v1", "Job")

	kindPod = Kind{Kind: "Pod", APIVersion: "v1", Resource: "pods", Namespaced: true}
)

func mustKind(apiVersion, kind string) Kind {
	k, ok := KindOf(apiVersion, kind)
	if !ok {
		panic("kube: " + apiVersion + " " + kind + " is not in Kinds")
	}
	return k
}

// listPageSize is every list's limit (§4).
const listPageSize = 500

// writeQuery is what every write but a delete names: farcast's field manager,
// and strict field validation, so a field the server does not know is an
// error rather than dropped.
func writeQuery() url.Values {
	return url.Values{"fieldManager": {FieldManager}, "fieldValidation": {"Strict"}}
}

// nameFault is why §5.2's rule refuses a name or namespace, "" when it does
// not. Each goes into a URL path, where "." or ".." would walk the request
// elsewhere.
func nameFault(what, s string) string {
	if validObjectName(s) {
		return ""
	}
	return fmt.Sprintf("the %s %q is not 1 to 253 characters of [a-z0-9.-]", what, s)
}

// kindFault is why a Kind is refused, "" when it is a row of Kinds: a
// hand-built Kind cannot address a resource the table does not name.
func kindFault(k Kind) string {
	t, ok := KindOf(k.APIVersion, k.Kind)
	if ok && t.Resource == k.Resource && t.Namespaced == k.Namespaced {
		return ""
	}
	return fmt.Sprintf("%s %s (%s) is not a kind farcast reads or writes (ADR 0023 decision 2's table)", k.APIVersion, k.Kind, k.Resource)
}

// addressFault is why one object's address is refused, "" when it is not: a
// namespaced kind names its namespace, a cluster-scoped kind none, and both
// pass the name rule.
func addressFault(k Kind, namespace, name string) string {
	if k.Namespaced {
		if f := nameFault("namespace", namespace); f != "" {
			return f
		}
	} else if namespace != "" {
		return fmt.Sprintf("a cluster-scoped %s names namespace %q", k.Kind, namespace)
	}
	return nameFault(k.Kind+" name", name)
}

// notSent is a request refused before anything was sent.
func notSent(fault string) error {
	return fmt.Errorf("kube: %s; nothing was sent", fault)
}

// objectPath is one object's checked path.
func objectPath(k Kind, namespace, name string) (string, error) {
	if f := addressFault(k, namespace, name); f != "" {
		return "", notSent(f)
	}
	return k.Path(namespace, name), nil
}

// listPath is a collection's checked path; an empty namespace is every
// namespace, or the cluster scope.
func listPath(k Kind, namespace string) (string, error) {
	if namespace != "" {
		if !k.Namespaced {
			return "", notSent(fmt.Sprintf("a cluster-scoped %s names namespace %q", k.Kind, namespace))
		}
		if f := nameFault("namespace", namespace); f != "" {
			return "", notSent(f)
		}
	}
	return k.ListPath(namespace), nil
}

// listAll is a paged GET of a collection (§4): limit=500, following
// metadata.continue until it is empty. A 410 Gone while following one restarts
// the list once from its first page, as an expired continue token asks. A
// server that hands back any token it was already sent in this pass, the one
// just sent or one before it (A, B, A), is unreadable, not followed forever.
// The items come in server order, and an empty list is empty, not nil.
func listAll[T any](ctx context.Context, c *Client, path string, q url.Values, accept string) ([]T, error) {
	items := []T{}
	restarted := false
	cont := ""
	sent := map[string]bool{} // the continue tokens sent in this pass
	for {
		pq := url.Values{}
		for k, v := range q {
			pq[k] = v
		}
		pq.Set("limit", strconv.Itoa(listPageSize))
		if cont != "" {
			pq.Set("continue", cont)
		}
		var page struct {
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
			Items []T `json:"items"`
		}
		err := c.decode(ctx, call{method: http.MethodGet, path: path, query: pq, accept: accept, retry: true}, &page)
		if err != nil {
			var ae *APIError
			if cont != "" && !restarted && errors.As(err, &ae) && ae.Status.Code == http.StatusGone {
				restarted, items, cont, sent = true, []T{}, "", map[string]bool{}
				continue
			}
			return nil, err
		}
		items = append(items, page.Items...)
		next := page.Metadata.Continue
		if next == "" {
			return items, nil
		}
		if sent[next] {
			return nil, refuse(ErrUnreadable, "the API server's list at %s handed back a continue token it was already sent", path)
		}
		sent[next] = true
		cont = next
	}
}

// get is a GET of one object, decoded into v.
func (c *Client) get(ctx context.Context, k Kind, namespace, name string, v any) error {
	path, err := objectPath(k, namespace, name)
	if err != nil {
		return err
	}
	return c.decode(ctx, call{method: http.MethodGet, path: path, retry: true}, v)
}

// ListDeployments lists the Deployments in a namespace ("" is every
// namespace), paged. Each one's Kind is stamped from this list, never read
// from the item.
func (c *Client) ListDeployments(ctx context.Context, namespace string) ([]Deployment, error) {
	path, err := listPath(kindDeployment, namespace)
	if err != nil {
		return nil, err
	}
	items, err := listAll[Deployment](ctx, c, path, nil, "")
	if err != nil {
		return nil, err
	}
	for i := range items {
		items[i].Kind = kindDeployment
	}
	return items, nil
}

// ListStatefulSets lists the StatefulSets in a namespace ("" is every
// namespace), paged, each one's Kind stamped from this list.
func (c *Client) ListStatefulSets(ctx context.Context, namespace string) ([]StatefulSet, error) {
	path, err := listPath(kindStatefulSet, namespace)
	if err != nil {
		return nil, err
	}
	items, err := listAll[StatefulSet](ctx, c, path, nil, "")
	if err != nil {
		return nil, err
	}
	for i := range items {
		items[i].Kind = kindStatefulSet
	}
	return items, nil
}

// GetDeployment reads one Deployment. A 404 is an APIError that unwraps to
// tkube.ErrNotFound.
func (c *Client) GetDeployment(ctx context.Context, namespace, name string) (Deployment, error) {
	var d Deployment
	if err := c.get(ctx, kindDeployment, namespace, name, &d); err != nil {
		return Deployment{}, err
	}
	d.Kind = kindDeployment
	return d, nil
}

// GetStatefulSet reads one StatefulSet.
func (c *Client) GetStatefulSet(ctx context.Context, namespace, name string) (StatefulSet, error) {
	var s StatefulSet
	if err := c.get(ctx, kindStatefulSet, namespace, name, &s); err != nil {
		return StatefulSet{}, err
	}
	s.Kind = kindStatefulSet
	return s, nil
}

// GetService reads one Service.
func (c *Client) GetService(ctx context.Context, namespace, name string) (Service, error) {
	var s Service
	if err := c.get(ctx, kindService, namespace, name, &s); err != nil {
		return Service{}, err
	}
	return s, nil
}

// GetJob reads one Job.
func (c *Client) GetJob(ctx context.Context, namespace, name string) (Job, error) {
	var j Job
	if err := c.get(ctx, kindJob, namespace, name, &j); err != nil {
		return Job{}, err
	}
	return j, nil
}

// ListPods lists the pods in a namespace that a label selector selects,
// paged. The selector is one SelectorString rendered; "" lists every pod.
func (c *Client) ListPods(ctx context.Context, namespace, selector string) ([]Pod, error) {
	path, err := listPath(kindPod, namespace)
	if err != nil {
		return nil, err
	}
	var q url.Values
	if selector != "" {
		q = url.Values{"labelSelector": {selector}}
	}
	return listAll[Pod](ctx, c, path, q, "")
}

// namespaceItem is a namespace list's item, as far as its name and uid.
type namespaceItem struct {
	Metadata tkube.ObjectMeta `json:"metadata"`
}

// ListNamespaces lists the namespaces a label selector selects ("" is every
// namespace), paged, by name, sorted.
func (c *Client) ListNamespaces(ctx context.Context, selector string) ([]string, error) {
	var q url.Values
	if selector != "" {
		q = url.Values{"labelSelector": {selector}}
	}
	items, err := listAll[namespaceItem](ctx, c, kindNamespace.ListPath(""), q, "")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(items))
	for _, it := range items {
		names = append(names, it.Metadata.Name)
	}
	slices.Sort(names)
	return names, nil
}

// NamespaceUID is one namespace's uid, read with the list verb
// (?fieldSelector=metadata.name%3D<name>), which the reader holds; "" when absent.
// An answer of more than one item, or of an item by another name or with no
// uid, is a server that did not apply the selector, and unreadable.
func (c *Client) NamespaceUID(ctx context.Context, name string) (string, error) {
	if f := nameFault("namespace", name); f != "" {
		return "", notSent(f)
	}
	path := kindNamespace.ListPath("")
	items, err := listAll[namespaceItem](ctx, c, path, url.Values{"fieldSelector": {"metadata.name=" + name}}, "")
	if err != nil {
		return "", err
	}
	switch {
	case len(items) == 0:
		return "", nil
	case len(items) > 1:
		return "", refuse(ErrUnreadable, "the API server answered the namespace %q with %d namespaces", name, len(items))
	case items[0].Metadata.Name != name || items[0].Metadata.UID == "":
		return "", refuse(ErrUnreadable, "the API server answered the namespace %q with another namespace, or one without a uid", name)
	}
	return items[0].Metadata.UID, nil
}

// GetConfigMap reads one ConfigMap. A 404 is an APIError that unwraps to
// tkube.ErrNotFound, and a 403 one that unwraps to tkube.ErrForbidden: the
// caller tells absent from forbidden by them.
func (c *Client) GetConfigMap(ctx context.Context, namespace, name string) (ConfigMap, error) {
	var cm ConfigMap
	if err := c.get(ctx, kindConfigMap, namespace, name, &cm); err != nil {
		return ConfigMap{}, err
	}
	return cm, nil
}

// configMapWrite is the part of a ConfigMap's JSON a create or a replace
// reads: what it is, where it goes, and the resourceVersion it was read at.
type configMapWrite struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name            string `json:"name"`
		Namespace       string `json:"namespace"`
		ResourceVersion string `json:"resourceVersion"`
	} `json:"metadata"`
}

// readConfigMapWrite checks a ConfigMap body (RenderPin's JSON) and returns
// its namespace, name and resourceVersion. A refusal names no value: the body
// is the pin.
func readConfigMapWrite(body []byte) (configMapWrite, error) {
	var w configMapWrite
	if err := json.Unmarshal(body, &w); err != nil {
		return w, refuse(ErrRefusedDocument, "kube: the ConfigMap to write is refused: it is not a JSON object")
	}
	if w.APIVersion != kindConfigMap.APIVersion || w.Kind != kindConfigMap.Kind {
		return w, refuse(ErrRefusedDocument, "kube: the ConfigMap to write is refused: it is %q %q, not v1 ConfigMap", w.APIVersion, w.Kind)
	}
	if !validObjectName(w.Metadata.Namespace) || !validObjectName(w.Metadata.Name) {
		return w, refuse(ErrRefusedDocument, "kube: the ConfigMap %q in %q is refused: its name and namespace must be 1 to 253 characters of [a-z0-9.-]", w.Metadata.Name, w.Metadata.Namespace)
	}
	return w, nil
}

// CreateConfigMap creates the ConfigMap body describes, with POST, never an
// apply. body is JSON, its namespace and name read from it. A 409
// AlreadyExists unwraps to tkube.ErrConflict. It is never retried on 429 or
// 503: its caller's loop decides (§9.5).
func (c *Client) CreateConfigMap(ctx context.Context, body []byte) error {
	w, err := readConfigMapWrite(body)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, call{
		method:      http.MethodPost,
		path:        kindConfigMap.ListPath(w.Metadata.Namespace),
		query:       writeQuery(),
		contentType: mediaJSON,
		body:        body,
	})
	return err
}

// ReplaceConfigMap replaces the ConfigMap body describes, with PUT at the
// resourceVersion body carries; a body without one is ErrRefusedDocument and
// sends nothing. A 409 Conflict, something written in between, unwraps to
// tkube.ErrConflict.
func (c *Client) ReplaceConfigMap(ctx context.Context, body []byte) error {
	w, err := readConfigMapWrite(body)
	if err != nil {
		return err
	}
	if w.Metadata.ResourceVersion == "" {
		return refuse(ErrRefusedDocument, "kube: the ConfigMap %s/%s is refused: it carries no metadata.resourceVersion, which a replace is guarded on", w.Metadata.Namespace, w.Metadata.Name)
	}
	_, err = c.do(ctx, call{
		method:      http.MethodPut,
		path:        kindConfigMap.Path(w.Metadata.Namespace, w.Metadata.Name),
		query:       writeQuery(),
		contentType: mediaJSON,
		body:        body,
	})
	return err
}
