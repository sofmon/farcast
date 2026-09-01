package kube

import "time"

// Only the fields TechnoCore reads are declared. This is the deliberate half
// of not vendoring client-go: a typed client models the whole API, and the
// whole API is not what a kernel that lists pods and patches a scale
// subresource needs. Unknown fields are ignored by encoding/json, so a server
// newer than this struct is a non-event.

type ObjectMeta struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	UID       string `json:"uid"`
	// ResourceVersion drives optimistic concurrency on writes. It is read
	// so that a second writer gets a conflict rather than silently winning —
	// TechnoCore runs one replica, and this is what makes a second one loud.
	ResourceVersion   string            `json:"resourceVersion,omitempty"`
	Labels            map[string]string `json:"labels"`
	Annotations       map[string]string `json:"annotations"`
	CreationTimestamp time.Time         `json:"creationTimestamp"`
	// DeletionTimestamp is set once a delete is in flight. A terminating pod
	// still bills, and still appears in a list, so it is read rather than
	// assumed absent.
	DeletionTimestamp *time.Time `json:"deletionTimestamp"`
}

type ResourceList struct {
	CPU    string `json:"cpu"`
	Memory string `json:"memory"`
}

type ResourceRequirements struct {
	Requests ResourceList `json:"requests"`
}

type Container struct {
	Name      string               `json:"name"`
	Resources ResourceRequirements `json:"resources"`
}

type PodSpec struct {
	Containers []Container `json:"containers"`
	// InitContainers are declared because Autopilot bills the maximum of the
	// init and main container request sets, not their sum. Ignoring them
	// would under-report a pod whose init step is the expensive one.
	InitContainers []Container `json:"initContainers"`
	NodeName       string      `json:"nodeName"`
}

type PodCondition struct {
	Type   string `json:"type"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}

type PodStatus struct {
	Phase      string         `json:"phase"`
	Conditions []PodCondition `json:"conditions"`
	StartTime  *time.Time     `json:"startTime"`
}

type Pod struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     PodSpec    `json:"spec"`
	Status   PodStatus  `json:"status"`
}

// Pod phases that matter here. A pod is billable from the moment Autopilot
// reserves capacity for it, which is before it Runs — so Pending counts.
const (
	PodPending   = "Pending"
	PodRunning   = "Running"
	PodSucceeded = "Succeeded"
	PodFailed    = "Failed"
)

// Billable reports whether Autopilot is charging for this pod.
//
// Pending is included deliberately: a pod stuck pulling a large image has had
// capacity reserved and is being billed, and a meter that ignored it would
// under-report exactly the workload most likely to be misbehaving. Succeeded
// and Failed pods hold no capacity and are excluded even though they are still
// listed.
func (p Pod) Billable() bool {
	switch p.Status.Phase {
	case PodPending, PodRunning:
		return true
	default:
		return false
	}
}

// Ready reports whether the pod's Ready condition is true.
func (p Pod) Ready() bool {
	for _, c := range p.Status.Conditions {
		if c.Type == "Ready" {
			return c.Status == "True"
		}
	}
	return false
}

// Requests returns what Autopilot bills this pod for: per-container requests
// summed across the main containers, floored by the largest single init
// container, which is the shape of Autopilot's own calculation.
func (p Pod) Requests() (cpuMilli, memMiB int, err error) {
	for _, c := range p.Spec.Containers {
		cpu, mem, err := containerRequests(c)
		if err != nil {
			return 0, 0, err
		}
		cpuMilli += cpu
		memMiB += mem
	}
	for _, c := range p.Spec.InitContainers {
		cpu, mem, err := containerRequests(c)
		if err != nil {
			return 0, 0, err
		}
		cpuMilli = max(cpuMilli, cpu)
		memMiB = max(memMiB, mem)
	}
	return cpuMilli, memMiB, nil
}

func containerRequests(c Container) (int, int, error) {
	var cpu, mem int
	var err error
	if s := c.Resources.Requests.CPU; s != "" {
		if cpu, err = ParseCPUMilli(s); err != nil {
			return 0, 0, err
		}
	}
	if s := c.Resources.Requests.Memory; s != "" {
		if mem, err = ParseMemMiB(s); err != nil {
			return 0, 0, err
		}
	}
	return cpu, mem, nil
}

type PodList struct {
	Items []Pod `json:"items"`
}

type DeploymentSpec struct {
	Replicas *int           `json:"replicas"`
	Selector *LabelSelector `json:"selector"`
}

type DeploymentStatus struct {
	Replicas          int `json:"replicas"`
	ReadyReplicas     int `json:"readyReplicas"`
	AvailableReplicas int `json:"availableReplicas"`
}

type Deployment struct {
	Metadata ObjectMeta       `json:"metadata"`
	Spec     DeploymentSpec   `json:"spec"`
	Status   DeploymentStatus `json:"status"`
}

type DeploymentList struct {
	Items []Deployment `json:"items"`
}

// Status is the API server's error object. It is returned with a 4xx/5xx and
// carries more than the HTTP code does — the reason is what distinguishes a
// missing object from a forbidden one when both could be a 404.
type Status struct {
	Kind    string `json:"kind"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Reason  string `json:"reason"`
	Code    int    `json:"code"`
}

// LabelSelector is a Deployment's claim on pods.
type LabelSelector struct {
	MatchLabels map[string]string `json:"matchLabels"`
}

// Matches reports whether a pod's labels satisfy the selector.
//
// A nil or empty selector matches NOTHING, which is the opposite of the
// Kubernetes API's own convention for an empty selector in some contexts. The
// reason is the use this package puts it to: attributing pods to the workload
// a cost shutdown would scale. An empty selector that matched everything would
// attribute every pod in the namespace to one deployment, and the shutdown
// would stop a workload believing it was stopping far more than it was.
func (s *LabelSelector) Matches(labels map[string]string) bool {
	if s == nil || len(s.MatchLabels) == 0 {
		return false
	}
	for k, v := range s.MatchLabels {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// ConfigMap is where the cost ledger is checkpointed. It is the one piece of
// cloud-resident state TechnoCore keeps, and it discloses nothing: the
// provider computed every number in it before TechnoCore did.
type ConfigMap struct {
	Kind       string            `json:"kind,omitempty"`
	APIVersion string            `json:"apiVersion,omitempty"`
	Metadata   ObjectMeta        `json:"metadata"`
	Data       map[string]string `json:"data"`
}
