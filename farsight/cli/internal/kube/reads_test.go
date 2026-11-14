package kube

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	tkube "github.com/sofmon/farcast/technocore/kube"
)

var (
	t0 = time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)
	t1 = t0.Add(time.Minute)
	t2 = t0.Add(2 * time.Minute)
)

// podSpec builds one pod for TestPickPodOrder. Every field the order reads
// has a default that ties, so each row changes only what it tests.
type podSpec struct {
	name     string
	node     string // "-" for unassigned
	phase    string
	ready    bool
	readyAt  time.Time
	restarts int32
	sidecar  int32 // restarts of an init container with restartPolicy Always
	initRst  int32 // restarts of an init container without it
	created  time.Time
}

func (s podSpec) pod() Pod {
	p := Pod{Metadata: ObjectMeta{ObjectMeta: tkube.ObjectMeta{Name: s.name, CreationTimestamp: s.created}}}
	p.Spec.NodeName = "node-1"
	if s.node == "-" {
		p.Spec.NodeName = ""
	} else if s.node != "" {
		p.Spec.NodeName = s.node
	}
	p.Status.Phase = s.phase
	if p.Status.Phase == "" {
		p.Status.Phase = "Running"
	}
	ready := "False"
	if s.ready {
		ready = "True"
	}
	p.Status.Conditions = []PodCondition{
		{Type: "Initialized", Status: "True", LastTransitionTime: t0},
		{Type: "Ready", Status: ready, LastTransitionTime: s.readyAt},
	}
	p.Spec.Containers = []PodContainer{{Name: "app"}}
	p.Status.ContainerStatuses = []ContainerStatus{{Name: "app", RestartCount: s.restarts}}
	p.Spec.InitContainers = []InitContainer{{Name: "proxy", RestartPolicy: "Always"}, {Name: "setup"}}
	p.Status.InitContainerStatuses = []InitContainerStatus{{Name: "proxy", RestartCount: s.sidecar}, {Name: "setup", RestartCount: s.initRst}}
	return p
}

// TestPickPodOrder is kubectl v0.37.2's podutils.ByLogging, criterion by
// criterion, each row a pod the earlier criteria cannot tell apart from its
// rival, listed after it so the server's order alone would not pick it.
func TestPickPodOrder(t *testing.T) {
	cases := []struct {
		name string
		pods []podSpec
		want string
	}{
		{"1: assigned before unassigned, whatever else",
			[]podSpec{{name: "unassigned", node: "-", ready: true, readyAt: t0, restarts: 9, created: t0}, {name: "assigned", phase: "Pending", created: t2}}, "assigned"},
		{"2: Running before Pending",
			[]podSpec{{name: "pending", phase: "Pending", created: t0}, {name: "running", created: t2}}, "running"},
		{"2: Unknown before Pending",
			[]podSpec{{name: "pending", phase: "Pending", created: t0}, {name: "unknown", phase: "Unknown", created: t2}}, "unknown"},
		{"2: Running before Unknown",
			[]podSpec{{name: "unknown", phase: "Unknown", created: t0}, {name: "running", created: t2}}, "running"},
		{"2: Succeeded ties Running, so the older wins",
			[]podSpec{{name: "running", created: t2}, {name: "succeeded", phase: "Succeeded", created: t1}}, "succeeded"},
		{"2: Failed ties Running, so the older wins",
			[]podSpec{{name: "running", created: t2}, {name: "failed", phase: "Failed", created: t1}}, "failed"},
		{"2: Succeeded comes before Pending",
			[]podSpec{{name: "pending", phase: "Pending", created: t0}, {name: "succeeded", phase: "Succeeded", created: t2}}, "succeeded"},
		{"3: ready before not ready, whatever the restarts",
			[]podSpec{{name: "crashing", restarts: 7, created: t0}, {name: "ready", ready: true, readyAt: t1, created: t2}}, "ready"},
		{"4: ready the longest first",
			[]podSpec{{name: "recent", ready: true, readyAt: t2, restarts: 3, created: t0}, {name: "longest", ready: true, readyAt: t1, created: t2}}, "longest"},
		{"4: a zero ready time counts as latest",
			[]podSpec{{name: "zero", ready: true, created: t0}, {name: "timed", ready: true, readyAt: t2, created: t2}}, "timed"},
		{"5: more restarts first",
			[]podSpec{{name: "fewer", restarts: 0, created: t0}, {name: "more", restarts: 3, created: t2}}, "more"},
		{"5: sidecar restarts break a tie in regular ones",
			[]podSpec{{name: "fewer", restarts: 1, sidecar: 0, created: t0}, {name: "more", restarts: 1, sidecar: 2, created: t2}}, "more"},
		{"5: regular restarts count before sidecar ones",
			[]podSpec{{name: "sidecar", restarts: 0, sidecar: 9, created: t0}, {name: "regular", restarts: 1, created: t2}}, "regular"},
		{"5: an init container that is not a sidecar does not count",
			[]podSpec{{name: "init", initRst: 9, created: t0}, {name: "sidecar", sidecar: 1, created: t2}}, "sidecar"},
		{"6: the older first",
			[]podSpec{{name: "newer", created: t2}, {name: "older", created: t1}}, "older"},
		{"6: a zero creation time sorts last",
			[]podSpec{{name: "zero"}, {name: "dated", created: t2}}, "dated"},
		{"a full tie keeps the server's order",
			[]podSpec{{name: "first", created: t1}, {name: "second", created: t1}, {name: "third", created: t1}}, "first"},
		{"the order across many",
			[]podSpec{
				{name: "pending", phase: "Pending", created: t0},
				{name: "unready", created: t0},
				{name: "ready-late", ready: true, readyAt: t2, created: t0},
				{name: "ready-early", ready: true, readyAt: t1, created: t1},
				{name: "unassigned", node: "-", ready: true, readyAt: t0, created: t0},
			}, "ready-early"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var pods []Pod
			for _, s := range tc.pods {
				pods = append(pods, s.pod())
			}
			before := slices.Clone(pods)
			got, ok := PickPod(pods)
			if !ok {
				t.Fatal("PickPod found no pod")
			}
			if got.Metadata.Name != tc.want {
				t.Errorf("PickPod chose %q, want %q", got.Metadata.Name, tc.want)
			}
			for i := range pods {
				if pods[i].Metadata.Name != before[i].Metadata.Name {
					t.Fatal("PickPod reordered the list it was given")
				}
			}
		})
	}
	if _, ok := PickPod(nil); ok {
		t.Error("PickPod(nil) found a pod")
	}
}

// TestSelectorStringRefusesExpressions: only equality-only, non-empty
// selectors render; anything with matchExpressions is refused, because it
// would read as a broader selector (§4).
func TestSelectorStringRefusesExpressions(t *testing.T) {
	expr := []LabelSelectorRequirement{{Key: "tier", Operator: "NotIn", Values: []string{"canary"}}}
	refused := []struct {
		name string
		s    *LabelSelector
		want string
	}{
		{"nil", nil, "selects its pods with an empty selector, which farcast does not read"},
		{"empty", &LabelSelector{}, "selects its pods with an empty selector, which farcast does not read"},
		{"an empty map", &LabelSelector{MatchLabels: map[string]string{}}, "selects its pods with an empty selector, which farcast does not read"},
		{"expressions only", &LabelSelector{MatchExpressions: expr}, "selects its pods with matchExpressions, which farcast does not read"},
		{"labels and expressions", &LabelSelector{MatchLabels: map[string]string{"app": "api"}, MatchExpressions: expr},
			"selects its pods with matchExpressions, which farcast does not read"},
		{"a value with a comma", &LabelSelector{MatchLabels: map[string]string{"app": "api,tier=x"}},
			"selects its pods with a label a selector cannot carry, which farcast does not read"},
		{"a key with an operator", &LabelSelector{MatchLabels: map[string]string{"app!": "api"}},
			"selects its pods with a label a selector cannot carry, which farcast does not read"},
		{"a value with a space", &LabelSelector{MatchLabels: map[string]string{"app": "a b"}},
			"selects its pods with a label a selector cannot carry, which farcast does not read"},
		{"an empty key", &LabelSelector{MatchLabels: map[string]string{"": "api"}},
			"selects its pods with a label a selector cannot carry, which farcast does not read"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SelectorString(tc.s)
			if err == nil {
				t.Fatalf("SelectorString = %q, want a refusal", got)
			}
			if !errors.Is(err, ErrUnreadable) {
				t.Errorf("error %v does not wrap ErrUnreadable", err)
			}
			if err.Error() != tc.want {
				t.Errorf("error = %q, want %q", err.Error(), tc.want)
			}
		})
	}
	_, err := SelectorString(&LabelSelector{MatchLabels: map[string]string{"app": "api"}, MatchExpressions: expr})
	if got, want := fmt.Errorf("the %s %s/%s %w", "Deployment", "web", "api", err).Error(),
		"the Deployment web/api selects its pods with matchExpressions, which farcast does not read"; got != want {
		t.Errorf("composed refusal = %q, want §4's %q", got, want)
	}

	for _, c := range []struct {
		labels map[string]string
		want   string
	}{
		{map[string]string{"app": "api"}, "app=api"},
		{map[string]string{"b": "2", "a": "1"}, "a=1,b=2"},
		{map[string]string{"a.b": "2", "a": "1"}, "a=1,a.b=2"},
		{map[string]string{"app.kubernetes.io/name": "web", "app.kubernetes.io/managed-by": "farcast"},
			"app.kubernetes.io/managed-by=farcast,app.kubernetes.io/name=web"},
		{map[string]string{"empty": ""}, "empty="},
	} {
		got, err := SelectorString(&LabelSelector{MatchLabels: c.labels})
		if err != nil || got != c.want {
			t.Errorf("SelectorString(%v) = %q, %v; want %q", c.labels, got, err, c.want)
		}
	}
}

// TestReadTypesDecodeTheirFields decodes answers shaped as a real API
// server's, so a mistyped JSON tag shows as a field left zero.
func TestReadTypesDecodeTheirFields(t *testing.T) {
	var d Deployment
	mustDecode(t, `{"kind":"Deployment","apiVersion":"apps/v1",
	  "metadata":{"name":"api","namespace":"web","uid":"u","resourceVersion":"9","generation":4,
	    "annotations":{"farcast.sofmon.com/adapted-at":"2026-11-14T09:00:00Z"},
	    "managedFields":[{"manager":"farcast","operation":"Apply","apiVersion":"apps/v1","time":"2026-11-14T09:00:00Z","fieldsType":"FieldsV1","fieldsV1":{"f:spec":{}}}]},
	  "spec":{"replicas":2,"selector":{"matchLabels":{"app":"api"},"matchExpressions":[{"key":"k","operator":"In","values":["v"]}]},
	    "template":{"spec":{"containers":[{"name":"api","image":"r/api@sha256:1","resources":{"requests":{"cpu":"250m","memory":"512Mi"}}}],
	      "initContainers":[{"name":"init","image":"r/init"}],"ephemeralContainers":[{"name":"debug","image":"r/dbg"}]}}},
	  "status":{"observedGeneration":4,"replicas":2,"updatedReplicas":2,"readyReplicas":1,"availableReplicas":1,
	    "conditions":[{"type":"Progressing","status":"True","reason":"NewReplicaSetAvailable","message":"m"}]}}`, &d)
	if d.Metadata.Name != "api" || d.Metadata.Generation != 4 || d.Metadata.ResourceVersion != "9" || len(d.Metadata.ManagedFields) != 1 ||
		d.Metadata.ManagedFields[0].Time != "2026-11-14T09:00:00Z" || string(d.Metadata.ManagedFields[0].FieldsV1) != `{"f:spec":{}}` ||
		d.Metadata.Annotations["farcast.sofmon.com/adapted-at"] == "" {
		t.Errorf("deployment metadata = %+v", d.Metadata)
	}
	if d.Spec.Replicas == nil || *d.Spec.Replicas != 2 || d.Spec.Selector == nil || d.Spec.Selector.MatchLabels["app"] != "api" ||
		len(d.Spec.Selector.MatchExpressions) != 1 || d.Spec.Selector.MatchExpressions[0].Values[0] != "v" {
		t.Errorf("deployment spec = %+v", d.Spec)
	}
	c := d.Spec.Template.Spec
	if len(c.Containers) != 1 || c.Containers[0].Image != "r/api@sha256:1" || c.Containers[0].Resources.Requests.CPU != "250m" ||
		c.Containers[0].Resources.Requests.Memory != "512Mi" || len(c.InitContainers) != 1 || len(c.EphemeralContainers) != 1 {
		t.Errorf("deployment template = %+v", c)
	}
	if s := d.Status; s.ObservedGeneration != 4 || s.Replicas != 2 || s.UpdatedReplicas != 2 || s.ReadyReplicas != 1 || s.AvailableReplicas != 1 ||
		len(s.Conditions) != 1 || s.Conditions[0].Reason != "NewReplicaSetAvailable" || s.Conditions[0].Message != "m" {
		t.Errorf("deployment status = %+v", s)
	}

	var ss StatefulSet
	mustDecode(t, `{"metadata":{"name":"db"},"spec":{"replicas":1,"selector":{"matchLabels":{"app":"db"}},"template":{"spec":{"containers":[{"name":"db","image":"r/db"}]}}},
	  "status":{"observedGeneration":1,"replicas":1,"readyReplicas":1}}`, &ss)
	if ss.Spec.Replicas == nil || *ss.Spec.Replicas != 1 || ss.Status.ReadyReplicas != 1 || ss.Status.ObservedGeneration != 1 || ss.Spec.Template.Spec.Containers[0].Image != "r/db" {
		t.Errorf("statefulset = %+v", ss)
	}

	var p Pod
	mustDecode(t, `{"metadata":{"name":"api-1","creationTimestamp":"2026-11-14T09:00:00Z"},
	  "spec":{"nodeName":"n","containers":[{"name":"api"}],"initContainers":[{"name":"proxy","restartPolicy":"Always"}],"ephemeralContainers":[{"name":"debug"}]},
	  "status":{"phase":"Running","conditions":[{"type":"Ready","status":"True","lastTransitionTime":"2026-11-14T09:01:00Z"}],
	    "containerStatuses":[{"name":"api","restartCount":3,"state":{"terminated":{"message":"oom"}}}],
	    "initContainerStatuses":[{"name":"proxy","restartCount":1}]}}`, &p)
	if p.Spec.NodeName != "n" || p.Spec.InitContainers[0].RestartPolicy != "Always" || len(p.Spec.EphemeralContainers) != 1 ||
		p.Status.Phase != "Running" || !p.Status.Conditions[0].LastTransitionTime.Equal(t1) ||
		p.Status.ContainerStatuses[0].RestartCount != 3 || p.Status.ContainerStatuses[0].State.Terminated == nil ||
		p.Status.ContainerStatuses[0].State.Terminated.Message != "oom" || p.Status.InitContainerStatuses[0].RestartCount != 1 ||
		!p.Metadata.CreationTimestamp.Equal(t0) {
		t.Errorf("pod = %+v", p)
	}

	var j Job
	mustDecode(t, `{"metadata":{"name":"build"},"spec":{"selector":{"matchLabels":{"batch.kubernetes.io/controller-uid":"u"}},"template":{"spec":{"containers":[{"name":"build"}]}}},
	  "status":{"succeeded":1,"failed":2,"conditions":[{"type":"Complete","status":"True"}]}}`, &j)
	if j.Spec.Selector == nil || j.Spec.Selector.MatchLabels["batch.kubernetes.io/controller-uid"] != "u" || j.Spec.Template.Spec.Containers[0].Name != "build" ||
		j.Status.Succeeded != 1 || j.Status.Failed != 2 || j.Status.Conditions[0].Type != "Complete" {
		t.Errorf("job = %+v", j)
	}

	var svc Service
	mustDecode(t, `{"status":{"loadBalancer":{"ingress":[{"ip":"203.0.113.7","hostname":"h"}]}}}`, &svc)
	if len(svc.Status.LoadBalancer.Ingress) != 1 || svc.Status.LoadBalancer.Ingress[0].IP != "203.0.113.7" || svc.Status.LoadBalancer.Ingress[0].Hostname != "h" {
		t.Errorf("service = %+v", svc)
	}

	var cm ConfigMap
	mustDecode(t, `{"kind":"ConfigMap","metadata":{"name":"pin","resourceVersion":"7"},"data":{"k":"v"}}`, &cm)
	if cm.Metadata.ResourceVersion != "7" || cm.Data["k"] != "v" {
		t.Errorf("configmap = %+v", cm)
	}

	// Object declares metadata only, and never reads kind from the body.
	var o Object
	mustDecode(t, `{"kind":"Secret","apiVersion":"v1","metadata":{"name":"s","annotations":{"a":"b"}},"data":{"token":"c2VjcmV0"}}`, &o)
	if o.Metadata.Name != "s" || o.Kind.Kind != "" {
		t.Errorf("object = %+v", o)
	}
}

func mustDecode(t *testing.T, body string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(strings.TrimSpace(body)), v); err != nil {
		t.Fatalf("decode %T: %v", v, err)
	}
}
