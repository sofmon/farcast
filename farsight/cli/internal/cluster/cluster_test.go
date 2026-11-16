package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dsdeploy "github.com/sofmon/farcast/datasphere/deploy"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
	tkube "github.com/sofmon/farcast/technocore/kube"
)

// The read tests below run each method in-process, on an Open'd reader
// against kubetest (ADR 0023 M2.4); the writes, on an Open'd writer (M2.5).
// Since ADR 0023 M2.5 no method but Apply runs kubectl, so no read keeps a
// kubectl half. Apply alone is tested on a fake Runner, until ADR 0023 M2.7.

// fakeRunner records each kubectl call and its stdin, and answers each with
// err.
type fakeRunner struct {
	calls  [][]string
	stdins [][]byte
	err    error
}

func (f *fakeRunner) Run(_ context.Context, stdin []byte, args ...string) ([]byte, error) {
	f.calls = append(f.calls, args)
	f.stdins = append(f.stdins, stdin)
	if f.err != nil {
		return nil, f.err
	}
	return nil, nil
}

// safeBuffer is a buffer a followed Logs writes to while the test reads it.
type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// quick shortens an Open'd client's waits, so that several polls take no time.
func quick(c *Client) *Client {
	c.poll = time.Millisecond
	return c
}

// waitFor polls cond until it holds or 10 s pass.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("waited 10 s for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// object is a kubetest object of one kind, with fields merged in; a
// "metadata" field is merged into the object's metadata.
func object(apiVersion, kind, namespace, name string, fields map[string]any) map[string]any {
	md := map[string]any{"name": name}
	if namespace != "" {
		md["namespace"] = namespace
	}
	o := map[string]any{"apiVersion": apiVersion, "kind": kind, "metadata": md}
	for k, v := range fields {
		if k == "metadata" {
			for mk, mv := range v.(map[string]any) {
				md[mk] = mv
			}
			continue
		}
		o[k] = v
	}
	return o
}

func selectorOf(labels map[string]string) map[string]any {
	return map[string]any{"matchLabels": labels}
}

// workloadObject is a Deployment or StatefulSet selecting app=<name>.
func workloadObject(kind, namespace, name string) map[string]any {
	return object("apps/v1", kind, namespace, name, map[string]any{
		"spec": map[string]any{"selector": selectorOf(map[string]string{"app": name})},
	})
}

// podObject is a pod with labels, containers (by name, init and ephemeral ones
// prefixed "init:" and "eph:") and annotations.
func podObject(namespace, name string, labels map[string]string, containers []string, annotations map[string]string) map[string]any {
	spec := map[string]any{}
	for _, c := range containers {
		field, n := "containers", c
		if rest, ok := strings.CutPrefix(c, "init:"); ok {
			field, n = "initContainers", rest
		} else if rest, ok := strings.CutPrefix(c, "eph:"); ok {
			field, n = "ephemeralContainers", rest
		}
		list, _ := spec[field].([]any)
		spec[field] = append(list, map[string]any{"name": n})
	}
	md := map[string]any{"labels": labels}
	if annotations != nil {
		md["annotations"] = annotations
	}
	return object("v1", "Pod", namespace, name, map[string]any{"metadata": md, "spec": spec})
}

// logQueries is the parsed query of every pod-log request s saw, in order.
func logQueries(t *testing.T, s *kubetest.Server) []url.Values {
	t.Helper()
	var out []url.Values
	for _, r := range s.Requests() {
		if strings.HasSuffix(r.Path, "/log") {
			q, err := url.ParseQuery(r.RawQuery)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, q)
		}
	}
	return out
}

// apiPaths is the method and path of every API request s saw.
func apiPaths(s *kubetest.Server) []string {
	var out []string
	for _, r := range apiRequests(s) {
		out = append(out, r.Method+" "+r.Path)
	}
	return out
}

func TestApplyPipesManifestToStdin(t *testing.T) {
	fr := &fakeRunner{}
	c := newWithRunner(fr)
	if err := c.Apply(context.Background(), []byte("MANIFEST")); err != nil {
		t.Fatal(err)
	}
	if len(fr.calls) != 1 || !slices.Equal(fr.calls[0], []string{"apply", "-f", "-"}) {
		t.Fatalf("calls=%v, want one [apply -f -]", fr.calls)
	}
	if string(fr.stdins[0]) != "MANIFEST" {
		t.Fatalf("stdin=%q, want MANIFEST", fr.stdins[0])
	}
}

// rolloutState is a Deployment farcast-system/fatline as the rollout rules
// read it.
func rolloutState(generation, observed, desired, replicas, updated, available int, progressReason string) map[string]any {
	status := map[string]any{"observedGeneration": observed, "replicas": replicas, "updatedReplicas": updated, "availableReplicas": available}
	if progressReason != "" {
		status["conditions"] = []any{map[string]any{"type": "Progressing", "status": "False", "reason": progressReason}}
	}
	return object("apps/v1", "Deployment", "farcast-system", "fatline", map[string]any{
		"metadata": map[string]any{"generation": generation},
		"spec":     map[string]any{"replicas": desired},
		"status":   status,
	})
}

const fatlineDeployment = "/apis/apps/v1/namespaces/farcast-system/deployments/fatline"

// An Open'd reader waits on the Deployment itself: it reads it until the
// rollout rules say done, as the reader.
func TestRolloutStatusArgs(t *testing.T) {
	s := kubetest.New(t)
	s.Script(fatlineDeployment,
		rolloutState(2, 1, 2, 2, 2, 2, ""), // the spec update not yet observed
		rolloutState(2, 2, 2, 2, 1, 1, ""), // 1 of 2 updated
		rolloutState(2, 2, 2, 2, 2, 2, ""), // done
	)
	c := quick(openReader(t, s, nil))
	if err := c.RolloutStatus(t.Context(), "farcast-system", "fatline", time.Minute); err != nil {
		t.Fatal(err)
	}
	reqs := apiRequests(s)
	if len(reqs) != 3 {
		t.Fatalf("%d requests, want three reads: %v", len(reqs), apiPaths(s))
	}
	for _, r := range reqs {
		if r.Method != http.MethodGet || r.Path != fatlineDeployment || r.As != "reader" {
			t.Errorf("request %s %s as %q", r.Method, r.Path, r.As)
		}
	}
}

// A rollout past its progress deadline is stalled, not a timeout; one still
// waiting at the deadline says what it was waiting for, wrapping
// kube.ErrTimedOut; an absent Deployment is an error; and a context that ends
// while it waits ends the wait.
func TestRolloutStatusStallsAndTimesOut(t *testing.T) {
	if rolloutPoll != 2*time.Second || servicePoll != 3*time.Second || jobPoll != 5*time.Second {
		t.Errorf("the waits are %v, %v and %v; design §4 has 2 s, 3 s and 5 s", rolloutPoll, servicePoll, jobPoll)
	}
	if got := (&Client{}).every(jobPoll); got != jobPoll {
		t.Errorf("an unset poll waits %v, want the method's own", got)
	}

	s := kubetest.New(t)
	c := quick(openReader(t, s, nil))
	ctx := t.Context()

	s.Script(fatlineDeployment, rolloutState(1, 1, 2, 2, 2, 1, "ProgressDeadlineExceeded"))
	err := c.RolloutStatus(ctx, "farcast-system", "fatline", time.Minute)
	if !errors.Is(err, kube.ErrRolloutStalled) || errors.Is(err, kube.ErrTimedOut) || err.Error() != `deployment "fatline" exceeded its progress deadline` {
		t.Errorf("a stalled rollout: %v", err)
	}

	s.Script(fatlineDeployment, rolloutState(1, 1, 2, 2, 1, 1, ""))
	err = c.RolloutStatus(ctx, "farcast-system", "fatline", 0)
	want := "deployment farcast-system/fatline did not finish rolling out within 0s: kube: timed out waiting (last: 1 out of 2 new replicas have been updated)"
	if !errors.Is(err, kube.ErrTimedOut) || err.Error() != want {
		t.Errorf("at the deadline: %v\nwant %s", err, want)
	}

	s.Script(fatlineDeployment)
	if err := c.RolloutStatus(ctx, "farcast-system", "fatline", time.Minute); !errors.Is(err, tkube.ErrNotFound) {
		t.Errorf("an absent Deployment: %v, want a 404", err)
	}

	s.Script(fatlineDeployment, rolloutState(1, 1, 2, 2, 1, 1, ""))
	c.poll = time.Hour
	short, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if err := c.RolloutStatus(short, "farcast-system", "fatline", time.Minute); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a context that ended while waiting: %v", err)
	}
}

func serviceWith(ingress ...map[string]any) map[string]any {
	lb := map[string]any{}
	if len(ingress) > 0 {
		var list []any
		for _, i := range ingress {
			list = append(list, i)
		}
		lb["ingress"] = list
	}
	return object("v1", "Service", "farcast-system", "fatline", map[string]any{"status": map[string]any{"loadBalancer": lb}})
}

const fatlineService = "/api/v1/namespaces/farcast-system/services/fatline"

func TestWaitExternalIPReturnsIP(t *testing.T) {
	s := kubetest.New(t)
	s.Script(fatlineService, serviceWith(), serviceWith(map[string]any{"hostname": ""}), serviceWith(map[string]any{"ip": "34.0.0.5"}))
	c := quick(openReader(t, s, nil))
	ip, err := c.WaitExternalIP(t.Context(), "farcast-system", "fatline", time.Minute)
	if err != nil || ip != "34.0.0.5" {
		t.Fatalf("ip = %q, %v", ip, err)
	}
	if got := apiPaths(s); len(got) != 3 || got[0] != "GET "+fatlineService {
		t.Errorf("requests = %v, want three reads of the Service", got)
	}

	// An address that is not one never becomes an endpoint.
	for _, bad := range []string{"34.0.0.256", "fe80::1%eth0", "fatline.example"} {
		s.Script(fatlineService, serviceWith(map[string]any{"ip": bad}))
		if ip, err := c.WaitExternalIP(t.Context(), "farcast-system", "fatline", time.Minute); err == nil || ip != "" {
			t.Errorf("ingress IP %q = %q, %v; want an error", bad, ip, err)
		}
	}
}

func TestWaitExternalIPTimesOut(t *testing.T) {
	const want = "cluster: service farcast-system/fatline had no external IP after 0s"
	s := kubetest.New(t)
	s.Put(serviceWith())
	c := openReader(t, s, nil)
	// Zero timeout: the first empty read is already past the deadline.
	ip, err := c.WaitExternalIP(t.Context(), "farcast-system", "fatline", 0)
	if ip != "" || !errors.Is(err, kube.ErrTimedOut) || err.Error() != want {
		t.Fatalf("= %q, %v; want %q wrapping kube.ErrTimedOut", ip, err, want)
	}
}

func TestRunnerErrorPropagates(t *testing.T) {
	fr := &fakeRunner{err: errors.New("boom")}
	c := newWithRunner(fr)
	if err := c.Apply(context.Background(), []byte("x")); err == nil {
		t.Fatal("expected the runner error to propagate")
	}
}

// jobObject is the Job farcast-system/<name>, selecting job-name=<name>, with
// these template containers and this status.
func jobObject(name string, containers []string, status map[string]any) map[string]any {
	var cs []any
	for _, c := range containers {
		cs = append(cs, map[string]any{"name": c, "image": "example.invalid/" + c})
	}
	return object("batch/v1", "Job", "farcast-system", name, map[string]any{
		"spec": map[string]any{
			"selector": selectorOf(map[string]string{"job-name": name}),
			"template": map[string]any{"spec": map[string]any{"containers": cs}},
		},
		"status": status,
	})
}

// A manifest read's whole output is the document, so asking for "the logs"
// must mean all of them. kubectl's own default is a tail, which is why this is
// a behaviour rather than an omission.
func TestJobLogsAsksForEverythingUnlessGivenALimit(t *testing.T) {
	s := kubetest.New(t)
	s.Put(jobObject("fetch", []string{"git"}, nil))
	s.Put(podObject("farcast-system", "fetch-abc", map[string]string{"job-name": "fetch"}, []string{"git"},
		map[string]string{kubetest.LogAnnotationPrefix + "git": "first\nsecond\nthird\n"}))
	s.Put(podObject("farcast-system", "other-xyz", map[string]string{"job-name": "other"}, []string{"git"},
		map[string]string{kubetest.LogAnnotationPrefix + "git": "not this job's\n"}))
	c := openReader(t, s, nil)
	for _, row := range []struct {
		name  string
		lines int
		tail  string // "" is no tailLines at all
		out   string
	}{
		{"no limit", 0, "", "first\nsecond\nthird\n"},
		{"negative limit", -1, "", "first\nsecond\nthird\n"},
		{"a limit", 40, "40", "first\nsecond\nthird\n"},
		{"one line", 1, "1", "third\n"},
	} {
		out, err := c.JobLogs(t.Context(), "farcast-system", "fetch", row.lines)
		if err != nil || out != row.out {
			t.Errorf("%s: %q, %v; want %q", row.name, out, err, row.out)
		}
		qs := logQueries(t, s)
		q := qs[len(qs)-1]
		if q.Get("container") != "git" || q.Has("tailLines") != (row.tail != "") || q.Get("tailLines") != row.tail || q.Has("follow") || q.Has("previous") {
			t.Errorf("%s: the log request asked %v", row.name, q)
		}
	}
}

// An Open'd client reads a Job's one container, from a pod its own selector
// chooses. A template of more containers is refused before the pods are
// listed, a Job with no pod says so, and a selector farcast cannot read is
// refused naming the Job.
func TestJobLogsReadsTheTemplatesOneContainer(t *testing.T) {
	s := kubetest.New(t)
	c := openReader(t, s, nil)
	ctx := t.Context()

	s.Put(jobObject("build", []string{"kaniko", "sidecar"}, nil))
	if _, err := c.JobLogs(ctx, "farcast-system", "build", 0); err == nil || err.Error() != "job farcast-system/build has 2 containers; farcast reads only one" {
		t.Errorf("two containers: %v", err)
	}
	if got := apiPaths(s); !slices.Equal(got, []string{"GET /apis/batch/v1/namespaces/farcast-system/jobs/build"}) {
		t.Errorf("a refused template still sent %v", got)
	}

	s.Put(jobObject("fetch", []string{"git"}, nil))
	if _, err := c.JobLogs(ctx, "farcast-system", "fetch", 0); err == nil || err.Error() != "job farcast-system/fetch has no pod to read" {
		t.Errorf("no pod: %v", err)
	}

	expr := jobObject("expr", []string{"git"}, nil)
	expr["spec"].(map[string]any)["selector"] = map[string]any{
		"matchExpressions": []any{map[string]any{"key": "job-name", "operator": "In", "values": []any{"expr"}}},
	}
	s.Put(expr)
	_, err := c.JobLogs(ctx, "farcast-system", "expr", 0)
	if !errors.Is(err, kube.ErrUnreadable) || err.Error() != "the Job farcast-system/expr selects its pods with matchExpressions, which farcast does not read" {
		t.Errorf("an expressions selector: %v", err)
	}
	if _, err := c.JobLogs(ctx, "farcast-system", "absent", 0); !errors.Is(err, tkube.ErrNotFound) {
		t.Errorf("an absent Job: %v", err)
	}
}

const buildJob = "/apis/batch/v1/namespaces/farcast-system/jobs/build"

// buildPod is a pod of Job build, created at created, with these container
// statuses.
func buildPod(name, created string, statuses ...map[string]any) map[string]any {
	var list []any
	for _, st := range statuses {
		list = append(list, st)
	}
	p := podObject("farcast-system", name, map[string]string{"job-name": "build"}, []string{"kaniko"}, nil)
	p["metadata"].(map[string]any)["creationTimestamp"] = created
	p["status"] = map[string]any{"containerStatuses": list}
	return p
}

func terminated(message string) map[string]any {
	return map[string]any{"name": "kaniko", "state": map[string]any{"terminated": map[string]any{"message": message}}}
}

func running() map[string]any {
	return map[string]any{"name": "sidecar", "state": map[string]any{"running": map[string]any{}}}
}

// A Job ends on its counts or on its conditions, and its message is the
// newest pod's first terminated container's, trimmed; a Job that has not
// ended by the deadline is a timeout.
func TestWaitJobReadsTheOutcomeAndTheNewestPodsMessage(t *testing.T) {
	for _, row := range []struct {
		name      string
		status    map[string]any
		succeeded bool
	}{
		{"succeeded", map[string]any{"succeeded": 1}, true},
		{"complete", map[string]any{"conditions": []any{map[string]any{"type": "Complete", "status": "True"}}}, true},
		{"failed", map[string]any{"failed": 1}, false},
		{"failed condition", map[string]any{"conditions": []any{map[string]any{"type": "Failed", "status": "True"}}}, false},
	} {
		s := kubetest.New(t)
		s.Put(jobObject("build", []string{"kaniko"}, row.status))
		s.Put(buildPod("build-old", "2026-11-15T10:00:00Z", terminated("sha256:old")))
		s.Put(buildPod("build-new", "2026-11-15T10:05:00Z", running(), terminated("  sha256:new\n")))
		s.Put(buildPod("build-mid", "2026-11-15T10:02:00Z", terminated("sha256:mid")))
		res, err := openReader(t, s, nil).WaitJob(t.Context(), "farcast-system", "build", time.Minute)
		if err != nil || res.Succeeded != row.succeeded || res.Message != "sha256:new" {
			t.Errorf("%s: %+v, %v; want succeeded %v with the newest pod's message", row.name, res, err, row.succeeded)
		}
	}

	s := kubetest.New(t)
	s.Script(buildJob,
		jobObject("build", []string{"kaniko"}, map[string]any{"active": 1}),
		jobObject("build", []string{"kaniko"}, map[string]any{"conditions": []any{map[string]any{"type": "Complete", "status": "False"}}}),
		jobObject("build", []string{"kaniko"}, map[string]any{"succeeded": 1}),
	)
	c := quick(openReader(t, s, nil))
	res, err := c.WaitJob(t.Context(), "farcast-system", "build", time.Minute)
	if err != nil || !res.Succeeded || res.Message != "" {
		t.Errorf("after polling, with no pod: %+v, %v; want succeeded with no message", res, err)
	}
	reads := 0
	for _, p := range apiPaths(s) {
		if p == "GET "+buildJob {
			reads++
		}
	}
	if reads != 4 {
		t.Errorf("the Job was read %d times; want three polls and the message's own read", reads)
	}

	s.Script(buildJob, jobObject("build", []string{"kaniko"}, map[string]any{"active": 1}))
	res, err = c.WaitJob(t.Context(), "farcast-system", "build", 0)
	const want = "cluster: job farcast-system/build neither succeeded nor failed after 0s"
	if res != (JobResult{}) || !errors.Is(err, kube.ErrTimedOut) || err.Error() != want {
		t.Errorf("at the deadline: %+v, %v; want %q wrapping kube.ErrTimedOut", res, err, want)
	}
}

// A Deployment with no explicit replicas runs one. Decoding that as zero would
// show every healthy application as stopped — and stopped is exactly what a
// protective cost shutdown leaves behind, so the two must not be confused.
func TestWorkloadsWithoutExplicitReplicasRunOne(t *testing.T) {
	check := func(t *testing.T, got []Workload, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d deployments, want 2", len(got))
		}
		if got[0].Desired != 1 || got[0].Ready != 1 {
			t.Errorf("api = %d/%d, want 1/1 — an absent replicas field means one", got[0].Ready, got[0].Desired)
		}
		if got[1].Desired != 0 {
			t.Errorf("web desired = %d, want 0 — an explicit zero is a stopped application", got[1].Desired)
		}
		if got[0].Labels["farcast.sofmon.com/tier"] != "app" {
			t.Errorf("labels were dropped: %v", got[0].Labels)
		}
		if len(got[0].Images) != 1 || got[0].Images[0] != "reg.example/api@sha256:abc" {
			t.Errorf("images = %v", got[0].Images)
		}
		if !got[0].CreatedAt.Equal(time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)) {
			t.Errorf("the creation timestamp is %v, so ps shows the wrong age", got[0].CreatedAt)
		}
		if got[0].Namespace != "apps" || got[0].Kind != "Deployment" {
			t.Errorf("api = %+v", got[0])
		}
	}
	s := kubetest.New(t)
	s.Put(object("apps/v1", "Deployment", "apps", "api", map[string]any{
		"metadata": map[string]any{"creationTimestamp": "2026-09-01T10:00:00Z", "labels": map[string]any{"farcast.sofmon.com/tier": "app"}},
		"spec":     map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "api", "image": "reg.example/api@sha256:abc"}}}}},
		"status":   map[string]any{"readyReplicas": 1},
	}))
	s.Put(object("apps/v1", "Deployment", "apps", "web", map[string]any{
		"spec": map[string]any{"replicas": 0, "template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "web", "image": "reg.example/web@sha256:def"}}}}},
	}))
	got, err := openReader(t, s, nil).Workloads(t.Context(), "apps")
	check(t, got, err)
}

// An empty answer is a namespace with no workloads, not a parse failure. An
// Open'd client refuses no namespace at all before sending anything: kube
// would read it as every namespace.
func TestWorkloadsHandlesAnEmptyAnswer(t *testing.T) {
	s := kubetest.New(t)
	c := openReader(t, s, nil)
	got, err := c.Workloads(t.Context(), "apps")
	if err != nil || len(got) != 0 {
		t.Errorf("an empty namespace = %v, %v; want nothing", got, err)
	}

	empty := kubetest.New(t)
	empty.Put(workloadObject("Deployment", "apps", "api"))
	got, err = openReader(t, empty, nil).Workloads(t.Context(), "")
	if err == nil || got != nil || !strings.Contains(err.Error(), "nothing was sent") {
		t.Errorf("no namespace = %v, %v; want a refusal", got, err)
	}
	if reqs := empty.Requests(); len(reqs) != 0 {
		t.Errorf("no namespace sent %d requests", len(reqs))
	}
}

// FarCast runs Deployments and StatefulSets — the key holder is the latter —
// so a listing must ask for both, and must carry back which is which. The
// Phase 4.3 walk found `farcast ps --all` silently omitting storage.
func TestWorkloadsAsksForBothKindsAndKeepsThem(t *testing.T) {
	kindsOf := func(got []Workload) map[string]string {
		kinds := map[string]string{}
		for _, w := range got {
			kinds[w.Name] = w.Kind
		}
		return kinds
	}
	s := kubetest.New(t)
	s.Put(workloadObject("Deployment", "farcast-system", "fatline"))
	s.Put(workloadObject("StatefulSet", "farcast-system", "datasphered"))
	c := openReader(t, s, nil)
	got, err := c.Workloads(t.Context(), "farcast-system")
	if err != nil {
		t.Fatal(err)
	}
	if k := kindsOf(got); k["datasphered"] != "StatefulSet" || k["fatline"] != "Deployment" || len(got) != 2 || got[0].Name != "fatline" {
		t.Errorf("workloads = %+v; Deployments first, each with its own kind", got)
	}
	// The request itself: asking only for deployments is how storage
	// vanished. Each kind is its own paged list.
	reqs := apiRequests(s)
	if len(reqs) != 2 {
		t.Fatalf("requests = %v, want two lists", apiPaths(s))
	}
	for i, path := range []string{"/apis/apps/v1/namespaces/farcast-system/deployments", "/apis/apps/v1/namespaces/farcast-system/statefulsets"} {
		if reqs[i].Path != path || reqs[i].RawQuery != "limit=500" || reqs[i].As != "reader" {
			t.Errorf("request %d = %s?%s as %q, want %s?limit=500", i, reqs[i].Path, reqs[i].RawQuery, reqs[i].As, path)
		}
	}

	// The kind comes from the list, never from an item: one that names
	// another kind, or none, is stamped by the list it came in.
	s.Script("/apis/apps/v1/namespaces/farcast-system/deployments",
		[]byte(`{"items":[{"kind":"StatefulSet","metadata":{"name":"liar"}}]}`))
	s.Script("/apis/apps/v1/namespaces/farcast-system/statefulsets",
		[]byte(`{"items":[{"kind":"Deployment","metadata":{"name":"keys"}},{"metadata":{"name":"bare"}}]}`))
	got, err = c.Workloads(t.Context(), "farcast-system")
	if err != nil {
		t.Fatal(err)
	}
	if k := kindsOf(got); k["liar"] != "Deployment" || k["keys"] != "StatefulSet" || k["bare"] != "StatefulSet" {
		t.Errorf("kinds = %v; each must be its list's", k)
	}
	if got[0].Namespace != "farcast-system" {
		t.Errorf("an item without a namespace = %q, want the namespace asked for", got[0].Namespace)
	}
}

// The keys FarCast stores contain dots, and jsonpath reads a dot as a path
// separator — which is why this reads JSON. A jsonpath asking for
// {.data.checkpoint.json} returns empty rather than failing, and empty reads
// as "the kernel has never checkpointed".
func TestConfigMapValueReadsADottedKey(t *testing.T) {
	check := func(t *testing.T, got string, found bool, err error) {
		t.Helper()
		if err != nil || !found || got != `{"version":1}` {
			t.Errorf("= %q, %v, %v", got, found, err)
		}
	}
	s := kubetest.New(t)
	s.Put(object("v1", "ConfigMap", "farcast-system", "technocore-ledger", map[string]any{"data": map[string]any{"checkpoint.json": `{"version":1}`}}))
	got, found, err := openReader(t, s, nil).ConfigMapValue(t.Context(), "farcast-system", "technocore-ledger", "checkpoint.json")
	check(t, got, found, err)
	if p := apiPaths(s); !slices.Equal(p, []string{"GET /api/v1/namespaces/farcast-system/configmaps/technocore-ledger"}) {
		t.Errorf("requests = %v", p)
	}
}

func TestConfigMapValueDistinguishesMissingFromEmpty(t *testing.T) {
	s := kubetest.New(t)
	c := openReader(t, s, nil)
	ctx := t.Context()
	if v, found, err := c.ConfigMapValue(ctx, "ns", "name", "key"); v != "" || found || err != nil {
		t.Errorf("absent = %q, %v, %v; want not found and no error", v, found, err)
	}
	s.Put(object("v1", "ConfigMap", "ns", "name", map[string]any{"data": map[string]any{"other": "x", "blank": ""}}))
	if _, found, err := c.ConfigMapValue(ctx, "ns", "name", "key"); !found || err == nil {
		t.Errorf("present without the key = found %v, %v; want found and an error", found, err)
	}
	if v, found, err := c.ConfigMapValue(ctx, "ns", "name", "blank"); v != "" || !found || err != nil {
		t.Errorf("an empty value = %q, %v, %v; want found, empty", v, found, err)
	}
}

// ADR 0023 M2.4, mutation 62: a ConfigMap is absent only when the API server
// says so, with a 404 whose body is a Kubernetes Status. A 403, whether RBAC's
// Status or the endpoint's own refusal, a 404 that is not a Status, and any
// other failure are errors with found false: never read as absent, which
// 'world' and 'costs' would show as "never checkpointed".
func TestConfigMapForbiddenIsNeverAbsent(t *testing.T) {
	const path = "/api/v1/namespaces/farcast-system/configmaps/technocore-ledger"
	google := kube.Status{Status: tkube.Status{Kind: "GoogleError"}}
	s := kubetest.New(t)
	s.Put(object("v1", "ConfigMap", "farcast-system", "technocore-ledger", map[string]any{
		"metadata": map[string]any{"resourceVersion": "9"}, "data": map[string]any{"checkpoint.json": "{}"},
	}))
	c := openReader(t, s, nil)
	ctx := t.Context()
	for _, row := range []struct {
		name string
		code int
		st   kube.Status
		is   error
	}{
		{"an RBAC 403", http.StatusForbidden, kube.Status{}, tkube.ErrForbidden},
		{"the endpoint's 403", http.StatusForbidden, google, tkube.ErrForbidden},
		{"a 404 that is not a Status", http.StatusNotFound, google, tkube.ErrNotFound},
		{"a 500", http.StatusInternalServerError, kube.Status{}, nil},
	} {
		s.Fail(http.MethodGet, path, row.code, row.st)
		v, found, err := c.ConfigMapValue(ctx, "farcast-system", "technocore-ledger", "checkpoint.json")
		if err == nil || found || v != "" || (row.is != nil && !errors.Is(err, row.is)) {
			t.Errorf("ConfigMapValue, %s = %q, %v, %v; want an error, not found", row.name, v, found, err)
		}
		s.Fail(http.MethodGet, path, row.code, row.st)
		data, rv, found, err := c.ConfigMapData(ctx, "farcast-system", "technocore-ledger")
		if err == nil || found || data != nil || rv != "" || (row.is != nil && !errors.Is(err, row.is)) {
			t.Errorf("ConfigMapData, %s = %v, %q, %v, %v; want an error, not found", row.name, data, rv, found, err)
		}
	}
	// The one absent answer: the API server's own 404 Status.
	if v, found, err := c.ConfigMapValue(ctx, "farcast-system", "absent", "k"); v != "" || found || err != nil {
		t.Errorf("a 404 Status = %q, %v, %v; want absent", v, found, err)
	}
	if _, _, found, err := c.ConfigMapData(ctx, "farcast-system", "absent"); found || err != nil {
		t.Errorf("ConfigMapData, a 404 Status = %v, %v; want absent", found, err)
	}
}

func TestConfigMapDataCarriesTheVersionItWasReadAt(t *testing.T) {
	const path = "/api/v1/namespaces/farcast-system/configmaps/datasphered-pin"
	s := kubetest.New(t)
	s.Put(object("v1", "ConfigMap", "farcast-system", "datasphered-pin", map[string]any{
		"metadata": map[string]any{"resourceVersion": "42"}, "data": map[string]any{"pin": "x"},
	}))
	c := openReader(t, s, nil)
	ctx := t.Context()
	data, rv, found, err := c.ConfigMapData(ctx, "farcast-system", "datasphered-pin")
	if err != nil || !found || rv != "42" || data["pin"] != "x" {
		t.Fatalf("= %v, %q, %v, %v", data, rv, found, err)
	}
	if p := apiPaths(s); !slices.Equal(p, []string{"GET " + path}) {
		t.Errorf("requests = %v", p)
	}
	if _, _, found, err := c.ConfigMapData(ctx, "ns", "name"); found || err != nil {
		t.Errorf("an absent ConfigMap = found %v, %v", found, err)
	}
	// Without a version there is nothing to compare a replace against, and
	// a replace without one is last-writer-wins.
	s.Script(path, object("v1", "ConfigMap", "farcast-system", "datasphered-pin", map[string]any{"data": map[string]any{"pin": "x"}}))
	if _, _, found, err := c.ConfigMapData(ctx, "farcast-system", "datasphered-pin"); found || err == nil ||
		err.Error() != "cluster: farcast-system/datasphered-pin carries no resourceVersion" {
		t.Errorf("no resourceVersion = found %v, %v", found, err)
	}
}

// pinPath is the storage key pin's ConfigMap, as dsdeploy.RenderPin names it.
const pinPath = "/api/v1/namespaces/farcast-system/configmaps/datasphered-pin"

// renderPin is the storage key pin's ConfigMap as the writing commands render
// it (dsdeploy.RenderPin), holding value, at resourceVersion rv ("" for none).
func renderPin(t *testing.T, value, rv string) []byte {
	t.Helper()
	b, err := dsdeploy.RenderPin(dsdeploy.DefaultNamespace, dsdeploy.DefaultName, value, rv)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// writeRequests is every request s saw that is neither a read nor the token's.
func writeRequests(s *kubetest.Server) []kubetest.Request {
	var out []kubetest.Request
	for _, r := range apiRequests(s) {
		if r.Method != http.MethodGet {
			out = append(out, r)
		}
	}
	return out
}

// ADR 0023 M2.5 (A20-7), mutation 70: create never overwrites and replace is
// refused on a stale version: neither is apply, which is last-writer-wins and
// could move the pin backwards. A writer creates the pin with a POST and
// replaces it with a PUT, in-process as the writer, each sending the body it
// was given byte for byte under farcast's field manager and strict field
// validation; a create over a pin that exists is AlreadyExists, a conflict.
// Nothing is patched or applied, and no kubectl runs.
func TestConfigMapWritesNeverApply(t *testing.T) {
	bin, saw := recordingKubectl(t)
	t.Setenv("PATH", bin)
	s := kubetest.New(t)
	c := openWriter(t, s, "/cfg/instances/atlas/kubeconfig.yaml", nil)
	ctx := t.Context()

	created := renderPin(t, `{"pin":1}`, "")
	if err := c.CreateConfigMap(ctx, created); err != nil {
		t.Fatal(err)
	}
	_, rv, found, err := c.ConfigMapData(ctx, dsdeploy.DefaultNamespace, dsdeploy.PinConfigMapName(""))
	if err != nil || !found {
		t.Fatalf("reading the created pin = %v, %v", found, err)
	}
	replaced := renderPin(t, `{"pin":2}`, rv)
	if err := c.ReplaceConfigMap(ctx, replaced); err != nil {
		t.Fatal(err)
	}
	err = c.CreateConfigMap(ctx, created)
	var ae *kube.APIError
	if !errors.Is(err, tkube.ErrConflict) || !errors.As(err, &ae) || ae.Status.Reason != "AlreadyExists" {
		t.Errorf("a create over the pin = %v; want AlreadyExists, unwrapping to tkube.ErrConflict", err)
	}
	if v, _, err := c.ConfigMapValue(ctx, dsdeploy.DefaultNamespace, dsdeploy.PinConfigMapName(""), dsdeploy.PinKey); v != `{"pin":2}` || err != nil {
		t.Errorf("the pin after the refused create = %q, %v; want the replaced value", v, err)
	}

	writes := writeRequests(s)
	if len(writes) != 3 {
		t.Fatalf("%d writes, want a POST, a PUT and the refused POST: %v", len(writes), apiPaths(s))
	}
	for i, want := range []struct {
		method, path string
		body         []byte
	}{
		{http.MethodPost, "/api/v1/namespaces/farcast-system/configmaps", created},
		{http.MethodPut, pinPath, replaced},
		{http.MethodPost, "/api/v1/namespaces/farcast-system/configmaps", created},
	} {
		r := writes[i]
		if r.Method != want.method || r.Path != want.path || r.RawQuery != "fieldManager=farcast&fieldValidation=Strict" ||
			r.ContentType != "application/json" || r.As != "writer" {
			t.Errorf("write %d = %s %s?%s (%s) as %q; want %s %s?fieldManager=farcast&fieldValidation=Strict (application/json) as the writer",
				i, r.Method, r.Path, r.RawQuery, r.ContentType, r.As, want.method, want.path)
		}
		if !bytes.Equal(r.Body, want.body) {
			t.Errorf("write %d sent %q, want the body it was given, %q", i, r.Body, want.body)
		}
	}
	for _, r := range apiRequests(s) {
		if r.Method == http.MethodPatch || strings.Contains(r.ContentType, "apply-patch") {
			t.Errorf("%s %s (%s): the pin is never patched or applied", r.Method, r.Path, r.ContentType)
		}
	}
	if _, _, ran := kubectlRecord(t, saw); ran {
		t.Error("a writer's ConfigMap write ran kubectl")
	}
}

// ADR 0023 M2.5 (A20-7), mutation 71: a writer's replace is guarded on the
// resourceVersion that was read. The PUT carries it, byte for byte as the
// body was given; a replace at a version that is no longer current is a
// conflict and leaves the pin as it was; and a body that names no version is
// refused before anything is sent, because a replace without one is
// last-writer-wins.
func TestReplaceConfigMapCarriesTheResourceVersion(t *testing.T) {
	s := kubetest.New(t)
	s.Put(object("v1", "ConfigMap", "farcast-system", "datasphered-pin", map[string]any{
		"metadata": map[string]any{"resourceVersion": "41"}, "data": map[string]any{"pin": `{"pin":1}`},
	}))
	c := openWriter(t, s, "", nil)
	ctx := t.Context()
	_, rv, found, err := c.ConfigMapData(ctx, dsdeploy.DefaultNamespace, dsdeploy.PinConfigMapName(""))
	if err != nil || !found || rv != "41" {
		t.Fatalf("the pin was read at %q (%v, %v), want 41", rv, found, err)
	}

	body := renderPin(t, `{"pin":2}`, rv)
	if err := c.ReplaceConfigMap(ctx, body); err != nil {
		t.Fatal(err)
	}
	writes := writeRequests(s)
	if len(writes) != 1 || writes[0].Method != http.MethodPut || writes[0].Path != pinPath || !bytes.Equal(writes[0].Body, body) {
		t.Fatalf("writes = %d (%v); want one PUT of the body as given", len(writes), apiPaths(s))
	}
	var sent struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(writes[0].Body, &sent); err != nil || sent.Metadata.ResourceVersion != rv ||
		!bytes.Contains(writes[0].Body, []byte(`"resourceVersion":"41"`)) {
		t.Errorf("the PUT carried the resourceVersion %q (%v), want the one read, %q", sent.Metadata.ResourceVersion, err, rv)
	}

	// The replace moved the pin on, so the version read is stale now.
	err = c.ReplaceConfigMap(ctx, renderPin(t, `{"pin":3}`, rv))
	if !errors.Is(err, tkube.ErrConflict) {
		t.Errorf("a replace at a stale resourceVersion = %v, want tkube.ErrConflict", err)
	}
	if v, _, err := c.ConfigMapValue(ctx, dsdeploy.DefaultNamespace, dsdeploy.PinConfigMapName(""), dsdeploy.PinKey); v != `{"pin":2}` || err != nil {
		t.Errorf("the pin after a stale replace = %q, %v; want it unchanged", v, err)
	}

	before := len(s.Requests())
	err = c.ReplaceConfigMap(ctx, renderPin(t, `{"pin":4}`, ""))
	if !errors.Is(err, kube.ErrRefusedDocument) {
		t.Errorf("a replace that names no resourceVersion = %v, want kube.ErrRefusedDocument", err)
	}
	if got := len(s.Requests()); got != before {
		t.Errorf("a replace with no resourceVersion sent %d requests; it sends nothing", got-before)
	}
}

// ADR 0023 M2.5 (A20-4): NamespaceUID is one namespace's uid, read with the
// list verb and a field selector, "" for a namespace that does not exist, and
// an error, never "", for a refused read. Each answer's warnings are written
// after it. The reader reads it too: a plan binds farcast-system's uid.
func TestNamespaceUIDIsThatNamespacesUID(t *testing.T) {
	var n atomic.Int32
	s := kubetest.New(t, kubetest.WithWarnings(func(r kubetest.Request) []string {
		if r.Path == "/api/v1/namespaces" {
			return []string{fmt.Sprintf("read %d", n.Add(1))}
		}
		return nil
	}))
	s.Put(object("v1", "Namespace", "", "farcast-system", map[string]any{"metadata": map[string]any{"uid": "uid-of-farcast-system"}}))
	s.Put(namespace("web", nil))
	var w bytes.Buffer
	c := openWriter(t, s, "", &w)
	ctx := t.Context()

	if uid, err := c.NamespaceUID(ctx, "farcast-system"); uid != "uid-of-farcast-system" || err != nil {
		t.Errorf("farcast-system's uid = %q, %v", uid, err)
	}
	if got := w.String(); got != "Warning (cluster): read 1\n" {
		t.Errorf("after the read, warnings = %q", got)
	}
	if uid, err := c.NamespaceUID(ctx, "absent"); uid != "" || err != nil {
		t.Errorf("an absent namespace's uid = %q, %v; want \"\" and no error", uid, err)
	}
	s.Fail(http.MethodGet, "/api/v1/namespaces", http.StatusForbidden, kube.Status{})
	if uid, err := c.NamespaceUID(ctx, "farcast-system"); uid != "" || !errors.Is(err, tkube.ErrForbidden) {
		t.Errorf("a refused read = %q, %v; want an error that unwraps to tkube.ErrForbidden", uid, err)
	}
	if got := w.String(); got != "Warning (cluster): read 1\nWarning (cluster): read 2\nWarning (cluster): read 3\n" {
		t.Errorf("after an absent and a refused read, warnings = %q", got)
	}
	reqs := apiRequests(s)
	if len(reqs) != 3 {
		t.Fatalf("%d requests, want three reads: %v", len(reqs), apiPaths(s))
	}
	for i, name := range []string{"farcast-system", "absent", "farcast-system"} {
		q, err := url.ParseQuery(reqs[i].RawQuery)
		if err != nil {
			t.Fatal(err)
		}
		if r := reqs[i]; r.Method != http.MethodGet || r.Path != "/api/v1/namespaces" || r.As != "writer" || q.Get("fieldSelector") != "metadata.name="+name {
			t.Errorf("read %d = %s %s?%s as %q; want a list of %s alone, as the writer", i, r.Method, r.Path, r.RawQuery, r.As, name)
		}
	}

	if uid, err := openReader(t, s, nil).NamespaceUID(ctx, "farcast-system"); uid != "uid-of-farcast-system" || err != nil {
		t.Errorf("as the reader, farcast-system's uid = %q, %v", uid, err)
	}
}

// Namespaces lists every namespace, with no selector, paged and sorted.
func TestNamespacesListsEveryNamespace(t *testing.T) {
	s := kubetest.New(t)
	for _, ns := range []string{"web", "kube-system", "api"} {
		s.Put(namespace(ns, nil))
	}
	got, err := openReader(t, s, nil).Namespaces(t.Context())
	if err != nil || !slices.Equal(got, []string{"api", "kube-system", "web"}) {
		t.Errorf("= %q, %v", got, err)
	}
	reqs := apiRequests(s)
	if len(reqs) != 1 || reqs[0].Path != "/api/v1/namespaces" || reqs[0].RawQuery != "limit=500" {
		t.Errorf("requests = %v; want one list with no selector", apiPaths(s))
	}
}

// logServer serves the Deployment apps/api and the StatefulSet apps/keys, and
// the pods given.
func logServer(t *testing.T, opts []kubetest.Option, pods ...map[string]any) *kubetest.Server {
	t.Helper()
	s := kubetest.New(t, opts...)
	s.Put(workloadObject("Deployment", "apps", "api"))
	s.Put(workloadObject("StatefulSet", "apps", "keys"))
	for _, p := range pods {
		s.Put(p)
	}
	return s
}

// followUntil runs a followed Logs until done says the output is complete,
// then cancels it as an operator's Ctrl-C would, and returns what Logs
// returned.
func followUntil(t *testing.T, c *Client, out io.Writer, target string, lines int, previous bool, done func() bool) error {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- c.Logs(ctx, out, "apps", target, lines, true, previous) }()
	waitFor(t, "the followed logs", func() bool {
		select {
		case err := <-result:
			result <- err
			return true
		default:
		}
		return done()
	})
	cancel()
	select {
	case err := <-result:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("a cancelled follow did not return")
	}
	return nil
}

// Logs reads the pod kubectl logs would choose, by the workload's own
// selector, and every container of it in a fixed order: init, then main, then
// ephemeral. lines is passed as it is, a negative one as everything. Without
// follow the containers are read one after another; a target that is not a
// Deployment or a StatefulSet, a selector farcast cannot read, a workload with
// no pod, and more containers than farcast follows at once are refused.
func TestLogsBuildsTheRightCall(t *testing.T) {
	api1 := map[string]string{
		kubetest.LogAnnotationPrefix + "app":         "log line\n",
		kubetest.PreviousLogAnnotationPrefix + "app": "before\n",
	}
	for _, row := range []struct {
		name                     string
		lines                    int
		follow, previous         bool
		tail                     string // "" is no tailLines at all
		out                      string
		wantFollow, wantPrevious bool
	}{
		{name: "a plain read", lines: 200, tail: "200", out: "log line\n"},
		{name: "after a crash", lines: 50, previous: true, tail: "50", out: "before\n", wantPrevious: true},
		{name: "following", lines: 10, follow: true, tail: "10", out: "log line\n", wantFollow: true},
		{name: "every line", lines: -1, out: "log line\n"},
		{name: "no lines", lines: 0, tail: "0", out: ""},
	} {
		t.Run(row.name, func(t *testing.T) {
			s := logServer(t, nil, podObject("apps", "api-1", map[string]string{"app": "api"}, []string{"app"}, api1))
			c := openReader(t, s, nil)
			var out safeBuffer
			var err error
			if row.follow {
				err = followUntil(t, c, &out, "deployment/api", row.lines, row.previous, func() bool { return out.String() == row.out })
			} else {
				err = c.Logs(t.Context(), &out, "apps", "deployment/api", row.lines, false, row.previous)
			}
			if err != nil || out.String() != row.out {
				t.Fatalf("= %q, %v; want %q", out.String(), err, row.out)
			}
			want := []string{
				"GET /apis/apps/v1/namespaces/apps/deployments/api",
				"GET /api/v1/namespaces/apps/pods",
				"GET /api/v1/namespaces/apps/pods/api-1/log",
			}
			if got := apiPaths(s); !slices.Equal(got, want) {
				t.Errorf("requests = %v, want %v", got, want)
			}
			if r := apiRequests(s)[1]; r.RawQuery != "labelSelector=app%3Dapi&limit=500" {
				t.Errorf("the pods were listed with %q", r.RawQuery)
			}
			q := logQueries(t, s)[0]
			if q.Get("container") != "app" || q.Has("tailLines") != (row.tail != "") || q.Get("tailLines") != row.tail ||
				(q.Get("follow") == "true") != row.wantFollow || (q.Get("previous") == "true") != row.wantPrevious {
				t.Errorf("the log request asked %v", q)
			}
		})
	}

	t.Run("a StatefulSet, every container in order", func(t *testing.T) {
		ann := map[string]string{}
		for _, c := range []string{"setup", "keys", "side", "debug"} {
			ann[kubetest.LogAnnotationPrefix+c] = c + " says hi\n"
		}
		s := logServer(t, nil, podObject("apps", "keys-0", map[string]string{"app": "keys"},
			[]string{"eph:debug", "keys", "init:setup", "side"}, ann))
		var out bytes.Buffer
		if err := openReader(t, s, nil).Logs(t.Context(), &out, "apps", "statefulset/keys", -1, false, false); err != nil {
			t.Fatal(err)
		}
		if want := "setup says hi\nkeys says hi\nside says hi\ndebug says hi\n"; out.String() != want {
			t.Errorf("out = %q, want %q", out.String(), want)
		}
		var order []string
		for _, q := range logQueries(t, s) {
			order = append(order, q.Get("container"))
		}
		if want := []string{"setup", "keys", "side", "debug"}; !slices.Equal(order, want) {
			t.Errorf("containers read in the order %v, want init, then main, then ephemeral: %v", order, want)
		}
		if p := apiPaths(s); p[0] != "GET /apis/apps/v1/namespaces/apps/statefulsets/keys" {
			t.Errorf("requests = %v", p)
		}
	})

	t.Run("refusals", func(t *testing.T) {
		six := []string{"init:a", "b", "c", "d", "e", "eph:f"}
		s := logServer(t, nil, podObject("apps", "keys-0", map[string]string{"app": "keys"}, six, nil))
		expr := workloadObject("Deployment", "apps", "expr")
		expr["spec"].(map[string]any)["selector"] = map[string]any{
			"matchExpressions": []any{map[string]any{"key": "app", "operator": "Exists"}},
		}
		s.Put(expr)
		c := openReader(t, s, nil)
		var out bytes.Buffer
		for _, row := range []struct {
			target string
			follow bool
			want   string
		}{
			{"job/fetch", false, `cluster: the log target "job/fetch" is neither deployment/<name> nor statefulset/<name>`},
			{"deployment/expr", false, "the Deployment apps/expr selects its pods with matchExpressions, which farcast does not read"},
			{"deployment/api", false, "no pod of apps/api is running yet"},
			{"statefulset/keys", true, "following 6 containers at once is more than farcast follows (5)"},
		} {
			if err := c.Logs(t.Context(), &out, "apps", row.target, 10, row.follow, false); err == nil || err.Error() != row.want {
				t.Errorf("%s: %v, want %q", row.target, err, row.want)
			}
		}
		if out.Len() != 0 || len(logQueries(t, s)) != 0 {
			t.Errorf("the refusals wrote %q and sent %d log requests", out.String(), len(logQueries(t, s)))
		}
	})
}

// With follow, a cancelled context is the operator stopping the follow: Logs
// returns nil, and what was read is all on out. The first failure that is
// not the context's ends the other streams and is returned.
func TestLogsFollowStopsOnCancelWithoutError(t *testing.T) {
	pod := podObject("apps", "api-1", map[string]string{"app": "api"}, []string{"init:setup", "app"}, map[string]string{
		kubetest.LogAnnotationPrefix + "setup": "migrated\n",
		kubetest.LogAnnotationPrefix + "app":   "listening\nserving\n",
	})
	s := logServer(t, nil, pod)
	c := openReader(t, s, nil)
	var out safeBuffer
	// The two containers' lines may come in any order between them, each
	// container's own in its order.
	err := followUntil(t, c, &out, "deployment/api", -1, false, func() bool {
		o := out.String()
		return strings.Contains(o, "migrated\n") && strings.Contains(o, "serving\n")
	})
	if err != nil {
		t.Errorf("a cancelled follow = %v, want nil", err)
	}
	o := out.String()
	if len(o) != len("migrated\nlistening\nserving\n") || !strings.Contains(o, "migrated\n") ||
		strings.Index(o, "listening\n") > strings.Index(o, "serving\n") {
		t.Errorf("out = %q", o)
	}

	t.Run("a failing stream ends the others", func(t *testing.T) {
		s := logServer(t, nil, pod)
		s.Fail(http.MethodGet, "/api/v1/namespaces/apps/pods/api-1/log", http.StatusNotFound, kube.Status{})
		c := openReader(t, s, nil)
		result := make(chan error, 1)
		go func() { result <- c.Logs(t.Context(), io.Discard, "apps", "deployment/api", -1, true, false) }()
		select {
		case err := <-result:
			if !errors.Is(err, tkube.ErrNotFound) {
				t.Errorf("= %v, want the failed stream's 404", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("one stream failed and Logs kept following the other")
		}
	})
}

// failWriter fails every write.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("the pipe is closed") }

// ADR 0023 M2.4 (A18-4): with follow, each container's stream reaches out a
// whole line at a time, so lines of containers followed at once never mix
// within a line; a line held without its end is written in 32 KiB pieces, and
// what a stream leaves unfinished is written when it ends.
func TestFollowedLogsInterleaveWholeLines(t *testing.T) {
	t.Run("the writer", func(t *testing.T) {
		var mu sync.Mutex
		var out bytes.Buffer
		a, b := &lineWriter{mu: &mu, out: &out}, &lineWriter{mu: &mu, out: &out}
		write := func(w *lineWriter, s string) {
			t.Helper()
			if n, err := w.Write([]byte(s)); n != len(s) || err != nil {
				t.Fatalf("Write(%d bytes) = %d, %v", len(s), n, err)
			}
		}
		write(a, "a1-")
		write(b, "b1\nb2-")
		write(a, "end\na2")
		write(b, "end\n")
		if got, want := out.String(), "b1\na1-end\nb2-end\n"; got != want {
			t.Errorf("out = %q, want %q", got, want)
		}
		if err := a.flush(); err != nil {
			t.Fatal(err)
		}
		if err := a.flush(); err != nil || !strings.HasSuffix(out.String(), "b2-end\na2") {
			t.Errorf("after flushing twice: %q, %v; want the unfinished line once", out.String(), err)
		}

		out.Reset()
		write(a, strings.Repeat("x", 40<<10))
		if out.String() != strings.Repeat("x", 32<<10) {
			t.Errorf("40 KiB of one line wrote %d bytes; want a 32 KiB piece", out.Len())
		}
		write(b, "b\n")
		write(a, "y\n")
		if want := strings.Repeat("x", 32<<10) + "b\n" + strings.Repeat("x", 8<<10) + "y\n"; out.String() != want {
			t.Errorf("a long line and another container's line came out as %d bytes, not its pieces around the other line", out.Len())
		}
		write(a, strings.Repeat("z", 32<<10))
		if !strings.HasSuffix(out.String(), "y\n"+strings.Repeat("z", 32<<10)) {
			t.Error("exactly 32 KiB of a line was held back")
		}

		broken := &lineWriter{mu: &mu, out: failWriter{}}
		if _, err := broken.Write([]byte("x\n")); err == nil {
			t.Error("a failing out was not reported by Write")
		}
		unfinished := &lineWriter{mu: &mu, out: failWriter{}}
		if _, err := unfinished.Write([]byte("partial")); err != nil {
			t.Fatal(err)
		}
		if err := unfinished.flush(); err == nil {
			t.Error("a failing out was not reported by flush")
		}
	})

	t.Run("through Logs", func(t *testing.T) {
		s := logServer(t, nil, podObject("apps", "api-1", map[string]string{"app": "api"}, []string{"a", "b"}, map[string]string{
			kubetest.LogAnnotationPrefix + "a": "a1\na2-unfinished",
			kubetest.LogAnnotationPrefix + "b": "b1\n",
		}))
		c := openReader(t, s, nil)
		var out safeBuffer
		err := followUntil(t, c, &out, "deployment/api", -1, false, func() bool {
			o := out.String()
			if !strings.Contains(o, "a1\n") || !strings.Contains(o, "b1\n") {
				return false
			}
			// Both whole lines are out. The unfinished one is held until its
			// stream ends, however long the stream lasts.
			time.Sleep(150 * time.Millisecond)
			if strings.Contains(out.String(), "a2") {
				t.Errorf("an unfinished line reached out while its stream ran: %q", out.String())
			}
			return true
		})
		if err != nil {
			t.Fatal(err)
		}
		o := out.String()
		if !strings.HasSuffix(o, "a2-unfinished") || len(o) != len("a1\nb1\na2-unfinished") {
			t.Errorf("out = %q; want both whole lines, then the unfinished one when its stream ended", o)
		}
	})
}

// ADR 0023 M2.4, mutation 68: a container with no previous instance is a note
// on the warnings writer, after the reads' own warnings, and never on out,
// which carries the application's own bytes; a name that would not print is
// quoted. Only the API server's 400 Status to a previous=true request is that
// note: any other failure stops Logs.
func TestPreviousNoteGoesToWarningsNotOut(t *testing.T) {
	const logPath = "/api/v1/namespaces/apps/pods/api-1/log"
	pod := podObject("apps", "api-1", map[string]string{"app": "api"}, []string{"app", "side\u202ecar"}, map[string]string{
		kubetest.PreviousLogAnnotationPrefix + "app": "before the crash\n",
	})
	warn := kubetest.WithWarnings(func(r kubetest.Request) []string {
		if r.Path == "/apis/apps/v1/namespaces/apps/deployments/api" {
			return []string{"w1"}
		}
		return nil
	})
	const note = "api-1/\"side\\u202ecar\": no previous instance\n"

	s := logServer(t, []kubetest.Option{warn}, pod)
	var out, warnings safeBuffer
	c := openReader(t, s, &warnings)
	if err := c.Logs(t.Context(), &out, "apps", "deployment/api", -1, false, true); err != nil {
		t.Fatal(err)
	}
	if out.String() != "before the crash\n" {
		t.Errorf("out = %q, want the previous log alone", out.String())
	}
	if got, want := warnings.String(), "Warning (cluster): w1\n"+note; got != want {
		t.Errorf("warnings = %q, want %q", got, want)
	}

	// Followed, the same.
	var fout, fwarn safeBuffer
	fc := openReader(t, logServer(t, nil, pod), &fwarn)
	if err := followUntil(t, fc, &fout, "deployment/api", -1, true, func() bool {
		return fout.String() == "before the crash\n" && fwarn.String() == note
	}); err != nil {
		t.Errorf("a followed previous read = %v", err)
	}
	if fout.String() != "before the crash\n" || fwarn.String() != note {
		t.Errorf("followed: out %q, warnings %q", fout.String(), fwarn.String())
	}

	// A nil warnings writer drops the note, and the read still succeeds.
	var nout bytes.Buffer
	if err := openReader(t, logServer(t, nil, pod), nil).Logs(t.Context(), &nout, "apps", "deployment/api", -1, false, true); err != nil || nout.String() != "before the crash\n" {
		t.Errorf("with no warnings writer: %q, %v", nout.String(), err)
	}

	for _, row := range []struct {
		name     string
		code     int
		st       kube.Status
		previous bool
	}{
		{"a 400 to a request for the current log", http.StatusBadRequest, kube.Status{}, false},
		{"a 400 that is not a Status", http.StatusBadRequest, kube.Status{Status: tkube.Status{Kind: "GoogleError"}}, true},
		{"a 500", http.StatusInternalServerError, kube.Status{}, true},
	} {
		s := logServer(t, nil, pod)
		s.Fail(http.MethodGet, logPath, row.code, row.st)
		var out, warnings safeBuffer
		err := openReader(t, s, &warnings).Logs(t.Context(), &out, "apps", "deployment/api", -1, false, row.previous)
		if err == nil || strings.Contains(warnings.String(), "no previous instance") || out.Len() != 0 {
			t.Errorf("%s: %v, out %q, warnings %q; want the error and no note", row.name, err, out.String(), warnings.String())
		}
	}
}

func (s *safeBuffer) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Len()
}

// A18-4, mutation O19: the warnings of the reads that find the pod, the
// workload's GET and the pod list, are written before any log, not after
// the streams. With one writer for both, as a terminal shares stdout and
// stderr, the warning comes first, unfollowed and followed: a follow would
// otherwise hold it back until the operator stops it. A GET that fails still
// writes its warning before Logs returns.
func TestLogWarningsComeBeforeTheLog(t *testing.T) {
	pod := podObject("apps", "api-1", map[string]string{"app": "api"}, []string{"app"}, map[string]string{
		kubetest.LogAnnotationPrefix + "app": "log line\n",
	})
	for _, path := range []string{"/apis/apps/v1/namespaces/apps/deployments/api", "/api/v1/namespaces/apps/pods"} {
		warn := kubetest.WithWarnings(func(r kubetest.Request) []string {
			if r.Path == path {
				return []string{"w1"}
			}
			return nil
		})
		const want = "Warning (cluster): w1\nlog line\n"
		var both safeBuffer
		if err := openReader(t, logServer(t, []kubetest.Option{warn}, pod), &both).Logs(t.Context(), &both, "apps", "deployment/api", -1, false, false); err != nil {
			t.Fatal(err)
		}
		if got := both.String(); got != want {
			t.Errorf("a warning on %s: %q, want %q", path, got, want)
		}

		var fboth safeBuffer
		fc := openReader(t, logServer(t, []kubetest.Option{warn}, pod), &fboth)
		if err := followUntil(t, fc, &fboth, "deployment/api", -1, false, func() bool {
			return strings.Contains(fboth.String(), "log line\n")
		}); err != nil {
			t.Fatal(err)
		}
		if got := fboth.String(); got != want {
			t.Errorf("followed, a warning on %s: %q, want %q", path, got, want)
		}
	}

	for _, target := range []string{"deployment/missing", "statefulset/missing"} {
		resource, _, _ := strings.Cut(target, "/")
		path := "/apis/apps/v1/namespaces/apps/" + resource + "s/missing"
		warn := kubetest.WithWarnings(func(r kubetest.Request) []string {
			if r.Path == path {
				return []string{"w1"}
			}
			return nil
		})
		var both safeBuffer
		err := openReader(t, logServer(t, []kubetest.Option{warn}, pod), &both).Logs(t.Context(), &both, "apps", target, -1, false, false)
		if err == nil {
			t.Errorf("%s: Logs read a workload that does not exist", target)
		}
		if got, want := both.String(), "Warning (cluster): w1\n"; got != want {
			t.Errorf("%s, whose GET failed: %q, want %q", target, got, want)
		}
	}
}
