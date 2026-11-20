package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
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
	"github.com/sofmon/farcast/technocore/kernel"
	tkube "github.com/sofmon/farcast/technocore/kube"
)

// The read tests below run each method in-process, on an Open'd reader
// against kubetest (ADR 0023 M2.4); the writes, on an Open'd writer (M2.5),
// Apply among them since ADR 0023 M2.7. No method runs kubectl.

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

// stream is three documents as farcast's renderers write them: a Namespace,
// then a ConfigMap and a ServiceAccount in it.
const stream = `apiVersion: v1
kind: Namespace
metadata:
  name: web
  labels:
    app.kubernetes.io/managed-by: farcast
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: settings
  namespace: web
  labels:
    app.kubernetes.io/managed-by: farcast
data:
  mode: "on"
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: api
  namespace: web
  labels:
    app.kubernetes.io/managed-by: farcast
`

// The paths stream's three documents are applied to.
const (
	webPath      = "/api/v1/namespaces/web"
	settingsPath = "/api/v1/namespaces/web/configmaps/settings"
	accountPath  = "/api/v1/namespaces/web/serviceaccounts/api"
)

// appliedRequests is every server-side apply s saw, in order: a PATCH whose
// Content-Type is application/apply-patch+yaml.
func appliedRequests(s *kubetest.Server) []kubetest.Request {
	var out []kubetest.Request
	for _, r := range s.Requests() {
		if r.Method == http.MethodPatch && r.ContentType == "application/apply-patch+yaml" {
			out = append(out, r)
		}
	}
	return out
}

// splitStream is kube.SplitStream of a stream these tests know is valid.
func splitStream(t *testing.T, manifests string) []kube.Document {
	t.Helper()
	docs, err := kube.SplitStream([]byte(manifests))
	if err != nil {
		t.Fatal(err)
	}
	return docs
}

// ADR 0023 M2.7 (A30-27, design §5.3): Apply runs no kubectl. It mints once,
// then sends each document as its own server-side apply, in stream order, as
// the writer: a PATCH to the document's own path, the apply patch media type,
// fieldManager farcast with strict validation, forced, and the document's own
// bytes as the body. Every document is stored.
func TestApplySendsEachDocumentAsServerSideApply(t *testing.T) {
	s := kubetest.New(t)
	c := openWriter(t, s, nil)
	if err := c.Apply(t.Context(), []byte(stream)); err != nil {
		t.Fatal(err)
	}
	reqs := s.Requests()
	docs := splitStream(t, stream)
	if len(reqs) != 1+len(docs) || reqs[0].Path != "/token" || reqs[0].As != "writer" {
		t.Fatalf("%d requests (%v); want one mint as the writer, then one apply per document", len(reqs), apiPaths(s))
	}
	for i, want := range []string{webPath, settingsPath, accountPath} {
		r := reqs[1+i]
		if r.Method != http.MethodPatch || r.Path != want || r.ContentType != "application/apply-patch+yaml" ||
			r.RawQuery != "fieldManager=farcast&fieldValidation=Strict&force=true" || r.As != "writer" {
			t.Errorf("document %d: %s %s?%s (%s) as %q; want PATCH %s?fieldManager=farcast&fieldValidation=Strict&force=true "+
				"(application/apply-patch+yaml) as the writer", i, r.Method, r.Path, r.RawQuery, r.ContentType, r.As, want)
		}
		if !bytes.Equal(r.Body, docs[i].Raw) {
			t.Errorf("document %d sent\n%s\nwant its own bytes\n%s", i, r.Body, docs[i].Raw)
		}
	}
	if v, found, err := c.ConfigMapValue(t.Context(), "web", "settings", "mode"); v != "on" || !found || err != nil {
		t.Errorf("the applied ConfigMap reads %q, %v, %v", v, found, err)
	}
}

// ADR 0023 M2.7 (A30-27, §10.5 row 100c): Apply stops at the first document
// that fails. Its error says how many documents were applied before it and
// names the one that failed, and unwraps to the API's own error; the
// documents after it are never sent, and the one before it stays applied: no
// apply is atomic.
func TestApplyStopsAtTheFirstFailingDocumentAndSaysHowManyWent(t *testing.T) {
	s := kubetest.New(t)
	s.Fail(http.MethodPatch, settingsPath, http.StatusInternalServerError, kube.Status{})
	c := openWriter(t, s, nil)
	err := c.Apply(t.Context(), []byte(stream))
	var ae *kube.APIError
	if !errors.As(err, &ae) || ae.Status.Code != http.StatusInternalServerError {
		t.Fatalf("Apply = %v; want the 500, as a *kube.APIError", err)
	}
	if want := "cluster: 1 of 3 documents were applied before ConfigMap web/settings failed: "; !strings.HasPrefix(err.Error(), want) {
		t.Errorf("Apply = %q; want it to begin %q", err, want)
	}
	var paths []string
	for _, r := range appliedRequests(s) {
		paths = append(paths, r.Path)
	}
	if !slices.Equal(paths, []string{webPath, settingsPath}) {
		t.Errorf("applied %q; want the Namespace, then the ConfigMap that failed, and nothing after it", paths)
	}
	if uid, err := c.NamespaceUID(t.Context(), "web"); uid == "" || err != nil {
		t.Errorf("the Namespace applied before the failure reads %q, %v: an apply is never undone", uid, err)
	}

	// The first document failing: 0 of them went, and it is named by its
	// own kind and name, cluster-scoped without a slash.
	s2 := kubetest.New(t)
	s2.Fail(http.MethodPatch, webPath, http.StatusForbidden, kube.Status{})
	err = openWriter(t, s2, nil).Apply(t.Context(), []byte(stream))
	if want := "cluster: 0 of 3 documents were applied before Namespace web failed: "; err == nil || !strings.HasPrefix(err.Error(), want) ||
		!errors.Is(err, tkube.ErrForbidden) {
		t.Errorf("Apply = %v; want it to begin %q and unwrap to tkube.ErrForbidden", err, want)
	}
	if got := len(appliedRequests(s2)); got != 1 {
		t.Errorf("%d applies sent; want the refused first one alone", got)
	}
}

// ADR 0023 M2.7 (A30-27, §10.5 row 100b): a stream SplitStream refuses, and
// a stream that holds no document, are each refused before anything is sent,
// a token included, and so is any apply by the reader.
func TestApplyRefusesBeforeSendingAnything(t *testing.T) {
	for _, row := range []struct {
		name, stream string
		want         string // the error's text, or its start for SplitStream's own
		whole        bool
	}{
		{"a document that names a resourceVersion", stream + "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: stale\n  namespace: web\n  resourceVersion: \"7\"\n",
			"kube: document 3 (ConfigMap \"stale\") is refused: ", false},
		{"a kind farcast never applies", "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n  namespace: web\n" + "---\n" + stream,
			"kube: document 0 ", false},
		{"no stream", "", "cluster: the stream holds no document, so nothing was sent: kube: a document is not one farcast applies", true},
		{"blanks and comments", "---\n# nothing\n---\n\n", "cluster: the stream holds no document, so nothing was sent: kube: a document is not one farcast applies", true},
	} {
		t.Run(row.name, func(t *testing.T) {
			s := kubetest.New(t)
			c := openWriter(t, s, nil)
			err := c.Apply(t.Context(), []byte(row.stream))
			if !errors.Is(err, kube.ErrRefusedDocument) || (row.whole && err.Error() != row.want) || !strings.HasPrefix(err.Error(), row.want) {
				t.Errorf("Apply = %v; want %q, wrapping kube.ErrRefusedDocument", err, row.want)
			}
			if got := s.Requests(); len(got) != 0 {
				t.Errorf("a refused stream sent %d requests (%v), the token's included; it sends nothing", len(got), apiPaths(s))
			}
		})
	}
	s := kubetest.New(t)
	if err := openReader(t, s, nil).Apply(t.Context(), []byte(stream)); !errors.Is(err, errNeverWrites) {
		t.Errorf("the reader's Apply = %v, want %v", err, errNeverWrites)
	}
	if got := s.Requests(); len(got) != 0 {
		t.Errorf("the reader's refused Apply sent %d requests", len(got))
	}
}

// ADR 0023 M2.7 (A30-27): a writer's Apply writes the warnings each answer
// carried, after that document and before the next is sent, a refused
// document's included, each distinct text once.
func TestAWritersApplyWritesItsWarnings(t *testing.T) {
	var w bytes.Buffer
	var seen []string
	s := kubetest.New(t, kubetest.WithWarnings(func(r kubetest.Request) []string {
		if r.Method != http.MethodPatch {
			return nil
		}
		// What the warnings writer held when this document was sent.
		seen = append(seen, w.String())
		return []string{"applied " + r.Path, "deprecated \u202e"}
	}))
	s.Fail(http.MethodPatch, accountPath, http.StatusUnprocessableEntity, kube.Status{})
	c := openWriter(t, s, &w)
	if err := c.Apply(t.Context(), []byte(stream)); err == nil {
		t.Fatal("the refused third document read as applied")
	}
	want := "Warning (cluster): applied " + webPath + "\nWarning (cluster): \"deprecated \\u202e\"\n" +
		"Warning (cluster): applied " + settingsPath + "\n" +
		"Warning (cluster): applied " + accountPath + "\n"
	if got := w.String(); got != want {
		t.Errorf("the warnings = %q, want %q", got, want)
	}
	if len(seen) != 3 || seen[0] != "" || !strings.HasSuffix(seen[1], "applied "+webPath+"\nWarning (cluster): \"deprecated \\u202e\"\n") ||
		!strings.HasSuffix(seen[2], "applied "+settingsPath+"\n") {
		t.Errorf("before each apply the warnings held %q; want each answer's written before the next document is sent", seen)
	}
}

// ADR 0023 M2.7 (A30-29, §10.5 row 100): every apply is forced, whatever the
// stream and however many documents it holds: each apply-patch request
// carries force=true.
func TestEveryApplyIsForced(t *testing.T) {
	s := kubetest.New(t)
	c := openWriter(t, s, nil)
	for _, part := range []string{stream, settingsV(2), stream} {
		if err := c.Apply(t.Context(), []byte(part)); err != nil {
			t.Fatal(err)
		}
	}
	applies := appliedRequests(s)
	if len(applies) != 7 {
		t.Fatalf("%d applies, want 7", len(applies))
	}
	for i, r := range applies {
		q, err := url.ParseQuery(r.RawQuery)
		if err != nil || q.Get("force") != "true" || len(q["force"]) != 1 {
			t.Errorf("apply %d (%s) sent ?%s; want force=true", i, r.Path, r.RawQuery)
		}
	}
}

// settingsV is the ConfigMap web/settings at a mode of its own.
func settingsV(mode int) string {
	return fmt.Sprintf("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: settings\n  namespace: web\n  labels:\n    app.kubernetes.io/managed-by: farcast\ndata:\n  mode: \"%d\"\n", mode)
}

// settingsAt is settingsV(mode) carrying metadata.resourceVersion rv, as a
// YAML string.
func settingsAt(mode int, rv string) string {
	return strings.Replace(settingsV(mode), "  namespace: web\n", "  namespace: web\n  resourceVersion: \""+rv+"\"\n", 1)
}

// ADR 0023 M2.7 (A30-40 as §31's A31-2 amends it): ApplyAt applies one
// document as Apply does, letting it carry the resourceVersion it is given.
// At the stored one it is written, the document's bytes sent as they are; at
// a stale one the API server's 409 comes back unwrapping to
// tkube.ErrConflict, named as Apply names a failure, with nothing written;
// with "" it is an apply with no precondition. A manifest that is not one
// document, or whose resourceVersion is not the one given, is refused with
// nothing sent, a token included, and so is the reader.
func TestApplyAtAppliesOneDocumentAtItsResourceVersion(t *testing.T) {
	s := kubetest.New(t)
	c := openWriter(t, s, nil)
	ctx := t.Context()
	if err := c.ApplyAt(ctx, []byte(settingsV(1)), ""); err != nil {
		t.Fatalf("ApplyAt with no resourceVersion = %v", err)
	}
	_, read, _, err := c.ConfigMapData(ctx, "web", "settings")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(ctx, []byte(settingsV(2))); err != nil {
		t.Fatal(err)
	}
	_, current, _, err := c.ConfigMapData(ctx, "web", "settings")
	if err != nil {
		t.Fatal(err)
	}

	err = c.ApplyAt(ctx, []byte(settingsAt(3, read)), read)
	if want := "cluster: 0 of 1 documents were applied before ConfigMap web/settings failed: "; !errors.Is(err, tkube.ErrConflict) || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("ApplyAt at a stale resourceVersion = %v; want it to begin %q and unwrap to tkube.ErrConflict", err, want)
	}
	if v, _, _ := c.ConfigMapValue(ctx, "web", "settings", "mode"); v != "2" {
		t.Errorf("after the refused apply the mode reads %q, want 2", v)
	}

	body := settingsAt(4, current)
	if err := c.ApplyAt(ctx, []byte(body), current); err != nil {
		t.Fatalf("ApplyAt at the stored resourceVersion = %v", err)
	}
	applies := appliedRequests(s)
	if r := applies[len(applies)-1]; r.Body == nil || string(r.Body) != body || r.RawQuery != "fieldManager=farcast&fieldValidation=Strict&force=true" || r.As != "writer" {
		t.Errorf("the apply sent ?%s as %q with\n%s\nwant the document's own bytes, forced, as the writer", r.RawQuery, r.As, r.Body)
	}
	if v, _, _ := c.ConfigMapValue(ctx, "web", "settings", "mode"); v != "4" {
		t.Errorf("after the apply at the stored resourceVersion the mode reads %q, want 4", v)
	}

	for _, row := range []struct {
		name, manifest, rv string
		want               string
	}{
		{"two documents", settingsV(5) + "---\n" + strings.Replace(settingsV(5), "name: settings", "name: other", 1), "",
			"cluster: ApplyAt applies exactly one document, and the manifest holds 2, so nothing was sent: kube: a document is not one farcast applies"},
		{"two documents, one at its resourceVersion", settingsAt(5, current) + "---\n" + strings.Replace(settingsV(5), "name: settings", "name: other", 1), current,
			"cluster: ApplyAt applies exactly one document, and the manifest holds 2, so nothing was sent: kube: a document is not one farcast applies"},
		{"no document", "# nothing\n", "",
			"cluster: ApplyAt applies exactly one document, and the manifest holds 0, so nothing was sent: kube: a document is not one farcast applies"},
		{"another resourceVersion", settingsAt(5, read), current,
			`kube: document 0 (ConfigMap "settings") is refused: it carries metadata.resourceVersion "` + read + `", and only "` + current + `" is allowed`},
		{"a resourceVersion with none given", settingsAt(5, current), "",
			`kube: document 0 (ConfigMap "settings") is refused: it carries metadata.resourceVersion, which only the API server sets`},
	} {
		t.Run(row.name, func(t *testing.T) {
			fresh := kubetest.New(t)
			err := openWriter(t, fresh, nil).ApplyAt(t.Context(), []byte(row.manifest), row.rv)
			if !errors.Is(err, kube.ErrRefusedDocument) || err.Error() != row.want {
				t.Errorf("ApplyAt = %v\nwant %q, wrapping kube.ErrRefusedDocument", err, row.want)
			}
			if got := fresh.Requests(); len(got) != 0 {
				t.Errorf("a refused manifest sent %d requests (%v), the token's included", len(got), apiPaths(fresh))
			}
		})
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
	s.Script(fatlineService, serviceWith(), serviceWith(map[string]any{"hostname": ""}), serviceWith(map[string]any{"ip": "203.0.113.5"}))
	c := quick(openReader(t, s, nil))
	ip, err := c.WaitExternalIP(t.Context(), "farcast-system", "fatline", time.Minute)
	if err != nil || ip != "203.0.113.5" {
		t.Fatalf("ip = %q, %v", ip, err)
	}
	if got := apiPaths(s); len(got) != 3 || got[0] != "GET "+fatlineService {
		t.Errorf("requests = %v, want three reads of the Service", got)
	}

	// An address that is not one never becomes an endpoint.
	for _, bad := range []string{"203.0.113.256", "fe80::1%eth0", "fatline.example"} {
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

// withUID is obj with metadata.uid set to uid.
func withUID(obj map[string]any, uid string) map[string]any {
	obj["metadata"].(map[string]any)["uid"] = uid
	return obj
}

// A Job ends on its counts or on its conditions, and its message is the
// newest pod's first terminated container's, trimmed; a Job that has not
// ended by the deadline is a timeout. Since ADR 0023 M2.6 (A23-46, A28-7)
// the result carries the uid the GET that ended the wait read.
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
		s.Put(withUID(jobObject("build", []string{"kaniko"}, row.status), "uid-"+row.name))
		s.Put(buildPod("build-old", "2026-11-15T10:00:00Z", terminated("sha256:old")))
		s.Put(buildPod("build-new", "2026-11-15T10:05:00Z", running(), terminated("  sha256:new\n")))
		s.Put(buildPod("build-mid", "2026-11-15T10:02:00Z", terminated("sha256:mid")))
		res, err := openReader(t, s, nil).WaitJob(t.Context(), "farcast-system", "build", time.Minute)
		if err != nil || res.Succeeded != row.succeeded || res.Message != "sha256:new" || res.UID != "uid-"+row.name {
			t.Errorf("%s: %+v, %v; want succeeded %v with the newest pod's message and the Job's uid", row.name, res, err, row.succeeded)
		}
	}

	// The uid is the one the GET that ended the wait read, not an earlier
	// poll's: a Job re-created under its name is another Job.
	s := kubetest.New(t)
	s.Script(buildJob,
		withUID(jobObject("build", []string{"kaniko"}, map[string]any{"active": 1}), "uid-first"),
		withUID(jobObject("build", []string{"kaniko"}, map[string]any{"conditions": []any{map[string]any{"type": "Complete", "status": "False"}}}), "uid-second"),
		withUID(jobObject("build", []string{"kaniko"}, map[string]any{"succeeded": 1}), "uid-third"),
	)
	c := quick(openReader(t, s, nil))
	res, err := c.WaitJob(t.Context(), "farcast-system", "build", time.Minute)
	if err != nil || !res.Succeeded || res.Message != "" || res.UID != "uid-third" {
		t.Errorf("after polling, with no pod: %+v, %v; want succeeded with no message, and the third read's uid", res, err)
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

// countedWarnings is a WithWarnings function whose every answer under prefix
// carries one Warning text no other answer carries, so that each read's own
// warning is written once, after it.
func countedWarnings(prefix string) kubetest.Option {
	var n atomic.Int64
	return kubetest.WithWarnings(func(r kubetest.Request) []string {
		if strings.HasPrefix(r.Path, prefix) {
			return []string{fmt.Sprintf("read %d", n.Add(1))}
		}
		return nil
	})
}

// onlyRead runs read and checks that it sent exactly one GET, of path, and
// wrote exactly that GET's warning, after it.
func onlyRead(t *testing.T, s *kubetest.Server, w *bytes.Buffer, path string, read func()) {
	t.Helper()
	sent, warned := len(apiRequests(s)), w.String()
	read()
	if got := apiPaths(s)[sent:]; !slices.Equal(got, []string{"GET " + path}) {
		t.Errorf("the read of %s sent %v; want one GET", path, got)
	}
	if got := strings.TrimPrefix(w.String(), warned); !strings.HasPrefix(got, "Warning (cluster): read ") || strings.Count(got, "\n") != 1 {
		t.Errorf("the read of %s wrote %q of warnings; want its one", path, got)
	}
}

// appDeployment is the Deployment web/<name> with these containers, each a
// name and its cpu and memory requests ("" for one not set), these replicas
// (nil for none), and these annotations and managed-fields entries.
func appDeployment(name string, replicas any, containers [][3]string, annotations map[string]string, managed ...map[string]any) map[string]any {
	var cs []any
	for _, ct := range containers {
		requests := map[string]any{}
		if ct[1] != "" {
			requests["cpu"] = ct[1]
		}
		if ct[2] != "" {
			requests["memory"] = ct[2]
		}
		cs = append(cs, map[string]any{"name": ct[0], "image": "example.invalid/" + ct[0], "resources": map[string]any{"requests": requests}})
	}
	spec := map[string]any{
		"selector": selectorOf(map[string]string{"app": name}),
		"template": map[string]any{"spec": map[string]any{"containers": cs}},
	}
	if replicas != nil {
		spec["replicas"] = replicas
	}
	md := map[string]any{}
	if annotations != nil {
		md["annotations"] = annotations
	}
	if managed != nil {
		var mf []any
		for _, e := range managed {
			mf = append(mf, e)
		}
		md["managedFields"] = mf
	}
	return object("apps/v1", "Deployment", "web", name, map[string]any{"metadata": md, "spec": spec})
}

// managedEntry is one managed-fields entry, as the API server writes it.
func managedEntry(manager, operation, subresource, at string) map[string]any {
	e := map[string]any{"manager": manager, "operation": operation, "apiVersion": "apps/v1", "time": at,
		"fieldsType": "FieldsV1", "fieldsV1": map[string]any{"f:spec": map[string]any{"f:replicas": map[string]any{}}}}
	if subresource != "" {
		e["subresource"] = subresource
		e["apiVersion"] = "autoscaling/v1"
	}
	return e
}

// stateText is a DeploymentState as a test failure shows it.
func stateText(st DeploymentState) string {
	replicas := "nil"
	if st.Replicas != nil {
		replicas = fmt.Sprint(*st.Replicas)
	}
	return fmt.Sprintf("present %v, replicas %s, requests %v, adapted %s, applied %s, rv %q",
		st.Present, replicas, st.Requests, st.AdaptedAt.Format(time.RFC3339), st.LastAppliedAt.Format(time.RFC3339), st.ResourceVersion)
}

// sameState compares two DeploymentStates field by field: the struct holds a
// map and a pointer, and its times are compared as instants.
func sameState(a, b DeploymentState) bool {
	sameReplicas := (a.Replicas == nil) == (b.Replicas == nil) && (a.Replicas == nil || *a.Replicas == *b.Replicas)
	return a.Present == b.Present && sameReplicas && (a.Requests == nil) == (b.Requests == nil) && maps.Equal(a.Requests, b.Requests) &&
		a.AdaptedAt.Equal(b.AdaptedAt) && a.LastAppliedAt.Equal(b.LastAppliedAt) && a.ResourceVersion == b.ResourceVersion
}

// ADR 0023 M2.6 (A23-46, A28-7), narrowed at M2.9a (design §37, A37-8,
// mutation row 200): DeploymentState is one GET of the Deployment, its
// warnings written after it. Its replicas, each container's requests ("" as
// 0), the kernel's adapted-at stamp as the kernel reads it (zero when it does
// not parse), and the newest time among the entries that record farcast's own
// Apply of the object, in UTC: web's is seeded at +02:00. kubectl's
// client-side apply Update, a subresource entry (the kernel's scale), another
// operation, another manager and a time that does not parse are passed over,
// each seeded newer than the answer. Only the API server's own 404 Status is
// absent; a 404 that is not a Status and a 403 are errors, and a set request
// that does not parse is an error wrapping kube.ErrUnreadable.
func TestDeploymentStateReadsTheAdaptationAndTheLastApply(t *testing.T) {
	const prefix = "/apis/apps/v1/namespaces/web/deployments/"
	s := kubetest.New(t, countedWarnings(prefix))
	var w bytes.Buffer
	c := openReader(t, s, &w)
	at := func(v string) time.Time {
		tm, err := time.Parse(time.RFC3339, v)
		if err != nil {
			t.Fatal(err)
		}
		return tm
	}
	zero, one := int32(0), int32(1)

	api := appDeployment("api", 0, [][3]string{{"api", "250m", "512Mi"}, {"sidecar", "", ""}, {"log", "100m", ""}},
		map[string]string{kernel.AdaptedAtLabel: "2026-11-17T10:00:00Z", kernel.AdaptedFromLabel: "100m/128Mi"},
		managedEntry("kubectl-client-side-apply", "Update", "", "2026-11-17T09:00:00Z"),
		managedEntry("farcast", "Apply", "", "2026-11-17T09:30:00Z"),
		managedEntry("farcast", "Apply", "status", "2026-11-17T11:00:00Z"),
		managedEntry("kubectl-client-side-apply", "Update", "scale", "2026-11-17T11:15:00Z"),
		managedEntry("farcast", "Update", "", "2026-11-17T11:30:00Z"),
		managedEntry("Go-http-client", "Update", "", "2026-11-17T12:00:00Z"),
		managedEntry("kubectl-client-side-apply", "Update", "", "not a time"),
	)
	api["metadata"].(map[string]any)["resourceVersion"] = "41"
	s.Put(api)
	s.Put(appDeployment("web", nil, [][3]string{{"web", "1", "1Gi"}},
		map[string]string{kernel.AdaptedAtLabel: "yesterday-ish"},
		managedEntry("farcast", "Apply", "", "2026-11-17T10:15:00+02:00"),
		managedEntry("kubectl-client-side-apply", "Update", "", "2026-11-17T12:45:30+02:00"),
	))
	s.Put(appDeployment("bare", 1, [][3]string{{"bare", "", ""}}, map[string]string{kernel.AdaptedAtLabel: "2026-11-17T11:00:00+01:00"}))
	s.Put(appDeployment("bad-cpu", 1, [][3]string{{"bad-cpu", "lots", "128Mi"}}, nil))
	s.Put(appDeployment("bad-mem", 1, [][3]string{{"bad-mem", "100m", "a lot"}}, nil))

	ctx := t.Context()
	read := func(name string) (DeploymentState, error) {
		var (
			st  DeploymentState
			err error
		)
		onlyRead(t, s, &w, prefix+name, func() { st, err = c.DeploymentState(ctx, "web", name) })
		return st, err
	}
	for _, row := range []struct {
		name string
		want DeploymentState
	}{
		{"api", DeploymentState{
			Present: true, Replicas: &zero,
			Requests:  map[string]Requests{"api": {250, 512}, "sidecar": {0, 0}, "log": {100, 0}},
			AdaptedAt: at("2026-11-17T10:00:00Z"), LastAppliedAt: at("2026-11-17T09:30:00Z"), ResourceVersion: "41",
		}},
		{"web", DeploymentState{
			Present: true, Requests: map[string]Requests{"web": {1000, 1024}},
			LastAppliedAt: at("2026-11-17T08:15:00Z"),
		}},
		{"bare", DeploymentState{
			Present: true, Replicas: &one, Requests: map[string]Requests{"bare": {0, 0}},
			AdaptedAt: at("2026-11-17T10:00:00Z"),
		}},
	} {
		got, err := read(row.name)
		if row.name != "api" {
			row.want.ResourceVersion = got.ResourceVersion // the one kubetest gave it
		}
		if err != nil || !sameState(got, row.want) {
			t.Errorf("DeploymentState(web/%s) = %s, %v;\nwant %s", row.name, stateText(got), err, stateText(row.want))
		}
		if got.AdaptedAt.Location() != time.UTC || got.LastAppliedAt.Location() != time.UTC {
			t.Errorf("web/%s's times read %s and %s; want both in UTC", row.name, got.AdaptedAt.Format(time.RFC3339), got.LastAppliedAt.Format(time.RFC3339))
		}
	}

	// The one absent answer: the API server's own 404 Status.
	if got, err := read("gone"); err != nil || !sameState(got, DeploymentState{}) {
		t.Errorf("an absent Deployment = %s, %v; want not present and no error", stateText(got), err)
	}

	// A 404 that is not a Status unwraps to tkube.ErrNotFound as the API
	// server's does, and proves nothing about the Deployment; a 403 is a
	// refused read. Neither is absent.
	google := kube.Status{Status: tkube.Status{Kind: "GoogleError"}}
	for _, row := range []struct {
		name string
		code int
		st   kube.Status
		is   error
	}{
		{"a 404 that is not a Status", http.StatusNotFound, google, tkube.ErrNotFound},
		{"an RBAC 403", http.StatusForbidden, kube.Status{}, tkube.ErrForbidden},
	} {
		s.Fail(http.MethodGet, prefix+"api", row.code, row.st)
		got, err := read("api")
		if err == nil || !errors.Is(err, row.is) || !sameState(got, DeploymentState{}) {
			t.Errorf("%s = %s, %v; want an error wrapping %v, and nothing read", row.name, stateText(got), err, row.is)
		}
	}

	// A request that is set and does not parse: nothing is known of the
	// application, rather than a request misread as 0.
	for _, row := range []struct{ name, want string }{
		{"bad-cpu", `cluster: the Deployment web/bad-cpu's container "bad-cpu" requests cpu "lots", which farcast cannot read as a quantity`},
		{"bad-mem", `cluster: the Deployment web/bad-mem's container "bad-mem" requests memory "a lot", which farcast cannot read as a quantity`},
	} {
		got, err := read(row.name)
		if !errors.Is(err, kube.ErrUnreadable) || err.Error() != row.want || !sameState(got, DeploymentState{}) {
			t.Errorf("web/%s = %s, %v; want %q wrapping kube.ErrUnreadable", row.name, stateText(got), err, row.want)
		}
	}
}

// ADR 0023 M2.6 (A23-46, A28-7): JobState is one GET of the Job, its warnings
// written after it, and reads no pod. A Job that is there is found, with the
// uid that GET read and whether it succeeded as WaitJob judges it, and never
// a message. Only the API server's own 404 Status is absent; a 404 that is
// not a Status and a 403 are errors, with found false.
func TestJobStateTellsAnAbsentJob(t *testing.T) {
	const prefix = "/apis/batch/v1/namespaces/farcast-system/jobs/"
	s := kubetest.New(t, countedWarnings(prefix))
	var w bytes.Buffer
	c := openReader(t, s, &w)
	ctx := t.Context()
	read := func(name string) (JobResult, bool, error) {
		var (
			res   JobResult
			found bool
			err   error
		)
		onlyRead(t, s, &w, prefix+name, func() { res, found, err = c.JobState(ctx, "farcast-system", name) })
		return res, found, err
	}

	s.Put(buildPod("fetch-pod", "2026-11-15T10:00:00Z", terminated("sha256:not-read")))
	for _, row := range []struct {
		name   string
		status map[string]any
		want   JobResult
	}{
		{"succeeded", map[string]any{"succeeded": 1}, JobResult{Succeeded: true, UID: "uid-succeeded"}},
		{"complete", map[string]any{"conditions": []any{map[string]any{"type": "Complete", "status": "True"}}}, JobResult{Succeeded: true, UID: "uid-complete"}},
		{"running", map[string]any{"active": 1}, JobResult{UID: "uid-running"}},
		{"failed", map[string]any{"failed": 1}, JobResult{UID: "uid-failed"}},
	} {
		s.Put(withUID(jobObject("fetch", []string{"git"}, row.status), "uid-"+row.name))
		res, found, err := read("fetch")
		if err != nil || !found || res != row.want {
			t.Errorf("%s: %+v, %v, %v; want %+v, found", row.name, res, found, err, row.want)
		}
	}

	// The one absent answer: the API server's own 404 Status.
	if res, found, err := read("gone"); err != nil || found || res != (JobResult{}) {
		t.Errorf("an absent Job = %+v, %v, %v; want not found and no error", res, found, err)
	}

	google := kube.Status{Status: tkube.Status{Kind: "GoogleError"}}
	for _, row := range []struct {
		name string
		code int
		st   kube.Status
		is   error
	}{
		{"a 404 that is not a Status", http.StatusNotFound, google, tkube.ErrNotFound},
		{"an RBAC 403", http.StatusForbidden, kube.Status{}, tkube.ErrForbidden},
	} {
		s.Fail(http.MethodGet, prefix+"fetch", row.code, row.st)
		res, found, err := read("fetch")
		if err == nil || !errors.Is(err, row.is) || found || res != (JobResult{}) {
			t.Errorf("%s = %+v, %v, %v; want an error wrapping %v, not found", row.name, res, found, err, row.is)
		}
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
// Nothing is patched or applied.
func TestConfigMapWritesNeverApply(t *testing.T) {
	s := kubetest.New(t)
	c := openWriter(t, s, nil)
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
	c := openWriter(t, s, nil)
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
	c := openWriter(t, s, &w)
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

// annotatedDeployment is the Deployment web/api as farcast applied it and
// kubectl then wrote it: farcast's label, farcast's Apply entry, and
// kubectl's last-applied annotation holding marker.
func annotatedDeployment(marker string) map[string]any {
	d := appDeployment("api", 1, [][3]string{{"api", "250m", "512Mi"}},
		map[string]string{"kubectl.kubernetes.io/last-applied-configuration": `{"kind":"Deployment","marker":"` + marker + `"}`},
		managedEntry("farcast", "Apply", "", "2026-11-01T09:00:00Z"))
	d["metadata"].(map[string]any)["labels"] = map[string]any{"app.kubernetes.io/managed-by": "farcast"}
	return d
}

// ADR 0023 M2.7 (A30-15), M2.9a (design §37, A37-7): GetMeta is kube's
// GetObject, metadata only, in process as the writer: one GET of the object,
// with no query, asking for PartialObjectMetadata, its warning written after
// it and before it returns. The last-applied annotation comes back with its
// key and an empty value (blankLastApplied), so its value, which on a Secret
// kubectl applied holds the Secret's values, reaches neither the caller nor
// the warnings.
func TestGetMetaIsKubesGetObject(t *testing.T) {
	deployments, ok := kube.KindOf("apps/v1", "Deployment")
	if !ok {
		t.Fatal("no Deployment kind")
	}
	s := kubetest.New(t, kubetest.WithWarnings(func(r kubetest.Request) []string {
		return []string{r.Method + " " + r.Path}
	}))
	const marker = "LAST-APPLIED-MARKER"
	s.Put(annotatedDeployment(marker))
	var w bytes.Buffer
	c := openWriter(t, s, &w)
	const (
		objPath = "/apis/apps/v1/namespaces/web/deployments/api"
		partial = "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1"
	)

	o, err := c.GetMeta(t.Context(), deployments, "web", "api")
	if err != nil {
		t.Fatal(err)
	}
	if o.Kind.Kind != "Deployment" || o.Metadata.Namespace != "web" || o.Metadata.Name != "api" || o.Metadata.UID == "" ||
		len(o.Metadata.ManagedFields) != 1 || !kube.IsOwnApply(o.Metadata.ManagedFields[0]) {
		t.Errorf("GetMeta = %s %s/%s, uid %q, managed fields %+v", o.Kind.Kind, o.Metadata.Namespace, o.Metadata.Name,
			o.Metadata.UID, o.Metadata.ManagedFields)
	}
	if want := "Warning (cluster): GET " + objPath + "\n"; w.String() != want {
		t.Errorf("after GetMeta the warnings are %q; want its own, %q", w.String(), want)
	}

	reqs := apiRequests(s)
	if len(reqs) != 1 {
		t.Fatalf("%d requests, want one get: %v", len(reqs), apiPaths(s))
	}
	get := reqs[0]
	if get.Method != http.MethodGet || get.Path != objPath || get.RawQuery != "" || get.Accept != partial || get.As != "writer" {
		t.Errorf("GetMeta sent %s %s?%s, Accept %q, as %q", get.Method, get.Path, get.RawQuery, get.Accept, get.As)
	}
	if strings.Contains(w.String(), marker) {
		t.Errorf("the annotation's value reached the warnings: %q", w.String())
	}
	value, present := o.Metadata.Annotations["kubectl.kubernetes.io/last-applied-configuration"]
	if !present || value != "" {
		t.Errorf("GetMeta: the annotation present %t, its value %d bytes; want the key with an empty value", present, len(value))
	}
}
