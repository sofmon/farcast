package cluster

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
)

const reviewPath = "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"

// loopbackConfig is a kube.Config for one identity registered with s.
func loopbackConfig(t *testing.T, s *kubetest.Server, id string, identity kube.Identity) kube.Config {
	t.Helper()
	ep, err := kube.ParseEndpoint(s.Endpoint(), "", s.CAPEM())
	if err != nil {
		t.Fatal(err)
	}
	return kube.Config{Endpoint: ep, Credential: s.Credential(id), Identity: identity}
}

func openReader(t *testing.T, s *kubetest.Server, warnings io.Writer) *Client {
	t.Helper()
	c, err := Open(loopbackConfig(t, s, "reader", kube.Reader), warnings, "")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func namespace(name string, labels map[string]string) map[string]any {
	md := map[string]any{"name": name}
	if labels != nil {
		md["labels"] = labels
	}
	return map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": md}
}

// apiRequests is every request s saw but the token's.
func apiRequests(s *kubetest.Server) []kubetest.Request {
	var out []kubetest.Request
	for _, r := range s.Requests() {
		if r.Path != "/token" {
			out = append(out, r)
		}
	}
	return out
}

// ADR 0023 M2.3, mutation 57: until M2.5, Open builds the reader and nothing
// else. The writer, an unnamed identity and a legacy kubeconfig (which only a
// writer's transitional kubectl Apply uses) are refused before anything is
// built, and nothing reaches the server. (Deleted in M2.5, which opens the
// writer.)
func TestOpenRefusesTheWriterUntilM25(t *testing.T) {
	s := kubetest.New(t)
	for _, row := range []struct {
		name     string
		identity kube.Identity
		legacy   string
	}{
		{"the writer", kube.Writer, ""},
		{"the writer with its kubeconfig", kube.Writer, "/cfg/instances/atlas/kubeconfig.yaml"},
		{"no identity", "", ""},
		{"an identity an instance does not have", "admin", ""},
		{"the reader with a kubeconfig", kube.Reader, "/cfg/instances/atlas/kubeconfig.yaml"},
	} {
		c, err := Open(loopbackConfig(t, s, "id", row.identity), io.Discard, row.legacy)
		if c != nil || err == nil || err.Error() != "cluster: until ADR 0023 M2.5 Open builds a reader only" {
			t.Errorf("%s: Open = %v, %v", row.name, c, err)
		}
	}
	if c, err := Open(loopbackConfig(t, s, "reader", kube.Reader), nil, ""); c == nil || err != nil {
		t.Fatalf("the reader: Open = %v, %v", c, err)
	}
	if got := s.Requests(); len(got) != 0 {
		t.Errorf("Open sent %d requests; it dials nothing", len(got))
	}
}

// A refused pairing is kube.New's, returned as it is: Open adds no path
// around the endpoint rule.
func TestOpenRefusesWhatKubeRefuses(t *testing.T) {
	s := kubetest.New(t)
	cfg := loopbackConfig(t, s, "reader", kube.Reader)
	cfg.Credential.Email = "reader@proj.iam.gserviceaccount.com"
	if c, err := Open(cfg, nil, ""); c != nil || !errors.Is(err, kube.ErrEndpointRefused) {
		t.Errorf("a Google credential to a loopback endpoint: %v, %v; want ErrEndpointRefused", c, err)
	}
	if got := s.Requests(); len(got) != 0 {
		t.Errorf("a refused Open sent %d requests", len(got))
	}
}

// An Open'd reader lists namespaces in-process, as the reader: kube's list
// with the selector, paged, the names sorted, and every request carrying the
// reader's token and farcast's user agent.
func TestAnOpenedReaderListsNamespacesInProcess(t *testing.T) {
	s := kubetest.New(t)
	managed := map[string]string{"app.kubernetes.io/managed-by": "farcast"}
	for _, ns := range []map[string]any{
		namespace("web", managed),
		namespace("kube-system", nil),
		namespace("farcast-system", managed),
		namespace("api", managed),
	} {
		s.Put(ns)
	}
	c := openReader(t, s, nil)
	names, err := c.NamespacesLabelled(t.Context(), "app.kubernetes.io/managed-by=farcast")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"api", "farcast-system", "web"}; !slices.Equal(names, want) {
		t.Errorf("NamespacesLabelled = %q, want %q", names, want)
	}
	none, err := c.NamespacesLabelled(t.Context(), "tier=none")
	if err != nil || none == nil || len(none) != 0 {
		t.Errorf("no match = %#v, %v; want an empty, non-nil list", none, err)
	}

	reqs := s.Requests()
	if len(reqs) != 3 || reqs[0].Path != "/token" || reqs[0].As != "reader" {
		t.Fatalf("requests = %+v; want one mint as the reader, then two lists", reqs)
	}
	for _, r := range reqs[1:] {
		q, err := url.ParseQuery(r.RawQuery)
		if err != nil {
			t.Fatal(err)
		}
		if r.Method != http.MethodGet || r.Path != "/api/v1/namespaces" || r.As != "reader" || r.UserAgent != "farcast" ||
			q.Get("limit") != "500" || q.Get("labelSelector") == "" {
			t.Errorf("list request = %s %s?%s as %q (%q)", r.Method, r.Path, r.RawQuery, r.As, r.UserAgent)
		}
	}
}

// CanI is a SelfSubjectAccessReview as the client's own identity, in-process.
func TestAnOpenedReaderAsksCanI(t *testing.T) {
	s := kubetest.New(t, kubetest.WithAccess(func(id string, a kube.ResourceAttributes) bool {
		return id == "reader" && a.Verb == "get" && a.Resource == "secrets" && a.Namespace == "farcast-system"
	}))
	c := openReader(t, s, nil)
	ctx := t.Context()
	if ok, err := c.CanI(ctx, kube.ResourceAttributes{Namespace: "farcast-system", Verb: "get", Resource: "secrets"}); !ok || err != nil {
		t.Errorf("get secrets = %v, %v; want allowed", ok, err)
	}
	if ok, err := c.CanI(ctx, kube.ResourceAttributes{Namespace: "farcast-system", Verb: "create", Group: "apps", Resource: "deployments"}); ok || err != nil {
		t.Errorf("create deployments = %v, %v; want not allowed", ok, err)
	}
	s.Fail(http.MethodPost, reviewPath, http.StatusInternalServerError, kube.Status{})
	if ok, err := c.CanI(ctx, kube.ResourceAttributes{Verb: "list", Resource: "secrets"}); ok || err == nil {
		t.Errorf("a failed review = %v, %v; want an error and never allowed", ok, err)
	}
	reviews := 0
	for _, r := range apiRequests(s) {
		if r.Method != http.MethodPost || r.Path != reviewPath || r.As != "reader" {
			t.Errorf("request %s %s as %q; want only reviews as the reader", r.Method, r.Path, r.As)
		}
		reviews++
	}
	if reviews != 3 {
		t.Errorf("%d reviews sent, want 3", reviews)
	}
}

// ADR 0023 M2.4 (A18-2): an Open'd client is the reader, and refuses every
// write before anything is sent: no token is minted and no request reaches
// the server. It never falls through to kubectl, which it does not have.
func TestAReaderClientNeverWrites(t *testing.T) {
	s := kubetest.New(t)
	c := openReader(t, s, nil)
	ctx := t.Context()
	pin := []byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"datasphered-pin","namespace":"farcast-system","resourceVersion":"7"},"data":{"pin":"x"}}`)
	for name, call := range map[string]func() error{
		"Apply":            func() error { return c.Apply(ctx, []byte("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: web\n")) },
		"CreateConfigMap":  func() error { return c.CreateConfigMap(ctx, pin) },
		"ReplaceConfigMap": func() error { return c.ReplaceConfigMap(ctx, pin) },
	} {
		if err := call(); err == nil || err.Error() != "cluster: a reader client never writes" {
			t.Errorf("%s: err = %v, want the reader's refusal", name, err)
		}
	}
	if got := s.Requests(); len(got) != 0 {
		t.Errorf("the refused writes sent %d requests", len(got))
	}
}

// A kubectl client has no CanI, Logs, Workloads or NamespacesLabelled: they
// are in-process only, and the kubectl client refuses each, naming it, and
// runs nothing for it (ADR 0023 M2.4). The writing commands build such a
// client, and none of them calls these.
func TestAKubectlClientHasNoCanI(t *testing.T) {
	// A kubectl that would answer, should a refusal ever fall through to one:
	// it leaves a mark, and the test reads that nothing ran.
	bin := t.TempDir()
	ran := filepath.Join(t.TempDir(), "ran")
	if err := os.WriteFile(filepath.Join(bin, "kubectl"), []byte("#!/bin/sh\ntouch '"+ran+"'\necho '{\"items\":[]}'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	var out bytes.Buffer
	for _, c := range []*Client{newWithEnv("/kc", []string{"PATH=" + bin}), New("/cfg/instances/atlas/kubeconfig.yaml")} {
		ok, err := c.CanI(context.Background(), kube.ResourceAttributes{Verb: "get", Resource: "secrets"})
		if ok || err == nil || err.Error() != "cluster: CanI is in-process only, and this client runs kubectl" {
			t.Errorf("CanI on a kubectl client = %v, %v", ok, err)
		}
		for _, followed := range []bool{false, true} {
			err := c.Logs(context.Background(), &out, "web", "deployment/api", 10, followed, false)
			if err == nil || err.Error() != "cluster: Logs is in-process only, and this client runs kubectl" {
				t.Errorf("Logs (follow %v) on a kubectl client = %v", followed, err)
			}
		}
		ws, err := c.Workloads(context.Background(), "web")
		if ws != nil || err == nil || err.Error() != "cluster: Workloads is in-process only, and this client runs kubectl" {
			t.Errorf("Workloads on a kubectl client = %v, %v", ws, err)
		}
		names, err := c.NamespacesLabelled(context.Background(), "a=b")
		if names != nil || err == nil || err.Error() != "cluster: NamespacesLabelled is in-process only, and this client runs kubectl" {
			t.Errorf("NamespacesLabelled on a kubectl client = %v, %v", names, err)
		}
	}
	if _, err := os.Stat(ran); err == nil || out.Len() != 0 {
		t.Errorf("the refusals ran kubectl (%v) and wrote %q", err, out.String())
	}
}

// Each distinct Warning text an answer carried is written once, after the
// call that saw it, in the order first seen; one that would not print as it
// is, is written quoted; and a nil writer discards them.
func TestAnOpenedClientWritesEachWarningOnce(t *testing.T) {
	warn := func(r kubetest.Request) []string {
		switch {
		case r.Path == "/api/v1/namespaces" && strings.Contains(r.RawQuery, "denied"):
			return []string{"d"}
		case r.Path == "/api/v1/namespaces":
			return []string{"a", "b"}
		case r.Path == reviewPath:
			return []string{"b", "c", "flip \u202e here"}
		case r.Path == "/api/v1/namespaces/farcast-system/configmaps/ledger":
			return []string{"e"}
		case strings.HasPrefix(r.Path, "/apis/apps/v1/namespaces/web/"):
			return []string{"f"}
		}
		return nil
	}
	s := kubetest.New(t, kubetest.WithWarnings(warn))
	var w bytes.Buffer
	c := openReader(t, s, &w)
	ctx := t.Context()

	if _, err := c.NamespacesLabelled(ctx, "x=y"); err != nil {
		t.Fatal(err)
	}
	if got, want := w.String(), "Warning (cluster): a\nWarning (cluster): b\n"; got != want {
		t.Errorf("after the first list: %q, want %q", got, want)
	}
	if _, err := c.NamespacesLabelled(ctx, "x=y"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CanI(ctx, kube.ResourceAttributes{Verb: "get", Resource: "pods"}); err != nil {
		t.Fatal(err)
	}
	want := "Warning (cluster): a\nWarning (cluster): b\nWarning (cluster): c\nWarning (cluster): \"flip \\u202e here\"\n"
	if got := w.String(); got != want {
		t.Errorf("after a second list and a review: %q, want %q", got, want)
	}

	// A refused answer's warnings are written too.
	s.Fail(http.MethodGet, "/api/v1/namespaces", http.StatusForbidden, kube.Status{})
	if _, err := c.NamespacesLabelled(ctx, "denied=yes"); err == nil {
		t.Fatal("an injected 403 read as a list")
	}
	if got := strings.TrimPrefix(w.String(), want); got != "Warning (cluster): d\n" {
		t.Errorf("after a refused list: %q appended, want the 403's own warning", got)
	}

	// The reads of M2.4 write theirs too: an absent ConfigMap's 404, and the
	// two lists of Workloads, whose shared text is written once.
	want = w.String()
	if _, found, err := c.ConfigMapValue(ctx, "farcast-system", "ledger", "ledger.json"); found || err != nil {
		t.Fatalf("an absent ConfigMap = %v, %v", found, err)
	}
	if _, err := c.Workloads(ctx, "web"); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimPrefix(w.String(), want); got != "Warning (cluster): e\nWarning (cluster): f\n" {
		t.Errorf("after a ConfigMap read and a Workloads list: %q appended", got)
	}

	quiet := kubetest.New(t, kubetest.WithWarnings(warn))
	qc := openReader(t, quiet, nil)
	if _, err := qc.NamespacesLabelled(ctx, "x=y"); err != nil {
		t.Errorf("a nil warnings writer: %v", err)
	}
}
