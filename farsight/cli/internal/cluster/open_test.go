package cluster

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
	tkube "github.com/sofmon/farcast/technocore/kube"
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

// openWriter opens the writer registered with s as id "writer", with a
// legacy kubeconfig for its Apply ("" for none).
func openWriter(t *testing.T, s *kubetest.Server, legacyKubeconfig string, warnings io.Writer) *Client {
	t.Helper()
	c, err := Open(loopbackConfig(t, s, "writer", kube.Writer), warnings, legacyKubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// recordingKubectl is a directory holding a fake kubectl that writes its
// arguments, each ending in a NUL, to <saw>/argv and its stdin to
// <saw>/stdin, and prints nothing. It runs with only the PATH a client hands
// it, so it names cat by its path.
func recordingKubectl(t *testing.T) (bin, saw string) {
	t.Helper()
	saw = t.TempDir()
	return fakeKubectl(t, "for a in \"$@\"; do printf '%s\\000' \"$a\"; done > '"+saw+"/argv'\n/bin/cat > '"+saw+"/stdin'\n"), saw
}

// kubectlRecord is what the recording kubectl saw, and whether it ran at all.
func kubectlRecord(t *testing.T, saw string) (argv []string, stdin []byte, ran bool) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(saw, "argv"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, false
	}
	if err != nil {
		t.Fatal(err)
	}
	if stdin, err = os.ReadFile(filepath.Join(saw, "stdin")); err != nil {
		t.Fatal(err)
	}
	argv = strings.Split(strings.TrimSuffix(string(raw), "\x00"), "\x00")
	return argv, stdin, true
}

// ADR 0023 M2.5 (A20-3), mutation 70a: Open builds an instance's reader or
// its writer, and nothing else. An identity that is neither, and a reader
// given a kubeconfig (only a writer's transitional kubectl Apply reads one),
// are refused before kube.New, so a pairing kube would refuse is never what
// they are told; nothing reaches the server. A writer opens with its legacy
// kubeconfig or without one, and one without one refuses to Apply, running
// no kubectl.
func TestOpenBuildsTheReaderOrTheWriter(t *testing.T) {
	bin, saw := recordingKubectl(t)
	t.Setenv("PATH", bin)
	s := kubetest.New(t)
	const kc = "/cfg/instances/atlas/kubeconfig.yaml"
	// unpaired is a Google credential to a loopback endpoint, which kube.New
	// refuses with ErrEndpointRefused.
	unpaired := func(identity kube.Identity) kube.Config {
		cfg := loopbackConfig(t, s, "unpaired", identity)
		cfg.Credential.Email = "unpaired@proj.iam.gserviceaccount.com"
		return cfg
	}
	const (
		neither = `cluster: Open builds an instance's reader or writer, and %q is neither`
		reader  = "cluster: a reader client runs no kubectl, so Open takes no kubeconfig for it"
	)
	for _, row := range []struct {
		name   string
		cfg    kube.Config
		legacy string
		want   string
	}{
		{"no identity", loopbackConfig(t, s, "id", ""), "", fmt.Sprintf(neither, "")},
		{"no identity, with a kubeconfig", loopbackConfig(t, s, "id", ""), kc, fmt.Sprintf(neither, "")},
		{"no identity, unpaired", unpaired(""), "", fmt.Sprintf(neither, "")},
		{"an identity an instance does not have", loopbackConfig(t, s, "admin", "admin"), "", fmt.Sprintf(neither, "admin")},
		{"an identity in another case", loopbackConfig(t, s, "writer", "Writer"), kc, fmt.Sprintf(neither, "Writer")},
		{"the reader with a kubeconfig", loopbackConfig(t, s, "reader", kube.Reader), kc, reader},
		{"the reader with a kubeconfig, unpaired", unpaired(kube.Reader), kc, reader},
	} {
		c, err := Open(row.cfg, io.Discard, row.legacy)
		if c != nil || err == nil || err.Error() != row.want {
			t.Errorf("%s: Open built a client (%v), %v; want %q", row.name, c != nil, err, row.want)
		}
	}

	r, err := Open(loopbackConfig(t, s, "reader", kube.Reader), nil, "")
	if r == nil || err != nil || r.runner != nil {
		t.Fatalf("the reader: Open built a client (%v), %v; want one with no kubectl", r != nil, err)
	}
	if w, err := Open(loopbackConfig(t, s, "writer", kube.Writer), nil, kc); w == nil || err != nil || w.runner == nil {
		t.Fatalf("the writer with its kubeconfig: Open built a client (%v), %v; want one that holds a kubectl", w != nil, err)
	}
	bare, err := Open(loopbackConfig(t, s, "writer", kube.Writer), nil, "")
	if bare == nil || err != nil {
		t.Fatalf("the writer without a kubeconfig: Open built a client (%v), %v", bare != nil, err)
	}
	err = bare.Apply(t.Context(), []byte("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: web\n"))
	if err == nil || err.Error() != "cluster: this client was opened without a kubeconfig, and Apply still runs kubectl until ADR 0023 M2.7" {
		t.Errorf("Apply on a writer opened without a kubeconfig = %v", err)
	}
	if _, _, ran := kubectlRecord(t, saw); ran {
		t.Error("a refused Open or Apply ran kubectl")
	}
	if got := s.Requests(); len(got) != 0 {
		t.Errorf("Open and the refused Apply sent %d requests; they send nothing", len(got))
	}
}

// ADR 0023 M2.5 (A20-4), mutation 70c: a writer's Apply is the one call that
// still runs kubectl, until M2.7. It runs the kubectl the PATH it was opened
// with finds, over the kubeconfig it was opened with, as 'apply -f -' with the
// manifest on stdin, and sends nothing in-process: no token is minted and no
// API request is made. A writer opened where no kubectl is found says what
// deploying needs, as the writing commands' kubectl always has.
func TestAWriterAppliesThroughKubectlWithItsKubeconfig(t *testing.T) {
	bin, saw := recordingKubectl(t)
	t.Setenv("PATH", bin)
	s := kubetest.New(t)
	const kc = "/cfg/instances/atlas/kubeconfig.yaml"
	manifest := []byte("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: web\n---\napiVersion: v1\nkind: Namespace\nmetadata:\n  name: api\n")
	c := openWriter(t, s, kc, nil)
	if err := c.Apply(t.Context(), manifest); err != nil {
		t.Fatal(err)
	}
	argv, stdin, ran := kubectlRecord(t, saw)
	if want := []string{"--kubeconfig", kc, "apply", "-f", "-"}; !ran || !slices.Equal(argv, want) {
		t.Errorf("kubectl ran (%v) with %q, want %q", ran, argv, want)
	}
	if !bytes.Equal(stdin, manifest) {
		t.Errorf("kubectl's stdin = %q, want the manifest", stdin)
	}
	if got := s.Requests(); len(got) != 0 {
		t.Errorf("Apply sent %d requests in-process; it runs kubectl alone", len(got))
	}

	t.Setenv("PATH", t.TempDir())
	err := openWriter(t, s, kc, nil).Apply(t.Context(), manifest)
	const missing = "kubectl not found on PATH — deploying into an instance needs kubectl and the gke-gcloud-auth-plugin"
	if !errors.Is(err, errKubectlMissing) || err.Error() != missing {
		t.Errorf("Apply with no kubectl on the PATH = %v, want %q", err, missing)
	}
	if got := s.Requests(); len(got) != 0 {
		t.Errorf("a missing kubectl sent %d requests", len(got))
	}
}

// ADR 0023 M2.5 (S-F2): ApplyReady says, running nothing and sending
// nothing, what Apply would refuse before kubectl reads a byte: a reader
// never applies, a writer opened without a kubeconfig cannot, and an Open'd
// writer needs kubectl on the PATH it was opened with and its kubeconfig in
// place. Each refusal is Apply's own; a writer with both is ready, and so is
// a test-built runner that is not kubectl.
func TestApplyReadySaysWhatApplyWouldRefuseRunningNothing(t *testing.T) {
	bin, saw := recordingKubectl(t)
	t.Setenv("PATH", bin)
	s := kubetest.New(t)
	kc := filepath.Join(t.TempDir(), "kubeconfig.yaml")
	if err := os.WriteFile(kc, []byte("apiVersion: v1\nkind: Config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := openWriter(t, s, kc, nil).ApplyReady(); err != nil {
		t.Errorf("a writer with kubectl and its kubeconfig: ApplyReady = %v", err)
	}
	if err := openReader(t, s, nil).ApplyReady(); !errors.Is(err, errNeverWrites) {
		t.Errorf("the reader: ApplyReady = %v, want %v", err, errNeverWrites)
	}
	if err := openWriter(t, s, "", nil).ApplyReady(); !errors.Is(err, errNoKubeconfig) {
		t.Errorf("a writer opened without a kubeconfig: ApplyReady = %v, want %v", err, errNoKubeconfig)
	}
	gone := filepath.Join(t.TempDir(), "kubeconfig.yaml")
	err := openWriter(t, s, gone, nil).ApplyReady()
	if !errors.Is(err, os.ErrNotExist) || !strings.HasPrefix(err.Error(), "this machine has no kubeconfig for the instance, which kubectl applies through until ADR 0023 M2.7 (") ||
		!strings.Contains(err.Error(), gone) {
		t.Errorf("a writer whose kubeconfig is not there: ApplyReady = %v", err)
	}
	if err := newWithRunner(&fakeRunner{}).ApplyReady(); err != nil {
		t.Errorf("a test-built runner: ApplyReady = %v", err)
	}

	// No kubectl on the PATH the writer was opened with: Apply's own
	// refusal, word for word, whichever kubeconfig it holds.
	t.Setenv("PATH", t.TempDir())
	const missing = "kubectl not found on PATH — deploying into an instance needs kubectl and the gke-gcloud-auth-plugin"
	for _, legacy := range []string{kc, gone} {
		w := openWriter(t, s, legacy, nil)
		ready := w.ApplyReady()
		if !errors.Is(ready, errKubectlMissing) || ready.Error() != missing {
			t.Errorf("no kubectl, kubeconfig %s: ApplyReady = %v, want %q", legacy, ready, missing)
		}
		if applied := w.Apply(t.Context(), []byte("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: web\n")); applied == nil || applied.Error() != ready.Error() {
			t.Errorf("no kubectl: Apply = %v; ApplyReady said %v", applied, ready)
		}
	}
	if _, _, ran := kubectlRecord(t, saw); ran {
		t.Error("ApplyReady ran kubectl")
	}
	if got := s.Requests(); len(got) != 0 {
		t.Errorf("ApplyReady sent %d requests; it sends nothing", len(got))
	}
}

// ADR 0023 M2.5 (A20-4): a writer reads in-process, as the writer. Every
// read, CanI and NamespaceUID reach the API server with the writer's token,
// and none runs kubectl, which the writer holds for Apply alone.
func TestAWriterReadsInProcessAsTheWriter(t *testing.T) {
	bin, saw := recordingKubectl(t)
	t.Setenv("PATH", bin)
	s := kubetest.New(t)
	managed := map[string]string{"app.kubernetes.io/managed-by": "farcast"}
	s.Put(namespace("farcast-system", managed))
	s.Put(object("v1", "ConfigMap", "farcast-system", "datasphered-pin", map[string]any{"data": map[string]any{"pin": "x"}}))
	s.Put(rolloutState(1, 1, 1, 1, 1, 1, ""))
	s.Put(serviceWith(map[string]any{"ip": "203.0.113.5"}))
	s.Put(jobObject("fetch", []string{"git"}, map[string]any{"succeeded": 1}))
	s.Put(podObject("farcast-system", "fetch-abc", map[string]string{"job-name": "fetch"}, []string{"git"},
		map[string]string{kubetest.LogAnnotationPrefix + "git": "manifest\n"}))
	s.Put(workloadObject("Deployment", "apps", "api"))
	s.Put(podObject("apps", "api-1", map[string]string{"app": "api"}, []string{"app"},
		map[string]string{kubetest.LogAnnotationPrefix + "app": "log line\n"}))
	c := openWriter(t, s, "/cfg/instances/atlas/kubeconfig.yaml", nil)
	ctx := t.Context()
	var out bytes.Buffer
	for _, read := range []struct {
		name string
		call func() (bool, error)
	}{
		{"Namespaces", func() (bool, error) {
			names, err := c.Namespaces(ctx)
			return slices.Equal(names, []string{"farcast-system"}), err
		}},
		{"NamespacesLabelled", func() (bool, error) {
			names, err := c.NamespacesLabelled(ctx, "app.kubernetes.io/managed-by=farcast")
			return slices.Equal(names, []string{"farcast-system"}), err
		}},
		{"NamespaceUID", func() (bool, error) {
			uid, err := c.NamespaceUID(ctx, "farcast-system")
			return uid != "", err
		}},
		{"ConfigMapValue", func() (bool, error) {
			v, found, err := c.ConfigMapValue(ctx, "farcast-system", "datasphered-pin", "pin")
			return v == "x" && found, err
		}},
		{"ConfigMapData", func() (bool, error) {
			data, rv, found, err := c.ConfigMapData(ctx, "farcast-system", "datasphered-pin")
			return data["pin"] == "x" && rv != "" && found, err
		}},
		{"Workloads", func() (bool, error) {
			ws, err := c.Workloads(ctx, "apps")
			return len(ws) == 1 && ws[0].Name == "api", err
		}},
		{"RolloutStatus", func() (bool, error) {
			return true, c.RolloutStatus(ctx, "farcast-system", "fatline", time.Minute)
		}},
		{"WaitExternalIP", func() (bool, error) {
			ip, err := c.WaitExternalIP(ctx, "farcast-system", "fatline", time.Minute)
			return ip == "203.0.113.5", err
		}},
		{"WaitJob", func() (bool, error) {
			res, err := c.WaitJob(ctx, "farcast-system", "fetch", time.Minute)
			return res.Succeeded, err
		}},
		{"JobLogs", func() (bool, error) {
			logs, err := c.JobLogs(ctx, "farcast-system", "fetch", 0)
			return logs == "manifest\n", err
		}},
		{"Logs", func() (bool, error) {
			err := c.Logs(ctx, &out, "apps", "deployment/api", -1, false, false)
			return out.String() == "log line\n", err
		}},
		{"CanI", func() (bool, error) {
			_, err := c.CanI(ctx, kube.ResourceAttributes{Namespace: "farcast-system", Verb: "get", Resource: "configmaps"})
			return true, err
		}},
	} {
		if ok, err := read.call(); !ok || err != nil {
			t.Errorf("%s as the writer = %v, %v", read.name, ok, err)
		}
	}
	reqs := s.Requests()
	if len(reqs) < 13 || reqs[0].Path != "/token" {
		t.Fatalf("%d requests; want one mint, then a request or more for each of the 12 reads", len(reqs))
	}
	for _, r := range reqs {
		if r.As != "writer" {
			t.Errorf("%s %s as %q; want every request as the writer", r.Method, r.Path, r.As)
		}
	}
	if _, _, ran := kubectlRecord(t, saw); ran {
		t.Error("a writer's read ran kubectl")
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

// ADR 0023 M2.4 (A18-2): a reader client refuses every write before anything
// is sent: no token is minted and no request reaches the server. It never
// falls through to kubectl, which it does not have. Since ADR 0023 M2.5 the
// refusal keys on the identity: a writer writes (TestConfigMapWritesNeverApply).
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

// ADR 0023 M2.5 (A20-5, A20-6): a Client with no in-process client, which
// only this package's tests build (newWithEnv) until kubectl goes in M2.7,
// has every method but Apply refuse, naming the method, with its zero values:
// the seven reads the writing commands ran through kubectl before M2.5 among
// them, and the pin's create and replace. None dereferences a nil kube, and
// none falls through to kubectl.
func TestAKubectlClientHasNoCanI(t *testing.T) {
	// A kubectl that would answer, should a refusal ever fall through to one:
	// it leaves a mark, and the test reads that nothing ran.
	bin := t.TempDir()
	ran := filepath.Join(t.TempDir(), "ran")
	if err := os.WriteFile(filepath.Join(bin, "kubectl"), []byte("#!/bin/sh\ntouch '"+ran+"'\necho '{\"items\":[]}'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	c := newWithEnv("/cfg/instances/atlas/kubeconfig.yaml", []string{"PATH=" + bin})
	ctx := context.Background()
	pin := []byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"datasphered-pin","namespace":"farcast-system","resourceVersion":"7"},"data":{"pin":"x"}}`)
	var out bytes.Buffer
	for _, m := range []struct {
		name string
		// call returns whether every other result was its zero value.
		call func() (bool, error)
	}{
		{"CanI", func() (bool, error) {
			ok, err := c.CanI(ctx, kube.ResourceAttributes{Verb: "get", Resource: "secrets"})
			return !ok, err
		}},
		{"NamespaceUID", func() (bool, error) {
			uid, err := c.NamespaceUID(ctx, "farcast-system")
			return uid == "", err
		}},
		{"Namespaces", func() (bool, error) {
			names, err := c.Namespaces(ctx)
			return names == nil, err
		}},
		{"NamespacesLabelled", func() (bool, error) {
			names, err := c.NamespacesLabelled(ctx, "a=b")
			return names == nil, err
		}},
		{"Workloads", func() (bool, error) {
			ws, err := c.Workloads(ctx, "web")
			return ws == nil, err
		}},
		{"ConfigMapValue", func() (bool, error) {
			v, found, err := c.ConfigMapValue(ctx, "farcast-system", "technocore-ledger", "checkpoint.json")
			return v == "" && !found, err
		}},
		{"ConfigMapData", func() (bool, error) {
			data, rv, found, err := c.ConfigMapData(ctx, "farcast-system", "datasphered-pin")
			return data == nil && rv == "" && !found, err
		}},
		{"CreateConfigMap", func() (bool, error) { return true, c.CreateConfigMap(ctx, pin) }},
		{"ReplaceConfigMap", func() (bool, error) { return true, c.ReplaceConfigMap(ctx, pin) }},
		{"RolloutStatus", func() (bool, error) {
			return true, c.RolloutStatus(ctx, "farcast-system", "fatline", time.Minute)
		}},
		{"WaitExternalIP", func() (bool, error) {
			ip, err := c.WaitExternalIP(ctx, "farcast-system", "fatline", time.Minute)
			return ip == "", err
		}},
		{"WaitJob", func() (bool, error) {
			res, err := c.WaitJob(ctx, "farcast-system", "build", time.Minute)
			return res == (JobResult{}), err
		}},
		// ADR 0023 M2.6 (A23-46, A28-7): DeploymentState holds a map, so its
		// zero value is checked field by field.
		{"DeploymentState", func() (bool, error) {
			st, err := c.DeploymentState(ctx, "web", "api")
			return !st.Present && st.Replicas == nil && st.Requests == nil && st.AdaptedAt.IsZero() && st.LastAppliedAt.IsZero() && st.ResourceVersion == "", err
		}},
		{"JobState", func() (bool, error) {
			res, found, err := c.JobState(ctx, "farcast-system", "fetch")
			return res == (JobResult{}) && !found, err
		}},
		{"JobLogs", func() (bool, error) {
			logs, err := c.JobLogs(ctx, "farcast-system", "fetch", 0)
			return logs == "", err
		}},
		{"Logs", func() (bool, error) {
			return true, c.Logs(ctx, &out, "web", "deployment/api", 10, false, false)
		}},
		{"Logs, followed", func() (bool, error) {
			return true, c.Logs(ctx, &out, "web", "deployment/api", 10, true, false)
		}},
	} {
		method, _, _ := strings.Cut(m.name, ",")
		zero, err := m.call()
		if want := "cluster: " + method + " is in-process only, and this client runs kubectl"; !zero || err == nil || err.Error() != want {
			t.Errorf("%s on a client with no in-process client = zero values %v, %v; want %q", m.name, zero, err, want)
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

// ADR 0023 M2.5 (A20-4): a writer's create and replace of a ConfigMap write
// the warnings their answers carried, a refused create's included, after the
// call and before it returns.
func TestAWritersConfigMapWritesWriteTheirWarnings(t *testing.T) {
	s := kubetest.New(t, kubetest.WithWarnings(func(r kubetest.Request) []string {
		switch {
		case r.Method == http.MethodPost && r.Path == "/api/v1/namespaces/farcast-system/configmaps":
			return []string{"created " + strconv.Itoa(len(r.Body))}
		case r.Method == http.MethodPut:
			return []string{"replaced"}
		}
		return nil
	}))
	var w bytes.Buffer
	c := openWriter(t, s, "", &w)
	ctx := t.Context()

	created := renderPin(t, `{"pin":1}`, "")
	if err := c.CreateConfigMap(ctx, created); err != nil {
		t.Fatal(err)
	}
	if got, want := w.String(), "Warning (cluster): created "+strconv.Itoa(len(created))+"\n"; got != want {
		t.Errorf("after the create: %q, want %q", got, want)
	}
	_, rv, _, err := c.ConfigMapData(ctx, "farcast-system", "datasphered-pin")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.ReplaceConfigMap(ctx, renderPin(t, `{"pin":2}`, rv)); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimPrefix(w.String(), "Warning (cluster): created "+strconv.Itoa(len(created))+"\n"); got != "Warning (cluster): replaced\n" {
		t.Errorf("after the replace: %q appended", got)
	}
	again := renderPin(t, `{"pin":10}`, "")
	before := w.String()
	if err := c.CreateConfigMap(ctx, again); !errors.Is(err, tkube.ErrConflict) {
		t.Fatalf("a create over the pin = %v", err)
	}
	if got := strings.TrimPrefix(w.String(), before); got != "Warning (cluster): created "+strconv.Itoa(len(again))+"\n" {
		t.Errorf("after a refused create: %q appended, want its own warning", got)
	}
}
