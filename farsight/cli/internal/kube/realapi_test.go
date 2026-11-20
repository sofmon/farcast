//go:build realapi

// The no-cost suite on a real API server (ADR 0023 M2.7, design §10.6 as
// A30-18 amends it, and M2.9a, which removed the migration and its tests:
// design §37, A37-9). It runs only by docs/runbooks/adr-0023-m2-realapi.md:
// an envtest kube-apiserver and etcd on the keeper VM, listening on that
// machine's loopback, reached from the Mac through ssh -L. ./check.sh
// type-checks and lints this file, and never runs it. R6 runs its tests by
// name, so none of the package's unit tests runs beside them.
//
// It reads three variables:
//   - FARCAST_REALAPI_ENDPOINT, 127.0.0.1:<port>, the Mac's end of the forward;
//   - FARCAST_REALAPI_CA_FILE, the server's self-signed certificate;
//   - FARCAST_REALAPI_TOKEN_FILE, a static bearer for a user in system:masters.
//
// Without all three every test fails, and none skips, so a tagged run cannot
// pass by testing nothing.
//
// The token is read once, trimmed, and used only as the bearer: it is never
// printed and never put in a message. The suite starts no process, and it
// dials only the endpoint. Each test writes into a namespace of its own, whose
// name ends in a suffix drawn once per run (runNamespace). kube deletes nothing
// but Secrets, so this is what lets a second run work against the same server.
//
// What a test records it logs on a line that carries "fact: ", after the
// "realapi_test.go:<line>: " every test log line begins with, scrubbed:
// managers, operations, subresources, field paths, HTTP codes, kinds and
// generation moves. No such line carries a uid, a resourceVersion, an address
// or a token. R8 copies only these lines into the records.
//
// Some helpers write around Apply on purpose, because Apply refuses what they
// send or is not the write they make, and each says so: rawApply (a second
// applier, and a body that carries a resourceVersion no AllowResourceVersion
// let through) and mergePatch (another manager's merge patch).
package kube

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/auth"

	tkube "github.com/sofmon/farcast/technocore/kube"
)

// The suite's environment (R6).
const (
	envRealAPIEndpoint  = "FARCAST_REALAPI_ENDPOINT"
	envRealAPICAFile    = "FARCAST_REALAPI_CA_FILE"
	envRealAPITokenFile = "FARCAST_REALAPI_TOKEN_FILE"
)

// realAPIEmail is the identity newClient pairs with a loopback endpoint: a
// credential under .invalid, which goes to a loopback endpoint and nowhere
// else (§3.2). It signs nothing: the token is the file's.
const realAPIEmail = "realapi@realapi.invalid"

// mediaMergePatch is the content type of a JSON merge patch, another
// manager's write that kube never sends.
const mediaMergePatch = "application/merge-patch+json"

// realAPIEnv is the suite's environment, read once per run.
type realAPIEnv struct {
	endpoint  string   // FARCAST_REALAPI_ENDPOINT, as given; only scrub uses it
	ep        Endpoint // classified by ParseEndpoint: loopback, trusted on the CA file alone
	tokenFile string   // the kernel's client reads the bearer from it itself
	token     string   // trimmed; never printed
	suffix    string   // runNamespace's, drawn once per run
}

var (
	realAPIOnce sync.Once
	realAPIVal  realAPIEnv
	realAPIErr  error
)

// loadRealAPIEnv reads the environment, the CA file and the token file once.
// Every test calls it before it dials anything.
func loadRealAPIEnv() (realAPIEnv, error) {
	realAPIOnce.Do(func() { realAPIVal, realAPIErr = readRealAPIEnv() })
	return realAPIVal, realAPIErr
}

func readRealAPIEnv() (realAPIEnv, error) {
	var missing []string
	get := func(name string) string {
		v := os.Getenv(name)
		if v == "" {
			missing = append(missing, name)
		}
		return v
	}
	endpoint, caFile, tokenFile := get(envRealAPIEndpoint), get(envRealAPICAFile), get(envRealAPITokenFile)
	if len(missing) > 0 {
		return realAPIEnv{}, fmt.Errorf("the real-API suite needs %s set (docs/runbooks/adr-0023-m2-realapi.md, R6); it fails rather than skips, so a tagged run cannot pass by testing nothing", strings.Join(missing, ", "))
	}
	caPEM, err := readNamedFile(envRealAPICAFile, caFile)
	if err != nil {
		return realAPIEnv{}, err
	}
	raw, err := readNamedFile(envRealAPITokenFile, tokenFile)
	if err != nil {
		return realAPIEnv{}, err
	}
	token := strings.TrimSpace(string(raw))
	clear(raw)
	if token == "" {
		return realAPIEnv{}, fmt.Errorf("the file %s names holds no token", envRealAPITokenFile)
	}
	ep, err := ParseEndpoint(endpoint, "", caPEM)
	if err != nil {
		return realAPIEnv{}, fmt.Errorf("%s: %w", envRealAPIEndpoint, err)
	}
	if ep.Mode != ModeLoopback {
		return realAPIEnv{}, fmt.Errorf("%s must be a loopback endpoint, 127.0.0.1:<port>", envRealAPIEndpoint)
	}
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return realAPIEnv{}, err
	}
	return realAPIEnv{endpoint: endpoint, ep: ep, tokenFile: tokenFile, token: token, suffix: hex.EncodeToString(b[:])}, nil
}

// readNamedFile reads the file a variable names. Its error names the
// variable and the cause, never the path, which is under the operator's
// run directory.
func readNamedFile(variable, path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return nil, fmt.Errorf("the file %s names cannot be read: %w", variable, err)
	}
	return b, nil
}

// scrub takes the endpoint out of a message: a transport's words name it.
func (e realAPIEnv) scrub(s string) string {
	for _, a := range []string{e.endpoint, net.JoinHostPort(e.ep.Host, e.ep.Port)} {
		if a != "" {
			s = strings.ReplaceAll(s, a, "<endpoint>")
		}
	}
	return s
}

// staticToken is the suite's tokenFunc: the token file's bearer, with no
// expiry, which the cache holds until a 401 drops it (token.go).
func staticToken(value string) tokenFunc {
	return func(context.Context) (*auth.Token, error) { return &auth.Token{Value: value}, nil }
}

// realAPI is one test's view of the server: the environment, and farcast's
// own client, built by the in-package newClient with the static token.
type realAPI struct {
	env realAPIEnv
	c   *Client
}

// openRealAPI checks the environment first, and fails the test without it,
// before anything is dialed. Then it builds the client and waits up to 60 s
// for GET /readyz.
func openRealAPI(t *testing.T) *realAPI {
	t.Helper()
	env, err := loadRealAPIEnv()
	if err != nil {
		t.Fatal(err)
	}
	r := &realAPI{env: env}
	r.c = r.client(t)
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	for {
		_, err := r.c.do(ctx, call{method: http.MethodGet, path: "/readyz", retry: true})
		if err == nil {
			return r
		}
		select {
		case <-ctx.Done():
			t.Fatalf("GET /readyz did not succeed within 60 s: %s", env.scrub(err.Error()))
		case <-time.After(time.Second):
		}
	}
}

// client is a new client on the same endpoint, as the writer, which has
// sent nothing yet.
func (r *realAPI) client(t *testing.T) *Client {
	t.Helper()
	c, err := newClient(Config{Endpoint: r.env.ep, Credential: Credential{Email: realAPIEmail}, Identity: Writer}, staticToken(r.env.token))
	if err != nil {
		t.Fatal(r.env.scrub(err.Error()))
	}
	return c
}

// kernel is TechnoCore's own client (technocore/kube.New) on the endpoint.
// Its transport is the in-process client's (newTransport): no proxy, TLS
// trusting the CA file alone, and a dialer that refuses every address but the
// endpoint's. It reads the bearer from the token file itself, on every
// request, as the kernel reads its own.
func (r *realAPI) kernel(t *testing.T, ns string) *tkube.Client {
	t.Helper()
	hc := &http.Client{Transport: newTransport(r.env.ep, responseHeaderTimeout), CheckRedirect: noRedirect, Timeout: requestTimeout}
	k, err := tkube.New(r.env.ep.BaseURL(), r.env.tokenFile, ns, hc)
	if err != nil {
		t.Fatal(r.env.scrub(err.Error()))
	}
	return k
}

// check fails the test on err, scrubbed.
func (r *realAPI) check(t *testing.T, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %s", what, r.env.scrub(err.Error()))
	}
}

// fact logs one recorded fact. Its arguments are scrubbed by construction:
// managers, operations, subresources, field paths, codes, kinds and
// generations, never a uid, a resourceVersion, an address or a token.
func fact(t *testing.T, format string, args ...any) {
	t.Helper()
	t.Logf("fact: "+format, args...)
}

// runNamespace creates, with Apply, a namespace of the test's own: its tag
// and the run's suffix, so a second run against the same server writes fresh
// objects. Nothing is cleaned up: kube deletes nothing but Secrets, and R9
// deletes the whole server.
func (r *realAPI) runNamespace(t *testing.T, tag string) string {
	t.Helper()
	name := "realapi-" + tag + "-" + r.env.suffix
	r.apply(t, fmt.Sprintf("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: %s\n  labels:\n    app.kubernetes.io/managed-by: farcast\n", name), true)
	return name
}

// document is SplitStream's one document of text.
func document(t *testing.T, text string) Document {
	t.Helper()
	docs, err := SplitStream([]byte(text))
	if err != nil || len(docs) != 1 {
		t.Fatalf("the test's document does not split into one: %d, %v", len(docs), err)
	}
	return docs[0]
}

// apply is farcast's own Apply of one document.
func (r *realAPI) apply(t *testing.T, text string, force bool) ObjectMeta {
	t.Helper()
	d := document(t, text)
	md, err := r.c.Apply(t.Context(), d, force)
	r.check(t, err, fmt.Sprintf("Apply of %s %s", d.Kind.Kind, d.Name))
	return md
}

// object is GetObject, failing the test on an error.
func (r *realAPI) object(t *testing.T, k Kind, ns, name string) Object {
	t.Helper()
	o, err := r.c.GetObject(t.Context(), k, ns, name)
	r.check(t, err, "GetObject of "+k.Kind+" "+name)
	return o
}

// rawGet reads path with a plain GET and decodes the whole answer into a
// map, for assertions on values no typed read declares. It is a read; it
// writes nothing around Apply.
func (r *realAPI) rawGet(ctx context.Context, path string) (map[string]any, error) {
	b, err := r.c.do(ctx, call{method: http.MethodGet, path: path, retry: true})
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("the answer to GET %s does not decode", path)
	}
	return m, nil
}

// raw is rawGet, failing the test on an error.
func (r *realAPI) raw(t *testing.T, path string) map[string]any {
	t.Helper()
	m, err := r.rawGet(t.Context(), path)
	r.check(t, err, "GET "+path)
	return m
}

// rawApply is one server-side apply, as Apply sends it, with the field
// manager and force given and none of Apply's checks: its query is
// fieldManager=<manager>, fieldValidation=Strict and force. It bypasses Apply
// on purpose, for the bodies Apply refuses (one carrying a resourceVersion
// that no AllowResourceVersion let through) and for a second applier. It
// returns the answer's metadata and, with no error, the answer's own 2xx
// status: 201 when the apply created the object, which c.decode does not
// tell from 200.
func (r *realAPI) rawApply(ctx context.Context, k Kind, ns, name string, body []byte, manager string, force bool) (ObjectMeta, int, error) {
	cl := call{
		method:      http.MethodPatch,
		path:        k.Path(ns, name),
		query:       url.Values{"fieldManager": {manager}, "fieldValidation": {"Strict"}, "force": {strconv.FormatBool(force)}},
		contentType: mediaApplyPatch,
		body:        body,
		retry:       true,
	}
	resp, done, err := r.c.open(ctx, cl)
	if err != nil {
		return ObjectMeta{}, 0, err
	}
	defer done()
	b, err := readCapped(ctx, resp.Body, cl)
	if err != nil {
		return ObjectMeta{}, 0, err
	}
	var answer struct {
		Metadata ObjectMeta `json:"metadata"`
	}
	if err := json.Unmarshal(b, &answer); err != nil {
		return ObjectMeta{}, 0, refuse(ErrUnreadable, msgAnswerUnread, cl.method, cl.path)
	}
	return answer.Metadata, resp.StatusCode, nil
}

// applied is the HTTP status a rawApply ended with: its own 2xx status for no
// error, or answered's code.
func (r *realAPI) applied(t *testing.T, code int, err error) int {
	t.Helper()
	if err == nil {
		return code
	}
	return r.answered(t, err)
}

// answered is the HTTP status a write ended with: 200 for no error, or an
// APIError's code. Any other error, such as no answer at all, fails the test.
// It is for writes that cannot create, such as an Apply of an object that
// exists, whose success is 200; rawApply's callers use applied.
func (r *realAPI) answered(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return http.StatusOK
	}
	var ae *APIError
	if !errors.As(err, &ae) {
		t.Fatalf("not answered: %s", r.env.scrub(err.Error()))
	}
	return ae.Status.Code
}

// entryName is a managed-fields entry as the facts name it:
// manager/operation, then /subresource when one is set.
func entryName(e ManagedFieldsEntry) string {
	s := e.Manager + "/" + e.Operation
	if e.Subresource != "" {
		s += "/" + e.Subresource
	}
	return s
}

// entryNames is every entry of md, as entryName names it, in list order.
func entryNames(md ObjectMeta) []string {
	out := make([]string, 0, len(md.ManagedFields))
	for _, e := range md.ManagedFields {
		out = append(out, entryName(e))
	}
	return out
}

// owns, which reads an entry's fieldsV1, is in owns_test.go, untagged, so
// that ./check.sh runs its own test.

// field reads a nested value of a decoded object, nil when a step is missing.
func field(v any, path ...string) any {
	for _, p := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[p]
	}
	return v
}

// itemNames lists the name of each item of a list of objects.
func itemNames(v any) []string {
	list, _ := v.([]any)
	var out []string
	for _, it := range list {
		if n, ok := field(it, "name").(string); ok {
			out = append(out, n)
		}
	}
	return out
}

// container is the pod template's container of that name, nil without one.
func container(obj map[string]any, name string) any {
	list, _ := field(obj, "spec", "template", "spec", "containers").([]any)
	for _, c := range list {
		if field(c, "name") == name {
			return c
		}
	}
	return nil
}

// keysOf is a map's keys, sorted.
func keysOf(v any) []string {
	m, _ := v.(map[string]any)
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// The suite's marker values. Nothing here is a real secret or a real address.
const (
	markerProxy   = "realapi-marker-proxy"
	markerDropped = "realapi-marker-dropped"
	seedV1        = "v1"
)

// doc fills a document template: {ns}, {seed} (the seed label's value,
// seedV1), {replicas} (2 unless more says otherwise), and the base64 of the
// Secret's two markers. Pairs in more come first, so they win.
func doc(tmpl, ns, seed string, more ...string) string {
	pairs := append(slices.Clone(more),
		"{ns}", ns, "{seed}", seed, "{replicas}", "2",
		"{proxy64}", base64.StdEncoding.EncodeToString([]byte(markerProxy)),
		"{dropped64}", base64.StdEncoding.EncodeToString([]byte(markerDropped)))
	return strings.NewReplacer(pairs...).Replace(tmpl)
}

// The documents, in the renderers' shape (FatLine's and TechnoCore's
// Deployments, an application's Deployment, Service, egress Secret, ConfigMap
// and NetworkPolicy, a build Job), with marker values only. Each v2 drops one
// thing its v1 has (§6.8).

const fatlineV1 = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: fatline
  namespace: {ns}
  labels:
    app.kubernetes.io/name: fatline
    app.kubernetes.io/managed-by: farcast
    realapi.farcast.sofmon.com/seed: {seed}
spec:
  replicas: {replicas}
  selector:
    matchLabels:
      app.kubernetes.io/name: fatline
  template:
    metadata:
      labels:
        app.kubernetes.io/name: fatline
        app.kubernetes.io/managed-by: farcast
    spec:
      automountServiceAccountToken: false
      containers:
        - name: fatline
          image: registry.invalid/realapi/fatline:marker
          args:
            - --tunnel-listen=:8443
            - --policy=/etc/fatline/policy/policy.json
            - --shrike-socket=/run/fatline/shrike.sock
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
          volumeMounts:
            - name: policy
              mountPath: /etc/fatline/policy
              readOnly: true
            - name: shrike-wire
              mountPath: /run/fatline
        - name: shrike
          image: registry.invalid/realapi/shrike:marker
          args:
            - --socket=/run/fatline/shrike.sock
          resources:
            requests:
              cpu: 10m
              memory: 32Mi
          volumeMounts:
            - name: shrike-wire
              mountPath: /run/fatline
      volumes:
        - name: shrike-wire
          emptyDir: {}
        - name: policy
          configMap:
            name: fatline-policy
            optional: true
`

const fatlineV2 = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: fatline
  namespace: {ns}
  labels:
    app.kubernetes.io/name: fatline
    app.kubernetes.io/managed-by: farcast
    realapi.farcast.sofmon.com/seed: {seed}
spec:
  replicas: {replicas}
  selector:
    matchLabels:
      app.kubernetes.io/name: fatline
  template:
    metadata:
      labels:
        app.kubernetes.io/name: fatline
        app.kubernetes.io/managed-by: farcast
    spec:
      automountServiceAccountToken: false
      containers:
        - name: fatline
          image: registry.invalid/realapi/fatline:marker
          args:
            - --tunnel-listen=:8443
            - --policy=/etc/fatline/policy/policy.json
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
          volumeMounts:
            - name: policy
              mountPath: /etc/fatline/policy
              readOnly: true
      volumes:
        - name: policy
          configMap:
            name: fatline-policy
            optional: true
`

const technocoreV1 = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: technocore
  namespace: {ns}
  labels:
    app.kubernetes.io/name: technocore
    app.kubernetes.io/managed-by: farcast
    realapi.farcast.sofmon.com/seed: {seed}
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: technocore
  template:
    metadata:
      labels:
        app.kubernetes.io/name: technocore
        app.kubernetes.io/managed-by: farcast
    spec:
      containers:
        - name: technocore
          image: registry.invalid/realapi/technocore:marker
          args:
            - serve
            - --instance=realapi
            - --cost-limit=50
            - --adapt
            - --adapt-cooldown=10m0s
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
`

const technocoreV2 = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: technocore
  namespace: {ns}
  labels:
    app.kubernetes.io/name: technocore
    app.kubernetes.io/managed-by: farcast
    realapi.farcast.sofmon.com/seed: {seed}
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: technocore
  template:
    metadata:
      labels:
        app.kubernetes.io/name: technocore
        app.kubernetes.io/managed-by: farcast
    spec:
      containers:
        - name: technocore
          image: registry.invalid/realapi/technocore:marker
          args:
            - serve
            - --instance=realapi
            - --cost-limit=50
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
`

const appV1 = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: {ns}
  labels:
    app.kubernetes.io/name: api
    app.kubernetes.io/managed-by: farcast
    realapi.farcast.sofmon.com/seed: {seed}
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: api
  template:
    metadata:
      labels:
        app.kubernetes.io/name: api
        app.kubernetes.io/managed-by: farcast
    spec:
      containers:
        - name: api
          image: registry.invalid/realapi/api:marker
          env:
            - name: FARCAST_APP_NAME
              value: api
            - name: REALAPI_DROPPED
              value: realapi-marker-env
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
`

const appV2 = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: {ns}
  labels:
    app.kubernetes.io/name: api
    app.kubernetes.io/managed-by: farcast
    realapi.farcast.sofmon.com/seed: {seed}
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: api
  template:
    metadata:
      labels:
        app.kubernetes.io/name: api
        app.kubernetes.io/managed-by: farcast
    spec:
      containers:
        - name: api
          image: registry.invalid/realapi/api:marker
          env:
            - name: FARCAST_APP_NAME
              value: api
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
`

const serviceV1 = `apiVersion: v1
kind: Service
metadata:
  name: api
  namespace: {ns}
  labels:
    app.kubernetes.io/name: api
    app.kubernetes.io/managed-by: farcast
    farcast.sofmon.com/instance: realapi
    realapi.farcast.sofmon.com/seed: {seed}
spec:
  selector:
    app.kubernetes.io/name: api
  ports:
    - name: http
      port: 80
      targetPort: 8080
`

const serviceV2 = `apiVersion: v1
kind: Service
metadata:
  name: api
  namespace: {ns}
  labels:
    app.kubernetes.io/name: api
    app.kubernetes.io/managed-by: farcast
    realapi.farcast.sofmon.com/seed: {seed}
spec:
  selector:
    app.kubernetes.io/name: api
  ports:
    - name: http
      port: 80
      targetPort: 8080
`

// secretV1 is the egress Secret as farcast renders it since ADR 0023 M2.2:
// data:, base64 (SplitStream refuses stringData).
const secretV1 = `apiVersion: v1
kind: Secret
metadata:
  name: api-egress
  namespace: {ns}
  labels:
    app.kubernetes.io/name: api
    app.kubernetes.io/managed-by: farcast
    realapi.farcast.sofmon.com/seed: {seed}
data:
  FARCAST_FATLINE_PROXY: "{proxy64}"
  REALAPI_DROPPED: "{dropped64}"
`

const secretV2 = `apiVersion: v1
kind: Secret
metadata:
  name: api-egress
  namespace: {ns}
  labels:
    app.kubernetes.io/name: api
    app.kubernetes.io/managed-by: farcast
    realapi.farcast.sofmon.com/seed: {seed}
data:
  FARCAST_FATLINE_PROXY: "{proxy64}"
`

const configMapV1 = `apiVersion: v1
kind: ConfigMap
metadata:
  name: api
  namespace: {ns}
  labels:
    app.kubernetes.io/name: api
    app.kubernetes.io/managed-by: farcast
    realapi.farcast.sofmon.com/seed: {seed}
data:
  FARCAST_APP_NAME: api
  REALAPI_DROPPED: realapi-marker-configmap
`

const configMapV2 = `apiVersion: v1
kind: ConfigMap
metadata:
  name: api
  namespace: {ns}
  labels:
    app.kubernetes.io/name: api
    app.kubernetes.io/managed-by: farcast
    realapi.farcast.sofmon.com/seed: {seed}
data:
  FARCAST_APP_NAME: api
`

// The two egress rules' addresses are RFC 5737's documentation ranges.
const networkPolicyV1 = `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api
  namespace: {ns}
  labels:
    app.kubernetes.io/name: api
    app.kubernetes.io/managed-by: farcast
    realapi.farcast.sofmon.com/seed: {seed}
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: api
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 192.0.2.0/24
      ports:
        - protocol: TCP
          port: 443
    - to:
        - ipBlock:
            cidr: 198.51.100.0/24
      ports:
        - protocol: TCP
          port: 443
`

const networkPolicyV2 = `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api
  namespace: {ns}
  labels:
    app.kubernetes.io/name: api
    app.kubernetes.io/managed-by: farcast
    realapi.farcast.sofmon.com/seed: {seed}
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: api
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 192.0.2.0/24
      ports:
        - protocol: TCP
          port: 443
`

const jobV1 = `apiVersion: batch/v1
kind: Job
metadata:
  name: build-realapi-api
  namespace: {ns}
  labels:
    app.kubernetes.io/name: farcast-builder
    app.kubernetes.io/managed-by: farcast
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 600
  template:
    metadata:
      labels:
        app.kubernetes.io/name: farcast-builder
        app.kubernetes.io/managed-by: farcast
    spec:
      restartPolicy: Never
      automountServiceAccountToken: false
      containers:
        - name: kaniko
          image: registry.invalid/realapi/builder:marker
          args:
            - --context=dir:///workspace
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
`

// egressPolicyName is the name fatline/deploy gives the egress policy
// (PolicyConfigMap), which testdata/realapi/egress-policy.yaml renders.
const egressPolicyName = "fatline-egress-policy"

// policyConfigMap is a ConfigMap in the egress policy's shape, the kind of
// object design A30-40's resourceVersion precondition guards.
const policyConfigMap = `apiVersion: v1
kind: ConfigMap
metadata:
  name: fatline-policy
  namespace: {ns}
  labels:
    app.kubernetes.io/name: fatline
    app.kubernetes.io/managed-by: farcast
data:
  policy.json: "{policy}"
`

// withResourceVersion is text with metadata.resourceVersion set to rv, the
// body only rawApply sends.
func withResourceVersion(t *testing.T, text, ns, rv string) []byte {
	t.Helper()
	line := "  namespace: " + ns + "\n"
	if strings.Count(text, line) != 1 {
		t.Fatal("the document names its namespace other than once")
	}
	return []byte(strings.Replace(text, line, line+"  resourceVersion: \""+rv+"\"\n", 1))
}

// stuckCase is one of §6.8's cases: an object farcast applied as v1, then
// applied as v2, which drops one thing.
type stuckCase struct {
	name   string
	kind   Kind
	object string
	v1, v2 string
	// left names what of the dropped thing the object still holds, "" when
	// it is gone.
	left func(obj map[string]any) string
	// held is what left reads after v1's forced apply: all of what v2 drops.
	held string
}

func stuckCases() []stuckCase {
	return []stuckCase{
		{
			name: "a Deployment loses its Shrike container, its volume and its mount", kind: kindDeployment, object: "fatline", v1: fatlineV1, v2: fatlineV2,
			left: func(obj map[string]any) string {
				var left []string
				if slices.Contains(itemNames(field(obj, "spec", "template", "spec", "containers")), "shrike") {
					left = append(left, "the container shrike")
				}
				if slices.Contains(itemNames(field(obj, "spec", "template", "spec", "volumes")), "shrike-wire") {
					left = append(left, "the volume shrike-wire")
				}
				if slices.Contains(itemNames(field(container(obj, "fatline"), "volumeMounts")), "shrike-wire") {
					left = append(left, "fatline's mount of shrike-wire")
				}
				return strings.Join(left, ", ")
			},
			held: "the container shrike, the volume shrike-wire, fatline's mount of shrike-wire",
		},
		{
			name: "an argument leaves an atomic args list", kind: kindDeployment, object: "technocore", v1: technocoreV1, v2: technocoreV2,
			left: func(obj map[string]any) string {
				for _, a := range asList(field(container(obj, "technocore"), "args")) {
					if a == "--adapt" {
						return "the argument --adapt"
					}
				}
				return ""
			},
			held: "the argument --adapt",
		},
		{
			name: "an env entry leaves", kind: kindDeployment, object: "api", v1: appV1, v2: appV2,
			left: func(obj map[string]any) string {
				if slices.Contains(itemNames(field(container(obj, "api"), "env")), "REALAPI_DROPPED") {
					return "the env entry REALAPI_DROPPED"
				}
				return ""
			},
			held: "the env entry REALAPI_DROPPED",
		},
		{
			name: "a label leaves", kind: kindService, object: "api", v1: serviceV1, v2: serviceV2,
			left: func(obj map[string]any) string {
				if field(obj, "metadata", "labels", "farcast.sofmon.com/instance") != nil {
					return "the label farcast.sofmon.com/instance"
				}
				return ""
			},
			held: "the label farcast.sofmon.com/instance",
		},
		{
			name: "a Secret data key leaves", kind: kindSecret, object: "api-egress", v1: secretV1, v2: secretV2,
			left: func(obj map[string]any) string {
				if field(obj, "data", "REALAPI_DROPPED") != nil {
					return "the data key REALAPI_DROPPED"
				}
				return ""
			},
			held: "the data key REALAPI_DROPPED",
		},
		{
			name: "a ConfigMap data key leaves", kind: kindConfigMap, object: "api", v1: configMapV1, v2: configMapV2,
			left: func(obj map[string]any) string {
				if field(obj, "data", "REALAPI_DROPPED") != nil {
					return "the data key REALAPI_DROPPED"
				}
				return ""
			},
			held: "the data key REALAPI_DROPPED",
		},
		{
			name: "a NetworkPolicy egress rule leaves", kind: mustKind("networking.k8s.io/v1", "NetworkPolicy"), object: "api", v1: networkPolicyV1, v2: networkPolicyV2,
			left: func(obj map[string]any) string {
				for _, rule := range asList(field(obj, "spec", "egress")) {
					for _, to := range asList(field(rule, "to")) {
						if field(to, "ipBlock", "cidr") == "198.51.100.0/24" {
							return "the egress rule to 198.51.100.0/24"
						}
					}
				}
				return ""
			},
			held: "the egress rule to 198.51.100.0/24",
		},
	}
}

// asList is a decoded list, nil when v is not one.
func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

// TestForcedApplyRemovesAFieldDroppedFromTheManifest is §6.8's stuck-fields
// test as ADR 0023 M2.9a keeps it (design §37, A37-9; written, not run), one
// subtest per case: apply v1 forced, require the live object to hold all of
// what v2 drops (held), apply v2 forced, and check that it is gone. Without
// held, a v1 that never stored the field would pass. The field's assertion
// begins "stuck field: ", which R6 tells from any other failure.
func TestForcedApplyRemovesAFieldDroppedFromTheManifest(t *testing.T) {
	r := openRealAPI(t)
	ns := r.runNamespace(t, "stuck")
	for _, sc := range stuckCases() {
		t.Run(sc.name, func(t *testing.T) {
			r.apply(t, doc(sc.v1, ns, seedV1), true)
			if held := sc.left(r.raw(t, sc.kind.Path(ns, sc.object))); held != sc.held {
				t.Fatalf("after v1's forced apply the live %s holds %q, not %q: what v2 drops was not stored, so its absence would show nothing", sc.kind.Kind, held, sc.held)
			}
			r.apply(t, doc(sc.v2, ns, seedV1), true)
			if left := sc.left(r.raw(t, sc.kind.Path(ns, sc.object))); left != "" {
				t.Errorf("stuck field: %s is still on the live %s after v2's forced apply", left, sc.kind.Kind)
			}
			back := r.object(t, sc.kind, ns, sc.object)
			fact(t, "%s: after v1's and v2's forced applies, entries %v", sc.name, entryNames(back.Metadata))
		})
	}
}

// TestReapplyingAnUnchangedJobIsANoOp: a Job farcast applied gets a selector
// and template labels from the server's own defaulting, which kubetest's
// WithSettledWorkloads emulates [unverified there; recorded here]. Applying
// the same document again, unforced and then forced, must raise no conflict
// over them, which a Job's immutable template would turn into a refusal, and
// leave the generation where it was.
func TestReapplyingAnUnchangedJobIsANoOp(t *testing.T) {
	r := openRealAPI(t)
	ns := r.runNamespace(t, "job")
	ctx := t.Context()
	text := doc(jobV1, ns, seedV1)
	r.apply(t, text, true)
	created := r.object(t, kindJob, ns, "build-realapi-api").Metadata
	raw := r.raw(t, kindJob.Path(ns, "build-realapi-api"))
	fact(t, "the server's Job: spec.selector.matchLabels keys %v; spec.template.metadata.labels keys %v; entries %v",
		keysOf(field(raw, "spec", "selector", "matchLabels")), keysOf(field(raw, "spec", "template", "metadata", "labels")), entryNames(created))
	for _, force := range []bool{false, true} {
		_, err := r.c.Apply(ctx, document(t, text), force)
		code := r.answered(t, err)
		again := r.object(t, kindJob, ns, "build-realapi-api").Metadata
		fact(t, "the unchanged Job applied again, force=%t: %d; generation %d, then %d; resourceVersion moved: %t; entries %v",
			force, code, created.Generation, again.Generation, again.ResourceVersion != created.ResourceVersion, entryNames(again))
		if err != nil {
			t.Errorf("force=%t: the re-apply of an unchanged Job: %s", force, r.env.scrub(err.Error()))
			continue
		}
		if again.Generation != created.Generation {
			t.Errorf("force=%t: the re-apply moved metadata.generation from %d to %d", force, created.Generation, again.Generation)
		}
		if !slices.Equal(entryNames(again), entryNames(created)) {
			t.Errorf("force=%t: the entries went from %v to %v", force, entryNames(created), entryNames(again))
		}
	}
}

// TestApplyRefusesAStaleResourceVersion records what an apply whose body
// carries a resourceVersion answers. Its subtest "a stale resourceVersion"
// (a_stale_resourceVersion, as -test.v names it) decided step 3 (A30-40,
// A31-2): an apply whose body carries a resourceVersion the object has moved
// on from is refused with 409, which the egress policy's precondition needs.
// It passes only on 409. The subtest "a Secret deleted since it was read"
// only records what such an apply answers for a Secret deleted since it was
// read: 404, 409, or a 2xx that recreated it, which the precondition then
// cannot tell from a policy that was never there (§31 recorded 201). It fails
// only on any other answer, or on a 2xx that left no new Secret there. Both
// bodies go through rawApply, which takes a body Apply would refuse.
//
// The subtest "the egress policy at a stale resourceVersion" (A31-2) runs
// step 3's own path: the policy as fldeploy.RenderPolicyConfigMap renders it
// at a stale resourceVersion, split with AllowResourceVersion, is refused by
// Apply with a 409 that unwraps to tkube.ErrConflict, and nothing is written.
// The same render at the stored resourceVersion then applies. kube's tests
// may not import fatline/deploy (doc_test.go), so the render is read from
// testdata/realapi/egress-policy.yaml, which the cli package's
// TestTheRealAPIEgressPolicyIsTheRenderers pins to the renderer's output.
func TestApplyRefusesAStaleResourceVersion(t *testing.T) {
	r := openRealAPI(t)
	ns := r.runNamespace(t, "stale")
	ctx := t.Context()
	t.Run("a stale resourceVersion", func(t *testing.T) {
		r.apply(t, doc(policyConfigMap, ns, seedV1, "{policy}", "realapi-marker-one"), true)
		read := r.object(t, kindConfigMap, ns, "fatline-policy")
		r.apply(t, doc(policyConfigMap, ns, seedV1, "{policy}", "realapi-marker-two"), true)
		current := r.object(t, kindConfigMap, ns, "fatline-policy")
		body := withResourceVersion(t, doc(policyConfigMap, ns, seedV1, "{policy}", "realapi-marker-three"), ns, read.Metadata.ResourceVersion)
		_, ok, err := r.rawApply(ctx, kindConfigMap, ns, "fatline-policy", body, FieldManager, true)
		code := r.applied(t, ok, err)
		after := r.object(t, kindConfigMap, ns, "fatline-policy")
		fact(t, "an apply carrying a stale metadata.resourceVersion: %d; the object was written: %t", code, after.Metadata.ResourceVersion != current.Metadata.ResourceVersion)
		if code != http.StatusConflict || !errors.Is(err, tkube.ErrConflict) {
			t.Errorf("an apply carrying a stale metadata.resourceVersion answered %d, not 409: the server does not hold an apply to it, so the egress policy's precondition (A30-40) does not hold here", code)
		}
		if code == http.StatusConflict && after.Metadata.ResourceVersion != current.Metadata.ResourceVersion {
			t.Error("the refused apply still wrote the object")
		}
	})
	t.Run("a Secret deleted since it was read", func(t *testing.T) {
		text := doc(secretV1, ns, seedV1)
		r.apply(t, text, true)
		read := r.object(t, kindSecret, ns, "api-egress")
		r.check(t, r.c.DeleteSecret(ctx, ns, "api-egress", read.Metadata.UID), "DeleteSecret")
		_, ok, err := r.rawApply(ctx, kindSecret, ns, "api-egress", withResourceVersion(t, text, ns, read.Metadata.ResourceVersion), FieldManager, true)
		code := r.applied(t, ok, err)
		// After a 2xx, whether a new Secret is there: its uid is compared
		// with the one read, and never printed.
		recreated := false
		if err == nil {
			now := r.object(t, kindSecret, ns, "api-egress")
			recreated = now.Metadata.UID != "" && now.Metadata.UID != read.Metadata.UID
		}
		fact(t, "an apply carrying the resourceVersion of a Secret deleted since it was read: %d; the Secret was recreated: %t", code, recreated)
		switch {
		case code == http.StatusNotFound || code == http.StatusConflict:
		case code >= 200 && code < 300:
			if !recreated {
				t.Errorf("the apply answered %d, and the Secret there is the one deleted: the delete did not take", code)
			}
		default:
			t.Errorf("the apply answered %d, neither 404, 409 nor a 2xx", code)
		}
	})
	t.Run("the egress policy at a stale resourceVersion", func(t *testing.T) {
		file, err := os.ReadFile(filepath.Join("testdata", "realapi", "egress-policy.yaml"))
		r.check(t, err, "the egress policy's testdata")
		_, rendered, ok := strings.Cut(string(file), "\n---\n")
		if !ok {
			t.Fatal("testdata/realapi/egress-policy.yaml holds no --- line")
		}
		// at is the policy as run renders it into ns, one application whose
		// credential_sha256 is credential (a marker), at rv ("" for none),
		// split as cluster.ApplyAt splits it.
		at := func(t *testing.T, credential, rv string) Document {
			t.Helper()
			text := rendered
			if rv == "" {
				text = strings.Replace(text, "  resourceVersion: \"{rv}\"\n", "", 1)
			}
			text = strings.NewReplacer("{ns}", ns, "{credential}", credential, "{rv}", rv).Replace(text)
			docs, err := SplitStream([]byte(text), AllowResourceVersion(rv))
			if err != nil || len(docs) != 1 {
				t.Fatalf("the rendered policy does not split into one document: %d, %v", len(docs), err)
			}
			return docs[0]
		}
		first, err := r.c.Apply(ctx, at(t, strings.Repeat("1", 64), ""), true)
		r.check(t, err, "the policy's first Apply")
		_, err = r.c.Apply(ctx, at(t, strings.Repeat("2", 64), ""), true)
		r.check(t, err, "the policy's second Apply")
		current := r.object(t, kindConfigMap, ns, egressPolicyName)

		_, err = r.c.Apply(ctx, at(t, strings.Repeat("3", 64), first.ResourceVersion), true)
		code := r.answered(t, err)
		after := r.object(t, kindConfigMap, ns, egressPolicyName)
		written := after.Metadata.ResourceVersion != current.Metadata.ResourceVersion
		fact(t, "the egress policy rendered at a stale resourceVersion, split with AllowResourceVersion: Apply answered %d; the object was written: %t", code, written)
		if !errors.Is(err, tkube.ErrConflict) {
			t.Errorf("Apply of the policy at a stale resourceVersion answered %d, not a 409 unwrapping to tkube.ErrConflict", code)
		}
		if written {
			t.Error("the refused apply still wrote the policy")
		}

		_, err = r.c.Apply(ctx, at(t, strings.Repeat("4", 64), current.Metadata.ResourceVersion), true)
		code = r.answered(t, err)
		now := r.object(t, kindConfigMap, ns, egressPolicyName)
		written = now.Metadata.ResourceVersion != current.Metadata.ResourceVersion
		fact(t, "the egress policy rendered at the stored resourceVersion: Apply answered %d; the object was written: %t", code, written)
		if err != nil || !written {
			t.Errorf("Apply of the policy at the stored resourceVersion answered %d, the object written: %t; want it applied", code, written)
		}
	})
}

// TestMetadataOnlyListsCarryNoSecretData: what farcast asks for as metadata
// only (§2.1, A30-9) comes back without a Secret's values. The Secret is
// farcast's own forced apply, which carries no kubectl annotation (design
// §37, A37-9). A full GET first requires the stored Secret to hold a value
// under each of its two keys, or an answer without them would show nothing;
// the values are checked for presence only and never printed. Then it reads
// the raw answers of ListObjects, a raw partial list and GetObject, through
// TapAnswers.
func TestMetadataOnlyListsCarryNoSecretData(t *testing.T) {
	r := openRealAPI(t)
	ns := r.runNamespace(t, "metadata")
	ctx := t.Context()
	r.apply(t, doc(secretV1, ns, seedV1), true)
	stored, _ := field(r.raw(t, kindSecret.Path(ns, "api-egress")), "data").(map[string]any)
	for _, key := range []string{"FARCAST_FATLINE_PROXY", "REALAPI_DROPPED"} {
		if v, _ := stored[key].(string); v == "" {
			t.Fatalf("the stored Secret holds no value under %s, so an answer without data would show nothing", key)
		}
	}

	c := r.client(t)
	var mu sync.Mutex
	last := map[string][]byte{} // the last answer to each method
	TapAnswers(c, func(method, _ string, body []byte) {
		mu.Lock()
		defer mu.Unlock()
		last[method] = body
	})
	answer := func(method string) []byte {
		mu.Lock()
		defer mu.Unlock()
		return last[method]
	}

	objs, err := c.ListObjects(ctx, kindSecret, ns, "")
	r.check(t, err, "ListObjects")
	if len(objs) != 1 || objs[0].Metadata.Name != "api-egress" {
		t.Errorf("ListObjects decoded %d object(s); want the one Secret", len(objs))
	}
	noSecretValues(t, "ListObjects' answer", answer(http.MethodGet))

	b, err := c.do(ctx, call{method: http.MethodGet, path: kindSecret.ListPath(ns), accept: acceptPartialList, retry: true})
	r.check(t, err, "the raw partial list")
	noSecretValues(t, "a raw partial list", b)

	_, err = c.GetObject(ctx, kindSecret, ns, "api-egress")
	r.check(t, err, "GetObject")
	noSecretValues(t, "GetObject's answer", answer(http.MethodGet))
}

// noSecretValues fails when any object of a raw answer, or of its items,
// carries data or stringData, or kubectl's annotation, which farcast's apply
// never writes and whose value is never read. It records the answer's kind
// and each object's top-level keys.
func noSecretValues(t *testing.T, what string, body []byte) {
	t.Helper()
	var top map[string]any
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatalf("%s does not decode", what)
	}
	objs := []any{top}
	if items, ok := top["items"].([]any); ok {
		objs = items
	}
	if len(objs) == 0 {
		t.Errorf("%s holds no object", what)
	}
	var shapes [][]string
	for _, o := range objs {
		m, _ := o.(map[string]any)
		shapes = append(shapes, keysOf(m))
		for _, k := range []string{"data", "stringData"} {
			if _, ok := m[k]; ok {
				t.Errorf("%s carries %s", what, k)
			}
		}
		if field(m, "metadata", "annotations", lastAppliedAnnotation) != nil {
			t.Errorf("%s carries kubectl's annotation", what)
		}
	}
	fact(t, "%s: kind %v; the objects' top-level keys %v", what, top["kind"], shapes)
}

// TestStatusCauseWireName: a 409 from a server-side apply carries its
// conflicts as causes whose type's wire name is "reason" (errors.go,
// StatusCause), which FieldConflicts reads. A second applier sets a label;
// farcast's unforced apply of another value for it is refused. The kernel's
// /scale is not used for this, because whether it is tracked is itself what
// TestKernelWritesAreTrackedAsTechnocore records.
func TestStatusCauseWireName(t *testing.T) {
	r := openRealAPI(t)
	ns := r.runNamespace(t, "cause")
	ctx := t.Context()
	const label = "realapi.farcast.sofmon.com/owner"
	cm := func(owner string) string {
		s := fmt.Sprintf("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: settings\n  namespace: %s\n  labels:\n    app.kubernetes.io/managed-by: farcast\n", ns)
		if owner != "" {
			s += "    " + label + ": " + owner + "\n"
		}
		return s + "data:\n  key: realapi-marker\n"
	}
	r.apply(t, cm(""), true)
	other := fmt.Sprintf("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: settings\n  namespace: %s\n  labels:\n    %s: other\n", ns, label)
	_, _, err := r.rawApply(ctx, kindConfigMap, ns, "settings", []byte(other), "realapi-other", false)
	r.check(t, err, "the second applier's apply")

	_, err = r.c.Apply(ctx, document(t, cm("farcast")), false)
	code := r.answered(t, err)
	causes, ok := FieldConflicts(err)
	var named []string
	for _, c := range causes {
		named = append(named, c.Type+" "+c.Field)
	}
	fact(t, "an unforced apply of a label another applier owns: %d; FieldConflicts read %t, causes %v", code, ok, named)
	if code != http.StatusConflict || !ok {
		t.Fatalf("the unforced apply answered %d, and FieldConflicts read %t; want 409 with FieldManagerConflict causes", code, ok)
	}
	if !slices.ContainsFunc(causes, func(c StatusCause) bool { return strings.HasSuffix(c.Field, label) }) {
		t.Errorf("no cause names the label's field path; the causes name %v", named)
	}
}

// TestTypedListItemsCarryNoKind: a typed list's items carry no kind, as kube
// assumes when it stamps each item's Kind from the request. It records the
// kind of a partial list's items, PartialObjectMetadata [doc], which kubetest
// leaves out (store.go).
func TestTypedListItemsCarryNoKind(t *testing.T) {
	r := openRealAPI(t)
	ns := r.runNamespace(t, "kinds")
	ctx := t.Context()
	r.apply(t, doc(configMapV2, ns, seedV1), true)
	for _, tc := range []struct {
		what, accept string
		typed        bool
	}{
		{"a typed list", "", true},
		{"a partial list", acceptPartialList, false},
	} {
		b, err := r.c.do(ctx, call{method: http.MethodGet, path: kindConfigMap.ListPath(ns), accept: tc.accept, retry: true})
		r.check(t, err, tc.what)
		var list struct {
			Kind  string           `json:"kind"`
			Items []map[string]any `json:"items"`
		}
		if err := json.Unmarshal(b, &list); err != nil || len(list.Items) == 0 {
			t.Fatalf("%s: %d items, %v", tc.what, len(list.Items), err)
		}
		var kinds []string
		for _, it := range list.Items {
			if k, ok := it["kind"].(string); ok {
				kinds = append(kinds, k)
			} else {
				kinds = append(kinds, "(none)")
			}
		}
		fact(t, "%s: list kind %s; item kinds %v", tc.what, list.Kind, kinds)
		if tc.typed && slices.ContainsFunc(kinds, func(k string) bool { return k != "(none)" }) {
			t.Errorf("%s's items carry a kind: %v", tc.what, kinds)
		}
	}
}

// kernelEntries is md's entries the kernel made, by its manager's name.
func kernelEntries(md ObjectMeta) []ManagedFieldsEntry {
	var out []ManagedFieldsEntry
	for _, e := range md.ManagedFields {
		if e.Manager == tkube.FieldManager {
			out = append(out, e)
		}
	}
	return out
}

// TestKernelWritesAreTrackedAsTechnocore drives the kernel's real writes
// through technocore/kube.Client: Scale, SetRequests, and SaveConfigMap's POST
// and PUT. Its main-resource writes must each be tracked under technocore
// (A30-11, built in M2.7a), never a name the server derives from the client.
// It records each entry's manager, operation and subresource.
//
// Its Scale to 0, the only Scale the kernel makes, was recorded under no
// manager on a loopback envtest kube-apiserver v1.36.2, and left spec.replicas
// owned by no entry (§31, A31-5). So the Scale subtest records the entries
// and asserts replicas 0 and no foreign manager, without requiring a
// technocore entry, and asserts that no entry owns spec.replicas, so a server
// that starts tracking it shows up. It records whether that Scale, sent at
// least a second after the apply, moved the time of farcast's Apply entry,
// which P1 (c)'s adapted fact compares with the kernel's stamp. Then it
// scales to 2, and records whether a technocore/Update entry with subresource
// scale appears and owns spec.replicas.
func TestKernelWritesAreTrackedAsTechnocore(t *testing.T) {
	r := openRealAPI(t)
	ns := r.runNamespace(t, "kernel")
	ctx := t.Context()
	k := r.kernel(t, ns)
	r.apply(t, doc(appV2, ns, seedV1), true)
	appliedAt := time.Now()
	foreign := func(t *testing.T, what string, md ObjectMeta) {
		t.Helper()
		for _, e := range md.ManagedFields {
			if e.Manager != FieldManager && e.Manager != tkube.FieldManager {
				t.Errorf("%s: an entry names %s, neither farcast nor %s", what, entryName(e), tkube.FieldManager)
			}
		}
	}
	named := func(t *testing.T, what string, md ObjectMeta) {
		t.Helper()
		var replicas []bool
		for _, e := range kernelEntries(md) {
			replicas = append(replicas, owns(e, "f:spec", "f:replicas"))
		}
		fact(t, "%s: entries %v; the kernel's entries own spec.replicas: %v", what, entryNames(md), replicas)
		if len(kernelEntries(md)) == 0 {
			t.Errorf("%s left no %s entry", what, tkube.FieldManager)
		}
		foreign(t, what, md)
	}
	// applyTime is the time of farcast's own Apply entry, "" without one.
	applyTime := func(md ObjectMeta) string {
		for _, e := range md.ManagedFields {
			if IsOwnApply(e) {
				return e.Time
			}
		}
		return ""
	}
	t.Run("Scale", func(t *testing.T) {
		before := r.object(t, kindDeployment, ns, "api").Metadata
		// An entry's time is kept to the second, so a Scale sent within the
		// apply's second could not be seen to move it.
		if wait := time.Second - time.Since(appliedAt); wait > 0 {
			time.Sleep(wait)
		}
		r.check(t, k.Scale(ctx, ns, "api", 0), "Scale to 0")
		zero := r.object(t, kindDeployment, ns, "api").Metadata
		owned := false
		for _, e := range zero.ManagedFields {
			if owns(e, "f:spec", "f:replicas") {
				owned = true
				t.Errorf("after the Scale to 0, %s owns spec.replicas; on v1.36.2 no entry did (A31-5)", entryName(e))
			}
		}
		fact(t, "Scale to 0: entries %v; an entry owns spec.replicas: %t; farcast/Apply's time moved: %t", entryNames(zero), owned, applyTime(zero) != applyTime(before))
		foreign(t, "Scale to 0", zero)
		if got := field(r.raw(t, kindDeployment.Path(ns, "api")), "spec", "replicas"); got != float64(0) {
			t.Errorf("spec.replicas reads %v after Scale to 0", got)
		}

		r.check(t, k.Scale(ctx, ns, "api", 2), "Scale to 2")
		two := r.object(t, kindDeployment, ns, "api").Metadata
		tracked, trackedOwns := false, false
		for _, e := range two.ManagedFields {
			if e.Manager == tkube.FieldManager && e.Operation == "Update" && e.Subresource == "scale" {
				tracked = true
				trackedOwns = trackedOwns || owns(e, "f:spec", "f:replicas")
			}
		}
		fact(t, "Scale to 2: entries %v; a %s/Update/scale entry appears: %t; it owns spec.replicas: %t", entryNames(two), tkube.FieldManager, tracked, trackedOwns)
		foreign(t, "Scale to 2", two)
		if got := field(r.raw(t, kindDeployment.Path(ns, "api")), "spec", "replicas"); got != float64(2) {
			t.Errorf("spec.replicas reads %v after Scale to 2", got)
		}
	})
	t.Run("SetRequests", func(t *testing.T) {
		cpu, mem, err := k.SetRequests(ctx, ns, "api", "api", 100, 128, map[string]string{"realapi.farcast.sofmon.com/adapted-at": "realapi-marker"})
		r.check(t, err, "SetRequests")
		fact(t, "SetRequests stored %dm and %dMi", cpu, mem)
		named(t, "SetRequests", r.object(t, kindDeployment, ns, "api").Metadata)
	})
	t.Run("SaveConfigMap", func(t *testing.T) {
		r.check(t, k.SaveConfigMap(ctx, ns, tkube.ConfigMap{Metadata: tkube.ObjectMeta{Name: "technocore-ledger"}, Data: map[string]string{"ledger": "realapi-marker-one"}}), "SaveConfigMap's POST")
		named(t, "SaveConfigMap's POST", r.object(t, kindConfigMap, ns, "technocore-ledger").Metadata)
		cm, err := k.GetConfigMap(ctx, ns, "technocore-ledger")
		r.check(t, err, "the kernel's GetConfigMap")
		cm.Data["ledger"] = "realapi-marker-two"
		r.check(t, k.SaveConfigMap(ctx, ns, *cm), "SaveConfigMap's PUT")
		named(t, "SaveConfigMap's PUT", r.object(t, kindConfigMap, ns, "technocore-ledger").Metadata)
	})
}

// TestForcedApplyTakesAnotherManagersField (design §37, A37-9; written, not
// run): a forced farcast apply takes another manager's field, which is P1
// (c)'s reset. The other manager is realapi-other's merge PATCH on the
// Deployment itself, which the server records as an Update owning
// spec.replicas (§31's /scale [diag]). The order is pinned (A31-5), because a
// /scale write of 0 strips every owner of spec.replicas:
//  1. farcast's forced apply of the Deployment, after which farcast/Apply
//     owns spec.replicas;
//  2. the kernel's Scale to 0, whose entries are recorded only;
//  3. realapi-other's merge PATCH of spec.replicas to 3, a value other than
//     the live one, after which realapi-other/Update owns it, farcast/Apply
//     does not, and it reads 3;
//  4. the forced apply of replicas: 1, after which farcast/Apply owns it and
//     it reads 1.
//
// Steps 1 and 3 require farcast/Apply to own the field and then not, so the
// last step cannot pass on a field farcast never lost. No /scale write
// follows the PATCH.
func TestForcedApplyTakesAnotherManagersField(t *testing.T) {
	r := openRealAPI(t)
	ns := r.runNamespace(t, "scale")
	ctx := t.Context()
	k := r.kernel(t, ns)
	r.apply(t, doc(fatlineV1, ns, seedV1), true)
	if !farcastOwnsReplicas(r.object(t, kindDeployment, ns, "fatline").Metadata) {
		t.Fatal("farcast/Apply does not own spec.replicas after its first forced apply, so nothing here shows the field taken back")
	}
	r.check(t, k.Scale(ctx, ns, "fatline", 0), "the kernel's Scale")
	scaled := r.object(t, kindDeployment, ns, "fatline")
	fact(t, "after the kernel's Scale to 0: entries %v", entryNames(scaled.Metadata))

	r.check(t, r.mergePatch(ctx, kindDeployment, ns, "fatline", []byte(`{"spec":{"replicas":3}}`), realAPIOther), "realapi-other's merge PATCH")
	patched := r.object(t, kindDeployment, ns, "fatline")
	ok := otherOwnsReplicas(patched.Metadata)
	fact(t, "after %s's merge PATCH of spec.replicas: entries %v; %s/Update owns spec.replicas: %t", realAPIOther, entryNames(patched.Metadata), realAPIOther, ok)
	if !ok {
		t.Fatalf("after its merge PATCH, no %s/Update entry owns spec.replicas", realAPIOther)
	}
	if farcastOwnsReplicas(patched.Metadata) {
		t.Fatalf("farcast/Apply still owns spec.replicas after %s's merge PATCH, so the forced apply would take nothing back", realAPIOther)
	}
	if got := field(r.raw(t, kindDeployment.Path(ns, "fatline")), "spec", "replicas"); got != float64(3) {
		t.Errorf("spec.replicas reads %v after the merge PATCH, not %s's 3", got, realAPIOther)
	}

	r.apply(t, doc(fatlineV1, ns, seedV1, "{replicas}", "1"), true)
	reset := r.object(t, kindDeployment, ns, "fatline")
	farcastOwns := farcastOwnsReplicas(reset.Metadata)
	fact(t, "after a forced farcast apply of replicas: 1: entries %v; farcast/Apply owns spec.replicas: %t", entryNames(reset.Metadata), farcastOwns)
	if got := field(r.raw(t, kindDeployment.Path(ns, "fatline")), "spec", "replicas"); got != float64(1) {
		t.Errorf("spec.replicas reads %v after the forced apply of 1", got)
	}
	if !farcastOwns {
		t.Error("farcast/Apply does not own spec.replicas after its forced apply")
	}
}

// realAPIOther is the other manager TestForcedApplyTakesAnotherManagersField
// writes as, the name the suite's other second appliers use too.
const realAPIOther = "realapi-other"

// otherOwnsReplicas is whether md has a realapi-other/Update entry on the
// main resource that owns spec.replicas.
func otherOwnsReplicas(md ObjectMeta) bool {
	for _, e := range md.ManagedFields {
		if e.Manager == realAPIOther && e.Operation == "Update" && e.Subresource == "" && owns(e, "f:spec", "f:replicas") {
			return true
		}
	}
	return false
}

// farcastOwnsReplicas is whether farcast's own Apply entry on md owns
// spec.replicas.
func farcastOwnsReplicas(md ObjectMeta) bool {
	return slices.ContainsFunc(md.ManagedFields, func(e ManagedFieldsEntry) bool {
		return IsOwnApply(e) && owns(e, "f:spec", "f:replicas")
	})
}

// mergePatch is a JSON merge PATCH of body on the object, as manager, with
// strict validation. It bypasses Apply on purpose: it is another manager's
// write, which the server records as that manager's Update.
func (r *realAPI) mergePatch(ctx context.Context, k Kind, ns, name string, body []byte, manager string) error {
	_, err := r.c.do(ctx, call{
		method:      http.MethodPatch,
		path:        k.Path(ns, name),
		query:       url.Values{"fieldManager": {manager}, "fieldValidation": {"Strict"}},
		contentType: mediaMergePatch,
		body:        body,
	})
	return err
}

// serviceAccountDoc is a ServiceAccount in the renderers' shape, the
// builder's (planck/build) and the keyholder's (datasphere/deploy): its
// name, its namespace and its app.kubernetes.io/name label.
const serviceAccountDoc = `apiVersion: v1
kind: ServiceAccount
metadata:
  name: %s
  namespace: %s
  labels:
    app.kubernetes.io/name: %s
    app.kubernetes.io/managed-by: farcast
`

// TestServiceAccountUIDSurvivesAForcedApply (design §33, R1, as §37's A37-9
// narrows it; written, not run): the grants of ADR 0023 M2.8 name a
// ServiceAccount by the uid the API server gave it, so nothing farcast does
// to the account may give it another. A forced apply of the builder's
// ServiceAccount over itself, as kernel deploy and every build apply it,
// keeps its uid; and so does a forced apply that changes the keyholder's
// ServiceAccount's labels. That account must have a uid and lack the added
// label before the change, so the change is one. What it records: whether
// each kept the uid, never the uid.
func TestServiceAccountUIDSurvivesAForcedApply(t *testing.T) {
	r := openRealAPI(t)
	ns := r.runNamespace(t, "sauid")
	k := mustKind("v1", "ServiceAccount")

	builder := fmt.Sprintf(serviceAccountDoc, "farcast-builder", ns, "farcast-builder")
	r.apply(t, builder, true)
	first := r.object(t, k, ns, "farcast-builder").Metadata
	r.apply(t, builder, true)
	second := r.object(t, k, ns, "farcast-builder").Metadata
	fact(t, "a forced apply of an unchanged ServiceAccount: uid kept %t, resourceVersion moved %t",
		second.UID == first.UID, second.ResourceVersion != first.ResourceVersion)
	if first.UID == "" || second.UID != first.UID {
		t.Errorf("a forced apply of an unchanged ServiceAccount gave it another uid, or none")
	}

	const managedBy = "    app.kubernetes.io/managed-by: farcast\n"
	keyholder := fmt.Sprintf(serviceAccountDoc, "datasphered", ns, "datasphered")
	relabelled := strings.Replace(keyholder, managedBy, managedBy+"    realapi.farcast.sofmon.com/seed: changed\n", 1)
	if relabelled == keyholder {
		t.Fatal("the keyholder's ServiceAccount carries no managed-by label to add a label after")
	}
	r.apply(t, keyholder, true)
	created := r.object(t, k, ns, "datasphered").Metadata
	if _, ok := created.Labels["realapi.farcast.sofmon.com/seed"]; ok || created.UID == "" {
		t.Fatal("the keyholder's ServiceAccount already carries the label the second apply adds, or has no uid, so that apply would show nothing")
	}
	r.apply(t, relabelled, true)
	changed := r.object(t, k, ns, "datasphered").Metadata
	fact(t, "a forced apply that changes a ServiceAccount's labels: label applied %t, uid kept %t, resourceVersion moved %t; entries %v",
		changed.Labels["realapi.farcast.sofmon.com/seed"] == "changed", changed.UID == created.UID,
		changed.ResourceVersion != created.ResourceVersion, entryNames(changed))
	if changed.Labels["realapi.farcast.sofmon.com/seed"] != "changed" {
		t.Fatal("the forced apply of the changed labels did not change them")
	}
	if created.UID == "" || changed.UID != created.UID {
		t.Errorf("a forced apply that changes a ServiceAccount's labels gave it another uid, or none")
	}
}

// gitCredentialDoc is a Git credential in git-credential set's shape (ADR
// 0023 M2.8, design §33, A33-29): its name and its namespace, then a
// placeholder's data, which carries no credential.
const gitCredentialDoc = `apiVersion: v1
kind: Secret
metadata:
  name: "%s"
  namespace: "%s"
  labels:
    app.kubernetes.io/managed-by: farcast
    app.kubernetes.io/component: git-credential
type: Opaque
data:
  username: "cmVhbGFwaS11c2Vy"
  token: "cmVhbGFwaS10b2tlbg=="
`

// TestDeleteSecretHonoursItsUIDPrecondition (design §33, A33-31, R3;
// written, not run): git-credential rm deletes a Secret on the uid it read,
// so one replaced since that read is never deleted. On a real API server a
// delete on the stored uid deletes the Secret. A Secret deleted and created
// again under its name since the read is refused 409, unwrapping to
// tkube.ErrConflict, and kept. A delete of a Secret that is gone is a 404,
// unwrapping to tkube.ErrNotFound. What it records: the codes, and whether
// the Secret was deleted or kept, never a uid.
func TestDeleteSecretHonoursItsUIDPrecondition(t *testing.T) {
	r := openRealAPI(t)
	ns := r.runNamespace(t, "delete")
	ctx := t.Context()
	text := fmt.Sprintf(gitCredentialDoc, "repo-git", ns)

	// A delete that succeeds comes back as no error for any 2xx, so its code
	// is not known here, and is not recorded as one; a refusal's is.
	answer := func(err error) string {
		t.Helper()
		if err == nil {
			return "a 2xx, its code not kept"
		}
		return strconv.Itoa(r.answered(t, err))
	}

	r.apply(t, text, true)
	read := r.object(t, kindSecret, ns, "repo-git").Metadata
	err := r.c.DeleteSecret(ctx, ns, "repo-git", read.UID)
	_, gone := r.c.GetObject(ctx, kindSecret, ns, "repo-git")
	fact(t, "a delete on the stored uid: %s; the Secret deleted: %t", answer(err), errors.Is(gone, tkube.ErrNotFound))
	if err != nil || !errors.Is(gone, tkube.ErrNotFound) {
		t.Errorf("a delete on the stored uid answered %s, and the Secret is still there: %t", answer(err), !errors.Is(gone, tkube.ErrNotFound))
	}

	r.apply(t, text, true)
	again := r.object(t, kindSecret, ns, "repo-git").Metadata
	if again.UID == "" || again.UID == read.UID {
		t.Fatal("the Secret created again under its name has no uid, or the deleted one's")
	}
	err = r.c.DeleteSecret(ctx, ns, "repo-git", read.UID)
	kept := r.object(t, kindSecret, ns, "repo-git").Metadata
	fact(t, "a delete on the uid read before the Secret was created again: %s; the new Secret kept: %t", answer(err), kept.UID == again.UID)
	if !errors.Is(err, tkube.ErrConflict) || kept.UID != again.UID {
		t.Errorf("a delete on a uid that is no longer the stored one answered %s, not a 409 unwrapping to tkube.ErrConflict, or the new Secret is gone", answer(err))
	}

	r.check(t, r.c.DeleteSecret(ctx, ns, "repo-git", again.UID), "the delete on the new Secret's uid")
	err = r.c.DeleteSecret(ctx, ns, "repo-git", again.UID)
	fact(t, "a delete of a Secret that is gone: %s", answer(err))
	if !errors.Is(err, tkube.ErrNotFound) {
		t.Errorf("a delete of a Secret that is gone answered %s, not a 404 unwrapping to tkube.ErrNotFound", answer(err))
	}
}
