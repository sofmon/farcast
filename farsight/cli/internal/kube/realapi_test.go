//go:build realapi

// The no-cost suite on a real API server (ADR 0023 M2.7, design §10.6 as
// A30-18 amends it). It runs only by docs/runbooks/adr-0023-m2-realapi.md:
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
// pass by testing nothing. The one exception is TestEmulatedSeedMatchesKubectl,
// which skips, saying why, when FARCAST_REALAPI_KUBECTL_NAMESPACE is unset (R7).
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
// send or is not the write they make, and each says so: seedClientSide
// (kubectl's client-side apply, with its annotation), rawApply (a second
// applier, and a body that carries a resourceVersion no AllowResourceVersion
// let through), migrateOne (the migration's JSON patch) and mergePatch
// (another manager's merge patch).
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
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/auth"
	"github.com/goccy/go-yaml"

	tkube "github.com/sofmon/farcast/technocore/kube"
)

// The suite's environment (R6, R7).
const (
	envRealAPIEndpoint         = "FARCAST_REALAPI_ENDPOINT"
	envRealAPICAFile           = "FARCAST_REALAPI_CA_FILE"
	envRealAPITokenFile        = "FARCAST_REALAPI_TOKEN_FILE"
	envRealAPIKubectlNamespace = "FARCAST_REALAPI_KUBECTL_NAMESPACE"
)

// realAPIEmail is the identity newClient pairs with a loopback endpoint: a
// credential under .invalid, which goes to a loopback endpoint and nowhere
// else (§3.2). It signs nothing: the token is the file's.
const realAPIEmail = "realapi@realapi.invalid"

// mediaStrategicMergePatch is the content type of kubectl's client-side
// apply's second write, which kube never sends.
const mediaStrategicMergePatch = "application/strategic-merge-patch+json"

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

// clientSideQuery is the query of kubectl's client-side apply's two writes:
// its field manager, and the strict validation kubectl asks for by default.
func clientSideQuery() url.Values {
	return url.Values{"fieldManager": {kubectlClientSideApply}, "fieldValidation": {"Strict"}}
}

// seedClientSide leaves an object as kubectl's client-side apply leaves it
// after two applies (design §6.8 step 1, L4.4). It bypasses Apply on purpose:
// Apply refuses the last-applied annotation, and kube has no create and no
// strategic-merge patch.
//  1. A POST of v1 to k.ListPath(ns), under kubectl-client-side-apply,
//     carrying the annotation kubectl writes: v1's own JSON and a newline.
//  2. A strategic-merge PATCH of v1bSMP under the same manager, carrying the
//     annotation updated to v1 with v1bSMP merged in, as kubectl's second
//     apply of a changed manifest sends it.
//
// v1JSON is one object; its namespace is set to ns. v1bSMP changes map
// fields only, such as a label's value, where a strategic merge patch and a
// JSON merge patch agree, so the updated annotation is v1 with the patch
// merged; a list in it is refused. A nil v1bSMP sends the POST alone, as
// kubectl sends nothing for a manifest that did not change.
func (r *realAPI) seedClientSide(ctx context.Context, k Kind, ns string, v1JSON, v1bSMP []byte) error {
	var v1 map[string]any
	if err := json.Unmarshal(v1JSON, &v1); err != nil {
		return fmt.Errorf("v1 does not decode: %w", err)
	}
	md, _ := v1["metadata"].(map[string]any)
	if md == nil {
		return errors.New("v1 has no metadata")
	}
	name, _ := md["name"].(string)
	if k.Namespaced {
		md["namespace"] = ns
	}
	created, err := withLastApplied(v1, v1)
	if err != nil {
		return err
	}
	if _, err := r.c.do(ctx, call{method: http.MethodPost, path: k.ListPath(ns), query: clientSideQuery(), contentType: mediaJSON, body: created}); err != nil {
		return fmt.Errorf("the client-side create: %w", err)
	}
	if v1bSMP == nil {
		return nil
	}
	var smp map[string]any
	if err := json.Unmarshal(v1bSMP, &smp); err != nil {
		return fmt.Errorf("v1b's patch does not decode: %w", err)
	}
	v1b := cloneJSON(v1)
	if err := mergeMaps(v1b, smp); err != nil {
		return err
	}
	patch, err := withLastApplied(smp, v1b)
	if err != nil {
		return err
	}
	if _, err := r.c.do(ctx, call{method: http.MethodPatch, path: k.Path(ns, name), query: clientSideQuery(), contentType: mediaStrategicMergePatch, body: patch}); err != nil {
		return fmt.Errorf("the client-side second apply: %w", err)
	}
	return nil
}

// withLastApplied is body with kubectl's annotation set to applied's JSON
// and a newline, as kubectl's client-side apply records the manifest it
// applied, encoded.
func withLastApplied(body, applied map[string]any) ([]byte, error) {
	a, err := json.Marshal(applied)
	if err != nil {
		return nil, err
	}
	out := cloneJSON(body)
	md, _ := out["metadata"].(map[string]any)
	if md == nil {
		md = map[string]any{}
		out["metadata"] = md
	}
	ann, _ := md["annotations"].(map[string]any)
	if ann == nil {
		ann = map[string]any{}
		md["annotations"] = ann
	}
	ann[lastAppliedAnnotation] = string(a) + "\n"
	return json.Marshal(out)
}

// cloneJSON is a deep copy of a decoded JSON object.
func cloneJSON(m map[string]any) map[string]any {
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		panic(err)
	}
	return out
}

// mergeMaps merges patch into dst as a JSON merge patch does (RFC 7386): a
// null deletes, a map merges, a value replaces. A list is refused, because
// there a strategic merge patch would merge by key and a merge patch would
// replace.
func mergeMaps(dst, patch map[string]any) error {
	for k, pv := range patch {
		switch v := pv.(type) {
		case nil:
			delete(dst, k)
		case map[string]any:
			d, _ := dst[k].(map[string]any)
			if d == nil {
				d = map[string]any{}
				dst[k] = d
			}
			if err := mergeMaps(d, v); err != nil {
				return err
			}
		case []any:
			return fmt.Errorf("the emulated second apply changes map fields only, and its patch carries a list at %q", k)
		default:
			dst[k] = v
		}
	}
	return nil
}

// secondApplyPatch is the patch kubectl's second apply sends for documents
// that differ in map values only: each changed value, null for a removed key.
// A list that differs is refused, as mergeMaps refuses it. It is nil when the
// two are equal.
func secondApplyPatch(v1, v1b map[string]any) (map[string]any, error) {
	patch := map[string]any{}
	for k, b := range v1b {
		a, ok := v1[k]
		switch {
		case !ok:
			patch[k] = b
		case reflect.DeepEqual(a, b):
		default:
			am, aok := a.(map[string]any)
			bm, bok := b.(map[string]any)
			if aok && bok {
				sub, err := secondApplyPatch(am, bm)
				if err != nil {
					return nil, err
				}
				patch[k] = sub
				continue
			}
			if _, isList := a.([]any); isList {
				return nil, fmt.Errorf("the seed files differ in the list at %q; they may differ in map values only", k)
			}
			patch[k] = b
		}
	}
	for k := range v1 {
		if _, ok := v1b[k]; !ok {
			patch[k] = nil
		}
	}
	if len(patch) == 0 {
		return nil, nil
	}
	return patch, nil
}

// seed is seedClientSide of a YAML document, failing the test on an error.
func (r *realAPI) seed(t *testing.T, k Kind, ns, v1YAML, v1bSMP string) {
	t.Helper()
	var v1 map[string]any
	if err := yaml.Unmarshal([]byte(v1YAML), &v1); err != nil {
		t.Fatalf("the test's v1 does not decode: %v", err)
	}
	v1JSON, err := json.Marshal(v1)
	if err != nil {
		t.Fatal(err)
	}
	var smp []byte
	if v1bSMP != "" {
		smp = []byte(v1bSMP)
	}
	r.check(t, r.seedClientSide(t.Context(), k, ns, v1JSON, smp), "seed "+k.Kind)
}

// migration is what migrateOne read and was answered, as far as it got.
type migration struct {
	csa      []string // ClientSideManagers of the object as read
	hadApply bool     // the read carried farcast's own Apply entry
	before   Object   // the read
	answer   Object   // PatchJSON's answer, when it was sent
	after    Object   // the fresh read after it
}

// migrateOne is §6.4's steps 1 to 3 for one object, over kube's primitives
// (C20): GetObject; ClientSideManagers; MigrationPatch, then PatchJSON;
// MigratedEndState on the answer; then a fresh GetObject and MigratedEndState
// on it. It bypasses Apply on purpose: the migration's one write is a JSON
// patch. It retries nothing; migrate's loop is a cli test (A30-23). The fresh
// read is made even when the answer's end state is refused, so a test can
// record what the server kept.
func (r *realAPI) migrateOne(ctx context.Context, k Kind, ns, name string) (migration, error) {
	var m migration
	var err error
	if m.before, err = r.c.GetObject(ctx, k, ns, name); err != nil {
		return m, fmt.Errorf("the read: %w", err)
	}
	if m.csa, err = ClientSideManagers(m.before.Metadata.ManagedFields); err != nil {
		return m, err
	}
	m.hadApply = slices.ContainsFunc(m.before.Metadata.ManagedFields, IsOwnApply)
	patch, err := MigrationPatch(m.before, m.csa, FieldManager)
	if err != nil {
		return m, err
	}
	if patch == nil {
		return m, errors.New("the object needs no migration")
	}
	if m.answer, err = r.c.PatchJSON(ctx, k, ns, name, patch); err != nil {
		return m, fmt.Errorf("the patch: %w", err)
	}
	answerState := MigratedEndState(m.answer, m.csa, FieldManager, m.hadApply)
	if m.after, err = r.c.GetObject(ctx, k, ns, name); err != nil {
		return m, fmt.Errorf("the read-back: %w", err)
	}
	if answerState != nil {
		return m, fmt.Errorf("the patch's answer: %w", answerState)
	}
	if err := MigratedEndState(m.after, m.csa, FieldManager, m.hadApply); err != nil {
		return m, fmt.Errorf("the read-back: %w", err)
	}
	return m, nil
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
// It is for writes that cannot create, a PatchJSON or an Apply of an object
// that exists, whose success is 200; rawApply's callers use applied.
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

// owns is whether an entry's fields hold path, false when they do not read.
func owns(e ManagedFieldsEntry, path ...string) bool {
	ok, err := ownsPath(e.FieldsV1, path)
	return err == nil && ok
}

// annotated is whether md carries kubectl's last-applied annotation. Its
// value is never read.
func annotated(md ObjectMeta) bool {
	_, ok := md.Annotations[lastAppliedAnnotation]
	return ok
}

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
	seedV1b       = "v1b"
	// seedV1bPatch is v1b: kubectl's second apply of a manifest whose seed
	// label's value changed (L4.4).
	seedV1bPatch = `{"metadata":{"labels":{"realapi.farcast.sofmon.com/seed":"v1b"}}}`
)

// doc fills a document template: {ns}, {seed} ("v1", or "v1b" for the
// manifest as kubectl last applied it), {replicas} (2 unless more says
// otherwise), and the base64 of the Secret's two markers. Pairs in more come
// first, so they win.
func doc(tmpl, ns, seed string, more ...string) string {
	pairs := append(slices.Clone(more),
		"{ns}", ns, "{seed}", seed, "{replicas}", "2",
		"{proxy64}", base64.StdEncoding.EncodeToString([]byte(markerProxy)),
		"{dropped64}", base64.StdEncoding.EncodeToString([]byte(markerDropped)))
	return strings.NewReplacer(pairs...).Replace(tmpl)
}

// The documents, in the renderers' shape (FatLine's and TechnoCore's
// Deployments, an application's Deployment, Service, egress Secret, ConfigMap
// and NetworkPolicy, the keyholder's StatefulSet, a build Job), with marker
// values only. Each v2 drops one thing its v1 has (§6.8).

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

// secretSeed is the egress Secret as farcast rendered it before ADR 0023
// M2.2: stringData, which only a seed may carry (SplitStream refuses it).
const secretSeed = `apiVersion: v1
kind: Secret
metadata:
  name: api-egress
  namespace: {ns}
  labels:
    app.kubernetes.io/name: api
    app.kubernetes.io/managed-by: farcast
    realapi.farcast.sofmon.com/seed: {seed}
stringData:
  FARCAST_FATLINE_PROXY: realapi-marker-proxy
  REALAPI_DROPPED: realapi-marker-dropped
`

// secretV1 is secretSeed as farcast renders it since M2.2: data:, base64.
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

const statefulSetV1 = `apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: datasphered
  namespace: {ns}
  labels:
    app.kubernetes.io/name: datasphered
    app.kubernetes.io/managed-by: farcast
    realapi.farcast.sofmon.com/seed: {seed}
spec:
  serviceName: datasphered
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: datasphered
  template:
    metadata:
      labels:
        app.kubernetes.io/name: datasphered
        app.kubernetes.io/managed-by: farcast
    spec:
      automountServiceAccountToken: false
      containers:
        - name: datasphered
          image: registry.invalid/realapi/datasphered:marker
          args:
            - serve
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
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

// stuckCase is one of §6.8's cases: an object seeded by kubectl's
// client-side apply, migrated, then applied as v2, which drops one thing.
type stuckCase struct {
	name   string
	kind   Kind
	object string
	v1, v2 string
	// left names what of the dropped thing the object still holds, "" when
	// it is gone.
	left func(obj map[string]any) string
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
		},
		{
			name: "an env entry leaves", kind: kindDeployment, object: "api", v1: appV1, v2: appV2,
			left: func(obj map[string]any) string {
				if slices.Contains(itemNames(field(container(obj, "api"), "env")), "REALAPI_DROPPED") {
					return "the env entry REALAPI_DROPPED"
				}
				return ""
			},
		},
		{
			name: "a label leaves", kind: kindService, object: "api", v1: serviceV1, v2: serviceV2,
			left: func(obj map[string]any) string {
				if field(obj, "metadata", "labels", "farcast.sofmon.com/instance") != nil {
					return "the label farcast.sofmon.com/instance"
				}
				return ""
			},
		},
		{
			name: "a Secret data key leaves, from a stringData v1", kind: kindSecret, object: "api-egress", v1: secretSeed, v2: secretV2,
			left: func(obj map[string]any) string {
				if field(obj, "data", "REALAPI_DROPPED") != nil {
					return "the data key REALAPI_DROPPED"
				}
				return ""
			},
		},
		{
			name: "a ConfigMap data key leaves", kind: kindConfigMap, object: "api", v1: configMapV1, v2: configMapV2,
			left: func(obj map[string]any) string {
				if field(obj, "data", "REALAPI_DROPPED") != nil {
					return "the data key REALAPI_DROPPED"
				}
				return ""
			},
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
		},
	}
}

// asList is a decoded list, nil when v is not one.
func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

// TestMigrationRemovesAFieldLaterDroppedFromTheManifest is §6.8's stuck-fields
// test, one subtest per case: seed v1 as kubectl's client-side apply would,
// migrate it, apply v2 forced, and check that what v2 dropped is gone from the
// live object and that the end state still holds. The field's assertion
// begins "stuck field: ", which R6 tells from any other failure: mutation row
// 104 counts as killed only on it.
func TestMigrationRemovesAFieldLaterDroppedFromTheManifest(t *testing.T) {
	r := openRealAPI(t)
	ns := r.runNamespace(t, "stuck")
	for _, sc := range stuckCases() {
		t.Run(sc.name, func(t *testing.T) {
			r.seed(t, sc.kind, ns, doc(sc.v1, ns, seedV1), seedV1bPatch)
			m, err := r.migrateOne(t.Context(), sc.kind, ns, sc.object)
			r.check(t, err, "the migration")
			r.apply(t, doc(sc.v2, ns, seedV1b), true)
			if left := sc.left(r.raw(t, sc.kind.Path(ns, sc.object))); left != "" {
				t.Errorf("stuck field: %s is still on the live %s after v2's forced apply", left, sc.kind.Kind)
			}
			back := r.object(t, sc.kind, ns, sc.object)
			if err := MigratedEndState(back, m.csa, FieldManager, m.hadApply); err != nil {
				t.Errorf("the end state after v2's apply: %v", err)
			}
			fact(t, "%s: after the migration and v2's apply, entries %v", sc.name, entryNames(back.Metadata))
		})
	}
}

// TestAnnotationRemovalInTheSamePatchLeavesNoUpdateEntry decides §6.3 (A30-1):
// the migration removes the annotation in the same JSON patch that rewrites
// the managed fields. If the server then records the patch as farcast's
// Update, the removal moves to a second request. It records the entries, and
// whether farcast's Apply entry still owns the annotation's path.
func TestAnnotationRemovalInTheSamePatchLeavesNoUpdateEntry(t *testing.T) {
	r := openRealAPI(t)
	ns := r.runNamespace(t, "samepatch")
	for _, tc := range []struct {
		kind         Kind
		object, seed string
	}{
		{kindDeployment, "fatline", fatlineV1},
		{kindSecret, "api-egress", secretSeed},
		{kindConfigMap, "api", configMapV1},
	} {
		t.Run(tc.kind.Kind, func(t *testing.T) {
			r.seed(t, tc.kind, ns, doc(tc.seed, ns, seedV1), seedV1bPatch)
			m, err := r.migrateOne(t.Context(), tc.kind, ns, tc.object)
			for _, o := range []struct {
				what string
				obj  Object
			}{{"the patch's answer", m.answer}, {"the read-back", m.after}} {
				if o.obj.Metadata.Name == "" {
					continue
				}
				var updates int
				ownsAnnotation := false
				for _, e := range o.obj.Metadata.ManagedFields {
					if e.Manager == FieldManager && e.Operation == operationUpdate {
						updates++
					}
					if IsOwnApply(e) && owns(e, lastAppliedFieldPath...) {
						ownsAnnotation = true
					}
				}
				fact(t, "%s, %s: entries %v; farcast/Update entries %d; farcast/Apply owns the annotation's path: %t; annotation present: %t",
					tc.kind.Kind, o.what, entryNames(o.obj.Metadata), updates, ownsAnnotation, annotated(o.obj.Metadata))
				if updates != 0 {
					t.Errorf("%s carries %d farcast/Update entries after the same-patch removal; §6.3's removal moves to a second request", o.what, updates)
				}
				if ownsAnnotation {
					t.Errorf("%s: farcast/Apply still owns the annotation's path", o.what)
				}
			}
			r.check(t, err, "the migration")
		})
	}
}

// TestRealAPIKeepsTheLiveListOnAnUndecodableRewrite: a rewrite whose entries
// the server cannot decode (an apiVersion of "") is ignored without an error.
// The server keeps the live list and still applies the annotation's removal, and
// MigratedEndState refuses on the answer and on the read-back (§6.3, "Why it
// is read back"). The migration's own write is sent through PatchJSON, as
// migrateOne sends it.
func TestRealAPIKeepsTheLiveListOnAnUndecodableRewrite(t *testing.T) {
	r := openRealAPI(t)
	ns := r.runNamespace(t, "undecodable")
	ctx := t.Context()
	r.seed(t, kindDeployment, ns, doc(fatlineV1, ns, seedV1), seedV1bPatch)
	before := r.object(t, kindDeployment, ns, "fatline")
	csa, err := ClientSideManagers(before.Metadata.ManagedFields)
	r.check(t, err, "ClientSideManagers")
	hadApply := slices.ContainsFunc(before.Metadata.ManagedFields, IsOwnApply)
	patch, err := MigrationPatch(before, csa, FieldManager)
	r.check(t, err, "MigrationPatch")
	undecodable := strings.Replace(string(patch), `"apiVersion":"apps/v1"`, `"apiVersion":""`, 1)
	if patch == nil || undecodable == string(patch) {
		t.Fatal("the patch carries no apiVersion to break")
	}
	answer, err := r.c.PatchJSON(ctx, kindDeployment, ns, "fatline", []byte(undecodable))
	code := r.answered(t, err)
	fact(t, "an undecodable managed-fields rewrite: %d", code)
	if err != nil {
		t.Fatalf("the server refused the undecodable rewrite rather than keeping the live list: %s", r.env.scrub(err.Error()))
	}
	back := r.object(t, kindDeployment, ns, "fatline")
	for _, o := range []struct {
		what string
		obj  Object
	}{{"the answer", answer}, {"the read-back", back}} {
		kept := slices.ContainsFunc(o.obj.Metadata.ManagedFields, isCSAEntry(kubectlClientSideApply))
		fact(t, "%s: entries %v; annotation present: %t", o.what, entryNames(o.obj.Metadata), annotated(o.obj.Metadata))
		if annotated(o.obj.Metadata) {
			t.Errorf("%s still carries the annotation: its removal did not apply", o.what)
		}
		if !kept {
			t.Errorf("%s lost kubectl-client-side-apply/Update: the server did not keep the live list", o.what)
		}
		if err := MigratedEndState(o.obj, csa, FieldManager, hadApply); !errors.Is(err, ErrNotMigrated) {
			t.Errorf("%s: MigratedEndState = %v, want a refusal", o.what, err)
		}
	}
}

// TestMigrationIsResumable, at the level of the primitives (C20; the
// five-attempt loop is a cli test, A30-23): a patch read at a resourceVersion
// another writer has since moved is a 409 that unwraps to tkube.ErrConflict,
// and leaves the object as it was; a fresh read then migrates it; and a second
// pass finds nothing to do.
func TestMigrationIsResumable(t *testing.T) {
	r := openRealAPI(t)
	ns := r.runNamespace(t, "resume")
	ctx := t.Context()
	r.seed(t, kindConfigMap, ns, doc(configMapV1, ns, seedV1), seedV1bPatch)
	stale := r.object(t, kindConfigMap, ns, "api")
	csa, err := ClientSideManagers(stale.Metadata.ManagedFields)
	r.check(t, err, "ClientSideManagers")
	other := fmt.Sprintf("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: api\n  namespace: %s\n  labels:\n    realapi.farcast.sofmon.com/other: \"yes\"\n", ns)
	_, _, err = r.rawApply(ctx, kindConfigMap, ns, "api", []byte(other), "realapi-other", false)
	r.check(t, err, "another writer's apply")
	moved := r.object(t, kindConfigMap, ns, "api")

	patch, err := MigrationPatch(stale, csa, FieldManager)
	r.check(t, err, "MigrationPatch")
	_, err = r.c.PatchJSON(ctx, kindConfigMap, ns, "api", patch)
	code := r.answered(t, err)
	fact(t, "a migration patch read at a moved resourceVersion: %d", code)
	if !errors.Is(err, tkube.ErrConflict) {
		t.Fatalf("the stale patch: %d, want 409 unwrapping to tkube.ErrConflict", code)
	}
	unchanged := r.object(t, kindConfigMap, ns, "api")
	left, _ := ClientSideManagers(unchanged.Metadata.ManagedFields)
	if unchanged.Metadata.ResourceVersion != moved.Metadata.ResourceVersion || !annotated(unchanged.Metadata) || !slices.Equal(left, csa) {
		t.Errorf("the refused patch changed the object: entries %v, annotation present %t", entryNames(unchanged.Metadata), annotated(unchanged.Metadata))
	}

	m, err := r.migrateOne(ctx, kindConfigMap, ns, "api")
	r.check(t, err, "the migration from a fresh read")
	fact(t, "after the resumed migration: entries %v", entryNames(m.after.Metadata))

	again := r.object(t, kindConfigMap, ns, "api")
	csa2, err := ClientSideManagers(again.Metadata.ManagedFields)
	r.check(t, err, "ClientSideManagers on the second pass")
	if p, err := MigrationPatch(again, csa2, FieldManager); err != nil || p != nil {
		t.Errorf("the second pass: MigrationPatch = %d bytes, %v; want nothing to do", len(p), err)
	}
}

// TestFirstApplyAfterMigrationChangesNoGeneration is csaupgrade's caveat 3
// (§6.3): after the migration farcast owns the fields the client-side create
// had defaulted, and its first forced apply, which omits them, releases them.
// The baseline is the read after the migration, whose own generation move is
// recorded: a Deployment's annotation change bumps it [doc]. The re-apply is
// the manifest as kubectl last applied it (v1 with v1b's one change; the
// Secret in its data: form): it must leave the generation where it was and
// add no entry. Whether the resourceVersion moved is recorded.
func TestFirstApplyAfterMigrationChangesNoGeneration(t *testing.T) {
	r := openRealAPI(t)
	ns := r.runNamespace(t, "generation")
	for _, tc := range []struct {
		kind              Kind
		object, seed, now string
	}{
		{kindDeployment, "fatline", fatlineV1, fatlineV1},
		{kindStatefulSet, "datasphered", statefulSetV1, statefulSetV1},
		{kindService, "api", serviceV1, serviceV1},
		{kindSecret, "api-egress", secretSeed, secretV1},
	} {
		t.Run(tc.kind.Kind, func(t *testing.T) {
			r.seed(t, tc.kind, ns, doc(tc.seed, ns, seedV1), seedV1bPatch)
			seeded := r.object(t, tc.kind, ns, tc.object)
			m, err := r.migrateOne(t.Context(), tc.kind, ns, tc.object)
			r.check(t, err, "the migration")
			base := m.after.Metadata
			r.apply(t, doc(tc.now, ns, seedV1b), true)
			after := r.object(t, tc.kind, ns, tc.object).Metadata
			var added []string
			for _, e := range entryNames(after) {
				if !slices.Contains(entryNames(base), e) {
					added = append(added, e)
				}
			}
			fact(t, "%s: generation %d seeded, %d after the migration, %d after the first apply; entries added %v; resourceVersion moved on the apply: %t",
				tc.kind.Kind, seeded.Metadata.Generation, base.Generation, after.Generation, added, after.ResourceVersion != base.ResourceVersion)
			if after.Generation != base.Generation {
				t.Errorf("the first apply after the migration moved metadata.generation from %d to %d", base.Generation, after.Generation)
			}
			if len(added) > 0 {
				t.Errorf("the first apply after the migration added entries %v", added)
			}
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
// only (§2.1, A30-9) comes back without a Secret's values, while kubectl's
// annotation, which holds a copy of them, is still there; no message may
// quote it. It reads the raw answers of ListObjects, a raw partial list,
// GetObject and the migration's PatchJSON, through TapAnswers.
func TestMetadataOnlyListsCarryNoSecretData(t *testing.T) {
	r := openRealAPI(t)
	ns := r.runNamespace(t, "metadata")
	ctx := t.Context()
	r.seed(t, kindSecret, ns, doc(secretSeed, ns, seedV1), seedV1bPatch)

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
	tapped := &realAPI{env: r.env, c: c}

	objs, err := c.ListObjects(ctx, kindSecret, ns, "")
	r.check(t, err, "ListObjects")
	if len(objs) != 1 || !annotated(objs[0].Metadata) {
		t.Errorf("ListObjects decoded %d object(s); want the one Secret, its annotation present", len(objs))
	}
	noSecretValues(t, "ListObjects' answer", answer(http.MethodGet), true)

	b, err := c.do(ctx, call{method: http.MethodGet, path: kindSecret.ListPath(ns), accept: acceptPartialList, retry: true})
	r.check(t, err, "the raw partial list")
	noSecretValues(t, "a raw partial list", b, true)

	_, err = c.GetObject(ctx, kindSecret, ns, "api-egress")
	r.check(t, err, "GetObject")
	noSecretValues(t, "GetObject's answer", answer(http.MethodGet), true)

	_, err = tapped.migrateOne(ctx, kindSecret, ns, "api-egress")
	r.check(t, err, "the migration")
	noSecretValues(t, "PatchJSON's answer", answer(http.MethodPatch), false)
	noSecretValues(t, "GetObject's answer after the migration", answer(http.MethodGet), false)
}

// noSecretValues fails when any object of a raw answer, or of its items,
// carries data or stringData. wantAnnotation is whether each must still carry
// kubectl's annotation, whose value is never read. It records the answer's
// kind and each object's top-level keys.
func noSecretValues(t *testing.T, what string, body []byte, wantAnnotation bool) {
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
		if got := field(m, "metadata", "annotations", lastAppliedAnnotation) != nil; got != wantAnnotation {
			t.Errorf("%s: the annotation present %t, want %t", what, got, wantAnnotation)
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

// TestMigrationLeavesAnotherManagersFieldAlone: another manager's field, on
// an object kubectl's client-side apply seeded, survives the migration, and a
// forced farcast apply then takes it, which is P1 (c)'s reset. The other
// manager is realapi-other's merge PATCH on the Deployment itself, which the
// server records as an Update owning spec.replicas (§31's /scale [diag]).
// The order is pinned (A31-5), because a /scale write of 0 strips every owner
// of spec.replicas:
//  1. the client-side seed;
//  2. the kernel's Scale to 0, whose entries are recorded only;
//  3. realapi-other's merge PATCH of spec.replicas to 3, a value other than
//     the live one, after which realapi-other/Update owns it;
//  4. migrateOne, after which that entry is unchanged and replicas reads 3;
//  5. the forced apply of replicas: 1, after which farcast/Apply owns it and
//     it reads 1.
//
// No /scale write follows the PATCH.
func TestMigrationLeavesAnotherManagersFieldAlone(t *testing.T) {
	r := openRealAPI(t)
	ns := r.runNamespace(t, "scale")
	ctx := t.Context()
	k := r.kernel(t, ns)
	r.seed(t, kindDeployment, ns, doc(fatlineV1, ns, seedV1), seedV1bPatch)
	r.check(t, k.Scale(ctx, ns, "fatline", 0), "the kernel's Scale")
	scaled := r.object(t, kindDeployment, ns, "fatline")
	fact(t, "after the kernel's Scale to 0: entries %v", entryNames(scaled.Metadata))

	r.check(t, r.mergePatch(ctx, kindDeployment, ns, "fatline", []byte(`{"spec":{"replicas":3}}`), realAPIOther), "realapi-other's merge PATCH")
	patched := r.object(t, kindDeployment, ns, "fatline")
	other, ok := otherReplicasEntry(patched.Metadata)
	fact(t, "after %s's merge PATCH of spec.replicas: entries %v; %s/Update owns spec.replicas: %t", realAPIOther, entryNames(patched.Metadata), realAPIOther, ok)
	if !ok {
		t.Fatalf("after its merge PATCH, no %s/Update entry owns spec.replicas", realAPIOther)
	}

	m, err := r.migrateOne(ctx, kindDeployment, ns, "fatline")
	r.check(t, err, "the migration")
	migrated, ok := otherReplicasEntry(m.after.Metadata)
	fact(t, "after the migration: entries %v; %s/Update unchanged: %t", entryNames(m.after.Metadata), realAPIOther, ok && sameEntries([]ManagedFieldsEntry{other}, []ManagedFieldsEntry{migrated}))
	if !ok || !sameEntries([]ManagedFieldsEntry{other}, []ManagedFieldsEntry{migrated}) {
		t.Errorf("the migration changed %s's entry, or its ownership of spec.replicas", realAPIOther)
	}
	if got := field(r.raw(t, kindDeployment.Path(ns, "fatline")), "spec", "replicas"); got != float64(3) {
		t.Errorf("spec.replicas reads %v after the migration, not %s's 3", got, realAPIOther)
	}

	r.apply(t, doc(fatlineV1, ns, seedV1b, "{replicas}", "1"), true)
	reset := r.object(t, kindDeployment, ns, "fatline")
	var farcastOwns bool
	for _, e := range reset.Metadata.ManagedFields {
		if IsOwnApply(e) && owns(e, "f:spec", "f:replicas") {
			farcastOwns = true
		}
	}
	fact(t, "after a forced farcast apply of replicas: 1: entries %v; farcast/Apply owns spec.replicas: %t", entryNames(reset.Metadata), farcastOwns)
	if got := field(r.raw(t, kindDeployment.Path(ns, "fatline")), "spec", "replicas"); got != float64(1) {
		t.Errorf("spec.replicas reads %v after the forced apply of 1", got)
	}
	if !farcastOwns {
		t.Error("farcast/Apply does not own spec.replicas after its forced apply")
	}
}

// realAPIOther is the other manager TestMigrationLeavesAnotherManagersFieldAlone
// writes as, the name the suite's other second appliers use too.
const realAPIOther = "realapi-other"

// otherReplicasEntry is md's realapi-other/Update entry on the main
// resource, and whether there is one that owns spec.replicas.
func otherReplicasEntry(md ObjectMeta) (ManagedFieldsEntry, bool) {
	for _, e := range md.ManagedFields {
		if e.Manager == realAPIOther && e.Operation == "Update" && e.Subresource == "" && owns(e, "f:spec", "f:replicas") {
			return e, true
		}
	}
	return ManagedFieldsEntry{}, false
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

// sameEntries compares two lists of entries by manager, operation,
// subresource and fields, the time aside.
func sameEntries(a, b []ManagedFieldsEntry) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if entryName(a[i]) != entryName(b[i]) || !sameFields(a[i].FieldsV1, b[i].FieldsV1) {
			return false
		}
	}
	return true
}

// sameFields compares two fieldsV1 as decoded JSON.
func sameFields(a, b json.RawMessage) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

// seedDocs reads one of the kubectl variant's files, testdata/realapi/<file>,
// the documents R7 applies with kubectl -n: each decoded, in file order.
func seedDocs(t *testing.T, file string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "realapi", file))
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, c := range splitChunks(b) {
		if c.empty() {
			continue
		}
		var m map[string]any
		if err := yaml.Unmarshal(c.raw, &m); err != nil {
			t.Fatalf("%s: a document does not decode: %v", file, err)
		}
		out = append(out, cloneJSON(m))
	}
	return out
}

// seedV2 is a kubectl seed document as farcast applies its next version:
// v1b in namespace ns, without the label farcast.sofmon.com/instance, and a
// Secret's stringData as data:. It is YAML, which SplitStream checks.
func seedV2(t *testing.T, v1b map[string]any, ns string) string {
	t.Helper()
	v2 := cloneJSON(v1b)
	labels, _ := field(v2, "metadata", "labels").(map[string]any)
	if _, ok := labels["farcast.sofmon.com/instance"]; !ok {
		t.Fatal("a seed document carries no label farcast.sofmon.com/instance to drop")
	}
	delete(labels, "farcast.sofmon.com/instance")
	field(v2, "metadata").(map[string]any)["namespace"] = ns
	if sd, ok := v2["stringData"].(map[string]any); ok {
		data := map[string]any{}
		for k, v := range sd {
			s, _ := v.(string)
			data[k] = base64.StdEncoding.EncodeToString([]byte(s))
		}
		delete(v2, "stringData")
		v2["data"] = data
	}
	// Through JSON, so a number decoded as a float64 is written as the
	// integer it is (443, not 443.0).
	j, err := json.Marshal(v2)
	if err != nil {
		t.Fatal(err)
	}
	b, err := yaml.JSONToYAML(j)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// seedEntry is a managed-fields entry as the kubectl variant compares it:
// the time and the apiVersion aside.
type seedEntry struct {
	Name   string
	Fields any
}

func seedEntriesOf(t *testing.T, md ObjectMeta) []seedEntry {
	t.Helper()
	out := make([]seedEntry, 0, len(md.ManagedFields))
	for _, e := range md.ManagedFields {
		var f any
		if err := json.Unmarshal(e.FieldsV1, &f); err != nil {
			t.Fatalf("%s's fieldsV1 does not decode", entryName(e))
		}
		out = append(out, seedEntry{Name: entryName(e), Fields: f})
	}
	return out
}

// TestEmulatedSeedMatchesKubectl validates the emulated client-side seed the
// stuck-field cases rely on (A30-3), once, in R7: kubectl has applied
// kubectl-seed-v1.yaml and then kubectl-seed-v1b.yaml in the namespace
// FARCAST_REALAPI_KUBECTL_NAMESPACE names; this seeds the same documents with
// seedClientSide in a namespace of its own. Each entry's manager, operation,
// subresource and fieldsV1, and the annotation's presence, must match. Then
// both are migrated and applied as v2, and must end the same way.
func TestEmulatedSeedMatchesKubectl(t *testing.T) {
	kns := os.Getenv(envRealAPIKubectlNamespace)
	if kns == "" {
		t.Skipf("%s is unset: this test compares kubectl's own client-side seed, which R7 of docs/runbooks/adr-0023-m2-realapi.md makes on the VM, with the emulated one, and R7 runs it", envRealAPIKubectlNamespace)
	}
	r := openRealAPI(t)
	ns := r.runNamespace(t, "emulated")
	ctx := t.Context()
	v1s, v1bs := seedDocs(t, "kubectl-seed-v1.yaml"), seedDocs(t, "kubectl-seed-v1b.yaml")
	if len(v1s) == 0 || len(v1s) != len(v1bs) {
		t.Fatalf("the seed files hold %d and %d documents", len(v1s), len(v1bs))
	}
	for i, v1 := range v1s {
		v1b := v1bs[i]
		apiVersion, _ := v1["apiVersion"].(string)
		kindName, _ := v1["kind"].(string)
		name, _ := field(v1, "metadata", "name").(string)
		k, ok := KindOf(apiVersion, kindName)
		if !ok || v1b["kind"] != kindName || field(v1b, "metadata", "name") != name {
			t.Fatalf("seed document %d: %s %s %q is not a kind farcast applies, or v1b's document %d is not the same object", i, apiVersion, kindName, name, i)
		}
		t.Run(kindName+" "+name, func(t *testing.T) {
			v1JSON, err := json.Marshal(v1)
			r.check(t, err, "v1")
			patch, err := secondApplyPatch(v1, v1b)
			r.check(t, err, "v1b's patch")
			var smp []byte
			if patch != nil {
				if smp, err = json.Marshal(patch); err != nil {
					t.Fatal(err)
				}
			}
			r.check(t, r.seedClientSide(ctx, k, ns, v1JSON, smp), "the emulated seed")
			kubectl := r.object(t, k, kns, name).Metadata
			emulated := r.object(t, k, ns, name).Metadata
			same := reflect.DeepEqual(seedEntriesOf(t, kubectl), seedEntriesOf(t, emulated)) && annotated(kubectl) == annotated(emulated)
			fact(t, "%s %s: kubectl's seed %v, annotation %t; the emulated seed %v, annotation %t; equal: %t",
				kindName, name, entryNames(kubectl), annotated(kubectl), entryNames(emulated), annotated(emulated), same)
			if !same {
				for _, md := range []struct {
					who string
					md  ObjectMeta
				}{{"kubectl's", kubectl}, {"the emulated", emulated}} {
					for _, e := range md.md.ManagedFields {
						fact(t, "%s seed's %s fieldsV1 %s", md.who, entryName(e), e.FieldsV1)
					}
				}
				t.Errorf("the emulated seed differs from kubectl's")
			}
			for _, n := range []string{kns, ns} {
				m, err := r.migrateOne(ctx, k, n, name)
				r.check(t, err, "the migration")
				r.apply(t, seedV2(t, v1b, n), true)
				if field(r.raw(t, k.Path(n, name)), "metadata", "labels", "farcast.sofmon.com/instance") != nil {
					t.Errorf("stuck field: the label farcast.sofmon.com/instance is still on the live %s after v2's forced apply", kindName)
				}
				back := r.object(t, k, n, name)
				if err := MigratedEndState(back, m.csa, FieldManager, m.hadApply); err != nil {
					t.Errorf("the end state after v2's apply: %v", err)
				}
			}
		})
	}
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

// TestServiceAccountUIDSurvivesForcedApplyAndMigration (design §33, R1;
// written, not run): the grants of ADR 0023 M2.8 name a ServiceAccount by
// the uid the API server gave it, so nothing farcast does to the account
// may give it another. A forced apply of the builder's ServiceAccount over
// itself, as kernel deploy and every build apply it, keeps its uid; and a
// keyholder's ServiceAccount kubectl's client-side apply created keeps its
// uid through the migration's patch and the first forced apply after it.
// What it records: whether each kept the uid, never the uid.
func TestServiceAccountUIDSurvivesForcedApplyAndMigration(t *testing.T) {
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

	keyholder := fmt.Sprintf(serviceAccountDoc, "datasphered", ns, "datasphered")
	r.seed(t, k, ns, keyholder, "")
	seeded := r.object(t, k, ns, "datasphered").Metadata
	m, err := r.migrateOne(t.Context(), k, ns, "datasphered")
	r.check(t, err, "the migration of the ServiceAccount")
	r.apply(t, keyholder, true)
	applied := r.object(t, k, ns, "datasphered").Metadata
	fact(t, "a ServiceAccount kubectl created: uid kept through the migration %t, through the first apply after it %t; entries %v",
		m.after.Metadata.UID == seeded.UID, applied.UID == seeded.UID, entryNames(applied))
	if seeded.UID == "" || m.after.Metadata.UID != seeded.UID || applied.UID != seeded.UID {
		t.Errorf("the migration, or the first apply after it, gave the ServiceAccount another uid")
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
