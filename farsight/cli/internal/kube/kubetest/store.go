package kubetest

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/kube"
)

// podKind is the one kind kubetest serves beyond kube.Kinds: farcast never
// applies a Pod, but its reads list pods and follow their logs.
var podKind = kube.Kind{Kind: "Pod", APIVersion: "v1", Resource: "pods", Namespaced: true}

// servedKinds is every kind the emulation stores, lists and answers.
var servedKinds = append(kube.Kinds[:len(kube.Kinds):len(kube.Kinds)], podKind)

func kindOf(apiVersion, kind string) (kube.Kind, bool) {
	for _, k := range servedKinds {
		if k.APIVersion == apiVersion && k.Kind == kind {
			return k, true
		}
	}
	return kube.Kind{}, false
}

func kindByResource(apiVersion, resource string) (kube.Kind, bool) {
	for _, k := range servedKinds {
		if k.APIVersion == apiVersion && k.Resource == resource {
			return k, true
		}
	}
	return kube.Kind{}, false
}

// groupOf is a kind's API group: "" for the core group.
func groupOf(k kube.Kind) string {
	if g, _, ok := strings.Cut(k.APIVersion, "/"); ok {
		return g
	}
	return ""
}

// qualifiedResource is how the API server's messages name a resource:
// "configmaps", "deployments.apps".
func qualifiedResource(k kube.Kind) string {
	if g := groupOf(k); g != "" {
		return k.Resource + "." + g
	}
	return k.Resource
}

// kindFor is the kind a request addresses, when kubetest serves it at that
// scope: a namespaced kind's object needs its namespace, and a cluster-scoped
// kind names none (a Namespace object's namespace attribute is its own name,
// as the API server reads it).
func kindFor(ri requestInfo) (kube.Kind, bool) {
	if !ri.resourceRequest {
		return kube.Kind{}, false
	}
	k, ok := kindByResource(ri.apiVersion(), ri.resource)
	if !ok {
		return kube.Kind{}, false
	}
	switch {
	case k.Namespaced:
		if ri.name != "" && ri.namespace == "" {
			return kube.Kind{}, false
		}
	case k.Resource == "namespaces":
		if ri.namespace != ri.name {
			return kube.Kind{}, false
		}
	default:
		if ri.namespace != "" {
			return kube.Kind{}, false
		}
	}
	return k, true
}

// singleObjectKind is the kind of a single-object path, for Script.
func singleObjectKind(path string) (kube.Kind, bool) {
	ri := parseRequestInfo(http.MethodGet, path, nil)
	if ri.name == "" || ri.subresource != "" {
		return kube.Kind{}, false
	}
	return kindFor(ri)
}

// stored is one object, as the server keeps it: JSON decoded with numbers
// kept exact, kind and apiVersion included.
type stored struct {
	kind            kube.Kind
	namespace, name string
	obj             map[string]any
}

// serverSetMetadata are the metadata fields only the server sets. A write's
// body never sets them; the server does.
var serverSetMetadata = []string{"uid", "resourceVersion", "creationTimestamp", "managedFields", "generation", "deletionTimestamp", "selfLink"}

// generationKinds are the kinds whose metadata.generation the server keeps
// and moves when their spec changes [unverified, from memory of the
// Kubernetes registry strategies; the rollout rules read it on Deployments].
var generationKinds = map[string]bool{"Deployment": true, "StatefulSet": true, "Job": true, "PodDisruptionBudget": true, "NetworkPolicy": true}

// Put seeds an object (JSON-marshalled).
//
// obj may also be raw JSON, as []byte or json.RawMessage. It must carry the
// apiVersion and kind of a kind kubetest serves (kube.Kinds, and Pod), a
// metadata.name, and a metadata.namespace exactly when the kind is
// namespaced; otherwise Put panics. The object is stored as given, an
// existing one at the same path replaced, except that a missing uid,
// resourceVersion or creationTimestamp is set: a re-seed without a uid is a
// new object, with a new uid. A pod's logs are its LogAnnotationPrefix and
// PreviousLogAnnotationPrefix annotations.
func (s *Server) Put(obj any) {
	raw, err := marshalAny(obj)
	if err != nil {
		panic(fmt.Sprintf("kubetest: Put: %v", err))
	}
	m, err := decodeJSONObject(raw)
	if err != nil {
		panic(fmt.Sprintf("kubetest: Put: %v", err))
	}
	k, ok := kindOf(str(m, "apiVersion"), str(m, "kind"))
	if !ok {
		panic(fmt.Sprintf("kubetest: Put: kind %q %q is not one kubetest serves", str(m, "apiVersion"), str(m, "kind")))
	}
	md := metadataOf(m)
	name, ns := str(md, "name"), str(md, "namespace")
	switch {
	case name == "":
		panic(fmt.Sprintf("kubetest: Put: a %s with no metadata.name", k.Kind))
	case k.Namespaced && ns == "":
		panic(fmt.Sprintf("kubetest: Put: a namespaced %s %q with no metadata.namespace", k.Kind, name))
	case !k.Namespaced && ns != "":
		panic(fmt.Sprintf("kubetest: Put: a cluster-scoped %s %q with namespace %q", k.Kind, name, ns))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if str(md, "uid") == "" {
		md["uid"] = newUID()
	}
	if rv := str(md, "resourceVersion"); rv == "" {
		md["resourceVersion"] = s.nextRV()
	} else if n, err := strconv.ParseUint(rv, 10, 64); err == nil && n > s.rv {
		s.rv = n
	}
	if _, ok := md["creationTimestamp"]; !ok {
		md["creationTimestamp"] = nowString()
	}
	s.objects[k.Path(ns, name)] = &stored{kind: k, namespace: ns, name: name, obj: m}
}

// nextRV is a fresh resourceVersion. It is called with mu held.
func (s *Server) nextRV() string {
	s.rv++
	return strconv.FormatUint(s.rv, 10)
}

// newUID is a random version-4 UUID.
func newUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("kubetest: draw a uid: %v", err))
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func nowString() string { return time.Now().UTC().Format(time.RFC3339) }

// decodeJSONObject decodes exactly one JSON object, with numbers kept as
// json.Number so they re-encode exactly.
func decodeJSONObject(b []byte) (map[string]any, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var m map[string]any
	if err := d.Decode(&m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errNotObject
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errNotObject
	}
	return m, nil
}

// cloneObject is a deep copy, through JSON.
func cloneObject(m map[string]any) map[string]any {
	c, err := decodeJSONObject(mustMarshal(m))
	if err != nil {
		panic(fmt.Sprintf("kubetest: copy an object: %v", err))
	}
	return c
}

// metadataOf is m's metadata, made empty when absent.
func metadataOf(m map[string]any) map[string]any {
	md, ok := m["metadata"].(map[string]any)
	if !ok {
		md = map[string]any{}
		m["metadata"] = md
	}
	return md
}

func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// stampKind gives an object its kind's kind and apiVersion when it carries
// none, as a real server's single-object answers do.
func stampKind(m map[string]any, k kube.Kind) {
	if str(m, "kind") == "" {
		m["kind"] = k.Kind
	}
	if str(m, "apiVersion") == "" {
		m["apiVersion"] = k.APIVersion
	}
}

// emulate is the API emulation, after every earlier step let the request by.
func (s *Server) emulate(w http.ResponseWriter, r *http.Request, req Request, ri requestInfo, caller tokenInfo, az *authorizer) {
	if r.Method == http.MethodPost && ri.isSelfReview() {
		s.selfReview(w, req, caller)
		return
	}
	k, ok := kindFor(ri)
	if !ok {
		notEmulated(w, r)
		return
	}
	object := ri.name != "" && ri.subresource == ""
	switch r.Method {
	case http.MethodGet:
		switch {
		case ri.name == "":
			s.list(w, r, ri, k)
			return
		case object:
			s.get(w, r, ri, k)
			return
		case ri.subresource == "log" && k.Kind == podKind.Kind && k.APIVersion == podKind.APIVersion:
			s.logs(w, r, ri, k)
			return
		}
	case http.MethodPatch:
		if object {
			switch mediaType(req.ContentType) {
			case applyPatchType:
				s.apply(w, r, req, ri, k, caller, az)
				return
			case "application/json-patch+json":
				s.jsonPatch(w, r, req, ri, k)
				return
			}
		}
	case http.MethodPost:
		if ri.name == "" && ri.namespace != "" && k.Kind == "ConfigMap" {
			s.createConfigMap(w, req, ri, k)
			return
		}
	case http.MethodPut:
		if object && k.Kind == "ConfigMap" {
			s.replaceConfigMap(w, req, ri, k)
			return
		}
	case http.MethodDelete:
		if object && k.Kind == "Secret" {
			s.deleteSecret(w, req, ri, k)
			return
		}
	}
	notEmulated(w, r)
}

// applyPatchType is a server-side apply's Content-Type.
const applyPatchType = "application/apply-patch+yaml"

func mediaType(contentType string) string {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return ""
	}
	return mt
}

// The metadata-only views an Accept header may ask for.
const (
	metaGroup        = "meta.k8s.io"
	asPartial        = "PartialObjectMetadata"
	asPartialList    = "PartialObjectMetadataList"
	metaV1APIVersion = metaGroup + "/v1"
)

// wantPartial reads Accept: the first application/json media type decides.
// One that asks, with as=, g=meta.k8s.io and v=v1, for the metadata-only view
// of this answer (PartialObjectMetadata for an object,
// PartialObjectMetadataList for a list) gets it; one that asks for any other
// view is not acceptable (406). No application/json type is the full answer.
func wantPartial(accept string, list bool) (bool, error) {
	want := asPartial
	if list {
		want = asPartialList
	}
	for _, part := range strings.Split(accept, ",") {
		mt, params, err := mime.ParseMediaType(strings.TrimSpace(part))
		if err != nil || mt != "application/json" {
			continue
		}
		as := params["as"]
		if as == "" {
			return false, nil
		}
		if as != want || params["g"] != metaGroup || params["v"] != "v1" {
			return false, fmt.Errorf("kubetest serves application/json, and application/json;as=%s;g=%s;v=v1 here; not as=%s;g=%s;v=%s", want, metaGroup, as, params["g"], params["v"])
		}
		return true, nil
	}
	return false, nil
}

// answerBody is one object as an answer carries it: whole, or, when the
// request asked for it (wantPartial), its metadata alone as a
// PartialObjectMetadata. A GET and a PATCH answer alike.
func answerBody(obj map[string]any, partial bool) []byte {
	if partial {
		return mustMarshal(map[string]any{"kind": asPartial, "apiVersion": metaV1APIVersion, "metadata": obj["metadata"]})
	}
	return mustMarshal(obj)
}

func notFound(w http.ResponseWriter, k kube.Kind, name string) {
	writeStatus(w, http.StatusNotFound, "", fmt.Sprintf("%s %q not found", qualifiedResource(k), name),
		&wireDetails{Name: name, Group: groupOf(k), Kind: k.Resource})
}

// get is a GET of one object: the object with its kind and apiVersion, or its
// metadata only as a PartialObjectMetadata; 404 when absent.
func (s *Server) get(w http.ResponseWriter, r *http.Request, ri requestInfo, k kube.Kind) {
	partial, err := wantPartial(r.Header.Get("Accept"), false)
	if err != nil {
		writeStatus(w, http.StatusNotAcceptable, "", err.Error(), nil)
		return
	}
	s.mu.Lock()
	so := s.objects[k.Path(ri.namespace, ri.name)]
	var body []byte
	if so != nil {
		body = answerBody(so.obj, partial)
	}
	s.mu.Unlock()
	if so == nil {
		notFound(w, k, ri.name)
		return
	}
	writeRaw(w, http.StatusOK, "application/json", body)
}

// requirement is one equality-based selector term.
type requirement struct {
	key, value string
	not        bool // != rather than = or ==
}

// parseSelector reads an equality-based selector: comma-separated terms
// k=v, k==v and k!=v. A set-based or existence term is refused, because
// kubetest does not emulate it.
func parseSelector(sel string) ([]requirement, error) {
	sel = strings.TrimSpace(sel)
	if sel == "" {
		return nil, nil
	}
	var reqs []requirement
	for _, term := range strings.Split(sel, ",") {
		term = strings.TrimSpace(term)
		var rq requirement
		var key, value string
		var found bool
		switch {
		case strings.Contains(term, "!="):
			key, value, found = strings.Cut(term, "!=")
			rq.not = true
		case strings.Contains(term, "=="):
			key, value, found = strings.Cut(term, "==")
		default:
			key, value, found = strings.Cut(term, "=")
		}
		rq.key, rq.value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !found || rq.key == "" || strings.ContainsAny(rq.key+rq.value, " !=(),") {
			return nil, fmt.Errorf("kubetest honours equality-based selector terms only (k=v, k==v, k!=v), not %q", term)
		}
		reqs = append(reqs, rq)
	}
	return reqs, nil
}

func (rq requirement) matches(value string, present bool) bool {
	if rq.not {
		return !present || value != rq.value
	}
	return present && value == rq.value
}

// continueToken is the opaque continue of a paged list: the key of the last
// item it returned.
type continueToken struct {
	Namespace string `json:"ns"`
	Name      string `json:"name"`
}

// list is a GET of a collection: in one namespace, or in every namespace when
// the path names none. It honours labelSelector and fieldSelector
// (metadata.name and metadata.namespace) with equality terms, pages with
// limit and continue in namespace-then-name order, and answers metadata-only
// items to an Accept that asks for a PartialObjectMetadataList. As the real
// server answered (v1.36.2, ADR 0023 design §31), a typed list's items carry
// no kind or apiVersion, and neither do these; a partial list's items there
// are each a PartialObjectMetadata, where these carry their metadata alone.
// kube stamps each item's kind from the kind it listed, so neither reaches a
// caller.
func (s *Server) list(w http.ResponseWriter, r *http.Request, ri requestInfo, k kube.Kind) {
	q := r.URL.Query()
	labels, err := parseSelector(q.Get("labelSelector"))
	if err != nil {
		writeStatus(w, http.StatusBadRequest, "", err.Error(), nil)
		return
	}
	fields, err := parseSelector(q.Get("fieldSelector"))
	if err != nil {
		writeStatus(w, http.StatusBadRequest, "", err.Error(), nil)
		return
	}
	for _, f := range fields {
		if f.key != "metadata.name" && f.key != "metadata.namespace" {
			writeStatus(w, http.StatusBadRequest, "", fmt.Sprintf("%q is not a known field selector: only \"metadata.name\", \"metadata.namespace\"", f.key), nil)
			return
		}
	}
	limit := 0
	if v := q.Get("limit"); v != "" {
		if limit, err = strconv.Atoi(v); err != nil || limit < 0 {
			writeStatus(w, http.StatusBadRequest, "", fmt.Sprintf("limit %q is not a non-negative integer", v), nil)
			return
		}
	}
	var after *continueToken
	if v := q.Get("continue"); v != "" {
		after, err = decodeContinue(v)
		if err != nil {
			writeStatus(w, http.StatusBadRequest, "", "continue key is not valid", nil)
			return
		}
	}
	partial, err := wantPartial(r.Header.Get("Accept"), true)
	if err != nil {
		writeStatus(w, http.StatusNotAcceptable, "", err.Error(), nil)
		return
	}
	namespace := ""
	if k.Namespaced {
		namespace = ri.namespace
	}

	s.mu.Lock()
	var matched []*stored
	for _, so := range s.objects {
		if so.kind.APIVersion != k.APIVersion || so.kind.Kind != k.Kind {
			continue
		}
		if namespace != "" && so.namespace != namespace {
			continue
		}
		if after != nil && !keyAfter(so, after) {
			continue
		}
		if !selected(so, labels, fields) {
			continue
		}
		matched = append(matched, so)
	}
	slices.SortFunc(matched, func(a, b *stored) int {
		if c := strings.Compare(a.namespace, b.namespace); c != 0 {
			return c
		}
		return strings.Compare(a.name, b.name)
	})
	meta := map[string]any{"resourceVersion": strconv.FormatUint(s.rv, 10)}
	if limit > 0 && len(matched) > limit {
		last := matched[limit-1]
		meta["continue"] = encodeContinue(continueToken{Namespace: last.namespace, Name: last.name})
		meta["remainingItemCount"] = len(matched) - limit
		matched = matched[:limit]
	}
	items := make([]any, 0, len(matched))
	for _, so := range matched {
		if partial {
			items = append(items, map[string]any{"metadata": so.obj["metadata"]})
			continue
		}
		item := make(map[string]any, len(so.obj))
		for key, v := range so.obj {
			if key != "kind" && key != "apiVersion" {
				item[key] = v
			}
		}
		items = append(items, item)
	}
	answer := map[string]any{"kind": k.Kind + "List", "apiVersion": k.APIVersion, "metadata": meta, "items": items}
	if partial {
		answer["kind"], answer["apiVersion"] = asPartialList, metaV1APIVersion
	}
	body := mustMarshal(answer)
	s.mu.Unlock()
	writeRaw(w, http.StatusOK, "application/json", body)
}

func keyAfter(so *stored, after *continueToken) bool {
	if so.namespace != after.Namespace {
		return so.namespace > after.Namespace
	}
	return so.name > after.Name
}

// selected reports whether an object's labels and fields satisfy every term.
func selected(so *stored, labels, fields []requirement) bool {
	md := metadataOf(so.obj)
	lm, _ := md["labels"].(map[string]any)
	for _, rq := range labels {
		v, present := lm[rq.key].(string)
		if !rq.matches(v, present) {
			return false
		}
	}
	for _, rq := range fields {
		v := so.name
		if rq.key == "metadata.namespace" {
			v = so.namespace
		}
		if !rq.matches(v, true) {
			return false
		}
	}
	return true
}

func encodeContinue(t continueToken) string {
	return base64.RawURLEncoding.EncodeToString(mustMarshal(t))
}

func decodeContinue(v string) (*continueToken, error) {
	b, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return nil, err
	}
	var t continueToken
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, err
	}
	if t.Name == "" {
		return nil, errNotObject
	}
	return &t, nil
}
