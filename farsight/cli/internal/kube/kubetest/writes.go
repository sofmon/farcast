package kubetest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/sofmon/farcast/farsight/cli/internal/kube"
)

// mfEntry is meta/v1's ManagedFieldsEntry on the wire, kubetest's own copy.
// It is used to read and write the store's own entries.
type mfEntry struct {
	Manager     string          `json:"manager,omitempty"`
	Operation   string          `json:"operation,omitempty"`
	APIVersion  string          `json:"apiVersion,omitempty"`
	Time        string          `json:"time,omitempty"`
	FieldsType  string          `json:"fieldsType,omitempty"`
	FieldsV1    json.RawMessage `json:"fieldsV1,omitempty"`
	Subresource string          `json:"subresource,omitempty"`
}

const (
	operationApply = "Apply"
	fieldsTypeV1   = "FieldsV1"
)

// The wire names of the fields of the bodies kubetest checks under strict
// field validation, case and all: meta/v1's ObjectMeta (k8s.io/apimachinery
// v0.37.2 pkg/apis/meta/v1/types.go) and core/v1's ConfigMap (k8s.io/api
// v0.37.2 core/v1/types.go). DeleteOptions and a SelfSubjectAccessReview are
// read by their exact keys too, but never under strict validation, so an
// unknown key in them is only dropped.
//
// The API server decodes every request body case-sensitively: an unknown key,
// one that differs from a field's name only in case included, is dropped, or
// under fieldValidation=Strict refused (k8s.io/apimachinery v0.37.2
// pkg/runtime/serializer/json/json.go, unmarshal:
// UnmarshalCaseSensitivePreserveInts, and UnmarshalStrict when strict).
// encoding/json's struct decoding matches a key in any case, so a client that
// sent "Preconditions" would pass against a fake that used it, while a real
// server deletes without the precondition. kubetest therefore reads what a
// client sends as maps whose keys must match exactly.
var (
	configMapFields  = []string{"apiVersion", "kind", "metadata", "immutable", "data", "binaryData"}
	objectMetaFields = []string{
		"name", "generateName", "namespace", "selfLink", "uid", "resourceVersion", "generation",
		"creationTimestamp", "deletionTimestamp", "deletionGracePeriodSeconds", "labels", "annotations",
		"ownerReferences", "finalizers", "managedFields",
	}
)

// exactObject reads one JSON object with its keys as they were sent.
func exactObject(raw []byte) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, errNotObject
	}
	return m, nil
}

// unknownField is the first of keys, in sorted order, that is not exactly one
// of known, prefixed with prefix (such as "metadata."); "" when there is none.
func unknownField(keys []string, prefix string, known []string) string {
	slices.Sort(keys)
	for _, k := range keys {
		if !slices.Contains(known, k) {
			return prefix + k
		}
	}
	return ""
}

func keysOf[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// stringValue reads one JSON string; absent (nil) and null are "".
func stringValue(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || isNull(raw) {
		return "", nil
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", err
	}
	return v, nil
}

func isNull(raw json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) }

// strictDecodingError is the API server's words for a key no field has,
// under fieldValidation=Strict (sigs.k8s.io/json's strict errors, as
// k8s.io/apimachinery v0.37.2 runtime.NewStrictDecodingError renders them).
func strictDecodingError(field string) error {
	return fmt.Errorf("strict decoding error: unknown field %q", field)
}

// entriesOf reads an object's managed fields.
func entriesOf(md map[string]any) ([]mfEntry, error) {
	v, ok := md["managedFields"]
	if !ok || v == nil {
		return nil, nil
	}
	var es []mfEntry
	if err := json.Unmarshal(mustMarshal(v), &es); err != nil {
		return nil, err
	}
	return es, nil
}

// setEntries writes an object's managed fields; none removes the field.
func setEntries(md map[string]any, es []mfEntry) {
	if len(es) == 0 {
		delete(md, "managedFields")
		return
	}
	var v []any
	d := json.NewDecoder(bytes.NewReader(mustMarshal(es)))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		panic(fmt.Sprintf("kubetest: encode managed fields: %v", err))
	}
	md["managedFields"] = v
}

// sortEntries is the API server's order of managed-fields entries:
// operation, then time ascending, then manager, apiVersion and subresource.
// A port of k8s.io/apimachinery v0.37.2
// pkg/util/managedfields/internal/managedfields.go (sortEncodedManagedFields),
// made stable.
func sortEntries(es []mfEntry) {
	seconds := func(e mfEntry) int64 {
		t, err := time.Parse(time.RFC3339, e.Time)
		if err != nil {
			return 0
		}
		return t.Unix()
	}
	slices.SortStableFunc(es, func(p, q mfEntry) int {
		if p.Operation != q.Operation {
			return strings.Compare(p.Operation, q.Operation)
		}
		if ps, qs := seconds(p), seconds(q); ps != qs {
			if ps < qs {
				return -1
			}
			return 1
		}
		if p.Manager != q.Manager {
			return strings.Compare(p.Manager, q.Manager)
		}
		if p.APIVersion != q.APIVersion {
			return strings.Compare(p.APIVersion, q.APIVersion)
		}
		return strings.Compare(p.Subresource, q.Subresource)
	})
}

// decodeYAMLObject reads an apply body with go-yaml, as one mapping, and
// returns it in the store's JSON form.
func decodeYAMLObject(body []byte) (map[string]any, error) {
	var m map[string]any
	if err := yaml.Unmarshal(body, &m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errNotObject
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return decodeJSONObject(b)
}

// conflict is the API server's answer to a write at a resourceVersion that is
// not current.
func conflict(w http.ResponseWriter, k kube.Kind, name string) {
	writeStatus(w, http.StatusConflict, "", fmt.Sprintf("Operation cannot be fulfilled on %s %q: the object has been modified; please apply your changes to the latest version and try again", qualifiedResource(k), name),
		&wireDetails{Name: name, Group: groupOf(k), Kind: k.Resource})
}

func badRequest(w http.ResponseWriter, format string, a ...any) {
	writeStatus(w, http.StatusBadRequest, "", fmt.Sprintf(format, a...), nil)
}

func invalid(w http.ResponseWriter, k kube.Kind, name, format string, a ...any) {
	writeStatus(w, http.StatusUnprocessableEntity, "", fmt.Sprintf("%s %q is invalid: %s", k.Kind, name, fmt.Sprintf(format, a...)),
		&wireDetails{Name: name, Group: groupOf(k), Kind: k.Kind})
}

// apply is a server-side apply: PATCH with Content-Type
// application/apply-patch+yaml. It requires fieldManager and
// fieldValidation=Strict, a YAML body with the URL's kind, name and
// namespace, and answers 201 on create and 200 on update with the object, or
// its metadata alone as a PartialObjectMetadata when Accept asks for that, as
// a GET's answer is.
//
// The object becomes the body, minus status and the server-set metadata,
// which the server keeps (uid, creationTimestamp, status) or sets
// (resourceVersion, and generation on the kinds that carry one, moved when
// the spec changes). Its managed fields keep one entry per manager: this
// manager's Apply entry, {manager, operation: Apply, apiVersion, time,
// fieldsType: FieldsV1, fieldsV1: {}}, is replaced, and every other entry
// stays as it was. No field-level ownership is kept, so no conflict is ever
// found; Fail and FailNextApply inject one. An apply that changes nothing
// writes nothing. WithSettledWorkloads settles what it stores.
//
// A body that carries metadata.resourceVersion is held to it, as the API
// server holds one (design §31, A31-2): one that is not the stored object's
// answers 409 Conflict and stores nothing, and the stored one applies. For an
// absent object it is no precondition: the object is created, answered 201,
// as the server recreates a deleted one. An empty or null one is none at all,
// and one that is not a string answers 422.
//
// A gap, kept on purpose: kubetest rebuilds an applied object from the body.
// From the stored one it keeps only uid, creationTimestamp, resourceVersion,
// status, and other managers' managed-fields entries (and, under
// WithSettledWorkloads, a Job's selector and template labels). A real server
// keeps every field another manager owns (kubectl's last-applied annotation,
// the kernel's adapted-at annotation). It also keeps replicas set through
// /scale, which no manager owns after a /scale of 0, against an apply that
// omits it; an apply that carries it takes it back.
func (s *Server) apply(w http.ResponseWriter, r *http.Request, req Request, ri requestInfo, k kube.Kind, caller tokenInfo, az *authorizer) {
	partial, err := wantPartial(r.Header.Get("Accept"), false)
	if err != nil {
		writeStatus(w, http.StatusNotAcceptable, "", err.Error(), nil)
		return
	}
	q := r.URL.Query()
	manager := q.Get("fieldManager")
	if manager == "" {
		badRequest(w, "PATCH with application/apply-patch+yaml requires the fieldManager parameter")
		return
	}
	if v := q.Get("fieldValidation"); v != "Strict" {
		badRequest(w, "kubetest requires fieldValidation=Strict on every apply, not %q", v)
		return
	}
	if v := q.Get("force"); v != "" {
		if _, err := strconv.ParseBool(v); err != nil {
			badRequest(w, "force %q is not a boolean", v)
			return
		}
	}
	if q.Has("dryRun") {
		badRequest(w, "kubetest does not emulate dryRun")
		return
	}
	applied, err := decodeYAMLObject(req.Body)
	if err != nil {
		badRequest(w, "error decoding patch: the body is not one YAML mapping")
		return
	}
	if str(applied, "apiVersion") != k.APIVersion || str(applied, "kind") != k.Kind {
		badRequest(w, "the body is %s %s, and the URL addresses %s %s", str(applied, "apiVersion"), str(applied, "kind"), k.APIVersion, k.Kind)
		return
	}
	amd := metadataOf(applied)
	wantNS := ""
	if k.Namespaced {
		wantNS = ri.namespace
	}
	if name := str(amd, "name"); name != ri.name {
		badRequest(w, "the name of the object (%s) does not match the name on the URL (%s)", name, ri.name)
		return
	}
	if ns := str(amd, "namespace"); ns != wantNS {
		badRequest(w, "the namespace of the object (%s) does not match the namespace on the URL (%s)", ns, wantNS)
		return
	}
	var rv string
	if v := amd["resourceVersion"]; v != nil {
		var ok bool
		if rv, ok = v.(string); !ok {
			invalid(w, k, ri.name, "metadata.resourceVersion is not a string")
			return
		}
	}

	path := k.Path(ri.namespace, ri.name)
	now := nowString()
	s.mu.Lock()
	old := s.objects[path]
	if old == nil && az != nil && !az.allows(ri.withVerb("create")) {
		// k8s.io/apiserver v0.37.2 pkg/endpoints/handlers/patch.go:214-243:
		// a patch that creates its object is authorized for create too.
		s.mu.Unlock()
		writeForbidden(w, ri.withVerb("create"), caller.email)
		return
	}
	if rv != "" && old != nil && rv != str(metadataOf(old.obj), "resourceVersion") {
		s.mu.Unlock()
		conflict(w, k, ri.name)
		return
	}
	next, err := s.appliedObject(old, applied, k, manager, now)
	if err != nil {
		s.mu.Unlock()
		writeStatus(w, http.StatusInternalServerError, "", "failed to decode managed fields: "+err.Error(), nil)
		return
	}
	s.settle(next, k)
	code := http.StatusOK
	switch {
	case old == nil:
		code = http.StatusCreated
		metadataOf(next)["resourceVersion"] = s.nextRV()
		s.objects[path] = &stored{kind: k, namespace: wantNS, name: ri.name, obj: next}
	case reflect.DeepEqual(old.obj, next):
	default:
		metadataOf(next)["resourceVersion"] = s.nextRV()
		old.obj = next
	}
	body := answerBody(next, partial)
	s.mu.Unlock()
	writeRaw(w, code, "application/json", body)
}

// appliedObject is what an apply of body by manager makes of old (nil when
// absent). A no-op apply comes back equal to old.obj. It is called with mu
// held.
func (s *Server) appliedObject(old *stored, body map[string]any, k kube.Kind, manager, now string) (map[string]any, error) {
	next := cloneObject(body)
	delete(next, "status")
	md := metadataOf(next)
	for _, key := range serverSetMetadata {
		delete(md, key)
	}
	var es []mfEntry
	if old == nil {
		md["uid"] = newUID()
		md["creationTimestamp"] = now
		if generationKinds[k.Kind] {
			md["generation"] = json.Number("1")
		}
		if s.opts.settled && k.Kind == "Job" {
			defaultJobSelector(next)
		}
	} else {
		omd := metadataOf(old.obj)
		for _, key := range []string{"uid", "creationTimestamp", "resourceVersion"} {
			if v, ok := omd[key]; ok {
				md[key] = v
			}
		}
		if st, ok := old.obj["status"]; ok {
			next["status"] = st
		}
		if s.opts.settled && k.Kind == "Job" {
			keepJobSelector(next, old.obj)
		}
		if generationKinds[k.Kind] {
			g, _ := strconv.ParseInt(fmt.Sprint(omd["generation"]), 10, 64)
			if !reflect.DeepEqual(old.obj["spec"], next["spec"]) {
				g++
			}
			if g > 0 {
				md["generation"] = json.Number(strconv.FormatInt(g, 10))
			}
		}
		var err error
		if es, err = entriesOf(omd); err != nil {
			return nil, err
		}
	}

	entry := mfEntry{Manager: manager, Operation: operationApply, APIVersion: k.APIVersion, Time: now, FieldsType: fieldsTypeV1, FieldsV1: json.RawMessage("{}")}
	mine := slices.IndexFunc(es, func(e mfEntry) bool {
		return e.Manager == manager && e.Operation == operationApply && e.Subresource == ""
	})
	withEntry := func(t string) {
		out := slices.Clone(es)
		e := entry
		e.Time = t
		if mine >= 0 {
			out[mine] = e
		} else {
			out = append(out, e)
		}
		sortEntries(out)
		setEntries(md, out)
	}
	if mine >= 0 {
		// An unchanged object keeps its entry's time, as a no-op apply does.
		withEntry(es[mine].Time)
		if reflect.DeepEqual(old.obj, next) {
			return cloneObject(old.obj), nil
		}
	}
	withEntry(now)
	return cloneObject(next), nil
}

// The settled values WithSettledWorkloads writes.
const (
	// settledIngressIP is the address a LoadBalancer Service is given: from
	// TEST-NET-3 (RFC 5737), so it can never reach anything.
	settledIngressIP = "203.0.113.10"

	// The labels the API server's Job defaulting gives a Job created with no
	// selector, and its template [unverified; design A30-10].
	jobControllerUID = "batch.kubernetes.io/controller-uid"
	jobName          = "batch.kubernetes.io/job-name"
	legacyJobUID     = "controller-uid"
	legacyJobName    = "job-name"
)

// settle is WithSettledWorkloads' controller, run on an object a write is
// about to store (its comment has the rules); without the option it does
// nothing. It is called with mu held, on the write's own copy.
func (s *Server) settle(obj map[string]any, k kube.Kind) {
	if !s.opts.settled {
		return
	}
	switch k.Kind {
	case "Deployment", "StatefulSet":
		spec, _ := obj["spec"].(map[string]any)
		replicas := json.Number("1")
		if v, ok := spec["replicas"]; ok && v != nil {
			replicas = json.Number(fmt.Sprint(v))
		}
		st := childMap(obj, "status")
		if g, ok := metadataOf(obj)["generation"]; ok {
			st["observedGeneration"] = g
		}
		for _, f := range []string{"replicas", "updatedReplicas", "readyReplicas", "availableReplicas"} {
			st[f] = replicas
		}
	case "Service":
		spec, _ := obj["spec"].(map[string]any)
		if str(spec, "type") != "LoadBalancer" {
			return
		}
		lb := childMap(childMap(obj, "status"), "loadBalancer")
		if ingress, _ := lb["ingress"].([]any); len(ingress) > 0 {
			return
		}
		lb["ingress"] = []any{map[string]any{"ip": settledIngressIP}}
	}
}

// defaultJobSelector is the API server's defaulting of a Job created with no
// spec.selector, under WithSettledWorkloads: a selector on its uid, and the
// template labels it selects.
func defaultJobSelector(job map[string]any) {
	spec := childMap(job, "spec")
	if sel, ok := spec["selector"]; ok && sel != nil {
		return
	}
	md := metadataOf(job)
	uid, name := str(md, "uid"), str(md, "name")
	spec["selector"] = map[string]any{"matchLabels": map[string]any{jobControllerUID: uid}}
	labels := childMap(childMap(childMap(spec, "template"), "metadata"), "labels")
	labels[jobControllerUID], labels[jobName] = uid, name
	labels[legacyJobUID], labels[legacyJobName] = uid, name
}

// keepJobSelector keeps, in an apply's Job, the stored Job's spec.selector
// and the stored template labels the body omits, under WithSettledWorkloads:
// the applier does not own them, and a real server keeps them.
func keepJobSelector(job, stored map[string]any) {
	ospec, _ := stored["spec"].(map[string]any)
	sel, ok := ospec["selector"].(map[string]any)
	if !ok {
		return
	}
	spec := childMap(job, "spec")
	spec["selector"] = cloneObject(sel)
	otmpl, _ := ospec["template"].(map[string]any)
	otmd, _ := otmpl["metadata"].(map[string]any)
	olabels, _ := otmd["labels"].(map[string]any)
	if len(olabels) == 0 {
		return
	}
	labels := childMap(childMap(childMap(spec, "template"), "metadata"), "labels")
	for key, v := range olabels {
		if _, ok := labels[key]; !ok {
			labels[key] = v
		}
	}
}

// childMap is m[key] as an object, made empty when absent or not an object.
func childMap(m map[string]any, key string) map[string]any {
	c, ok := m[key].(map[string]any)
	if !ok {
		c = map[string]any{}
		m[key] = c
	}
	return c
}

// writeBody reads a POST's or PUT's JSON body for kind k in the URL's
// namespace: its apiVersion and kind, when present, must be k's; a namespace
// left out is the URL's, and one given must be it.
//
// Its keys are read exactly, as the API server reads them. A top-level key
// that is not a ConfigMap's field, or a metadata key that is not ObjectMeta's,
// is refused under fieldValidation=Strict with 400, as the API server refuses
// a create's strict decoding error (k8s.io/apiserver v0.37.2
// pkg/endpoints/handlers/create.go, transformDecodeError; that it answers 400
// is from memory, rest.go was not read), and dropped otherwise.
func writeBody(w http.ResponseWriter, req Request, ri requestInfo, k kube.Kind) (map[string]any, bool) {
	m, err := decodeJSONObject(req.Body)
	if err != nil {
		badRequest(w, "the body is not one JSON object")
		return nil, false
	}
	q, _ := url.ParseQuery(req.RawQuery)
	strict := q.Get("fieldValidation") == "Strict"
	md, _ := m["metadata"].(map[string]any)
	for _, level := range []struct {
		obj    map[string]any
		prefix string
		known  []string
	}{{m, "", configMapFields}, {md, "metadata.", objectMetaFields}} {
		if f := unknownField(keysOf(level.obj), level.prefix, level.known); f != "" {
			if strict {
				badRequest(w, "%s in version %q cannot be handled as a %s: %v", k.Kind, k.APIVersion, k.Kind, strictDecodingError(f))
				return nil, false
			}
			for _, key := range keysOf(level.obj) {
				if !slices.Contains(level.known, key) {
					delete(level.obj, key)
				}
			}
		}
	}
	if av, kd := str(m, "apiVersion"), str(m, "kind"); (av != "" && av != k.APIVersion) || (kd != "" && kd != k.Kind) {
		badRequest(w, "the body is %s %s, and the URL addresses %s %s", av, kd, k.APIVersion, k.Kind)
		return nil, false
	}
	m["apiVersion"], m["kind"] = k.APIVersion, k.Kind
	md = metadataOf(m)
	switch ns := str(md, "namespace"); {
	case ns == "":
		md["namespace"] = ri.namespace
	case ns != ri.namespace:
		badRequest(w, "the namespace of the provided object does not match the namespace sent on the request")
		return nil, false
	}
	return m, true
}

// createConfigMap is POST …/configmaps: 201 with the object, or 409
// AlreadyExists. POST and PUT record no managed-fields entry. Only ConfigMaps
// are written this way, so WithSettledWorkloads finds nothing to settle in
// either.
func (s *Server) createConfigMap(w http.ResponseWriter, req Request, ri requestInfo, k kube.Kind) {
	m, ok := writeBody(w, req, ri, k)
	if !ok {
		return
	}
	md := metadataOf(m)
	name := str(md, "name")
	if name == "" {
		invalid(w, k, name, "metadata.name: Required value: name or generateName is required")
		return
	}
	for _, key := range serverSetMetadata {
		delete(md, key)
	}
	path := k.Path(ri.namespace, name)
	s.mu.Lock()
	if s.objects[path] != nil {
		s.mu.Unlock()
		writeStatus(w, http.StatusConflict, "AlreadyExists", fmt.Sprintf("%s %q already exists", qualifiedResource(k), name),
			&wireDetails{Name: name, Group: groupOf(k), Kind: k.Resource})
		return
	}
	md["uid"] = newUID()
	md["creationTimestamp"] = nowString()
	md["resourceVersion"] = s.nextRV()
	s.settle(m, k)
	s.objects[path] = &stored{kind: k, namespace: ri.namespace, name: name, obj: m}
	body := mustMarshal(m)
	s.mu.Unlock()
	writeRaw(w, http.StatusCreated, "application/json", body)
}

// replaceConfigMap is PUT …/configmaps/<n>. It requires the stored
// resourceVersion in the body: a stale one, or none, answers 409 Conflict, and
// an absent object 404. It answers 200 with the object.
func (s *Server) replaceConfigMap(w http.ResponseWriter, req Request, ri requestInfo, k kube.Kind) {
	m, ok := writeBody(w, req, ri, k)
	if !ok {
		return
	}
	md := metadataOf(m)
	if name := str(md, "name"); name != ri.name {
		badRequest(w, "the name of the object (%s) does not match the name on the URL (%s)", name, ri.name)
		return
	}
	rv := str(md, "resourceVersion")
	for _, key := range serverSetMetadata {
		delete(md, key)
	}
	path := k.Path(ri.namespace, ri.name)
	s.mu.Lock()
	old := s.objects[path]
	if old == nil {
		s.mu.Unlock()
		notFound(w, k, ri.name)
		return
	}
	omd := metadataOf(old.obj)
	if rv != str(omd, "resourceVersion") {
		s.mu.Unlock()
		conflict(w, k, ri.name)
		return
	}
	for _, key := range []string{"uid", "creationTimestamp", "resourceVersion", "managedFields"} {
		if v, ok := omd[key]; ok {
			md[key] = v
		}
	}
	s.settle(m, k)
	if !reflect.DeepEqual(old.obj, m) {
		md["resourceVersion"] = s.nextRV()
		old.obj = m
	}
	body := mustMarshal(old.obj)
	s.mu.Unlock()
	writeRaw(w, http.StatusOK, "application/json", body)
}

// deleteSecret is DELETE …/secrets/<n> with a DeleteOptions body. Its
// preconditions.uid must be the stored uid, and a body without one is not
// (409 Conflict); a preconditions.resourceVersion, when given, must be the
// stored one too. An absent Secret answers 404; a deleted one 200 with a
// Success Status.
//
// The body's keys are read exactly: a "Preconditions" or a "UID" is no
// field, so the precondition is missing, as the API server, which drops a
// key it does not know from a DELETE body, would delete without it.
func (s *Server) deleteSecret(w http.ResponseWriter, req Request, ri requestInfo, k kube.Kind) {
	uid, rv := "", ""
	if len(bytes.TrimSpace(req.Body)) > 0 {
		var err error
		uid, rv, err = readPreconditions(req.Body)
		if err != nil {
			badRequest(w, "the body is not DeleteOptions")
			return
		}
	}
	path := k.Path(ri.namespace, ri.name)
	s.mu.Lock()
	old := s.objects[path]
	if old == nil {
		s.mu.Unlock()
		notFound(w, k, ri.name)
		return
	}
	omd := metadataOf(old.obj)
	storedUID := str(omd, "uid")
	if uid != storedUID {
		s.mu.Unlock()
		writeStatus(w, http.StatusConflict, "", fmt.Sprintf("Precondition failed: UID in precondition: %s, UID in object meta: %s", uid, storedUID),
			&wireDetails{Name: ri.name, Kind: k.Resource})
		return
	}
	if rv != "" && rv != str(omd, "resourceVersion") {
		s.mu.Unlock()
		conflict(w, k, ri.name)
		return
	}
	delete(s.objects, path)
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, wireStatus{Kind: "Status", APIVersion: "v1", Status: "Success",
		Details: &wireDetails{Name: ri.name, Kind: k.Resource, UID: storedUID}})
}

// readPreconditions reads a DeleteOptions body's preconditions.uid and
// preconditions.resourceVersion, by their exact keys; each is "" when absent.
func readPreconditions(body []byte) (uid, rv string, err error) {
	opts, err := exactObject(body)
	if err != nil {
		return "", "", err
	}
	raw, ok := opts["preconditions"]
	if !ok || isNull(raw) {
		return "", "", nil
	}
	p, err := exactObject(raw)
	if err != nil {
		return "", "", err
	}
	if uid, err = stringValue(p["uid"]); err != nil {
		return "", "", err
	}
	if rv, err = stringValue(p["resourceVersion"]); err != nil {
		return "", "", err
	}
	return uid, rv, nil
}

// selfReview is POST /apis/authorization.k8s.io/v1/selfsubjectaccessreviews.
// It answers 201 with the review, its spec as sent, and status.allowed from
// WithAccess for the caller's id; false without it.
//
// The review's keys are read exactly, as the API server reads them: a key in
// another case is no field, and a review whose spec or resourceAttributes is
// spelt so has none.
func (s *Server) selfReview(w http.ResponseWriter, req Request, caller tokenInfo) {
	notReview := func() { badRequest(w, "the body is not a SelfSubjectAccessReview") }
	review, err := exactObject(req.Body)
	if err != nil {
		notReview()
		return
	}
	specRaw, ok := review["spec"]
	if !ok || isNull(specRaw) {
		notReview()
		return
	}
	spec, err := exactObject(specRaw)
	if err != nil {
		notReview()
		return
	}
	raRaw, ok := spec["resourceAttributes"]
	if !ok || isNull(raRaw) {
		writeStatus(w, http.StatusUnprocessableEntity, "", "SelfSubjectAccessReview is invalid: spec.resourceAttributes: kubetest answers resource reviews only", nil)
		return
	}
	ra, err := exactObject(raRaw)
	if err != nil {
		notReview()
		return
	}
	var a kube.ResourceAttributes
	for _, field := range []struct {
		name string
		dst  *string
	}{
		{"namespace", &a.Namespace}, {"verb", &a.Verb}, {"group", &a.Group},
		{"resource", &a.Resource}, {"subresource", &a.Subresource}, {"name", &a.Name},
	} {
		if *field.dst, err = stringValue(ra[field.name]); err != nil {
			notReview()
			return
		}
	}
	allowed := false
	if f := s.opts.access; f != nil {
		allowed = f(caller.id, a)
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"kind":       "SelfSubjectAccessReview",
		"apiVersion": "authorization.k8s.io/v1",
		"metadata":   map[string]any{},
		"spec":       specRaw,
		"status":     map[string]any{"allowed": allowed},
	})
}
