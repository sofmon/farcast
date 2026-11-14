package kubetest

import (
	"bytes"
	"encoding/json"
	"errors"
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
// It is used to read and write the store's own entries. An entry a client
// sends is never decoded into it with encoding/json, which would match its
// keys in any case: submittedEntries reads it key by key (exactObject).
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
	operationApply  = "Apply"
	operationUpdate = "Update"
	fieldsTypeV1    = "FieldsV1"
)

// The wire names of the fields of the bodies kubetest checks under strict
// field validation, case and all: meta/v1's ManagedFieldsEntry and ObjectMeta
// (k8s.io/apimachinery v0.37.2 pkg/apis/meta/v1/types.go), core/v1's
// ConfigMap (k8s.io/api v0.37.2 core/v1/types.go), and the JSON patch
// operation the API server decodes a patch into (k8s.io/apiserver v0.37.2
// pkg/endpoints/handlers/patch.go, jsonPatchOp). DeleteOptions and a
// SelfSubjectAccessReview are read by their exact keys too, but never under
// strict validation, so an unknown key in them is only dropped.
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
	managedFieldsEntryFields = []string{"manager", "operation", "apiVersion", "time", "fieldsType", "fieldsV1", "subresource"}
	jsonPatchOpFields        = []string{"op", "path", "from", "value"}
	configMapFields          = []string{"apiVersion", "kind", "metadata", "immutable", "data", "binaryData"}
	objectMetaFields         = []string{
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

// managerIdentifier is the key the API server decodes entries under: an
// entry's manager, operation, subresource and, for Update only, apiVersion.
// Two entries with one identifier collapse into the later one. A port of
// k8s.io/apimachinery v0.37.2 managedfields.go (BuildManagerIdentifier).
func managerIdentifier(e mfEntry) string {
	id := mfEntry{Manager: e.Manager, Operation: e.Operation, APIVersion: e.APIVersion, Subresource: e.Subresource}
	if e.Operation == operationApply {
		id.APIVersion = ""
	}
	return string(mustMarshal(id))
}

// decodable is the API server's check of a submitted managed-fields list: a
// port of k8s.io/apimachinery v0.37.2 managedfields.go (DecodeManagedFields).
// Every entry's operation is Apply or Update, its apiVersion is not empty,
// its fieldsType is FieldsV1, and its fieldsV1, when present, parses.
func decodable(es []mfEntry) bool {
	for _, e := range es {
		if e.Operation != operationApply && e.Operation != operationUpdate {
			return false
		}
		if e.APIVersion == "" || e.FieldsType != fieldsTypeV1 {
			return false
		}
		if f := bytes.TrimSpace(e.FieldsV1); len(f) > 0 && !bytes.Equal(f, []byte("null")) && !validFieldsV1(f) {
			return false
		}
	}
	return true
}

// validFieldsV1 reports whether f parses as a FieldsV1 trie: every node a
// JSON object; "." marking membership, as {}; every other key a path element,
// f:<name>, k:<JSON object>, v:<JSON value> or i:<integer>. The node rules are
// kube's (fields.go); the element rules are structured-merge-diff's
// fieldpath element encoding, from memory and not fetched.
func validFieldsV1(f []byte) bool {
	var node map[string]json.RawMessage
	if err := json.Unmarshal(f, &node); err != nil || node == nil {
		return false
	}
	for k, v := range node {
		if k == "." {
			var self map[string]json.RawMessage
			if err := json.Unmarshal(v, &self); err != nil || self == nil || len(self) != 0 {
				return false
			}
			continue
		}
		prefix, rest, ok := strings.Cut(k, ":")
		if !ok {
			return false
		}
		switch prefix {
		case "f":
		case "k":
			var key map[string]json.RawMessage
			if err := json.Unmarshal([]byte(rest), &key); err != nil || key == nil {
				return false
			}
		case "v":
			if !json.Valid([]byte(rest)) {
				return false
			}
		case "i":
			if _, err := strconv.Atoi(rest); err != nil {
				return false
			}
		default:
			return false
		}
		if !validFieldsV1(v) {
			return false
		}
	}
	return true
}

// errReset is a submitted managed-fields list the API server reads as a
// reset, which kubetest does not emulate.
var errReset = errors.New("a managedFields of [] or [{}] resets the field on a real API server, which kubetest does not emulate")

// submittedEntries reads the value of a JSON patch's managedFields replace as
// the API server's field manager reads it (k8s.io/apimachinery v0.37.2
// pkg/util/managedfields/internal/fieldmanager.go, decodeLiveOrNew): a list
// that does not decode, or decodes to nothing, keeps the live list, silently
// ("If the managed field is empty or we failed to decode it, let's try the
// live object"), and the patch's other operations still apply. keep reports
// that. An error is a value the object itself cannot hold: not a list, an
// entry that is not an entry, a time that is not a time, and, under strict
// field validation, a key that is not exactly one of an entry's fields.
//
// Each entry is read key by key, exactly: a key in another case is no field.
// Under strict validation it is refused, as the API server refuses the
// patched object (k8s.io/apiserver v0.37.2 pkg/endpoints/handlers/patch.go,
// applyPatchToCurrentObject: a strict decoding error is 422 Invalid); without
// it, it is dropped, and the entry is read without it.
func submittedEntries(value json.RawMessage, strict bool) (es []mfEntry, keep bool, err error) {
	if value == nil {
		return nil, false, errors.New("a replace needs a value")
	}
	if isNull(value) {
		return nil, true, nil
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(value, &raw); err != nil {
		return nil, false, errors.New("metadata.managedFields is not a list")
	}
	es = make([]mfEntry, len(raw))
	for i, r := range raw {
		m, err := exactObject(r)
		if err != nil {
			return nil, false, fmt.Errorf("metadata.managedFields[%d] is not a managed-fields entry", i)
		}
		if strict {
			if f := unknownField(keysOf(m), fmt.Sprintf("metadata.managedFields[%d].", i), managedFieldsEntryFields); f != "" {
				return nil, false, strictDecodingError(f)
			}
		}
		e := &es[i]
		for _, field := range []struct {
			name string
			dst  *string
		}{
			{"manager", &e.Manager}, {"operation", &e.Operation}, {"apiVersion", &e.APIVersion},
			{"time", &e.Time}, {"fieldsType", &e.FieldsType}, {"subresource", &e.Subresource},
		} {
			if *field.dst, err = stringValue(m[field.name]); err != nil {
				return nil, false, fmt.Errorf("metadata.managedFields[%d] is not a managed-fields entry", i)
			}
		}
		if f, ok := m["fieldsV1"]; ok {
			e.FieldsV1 = slices.Clone(f)
		}
		if es[i].Time != "" {
			if _, err := time.Parse(time.RFC3339, es[i].Time); err != nil {
				return nil, false, fmt.Errorf("metadata.managedFields[%d].time is not an RFC 3339 time", i)
			}
		}
	}
	// isResetManagedFields, in the same file.
	if len(es) == 0 || (len(es) == 1 && reflect.DeepEqual(es[0], mfEntry{})) {
		return nil, false, errReset
	}
	if !decodable(es) {
		return nil, true, nil
	}
	// Decoded into a map by identifier, then encoded sorted.
	byID := map[string]int{}
	var out []mfEntry
	for _, e := range es {
		id := managerIdentifier(e)
		if i, ok := byID[id]; ok {
			out[i] = e
			continue
		}
		byID[id] = len(out)
		out = append(out, e)
	}
	sortEntries(out)
	return out, false, nil
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
// namespace, and answers 201 on create and 200 on update with the object.
//
// The object becomes the body, minus status and the server-set metadata,
// which the server keeps (uid, creationTimestamp, status) or sets
// (resourceVersion, and generation on the kinds that carry one, moved when
// the spec changes). Its managed fields keep one entry per manager: this
// manager's Apply entry, {manager, operation: Apply, apiVersion, time,
// fieldsType: FieldsV1, fieldsV1: {}}, is replaced, and every other entry
// stays as it was. No field-level ownership is kept, so no conflict is ever
// found; Fail injects one. An apply that changes nothing writes nothing.
func (s *Server) apply(w http.ResponseWriter, r *http.Request, req Request, ri requestInfo, k kube.Kind, caller tokenInfo, az *authorizer) {
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
	next, err := s.appliedObject(old, applied, k, manager, now)
	if err != nil {
		s.mu.Unlock()
		writeStatus(w, http.StatusInternalServerError, "", "failed to decode managed fields: "+err.Error(), nil)
		return
	}
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
	body := mustMarshal(next)
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

// patchOp is one RFC 6902 operation, as readPatch reads it.
type patchOp struct {
	Op    string
	Path  string
	Value json.RawMessage // nil when the operation has no "value"
}

// readPatch reads a JSON patch's operations key by key, exactly. An
// operation whose "op" or "path" is spelt in another case has none, and is
// answered as an operation kubetest does not emulate (422), as the API
// server's patch library finds no operation there (evanphx/json-patch reads
// op["op"] and op["path"] from a map). Under strict field validation any key
// that is not op, path, from or value is refused with 422, as the API server
// refuses the strict errors of decoding the patch (k8s.io/apiserver v0.37.2
// pkg/endpoints/handlers/patch.go, applyJSPatch then
// applyPatchToCurrentObject).
func readPatch(body []byte, strict bool) (ops []patchOp, badRequest bool, err error) {
	var raw []json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, true, errors.New("the body is not a JSON patch (RFC 6902)")
	}
	ops = make([]patchOp, len(raw))
	for i, r := range raw {
		m, err := exactObject(r)
		if err != nil {
			return nil, true, errors.New("the body is not a JSON patch (RFC 6902)")
		}
		if strict {
			if f := unknownField(keysOf(m), "", jsonPatchOpFields); f != "" {
				return nil, false, fmt.Errorf("operation %d: json patch %w", i, strictDecodingError(f))
			}
		}
		op, err1 := stringValue(m["op"])
		path, err2 := stringValue(m["path"])
		if err1 != nil || err2 != nil {
			return nil, true, errors.New("the body is not a JSON patch (RFC 6902)")
		}
		ops[i] = patchOp{Op: op, Path: path, Value: m["value"]}
	}
	return ops, false, nil
}

const annotationsPointer = "/metadata/annotations/"

// jsonPatch is the migration's PATCH with Content-Type
// application/json-patch+json. It supports replace on /metadata/managedFields
// and /metadata/resourceVersion, and remove on one annotation; anything else
// answers 422. The operations apply in order and all or nothing. A
// resourceVersion that is not current answers 409 Conflict, as etcd's
// precondition does (csaupgrade's guard, client-go v0.37.2
// util/csaupgrade/upgrade.go). A managedFields list is read as
// submittedEntries reads it, so an undecodable one keeps the live list while
// the other operations still apply.
//
// The operations and the managed-fields entries are read with their keys
// exactly as sent (readPatch, submittedEntries); under fieldValidation=Strict
// a key that names no field is 422.
//
// When the patch removes an annotation, its path leaves the fieldsV1 of
// every entry the object keeps, the live list kept silently included, and an
// entry left with no field at all goes: the API server's field manager
// subtracts the fields an update removed from every manager, and drops a
// manager with none left (sigs.k8s.io/structured-merge-diff v6.3.1
// merge/update.go, Updater.update). When it removes the last annotation, the
// annotations map itself is gone from the object (ObjectMeta.Annotations is
// omitempty), so its own path, .metadata.annotations, is removed too
// (typed/compare.go, compare) and leaves every entry the same way. An entry
// with no fields before the patch is kept, because kubetest's own apply
// entries own none.
//
// The real API server also records the patch itself as an Update by its
// field manager; whether that leaves a farcast/Update entry is open (§6.3),
// and kubetest records none.
func (s *Server) jsonPatch(w http.ResponseWriter, r *http.Request, req Request, ri requestInfo, k kube.Kind) {
	q := r.URL.Query()
	if q.Has("dryRun") {
		badRequest(w, "kubetest does not emulate dryRun")
		return
	}
	strict := q.Get("fieldValidation") == "Strict"
	ops, bad, err := readPatch(req.Body, strict)
	switch {
	case err != nil && bad:
		badRequest(w, "%v", err)
		return
	case err != nil:
		invalid(w, k, ri.name, "%v", err)
		return
	}
	path := k.Path(ri.namespace, ri.name)
	s.mu.Lock()
	old := s.objects[path]
	if old == nil {
		s.mu.Unlock()
		notFound(w, k, ri.name)
		return
	}
	next := cloneObject(old.obj)
	md := metadataOf(next)
	var removed []string // the annotations this patch removes
	for i, op := range ops {
		switch {
		case op.Op == "replace" && op.Path == "/metadata/managedFields":
			es, keep, err := submittedEntries(op.Value, strict)
			if err != nil {
				s.mu.Unlock()
				invalid(w, k, ri.name, "operation %d: %v", i, err)
				return
			}
			if !keep {
				setEntries(md, es)
			}
		case op.Op == "replace" && op.Path == "/metadata/resourceVersion":
			var rv string
			if err := json.Unmarshal(op.Value, &rv); err != nil {
				s.mu.Unlock()
				invalid(w, k, ri.name, "operation %d: metadata.resourceVersion is not a string", i)
				return
			}
			if rv != str(md, "resourceVersion") {
				s.mu.Unlock()
				conflict(w, k, ri.name)
				return
			}
		case op.Op == "remove" && strings.HasPrefix(op.Path, annotationsPointer) &&
			!strings.Contains(strings.TrimPrefix(op.Path, annotationsPointer), "/"):
			key := strings.NewReplacer("~1", "/", "~0", "~").Replace(strings.TrimPrefix(op.Path, annotationsPointer))
			ann, _ := md["annotations"].(map[string]any)
			if _, ok := ann[key]; !ok {
				s.mu.Unlock()
				invalid(w, k, ri.name, "operation %d: jsonpatch remove operation does not apply: doc is missing path: %s", i, op.Path)
				return
			}
			delete(ann, key)
			if len(ann) == 0 {
				delete(md, "annotations")
			}
			removed = append(removed, key)
		default:
			s.mu.Unlock()
			invalid(w, k, ri.name, "operation %d (%s %s): kubetest emulates only replace of /metadata/managedFields and /metadata/resourceVersion, and remove of one annotation", i, op.Op, op.Path)
			return
		}
	}
	if len(removed) > 0 {
		_, kept := md["annotations"]
		if es, err := entriesOf(md); err == nil {
			if stripped, changed := stripAnnotations(es, removed, !kept); changed {
				setEntries(md, stripped)
			}
		}
	}
	if !reflect.DeepEqual(old.obj, next) {
		md["resourceVersion"] = s.nextRV()
		old.obj = next
	}
	body := mustMarshal(next)
	s.mu.Unlock()
	writeRaw(w, http.StatusOK, "application/json", body)
}

// stripAnnotations is the field manager's subtraction for removed
// annotations: each key's path, f:metadata.f:annotations.f:<key>, leaves every
// entry's fieldsV1 (kube.RemoveField's rule), and, when gone, so does the
// annotations map's own path (dropAnnotationsMember); an entry that held one
// and is left with no field goes. It reports whether any entry changed.
func stripAnnotations(es []mfEntry, keys []string, gone bool) ([]mfEntry, bool) {
	var out []mfEntry
	changed := false
	for _, e := range es {
		f := e.FieldsV1
		if len(bytes.TrimSpace(f)) == 0 || isNull(f) {
			out = append(out, e)
			continue
		}
		for _, key := range keys {
			next, err := kube.RemoveField(f, "f:metadata", "f:annotations", "f:"+key)
			if err != nil {
				break // fields kubetest cannot read are kept as they are
			}
			f = next
		}
		if gone {
			if next, err := dropAnnotationsMember(f); err == nil {
				f = next
			}
		}
		if bytes.Equal(f, e.FieldsV1) {
			out = append(out, e)
			continue
		}
		changed = true
		if bytes.Equal(f, []byte("{}")) {
			continue // the annotation was all it held
		}
		e.FieldsV1 = f
		out = append(out, e)
	}
	return out, changed
}

// dropAnnotationsMember takes the path .metadata.annotations itself out of a
// FieldsV1 set, as fieldpath.Set's Difference does: the "." member of
// f:metadata.f:annotations goes, the node goes once nothing is left under it,
// and f:metadata goes once it is empty. A key still under f:annotations, one
// the object no longer had, is kept, as it was not among the removed fields.
// A set that does not hold the path is returned as it was, byte for byte.
func dropAnnotationsMember(f json.RawMessage) (json.RawMessage, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(f, &root); err != nil {
		return nil, err
	}
	// No f:metadata object, or no f:annotations object in it: nothing to
	// take out.
	var md, ann map[string]json.RawMessage
	if json.Unmarshal(root["f:metadata"], &md) != nil || md == nil {
		return f, nil
	}
	if json.Unmarshal(md["f:annotations"], &ann) != nil || ann == nil {
		return f, nil
	}
	// {} alone is the member itself; otherwise "." marks it.
	if _, member := ann["."]; !member && len(ann) != 0 {
		return f, nil
	}
	delete(ann, ".")
	if len(ann) == 0 {
		delete(md, "f:annotations")
	} else {
		md["f:annotations"] = mustMarshal(ann)
	}
	if len(md) == 0 {
		delete(root, "f:metadata")
	} else {
		root["f:metadata"] = mustMarshal(md)
	}
	return mustMarshal(root), nil
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
// AlreadyExists. POST and PUT record no managed-fields entry.
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
