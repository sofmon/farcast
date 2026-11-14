package kube

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
)

// Object is any kind's metadata, as the migration reads it. It declares
// metadata only, so a full answer, a Secret's included, is decoded into
// metadata and its values are discarded unread.
type Object struct {
	Kind     Kind       `json:"-"` // set from the request's Kind after decoding, never from the body
	Metadata ObjectMeta `json:"metadata"`
}

// The managed-fields vocabulary (meta/v1).
const (
	operationApply  = "Apply"
	operationUpdate = "Update"
	fieldsTypeV1    = "FieldsV1"

	// kubectlClientSideApply is the manager kubectl's client-side apply
	// records its Update entries under.
	kubectlClientSideApply = "kubectl-client-side-apply"
)

// lastAppliedFieldPath is the last-applied annotation's path in FieldsV1
// (kubectl v0.37.2, pkg/cmd/apply/apply.go, lastAppliedAnnotationFieldPath:
// metadata, annotations, the annotation's key).
var lastAppliedFieldPath = []string{"f:metadata", "f:annotations", "f:" + lastAppliedAnnotation}

// lastAppliedPatchPath is the annotation's JSON Pointer (RFC 6901: "/" in a
// key is written "~1").
const lastAppliedPatchPath = "/metadata/annotations/kubectl.kubernetes.io~1last-applied-configuration"

// ClientSideManagers names the managers a migration converts (§6.2): every Update
// entry that owns the last-applied annotation's path, plus kubectl-client-side-apply.
//
// The first half is kubectl v0.37.2's own selection (pkg/cmd/apply/apply.go,
// migrateToSSAIfNecessary: csaupgrade.FindFieldsOwners(…,
// ManagedFieldsOperationUpdate, lastAppliedAnnotationFieldPath)); the second
// adds kubectl-client-side-apply by name whenever it has an Update entry. The
// names are sorted and distinct. kubectl skips an entry whose fields do not
// decode; farcast refuses instead, because such an entry may own the
// annotation and would then be left behind.
func ClientSideManagers(entries []ManagedFieldsEntry) ([]string, error) {
	var names []string
	for i, e := range entries {
		if e.Operation != operationUpdate {
			continue
		}
		if e.Manager == kubectlClientSideApply {
			names = append(names, e.Manager)
			continue
		}
		if e.FieldsType != "" && e.FieldsType != fieldsTypeV1 {
			return nil, fmt.Errorf("kube: managed-fields entry %d (%s/%s) has fieldsType %q, which farcast does not read", i, e.Manager, e.Operation, e.FieldsType)
		}
		owns, err := ownsPath(e.FieldsV1, lastAppliedFieldPath)
		if err != nil {
			return nil, fmt.Errorf("managed-fields entry %d (%s/%s): %w", i, e.Manager, e.Operation, err)
		}
		if owns {
			names = append(names, e.Manager)
		}
	}
	slices.Sort(names)
	return slices.Compact(names), nil
}

// UpgradeManagedFields is a port of client-go v0.37.2's
// csaupgrade.UpgradeManagedFields (k8s.io/client-go/util/csaupgrade/upgrade.go,
// client-go v0.37.2) for the main resource (subresource ""), run once per name
// of csa in sorted order (§6.3). For each name:
//  1. copy the entries;
//  2. find ssa's Apply entry;
//  3. if there is none, convert the first of name's Update entries to it, its
//     fieldsV1, time and apiVersion kept; with neither, change nothing;
//  4. union into it the fields of name's Update entry at its apiVersion;
//  5. drop every one of name's Update entries, at any apiVersion.
//
// Then, farcast's addition, not in csaupgrade: ssa's Apply entry loses the
// last-applied annotation's path, so the first apply after the migration,
// which never writes the annotation, does not leave farcast owning it.
// The entries passed in are never modified.
func UpgradeManagedFields(entries []ManagedFieldsEntry, csa []string, ssa string) ([]ManagedFieldsEntry, error) {
	if entries == nil {
		return nil, nil
	}
	names := slices.Clone(csa)
	slices.Sort(names)
	names = slices.Compact(names)

	out := slices.Clone(entries)
	var err error
	for _, name := range names {
		if out, err = upgradeOne(out, name, ssa); err != nil {
			return nil, err
		}
	}
	if i := slices.IndexFunc(out, isSSAEntry(ssa)); i >= 0 && len(bytes.TrimSpace(out[i].FieldsV1)) > 0 {
		f, err := RemoveField(out[i].FieldsV1, lastAppliedFieldPath...)
		if err != nil {
			return nil, fmt.Errorf("the %s/%s entry: %w", ssa, operationApply, err)
		}
		out[i].FieldsV1 = f // out is this call's own copy
	}
	return out, nil
}

func isSSAEntry(ssa string) func(ManagedFieldsEntry) bool {
	return func(e ManagedFieldsEntry) bool {
		return e.Manager == ssa && e.Operation == operationApply && e.Subresource == ""
	}
}

func isCSAEntry(name string) func(ManagedFieldsEntry) bool {
	return func(e ManagedFieldsEntry) bool {
		return e.Manager == name && e.Operation == operationUpdate && e.Subresource == ""
	}
}

// upgradeOne is csaupgrade's upgradedManagedFields, with
// unionManagerIntoIndex and filter, for one client-side manager.
func upgradeOne(entries []ManagedFieldsEntry, name, ssa string) ([]ManagedFieldsEntry, error) {
	if entries == nil {
		return nil, nil
	}
	// 1. Copy the entries: the fields below are replaced, never edited in place.
	mf := slices.Clone(entries)

	// 2. Locate the SSA manager.
	target := slices.IndexFunc(mf, isSSAEntry(ssa))
	if target < 0 {
		// 3. Convert the first matching CSA entry. The API server sorts
		// managed fields by operation, then time ascending (apimachinery
		// v0.37.2, managedfields.go, sortEncodedManagedFields), so with
		// several this is the oldest, not csaupgrade's "most recent"; a
		// farcast object carries one.
		target = slices.IndexFunc(mf, isCSAEntry(name))
		if target < 0 {
			return mf, nil
		}
		mf[target].Operation = operationApply
		mf[target].Manager = ssa
	}

	// 4. Union the CSA entry of the SSA entry's apiVersion into it.
	csa := slices.IndexFunc(mf, func(e ManagedFieldsEntry) bool {
		return isCSAEntry(name)(e) && e.APIVersion == mf[target].APIVersion
	})
	if csa >= 0 {
		u, err := UnionFields(mf[target].FieldsV1, mf[csa].FieldsV1)
		if err != nil {
			return nil, fmt.Errorf("union of %s/%s into %s/%s: %w", name, operationUpdate, ssa, operationApply, err)
		}
		mf[target].FieldsV1 = u
	}

	// 5. Drop every remaining Update entry of the name, at any apiVersion.
	out := slices.DeleteFunc(mf, isCSAEntry(name))
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// jsonPatchOp is one RFC 6902 operation.
type jsonPatchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value,omitempty"`
}

// MigrationPatch returns the JSON patch (RFC 6902) that migrates o (§6.3): the
// rewritten managed fields, a replace of the resourceVersion it was read at,
// and, when o carries it, the removal of the last-applied annotation. It is
// nil when the object needs nothing: UpgradeManagedFields changes nothing and
// there is no annotation.
//
// The resourceVersion replace is csaupgrade's own guard, "so that etcd
// rejects with 409 conflict instead of apiserver with an invalid request"
// (client-go v0.37.2, upgrade.go). The patch never carries an empty
// managedFields list, which would not reset the field.
func MigrationPatch(o Object, csa []string, ssa string) ([]byte, error) {
	upgraded, err := UpgradeManagedFields(o.Metadata.ManagedFields, csa, ssa)
	if err != nil {
		return nil, err
	}
	_, annotated := o.Metadata.Annotations[lastAppliedAnnotation]
	if !annotated && reflect.DeepEqual(upgraded, o.Metadata.ManagedFields) {
		return nil, nil
	}
	id := fmt.Sprintf("%s %s/%s", o.Kind.Kind, o.Metadata.Namespace, o.Metadata.Name)
	if len(upgraded) == 0 {
		return nil, fmt.Errorf("kube: the rewrite of %s leaves no managed-fields entry, and an empty list does not reset the field", id)
	}
	if o.Metadata.ResourceVersion == "" {
		return nil, fmt.Errorf("kube: %s was read without a resourceVersion, which the rewrite is guarded on", id)
	}
	ops := []jsonPatchOp{
		{Op: "replace", Path: "/metadata/managedFields", Value: upgraded},
		{Op: "replace", Path: "/metadata/resourceVersion", Value: o.Metadata.ResourceVersion},
	}
	if annotated {
		ops = append(ops, jsonPatchOp{Op: "remove", Path: lastAppliedPatchPath})
	}
	return json.Marshal(ops)
}

// MigratedEndState checks an object read back after its patch against §6.3's end
// state, wrapping ErrNotMigrated with what is left. The text names only managers,
// operations and the annotation's key; it never carries an annotation's value,
// which on a Secret holds every key (§6.4).
//
// csa is the set the patch was computed for: ClientSideManagers of the object
// as it was read before the patch, the set the plan binds (§6.4). It is
// needed because the read-back alone cannot show it. When the API server keeps
// the live managed-fields list silently, it still applies the annotation's
// removal, and its field manager then strips the annotation's path from every
// entry (sigs.k8s.io/structured-merge-diff v6.3.1 merge/update.go,
// Updater.update, the removed set subtracted from each manager). An owner
// other than kubectl-client-side-apply then no longer reads as client-side,
// although it still holds its other client-side fields.
//
// The end state is: no Update entry, on the main resource, of any manager in
// csa or in ClientSideManagers of the object as read back; no annotation;
// exactly one ssa entry with operation Apply; and no ssa entry with operation
// Update. The error's whole text is what is left, such as
// "kubectl-client-side-apply/Update still present; annotation
// kubectl.kubernetes.io/last-applied-configuration still present".
func MigratedEndState(o Object, csa []string, ssa string) error {
	left, err := ClientSideManagers(o.Metadata.ManagedFields)
	if err != nil {
		return refuse(ErrNotMigrated, "its managed fields do not read")
	}
	for _, name := range csa {
		if slices.ContainsFunc(o.Metadata.ManagedFields, isCSAEntry(name)) {
			left = append(left, name)
		}
	}
	slices.Sort(left)
	left = slices.Compact(left)
	var faults []string
	for _, name := range left {
		faults = append(faults, name+"/"+operationUpdate+" still present")
	}
	if _, annotated := o.Metadata.Annotations[lastAppliedAnnotation]; annotated {
		faults = append(faults, "annotation "+lastAppliedAnnotation+" still present")
	}
	var applies, updates int
	for _, e := range o.Metadata.ManagedFields {
		if e.Manager != ssa {
			continue
		}
		switch e.Operation {
		case operationApply:
			applies++
		case operationUpdate:
			updates++
		}
	}
	if applies != 1 {
		faults = append(faults, fmt.Sprintf("%s/%s present %d times, not once", ssa, operationApply, applies))
	}
	if updates > 0 {
		faults = append(faults, ssa+"/"+operationUpdate+" present")
	}
	if len(faults) > 0 {
		return refuse(ErrNotMigrated, "%s", strings.Join(faults, "; "))
	}
	return nil
}

// ListObjects lists one kind's objects, metadata only (§6.2): GET
// k.ListPath(namespace), "" being every namespace, with the label selector,
// paged, asking for a PartialObjectMetadataList. A server that answers with
// full objects is decoded into Object, which declares metadata only, so a
// Secret's values are discarded unread. Each Object's Kind is k, never read
// from the answer.
func (c *Client) ListObjects(ctx context.Context, k Kind, namespace, selector string) ([]Object, error) {
	if f := kindFault(k); f != "" {
		return nil, notSent(f)
	}
	path, err := listPath(k, namespace)
	if err != nil {
		return nil, err
	}
	var q url.Values
	if selector != "" {
		q = url.Values{"labelSelector": {selector}}
	}
	items, err := listAll[Object](ctx, c, path, q, acceptPartialList)
	if err != nil {
		return nil, err
	}
	for i := range items {
		items[i].Kind = stampKind(k)
	}
	return items, nil
}

// GetObject reads one object's metadata, asking for a PartialObjectMetadata.
// Its Kind is k, never read from the answer, whose kind is
// PartialObjectMetadata or, from a server that sends the whole object, the
// object's own.
func (c *Client) GetObject(ctx context.Context, k Kind, namespace, name string) (Object, error) {
	if f := kindFault(k); f != "" {
		return Object{}, notSent(f)
	}
	path, err := objectPath(k, namespace, name)
	if err != nil {
		return Object{}, err
	}
	var o Object
	if err := c.decode(ctx, call{method: http.MethodGet, path: path, accept: acceptPartial, retry: true}, &o); err != nil {
		return Object{}, err
	}
	o.Kind = stampKind(k)
	return o, nil
}

// PatchJSON sends one JSON patch (RFC 6902), the migration's one write (§6.3):
// PATCH k.Path(namespace, name)?fieldManager=farcast&fieldValidation=Strict,
// Content-Type: application/json-patch+json. It is never retried on 429 or
// 503: the migration's own loop re-reads and retries (§6.4). The answer is
// decoded into Object, its Kind k.
func (c *Client) PatchJSON(ctx context.Context, k Kind, namespace, name string, patch []byte) (Object, error) {
	if f := kindFault(k); f != "" {
		return Object{}, notSent(f)
	}
	path, err := objectPath(k, namespace, name)
	if err != nil {
		return Object{}, err
	}
	var o Object
	err = c.decode(ctx, call{
		method:      http.MethodPatch,
		path:        path,
		query:       writeQuery(),
		contentType: mediaJSONPatch,
		body:        patch,
	}, &o)
	if err != nil {
		return Object{}, err
	}
	o.Kind = stampKind(k)
	return o, nil
}

// stampKind is k as an Object carries it, with its own copy of Names.
func stampKind(k Kind) Kind {
	k.Names = slices.Clone(k.Names)
	return k
}
