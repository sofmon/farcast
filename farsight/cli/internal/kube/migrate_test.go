package kube

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	tkube "github.com/sofmon/farcast/technocore/kube"
)

// The fields a client-side apply leaves: the annotation and the spec it
// applied, the annotations map itself a member as a real server writes it.
// ownsAnn holds the annotation's path; ownsAnnRemoved is it after
// RemoveField, the annotations map left as a member leaf; ownsAnnNot never
// held it.
const (
	ownsAnn        = `{"f:metadata":{"f:annotations":{".":{},"f:kubectl.kubernetes.io/last-applied-configuration":{}},"f:labels":{".":{},"f:app":{}}},"f:spec":{"f:replicas":{}}}`
	ownsAnnRemoved = `{"f:metadata":{"f:annotations":{},"f:labels":{".":{},"f:app":{}}},"f:spec":{"f:replicas":{}}}`
	ownsAnnNot     = `{"f:metadata":{"f:labels":{".":{},"f:app":{}}},"f:spec":{"f:replicas":{}}}`
)

func entry(manager, operation, apiVersion, fields string) ManagedFieldsEntry {
	e := ManagedFieldsEntry{Manager: manager, Operation: operation, APIVersion: apiVersion, Time: "2026-11-01T10:00:00Z", FieldsType: "FieldsV1"}
	if fields != "" {
		e.FieldsV1 = json.RawMessage(fields)
	}
	return e
}

func cloneEntries(es []ManagedFieldsEntry) []ManagedFieldsEntry {
	out := make([]ManagedFieldsEntry, len(es))
	for i, e := range es {
		out[i] = e
		out[i].FieldsV1 = slices.Clone(e.FieldsV1)
	}
	return out
}

// TestClientSideManagersFindsTheAnnotationsOwner: every Update entry that owns
// the last-applied annotation's path is selected, whatever its name, as
// kubectl's own migration selects them; kubectl-client-side-apply is selected
// by name; no Apply entry and no entry that does not own the path is.
func TestClientSideManagersFindsTheAnnotationsOwner(t *testing.T) {
	entries := []ManagedFieldsEntry{
		entry("kubectl-edit", "Update", "apps/v1", ownsAnn),
		entry("kubectl-client-side-apply", "Update", "apps/v1", ownsAnnNot),
		entry("farcast", "Apply", "apps/v1", ownsAnn),
		entry("technocore", "Update", "apps/v1", `{"f:spec":{"f:template":{"f:spec":{}}}}`),
		entry("kubectl-label", "Update", "apps/v1", `{"f:metadata":{"f:annotations":{"f:other":{}}}}`),
		entry("kubectl-annotate", "Update", "apps/v1", `{"f:metadata":{"f:annotations":{".":{}}}}`),
		{Manager: "kubectl-scale", Operation: "Update", APIVersion: "autoscaling/v1", Subresource: "scale", FieldsType: "FieldsV1", FieldsV1: json.RawMessage(`{"f:spec":{"f:replicas":{}}}`)},
		{Manager: "kube-controller-manager", Operation: "Update", APIVersion: "apps/v1", Subresource: "status"},
		entry("kubectl-edit", "Update", "apps/v1beta1", ownsAnn),
	}
	got, err := ClientSideManagers(entries)
	if err != nil {
		t.Fatalf("ClientSideManagers: %v", err)
	}
	if want := []string{"kubectl-client-side-apply", "kubectl-edit"}; !slices.Equal(got, want) {
		t.Errorf("ClientSideManagers = %q, want %q", got, want)
	}

	// kubectl-client-side-apply in an Apply entry is not a client-side manager.
	got, err = ClientSideManagers([]ManagedFieldsEntry{entry("kubectl-client-side-apply", "Apply", "v1", ownsAnn)})
	if err != nil || len(got) != 0 {
		t.Errorf("an Apply entry named kubectl-client-side-apply: %q, %v", got, err)
	}
	// An Update entry whose fields cannot be read may own the annotation: refused.
	if got, err := ClientSideManagers([]ManagedFieldsEntry{entry("kubectl-edit", "Update", "v1", `{"f:metadata":[]}`)}); err == nil {
		t.Errorf("an unreadable fieldsV1 gave %q and no error", got)
	}
	if got, err := ClientSideManagers([]ManagedFieldsEntry{{Manager: "x", Operation: "Update", FieldsType: "FieldsV2", FieldsV1: json.RawMessage(`{}`)}}); err == nil {
		t.Errorf("an unknown fieldsType gave %q and no error", got)
	}
}

// TestClientSideManagersIgnoresSubresourceEntries (design A30-7): a
// kubectl-client-side-apply Update entry on /scale or /status is not selected
// by its name, because the rewrite converts and removes only the main
// resource's (isCSAEntry); selected, it would never be converted and would
// refuse the end state on every run. Judged by its fields, as any other
// manager's entry is, it owns no annotation and is not selected either.
func TestClientSideManagersIgnoresSubresourceEntries(t *testing.T) {
	scale := ManagedFieldsEntry{Manager: "kubectl-client-side-apply", Operation: "Update", APIVersion: "autoscaling/v1", Subresource: "scale",
		FieldsType: "FieldsV1", FieldsV1: json.RawMessage(`{"f:spec":{"f:replicas":{}}}`)}
	status := ManagedFieldsEntry{Manager: "kubectl-client-side-apply", Operation: "Update", APIVersion: "apps/v1", Subresource: "status"}
	for _, row := range []struct {
		name    string
		entries []ManagedFieldsEntry
		want    []string
	}{
		{"a scale entry alone", []ManagedFieldsEntry{scale}, nil},
		{"a status entry with no fields", []ManagedFieldsEntry{status}, nil},
		{"beside farcast's own Apply", []ManagedFieldsEntry{entry("farcast", "Apply", "apps/v1", ownsAnnNot), scale, status}, nil},
		{"beside the main resource's entry, which is still selected",
			[]ManagedFieldsEntry{scale, entry("kubectl-client-side-apply", "Update", "apps/v1", ownsAnnNot), status}, []string{"kubectl-client-side-apply"}},
	} {
		got, err := ClientSideManagers(row.entries)
		if err != nil {
			t.Errorf("%s: ClientSideManagers: %v", row.name, err)
			continue
		}
		if !slices.Equal(got, row.want) {
			t.Errorf("%s: ClientSideManagers = %q, want %q", row.name, got, row.want)
		}
	}

	// The end state of an object that keeps only the scale entry: nothing
	// is left to convert, so it passes.
	o := migratable()
	o.Metadata.Annotations = map[string]string{"other": "x"}
	o.Metadata.ManagedFields = []ManagedFieldsEntry{entry("farcast", "Apply", "apps/v1", ownsAnnRemoved), scale}
	if err := MigratedEndState(o, []string{"kubectl-client-side-apply"}, "farcast", false); err != nil {
		t.Errorf("a migrated object keeping kubectl-client-side-apply's scale entry is refused: %v", err)
	}
}

// TestClientSideTraceIsNotFarcastsOwnApply (design A30-6): an object carries
// a trace of kubectl's client-side apply when it has the last-applied
// annotation or a client-side manager, or managed fields ClientSideManagers
// cannot read; farcast's own Apply entry, which every server-side apply's
// answer carries, is no trace, and neither is a subresource's entry.
func TestClientSideTraceIsNotFarcastsOwnApply(t *testing.T) {
	meta := func(annotations map[string]string, entries ...ManagedFieldsEntry) ObjectMeta {
		var md ObjectMeta
		md.Name, md.Namespace = "api", "web"
		md.Annotations = annotations
		md.ManagedFields = entries
		return md
	}
	own := entry("farcast", "Apply", "apps/v1", ownsAnnNot)
	annotated := map[string]string{lastAppliedAnnotation: `{"marker":"MARKER-VALUE"}`}
	for _, row := range []struct {
		name string
		md   ObjectMeta
		want bool
	}{
		{"the annotation alone", meta(annotated), true},
		{"the annotation beside farcast's own Apply", meta(annotated, own), true},
		// The key is the trace, whatever its value (A30-6): cluster's
		// ListMeta, GetMeta and PatchManagedFields hand it over blanked.
		{"the annotation's key with an empty value", meta(map[string]string{lastAppliedAnnotation: ""}), true},
		{"kubectl-client-side-apply/Update", meta(nil, entry("kubectl-client-side-apply", "Update", "apps/v1", ownsAnnNot)), true},
		{"another Update manager owning the annotation's path", meta(nil, own, entry("kubectl-edit", "Update", "apps/v1", ownsAnn)), true},
		{"an Update entry whose fieldsType is not FieldsV1",
			meta(nil, own, ManagedFieldsEntry{Manager: "kubectl-edit", Operation: "Update", APIVersion: "apps/v1", FieldsType: "FieldsV2", FieldsV1: json.RawMessage(`{}`)}), true},
		{"an Update entry whose fields do not read", meta(nil, entry("kubectl-edit", "Update", "apps/v1", `{"f:metadata":[]}`)), true},
		{"farcast/Apply alone", meta(nil, own), false},
		{"farcast/Apply owning the annotation's path, as an Apply entry", meta(nil, entry("farcast", "Apply", "apps/v1", ownsAnn)), false},
		{"kubectl-client-side-apply/Update with subresource scale",
			meta(nil, own, ManagedFieldsEntry{Manager: "kubectl-client-side-apply", Operation: "Update", APIVersion: "autoscaling/v1", Subresource: "scale",
				FieldsType: "FieldsV1", FieldsV1: json.RawMessage(`{"f:spec":{"f:replicas":{}}}`)}), false},
		{"the kernel's Update entry", meta(nil, own, entry("technocore", "Update", "apps/v1", `{"f:spec":{"f:template":{}}}`)), false},
		{"nothing at all", meta(nil), false},
	} {
		if got := ClientSideTrace(row.md); got != row.want {
			t.Errorf("%s: ClientSideTrace = %v, want %v", row.name, got, row.want)
		}
	}
}

// ADR 0023 M2.6 (A23-46, A28-7): an apply of the object by farcast is
// farcast's own Apply or kubectl's client-side apply Update, each on the
// object itself. The same managers under the other operation, a subresource
// entry under either, and every other manager are not one: the kernel's
// writes among them, under whatever name the server gives them.
func TestIsLastApplyIsFarcastsOwnApplyOfTheObject(t *testing.T) {
	for _, row := range []struct {
		e    ManagedFieldsEntry
		want bool
	}{
		{entry("farcast", "Apply", "apps/v1", ""), true},
		{entry("kubectl-client-side-apply", "Update", "apps/v1", ""), true},
		{entry("farcast", "Update", "apps/v1", ""), false},
		{entry("kubectl-client-side-apply", "Apply", "apps/v1", ""), false},
		{ManagedFieldsEntry{Manager: "farcast", Operation: "Apply", APIVersion: "apps/v1", Subresource: "status"}, false},
		{ManagedFieldsEntry{Manager: "kubectl-client-side-apply", Operation: "Update", APIVersion: "autoscaling/v1", Subresource: "scale"}, false},
		{entry("kubectl", "Apply", "apps/v1", ""), false},
		{entry("Go-http-client", "Update", "apps/v1", ""), false},
		{entry("technocore", "Update", "apps/v1", ""), false},
		{ManagedFieldsEntry{}, false},
	} {
		if got := IsLastApply(row.e); got != row.want {
			t.Errorf("IsLastApply(%s, %s, subresource %q) = %v, want %v", row.e.Manager, row.e.Operation, row.e.Subresource, got, row.want)
		}
	}
}

// TestUpgradeManagedFields is the csaupgrade port of §6.3, step by step.
func TestUpgradeManagedFields(t *testing.T) {
	const csaV1beta1 = `{"f:spec":{"f:paused":{}}}`
	scale := ManagedFieldsEntry{Manager: "kubectl-scale", Operation: "Update", APIVersion: "autoscaling/v1", Time: "2026-11-02T10:00:00Z", FieldsType: "FieldsV1", Subresource: "scale", FieldsV1: json.RawMessage(`{"f:spec":{"f:replicas":{}}}`)}
	kernel := entry("technocore", "Update", "apps/v1", `{"f:spec":{"f:template":{"f:spec":{"f:containers":{}}}}}`)

	converted := entry("farcast", "Apply", "apps/v1", ownsAnnRemoved)
	cases := []struct {
		name    string
		entries []ManagedFieldsEntry
		csa     []string
		want    []ManagedFieldsEntry
	}{
		{
			name: "the client-side entry becomes farcast's, other apiVersions and other managers' entries kept or dropped as csaupgrade does",
			entries: []ManagedFieldsEntry{
				entry("kubectl-client-side-apply", "Update", "apps/v1", ownsAnn),
				scale,
				entry("kubectl-client-side-apply", "Update", "apps/v1beta1", csaV1beta1),
				kernel,
			},
			csa:  []string{"kubectl-client-side-apply"},
			want: []ManagedFieldsEntry{converted, scale, kernel},
		},
		{
			name: "an existing farcast Apply entry takes the union of the client-side fields at its apiVersion",
			entries: []ManagedFieldsEntry{
				entry("farcast", "Apply", "apps/v1", `{"f:spec":{"f:template":{}}}`),
				entry("kubectl-client-side-apply", "Update", "apps/v1", ownsAnn),
			},
			csa: []string{"kubectl-client-side-apply"},
			want: []ManagedFieldsEntry{
				entry("farcast", "Apply", "apps/v1", `{"f:metadata":{"f:annotations":{},"f:labels":{".":{},"f:app":{}}},"f:spec":{"f:replicas":{},"f:template":{}}}`),
			},
		},
		{
			name: "no union across apiVersions, and the other apiVersion's entry still goes",
			entries: []ManagedFieldsEntry{
				entry("farcast", "Apply", "apps/v1", `{"f:spec":{"f:template":{}}}`),
				entry("kubectl-client-side-apply", "Update", "apps/v1beta1", ownsAnn),
			},
			csa:  []string{"kubectl-client-side-apply"},
			want: []ManagedFieldsEntry{entry("farcast", "Apply", "apps/v1", `{"f:spec":{"f:template":{}}}`)},
		},
		{
			name: "two names, in sorted order: the first converts, the second unions in",
			entries: []ManagedFieldsEntry{
				entry("kubectl-edit", "Update", "apps/v1", `{"f:metadata":{"f:annotations":{"f:kubectl.kubernetes.io/last-applied-configuration":{}}},"f:spec":{"f:paused":{}}}`),
				entry("kubectl-client-side-apply", "Update", "apps/v1", ownsAnn),
			},
			csa: []string{"kubectl-edit", "kubectl-client-side-apply"},
			want: []ManagedFieldsEntry{
				entry("farcast", "Apply", "apps/v1", `{"f:metadata":{"f:annotations":{},"f:labels":{".":{},"f:app":{}}},"f:spec":{"f:paused":{},"f:replicas":{}}}`),
			},
		},
		{
			name:    "no client-side entry: nothing changes",
			entries: []ManagedFieldsEntry{entry("farcast", "Apply", "apps/v1", ownsAnnNot), kernel},
			csa:     []string{"kubectl-client-side-apply"},
			want:    []ManagedFieldsEntry{entry("farcast", "Apply", "apps/v1", ownsAnnNot), kernel},
		},
		{
			name:    "a client-side entry on a subresource is not the object's",
			entries: []ManagedFieldsEntry{{Manager: "kubectl-client-side-apply", Operation: "Update", APIVersion: "v1", Subresource: "status", FieldsType: "FieldsV1", FieldsV1: json.RawMessage(`{}`)}},
			csa:     []string{"kubectl-client-side-apply"},
			want:    []ManagedFieldsEntry{{Manager: "kubectl-client-side-apply", Operation: "Update", APIVersion: "v1", Subresource: "status", FieldsType: "FieldsV1", FieldsV1: json.RawMessage(`{}`)}},
		},
		{
			name:    "no entries",
			entries: nil,
			csa:     []string{"kubectl-client-side-apply"},
			want:    nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := cloneEntries(tc.entries)
			got, err := UpgradeManagedFields(tc.entries, tc.csa, "farcast")
			if err != nil {
				t.Fatalf("UpgradeManagedFields: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				g, _ := json.Marshal(got)
				w, _ := json.Marshal(tc.want)
				t.Errorf("got  %s\nwant %s", g, w)
			}
			if tc.entries != nil && !reflect.DeepEqual(tc.entries, before) {
				t.Error("UpgradeManagedFields modified the entries it was given")
			}
		})
	}
}

func migratable() Object {
	return Object{
		Kind: Kinds[5],
		Metadata: ObjectMeta{
			ObjectMeta: tkube.ObjectMeta{
				Name: "api", Namespace: "web", UID: "u-1", ResourceVersion: "4711",
				Annotations: map[string]string{lastAppliedAnnotation: `{"kind":"Deployment","marker":"MARKER-VALUE"}`, "other": "x"},
			},
			ManagedFields: []ManagedFieldsEntry{entry("kubectl-client-side-apply", "Update", "apps/v1", ownsAnn)},
		},
	}
}

// TestMigrationPatchCarriesTheResourceVersion: the patch replaces the managed
// fields, replaces the resourceVersion with the one the object was read at,
// and removes the annotation, in that order (§6.3).
func TestMigrationPatchCarriesTheResourceVersion(t *testing.T) {
	o := migratable()
	patch, err := MigrationPatch(o, []string{"kubectl-client-side-apply"}, "farcast")
	if err != nil {
		t.Fatalf("MigrationPatch: %v", err)
	}
	// The patch is read as the API server reads it, by exact keys, never into
	// a struct: encoding/json would match "Op" or "Manager" too, and the
	// server, which decodes case-sensitively, would not.
	var ops []map[string]json.RawMessage
	if err := json.Unmarshal(patch, &ops); err != nil {
		t.Fatalf("the patch is not a JSON array of operations: %v\n%s", err, patch)
	}
	if len(ops) != 3 {
		t.Fatalf("the patch has %d operations, want 3: %s", len(ops), patch)
	}
	wantOp := func(i int, op, path, value string) {
		t.Helper()
		want := map[string]string{"op": `"` + op + `"`, "path": `"` + path + `"`}
		if value != "" {
			want["value"] = value
		}
		got := map[string]string{}
		for k, v := range ops[i] {
			got[k] = string(v)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("operation %d = %v\nwant          %v", i+1, got, want)
		}
	}
	var mf []map[string]json.RawMessage
	if err := json.Unmarshal(ops[0]["value"], &mf); err != nil || len(mf) != 1 {
		t.Fatalf("the managed fields replaced = %s (%v)", ops[0]["value"], err)
	}
	wantEntry := map[string]string{
		"manager": `"farcast"`, "operation": `"Apply"`, "apiVersion": `"apps/v1"`,
		"time": `"2026-11-01T10:00:00Z"`, "fieldsType": `"FieldsV1"`, "fieldsV1": ownsAnnRemoved,
	}
	gotEntry := map[string]string{}
	for k, v := range mf[0] {
		gotEntry[k] = string(v)
	}
	if !reflect.DeepEqual(gotEntry, wantEntry) {
		t.Errorf("the entry sent, key by key = %v\nwant                         %v", gotEntry, wantEntry)
	}
	wantOp(0, "replace", "/metadata/managedFields", string(ops[0]["value"]))
	wantOp(1, "replace", "/metadata/resourceVersion", `"4711"`)
	wantOp(2, "remove", "/metadata/annotations/kubectl.kubernetes.io~1last-applied-configuration", "")
	if strings.Contains(string(patch), "MARKER-VALUE") {
		t.Error("the patch carries the annotation's value")
	}

	// Only the annotation left: the list is sent unchanged, with the guard.
	annOnly := migratable()
	annOnly.Metadata.ManagedFields = []ManagedFieldsEntry{entry("farcast", "Apply", "apps/v1", ownsAnnNot)}
	patch, err = MigrationPatch(annOnly, nil, "farcast")
	if err != nil || !strings.Contains(string(patch), `"path":"/metadata/resourceVersion","value":"4711"`) || !strings.Contains(string(patch), `"op":"remove"`) {
		t.Errorf("annotation only: %s, %v", patch, err)
	}

	// Already migrated: nothing to send.
	done := migratable()
	done.Metadata.Annotations = map[string]string{"other": "x"}
	done.Metadata.ManagedFields = []ManagedFieldsEntry{entry("farcast", "Apply", "apps/v1", ownsAnnNot)}
	if patch, err := MigrationPatch(done, []string{"kubectl-client-side-apply"}, "farcast"); patch != nil || err != nil {
		t.Errorf("a migrated object: %s, %v; want nil, nil", patch, err)
	}

	// No resourceVersion: no guard, so no patch.
	noRV := migratable()
	noRV.Metadata.ResourceVersion = ""
	if patch, err := MigrationPatch(noRV, []string{"kubectl-client-side-apply"}, "farcast"); err == nil {
		t.Errorf("an object read without a resourceVersion gave %s", patch)
	}

	// A rewrite that would leave an empty list is refused, not sent.
	empty := migratable()
	empty.Metadata.ManagedFields = nil
	if patch, err := MigrationPatch(empty, nil, "farcast"); err == nil {
		t.Errorf("an empty managed-fields list gave %s", patch)
	}
}

// TestMigratedEndStateRefusesALeftoverEntry: an object read back after its
// patch passes only in §6.3's end state, and the refusal names managers,
// operations and the annotation's key, never the annotation's value. csa is
// the set the patch was computed for: an entry of one of those managers left
// on the main resource is refused even when the read-back no longer shows it
// owning the annotation, as after the API server kept the live list and
// stripped the removed annotation's path from it.
func TestMigratedEndStateRefusesALeftoverEntry(t *testing.T) {
	migrated := func(entries ...ManagedFieldsEntry) Object {
		o := migratable()
		o.Metadata.Annotations = map[string]string{"other": "x"}
		o.Metadata.ManagedFields = entries
		return o
	}
	applied := entry("farcast", "Apply", "apps/v1", ownsAnnNot)
	kernel := entry("technocore", "Update", "apps/v1", `{"f:spec":{"f:template":{}}}`)
	csaOnly := []string{"kubectl-client-side-apply"}
	withEdit := []string{"kubectl-client-side-apply", "kubectl-edit"}

	if err := MigratedEndState(migrated(applied, kernel), withEdit, "farcast", false); err != nil {
		t.Errorf("a migrated object is refused: %v", err)
	}
	// A manager of csa may keep an entry on a subresource: only the main
	// resource's Update entries are the client-side ones.
	scale := ManagedFieldsEntry{Manager: "kubectl-edit", Operation: "Update", APIVersion: "autoscaling/v1", Subresource: "scale", FieldsType: "FieldsV1", FieldsV1: json.RawMessage(`{"f:spec":{"f:replicas":{}}}`)}
	if err := MigratedEndState(migrated(applied, scale), withEdit, "farcast", false); err != nil {
		t.Errorf("a subresource entry of a converted manager is refused: %v", err)
	}

	// hadApply is what each fixture implies of the object before its patch:
	// a farcast/Apply entry it already carried, when the live list was kept
	// with one in it; with a non-empty csa it does not change the rule.
	cases := []struct {
		name     string
		o        Object
		csa      []string
		hadApply bool
		want     string
	}{
		{"the live list kept, and the annotation", migratable(), csaOnly, slices.ContainsFunc(migratable().Metadata.ManagedFields, IsOwnApply),
			"kubectl-client-side-apply/Update still present; annotation kubectl.kubernetes.io/last-applied-configuration still present; farcast/Apply present 0 times, not once"},
		{"the client-side entry left", migrated(applied, entry("kubectl-client-side-apply", "Update", "apps/v1", ownsAnnNot)), csaOnly, true,
			"kubectl-client-side-apply/Update still present"},
		{"another owner of the annotation left", migrated(applied, entry("kubectl-edit", "Update", "apps/v1", ownsAnn)), csaOnly, false,
			"kubectl-edit/Update still present"},
		// The live list was kept with a farcast/Apply entry already in it (an
		// instance written again by kubectl after its migration, §6.6), and
		// the server stripped the annotation's path from kubectl-edit's entry
		// when it removed the annotation: only csa still names it.
		{"a converted owner left without the annotation's path", migrated(applied, entry("kubectl-edit", "Update", "apps/v1", ownsAnnNot)), withEdit, true,
			"kubectl-edit/Update still present"},
		{"a converted owner left, and kubectl-client-side-apply", migrated(applied,
			entry("kubectl-edit", "Update", "apps/v1", ownsAnnNot), entry("kubectl-client-side-apply", "Update", "apps/v1", ownsAnnNot)), withEdit, true,
			"kubectl-client-side-apply/Update still present; kubectl-edit/Update still present"},
		{"the annotation left", func() Object {
			o := migrated(applied)
			o.Metadata.Annotations = migratable().Metadata.Annotations
			return o
		}(), csaOnly, false,
			"annotation kubectl.kubernetes.io/last-applied-configuration still present"},
		{"no farcast entry", migrated(kernel), csaOnly, false, "farcast/Apply present 0 times, not once"},
		{"two farcast Apply entries", migrated(applied, entry("farcast", "Apply", "apps/v1beta1", `{}`)), csaOnly, false, "farcast/Apply present 2 times, not once"},
		{"a farcast Update entry", migrated(applied, entry("farcast", "Update", "apps/v1", `{"f:metadata":{}}`)), csaOnly, false, "farcast/Update present"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := MigratedEndState(tc.o, tc.csa, "farcast", tc.hadApply)
			if err == nil {
				t.Fatal("the end state passed")
			}
			if !errors.Is(err, ErrNotMigrated) {
				t.Errorf("error %v does not wrap ErrNotMigrated", err)
			}
			if err.Error() != tc.want {
				t.Errorf("error = %q\nwant    %q", err.Error(), tc.want)
			}
			if strings.Contains(err.Error(), "MARKER-VALUE") {
				t.Error("the error carries the annotation's value")
			}
		})
	}
}

// TestMigratedEndStateAllowsAnAnnotationOnlyObject (design A30-8): an
// operator's `kubectl apply --server-side` leaves kubectl/Apply and the
// last-applied annotation, and no client-side manager. Its migration only
// removes the annotation and adds no farcast/Apply, so that object ends
// migrated with none. An object that had farcast's Apply entry before the
// patch must still have exactly one, and one with client-side managers keeps
// today's rule.
func TestMigratedEndStateAllowsAnAnnotationOnlyObject(t *testing.T) {
	serverSide := entry("kubectl", "Apply", "apps/v1", ownsAnn) // kubectl's own csaupgrade renamed kubectl-client-side-apply
	before := migratable()
	before.Metadata.ManagedFields = []ManagedFieldsEntry{serverSide}
	csa, err := ClientSideManagers(before.Metadata.ManagedFields)
	if err != nil || len(csa) != 0 {
		t.Fatalf("ClientSideManagers of kubectl/Apply = %q, %v; want none", csa, err)
	}
	hadApply := slices.ContainsFunc(before.Metadata.ManagedFields, IsOwnApply)
	if hadApply {
		t.Fatal("kubectl/Apply read as farcast's own Apply")
	}
	patch, err := MigrationPatch(before, csa, "farcast")
	if err != nil || !strings.Contains(string(patch), `"op":"remove"`) {
		t.Fatalf("an annotation-only object's patch = %s, %v; want the annotation's removal", patch, err)
	}
	// As the API server leaves it: the annotation gone, and its path
	// stripped from kubectl/Apply's fields.
	after := func(entries ...ManagedFieldsEntry) Object {
		o := migratable()
		o.Metadata.Annotations = map[string]string{"other": "x"}
		o.Metadata.ManagedFields = entries
		return o
	}
	stripped := entry("kubectl", "Apply", "apps/v1", ownsAnnRemoved)
	own := entry("farcast", "Apply", "apps/v1", ownsAnnRemoved)

	if err := MigratedEndState(after(stripped), csa, "farcast", hadApply); err != nil {
		t.Errorf("csa empty, no farcast/Apply before or after, the annotation gone: %v", err)
	}
	if err := MigratedEndState(after(stripped, own), nil, "farcast", true); err != nil {
		t.Errorf("csa empty, farcast/Apply before and after: %v", err)
	}
	for _, row := range []struct {
		name     string
		o        Object
		csa      []string
		hadApply bool
		want     string
	}{
		{"csa empty, hadApply, and the entry gone after", after(stripped), nil, true, "farcast/Apply present 0 times, not once"},
		{"csa empty, no farcast/Apply before, and one after", after(stripped, own), nil, false, "farcast/Apply present 1 times, where the object had none"},
		{"csa empty, the annotation left", func() Object {
			o := after(stripped)
			o.Metadata.Annotations = migratable().Metadata.Annotations
			return o
		}(), nil, false, "annotation kubectl.kubernetes.io/last-applied-configuration still present"},
		{"csa non-empty, no farcast/Apply after", after(stripped), []string{"kubectl-client-side-apply"}, false, "farcast/Apply present 0 times, not once"},
		{"csa non-empty and hadApply, no farcast/Apply after", after(stripped), []string{"kubectl-client-side-apply"}, true, "farcast/Apply present 0 times, not once"},
	} {
		err := MigratedEndState(row.o, row.csa, "farcast", row.hadApply)
		if !errors.Is(err, ErrNotMigrated) || err.Error() != row.want {
			t.Errorf("%s: MigratedEndState = %v, want %q", row.name, err, row.want)
		}
		if err != nil && strings.Contains(err.Error(), "MARKER-VALUE") {
			t.Errorf("%s: the refusal carries the annotation's value", row.name)
		}
	}
	// csa non-empty: exactly one, today's rule, whatever hadApply says.
	for _, had := range []bool{false, true} {
		if err := MigratedEndState(after(stripped, own), []string{"kubectl-client-side-apply"}, "farcast", had); err != nil {
			t.Errorf("csa non-empty, hadApply %v, one farcast/Apply after: %v", had, err)
		}
	}
}

// TestMigrationRoundTrip: the patch's managed fields and annotation removal,
// applied by hand, give an object in the end state.
func TestMigrationRoundTrip(t *testing.T) {
	o := migratable()
	csa, err := ClientSideManagers(o.Metadata.ManagedFields)
	if err != nil || !slices.Equal(csa, []string{"kubectl-client-side-apply"}) {
		t.Fatalf("ClientSideManagers = %q, %v", csa, err)
	}
	up, err := UpgradeManagedFields(o.Metadata.ManagedFields, csa, "farcast")
	if err != nil {
		t.Fatal(err)
	}
	after := o
	after.Metadata.ManagedFields = up
	after.Metadata.Annotations = map[string]string{"other": "x"}
	if err := MigratedEndState(after, csa, "farcast", slices.ContainsFunc(o.Metadata.ManagedFields, IsOwnApply)); err != nil {
		t.Errorf("the rewritten object is not in the end state: %v", err)
	}
	if again, err := MigrationPatch(after, csa, "farcast"); again != nil || err != nil {
		t.Errorf("a second migration would send %s, %v", again, err)
	}
}
