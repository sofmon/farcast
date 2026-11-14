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

	if err := MigratedEndState(migrated(applied, kernel), withEdit, "farcast"); err != nil {
		t.Errorf("a migrated object is refused: %v", err)
	}
	// A manager of csa may keep an entry on a subresource: only the main
	// resource's Update entries are the client-side ones.
	scale := ManagedFieldsEntry{Manager: "kubectl-edit", Operation: "Update", APIVersion: "autoscaling/v1", Subresource: "scale", FieldsType: "FieldsV1", FieldsV1: json.RawMessage(`{"f:spec":{"f:replicas":{}}}`)}
	if err := MigratedEndState(migrated(applied, scale), withEdit, "farcast"); err != nil {
		t.Errorf("a subresource entry of a converted manager is refused: %v", err)
	}

	cases := []struct {
		name string
		o    Object
		csa  []string
		want string
	}{
		{"the live list kept, and the annotation", migratable(), csaOnly,
			"kubectl-client-side-apply/Update still present; annotation kubectl.kubernetes.io/last-applied-configuration still present; farcast/Apply present 0 times, not once"},
		{"the client-side entry left", migrated(applied, entry("kubectl-client-side-apply", "Update", "apps/v1", ownsAnnNot)), csaOnly,
			"kubectl-client-side-apply/Update still present"},
		{"another owner of the annotation left", migrated(applied, entry("kubectl-edit", "Update", "apps/v1", ownsAnn)), csaOnly,
			"kubectl-edit/Update still present"},
		// The live list was kept with a farcast/Apply entry already in it (an
		// instance written again by kubectl after its migration, §6.6), and
		// the server stripped the annotation's path from kubectl-edit's entry
		// when it removed the annotation: only csa still names it.
		{"a converted owner left without the annotation's path", migrated(applied, entry("kubectl-edit", "Update", "apps/v1", ownsAnnNot)), withEdit,
			"kubectl-edit/Update still present"},
		{"a converted owner left, and kubectl-client-side-apply", migrated(applied,
			entry("kubectl-edit", "Update", "apps/v1", ownsAnnNot), entry("kubectl-client-side-apply", "Update", "apps/v1", ownsAnnNot)), withEdit,
			"kubectl-client-side-apply/Update still present; kubectl-edit/Update still present"},
		{"the annotation left", func() Object {
			o := migrated(applied)
			o.Metadata.Annotations = migratable().Metadata.Annotations
			return o
		}(), csaOnly,
			"annotation kubectl.kubernetes.io/last-applied-configuration still present"},
		{"no farcast entry", migrated(kernel), csaOnly, "farcast/Apply present 0 times, not once"},
		{"two farcast Apply entries", migrated(applied, entry("farcast", "Apply", "apps/v1beta1", `{}`)), csaOnly, "farcast/Apply present 2 times, not once"},
		{"a farcast Update entry", migrated(applied, entry("farcast", "Update", "apps/v1", `{"f:metadata":{}}`)), csaOnly, "farcast/Update present"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := MigratedEndState(tc.o, tc.csa, "farcast")
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
	if err := MigratedEndState(after, csa, "farcast"); err != nil {
		t.Errorf("the rewritten object is not in the end state: %v", err)
	}
	if again, err := MigrationPatch(after, csa, "farcast"); again != nil || err != nil {
		t.Errorf("a second migration would send %s, %v", again, err)
	}
}
