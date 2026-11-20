package kube

import "testing"

// entry is a managed-fields entry on the main resource, with no fields.
func entry(manager, operation, apiVersion string) ManagedFieldsEntry {
	return ManagedFieldsEntry{Manager: manager, Operation: operation, APIVersion: apiVersion, Time: "2026-11-01T10:00:00Z", FieldsType: "FieldsV1"}
}

// ADR 0023 M2.6 (A23-46, A28-7), narrowed at M2.9a (design §37, A37-8): an
// apply of the object by farcast is farcast's own Apply on the object itself.
// kubectl's client-side apply Update is not one, nor are the same managers
// under the other operation, a subresource entry under either, and every
// other manager: the kernel's writes among them, under whatever name the
// server gives them.
func TestIsOwnApplyIsFarcastsOwnApplyOfTheObject(t *testing.T) {
	for _, row := range []struct {
		e    ManagedFieldsEntry
		want bool
	}{
		{entry("farcast", "Apply", "apps/v1"), true},
		{entry("kubectl-client-side-apply", "Update", "apps/v1"), false},
		{entry("farcast", "Update", "apps/v1"), false},
		{entry("kubectl-client-side-apply", "Apply", "apps/v1"), false},
		{ManagedFieldsEntry{Manager: "farcast", Operation: "Apply", APIVersion: "apps/v1", Subresource: "status"}, false},
		{ManagedFieldsEntry{Manager: "kubectl-client-side-apply", Operation: "Update", APIVersion: "autoscaling/v1", Subresource: "scale"}, false},
		{entry("kubectl", "Apply", "apps/v1"), false},
		{entry("Go-http-client", "Update", "apps/v1"), false},
		{entry("technocore", "Update", "apps/v1"), false},
		{ManagedFieldsEntry{}, false},
	} {
		if got := IsOwnApply(row.e); got != row.want {
			t.Errorf("IsOwnApply(%s, %s, subresource %q) = %v, want %v", row.e.Manager, row.e.Operation, row.e.Subresource, got, row.want)
		}
	}
}
