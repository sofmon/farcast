package cli

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	dsdeploy "github.com/sofmon/farcast/datasphere/deploy"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	pbuild "github.com/sofmon/farcast/planck/build"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
	tkube "github.com/sofmon/farcast/technocore/kube"
)

// The fixtures of design §33 (A33-40): the project number, and datasphered's
// and farcast-builder's uids.
const (
	fixtureProjectNumber = 123456789012
	fixtureKeyholderUID  = "00000000-0000-4000-8000-0000000000d5"
	fixtureBuilderUID    = "00000000-0000-4000-8000-0000000000b5"
)

// fixtureAccounts are the ServiceAccounts a fixture cluster holds in
// farcast-system by default, each at its fixture uid (A33-40).
func fixtureAccounts() map[string]string {
	return map[string]string{dsdeploy.DefaultName: fixtureKeyholderUID, pbuild.ServiceAccount: fixtureBuilderUID}
}

// accountMeta is GetMeta for a test fake whose cluster holds accounts, the
// ServiceAccounts of farcast-system by name, each at its uid: an account it
// holds is its metadata, and any other, in any namespace, is
// tkube.ErrNotFound, as the API server answers. A kind other than
// ServiceAccount is the test's own error: no plan reads another.
func accountMeta(accounts map[string]string, k kube.Kind, namespace, name string) (kube.Object, error) {
	if k.Kind != "ServiceAccount" || k.APIVersion != "v1" {
		return kube.Object{}, fmt.Errorf("test: a GetMeta of %s %s/%s", k.Kind, namespace, name)
	}
	uid, ok := accounts[name]
	if !ok || namespace != tcdeploy.DefaultNamespace {
		return kube.Object{}, fmt.Errorf("serviceaccounts %q: %w", name, tkube.ErrNotFound)
	}
	o := kube.Object{Kind: k}
	o.Metadata.Name, o.Metadata.Namespace, o.Metadata.UID = name, namespace, uid
	return o, nil
}

// TestWorkloadPrincipalsRefuseUnsafeValues: the two principals a grant names
// (A33-10) are built only from values of their shapes, since a plan binds
// them, a policy write sends them and a printed command carries them into an
// Owner's shell. A project or a uid that could act on that shell is refused,
// kind internal, and nothing is returned to print (mutation row 135).
func TestWorkloadPrincipalsRefuseUnsafeValues(t *testing.T) {
	const project = "proj-atlas"

	t.Run("the fixture principals", func(t *testing.T) {
		got, err := workloadUIDPrincipal(fixtureProjectNumber, project, fixtureKeyholderUID)
		if err != nil {
			t.Fatal(err)
		}
		const want = "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/proj-atlas.svc.id.goog/kubernetes.serviceaccount.uid/00000000-0000-4000-8000-0000000000d5"
		if got != want {
			t.Errorf("the uid principal is\n  %s\nwant\n  %s", got, want)
		}
		if _, _, ok := placeholderServiceAccount(got); ok {
			t.Errorf("%s reads as carrying the uid placeholder", got)
		}
		shared, err := workloadNamePrincipal(fixtureProjectNumber, project, "farcast-system", "datasphered")
		if err != nil {
			t.Fatal(err)
		}
		const wantShared = "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/proj-atlas.svc.id.goog/subject/ns/farcast-system/sa/datasphered"
		if shared != wantShared {
			t.Errorf("the shared principal is\n  %s\nwant\n  %s", shared, wantShared)
		}
	})

	t.Run("the uid placeholder", func(t *testing.T) {
		placeholder := saUIDPlaceholder("farcast-system", "farcast-builder")
		if placeholder != "farcast-placeholder:sa-uid:farcast-system/farcast-builder" {
			t.Errorf("saUIDPlaceholder = %q", placeholder)
		}
		got, err := workloadUIDPrincipal(fixtureProjectNumber, project, placeholder)
		if err != nil {
			t.Fatalf("the placeholder of an account this command creates is refused: %v", err)
		}
		ns, name, ok := placeholderServiceAccount(got)
		if !ok || ns != "farcast-system" || name != "farcast-builder" {
			t.Errorf("placeholderServiceAccount(%s) = %q, %q, %v", got, ns, name, ok)
		}
	})

	// The refusals: each is internal and returns no principal.
	refused := func(t *testing.T, what, principal string, err error, want string) {
		t.Helper()
		if err == nil || principal != "" {
			t.Fatalf("%s: got %q, %v; want a refusal and no principal", what, principal, err)
		}
		if err.Error() != want {
			t.Errorf("%s: the refusal is\n  %s\nwant\n  %s", what, err, want)
		}
		if kind := kindOf(err); kind != kindInternal {
			t.Errorf("%s: kind %q, want internal", what, kind)
		}
	}

	for _, p := range []string{"proj-$(id)", "proj-'atlas", "Proj-atlas", "proj-atlas\n"} {
		want := fmt.Sprintf(msgUnsafeGrantProject, p)
		got, err := workloadUIDPrincipal(fixtureProjectNumber, p, fixtureKeyholderUID)
		refused(t, fmt.Sprintf("uid principal, project %q", p), got, err, want)
		got, err = workloadNamePrincipal(fixtureProjectNumber, p, "farcast-system", "datasphered")
		refused(t, fmt.Sprintf("name principal, project %q", p), got, err, want)
	}

	for _, n := range []int64{0, -1} {
		want := fmt.Sprintf(msgUnsafeGrantNumber, n)
		got, err := workloadUIDPrincipal(n, project, fixtureKeyholderUID)
		refused(t, fmt.Sprintf("uid principal, number %d", n), got, err, want)
		got, err = workloadNamePrincipal(n, project, "farcast-system", "datasphered")
		refused(t, fmt.Sprintf("name principal, number %d", n), got, err, want)
	}

	// A uid the API server sent is never quoted, and never refused with
	// the record's words: the record does not hold it.
	for name, uid := range map[string]string{
		"a quote":                    "00000000-0000-4000-8000-0000000'00d5",
		"a newline":                  "00000000-0000-4000-8000-0000000000d5\n",
		"upper case":                 "00000000-0000-4000-8000-0000000000D5",
		"35 characters":              "00000000-0000-4000-8000-0000000000d",
		"37 characters":              "00000000-0000-4000-8000-0000000000d55",
		"empty":                      "",
		"a placeholder's prefix":     "farcast-placeholder:sa-uid:",
		"a placeholder with a quote": "farcast-placeholder:sa-uid:farcast-system/data'sphered",
		"a placeholder with a path":  "farcast-placeholder:sa-uid:farcast-system/a/b",
		"a placeholder with $(":      "farcast-placeholder:sa-uid:$(id)/datasphered",
	} {
		got, err := workloadUIDPrincipal(fixtureProjectNumber, project, uid)
		refused(t, "uid "+name, got, err, msgUnsafeGrantUID)
		if err != nil && strings.Contains(err.Error(), "record") {
			t.Errorf("uid %s: the refusal %q speaks of the record, which does not hold a uid", name, err)
		}
	}

	for _, v := range [][2]string{{"farcast-system", "data'sphered"}, {"farcast system", "datasphered"}, {"farcast-system", ""}} {
		got, err := workloadNamePrincipal(fixtureProjectNumber, project, v[0], v[1])
		if err == nil || got != "" || kindOf(err) != kindInternal {
			t.Errorf("name principal of %q/%q: got %q, %v; want an internal refusal", v[0], v[1], got, err)
		}
	}
}

// accountReader is a serviceAccountReader that answers every read with obj
// and err, and records each.
type accountReader struct {
	obj   kube.Object
	err   error
	reads []string
}

func (r *accountReader) GetMeta(_ context.Context, k kube.Kind, namespace, name string) (kube.Object, error) {
	r.reads = append(r.reads, k.Kind+" "+namespace+"/"+name)
	return r.obj, r.err
}

// TestReadServiceAccountUIDAnswers (design §33, A33-18, A33-17): the uid
// read is one GetMeta of the ServiceAccount, metadata only. An account that
// is not there is "", no error. Under --plan and --confirm an RBAC 403 is a
// reader granted before ADR 0023 M2.8: kind forbidden, A33-17's words, the
// server's own message (which names the reader's email) not echoed, and
// marked as the reader's so the writer's sentence is never added; read as
// the writer it stays the writer's, for writerRefused. A uid that is not one
// the API server issues is document_unreadable.
func TestReadServiceAccountUIDAnswers(t *testing.T) {
	read := func(t *testing.T, r *accountReader, m consentMode) (string, error) {
		t.Helper()
		uid, err := readServiceAccountUID(t.Context(), r, m, "atlas", tcdeploy.DefaultNamespace, pbuild.ServiceAccount, "push")
		if !slices.Equal(r.reads, []string{"ServiceAccount farcast-system/farcast-builder"}) {
			t.Errorf("read %q; want the builder's ServiceAccount, once", r.reads)
		}
		return uid, err
	}
	present := kube.Object{}
	present.Metadata.UID = fixtureBuilderUID
	if uid, err := read(t, &accountReader{obj: present}, consentPlan); uid != fixtureBuilderUID || err != nil {
		t.Errorf("a present account = %q, %v; want its uid", uid, err)
	}
	if uid, err := read(t, &accountReader{err: fmt.Errorf("serviceaccounts %q: %w", "farcast-builder", tkube.ErrNotFound)}, consentConfirm); uid != "" || err != nil {
		t.Errorf("an absent account = %q, %v; want \"\" and no error", uid, err)
	}
	rbac := &kube.APIError{Method: "GET", Path: "/api/v1/namespaces/farcast-system/serviceaccounts/farcast-builder",
		Status: kube.Status{Status: tkube.Status{Code: 403, Reason: "Forbidden",
			Message: `serviceaccounts "farcast-builder" is forbidden: User "farcast-reader-1a2b3c4d@proj-atlas.iam.gserviceaccount.com" cannot get resource "serviceaccounts"`}},
		KubernetesStatus: true}
	for _, m := range []consentMode{consentPlan, consentConfirm} {
		_, err := read(t, &accountReader{err: rbac}, m)
		want := "the instance's reader may not read the ServiceAccount farcast-system/farcast-builder, whose uid the push grant names since ADR 0023 M2.8; " +
			"run 'farcast reader grant atlas' again, which adds that read, then plan again (kube: forbidden)"
		var phase *readerPhaseError
		if err == nil || err.Error() != want || kindOf(classified(err)) != kindForbidden || !errors.As(err, &phase) {
			t.Errorf("an RBAC 403 under %v = %v; want %q, forbidden, the reader's", m, err, want)
		}
		if err != nil && (strings.Contains(err.Error(), "iam.gserviceaccount.com") || writerRefused(err, &config.InstanceMetadata{Name: "atlas"}).Error() != err.Error()) {
			t.Errorf("the refusal echoes the server's message, or takes the writer's sentence: %v", err)
		}
	}
	if _, err := read(t, &accountReader{err: rbac}, consentNone); !errors.Is(err, tkube.ErrForbidden) || !forbiddenByRBAC(err) ||
		strings.Contains(err.Error(), "reader grant") {
		t.Errorf("an RBAC 403 as the writer = %v; want the server's 403, for writerRefused", err)
	}
	for _, uid := range []string{"00000000-0000-4000-8000-0000000'00b5", "00000000-0000-4000-8000-0000000000b5\n", "", "FARCAST"} {
		bad := kube.Object{}
		bad.Metadata.UID = uid
		if got, err := read(t, &accountReader{obj: bad}, consentPlan); got != "" || kindOf(classified(err)) != kindDocumentUnreadable {
			t.Errorf("the uid %q = %q, %v; want document_unreadable", uid, got, err)
		}
	}
}
