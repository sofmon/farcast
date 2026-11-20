package gke

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/auth"

	"github.com/sofmon/farcast/planck"
)

// fakeRegistryClient is a programmable registryAPI for exercising the adapter's
// logic — name derivation, defaults, the idempotent IAM merge, operation
// waiting — without the cloud.
type fakeRegistryClient struct {
	created   *repositoryInput
	createOp  string
	createErr error

	deleted   []planck.RegistryRef
	deleteOp  string
	deleteErr error

	ownedErr    error // returned by verifyOwned
	ownedChecks []string

	opStates []opResult // returned by successive operationDone calls; the last repeats
	opCalls  int
	opNames  []string

	policy     iamPolicy
	policyErr  error
	policyRefs []planck.RegistryRef // every getPolicy's ref, in order

	setPolicies []iamPolicy
	setErr      error

	number    int64
	numberErr error

	tok    planck.RegistryToken
	tokErr error
}

type opResult struct {
	done bool
	err  error
}

func (f *fakeRegistryClient) createRepository(_ context.Context, in repositoryInput) (string, error) {
	if f.createErr != nil {
		return "", f.createErr
	}
	f.created = &in
	return f.createOp, nil
}

func (f *fakeRegistryClient) deleteRepository(_ context.Context, ref planck.RegistryRef) (string, error) {
	f.deleted = append(f.deleted, ref)
	if f.deleteErr != nil {
		return "", f.deleteErr
	}
	return f.deleteOp, nil
}

func (f *fakeRegistryClient) verifyOwned(_ context.Context, ref planck.RegistryRef, instance string) error {
	f.ownedChecks = append(f.ownedChecks, ref.Name+"/"+instance)
	return f.ownedErr
}

func (f *fakeRegistryClient) operationDone(_ context.Context, op string) (bool, error) {
	f.opNames = append(f.opNames, op)
	i := f.opCalls
	f.opCalls++
	if len(f.opStates) == 0 {
		return true, nil
	}
	if i >= len(f.opStates) {
		i = len(f.opStates) - 1
	}
	return f.opStates[i].done, f.opStates[i].err
}

func (f *fakeRegistryClient) getPolicy(_ context.Context, ref planck.RegistryRef) (iamPolicy, error) {
	f.policyRefs = append(f.policyRefs, ref)
	return f.policy, f.policyErr
}

func (f *fakeRegistryClient) setPolicy(_ context.Context, _ planck.RegistryRef, pol iamPolicy) error {
	if f.setErr != nil {
		return f.setErr
	}
	f.setPolicies = append(f.setPolicies, pol)
	return nil
}

func (f *fakeRegistryClient) projectNumber(context.Context) (int64, error) {
	if f.numberErr != nil {
		return 0, f.numberErr
	}
	if f.number == 0 {
		return 123456789012, nil
	}
	return f.number, nil
}

func (f *fakeRegistryClient) token(context.Context) (planck.RegistryToken, error) {
	return f.tok, f.tokErr
}

func newTestRegistryProvider(api registryAPI) *provider {
	return &provider{
		cfg:             planck.Config{Project: "proj"},
		regAPI:          api,
		defaultLocation: "us-central1",
		pollInterval:    time.Millisecond,
	}
}

// fastRegistryPolling shortens the long-running-operation poll so waiting tests
// finish instantly.
func fastRegistryPolling(t *testing.T) {
	t.Helper()
	orig := registryPollInterval
	registryPollInterval = time.Millisecond
	t.Cleanup(func() { registryPollInterval = orig })
}

func TestEnsureRegistryCreatesAndGrantsPull(t *testing.T) {
	api := &fakeRegistryClient{number: 42}
	p := newTestRegistryProvider(api)

	reg, err := p.EnsureRegistry(context.Background(), planck.RegistrySpec{
		Name:   "demo",
		Labels: map[string]string{"farcast-instance": "demo"},
	})
	if err != nil {
		t.Fatalf("EnsureRegistry: %v", err)
	}
	if api.created == nil {
		t.Fatal("expected createRepository to be called")
	}
	if api.created.Name != "farcast-demo" {
		t.Errorf("repository = %q, want farcast-demo", api.created.Name)
	}
	if api.created.Location != "us-central1" {
		t.Errorf("location = %q, want the provider default", api.created.Location)
	}
	if api.created.Labels["farcast-instance"] != "demo" {
		t.Errorf("labels = %v, want the spec's labels passed through", api.created.Labels)
	}
	if reg.Ref != (planck.RegistryRef{Name: "farcast-demo", Location: "us-central1"}) {
		t.Errorf("ref = %+v, want the resolved repository", reg.Ref)
	}
	if want := "us-central1-docker.pkg.dev/proj/farcast-demo"; reg.Prefix != want {
		t.Errorf("prefix = %q, want %q", reg.Prefix, want)
	}
	if want := "serviceAccount:42-compute@developer.gserviceaccount.com"; reg.Puller != want {
		t.Errorf("puller = %q, want %q", reg.Puller, want)
	}

	if len(api.setPolicies) != 1 {
		t.Fatalf("setPolicy called %d times, want 1", len(api.setPolicies))
	}
	got := api.setPolicies[0]
	if len(got.Bindings) != 1 || got.Bindings[0].Role != pullRole {
		t.Fatalf("policy = %+v, want a single %s binding", got, pullRole)
	}
	// The grant must be repository-scoped and reader-only: a wider role here
	// would hand the shared node account write access to the instance's images.
	if pullRole != "roles/artifactregistry.reader" {
		t.Errorf("pullRole = %q, want the read-only role", pullRole)
	}
	if got.Bindings[0].Members[0] != reg.Puller {
		t.Errorf("members = %v, want the node service account", got.Bindings[0].Members)
	}
}

func TestEnsureRegistryUsesSpecLocation(t *testing.T) {
	api := &fakeRegistryClient{}
	p := newTestRegistryProvider(api)

	reg, err := p.EnsureRegistry(context.Background(), planck.RegistrySpec{Name: "demo", Location: "europe-west1"})
	if err != nil {
		t.Fatalf("EnsureRegistry: %v", err)
	}
	if api.created.Location != "europe-west1" {
		t.Errorf("location = %q, want the spec's", api.created.Location)
	}
	if want := "europe-west1-docker.pkg.dev/proj/farcast-demo"; reg.Prefix != want {
		t.Errorf("prefix = %q, want %q", reg.Prefix, want)
	}
}

// TestEnsureRegistryIdempotent is the defensive-ensure path `farcast connect`
// runs on every reconnect: the repository is already there and already carries
// the grant, so nothing is written.
func TestEnsureRegistryIdempotent(t *testing.T) {
	api := &fakeRegistryClient{
		number: 42,
		policy: iamPolicy{
			Etag: "abc",
			Bindings: []iamBinding{{
				Role:    pullRole,
				Members: []string{"serviceAccount:42-compute@developer.gserviceaccount.com"},
			}},
		},
	}
	p := newTestRegistryProvider(api)

	if _, err := p.EnsureRegistry(context.Background(), planck.RegistrySpec{Name: "demo"}); err != nil {
		t.Fatalf("EnsureRegistry: %v", err)
	}
	if len(api.setPolicies) != 0 {
		t.Errorf("setPolicy called %d times, want 0 when the binding already exists", len(api.setPolicies))
	}
}

// TestEnsureRegistryPreservesOtherBindings guards the read-modify-write: the
// adapter replaces the whole policy, so anything it drops is a grant it deleted.
func TestEnsureRegistryPreservesOtherBindings(t *testing.T) {
	api := &fakeRegistryClient{
		number: 42,
		policy: iamPolicy{
			Etag:    "etag-1",
			Version: 3,
			Bindings: []iamBinding{
				{Role: "roles/artifactregistry.writer", Members: []string{"user:ops@example.com"}},
				{
					Role:      pullRole,
					Members:   []string{"user:auditor@example.com"},
					Condition: &iamCondition{Title: "expires", Expression: "request.time < timestamp('2030-01-01T00:00:00Z')"},
				},
			},
		},
	}
	p := newTestRegistryProvider(api)

	if _, err := p.EnsureRegistry(context.Background(), planck.RegistrySpec{Name: "demo"}); err != nil {
		t.Fatalf("EnsureRegistry: %v", err)
	}
	if len(api.setPolicies) != 1 {
		t.Fatalf("setPolicy called %d times, want 1", len(api.setPolicies))
	}
	got := api.setPolicies[0]
	if got.Etag != "etag-1" {
		t.Errorf("etag = %q, want it round-tripped for optimistic concurrency", got.Etag)
	}
	if got.Version != 3 {
		t.Errorf("version = %d, want 3 preserved (the policy has conditions)", got.Version)
	}
	if len(got.Bindings) != 3 {
		t.Fatalf("bindings = %d, want the two existing plus ours", len(got.Bindings))
	}
	if got.Bindings[1].Condition == nil {
		t.Error("the conditional binding lost its condition — that widens someone else's grant")
	}
	added := got.Bindings[2]
	if added.Role != pullRole || added.Condition != nil {
		t.Errorf("added binding = %+v, want an unconditional %s", added, pullRole)
	}
}

// TestEnsureRegistryWaitsForCreate proves the IAM grant is not attempted until
// the repository actually exists — a setIamPolicy on a half-created repository
// fails with a confusing NotFound.
func TestEnsureRegistryWaitsForCreate(t *testing.T) {
	fastRegistryPolling(t)
	api := &fakeRegistryClient{
		createOp: "projects/proj/locations/us-central1/operations/op-1",
		opStates: []opResult{{done: false}, {done: false}, {done: true}},
	}
	p := newTestRegistryProvider(api)

	if _, err := p.EnsureRegistry(context.Background(), planck.RegistrySpec{Name: "demo"}); err != nil {
		t.Fatalf("EnsureRegistry: %v", err)
	}
	if api.opCalls != 3 {
		t.Errorf("operationDone called %d times, want 3 (polled to completion)", api.opCalls)
	}
	if len(api.setPolicies) != 1 {
		t.Errorf("setPolicy called %d times, want 1 after the wait", len(api.setPolicies))
	}
}

func TestEnsureRegistryFailedOperation(t *testing.T) {
	fastRegistryPolling(t)
	wantErr := errors.New("quota exceeded")
	api := &fakeRegistryClient{
		createOp: "projects/proj/locations/us-central1/operations/op-1",
		opStates: []opResult{{done: true, err: wantErr}},
	}
	p := newTestRegistryProvider(api)

	_, err := p.EnsureRegistry(context.Background(), planck.RegistrySpec{Name: "demo"})
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want the operation's failure", err)
	}
	if len(api.setPolicies) != 0 {
		t.Error("no IAM grant may be attempted after a failed create")
	}
}

func TestEnsureRegistryRejectsBadNames(t *testing.T) {
	// "9lives" is deliberately absent: the farcast- prefix supplies the leading
	// letter, so an instance name starting with a digit is fine.
	for _, name := range []string{"", "Bad_Name", "trailing-", strings.Repeat("a", 64)} {
		p := newTestRegistryProvider(&fakeRegistryClient{})
		if _, err := p.EnsureRegistry(context.Background(), planck.RegistrySpec{Name: name}); err == nil {
			t.Errorf("EnsureRegistry(%q): expected an error", name)
		}
	}
}

// TestEnsureRegistryErrorStaysClassifiable keeps the ADR's degrade-to-warning
// path working: `connect` must be able to tell a stale installer service
// account (403) from a real failure, through the adapter's wrapping.
func TestEnsureRegistryErrorStaysClassifiable(t *testing.T) {
	api := &fakeRegistryClient{createErr: &apiError{Code: 403, Status: "PERMISSION_DENIED", Message: "missing artifactregistry.repositories.create"}}
	p := newTestRegistryProvider(api)

	_, err := p.EnsureRegistry(context.Background(), planck.RegistrySpec{Name: "demo"})
	if err == nil {
		t.Fatal("expected an error")
	}
	var apiErr *apiError
	if !errors.As(err, &apiErr) || apiErr.Code != 403 {
		t.Fatalf("err = %v, want a 403 reachable through errors.As", err)
	}
	if !strings.Contains(err.Error(), "farcast-demo") {
		t.Errorf("err = %v, want it to name the repository", err)
	}
}

func TestDeleteRegistryWaitsForCompletion(t *testing.T) {
	fastRegistryPolling(t)
	api := &fakeRegistryClient{
		deleteOp: "projects/proj/locations/us-central1/operations/op-2",
		opStates: []opResult{{done: false}, {done: true}},
	}
	p := newTestRegistryProvider(api)

	if err := p.DeleteRegistry(context.Background(), planck.RegistryRef{Name: "farcast-demo"}); err != nil {
		t.Fatalf("DeleteRegistry: %v", err)
	}
	if api.opCalls != 2 {
		t.Errorf("operationDone called %d times, want 2 — teardown must not report success on an unfinished delete", api.opCalls)
	}
	if api.opNames[0] != api.deleteOp {
		t.Errorf("polled %q, want the operation the delete returned (%q)", api.opNames[0], api.deleteOp)
	}
	if api.deleted[0].Location != "us-central1" {
		t.Errorf("location = %q, want the provider default", api.deleted[0].Location)
	}
}

// TestDeleteRegistryAcceptsEitherName is the anti-leak guard: a caller holding
// the instance name and a caller holding the repository name must delete the
// same repository, because deleting an absent one succeeds silently.
func TestDeleteRegistryAcceptsEitherName(t *testing.T) {
	for _, given := range []string{"demo", "farcast-demo"} {
		api := &fakeRegistryClient{}
		p := newTestRegistryProvider(api)
		if err := p.DeleteRegistry(context.Background(), planck.RegistryRef{Name: given, Location: "us-east1"}); err != nil {
			t.Fatalf("DeleteRegistry(%q): %v", given, err)
		}
		if api.deleted[0].Name != "farcast-demo" {
			t.Errorf("DeleteRegistry(%q) deleted %q, want farcast-demo", given, api.deleted[0].Name)
		}
	}
}

func TestDeleteRegistryAbsentIsSuccess(t *testing.T) {
	api := &fakeRegistryClient{} // deleteOp empty: nothing to wait for
	p := newTestRegistryProvider(api)
	if err := p.DeleteRegistry(context.Background(), planck.RegistryRef{Name: "farcast-gone"}); err != nil {
		t.Fatalf("DeleteRegistry: %v", err)
	}
	if api.opCalls != 0 {
		t.Errorf("operationDone called %d times, want 0 when there is no operation", api.opCalls)
	}
}

func TestDeleteRegistryRequiresName(t *testing.T) {
	p := newTestRegistryProvider(&fakeRegistryClient{})
	if err := p.DeleteRegistry(context.Background(), planck.RegistryRef{}); err == nil {
		t.Fatal("expected an error for an empty registry name")
	}
}

func TestDeleteRegistryContextCancelled(t *testing.T) {
	api := &fakeRegistryClient{
		deleteOp: "projects/proj/locations/us-central1/operations/op-3",
		opStates: []opResult{{done: false}}, // never completes
	}
	p := newTestRegistryProvider(api)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.DeleteRegistry(ctx, planck.RegistryRef{Name: "farcast-demo"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestRegistryTokenPassesThrough(t *testing.T) {
	want := planck.RegistryToken{Username: tokenUsername, Password: "ya29.token", Expiry: time.Unix(1000, 0)}
	p := newTestRegistryProvider(&fakeRegistryClient{tok: want})

	got, err := p.RegistryToken(context.Background())
	if err != nil {
		t.Fatalf("RegistryToken: %v", err)
	}
	if got != want {
		t.Errorf("token = %+v, want %+v", got, want)
	}
}

func TestRegistryTokenError(t *testing.T) {
	wantErr := errors.New("bad key")
	p := newTestRegistryProvider(&fakeRegistryClient{tokErr: wantErr})
	if _, err := p.RegistryToken(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
}

// TestLazyRegistryClientWiring exercises a provider built by New (regAPI starts
// nil) so every registry operation must construct the client via
// registryClient(), guarding against a method dereferencing a nil seam.
func TestLazyRegistryClientWiring(t *testing.T) {
	orig := newRegistryClient
	t.Cleanup(func() { newRegistryClient = orig })
	fake := &fakeRegistryClient{}
	built := 0
	newRegistryClient = func(planck.Config) (registryAPI, error) {
		built++
		return fake, nil
	}

	p, err := New(planck.Config{Project: "proj"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rp, ok := p.(planck.RegistryProvider)
	if !ok {
		t.Fatal("the GKE provider must satisfy planck.RegistryProvider")
	}
	ctx := context.Background()
	if _, err := rp.EnsureRegistry(ctx, planck.RegistrySpec{Name: "demo"}); err != nil {
		t.Fatalf("EnsureRegistry: %v", err)
	}
	if _, err := rp.RegistryToken(ctx); err != nil {
		t.Fatalf("RegistryToken: %v", err)
	}
	if err := rp.DeleteRegistry(ctx, planck.RegistryRef{Name: "demo"}); err != nil {
		t.Fatalf("DeleteRegistry: %v", err)
	}
	if built != 1 {
		t.Errorf("newRegistryClient called %d times, want 1 (built once, then reused)", built)
	}
}

func TestRepositoryName(t *testing.T) {
	cases := map[string]string{
		"demo":         "farcast-demo",
		"farcast-demo": "farcast-demo", // idempotent: install and release must agree
		"a":            "farcast-a",
	}
	for in, want := range cases {
		if got := repositoryName(in); got != want {
			t.Errorf("repositoryName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestImagePathPrefix(t *testing.T) {
	got := imagePathPrefix("us-central1", "my-proj", "farcast-demo")
	if want := "us-central1-docker.pkg.dev/my-proj/farcast-demo"; got != want {
		t.Errorf("imagePathPrefix = %q, want %q", got, want)
	}
}

func TestNodeServiceAccountMember(t *testing.T) {
	got := nodeServiceAccountMember(123456789012)
	if want := "serviceAccount:123456789012-compute@developer.gserviceaccount.com"; got != want {
		t.Errorf("nodeServiceAccountMember = %q, want %q", got, want)
	}
}

func TestValidateRepositoryName(t *testing.T) {
	valid := []string{"farcast-demo", "farcast-a1", "f"}
	for _, name := range valid {
		if err := validateRepositoryName(name); err != nil {
			t.Errorf("validateRepositoryName(%q) = %v, want nil", name, err)
		}
	}
	invalid := []string{
		"",
		"Farcast-Demo",          // uppercase: not a legal Docker reference path
		"farcast_demo",          // underscore: AR allows it, Docker paths do not
		"1farcast",              // must start with a letter
		"farcast-",              // trailing hyphen
		"farcast-é",             // non-ASCII
		strings.Repeat("a", 64), // over AR's length limit
	}
	for _, name := range invalid {
		if err := validateRepositoryName(name); err == nil {
			t.Errorf("validateRepositoryName(%q) = nil, want an error", name)
		}
	}
}

func TestGrantRole(t *testing.T) {
	const member = "serviceAccount:42-compute@developer.gserviceaccount.com"

	t.Run("empty policy", func(t *testing.T) {
		got, changed := grantRole(iamPolicy{}, pullRole, member)
		if !changed {
			t.Fatal("expected a change")
		}
		if len(got.Bindings) != 1 || got.Bindings[0].Role != pullRole || got.Bindings[0].Members[0] != member {
			t.Errorf("policy = %+v, want one binding for the member", got)
		}
	})

	t.Run("existing role binding is extended", func(t *testing.T) {
		in := iamPolicy{Bindings: []iamBinding{{Role: pullRole, Members: []string{"user:someone@example.com"}}}}
		got, changed := grantRole(in, pullRole, member)
		if !changed {
			t.Fatal("expected a change")
		}
		if len(got.Bindings) != 1 || len(got.Bindings[0].Members) != 2 {
			t.Errorf("policy = %+v, want the member appended to the existing binding", got)
		}
		if len(in.Bindings[0].Members) != 1 {
			t.Error("grantRole mutated its input policy")
		}
	})

	t.Run("already granted is a no-op", func(t *testing.T) {
		in := iamPolicy{Bindings: []iamBinding{{Role: pullRole, Members: []string{member}}}}
		if _, changed := grantRole(in, pullRole, member); changed {
			t.Error("expected no change when the member is already bound")
		}
	})

	t.Run("conditional binding does not count", func(t *testing.T) {
		in := iamPolicy{Bindings: []iamBinding{{
			Role:      pullRole,
			Members:   []string{member},
			Condition: &iamCondition{Expression: "false"},
		}}}
		got, changed := grantRole(in, pullRole, member)
		if !changed {
			t.Fatal("a conditional grant is not a guarantee of access; expected an unconditional binding to be added")
		}
		if len(got.Bindings) != 2 || got.Bindings[1].Condition != nil {
			t.Errorf("policy = %+v, want an unconditional binding added alongside", got)
		}
	})
}

func TestOperationOutcome(t *testing.T) {
	if done, err := operationOutcome(nil); done || err != nil {
		t.Errorf("operationOutcome(nil) = (%v, %v), want (false, nil)", done, err)
	}
	if done, err := operationOutcome(&operationResource{Done: true}); !done || err != nil {
		t.Errorf("done operation = (%v, %v), want (true, nil)", done, err)
	}
	if done, err := operationOutcome(&operationResource{}); done || err != nil {
		t.Errorf("pending operation = (%v, %v), want (false, nil)", done, err)
	}
	done, err := operationOutcome(&operationResource{Name: "op", Error: &statusResource{Code: 7, Message: "denied"}})
	if !done || err == nil {
		t.Fatalf("failed operation = (%v, %v), want (true, error)", done, err)
	}
	if !strings.Contains(err.Error(), "denied") {
		t.Errorf("err = %v, want the service's message", err)
	}
}

func TestPendingOperation(t *testing.T) {
	op, err := pendingOperation(&operationResource{Name: "projects/p/locations/l/operations/x"})
	if err != nil || op != "projects/p/locations/l/operations/x" {
		t.Errorf("pendingOperation = (%q, %v), want the name to poll", op, err)
	}
	if op, err := pendingOperation(&operationResource{Name: "x", Done: true}); err != nil || op != "" {
		t.Errorf("completed operation = (%q, %v), want nothing to wait for", op, err)
	}
}

func TestValidOperationName(t *testing.T) {
	if !validOperationName("projects/p/locations/us-central1/operations/abc-123") {
		t.Error("a normal operation name must be accepted")
	}
	for _, bad := range []string{
		"",
		"/projects/p/operations/x",
		"https://evil.example.com/steal",
		"projects/../../evil",
		"projects/p/operations/x?alt=media",
		"projects/p//operations/x",
	} {
		if validOperationName(bad) {
			t.Errorf("validOperationName(%q) = true, want it rejected before it becomes a URL", bad)
		}
	}
}

func TestParseAPIErrorAndClassification(t *testing.T) {
	body := `{"error":{"code":409,"message":"Repository already exists","status":"ALREADY_EXISTS"}}`
	err := parseAPIError(http.StatusConflict, []byte(body))
	if !isHTTPStatus(err, http.StatusConflict) {
		t.Fatalf("err = %v, want it classified as 409", err)
	}
	if !strings.Contains(err.Error(), "ALREADY_EXISTS") {
		t.Errorf("err = %v, want the canonical status", err)
	}
	// Wrapping must not hide the status — the adapter wraps every call.
	wrapped := errors.New("outer")
	if isHTTPStatus(wrapped, http.StatusConflict) {
		t.Error("an unrelated error must not classify as 409")
	}
	// A non-JSON body (a proxy or captive portal) still yields the HTTP status.
	plain := parseAPIError(http.StatusForbidden, []byte("<html>nope</html>"))
	if !isHTTPStatus(plain, http.StatusForbidden) {
		t.Errorf("err = %v, want the HTTP status preserved without a JSON envelope", plain)
	}
	if isHTTPStatus(nil, http.StatusNotFound) {
		t.Error("a nil error must not classify as a status")
	}
}

func TestPolicyWireRoundTrip(t *testing.T) {
	in := iamPolicy{
		Etag:    "etag-1",
		Version: 3,
		Bindings: []iamBinding{
			{Role: "roles/a", Members: []string{"user:x@example.com"}},
			{
				Role:      "roles/b",
				Members:   []string{"group:y@example.com"},
				Condition: &iamCondition{Title: "t", Description: "d", Expression: "e", Location: "l"},
			},
		},
	}
	got := fromWirePolicy(toWirePolicy(in))
	if got.Etag != in.Etag || got.Version != in.Version || len(got.Bindings) != 2 {
		t.Fatalf("round trip = %+v, want %+v", got, in)
	}
	if got.Bindings[1].Condition == nil || *got.Bindings[1].Condition != *in.Bindings[1].Condition {
		t.Errorf("condition = %+v, want it preserved in both directions", got.Bindings[1].Condition)
	}
	if fromWirePolicy(nil).Bindings != nil {
		t.Error("a nil policy must decode to an empty one")
	}
}

// --- wire-protocol tests: a fake RoundTripper, no listener, no network ---

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type capturedRequest struct {
	method string
	url    string
	body   string
}

// newWireClient builds a gkeRegistryClient whose transport records each request
// and replies with the queued responses, so the exact URLs, methods and bodies
// this adapter puts on the wire are asserted without contacting Google.
func newWireClient(t *testing.T, replies ...*http.Response) (*gkeRegistryClient, *[]capturedRequest) {
	t.Helper()
	var seen []capturedRequest
	i := 0
	return &gkeRegistryClient{
		http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			body := ""
			if r.Body != nil {
				b, err := io.ReadAll(r.Body)
				if err != nil {
					return nil, err
				}
				body = string(b)
			}
			seen = append(seen, capturedRequest{method: r.Method, url: r.URL.String(), body: body})
			if i >= len(replies) {
				t.Errorf("unexpected request %s %s", r.Method, r.URL)
				return jsonReply(http.StatusInternalServerError, "{}"), nil
			}
			reply := replies[i]
			i++
			return reply, nil
		})},
		project: "my-proj",
		arBase:  "https://artifactregistry.example/v1/",
		crmBase: "https://resourcemanager.example/v1/",
	}, &seen
}

func jsonReply(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestClientCreateRepositoryRequest(t *testing.T) {
	c, seen := newWireClient(t, jsonReply(http.StatusOK, `{"name":"projects/my-proj/locations/us-central1/operations/op-1"}`))

	op, err := c.createRepository(context.Background(), repositoryInput{
		Name:     "farcast-demo",
		Location: "us-central1",
		Labels:   map[string]string{"farcast-instance": "demo"},
	})
	if err != nil {
		t.Fatalf("createRepository: %v", err)
	}
	if op != "projects/my-proj/locations/us-central1/operations/op-1" {
		t.Errorf("operation = %q, want the returned name", op)
	}
	req := (*seen)[0]
	if req.method != http.MethodPost {
		t.Errorf("method = %s, want POST", req.method)
	}
	want := "https://artifactregistry.example/v1/projects/my-proj/locations/us-central1/repositories?repositoryId=farcast-demo"
	if req.url != want {
		t.Errorf("url = %q, want %q", req.url, want)
	}
	var body repositoryResource
	if err := json.Unmarshal([]byte(req.body), &body); err != nil {
		t.Fatalf("decode request body: %v", err)
	}
	if body.Format != "DOCKER" {
		t.Errorf("format = %q, want DOCKER (a kubelet pulls nothing else)", body.Format)
	}
	if body.Labels["farcast-instance"] != "demo" {
		t.Errorf("labels = %v, want the spec's labels", body.Labels)
	}
}

func TestClientCreateRepositoryConflictAdoptsOurOwn(t *testing.T) {
	// The repository already exists and carries FarCast's labels: ensure is
	// idempotent, so this is success with nothing to wait for.
	c, seen := newWireClient(t,
		jsonReply(http.StatusConflict, `{"error":{"code":409,"message":"already exists","status":"ALREADY_EXISTS"}}`),
		jsonReply(http.StatusOK, `{"format":"DOCKER","labels":{"managed-by":"farcast","farcast-instance":"demo"}}`))

	op, err := c.createRepository(context.Background(), repositoryInput{
		Name:     "farcast-demo",
		Location: "us-central1",
		Labels:   map[string]string{"managed-by": "farcast", "farcast-instance": "demo"},
	})
	if err != nil {
		t.Fatalf("an existing FarCast repository must not fail an ensure: %v", err)
	}
	if op != "" {
		t.Errorf("operation = %q, want nothing to wait for", op)
	}
	if len(*seen) != 2 || (*seen)[1].method != http.MethodGet {
		t.Fatalf("expected a verifying GET after the conflict, got %+v", *seen)
	}
}

// TestClientCreateRepositoryConflictRefusesAForeignRepository is the reason the
// verification exists: farcast release deletes this repository and everything
// in it, so a name collision with somebody else's repository must never be
// adopted silently.
func TestClientCreateRepositoryConflictRefusesAForeignRepository(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply string
		want  string
	}{
		{"foreign labels", `{"format":"DOCKER","labels":{"managed-by":"someone-else"}}`, "not FarCast's"},
		{"wrong format", `{"format":"MAVEN","labels":{"managed-by":"farcast","farcast-instance":"demo"}}`, "refusing to touch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := newWireClient(t,
				jsonReply(http.StatusConflict, `{"error":{"code":409,"message":"already exists","status":"ALREADY_EXISTS"}}`),
				jsonReply(http.StatusOK, tc.reply))

			_, err := c.createRepository(context.Background(), repositoryInput{
				Name:     "farcast-demo",
				Location: "us-central1",
				Labels:   map[string]string{"managed-by": "farcast", "farcast-instance": "demo"},
			})
			if err == nil {
				t.Fatal("adopted a repository FarCast did not create")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to explain the refusal (%q)", err, tc.want)
			}
		})
	}
}

func TestClientDeleteRepositoryNotFoundIsSuccess(t *testing.T) {
	c, seen := newWireClient(t, jsonReply(http.StatusNotFound,
		`{"error":{"code":404,"message":"not found","status":"NOT_FOUND"}}`))

	op, err := c.deleteRepository(context.Background(), planck.RegistryRef{Name: "farcast-demo", Location: "us-central1"})
	if err != nil {
		t.Fatalf("deleting an absent repository must succeed: %v", err)
	}
	if op != "" {
		t.Errorf("operation = %q, want nothing to wait for", op)
	}
	req := (*seen)[0]
	if req.method != http.MethodDelete {
		t.Errorf("method = %s, want DELETE", req.method)
	}
	want := "https://artifactregistry.example/v1/projects/my-proj/locations/us-central1/repositories/farcast-demo"
	if req.url != want {
		t.Errorf("url = %q, want %q", req.url, want)
	}
}

func TestClientPolicyRequests(t *testing.T) {
	c, seen := newWireClient(t,
		jsonReply(http.StatusOK, `{"version":3,"etag":"e1","bindings":[{"role":"roles/x","members":["user:a@example.com"]}]}`),
		jsonReply(http.StatusOK, `{}`),
	)
	ref := planck.RegistryRef{Name: "farcast-demo", Location: "us-central1"}

	pol, err := c.getPolicy(context.Background(), ref)
	if err != nil {
		t.Fatalf("getPolicy: %v", err)
	}
	if pol.Etag != "e1" || len(pol.Bindings) != 1 {
		t.Errorf("policy = %+v, want the decoded policy", pol)
	}
	get := (*seen)[0]
	if get.method != http.MethodGet {
		t.Errorf("method = %s, want GET", get.method)
	}
	// Version 3 is mandatory: a lower version omits conditional bindings from
	// the response, and writing that back would delete them.
	if !strings.Contains(get.url, ":getIamPolicy?options.requestedPolicyVersion=3") {
		t.Errorf("url = %q, want the policy version requested", get.url)
	}

	if err := c.setPolicy(context.Background(), ref, pol); err != nil {
		t.Fatalf("setPolicy: %v", err)
	}
	set := (*seen)[1]
	if set.method != http.MethodPost || !strings.HasSuffix(set.url, ":setIamPolicy") {
		t.Errorf("set request = %s %s, want POST …:setIamPolicy", set.method, set.url)
	}
	var envelope setPolicyRequest
	if err := json.Unmarshal([]byte(set.body), &envelope); err != nil {
		t.Fatalf("decode setIamPolicy body: %v", err)
	}
	if envelope.Policy == nil || envelope.Policy.Etag != "e1" {
		t.Errorf("body = %s, want the etag echoed back", set.body)
	}
}

func TestClientProjectNumber(t *testing.T) {
	c, seen := newWireClient(t, jsonReply(http.StatusOK, `{"projectId":"my-proj","projectNumber":"123456789012"}`))

	num, err := c.projectNumber(context.Background())
	if err != nil {
		t.Fatalf("projectNumber: %v", err)
	}
	if num != 123456789012 {
		t.Errorf("projectNumber = %d, want the string field parsed", num)
	}
	if want := "https://resourcemanager.example/v1/projects/my-proj"; (*seen)[0].url != want {
		t.Errorf("url = %q, want %q", (*seen)[0].url, want)
	}
}

func TestClientProjectNumberMissing(t *testing.T) {
	c, _ := newWireClient(t, jsonReply(http.StatusOK, `{"projectId":"my-proj"}`))
	if _, err := c.projectNumber(context.Background()); err == nil {
		t.Fatal("expected an error when the project reports no number")
	}
}

func TestClientOperationRejectsHostileName(t *testing.T) {
	c, seen := newWireClient(t)
	if _, err := c.operationDone(context.Background(), "https://evil.example.com/x"); err == nil {
		t.Fatal("expected a server-supplied operation name to be validated")
	}
	if len(*seen) != 0 {
		t.Error("no request may be made for a rejected operation name")
	}
}

type fakeTokenProvider struct {
	tok *auth.Token
	err error
}

func (f fakeTokenProvider) Token(context.Context) (*auth.Token, error) { return f.tok, f.err }

func TestClientToken(t *testing.T) {
	expiry := time.Now().Add(time.Hour).Truncate(time.Second)
	c := &gkeRegistryClient{tokens: fakeTokenProvider{tok: &auth.Token{Value: "ya29.abc", Expiry: expiry}}}

	tok, err := c.token(context.Background())
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if tok.Username != "oauth2accesstoken" {
		t.Errorf("username = %q, want oauth2accesstoken", tok.Username)
	}
	if tok.Password != "ya29.abc" || !tok.Expiry.Equal(expiry) {
		t.Errorf("token = %+v, want the minted access token and its expiry", tok)
	}
	// The credential must never render in a log line.
	if strings.Contains(tok.String(), "ya29.abc") {
		t.Errorf("String() leaked the access token: %s", tok.String())
	}
}

func TestRegistryCredentialsRejectsNonServiceAccount(t *testing.T) {
	// An authorized-user credential must be refused: only a service-account key
	// is an acceptable source for a registry push token.
	_, err := registryCredentials(planck.Config{
		Project:     "proj",
		Credentials: []byte(`{"type":"authorized_user","client_id":"x","client_secret":"y","refresh_token":"z"}`),
	})
	if err == nil {
		t.Fatal("expected a non-service-account credential to be rejected")
	}
}

// TestDeleteRegistryProvesOwnershipFirst is the destructive half of the same
// rule adoption follows. The derived repository name could belong to something
// FarCast never created, and DeleteRegistry removes a repository and every
// image in it — so it must refuse rather than guess.
func TestDeleteRegistryProvesOwnershipFirst(t *testing.T) {
	api := &fakeRegistryClient{ownedErr: errors.New("not FarCast's: label \"managed-by\" is \"someone-else\"")}
	p := newTestRegistryProvider(api)

	err := p.DeleteRegistry(context.Background(), planck.RegistryRef{Name: "demo", Location: "us-central1"})
	if err == nil {
		t.Fatal("deleted a repository without proving it was FarCast's")
	}
	if len(api.deleted) != 0 {
		t.Errorf("issued the delete anyway: %+v", api.deleted)
	}
	if len(api.ownedChecks) != 1 || api.ownedChecks[0] != "farcast-demo/demo" {
		t.Errorf("ownership checks = %v, want one for farcast-demo on behalf of demo", api.ownedChecks)
	}
}

// TestDeleteRegistryDeletesWhatItOwns is the other direction: a repository that
// passes the ownership proof is torn down as usual.
func TestDeleteRegistryDeletesWhatItOwns(t *testing.T) {
	api := &fakeRegistryClient{deleteOp: "projects/p/locations/us-central1/operations/op-1",
		opStates: []opResult{{done: true}}}
	p := newTestRegistryProvider(api)

	if err := p.DeleteRegistry(context.Background(), planck.RegistryRef{Name: "demo", Location: "us-central1"}); err != nil {
		t.Fatalf("DeleteRegistry: %v", err)
	}
	if len(api.deleted) != 1 || api.deleted[0].Name != "farcast-demo" {
		t.Errorf("deleted = %+v, want the instance's repository", api.deleted)
	}
}

// TestEnsureRegistryAlwaysStampsOwnership pins the invariant that teardown
// depends on. Ownership labels are not the caller's option: a repository
// created without them would be one FarCast made and could never delete, which
// is a lingering cloud resource — the cost pillar's exact failure mode. (Caught
// live: the first integration run created an unlabelled repository that the
// ownership check then refused to remove.)
func TestEnsureRegistryAlwaysStampsOwnership(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec planck.RegistrySpec
	}{
		{"no labels at all", planck.RegistrySpec{Name: "demo", Location: "us-central1"}},
		{"caller labels only", planck.RegistrySpec{Name: "demo", Location: "us-central1", Labels: map[string]string{"team": "infra"}}},
		{"caller tries to displace the identity", planck.RegistrySpec{Name: "demo", Location: "us-central1",
			Labels: map[string]string{"managed-by": "someone-else", "farcast-instance": "other"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := &fakeRegistryClient{number: 42}
			p := newTestRegistryProvider(api)
			if _, err := p.EnsureRegistry(context.Background(), tc.spec); err != nil {
				t.Fatalf("EnsureRegistry: %v", err)
			}
			if api.created == nil {
				t.Fatal("no repository was created")
			}
			if got := api.created.Labels["managed-by"]; got != "farcast" {
				t.Errorf("managed-by = %q, want farcast", got)
			}
			if got := api.created.Labels["farcast-instance"]; got != "demo" {
				t.Errorf("farcast-instance = %q, want the instance name", got)
			}
		})
	}
}

// TestDeleteRegistryAcceptsEitherNameForm covers the second bug the live run
// exposed: callers pass either the instance ("demo") or the resolved repository
// ("farcast-demo"), and the ownership label carries the instance either way.
func TestDeleteRegistryAcceptsEitherNameForm(t *testing.T) {
	for _, given := range []string{"demo", "farcast-demo"} {
		t.Run(given, func(t *testing.T) {
			api := &fakeRegistryClient{deleteOp: "projects/p/locations/us-central1/operations/op-1",
				opStates: []opResult{{done: true}}}
			p := newTestRegistryProvider(api)
			if err := p.DeleteRegistry(context.Background(), planck.RegistryRef{Name: given, Location: "us-central1"}); err != nil {
				t.Fatalf("DeleteRegistry(%q): %v", given, err)
			}
			if len(api.ownedChecks) != 1 || api.ownedChecks[0] != "farcast-demo/demo" {
				t.Errorf("ownership check = %v, want farcast-demo checked on behalf of instance demo", api.ownedChecks)
			}
		})
	}
}

// The grant reader (design §33, A33-12): the builder's push grant is read and
// stated, never applied.

const (
	writerRole = "roles/artifactregistry.writer"
	// uidMember and sharedMember are design §33's fixture principals for the
	// builder: by its ServiceAccount's uid, and the one every instance in the
	// project shares.
	uidMember    = "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/proj.svc.id.goog/kubernetes.serviceaccount.uid/00000000-0000-4000-8000-0000000000b5"
	sharedMember = "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/proj.svc.id.goog/subject/ns/farcast-system/sa/farcast-builder"
)

// TestRegistryGrantStates: one read of the repository's policy, as
// DeleteRegistry resolves it, gives both observations; a binding with a
// condition never counts; a 403 is unknown with no error; a 404 names the
// repository; and nothing is ever written.
func TestRegistryGrantStates(t *testing.T) {
	conditioned := &iamCondition{Title: "until", Expression: "request.time < timestamp('2030-01-01T00:00:00Z')"}
	for _, tc := range []struct {
		name          string
		bindings      []iamBinding
		state, shared planck.GrantState
	}{
		{"an empty policy", nil, planck.GrantMissing, planck.GrantMissing},
		{"the uid principal alone",
			[]iamBinding{{Role: writerRole, Members: []string{"user:ops@example.com", uidMember}}},
			planck.GrantPresent, planck.GrantMissing},
		{"the shared principal alone",
			[]iamBinding{{Role: writerRole, Members: []string{sharedMember}}},
			planck.GrantMissing, planck.GrantPresent},
		{"both",
			[]iamBinding{{Role: writerRole, Members: []string{sharedMember, uidMember}}},
			planck.GrantPresent, planck.GrantPresent},
		{"both, only under a condition",
			[]iamBinding{{Role: writerRole, Members: []string{uidMember, sharedMember}, Condition: conditioned}},
			planck.GrantMissing, planck.GrantMissing},
		{"both, in another role",
			[]iamBinding{{Role: pullRole, Members: []string{uidMember, sharedMember}}},
			planck.GrantMissing, planck.GrantMissing},
		{"a conditioned binding beside an unconditioned one",
			[]iamBinding{
				{Role: writerRole, Members: []string{uidMember}, Condition: conditioned},
				{Role: writerRole, Members: []string{"user:ops@example.com", uidMember}},
			},
			planck.GrantPresent, planck.GrantMissing},
		{"a member that only begins like the uid principal",
			[]iamBinding{{Role: writerRole, Members: []string{uidMember + "6", strings.ToUpper(sharedMember)}}},
			planck.GrantMissing, planck.GrantMissing},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := &fakeRegistryClient{policy: iamPolicy{Etag: "e", Version: 3, Bindings: tc.bindings}}
			p := newTestRegistryProvider(api)
			state, shared, err := p.RegistryGrant(context.Background(), planck.RegistryRef{Name: "demo"}, writerRole, uidMember, sharedMember)
			if err != nil {
				t.Fatalf("RegistryGrant: %v", err)
			}
			if state != tc.state || shared != tc.shared {
				t.Errorf("states = %s, %s; want %s, %s", state, shared, tc.state, tc.shared)
			}
			if want := []planck.RegistryRef{{Name: "farcast-demo", Location: "us-central1"}}; !slices.Equal(api.policyRefs, want) {
				t.Errorf("policy reads = %+v, want one of %+v: the repository a printed grant names", api.policyRefs, want)
			}
			if len(api.setPolicies) != 0 || api.created != nil || len(api.deleted) != 0 {
				t.Errorf("RegistryGrant wrote: set %d, created %v, deleted %v", len(api.setPolicies), api.created, api.deleted)
			}
		})
	}

	t.Run("a resolved name and a location are kept", func(t *testing.T) {
		api := &fakeRegistryClient{}
		p := newTestRegistryProvider(api)
		if _, _, err := p.RegistryGrant(context.Background(), planck.RegistryRef{Name: "farcast-demo", Location: "europe-west1"},
			writerRole, uidMember, sharedMember); err != nil {
			t.Fatal(err)
		}
		if want := []planck.RegistryRef{{Name: "farcast-demo", Location: "europe-west1"}}; !slices.Equal(api.policyRefs, want) {
			t.Errorf("policy reads = %+v, want %+v", api.policyRefs, want)
		}
	})

	t.Run("a policy the credential may not read", func(t *testing.T) {
		api := &fakeRegistryClient{policyErr: &apiError{Code: http.StatusForbidden, Status: "PERMISSION_DENIED", Message: "no"}}
		p := newTestRegistryProvider(api)
		state, shared, err := p.RegistryGrant(context.Background(), planck.RegistryRef{Name: "demo"}, writerRole, uidMember, sharedMember)
		if err != nil || state != planck.GrantUnknown || shared != planck.GrantUnknown {
			t.Errorf("a 403 gives %s, %s, %v; want unknown, unknown and no error", state, shared, err)
		}
	})

	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"a repository that is not there", &apiError{Code: http.StatusNotFound, Status: "NOT_FOUND", Message: "gone"},
			`the repository "farcast-demo" in us-central1 does not exist`},
		{"a server failure", &apiError{Code: http.StatusInternalServerError, Message: "boom"},
			`read the IAM policy of repository "farcast-demo"`},
		{"a transport failure", errors.New("dial: refused"), `read the IAM policy of repository "farcast-demo"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := &fakeRegistryClient{policyErr: tc.err}
			p := newTestRegistryProvider(api)
			state, shared, err := p.RegistryGrant(context.Background(), planck.RegistryRef{Name: "demo"}, writerRole, uidMember, sharedMember)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !errors.Is(err, tc.err) {
				t.Errorf("RegistryGrant = %s, %s, %v; want an error naming %q that wraps %v", state, shared, err, tc.want, tc.err)
			}
		})
	}

	for name, args := range map[string][4]string{
		"no name":   {"", writerRole, uidMember, sharedMember},
		"no role":   {"demo", "", uidMember, sharedMember},
		"no member": {"demo", writerRole, "", sharedMember},
		"no shared": {"demo", writerRole, uidMember, ""},
	} {
		t.Run(name, func(t *testing.T) {
			api := &fakeRegistryClient{}
			p := newTestRegistryProvider(api)
			if _, _, err := p.RegistryGrant(context.Background(), planck.RegistryRef{Name: args[0]}, args[1], args[2], args[3]); err == nil {
				t.Error("RegistryGrant read with a value missing")
			}
			if len(api.policyRefs) != 0 {
				t.Errorf("RegistryGrant read %d policies with a value missing", len(api.policyRefs))
			}
		})
	}
}

// TestProviderProjectNumberIsExported: the number grantPull builds the node
// account from is a GrantReader method of the provider New returns, read
// again on each call, and its failure names the project.
func TestProviderProjectNumberIsExported(t *testing.T) {
	orig := newRegistryClient
	t.Cleanup(func() { newRegistryClient = orig })
	fake := &fakeRegistryClient{number: 987654321098}
	newRegistryClient = func(planck.Config) (registryAPI, error) { return fake, nil }

	p, err := New(planck.Config{Project: "proj"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	gr, ok := p.(planck.GrantReader)
	if !ok {
		t.Fatal("the GKE provider must satisfy planck.GrantReader")
	}
	if _, ok := p.(planck.RegistryProvider); !ok {
		t.Fatal("the GKE provider must still satisfy planck.RegistryProvider")
	}
	num, err := gr.ProjectNumber(context.Background())
	if err != nil || num != 987654321098 {
		t.Errorf("ProjectNumber = %d, %v; want the project's number", num, err)
	}
	fake.number = 123456789012
	if num, err := gr.ProjectNumber(context.Background()); err != nil || num != 123456789012 {
		t.Errorf("ProjectNumber = %d, %v; want it read again, not kept", num, err)
	}

	cause := &apiError{Code: http.StatusForbidden, Message: "no"}
	fake.numberErr = cause
	num, err = gr.ProjectNumber(context.Background())
	if err == nil || num != 0 || !errors.Is(err, cause) || !strings.Contains(err.Error(), `project "proj"`) {
		t.Errorf("ProjectNumber = %d, %v; want 0 and an error naming the project that wraps the cause", num, err)
	}
}

// TestEnsureRegistryNeverGrantsPush: the one policy write the adapter makes
// adds the node account to the pull role and nothing else, whatever the
// repository already grants; push access stays a human's grant.
func TestEnsureRegistryNeverGrantsPush(t *testing.T) {
	for name, pol := range map[string]iamPolicy{
		"an empty policy": {},
		"a policy granting push by hand": {Etag: "e", Version: 3, Bindings: []iamBinding{
			{Role: writerRole, Members: []string{uidMember}},
			{Role: pullRole, Members: []string{"user:auditor@example.com"}},
		}},
		"a policy holding the shared principal": {Etag: "e", Version: 3, Bindings: []iamBinding{
			{Role: writerRole, Members: []string{sharedMember}},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			api := &fakeRegistryClient{number: 42, policy: pol}
			p := newTestRegistryProvider(api)
			if _, err := p.EnsureRegistry(context.Background(), planck.RegistrySpec{Name: "demo"}); err != nil {
				t.Fatalf("EnsureRegistry: %v", err)
			}
			if len(api.setPolicies) != 1 {
				t.Fatalf("setPolicy called %d times, want 1", len(api.setPolicies))
			}
			want, _ := grantRole(pol, pullRole, nodeServiceAccountMember(42))
			if got := api.setPolicies[0]; !reflect.DeepEqual(got, want) {
				t.Errorf("the policy written is\n  %+v\nwant the read one with only the node account's pull grant added\n  %+v", got, want)
			}
			for _, b := range api.setPolicies[0].Bindings {
				if b.Role == pullRole {
					continue
				}
				var before []string
				for _, o := range pol.Bindings {
					if o.Role == b.Role {
						before = append(before, o.Members...)
					}
				}
				for _, m := range b.Members {
					if !slices.Contains(before, m) {
						t.Errorf("EnsureRegistry granted %s %s", b.Role, m)
					}
				}
			}
			for _, b := range api.setPolicies[0].Bindings {
				if b.Role != pullRole {
					continue
				}
				for _, m := range b.Members {
					if strings.HasPrefix(m, "principal://") {
						t.Errorf("EnsureRegistry granted pull to a workload principal, %s", m)
					}
				}
			}
		})
	}
}
