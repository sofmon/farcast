package gcs

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/sofmon/farcast/datasphere"
)

// Bucket lifecycle on the wire. Two things are being pinned here and they are
// not the same thing: the exact create body (a posture field silently dropped
// is a bucket that is public-capable, versioned, or retaining deleted
// ciphertext, and nothing downstream would ever notice), and the three-way
// conflict split (whose failure mode is either adopting a stranger's bucket or
// orphaning the operator's own billable one).

// ownedBucket is the buckets.get response for a bucket FarCast created: both
// ownership labels and the full hardened posture. The location comes back
// uppercase, as GCS renders it, which is also why the posture comparison must
// be case-insensitive.
func ownedBucket(retentionSeconds string) string {
	return fmt.Sprintf(`{
		"name": %q,
		"location": "EUROPE-WEST1",
		"storageClass": "STANDARD",
		"labels": {"managed-by": "farcast", "farcast-instance": %q},
		"iamConfiguration": {
			"uniformBucketLevelAccess": {"enabled": true},
			"publicAccessPrevention": "enforced"
		},
		"versioning": {"enabled": false},
		"softDeletePolicy": {"retentionDurationSeconds": %q}
	}`, testBucket, testInstance, retentionSeconds)
}

func testSpec() datasphere.BucketSpec {
	return datasphere.BucketSpec{Name: testBucket, Instance: testInstance, Location: testLocation}
}

func testRef() datasphere.BucketRef {
	return datasphere.BucketRef{Name: testBucket, Instance: testInstance, Location: testLocation}
}

// conflict is the 409 buckets.insert answers when the name is taken — by a
// prior attempt of our own, or by a stranger. Which one it is, is precisely
// what the adapter must not guess.
func conflict() *http.Response {
	return errorReply(http.StatusConflict, "CONFLICT", "Your previous request to create the named bucket succeeded and you already own it.")
}

// TestEnsureBucketInsertRequest pins the create call field by field. Every one
// of these is spec-mandated posture rather than adapter discretion, and a
// dropped field fails open: no error, no symptom, just a bucket that is
// weaker, more expensive, or unattributable than the spec promises.
func TestEnsureBucketInsertRequest(t *testing.T) {
	p, fake := newTestProvider(t, jsonReply(http.StatusOK, ownedBucket("0")))

	b, err := p.EnsureBucket(context.Background(), testSpec())
	if err != nil {
		t.Fatalf("EnsureBucket: %v", err)
	}
	if b == nil || b.Ref != testRef() {
		t.Fatalf("bucket = %+v, want the ref the caller recorded (%+v)", b, testRef())
	}

	if n := fake.count(); n != 1 {
		t.Fatalf("made %d requests, want exactly the insert: %v", n, fake.trace())
	}
	req := fake.request(t, 0)
	if req.method != http.MethodPost {
		t.Errorf("method = %s, want POST", req.method)
	}
	// buckets.insert takes the project in the query, not the body.
	want := jsonAPIBase + "b?project=" + testProject
	if req.url != want {
		t.Errorf("url = %q, want %q", req.url, want)
	}
	if got := req.header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}

	for _, tc := range []struct {
		path []string
		want any
	}{
		{[]string{"name"}, testBucket},
		{[]string{"location"}, testLocation},
		{[]string{"storageClass"}, storageClassStandard},
		{[]string{"labels", labelManagedBy}, labelManagedByValue},
		{[]string{"labels", labelInstance}, testInstance},
		{[]string{"iamConfiguration", "uniformBucketLevelAccess", "enabled"}, true},
		{[]string{"iamConfiguration", "publicAccessPrevention"}, publicAccessPrevention},
		{[]string{"versioning", "enabled"}, false},
		// A JSON *string*: the API renders this int64 as a string, and sending
		// a number is rejected outright. Asserting the type here is not
		// pedantry — it is the difference between soft delete off and a create
		// that fails at 3am.
		{[]string{"softDeletePolicy", "retentionDurationSeconds"}, "0"},
	} {
		if got := jsonField(t, req.body, tc.path...); got != tc.want {
			t.Errorf("body %v = %#v, want %#v", tc.path, got, tc.want)
		}
	}
}

// TestEnsureBucketOwnershipLabelsCannotBeOverridden matters because the labels
// are the whole ownership proof: a caller that could set farcast-instance
// could make DeleteBucket agree to destroy somebody else's bucket.
func TestEnsureBucketOwnershipLabelsCannotBeOverridden(t *testing.T) {
	p, fake := newTestProvider(t, jsonReply(http.StatusOK, ownedBucket("0")))

	spec := testSpec()
	spec.Labels = map[string]string{
		labelManagedBy: "someone-else",
		labelInstance:  "someone-elses-instance",
		"cost-centre":  "research",
	}
	if _, err := p.EnsureBucket(context.Background(), spec); err != nil {
		t.Fatalf("EnsureBucket: %v", err)
	}

	labels, ok := jsonField(t, fake.request(t, 0).body, "labels").(map[string]any)
	if !ok {
		t.Fatalf("labels are not a JSON object; body = %s", fake.request(t, 0).body)
	}
	if got := labels[labelManagedBy]; got != labelManagedByValue {
		t.Errorf("%s = %v, want %q — a caller must not be able to override it", labelManagedBy, got, labelManagedByValue)
	}
	if got := labels[labelInstance]; got != testInstance {
		t.Errorf("%s = %v, want %q — a caller must not be able to override it", labelInstance, got, testInstance)
	}
	if got := labels["cost-centre"]; got != "research" {
		t.Errorf("cost-centre = %v, want the caller's extra label merged through", got)
	}
}

// TestEnsureBucketRejectsIncompleteSpecs checks the refusals happen before any
// request: the adapter never mints a name, so an empty one is the caller's bug
// and must not become a cloud call.
func TestEnsureBucketRejectsIncompleteSpecs(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec datasphere.BucketSpec
	}{
		{"no name", datasphere.BucketSpec{Instance: testInstance, Location: testLocation}},
		{"no instance", datasphere.BucketSpec{Name: testBucket, Location: testLocation}},
		{"no location", datasphere.BucketSpec{Name: testBucket, Instance: testInstance}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, fake := newTestProvider(t)
			if _, err := p.EnsureBucket(context.Background(), tc.spec); err == nil {
				t.Fatal("expected a refusal")
			}
			if n := fake.count(); n != 0 {
				t.Errorf("made %d requests, want none: %v", n, fake.trace())
			}
		})
	}
}

// TestEnsureBucketConflictAdoptsOurOwn is split (1): the inspection succeeds
// and both labels are ours, so the 409 is our own prior attempt. Ensure is
// idempotent — the defensive ensure on every storage path depends on it.
func TestEnsureBucketConflictAdoptsOurOwn(t *testing.T) {
	p, fake := newTestProvider(t, conflict(), jsonReply(http.StatusOK, ownedBucket("0")))

	b, err := p.EnsureBucket(context.Background(), testSpec())
	if err != nil {
		t.Fatalf("an existing FarCast bucket must not fail an ensure: %v", err)
	}
	if b == nil || b.Ref != testRef() {
		t.Fatalf("bucket = %+v, want the adopted ref %+v", b, testRef())
	}

	// Exactly one insert and one inspect. A second insert would mean the
	// adapter had tried a different name, which is the record owner's job.
	want := []string{
		"POST /storage/v1/b",
		"GET /storage/v1/b/" + testBucket,
	}
	if got := fake.trace(); !slices.Equal(got, want) {
		t.Errorf("calls = %v, want %v", got, want)
	}
}

// TestEnsureBucketConflictRefusesAProvenForeignBucket is split (2): the
// inspection succeeded and PROVED the bucket is somebody else's. This is the
// only branch that may return ErrNotOwned, because it is the only one holding
// proof.
func TestEnsureBucketConflictRefusesAProvenForeignBucket(t *testing.T) {
	foreign := fmt.Sprintf(`{"name":%q,"location":"EUROPE-WEST1","labels":{"managed-by":"farcast","farcast-instance":"someone-else"}}`, testBucket)
	p, _ := newTestProvider(t, conflict(), jsonReply(http.StatusOK, foreign))

	b, err := p.EnsureBucket(context.Background(), testSpec())
	if !errors.Is(err, datasphere.ErrNotOwned) {
		t.Fatalf("err = %v, want ErrNotOwned", err)
	}
	if b != nil {
		t.Errorf("bucket = %+v, want nothing adopted", b)
	}
	// An operator reading the refusal needs to know which half was wrong.
	for _, want := range []string{testBucket, labelInstance, "someone-else", testInstance} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to name %q", err, want)
		}
	}
}

// TestEnsureBucketConflictUnavailableInspectionIsNotProof is split (3), and it
// is the branch that matters most. A 5xx after the adapter's retries means the
// bucket could not be inspected — not that it is foreign. Returning ErrNotOwned
// here would tell the record-owning caller to mint a new name, orphaning an
// owned, billable bucket behind a name that now exists nowhere.
func TestEnsureBucketConflictUnavailableInspectionIsNotProof(t *testing.T) {
	replies := append([]*http.Response{conflict()}, repeatReply(maxAttempts, func() *http.Response {
		return errorReply(http.StatusServiceUnavailable, "UNAVAILABLE", "backend error")
	})...)
	p, fake := newTestProvider(t, replies...)

	b, err := p.EnsureBucket(context.Background(), testSpec())
	if err == nil {
		t.Fatal("expected an error when the bucket could not be inspected")
	}
	if errors.Is(err, datasphere.ErrNotOwned) {
		t.Fatalf("err = %v, want a PLAIN error: could-not-inspect is not proof of foreign ownership, and treating it as proof orphans an owned billable bucket", err)
	}
	if b != nil {
		t.Errorf("bucket = %+v, want nothing adopted", b)
	}
	if !strings.Contains(err.Error(), testBucket) {
		t.Errorf("err = %v, want it to name the bucket", err)
	}
	// The retries happened, and only then did it give up.
	if n := fake.count(); n != 1+maxAttempts {
		t.Errorf("made %d requests, want 1 insert plus %d inspect attempts: %v", n, maxAttempts, fake.trace())
	}
}

// TestEnsureBucketConflictForbiddenInspectionIsNotProof is split (3) again,
// through the door it actually comes through in practice: on GCS a foreign
// bucket answers 403 — and so does a bucket we created moments ago while IAM
// propagates. A persistent 403 on a recorded name is overwhelmingly our own
// bucket or a credential problem, since a squatter would have had to guess 32
// random bits that never left this machine.
func TestEnsureBucketConflictForbiddenInspectionIsNotProof(t *testing.T) {
	p, fake := newTestProvider(t, conflict(),
		errorReply(http.StatusForbidden, "PERMISSION_DENIED", "does not have storage.buckets.get access"))

	b, err := p.EnsureBucket(context.Background(), testSpec())
	if err == nil {
		t.Fatal("expected an error when the inspection is forbidden")
	}
	if errors.Is(err, datasphere.ErrNotOwned) {
		t.Fatalf("err = %v, want a PLAIN error: a 403 is could-not-inspect, not proven-foreign", err)
	}
	if b != nil {
		t.Errorf("bucket = %+v, want nothing adopted", b)
	}
	if !strings.Contains(err.Error(), testBucket) {
		t.Errorf("err = %v, want it to name the bucket the operator has to go look at", err)
	}
	// 403 is about the request, not the server: it must not be retried.
	if n := fake.count(); n != 2 {
		t.Errorf("made %d requests, want insert + one inspect: %v", n, fake.trace())
	}
}

// TestEnsureBucketConflictPostureMismatchIsNotAdopted covers the case where
// the labels match but the bucket is not one FarCast created — or is no longer
// the bucket FarCast created. It is a reason to look, not proof of a foreign
// owner, so it is a plain error and the caller keeps its record.
func TestEnsureBucketConflictPostureMismatchIsNotAdopted(t *testing.T) {
	labels := fmt.Sprintf(`"labels":{"managed-by":"farcast","farcast-instance":%q}`, testInstance)
	for _, tc := range []struct {
		name  string
		reply string
		want  string
	}{
		{
			"uniform bucket-level access off",
			fmt.Sprintf(`{"location":"EUROPE-WEST1",%s,"iamConfiguration":{"uniformBucketLevelAccess":{"enabled":false},"publicAccessPrevention":"enforced"}}`, labels),
			"uniform bucket-level access",
		},
		{
			"public access prevention not enforced",
			fmt.Sprintf(`{"location":"EUROPE-WEST1",%s,"iamConfiguration":{"uniformBucketLevelAccess":{"enabled":true},"publicAccessPrevention":"inherited"}}`, labels),
			"public access prevention",
		},
		{
			"different location",
			fmt.Sprintf(`{"location":"US-CENTRAL1",%s,"iamConfiguration":{"uniformBucketLevelAccess":{"enabled":true},"publicAccessPrevention":"enforced"}}`, labels),
			"location",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := newTestProvider(t, conflict(), jsonReply(http.StatusOK, tc.reply))

			b, err := p.EnsureBucket(context.Background(), testSpec())
			if err == nil {
				t.Fatal("adopted a bucket that does not carry FarCast's posture")
			}
			if errors.Is(err, datasphere.ErrNotOwned) {
				t.Fatalf("err = %v, want a plain error: a posture mismatch is a reason to look, not proof of foreign ownership", err)
			}
			if b != nil {
				t.Errorf("bucket = %+v, want nothing adopted", b)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to name what differs (%q)", err, tc.want)
			}
		})
	}
}

// TestEnsureBucketReadsBackForcedRetention is the "success carrying a notice"
// contract, and it is easy to break in either direction: dropping the notice
// hides ciphertext the cloud is holding and billing for, and dropping the
// Bucket makes an ensure that actually succeeded look like a failure.
func TestEnsureBucketReadsBackForcedRetention(t *testing.T) {
	p, _ := newTestProvider(t, jsonReply(http.StatusOK, ownedBucket("604800")))

	b, err := p.EnsureBucket(context.Background(), testSpec())
	if !errors.Is(err, datasphere.ErrRetentionForced) {
		t.Fatalf("err = %v, want ErrRetentionForced when an org policy forced soft delete back on", err)
	}
	if b == nil {
		t.Fatal("bucket = nil, want a usable bucket alongside the notice")
	}
	if b.Ref != testRef() {
		t.Errorf("ref = %+v, want the usable ref %+v", b.Ref, testRef())
	}
	// The operator has to be able to tell how long the retained copies bill.
	if !strings.Contains(err.Error(), "168h0m0s") || !strings.Contains(err.Error(), testBucket) {
		t.Errorf("err = %v, want it to name the bucket and the retention window", err)
	}
}

// TestEnsureBucketAdoptionCarriesForcedRetention: the notice is owed on the
// adoption path too — a re-ensure is where an org policy change is most likely
// to be noticed at all.
func TestEnsureBucketAdoptionCarriesForcedRetention(t *testing.T) {
	p, _ := newTestProvider(t, conflict(), jsonReply(http.StatusOK, ownedBucket("604800")))

	b, err := p.EnsureBucket(context.Background(), testSpec())
	if !errors.Is(err, datasphere.ErrRetentionForced) {
		t.Fatalf("err = %v, want ErrRetentionForced", err)
	}
	if b == nil || b.Ref != testRef() {
		t.Fatalf("bucket = %+v, want the adopted bucket to remain usable", b)
	}
}

// TestDeleteBucketRefusesAMismatchedInstance is the check that stands between
// `farcast release` and a stranger's data. The bucket name is not invertible
// to the instance, so the instance arrives from the caller's record — and if
// it does not match, nothing may be destroyed.
func TestDeleteBucketRefusesAMismatchedInstance(t *testing.T) {
	foreign := fmt.Sprintf(`{"name":%q,"labels":{"managed-by":"farcast","farcast-instance":"other-instance"}}`, testBucket)
	p, fake := newTestProvider(t, jsonReply(http.StatusOK, foreign))

	err := p.DeleteBucket(context.Background(), testRef())
	if !errors.Is(err, datasphere.ErrNotOwned) {
		t.Fatalf("err = %v, want ErrNotOwned", err)
	}
	if !strings.Contains(err.Error(), "other-instance") {
		t.Errorf("err = %v, want it to name what differs", err)
	}
	for _, call := range fake.trace() {
		if strings.HasPrefix(call, http.MethodDelete+" ") {
			t.Fatalf("issued %q — a refused ownership check must destroy nothing", call)
		}
	}
	if n := fake.count(); n != 1 {
		t.Errorf("made %d requests, want only the inspect: %v", n, fake.trace())
	}
}

// TestDeleteBucketRejectsAnIncompleteRef: the instance is not optional on the
// path that destroys data, and the refusal must precede the wire.
func TestDeleteBucketRejectsAnIncompleteRef(t *testing.T) {
	for _, tc := range []struct {
		name string
		ref  datasphere.BucketRef
	}{
		{"no name", datasphere.BucketRef{Instance: testInstance}},
		{"no instance", datasphere.BucketRef{Name: testBucket}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, fake := newTestProvider(t)
			if err := p.DeleteBucket(context.Background(), tc.ref); err == nil {
				t.Fatal("expected a refusal")
			}
			if n := fake.count(); n != 0 {
				t.Errorf("made %d requests, want none: %v", n, fake.trace())
			}
		})
	}
}

// TestDeleteBucketAbsentIsSuccess: teardown has to converge on a re-run, and a
// bucket that is already gone is the outcome that was wanted.
func TestDeleteBucketAbsentIsSuccess(t *testing.T) {
	p, fake := newTestProvider(t, errorReply(http.StatusNotFound, "NOT_FOUND", "The specified bucket does not exist."))

	if err := p.DeleteBucket(context.Background(), testRef()); err != nil {
		t.Fatalf("deleting an absent bucket must succeed: %v", err)
	}
	want := []string{"GET /storage/v1/b/" + testBucket}
	if got := fake.trace(); !slices.Equal(got, want) {
		t.Errorf("calls = %v, want %v", got, want)
	}
}

// TestDeleteBucketOrdering pins the sequence, which is load-bearing rather
// than incidental: already-soft-deleted objects retain under the policy in
// force at the moment of THEIR deletion, so resetting the retention window
// after the objects are gone is too late for every one of them. Ownership
// first (nothing is destroyed until it is proved ours), then the reset, then
// the drain, then the bucket.
func TestDeleteBucketOrdering(t *testing.T) {
	p, fake := newTestProvider(t,
		jsonReply(http.StatusOK, ownedBucket("604800")),
		jsonReply(http.StatusOK, ownedBucket("0")),
		jsonReply(http.StatusOK, fmt.Sprintf(`{"items":[{"name":%q}]}`, storedName)),
		jsonReply(http.StatusNoContent, ``),
		jsonReply(http.StatusOK, `{"items":[]}`),
		jsonReply(http.StatusNoContent, ``),
	)

	if err := p.DeleteBucket(context.Background(), testRef()); err != nil {
		t.Fatalf("DeleteBucket: %v", err)
	}

	want := []string{
		"GET /storage/v1/b/" + testBucket,
		"PATCH /storage/v1/b/" + testBucket,
		"GET /storage/v1/b/" + testBucket + "/o",
		"DELETE /storage/v1/b/" + testBucket + "/o/" + strings.ReplaceAll(storedName, "/", "%2F"),
		"GET /storage/v1/b/" + testBucket + "/o",
		"DELETE /storage/v1/b/" + testBucket,
	}
	if got := fake.trace(); !slices.Equal(got, want) {
		t.Fatalf("calls =\n  %v\nwant\n  %v", got, want)
	}
	if got := jsonField(t, fake.request(t, 1).body, "softDeletePolicy", "retentionDurationSeconds"); got != "0" {
		t.Errorf("patch body retention = %#v, want the string \"0\"", got)
	}
}

// TestDeleteBucketSkipsThePatchWhenRetentionIsAlreadyZero: the reset exists to
// undo an org policy, not as a ritual.
func TestDeleteBucketSkipsThePatchWhenRetentionIsAlreadyZero(t *testing.T) {
	p, fake := newTestProvider(t,
		jsonReply(http.StatusOK, ownedBucket("0")),
		jsonReply(http.StatusOK, `{"items":[]}`),
		jsonReply(http.StatusNoContent, ``),
	)

	if err := p.DeleteBucket(context.Background(), testRef()); err != nil {
		t.Fatalf("DeleteBucket: %v", err)
	}
	for _, call := range fake.trace() {
		if strings.HasPrefix(call, http.MethodPatch+" ") {
			t.Errorf("issued %q, want no reset when soft delete is already off", call)
		}
	}
}

// TestDeleteBucketSurfacesARefusedRetentionReset: an org policy can refuse the
// reset. The teardown still completes — leaving a billable bucket behind would
// be strictly worse — but the operator must be told, before the record is
// cleared, that deleted ciphertext is still held and still billing.
func TestDeleteBucketSurfacesARefusedRetentionReset(t *testing.T) {
	const singleToken = "6f1a9c2233445566778899aabbccddee"
	p, fake := newTestProvider(t,
		jsonReply(http.StatusOK, ownedBucket("604800")),
		errorReply(http.StatusForbidden, "PERMISSION_DENIED", "constraints/storage.softDeletePolicySeconds"),
		jsonReply(http.StatusOK, fmt.Sprintf(`{"items":[{"name":%q}]}`, singleToken)),
		jsonReply(http.StatusNoContent, ``),
		jsonReply(http.StatusOK, `{"items":[]}`),
		jsonReply(http.StatusNoContent, ``),
	)

	err := p.DeleteBucket(context.Background(), testRef())
	if !errors.Is(err, datasphere.ErrRetentionForced) {
		t.Fatalf("err = %v, want ErrRetentionForced", err)
	}
	for _, want := range []string{testBucket, "168h0m0s"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to name %q", err, want)
		}
	}
	// The objects and the bucket are still gone: the notice accompanies a
	// completed teardown, it does not replace one.
	want := []string{
		"GET /storage/v1/b/" + testBucket,
		"PATCH /storage/v1/b/" + testBucket,
		"GET /storage/v1/b/" + testBucket + "/o",
		"DELETE /storage/v1/b/" + testBucket + "/o/" + singleToken,
		"GET /storage/v1/b/" + testBucket + "/o",
		"DELETE /storage/v1/b/" + testBucket,
	}
	if got := fake.trace(); !slices.Equal(got, want) {
		t.Errorf("calls =\n  %v\nwant\n  %v", got, want)
	}
}

// TestDeleteBucketConflictIsNeverSuccess: GCS has no force-delete, so a 409
// from buckets.delete means the bucket is not empty and still exists. Reading
// it as "already gone" would clear the local record and leave billable storage
// with nobody watching it.
func TestDeleteBucketConflictIsNeverSuccess(t *testing.T) {
	p, _ := newTestProvider(t,
		jsonReply(http.StatusOK, ownedBucket("0")),
		jsonReply(http.StatusOK, `{"items":[]}`),
		errorReply(http.StatusConflict, "CONFLICT", "The bucket you tried to delete is not empty."),
	)

	err := p.DeleteBucket(context.Background(), testRef())
	if err == nil {
		t.Fatal("a 409 from buckets.delete must never be reported as success")
	}
	if errors.Is(err, datasphere.ErrRetentionForced) {
		t.Errorf("err = %v, want a failure, not a success-with-notice", err)
	}
	if !strings.Contains(err.Error(), testBucket) {
		t.Errorf("err = %v, want it to name the bucket", err)
	}
}

// TestValidateCredentialsProbe: a zero ref has no bucket to look at, so the
// probe lists this project's FarCast buckets — cheap, read-only, creating
// nothing.
func TestValidateCredentialsProbe(t *testing.T) {
	p, fake := newTestProvider(t, jsonReply(http.StatusOK, `{"items":[]}`))

	if err := p.Validate(context.Background(), datasphere.BucketRef{}); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	req := fake.request(t, 0)
	if req.method != http.MethodGet {
		t.Errorf("method = %s, want GET", req.method)
	}
	q := req.query(t)
	for _, tc := range []struct{ key, want string }{
		{"project", testProject},
		{"prefix", bucketNamePrefix},
		{"maxResults", "1"},
		{"fields", "items(name)"},
	} {
		if got := q.Get(tc.key); got != tc.want {
			t.Errorf("query %s = %q, want %q", tc.key, got, tc.want)
		}
	}
}

// TestValidateBucketRefChecksOwnership is the enforcement point for the write
// path: the composition root runs it before constructing a Store, so even
// tampered local metadata cannot point writes at a stranger's bucket.
func TestValidateBucketRefChecksOwnership(t *testing.T) {
	t.Run("ours", func(t *testing.T) {
		p, fake := newTestProvider(t, jsonReply(http.StatusOK, ownedBucket("0")))
		if err := p.Validate(context.Background(), testRef()); err != nil {
			t.Fatalf("Validate: %v", err)
		}
		// One read of the named bucket — not a project-wide listing, which a
		// credential scoped by IAM condition to farcast-* may not be allowed.
		want := []string{"GET /storage/v1/b/" + testBucket}
		if got := fake.trace(); !slices.Equal(got, want) {
			t.Errorf("calls = %v, want %v", got, want)
		}
	})

	t.Run("foreign", func(t *testing.T) {
		foreign := fmt.Sprintf(`{"name":%q,"labels":{"managed-by":"someone-else"}}`, testBucket)
		p, _ := newTestProvider(t, jsonReply(http.StatusOK, foreign))
		if err := p.Validate(context.Background(), testRef()); !errors.Is(err, datasphere.ErrNotOwned) {
			t.Fatalf("err = %v, want ErrNotOwned", err)
		}
	})

	t.Run("no instance", func(t *testing.T) {
		p, fake := newTestProvider(t)
		// The bucket name is not invertible to the instance, so an ownership
		// check without one would be no check at all.
		if err := p.Validate(context.Background(), datasphere.BucketRef{Name: testBucket}); err == nil {
			t.Fatal("expected a refusal")
		}
		if n := fake.count(); n != 0 {
			t.Errorf("made %d requests, want none: %v", n, fake.trace())
		}
	})

	// Validate is the enforcement point the composition root runs BEFORE
	// constructing a Store, so it has to be a plain yes or no. A forced
	// retention window is a warning, and a warning delivered here would become
	// a total storage outage in the hands of any caller that treats a
	// Validate error as fatal — which is the only sane way to treat one. The
	// window is still reported, on the paths where a caller can act on it and
	// where mistaking it for a failure is harmless: EnsureBucket and
	// DeleteBucket.
	t.Run("a forced retention window does not fail validation", func(t *testing.T) {
		p, _ := newTestProvider(t, jsonReply(http.StatusOK, ownedBucket("604800")))
		if err := p.Validate(context.Background(), testRef()); err != nil {
			t.Fatalf("Validate = %v, want nil: a retention warning must not block Store construction", err)
		}
	})
}
