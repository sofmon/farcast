//go:build integration

// These tests drive the GCS adapter against a live Google Cloud project. They
// are excluded from normal builds and CI by the //go:build integration tag:
// they need real credentials and — for the lifecycle test — create a real
// bucket that bills real money. Run them deliberately.
//
// Credential check only (cheap, read-only — lists this project's farcast-*
// buckets and creates nothing):
//
//	FARCAST_GCS_TEST_PROJECT=my-proj \
//	FARCAST_GCS_TEST_CREDENTIALS=/path/to/sa-key.json \
//	go test -tags integration -run TestIntegrationValidate ./datasphere/internal/providers/gcs/
//
// Full ensure → put → list → get → rm → delete lifecycle (creates a bucket —
// extra opt-in):
//
//	FARCAST_GCS_TEST_PROJECT=my-proj \
//	FARCAST_GCS_TEST_CREDENTIALS=/path/to/sa-key.json \
//	FARCAST_GCS_TEST_LOCATION=europe-west1 \
//	FARCAST_GCS_TEST_BUCKET=1 \
//	go test -tags integration -timeout 15m -run TestIntegrationBucketLifecycle ./datasphere/internal/providers/gcs/
//
// With FARCAST_GCS_TEST_PROJECT unset the tests skip. When
// FARCAST_GCS_TEST_CREDENTIALS is omitted, Application Default Credentials are
// used. The service account needs bucket create/get/patch/delete and object
// CRUD — roles/storage.admin, granted (recommended) with an IAM condition
// scoping it to farcast-* bucket names, which is also the deployment this
// adapter's Validate is written for.
package gcs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/datasphere"
)

// testConfig builds a datasphere.Config from the FARCAST_GCS_TEST_*
// environment, skipping the test when no project is configured.
func testConfig(t *testing.T) datasphere.Config {
	t.Helper()
	project := os.Getenv("FARCAST_GCS_TEST_PROJECT")
	if project == "" {
		t.Skip("set FARCAST_GCS_TEST_PROJECT (and credentials) to run GCS integration tests")
	}
	cfg := datasphere.Config{
		Project:  project,
		Location: os.Getenv("FARCAST_GCS_TEST_LOCATION"),
	}
	if path := os.Getenv("FARCAST_GCS_TEST_CREDENTIALS"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read FARCAST_GCS_TEST_CREDENTIALS: %v", err)
		}
		cfg.Credentials = data
	}
	return cfg
}

// TestIntegrationValidate confirms the stored credentials reach the project's
// storage API. A zero BucketRef is the credentials-only probe: it lists at most
// one bucket name and creates nothing, so it is the right first check that auth
// is wired before anything billable is attempted.
func TestIntegrationValidate(t *testing.T) {
	p, err := New(testConfig(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := p.Validate(ctx, datasphere.BucketRef{}); err != nil {
		t.Fatalf("Validate against the live project: %v", err)
	}
}

// TestIntegrationBucketLifecycle runs the whole adapter against a real bucket:
// ensure → put → list → get → rm → re-ensure → delete. It is gated a second
// time behind FARCAST_GCS_TEST_BUCKET=1 because everything it touches bills.
//
// Three things can only be learned here, and they are the reason this test
// exists at all: that GCS returns custom metadata under the field mask List
// uses (see below), that the tokenized "/" separators survive the object URL
// path, and that a second EnsureBucket meets a real 409 and adopts.
func TestIntegrationBucketLifecycle(t *testing.T) {
	if os.Getenv("FARCAST_GCS_TEST_BUCKET") != "1" {
		t.Skip("set FARCAST_GCS_TEST_BUCKET=1 to run the ensure→delete bucket lifecycle (creates a real bucket)")
	}
	cfg := testConfig(t)
	if cfg.Location == "" {
		t.Skip("set FARCAST_GCS_TEST_LOCATION: EnsureBucket requires an explicit single region")
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	instance := fmt.Sprintf("it-%d", time.Now().Unix())
	// The name is minted the way production mints it rather than hand-written,
	// so this test can never collide with a real instance's bucket — and so the
	// mint rule itself is exercised against the cloud's own name validation.
	name, err := datasphere.MintBucketName(instance)
	if err != nil {
		t.Fatalf("MintBucketName(%q): %v", instance, err)
	}
	ref := datasphere.BucketRef{Name: name, Location: cfg.Location, Instance: instance}

	// Teardown is registered BEFORE the first create call, not deferred after a
	// successful ensure: a bucket leaked by a mid-test failure is billable
	// storage nobody is watching, holding ciphertext under a name that appears
	// in no record anywhere. An absent bucket is success, so this is harmless
	// after the test deletes the bucket itself.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if err := p.DeleteBucket(ctx, ref); err != nil && !errors.Is(err, datasphere.ErrRetentionForced) {
			t.Errorf("cleanup DeleteBucket(%q): %v — DELETE THIS BUCKET BY HAND", name, err)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	bucket, err := p.EnsureBucket(ctx, datasphere.BucketSpec{Name: name, Instance: instance, Location: cfg.Location})
	// ErrRetentionForced accompanies a usable bucket: an org policy forced soft
	// delete back on. The test carries on and says so, exactly as a caller must.
	if err != nil && !errors.Is(err, datasphere.ErrRetentionForced) {
		t.Fatalf("EnsureBucket(%q): %v", name, err)
	}
	if err != nil {
		t.Logf("retention notice on ensure: %v", err)
	}
	if bucket.Ref != ref {
		t.Errorf("ref = %+v, want %+v", bucket.Ref, ref)
	}

	// A populated ref proves the ownership labels actually landed on the cloud
	// resource. This is the check the composition root runs before it will
	// construct a Store, so a bucket that fails it is a bucket FarCast refuses
	// to write through.
	if err := p.Validate(ctx, ref); err != nil && !errors.Is(err, datasphere.ErrRetentionForced) {
		t.Fatalf("Validate(%+v) on the bucket we just created: %v", ref, err)
	}

	// Names arriving at the adapter are tokenized paths: fixed-width lowercase
	// hex segments joined by "/". The "/" is the named wire trap — it must be
	// percent-encoded in the URL path or it re-routes the request — so the
	// fixtures are shaped like the real thing rather than like "obj1".
	parent := strings.Repeat("a1", 16)
	first := parent + "/" + strings.Repeat("b2", 16)
	second := parent + "/" + strings.Repeat("c3", 16)
	elsewhere := strings.Repeat("d4", 16) + "/" + strings.Repeat("e5", 16)

	stored := map[string][]byte{
		first:     []byte("ciphertext-stand-in-one"),
		second:    []byte("ciphertext-stand-in-two"),
		elsewhere: []byte("ciphertext-stand-in-three"),
	}
	// The metadata mirror, as Store writes it: the base64 of the sealed logical
	// name under the one metadata key this module reserves.
	sealed := map[string]string{
		first:     "c2VhbGVkLW5hbWUtb25l",
		second:    "c2VhbGVkLW5hbWUtdHdv",
		elsewhere: "c2VhbGVkLW5hbWUtdGhyZWU=",
	}
	for objName, data := range stored {
		obj := datasphere.Object{
			Name: objName,
			Data: data,
			Meta: map[string]string{datasphere.MetaName: sealed[objName]},
		}
		if err := p.Put(ctx, name, obj); err != nil {
			t.Fatalf("Put(%s): %v", objName, err)
		}
	}

	infos, err := p.List(ctx, name, parent+"/")
	if err != nil {
		t.Fatalf("List(%s): %v", parent, err)
	}
	if len(infos) != 2 {
		t.Fatalf("List under one token prefix returned %d objects, want the 2 sharing it: %+v", len(infos), infos)
	}
	for _, info := range infos {
		want, ok := stored[info.Name]
		if !ok {
			t.Fatalf("List returned an unexpected object %q", info.Name)
		}
		if info.Size != int64(len(want)) {
			t.Errorf("List size of %s = %d, want %d", info.Name, info.Size, len(want))
		}
		// THE UNPROVEN WIRE ASSUMPTION — this is the assertion the whole gated
		// suite is worth running for. The adapter lists with
		// fields=items(name,size,metadata),nextPageToken and the encrypting
		// layer reads each object's sealed logical name straight out of that
		// metadata map. No unit test can settle whether GCS actually returns
		// custom metadata under that mask, because a fake RoundTripper answers
		// whatever it is told to.
		//
		// If this fails, Store.List degrades to one full object download per
		// listed object — the metadata mirror stops paying for itself and the
		// README's "one list call per page" cost claim is wrong. Read a failure
		// here as "the cost model must be rewritten", never as flakiness.
		if got := info.Meta[datasphere.MetaName]; got != sealed[info.Name] {
			t.Errorf("List metadata %s of %s = %q, want %q: custom metadata did NOT come back in the default list projection — Store.List now costs one Get per object",
				datasphere.MetaName, info.Name, got, sealed[info.Name])
		}
	}

	got, err := p.Get(ctx, name, first)
	if err != nil {
		t.Fatalf("Get(%s): %v", first, err)
	}
	if string(got.Data) != string(stored[first]) {
		t.Errorf("Get(%s) data = %q, want %q", first, got.Data, stored[first])
	}
	// The X-Goog-Meta-* mirror on an alt=media download is best-effort by
	// design: nothing depends on it, because a listing supplies names and a
	// blob's own header is the authoritative copy.
	//
	// MEASURED 2026-08-27 against real GCS: the JSON API does NOT return
	// custom metadata as X-Goog-Meta-* headers on alt=media — Get.Meta comes
	// back empty, every time. That is the answer, not a fault, which is why
	// this is recorded rather than asserted: failing the suite over documented
	// best-effort behaviour would report a problem where there is none. What
	// would be worth noticing is the service silently starting to send them,
	// so the observation is logged either way.
	if meta := got.Meta[datasphere.MetaName]; meta == sealed[first] {
		t.Logf("Get(%s): the service DID return the sealed name in X-Goog-Meta-*; it did not when this was last measured", first)
	} else {
		t.Logf("Get(%s): no X-Goog-Meta-* custom metadata on the media download (Meta=%v) — expected, and nothing depends on it", first, got.Meta)
	}

	if _, err := p.Get(ctx, name, parent+"/"+strings.Repeat("ff", 16)); !errors.Is(err, datasphere.ErrObjectNotFound) {
		t.Errorf("Get of an absent object = %v, want ErrObjectNotFound", err)
	}

	for objName := range stored {
		if err := p.Delete(ctx, name, objName); err != nil {
			t.Fatalf("Delete(%s): %v", objName, err)
		}
	}
	// Deleting an absent object is success — teardown and re-runs have to
	// converge, and the bucket drain relies on it.
	if err := p.Delete(ctx, name, first); err != nil {
		t.Errorf("Delete of an already-deleted object: %v", err)
	}
	rest, err := p.List(ctx, name, "")
	if err != nil {
		t.Fatalf("List after deletes: %v", err)
	}
	if len(rest) != 0 {
		t.Errorf("List after deletes returned %d objects, want none: %+v", len(rest), rest)
	}

	// Re-ensure before the delete. This is the only place the adopt path meets a
	// REAL 409 from the service rather than a fake one, and every storage
	// command ensures defensively, so a re-ensure that failed would break every
	// second command an operator ran.
	again, err := p.EnsureBucket(ctx, datasphere.BucketSpec{Name: name, Instance: instance, Location: cfg.Location})
	if err != nil && !errors.Is(err, datasphere.ErrRetentionForced) {
		t.Fatalf("second EnsureBucket (idempotence, adopting on 409): %v", err)
	}
	if again.Ref != ref {
		t.Errorf("re-ensure ref = %+v, want %+v", again.Ref, ref)
	}

	if err := p.DeleteBucket(ctx, ref); err != nil && !errors.Is(err, datasphere.ErrRetentionForced) {
		t.Fatalf("DeleteBucket(%q): %v", name, err)
	} else if err != nil {
		// The operator is owed this before any record is cleared: the bucket is
		// gone and its ciphertext is still held and billed.
		t.Logf("retention notice on teardown: %v", err)
	}
	// An absent bucket is success, so `farcast release` converges on a re-run.
	if err := p.DeleteBucket(ctx, ref); err != nil {
		t.Errorf("DeleteBucket on an absent bucket: %v", err)
	}
}
