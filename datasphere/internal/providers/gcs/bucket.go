package gcs

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sofmon/farcast/datasphere"
)

// Bucket lifecycle, and the ownership discipline that makes it safe.
//
// GCS bucket names are globally unique across all of Google Cloud — a
// namespace shared with every stranger on the platform. That inverts the
// presumption Planck's per-project registry could afford: here, every
// unrecorded collision is hostile until proven otherwise, and "proven" is a
// word this file takes literally.

// maxDeleteSweeps bounds the object-drain loop in DeleteBucket. Strong
// read-after-write means one sweep normally suffices; the bound exists so that
// a cloud re-serving deleted objects turns into a clear error instead of a
// teardown that never returns.
const maxDeleteSweeps = 100

// Validate confirms the configured credentials are usable, and — given a
// populated ref — that the named bucket is this instance's. It returns a plain
// yes or no: a caller may safely treat any error from it as fatal.
//
// The two probes are deliberately different calls. A zero ref has no bucket to
// look at, so it lists this project's FarCast buckets: cheap, read-only, and
// creating nothing. A populated ref reads that one bucket instead, which
// exercises the credentials end-to-end just as well while also proving
// ownership. Making the populated case do both would break exactly the
// deployment the spec recommends — a credential scoped by IAM condition to
// farcast-* buckets, which may hold no project-wide list permission at all.
func (p *provider) Validate(ctx context.Context, ref datasphere.BucketRef) error {
	if ref.Name == "" {
		query := url.Values{
			"project":    {p.cfg.Project},
			"prefix":     {bucketNamePrefix},
			"maxResults": {"1"},
			"fields":     {"items(name)"},
		}
		if err := p.doJSON(ctx, http.MethodGet, p.base+"b?"+query.Encode(), nil, nil); err != nil {
			return fmt.Errorf("gcs: validate credentials: %w", err)
		}
		return nil
	}
	if ref.Instance == "" {
		return errors.New("gcs: BucketRef.Instance is required: a bucket name is not invertible to the instance it belongs to")
	}
	b, err := p.getBucket(ctx, ref.Name)
	if isHTTPStatus(err, http.StatusNotFound) {
		// Proven absent, not merely unreachable. Reported as its own sentinel so
		// a teardown can tell the two apart: there is nothing here to write to,
		// nothing to count, and nothing to delete.
		return fmt.Errorf("%w: %s", datasphere.ErrBucketNotFound, ref.Name)
	}
	if err != nil {
		return fmt.Errorf("gcs: inspect bucket %q: %w", ref.Name, err)
	}
	if err := verifyOwned(b, ref.Name, ref.Instance); err != nil {
		return err
	}
	// Deliberately NOT the place to raise a forced retention window, even
	// though this call has just read the policy. ErrRetentionForced is safe to
	// return alongside a successful EnsureBucket or DeleteBucket precisely
	// because a caller that fails to classify it retries an idempotent
	// operation. That argument collapses here: the composition root runs
	// Validate before constructing a Store, so a caller that treats any error
	// as fatal turns an org-policy warning into a total storage outage. Nothing
	// is lost by staying silent — every storage path ensures defensively, and
	// EnsureBucket reports the window on the same read.
	return nil
}

// EnsureBucket idempotently creates the instance's bucket with FarCast's
// ownership labels and hardened posture.
//
// It never mints a name and never retries under a different one. The name
// arrives already recorded in the instance's local metadata — the record is
// written before the create, because the bucket's random suffix exists nowhere
// else and an unrecorded bucket is billable storage nobody is watching — and
// the mint-new-suffix/update-record/retry loop belongs to whoever owns that
// record, never to the adapter.
//
// A non-nil Bucket may be returned alongside an error wrapping
// ErrRetentionForced: the bucket is usable, and the caller owes the operator
// the notice.
func (p *provider) EnsureBucket(ctx context.Context, spec datasphere.BucketSpec) (*datasphere.Bucket, error) {
	switch {
	case spec.Name == "":
		return nil, errors.New("gcs: a bucket name is required; the caller mints and records it before ensuring")
	case spec.Instance == "":
		return nil, errors.New("gcs: an instance name is required; it is stamped into the ownership labels")
	case spec.Location == "":
		return nil, errors.New("gcs: a location is required")
	}

	body := bucketResource{
		Name:         spec.Name,
		Location:     spec.Location,
		StorageClass: storageClassStandard,
		Labels:       ownershipLabels(spec.Instance, spec.Labels),
		IAMConfiguration: &iamConfiguration{
			UniformBucketLevelAccess: &uniformBucketLevelAccess{Enabled: true},
			PublicAccessPrevention:   publicAccessPrevention,
		},
		// Versioning off and soft delete disabled are cost and privacy
		// decisions in one: GCS's 7-day soft-delete default both bills for
		// retained copies of deleted ciphertext and retains data the operator
		// ordered destroyed. Consequence, stated plainly: deletes are immediate
		// and final.
		Versioning:       &versioning{Enabled: false},
		SoftDeletePolicy: &softDeletePolicy{RetentionDurationSeconds: "0"},
	}

	var created bucketResource
	err := p.doJSON(ctx, http.MethodPost, p.base+"b?"+url.Values{"project": {p.cfg.Project}}.Encode(), body, &created)
	switch {
	case err == nil:
		// The insert response is the stored resource, so it is also the
		// read-back that catches an org policy forcing soft delete on.
		return &datasphere.Bucket{Ref: refFor(spec)}, retentionNotice(&created, spec.Name)
	case isHTTPStatus(err, http.StatusConflict):
		return p.adoptBucket(ctx, spec)
	default:
		return nil, fmt.Errorf("gcs: create bucket %q: %w", spec.Name, err)
	}
}

// adoptBucket resolves a name conflict, and it is the three-way split the
// whole ownership design turns on:
//
//  1. The inspection succeeds and both labels are ours — this is our own prior
//     attempt, so adopt it.
//  2. The inspection succeeds and PROVES the bucket is not ours — ErrNotOwned.
//  3. The inspection merely FAILS — a plain error, never ErrNotOwned, and the
//     caller's record stays untouched.
//
// The third case is the one that is easy to get wrong and expensive to get
// wrong. On GCS a foreign bucket answers 403, and so can a bucket we created
// moments ago while IAM propagates; treating "could not inspect" as "proven
// foreign" is how an ensure orphans an owned, billable bucket behind a freshly
// minted name.
func (p *provider) adoptBucket(ctx context.Context, spec datasphere.BucketSpec) (*datasphere.Bucket, error) {
	b, err := p.getBucket(ctx, spec.Name)
	if err != nil {
		return nil, fmt.Errorf("gcs: bucket %q already exists but could not be inspected, so ownership is unknown; the local record is unchanged and the same name should be retried: %w", spec.Name, err)
	}
	if err := verifyOwned(b, spec.Name, spec.Instance); err != nil {
		return nil, err
	}
	// The labels match, so this is ours or something has gone strange. A
	// bucket FarCast created always carries the hardened posture, and a bucket
	// whose metadata a stranger could have made readable could not. Refusing
	// to adopt on a posture mismatch is deliberately a plain error rather than
	// ErrNotOwned: it is a reason to look, not proof of a foreign owner, and
	// the caller must not respond by abandoning the record.
	if err := verifyPosture(b, spec.Location); err != nil {
		return nil, fmt.Errorf("gcs: bucket %q carries this instance's labels but not FarCast's posture, so it is not being adopted; inspect it before proceeding: %w", spec.Name, err)
	}
	return &datasphere.Bucket{Ref: refFor(spec)}, retentionNotice(b, spec.Name)
}

// DeleteBucket verifies ownership, empties the bucket, and removes it.
//
// The ordering is load-bearing. Ownership is proved first, because this is the
// half that destroys data and a derived name could collide with a bucket
// FarCast never created. The soft-delete policy is reset second and before any
// object is deleted, because already-soft-deleted objects retain under the
// policy in force at the moment of their deletion — resetting afterwards would
// be too late for everything already gone. Only then are objects removed, and
// only then the bucket.
//
// An absent bucket is success. Any failure leaves the caller's record in place
// so a re-run converges.
func (p *provider) DeleteBucket(ctx context.Context, ref datasphere.BucketRef) error {
	switch {
	case ref.Name == "":
		return errors.New("gcs: a bucket name is required")
	case ref.Instance == "":
		return errors.New("gcs: BucketRef.Instance is required to verify ownership before destroying data")
	}

	b, err := p.getBucket(ctx, ref.Name)
	if isHTTPStatus(err, http.StatusNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("gcs: inspect bucket %q: %w", ref.Name, err)
	}
	if err := verifyOwned(b, ref.Name, ref.Instance); err != nil {
		return err
	}

	var notice error
	if window, ok := retentionWindow(b); ok && window > 0 {
		if err := p.resetSoftDelete(ctx, ref.Name); err != nil {
			notice = fmt.Errorf("%w: bucket %q retains deleted objects for %s and the reset was refused (%v); the ciphertext deleted here remains held and billed until that window lapses", datasphere.ErrRetentionForced, ref.Name, window, err)
		}
	}

	if err := p.drainObjects(ctx, ref.Name); err != nil {
		return err
	}
	if err := p.doJSON(ctx, http.MethodDelete, p.base+"b/"+url.PathEscape(ref.Name), nil, nil); err != nil {
		if isHTTPStatus(err, http.StatusNotFound) {
			return notice
		}
		// A 409 here means the bucket is not empty. It must never be read as
		// "already gone": GCS has no force-delete, and reporting success would
		// leave billable storage behind with nobody watching it.
		return fmt.Errorf("gcs: delete bucket %q: %w", ref.Name, err)
	}
	return notice
}

// getBucket reads a bucket's resource, labels and posture included.
func (p *provider) getBucket(ctx context.Context, name string) (*bucketResource, error) {
	var out bucketResource
	if err := p.doJSON(ctx, http.MethodGet, p.base+"b/"+url.PathEscape(name), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// resetSoftDelete patches the retention window back to zero.
func (p *provider) resetSoftDelete(ctx context.Context, name string) error {
	body := bucketResource{SoftDeletePolicy: &softDeletePolicy{RetentionDurationSeconds: "0"}}
	return p.doJSON(ctx, http.MethodPatch, p.base+"b/"+url.PathEscape(name), body, nil)
}

// drainObjects removes every object in the bucket, paging and honouring ctx.
func (p *provider) drainObjects(ctx context.Context, bucket string) error {
	for sweep := 0; sweep < maxDeleteSweeps; sweep++ {
		var names []string
		err := p.eachPage(ctx, bucket, "", "items(name),nextPageToken", func(items []objectResource) error {
			for _, item := range items {
				names = append(names, item.Name)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("gcs: list objects in %q: %w", bucket, err)
		}
		if len(names) == 0 {
			return nil
		}
		for _, name := range names {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := p.Delete(ctx, bucket, name); err != nil {
				return fmt.Errorf("gcs: empty bucket %q: %w", bucket, err)
			}
		}
	}
	return fmt.Errorf("gcs: bucket %q still reports objects after %d delete sweeps", bucket, maxDeleteSweeps)
}

// ownershipLabels builds the label set stamped on every FarCast bucket. The
// caller's extra labels are merged underneath, so nothing can override the two
// that establish ownership.
func ownershipLabels(instance string, extra map[string]string) map[string]string {
	labels := make(map[string]string, len(extra)+2)
	for k, v := range extra {
		labels[k] = v
	}
	labels[labelManagedBy] = labelManagedByValue
	labels[labelInstance] = labelValue(instance)
	return labels
}

// labelValue renders an instance name as a GCS label value, which admits only
// lowercase letters, digits, underscores and dashes. Instance names are DNS
// labels already, so this is a guard rather than a transformation.
func labelValue(instance string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(instance) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

// verifyOwned reports whether a bucket resource PROVES the bucket is this
// instance's. A label that is absent or names something else is proof of the
// negative — FarCast stamps both labels on every bucket it creates — and only
// that returns ErrNotOwned. The error names what differs, because an operator
// staring at a refusal needs to know which half was wrong.
func verifyOwned(b *bucketResource, name, instance string) error {
	var differs []string
	if got := b.Labels[labelManagedBy]; got != labelManagedByValue {
		differs = append(differs, fmt.Sprintf("label %s is %q, want %q", labelManagedBy, got, labelManagedByValue))
	}
	if want := labelValue(instance); b.Labels[labelInstance] != want {
		differs = append(differs, fmt.Sprintf("label %s is %q, want %q", labelInstance, b.Labels[labelInstance], want))
	}
	if len(differs) == 0 {
		return nil
	}
	return fmt.Errorf("%w: bucket %q: %s", datasphere.ErrNotOwned, name, strings.Join(differs, "; "))
}

// verifyPosture reports whether a bucket carries the posture FarCast applies at
// create. It is checked before adopting, never to prove foreign ownership.
func verifyPosture(b *bucketResource, location string) error {
	var differs []string
	if b.IAMConfiguration == nil || b.IAMConfiguration.UniformBucketLevelAccess == nil || !b.IAMConfiguration.UniformBucketLevelAccess.Enabled {
		differs = append(differs, "uniform bucket-level access is not enabled")
	}
	if b.IAMConfiguration == nil || !strings.EqualFold(b.IAMConfiguration.PublicAccessPrevention, publicAccessPrevention) {
		differs = append(differs, "public access prevention is not enforced")
	}
	if location != "" && b.Location != "" && !strings.EqualFold(b.Location, location) {
		differs = append(differs, fmt.Sprintf("location is %q, want %q", b.Location, location))
	}
	if len(differs) == 0 {
		return nil
	}
	return errors.New(strings.Join(differs, "; "))
}

// retentionWindow reads the bucket's soft-delete retention, reporting false
// when the cloud did not state one.
func retentionWindow(b *bucketResource) (time.Duration, bool) {
	if b.SoftDeletePolicy == nil || b.SoftDeletePolicy.RetentionDurationSeconds == "" {
		return 0, false
	}
	seconds, err := strconv.ParseInt(b.SoftDeletePolicy.RetentionDurationSeconds, 10, 64)
	if err != nil {
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}

// retentionNotice turns a non-zero retention window into the notice the
// operator is owed. It is an error wrapping ErrRetentionForced returned
// alongside a successful result: a caller that classifies it warns and carries
// on, and a caller that does not treats it as a failure and retries — which is
// harmless, because everything it accompanies is idempotent.
//
// Silence here would be the expensive outcome. A teardown that reports
// "nothing left billing" while retained copies bill for days offends the cost
// pillar and the privacy pillar in the same breath.
func retentionNotice(b *bucketResource, name string) error {
	window, ok := retentionWindow(b)
	if !ok || window == 0 {
		return nil
	}
	return fmt.Errorf("%w: bucket %q retains deleted objects for %s; ciphertext deleted from it remains held and billed until that window lapses", datasphere.ErrRetentionForced, name, window)
}

// refFor is the BucketRef an ensured spec resolves to.
func refFor(spec datasphere.BucketSpec) datasphere.BucketRef {
	return datasphere.BucketRef{Name: spec.Name, Location: spec.Location, Instance: spec.Instance}
}
