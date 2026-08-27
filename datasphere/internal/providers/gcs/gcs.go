// Package gcs implements datasphere.Provider on Google Cloud Storage. It is
// the first storage adapter, matching the Phase 1 cloud.
//
// Nothing in this package can see what it is storing. Names arrive as opaque
// tokens and bodies as ciphertext, both produced by the encrypting layer
// above; there is no code path here that could leak a logical name or a
// plaintext byte, because neither is ever passed in. What this package owns is
// the unglamorous half: bucket lifecycle with ownership discipline, a hardened
// posture the cloud cannot quietly relax, and four object operations.
package gcs

import (
	"errors"
	"net/http"
	"sync"

	"github.com/sofmon/farcast/datasphere"
)

const (
	// providerName is this adapter's stable identifier.
	providerName = "gcs"

	// bucketNamePrefix is what every FarCast bucket name begins with. It is
	// what the credentials probe narrows its listing to, and what an IAM
	// condition scoping the stored credential to FarCast's own buckets keys on.
	bucketNamePrefix = "farcast-"

	// Ownership labels. Both are stamped at create and both are checked before
	// anything is adopted or destroyed — Planck's hard-learned rule, and it
	// matters more here: GCS bucket names live in a namespace shared with every
	// stranger on the platform.
	labelManagedBy      = "managed-by"
	labelManagedByValue = "farcast"
	labelInstance       = "farcast-instance"

	// bucketDescription-equivalent posture constants. These are spec-mandated,
	// not adapter discretion.
	storageClassStandard   = "STANDARD"
	publicAccessPrevention = "enforced"

	// maxListResults is the page size for object listings.
	maxListResults = 1000
)

func init() { datasphere.Register(providerName, New) }

// provider is one GCP project's object storage.
//
// The endpoints are fields rather than constants so tests can drive the whole
// wire protocol through a fake RoundTripper, with no listener and no network.
// The HTTP client lives for the life of the process — FarCast's callers are
// short-lived — so nothing is closed; per-call bounds come from ctx.
type provider struct {
	cfg    datasphere.Config
	base   string // JSON API base, trailing slash included
	upload string // upload API base, trailing slash included

	mu sync.Mutex
	hc *http.Client
}

var _ datasphere.Provider = (*provider)(nil)

// New builds the GCS adapter. Credential resolution is deferred to the first
// operation, exactly as Planck's adapters defer theirs: constructing a
// provider is not the moment to fail on the operator's machine, and a caller
// that only wanted Providers() should not need credentials at all.
func New(cfg datasphere.Config) (datasphere.Provider, error) {
	if cfg.Project == "" {
		return nil, errors.New("gcs: a project is required")
	}
	return &provider{cfg: cfg, base: jsonAPIBase, upload: uploadAPIBase}, nil
}

// Name is the provider's stable identifier.
func (p *provider) Name() string { return providerName }

// bucketResource is the subset of a GCS bucket FarCast sets or reads.
// Everything else — lifecycle rules, CMEK, retention policies, logging — is
// left at the service default.
type bucketResource struct {
	Name             string            `json:"name,omitempty"`
	Location         string            `json:"location,omitempty"`
	StorageClass     string            `json:"storageClass,omitempty"`
	Labels           map[string]string `json:"labels,omitempty"`
	IAMConfiguration *iamConfiguration `json:"iamConfiguration,omitempty"`
	Versioning       *versioning       `json:"versioning,omitempty"`
	SoftDeletePolicy *softDeletePolicy `json:"softDeletePolicy,omitempty"`
}

type iamConfiguration struct {
	UniformBucketLevelAccess *uniformBucketLevelAccess `json:"uniformBucketLevelAccess,omitempty"`
	PublicAccessPrevention   string                    `json:"publicAccessPrevention,omitempty"`
}

type uniformBucketLevelAccess struct {
	Enabled bool `json:"enabled"`
}

type versioning struct {
	Enabled bool `json:"enabled"`
}

// softDeletePolicy carries GCS's retention window for deleted objects. The
// duration is an int64 the JSON API renders as a string, so it is typed as one
// here rather than silently losing the distinction between "zero" and "unset".
type softDeletePolicy struct {
	RetentionDurationSeconds string `json:"retentionDurationSeconds,omitempty"`
}

// objectResource is the subset of a GCS object this adapter reads or writes.
type objectResource struct {
	Name     string            `json:"name,omitempty"`
	Size     string            `json:"size,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// objectListPage is one page of an object listing.
type objectListPage struct {
	Items         []objectResource `json:"items"`
	NextPageToken string           `json:"nextPageToken"`
}
