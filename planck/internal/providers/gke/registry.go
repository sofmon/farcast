package gke

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/auth"
	"cloud.google.com/go/auth/credentials"
	"cloud.google.com/go/auth/httptransport"

	"github.com/sofmon/farcast/planck"
)

// This file realizes planck.RegistryProvider on Google Artifact Registry: the
// per-instance image registry ADR 0007 gives every instance so that nothing the
// cluster runs comes from a feed outside the operator's control.
//
// The seven REST calls it needs (repository create/delete, one long-running
// operation poll, repository getIamPolicy/setIamPolicy, and a project lookup)
// are issued with net/http and encoding/json over the Google auth stack this
// module already vendors. ADR 0007 decision 2 named the generated
// google.golang.org/api/artifactregistry/v1 client instead, on the measured
// premise that it costs zero new modules. Re-measured here, that premise is
// false by one: every generated REST client imports
// google.golang.org/api/internal/gensupport, which imports github.com/google/uuid
// — `go mod vendor` goes from 31 modules to 32. The dependency budget for this
// feature is zero in a binary that holds the operator's cloud credentials, so
// the ADR's own fallback applies (the same stdlib-over-vendored-auth trade the
// CLI's OCI client takes). What is *not* re-owned is auth: token minting and
// refresh stay inside cloud.google.com/go/auth, which answers ADR 0006's K3
// objection to hand-rolled REST.

const (
	// repositoryNamePrefix names the registry after the instance exactly as the
	// cluster is named (farcast-<instance>), so one instance reads as one
	// recognisable set of cloud resources in the console and in a bill.
	repositoryNamePrefix = "farcast-"

	// repositoryFormat is Artifact Registry's Docker package format. A kubelet
	// can only pull OCI/Docker images, so the format is fixed, not a knob.
	repositoryFormat = "DOCKER"

	// repositoryDescription tells an operator browsing the cloud console what
	// created this repository and what removes it again.
	repositoryDescription = "FarCast instance images (ADR 0007) — created by farcast install, deleted by farcast release."

	// pullRole is the narrowest predefined role that permits an image pull. It
	// is bound on the one repository, never on the project: a project-level
	// grant would let every workload in the project read the instance's images.
	pullRole = "roles/artifactregistry.reader"

	// nodeServiceAccountFmt is the Compute Engine default service account, the
	// identity GKE Autopilot nodes run as today. The cluster object reports its
	// service account as the literal "default", so the email has to be rebuilt
	// from the project *number* (see projectNumber). A dedicated per-instance
	// node SA is recorded follow-up hardening in ADR 0007.
	nodeServiceAccountFmt = "serviceAccount:%d-compute@developer.gserviceaccount.com"

	// registryHostSuffix completes an Artifact Registry Docker host, e.g.
	// us-central1-docker.pkg.dev.
	registryHostSuffix = "-docker.pkg.dev"

	// tokenUsername is the fixed username Artifact Registry expects when the
	// password is an OAuth2 access token.
	tokenUsername = "oauth2accesstoken"

	// registryScope is the OAuth2 scope an Artifact Registry push/pull token
	// needs. Google issues no narrower scope for pkg.dev registries.
	registryScope = "https://www.googleapis.com/auth/cloud-platform"

	// iamPolicyVersion is the policy version requested when reading a
	// repository's IAM policy. It must be 3: asking for a lower version makes
	// the API *omit* conditional bindings from the response, and writing that
	// truncated policy back would silently delete another tool's conditional
	// grants.
	iamPolicyVersion = 3

	// maxRepositoryNameLen is Artifact Registry's repository-ID length limit.
	maxRepositoryNameLen = 63
)

// registryPollInterval paces the wait on a repository long-running operation.
// It is far shorter than defaultPollInterval because repository create/delete
// finishes in seconds, not the minutes a cluster takes. It is a package
// variable so tests can shorten it further.
var registryPollInterval = 2 * time.Second

// registryAPI is the narrow seam over the cloud's registry-admin API, expressed
// in neutral terms so the adapter's logic (name derivation, defaults, the
// idempotent IAM merge, operation waiting, error mapping) stays unit testable
// without the cloud SDK. The real implementation, gkeRegistryClient, wraps the
// Artifact Registry and Resource Manager REST clients; the unit tests use a
// fake (see registry_test.go).
type registryAPI interface {
	// createRepository requests creation of the repository and returns the name
	// of the long-running operation to wait on. It returns an empty name when
	// there is nothing to wait for — the repository already existed, or the
	// cloud completed the operation inline.
	createRepository(ctx context.Context, in repositoryInput) (string, error)
	// deleteRepository requests deletion and returns the operation to wait on,
	// or an empty name when the repository is already absent.
	deleteRepository(ctx context.Context, ref planck.RegistryRef) (string, error)
	// verifyOwned confirms a repository is the one FarCast created for the
	// named instance, so teardown never deletes somebody else's images. An
	// absent repository is not an error.
	verifyOwned(ctx context.Context, ref planck.RegistryRef, instance string) error
	// operationDone reports whether a long-running operation has finished,
	// surfacing its terminal error if it failed.
	operationDone(ctx context.Context, op string) (bool, error)
	// getPolicy reads the repository's IAM policy, conditions included.
	getPolicy(ctx context.Context, ref planck.RegistryRef) (iamPolicy, error)
	// setPolicy writes a complete IAM policy back onto the repository.
	setPolicy(ctx context.Context, ref planck.RegistryRef, pol iamPolicy) error
	// projectNumber resolves the configured project's number, which the node
	// service account's email is built from.
	projectNumber(ctx context.Context) (int64, error)
	// token mints a short-lived registry credential.
	token(ctx context.Context) (planck.RegistryToken, error)
}

// repositoryInput is the neutral, defaults-resolved description of the
// repository to ensure. The adapter builds it from a planck.RegistrySpec.
type repositoryInput struct {
	Name     string // resolved repository ID, e.g. farcast-demo
	Location string // resolved region
	Labels   map[string]string
}

// iamPolicy is a neutral snapshot of a resource's IAM policy. Etag and Version
// are carried verbatim: the etag is what makes the read-modify-write cycle
// safe against a concurrent policy change, and the version must round-trip so a
// conditional policy is not downgraded on the way back.
type iamPolicy struct {
	Bindings []iamBinding
	Etag     string
	Version  int64
}

// iamBinding is one role granted to a set of principals.
type iamBinding struct {
	Role    string
	Members []string
	// Condition is carried opaquely rather than dropped, because this adapter
	// writes back the *whole* policy: a condition lost in translation would
	// quietly widen or delete somebody else's grant on the repository.
	Condition *iamCondition
}

// iamCondition mirrors an IAM condition expression.
type iamCondition struct {
	Title       string
	Description string
	Expression  string
	Location    string
}

var _ planck.RegistryProvider = (*provider)(nil)

// registryClient lazily builds the GCP-backed registryAPI. Construction
// resolves credentials, so — as with the cluster client — it is deferred out of
// New and first surfaces through whichever registry operation the caller runs.
// Tests inject a fake regAPI directly, bypassing this path.
func (p *provider) registryClient() (registryAPI, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.regAPI == nil {
		api, err := newRegistryClient(p.cfg)
		if err != nil {
			return nil, err
		}
		p.regAPI = api
	}
	return p.regAPI, nil
}

// EnsureRegistry creates the instance's Docker repository if it is missing and
// makes sure the cluster's nodes can pull from it. Both halves are idempotent,
// so `install` and every later defensive `connect` converge on the same state.
//
// The IAM grant is repository-scoped on purpose (ADR 0007 decision 3): the node
// service account is the *shared* Compute Engine default account, so a
// project-level reader role would hand every workload in the project the
// instance's images. Nor does this rely on that account's automatic project
// Editor grant — that grant is org-policy-conditional and Google recommends
// disabling it, so pulls leaning on it work by accident and break on a hardened
// project.
//
// Errors keep their HTTP status reachable within this package, so a
// caller can tell "the installer service account predates roles/
// artifactregistry.admin" (403) from a real failure and degrade to a warning on
// paths that need no registry access.
func (p *provider) EnsureRegistry(ctx context.Context, spec planck.RegistrySpec) (*planck.Registry, error) {
	in, err := p.planEnsureRegistry(spec)
	if err != nil {
		return nil, err
	}
	api, err := p.registryClient()
	if err != nil {
		return nil, err
	}

	op, err := api.createRepository(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("gke: create repository %q: %w", in.Name, err)
	}
	// Wait for creation to finish before touching IAM: setIamPolicy on a
	// repository the cloud has accepted but not yet materialised fails with a
	// confusing NotFound, and an ensure that returns without the pull grant is
	// worse than one that returns an error.
	if err := p.waitOperation(ctx, api, op); err != nil {
		return nil, fmt.Errorf("gke: create repository %q: %w", in.Name, err)
	}

	ref := planck.RegistryRef{Name: in.Name, Location: in.Location}
	puller, err := p.grantPull(ctx, api, ref)
	if err != nil {
		return nil, err
	}
	return &planck.Registry{
		Ref:    ref,
		Prefix: imagePathPrefix(in.Location, p.cfg.Project, in.Name),
		Puller: puller,
	}, nil
}

// DeleteRegistry removes the instance's repository and everything in it,
// blocking until the cloud has actually run the deletion. Waiting is the point:
// teardown that reports success on a merely *accepted* delete can leave a
// billable repository behind with nobody left watching it.
func (p *provider) DeleteRegistry(ctx context.Context, ref planck.RegistryRef) error {
	if ref.Name == "" {
		return fmt.Errorf("gke: registry name is required")
	}
	resolved := planck.RegistryRef{
		Name:     repositoryName(ref.Name),
		Location: ref.Location,
	}
	if resolved.Location == "" {
		resolved.Location = p.defaultLocation
	}
	api, err := p.registryClient()
	if err != nil {
		return err
	}
	// Deleting is the half that destroys data, so it carries the same ownership
	// proof as adopting: the derived name could collide with a repository
	// FarCast never created, and teardown must not remove somebody else's
	// images because their repository happened to be named like ours. An absent
	// repository stays a success — teardown is idempotent.
	// The caller may name the instance ("demo") or the resolved repository
	// ("farcast-demo") — repositoryName accepts both — so the instance the
	// ownership label must carry is derived from the resolved name rather than
	// from whatever was passed in.
	if err := api.verifyOwned(ctx, resolved, instanceFromRepository(resolved.Name)); err != nil {
		return fmt.Errorf("gke: delete repository %q: %w", resolved.Name, err)
	}
	op, err := api.deleteRepository(ctx, resolved)
	if err != nil {
		return fmt.Errorf("gke: delete repository %q: %w", resolved.Name, err)
	}
	if err := p.waitOperation(ctx, api, op); err != nil {
		return fmt.Errorf("gke: delete repository %q: %w", resolved.Name, err)
	}
	return nil
}

// RegistryToken mints a ~60-minute Google OAuth2 access token from the
// configured service-account key. It never leaves the process except into the
// Authorization header of a registry request: no docker login, no credential
// helper, no file on disk.
func (p *provider) RegistryToken(ctx context.Context) (planck.RegistryToken, error) {
	api, err := p.registryClient()
	if err != nil {
		return planck.RegistryToken{}, err
	}
	tok, err := api.token(ctx)
	if err != nil {
		return planck.RegistryToken{}, fmt.Errorf("gke: mint a registry access token: %w", err)
	}
	return tok, nil
}

// planEnsureRegistry resolves a RegistrySpec into a defaults-filled
// repositoryInput. spec.Cluster is not read here: today's node identity is the
// project's default compute account, which the project number alone determines
// (see grantPull). The field is what a dedicated per-instance node service
// account will key on once that hardening lands.
func (p *provider) planEnsureRegistry(spec planck.RegistrySpec) (repositoryInput, error) {
	if spec.Name == "" {
		return repositoryInput{}, fmt.Errorf("gke: registry name (the instance name) is required")
	}
	name := repositoryName(spec.Name)
	if err := validateRepositoryName(name); err != nil {
		return repositoryInput{}, err
	}
	loc := spec.Location
	if loc == "" {
		loc = p.defaultLocation
	}
	// The ownership labels are FarCast's invariant, not the caller's option:
	// they are the proof teardown checks for, so a repository created without
	// them could never be deleted by the tool that made it. Caller labels are
	// merged underneath and cannot displace the identity.
	labels := make(map[string]string, len(spec.Labels)+2)
	maps.Copy(labels, spec.Labels)
	maps.Copy(labels, ownershipLabels(spec.Name))
	return repositoryInput{Name: name, Location: loc, Labels: labels}, nil
}

// grantPull binds the pull role to the cluster's node service account on this
// one repository, and returns the principal it granted so the caller can record
// who can read the instance's images.
//
// The write is skipped when the binding is already there. That keeps the
// defensive ensure on every `connect` free of pointless policy churn, and — more
// importantly — the read-modify-write preserves every other binding on the
// repository instead of replacing the policy with our own.
func (p *provider) grantPull(ctx context.Context, api registryAPI, ref planck.RegistryRef) (string, error) {
	num, err := api.projectNumber(ctx)
	if err != nil {
		return "", fmt.Errorf("gke: look up the number of project %q: %w", p.cfg.Project, err)
	}
	member := nodeServiceAccountMember(num)

	pol, err := api.getPolicy(ctx, ref)
	if err != nil {
		return "", fmt.Errorf("gke: read the IAM policy of repository %q: %w", ref.Name, err)
	}
	next, changed := grantRole(pol, pullRole, member)
	if !changed {
		return member, nil
	}
	if err := api.setPolicy(ctx, ref, next); err != nil {
		return "", fmt.Errorf("gke: grant %s on repository %q: %w", pullRole, ref.Name, err)
	}
	return member, nil
}

// waitOperation polls a long-running operation until it completes or ctx
// expires. An empty name means there was nothing to wait for.
func (p *provider) waitOperation(ctx context.Context, api registryAPI, op string) error {
	if op == "" {
		return nil
	}
	for {
		done, err := api.operationDone(ctx, op)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(registryPollInterval):
		}
	}
}

// grantRole adds member to role in pol without disturbing anything else, and
// reports whether the policy actually changed. It only ever extends the
// *unconditional* binding for the role: a conditional grant is not a guarantee
// of access, so one must not be mistaken for the binding we need.
func grantRole(pol iamPolicy, role, member string) (iamPolicy, bool) {
	next := pol
	next.Bindings = slices.Clone(pol.Bindings)
	for i, b := range next.Bindings {
		if b.Role != role || b.Condition != nil {
			continue
		}
		if slices.Contains(b.Members, member) {
			return pol, false
		}
		b.Members = append(slices.Clone(b.Members), member)
		next.Bindings[i] = b
		return next, true
	}
	next.Bindings = append(next.Bindings, iamBinding{Role: role, Members: []string{member}})
	return next, true
}

// repositoryName derives the repository ID from an instance name. It is
// idempotent under re-prefixing so that `install` (given an instance name) and
// `release` (given whatever a caller recorded) cannot disagree about which
// repository is the instance's — disagreeing would leave a billable repository
// behind while teardown reported success, since deleting an absent repository
// is deliberately not an error.
// instanceFromRepository is repositoryName's inverse: the instance a repository
// belongs to, which is what the identifying label carries.
func instanceFromRepository(repository string) string {
	return strings.TrimPrefix(repository, repositoryNamePrefix)
}

func repositoryName(instance string) string {
	if strings.HasPrefix(instance, repositoryNamePrefix) {
		return instance
	}
	return repositoryNamePrefix + instance
}

// imagePathPrefix builds the image-path prefix images are pushed under and the
// kubelet pulls from, e.g. us-central1-docker.pkg.dev/proj/farcast-demo.
// Everything below it is convention (ADR 0007 decision 6): system/<component>
// for FarCast's own images, app/<deployment>/<app> for Phase 4 app images.
func imagePathPrefix(location, project, repository string) string {
	return fmt.Sprintf("%s%s/%s/%s", location, registryHostSuffix, project, repository)
}

// nodeServiceAccountMember builds the IAM principal for the cluster's nodes.
func nodeServiceAccountMember(projectNumber int64) string {
	return fmt.Sprintf(nodeServiceAccountFmt, projectNumber)
}

// validateRepositoryName enforces the intersection of Artifact Registry's
// repository-ID rules and Docker's reference grammar: 1–63 characters, starting
// with a lowercase letter, no trailing hyphen, and lowercase letters, digits and
// hyphens only. Artifact Registry itself tolerates uppercase and underscores,
// but this name becomes a segment of every image reference the cluster pulls,
// and a Docker reference path must be lowercase — so a name that AR accepts
// could still produce images nothing can pull.
func validateRepositoryName(name string) error {
	if name == "" {
		return fmt.Errorf("gke: registry name is required")
	}
	if len(name) > maxRepositoryNameLen {
		return fmt.Errorf("gke: registry name %q is longer than %d characters", name, maxRepositoryNameLen)
	}
	if name[0] < 'a' || name[0] > 'z' {
		return fmt.Errorf("gke: registry name %q must start with a lowercase letter", name)
	}
	if name[len(name)-1] == '-' {
		return fmt.Errorf("gke: registry name %q must not end with a hyphen", name)
	}
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-':
		default:
			return fmt.Errorf("gke: registry name %q contains invalid character %q", name, string(c))
		}
	}
	return nil
}

// gkeRegistryClient is the real registryAPI: Artifact Registry for the
// repository and its IAM policy, Resource Manager for the project number, and a
// token provider of its own for minting registry credentials. One client is
// scoped to a single GCP project. As with gkeClient, the HTTP client lives for
// the life of the process — FarCast's callers are short-lived — so nothing is
// closed; per-call bounds come from ctx.
//
// The endpoints and the token provider are fields rather than constants so
// tests can drive the wire protocol through a fake RoundTripper, with no
// listener and no network.
type gkeRegistryClient struct {
	http    *http.Client
	tokens  auth.TokenProvider
	project string
	arBase  string // Artifact Registry v1 base URL, trailing slash included
	crmBase string // Resource Manager v1 base URL, trailing slash included
}

var _ registryAPI = (*gkeRegistryClient)(nil)

const (
	artifactRegistryBase = "https://artifactregistry.googleapis.com/v1/"
	resourceManagerBase  = "https://cloudresourcemanager.googleapis.com/v1/"

	// maxResponseBytes caps how much of a response is read. Repositories,
	// operations and IAM policies are kilobytes; the cap exists so a captive
	// portal or a proxy error page cannot make the credential-holding CLI
	// allocate without bound.
	maxResponseBytes = 1 << 20
)

// newRegistryClient builds the GCP-backed registryAPI from cfg. It is a package
// variable so tests can substitute a fake and exercise the provider's
// lazy-construction path without real credentials.
var newRegistryClient = func(cfg planck.Config) (registryAPI, error) {
	creds, err := registryCredentials(cfg)
	if err != nil {
		return nil, fmt.Errorf("gke: resolve registry credentials: %w", err)
	}
	// The auth stack owns the Authorization header and the token refresh behind
	// it, so nothing here handles a bearer token by hand.
	hc, err := httptransport.NewClient(&httptransport.Options{Credentials: creds})
	if err != nil {
		return nil, fmt.Errorf("gke: build registry HTTP client: %w", err)
	}
	return &gkeRegistryClient{
		http:    hc,
		tokens:  creds,
		project: cfg.Project,
		arBase:  artifactRegistryBase,
		crmBase: resourceManagerBase,
	}, nil
}

// registryCredentials resolves the credential that authenticates the admin
// calls and mints registry tokens. A configured key is loaded as a service
// account *and nothing else* — the type-restricted loader refuses, say, an
// external-account configuration that would redirect token minting at a URL of
// the file author's choosing. An empty Config.Credentials falls back to
// Application Default Credentials, matching the cluster client's behaviour.
func registryCredentials(cfg planck.Config) (*auth.Credentials, error) {
	opts := &credentials.DetectOptions{Scopes: []string{registryScope}}
	if len(cfg.Credentials) > 0 {
		return credentials.NewCredentialsFromJSON(credentials.ServiceAccount, cfg.Credentials, opts)
	}
	return credentials.DetectDefault(opts)
}

// locationPath is the "projects/P/locations/L" parent path.
func (c *gkeRegistryClient) locationPath(location string) string {
	return fmt.Sprintf("projects/%s/locations/%s", url.PathEscape(c.project), url.PathEscape(location))
}

// repositoryPath is the fully-qualified
// "projects/P/locations/L/repositories/R" resource name.
func (c *gkeRegistryClient) repositoryPath(ref planck.RegistryRef) string {
	return fmt.Sprintf("%s/repositories/%s", c.locationPath(ref.Location), url.PathEscape(ref.Name))
}

func (c *gkeRegistryClient) createRepository(ctx context.Context, in repositoryInput) (string, error) {
	target := c.arBase + c.locationPath(in.Location) + "/repositories?repositoryId=" + url.QueryEscape(in.Name)
	body := repositoryResource{
		Format:      repositoryFormat,
		Description: repositoryDescription,
		Labels:      in.Labels,
	}
	var op operationResource
	err := c.do(ctx, http.MethodPost, target, body, &op)
	if isHTTPStatus(err, http.StatusConflict) {
		// Already there — ensure is idempotent. But "a repository with this
		// name exists" is not the same as "*our* repository exists", and the
		// difference matters: farcast release deletes this repository and
		// everything in it. Adopting a name that happens to collide would put
		// somebody else's images behind our teardown, so the existing
		// repository has to prove it is ours before we claim it.
		return "", c.verifyAdoptable(ctx, in)
	}
	if err != nil {
		return "", err
	}
	return pendingOperation(&op)
}

// verifyAdoptable confirms that a pre-existing repository is one FarCast
// created for this instance: the right format, and the identifying labels
// install stamps on it. Anything else is refused rather than adopted.
func (c *gkeRegistryClient) verifyAdoptable(ctx context.Context, in repositoryInput) error {
	ref := planck.RegistryRef{Name: in.Name, Location: in.Location}
	got, err := c.getRepository(ctx, ref)
	if err != nil {
		return err
	}
	if got == nil {
		return nil // vanished between the conflict and the read; the next ensure settles it
	}
	if err := checkOwned(got, in.Name, in.Location, in.Labels); err != nil {
		return err
	}
	return nil
}

// verifyOwned is the teardown-side ownership proof. It reads the repository and
// requires FarCast's identifying labels, naming the instance it belongs to. An
// absent repository is not an error: teardown is idempotent.
func (c *gkeRegistryClient) verifyOwned(ctx context.Context, ref planck.RegistryRef, instance string) error {
	got, err := c.getRepository(ctx, ref)
	if err != nil || got == nil {
		return err
	}
	return checkOwned(got, ref.Name, ref.Location, ownershipLabels(instance))
}

// getRepository reads a repository, reporting a nil resource when it does not
// exist so callers can treat absence as their own kind of success.
func (c *gkeRegistryClient) getRepository(ctx context.Context, ref planck.RegistryRef) (*repositoryResource, error) {
	var got repositoryResource
	err := c.do(ctx, http.MethodGet, c.arBase+c.repositoryPath(ref), nil, &got)
	if isHTTPStatus(err, http.StatusNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect repository %q: %w", ref.Name, err)
	}
	return &got, nil
}

// checkOwned is the single rule for "is this repository FarCast's": the right
// artifact format, and every identifying label matching. It is shared by
// adoption and teardown so the two can never drift — the destructive side must
// never be more permissive than the side that merely reuses.
func checkOwned(got *repositoryResource, name, location string, want map[string]string) error {
	if got.Format != "" && !strings.EqualFold(got.Format, repositoryFormat) {
		return fmt.Errorf("a %s repository named %q already exists in %s; refusing to touch it, because it is not one FarCast created "+
			"(delete it yourself if it is disposable, or install this instance under a different name)",
			got.Format, name, location)
	}
	for k, v := range want {
		if got.Labels[k] != v {
			return fmt.Errorf("the repository %q in %s is not FarCast's: label %q is %q, expected %q. Refusing to touch it, "+
				"because farcast release deletes this repository and everything in it "+
				"(delete it yourself if it is disposable, or install this instance under a different name)",
				name, location, k, got.Labels[k], v)
		}
	}
	return nil
}

// ownershipLabels is the identifying stamp FarCast puts on an instance's
// repository, and the proof teardown checks for. It mirrors the labels the CLI
// supplies at install; keep the two in step.
func ownershipLabels(instance string) map[string]string {
	return map[string]string{"managed-by": "farcast", "farcast-instance": instance}
}

func (c *gkeRegistryClient) deleteRepository(ctx context.Context, ref planck.RegistryRef) (string, error) {
	var op operationResource
	err := c.do(ctx, http.MethodDelete, c.arBase+c.repositoryPath(ref), nil, &op)
	if isHTTPStatus(err, http.StatusNotFound) {
		return "", nil // already gone — deletion is idempotent
	}
	if err != nil {
		return "", err
	}
	return pendingOperation(&op)
}

func (c *gkeRegistryClient) operationDone(ctx context.Context, op string) (bool, error) {
	if !validOperationName(op) {
		return false, fmt.Errorf("cloud returned an unusable operation name %q", op)
	}
	var got operationResource
	if err := c.do(ctx, http.MethodGet, c.arBase+op, nil, &got); err != nil {
		return false, err
	}
	return operationOutcome(&got)
}

func (c *gkeRegistryClient) getPolicy(ctx context.Context, ref planck.RegistryRef) (iamPolicy, error) {
	target := fmt.Sprintf("%s%s:getIamPolicy?options.requestedPolicyVersion=%d",
		c.arBase, c.repositoryPath(ref), iamPolicyVersion)
	var pol policyResource
	if err := c.do(ctx, http.MethodGet, target, nil, &pol); err != nil {
		return iamPolicy{}, err
	}
	return fromWirePolicy(&pol), nil
}

func (c *gkeRegistryClient) setPolicy(ctx context.Context, ref planck.RegistryRef, pol iamPolicy) error {
	target := c.arBase + c.repositoryPath(ref) + ":setIamPolicy"
	return c.do(ctx, http.MethodPost, target, setPolicyRequest{Policy: toWirePolicy(pol)}, nil)
}

func (c *gkeRegistryClient) projectNumber(ctx context.Context) (int64, error) {
	var proj projectResource
	if err := c.do(ctx, http.MethodGet, c.crmBase+"projects/"+url.PathEscape(c.project), nil, &proj); err != nil {
		return 0, err
	}
	// Resource Manager sends the number as a JSON string, because it exceeds
	// what JSON numbers safely represent in other languages.
	num, err := strconv.ParseInt(proj.ProjectNumber, 10, 64)
	if err != nil || num == 0 {
		return 0, fmt.Errorf("project %q reported no usable project number", c.project)
	}
	return num, nil
}

func (c *gkeRegistryClient) token(ctx context.Context) (planck.RegistryToken, error) {
	tok, err := c.tokens.Token(ctx)
	if err != nil {
		return planck.RegistryToken{}, err
	}
	return planck.RegistryToken{
		Username: tokenUsername,
		Password: tok.Value,
		Expiry:   tok.Expiry,
	}, nil
}

// do issues one authenticated JSON request and decodes the response into out
// (nil to discard it). Non-2xx responses become an *apiError carrying the
// status, which is what the adapter's idempotency decisions read.
func (c *gkeRegistryClient) do(ctx context.Context, method, target string, in, out any) error {
	var body io.Reader
	if in != nil {
		encoded, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("encode request body: %w", err)
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return parseAPIError(resp.StatusCode, data)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// repositoryResource is the subset of an Artifact Registry repository FarCast
// sets. Everything else — cleanup policies, CMEK, immutable tags — is left at
// the service default and revisited when 4.3 wires up retention.
type repositoryResource struct {
	Format      string            `json:"format"`
	Description string            `json:"description,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// operationResource is a long-running operation as the API reports it.
type operationResource struct {
	Name  string          `json:"name"`
	Done  bool            `json:"done"`
	Error *statusResource `json:"error,omitempty"`
}

// statusResource is an operation's terminal error.
type statusResource struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// policyResource, bindingResource and exprResource mirror the IAM policy wire
// format. They exist so a policy can be read and written back whole, with
// nothing silently dropped in between.
type policyResource struct {
	Version  int64              `json:"version,omitempty"`
	Etag     string             `json:"etag,omitempty"`
	Bindings []*bindingResource `json:"bindings,omitempty"`
}

type bindingResource struct {
	Role      string        `json:"role"`
	Members   []string      `json:"members,omitempty"`
	Condition *exprResource `json:"condition,omitempty"`
}

type exprResource struct {
	Expression  string `json:"expression,omitempty"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Location    string `json:"location,omitempty"`
}

// setPolicyRequest is the setIamPolicy request envelope.
type setPolicyRequest struct {
	Policy *policyResource `json:"policy"`
}

// projectResource is the slice of a Resource Manager project this adapter
// needs: the number the node service account's email is built from.
type projectResource struct {
	ProjectNumber string `json:"projectNumber"`
}

// pendingOperation reduces a freshly-returned operation to the name the caller
// must poll, or an empty name when the cloud already finished it inline.
func pendingOperation(op *operationResource) (string, error) {
	done, err := operationOutcome(op)
	if err != nil {
		return "", err
	}
	if done {
		return "", nil
	}
	return op.Name, nil
}

// operationOutcome maps a long-running operation onto (finished, terminal
// error). A carried error is terminal whether or not the operation admits to
// being done, so a failed create or delete never looks like progress.
func operationOutcome(op *operationResource) (bool, error) {
	if op == nil {
		return false, nil
	}
	if op.Error != nil {
		return true, fmt.Errorf("operation %s failed: %s (code %d)", op.Name, op.Error.Message, op.Error.Code)
	}
	return op.Done, nil
}

// validOperationName guards the one place a server-supplied string becomes part
// of a URL this client requests. An operation name is a resource path, so
// anything that could climb out of it — an absolute path, a traversal, a
// scheme — is rejected rather than fetched.
func validOperationName(op string) bool {
	if !strings.HasPrefix(op, "projects/") {
		return false
	}
	if strings.Contains(op, "..") || strings.Contains(op, "//") || strings.ContainsAny(op, "?#") {
		return false
	}
	return true
}

// fromWirePolicy converts an IAM policy into the neutral form, keeping etag,
// version and conditions so it can be written back faithfully.
func fromWirePolicy(pol *policyResource) iamPolicy {
	if pol == nil {
		return iamPolicy{}
	}
	out := iamPolicy{Etag: pol.Etag, Version: pol.Version}
	for _, b := range pol.Bindings {
		if b == nil {
			continue
		}
		binding := iamBinding{Role: b.Role, Members: slices.Clone(b.Members)}
		if b.Condition != nil {
			binding.Condition = &iamCondition{
				Title:       b.Condition.Title,
				Description: b.Condition.Description,
				Expression:  b.Condition.Expression,
				Location:    b.Condition.Location,
			}
		}
		out.Bindings = append(out.Bindings, binding)
	}
	return out
}

// toWirePolicy is fromWirePolicy's inverse.
func toWirePolicy(pol iamPolicy) *policyResource {
	out := &policyResource{Etag: pol.Etag, Version: pol.Version}
	for _, b := range pol.Bindings {
		binding := &bindingResource{Role: b.Role, Members: slices.Clone(b.Members)}
		if b.Condition != nil {
			binding.Condition = &exprResource{
				Title:       b.Condition.Title,
				Description: b.Condition.Description,
				Expression:  b.Condition.Expression,
				Location:    b.Condition.Location,
			}
		}
		out.Bindings = append(out.Bindings, binding)
	}
	return out
}

// apiError is a failed Google API call. It carries the status so callers can
// treat "already exists" and "not found" as success, and the service's message
// so an operator sees why a call failed — but never the request, which names
// the project and the credential's audience.
type apiError struct {
	Code    int    // HTTP status
	Status  string // canonical status, e.g. ALREADY_EXISTS
	Message string
}

func (e *apiError) Error() string {
	switch {
	case e.Status != "" && e.Message != "":
		return fmt.Sprintf("cloud API error %d %s: %s", e.Code, e.Status, e.Message)
	case e.Message != "":
		return fmt.Sprintf("cloud API error %d: %s", e.Code, e.Message)
	default:
		return fmt.Sprintf("cloud API error %d", e.Code)
	}
}

// parseAPIError builds an apiError from a non-2xx response, falling back to the
// HTTP status when the body is not the JSON error envelope (a proxy or a
// captive portal answering instead of the API).
func parseAPIError(status int, body []byte) error {
	out := &apiError{Code: status}
	var envelope struct {
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Status  string `json:"status"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err == nil {
		out.Message = envelope.Error.Message
		out.Status = envelope.Error.Status
		if envelope.Error.Code != 0 {
			out.Code = envelope.Error.Code
		}
	}
	return out
}

// isHTTPStatus reports whether err is a cloud API error carrying code.
func isHTTPStatus(err error, code int) bool {
	var apiErr *apiError
	return errors.As(err, &apiErr) && apiErr.Code == code
}
