package kube

import (
	"context"
	"net/http"
	"slices"
	"sync"
	"time"
)

// The fixed values of every cluster and token request.
const (
	// FieldManager is the field manager farcast names, explicitly, on every
	// write it makes, apply or not.
	FieldManager = "farcast"
	// UserAgent is the whole User-Agent of every cluster and token request:
	// no version, operating system, architecture or Go version.
	UserAgent = "farcast"
	// GoogleTokenURL is the only token endpoint a Google-mode client uses. It
	// is fixed in code and never read from a key file.
	GoogleTokenURL = "https://oauth2.googleapis.com/token"
	// ScopeCloudPlatform is the first of a cluster token's two scopes
	// (TokenScopes). GKE's DNS endpoint checks IAM, and that check needs it:
	// the 2026-11-16 probe walk got 401 for a token scoped to userinfo.email
	// alone, and 200 with this one added (design A22-7).
	ScopeCloudPlatform = "https://www.googleapis.com/auth/cloud-platform"
	// ScopeUserinfoEmail is the second of a cluster token's two scopes
	// (TokenScopes). It keeps the account's email in the identity GKE derives
	// from the token, which is the name the reader's RoleBindings use. M2's walk
	// showed it for an impersonated token; for the reader's own key it is inferred.
	ScopeUserinfoEmail = "https://www.googleapis.com/auth/userinfo.email"
)

// TokenScopes is what every cluster token is minted with: cloud-platform,
// then userinfo.email, the order the probe walk's probe sent them in when the
// DNS endpoint answered 200 (design A22-7). Each call returns a fresh slice.
//
// The trade-off: with cloud-platform, a leaked cluster token works for every
// Google API the account's IAM allows, not only the cluster. For the reader
// that is roles/container.clusterViewer; for the writer, everything the
// installer holds. The token is held in memory only, one per client, and is
// sent as a bearer only to the endpoint's own host (apiTransport,
// TestAuthorizationOnlyToTheEndpointHost); the token endpoint is sent none.
func TokenScopes() []string {
	return []string{ScopeCloudPlatform, ScopeUserinfoEmail}
}

// Identity is which of an instance's two service accounts a client acts as.
type Identity string

const (
	Writer Identity = "writer"
	Reader Identity = "reader"
)

// Config is everything a client is built from: where the cluster is, the
// credential its token comes from (a service-account key, or a federated
// credential), and which of the instance's identities that credential is.
type Config struct {
	Endpoint   Endpoint
	Credential Credential
	Identity   Identity
}

// Client is farcast's client for one instance's API server, acting as one of
// its identities. It holds its token in memory only, and is safe for
// concurrent use.
type Client struct {
	ep       Endpoint
	identity Identity
	base     string // ep.BaseURL()
	domain   string // the credential email's domain, the only part of it a message names

	api       *http.Client // the API: apiTransport, no Timeout, no redirects
	follow    *http.Client // a followed log: api's shape with no ResponseHeaderTimeout
	tokenHTTP *http.Client // the token endpoint: tokenTransport, 30 s, no redirects; nil for a federated credential
	tokens    *tokenCache

	// attemptTimeout bounds each attempt of a non-streaming request
	// (requestTimeout, §3.4's 60 s); a test shortens it.
	attemptTimeout time.Duration

	// sleep waits between retries (§3.4); a test replaces it.
	sleep func(ctx context.Context, d time.Duration) error

	mu       sync.Mutex
	warnings []string
	seen     map[string]bool
}

// New checks that the endpoint and the credential pair (§3.2), then builds the
// transports and the token cache. It dials nothing and mints nothing.
//
// Its token depends on the credential:
//   - for a service-account key, the key's own 2LO token (§3.3): minted in
//     memory from the key, scoped to TokenScopes (cloud-platform and
//     userinfo.email), from Endpoint.TokenURL and never from a URL a key file
//     names;
//   - for a federated credential (NewFederatedCredential), the role's
//     service-account token for ScopesCluster (design D5): impersonated at
//     IAM Credentials with the role's one federated token, which the
//     credential shares with its other consumers. No token client is built.
func New(cfg Config) (*Client, error) {
	return newClient(cfg, nil)
}

// Identity is which of the instance's identities the client acts as.
func (c *Client) Identity() Identity { return c.identity }

// Warnings returns the distinct API Warning header texts seen, in order.
// Each call returns a copy.
func (c *Client) Warnings() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.warnings)
}
