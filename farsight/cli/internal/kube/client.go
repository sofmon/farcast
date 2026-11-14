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
	// ScopeUserinfoEmail is the one scope a cluster token carries, so a leaked
	// cluster token reaches no other Google API.
	ScopeUserinfoEmail = "https://www.googleapis.com/auth/userinfo.email"
)

// Identity is which of an instance's two service accounts a client acts as.
type Identity string

const (
	Writer Identity = "writer"
	Reader Identity = "reader"
)

// Config is everything a client is built from: where the cluster is, whose
// key signs the token, and which of the instance's identities that key is.
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
	tokenHTTP *http.Client // the token endpoint: tokenTransport, 30 s, no redirects
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
// Its token is the credential's own 2LO token (§3.3): minted in memory from
// the key, scoped to userinfo.email alone, from Endpoint.TokenURL and never
// from a URL a key file names.
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
