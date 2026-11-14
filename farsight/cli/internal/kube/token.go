package kube

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/auth"
)

// tokenFunc mints one token. The 2LO provider of §3.3 is the only one a
// product path builds; a test, or the real-Kubernetes test of §10.6, hands
// newClient a static one. No exported path takes a token function.
type tokenFunc func(ctx context.Context) (*auth.Token, error)

// earlyExpiry is how long before its expiry a cached token is minted anew:
// the vendored cache's own early-expiry default, 225 s
// (vendor/cloud.google.com/go/auth/auth.go, defaultExpiryDelta).
const earlyExpiry = 225 * time.Second

// The refusal messages of a mint (§3.3). Each names the identity's email
// domain and, for a refusal, the HTTP status, and never the token, the
// assertion or the key.
const (
	msgTokenRefused     = "Google refused to mint a token for the %s service account (%d %s)"
	msgTokenUnreachable = "the token endpoint for the %s service account could not be reached: %s"
	msgTokenUnreadable  = "the token endpoint's answer for the %s service account could not be read"
	msgTokenEmpty       = "the token endpoint answered without a token"
)

// newClient is New with the token source given. It checks that the endpoint
// and the credential pair (§3.2) before it builds a transport, a token source
// or a cache, so the rule holds for every caller of either; it dials nothing
// and mints nothing. A nil mint is the 2LO provider of §3.3, which is what New
// passes.
//
// Before anything else it refuses, with ErrUnsafeEnvironment, while GODEBUG
// has turned on Go's HTTP/2 logging (http2Verbose), which would print the
// bearer token, and with http2debug=2 the signed assertion and the minted
// token, to stderr.
func newClient(cfg Config, mint tokenFunc) (*Client, error) {
	if http2Verbose {
		return nil, refuse(ErrUnsafeEnvironment, msgHTTP2Debug)
	}
	if err := pair(cfg.Endpoint, cfg.Credential); err != nil {
		return nil, err
	}
	ep := cfg.Endpoint
	c := &Client{
		ep:       ep,
		identity: cfg.Identity,
		base:     ep.BaseURL(),
		domain:   emailDomain(cfg.Credential.Email),
		sleep:    sleepContext,

		attemptTimeout: requestTimeout,
	}
	c.api = apiHTTPClient(ep)
	c.follow = followHTTPClient(ep)
	c.tokenHTTP = tokenHTTPClient(ep)
	if mint == nil {
		var err error
		if mint, err = twoLegged(cfg, c.tokenHTTP, c.domain); err != nil {
			return nil, err
		}
	}
	c.tokens = &tokenCache{mint: mint, now: wallNow}
	return c, nil
}

// wallNow is the token cache's clock: the wall time alone, with no monotonic
// reading. A minted token's Expiry carries one (vendor/cloud.google.com/go/auth/auth.go,
// time.Now().Add), and Before compares two monotonic readings when both have
// one; the monotonic clock stops while the machine sleeps, so after a sleep
// an expired token would read as fresh. With one side wall-only, freshness is
// wall time, as the vendored Token.IsValid compares it (t.Expiry.Round(0)).
func wallNow() time.Time { return time.Now().Round(0) }

// twoLegged is the token source of §3.3: the vendored 2LO provider, with the
// token URL fixed in code (Endpoint.TokenURL, never the key file's token_uri),
// the one scope userinfo.email, and a logger that discards. Expires is left
// zero, so the vendored encoder sends iat = now − 10 s and exp = iat + 3600,
// within Google's hour (vendor/cloud.google.com/go/auth/internal/jwt/jwt.go,
// Claims.encode). Its errors are classified here, so none carries the token
// endpoint's body.
func twoLegged(cfg Config, client *http.Client, domain string) (tokenFunc, error) {
	cred := cfg.Credential
	if !isRSAPrivateKeyPEM(cred.PrivateKeyPEM) {
		return nil, refuse(ErrCredentialInvalid, msgCredential, "private_key")
	}
	tp, err := auth.New2LOTokenProvider(&auth.Options2LO{
		Email:        cred.Email,
		PrivateKey:   append([]byte(nil), cred.PrivateKeyPEM...),
		PrivateKeyID: cred.PrivateKeyID,
		Scopes:       []string{ScopeUserinfoEmail},
		TokenURL:     cfg.Endpoint.TokenURL(),
		Client:       client,
		// A nil Logger makes the library read GOOGLE_SDK_GO_LOGGING_LEVEL and
		// log the signed assertion and the access token to stderr
		// (vendor/github.com/googleapis/gax-go/v2/internallog/internallog.go,
		// New). A non-nil one is used as given.
		Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		return nil, refuse(ErrCredentialInvalid, msgCredential, "client_email")
	}
	return func(ctx context.Context) (*auth.Token, error) {
		t, err := tp.Token(ctx)
		if err != nil {
			return nil, tokenError(err, domain)
		}
		return t, nil
	}, nil
}

// tokenError classifies a mint's failure. A non-2xx answer, which the
// library reports as *auth.Error, is ErrTokenRefused, named by its code
// alone: the body, which the library's own text quotes, is never carried. A
// failure to reach the endpoint is ErrUnreachable, with the transport's own
// words, which name an address and never a header. Anything else is a
// token answer that could not be read.
func tokenError(err error, domain string) error {
	var ae *auth.Error
	if errors.As(err, &ae) && ae.Response != nil {
		code := ae.Response.StatusCode
		return refuse(ErrTokenRefused, msgTokenRefused, domain, code, http.StatusText(code))
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return &wireError{
			msg:      fmt.Sprintf(msgTokenUnreachable, domain, ue.Err.Error()),
			sentinel: ErrUnreachable,
			cause:    ue.Err,
		}
	}
	return refuse(ErrUnreadable, msgTokenUnreadable, domain)
}

// tokenCache holds one token for one identity, in memory only. It is
// FarCast's own, rather than auth.NewCachedTokenProvider, because that one
// hands back its cached token for as long as it is valid
// (vendor/cloud.google.com/go/auth/auth.go, cachedTokenProvider), so a re-mint
// after a 401 would return the very token the server refused.
type tokenCache struct {
	mint tokenFunc
	now  func() time.Time

	mu  sync.Mutex
	tok *auth.Token
}

// token returns the cached token. It mints, holding mu, when there is none, when
// it has expired, or when it is within 225 s of expiring (the vendored cache's
// own early-expiry default, vendor/cloud.google.com/go/auth/auth.go:49).
//
// A token with no expiry is held until invalidate drops it, as the vendored
// Token.IsValid holds one. A failed mint caches nothing.
func (c *tokenCache) token(ctx context.Context) (*auth.Token, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tok != nil && fresh(c.tok, c.now()) {
		return c.tok, nil
	}
	c.tok = nil
	t, err := c.mint(ctx)
	if err != nil {
		return nil, err
	}
	if t == nil || t.Value == "" {
		return nil, refuse(ErrUnreadable, msgTokenEmpty)
	}
	c.tok = t
	return t, nil
}

// invalidate drops the cached token if it is still the one a 401 answered. A
// token another request has already replaced is kept, so concurrent 401s mint once.
func (c *tokenCache) invalidate(rejected *auth.Token) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tok == rejected {
		c.tok = nil
	}
}

// fresh reports whether t may still be sent at now: it has no expiry, or its
// expiry is more than earlyExpiry away.
func fresh(t *auth.Token, now time.Time) bool {
	return t.Expiry.IsZero() || now.Add(earlyExpiry).Before(t.Expiry)
}

// The email suffixes that decide a credential's origin (§3.2).
const (
	googleEmailSuffix   = ".iam.gserviceaccount.com"
	loopbackEmailSuffix = ".invalid"
	googleUniverse      = "googleapis.com"
)

// The pairing refusals of §3.2, each wrapping ErrEndpointRefused.
const (
	msgPairOrigin   = "a %s credential (%s) does not go to a %s endpoint; nothing was sent"
	msgPairTokenURI = "the credential names the token endpoint %q, and a %s endpoint takes its token only from %s; nothing was sent"
	msgPairUniverse = "the credential names the universe %q, and farcast's cluster client works in googleapis.com only; nothing was sent"
	msgPairEndpoint = "the cluster endpoint %q was not classified by ParseEndpoint; nothing was sent"
)

// pair is §3.2's table: each endpoint mode takes only a credential of its own
// origin, a token URI that is absent or the mode's own, and a universe that is
// absent or, in Google mode, googleapis.com. So no single field enables either
// mode. An Endpoint that ParseEndpoint would not have made is refused first.
func pair(ep Endpoint, cred Credential) error {
	if !classified(ep) {
		return refuse(ErrEndpointRefused, msgPairEndpoint, ep.Host)
	}
	domain := emailDomain(cred.Email)
	if origin := credentialOrigin(domain); origin != ep.Mode {
		name := "unknown"
		if origin != 0 {
			name = origin.String()
		}
		return refuse(ErrEndpointRefused, msgPairOrigin, name, domain, ep.Mode)
	}
	if cred.TokenURI != "" && cred.TokenURI != ep.TokenURL() {
		return refuse(ErrEndpointRefused, msgPairTokenURI, cred.TokenURI, ep.Mode, ep.TokenURL())
	}
	switch {
	case ep.Mode == ModeGoogle && cred.UniverseDomain != "" && cred.UniverseDomain != googleUniverse,
		ep.Mode == ModeLoopback && cred.UniverseDomain != "":
		return refuse(ErrEndpointRefused, msgPairUniverse, cred.UniverseDomain)
	}
	return nil
}

// classified reports whether ep is an Endpoint ParseEndpoint could have
// made. Endpoint's fields are exported, so one can be built by hand; this
// repeats the cheap half of §3.1 on it, so a hand-built loopback endpoint
// outside 127.0.0.0/8 or ::1, or a Google one with a CA, pairs with nothing.
func classified(ep Endpoint) bool {
	switch ep.Mode {
	case ModeGoogle:
		return googleHost.MatchString(ep.Host) && ep.Port == "443" && ep.CA == nil
	case ModeLoopback:
		addr, err := netip.ParseAddr(ep.Host)
		return err == nil && !addr.Is4In6() && addr.Zone() == "" && addr.String() == ep.Host &&
			(loopbackV4.Contains(addr) || addr == netip.IPv6Loopback()) &&
			validPort(ep.Port) && ep.CA != nil
	}
	return false
}

// emailDomain is the part of an email after its last @, "" without one. It
// is the only part of an email a message names.
func emailDomain(email string) string {
	i := strings.LastIndexByte(email, '@')
	if i < 0 {
		return ""
	}
	return email[i+1:]
}

// credentialOrigin is where a credential's email says it belongs: Google for
// a service account under .iam.gserviceaccount.com, loopback for a test
// identity under .invalid, and 0, unknown, for anything else.
func credentialOrigin(domain string) Mode {
	d := strings.ToLower(domain)
	switch {
	case len(d) > len(googleEmailSuffix) && strings.HasSuffix(d, googleEmailSuffix):
		return ModeGoogle
	case len(d) > len(loopbackEmailSuffix) && strings.HasSuffix(d, loopbackEmailSuffix):
		return ModeLoopback
	}
	return 0
}
