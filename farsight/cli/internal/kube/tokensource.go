package kube

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"cloud.google.com/go/auth"
)

// This file is the per-role token source the consumers outside the cluster
// client take (M3b.3, wired from M3b.4): Artifact Registry, Cloud Storage
// and IAM's API. It holds no init-time state (TestFederatedHasNoInitTimeState)
// and reads no environment variable, file or argument
// (TestNewFederationURLsAreTheConstants).

// ScopeDevstorageFullControl is Cloud Storage's scope, ScopesStorage's one:
// bucket create and delete, a bucket's IAM policy, and object reads and
// writes (datasphere/internal/providers/gcs/client.go's storageScope).
const ScopeDevstorageFullControl = "https://www.googleapis.com/auth/devstorage.full_control"

// Scopes is one consumer's scopes, from a closed list (N9): every token a
// role's service account is impersonated for, or a key mints, carries one of
// these sets and no other. The zero Scopes is none of them.
type Scopes uint8

const (
	// ScopesCluster is the cluster client's: TokenScopes, cloud-platform then
	// userinfo.email, exactly D5.2's.
	ScopesCluster Scopes = iota + 1
	// ScopesStorage is Cloud Storage's: devstorage.full_control alone.
	ScopesStorage
	// ScopesRegistry is Artifact Registry's, and with it the rest of planck's
	// Google adapter: cloud-platform alone, because Google issues no narrower
	// scope for pkg.dev registries.
	ScopesRegistry

	// scopesIAM is the IAM reader's: TokenScopes too, the set M3a's T4 read
	// the providers with on 2026-11-23. NewIAMReader alone uses it;
	// TokenSourceFor refuses it.
	scopesIAM
)

// List is s's scopes, in the order they are sent, as a fresh slice; nil for
// a value the closed list does not hold.
func (s Scopes) List() []string {
	switch s {
	case ScopesCluster, scopesIAM:
		return TokenScopes()
	case ScopesStorage:
		return []string{ScopeDevstorageFullControl}
	case ScopesRegistry:
		return []string{ScopeCloudPlatform}
	}
	return nil
}

// consumer reports whether s is one a consumer may ask TokenSourceFor for.
func (s Scopes) consumer() bool {
	return s == ScopesCluster || s == ScopesStorage || s == ScopesRegistry
}

// msgTokenSource is TokenSourceFor's refusal. Its %s names the part that
// failed (scopes, service account, private key, token endpoint, universe,
// token source), never its value.
const msgTokenSource = "kube: the token source has no usable %s; nothing was sent"

// msgTokenNoExpiry is a mint whose token came without an expiry, which a
// consumer's cache would hold forever.
const msgTokenNoExpiry = "the token endpoint answered without an expiry"

// roleTokensText is every formatting of a RoleTokens.
const roleTokensText = "role tokens (not printed)"

// RoleTokens is one consumer's token source for one role: Token returns the
// role's service-account token for the consumer's scopes, minted when there
// is none or it is within 225 s of expiring, and Invalidate drops it after a
// 401. It is the token source planck's and datasphere's neutral interfaces
// take (Token's signature is theirs), so they need not import auth.
//
// It is safe for concurrent use: httptransport's cache refreshes in the
// background (vendor/cloud.google.com/go/auth/httptransport/transport.go:90),
// and gRPC asks per call. Its contents are held two pointers deep, and it
// formats as "role tokens (not printed)" under every verb, slog and
// encoding/json.
type RoleTokens struct{ p **roleTokens }

type roleTokens struct {
	role      Identity // "" for a key
	federated bool
	scopes    Scopes
	mint      tokenFunc
	now       func() time.Time // wallNow

	// tokenClient is the client a key's 2LO provider posts its assertion
	// with (tokenHTTPClient), kept so its shape can be checked (R3: the
	// provider holds it unexported); nil for a federated credential, whose
	// mint needs none. Nothing but the provider sends with it.
	tokenClient *http.Client

	mu  sync.Mutex
	tok *auth.Token
}

// TokenSourceFor is a token source for cred, for a consumer with scopes s:
//   - for a federated credential, its mint with s (design D5): the role's one
//     federated token, shared with every other consumer of every copy of
//     cred, and an impersonation of its own, one per RoleTokens;
//   - for a service-account key (reader.key, credentials.yaml's key), the
//     vendored 2LO provider with s's scopes, the token URL fixed to
//     GoogleTokenURL, a logger that discards, and a token client with no
//     proxy, the system roots, TLS 1.2 at least, no redirects, 30 s,
//     User-Agent farcast and no Authorization (tokenTransport).
//
// It calls UnsafeEnvironment first. It refuses, with ErrCredentialInvalid
// and msgTokenSource naming the part, never its value: an s that is not
// ScopesCluster, ScopesStorage or ScopesRegistry; and for a key, an email
// that is not a Google service account's, a key the 2LO signer cannot use, a
// token_uri other than GoogleTokenURL and a universe other than
// googleapis.com. A key's token_uri is never dialled. It sends nothing.
func TokenSourceFor(cred Credential, s Scopes) (*RoleTokens, error) {
	return tokenSourceFor(cred, s, Endpoint{Mode: ModeGoogle})
}

// tokenSourceFor is TokenSourceFor with the endpoint a key's token is minted
// at: Google's, whose TokenURL is GoogleTokenURL and whose token client
// trusts the system roots; export_test.go points it at a loopback one.
func tokenSourceFor(cred Credential, s Scopes, tokenAt Endpoint) (*RoleTokens, error) {
	if err := UnsafeEnvironment(); err != nil {
		return nil, err
	}
	if !s.consumer() {
		return nil, refuse(ErrCredentialInvalid, msgTokenSource, "scopes")
	}
	if fc := cred.fed(); fc != nil {
		return newRoleTokens(fc.role, true, s, fc.minter(s)), nil
	}
	switch {
	case !isServiceAccountEmail(cred.Email):
		return nil, refuse(ErrCredentialInvalid, msgTokenSource, "service account")
	case !isRSAPrivateKeyPEM(cred.PrivateKeyPEM):
		return nil, refuse(ErrCredentialInvalid, msgTokenSource, "private key")
	case cred.TokenURI != "" && cred.TokenURI != GoogleTokenURL:
		return nil, refuse(ErrCredentialInvalid, msgTokenSource, "token endpoint")
	case cred.UniverseDomain != "" && cred.UniverseDomain != googleUniverse:
		return nil, refuse(ErrCredentialInvalid, msgTokenSource, "universe")
	}
	client := tokenHTTPClient(tokenAt)
	tp, err := auth.New2LOTokenProvider(&auth.Options2LO{
		Email:        cred.Email,
		PrivateKey:   append([]byte(nil), cred.PrivateKeyPEM...),
		PrivateKeyID: cred.PrivateKeyID,
		Scopes:       s.List(),
		TokenURL:     tokenAt.TokenURL(),
		Client:       client,
		// A nil Logger reads GOOGLE_SDK_GO_LOGGING_LEVEL and logs the
		// assertion and the token (twoLegged's comment).
		Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		return nil, refuse(ErrCredentialInvalid, msgTokenSource, "service account")
	}
	domain := emailDomain(cred.Email)
	mint := func(ctx context.Context) (*auth.Token, error) {
		t, err := tp.Token(ctx)
		if err != nil {
			return nil, tokenError(err, domain)
		}
		return t, nil
	}
	rt := newRoleTokens("", false, s, mint)
	rt.get().tokenClient = client
	return rt, nil
}

// newRoleTokens holds one consumer's mint two pointers deep.
func newRoleTokens(role Identity, federated bool, s Scopes, mint tokenFunc) *RoleTokens {
	v := &roleTokens{role: role, federated: federated, scopes: s, mint: mint, now: wallNow}
	return &RoleTokens{p: &v}
}

// get is the contents; nil for the zero RoleTokens.
func (r RoleTokens) get() *roleTokens {
	if r.p == nil {
		return nil
	}
	return *r.p
}

// Token is the consumer's token's value and its expiry on the wall clock (no
// monotonic reading). It mints, holding the consumer's lock, when there is no
// token, or the one held is within 225 s of its expiry, so concurrent callers
// mint once. It never returns an empty value or a zero expiry: either is
// ErrUnreadable, and nothing is held. A failed mint holds nothing.
func (r RoleTokens) Token(ctx context.Context) (string, time.Time, error) {
	v := r.get()
	if v == nil {
		return "", time.Time{}, refuse(ErrCredentialInvalid, msgTokenSource, "token source")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.tok != nil && v.now().Add(earlyExpiry).Before(v.tok.Expiry) {
		return v.tok.Value, v.tok.Expiry, nil
	}
	v.tok = nil
	t, err := v.mint(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	if t == nil || t.Value == "" {
		return "", time.Time{}, refuse(ErrUnreadable, msgTokenEmpty)
	}
	if t.Expiry.IsZero() {
		return "", time.Time{}, refuse(ErrUnreadable, msgTokenNoExpiry)
	}
	held := &auth.Token{Value: t.Value, Type: t.Type, Expiry: t.Expiry.Round(0)}
	v.tok = held
	return held.Value, held.Expiry, nil
}

// Invalidate drops the consumer's token if its value is token, the one a
// server answered 401 to; one another caller has already replaced is kept,
// so concurrent 401s mint once. It never drops the role's federated token:
// the next Token impersonates again with it, and does not exchange.
func (r RoleTokens) Invalidate(token string) {
	v := r.get()
	if v == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.tok != nil && v.tok.Value == token {
		v.tok = nil
	}
}

// Role is the federated credential's role; "" for a key.
func (r RoleTokens) Role() Identity {
	if v := r.get(); v != nil {
		return v.role
	}
	return ""
}

// Federated reports whether the tokens come from a federated credential.
func (r RoleTokens) Federated() bool {
	v := r.get()
	return v != nil && v.federated
}

// Scopes is the consumer's scopes.
func (r RoleTokens) Scopes() Scopes {
	if v := r.get(); v != nil {
		return v.scopes
	}
	return 0
}

// String is "role tokens (not printed)".
func (r RoleTokens) String() string { return roleTokensText }

// GoString is "role tokens (not printed)".
func (r RoleTokens) GoString() string { return roleTokensText }

// Format writes "role tokens (not printed)" for every verb.
func (r RoleTokens) Format(f fmt.State, verb rune) { _, _ = io.WriteString(f, roleTokensText) }

// LogValue is slog.StringValue("role tokens (not printed)").
func (r RoleTokens) LogValue() slog.Value { return slog.StringValue(roleTokensText) }

// MarshalJSON is the JSON string "role tokens (not printed)".
func (r RoleTokens) MarshalJSON() ([]byte, error) { return json.Marshal(roleTokensText) }
