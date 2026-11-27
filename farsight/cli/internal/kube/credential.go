package kube

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/auth"
)

// Credential is how a client gets its token: one service account's signing
// key (the 2LO route, §3.3), or, built only by NewFederatedCredential, a
// role's federated credential (design D5): a device leaf exchanged at STS and
// the role's service account impersonated at IAM Credentials.
//
// The federated part is held two pointers deep, as ClientIdentity holds its
// contents, so a Credential printed with any verb shows at most an address
// for it, and encoding/json, which skips an unexported field, nothing. Every
// copy of a federated Credential shares that part, and with it one exchange
// cache: one federated token per credential, which is D5.1's one per role per
// process only while a caller builds one credential per role and hands it to
// every consumer. A second credential for the same role exchanges on its own.
type Credential struct {
	Email          string
	PrivateKeyID   string // "" when unknown; sent as the JWT kid
	PrivateKeyPEM  []byte // RSA, PKCS#1 or PKCS#8
	TokenURI       string // as the key file recorded it, "" when absent; paired (§3.2), never dialled
	UniverseDomain string // as the key file recorded it, "" when absent; paired (§3.2)

	federated **federatedCredential // nil for a key; set by NewFederatedCredential alone
}

// Federated reports whether c is a federated credential, made by
// NewFederatedCredential.
func (c Credential) Federated() bool { return c.fed() != nil }

// Role is the role a federated credential acts as, Reader or Writer, and ""
// for a service-account key, whose role the caller states in Config.Identity.
func (c Credential) Role() Identity {
	if fc := c.fed(); fc != nil {
		return fc.role
	}
	return ""
}

// fed is the federated part; nil for a service-account key.
func (c Credential) fed() *federatedCredential {
	if c.federated == nil {
		return nil
	}
	return *c.federated
}

// federatedCredential is a federated Credential's part: everything a mint
// needs, and the one exchange cache every copy of the Credential shares. It
// is reached only through a pointer, never copied.
type federatedCredential struct {
	fed      *Federation
	audience string
	id       ClientIdentity
	email    string
	role     Identity
	cache    exchangeCache
}

// msgFederatedCredential is NewFederatedCredential's refusal. Its %s names
// the part that failed (federation, audience, client certificate, service
// account, role), never its value.
const msgFederatedCredential = "kube: the federated credential has no usable %s; nothing was sent"

// NewFederatedCredential is a role's federated credential (design D5): fed's
// exchange of id at audience, then generateAccessToken for email, the role's
// service account. It sets Email to email, which messages name by its domain
// alone, and nothing else of the key fields, which pair requires empty.
//
// Before anything can be sent it refuses, with ErrCredentialInvalid and
// msgFederatedCredential naming the part, never its value: a nil Federation;
// an audience Exchange's guard refuses (Audience's number form alone); the
// zero ClientIdentity, or one whose chain does not parse or whose signer is
// not the leaf's; an email that is not a service account's
// (GenerateAccessTokenPath's shape); and a role other than Reader or Writer.
//
// It sends nothing. The first token a client or a RoleTokens asks for runs
// the exchange; every later one, until that federated token is within 225 s
// of its expiry, impersonates with it.
func NewFederatedCredential(fed *Federation, audience string, id ClientIdentity, email string, role Identity) (Credential, error) {
	switch {
	case fed == nil:
		return Credential{}, refuse(ErrCredentialInvalid, msgFederatedCredential, "federation")
	case !checkAudience(audience):
		return Credential{}, refuse(ErrCredentialInvalid, msgFederatedCredential, "audience")
	}
	if _, ok := clientLeaf(id); !ok {
		return Credential{}, refuse(ErrCredentialInvalid, msgFederatedCredential, "client certificate")
	}
	switch {
	case !isServiceAccountEmail(email):
		return Credential{}, refuse(ErrCredentialInvalid, msgFederatedCredential, "service account")
	case role != Reader && role != Writer:
		return Credential{}, refuse(ErrCredentialInvalid, msgFederatedCredential, "role")
	}
	v := &federatedCredential{fed: fed, audience: audience, id: id, email: email, role: role}
	v.cache.now = wallNow
	return Credential{Email: email, federated: &v}, nil
}

// productExchange is the one exchange a product path makes (D5.1): the
// role's audience and leaf, the leaf alone as the subject token, and
// cloud-platform alone. No product caller passes NewExchangeRequest a
// subject chain or scopes; TestProductExchangesCarryNoKnobs holds that.
func productExchange(audience string, id ClientIdentity) ExchangeRequest {
	return NewExchangeRequest(audience, id, nil, nil)
}

// federatedEarlyExpiry is how long before its expiry a federated token is
// exchanged anew: earlyExpiry, the same 225 s as a service account's token.
const federatedEarlyExpiry = earlyExpiry

// exchangeCache holds a role's current federated token, in memory only. It
// holds mu across the exchange, as tokenCache holds its own across a mint,
// so consumers asking at once exchange once.
type exchangeCache struct {
	now func() time.Time // wallNow

	mu  sync.Mutex
	tok *auth.Token
}

// federated returns the cached federated token while it is more than
// federatedEarlyExpiry from its expiry on the wall clock, and otherwise
// exchanges, holding mu. A failed exchange caches nothing.
func (c *exchangeCache) federated(ctx context.Context, fc *federatedCredential) (*auth.Token, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tok != nil && c.now().Add(federatedEarlyExpiry).Before(c.tok.Expiry) {
		return c.tok, nil
	}
	c.tok = nil
	ans, err := fc.fed.Exchange(ctx, productExchange(fc.audience, fc.id))
	if err != nil {
		return nil, err
	}
	tok := ans.Token()
	if tok == nil || tok.Value == "" {
		return nil, refuse(ErrUnreadable, msgTokenEmpty)
	}
	c.tok = tok
	return tok, nil
}

// invalidate drops the cached federated token if it is still the one IAM
// Credentials refused. A token another consumer has already replaced is
// kept, so concurrent refusals exchange once.
func (c *exchangeCache) invalidate(rejected *auth.Token) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tok == rejected {
		c.tok = nil
	}
}

// mint is one consumer's federated mint (design D5): the role's federated
// token from the shared cache, then generateAccessToken for the role's
// service account with s's scopes. When IAM Credentials answers 401, the
// federated token is dropped and exchanged once more, and the impersonation
// is made once more; a second failure is the error. Every other failure is
// returned as it is. The token's Expiry is impersonationAnswer's: UTC, with
// no monotonic reading.
//
// A cluster 401 never reaches here as such: tokenCache drops the service
// account's token and calls mint again, which impersonates with the cached
// federated token and does not exchange.
func (fc *federatedCredential) mint(ctx context.Context, s Scopes) (*auth.Token, error) {
	fedTok, err := fc.cache.federated(ctx, fc)
	if err != nil {
		return nil, err
	}
	sa, err := fc.fed.Impersonate(ctx, fedTok, fc.email, s)
	var fe *FederationError
	if errors.As(err, &fe) && fe.Step == StepImpersonate && fe.Status == http.StatusUnauthorized {
		fc.cache.invalidate(fedTok)
		if fedTok, err = fc.cache.federated(ctx, fc); err != nil {
			return nil, err
		}
		sa, err = fc.fed.Impersonate(ctx, fedTok, fc.email, s)
	}
	if err != nil {
		return nil, err
	}
	return sa, nil
}

// minter is mint for one consumer's scopes, as a tokenFunc.
func (fc *federatedCredential) minter(s Scopes) tokenFunc {
	return func(ctx context.Context) (*auth.Token, error) { return fc.mint(ctx, s) }
}

// msgCredential is ParseServiceAccountJSON's one refusal. Its %s names the
// field that failed and never the field's value.
const msgCredential = "the stored service-account key is not a service-account key farcast uses (%s)"

// serviceAccountFile is the part of a Google service-account key file farcast
// reads. Every other field (project_id, client_id, the certificate URLs) is
// ignored: Google's files carry more than this, and their presence decides
// nothing.
type serviceAccountFile struct {
	Type           string `json:"type"`
	ClientEmail    string `json:"client_email"`
	PrivateKey     string `json:"private_key"`
	PrivateKeyID   string `json:"private_key_id"`
	TokenURI       string `json:"token_uri"`
	UniverseDomain string `json:"universe_domain"`
}

// ParseServiceAccountJSON reads a service-account key file's JSON (credentials.yaml's
// service_account_key) without deciding where it may be used (§3.2). It refuses,
// with ErrCredentialInvalid, anything that is not a service-account key with an
// email and an RSA private key. Where the key may go is kube.New's pairing rule.
//
// So a Google key and a loopback test key both parse: an email's domain, a
// token_uri on 127.0.0.1 and a universe_domain are kept as recorded, for the
// pairing to judge.
func ParseServiceAccountJSON(b []byte) (Credential, error) {
	var f serviceAccountFile
	if err := json.Unmarshal(b, &f); err != nil {
		// A type error names the field it met, never the value; any other
		// failure is the body as a whole.
		var te *json.UnmarshalTypeError
		if errors.As(err, &te) && te.Field != "" {
			return Credential{}, refuse(ErrCredentialInvalid, msgCredential, te.Field)
		}
		return Credential{}, refuse(ErrCredentialInvalid, msgCredential, "not a JSON object")
	}
	if f.Type != "service_account" {
		return Credential{}, refuse(ErrCredentialInvalid, msgCredential, "type")
	}
	if local, domain, ok := strings.Cut(f.ClientEmail, "@"); !ok || local == "" || domain == "" || strings.Contains(domain, "@") {
		return Credential{}, refuse(ErrCredentialInvalid, msgCredential, "client_email")
	}
	if !isRSAPrivateKeyPEM([]byte(f.PrivateKey)) {
		return Credential{}, refuse(ErrCredentialInvalid, msgCredential, "private_key")
	}
	if f.TokenURI != "" {
		u, err := url.Parse(f.TokenURI)
		if err != nil || !u.IsAbs() || u.Scheme != "https" || u.Host == "" {
			return Credential{}, refuse(ErrCredentialInvalid, msgCredential, "token_uri")
		}
	}
	return Credential{
		Email:          f.ClientEmail,
		PrivateKeyID:   f.PrivateKeyID,
		PrivateKeyPEM:  []byte(f.PrivateKey),
		TokenURI:       f.TokenURI,
		UniverseDomain: f.UniverseDomain,
	}, nil
}

// isRSAPrivateKeyPEM reports whether pemBytes holds a PEM block whose
// contents parse as an RSA private key, in PKCS#8 or PKCS#1, the two forms
// the vendored 2LO signer reads (cloud.google.com/go/auth internal.ParseKey).
// The 2LO header is always RS256, so any other key type is refused here
// rather than at the first mint.
func isRSAPrivateKeyPEM(pemBytes []byte) bool {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return false
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		_, ok := k.(*rsa.PrivateKey)
		return ok
	}
	_, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	return err == nil
}
