package kubetest

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/kube"
)

const (
	// jwtBearerGrant is the 2LO grant type (RFC 7523), as the vendored
	// cloud.google.com/go/auth sends it (auth.go, defaultGrantType).
	jwtBearerGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer"

	// maxAssertionLifetime is Google's limit: "a maximum of 1 hour after the
	// issued time" (developers.google.com/identity/protocols/oauth2/service-account).
	maxAssertionLifetime = 3600
	// maxClockSkew is how far iat may be from the server's clock, either way.
	maxClockSkew = 5 * 60

	// tokenLifetime is the expires_in of every minted token.
	tokenLifetime = 3600
)

// registeredKey is one public key an email's assertions may be signed with.
type registeredKey struct {
	id  string
	pub *rsa.PublicKey
}

// tokenInfo is one minted token: the id of the key that verified the
// assertion, and the email (iss) it was minted for.
type tokenInfo struct {
	id, email string
	revoked   bool
}

// tokenAnswer is the token endpoint's answer, in the order Google writes it.
type tokenAnswer struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// oauthError is the token endpoint's refusal (RFC 6749 §5.2). The description
// says which rule failed, so a failing test names it.
type oauthError struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// verified is what the checks of one assertion found.
type verified struct {
	id, email, kid string
	err            error
}

// serveToken is POST /token. A verified assertion mints
// "kubetest:<id>:<n>", or answers what WithTokenAnswer gives; anything else
// answers 400 invalid_grant, and a method other than POST 405.
func (s *Server) serveToken(w http.ResponseWriter, r *http.Request, req Request) {
	v := s.verifyAssertion(r.Method, req.ContentType, req.Body)
	req.KeyID = v.kid
	if v.err == nil {
		req.As = v.id
	}
	s.record(req)
	if !s.hold(r.Context(), req) {
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, oauthError{Error: "invalid_request", Description: "the token endpoint takes POST only"})
		return
	}
	if v.err != nil {
		writeJSON(w, http.StatusBadRequest, oauthError{Error: "invalid_grant", Description: v.err.Error()})
		return
	}
	if f := s.opts.tokenAnswer; f != nil {
		if code, body, ok := f(v.email); ok {
			writeAnswer(w, code, body)
			return
		}
	}
	s.mu.Lock()
	s.minted++
	token := fmt.Sprintf("kubetest:%s:%d", v.id, s.minted)
	s.tokens[token] = &tokenInfo{id: v.id, email: v.email}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, tokenAnswer{AccessToken: token, TokenType: "Bearer", ExpiresIn: tokenLifetime})
}

// verifyAssertion applies §2.2's /token rules to one request: a form-encoded
// POST whose grant_type is the JWT bearer grant and whose assertion is an
// RS256 JWT; its iss a registered email whose key verifies the signature; its
// aud "https://"+Endpoint()+"/token"; its scope exactly
// kube.ScopeUserinfoEmail; iat and exp both present, 0 < exp − iat ≤ 3600,
// and iat within five minutes of the server's clock. The vendored encoder
// sends iat = now − 10 s and exp = iat + 3600
// (vendor/cloud.google.com/go/auth/internal/jwt/jwt.go, Claims.encode).
func (s *Server) verifyAssertion(method, contentType string, body []byte) verified {
	var v verified
	fail := func(format string, a ...any) verified {
		v.err = fmt.Errorf(format, a...)
		return v
	}
	if method != http.MethodPost {
		return fail("not a POST")
	}
	if mt, _, err := mime.ParseMediaType(contentType); err != nil || mt != "application/x-www-form-urlencoded" {
		return fail("the body is not form-encoded")
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return fail("the form does not parse")
	}
	if g := form["grant_type"]; len(g) != 1 || g[0] != jwtBearerGrant {
		return fail("grant_type is not %s", jwtBearerGrant)
	}
	as := form["assertion"]
	if len(as) != 1 {
		return fail("the form carries %d assertions, not one", len(as))
	}
	parts := strings.Split(as[0], ".")
	if len(parts) != 3 {
		return fail("the assertion is not a JWS of three parts")
	}
	headerJSON, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	claimsJSON, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err := errors.Join(err1, err2, err3); err != nil {
		return fail("the assertion is not base64url")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return fail("the assertion's header is not JSON")
	}
	v.kid = header.Kid
	if header.Alg != "RS256" {
		return fail("the assertion's alg is %q, not RS256", header.Alg)
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(claimsJSON, &claims); err != nil || claims == nil {
		return fail("the assertion's claims are not a JSON object")
	}

	iss, _ := claimString(claims, "iss")
	s.mu.Lock()
	keys := slices.Clone(s.keys[iss])
	s.mu.Unlock()
	if iss == "" || len(keys) == 0 {
		return fail("iss %q is not a registered email", iss)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	id := ""
	for _, k := range keys {
		if rsa.VerifyPKCS1v15(k.pub, crypto.SHA256, digest[:], sig) == nil {
			id = k.id
			break
		}
	}
	if id == "" {
		return fail("the signature verifies against no key registered for %s", iss)
	}
	wantAud := "https://" + s.endpoint + tokenPath
	if aud, ok := claimString(claims, "aud"); !ok || aud != wantAud {
		return fail("aud is not %s", wantAud)
	}
	if scope, ok := claimString(claims, "scope"); !ok || scope != kube.ScopeUserinfoEmail {
		return fail("scope is not exactly %s", kube.ScopeUserinfoEmail)
	}
	iat, okIat := claimInt(claims, "iat")
	exp, okExp := claimInt(claims, "exp")
	if !okIat || !okExp {
		return fail("iat and exp must both be present, as integers")
	}
	if life := exp - iat; life <= 0 || life > maxAssertionLifetime {
		return fail("exp − iat is %d s; it must be more than 0 and at most %d", life, maxAssertionLifetime)
	}
	if now := time.Now().Unix(); iat < now-maxClockSkew || iat > now+maxClockSkew {
		return fail("iat is %d s from the server's clock; at most %d is allowed", iat-now, maxClockSkew)
	}
	v.id, v.email = id, iss
	return v
}

// claimString is a string claim, and whether it is present as one.
func claimString(claims map[string]json.RawMessage, name string) (string, bool) {
	raw, ok := claims[name]
	if !ok {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// claimInt is an integer claim (NumericDate, in whole seconds), and whether
// it is present as one.
func claimInt(claims map[string]json.RawMessage, name string) (int64, bool) {
	raw, ok := claims[name]
	if !ok {
		return 0, false
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, false
	}
	return n, true
}

// authenticate reads a request's bearer. It returns the token's identity
// and the request's As: "" with no Authorization header at all, "?" for any
// header that carries no live kubetest token, and the identity's id otherwise.
func (s *Server) authenticate(header string) (*tokenInfo, string) {
	if header == "" {
		return nil, ""
	}
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return nil, "?"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	info := s.tokens[token]
	if info == nil || info.revoked {
		return nil, "?"
	}
	c := *info
	return &c, c.id
}
