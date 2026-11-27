package kubetest

import (
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/kube"
)

// The IAM API fake (M3b.3): the two reads kube.IAMReader makes at IAM's API
// host, of one provider and of a pool's providers, answered as Google's JSON
// as devicekey's CheckNamedProvider, ParseProvider and ParseProviders read it
// [PROV for the get, which M3a's T4 read on 2026-11-23; inf for the list].
//
// Every request is recorded first, with As the service account whose token it
// carried ("" none, "?" no live service-account token), and answered, in
// this order, with Google's JSON error shape on failure:
//  1. WithIAMAPIAnswer's answer, when it is given;
//  2. 404 NOT_FOUND for a path that is neither
//     /v1/projects/<n>/locations/global/workloadIdentityPools/<pool>/providers
//     nor that followed by /<provider>;
//  3. 405 for a method other than GET;
//  4. 401 UNAUTHENTICATED with no bearer, or one that is not a live
//     service-account token from IAM Credentials' registry: a federated token
//     and a Server's 2LO token are refused here;
//  5. 403 PERMISSION_DENIED for a token whose scopes do not hold
//     cloud-platform [inf: Google's reason is ACCESS_TOKEN_SCOPE_INSUFFICIENT],
//     and for an account GrantPoolViewer did not grant;
//  6. 400 INVALID_ARGUMENT for a project number, pool or provider out of
//     Google's shape, a get with any query, and a list whose query holds a
//     key other than pageSize, pageToken and showDeleted, a key twice, a
//     pageSize that is not an integer from 0, a showDeleted that is not true
//     or false, or a pageToken this list did not give: stricter than Google
//     [inf], so a client that sends more than it means to is caught;
//  7. a get: 404 NOT_FOUND for a provider AddProvider never added, else 200
//     with the provider, a DELETED one with its state and expireTime;
//  8. a list: 200 with the pool's providers in ID order, the DELETED ones
//     only under showDeleted=true, pageSize a page (0 or absent is 50, more
//     than 100 is 100), and a nextPageToken on every page but the last.
//
// A provider is
// {"name","state","disabled" (only when true),"attributeMapping",
// "attributeCondition","expireTime" (only when DELETED),"x509":{"trustStore":
// {"trustAnchors":[{"pemCertificate"}]}}}, with no displayName and no
// description, and a list is {"workloadIdentityPoolProviders":[…],
// "nextPageToken":…}, each key left out when empty, as Google leaves out an
// empty field [inf].

const (
	// The providers' collection path's fixed parts.
	iamAPIProjects  = "/v1/projects/"
	iamAPILocations = "locations"
	iamAPIGlobal    = "global"
	iamAPIPools     = "workloadIdentityPools"
	iamAPIProviders = "providers"

	// defaultProvidersPage and maxProvidersPage are a list's pageSize when
	// none is given, and the most it takes [PROV].
	defaultProvidersPage = 50
	maxProvidersPage     = 100

	// pageTokenPrefix and pageTokenSuffix frame a list's page token around
	// its filter and the offset of the page it names: "kubetest+page/" then
	// "d" (showDeleted) or "a" (ACTIVE alone), "/", the offset, and "=". It
	// is in devicekey's token shape, and holds '+', '/' and '=' on purpose,
	// so a client that does not escape it in the query sends another token.
	pageTokenPrefix = "kubetest+page/"
	pageTokenSuffix = "="
)

// providerAnswer is one provider as the IAM API answers it, in Google's
// field order.
type providerAnswer struct {
	Name               string            `json:"name"`
	State              string            `json:"state"`
	Disabled           bool              `json:"disabled,omitempty"`
	AttributeMapping   map[string]string `json:"attributeMapping"`
	AttributeCondition string            `json:"attributeCondition"`
	ExpireTime         string            `json:"expireTime,omitempty"`
	X509               providerX509      `json:"x509"`
}

type providerX509 struct {
	TrustStore providerTrustStore `json:"trustStore"`
}

type providerTrustStore struct {
	TrustAnchors []providerAnchor `json:"trustAnchors"`
}

type providerAnchor struct {
	PEMCertificate string `json:"pemCertificate"`
}

// providersPage is one page of a list.
type providersPage struct {
	Providers     []providerAnswer `json:"workloadIdentityPoolProviders,omitempty"`
	NextPageToken string           `json:"nextPageToken,omitempty"`
}

// answer is p as the IAM API answers it.
func (p federationProvider) answer() providerAnswer {
	a := providerAnswer{
		Name:               p.name(),
		State:              p.state,
		Disabled:           p.disabled,
		AttributeMapping:   map[string]string{},
		AttributeCondition: p.condition,
	}
	for k, v := range p.mapping {
		a.AttributeMapping[k] = v
	}
	if p.state == providerDeleted {
		a.ExpireTime = p.expireTime.Format(time.RFC3339Nano)
	}
	for _, pemText := range p.anchorsPEM {
		a.X509.TrustStore.TrustAnchors = append(a.X509.TrustStore.TrustAnchors, providerAnchor{PEMCertificate: pemText})
	}
	return a
}

// serveIAMAPI is the IAM API fake's handler.
func (f *Federation) serveIAMAPI(w http.ResponseWriter, r *http.Request) {
	req := newFederationRequest("iamapi", r)
	bearer, hasBearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	sa, known := f.liveServiceAccount(bearer)
	switch {
	case r.Header.Get("Authorization") == "":
	case hasBearer && known:
		req.As = sa.Email
	default:
		req.As = "?"
		known = false
	}
	f.record(req)

	if a := f.cfg.iamAPIAnswer; a != nil {
		writeAnswer(w, a.code, a.body)
		return
	}
	fail := func(code int, status, message string) {
		writeJSON(w, code, googleError{Error: googleErrorBody{Code: code, Message: message, Status: status}})
	}
	number, pool, provider, isList, ok := providersPath(r.URL.Path)
	switch {
	case !ok || r.URL.RawPath != "":
		fail(http.StatusNotFound, "NOT_FOUND", "the IAM API fake answers a pool's providers and one provider only")
	case r.Method != http.MethodGet:
		fail(http.StatusMethodNotAllowed, "INVALID_ARGUMENT", "the IAM API fake takes GET only")
	case !known:
		fail(http.StatusUnauthorized, "UNAUTHENTICATED", "the bearer is not a live service-account token IAM Credentials issued")
	case !slices.Contains(sa.Scopes, kube.ScopeCloudPlatform):
		fail(http.StatusForbidden, "PERMISSION_DENIED", "the token's scopes do not hold cloud-platform")
	case !f.poolViewer(sa.Email):
		fail(http.StatusForbidden, "PERMISSION_DENIED", "the service account may not view the workload identity pool")
	case !isProjectNumber(number) || !isPoolOrProviderID(pool) || (!isList && !isPoolOrProviderID(provider)):
		fail(http.StatusBadRequest, "INVALID_ARGUMENT", "the resource name is not Google's shape")
	case isList:
		f.answerProviders(w, r, number, pool, fail)
	case r.URL.RawQuery != "":
		fail(http.StatusBadRequest, "INVALID_ARGUMENT", "a provider's get takes no query")
	default:
		p, found := f.provider(number, pool, provider)
		if !found {
			fail(http.StatusNotFound, "NOT_FOUND", "no such provider")
			return
		}
		writeJSON(w, http.StatusOK, p.answer())
	}
}

// answerProviders answers a list, its query read strictly.
func (f *Federation) answerProviders(w http.ResponseWriter, r *http.Request, number, pool string, fail func(int, string, string)) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		fail(http.StatusBadRequest, "INVALID_ARGUMENT", "the query does not parse")
		return
	}
	for k, v := range q {
		if (k != "pageSize" && k != "pageToken" && k != "showDeleted") || len(v) != 1 {
			fail(http.StatusBadRequest, "INVALID_ARGUMENT", "the query holds a key the list does not take, or a key twice")
			return
		}
	}
	size := defaultProvidersPage
	if s, ok := q["pageSize"]; ok {
		n, err := strconv.Atoi(s[0])
		if err != nil || n < 0 || strconv.Itoa(n) != s[0] {
			fail(http.StatusBadRequest, "INVALID_ARGUMENT", "pageSize is not an integer from 0")
			return
		}
		if n > 0 {
			size = min(n, maxProvidersPage)
		}
	}
	showDeleted := false
	if s, ok := q["showDeleted"]; ok {
		switch s[0] {
		case "true":
			showDeleted = true
		case "false":
		default:
			fail(http.StatusBadRequest, "INVALID_ARGUMENT", "showDeleted is not true or false")
			return
		}
	}
	all := f.poolProviders(number, pool, showDeleted)
	offset := 0
	if s, ok := q["pageToken"]; ok {
		n, ok := parsePageToken(s[0], showDeleted)
		if !ok || n > len(all) {
			fail(http.StatusBadRequest, "INVALID_ARGUMENT", "the page token is not one this list gave")
			return
		}
		offset = n
	}
	end := min(offset+size, len(all))
	var page providersPage
	for _, p := range all[offset:end] {
		page.Providers = append(page.Providers, p.answer())
	}
	if end < len(all) {
		page.NextPageToken = pageToken(end, showDeleted)
	}
	writeJSON(w, http.StatusOK, page)
}

// provider is the pool's provider by its ID.
func (f *Federation) provider(number, pool, id string) (federationProvider, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.providers {
		if p.project == number && p.pool == pool && p.id == id {
			return p, true
		}
	}
	return federationProvider{}, false
}

// poolProviders are the pool's providers in ID order, the DELETED ones only
// when showDeleted.
func (f *Federation) poolProviders(number, pool string, showDeleted bool) []federationProvider {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []federationProvider
	for _, p := range f.providers {
		if p.project == number && p.pool == pool && (showDeleted || p.state != providerDeleted) {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(a, b federationProvider) int { return strings.Compare(a.id, b.id) })
	return out
}

// pageToken is the token of the page that starts at offset.
func pageToken(offset int, showDeleted bool) string {
	return pageTokenFilter(showDeleted) + strconv.Itoa(offset) + pageTokenSuffix
}

// pageTokenFilter is a page token's part before its offset.
func pageTokenFilter(showDeleted bool) string {
	if showDeleted {
		return pageTokenPrefix + "d/"
	}
	return pageTokenPrefix + "a/"
}

// parsePageToken is pageToken's offset, from 1, for a token given under the
// same filter and written as pageToken writes it; false for anything else.
func parsePageToken(token string, showDeleted bool) (int, bool) {
	digits, ok := strings.CutPrefix(token, pageTokenFilter(showDeleted))
	if !ok {
		return 0, false
	}
	digits, ok = strings.CutSuffix(digits, pageTokenSuffix)
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(digits)
	if err != nil || n <= 0 || strconv.Itoa(n) != digits {
		return 0, false
	}
	return n, true
}

// providersPath reads an IAM API path: a pool's providers (isList), or one
// provider. Its parts are returned as they stand, for the caller to check.
func providersPath(path string) (number, pool, provider string, isList, ok bool) {
	rest, ok := strings.CutPrefix(path, iamAPIProjects)
	if !ok {
		return "", "", "", false, false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 6 && len(parts) != 7 {
		return "", "", "", false, false
	}
	if parts[1] != iamAPILocations || parts[2] != iamAPIGlobal || parts[3] != iamAPIPools || parts[5] != iamAPIProviders {
		return "", "", "", false, false
	}
	if len(parts) == 6 {
		return parts[0], parts[4], "", true, true
	}
	return parts[0], parts[4], parts[6], false, true
}

// isProjectNumber is ^[0-9]{1,20}$.
func isProjectNumber(s string) bool {
	if len(s) < 1 || len(s) > 20 {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// isPoolOrProviderID is ^[a-z0-9-]{4,32}$, not starting "gcp-" [MGMT].
func isPoolOrProviderID(s string) bool {
	if len(s) < 4 || len(s) > 32 || strings.HasPrefix(s, "gcp-") {
		return false
	}
	for i := range len(s) {
		if c := s[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}
