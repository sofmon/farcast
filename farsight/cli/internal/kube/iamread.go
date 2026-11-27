package kube

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
)

// This file is the reader's read of the instance's providers at IAM's API
// host (M3b.3; Q3, answered 2026-11-26: IAM's API host is one more bearer
// host, for the reader's service-account token only). It holds no init-time
// state (TestFederatedHasNoInitTimeState) and reads no environment variable,
// file or argument (TestNewFederationURLsAreTheConstants). kube does not
// import devicekey: it returns each answer's bytes, and cli parses them with
// devicekey's CheckNamedProvider, ParseProvider and ParseProviders.

// IAMHost is IAM's API host [PROV; M3a's T4 read the providers there on
// 2026-11-23].
const IAMHost = "iam.googleapis.com"

// The provider reads' fixed values.
const (
	// maxProviderAnswer is the most of one answer a read takes, read +1 and
	// refused, never cut: devicekey.MaxProvidersList, which its parsers refuse
	// beyond.
	maxProviderAnswer = 1 << 20
	// maxProviderPages is the most pages a list follows; a list that asks
	// for more is refused.
	maxProviderPages = 50
	// maxPageToken is the longest nextPageToken taken, devicekey's.
	maxPageToken = 4096

	// The paths' fixed parts [PROV]: audiencePools and audienceProvider are
	// the audience's own.
	iamProjectsPrefix  = "/v1/projects/"
	iamProvidersSuffix = "/providers"

	// providerListQuery is every list's query before its page token: ten
	// providers a page, and the soft-deleted ones too, which a list shows
	// only when asked [PROV]. A provider at Google's trust-store limits is
	// some tens of KB (devicekey.MaxProvidersList's comment), so ten keep a
	// page under maxProviderAnswer.
	providerListQuery = "pageSize=10&showDeleted=true"

	// The words an unusable answer gives in place of a field.
	answerOversizeIAM   = "the answer is larger than 1 MiB"
	answerKeyTwice      = "a key given twice"
	answerTokenRepeated = "a nextPageToken given before"
	answerTooManyPages  = "more than 50 pages"

	// iamReaderText is every formatting of an IAMReader.
	iamReaderText = "IAM reader (not printed)"
)

// The IAM reader's refusals before anything is sent.
const (
	msgIAMRequest      = "kube: the IAM read has no usable %s; nothing was sent" // project number, pool, provider, request
	msgIAMReaderKey    = "kube: IAM's API is read with the reader's federated credential alone, and this credential is not federated; nothing was sent"
	msgIAMReaderWriter = "kube: IAM's API is read with the reader's federated credential alone, and this one is the writer's; nothing was sent"
)

// IAMReader reads the instance's workload identity providers at IAM's API
// host, as the reader's service account and no other identity. It formats as
// "IAM reader (not printed)" under every verb, slog and encoding/json.
type IAMReader struct{ p **iamReader }

type iamReader struct {
	host   federationHost
	tokens *RoleTokens
	client *http.Client
}

// NewIAMReader is the reader's IAM reader. It takes the reader's federated
// credential alone: a service-account key and the writer's federated
// credential are refused before anything is sent (ErrEndpointRefused), so
// only the reader's service-account token is ever sent to IAM's API host. It
// impersonates the reader's service account for itself, with
// TokenScopes (the set M3a's T4 read with), sharing the role's one federated
// token with the credential's other consumers.
//
// Its client reaches the credential's Federation's IAM API host alone, with
// no proxy, that host's roots (the system's in Google mode), TLS 1.2 at
// least, HTTP/2 allowed, no client certificate of any kind, no redirects,
// a header cap, 30 s a call, User-Agent farcast and Accept JSON. It calls
// UnsafeEnvironment first, and sends nothing.
func NewIAMReader(cred Credential) (*IAMReader, error) {
	if err := UnsafeEnvironment(); err != nil {
		return nil, err
	}
	fc := cred.fed()
	switch {
	case fc == nil:
		return nil, refuse(ErrEndpointRefused, msgIAMReaderKey)
	case fc.role != Reader:
		return nil, refuse(ErrEndpointRefused, msgIAMReaderWriter)
	}
	v := &iamReader{
		host:   fc.fed.iamAPI,
		tokens: newRoleTokens(fc.role, true, scopesIAM, fc.minter(scopesIAM)),
		client: fc.fed.iamAPIClient(),
	}
	return &IAMReader{p: &v}, nil
}

// get is the contents; nil for the zero IAMReader.
func (r IAMReader) get() *iamReader {
	if r.p == nil {
		return nil
	}
	return *r.p
}

// GetProvider reads one provider:
//
//	GET /v1/projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>
//
// with no query, and returns the 200's body, at most 1 MiB, for
// devicekey.CheckNamedProvider or ParseProvider. projectNumber is
// ^[0-9]{1,20}$, pool and provider ^[a-z0-9-]{4,32}$ not starting "gcp-";
// anything else is refused before anything is built or sent
// (ErrCredentialInvalid, msgIAMRequest naming the part).
//
// A 401 drops the service account's token, impersonates once more, and
// reads once more; a second 401, and any other status but 200, is a
// *FederationError at StepProviderGet wrapping ErrIAMRefused, with the
// status and Google's error.status in its shape, never the body. An
// unreachable host is ErrUnreachable, and a 200 larger than the cap
// ErrUnreadable.
func (r IAMReader) GetProvider(ctx context.Context, projectNumber, pool, provider string) ([]byte, error) {
	if err := checkProviderParts(projectNumber, pool); err != nil {
		return nil, err
	}
	if !isPoolOrProviderID(provider) {
		return nil, refuse(ErrCredentialInvalid, msgIAMRequest, "provider")
	}
	body, _, err := r.read(ctx, StepProviderGet, providersPath(projectNumber, pool)+"/"+provider, "")
	return body, err
}

// ListProviders reads the pool's providers, the soft-deleted ones included:
//
//	GET /v1/projects/<number>/locations/global/workloadIdentityPools/<pool>/providers?pageSize=10&showDeleted=true[&pageToken=<escaped>]
//
// following the pages, and returns each page's body, in order, for
// devicekey.ParseProviders. The parts are shape-checked as GetProvider's.
//
// Only a 200 is read, each at most 1 MiB. Each page must be a JSON object
// with no key twice, and its nextPageToken absent, null or "" (the last
// page) or 1 to 4096 of [A-Za-z0-9+/=_.~-]. A token already given is
// refused, because a server that repeats one would loop, and so is a list
// of more than 50 pages; each is ErrUnreadable at StepProviderList, naming
// what failed. The rest is GetProvider's.
func (r IAMReader) ListProviders(ctx context.Context, projectNumber, pool string) ([][]byte, error) {
	if err := checkProviderParts(projectNumber, pool); err != nil {
		return nil, err
	}
	path := providersPath(projectNumber, pool)
	given := map[string]bool{}
	var pages [][]byte
	query := providerListQuery
	for {
		body, tlsVersion, err := r.read(ctx, StepProviderList, path, query)
		if err != nil {
			return nil, err
		}
		next, field := providerPageToken(body)
		if field != "" {
			return nil, unusableAnswer(StepProviderList, field, tlsVersion)
		}
		pages = append(pages, body)
		switch {
		case next == "":
			return pages, nil
		case given[next]:
			return nil, unusableAnswer(StepProviderList, answerTokenRepeated, tlsVersion)
		case len(pages) == maxProviderPages:
			return nil, unusableAnswer(StepProviderList, answerTooManyPages, tlsVersion)
		}
		given[next] = true
		query = providerListQuery + "&pageToken=" + url.QueryEscape(next)
	}
}

// checkProviderParts is the shape check a read's project number and pool
// pass before anything is built.
func checkProviderParts(projectNumber, pool string) error {
	switch {
	case !isProjectNumber(projectNumber):
		return refuse(ErrCredentialInvalid, msgIAMRequest, "project number")
	case !isPoolOrProviderID(pool):
		return refuse(ErrCredentialInvalid, msgIAMRequest, "pool")
	}
	return nil
}

// providersPath is the pool's providers collection, from checked parts.
func providersPath(projectNumber, pool string) string {
	return iamProjectsPrefix + projectNumber + audiencePools + pool + iamProvidersSuffix
}

// read sends one GET for path and query as the reader's service account,
// and returns a 200's body and the TLS version it came over. A 401
// invalidates the token it carried and is sent once more with a new one.
func (r IAMReader) read(ctx context.Context, step Step, path, query string) ([]byte, uint16, error) {
	v := r.get()
	if v == nil || ctx == nil {
		return nil, 0, refuse(ErrCredentialInvalid, msgIAMRequest, "request")
	}
	reimpersonated := false
	for {
		tok, _, err := v.tokens.Token(ctx)
		if err != nil {
			return nil, 0, err
		}
		code, body, tlsVersion, err := v.send(ctx, step, path, query, tok)
		if err != nil {
			return nil, 0, err
		}
		switch {
		case code == http.StatusOK && len(body) > maxProviderAnswer:
			return nil, 0, unusableAnswer(step, answerOversizeIAM, tlsVersion)
		case code == http.StatusOK:
			return body, tlsVersion, nil
		case code == http.StatusUnauthorized && !reimpersonated:
			v.tokens.Invalidate(tok)
			reimpersonated = true
			continue
		}
		return nil, 0, refusedAnswer(step, code, body, tlsVersion)
	}
}

// send makes one attempt and reads its answer, at most maxProviderAnswer+1
// bytes, so a larger one is seen as larger.
func (v *iamReader) send(ctx context.Context, step Step, path, query, tok string) (int, []byte, uint16, error) {
	target := v.host.origin + path
	if query != "" {
		target += "?" + query
	}
	req, err := http.NewRequestWithContext(withServiceAccountBearer(ctx, tok), http.MethodGet, target, nil)
	if err != nil {
		return 0, nil, 0, refuse(ErrCredentialInvalid, msgIAMRequest, "request")
	}
	req.Header.Set("Accept", mediaJSON)
	resp, err := v.client.Do(req)
	if err != nil {
		return 0, nil, 0, classifyFailure(ctx, step, err, false)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProviderAnswer+1))
	if err != nil {
		return 0, nil, 0, classifyFailure(ctx, step, err, true)
	}
	return resp.StatusCode, body, negotiated(resp), nil
}

// providerPageToken reads a list page's nextPageToken: "" for the last page
// (absent, null or ""). field is "" on success, else the words for what the
// page is: not a JSON object, an object with a key twice (an escaped
// spelling of a key included, since keys are compared unescaped), or a
// nextPageToken out of its shape. Nothing of the page is carried.
func providerPageToken(body []byte) (next, field string) {
	dec := json.NewDecoder(bytes.NewReader(body))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return "", answerNotObject
	}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		key, ok := t.(string)
		if err != nil || !ok {
			return "", answerNotObject
		}
		if seen[key] {
			return "", answerKeyTwice
		}
		seen[key] = true
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return "", answerNotObject
		}
		raw = bytes.TrimSpace(raw)
		if key != "nextPageToken" || bytes.Equal(raw, []byte("null")) {
			continue
		}
		s, ok := jsonString(raw)
		if !ok || (s != "" && !isPageToken(s)) {
			return "", "nextPageToken"
		}
		next = s
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return "", answerNotObject
	}
	if _, err := dec.Token(); err != io.EOF {
		return "", answerNotObject
	}
	return next, ""
}

// isPageToken is ^[A-Za-z0-9+/=_.~-]{1,4096}$, the shape devicekey's
// ParseProviders reads.
func isPageToken(s string) bool {
	return len(s) >= 1 && len(s) <= maxPageToken && allBytes(s, func(c byte) bool {
		return isLower(c) || (c >= 'A' && c <= 'Z') || isDigit(c) || c == '+' || c == '/' || c == '=' || c == '_' || c == '.' || c == '~' || c == '-'
	})
}

// String is "IAM reader (not printed)".
func (r IAMReader) String() string { return iamReaderText }

// GoString is "IAM reader (not printed)".
func (r IAMReader) GoString() string { return iamReaderText }

// Format writes "IAM reader (not printed)" for every verb.
func (r IAMReader) Format(f fmt.State, verb rune) { _, _ = io.WriteString(f, iamReaderText) }

// LogValue is slog.StringValue("IAM reader (not printed)").
func (r IAMReader) LogValue() slog.Value { return slog.StringValue(iamReaderText) }

// MarshalJSON is the JSON string "IAM reader (not printed)".
func (r IAMReader) MarshalJSON() ([]byte, error) { return json.Marshal(iamReaderText) }
