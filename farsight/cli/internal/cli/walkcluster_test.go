//go:build walk

// The walk probe's cluster modes (ADR 0023 M2, the probe walk:
// docs/runbooks/adr-0023-m2-probe-walk.md): mint-empty-kid, review and
// forbidden-body. Each asks Google's token endpoint or the instance's API
// server one thing that farcast's own client cannot show. kube classifies
// every answer and quotes nothing of a token endpoint's body, a review's
// reason or a refusal's Content-Type. That is right for farcast, and it hides
// exactly what the probe walk records.
//
// So these build their one request here, from the pieces kube builds its own
// from (farsight/cli/internal/kube/token.go and transport.go):
//   - the record, read under config.Resolve's directory, refused unless it
//     names the instance given (recordNamed);
//   - for the writer and the reader, openCluster itself as the gate, so every
//     rule farcast applies before it sends anything applies here, kube.New's
//     pairing and its GODEBUG refusal included. Then the credential that gate
//     accepted (writerCredential, readerCredential). The reader opens as reader
//     grant's own verifying read does, before 'reader grant' has verified it;
//   - for a key file, openCluster's endpoint steps, then kube.New's pairing;
//   - the vendored 2LO provider, with the token URL fixed in code
//     (Endpoint.TokenURL, never the key file's token_uri), the one scope
//     userinfo.email, and a logger that discards;
//   - a transport with no proxy and no redirect, User-Agent farcast, and the
//     bearer only on the one request built for the endpoint's own origin.
//
// Nothing here prints a token, a key, an assertion, an email, a project id or
// an address. What the cluster or Google sent is printed only through
// walkScrubber, and only the parts each mode names. A refused mint is named by
// its OAuth error code alone, because the vendored error's text quotes the
// token endpoint's whole body.
package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"cloud.google.com/go/auth"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
)

// walkMaxBody is the most of an answer the cluster probes read. A refusal
// or a review is a few hundred bytes.
const walkMaxBody = 1 << 20

// walkKeyIdentity is the identity a key file's client is paired under. kube
// takes any name, and the instance's two are not this: a throwaway account
// is neither its writer nor its reader.
const walkKeyIdentity kube.Identity = "walk-key"

// walkPreflightPath and walkPreflightQuery are the GET forbidden-body sends:
// the writing commands' preflight read since ADR 0023 M2.5,
// kube.Client.NamespaceUID's list of farcast-system (kube/reads.go). It reads
// a namespace's name and uid, and never a Secret, whoever answers it.
const walkPreflightPath = "/api/v1/namespaces"

func walkPreflightQuery() url.Values {
	return url.Values{"fieldSelector": {"metadata.name=farcast-system"}, "limit": {"500"}}
}

// walkTarget is who a cluster probe acts as and the endpoint it sends to.
type walkTarget struct {
	who   string
	ep    kube.Endpoint
	cred  kube.Credential
	scrub walkScrubber
}

// record loads the instance's record as farcast does, and the scrubber built
// from it.
func (w *walk) record() (*config.InstanceMetadata, walkScrubber) {
	w.t.Helper()
	sc := newWalkScrubber(nil)
	meta, err := w.env.ConfigDir.LoadInstanceMetadata(w.instance)
	if err != nil {
		w.stop(sc, "load instance %q: %v", w.instance, err)
	}
	if err := recordNamed(meta, w.instance); err != nil {
		w.stop(sc, "%v", err)
	}
	return meta, newWalkScrubber(meta)
}

// stop ends the probe with a scrubbed message.
func (w *walk) stop(sc walkScrubber, format string, args ...any) {
	w.t.Helper()
	w.t.Fatal(sc.text(fmt.Sprintf(format, args...)))
}

// endpoint is openCluster's steps 1 to 3: the record names an endpoint, its
// name is one install accepts, cluster-ca.crt is read if it exists, and the
// endpoint is classified against the region and that CA.
func (w *walk) endpoint(meta *config.InstanceMetadata, sc walkScrubber) kube.Endpoint {
	w.t.Helper()
	if meta.Endpoint == "" {
		w.stop(sc, "instance %q records no cluster endpoint; 'farcast install' records one", meta.Name)
	}
	if validateInstanceName(meta.Name) != nil {
		w.stop(sc, msgUnsafeRecord, meta.Name, "name", meta.Name)
	}
	ca, ok, err := w.env.ConfigDir.LoadClusterCA(meta.Name)
	if err != nil {
		w.stop(sc, "instance %q's cluster-ca.crt exists and cannot be read (%v)", meta.Name, err)
	}
	if !ok {
		ca = nil
	}
	ep, err := kube.ParseEndpoint(meta.Endpoint, meta.Region, ca)
	if err != nil {
		w.stop(sc, "%v", err)
	}
	return ep
}

// target resolves FARCAST_WALK_IDENTITY: writer, the installer's key in
// credentials.yaml; reader, reader.key under its recorded key id; or key, the
// service-account key file FARCAST_WALK_KEY_JSON names, resolved against
// FARCAST_WALK_CWD. It has no default.
func (w *walk) target() walkTarget {
	w.t.Helper()
	meta, sc := w.record()
	tg := walkTarget{scrub: sc}
	switch id := os.Getenv("FARCAST_WALK_IDENTITY"); id {
	case "writer", "reader":
		r := clusterRef{Dir: w.env.ConfigDir, Meta: meta, Identity: kube.Writer, Warn: io.Discard}
		if id == "reader" {
			r.Identity, r.Verifying = kube.Reader, true
		}
		if _, err := openCluster(r); err != nil {
			w.stop(sc, "farcast would not open instance %q's %s: %v", meta.Name, id, err)
		}
		tg.ep = w.endpoint(meta, sc)
		var err error
		if id == "writer" {
			tg.who = "the writer (the installer's key in credentials.yaml)"
			tg.cred, err = writerCredential(r)
		} else {
			tg.who = "the reader (reader.key, under its recorded key id)"
			tg.cred, err = readerCredential(r, tg.ep)
		}
		if err != nil {
			w.stop(sc, "%v", err)
		}
	case "key":
		file := os.Getenv("FARCAST_WALK_KEY_JSON")
		if file == "" {
			w.stop(sc, "FARCAST_WALK_IDENTITY=key reads the service-account key file FARCAST_WALK_KEY_JSON names, and it is not set")
		}
		tg.ep = w.endpoint(meta, sc)
		raw, err := os.ReadFile(w.path(file))
		if err != nil {
			w.stop(sc, "read FARCAST_WALK_KEY_JSON: %v", err)
		}
		tg.cred, err = kube.ParseServiceAccountJSON(raw)
		clear(raw)
		if err != nil {
			w.stop(sc, "%v", err)
		}
		// kube.New is the pairing rule (and the GODEBUG refusal); it sends
		// nothing, and its client is not used.
		if _, err := kube.New(kube.Config{Endpoint: tg.ep, Credential: tg.cred, Identity: walkKeyIdentity}); err != nil {
			w.stop(sc, "%v", err)
		}
		tg.who = "the key FARCAST_WALK_KEY_JSON names"
	default:
		w.stop(sc, "FARCAST_WALK_IDENTITY=%q: want writer, reader or key; there is no default", id)
	}
	w.t.Cleanup(func() { clear(tg.cred.PrivateKeyPEM) })
	return tg
}

// walkMint mints one token for cred with kid as the assertion's key id, as
// kube's twoLegged does: the vendored 2LO provider, ep.TokenURL(), the one
// scope userinfo.email, Expires left zero, and a logger that discards. A nil
// Logger would let GOOGLE_SDK_GO_LOGGING_LEVEL log the assertion and the token
// (vendor/github.com/googleapis/gax-go/v2/internallog/internallog.go).
func walkMint(ctx context.Context, ep kube.Endpoint, cred kube.Credential, kid string) (*auth.Token, error) {
	key := slices.Clone(cred.PrivateKeyPEM)
	defer clear(key)
	tp, err := auth.New2LOTokenProvider(&auth.Options2LO{
		Email:        cred.Email,
		PrivateKey:   key,
		PrivateKeyID: kid,
		Scopes:       []string{kube.ScopeUserinfoEmail},
		TokenURL:     ep.TokenURL(),
		Client:       walkHTTPClient(ep),
		Logger:       slog.New(slog.DiscardHandler),
	})
	if err != nil {
		return nil, err
	}
	return tp.Token(ctx)
}

// walkHTTPClient is kube's transport shape (kube/transport.go, newTransport):
// a fresh transport whose Proxy is nil, so no proxy variable routes a bearer
// or an assertion; TLS 1.2 or later against the system roots (Google mode) or
// the instance's cluster CA alone (loopback); no redirect followed; and
// User-Agent farcast on every request.
func walkHTTPClient(ep kube.Endpoint) *http.Client {
	return &http.Client{
		Transport: walkAgent{inner: &http.Transport{
			Proxy:                 nil,
			DialContext:           (&net.Dialer{Timeout: 30 * time.Second}).DialContext,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: ep.CA},
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		}},
		Timeout:       60 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// walkAgent sets User-Agent: farcast, kube.UserAgent, on every request.
type walkAgent struct{ inner http.RoundTripper }

func (a walkAgent) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Header.Set("User-Agent", kube.UserAgent)
	return a.inner.RoundTrip(r)
}

// mintReport prints how a mint ended: accepted, with the token not printed;
// refused, by its OAuth error code alone; or not answered, with the
// transport's words scrubbed. It reports whether a token was minted.
func (w *walk) mintReport(sc walkScrubber, tok *auth.Token, err error) bool {
	if err == nil {
		if tok != nil && tok.Value != "" {
			w.say("  ACCEPTED: Google minted a token (not printed)")
			return true
		}
		w.say("  ANSWERED without a token")
		return false
	}
	var ae *auth.Error
	if errors.As(err, &ae) && ae.Response != nil {
		w.say("  REFUSED: OAuth error %s", oauthErrorCode(ae.Body))
		return false
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		w.say("  NOT ANSWERED: %s", sc.text(ue.Err.Error()))
		return false
	}
	// The vendored error's own text can quote the endpoint's body.
	w.say("  the token endpoint's answer could not be read")
	return false
}

// oauthErrorShape is an OAuth error code (RFC 6749 §5.2).
var oauthErrorShape = regexp.MustCompile(`^[a-z_]{1,64}$`)

// oauthErrorCode is the "error" of a token endpoint's refusal, quoted, or a
// note that it names none. Its error_description is never read.
func oauthErrorCode(body []byte) string {
	var e struct {
		Error any `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil {
		if code, ok := e.Error.(string); ok && oauthErrorShape.MatchString(code) {
			return fmt.Sprintf("%q", code)
		}
	}
	return "none (the answer names no OAuth error code)"
}

// mintEmptyKid mints once with the reader's key and "kid":"" (probe walk
// item 5). The reader must be recorded with its uploaded key's id, as
// openCluster requires, and that id is replaced by "" for this one mint: a
// refusal then says the empty id is refused, not that no key is uploaded.
func (w *walk) mintEmptyKid() {
	meta, sc := w.record()
	r := clusterRef{Dir: w.env.ConfigDir, Meta: meta, Identity: kube.Reader, Warn: io.Discard, Verifying: true}
	if _, err := openCluster(r); err != nil {
		w.stop(sc, "farcast would not open instance %q's reader: %v", meta.Name, err)
	}
	ep := w.endpoint(meta, sc)
	cred, err := readerCredential(r, ep)
	if err != nil {
		w.stop(sc, "%v", err)
	}
	defer clear(cred.PrivateKeyPEM)
	w.say("mint-empty-kid: one mint with the reader's key, its recorded key id replaced by \"kid\":\"\"")
	tok, err := walkMint(w.ctx, ep, cred, "")
	w.mintReport(sc, tok, err)
}

// send makes one request as tg: it mints, as farcast does, under the
// credential's own key id, then sends the request to the endpoint's origin
// with the token as its bearer. It returns the status, the Content-Type and
// at most walkMaxBody of the body. A mint that gives no token ends the probe.
func (w *walk) send(tg walkTarget, method, path string, q url.Values, body []byte) (int, string, []byte) {
	w.t.Helper()
	tok, err := walkMint(w.ctx, tg.ep, tg.cred, tg.cred.PrivateKeyID)
	if err != nil || tok == nil || tok.Value == "" {
		w.say("the token endpoint minted no token for %s:", tg.who)
		w.mintReport(tg.scrub, tok, err)
		w.t.FailNow()
	}
	target := tg.ep.BaseURL() + path
	if e := q.Encode(); e != "" {
		target += "?" + e
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(w.ctx, method, target, rd)
	if err != nil {
		w.stop(tg.scrub, "build %s %s: %v", method, path, err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+tok.Value)
	resp, err := walkHTTPClient(tg.ep).Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		w.stop(tg.scrub, "%s %s was not answered: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, walkMaxBody))
	if err != nil {
		w.stop(tg.scrub, "%s %s: the answer could not be read: %v", method, path, err)
	}
	return resp.StatusCode, resp.Header.Get("Content-Type"), answer
}

// answer prints an answer's status and Content-Type, and for a refusal, its
// body's shape: whether it is a Kubernetes Status, with its reason and code,
// or Google's JSON error, with its status and code, and its message scrubbed.
// It reports whether the answer was a 2xx.
func (w *walk) answer(sc walkScrubber, code int, contentType string, body []byte) bool {
	w.say("  status %d %s", code, http.StatusText(code))
	if contentType == "" {
		contentType = "(none)"
	}
	w.say("  content-type %s", sc.text(contentType))
	if code >= 200 && code < 300 {
		return true
	}
	var obj map[string]json.RawMessage
	if len(body) == 0 || json.Unmarshal(body, &obj) != nil || obj == nil {
		w.say("  a Kubernetes Status: no; the body is not a JSON object (%d bytes)", len(body))
		if line, _, _ := strings.Cut(string(body), "\n"); line != "" {
			w.say("  its first line (scrubbed): %s", sc.text(line))
		}
		return false
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, sc.word(k))
	}
	slices.Sort(keys)
	w.say("  body: a JSON object, keys %s", strings.Join(keys, " "))
	var st kube.Status
	_ = json.Unmarshal(body, &st)
	if st.Kind == "Status" {
		w.say("  a Kubernetes Status: yes, reason %s, code %d", sc.word(st.Reason), st.Code)
		w.say("  message (scrubbed): %s", sc.text(st.Message))
		return false
	}
	w.say("  a Kubernetes Status: no (kind %s)", sc.word(st.Kind))
	var g struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Status  string `json:"status"`
			Details []struct {
				Type   string `json:"@type"`
				Reason string `json:"reason"`
			} `json:"details"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &g) != nil || g.Error == nil {
		w.say("  not Google's JSON error either")
		return false
	}
	w.say("  Google's JSON error: status %s, code %d", sc.word(g.Error.Status), g.Error.Code)
	for _, d := range g.Error.Details {
		w.say("    detail %s, reason %s", sc.word(d.Type), sc.word(d.Reason))
	}
	w.say("  message (scrubbed): %s", sc.text(g.Error.Message))
	return false
}

// forbiddenBody sends the writing commands' preflight read once as
// FARCAST_WALK_IDENTITY (probe walk item 6, and item 1 as the writer). A 2xx is
// not a refusal, and nothing of its body is printed.
func (w *walk) forbiddenBody() {
	tg := w.target()
	w.say("forbidden-body: GET %s?%s (the writing commands' preflight read) as %s",
		walkPreflightPath, walkPreflightQuery().Encode(), tg.who)
	code, contentType, body := w.send(tg, http.MethodGet, walkPreflightPath, walkPreflightQuery(), nil)
	defer clear(body)
	if w.answer(tg.scrub, code, contentType, body) {
		w.say("  not a refusal; nothing of the body is printed")
	}
}

// The shapes review takes its attributes in. An empty group is the core
// group, and an empty namespace asks about every namespace.
var (
	walkVerbShape      = regexp.MustCompile(`^(?:[a-z]{1,32}|\*)$`)
	walkResourceShape  = regexp.MustCompile(`^(?:[a-z0-9][a-z0-9.-]{0,62}|\*)$`)
	walkGroupShape     = regexp.MustCompile(`^(?:[a-z0-9.-]{0,253}|\*)$`)
	walkNamespaceShape = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)?$`)
)

// reviewAttributes reads review's attributes: FARCAST_WALK_VERB and
// FARCAST_WALK_RESOURCE (a resource, or resource/subresource), both required,
// FARCAST_WALK_GROUP and FARCAST_WALK_NAMESPACE.
func (w *walk) reviewAttributes() kube.ResourceAttributes {
	w.t.Helper()
	a := kube.ResourceAttributes{
		Verb:      os.Getenv("FARCAST_WALK_VERB"),
		Group:     os.Getenv("FARCAST_WALK_GROUP"),
		Namespace: os.Getenv("FARCAST_WALK_NAMESPACE"),
	}
	a.Resource, a.Subresource, _ = strings.Cut(os.Getenv("FARCAST_WALK_RESOURCE"), "/")
	sc := newWalkScrubber(nil)
	switch {
	case !walkVerbShape.MatchString(a.Verb):
		w.stop(sc, "FARCAST_WALK_VERB=%q: want a verb such as create, get or patch", a.Verb)
	case !walkResourceShape.MatchString(a.Resource) || (a.Subresource != "" && !walkResourceShape.MatchString(a.Subresource)):
		w.stop(sc, "FARCAST_WALK_RESOURCE=%q: want a resource such as deployments, or resource/subresource", os.Getenv("FARCAST_WALK_RESOURCE"))
	case !walkGroupShape.MatchString(a.Group):
		w.stop(sc, "FARCAST_WALK_GROUP=%q: want an API group such as apps, or empty for the core group", a.Group)
	case !walkNamespaceShape.MatchString(a.Namespace):
		w.stop(sc, "FARCAST_WALK_NAMESPACE=%q: want a namespace, or empty for every namespace", a.Namespace)
	}
	return a
}

// review asks one SelfSubjectAccessReview as FARCAST_WALK_IDENTITY (probe
// walk item 4): whether GKE's reviews consult IAM shows as an account with an
// IAM role and no RBAC being allowed. It prints allowed, denied or no opinion,
// and the reason, scrubbed.
func (w *walk) review() {
	a := w.reviewAttributes()
	tg := w.target()
	resource := a.Resource
	if a.Subresource != "" {
		resource += "/" + a.Subresource
	}
	if a.Group != "" {
		resource += "." + a.Group
	}
	where := "in every namespace"
	if a.Namespace != "" {
		where = "in " + a.Namespace
	}
	type attributes struct {
		Namespace   string `json:"namespace,omitempty"`
		Verb        string `json:"verb,omitempty"`
		Group       string `json:"group,omitempty"`
		Resource    string `json:"resource,omitempty"`
		Subresource string `json:"subresource,omitempty"`
	}
	body, err := json.Marshal(map[string]any{
		"apiVersion": "authorization.k8s.io/v1",
		"kind":       "SelfSubjectAccessReview",
		"spec":       map[string]any{"resourceAttributes": attributes{a.Namespace, a.Verb, a.Group, a.Resource, a.Subresource}},
	})
	if err != nil {
		w.t.Fatal(err)
	}
	w.say("review as %s: may it %s %s %s?", tg.who, a.Verb, resource, where)
	code, contentType, answer := w.send(tg, http.MethodPost, "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", nil, body)
	if code < 200 || code >= 300 {
		w.say("  the review itself was refused:")
		w.answer(tg.scrub, code, contentType, answer)
		return
	}
	var r struct {
		Status *struct {
			Allowed         bool   `json:"allowed"`
			Denied          bool   `json:"denied"`
			Reason          string `json:"reason"`
			EvaluationError string `json:"evaluationError"`
		} `json:"status"`
	}
	if json.Unmarshal(answer, &r) != nil || r.Status == nil {
		w.say("  the answer (%d) carries no status", code)
		w.t.Fail()
		return
	}
	verdict := "NO OPINION (neither allowed nor denied)"
	switch {
	case r.Status.Allowed:
		verdict = "ALLOWED"
	case r.Status.Denied:
		verdict = "DENIED"
	}
	reason := r.Status.Reason
	if reason == "" {
		reason = "(none given)"
	}
	w.say("  %s; reason (scrubbed): %s", verdict, tg.scrub.text(reason))
	if r.Status.EvaluationError != "" {
		w.say("  evaluation error (scrubbed): %s", tg.scrub.text(r.Status.EvaluationError))
	}
}

// walkScrubber replaces, in text the cluster or Google sent (and in the
// probe's own refusals, which can name a path or a recorded value), what a
// walk never records: an email; the instance's project id and any other
// projects/<id>; the endpoint's host and any other gke.goog name; IP
// addresses, with their ports; the home directory; runs of 32 or more token
// characters (a token, an assertion, a key id); and runs of six or more
// digits (a project number, an account's unique id). The result is cut to 600
// characters, and quoted when it would not print as it is (terminalText).
type walkScrubber struct {
	literals [][2]string // exact values first, longest first
}

var (
	walkEmailShape    = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+`)
	walkGKEHostShape  = regexp.MustCompile(`(?i)(?:[a-z0-9-]+\.)+gke\.goog`)
	walkProjectsShape = regexp.MustCompile(`projects/[^/\s"'\],}]+`)
	walkIPv4Shape     = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b`)
	walkIPv6Shape     = regexp.MustCompile(`(?i)\[?(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\]?(?::\d{1,5})?`)
	walkOpaqueShape   = regexp.MustCompile(`[A-Za-z0-9_-]{32,}`)
	walkDigitsShape   = regexp.MustCompile(`\d{6,}`)
	walkWordShape     = regexp.MustCompile(`^[A-Za-z0-9_.@/:-]{1,128}$`)
)

// walkScrubMax is the longest scrubbed text printed, in runes.
const walkScrubMax = 600

// newWalkScrubber builds the scrubber for one instance's record; nil gives
// one that knows no recorded value.
func newWalkScrubber(meta *config.InstanceMetadata) walkScrubber {
	var sc walkScrubber
	if home, err := os.UserHomeDir(); err == nil && len(home) > 1 {
		sc.literals = append(sc.literals, [2]string{home, "$HOME"})
	}
	if meta != nil {
		if meta.Endpoint != "" {
			sc.literals = append(sc.literals, [2]string{meta.Endpoint, "$ENDPOINT"})
		}
		if meta.Project != "" {
			sc.literals = append(sc.literals, [2]string{meta.Project, "$PROJECT"})
		}
	}
	slices.SortFunc(sc.literals, func(a, b [2]string) int { return len(b[0]) - len(a[0]) })
	return sc
}

// text is s with everything walkScrubber names replaced, cut and made
// printable.
func (sc walkScrubber) text(s string) string {
	s = walkEmailShape.ReplaceAllString(s, "$$EMAIL")
	for _, l := range sc.literals {
		s = strings.ReplaceAll(s, l[0], l[1])
	}
	s = walkGKEHostShape.ReplaceAllString(s, "$$ENDPOINT")
	s = walkProjectsShape.ReplaceAllString(s, "projects/$$PROJECT")
	s = walkIPv4Shape.ReplaceAllString(s, "$$ADDRESS")
	s = walkIPv6Shape.ReplaceAllString(s, "$$ADDRESS")
	s = walkOpaqueShape.ReplaceAllString(s, "$$OPAQUE")
	s = walkDigitsShape.ReplaceAllString(s, "$$NUMBER")
	if r := []rune(s); len(r) > walkScrubMax {
		s = string(r[:walkScrubMax]) + "…"
	}
	return terminalText(s)
}

// word is a single token the answer carried (a reason, a status, a key, an
// @type), scrubbed, and quoted; anything that is not one word is not printed.
func (sc walkScrubber) word(s string) string {
	if s == "" {
		return `""`
	}
	s = sc.text(s)
	if !walkWordShape.MatchString(strings.TrimPrefix(s, "$")) {
		return fmt.Sprintf("<%d characters, not printed>", len(s))
	}
	return fmt.Sprintf("%q", s)
}
