package kube

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"cloud.google.com/go/auth"
)

// The transports' fixed values (§3.4).
const (
	// maxAnswer caps an answer's body. One byte more is read, so a larger
	// body is refused rather than silently cut (technocore/kube/client.go
	// truncates; this client must not). Log streams are not capped.
	maxAnswer = 64 << 20

	// requestTimeout bounds each attempt of a non-streaming request: it is
	// every Client's attemptTimeout. The API client itself has no Timeout, so
	// a followed log is never cut off.
	requestTimeout = 60 * time.Second
	// responseHeaderTimeout bounds the wait for an answer's headers, on every
	// transport but a followed log's: the kubelet sends a log's headers only
	// with its first line, so a follow of a container that has logged nothing
	// yet has none to send.
	responseHeaderTimeout = 30 * time.Second
	// tokenTimeout is the token client's whole-request timeout.
	tokenTimeout = 30 * time.Second

	// maxAttempts is how many times a GET or a server-side apply is sent in
	// all when the server answers 429 or 503 (D12).
	maxAttempts = 3
	// maxRetryWait caps a Retry-After; defaultRetryWait is the wait when the
	// answer names none.
	maxRetryWait     = 10 * time.Second
	defaultRetryWait = time.Second

	// drainLimit is how much of a discarded body is read so its connection
	// can be reused.
	drainLimit = 64 << 10
)

// The media types the client sends and asks for.
const (
	mediaJSON          = "application/json"
	mediaApplyPatch    = "application/apply-patch+yaml"
	acceptPartial      = "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1"
	acceptPartialList  = "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1"
	msgAnswerTooLarge  = "the API server's answer to %s %s is larger than 64 MiB"
	msgAnswerUnread    = "the API server's answer to %s %s could not be read"
	msgLoopbackRefused = "kube: loopback client refused to dial %s"
)

// http2Verbose is whether Go's HTTP/2 client logs every request header, the
// bearer included, and with http2debug=2 every frame, the token endpoint's
// form (the assertion) and answer (the access token) included, to stderr.
// net/http reads GODEBUG once, at its own init, for this
// (go1.27.4 src/net/http/internal/http2/http2.go, init); this package's
// variables are initialized after net/http's, from the same environment, so
// this is exactly what net/http saw. Unsetting GODEBUG later cannot turn the
// logging off, so UnsafeEnvironment refuses instead (D14's kind of leak,
// through another variable).
var http2Verbose = http2DebugLogging(os.Getenv("GODEBUG"))

// UnsafeEnvironment refuses, with ErrUnsafeEnvironment and msgHTTP2Debug,
// while http2Verbose holds, and is nil otherwise. It is the one test of it:
// newClient asks it before anything else, and farcast's router asks it before
// every command reads anything (ADR 0023 M2.8's step 0), because the vendored
// Google clients' HTTP/2 transport (golang.org/x/net/http2) reads the same
// GODEBUG setting at its own init and logs the same headers.
func UnsafeEnvironment() error {
	if http2Verbose {
		return refuse(ErrUnsafeEnvironment, msgHTTP2Debug)
	}
	return nil
}

// http2DebugLogging is net/http's own test of GODEBUG for HTTP/2 logging,
// with its two settings (go1.27.4 src/net/http/internal/http2/http2.go).
func http2DebugLogging(godebug string) bool {
	return strings.Contains(godebug, "http2debug=1") || strings.Contains(godebug, "http2debug=2")
}

// msgHTTP2Debug is UnsafeEnvironment's refusal while http2Verbose holds.
const msgHTTP2Debug = "the environment's GODEBUG names http2debug, which makes Go's HTTP/2 client print every request header, the bearer token included, to stderr; unset it and run farcast again; nothing was sent"

// newTransport is the one transport shape every one of a client's HTTP
// clients uses: a fresh literal, never http.DefaultTransport.Clone(), whose
// Proxy is http.ProxyFromEnvironment. Proxy is left nil, so HTTPS_PROXY and
// the other proxy variables never route a bearer. RootCAs nil is the system
// roots (Google mode); in loopback mode they are the instance's cluster CA
// alone, and the dialer refuses any address but the endpoint's. headerTimeout
// is responseHeaderTimeout, or 0, none, for a followed log alone.
func newTransport(ep Endpoint, headerTimeout time.Duration) *http.Transport {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	if ep.Mode == ModeLoopback {
		allowed := net.JoinHostPort(ep.Host, ep.Port)
		dialer.Control = func(_, address string, _ syscall.RawConn) error {
			if address != allowed {
				return fmt.Errorf(msgLoopbackRefused, address)
			}
			return nil
		}
	}
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: ep.CA},
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: headerTimeout,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   4,
	}
}

// noRedirect makes a 3xx the answer: no redirect is followed, so a bearer
// never goes where the endpoint sends it, and a 3xx is an APIError.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// apiHTTPClient is the API client: no Timeout (each non-streaming attempt has
// its own deadline), no redirects, and the bearer set by apiTransport.
func apiHTTPClient(ep Endpoint) *http.Client {
	return bearerHTTPClient(ep, responseHeaderTimeout)
}

// followHTTPClient is the API client for a followed log alone: the same, but
// with no ResponseHeaderTimeout, because the kubelet sends a log's headers
// only with its first line, and a quiet container may log nothing for hours.
// It is bounded by its caller's context alone.
func followHTTPClient(ep Endpoint) *http.Client {
	return bearerHTTPClient(ep, 0)
}

func bearerHTTPClient(ep Endpoint, headerTimeout time.Duration) *http.Client {
	return &http.Client{
		Transport:     &apiTransport{inner: newTransport(ep, headerTimeout), host: endpointHost(ep)},
		CheckRedirect: noRedirect,
	}
}

// tokenHTTPClient is the client the 2LO provider posts its assertion with.
// It never sends an Authorization header.
func tokenHTTPClient(ep Endpoint) *http.Client {
	return &http.Client{
		Transport:     &tokenTransport{inner: newTransport(ep, responseHeaderTimeout)},
		Timeout:       tokenTimeout,
		CheckRedirect: noRedirect,
	}
}

// endpointHost is the endpoint as a request URL's Host names it: the name
// alone in Google mode (port 443 is the scheme's), host:port in loopback mode.
func endpointHost(ep Endpoint) string {
	return strings.TrimPrefix(ep.BaseURL(), "https://")
}

// bearerKey carries a request's token on its context, from Client.open to
// apiTransport, which alone decides whether the request may carry it.
type bearerKey struct{}

func withBearer(ctx context.Context, tok *auth.Token) context.Context {
	return context.WithValue(ctx, bearerKey{}, tok)
}

func bearerFrom(ctx context.Context) *auth.Token {
	tok, _ := ctx.Value(bearerKey{}).(*auth.Token)
	return tok
}

// apiTransport sets User-Agent: farcast on every request, and
// Authorization: Bearer <Token.Value> only on an https request to the
// endpoint's own host. A request built for any other host, or another scheme,
// goes without one, whatever its caller set. It sets the header itself
// rather than through httptransport, so Google's trust-boundary header never
// reaches a cluster.
type apiTransport struct {
	inner http.RoundTripper
	host  string
}

func (t *apiTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Header.Set("User-Agent", UserAgent)
	r.Header.Del("Authorization")
	if tok := bearerFrom(r.Context()); tok != nil && r.URL.Scheme == "https" && r.URL.Host == t.host {
		r.Header.Set("Authorization", "Bearer "+tok.Value)
	}
	return t.inner.RoundTrip(r)
}

// tokenTransport sets User-Agent: farcast and never an Authorization header.
type tokenTransport struct {
	inner http.RoundTripper
}

func (t *tokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Header.Set("User-Agent", UserAgent)
	r.Header.Del("Authorization")
	return t.inner.RoundTrip(r)
}

// call is one API request, as the methods describe it.
type call struct {
	method      string
	path        string // already escaped: Kind.Path or a fixed path
	query       url.Values
	accept      string // "" is application/json
	contentType string
	body        []byte
	// retry is D12's policy: a GET or a server-side apply is sent again on
	// 429 and 503. POST, PUT and DELETE never are; their callers have their
	// own policies.
	retry bool
	// stream is a log read: no per-attempt deadline, and no cap on its body.
	stream bool
	// follow is a followed log read: it goes through the client with no
	// ResponseHeaderTimeout, so a container that has logged nothing yet is
	// waited for. A log read that does not follow keeps the header bound.
	follow bool
}

// do runs a non-streaming call and returns its 2xx body, read whole under the
// 64 MiB cap.
func (c *Client) do(ctx context.Context, cl call) ([]byte, error) {
	resp, done, err := c.open(ctx, cl)
	if err != nil {
		return nil, err
	}
	defer done()
	return readCapped(ctx, resp.Body, cl)
}

// decode runs a call and decodes its answer into v. An answer that does not
// decode is ErrUnreadable; the decoder's own words are not carried, because
// they can quote the answer.
func (c *Client) decode(ctx context.Context, cl call, v any) error {
	body, err := c.do(ctx, cl)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, v); err != nil {
		return refuse(ErrUnreadable, msgAnswerUnread, cl.method, cl.path)
	}
	return nil
}

// open runs one call to its first 2xx answer and returns it with its body
// open, and the function that ends it. It applies §3.4's retries:
//   - a 401 drops the token the request carried, mints once more and sends
//     the call once more, whatever its method, because the server refused it
//     before processing it; a second 401 is the error (tkube.ErrUnauthorized);
//   - a 429 or 503 to a call marked retry is sent again, up to maxAttempts in
//     all, after the answer's Retry-After in seconds, capped at 10 s, or 1 s
//     when it names none;
//
// and nothing else is retried. Every answer's Warning headers are kept.
func (c *Client) open(ctx context.Context, cl call) (*http.Response, func(), error) {
	reminted := false
	attempt := 1
	for {
		tok, err := c.tokens.token(ctx)
		if err != nil {
			return nil, nil, err
		}
		resp, done, err := c.send(ctx, cl, tok)
		if err != nil {
			return nil, nil, err
		}
		c.noteWarnings(resp.Header)
		code := resp.StatusCode
		switch {
		case code >= 200 && code < 300:
			return resp, done, nil
		case code == http.StatusUnauthorized && !reminted:
			drain(resp.Body)
			done()
			c.tokens.invalidate(tok)
			reminted = true
			continue
		case cl.retry && (code == http.StatusTooManyRequests || code == http.StatusServiceUnavailable) && attempt < maxAttempts:
			wait := retryAfter(resp.Header)
			drain(resp.Body)
			done()
			if err := c.sleep(ctx, wait); err != nil {
				return nil, nil, err
			}
			attempt++
			continue
		}
		err = readAPIError(ctx, cl, resp)
		done()
		return nil, nil, err
	}
}

// send makes one attempt. It returns the answer with its body open, and the
// function that closes the body and releases the attempt's deadline.
func (c *Client) send(ctx context.Context, cl call, tok *auth.Token) (*http.Response, func(), error) {
	actx, cancel := ctx, context.CancelFunc(func() {})
	if !cl.stream {
		actx, cancel = context.WithTimeout(ctx, c.attemptTimeout)
	}
	target := c.base + cl.path
	if q := cl.query.Encode(); q != "" {
		target += "?" + q
	}
	var body io.Reader
	if cl.body != nil {
		body = bytes.NewReader(cl.body)
	}
	req, err := http.NewRequestWithContext(withBearer(actx, tok), cl.method, target, body)
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("kube: build %s %s: %w", cl.method, cl.path, err)
	}
	accept := cl.accept
	if accept == "" {
		accept = mediaJSON
	}
	req.Header.Set("Accept", accept)
	if cl.contentType != "" {
		req.Header.Set("Content-Type", cl.contentType)
	}
	hc := c.api
	if cl.follow {
		hc = c.follow
	}
	resp, err := hc.Do(req)
	if err != nil {
		// Classified before cancel, which would end actx and make every
		// failure read as the attempt's deadline.
		e := unreachable(ctx, actx, c.attemptTimeout, cl, err)
		cancel()
		return nil, nil, e
	}
	return resp, func() {
		_ = resp.Body.Close()
		cancel()
	}, nil
}

// readCapped reads a whole body, at most maxAnswer bytes. It reads one byte
// more than the cap, so a larger body is ErrUnreadable and never a silent
// truncation.
func readCapped(ctx context.Context, r io.Reader, cl call) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxAnswer+1))
	if err != nil {
		return nil, unreachable(ctx, ctx, 0, cl, err)
	}
	if len(b) > maxAnswer {
		return nil, refuse(ErrUnreadable, msgAnswerTooLarge, cl.method, cl.path)
	}
	return b, nil
}

// drain reads a little of a body that is being discarded, so its connection
// can be reused.
func drain(r io.Reader) { _, _ = io.Copy(io.Discard, io.LimitReader(r, drainLimit)) }

// readAPIError reads a non-2xx answer into an APIError. KubernetesStatus is true
// only for a Status object (kind "Status"); any other body, such as the JSON
// error of the DNS endpoint's IAM check, keeps the code and, from a Google
// error, its message. The answer's code is the HTTP status, whatever the body
// says.
func readAPIError(ctx context.Context, cl call, resp *http.Response) error {
	body, err := readCapped(ctx, resp.Body, cl)
	if err != nil {
		return err
	}
	e := &APIError{Method: cl.method, Path: cl.path}
	var st Status
	if json.Unmarshal(body, &st) == nil && st.Kind == "Status" {
		e.Status = st
		e.KubernetesStatus = true
	} else {
		var g struct {
			Error *struct {
				Message string `json:"message"`
				Status  string `json:"status"`
			} `json:"error"`
		}
		if json.Unmarshal(body, &g) == nil && g.Error != nil {
			e.Status.Message = g.Error.Message
		}
	}
	e.Status.Code = resp.StatusCode
	return e
}

// wireError is a failure on the wire: its text is its message, and it
// unwraps to its sentinel and to the cause, so errors.Is finds both
// ErrUnreachable and, say, context.Canceled.
type wireError struct {
	msg      string
	sentinel error
	cause    error
}

func (e *wireError) Error() string   { return e.msg }
func (e *wireError) Unwrap() []error { return []error{e.sentinel, e.cause} }

// unreachable classifies a failure to send a call or read its answer. The
// caller's own context ending is that context's error. The attempt's deadline
// passing (actx's, of within), or the transport failing, is ErrUnreachable,
// with the transport's words: they name an address and never a header or a
// body. A caller with no attempt deadline passes ctx as actx.
func unreachable(ctx, actx context.Context, within time.Duration, cl call, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("kube: %s %s: %w", cl.method, cl.path, ctx.Err())
	}
	why := err.Error()
	var ue *url.Error
	if errors.As(err, &ue) {
		why = ue.Err.Error()
	}
	if errors.Is(actx.Err(), context.DeadlineExceeded) {
		why = fmt.Sprintf("no answer within %s", within)
	}
	return &wireError{
		msg:      fmt.Sprintf("kube: %s %s: the API server could not be reached: %s", cl.method, cl.path, why),
		sentinel: ErrUnreachable,
		cause:    err,
	}
}

// retryAfter is the wait an answer asks for: its Retry-After in whole
// seconds, capped at maxRetryWait, or defaultRetryWait when it names none or
// names a date.
func retryAfter(h http.Header) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(h.Get("Retry-After")))
	if err != nil || n < 0 {
		return defaultRetryWait
	}
	// Capped before it is multiplied, so a large value cannot overflow into
	// a negative or short wait.
	if n > int(maxRetryWait/time.Second) {
		return maxRetryWait
	}
	return time.Duration(n) * time.Second
}

// sleepContext waits d, or until ctx ends.
func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// noteWarnings keeps each distinct text of an answer's Warning headers, in
// the order first seen.
func (c *Client) noteWarnings(h http.Header) {
	texts := parseWarnings(h.Values("Warning"))
	if len(texts) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, t := range texts {
		if c.seen == nil {
			c.seen = map[string]bool{}
		}
		if !c.seen[t] {
			c.seen[t] = true
			c.warnings = append(c.warnings, t)
		}
	}
}

// parseWarnings reads Warning header values in RFC 7234 §5.5's form, the one
// the API server writes: a comma-separated list of
// warn-code SP warn-agent SP warn-text [SP warn-date], with warn-text a
// quoted-string. It keeps the text of each code-299 warning, the only code
// the API server sends. A value that stops parsing keeps what it read before.
// Written from the RFC, not ported: k8s.io/apimachinery's ParseWarningHeader
// was not fetched for this.
func parseWarnings(values []string) []string {
	var texts []string
	for _, v := range values {
		for {
			v = strings.TrimLeft(v, " \t,")
			if v == "" {
				break
			}
			code, rest, ok := strings.Cut(v, " ")
			if !ok || len(code) != 3 {
				break
			}
			_, rest, ok = strings.Cut(strings.TrimLeft(rest, " "), " ")
			if !ok {
				break
			}
			text, rest, ok := unquote(strings.TrimLeft(rest, " "))
			if !ok {
				break
			}
			if trimmed := strings.TrimLeft(rest, " \t"); strings.HasPrefix(trimmed, `"`) {
				if _, after, ok := unquote(trimmed); ok {
					rest = after
				}
			}
			if code == "299" {
				texts = append(texts, text)
			}
			v = rest
		}
	}
	return texts
}

// unquote reads one quoted-string from the start of s, with \ escaping the
// character after it, and returns its contents and what follows it.
func unquote(s string) (text, rest string, ok bool) {
	if !strings.HasPrefix(s, `"`) {
		return "", s, false
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if i+1 >= len(s) {
				return "", s, false
			}
			i++
			b.WriteByte(s[i])
		case '"':
			return b.String(), s[i+1:], true
		default:
			b.WriteByte(s[i])
		}
	}
	return "", s, false
}
