package gcs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"time"

	"cloud.google.com/go/auth"
	"cloud.google.com/go/auth/credentials"
	"cloud.google.com/go/auth/httptransport"

	"github.com/sofmon/farcast/datasphere"
)

// The wire layer. Every call this adapter makes is hand-issued net/http plus
// encoding/json over the Google auth stack the repo already vendors — the same
// division ADR 0007 settled for the instance registry: own the boring REST
// protocol, never own auth.
//
// The trade is measured, not assumed: the official clients for this API were
// weighed against a zero-new-vendored-module budget in a binary that holds the
// operator's cloud credentials, and the measurement is recorded in the module
// README's decision 8. What is emphatically NOT re-owned here is credential
// resolution, token minting, or refresh — all of that stays inside
// cloud.google.com/go/auth, which is what answers ADR 0006's objection to
// hand-rolled REST.

const (
	// jsonAPIBase and uploadAPIBase are the JSON API's two hosts. Uploads use a
	// separate path prefix; everything else is the plain resource API.
	jsonAPIBase   = "https://storage.googleapis.com/storage/v1/"
	uploadAPIBase = "https://storage.googleapis.com/upload/storage/v1/"

	// storageScope is the narrowest OAuth2 scope covering bucket
	// create/get/patch/delete plus object CRUD. cloud-platform would work and
	// would also hand this token every other API in the project.
	storageScope = "https://www.googleapis.com/auth/devstorage.full_control"

	// maxResponseBytes caps an ordinary JSON response. A bucket resource and an
	// error envelope are kilobytes; the cap exists so a captive portal or a
	// proxy error page cannot make the credential-holding CLI allocate without
	// bound.
	maxResponseBytes = 1 << 20

	// maxListBytes caps an object listing, which is emphatically NOT
	// kilobytes and must not share the cap above.
	//
	// One page is maxListResults entries, and each entry carries the object's
	// name plus its custom metadata map — which is where the sealed logical
	// name rides, and the reason a listing costs one round trip instead of one
	// fetch per object. Sized against GCS's own published per-object limits
	// rather than against what FarCast happens to write today: 1024 bytes of
	// object name plus 8 KiB of custom metadata plus JSON framing is roughly
	// 9.5 KB per entry, so a full page can legitimately approach 9.5 MB.
	//
	// Getting this wrong is not a truncation, it is an outage: send refuses an
	// over-cap body outright and the status is not retryable, so a bucket whose
	// keys are merely long — well inside what the module advertises as legal —
	// would become permanently unlistable, with the header-fallback recovery
	// path never reached because the failure is in the page fetch itself.
	maxListBytes = 16 << 20

	// maxObjectBytes caps a downloaded object body. It sits generously above
	// the 64 MiB plaintext limit the encrypting layer enforces (plus its ~163
	// bytes of envelope) for the same reason: an endpoint that answers with an
	// endless stream must not be able to exhaust memory.
	maxObjectBytes = 96 << 20
)

// Retry policy. Hand-rolling the protocol means owning its transient-failure
// handling too, and every operation here is safely retryable as a whole
// request: an upload is atomic per stored name, a delete treats absence as
// success, and the reads are reads. What must never exist is a partial resume
// of an upload body — a truncated ciphertext would pass silently at write time
// and only surface as an integrity failure on a read, long afterwards.
const (
	maxAttempts = 5
	maxBackoff  = 8 * time.Second
)

// retryBackoff is the first backoff step, doubling per attempt with full
// jitter. It is a package variable so tests can drive the retry paths without
// sleeping.
var retryBackoff = 250 * time.Millisecond

// newHTTPClient builds the authenticated client. It is a package variable so
// tests can substitute a fake RoundTripper and exercise the whole wire
// protocol with no listener, no network, and no credentials.
var newHTTPClient = func(cfg datasphere.Config) (*http.Client, error) {
	creds, err := storageCredentials(cfg)
	if err != nil {
		return nil, fmt.Errorf("gcs: resolve credentials: %w", err)
	}
	hc, err := httptransport.NewClient(&httptransport.Options{Credentials: creds})
	if err != nil {
		return nil, fmt.Errorf("gcs: build HTTP client: %w", err)
	}
	return hc, nil
}

// storageCredentials resolves the credential that authenticates every call. A
// configured key is loaded as a service account and nothing else: the
// type-restricted loader refuses, say, an external-account configuration that
// would redirect token minting at a URL of the file author's choosing. An
// empty Config.Credentials falls back to Application Default Credentials.
func storageCredentials(cfg datasphere.Config) (*auth.Credentials, error) {
	opts := &credentials.DetectOptions{Scopes: []string{storageScope}}
	if len(cfg.Credentials) > 0 {
		return credentials.NewCredentialsFromJSON(credentials.ServiceAccount, cfg.Credentials, opts)
	}
	return credentials.DetectDefault(opts)
}

// client lazily builds the authenticated HTTP client. Construction resolves
// credentials, so — as in Planck's adapters — it is deferred out of New and
// first surfaces through whichever operation the caller actually runs.
func (p *provider) client() (*http.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.hc == nil {
		hc, err := newHTTPClient(p.cfg)
		if err != nil {
			return nil, err
		}
		p.hc = hc
	}
	return p.hc, nil
}

// reply is one completed HTTP exchange, already read and bounded.
type reply struct {
	status int
	header http.Header
	body   []byte
}

// send issues one request with retries, returning the final reply. body may be
// nil; it is buffered rather than streamed precisely so that a retry replays
// the identical bytes.
func (p *provider) send(ctx context.Context, method, target, contentType string, body []byte, limit int64) (*reply, error) {
	hc, err := p.client()
	if err != nil {
		return nil, err
	}

	backoff := retryBackoff
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			if err := sleepWithContext(ctx, jitter(backoff)); err != nil {
				return nil, err
			}
			if backoff *= 2; backoff > maxBackoff {
				backoff = maxBackoff
			}
		}

		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, target, reader)
		if err != nil {
			return nil, err
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		req.Header.Set("Accept", "application/json")

		resp, err := hc.Do(req)
		if err != nil {
			// A transport error is retryable only if the context is still
			// alive; otherwise the caller cancelled or timed out and retrying
			// would ignore them.
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = err
			continue
		}
		// Read one byte past the cap so that hitting it is detectable. A
		// silently truncated body would be worse than a failure: a clipped
		// ciphertext passes back up as a perfectly ordinary blob and only fails
		// authentication in Store, reporting "tampered or corrupted" for what
		// was really "the response outgrew the adapter's cap".
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		_ = resp.Body.Close()
		if readErr != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = fmt.Errorf("read response: %w", readErr)
			continue
		}
		if retryableStatus(resp.StatusCode) {
			lastErr = parseAPIError(resp.StatusCode, data)
			continue
		}
		if int64(len(data)) > limit {
			return nil, fmt.Errorf("gcs: response body exceeds the %d-byte cap; refusing to return a truncated body", limit)
		}
		return &reply{status: resp.StatusCode, header: resp.Header, body: data}, nil
	}
	return nil, fmt.Errorf("gcs: giving up after %d attempts: %w", maxAttempts, lastErr)
}

// doJSON issues an authenticated JSON request and decodes the response into
// out (nil to discard it). Non-2xx responses become an *apiError carrying the
// status, which is what this adapter's idempotency decisions read.
func (p *provider) doJSON(ctx context.Context, method, target string, in, out any) error {
	return p.doJSONLimit(ctx, method, target, in, out, maxResponseBytes)
}

// doJSONLimit is doJSON with an explicit response cap, for the one call whose
// responses are megabytes rather than kilobytes.
func (p *provider) doJSONLimit(ctx context.Context, method, target string, in, out any, limit int64) error {
	var body []byte
	contentType := ""
	if in != nil {
		encoded, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("encode request body: %w", err)
		}
		body, contentType = encoded, "application/json"
	}
	rep, err := p.send(ctx, method, target, contentType, body, limit)
	if err != nil {
		return err
	}
	if !okStatus(rep.status) {
		return parseAPIError(rep.status, rep.body)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(rep.body, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func okStatus(status int) bool { return status >= 200 && status <= 299 }

// retryableStatus reports whether a status is worth another attempt: rate
// limiting and the server-side failures that are, by definition, not about
// this request's content.
func retryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

// jitter applies full jitter to a backoff step, so a fleet of retrying clients
// does not re-converge on the same instant.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(d)) + 1)
}

// sleepWithContext waits out a backoff without outliving the caller's context.
func sleepWithContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// apiError is a failed Google API call. It carries the status so callers can
// treat "already exists" and "not found" as success, and the service's message
// so an operator sees why a call failed — but never the request, which names
// the project and the credential's audience.
type apiError struct {
	Code    int    // HTTP status
	Status  string // canonical status, e.g. NOT_FOUND
	Message string
}

func (e *apiError) Error() string {
	switch {
	case e.Status != "" && e.Message != "":
		return fmt.Sprintf("cloud API error %d %s: %s", e.Code, e.Status, e.Message)
	case e.Message != "":
		return fmt.Sprintf("cloud API error %d: %s", e.Code, e.Message)
	default:
		return fmt.Sprintf("cloud API error %d", e.Code)
	}
}

// parseAPIError builds an apiError from a non-2xx response, falling back to
// the HTTP status when the body is not the JSON error envelope (a proxy or a
// captive portal answering instead of the API).
func parseAPIError(status int, body []byte) error {
	out := &apiError{Code: status}
	var envelope struct {
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Status  string `json:"status"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err == nil {
		out.Message = envelope.Error.Message
		out.Status = envelope.Error.Status
		if envelope.Error.Code != 0 {
			out.Code = envelope.Error.Code
		}
	}
	return out
}

// isHTTPStatus reports whether err is a cloud API error carrying code.
func isHTTPStatus(err error, code int) bool {
	var apiErr *apiError
	return errors.As(err, &apiErr) && apiErr.Code == code
}
