package gcs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sofmon/farcast/datasphere"
)

// This adapter is hand-issued REST, so the wire IS the contract: a wrong URL,
// a missing body field, or a raw "/" where a %2F belongs is a production bug
// that no amount of Go-level testing would catch. Every test in this package
// therefore drives the REAL adapter through a fake http.RoundTripper and
// asserts on the exact method, URL, headers and body of every request — the
// same discipline as the GKE registry adapter's wire tests, and with the same
// cost: no listener, no network, no credentials, no cloud spend.
//
// Two package variables are the seams. newHTTPClient supplies the transport
// (so credential resolution never runs) and retryBackoff collapses the retry
// schedule (so the retry paths are exercised without sleeping). Both are
// process-global, which is why nothing here calls t.Parallel.

const (
	testProject  = "farcast-test-proj"
	testLocation = "europe-west1"
	testInstance = "demo"

	// testBucket has the shape the spec mints: the legible prefix plus the 8
	// random hex characters that are the actual uniqueness, and that exist
	// nowhere but the caller's local record.
	testBucket = "farcast-demo-0a1b2c3d"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// capturedRequest is one request exactly as the adapter put it on the wire.
type capturedRequest struct {
	method string
	url    string
	header http.Header
	body   []byte
}

// query decodes the request's query string once. Asserting on decoded values
// is what catches double-encoding: a prefix escaped twice decodes to the
// literal "%2F" rather than to "/".
func (r capturedRequest) query(t *testing.T) url.Values {
	t.Helper()
	u, err := url.Parse(r.url)
	if err != nil {
		t.Fatalf("parse request URL %q: %v", r.url, err)
	}
	return u.Query()
}

// fakeCloud records every exchange the adapter attempts.
type fakeCloud struct {
	mu   sync.Mutex
	seen []capturedRequest
}

func (f *fakeCloud) record(r capturedRequest) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r)
}

func (f *fakeCloud) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.seen)
}

// request returns the i-th captured request, failing the test if the adapter
// never made it — a missing call is as much a finding as a wrong one.
func (f *fakeCloud) request(t *testing.T, i int) capturedRequest {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if i >= len(f.seen) {
		t.Fatalf("expected at least %d requests, got %d: %v", i+1, len(f.seen), traceOf(f.seen))
	}
	return f.seen[i]
}

// trace renders the calls as "METHOD path", which is the form the teardown
// ordering assertions compare against.
func (f *fakeCloud) trace() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return traceOf(f.seen)
}

func traceOf(seen []capturedRequest) []string {
	out := make([]string, 0, len(seen))
	for _, r := range seen {
		u, err := url.Parse(r.url)
		if err != nil {
			out = append(out, r.method+" "+r.url)
			continue
		}
		out = append(out, r.method+" "+u.EscapedPath())
	}
	return out
}

// newTestProvider builds the real adapter over a fake transport that answers
// from replies, in order.
//
// The endpoints stay the production ones — New sets them — so every URL
// assertion below pins the endpoint FarCast actually calls, not a fixture.
func newTestProvider(t *testing.T, replies ...*http.Response) (*provider, *fakeCloud) {
	t.Helper()
	return newTestProviderFunc(t, queued(t, replies...))
}

// newTestProviderFunc is the routing variant, for the handful of tests whose
// reply depends on the request rather than on its position in a script.
func newTestProviderFunc(t *testing.T, respond func(*http.Request) (*http.Response, error)) (*provider, *fakeCloud) {
	t.Helper()

	fake := &fakeCloud{}
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var body []byte
		if r.Body != nil {
			b, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			body = b
		}
		fake.record(capturedRequest{method: r.Method, url: r.URL.String(), header: r.Header.Clone(), body: body})
		return respond(r)
	})

	oldClient, oldBackoff := newHTTPClient, retryBackoff
	t.Cleanup(func() { newHTTPClient, retryBackoff = oldClient, oldBackoff })
	newHTTPClient = func(datasphere.Config) (*http.Client, error) {
		return &http.Client{Transport: transport}, nil
	}
	// Short enough that the retry paths cost nothing; individual tests raise it
	// again when the point is that a backoff was abandoned rather than waited.
	retryBackoff = time.Microsecond

	p, err := New(datasphere.Config{Project: testProject, Location: testLocation})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	gp, ok := p.(*provider)
	if !ok {
		t.Fatalf("New returned %T, want *provider", p)
	}
	return gp, fake
}

// queued answers from replies in order and fails the test on an unscripted
// request: an adapter making a call the test did not expect is a finding.
func queued(t *testing.T, replies ...*http.Response) func(*http.Request) (*http.Response, error) {
	t.Helper()
	i := 0
	return func(r *http.Request) (*http.Response, error) {
		if i >= len(replies) {
			t.Errorf("unscripted request %d: %s %s", i+1, r.Method, r.URL)
			return jsonReply(http.StatusInternalServerError, `{}`), nil
		}
		reply := replies[i]
		i++
		return reply, nil
	}
}

func jsonReply(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

// mediaReply is the alt=media download shape: arbitrary bytes plus the
// X-Goog-Meta-* headers that carry an object's custom metadata.
func mediaReply(status int, header http.Header, body []byte) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(bytes.NewReader(body))}
}

// errorReply is the JSON error envelope the API answers failures with.
func errorReply(code int, status, message string) *http.Response {
	return jsonReply(code, fmt.Sprintf(`{"error":{"code":%d,"message":%q,"status":%q}}`, code, message, status))
}

// repeatReply builds n identical responses. Each needs its own body, because a
// response body is read exactly once.
func repeatReply(n int, build func() *http.Response) []*http.Response {
	out := make([]*http.Response, 0, n)
	for range n {
		out = append(out, build())
	}
	return out
}

// jsonField walks a decoded JSON document, so the body assertions pin the
// literal wire keys rather than this package's own struct tags — decoding a
// request body back through bucketResource would round-trip a renamed tag
// invisibly, which is exactly the bug that would silently unharden a bucket.
func jsonField(t *testing.T, body []byte, path ...string) any {
	t.Helper()
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode request body: %v", err)
	}
	for i, key := range path {
		obj, ok := doc.(map[string]any)
		if !ok {
			t.Fatalf("%v is not a JSON object; body = %s", path[:i], body)
		}
		next, ok := obj[key]
		if !ok {
			t.Fatalf("request body has no %v; body = %s", path[:i+1], body)
		}
		doc = next
	}
	return doc
}

// TestProviderRegistration pins the database/sql-shaped wiring: a blank import
// of datasphere/providers must be all a composition root needs to reach GCS.
func TestProviderRegistration(t *testing.T) {
	if names := datasphere.Providers(); !slices.Contains(names, providerName) {
		t.Fatalf("Providers() = %v, want it to contain %q", names, providerName)
	}
	p, err := datasphere.Open(providerName, datasphere.Config{Project: testProject, Location: testLocation})
	if err != nil {
		t.Fatalf("Open(%q): %v", providerName, err)
	}
	if p.Name() != providerName {
		t.Errorf("Name() = %q, want %q", p.Name(), providerName)
	}
}

// TestNewRejectsAnEmptyProject guards the one thing New can check without
// touching the network: every URL this adapter builds names the project, and a
// missing one would surface as a baffling API error much later.
func TestNewRejectsAnEmptyProject(t *testing.T) {
	if _, err := New(datasphere.Config{Location: testLocation}); err == nil {
		t.Fatal("New with no project must fail")
	}
	if _, err := datasphere.Open(providerName, datasphere.Config{}); err == nil {
		t.Fatal("Open must surface the factory's refusal")
	}
}
