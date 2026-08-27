package gcs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/datasphere"
)

// The wire layer's own behaviour: what gets retried, what does not, and what
// happens when the caller gives up mid-backoff.
//
// Hand-rolling the protocol means owning its transient-failure handling, and
// the retry policy is a correctness question rather than a comfort: retrying
// too little makes an ordinary 503 a teardown that leaves a billable bucket
// behind, and retrying a 403 or a 404 turns a request-level mistake into five
// times the latency and five times the log noise.

// The credentials probe is the cheapest call the adapter makes and touches no
// state, so it is what the retry tests drive.
func probe(t *testing.T, p *provider) error {
	t.Helper()
	return p.Validate(context.Background(), datasphere.BucketRef{})
}

// TestSendRetriesTransientFailures: a 429 or a 5xx is about the server or the
// rate, not about this request, and every operation in this adapter is safely
// retryable as a whole request.
func TestSendRetriesTransientFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		code   string
	}{
		{"service unavailable", http.StatusServiceUnavailable, "UNAVAILABLE"},
		{"rate limited", http.StatusTooManyRequests, "RESOURCE_EXHAUSTED"},
		{"internal", http.StatusInternalServerError, "INTERNAL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, fake := newTestProvider(t,
				errorReply(tc.status, tc.code, "try again"),
				jsonReply(http.StatusOK, `{"items":[]}`),
			)
			if err := probe(t, p); err != nil {
				t.Fatalf("a transient %d must be retried, not surfaced: %v", tc.status, err)
			}
			if n := fake.count(); n != 2 {
				t.Errorf("made %d attempts, want the failure plus one retry", n)
			}
		})
	}
}

// TestSendExhaustsItsAttempts: the retries are bounded. An adapter that
// retried forever would hang a teardown behind a cloud outage, and the error
// has to say how hard it tried so an operator can tell a blip from an outage.
func TestSendExhaustsItsAttempts(t *testing.T) {
	p, fake := newTestProvider(t, repeatReply(maxAttempts, func() *http.Response {
		return errorReply(http.StatusInternalServerError, "INTERNAL", "backend error")
	})...)

	err := probe(t, p)
	if err == nil {
		t.Fatal("expected an error once the attempts are exhausted")
	}
	if want := fmt.Sprintf("%d attempts", maxAttempts); !strings.Contains(err.Error(), want) {
		t.Errorf("err = %v, want it to name the attempt count (%q)", err, want)
	}
	if n := fake.count(); n != maxAttempts {
		t.Errorf("made %d attempts, want %d", n, maxAttempts)
	}
}

// TestSendDoesNotRetryRequestFailures. A 404 and a 403 are answers about the
// request — the resource is not there, or this credential may not have it —
// and repeating an identical request cannot change either. Retrying them also
// costs the caller the full backoff schedule on the single most common
// non-error outcome in this adapter (an absent bucket, an absent object).
func TestSendDoesNotRetryRequestFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		code   string
	}{
		{"not found", http.StatusNotFound, "NOT_FOUND"},
		{"forbidden", http.StatusForbidden, "PERMISSION_DENIED"},
		{"bad request", http.StatusBadRequest, "INVALID_ARGUMENT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, fake := newTestProvider(t, errorReply(tc.status, tc.code, "no"))
			if err := probe(t, p); err == nil {
				t.Fatalf("expected the %d to surface", tc.status)
			}
			if n := fake.count(); n != 1 {
				t.Errorf("made %d attempts, want exactly one: a %d is about the request, not the server", n, tc.status)
			}
		})
	}
}

// TestSendAbandonsTheBackoffWhenTheContextIsDone. The backoff schedule is
// seconds long by design, and a cancelled caller must not be held for it —
// ctx is the only bound the operator has on a command that is already going
// badly.
func TestSendAbandonsTheBackoffWhenTheContextIsDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p, fake := newTestProviderFunc(t, func(*http.Request) (*http.Response, error) {
		// The caller gives up while the adapter is between attempts.
		cancel()
		return errorReply(http.StatusServiceUnavailable, "UNAVAILABLE", "try again"), nil
	})
	// Long enough that waiting it out would be unmistakable in the elapsed
	// time below; the point of the test is that it is never waited out.
	retryBackoff = time.Hour

	start := time.Now()
	err := p.Validate(ctx, datasphere.BucketRef{})
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if elapsed > 5*time.Second {
		t.Errorf("took %v, want the backoff abandoned rather than slept out", elapsed)
	}
	if n := fake.count(); n != 1 {
		t.Errorf("made %d attempts, want no attempt after the cancellation", n)
	}
}

// TestAPIErrorParsingAndClassification. Every idempotency decision in this
// adapter — adopt on 409, success on 404, refuse on 403 — reads the status off
// this error, through several layers of wrapping.
func TestAPIErrorParsingAndClassification(t *testing.T) {
	err := parseAPIError(http.StatusConflict, []byte(`{"error":{"code":409,"message":"you already own it","status":"CONFLICT"}}`))
	if !isHTTPStatus(err, http.StatusConflict) {
		t.Fatalf("err = %v, want it classified as 409", err)
	}
	if !strings.Contains(err.Error(), "CONFLICT") || !strings.Contains(err.Error(), "you already own it") {
		t.Errorf("err = %v, want the canonical status and the service's message", err)
	}
	// Wrapping must not hide the status: every call site here wraps.
	if !isHTTPStatus(fmt.Errorf("gcs: create bucket: %w", err), http.StatusConflict) {
		t.Error("wrapping must not hide the status")
	}
	if isHTTPStatus(errors.New("unrelated"), http.StatusConflict) {
		t.Error("an unrelated error must not classify as 409")
	}
	if isHTTPStatus(nil, http.StatusNotFound) {
		t.Error("a nil error must not classify as a status")
	}
	// A proxy or captive portal answering instead of the API still yields the
	// HTTP status, which is what the idempotency decisions need.
	if plain := parseAPIError(http.StatusForbidden, []byte("<html>nope</html>")); !isHTTPStatus(plain, http.StatusForbidden) {
		t.Errorf("err = %v, want the status preserved without a JSON envelope", plain)
	}
}

func TestRetryableStatus(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   bool
	}{
		{http.StatusOK, false},
		{http.StatusBadRequest, false},
		{http.StatusForbidden, false},
		{http.StatusNotFound, false},
		{http.StatusConflict, false},
		{http.StatusTooManyRequests, true},
		{http.StatusInternalServerError, true},
		{http.StatusBadGateway, true},
		{http.StatusServiceUnavailable, true},
		{http.StatusGatewayTimeout, true},
	} {
		if got := retryableStatus(tc.status); got != tc.want {
			t.Errorf("retryableStatus(%d) = %v, want %v", tc.status, got, tc.want)
		}
	}
}

// TestSendRefusesAnOversizedBody pins that hitting the response cap is a loud
// failure rather than a quiet truncation.
//
// The quiet version is the dangerous one. A clipped ciphertext travels back up
// as a perfectly ordinary blob and fails authentication in Store, so the
// operator is told their data was tampered with or corrupted when what actually
// happened is that a response outgrew a cap in the adapter. Those demand
// completely different responses, and only one of them is true.
func TestSendRefusesAnOversizedBody(t *testing.T) {
	p, _ := newTestProvider(t, mediaReply(http.StatusOK, nil, bytes.Repeat([]byte{'x'}, 64)))

	_, err := p.send(context.Background(), http.MethodGet, "https://storage.googleapis.com/whatever", "", nil, 32)
	if err == nil {
		t.Fatal("send returned nil, want a refusal: a truncated body must never be handed back as data")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Errorf("err = %v, want it to say the body was refused for exceeding the cap", err)
	}
}

// TestSendAcceptsABodyExactlyAtTheCap guards the boundary the test above
// depends on: the cap is inclusive, so a response of exactly limit bytes is
// complete and must not be mistaken for an overflow.
func TestSendAcceptsABodyExactlyAtTheCap(t *testing.T) {
	body := bytes.Repeat([]byte{'x'}, 32)
	p, _ := newTestProvider(t, mediaReply(http.StatusOK, nil, body))

	rep, err := p.send(context.Background(), http.MethodGet, "https://storage.googleapis.com/whatever", "", nil, 32)
	if err != nil {
		t.Fatalf("send = %v, want a body of exactly the cap to be accepted", err)
	}
	if !bytes.Equal(rep.body, body) {
		t.Errorf("body = %q, want the full %d bytes", rep.body, len(body))
	}
}
