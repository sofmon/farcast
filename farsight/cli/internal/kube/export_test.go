package kube

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"cloud.google.com/go/auth"
)

// SetSleep replaces c's wait between retries, for package kube_test: the
// retry tests record the waits instead of sleeping them.
func SetSleep(c *Client, f func(ctx context.Context, d time.Duration) error) { c.sleep = f }

// SetAttemptTimeout shortens c's per-attempt deadline of a non-streaming
// request (60 s in a product client), for package kube_test.
func SetAttemptTimeout(c *Client, d time.Duration) { c.attemptTimeout = d }

// SetResponseHeaderTimeout shortens the API transport's wait for an answer's
// headers (30 s in a product client), for package kube_test. The follow
// client, which has none, is left as it is. Call it before c sends anything.
func SetResponseHeaderTimeout(c *Client, d time.Duration) {
	c.api.Transport.(*apiTransport).inner.(*http.Transport).ResponseHeaderTimeout = d
}

// TapAnswers lets f see the whole body of every API answer c receives, with
// its request's method and path, for package kube_test: a test reads what the
// server sent, which the client's decode then reduces to what it declares. f
// runs on the request's own goroutine. Call it before c sends anything, and
// not with SetResponseHeaderTimeout, which reaches the transport it wraps.
func TapAnswers(c *Client, f func(method, path string, body []byte)) {
	at := c.api.Transport.(*apiTransport)
	at.inner = answerTap{inner: at.inner, f: f}
}

type answerTap struct {
	inner http.RoundTripper
	f     func(method, path string, body []byte)
}

func (t answerTap) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.inner.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	t.f(req.Method, req.URL.Path, b)
	resp.Body = io.NopCloser(bytes.NewReader(b))
	return resp, nil
}

// The documents stream_test.go hides a refused key in, from go-yaml alone
// (C-C2-1, C-C2-2), for package kube_test's Apply rows.
const (
	FlowHidingStatus          = flowHidingStatus
	QuestionHidingStringData  = questionHidingStringData
	MultiLineHidingStringData = multiLineHidingStringData
	BareEntryHidingStringData = bareEntryHidingStringData
	LoneQuestionHidingStatus  = loneQuestionHidingStatus
)

// UTF16Polyglot is stream_test.go's UTF-16LE polyglot Secret.
func UTF16Polyglot() string { return utf16Polyglot() }

// SetFederationClock replaces f's wall clock.
func SetFederationClock(f *Federation, now func() time.Time) { f.now = now }

// WithFederatedBearer puts tok on ctx under the federated bearer's own key,
// for package kube_test: a wire test sends an exchange with one on its
// context, which the exchange transport must never send.
func WithFederatedBearer(ctx context.Context, tok *auth.Token) context.Context {
	return withFederatedBearer(ctx, tok)
}

// FederationDial dials address through one of f's three dialers, named as
// kubetest names its servers: "sts", "iam" (IAM Credentials) or "iamapi"
// (IAM's API), as that transport's DialContext would, and closes what it
// reached, for package kube_test's dial-guard rows.
func FederationDial(ctx context.Context, f *Federation, host, address string) error {
	var h federationHost
	switch host {
	case "sts":
		h = f.sts
	case "iam":
		h = f.iam
	case "iamapi":
		h = f.iamAPI
	default:
		return errors.New("kube: FederationDial names sts, iam or iamapi")
	}
	c, err := h.dialContext()(ctx, "tcp", address)
	if err != nil {
		return err
	}
	return c.Close()
}

// TwoLeggedTokensAt is TokenSourceFor for a service-account key with its
// token minted at ep's token endpoint (Endpoint.TokenURL, a loopback one in
// a test) instead of Google's, for package kube_test. Every other rule of
// TokenSourceFor holds, the email's shape and the key's token_uri included.
func TwoLeggedTokensAt(cred Credential, s Scopes, ep Endpoint) (*RoleTokens, error) {
	return tokenSourceFor(cred, s, ep)
}
