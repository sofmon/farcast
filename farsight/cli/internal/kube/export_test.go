package kube

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
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

// NewFederationForTest is NewFederation pointed at loopback fakes, for package
// kube_test. stsAddr and iamAddr are host:port with an IP in 127.0.0.0/8 or
// ::1, classified as ParseEndpoint's loopback mode classifies it, and roots is
// their CA. Each host's dialer reaches its own address alone, and TLS
// verifies the IP.
func NewFederationForTest(stsAddr, iamAddr string, roots *x509.CertPool) (*Federation, error) {
	if roots == nil {
		return nil, errors.New("kube: NewFederationForTest needs the fakes' CA")
	}
	sts, err := loopbackFederationHost(stsAddr, roots)
	if err != nil {
		return nil, err
	}
	iam, err := loopbackFederationHost(iamAddr, roots)
	if err != nil {
		return nil, err
	}
	return newFederation(sts, iam)
}

// msgLoopbackFederation is NewFederationForTest's refusal of an address.
const msgLoopbackFederation = "kube: NewFederationForTest takes a loopback IP literal with its port (127.0.0.0/8 or ::1), not %q"

// loopbackFederationHost is one loopback destination: the address must be
// an Endpoint ParseEndpoint's loopback mode would make (classified), and the
// dialer may reach it alone.
func loopbackFederationHost(addr string, roots *x509.CertPool) (federationHost, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || !classified(Endpoint{Mode: ModeLoopback, Host: host, Port: port, CA: roots}) {
		return federationHost{}, refuse(ErrEndpointRefused, msgLoopbackFederation, addr)
	}
	hostPort := net.JoinHostPort(host, port)
	return federationHost{
		origin:     "https://" + hostPort,
		host:       hostPort,
		serverName: host,
		roots:      roots,
		dialOnly:   hostPort,
	}, nil
}

// SetFederationClock replaces f's wall clock.
func SetFederationClock(f *Federation, now func() time.Time) { f.now = now }

// WithFederatedBearer puts tok on ctx under the federated bearer's own key,
// for package kube_test: a wire test sends an exchange with one on its
// context, which the exchange transport must never send.
func WithFederatedBearer(ctx context.Context, tok *auth.Token) context.Context {
	return withFederatedBearer(ctx, tok)
}

// FederationDial dials address through f's STS dialer (sts true) or its IAM
// Credentials dialer, as the transport's DialContext would, and closes what
// it reached, for package kube_test's dial-guard rows.
func FederationDial(ctx context.Context, f *Federation, sts bool, address string) error {
	h := f.iam
	if sts {
		h = f.sts
	}
	c, err := h.dialContext()(ctx, "tcp", address)
	if err != nil {
		return err
	}
	return c.Close()
}
