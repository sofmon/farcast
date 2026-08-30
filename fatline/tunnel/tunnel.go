// Package tunnel is FatLine's client side: the operator (and later the FarSight
// GUI) dials it to establish the mutually-authenticated session into an
// instance. It is the one import surface `farcast connect` (2.3) consumes, so
// it is public and depends only on standard-library types in its API.
//
// The default carrier is bound at 2.3 (ADR 0005); in 2.1 the endpoint is
// whatever address the server listens on (a ClusterIP / loopback in tests).
// Either way the client presents its certificate, trusts ONLY the per-instance
// CA, and pins the server name.
package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sofmon/farcast/fatline"
	fcrypto "github.com/sofmon/farcast/fatline/internal/crypto"
)

// ClientIdentity is the operator's data-plane credential: a client leaf + key,
// the per-instance CA to verify the server, and the server name to pin.
type ClientIdentity struct {
	Cert       tls.Certificate
	CA         *x509.CertPool
	ServerName string
}

// Conn is an established tunnel. Its HTTPClient routes requests through the
// instance over the mutually-authenticated, multiplexed session.
type Conn struct {
	endpoint string
	client   *http.Client
}

// Connect dials endpoint (a base URL such as https://host:port), performs the
// mTLS handshake, and verifies reachability by probing the status endpoint so a
// bad certificate or unreachable instance fails here, not on first use.
func Connect(ctx context.Context, endpoint string, id ClientIdentity) (*Conn, error) {
	tr := &http.Transport{
		TLSClientConfig:   fcrypto.ClientTLSConfig(id.Cert, id.CA, id.ServerName),
		ForceAttemptHTTP2: true,
		IdleConnTimeout:   90 * time.Second,
	}
	c := &Conn{endpoint: strings.TrimRight(endpoint, "/"), client: &http.Client{Transport: tr}}
	if _, err := c.Status(ctx); err != nil {
		tr.CloseIdleConnections()
		return nil, fmt.Errorf("fatline: connect %s: %w", endpoint, err)
	}
	return c, nil
}

// HTTPClient returns an *http.Client whose requests route through the instance.
func (c *Conn) HTTPClient() *http.Client { return c.client }

// Status queries the instance's network-boundary health over the tunnel.
func (c *Conn) Status(ctx context.Context) (fatline.ConnStatus, error) {
	var st fatline.ConnStatus
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+fatline.StatusPath, nil)
	if err != nil {
		return st, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return st, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return st, fmt.Errorf("fatline: status %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return st, fmt.Errorf("fatline: decode status: %w", err)
	}
	return st, nil
}

// Close releases the tunnel's idle connections.
func (c *Conn) Close() error {
	c.client.CloseIdleConnections()
	return nil
}

// DialStream opens an opaque, full-duplex byte stream to a named in-instance
// service through the tunnel.
//
// FatLine relays the bytes and does not terminate them, so a TLS session run
// over the returned connection is end-to-end between this process and the
// service — which is what lets an operator hand key material to the DataSphere
// keyholder without it ever existing in FatLine's address space.
//
// The caller names a ROUTE, never an address. FatLine expands the name against
// a closed table fixed at deploy time, so an operator credential reaches the
// services FarCast deployed and is not a general port-forward into the
// cluster. Pass a negative ordinal for a route that addresses a single service;
// a non-negative one selects a replica of a StatefulSet.
//
// The returned connection's deadline methods are no-ops: the stream's lifetime
// is governed by ctx, and cancelling it tears the stream down.
func (c *Conn) DialStream(ctx context.Context, route string, ordinal int) (net.Conn, error) {
	if route == "" {
		return nil, fmt.Errorf("fatline: stream route is required")
	}
	target := c.endpoint + fatline.StreamPathPrefix + url.PathEscape(route)
	if ordinal >= 0 {
		target += "?ordinal=" + strconv.Itoa(ordinal)
	}

	// The request body is a pipe so the caller can keep writing after the
	// response headers arrive — that is what makes the stream duplex rather
	// than request-then-response.
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, pr)
	if err != nil {
		_ = pw.CloseWithError(err)
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := c.client.Do(req)
	if err != nil {
		_ = pw.CloseWithError(err)
		return nil, fmt.Errorf("fatline: dial stream %q: %w", route, err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		_ = pw.Close()
		return nil, fmt.Errorf("fatline: dial stream %q: %s", route, resp.Status)
	}
	// A relay that fell back to HTTP/1.1 would not be duplex, and the
	// symptom is a hang rather than an error — so it is refused here.
	if resp.ProtoMajor != 2 {
		_ = resp.Body.Close()
		_ = pw.Close()
		return nil, fmt.Errorf("fatline: dial stream %q: relay negotiated HTTP/%d, which cannot carry a duplex stream", route, resp.ProtoMajor)
	}
	return &streamConn{w: pw, r: resp.Body}, nil
}

// streamConn adapts the relayed HTTP/2 stream to net.Conn so a TLS session can
// run over it.
type streamConn struct {
	w *io.PipeWriter
	r io.ReadCloser
}

func (s *streamConn) Read(p []byte) (int, error)  { return s.r.Read(p) }
func (s *streamConn) Write(p []byte) (int, error) { return s.w.Write(p) }

func (s *streamConn) Close() error {
	werr := s.w.Close()
	rerr := s.r.Close()
	if werr != nil {
		return werr
	}
	return rerr
}

// CloseWrite half-closes the stream, so the far side sees a clean EOF while
// this side keeps reading.
func (s *streamConn) CloseWrite() error { return s.w.Close() }

func (*streamConn) LocalAddr() net.Addr  { return streamAddr{} }
func (*streamConn) RemoteAddr() net.Addr { return streamAddr{} }

// Deadlines are no-ops: the stream lives and dies with the request context.
func (*streamConn) SetDeadline(time.Time) error      { return nil }
func (*streamConn) SetReadDeadline(time.Time) error  { return nil }
func (*streamConn) SetWriteDeadline(time.Time) error { return nil }

type streamAddr struct{}

func (streamAddr) Network() string { return "fatline-stream" }
func (streamAddr) String() string  { return "fatline-stream" }
