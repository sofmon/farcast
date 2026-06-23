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
	"net/http"
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
