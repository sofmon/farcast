// Package keyholder is the operator's side of the DataSphere keyholder
// protocol: fetch a challenge, seal a bundle to one specific process, push it,
// and report what came back.
//
// Every call rides an opaque byte stream through FatLine with its own TLS
// session inside, so the bundle is end-to-end between this machine and the
// keyholder. FatLine relays bytes it holds no key for — the reason key
// material never exists in the address space of the process that parses
// attacker-controlled input.
package keyholder

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	dskeyholder "github.com/sofmon/farcast/datasphere/keyholder"
	"github.com/sofmon/farcast/fatline/identity"
	"github.com/sofmon/farcast/fatline/tunnel"
)

// StreamRoute is the FatLine route that reaches the keyholder.
const StreamRoute = "datasphered"

// requestTimeout bounds a single call to one replica.
const requestTimeout = 30 * time.Second

// State is what a replica reports about itself.
type State struct {
	Instance   string    `json:"instance"`
	Phase      string    `json:"phase"`
	Since      time.Time `json:"since"`
	Generation uint64    `json:"generation"`
	HoldReason string    `json:"hold_reason,omitempty"`
	Scopes     []string  `json:"scopes,omitempty"`
}

// Sealed reports whether this replica is holding no key material.
func (s State) Sealed() bool { return s.Phase != "unsealed" }

// Dialer opens a stream to one replica. It is an interface so the commands can
// be tested without a cluster.
type Dialer interface {
	DialStream(ctx context.Context, route string, ordinal int) (net.Conn, error)
}

// Client speaks to an instance's keyholder replicas.
type Client struct {
	dialer   Dialer
	instance string
	tlsCfg   *tls.Config
}

// New builds a client from the operator's own mTLS material.
func New(dialer Dialer, instance string, caCertPEM, clientCertPEM, clientKeyPEM []byte) (*Client, error) {
	cert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("keyholder: the operator certificate and key do not form a valid pair")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("keyholder: no certificate in the instance CA material")
	}
	return &Client{
		dialer:   dialer,
		instance: instance,
		tlsCfg: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cert},
			RootCAs:      pool,
			ServerName:   identity.KeyholderServerName(instance),
			// Pinned so the inner session is HTTP/1.1: the relay carries
			// bytes, and negotiating h2 inside it would add a multiplexer
			// nobody needs on a one-request-per-stream path.
			NextProtos: []string{"http/1.1"},
		},
	}, nil
}

// State asks one replica what it is doing.
func (c *Client) State(ctx context.Context, ordinal int) (State, error) {
	var st State
	err := c.call(ctx, ordinal, http.MethodGet, "/v1/state", "", nil, &st)
	return st, err
}

// Unseal seals a bundle to one replica and pushes it.
//
// The challenge is fetched from that same replica moments before, and is
// answerable only by the process that issued it — so a bundle prepared for one
// replica cannot be replayed into another, or into the same one twice.
func (c *Client) Unseal(ctx context.Context, ordinal int, bundle []byte, intent string) (State, error) {
	var challenge dskeyholder.Challenge
	if err := c.call(ctx, ordinal, http.MethodGet, dskeyholder.SealChallengePath, "", nil, &challenge); err != nil {
		return State{}, fmt.Errorf("fetching a challenge from replica %d: %w", ordinal, err)
	}
	sealed, err := dskeyholder.SealBundle(bundle, c.instance, challenge)
	if err != nil {
		return State{}, err
	}
	var st State
	path := "/v1/unseal?intent=" + intent
	err = c.call(ctx, ordinal, http.MethodPost, path, dskeyholder.ContentTypeSealed, sealed, &st)
	return st, err
}

// Seal drops a replica's key material, optionally as a deliberate hold.
func (c *Client) Seal(ctx context.Context, ordinal int, hold bool, reason string) (State, error) {
	path := fmt.Sprintf("/v1/seal?hold=%t&reason=%s", hold, urlQueryEscape(reason))
	var st State
	err := c.call(ctx, ordinal, http.MethodPost, path, "", nil, &st)
	return st, err
}

// ReleaseHold makes a held replica eligible for an unattended re-seed again.
// It does not hand back key material: the replica lands sealed.
func (c *Client) ReleaseHold(ctx context.Context, ordinal int) (State, error) {
	var st State
	err := c.call(ctx, ordinal, http.MethodPost, "/v1/release-hold", "", nil, &st)
	return st, err
}

// call runs one request over its own relayed stream.
//
// A stream carries exactly one request: these are rare, deliberate operations
// on the process holding the crown jewels, and a pooled connection that
// outlived its purpose would be a standing path into it.
func (c *Client) call(ctx context.Context, ordinal int, method, path, contentType string, body []byte, out any) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	raw, err := c.dialer.DialStream(ctx, StreamRoute, ordinal)
	if err != nil {
		return fmt.Errorf("reaching replica %d: %w", ordinal, err)
	}
	defer func() { _ = raw.Close() }()

	conn := tls.Client(raw, c.tlsCfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		// Named precisely: this is the check that the process on the far end
		// is the keyholder this instance's CA vouches for, and not something
		// the cloud stood up in its place.
		return fmt.Errorf("replica %d did not present a certificate this instance's CA vouches for: %w", ordinal, err)
	}
	defer func() { _ = conn.Close() }()

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://"+c.tlsCfg.ServerName+path, reader)
	if err != nil {
		return err
	}
	req.Host = c.tlsCfg.ServerName
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if body != nil {
		req.ContentLength = int64(len(body))
	}
	if err := req.Write(conn); err != nil {
		return fmt.Errorf("sending to replica %d: %w", ordinal, err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return fmt.Errorf("reading from replica %d: %w", ordinal, err)
	}
	defer func() { _ = resp.Body.Close() }()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("reading from replica %d: %w", ordinal, err)
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("replica %d refused: %s", ordinal, refusalReason(payload, resp.Status))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("replica %d answered unintelligibly", ordinal)
	}
	return nil
}

// refusalReason pulls the keyholder's own message out of an error body.
func refusalReason(payload []byte, fallback string) string {
	var body struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if json.Unmarshal(payload, &body) == nil && body.Message != "" {
		if body.Code != "" {
			return body.Message + " (" + body.Code + ")"
		}
		return body.Message
	}
	return fallback
}

// urlQueryEscape is a minimal escaper for the one free-text value that reaches
// a query string. A hold reason is operator prose and must not be able to add
// parameters of its own.
func urlQueryEscape(s string) string {
	var b bytes.Buffer
	for i := range len(s) {
		ch := s[i]
		switch {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9',
			ch == '-', ch == '_', ch == '.', ch == '~':
			b.WriteByte(ch)
		default:
			fmt.Fprintf(&b, "%%%02X", ch)
		}
	}
	return b.String()
}

// Conn adapts a live tunnel connection to the Dialer this package needs.
func Conn(c *tunnel.Conn) Dialer { return c }
