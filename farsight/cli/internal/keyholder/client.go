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
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	dskeyholder "github.com/sofmon/farcast/datasphere/keyholder"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
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

	// Boot identifies the keyholder PROCESS that answered, and is served only
	// on the mutually-authenticated control surface. It is what makes a
	// keeper's ledger reconcilable: one reseed per distinct boot is a cluster
	// restarting, and two into the same boot is a live process being asked for
	// key material it already held.
	Boot string `json:"boot,omitempty"`

	// Keys lists, per scope this replica holds, the IDs of every
	// key-encryption key the scope holds, the active one first — control
	// surface only. It is how a pusher tells whether a replica holds the keys
	// it sent; the generation cannot, because it advances on every unseal
	// whether or not a key changed.
	Keys map[string][]string `json:"keys,omitempty"`

	// Pin is the key pin this replica enforces — control surface only. Nil
	// is an image that predates the pin.
	Pin *dskeyholder.PinReport `json:"pin,omitempty"`

	// Node is the Kubernetes node this replica runs on — control surface
	// only. Empty is an image or manifest that predates it, and means
	// "placement unknown", never a node of its own. It is reported, and
	// nothing decides on it.
	Node string `json:"node,omitempty"`
}

// Intents a pusher may claim. The keyholder decides which a caller may use
// from the leaf it presents; these are the names on the wire.
const (
	IntentOperator = string(dskeyholder.IntentOperator)
	IntentHandOver = string(dskeyholder.IntentHandOver)
	// IntentOperatorBelowPin is an operator unseal past the key pin. It is
	// not an intent on the wire — Unseal sends operator-unseal with the pin
	// override — but it is what the caller asked for, and the ledger and the
	// result say so.
	IntentOperatorBelowPin = IntentOperator + "+below-pin"
)

// Refusal is a replica declining a request, with the keyholder's own code.
type Refusal struct {
	Ordinal int
	Code    string
	Reason  string
	// Status is the HTTP status the replica answered with.
	Status int
}

// Error is the refusal as prose. The reason is the replica's own words, and
// they reach an operator inside this machine's errors and rows — and an error
// keeps its newlines, so a reason carrying one could start a line of its own
// ("farcast: …") that reads as this machine's. A reason that does not print
// as it is goes in Go-quoted, the rule every renderer here uses. Code and
// Reason stay raw on the struct for a caller that decides on them.
func (r *Refusal) Error() string {
	reason := r.Reason
	if !output.Printable(reason) {
		reason = strconv.QuoteToGraphic(reason)
	}
	return fmt.Sprintf("replica %d refused: %s", r.Ordinal, reason)
}

// NothingSentError is a push that failed before any of its sealed bundle was
// written: the replica could not be dialled, did not complete the handshake,
// would not issue a challenge, or the bundle could not be sealed. Everything
// else that fails a push — a refusal above all — came back after the bundle
// was written to whoever answered the challenge, and a caller counting where
// key material went must count it.
type NothingSentError struct{ Err error }

func (e *NothingSentError) Error() string { return e.Err.Error() }
func (e *NothingSentError) Unwrap() error { return e.Err }

// NothingSent reports whether a failed Unseal failed before any of the sealed
// bundle left this machine.
//
// The default is the other answer, on purpose: a failure this does not
// recognise counts as one after sending. The bundle is sealed to the key in
// the challenge, and the challenge comes from whatever answered — which ADR
// 0008 finding 1's solicitor can be, holding the keyholder's server leaf. A
// refusal from it arrives after it has read, and can open, the bundle.
func NothingSent(err error) bool {
	var n *NothingSentError
	return errors.As(err, &n)
}

// NotServing reports a hand-over that a replica refused because it is
// sealed. That is not a failure of the hand-over — a hand-over never unseals
// — so a caller treats the replica as waiting, not as broken.
func NotServing(err error) bool {
	var r *Refusal
	return errors.As(err, &r) && r.Code == dskeyholder.CodeNotServing
}

// AlreadyServing reports a re-seed a replica refused because it holds keys.
// A re-seed only restores a replica that restarted.
func AlreadyServing(err error) bool {
	var r *Refusal
	return errors.As(err, &r) && r.Code == dskeyholder.CodeAlreadyServing
}

// WouldDrop reports a push a SERVING replica refused because the bundle lacks a
// key or scope it holds: the pusher's keyring is behind the instance's.
func WouldDrop(err error) bool {
	var r *Refusal
	return errors.As(err, &r) && r.Code == dskeyholder.CodeWouldDrop
}

// GenerationTooOld reports a push a replica refused because it has held a
// newer generation — which, when it is serving, means another pusher reached
// it first.
func GenerationTooOld(err error) bool {
	var r *Refusal
	return errors.As(err, &r) && r.Code == dskeyholder.CodeGenerationOld
}

// BelowPin reports a push a replica refused because the bundle predates the
// instance's key pin: this keyring lacks a key the instance has, or writes
// under one it retired.
func BelowPin(err error) bool {
	var r *Refusal
	return errors.As(err, &r) && r.Code == dskeyholder.CodeBelowPin
}

// PinUnreadable reports a re-seed a replica refused because it cannot read its
// own key pin.
func PinUnreadable(err error) bool {
	var r *Refusal
	return errors.As(err, &r) && r.Code == dskeyholder.CodePinUnreadable
}

// KeeperBundle reports a keeper's push refused because its leaf binds another
// bundle, or none.
func KeeperBundle(err error) bool {
	var r *Refusal
	return errors.As(err, &r) && r.Code == dskeyholder.CodeKeeperBundle
}

// Unsupported reports a route the replica does not have: its image predates
// it.
func Unsupported(err error) bool {
	var r *Refusal
	return errors.As(err, &r) && r.Status == http.StatusNotFound && r.Code == ""
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
		return State{}, &NothingSentError{fmt.Errorf("fetching a challenge from replica %d: %w", ordinal, err)}
	}
	sealed, err := dskeyholder.SealBundle(bundle, c.instance, challenge)
	if err != nil {
		return State{}, &NothingSentError{err}
	}
	var st State
	path := "/v1/unseal?intent=" + intent
	if intent == IntentOperatorBelowPin {
		path = "/v1/unseal?intent=" + IntentOperator + "&pin=" + dskeyholder.PinOverride
	}
	err = c.call(ctx, ordinal, http.MethodPost, path, dskeyholder.ContentTypeSealed, sealed, &st)
	return st, err
}

// RaisePin hands a running replica the key pin, which it unions with its own,
// or takes in place of its own when replace is set. A replica reads the pin
// from its environment only when it starts; this is how one that is already
// running learns a pin written since.
func (c *Client) RaisePin(ctx context.Context, ordinal int, pin string, replace bool) (State, error) {
	path := dskeyholder.PinPath
	if replace {
		path += "?replace=true"
	}
	var st State
	err := c.call(ctx, ordinal, http.MethodPost, path, dskeyholder.ContentTypePin, []byte(pin), &st)
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
//
// A replica that could not be dialled, or did not complete the handshake,
// comes back as a NothingSentError: the body, if there is one, never left
// this machine. Nothing from the request's write on is marked — a write that
// failed part-way may have sent part of it — and neither is anything else,
// which a caller counting where key material went then counts as sent.
func (c *Client) call(ctx context.Context, ordinal int, method, path, contentType string, body []byte, out any) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	raw, err := c.dialer.DialStream(ctx, StreamRoute, ordinal)
	if err != nil {
		return &NothingSentError{fmt.Errorf("reaching replica %d: %w", ordinal, err)}
	}
	defer func() { _ = raw.Close() }()

	conn := tls.Client(raw, c.tlsCfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		// Named precisely: this is the check that the process on the far end
		// is the keyholder this instance's CA vouches for, and not something
		// the cloud stood up in its place.
		return &NothingSentError{fmt.Errorf("replica %d did not present a certificate this instance's CA vouches for: %w", ordinal, err)}
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
		code, reason := refusalReason(payload, resp.Status)
		return &Refusal{Ordinal: ordinal, Code: code, Reason: reason, Status: resp.StatusCode}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("replica %d answered unintelligibly", ordinal)
	}
	return nil
}

// refusalReason pulls the keyholder's own code and message out of an error
// body. The reason keeps the code in parentheses, so the text an operator reads
// is unchanged by the code now also being returned on its own.
func refusalReason(payload []byte, fallback string) (code, reason string) {
	var body struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if json.Unmarshal(payload, &body) == nil && body.Message != "" {
		if body.Code != "" {
			return body.Code, body.Message + " (" + body.Code + ")"
		}
		return "", body.Message
	}
	return "", fallback
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
