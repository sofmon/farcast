// Package proxy is FatLine's deny-by-default egress forward proxy: the
// userspace path an in-instance application's outbound traffic takes to reach
// the external hosts its ./farcast manifest declares, and nothing else.
//
// It is an http.Handler so it slots behind an ordinary http.Server (and the
// language-neutral Egress seam in the fatline package), and so a future Rust
// data plane (ADR 0002) can replace it without caller churn. For HTTPS it
// tunnels CONNECT opaquely — it never terminates TLS to the upstream, so the
// cloud and FatLine see ciphertext only. Plain http:// is denied by default
// (confidentiality is part of deny-by-default). On an allowed CONNECT it peeks
// the TLS ClientHello as defense-in-depth, asserting SNI == authority.
package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/sofmon/farcast/fatline/event"
	"github.com/sofmon/farcast/fatline/internal/allowlist"
	"github.com/sofmon/farcast/fatline/internal/netcopy"
)

// DialFunc dials an upstream address. It is injectable for tests.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Caller is the application a request was identified as.
type Caller struct {
	// Tenant is the key its allowlist is held under.
	Tenant string
	// Namespace and App are for attribution: every decision names them, so an
	// alert can say which application attempted what (ADR 0013 decision 7).
	Namespace string
	App       string
}

// IdentifyFunc resolves a presented credential to an application.
//
// A function rather than the policy type, so this package stays free of the
// document format and a test can identify callers without building one.
type IdentifyFunc func(credential string) (Caller, bool)

// Options configures a Proxy.
type Options struct {
	Allowlist   *allowlist.List
	Events      event.Sink
	EnforceSNI  bool
	DialContext DialFunc

	// Identify resolves the caller. A nil Identify denies every request:
	// per-application policy with no way to tell applications apart is not a
	// weaker policy, it is no policy, and failing closed is the only safe
	// reading of a misconfiguration here.
	Identify IdentifyFunc
}

// Proxy is the egress forward proxy.
type Proxy struct {
	allow      *allowlist.List
	events     event.Sink
	enforceSNI bool
	dial       DialFunc
	identify   IdentifyFunc
}

// New builds a Proxy. A nil Events logs via slog; a nil DialContext uses a
// default net.Dialer.
func New(o Options) *Proxy {
	p := &Proxy{allow: o.Allowlist, events: o.Events, enforceSNI: o.EnforceSNI, dial: o.DialContext, identify: o.Identify}
	if p.identify == nil {
		p.identify = func(string) (Caller, bool) { return Caller{}, false }
	}
	if p.events == nil {
		p.events = event.SlogSink{}
	}
	if p.dial == nil {
		d := &net.Dialer{Timeout: 30 * time.Second}
		p.dial = d.DialContext
	}
	return p
}

// ServeHTTP routes CONNECT (HTTPS tunnel) and absolute-URI (plain HTTP) requests.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handlePlain(w, r)
}

// handlePlain denies plain http:// egress by default: the manifest declares a
// hostname with no scheme, so FarCast cannot make cleartext confidential, and
// FatLine refuses to proxy traffic it (and the cloud) would see in the clear.
func (p *Proxy) handlePlain(w http.ResponseWriter, r *http.Request) {
	host, port := authority(plainHost(r), "80")
	// Identified anyway, so the refusal names who tried. A denial nobody can
	// attribute is telemetry rather than enforcement.
	caller, _ := p.identify(credentialFrom(r))
	p.events.Emit(event.Event{
		Kind: event.Deny, Tenant: caller.Namespace, App: caller.App,
		Host: host, Port: port, Proto: "http", Reason: event.ReasonCleartext,
	})
	http.Error(w, "fatline: cleartext http egress is denied by default", http.StatusForbidden)
}

// handleConnect allowlists the CONNECT authority, then tunnels opaquely.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, port := authority(r.Host, "443")

	// Who is asking, before what they asked for. With per-application policy
	// there is no instance-wide allowlist to check against, so a caller FatLine
	// cannot identify has nothing to be checked against and is refused
	// (ADR 0013 decision 6).
	caller, known := p.identify(credentialFrom(r))
	if !known {
		p.events.Emit(event.Event{Kind: event.Deny, Host: host, Port: port, Proto: "connect", Reason: event.ReasonUnknownApp})
		w.Header().Set("Proxy-Authenticate", `Basic realm="farcast"`)
		http.Error(w, "fatline: unidentified application", http.StatusProxyAuthRequired)
		return
	}

	d := p.allow.Allow(caller.Tenant, host)
	if !d.Allowed {
		p.events.Emit(event.Event{
			Kind: event.Deny, Tenant: caller.Namespace, App: caller.App,
			Host: host, Port: port, Proto: "connect", Reason: d.Reason,
		})
		http.Error(w, "fatline: host not in allowlist", http.StatusForbidden)
		return
	}
	p.events.Emit(event.Event{
		Kind: event.Allow, Tenant: caller.Namespace, App: caller.App,
		Host: host, Port: port, Proto: "connect", Reason: d.Reason,
	})

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "fatline: connection hijack unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer func() { _ = clientConn.Close() }()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	// SNI defense-in-depth: peek the ClientHello without terminating, buffer the
	// consumed bytes so they can be replayed unchanged into the upstream copy.
	sni, buffered := peekSNI(clientConn)
	if p.enforceSNI && sni != "" && !strings.EqualFold(sni, host) {
		p.events.Emit(event.Event{
			Kind: event.Deny, Tenant: caller.Namespace, App: caller.App,
			Host: host, Port: port, Proto: "connect", SNI: sni, Reason: event.ReasonSNIMismatch,
		})
		return
	}

	upstream, err := p.dial(context.Background(), "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return
	}
	defer func() { _ = upstream.Close() }()

	clientSrc := io.MultiReader(bytes.NewReader(buffered), clientConn)
	up, down := netcopy.Duplex(upstream, clientConn, clientSrc)
	p.events.Emit(event.Event{
		Kind: event.Close, Tenant: caller.Namespace, App: caller.App,
		Host: host, Port: port, Proto: "connect", SNI: sni, BytesUp: up, BytesDown: down,
	})
}

// splice copies bidirectionally between the client and the upstream, returning
// bytes sent up (client→upstream) and down (upstream→client). It waits for both
// directions, so the byte counts are safely published through the channel.

// peekSNI reads the TLS ClientHello off conn, returns the SNI and the exact
// bytes consumed (to be replayed). It never terminates the handshake: it aborts
// from GetConfigForClient once the ServerName is parsed. A read or parse failure
// returns an empty SNI (the caller degrades to authority-only — never fail-open).
func peekSNI(conn net.Conn) (sni string, buffered []byte) {
	var buf bytes.Buffer
	tee := io.TeeReader(conn, &buf)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	_ = tls.Server(readOnlyConn{r: tee}, &tls.Config{
		GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = hi.ServerName
			return nil, errStopHandshake
		},
	}).Handshake()
	return sni, buf.Bytes()
}

var errStopHandshake = errors.New("fatline: stop after ClientHello")

// readOnlyConn adapts an io.Reader to net.Conn for the SNI peek: reads come from
// the tee'd ClientHello bytes; writes are refused (the handshake is aborted
// before any ServerHello). Deadlines are managed on the real conn by the caller.
type readOnlyConn struct{ r io.Reader }

func (c readOnlyConn) Read(p []byte) (int, error)     { return c.r.Read(p) }
func (readOnlyConn) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (readOnlyConn) Close() error                     { return nil }
func (readOnlyConn) LocalAddr() net.Addr              { return nil }
func (readOnlyConn) RemoteAddr() net.Addr             { return nil }
func (readOnlyConn) SetDeadline(time.Time) error      { return nil }
func (readOnlyConn) SetReadDeadline(time.Time) error  { return nil }
func (readOnlyConn) SetWriteDeadline(time.Time) error { return nil }

// authority splits an "host:port" or bare-host authority, defaulting the port.
func authority(s, defPort string) (host, port string) {
	if s == "" {
		return "", defPort
	}
	if h, p, err := net.SplitHostPort(s); err == nil {
		return h, p
	}
	return strings.TrimSpace(s), defPort
}

// plainHost extracts the target host:port from a forward-proxy plain-HTTP
// request (absolute-URI form, falling back to the Host header).
func plainHost(r *http.Request) string {
	if r.URL != nil && r.URL.Host != "" {
		return r.URL.Host
	}
	return r.Host
}

// credentialFrom lifts an application's egress credential out of a request.
//
// It reads Proxy-Authorization, which is where every standard HTTP client puts
// the userinfo from a proxy URL — that is what lets ADR 0013 decision 2 claim
// an application needs no change. Only the password is returned: the username
// is the caller's own claim about who they are, and trusting it would make the
// credential decorative.
//
// The credential is never logged, never emitted on an event, and never reaches
// the upstream — a CONNECT is hijacked rather than forwarded, so the header
// dies with the request that carried it.
func credentialFrom(r *http.Request) string {
	header := r.Header.Get("Proxy-Authorization")
	scheme, encoded, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "basic") {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return ""
	}
	_, credential, ok := strings.Cut(string(raw), ":")
	if !ok {
		return ""
	}
	return credential
}
