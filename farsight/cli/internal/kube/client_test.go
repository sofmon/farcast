package kube

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/auth"
)

// TestFixedRequestValues pins the values every request and every write
// carries (§1, §2.1): a change to any of them is a change to what the cluster,
// Google and the operator's audit logs see.
func TestFixedRequestValues(t *testing.T) {
	for _, c := range []struct{ name, got, want string }{
		{"FieldManager", FieldManager, "farcast"},
		{"UserAgent", UserAgent, "farcast"},
		{"GoogleTokenURL", GoogleTokenURL, "https://oauth2.googleapis.com/token"},
		{"ScopeCloudPlatform", ScopeCloudPlatform, "https://www.googleapis.com/auth/cloud-platform"},
		{"ScopeUserinfoEmail", ScopeUserinfoEmail, "https://www.googleapis.com/auth/userinfo.email"},
		{"TokenScopes", strings.Join(TokenScopes(), " "),
			"https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email"},
		{"Writer", string(Writer), "writer"},
		{"Reader", string(Reader), "reader"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
}

// TestTokenScopesIsAFreshPair: TokenScopes is the endpoint's two scopes,
// cloud-platform then userinfo.email (design A22-7), and a caller that
// changes the slice it got changes no later call's.
func TestTokenScopesIsAFreshPair(t *testing.T) {
	got := TokenScopes()
	if len(got) != 2 || got[0] != ScopeCloudPlatform || got[1] != ScopeUserinfoEmail {
		t.Fatalf("TokenScopes() = %q, want [%s %s]", got, ScopeCloudPlatform, ScopeUserinfoEmail)
	}
	got[0], got[1] = "changed", "changed"
	if again := TokenScopes(); again[0] != ScopeCloudPlatform || again[1] != ScopeUserinfoEmail {
		t.Errorf("TokenScopes() after a caller changed its copy = %q", again)
	}
}

// countingListener is a loopback TCP listener that counts the connections it
// accepts and closes each at once. A refused pair must leave it at zero.
type countingListener struct {
	ln net.Listener

	mu     sync.Mutex
	remote []string // the peer address of every accepted connection
}

// listenCounting listens on host:0. ok is false when the host has no such
// address (a machine without IPv6 loopback).
func listenCounting(t *testing.T, host string) (*countingListener, bool) {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		return nil, false
	}
	l := &countingListener{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			l.mu.Lock()
			l.remote = append(l.remote, c.RemoteAddr().String())
			l.mu.Unlock()
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return l, true
}

func (l *countingListener) port() string {
	_, p, _ := net.SplitHostPort(l.ln.Addr().String())
	return p
}

// accepted is how many connections reached the listener since the last call.
// It dials the listener itself and waits until that connection is accepted:
// any dial made earlier completed its handshake first, and so was accepted
// first, so nothing in flight is missed.
func (l *countingListener) accepted(t *testing.T) int {
	t.Helper()
	conn, err := net.Dial("tcp", l.ln.Addr().String())
	if err != nil {
		t.Fatalf("dial the counting listener: %v", err)
	}
	mine := conn.LocalAddr().String()
	defer func() { _ = conn.Close() }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		l.mu.Lock()
		for _, r := range l.remote {
			if r == mine {
				n := len(l.remote) - 1
				l.remote = nil // the next call counts from here
				l.mu.Unlock()
				return n
			}
		}
		l.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	t.Fatal("the counting listener never accepted the test's own connection")
	return 0
}

// The credentials of the pairing table.
const (
	googleEmail   = "farcast-installer@proj-1.iam.gserviceaccount.com"
	googleDomain  = "proj-1.iam.gserviceaccount.com"
	loopbackEmail = "writer@kubetest.invalid"
)

func googleCredential(t *testing.T) Credential {
	return Credential{Email: googleEmail, PrivateKeyID: "0123abcd", PrivateKeyPEM: []byte(rsaPKCS8PEM(t))}
}

func loopbackCredential(t *testing.T) Credential {
	return Credential{Email: loopbackEmail, PrivateKeyID: "", PrivateKeyPEM: []byte(rsaPKCS8PEM(t))}
}

// fromJSON is a credential loaded as credentials.yaml's service_account_key
// carries it.
func fromJSON(t *testing.T, email, tokenURI string) Credential {
	t.Helper()
	fields := map[string]any{"type": "service_account", "client_email": email, "private_key": rsaPKCS8PEM(t), "private_key_id": "k1"}
	if tokenURI != "" {
		fields["token_uri"] = tokenURI
	}
	c, err := ParseServiceAccountJSON(keyJSON(t, fields))
	if err != nil {
		t.Fatalf("ParseServiceAccountJSON(%s, %s): %v", email, tokenURI, err)
	}
	return c
}

// pairingRow is one row of §10.3's table. endpoint may hold P4 and P6, the
// IPv4 and IPv6 counting listeners' ports.
type pairingRow struct {
	name     string
	cred     func(t *testing.T, p4 string) Credential
	endpoint string
	region   string // us-central1 when empty
	ca       []byte
	want     string // the whole refusal; "" is accepted
}

func (r pairingRow) recorded(p4, p6 string) string {
	return strings.NewReplacer("P4", p4, "P6", p6).Replace(r.endpoint)
}

func (r pairingRow) wantText(p4, p6 string) string {
	return strings.NewReplacer("P4", p4, "P6", p6).Replace(r.want)
}

// pairingRows is §10.3's table, every refusal by its whole message as §3.1
// and §3.2 pin it.
func pairingRows() []pairingRow {
	ca := testCAPEM()
	noCert := []byte("this file holds no certificate\n")
	google := func(t *testing.T, _ string) Credential { return googleCredential(t) }
	loop := func(t *testing.T, _ string) Credential { return loopbackCredential(t) }

	shape := func(e string) string {
		return fmt.Sprintf("the instance records the cluster endpoint %q, which is neither a name under gke.goog nor a loopback IP literal with its port; nothing was sent", e)
	}
	rangeMsg := func(e string) string {
		return fmt.Sprintf("the instance records the endpoint %q, an IP literal outside 127.0.0.0/8 and ::1; nothing was sent", e)
	}
	port := func(e, p string) string {
		return fmt.Sprintf("the instance records the endpoint %q with port %q; a Google endpoint is port 443 only, and a loopback endpoint names a port from 1 to 65535; nothing was sent", e, p)
	}
	origin := func(credMode, domain, epMode string) string {
		return fmt.Sprintf("a %s credential (%s) does not go to a %s endpoint; nothing was sent", credMode, domain, epMode)
	}
	tokenURI := func(uri, mode, want string) string {
		return fmt.Sprintf("the credential names the token endpoint %q, and a %s endpoint takes its token only from %s; nothing was sent", uri, mode, want)
	}

	return []pairingRow{
		{name: "Google credential, 127.0.0.1", cred: google, endpoint: "127.0.0.1:P4", ca: ca, want: origin("Google", googleDomain, "loopback")},
		{name: "Google credential, [::1]", cred: google, endpoint: "[::1]:P6", ca: ca, want: origin("Google", googleDomain, "loopback")},
		{name: "Google credential, localhost", cred: google, endpoint: "localhost:P4", ca: ca, want: shape("localhost:P4")},
		{name: "loopback credential, localhost (ADR 0023:100)", cred: loop, endpoint: "localhost:P4", ca: ca, want: shape("localhost:P4")},
		{name: "Google credential, 10.0.0.5", cred: google, endpoint: "10.0.0.5:443", want: rangeMsg("10.0.0.5:443")},
		{name: "loopback credential, 10.0.0.5", cred: loop, endpoint: "10.0.0.5:443", ca: ca, want: rangeMsg("10.0.0.5:443")},
		{name: "evil.example", cred: google, endpoint: "evil.example", want: shape("evil.example")},
		{name: "gke.goog alone", cred: google, endpoint: "gke.goog", want: shape("gke.goog")},
		{name: "gke.goog inside another name", cred: google, endpoint: "a.gke.goog.evil.example", want: shape("a.gke.goog.evil.example")},
		{name: "agke.goog", cred: google, endpoint: "agke.goog", want: shape("agke.goog")},
		{name: "trailing dot", cred: google, endpoint: "uid.us-central1.gke.goog.", want: shape("uid.us-central1.gke.goog.")},
		{name: "a scheme", cred: google, endpoint: "https://uid.us-central1.gke.goog", want: shape("https://uid.us-central1.gke.goog")},
		{name: "Google port 8443", cred: google, endpoint: "uid.us-central1.gke.goog:8443", want: port("uid.us-central1.gke.goog:8443", "8443")},
		{name: "Google endpoint with a CA file", cred: google, endpoint: "uid.us-central1.gke.goog", ca: ca,
			want: `the instance records the Google endpoint "uid.us-central1.gke.goog", and cluster-ca.crt exists: a Google endpoint is trusted on the system roots alone, so a cluster CA beside it is refused; nothing was sent`},
		{name: "another region", cred: google, endpoint: "uid.europe-west1.gke.goog",
			want: `the instance records the Google endpoint "uid.europe-west1.gke.goog", and none of its labels is the instance's region "us-central1"; nothing was sent`},
		{name: "bare mapped IPv6", cred: loop, endpoint: "::ffff:127.0.0.1", ca: ca, want: shape("::ffff:127.0.0.1")},
		{name: "bracketed mapped IPv6", cred: loop, endpoint: "[::ffff:127.0.0.1]:P4", ca: ca,
			want: `the instance records the endpoint "[::ffff:127.0.0.1]:P4", an IPv4-mapped IPv6 address, which is never a loopback endpoint; nothing was sent`},
		{name: "bare ::1", cred: loop, endpoint: "::1", ca: ca, want: shape("::1")},
		{name: "[::1] without a port", cred: loop, endpoint: "[::1]", ca: ca, want: shape("[::1]")},
		{name: "127.0.0.1 without a port", cred: loop, endpoint: "127.0.0.1", ca: ca, want: port("127.0.0.1", "")},
		{name: "a CA file with no certificate", cred: loop, endpoint: "127.0.0.1:P4", ca: noCert, want: "cluster-ca.crt holds no certificate"},
		{name: "no CA file", cred: loop, endpoint: "127.0.0.1:P4",
			want: `the instance records the loopback endpoint "127.0.0.1:P4" with no cluster-ca.crt; a loopback endpoint is trusted only on its own CA; nothing was sent`},
		{name: "loopback credential, Google endpoint", cred: loop, endpoint: "uid.us-central1.gke.goog", want: origin("loopback", "kubetest.invalid", "Google")},
		{name: "loopback credential, token_uri on another port", endpoint: "127.0.0.1:P4", ca: ca,
			cred: func(t *testing.T, p4 string) Credential {
				c := loopbackCredential(t)
				c.TokenURI = "https://127.0.0.1:" + otherPort(p4) + "/token"
				return c
			},
			want: tokenURI("https://127.0.0.1:OTHER/token", "loopback", "https://127.0.0.1:P4/token")},
		{name: "loopback credential from JSON with Google's token_uri", endpoint: "127.0.0.1:P4", ca: ca,
			cred: func(t *testing.T, _ string) Credential { return fromJSON(t, loopbackEmail, GoogleTokenURL) },
			want: tokenURI(GoogleTokenURL, "loopback", "https://127.0.0.1:P4/token")},
		{name: "Google credential with token_uri evil.example", endpoint: "uid.us-central1.gke.goog",
			cred: func(t *testing.T, _ string) Credential {
				c := googleCredential(t)
				c.TokenURI = "https://evil.example/token"
				return c
			},
			want: tokenURI("https://evil.example/token", "Google", GoogleTokenURL)},
		{name: "Google credential with universe example.com", endpoint: "uid.us-central1.gke.goog",
			cred: func(t *testing.T, _ string) Credential {
				c := googleCredential(t)
				c.UniverseDomain = "example.com"
				return c
			},
			want: `the credential names the universe "example.com", and farcast's cluster client works in googleapis.com only; nothing was sent`},
		{name: "loopback endpoint, real-shaped Google email", endpoint: "127.0.0.1:P4", ca: ca,
			cred: func(t *testing.T, _ string) Credential {
				c := loopbackCredential(t)
				c.Email = "writer@x.iam.gserviceaccount.com"
				return c
			},
			want: origin("Google", "x.iam.gserviceaccount.com", "loopback")},
		{name: "accepted: Google", cred: google, endpoint: "uid.us-central1.gke.goog"},
		{name: "accepted: Google :443", cred: google, endpoint: "uid.us-central1.gke.goog:443"},
		{name: "accepted: 127.0.0.1", cred: loop, endpoint: "127.0.0.1:P4", ca: ca},
		{name: "accepted: [::1]", cred: loop, endpoint: "[::1]:P6", ca: ca},
		{name: "accepted: the loopback writer from credentials.yaml JSON", endpoint: "127.0.0.1:P4", ca: ca,
			cred: func(t *testing.T, p4 string) Credential {
				return fromJSON(t, loopbackEmail, "https://127.0.0.1:"+p4+"/token")
			}},
	}
}

// otherPort is a port that is not p.
func otherPort(p string) string {
	if p == "1" {
		return "2"
	}
	return "1"
}

// pairingListeners are the counting listeners every pairing row may name:
// 127.0.0.1 always, and ::1 when the machine has it.
type pairingListeners struct {
	v4, v6 *countingListener
}

func newPairingListeners(t *testing.T) pairingListeners {
	v4, ok := listenCounting(t, "127.0.0.1")
	if !ok {
		t.Fatal("listen on 127.0.0.1")
	}
	v6, _ := listenCounting(t, "::1")
	return pairingListeners{v4: v4, v6: v6}
}

// ports are P4 and P6; without IPv6 loopback, P6 is P4's and the [::1] rows
// are skipped by the caller.
func (l pairingListeners) ports() (string, string) {
	if l.v6 == nil {
		return l.v4.port(), l.v4.port()
	}
	return l.v4.port(), l.v6.port()
}

func (l pairingListeners) assertNoDial(t *testing.T, row string) {
	t.Helper()
	if n := l.v4.accepted(t); n != 0 {
		t.Errorf("%s: the 127.0.0.1 listener accepted %d connections; a refused or new client dials nothing", row, n)
	}
	if l.v6 != nil {
		if n := l.v6.accepted(t); n != 0 {
			t.Errorf("%s: the ::1 listener accepted %d connections; a refused or new client dials nothing", row, n)
		}
	}
}

// classify runs one row as farcast will: ParseEndpoint, then New.
func classify(t *testing.T, row pairingRow, p4, p6 string, newFn func(Config) (*Client, error)) (*Client, error) {
	t.Helper()
	region := row.region
	if region == "" {
		region = "us-central1"
	}
	ep, err := ParseEndpoint(row.recorded(p4, p6), region, row.ca)
	if err != nil {
		return nil, err
	}
	return newFn(Config{Endpoint: ep, Credential: row.cred(t, p4), Identity: Writer})
}

// TestEndpointRule is §10.3's table: the endpoint rule of §3.1 and the
// pairing of §3.2 together, as New sees them. Every refused row asserts its
// whole message, that it wraps ErrEndpointRefused, and that nothing dialled
// either loopback listener: a mint placed in New, before the pairing, would
// dial the token endpoint of a refused loopback row.
func TestEndpointRule(t *testing.T) {
	l := newPairingListeners(t)
	p4, p6 := l.ports()
	for _, row := range pairingRows() {
		t.Run(row.name, func(t *testing.T) {
			if strings.Contains(row.endpoint, "P6") && l.v6 == nil {
				t.Skip("this machine has no IPv6 loopback")
			}
			c, err := classify(t, row, p4, p6, New)
			want := strings.ReplaceAll(row.wantText(p4, p6), "OTHER", otherPort(p4))
			switch {
			case want == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case want == "" && c == nil:
				t.Fatal("accepted, and no client")
			case want != "" && err == nil:
				t.Fatalf("accepted; want the refusal %q", want)
			case want != "":
				if err.Error() != want {
					t.Errorf("refusal\n got: %s\nwant: %s", err, want)
				}
				if !errors.Is(err, ErrEndpointRefused) {
					t.Errorf("the refusal does not wrap ErrEndpointRefused: %v", err)
				}
			}
			l.assertNoDial(t, row.name)
		})
	}
}

// countingMint is a tokenFunc that counts its calls and mints a static token.
type countingMint struct {
	mu sync.Mutex
	n  int
}

func (m *countingMint) mint(context.Context) (*auth.Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.n++
	return &auth.Token{Value: "static-" + strconv.Itoa(m.n), Type: "Bearer"}, nil
}

func (m *countingMint) calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.n
}

// TestNoTokenIsMintedForARefusedPair passes a counting tokenFunc through
// newClient for every refused row of §10.3's table that reaches the pairing,
// and for Endpoints that ParseEndpoint could not have made: the pairing comes
// before any mint, in newClient itself.
func TestNoTokenIsMintedForARefusedPair(t *testing.T) {
	l := newPairingListeners(t)
	p4, p6 := l.ports()
	paired := 0
	for _, row := range pairingRows() {
		if row.want == "" || (strings.Contains(row.endpoint, "P6") && l.v6 == nil) {
			continue
		}
		m := &countingMint{}
		_, err := classify(t, row, p4, p6, func(cfg Config) (*Client, error) {
			paired++
			return newClient(cfg, m.mint)
		})
		if err == nil {
			t.Errorf("%s: accepted", row.name)
		}
		if m.calls() != 0 {
			t.Errorf("%s: %d mints for a refused pair", row.name, m.calls())
		}
	}
	if paired < 6 {
		t.Fatalf("only %d refused rows reached the pairing; the table lost its pairing rows", paired)
	}

	pool := mustPool(t)
	handBuilt := []struct {
		name string
		ep   Endpoint
		cred Credential
	}{
		{"the zero Endpoint", Endpoint{}, loopbackCredential(t)},
		{"loopback outside 127.0.0.0/8", Endpoint{Mode: ModeLoopback, Host: "10.0.0.5", Port: "443", CA: pool}, loopbackCredential(t)},
		{"loopback without a CA", Endpoint{Mode: ModeLoopback, Host: "127.0.0.1", Port: p4}, loopbackCredential(t)},
		{"loopback, mapped", Endpoint{Mode: ModeLoopback, Host: "::ffff:127.0.0.1", Port: p4, CA: pool}, loopbackCredential(t)},
		{"Google with a CA", Endpoint{Mode: ModeGoogle, Host: "uid.us-central1.gke.goog", Port: "443", CA: pool}, googleCredential(t)},
		{"Google off gke.goog", Endpoint{Mode: ModeGoogle, Host: "evil.example", Port: "443"}, googleCredential(t)},
		{"Google on another port", Endpoint{Mode: ModeGoogle, Host: "uid.us-central1.gke.goog", Port: "8443"}, googleCredential(t)},
	}
	for _, h := range handBuilt {
		m := &countingMint{}
		_, err := newClient(Config{Endpoint: h.ep, Credential: h.cred, Identity: Writer}, m.mint)
		if !errors.Is(err, ErrEndpointRefused) {
			t.Errorf("%s: err = %v, want ErrEndpointRefused", h.name, err)
		}
		if m.calls() != 0 {
			t.Errorf("%s: %d mints", h.name, m.calls())
		}
	}
	l.assertNoDial(t, "every refused pair")
}

// mustPool is the test CA as a pool, as ParseEndpoint builds one.
func mustPool(t *testing.T) *x509.CertPool {
	t.Helper()
	ep, err := ParseEndpoint("127.0.0.1:1", "", testCAPEM())
	if err != nil {
		t.Fatal(err)
	}
	return ep.CA
}

// TestNewDialsAndMintsNothing: for every accepted row, neither New nor
// newClient mints or dials. Only the first request does: on a loopback row
// it mints once and dials the listener (which closes the connection, so the
// request fails as unreachable).
func TestNewDialsAndMintsNothing(t *testing.T) {
	l := newPairingListeners(t)
	p4, p6 := l.ports()
	for _, row := range pairingRows() {
		if row.want != "" || (strings.Contains(row.endpoint, "P6") && l.v6 == nil) {
			continue
		}
		m := &countingMint{}
		c, err := classify(t, row, p4, p6, func(cfg Config) (*Client, error) { return newClient(cfg, m.mint) })
		if err != nil {
			t.Fatalf("%s: %v", row.name, err)
		}
		cNew, err := classify(t, row, p4, p6, New)
		if err != nil {
			t.Fatalf("%s: New: %v", row.name, err)
		}
		if m.calls() != 0 {
			t.Errorf("%s: newClient minted %d times", row.name, m.calls())
		}
		l.assertNoDial(t, row.name)
		if c.ep.Mode != ModeLoopback {
			continue // a Google row's first request would leave the machine
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err = c.ListNamespaces(ctx, "")
		cancel()
		if !errors.Is(err, ErrUnreachable) {
			t.Errorf("%s: the first request: err = %v, want ErrUnreachable (the listener closes every connection)", row.name, err)
		}
		if m.calls() != 1 {
			t.Errorf("%s: the first request minted %d times, want 1", row.name, m.calls())
		}
		listener := l.v4
		if c.ep.Host == "::1" {
			listener = l.v6
		}
		if n := listener.accepted(t); n < 1 {
			t.Errorf("%s: the first request dialled nothing", row.name)
		}

		// New's own first request dials the token endpoint, on the same
		// listener, and fails there.
		ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		_, err = cNew.ListNamespaces(ctx, "")
		cancel()
		if !errors.Is(err, ErrUnreachable) {
			t.Errorf("%s: New's first request: err = %v, want ErrUnreachable", row.name, err)
		}
		if n := listener.accepted(t); n < 1 {
			t.Errorf("%s: New's first request dialled nothing", row.name)
		}
	}
}
