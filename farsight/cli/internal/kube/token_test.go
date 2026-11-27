package kube

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/auth"
)

// TestInvalidateForcesOneMint drives the cache directly (§3.4). Two requests
// that carried the same token both got 401: the first invalidate drops it and
// the next token mints once; the second invalidate names a token that is no
// longer cached and keeps the new one. Two concurrent 401s on the same token
// mint once more, not twice.
func TestInvalidateForcesOneMint(t *testing.T) {
	ctx := t.Context()
	m := &countingMint{}
	c := &tokenCache{mint: m.mint, now: time.Now}

	first, err := c.token(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c.invalidate(first) // the first 401
	second, err := c.token(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c.invalidate(first) // the second 401, on the same rejected token
	third, err := c.token(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if m.calls() != 2 {
		t.Fatalf("two 401s on one token minted %d times in all, want 2: the second invalidate dropped the new token", m.calls())
	}
	if second == first || third != second {
		t.Fatalf("tokens %q, %q, %q: want a new token, then that one kept", first.Value, second.Value, third.Value)
	}

	// The same, concurrently: every goroutine holds third and got 401.
	const n = 8
	var wg sync.WaitGroup
	start := make(chan struct{})
	got := make([]*auth.Token, n)
	for i := range n {
		wg.Go(func() {
			<-start
			c.invalidate(third)
			tok, err := c.token(ctx)
			if err != nil {
				t.Error(err)
			}
			got[i] = tok
		})
	}
	close(start)
	wg.Wait()
	if m.calls() != 3 {
		t.Errorf("%d concurrent 401s on one token minted %d more times, want 1", n, m.calls()-2)
	}
	for i, tok := range got {
		if tok == nil || tok == third || tok != got[0] {
			t.Errorf("goroutine %d holds %v; every one holds the one new token", i, tok)
		}
	}
}

// TestTokenCacheMintsWithin225sOfExpiry: a token is reused until it is
// within 225 s of its expiry, the vendored cache's own margin; a token with
// no expiry is reused until a 401 drops it; a failed mint caches nothing.
func TestTokenCacheMintsWithin225sOfExpiry(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)
	var mints int
	var expiry time.Time
	var fail error
	c := &tokenCache{
		mint: func(context.Context) (*auth.Token, error) {
			if fail != nil {
				return nil, fail
			}
			mints++
			return &auth.Token{Value: fmt.Sprintf("t%d", mints), Expiry: expiry}, nil
		},
		now: func() time.Time { return now },
	}

	expiry = now.Add(226 * time.Second)
	if _, err := c.token(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.token(ctx); err != nil || mints != 1 {
		t.Fatalf("226 s before expiry: %d mints, %v; want the cached token", mints, err)
	}
	now = now.Add(2 * time.Second) // 224 s left
	if _, err := c.token(ctx); err != nil || mints != 2 {
		t.Fatalf("224 s before expiry: %d mints, %v; want a fresh one", mints, err)
	}

	expiry = time.Time{}
	c.invalidate(c.tok)
	if _, err := c.token(ctx); err != nil || mints != 3 {
		t.Fatal(err)
	}
	now = now.Add(24 * time.Hour)
	if _, err := c.token(ctx); err != nil || mints != 3 {
		t.Fatalf("a token with no expiry was minted again (%d mints): %v", mints, err)
	}

	c.invalidate(c.tok)
	fail = errors.New("mint failed")
	if _, err := c.token(ctx); err == nil || c.tok != nil {
		t.Fatalf("a failed mint: err %v, cached %v", err, c.tok)
	}

	fail = nil
	c.mint = func(context.Context) (*auth.Token, error) { return &auth.Token{}, nil }
	if _, err := c.token(ctx); !errors.Is(err, ErrUnreadable) || c.tok != nil {
		t.Fatalf("an empty token: err %v, cached %v; want ErrUnreadable and nothing cached", err, c.tok)
	}
}

// TestTokenErrorsNameTheDomainAndCodeOnly: a token endpoint's refusal names
// the identity's email domain and the HTTP status, never the endpoint's body,
// which the library's own error quotes (§3.3).
func TestTokenErrorsNameTheDomainAndCodeOnly(t *testing.T) {
	const marker = "SECRET-MARKER"
	refused := &auth.Error{
		Response: &http.Response{StatusCode: http.StatusBadRequest},
		Body:     []byte(`{"error":"invalid_grant","error_description":"` + marker + `"}`),
	}
	err := tokenError(fmt.Errorf("wrapped: %w", refused), googleDomain)
	if want := "Google refused to mint a token for the proj-1.iam.gserviceaccount.com service account (400 Bad Request)"; err.Error() != want {
		t.Errorf("refusal = %q, want %q", err, want)
	}
	if !errors.Is(err, ErrTokenRefused) {
		t.Errorf("a refusal does not wrap ErrTokenRefused: %v", err)
	}

	dial := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connect: connection refused")}
	unreached := &url.Error{Op: "Post", URL: GoogleTokenURL + "?" + marker, Err: dial}
	err = tokenError(fmt.Errorf("auth: cannot fetch token: %w", unreached), googleDomain)
	if want := "the token endpoint for the " + googleDomain + " service account could not be reached: dial tcp: connect: connection refused"; err.Error() != want ||
		!errors.Is(err, ErrUnreachable) || !errors.Is(err, dial) {
		t.Errorf("a network failure = %v, want ErrUnreachable %q with the dial error as its cause", err, want)
	}

	// Go's own words for an answer it could not parse quote the server's
	// bytes, which may echo the signed assertion: none is kept, and neither
	// is the error that carries them. A server's TLS alert keeps its words,
	// which Go writes from the alert's code.
	for _, c := range []struct {
		name, want string
		inner      error
	}{
		{"a malformed status line", "no readable answer", fmt.Errorf("net/http: HTTP/1.x transport connection broken: %w",
			errors.New(`malformed HTTP status code "`+marker+`"`))},
		{"a malformed header line", "no readable answer", errors.New(`malformed MIME header: missing colon: "` + marker + `"`)},
		{"an unparsable Location", "no readable answer", fmt.Errorf("failed to parse Location header %q: %w", "http://["+marker, errors.New("missing ']' in host"))},
		{"an alert in its shape", "remote error: tls: bad certificate", &net.OpError{Op: "remote error", Err: errors.New("tls: bad certificate")}},
		{"an alert out of its shape", "no readable answer", &net.OpError{Op: "remote error", Err: errors.New("tls: " + marker)}},
	} {
		err := tokenError(&url.Error{Op: "Post", URL: GoogleTokenURL, Err: c.inner}, googleDomain)
		want := "the token endpoint for the " + googleDomain + " service account could not be reached: " + c.want
		if err.Error() != want || !errors.Is(err, ErrUnreachable) {
			t.Errorf("%s = %v, want ErrUnreachable %q", c.name, err, want)
		}
		for _, e := range fedErrorTree(err) {
			if strings.Contains(e.Error(), marker) {
				t.Errorf("%s: the error tree carries the server's bytes: %v", c.name, e)
			}
		}
	}

	err = tokenError(errors.New("auth: cannot fetch token: invalid character '"+marker+"'"), googleDomain)
	if !errors.Is(err, ErrUnreadable) || strings.Contains(err.Error(), marker) {
		t.Errorf("an unreadable answer = %v, want ErrUnreadable without the answer's words", err)
	}
}

// TestNewRefusesAKeyThe2LOSignerCannotUse: New builds the 2LO provider, so a
// credential without an RSA key is refused there, before any mint; a test
// client with its own token function needs no key.
func TestNewRefusesAKeyThe2LOSignerCannotUse(t *testing.T) {
	ep, err := ParseEndpoint("127.0.0.1:6443", "", testCAPEM())
	if err != nil {
		t.Fatal(err)
	}
	ecPKCS8, _ := ecPEMs(t)
	for _, key := range [][]byte{nil, []byte("not a key"), []byte(ecPKCS8)} {
		_, err := New(Config{Endpoint: ep, Credential: Credential{Email: loopbackEmail, PrivateKeyPEM: key}, Identity: Writer})
		if !errors.Is(err, ErrCredentialInvalid) {
			t.Errorf("key %.20q: err = %v, want ErrCredentialInvalid", key, err)
		}
	}
	if _, err := newClient(Config{Endpoint: ep, Credential: Credential{Email: loopbackEmail}, Identity: Writer}, staticMint("x")); err != nil {
		t.Errorf("a static token function: %v", err)
	}
}

// TestTheTokenClockHasNoMonotonicReading (A-A2-3): the cache's clock is wall
// time alone, for a client built by New (the 2LO provider) and by newClient. A
// minted token's Expiry carries a monotonic reading, and two readings are
// compared on the monotonic clock alone, which stops while the machine
// sleeps: an expired token would read as fresh after a sleep. With the clock
// wall-only, freshness is wall time, as the vendored Token.IsValid has it.
func TestTheTokenClockHasNoMonotonicReading(t *testing.T) {
	ep, err := ParseEndpoint("127.0.0.1:6443", "", testCAPEM())
	if err != nil {
		t.Fatal(err)
	}
	for name, build := range map[string]func() (*Client, error){
		"New": func() (*Client, error) {
			return New(Config{Endpoint: ep, Credential: loopbackCredential(t), Identity: Writer})
		},
		"newClient": func() (*Client, error) {
			return newClient(Config{Endpoint: ep, Credential: Credential{Email: loopbackEmail}, Identity: Reader}, staticMint("x"))
		},
	} {
		c, err := build()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		n := c.tokens.now()
		if n != n.Round(0) {
			t.Errorf("%s: the token cache's clock carries a monotonic reading (%v)", name, n)
		}
		if d := time.Since(n); d < 0 || d > time.Minute {
			t.Errorf("%s: the token cache's clock reads %v, %s from now", name, n, d)
		}
	}
}
