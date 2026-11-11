package keyholder

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	dskeyholder "github.com/sofmon/farcast/datasphere/keyholder"
	"github.com/sofmon/farcast/fatline/identity"
)

type failingDialer struct{}

func (failingDialer) DialStream(context.Context, string, int) (net.Conn, error) {
	return nil, errors.New("the tunnel is down")
}

// thenDialer dials first for the first stream — the challenge — and then for
// every later one: the push's own stream, which then (when then is "") fails
// to dial, or reaches another peer.
type thenDialer struct {
	first, then string
	n           int
}

func (d *thenDialer) DialStream(ctx context.Context, _ string, _ int) (net.Conn, error) {
	d.n++
	addr := d.first
	if d.n > 1 {
		addr = d.then
	}
	if addr == "" {
		return nil, errors.New("the tunnel dropped")
	}
	var dl net.Dialer
	return dl.DialContext(ctx, "tcp", addr)
}

// Review finding V3-3. A push says whether its sealed bundle left this
// machine: it did not when the replica could not be dialled, did not
// complete the handshake, or would not issue a challenge; it did once the
// request was written — and every refusal of the push itself comes after
// that, even one that reads like "nothing happened". The default, for any
// failure not marked, is "sent".
func TestAPushSaysWhetherItsBundleWasSent(t *testing.T) {
	m, err := identity.Mint("prod")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	bundle := bundleFor(t, "prod", 1)

	t.Run("no dial", func(t *testing.T) {
		c, err := New(failingDialer{}, "prod", m.CACertPEM, m.ClientCertPEM, m.ClientKeyPEM)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Unseal(ctx, 0, bundle, IntentOperator); err == nil || !NothingSent(err) {
			t.Errorf("a push over a tunnel that is down: %v; want it marked as sending nothing", err)
		}
	})

	t.Run("no handshake", func(t *testing.T) {
		foreign, _ := identity.Mint("prod")
		kh := startKeyholder(t, "prod", foreign)
		if _, err := newClient(t, "prod", m, kh.addr).Unseal(ctx, 0, bundle, IntentOperator); err == nil || !NothingSent(err) {
			t.Errorf("a push to a peer the CA does not vouch for: %v; want it marked as sending nothing", err)
		}
	})

	// The challenge was fetched, and the push's own stream failed before a
	// byte of it was written: the tunnel dropped, or what answered was not
	// the keyholder the CA vouches for.
	for _, tc := range []struct {
		name    string
		foreign bool
	}{{"no dial for the push", false}, {"no handshake for the push", true}} {
		t.Run(tc.name, func(t *testing.T) {
			kh := startKeyholder(t, "prod", m)
			d := &thenDialer{first: kh.addr}
			if tc.foreign {
				other, _ := identity.Mint("prod")
				d.then = startKeyholder(t, "prod", other).addr
			}
			c, err := New(d, "prod", m.CACertPEM, m.ClientCertPEM, m.ClientKeyPEM)
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.Unseal(ctx, 0, bundle, IntentOperator)
			if d.n != 2 {
				t.Fatalf("guard: %d stream(s) dialled; want the challenge's and the push's", d.n)
			}
			if err == nil || !NothingSent(err) {
				t.Errorf("a push whose stream failed before the request: %v; want it marked as sending nothing", err)
			}
		})
	}

	t.Run("no challenge", func(t *testing.T) {
		kh := startKeyholderOn(t, "prod", m, "", func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == dskeyholder.SealChallengePath {
					http.Error(w, `{"code":"bad-request","message":"cannot issue a challenge"}`, http.StatusTooManyRequests)
					return
				}
				h.ServeHTTP(w, r)
			})
		})
		_, err := newClient(t, "prod", m, kh.addr).Unseal(ctx, 0, bundle, IntentOperator)
		var r *Refusal
		if err == nil || !NothingSent(err) || !errors.As(err, &r) {
			t.Errorf("a push the replica would issue no challenge for: %v; want a refusal marked as sending nothing", err)
		}
	})

	// A challenge the bundle cannot be sealed to: nothing to send it with.
	t.Run("an unusable challenge", func(t *testing.T) {
		kh := startKeyholderOn(t, "prod", m, "", func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == dskeyholder.SealChallengePath {
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, `{"session_id":"AA==","challenge":"AA==","public_key":"AA=="}`)
					return
				}
				h.ServeHTTP(w, r)
			})
		})
		if _, err := newClient(t, "prod", m, kh.addr).Unseal(ctx, 0, bundle, IntentOperator); err == nil || !NothingSent(err) {
			t.Errorf("a push with a challenge it could not seal to: %v; want it marked as sending nothing", err)
		}
	})

	t.Run("refused after sending", func(t *testing.T) {
		kh := startKeyholder(t, "prod", m)
		c := newClient(t, "prod", m, kh.addr)
		if _, err := c.Unseal(ctx, 0, bundle, IntentOperator); err != nil {
			t.Fatal(err)
		}
		_, err := c.Unseal(ctx, 0, bundleFor(t, "prod", 2), "restart-reseed")
		if !AlreadyServing(err) || NothingSent(err) {
			t.Errorf("a re-seed a serving keyholder refused: %v (nothing sent: %v); the bundle had been sent", err, NothingSent(err))
		}
	})

	// ADR 0008 finding 1's solicitor: it answers the challenge with its own
	// key, reads the sealed body, and refuses. The bundle is gone, and the
	// error must not say otherwise.
	t.Run("a solicitor's refusal", func(t *testing.T) {
		var received atomic.Int64
		kh := startKeyholderOn(t, "prod", m, "", func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost && r.URL.Path == "/v1/unseal" {
					n, _ := io.Copy(io.Discard, r.Body)
					received.Add(n)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusConflict)
					_, _ = io.WriteString(w, `{"code":"already-serving","message":"serving"}`)
					return
				}
				h.ServeHTTP(w, r)
			})
		})
		_, err := newClient(t, "prod", m, kh.addr).Unseal(ctx, 0, bundle, "restart-reseed")
		if received.Load() == 0 {
			t.Fatal("guard: the solicitor received no body")
		}
		if !AlreadyServing(err) || NothingSent(err) {
			t.Errorf("a refusal after %d bytes of sealed bundle were read: %v (nothing sent: %v)", received.Load(), err, NothingSent(err))
		}
	})

	if NothingSent(errors.New("anything else")) || NothingSent(nil) {
		t.Error("an unmarked failure reads as sending nothing")
	}
}

// Review finding R3-3. A refusal's reason is the replica's words, and an
// error keeps its newlines: a reason that does not print as it is goes in
// quoted, so it cannot start a line of its own or act on the terminal. One
// that prints is unchanged.
func TestARefusalQuotesAReasonThatWouldNotPrint(t *testing.T) {
	forged := "pin\nfarcast: forged: storage unsealed\x1b]52;c;ZXZpbA==\a"
	got := (&Refusal{Ordinal: 1, Code: dskeyholder.CodeBelowPin, Reason: forged}).Error()
	if strings.ContainsAny(got, "\n\x1b\a") {
		t.Errorf("Error() = %q; the replica's newline or escape reached the text raw", got)
	}
	if !strings.Contains(got, `pin\nfarcast: forged`) {
		t.Errorf("Error() = %q; want the reason kept, quoted", got)
	}
	plain := (&Refusal{Ordinal: 0, Reason: "keyholder: sealed (not-serving)"}).Error()
	if plain != "replica 0 refused: keyholder: sealed (not-serving)" {
		t.Errorf("a printable reason changed: %q", plain)
	}
}

// Review finding V3-2. A write that failed part-way — a full disk, a crash —
// leaves the ledger ending in a fragment with no newline. The next entry must
// still be readable: fused to the fragment it would be dropped as damaged,
// and a push recorded before it was made would stand on disk unread.
func TestAnEntryAfterATornLineIsReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	at := time.Date(2026, 11, 10, 1, 0, 0, 0, time.UTC)
	if err := AppendLedger(path, LedgerEntry{Time: at, Instance: "prod", Intent: "restart-reseed", Result: "pending", Push: "a"}); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, LedgerMode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"time":"2026-11-10T01:00:00Z","instance":"prod","ordinal":0,"intent":"restart-res`); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if err := AppendLedger(path, LedgerEntry{Time: at, Instance: "prod", Intent: "restart-reseed", Result: "pending", Push: "b"}); err != nil {
		t.Fatal(err)
	}
	entries, err := ReadLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[1].Push != "b" {
		t.Fatalf("read %+v; want both entries, the one after the fragment last", entries)
	}
	// And a ledger that ends cleanly gains no blank line.
	data, _ := os.ReadFile(path)
	if err := AppendLedger(path, LedgerEntry{Time: at, Instance: "prod", Intent: "restart-reseed", Result: "ok", Push: "b"}); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if strings.Contains(string(after[len(data):]), "\n\n") || after[len(data)] == '\n' {
		t.Errorf("a clean ledger gained a blank line: %q", after[len(data):])
	}
}
