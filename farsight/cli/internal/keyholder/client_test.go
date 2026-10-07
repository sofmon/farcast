package keyholder

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/datasphere"
	dskeyholder "github.com/sofmon/farcast/datasphere/keyholder"
	"github.com/sofmon/farcast/fatline/identity"
)

// liveKeyholder runs a REAL datasphered control surface over TLS, so these
// tests exercise the actual protocol — challenge, envelope, seal state — and
// not a mock of it.
type liveKeyholder struct {
	addr  string
	vault *dskeyholder.Vault
}

func startKeyholder(t *testing.T, instance string, m *identity.Material) *liveKeyholder {
	t.Helper()
	certPEM, keyPEM, err := identity.IssueKeyholderServer(m.CACertPEM, m.CAKeyPEM, instance)
	if err != nil {
		t.Fatalf("IssueKeyholderServer: %v", err)
	}
	cert, err := dskeyholder.LoadTLS(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("LoadTLS: %v", err)
	}
	pool, err := dskeyholder.LoadCAPool(m.CACertPEM)
	if err != nil {
		t.Fatalf("LoadCAPool: %v", err)
	}

	vault := dskeyholder.New(instance)
	srv, err := dskeyholder.NewServer(dskeyholder.Config{
		Instance: instance,
		Vault:    vault,
		Stores: func(s datasphere.Scope) (*datasphere.Store, error) {
			return nil, errors.New("no provider in this test")
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	l, err := tls.Listen("tcp", "127.0.0.1:0",
		dskeyholder.ControlTLS(cert, pool, dskeyholder.AllowPusher(instance)))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	go func() {
		_ = (&http.Server{Handler: srv.ControlHandler()}).Serve(l)
	}()
	return &liveKeyholder{addr: l.Addr().String(), vault: vault}
}

// directDialer stands in for FatLine's relay: these tests are about the
// operator↔keyholder protocol, and the relay has its own end-to-end tests.
type directDialer struct{ addr string }

func (d directDialer) DialStream(ctx context.Context, _ string, _ int) (net.Conn, error) {
	var dl net.Dialer
	return dl.DialContext(ctx, "tcp", d.addr)
}

func newClient(t *testing.T, instance string, m *identity.Material, addr string) *Client {
	t.Helper()
	c, err := New(directDialer{addr: addr}, instance, m.CACertPEM, m.ClientCertPEM, m.ClientKeyPEM)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func bundleFor(t *testing.T, instance string, generation uint64) []byte {
	t.Helper()
	scope, err := datasphere.NewScope("app", "app/")
	if err != nil {
		t.Fatalf("NewScope: %v", err)
	}
	b, err := datasphere.NewBundle(instance, generation, []datasphere.Scope{scope})
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	out, err := b.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return out
}

// The whole operator-side protocol, against a real keyholder: it starts
// sealed, an unseal loads it, and a seal empties it again.
func TestClientUnsealsARealKeyholder(t *testing.T) {
	m, err := identity.Mint("prod")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	kh := startKeyholder(t, "prod", m)
	c := newClient(t, "prod", m, kh.addr)
	ctx := context.Background()

	st, err := c.State(ctx, 0)
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if !st.Sealed() || st.Phase != "restart-sealed" {
		t.Fatalf("a fresh keyholder reported %+v", st)
	}

	st, err = c.Unseal(ctx, 0, bundleFor(t, "prod", 4), "operator-unseal")
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if st.Sealed() || st.Generation != 4 {
		t.Fatalf("after unseal: %+v", st)
	}

	st, err = c.Seal(ctx, 0, true, "planned maintenance")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if st.Phase != "operator-hold" || !strings.Contains(st.HoldReason, "planned maintenance") {
		t.Fatalf("after seal: %+v", st)
	}

	// A keeper may not clear an operator hold — enforced in-cluster, so it
	// binds whatever is holding a keeper's credential.
	if _, err := c.Unseal(ctx, 0, bundleFor(t, "prod", 5), "restart-reseed"); err == nil {
		t.Fatal("a keeper reseed cleared an operator hold")
	}

	// Releasing the hold lands sealed, never unsealed.
	st, err = c.ReleaseHold(ctx, 0)
	if err != nil {
		t.Fatalf("ReleaseHold: %v", err)
	}
	if !st.Sealed() {
		t.Fatal("releasing a hold handed back key material")
	}
}

// The client must refuse a peer the instance CA does not vouch for — the case
// where something has been stood up in the keyholder's place.
func TestClientRefusesAnUnvouchedPeer(t *testing.T) {
	real, _ := identity.Mint("prod")
	foreign, _ := identity.Mint("prod")

	kh := startKeyholder(t, "prod", foreign) // serves a leaf from the WRONG CA
	c := newClient(t, "prod", real, kh.addr)

	if _, err := c.State(context.Background(), 0); err == nil {
		t.Fatal("the client accepted a keyholder the instance CA does not vouch for")
	} else if !strings.Contains(err.Error(), "vouch") {
		t.Errorf("the error should say what failed: %v", err)
	}
}

// A bundle for one instance must not load into another.
func TestClientCannotPushAcrossInstances(t *testing.T) {
	m, _ := identity.Mint("prod")
	kh := startKeyholder(t, "prod", m)
	c := newClient(t, "prod", m, kh.addr)

	if _, err := c.Unseal(context.Background(), 0, bundleFor(t, "staging", 1), "operator-unseal"); err == nil {
		t.Fatal("a bundle for another instance was accepted")
	}
	if !kh.vault.State().Sealed() {
		t.Fatal("a refused push left the keyholder unsealed")
	}
}

func TestLedgerAppendsAndReads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "datasphere", "unseal-ledger.jsonl")
	for i := range 3 {
		if err := AppendLedger(path, LedgerEntry{
			Time: time.Now().UTC(), Instance: "prod", Ordinal: i,
			Intent: "operator-unseal", Generation: uint64(i), Result: "ok",
		}); err != nil {
			t.Fatalf("AppendLedger: %v", err)
		}
	}
	entries, err := ReadLedger(path)
	if err != nil {
		t.Fatalf("ReadLedger: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("read %d entries, want 3", len(entries))
	}
	if entries[0].Ordinal != 0 || entries[2].Ordinal != 2 {
		t.Error("the ledger is not in append order")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != LedgerMode {
		t.Errorf("ledger mode = %o, want %o", info.Mode().Perm(), LedgerMode)
	}

	// A damaged line must not make the rest unreadable.
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, LedgerMode)
	_, _ = f.WriteString("{ this is not json\n")
	_ = f.Close()
	if again, err := ReadLedger(path); err != nil || len(again) != 3 {
		t.Errorf("a damaged line broke the read: %d entries, %v", len(again), err)
	}
}

func TestReadLedgerOnAMissingFile(t *testing.T) {
	entries, err := ReadLedger(filepath.Join(t.TempDir(), "absent.jsonl"))
	if err != nil || entries != nil {
		t.Errorf("a missing ledger should read as empty: %v, %v", entries, err)
	}
}

// A hand-over refused because the replica is sealed is not a failure — the
// replica is waiting for an unseal — and the caller has to be able to tell it
// apart from a refusal that is one, without parsing prose.
func TestARefusalCarriesTheKeyholdersCode(t *testing.T) {
	code, reason := refusalReason([]byte(`{"code":"not-serving","message":"keyholder: sealed"}`), "409 Conflict")
	if code != "not-serving" || reason != "keyholder: sealed (not-serving)" {
		t.Fatalf("refusalReason = %q, %q", code, reason)
	}
	notServing := fmt.Errorf("pushing: %w", &Refusal{Ordinal: 1, Code: code, Reason: reason})
	if !NotServing(notServing) {
		t.Error("a wrapped not-serving refusal was not recognised")
	}
	if got := notServing.Error(); !strings.Contains(got, "replica 1 refused: keyholder: sealed (not-serving)") {
		t.Errorf("the operator-facing text changed: %q", got)
	}
	for _, other := range []error{
		&Refusal{Ordinal: 0, Code: "permission", Reason: "no"},
		&Refusal{Ordinal: 0, Code: "", Reason: "502 Bad Gateway"},
		errors.New("not-serving"),
	} {
		if NotServing(other) {
			t.Errorf("NotServing(%v) = true", other)
		}
	}
	if code, reason := refusalReason([]byte("<html>gateway</html>"), "502 Bad Gateway"); code != "" || reason != "502 Bad Gateway" {
		t.Errorf("an unparseable body = %q, %q; want the status, no code", code, reason)
	}
}

// keyringBundle marshals a bundle carrying exactly this keyring's scopes.
func keyringBundle(t *testing.T, generation uint64, k datasphere.Keyring) []byte {
	t.Helper()
	b, err := datasphere.NewBundle("prod", generation, k.Scopes())
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	out, err := b.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return out
}

// The hand-over counts a replica as holding the keys only if the keys in the
// unseal RESPONSE are the ones it sent. That response crosses the real wire —
// the server's encoder, the field name, the client's decoder — and every CLI
// test reads it from a fake. This reads it from a real keyholder: a staged
// rotation, then its activation.
func TestTheKeysAReplicaHoldsCrossTheRealWire(t *testing.T) {
	m, err := identity.Mint("prod")
	if err != nil {
		t.Fatal(err)
	}
	kh := startKeyholder(t, "prod", m)
	c := newClient(t, "prod", m, kh.addr)
	ctx := context.Background()

	k, err := datasphere.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	web, err := datasphere.NewAppScope("apps", "web")
	if err != nil {
		t.Fatal(err)
	}
	if k, err = k.AddScope(web); err != nil {
		t.Fatal(err)
	}
	ids := func(k datasphere.Keyring) []string {
		var out []string
		for _, e := range k.Scopes()[0].Keyring().KEKs() {
			out = append(out, e.ID.String())
		}
		return out
	}

	st, err := c.Unseal(ctx, 0, keyringBundle(t, 1, k), IntentOperator)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if !slices.Equal(st.Keys["app-apps-web"], ids(k)) {
		t.Fatalf("the unseal response carried keys %v, want %v", st.Keys, ids(k))
	}

	rotated, rotations, err := k.RotateScopeKEKs()
	if err != nil {
		t.Fatal(err)
	}
	previous := map[string]datasphere.KeyID{}
	for _, r := range rotations {
		previous[r.Scope] = r.Previous
	}
	staged, err := rotated.WithScopeActive(previous)
	if err != nil {
		t.Fatal(err)
	}
	if st, err = c.Unseal(ctx, 0, keyringBundle(t, 2, staged), IntentHandOver); err != nil {
		t.Fatalf("hand-over of the staged keys: %v", err)
	}
	if !slices.Equal(st.Keys["app-apps-web"], ids(staged)) {
		t.Fatalf("after staging the response carried %v, want %v", st.Keys["app-apps-web"], ids(staged))
	}
	if st, err = c.Unseal(ctx, 0, keyringBundle(t, 3, rotated), IntentHandOver); err != nil {
		t.Fatalf("hand-over of the rotated keys: %v", err)
	}
	if got := st.Keys["app-apps-web"]; len(got) == 0 || got[0] != rotations[0].Active.String() {
		t.Fatalf("after activation the response carried %v, want %s first", got, rotations[0].Active)
	}
	// And GET /v1/state says the same.
	if st, err = c.State(ctx, 0); err != nil || !slices.Equal(st.Keys["app-apps-web"], ids(rotated)) {
		t.Fatalf("State reports %v (%v), want %v", st.Keys, err, ids(rotated))
	}
}

// A hand-over to a sealed replica is not a failure — the replica waits for an
// unseal — and the CLI can only tell that from the keyholder's own code, which
// has to survive the trip: status, header, body, the client's typing.
func TestARefusedHandOverArrivesAsNotServing(t *testing.T) {
	m, err := identity.Mint("prod")
	if err != nil {
		t.Fatal(err)
	}
	kh := startKeyholder(t, "prod", m)
	c := newClient(t, "prod", m, kh.addr)
	ctx := context.Background()

	_, err = c.Unseal(ctx, 0, bundleFor(t, "prod", 1), IntentHandOver)
	if !NotServing(err) {
		t.Fatalf("a hand-over to a sealed keyholder returned %v; want a not-serving refusal", err)
	}
	var r *Refusal
	if !errors.As(err, &r) || r.Ordinal != 0 || r.Code != "not-serving" {
		t.Fatalf("refusal = %+v", r)
	}
	if st, serr := c.State(ctx, 0); serr != nil || !st.Sealed() {
		t.Fatalf("the refused hand-over left the keyholder %+v (%v); it must stay sealed", st, serr)
	}
	// Its mirror: a re-seed into a replica that is serving.
	if _, err := c.Unseal(ctx, 0, bundleFor(t, "prod", 2), IntentOperator); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Unseal(ctx, 0, bundleFor(t, "prod", 9), "restart-reseed"); !AlreadyServing(err) {
		t.Fatalf("a re-seed into a serving keyholder returned %v; want an already-serving refusal", err)
	}
}
