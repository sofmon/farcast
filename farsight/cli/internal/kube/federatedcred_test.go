package kube

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/auth"
)

// TestNewFederatedCredentialRefusesEachPart: each part NewFederatedCredential
// takes is refused, by name and never by value, with ErrCredentialInvalid;
// the credential it makes carries the email alone of the key fields.
func TestNewFederatedCredentialRefusesEachPart(t *testing.T) {
	fed, err := NewLoopbackFederation("127.0.0.1:1", "127.0.0.1:2", "127.0.0.1:3", fedPool(t))
	if err != nil {
		t.Fatal(err)
	}
	id := newFedIdentity(t, fedHexID)
	other := newFedIdentity(t, fedHexID)
	good := NewClientIdentity([][]byte{id.leafDER}, id.key)
	idForm := "//iam.googleapis.com/projects/my-project-1/locations/global/workloadIdentityPools/pool1234/providers/prov1234"
	for _, c := range []struct {
		name, part, aud, email string
		fed                    *Federation
		id                     ClientIdentity
		role                   Identity
	}{
		{"no federation", "federation", fedAudience, fedEmail, nil, good, Reader},
		{"an empty audience", "audience", "", fedEmail, fed, good, Reader},
		{"the project-ID audience", "audience", idForm, fedEmail, fed, good, Reader},
		{"an audience with a suffix", "audience", fedAudience + "/x", fedEmail, fed, good, Reader},
		{"the zero client identity", "client certificate", fedAudience, fedEmail, fed, ClientIdentity{}, Reader},
		{"an empty chain", "client certificate", fedAudience, fedEmail, fed, NewClientIdentity(nil, id.key), Reader},
		{"a chain that does not parse", "client certificate", fedAudience, fedEmail, fed, NewClientIdentity([][]byte{[]byte(fedSecretMarker)}, id.key), Reader},
		{"another leaf's signer", "client certificate", fedAudience, fedEmail, fed, NewClientIdentity([][]byte{id.leafDER}, other.key), Reader},
		{"no signer", "client certificate", fedAudience, fedEmail, fed, NewClientIdentity([][]byte{id.leafDER}, nil), Reader},
		{"a test identity's email", "service account", fedAudience, "writer@kubetest.invalid", fed, good, Reader},
		{"no email", "service account", fedAudience, "", fed, good, Reader},
		{"an email with a planted suffix", "service account", fedAudience, fedEmail + fedSecretMarker, fed, good, Reader},
		{"no role", "role", fedAudience, fedEmail, fed, good, ""},
		{"another role", "role", fedAudience, fedEmail, fed, good, Identity("admin")},
	} {
		cred, err := NewFederatedCredential(c.fed, c.aud, c.id, c.email, c.role)
		want := "kube: the federated credential has no usable " + c.part + "; nothing was sent"
		if !errors.Is(err, ErrCredentialInvalid) || err.Error() != want {
			t.Errorf("%s: %v; want %q", c.name, err, want)
		}
		if cred.Federated() || cred.Email != "" {
			t.Errorf("%s: a refused credential is not the zero Credential", c.name)
		}
		if m := containsAnyOf(err.Error(), fedSecretMarker, fedEmail, "pool1234", "123456789012", "my-project-1"); m != "" {
			t.Errorf("%s: the refusal quotes %q", c.name, m)
		}
	}

	for _, role := range []Identity{Reader, Writer} {
		cred, err := NewFederatedCredential(fed, fedAudience, good, fedEmail, role)
		if err != nil {
			t.Fatalf("%s: %v", role, err)
		}
		if !cred.Federated() || cred.Role() != role || cred.Email != fedEmail {
			t.Errorf("%s: Federated %v, Role %q, Email %q", role, cred.Federated(), cred.Role(), cred.Email)
		}
		if cred.PrivateKeyPEM != nil || cred.PrivateKeyID != "" || cred.TokenURI != "" || cred.UniverseDomain != "" {
			t.Errorf("%s: a federated credential carries a key field", role)
		}
		copied := cred
		if copied.fed() != cred.fed() {
			t.Errorf("%s: a copy does not share the federated part, and with it the exchange cache", role)
		}
	}
	key := googleCredential(t)
	if key.Federated() || key.Role() != "" || (Credential{}).Federated() || (Credential{}).Role() != "" {
		t.Error("a key, or the zero Credential, reads as federated or with a role")
	}
}

// fedCountingFederation is a loopback Federation whose three hosts are one
// counting listener's address, and that listener: a refusal before sending
// must leave it at zero.
func fedCountingFederation(t *testing.T) (*Federation, *countingListener) {
	t.Helper()
	l, ok := listenCounting(t, "127.0.0.1")
	if !ok {
		t.Fatal("no IPv4 loopback")
	}
	addr := net.JoinHostPort("127.0.0.1", l.port())
	f, err := NewLoopbackFederation(addr, addr, addr, fedPool(t))
	if err != nil {
		t.Fatal(err)
	}
	return f, l
}

// TestFederatedPairingRefusesEachMismatch is §3.2's table for a federated
// credential: its origin is its Federation's mode, never its email's domain;
// the client's identity must be its role; no key field may be set; and its
// email must be the one it impersonates. Each refusal is pinned by its whole
// text, wraps ErrEndpointRefused, and comes before anything is minted or
// dialled. The 2LO table is unchanged: a key with a real-shaped Google email
// still does not pair with a loopback endpoint.
func TestFederatedPairingRefusesEachMismatch(t *testing.T) {
	loopFed, fedL := fedCountingFederation(t)
	googleFed, err := NewFederation()
	if err != nil {
		t.Fatal(err)
	}
	epL, ok := listenCounting(t, "127.0.0.1")
	if !ok {
		t.Fatal("no IPv4 loopback")
	}
	loopEP, err := ParseEndpoint(net.JoinHostPort("127.0.0.1", epL.port()), "", testCAPEM())
	if err != nil {
		t.Fatal(err)
	}
	googleEP, err := ParseEndpoint("uid.us-central1.gke.goog", "us-central1", nil)
	if err != nil {
		t.Fatal(err)
	}
	id := newFedIdentity(t, fedHexID)
	ci := NewClientIdentity([][]byte{id.leafDER}, id.key)
	cred := func(f *Federation, role Identity) Credential {
		c, err := NewFederatedCredential(f, fedAudience, ci, fedEmail, role)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	with := func(c Credential, edit func(*Credential)) Credential {
		edit(&c)
		return c
	}
	reader := cred(loopFed, Reader)
	for _, c := range []struct {
		name     string
		ep       Endpoint
		cred     Credential
		identity Identity
		want     string
	}{
		{"a loopback federation at a Google endpoint", googleEP, reader, Reader,
			"a loopback federated credential does not go to a Google endpoint; nothing was sent"},
		{"a Google federation at a loopback endpoint", loopEP, cred(googleFed, Reader), Reader,
			"a Google federated credential does not go to a loopback endpoint; nothing was sent"},
		{"the reader acting as the writer", loopEP, reader, Writer,
			`the federated credential is the reader's, and the client was asked to act as "writer"; nothing was sent`},
		{"the writer acting as the reader", loopEP, cred(loopFed, Writer), Reader,
			`the federated credential is the writer's, and the client was asked to act as "reader"; nothing was sent`},
		{"no identity", loopEP, reader, "",
			`the federated credential is the reader's, and the client was asked to act as ""; nothing was sent`},
		{"a private key", loopEP, with(reader, func(c *Credential) { c.PrivateKeyPEM = []byte(rsaPKCS8PEM(t)) }), Reader,
			"a federated credential takes no private key from a key file; nothing was sent"},
		{"a private key ID", loopEP, with(reader, func(c *Credential) { c.PrivateKeyID = fedSecretMarker }), Reader,
			"a federated credential takes no private key ID from a key file; nothing was sent"},
		{"a token URI", loopEP, with(reader, func(c *Credential) { c.TokenURI = loopEP.TokenURL() }), Reader,
			"a federated credential takes no token URI from a key file; nothing was sent"},
		{"a universe", loopEP, with(reader, func(c *Credential) { c.UniverseDomain = googleUniverse }), Reader,
			"a federated credential takes no universe domain from a key file; nothing was sent"},
		{"another email", loopEP, with(reader, func(c *Credential) { c.Email = "writer-sa1@proj-01.iam.gserviceaccount.com" }), Reader,
			"the federated credential's email is not the service account it impersonates; nothing was sent"},
		{"an endpoint ParseEndpoint did not make", Endpoint{Mode: ModeLoopback, Host: "10.0.0.5", Port: "443", CA: mustPool(t)}, reader, Reader,
			`the cluster endpoint "10.0.0.5" was not classified by ParseEndpoint; nothing was sent`},
		// The order, when more than one fails: the mode, the role, the key
		// file's fields, the email.
		{"a Google federation at a loopback endpoint, as the writer", loopEP, cred(googleFed, Reader), Writer,
			"a Google federated credential does not go to a loopback endpoint; nothing was sent"},
		{"the reader as the writer, with a private key", loopEP, with(reader, func(c *Credential) { c.PrivateKeyPEM = []byte(rsaPKCS8PEM(t)) }), Writer,
			`the federated credential is the reader's, and the client was asked to act as "writer"; nothing was sent`},
		{"a universe and another email", loopEP, with(reader, func(c *Credential) {
			c.UniverseDomain, c.Email = googleUniverse, "writer-sa1@proj-01.iam.gserviceaccount.com"
		}), Reader, "a federated credential takes no universe domain from a key file; nothing was sent"},
	} {
		m := &countingMint{}
		for name, build := range map[string]func(Config) (*Client, error){
			"New":       New,
			"newClient": func(cfg Config) (*Client, error) { return newClient(cfg, m.mint) },
		} {
			cl, err := build(Config{Endpoint: c.ep, Credential: c.cred, Identity: c.identity})
			if cl != nil || !errors.Is(err, ErrEndpointRefused) || err.Error() != c.want {
				t.Errorf("%s (%s): %v, %v; want %q", c.name, name, cl != nil, err, c.want)
			}
			if err != nil && strings.Contains(err.Error(), fedSecretMarker) {
				t.Errorf("%s (%s): the refusal quotes a value", c.name, name)
			}
		}
		if m.calls() != 0 {
			t.Errorf("%s: %d mints for a refused pair", c.name, m.calls())
		}
	}

	// The accepted pairs: by the Federation's mode, with a real-shaped email
	// in both modes. Neither dials or mints, and a federated client has no
	// token client.
	for _, c := range []struct {
		name string
		ep   Endpoint
		cred Credential
		role Identity
	}{
		{"a loopback reader at a loopback endpoint", loopEP, reader, Reader},
		{"a loopback writer at a loopback endpoint", loopEP, cred(loopFed, Writer), Writer},
		{"a Google reader at a Google endpoint", googleEP, cred(googleFed, Reader), Reader},
	} {
		cl, err := New(Config{Endpoint: c.ep, Credential: c.cred, Identity: c.role})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if cl.tokenHTTP != nil {
			t.Errorf("%s: a federated client has a token client", c.name)
		}
		if cl.Identity() != c.role || cl.domain != "proj-01.iam.gserviceaccount.com" {
			t.Errorf("%s: identity %q, domain %q", c.name, cl.Identity(), cl.domain)
		}
	}
	// The 2LO row of §10.3 stays: a key with a real-shaped Google email does
	// not pair with a loopback endpoint, whatever a federated one may do.
	key := Credential{Email: "writer@x.iam.gserviceaccount.com", PrivateKeyPEM: []byte(rsaPKCS8PEM(t))}
	if _, err := New(Config{Endpoint: loopEP, Credential: key, Identity: Writer}); !errors.Is(err, ErrEndpointRefused) ||
		err.Error() != "a Google credential (x.iam.gserviceaccount.com) does not go to a loopback endpoint; nothing was sent" {
		t.Errorf("a key with a Google email at a loopback endpoint: %v", err)
	}
	if n := fedL.accepted(t); n != 0 {
		t.Errorf("%d connections reached the federation's hosts", n)
	}
	if n := epL.accepted(t); n != 0 {
		t.Errorf("%d connections reached the cluster endpoint", n)
	}
}

// TestFederatedClientMintsThroughTheFederation: a federated reader's client
// exchanges its leaf once, impersonates its service account with the
// cluster's scopes, and sends that token, and only it, to the cluster. The
// client certificate goes to STS alone (R2).
func TestFederatedClientMintsThroughTheFederation(t *testing.T) {
	fake := newFedFake(t)
	c, err := New(Config{Endpoint: fake.endpoint(t), Credential: fake.credential(t, Reader), Identity: Reader})
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		names, err := c.ListNamespaces(t.Context(), "")
		if err != nil {
			t.Fatal(err)
		}
		if len(names) != 1 || names[0] != "default" {
			t.Fatalf("ListNamespaces = %q", names)
		}
	}
	if n := len(fake.requests("sts")); n != 1 {
		t.Errorf("%d exchanges, want 1", n)
	}
	if bodies := fake.impersonationBodies(); len(bodies) != 1 || bodies[0] != string(ImpersonationBody(ScopesCluster)) {
		t.Errorf("the impersonations' bodies are %q, want one with the cluster's scopes", bodies)
	}
	cluster := fake.requests("cluster")
	if len(cluster) != 3 {
		t.Fatalf("%d cluster requests, want 3", len(cluster))
	}
	for _, r := range cluster {
		if r.bearer != "sa" {
			t.Errorf("the cluster was sent a %q bearer, want the service account's", r.bearer)
		}
	}
	for _, server := range []string{"iam", "cluster"} {
		for _, r := range fake.requests(server) {
			if r.certs != 0 {
				t.Errorf("a %s request's connection presented %d certificates", server, r.certs)
			}
		}
	}
	for _, r := range fake.requests("sts") {
		if r.certs != 1 || r.bearer != "" {
			t.Errorf("the exchange presented %d certificates and a %q bearer; want the leaf and none", r.certs, r.bearer)
		}
	}
}

// TestFederatedMintReimpersonatesOnAClusterUnauthorized: a cluster 401
// drops the service account's token and impersonates once more with the
// cached federated token; nothing is exchanged again. A second 401 is the
// error.
func TestFederatedMintReimpersonatesOnAClusterUnauthorized(t *testing.T) {
	fake := newFedFake(t)
	c, err := New(Config{Endpoint: fake.endpoint(t), Credential: fake.credential(t, Reader), Identity: Reader})
	if err != nil {
		t.Fatal(err)
	}
	fake.set(func(f *fedFake) { f.clusterFail = []int{http.StatusUnauthorized} })
	if _, err := c.ListNamespaces(t.Context(), ""); err != nil {
		t.Fatal(err)
	}
	if n, m := len(fake.requests("sts")), len(fake.requests("iam")); n != 1 || m != 2 {
		t.Errorf("after one cluster 401: %d exchanges and %d impersonations, want 1 and 2", n, m)
	}
	fake.set(func(f *fedFake) { f.clusterFail = []int{http.StatusUnauthorized, http.StatusUnauthorized} })
	if _, err := c.ListNamespaces(t.Context(), ""); err == nil {
		t.Fatal("two cluster 401s in a row read")
	}
	if n, m := len(fake.requests("sts")), len(fake.requests("iam")); n != 1 || m != 3 {
		t.Errorf("after two more: %d exchanges and %d impersonations, want 1 and 3", n, m)
	}
}

// TestFederatedMintReexchangesOnceOnAnIAMUnauthorized: when IAM Credentials
// answers 401 to the cached federated token, the mint drops it, exchanges
// once more, and impersonates once more; a second 401 is the error, after
// exactly one more exchange. Any other refusal is returned as it is, with no
// exchange.
func TestFederatedMintReexchangesOnceOnAnIAMUnauthorized(t *testing.T) {
	fake := newFedFake(t)
	cred := fake.credential(t, Reader)
	storage, err := TokenSourceFor(cred, ScopesStorage)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := storage.Token(t.Context()); err != nil {
		t.Fatal(err)
	}
	fake.revokeFederated()
	registry, err := TokenSourceFor(cred, ScopesRegistry)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := registry.Token(t.Context()); err != nil {
		t.Fatalf("after the federated token was revoked: %v", err)
	}
	if n, m := len(fake.requests("sts")), len(fake.requests("iam")); n != 2 || m != 3 {
		t.Errorf("%d exchanges and %d impersonations, want 2 and 3", n, m)
	}

	// Two 401s: the second is the error, after one more exchange.
	fake.set(func(f *fedFake) { f.iamStatus = []int{http.StatusUnauthorized, http.StatusUnauthorized} })
	cluster, err := TokenSourceFor(cred, ScopesCluster)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = cluster.Token(t.Context())
	var fe *FederationError
	if !errors.As(err, &fe) || fe.Step != StepImpersonate || fe.Status != http.StatusUnauthorized || !errors.Is(err, ErrTokenRefused) {
		t.Fatalf("two IAM 401s: %v; want the second", err)
	}
	if n, m := len(fake.requests("sts")), len(fake.requests("iam")); n != 3 || m != 5 {
		t.Errorf("%d exchanges and %d impersonations, want 3 and 5", n, m)
	}
	if strings.Contains(err.Error(), fedSecretMarker) {
		t.Error("the refusal carries the answer's body")
	}
	// A 403 exchanges nothing more.
	fake.set(func(f *fedFake) { f.iamStatus = []int{http.StatusForbidden} })
	_, _, err = cluster.Token(t.Context())
	if !errors.As(err, &fe) || fe.Status != http.StatusForbidden {
		t.Fatalf("an IAM 403: %v", err)
	}
	if n, m := len(fake.requests("sts")), len(fake.requests("iam")); n != 3 || m != 6 {
		t.Errorf("after a 403: %d exchanges and %d impersonations, want 3 and 6", n, m)
	}
	if strings.Contains(err.Error(), fedSecretMarker) {
		t.Error("the refusal carries the answer's body")
	}
}

// TestFederatedMintReturnsTheSecondFailure: after IAM Credentials' 401 the
// mint exchanges again and impersonates again for the consumer's own
// scopes; when that second impersonation fails another way, its failure is
// the error, not the first 401; and when the exchange itself fails, the
// exchange's failure is.
func TestFederatedMintReturnsTheSecondFailure(t *testing.T) {
	fake := newFedFake(t)
	cred := fake.credential(t, Reader)
	storage, err := TokenSourceFor(cred, ScopesStorage)
	if err != nil {
		t.Fatal(err)
	}
	fake.set(func(f *fedFake) { f.iamStatus = []int{http.StatusUnauthorized} })
	if _, _, err := storage.Token(t.Context()); err != nil {
		t.Fatalf("a 401, then a fresh exchange: %v", err)
	}
	want := string(ImpersonationBody(ScopesStorage))
	if bodies := fake.impersonationBodies(); len(bodies) != 2 || bodies[0] != want || bodies[1] != want {
		t.Errorf("the impersonations, the retry included: %q; want two of %q", bodies, want)
	}
	if n := len(fake.requests("sts")); n != 2 {
		t.Errorf("%d exchanges, want 2", n)
	}

	registry, err := TokenSourceFor(cred, ScopesRegistry)
	if err != nil {
		t.Fatal(err)
	}
	fake.set(func(f *fedFake) { f.iamStatus = []int{http.StatusUnauthorized, http.StatusForbidden} })
	_, _, err = registry.Token(t.Context())
	var fe *FederationError
	if !errors.As(err, &fe) || fe.Step != StepImpersonate || fe.Status != http.StatusForbidden || !errors.Is(err, ErrTokenRefused) {
		t.Errorf("a 401, then a 403: %v; want the 403", err)
	}

	cluster, err := TokenSourceFor(cred, ScopesCluster)
	if err != nil {
		t.Fatal(err)
	}
	fake.set(func(f *fedFake) { f.iamStatus = []int{http.StatusUnauthorized} })
	fake.sts.Close()
	_, _, err = cluster.Token(t.Context())
	if !errors.As(err, &fe) || fe.Step != StepExchange || !errors.Is(err, ErrUnreachable) ||
		!strings.HasPrefix(err.Error(), "kube: Google's token exchange could not be reached: ") {
		t.Errorf("a 401, then an exchange that fails: %v; want the exchange's failure", err)
	}
}

// TestOneExchangeAcrossConsumers is D5.1 in package kube: one credential, a
// cluster client, storage and registry RoleTokens and an IAM reader, asked at
// once from many goroutines, and a copy of the credential besides, exchange
// once, and impersonate once per consumer, each with its own scopes. Another
// credential for the same role exchanges on its own.
func TestOneExchangeAcrossConsumers(t *testing.T) {
	fake := newFedFake(t)
	cred := fake.credential(t, Reader)
	copied := cred
	client, err := New(Config{Endpoint: fake.endpoint(t), Credential: cred, Identity: Reader})
	if err != nil {
		t.Fatal(err)
	}
	storage, err := TokenSourceFor(cred, ScopesStorage)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := TokenSourceFor(copied, ScopesRegistry)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewIAMReader(copied)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for range 8 {
		wg.Go(func() {
			if _, err := client.ListNamespaces(context.Background(), ""); err != nil {
				errs <- err
			}
			for _, rt := range []*RoleTokens{storage, registry} {
				if _, _, err := rt.Token(context.Background()); err != nil {
					errs <- err
				}
			}
			if _, err := reader.GetProvider(context.Background(), "123456789012", "pool1234", "prov1234"); err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if n := len(fake.requests("sts")); n != 1 {
		t.Errorf("%d exchanges, want 1 for the role", n)
	}
	bodies := fake.impersonationBodies()
	want := map[string]int{
		string(ImpersonationBody(ScopesCluster)):  2, // the cluster client and the IAM reader
		string(ImpersonationBody(ScopesStorage)):  1,
		string(ImpersonationBody(ScopesRegistry)): 1,
	}
	got := map[string]int{}
	for _, b := range bodies {
		got[b]++
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("impersonations by body: %v, want one per consumer: %v", got, want)
	}
	for _, r := range fake.requests("iam") {
		if r.bearer != "fed" {
			t.Errorf("an impersonation carried a %q bearer, want the federated token", r.bearer)
		}
	}

	other := fake.credential(t, Reader)
	ts, err := TokenSourceFor(other, ScopesCluster)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ts.Token(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := len(fake.requests("sts")); n != 2 {
		t.Errorf("another credential: %d exchanges in all, want 2", n)
	}
}

// TestExchangeCacheExchangesWithin225sOfExpiry: the federated token is
// reused until it is within 225 s of its expiry on the cache's wall clock,
// is dropped only when it is still the one refused, and a failed exchange
// caches nothing.
func TestExchangeCacheExchangesWithin225sOfExpiry(t *testing.T) {
	fake := newFedFake(t)
	cred := fake.credential(t, Reader)
	fc := cred.fed()
	now := time.Now().Round(0)
	fc.cache.now = func() time.Time { return now }
	first, err := fc.cache.federated(t.Context(), fc)
	if err != nil {
		t.Fatal(err)
	}
	if d := first.Expiry.Sub(now); d < 3590*time.Second || d > 3610*time.Second {
		t.Fatalf("the federated token expires %s from now", d)
	}
	now = first.Expiry.Add(-226 * time.Second)
	if again, err := fc.cache.federated(t.Context(), fc); err != nil || again != first {
		t.Errorf("226 s before its expiry: %v; want the cached token", err)
	}
	now = first.Expiry.Add(-224 * time.Second)
	second, err := fc.cache.federated(t.Context(), fc)
	if err != nil || second == first {
		t.Errorf("224 s before its expiry: %v; want a new exchange", err)
	}
	now = time.Now().Round(0)  // the new token is fresh again on the wall clock
	fc.cache.invalidate(first) // no longer the cached one: kept
	if kept, _ := fc.cache.federated(t.Context(), fc); kept != second {
		t.Error("invalidating a replaced token dropped the current one")
	}
	if n := len(fake.requests("sts")); n != 2 {
		t.Errorf("%d exchanges, want 2", n)
	}
	// A failed exchange caches nothing: not a new token, and not the stale
	// one it was replacing, which a clock set back would find fresh again.
	fake.sts.Close()
	now = second.Expiry.Add(-224 * time.Second)
	if tok, err := fc.cache.federated(t.Context(), fc); tok != nil || !errors.Is(err, ErrUnreachable) {
		t.Errorf("an exchange that failed: %v, %v", tok, err)
	}
	if fc.cache.tok != nil {
		t.Error("a failed exchange left the token it was replacing cached")
	}
	now = second.Expiry.Add(-time.Hour)
	if tok, err := fc.cache.federated(t.Context(), fc); tok != nil || !errors.Is(err, ErrUnreachable) {
		t.Errorf("after a failed exchange, with the clock set back: %v, %v; want another exchange, failing", tok, err)
	}
	fc.cache.invalidate(second)
	if tok, err := fc.cache.federated(t.Context(), fc); tok != nil || !errors.Is(err, ErrUnreachable) {
		t.Errorf("an exchange that failed: %v, %v", tok, err)
	}
	if fc.cache.tok != nil {
		t.Error("a failed exchange left a token cached")
	}
}

// TestFederatedTokensHaveNoMonotonicReading: the service account's token a
// federated mint returns, and a RoleTokens' expiry, are wall time alone.
func TestFederatedTokensHaveNoMonotonicReading(t *testing.T) {
	fake := newFedFake(t)
	cred := fake.credential(t, Reader)
	tok, err := cred.fed().mint(t.Context(), ScopesCluster)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Expiry != tok.Expiry.Round(0) || tok.Expiry.Location() != time.UTC {
		t.Errorf("the service account's token's Expiry %v carries a monotonic reading or is not UTC", tok.Expiry)
	}
	rt, err := TokenSourceFor(cred, ScopesStorage)
	if err != nil {
		t.Fatal(err)
	}
	_, exp, err := rt.Token(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if exp != exp.Round(0) || time.Until(exp) < 59*time.Minute {
		t.Errorf("RoleTokens' expiry %v", exp)
	}
}

// TestIdentityConstructorsRefuseUnderHTTP2Debug: while GODEBUG has turned on
// Go's HTTP/2 logging, every constructor of the identity path refuses first,
// with UnsafeEnvironment's whole text, before any other check.
func TestIdentityConstructorsRefuseUnderHTTP2Debug(t *testing.T) {
	fake := newFedFake(t)
	reader := fake.credential(t, Reader)
	saved := http2Verbose
	t.Cleanup(func() { http2Verbose = saved })
	http2Verbose = true
	for name, build := range map[string]func() (any, error){
		"NewLoopbackFederation": func() (any, error) {
			return NewLoopbackFederation("192.0.2.1:1", "", "", nil)
		},
		"TokenSourceFor":                 func() (any, error) { return TokenSourceFor(reader, ScopesStorage) },
		"TokenSourceFor, unknown scopes": func() (any, error) { return TokenSourceFor(reader, 0) },
		"NewIAMReader":                   func() (any, error) { return NewIAMReader(reader) },
		"NewIAMReader, a key":            func() (any, error) { return NewIAMReader(googleCredential(t)) },
		"New, federated": func() (any, error) {
			return New(Config{Endpoint: fake.endpoint(t), Credential: reader, Identity: Reader})
		},
	} {
		_, err := build()
		if !errors.Is(err, ErrUnsafeEnvironment) || err.Error() != msgHTTP2Debug {
			t.Errorf("%s under http2debug: %v; want the GODEBUG refusal", name, err)
		}
	}
	if n := len(fake.requests("sts")) + len(fake.requests("iam")) + len(fake.requests("api")) + len(fake.requests("cluster")); n != 0 {
		t.Errorf("%d requests were sent", n)
	}
}

// staticFederatedMint is a mint that counts and returns tokens expiring after
// life, for the RoleTokens tests.
type staticFederatedMint struct {
	mu   sync.Mutex
	n    int
	life time.Duration
}

func (m *staticFederatedMint) mint(context.Context) (*auth.Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.n++
	return &auth.Token{Value: fmt.Sprintf("sa-%d", m.n), Type: "Bearer", Expiry: time.Now().Add(m.life)}, nil
}

func (m *staticFederatedMint) calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.n
}
