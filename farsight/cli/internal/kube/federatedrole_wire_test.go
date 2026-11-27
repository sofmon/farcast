package kube_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
	tkube "github.com/sofmon/farcast/technocore/kube"
)

// The federated credential, the role token sources and the IAM reader on
// kubetest's fakes (M3b.3): the Federation fake's three hosts and a cluster
// fake given WithFederation, from package kube_test, as cli will wire them.

// wireRoleCredential adds a role's provider to fake, binds its role ID to
// email, and is the role's federated credential over fed.
func wireRoleCredential(t *testing.T, fake *kubetest.Federation, fed *kube.Federation, provider string, role kube.Identity, email string) (wireRole, kube.Credential) {
	t.Helper()
	r := newWireRole(t, provider)
	addRole(fake, r)
	fake.Bind(r.id, email)
	cred, err := kube.NewFederatedCredential(fed, r.aud, r.identity(), email, role)
	if err != nil {
		t.Fatal(err)
	}
	return r, cred
}

// wireReaderRig is the reader's role on fresh fakes: its provider
// provreader1, bound to wireReaderSA, which may view the pool, and its
// credential.
func wireReaderRig(t *testing.T, opts ...kubetest.FederationOption) (*kubetest.Federation, wireRole, kube.Credential) {
	t.Helper()
	fake, fed := wireSetup(t, opts...)
	r, cred := wireRoleCredential(t, fake, fed, "provreader1", kube.Reader, wireReaderSA)
	fake.GrantPoolViewer(wireReaderSA)
	return fake, r, cred
}

// fedClusterClient is a client of s, a cluster fake, for cred acting as
// role, with its retry waits recorded rather than slept.
func fedClusterClient(t *testing.T, s *kubetest.Server, cred kube.Credential, role kube.Identity) *kube.Client {
	t.Helper()
	ep, err := kube.ParseEndpoint(s.Endpoint(), "", s.CAPEM())
	if err != nil {
		t.Fatal(err)
	}
	c, err := kube.New(kube.Config{Endpoint: ep, Credential: cred, Identity: role})
	if err != nil {
		t.Fatal(err)
	}
	kube.SetSleep(c, (&waits{}).sleep)
	return c
}

// wireNamespacesRBAC grants email the namespaces' list, cluster-wide, and
// nothing else.
func wireNamespacesRBAC(email string) []byte {
	return []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: farcast-reader-namespaces
rules:
- apiGroups: [""]
  resources: [namespaces]
  verbs: [list]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: farcast-reader-namespaces
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: farcast-reader-namespaces
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: User
  name: ` + email + `
`)
}

// impersonationBodies are the bodies of the IAM Credentials requests, sorted.
func impersonationBodies(fake *kubetest.Federation) []string {
	var out []string
	for _, r := range requestsOf(fake, "iam") {
		out = append(out, string(r.Body))
	}
	slices.Sort(out)
	return out
}

// asOf is each request's As, in order.
func asOf(reqs []kubetest.FederationRequest) []string {
	var out []string
	for _, r := range reqs {
		out = append(out, r.As)
	}
	return out
}

// TestFederatedClientReadsTheCluster: a reader's federated credential reads
// the cluster fake as its service account: one exchange, one cluster-scoped
// impersonation, and no 2LO mint; the username is the account's email, so
// WithRBAC on that email grants the read, a read it does not grant is 403
// naming the email, and the request is recorded as the email, or as the
// label WithFederatedIdentity gives it.
func TestFederatedClientReadsTheCluster(t *testing.T) {
	fake, r, cred := wireReaderRig(t)
	s := kubetest.New(t, kubetest.WithFederation(fake), kubetest.WithRBAC(wireReaderSA, wireNamespacesRBAC(wireReaderSA)))
	c := fedClusterClient(t, s, cred, kube.Reader)
	ctx := t.Context()
	if _, err := c.ListNamespaces(ctx, ""); err != nil {
		t.Fatalf("the granted read: %v", err)
	}
	if got := last(t, s); got.As != wireReaderSA || got.Path != "/api/v1/namespaces" {
		t.Errorf("the read was recorded as %q at %s", got.As, got.Path)
	}
	_, err := c.ListPods(ctx, "web", "")
	var ae *kube.APIError
	if !errors.Is(err, tkube.ErrForbidden) || !errors.As(err, &ae) || !ae.KubernetesStatus || !strings.Contains(err.Error(), `User "`+wireReaderSA+`"`) {
		t.Errorf("the read not granted: %v; want an RBAC 403 naming the account", err)
	}
	if n := len(requestsOf(fake, "sts")); n != 1 {
		t.Errorf("%d exchanges, want 1", n)
	}
	if got := asOf(requestsOf(fake, "iam")); !slices.Equal(got, []string{r.id}) {
		t.Errorf("the impersonations were made as %q, want the reader's role ID once", got)
	}
	if got := impersonationBodies(fake); !slices.Equal(got, []string{string(kube.ImpersonationBody(kube.ScopesCluster))}) {
		t.Errorf("the impersonation bodies: %q", got)
	}
	sas := fake.ServiceAccountTokens()
	if len(sas) != 1 || sas[0].Email != wireReaderSA || sas[0].RoleID != r.id || !slices.Equal(sas[0].Scopes, kube.TokenScopes()) {
		t.Errorf("the tokens issued: %+v", sas)
	}
	if n := len(tokenRequests(s)); n != 0 {
		t.Errorf("the cluster fake's /token was asked %d times", n)
	}

	labelled := kubetest.New(t, kubetest.WithFederation(fake), kubetest.WithFederatedIdentity("reader", wireReaderSA))
	if _, err := fedClusterClient(t, labelled, cred, kube.Reader).ListNamespaces(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if got := last(t, labelled).As; got != "reader" {
		t.Errorf("with a label, the read was recorded as %q", got)
	}
	if n := len(requestsOf(fake, "sts")); n != 1 {
		t.Errorf("the second client exchanged: %d exchanges, want 1 for the credential", n)
	}
}

// TestOneExchangePerRolePerProcess is D5.1: one federated credential, with
// its copies, serves a cluster client, Cloud Storage's and Artifact
// Registry's token sources and an IAM reader, all at once, with one exchange
// at STS and one impersonation per consumer at IAM Credentials, each with
// its own scopes; asking again sends nothing; and another credential, as in
// another process, exchanges its own.
func TestOneExchangePerRolePerProcess(t *testing.T) {
	fake, r, cred := wireReaderRig(t)
	s := kubetest.New(t, kubetest.WithFederation(fake))
	copied := cred
	c := fedClusterClient(t, s, cred, kube.Reader)
	storage, err := kube.TokenSourceFor(copied, kube.ScopesStorage)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := kube.TokenSourceFor(cred, kube.ScopesRegistry)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := kube.NewIAMReader(copied)
	if err != nil {
		t.Fatal(err)
	}
	consumers := map[string]func() error{
		"cluster": func() error { _, err := c.ListNamespaces(t.Context(), ""); return err },
		"storage": func() error { _, _, err := storage.Token(t.Context()); return err },
		"registry": func() error {
			_, _, err := registry.Token(t.Context())
			return err
		},
		"iam": func() error {
			_, err := reader.GetProvider(t.Context(), wireProject, wirePool, r.provider)
			return err
		},
	}
	run := func() {
		var wg sync.WaitGroup
		errs := make(chan error, 4*len(consumers))
		for range 4 {
			for name, f := range consumers {
				wg.Go(func() {
					if err := f(); err != nil {
						errs <- fmt.Errorf("%s: %w", name, err)
					}
				})
			}
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
	}
	run()
	if n := len(requestsOf(fake, "sts")); n != 1 {
		t.Errorf("%d exchanges, want 1 for the role", n)
	}
	cluster := string(kube.ImpersonationBody(kube.ScopesCluster))
	want := []string{cluster, cluster, string(kube.ImpersonationBody(kube.ScopesRegistry)), string(kube.ImpersonationBody(kube.ScopesStorage))}
	slices.Sort(want)
	if got := impersonationBodies(fake); !slices.Equal(got, want) {
		t.Errorf("the impersonations: %q, want one per consumer: %q", got, want)
	}
	run()
	if n, m := len(requestsOf(fake, "sts")), len(requestsOf(fake, "iam")); n != 1 || m != 4 {
		t.Errorf("asking again: %d exchanges and %d impersonations in all, want 1 and 4", n, m)
	}

	again, err := kube.NewFederatedCredential(mustLoopback(t, fake), r.aud, r.identity(), wireReaderSA, kube.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ts, err := kube.TokenSourceFor(again, kube.ScopesStorage)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ts.Token(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := len(requestsOf(fake, "sts")); n != 2 {
		t.Errorf("another credential: %d exchanges in all, want 2", n)
	}
}

// mustLoopback is a loopback Federation at fake's three hosts.
func mustLoopback(t *testing.T, fake *kubetest.Federation) *kube.Federation {
	t.Helper()
	f, err := kube.NewLoopbackFederation(fake.STSAddr(), fake.IAMAddr(), fake.IAMAPIAddr(), fake.Roots())
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// TestClusterUnauthorizedReimpersonatesOnly: a cluster 401 drops the service
// account's token and impersonates once more with the role's federated
// token, never exchanging again; a second 401 in a row is the error, after
// one more impersonation.
func TestClusterUnauthorizedReimpersonatesOnly(t *testing.T) {
	fake, r, cred := wireReaderRig(t)
	s := kubetest.New(t, kubetest.WithFederation(fake))
	c := fedClusterClient(t, s, cred, kube.Reader)
	ctx := t.Context()
	if _, err := c.ListNamespaces(ctx, ""); err != nil {
		t.Fatal(err)
	}
	s.Fail(http.MethodGet, "/api/v1/namespaces", http.StatusUnauthorized, kube.Status{})
	if _, err := c.ListNamespaces(ctx, ""); err != nil {
		t.Fatalf("after a 401: %v; one re-impersonation and one retry", err)
	}
	if n := len(requestsOf(fake, "sts")); n != 1 {
		t.Errorf("%d exchanges, want 1: a cluster 401 never exchanges", n)
	}
	if got := asOf(requestsOf(fake, "iam")); !slices.Equal(got, []string{r.id, r.id}) {
		t.Errorf("the impersonations: %q, want two with the one federated token", got)
	}
	if n := len(requestsTo(s, http.MethodGet, "/api/v1/namespaces")); n != 3 {
		t.Errorf("%d reads, want 3", n)
	}

	s.Fail(http.MethodGet, "/api/v1/namespaces", http.StatusUnauthorized, kube.Status{})
	s.Fail(http.MethodGet, "/api/v1/namespaces", http.StatusUnauthorized, kube.Status{})
	if _, err := c.ListNamespaces(ctx, ""); !errors.Is(err, tkube.ErrUnauthorized) {
		t.Fatalf("two 401s: %v; want tkube.ErrUnauthorized", err)
	}
	if n, m := len(requestsOf(fake, "sts")), len(requestsOf(fake, "iam")); n != 1 || m != 3 {
		t.Errorf("two 401s: %d exchanges and %d impersonations in all, want 1 and 3", n, m)
	}
}

// TestIAMUnauthorizedReexchangesOnce: when IAM Credentials answers 401 to
// the role's federated token, the mint drops it, exchanges once more and
// impersonates once more; a second 401 is the error, after exactly two
// exchanges and two impersonations, with no body text in it (R10); any other
// refusal exchanges nothing more.
func TestIAMUnauthorizedReexchangesOnce(t *testing.T) {
	fake, r, cred := wireReaderRig(t)
	s := kubetest.New(t, kubetest.WithFederation(fake))
	c := fedClusterClient(t, s, cred, kube.Reader)
	ctx := t.Context()
	if _, err := c.ListNamespaces(ctx, ""); err != nil {
		t.Fatal(err)
	}
	fake.RevokeFederatedTokens()
	s.Fail(http.MethodGet, "/api/v1/namespaces", http.StatusUnauthorized, kube.Status{})
	if _, err := c.ListNamespaces(ctx, ""); err != nil {
		t.Fatalf("after a revoked federated token: %v", err)
	}
	if n := len(requestsOf(fake, "sts")); n != 2 {
		t.Errorf("%d exchanges, want 2: one more after IAM Credentials' 401", n)
	}
	if got := asOf(requestsOf(fake, "iam")); !slices.Equal(got, []string{r.id, "?", r.id}) {
		t.Errorf("the impersonations were made as %q, want the role, the revoked token, the role", got)
	}
	// A fresh consumer of the same credential uses the new federated token.
	ts, err := kube.TokenSourceFor(cred, kube.ScopesStorage)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ts.Token(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(requestsOf(fake, "sts")); n != 2 {
		t.Errorf("a fresh consumer exchanged: %d exchanges, want 2", n)
	}

	for _, row := range []struct {
		name             string
		code             int
		status           string
		exchanges, gats  int
		wantGoogleStatus string
	}{
		{"401 twice", http.StatusUnauthorized, "UNAUTHENTICATED", 2, 2, "UNAUTHENTICATED"},
		{"403", http.StatusForbidden, "PERMISSION_DENIED", 1, 1, "PERMISSION_DENIED"},
		{"500", http.StatusInternalServerError, "INTERNAL", 1, 1, "INTERNAL"},
	} {
		body := `{"error":{"code":` + fmt.Sprint(row.code) + `,"message":"` + wireMarker + `","status":"` + row.status + `"}}`
		fake, _, cred := wireReaderRig(t, kubetest.WithImpersonationAnswer(row.code, body))
		ts, err := kube.TokenSourceFor(cred, kube.ScopesRegistry)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = ts.Token(ctx)
		fe := federationError(t, err)
		if fe.Step != kube.StepImpersonate || fe.Status != row.code || fe.GoogleStatus != row.wantGoogleStatus || !errors.Is(err, kube.ErrTokenRefused) {
			t.Errorf("%s: %v; want IAM Credentials' refusal", row.name, err)
		}
		want := "kube: IAM Credentials refused the service account's token (" + fmt.Sprint(row.code) + " " + http.StatusText(row.code) + ", status " + row.status + ")"
		if err.Error() != want {
			t.Errorf("%s: %q, want %q", row.name, err, want)
		}
		for _, e := range wireErrorTree(err) {
			if strings.Contains(e.Error(), wireMarker) {
				t.Errorf("%s: the body's text is in the error", row.name)
			}
		}
		if n, m := len(requestsOf(fake, "sts")), len(requestsOf(fake, "iam")); n != row.exchanges || m != row.gats {
			t.Errorf("%s: %d exchanges and %d impersonations, want %d and %d", row.name, n, m, row.exchanges, row.gats)
		}
	}
}

// wireIAMAPIGet sends a GET for path to fake's IAM API with bearer, from a
// client of the fakes' roots, and returns the status and Google's
// error.status. The bearer is never printed.
func wireIAMAPIGet(t *testing.T, fake *kubetest.Federation, path, bearer string) (int, string) {
	t.Helper()
	c := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: fake.Roots(), ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}, DisableKeepAlives: true},
		Timeout:   10 * time.Second,
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+fake.IAMAPIAddr()+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal("the GET failed")
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var e struct {
		Error struct {
			Status string `json:"status"`
		} `json:"error"`
	}
	_ = json.Unmarshal(b, &e)
	return resp.StatusCode, e.Error.Status
}

// TestIAMReaderRefusesAWriterAtTheFake is R1 on the wire: NewIAMReader
// refuses the writer's credential before anything is sent, and a writer's
// service-account token, which its token source does give, is refused at
// IAM's API (403), where the reader's IAMReader reads.
func TestIAMReaderRefusesAWriterAtTheFake(t *testing.T) {
	fake, fed := wireSetup(t)
	reader, readerCred := wireRoleCredential(t, fake, fed, "provreader1", kube.Reader, wireReaderSA)
	_, writerCred := wireRoleCredential(t, fake, fed, "provwriter1", kube.Writer, wireWriterSA)
	fake.GrantPoolViewer(wireReaderSA)

	r, err := kube.NewIAMReader(writerCred)
	want := "kube: IAM's API is read with the reader's federated credential alone, and this one is the writer's; nothing was sent"
	if r != nil || !errors.Is(err, kube.ErrEndpointRefused) || err.Error() != want {
		t.Errorf("the writer's IAM reader: %v, %v; want %q", r, err, want)
	}
	if n := len(fake.Requests()); n != 0 {
		t.Errorf("%d requests reached the fakes", n)
	}

	writerTokens, err := kube.TokenSourceFor(writerCred, kube.ScopesCluster)
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := writerTokens.Token(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/projects/" + wireProject + "/locations/global/workloadIdentityPools/" + wirePool + "/providers/" + reader.provider
	if code, status := wireIAMAPIGet(t, fake, path, tok); code != http.StatusForbidden || status != "PERMISSION_DENIED" {
		t.Errorf("the writer's token at IAM's API: %d %s, want 403 PERMISSION_DENIED", code, status)
	}
	if got := requestsOf(fake, "iamapi"); len(got) != 1 || got[0].As != wireWriterSA {
		t.Errorf("IAM's API saw %q, want the writer's account once", asOf(got))
	}

	ir, err := kube.NewIAMReader(readerCred)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ir.GetProvider(t.Context(), wireProject, wirePool, reader.provider); err != nil {
		t.Errorf("the reader's read: %v", err)
	}
	if got := asOf(requestsOf(fake, "iamapi")); !slices.Equal(got, []string{wireWriterSA, wireReaderSA}) {
		t.Errorf("IAM's API saw %q", got)
	}
}

// wirePage is a list page as these tests read it.
type wirePage struct {
	Providers []struct {
		Name  string `json:"name"`
		State string `json:"state"`
	} `json:"workloadIdentityPoolProviders"`
	NextPageToken string `json:"nextPageToken"`
}

// TestListProvidersPagesAndDeletedOnTheWire: ListProviders follows the IAM
// API fake's pages, ten at a time with the soft-deleted ones, each next
// page's token escaped in the query; it refuses a server that repeats a
// token, a list of more than 50 pages after exactly 50 requests, a page over
// 1 MiB and a non-200 page, none of them carrying the answer's text (R10).
func TestListProvidersPagesAndDeletedOnTheWire(t *testing.T) {
	fake, r, cred := wireReaderRig(t)
	for i := range 22 {
		fake.AddProvider(wireProject, wirePool, fmt.Sprintf("prov%04d", i), r.anchorDER, r.id)
	}
	fake.RemoveProvider(wireProject, wirePool, "prov0007")
	fake.DisableProvider(wireProject, wirePool, "prov0008")
	reader, err := kube.NewIAMReader(cred)
	if err != nil {
		t.Fatal(err)
	}
	pages, err := reader.ListProviders(t.Context(), wireProject, wirePool)
	if err != nil {
		t.Fatal(err)
	}
	var sizes []int
	var ids []string
	states := map[string]string{}
	var tokens []string
	for _, body := range pages {
		var p wirePage
		if err := json.Unmarshal(body, &p); err != nil {
			t.Fatal(err)
		}
		sizes = append(sizes, len(p.Providers))
		for _, e := range p.Providers {
			id := e.Name[strings.LastIndex(e.Name, "/")+1:]
			ids = append(ids, id)
			states[id] = e.State
		}
		if p.NextPageToken != "" {
			tokens = append(tokens, p.NextPageToken)
		}
	}
	if !slices.Equal(sizes, []int{10, 10, 3}) || len(ids) != 23 || !slices.IsSorted(ids) || states["prov0007"] != "DELETED" || states["provreader1"] != "ACTIVE" {
		t.Errorf("the pages: sizes %v, IDs %v, states %v", sizes, ids, states)
	}
	reqs := requestsOf(fake, "iamapi")
	wantQueries := []string{"pageSize=10&showDeleted=true"}
	for _, tok := range tokens {
		wantQueries = append(wantQueries, "pageSize=10&showDeleted=true&pageToken="+url.QueryEscape(tok))
	}
	var queries []string
	for _, q := range reqs {
		queries = append(queries, q.RawQuery)
		if q.As != wireReaderSA || q.PeerCertificates != nil || q.Path != "/v1/projects/"+wireProject+"/locations/global/workloadIdentityPools/"+wirePool+"/providers" {
			t.Errorf("a page's request: As %q, %d certificates, path %s", q.As, len(q.PeerCertificates), q.Path)
		}
	}
	if !slices.Equal(queries, wantQueries) || len(tokens) != 2 || !strings.Contains(queries[1], "%2B") || !strings.Contains(queries[1], "%2F") || !strings.Contains(queries[1], "%3D") {
		t.Errorf("the queries %q, want %q, the tokens escaped", queries, wantQueries)
	}

	// The page cap: 502 providers are 51 pages of ten, refused after 50.
	big, bigRole, bigCred := wireReaderRig(t)
	for i := range 501 {
		big.AddProvider(wireProject, wirePool, fmt.Sprintf("prov%04d", i), bigRole.anchorDER, bigRole.id)
	}
	bigReader, err := kube.NewIAMReader(bigCred)
	if err != nil {
		t.Fatal(err)
	}
	_, err = bigReader.ListProviders(t.Context(), wireProject, wirePool)
	if fe := federationError(t, err); fe.Step != kube.StepProviderList || !errors.Is(err, kube.ErrUnreadable) ||
		err.Error() != "kube: IAM answered without a usable provider read (more than 50 pages)" {
		t.Errorf("51 pages: %v", err)
	}
	if n := len(requestsOf(big, "iamapi")); n != 50 {
		t.Errorf("51 pages: %d requests, want 50", n)
	}

	for _, row := range []struct {
		name, body string
		code       int
		want       string
		sentinel   error
		requests   int
	}{
		{"a repeated token", `{"nextPageToken":"` + wireMarker + `"}`, http.StatusOK,
			"kube: IAM answered without a usable provider read (a nextPageToken given before)", kube.ErrUnreadable, 2},
		{"a page over 1 MiB", `{"workloadIdentityPoolProviders":[],"x":"` + wireMarker + strings.Repeat("a", 1<<20) + `"}`, http.StatusOK,
			"kube: IAM answered without a usable provider read (the answer is larger than 1 MiB)", kube.ErrUnreadable, 1},
		{"a non-200 page", `{"error":{"code":500,"message":"` + wireMarker + `","status":"INTERNAL"}}`, http.StatusInternalServerError,
			"kube: IAM refused the provider read (500 Internal Server Error, status INTERNAL)", kube.ErrIAMRefused, 1},
		{"a 401 twice", `{"error":{"code":401,"message":"` + wireMarker + `","status":"UNAUTHENTICATED"}}`, http.StatusUnauthorized,
			"kube: IAM refused the provider read (401 Unauthorized, status UNAUTHENTICATED)", kube.ErrIAMRefused, 2},
	} {
		fake, _, cred := wireReaderRig(t, kubetest.WithIAMAPIAnswer(row.code, row.body))
		reader, err := kube.NewIAMReader(cred)
		if err != nil {
			t.Fatal(err)
		}
		pages, err := reader.ListProviders(t.Context(), wireProject, wirePool)
		if pages != nil || err == nil || err.Error() != row.want || !errors.Is(err, row.sentinel) {
			t.Errorf("%s: %v; want %q", row.name, err, row.want)
			continue
		}
		if fe := federationError(t, err); fe.Step != kube.StepProviderList {
			t.Errorf("%s: step %q", row.name, fe.Step)
		}
		for _, e := range wireErrorTree(err) {
			if strings.Contains(e.Error(), wireMarker) {
				t.Errorf("%s: the answer's text is in the error", row.name)
			}
		}
		if n := len(requestsOf(fake, "iamapi")); n != row.requests {
			t.Errorf("%s: %d requests, want %d", row.name, n, row.requests)
		}
	}
}

// TestOnlySTSSeesAClientCertificate is R2 on the fakes: across a cluster
// read, three token sources and an IAM reader's get and list, the leaf is
// presented at STS's handshakes and requests alone; IAM Credentials and
// IAM's API, which ask for one, record none on any handshake or request.
func TestOnlySTSSeesAClientCertificate(t *testing.T) {
	fake, r, cred := wireReaderRig(t)
	s := kubetest.New(t, kubetest.WithFederation(fake))
	if _, err := fedClusterClient(t, s, cred, kube.Reader).ListNamespaces(t.Context(), ""); err != nil {
		t.Fatal(err)
	}
	for _, sc := range []kube.Scopes{kube.ScopesCluster, kube.ScopesStorage, kube.ScopesRegistry} {
		ts, err := kube.TokenSourceFor(cred, sc)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := ts.Token(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	reader, err := kube.NewIAMReader(cred)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.GetProvider(t.Context(), wireProject, wirePool, r.provider); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ListProviders(t.Context(), wireProject, wirePool); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, q := range fake.Requests() {
		counts[q.Server]++
		switch q.Server {
		case "sts":
			if !equalDERs(q.PeerCertificates, [][]byte{r.leafDER}) {
				t.Errorf("an exchange's request presented %d certificates, not the leaf", len(q.PeerCertificates))
			}
		default:
			if q.PeerCertificates != nil {
				t.Errorf("a request at %s carried a client certificate", q.Server)
			}
		}
	}
	for _, h := range fake.Handshakes() {
		if h.Server != "sts" && len(h.PeerCertificates) != 0 {
			t.Errorf("a handshake at %s presented a client certificate", h.Server)
		}
	}
	if counts["sts"] != 1 || counts["iam"] != 5 || counts["iamapi"] != 2 {
		t.Errorf("the requests by server: %v", counts)
	}
	if len(handshakesOf(fake, "iamapi")) == 0 || len(handshakesOf(fake, "iam")) == 0 {
		t.Error("no handshake at IAM Credentials or IAM's API was recorded")
	}
}

// TestPerConsumerScopesAtTheCluster is N9 at the cluster fake: of a reader's
// three token sources, only the cluster's token is taken by the cluster; the
// storage-scoped and registry-scoped tokens are 401 there.
func TestPerConsumerScopesAtTheCluster(t *testing.T) {
	fake, _, cred := wireReaderRig(t)
	s := kubetest.New(t, kubetest.WithFederation(fake))
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(s.CAPEM()) {
		t.Fatal("the cluster fake's CA does not parse")
	}
	c := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true},
		Timeout:   10 * time.Second,
	}
	for _, row := range []struct {
		name string
		sc   kube.Scopes
		code int
		as   string
	}{
		{"cluster", kube.ScopesCluster, http.StatusOK, wireReaderSA},
		{"storage", kube.ScopesStorage, http.StatusUnauthorized, "?"},
		{"registry", kube.ScopesRegistry, http.StatusUnauthorized, "?"},
	} {
		ts, err := kube.TokenSourceFor(cred, row.sc)
		if err != nil {
			t.Fatal(err)
		}
		tok, _, err := ts.Token(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+s.Endpoint()+"/api/v1/namespaces", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("%s: the read failed", row.name)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != row.code || last(t, s).As != row.as {
			t.Errorf("%s: %d as %q, want %d as %q", row.name, resp.StatusCode, last(t, s).As, row.code, row.as)
		}
	}
}
