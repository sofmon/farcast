package kubetest_test

import (
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
)

// fedSAToken is a service-account token for email, impersonated with r's
// federated token at aud, for scopes.
func fedSAToken(t *testing.T, fake *kubetest.Federation, r fedRole, aud, email string, scopes kube.Scopes) string {
	t.Helper()
	fedTok := fedFederatedToken(t, fake, r, aud)
	code, m := fedPost(t, fedHTTP(fake, nil, nil, tls.VersionTLS12),
		"https://"+fake.IAMAddr()+"/v1/projects/-/serviceAccounts/"+email+":generateAccessToken", "application/json", fedTok, string(kube.ImpersonationBody(scopes)))
	tok, _ := m["accessToken"].(string)
	if code != http.StatusOK || tok == "" {
		t.Fatalf("the impersonation answered %d", code)
	}
	return tok
}

// fedGet is a GET of target with bearer ("" none), and its status and body.
func fedGet(t *testing.T, c *http.Client, target, bearer string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, b
}

// providersURL is the IAM API fake's URL for the pool's providers, with
// provider appended when it is not "", and query when it is not "".
func providersURL(fake *kubetest.Federation, pool, provider, query string) string {
	u := "https://" + fake.IAMAPIAddr() + "/v1/projects/" + fedProject + "/locations/global/workloadIdentityPools/" + pool + "/providers"
	if provider != "" {
		u += "/" + provider
	}
	if query != "" {
		u += "?" + query
	}
	return u
}

// fedIAMAPIStatus is a Google JSON error's code and status.
func fedIAMAPIStatus(t *testing.T, body []byte) (int, string) {
	t.Helper()
	var e struct {
		Error struct {
			Code   int    `json:"code"`
			Status string `json:"status"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &e); err != nil {
		t.Fatalf("the answer is not Google's JSON error: %v", err)
	}
	return e.Error.Code, e.Error.Status
}

// iamAPIFixture is a Federation with the reader's role added as provreader1,
// bound to fedSA, which may view the pool, and a client of the fakes that
// presents no certificate.
type iamAPIFixture struct {
	fake *kubetest.Federation
	r    fedRole
	aud  string
	c    *http.Client
}

func newIAMAPIFixture(t *testing.T, opts ...kubetest.FederationOption) iamAPIFixture {
	t.Helper()
	fake := kubetest.NewFederation(t, opts...)
	r := newFedRole(t)
	aud := fedAddRole(t, fake, "provreader1", r, r.id)
	fake.Bind(r.id, fedSA)
	fake.GrantPoolViewer(fedSA)
	return iamAPIFixture{fake: fake, r: r, aud: aud, c: fedHTTP(fake, nil, nil, tls.VersionTLS12)}
}

// TestFakeSTSRefusesADeletedOrDisabledProvider: a provider RemoveProvider
// deleted, or DisableProvider disabled, takes no exchange (invalid_target);
// the others in the pool still do; and AddProvider puts back an ACTIVE one.
func TestFakeSTSRefusesADeletedOrDisabledProvider(t *testing.T) {
	fake := kubetest.NewFederation(t)
	kept, removed, disabled := newFedRole(t), newFedRole(t), newFedRole(t)
	audKept := fedAddRole(t, fake, "provkept1", kept, kept.id)
	audRemoved := fedAddRole(t, fake, "provremoved1", removed, removed.id)
	audDisabled := fedAddRole(t, fake, "provdisabled1", disabled, disabled.id)
	exchange := func(r fedRole, aud string) (int, string) {
		code, m := fedExchange(t, fedHTTP(fake, [][]byte{r.leafDER}, r.leafKey, tls.VersionTLS13), fake, fedForm(t, aud, r.leafDER))
		return code, oauthCode(m)
	}
	for _, r := range []struct {
		role fedRole
		aud  string
	}{{kept, audKept}, {removed, audRemoved}, {disabled, audDisabled}} {
		if code, oauth := exchange(r.role, r.aud); code != http.StatusOK {
			t.Fatalf("before: %d %q", code, oauth)
		}
	}
	fake.RemoveProvider(fedProject, fedPool, "provremoved1")
	fake.DisableProvider(fedProject, fedPool, "provdisabled1")
	for name, r := range map[string]struct {
		role fedRole
		aud  string
	}{"deleted": {removed, audRemoved}, "disabled": {disabled, audDisabled}} {
		if code, oauth := exchange(r.role, r.aud); code != http.StatusBadRequest || oauth != "invalid_target" {
			t.Errorf("a %s provider: %d %q, want 400 invalid_target", name, code, oauth)
		}
	}
	if code, oauth := exchange(kept, audKept); code != http.StatusOK {
		t.Errorf("the provider left alone: %d %q", code, oauth)
	}
	fedAddRole(t, fake, "provremoved1", removed, removed.id)
	if code, oauth := exchange(removed, audRemoved); code != http.StatusOK {
		t.Errorf("a provider added again: %d %q", code, oauth)
	}
	for name, f := range map[string]func(){
		"RemoveProvider of an unknown provider":  func() { fake.RemoveProvider(fedProject, fedPool, "provunknown") },
		"DisableProvider of an unknown provider": func() { fake.DisableProvider(fedProject, fedPool, "provunknown") },
		"RemoveProvider of a bad shape":          func() { fake.RemoveProvider("my-project", fedPool, "provkept1") },
		"AddProvider with a role ID not hex":     func() { fake.AddProvider(fedProject, fedPool, "provbad1", kept.anchorDER, "x' || true || '") },
		"GrantPoolViewer of no account":          func() { fake.GrantPoolViewer("") },
	} {
		if !panics(f) {
			t.Errorf("%s did not panic", name)
		}
	}
}

func panics(f func()) (did bool) {
	defer func() { did = recover() != nil }()
	f()
	return false
}

// TestFakeIAMCredentialsUnbindAndRevoke: Unbind takes back a binding (403
// from then on, while a token already issued is kept), and
// RevokeFederatedTokens makes every federated token issued so far unknown
// (401), while a fresh exchange works.
func TestFakeIAMCredentialsUnbindAndRevoke(t *testing.T) {
	fake := kubetest.NewFederation(t)
	r := newFedRole(t)
	aud := fedAddRole(t, fake, "provreader1", r, r.id)
	fake.Bind(r.id, fedSA)
	fake.Bind(r.id, fedOtherSA)
	c := fedHTTP(fake, nil, nil, tls.VersionTLS12)
	gat := func(email, fedTok string) (int, string) {
		code, m := fedPost(t, c, "https://"+fake.IAMAddr()+"/v1/projects/-/serviceAccounts/"+email+":generateAccessToken", "application/json", fedTok, string(kube.ImpersonationBody(kube.ScopesCluster)))
		return code, googleStatus(m)
	}
	first := fedFederatedToken(t, fake, r, aud)
	if code, st := gat(fedSA, first); code != http.StatusOK {
		t.Fatalf("bound: %d %s", code, st)
	}
	fake.Unbind(r.id, fedSA)
	if code, st := gat(fedSA, first); code != http.StatusForbidden || st != "PERMISSION_DENIED" {
		t.Errorf("unbound: %d %s, want 403 PERMISSION_DENIED", code, st)
	}
	if code, st := gat(fedOtherSA, first); code != http.StatusOK {
		t.Errorf("the other binding: %d %s, want 200", code, st)
	}
	fake.Unbind(r.id, fedOtherSA)
	fake.Unbind(r.id, fedOtherSA) // twice changes nothing
	if code, _ := gat(fedOtherSA, first); code != http.StatusForbidden {
		t.Errorf("the other binding unbound: %d, want 403", code)
	}
	if n := len(fake.ServiceAccountTokens()); n != 2 {
		t.Errorf("Unbind changed the registry: %d tokens, want the 2 issued", n)
	}

	fake.Bind(r.id, fedSA)
	fake.RevokeFederatedTokens()
	before := len(fake.Requests())
	if code, st := gat(fedSA, first); code != http.StatusUnauthorized || st != "UNAUTHENTICATED" {
		t.Errorf("a revoked federated token: %d %s, want 401 UNAUTHENTICATED", code, st)
	}
	if reqs := fake.Requests(); len(reqs) != before+1 || reqs[before].As != "?" {
		t.Error("the revoked token's request was not recorded as unknown")
	}
	if code, st := gat(fedSA, fedFederatedToken(t, fake, r, aud)); code != http.StatusOK {
		t.Errorf("a fresh federated token: %d %s, want 200", code, st)
	}
}

// TestFakeIAMAPIGetsAProvider: a get answers the provider as Google's JSON,
// exactly: its name with the project's number, ACTIVE, D3's mapping and
// condition, the anchor's PEM as the one trust anchor, and no disabled,
// displayName, description or expireTime; a disabled one says so; a deleted
// one is still answered, DELETED, with an expireTime about 30 days on; an
// unknown one is 404; and the request is recorded as the account's, with no
// query and no client certificate.
func TestFakeIAMAPIGetsAProvider(t *testing.T) {
	x := newIAMAPIFixture(t)
	tok := fedSAToken(t, x.fake, x.r, x.aud, fedSA, kube.ScopesCluster)
	name := "projects/" + fedProject + "/locations/global/workloadIdentityPools/" + fedPool + "/providers/provreader1"
	want := map[string]any{
		"name":               name,
		"state":              "ACTIVE",
		"attributeMapping":   map[string]any{"google.subject": "assertion.issuer.dn.cn"},
		"attributeCondition": "assertion.issuer.dn.cn == '" + x.r.id + "' && assertion.subject.dn.cn == '" + x.r.id + "'",
		"x509": map[string]any{"trustStore": map[string]any{"trustAnchors": []any{
			map[string]any{"pemCertificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x.r.anchorDER}))},
		}}},
	}
	get := func() (int, map[string]any) {
		t.Helper()
		code, body := fedGet(t, x.c, providersURL(x.fake, fedPool, "provreader1", ""), tok)
		var m map[string]any
		if err := json.Unmarshal(body, &m); err != nil {
			t.Fatalf("the answer is not JSON: %v", err)
		}
		return code, m
	}
	code, got := get()
	if code != http.StatusOK || !reflect.DeepEqual(got, want) {
		t.Errorf("the get: %d %v\nwant %v", code, got, want)
	}
	reqs := x.fake.Requests()
	last := reqs[len(reqs)-1]
	if last.Server != "iamapi" || last.Method != http.MethodGet || last.Path != "/v1/"+name || last.RawQuery != "" || last.As != fedSA ||
		last.PeerCertificates != nil || !slices.Contains(last.Headers, "Authorization") {
		t.Errorf("the get was recorded as %+v", last)
	}

	x.fake.DisableProvider(fedProject, fedPool, "provreader1")
	code, got = get()
	want["disabled"] = true
	if code != http.StatusOK || !reflect.DeepEqual(got, want) {
		t.Errorf("a disabled provider: %d %v", code, got)
	}

	x.fake.RemoveProvider(fedProject, fedPool, "provreader1")
	code, got = get()
	exp, _ := got["expireTime"].(string)
	when, err := time.Parse(time.RFC3339Nano, exp)
	if code != http.StatusOK || got["state"] != "DELETED" || err != nil || time.Until(when) < 29*24*time.Hour || time.Until(when) > 31*24*time.Hour {
		t.Errorf("a deleted provider: %d, state %v, expireTime %q", code, got["state"], exp)
	}
	delete(got, "expireTime")
	want["state"] = "DELETED"
	if !reflect.DeepEqual(got, want) {
		t.Errorf("a deleted provider's other fields: %v", got)
	}

	for _, c := range []struct {
		name, target string
		code         int
		status       string
	}{
		{"an unknown provider", providersURL(x.fake, fedPool, "provunknown", ""), http.StatusNotFound, "NOT_FOUND"},
		{"another pool", providersURL(x.fake, "pool5678", "provreader1", ""), http.StatusNotFound, "NOT_FOUND"},
		{"a get with a query", providersURL(x.fake, fedPool, "provreader1", "showDeleted=true"), http.StatusBadRequest, "INVALID_ARGUMENT"},
		{"a provider ID out of shape", providersURL(x.fake, fedPool, "gcp-provider", ""), http.StatusBadRequest, "INVALID_ARGUMENT"},
		{"a pool ID out of shape", providersURL(x.fake, "Pool1234", "provreader1", ""), http.StatusBadRequest, "INVALID_ARGUMENT"},
		{"a project ID for the number", strings.Replace(providersURL(x.fake, fedPool, "provreader1", ""), fedProject, "my-project", 1), http.StatusBadRequest, "INVALID_ARGUMENT"},
		{"another path", "https://" + x.fake.IAMAPIAddr() + "/v1/projects/" + fedProject + "/locations/global/workloadIdentityPools/" + fedPool, http.StatusNotFound, "NOT_FOUND"},
		{"a path one level too deep", providersURL(x.fake, fedPool, "provreader1/x", ""), http.StatusNotFound, "NOT_FOUND"},
		{"an escaped path", "https://" + x.fake.IAMAPIAddr() + "/v1/projects/" + fedProject + "/locations/global/workloadIdentityPools/" + fedPool + "/providers/prov%2Freader1", http.StatusNotFound, "NOT_FOUND"},
	} {
		code, body := fedGet(t, x.c, c.target, tok)
		if gotCode, st := fedIAMAPIStatus(t, body); code != c.code || gotCode != c.code || st != c.status {
			t.Errorf("%s: %d %s, want %d %s", c.name, code, st, c.code, c.status)
		}
	}
	if code, m := fedPost(t, x.c, providersURL(x.fake, fedPool, "provreader1", ""), "application/json", tok, `{}`); code != http.StatusMethodNotAllowed || googleStatus(m) != "INVALID_ARGUMENT" {
		t.Errorf("a POST: %d %s, want 405", code, googleStatus(m))
	}
}

// listPage is a list page as the test reads it.
type listPage struct {
	Providers []struct {
		Name     string `json:"name"`
		State    string `json:"state"`
		Disabled bool   `json:"disabled"`
	} `json:"workloadIdentityPoolProviders"`
	NextPageToken *string `json:"nextPageToken"`
}

// TestFakeIAMAPIListsInPages: a list is the pool's providers in ID order,
// pageSize a page, with a nextPageToken (holding '+', '/' and '=', so it
// must be escaped) on every page but the last, which has none; the DELETED
// ones only under showDeleted=true; pageSize 0 or absent is 50 and more than
// 100 is 100; another pool's providers never; and a query out of the list's
// shape, or a token from another filter or never given, is 400.
func TestFakeIAMAPIListsInPages(t *testing.T) {
	x := newIAMAPIFixture(t)
	tok := fedSAToken(t, x.fake, x.r, x.aud, fedSA, kube.ScopesCluster)
	var ids []string
	for i := range 23 {
		id := fmt.Sprintf("prov%04d", 22-i) // added out of order
		x.fake.AddProvider(fedProject, fedPool, id, x.r.anchorDER, x.r.id)
		ids = append(ids, id)
	}
	x.fake.AddProvider(fedProject, "pool5678", "provother1", x.r.anchorDER, x.r.id)
	ids = append(ids, "provreader1")
	slices.Sort(ids)
	x.fake.RemoveProvider(fedProject, fedPool, "prov0003")
	x.fake.DisableProvider(fedProject, fedPool, "prov0004")

	list := func(query string) []listPage {
		t.Helper()
		var pages []listPage
		next := ""
		for range 100 {
			q := query
			if next != "" {
				q += "&pageToken=" + url.QueryEscape(next)
			}
			code, body := fedGet(t, x.c, providersURL(x.fake, fedPool, "", q), tok)
			if code != http.StatusOK {
				t.Fatalf("%s: page %d answered %d: %s", query, len(pages)+1, code, body)
			}
			var p listPage
			if err := json.Unmarshal(body, &p); err != nil {
				t.Fatal(err)
			}
			var top map[string]json.RawMessage
			if err := json.Unmarshal(body, &top); err != nil {
				t.Fatal(err)
			}
			for k := range top {
				if k != "workloadIdentityPoolProviders" && k != "nextPageToken" {
					t.Errorf("a page holds the key %q", k)
				}
			}
			pages = append(pages, p)
			if p.NextPageToken == nil {
				return pages
			}
			if *p.NextPageToken == "" || !strings.ContainsAny(*p.NextPageToken, "+/=") {
				t.Fatalf("the page token %q is empty, or holds none of + / =", *p.NextPageToken)
			}
			next = *p.NextPageToken
		}
		t.Fatal("the list never ended")
		return nil
	}
	names := func(pages []listPage) (sizes []int, ids []string, states map[string]string) {
		states = map[string]string{}
		for _, p := range pages {
			sizes = append(sizes, len(p.Providers))
			for _, e := range p.Providers {
				id := e.Name[strings.LastIndex(e.Name, "/")+1:]
				ids = append(ids, id)
				states[id] = e.State
				if e.Disabled {
					states[id] += " disabled"
				}
			}
		}
		return sizes, ids, states
	}

	sizes, got, states := names(list("pageSize=10&showDeleted=true"))
	if !slices.Equal(sizes, []int{10, 10, 4}) || !slices.Equal(got, ids) {
		t.Errorf("showDeleted, ten a page: sizes %v, IDs %v", sizes, got)
	}
	if states["prov0003"] != "DELETED" || states["prov0004"] != "ACTIVE disabled" || states["prov0005"] != "ACTIVE" {
		t.Errorf("the states: %v", states)
	}
	sizes, got, _ = names(list("pageSize=10"))
	if !slices.Equal(sizes, []int{10, 10, 3}) || slices.Contains(got, "prov0003") || len(got) != len(ids)-1 {
		t.Errorf("without showDeleted: sizes %v, IDs %v", sizes, got)
	}
	if sizes, _, _ = names(list("showDeleted=false")); !slices.Equal(sizes, []int{23}) {
		t.Errorf("no pageSize: sizes %v, want one page of 23 (50 a page)", sizes)
	}
	if sizes, _, _ = names(list("pageSize=0&showDeleted=true")); !slices.Equal(sizes, []int{24}) {
		t.Errorf("pageSize 0: sizes %v, want one page", sizes)
	}
	for i := range 80 {
		x.fake.AddProvider(fedProject, fedPool, fmt.Sprintf("provmore%03d", i), x.r.anchorDER, x.r.id)
	}
	if sizes, _, _ = names(list("pageSize=500&showDeleted=true")); !slices.Equal(sizes, []int{100, 4}) {
		t.Errorf("pageSize 500: sizes %v, want 100 a page", sizes)
	}
	if sizes, _, _ = names(list("")); !slices.Equal(sizes, []int{50, 50, 3}) {
		t.Errorf("no query: sizes %v, want 50 a page", sizes)
	}
	code, body := fedGet(t, x.c, providersURL(x.fake, "pool9999", "", ""), tok)
	if code != http.StatusOK || strings.TrimSpace(string(body)) != "{}" {
		t.Errorf("an empty pool: %d %s, want 200 {}", code, body)
	}

	_, first := fedGet(t, x.c, providersURL(x.fake, fedPool, "", "pageSize=10&showDeleted=true"), tok)
	var p listPage
	if err := json.Unmarshal(first, &p); err != nil || p.NextPageToken == nil {
		t.Fatalf("the first page: %v", err)
	}
	given := *p.NextPageToken
	for _, c := range []struct{ name, query string }{
		{"an unknown key", "pageSize=10&filter=x"},
		{"a key twice", "pageSize=10&pageSize=10"},
		{"a negative pageSize", "pageSize=-1"},
		{"a pageSize not an integer", "pageSize=ten"},
		{"a pageSize with a sign", "pageSize=+10"},
		{"showDeleted not a bool", "showDeleted=yes"},
		{"a token from the other filter", "pageSize=10&pageToken=" + url.QueryEscape(given)},
		{"the token unescaped", "pageSize=10&showDeleted=true&pageToken=" + given},
		{"a token never given", "pageSize=10&showDeleted=true&pageToken=kubetest-page-10"},
		{"a token past the end", "showDeleted=true&pageToken=" + url.QueryEscape(strings.Replace(given, "10", "9999", 1))},
		{"a query that does not parse", "pageSize=%zz"},
	} {
		code, body := fedGet(t, x.c, providersURL(x.fake, fedPool, "", c.query), tok)
		if _, st := fedIAMAPIStatus(t, body); code != http.StatusBadRequest || st != "INVALID_ARGUMENT" {
			t.Errorf("%s: %d %s, want 400 INVALID_ARGUMENT", c.name, code, st)
		}
	}
	if code, _ := fedGet(t, x.c, providersURL(x.fake, fedPool, "", "showDeleted=true&pageToken="+url.QueryEscape(given)), tok); code != http.StatusOK {
		t.Errorf("the given token under its own filter: %d", code)
	}
}

// TestFakeIAMAPIChecksTheBearer is R1 at the fake: IAM's API takes a live
// service-account token whose scopes hold cloud-platform, of an account
// GrantPoolViewer granted, and nothing else: no bearer and a token IAM
// Credentials never issued (a federated token, a Server's 2LO token, a
// planted string) are 401; a storage-scoped token, and a writer's token, are
// 403. The request is recorded first, with As the account, "?" or "".
func TestFakeIAMAPIChecksTheBearer(t *testing.T) {
	x := newIAMAPIFixture(t)
	writer := newFedRole(t)
	audWriter := fedAddRole(t, x.fake, "provwriter1", writer, writer.id)
	x.fake.Bind(writer.id, fedOtherSA)
	s := kubetest.New(t)
	twoLegged := (&fixture{t: t, s: s, hc: clientFor(t, s, false)}).mint(s.Credential("reader"))
	for _, row := range []struct {
		name, bearer string
		code         int
		status, as   string
	}{
		{"no bearer", "", http.StatusUnauthorized, "UNAUTHENTICATED", ""},
		{"a federated token", fedFederatedToken(t, x.fake, x.r, x.aud), http.StatusUnauthorized, "UNAUTHENTICATED", "?"},
		{"a Server's 2LO token", twoLegged, http.StatusUnauthorized, "UNAUTHENTICATED", "?"},
		{"a planted string", "kubetest-sa-1-0000000000000000", http.StatusUnauthorized, "UNAUTHENTICATED", "?"},
		{"a storage-scoped token", fedSAToken(t, x.fake, x.r, x.aud, fedSA, kube.ScopesStorage), http.StatusForbidden, "PERMISSION_DENIED", fedSA},
		{"the writer's token", fedSAToken(t, x.fake, writer, audWriter, fedOtherSA, kube.ScopesCluster), http.StatusForbidden, "PERMISSION_DENIED", fedOtherSA},
		{"a registry-scoped reader token", fedSAToken(t, x.fake, x.r, x.aud, fedSA, kube.ScopesRegistry), http.StatusOK, "", fedSA},
		{"a cluster-scoped reader token", fedSAToken(t, x.fake, x.r, x.aud, fedSA, kube.ScopesCluster), http.StatusOK, "", fedSA},
	} {
		before := len(x.fake.Requests())
		code, body := fedGet(t, x.c, providersURL(x.fake, fedPool, "provreader1", ""), row.bearer)
		if code != row.code {
			t.Errorf("%s: %d, want %d", row.name, code, row.code)
		}
		if row.code != http.StatusOK {
			if _, st := fedIAMAPIStatus(t, body); st != row.status {
				t.Errorf("%s: status %s, want %s", row.name, st, row.status)
			}
		}
		reqs := x.fake.Requests()
		if len(reqs) != before+1 || reqs[before].Server != "iamapi" || reqs[before].As != row.as {
			t.Errorf("%s: not recorded first, as %q", row.name, row.as)
		}
		if row.bearer != "" && strings.Contains(fmt.Sprintf("%#v", reqs), row.bearer) {
			t.Errorf("%s: the bearer is in the record", row.name)
		}
	}
	// A list is held to the same bearer.
	if code, _ := fedGet(t, x.c, providersURL(x.fake, fedPool, "", ""), fedSAToken(t, x.fake, writer, audWriter, fedOtherSA, kube.ScopesCluster)); code != http.StatusForbidden {
		t.Errorf("the writer's list: %d, want 403", code)
	}
	// The other kinds of request answer as their path decides before the
	// bearer is looked at.
	if code, _ := fedGet(t, x.c, "https://"+x.fake.IAMAPIAddr()+"/v1/elsewhere", ""); code != http.StatusNotFound {
		t.Errorf("an unknown path with no bearer: %d, want 404", code)
	}
}

// fedIAMAPIMessage is a Google JSON error's message.
func fedIAMAPIMessage(t *testing.T, body []byte) string {
	t.Helper()
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &e); err != nil {
		t.Fatalf("the answer is not Google's JSON error: %v", err)
	}
	return e.Error.Message
}

// TestFakeIAMAPIChecksInOrder: the IAM API fake looks at the bearer before
// the resource name's shape (401, then 403 for the scopes, then 403 for the
// pool viewer, and only then 400), takes the bearer only as
// "Bearer <token>", and answers an escaped path as no path it serves (404).
func TestFakeIAMAPIChecksInOrder(t *testing.T) {
	x := newIAMAPIFixture(t)
	other := newFedRole(t)
	audOther := fedAddRole(t, x.fake, "provother1", other, other.id)
	x.fake.Bind(other.id, fedOtherSA) // fedOtherSA is no pool viewer
	reader := fedSAToken(t, x.fake, x.r, x.aud, fedSA, kube.ScopesCluster)
	badNumber := "https://" + x.fake.IAMAPIAddr() + "/v1/projects/12ab/locations/global/workloadIdentityPools/" + fedPool + "/providers/provreader1"
	for _, row := range []struct {
		name, target, bearer string
		code                 int
		status, message      string
	}{
		{"no bearer, a malformed name", badNumber, "", http.StatusUnauthorized, "UNAUTHENTICATED", ""},
		{"a planted bearer, a malformed name", badNumber, "kubetest-sa-1-0000000000000000", http.StatusUnauthorized, "UNAUTHENTICATED", ""},
		{"a non-viewer's token, a malformed name", badNumber, fedSAToken(t, x.fake, other, audOther, fedOtherSA, kube.ScopesCluster),
			http.StatusForbidden, "PERMISSION_DENIED", "the service account may not view the workload identity pool"},
		{"a non-viewer's storage-scoped token: the scopes first", providersURL(x.fake, fedPool, "provreader1", ""),
			fedSAToken(t, x.fake, other, audOther, fedOtherSA, kube.ScopesStorage),
			http.StatusForbidden, "PERMISSION_DENIED", "the token's scopes do not hold cloud-platform"},
		{"the reader's token, a malformed name", badNumber, reader, http.StatusBadRequest, "INVALID_ARGUMENT", ""},
		{"the reader's token, an escaped path", strings.Replace(providersURL(x.fake, fedPool, "provreader1", ""), "provreader1", "prov%72eader1", 1),
			reader, http.StatusNotFound, "NOT_FOUND", ""},
	} {
		code, body := fedGet(t, x.c, row.target, row.bearer)
		if code != row.code {
			t.Errorf("%s: %d, want %d", row.name, code, row.code)
			continue
		}
		if _, st := fedIAMAPIStatus(t, body); st != row.status {
			t.Errorf("%s: status %s, want %s", row.name, st, row.status)
		}
		if msg := fedIAMAPIMessage(t, body); row.message != "" && msg != row.message {
			t.Errorf("%s: %q, want %q", row.name, msg, row.message)
		}
	}
	// A bearer without its scheme is no bearer the fake takes.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, providersURL(x.fake, fedPool, "provreader1", ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", reader)
	resp, err := x.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	reqs := x.fake.Requests()
	if resp.StatusCode != http.StatusUnauthorized || reqs[len(reqs)-1].As != "?" {
		t.Errorf("a token without \"Bearer \": %d, recorded as %q; want 401 as \"?\"", resp.StatusCode, reqs[len(reqs)-1].As)
	}
	// The control: the same token, as a bearer, reads.
	if code, _ := fedGet(t, x.c, providersURL(x.fake, fedPool, "provreader1", ""), reader); code != http.StatusOK {
		t.Errorf("the reader's token: %d, want 200", code)
	}
}

// TestFakeIAMAPIRecordsAClientCertificate: the IAM API fake asks for a client
// certificate without needing one, so one a client sends is recorded, on the
// handshake and on the request: R2's check that none reaches it means
// something.
func TestFakeIAMAPIRecordsAClientCertificate(t *testing.T) {
	x := newIAMAPIFixture(t)
	tok := fedSAToken(t, x.fake, x.r, x.aud, fedSA, kube.ScopesCluster)
	with := fedHTTP(x.fake, [][]byte{x.r.leafDER}, x.r.leafKey, tls.VersionTLS12)
	if code, _ := fedGet(t, with, providersURL(x.fake, fedPool, "provreader1", ""), tok); code != http.StatusOK {
		t.Fatalf("with a certificate: %d", code)
	}
	reqs := x.fake.Requests()
	last := reqs[len(reqs)-1]
	hs := handshakesAt(x.fake, "iamapi")
	if len(last.PeerCertificates) != 1 || string(last.PeerCertificates[0]) != string(x.r.leafDER) ||
		len(hs) == 0 || len(hs[len(hs)-1].PeerCertificates) != 1 {
		t.Error("a certificate sent to the IAM API fake was not recorded")
	}
}

// TestFakeIAMAPIAnswerOverride: WithIAMAPIAnswer answers every request with
// its code and body, a get's and a list's alike, whatever the bearer; each
// is still recorded.
func TestFakeIAMAPIAnswerOverride(t *testing.T) {
	x := newIAMAPIFixture(t, kubetest.WithIAMAPIAnswer(http.StatusServiceUnavailable, `{"error":{"code":503,"status":"UNAVAILABLE","message":"MARKER"}}`))
	for _, target := range []string{providersURL(x.fake, fedPool, "provreader1", ""), providersURL(x.fake, fedPool, "", "pageSize=10")} {
		code, body := fedGet(t, x.c, target, "")
		if code != http.StatusServiceUnavailable || !strings.Contains(string(body), "MARKER") {
			t.Errorf("%s: %d %s", target, code, body)
		}
	}
	if n := len(x.fake.Requests()); n != 2 {
		t.Errorf("%d requests recorded, want 2", n)
	}
	page := newIAMAPIFixture(t, kubetest.WithIAMAPIAnswer(0, `{"nextPageToken":"same"}`))
	if code, body := fedGet(t, page.c, providersURL(page.fake, fedPool, "", ""), ""); code != http.StatusOK || string(body) != `{"nextPageToken":"same"}` {
		t.Errorf("a 0 code: %d %s, want 200 with the body as given", code, body)
	}
}

// TestStartFederationIsNewFederationForTheRehearsal: StartFederation runs
// without a testing.TB; Close stops all three fakes and may be called again.
func TestStartFederationIsNewFederationForTheRehearsal(t *testing.T) {
	f, err := kubetest.StartFederation()
	if err != nil {
		t.Fatal(err)
	}
	addrs := []string{f.STSAddr(), f.IAMAddr(), f.IAMAPIAddr()}
	for _, a := range addrs {
		if !strings.HasPrefix(a, "127.0.0.1:") {
			t.Errorf("a fake listens on %s, not on 127.0.0.1", a)
		}
	}
	if code, _ := fedGet(t, fedHTTP(f, nil, nil, tls.VersionTLS12), providersURL(f, fedPool, "", ""), ""); code != http.StatusUnauthorized {
		t.Errorf("the IAM API fake: %d, want 401", code)
	}
	f.Close()
	f.Close()
	for _, a := range addrs {
		if c, err := net.DialTimeout("tcp", a, time.Second); err == nil {
			_ = c.Close()
			t.Errorf("%s still accepts connections after Close", a)
		}
	}
}

// TestWithFederationTakesClusterScopedServiceAccountTokens: a Server given
// WithFederation authenticates a live service-account token the IAM
// Credentials fake minted with kube.ScopesCluster's scopes as its account:
// WithRBAC on that email decides, a 403 names it, Request.As and WithAccess
// see WithFederatedIdentity's id for it, or the email without one. Storage-
// and registry-scoped tokens, a federated token and a server without the
// option are 401; the server's own 2LO tokens work beside it.
func TestWithFederationTakesClusterScopedServiceAccountTokens(t *testing.T) {
	fake := kubetest.NewFederation(t)
	r := newFedRole(t)
	aud := fedAddRole(t, fake, "provreader1", r, r.id)
	fake.Bind(r.id, fedSA)
	fake.Bind(r.id, fedOtherSA)
	var mu sync.Mutex
	var accessIDs []string
	f := newFixture(t,
		kubetest.WithFederation(fake),
		kubetest.WithFederatedIdentity("reader", fedSA),
		kubetest.WithRBAC(fedSA, readerRBAC(fedSA, "web")),
		kubetest.WithAccess(func(id string, _ kube.ResourceAttributes) bool {
			mu.Lock()
			defer mu.Unlock()
			accessIDs = append(accessIDs, id)
			return id == "reader"
		}))
	f.s.Put(pod("web", "p", nil, "app"))
	cluster := fedSAToken(t, fake, r, aud, fedSA, kube.ScopesCluster)
	unlabelled := fedSAToken(t, fake, r, aud, fedOtherSA, kube.ScopesCluster)
	twoLegged := f.mint(f.s.Credential("writer"))
	for _, row := range []struct {
		name, path, token string
		code              int
		as                string
	}{
		{"the namespaces, granted", "/api/v1/namespaces", cluster, http.StatusOK, "reader"},
		{"web's pods, granted", "/api/v1/namespaces/web/pods", cluster, http.StatusOK, "reader"},
		{"kube-system's pods, not granted", "/api/v1/namespaces/kube-system/pods", cluster, http.StatusForbidden, "reader"},
		{"a storage-scoped token", "/api/v1/namespaces", fedSAToken(t, fake, r, aud, fedSA, kube.ScopesStorage), http.StatusUnauthorized, "?"},
		{"a registry-scoped token", "/api/v1/namespaces", fedSAToken(t, fake, r, aud, fedSA, kube.ScopesRegistry), http.StatusUnauthorized, "?"},
		{"a federated token", "/api/v1/namespaces", fedFederatedToken(t, fake, r, aud), http.StatusUnauthorized, "?"},
		{"an account with no label or RBAC", "/api/v1/namespaces/kube-system/pods", unlabelled, http.StatusOK, fedOtherSA},
		{"the server's own 2LO token", "/api/v1/namespaces", twoLegged, http.StatusOK, "writer"},
	} {
		a := f.get(row.path, row.token)
		if a.code != row.code {
			t.Errorf("%s: %d, want %d: %s", row.name, a.code, row.code, a.body)
		}
		if got := f.lastRequest().As; got != row.as {
			t.Errorf("%s: As %q, want %q", row.name, got, row.as)
		}
		if row.code == http.StatusForbidden {
			if st := status(t, a); !strings.Contains(st.Message, `User "`+fedSA+`"`) {
				t.Errorf("%s: the 403 does not name the account: %q", row.name, st.Message)
			}
		}
	}
	review := []byte(`{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"namespace":"web","verb":"get","resource":"pods"}}}`)
	wantCode(t, f.send(call{method: http.MethodPost, path: "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", token: cluster, contentType: "application/json", body: review}), http.StatusCreated)
	mu.Lock()
	if !slices.Equal(accessIDs, []string{"reader"}) {
		t.Errorf("WithAccess saw %q, want the label", accessIDs)
	}
	mu.Unlock()

	plain := newFixture(t)
	wantCode(t, plain.get("/api/v1/namespaces", cluster), http.StatusUnauthorized)
	if as := plain.lastRequest().As; as != "?" {
		t.Errorf("a server without WithFederation recorded As %q", as)
	}
	for _, opt := range []kubetest.Option{kubetest.WithFederatedIdentity("", fedSA), kubetest.WithFederatedIdentity("reader", "")} {
		if s, err := kubetest.Start(opt); err == nil {
			s.Close()
			t.Error("Start took a WithFederatedIdentity with an empty part")
		}
	}
}

// TestFakesRefuseAnExpiredServiceAccountToken: a service-account token past
// its expiry is not live. WithServiceAccountTokenLifetime gives the IAM
// Credentials fake's tokens a lifetime; with one already over, the IAM API
// fake and a Server given WithFederation answer the token 401, recorded as
// "?", as they answer one never issued. The same requests with a token that
// lives an hour are answered 200, as the account.
func TestFakesRefuseAnExpiredServiceAccountToken(t *testing.T) {
	for _, c := range []struct {
		name          string
		life          time.Duration
		code          int
		apiAs, kubeAs string
	}{
		{"an hour", time.Hour, http.StatusOK, fedSA, "reader"},
		{"already over", -time.Minute, http.StatusUnauthorized, "?", "?"},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := newIAMAPIFixture(t, kubetest.WithServiceAccountTokenLifetime(c.life))
			issued := time.Now()
			tok := fedSAToken(t, x.fake, x.r, x.aud, fedSA, kube.ScopesCluster)
			sas := x.fake.ServiceAccountTokens()
			if len(sas) != 1 || sas[0].Expires.Sub(issued) < c.life || sas[0].Expires.Sub(issued) > c.life+time.Minute {
				t.Fatalf("the registry holds %+v; want one token expiring %s after it was issued", sas, c.life)
			}

			code, _ := fedGet(t, x.c, providersURL(x.fake, fedPool, "provreader1", ""), tok)
			reqs := x.fake.Requests()
			if code != c.code || reqs[len(reqs)-1].Server != "iamapi" || reqs[len(reqs)-1].As != c.apiAs {
				t.Errorf("the IAM API fake: %d as %q, want %d as %q", code, reqs[len(reqs)-1].As, c.code, c.apiAs)
			}

			f := newFixture(t,
				kubetest.WithFederation(x.fake),
				kubetest.WithFederatedIdentity("reader", fedSA),
				kubetest.WithRBAC(fedSA, readerRBAC(fedSA, "web")))
			wantCode(t, f.get("/api/v1/namespaces", tok), c.code)
			if as := f.lastRequest().As; as != c.kubeAs {
				t.Errorf("the cluster fake recorded As %q, want %q", as, c.kubeAs)
			}
		})
	}
}
