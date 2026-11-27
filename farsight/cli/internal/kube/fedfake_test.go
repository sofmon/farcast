package kube

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// fedFake is three loopback TLS servers standing for STS, IAM Credentials and
// IAM's API, each on an address of its own, and a cluster API server, for
// package kube's own tests of the federated credential, RoleTokens and the
// IAM reader. (kube's white-box tests cannot import kubetest, which imports
// kube; the wire tests in package kube_test use kubetest's fakes.)
//
// STS issues "fed-<n>" for any form; IAM Credentials issues "sa-<n>" for a
// federated token STS issued and not revoked, with the body's scopes; IAM's
// API and the cluster take only a service-account token it issued, IAM's
// API one holding cloud-platform, the cluster one with exactly the cluster's
// scopes. Every server asks for a client certificate (RequestClientCert), so
// one a client sent is recorded. No token value is recorded in a request.
type fedFake struct {
	sts, iam, api, cluster *httptest.Server
	roots                  *x509.CertPool
	clusterCAPEM           []byte

	mu        sync.Mutex
	n         int
	federated map[string]bool     // issued, not revoked
	sa        map[string][]string // issued service-account token → its scopes
	reqs      []fedFakeRequest

	// The knobs, set before the servers are used or under mu.
	expiresIn   int           // STS's expires_in; 3599
	saLife      time.Duration // IAM Credentials' token lifetime; 1 h
	iamStatus   []int         // the next IAM Credentials answers' statuses, consumed first
	apiStatus   []int         // the next IAM API answers' statuses, consumed first
	clusterFail []int         // the next cluster answers' statuses, consumed first
	apiAnswer   func(r *http.Request) (int, string)
}

// fedFakeRequest is one request a fake server saw.
type fedFakeRequest struct {
	server  string // "sts", "iam", "api" or "cluster"
	method  string
	path    string
	query   string
	headers []string // the header names, sorted
	certs   int      // how many certificates the connection presented
	bearer  string   // "fed", "sa" or "" (which kind of token, never its value)
	body    string   // IAM Credentials' body (no secret in it)
}

func newFedFake(t *testing.T) *fedFake {
	t.Helper()
	f := &fedFake{federated: map[string]bool{}, sa: map[string][]string{}, expiresIn: 3599, saLife: time.Hour}
	start := func(h http.HandlerFunc) *httptest.Server {
		srv := httptest.NewUnstartedServer(h)
		srv.Config.ErrorLog = log.New(io.Discard, "", 0)
		srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
		srv.StartTLS()
		t.Cleanup(srv.Close)
		return srv
	}
	f.sts = start(f.serveSTS)
	f.iam = start(f.serveIAM)
	f.api = start(f.serveAPI)
	f.cluster = start(f.serveCluster)
	f.roots = x509.NewCertPool()
	f.roots.AddCert(f.sts.Certificate())
	f.clusterCAPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.cluster.Certificate().Raw})
	return f
}

// federation is a loopback Federation pointed at the fake's three servers.
func (f *fedFake) federation(t *testing.T) *Federation {
	t.Helper()
	fed, err := NewLoopbackFederation(f.sts.Listener.Addr().String(), f.iam.Listener.Addr().String(), f.api.Listener.Addr().String(), f.roots)
	if err != nil {
		t.Fatal(err)
	}
	return fed
}

// endpoint is the cluster server's loopback Endpoint.
func (f *fedFake) endpoint(t *testing.T) Endpoint {
	t.Helper()
	ep, err := ParseEndpoint(f.cluster.Listener.Addr().String(), "", f.clusterCAPEM)
	if err != nil {
		t.Fatal(err)
	}
	return ep
}

// credential is a federated credential of role for the fake, with a fresh
// device leaf.
func (f *fedFake) credential(t *testing.T, role Identity) Credential {
	t.Helper()
	id := newFedIdentity(t, fedHexID)
	cred, err := NewFederatedCredential(f.federation(t), fedAudience, NewClientIdentity([][]byte{id.leafDER}, id.key), fedEmail, role)
	if err != nil {
		t.Fatal(err)
	}
	return cred
}

// record notes one request; the caller holds no lock.
func (f *fedFake) record(server string, r *http.Request, bearer, body string) {
	names := make([]string, 0, len(r.Header))
	for k := range r.Header {
		if k == "Accept-Encoding" || k == "Content-Length" || k == "Connection" {
			continue
		}
		names = append(names, k)
	}
	slices.Sort(names)
	certs := 0
	if r.TLS != nil {
		certs = len(r.TLS.PeerCertificates)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, fedFakeRequest{server: server, method: r.Method, path: r.URL.Path, query: r.URL.RawQuery, headers: names, certs: certs, bearer: bearer, body: body})
}

// bearerKind is which kind of token a request's bearer is, under mu.
func (f *fedFake) bearerKind(r *http.Request) (string, string) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return "", ""
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case f.federated[tok]:
		return "fed", tok
	case f.sa[tok] != nil:
		return "sa", tok
	}
	return "?", tok
}

// popStatus pops the first status of q, or 0.
func popStatus(q *[]int) int {
	if len(*q) == 0 {
		return 0
	}
	c := (*q)[0]
	*q = (*q)[1:]
	return c
}

func (f *fedFake) serveSTS(w http.ResponseWriter, r *http.Request) {
	kind, _ := f.bearerKind(r)
	f.record("sts", r, kind, "")
	if r.Method != http.MethodPost || r.URL.Path != STSTokenPath || r.ParseForm() != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.n++
	tok := fmt.Sprintf("fed-%d", f.n)
	f.federated[tok] = true
	expiresIn := f.expiresIn
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"access_token":%q,"issued_token_type":%q,"token_type":"Bearer","expires_in":%d}`, tok, TokenTypeAccessToken, expiresIn)
}

func (f *fedFake) serveIAM(w http.ResponseWriter, r *http.Request) {
	kind, _ := f.bearerKind(r)
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	f.record("iam", r, kind, string(body))
	f.mu.Lock()
	status := popStatus(&f.iamStatus)
	f.mu.Unlock()
	switch {
	case status != 0:
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"error":{"code":0,"message":"`+fedPlanted+`","status":"UNAUTHENTICATED"}}`)
		return
	case kind != "fed":
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":{"code":401,"message":"`+fedPlanted+`","status":"UNAUTHENTICATED"}}`)
		return
	}
	var m struct {
		Scope []string `json:"scope"`
	}
	if json.Unmarshal(body, &m) != nil || len(m.Scope) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.n++
	tok := fmt.Sprintf("sa-%d", f.n)
	f.sa[tok] = m.Scope
	life := f.saLife
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"accessToken":%q,"expireTime":%q}`, tok, time.Now().UTC().Add(life).Format(time.RFC3339Nano))
}

func (f *fedFake) serveAPI(w http.ResponseWriter, r *http.Request) {
	kind, tok := f.bearerKind(r)
	f.record("api", r, kind, "")
	f.mu.Lock()
	status := popStatus(&f.apiStatus)
	scopes := f.sa[tok]
	var code int
	var body string
	if f.apiAnswer != nil && status == 0 && kind == "sa" && slices.Contains(scopes, ScopeCloudPlatform) {
		code, body = f.apiAnswer(r) // under the lock, so an answer may keep state
	}
	f.mu.Unlock()
	switch {
	case status != 0:
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"error":{"code":0,"message":"`+fedPlanted+`","status":"UNAUTHENTICATED"}}`)
		return
	case kind != "sa":
		w.WriteHeader(http.StatusUnauthorized)
		return
	case !slices.Contains(scopes, ScopeCloudPlatform):
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"error":{"code":403,"message":"`+fedPlanted+`","status":"PERMISSION_DENIED"}}`)
		return
	case code != 0:
		w.WriteHeader(code)
		_, _ = io.WriteString(w, body)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{}`)
}

func (f *fedFake) serveCluster(w http.ResponseWriter, r *http.Request) {
	kind, tok := f.bearerKind(r)
	f.record("cluster", r, kind, "")
	f.mu.Lock()
	status := popStatus(&f.clusterFail)
	scopes := f.sa[tok]
	f.mu.Unlock()
	switch {
	case status != 0:
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","code":401,"reason":"Unauthorized"}`)
		return
	case kind != "sa" || strings.Join(scopes, " ") != strings.Join(TokenScopes(), " "):
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","code":401,"reason":"Unauthorized"}`)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"kind":"NamespaceList","apiVersion":"v1","metadata":{},"items":[{"metadata":{"name":"default"}}]}`)
}

// set changes the fake's knobs under its lock.
func (f *fedFake) set(edit func(*fedFake)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	edit(f)
}

// revokeFederated makes every federated token issued so far unknown, so IAM
// Credentials answers 401 to it.
func (f *fedFake) revokeFederated() {
	f.mu.Lock()
	defer f.mu.Unlock()
	clear(f.federated)
}

// requests are the requests one server saw, in order.
func (f *fedFake) requests(server string) []fedFakeRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []fedFakeRequest
	for _, r := range f.reqs {
		if r.server == server {
			out = append(out, r)
		}
	}
	return out
}

// impersonationBodies are IAM Credentials' bodies, in order.
func (f *fedFake) impersonationBodies() []string {
	var out []string
	for _, r := range f.requests("iam") {
		out = append(out, r.body)
	}
	return out
}
