package kubetest_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
	tkube "github.com/sofmon/farcast/technocore/kube"
)

const (
	jwtBearer   = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	formType    = "application/x-www-form-urlencoded"
	applyType   = "application/apply-patch+yaml"
	jsonPatch   = "application/json-patch+json"
	applyQuery  = "?fieldManager=farcast&fieldValidation=Strict&force=true"
	partialList = "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1"
	partialOne  = "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1"
	lastApplied = "kubectl.kubernetes.io/last-applied-configuration"
)

// ---- the test client -------------------------------------------------------

type fixture struct {
	t  *testing.T
	s  *kubetest.Server
	hc *http.Client
}

func newFixture(t *testing.T, opts ...kubetest.Option) *fixture {
	t.Helper()
	s := kubetest.New(t, opts...)
	return &fixture{t: t, s: s, hc: clientFor(t, s, false)}
}

// clientFor trusts the server's own CA only. http1 forces HTTP/1.1, where a
// streamed body is visibly chunked.
func clientFor(t *testing.T, s *kubetest.Server, http1 bool) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(s.CAPEM()) {
		t.Fatal("CAPEM holds no certificate")
	}
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: !http1,
	}
	if http1 {
		p := new(http.Protocols)
		p.SetHTTP1(true)
		tr.Protocols = p
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr}
}

type call struct {
	ctx                                      context.Context
	method, path, token, contentType, accept string
	authorization                            string // a raw Authorization header, instead of token
	body                                     []byte
}

type answer struct {
	code   int
	header http.Header
	body   []byte
	proto  int
	te     []string
}

func (f *fixture) send(c call) answer {
	f.t.Helper()
	a, err := f.try(c)
	if err != nil {
		f.t.Fatalf("%s %s: %v", c.method, c.path, err)
	}
	return a
}

func (f *fixture) try(c call) (answer, error) {
	ctx := c.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	var body io.Reader
	if c.body != nil {
		body = bytes.NewReader(c.body)
	}
	req, err := http.NewRequestWithContext(ctx, c.method, "https://"+f.s.Endpoint()+c.path, body)
	if err != nil {
		return answer{}, err
	}
	req.Header.Set("User-Agent", "farcast")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.authorization != "" {
		req.Header.Set("Authorization", c.authorization)
	}
	if c.contentType != "" {
		req.Header.Set("Content-Type", c.contentType)
	}
	if c.accept != "" {
		req.Header.Set("Accept", c.accept)
	}
	resp, err := f.hc.Do(req)
	if err != nil {
		return answer{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return answer{}, err
	}
	return answer{code: resp.StatusCode, header: resp.Header, body: b, proto: resp.ProtoMajor, te: resp.TransferEncoding}, nil
}

func (f *fixture) get(path, token string) answer {
	f.t.Helper()
	return f.send(call{method: http.MethodGet, path: path, token: token})
}

func (f *fixture) apply(path, token, doc string) answer {
	f.t.Helper()
	return f.send(call{method: http.MethodPatch, path: path + applyQuery, token: token, contentType: applyType, body: []byte(doc)})
}

func (f *fixture) patchJSON(path, token string, ops any) answer {
	f.t.Helper()
	b, err := json.Marshal(ops)
	if err != nil {
		f.t.Fatal(err)
	}
	return f.send(call{method: http.MethodPatch, path: path + "?fieldManager=farcast&fieldValidation=Strict", token: token, contentType: jsonPatch, body: b})
}

func (f *fixture) lastRequest() kubetest.Request {
	f.t.Helper()
	reqs := f.s.Requests()
	if len(reqs) == 0 {
		f.t.Fatal("the server recorded no request")
	}
	return reqs[len(reqs)-1]
}

func object(t *testing.T, a answer) map[string]any {
	t.Helper()
	var m map[string]any
	d := json.NewDecoder(bytes.NewReader(a.body))
	d.UseNumber()
	if err := d.Decode(&m); err != nil {
		t.Fatalf("answer %d is not a JSON object: %v: %s", a.code, err, a.body)
	}
	return m
}

func status(t *testing.T, a answer) kube.Status {
	t.Helper()
	var st kube.Status
	if err := json.Unmarshal(a.body, &st); err != nil {
		t.Fatalf("answer %d is not JSON: %v: %s", a.code, err, a.body)
	}
	if st.Kind != "Status" {
		t.Fatalf("answer %d is not a Status: %s", a.code, a.body)
	}
	return st
}

func wantCode(t *testing.T, a answer, code int) {
	t.Helper()
	if a.code != code {
		t.Fatalf("answer = %d, want %d: %s", a.code, code, a.body)
	}
}

func wantStatus(t *testing.T, a answer, code int, reason string) kube.Status {
	t.Helper()
	wantCode(t, a, code)
	st := status(t, a)
	if st.Code != code || st.Reason != reason || object(t, a)["apiVersion"] != "v1" {
		t.Fatalf("Status = %+v, want apiVersion v1, code %d, reason %s: %s", st, code, reason, a.body)
	}
	return st
}

func metaOf(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	md, ok := m["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("no metadata in %v", m)
	}
	return md
}

func get(m map[string]any, path ...string) any {
	var v any = m
	for _, p := range path {
		mm, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = mm[p]
	}
	return v
}

// ---- tokens ----------------------------------------------------------------

type claims map[string]any

func privateKey(t *testing.T, c kube.Credential) *rsa.PrivateKey {
	t.Helper()
	block, _ := pem.Decode(c.PrivateKeyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("the credential's key is not a PRIVATE KEY block")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse the credential's key: %v", err)
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("the credential's key is %T, not RSA", k)
	}
	return rk
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// sign builds a JWS the way the vendored encoder does: base64url header and
// claims, signed with RS256.
func sign(t *testing.T, key *rsa.PrivateKey, header map[string]any, c claims) string {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	cl, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	signing := b64(h) + "." + b64(cl)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + b64(sig)
}

func goodHeader(c kube.Credential) map[string]any {
	return map[string]any{"alg": "RS256", "typ": "JWT", "kid": c.PrivateKeyID}
}

// goodClaims are what the vendored encoder sends: iat now − 10 s, exp iat + 3600.
func goodClaims(s *kubetest.Server, c kube.Credential) claims {
	iat := time.Now().Add(-10 * time.Second).Unix()
	return claims{"iss": c.Email, "scope": kube.ScopeUserinfoEmail, "aud": "https://" + s.Endpoint() + "/token", "iat": iat, "exp": iat + 3600}
}

func (f *fixture) tokenForm(form url.Values) answer {
	f.t.Helper()
	return f.send(call{method: http.MethodPost, path: "/token", contentType: formType, body: []byte(form.Encode())})
}

func (f *fixture) tokenRequest(assertion string) answer {
	f.t.Helper()
	return f.tokenForm(url.Values{"grant_type": {jwtBearer}, "assertion": {assertion}})
}

func (f *fixture) mint(c kube.Credential) string {
	f.t.Helper()
	a := f.tokenRequest(sign(f.t, privateKey(f.t, c), goodHeader(c), goodClaims(f.s, c)))
	wantCode(f.t, a, http.StatusOK)
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(a.body, &tok); err != nil || tok.AccessToken == "" {
		f.t.Fatalf("the token answer carries no access_token: %s", a.body)
	}
	return tok.AccessToken
}

// ---- documents -------------------------------------------------------------

func deploymentDoc(name, ns string, replicas int) string {
	return fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: %s
  namespace: %s
  labels:
    app.kubernetes.io/managed-by: farcast
spec:
  replicas: %d
  selector:
    matchLabels:
      app: %s
  template:
    metadata:
      labels:
        app: %s
    spec:
      containers:
      - name: app
        image: example.invalid/app:1
`, name, ns, replicas, name, name)
}

func configMap(ns, name string, data map[string]string) map[string]any {
	d := map[string]any{}
	for k, v := range data {
		d[k] = v
	}
	return map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": name, "namespace": ns}, "data": d}
}

func pod(ns, name string, annotations map[string]string, containers ...string) map[string]any {
	var cs []any
	for _, c := range containers {
		cs = append(cs, map[string]any{"name": c})
	}
	ann := map[string]any{}
	for k, v := range annotations {
		ann[k] = v
	}
	return map[string]any{"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": name, "namespace": ns, "annotations": ann},
		"spec":     map[string]any{"containers": cs}}
}

// =============================================================================

// TestNewServesTLSOnLoopbackWithItsOwnCA: the server listens on 127.0.0.1,
// behind a P-256 CA of its own whose leaf names exactly IP 127.0.0.1, and its
// endpoint and CA pair in kube's loopback mode with the token URL its aud rule
// expects.
func TestNewServesTLSOnLoopbackWithItsOwnCA(t *testing.T) {
	s := kubetest.New(t)
	host, port, err := net.SplitHostPort(s.Endpoint())
	if err != nil || host != "127.0.0.1" {
		t.Fatalf("Endpoint() = %q, want 127.0.0.1:<port>", s.Endpoint())
	}
	if p, err := strconv.Atoi(port); err != nil || p <= 0 {
		t.Fatalf("Endpoint() = %q names no port", s.Endpoint())
	}

	block, rest := pem.Decode(s.CAPEM())
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("CAPEM() is not one CERTIFICATE block")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.IsCA || !ca.BasicConstraintsValid {
		t.Error("the CA certificate is not a CA")
	}
	if pub, ok := ca.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		t.Errorf("the CA key is %T, want ECDSA P-256", ca.PublicKey)
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca)
	conn, err := tls.Dial("tcp", s.Endpoint(), &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("a client trusting CAPEM alone does not connect: %v", err)
	}
	leaf := conn.ConnectionState().PeerCertificates[0]
	_ = conn.Close()
	if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.IPv4(127, 0, 0, 1)) || len(leaf.DNSNames) != 0 {
		t.Errorf("the leaf names IPs %v and names %v, want exactly 127.0.0.1", leaf.IPAddresses, leaf.DNSNames)
	}
	if pub, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		t.Errorf("the leaf key is %T, want ECDSA P-256", leaf.PublicKey)
	}

	if c, err := tls.Dial("tcp", s.Endpoint(), &tls.Config{MinVersion: tls.VersionTLS12}); err == nil {
		_ = c.Close()
		t.Error("a client on the system roots verified the server; it must trust only its own CA")
	}
	if c, err := tls.Dial("tcp", s.Endpoint(), &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}); err == nil {
		_ = c.Close()
		t.Error("the leaf verified for the name localhost")
	}

	ep, err := kube.ParseEndpoint(s.Endpoint(), "rehearsal-local", s.CAPEM())
	if err != nil {
		t.Fatalf("kube.ParseEndpoint refuses the server's endpoint and CA: %v", err)
	}
	if ep.Mode != kube.ModeLoopback || ep.TokenURL() != "https://"+s.Endpoint()+"/token" {
		t.Errorf("the endpoint parses to mode %v, token URL %s", ep.Mode, ep.TokenURL())
	}
}

// TestStartIsNewForTheRehearsal: Start runs without a testing.TB, Close stops
// it, and Close may be called again.
func TestStartIsNewForTheRehearsal(t *testing.T) {
	s, err := kubetest.Start()
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, s: s, hc: clientFor(t, s, false)}
	wantCode(t, f.get("/api/v1/namespaces", ""), http.StatusUnauthorized)
	s.Close()
	s.Close()
	if c, err := net.DialTimeout("tcp", s.Endpoint(), time.Second); err == nil {
		_ = c.Close()
		t.Error("the server still accepts connections after Close")
	}
}

// TestWithAddrListensWhereTheRecordSays: a restart on the recorded endpoint
// gets that endpoint, and nothing but a loopback IP literal with a port is
// accepted.
func TestWithAddrListensWhereTheRecordSays(t *testing.T) {
	first, err := kubetest.Start()
	if err != nil {
		t.Fatal(err)
	}
	ep := first.Endpoint()
	first.Close()
	second, err := kubetest.Start(kubetest.WithAddr(ep))
	if err != nil {
		t.Fatalf("restart on %s: %v", ep, err)
	}
	defer second.Close()
	if second.Endpoint() != ep {
		t.Errorf("restarted Endpoint() = %s, want %s", second.Endpoint(), ep)
	}

	for _, addr := range []string{"0.0.0.0:0", "localhost:0", "10.0.0.5:443", "[::ffff:127.0.0.1]:0", "127.0.0.1", "[fe80::1%lo0]:0", "127.0.0.1:x", "[::]:0"} {
		if s, err := kubetest.Start(kubetest.WithAddr(addr)); err == nil {
			s.Close()
			t.Errorf("WithAddr(%q) started; only a loopback IP literal with a port may", addr)
		}
	}

	six, err := kubetest.Start(kubetest.WithAddr("[::1]:0"))
	if err != nil {
		t.Logf("no IPv6 loopback here: %v", err)
		return
	}
	defer six.Close()
	if !strings.HasPrefix(six.Endpoint(), "[::1]:") {
		t.Errorf("Endpoint() = %s, want [::1]:<port>", six.Endpoint())
	}
	f := &fixture{t: t, s: six, hc: clientFor(t, six, false)}
	c := six.Credential("reader")
	f.mint(c) // the aud rule uses the bracketed endpoint
}

// TestTokenMintsForAVerifiedAssertion: a good assertion mints
// kubetest:<id>:<n>, and the /token request records the identity and the kid.
func TestTokenMintsForAVerifiedAssertion(t *testing.T) {
	f := newFixture(t)
	c := f.s.Credential("reader")
	a := f.tokenRequest(sign(t, privateKey(t, c), goodHeader(c), goodClaims(f.s, c)))
	wantCode(t, a, http.StatusOK)
	if got, want := string(a.body), `{"access_token":"kubetest:reader:1","token_type":"Bearer","expires_in":3600}`; got != want {
		t.Errorf("token answer = %s, want %s", got, want)
	}
	if ct := a.header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("token answer Content-Type = %q", ct)
	}
	r := f.lastRequest()
	if r.Method != http.MethodPost || r.Path != "/token" || r.As != "reader" || r.KeyID != c.PrivateKeyID || r.ContentType != formType {
		t.Errorf("the /token request is recorded as %+v", r)
	}
	if tok := f.mint(c); tok != "kubetest:reader:2" {
		t.Errorf("second token = %s, want kubetest:reader:2", tok)
	}
	wantCode(t, f.get("/api/v1/namespaces", "kubetest:reader:1"), http.StatusOK)
	if r := f.lastRequest(); r.As != "reader" || r.KeyID != "" {
		t.Errorf("an API request with the token is recorded As %q KeyID %q", r.As, r.KeyID)
	}
}

// TestTokenRefusesEveryOtherAssertion: each /token rule refuses on its own.
func TestTokenRefusesEveryOtherAssertion(t *testing.T) {
	f := newFixture(t)
	c := f.s.Credential("reader")
	key := privateKey(t, c)
	stranger, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	type row struct {
		name        string
		header      func(map[string]any)
		claims      func(claims)
		signer      *rsa.PrivateKey
		form        func(url.Values)
		contentType string
	}
	rows := []row{
		{name: "another grant_type", form: func(v url.Values) { v.Set("grant_type", "client_credentials") }},
		{name: "no grant_type", form: func(v url.Values) { v.Del("grant_type") }},
		{name: "no assertion", form: func(v url.Values) { v.Del("assertion") }},
		{name: "two assertions", form: func(v url.Values) { v.Add("assertion", v.Get("assertion")) }},
		{name: "not form-encoded", contentType: "application/json"},
		{name: "alg none", header: func(h map[string]any) { h["alg"] = "none" }},
		{name: "alg HS256", header: func(h map[string]any) { h["alg"] = "HS256" }},
		{name: "an unregistered iss", claims: func(c claims) { c["iss"] = "stranger@kubetest.invalid" }},
		{name: "signed by an unregistered key", signer: stranger},
		{name: "aud is Google's", claims: func(c claims) { c["aud"] = kube.GoogleTokenURL }},
		{name: "aud without its port", claims: func(c claims) { c["aud"] = "https://127.0.0.1/token" }},
		{name: "no aud", claims: func(c claims) { delete(c, "aud") }},
		{name: "cloud-platform added to the scope", claims: func(c claims) {
			c["scope"] = kube.ScopeUserinfoEmail + " https://www.googleapis.com/auth/cloud-platform"
		}},
		{name: "cloud-platform alone", claims: func(c claims) { c["scope"] = "https://www.googleapis.com/auth/cloud-platform" }},
		{name: "no scope", claims: func(c claims) { delete(c, "scope") }},
		{name: "no iat", claims: func(c claims) { delete(c, "iat") }},
		{name: "no exp", claims: func(c claims) { delete(c, "exp") }},
		{name: "iat a string", claims: func(c claims) { c["iat"] = strconv.FormatInt(now, 10) }},
		{name: "exp − iat is 3610", claims: func(c claims) { c["iat"] = now - 10; c["exp"] = now + 3600 }},
		{name: "exp equals iat", claims: func(c claims) { c["exp"] = c["iat"] }},
		{name: "exp before iat", claims: func(c claims) { c["exp"] = now - 100 }},
		{name: "iat six minutes ago", claims: func(c claims) { c["iat"] = now - 360; c["exp"] = now - 360 + 3600 }},
		{name: "iat six minutes ahead", claims: func(c claims) { c["iat"] = now + 360; c["exp"] = now + 360 + 3600 }},
		{name: "not three parts", form: func(v url.Values) { v.Set("assertion", "a.b") }},
		{name: "not base64url", form: func(v url.Values) { v.Set("assertion", "!!.!!.!!") }},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			h, cl := goodHeader(c), goodClaims(f.s, c)
			if r.header != nil {
				r.header(h)
			}
			if r.claims != nil {
				r.claims(cl)
			}
			signer := key
			if r.signer != nil {
				signer = r.signer
			}
			form := url.Values{"grant_type": {jwtBearer}, "assertion": {sign(t, signer, h, cl)}}
			if r.form != nil {
				r.form(form)
			}
			ct := formType
			if r.contentType != "" {
				ct = r.contentType
			}
			a := f.send(call{method: http.MethodPost, path: "/token", contentType: ct, body: []byte(form.Encode())})
			wantCode(t, a, http.StatusBadRequest)
			var e struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(a.body, &e); err != nil || e.Error != "invalid_grant" {
				t.Errorf("refusal body = %s, want error invalid_grant", a.body)
			}
			if got := f.lastRequest().As; got != "" {
				t.Errorf("a refused /token request is recorded As %q", got)
			}
		})
	}

	t.Run("the limits themselves are accepted", func(t *testing.T) {
		cl := goodClaims(f.s, c)
		cl["iat"], cl["exp"] = now-240, now-240+3600
		wantCode(t, f.tokenRequest(sign(t, key, goodHeader(c), cl)), http.StatusOK)
	})
	t.Run("GET is not a token request", func(t *testing.T) {
		wantCode(t, f.get("/token", ""), http.StatusMethodNotAllowed)
	})
}

// TestTokenVerifiesAgainstAnyKeyOfTheEmail: an email may hold several keys,
// at start or added later, and the token is minted for the key that verified.
func TestTokenVerifiesAgainstAnyKeyOfTheEmail(t *testing.T) {
	writerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, kubetest.WithIdentity("writer", "writer@rehearsal.invalid", &writerKey.PublicKey))
	writer := kube.Credential{Email: "writer@rehearsal.invalid", PrivateKeyPEM: pkcs8(t, writerKey)}
	if tok := f.mint(writer); tok != "kubetest:writer:1" {
		t.Errorf("WithIdentity's key mints %s", tok)
	}

	const email = "farcast-reader-0a1b2c3d@kubetest.invalid"
	old := f.s.CredentialFor("old", email)
	next := f.s.CredentialFor("new", email)
	if tok := f.mint(next); tok != "kubetest:new:2" {
		t.Errorf("the second key mints %s, want kubetest:new:2", tok)
	}
	if r := f.lastRequest(); r.As != "new" || r.KeyID != next.PrivateKeyID {
		t.Errorf("the /token request is recorded As %q KeyID %q", r.As, r.KeyID)
	}
	if tok := f.mint(old); tok != "kubetest:old:3" {
		t.Errorf("the first key mints %s, want kubetest:old:3", tok)
	}

	added, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f.s.AddKey("added", email, &added.PublicKey)
	if tok := f.mint(kube.Credential{Email: email, PrivateKeyID: "k", PrivateKeyPEM: pkcs8(t, added)}); tok != "kubetest:added:4" {
		t.Errorf("a key added on the running server mints %s", tok)
	}

	if s, err := kubetest.Start(kubetest.WithIdentity("", "x@kubetest.invalid", &added.PublicKey)); err == nil {
		s.Close()
		t.Error("WithIdentity with no id started")
	}
	if s, err := kubetest.Start(kubetest.WithIdentity("x", "x@kubetest.invalid", nil)); err == nil {
		s.Close()
		t.Error("WithIdentity with no key started")
	}
}

func pkcs8(t *testing.T, k *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// TestWithTokenAnswerSeesOnlyVerifiedAssertions: the closure is keyed by iss,
// runs per request, and sees nothing that failed a rule.
func TestWithTokenAnswerSeesOnlyVerifiedAssertions(t *testing.T) {
	var refuse atomic.Bool
	var mu sync.Mutex
	var seen []string
	f := newFixture(t, kubetest.WithTokenAnswer(func(email string) (int, []byte, bool) {
		mu.Lock()
		seen = append(seen, email)
		mu.Unlock()
		if refuse.Load() {
			return http.StatusBadRequest, []byte(`{"error":"invalid_grant"}`), true
		}
		return 0, nil, false
	}))
	c := f.s.Credential("reader")
	if tok := f.mint(c); tok != "kubetest:reader:1" {
		t.Errorf("an unhandled answer mints %s", tok)
	}
	refuse.Store(true)
	a := f.tokenRequest(sign(t, privateKey(t, c), goodHeader(c), goodClaims(f.s, c)))
	if a.code != http.StatusBadRequest || string(a.body) != `{"error":"invalid_grant"}` {
		t.Errorf("a handled answer = %d %s", a.code, a.body)
	}
	if r := f.lastRequest(); r.As != "reader" {
		t.Errorf("a verified assertion the closure answered is recorded As %q", r.As)
	}
	cl := goodClaims(f.s, c)
	cl["aud"] = kube.GoogleTokenURL
	wantCode(t, f.tokenRequest(sign(t, privateKey(t, c), goodHeader(c), cl)), http.StatusBadRequest)
	mu.Lock()
	defer mu.Unlock()
	if want := []string{c.Email, c.Email}; !slices.Equal(seen, want) {
		t.Errorf("the closure saw %v, want %v", seen, want)
	}
}

// TestAPIRefusesMissingUnknownAndRevokedTokens: every API path needs a live
// token; 401 is a JSON Status.
func TestAPIRefusesMissingUnknownAndRevokedTokens(t *testing.T) {
	f := newFixture(t)
	c := f.s.Credential("reader")
	tok := f.mint(c)
	const path = "/api/v1/namespaces"

	for _, r := range []struct {
		name, authorization, as string
	}{
		{"no header", "", ""},
		{"an unknown token", "Bearer kubetest:reader:999", "?"},
		{"another scheme", "Basic cmVhZGVyOng=", "?"},
		{"an empty bearer", "Bearer ", "?"},
	} {
		a := f.send(call{method: http.MethodGet, path: path, authorization: r.authorization})
		st := wantStatus(t, a, http.StatusUnauthorized, "Unauthorized")
		if st.Message != "Unauthorized" {
			t.Errorf("%s: 401 message = %q", r.name, st.Message)
		}
		if got := f.lastRequest().As; got != r.as {
			t.Errorf("%s: recorded As %q, want %q", r.name, got, r.as)
		}
	}

	wantCode(t, f.get(path, tok), http.StatusOK)
	f.s.Revoke(tok)
	for range 2 {
		wantStatus(t, f.get(path, tok), http.StatusUnauthorized, "Unauthorized")
		if got := f.lastRequest().As; got != "?" {
			t.Errorf("a revoked token is recorded As %q, want ?", got)
		}
	}
	fresh := f.mint(c)
	wantCode(t, f.get(path, fresh), http.StatusOK)
}

// TestWithHandlerSeesAuthorizedRequestsFirst: the handler runs before the
// emulation for authorized API requests only, and per request.
func TestWithHandlerSeesAuthorizedRequestsFirst(t *testing.T) {
	const ledger = "/api/v1/namespaces/farcast-system/configmaps/technocore-ledger"
	var answerIt atomic.Bool
	var calls atomic.Int32
	var lastAs atomic.Value
	f := newFixture(t, kubetest.WithHandler(func(r kubetest.Request) (int, []byte, bool) {
		calls.Add(1)
		lastAs.Store(r.As)
		switch {
		case r.Path == ledger && answerIt.Load():
			return 0, []byte(`{"handled":true}`), true
		case r.Path == "/text":
			return http.StatusTeapot, []byte("plain words"), true
		}
		return 0, nil, false
	}))
	wantCode(t, f.get(ledger, ""), http.StatusUnauthorized)
	c := f.s.Credential("reader")
	tok := f.mint(c)
	if n := calls.Load(); n != 0 {
		t.Fatalf("the handler saw %d requests before an authorized one; it never sees 401s or /token", n)
	}
	wantStatus(t, f.get(ledger, tok), http.StatusNotFound, "NotFound")
	answerIt.Store(true)
	a := f.get(ledger, tok)
	if a.code != http.StatusOK || string(a.body) != `{"handled":true}` || a.header.Get("Content-Type") != "application/json" {
		t.Errorf("a handled answer = %d %q %s", a.code, a.header.Get("Content-Type"), a.body)
	}
	a = f.get("/text", tok)
	if a.code != http.StatusTeapot || string(a.body) != "plain words" || !strings.HasPrefix(a.header.Get("Content-Type"), "text/plain") {
		t.Errorf("a text answer = %d %q %s", a.code, a.header.Get("Content-Type"), a.body)
	}
	if n, as := calls.Load(), lastAs.Load(); n != 3 || as != "reader" {
		t.Errorf("the handler ran %d times, last As %v; want 3, reader", n, as)
	}
}

// TestWithDelayHoldsTheAnswer: a held answer waits for the duration, or ends
// with its client, and /token is held too.
func TestWithDelayHoldsTheAnswer(t *testing.T) {
	var hold atomic.Int64
	f := newFixture(t, kubetest.WithDelay(func(kubetest.Request) time.Duration { return time.Duration(hold.Load()) }))
	c := f.s.Credential("reader")
	tok := f.mint(c)

	hold.Store(int64(10 * time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := f.try(call{ctx: ctx, method: http.MethodGet, path: "/api/v1/namespaces", token: tok}); err == nil {
		t.Fatal("a request held for 10 s answered within its 200 ms deadline")
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("the client waited %v for its own deadline", took)
	}
	if r := f.lastRequest(); r.Path != "/api/v1/namespaces" || r.As != "reader" {
		t.Errorf("the held request is recorded as %+v", r)
	}

	hold.Store(int64(150 * time.Millisecond))
	start = time.Now()
	wantCode(t, f.get("/api/v1/namespaces", tok), http.StatusOK)
	if took := time.Since(start); took < 150*time.Millisecond {
		t.Errorf("an answer held for 150 ms came after %v", took)
	}
	start = time.Now()
	f.mint(c)
	if took := time.Since(start); took < 150*time.Millisecond {
		t.Errorf("a /token answer held for 150 ms came after %v", took)
	}

	// D-D-1: the hold ends when the request's context does, so a request
	// abandoned during it changes nothing, even once the hold would have run
	// out, and Close does not wait the hold out.
	t.Run("an apply abandoned during its hold changes nothing", func(t *testing.T) {
		g := newFixture(t, kubetest.WithDelay(func(r kubetest.Request) time.Duration {
			if r.Method == http.MethodPatch {
				return 500 * time.Millisecond
			}
			return 0
		}))
		tok := g.mint(g.s.Credential("writer"))
		const path = "/apis/apps/v1/namespaces/web/deployments/web"
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		if _, err := g.try(call{ctx: ctx, method: http.MethodPatch, path: path + applyQuery, token: tok, contentType: applyType,
			body: []byte(deploymentDoc("web", "web", 1))}); err == nil {
			t.Fatal("an apply held for 500 ms answered within its 100 ms deadline")
		}
		time.Sleep(800 * time.Millisecond) // past the hold
		wantCode(t, g.get(path, tok), http.StatusNotFound)
	})
	t.Run("Close does not wait out an abandoned hold", func(t *testing.T) {
		g := newFixture(t, kubetest.WithDelay(func(r kubetest.Request) time.Duration {
			if r.Path == "/token" {
				return 0
			}
			return 10 * time.Second
		}))
		tok := g.mint(g.s.Credential("reader"))
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		if _, err := g.try(call{ctx: ctx, method: http.MethodGet, path: "/api/v1/namespaces", token: tok}); err == nil {
			t.Fatal("a request held for 10 s answered within its 100 ms deadline")
		}
		start := time.Now()
		g.s.Close()
		if took := time.Since(start); took > 3*time.Second {
			t.Errorf("Close took %v: it waited out a 10 s hold", took)
		}
	})
}

// TestSelfSubjectAccessReviewsAnswerFromWithAccess: reviews answer allowed
// from WithAccess by the caller's id, and false without it.
func TestSelfSubjectAccessReviewsAnswerFromWithAccess(t *testing.T) {
	const path = "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
	review := func(ns, verb, group, resource, sub, name string) []byte {
		return []byte(fmt.Sprintf(`{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"namespace":%q,"verb":%q,"group":%q,"resource":%q,"subresource":%q,"name":%q}}}`,
			ns, verb, group, resource, sub, name))
	}
	allowed := func(t *testing.T, a answer) bool {
		t.Helper()
		wantCode(t, a, http.StatusCreated)
		m := object(t, a)
		if m["kind"] != "SelfSubjectAccessReview" || m["apiVersion"] != "authorization.k8s.io/v1" {
			t.Errorf("review answer = %s", a.body)
		}
		if get(m, "spec", "resourceAttributes", "verb") == nil {
			t.Errorf("the review answer does not carry its spec: %s", a.body)
		}
		b, ok := get(m, "status", "allowed").(bool)
		if !ok {
			t.Fatalf("status.allowed is not a boolean: %s", a.body)
		}
		return b
	}

	t.Run("without WithAccess", func(t *testing.T) {
		f := newFixture(t)
		tok := f.mint(f.s.Credential("reader"))
		if allowed(t, f.send(call{method: http.MethodPost, path: path, token: tok, contentType: "application/json", body: review("farcast-system", "get", "", "secrets", "", "")})) {
			t.Error("a review answered allowed without WithAccess")
		}
	})

	t.Run("with WithAccess", func(t *testing.T) {
		var got []kube.ResourceAttributes
		var mu sync.Mutex
		f := newFixture(t, kubetest.WithAccess(func(id string, a kube.ResourceAttributes) bool {
			mu.Lock()
			got = append(got, a)
			mu.Unlock()
			return id == "reader" && a == kube.ResourceAttributes{Namespace: "farcast-system", Verb: "patch", Group: "apps", Resource: "deployments", Subresource: "scale", Name: "web"}
		}))
		reader, writer := f.mint(f.s.Credential("reader")), f.mint(f.s.Credential("writer"))
		send := func(tok string, body []byte) answer {
			return f.send(call{method: http.MethodPost, path: path, token: tok, contentType: "application/json", body: body})
		}
		if !allowed(t, send(reader, review("farcast-system", "patch", "apps", "deployments", "scale", "web"))) {
			t.Error("the reader's allowed review answered false")
		}
		if allowed(t, send(reader, review("farcast-system", "get", "", "secrets", "", ""))) {
			t.Error("another review answered true")
		}
		if allowed(t, send(writer, review("farcast-system", "patch", "apps", "deployments", "scale", "web"))) {
			t.Error("the same review answered true for another id")
		}
		wantCode(t, send(reader, []byte(`{"spec":{"nonResourceAttributes":{"path":"/","verb":"get"}}}`)), http.StatusUnprocessableEntity)
		wantCode(t, send(reader, []byte(`not json`)), http.StatusBadRequest)
		mu.Lock()
		defer mu.Unlock()
		if len(got) != 3 || got[0].Subresource != "scale" || got[0].Group != "apps" {
			t.Errorf("WithAccess saw %+v", got)
		}
	})
}

// readerRBAC is §7.2's reader RBAC, as renderReaderRBAC renders it, with one
// RoleBinding per namespace.
func readerRBAC(email string, namespaces ...string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: farcast-reader-namespaces
  labels:
    app.kubernetes.io/managed-by: farcast
    app.kubernetes.io/part-of: farcast-reader
rules:
- apiGroups: [""]
  resources: [namespaces]
  verbs: [list]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: farcast-reader-namespaces
  labels:
    app.kubernetes.io/managed-by: farcast
    app.kubernetes.io/part-of: farcast-reader
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: farcast-reader-namespaces
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: User
  name: %s
---
# A rule set, never bound cluster-wide: each RoleBinding below grants it in one namespace.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: farcast-reader
  labels:
    app.kubernetes.io/managed-by: farcast
    app.kubernetes.io/part-of: farcast-reader
rules:
- apiGroups: [apps]
  resources: [deployments, statefulsets]
  verbs: [get, list]
- apiGroups: [""]
  resources: [pods]
  verbs: [list]
- apiGroups: [""]
  resources: [pods/log]
  verbs: [get]
- apiGroups: [batch]
  resources: [jobs]
  verbs: [get]
- apiGroups: [""]
  resources: [configmaps]
  resourceNames: [technocore-namespaces, technocore-ledger, technocore-profiles,
                  fatline-egress-policy, datasphered-pin]
  verbs: [get]
`, email)
	for _, ns := range namespaces {
		fmt.Fprintf(&b, `---
# One per namespace: farcast-system, and every metered namespace.
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: farcast-reader
  namespace: %s
  labels:
    app.kubernetes.io/managed-by: farcast
    app.kubernetes.io/part-of: farcast-reader
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: farcast-reader
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: User
  name: %s
`, ns, email)
	}
	return []byte(b.String())
}

// TestWithRBACAllowsOnlyWhatTheStreamGrants: the reader RBAC of §7.2 grants
// exactly its rules, in exactly its namespaces; anything else is 403 before
// any object is looked up, so a forbidden read of an absent object is never
// 404. Another identity is unaffected.
func TestWithRBACAllowsOnlyWhatTheStreamGrants(t *testing.T) {
	const email = "farcast-reader-0a1b2c3d@kubetest.invalid"
	var handled atomic.Int32
	f := newFixture(t,
		kubetest.WithRBAC(email, readerRBAC(email, "farcast-system", "web")),
		kubetest.WithHandler(func(kubetest.Request) (int, []byte, bool) { handled.Add(1); return 0, nil, false }))
	reader := f.mint(f.s.CredentialFor("reader", email))
	writer := f.mint(f.s.Credential("writer"))
	f.s.Put(configMap("farcast-system", "technocore-ledger", map[string]string{"k": "v"}))
	f.s.Put(pod("web", "p", map[string]string{kubetest.LogAnnotationPrefix + "app": "hello\n"}, "app"))

	rows := []struct {
		method, path string
		code         int
	}{
		{http.MethodGet, "/api/v1/namespaces", http.StatusOK},
		{http.MethodGet, "/api/v1/namespaces/farcast-system", http.StatusForbidden},
		{http.MethodGet, "/apis/apps/v1/namespaces/farcast-system/deployments", http.StatusOK},
		{http.MethodGet, "/apis/apps/v1/namespaces/farcast-system/deployments/absent", http.StatusNotFound},
		{http.MethodGet, "/apis/apps/v1/namespaces/web/statefulsets", http.StatusOK},
		{http.MethodGet, "/apis/apps/v1/namespaces/kube-system/deployments", http.StatusForbidden},
		{http.MethodGet, "/apis/apps/v1/deployments", http.StatusForbidden},
		{http.MethodGet, "/api/v1/namespaces/farcast-system/configmaps/technocore-ledger", http.StatusOK},
		{http.MethodGet, "/api/v1/namespaces/farcast-system/configmaps/datasphered-pin", http.StatusNotFound},
		{http.MethodGet, "/api/v1/namespaces/farcast-system/configmaps/technocore-confirmed", http.StatusForbidden},
		{http.MethodGet, "/api/v1/namespaces/farcast-system/configmaps", http.StatusForbidden},
		{http.MethodGet, "/api/v1/namespaces/kube-system/configmaps/technocore-ledger", http.StatusForbidden},
		{http.MethodGet, "/api/v1/namespaces/web/pods", http.StatusOK},
		{http.MethodGet, "/api/v1/namespaces/web/pods/p", http.StatusForbidden},
		{http.MethodGet, "/api/v1/namespaces/web/pods/p/log", http.StatusOK},
		{http.MethodGet, "/api/v1/namespaces/web/pods/absent/log", http.StatusNotFound},
		{http.MethodGet, "/apis/batch/v1/namespaces/farcast-system/jobs/fetch", http.StatusNotFound},
		{http.MethodGet, "/apis/batch/v1/namespaces/farcast-system/jobs", http.StatusForbidden},
		{http.MethodGet, "/api/v1/namespaces/farcast-system/secrets/s", http.StatusForbidden},
		{http.MethodGet, "/version", http.StatusForbidden},
	}
	for _, r := range rows {
		before := handled.Load()
		a := f.send(call{method: r.method, path: r.path, token: reader})
		if a.code != r.code {
			t.Errorf("reader %s %s = %d, want %d: %s", r.method, r.path, a.code, r.code, a.body)
			continue
		}
		if r.code == http.StatusForbidden {
			st := status(t, a)
			if st.Reason != "Forbidden" || st.Code != http.StatusForbidden || !strings.Contains(st.Message, `User "`+email+`"`) {
				t.Errorf("reader %s %s: 403 Status = %+v", r.method, r.path, st)
			}
			if handled.Load() != before {
				t.Errorf("reader %s %s: the handler saw a forbidden request", r.method, r.path)
			}
		}
	}

	a := f.get("/api/v1/namespaces/farcast-system/configmaps/technocore-confirmed", reader)
	want := `configmaps "technocore-confirmed" is forbidden: User "` + email + `" cannot get resource "configmaps" in API group "" in the namespace "farcast-system"`
	if st := status(t, a); st.Message != want {
		t.Errorf("403 message = %q, want %q", st.Message, want)
	}
	a = f.get("/apis/apps/v1/deployments", reader)
	want = `deployments.apps is forbidden: User "` + email + `" cannot list resource "deployments" in API group "apps" at the cluster scope`
	if st := status(t, a); st.Message != want {
		t.Errorf("403 message = %q, want %q", st.Message, want)
	}

	wantCode(t, f.apply("/apis/apps/v1/namespaces/web/deployments/web", reader, deploymentDoc("web", "web", 1)), http.StatusForbidden)
	wantCode(t, f.send(call{method: http.MethodPost, path: "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", token: reader, contentType: "application/json",
		body: []byte(`{"spec":{"resourceAttributes":{"namespace":"farcast-system","verb":"get","resource":"secrets"}}}`)}), http.StatusCreated)

	wantCode(t, f.get("/api/v1/namespaces/farcast-system/secrets/s", writer), http.StatusNotFound)
	wantCode(t, f.get("/api/v1/namespaces/farcast-system", writer), http.StatusNotFound)
	wantCode(t, f.apply("/apis/apps/v1/namespaces/web/deployments/web", writer, deploymentDoc("web", "web", 1)), http.StatusCreated)

	if s, err := kubetest.Start(kubetest.WithRBAC(email, []byte("apiVersion: v1\nkind: Secret\nmetadata:\n  name: x\n  namespace: y\nstringData:\n  a: b\n"))); err == nil {
		s.Close()
		t.Error("WithRBAC started on a stream kube.SplitStream refuses")
	}
}

// TestWithRBACReadsAListsNameFromItsFieldSelector (D-D-2): authorization
// reads a list's or a watch's object name from an exact metadata.name field
// selector, as NewRequestInfo does, so a resourceNames rule allows that list
// and no other; the first exact term, once the terms are sorted, is the name,
// as fields.Selector's RequiresExactMatch reads it, and a selector that does
// not parse names nothing. watch is any value but 0 or false. A path is
// unescaped once, by net/http, and never again, so %256F is the name's own
// %6F and not an o.
func TestWithRBACReadsAListsNameFromItsFieldSelector(t *testing.T) {
	const email = "reader@kubetest.invalid"
	stream := []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: one
  namespace: web
rules:
- apiGroups: [""]
  resources: [configmaps]
  resourceNames: [one]
  verbs: [get, list]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: one
  namespace: web
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: one
subjects:
- kind: User
  name: ` + email + `
`)
	f := newFixture(t, kubetest.WithRBAC(email, stream))
	tok := f.mint(f.s.CredentialFor("reader", email))
	f.s.Put(configMap("web", "one", map[string]string{"k": "v"}))
	f.s.Put(configMap("web", "two", map[string]string{"k": "v"}))

	const list = "/api/v1/namespaces/web/configmaps"
	for _, r := range []struct {
		path string
		code int
		verb string // for a 403, the verb its message names
	}{
		{list + "?fieldSelector=metadata.name%3Done", http.StatusOK, ""},
		{list + "?fieldSelector=metadata.name%3D%3Done", http.StatusOK, ""},
		{list + "?fieldSelector=metadata.namespace%3Dweb%2Cmetadata.name%3Done", http.StatusOK, ""},
		{list + "?fieldSelector=metadata.name%3Done&watch=false", http.StatusOK, ""},
		{list + "?fieldSelector=metadata.name%3Done&watch=0", http.StatusOK, ""},
		{list + "/one", http.StatusOK, ""},
		{list + "?fieldSelector=metadata.name%3Dtwo", http.StatusForbidden, "list"},
		{list, http.StatusForbidden, "list"},
		{list + "?fieldSelector=metadata.name%21%3Dtwo", http.StatusForbidden, "list"},
		{list + "?fieldSelector=metadata.name%3Done%2Cbad", http.StatusForbidden, "list"},
		{list + "?fieldSelector=metadata.name%3Done&watch=yes", http.StatusForbidden, "watch"},
		{list + "?fieldSelector=metadata.name%3Done&watch=", http.StatusForbidden, "watch"},
		{list + "/%256Fne", http.StatusForbidden, "get"},
	} {
		a := f.get(r.path, tok)
		if a.code != r.code {
			t.Errorf("GET %s = %d, want %d: %s", r.path, a.code, r.code, a.body)
			continue
		}
		if r.code == http.StatusForbidden {
			if st := status(t, a); !strings.Contains(st.Message, "cannot "+r.verb+` resource "configmaps"`) {
				t.Errorf("GET %s: 403 message %q does not name the verb %s", r.path, st.Message, r.verb)
			}
		}
	}

	// A refused list names the object its selector asked for, as the API
	// server's Forbidden does.
	a := f.get(list+"?fieldSelector=metadata.name%3Dtwo", tok)
	want := `configmaps "two" is forbidden: User "` + email + `" cannot list resource "configmaps" in API group "" in the namespace "web"`
	if st := status(t, a); st.Message != want || st.Details == nil || st.Details.Name != "two" {
		t.Errorf("403 = %q (details %+v), want %q naming two", st.Message, st.Details, want)
	}

	// A method NewRequestInfo does not know has the verb "", not its own name.
	a = f.send(call{method: http.MethodOptions, path: list + "/one", token: tok})
	want = `configmaps "one" is forbidden: User "` + email + `" cannot  resource "configmaps" in API group "" in the namespace "web"`
	if st := status(t, a); a.code != http.StatusForbidden || st.Message != want {
		t.Errorf("OPTIONS = %d %q, want 403 %q", a.code, st.Message, want)
	}
}

// TestWithRBACAuthorizesAnApplyThatCreatesForCreateToo: a server-side apply
// of an absent object needs create as well as patch, as the API server's
// patch handler checks; an update needs patch alone.
func TestWithRBACAuthorizesAnApplyThatCreatesForCreateToo(t *testing.T) {
	const email = "writer@kubetest.invalid"
	stream := func(verbs string) []byte {
		return []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: cm
  namespace: web
rules:
- apiGroups: [""]
  resources: [configmaps]
  verbs: [` + verbs + `]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cm
  namespace: web
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: cm
subjects:
- kind: User
  name: ` + email + `
`)
	}
	doc := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n  namespace: web\ndata:\n  a: b\n"
	const path = "/api/v1/namespaces/web/configmaps/c"

	f := newFixture(t, kubetest.WithRBAC(email, stream("patch")))
	tok := f.mint(f.s.CredentialFor("writer", email))
	a := f.apply(path, tok, doc)
	wantCode(t, a, http.StatusForbidden)
	if st := status(t, a); !strings.Contains(st.Message, "cannot create resource") {
		t.Errorf("the create refusal reads %q", st.Message)
	}
	f.s.Put(configMap("web", "c", map[string]string{"a": "old"}))
	wantCode(t, f.apply(path, tok, doc), http.StatusOK)

	g := newFixture(t, kubetest.WithRBAC(email, stream("patch, create")))
	wantCode(t, g.apply(path, g.mint(g.s.CredentialFor("writer", email)), doc), http.StatusCreated)
}

// TestApplyCreatesThenUpdatesKeepingOneEntryPerManager: 201 then 200, the
// server's metadata kept or set, status kept, and one managed-fields entry
// per manager.
func TestApplyCreatesThenUpdatesKeepingOneEntryPerManager(t *testing.T) {
	f := newFixture(t)
	tok := f.mint(f.s.Credential("writer"))
	const path = "/apis/apps/v1/namespaces/web/deployments/web"

	a := f.apply(path, tok, deploymentDoc("web", "web", 1))
	wantCode(t, a, http.StatusCreated)
	created := object(t, a)
	md := metaOf(t, created)
	if created["kind"] != "Deployment" || created["apiVersion"] != "apps/v1" {
		t.Errorf("the apply answer carries kind %v apiVersion %v", created["kind"], created["apiVersion"])
	}
	if md["uid"] == "" || md["resourceVersion"] == "" || md["creationTimestamp"] == nil || md["generation"] != json.Number("1") {
		t.Errorf("created metadata = %v", md)
	}
	entries := managedFields(t, created)
	if len(entries) != 1 {
		t.Fatalf("managedFields = %+v, want one entry", entries)
	}
	if e := entries[0]; e.Manager != "farcast" || e.Operation != "Apply" || e.APIVersion != "apps/v1" || e.FieldsType != "FieldsV1" || string(e.FieldsV1) != "{}" || e.Time == "" || e.Subresource != "" {
		t.Errorf("the entry = %+v", e)
	}

	a = f.apply(path, tok, deploymentDoc("web", "web", 1))
	wantCode(t, a, http.StatusOK)
	again := object(t, a)
	if metaOf(t, again)["resourceVersion"] != md["resourceVersion"] || !reflect.DeepEqual(managedFields(t, again), entries) {
		t.Errorf("an unchanged apply wrote: %v", metaOf(t, again))
	}

	a = f.apply(path, tok, deploymentDoc("web", "web", 2))
	wantCode(t, a, http.StatusOK)
	updated := object(t, a)
	umd := metaOf(t, updated)
	if umd["uid"] != md["uid"] || umd["creationTimestamp"] != md["creationTimestamp"] || umd["resourceVersion"] == md["resourceVersion"] || umd["generation"] != json.Number("2") {
		t.Errorf("updated metadata = %v (created %v)", umd, md)
	}
	if get(updated, "spec", "replicas") != json.Number("2") {
		t.Errorf("the update did not take: %v", updated["spec"])
	}
	if es := managedFields(t, updated); len(es) != 1 || es[0].Manager != "farcast" {
		t.Errorf("after an update managedFields = %+v", es)
	}

	tech := f.send(call{method: http.MethodPatch, path: path + "?fieldManager=technocore&fieldValidation=Strict", token: tok, contentType: applyType, body: []byte(deploymentDoc("web", "web", 0))})
	wantCode(t, tech, http.StatusOK)
	a = f.apply(path, tok, deploymentDoc("web", "web", 2))
	wantCode(t, a, http.StatusOK)
	var managers []string
	for _, e := range managedFields(t, object(t, a)) {
		managers = append(managers, e.Manager+"/"+e.Operation)
	}
	slices.Sort(managers)
	if !slices.Equal(managers, []string{"farcast/Apply", "technocore/Apply"}) {
		t.Errorf("managers = %v, want one entry each", managers)
	}

	f.s.Put(map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": map[string]any{"name": "s", "namespace": "web"},
		"spec": map[string]any{"replicas": 1}, "status": map[string]any{"readyReplicas": 3}})
	a = f.apply("/apis/apps/v1/namespaces/web/deployments/s", tok, deploymentDoc("s", "web", 1)+"status:\n  readyReplicas: 9\n")
	wantCode(t, a, http.StatusOK)
	if got := get(object(t, a), "status", "readyReplicas"); got != json.Number("3") {
		t.Errorf("status after an apply = %v, want the server's 3", got)
	}
}

type entry struct {
	Manager     string          `json:"manager"`
	Operation   string          `json:"operation"`
	APIVersion  string          `json:"apiVersion"`
	Time        string          `json:"time"`
	FieldsType  string          `json:"fieldsType"`
	FieldsV1    json.RawMessage `json:"fieldsV1"`
	Subresource string          `json:"subresource"`
}

func managedFields(t *testing.T, obj map[string]any) []entry {
	t.Helper()
	b, err := json.Marshal(get(obj, "metadata", "managedFields"))
	if err != nil {
		t.Fatal(err)
	}
	var es []entry
	if err := json.Unmarshal(b, &es); err != nil {
		t.Fatalf("managedFields do not decode: %v: %s", err, b)
	}
	return es
}

// TestApplyRequiresFieldManagerAndStrictValidation: an apply without
// fieldManager, or without fieldValidation=Strict, is 400 and stores nothing.
func TestApplyRequiresFieldManagerAndStrictValidation(t *testing.T) {
	f := newFixture(t)
	tok := f.mint(f.s.Credential("writer"))
	const path = "/apis/apps/v1/namespaces/web/deployments/web"
	for _, q := range []string{
		"?fieldValidation=Strict",
		"?fieldManager=&fieldValidation=Strict",
		"?fieldManager=farcast",
		"?fieldManager=farcast&fieldValidation=Warn",
		"?fieldManager=farcast&fieldValidation=Strict&force=maybe",
		"?fieldManager=farcast&fieldValidation=Strict&dryRun=All",
	} {
		a := f.send(call{method: http.MethodPatch, path: path + q, token: tok, contentType: applyType, body: []byte(deploymentDoc("web", "web", 1))})
		wantStatus(t, a, http.StatusBadRequest, "BadRequest")
	}
	wantCode(t, f.get(path, tok), http.StatusNotFound)
}

// TestApplyRequiresTheBodyToNameTheURLsObject: the body's kind, name and
// namespace must be the URL's, and it must parse as YAML.
func TestApplyRequiresTheBodyToNameTheURLsObject(t *testing.T) {
	f := newFixture(t)
	tok := f.mint(f.s.Credential("writer"))
	const path = "/apis/apps/v1/namespaces/web/deployments/web"
	for name, doc := range map[string]string{
		"another name":         deploymentDoc("api", "web", 1),
		"another namespace":    deploymentDoc("web", "other", 1),
		"no namespace":         strings.Replace(deploymentDoc("web", "web", 1), "  namespace: web\n", "", 1),
		"another kind":         strings.Replace(deploymentDoc("web", "web", 1), "kind: Deployment", "kind: StatefulSet", 1),
		"another apiVersion":   strings.Replace(deploymentDoc("web", "web", 1), "apiVersion: apps/v1", "apiVersion: apps/v1beta1", 1),
		"not YAML":             "kind: [unclosed\n",
		"a list, not a object": "- a\n- b\n",
	} {
		a := f.apply(path, tok, doc)
		if a.code != http.StatusBadRequest {
			t.Errorf("%s: apply = %d, want 400: %s", name, a.code, a.body)
		}
	}
	a := f.apply("/api/v1/namespaces/web/configmaps/c", tok, `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"c","namespace":"web"}}`)
	wantCode(t, a, http.StatusCreated) // JSON is YAML
	wantCode(t, f.get(path, tok), http.StatusNotFound)
	a = f.apply("/api/v1/namespaces/c", tok, "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: c\n")
	wantCode(t, a, http.StatusCreated)
	if md := metaOf(t, object(t, a)); md["namespace"] != nil {
		t.Errorf("a cluster-scoped object answered with namespace %v", md["namespace"])
	}
}

// TestSingleObjectAnswersCarryKindAndListItemsDoNot: GET, PATCH, POST and PUT
// answers carry kind and apiVersion; list items carry neither.
func TestSingleObjectAnswersCarryKindAndListItemsDoNot(t *testing.T) {
	f := newFixture(t)
	tok := f.mint(f.s.Credential("writer"))
	hasKind := func(t *testing.T, what string, a answer, kind, apiVersion string) {
		t.Helper()
		m := object(t, a)
		if m["kind"] != kind || m["apiVersion"] != apiVersion {
			t.Errorf("%s answers kind %v apiVersion %v, want %s %s", what, m["kind"], m["apiVersion"], kind, apiVersion)
		}
	}
	a := f.send(call{method: http.MethodPost, path: "/api/v1/namespaces/web/configmaps", token: tok, contentType: "application/json", body: []byte(`{"metadata":{"name":"pin"},"data":{"a":"b"}}`)})
	wantCode(t, a, http.StatusCreated)
	hasKind(t, "POST", a, "ConfigMap", "v1")
	rv := metaOf(t, object(t, a))["resourceVersion"].(string)
	a = f.send(call{method: http.MethodPut, path: "/api/v1/namespaces/web/configmaps/pin", token: tok, contentType: "application/json", body: []byte(`{"metadata":{"name":"pin","resourceVersion":"` + rv + `"},"data":{"a":"c"}}`)})
	wantCode(t, a, http.StatusOK)
	hasKind(t, "PUT", a, "ConfigMap", "v1")
	hasKind(t, "GET", f.get("/api/v1/namespaces/web/configmaps/pin", tok), "ConfigMap", "v1")
	a = f.apply("/apis/apps/v1/namespaces/web/deployments/web", tok, deploymentDoc("web", "web", 1))
	hasKind(t, "PATCH", a, "Deployment", "apps/v1")

	l := object(t, f.get("/apis/apps/v1/namespaces/web/deployments", tok))
	if l["kind"] != "DeploymentList" || l["apiVersion"] != "apps/v1" {
		t.Errorf("the list is kind %v apiVersion %v", l["kind"], l["apiVersion"])
	}
	items, _ := l["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("items = %v", items)
	}
	item := items[0].(map[string]any)
	if _, ok := item["kind"]; ok {
		t.Error("a list item carries kind")
	}
	if _, ok := item["apiVersion"]; ok {
		t.Error("a list item carries apiVersion")
	}
	if get(item, "metadata", "name") != "web" || item["spec"] == nil {
		t.Errorf("the list item lost its object: %v", item)
	}
	empty := object(t, f.get("/apis/apps/v1/namespaces/none/deployments", tok))
	if items, ok := empty["items"].([]any); !ok || len(items) != 0 {
		t.Errorf("an empty list's items = %#v, want []", empty["items"])
	}
}

// TestConfigMapCreateReplaceAndGet: POST is 201 or 409 AlreadyExists; PUT
// needs the stored resourceVersion (409 on a stale or missing one, 404 when
// absent); GET is 404 when absent.
func TestConfigMapCreateReplaceAndGet(t *testing.T) {
	f := newFixture(t)
	tok := f.mint(f.s.Credential("writer"))
	const coll, path = "/api/v1/namespaces/farcast-system/configmaps", "/api/v1/namespaces/farcast-system/configmaps/datasphered-pin"
	post := func(body string) answer {
		return f.send(call{method: http.MethodPost, path: coll + "?fieldManager=farcast&fieldValidation=Strict", token: tok, contentType: "application/json", body: []byte(body)})
	}
	put := func(body string) answer {
		return f.send(call{method: http.MethodPut, path: path + "?fieldManager=farcast&fieldValidation=Strict", token: tok, contentType: "application/json", body: []byte(body)})
	}

	st := wantStatus(t, f.get(path, tok), http.StatusNotFound, "NotFound")
	if st.Message != `configmaps "datasphered-pin" not found` || st.Details == nil || st.Details.Kind != "configmaps" || st.Details.Name != "datasphered-pin" {
		t.Errorf("404 Status = %+v", st)
	}
	wantStatus(t, put(`{"metadata":{"name":"datasphered-pin","resourceVersion":"1"}}`), http.StatusNotFound, "NotFound")

	a := post(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"datasphered-pin","namespace":"farcast-system"},"data":{"key":"one"}}`)
	wantCode(t, a, http.StatusCreated)
	created := metaOf(t, object(t, a))
	st = wantStatus(t, post(`{"metadata":{"name":"datasphered-pin"},"data":{"key":"two"}}`), http.StatusConflict, "AlreadyExists")
	if st.Message != `configmaps "datasphered-pin" already exists` {
		t.Errorf("409 message = %q", st.Message)
	}
	wantStatus(t, post(`{"metadata":{"name":"x","namespace":"other"}}`), http.StatusBadRequest, "BadRequest")
	wantStatus(t, post(`{"metadata":{}}`), http.StatusUnprocessableEntity, "Invalid")
	wantStatus(t, post(`{"apiVersion":"v1","kind":"Secret","metadata":{"name":"x"}}`), http.StatusBadRequest, "BadRequest")

	rv := created["resourceVersion"].(string)
	wantStatus(t, put(`{"metadata":{"name":"datasphered-pin","resourceVersion":"stale"},"data":{"key":"two"}}`), http.StatusConflict, "Conflict")
	wantStatus(t, put(`{"metadata":{"name":"datasphered-pin"},"data":{"key":"two"}}`), http.StatusConflict, "Conflict")
	wantStatus(t, put(`{"metadata":{"name":"other","resourceVersion":"`+rv+`"}}`), http.StatusBadRequest, "BadRequest")
	a = put(`{"metadata":{"name":"datasphered-pin","resourceVersion":"` + rv + `"},"data":{"key":"two"}}`)
	wantCode(t, a, http.StatusOK)
	replaced := object(t, a)
	if md := metaOf(t, replaced); md["resourceVersion"] == rv || md["uid"] != created["uid"] || get(replaced, "data", "key") != "two" {
		t.Errorf("replaced = %v", replaced)
	}
	wantStatus(t, put(`{"metadata":{"name":"datasphered-pin","resourceVersion":"`+rv+`"},"data":{"key":"three"}}`), http.StatusConflict, "Conflict")
	if got := get(object(t, f.get(path, tok)), "data", "key"); got != "two" {
		t.Errorf("after a stale PUT the data is %v", got)
	}
}

// TestListsSelectPageAndSpanNamespaces: equality selectors, the name field
// selector, lists across every namespace, and limit/continue paging, for
// every kind farcast applies.
func TestListsSelectPageAndSpanNamespaces(t *testing.T) {
	f := newFixture(t)
	tok := f.mint(f.s.Credential("reader"))
	names := func(t *testing.T, a answer) []string {
		t.Helper()
		wantCode(t, a, http.StatusOK)
		var out []string
		items, _ := object(t, a)["items"].([]any)
		for _, it := range items {
			out = append(out, get(it.(map[string]any), "metadata", "name").(string))
		}
		return out
	}
	for _, n := range []string{"web", "farcast-system", "api", "kube-system", "default"} {
		labels := map[string]any{}
		if n == "web" || n == "farcast-system" || n == "api" {
			labels["app.kubernetes.io/managed-by"] = "farcast"
		}
		f.s.Put(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": n, "labels": labels}})
	}
	for q, want := range map[string][]string{
		"labelSelector=" + url.QueryEscape("app.kubernetes.io/managed-by=farcast"):  {"api", "farcast-system", "web"},
		"labelSelector=" + url.QueryEscape("app.kubernetes.io/managed-by==farcast"): {"api", "farcast-system", "web"},
		"labelSelector=" + url.QueryEscape("app.kubernetes.io/managed-by!=farcast"): {"default", "kube-system"},
		"fieldSelector=" + url.QueryEscape("metadata.name=web"):                     {"web"},
		"": {"api", "default", "farcast-system", "kube-system", "web"},
	} {
		if got := names(t, f.get("/api/v1/namespaces?"+q, tok)); !slices.Equal(got, want) {
			t.Errorf("namespaces?%s = %v, want %v", q, got, want)
		}
	}
	for _, q := range []string{
		"labelSelector=" + url.QueryEscape("app in (web)"),
		"labelSelector=" + url.QueryEscape("!app"),
		"labelSelector=" + url.QueryEscape("app"),
		"fieldSelector=" + url.QueryEscape("spec.x=y"),
		"limit=-1", "limit=x", "continue=%21%21",
	} {
		wantStatus(t, f.get("/api/v1/namespaces?"+q, tok), http.StatusBadRequest, "BadRequest")
	}

	for i := range 5 {
		f.s.Put(configMap("p", fmt.Sprintf("cm-%d", i), nil))
	}
	f.s.Put(configMap("q", "cm-x", nil))
	var seen []string
	next := ""
	for page := 0; ; page++ {
		path := "/api/v1/namespaces/p/configmaps?limit=2"
		if next != "" {
			path += "&continue=" + url.QueryEscape(next)
		}
		a := f.get(path, tok)
		seen = append(seen, names(t, a)...)
		md := metaOf(t, object(t, a))
		if page == 0 && md["remainingItemCount"] != json.Number("3") {
			t.Errorf("first page remainingItemCount = %v, want 3", md["remainingItemCount"])
		}
		next, _ = md["continue"].(string)
		if next == "" {
			break
		}
		if page > 5 {
			t.Fatal("paging does not end")
		}
	}
	if want := []string{"cm-0", "cm-1", "cm-2", "cm-3", "cm-4"}; !slices.Equal(seen, want) {
		t.Errorf("pages = %v, want %v", seen, want)
	}
	if got := names(t, f.get("/api/v1/configmaps", tok)); !slices.Equal(got, []string{"cm-0", "cm-1", "cm-2", "cm-3", "cm-4", "cm-x"}) {
		t.Errorf("configmaps in every namespace = %v", got)
	}

	for _, k := range kube.Kinds {
		name := "obj"
		if k.Names != nil {
			name = k.Names[0]
		}
		md := map[string]any{"name": name}
		ns := ""
		if k.Namespaced {
			ns = "kinds"
			md["namespace"] = ns
		}
		f.s.Put(map[string]any{"apiVersion": k.APIVersion, "kind": k.Kind, "metadata": md})
		if got := names(t, f.get(k.ListPath(ns), tok)); !slices.Contains(got, name) {
			t.Errorf("%s: list in its namespace = %v", k.Kind, got)
		}
		if got := names(t, f.get(k.ListPath(""), tok)); !slices.Contains(got, name) {
			t.Errorf("%s: list across namespaces = %v", k.Kind, got)
		}
		a := f.get(k.Path(ns, name), tok)
		wantCode(t, a, http.StatusOK)
		if m := object(t, a); m["kind"] != k.Kind {
			t.Errorf("%s: GET answers kind %v", k.Kind, m["kind"])
		}
	}
}

// TestPartialObjectMetadataAnswersCarryNoData: an Accept for the
// metadata-only views gets metadata alone, so a Secret's values never leave
// the server.
func TestPartialObjectMetadataAnswersCarryNoData(t *testing.T) {
	f := newFixture(t)
	tok := f.mint(f.s.Credential("writer"))
	secretValue := base64.StdEncoding.EncodeToString([]byte("marker-secret-value"))
	f.s.Put(map[string]any{"apiVersion": "v1", "kind": "Secret",
		"metadata": map[string]any{"name": "s", "namespace": "web", "labels": map[string]any{"app.kubernetes.io/managed-by": "farcast"}},
		"data":     map[string]any{"key": secretValue}})

	a := f.send(call{method: http.MethodGet, path: "/api/v1/secrets?labelSelector=" + url.QueryEscape("app.kubernetes.io/managed-by=farcast"), token: tok, accept: partialList})
	wantCode(t, a, http.StatusOK)
	if bytes.Contains(a.body, []byte(secretValue)) {
		t.Errorf("a metadata-only list carries the Secret's data: %s", a.body)
	}
	l := object(t, a)
	if l["kind"] != "PartialObjectMetadataList" || l["apiVersion"] != "meta.k8s.io/v1" {
		t.Errorf("the list is kind %v apiVersion %v", l["kind"], l["apiVersion"])
	}
	items, _ := l["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("items = %v", items)
	}
	var keys []string
	for k := range items[0].(map[string]any) {
		keys = append(keys, k)
	}
	if !slices.Equal(keys, []string{"metadata"}) || get(items[0].(map[string]any), "metadata", "name") != "s" {
		t.Errorf("a metadata-only item holds %v", items[0])
	}

	a = f.send(call{method: http.MethodGet, path: "/api/v1/namespaces/web/secrets/s", token: tok, accept: partialOne})
	wantCode(t, a, http.StatusOK)
	one := object(t, a)
	if one["kind"] != "PartialObjectMetadata" || one["apiVersion"] != "meta.k8s.io/v1" || one["data"] != nil || bytes.Contains(a.body, []byte(secretValue)) {
		t.Errorf("a metadata-only get = %s", a.body)
	}

	wantStatus(t, f.send(call{method: http.MethodGet, path: "/api/v1/namespaces/web/secrets/s", token: tok, accept: partialList}), http.StatusNotAcceptable, "NotAcceptable")
	wantStatus(t, f.send(call{method: http.MethodGet, path: "/api/v1/secrets", token: tok, accept: partialOne}), http.StatusNotAcceptable, "NotAcceptable")
	a = f.send(call{method: http.MethodGet, path: "/api/v1/namespaces/web/secrets/s", token: tok, accept: "application/json"})
	if !bytes.Contains(a.body, []byte(secretValue)) {
		t.Errorf("a full get lost the data: %s", a.body)
	}
}

// TestScriptAnswersSuccessiveGetsInTurn: a script answers in turn, repeats
// its last answer, carries the kind, comes after Fail's answers, and leaves
// the store alone.
func TestScriptAnswersSuccessiveGetsInTurn(t *testing.T) {
	f := newFixture(t)
	tok := f.mint(f.s.Credential("reader"))
	const path = "/apis/apps/v1/namespaces/web/deployments/web"
	step := func(observed int) map[string]any {
		return map[string]any{"metadata": map[string]any{"name": "web", "namespace": "web", "generation": 3}, "status": map[string]any{"observedGeneration": observed}}
	}
	f.s.Script(path, step(1), step(2), step(3))
	f.s.Fail(http.MethodGet, path, http.StatusServiceUnavailable, kube.Status{})
	wantCode(t, f.get(path, tok), http.StatusServiceUnavailable)
	for _, want := range []string{"1", "2", "3", "3"} {
		a := f.get(path, tok)
		wantCode(t, a, http.StatusOK)
		m := object(t, a)
		if got := get(m, "status", "observedGeneration"); got != json.Number(want) {
			t.Errorf("scripted observedGeneration = %v, want %s", got, want)
		}
		if m["kind"] != "Deployment" || m["apiVersion"] != "apps/v1" {
			t.Errorf("a scripted single-object answer carries kind %v apiVersion %v", m["kind"], m["apiVersion"])
		}
	}
	f.s.Script(path)
	wantCode(t, f.get(path, tok), http.StatusNotFound)

	f.s.Script("/apis/apps/v1/namespaces/web/deployments", map[string]any{"items": []any{}})
	if m := object(t, f.get("/apis/apps/v1/namespaces/web/deployments", tok)); m["kind"] != nil {
		t.Errorf("a scripted list answer was given kind %v", m["kind"])
	}
}

// TestLogsHonourContainerTailLinesAndPrevious: the log parameters, and the
// refusals a real API server gives.
func TestLogsHonourContainerTailLinesAndPrevious(t *testing.T) {
	f := newFixture(t)
	tok := f.mint(f.s.Credential("reader"))
	f.s.Put(pod("web", "two", map[string]string{
		kubetest.LogAnnotationPrefix + "app":           "a1\na2\na3\n",
		kubetest.LogAnnotationPrefix + "shrike":        "s1\n",
		kubetest.PreviousLogAnnotationPrefix + "app":   "crashed\n",
		kubetest.LogAnnotationPrefix + "unrelated-one": "x\n",
	}, "app", "shrike"))
	f.s.Put(pod("web", "one", map[string]string{kubetest.LogAnnotationPrefix + "app": "only\n"}, "app"))
	const base = "/api/v1/namespaces/web/pods/"
	for q, want := range map[string]string{
		"two/log?container=app":                          "a1\na2\na3\n",
		"two/log?container=shrike":                       "s1\n",
		"two/log?container=app&tailLines=1":              "a3\n",
		"two/log?container=app&tailLines=2":              "a2\na3\n",
		"two/log?container=app&tailLines=0":              "",
		"two/log?container=app&tailLines=9":              "a1\na2\na3\n",
		"two/log?container=app&previous=true":            "crashed\n",
		"two/log?container=app&previous=false":           "a1\na2\na3\n",
		"one/log":                                        "only\n",
		"one/log?container=app&follow=false&tailLines=1": "only\n",
	} {
		a := f.get(base+q, tok)
		if a.code != http.StatusOK || string(a.body) != want {
			t.Errorf("%s = %d %q, want %q", q, a.code, a.body, want)
		}
		if ct := a.header.Get("Content-Type"); ct != "text/plain" {
			t.Errorf("%s: Content-Type %q", q, ct)
		}
	}
	for _, q := range []string{
		"two/log?container=app&tailLines=-1",
		"two/log?container=app&tailLines=x",
		"two/log?container=app&tailLines=1.5",
		"two/log",
		"two/log?container=sidecar",
		"two/log?container=shrike&previous=true",
		"two/log?container=app&previous=maybe",
		"two/log?container=app&follow=maybe",
	} {
		wantStatus(t, f.get(base+q, tok), http.StatusBadRequest, "BadRequest")
	}
	wantStatus(t, f.get(base+"absent/log", tok), http.StatusNotFound, "NotFound")
}

// TestLogsAreChunkedFlushedAndFollowedUntilTheContextEnds: the body is
// chunked and flushed per line, and with follow it stays open until the
// client goes or the server closes.
func TestLogsAreChunkedFlushedAndFollowedUntilTheContextEnds(t *testing.T) {
	f := newFixture(t)
	tok := f.mint(f.s.Credential("reader"))
	f.s.Put(pod("web", "p", map[string]string{kubetest.LogAnnotationPrefix + "app": "one\ntwo\n"}, "app"))
	const path = "/api/v1/namespaces/web/pods/p/log?container=app"

	h1 := &fixture{t: t, s: f.s, hc: clientFor(t, f.s, true)}
	a := h1.get(path, tok)
	if a.proto != 1 || !slices.Contains(a.te, "chunked") || string(a.body) != "one\ntwo\n" {
		t.Errorf("an HTTP/1.1 log answer is HTTP/%d, Transfer-Encoding %v, body %q", a.proto, a.te, a.body)
	}

	follow := func(t *testing.T, hc *http.Client, ctx context.Context) (*http.Response, *bufio.Reader) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+f.s.Endpoint()+path+"&follow=true", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		br := bufio.NewReader(resp.Body)
		for _, want := range []string{"one\n", "two\n"} {
			line, err := br.ReadString('\n')
			if err != nil || line != want {
				t.Fatalf("followed line = %q, %v; want %q (the lines must arrive while the stream is open)", line, err, want)
			}
		}
		return resp, br
	}
	ended := func(br *bufio.Reader) chan error {
		done := make(chan error, 1)
		go func() {
			_, err := br.ReadByte()
			done <- err
		}()
		return done
	}

	for _, hc := range []*http.Client{f.hc, h1.hc} {
		ctx, cancel := context.WithCancel(context.Background())
		resp, br := follow(t, hc, ctx)
		done := ended(br)
		select {
		case err := <-done:
			t.Fatalf("a followed stream ended by itself: %v", err)
		case <-time.After(200 * time.Millisecond):
		}
		cancel()
		select {
		case err := <-done:
			if err == nil {
				t.Error("a followed stream sent more after its context ended")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a followed stream did not end with its context")
		}
		_ = resp.Body.Close()
	}

	resp, br := follow(t, f.hc, context.Background())
	defer func() { _ = resp.Body.Close() }()
	done := ended(br)
	closed := make(chan struct{})
	go func() { f.s.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not end a followed stream")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Error("a followed stream sent more after Close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the client's followed stream outlived Close")
	}
}

// liveCSAObject is a Deployment as kubectl's client-side apply leaves it: a
// kubectl-client-side-apply Update entry that owns the last-applied
// annotation, and the annotation itself.
func liveCSAObject() map[string]any {
	return map[string]any{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{
			"name": "web", "namespace": "web",
			"annotations": map[string]any{lastApplied: `{"marker":"last-applied"}`, "keep": "me"},
			"managedFields": []any{map[string]any{
				"manager": "kubectl-client-side-apply", "operation": "Update", "apiVersion": "apps/v1",
				"time": "2026-11-01T00:00:00Z", "fieldsType": "FieldsV1",
				"fieldsV1": map[string]any{
					"f:metadata": map[string]any{"f:annotations": map[string]any{".": map[string]any{}, "f:" + lastApplied: map[string]any{}}},
					"f:spec":     map[string]any{"f:replicas": map[string]any{}},
				},
			}},
		},
		"spec": map[string]any{"replicas": 1},
	}
}

// migratedEntry is the entry the rewrite submits, decodable as the server
// decodes it; mutate makes it not.
func migratedEntry(mutate func(map[string]any)) map[string]any {
	e := map[string]any{
		"manager": "farcast", "operation": "Apply", "apiVersion": "apps/v1",
		"time": "2026-11-01T00:00:00Z", "fieldsType": "FieldsV1",
		"fieldsV1": map[string]any{"f:spec": map[string]any{"f:replicas": map[string]any{}}},
	}
	if mutate != nil {
		mutate(e)
	}
	return e
}

func migrationOps(managedFields any, rv string) []map[string]any {
	return []map[string]any{
		{"op": "replace", "path": "/metadata/managedFields", "value": managedFields},
		{"op": "replace", "path": "/metadata/resourceVersion", "value": rv},
		{"op": "remove", "path": "/metadata/annotations/kubectl.kubernetes.io~1last-applied-configuration"},
	}
}

// withoutLastApplied is liveCSAObject's entries as the API server keeps them
// after a patch that removed the last-applied annotation: its field manager
// subtracts the removed path from every entry (structured-merge-diff v6.3.1
// merge/update.go), so kubectl-client-side-apply's annotations node is left a
// member with no children.
func withoutLastApplied(t *testing.T, live []entry) []entry {
	t.Helper()
	if len(live) != 1 || live[0].Manager != "kubectl-client-side-apply" {
		t.Fatalf("live entries = %+v, want liveCSAObject's one", live)
	}
	out := slices.Clone(live)
	out[0].FieldsV1 = json.RawMessage(`{"f:metadata":{"f:annotations":{}},"f:spec":{"f:replicas":{}}}`)
	return out
}

// TestKubetestKeepsTheLiveListOnAnUndecodableRewrite (§10.5 row 37): a
// submitted managedFields list the API server cannot decode leaves the live
// list in place, silently, while the patch's other operations still apply,
// as apimachinery v0.37.2's decodeLiveOrNew does. Each row breaks one of
// DecodeManagedFields' rules; the last row is decodable, and is taken. The
// live list is kept less the removed annotation's path, which the field
// manager then strips from every entry it keeps.
func TestKubetestKeepsTheLiveListOnAnUndecodableRewrite(t *testing.T) {
	f := newFixture(t)
	tok := f.mint(f.s.Credential("writer"))
	const path = "/apis/apps/v1/namespaces/web/deployments/web"
	rows := []struct {
		name    string
		list    []any
		decodes bool
	}{
		{"an operation that is neither Apply nor Update", []any{migratedEntry(func(e map[string]any) { e["operation"] = "Merge" })}, false},
		{"no operation", []any{migratedEntry(func(e map[string]any) { delete(e, "operation") })}, false},
		{"an empty apiVersion", []any{migratedEntry(func(e map[string]any) { e["apiVersion"] = "" })}, false},
		{"no fieldsType", []any{migratedEntry(func(e map[string]any) { delete(e, "fieldsType") })}, false},
		{"fieldsType FieldsV2", []any{migratedEntry(func(e map[string]any) { e["fieldsType"] = "FieldsV2" })}, false},
		{"fieldsV1 that is a string", []any{migratedEntry(func(e map[string]any) { e["fieldsV1"] = "f:spec" })}, false},
		{"fieldsV1 with a key that is no path element", []any{migratedEntry(func(e map[string]any) { e["fieldsV1"] = map[string]any{"spec": map[string]any{}} })}, false},
		{"fieldsV1 with a node that is not an object", []any{migratedEntry(func(e map[string]any) { e["fieldsV1"] = map[string]any{"f:spec": []any{}} })}, false},
		{"fieldsV1 with a k: key that is not JSON", []any{migratedEntry(func(e map[string]any) {
			e["fieldsV1"] = map[string]any{"f:spec": map[string]any{"k:{name": map[string]any{}}}
		})}, false},
		{"one good entry and one bad", []any{migratedEntry(nil), migratedEntry(func(e map[string]any) { e["manager"] = "x"; e["apiVersion"] = "" })}, false},
		{"a decodable list", []any{migratedEntry(nil)}, true},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			f.s.Put(liveCSAObject())
			live := object(t, f.get(path, tok))
			liveEntries := managedFields(t, live)
			rv := metaOf(t, live)["resourceVersion"].(string)

			a := f.patchJSON(path, tok, migrationOps(r.list, rv))
			wantCode(t, a, http.StatusOK)
			for _, got := range []map[string]any{object(t, a), object(t, f.get(path, tok))} {
				md := metaOf(t, got)
				ann, _ := md["annotations"].(map[string]any)
				if _, ok := ann[lastApplied]; ok {
					t.Error("the annotation's removal did not apply")
				}
				if ann["keep"] != "me" {
					t.Errorf("another annotation was lost: %v", ann)
				}
				if md["resourceVersion"] == rv {
					t.Error("a patch that removed the annotation kept the resourceVersion")
				}
				es := managedFields(t, got)
				switch {
				case r.decodes && (len(es) != 1 || es[0].Manager != "farcast" || es[0].Operation != "Apply"):
					t.Errorf("a decodable list was not taken: %+v", es)
				case !r.decodes && !reflect.DeepEqual(es, withoutLastApplied(t, liveEntries)):
					t.Errorf("an undecodable list replaced the live one: %+v, live %+v", es, liveEntries)
				}
			}
		})
	}
}

// TestJSONPatchGuardsAndRefusesWhatItDoesNotEmulate: the resourceVersion
// guard, all-or-nothing operations, and the shapes the fake refuses rather
// than misread.
func TestJSONPatchGuardsAndRefusesWhatItDoesNotEmulate(t *testing.T) {
	f := newFixture(t)
	tok := f.mint(f.s.Credential("writer"))
	const path = "/apis/apps/v1/namespaces/web/deployments/web"
	fresh := func(t *testing.T) (map[string]any, string) {
		t.Helper()
		f.s.Put(liveCSAObject())
		live := object(t, f.get(path, tok))
		return live, metaOf(t, live)["resourceVersion"].(string)
	}
	unchanged := func(t *testing.T, live map[string]any) {
		t.Helper()
		if now := object(t, f.get(path, tok)); !reflect.DeepEqual(now, live) {
			t.Errorf("a refused patch changed the object:\n got %v\nwant %v", now, live)
		}
	}

	t.Run("a stale resourceVersion is 409", func(t *testing.T) {
		live, _ := fresh(t)
		st := wantStatus(t, f.patchJSON(path, tok, migrationOps([]any{migratedEntry(nil)}, "stale")), http.StatusConflict, "Conflict")
		if !strings.Contains(st.Message, "the object has been modified") {
			t.Errorf("409 message = %q", st.Message)
		}
		unchanged(t, live)
	})
	t.Run("operations are all or nothing", func(t *testing.T) {
		live, _ := fresh(t)
		ops := []map[string]any{
			{"op": "remove", "path": "/metadata/annotations/kubectl.kubernetes.io~1last-applied-configuration"},
			{"op": "replace", "path": "/metadata/resourceVersion", "value": "stale"},
		}
		wantCode(t, f.patchJSON(path, tok, ops), http.StatusConflict)
		unchanged(t, live)
	})
	for name, ops := range map[string]func(rv string) any{
		"removing an absent annotation": func(rv string) any {
			return []map[string]any{{"op": "remove", "path": "/metadata/annotations/absent"}}
		},
		"an add": func(rv string) any {
			return []map[string]any{{"op": "add", "path": "/metadata/labels/x", "value": "y"}}
		},
		"a replace elsewhere": func(rv string) any {
			return []map[string]any{{"op": "replace", "path": "/spec/replicas", "value": 3}}
		},
		"a remove of more than one annotation key": func(rv string) any {
			return []map[string]any{{"op": "remove", "path": "/metadata/annotations/a/b"}}
		},
		"a reset to []": func(rv string) any { return migrationOps([]any{}, rv) },
		"a reset to [{}]": func(rv string) any {
			return migrationOps([]any{map[string]any{}}, rv)
		},
		"managedFields that is not a list": func(rv string) any { return migrationOps("x", rv) },
		"an entry time that is not a time": func(rv string) any {
			return migrationOps([]any{migratedEntry(func(e map[string]any) { e["time"] = "yesterday" })}, rv)
		},
		"a replace with no value": func(rv string) any {
			return []map[string]any{{"op": "replace", "path": "/metadata/managedFields"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			live, rv := fresh(t)
			wantStatus(t, f.patchJSON(path, tok, ops(rv)), http.StatusUnprocessableEntity, "Invalid")
			unchanged(t, live)
		})
	}
	t.Run("a null list keeps the live one", func(t *testing.T) {
		live, rv := fresh(t)
		a := f.patchJSON(path, tok, migrationOps(nil, rv))
		wantCode(t, a, http.StatusOK)
		if es := managedFields(t, object(t, a)); !reflect.DeepEqual(es, withoutLastApplied(t, managedFields(t, live))) {
			t.Errorf("a null managedFields replaced the live list: %+v", es)
		}
	})
	t.Run("a decodable list is collapsed by manager and sorted as the server sorts it", func(t *testing.T) {
		_, rv := fresh(t)
		list := []any{
			map[string]any{"manager": "kubectl-scale", "operation": "Update", "apiVersion": "apps/v1", "time": "2026-11-02T00:00:00Z", "fieldsType": "FieldsV1", "subresource": "scale",
				"fieldsV1": map[string]any{"f:spec": map[string]any{"f:replicas": map[string]any{}}}},
			migratedEntry(func(e map[string]any) { e["time"] = "2026-10-01T00:00:00Z" }),
			migratedEntry(func(e map[string]any) { e["apiVersion"] = "apps/v2"; e["time"] = "2026-11-03T00:00:00Z" }),
		}
		a := f.patchJSON(path, tok, migrationOps(list, rv))
		wantCode(t, a, http.StatusOK)
		var got []string
		for _, e := range managedFields(t, object(t, a)) {
			got = append(got, e.Manager+"/"+e.Operation+"/"+e.APIVersion)
		}
		if want := []string{"farcast/Apply/apps/v2", "kubectl-scale/Update/apps/v1"}; !slices.Equal(got, want) {
			t.Errorf("managedFields = %v, want %v", got, want)
		}
	})
	t.Run("the object must exist", func(t *testing.T) {
		wantStatus(t, f.patchJSON("/apis/apps/v1/namespaces/web/deployments/absent", tok, migrationOps([]any{migratedEntry(nil)}, "1")), http.StatusNotFound, "NotFound")
	})
	t.Run("the body must be a JSON patch", func(t *testing.T) {
		live, _ := fresh(t)
		wantStatus(t, f.send(call{method: http.MethodPatch, path: path, token: tok, contentType: jsonPatch, body: []byte(`{"op":"remove"}`)}), http.StatusBadRequest, "BadRequest")
		unchanged(t, live)
	})
}

// TestJSONPatchStripsARemovedAnnotationFromEveryEntry (F-F2): when a patch
// removes an annotation, the API server's field manager subtracts its path
// from every entry the object keeps, and drops an entry left with no field
// (structured-merge-diff v6.3.1 merge/update.go, Updater.update). kubetest
// does the same, whether the list is the live one kept or the one submitted.
// An entry that owned no field before the patch stays, because kubetest's own
// apply entries own none.
func TestJSONPatchStripsARemovedAnnotationFromEveryEntry(t *testing.T) {
	f := newFixture(t)
	tok := f.mint(f.s.Credential("writer"))
	const path = "/apis/apps/v1/namespaces/web/deployments/web"
	ownsAnn := map[string]any{".": map[string]any{}, "f:" + lastApplied: map[string]any{}}
	mf := func(manager, operation, at string, fields map[string]any) map[string]any {
		return map[string]any{"manager": manager, "operation": operation, "apiVersion": "apps/v1", "time": at, "fieldsType": "FieldsV1", "fieldsV1": fields}
	}
	seed := func(t *testing.T) string {
		t.Helper()
		o := liveCSAObject()
		md := o["metadata"].(map[string]any)
		md["managedFields"] = []any{
			mf("farcast", "Apply", "2026-11-01T00:00:00Z", map[string]any{}),
			mf("kubectl-edit", "Update", "2026-11-02T00:00:00Z", map[string]any{
				"f:metadata": map[string]any{"f:annotations": ownsAnn},
				"f:spec":     map[string]any{"f:template": map[string]any{}},
			}),
			mf("kubectl-annotate", "Update", "2026-11-03T00:00:00Z", map[string]any{
				"f:metadata": map[string]any{"f:annotations": map[string]any{"f:" + lastApplied: map[string]any{}}},
			}),
			mf("technocore", "Update", "2026-11-04T00:00:00Z", map[string]any{"f:spec": map[string]any{"f:replicas": map[string]any{}}}),
		}
		f.s.Put(o)
		return metaOf(t, object(t, f.get(path, tok)))["resourceVersion"].(string)
	}
	want := []string{
		`farcast/Apply {}`,
		`kubectl-edit/Update {"f:metadata":{"f:annotations":{}},"f:spec":{"f:template":{}}}`,
		`technocore/Update {"f:spec":{"f:replicas":{}}}`,
	}
	got := func(t *testing.T, a answer) []string {
		t.Helper()
		var out []string
		for _, e := range managedFields(t, object(t, a)) {
			out = append(out, e.Manager+"/"+e.Operation+" "+string(e.FieldsV1))
		}
		return out
	}

	t.Run("the live list kept", func(t *testing.T) {
		rv := seed(t)
		a := f.patchJSON(path, tok, migrationOps([]any{migratedEntry(func(e map[string]any) { e["apiVersion"] = "" })}, rv))
		wantCode(t, a, http.StatusOK)
		for _, ans := range []answer{a, f.get(path, tok)} {
			if g := got(t, ans); !slices.Equal(g, want) {
				t.Errorf("entries = %q\nwant      %q", g, want)
			}
		}
	})
	t.Run("only the annotation removed", func(t *testing.T) {
		rv := seed(t)
		a := f.patchJSON(path, tok, []map[string]any{
			{"op": "replace", "path": "/metadata/resourceVersion", "value": rv},
			{"op": "remove", "path": "/metadata/annotations/kubectl.kubernetes.io~1last-applied-configuration"},
		})
		wantCode(t, a, http.StatusOK)
		if g := got(t, a); !slices.Equal(g, want) {
			t.Errorf("entries = %q\nwant      %q", g, want)
		}
	})
	t.Run("the submitted list, taken", func(t *testing.T) {
		rv := seed(t)
		submitted := []any{migratedEntry(func(e map[string]any) {
			e["fieldsV1"] = map[string]any{"f:metadata": map[string]any{"f:annotations": ownsAnn}, "f:spec": map[string]any{"f:replicas": map[string]any{}}}
		})}
		a := f.patchJSON(path, tok, migrationOps(submitted, rv))
		wantCode(t, a, http.StatusOK)
		if g, w := got(t, a), []string{`farcast/Apply {"f:metadata":{"f:annotations":{}},"f:spec":{"f:replicas":{}}}`}; !slices.Equal(g, w) {
			t.Errorf("entries = %q\nwant      %q", g, w)
		}
	})
	t.Run("no annotation removed, nothing stripped", func(t *testing.T) {
		rv := seed(t)
		before := managedFields(t, object(t, f.get(path, tok)))
		a := f.patchJSON(path, tok, []map[string]any{{"op": "replace", "path": "/metadata/resourceVersion", "value": rv}})
		wantCode(t, a, http.StatusOK)
		if es := managedFields(t, object(t, a)); !reflect.DeepEqual(es, before) {
			t.Errorf("entries = %+v, want them unchanged %+v", es, before)
		}
	})

	// D-D-5: removing the last annotation removes the annotations map
	// itself, so its own path, the "." member, leaves every entry too, and an
	// entry that owned nothing else goes; a key the object no longer had stays,
	// as it was not among the removed fields.
	seedLast := func(t *testing.T) string {
		t.Helper()
		o := liveCSAObject()
		md := o["metadata"].(map[string]any)
		delete(md["annotations"].(map[string]any), "keep")
		md["managedFields"] = append(md["managedFields"].([]any),
			mf("farcast", "Apply", "2026-11-01T00:00:00Z", map[string]any{}),
			mf("kubectl-edit", "Update", "2026-11-02T00:00:00Z", map[string]any{"f:metadata": map[string]any{"f:annotations": ownsAnn}}),
			mf("kubectl-annotate", "Update", "2026-11-03T00:00:00Z", map[string]any{
				"f:metadata": map[string]any{"f:annotations": map[string]any{".": map[string]any{}, "f:stale": map[string]any{}}},
			}),
		)
		f.s.Put(o)
		return metaOf(t, object(t, f.get(path, tok)))["resourceVersion"].(string)
	}
	t.Run("the last annotation removed, the live list kept", func(t *testing.T) {
		rv := seedLast(t)
		a := f.patchJSON(path, tok, migrationOps([]any{migratedEntry(func(e map[string]any) { e["apiVersion"] = "" })}, rv))
		wantCode(t, a, http.StatusOK)
		want := []string{
			`kubectl-client-side-apply/Update {"f:spec":{"f:replicas":{}}}`,
			`farcast/Apply {}`,
			`kubectl-annotate/Update {"f:metadata":{"f:annotations":{"f:stale":{}}}}`,
		}
		for _, ans := range []answer{a, f.get(path, tok)} {
			if _, has := metaOf(t, object(t, ans))["annotations"]; has {
				t.Error("the object still has an annotations map")
			}
			if g := got(t, ans); !slices.Equal(g, want) {
				t.Errorf("entries = %q\nwant      %q", g, want)
			}
		}
	})
	t.Run("the last annotation removed, the submitted list taken", func(t *testing.T) {
		rv := seedLast(t)
		submitted := []any{migratedEntry(func(e map[string]any) {
			e["fieldsV1"] = map[string]any{"f:metadata": map[string]any{"f:annotations": ownsAnn}, "f:spec": map[string]any{"f:replicas": map[string]any{}}}
		})}
		a := f.patchJSON(path, tok, migrationOps(submitted, rv))
		wantCode(t, a, http.StatusOK)
		if g, w := got(t, a), []string{`farcast/Apply {"f:spec":{"f:replicas":{}}}`}; !slices.Equal(g, w) {
			t.Errorf("entries = %q\nwant      %q", g, w)
		}
	})
}

// TestClientBodiesAreReadByExactKeys (F-F1): the API server decodes what a
// client sends case-sensitively, so a key spelt in another case is no field:
// dropped, or under fieldValidation=Strict refused. kubetest reads every
// client body the same way, so a client whose wire names differ from the API's
// only in case fails here as it would against a real server.
func TestClientBodiesAreReadByExactKeys(t *testing.T) {
	const deployment = "/apis/apps/v1/namespaces/web/deployments/web"
	const strict, warn = "?fieldManager=farcast&fieldValidation=Strict", "?fieldManager=farcast"
	patch := func(f *fixture, tok, query string, ops any) answer {
		b, err := json.Marshal(ops)
		if err != nil {
			t.Fatal(err)
		}
		return f.send(call{method: http.MethodPatch, path: deployment + query, token: tok, contentType: jsonPatch, body: b})
	}

	t.Run("a JSON patch operation", func(t *testing.T) {
		f := newFixture(t)
		tok := f.mint(f.s.Credential("writer"))
		f.s.Put(liveCSAObject())
		live := object(t, f.get(deployment, tok))
		rv := metaOf(t, live)["resourceVersion"].(string)
		for name, op := range map[string]map[string]any{
			"Op":   {"Op": "replace", "path": "/metadata/resourceVersion", "value": rv},
			"Path": {"op": "replace", "Path": "/metadata/resourceVersion", "value": rv},
		} {
			st := wantStatus(t, patch(f, tok, strict, []any{op}), http.StatusUnprocessableEntity, "Invalid")
			if !strings.Contains(st.Message, `strict decoding error: unknown field "`+name+`"`) {
				t.Errorf("%s under Strict: message %q", name, st.Message)
			}
			// Without strict validation the key is dropped, and the
			// operation has no op or no path.
			wantStatus(t, patch(f, tok, warn, []any{op}), http.StatusUnprocessableEntity, "Invalid")
		}
		st := wantStatus(t, patch(f, tok, strict, []any{map[string]any{"op": "replace", "path": "/metadata/resourceVersion", "value": rv, "extra": 1}}),
			http.StatusUnprocessableEntity, "Invalid")
		if !strings.Contains(st.Message, `unknown field "extra"`) {
			t.Errorf("an unknown key under Strict: message %q", st.Message)
		}
		if now := object(t, f.get(deployment, tok)); !reflect.DeepEqual(now, live) {
			t.Error("a refused patch changed the object")
		}
	})

	t.Run("a managed-fields entry", func(t *testing.T) {
		f := newFixture(t)
		tok := f.mint(f.s.Credential("writer"))
		for _, key := range []string{"Manager", "Operation", "APIVersion", "FieldsV1", "fieldsv1"} {
			f.s.Put(liveCSAObject())
			live := object(t, f.get(deployment, tok))
			rv := metaOf(t, live)["resourceVersion"].(string)
			e := migratedEntry(nil)
			lower := map[string]string{"Manager": "manager", "Operation": "operation", "APIVersion": "apiVersion", "FieldsV1": "fieldsV1", "fieldsv1": "fieldsV1"}[key]
			e[key] = e[lower]
			delete(e, lower)
			st := wantStatus(t, f.patchJSON(deployment, tok, migrationOps([]any{e}, rv)), http.StatusUnprocessableEntity, "Invalid")
			if !strings.Contains(st.Message, `strict decoding error: unknown field "metadata.managedFields[0].`+key+`"`) {
				t.Errorf("%s under Strict: message %q", key, st.Message)
			}
			if now := object(t, f.get(deployment, tok)); !reflect.DeepEqual(now, live) {
				t.Errorf("%s: a refused patch changed the object", key)
			}
		}
		// Without strict validation the key is dropped: "Manager" is no
		// manager, and "Operation" leaves the entry undecodable, so the
		// live list is kept.
		f.s.Put(liveCSAObject())
		rv := metaOf(t, object(t, f.get(deployment, tok)))["resourceVersion"].(string)
		e := migratedEntry(nil)
		e["Operation"] = e["operation"]
		delete(e, "operation")
		a := patch(f, tok, warn, migrationOps([]any{e}, rv))
		wantCode(t, a, http.StatusOK)
		if es := managedFields(t, object(t, a)); len(es) != 1 || es[0].Manager != "kubectl-client-side-apply" {
			t.Errorf("an entry whose operation is spelt Operation was taken: %+v", es)
		}
	})

	t.Run("a ConfigMap write", func(t *testing.T) {
		f := newFixture(t)
		tok := f.mint(f.s.Credential("writer"))
		const coll = "/api/v1/namespaces/farcast-system/configmaps"
		post := func(query, body string) answer {
			return f.send(call{method: http.MethodPost, path: coll + query, token: tok, contentType: "application/json", body: []byte(body)})
		}
		for body, field := range map[string]string{
			`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"a","namespace":"farcast-system"},"Data":{"k":"v"}}`:        "Data",
			`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"Name":"a","name":"a","namespace":"farcast-system"}}`:              "metadata.Name",
			`{"apiVersion":"v1","kind":"ConfigMap","Metadata":{"name":"a"},"metadata":{"name":"a","namespace":"farcast-system"}}`: "Metadata",
			`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"a","namespace":"farcast-system"},"status":{}}`:             "status",
		} {
			st := wantStatus(t, post(strict, body), http.StatusBadRequest, "BadRequest")
			if !strings.Contains(st.Message, `strict decoding error: unknown field "`+field+`"`) {
				t.Errorf("POST %s: message %q", body, st.Message)
			}
		}
		wantStatus(t, f.get(coll+"/a", tok), http.StatusNotFound, "NotFound")

		// Without strict validation an unknown key is dropped, not stored.
		a := post(warn, `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"a","namespace":"farcast-system","Labels":{"x":"y"}},"Data":{"k":"v"},"data":{"k":"w"}}`)
		wantCode(t, a, http.StatusCreated)
		got := object(t, f.get(coll+"/a", tok))
		if _, ok := got["Data"]; ok || get(got, "data", "k") != "w" {
			t.Errorf("stored %v; Data dropped and data kept", got)
		}
		if _, ok := metaOf(t, got)["Labels"]; ok {
			t.Errorf("stored metadata %v; Labels dropped", metaOf(t, got))
		}
		rv := metaOf(t, got)["resourceVersion"].(string)
		st := wantStatus(t, f.send(call{method: http.MethodPut, path: coll + "/a" + strict, token: tok, contentType: "application/json",
			body: []byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"a","namespace":"farcast-system","resourceVersion":"` + rv + `"},"Data":{"k":"x"}}`)}),
			http.StatusBadRequest, "BadRequest")
		if !strings.Contains(st.Message, `unknown field "Data"`) {
			t.Errorf("PUT under Strict: message %q", st.Message)
		}
	})

	t.Run("a SelfSubjectAccessReview", func(t *testing.T) {
		var got []kube.ResourceAttributes
		var mu sync.Mutex
		f := newFixture(t, kubetest.WithAccess(func(id string, a kube.ResourceAttributes) bool {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, a)
			return a.Verb == "get"
		}))
		tok := f.mint(f.s.Credential("reader"))
		send := func(body string) answer {
			return f.send(call{method: http.MethodPost, path: "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", token: tok, contentType: "application/json", body: []byte(body)})
		}
		a := send(`{"spec":{"resourceAttributes":{"Verb":"get","resource":"pods","Namespace":"web"}}}`)
		wantCode(t, a, http.StatusCreated)
		if allowed, _ := get(object(t, a), "status", "allowed").(bool); allowed {
			t.Error("a review whose verb is spelt Verb was read as get")
		}
		wantCode(t, send(`{"Spec":{"resourceAttributes":{"verb":"get","resource":"pods"}}}`), http.StatusBadRequest)
		wantCode(t, send(`{"spec":{"ResourceAttributes":{"verb":"get","resource":"pods"}}}`), http.StatusUnprocessableEntity)
		mu.Lock()
		defer mu.Unlock()
		if len(got) != 1 || got[0] != (kube.ResourceAttributes{Resource: "pods"}) {
			t.Errorf("WithAccess saw %+v, want one review of pods with no verb and no namespace", got)
		}
	})
}

// TestSecretDeleteNeedsItsUID: DELETE of a Secret is preconditioned on its
// uid (409 otherwise, a missing precondition included), 404 when absent; no
// other kind is deleted.
func TestSecretDeleteNeedsItsUID(t *testing.T) {
	f := newFixture(t)
	tok := f.mint(f.s.Credential("writer"))
	const path = "/api/v1/namespaces/farcast-system/secrets/git-credential-web"
	f.s.Put(map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": map[string]any{"name": "git-credential-web", "namespace": "farcast-system"}, "data": map[string]any{"token": "eA=="}})
	md := metaOf(t, object(t, f.get(path, tok)))
	uid, rv := md["uid"].(string), md["resourceVersion"].(string)
	del := func(body string) answer {
		var b []byte
		if body != "" {
			b = []byte(body)
		}
		return f.send(call{method: http.MethodDelete, path: path, token: tok, contentType: "application/json", body: b})
	}

	st := wantStatus(t, del(`{"preconditions":{"uid":"another"}}`), http.StatusConflict, "Conflict")
	if !strings.Contains(st.Message, "Precondition failed: UID in precondition: another") {
		t.Errorf("409 message = %q", st.Message)
	}
	wantStatus(t, del(""), http.StatusConflict, "Conflict")
	wantStatus(t, del(`{}`), http.StatusConflict, "Conflict")
	wantStatus(t, del(`{"preconditions":{"uid":"`+uid+`","resourceVersion":"stale"}}`), http.StatusConflict, "Conflict")
	wantStatus(t, del(`not json`), http.StatusBadRequest, "BadRequest")
	// The keys are read exactly, as the API server reads a DELETE body: a
	// precondition spelt in another case is no precondition (F-F1).
	wantStatus(t, del(`{"Preconditions":{"uid":"`+uid+`"}}`), http.StatusConflict, "Conflict")
	wantStatus(t, del(`{"preconditions":{"UID":"`+uid+`"}}`), http.StatusConflict, "Conflict")
	wantStatus(t, del(`{"preconditions":{"uid":5}}`), http.StatusBadRequest, "BadRequest")
	wantCode(t, f.get(path, tok), http.StatusOK)

	a := del(`{"preconditions":{"uid":"` + uid + `","resourceVersion":"` + rv + `"}}`)
	wantCode(t, a, http.StatusOK)
	var done kube.Status
	if err := json.Unmarshal(a.body, &done); err != nil || done.Kind != "Status" || done.Status.Status != "Success" || done.Details == nil || done.Details.Name != "git-credential-web" {
		t.Errorf("a delete answers %s", a.body)
	}
	wantStatus(t, f.get(path, tok), http.StatusNotFound, "NotFound")
	wantStatus(t, del(`{"preconditions":{"uid":"`+uid+`"}}`), http.StatusNotFound, "NotFound")

	f.s.Put(configMap("farcast-system", "c", nil))
	wantStatus(t, f.send(call{method: http.MethodDelete, path: "/api/v1/namespaces/farcast-system/configmaps/c", token: tok}), http.StatusMethodNotAllowed, "MethodNotAllowed")
	wantStatus(t, f.send(call{method: http.MethodDelete, path: "/api/v1/namespaces/farcast-system/secrets", token: tok}), http.StatusMethodNotAllowed, "MethodNotAllowed")
	wantCode(t, f.get("/api/v1/namespaces/farcast-system/configmaps/c", tok), http.StatusOK)
}

// TestWarningHeadersRideOnEveryAPIAnswer: WithWarnings puts each text on
// every API answer as 299 - "<text>", quoted; /token answers carry none.
func TestWarningHeadersRideOnEveryAPIAnswer(t *testing.T) {
	f := newFixture(t, kubetest.WithWarnings(func(r kubetest.Request) []string {
		return []string{"first", `say "hi" \ now`}
	}))
	want := []string{`299 - "first"`, `299 - "say \"hi\" \\ now"`}
	c := f.s.Credential("reader")
	a := f.tokenRequest(sign(t, privateKey(t, c), goodHeader(c), goodClaims(f.s, c)))
	if got := a.header.Values("Warning"); len(got) != 0 {
		t.Errorf("a /token answer carries warnings %v", got)
	}
	tok := f.mint(c)
	for _, a := range []answer{
		f.get("/api/v1/namespaces", tok),
		f.get("/api/v1/namespaces/web/configmaps/absent", tok),
		f.get("/api/v1/namespaces", ""),
		f.get("/version", tok),
	} {
		if got := a.header.Values("Warning"); !slices.Equal(got, want) {
			t.Errorf("answer %d carries Warning %q, want %q", a.code, got, want)
		}
	}
}

// TestFailInjectsEachAnswerOnce: every failure §2.2 lists, each consumed by
// one request, in the order injected, after authentication.
func TestFailInjectsEachAnswerOnce(t *testing.T) {
	f := newFixture(t)
	const email = "reader@kubetest.invalid"
	tok := f.mint(f.s.Credential("reader"))
	const path = "/api/v1/namespaces/farcast-system/configmaps/technocore-ledger"
	conflictCause := kube.StatusCause{Type: "FieldManagerConflict", Message: `conflict with "technocore": .spec.replicas`, Field: ".spec.replicas"}

	rows := []struct {
		name   string
		code   int
		st     kube.Status
		reason string
		check  func(t *testing.T, a answer)
	}{
		{name: "401", code: 401, reason: "Unauthorized"},
		{name: "403 naming the caller", code: 403, reason: "Forbidden", check: func(t *testing.T, a answer) {
			st := status(t, a)
			want := `configmaps "technocore-ledger" is forbidden: User "` + email + `" cannot get resource "configmaps" in API group "" in the namespace "farcast-system"`
			if st.Message != want {
				t.Errorf("message = %q, want %q", st.Message, want)
			}
		}},
		{name: "403 that is not a Status", code: 403, st: kube.Status{Status: tkube.Status{Kind: "GoogleError"}}, check: func(t *testing.T, a answer) {
			m := object(t, a)
			if m["kind"] != nil || get(m, "error", "code") != json.Number("403") || get(m, "error", "status") != "PERMISSION_DENIED" {
				t.Errorf("a non-Status 403 = %s", a.body)
			}
		}},
		{name: "404", code: 404, reason: "NotFound"},
		{name: "409 with FieldManagerConflict causes", code: 409, reason: "Conflict",
			st: kube.Status{Details: &kube.StatusDetails{Causes: []kube.StatusCause{conflictCause}}},
			check: func(t *testing.T, a answer) {
				if !bytes.Contains(a.body, []byte(`"causes":[{"reason":"FieldManagerConflict","message":"conflict with \"technocore\": .spec.replicas","field":".spec.replicas"}]`)) {
					t.Errorf("the causes are not on the wire as meta/v1 writes them: %s", a.body)
				}
				if st := status(t, a); st.Details == nil || !reflect.DeepEqual(st.Details.Causes, []kube.StatusCause{conflictCause}) {
					t.Errorf("kube.Status decodes the causes as %+v", st.Details)
				}
			}},
		{name: "410", code: 410, reason: "Expired"},
		{name: "422", code: 422, reason: "Invalid"},
		{name: "429 with Retry-After", code: 429, reason: "TooManyRequests", check: func(t *testing.T, a answer) {
			if got := a.header.Get("Retry-After"); got != "1" {
				t.Errorf("Retry-After = %q, want 1", got)
			}
		}},
		{name: "500", code: 500, reason: "InternalError"},
		{name: "503", code: 503, reason: "ServiceUnavailable", check: func(t *testing.T, a answer) {
			if got := a.header.Get("Retry-After"); got != "" {
				t.Errorf("a 503 carries Retry-After %q", got)
			}
		}},
		{name: "a given reason and message", code: 409, st: kube.Status{Status: tkube.Status{Reason: "AlreadyExists", Message: "it is there"}}, reason: "AlreadyExists", check: func(t *testing.T, a answer) {
			if st := status(t, a); st.Message != "it is there" {
				t.Errorf("message = %q", st.Message)
			}
		}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			f.s.Fail(http.MethodGet, path, r.code, r.st)
			wantCode(t, f.get(path, ""), http.StatusUnauthorized) // an unauthenticated request consumes nothing
			a := f.get(path, tok)
			wantCode(t, a, r.code)
			if r.reason != "" {
				st := status(t, a)
				if st.Reason != r.reason || st.Code != r.code || st.Status.Status != "Failure" {
					t.Errorf("Status = %+v, want reason %s code %d", st, r.reason, r.code)
				}
			}
			if r.check != nil {
				r.check(t, a)
			}
			wantStatus(t, f.get(path, tok), http.StatusNotFound, "NotFound")
		})
	}

	t.Run("queued answers come in order, per method and path", func(t *testing.T) {
		f.s.Fail(http.MethodGet, path, 429, kube.Status{})
		f.s.Fail(http.MethodGet, path, 503, kube.Status{})
		f.s.Fail(http.MethodPatch, path, 500, kube.Status{})
		wantCode(t, f.get("/api/v1/namespaces/farcast-system/configmaps/other", tok), http.StatusNotFound)
		for _, want := range []int{429, 503, 404, 404} {
			wantCode(t, f.get(path, tok), want)
		}
		wantCode(t, f.apply(path, tok, "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: technocore-ledger\n  namespace: farcast-system\n"), 500)
	})
}

// TestEverythingElseIs405AndRecorded: what the emulation does not cover is
// 405, as a Status, and still recorded.
func TestEverythingElseIs405AndRecorded(t *testing.T) {
	f := newFixture(t)
	tok := f.mint(f.s.Credential("writer"))
	f.s.Put(map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": map[string]any{"name": "web", "namespace": "web"}})
	rows := []call{
		{method: http.MethodPost, path: "/apis/apps/v1/namespaces/web/deployments", contentType: "application/json", body: []byte(`{}`)},
		{method: http.MethodPut, path: "/api/v1/namespaces/web/secrets/s", contentType: "application/json", body: []byte(`{}`)},
		{method: http.MethodPatch, path: "/apis/apps/v1/namespaces/web/deployments/web", contentType: "application/merge-patch+json", body: []byte(`{}`)},
		{method: http.MethodPatch, path: "/apis/apps/v1/namespaces/web/deployments/web", contentType: "application/strategic-merge-patch+json", body: []byte(`{}`)},
		{method: http.MethodPatch, path: "/apis/apps/v1/namespaces/web/deployments/web/scale" + applyQuery, contentType: applyType, body: []byte(`{}`)},
		{method: http.MethodGet, path: "/apis/apps/v1/namespaces/web/deployments/web/status"},
		{method: http.MethodGet, path: "/version"},
		{method: http.MethodGet, path: "/apis/example.com/v1/widgets"},
		{method: http.MethodGet, path: "/api/v1/configmaps/x"},
		{method: http.MethodGet, path: "/api/v1/namespaces/web/clusterroles"},
		{method: http.MethodGet, path: "/api/v1/namespaces/web/status"},
		{method: http.MethodDelete, path: "/api/v1/namespaces/web"},
		{method: http.MethodPost, path: "/api/v1/configmaps", contentType: "application/json", body: []byte(`{"metadata":{"name":"x"}}`)},
	}
	for _, c := range rows {
		c.token = tok
		a := f.send(c)
		if a.code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s = %d, want 405: %s", c.method, c.path, a.code, a.body)
			continue
		}
		if st := status(t, a); st.Reason != "MethodNotAllowed" || st.Code != 405 {
			t.Errorf("%s %s: 405 Status = %+v", c.method, c.path, st)
		}
		r := f.lastRequest()
		if r.Method != c.method || r.Path != strings.SplitN(c.path, "?", 2)[0] || r.As != "writer" {
			t.Errorf("%s %s is recorded as %+v", c.method, c.path, r)
		}
	}
	wantCode(t, f.send(call{method: http.MethodHead, path: "/api/v1/namespaces", token: tok}), http.StatusMethodNotAllowed)
}

// TestRequestsRecordWhatWasSent: every field of a request is recorded, in
// order, and the caller's copy is its own.
func TestRequestsRecordWhatWasSent(t *testing.T) {
	f := newFixture(t)
	c := f.s.Credential("reader")
	tok := f.mint(c)
	body := []byte(`{"metadata":{"name":"pin"}}`)
	f.send(call{method: http.MethodPost, path: "/api/v1/namespaces/web/configmaps?fieldManager=farcast&fieldValidation=Strict", token: tok,
		contentType: "application/json", accept: "application/json", body: body})
	reqs := f.s.Requests()
	if len(reqs) != 2 {
		t.Fatalf("Requests() = %d requests, want 2", len(reqs))
	}
	if r := reqs[0]; r.Path != "/token" || r.As != "reader" || r.KeyID != c.PrivateKeyID || !bytes.Contains(r.Body, []byte("assertion=")) {
		t.Errorf("the /token request = %+v", r)
	}
	want := kubetest.Request{Method: "POST", Path: "/api/v1/namespaces/web/configmaps", RawQuery: "fieldManager=farcast&fieldValidation=Strict",
		ContentType: "application/json", UserAgent: "farcast", Accept: "application/json", As: "reader", Body: body}
	if !reflect.DeepEqual(reqs[1], want) {
		t.Errorf("recorded\n %+v\nwant\n %+v", reqs[1], want)
	}
	reqs[1].Body[0] = 'X'
	if again := f.s.Requests(); again[1].Body[0] != '{' {
		t.Error("a caller's edit of a recorded body reached the server's record")
	}
}

// waitFor polls cond until it holds or 10 s pass. WithAnswered runs after an
// answer is written, so a client can hold its answer a moment before f has
// been called.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("waited 10 s for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestWithAnsweredSeesEveryAnswer (ADR 0023 M2.4, A18-7): f is called once
// for every request, after its answer, with the request as Requests records
// it and the code the answer was sent with. The refused ones reach it too: an
// assertion that does not verify, a GET of /token, a 401 with no token and
// with an unknown one, an injected 403, a 404 and a 405. A request abandoned
// during WithDelay's hold was answered nothing, and is passed with 0.
func TestWithAnsweredSeesEveryAnswer(t *testing.T) {
	type seen struct {
		r      kubetest.Request
		status int
	}
	var mu sync.Mutex
	var got []seen
	answered := func() []seen {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(got)
	}
	var hold atomic.Bool
	const heldPath = "/api/v1/namespaces/web/pods"
	f := newFixture(t,
		kubetest.WithAnswered(func(r kubetest.Request, status int) {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, seen{r, status})
		}),
		kubetest.WithDelay(func(r kubetest.Request) time.Duration {
			if hold.Load() && r.Path == heldPath {
				return 10 * time.Second
			}
			return 0
		}))
	c := f.s.Credential("reader")
	tok := f.mint(c)
	badScope := goodClaims(f.s, c)
	badScope["scope"] = "https://www.googleapis.com/auth/cloud-platform"
	wantCode(t, f.tokenRequest(sign(t, privateKey(t, c), goodHeader(c), badScope)), http.StatusBadRequest)
	wantCode(t, f.get("/token", ""), http.StatusMethodNotAllowed)
	wantCode(t, f.get("/api/v1/namespaces", ""), http.StatusUnauthorized)
	wantCode(t, f.send(call{method: http.MethodGet, path: "/api/v1/namespaces", authorization: "Bearer kubetest:reader:999"}), http.StatusUnauthorized)
	f.s.Fail(http.MethodGet, "/api/v1/namespaces/web/configmaps/pin", http.StatusForbidden, kube.Status{})
	wantCode(t, f.get("/api/v1/namespaces/web/configmaps/pin", tok), http.StatusForbidden)
	wantCode(t, f.get("/api/v1/namespaces/web/configmaps/absent", tok), http.StatusNotFound)
	f.s.Put(configMap("web", "pin", map[string]string{"k": "v"}))
	wantCode(t, f.get("/api/v1/namespaces/web/configmaps/pin", tok), http.StatusOK)
	wantCode(t, f.get("/version", tok), http.StatusMethodNotAllowed)
	hold.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := f.try(call{ctx: ctx, method: http.MethodGet, path: heldPath, token: tok}); err == nil {
		t.Fatal("a request held for 10 s answered within its 200 ms deadline")
	}

	want := []struct {
		method, path, as string
		status           int
	}{
		{http.MethodPost, "/token", "reader", http.StatusOK},
		{http.MethodPost, "/token", "", http.StatusBadRequest},
		{http.MethodGet, "/token", "", http.StatusMethodNotAllowed},
		{http.MethodGet, "/api/v1/namespaces", "", http.StatusUnauthorized},
		{http.MethodGet, "/api/v1/namespaces", "?", http.StatusUnauthorized},
		{http.MethodGet, "/api/v1/namespaces/web/configmaps/pin", "reader", http.StatusForbidden},
		{http.MethodGet, "/api/v1/namespaces/web/configmaps/absent", "reader", http.StatusNotFound},
		{http.MethodGet, "/api/v1/namespaces/web/configmaps/pin", "reader", http.StatusOK},
		{http.MethodGet, "/version", "reader", http.StatusMethodNotAllowed},
		{http.MethodGet, heldPath, "reader", 0},
	}
	waitFor(t, "every answer to reach WithAnswered", func() bool { return len(answered()) >= len(want) })
	time.Sleep(50 * time.Millisecond) // a second call for any request would land here
	seenAll, reqs := answered(), f.s.Requests()
	if len(seenAll) != len(want) || len(reqs) != len(want) {
		t.Fatalf("WithAnswered was called %d times and %d requests were recorded; want %d of each", len(seenAll), len(reqs), len(want))
	}
	for i, w := range want {
		g := seenAll[i]
		if g.r.Method != w.method || g.r.Path != w.path || g.r.As != w.as || g.status != w.status {
			t.Errorf("answer %d = %s %s as %q, %d; want %s %s as %q, %d", i, g.r.Method, g.r.Path, g.r.As, g.status, w.method, w.path, w.as, w.status)
		}
		if !reflect.DeepEqual(g.r, reqs[i]) {
			t.Errorf("answer %d (%s %s): WithAnswered's request is not the one Requests recorded", i, w.method, w.path)
		}
	}
	for _, i := range []int{0, 1} {
		if seenAll[i].r.KeyID != c.PrivateKeyID {
			t.Errorf("/token answer %d carries KeyID %q, want the assertion's kid", i, seenAll[i].r.KeyID)
		}
	}
	seenAll[0].r.Body[0] = 'X'
	if again := f.s.Requests(); again[0].Body[0] == 'X' {
		t.Error("WithAnswered's body is the server's record, not f's own copy")
	}
}

// TestWithoutRecordingKeepsNoLog (ADR 0023 M2.4, A18-7): with
// WithoutRecording, Requests is nil whatever was served, the server answers
// as it always does, and WithAnswered still sees every request.
func TestWithoutRecordingKeepsNoLog(t *testing.T) {
	var answered atomic.Int32
	f := newFixture(t, kubetest.WithoutRecording(), kubetest.WithAnswered(func(kubetest.Request, int) { answered.Add(1) }))
	c := f.s.Credential("reader")
	tok := f.mint(c)
	wantCode(t, f.get("/api/v1/namespaces", tok), http.StatusOK)
	wantStatus(t, f.get("/api/v1/namespaces", ""), http.StatusUnauthorized, "Unauthorized")
	wantCode(t, f.tokenRequest("not.a.jwt"), http.StatusBadRequest)
	if reqs := f.s.Requests(); reqs != nil {
		t.Errorf("Requests() = %d requests, want nil", len(reqs))
	}
	waitFor(t, "four answers to reach WithAnswered", func() bool { return answered.Load() >= 4 })

	g := newFixture(t, kubetest.WithoutRecording())
	gt := g.mint(g.s.Credential("reader"))
	wantCode(t, g.get("/api/v1/namespaces", gt), http.StatusOK)
	if reqs := g.s.Requests(); reqs != nil {
		t.Errorf("without WithAnswered: Requests() = %d requests, want nil", len(reqs))
	}
}

// TestCredentialIsAFreshRegisteredKey: Credential and CredentialFor return a
// new RSA-2048 PKCS#8 key each, with a Google-shaped key id, already
// registered; a key file made of it parses and pairs as a loopback key.
func TestCredentialIsAFreshRegisteredKey(t *testing.T) {
	f := newFixture(t)
	a, b := f.s.Credential("reader"), f.s.Credential("reader")
	if a.Email != "reader@kubetest.invalid" || a.TokenURI != "" || a.UniverseDomain != "" {
		t.Errorf("Credential = %+v", a)
	}
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(a.PrivateKeyID) {
		t.Errorf("PrivateKeyID = %q, want 40 hex characters", a.PrivateKeyID)
	}
	if k := privateKey(t, a); k.N.BitLen() != 2048 {
		t.Errorf("the key is %d bits", k.N.BitLen())
	}
	if bytes.Equal(a.PrivateKeyPEM, b.PrivateKeyPEM) || a.PrivateKeyID == b.PrivateKeyID {
		t.Error("two Credentials share a key")
	}
	w := f.s.CredentialFor("writer", "writer@rehearsal.invalid")
	if w.Email != "writer@rehearsal.invalid" {
		t.Errorf("CredentialFor's email = %q", w.Email)
	}
	if got := []string{f.mint(a), f.mint(b), f.mint(w)}; !slices.Equal(got, []string{"kubetest:reader:1", "kubetest:reader:2", "kubetest:writer:3"}) {
		t.Errorf("tokens = %v", got)
	}

	file, err := json.Marshal(map[string]string{"type": "service_account", "client_email": a.Email, "private_key": string(a.PrivateKeyPEM),
		"private_key_id": a.PrivateKeyID, "token_uri": "https://" + f.s.Endpoint() + "/token"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := kube.ParseServiceAccountJSON(file)
	if err != nil {
		t.Fatalf("a key file of the credential does not parse: %v", err)
	}
	ep, err := kube.ParseEndpoint(f.s.Endpoint(), "", f.s.CAPEM())
	if err != nil || parsed.TokenURI != ep.TokenURL() {
		t.Errorf("the key file's token_uri %s is not the endpoint's token URL %s (%v)", parsed.TokenURI, ep.TokenURL(), err)
	}
}

// TestPutSeedsWhatGetAnswers: Put stores the object as given, setting only
// a missing uid, resourceVersion and creationTimestamp, and refuses what no
// server could store.
func TestPutSeedsWhatGetAnswers(t *testing.T) {
	f := newFixture(t)
	tok := f.mint(f.s.Credential("reader"))
	const path = "/api/v1/namespaces/web/configmaps/c"

	f.s.Put(configMap("web", "c", map[string]string{"a": "1"}))
	first := metaOf(t, object(t, f.get(path, tok)))
	if first["uid"] == "" || first["resourceVersion"] == "" || first["creationTimestamp"] == nil {
		t.Errorf("Put set no server metadata: %v", first)
	}
	f.s.Put(configMap("web", "c", map[string]string{"a": "2"}))
	second := metaOf(t, object(t, f.get(path, tok)))
	if second["uid"] == first["uid"] {
		t.Error("a re-seed without a uid kept the old uid")
	}

	f.s.Put([]byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"c","namespace":"web","uid":"given","resourceVersion":"100","creationTimestamp":"2026-01-02T03:04:05Z"}}`))
	md := metaOf(t, object(t, f.get(path, tok)))
	if md["uid"] != "given" || md["resourceVersion"] != "100" || md["creationTimestamp"] != "2026-01-02T03:04:05Z" {
		t.Errorf("Put changed given metadata: %v", md)
	}
	f.s.Put(json.RawMessage(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"d","namespace":"web"}}`))
	if rv, _ := strconv.Atoi(metaOf(t, object(t, f.get("/api/v1/namespaces/web/configmaps/d", tok)))["resourceVersion"].(string)); rv <= 100 {
		t.Errorf("a write after a seeded resourceVersion 100 got %d", rv)
	}

	for name, obj := range map[string]any{
		"an unserved kind":                map[string]any{"apiVersion": "v1", "kind": "Endpoints", "metadata": map[string]any{"name": "x", "namespace": "web"}},
		"no name":                         configMap("web", "", nil),
		"a namespaced kind without one":   configMap("", "x", nil),
		"a cluster-scoped kind with one":  map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "x", "namespace": "web"}},
		"something that is not an object": []byte(`[1]`),
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Put of %s did not panic", name)
				}
			}()
			f.s.Put(obj)
		}()
	}
}

// TestServerIsSafeUnderConcurrentUse drives every method at once, for -race.
func TestServerIsSafeUnderConcurrentUse(t *testing.T) {
	f := newFixture(t, kubetest.WithDelay(func(kubetest.Request) time.Duration { return 0 }))
	c := f.s.Credential("reader")
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for g := range 8 {
		wg.Go(func() {
			for i := range 5 {
				tok, err := f.mintErr(c)
				if err != nil {
					errs <- err
					return
				}
				name := fmt.Sprintf("c-%d-%d", g, i)
				path := "/api/v1/namespaces/web/configmaps/" + name
				doc := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: " + name + "\n  namespace: web\n"
				if a, err := f.try(call{method: http.MethodPatch, path: path + applyQuery, token: tok, contentType: applyType, body: []byte(doc)}); err != nil || a.code != http.StatusCreated {
					errs <- fmt.Errorf("apply %s: %v %d", name, err, a.code)
					return
				}
				f.s.Put(configMap("web", name+"-seeded", nil))
				f.s.Script("/api/v1/namespaces/web/configmaps/scripted", configMap("web", "scripted", nil))
				f.s.Fail(http.MethodGet, "/api/v1/namespaces/web/configmaps/failed", 500, kube.Status{})
				for _, p := range []string{"/api/v1/namespaces/web/configmaps", "/api/v1/namespaces/web/configmaps/scripted", "/api/v1/namespaces/web/configmaps/failed"} {
					if _, err := f.try(call{method: http.MethodGet, path: p, token: tok}); err != nil {
						errs <- err
						return
					}
				}
				_ = f.s.Requests()
				f.s.Revoke(tok)
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func (f *fixture) mintErr(c kube.Credential) (string, error) {
	key, err := parseKey(c.PrivateKeyPEM)
	if err != nil {
		return "", err
	}
	iat := time.Now().Add(-10 * time.Second).Unix()
	h, _ := json.Marshal(goodHeader(c))
	cl, _ := json.Marshal(claims{"iss": c.Email, "scope": kube.ScopeUserinfoEmail, "aud": "https://" + f.s.Endpoint() + "/token", "iat": iat, "exp": iat + 3600})
	signing := b64(h) + "." + b64(cl)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	form := url.Values{"grant_type": {jwtBearer}, "assertion": {signing + "." + b64(sig)}}
	a, err := f.try(call{method: http.MethodPost, path: "/token", contentType: formType, body: []byte(form.Encode())})
	if err != nil {
		return "", err
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(a.body, &tok); err != nil || tok.AccessToken == "" {
		return "", fmt.Errorf("mint: %d %s", a.code, a.body)
	}
	return tok.AccessToken, nil
}

func parseKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not RSA")
	}
	return rk, nil
}
